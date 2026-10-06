import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Button, Form, InputGroup, Spinner, Badge, OverlayTrigger, Tooltip, Modal,
} from 'react-bootstrap';
import QueryLanguageHelp from './QueryLanguageHelp';

// Single Request: a repeater over the requests the manual crawl already recorded.
//
// This is the whole repeater as a plain block. It carries no chrome of its own: no modal, no
// header, no viewport heights. It fills whatever container it is given, so it can sit inside a
// modal body as easily as inside a tab pane. ReplayRequestsModal is its caller.
//
// Four columns. The sitemap on the left is the corpus, filtered by the query language the server
// parses. Then the raw request, editable to the byte. Then the raw response exactly as it came
// back, including the status line and headers. Then the versions of the request now loaded.
//
// Three invariants this file exists to protect:
//
//   1. What the operator sees in the request pane is what gets sent. Nothing here reformats,
//      pretty-prints, re-orders headers or trims whitespace. The one exception is the line
//      terminator, and only because a browser textarea forces it: the HTML spec normalises every
//      terminator in a textarea's value to a bare LF, so an edit anywhere in a CRLF document would
//      silently strip every CR. handleRequestChange puts them back to match the terminator style
//      the document was loaded with, and the EOL selector is how an operator changes that style
//      deliberately rather than by accident.
//
//   2. Syntax colour and the line-ending display toggle are display only. They render a coloured copy
//      of the buffer (renderHttpNodes) into a mirror element behind the textarea. That copy is never
//      read back, so no amount of toggling or colouring can reach the bytes that get sent. The
//      versions column does not change this: every path that leaves this file with bytes in it -- the
//      send, and the version save -- reads rawRequest, never the mirror the render produces.
//
//      Two more display controls follow the same rule and are held to it the same way:
//
//        WRAP LINES is CSS and one HTML attribute. white-space: pre-wrap on the panes, and
//        wrap="soft" on the textarea. Soft is the only value used, ever: the HTML spec says a soft
//        wrap inserts no line breaks into the element's value, while wrap="hard" inserts them into
//        the value a FORM submits. Nothing here submits a form -- the send reads rawRequest out of
//        React state -- but "soft" is still what is written, so the question cannot arise.
//
//        JSON PRETTY-PRINTING on the RESPONSE is display only (the responseText memo hands a string to
//        a <pre> and to nothing else), with a Raw/Pretty toggle because sometimes the exact bytes are
//        the finding.
//
//      The request body IS pretty-printed by default, unlike the response's display-only path, because
//      the request pane is editable and the buffer has to BE what is shown -- so prettifyRequestJson
//      folds the formatting into the loaded bytes on load and recomputes Content-Length. It only ever
//      touches a JSON body (whitespace-insensitive), leaves everything else byte-exact, matches the
//      "Format JSON body" button's own logic, and Raw mode still sends the buffer byte for byte. This
//      is the deliberate reversal of the old "never reformat the request" rule, at the user's request,
//      to match how Burp and Caido show a request by default.
//
//   3. Nothing the operator typed disappears without them being told. Before this file had
//      versions, that was one confirm on every path that replaced the buffer. It still is, but the
//      confirm is now the FALLBACK: the edit is first offered to the version store, and the confirm
//      only fires if that could not keep it. An edit that was saved is not an unsaved edit, so asking
//      about it would be a prompt the operator learns to click through. The confirm is a small modal
//      stacked on the pane (askConfirm), never a window.confirm: a browser dialog would freeze the
//      page and cannot be styled.
//
// WHEN A VERSION IS CREATED, exhaustively:
//
//   - Replay is pressed and the buffer differs from the version that is open.
//   - Another version in the column is clicked while the buffer differs.
//   - Another request is loaded, from the sitemap or from the loadCaptureId prop, while the buffer
//     differs.
//   - AUTOSAVE_IDLE_MS passes with no edit while the buffer differs.
//   - The pane unmounts, which is what closing the modal does, while the buffer differs.
//
// and never otherwise. Not per keystroke: the idle timer restarts on every change. Not when the
// bytes are unchanged: every entry point compares the buffer against the version it was loaded
// from first. Not when the server judges the bytes identical to the parent, which it answers 409
// to; that is reported in the column as "nothing to save", not as an error. Not when no request
// has been loaded, because a version tree needs a root and a scratch buffer has none.

// The sitemap shows the whole matched corpus, not an arbitrary page of it: the tree the operator
// navigates is built from these rows, and a tree that stops at 500 hides most of a real crawl
// behind a limit nobody asked for. This is the server's scan ceiling, a guard against a
// pathological corpus rather than a page size, and the only thing that truncates is exceeding it -
// which the query language is then how you narrow back under it.
const RESULT_LIMIT = 50000;

// How long the operator has to stop typing before the edit is written down. Long enough that
// composing a header does not leave a row per pause, short enough that walking away from the
// keyboard does not lose the edit. Rendered into the hint text, so changing it here changes what
// the column promises.
const AUTOSAVE_IDLE_MS = 3000;

// Display glyphs for the line-ending view. Chosen from the Unicode control pictures block so they
// cannot be confused with anything that appears in a real request.
const GLYPH_CR = '␍';
const GLYPH_LF = '␊';

function statusVariant(status) {
  const code = Number(status);
  if (!code) return 'secondary';
  if (code < 300) return 'success';
  if (code < 400) return 'info';
  if (code < 500) return 'warning';
  return 'danger';
}

// Splits a capture url into the pieces the tree is built from. A capture with a url the browser
// cannot parse still has to appear, because a request that vanishes from the sitemap looks
// identical to a request that was never recorded.
function parseUrlParts(rawUrl) {
  const fallback = { host: String(rawUrl || 'unknown'), path: '/', query: '' };
  if (!rawUrl) return fallback;
  try {
    const parsed = new URL(rawUrl);
    return { host: parsed.host || parsed.hostname, path: parsed.pathname || '/', query: parsed.search || '' };
  } catch (err) {
    const match = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]+)([^?#]*)(\?[^#]*)?/.exec(String(rawUrl));
    if (match) return { host: match[1], path: match[2] || '/', query: match[3] || '' };
    return fallback;
  }
}

function pickString(obj, keys) {
  if (!obj || typeof obj !== 'object') return null;
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === 'string' && value !== '') return value;
  }
  return null;
}

function pickNumber(obj, keys) {
  if (!obj || typeof obj !== 'object') return null;
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  }
  return null;
}

function byteLength(text) {
  if (!text) return 0;
  try {
    return new TextEncoder().encode(text).length;
  } catch (err) {
    return text.length;
  }
}

// A version's timestamp, short enough for a narrow column. The full stamp goes in the row's title
// attribute, because "14:02:11" on its own stops being useful the day after.
function formatVersionTime(value) {
  if (!value) return '';
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return String(value);
  const today = new Date();
  const sameDay = at.getFullYear() === today.getFullYear()
    && at.getMonth() === today.getMonth()
    && at.getDate() === today.getDate();
  return sameDay
    ? at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : at.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatVersionTimestamp(value) {
  if (!value) return 'unknown';
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? String(value) : at.toLocaleString();
}

// Reads whatever the framework said went wrong. The versions endpoints answer {error, message};
// anything that never reached them answers with a body that is not JSON at all.
function versionErrorMessage(data, body, status) {
  const message = pickString(data, ['message', 'error']);
  if (message) return message;
  if (body && body.length < 300) return body;
  return `Framework returned ${status}`;
}

// The line-ending glyphs (GLYPH_CR / GLYPH_LF) are now emitted by renderHttpNodes, folded into the
// same coloured render as everything else, so the standalone decorateLineEndings helpers this pane
// used to carry are gone: two code paths for the same overlay were how colour and glyphs came to
// disagree about where a line ended.

// Splits an HTTP message into its header block and its body at the first blank line, and hands back
// the terminator it found rather than assuming one. A caller that rejoins with a different
// terminator has changed the message, so the pieces it would need to avoid that come back with it.
function splitHttpMessage(text) {
  const source = text || '';
  const crlf = source.indexOf('\r\n\r\n');
  const lf = source.indexOf('\n\n');
  let index = -1;
  let separator = '';
  // A CRLF document contains no "\n\n" and an LF document contains no "\r\n\r\n", so this only has
  // to choose for a document that mixes them, and then the earlier blank line is the real one.
  if (crlf >= 0 && (lf < 0 || crlf <= lf)) {
    index = crlf;
    separator = '\r\n\r\n';
  } else if (lf >= 0) {
    index = lf;
    separator = '\n\n';
  }
  if (index < 0) return { found: false, head: source, separator: '', body: '' };
  return {
    found: true,
    head: source.slice(0, index),
    separator,
    body: source.slice(index + separator.length),
  };
}

// First value of a header out of a raw header block. The start line has no colon, so it cannot be
// mistaken for one.
function headerValueFrom(head, name) {
  const wanted = name.toLowerCase();
  const lines = String(head || '').split(/\r\n|\n/);
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    if (line.slice(0, colon).trim().toLowerCase() === wanted) return line.slice(colon + 1).trim();
  }
  return '';
}

// JSON.stringify emits \n and nothing else for its own line breaks, and escapes any newline inside a
// string value as the two characters \ and n. So rewriting every \n to \r\n retargets the
// indentation and cannot reach the data.
function formatJsonText(value, newline) {
  const text = JSON.stringify(value, null, 2);
  return newline === '\r\n' ? text.replace(/\n/g, '\r\n') : text;
}

// Rewrites the Content-Length of a header block, or adds one. Returns null rather than guessing when
// the block declares Content-Length twice: that disagreement is a smuggling probe often enough that
// silently collapsing it would delete the test.
function withContentLength(head, length, newline) {
  const lines = String(head || '').split(/\r\n|\n/);
  const declarations = lines.filter((line) => /^\s*content-length\s*:/i.test(line));
  if (declarations.length > 1) return null;
  const out = lines.map((line) => (/^\s*content-length\s*:/i.test(line) ? `Content-Length: ${length}` : line));
  if (declarations.length === 0) out.push(`Content-Length: ${length}`);
  return out.join(newline);
}

// ---------------------------------------------------------------------------
// Syntax highlighting for the request and response, the way Burp and Caido colour theirs.
//
// The one hard rule: highlighting NEVER changes a character. It wraps the exact bytes in coloured
// spans and nothing else, because the request mirror sits pixel-for-pixel behind an editable
// textarea and a single added or dropped character walks the caret off the text. Pretty-printing a
// JSON body is a separate, explicit step (prettifyRequestJson / the response Pretty toggle) that
// happens BEFORE this runs; by the time the colouriser sees the text, what it is given is what it
// paints. Palette is VS Code Dark+, which is the dark-repeater look these tools share.
const HL = {
  method: '#4ec9b0',
  path: '#d4d4d4',
  version: '#808080',
  status2: '#4ec9b0',
  status3: '#569cd6',
  status4: '#ce9178',
  status5: '#f14c4c',
  reason: '#d4d4d4',
  headerName: '#9cdcfe',
  headerValue: '#ce9178',
  jsonKey: '#9cdcfe',
  jsonString: '#ce9178',
  jsonNumber: '#b5cea8',
  jsonKeyword: '#569cd6',
  jsonPunct: '#808080',
  glyph: '#6a6a6a',
  plain: '#d0d0d0',
};

function statusClass(code) {
  const n = String(code)[0];
  return n === '2' ? 'status2' : n === '3' ? 'status3' : n === '4' ? 'status4'
    : n === '5' ? 'status5' : 'reason';
}

// Colours a JSON body into {text, cls} segments without reformatting it. Lenient: anything it cannot
// place is left plain, so a body that is nearly-but-not-JSON still renders rather than throwing.
function pushJsonSegments(push, body) {
  const n = body.length;
  let i = 0;
  while (i < n) {
    const c = body[i];
    if (c === '"') {
      let j = i + 1;
      let esc = false;
      while (j < n) {
        const cj = body[j];
        if (esc) esc = false;
        else if (cj === '\\') esc = true;
        else if (cj === '"') { j += 1; break; }
        j += 1;
      }
      let k = j;
      while (k < n && /\s/.test(body[k])) k += 1;
      push(body.slice(i, j), body[k] === ':' ? 'jsonKey' : 'jsonString');
      i = j;
    } else if (c === '{' || c === '}' || c === '[' || c === ']' || c === ':' || c === ',') {
      push(c, 'jsonPunct');
      i += 1;
    } else if (c === '-' || (c >= '0' && c <= '9')) {
      let j = i + 1;
      while (j < n && /[-+.0-9eE]/.test(body[j])) j += 1;
      push(body.slice(i, j), 'jsonNumber');
      i = j;
    } else if ((c === 't' && body.startsWith('true', i))
      || (c === 'f' && body.startsWith('false', i))
      || (c === 'n' && body.startsWith('null', i))) {
      const word = c === 't' ? 'true' : c === 'f' ? 'false' : 'null';
      push(word, 'jsonKeyword');
      i += word.length;
    } else {
      let j = i;
      while (j < n) {
        const cj = body[j];
        if (cj === '"' || cj === '{' || cj === '}' || cj === '[' || cj === ']' || cj === ':'
          || cj === ',' || cj === '-' || (cj >= '0' && cj <= '9')
          || cj === 't' || cj === 'f' || cj === 'n') break;
        j += 1;
      }
      if (j === i) j += 1;
      push(body.slice(i, j), 'plain');
      i = j;
    }
  }
}

// Splits an HTTP message into ordered {text, cls} segments. Terminators are their own plain segments
// so the renderer can find every line break. Covers every character of the input exactly once.
function httpSegments(text) {
  const src = text || '';
  if (!src) return [];
  const segs = [];
  const push = (t, cls) => { if (t) segs.push({ text: t, cls }); };
  const { found, head, separator, body } = splitHttpMessage(src);

  const headText = found ? head : src;
  const headParts = headText.split(/(\r\n|\n|\r)/);
  for (let idx = 0; idx < headParts.length; idx += 2) {
    const line = headParts[idx];
    const term = headParts[idx + 1] || '';
    if (idx === 0) {
      // Start line: a request (METHOD path HTTP/x) or a status line (HTTP/x 200 reason).
      let m;
      if (/^HTTP\/\d/i.test(line) && (m = line.match(/^(HTTP\/\S+)(\s+)(\d{3})(\s*)(.*)$/))) {
        push(m[1], 'version'); push(m[2], 'plain'); push(m[3], statusClass(m[3]));
        push(m[4], 'plain'); push(m[5], 'reason');
      } else if ((m = line.match(/^(\S+)(\s+)(.*?)(\s+)(HTTP\/\S+)\s*$/))) {
        push(m[1], 'method'); push(m[2], 'plain'); push(m[3], 'path');
        push(m[4], 'plain'); push(m[5], 'version');
      } else {
        push(line, 'plain');
      }
    } else if (line !== '') {
      const colon = line.indexOf(':');
      if (colon > 0) {
        push(line.slice(0, colon), 'headerName');
        push(':', 'jsonPunct');
        push(line.slice(colon + 1), 'headerValue');
      } else {
        push(line, 'plain');
      }
    }
    push(term, 'plain');
  }

  if (found) {
    push(separator, 'plain');
    const trimmed = body.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      pushJsonSegments(push, body);
    } else {
      push(body, 'plain');
    }
  }
  return segs;
}

// The background a highlighted parameter token gets in the request mirror. An rgba fill with alpha,
// so the syntax colour underneath still reads through. It is a PAINT-only property, exactly like a
// text colour, so it moves no glyph - see splitHighlightRuns and renderHttpNodes for why that matters.
const HL_MATCH_BG = 'rgba(255,99,99,0.30)';

// Partitions one already-coloured content chunk into runs, flagging the whole-token occurrences of
// any highlight term. "Whole token" means bounded by a non-[A-Za-z0-9_] character or a string end,
// matched case-sensitively: `token` inside `access_token` does NOT match, `access_token` as a whole
// does. The returned run texts concatenate back to `text` EXACTLY - this only slices the string, it
// never adds, drops or rewrites a byte - which is the invariant that keeps the coloured mirror
// character-for-character aligned with the textarea behind it. Overlapping matches from different
// terms merge through a per-character mark, so the partition is always clean and contiguous.
function splitHighlightRuns(text, terms) {
  const isWord = (ch) => ch !== undefined && /[A-Za-z0-9_]/.test(ch);
  const marks = new Array(text.length).fill(false);
  let any = false;
  terms.forEach((term) => {
    if (!term) return;
    let from = 0;
    let idx;
    while ((idx = text.indexOf(term, from)) !== -1) {
      const before = idx > 0 ? text[idx - 1] : undefined;
      const after = idx + term.length < text.length ? text[idx + term.length] : undefined;
      if (!isWord(before) && !isWord(after)) {
        for (let k = idx; k < idx + term.length; k += 1) marks[k] = true;
        any = true;
      }
      from = idx + term.length;
    }
  });
  if (!any) return [{ text, hl: false }];
  const runs = [];
  let start = 0;
  for (let i = 1; i <= text.length; i += 1) {
    if (i === text.length || marks[i] !== marks[start]) {
      runs.push({ text: text.slice(start, i), hl: marks[start] });
      start = i;
    }
  }
  return runs;
}

// Turns {text, cls} segments into React nodes. Splits every segment at its line breaks so a coloured
// run that spans lines still lays out one line per break, and drops in the line-ending glyph when the
// view asks for it. The glyph is zero-width so it never shifts the text the mirror sits behind.
function renderHttpNodes(segments, showEol, highlightTerms) {
  const nodes = [];
  // A non-empty term list turns parameter highlighting on; an absent or empty one is the exact prior
  // behaviour. responseNodes calls this with two args, so its third arg is undefined and it takes the
  // old path unchanged - the response mirror never highlights.
  const terms = highlightTerms && highlightTerms.length ? highlightTerms : null;
  let key = 0;
  segments.forEach((seg) => {
    const color = HL[seg.cls] || HL.plain;
    const parts = seg.text.split(/(\r\n|\n|\r)/);
    for (let i = 0; i < parts.length; i += 2) {
      const content = parts[i];
      const term = parts[i + 1];
      if (content) {
        if (terms) {
          // One span per run. A highlighted run adds ONLY backgroundColor + borderRadius on top of the
          // SAME base colour; it sets nothing - no width, padding, margin, border, font, letter-spacing
          // or display - that could change a glyph's advance, and the runs concatenate back to `content`
          // byte for byte, so the mirror stays aligned under the transparent textarea.
          splitHighlightRuns(content, terms).forEach((run, ri) => {
            nodes.push(
              <span
                key={`s${key}_${ri}`}
                style={run.hl
                  ? { color, backgroundColor: HL_MATCH_BG, borderRadius: 2 }
                  : { color }}
              >
                {run.text}
              </span>
            );
          });
        } else {
          nodes.push(<span key={`s${key}`} style={{ color }}>{content}</span>);
        }
        key += 1;
      }
      if (term !== undefined && term !== '') {
        if (showEol) {
          const glyph = term === '\r\n' ? `${GLYPH_CR}${GLYPH_LF}` : term === '\n' ? GLYPH_LF : GLYPH_CR;
          nodes.push(
            <span
              key={`g${key}`}
              style={{ display: 'inline-block', width: 0, whiteSpace: 'pre', overflow: 'visible', color: HL.glyph }}
            >
              {glyph}
            </span>
          );
          key += 1;
        }
        nodes.push('\n');
      }
    }
  });
  return nodes;
}

// Pretty-prints a JSON request body and fixes its Content-Length, or returns the request unchanged
// when there is nothing safe to do: no body, a chunked body, a body that is not JSON, one already
// formatted this way, or a request that declares Content-Length twice (a smuggling shape we must not
// collapse). This runs on load so a JSON request reads formatted by default, the way Burp and Caido
// show it; non-JSON bodies are never touched, and Raw mode still sends the buffer byte for byte.
function prettifyRequestJson(raw, newline) {
  const parts = splitHttpMessage(raw);
  if (!parts.found || parts.body.trim() === '') return raw;
  if (/^\s*transfer-encoding\s*:.*chunked/im.test(parts.head)) return raw;
  const trimmed = parts.body.trim();
  if (!(trimmed.startsWith('{') || trimmed.startsWith('['))) return raw;
  let value;
  try { value = JSON.parse(parts.body); } catch (err) { return raw; }
  const formatted = formatJsonText(value, newline);
  if (formatted === parts.body) return raw;
  const head = withContentLength(parts.head, byteLength(formatted), newline);
  if (head === null) return raw;
  return head + newline + newline + formatted;
}

// Builds the sitemap. Hosts at the top, then one node per path segment, leaves are individual
// captures. A path ending in a slash keeps its whole segment list as directories and shows the
// request itself as "/" underneath, the way Burp does, so a folder and the request to that folder
// stay distinguishable.
function captureTimeMs(value) {
  const n = Date.parse(value);
  return Number.isNaN(n) ? 0 : n;
}

// One leaf per ENDPOINT (method + host + path, query excluded), not one per capture. The captures
// that landed on that endpoint are folded into leaf.variants, deduped by the server's request/response
// signatures: identical exchanges collapse, and a differing query string, request body, status or
// response body survives as a distinct variant. The variants are the versions the sitemap click opens.
// See requestSig/responseSig on the server for what "distinct" means.
// The overlay key for a variant, matching the server's five-column identity
// (replayVariantMetaKey). NUL-joined in memory only; the wire form sends the parts as fields.
function variantMetaKey(method, host, path, reqSig, respSig) {
  return `${method}\u0000${host}\u0000${path}\u0000${reqSig || ''}\u0000${respSig || ''}`;
}

// ---------------------------------------------------------------------------
// Attack-vector overlay. The target's modelled attack vectors (method + host + a possibly templatized
// path, plus an insertion point and the parameter names) are matched against the sitemap's endpoints so
// a leaf that has a vector can be flagged and its parameters highlighted in the request. Pure helpers,
// no network and no state: buildTree takes the prebuilt index as a third argument and the caller owns
// the fetch. With no index (the default) every leaf reports zero vectors, so behaviour is unchanged.

// Strip a ":port" suffix from a sitemap host so an attack-vector domain (which never carries a port)
// can match a capture host that does. parseUrlParts yields parsed.host, which includes the port, so a
// capture on www.example.com:443 must still match a vector on www.example.com. An IPv6 literal is
// bracketed ([::1]:8080); its brackets are kept and only the trailing :port is dropped.
function hostnameOf(host) {
  const h = String(host == null ? '' : host);
  if (h.startsWith('[')) {
    const end = h.indexOf(']');
    return end === -1 ? h : h.slice(0, end + 1);
  }
  const colon = h.indexOf(':');
  return colon === -1 ? h : h.slice(0, colon);
}

// Does a concrete request path fit a (possibly templatized) attack-vector path? Both are split on "/",
// a single trailing empty segment is dropped on each so a trailing slash on either side never changes
// the result, and the two must then have the SAME number of segments. A template segment matches when
// it is byte-identical to the concrete one OR is a "{...}" placeholder, which stands for exactly one
// segment. Literal segments are compared case-sensitively, because URL paths are. A segment-count
// mismatch, or any literal that differs, is NO match: an unknown path must never borrow a vector.
function pathMatchesTemplate(concretePath, templatePath) {
  const norm = (p) => {
    const parts = String(p == null ? '' : p).split('/');
    if (parts.length > 1 && parts[parts.length - 1] === '') parts.pop();
    return parts;
  };
  const a = norm(concretePath);
  const b = norm(templatePath);
  if (a.length !== b.length) return false;
  for (let i = 0; i < b.length; i += 1) {
    const t = b[i];
    if (t.length >= 2 && t[0] === '{' && t[t.length - 1] === '}') continue;
    if (t !== a[i]) return false;
  }
  return true;
}

// Index the target's attack vectors by METHOD + hostname so a sitemap leaf can find candidates in one
// lookup and then confirm the path against each candidate's template. The stored entry keeps the fields
// the UI needs to explain WHY a leaf is flagged (the insertion point, the parameter names) plus a stable
// per-vector key for React. A vector with no method defaults to GET, matching buildTree's leaf method.
function buildAttackVectorIndex(vectors) {
  const index = new Map();
  (Array.isArray(vectors) ? vectors : []).forEach((v) => {
    if (!v) return;
    const method = String(v.method || 'GET').toUpperCase();
    const host = hostnameOf(v.domain || '');
    const path = v.path || '/';
    const key = `${method}\u0000${host}`;
    const entry = {
      path,
      insertion_point: v.insertion_point || '',
      parameters: Array.isArray(v.parameters) ? v.parameters : [],
      id: v.id != null ? v.id : null,
      vectorKey: `${method}\u0000${host}\u0000${path}\u0000${v.insertion_point || ''}\u0000${v.id != null ? v.id : ''}`,
    };
    const arr = index.get(key);
    if (arr) arr.push(entry); else index.set(key, [entry]);
  });
  return index;
}

// The vectors that apply to one sitemap leaf: same method, same hostname, and a path that fits the
// vector's (templatized) path. Returns a fresh array - [] when the index is absent/empty or nothing
// matches - and never throws on a null index, which is simply the zero-vectors case.
function matchAttackVectors(index, method, host, path) {
  if (!index || index.size === 0) return [];
  const key = `${String(method || 'GET').toUpperCase()}\u0000${hostnameOf(host)}`;
  const candidates = index.get(key);
  if (!candidates || candidates.length === 0) return [];
  return candidates.filter((entry) => pathMatchesTemplate(path, entry.path));
}

function buildTree(rows, variantMeta, avIndex = null) {
  const meta = variantMeta || {};
  const hosts = new Map();

  rows.forEach((row) => {
    const parts = parseUrlParts(row.url || row.endpoint || '');
    const host = row.host || parts.host || 'unknown';
    // The server-derived path already excludes the query; parseUrlParts agrees (pathname). Prefer the
    // server value so the endpoint key and the server's grouping cannot drift.
    const path = row.path || parts.path || '/';
    const segments = path.split('/').filter(Boolean);
    const endsWithSlash = path.endsWith('/') || segments.length === 0;
    const dirs = endsWithSlash ? segments : segments.slice(0, -1);
    const leafLabel = endsWithSlash ? '/' : segments[segments.length - 1];
    const method = (row.method || 'GET').toUpperCase();

    if (!hosts.has(host)) {
      hosts.set(host, { key: `h:${host}`, name: host, dirs: new Map(), groups: new Map(), count: 0 });
    }
    let node = hosts.get(host);
    let key = node.key;
    dirs.forEach((segment) => {
      key = `${key}/${segment}`;
      if (!node.dirs.has(segment)) {
        node.dirs.set(segment, { key, name: segment, dirs: new Map(), groups: new Map(), count: 0 });
      }
      node = node.dirs.get(segment);
    });

    // One group per endpoint within this node. The node fixes host + dirs, so method + path is the
    // whole identity, and it is stable across searches so it can key React rows and the selection.
    const epKey = `${method}\u0000${host}\u0000${path}`;
    let group = node.groups.get(epKey);
    if (!group) {
      group = { epKey, label: leafLabel, method, path, host, rows: [] };
      node.groups.set(epKey, group);
    }
    group.rows.push(row);
  });

  const makeLeaf = (group) => {
    // Newest first, so the canonical variant the leaf opens with is the most recent recording. The
    // rows arrive oldest-first (server ORDER BY timestamp ASC); reversing before the stable descending
    // sort makes captures that share a millisecond resolve newest-first too, instead of the stable sort
    // preserving the oldest at the front on a tie.
    const sorted = [...group.rows].reverse().sort((a, b) => captureTimeMs(b.timestamp) - captureTimeMs(a.timestamp));
    const byKey = new Map();
    const order = [];
    sorted.forEach((r) => {
      // Dedupe on the server signatures. If BOTH are absent (a backend too old to send them), fall
      // back to the capture id so distinct captures are never silently collapsed into one variant -
      // over-showing is safe, over-merging loses recordings.
      const vkey = (r.request_sig || r.response_sig)
        ? `${r.request_sig || ''}\u0000${r.response_sig || ''}`
        : `id\u0000${r.id}`;
      if (byKey.has(vkey)) { byKey.get(vkey).count += 1; return; }
      // The overlay row for this variant, if the operator has named it or made it primary. Keyed by the
      // server's five-column identity, so an empty-sig variant (legacy) simply never matches and keeps
      // its default name.
      const mk = variantMetaKey(group.method, group.host, group.path, r.request_sig || '', r.response_sig || '');
      const m = meta[mk];
      const source = r.source || '';
      const v = {
        id: r.id,
        method: group.method,
        host: group.host,
        path: group.path,
        status: r.status_code != null ? r.status_code : r.status,
        size: r.size,
        mime: r.mime_type,
        url: r.url || '',
        query: parseUrlParts(r.url || '').query || '',
        hasQuery: !!parseUrlParts(r.url || '').query,
        timestamp: r.timestamp,
        requestSig: r.request_sig || '',
        responseSig: r.response_sig || '',
        variantSig: vkey,
        source,
        // Name: the operator's if they set one, otherwise the source label the server derived
        // ("Active detection", "Manual crawl"). A variant with no discernible source still gets a word.
        name: (m && m.name) ? m.name : (source || 'Recorded'),
        nameCustom: !!(m && m.name),
        isPrimary: !!(m && m.is_primary),
        // Hidden is a display choice stored in the overlay; the capture behind it is untouched. A hidden
        // variant is dropped from the list and can never be the effective primary.
        hidden: !!(m && m.hidden),
        count: 1,
        row: r,
      };
      byKey.set(vkey, v);
      order.push(vkey);
    });
    const variants = order.map((k) => byKey.get(k));
    // The PRIMARY is the operator's chosen VISIBLE variant, or the newest visible recording when none is
    // chosen. It is the one whose status the sitemap shows and the one a leaf click opens. Marked on the
    // variant so the column's star reflects the EFFECTIVE primary, not only a stored one.
    const visible = variants.filter((v) => !v.hidden);
    const primary = visible.find((v) => v.isPrimary) || visible[0] || null;
    // Clear any stale stored-primary flag on hidden variants so exactly one visible variant is starred.
    variants.forEach((v) => { if (v !== primary) v.isPrimary = false; });
    if (primary) primary.isPrimary = true;
    // The attack vectors modelled for THIS endpoint (method + host + templatized path). Empty when no
    // index was passed - the default - so a leaf looks exactly as it does today in that case. matchAttack-
    // Vectors already returns [], the `|| []` only guards a future change to the helper.
    const attackVectors = matchAttackVectors(avIndex, group.method, group.host, group.path) || [];
    return {
      key: group.epKey,
      attackVectors,
      hasAttackVector: attackVectors.length > 0,
      label: group.label,
      method: group.method,
      host: group.host,
      path: group.path,
      status: primary ? primary.status : undefined,
      primaryStatus: primary ? primary.status : undefined,
      primaryId: primary ? primary.id : null,
      hasQuery: visible.some((v) => v.hasQuery),
      url: primary ? primary.url : (visible[0] ? visible[0].url : ''),
      variants,
      variantCount: visible.length,
      hiddenCount: variants.length - visible.length,
      hasVisible: visible.length > 0,
      captureCount: group.rows.length,
      canonicalId: visible[0] ? visible[0].id : null,
      row: primary ? primary.row : (visible[0] ? visible[0].row : null),
    };
  };

  const finish = (node) => {
    node.leaves = Array.from(node.groups.values()).map(makeLeaf);
    // Count ENDPOINTS under this node now, not captures. Fully-hidden endpoints (every variant hidden)
    // are not counted, so the folder badge matches the default sitemap, which does not draw them.
    let count = node.leaves.filter((l) => l.hasVisible).length;
    // Attack-vector tally is independent of the visible-endpoint count: it counts leaves that carry at
    // least one matched vector plus the same tally from every child, so a folder badge can show how many
    // flagged endpoints sit beneath it. avIndex null/empty => no leaf has one => this is 0 everywhere.
    let avCount = node.leaves.filter((l) => l.hasAttackVector).length;
    const children = Array.from(node.dirs.values()).sort((a, b) => a.name.localeCompare(b.name));
    children.forEach((child) => {
      count += finish(child);
      avCount += child.attackVectorCount || 0;
    });
    node.children = children;
    node.leaves.sort((a, b) => (a.label.localeCompare(b.label) || a.method.localeCompare(b.method)));
    node.count = count;
    node.attackVectorCount = avCount;
    return count;
  };

  const roots = Array.from(hosts.values()).sort((a, b) => a.name.localeCompare(b.name));
  roots.forEach(finish);
  return roots;
}

// One text style, shared by the textarea and the mirror behind it. Any divergence between the two
// shows up immediately as glyphs drifting out of line, so they read from the same object.
const MONO_STYLE = {
  fontFamily: 'Menlo, Consolas, "Courier New", monospace',
  fontSize: '0.78rem',
  lineHeight: '1.35',
  padding: '0.5rem',
  margin: 0,
  border: 'none',
  letterSpacing: 'normal',
  tabSize: 4,
  whiteSpace: 'pre',
};

// The wrap toggle, as CSS. Both objects are spread over MONO_STYLE so the textarea and the mirror
// behind it can never end up on different sides of the switch. break-word rather than normal because
// the thing that needs wrapping is usually one 4,000 character token with no space in it: a base64
// blob or a single line of JSON, which is exactly the case "wrap at word boundaries" cannot help.
const WRAP_ON = { whiteSpace: 'pre-wrap', overflowWrap: 'break-word', wordBreak: 'normal' };
const WRAP_OFF = { whiteSpace: 'pre', overflowWrap: 'normal', wordBreak: 'normal' };

// A raw-bytes handover, in one place so the pane and its callers cannot disagree about its shape.
//   raw_request  the bytes to put in the editor. Required; anything else is ignored.
//   base_url     where to send them. Optional, but see the note on loadRawBytes: without it the
//                framework falls back to the Host header and assumes https.
//   label        where the bytes came from, in words, for the REQUEST header. Optional.
const rawHandoverBytes = (payload) => (
  payload && typeof payload.raw_request === 'string' ? payload.raw_request : ''
);

export const SingleRequestPane = ({
  activeTarget, loadCaptureId, loadRawRequest, onLoadedCapture,
}) => {
  const targetId = activeTarget && activeTarget.id;

  // Sitemap and search.
  const [query, setQuery] = useState('');
  const [captures, setCaptures] = useState([]);
  // The variant overlay: names and the one primary per endpoint, keyed by variantMetaKey. A sparse
  // map - only variants the operator has renamed or made primary have a row. buildTree reads it, so
  // the tree, the sitemap status and the variants column all reflect the same choices.
  const [variantMeta, setVariantMeta] = useState({});
  // The attack-vector overlay: every vector the Consolidate/Investigate passes have modelled for this
  // target, fetched once per target the same way variantMeta is. buildAttackVectorIndex turns it into a
  // method+host lookup and buildTree marks the leaves whose endpoint carries one, so the sitemap, the
  // request-mirror highlight and the "attack vectors only" filter all read the same list. Empty is the
  // whole-feature-off state and changes nothing the operator sees today.
  const [attackVectors, setAttackVectors] = useState([]);
  // Sitemap filter: show only endpoints that carry an attack vector. Off by default; reset per target.
  const [attackVectorsOnly, setAttackVectorsOnly] = useState(false);
  const [total, setTotal] = useState(0);
  const [corpusTotal, setCorpusTotal] = useState(null);
  const [truncated, setTruncated] = useState(false);
  const [searching, setSearching] = useState(false);
  const [queryError, setQueryError] = useState('');
  const [expanded, setExpanded] = useState({});
  // selectedId now holds the ENDPOINT key of the selected sitemap leaf (method+host+path), not a
  // capture id, because a leaf is one endpoint. The loaded capture within it is versionCaptureId.
  const [selectedId, setSelectedId] = useState(null);
  // endpointVariants is DERIVED from the tree below (keyed by selectedId), never stored, so a
  // re-search that rebuilds the leaves can never leave it describing captures the filter has since
  // dropped. It is the selected endpoint's deduped variants - the recorded captures shown as versions
  // - or empty when nothing is selected or a request was handed over from outside the sitemap.
  const searchSeq = useRef(0);

  // Request pane.
  const [rawRequest, setRawRequest] = useState('');
  const [loadedRequest, setLoadedRequest] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [eol, setEol] = useState('CRLF');
  const [loadingCapture, setLoadingCapture] = useState(false);

  // Response pane.
  const [rawResponse, setRawResponse] = useState('');
  const [respBytes, setRespBytes] = useState(null);
  const [respMs, setRespMs] = useState(null);
  const [respStatus, setRespStatus] = useState(null);
  const [respNote, setRespNote] = useState('');
  const [replaying, setReplaying] = useState(false);
  const [hasReplayed, setHasReplayed] = useState(false);
  // What the response pane is currently showing, so it can say WHOSE response it is:
  //   'recorded'   the response the crawl stored for this capture, shown on load next to the request.
  //   'live'       the response a Replay just produced.
  //   'unrecorded' a capture was loaded but the crawl stored no response for it (status 0).
  //   null         nothing loaded, or an edited/handed-over request with no response of its own.
  // A recorded response next to a request the operator has since edited is flagged, because at that
  // point the two no longer belong together.
  const [responseSource, setResponseSource] = useState(null);

  // The redirect chain, when one was followed. Every hop, in order, the last of which is the final
  // response. hopIndex is which one the response pane is showing.
  const [hops, setHops] = useState([]);
  const [hopIndex, setHopIndex] = useState(0);
  const [redirectCapped, setRedirectCapped] = useState(false);

  // Controls.
  const [showEol, setShowEol] = useState(false);
  const [rawMode, setRawMode] = useState(false);
  // On by default: the panes hold long single-line tokens (a base64 blob, one line of minified
  // JSON) far more often than not, and sideways scrolling to read them is the worse default.
  const [wrapText, setWrapText] = useState(true);
  // On by default. Following the chain is what makes a click show the exchange the operator meant,
  // not a 302 they then have to chase by hand; every hop is still listed, so nothing is hidden by
  // following it. Off is there for when the 3xx itself is the thing being looked at.
  const [followRedirects, setFollowRedirects] = useState(true);
  const [maxRedirects, setMaxRedirects] = useState(10);
  // 'pretty' or 'raw'. Only consulted when the body actually is JSON; anything else is raw whatever
  // this says. Sticky across sends, because an operator who switched to raw wants raw.
  const [responseFormat, setResponseFormat] = useState('pretty');
  // What the Format JSON body button did, or why it declined. Not an alert: it sits under the
  // button, and the operator is looking at the button.
  const [formatNote, setFormatNote] = useState('');

  // Where the bytes in the editor came from, when they did not come from the corpus. Empty for
  // everything the sitemap loaded, because for those the selected row already says it. Non-empty
  // means the request was handed over from somewhere else -- a tool finding, today -- and it is
  // shown next to REQUEST and again in the versions column, which cannot version it.
  const [handoverNote, setHandoverNote] = useState('');

  // Confirmations render as a small modal stacked on top of this pane, never as a window.confirm. A
  // browser dialog freezes the whole page (and, in the extension, every subsequent command), cannot
  // be styled, and would sit outside the fullscreen modal. askConfirm returns a promise the modal's
  // buttons resolve, so every call site stays a one-line await and the big modal never closes.
  const [confirmDialog, setConfirmDialog] = useState(null);
  const confirmResolveRef = useRef(null);
  const askConfirm = useCallback((opts) => new Promise((resolve) => {
    confirmResolveRef.current = resolve;
    setConfirmDialog({
      title: (opts && opts.title) || 'Are you sure?',
      body: (opts && opts.body) || '',
      confirmLabel: (opts && opts.confirmLabel) || 'Confirm',
      variant: (opts && opts.variant) || 'danger',
    });
  }), []);
  const resolveConfirm = useCallback((result) => {
    setConfirmDialog(null);
    const resolve = confirmResolveRef.current;
    confirmResolveRef.current = null;
    if (resolve) resolve(result);
  }, []);

  // Versions column. versionCaptureId is the capture the column currently describes, and it is also
  // the gate on the whole feature: with nothing loaded there is no root to hang a tree off, so a
  // scratch buffer is never saved. versionsAvailable goes false only when the framework does not
  // serve these routes at all, which has to leave the repeater working rather than break it.
  const [versions, setVersions] = useState([]);
  const [versionCaptureId, setVersionCaptureId] = useState(null);
  const [activeVersionId, setActiveVersionId] = useState(null);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [versionsError, setVersionsError] = useState('');
  const [versionsAvailable, setVersionsAvailable] = useState(true);
  const [savingVersion, setSavingVersion] = useState(false);
  const [versionNote, setVersionNote] = useState('');
  const [renamingId, setRenamingId] = useState(null);
  const [renameText, setRenameText] = useState('');
  // The variant being renamed (its representative capture id) and the text in the box. Kept separate
  // from the version rename above: a variant is a recording, a version is an edit, and their rename
  // targets and endpoints differ.
  const [variantRenamingId, setVariantRenamingId] = useState(null);
  const [variantRenameText, setVariantRenameText] = useState('');
  // Reveal hidden variants (and the endpoints whose every variant is hidden) so they can be restored.
  const [showHiddenVariants, setShowHiddenVariants] = useState(false);

  const textareaRef = useRef(null);
  const mirrorRef = useRef(null);

  // The last capture id this pane asked the framework for, whether the request came from a tree
  // click or from the loadCaptureId prop. The prop effect reads it so that re-rendering with the
  // same id does not refetch, and so that a tree click in between makes the same id loadable again.
  const requestedCaptureRef = useRef(null);
  // The same thing for the raw-bytes handover, held by IDENTITY rather than by value. Two findings
  // can carry byte-identical requests, and re-handing the same object over on a re-render must not
  // reload, so the object the parent passed is the token. The parent makes a new one per handover.
  const requestedRawRef = useRef(null);
  // The parent's callback and the current dirty flag, held in refs so neither of them re-arms the
  // load effect. A changing callback identity must not be able to trigger a second fetch.
  const onLoadedRef = useRef(onLoadedCapture);
  const dirtyRef = useRef(false);

  // The save path runs after awaits, inside callbacks that were created several renders ago, so it
  // cannot read the buffer out of a closure and cannot read it out of state either: both would be
  // whatever they were when the callback was made. These four refs are refreshed on every render
  // and are the save path's only source of truth about what is in the editor.
  const bufferRef = useRef('');
  const baselineRef = useRef('');
  const baseUrlRef = useRef('');
  const activeVersionRef = useRef(null);
  const versionCaptureRef = useRef(null);
  const versionsAvailableRef = useRef(true);
  // One save at a time. The idle timer and a Replay click can both decide to save the same bytes
  // within a few milliseconds of each other, and two POSTs would be two rows for one edit.
  const savePromiseRef = useRef(null);
  const versionsSeq = useRef(0);
  // targetId is read through a ref by everything the version column does, so that loadVersions,
  // saveVersionIfDirty and loadCapture can all be created once and never change identity. A
  // callback that changes identity on a target switch would re-arm the loadCaptureId effect below,
  // and that effect re-running means the previous target's capture loaded into a pane now pointed
  // at a different host.
  const targetIdRef = useRef(null);

  const dirty = rawRequest !== loadedRequest;

  const runSearch = useCallback(async (text) => {
    if (!targetId) return;
    const seq = searchSeq.current + 1;
    searchSeq.current = seq;
    setSearching(true);
    try {
      const res = await fetch(
        `/api/replay-request/${targetId}/captures?q=${encodeURIComponent(text)}&limit=${RESULT_LIMIT}`
      );
      const body = await res.text();
      let data = null;
      try { data = body ? JSON.parse(body) : null; } catch (err) { data = null; }
      if (seq !== searchSeq.current) return;

      // A broken query keeps the previous tree on screen. Blanking it would make a syntax error
      // look exactly like a search that matched nothing, which is the one failure this box has to
      // never produce.
      if (!res.ok) {
        setQueryError(pickString(data, ['error', 'message']) || body || `Search failed (${res.status})`);
        return;
      }
      const inlineError = pickString(data, ['error']);
      if (inlineError) { setQueryError(inlineError); return; }

      const rows = Array.isArray(data)
        ? data
        : ((data && (data.captures || data.results || data.rows)) || []);
      setCaptures(rows);
      // The denominator has to be how many captures MATCHED, not how many exist. `total` is the
      // size of the whole corpus, so reading it first turns "79 of 79" into "79 of 169" and tells
      // the operator 90 results are hidden behind a limit they never hit. `matched` first.
      const reported = pickNumber(data, ['matched', 'total_matched', 'match_count']);
      setTotal(reported == null ? rows.length : reported);
      setCorpusTotal(pickNumber(data, ['total']));
      setTruncated(!!(data && (data.truncated || data.is_truncated)));
      setQueryError('');
    } catch (err) {
      if (seq === searchSeq.current) setQueryError(`Could not reach the framework: ${err.message}`);
    } finally {
      if (seq === searchSeq.current) setSearching(false);
    }
  }, [targetId]);

  // Debounced. Thousands of rows behind this box, so one request per keystroke is not an option.
  useEffect(() => {
    if (!targetId) return undefined;
    const timer = setTimeout(() => { runSearch(query); }, 300);
    return () => clearTimeout(timer);
  }, [query, targetId, runSearch]);

  // The variant overlay is per target, not per query, so it is fetched once per target and again after
  // a rename or a primary change. buildTree merges it, so the sitemap status and the variants column
  // both follow it without a re-search.
  const loadVariantMeta = useCallback(async () => {
    if (!targetId) { setVariantMeta({}); return; }
    try {
      const res = await fetch(`/api/replay-request/${targetId}/variant-meta`);
      if (!res.ok) { setVariantMeta({}); return; }
      const data = await res.json().catch(() => null);
      const rows = (data && Array.isArray(data.variant_meta)) ? data.variant_meta : [];
      const map = {};
      rows.forEach((m) => {
        if (!m) return;
        map[variantMetaKey(m.method, m.host, m.path, m.request_sig, m.response_sig)] = {
          name: m.name || '',
          is_primary: !!m.is_primary,
          hidden: !!m.hidden,
        };
      });
      setVariantMeta(map);
    } catch {
      setVariantMeta({});
    }
  }, [targetId]);

  useEffect(() => { loadVariantMeta(); }, [loadVariantMeta]);

  // The attack-vector overlay is per target, fetched once per target, exactly like loadVariantMeta.
  // Reuses the existing GET /attack-vectors route (no server change); fail-closed to empty so a build
  // that does not serve it, a 4xx/5xx, or a network error simply leaves every leaf unmarked.
  const loadAttackVectors = useCallback(async () => {
    if (!targetId) { setAttackVectors([]); return; }
    try {
      const res = await fetch(`/api/attack-vectors/${targetId}`);
      if (!res.ok) { setAttackVectors([]); return; }
      const data = await res.json().catch(() => null);
      setAttackVectors((data && Array.isArray(data.vectors)) ? data.vectors : []);
    } catch {
      setAttackVectors([]);
    }
  }, [targetId]);

  useEffect(() => { loadAttackVectors(); }, [loadAttackVectors]);

  // Rename a variant, or make it the endpoint's primary. Both are one POST to the overlay; the reload
  // is what makes the change show up in the sitemap and the column at once.
  const postVariantMeta = useCallback(async (variant, patch) => {
    const target = targetIdRef.current || targetId;
    if (!target || !variant) return;
    try {
      await fetch(`/api/replay-request/${target}/variant-meta`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: variant.method,
          host: variant.host,
          path: variant.path,
          request_sig: variant.requestSig,
          response_sig: variant.responseSig,
          ...patch,
        }),
      });
    } catch {
      // Swallowed: the reload below reflects whatever actually stuck rather than an optimistic guess.
    }
    loadVariantMeta();
  }, [targetId, loadVariantMeta]);

  const beginVariantRename = (variant) => {
    if (!variant) return;
    setVariantRenamingId(variant.id);
    // Seed with the CUSTOM name only, so an empty box means "back to the source default" rather than
    // pinning the default in as a custom name.
    setVariantRenameText(variant.nameCustom ? (variant.name || '') : '');
  };

  const commitVariantRename = (variant) => {
    const text = variantRenameText.trim();
    setVariantRenamingId(null);
    if (!variant) return;
    // No change if the box holds what is already the custom name (or is empty and there was none).
    const current = variant.nameCustom ? String(variant.name || '').trim() : '';
    if (text === current) return;
    postVariantMeta(variant, { name: text });
  };

  const setPrimaryVariant = (variant) => {
    if (!variant || variant.isPrimary) return;
    postVariantMeta(variant, { set_primary: true });
  };

  // "Delete" a variant HIDES it from the list. It is NOT destructive: the captures behind it stay in
  // the corpus for every other tool, and it is reversible (unhide, or the "show hidden" toggle). Because
  // it is reversible there is no confirm - a hide the operator did not mean is one click to undo. The
  // overlay reload rebuilds the tree, dropping the variant from the column and the sitemap.
  const hideVariant = (variant) => {
    if (!variant) return;
    postVariantMeta(variant, { hidden: true });
  };

  const unhideVariant = (variant) => {
    if (!variant) return;
    postVariantMeta(variant, { hidden: false });
  };

  // Fresh target, fresh state. A previous target's request left in the pane is a request sent to
  // the wrong host the moment somebody hits Replay.
  useEffect(() => {
    setQuery('');
    setCaptures([]);
    setVariantMeta({});
    setAttackVectors([]);
    setAttackVectorsOnly(false);
    setVariantRenamingId(null);
    setShowHiddenVariants(false);
    setTotal(0);
    setCorpusTotal(null);
    setTruncated(false);
    setQueryError('');
    setExpanded({});
    setSelectedId(null);
    setRawRequest('');
    setLoadedRequest('');
    setBaseUrl('');
    setRawResponse('');
    setRespBytes(null);
    setRespMs(null);
    setRespStatus(null);
    setRespNote('');
    setResponseSource(null);
    setHasReplayed(false);
    setHops([]);
    setHopIndex(0);
    setRedirectCapped(false);
    setFormatNote('');
    setHandoverNote('');
    setShowEol(false);
    setRawMode(false);
    setVersions([]);
    setVersionCaptureId(null);
    setActiveVersionId(null);
    setVersionsError('');
    setVersionNote('');
    setRenamingId(null);
    // Availability is a property of the framework, not of the target, so it is not reset here. A
    // build that does not serve these routes will not start serving them because the operator
    // picked a different scope target, and re-discovering that on every switch means one failed
    // fetch per switch.
    requestedCaptureRef.current = null;
    requestedRawRef.current = null;
    versionsSeq.current += 1;
  }, [targetId]);

  // Both refs are refreshed before the load effect below runs, because effects fire in declaration
  // order. That is what lets the load effect see this render's dirty flag.
  useEffect(() => { onLoadedRef.current = onLoadedCapture; }, [onLoadedCapture]);
  useEffect(() => { dirtyRef.current = dirty; }, [dirty]);

  // No dependency array on purpose. These mirror this render's values for the async save path, and
  // an omitted value here is a save that writes down bytes the operator has already replaced.
  useEffect(() => {
    bufferRef.current = rawRequest;
    baselineRef.current = loadedRequest;
    baseUrlRef.current = baseUrl;
    activeVersionRef.current = activeVersionId;
    versionCaptureRef.current = versionCaptureId;
    versionsAvailableRef.current = versionsAvailable;
    targetIdRef.current = targetId;
  });

  // The method+host lookup the tree uses to mark leaves. Rebuilt only when the overlay changes.
  const avIndex = useMemo(() => buildAttackVectorIndex(attackVectors), [attackVectors]);
  const tree = useMemo(() => buildTree(captures, variantMeta, avIndex), [captures, variantMeta, avIndex]);
  const leafCount = useMemo(() => tree.reduce((sum, node) => sum + node.count, 0), [tree]);

  // How many endpoints across the whole tree carry a modelled attack vector. Drives the filter
  // toggle's count and lets it disable itself when there is nothing to filter to. It rolls up the
  // per-node counts buildTree already summed, so it is 0 (and the toggle inert) whenever the attack
  // vector index is empty - exactly today's behaviour before the model is loaded.
  const avEndpointCount = useMemo(
    () => tree.reduce((sum, node) => sum + (node.attackVectorCount || 0), 0),
    [tree]
  );

  // The selected endpoint's variants, derived from the freshly built tree rather than snapshotted on
  // click. This is what keeps the versions column, its count, and the sitemap's own variant badge in
  // agreement after a re-search: they all read the same leaf. Empty when nothing in the tree matches
  // selectedId - a filtered-out endpoint, a handed-over request (selectedId null), or a fresh pane.
  const endpointVariants = useMemo(() => {
    if (!selectedId) return [];
    const findIn = (nodes) => {
      for (const node of nodes) {
        for (const leaf of (node.leaves || [])) {
          if (leaf.key === selectedId) return leaf.variants || [];
        }
        const deeper = findIn(node.children || []);
        if (deeper) return deeper;
      }
      return null;
    };
    return findIn(tree) || [];
  }, [tree, selectedId]);

  // The attack vectors that match the SELECTED endpoint. selectedId is the leaf epKey, method + host +
  // path NUL-joined (buildTree), so it is split back into those three parts and matched. matchAttackVectors
  // upcases the method and strips the host port itself, so the raw epKey parts can be passed straight in.
  // Empty when nothing is selected, the index is empty, or no vector matches - the ZERO-behaviour default.
  const selectedVectors = useMemo(() => {
    if (!selectedId) return [];
    const parts = String(selectedId).split('\u0000');
    if (parts.length < 3) return [];
    return matchAttackVectors(avIndex, parts[0], parts[1], parts.slice(2).join('\u0000'));
  }, [selectedId, avIndex]);

  // The distinct parameter names to highlight, in first-seen order. The server sends parameters as a
  // string[], but we read defensively so a future object shape cannot throw here. Blank names drop.
  const highlightTerms = useMemo(() => {
    const seen = new Set();
    const out = [];
    selectedVectors.forEach((v) => {
      (v.parameters || []).forEach((raw) => {
        const name = typeof raw === 'string' ? raw : (raw && (raw.name || raw.param || raw.key));
        const term = typeof name === 'string' ? name.trim() : '';
        if (term && !seen.has(term)) { seen.add(term); out.push(term); }
      });
    });
    return out;
  }, [selectedVectors]);

  // A one-line legend: which insertion point(s) the matched vectors use, then the highlighted names.
  // Empty whenever nothing is highlighted, so the badge simply does not render.
  const highlightLegend = useMemo(() => {
    if (highlightTerms.length === 0) return '';
    const points = [];
    selectedVectors.forEach((v) => {
      const p = v.insertion_point || '';
      if (p && !points.includes(p)) points.push(p);
    });
    const where = points.join(', ');
    return where ? `${where} ${highlightTerms.join(', ')}` : highlightTerms.join(', ');
  }, [selectedVectors, highlightTerms]);

  // v1, v2, v3 down the column. Numbered by position rather than stored, because the number is a
  // reading aid and the identity is the id; a deletion renumbering the rows below it is exactly
  // what an operator expects from a list they are looking at.
  const versionOrdinals = useMemo(() => {
    const map = {};
    let n = 0;
    versions.forEach((v) => {
      if (!v || !v.id) return;
      if (v.is_original) { map[v.id] = 0; return; }
      n += 1;
      map[v.id] = n;
    });
    return map;
  }, [versions]);

  // With a query in the box and a small result set, opening everything is what the operator wanted
  // by typing it. Anything they toggled by hand wins over this.
  const autoExpand = query.trim() !== '' && leafCount > 0 && leafCount <= 300;

  const isOpen = useCallback((key, depth) => {
    if (Object.prototype.hasOwnProperty.call(expanded, key)) return expanded[key];
    if (autoExpand) return true;
    return depth === 0;
  }, [expanded, autoExpand]);

  const toggleNode = (key, depth) => {
    const current = isOpen(key, depth);
    setExpanded((prev) => ({ ...prev, [key]: !current }));
  };

  // ---------------------------------------------------------------------------
  // Versions
  // ---------------------------------------------------------------------------

  // The list for one capture. The GET materialises the original if it is not there yet, so this is
  // also what puts the observed request at the top of the column the first time a capture is
  // opened; there is no separate "start versioning" call to forget to make.
  const loadVersions = useCallback(async (captureId, options) => {
    const target = targetIdRef.current;
    if (!target || !captureId) return;
    const selectOriginal = !!(options && options.selectOriginal);
    const seq = versionsSeq.current + 1;
    versionsSeq.current = seq;
    setVersionsLoading(true);
    try {
      const res = await fetch(
        `/api/replay-request/${target}/versions?capture_id=${encodeURIComponent(captureId)}`
      );
      const body = await res.text();
      let data = null;
      try { data = body ? JSON.parse(body) : null; } catch (err) { data = null; }
      if (seq !== versionsSeq.current) return;

      // A 404 here is the route not being served, not a missing version: the list handler has no
      // 404 of its own. A framework that predates this feature must leave the repeater working, so
      // the column stands itself down instead of painting an error the operator cannot act on.
      if (res.status === 404) {
        setVersionsAvailable(false);
        versionsAvailableRef.current = false;
        setVersions([]);
        setActiveVersionId(null);
        activeVersionRef.current = null;
        setVersionsError('');
        return;
      }
      if (!res.ok) {
        setVersionsError(versionErrorMessage(data, body, res.status));
        return;
      }
      const rows = Array.isArray(data && data.versions) ? data.versions : [];
      setVersions(rows);
      setVersionsError('');
      setVersionsAvailable(true);
      versionsAvailableRef.current = true;
      if (selectOriginal) {
        const original = rows.find((v) => v && v.is_original);
        const next = original ? original.id : null;
        setActiveVersionId(next);
        activeVersionRef.current = next;
      }
    } catch (err) {
      if (seq === versionsSeq.current) {
        setVersionsError(`Could not reach the framework: ${err.message}`);
      }
    } finally {
      if (seq === versionsSeq.current) setVersionsLoading(false);
    }
  }, []);

  // The buffer becomes the new baseline. Written to the ref as well as to state, because a second
  // save can be decided in the same tick and would otherwise still see the old baseline and send
  // the same bytes again.
  const adoptBaseline = useCallback((bytes) => {
    baselineRef.current = bytes;
    setLoadedRequest(bytes);
  }, []);

  // The whole of the auto-save. Returns what happened rather than leaving the caller to re-read
  // state that React may not have committed yet:
  //   { saved, wasDirty }  saved false with wasDirty true is the ONLY case in which the caller
  //                        falls back to the unsaved-edit confirmation.
  const saveVersionIfDirty = useCallback(async () => {
    const startingBytes = bufferRef.current;
    if (startingBytes === baselineRef.current) return { saved: false, wasDirty: false };

    const target = targetIdRef.current;
    const captureId = versionCaptureRef.current;
    // No capture means no root to hang the tree off. A request typed into an empty pane is a
    // scratch request, and inventing a root for it would put a fiction at the top of the column
    // and save a half-typed line every time the operator paused.
    if (!target || !captureId || !versionsAvailableRef.current || startingBytes.trim() === '') {
      return { saved: false, wasDirty: true };
    }

    // Serialise. The idle timer and a Replay click can decide to save the same edit within a few
    // milliseconds of each other, and two POSTs would be two rows for one edit.
    if (savePromiseRef.current) {
      try { await savePromiseRef.current; } catch (err) { /* its own caller reported it */ }
      // Compared against the bytes THIS call was asked to preserve, not against whatever is in the
      // editor now: the question is whether our edit got written down, and the answer is yes only
      // if it is the thing the baseline moved to.
      if (baselineRef.current === startingBytes) return { saved: true, wasDirty: true };
    }

    const attempt = (async () => {
      // The bytes read at ENTRY, not the ones in the editor now. If a queued save delayed this one
      // and the operator kept typing, the entry bytes are the ones the action was about -- the ones
      // that were on screen when Replay was pressed, and therefore the ones that went out. Saving
      // whatever is in the editor at this instant instead would leave the sent request unrecorded.
      // Anything typed since stays dirty and the idle timer writes it down as a child of this row.
      const bytes = startingBytes;
      const base = baseUrlRef.current;
      // The parent is read HERE rather than at entry: a save we queued behind has just created a
      // row, and these bytes were edited on top of it.
      const parentId = activeVersionRef.current || '';
      setSavingVersion(true);
      setVersionNote('');
      try {
        const res = await fetch(`/api/replay-request/${target}/versions`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            capture_id: captureId,
            parent_version_id: parentId,
            // rawRequest, never the mirror. The colour/line-ending render builds a copy of this
            // buffer for the mirror element and that copy is not reachable from here.
            raw_request: bytes,
            base_url: base,
          }),
        });
        const body = await res.text();
        let data = null;
        try { data = body ? JSON.parse(body) : null; } catch (err) { data = null; }

        if (res.status === 404) {
          setVersionsAvailable(false);
          versionsAvailableRef.current = false;
          return { saved: false, wasDirty: true };
        }

        // Not a failure. The server compares normalised bytes, so an edit that only changed line
        // terminators or trailing newlines has nothing to record. Refusing to accept the buffer
        // afterwards would leave it permanently "edited" and re-offer the same no-op on every
        // action, so the parent is adopted as what the pane is holding.
        if (res.status === 409 && data && data.error === 'identical_to_parent') {
          adoptBaseline(bytes);
          const existing = data.existing;
          if (existing && existing.id) {
            setActiveVersionId(existing.id);
            activeVersionRef.current = existing.id;
          }
          setVersionNote(data.message
            || 'Those bytes match the version they were edited from, so no new version was made.');
          return { saved: true, wasDirty: true, identical: true };
        }

        if (!res.ok || !data || !data.id) {
          const message = res.ok
            ? 'The framework accepted the version but returned nothing to show for it.'
            : versionErrorMessage(data, body, res.status);
          setVersionsError(message);
          return { saved: false, wasDirty: true, error: message };
        }

        adoptBaseline(bytes);
        setActiveVersionId(data.id);
        activeVersionRef.current = data.id;
        // Appended rather than refetched. The server orders is_original first then created_at
        // ascending, so the newest row belongs exactly here, and a refetch would race the next
        // save. Deletes and renames do refetch, because they change other rows.
        setVersions((prev) => (prev.some((v) => v && v.id === data.id) ? prev : prev.concat(data)));
        setVersionsError('');
        return { saved: true, wasDirty: true, version: data };
      } catch (err) {
        const message = `Could not save a version: ${err.message}`;
        setVersionsError(message);
        return { saved: false, wasDirty: true, error: message };
      } finally {
        setSavingVersion(false);
      }
    })();

    savePromiseRef.current = attempt;
    try {
      return await attempt;
    } finally {
      if (savePromiseRef.current === attempt) savePromiseRef.current = null;
    }
  }, [adoptBaseline]);

  // Idle auto-save. Re-armed by every change to the bytes or the base URL, so it fires once the
  // operator stops, never per keystroke.
  useEffect(() => {
    if (!dirty || !targetId || !versionCaptureId || !versionsAvailable) return undefined;
    if (rawRequest.trim() === '') return undefined;
    const timer = setTimeout(() => { saveVersionIfDirty(); }, AUTOSAVE_IDLE_MS);
    return () => clearTimeout(timer);
  }, [dirty, rawRequest, baseUrl, targetId, versionCaptureId, versionsAvailable, saveVersionIfDirty]);

  // Closing the modal unmounts this pane, and an edit made in the seconds before that is the one
  // the idle timer never got to. The last thing the pane does is offer it. The request outlives the
  // component that started it, and the state updates it makes afterwards land on nothing, which is
  // fine: the row is on the server and the next open reads it back. saveVersionIfDirty never
  // changes identity, so this cleanup runs on unmount and at no other time.
  useEffect(() => () => { saveVersionIfDirty(); }, [saveVersionIfDirty]);

  // Puts a stored version into the editor. The response pane is cleared for the same reason a
  // capture load clears it: a response sitting next to bytes that did not produce it is a claim
  // about a request nobody sent.
  const applyVersion = useCallback((version) => {
    const raw = typeof version.raw_request === 'string' ? version.raw_request : '';
    setRawRequest(raw);
    setLoadedRequest(raw);
    bufferRef.current = raw;
    baselineRef.current = raw;
    setEol(raw.includes('\r\n') ? 'CRLF' : 'LF');
    if (version.base_url) {
      setBaseUrl(version.base_url);
      baseUrlRef.current = version.base_url;
    }
    setActiveVersionId(version.id);
    activeVersionRef.current = version.id;
    setRawResponse('');
    setRespBytes(null);
    setRespMs(null);
    setRespStatus(null);
    setRespNote('');
    // A version is an edited request; the recorded response belonged to the original bytes, not
    // these, so it is cleared rather than left claiming to be this version's answer.
    setResponseSource(null);
    setHasReplayed(false);
    setHops([]);
    setHopIndex(0);
    setRedirectCapped(false);
    setFormatNote('');
    setVersionNote('');
  }, []);

  const selectVersion = async (version) => {
    if (!version || !version.id) return;
    if (renamingId === version.id) return;
    // Clicking the row that is already open, with nothing edited, is a no-op rather than a reload:
    // reloading would throw away the response next to it for no gain.
    if (version.id === activeVersionId && !dirtyRef.current) return;
    const result = await saveVersionIfDirty();
    if (!result.saved && result.wasDirty
      && !(await askConfirm({
        title: 'Discard unsaved edits?',
        body: 'The request pane has edits that could not be saved as a version. Discard them and open the version you clicked?',
        confirmLabel: 'Discard & open',
      }))) {
      return;
    }
    applyVersion(version);
  };

  const beginRename = (version) => {
    // The original's name is not the operator's to choose, for the same reason its bytes are not
    // theirs to edit: it is a record of what happened. The API refuses it too.
    if (!version || !version.id || version.is_original) return;
    setRenamingId(version.id);
    setRenameText(version.label || '');
  };

  const commitRename = async (version) => {
    const text = renameText.trim();
    setRenamingId(null);
    if (!version || !version.id || version.is_original) return;
    if (text === String(version.label || '').trim()) return;
    try {
      const res = await fetch(`/api/replay-request/versions/${version.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        // Only the label. raw_request and base_url are absent rather than empty, which is the
        // difference between leaving those columns alone and wiping them.
        body: JSON.stringify({ label: text }),
      });
      const body = await res.text();
      let data = null;
      try { data = body ? JSON.parse(body) : null; } catch (err) { data = null; }
      if (!res.ok || !data || !data.id) {
        setVersionsError(versionErrorMessage(data, body, res.status));
        return;
      }
      setVersions((prev) => prev.map((v) => (v && v.id === data.id ? data : v)));
      setVersionsError('');
    } catch (err) {
      setVersionsError(`Could not rename that version: ${err.message}`);
    }
  };

  const deleteVersion = async (version) => {
    // The column does not render this control on the original. This is the second lock on the same
    // door, because the first one is a render condition and those get edited.
    if (!version || !version.id || version.is_original) return;
    const isActive = version.id === activeVersionId;
    const name = version.label || 'this version';
    const consequence = isActive
      ? `\n\nIt is the version open in the editor, so the pane falls back to the version it was edited from${dirtyRef.current ? ', taking the unsaved edits in the pane with it' : ''}.`
      : '\n\nAnything edited from it is kept, reparented onto its own parent.';
    if (!(await askConfirm({
      title: 'Delete version?',
      body: `Delete "${name}"?${consequence}`,
      confirmLabel: 'Delete',
    }))) return;
    try {
      const res = await fetch(`/api/replay-request/versions/${version.id}`, { method: 'DELETE' });
      const body = await res.text();
      let data = null;
      try { data = body ? JSON.parse(body) : null; } catch (err) { data = null; }
      if (!res.ok) {
        setVersionsError(versionErrorMessage(data, body, res.status));
        return;
      }
      if (isActive) {
        const fallback = versions.find((v) => v && v.id === version.parent_version_id)
          || versions.find((v) => v && v.is_original)
          || null;
        if (fallback) {
          applyVersion(fallback);
        } else {
          setActiveVersionId(null);
          activeVersionRef.current = null;
        }
      }
      setVersionsError('');
      // Refetched rather than spliced: the server reparents the descendants and recomputes their
      // generated labels, so the rows left behind are not the rows we are holding.
      loadVersions(versionCaptureRef.current);
    } catch (err) {
      setVersionsError(`Could not delete that version: ${err.message}`);
    }
  };

  const loadCapture = useCallback(async (captureId) => {
    requestedCaptureRef.current = captureId;
    setLoadingCapture(true);
    try {
      const res = await fetch(`/api/replay-request/capture/${captureId}/raw`);
      const body = await res.text();
      let data = null;
      try { data = body ? JSON.parse(body) : null; } catch (err) { data = null; }
      if (!res.ok) {
        const message = pickString(data, ['error', 'message']) || body || `Framework returned ${res.status}`;
        setRawResponse(`Could not load that request.\n\n${message}`);
        setResponseSource(null);
        return;
      }
      const raw = (typeof data === 'string' ? data : pickString(data, ['raw_request', 'raw', 'request'])) || '';
      const derivedBase = pickString(data, ['base_url', 'baseUrl', 'origin']);
      let base = derivedBase || '';
      if (!base) {
        const url = pickString(data, ['url']) || '';
        try { base = new URL(url).origin; } catch (err) { base = ''; }
      }
      // A JSON body is pretty-printed on load, so a sitemap click reads formatted by default the way
      // Burp and Caido show it. It is folded into the loaded bytes rather than left as a separate view
      // because the request pane is editable: the buffer has to BE what is shown. baseline is set to
      // the same value, so this normalisation does not read as an unsaved edit. Non-JSON bodies are
      // returned untouched, and Raw mode still sends the buffer byte for byte.
      const shown = prettifyRequestJson(raw, raw.includes('\r\n') ? '\r\n' : '\n');
      setRawRequest(shown);
      setLoadedRequest(shown);
      // Both refs move now rather than on the next render, so an auto-save decided between here
      // and that render compares against the request that was just loaded.
      bufferRef.current = shown;
      baselineRef.current = shown;
      setEol(shown.includes('\r\n') ? 'CRLF' : 'LF');
      setBaseUrl(base);
      baseUrlRef.current = base;

      // Show the response the crawl recorded for this exact request, next to it, so a click on the
      // sitemap is a whole exchange rather than a request beside an empty pane. The server builds
      // original_raw_response from the stored status, headers and body, and returns "" only when no
      // response was ever recorded (the capture's status is 0) - the one case there is nothing to
      // show. There are no hops on a recorded response, so the chain view stays empty and the
      // response pane reads straight off rawResponse.
      const originalRaw = (typeof data === 'string' ? '' : pickString(data, ['original_raw_response'])) || '';
      const originalStatus = pickNumber(data, ['original_status']);
      const originalBody = pickString(data, ['original_body']) || '';
      const originalMs = pickNumber(data, ['original_duration_ms']);
      const bodyTruncated = !!(data && (data.response_body_truncated || data.responseBodyTruncated));
      setHasReplayed(false);
      setHops([]);
      setHopIndex(0);
      setRedirectCapped(false);
      setFormatNote('');
      if (originalRaw.trim() !== '') {
        setRawResponse(originalRaw);
        setRespStatus(originalStatus && originalStatus > 0 ? originalStatus : null);
        const haveBody = originalBody !== '';
        // null, not 0, when the body was not stored: "0 bytes" reads as an empty response, and the
        // recorded headers below often say a body of thousands of bytes was sent - just not kept.
        setRespBytes(haveBody ? byteLength(originalBody) : null);
        setRespMs(originalMs == null ? null : originalMs);
        // Three cases, said once next to the response they explain: a truncated body is shorter than
        // what the server sent; a body the crawl never stored while the headers say one existed is
        // not an empty response and must not read as one; anything else needs no note.
        const respParts = splitHttpMessage(originalRaw);
        const headersSayBody = respParts.found && (
          /[1-9]/.test(headerValueFrom(respParts.head, 'content-length') || '')
          || (headerValueFrom(respParts.head, 'transfer-encoding') || '').trim() !== ''
        );
        setRespNote(
          bodyTruncated
            ? 'Recorded response. The crawl truncated the stored body, so it is shorter than what the '
              + 'server returned - replay to fetch the whole of it.'
            : (!haveBody && headersSayBody)
              ? 'Recorded response headers. The crawl did not store this response’s body - '
                + 'replay to fetch it.'
              : ''
        );
        setResponseSource('recorded');
      } else {
        setRawResponse('');
        setRespStatus(null);
        setRespBytes(null);
        setRespMs(null);
        setRespNote('');
        setResponseSource('unrecorded');
      }

      // The version column follows the request. Cleared first so a slow list cannot leave the
      // previous request's versions sitting next to these bytes.
      setVersions([]);
      setActiveVersionId(null);
      activeVersionRef.current = null;
      setVersionCaptureId(captureId);
      versionCaptureRef.current = captureId;
      setVersionNote('');
      setRenamingId(null);
      setHandoverNote('');
      if (versionsAvailableRef.current) loadVersions(captureId, { selectOriginal: true });

      if (onLoadedRef.current) onLoadedRef.current(captureId);
    } catch (err) {
      setRawResponse(`Could not load that request.\n\n${err.message}`);
      setResponseSource(null);
    } finally {
      setLoadingCapture(false);
    }
  }, [loadVersions]);

  // The parent hands a capture in by id: on mount, or whenever it changes. Same id twice is not a
  // reload, so a parent that wants one asks for null first. Edits in the pane are saved as a
  // version first and only confirmed about if that could not happen, because arriving here from
  // another modal is no reason to throw away bytes the operator typed.
  useEffect(() => {
    if (loadCaptureId === null || loadCaptureId === undefined || loadCaptureId === '') return undefined;
    if (requestedCaptureRef.current === loadCaptureId) return undefined;
    let cancelled = false;
    (async () => {
      const result = await saveVersionIfDirty();
      // A second handover landing while the save was in flight owns the pane now.
      if (cancelled) return;
      if (result.wasDirty && !result.saved
        && !(await askConfirm({
          title: 'Discard unsaved edits?',
          body: 'The request pane has unsaved edits. Discard them and load the selected request?',
          confirmLabel: 'Discard & load',
        }))) {
        return;
      }
      // A capture handed in from another modal is a single request, not a sitemap endpoint: clearing
      // the endpoint selection empties the derived variant list, so the versions column shows this
      // capture's own tree.
      setSelectedId(null);
      loadCapture(loadCaptureId);
    })();
    return () => { cancelled = true; };
    // saveVersionIfDirty is created once and never changes identity, which is what keeps this
    // effect armed only by the id. See the note on targetIdRef.
  }, [loadCaptureId, loadCapture, saveVersionIfDirty, askConfirm]);

  // The second way bytes get into this pane: handed straight in, with no capture behind them.
  //
  // A tool finding is the case this exists for. The scanner's request is not in the crawl corpus and
  // never will be, so there is no id to look up and nothing for the sitemap query to match; the only
  // thing that can travel is the bytes. Everything downstream of the editor is unchanged, which is
  // the point: the same buffer, the same Replay, the same raw mode, the same byte-for-byte send.
  //
  // NOTHING HERE SENDS. The bytes are loaded and the operator presses Replay, or does not. A results
  // list that fired a request because a button was clicked in it would be a scan nobody asked for.
  const loadRawBytes = useCallback((payload) => {
    requestedRawRef.current = payload;
    // The capture id this pane last fetched is no longer what is on screen. Left set, a later
    // handover of that same capture would be skipped as "already loaded" and the button that sent
    // it would do nothing.
    requestedCaptureRef.current = null;

    const raw = rawHandoverBytes(payload);
    const base = payload && typeof payload.base_url === 'string' ? payload.base_url : '';

    // No row in the sitemap corresponds to these bytes. Leaving the previous selection highlighted
    // would claim they came from it, and would also make clicking that row again a no-op, which is
    // the one gesture that gets the operator back to the recorded request.
    setSelectedId(null);

    setRawRequest(raw);
    setLoadedRequest(raw);
    bufferRef.current = raw;
    baselineRef.current = raw;
    setEol(raw.includes('\r\n') ? 'CRLF' : 'LF');
    // Carried rather than derived. With base_url empty the framework falls back to the Host header
    // AND ASSUMES HTTPS, so a finding on an http origin would be re-sent over TLS to a different
    // port and the answer would be about a request the tool never made. The box is on screen and
    // editable, so the operator can see and change what this decided.
    setBaseUrl(base);
    baseUrlRef.current = base;

    setRawResponse('');
    setRespBytes(null);
    setRespMs(null);
    setRespStatus(null);
    setRespNote('');
    // Handed-over bytes are not in the corpus, so there is no recorded response to sit beside them.
    setResponseSource(null);
    setHasReplayed(false);
    setHops([]);
    setHopIndex(0);
    setRedirectCapped(false);
    setFormatNote('');

    // Versioning is OFF for these bytes, and that is not an oversight. A version tree is rooted in
    // the request as the crawl recorded it; there is no such row here, so inventing one would put a
    // scanner's composed request at the top of a column that promises "what the target actually
    // sent". The column says so in words rather than silently saving nothing.
    setVersions([]);
    setActiveVersionId(null);
    activeVersionRef.current = null;
    setVersionCaptureId(null);
    versionCaptureRef.current = null;
    setVersionNote('');
    setRenamingId(null);

    setHandoverNote(payload && payload.label ? String(payload.label) : '');
  }, []);

  // Armed by the identity of the payload object, for the same reason the effect above is armed by
  // the id: re-rendering with the same handover is not a second handover. The parent re-arms by
  // passing null for one commit, which is the pattern ReplayRequestsModal documents.
  useEffect(() => {
    if (!loadRawRequest || rawHandoverBytes(loadRawRequest).trim() === '') return undefined;
    if (requestedRawRef.current === loadRawRequest) return undefined;
    let cancelled = false;
    (async () => {
      const result = await saveVersionIfDirty();
      if (cancelled) return;
      // Same fallback as the capture path. A scratch buffer cannot be saved as a version at all, so
      // for those this confirm is the only thing standing between an edit and the bin.
      if (result.wasDirty && !result.saved
        && !(await askConfirm({
          title: 'Discard unsaved edits?',
          body: 'The request pane has unsaved edits. Discard them and load the request that was handed over?',
          confirmLabel: 'Discard & load',
        }))) {
        return;
      }
      // Handed-over bytes are not in the corpus, so there is no endpoint; clearing the selection
      // empties the derived variant list.
      setSelectedId(null);
      loadRawBytes(loadRawRequest);
    })();
    return () => { cancelled = true; };
  }, [loadRawRequest, loadRawBytes, saveVersionIfDirty, askConfirm]);

  // Selecting an endpoint leaf loads its most-recent (canonical) variant; the versions column derives
  // the variant list from the same leaf. Clicking the same endpoint again reloads the canonical - it
  // is a no-op ONLY when the canonical is already the loaded variant and the buffer is clean, so after
  // stepping to another variant a re-click still snaps back to the canonical (the guard used to just
  // check the endpoint key, which stranded a non-canonical variant).
  const selectLeaf = async (leaf) => {
    // Open the PRIMARY variant - the one whose status the sitemap shows - so the badge and the loaded
    // request agree. Falls back to the newest recording when nothing is marked primary.
    const primary = (leaf.variants && (leaf.variants.find((v) => v.isPrimary) || leaf.variants[0])) || null;
    const primaryId = primary ? primary.id : null;
    if (leaf.key === selectedId && rawRequest !== ''
      && versionCaptureId === primaryId && !dirtyRef.current) return;
    const result = await saveVersionIfDirty();
    if (result.wasDirty && !result.saved
      && !(await askConfirm({
        title: 'Discard unsaved edits?',
        body: 'The request pane has unsaved edits. Discard them and load the selected request?',
        confirmLabel: 'Discard & load',
      }))) {
      return;
    }
    setSelectedId(leaf.key);
    if (!primary || primary.id == null) {
      setRawResponse('That capture has no id, so the framework cannot fetch its raw request.');
      setResponseSource(null);
      return;
    }
    loadCapture(primary.id);
  };

  // Selecting a variant in the versions column loads that recorded capture - its request AND its
  // recorded response (loadCapture), unlike an edit version which clears the response. The endpoint
  // selection is untouched, so the variant list stays put while the operator steps through it.
  const loadVariant = async (variant) => {
    if (!variant || variant.id == null) return;
    // No-op only when this variant's RECORDED response is what the pane is showing. After a live
    // Replay overwrote it (responseSource==='live'), a re-click must fall through and restore the
    // recording - otherwise the "replay, then compare against the recording" step silently does nothing.
    if (variant.id === versionCaptureId && responseSource === 'recorded' && !dirtyRef.current) return;
    const result = await saveVersionIfDirty();
    if (result.wasDirty && !result.saved
      && !(await askConfirm({
        title: 'Discard unsaved edits?',
        body: 'The request pane has unsaved edits. Discard them and load the selected variant?',
        confirmLabel: 'Discard & load',
      }))) {
      return;
    }
    loadCapture(variant.id);
  };

  // The browser hands back an LF-only value no matter what the buffer held, so the CRs go back in
  // to match the terminator style the document was loaded with. Without this, the first keystroke
  // in a CRLF request silently rewrites every line ending in it.
  const handleRequestChange = (event) => {
    const typed = event.target.value;
    setFormatNote('');
    setRawRequest(eol === 'CRLF'
      ? typed.replace(/\r\n|\r|\n/g, '\r\n')
      : typed.replace(/\r\n|\r/g, '\n'));
  };

  // The one thing in this file that rewrites the request on purpose.
  //
  // It is a button rather than an automatic pass because the request pane is the payload: a body
  // reformatted the moment it was loaded would mean the bytes a target received were chosen by a
  // pretty-printer rather than by the operator, and a whitespace-sensitive endpoint, a signed body
  // or a length-based probe would all be silently altered. As a button, the rewrite is visible in
  // the pane before anything is sent, it becomes a version like any other edit, and the operator can
  // walk back to the previous version if it was not what they wanted.
  //
  // It declines rather than guesses in every case where reformatting would destroy something
  // deliberate, and says which case it was.
  const formatRequestBody = () => {
    const parts = splitHttpMessage(rawRequest);
    if (!parts.found || parts.body.trim() === '') {
      setFormatNote('There is no request body to format.');
      return;
    }
    if (/^\s*transfer-encoding\s*:.*chunked/im.test(parts.head)) {
      setFormatNote('The body is chunked. Reformatting it would break the chunk framing, so it was left alone.');
      return;
    }
    let value;
    try {
      value = JSON.parse(parts.body);
    } catch (err) {
      setFormatNote(`The body did not parse as JSON, so nothing was changed: ${err.message}`);
      return;
    }
    const newline = eol === 'CRLF' ? '\r\n' : '\n';
    const formatted = formatJsonText(value, newline);
    if (formatted === parts.body) {
      setFormatNote('The body was already formatted this way, so nothing changed.');
      return;
    }
    const length = byteLength(formatted);
    const head = withContentLength(parts.head, length, newline);
    if (head === null) {
      setFormatNote('This request declares Content-Length twice. That disagreement is usually the '
        + 'point, so the body was left alone rather than collapsing it.');
      return;
    }
    setRawRequest(head + newline + newline + formatted);
    setFormatNote(`Body reformatted as indented JSON. Content-Length is now ${length.toLocaleString()}.`);
  };

  const changeEol = (next) => {
    setEol(next);
    // Changing the terminator changes the byte count of every line, so any Content-Length the format
    // button just reported no longer describes the buffer.
    setFormatNote('');
    setRawRequest((prev) => (next === 'CRLF'
      ? prev.replace(/\r\n|\r|\n/g, '\r\n')
      : prev.replace(/\r\n|\r/g, '\n')));
  };

  const syncMirrorScroll = () => {
    const area = textareaRef.current;
    const mirror = mirrorRef.current;
    if (!area || !mirror) return;
    mirror.scrollTop = area.scrollTop;
    mirror.scrollLeft = area.scrollLeft;
  };

  useEffect(() => { syncMirrorScroll(); }, [showEol, wrapText, rawRequest]);

  const replay = async () => {
    if (!rawRequest.trim()) {
      setRawResponse('Nothing to send. The request pane is empty.');
      setHasReplayed(false);
      setResponseSource(null);
      return;
    }
    // Sending an edit is the moment it becomes worth keeping, so it is written down first. A save
    // that fails does NOT stop the send: the operator asked for these bytes to go out, and refusing
    // to send them because a bookkeeping row could not be written would be the framework deciding
    // it matters more than the test. The failure shows in the versions column.
    await saveVersionIfDirty();

    setReplaying(true);
    setHops([]);
    setHopIndex(0);
    setRedirectCapped(false);
    try {
      const res = await fetch('/api/replay-request/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // rawRequest. Not the mirror the line-ending view builds, not the wrapped rendering, not the
        // pretty-printed response: the buffer, exactly as the pane shows it.
        body: JSON.stringify({
          raw_request: rawRequest,
          base_url: baseUrl,
          raw_mode: rawMode,
          follow_redirects: followRedirects,
          max_redirects: maxRedirects,
        }),
      });
      const body = await res.text();
      let data = null;
      try { data = body ? JSON.parse(body) : null; } catch (err) { data = null; }

      // A transport failure is a result, not an accident. It belongs in the response pane where the
      // operator is already looking, next to the request that caused it.
      // The framing note says which of the bytes in the request pane the transport is about to
      // overrule. Dropping it is how an operator concludes a target is not vulnerable to a probe
      // they never actually sent, so it is read on every path that reaches a response.
      setRespNote(pickString(data, ['note']) || '');

      if (!res.ok) {
        const message = pickString(data, ['error', 'message']) || body || `Framework returned ${res.status}`;
        setRawResponse(message);
        setRespBytes(null);
        setRespMs(pickNumber(data, ['duration_ms', 'elapsed_ms', 'time_ms', 'duration']));
        setRespStatus(null);
        setHasReplayed(true);
        setResponseSource('live');
        return;
      }

      const transportError = pickString(data, ['error']);
      const raw = (typeof data === 'string' ? data : pickString(data, ['raw_response', 'response', 'raw'])) || '';
      const text = transportError && !raw ? transportError : raw;
      setRawResponse(text);

      // The chain, if one was followed. The last hop IS the response the flat fields describe, so
      // opening on it shows the same thing a send without redirects would have shown, with the hops
      // that led there listed above it rather than lost.
      const hopRows = Array.isArray(data && data.hops) ? data.hops : [];
      setHops(hopRows);
      setHopIndex(hopRows.length > 0 ? hopRows.length - 1 : 0);
      setRedirectCapped(!!(data && data.redirect_cap_reached));

      const reportedBytes = pickNumber(data, ['size_bytes', 'response_size', 'size', 'bytes', 'length']);
      setRespBytes(reportedBytes == null ? byteLength(text) : reportedBytes);
      setRespMs(pickNumber(data, ['duration_ms', 'elapsed_ms', 'time_ms', 'duration']));
      // A transport failure reports status 0. Painting that as a status badge invents a response
      // that never arrived, so it stays blank and the error text in the pane speaks for itself.
      const reportedStatus = pickNumber(data, ['status_code', 'status']);
      setRespStatus(reportedStatus ? reportedStatus : null);
      setHasReplayed(true);
      setResponseSource('live');
    } catch (err) {
      setRawResponse(`Transport error.\n\n${err.message}`);
      setRespBytes(null);
      setRespMs(null);
      setRespStatus(null);
      setRespNote('');
      setHasReplayed(true);
      setResponseSource('live');
    } finally {
      setReplaying(false);
    }
  };

  // Whether there is anything for the format button to act on. A request with no body at all makes
  // the button a promise it cannot keep, so it is disabled rather than left to explain itself.
  const hasRequestBody = useMemo(() => {
    const parts = splitHttpMessage(rawRequest);
    return parts.found && parts.body.trim() !== '';
  }, [rawRequest]);

  // The syntax-coloured rendering that sits behind the editable textarea. Always on now (colour is
  // the readability the request pane exists to give), with the line-ending glyphs folded in when that
  // view is toggled. It colours the EXACT bytes in the buffer, so it stays character-aligned with the
  // textarea whatever is typed. Line endings do not change the colours, so wrap is not a dependency.
  const requestNodes = useMemo(
    () => renderHttpNodes(httpSegments(rawRequest), showEol, highlightTerms),
    [rawRequest, showEol, highlightTerms]
  );

  // Which exchange the response pane is describing. With no chain that is simply the response; with
  // one it is the hop whose row is selected, and every number in the header and the footer follows
  // it, so a 302 selected in the chain reads as a 302 and not as the 200 it eventually led to.
  const activeHop = hops.length > 0 ? (hops[hopIndex] || hops[hops.length - 1]) : null;
  const shownRaw = activeHop
    ? (activeHop.raw_response || activeHop.error || '')
    : (rawResponse || '');
  const shownStatus = activeHop ? (activeHop.status || null) : respStatus;
  const shownBytes = activeHop ? pickNumber(activeHop, ['size_bytes']) : respBytes;
  const shownMs = activeHop ? pickNumber(activeHop, ['time_ms']) : respMs;
  const totalMs = useMemo(
    () => hops.reduce((sum, hop) => sum + (Number(hop && hop.time_ms) || 0), 0),
    [hops]
  );

  // There is a response worth putting numbers under when one was recorded by the crawl or produced
  // by a live send. An 'unrecorded' capture and a fresh scratch buffer have none, and the footer
  // says so rather than showing a zero.
  const haveShownResponse = responseSource === 'recorded' || responseSource === 'live';

  // Is the response body JSON, and what does it look like formatted?
  //
  // Detected from the content-type OR by parsing it, because plenty of APIs answer JSON as
  // text/plain, and plenty of things labelled JSON are not. A body that claims to be JSON and does
  // not parse is reported and shown raw: throwing, or quietly showing nothing, would lose a response
  // at exactly the moment it got interesting.
  const responseJson = useMemo(() => {
    const parts = splitHttpMessage(shownRaw);
    const body = parts.found ? parts.body : '';
    const trimmed = body.trim();
    const contentType = parts.found ? headerValueFrom(parts.head, 'content-type') : '';
    const claimsJson = /json/i.test(contentType);
    const looksJson = trimmed.startsWith('{') || trimmed.startsWith('[');
    if (!parts.found || trimmed === '' || (!claimsJson && !looksJson)) {
      return { isJson: false, pretty: '', parseError: '' };
    }
    try {
      const newline = parts.separator === '\r\n\r\n' ? '\r\n' : '\n';
      return {
        isJson: true,
        pretty: parts.head + parts.separator + formatJsonText(JSON.parse(trimmed), newline),
        parseError: '',
      };
    } catch (err) {
      return {
        isJson: false,
        pretty: '',
        parseError: claimsJson
          ? `The content-type says JSON but the body did not parse (${err.message}). Showing it raw.`
          : `That body starts like JSON but did not parse (${err.message}). Showing it raw.`,
      };
    }
  }, [shownRaw]);

  const showingPretty = responseJson.isJson && responseFormat === 'pretty';

  // A response body can be far larger than anything worth handing to the DOM. The number in the
  // footer is always the real size; only what is painted is capped, and it says so.
  //
  // Every step here is a transform of a string on its way to a <pre>. Nothing in this memo is ever
  // read back into rawRequest, into rawResponse, or into anything that is sent.
  const responseText = useMemo(() => {
    const limit = 500000;
    const source = showingPretty ? responseJson.pretty : shownRaw;
    return source.length > limit
      ? `${source.slice(0, limit)}\n\n[display truncated at ${limit.toLocaleString()} characters. The size below is the full response.]`
      : source;
  }, [shownRaw, showingPretty, responseJson]);

  // The coloured rendering of whatever responseText holds. Line-ending glyphs are folded in here, the
  // same as the request, rather than decorated into the string, so colour and glyphs coexist.
  const responseNodes = useMemo(
    () => renderHttpNodes(httpSegments(responseText), showEol),
    [responseText, showEol]
  );

  const renderLeaf = (leaf, depth) => {
    const active = leaf.key === selectedId;
    // ONE status only: the primary variant's. The endpoint may have several recorded variants with
    // several statuses, but the sitemap shows the one the operator chose as representative (or the
    // newest, absent a choice). The rest are in the variants column.
    const primaryStatus = leaf.primaryStatus != null ? leaf.primaryStatus : leaf.status;
    // An endpoint the attack-vector model knows about is drawn red - the way the rest of the
    // framework flags a modelled vector - and carries a bullseye whose hover lists each vector's
    // insertion point and parameters. A leaf with no modelled vector is untouched and reads exactly
    // as before (hasAttackVector is false and attackVectors is [] when the model is not loaded).
    const hasAv = !!leaf.hasAttackVector;
    const avTitle = hasAv
      ? `Attack vector${leaf.attackVectors.length === 1 ? '' : 's'}:\n${leaf.attackVectors
          .map((v) => {
            const params = (v.parameters || []).filter(Boolean);
            return params.length ? `${v.insertion_point}: ${params.join(', ')}` : v.insertion_point;
          })
          .join('\n')}`
      : undefined;
    const labelClass = hasAv ? 'text-danger' : (active ? 'text-light' : 'text-white-50');
    return (
      <div
        key={`leaf-${leaf.key}`}
        onClick={() => selectLeaf(leaf)}
        title={leaf.variantCount > 1
          ? `${leaf.url}\n${leaf.variantCount} variants from ${leaf.captureCount} captures`
          : leaf.url}
        className={`d-flex align-items-center py-1 pe-2 ${active ? 'bg-secondary bg-opacity-25' : ''}`}
        style={{ cursor: 'pointer', paddingLeft: `${8 + depth * 14}px` }}
      >
        <Badge
          bg="dark"
          className={`border ${hasAv ? 'border-danger text-danger' : 'border-secondary text-white-50'} me-2`}
          style={{ fontSize: '0.55rem', minWidth: '42px' }}
        >
          {leaf.method}
        </Badge>
        <code
          className={`flex-grow-1 text-truncate ${labelClass}`}
          style={{ fontSize: '0.72rem' }}
        >
          {leaf.label}{leaf.hasQuery ? '?' : ''}
        </code>
        {hasAv && (
          <i
            className="bi bi-bullseye text-danger ms-1"
            style={{ fontSize: '0.7rem' }}
            title={avTitle}
          />
        )}
        {primaryStatus != null && (
          <Badge
            bg={statusVariant(primaryStatus)}
            className="ms-1"
            style={{ fontSize: '0.55rem' }}
            title={leaf.variantCount > 1 ? 'status of the primary variant' : undefined}
          >
            {primaryStatus || '?'}
          </Badge>
        )}
      </div>
    );
  };

  const renderNode = (node, depth) => {
    // With the attack-vectors-only filter on, every node is forced open so the matches are always
    // visible, and its children and leaves are pruned to only those carrying a modelled vector. With
    // the filter off this is byte-for-byte the previous behaviour.
    const open = attackVectorsOnly ? true : isOpen(node.key, depth);
    const children = attackVectorsOnly
      ? node.children.filter((child) => child.attackVectorCount > 0)
      : node.children;
    const leaves = attackVectorsOnly
      ? node.leaves.filter((leaf) => leaf.hasAttackVector)
      : node.leaves.filter((leaf) => showHiddenVariants || leaf.hasVisible);
    return (
      <div key={node.key}>
        <div
          onClick={() => toggleNode(node.key, depth)}
          className="d-flex align-items-center py-1 pe-2"
          style={{ cursor: 'pointer', paddingLeft: `${8 + depth * 14}px` }}
        >
          <i
            className={`bi ${open ? 'bi-chevron-down' : 'bi-chevron-right'} text-white-50 me-1`}
            style={{ fontSize: '0.65rem' }}
          />
          <i className={`bi ${depth === 0 ? 'bi-hdd-network' : 'bi-folder'} text-danger me-2`} style={{ fontSize: '0.7rem' }} />
          <span
            className={`flex-grow-1 text-truncate ${node.attackVectorCount > 0 ? 'text-danger fw-semibold' : 'text-light'}`}
            style={{ fontSize: '0.75rem' }}
            title={node.attackVectorCount > 0
              ? `Contains ${node.attackVectorCount} endpoint${node.attackVectorCount === 1 ? '' : 's'} with a modelled attack vector - dig in`
              : undefined}
          >
            {node.name}
          </span>
          <Badge bg="dark" className="border border-secondary text-white-50" style={{ fontSize: '0.55rem' }}>
            {node.count}
          </Badge>
          {node.attackVectorCount > 0 && (
            <Badge
              bg="dark"
              className="border border-danger text-danger ms-1"
              style={{ fontSize: '0.55rem' }}
              title={`${node.attackVectorCount} endpoint${node.attackVectorCount === 1 ? '' : 's'} with a modelled attack vector`}
            >
              <i className="bi bi-bullseye me-1" />{node.attackVectorCount}
            </Badge>
          )}
        </div>
        {open && (
          <div>
            {children.map((child) => renderNode(child, depth + 1))}
            {leaves.map((leaf) => renderLeaf(leaf, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  // One hop of a redirect chain. The status and the Location are on the row itself rather than only
  // in the response below it, because the whole reason for showing a chain is that "302 to /login"
  // is the observation. Clicking a row puts that exchange in the pane.
  const renderHopRow = (hop, index) => {
    const active = index === hopIndex;
    const status = Number(hop && hop.status) || 0;
    const select = () => setHopIndex(index);
    return (
      <div key={`hop-${index}`}>
        <div
          role="button"
          tabIndex={0}
          onClick={select}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(); }
          }}
          className="srp-hop-row d-flex align-items-center px-2 py-1"
          title={hop.url}
          style={{
            cursor: 'pointer',
            borderLeft: `3px solid ${active ? '#0dcaf0' : 'transparent'}`,
            backgroundColor: active ? '#2b3035' : 'transparent',
          }}
        >
          <span
            className="text-white-50 me-2"
            style={{ fontFamily: MONO_STYLE.fontFamily, fontSize: '0.62rem', minWidth: '12px' }}
          >
            {index + 1}
          </span>
          <Badge
            bg={status ? statusVariant(status) : 'secondary'}
            style={{ fontSize: '0.55rem', minWidth: '36px' }}
          >
            {status || 'ERR'}
          </Badge>
          <code className="ms-2 text-white-50" style={{ fontSize: '0.62rem' }}>{hop.method || '?'}</code>
          <code
            className={`ms-2 flex-grow-1 text-truncate ${active ? 'text-light' : 'text-white-50'}`}
            style={{ fontSize: '0.65rem' }}
          >
            {hop.url}
          </code>
          <span
            className="text-white-50 ms-2"
            style={{ fontSize: '0.62rem', whiteSpace: 'nowrap' }}
          >
            {Math.round(Number(hop.time_ms) || 0).toLocaleString()} ms
          </span>
        </div>

        {/* Verbatim, as the server wrote it. A relative Location and an absolute one to another host
            are different findings, so this is not normalised into the resolved URL; that is in the
            tooltip, where it belongs. */}
        {hop.location && (
          <div
            className="text-truncate"
            style={{ fontSize: '0.62rem', paddingLeft: '2.1rem', paddingRight: '0.5rem', paddingBottom: '0.2rem' }}
            title={hop.resolved_url ? `resolved to ${hop.resolved_url}` : hop.location}
          >
            <span className="text-info">Location:</span>{' '}
            <code className="text-white-50">{hop.location}</code>
          </div>
        )}
        {hop.note && (
          <div className="text-warning" style={{ fontSize: '0.62rem', padding: '0 0.5rem 0.25rem 2.1rem' }}>
            {hop.note}
          </div>
        )}
        {hop.error && (
          <div className="text-danger" style={{ fontSize: '0.62rem', padding: '0 0.5rem 0.25rem 2.1rem' }}>
            {hop.error}
          </div>
        )}
      </div>
    );
  };

  const renderVersionRow = (version) => {
    const active = version.id === activeVersionId;
    const isOriginal = !!version.is_original;
    const renaming = renamingId === version.id;
    const label = String(version.label || '').trim();
    const ordinal = versionOrdinals[version.id];
    return (
      <div
        key={version.id}
        role="button"
        tabIndex={0}
        onClick={() => { if (!renaming) selectVersion(version); }}
        onKeyDown={(e) => {
          if (renaming) return;
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectVersion(version); }
        }}
        className="srp-version-row px-2 py-2 border-bottom border-secondary"
        title={`${label}\n${version.summary || ''}\nSaved ${formatVersionTimestamp(version.created_at)}`}
        style={{
          cursor: 'pointer',
          borderLeft: `3px solid ${active ? '#dc3545' : 'transparent'}`,
          backgroundColor: active ? '#2b3035' : 'transparent',
        }}
      >
        <div className="d-flex align-items-center mb-1">
          {isOriginal ? (
            <OverlayTrigger
              placement="left"
              overlay={(
                <Tooltip>
                  The request exactly as the crawl recorded it. It cannot be renamed, edited or
                  deleted: every edit is saved as a new version below it, so this row is always the
                  way back to what the target actually sent.
                </Tooltip>
              )}
            >
              <Badge bg="danger" style={{ fontSize: '0.55rem' }}>
                <i className="bi bi-lock-fill me-1" />
                ORIGINAL
              </Badge>
            </OverlayTrigger>
          ) : (
            <span
              className="text-white-50"
              style={{ fontFamily: MONO_STYLE.fontFamily, fontSize: '0.62rem' }}
            >
              v{ordinal}
            </span>
          )}
          {active && (
            <Badge
              bg="dark"
              className="border border-danger text-danger ms-2"
              style={{ fontSize: '0.55rem' }}
            >
              open
            </Badge>
          )}
          <span className="text-white-50 ms-auto" style={{ fontSize: '0.62rem' }}>
            {formatVersionTime(version.created_at)}
          </span>
        </div>

        {renaming ? (
          <Form.Control
            size="sm"
            autoFocus
            value={renameText}
            onChange={(e) => setRenameText(e.target.value)}
            onClick={(e) => e.stopPropagation()}
            onBlur={() => commitRename(version)}
            onKeyDown={(e) => {
              e.stopPropagation();
              if (e.key === 'Enter') { e.preventDefault(); commitRename(version); }
              if (e.key === 'Escape') { e.preventDefault(); setRenamingId(null); }
            }}
            placeholder="Empty restores the automatic label"
            spellCheck={false}
            style={{ fontSize: '0.72rem' }}
            data-bs-theme="dark"
          />
        ) : (
          <div
            className={active ? 'text-light' : 'text-white-50'}
            style={{ fontSize: '0.72rem', wordBreak: 'break-word' }}
          >
            {label || 'no label'}
          </div>
        )}

        <div
          className="text-white-50 text-truncate"
          style={{ fontFamily: MONO_STYLE.fontFamily, fontSize: '0.65rem' }}
        >
          {version.summary || ''}
        </div>

        <div className="d-flex align-items-center mt-1">
          <span className="text-white-50" style={{ fontSize: '0.62rem' }}>
            {Number(version.size_bytes || 0).toLocaleString()} bytes
          </span>
          {/* Nothing to press on the original. The handlers refuse it as well, because a render
              condition is not a guarantee. */}
          {!isOriginal && !renaming && (
            <span className="ms-auto d-flex gap-2">
              <button
                type="button"
                className="btn btn-link p-0 text-white-50"
                title="Rename this version"
                onClick={(e) => { e.stopPropagation(); beginRename(version); }}
                style={{ fontSize: '0.72rem', lineHeight: 1 }}
              >
                <i className="bi bi-pencil" />
              </button>
              <button
                type="button"
                className="btn btn-link p-0 text-white-50"
                title="Delete this version"
                onClick={(e) => { e.stopPropagation(); deleteVersion(version); }}
                style={{ fontSize: '0.72rem', lineHeight: 1 }}
              >
                <i className="bi bi-trash" />
              </button>
            </span>
          )}
        </div>
      </div>
    );
  };

  // One recorded variant of the selected endpoint as a selectable row. Clicking it loads that
  // recording's request AND its recorded response. It carries a NAME (the operator's, or the source
  // default), a PRIMARY star that makes it the one the sitemap shows, and a rename pencil. Its own
  // manual edits are the "Edits" section below, not here: a variant is the recording, an edit is a
  // change to it.
  const renderVariantRow = (variant, index) => {
    const active = variant.id === versionCaptureId;
    const renaming = variantRenamingId === variant.id;
    const sizeTxt = variant.size != null ? `${Number(variant.size).toLocaleString()} B` : '';
    // What tells this variant from its siblings: a query string for a GET, otherwise the mime.
    const detail = variant.query
      ? variant.query
      : (variant.mime || 'recorded request');
    return (
      <div
        key={`variant-${variant.id}`}
        role="button"
        tabIndex={0}
        onClick={() => loadVariant(variant)}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); loadVariant(variant); } }}
        className="srp-version-row px-2 py-2 border-bottom border-secondary"
        title={variant.url}
        style={{
          cursor: 'pointer',
          borderLeft: `3px solid ${active ? '#dc3545' : 'transparent'}`,
          backgroundColor: active ? '#2b3035' : 'transparent',
          opacity: variant.hidden ? 0.5 : 1,
        }}
      >
        <div className="d-flex align-items-center mb-1">
          {/* Primary star: filled and red (the framework accent) when this is the endpoint's primary,
              hollow grey otherwise. Clicking a hollow one makes this the primary. A hidden variant can
              never be primary, so it shows a muted "hidden" tag in the star's place instead. */}
          {variant.hidden ? (
            <span
              className="me-2 text-white-50"
              style={{ fontSize: '0.6rem', letterSpacing: '0.03em' }}
              title="Hidden from the list. The recording is still in the corpus for every other tool."
            >
              <i className="bi bi-eye-slash" style={{ fontSize: '0.72rem' }} />
            </span>
          ) : (
            <button
              type="button"
              className="btn btn-link p-0 me-2"
              style={{ lineHeight: 1, color: variant.isPrimary ? '#dc3545' : '#6c757d' }}
              title={variant.isPrimary
                ? 'Primary variant. This is the one the sitemap shows and a leaf click opens.'
                : 'Make this the primary variant (shown in the sitemap).'}
              onClick={(e) => { e.stopPropagation(); setPrimaryVariant(variant); }}
            >
              <i className={`bi ${variant.isPrimary ? 'bi-star-fill' : 'bi-star'}`} style={{ fontSize: '0.72rem' }} />
            </button>
          )}
          <Badge bg={statusVariant(variant.status)} style={{ fontSize: '0.55rem' }}>
            {variant.status || '?'}
          </Badge>
          {active && (
            <Badge bg="dark" className="border border-danger text-danger ms-2" style={{ fontSize: '0.55rem' }}>
              open
            </Badge>
          )}
          <span className="text-white-50 ms-auto" style={{ fontSize: '0.62rem' }}>
            {formatVersionTime(variant.timestamp)}
          </span>
        </div>

        {renaming ? (
          <Form.Control
            size="sm"
            autoFocus
            value={variantRenameText}
            onChange={(e) => setVariantRenameText(e.target.value)}
            onClick={(e) => e.stopPropagation()}
            onBlur={() => commitVariantRename(variant)}
            onKeyDown={(e) => {
              e.stopPropagation();
              if (e.key === 'Enter') { e.preventDefault(); commitVariantRename(variant); }
              if (e.key === 'Escape') { e.preventDefault(); setVariantRenamingId(null); }
            }}
            placeholder="Empty restores the source name"
            spellCheck={false}
            style={{ fontSize: '0.72rem' }}
            data-bs-theme="dark"
          />
        ) : (
          <div
            className={active ? 'text-light' : 'text-white'}
            style={{ fontSize: '0.72rem', wordBreak: 'break-word' }}
          >
            {variant.name}
            {!variant.nameCustom && (
              <span className="text-white-50 fst-italic ms-1" style={{ fontSize: '0.6rem' }}>default</span>
            )}
          </div>
        )}

        <div
          className="text-white-50 text-truncate mt-1"
          style={{ fontSize: '0.65rem', fontFamily: MONO_STYLE.fontFamily }}
          title={detail}
        >
          {detail}
        </div>
        <div className="d-flex align-items-center mt-1">
          <span className="text-white-50" style={{ fontSize: '0.62rem' }}>
            {sizeTxt}
            {variant.mime && variant.query ? ` · ${variant.mime}` : ''}
            {variant.count > 1 ? ` · ×${variant.count} captures` : ''}
          </span>
          {!renaming && (
            <span className="ms-auto d-flex gap-2">
              <button
                type="button"
                className="btn btn-link p-0 text-white-50"
                title="Rename this variant"
                onClick={(e) => { e.stopPropagation(); beginVariantRename(variant); }}
                style={{ fontSize: '0.72rem', lineHeight: 1 }}
              >
                <i className="bi bi-pencil" />
              </button>
              {variant.hidden ? (
                <button
                  type="button"
                  className="btn btn-link p-0 text-white-50"
                  title="Restore this variant to the list"
                  onClick={(e) => { e.stopPropagation(); unhideVariant(variant); }}
                  style={{ fontSize: '0.72rem', lineHeight: 1 }}
                >
                  <i className="bi bi-arrow-counterclockwise" />
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-link p-0 text-white-50"
                  title="Remove this variant from the list. It stays in the scan results and every other tool; use the toggle above to restore it."
                  onClick={(e) => { e.stopPropagation(); hideVariant(variant); }}
                  style={{ fontSize: '0.72rem', lineHeight: 1 }}
                >
                  <i className="bi bi-trash" />
                </button>
              )}
            </span>
          )}
        </div>
      </div>
    );
  };

  const renderVersionsBody = () => {
    if (!versionsAvailable) {
      return (
        <div className="text-white-50 p-3" style={{ fontSize: '0.72rem' }}>
          This framework build does not serve the version endpoints, so edits are not being saved.
          The repeater itself is unaffected: what goes out is still exactly what is in the request
          pane, and switching request still asks before discarding an edit.
        </div>
      );
    }
    if (!targetId) {
      return <div className="text-white-50 p-3" style={{ fontSize: '0.72rem' }}>No target selected.</div>;
    }

    // A selected endpoint: its distinct variants, each nameable and one primary, with the open
    // variant's own manual edits below them. One row per variant even when there is only one, so the
    // model reads the same whether an endpoint was recorded once or forty times.
    if (endpointVariants.length >= 1) {
      const edits = versions.filter((v) => v && !v.is_original);
      const hiddenInEndpoint = endpointVariants.filter((v) => v.hidden).length;
      const visibleVariants = endpointVariants.filter((v) => !v.hidden);
      const shownSource = showHiddenVariants ? endpointVariants : visibleVariants;
      // Primary first, the rest keeping their newest-first order (stable sort). The primary is the one
      // the sitemap shows and a click opens, so it belongs at the top of the column too.
      const orderedVariants = [...shownSource].sort((a, b) => {
        if (a.isPrimary && !b.isPrimary) return -1;
        if (b.isPrimary && !a.isPrimary) return 1;
        return 0;
      });
      return (
        <>
          <div
            className="px-2 py-1 border-bottom border-secondary d-flex align-items-center"
            style={{ fontSize: '0.62rem', letterSpacing: '0.04em' }}
          >
            <span
              className="text-white-50"
              style={{ textTransform: 'uppercase' }}
              title="One row per distinct recorded request/response for this endpoint. Duplicates were collapsed. The starred one is primary and shown first."
            >
              Variants ({visibleVariants.length})
            </span>
            {hiddenInEndpoint > 0 && (
              <button
                type="button"
                className="btn btn-link p-0 ms-auto text-white-50"
                style={{ fontSize: '0.62rem', lineHeight: 1 }}
                onClick={() => setShowHiddenVariants((s) => !s)}
                title="Hidden variants are removed from the list but kept in the scan results. Show them to restore."
              >
                {showHiddenVariants ? 'hide' : 'show'} {hiddenInEndpoint} hidden
              </button>
            )}
          </div>
          {orderedVariants.map((v, i) => renderVariantRow(v, i))}
          {edits.length > 0 && (
            <>
              <div
                className="px-2 py-1 border-bottom border-secondary text-white-50"
                style={{ fontSize: '0.62rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}
              >
                Edits of the open variant
              </div>
              {edits.map(renderVersionRow)}
            </>
          )}
        </>
      );
    }

    if (!versionCaptureId) {
      return (
        <div className="text-white-50 p-3" style={{ fontSize: '0.72rem' }}>
          Open a request from the sitemap. The version it was recorded as is kept here, and every
          edit you make becomes a new version next to it rather than replacing anything.
          <div className="text-warning mt-2">
            {handoverNote
              // Named rather than lumped in with a typed request, because the operator did not type
              // this and would otherwise be told it is unversioned with no explanation of why.
              ? `These bytes were handed over from ${handoverNote}. They are not in the capture `
                + 'corpus, so there is no recorded version for them to descend from and edits here '
                + 'are not saved.'
              : 'A request typed straight into the pane has no recorded version to descend from, so '
                + 'it is not versioned. Load one from the sitemap to keep a history.'}
          </div>
        </div>
      );
    }
    if (versions.length === 0) {
      return (
        <div className="text-white-50 p-3" style={{ fontSize: '0.72rem' }}>
          {versionsLoading ? 'Loading versions.' : 'No versions recorded for this request yet.'}
        </div>
      );
    }
    return versions.map(renderVersionRow);
  };

  return (
    <div
      className="d-flex flex-column p-2"
      data-bs-theme="dark"
      style={{ height: '100%', flex: '1 1 auto', minHeight: 0, overflow: 'hidden' }}
    >
      <style>{`
        .srp-version-row:hover { background-color: #2b3035 !important; }
        .srp-version-row .btn-link:hover { color: #dc3545 !important; }
        .srp-hop-row:hover { background-color: #2b3035 !important; }
      `}</style>
      <QueryLanguageHelp onExample={setQuery} />

      <div className="d-flex flex-grow-1" style={{ minHeight: 0 }}>
        {/* Left: search and the sitemap. */}
        <div className="d-flex flex-column border border-secondary rounded me-2"
             style={{ width: '25%', minWidth: '260px', minHeight: 0 }}>
          <div className="p-2 border-bottom border-secondary">
            <InputGroup size="sm">
              <InputGroup.Text className="bg-dark border-secondary text-white-50">
                {searching ? <Spinner animation="border" size="sm" variant="danger" /> : <i className="bi bi-search" />}
              </InputGroup.Text>
              <Form.Control
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="method = POST AND status >= 400"
                spellCheck={false}
                style={{ fontFamily: MONO_STYLE.fontFamily, fontSize: '0.75rem' }}
                data-bs-theme="dark"
              />
              {query !== '' && (
                <Button variant="outline-secondary" onClick={() => setQuery('')} title="Clear the query">
                  <i className="bi bi-x" />
                </Button>
              )}
            </InputGroup>
            {/* Narrow the sitemap to endpoints the attack-vector model knows about. Disabled only
                when the target has none modelled AND the filter is off, so the switch can always be
                turned back off and can never blank the tree out from under the operator. */}
            <Form.Check
              type="switch"
              id="replay-av-only"
              className="text-white-50 mt-2"
              style={{ fontSize: '0.72rem' }}
              checked={!!attackVectorsOnly}
              disabled={avEndpointCount === 0 && !attackVectorsOnly}
              onChange={(e) => setAttackVectorsOnly(e.target.checked)}
              label={(
                <span>
                  <i className="bi bi-bullseye text-danger me-1" />
                  Attack vectors only
                  <span className="ms-1">({avEndpointCount.toLocaleString()})</span>
                </span>
              )}
              title={avEndpointCount === 0
                ? 'No endpoints on this target have a modelled attack vector yet.'
                : `Show only the ${avEndpointCount.toLocaleString()} endpoint${avEndpointCount === 1 ? '' : 's'} with a modelled attack vector.`}
            />
            {queryError && (
              <div className="text-danger mt-1" style={{ fontSize: '0.72rem' }}>
                <i className="bi bi-exclamation-triangle me-1" />
                {queryError}
              </div>
            )}
            <div className="text-white-50 mt-1" style={{ fontSize: '0.7rem' }}>
              {leafCount.toLocaleString()} {leafCount === 1 ? 'endpoint' : 'endpoints'}
              <span className="ms-1">
                from {Math.max(total, leafCount).toLocaleString()} {total === 1 ? 'capture' : 'captures'} matched
              </span>
              {corpusTotal != null && (
                <span className="ms-1">({corpusTotal.toLocaleString()} recorded)</span>
              )}
              {truncated && (
                <span className="text-warning ms-1">
                  (more than {RESULT_LIMIT.toLocaleString()} matched, the ceiling one search can scan; narrow the query to see the rest)
                </span>
              )}
            </div>
          </div>

          <div className="flex-grow-1" style={{ overflowY: 'auto', overflowX: 'hidden', minHeight: 0 }}>
            {!targetId ? (
              <div className="text-white-50 small p-3">No target selected.</div>
            ) : tree.length === 0 ? (
              <div className="text-white-50 small p-3">
                {searching ? 'Searching.' : 'Nothing matched. Captures come from the manual crawl, so run one first if this target has none.'}
              </div>
            ) : (
              (() => {
                const shown = tree.filter((node) => !attackVectorsOnly || node.attackVectorCount > 0);
                if (attackVectorsOnly && shown.length === 0) {
                  return (
                    <div className="text-white-50 small p-3">
                      No endpoints with a modelled attack vector match the current query.
                    </div>
                  );
                }
                return shown.map((node) => renderNode(node, 0));
              })()
            )}
          </div>
        </div>

        {/* Middle: request on the left half, response on the right half. */}
        <div className="d-flex flex-grow-1 me-2" style={{ minWidth: 0 }}>
          <div className="d-flex flex-column border border-secondary rounded me-2"
               style={{ width: '50%', minWidth: 0, minHeight: 0 }}>
            <div className="d-flex align-items-center px-2 py-1 border-bottom border-secondary">
              <span className="text-white-50" style={{ fontSize: '0.72rem' }}>REQUEST</span>
              {/* Provenance, next to the bytes. Nothing in the sitemap is highlighted for a handed
                  over request, so without this the pane silently claims a request nobody can trace
                  back to a row. */}
              {handoverNote && (
                <span className="text-info ms-2 text-truncate" style={{ fontSize: '0.68rem', maxWidth: '260px' }}
                  title={`Loaded from ${handoverNote}. Not sent yet.`}>
                  from {handoverNote}
                </span>
              )}
              {dirty && <span className="text-warning ms-2" style={{ fontSize: '0.68rem' }}>edited</span>}
              {loadingCapture && <Spinner animation="border" size="sm" variant="danger" className="ms-2" />}
              {highlightTerms.length > 0 && (
                <Badge
                  bg="danger"
                  className="ms-2 text-truncate d-inline-flex align-items-center"
                  style={{ fontSize: '0.6rem', fontWeight: 'normal', maxWidth: '320px' }}
                  title={`Highlighted in the request below: ${highlightLegend}`}
                >
                  <i className="bi bi-bullseye me-1" />
                  Attack vector: {highlightLegend}
                </Badge>
              )}
              <div className="ms-auto d-flex align-items-center">
                <span className="text-white-50 me-1" style={{ fontSize: '0.68rem' }}>Base URL</span>
                <Form.Control
                  size="sm"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder="https://host"
                  spellCheck={false}
                  style={{ fontFamily: MONO_STYLE.fontFamily, fontSize: '0.7rem', width: '250px' }}
                  data-bs-theme="dark"
                />
              </div>
            </div>

            <div className="flex-grow-1" style={{ position: 'relative', minHeight: 0, backgroundColor: '#1e1e1e' }}>
              {/* The syntax-coloured rendering, always behind the textarea now. The textarea paints a
                  transparent glyph layer of its own (caret and selection) over this, so the colour and
                  the line-ending glyphs come from here and the editing comes from there. They share
                  MONO_STYLE and the wrap setting, so they lay out identically and stay aligned. */}
              <pre
                ref={mirrorRef}
                aria-hidden="true"
                style={{
                  ...MONO_STYLE,
                  ...(wrapText ? WRAP_ON : WRAP_OFF),
                  position: 'absolute',
                  top: 0, left: 0, right: 0, bottom: 0,
                  overflow: 'hidden',
                  pointerEvents: 'none',
                }}
              >
                {requestNodes}
              </pre>
              <textarea
                ref={textareaRef}
                value={rawRequest}
                onChange={handleRequestChange}
                onScroll={syncMirrorScroll}
                // "soft" and never "hard". A soft wrap is defined to leave the element's value
                // alone; a hard wrap inserts the line breaks it drew into the value a form submits.
                wrap={wrapText ? 'soft' : 'off'}
                spellCheck={false}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                placeholder="Select a request in the sitemap, or type one here."
                style={{
                  ...MONO_STYLE,
                  ...(wrapText ? WRAP_ON : WRAP_OFF),
                  position: 'absolute',
                  top: 0, left: 0, right: 0, bottom: 0,
                  width: '100%',
                  height: '100%',
                  resize: 'none',
                  outline: 'none',
                  overflow: 'auto',
                  backgroundColor: 'transparent',
                  // The characters come from the coloured mirror behind this element; the textarea
                  // paints only its caret and selection. The value it holds is untouched.
                  color: 'transparent',
                  caretColor: '#f8f9fa',
                }}
              />
            </div>

            <div className="d-flex align-items-center gap-2 px-2 py-2 border-top border-secondary flex-wrap">
              <Button variant="danger" size="sm" onClick={replay} disabled={replaying || !rawRequest}>
                {replaying ? (
                  <>
                    <Spinner animation="border" size="sm" className="me-2" />
                    Sending
                  </>
                ) : (
                  <>
                    <i className="bi bi-send me-2" />
                    Replay
                  </>
                )}
              </Button>

              <OverlayTrigger
                placement="top"
                overlay={(
                  <Tooltip>
                    Shows every line terminator as a glyph, {GLYPH_CR}{GLYPH_LF} for CRLF and {GLYPH_LF} for a
                    bare LF. Display only. It never changes the bytes that get sent.
                  </Tooltip>
                )}
              >
                <span>
                  <Form.Check
                    type="switch"
                    id="replay-eol-toggle"
                    className="text-white-50"
                    style={{ fontSize: '0.75rem' }}
                    label={`${GLYPH_CR}${GLYPH_LF} line endings`}
                    checked={showEol}
                    onChange={(e) => setShowEol(e.target.checked)}
                  />
                </span>
              </OverlayTrigger>

              <OverlayTrigger
                placement="top"
                overlay={(
                  <Tooltip>
                    Wraps long lines in both panes instead of scrolling sideways. Display only: it is
                    CSS and a soft wrap, which never puts a line break into the bytes.
                  </Tooltip>
                )}
              >
                <span>
                  <Form.Check
                    type="switch"
                    id="replay-wrap-toggle"
                    className="text-white-50"
                    style={{ fontSize: '0.75rem' }}
                    label="Wrap lines"
                    checked={wrapText}
                    onChange={(e) => setWrapText(e.target.checked)}
                  />
                </span>
              </OverlayTrigger>

              <OverlayTrigger
                placement="top"
                overlay={(
                  <Tooltip>
                    Sends the request each Location names, up to the hop limit, and lists every
                    exchange. Off sends one request and shows the 3xx itself.
                  </Tooltip>
                )}
              >
                <span>
                  <Form.Check
                    type="switch"
                    id="replay-follow-redirects"
                    className={followRedirects ? 'text-info' : 'text-white-50'}
                    style={{ fontSize: '0.75rem' }}
                    label="Follow redirects"
                    checked={followRedirects}
                    onChange={(e) => setFollowRedirects(e.target.checked)}
                  />
                </span>
              </OverlayTrigger>

              {followRedirects && (
                <OverlayTrigger
                  placement="top"
                  overlay={<Tooltip>How many redirects may be followed in one send.</Tooltip>}
                >
                  <Form.Select
                    size="sm"
                    value={maxRedirects}
                    onChange={(e) => setMaxRedirects(Number(e.target.value))}
                    style={{ width: '105px', fontSize: '0.72rem' }}
                    data-bs-theme="dark"
                  >
                    <option value={1}>1 hop</option>
                    <option value={3}>3 hops</option>
                    <option value={5}>5 hops</option>
                    <option value={10}>10 hops</option>
                    <option value={20}>20 hops</option>
                  </Form.Select>
                </OverlayTrigger>
              )}

              <OverlayTrigger
                placement="top"
                overlay={(
                  <Tooltip>
                    Raw mode sends the bytes exactly as typed, without recomputing Content-Length or
                    repairing the headers. Required for request smuggling tests, and wrong for
                    everything else.
                  </Tooltip>
                )}
              >
                <span>
                  <Form.Check
                    type="switch"
                    id="replay-raw-mode"
                    className={rawMode ? 'text-warning' : 'text-white-50'}
                    style={{ fontSize: '0.75rem' }}
                    label="Raw mode"
                    checked={rawMode}
                    onChange={(e) => setRawMode(e.target.checked)}
                  />
                </span>
              </OverlayTrigger>

              <OverlayTrigger
                placement="top"
                overlay={(
                  <Tooltip>
                    Rewrites the request body as indented JSON, using the line ending selected here,
                    and recomputes Content-Length. This one changes the bytes that get sent, which is
                    why it is a button and not automatic.
                  </Tooltip>
                )}
              >
                <span>
                  <Button
                    variant="outline-secondary"
                    size="sm"
                    onClick={formatRequestBody}
                    disabled={!hasRequestBody}
                    style={{ fontSize: '0.72rem' }}
                  >
                    <i className="bi bi-braces me-1" />
                    Format JSON body
                  </Button>
                </span>
              </OverlayTrigger>

              <OverlayTrigger
                placement="top"
                overlay={(
                  <Tooltip>
                    The terminator every line in this buffer carries. A browser textarea cannot hold a
                    bare CR, so edits are written back in the style chosen here. Switch to LF only when
                    you mean to send LF terminated lines.
                  </Tooltip>
                )}
              >
                <Form.Select
                  size="sm"
                  value={eol}
                  onChange={(e) => changeEol(e.target.value)}
                  style={{ width: '95px', fontSize: '0.72rem' }}
                  data-bs-theme="dark"
                >
                  <option value="CRLF">CRLF</option>
                  <option value="LF">LF</option>
                </Form.Select>
              </OverlayTrigger>

              <span className="text-white-50 ms-auto" style={{ fontSize: '0.68rem' }}>
                {byteLength(rawRequest).toLocaleString()} bytes
              </span>
            </div>

            {formatNote && (
              <div
                className="text-info px-2 pb-2"
                style={{ fontSize: '0.68rem' }}
              >
                <i className="bi bi-info-circle me-1" />
                {formatNote}
              </div>
            )}
          </div>

          <div className="d-flex flex-column border border-secondary rounded"
               style={{ width: '50%', minWidth: 0, minHeight: 0 }}>
            <div className="d-flex align-items-center px-2 py-1 border-bottom border-secondary">
              <span className="text-white-50" style={{ fontSize: '0.72rem' }}>RESPONSE</span>
              {shownStatus != null && (
                <Badge bg={statusVariant(shownStatus)} className="ms-2" style={{ fontSize: '0.6rem' }}>
                  {shownStatus}
                </Badge>
              )}
              {/* Says whose response this is. A recorded one is the crawl's, shown on load; once the
                  operator edits the request it no longer belongs to these bytes, so it says so. */}
              {responseSource === 'recorded' && (
                <span
                  className={`ms-2 ${dirty ? 'text-warning' : 'text-white-50'}`}
                  style={{ fontSize: '0.68rem' }}
                  title={dirty
                    ? 'The response the crawl recorded for this request. You have edited the request since, so it is no longer this request’s answer - replay to get a fresh one.'
                    : 'The response the crawl recorded for this request. Replay to send it again and get a fresh one.'}
                >
                  <i className="bi bi-record-circle me-1" />
                  {dirty ? 'recorded · request edited since' : 'recorded'}
                </span>
              )}
              {activeHop && hops.length > 1 && (
                <span className="text-info ms-2" style={{ fontSize: '0.68rem' }}>
                  hop {hopIndex + 1} of {hops.length}
                </span>
              )}
              {rawMode && (
                <span className="text-warning ms-2" style={{ fontSize: '0.68rem' }}>
                  <i className="bi bi-exclamation-triangle me-1" />
                  raw mode
                </span>
              )}

              {/* Raw or pretty, and only when the body actually parsed as JSON. The exact bytes are
                  sometimes the finding, so there is always a way back to them. */}
              {responseJson.isJson && (
                <div className="ms-auto d-flex align-items-center gap-1">
                  <OverlayTrigger
                    placement="top"
                    overlay={<Tooltip>Indented copy of the JSON body. The headers are untouched.</Tooltip>}
                  >
                    <Button
                      variant={responseFormat === 'pretty' ? 'secondary' : 'outline-secondary'}
                      size="sm"
                      className="py-0"
                      style={{ fontSize: '0.65rem' }}
                      onClick={() => setResponseFormat('pretty')}
                    >
                      Pretty
                    </Button>
                  </OverlayTrigger>
                  <OverlayTrigger
                    placement="top"
                    overlay={<Tooltip>The response exactly as it arrived, byte for byte.</Tooltip>}
                  >
                    <Button
                      variant={responseFormat === 'raw' ? 'secondary' : 'outline-secondary'}
                      size="sm"
                      className="py-0"
                      style={{ fontSize: '0.65rem' }}
                      onClick={() => setResponseFormat('raw')}
                    >
                      Raw
                    </Button>
                  </OverlayTrigger>
                </div>
              )}
            </div>

            {respNote && (
              <div
                className="text-warning px-2 py-1 border-bottom border-secondary"
                style={{ fontSize: '0.7rem', backgroundColor: '#2b2410' }}
              >
                <i className="bi bi-exclamation-triangle me-1" />
                {respNote}
              </div>
            )}

            {/* A body that claimed to be JSON and was not. Said once, quietly, next to the raw bytes
                it is explaining rather than instead of them. */}
            {responseJson.parseError && (
              <div
                className="text-white-50 px-2 py-1 border-bottom border-secondary"
                style={{ fontSize: '0.68rem' }}
              >
                <i className="bi bi-info-circle me-1" />
                {responseJson.parseError}
              </div>
            )}

            {/* The chain. Every hop is a row: what was sent, what came back, and where it was sent
                next. Clicking one shows that exchange in the pane below, so the 302 is still there to
                read after the 200 arrives. */}
            {hops.length > 1 && (
              <div
                className="border-bottom border-secondary"
                style={{ maxHeight: '34%', overflowY: 'auto', backgroundColor: '#212529' }}
              >
                {hops.map((hop, index) => renderHopRow(hop, index))}
                {redirectCapped && (
                  <div className="text-warning px-2 py-1" style={{ fontSize: '0.68rem' }}>
                    <i className="bi bi-exclamation-triangle me-1" />
                    Stopped at the {maxRedirects} hop limit. The chain was still redirecting, so the
                    response below is not the end of it.
                  </div>
                )}
              </div>
            )}

            <div className="flex-grow-1" style={{ overflow: 'auto', minHeight: 0, backgroundColor: '#1e1e1e' }}>
              {replaying ? (
                <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
              ) : responseText ? (
                <pre style={{ ...MONO_STYLE, ...(wrapText ? WRAP_ON : WRAP_OFF), color: HL.plain }}>
                  {responseNodes}
                </pre>
              ) : responseSource === 'unrecorded' ? (
                <div className="text-white-50 p-3" style={{ fontSize: '0.75rem' }}>
                  The manual crawl did not store a response for this request. Hit Replay to send it
                  now and see a fresh one.
                </div>
              ) : (
                <div className="text-white-50 p-3" style={{ fontSize: '0.75rem' }}>
                  No response yet. Pick a request from the sitemap, or edit one and hit Replay.
                </div>
              )}
            </div>

            <div className="d-flex align-items-center justify-content-end gap-3 px-2 py-2 border-top border-secondary">
              {haveShownResponse ? (
                <>
                  {hops.length > 1 && (
                    <span className="text-white-50 me-auto" style={{ fontSize: '0.72rem' }}>
                      {hops.length} hops, {Math.round(totalMs).toLocaleString()} ms in total
                    </span>
                  )}
                  <span className="text-light" style={{ fontSize: '0.72rem' }}>
                    {shownBytes == null ? 'size not reported' : `${shownBytes.toLocaleString()} bytes`}
                  </span>
                  <span className="text-light" style={{ fontSize: '0.72rem' }}>
                    {shownMs == null ? 'time not reported' : `${Math.round(shownMs).toLocaleString()} ms`}
                  </span>
                </>
              ) : (
                <span className="text-muted" style={{ fontSize: '0.72rem' }}>
                  {responseSource === 'unrecorded' ? 'no response recorded' : 'no response yet'}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Far right: the variants of the selected endpoint, the primary first-class among them, with
            the open variant's edits below. */}
        <div
          className="d-flex flex-column border border-secondary rounded"
          style={{ width: '19%', minWidth: '215px', minHeight: 0 }}
        >
          <div className="d-flex align-items-center px-2 py-1 border-bottom border-secondary">
            <span className="text-white-50" style={{ fontSize: '0.72rem' }}>VARIANTS</span>
            {versionsLoading && <Spinner animation="border" size="sm" variant="danger" className="ms-2" />}
            {(endpointVariants.length >= 1
              ? endpointVariants.filter((v) => !v.hidden).length
              : versions.length) > 0 && (
              <Badge
                bg="dark"
                className="border border-secondary text-white-50 ms-2"
                style={{ fontSize: '0.55rem' }}
                title={endpointVariants.length >= 1 ? 'variants of this endpoint' : 'edits of this request'}
              >
                {endpointVariants.length >= 1
                  ? endpointVariants.filter((v) => !v.hidden).length
                  : versions.length}
              </Badge>
            )}
            {versionCaptureId && versionsAvailable && (
              <button
                type="button"
                className="btn btn-link p-0 ms-auto text-white-50"
                title="Reload the version list"
                onClick={() => loadVersions(versionCaptureId)}
                style={{ fontSize: '0.75rem', lineHeight: 1 }}
              >
                <i className="bi bi-arrow-clockwise" />
              </button>
            )}
          </div>

          {versionsError && (
            <div
              className="text-danger px-2 py-1 border-bottom border-secondary"
              style={{ fontSize: '0.68rem' }}
            >
              <i className="bi bi-exclamation-triangle me-1" />
              {versionsError}
            </div>
          )}

          {/* The server refusing a save because the bytes were already recorded is not an error and
              must not be painted as one, or the operator learns to ignore this strip. */}
          {versionNote && (
            <div
              className="text-info px-2 py-1 border-bottom border-secondary"
              style={{ fontSize: '0.68rem' }}
            >
              <i className="bi bi-info-circle me-1" />
              {versionNote}
            </div>
          )}

          <div className="flex-grow-1" style={{ overflowY: 'auto', overflowX: 'hidden', minHeight: 0 }}>
            {renderVersionsBody()}
          </div>

          {versionCaptureId && versionsAvailable && (
            <div
              className="px-2 py-1 border-top border-secondary"
              style={{ fontSize: '0.66rem', backgroundColor: dirty ? '#2b2410' : 'transparent' }}
            >
              {savingVersion ? (
                <span className="text-warning">
                  <Spinner animation="border" size="sm" className="me-2" />
                  Saving a new version
                </span>
              ) : dirty ? (
                <span className="text-warning">
                  <i className="bi bi-pencil-fill me-1" />
                  Edited. Saved as a new version when you replay, open another version, load another
                  request, or stop typing for {Math.round(AUTOSAVE_IDLE_MS / 1000)}s.
                </span>
              ) : (
                <span className="text-white-50">
                  Every edit becomes a new version of the one it was made from. Nothing here is
                  overwritten.
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Stacked on top of the pane and its fullscreen modal, never a window.confirm. Renders through
          a portal, so it sits above everything and closing it leaves the repeater exactly as it was. */}
      <Modal
        show={!!confirmDialog}
        onHide={() => resolveConfirm(false)}
        size="sm"
        centered
        data-bs-theme="dark"
        backdrop="static"
      >
        <Modal.Header closeButton>
          <Modal.Title className="text-danger" style={{ fontSize: '1rem' }}>
            {confirmDialog?.title}
          </Modal.Title>
        </Modal.Header>
        <Modal.Body className="text-white" style={{ fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>
          {confirmDialog?.body}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="outline-secondary" size="sm" onClick={() => resolveConfirm(false)}>
            Cancel
          </Button>
          <Button
            variant={confirmDialog?.variant || 'danger'}
            size="sm"
            onClick={() => resolveConfirm(true)}
          >
            {confirmDialog?.confirmLabel}
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};

// Named exports for unit tests only. All pure module-level helpers - no component state is touched by
// exporting them.
export {
  httpSegments,
  renderHttpNodes,
  pathMatchesTemplate,
  buildAttackVectorIndex,
  matchAttackVectors,
};

export default SingleRequestPane;
