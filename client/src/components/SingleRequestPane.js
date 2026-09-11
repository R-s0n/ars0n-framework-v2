import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Button, Form, InputGroup, Spinner, Badge, Accordion, Table, OverlayTrigger, Tooltip,
} from 'react-bootstrap';

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
//   2. The line-ending display toggle is display only. It renders a decorated copy of the buffer
//      into a mirror element behind the textarea. That copy is never read back, so no amount of
//      toggling can reach the bytes that get sent. The versions column does not change this: every
//      path that leaves this file with bytes in it -- the send, and the version save -- reads
//      rawRequest, never requestMirror, which is the only thing the toggle produces.
//
//      Two more display controls follow the same rule and are held to it the same way:
//
//        WRAP LINES is CSS and one HTML attribute. white-space: pre-wrap on the panes, and
//        wrap="soft" on the textarea. Soft is the only value used, ever: the HTML spec says a soft
//        wrap inserts no line breaks into the element's value, while wrap="hard" inserts them into
//        the value a FORM submits. Nothing here submits a form -- the send reads rawRequest out of
//        React state -- but "soft" is still what is written, so the question cannot arise.
//
//        JSON PRETTY-PRINTING happens on the RESPONSE only, in the responseText memo, which reads
//        rawResponse and returns a string that is handed to a <pre> and to nothing else. The
//        Raw/Pretty toggle is there because sometimes the exact bytes are the finding.
//
//      The request body is NOT auto-formatted, and that asymmetry is the point: the response is a
//      view, the request is the payload. Reformatting a payload behind the operator's back would
//      change what a target receives. The "Format JSON body" button is the one deliberate exception
//      -- it is a button, it rewrites the visible buffer, it recomputes Content-Length to match the
//      bytes it produced, and what it produced is then plainly there to read before anything is
//      sent.
//
//   3. Nothing the operator typed disappears without them being told. Before this file had
//      versions, that was one window.confirm on every path that replaced the buffer. It still is,
//      but the confirm is now the FALLBACK: the edit is first offered to the version store, and the
//      confirm only fires if that could not keep it. An edit that was saved is not an unsaved edit,
//      so asking about it would be a prompt the operator learns to click through.
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

const RESULT_LIMIT = 500;

// How long the operator has to stop typing before the edit is written down. Long enough that
// composing a header does not leave a row per pause, short enough that walking away from the
// keyboard does not lose the edit. Rendered into the hint text, so changing it here changes what
// the column promises.
const AUTOSAVE_IDLE_MS = 3000;

// Display glyphs for the line-ending view. Chosen from the Unicode control pictures block so they
// cannot be confused with anything that appears in a real request.
const GLYPH_CR = '␍';
const GLYPH_LF = '␊';

const QUERY_FIELDS = [
  ['method', 'Request method', 'method = POST'],
  ['status', 'Response status code', 'status >= 400'],
  ['host', 'Hostname from the url', 'host ~ assurant'],
  ['domain', 'Same as host', 'domain = api.example.com'],
  ['path', 'Url path, no query string', 'path ^= /api'],
  ['url', 'The whole url', 'url ~ /admin'],
  ['query', 'The raw query string', 'query ~ redirect'],
  ['mime', 'Response mime type', 'mime ~ json'],
  ['ext', 'File extension from the path', 'ext = js'],
  ['body', 'Request body', 'body ~ password'],
  ['resp.body', 'Response body. Recorded bodies only, see the note below', 'resp.body ~ token'],
  ['size', 'Response body length in bytes. Recorded bodies only', 'size > 10000'],
  ['time', 'Request duration in milliseconds', 'time > 2000'],
  ['status_class', 'First digit of the status: 1, 2, 3, 4 or 5', 'status_class = 4'],
  ['resource_type', 'Browser resource type', 'resource_type = xhr'],
  ['initiator', 'What issued the request', 'initiator ~ main.js'],
  ['is_direct', 'On the scope target host itself: true or false', 'is_direct = true'],
  ['graphql', 'GraphQL operation name', 'graphql ~ mutation'],
  ['header.<NAME>', 'A REQUEST header, by name', 'header.cookie ~ session'],
  ['resp.header.<NAME>', 'A RESPONSE header, by name', 'resp.header.server ~ nginx'],
  ['param.<NAME>', 'A GET or POST parameter, by name', 'param.id = 5'],
  ['has:header.<NAME>', 'Presence test on a request header', 'has:header.authorization'],
  ['has:param.<NAME>', 'Presence test on a parameter', 'has:param.debug'],
];

const QUERY_OPERATORS = [
  ['=', 'Equals, case insensitive', 'method = GET'],
  ['!=', 'Not equals', 'method != GET'],
  ['~', 'Contains, case insensitive', 'host ~ assurant'],
  ['!~', 'Does not contain', 'path !~ /static'],
  ['^=', 'Starts with', 'path ^= /api'],
  ['$=', 'Ends with', 'url $= .json'],
  ['=~', 'Matches a regular expression (RE2)', 'path =~ ^/api/v[0-9]+/'],
  ['>  <  >=  <=', 'Numeric. Valid on status, size, time and status_class', 'size >= 5000'],
];

const QUERY_EXAMPLES = [
  ['method = POST AND status >= 400', 'Writes that the application rejected.'],
  ['host ~ assurant AND (ext = js OR ext = json)', 'Script and data files on one host.'],
  ['has:header.authorization AND NOT path ^= /static', 'Authenticated requests, minus the asset noise.'],
  ['resp.header.content-type ~ json AND size > 5000', 'Substantial JSON responses.'],
  ['header.cookie ~ session AND method != GET', 'Session-carrying requests that change state.'],
  ['login', 'A bare term. Substring match across url, method and status.'],
  ['status_class = 5 AND time > 2000', 'Server errors that were also slow.'],
  ['path =~ ^/api/v[0-9]+/ AND method != GET', 'Versioned API routes that are not reads.'],
  ['param.id = 5 OR has:param.redirect', 'Object references and redirect parameters.'],
  ['graphql ~ mutation AND resp.body ~ error', 'GraphQL mutations whose response mentioned an error.'],
  ['is_direct = true AND resource_type = xhr', 'XHR traffic on the scope target host itself.'],
  ['path = "/a b/c"', 'Double quotes for any value containing spaces.'],
];

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

// Renders line terminators as visible glyphs. Display only: the result is never written back into
// the request buffer and never sent. Each terminator is followed by a real newline so the decorated
// copy keeps exactly the same number of visual lines as the original, which is what lets the mirror
// element sit behind the textarea in alignment.
function decorateLineEndings(text) {
  if (!text) return '';
  const parts = text.split(/(\r\n|\n|\r)/);
  let out = '';
  for (let i = 0; i < parts.length; i += 2) {
    out += parts[i];
    const terminator = parts[i + 1];
    if (terminator === '\r\n') out += `${GLYPH_CR}${GLYPH_LF}\n`;
    else if (terminator === '\n') out += `${GLYPH_LF}\n`;
    else if (terminator === '\r') out += `${GLYPH_CR}\n`;
  }
  return out;
}

// The same decoration as a list of nodes, with every glyph in a zero-width box.
//
// Needed only when the panes wrap. Unwrapped, the mirror's lines can be two characters longer than
// the textarea's with no consequence: nothing about where a line ends depends on how long it is.
// Wrapped, it decides everything. A line two glyphs longer than the one behind it wraps two
// characters earlier, gains a row, and every line below it in the mirror sits one row lower than the
// text it is supposed to be sitting behind. Giving the glyph a width of zero means the text lays out
// as if the glyph were not there, which is exactly the claim the mirror makes.
function decorateLineEndingNodes(text) {
  if (!text) return null;
  const parts = text.split(/(\r\n|\n|\r)/);
  const nodes = [];
  for (let i = 0; i < parts.length; i += 2) {
    if (parts[i]) nodes.push(parts[i]);
    const terminator = parts[i + 1];
    if (!terminator) continue;
    let glyph = GLYPH_CR;
    if (terminator === '\r\n') glyph = `${GLYPH_CR}${GLYPH_LF}`;
    else if (terminator === '\n') glyph = GLYPH_LF;
    nodes.push(
      <span
        key={`eol-${i}`}
        style={{ display: 'inline-block', width: 0, whiteSpace: 'pre', overflow: 'visible' }}
      >
        {glyph}
      </span>
    );
    nodes.push('\n');
  }
  return nodes;
}

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

// Builds the sitemap. Hosts at the top, then one node per path segment, leaves are individual
// captures. A path ending in a slash keeps its whole segment list as directories and shows the
// request itself as "/" underneath, the way Burp does, so a folder and the request to that folder
// stay distinguishable.
function buildTree(rows) {
  const hosts = new Map();
  let nextLeaf = 0;

  rows.forEach((row) => {
    const parts = parseUrlParts(row.url || row.endpoint || '');
    const host = row.host || parts.host || 'unknown';
    const segments = parts.path.split('/').filter(Boolean);
    const endsWithSlash = parts.path.endsWith('/') || segments.length === 0;
    const dirs = endsWithSlash ? segments : segments.slice(0, -1);
    const leafLabel = endsWithSlash ? '/' : segments[segments.length - 1];

    if (!hosts.has(host)) {
      hosts.set(host, { key: `h:${host}`, name: host, dirs: new Map(), leaves: [], count: 0 });
    }
    let node = hosts.get(host);
    let key = node.key;
    dirs.forEach((segment) => {
      key = `${key}/${segment}`;
      if (!node.dirs.has(segment)) {
        node.dirs.set(segment, { key, name: segment, dirs: new Map(), leaves: [], count: 0 });
      }
      node = node.dirs.get(segment);
    });

    nextLeaf += 1;
    node.leaves.push({
      id: row.id != null ? row.id : `row-${nextLeaf}`,
      label: leafLabel,
      method: (row.method || 'GET').toUpperCase(),
      status: row.status_code != null ? row.status_code : row.status,
      hasQuery: !!parts.query,
      url: row.url || '',
      row,
    });
  });

  const finish = (node) => {
    let count = node.leaves.length;
    const children = Array.from(node.dirs.values()).sort((a, b) => a.name.localeCompare(b.name));
    children.forEach((child) => { count += finish(child); });
    node.children = children;
    node.leaves.sort((a, b) => (a.label.localeCompare(b.label) || a.method.localeCompare(b.method)));
    node.count = count;
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
  const [total, setTotal] = useState(0);
  const [corpusTotal, setCorpusTotal] = useState(null);
  const [truncated, setTruncated] = useState(false);
  const [searching, setSearching] = useState(false);
  const [queryError, setQueryError] = useState('');
  const [expanded, setExpanded] = useState({});
  const [selectedId, setSelectedId] = useState(null);
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

  // The redirect chain, when one was followed. Every hop, in order, the last of which is the final
  // response. hopIndex is which one the response pane is showing.
  const [hops, setHops] = useState([]);
  const [hopIndex, setHopIndex] = useState(0);
  const [redirectCapped, setRedirectCapped] = useState(false);

  // Controls.
  const [showEol, setShowEol] = useState(false);
  const [rawMode, setRawMode] = useState(false);
  const [wrapText, setWrapText] = useState(false);
  // Off by default. A repeater's job is to show one exchange, and a redirect followed without being
  // shown turns a 302 into a 200 and takes the thing being looked at with it.
  const [followRedirects, setFollowRedirects] = useState(false);
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

  // Fresh target, fresh state. A previous target's request left in the pane is a request sent to
  // the wrong host the moment somebody hits Replay.
  useEffect(() => {
    setQuery('');
    setCaptures([]);
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

  const tree = useMemo(() => buildTree(captures), [captures]);
  const leafCount = useMemo(() => tree.reduce((sum, node) => sum + node.count, 0), [tree]);

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
            // rawRequest, never requestMirror. The line-ending view builds a decorated copy of
            // this buffer for the mirror element and that copy is not reachable from here.
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
      && !window.confirm('The request pane has edits that could not be saved as a version. Discard them and open the version you clicked?')) {
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
    if (!window.confirm(`Delete "${name}"?${consequence}`)) return;
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
        return;
      }
      const raw = (typeof data === 'string' ? data : pickString(data, ['raw_request', 'raw', 'request'])) || '';
      const derivedBase = pickString(data, ['base_url', 'baseUrl', 'origin']);
      let base = derivedBase || '';
      if (!base) {
        const url = pickString(data, ['url']) || '';
        try { base = new URL(url).origin; } catch (err) { base = ''; }
      }
      setRawRequest(raw);
      setLoadedRequest(raw);
      // Both refs move now rather than on the next render, so an auto-save decided between here
      // and that render compares against the request that was just loaded.
      bufferRef.current = raw;
      baselineRef.current = raw;
      setEol(raw.includes('\r\n') ? 'CRLF' : 'LF');
      setBaseUrl(base);
      baseUrlRef.current = base;
      setRawResponse('');
      setRespBytes(null);
      setRespMs(null);
      setRespStatus(null);
      setRespNote('');
      setHasReplayed(false);
      setHops([]);
      setHopIndex(0);
      setRedirectCapped(false);
      setFormatNote('');

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
        && !window.confirm('The request pane has unsaved edits. Discard them and load the selected request?')) {
        return;
      }
      setSelectedId(loadCaptureId);
      loadCapture(loadCaptureId);
    })();
    return () => { cancelled = true; };
    // saveVersionIfDirty is created once and never changes identity, which is what keeps this
    // effect armed only by the id. See the note on targetIdRef.
  }, [loadCaptureId, loadCapture, saveVersionIfDirty]);

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
        && !window.confirm('The request pane has unsaved edits. Discard them and load the request that was handed over?')) {
        return;
      }
      loadRawBytes(loadRawRequest);
    })();
    return () => { cancelled = true; };
  }, [loadRawRequest, loadRawBytes, saveVersionIfDirty]);

  const selectLeaf = async (leaf) => {
    // Clicking the current selection again is a reload, which is the only way back from a load that
    // failed. It is a no-op only when the pane already holds that request.
    // (Unchanged: reverting to the request as it was observed is what the ORIGINAL row in the
    // versions column is for, so this stays a no-op rather than becoming a second revert gesture.)
    if (leaf.id === selectedId && rawRequest !== '') return;
    const result = await saveVersionIfDirty();
    if (result.wasDirty && !result.saved
      && !window.confirm('The request pane has unsaved edits. Discard them and load the selected request?')) {
      return;
    }
    setSelectedId(leaf.id);
    if (!leaf.row || leaf.row.id == null) {
      setRawResponse('That capture has no id, so the framework cannot fetch its raw request.');
      return;
    }
    loadCapture(leaf.row.id);
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
    } catch (err) {
      setRawResponse(`Transport error.\n\n${err.message}`);
      setRespBytes(null);
      setRespMs(null);
      setRespStatus(null);
      setRespNote('');
      setHasReplayed(true);
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

  const requestMirror = useMemo(() => {
    if (!showEol) return '';
    return wrapText ? decorateLineEndingNodes(rawRequest) : decorateLineEndings(rawRequest);
  }, [showEol, wrapText, rawRequest]);

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
    const clipped = source.length > limit
      ? `${source.slice(0, limit)}\n\n[display truncated at ${limit.toLocaleString()} characters. The size below is the full response.]`
      : source;
    return showEol ? decorateLineEndings(clipped) : clipped;
  }, [shownRaw, showingPretty, responseJson, showEol]);

  const renderLeaf = (leaf, depth) => {
    const active = leaf.id === selectedId;
    return (
      <div
        key={`leaf-${leaf.id}`}
        onClick={() => selectLeaf(leaf)}
        title={leaf.url}
        className={`d-flex align-items-center py-1 pe-2 ${active ? 'bg-secondary bg-opacity-25' : ''}`}
        style={{ cursor: 'pointer', paddingLeft: `${8 + depth * 14}px` }}
      >
        <Badge
          bg="dark"
          className="border border-secondary text-white-50 me-2"
          style={{ fontSize: '0.55rem', minWidth: '42px' }}
        >
          {leaf.method}
        </Badge>
        <code
          className={`flex-grow-1 text-truncate ${active ? 'text-light' : 'text-white-50'}`}
          style={{ fontSize: '0.72rem' }}
        >
          {leaf.label}{leaf.hasQuery ? '?' : ''}
        </code>
        <Badge bg={statusVariant(leaf.status)} className="ms-1" style={{ fontSize: '0.55rem' }}>
          {leaf.status || '?'}
        </Badge>
      </div>
    );
  };

  const renderNode = (node, depth) => {
    const open = isOpen(node.key, depth);
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
          <span className="flex-grow-1 text-truncate text-light" style={{ fontSize: '0.75rem' }}>{node.name}</span>
          <Badge bg="dark" className="border border-secondary text-white-50" style={{ fontSize: '0.55rem' }}>
            {node.count}
          </Badge>
        </div>
        {open && (
          <div>
            {node.children.map((child) => renderNode(child, depth + 1))}
            {node.leaves.map((leaf) => renderLeaf(leaf, depth + 1))}
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
      <Accordion className="mb-2" data-bs-theme="dark">
        <Accordion.Item eventKey="0" className="bg-dark border-secondary">
          <Accordion.Header>
            <span className="text-danger">
              <i className="bi bi-question-circle me-2" />
              How to search: the query language
            </span>
          </Accordion.Header>
          <Accordion.Body style={{ maxHeight: '45vh', overflowY: 'auto' }}>
            <div className="row g-3">
              <div className="col-lg-5">
                <div className="text-light small fw-bold mb-1">Fields</div>
                <Table size="sm" variant="dark" borderless className="mb-0">
                  <tbody>
                    {QUERY_FIELDS.map(([name, meaning, example]) => (
                      <tr key={name}>
                        <td style={{ whiteSpace: 'nowrap' }}><code className="text-danger">{name}</code></td>
                        <td className="text-white-50" style={{ fontSize: '0.75rem' }}>{meaning}</td>
                        <td>
                          <code
                            className="text-info"
                            style={{ fontSize: '0.72rem', cursor: 'pointer' }}
                            onClick={() => setQuery(example)}
                          >
                            {example}
                          </code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>

              <div className="col-lg-3">
                <div className="text-light small fw-bold mb-1">Operators</div>
                <Table size="sm" variant="dark" borderless className="mb-3">
                  <tbody>
                    {QUERY_OPERATORS.map(([symbol, meaning, example]) => (
                      <tr key={symbol}>
                        <td style={{ whiteSpace: 'nowrap' }}><code className="text-danger">{symbol}</code></td>
                        <td className="text-white-50" style={{ fontSize: '0.75rem' }}>
                          {meaning}
                          <div>
                            <code
                              className="text-info"
                              style={{ fontSize: '0.72rem', cursor: 'pointer' }}
                              onClick={() => setQuery(example)}
                            >
                              {example}
                            </code>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>

                <div className="text-light small fw-bold mb-1">Booleans and grouping</div>
                <div className="text-white-50" style={{ fontSize: '0.75rem' }}>
                  <div><code className="text-danger">AND</code>, <code className="text-danger">OR</code>,{' '}
                    <code className="text-danger">NOT</code> and parentheses.</div>
                  <div className="mt-1">
                    <code className="text-danger">AND</code> is implied between adjacent terms, so{' '}
                    <code className="text-info">method = POST status &gt;= 400</code> means the same as{' '}
                    <code className="text-info">method = POST AND status &gt;= 400</code>.
                  </div>
                  <div className="mt-1">
                    A <strong>bare term</strong> with no field is a case insensitive substring match across
                    url, method and status. Typing <code className="text-info">login</code> matches any
                    capture whose url contains "login".
                  </div>
                  <div className="mt-1">
                    Use <strong>double quotes</strong> for a value containing spaces:{' '}
                    <code className="text-info">path = "/a b/c"</code>.
                  </div>
                </div>
              </div>

              <div className="col-lg-4">
                <div className="text-light small fw-bold mb-1">Examples, click to use</div>
                <Table size="sm" variant="dark" borderless className="mb-0">
                  <tbody>
                    {QUERY_EXAMPLES.map(([example, meaning]) => (
                      <tr key={example}>
                        <td>
                          <code
                            className="text-info"
                            style={{ fontSize: '0.73rem', cursor: 'pointer' }}
                            onClick={() => setQuery(example)}
                          >
                            {example}
                          </code>
                          <div className="text-white-50" style={{ fontSize: '0.7rem' }}>{meaning}</div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
                <div className="text-white-50 mt-2" style={{ fontSize: '0.72rem' }}>
                  A query the parser cannot read is reported under the search box with the position it
                  stopped at. The tree keeps showing the last good result, so a syntax error never looks
                  like a search that matched nothing.
                </div>
                <div className="text-warning mt-2" style={{ fontSize: '0.72rem' }}>
                  <i className="bi bi-info-circle me-1" />
                  The manual crawl does not store a response body for every capture. A capture without
                  one is excluded from <code className="text-danger">size</code> and{' '}
                  <code className="text-danger">resp.body</code> entirely, including from the negative
                  forms: <code className="text-info">resp.body !~ password</code> will not answer for a
                  body nobody recorded. Every other field covers the whole corpus.
                </div>
              </div>
            </div>
          </Accordion.Body>
        </Accordion.Item>
      </Accordion>

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
            {queryError && (
              <div className="text-danger mt-1" style={{ fontSize: '0.72rem' }}>
                <i className="bi bi-exclamation-triangle me-1" />
                {queryError}
              </div>
            )}
            <div className="text-white-50 mt-1" style={{ fontSize: '0.7rem' }}>
              showing {leafCount.toLocaleString()} of {Math.max(total, leafCount).toLocaleString()} matched
              {corpusTotal != null && (
                <span className="ms-1">({corpusTotal.toLocaleString()} recorded)</span>
              )}
              {truncated && (
                <span className="text-warning ms-1">
                  (truncated at {RESULT_LIMIT.toLocaleString()}, narrow the query to see the rest)
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
              tree.map((node) => renderNode(node, 0))
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
              {showEol && (
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
                    color: '#d0d0d0',
                  }}
                >
                  {requestMirror}
                </pre>
              )}
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
                  // With the line-ending view on, the glyphs come from the mirror behind this
                  // element, so the textarea paints only its caret and selection. The value it
                  // holds is untouched either way.
                  color: showEol ? 'transparent' : '#d0d0d0',
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
                <pre style={{ ...MONO_STYLE, ...(wrapText ? WRAP_ON : WRAP_OFF), color: '#d0d0d0' }}>
                  {responseText}
                </pre>
              ) : (
                <div className="text-white-50 p-3" style={{ fontSize: '0.75rem' }}>
                  No response yet. Pick a request, edit it, and hit Replay.
                </div>
              )}
            </div>

            <div className="d-flex align-items-center justify-content-end gap-3 px-2 py-2 border-top border-secondary">
              {hasReplayed ? (
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
                <span className="text-muted" style={{ fontSize: '0.72rem' }}>no replay yet</span>
              )}
            </div>
          </div>
        </div>

        {/* Far right: every version of the request now loaded, original first. */}
        <div
          className="d-flex flex-column border border-secondary rounded"
          style={{ width: '19%', minWidth: '215px', minHeight: 0 }}
        >
          <div className="d-flex align-items-center px-2 py-1 border-bottom border-secondary">
            <span className="text-white-50" style={{ fontSize: '0.72rem' }}>VERSIONS</span>
            {versionsLoading && <Spinner animation="border" size="sm" variant="danger" className="ms-2" />}
            {versions.length > 0 && (
              <Badge
                bg="dark"
                className="border border-secondary text-white-50 ms-2"
                style={{ fontSize: '0.55rem' }}
              >
                {versions.length}
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
    </div>
  );
};

export default SingleRequestPane;
