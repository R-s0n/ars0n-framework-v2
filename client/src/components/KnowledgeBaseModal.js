import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Modal, Button, Form, Spinner, Alert, Badge } from 'react-bootstrap';
import useDebounce from '../hooks/useDebounce';

/* ===================================================================================================
   THE MARKDOWN RENDERER, AND WHY IT IS WRITTEN HERE RATHER THAN INSTALLED

   client/package.json carries no markdown renderer: not marked, not react-markdown, not showdown,
   nothing. Adding one so that 27 vendored files can be read would pull a parser and its transitive
   tree into the bundle for a feature that is one button in the header, so this is a small purpose
   built one instead. It handles what the knowledge base actually contains: ATX headings, ordered and
   unordered lists with nesting, links, bare URLs, fenced and inline code, bold, italic, blockquotes
   and horizontal rules. Anything else falls through as plain text rather than being mangled.

   THE SAFETY RULE, WHICH IS THE ONLY PART THAT MATTERS:

     escapeHtml() runs on the source FIRST, before a single character of markup is produced.

   Every transformation below therefore operates on text in which <, >, &, " and ' are already
   entities. A <script> in a vendored report has become &lt;script&gt; by the time any regex sees it
   and cannot turn back into a tag, because nothing downstream ever un-escapes. That ordering is what
   makes the dangerouslySetInnerHTML at the bottom of this file defensible. Reverse it and this is a
   stored XSS sink fed by markdown pulled off GitHub.

   Links get a second check on top of escaping: only http and https survive as anchors. A
   [click me](javascript:...) renders as its own literal text, because escaping does nothing about a
   javascript: URL sitting in an href.
   =================================================================================================== */

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* Only http(s) becomes an anchor. The input is already escaped, so a quote cannot break out of the
   attribute; this check is about the scheme, which escaping leaves entirely alone. */
function safeHref(url) {
  const trimmed = String(url).trim();
  if (/^https?:\/\/[^\s]+$/i.test(trimmed)) return trimmed;
  return null;
}

/* Inline spans, applied to an ALREADY ESCAPED line.

   Code spans come out first and are held as sentinels until everything else has run. Without that,
   `**kwargs` inside backticks would render bold and the reader would be shown something the file
   does not say.

   The sentinels are <C0>, <C1> for code and <A0>, <A1> for finished anchors, and they are safe
   precisely BECAUSE the input is escaped: a literal '<' cannot exist in the text at this point, so
   no document can forge one. They also cannot collide with the markup the rules below emit, which
   is only <a>, <strong> and <em>. */
function renderInline(escaped) {
  const codes = [];
  let out = escaped.replace(/`([^`]+)`/g, (m, code) => {
    codes.push(code);
    return '<C' + (codes.length - 1) + '>';
  });

  /* Finished anchors are held as <A0>, <A1> sentinels for the same reason code spans are, and it is
     not theoretical on either count.

     MEASURED in the vendored corpus: 13 report lines are written [https://url](https://url), and
     with the anchor left in place the bare URL rule below saw its own link text sitting after a '>'
     and wrapped it a second time, emitting <a href=...><a href=...>url</a></a>. Nested anchors are
     not valid HTML and the parser unpicks them into something nobody wrote.

     It also keeps the emphasis rules out of an href. A link to .../_private_/x came out as
     href="https://.../<em>private</em>/x", which is escaped and therefore harmless, and also a dead
     link, in a corpus whose entire value is that the links work. */
  const anchors = [];
  const hold = (html) => {
    anchors.push(html);
    return '<A' + (anchors.length - 1) + '>';
  };

  /* [text](url). Both halves are already escaped; the href is scheme checked, and a rejected URL
     degrades to its literal markdown rather than silently vanishing.

     The label alternation allows ONE level of nested brackets, which a naive [^\]]* does not. Real
     report titles in this corpus are full of them:

       [[Pre-Submission][H1-4420-2019] API access to Phabricator](https://hackerone.com/reports/591813)

     and without the nesting the label match stopped at the first ']', the anchor never formed, and
     the line rendered as raw markdown with a bare URL hanging off the end. The two alternatives can
     never match the same first character, so this cannot backtrack quadratically. */
  out = out.replace(/\[((?:[^[\]]|\[[^\]]*\])*)\]\(([^)\s]+)\)/g, (m, text, url) => {
    const href = safeHref(url);
    if (!href) return m;
    return hold('<a href="' + href + '" target="_blank" rel="noopener noreferrer">' + text + '</a>');
  });

  // Bare URLs, which is how most of the report files cite their sources ("- **Source:** https://...").
  // Requiring a space, '>' or '(' in front keeps this off URLs the rule above already wrapped in an
  // href, and the trailing class refuses to swallow the full stop at the end of a sentence.
  out = out.replace(/(^|[\s>(])(https?:\/\/[^\s<)]*[^\s<).,;:!?])/g, (m, pre, url) => {
    return pre + hold('<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + url + '</a>');
  });

  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/(^|[^*\w])\*([^*\n]+)\*(?!\*)/g, '$1<em>$2</em>');
  out = out.replace(/(^|[^_\w])_([^_\n]+)_(?![_\w])/g, '$1<em>$2</em>');

  // Anchors first: a held anchor can contain a code sentinel from a label written [`x`](url), so the
  // code pass has to come after the thing that puts it back in the string.
  out = out.replace(/<A(\d+)>/g, (m, i) => anchors[Number(i)]);
  out = out.replace(/<C(\d+)>/g, (m, i) => '<code>' + codes[Number(i)] + '</code>');
  return out;
}

/* Block level. Returns an HTML string.

   Every block carries data-kb-line with its 1 based source line number. That is what lets a search
   hit scroll to the line it matched instead of dumping the reader at the top of a 4700 line file. */
function renderMarkdown(src) {
  const lines = String(src).split(/\r?\n/);
  const html = [];

  // Open lists, as { tag, indent }. Nesting is by leading whitespace, which is how the vendored files
  // indent their sub bullets. No attempt is made at lazy continuation lines; none of the corpus uses
  // them and guessing wrong would silently drop text.
  let listStack = [];
  let inCode = false;
  let codeBuf = [];
  let codeLine = 0;
  let paraBuf = [];
  let paraLine = 0;
  let quoteBuf = [];
  let quoteLine = 0;

  const closeLists = () => {
    while (listStack.length) html.push('</' + listStack.pop().tag + '>');
  };
  const flushPara = () => {
    if (!paraBuf.length) return;
    html.push('<p data-kb-line="' + paraLine + '">' + renderInline(paraBuf.join(' ')) + '</p>');
    paraBuf = [];
  };
  const flushQuote = () => {
    if (!quoteBuf.length) return;
    html.push('<blockquote data-kb-line="' + quoteLine + '">' +
      quoteBuf.map((q) => '<p>' + renderInline(q) + '</p>').join('') + '</blockquote>');
    quoteBuf = [];
  };
  const flushAll = () => { flushPara(); flushQuote(); closeLists(); };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const lineNo = i + 1;

    // Fenced code. The body is escaped but otherwise untouched: no inline rule runs inside a fence,
    // which is the entire point of one.
    if (/^\s*```/.test(raw)) {
      if (inCode) {
        html.push('<pre data-kb-line="' + codeLine + '"><code>' + escapeHtml(codeBuf.join('\n')) + '</code></pre>');
        codeBuf = [];
        inCode = false;
      } else {
        flushAll();
        inCode = true;
        codeLine = lineNo;
      }
      continue;
    }
    if (inCode) { codeBuf.push(raw); continue; }

    if (!raw.trim()) { flushPara(); flushQuote(); continue; }

    const heading = raw.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      flushAll();
      const level = heading[1].length;
      html.push('<h' + level + ' data-kb-line="' + lineNo + '">' +
        renderInline(escapeHtml(heading[2].replace(/\s*#+\s*$/, ''))) + '</h' + level + '>');
      continue;
    }

    if (/^\s*([-*_])\s*\1\s*\1[-*_\s]*$/.test(raw)) {
      flushAll();
      html.push('<hr />');
      continue;
    }

    const quote = raw.match(/^\s*>\s?(.*)$/);
    if (quote) {
      flushPara();
      closeLists();
      if (!quoteBuf.length) quoteLine = lineNo;
      quoteBuf.push(escapeHtml(quote[1]));
      continue;
    }
    flushQuote();

    const bullet = raw.match(/^(\s*)[-*+]\s+(.*)$/);
    const numbered = raw.match(/^(\s*)\d+[.)]\s+(.*)$/);
    if (bullet || numbered) {
      flushPara();
      const m = bullet || numbered;
      const indent = m[1].length;
      const tag = bullet ? 'ul' : 'ol';
      while (listStack.length && listStack[listStack.length - 1].indent > indent) {
        html.push('</' + listStack.pop().tag + '>');
      }
      const top = listStack[listStack.length - 1];
      if (!top || top.indent < indent) {
        listStack.push({ tag, indent });
        html.push('<' + tag + '>');
      } else if (top.tag !== tag) {
        html.push('</' + listStack.pop().tag + '>');
        listStack.push({ tag, indent });
        html.push('<' + tag + '>');
      }
      html.push('<li data-kb-line="' + lineNo + '">' + renderInline(escapeHtml(m[2])) + '</li>');
      continue;
    }
    closeLists();

    if (!paraBuf.length) paraLine = lineNo;
    paraBuf.push(escapeHtml(raw.trim()));
  }

  // An unterminated fence at EOF still has to render, otherwise the tail of the file disappears.
  if (inCode) {
    html.push('<pre data-kb-line="' + codeLine + '"><code>' + escapeHtml(codeBuf.join('\n')) + '</code></pre>');
  }
  flushAll();
  return html.join('\n');
}

/* ===================================================================================================
   THE TREE

   The API names each file's category ("methodology", "checklists", "reports/accepted",
   "reports/rejected") and hands back a label for it, and it returns the files already sorted into the
   order the methodology would have someone read them. Both are used as given rather than re-derived.

   What is NOT taken from the API is the icon, and what is kept as a fallback is the path prefix: the
   directory layout is fixed by the //go:embed and cannot drift, so a category string the client has
   never heard of still lands in a sensible group instead of vanishing. Anything matching neither goes
   to "Other", because a file dropped silently from a reader is worse than one filed oddly.
   =================================================================================================== */

const GROUPS = [
  { key: 'methodology', label: 'Methodology', prefix: 'methodology/', icon: 'bi-compass' },
  { key: 'checklists', label: 'Checklists', prefix: 'checklists/', icon: 'bi-check2-square' },
  { key: 'reports/accepted', label: 'Accepted Reports', prefix: 'reports/accepted/', icon: 'bi-trophy' },
  { key: 'reports/rejected', label: 'Rejected Reports', prefix: 'reports/rejected/', icon: 'bi-x-octagon' },
];
const OTHER_GROUP = { key: 'other', label: 'Other', icon: 'bi-file-earmark-text' };

function groupOf(file) {
  const category = String((file && file.category) || '').toLowerCase();
  if (GROUPS.some((g) => g.key === category)) return category;
  const p = String((file && file.path) || '').replace(/^\.?\//, '');
  const hit = GROUPS.find((g) => p.startsWith(g.prefix));
  return hit ? hit.key : 'other';
}

// The API derives the title from the document's own H1, so this only runs for a response shape that
// has changed under us.
function titleOf(file) {
  if (file && file.title) return file.title;
  const base = String((file && file.path) || '').split('/').pop().replace(/\.md$/i, '');
  return base.replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function humanSize(bytes) {
  const n = Number(bytes) || 0;
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  if (n >= 1024) return Math.round(n / 1024) + ' KB';
  return n + ' B';
}

/* Module scope on purpose, not component state and not a ref.

   The modal unmounts when it is closed, so anything held inside it dies with it and reopening would
   re-pull the tree and re-fetch whatever was being read. These two survive that. The document cache holds
   the PARSED HTML keyed by path, not the markdown it came from: the raw text has no second reader,
   and keeping it would double the footprint for nothing. The reason the cache exists at all is
   hackerone-top-reports.md, which is 607 KB and 4702 lines, and clicking away from it and back must
   not cost a second download and a second parse. Nothing is evicted; 1.4 MB is the whole corpus and
   the operator can only read one file at a time. */
const docCache = new Map();
let treeCache = null;
let treeInFlight = null;

/* The tree, fetched at most once per page load however many times the modal is opened.

   The in-flight promise is shared rather than merely flagged, so opening, closing and reopening while
   the request is still out joins the existing one instead of firing a second. On failure the promise
   is dropped so the next open genuinely retries: caching a rejection would turn one bad response into
   a reader that stays broken until a refresh. */
function loadKnowledgeTree() {
  if (treeCache) return Promise.resolve(treeCache);
  if (!treeInFlight) {
    treeInFlight = fetch('/api/knowledge-base')
      .then((r) => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then((data) => {
        // The list may arrive bare or wrapped. Accept either, rather than showing an empty sidebar
        // because of a key name.
        treeCache = Array.isArray(data) ? data : (data.files || data.tree || []);
        return treeCache;
      })
      .catch((e) => { treeInFlight = null; throw e; });
  }
  return treeInFlight;
}

function KnowledgeBaseModal({ show, onHide }) {
  const [tree, setTree] = useState(treeCache || []);
  const [treeError, setTreeError] = useState('');
  const [treeLoading, setTreeLoading] = useState(false);

  const [selected, setSelected] = useState(null);
  const [doc, setDoc] = useState(null);
  const [docLoading, setDocLoading] = useState(false);
  const [docError, setDocError] = useState('');

  const [query, setQuery] = useState('');
  const debouncedQuery = useDebounce(query, 300);
  const [hits, setHits] = useState(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState('');

  // The line a search hit asked for, consumed once by the scroll effect below. A ref because the
  // scroll happens after paint and re-rendering just to record a number would be wasted work.
  const pendingLine = useRef(null);
  const docRef = useRef(null);

  /* The only request made on open. File bodies are fetched on selection, so opening the reader never
     pulls 1.4 MB.

     DEPS ARE [show] AND NOTHING ELSE, and that is load bearing. The first version also listed
     treeLoading and tree.length, and the spinner then ran forever: setTreeLoading(true) changed a
     dependency, so React tore the effect down and re-ran it while the request was still out, the
     cleanup set cancelled, and every branch of the settled promise, including the finally that clears
     the spinner, was skipped. Caught by opening the modal in a browser, where the sidebar sat on a
     spinner while a hand rolled fetch from the console returned all 27 files. Any state this effect
     writes must stay out of its dependency list. */
  useEffect(() => {
    if (!show) return;
    let cancelled = false;
    setTreeLoading(true);
    setTreeError('');
    loadKnowledgeTree()
      .then((files) => { if (!cancelled) setTree(files); })
      .catch((e) => { if (!cancelled) setTreeError('Could not load the knowledge base: ' + e.message); })
      .finally(() => { if (!cancelled) setTreeLoading(false); });
    return () => { cancelled = true; };
  }, [show]);

  const openFile = useCallback((path, line) => {
    if (!path) return;
    setSelected(path);
    pendingLine.current = line || null;
    setDocError('');

    const cached = docCache.get(path);
    if (cached) {
      // Re-set the same object so the scroll effect below re-runs for a second hit in a file that is
      // already open. Identity has to change or React sees no update.
      setDoc({ ...cached });
      return;
    }

    setDoc(null);
    setDocLoading(true);
    // full=true on purpose. A person scrolling a document is not an agent's context budget, and the
    // API's 20000 character default would cut hackerone-top-reports.md off around report 150 of 4702.
    fetch('/api/knowledge-base/file?full=true&path=' + encodeURIComponent(path))
      .then((r) => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then((data) => {
        const content = typeof data === 'string' ? data : (data.content || '');
        const entry = {
          path,
          title: (data && data.title) || '',
          corpus: !!(data && data.corpus),
          totalLines: (data && data.total_lines) || 0,
          truncated: !!(data && data.truncated),
          html: renderMarkdown(content),
        };
        docCache.set(path, entry);
        setDoc(entry);
      })
      .catch((e) => setDocError('Could not load ' + path + ': ' + e.message))
      .finally(() => setDocLoading(false));
  }, []);

  // Search runs against the API, never against what has been fetched. Only a handful of the corpus
  // is in memory at any moment, so searching locally would return a confident, wrong, small answer.
  useEffect(() => {
    if (!show) return;
    const q = debouncedQuery.trim();
    if (q.length < 2) { setHits(null); setSearchError(''); setSearching(false); return; }
    let cancelled = false;
    setSearching(true);
    setSearchError('');
    fetch('/api/knowledge-base/search?max=60&q=' + encodeURIComponent(q))
      .then((r) => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then((data) => {
        if (cancelled) return;
        setHits(Array.isArray(data) ? data : (data.results || data.hits || []));
      })
      .catch((e) => { if (!cancelled) { setHits([]); setSearchError('Search failed: ' + e.message); } })
      .finally(() => { if (!cancelled) setSearching(false); });
    return () => { cancelled = true; };
  }, [debouncedQuery, show]);

  /* Scroll a search hit into view. Blocks carry data-kb-line, so the target is the first block at or
     past the matched line rather than the top of the file, and the last block when the match is past
     everything anchored.

     Done straight in the effect, NOT inside requestAnimationFrame. The first version wrapped it in
     one and the jump never happened in a browser whose rAF was starved, which is not a hypothetical:
     a throttled or backgrounded tab does the same thing, and the failure is silent because clicking a
     hit still opens the right file, just at line 1 of 4702. The effect already runs after React has
     committed the DOM, and scrollIntoView forces the layout it needs, so there was nothing to wait
     for. */
  useEffect(() => {
    if (!doc || pendingLine.current === null) return;
    const want = pendingLine.current;
    pendingLine.current = null;
    const root = docRef.current;
    if (!root) return;

    const nodes = root.querySelectorAll('[data-kb-line]');
    let target = null;
    for (let i = 0; i < nodes.length; i++) {
      if (Number(nodes[i].getAttribute('data-kb-line')) >= want) { target = nodes[i]; break; }
    }
    if (!target && nodes.length) target = nodes[nodes.length - 1];
    if (!target) return;

    target.scrollIntoView({ block: 'center' });
    // A 4702 line file is a wall of near identical lines. Landing on the right scroll position is not
    // enough on its own: without the flash the reader still has to find the matched line by eye.
    target.classList.add('kb-hit-flash');
    const timer = setTimeout(() => target.classList.remove('kb-hit-flash'), 2400);
    return () => clearTimeout(timer);
  }, [doc]);

  // Not re-sorted. The API already returns instruction before examples and accepted before rejected,
  // and re-sorting by title here would quietly throw that away.
  const grouped = useMemo(() => {
    const buckets = {};
    for (const f of tree) {
      const g = groupOf(f);
      (buckets[g] = buckets[g] || []).push(f);
    }
    return buckets;
  }, [tree]);

  const selectedMeta = useMemo(
    () => tree.find((f) => f.path === selected) || null,
    [tree, selected]
  );

  const renderHit = (hit, i) => {
    const meta = tree.find((f) => f.path === hit.path);
    return (
      <button
        key={hit.path + ':' + hit.line_number + ':' + i}
        type="button"
        className="kb-hit"
        onClick={() => openFile(hit.path, hit.line_number)}
      >
        <div className="kb-hit-text">{hit.line}</div>
        <div className="kb-hit-meta">
          {meta ? titleOf(meta) : hit.path}
          {hit.heading ? <span className="kb-hit-heading"> &middot; {hit.heading}</span> : null}
          <span> &middot; line {hit.line_number}</span>
        </div>
      </button>
    );
  };

  return (
    <Modal show={show} onHide={onHide} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-book me-2"></i>
          Knowledge Base
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="p-0 kb-body">
        <div className="kb-layout">

          <div className="kb-sidebar">
            <div className="p-3 pb-2">
              <Form.Control
                size="sm"
                type="search"
                data-bs-theme="dark"
                className="custom-input"
                placeholder="Search every file"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <div className="small text-white-50 mt-1">
                {searching
                  ? 'Searching...'
                  : hits
                    ? hits.length + ' matching line' + (hits.length === 1 ? '' : 's')
                    : 'Line level search across the whole corpus.'}
              </div>
            </div>

            <div className="kb-sidebar-scroll px-3 pb-3">
              {treeError && <Alert variant="danger" className="py-2 small">{treeError}</Alert>}
              {searchError && <Alert variant="danger" className="py-2 small">{searchError}</Alert>}

              {treeLoading && !tree.length ? (
                <div className="text-center py-4"><Spinner animation="border" variant="danger" size="sm" /></div>
              ) : hits ? (
                hits.length === 0 && !searching ? (
                  <div className="text-white-50 small py-2">
                    Nothing matched. This is a substring search, so a shorter term will find more.
                  </div>
                ) : (
                  <div className="kb-hits">{hits.map(renderHit)}</div>
                )
              ) : (
                GROUPS.concat([OTHER_GROUP]).map((g) => {
                  const files = grouped[g.key] || [];
                  if (!files.length) return null;
                  return (
                    <div key={g.key} className="mb-3">
                      <div className="kb-group-label">
                        <i className={'bi ' + g.icon + ' me-2'}></i>
                        {files[0].category_label || g.label}
                        <Badge bg="secondary" className="ms-2">{files.length}</Badge>
                      </div>
                      {files.map((f) => (
                        <button
                          key={f.path}
                          type="button"
                          className={'kb-file' + (selected === f.path ? ' kb-file-active' : '')}
                          onClick={() => openFile(f.path)}
                          title={
                            f.path +
                            (f.lines ? '\n' + f.lines + ' lines' : '') +
                            (f.corpus ? '\nA corpus. Searching it beats reading it.' : '')
                          }
                        >
                          <span className="kb-file-title">{titleOf(f)}</span>
                          <span className="kb-file-size">{humanSize(f.size_bytes)}</span>
                        </button>
                      ))}
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <div className="kb-doc" ref={docRef}>
            {docError && <Alert variant="danger" className="py-2 small m-3">{docError}</Alert>}

            {docLoading ? (
              <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
            ) : !doc ? (
              <div className="kb-empty">
                <i className="bi bi-book"></i>
                <p className="mb-1">Pick a file on the left, or search across every file at once.</p>
                <p className="text-white-50 small mb-0">
                  Methodology and checklists are instructional prose. The report files are a corpus:
                  searching them for a vulnerability class returns the reports that were paid for it,
                  with their links and their bounties.
                </p>
              </div>
            ) : (
              <>
                <div className="kb-doc-head">
                  <div className="text-danger fw-bold">{doc.title || titleOf(selectedMeta) || doc.path}</div>
                  <div className="small text-white-50">
                    {doc.path}
                    {doc.totalLines ? ' · ' + doc.totalLines.toLocaleString() + ' lines' : ''}
                    {/* Said here rather than only in the empty state, because the file that most
                        needs saying it is the one you are already staring at 4702 lines of. */}
                    {doc.corpus ? ' · a corpus, searching beats scrolling' : ''}
                  </div>
                  {doc.truncated && (
                    <Alert variant="warning" className="py-1 px-2 small mt-2 mb-0">
                      The API returned this file truncated. You are not seeing all of it.
                    </Alert>
                  )}
                </div>
                {/* Safe because renderMarkdown escapes the source before producing any markup and
                    only ever emits tags it built itself. See the block comment at the top of this
                    file; the escape-first ordering is the whole of the argument. */}
                <div className="kb-markdown" dangerouslySetInnerHTML={{ __html: doc.html }} />
              </>
            )}
          </div>

        </div>
      </Modal.Body>

      <Modal.Footer className="py-2">
        <span className="text-white-50 small me-auto">
          {tree.length} file{tree.length === 1 ? '' : 's'} embedded in the API binary
        </span>
        <Button variant="secondary" size="sm" onClick={onHide}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
}

export default KnowledgeBaseModal;
