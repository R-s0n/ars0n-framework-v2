import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import KnowledgeBaseModal from './KnowledgeBaseModal';

beforeAll(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });

/* THE ORDER OF THE TESTS IN THIS FILE IS LOAD BEARING.

   The module keeps the tree and the parsed documents in module scope on purpose: closing and
   reopening the reader must not re-download 1.4 MB. That cache survives a test, and it cannot be
   reset with jest.isolateModules, which hands the re-required component its own copy of React whose
   hook dispatcher is null under the outer react-dom.

   So the caches are treated as state the suite moves through rather than as something to clear: the
   failure case runs first while nothing is cached (a failed tree load drops the in-flight promise
   and caches nothing), then the cold load, then the reads. Each test says which cache it expects to
   be warm, which turns the constraint into coverage of the caching claim itself. */

// Response shapes copied from the live routes, not invented:
//   GET /api/knowledge-base
//   GET /api/knowledge-base/file?full=true&path=<p>
//   GET /api/knowledge-base/search?max=60&q=<q>
// The field names matter more than the values. The MCP side of this feature shipped reading a key
// called `size` off the tree while the route spells it size_bytes, and every test there passed while
// the live tool reported a corpus of zero bytes, so a fixture that guesses is worse than no fixture.
const TREE = {
  total_files: 4,
  total_bytes: 629005,
  categories: [
    { category: 'methodology', label: 'Methodology', files: 1, size_bytes: 6022 },
    { category: 'checklists', label: 'Checklists', files: 1, size_bytes: 6028 },
    { category: 'reports/accepted', label: 'Accepted Reports', files: 1, size_bytes: 607459 },
    { category: 'reports/rejected', label: 'Rejected Reports', files: 1, size_bytes: 9496 },
  ],
  files: [
    {
      path: 'methodology/web-app-methodology.md',
      title: 'Web Application Bug Bounty Methodology',
      category: 'methodology',
      category_label: 'Methodology',
      size_bytes: 6022,
      lines: 177,
      corpus: false,
    },
    {
      path: 'checklists/web-app-checklist.md',
      title: 'Web App Checklist',
      category: 'checklists',
      category_label: 'Checklists',
      size_bytes: 6028,
      lines: 160,
      corpus: false,
    },
    {
      path: 'reports/accepted/hackerone-top-reports.md',
      title: 'Top HackerOne Disclosed Reports by Category',
      category: 'reports/accepted',
      category_label: 'Accepted Reports',
      size_bytes: 607459,
      lines: 4702,
      corpus: true,
    },
    {
      path: 'reports/rejected/common-rejections.md',
      title: 'Common Rejections',
      category: 'reports/rejected',
      category_label: 'Rejected Reports',
      size_bytes: 9496,
      lines: 60,
      corpus: true,
    },
  ],
};

// A real index line out of hackerone-top-reports.md, the nested-bracket title that broke the link
// rule once, and two lines that exist to prove the renderer escapes before it marks up.
const CORPUS_BODY = [
  '# Top HackerOne Disclosed Reports by Category',
  '',
  '## Top 100 Reports by Bounty Amount',
  '1. [Full Response SSRF via Google Drive](https://hackerone.com/reports/1406938) to Dropbox - $17576, 302 upvotes',
  '2. [[Pre-Submission][H1-4420-2019] API access to Phabricator](https://hackerone.com/reports/591813) to HackerOne - $20000, 411 upvotes',
  '3. [Click me](javascript:alert(1)) to Nobody - $0, 0 upvotes',
  '4. An IDOR <script>alert("xss")</script> in the report title',
  // Both of these are shapes the corpus actually contains. The first is written 13 times in
  // hackerone-top-reports.md and used to come out as one anchor nested inside another; the second is
  // a link whose path has underscores at a word boundary, which the emphasis rule used to rewrite
  // INSIDE the href and quietly break.
  '5. [https://hackerone.com/reports/312543](https://hackerone.com/reports/312543) to Nobody - $1, 1 upvote',
  '6. [Session fixation](https://example.com/docs/_internal_/notes) to Nobody - $2, 2 upvotes',
].join('\n');

const METHODOLOGY_BODY = [
  '# Web Application Bug Bounty Methodology',
  '',
  '## Phase 4: Access Control',
  '- [ ] IDOR - Change IDs in requests to access other users\' data',
].join('\n');

const SEARCH = {
  query: 'IDOR',
  returned: 2,
  total_matches: 449,
  max: 60,
  scan_capped: false,
  hits: [
    {
      path: 'reports/accepted/hackerone-top-reports.md',
      line_number: 7,
      line: '4. An IDOR <script>alert("xss")</script> in the report title',
      heading: 'Top 100 Reports by Bounty Amount',
      category: 'reports/accepted',
      title: 'Top HackerOne Disclosed Reports by Category',
    },
    {
      path: 'methodology/web-app-methodology.md',
      line_number: 4,
      line: '- [ ] IDOR - Change IDs in requests to access other users\' data',
      heading: 'Phase 4: Access Control',
      category: 'methodology',
      title: 'Web Application Bug Bounty Methodology',
    },
  ],
};

const BODIES = {
  'methodology/web-app-methodology.md': METHODOLOGY_BODY,
  'reports/accepted/hackerone-top-reports.md': CORPUS_BODY,
};

let requested = [];

function installFetch() {
  requested = [];
  global.fetch = jest.fn((url) => {
    requested.push(url);
    if (url === '/api/knowledge-base') {
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(TREE) });
    }
    if (url.startsWith('/api/knowledge-base/file')) {
      const path = decodeURIComponent((url.match(/[?&]path=([^&]*)/) || [])[1] || '');
      const meta = TREE.files.find((f) => f.path === path) || {};
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          path,
          title: meta.title,
          category: meta.category,
          corpus: !!meta.corpus,
          size_bytes: meta.size_bytes,
          total_lines: meta.lines,
          returned_lines: meta.lines,
          truncated: false,
          content: BODIES[path] || '',
        }),
      });
    }
    if (url.startsWith('/api/knowledge-base/search')) {
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(SEARCH) });
    }
    return Promise.reject(new Error('unexpected fetch: ' + url));
  });
}

async function mountModal() {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(<KnowledgeBaseModal show onHide={() => {}} />);
  });
  // The fullscreen Modal renders through a portal onto body, not into the container.
  return { container, root, doc: document.body };
}

function click(node) {
  return act(async () => {
    node.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
}

async function typeSearch(doc, text) {
  const box = doc.querySelector('input[type="search"]');
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(box, text);
    box.dispatchEvent(new Event('input', { bubbles: true }));
  });
  // The box is debounced by 300ms, so a four letter query is one request and not four.
  await act(async () => { await new Promise((r) => setTimeout(r, 400)); });
}

afterEach(() => {
  document.body.innerHTML = '';
  delete global.fetch;
});

// FIRST, while nothing is cached. An empty sidebar and a broken one look identical, and one of them
// means the api is up and the corpus was never embedded in it.
test('a tree that fails to load says so instead of showing an empty corpus', async () => {
  requested = [];
  global.fetch = jest.fn((url) => {
    requested.push(url);
    return Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({}) });
  });
  const { doc } = await mountModal();

  expect(doc.textContent).toMatch(/Could not load the knowledge base/);
  expect(doc.querySelectorAll('.kb-file')).toHaveLength(0);
  expect(requested).toEqual(['/api/knowledge-base']);
});

test('opening the reader fetches the tree and groups it by category', async () => {
  installFetch();
  const { doc } = await mountModal();

  const labels = [...doc.querySelectorAll('.kb-group-label')].map((n) => n.textContent).join(' | ');
  expect(labels).toMatch(/Methodology/);
  expect(labels).toMatch(/Checklists/);
  expect(labels).toMatch(/Accepted Reports/);
  expect(labels).toMatch(/Rejected Reports/);

  const files = [...doc.querySelectorAll('.kb-file')];
  expect(files).toHaveLength(TREE.files.length);

  // The size on the row is what tells a reader the 607 KB index is not something to scroll. It is
  // read off size_bytes, and a wrong key renders "0 B" on every row without failing anything.
  const corpusRow = files.find((b) => b.textContent.includes('Top HackerOne'));
  expect(corpusRow.textContent).toMatch(/593 KB/);
  const smallRow = files.find((b) => b.textContent.includes('Web App Checklist'));
  expect(smallRow.textContent).toMatch(/6 KB/);
  expect(corpusRow.getAttribute('title')).toMatch(/4702 lines/);
  expect(corpusRow.getAttribute('title')).toMatch(/corpus/i);

  // Opening the reader must not pull a single file body. That is the whole lazy-load claim.
  expect(requested).toEqual(['/api/knowledge-base']);
});

test('selecting a file fetches it whole and renders it, escaping before it marks up', async () => {
  installFetch();
  const { doc } = await mountModal();

  // The tree is cached from the test above, so reopening the reader costs nothing.
  expect(requested).toEqual([]);

  const corpusRow = [...doc.querySelectorAll('.kb-file')].find((b) => b.textContent.includes('Top HackerOne'));
  await click(corpusRow);

  // full=true, because a person scrolling a document is not an agent's context budget.
  const fileCall = requested.find((u) => u.startsWith('/api/knowledge-base/file'));
  expect(fileCall).toContain('full=true');
  expect(fileCall).toContain('path=reports%2Faccepted%2Fhackerone-top-reports.md');

  const rendered = doc.querySelector('.kb-markdown');
  expect(rendered).toBeTruthy();

  // A report title carrying a script tag is TEXT. If escaping ran after the markup instead of before
  // it, this is stored XSS in the reader, fed by a vendored corpus nobody reviews line by line.
  expect(rendered.querySelector('script')).toBeNull();
  expect(rendered.textContent).toContain('<script>alert("xss")</script>');

  const hrefs = [...rendered.querySelectorAll('a')].map((a) => a.getAttribute('href'));
  expect(hrefs).toContain('https://hackerone.com/reports/1406938');
  // The nested-bracket title is the shape that broke the link rule once; it must still produce an
  // anchor rather than rendering as raw markdown with a bare URL hanging off the end.
  expect(hrefs).toContain('https://hackerone.com/reports/591813');
  // Only http(s) becomes an anchor. Escaping does nothing to a scheme.
  for (const href of hrefs) expect(href).toMatch(/^https?:\/\//);
  expect(rendered.textContent).toContain('[Click me](javascript:alert(1))');

  // A link whose LABEL is the same URL must produce exactly one anchor. The bare-URL rule used to
  // see the finished anchor's own text sitting after a '>' and wrap it again, and nested anchors are
  // not valid HTML: the parser unpicks them into something nobody wrote.
  const selfTitled = [...rendered.querySelectorAll('a')]
    .filter((a) => a.getAttribute('href') === 'https://hackerone.com/reports/312543');
  expect(selfTitled).toHaveLength(1);
  expect(selfTitled[0].querySelector('a')).toBeNull();

  // Emphasis must not run inside an href. Escaped or not, href="https://.../<em>internal</em>/notes"
  // is a dead link, and working links are the entire value of this corpus.
  expect(hrefs).toContain('https://example.com/docs/_internal_/notes');
  for (const href of hrefs) expect(href).not.toContain('<');
});

test('a search runs against the API and a hit opens that file at that line', async () => {
  installFetch();
  const { doc } = await mountModal();
  await typeSearch(doc, 'IDOR');

  const searchCall = requested.find((u) => u.startsWith('/api/knowledge-base/search'));
  expect(searchCall).toBeTruthy();
  expect(searchCall).toContain('q=IDOR');
  expect(requested.filter((u) => u.startsWith('/api/knowledge-base/search'))).toHaveLength(1);

  const hits = [...doc.querySelectorAll('.kb-hit')];
  expect(hits).toHaveLength(SEARCH.hits.length);
  expect(hits[1].textContent).toContain('Phase 4: Access Control');
  expect(hits[1].textContent).toContain('line 4');

  // scrollIntoView does not exist in jsdom, and its absence would throw inside the scroll effect.
  window.HTMLElement.prototype.scrollIntoView = jest.fn();

  // The methodology file has not been read yet, so this proves the click fetches as well as anchors.
  await click(hits[1]);

  const fileCall = requested.find((u) => u.startsWith('/api/knowledge-base/file'));
  expect(fileCall).toContain('path=methodology%2Fweb-app-methodology.md');

  // The hit is ANCHORED, not merely opened: every block carries its source line, and the block at or
  // past the matched line is the one flashed. Without that a hit in a 4702 line file opens at line 1
  // and the click has told the reader nothing.
  const rendered = doc.querySelector('.kb-markdown');
  expect(rendered.querySelectorAll('[data-kb-line]').length).toBeGreaterThan(0);
  expect(window.HTMLElement.prototype.scrollIntoView).toHaveBeenCalled();
  const flashed = rendered.querySelector('.kb-hit-flash');
  expect(flashed).toBeTruthy();
  expect(Number(flashed.getAttribute('data-kb-line'))).toBeGreaterThanOrEqual(SEARCH.hits[1].line_number);
});

test('a file already read is served from the cache rather than downloaded again', async () => {
  installFetch();
  const { doc } = await mountModal();

  // Read in the test above. 607 KB must not cross the wire a second time because the operator
  // clicked away and back.
  const corpusRow = [...doc.querySelectorAll('.kb-file')].find((b) => b.textContent.includes('Top HackerOne'));
  await click(corpusRow);

  expect(requested.filter((u) => u.startsWith('/api/knowledge-base/file'))).toHaveLength(0);
  expect(doc.querySelector('.kb-markdown').textContent).toContain('Full Response SSRF via Google Drive');
});
