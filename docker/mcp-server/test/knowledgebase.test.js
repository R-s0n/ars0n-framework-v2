const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// The knowledge base is 1.4 MB and ONE file of it is 607 KB. Every assertion below exists because a
// tool that reads a corpus that size has exactly one way to fail badly: it succeeds, and the answer
// costs the context window that was supposed to do the work.
//
// So this suite is mostly about budget. It builds a file larger than anything actually vendored,
// asks for it in the sloppiest way an agent might, and checks that what comes back is bounded, that
// the counts describing what was NOT returned are true, and that a caller can continue from where it
// stopped. The prose is checked too, for the same reason flowverbs.test.js checks prose: an agent
// picks a tool by reading its description, and a description that fails to say "search this, do not
// read it" sends it down the expensive path forever.

// Every path this module asks the API for, so a rejection can be proved to be a LOCAL refusal rather
// than a request that happened to fail.
const REQUESTED = [];

// A stand-in for reports/accepted/hackerone-top-reports.md: more lines than the real one and longer
// lines, because the ceiling has to hold against something worse than what is vendored.
const BIG_LINES = 5000;
const BIG_LINE_CHARS = 150;
const BIG_FILE = Array.from({ length: BIG_LINES }, (_, i) =>
  `${i + 1}. [A disclosed report title padded out](https://hackerone.com/reports/${100000 + i}) `
    .padEnd(BIG_LINE_CHARS, 'x')).join('\n');

const SMALL_FILE = ['# Web Application Bug Bounty Methodology', '', '## Phase 1: Reconnaissance', '',
  '1. Subdomain enumeration', '2. Technology fingerprinting', '3. Content discovery'].join('\n');

// The rejected corpus, which is the one the api's hit cap was measured to hide completely. Two lines
// mention the starved query and they sit under different headings, so a local scan has to carry the
// nearest PRECEDING heading the way the api route does rather than the first one in the file.
const REJECTED_FILE = [
  '# Common Reasons Bug Bounty Reports Get Rejected',
  '',
  '## 1. Previously Known / Already Reported',
  'A starved claim of account takeover that another researcher already filed.',
  '',
  '## 2. Self-XSS',
  'Self-XSS alone is not a vulnerability.',
  'A starved account takeover claim that needs a victim to paste a payload is closed as informational.',
].join('\n');

// One line long enough that a plain head clip would return the bullet label and nothing useful.
const LONG_HIT_LINE = '- **Description:** '
  + 'The endpoint accepted an organization_id belonging to another tenant. '.repeat(20)
  + 'IDOR on the billing route. '
  + 'Filler that follows the interesting part and must not crowd it out. '.repeat(20);

// THE FIELD NAMES HERE ARE THE ROUTE'S, NOT PLAUSIBLE ONES.
//
// They were plausible ones once: this stub said `size`, the route says `size_bytes`, and every test
// below passed while the live tool returned total_bytes 0, no size on any row, and a how_to_read
// telling a caller to page through the 607 KB index with next_offset instead of searching it. A stub
// that invents a field name tests the stub. Checked against server/utils/knowledgeBase.go: the tree
// serves path, title, category, category_label, size_bytes, lines and corpus.
const TREE = {
  total_files: 6,
  categories: [
    { category: 'methodology', label: 'Methodology', files: 2, size_bytes: 12110 },
    { category: 'checklists', label: 'Checklists', files: 1, size_bytes: 6028 },
    { category: 'reports/accepted', label: 'Accepted Reports', files: 2, size_bytes: 655415 },
    { category: 'reports/rejected', label: 'Rejected Reports', files: 1, size_bytes: 9496 },
  ],
  files: [
    { path: 'methodology/web-app-methodology.md', title: 'Web Application Methodology', category: 'methodology', category_label: 'Methodology', size_bytes: 6022, lines: 177, corpus: false },
    { path: 'methodology/recon-methodology.md', title: 'Recon Methodology', category: 'methodology', category_label: 'Methodology', size_bytes: 6088, lines: 180, corpus: false },
    { path: 'checklists/web-app-checklist.md', title: 'Web App Checklist', category: 'checklists', category_label: 'Checklists', size_bytes: 6028, lines: 160, corpus: false },
    { path: 'reports/accepted/hackerone-top-reports.md', title: 'Top HackerOne Reports', category: 'reports/accepted', category_label: 'Accepted Reports', size_bytes: 607459, lines: 4702, corpus: true },
    { path: 'reports/accepted/idor-reports.md', title: 'IDOR Reports', category: 'reports/accepted', category_label: 'Accepted Reports', size_bytes: 47956, lines: 1200, corpus: true },
    { path: 'reports/rejected/common-rejections.md', title: 'Common Rejections', category: 'reports/rejected', category_label: 'Rejected Reports', size_bytes: 9496, lines: 60, corpus: true },
  ],
};

// What the file route serves, per path, so a local scan of a category reads plausible content.
const FILES = {
  'methodology/web-app-methodology.md': SMALL_FILE,
  'methodology/recon-methodology.md': SMALL_FILE,
  'checklists/web-app-checklist.md': SMALL_FILE,
  'reports/accepted/hackerone-top-reports.md': BIG_FILE,
  'reports/accepted/idor-reports.md': BIG_FILE,
  'reports/rejected/common-rejections.md': REJECTED_FILE,
};

// Search hits, ranked the way the route ranks them, with enough of them to trip the cap and one line
// far past any sane per-hit budget.
//
// The query "starved" reproduces the measured failure exactly: every hit the api is willing to return
// comes from reports/accepted, so a filter for any other category, applied to this list, finds
// nothing at all while the corpus plainly contains matches.
function searchHits(n, query) {
  const out = [];
  const starved = String(query || '').toLowerCase().includes('starved');
  for (let i = 0; i < n; i += 1) {
    const inAccepted = starved || i % 2 === 0;
    out.push({
      path: inAccepted ? 'reports/accepted/idor-reports.md' : 'reports/rejected/common-rejections.md',
      line_number: 100 + i,
      line: i === 0 && !starved ? LONG_HIT_LINE : `short line ${i} mentioning ${query}`,
      heading: inAccepted ? `### ${i + 1}. IDOR on something` : '## 3. Self-XSS',
      category: inAccepted ? 'reports/accepted' : 'reports/rejected',
    });
  }
  return out;
}

// A switch the stubs read, so one test can make the api behave as an image built before the
// knowledge base existed without unloading the module.
//
// 'ignores_category' is the api image whose search route predates the category parameter. It is a
// mode rather than the default because the live route DOES filter, and a stub that pretends
// otherwise is how the tool ended up with a fifteen-round-trip reimplementation of a filter the
// server already runs.
let mode = 'ok';

let stubbed = null;
try {
  const apiPath = require.resolve('../src/api.js');
  const stub = {
    apiGet: async (p) => {
      REQUESTED.push(p);
      if (mode === '404') throw new Error(`API GET ${p} failed (404): 404 page not found`);
      if (p === '/knowledge-base') {
        if (mode === 'sizeless_tree') {
          return { files: TREE.files.map(({ size_bytes, ...rest }) => rest) };
        }
        return TREE;
      }
      if (p.startsWith('/knowledge-base/file')) {
        const asked = decodeURIComponent((p.match(/[?&]path=([^&]*)/) || [])[1] || '');
        const full = /[?&]full=true/.test(p);
        const body = FILES[asked] || (asked.startsWith('reports/') ? BIG_FILE : SMALL_FILE);
        if (mode === 'ignores_full' || !full) {
          // What the route does without full=true, and what a future version might do WITH it.
          return { path: asked, content: body.slice(0, 20000), truncated: true, size_bytes: body.length };
        }
        return { path: asked, content: body, truncated: false, size_bytes: body.length };
      }
      if (p.startsWith('/knowledge-base/search')) {
        const max = parseInt((p.match(/[?&]max=(\d+)/) || [])[1], 10) || 40;
        const q = decodeURIComponent((p.match(/[?&]q=([^&]*)/) || [])[1] || '');
        const wanted = decodeURIComponent((p.match(/[?&]category=([^&]*)/) || [])[1] || '');
        // Read as flags rather than as one value: "the api ignores category" and "this query has
        // few hits" are independent facts and a test needs to set both at once.
        let hits = searchHits(mode.includes('few_hits') ? 3 : max, q);
        if (wanted && !mode.includes('ignores_category')) {
          // The route spells the report categories reports/accepted and reports/rejected. A name it
          // does not index is a 404, not an empty 200: that zero is indistinguishable from a corpus
          // that is silent on the query, and one of the two is a reason to stop looking.
          const known = ['methodology', 'checklists', 'reports', 'reports/accepted', 'reports/rejected'];
          if (!known.includes(wanted.toLowerCase())) {
            throw new Error(`API GET ${p} failed (404): {"error":"unknown_category"}`);
          }
          hits = hits.filter((h) => h.category === wanted || h.category.startsWith(`${wanted}/`));
        }
        return {
          query: q,
          hits,
          returned: hits.length,
          // The route counts every matching line, not the ones it chose to return. A capped page of
          // 200 out of 4000 and a complete page of 200 out of 200 are the same rows and different
          // answers, and returned alone cannot tell them apart.
          total_matches: hits.length + 37,
          max,
          scan_capped: false,
        };
      }
      throw new Error(`API GET ${p} failed (404): not found`);
    },
    apiPost: async () => ({}),
    apiPut: async () => ({}),
    apiPatch: async () => ({}),
    apiDelete: async () => ({}),
  };
  require.cache[apiPath] = { id: apiPath, filename: apiPath, loaded: true, exports: stub };
  stubbed = true;
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

let kb = null;
try {
  kb = require('../src/tools/knowledgebase');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = kb ? test : test.skip;
const wired = kb && stubbed ? test : test.skip;

const SRC = path.join(__dirname, '..', 'src', 'tools', 'knowledgebase.js');

// === The exports index.js is going to import ===================================================

maybe('the three tools are exported under the names the registration uses', () => {
  for (const name of ['browseKnowledgeBase', 'browseKnowledgeBaseSchema',
    'readKnowledgeFile', 'readKnowledgeFileSchema',
    'searchKnowledgeBase', 'searchKnowledgeBaseSchema']) {
    assert.ok(kb[name], `${name} is not exported, so index.js cannot register it`);
  }
});

// === Budget: the point of the whole file ========================================================

wired('a sloppy read of a huge file is bounded by the character ceiling, not by the line limit', async () => {
  const out = await kb.readKnowledgeFile({
    path: 'reports/accepted/hackerone-top-reports.md',
    limit: 999999,
  });
  assert.ok(out.content.length <= kb.CHAR_CEILING,
    `a single read returned ${out.content.length} characters, past the ${kb.CHAR_CEILING} ceiling`);
  assert.ok(out.lines_returned < kb.LINE_MAX,
    'the ceiling should have stopped this read well short of the line cap');
  assert.equal(out.truncated_by, 'char_ceiling');
  // And the caller is told the truth about what it has NOT seen.
  assert.equal(out.total_lines, BIG_LINES);
  assert.equal(out.next_offset, out.lines_returned + 1);
  assert.match(out.note || '', /search_knowledge_base/,
    'a partial read of a corpus must point at the tool that would have answered the question');
});

wired('no sequence of default reads can pull the whole corpus file in one call', async () => {
  const out = await kb.readKnowledgeFile({ path: 'reports/accepted/hackerone-top-reports.md' });
  assert.ok(out.content.length <= kb.CHAR_CEILING);
  // The read is a window and is described as one. 607 KB is about 30 of these.
  assert.ok(out.lines_returned < BIG_LINES / 10,
    `one default read returned ${out.lines_returned} of ${BIG_LINES} lines, which is not a window`);
});

wired('a short file comes back whole, because that is what methodology files are for', async () => {
  const out = await kb.readKnowledgeFile({ path: 'methodology/web-app-methodology.md' });
  assert.equal(out.content, SMALL_FILE);
  assert.equal(out.next_offset, null, 'a file read to its end must not offer a next offset');
  assert.equal(out.truncated_by, null);
  assert.equal(out.total_lines, SMALL_FILE.split('\n').length);
});

// === Offsets compose with search, which is the intended way to use reports/ =====================

wired('offset is the same 1-based number search reports, so a hit can be read directly', async () => {
  const all = BIG_FILE.split('\n');
  const out = await kb.readKnowledgeFile({
    path: 'reports/accepted/idor-reports.md', offset: 3120, limit: 5,
  });
  assert.equal(out.lines_returned, 5);
  assert.equal(out.content.split('\n')[0], all[3119],
    'offset 3120 did not start at line 3120; search line_numbers would not compose with this');
  assert.equal(out.next_offset, 3125);
  assert.equal(out.truncated_by, 'line_limit');
});

wired('walking next_offset covers the file exactly once, with no gap and no repeat', async () => {
  const all = BIG_FILE.split('\n');
  let offset = 1;
  const seen = [];
  for (let i = 0; i < 4 && offset; i += 1) {
    const page = await kb.readKnowledgeFile({
      path: 'reports/accepted/idor-reports.md', offset, limit: 20,
    });
    seen.push(...page.content.split('\n'));
    offset = page.next_offset;
  }
  assert.deepStrictEqual(seen, all.slice(0, 80));
});

wired('an offset past the end says so rather than returning an empty file', async () => {
  const out = await kb.readKnowledgeFile({
    path: 'reports/accepted/idor-reports.md', offset: BIG_LINES + 500,
  });
  assert.equal(out.lines_returned, 0);
  assert.equal(out.next_offset, null);
  assert.equal(out.total_lines, BIG_LINES);
  assert.match(out.note || '', /past the end/);
});

// === A count that cannot be a total is not called one ===========================================

wired('when the api does not return the whole file, the line count is reported as a floor', async () => {
  mode = 'ignores_full';
  try {
    const out = await kb.readKnowledgeFile({ path: 'reports/accepted/idor-reports.md' });
    assert.ok(!('total_lines' in out),
      'total_lines was emitted for a truncated payload, so a caller reading 130 of 5000 lines is '
      + 'told it has the whole file');
    assert.ok(out.total_lines_at_least > 0);
    assert.match(out.reading, /floor/);

    // And the end of what arrived must not be reported as the end of the file, which is the same
    // mistake wearing a different hat.
    const past = await kb.readKnowledgeFile({ path: 'reports/accepted/idor-reports.md', offset: 4000 });
    assert.equal(past.lines_returned, 0);
    assert.match(past.note, /NOT proof the file ends/);
  } finally {
    mode = 'ok';
  }
});

// === Paths are refused here, not sent ===========================================================

wired('a traversal path is refused locally and never reaches the api', async () => {
  REQUESTED.length = 0;
  for (const bad of ['../../etc/passwd', 'reports/../../secrets.md', '..\\..\\windows\\win.ini']) {
    const out = await kb.readKnowledgeFile({ path: bad });
    assert.match(out.error || '', /\.\./, `${bad} was not refused`);
  }
  assert.equal(REQUESTED.length, 0, 'a rejected path still produced an API call');
});

wired('a leading slash is normalised rather than sent as an absolute path', async () => {
  REQUESTED.length = 0;
  const out = await kb.readKnowledgeFile({ path: '/methodology/web-app-methodology.md' });
  assert.equal(out.path, 'methodology/web-app-methodology.md');
  assert.ok(REQUESTED.some((p) => p.includes('path=methodology%2Fweb-app-methodology.md')),
    `the request kept a leading slash: ${REQUESTED.join(', ')}`);
});

wired('a non-markdown path is refused, since the corpus holds nothing else', async () => {
  const out = await kb.readKnowledgeFile({ path: 'reports/accepted/idor-reports' });
  assert.match(out.error || '', /\.md/);
});

// === Search: the primary entry point for the report corpora =====================================

wired('search clips a long hit around the query rather than returning the line', async () => {
  const out = await kb.searchKnowledgeBase({ query: 'IDOR' });
  const long = out.matches.find((m) => m.line_number === 100);
  assert.ok(long.line.length < LONG_HIT_LINE.length, 'the oversized hit line came back in full');
  assert.match(long.line, /IDOR/, 'the clip dropped the very substring that was searched for');
});

wired('a full page of hits stays inside a sane total, however long the lines are', async () => {
  const out = await kb.searchKnowledgeBase({ query: 'IDOR', max: 200 });
  const bytes = JSON.stringify(out).length;
  assert.ok(bytes < 60000, `a 200-hit search cost ${bytes} characters`);
  assert.equal(out.returned, 200);
  assert.equal(out.capped, true, 'a result at the api cap must say so');
  // The route RANKS, so the honest warning is not "these are the first hits" but "there is a tail
  // you cannot see", and total_matches is the only field that says how long it is.
  assert.equal(out.total_matches, 237,
    'the route total was dropped, so a page of 200 out of 237 looks the same as 200 out of 4000');
  assert.match(out.capped_note || '', /237 matching lines/,
    'a capped result must say how much it did not return');
  assert.match(out.capped_note || '', /tail/,
    'a capped result must say what is missing rather than mislabel what was returned');
});

wired('max is clamped to the api cap rather than passed through', async () => {
  REQUESTED.length = 0;
  const out = await kb.searchKnowledgeBase({ query: 'IDOR', max: 100000 });
  assert.ok(out.returned <= kb.SEARCH_MAX);
  const sent = REQUESTED.find((p) => p.startsWith('/knowledge-base/search'));
  assert.match(sent, new RegExp(`max=${kb.SEARCH_MAX}(&|$)`));
});

// The route takes the category, so the narrowing happens there and the cap applies after it. The
// name has to be translated on the way out: this schema says "rejected", the route indexes
// "reports/rejected", and the short form used to go through as a 200 with zero hits.
wired('a category is narrowed by the route, under the name the route indexes', async () => {
  mode = 'few_hits';
  REQUESTED.length = 0;
  try {
    const out = await kb.searchKnowledgeBase({ query: 'IDOR', category: 'rejected', max: 10 });
    assert.equal(out.search_method, 'api',
      'the api filtered this one, so nothing here needed a local scan');
    assert.ok(out.matches.length > 0);
    for (const m of out.matches) {
      assert.ok(m.path.startsWith('reports/rejected/'), `${m.path} is not in the rejected category`);
    }
    assert.ok(!out.filtered_out,
      'filtered_out counts hits this container threw away, and the route threw none of them at us');
    const sent = REQUESTED.find((p) => p.startsWith('/knowledge-base/search'));
    assert.match(sent, /category=reports%2Frejected/,
      `the short category name went to the route unchanged: ${sent}`);
  } finally {
    mode = 'ok';
  }
});

// An api image whose search route predates the category parameter answers the whole corpus and lets
// the cap decide. The local filter has to stay for that image, and has to say what it dropped.
wired('an api that ignores the category is filtered here, and the drop is reported', async () => {
  mode = 'ignores_category_few_hits';
  try {
    const out = await kb.searchKnowledgeBase({ query: 'IDOR', category: 'rejected', max: 10 });
    assert.equal(out.search_method, 'api');
    assert.ok(out.matches.length > 0);
    for (const m of out.matches) {
      assert.ok(m.path.startsWith('reports/rejected/'), `${m.path} is not in the rejected category`);
    }
    assert.ok(out.filtered_out > 0, 'the hits dropped by the local filter were not reported');
  } finally {
    mode = 'ok';
  }
});

// MEASURED against the real corpus before this branch existed: searching "account takeover" with
// category=rejected returned zero hits and filtered_out 200, because every hit the api was willing to
// return came from reports/accepted. The rejected corpus does discuss account takeover. A zero that
// means "the cap ate them" is indistinguishable from a zero that means "the corpus is silent", and
// the second one is a reason to stop looking.
wired('a capped result that hides a small category is answered by searching that category instead', async () => {
  mode = 'ignores_category';
  try {
    const out = await kb.searchKnowledgeBase({ query: 'starved account takeover', category: 'rejected' });
    assert.ok(out.returned > 0,
      'the filter returned nothing while the category plainly contains the query');
    assert.equal(out.search_method, 'local_scan');
    assert.equal(out.complete_for_category, true);
    assert.ok(!out.capped,
      'capped describes rows that were not returned; saying it about a complete answer is noise');
    assert.ok(!('total_matches' in out),
      'the whole-corpus total belongs to hits this answer did not return');
    assert.match(out.method_note || '', /capped/);
    for (const m of out.matches) {
      assert.ok(m.path.startsWith('reports/rejected/'), `${m.path} is not in the rejected category`);
    }
  } finally {
    mode = 'ok';
  }
});

// The fallback is for an api that did not filter. Against one that did, a capped ranked page must be
// left alone: the local scan is a corpus-order substring walk with no ranking, so swapping it in
// would be a downgrade wearing the word "complete".
wired('a route that does filter is never second-guessed by the local scan', async () => {
  REQUESTED.length = 0;
  const out = await kb.searchKnowledgeBase({ query: 'IDOR', category: 'rejected' });
  assert.equal(out.search_method, 'api',
    'the route narrowed this itself, so re-reading every file in the category buys nothing');
  assert.equal(REQUESTED.filter((p) => p.startsWith('/knowledge-base/file')).length, 0,
    'a filtered search read files one by one when the route had already answered it');
  for (const m of out.matches) {
    assert.ok(m.path.startsWith('reports/rejected/'), `${m.path} is not in the rejected category`);
  }
});

wired('the hits from a local scan carry line numbers that read_knowledge_file resolves', async () => {
  mode = 'ignores_category';
  let out;
  try {
    out = await kb.searchKnowledgeBase({ query: 'starved account takeover', category: 'rejected' });
  } finally {
    mode = 'ok';
  }
  const expected = REJECTED_FILE.split('\n');
  for (const m of out.matches) {
    const read = await kb.readKnowledgeFile({ path: m.path, offset: m.line_number, limit: 1 });
    assert.equal(read.content, expected[m.line_number - 1],
      'a hit line number does not resolve to that line through read_knowledge_file');
    assert.match(read.content.toLowerCase(), /starved account takeover/);
  }
  // The nearest PRECEDING heading, not the file title, or a hit cannot be placed in the document.
  const last = out.matches[out.matches.length - 1];
  assert.match(last.heading, /Self-XSS/);
});

wired('the 1.26 MB accepted corpus is never scanned locally, and says it is capped instead', async () => {
  const out = await kb.searchKnowledgeBase({ query: 'starved account takeover', category: 'accepted' });
  assert.equal(out.search_method, 'api',
    'scanning 1.26 MB through this container to answer one search is not a trade worth making');
  assert.equal(out.capped, true);
  assert.match(out.capped_note || '', /1\.26 MB/,
    'the one category whose filter really can hide hits must say so');
});

wired('a filtered search asks the api for its full cap, so the filter is not fed three rows', async () => {
  REQUESTED.length = 0;
  await kb.searchKnowledgeBase({ query: 'IDOR', category: 'accepted', max: 5 });
  const sent = REQUESTED.find((p) => p.startsWith('/knowledge-base/search'));
  assert.match(sent, new RegExp(`max=${kb.SEARCH_MAX}(&|$)`),
    'a category filter applied after a max=5 request would report 2 hits for a query with hundreds');
});

wired('an empty query is refused instead of matching every line in 1.4 MB', async () => {
  for (const q of [undefined, '', '   ']) {
    const out = await kb.searchKnowledgeBase({ query: q });
    assert.match(out.error || '', /query is required/);
  }
});

wired('every hit carries the line number that read_knowledge_file takes as an offset', async () => {
  const out = await kb.searchKnowledgeBase({ query: 'IDOR', max: 5 });
  for (const m of out.matches) {
    assert.ok(Number.isFinite(m.line_number), 'a hit with no line_number cannot be read around');
    assert.ok(m.path, 'a hit with no path cannot be read at all');
  }
  assert.match(out.note || '', /read_knowledge_file/);
});

// === Browse ======================================================================================

wired('browse returns the tree and tells each file which read it wants', async () => {
  const out = await kb.browseKnowledgeBase({});
  assert.equal(out.returned, TREE.files.length);
  const big = out.files.find((f) => f.path.endsWith('hackerone-top-reports.md'));
  assert.match(big.how_to_read, /search_knowledge_base/,
    'the 607 KB index file must not be advertised as something to read');
  const small = out.files.find((f) => f.path.startsWith('methodology/'));
  assert.match(small.how_to_read, /one read/i);
  assert.equal(small.category, 'methodology');

  // The size is the number how_to_read is DERIVED from, so reading it out of the wrong key does not
  // fail, it just turns a corpus into something the tool advises paging through. Measured live
  // before this assertion existed: every row came back with no size, total_bytes 0, and the 607 KB
  // index advertised as "Read with next_offset."
  assert.equal(big.size, 607459, 'the 607 KB index came back with no size');
  assert.equal(small.size, 6022);
  assert.equal(out.total_bytes, TREE.files.reduce((n, f) => n + f.size_bytes, 0),
    'total_bytes did not sum the corpus, which is what a caller would budget against');
  assert.ok(!('size_unknown' in out), 'sizes were present, so nothing should be reported missing');
});

// The failure above was silent because an absent size is indistinguishable from a zero-byte file.
wired('a tree with no sizes says so rather than reporting a corpus of zero bytes', async () => {
  mode = 'sizeless_tree';
  try {
    const out = await kb.browseKnowledgeBase({});
    assert.equal(out.size_unknown, TREE.files.length);
    assert.match(out.size_unknown_note || '', /size_bytes/,
      'the note must name the field, since a rename there is how this breaks');
    const big = out.files.find((f) => f.path.endsWith('hackerone-top-reports.md'));
    assert.match(big.how_to_read, /search_knowledge_base/,
      'with no size the path still says this is a corpus, and the advice must not regress to paging');
  } finally {
    mode = 'ok';
  }
});

wired('browse filters by category on the path prefix, not on whatever the api calls it', async () => {
  for (const [category, prefix] of Object.entries(kb.CATEGORY_PREFIX)) {
    const out = await kb.browseKnowledgeBase({ category });
    assert.ok(out.files.length > 0, `${category} returned nothing`);
    for (const f of out.files) {
      assert.ok(f.path.startsWith(prefix), `${f.path} came back under category ${category}`);
    }
  }
});

// === An api that predates the knowledge base ====================================================

wired('a 404 is explained as an old api image rather than as a missing file', async () => {
  mode = '404';
  try {
    for (const out of [
      await kb.browseKnowledgeBase({}),
      await kb.readKnowledgeFile({ path: 'methodology/recon-methodology.md' }),
      await kb.searchKnowledgeBase({ query: 'IDOR' }),
    ]) {
      assert.match(out.error || '', /Rebuild the api/i,
        'a 404 on these routes reads as a missing corpus unless it says what it actually means');
    }
  } finally {
    mode = 'ok';
  }
});

// === The prose, which is how an agent chooses between these three ===============================

maybe('search describes itself as the way into the report corpora', () => {
  const strings = [
    kb.searchKnowledgeBaseSchema.shape.query._def.description,
    kb.searchKnowledgeBaseSchema.shape.max._def.description,
  ].join(' ');
  assert.match(strings, /substring/i, 'an agent must know this is not a concept search');
  // The route ranks, so the description has to say what a capped result actually costs: the tail,
  // not the quality. Claiming "corpus order" here was wrong about the service and told an agent to
  // distrust the rows it had rather than the ones it did not.
  assert.match(strings, /ranked/i, 'an agent must know the order the route returns hits in');
  assert.match(strings, /total_matches/,
    'an agent must be told which field says how much a capped result left behind');
});

maybe('the read tool advertises the ceiling it cannot be talked out of', () => {
  const d = kb.readKnowledgeFileSchema.shape.limit._def.description;
  assert.match(d, new RegExp(String(kb.CHAR_CEILING)));
  assert.match(d, /next_offset/, 'the way to continue must be in the description, not discovered');
  const o = kb.readKnowledgeFileSchema.shape.offset._def.description;
  assert.match(o, /line_number/,
    'offset must be described as the number search returns, or the two tools do not compose');
});

maybe('nothing raises the character ceiling from the outside', () => {
  for (const key of Object.keys(readKeys())) {
    assert.ok(!/char|byte|budget|ceiling|max_body/i.test(key),
      `read_knowledge_file offers ${key}, which is a way to raise the only real bound here`);
  }
  function readKeys() { return kb.readKnowledgeFileSchema.shape; }
});

maybe('the source carries no em dash, per the house rule', () => {
  const text = fs.readFileSync(SRC, 'utf8');
  assert.ok(!text.includes('—'), 'an em dash is in the source');
});
