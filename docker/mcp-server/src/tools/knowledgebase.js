const { z } = require('zod');
const { apiGet } = require('../api');
const { clip } = require('../utils/clip');

// The vendored bug bounty knowledge base, read through the Go API.
//
// 27 markdown files, 1.4 MB, embedded in the api binary with //go:embed. Two of those numbers decide
// everything in this file: 1.4 MB is more than an agent's whole context window, and ONE file,
// reports/accepted/hackerone-top-reports.md, is 607 KB of it. That file is not prose. It is an index,
// one disclosed report per line, each line a title, a hackerone.com link, the program and the bounty.
// Returning it, or any sizeable slice of it, teaches nothing and costs everything.
//
// So the split is deliberate and the descriptions below say it out loud, because an agent picks a
// tool by reading its description and will otherwise reach for the read:
//   search_knowledge_base  the way into reports/. A query returns matching LINES with their links and
//                          bounties, which is tiny and is the actual product of a corpus that size.
//   read_knowledge_file    the way into methodology/ and checklists/, which are short instructional
//                          prose. It works on reports/ too, but only ever a window at a time.
//   browse_knowledge_base  what exists, how big it is, and which of the two reads it wants.
//
// BUDGET IS THE WHOLE JOB HERE. read_knowledge_file takes offset and limit in LINES, and on top of
// the line limit there is a CHARACTER ceiling that is not a parameter and cannot be raised by any
// caller. A line limit alone does not bound anything: 200 lines of hackerone-top-reports.md is 30 KB,
// and 200 lines of a file with one long line each is unbounded. The ceiling is the thing that makes
// "you cannot pull 607 KB through this by accident" true rather than aspirational.
//
// The files live in the api binary, not in this container. Everything here proxies, the way every
// other tool in this server does; nothing reads the filesystem.

// Line budget for one read. The ceiling is the real bound and the line limit is the convenience.
const LINE_DEFAULT = 200;
const LINE_MAX = 1000;

// The hard character ceiling, roughly 5k tokens. Deliberately NOT a schema parameter: the moment a
// caller can raise it, "by accident" becomes reachable again. It matches the Go API's own unguarded
// default so the two layers agree on what one read costs.
const CHAR_CEILING = 20000;

// Search budgets. The API caps at 200 hits; the totals below cap what those hits are allowed to cost,
// because a matched line in reports/accepted/idor-reports.md is a whole Description block and forty
// of those is 80 KB.
const SEARCH_DEFAULT = 40;
const SEARCH_MAX = 200;
const SEARCH_TOTAL_BUDGET = 24000;
const SEARCH_LINE_MAX = 600;
const SEARCH_LINE_MIN = 120;

// A file is "short" when one read at the ceiling holds all of it, which is the only case where
// reading a whole document is honest advice.
const SHORT_FILE_BYTES = 12000;

// A heading is a report title and is normally short, but nothing guarantees it, and 200 of them in
// one response is a multiplier like any other.
const HEADING_MAX = 160;

// Categories small enough to search inside this container when the API's cap has hidden them.
//
// MEASURED against the real corpus: searching "account takeover" with category=rejected returned
// ZERO hits and filtered_out 200, because all 200 corpus-order hits the API was willing to return
// came from reports/accepted/. A caller reads that zero as "the rejected corpus never discusses
// account takeover", which is the exact shape of lie this whole layer exists to prevent, and the
// rejected corpus is the single most useful thing to search before writing a report.
//
// The route filters by category now, so this is a FALLBACK for an api image that predates that and
// answers the whole corpus regardless. It fires only when the returned hits prove the parameter was
// ignored; see searchKnowledgeBase. Against a filtering route it must stay out of the way, because
// it walks the corpus in order with no ranking and the route's page is ranked.
//
// These three categories total about 110 KB across 15 files, so scanning them directly is cheap and
// gives a COMPLETE answer for the category instead of a capped one. accepted is deliberately absent:
// it is 1.26 MB, and it is also the category the cap almost never starves, since most hits are in it.
const LOCAL_SCAN_CATEGORIES = new Set(['methodology', 'checklists', 'rejected']);
const LOCAL_SCAN_MAX_FILES = 15;

// Category is resolved from the PATH PREFIX rather than from whatever the API calls its category
// field. The embed layout is fixed and these four prefixes are it, so filtering here cannot drift out
// of step with a rename on the Go side, and a category filter can never silently return nothing
// because the two layers spell "accepted" differently.
const CATEGORY_PREFIX = {
  methodology: 'methodology/',
  checklists: 'checklists/',
  accepted: 'reports/accepted/',
  rejected: 'reports/rejected/',
};
const CATEGORIES = Object.keys(CATEGORY_PREFIX);

const browseKnowledgeBaseSchema = z.object({
  category: z.enum(CATEGORIES).optional().describe(
    'Narrow the tree to one part of the corpus. Omit for all 27 files, which is small enough to read ' +
    'whole. ' +
    'methodology: 5 short instructional documents, web app, api testing, recon, report writing and ' +
    'vulnerability chaining. Read these whole. ' +
    'checklists: 1 file, the web app checklist. ' +
    'accepted: 12 files of disclosed reports that PAID, 1.26 MB of them. This is a corpus, not a ' +
    'document. Search it. ' +
    'rejected: 9 files on why reports get closed as informational, duplicate, out of scope or ' +
    'not-a-bug. Small enough to read, and the most useful thing here before writing anything up, ' +
    'because a finding that matches one of these patterns is not worth the report.'),
});

const readKnowledgeFileSchema = z.object({
  path: z.string().describe(
    'File path as returned by browse_knowledge_base, e.g. methodology/web-app-methodology.md or ' +
    'reports/rejected/common-rejections.md. Relative to the knowledge base root: no leading slash ' +
    'and no ".." segment.'),

  offset: z.number().int().optional().describe(
    'First line to return, 1-based, defaulting to 1. This is the SAME numbering search_knowledge_base ' +
    'reports, so a hit at line_number 3120 is read by passing offset 3120, which is the intended way ' +
    'to use the report corpora: search, then read the block around the hit. Values below 1 are ' +
    'treated as 1.'),

  limit: z.number().int().optional().describe(
    `Lines to return, default ${LINE_DEFAULT}, capped at ${LINE_MAX}. The line limit is not the real ` +
    `bound: a hard ${CHAR_CEILING}-character ceiling applies to every read and is not adjustable, so ` +
    'a large limit on a file with long lines returns fewer lines than asked and says so in ' +
    'truncated_by. Use next_offset to continue rather than raising this.'),
});

const searchKnowledgeBaseSchema = z.object({
  query: z.string().describe(
    'Case-insensitive substring, matched line by line across all 27 files. It is a substring and not ' +
    'a regex and not a concept: "IDOR" finds the literal letters, so it will not find a report ' +
    'titled "Broken Access Control". Search for both, and prefer the words a report TITLE would use ' +
    '(the product name, the endpoint, "password reset", "GraphQL") over the words a taxonomy would.'),

  max: z.number().int().optional().describe(
    `Maximum hits, default ${SEARCH_DEFAULT}, hard cap ${SEARCH_MAX} at the API. Hits are RANKED: ` +
    'methodology and checklists first, then accepted reports, then rejected, and scored within a ' +
    'category so a heading beats a passing mention. A capped result is therefore the strongest N and ' +
    'not a random N, but the tail is still invisible, and total_matches on the response says how ' +
    'long that tail is. Narrow the query instead of raising this.'),

  category: z.enum(CATEGORIES).optional().describe(
    'Restrict hits to one part of the corpus: methodology, checklists, accepted, rejected. The route ' +
    'does the narrowing, so the cap applies AFTER it and a small category is never starved by a ' +
    'bigger one. search_method on the response says api when that happened. Note the spelling: the ' +
    'API indexes the report categories as reports/accepted and reports/rejected and this tool sends ' +
    'the translation, which matters because the short names went through as a 200 with zero hits ' +
    'before the route learned to refuse a category it does not know. For accepted, 1.26 MB of it, ' +
    `a query with more than ${SEARCH_MAX} hits still hides its tail; read total_matches.`),
});

// Normalise a caller-supplied path into the form the embed FS uses. Backslashes are here because this
// framework is operated from Windows and a path pasted out of a file listing arrives with them.
function normalizePath(raw) {
  return String(raw || '').trim().replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
}

// Refuse locally rather than sending. The Go side rejects traversal too and the embed FS is read-only
// and rooted, so this is not the security boundary; it is the layer that answers "you typed a path
// that cannot exist" with that sentence instead of with a 400 from somewhere else.
function pathProblem(p) {
  if (!p) return 'path is required. Use browse_knowledge_base to get the exact paths.';
  if (p.split('/').includes('..')) return `path must not contain "..": ${p}`;
  if (!p.endsWith('.md')) return `the knowledge base holds markdown only, so path must end in .md: ${p}`;
  return null;
}

function categoryOf(p) {
  for (const [name, prefix] of Object.entries(CATEGORY_PREFIX)) {
    if (p.startsWith(prefix)) return name;
  }
  return 'other';
}

function inCategory(p, category) {
  if (!category) return true;
  return p.startsWith(CATEGORY_PREFIX[category]);
}

function clampInt(value, def, min, max) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(n, min), max);
}

// A 404 on these routes means one specific thing and it is worth saying: the api container was built
// before the knowledge base existed. Left as a bare "API GET failed (404)" it reads like the corpus
// is missing or the path was wrong, and someone goes looking for the files.
async function kbGet(path) {
  try {
    return { data: await apiGet(path) };
  } catch (err) {
    const message = String((err && err.message) || err);
    if (/\(404\)/.test(message)) {
      return {
        error: 'The knowledge base routes are not served by this api container. The 27 files are '
          + 'embedded in the api binary at build time, so an api image built before the knowledge '
          + 'base was added answers 404 on every one of these routes. Rebuild the api service.',
      };
    }
    return { error: message };
  }
}

// The API's own response shape is not something this file gets to assume, so text is taken from the
// first string-valued key that could plausibly carry it, and a payload that carries none is reported
// with the keys it did have rather than silently read as an empty file. An empty file and an
// unrecognised envelope look identical downstream, and one of them is a bug.
function fileText(payload) {
  if (typeof payload === 'string') return payload;
  if (payload && typeof payload === 'object') {
    for (const key of ['content', 'text', 'body', 'markdown', 'data']) {
      if (typeof payload[key] === 'string') return payload[key];
    }
  }
  return null;
}

// The declared byte size of a file, from whichever key the payload spells it with.
//
// The route calls it size_bytes and that is the one that matters; the rest are a hedge against a
// rename. MEASURED, and the reason this is a named function rather than an inline `f.size`: every
// row came back with no size at all, so total_bytes was 0 and how_to_read told a caller to page
// through the 607 KB index with next_offset instead of searching it. An undefined size does not
// throw and does not look wrong, it just quietly turns the one number this layer exists to act on
// into nothing.
function declaredSize(payload) {
  if (!payload || typeof payload !== 'object') return undefined;
  for (const key of ['size_bytes', 'size', 'total_size', 'bytes', 'total_bytes']) {
    const n = Number(payload[key]);
    if (payload[key] !== undefined && Number.isFinite(n)) return n;
  }
  return undefined;
}

// Did we actually receive the whole file? This decides whether total_lines is a TOTAL or a FLOOR.
//
// The route truncates at 20000 characters unless full=true. If that flag is ever not honoured, or a
// future version caps harder, a 4702-line file arrives as 130 lines and reporting "total_lines: 130"
// tells a caller it has read everything when it has read 3 percent. That is the same shape as a scan
// that reports clean having sent nothing, so the count is only called a total when it can be one.
function heldWholeFile(payload, text) {
  if (!payload || typeof payload !== 'object') return true;
  if (payload.truncated === true) return false;
  const declared = declaredSize(payload);
  if (Number.isFinite(declared) && declared > Buffer.byteLength(text, 'utf8')) return false;
  return true;
}

// How to read this file, stated per entry rather than left for the caller to infer from a byte count.
function howToRead(path, size) {
  const bytes = Number.isFinite(Number(size)) ? Number(size) : null;
  if (bytes !== null && bytes <= SHORT_FILE_BYTES) {
    return 'Short. One read_knowledge_file call returns all of it.';
  }
  if (path.startsWith('reports/')) {
    const reads = bytes ? Math.ceil(bytes / CHAR_CEILING) : null;
    return 'Corpus, not a document. Use search_knowledge_base, then read_knowledge_file at the hit\'s '
      + 'line_number' + (reads ? `. Reading it end to end would take about ${reads} calls.` : '.');
  }
  const reads = bytes ? Math.ceil(bytes / CHAR_CEILING) : null;
  return reads ? `About ${reads} reads end to end; follow next_offset.` : 'Read with next_offset.';
}

async function browseKnowledgeBase(params = {}) {
  const got = await kbGet('/knowledge-base');
  if (got.error) return { error: got.error };
  const data = got.data;

  const raw = Array.isArray(data) ? data
    : (data && (data.files || data.tree || data.entries || data.items)) || [];
  if (!Array.isArray(raw)) {
    return { error: `unexpected /knowledge-base shape, keys: ${Object.keys(data || {}).join(', ')}` };
  }

  const category = params.category;
  const files = raw
    .map((f) => {
      const path = normalizePath(typeof f === 'string' ? f : (f.path || f.file || ''));
      const size = declaredSize(f);
      return {
        path,
        title: (typeof f === 'object' && f && f.title) || undefined,
        category: categoryOf(path),
        size,
        how_to_read: howToRead(path, size),
      };
    })
    .filter((f) => f.path && inCategory(f.path, category));

  const bytes = files.reduce((sum, f) => sum + (Number(f.size) || 0), 0);
  const sizeless = files.filter((f) => f.size === undefined).length;

  const out = {
    category: category || 'all',
    returned: files.length,
    total_bytes: bytes,
    files,
    note: 'methodology and checklists are instructional prose and are meant to be read. reports/ is '
      + 'a corpus of disclosed findings: search it. reports/accepted/hackerone-top-reports.md alone '
      + 'is 607 KB of index lines, each one a title, a link and a bounty, so reading it in sequence '
      + 'costs a context window and returns a list.',
  };

  // Size is the field the whole browse response is FOR: it is what decides read versus search, and
  // total_bytes is the only figure here a caller could budget against. A missing size reads as a
  // zero-byte file and a total_bytes of 0 reads as an empty corpus, neither of which errors, so the
  // absence is reported rather than summed away.
  if (sizeless > 0) {
    out.size_unknown = sizeless;
    out.size_unknown_note = `the api returned no byte size for ${sizeless} of ${files.length} files, `
      + 'so total_bytes is a floor and how_to_read on those rows is a guess from the path. The route '
      + 'spells it size_bytes; a rename there lands here as silently missing numbers.';
  }

  return out;
}

async function readKnowledgeFile(params = {}) {
  const path = normalizePath(params.path);
  const problem = pathProblem(path);
  if (problem) return { error: problem };

  // full=true, then slice HERE. The character-window the route serves without it starts at byte zero,
  // so it cannot answer a line offset at all, and a read at offset 1 of a 4702-line file would report
  // an end of file 4570 lines early. The whole file crosses the docker network into this process and
  // never leaves it: what the caller receives is bounded below by the ceiling regardless.
  const got = await kbGet(`/knowledge-base/file?path=${encodeURIComponent(path)}&full=true`);
  if (got.error) return { error: got.error };

  const text = fileText(got.data);
  if (text === null) {
    return {
      error: `no file content in the response for ${path}. Keys present: `
        + `${Object.keys(got.data || {}).join(', ') || 'none'}.`,
    };
  }

  const lines = text.split(/\r?\n/);
  const complete = heldWholeFile(got.data, text);
  const offset = Math.max(1, clampInt(params.offset, 1, 1, Number.MAX_SAFE_INTEGER));
  const limit = clampInt(params.limit, LINE_DEFAULT, 1, LINE_MAX);

  if (offset > lines.length) {
    return {
      path,
      category: categoryOf(path),
      [complete ? 'total_lines' : 'total_lines_at_least']: lines.length,
      offset,
      lines_returned: 0,
      next_offset: null,
      content: '',
      note: complete
        ? `offset ${offset} is past the end of this file, which has ${lines.length} lines.`
        : `offset ${offset} is past the ${lines.length} lines the api returned, and the api did not `
          + 'return the whole file, so this is NOT proof the file ends there.',
    };
  }

  // Fill up to the line limit, stopping early on the character ceiling. A single line longer than the
  // whole ceiling is clipped rather than dropped, so a minified or one-line document still returns
  // something instead of an empty read that looks like an empty file.
  const window = lines.slice(offset - 1, offset - 1 + limit);
  const kept = [];
  let used = 0;
  let hitCeiling = false;
  for (const line of window) {
    if (kept.length > 0 && used + line.length + 1 > CHAR_CEILING) {
      hitCeiling = true;
      break;
    }
    if (kept.length === 0 && line.length > CHAR_CEILING) {
      kept.push(clip(line, CHAR_CEILING));
      used = CHAR_CEILING;
      hitCeiling = true;
      break;
    }
    kept.push(line);
    used += line.length + 1;
  }

  const lastLine = offset + kept.length - 1;
  const more = lastLine < lines.length;
  const truncatedBy = hitCeiling ? 'char_ceiling' : (more && kept.length === limit ? 'line_limit' : null);

  const out = {
    path,
    category: categoryOf(path),
    offset,
    lines_returned: kept.length,
    next_offset: more ? lastLine + 1 : null,
    truncated_by: truncatedBy,
    content: kept.join('\n'),
  };

  if (complete) {
    out.total_lines = lines.length;
    out.reading = `lines ${offset} to ${lastLine} of ${lines.length}`;
  } else {
    // Say floor, not total. See heldWholeFile.
    out.total_lines_at_least = lines.length;
    out.reading = `lines ${offset} to ${lastLine}; the api did not return the whole file, so the `
      + 'line count above is a floor and not a total.';
  }

  if (more && path.startsWith('reports/')) {
    out.note = 'This is a report corpus and you have read a window of it. Do not summarise the file '
      + 'from this window. search_knowledge_base finds the lines that matter across all 27 files in '
      + 'one call, and each hit carries the line_number to pass back here as offset.';
  }

  return out;
}

// Search one small category exhaustively, in this container, when the API's cap has hidden it.
//
// The heading carried on each hit is the nearest PRECEDING markdown heading, which is the same rule
// the API route follows, so a hit from here and a hit from there read identically. A file that fails
// to load is named in skipped rather than dropped, because a silently short result set is the thing
// being fixed.
async function scanCategoryLocally(category, query, max) {
  const tree = await kbGet('/knowledge-base');
  if (tree.error) return { error: tree.error };

  const raw = Array.isArray(tree.data) ? tree.data
    : (tree.data && (tree.data.files || tree.data.tree || tree.data.entries || tree.data.items)) || [];
  const paths = raw
    .map((f) => normalizePath(typeof f === 'string' ? f : (f.path || f.file || '')))
    .filter((p) => p && inCategory(p, category))
    .slice(0, LOCAL_SCAN_MAX_FILES);

  const needle = query.toLowerCase();
  const hits = [];
  const skipped = [];
  for (const p of paths) {
    const got = await kbGet(`/knowledge-base/file?path=${encodeURIComponent(p)}&full=true`);
    const text = got.error ? null : fileText(got.data);
    if (text === null) {
      skipped.push(p);
      continue;
    }
    let heading = '';
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      if (/^#{1,6}\s/.test(lines[i])) heading = lines[i].trim();
      if (lines[i].toLowerCase().includes(needle)) {
        hits.push({ path: p, line_number: i + 1, line: lines[i], heading });
        if (hits.length >= max) return { hits, files_scanned: paths.length, skipped, complete: false };
      }
    }
  }
  return { hits, files_scanned: paths.length, skipped, complete: skipped.length === 0 };
}

async function searchKnowledgeBase(params = {}) {
  const query = String(params.query || '').trim();
  if (!query) {
    return { error: 'query is required. It is a case-insensitive substring matched line by line.' };
  }

  const max = clampInt(params.max, SEARCH_DEFAULT, 1, SEARCH_MAX);
  const category = params.category;

  // The ROUTE filters by category, and the name it filters on is not the name this schema uses.
  //
  // The API spells the report categories reports/accepted and reports/rejected; this tool's enum is
  // the short accepted and rejected, because that is what a caller types. Sending the short form
  // unchanged used to come back 200 with zero hits, so the translation happens here and the API also
  // refuses a category it does not know rather than answering empty.
  //
  // The full cap is still requested whenever a category is set, because the filter below is kept as
  // a fallback for an api image whose search route predates category support: that one ignores the
  // parameter, and asking it for max and then filtering locally would return three hits for a query
  // with hundreds, which reads as "the corpus barely covers this" and is an artefact of the request.
  const apiCategory = category && CATEGORY_PREFIX[category]
    ? CATEGORY_PREFIX[category].replace(/\/$/, '')
    : category;
  const ask = category ? SEARCH_MAX : max;
  const got = await kbGet(`/knowledge-base/search?q=${encodeURIComponent(query)}&max=${ask}`
    + (apiCategory ? `&category=${encodeURIComponent(apiCategory)}` : ''));
  if (got.error) return { error: got.error };
  const data = got.data;

  const raw = Array.isArray(data) ? data
    : (data && (data.results || data.matches || data.hits)) || [];
  if (!Array.isArray(raw)) {
    return { error: `unexpected /knowledge-base/search shape, keys: ${Object.keys(data || {}).join(', ')}` };
  }

  const normalised = raw.map((h) => ({
    path: normalizePath(h && (h.path || h.file)),
    line_number: h && (h.line_number !== undefined ? h.line_number : h.line_no),
    line: h && (h.line !== undefined ? h.line : h.text),
    heading: h && h.heading,
  }));

  let inScope = normalised.filter((h) => inCategory(h.path, category));
  let searchMethod = 'api';
  let localScan = null;

  // The local scan is a FALLBACK for an api that did not filter, not the normal path.
  //
  // It fires only when the route was asked for a category, came back at its cap, and returned hits
  // from OUTSIDE that category, which together mean the parameter was ignored. Measured on the image
  // that ignored it: "account takeover" with category=rejected returned zero hits and filtered_out
  // 200, because all 200 hits the api was willing to return came from reports/accepted. A caller
  // reads that zero as "the rejected corpus never discusses account takeover", which is the exact
  // lie this layer exists to prevent, and the rejected corpus is the first thing to search before
  // writing a report.
  //
  // Against a route that DOES filter, this must stay out of the way: it scans in corpus order with
  // no ranking, so replacing a ranked capped page with it would be a downgrade dressed as a repair.
  const apiIgnoredCategory = category && inScope.length < normalised.length;
  if (category && apiIgnoredCategory && raw.length >= ask && LOCAL_SCAN_CATEGORIES.has(category)) {
    localScan = await scanCategoryLocally(category, query, max);
    if (!localScan.error) {
      inScope = localScan.hits;
      searchMethod = 'local_scan';
    }
  }

  const matches = inScope.slice(0, max);

  // Per-line budget shrinks as the hit count grows, so the response cost is bounded by the total
  // rather than by the per-line number. A matched Description line in idor-reports.md runs past 800
  // characters on its own.
  const perLine = Math.max(
    SEARCH_LINE_MIN,
    Math.min(SEARCH_LINE_MAX, Math.floor(SEARCH_TOTAL_BUDGET / Math.max(1, matches.length))));

  // total_matches is the route's count of every matching LINE in the scope it searched, which is a
  // different number from returned and is the one that says whether a query was too broad. Carried
  // through rather than recomputed: forty rows out of six is a finding, forty out of four thousand
  // means narrow the query, and returned alone cannot tell those apart.
  const apiTotal = data && typeof data === 'object' && Number.isFinite(Number(data.total_matches))
    ? Number(data.total_matches)
    : undefined;

  const out = {
    query,
    category: category || 'all',
    returned: matches.length,
    search_method: searchMethod,
    matches: matches.map((h) => ({
      path: h.path,
      line_number: h.line_number,
      heading: clipLine(h.heading, query, HEADING_MAX),
      line: clipLine(h.line, query, perLine),
    })),
  };

  if (searchMethod === 'local_scan') {
    // The API's cap hid this category, so the category was searched end to end instead. Say so:
    // "0 hits" means two completely different things under the two methods.
    out.files_scanned = localScan.files_scanned;
    out.complete_for_category = localScan.complete && matches.length < max;
    if (localScan.skipped.length) out.files_unreadable = localScan.skipped;
    out.method_note = `the api capped at ${ask} hits, did not honour the category, and none of the `
      + `ones it returned were in ${category}, so all ${localScan.files_scanned} files in that `
      + 'category were searched directly. These hits are in corpus order with no ranking. '
      + (out.complete_for_category
        ? `They are every line in ${category} that matches.`
        : `Stopped at max, so more matches exist in ${category}.`);
  } else if (category && inScope.length < normalised.length) {
    out.filtered_out = normalised.length - inScope.length;
  }

  // The corpus-wide count, reported only for the api path. A local scan covers one category and a
  // total taken from the whole-corpus search would be answering a different question beside rows it
  // did not produce.
  if (apiTotal !== undefined && searchMethod === 'api') out.total_matches = apiTotal;

  // Capped means the answer is incomplete in a way the caller cannot see from the rows themselves.
  // Not reported when a local scan replaced the capped result, because that result is not what was
  // returned and saying "capped" about rows nobody received is its own kind of lie.
  if (raw.length >= ask && searchMethod === 'api') {
    out.capped = true;
    out.capped_note = `the api returned its maximum of ${ask} hits`
      + (apiTotal !== undefined ? ` out of ${apiTotal} matching lines` : ', so more exist')
      + '. The route ranks methodology and checklists ahead of accepted reports and those ahead of '
      + 'rejected, and scores within a category, so these are the strongest hits it found and not a '
      + 'random page; what is missing is the tail. Narrow the query to see past it.'
      + (category === 'accepted'
        ? ' reports/accepted is 1.26 MB, so a great deal sits in that tail.'
        : '');
  }

  out.note = 'Each hit is ONE LINE. In reports/accepted/hackerone-top-reports.md a line is an index '
    + 'entry, meaning a title, a hackerone.com link, the program and the bounty, and the report text '
    + 'is at the link and not in this corpus. In the other report files a line sits inside a block '
    + 'carrying description, how it was found, impact and the takeaway, so pass line_number to '
    + 'read_knowledge_file as offset to read the block around it. A hit proves the words appear, not '
    + 'that the finding applies to your target.';

  return out;
}

// Show the window around the hit rather than the first N characters, which on a report line is the
// bullet label and nothing else. Falls back to a plain head clip when the needle is not literally in
// the line, which happens if the API ever matches on a normalised form.
function clipLine(line, needle, budget) {
  if (typeof line !== 'string') return line;
  if (line.length <= budget) return line;
  if (needle && line.toLowerCase().includes(needle.toLowerCase())) {
    return clip(line, budget, { match: needle, window: Math.max(60, Math.floor(budget / 2)) });
  }
  return clip(line, budget);
}

module.exports = {
  browseKnowledgeBaseSchema,
  browseKnowledgeBase,
  readKnowledgeFileSchema,
  readKnowledgeFile,
  searchKnowledgeBaseSchema,
  searchKnowledgeBase,
  // Exported for the test suite and for anyone checking the budget claims are real.
  CATEGORY_PREFIX,
  LINE_DEFAULT,
  LINE_MAX,
  CHAR_CEILING,
  SEARCH_DEFAULT,
  SEARCH_MAX,
  normalizePath,
};
