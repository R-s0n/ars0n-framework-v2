const test = require('node:test');
const assert = require('node:assert');

// db.js opens a Postgres pool and api.js an HTTP client at require time. Populating require.cache
// with a stub means neither file is ever executed, so the tools can be loaded and driven here.
function stubModule(relPath, exports) {
  const filename = require.resolve(relPath);
  require.cache[filename] = { id: filename, filename, loaded: true, exports, children: [], paths: [] };
}

const queries = [];
let respond = () => ({ rows: [] });

stubModule('../src/db', {
  query: async (sql, values) => { queries.push({ sql, values }); return respond(sql, values); },
});
stubModule('../src/api', {
  apiGet: async () => ({}), apiPost: async () => ({}), apiPut: async () => ({}), apiDelete: async () => ({}),
});

// These modules import zod, and the repo carries no node_modules locally (the image installs them,
// and .dockerignore keeps test/ out of the image). So the suite skips rather than fails where the
// dependency is absent: a red suite that means "you have not run npm install" trains people to
// ignore red suites.
let recon = null;
let targets = null;
let bugbounty = null;
try {
  recon = require('../src/tools/recon');
  targets = require('../src/tools/targets');
  bugbounty = require('../src/tools/bugbounty');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const { countStore, storeApplies, notApplicable } = require('../src/utils/scopeStores');

const maybe = recon && targets && bugbounty ? test : test.skip;

function urlTarget(extra = {}) {
  return (sql) => {
    if (sql.includes('FROM scope_targets')) return { rows: [{ id: 'target-1', type: 'URL' }] };
    for (const [needle, rows] of Object.entries(extra)) {
      if (sql.includes(needle)) return { rows };
    }
    return { rows: [] };
  };
}

// query_endpoints took a source argument, validated it against an enum, and then queried
// /consolidated-endpoints, a corpus with no per-crawler column. The filter had nowhere to go and was
// dropped: filtering by katana returned exactly the same rows as filtering by gospider or by
// nothing, so an agent comparing crawler coverage got one answer five times.
maybe('query_endpoints applies its source filter to the query', async () => {
  queries.length = 0;
  respond = urlTarget();
  await recon.queryEndpoints({ target_id: 'target-1', source: 'gospider' });

  const main = queries.find((q) => q.sql.includes('FROM discovered_endpoints') && !q.sql.includes('GROUP BY'));
  assert.ok(main, 'the raw crawler corpus (discovered_endpoints) was never queried');
  assert.match(main.sql, /scan_type = \$2/, 'the source filter is not in the SQL');
  assert.deepEqual(main.values, ['target-1', 'gospider']);
});

maybe('query_endpoints with no source does not invent a filter', async () => {
  queries.length = 0;
  respond = urlTarget();
  await recon.queryEndpoints({ target_id: 'target-1' });

  const main = queries.find((q) => q.sql.includes('FROM discovered_endpoints') && !q.sql.includes('GROUP BY'));
  assert.ok(main);
  assert.ok(!main.sql.includes('scan_type ='), 'an unfiltered call must not narrow to one crawler');
  assert.deepEqual(main.values, ['target-1']);
});

// Every zero from this tool has to say which of the two things it means.
maybe('query_endpoints reports which crawlers have rows so a zero can be read', async () => {
  respond = urlTarget({ 'GROUP BY 1': [{ scan_type: 'katana', count: '22' }] });
  const out = await recon.queryEndpoints({ target_id: 'target-1', source: 'gospider' });

  assert.equal(out.source_filter, 'gospider');
  assert.deepEqual(out.sources_present, { katana: 22 });
});

// get_attack_surface answered 0 subdomains, 0 target URLs and 0 live servers for a URL target that
// held 196 consolidated endpoints and 202 attack vectors. Every count came from a Wildcard or
// Company table, and the tool is described as a complete overview, so the answer read as an
// untouched target.
maybe('get_attack_surface reads the URL corpus for a URL target', async () => {
  respond = urlTarget({
    'COUNT(*) AS total,': [{ total: '196', manually_added: '24', api_class: '55' }],
    'COUNT(*) AS total FROM attack_vectors': [{ total: '202' }],
  });
  const surface = await recon.getAttackSurface({ target_id: 'target-1' });

  assert.equal(surface.endpoints.total, 196, 'the endpoint corpus is the attack surface of a URL target');
  assert.equal(surface.attack_vectors.total, 202);
});

maybe('get_attack_surface says why the Wildcard and Company stores are empty', async () => {
  respond = urlTarget();
  const surface = await recon.getAttackSurface({ target_id: 'target-1' });

  for (const key of ['subdomain_count', 'company_domain_count', 'network_range_count', 'live_server_count', 'target_urls']) {
    assert.equal(surface[key].applicable, false, `${key} came back as a bare count, which reads as "none found"`);
    assert.match(surface[key].reason, /URL target/, `${key} does not explain itself`);
  }
});

// live_web_servers has no scope_target_id column. The old count threw, the throw was caught, and the
// caller got 0, so "0 live servers" was never once a measurement, on any target of any type.
test('the live web server count joins through the IP/port scan', async () => {
  const seen = [];
  const stub = async (sql) => { seen.push(sql); return { rows: [{ count: '7' }] }; };
  const count = await countStore(stub, 'live_web_servers', 'Company', 'target-1');

  assert.equal(count, 7);
  assert.match(seen[0], /JOIN ip_port_scans/);
  assert.ok(!/live_web_servers\s+WHERE scope_target_id/.test(seen[0]),
    'live_web_servers has no scope_target_id column, so this query would throw and be read as zero');
});

// A store that cannot be read is not a store with nothing in it.
test('a failing count reports the error instead of zero', async () => {
  const stub = async () => { throw new Error('relation "consolidated_subdomains" does not exist'); };
  const out = await countStore(stub, 'consolidated_subdomains', 'Wildcard', 'target-1');

  assert.ok(out && out.error, 'a query that failed came back looking like a count of nothing');
});

test('a store the target type cannot populate is never counted', async () => {
  let called = false;
  const stub = async () => { called = true; return { rows: [{ count: '0' }] }; };
  const out = await countStore(stub, 'consolidated_subdomains', 'URL', 'target-1');

  assert.equal(called, false, 'a store that cannot apply must not be queried at all');
  assert.equal(out.applicable, false);
  assert.equal(storeApplies('consolidated_subdomains', 'URL'), false);
  assert.match(notApplicable('target_urls', 'URL').reason, /Wildcard and Company/);
});

// find_api_endpoints searched target_urls only. A URL target has no row in that table, so on a
// target holding /api-docs/swagger.json plus 25 /rest/ and 27 /api/ endpoints it returned total 0
// with every category empty.
maybe('find_api_endpoints searches the corpus the target type actually has', async () => {
  queries.length = 0;
  respond = urlTarget({
    'FROM consolidated_url_endpoints': [
      { url: 'http://t/api-docs/swagger.json', method: 'GET' },
      { url: 'http://t/rest/products/search', method: 'GET' },
    ],
  });
  const out = await bugbounty.findApiEndpoints({ target_id: 'target-1' });

  assert.equal(out.searched, 'consolidated_url_endpoints');
  assert.equal(out.total, 2);
  assert.equal(out.categories.swagger_openapi.length, 1);
  assert.ok(!queries.some((q) => q.sql.includes('FROM target_urls')),
    'target_urls is empty for every URL target and searching it can only return nothing');
});

// get_target_summary counted a fixed list of Wildcard scan tables for every target type, so a URL
// target with seventeen finished runs reported scan_counts: {}.
maybe('get_target_summary counts the workflow that actually ran', async () => {
  queries.length = 0;
  respond = urlTarget();
  const summary = await targets.getTargetSummary({ target_id: 'target-1' });

  for (const tool of ['katana_url', 'linkfinder_url', 'waybackurls', 'gau_url', 'gospider_url', 'arjun', 'x8']) {
    assert.ok(tool in summary.scan_counts, `${tool} is missing from scan_counts, so its runs are invisible`);
  }
  assert.ok(!('amass' in summary.scan_counts),
    'amass cannot run against a URL target, and reporting it as 0 says the same thing as a tool that has not been run');
  assert.equal(summary.asset_counts.target_urls.applicable, false);
  assert.equal(typeof summary.asset_counts.consolidated_url_endpoints, 'number');
});

// MEASURED, and the reason limitFetched exists. query_endpoints with source=linkfinder and
// max_results=5 answered `total: 6` while sources_present in the SAME response said linkfinder had
// found 13. `total` was rows.length on a page Postgres had already clipped to LIMIT 6, so the number
// that reads as "how much is there" could never exceed the page size. A caller reads 6 and stops.
maybe('a clipped page reports the counted total, not the page size', async () => {
  queries.length = 0;
  const page = Array.from({ length: 6 }, (_, i) => ({ url: `http://t/${i}`, source: 'linkfinder' }));
  respond = (sql) => {
    if (sql.includes('FROM scope_targets')) return { rows: [{ id: 'target-1', type: 'URL' }] };
    if (sql.includes('COUNT(*) AS count')) return { rows: [{ count: '13' }] };
    if (sql.includes('GROUP BY')) return { rows: [{ scan_type: 'linkfinder', count: '13' }] };
    return { rows: page };
  };
  const out = await recon.queryEndpoints({ target_id: 'target-1', source: 'linkfinder', max_results: 5 });

  assert.equal(out.returned, 5, 'the caller asked for 5 rows and must get 5, not the truncation probe row');
  assert.equal(out.data.length, 5);
  assert.equal(out.truncated, true);
  assert.equal(out.total, 13, 'total must be the counted match, not the size of the clipped page');
  assert.ok(queries.some((q) => q.sql.includes('COUNT(*) AS count') && q.sql.includes('scan_type = $2')),
    'the count must apply the same filters as the page, or it counts a different question');
});

// The counterpart: when nothing was clipped the page IS the whole answer, and paying for a second
// COUNT query to learn a number already in hand would be waste.
maybe('an unclipped page reports its own length and does not run a count query', async () => {
  queries.length = 0;
  respond = (sql) => {
    if (sql.includes('FROM scope_targets')) return { rows: [{ id: 'target-1', type: 'URL' }] };
    if (sql.includes('GROUP BY')) return { rows: [{ scan_type: 'katana', count: '2' }] };
    return { rows: [{ url: 'http://t/a' }, { url: 'http://t/b' }] };
  };
  const out = await recon.queryEndpoints({ target_id: 'target-1', max_results: 50 });

  assert.equal(out.truncated, false);
  assert.equal(out.total, 2);
  assert.equal(out.returned, 2);
  // sources_present is a COUNT too, so the check has to exclude it or it can never pass.
  assert.ok(!queries.some((q) => q.sql.includes('COUNT(*) AS count') && !q.sql.includes('GROUP BY')),
    'a page that was not clipped already knows its total');
});
