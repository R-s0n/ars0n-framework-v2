const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// These run without node_modules. The tool module itself imports zod and is skipped where the
// dependency is absent, the way attackvectors.test.js and parity.test.js do, but the two things most
// worth checking here are the tool key list and the Go registry it mirrors, and neither needs zod.
const { DISCOVERY_TOOL_KEYS } = require('../src/utils/discoveryTools');

let tooloutput = null;
try {
  tooloutput = require('../src/tools/tooloutput');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = tooloutput ? test : test.skip;

const GO_SOURCE = path.join(__dirname, '..', '..', '..', 'server', 'utils', 'toolOutputAPI.go');

// Returns null when the Go source is not beside us, which happens when the suite is run from a copy
// of docker/mcp-server rather than from the repo. Skipping there rather than failing follows the
// same reasoning as the MODULE_NOT_FOUND skip above: a red suite that means "you ran it from the
// wrong directory" teaches people to ignore red suites.
function goRegistryKeys() {
  let source;
  try {
    source = fs.readFileSync(GO_SOURCE, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  const body = source.slice(source.indexOf('discoveryToolOutputSources = map['));
  const keys = [...body.matchAll(/"([a-z0-9_]+)":\s*\{Table:/g)].map((m) => m[1]);
  return keys.sort();
}

// The MCP enum and the Go map are two copies of one list. A key present here and missing there is a
// 404 an agent reads as "this target has never run that tool", which is exactly the wrong conclusion
// and exactly the class of confusion this whole surface was built to end. A key present there and
// missing here is a tool whose output simply cannot be requested.
test('the tool vocabulary matches the Go registry exactly', (t) => {
  const go = goRegistryKeys();
  if (go === null) {
    t.skip('server/utils/toolOutputAPI.go is not reachable from here');
    return;
  }
  assert.ok(go.length > 30, `parsed only ${go.length} keys out of the Go registry, check the regex`);
  assert.deepStrictEqual([...DISCOVERY_TOOL_KEYS].sort(), go);
});

// LinkFinder is the run that cost four attempts and could not be read. If it ever falls out of the
// list, the specific failure this was built for becomes undiagnosable again.
test('the tools that produced the measured failure are all readable', () => {
  for (const tool of ['linkfinder_url', 'katana_url', 'gospider_url', 'gau_url', 'waybackurls']) {
    assert.ok(DISCOVERY_TOOL_KEYS.includes(tool),
      `${tool} is not readable, and its status route selects neither stdout nor stderr`);
  }
});

// ip_port_scans stores no stdout, no stderr and no result, and puts its failure text in
// error_message. Serving it through a shape that promises those columns would report every run as
// having printed nothing, which is the lie the whole surface exists to stop.
test('a table that cannot answer the shape is not offered', () => {
  assert.ok(!DISCOVERY_TOOL_KEYS.includes('ip_port_scan'));
});

maybe('an action that needs a target or a scan says so instead of calling the API with undefined', async () => {
  const runs = await tooloutput.getToolOutput({ action: 'runs' });
  assert.match(runs.error || '', /target_id/);

  const run = await tooloutput.getToolOutput({ action: 'run' });
  assert.match(run.error || '', /scan_id/);
});

maybe('an unknown action is reported rather than silently doing nothing', async () => {
  const result = await tooloutput.getToolOutput({ action: 'run_' });
  assert.match(result.error || '', /unknown action/);
});

maybe('the three reads are all offered and nothing else is', () => {
  const actions = [...tooloutput.getToolOutputSchema.shape.action._def.values].sort();
  assert.deepStrictEqual(actions, ['run', 'runs', 'tools']);
});

// tool is optional on purpose. A scan id arrives from a workflow response or a log line without the
// table it came from, and having to guess the tool before the error can be read is the same wall
// this tool removes.
maybe('a run can be read without already knowing which tool produced it', () => {
  const tool = tooloutput.getToolOutputSchema.shape.tool;
  assert.ok(tool.isOptional(), 'tool must be optional, or "any" is unreachable');
});

// only_problems must not drop a failure because a second language did not learn its name.
//
// MEASURED 2026-08-21. PROBLEM_DIAGNOSES was an allowlist hand-copied from the Go side. Go gained
// "unreachable_or_usage" and the response came back saying needs_attention: 5 while returning 1 row:
// the four LinkFinder failures were filtered out by the very filter whose job is to show failures.
//
// So the rule is stated by exclusion. A diagnosis nobody here has heard of is a problem by default.
maybe('an unknown diagnosis is treated as a problem rather than filtered away', () => {
  const { isProblemDiagnosis } = tooloutput;
  assert.ok(isProblemDiagnosis('unreachable_or_usage'),
    'the diagnosis that exposed this bug is filtered out again');
  assert.ok(isProblemDiagnosis('some_future_diagnosis_go_adds_later'),
    'an unrecognised diagnosis must default to visible; defaulting to hidden is how a failure ' +
    'becomes invisible without anyone changing the filter');
  for (const d of ['usage_error', 'failed', 'no_output']) {
    assert.ok(isProblemDiagnosis(d), `${d} is no longer treated as a problem`);
  }
  for (const d of ['ok', 'running']) {
    assert.ok(!isProblemDiagnosis(d), `${d} is reported as a problem, which makes the filter noise`);
  }
  // An absent diagnosis is also not "fine".
  assert.ok(isProblemDiagnosis(undefined), 'a row with no diagnosis is silently treated as healthy');
});
