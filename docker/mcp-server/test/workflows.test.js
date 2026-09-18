const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const workflows = require('../src/workflows');
const schema = require('../src/workflows/schema');

// The tool module imports zod, which the repo does not vendor locally (the image installs it, and
// .dockerignore keeps test/ out of the image). Same skip idiom as knowledgebase.test.js: a red suite
// that means "you have not run npm install" trains people to ignore red suites.
let book = null;
try {
  book = require('../src/tools/workflowbook');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = book ? test : test.skip;

// A definition that passes, used as the base every malformed fixture is derived from. Deriving
// rather than hand-writing each bad case is what makes the failures attributable: if the base stops
// validating, the base test fails, and every other test in this file is still testing one deviation.
function goodDefinition(overrides = {}) {
  return {
    name: 'fixture-workflow',
    title: 'A fixture workflow used only by this test file',
    purpose: 'Exists so the validator can be driven against a definition nobody ships to an agent.',
    reach_for_it_when: 'Never. It is a test fixture and it is not in the registry.',
    measured_on: 'Nothing real. 0 targets, 0 vectors, 0 runs, written 2026-09-17.',
    preconditions: [{
      check: 'A precondition that is long enough to be a statement.',
      why: 'Because the validator refuses anything shorter than a sentence.',
    }],
    steps: [{
      do: 'A step that is long enough to be a statement rather than a label.',
      verify: 'A postcondition that separates tested and clean from never ran.',
    }],
    lessons: [{
      lesson: 'A lesson that is long enough to be a statement.',
      measured: 'Measured on 1 run of 0 vectors, which is a number and therefore passes.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:12.',
    }],
    gotchas: [{
      gotcha: 'A gotcha that is long enough to be a statement.',
      symptom: 'What the wrong answer looks like, which is never an error.',
      measured: 'Measured across 2 runs: 1 crashed and 1 was recorded clean.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:34.',
      fix: 'What to do instead, stated as an action rather than as a warning.',
    }],
    ...overrides,
  };
}

// --- the schema refuses, rather than half-loading -----------------------------------------------

test('the base fixture validates, so every other fixture tests one deviation', () => {
  assert.deepStrictEqual(schema.validate(goodDefinition()), []);
});

test('a gotcha whose measurement carries no number is refused', () => {
  // THE RULE THE WHOLE STORE RESTS ON. A knowledge store fills up with plausible advice nobody
  // measured unless something refuses it, and at that point a reader cannot tell which half to
  // trust. The text is long enough and reads perfectly well; it just has no evidence in it.
  const def = goodDefinition({
    gotchas: [{
      gotcha: 'dalfox can be configured in a way that stops it verifying anything.',
      symptom: 'A scan that looks completely normal and finds nothing at all.',
      measured: 'This has been seen to happen on several occasions in the past.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:34.',
      fix: 'Do not set that option, and check the eligible count after saving.',
    }],
  });
  const problems = schema.validate(def);
  assert.strictEqual(problems.length, 1, `expected exactly one problem, got ${problems.join('; ')}`);
  assert.match(problems[0], /gotchas\[0\]\.measured/);
  assert.match(problems[0], /claim and not a measurement/);
});

test('a lesson is held to the same evidence rule as a gotcha', () => {
  const problems = schema.validate(goodDefinition({
    lessons: [{
      lesson: 'Verify a fix on a few vectors before committing to a full run.',
      measured: 'It saved a considerable amount of time on the most recent run.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:12.',
    }],
  }));
  assert.strictEqual(problems.length, 1);
  assert.match(problems[0], /lessons\[0\]\.measured/);
});

test('a gotcha missing its symptom or its fix is refused, and each is reported once', () => {
  const problems = schema.validate(goodDefinition({
    gotchas: [{
      gotcha: 'A gotcha that is long enough to be a statement.',
      measured: 'Measured across 2 runs: 1 crashed and 1 was recorded clean.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:34.',
    }],
  }));
  assert.strictEqual(problems.length, 2, problems.join('; '));
  assert.ok(problems.some((p) => /gotchas\[0\]\.symptom/.test(p)));
  assert.ok(problems.some((p) => /gotchas\[0\]\.fix/.test(p)));
});

test('a missing measurement is reported as missing, not as evidence-free', () => {
  // The evidence check runs after the required-field check so one absence produces one problem.
  // Two messages about the same field sends an author looking for two things.
  const problems = schema.validate(goodDefinition({
    gotchas: [{
      gotcha: 'A gotcha that is long enough to be a statement.',
      symptom: 'What the wrong answer looks like, which is never an error.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:34.',
      fix: 'What to do instead, stated as an action rather than as a warning.',
    }],
  }));
  assert.strictEqual(problems.length, 1, problems.join('; '));
  assert.match(problems[0], /gotchas\[0\]\.measured is missing/);
});

// --- a digit is not evidence: the source address rule ------------------------------------------

test('a measurement with nowhere to check it is refused, however numeric it reads', () => {
  // THE GAP THAT LET THE FABRICATED NUMBERS LOAD. The evidence rule above is satisfied by any
  // digit, and both numbers the SQLi entry shipped wrong had digits. These are those two claims
  // verbatim, as they shipped: no source, so the store now refuses them at load.
  const asShipped = [
    'ghauri spends 133 requests against the oracle and about 1690 on a real cookie vector, 13 '
    + 'times more. That mistake was made during this very run.',
    'About 200 burst refilling near 3.33/s. Proof: 40 requests at /api/v1/assets left the counters '
    + 'on accounts, country-infos AND assets itself unchanged.',
  ];
  for (const measured of asShipped) {
    const problems = schema.validate(goodDefinition({
      lessons: [{ lesson: 'A lesson that is long enough to be a statement.', measured }],
    }));
    assert.strictEqual(problems.length, 1, problems.join('; '));
    assert.match(problems[0], /lessons\[0\]\.source is missing/);
  }
});

test('a source that gestures at the run rather than naming a place is refused', () => {
  // The obvious way to satisfy a source field without satisfying the point of one. Each of these
  // is a real sentence about where the number came from and none of them can be opened.
  for (const source of [
    'Measured during the authenticated arm of this campaign, on 2026-09-18.',
    'Recorded in the campaign log at the time, as the run was happening.',
    'Observed against the reference target by the operator running the sweep.',
  ]) {
    const problems = schema.validate(goodDefinition({
      lessons: [{
        lesson: 'A lesson that is long enough to be a statement.',
        measured: 'Measured on 1 run of 0 vectors, which is a number and therefore passes.',
        source,
      }],
    }));
    assert.strictEqual(problems.length, 1, `${source} :: ${problems.join('; ')}`);
    assert.match(problems[0], /lessons\[0\]\.source names no address a reader can open/);
  }
});

test('the two true claims that were doubted pass, with the addresses they actually have', () => {
  // The other half of the discrimination. Both of these were challenged as fabricated and both are
  // real; what they lacked was an address, and each has one. Driven as fixtures rather than read
  // out of the registry so this still tests the rule if somebody rewrites the entry.
  const sourced = [
    {
      lesson: 'sqlmap exits 0 on a 401 baseline and the framework files that as clean.',
      measured: 'Cost of omitting ignoreCode 401: 91 of 249 vectors, 37 percent, each recorded '
        + 'clean in 1.9s having tested nothing.',
      source: 'sqli/WORKFLOW-sqli-campaign.md:30 and memory/sqli-tooling.md:165.',
    },
    {
      lesson: 'ghauri --threads does not throttle anything, so raising it buys no speed.',
      measured: 'delay 1 at threads 1, 2, 3 and 4 measured 144s, 135s, 141s and 149s for '
        + 'identical output.',
      source: 'memory/sqli-tooling.md:69, measured 2026-09-18, not in the sqli scratchpad.',
    },
  ];
  for (const lesson of sourced) {
    assert.deepStrictEqual(schema.validate(goodDefinition({ lessons: [lesson] })), [],
      `${lesson.source} should have been accepted`);
  }
});

test('every address form the book actually uses is recognised, and prose alone is not', () => {
  // The closed vocabulary, asserted directly so a regex edit cannot quietly narrow it.
  for (const good of [
    'sqli/campaign.log:33', 'server/utils/sqliCompose.go:84', 'memory/sqli-tooling.md:69',
    'xss/LESSONS-xss-campaign.md:113', 'b7fe528f-6e7a-41e1-81fc-eb437cd58c92',
  ]) {
    assert.ok(schema.SOURCE_ADDRESS.test(good), `${good} should be an address`);
  }
  for (const bad of [
    'the campaign log', 'sqliCompose.go', 'roughly 3.33/s sustained', '2026-09-18', '91 of 249',
  ]) {
    assert.ok(!schema.SOURCE_ADDRESS.test(bad), `${bad} should not be an address`);
  }
});

test('every repo address in a shipped source resolves to a real file and a real line', () => {
  // The half of the promise that CAN be mechanically resolved. A campaign scratchpad path and a
  // Postgres scan id cannot be checked here: neither the scratchpad nor the database exists at
  // load, which is the honest limit on the rule and the reason this test covers repo paths only.
  const repoRoot = path.join(__dirname, '..', '..', '..');
  const addresses = /\b((?:server|client|docker|src)\/[A-Za-z0-9_./-]+\.[A-Za-z0-9]{1,8}):(\d+)/g;
  let checked = 0;
  for (const def of Object.values(workflows.ALL)) {
    for (const section of ['lessons', 'gotchas']) {
      for (const [i, item] of def[section].entries()) {
        for (const [, file, line] of item.source.matchAll(addresses)) {
          const full = path.join(repoRoot, file);
          assert.ok(fs.existsSync(full), `${def.name}.${section}[${i}] cites ${file}, which does not exist`);
          const lines = fs.readFileSync(full, 'utf8').split('\n').length;
          assert.ok(Number(line) <= lines,
            `${def.name}.${section}[${i}] cites ${file}:${line}, which has ${lines} lines`);
          checked += 1;
        }
      }
    }
  }
  assert.ok(checked >= 4, `only ${checked} repo addresses were checked, so this asserts nothing`);
});

// --- the address rule reaching the fields that were actually wrong ----------------------------
//
// The rule above covers `measured` on a lesson or a gotcha, and the two numbers this store got
// wrong next were in neither: the per-vector durations were in the top-level `cost` field and the
// token-lifetime range was in a step's `verify`. Both are quoted here as they shipped.

test('a cost that states a number and names no place is refused', () => {
  const asShipped = '9 settled authenticated body vectors measured 95, 95, 141, 206, 233, 310, '
    + '310, 340 and 417 seconds and 1 cookie vector at 65, with 4 more hitting the 900s cap.';
  const problems = schema.validate(goodDefinition({ cost: asShipped }));
  assert.strictEqual(problems.length, 1, problems.join('; '));
  assert.match(problems[0], /\.cost states a number and names no address/);
  // The same sentence with the ledger address on it loads.
  assert.deepStrictEqual(
    schema.validate(goodDefinition({ cost: `${asShipped} sqli/sqli-ledger.json:44.` })), []);
});

test('a cost with no number in it is left alone, because it is not a measurement', () => {
  assert.deepStrictEqual(schema.validate(goodDefinition({
    cost: 'Minutes per vector rather than seconds, on every tool in this section.',
  })), []);
});

test("a step's postcondition that states a number and names no place is refused", () => {
  const asShipped = 'Each vector settles with an outcome rather than an expiry. Measured '
    + 'token_left_s at the starts here ranged 482 to 835 seconds against settled vector durations '
    + 'of 65 to 417s.';
  const problems = schema.validate(goodDefinition({
    steps: [{ do: 'Run the authenticated arm one scan per vector, fresh credential each time.', verify: asShipped }],
  }));
  assert.strictEqual(problems.length, 1, problems.join('; '));
  assert.match(problems[0], /steps\[0\]\.verify states a number and names no address/);
});

test('a step satisfies the rule with a source OR with an address already in the postcondition', () => {
  const asShipped = 'Token lifetime at the start ranged 482 to 835 seconds against durations of '
    + '65 to 417s.';
  const doing = 'Run the authenticated arm one scan per vector, fresh credential each time.';
  // A sibling source field, which is the new optional field on a step.
  assert.deepStrictEqual(schema.validate(goodDefinition({
    steps: [{ do: doing, verify: asShipped, source: 'sqli/sqli-ledger.json:230 and :105.' }],
  })), []);
  // Or the address inline, which is what the unauthenticated-arm step already does with a scan id.
  assert.deepStrictEqual(schema.validate(goodDefinition({
    steps: [{ do: doing, verify: `${asShipped} Postgres scan b7fe528f-6e7a-41e1-81fc-eb437cd58c92.` }],
  })), []);
});

test('a postcondition with no number in it needs no address, so the rule is not noise', () => {
  assert.deepStrictEqual(schema.validate(goodDefinition({
    steps: [{
      do: 'Read the composed command back before trusting any verdict from the run.',
      verify: 'The saved delay survives the round trip as the type the tool expects.',
    }],
  })), []);
});

test('a number in a do or a looks_like is not held to the address rule', () => {
  // Deliberately narrower than "every field". `do` describes the work and `looks_like` describes
  // the wrong answer; neither certifies a result, and holding them to it would make the rule noise.
  assert.deepStrictEqual(schema.validate(goodDefinition({
    steps: [{
      do: 'Run all 218 vectors, one scan each, at delay 0.35 and threads 1.',
      verify: 'Every vector settles with an outcome rather than with an expiry.',
      looks_like: 'A 53 vector run that finishes in 40 seconds and records all 53 clean.',
    }],
  })), []);
});

test('every shipped cost and postcondition that states a number carries an address', () => {
  // The registry half. The two that were wrong are in the book, so this is the assertion that the
  // book itself satisfies the rule rather than the rule merely existing.
  let checked = 0;
  for (const def of Object.values(workflows.ALL)) {
    if (def.cost && schema.MEASUREMENT_PATTERN.test(def.cost)) {
      assert.ok(schema.SOURCE_ADDRESS.test(def.cost), `${def.name}.cost states a number unaddressed`);
      checked += 1;
    }
    for (const [i, step] of def.steps.entries()) {
      if (!schema.MEASUREMENT_PATTERN.test(step.verify)) continue;
      const addressed = Object.values(step)
        .some((v) => typeof v === 'string' && schema.SOURCE_ADDRESS.test(v));
      assert.ok(addressed, `${def.name}.steps[${i}].verify states a number unaddressed`);
      checked += 1;
    }
  }
  assert.ok(checked >= 10, `only ${checked} numeric costs and postconditions were checked`);
});

test('a step with no verify is refused, because it cannot be told from a step that never ran', () => {
  const problems = schema.validate(goodDefinition({
    steps: [{ do: 'Run the scanner across the whole corpus and wait for it.' }],
  }));
  assert.strictEqual(problems.length, 1);
  assert.match(problems[0], /steps\[0\]\.verify/);
});

test('a typo in a field name is refused rather than dropped', () => {
  // The reason this matters: a definition with `gotchya:` would load cleanly and serve a workflow
  // with a section silently missing, and a reader cannot see an absence.
  const problems = schema.validate(goodDefinition({
    gotchas: [{
      gotcha: 'A gotcha that is long enough to be a statement.',
      symptom: 'What the wrong answer looks like, which is never an error.',
      measured: 'Measured across 2 runs: 1 crashed and 1 was recorded clean.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:34.',
      fix: 'What to do instead, stated as an action rather than as a warning.',
      lessons_learned: 'A field that does not exist and would be thrown away.',
    }],
  }));
  assert.strictEqual(problems.length, 1);
  assert.match(problems[0], /unknown field "lessons_learned"/);
});

test('a top level typo is refused too', () => {
  const problems = schema.validate(goodDefinition({ gotchyas: [] }));
  assert.ok(problems.some((p) => /unknown field "gotchyas"/.test(p)));
});

test('a section that is empty is refused, since an empty gotcha list is a claim', () => {
  const problems = schema.validate(goodDefinition({ gotchas: [] }));
  assert.strictEqual(problems.length, 1);
  assert.match(problems[0], /gotchas is missing or empty/);
});

test('a name that is not a stable id is refused', () => {
  for (const name of ['XSS Campaign', '2-campaign', 'xss_campaign', 'a']) {
    const problems = schema.validate(goodDefinition({ name }));
    assert.ok(problems.some((p) => /\.name must be kebab case/.test(p)),
      `${JSON.stringify(name)} should have been refused`);
  }
});

test('validate never throws, whatever it is handed', () => {
  for (const junk of [null, undefined, 42, 'a string', [], () => {}]) {
    assert.doesNotThrow(() => schema.validate(junk));
    assert.ok(schema.validate(junk).length > 0, `${String(junk)} should produce a problem`);
  }
});

// --- assemble is all or nothing -----------------------------------------------------------------

test('one malformed workflow refuses the whole load, so nothing is half-loaded', () => {
  // The alternative, skipping the bad one and serving the rest, is the exact failure the seed
  // workflow is about: a partial load that reports success. A caller asking for the dropped
  // workflow would be told "unknown workflow" and would read it as "nobody has written that one".
  const bad = goodDefinition({ name: 'broken-workflow', gotchas: [] });
  const good = goodDefinition({ name: 'fine-workflow' });
  assert.throws(
    () => workflows.assemble([good, bad]),
    (err) => {
      assert.match(err.message, /nothing was loaded/);
      assert.match(err.message, /broken-workflow\.gotchas is missing or empty/);
      return true;
    });
});

test('assemble reports every problem at once rather than the first', () => {
  const bad = goodDefinition({ name: 'broken-workflow', gotchas: [], steps: [] });
  try {
    workflows.assemble([bad]);
    assert.fail('assemble should have thrown');
  } catch (err) {
    assert.match(err.message, /2 problem\(s\)/);
  }
});

test('two workflows with one name are refused rather than one silently winning', () => {
  const a = goodDefinition({ name: 'same-name' });
  const b = goodDefinition({ name: 'same-name', title: 'A different workflow with the same name' });
  assert.throws(() => workflows.assemble([a, b]), /defined twice/);
});

test('a well formed pair assembles', () => {
  const all = workflows.assemble([goodDefinition({ name: 'one-workflow' }),
    goodDefinition({ name: 'two-workflow' })]);
  assert.deepStrictEqual(Object.keys(all).sort(), ['one-workflow', 'two-workflow']);
});

// --- the shipped registry ------------------------------------------------------------------------

test('every shipped workflow validates', () => {
  // The registry throws at require time on a problem, so reaching this line is most of the
  // assertion. This re-runs it per workflow so a failure names the one that broke.
  for (const [name, def] of Object.entries(workflows.ALL)) {
    assert.deepStrictEqual(schema.validate(def), [], `${name} does not validate`);
  }
  assert.ok(Object.keys(workflows.ALL).length >= 1, 'the book should not be empty');
});

test('the seed XSS campaign carries the lessons that cost the most to learn', () => {
  // A content assertion, deliberately. These four are the ones whose absence would make the entry
  // worth less than the hour it took to write: each cost either a restart or a whole arm of the run.
  const text = JSON.stringify(workflows.ALL['xss-campaign']).toLowerCase();
  for (const needle of [
    'useragent',          // gotcha 1, 53 vectors and 48,859 requests for nothing
    '170 of 215',         // the arm split, the single most expensive error of the run
    'content type is not text/html',  // domdig exiting 0 having scanned nothing
    'setextrahttpheaders',            // the CORS logout that revokes the session
    'sparsely',           // the stale selection that outlives its phase
    'oracle',             // the self-test stored as a real finding
  ]) {
    assert.ok(text.includes(needle), `the seed workflow no longer mentions ${needle}`);
  }
});

test('no em dashes anywhere in the workflow store', () => {
  const dir = path.join(__dirname, '..', 'src', 'workflows');
  for (const file of fs.readdirSync(dir)) {
    const body = fs.readFileSync(path.join(dir, file), 'utf8');
    assert.ok(!body.includes('—'), `${file} contains an em dash`);
    assert.ok(!body.includes('–'), `${file} contains an en dash`);
  }
});

// --- list --------------------------------------------------------------------------------------

test('list returns counts rather than contents', () => {
  const rows = workflows.list();
  assert.ok(rows.length >= 1);
  const seed = rows.find((r) => r.name === 'xss-campaign');
  assert.ok(seed, 'the seed workflow should be listed');
  for (const field of ['steps', 'preconditions', 'lessons', 'gotchas', 'chars']) {
    assert.strictEqual(typeof seed[field], 'number', `${field} should be a count`);
    assert.ok(seed[field] > 0);
  }
  // The counts are what an operator chooses on, so they have to be the real ones.
  assert.strictEqual(seed.gotchas, workflows.ALL['xss-campaign'].gotchas.length);
  assert.ok(!Array.isArray(seed.steps), 'list must not inline the step bodies');
});

test('a query filters and a query that matches nothing returns nothing', () => {
  assert.strictEqual(workflows.list('xss').length, 1);
  assert.strictEqual(workflows.list('XSS').length, 1, 'the filter is case insensitive');
  assert.strictEqual(workflows.list('deserialisation').length, 0);
});

// --- get ---------------------------------------------------------------------------------------

test('get returns the whole workflow by default', () => {
  const body = workflows.get('xss-campaign');
  assert.ok(!body.error, `expected a body, got ${body.error}`);
  for (const section of ['preconditions', 'steps', 'lessons', 'gotchas']) {
    assert.ok(Array.isArray(body[section]) && body[section].length > 0, `${section} is missing`);
  }
  assert.ok(body.measured_on, 'provenance travels with every read');
});

test('a section read still carries the overview', () => {
  // A page of advice with no addressee is not usable: a caller who asked for gotchas alone still
  // needs to know which target and which day produced them.
  const body = workflows.get('xss-campaign', 'gotchas');
  assert.ok(Array.isArray(body.gotchas));
  assert.strictEqual(body.steps, undefined, 'a section read should not carry the other sections');
  assert.ok(body.measured_on && body.reach_for_it_when);
});

test('an unknown name is answered with the names that exist', () => {
  const body = workflows.get('xss-campain');
  assert.strictEqual(body.error, 'unknown workflow');
  assert.ok(body.known_workflows.includes('xss-campaign'));
});

test('a workflow too large for one read is refused with its section sizes, not truncated', () => {
  // Truncation is the one thing this store must never do. A cut list of gotchas reads exactly like
  // a complete one, which is the failure mode every entry in the seed workflow is about. Driven
  // through a real oversized definition rather than by lowering the ceiling, so what is asserted is
  // the behaviour a caller would actually meet.
  const padding = 'x'.repeat(2000);
  const huge = goodDefinition({
    name: 'huge-workflow',
    gotchas: Array.from({ length: 30 }, (_, i) => ({
      gotcha: `Gotcha number ${i} that is long enough to be a statement. ${padding}`,
      symptom: 'What the wrong answer looks like, which is never an error.',
      measured: 'Measured across 2 runs: 1 crashed and 1 was recorded clean.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:34.',
      fix: 'What to do instead, stated as an action rather than as a warning.',
    })),
  });
  assert.deepStrictEqual(schema.validate(huge), [], 'the oversized workflow is valid, just large');

  const raw = JSON.stringify(huge).length;
  assert.ok(raw > workflows.GET_CHAR_CEILING,
    `the fixture must exceed the ceiling to test it, ${raw} vs ${workflows.GET_CHAR_CEILING}`);

  // Injected into the live registry, the way guidance.test.js injects a lies fixture, because get()
  // reads the registry and the refusal is what a caller would actually meet.
  workflows.ALL['huge-workflow'] = huge;
  try {
    const refused = workflows.get('huge-workflow');
    assert.strictEqual(refused.error, 'this workflow is larger than one read');
    assert.strictEqual(refused.gotchas, undefined, 'nothing is returned cut down');
    assert.strictEqual(refused.section_chars.gotchas, JSON.stringify(huge.gotchas).length);
    assert.ok(refused.measured_on, 'the refusal still says what the workflow is');

    // One section of it still comes back whole: the ceiling refuses the read, not the workflow.
    const section = workflows.get('huge-workflow', 'lessons');
    assert.strictEqual(section.lessons.length, huge.lessons.length);
  } finally {
    delete workflows.ALL['huge-workflow'];
  }

  // And the shipped one must NOT, or the default read of the only workflow in the book is a refusal.
  const seed = JSON.stringify(workflows.ALL['xss-campaign']).length;
  assert.ok(seed <= workflows.GET_CHAR_CEILING,
    `the seed workflow no longer fits one read: ${seed} vs ${workflows.GET_CHAR_CEILING}`);
});

// --- the tool surface ----------------------------------------------------------------------------

maybe('list_workflows answers with the index and how to read one', async () => {
  const out = await book.listWorkflows({});
  assert.strictEqual(out.count, out.workflows.length);
  assert.strictEqual(out.total, Object.keys(workflows.ALL).length);
  assert.match(out.how_to_read_one, /get_workflow name=/);
  assert.match(out.how_to_read_one, /gotchas before the steps/);
});

maybe('a query that matches nothing says so rather than answering with an empty list', async () => {
  const out = await book.listWorkflows({ query: 'deserialisation' });
  assert.strictEqual(out.count, 0);
  assert.match(out.note, /No workflow matches/);
});

maybe('get_workflow returns a section and names which one it returned', async () => {
  const out = await book.getWorkflow({ name: 'xss-campaign', section: 'gotchas' });
  assert.strictEqual(out.section, 'gotchas');
  assert.ok(out.gotchas.length > 0);
  assert.match(out.provenance, /measured_on/);
});

maybe('get_workflow passes an unknown name through as the registry refusal', async () => {
  const out = await book.getWorkflow({ name: 'nope' });
  assert.strictEqual(out.error, 'unknown workflow');
  assert.strictEqual(out.provenance, undefined, 'a refusal is not dressed up as a workflow');
});

maybe('the section enum offers every section plus all, and nothing else', () => {
  const values = [...book.getWorkflowSchema.shape.section._def.innerType._def.values];
  assert.deepStrictEqual(values.sort(), ['all', ...workflows.SECTIONS].sort());
});

maybe('the tool descriptions say the gotchas are the product', () => {
  // An agent picks a tool by reading its description. One that fails to say this gets the store used
  // as a list of steps, which is the one thing it is not.
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');
  const registered = source.match(/server\.tool\('(list_workflows|get_workflow)', '([^']+)'/g) || [];
  assert.strictEqual(registered.length, 2, 'both workflow book tools should be registered');
  assert.ok(/READ THE GOTCHAS FIRST/.test(source), 'get_workflow should say to read the gotchas first');
});

// --- related names have to resolve ---------------------------------------------------------------

test('a related name that is not in the registry refuses the whole load', () => {
  // The schema can only see one definition at a time, so this is checked in assemble(). A dead
  // pointer is worse here than in most stores: get() answers an unknown name with the names that
  // DO exist, which reads as "nobody has written that one yet", so a reader sent there by a typo
  // is told the opposite of the truth.
  const def = goodDefinition({ name: 'pointing-workflow', related: ['xss-campain'] });
  assert.throws(() => workflows.assemble([def]), (err) => {
    assert.match(err.message, /pointing-workflow\.related names "xss-campain"/);
    assert.match(err.message, /nothing was loaded/);
    return true;
  });
});

test('a pair of workflows that point at each other loads', () => {
  const a = goodDefinition({ name: 'one-workflow', related: ['two-workflow'] });
  const b = goodDefinition({ name: 'two-workflow', related: ['one-workflow'] });
  assert.deepStrictEqual(Object.keys(workflows.assemble([a, b])).sort(),
    ['one-workflow', 'two-workflow']);
});

test('a forward reference is fine, since the check runs after everything is keyed', () => {
  const first = goodDefinition({ name: 'first-workflow', related: ['second-workflow'] });
  const second = goodDefinition({ name: 'second-workflow' });
  assert.doesNotThrow(() => workflows.assemble([first, second]));
});

test('a workflow related to itself is refused', () => {
  const def = goodDefinition({ name: 'selfish-workflow', related: ['selfish-workflow'] });
  assert.throws(() => workflows.assemble([def]), /selfish-workflow\.related points at itself/);
});

test('every related name in the shipped book resolves', () => {
  for (const def of Object.values(workflows.ALL)) {
    for (const name of def.related || []) {
      assert.ok(workflows.ALL[name], `${def.name} points at ${name}, which does not exist`);
    }
  }
  // Two entries that know about each other is the whole reason the check above exists.
  assert.ok((workflows.ALL['xss-campaign'].related || []).includes('sqli-campaign'));
  assert.ok((workflows.ALL['sqli-campaign'].related || []).includes('xss-campaign'));
});

// --- the age signal -------------------------------------------------------------------------

test('a workflow that cannot be dated is refused at load', () => {
  // Every read reports the age. An undateable entry would be the one entry silently exempt from
  // that, which is exactly the note this project already acted on after it went stale.
  const problems = schema.validate(goodDefinition({
    measured_on: 'A real target and a real corpus of 218 vectors, some time last spring.',
  }));
  assert.strictEqual(problems.length, 1, problems.join('; '));
  assert.match(problems[0], /measured_on carries no YYYY-MM-DD date/);
});

test('an updated line with no date in it is refused too', () => {
  const problems = schema.validate(goodDefinition({
    updated: 'Revised after the 2 reruns, at the end of the campaign.',
  }));
  assert.strictEqual(problems.length, 1, problems.join('; '));
  assert.match(problems[0], /updated carries no YYYY-MM-DD date/);
});

test('the age is read off the latest date the entry claims', () => {
  const def = goodDefinition({
    measured_on: 'A corpus of 218 vectors, measured 2026-01-10 on one target.',
    updated: 'Revised 2026-03-11 after 2 of the numbers moved.',
  });
  const at = new Date('2026-03-21T00:00:00Z');
  assert.deepStrictEqual(workflows.ageOf(def, at),
    { as_of: '2026-03-11', age_days: 10, stale: false });
});

test('a date in the future is clamped rather than reported as a negative age', () => {
  const def = goodDefinition({ measured_on: 'Measured 2026-12-01 across 218 vectors on 1 target.' });
  const age = workflows.ageOf(def, new Date('2026-09-18T00:00:00Z'));
  assert.strictEqual(age.age_days, 0, 'a clock disagreement reads as a bug in the store, not a note');
});

test('every list row carries the age without anyone asking for it', () => {
  const rows = workflows.list(undefined, new Date('2026-09-18T00:00:00Z'));
  assert.ok(rows.length >= 2);
  for (const row of rows) {
    assert.match(row.as_of, /^20\d\d-\d\d-\d\d$/, `${row.name} has no as_of`);
    assert.strictEqual(typeof row.age_days, 'number', `${row.name} has no age_days`);
    assert.strictEqual(row.staleness, undefined,
      `${row.name} is not stale yet and should not say so`);
  }
});

test('a get carries the age, and only a stale workflow carries the sentence', () => {
  // Rare enough to mean something: a warning attached to every entry is furniture. Driven at fixed
  // dates because a staleness rule tested only against the real clock passes for 90 days and then
  // starts failing on its own.
  const fresh = workflows.get('sqli-campaign', 'overview', new Date('2026-11-01T00:00:00Z'));
  assert.strictEqual(fresh.age_days, 44);
  assert.strictEqual(fresh.staleness, undefined);

  const dayBefore = new Date('2026-12-16T00:00:00Z'); // 89 days after 2026-09-18
  assert.strictEqual(workflows.get('sqli-campaign', 'overview', dayBefore).staleness, undefined);

  const onThreshold = new Date('2026-12-17T00:00:00Z');
  const stale = workflows.get('sqli-campaign', 'overview', onThreshold);
  assert.strictEqual(stale.age_days, workflows.STALE_AFTER_DAYS);
  assert.match(stale.staleness, /Re-measure the numbers in this workflow/);
  assert.match(stale.staleness, /90 days ago/);
});

// --- the second entry ----------------------------------------------------------------------------

test('the book holds more than one workflow, because one workflow is not a book', () => {
  assert.ok(Object.keys(workflows.ALL).length >= 2,
    `the book holds ${Object.keys(workflows.ALL).length}`);
});

test('the SQLi campaign carries the measurements that cost the most to learn', () => {
  // Same shape of assertion as the XSS one: each of these is a failure that cost either a restart
  // or a whole arm, and paraphrasing any of them away would make the entry worth less than the run.
  const text = JSON.stringify(workflows.ALL['sqli-campaign']).toLowerCase();
  for (const needle of [
    '91 of 249',             // sqlmap exits 0 on a 401 baseline and the framework files it clean
    'ignorecode 401',        // the fix for it
    'delay is a float',      // 0.5 makes ghauri exit 2 having sent nothing
    'header must be a list', // one -H with a newline puts no credential on the wire
    'token bucket',          // per endpoint, authenticated tier only
    '1690',                  // the real cookie vector cost, the number the pacing lesson rests on
    '871ms',                 // the replayed control that certifies a broken run
    '144s',                  // ghauri --threads does not throttle
    '/proc',                 // ps is not installed in these containers
    '29 of 29',              // the result, with the control attached
  ]) {
    assert.ok(text.includes(needle), `the SQLi workflow no longer mentions ${needle}`);
  }
});

test('the SQLi entry carries the corrected ledger numbers and not the two withdrawn claims', () => {
  // Each of these was wrong in the shipped entry and each was adjudicated against the ledger, the
  // campaign log or Postgres. Asserted as text so a rewrite cannot quietly put a mid-run number back.
  const text = JSON.stringify(workflows.ALL['sqli-campaign']);
  for (const needle of [
    '95, 95, 141, 206, 233, 310, 310, 340 and 417',   // 9 CLEAN body rows in the ledger, not 8
    '482 and 835',                                     // the 10 ledger rows that record a lifetime
    '9 clean, 3 timed out',                            // the first 13 by finished_at in the ledger
    'b7fe528f-6e7a-41e1-81fc-eb437cd58c92',            // the unauthenticated arm is in Postgres
    'OBSERVED rather than proven',                     // per-endpoint was never isolated
  ]) {
    assert.ok(text.includes(needle), `the SQLi workflow no longer carries ${needle}`);
  }
  for (const withdrawn of [
    '133 requests',            // the resume denominator, never a request count
    '40 requests at',          // an experiment that does not exist in any artifact
    '13 times more',           // the ratio built on the misread progress bar
  ]) {
    assert.ok(!text.includes(withdrawn), `the SQLi workflow still claims "${withdrawn}"`);
  }
});

test('the SQLi entry says the ledger is not a census, because two drivers shared it', () => {
  // THE CORRECTION THAT MATTERS MOST, because every per-vector count in the entry is read off an
  // artifact that lost rows. campaign.log holds 21 distinct vectors and the ledger 16, the union is
  // 22, and the ledger is not even last-write-wins by finished_at. An entry that quotes the ledger
  // without saying that is quoting the overwrites.
  const def = workflows.ALL['sqli-campaign'];
  const text = JSON.stringify(def);
  for (const needle of [
    'union of 22',           // the reconciliation a reader has to do before quoting a count
    '6 settled vectors',     // what the ledger never received
    '12:10:29',              // the CLEAN the ledger still holds as TIMED_OUT at 12:08:49
    'LEDGER ROWS',           // the cost field saying what it is quoting
  ]) {
    assert.ok(text.includes(needle), `the SQLi workflow no longer carries ${needle}`);
  }
  // And the reusable half is a gotcha rather than a footnote on this one run.
  const concurrent = def.gotchas.find((g) => /second driver/i.test(g.gotcha));
  assert.ok(concurrent, 'the concurrent-driver gotcha is gone');
  assert.match(concurrent.fix, /stopping gotcha/,
    'the concurrent-driver gotcha no longer points at the stopping procedure that prevents it');
  assert.ok(def.gotchas.some((g) => /killing the shell is not one of them/.test(g.gotcha)),
    'the stopping gotcha it cross-references is gone');
});

test('both shipped workflows fit one read', () => {
  for (const [name, def] of Object.entries(workflows.ALL)) {
    const chars = JSON.stringify(def).length;
    assert.ok(chars <= workflows.GET_CHAR_CEILING,
      `${name} no longer fits one read: ${chars} against ${workflows.GET_CHAR_CEILING}`);
  }
});
