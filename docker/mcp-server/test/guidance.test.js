const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const guidance = require('../src/guidance');
const session = require('../src/guidance/session');
const steps = require('../src/guidance/steps');
const { createServer, teach } = require('../src/index');

// The guidance layer's job is to teach without ever being able to break a tool, so most of what is
// asserted here is about what it must NOT do: not corrupt a response shape, not attach an empty
// object, not overwrite a tool that already answers for itself, not survive its own bugs by taking
// the tool down with it.
//
// The last test is the one that keeps the registry honest over time. It enumerates the REAL
// registration list out of a live createServer() rather than a hardcoded copy, so a tool added next
// year fails this file until someone writes its entry or explains why it does not need one.

function envelope(value) {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

function decode(env) {
  return JSON.parse(env.content[0].text);
}

// A stand-in for a real handler, with the same shape every handler in index.js has.
function handlerReturning(value) {
  return async () => envelope(value);
}

test.beforeEach(() => session.reset());

// --- lookup -----------------------------------------------------------------------------------

test('lookup merges a per-action override over the tool entry', () => {
  // manage_sqli/eligibility overrides tool and next and inherits everything else. Picked because it
  // is a real entry: a synthetic fixture would prove the merge works on a fixture.
  const base = guidance.lookup('manage_sqli');
  const scoped = guidance.lookup('manage_sqli', 'eligibility');

  assert.ok(base, 'manage_sqli should have a tool-level entry');
  assert.ok(scoped, 'manage_sqli/eligibility should resolve');

  assert.notStrictEqual(scoped.tool, base.tool, 'the override should replace the tool sentence');
  assert.notStrictEqual(scoped.next, base.next, 'the override should replace next');
  assert.strictEqual(scoped.step, base.step, 'step is inherited, an action cannot move a tool');
  assert.strictEqual(scoped.vuln, base.vuln, 'a field the override does not restate is inherited');
});

// --- lies is a list ----------------------------------------------------------------------------
//
// `lies` is the one field that accumulates rather than being replaced, because a lie is a fact about
// the TOOL and stays true when a caller picks one action of it. These tests pin three things: the
// old single-string shape still works, an action that has learned its own lie is handed the
// tool-level ones as well instead of silently replacing them, and the ACTION'S OWN lie is the one
// that leads, because that is the only one the compact reminder can still deliver.
//
// Every test in this block was written to fail against the pre-list code. Three earlier ones did
// not: they passed unchanged against it and therefore pinned nothing, which is the reason the
// dedupe, budget and registry-lint tests below look the way they do. `String(anArray)` comma-joins
// and `firstSentence` stops at the first full stop, so the old compactLine returned the same lead
// by accident for any list whose first entry ends in a sentence.

test('a lies field written as a plain string still resolves, as a list of one', () => {
  // The shape 103 entries were authored in. asLies is the single place that rule lives, so it is
  // checked directly as well as through a real entry.
  assert.deepStrictEqual(guidance.asLies('one lie'), ['one lie']);
  assert.deepStrictEqual(guidance.asLies(['one lie']), ['one lie']);

  const entry = guidance.lookup('find_high_value_targets');
  assert.ok(Array.isArray(entry.lies), 'every attached lies field is a list, whatever it was authored as');
  assert.strictEqual(entry.lies.length, 1);
  assert.ok(entry.lies[0].includes('ROI is computed'));
});

test('a lies field written as a list returns all of them, in order', () => {
  const line = guidance.compactLine({
    step: 'S',
    tool: 'T.',
    lies: ['FIRST LIE, long enough to be a sentence.', 'SECOND LIE, also long enough.'],
    next: 'x',
  });
  // Only the first leads the reminder. The rest went out in full on the first call.
  assert.ok(line.includes('FIRST LIE'), `the first lie should lead: ${line}`);
  assert.ok(!line.includes('SECOND LIE'), `only one lie belongs in the compact line: ${line}`);
});

test('an action override accumulates lies rather than replacing the tool level ones', () => {
  // A real pair: manage_sqli/run defines its own lies and the tool entry defines its own. Before
  // this change the tool-level lesson (how the SQLi section as a whole misleads) was dropped on
  // exactly the call that runs the scanners, which is when it matters most.
  const base = guidance.lookup('manage_sqli');
  const scoped = guidance.lookup('manage_sqli', 'run');

  assert.ok(base.lies.length > 0, 'manage_sqli should carry tool-level lies');
  assert.ok(scoped.lies.length > base.lies.length,
    'the action adds to the tool-level lies instead of replacing them');
  for (const lie of base.lies) {
    assert.ok(scoped.lies.includes(lie), 'a tool-level lie survives an action override');
  }
  assert.deepStrictEqual(scoped.lies.slice(scoped.lies.length - base.lies.length), base.lies,
    'the tool-level lies follow the action ones, in their authored order');
  assert.ok(!base.lies.includes(scoped.lies[0]),
    'the ACTION lie leads: the tool-level one went out in full on the session first call, the ' +
    'action one has been delivered zero times, so the reminder repeats the action one');

  // And the contrast that makes the rule a decision rather than an accident: every other field the
  // override restates is still replaced outright. manage_sqli/run restates next and nothing else.
  assert.notStrictEqual(scoped.next, base.next, 'next is replaced, not accumulated');
  assert.strictEqual(scoped.tool, base.tool, 'a field the override does not restate is inherited');
});

test('the action lie, not the tool lie, leads the compact line of every action that has one', () => {
  // The delivery guard, registry-wide. The brief is tracked per TOOL (guidance/session.js), so the
  // full entry goes out once per tool per session and every later call gets compactLine(). The
  // first version of the list change ordered tool-level lies first, so the reminder always repeated
  // the tool lie: MEASURED, 156 action overrides define lies and the action lie led 0 of the 343
  // compact lines, which for an eight-action tool means seven lessons delivered on no call at all.
  const missed = [];
  let checked = 0;
  for (const [name, entry] of Object.entries(guidance.ALL)) {
    for (const [action, override] of Object.entries(entry.actions || {})) {
      const own = guidance.asLies(override.lies);
      if (own.length === 0) continue;
      checked++;
      const merged = guidance.lookup(name, action);
      if (merged.lies[0] !== own[0]) missed.push(`${name}:${action}`);
    }
  }
  assert.deepStrictEqual(missed, [], `these actions cannot deliver their own lie: ${missed.join(', ')}`);
  // Not vacuous: if a refactor stopped overrides carrying lies at all the loop above would pass on
  // an empty set, which is the failure this assertion exists to catch.
  assert.ok(checked > 100, `expected the registry to still hold action-level lies, found ${checked}`);
});

test('a lie repeated by an action override is not attached twice', () => {
  const shared = 'A zero here can mean nothing was eligible.';
  const entry = {
    step: 'S',
    tool: 'T.',
    lies: [shared, 'Only the tool level knows this one.'],
    next: 'x',
    actions: { run: { lies: [shared, 'Only the action knows this one.'] } },
  };
  // lookup() reads the registry, so the dedupe is exercised through the same code path by
  // temporarily registering the fixture rather than by reimplementing the merge here.
  guidance.ALL.__lies_fixture__ = entry;
  try {
    const merged = guidance.lookup('__lies_fixture__', 'run');
    // Exact list, not a contains check: the dedupe and the most-specific-first order are one
    // decision and asserting only the count would pass on either ordering.
    assert.deepStrictEqual(merged.lies, [
      shared,
      'Only the action knows this one.',
      'Only the tool level knows this one.',
    ], 'the repeated lie appears once, at the ACTION position, which is first');
  } finally {
    delete guidance.ALL.__lies_fixture__;
  }
});

test('the compact line takes one lie whole and never the comma join of the list', () => {
  // This is what the earlier "five lies still fit the budget" test failed to pin. `String(array)`
  // comma-joins, and the old compactLine passed the raw field to firstSentence, so with a first lie
  // that ENDS IN A FULL STOP the old code happened to return the same lead and the test could not
  // tell the two implementations apart. A first lie shorter than MIN_SENTENCE can: firstSentence
  // skips a terminator that early, runs on into the comma and returns "Short one., Then the next
  // lie entirely." The lead must be the first lie and nothing else, whatever its length.
  const joined = guidance.compactLine({
    step: '6/8 Vector Scanning',
    tool: 'Runs the scanners.',
    lies: ['A zero is not a clean.', 'THE SECOND LIE, which must not be dragged in behind a comma.'],
    next: 'get_tool_output',
  });
  assert.ok(joined.includes('A zero is not a clean.'), `the first lie leads: ${joined}`);
  assert.ok(!joined.includes('THE SECOND LIE'), `one lie, not a comma join: ${joined}`);
  assert.ok(!joined.includes('.,'), `the array was stringified rather than indexed: ${joined}`);
});

test('the compact line still fits the budget when an entry carries five lies', () => {
  const entry = {
    step: '6/8 Vector Scanning',
    tool: 'Runs the SQL injection scanners against the selected vectors.',
    lies: [
      'A scanner handed a flag it does not understand exits 0 having sent nothing and the runner '
        + 'records every vector clean, which is indistinguishable in the response from a real clean.',
      'The vector count counts rows the run skipped, so it is a selection size and not a coverage number.',
      'A per-vector timeout is recorded as a completed scan rather than as an incomplete one.',
      'The results view reads the last run only, so an older finding on the same vector is not shown.',
      'An empty findings list is also what a run that never started looks like from here.',
    ],
    next: 'get_tool_output, then manage_attack_vectors',
  };
  const line = guidance.compactLine(entry);
  // The registry has no five-lie entry yet, so this is the only place the ceiling is exercised
  // against one. The registry-wide budget test further down is what guards the shipped entries.
  assert.ok(line.length <= guidance.COMPACT_MAX,
    `five lies must not widen the reminder: ${line.length} characters`);
  assert.ok(line.startsWith('6/8 Vector Scanning.'), `the step survives: ${line}`);
  assert.ok(line.includes('Next: '), `the next pointer survives: ${line}`);
  assert.ok(!line.includes('vector count'), 'only the first lie is allowed into the reminder');
});

test('every lies field in the registry survives asLies without losing an entry', () => {
  // A DATA LINT, not a regression test, and it is kept as one deliberately. It passes against any
  // version of the merge because what it checks is the registry, not the code: a null, a number or
  // an empty string authored into a lies list is dropped SILENTLY by asLies, so an author would see
  // a lesson quietly not ship. The cheapest place to catch that is here.
  //
  // It calls asLies rather than restating the rule, which the first version of it did. Restating it
  // meant the lint agreed with a broken asLies by construction and could not notice a change in it;
  // comparing the input count with the survivor count notices both a bad entry and a bad drop.
  const bad = [];
  const check = (where, value) => {
    if (value === undefined) return;
    const raw = Array.isArray(value) ? value : [value];
    if (raw.length === 0) bad.push(`${where} has an empty lies list`);
    const kept = guidance.asLies(value);
    if (kept.length !== raw.length) {
      bad.push(`${where}: asLies kept ${kept.length} of ${raw.length} lies, so one is being dropped`);
    }
  };
  for (const [name, entry] of Object.entries(guidance.ALL)) {
    check(name, entry.lies);
    for (const [action, override] of Object.entries(entry.actions || {})) {
      check(`${name}:${action}`, override.lies);
    }
  }
  assert.deepStrictEqual(bad, [], bad.join(', '));
});

test('lookup falls back to the tool entry for an action with no override', () => {
  const base = guidance.lookup('manage_sqli');
  const unknownAction = guidance.lookup('manage_sqli', 'no_such_action_exists');
  assert.deepStrictEqual(unknownAction, base);
});

test('lookup returns null for an unknown tool', () => {
  assert.strictEqual(guidance.lookup('not_a_real_tool'), null);
  assert.strictEqual(guidance.lookup('not_a_real_tool', 'list'), null);
  assert.strictEqual(guidance.lookup(undefined), null);
  assert.strictEqual(guidance.lookup(''), null);
});

test('lookup never returns registry bookkeeping', () => {
  const entry = guidance.lookup('manage_sqli');
  assert.strictEqual(entry.actions, undefined, 'actions is the lookup table, not payload');
  assert.strictEqual(entry.derived, undefined, 'derived is a fact about the registry, not the target');
  for (const key of Object.keys(entry)) {
    assert.ok(guidance.ATTACHED_FIELDS.includes(key), `unexpected attached field: ${key}`);
  }
});

// --- the compact line -------------------------------------------------------------------------

test('the compact line is step, one sentence, then next', () => {
  const line = guidance.compactLine({
    step: '6/8 Vector Scanning',
    tool: 'Runs the SQL injection scanners.',
    lies: 'Check scanned-vs-available. A zero here can mean nothing was eligible.',
    next: 'manage_sqli',
  });
  assert.strictEqual(line, '6/8 Vector Scanning. Check scanned-vs-available. Next: manage_sqli.');
});

test('the compact line prefers lies and falls back to tool', () => {
  const withLies = guidance.compactLine({ step: 'S', tool: 'TOOL SENTENCE.', lies: 'LIES SENTENCE.', next: 'x' });
  assert.ok(withLies.includes('LIES SENTENCE.'));
  assert.ok(!withLies.includes('TOOL SENTENCE.'));

  // Several real entries have no lies field at all, so the fallback is load bearing rather than
  // defensive.
  const withoutLies = guidance.compactLine({ step: 'S', tool: 'TOOL SENTENCE.', next: 'x' });
  assert.ok(withoutLies.includes('TOOL SENTENCE.'));
});

test('sentence splitting survives decimals and abbreviations', () => {
  assert.strictEqual(
    guidance.firstSentence('x8 4.3.1 reports a parameter it never sent. Then it exits 0.'),
    'x8 4.3.1 reports a parameter it never sent.');
  assert.strictEqual(
    guidance.firstSentence('Header vectors, e.g. User-Agent, are only tested when marked. Not otherwise.'),
    'Header vectors, e.g. User-Agent, are only tested when marked.');
});

test('every real entry derives a non-empty compact line', () => {
  for (const name of Object.keys(guidance.ALL)) {
    const line = guidance.compactLine(guidance.lookup(name));
    assert.ok(line.length > 0, `${name} derives an empty compact line`);
    assert.ok(line.includes('Next: '), `${name} compact line has no next pointer`);
  }
});

// The budget, asserted against every tool AND every per-action override, because an override
// replaces the lead and the next pointer and is the version a scan loop actually receives.
//
// This replaces an assertion that read `line.length < entry.tool.length + 400`, which named the
// right property and could not fail: it compared the line against a bound derived from a field the
// line does not contain. Under it the mean line was 217 characters and the worst was 394, on
// run_endpoint_scan.
test('no compact line exceeds the budget, for any tool or action', () => {
  const over = [];
  for (const [name, entry] of Object.entries(guidance.ALL)) {
    const cases = [[name, undefined], ...Object.keys(entry.actions || {}).map((a) => [name, a])];
    for (const [tool, action] of cases) {
      const line = guidance.compactLine(guidance.lookup(tool, action));
      if (line.length > guidance.COMPACT_MAX) {
        over.push(`${tool}${action ? ':' + action : ''} is ${line.length}`);
      }
      assert.ok(line.includes('Next: '), `${tool}${action ? ':' + action : ''} lost its next pointer`);
    }
  }
  assert.deepStrictEqual(over, [],
    `these compact lines are over ${guidance.COMPACT_MAX} characters: ${over.join(', ')}`);
});

test('a lead too long for the budget is cut at a boundary and says it was cut', () => {
  // The clause cut: everything after the colon is the worked example, so the claim survives whole.
  assert.strictEqual(
    guidance.fitLead('Both reasons mean the verdict is wrong in the same direction: the saved '
      + 'credentials are not honoured, so the run fingerprints the login wall.', 61),
    'Both reasons mean the verdict is wrong in the same direction.');

  // The hard cut: a word boundary, an ellipsis, and no dangling conjunction promising a clause that
  // is no longer there.
  const hard = guidance.fitLead('A table that cannot be read is skipped in silence, so a count of '
    + 'zero is not a measurement.', 70);
  assert.ok(hard.length <= 70, `hard cut overran its budget: ${hard.length}`);
  assert.ok(hard.endsWith(' ...'), `a cut lead must announce itself: ${hard}`);
  assert.ok(!/\b(so|and|because|the|a)\s\.\.\.$/.test(hard), `cut ends on a dangling word: ${hard}`);

  // Below the floor there is no honest fragment, so the lead is dropped rather than mangled. step
  // and next still make it out, which is why compactLine spends their budget first.
  assert.strictEqual(guidance.fitLead('Anything at all here.', 10), '');
});

// --- progressive delivery ---------------------------------------------------------------------

test('first call attaches the object, later calls attach the compact string', async () => {
  const wrapped = teach('manage_sqli', handlerReturning({ ok: true }));
  const extra = { sessionId: 'session-a' };

  const first = decode(await wrapped({}, extra));
  assert.strictEqual(typeof first.guidance, 'object', 'the first call teaches in full');
  assert.ok(first.guidance.step && first.guidance.tool && first.guidance.next);
  assert.strictEqual(first.ok, true, 'the tool result survives intact');

  const second = decode(await wrapped({}, extra));
  assert.strictEqual(typeof second.guidance, 'string', 'later calls remind cheaply');
  assert.strictEqual(second.guidance, guidance.compactLine(guidance.lookup('manage_sqli')));
  assert.strictEqual(second.ok, true);
});

test('a different session is taught from scratch', async () => {
  const wrapped = teach('manage_sqli', handlerReturning({ ok: true }));
  await wrapped({}, { sessionId: 'session-a' });
  const other = decode(await wrapped({}, { sessionId: 'session-b' }));
  assert.strictEqual(typeof other.guidance, 'object',
    'a session id we have never seen must re-teach, never go quiet');
});

test('an expired session is taught again', () => {
  const past = Date.now() - session.IDLE_MS - 1000;
  assert.strictEqual(session.firstBrief('s', 'manage_sqli', past), true);
  assert.strictEqual(session.firstBrief('s', 'manage_sqli', past), false);
  assert.strictEqual(session.firstBrief('s', 'manage_sqli', Date.now()), true,
    'two hours idle and the briefed set is gone');
});

test('no session id falls back to one process-wide set', async () => {
  const wrapped = teach('manage_sqli', handlerReturning({ ok: true }));
  const first = decode(await wrapped({}, undefined));
  const second = decode(await wrapped({}, {}));
  assert.strictEqual(typeof first.guidance, 'object');
  assert.strictEqual(typeof second.guidance, 'string',
    'both anonymous calls share the fallback key, which is the documented compromise');
});

// --- wrapper safety ----------------------------------------------------------------------------

test('a non-object result is wrapped rather than corrupted', async () => {
  for (const value of ['just a string', [1, 2, 3], null, 42]) {
    const wrapped = teach('manage_sqli', handlerReturning(value));
    session.reset();
    const out = decode(await wrapped({}, { sessionId: 's' }));
    assert.deepStrictEqual(out.result, value, `a ${typeof value} result must survive verbatim`);
    assert.ok(out.guidance, 'and still carry guidance');
  }
});

test('a result that already has a guidance key is left alone', async () => {
  const original = { guidance: 'the tool speaks for itself', rows: 3 };
  const wrapped = teach('manage_sqli', handlerReturning(original));
  const out = decode(await wrapped({}, { sessionId: 's' }));
  assert.deepStrictEqual(out, original);
  assert.strictEqual(session.hasBriefed('s', 'manage_sqli'), false,
    'a brief consumed on a call that attached nothing is a lesson the agent never received');
});

test('a tool with no entry gets nothing attached, not an empty object', async () => {
  const wrapped = teach('browse_knowledge_base', handlerReturning({ files: [] }));
  const out = decode(await wrapped({}, { sessionId: 's' }));
  assert.deepStrictEqual(out, { files: [] });
  assert.ok(!('guidance' in out));
});

test('an error envelope is not touched', async () => {
  const errored = async () => ({ isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'boom' }) }] });
  const wrapped = teach('manage_sqli', errored);
  const out = await wrapped({}, { sessionId: 's' });
  assert.deepStrictEqual(decode(out), { error: 'boom' });
});

test('a non-JSON text envelope is not reshaped', async () => {
  const prose = async () => ({ content: [{ type: 'text', text: 'plain prose, not JSON' }] });
  const wrapped = teach('manage_sqli', prose);
  const out = await wrapped({}, { sessionId: 's' });
  assert.strictEqual(out.content[0].text, 'plain prose, not JSON');
});

test('a throw inside the guidance layer leaves the result untouched', async () => {
  const realLookup = guidance.lookup;
  guidance.lookup = () => { throw new Error('deliberate guidance bug'); };
  const originalError = console.error;
  console.error = () => {};
  try {
    const wrapped = teach('manage_sqli', handlerReturning({ ok: true, rows: 7 }));
    const out = await wrapped({}, { sessionId: 's' });
    assert.deepStrictEqual(decode(out), { ok: true, rows: 7 },
      'a teaching bug must never be able to break a tool');
  } finally {
    guidance.lookup = realLookup;
    console.error = originalError;
  }
});

test('a throw inside the tool still propagates', async () => {
  const broken = async () => { throw new Error('the tool failed'); };
  const wrapped = teach('manage_sqli', broken);
  await assert.rejects(() => wrapped({}, { sessionId: 's' }), /the tool failed/);
});

test('params without an action, or params missing entirely, still resolve', async () => {
  const wrapped = teach('manage_sqli', handlerReturning({ ok: true }));
  const out = decode(await wrapped(undefined, undefined));
  assert.ok(out.guidance);
});

// --- registry integrity -------------------------------------------------------------------------

test('no tool is defined in two domain files', () => {
  // assemble() throws at load time on a collision, so reaching this line at all is the assertion.
  // The count check catches the opposite mistake: a domain file that silently exports nothing.
  const domains = new Set(Object.values(guidance.DOMAIN_OF));
  assert.strictEqual(domains.size, 4, 'all four domain files should contribute entries');
  assert.ok(Object.keys(guidance.ALL).length > 140);
});

test('every entry carries step, tool and next', () => {
  for (const [name, entry] of Object.entries(guidance.ALL)) {
    for (const field of ['step', 'tool', 'next']) {
      assert.ok(typeof entry[field] === 'string' && entry[field].trim().length > 0,
        `${name} is missing a ${field}`);
    }
    for (const [action, override] of Object.entries(entry.actions || {})) {
      for (const field of Object.keys(override)) {
        assert.ok(guidance.ATTACHED_FIELDS.includes(field),
          `${name}/${action} overrides ${field}, which is not an attachable field`);
      }
    }
  }
});

// One step, one name. recon.js and data.js each declared their own S_CRAWL, S_ARCHIVE and
// S_CONSOLIDATE and the two files disagreed on all three, while scanning.js and workflow.js wrote a
// third spelling of the pre-step inline. An agent told that manage_param_enum is at "4/8 Hidden
// parameter enumeration" and query_parameters at "4/8 Parameter Discovery" has been told they are
// different phases, which is the confusion this layer exists to remove.
test('every step label comes from the shared vocabulary', () => {
  const seen = new Set();
  const wrong = [];
  for (const [name, entry] of Object.entries(guidance.ALL)) {
    const cases = [[name, entry.step], ...Object.entries(entry.actions || {})
      .filter(([, o]) => o.step)
      .map(([a, o]) => [`${name}:${a}`, o.step])];
    for (const [key, step] of cases) {
      seen.add(step);
      if (!steps.ALLOWED_STEPS.has(step)) wrong.push(`${key} => "${step}"`);
    }
  }
  assert.deepStrictEqual(wrong, [],
    `these steps are not in src/guidance/steps.js: ${wrong.join(', ')}`);

  // And the other direction: two labels differing only in case or wording are the drift itself, so
  // the vocabulary is checked for near duplicates rather than only for membership.
  const normalised = new Map();
  for (const step of seen) {
    const key = step.toLowerCase().replace(/[^a-z0-9/]/g, '');
    if (normalised.has(key) && normalised.get(key) !== step) {
      assert.fail(`two spellings of one step: "${normalised.get(key)}" and "${step}"`);
    }
    normalised.set(key, step);
  }
});

test('no em dashes anywhere in the guidance layer', () => {
  const dir = path.join(__dirname, '..', 'src', 'guidance');
  for (const file of fs.readdirSync(dir)) {
    const text = fs.readFileSync(path.join(dir, file), 'utf8');
    assert.ok(!text.includes('—'), `${file} contains an em dash`);
    assert.ok(!text.includes('–'), `${file} contains an en dash`);
  }
});

// --- the one that keeps this honest ---------------------------------------------------------------

test('every registered tool has guidance or is deliberately exempt', () => {
  // The real list, out of a real server, so this cannot drift from what is actually registered.
  const server = createServer();
  const registered = Object.keys(server._registeredTools);
  assert.ok(registered.length > 140, `expected the full tool set, got ${registered.length}`);

  const missing = registered.filter((name) => !guidance.ALL[name] && !guidance.EXEMPT[name]);
  assert.deepStrictEqual(missing, [],
    `these tools have no guidance entry and are not listed as exempt in src/guidance/index.js: ${missing.join(', ')}`);

  // And the other direction: an entry for a tool that no longer exists is dead text that will never
  // be shown to anyone, and it reads as coverage.
  const orphaned = Object.keys(guidance.ALL).filter((name) => !registered.includes(name));
  assert.deepStrictEqual(orphaned, [],
    `these guidance entries name tools that are not registered: ${orphaned.join(', ')}`);

  // An exemption for a tool that is gone is stale too, and it would hide a genuine gap if the name
  // were ever reused.
  const staleExemptions = Object.keys(guidance.EXEMPT).filter((name) => !registered.includes(name));
  assert.deepStrictEqual(staleExemptions, [],
    `these exemptions name tools that are not registered: ${staleExemptions.join(', ')}`);
});

test('every tool named in a next pointer exists', () => {
  const server = createServer();
  const registered = new Set(Object.keys(server._registeredTools));
  const unknown = new Set();
  for (const entry of Object.values(guidance.ALL)) {
    const pointers = [entry.next, ...Object.values(entry.actions || {}).map((a) => a.next)];
    for (const pointer of pointers) {
      if (!pointer) continue;
      for (const token of pointer.split(',').map((t) => t.trim())) {
        // next is prose-tolerant on purpose ("manage_sqli, or run_endpoint_scan"), so only bare
        // snake_case words are treated as tool names.
        if (/^[a-z][a-z0-9_]+$/.test(token) && !registered.has(token)) unknown.add(token);
      }
    }
  }
  assert.deepStrictEqual([...unknown], [],
    `next pointers name tools that do not exist: ${[...unknown].join(', ')}`);
});

// --- `rule`: a standing constraint, not a caveat ----------------------------------------------

test('a rule is inherited by every action of the tool that defines it', () => {
  // Not a fixture. manage_xss carries the weaponisability bar and none of its four actions restate
  // it, so the bar has to arrive through inheritance or it reaches nobody at the moment they are
  // reading findings and deciding what is reportable.
  const base = guidance.lookup('manage_xss');
  assert.ok(base.rule && base.rule.length > 0, 'manage_xss lost its rule');
  for (const action of Object.keys(guidance.ALL.manage_xss.actions)) {
    const scoped = guidance.lookup('manage_xss', action);
    assert.strictEqual(scoped.rule, base.rule, `manage_xss/${action} did not inherit the rule`);
  }
});

test('a rule never reaches the compact line, however long it is', () => {
  // This is what makes `rule` the right home for a long standing constraint. compactLine spends its
  // 200 characters on step, one lie and next; a rule is delivered in full on the session's first
  // call for the tool and costs the repeated reminder nothing. If that ever changes, a 973 character
  // rule would blow the ceiling on every call of a scan loop.
  const entry = { step: 'S', tool: 'TOOL SENTENCE.', lies: 'LIES SENTENCE.', next: 'x' };
  const withoutRule = guidance.compactLine(entry);
  const withRule = guidance.compactLine({ ...entry, rule: 'R'.repeat(5000) });
  assert.strictEqual(withRule, withoutRule);
});

test('every rule in the registry is a non-empty string', () => {
  const bad = [];
  for (const [name, entry] of Object.entries(guidance.ALL)) {
    const cases = [[name, entry], ...Object.entries(entry.actions || {})
      .map(([a, o]) => [`${name}/${a}`, o])];
    for (const [label, obj] of cases) {
      if (!('rule' in obj)) continue;
      if (typeof obj.rule !== 'string' || obj.rule.trim().length === 0) bad.push(label);
    }
  }
  assert.deepStrictEqual(bad, [], `these rules are not usable text: ${bad.join(', ')}`);
});

test('the XSS rule still ranks every insertion point the corpus can produce', () => {
  // A content assertion on purpose. The ranking is the whole substance of this rule and it is one
  // sentence away from being edited into a general warning that ranks nothing, which would read
  // fine and teach nothing.
  //
  // fragment is one of the six the consolidator emits. It used to be named here as a class that did
  // not exist, which stopped being true when the Go side gained the insertion point in the same
  // tree; the comment is corrected rather than deleted because the reason it is in the list changed
  // and the list did not. A fragment vector is emitted only where a hash was observed, and domdig
  // is the only tool that reaches one.
  const rule = guidance.lookup('manage_xss').rule;
  for (const point of ['query', 'path', 'fragment', 'cookie', 'header']) {
    assert.ok(rule.includes(point), `the XSS rule no longer names the ${point} insertion point`);
  }
  // The fragment is top tier and undiscoverable, so the rule has to say who can reach one. Without
  // this an edit could put fragment back in the ranking while dropping the reason its count is
  // usually zero, and an agent would read a zero as "this target has no DOM XSS".
  assert.ok(rule.includes('domdig'), 'the XSS rule no longer names the one tool that reaches a fragment');
  // The three chains are what make a cookie or header finding reportable at all. Naming the class
  // without naming a route to it is the advice that gets ignored.
  for (const chain of ['Set-Cookie', 'sibling subdomain', 'cache']) {
    assert.ok(rule.includes(chain), `the XSS rule no longer names the ${chain} chain`);
  }
});

test('the attack vector lies do not deny that the fragment insertion point exists', () => {
  // THE GUIDANCE LAYER AND THE GO LAYER SHIPPED IN THE SAME TREE AND CONTRADICTED EACH OTHER.
  //
  // lies[1] read "THERE IS NO FRAGMENT INSERTION POINT ... the consolidator simply never emits one
  // ... domdig fuzzes the URL hash and can never be handed one". Every clause of that was made false
  // by the Go change beside it: insertion_point now has six values, the consolidator emits a
  // fragment vector from an observed hash, and domdig declares fragment in its reach. On the first
  // manage_attack_vectors call of any session the framework would have taught an agent that a
  // feature it had just built did not exist.
  //
  // The honest lesson is the one that survives: the zero at that point is not like the other five.
  const lies = guidance.lookup('manage_attack_vectors').lies;
  const fragmentLie = lies.find((l) => l.toLowerCase().includes('fragment'));
  assert.ok(fragmentLie, 'the fragment is the one point whose zero needs explaining');
  for (const denial of [
    'THERE IS NO FRAGMENT INSERTION POINT',
    'never emits one',
    'can never be handed one',
    'structurally absent',
  ]) {
    assert.ok(!fragmentLie.includes(denial),
      `the guidance still denies the fragment point the Go layer emits: "${denial}"`);
  }
  assert.ok(fragmentLie.includes('domdig'),
    'the lesson has to name the one tool that can reach a fragment');
  assert.ok(/observed/i.test(fragmentLie),
    'the lesson has to say a fragment vector is emitted only where a hash was observed');

  // lies[0] is what compactLine repeats on every call, so it must not have moved.
  assert.ok(lies[0].startsWith('This list is what every scanner below will run against'),
    'the repeated lie changed, which changes every compact line on this tool');
});

// --- the census the comments claim -------------------------------------------------------------
//
// index.js justifies leading the compact line with the ACTION lie by a measured census, twice, in
// prose: so many action overrides define lies, and the action lie led 0 of so many compact lines
// under the old tool-first ordering. Prose goes stale the next time the registry grows, and a
// stale measurement reads exactly like a current one. So the numbers are read back out of the
// comments and compared against the live registry. When this fails, recount and edit the comment.
// Do not delete the numbers: the ordering rule has no other justification on record.
test('the measured census in the comments still matches the registry', () => {
  let overridesWithLies = 0;
  let lines = 0;
  let actionLedUnderOldOrdering = 0;

  for (const [name, entry] of Object.entries(guidance.ALL)) {
    const toolLies = guidance.asLies(entry.lies);
    lines += 1; // the line for a call with no action
    for (const override of Object.values(entry.actions || {})) {
      lines += 1;
      const ownLies = guidance.asLies(override && override.lies);
      if (ownLies.length === 0) continue;
      overridesWithLies += 1;
      // Tool lies first, action lies after, deduped: the ordering this file replaced.
      if ([...toolLies, ...ownLies][0] === ownLies[0]) actionLedUnderOldOrdering += 1;
    }
  }

  assert.strictEqual(actionLedUnderOldOrdering, 0,
    'a tool entry has lost its own lies, so the old ordering would no longer bury the action lie');

  // Both files state the census: index.js twice, and the delivery test above once.
  // Comment continuations are unwrapped first, so a claim that happens to break across two lines
  // is still one sentence to the regexes below.
  const source = ['src/guidance/index.js', 'test/guidance.test.js']
    .map((f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8')).join('\n')
    .replace(/\n\s*\/\/ ?/g, ' ');
  const counted = [...source.matchAll(/(\d+) action overrides define/g)].map((m) => Number(m[1]));
  const totals = [...source.matchAll(/0 of the (\d+) compact lines/g)].map((m) => Number(m[1]));
  assert.ok(counted.length >= 3 && totals.length >= 3,
    'the census claim has been reworded, so this test can no longer read it; recount by hand');
  for (const claimed of counted) {
    assert.strictEqual(claimed, overridesWithLies,
      `a comment claims ${claimed} action overrides define lies; the registry has ${overridesWithLies}`);
  }
  for (const claimed of totals) {
    assert.strictEqual(claimed, lines,
      `a comment claims ${claimed} compact lines; the registry produces ${lines}`);
  }
});
