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
// line does not contain. Under it the mean line was 218 characters and the worst was 401, on
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
