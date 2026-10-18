// The goal layer is OFF for this unit suite: a live createServer() would otherwise wake teach()'s
// goal-fetch against an API that is not running under the unit tests. GATE_MODE is read once at
// index.js load, so this must be set before any require that reaches index.js below.
process.env.GOAL_GATE = 'off';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const roles = require('../src/roles');
const schema = require('../src/roles/schema');
const steps = require('../src/guidance/steps');
const guidance = require('../src/guidance');

// index.js imports zod (and src/tools/roles.js), which the repo does not vendor into the test tree in
// every environment. Same skip idiom as workflows.test.js: a red suite that only means "you have not
// run npm install" trains people to ignore red suites. The createServer() enumeration tests ride this.
let index = null;
try {
  index = require('../src/index');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = index ? test : test.skip;

// A role that validates, used as the base every malformed fixture is derived from. Deriving rather
// than hand-writing each bad case is what makes the failures attributable: if the base stops
// validating, the base test fails, and every other test in this file is still testing one deviation.
// The primary step is steps.ANY so the base never claims a STEP_INDEX slot and assemble() fixtures do
// not collide on it by accident.
function goodRole(overrides = {}) {
  return {
    id: 'fixture-role',
    title: 'A fixture role used only by this test file',
    pillar: 'support',
    scope_target_types: ['*'],
    anchors: [{ step: steps.ANY }],
    mandate: 'Exists so the validator can be driven against a role nobody ships to an agent.',
    allowed_tools: [],
    encouraged_tools: [],
    off_limits_tools: [],
    entry_criteria: 'A precondition that is long enough to be a statement rather than a label.',
    exit_criteria: 'A postcondition that separates work that finished from work that never ran.',
    definition_of_done: {
      measured: 'Measured on 1 run of 0 vectors, which is a number and therefore passes.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:12.',
    },
    handoff: [],
    measured_on: 'Nothing real, written 2026-09-17 for this fixture and nowhere else.',
    ...overrides,
  };
}

// --- the schema refuses, rather than half-loading -----------------------------------------------

test('the base fixture validates, so every other fixture tests one deviation', () => {
  assert.deepStrictEqual(schema.validate(goodRole()), []);
});

test('validate never throws, whatever it is handed', () => {
  for (const junk of [null, undefined, 42, 'a string', [], () => {}]) {
    assert.doesNotThrow(() => schema.validate(junk));
    assert.ok(schema.validate(junk).length > 0, `${String(junk)} should produce a problem`);
  }
});

test('an id that is not a stable kebab id is refused', () => {
  for (const id of ['Bad Role', '2-role', 'has_underscore', 'a']) {
    const problems = schema.validate(goodRole({ id }));
    assert.ok(problems.length > 0, `${JSON.stringify(id)} should have been refused`);
  }
});

test('a role with no anchors is refused', () => {
  assert.ok(schema.validate(goodRole({ anchors: undefined })).length > 0);
  assert.ok(schema.validate(goodRole({ anchors: [] })).length > 0);
});

test('an anchor step outside the shared vocabulary is refused', () => {
  // The ONE validated field on an anchor. A step nobody defined is a role anchored nowhere, which is
  // the exact confusion steps.js exists to remove.
  const problems = schema.validate(goodRole({ anchors: [{ step: '4/8 Parameter Discovery but misspelled' }] }));
  assert.ok(problems.length > 0, 'an unknown anchor step must be refused');
});

test('a definition of done whose measurement carries no digit is refused', () => {
  // THE EVIDENCE RULE. A done signal with no number is an opinion, and a reader cannot tell a
  // finished role from an aspirational one. The text reads fine; it just certifies nothing.
  const problems = schema.validate(goodRole({
    definition_of_done: {
      measured: 'The role is done when the operator agrees that it is finished enough.',
      source: 'A fixture artifact nobody ships, fixture/notes.md:12.',
    },
  }));
  assert.ok(problems.length > 0, 'a numberless definition of done must be refused');
});

test('a definition of done measurement too short to be a statement is refused', () => {
  const problems = schema.validate(goodRole({
    definition_of_done: {
      measured: '1 done',
      source: 'A fixture artifact nobody ships, fixture/notes.md:12.',
    },
  }));
  assert.ok(problems.length > 0, 'a one-word measurement must be refused');
});

test('a scope target type outside the allowed set is refused', () => {
  const problems = schema.validate(goodRole({ scope_target_types: ['Company', 'Nope'] }));
  assert.ok(problems.length > 0, 'an unknown scope target type must be refused');
});

test('an empty scope target type list is refused', () => {
  assert.ok(schema.validate(goodRole({ scope_target_types: [] })).length > 0);
});

test('an unknown top level key is refused rather than dropped', () => {
  // The typo guard, like workflows. A role with a `persona:` field would load cleanly and serve a
  // role with a section silently missing, and a reader cannot see an absence. No persona/backstory
  // field exists in this schema; any unknown key is a refusal.
  const problems = schema.validate(goodRole({ persona: 'A backstory field that does not exist.' }));
  assert.ok(problems.length > 0, 'an unknown top level key must be refused');
});

// --- assemble is all or nothing -----------------------------------------------------------------

test('two roles with one id are refused rather than one silently winning', () => {
  // Both anchor steps.ANY so the ONLY collision is the id, not a shared primary step.
  const a = goodRole({ id: 'same-role', anchors: [{ step: steps.ANY }] });
  const b = goodRole({ id: 'same-role', title: 'Another fixture role sharing the same id here',
    anchors: [{ step: steps.ANY }] });
  assert.throws(() => roles.assemble([a, b]), (err) => {
    assert.match(err.message, /nothing was loaded/);
    return true;
  });
});

test('two roles claiming one non-ANY primary step are refused', () => {
  // This is the TOTAL one-role-per-step guarantee that makes hintForStep deterministic. If two roles
  // anchored 8/8 Threat Model, hintForStep could only ever return one of them, so the load refuses.
  const a = goodRole({ id: 'first-role', anchors: [{ step: steps.THREAT }] });
  const b = goodRole({ id: 'second-role', anchors: [{ step: steps.THREAT }] });
  assert.throws(() => roles.assemble([a, b]), (err) => {
    assert.match(err.message, /nothing was loaded/);
    return true;
  });
});

test('a handoff pointing at a role that does not exist refuses the whole load', () => {
  // A dead pointer is worse here than in most stores: a reader sent to a role that does not exist is
  // told nothing at the handoff boundary the role exists to guard.
  const def = goodRole({
    id: 'pointing-role',
    anchors: [{ step: steps.ANY }],
    handoff: [{ to: 'ghost-role', when: 'When the fixture needs somewhere to hand off to.',
      artifact: 'A fixture artifact nobody ships, named only here.' }],
  });
  assert.throws(() => roles.assemble([def]), (err) => {
    assert.match(err.message, /nothing was loaded/);
    return true;
  });
});

test('a role that hands off to itself is refused', () => {
  const def = goodRole({
    id: 'selfish-role',
    anchors: [{ step: steps.ANY }],
    handoff: [{ to: 'selfish-role', when: 'When the fixture points a handoff at its own id.',
      artifact: 'A fixture artifact nobody ships, named only here.' }],
  });
  assert.throws(() => roles.assemble([def]), (err) => {
    assert.match(err.message, /nothing was loaded/);
    return true;
  });
});

test('a well formed pair assembles', () => {
  const all = roles.assemble([
    goodRole({ id: 'one-role', anchors: [{ step: steps.ANY }] }),
    goodRole({ id: 'two-role', anchors: [{ step: steps.ANY }] }),
  ]);
  assert.deepStrictEqual(Object.keys(all).sort(), ['one-role', 'two-role']);
});

// --- the shipped catalogue ----------------------------------------------------------------------

test('every shipped role validates', () => {
  // The registry throws at require time on a problem, so reaching this line is most of the assertion.
  // This re-runs it per role so a failure names the one that broke.
  for (const [id, def] of Object.entries(roles.ALL)) {
    assert.deepStrictEqual(schema.validate(def), [], `${id} does not validate`);
  }
});

test('the catalogue holds a real number of roles, derived not hardcoded', () => {
  assert.ok(Object.keys(roles.ALL).length >= 15,
    `the catalogue holds ${Object.keys(roles.ALL).length}, expected at least 15`);
});

test('every role id is unique and kebab case', () => {
  const ids = Object.keys(roles.ALL);
  assert.strictEqual(new Set(ids).size, ids.length, 'two roles share an id');
  for (const id of ids) {
    assert.ok(schema.NAME_PATTERN.test(id), `${id} is not a kebab id`);
    assert.strictEqual(roles.ALL[id].id, id, `${id} disagrees with its own id field`);
  }
});

test('every anchor step across the catalogue is in the shared vocabulary', () => {
  for (const [id, def] of Object.entries(roles.ALL)) {
    for (const [i, anchor] of def.anchors.entries()) {
      assert.ok(steps.ALLOWED_STEPS.has(anchor.step),
        `${id}.anchors[${i}] carries "${anchor.step}", which is not in src/guidance/steps.js`);
    }
  }
});

test('every handoff target resolves to a real role id', () => {
  for (const [id, def] of Object.entries(roles.ALL)) {
    for (const [i, h] of (def.handoff || []).entries()) {
      assert.ok(roles.ALL[h.to], `${id}.handoff[${i}] points at "${h.to}", which is not a role`);
    }
  }
});

test('every definition of done carries a measurement with a digit', () => {
  for (const [id, def] of Object.entries(roles.ALL)) {
    const measured = def.definition_of_done.measured;
    assert.ok(schema.MEASUREMENT_PATTERN.test(measured),
      `${id} definition_of_done.measured states no number`);
    assert.ok(measured.length >= schema.MIN_MEASUREMENT_CHARS,
      `${id} definition_of_done.measured is too short to be a statement`);
  }
});

// --- STEP_INDEX is total and collision free -----------------------------------------------------

test('STEP_INDEX maps each indexed step to exactly one role, and excludes ANY and CONFIG', () => {
  // Rebuilt from the catalogue the same way assemble() builds it, then compared whole: a deepStrictEqual
  // proves totality (every non-ANY, non-CONFIG primary is indexed) AND that nothing was added that no
  // role claims. collisions stays empty because assemble() would have thrown before we got here.
  const expected = {};
  const collisions = [];
  for (const [id, def] of Object.entries(roles.ALL)) {
    const primary = def.anchors[0].step;
    if (primary === steps.ANY || primary === steps.CONFIG) continue;
    if (expected[primary]) collisions.push(primary);
    expected[primary] = id;
  }
  assert.deepStrictEqual(collisions, [], `two roles share a primary step: ${collisions.join(', ')}`);
  assert.deepStrictEqual(roles.STEP_INDEX, expected,
    'STEP_INDEX is not the exact one-role-per-step map derived from the catalogue');
  assert.ok(!(steps.ANY in roles.STEP_INDEX), 'steps.ANY must never be a STEP_INDEX key');
  assert.ok(!(steps.CONFIG in roles.STEP_INDEX), 'steps.CONFIG must never be a STEP_INDEX key');
});

// --- hintForStep is deterministic and never fires on the wrong phase -----------------------------

test('hintForStep no-ops on ANY, CONFIG, and any unmapped step', () => {
  assert.strictEqual(roles.hintForStep(steps.ANY), null);
  assert.strictEqual(roles.hintForStep(steps.CONFIG), null);
  assert.strictEqual(roles.hintForStep('a step no role was ever anchored to'), null);
  assert.strictEqual(roles.hintForStep(undefined), null);
  assert.strictEqual(roles.hintForStep(''), null);
});

test('hintForStep returns one derived line for an indexed phase step', () => {
  const indexed = Object.keys(roles.STEP_INDEX);
  assert.ok(indexed.length > 0, 'the catalogue should index at least one phase step');
  for (const step of indexed) {
    const hint = roles.hintForStep(step);
    assert.strictEqual(typeof hint, 'string', `${step} produced no hint`);
    assert.ok(hint.length > 0, `${step} produced an empty hint`);
    assert.ok(!hint.includes('\n'), `${step} hint is more than one line`);
    assert.ok(hint.includes(roles.STEP_INDEX[step]), `${step} hint does not name its role`);
  }
});

// --- house style --------------------------------------------------------------------------------

test('no em dashes or en dashes anywhere in the roles store', () => {
  const dir = path.join(__dirname, '..', 'src', 'roles');
  for (const file of fs.readdirSync(dir)) {
    const body = fs.readFileSync(path.join(dir, file), 'utf8');
    assert.ok(!body.includes('—'), `${file} contains an em dash`);
    assert.ok(!body.includes('–'), `${file} contains an en dash`);
  }
});

// --- the advisory tool boundaries name real tools -----------------------------------------------

maybe('every tool a role names is a live registered tool or deliberately exempt', () => {
  // The real list, out of a real server, so a role cannot name a tool that was renamed or removed.
  // EXEMPT tools are registered too, but they are unioned in explicitly so the check reads as the
  // contract states it: a live registered tool OR an EXEMPT one.
  const server = index.createServer();
  const allow = new Set([...Object.keys(server._registeredTools), ...Object.keys(guidance.EXEMPT)]);
  const bad = [];
  for (const [id, def] of Object.entries(roles.ALL)) {
    for (const field of ['allowed_tools', 'encouraged_tools', 'off_limits_tools']) {
      for (const name of def[field] || []) {
        if (!allow.has(name)) bad.push(`${id}.${field} names "${name}"`);
      }
    }
  }
  assert.deepStrictEqual(bad, [],
    `these role tool boundaries name tools that are neither registered nor exempt: ${bad.join(', ')}`);
});
