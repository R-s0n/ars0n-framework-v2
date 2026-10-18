// The goal layer is OFF for this unit suite: the skip-guarded teach() check below would otherwise
// wake teach()'s goal-fetch against an API that is not running under the unit tests. GATE_MODE is
// read once at index.js load, so this must be set before any require that reaches index.js.
process.env.GOAL_GATE = 'off';

const test = require('node:test');
const assert = require('node:assert');

const memory = require('../src/guidance/memory');
const session = require('../src/guidance/session');
const guidance = require('../src/guidance');

// index.js imports zod, which the repo does not vendor into the test tree in every environment. Same
// skip idiom as workflows.test.js: the one test that drives teach() rides this; everything else tests
// memory.js and session.js directly and never needs it.
let index = null;
try {
  index = require('../src/index');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = index ? test : test.skip;

function envelope(value) {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}
function decode(env) {
  return JSON.parse(env.content[0].text);
}
function handlerReturning(value) {
  return async () => envelope(value);
}

test.beforeEach(() => session.reset());

// --- the tier derivation ------------------------------------------------------------------------

test('a head field is tiered by the manifest, and an unknown field falls to the default', () => {
  assert.strictEqual(memory.tierOfHead('keep_hunting'), memory.TIERS.PERMANENT);
  assert.strictEqual(memory.tierOfHead('role_hint'), memory.TIERS.PERMANENT);
  assert.strictEqual(memory.tierOfHead('goal'), memory.TIERS.SCOPE_TARGET);
  assert.strictEqual(memory.tierOfHead('guidance'), memory.TIERS.STRATEGY);
  assert.strictEqual(memory.tierOfHead('anything-else'), memory.DEFAULT_TIER);
  assert.strictEqual(memory.DEFAULT_TIER, memory.TIERS.STRATEGY);
});

test('a tool is tiered by its guidance domain, read live, and an unknown tool falls to the default', () => {
  // Tool names are read out of guidance.DOMAIN_OF rather than hardcoded, so a tool that changes domain
  // next year still exercises the rule it belongs to instead of a stale literal.
  const byDomain = {};
  for (const [tool, domain] of Object.entries(guidance.DOMAIN_OF)) {
    if (!byDomain[domain]) byDomain[domain] = tool;
  }
  assert.ok(byDomain.scanning, 'the registry should have a scanning-domain tool');
  assert.ok(byDomain.recon, 'the registry should have a recon-domain tool');

  assert.strictEqual(memory.tierOfTool(byDomain.scanning), memory.TIERS.STRATEGY,
    `${byDomain.scanning} is a scanning-domain tool and should be STRATEGY`);
  assert.strictEqual(memory.tierOfTool(byDomain.recon), memory.TIERS.SCOPE_TARGET,
    `${byDomain.recon} is a recon-domain tool and should be SCOPE_TARGET`);
  if (byDomain.data) {
    assert.strictEqual(memory.tierOfTool(byDomain.data), memory.TIERS.SCOPE_TARGET);
  }
  if (byDomain.workflow) {
    assert.strictEqual(memory.tierOfTool(byDomain.workflow), memory.TIERS.STRATEGY);
  }
  assert.strictEqual(memory.tierOfTool('a_tool_that_is_not_registered_anywhere'), memory.DEFAULT_TIER);
});

test('the manifest covers every head field and every guidance domain exactly once', () => {
  // Every value is a real tier.
  const tiers = new Set(Object.values(memory.TIERS));
  for (const [where, map] of [['head', memory.MANIFEST.head], ['domain', memory.MANIFEST.domain]]) {
    for (const [key, tier] of Object.entries(map)) {
      assert.ok(tiers.has(tier), `MANIFEST.${where}.${key} is "${tier}", not a known tier`);
    }
  }
  // Every head field the contract attaches is tiered, and no extra ones are invented. Object keys are
  // unique by construction, so an exact set match is the "exactly once" assertion.
  assert.deepStrictEqual(new Set(Object.keys(memory.MANIFEST.head)),
    new Set(['keep_hunting', 'role_hint', 'goal', 'guidance']));
  // Every guidance domain file is tiered, read live from DOMAIN_OF so a fifth domain file could not be
  // added without this failing until its tier is declared.
  assert.deepStrictEqual(new Set(Object.keys(memory.MANIFEST.domain)),
    new Set(Object.values(guidance.DOMAIN_OF)));
});

test('tier is server-side bookkeeping and is never an attached field', () => {
  // The whole point of deriving tier from DOMAIN_OF rather than storing it on the entry: adding it to
  // ATTACHED_FIELDS would ship it on every result and re-add the per-call token tax this feature cuts.
  assert.ok(!guidance.ATTACHED_FIELDS.includes('tier'),
    'tier must never be an attached field');
});

maybe('a manage_* result carries no tier key in its guidance head', async () => {
  // The invariant at the choke point: attachGuidance rides every manage_* call, and whatever it adds
  // (guidance, keep_hunting, role_hint) must not include a tier the client would then pay to carry.
  const result = decode(await index.teach('manage_sqli', handlerReturning({ ok: true }))({}, { sessionId: 'm' }));
  assert.ok(!('tier' in result), 'the result envelope must not carry a tier');
  if (result.guidance && typeof result.guidance === 'object') {
    assert.ok(!('tier' in result.guidance), 'the guidance head must not carry a tier');
  }
});

// --- the ledger records counts and keys, never bodies -------------------------------------------

test('recordOut accumulates chars, calls, and the per-tier and per-tool buckets', () => {
  session.recordOut('sid', { tier: 'STRATEGY', topic: 'scanning', tool: 'manage_sqli', chars: 400 });
  const b = session.budget('sid');
  assert.strictEqual(b.chars_out, 400);
  assert.strictEqual(b.by_tier.STRATEGY, 400);
  assert.strictEqual(b.by_topic.scanning, 400);
  assert.strictEqual(b.by_tool.manage_sqli.calls, 1);
  assert.strictEqual(b.by_tool.manage_sqli.charsOut, 400);
  assert.strictEqual(b.call_count, 1);
});

test('the budget estimate is labelled a floor, not a total or a window gauge', () => {
  session.recordOut('sid', { tier: 'STRATEGY', topic: 'scanning', tool: 'manage_sqli', chars: 400 });
  const b = session.budget('sid');
  assert.strictEqual(b.est_tokens_floor, Math.ceil(400 / 4),
    'the token estimate is chars/4, rounded up');
  assert.match(b.note, /floor/i,
    'the budget must say in words that the number is a floor, never a trusted total');
});

test('forgetWhere clears the briefed set and the ledger meta in lockstep', () => {
  // THE CRITICAL INVARIANT. A forgotten tool must re-teach in full on its next call, so its briefed
  // flag and its ledger accounting have to disappear together: a stuck briefed flag silences the
  // re-teach, and an orphan meta row keeps charging for a lesson no longer served.
  const tool = 'manage_sqli';
  assert.strictEqual(session.firstBrief('sid', tool), true);
  session.recordOut('sid', { tier: 'STRATEGY', topic: 'scanning', tool, chars: 320 });
  assert.strictEqual(session.hasBriefed('sid', tool), true);

  const forgotten = session.forgetWhere('sid', (d) => d.tier === 'STRATEGY');
  assert.ok(forgotten >= 1, 'the STRATEGY-tier tool should have been forgotten');

  assert.strictEqual(session.hasBriefed('sid', tool), false, 'the briefed flag is gone, so it re-teaches');
  const b = session.budget('sid');
  assert.strictEqual(b.by_tool[tool], undefined, 'no orphan meta row survives the forget');
  assert.strictEqual(b.by_tier.STRATEGY, 0, 'the tier accounting drops in lockstep');
});

// --- the two eviction paths ---------------------------------------------------------------------

test('switchTarget clears SCOPE_TARGET and STRATEGY but keeps PERMANENT accounting', () => {
  session.recordOut('sid', { tier: 'PERMANENT', topic: 'methodology', tool: 'get_methodology', chars: 100 });
  session.recordOut('sid', { tier: 'SCOPE_TARGET', topic: 'recon', tool: 'query_subdomains', chars: 200 });
  session.recordOut('sid', { tier: 'STRATEGY', topic: 'scanning', tool: 'manage_sqli', chars: 400 });

  const summary = session.switchTarget('sid', 'T1');
  assert.strictEqual(summary.target_id, 'T1');
  assert.ok(Array.isArray(summary.carried_over) && summary.carried_over.length > 0);
  assert.ok(Array.isArray(summary.dropped));

  const b = session.budget('sid');
  assert.strictEqual(b.by_tool.get_methodology && b.by_tool.get_methodology.charsOut, 100,
    'PERMANENT accounting survives a target switch');
  assert.strictEqual(b.by_tool.query_subdomains, undefined, 'SCOPE_TARGET is dropped');
  assert.strictEqual(b.by_tool.manage_sqli, undefined, 'STRATEGY is dropped');
  assert.strictEqual(b.last_target_id, 'T1', 'the new target is recorded');
});

test('setStrategy clears only STRATEGY and keeps PERMANENT and SCOPE_TARGET', () => {
  session.recordOut('sid', { tier: 'PERMANENT', topic: 'methodology', tool: 'get_methodology', chars: 100 });
  session.recordOut('sid', { tier: 'SCOPE_TARGET', topic: 'recon', tool: 'query_subdomains', chars: 200 });
  session.recordOut('sid', { tier: 'STRATEGY', topic: 'scanning', tool: 'manage_sqli', chars: 400 });

  const summary = session.setStrategy('sid', 'go-wide');
  assert.strictEqual(summary.strategy, 'go-wide');
  assert.ok(Array.isArray(summary.carried_over) && summary.carried_over.length > 0);
  assert.ok(Array.isArray(summary.dropped));

  const b = session.budget('sid');
  assert.strictEqual(b.by_tool.get_methodology.charsOut, 100, 'PERMANENT survives a strategy change');
  assert.strictEqual(b.by_tool.query_subdomains.charsOut, 200, 'SCOPE_TARGET survives a strategy change');
  assert.strictEqual(b.by_tool.manage_sqli, undefined, 'STRATEGY is dropped');
  assert.strictEqual(b.strategy, 'go-wide');
});

test('setStrategy does not silence the keep-hunting layer', () => {
  // Anti-thrash: a strategy switch clears STRATEGY lessons but must never reset the consecutive-empty
  // counter, or the model could dodge the loud keep-hunting block by switching strategy between calls.
  assert.strictEqual(session.recordEmpty('sid', true), 1);
  assert.strictEqual(session.recordEmpty('sid', true), 2);
  session.setStrategy('sid', 'go-narrow');
  assert.strictEqual(session.recordEmpty('sid', true), 3,
    'the empty run survives a strategy change, so keep_hunting still escalates');
});

// --- the map is bounded -------------------------------------------------------------------------

test('the session map is bounded by MAX_SESSIONS regardless of reconnect churn', () => {
  // Each SSE reconnect mints a new sessionId, so the lazy idle sweep cannot bound the map on its own;
  // the LRU eviction is what caps it. Driving well past the cap and asserting the size proves the cap.
  const over = session.MAX_SESSIONS + 100;
  for (let i = 0; i < over; i += 1) {
    session.recordOut(`sid-${i}`, { tier: 'STRATEGY', topic: 'scanning', tool: 'manage_sqli', chars: 10 });
  }
  assert.ok(session._sessions.size <= session.MAX_SESSIONS,
    `the map holds ${session._sessions.size}, over the ${session.MAX_SESSIONS} cap`);
});

// --- the fallback key is shared, so its budget is never a trusted total -------------------------

test('the fallback key is a shared bucket, so its budget is never a trusted per-caller total', () => {
  // A missing session id buckets every anonymous caller onto one key. The budget there sums callers
  // who are not the same agent, so it is explicitly labelled a floor and must never read as a trusted
  // per-session total. Both an undefined id and an empty-string id land on the one fallback key.
  session.recordOut(undefined, { tier: 'STRATEGY', topic: 'scanning', tool: 'manage_sqli', chars: 100 });
  session.recordOut('', { tier: 'STRATEGY', topic: 'scanning', tool: 'manage_xss', chars: 100 });

  const fallback = session.budget(session.FALLBACK_KEY);
  assert.strictEqual(fallback.chars_out, 200,
    'both anonymous callers accumulate on the one fallback key, which is why its budget cannot be trusted');
  assert.strictEqual(session.budget(undefined).chars_out, 200, 'an undefined id reads the fallback bucket');
  assert.strictEqual(session.budget('').chars_out, 200, 'an empty id reads the fallback bucket too');
  assert.match(fallback.note, /floor/i, 'the shared accumulation is labelled a floor, not a trusted total');
});
