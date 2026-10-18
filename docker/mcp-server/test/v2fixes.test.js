// Regression tests for four defects found by the post-build adversarial review and fixed in v2.
// Each test names the defect it guards so a future edit that reopens it fails here.
const { test } = require('node:test');
const assert = require('node:assert');

const schema = require('../src/roles/schema');
const session = require('../src/guidance/session');
const memory = require('../src/guidance/memory');
const reconRoles = require('../src/roles/recon');
const methodology = require('../src/tools/methodology');

// A. ageOf() reads def.updated, so the schema must ALLOW updated (and require it to be dated) rather
// than reject it as an unknown key, which would brick the whole registry load at require time.
test('A: schema accepts a dated updated field and refuses a dateless one', () => {
  const base = JSON.parse(JSON.stringify(reconRoles[0]));
  assert.deepStrictEqual(schema.validate(base), [], 'the base role should be valid to begin with');

  const good = { ...base, updated: 'refreshed against the 2026-10-18 corpus pass' };
  assert.deepStrictEqual(schema.validate(good), [], 'a dated updated must be accepted, not an unknown-key error');

  const bad = { ...base, updated: 'updated recently with no date at all here' };
  const problems = schema.validate(bad);
  assert.ok(problems.some((p) => p.includes('updated')), 'a dateless updated must be refused with a clear problem');
  assert.ok(!problems.some((p) => p.includes('unknown field "updated"')), 'updated must be a known key, not rejected outright');
});

// B. Advisory set_strategy (gate off) claimed it recorded the strategy but never persisted it, so the
// budget report showed strategy:null. recordStrategy persists the label without evicting.
test('B: recordStrategy persists the label for the budget report without evicting', () => {
  const sid = 'v2fix-B';
  session.recordOut(sid, { tier: memory.TIERS.STRATEGY, topic: 'scanning', tool: 'manage_sqli', chars: 400 });
  session.recordStrategy(sid, 'idor-sweep');
  const b = session.budget(sid);
  assert.strictEqual(b.strategy, 'idor-sweep', 'budget must reflect the recorded strategy label');
  assert.ok(b.by_tool.manage_sqli, 'recording a strategy label must NOT evict existing lessons');
});

// C. Head fields ride every result and must be tiered by what they ARE (recordHead), updating by_tier
// but never by_tool, so forgetWhere cannot evict them and by_tier is honest.
test('C: recordHead tiers head bytes without polluting by_tool, and survives a STRATEGY forget', () => {
  const sid = 'v2fix-C';
  session.recordHead(sid, { tier: memory.TIERS.PERMANENT, topic: 'workflow', chars: 100 });
  session.recordOut(sid, { tier: memory.TIERS.STRATEGY, topic: 'scanning', tool: 'manage_xss', chars: 250 });
  let b = session.budget(sid);
  assert.strictEqual(b.by_tier.PERMANENT, 100, 'permanent head bytes must land in the PERMANENT tier');
  assert.strictEqual(b.by_tier.STRATEGY, 250, 'body bytes must land in the tool tier');
  assert.ok(!b.by_tool.PERMANENT && !b.by_tool.keep_hunting, 'head bytes must never create a by_tool entry');

  const dropped = session.forgetWhere(sid, (d) => d.tier === memory.TIERS.STRATEGY);
  assert.strictEqual(dropped, 1, 'the STRATEGY tool lesson is evictable');
  b = session.budget(sid);
  assert.strictEqual(b.by_tier.PERMANENT, 100, 'PERMANENT head cost persists across a STRATEGY forget');
  assert.ok(!b.by_tool.manage_xss, 'the evicted tool lesson is gone from by_tool');
});

// D. Re-activating the SAME target is idempotent and must not drop that target's freshly taught
// lessons or null its strategy; only an actual target change evicts.
test('D: switchTarget to the same target is a no-op; a different target evicts', () => {
  const sid = 'v2fix-D';
  session.switchTarget(sid, 'target-1');
  session.recordOut(sid, { tier: memory.TIERS.SCOPE_TARGET, topic: 'recon', tool: 'query_subdomains', chars: 300 });

  const same = session.switchTarget(sid, 'target-1');
  assert.ok(same.carried_over.join(' ').includes('unchanged'), 'same-target re-activation reports unchanged');
  assert.ok(session.budget(sid).by_tool.query_subdomains, 'same-target re-activation must NOT drop the lesson');

  const diff = session.switchTarget(sid, 'target-2');
  assert.ok(diff.dropped.length >= 1, 'a real target change evicts SCOPE_TARGET/STRATEGY lessons');
  assert.ok(!session.budget(sid).by_tool.query_subdomains, 'the lesson is dropped on a real switch');
});

// E. whats_next is role-aware: every advisor step key the advisor actually emits (except the ANY-level
// authentication note and the empty note step) must resolve to a real owning role, so a blocker/gap
// can point the agent at the role that clears it.
test('E: advisor step keys map to owning roles for whats_next enrichment', () => {
  const mustMap = ['manual-crawl', 'content-discovery', 'consolidate-vectors',
    'vector-scanning', 'access-bypass', 'threat-model'];
  for (const k of mustMap) {
    const r = methodology.roleForAdvisorStep(k);
    assert.ok(r && typeof r.assume === 'string' && r.assume.length > 0, `advisor step ${k} must map to an owning role`);
    assert.ok(/role_id:/.test(r.how), 'the pointer tells the agent how to assume the role');
    assert.ok(r.hint && r.hint.includes(r.assume), 'the hint names the resolved role id');
  }
  assert.strictEqual(methodology.roleForAdvisorStep('authentication'), null, 'authentication has no single owning role');
  assert.strictEqual(methodology.roleForAdvisorStep(''), null, 'the empty note step maps to no role');
});
