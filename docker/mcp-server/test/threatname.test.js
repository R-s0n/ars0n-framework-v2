const test = require('node:test');
const assert = require('node:assert');

// The accordion header for a threat is `<attack name> - <mechanism> on <target object>`, and both
// halves are now capped: 65 characters for an ad hoc attack name, 125 for the composed second half.
//
// The composed half is the interesting one. It is not one field, so a per-field cap does not bound
// it, and it was not capped at all until now: 68 of the 252 rows on the reference target are over
// budget already and one of them carries an 845-character paragraph in `mechanism`. Those rows have
// to stay editable, because the pass that settles them changes test_status and never touches the
// name. A cap that refuses those updates breaks the workflow it was added to tidy up.
//
// So the rule is "must not get worse" rather than "must be in range", and this suite pins both
// halves of it.
const {
  threatNameError, MAX_THREAT_NAME, MAX_ATTACK_CUSTOM_NAME, manageThreatModelSchema,
} = require('../src/tools/threatmodel.js');

const name = (n) => 'x'.repeat(n);

test('a name inside the budget passes on create', () => {
  assert.equal(threatNameError({ mechanism: 'Password Reset', target_object: 'Session Object' }), null);
});

test('the budget covers the composed string, not either field alone', () => {
  // Two values that are each comfortably inside 125 but compose to 129 with the " on " joiner.
  const err = threatNameError({ mechanism: name(70), target_object: name(55) });
  assert.ok(err, 'two in-range fields composing out of range must be refused');
  assert.equal(err.threat_name.length, 70 + 4 + 55);
});

test('the " on " joiner is only counted when there is a target object', () => {
  assert.equal(threatNameError({ mechanism: name(MAX_THREAT_NAME) }), null);
  assert.ok(threatNameError({ mechanism: name(MAX_THREAT_NAME + 1) }));
});

test('create is strict: no previous row means no exemption', () => {
  const err = threatNameError({ mechanism: name(200) }, null);
  assert.ok(err);
  assert.match(err.error, /125 characters together/);
});

test('an over-budget row stays editable as long as the name does not grow', () => {
  const previous = { mechanism: name(845) };
  // The test_status pass: name unchanged, still 845, still over budget. Must be allowed.
  assert.equal(threatNameError({ mechanism: name(845) }, previous), null,
    'an unchanged over-budget name must not block an update that is not touching it');
  // Shortening toward the cap without reaching it. Must be allowed, or the row can never recover.
  assert.equal(threatNameError({ mechanism: name(400) }, previous), null);
  // Actually reaching the cap. Allowed by the plain check.
  assert.equal(threatNameError({ mechanism: name(120) }, previous), null);
});

test('an over-budget row cannot be made worse', () => {
  const previous = { mechanism: name(845) };
  assert.ok(threatNameError({ mechanism: name(846) }, previous),
    'growing an already-over-budget name must still be refused');
});

test('the error names the offending length and points somewhere uncapped', () => {
  const err = threatNameError({ mechanism: name(130) });
  assert.match(err.error, /is 130/);
  assert.match(err.error, /one_sentence or summary/);
});

test('the schema caps the ad hoc attack name at 65', () => {
  const shape = manageThreatModelSchema.shape;
  assert.equal(shape.attack_custom_name.safeParse(name(MAX_ATTACK_CUSTOM_NAME)).success, true);
  assert.equal(shape.attack_custom_name.safeParse(name(MAX_ATTACK_CUSTOM_NAME + 1)).success, false);
});

test('the schema caps each name half individually as a first line of defence', () => {
  const shape = manageThreatModelSchema.shape;
  assert.equal(shape.mechanism.safeParse(name(MAX_THREAT_NAME)).success, true);
  assert.equal(shape.mechanism.safeParse(name(MAX_THREAT_NAME + 1)).success, false);
  assert.equal(shape.target_object.safeParse(name(MAX_THREAT_NAME + 1)).success, false);
});

test('the caps are stated in the prose an agent reads, not just enforced', () => {
  const shape = manageThreatModelSchema.shape;
  assert.match(shape.mechanism.description, /125 characters TOGETHER/);
  assert.match(shape.target_object.description, /125-character budget/);
});
