const test = require('node:test');
const assert = require('node:assert');

// These modules import zod, and the repo carries no node_modules locally (the image installs them,
// and .dockerignore keeps test/ out of the image). So the suite skips rather than fails where the
// dependency is absent: a red suite that means "you have not run npm install" trains people to
// ignore red suites.
let vectortools = null;
let fuzz = null;
try {
  vectortools = require('../src/tools/vectortools');
  fuzz = require('../src/tools/fuzz');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

const maybe = vectortools && fuzz ? test : test.skip;

const actionsOf = (schema) => [...schema.shape.action._def.values];

// The Targets tab helper routes feed the UI's endpoint picker, and MCP could read NONE of them. All
// twelve sections share manageVectorTools, whose action list was a closed enum with no per-section
// extension point, so an agent could WRITE a tool's endpoints setting but never see the candidates
// the UI offers it. Three of the six were even named in the tool descriptions, which turned an
// omission into an instruction that could not be followed.
maybe('the sections with a Targets tab expose its lists', () => {
  const expected = {
    manageBypassSchema: ['candidate_endpoints', 'denied_endpoints'],
    manageGraphqlSchema: ['candidate_endpoints', 'known_endpoints'],
    manageLeakSchema: ['candidate_endpoints'],
    manageGitSchema: ['candidate_endpoints', 'git_endpoints'],
    manageMiscSchema: ['upload_candidates', 'found_jwts'],
  };
  for (const [name, wanted] of Object.entries(expected)) {
    const actions = actionsOf(vectortools[name]);
    for (const action of wanted) {
      assert.ok(actions.includes(action), `${name} is missing the ${action} action`);
    }
  }
});

// The enum is shared by all twelve sections. Offering found_jwts on manage_xss would advertise a
// call that cannot work, which is the same failure as naming the raw route in a description.
maybe('a section without a Targets tab is not offered one', () => {
  for (const name of ['manageXSSSchema', 'manageSQLiSchema', 'manageCacheSchema',
    'manageCmdiSchema', 'manageRedirectSchema', 'manageLfiSchema', 'manageSmugglingSchema']) {
    const actions = actionsOf(vectortools[name]);
    for (const forbidden of ['candidate_endpoints', 'denied_endpoints', 'known_endpoints',
      'git_endpoints', 'upload_candidates', 'found_jwts']) {
      assert.ok(!actions.includes(forbidden),
        `${name} offers ${forbidden}, which does not exist on that section`);
    }
  }
});

// Every section keeps the shared actions. A regression here would be silent: the schema still
// builds, and the action simply stops being offered.
maybe('adding the extra actions did not drop the shared ones', () => {
  const shared = ['eligibility', 'option_reference', 'settings', 'save_settings',
    'section_settings', 'save_section_settings', 'run', 'status', 'results', 'triage'];
  for (const name of ['manageXSSSchema', 'manageGitSchema', 'manageMiscSchema',
    'manageBypassSchema']) {
    const actions = actionsOf(vectortools[name]);
    for (const action of shared) {
      assert.ok(actions.includes(action), `${name} lost the ${action} action`);
    }
  }
});

// A section-scoped action asked of the wrong section must say so rather than building a URL that
// 404s, because a 404 here reads as "this target has nothing", not "wrong tool".
maybe('a Targets action on the wrong section is refused with a useful reason', async () => {
  const result = await vectortools.manageGit({
    action: 'found_jwts', target_id: '00000000-0000-0000-0000-000000000000',
  });
  assert.match(result.error || '', /misc/,
    'the error must name the section the action does exist on');
});

// Seeing an endpoint's request bytes used to require CREATING a fuzz step and deleting it again,
// because the renderer's only other caller is CreateFuzzStep. A read-only question mutated the
// target's shared fuzz flow, and there was no fallback: query_consolidated_endpoints returns
// neither headers nor request body.
maybe('one endpoint can be rendered as request bytes without creating a step', () => {
  const actions = actionsOf(fuzz.manageFuzzSchema);
  assert.ok(actions.includes('seed'), 'manage_fuzz cannot render a seed without writing a step');
  assert.ok(actions.includes('seed_endpoints'), 'the list action must still exist beside it');
});

maybe('seed demands the endpoint id rather than silently listing everything', async () => {
  await assert.rejects(
    () => fuzz.manageFuzz({ action: 'seed' }),
    /seed_endpoint_id/,
  );
});

// The server renumbers only the ids it is handed, so a partial list can collide with the unique
// (flow_id, ordinal) index and fail part way through, leaving already-moved steps parked on their
// temporary high ordinals. The completeness check has to live in the tool.
maybe('reorder_steps exists and refuses an empty or missing list', async () => {
  assert.ok(actionsOf(fuzz.manageFuzzSchema).includes('reorder_steps'));
  for (const params of [{ action: 'reorder_steps' }, { action: 'reorder_steps', step_ids: [] }]) {
    await assert.rejects(() => fuzz.manageFuzz(params), /step_ids/);
  }
});
