const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');
const { clip, resolveLimit, DEFAULTS } = require('../utils/clip');

// The Request Flow BUILDER over MCP: the operator assembles a flow by hand, or seeds one from a
// flow the detector already found, and then runs it.
//
// The rule this file exists to satisfy is the one wildcard.js is written for: anything an operator
// can do in the UI must be doable here. The builder is fifteen routes and had none. Detection could
// be run and read over MCP, and the repeater could send one request, but the thing an operator
// actually does between those two - "these four requests, in this order, with the token from step
// two carried into step three, and branch on what step three answers" - was reachable only from a
// browser.
//
// One tool with an action enum rather than seventeen tools, for the same reason manage_notes,
// manage_xss and manage_manual_crawl are one each: the actions share a vocabulary (flow_id,
// step_id, conditions, caps) and splitting them multiplies that vocabulary across a tool list the
// model has to read in full before it can choose.
//
// FOUR THINGS TO KNOW BEFORE AUTHORING ANYTHING HERE.
//
// WHAT DECIDES WHETHER A STEP IS SENT. Two things, and the verb is not one of them. First, the
// step's own `enabled` switch, which is the operator's control: a turned-off step keeps its place
// in the sequence and is skipped. Second, the boundary, judged on every send in this order - the
// operator's out-of-scope host list, the target's scope boundary, then the flow exclusion rules. A
// GET and a POST are treated identically by both. Nothing here refuses a step for being a POST,
// PUT, PATCH or DELETE, and nothing seeds one turned off for that reason, because a flow whose
// write steps silently did not run proves nothing when it comes back green.
//
// CONDITIONS are the feature and are the easiest thing to get wrong, so the grammar is a first
// class action (action:"grammar") as well as being summarised in the parameter descriptions. They
// are validated at SAVE time: a catch-all that is not last, a goto to a step that does not exist, a
// regex that will not compile and a numeric operator with a non-numeric value are all 400s at the
// moment they are written rather than silent never-matches at the moment the flow fires at a live
// target.
//
// LOOP PROTECTION cannot be turned off, only lowered, and a run that ends on a cap ends without an
// answer. The defaults are stated in the schema so a model authoring a retry loop knows what it is
// working inside, and a capped run comes back with cap_hit naming the cap, its value, and the fact
// that it was a cap rather than the target.
//
// SIZE. A step holds a whole raw HTTP request and, after a run, a whole response body. A flow of
// twelve steps returned verbatim is a context window. So: raw requests and bodies are CLIPPED in
// every list view and full only in get_step, and the trace, which is one entry per EXECUTION and so
// can run to the 300-execution ceiling, is capped and says when it capped.
//
// There is one thing here that is not a route: get_step. The API has no GET for a single step, so
// it reads the flow and picks the step out. That is why it wants flow_id, and why passing only
// step_id costs one request per flow on the target.

// === Sizes ======================================================================================

// A raw request inside a multi-step listing. Enough to recognise the request line, the Host and the
// first headers, which is what identifies a step; the whole thing is one get_step away.
const RAW_PREVIEW = 700;
// A response body inside a listing. Enough for an error message or the first field of a JSON body.
const BODY_PREVIEW = 400;
// How many flows a listing returns before it truncates.
const FLOW_LIST_DEFAULT = 25;
// How many steps a flow view returns before it truncates. A hand-built flow is rarely longer.
const STEP_LIST_DEFAULT = 50;
// How many trace entries a run returns. The run itself may execute up to the 300 ceiling, and the
// tail of a capped run is the interesting half, so both ends are kept when it truncates.
const TRACE_DEFAULT = 40;

// === The grammar, which is what a model gets wrong ==============================================

const CONDITION_GRAMMAR = `
A condition is {when, then, target, message}. A step holds an ORDERED list of them, evaluated
against the response THAT step just produced. FIRST MATCH WINS. If nothing matches, the flow
continues to the next step, which is exactly what a step with no conditions does - so adding
conditions to one step cannot change what the rest of the flow already did.

WHEN:  <field> <operator> <value>        e.g.  status == 302
       *   or   else                     the catch-all

FIELDS, of the step that just ran:
  status              the response status code
  header.<name>       a response header; the name is matched case-insensitively. A header sent
                      several times matches on ANY value for the positive operators and on ALL
                      values for the negative ones (!= and !~), because "no value of this header
                      contains x" is what a negation means when there are three of them.
  body                the response body
  size                the response body length in bytes
  time_ms             the elapsed time in milliseconds

FIELDS, of an EARLIER step, named by its step name or its step id:
  step.Login.status == 200
  step.Login.header.Location ~ /dashboard
  step."GET /login".size > 0            quote the reference when the step name has spaces, which
                                        seeded step names do ("GET /login")
  A step that has not run yet, is turned off, or was refused is ABSENT, not zero. The condition does
  not match, and the reason is reported in the trace as a condition problem rather than swallowed,
  because a condition that silently never matches looks exactly like one whose case never happened.

OPERATORS:
  >  <  >=  <=      numbers only. A non-numeric field or value is an ERROR, not a false.
  ==  !=            numeric when both sides are numbers, otherwise an exact string comparison
  ~   !~            case-insensitive substring
  =~                RE2 regular expression, compiled when you SAVE it

ACTIONS (then):
  continue   go to the next step in order. The same thing an unmatched step does, said explicitly,
             which is worth having because it stops the SEARCH: put {"when":"status == 200",
             "then":"continue"} before a catch-all fail and the 200 case is spelled out.
  goto       jump to the step named in target, by step name or step id. The ONLY action that can
             move backwards, and therefore the only one that can loop.
  stop       end the run, reporting success (outcome "stopped").
  fail       end the run, reporting failure (outcome "failed"), with message as the reason.
  retry      re-send THIS step after retry_delay_ms, subject to the retry cap.
  Only goto may carry a target. A target on any other action is refused rather than ignored.

RULES ENFORCED WHEN YOU SAVE, so a bad list is a 400 now and not a surprise against a live target:
  - The catch-all must be LAST. A catch-all matches everything, so every condition after it is dead
    code the operator can still see in the list and believes can fire.
  - A goto target must ALREADY resolve: an existing step id, or a step name that is unique in this
    flow. Two steps called "Login" with a jump to "Login" is refused rather than resolved to the
    first, because the behaviour would depend on row order.
  - A regex must compile and a numeric operator needs a numeric value.
  - A CYCLE is warned about, never refused: a bounded retry loop is legitimate. The warnings come
    back on the save and on every get_flow, recomputed each time, so a loop created by DELETING a
    step is reported too.
`;

const CONDITION_EXAMPLES = [
  {
    what: 'Follow a redirect the flow expects, and say so when it does not come.',
    conditions: [
      { when: 'status == 302', then: 'goto', target: 'GET /dashboard', message: 'logged in, following the redirect' },
      { when: '*', then: 'fail', message: 'the login did not redirect, so the session was never established' },
    ],
  },
  {
    what: 'A bounded retry on a rate limit or a flaky 5xx. The retry cap (default 3) and the delay (default 1000ms) are what make this safe; a run that exhausts them stops and says so.',
    conditions: [
      { when: 'status == 429', then: 'retry', message: 'rate limited, backing off' },
      { when: 'status >= 500', then: 'retry', message: 'server error, trying once more' },
      { when: '*', then: 'continue' },
    ],
  },
  {
    what: 'Gate the rest of the flow on an earlier step, which is the real reason step.<name> exists: everything after an unauthenticated step proves nothing.',
    conditions: [
      { when: 'step.Login.status != 200', then: 'fail', message: 'login did not succeed, so nothing after this step is evidence of anything' },
    ],
  },
  {
    what: 'Assert the access-control result: the attacker session asked for the victim record.',
    conditions: [
      { when: 'body ~ "victim@example.com"', then: 'fail', message: 'IDOR: the victim record came back to the attacker session' },
      { when: 'status == 403', then: 'stop', message: 'access control held' },
      { when: 'else', then: 'continue' },
    ],
  },
  {
    what: 'Stop as soon as the thing you were waiting for lands, rather than walking the rest of the flow.',
    conditions: [
      { when: 'header.Location =~ ^/account/[0-9]+', then: 'stop', message: 'reached the account page' },
    ],
  },
];

// === The caps, stated rather than implied =======================================================
//
// Mirrors the constants in server/utils/flowConditions.go. Kept here as data so the schema, the
// grammar action and the stopped-by-a-cap explanation all quote the same numbers: a client that
// prints its own constants while the server enforces others is a promise the screen cannot keep.
const CAPS = {
  max_executions: {
    default: 50, ceiling: 300,
    what: 'Executions, NOT steps. A 4-step flow that jumps backwards reaches this long before it ' +
          'runs out of steps. Every visit counts, including a step that was skipped or refused, ' +
          'because two turned-off steps that goto each other would otherwise spin forever without ' +
          'sending a single request.',
  },
  per_step_max_executions: {
    default: 10, ceiling: 50,
    what: 'One step cannot be re-entered indefinitely even inside a budget that still has room.',
  },
  retry_cap: {
    default: 3, ceiling: 10,
    what: 'Separate and small, because a retry is for a flaky response and not for brute force.',
  },
  retry_delay_ms: {
    default: 1000, floor: 250, ceiling: 30000,
    what: 'The delay between retries. A retry with no delay is a tight loop that happens to be counted.',
  },
  wall_clock_s: {
    default: 600, ceiling: 1800,
    what: 'However slowly a run is paced, it cannot outlive the operator watching it.',
  },
  max_requests: {
    default: 250, settable: false,
    what: "This target's ENGAGEMENT request budget. The programme's number, set in the engagement " +
          'config, not a flow setting and not raisable from here.',
  },
  rps: {
    default: 1.0, settable: false,
    what: 'The engagement rate limit. Paces EVERY request the run sends, loop or not. Also from the ' +
          'engagement config.',
  },
};

// Which cap a stop_reason names, so a capped run can say what stopped it instead of leaving the
// caller to infer it from a sentence. The two condition outcomes and the goto error are here too,
// because "did my flow end, or did a cap end it" is the first question and it needs a straight
// answer for every outcome and not only the capped ones.
const STOP_REASONS = {
  completed: { cap: null, means: 'the flow ran off the end of its steps' },
  stopped_by_condition: { cap: null, means: 'a condition said stop; this is your flow ending, not a cap' },
  failed_by_condition: { cap: null, means: 'a condition said fail; this is your flow ending, not a cap' },
  max_executed_steps: { cap: 'max_executions', means: 'the executed-step budget ran out' },
  per_step_execution_cap: { cap: 'per_step_max_executions', means: 'one step was re-entered too many times' },
  retry_cap: { cap: 'retry_cap', means: 'a condition asked to retry after the retry budget was spent' },
  wall_clock: { cap: 'wall_clock_s', means: 'the run ran out of wall clock time' },
  engagement_request_budget: { cap: 'max_requests', means: "the target's engagement request budget ran out; this is the programme's number, not a flow setting" },
  goto_target_missing: { cap: null, means: 'a goto named a step that could not be resolved at run time; this is an authoring error, not a cap' },
};

// === Schema =====================================================================================

const manageFlowBuilderSchema = z.object({
  action: z.enum([
    'grammar',
    'list_flows', 'get_flow', 'create_flow', 'update_flow', 'delete_flow',
    'seed_from_detected_flow', 'seed_from_captures',
    'add_step', 'get_step', 'update_step', 'delete_step', 'reorder_steps', 'move_step',
    'preview', 'replay', 'replay_step',
  ]).describe(
    'grammar: the condition grammar, the actions, the save-time rules, worked examples, and every ' +
    'loop-protection cap with its default and ceiling. Takes no arguments. READ THIS FIRST if you ' +
    'are about to write a condition or a retry loop. ' +
    'list_flows: the built flows on a target, newest edit first, with their step and armed-step ' +
    'counts. ' +
    'get_flow: one flow with its steps (raw requests CLIPPED), the dry-run preview of what a replay ' +
    'would send, the scope boundary those steps are judged against, the caps a run would be held ' +
    'to, and any cycle warnings. This is the main read. ' +
    'create_flow: an empty flow. Usually the wrong start: prefer seed_from_detected_flow. ' +
    'update_flow: rename it, change its description, or repoint its base_url. Every field is ' +
    'optional and an omitted one is left alone. ' +
    'delete_flow: remove the flow and its steps. No restore. ' +
    'seed_from_detected_flow: THE PATH MOST OPERATORS WANT. Take a flow the detector found, turn ' +
    'its captured requests into editable steps in flow order, and then modify one. Detect, then ' +
    'change. The steps you asked for arrive ENABLED whatever verb they carry; scope and the ' +
    'exclusion rules still decide what a run may send. ' +
    'seed_from_captures: the same thing from an explicit list of capture ids, ordered by when they ' +
    'were recorded rather than by the order you list them. For a flow the detector did not segment ' +
    'the way you want. ' +
    'add_step: append a step, either from raw_request bytes you write or from capture_id, which ' +
    'rebuilds a recorded request. Never sent on add. ' +
    'get_step: ONE step in full: the whole raw request, all its captures, all its conditions and ' +
    'its stored response. There is no route for this, so it reads the flow and picks the step out; ' +
    'pass flow_id or it has to ask every flow on the target. ' +
    'update_step: edit a step. Every field is optional and an omitted one is left alone; ' +
    'extractions:[] and conditions:[] CLEAR those lists. This is also how you turn a step off ' +
    '(enabled:false) or back on. ' +
    'delete_step: remove a step. The rest close up into 1..n. ' +
    'reorder_steps: set the whole order at once. step_ids must be EVERY step id in the flow. ' +
    'move_step: lift one step out and drop it at a 1-based position. The convenience form. ' +
    'preview: the dry run. Which steps would go out, to which hosts, with which verbs, which would ' +
    'be refused and why, and how many requests that is. SENDS NOTHING. Do this before replay. ' +
    'replay: RUN THE FLOW. Sends live requests, follows the conditions, and comes back with the ' +
    'execution trace, the outcome and the caps it was judged against. ' +
    'replay_step: re-send ONE step, seeding cookies and captured values from the responses earlier ' +
    'steps have ALREADY recorded rather than by re-sending them. This is how you iterate on step ' +
    'four without firing the whole flow at the target each time. A turned-off step is refused.'),

  // --- addressing ---
  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list_flows, create_flow, seed_from_detected_flow and ' +
    'seed_from_captures. Optional on get_step, where without flow_id it is what makes the search ' +
    'for the step possible at all.'),
  flow_id: z.string().uuid().optional().describe(
    'A BUILT flow\'s own UUID, the "id" from list_flows / create_flow / a seed. Required for ' +
    'get_flow, update_flow, delete_flow, add_step, reorder_steps, preview and replay, and worth ' +
    'passing on get_step. This is NOT the detected-flow id, which is not a UUID at all; see ' +
    'detected_flow_id.'),
  step_id: z.string().uuid().optional().describe(
    'A step\'s own UUID. Required for get_step, update_step, delete_step, move_step and ' +
    'replay_step.'),

  // --- flow fields ---
  name: z.string().optional().describe(
    'create_flow: required, and the flow is found by it later. update_flow: replaces it; it cannot ' +
    'be blanked. A seed generates one from the detected flow\'s label when you do not give one. ' +
    'add_step / update_step: the STEP\'s name, which is also what a goto and a step.<name> ' +
    'condition refer to, so keep it short, unique within the flow, and stable once conditions ' +
    'point at it.'),
  description: z.string().optional().describe('create_flow / update_flow: free text about what the flow is for.'),
  base_url: z.string().optional().describe(
    'create_flow / update_flow: the FALLBACK origin, e.g. https://app.example.com. It is not an ' +
    'override: a step\'s own Host header always wins, so a flow that crosses hosts still works. It ' +
    'is what a hand-typed step with no Host header falls back to, and how a whole flow is pointed ' +
    'at a staging origin.'),

  // --- seeding ---
  detected_flow_id: z.string().optional().describe(
    'seed_from_detected_flow: the DETECTED flow id, which is "<session>~<tab>~<root capture>" and ' +
    'not a UUID. Get it from the detected-flows list for the target. It is provenance rather than a ' +
    'key: re-segmentation as new captures arrive can retire an id, and the seed then answers that ' +
    'no flow starts at that request, which means reload the list rather than that anything broke.'),
  capture_ids: z.array(z.string().uuid()).optional().describe(
    'seed_from_captures: the manual-crawl capture ids to build steps from. Required there, and ' +
    'ordered by RECORDED time rather than by the order you list them, because a flow\'s meaning is ' +
    'its sequence and a set of ticked checkboxes has no reason to be in timeline order. ' +
    'seed_from_detected_flow: optional, and when given it names exactly which of that flow\'s ' +
    'captures become steps, overriding the noise filter and include_all.'),
  include_all: z.boolean().optional().describe(
    'seed_from_detected_flow: bring in the subresources the flow diagram hides (images, ' +
    'stylesheets, fonts). Default false, which seeds the root plus the significant requests - the ' +
    'same selection the diagram drew, so the flow you get resembles the flow you picked.'),

  // --- steps ---
  raw_request: z.string().optional().describe(
    'add_step / update_step: the whole HTTP request, byte for byte - request line, headers, blank ' +
    'line, body. It needs a Host header or it cannot be sent, and it is NORMALIZED on the way in ' +
    '(framing repaired, Content-Length recomputed) unless raw_mode is set. Placeholders {{af:NAME}} ' +
    'are substituted at send time from what earlier steps captured.'),
  capture_id: z.string().uuid().optional().describe(
    'add_step: build the step from a recorded manual-crawl capture instead of writing bytes. Same ' +
    'rebuild the repeater uses. It arrives enabled whatever verb it carries; pass enabled:false if ' +
    'you want it parked. Nothing is sent on add.'),
  enabled: z.boolean().optional().describe(
    'add_step / update_step: whether the step is armed. Default true. A disabled step keeps its ' +
    'place in the sequence and is skipped on a run, rather than being deleted, because deleting to ' +
    'prune would destroy the sequence and the sequence is the flow. This is the switch that decides ' +
    'what a run sends, and it is yours: the verb never overrides it in either direction.'),
  raw_mode: z.boolean().optional().describe(
    'update_step: keep the bytes EXACTLY as sent, with no framing repair and no Content-Length ' +
    'recompute. For a deliberate Content-Length / Transfer-Encoding disagreement: "helpfully" ' +
    'repairing a smuggling probe turns it into an ordinary POST and you conclude the target is not ' +
    'vulnerable when you never sent the test.'),
  extractions: z.array(z.object({
    name: z.string().describe('Letters, digits and underscore only. Later steps refer to it as {{af:NAME}}.'),
    source: z.enum(['body', 'header', 'cookie']),
    source_key: z.string().optional().describe('The header or cookie name. Required for header and cookie.'),
    pattern: z.string().optional().describe('RE2. Capture group 1 is the value.'),
    decode_as: z.string().optional(),
    optional: z.boolean().optional().describe(
      'Default false, which is the safe direction: a REQUIRED capture that matches nothing refuses ' +
      'the step that needs it rather than sending a literal {{af:NAME}} at the target.'),
  })).optional().describe(
    'add_step / update_step: pull values out of THIS step\'s response so later steps can use them ' +
    'as {{af:NAME}}. This is what makes a per-request CSRF token work. One variable map spans the ' +
    'whole run, so a value survives a goto. On update_step, omitting leaves the list alone and [] ' +
    'clears it. Two captures with the same name on one step is refused.'),
  conditions: z.array(z.object({
    when: z.string().describe('<field> <op> <value>, or "*" / "else" for the catch-all, which must be last.'),
    then: z.enum(['continue', 'goto', 'stop', 'fail', 'retry']),
    target: z.string().optional().describe('goto only: the step name or step id to jump to. Refused on any other action.'),
    message: z.string().optional().describe('What you will read in the trace, and for fail the reason the run ended. Write one.'),
  })).optional().describe(
    'add_step / update_step: the ORDERED branch rules for this step, evaluated against the response ' +
    'THIS step produced, first match wins, no match means continue. Fields: status, header.<name>, ' +
    'body, size, time_ms, and step.<name>.<field> for an earlier step. Operators: == != > < >= <= ~ ' +
    '!~ =~. Actions: continue, goto, stop, fail, retry. The catch-all must be LAST or the save is ' +
    'refused, and a goto target must already exist as a step. CALL action:"grammar" for the full ' +
    'reference and worked examples. On update_step, omitting leaves the branching alone and [] ' +
    'makes the step linear again.'),
  step_ids: z.array(z.string().uuid()).optional().describe(
    'reorder_steps: the new order, as EVERY step id in the flow. A partial list is refused rather ' +
    'than treated as "these first, the rest behind": sending four ids out of eleven would move ' +
    'seven steps you never touched, in a thing whose whole meaning is its order. Read them from ' +
    'get_flow. For a single step, move_step is easier.'),
  to_position: z.number().int().optional().describe(
    'move_step: the 1-based position to drop the step at. Past either end is clamped rather than ' +
    'refused, because that is what a drag past the end of a list means.'),

  // --- run caps ---
  max_executions: z.number().int().optional().describe(
    `replay: cap on EXECUTIONS, not steps (default ${CAPS.max_executions.default}, ceiling ` +
    `${CAPS.max_executions.ceiling}). A flow that jumps backwards reaches it with only four steps. ` +
    'Cannot be turned off; a value over the ceiling is clamped and the clamp is reported.'),
  per_step_max_executions: z.number().int().optional().describe(
    `replay: how many times one step may be entered (default ${CAPS.per_step_max_executions.default}, ` +
    `ceiling ${CAPS.per_step_max_executions.ceiling}).`),
  retry_cap: z.number().int().optional().describe(
    `replay: retries per step (default ${CAPS.retry_cap.default}, ceiling ${CAPS.retry_cap.ceiling}). ` +
    'A retry is for a flaky response, not for brute force.'),
  retry_delay_ms: z.number().int().optional().describe(
    `replay: delay between retries (default ${CAPS.retry_delay_ms.default}, floor ` +
    `${CAPS.retry_delay_ms.floor}, ceiling ${CAPS.retry_delay_ms.ceiling}).`),
  wall_clock_s: z.number().int().optional().describe(
    `replay: the whole run's time budget (default ${CAPS.wall_clock_s.default}, ceiling ` +
    `${CAPS.wall_clock_s.ceiling}).`),

  // --- shaping the response ---
  max_results: z.number().optional().describe(
    `How many rows to return: flows on list_flows (default ${FLOW_LIST_DEFAULT}), steps on get_flow ` +
    `and the seeds (default ${STEP_LIST_DEFAULT}), trace entries on replay (default ${TRACE_DEFAULT}).`),
  max_body_chars: z.number().optional().describe(
    `How much of each raw request and each stored response body to return: clipped per row in list ` +
    `views (raw ${RAW_PREVIEW}, body ${BODY_PREVIEW}), and ${DEFAULTS.single} for the one record ` +
    'get_step returns. Raise it on get_step when a request or a response is longer than that and ' +
    'you need the rest. It is divided across the rows in a listing, so raising it on a twelve-step ' +
    'flow does not multiply by twelve.'),
  body_match: z.string().optional().describe(
    'Instead of the first N characters of a body, return the WINDOW around the first ' +
    'case-insensitive hit for this string. How you read a CSRF token that sits at character 3500 of ' +
    'a 7000 character form without transferring the form.'),
});

// === Dispatch ===================================================================================

async function manageFlowBuilder(params) {
  try {
    switch (params.action) {
      case 'grammar': return grammar();

      case 'list_flows': return await listFlows(params);
      case 'get_flow': return await getFlow(params);
      case 'create_flow': return await createFlow(params);
      case 'update_flow': return await updateFlow(params);
      case 'delete_flow': return await deleteFlow(params);

      case 'seed_from_detected_flow': return await seedFromDetectedFlow(params);
      case 'seed_from_captures': return await seedFromCaptures(params);

      case 'add_step': return await addStep(params);
      case 'get_step': return await getStep(params);
      case 'update_step': return await updateStep(params);
      case 'delete_step': return await deleteStep(params);
      case 'reorder_steps': return await reorderSteps(params);
      case 'move_step': return await moveStep(params);

      case 'preview': return await preview(params);
      case 'replay': return await replay(params);
      case 'replay_step': return await replayStep(params);

      default:
        return { error: `unknown action: ${params.action}` };
    }
  } catch (err) {
    return apiError(err, params);
  }
}

// === Reference ==================================================================================

function grammar() {
  return {
    conditions: CONDITION_GRAMMAR.trim(),
    examples: CONDITION_EXAMPLES,
    loop_protection: {
      note: 'None of these can be turned off, only lowered. A value above a ceiling is CLAMPED and ' +
            'the clamp is reported in caps.notes rather than silently applied. A run that hits one ' +
            'STOPS and says which, in cap_hit; a run that ends on a cap ends without an answer, so ' +
            'if you are seeing them, the flow is wrong rather than the target.',
      caps: CAPS,
    },
    extractions: {
      what: 'Captures pull a value out of a step\'s response and later steps use it as {{af:NAME}}. ' +
            'One variable map spans the whole run, so a captured value survives a goto and a step ' +
            'run twice refreshes what it captured.',
      required_by_default: 'optional defaults to false. A required capture that matches nothing ' +
            'REFUSES the step that needs it, rather than sending a literal {{af:NAME}} at the target.',
    },
    safety: {
      what_runs: 'The steps that run are the ones the operator ENABLED, in order. The verb has no ' +
            'say in it: a POST, PUT, PATCH or DELETE step is planned and sent exactly like a GET. ' +
            'Turn a step off with update_step enabled:false when you do not want it sent.',
      boundary: 'Every send is judged three times, in this order: the operator\'s out-of-scope host ' +
            'list, the target\'s scope boundary, then the flow exclusion rules. A refusal is ' +
            'recorded on the step and shown by preview BEFORE a run, not discovered during one. A ' +
            'boundary that cannot be READ refuses everything rather than defaulting to empty.',
      one_run_per_target: 'Only one flow run per scope target at a time. A second replay answers ' +
            '409 target_busy, because every cap including the pacer is per-run and two runs each ' +
            'holding to 2 rps put 4 rps on the programme.',
    },
  };
}

// === Flows ======================================================================================

async function listFlows(params) {
  if (!params.target_id) return { error: 'list_flows needs target_id' };
  const body = await apiGet(`/request-flow-builder/${params.target_id}/flows`);
  const flows = Array.isArray(body && body.flows) ? body.flows : [];
  // The route returns every flow on the target, so rows.length here really is the total.
  const out = limitResults(flows.map(flowRow), clampLimit(params.max_results, FLOW_LIST_DEFAULT));
  return { ...out, note: flows.length === 0 ? 'No built flows on this target yet. seed_from_detected_flow is the usual way to make the first one.' : undefined };
}

async function getFlow(params) {
  if (!params.flow_id) return { error: 'get_flow needs flow_id' };
  const body = await apiGet(`/request-flow-builder/flow/${params.flow_id}`);
  return flowView(body, params);
}

async function createFlow(params) {
  if (!params.target_id) return { error: 'create_flow needs target_id' };
  if (!params.name || !params.name.trim()) {
    return { error: 'create_flow needs a name with something in it; a flow is found by its name' };
  }
  const out = await apiPost(`/request-flow-builder/${params.target_id}/flows`, {
    name: params.name,
    description: params.description || '',
    base_url: params.base_url || '',
  });
  return {
    created: true,
    flow: flowRow(out),
    note: 'Empty. Add steps with add_step (raw_request or capture_id), or throw this away and use ' +
          'seed_from_detected_flow, which is usually what you wanted.',
  };
}

async function updateFlow(params) {
  if (!params.flow_id) return { error: 'update_flow needs flow_id' };
  // Only the fields the caller named are sent. The handler COALESCEs every column, so an omitted
  // field is left alone; sending nulls for the untouched ones would be a partial PUT that wipes.
  const body = {};
  if (params.name !== undefined) {
    if (!params.name.trim()) return { error: 'name cannot be blanked; a flow is identified by its name' };
    body.name = params.name;
  }
  if (params.description !== undefined) body.description = params.description;
  if (params.base_url !== undefined) body.base_url = params.base_url;
  if (Object.keys(body).length === 0) {
    return { error: 'update_flow needs a name, description or base_url, otherwise there is nothing to change' };
  }
  return { updated: true, flow: flowRow(await apiPut(`/request-flow-builder/flow/${params.flow_id}`, body)) };
}

async function deleteFlow(params) {
  if (!params.flow_id) return { error: 'delete_flow needs flow_id' };
  await apiDelete(`/request-flow-builder/flow/${params.flow_id}`);
  return { deleted: true, flow_id: params.flow_id, note: 'The steps went with it. There is no restore.' };
}

// === Seeding ====================================================================================

async function seedFromDetectedFlow(params) {
  if (!params.target_id) return { error: 'seed_from_detected_flow needs target_id' };
  if (!params.detected_flow_id) {
    return {
      error: 'seed_from_detected_flow needs detected_flow_id',
      hint: 'That is the DETECTED flow id, "<session>~<tab>~<root capture>", from the detected ' +
            'flows list for this target. It is not a UUID and it is not flow_id.',
    };
  }
  const out = await apiPost(`/request-flow-builder/${params.target_id}/from-flow`, {
    flow_id: params.detected_flow_id,
    name: params.name || '',
    include_all: params.include_all === true,
    capture_ids: params.capture_ids || [],
  });
  return seedView(out, params);
}

async function seedFromCaptures(params) {
  if (!params.target_id) return { error: 'seed_from_captures needs target_id' };
  if (!params.capture_ids || params.capture_ids.length === 0) {
    return { error: 'seed_from_captures needs capture_ids' };
  }
  const out = await apiPost(`/request-flow-builder/${params.target_id}/from-captures`, {
    name: params.name || '',
    capture_ids: params.capture_ids,
  });
  return seedView(out, params);
}

// === Steps ======================================================================================

async function addStep(params) {
  if (!params.flow_id) return { error: 'add_step needs flow_id' };
  if (!params.raw_request && !params.capture_id) {
    return { error: 'add_step needs raw_request (bytes you write) or capture_id (a recorded request to rebuild)' };
  }
  const body = {};
  if (params.name !== undefined) body.name = params.name;
  if (params.capture_id) body.capture_id = params.capture_id;
  else body.raw_request = params.raw_request;
  if (params.extractions !== undefined) body.extractions = params.extractions;
  if (params.conditions !== undefined) body.conditions = params.conditions;
  if (params.enabled !== undefined) body.enabled = params.enabled;

  const out = await apiPost(`/request-flow-builder/flow/${params.flow_id}/steps`, body);
  const limit = resolveLimit(params.max_body_chars, DEFAULTS.single);
  return {
    added: true,
    step: stepRecord(out.step, limit, limit, params),
    // note is whatever the server had to say about the step it just wrote; cycle_warnings is how a
    // loop is announced when it is created rather than when it fires at a live target.
    note: out.note || undefined,
    cycle_warnings: nonEmpty(out.cycle_warnings),
    reminder: 'Nothing was sent. add_step never replays; use replay_step when you mean to send it.',
  };
}

async function getStep(params) {
  if (!params.step_id) return { error: 'get_step needs step_id' };
  const found = await findStep(params.step_id, params.flow_id, params.target_id);
  if (found.error) return found;

  const limit = resolveLimit(params.max_body_chars, DEFAULTS.single);
  return {
    flow_id: found.flow.id,
    flow_name: found.flow.name,
    step: stepRecord(found.step, limit, limit, params),
    // The step's own row of the dry run, so "would this even be sent" is answered next to the bytes.
    would_send: (found.body.preview || []).find((p) => p.step_id === params.step_id),
    scope_boundary: found.body.scope_boundary,
  };
}

async function updateStep(params) {
  if (!params.step_id) return { error: 'update_step needs step_id' };
  // Pointer semantics, mirrored: only what the caller named is sent, and [] is a deliberate clear
  // rather than an omission. Sending the untouched fields would overwrite an edit made elsewhere.
  const body = {};
  if (params.name !== undefined) body.name = params.name;
  if (params.raw_request !== undefined) body.raw_request = params.raw_request;
  if (params.enabled !== undefined) body.enabled = params.enabled;
  if (params.extractions !== undefined) body.extractions = params.extractions;
  if (params.conditions !== undefined) body.conditions = params.conditions;
  if (params.raw_mode !== undefined) body.raw_mode = params.raw_mode;
  if (Object.keys(body).length === 0) {
    return {
      error: 'update_step needs at least one of name, raw_request, enabled, extractions or conditions',
      hint: 'An omitted field is left alone. Pass extractions:[] or conditions:[] to clear one.',
    };
  }

  const limit = resolveLimit(params.max_body_chars, DEFAULTS.single);
  const step = await apiPut(`/request-flow-builder/steps/${params.step_id}`, body);
  const out = { updated: true, step: stepRecord(step, limit, limit, params) };
  // Only present when conditions were part of the edit, which is the only time the server recomputes
  // them on this route.
  const warnings = nonEmpty(step.cycle_warnings);
  if (warnings) out.cycle_warnings = warnings;
  if (params.enabled === true) {
    out.note = 'This step is now ARMED and will be sent by the next replay, subject to scope and ' +
               'the exclusion rules. A step seeded from a capture carries the bytes that were ' +
               'recorded, body included.';
  }
  return out;
}

async function deleteStep(params) {
  if (!params.step_id) return { error: 'delete_step needs step_id' };
  await apiDelete(`/request-flow-builder/steps/${params.step_id}`);
  return {
    deleted: true,
    step_id: params.step_id,
    note: 'The remaining steps closed up into 1..n. Deleting a step can also CREATE a loop by ' +
          'shortening one, so re-read get_flow and check cycle_warnings if any step has a goto.',
  };
}

async function reorderSteps(params) {
  if (!params.flow_id) return { error: 'reorder_steps needs flow_id' };
  if (!params.step_ids || params.step_ids.length === 0) {
    return {
      error: 'reorder_steps needs step_ids',
      hint: 'It must be EVERY step id in the flow, in the order you want. Read them from get_flow. ' +
            'A partial list is refused, because it would move the steps you did not name.',
    };
  }
  const out = await apiPut(`/request-flow-builder/flow/${params.flow_id}/steps/order`, {
    step_ids: params.step_ids,
  });
  return stepsAfterOrdering(out, params);
}

async function moveStep(params) {
  if (!params.step_id) return { error: 'move_step needs step_id' };
  if (params.to_position === undefined) {
    return { error: 'move_step needs to_position (1-based; past either end is clamped)' };
  }
  const out = await apiPost(`/request-flow-builder/steps/${params.step_id}/move`, {
    to_position: params.to_position,
  });
  return stepsAfterOrdering(out, params);
}

// === Preview and run ============================================================================

async function preview(params) {
  if (!params.flow_id) return { error: 'preview needs flow_id' };
  const body = await apiGet(`/request-flow-builder/flow/${params.flow_id}/preview`);
  return {
    sent_nothing: true,
    flow: flowRow(body.flow),
    // These three are counted by the SERVER over every step, so they stay true even when the row
    // list below is truncated. That is the whole reason they are lifted out rather than left to be
    // recounted from the rows: a request_count derived from a clipped list would understate the
    // traffic a run is about to put on the programme.
    request_count: body.request_count,
    skipped_count: body.skipped_count,
    hosts: body.hosts || [],
    scope_boundary: body.scope_boundary,
    steps: limitResults(body.steps || [], clampLimit(params.max_results, STEP_LIST_DEFAULT)),
    caps: body.caps,
    cycle_warnings: nonEmpty(body.cycle_warnings),
    // Present only on a branching flow, and when it is present request_count is an upper bound on
    // ONE possible path rather than a total. Planning a run against a rate cap on that number and
    // then exceeding it is exactly what this sentence exists to prevent.
    branch_note: body.branch_note || undefined,
    note: 'request_count counts steps that are armed AND in scope. A step with refusal set will not ' +
          'be sent; the reason is on the step.',
  };
}

async function replay(params) {
  if (!params.flow_id) return { error: 'replay needs flow_id' };

  // Only caps the caller actually asked for. Every field on the server is a pointer, where absent
  // means "the default" - a different statement from zero, and zero must never read as "no cap".
  const body = {};
  for (const key of ['max_executions', 'per_step_max_executions', 'retry_cap', 'retry_delay_ms', 'wall_clock_s']) {
    if (params[key] !== undefined) body[key] = params[key];
  }

  const out = await apiPost(`/request-flow-builder/flow/${params.flow_id}/replay`, body);
  const run = out.run || {};
  const stepLimit = clampLimit(params.max_results, STEP_LIST_DEFAULT);
  const steps = Array.isArray(out.steps) ? out.steps : [];
  const rawLimit = resolveLimit(params.max_body_chars, RAW_PREVIEW, steps.length);
  const bodyLimit = resolveLimit(params.max_body_chars, BODY_PREVIEW, steps.length);

  const result = {
    flow: flowRow(out.flow),
    outcome: out.outcome || run.outcome,
    stop_reason: out.stop_reason || run.stop_reason,
    stop_detail: out.stop_detail || run.stop_detail,
    executions: run.executions,
    requests_sent: run.requests_sent,
    caps: run.caps,
    // The one thing a caller must not have to infer: did MY FLOW end, or did a cap end it.
    ...capHit(run),
    warnings: nonEmpty(run.warnings),
    // The trace is the only explanation a branching run has: the step rows hold the LAST response
    // only, so a step that ran three times leaves two of them nowhere else.
    ...traceView(run.trace, clampLimit(params.max_results, TRACE_DEFAULT)),
    refused_hosts: nonEmpty(out.refused_hosts),
    scope_boundary: out.scope_boundary,
    steps: limitResults(steps.map((s) => stepRow(s, rawLimit, bodyLimit, params)), stepLimit),
    run_id: run.run_id,
  };
  if (run.caps && Array.isArray(run.caps.notes) && run.caps.notes.length) {
    result.caps_clamped = run.caps.notes;
  }
  return result;
}

async function replayStep(params) {
  if (!params.step_id) return { error: 'replay_step needs step_id' };
  const out = await apiPost(`/request-flow-builder/steps/${params.step_id}/replay`, {});
  const limit = resolveLimit(params.max_body_chars, DEFAULTS.single);
  const result = { step: stepRecord(out.step, limit, limit, params) };
  if (out.replay_error) {
    // The row still holds the PREVIOUS run's response when a replay failed, so returning it without
    // this marker would show a stale success for a request that had just gone wrong.
    result.replay_error = out.replay_error;
    result.replay_note = out.replay_note ||
      'The replay did not complete. The response shown is from the previous run.';
  } else if (result.step && result.step.error && !result.step.response) {
    // A REFUSED step is not a failed replay, so the API answers 200 with no replay_error and writes
    // the reason onto the step instead. Saying "Sent alone" here - which is what this branch used to
    // do - asserts that a request went out when the scope rail, an unresolved {{af:NAME}} or an
    // unreadable boundary stopped it before anything was sent. The refusal is on step.error either
    // way, but a caller reads the note first, and a note that claims a send is worse than no note.
    result.sent = false;
    result.refused = result.step.error;
    result.note = 'NOTHING WAS SENT. This step was refused before it reached the wire and the ' +
      'reason is in `refused`. The usual causes are a host outside this target\'s scope, a ' +
      '{{af:NAME}} placeholder no earlier step has produced yet, and a boundary that could not be ' +
      'read (which refuses rather than defaulting to empty). Do not read this as the target ' +
      'answering nothing.';
  } else {
    result.sent = true;
    result.note = 'Sent alone: cookies and {{af:NAME}} values were seeded from the responses EARLIER ' +
      'steps had already recorded, not by re-sending them. A placeholder no earlier step has ' +
      'produced yet refuses this step rather than sending the literal text.';
  }
  return result;
}

// === Shared views ===============================================================================

// flowView is what get_flow and the seeds both return: the flow, its steps, and the three things
// that are only knowable server-side - the boundary those steps will be judged against, the dry run
// of what would be sent, and the caps a run would be held to.
function flowView(body, params, extra = {}) {
  const steps = Array.isArray(body.steps) ? body.steps : [];
  const rawLimit = resolveLimit(params.max_body_chars, RAW_PREVIEW, steps.length);
  const bodyLimit = resolveLimit(params.max_body_chars, BODY_PREVIEW, steps.length);
  const limit = clampLimit(params.max_results, STEP_LIST_DEFAULT);

  return {
    flow: flowRow(body.flow),
    ...extra,
    steps: limitResults(steps.map((s) => stepRow(s, rawLimit, bodyLimit, params)), limit),
    // One row per step, so it is held to the SAME limit. Capping the steps and not the dry run would
    // return a "this step would be refused" row for a step that is not in the response.
    preview: body.preview ? limitResults(body.preview, limit) : undefined,
    scope_boundary: body.scope_boundary,
    caps: body.caps,
    cycle_warnings: nonEmpty(body.cycle_warnings),
    branch_note: body.branch_note || undefined,
    note: 'Raw requests are CLIPPED here. Use get_step for one step in full.',
  };
}

function seedView(body, params) {
  return flowView(body, params, {
    created: true,
    next: 'Every step your include choice brought in is ENABLED, whatever verb it carries. Run ' +
      'preview before replay: it says which steps would go out and to which hosts, which would be ' +
      'refused by scope or an exclusion rule, and it sends nothing. Turn off any step you do not ' +
      'want sent with update_step enabled:false.',
  });
}

// Both ordering routes answer with the whole step list. Returned compact, because after a reorder
// what the caller needs is the new sequence, not the bytes they already have.
function stepsAfterOrdering(body, params) {
  const steps = Array.isArray(body.steps) ? body.steps : [];
  return {
    reordered: true,
    steps: limitResults(steps.map((s) => ({
      id: s.id,
      step_order: s.step_order,
      name: s.name,
      enabled: s.enabled,
      method: methodOf(s.raw_request),
      conditions: (s.conditions || []).length,
    })), clampLimit(params.max_results, STEP_LIST_DEFAULT)),
    note: 'A goto names a step by NAME or id, not by position, so reordering does not repoint one. ' +
          'It can still create or remove a loop: check cycle_warnings on the next get_flow.',
  };
}

// === Projections ================================================================================

function flowRow(f) {
  if (!f) return undefined;
  return {
    id: f.id,
    name: f.name,
    description: f.description || undefined,
    base_url: f.base_url || undefined,
    // How it was made. "Why does this flow have eleven steps I do not recognise" is a question the
    // caller will ask, and blank / detected_flow / captures is the answer.
    source: f.source,
    seeded_from_flow_id: f.seeded_from_flow_id || undefined,
    step_count: f.step_count,
    // Steps that would actually be sent. Lower than step_count only where somebody turned a step
    // off, which is the one control that decides this.
    enabled_count: f.enabled_count,
    created_at: f.created_at,
    updated_at: f.updated_at,
  };
}

// A step in a LIST: enough to identify it and to see its branching, with the bytes clipped.
function stepRow(s, rawLimit, bodyLimit, params) {
  const raw = typeof s.raw_request === 'string' ? s.raw_request : '';
  const row = {
    id: s.id,
    step_order: s.step_order,
    name: s.name,
    enabled: s.enabled,
    method: methodOf(raw),
    raw_request: clip(raw, rawLimit, { match: params.body_match }),
    raw_request_chars: raw.length,
    raw_request_clipped: raw.length > rawLimit,
    source_capture_id: s.source_capture_id || undefined,
    // Returned in full rather than counted: they are small, and they are the thing worth reasoning
    // about. A count would send the caller straight back for another read.
    conditions: nonEmpty(s.conditions),
    captures: (s.extractions || []).map((e) => e.name),
  };
  const response = responseOf(s, bodyLimit, params);
  if (response) row.response = response;
  if (s.error) row.error = s.error;
  // Filled by a replay only, and only for the LAST execution of this step; the rest are in the trace.
  if (s.skipped) row.skipped = true;
  if (nonEmpty(s.substituted)) row.substituted = s.substituted;
  if (nonEmpty(s.captured)) row.captured = s.captured;
  return row;
}

// A step on its OWN: the whole thing, because the multiplier is one.
function stepRecord(s, rawLimit, bodyLimit, params) {
  if (!s) return undefined;
  const row = stepRow(s, rawLimit, bodyLimit, params);
  row.request_flow_id = s.request_flow_id;
  row.extractions = nonEmpty(s.extractions);
  row.created_at = s.created_at;
  row.updated_at = s.updated_at;
  const response = responseOf(s, bodyLimit, params, true);
  if (response) row.response = response;
  return row;
}

// The stored response, which is the LAST one this step produced and may be from an earlier run.
// Absent rather than an object full of nulls when the step has never produced one, because those
// two read the same in JSON and only one of them means "this step has not run".
function responseOf(s, bodyLimit, params, withHeaders = false) {
  if (s.response_status === null || s.response_status === undefined) return undefined;
  const body = typeof s.response_body === 'string' ? s.response_body : '';
  const out = {
    status: s.response_status,
    time_ms: s.response_time_ms,
    size_bytes: body.length,
    body: clip(body, bodyLimit, { match: params.body_match }),
    body_clipped: body.length > bodyLimit,
  };
  if (withHeaders && s.response_headers) out.headers = s.response_headers;
  return out;
}

// traceView returns the run's explanation, bounded.
//
// When it truncates it keeps BOTH ENDS rather than the first N. The tail is where a capped or
// failed run says what it was doing when it stopped, and a trace clipped to its first forty entries
// throws away exactly the part the caller is reading it for.
function traceView(trace, limit) {
  const rows = Array.isArray(trace) ? trace.map(traceRow) : [];
  if (rows.length <= limit) {
    return { trace: rows, trace_returned: rows.length, trace_total: rows.length, trace_truncated: false };
  }
  const head = Math.ceil(limit / 2);
  const tail = limit - head;
  return {
    trace: [...rows.slice(0, head), ...rows.slice(rows.length - tail)],
    trace_returned: limit,
    trace_total: rows.length,
    trace_truncated: true,
    trace_note: `${rows.length - limit} execution(s) in the middle were dropped. The first ${head} ` +
      `and the last ${tail} are kept, because the end of a run is where it says why it ended. ` +
      'Raise max_results to see more.',
  };
}

function traceRow(t) {
  const row = {
    sequence: t.sequence,
    step: t.step_name,
    step_id: t.step_id,
    // Which time round for this step: attempt counts retries of the same visit, executions counts
    // every entry into the step, so a loop shows up in the second even when the first stays at 1.
    attempt: t.attempt,
    executions: t.executions,
    sent: t.sent,
    action: t.action,
  };
  if (t.status) row.status = t.status;
  if (t.size_bytes) row.size_bytes = t.size_bytes;
  if (t.time_ms) row.time_ms = t.time_ms;
  // -1 means no condition matched, which is not the same as having no conditions, so it is reported
  // rather than dropped as falsy.
  row.matched_condition = t.matched_condition;
  if (t.matched_when) row.matched_when = t.matched_when;
  if (t.action_target_name) row.action_target = t.action_target_name;
  if (t.message) row.message = t.message;
  if (t.skipped) { row.skipped = true; row.skip_reason = t.skip_reason; }
  if (t.refusal) row.refusal = t.refusal;
  if (t.error) row.error = t.error;
  if (nonEmpty(t.captured)) row.captured = t.captured;
  if (nonEmpty(t.substituted)) row.substituted = t.substituted;
  // A condition that could not be judged: a regex that would not compile, a numeric comparison
  // against text, a reference to a step that was turned off. Never dropped: a condition that
  // silently never matches looks exactly like one whose case never happened.
  if (nonEmpty(t.condition_problems)) row.condition_problems = t.condition_problems;
  if (nonEmpty(t.notes)) row.notes = t.notes;
  return row;
}

// capHit answers the first question about any run: did the flow end, or did a cap end it.
function capHit(run) {
  const reason = run.stop_reason;
  const known = STOP_REASONS[reason];
  if (!known) return { ended_on_a_cap: false };
  if (!known.cap) return { ended_on_a_cap: false, ended_because: known.means };

  const caps = run.caps || {};
  const spec = CAPS[known.cap] || {};
  return {
    ended_on_a_cap: true,
    ended_because: known.means,
    cap_hit: {
      cap: known.cap,
      value_enforced: caps[known.cap],
      what: spec.what,
      ...(spec.settable === false
        ? { raisable: false, where: 'the engagement config for this target, not a flow setting' }
        : { ceiling: spec.ceiling, raisable_to_ceiling: true }),
    },
    what_this_means: 'The run stopped on a limit, not on your flow. Nothing further was sent, so ' +
      'the trace is complete up to the stop and everything after it simply did not happen. Do not ' +
      'read this as the target behaving differently.',
  };
}

// === Helpers ====================================================================================

// The verb, read off the front of the bytes rather than by parsing, so it still works on a request
// that is mid-edit and would not currently parse. Same rule the server uses.
function methodOf(raw) {
  if (typeof raw !== 'string') return undefined;
  const line = raw.split(/[\r\n]/, 1)[0] || '';
  const verb = line.trim().split(' ')[0];
  return verb ? verb.toUpperCase() : undefined;
}

function nonEmpty(list) {
  return Array.isArray(list) && list.length > 0 ? list : undefined;
}

// There is no route that fetches one step, so it is found through the flow it belongs to. With
// flow_id that is one request; without it, one per flow on the target, which is why flow_id is
// worth passing and target_id is the fallback rather than the plan.
async function findStep(stepId, flowId, targetId) {
  if (flowId) {
    const body = await apiGet(`/request-flow-builder/flow/${flowId}`);
    const step = (body.steps || []).find((s) => s.id === stepId);
    if (step) return { step, flow: body.flow, body };
    return {
      error: 'that flow has no step with that id',
      step_id: stepId,
      flow_id: flowId,
      hint: 'The step may belong to a different flow. Pass target_id instead of flow_id to search ' +
            'every flow on the target.',
    };
  }
  if (!targetId) {
    return {
      error: 'get_step needs flow_id, or target_id to search with',
      hint: 'There is no route that fetches a step by its id alone, so the step has to be found ' +
            'through the flow that holds it.',
    };
  }
  const list = await apiGet(`/request-flow-builder/${targetId}/flows`);
  for (const f of (list.flows || [])) {
    const body = await apiGet(`/request-flow-builder/flow/${f.id}`);
    const step = (body.steps || []).find((s) => s.id === stepId);
    if (step) return { step, flow: body.flow, body };
  }
  return { error: 'no step with that id on any flow of this target', step_id: stepId };
}

// The api helpers flatten a failure into one message string. Pulling the status and the server's own
// error code back out is what lets a 409 be reported as "another run is in progress" rather than as
// the server being broken, and a 400 be reported as the specific rule that refused the save.
function apiError(err, params) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  let code = '';
  let message = (m ? m[2] : raw).trim();
  try {
    const parsed = JSON.parse(message);
    if (parsed && typeof parsed === 'object') {
      code = parsed.error || '';
      message = parsed.message || message;
    }
  } catch { /* a plain-text body, which is already the message */ }

  const out = { error: clip(message, 1200) };
  if (status !== undefined) out.http_status = status;
  if (code) out.error_code = code;

  const hint = hintFor(code, status, params);
  if (hint) out.hint = hint;
  return out;
}

function hintFor(code, status, params) {
  switch (code) {
    case 'condition_invalid':
      return 'The condition list was refused at SAVE time, which is the point: it would otherwise ' +
             'have silently never matched against a live target. Call action:"grammar" for the ' +
             'rules. The usual causes are a catch-all ("*" or "else") that is not last, a goto ' +
             'whose target names a step that does not exist yet or whose name is not unique, a ' +
             'target on an action other than goto, a regex that does not compile, and a numeric ' +
             'operator (> < >= <=) with a non-numeric value.';
    case 'extraction_invalid':
      return 'A capture rule cannot work. A name must be letters, digits and underscore; source ' +
             'must be body, header or cookie; header and cookie captures need source_key; and two ' +
             'captures on one step cannot share a name.';
    case 'raw_request_invalid':
      return 'The bytes do not parse as an HTTP request, or have no Host header. Expected a request ' +
             'line, then headers, then a BLANK LINE, then the body.';
    case 'invalid_order':
      return 'reorder_steps takes EVERY step id in the flow, each exactly once. Read the current ' +
             'ids from get_flow. A partial list is refused because it would move the steps you did ' +
             'not name.';
    case 'target_busy':
      return 'Only one flow run per scope target at a time, because every cap including the rate ' +
             'pacer is per-run and two runs each holding to the limit put double that on the ' +
             'programme. Wait for the other run, or read its result.';
    case 'step_disabled':
      return 'Somebody turned this step off, so nothing was sent. A turned-off step keeps its ' +
             'place in the sequence and is skipped. Turn it back on with update_step enabled:true ' +
             'if you meant to send it.';
    case 'flow_empty':
      return 'The flow has no steps. Add one with add_step, or seed the flow from a detected flow.';
    case 'rails_unreadable':
    case 'engagement_unreadable':
      return 'The run FAILED CLOSED and sent nothing. The out-of-scope host list, the exclusion ' +
             'rules or the engagement config could not be read, and an unreadable boundary is not ' +
             'an empty one. Fix the underlying error rather than retrying.';
    case 'invalid_flow_id':
    case 'flow_not_found':
      if (params && params.action === 'seed_from_detected_flow') {
        return 'detected_flow_id is "<session>~<tab>~<root capture>" from the detected flows list, ' +
               'not a UUID and not a built flow id. A detected flow is recomputed on every request, ' +
               'so an id can also be retired by re-segmentation as new captures arrive: reload the ' +
               'detected flows list and try the current id.';
      }
      return 'No built flow with that id. flow_id is the "id" from list_flows, create_flow or a seed.';
    case 'nothing_to_seed':
      return 'None of those requests could become steps. If you named capture_ids, check they are ' +
             'still in that flow and belong to this target.';
    case 'capture_not_found':
      return 'No manual-crawl capture with that id on this target. Capture ids come from the manual ' +
             'crawl corpus for this same scope target.';
    default:
      break;
  }
  if (status === 404) {
    return 'Nothing matched that id. flow_id addresses a built flow, step_id addresses a step ' +
           'inside one, and target_id addresses the scope target; a valid UUID of the wrong kind ' +
           'reports as not found rather than as the wrong kind.';
  }
  return undefined;
}

module.exports = { manageFlowBuilderSchema, manageFlowBuilder };
