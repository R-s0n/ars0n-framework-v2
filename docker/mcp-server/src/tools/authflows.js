const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { clip, bodyOptions, DEFAULTS } = require('../utils/clip');
const { DETAIL_LEVELS, isFull, withoutHeavy, detailDescription } = require('../utils/detail');

// Auth Flows tools let an MCP client document & replay a target's HTTP authentication flows
// (register / login / mfa_otp / reset). Each flow is an ordered list of steps; a step holds a raw
// HTTP request that the app SENDS to the target and records the live response for (replay engine),
// carrying cookies/session between steps. These proxy the same Go endpoints the web UI uses.

// Five, matching the DB CHECK constraint, the Go validator, the recorder and the UI. magic_link
// was missing here, so an agent could not create a magic-link flow and could not update ANY flow
// imported from one: the client sends the category back on every update, so the zod enum rejected
// the request before it ever reached the API.
const CATEGORY = z.enum(['register', 'login', 'mfa_otp', 'magic_link', 'reset']);

// A recorded response body can be up to 2MB; trim it before returning to an MCP client so it
// doesn't blow up the model's context. The full body stays available in the web UI / DB.
// The budget is no longer a fixed 2000. A value worth reading can sit past it: pulling a CSRF token
// out of a captured login form was impossible because the token sat around character 3500 of a 7492
// character page. Reading ONE step, or asking for the window around a match, costs a fraction of the
// page and answers the question.
//
// raw_request is deliberately NOT clipped here. It round-trips into update_auth_flow_step, where the
// server replaces the stored request wholesale, so handing back a truncated one means a later write
// stores a truncated request and the replay engine fires it at the target as if it were real.
function trimStep(step, opts) {
  if (!step || typeof step !== 'object') return step;
  const body = step.response_body;
  if (typeof body !== 'string') return step;
  return { ...step, response_body: clip(body, (opts && opts.limit) || DEFAULTS.record, opts || {}) };
}
function trimSteps(steps, opts) {
  return Array.isArray(steps) ? steps.map((s) => trimStep(s, opts)) : steps;
}

// The per-step capture rules, shared by add_auth_flow_step and update_auth_flow_step so the two can
// never drift. A step captures values out of its OWN response for a later step to use as {{af:NAME}},
// which is what makes a per-request CSRF token work.
const extractionSchema = z.array(z.object({
  name: z.string(),
  source: z.enum(['body', 'header', 'cookie']),
  source_key: z.string().optional(),
  pattern: z.string().optional(),
  decode_as: z.enum(['none', 'html', 'url']).optional(),
  optional: z.boolean().optional(),
}));

// What the user must supply for this step when the flow is REFRESHED. Shared by add and update.
const interactionSchema = z.object({
  kind: z.enum(['none', 'input', 'totp_auto', 'action']),
  var_name: z.string().optional(),
  input_kind: z.enum(['otp', 'totp', 'password', 'text', 'url', 'token']).optional(),
  prompt: z.string().optional(),
  optional: z.boolean().optional(),
  totp_secret: z.string().optional(),
  action_kind: z.enum(['approve', 'magic_link']).optional(),
});

const INTERACTION_DESC = "What the user must supply for this step when the flow is REFRESHED. Omit, " +
  "or {kind:'none'}, means fully automatable. {kind:'input', var_name:'mfa_code', input_kind:'otp', " +
  "prompt:'Enter the 6-digit code'} makes refresh PAUSE at this step and ask the operator for the " +
  "value, substituted into the request as {{af:var_name}} - this is how an MFA/OTP login refreshes " +
  "instead of failing (answer the pause with check_session_tokens action:'provide_refresh_input'). " +
  "{kind:'totp_auto', var_name:'mfa_code', totp_secret:'<base32>'} instead GENERATES the TOTP code " +
  "from the operator's stored authenticator secret at refresh time, so an authenticator-MFA login " +
  "refreshes with NO pause. {kind:'action', action_kind:'approve', prompt:'Approve the push on your " +
  "phone'} pauses for a push/2FA approval (answer with provide_refresh_input, no value needed). " +
  "{kind:'action', action_kind:'magic_link', var_name:'link_url', prompt:'Click the emailed link and " +
  "paste the URL you land on'} pauses for a magic link (answer with the URL, used as {{af:var_name}}).";

const EXTRACTION_DESC = "Values to capture out of THIS step's response for later steps to refer to " +
  "as {{af:NAME}}. This is what makes a per-request CSRF token work: step 1 captures the token, " +
  "step 2 uses it. pattern is a Go RE2 regex whose capture group 1 is the value, e.g. " +
  "name=\"csrf\" value=\"([^\"]+)\". A required capture that does not match stops every later step " +
  "that needs it, rather than sending a blank token.";

// === List flows for a target ===
const listAuthFlowsSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID (use list_targets to resolve a name).'),
  category: CATEGORY.optional().describe('Optional: only flows in this category.'),
});
async function listAuthFlows(params) {
  const qs = params.category ? `?category=${encodeURIComponent(params.category)}` : '';
  return apiGet(`/auth-flows/${params.target_id}${qs}`);
}

// === Create a flow ===
const createAuthFlowSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID.'),
  category: CATEGORY.describe('Which auth flow this documents.'),
  name: z.string().describe('A short name for the flow, e.g. "Password login".'),
  auth_type: z.string().optional().describe('Optional auth mechanism, e.g. password, oauth, oidc, saml, passkey, jwt, api_key, mfa, biometric.'),
  base_url: z.string().optional().describe('Optional scheme://host[:port] the steps replay against. If omitted, derived from each step request Host header (https).'),
  description: z.string().optional(),
});
async function createAuthFlow(params) {
  return apiPost(`/auth-flows/${params.target_id}`, {
    category: params.category,
    name: params.name,
    auth_type: params.auth_type || '',
    base_url: params.base_url || '',
    description: params.description || '',
  });
}

// === Update a flow ===
const updateAuthFlowSchema = z.object({
  flow_id: z.string().uuid().describe('The auth flow UUID.'),
  name: z.string().optional(),
  description: z.string().optional(),
  auth_type: z.string().optional(),
  base_url: z.string().optional(),
  category: CATEGORY.optional(),
});
async function updateAuthFlow(params) {
  const body = {};
  for (const k of ['name', 'description', 'auth_type', 'base_url', 'category']) {
    if (params[k] !== undefined) body[k] = params[k];
  }
  return apiPut(`/auth-flows/flow/${params.flow_id}`, body);
}

// === Delete a flow ===
const deleteAuthFlowSchema = z.object({
  flow_id: z.string().uuid().describe('The auth flow UUID to delete (cascades its steps).'),
});
async function deleteAuthFlow(params) {
  await apiDelete(`/auth-flows/flow/${params.flow_id}`);
  return { status: 'deleted', flow_id: params.flow_id };
}

// === List a flow's steps (with recorded responses) ===
const getAuthFlowStepsSchema = z.object({
  flow_id: z.string().uuid().describe('The auth flow UUID.'),
  step_id: z.string().uuid().optional().describe(
    'Read only this step, at a much larger body budget. With one row there is no row multiplier, ' +
    'so this is how you read a value out of a large recorded response.'),
  max_body_chars: z.number().int().positive().optional().describe(
    'Raise the per-body character budget for this call. Bounded at 200000, and divided by the row ' +
    'count so raising it on a long flow degrades instead of exploding.'),
  body_match: z.string().optional().describe(
    'Return the window of the body AROUND the first case-insensitive occurrence of this string ' +
    'rather than the first N characters. The cheap way to pull one value out of a large page.'),
  body_match_window: z.number().int().positive().optional().describe(
    'Characters either side of a body_match hit. Default 400.'),
  detail: z.enum(DETAIL_LEVELS).optional().describe(detailDescription(
    'omits raw_request from a MULTI-step listing and reports raw_request_chars instead. Reading ' +
    'one step with step_id always includes it.',
    'includes raw_request on every step. A login flow of six steps is six whole HTTP requests, ' +
    'which is what put listings like this past the MCP output cap.')),
});
async function getAuthFlowSteps(params) {
  let steps = await apiGet(`/auth-flows/flow/${params.flow_id}/steps`);
  steps = Array.isArray(steps) ? steps : [];
  if (params.step_id) steps = steps.filter((s) => s.id === params.step_id);
  const single = Boolean(params.step_id);
  const trimmed = trimSteps(steps, bodyOptions(
    params,
    single ? DEFAULTS.single : DEFAULTS.record,
    single ? 1 : steps.length,
  ));

  // raw_request is OMITTED here, never clipped. The distinction matters: this shape round-trips into
  // update_auth_flow_step, which replaces the stored request wholesale, so a truncated raw_request
  // handed back becomes a truncated request the replay engine later fires at the target as if it
  // were real. An absent field cannot be written back by accident; a truncated one can.
  if (single || isFull(params)) return trimmed;
  return trimmed.map((s) => withoutHeavy(s, ['raw_request']));
}

// === Add a step (app sends the request and records the response) ===
const addAuthFlowStepSchema = z.object({
  flow_id: z.string().uuid().describe('The auth flow UUID.'),
  raw_request: z.string().describe('The full raw HTTP request: request line (e.g. "POST /login HTTP/1.1"), headers (including Host), a blank line, then the body. The app sends this to the target and records the live response. Placeholders of the form {{af:NAME}} are replaced with values an EARLIER step captured, and Content-Length is recomputed afterwards; a step with no placeholders is sent byte for byte as stored.'),
  name: z.string().optional().describe('Optional label for the step, e.g. "Submit credentials".'),
  replay: z.boolean().optional().describe('Send the request and record the response now (default true). Set false to store the request without sending.'),
  extractions: extractionSchema.optional().describe(EXTRACTION_DESC),
  interaction: interactionSchema.optional().describe(INTERACTION_DESC),
});
async function addAuthFlowStep(params) {
  const body = {
    raw_request: params.raw_request,
    name: params.name || '',
    replay: params.replay === undefined ? true : params.replay,
    extractions: params.extractions || [],
  };
  if (params.interaction !== undefined) body.interaction = params.interaction;
  return trimStep(await apiPost(`/auth-flows/flow/${params.flow_id}/steps`, body));
}

// === Update a step ===
const updateAuthFlowStepSchema = z.object({
  step_id: z.string().uuid().describe('The step UUID.'),
  raw_request: z.string().optional(),
  name: z.string().optional(),
  step_order: z.number().int().min(1).optional().describe('Reorder the step within its flow.'),
  extractions: extractionSchema.optional().describe(
    EXTRACTION_DESC + ' Omit to leave the existing rules untouched; pass [] to clear them. Without ' +
    'this a wrong capture rule could be created but never edited or removed via this tool.'),
  interaction: interactionSchema.optional().describe(
    INTERACTION_DESC + ' Omit to leave it alone; {kind:"none"} clears it.'),
});
async function updateAuthFlowStep(params) {
  const body = {};
  for (const k of ['raw_request', 'name', 'step_order', 'extractions', 'interaction']) {
    if (params[k] !== undefined) body[k] = params[k];
  }
  return trimStep(await apiPut(`/auth-flows/steps/${params.step_id}`, body));
}

// === Delete a step ===
const deleteAuthFlowStepSchema = z.object({
  step_id: z.string().uuid().describe('The step UUID to delete.'),
});
async function deleteAuthFlowStep(params) {
  await apiDelete(`/auth-flows/steps/${params.step_id}`);
  return { status: 'deleted', step_id: params.step_id };
}

// === Replay a single step (re-send, seeding cookies from earlier steps) ===
const replayAuthFlowStepSchema = z.object({
  step_id: z.string().uuid().describe('The step UUID to re-send and re-record.'),
});
async function replayAuthFlowStep(params) {
  return trimStep(await apiPost(`/auth-flows/steps/${params.step_id}/replay`, {}));
}

// === Replay a whole flow in order (shared cookie jar across steps) ===
const replayAuthFlowSchema = z.object({
  flow_id: z.string().uuid().describe('The auth flow UUID to run end-to-end.'),
});
async function replayAuthFlow(params) {
  return trimSteps(await apiPost(`/auth-flows/flow/${params.flow_id}/replay`, {}));
}

// === Classify how a flow can be refreshed ===
// Answers the one question you need before turning auto_refresh on for a token: can this flow renew
// itself headlessly (kind "replay"), does it need a value from the operator each run (kind
// "interactive": an MFA/OTP or push step), or can it not be replayed at all (kind "browser_only": it
// crosses a federated identity provider, hits a bot challenge, or carries a single-use OAuth code)?
// Also names the provider it crosses when it recognises one, so the label is precise.
const classifyAuthFlowRefreshSchema = z.object({
  flow_id: z.string().uuid().describe('The auth flow UUID to classify.'),
});
async function classifyAuthFlowRefresh(params) {
  return apiGet(`/auth-flows/flow/${params.flow_id}/refresh-classification`);
}

// === List capture candidates that look like part of an auth exchange ===
// The manual crawl already recorded the login/register/MFA/reset requests with their real headers,
// cookies and CSRF values. This surfaces the ones that look like auth so they can be imported as a
// flow with import_auth_flow_from_captures, instead of transcribing raw requests by hand.
const listAuthFlowCandidatesSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID whose recorded requests to scan.'),
});
async function listAuthFlowCandidates(params) {
  return apiGet(`/manual-crawl/captures/target/${params.target_id}/auth-candidates`);
}

// === Build a flow directly from recorded captures ===
// The AI-native equivalent of the UI's "Import from Manual Crawl". Ordering is by capture timestamp
// on the server, so the sequence matches what happened rather than the order the ids were listed.
const importAuthFlowFromCapturesSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID.'),
  category: CATEGORY.describe('Which auth flow these captures document.'),
  capture_ids: z.array(z.string().uuid()).min(1).describe(
    'The manual_crawl capture ids to turn into steps, from list_auth_flow_candidates.'),
  name: z.string().optional().describe('Optional name for the created flow.'),
});
async function importAuthFlowFromCaptures(params) {
  return apiPost(`/auth-flows/${params.target_id}/from-captures`, {
    category: params.category,
    name: params.name || '',
    capture_ids: params.capture_ids,
  });
}

// === Adopt a detected refresh request as a headless refresh flow ===
// Turns the app's own silent-refresh request (a capture whose oauth_role is "refresh_request" in
// list_auth_flow_candidates) into a flow_purpose='refresh' flow: it rewrites the captured refresh token
// to the {{token:refresh_token}} placeholder so replay spends the CURRENT stored refresh token, and links
// the flow to the anchor session token as its refresh_flow_id. From then on refreshing that token replays
// this flow (a headless OAuth refresh grant) instead of the interactive login. This is the OAuth answer
// to "renew the session without logging in again".
const buildRefreshFlowSchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID.'),
  capture_ids: z.array(z.string().uuid()).min(1).describe(
    'The manual_crawl capture id(s) of the refresh request (oauth_role "refresh_request" in ' +
    'list_auth_flow_candidates). Must include the request that carries grant_type=refresh_token.'),
  anchor_token_id: z.string().uuid().optional().describe(
    'The session token (the access-token credential) to link this refresh flow to. When given, its ' +
    'refresh_flow_id is set so refresh uses the new flow. Omit to build the flow without linking.'),
  name: z.string().optional().describe('Optional name for the refresh flow.'),
  refresh_strategy: z.string().optional().describe('Default oauth_refresh_grant.'),
});
async function buildRefreshFlow(params) {
  return apiPost(`/auth-flows/${params.target_id}/refresh-from-captures`, {
    capture_ids: params.capture_ids,
    anchor_token_id: params.anchor_token_id || '',
    name: params.name || '',
    refresh_strategy: params.refresh_strategy || '',
  });
}

module.exports = {
  listAuthFlowsSchema, listAuthFlows,
  createAuthFlowSchema, createAuthFlow,
  updateAuthFlowSchema, updateAuthFlow,
  deleteAuthFlowSchema, deleteAuthFlow,
  getAuthFlowStepsSchema, getAuthFlowSteps,
  addAuthFlowStepSchema, addAuthFlowStep,
  updateAuthFlowStepSchema, updateAuthFlowStep,
  deleteAuthFlowStepSchema, deleteAuthFlowStep,
  replayAuthFlowStepSchema, replayAuthFlowStep,
  replayAuthFlowSchema, replayAuthFlow,
  classifyAuthFlowRefreshSchema, classifyAuthFlowRefresh,
  listAuthFlowCandidatesSchema, listAuthFlowCandidates,
  importAuthFlowFromCapturesSchema, importAuthFlowFromCaptures,
  buildRefreshFlowSchema, buildRefreshFlow,
};
