const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');

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
const BODY_LIMIT = 2000;
function trimStep(step) {
  if (!step || typeof step !== 'object') return step;
  const body = step.response_body;
  if (typeof body === 'string' && body.length > BODY_LIMIT) {
    return { ...step, response_body: body.slice(0, BODY_LIMIT) + `\n…[truncated ${body.length - BODY_LIMIT} chars]` };
  }
  return step;
}
function trimSteps(steps) {
  return Array.isArray(steps) ? steps.map(trimStep) : steps;
}

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
});
async function getAuthFlowSteps(params) {
  return trimSteps(await apiGet(`/auth-flows/flow/${params.flow_id}/steps`));
}

// === Add a step (app sends the request and records the response) ===
const addAuthFlowStepSchema = z.object({
  flow_id: z.string().uuid().describe('The auth flow UUID.'),
  raw_request: z.string().describe('The full raw HTTP request: request line (e.g. "POST /login HTTP/1.1"), headers (including Host), a blank line, then the body. The app sends this to the target and records the live response.'),
  name: z.string().optional().describe('Optional label for the step, e.g. "Submit credentials".'),
  replay: z.boolean().optional().describe('Send the request and record the response now (default true). Set false to store the request without sending.'),
});
async function addAuthFlowStep(params) {
  return trimStep(await apiPost(`/auth-flows/flow/${params.flow_id}/steps`, {
    raw_request: params.raw_request,
    name: params.name || '',
    replay: params.replay === undefined ? true : params.replay,
  }));
}

// === Update a step ===
const updateAuthFlowStepSchema = z.object({
  step_id: z.string().uuid().describe('The step UUID.'),
  raw_request: z.string().optional(),
  name: z.string().optional(),
  step_order: z.number().int().min(1).optional().describe('Reorder the step within its flow.'),
});
async function updateAuthFlowStep(params) {
  const body = {};
  for (const k of ['raw_request', 'name', 'step_order']) {
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
};
