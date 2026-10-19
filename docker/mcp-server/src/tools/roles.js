const { z } = require('zod');
const roles = require('../roles');
const session = require('../guidance/session');
// Call through the api module object (api.apiPost) rather than destructuring at load, so a test that
// reassigns api.apiPost after requiring this module (board.test.js simulates a 409 that way) exercises
// the real path. Behavior is identical to destructuring; only the binding time differs.
const api = require('../api');

// AGENT ROLES: a methodology-anchored catalogue of hunt roles (recon, mapping, scanning, bypass,
// analysis, support). Each role carries a mandate, advisory tool boundaries, entry and exit
// criteria, a measured definition of done, and handoffs, and is anchored to a methodology step.
//
// This tool folds the old get_role_guidance into action:get. It is named manage_agent_roles, NOT
// manage_roles, so it does not collide with the authz tool manage_role_access, which owns a
// different meaning of "role" entirely.
//
// Role tool-scoping is ADVISORY ONLY. There is no board and no hard gate. list and get read the
// in-repo role store; assign and release set session-scoped state through the session.js role API.
// The MCP client still sees every tool; the one authoritative gate remains the operator GOAL_GATE.
//
// Fail soft. The store is required at load time, but any read that throws returns {error,hint}
// rather than letting a tool call fail, mirroring tools/notes.js: guidance is advisory and must
// never take a tool down with it.

const manageAgentRolesSchema = z.object({
  action: z.enum(['list', 'get', 'assign', 'release', 'board', 'claim', 'handoff']).describe(
    'list: the role catalogue. get: one role in full (or the session-assigned role). ' +
    'assign: adopt a role for THIS SESSION only (advisory, in-memory, no board write). ' +
    'release: drop the session role; with target_id/assignment_id also release the board claim. ' +
    'board: read the cross-agent ROLE BOARD for a target (who holds what, with stale flags). ' +
    'claim: take a role on a target on the shared board (coordinates across agents) and set the ' +
    'session role too; fails soft with {error,held_by} if already held, unless force. ' +
    'handoff: mark a board claim handed off to another role.'),
  role_id: z.string().optional().describe('Kebab role id. Required for assign and claim; optional for get.'),
  section: z.enum(['all', 'mandate', 'rule', 'boundaries', 'criteria', 'definition_of_done', 'handoff'])
    .optional().describe('get: read one section. Default all; a role over the read ceiling is refused with its section sizes.'),
  query: z.string().optional().describe('list: case-insensitive substring over id/title/pillar/mandate.'),
  target_id: z.string().optional().describe(
    'The scope target UUID. Required for board and claim. On release, releasing WITH a target_id/' +
    'assignment_id also drops the board claim; WITHOUT either, release clears only the session role ' +
    '(back-compat).'),
  agent_label: z.string().optional().describe(
    'Stable, caller-supplied agent identity. REQUIRED for claim. It is what the board shows as the ' +
    'holder and what a conflict reports in held_by. Pick one stable string per agent and reuse it. ' +
    'It MUST be unique per logical agent: two agents sharing a label cannot corrupt the board (the ' +
    'one-active-holder guard is on target+role, not label), but held_by attribution becomes ambiguous ' +
    'and a handoff cannot tell them apart. When an orchestrator fans out many agents, give each a ' +
    'distinct label.'),
  force: z.boolean().optional().describe(
    'claim: take over a role already actively held, atomically releasing the current holder. Default ' +
    'false, which fails soft on a conflict instead of stealing the role.'),
  handoff_to_role: z.string().optional().describe('handoff: the role id this claim is being handed to.'),
  note: z.string().optional().describe('claim/handoff: a short free-text note stored on the assignment.'),
  assignment_id: z.string().optional().describe(
    'The role_assignment row id (the "id" from board/claim). Required for handoff and for a board ' +
    'release.'),
});

async function manageAgentRoles(params, extra) {
  const key = session.principalFor(extra, params);
  switch (params.action) {
    case 'list':
      try {
        return json(roles.list(params.query));
      } catch (err) {
        return json(storeError(err));
      }
    case 'get': {
      let id;
      try {
        id = params.role_id || session.assignedRole(key);
      } catch (err) {
        return json(storeError(err));
      }
      if (!id) {
        try {
          return json({ assigned: null, catalogue: roles.list() });
        } catch (err) {
          return json(storeError(err));
        }
      }
      try {
        return json({ assigned: session.assignedRole(key) === id, ...roles.get(id, params.section || 'all') });
      } catch (err) {
        return json(storeError(err));
      }
    }
    case 'assign': {
      if (!params.role_id || !roles.ALL[params.role_id]) {
        return json({
          error: 'unknown role_id',
          hint: 'assign needs a role_id that exists in the catalogue. Call action:list to see the ' +
            'ids, then pass one here. The id is the kebab string, not the title.',
          known_roles: Object.keys(roles.ALL).sort(),
        });
      }
      try {
        session.assignRole(key, params.role_id);
      } catch (err) {
        return json(storeError(err));
      }
      return json({
        assigned: params.role_id,
        advisory: 'Tool scoping is advisory only; the client still sees every tool.',
      });
    }
    case 'board': {
      if (!params.target_id) {
        return json({ error: 'board needs target_id', hint: 'Pass the scope target UUID to read its role board.' });
      }
      try {
        const body = await api.apiGet('/roles/' + params.target_id);
        const rows = Array.isArray(body && body.roles) ? body.roles : [];
        return json({ target_id: params.target_id, count: rows.length, roles: rows });
      } catch (err) {
        return json(apiError(err));
      }
    }

    case 'claim': {
      if (!params.target_id) {
        return json({ error: 'claim needs target_id', hint: 'Pass the scope target UUID to claim a role on it.' });
      }
      if (!params.role_id || !roles.ALL[params.role_id]) {
        return json({
          error: 'unknown role_id',
          hint: 'claim needs a role_id that exists in the catalogue. Call action:list to see the ids.',
          known_roles: Object.keys(roles.ALL).sort(),
        });
      }
      if (!params.agent_label || !params.agent_label.trim()) {
        return json({ error: 'claim needs agent_label', hint: 'agent_label is your stable agent identity; it is shown as the board holder.' });
      }
      let out;
      try {
        out = await api.apiPost('/roles', {
          scope_target_id: params.target_id,
          role_id: params.role_id,
          agent_label: params.agent_label,
          force: params.force === true,
        });
      } catch (err) {
        const { status, parsed } = parseApiError(err);
        if (status === 409) {
          // Soft fail: the role is actively held. Do NOT set the session role; tell the caller how
          // to proceed. The board never blocks a tool, so this is advice, not an error state.
          return json({
            error: (parsed && parsed.error) || 'role already held',
            held_by: parsed ? parsed.held_by : undefined,
            stale: parsed ? parsed.stale : undefined,
            hint: 'That role is actively held on this target. Pass force:true to take it over, or ' +
              'claim a different role. Call action:board to see who holds what.',
          });
        }
        return json(apiError(err));
      }
      // Claimed on the board; ALSO set the session role so solo behavior is unchanged.
      try {
        session.assignRole(key, params.role_id);
      } catch (err) {
        return json(storeError(err));
      }
      return json({
        claimed: true,
        assignment: out,
        advisory: 'Claim coordinates across agents but never blocks any tool. The one hard gate stays the operator GOAL_GATE.',
      });
    }

    case 'handoff': {
      if (!params.assignment_id) {
        return json({ error: 'handoff needs assignment_id', hint: 'the role_assignment id from board/claim' });
      }
      if (!params.handoff_to_role) {
        return json({ error: 'handoff needs handoff_to_role', hint: 'the role id you are handing this claim to' });
      }
      try {
        const out = await api.apiPatch('/roles/' + params.assignment_id, {
          status: 'handed_off',
          handoff_to_role: params.handoff_to_role,
          note: params.note,
        });
        return json({ handed_off: true, assignment: out });
      } catch (err) {
        return json(apiError(err));
      }
    }

    case 'release': {
      // Board release when an assignment_id is given; always clear the session role too. With neither
      // assignment_id nor target_id, this is the original session-only release (back-compat).
      let board_released = false;
      if (params.assignment_id) {
        try {
          await api.apiDelete('/roles/' + params.assignment_id);
          board_released = true;
        } catch (err) {
          // Still clear the session role; report the board failure without taking the tool down.
          try { session.releaseRole(key); } catch (e) { return json(storeError(e)); }
          return json({ released: true, session_cleared: true, board_error: apiError(err),
            hint: 'Session role cleared, but the board delete failed. assignment_id is the row id from board/claim.' });
        }
      }
      try { session.releaseRole(key); } catch (err) { return json(storeError(err)); }
      return json({ released: true, board_released });
    }
    default:
      return json({ error: `unknown action: ${params.action}` });
  }
}

// The role store is a static in-repo catalogue, so a throw here means a bug in the store or an
// unreadable section, not a backend outage. Report it as the wrong kind of request with a hint
// toward the catalogue, the way notes.js reports a bad id rather than a dead server.
function storeError(err) {
  return {
    error: `role store read failed: ${String(err && err.message ? err.message : err)}`,
    hint: 'Roles are read from the in-repo catalogue, not a backend. Call action:list for the valid ' +
      'ids, and action:get with a section (mandate, rule, boundaries, criteria, definition_of_done, ' +
      'handoff) if the whole role is over the read ceiling.',
  };
}

// Pull the HTTP status and JSON body back out of an api.js error string. api.js throws
// `API <VERB> <path> failed (<status>): <body>`, so a backend JSON error (e.g. the 409 conflict)
// arrives as a thrown Error, not a return value. This recovers it so claim can surface held_by.
function parseApiError(err) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  const bodyText = (m ? m[2] : raw).trim();
  let parsed = null;
  try { parsed = JSON.parse(bodyText); } catch (e) { /* plain-text body */ }
  return { status, bodyText, parsed };
}

function apiError(err) {
  const { status, bodyText, parsed } = parseApiError(err);
  const out = { error: (parsed && parsed.error) ? parsed.error : bodyText.slice(0, 240) };
  if (status !== undefined) out.http_status = status;
  return out;
}

function json(o) {
  return { content: [{ type: 'text', text: JSON.stringify(o, null, 2) }] };
}

// Registered inline in index.js (like tools/context.js) so the server.tool override wraps the
// handler with teach(). Exporting only the schema and handler keeps one registration and one
// description, with no second copy here that could drift from it.
module.exports = { manageAgentRolesSchema, manageAgentRoles };
