const { z } = require('zod');
const roles = require('../roles');
const session = require('../guidance/session');

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
  action: z.enum(['list', 'get', 'assign', 'release']).describe(
    'list: the role catalogue (id, pillar, primary step, mandate). ' +
    'get: one role in full (mandate, rule, tool boundaries, entry/exit, measured definition of done, ' +
    'handoffs); with no role_id returns the role currently assigned to this session or the index. ' +
    'assign: adopt a role for this session (advisory tool-scoping only, no hard gate). ' +
    'release: drop the session role.'),
  role_id: z.string().optional().describe('Kebab role id. Required for assign; optional for get.'),
  section: z.enum(['all', 'mandate', 'rule', 'boundaries', 'criteria', 'definition_of_done', 'handoff'])
    .optional().describe('get: read one section. Default all; a role over the read ceiling is refused with its section sizes.'),
  query: z.string().optional().describe('list: case-insensitive substring over id/title/pillar/mandate.'),
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
    case 'release':
      try {
        session.releaseRole(key);
      } catch (err) {
        return json(storeError(err));
      }
      return json({ released: true });
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

function json(o) {
  return { content: [{ type: 'text', text: JSON.stringify(o, null, 2) }] };
}

// Registered inline in index.js (like tools/context.js) so the server.tool override wraps the
// handler with teach(). Exporting only the schema and handler keeps one registration and one
// description, with no second copy here that could drift from it.
module.exports = { manageAgentRolesSchema, manageAgentRoles };
