const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');

// The Authorization workflow over MCP: the four ways an application decides whether a caller may do
// a thing, modelled ahead of testing so that later work knows what SHOULD be refused. Client
// Identity Patterns (how the server works out who is asking), Policy Based (a permission granted or
// withheld one at a time), Role Based (roles against actions, one verdict per cell) and
// Discretionary (access a holder can pass on, up to their own level). Everything the four modals
// can do, create read update and delete on every object, including the destructive half. A model an
// agent can build but not correct is a model that goes stale, and a stale authorization model is
// worse than none: it tells the next test the wrong thing is expected.
//
// These proxy the Go API rather than reading Postgres, and that is not a preference here. The
// identity-pattern replay sends a real HTTP request at the target and persists the status, headers,
// body and timing it got back, which is not reachable from a SELECT. The read routes assemble the
// shapes the modals render, entity to permissions to instances to settings for policy and roles by
// actions by cells for RBAC, and a second implementation of those joins drifts from the first
// without anyone noticing. The writes matter for the same reason in the other direction: category,
// setting value and matrix value are CHECK constrained, and going through the handlers keeps one
// definition of what is valid instead of two.
//
// Size is the constraint on the way back. An identity pattern carries a whole raw request and the
// response body it produced, which is routinely a full HTML page or a JSON document, so nothing
// comes back whole by default: bodies are clipped, lists are clamped, and the verbose half of every
// row sits behind detail:"full".

const IDENTITY_CATEGORY = z.enum(['user_context_object', 'signed_token', 'parameter']);
const IDENTIFIER_LOCATION = z.enum(['', 'query', 'path', 'body', 'header', 'cookie',
                                    'token_claim', 'server_side']);
const POLICY_VALUE = z.enum(['allow', 'deny', 'unset']);
const MATRIX_VALUE = z.enum(['can_do', 'cannot_do', 'forbidden_to_do']);

// The ceiling on anything that came off the wire, applied per field. A replay must never echo more
// than this, whatever the target returned.
const BODY_LIMIT = 2000;
// What a single compact row shows of a body. Enough to read the account name a response echoed
// back, or the first field of a JSON error, which is what identifies the pattern being modelled.
const BODY_PREVIEW = 600;
// And what a row in a list shows. Smaller because the multiplier is different: fifty patterns at
// the single-row preview is thirty kilobytes of mostly page furniture, and a list is read to pick
// which pattern to open, not to read the evidence on all of them.
const LIST_PREVIEW = 200;

// How much of the identity the attacker controls, worst to best. Used to order the pattern list so
// the rows worth testing first arrive first, because the list is read to pick a target.
const IDOR_RANK = { parameter: 0, signed_token: 1, user_context_object: 2 };

// === Client identity patterns ==================================================================

const manageIdentityPatternsSchema = z.object({
  action: z.enum(['list', 'get', 'create', 'update', 'delete', 'replay'])
    .describe(
      'list: every identity pattern on a target, best IDOR targets first. ' +
      'get: one pattern with the request and the response it last recorded. ' +
      'create: record a pattern from one real request and its response. ' +
      'update: change any field. Editing raw_request does not re-send it. ' +
      'delete: drop the pattern. ' +
      'replay: send the stored raw_request again and overwrite the recorded response with what ' +
      'comes back. This puts real traffic on the target, and it is how you check whether the ' +
      'identity mechanism you modelled is still the one in front of you.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list and create. Required on get as well, because ' +
    'patterns are only readable per target: there is no route that fetches one by id.'),
  pattern_id: z.string().uuid().optional().describe(
    'The identity pattern UUID. Required for get, update, delete and replay.'),

  name: z.string().optional().describe(
    'Short label for the pattern, e.g. "GET /api/v2/invoices/{id} as tenant admin". Required on ' +
    'create.'),
  category: IDENTITY_CATEGORY.optional().describe(
    'How the server decides who is asking, and the most important field on the record because it ' +
    'is what says whether the endpoint is worth attacking at all. ' +
    'parameter: the id sits in a query, path or body parameter and the caller sets it directly. ' +
    'This is the BEST IDOR target, because testing it is just changing the value and re-sending. ' +
    'signed_token: the id lives inside a signed token, usually a JWT, so the signature has to be ' +
    'broken, stripped or confused before the id can be moved. Worth testing, but the bug has to ' +
    'be in the token handling first. ' +
    'user_context_object: the server validates the session and builds the identity itself, then ' +
    'passes it to downstream services. The attacker controls nothing in the request, so this is ' +
    'the WORST case for IDOR and the endpoint is better attacked another way. ' +
    'Filters the list, and is required on create.'),
  description: z.string().optional().describe(
    'What this request does and which account it was sent as. The context a later reader needs to ' +
    'know what the recorded response proves.'),
  raw_request: z.string().optional().describe(
    'The complete raw HTTP request that demonstrates the pattern. Request line, then headers ' +
    'including Host, then a blank line, then the body. This is sent verbatim on replay, so it is ' +
    'also where the session cookie or Authorization header that made it succeed lives.'),
  response_status: z.number().int().optional().describe(
    'The status code the request returned. Set it on create when you already have the response ' +
    'and do not want to fire the request again; replay overwrites it with the live one.'),
  response_headers: z.record(z.any()).optional().describe(
    'Response headers as an object. Same story as response_status: supply what you already ' +
    'captured, or let replay fill it in.'),
  response_body: z.string().optional().describe(
    'The response body. This is the evidence: it is what shows the endpoint returned the object ' +
    'belonging to the identifier, which is the thing an IDOR test later tries to move.'),
  response_time_ms: z.number().optional().describe(
    'How long the request took, in milliseconds. Worth keeping for the case where authorization ' +
    'is enforced by a slow downstream check and a refusal is measurably slower than a success.'),

  identifier_location: IDENTIFIER_LOCATION.optional().describe(
    'Where in the request the identifier sits, which is what a test needs in order to move it. ' +
    'query, path or body go with category "parameter". header and cookie are still caller ' +
    'controlled, just less obviously so. token_claim goes with "signed_token" and names the claim ' +
    'inside it. server_side goes with "user_context_object" and means the value is never on the ' +
    'wire at all. Empty string when it is not established yet.'),
  identifier_name: z.string().optional().describe(
    'What the identifier is called where it sits, e.g. account_id, sub, X-Tenant-Id.'),
  identifier_value: z.string().optional().describe(
    'The value observed in this request, e.g. the tenant UUID. The known-good value a test swaps ' +
    'for another account\'s.'),
  notes: z.string().optional().describe('Free text, anything the next reader needs.'),

  detail: z.enum(['compact', 'full']).optional().describe(
    'compact (default) is the category, identifier, response status and timing, plus a preview of ' +
    `the response body (${LIST_PREVIEW} chars in a list, ${BODY_PREVIEW} on a single pattern). ` +
    `full adds the raw request, the complete response headers, and up to ${BODY_LIMIT} chars of ` +
    'body.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function manageIdentityPatterns(params) {
  const full = params.detail === 'full';

  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      let rows = await fetchPatterns(params.target_id);
      if (params.category) rows = rows.filter((p) => p.category === params.category);

      // Ordered by how much of the identity the caller controls, not by creation time. The list is
      // read to decide what to attack next, and a parameter pattern is worth an hour of testing
      // where a user_context_object pattern is worth none.
      rows.sort((a, b) => (IDOR_RANK[a.category] ?? 9) - (IDOR_RANK[b.category] ?? 9));

      const projected = rows.map((p) => compactPattern(p, full, LIST_PREVIEW));
      return {
        by_category: countBy(rows, (p) => p.category),
        ...limitResults(projected, clampLimit(params.max_results)),
      };
    }

    case 'get': {
      if (!params.pattern_id) return { error: 'get needs pattern_id' };
      if (!params.target_id) {
        return { error: 'get needs target_id as well, patterns are only readable per target' };
      }
      const hit = (await fetchPatterns(params.target_id)).find((p) => p.id === params.pattern_id);
      if (!hit) return { error: 'no identity pattern with that id on this target' };
      return compactPattern(hit, full);
    }

    case 'create': {
      if (!params.target_id) return { error: 'create needs target_id' };
      if (!params.name) return { error: 'create needs name' };
      if (!params.category) return { error: 'create needs category' };
      const out = await apiPost(`/authz/identity-patterns/${params.target_id}`,
        patternBody(params, false));
      return clean({
        id: out.id,
        created: true,
        category: params.category,
        // Said on the call where the caller can still act on it. A parameter pattern is the one
        // worth queueing IDOR work against, and the category is exactly the judgement this record
        // exists to capture.
        note: params.category === 'parameter'
          ? 'Caller controlled identifier, so this is a direct IDOR candidate.'
          : (params.category === 'user_context_object'
            ? 'The identity is built server side, so there is nothing in the request to move. IDOR ' +
              'testing here needs a different way in.'
            : undefined),
      });
    }

    case 'update': {
      if (!params.pattern_id) return { error: 'update needs pattern_id' };
      const body = patternBody(params, true);
      if (!Object.keys(body).length) return { error: 'update needs at least one field to change' };
      const out = await apiPut(`/authz/identity-patterns/id/${params.pattern_id}`, body);
      return clean({
        updated: out.updated ?? true,
        pattern_id: params.pattern_id,
        // Editing the request does not send it, so the stored response still belongs to the old
        // one. Worth saying, because the record will otherwise look like the new request succeeded.
        note: body.raw_request !== undefined
          ? 'The recorded response is still the old request\'s. Replay this pattern to refresh it.'
          : undefined,
      });
    }

    case 'delete': {
      if (!params.pattern_id) return { error: 'delete needs pattern_id' };
      await apiDelete(`/authz/identity-patterns/id/${params.pattern_id}`);
      return { deleted: true, pattern_id: params.pattern_id };
    }

    case 'replay': {
      if (!params.pattern_id) return { error: 'replay needs pattern_id' };
      let out;
      try {
        out = await apiPost(`/authz/identity-patterns/id/${params.pattern_id}/replay`, {});
      } catch (err) {
        // A replay failing is a result, not a tool error. The host no longer resolving, the
        // session having expired or a WAF sitting in front of it are all answers to the question
        // that was asked, and a caller needs the reason rather than a stack trace.
        return { pattern_id: params.pattern_id, replayed: false, error: apiError(err) };
      }
      return {
        pattern_id: params.pattern_id,
        replayed: true,
        ...compactPattern(out, full),
      };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Policy based ==============================================================================

const managePolicyAccessSchema = z.object({
  action: z.enum(['list', 'create_entity', 'update_entity', 'delete_entity',
                  'add_permission', 'update_permission', 'delete_permission',
                  'add_instance', 'update_instance', 'delete_instance', 'set_settings'])
    .describe(
      'list: every policy entity on a target with its permissions and its instances, or one ' +
      'entity when entity_id is given. There is no route that fetches an entity on its own. ' +
      'create_entity / update_entity / delete_entity: the thing permissions are granted on, e.g. ' +
      '"Workspace member". Deleting an entity takes its permissions, instances and settings with ' +
      'it. ' +
      'add_permission / update_permission / delete_permission: one action the entity can be ' +
      'granted or refused. Enumerate all of them, including the ones you expect nobody to have, ' +
      'because a permission that is never modelled is never tested. Deleting a permission also ' +
      'removes its setting on every instance. ' +
      'add_instance / update_instance / delete_instance: a specific subject configured a specific ' +
      'way, e.g. "Bob, read only". ' +
      'set_settings: set the value of one or more permissions on one instance.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list and create_entity, and for set_settings when the ' +
    'settings are given by permission_key rather than permission_id.'),
  entity_id: z.string().uuid().optional().describe(
    'The policy entity UUID. Required for update_entity, delete_entity, add_permission and ' +
    'add_instance. Optional on list, where it narrows the result to that one entity.'),
  permission_id: z.string().uuid().optional().describe(
    'The permission UUID, for update_permission and delete_permission.'),
  instance_id: z.string().uuid().optional().describe(
    'The instance UUID, for update_instance, delete_instance and set_settings.'),

  name: z.string().optional().describe(
    'Entity, permission or instance name depending on the action. Required on create_entity and ' +
    'add_instance. On a permission it is the readable label, e.g. "Delete invoices", where key is ' +
    'the identifier.'),
  key: z.string().optional().describe(
    'add_permission / update_permission: the stable identifier for the permission, e.g. ' +
    'invoice.delete. Unique per entity, and what set_settings can address the permission by, so ' +
    'prefer the name the application itself uses over one you invent.'),
  subject: z.string().optional().describe(
    'add_instance / update_instance: who or what this instance is, e.g. the account, API key or ' +
    'service the configuration belongs to. This is the identity you will authenticate as when you ' +
    'test whether the configuration is really enforced.'),
  description: z.string().optional().describe('Free text on the entity, permission or instance.'),
  notes: z.string().optional().describe(
    'Free text on the entity or instance. On an instance this is the place to record how the ' +
    'configuration was applied, since reproducing it is half the work of retesting.'),
  sort_order: z.number().int().optional().describe(
    'add_permission / update_permission: display position. Lower sorts first.'),

  settings: z.array(z.object({
    permission_id: z.string().uuid().optional().describe(
      'The permission UUID. Either this or permission_key is required per row.'),
    permission_key: z.string().optional().describe(
      'The permission key instead of its UUID, resolved against the entity that owns this ' +
      'instance. Needs target_id on the call, since keys are only unique within an entity.'),
    value: POLICY_VALUE.describe(
      'allow: the instance has been granted this permission. ' +
      'deny: it has been explicitly revoked. ' +
      'unset: it was never granted in the first place. unset is deliberately not the same as ' +
      'deny, because an application that never granted a permission and one that revoked it can ' +
      'take different code paths, and that difference is exactly what a test goes looking for.'),
    notes: z.string().optional().describe(
      'Why this value, or what was observed when it was tested. Pass an empty string to clear an ' +
      'existing note.'),
  })).optional().describe(
    'set_settings: the permission values to write on this instance. Permissions left out keep ' +
    'whatever they already have, so a partial set is safe.'),

  detail: z.enum(['compact', 'full']).optional().describe(
    'compact (default) groups each instance\'s settings by value and lists the permissions that ' +
    'have no setting row at all. full returns one row per setting with its permission_id and ' +
    'notes, which is what you want before writing settings back.'),
  max_results: z.number().optional().describe('Maximum entities (default 50, max 1000)'),
});

async function managePolicyAccess(params) {
  const full = params.detail === 'full';

  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      let entities = await fetchPolicy(params.target_id);
      if (params.entity_id) entities = entities.filter((e) => e.id === params.entity_id);
      const projected = entities.map((e) => compactEntity(e, full));
      return limitResults(projected, clampLimit(params.max_results));
    }

    case 'create_entity': {
      if (!params.target_id) return { error: 'create_entity needs target_id' };
      if (!params.name) return { error: 'create_entity needs name' };
      const out = await apiPost(`/authz/policy/${params.target_id}`,
        pick(params, ['name', 'description', 'notes']));
      return { id: out.id, created: true };
    }

    case 'update_entity': {
      if (!params.entity_id) return { error: 'update_entity needs entity_id' };
      const body = pick(params, ['name', 'description', 'notes']);
      if (!Object.keys(body).length) {
        return { error: 'update_entity needs name, description or notes' };
      }
      const out = await apiPut(`/authz/policy/entity/${params.entity_id}`, body);
      return { updated: out.updated ?? true, entity_id: params.entity_id };
    }

    case 'delete_entity': {
      if (!params.entity_id) return { error: 'delete_entity needs entity_id' };
      await apiDelete(`/authz/policy/entity/${params.entity_id}`);
      return {
        deleted: true,
        entity_id: params.entity_id,
        note: 'Its permissions, instances and every setting on them went with it.',
      };
    }

    case 'add_permission': {
      if (!params.entity_id) return { error: 'add_permission needs entity_id' };
      if (!params.key) return { error: 'add_permission needs key' };
      const out = await apiPost(`/authz/policy/entity/${params.entity_id}/permissions`,
        pick(params, ['key', 'name', 'description', 'sort_order']));
      return {
        id: out.id,
        created: true,
        // Adding a permission does not configure it anywhere. Every existing instance is now
        // carrying an unmodelled permission, which reads as "nobody has it" when the truth is
        // "nobody has said".
        note: 'No instance has a value for this permission yet. Use set_settings to record one.',
      };
    }

    case 'update_permission': {
      if (!params.permission_id) return { error: 'update_permission needs permission_id' };
      const body = pick(params, ['key', 'name', 'description', 'sort_order']);
      if (!Object.keys(body).length) {
        return { error: 'update_permission needs key, name, description or sort_order' };
      }
      const out = await apiPut(`/authz/policy/permission/${params.permission_id}`, body);
      return { updated: out.updated ?? true, permission_id: params.permission_id };
    }

    case 'delete_permission': {
      if (!params.permission_id) return { error: 'delete_permission needs permission_id' };
      await apiDelete(`/authz/policy/permission/${params.permission_id}`);
      return {
        deleted: true,
        permission_id: params.permission_id,
        note: 'Its value on every instance went with it.',
      };
    }

    case 'add_instance': {
      if (!params.entity_id) return { error: 'add_instance needs entity_id' };
      if (!params.name) return { error: 'add_instance needs name' };
      const out = await apiPost(`/authz/policy/entity/${params.entity_id}/instances`,
        pick(params, ['name', 'subject', 'description', 'notes']));
      return {
        id: out.id,
        created: true,
        note: 'Every permission on the entity is unset on this instance until set_settings says ' +
              'otherwise.',
      };
    }

    case 'update_instance': {
      if (!params.instance_id) return { error: 'update_instance needs instance_id' };
      const body = pick(params, ['name', 'subject', 'description', 'notes']);
      if (!Object.keys(body).length) {
        return { error: 'update_instance needs name, subject, description or notes' };
      }
      const out = await apiPut(`/authz/policy/instance/${params.instance_id}`, body);
      return { updated: out.updated ?? true, instance_id: params.instance_id };
    }

    case 'delete_instance': {
      if (!params.instance_id) return { error: 'delete_instance needs instance_id' };
      await apiDelete(`/authz/policy/instance/${params.instance_id}`);
      return {
        deleted: true,
        instance_id: params.instance_id,
        note: 'Its settings went with it. The entity and its permissions are untouched.',
      };
    }

    case 'set_settings': {
      if (!params.instance_id) return { error: 'set_settings needs instance_id' };
      if (!params.settings?.length) return { error: 'set_settings needs settings' };

      // permission_key is what a human reasons about and what the listing shows, so it is accepted
      // here and resolved to ids. Keys are unique per entity, not per target, which is why the
      // lookup starts from the entity that owns this instance rather than from a flat map.
      let byKey = null;
      if (params.settings.some((s) => !s.permission_id)) {
        if (!params.target_id) {
          return {
            error: 'set_settings by permission_key needs target_id, so the keys can be resolved ' +
                   'against the entity that owns this instance',
          };
        }
        const entities = await fetchPolicy(params.target_id);
        const owner = entities.find(
          (e) => (e.instances || []).some((i) => i.id === params.instance_id));
        if (!owner) return { error: 'no policy instance with that id on this target' };
        byKey = new Map((owner.permissions || []).map((p) => [p.key, p.id]));
      }

      const cells = [];
      const unknown = [];
      for (const s of params.settings) {
        const id = s.permission_id || (byKey ? byKey.get(s.permission_key) : undefined);
        if (!id) {
          unknown.push(s.permission_key || '(neither permission_id nor permission_key)');
          continue;
        }
        // Built field by field rather than spread, so notes:"" is sent as a deliberate clear while
        // an omitted notes leaves whatever is already stored alone.
        const cell = { permission_id: id, value: s.value };
        if (s.notes !== undefined) cell.notes = s.notes;
        cells.push(cell);
      }
      if (unknown.length) {
        return {
          error: 'those permissions are not on the entity that owns this instance',
          unknown_permissions: unknown,
        };
      }

      const out = await apiPut(`/authz/policy/instance/${params.instance_id}/settings`,
        { settings: cells });
      return {
        updated: out.updated ?? cells.length,
        instance_id: params.instance_id,
        by_value: countBy(cells, (c) => c.value),
      };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Role based ================================================================================

const manageRoleAccessSchema = z.object({
  action: z.enum(['get', 'add_role', 'update_role', 'delete_role',
                  'add_action', 'update_action', 'delete_action', 'set_matrix'])
    .describe(
      'get: the roles, the actions and the matrix cell for every pair, with the forbidden cells ' +
      'pulled out separately because those are the ones that become findings. ' +
      'add_role / update_role / delete_role: the roles down one axis. Deleting a role removes its ' +
      'whole row of cells. ' +
      'add_action / update_action / delete_action: the actions across the other axis. Deleting an ' +
      'action removes its whole column. ' +
      'set_matrix: write one or more cells. Pairs left out keep what they have.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for get, add_role, add_action and set_matrix. Roles and ' +
    'actions are per target, and the matrix route is addressed by target as well.'),
  role_id: z.string().uuid().optional().describe(
    'The role UUID, for update_role and delete_role.'),
  action_id: z.string().uuid().optional().describe(
    'The RBAC action UUID, for update_action and delete_action. This is the action being ' +
    'governed, not the action parameter of this tool.'),

  name: z.string().optional().describe(
    'The role or action name depending on the tool action, e.g. "Billing admin" or "Delete ' +
    'another user\'s comment". Required on add_role and add_action.'),
  description: z.string().optional().describe(
    'Free text on the role or action. On an action this is worth filling in: "delete comment" and ' +
    '"delete anyone\'s comment" are different actions and a matrix cell cannot tell you which one ' +
    'was meant.'),
  sort_order: z.number().int().optional().describe('Display position. Lower sorts first.'),

  cells: z.array(z.object({
    role_id: z.string().uuid().optional().describe(
      'The role UUID. Either this or role_name is required per cell.'),
    role_name: z.string().optional().describe(
      'The role name instead of its UUID, resolved against the target. Case insensitive.'),
    action_id: z.string().uuid().optional().describe(
      'The action UUID. Either this or action_name is required per cell.'),
    action_name: z.string().optional().describe(
      'The action name instead of its UUID, resolved against the target. Case insensitive.'),
    value: MATRIX_VALUE.describe(
      'can_do: the role is granted this action. ' +
      'cannot_do: the role simply has not been given it. If it turns out to be reachable that is ' +
      'a gap in the configuration, and often a low-value one. ' +
      'forbidden_to_do: the role must never be able to perform this action under any ' +
      'circumstances, whatever it is configured with. This is the value the whole matrix exists ' +
      'for. A UI greys the button out identically for both, so nothing on screen tells them ' +
      'apart, and only a reachable forbidden_to_do is the finding: it is a violation of the ' +
      'security model rather than a missing grant. Mark every cell you would escalate on.'),
    notes: z.string().optional().describe(
      'Why this verdict, or what happened when it was tested. Pass an empty string to clear an ' +
      'existing note.'),
  })).optional().describe(
    'set_matrix: the cells to write. Pairs not listed are left alone, so a partial write is safe.'),

  detail: z.enum(['compact', 'full']).optional().describe(
    'compact (default) gives one row per role with the actions grouped by verdict, plus the ' +
    'pairs that have no cell yet. full adds the raw cells with their ids and notes, which is what ' +
    'you want before writing the matrix back.'),
  max_results: z.number().optional().describe('Maximum matrix rows (default 50, max 1000)'),
});

async function manageRoleAccess(params) {
  const full = params.detail === 'full';

  switch (params.action) {
    case 'get': {
      if (!params.target_id) return { error: 'get needs target_id' };
      const rbac = await fetchRbac(params.target_id);
      return projectMatrix(rbac, params, full);
    }

    case 'add_role': {
      if (!params.target_id) return { error: 'add_role needs target_id' };
      if (!params.name) return { error: 'add_role needs name' };
      const out = await apiPost(`/authz/rbac/${params.target_id}/roles`,
        pick(params, ['name', 'description', 'sort_order']));
      return {
        id: out.id,
        created: true,
        // A new role starts with an empty row, and an empty cell is not the same as cannot_do. Said
        // here so the row gets filled in while the model is being built rather than being read as
        // "this role can do nothing" later.
        note: 'Every action is uncelled for this role until set_matrix says otherwise.',
      };
    }

    case 'update_role': {
      if (!params.role_id) return { error: 'update_role needs role_id' };
      const body = pick(params, ['name', 'description', 'sort_order']);
      if (!Object.keys(body).length) {
        return { error: 'update_role needs name, description or sort_order' };
      }
      const out = await apiPut(`/authz/rbac/role/${params.role_id}`, body);
      return { updated: out.updated ?? true, role_id: params.role_id };
    }

    case 'delete_role': {
      if (!params.role_id) return { error: 'delete_role needs role_id' };
      await apiDelete(`/authz/rbac/role/${params.role_id}`);
      return { deleted: true, role_id: params.role_id, note: 'Its row of matrix cells went with it.' };
    }

    case 'add_action': {
      if (!params.target_id) return { error: 'add_action needs target_id' };
      if (!params.name) return { error: 'add_action needs name' };
      const out = await apiPost(`/authz/rbac/${params.target_id}/actions`,
        pick(params, ['name', 'description', 'sort_order']));
      return {
        id: out.id,
        created: true,
        note: 'No role has a verdict for this action yet. Use set_matrix, and mark the roles that ' +
              'must never reach it forbidden_to_do.',
      };
    }

    case 'update_action': {
      if (!params.action_id) return { error: 'update_action needs action_id' };
      const body = pick(params, ['name', 'description', 'sort_order']);
      if (!Object.keys(body).length) {
        return { error: 'update_action needs name, description or sort_order' };
      }
      const out = await apiPut(`/authz/rbac/action/${params.action_id}`, body);
      return { updated: out.updated ?? true, action_id: params.action_id };
    }

    case 'delete_action': {
      if (!params.action_id) return { error: 'delete_action needs action_id' };
      await apiDelete(`/authz/rbac/action/${params.action_id}`);
      return {
        deleted: true,
        action_id: params.action_id,
        note: 'Its column of matrix cells went with it.',
      };
    }

    case 'set_matrix': {
      if (!params.target_id) return { error: 'set_matrix needs target_id' };
      if (!params.cells?.length) return { error: 'set_matrix needs cells' };

      // Names are resolved to ids here for the same reason the policy tool resolves permission
      // keys: the listing a caller works from shows names, and making it round-trip through a GET
      // to build the id pairs by hand is work the tool can do once and get right.
      let roleByName = null;
      let actionByName = null;
      if (params.cells.some((c) => !c.role_id || !c.action_id)) {
        const rbac = await fetchRbac(params.target_id);
        roleByName = new Map((rbac.roles || []).map((r) => [String(r.name || '').toLowerCase(), r.id]));
        actionByName = new Map((rbac.actions || []).map((a) => [String(a.name || '').toLowerCase(), a.id]));
      }

      const cells = [];
      const unknownRoles = [];
      const unknownActions = [];
      for (const c of params.cells) {
        const roleID = c.role_id
          || (roleByName ? roleByName.get(String(c.role_name || '').toLowerCase()) : undefined);
        const actionID = c.action_id
          || (actionByName ? actionByName.get(String(c.action_name || '').toLowerCase()) : undefined);
        if (!roleID) unknownRoles.push(c.role_name || '(neither role_id nor role_name)');
        if (!actionID) unknownActions.push(c.action_name || '(neither action_id nor action_name)');
        if (!roleID || !actionID) continue;
        const cell = { role_id: roleID, action_id: actionID, value: c.value };
        if (c.notes !== undefined) cell.notes = c.notes;
        cells.push(cell);
      }
      // Nothing is written when any cell fails to resolve. A half-applied matrix is worse than an
      // unapplied one, because the rows that did land make it look like the write succeeded.
      if (unknownRoles.length || unknownActions.length) {
        return clean({
          error: 'those roles or actions are not on this target, so no cells were written',
          unknown_roles: unknownRoles,
          unknown_actions: unknownActions,
        });
      }

      const out = await apiPut(`/authz/rbac/${params.target_id}/matrix`, { cells });
      const byValue = countBy(cells, (c) => c.value);
      return clean({
        updated: out.updated ?? cells.length,
        by_value: byValue,
        // Repeated back because it is the count that decides what gets tested. Every forbidden cell
        // is a claim that has to be falsified before the model is worth anything.
        note: byValue.forbidden_to_do
          ? `${byValue.forbidden_to_do} cell(s) marked forbidden_to_do. Each one is a claim to ` +
            'attack: reaching any of them is a finding.'
          : undefined,
      });
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Discretionary access control ==============================================================

const manageDiscretionaryAccessSchema = z.object({
  action: z.enum(['list', 'create_object', 'update_object', 'delete_object',
                  'add_level', 'update_level', 'delete_level'])
    .describe(
      'list: every DAC object on a target with its levels in rank order, and for each level the ' +
      'levels it should be able to grant and the ones granting would be an escalation. ' +
      'create_object / update_object / delete_object: the shared thing whose access gets passed ' +
      'on, e.g. a Figma board, a document, a project. Deleting an object takes its levels with it. ' +
      'add_level / update_level / delete_level: the rungs on that object\'s ladder, e.g. viewer, ' +
      'user, admin.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list and create_object.'),
  object_id: z.string().uuid().optional().describe(
    'The DAC object UUID. Required for update_object, delete_object and add_level.'),
  level_id: z.string().uuid().optional().describe(
    'The level UUID, for update_level and delete_level.'),

  name: z.string().optional().describe(
    'The object or level name depending on the action, e.g. "Design board" or "admin". Required ' +
    'on create_object and add_level. Level names are unique per object.'),
  description: z.string().optional().describe('Free text on the object or level.'),
  notes: z.string().optional().describe(
    'Free text on the object, e.g. how a share is issued and what the invite request looks like.'),

  rank: z.number().int().optional().describe(
    'add_level / update_level: how much authority this level carries. Higher is more. Ranks are ' +
    'only compared with each other, so 1 for user and 2 for admin says everything that 10 and 20 ' +
    'would. Required on add_level.'),
  grant_ceiling_rank: z.number().int().optional().describe(
    'add_level / update_level: the highest rank this level may hand out. A level may grant any ' +
    'level at or below its ceiling, and nothing above it. On a Figma style board admin is rank 2 ' +
    'with ceiling 2, so an admin can invite another admin, while user is rank 1 with ceiling 1, so ' +
    'a user can only invite users. A ceiling below the level\'s own rank models a holder that ' +
    'cannot clone itself. A user who manages to grant a level above this ceiling is the privilege ' +
    'escalation the whole object exists to model, so set it to what the application claims and ' +
    'then go try to exceed it.'),
  can_grant: z.boolean().optional().describe(
    'add_level / update_level: whether this level can pass access on at all (default true). false ' +
    'is a level that holds access and cannot share it, which is a stronger claim than a ceiling ' +
    'of zero and is tested by trying to share anyway.'),

  max_results: z.number().optional().describe('Maximum objects (default 50, max 1000)'),
});

async function manageDiscretionaryAccess(params) {
  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      let objects = await fetchDac(params.target_id);
      if (params.object_id) objects = objects.filter((o) => o.id === params.object_id);
      const projected = objects.map(compactDacObject);
      return limitResults(projected, clampLimit(params.max_results));
    }

    case 'create_object': {
      if (!params.target_id) return { error: 'create_object needs target_id' };
      if (!params.name) return { error: 'create_object needs name' };
      const out = await apiPost(`/authz/dac/${params.target_id}`,
        pick(params, ['name', 'description', 'notes']));
      return { id: out.id, created: true };
    }

    case 'update_object': {
      if (!params.object_id) return { error: 'update_object needs object_id' };
      const body = pick(params, ['name', 'description', 'notes']);
      if (!Object.keys(body).length) {
        return { error: 'update_object needs name, description or notes' };
      }
      const out = await apiPut(`/authz/dac/object/${params.object_id}`, body);
      return { updated: out.updated ?? true, object_id: params.object_id };
    }

    case 'delete_object': {
      if (!params.object_id) return { error: 'delete_object needs object_id' };
      await apiDelete(`/authz/dac/object/${params.object_id}`);
      return { deleted: true, object_id: params.object_id, note: 'Its levels went with it.' };
    }

    case 'add_level': {
      if (!params.object_id) return { error: 'add_level needs object_id' };
      if (!params.name) return { error: 'add_level needs name' };
      if (params.rank === undefined) return { error: 'add_level needs rank' };
      const out = await apiPost(`/authz/dac/object/${params.object_id}/levels`,
        levelBody(params, false));
      return clean({
        id: out.id,
        created: true,
        // A level with no ceiling has no claim attached to it, so there is nothing to falsify. Said
        // on create, where it costs one more field rather than a re-read of the object later.
        note: params.grant_ceiling_rank === undefined
          ? 'No grant_ceiling_rank was set, so this level makes no claim about what it may hand ' +
            'out and there is nothing here to test.'
          : undefined,
      });
    }

    case 'update_level': {
      if (!params.level_id) return { error: 'update_level needs level_id' };
      const body = levelBody(params, true);
      if (!Object.keys(body).length) {
        return { error: 'update_level needs name, rank, grant_ceiling_rank, can_grant or description' };
      }
      const out = await apiPut(`/authz/dac/level/${params.level_id}`, body);
      return { updated: out.updated ?? true, level_id: params.level_id };
    }

    case 'delete_level': {
      if (!params.level_id) return { error: 'delete_level needs level_id' };
      await apiDelete(`/authz/dac/level/${params.level_id}`);
      return { deleted: true, level_id: params.level_id };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Summary ===================================================================================

const getAuthzSummarySchema = z.object({
  target_id: z.string().uuid().describe('The scope target UUID'),
});

// The counts behind the Authorization card, and the cheapest way to find out what has been modelled
// on a target before spending calls on the four listing tools.
async function getAuthzSummary(params) {
  const out = await apiGet(`/authz/summary/${params.target_id}`);
  const identity = out.identity_patterns || {};
  const policy = out.policy || {};
  const rbac = out.rbac || {};
  const dac = out.dac || {};

  const unmodelled = [];
  if (!identity.total) unmodelled.push('identity_patterns');
  if (!policy.entities) unmodelled.push('policy');
  if (!rbac.roles && !rbac.actions) unmodelled.push('rbac');
  if (!dac.objects) unmodelled.push('dac');

  return clean({
    identity_patterns: identity,
    policy,
    rbac,
    dac,
    // The two numbers worth surfacing on their own, because they are the ones that say what to
    // test next rather than how much has been written down.
    idor_candidates: identity.parameter,
    forbidden_cells: rbac.forbidden_cells,
    unmodelled,
    note: unmodelled.length
      ? `Nothing recorded yet for: ${unmodelled.join(', ')}.`
      : undefined,
  });
}

// === projections ===============================================================================

// bodyPreview is how much of the response body a compact row carries, so a list can be stingier
// than a single row without a second projection existing to drift from this one.
function compactPattern(p, full, bodyPreview = BODY_PREVIEW) {
  if (!p || typeof p !== 'object') return p;
  const headers = p.response_headers || {};
  return clean({
    id: p.id,
    name: p.name,
    // The Go handler returns this when the request could not be sent at all: an unparseable raw
    // request, a refused connection, a name that no longer resolves. Dropping it meant a failed
    // replay came back as replayed:true with no status, no body and no reason, and the only way to
    // find out why was to read the server source. A transport failure is a fact about the target
    // and belongs in the answer.
    replay_error: p.replay_error || undefined,
    // First field after the name on purpose. It is the judgement the record exists to hold, and
    // everything else is only worth reading once you know which case you are in.
    category: p.category,
    description: p.description,
    identifier_location: p.identifier_location,
    identifier_name: p.identifier_name,
    identifier_value: p.identifier_value,
    response_status: p.response_status === null ? undefined : p.response_status,
    response_time_ms: p.response_time_ms === null ? undefined : p.response_time_ms,
    content_type: full ? undefined : headerValue(headers, 'content-type'),
    response_body: clip(p.response_body, full ? BODY_LIMIT : bodyPreview),
    notes: p.notes,
    created_at: p.created_at,
    updated_at: p.updated_at,

    ...(full ? {
      raw_request: clip(p.raw_request, BODY_LIMIT),
      response_headers: headers,
    } : {}),
  });
}

function compactEntity(e, full) {
  if (!e || typeof e !== 'object') return e;
  const permissions = (e.permissions || []).slice()
    .sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));
  const keyByID = new Map(permissions.map((p) => [p.id, p.key || p.name || p.id]));

  return clean({
    id: e.id,
    name: e.name,
    description: e.description,
    notes: e.notes,
    // Always carries id and key, because those are what set_settings is addressed by. An entity
    // listing that cannot be acted on without a second call is a listing that costs two calls.
    permissions: permissions.map((p) => clean({
      id: p.id,
      key: p.key,
      name: p.name,
      description: full ? p.description : undefined,
      sort_order: full ? p.sort_order : undefined,
    })),
    instances: (e.instances || []).map((i) => compactInstance(i, permissions, keyByID, full)),
    created_at: full ? e.created_at : undefined,
    updated_at: full ? e.updated_at : undefined,
  });
}

function compactInstance(i, permissions, keyByID, full) {
  if (!i || typeof i !== 'object') return i;
  const settings = i.settings || [];

  if (full) {
    return clean({
      id: i.id,
      name: i.name,
      subject: i.subject,
      description: i.description,
      notes: i.notes,
      settings: settings.map((s) => clean({
        permission_id: s.permission_id,
        key: keyByID.get(s.permission_id),
        value: s.value,
        notes: s.notes,
        updated_at: s.updated_at,
      })),
    });
  }

  // Grouped by value rather than listed one per row. A dozen permissions across a dozen instances
  // is a hundred and forty-four rows of {permission_id, value} that say the same thing as four
  // short lists, and the lists are the shape a reader actually compares between instances.
  const grouped = { allow: [], deny: [], unset: [] };
  const configured = new Set();
  for (const s of settings) {
    const key = keyByID.get(s.permission_id) || s.permission_id;
    configured.add(s.permission_id);
    (grouped[s.value] || (grouped[s.value] = [])).push(key);
  }
  // A permission with no row at all behaves like unset but was never actually decided, and the
  // difference is the same one that makes unset worth keeping apart from deny: nobody has said.
  const not_configured = permissions
    .filter((p) => !configured.has(p.id))
    .map((p) => p.key || p.name || p.id);

  return clean({
    id: i.id,
    name: i.name,
    subject: i.subject,
    description: i.description,
    notes: i.notes,
    allow: grouped.allow,
    deny: grouped.deny,
    unset: grouped.unset,
    not_configured,
  });
}

function projectMatrix(rbac, params, full) {
  const roles = (rbac.roles || []).slice()
    .sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));
  const actions = (rbac.actions || []).slice()
    .sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));
  // The server sends a DENSE matrix: every role crossed with every action, with pairs nobody has
  // decided carrying cannot_do and a null updated_at. Treating presence as a verdict therefore
  // reported every pair as decided, so uncelled was always empty and coverage always read 100%,
  // which is precisely the "gap in the model becomes a claim about the application" this file
  // warns about below. A real verdict is one somebody wrote, which is what updated_at records.
  const allCells = rbac.matrix || rbac.cells || [];
  const cells = allCells.filter((c) => c.updated_at != null);

  const actionName = new Map(actions.map((a) => [a.id, a.name]));
  const roleName = new Map(roles.map((r) => [r.id, r.name]));
  const byRole = new Map();
  for (const c of cells) {
    if (!byRole.has(c.role_id)) byRole.set(c.role_id, new Map());
    byRole.get(c.role_id).set(c.action_id, c);
  }

  const rows = roles.map((r) => {
    const mine = byRole.get(r.id) || new Map();
    const grouped = { can_do: [], cannot_do: [], forbidden_to_do: [] };
    const uncelled = [];
    for (const a of actions) {
      const cell = mine.get(a.id);
      if (!cell) {
        // No cell is not a verdict. Reporting it as cannot_do would turn a gap in the model into a
        // claim about the application, and that claim would then never be tested.
        uncelled.push(a.name);
        continue;
      }
      (grouped[cell.value] || (grouped[cell.value] = [])).push(a.name);
    }
    return clean({
      role_id: r.id,
      role: r.name,
      description: full ? r.description : undefined,
      can_do: grouped.can_do,
      cannot_do: grouped.cannot_do,
      forbidden_to_do: grouped.forbidden_to_do,
      uncelled,
    });
  });

  // Pulled out of the grid on purpose. These are the cells that are worth an attack: every one is
  // an assertion that the application must never allow this, and a single reachable one is a
  // finding rather than a missing grant.
  const forbidden = cells
    .filter((c) => c.value === 'forbidden_to_do')
    .map((c) => clean({
      role_id: c.role_id,
      role: roleName.get(c.role_id),
      action_id: c.action_id,
      action: actionName.get(c.action_id),
      notes: c.notes,
    }));

  return clean({
    roles: roles.map((r) => clean({
      id: r.id,
      name: r.name,
      description: r.description,
      sort_order: full ? r.sort_order : undefined,
    })),
    actions: actions.map((a) => clean({
      id: a.id,
      name: a.name,
      description: a.description,
      sort_order: full ? a.sort_order : undefined,
    })),
    coverage: {
      cells_set: cells.length,
      cells_possible: roles.length * actions.length,
      // Named so an agent reading this knows the difference between a pair carrying a default and
      // a pair somebody actually ruled on.
      cells_undecided: Math.max(0, roles.length * actions.length - cells.length),
    },
    forbidden_to_do: forbidden,
    // Only under full, because these repeat what the rows above already say and exist for the one
    // case that needs them: reading the ids and notes back before a set_matrix write.
    cells: full
      ? cells.map((c) => clean({
        role_id: c.role_id,
        action_id: c.action_id,
        value: c.value,
        notes: c.notes,
        updated_at: c.updated_at,
      }))
      : undefined,
    ...limitResults(rows, clampLimit(params.max_results)),
  });
}

function compactDacObject(o) {
  if (!o || typeof o !== 'object') return o;
  // Ascending by rank, so the ladder reads from the least privileged rung up and a ceiling can be
  // checked against the levels printed after it.
  const levels = (o.levels || []).slice().sort((a, b) => (a.rank || 0) - (b.rank || 0));

  return clean({
    id: o.id,
    name: o.name,
    description: o.description,
    notes: o.notes,
    levels: levels.map((l) => {
      const ceiling = typeof l.grant_ceiling_rank === 'number' ? l.grant_ceiling_rank : undefined;
      const grants = ceiling === undefined || l.can_grant === false
        ? undefined
        : levels.filter((x) => (x.rank || 0) <= ceiling).map((x) => x.name);
      // What granting would be an escalation, worked out here rather than left to the caller. The
      // model is only worth having because this list is the test plan: authenticate as this level
      // and try to hand out each of these.
      const escalation = ceiling === undefined
        ? undefined
        : levels.filter((x) => (x.rank || 0) > ceiling).map((x) => x.name);

      return clean({
        id: l.id,
        name: l.name,
        rank: l.rank,
        grant_ceiling_rank: ceiling,
        // Never stripped, because false is the whole point of the field and an absent can_grant
        // would read as "yes".
        can_grant: l.can_grant === false ? false : true,
        description: l.description,
        may_grant: grants,
        escalation_targets: l.can_grant === false ? undefined : escalation,
      });
    }),
    created_at: o.created_at,
    updated_at: o.updated_at,
  });
}

// === fetchers ==================================================================================

async function fetchPatterns(targetID) {
  const rows = await apiGet(`/authz/identity-patterns/${targetID}`);
  return Array.isArray(rows) ? rows : (rows?.patterns || []);
}

async function fetchPolicy(targetID) {
  const rows = await apiGet(`/authz/policy/${targetID}`);
  return Array.isArray(rows) ? rows : (rows?.entities || []);
}

async function fetchRbac(targetID) {
  const out = await apiGet(`/authz/rbac/${targetID}`);
  return out && typeof out === 'object' ? out : { roles: [], actions: [], matrix: [] };
}

async function fetchDac(targetID) {
  const rows = await apiGet(`/authz/dac/${targetID}`);
  return Array.isArray(rows) ? rows : (rows?.objects || []);
}

// === helpers ===================================================================================

// Builds the identity pattern payload from whatever the caller supplied. On update, forUpdate keeps
// the body to the fields actually passed: sending the whole shape would push empty strings over
// columns the caller never mentioned and quietly wipe, say, the recorded response body on an edit
// that only meant to fix the name.
function patternBody(params, forUpdate) {
  const fields = ['name', 'category', 'description', 'raw_request', 'response_status',
                  'response_headers', 'response_body', 'response_time_ms', 'identifier_location',
                  'identifier_name', 'identifier_value', 'notes'];
  const body = {};
  for (const f of fields) {
    if (params[f] !== undefined) body[f] = params[f];
  }
  if (!forUpdate && body.raw_request === undefined) body.raw_request = '';
  return body;
}

function levelBody(params, forUpdate) {
  const body = pick(params, ['name', 'rank', 'grant_ceiling_rank', 'can_grant', 'description']);
  // The column defaults to TRUE, and a level created without saying otherwise is one that can pass
  // access on, which matches every application this models.
  if (!forUpdate && body.can_grant === undefined) body.can_grant = true;
  return body;
}

function pick(params, keys) {
  const out = {};
  for (const k of keys) {
    if (params[k] !== undefined) out[k] = params[k];
  }
  return out;
}

function countBy(rows, fn) {
  const out = {};
  for (const r of rows) {
    const k = fn(r) || 'unknown';
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

// Shallow on purpose, applied to the rows built above rather than to anything that came back from
// the API untouched. Most of these tables are optional free text (description, notes, and three
// identifier columns of which one is ever set), so an unstripped row is mostly empty strings. false
// and 0 survive: can_grant:false and rank:0 both mean something.
function clean(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined || v === '') continue;
    if (Array.isArray(v) && v.length === 0) continue;
    if (typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0) continue;
    out[k] = v;
  }
  return out;
}

function clip(text, limit) {
  if (typeof text !== 'string' || !text) return undefined;
  if (text.length <= limit) return text;
  return text.slice(0, limit) + `\n... [truncated, ${text.length - limit} chars remaining]`;
}

// Response headers come back as {name: [values]} from the Go replay engine and as {name: value}
// from anything that round-tripped through JSON, so both are handled rather than guessed at.
function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') return undefined;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
  if (!key) return undefined;
  const v = headers[key];
  return Array.isArray(v) ? v[0] : v;
}

// Strips the transport wrapper off a thrown API error. "API POST /authz/identity-patterns/id/<uuid>
// /replay failed (502): dial tcp: lookup failed" is plumbing around the one clause that matters.
function apiError(err) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  return clip((m ? m[2] : raw).trim(), BODY_PREVIEW);
}

module.exports = {
  manageIdentityPatternsSchema, manageIdentityPatterns,
  managePolicyAccessSchema, managePolicyAccess,
  manageRoleAccessSchema, manageRoleAccess,
  manageDiscretionaryAccessSchema, manageDiscretionaryAccess,
  getAuthzSummarySchema, getAuthzSummary,
};
