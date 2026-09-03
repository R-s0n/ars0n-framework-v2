const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');

// The threat modelling collections over MCP: the STRIDE threat model itself, and the four note
// collections the model is built out of. Application questions are what you worked out about how
// the application behaves, mechanisms are the actions it lets a user perform, notable objects are
// the data structures those actions move around, and security control notes are what stands in the
// way of an attack. A threat then names a mechanism, a target object and the controls it runs into,
// by name, which is why all five sit behind one pair of tools: a threat pointing at a mechanism
// nobody documented is a threat nobody can act on.
//
// Full CRUD on all five, not just the read. The rule for this project is that anything a human can
// do in a modal the agent can do over MCP, and a threat model an agent can write but never correct
// or retract is a document that still needs a human to finish it, which defeats the point of having
// the tools.
//
// These proxy the Go API rather than reading Postgres. The handlers hold the required-field checks
// and the id generation, steps and security_controls are stored as JSON text which the API decodes
// into strings rather than into lists, and a second implementation of any of that drifts from the
// first without anyone noticing.
//
// Two things about these routes will bite a caller who does not already know them, so both are
// repeated in the field descriptions. First, the addressing is asymmetric: list and create are
// addressed by the scope target, update and delete by the row's own id. Passing a scope target id
// where a row id belongs does not come back as "wrong kind of id", it comes back as the row not
// existing. Second, every PUT here replaces the row's editable columns wholesale, so a partial
// update blanks whatever it did not mention. Both tools read the current row back and merge your
// changes over it rather than letting that happen, and that read is the one reason an update ever
// wants the scope target id as well.

const STRIDE = z.enum(['spoofing', 'tampering', 'repudiation', 'information_disclosure',
                       'denial_of_service', 'elevation_of_privilege']);

// The ceiling on any single stored field, applied per column. Object structures get pasted in whole
// and an impact assessment is three paragraphs of prose, so none of this is hypothetical.
const BODY_LIMIT = 2000;
// What a compact row shows of a long field. Enough to tell two answers apart and to recognise the
// one you are looking for before spending a full read on it.
const BODY_PREVIEW = 600;

// === The STRIDE threat model ===================================================================

// Every column the modal writes, in the order the Go handler lists them. Used to work out whether
// an update is partial, because the PUT sets all nine unconditionally.
// Generated from client/src/data/attacks.js by scripts/gen-attack-catalog.mjs. Imported rather than
// duplicated so the ids this tool accepts cannot drift from the ones the UI dropdown offers.
const ATTACK_CATALOG = require('../data/attackCatalog.json').attacks;
const ATTACK_IDS = ATTACK_CATALOG.map((a) => a.id);
const ATTACKS_BY_CATEGORY = ATTACK_CATALOG.reduce((acc, a) => {
  for (const c of a.categories) (acc[c] ||= []).push(a.id);
  return acc;
}, {});

const THREAT_FIELDS = ['category', 'url', 'mechanism', 'target_object', 'steps',
                       'security_controls', 'impact_customer_data', 'impact_attacker_scope',
                       'impact_company_reputation', 'one_sentence', 'summary', 'severity', 'authenticated', 'attack_id', 'attack_custom_name', 'test_status'];

// Whether the threat has actually been run against the target yet. The Go handler preserves this
// column when the PUT omits it, so an update that only edits prose cannot silently reset a threat
// that was already tested back to untested.
const TEST_STATUS = z.enum(['untested', 'validated', 'rejected']);
const SEVERITY = z.enum(['critical', 'high', 'moderate', 'low', 'informational']);

const manageThreatModelSchema = z.object({
  action: z.enum(['list', 'create', 'update', 'delete']).describe(
    'list: every threat documented on a target, with a count per STRIDE category so you can see ' +
    'which parts of the model are empty before reading any of it. ' +
    'create: add one threat under one STRIDE category. ' +
    'update: change a threat. The route replaces every column, so pass target_id as well and the ' +
    'current row is read back and merged underneath whatever you supply. ' +
    'delete: remove one threat. There is no soft delete and no restore here, it is gone.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list and create, which are addressed by scope target. ' +
    'Also wanted on update, where it is what lets the current row be read back and merged: threats ' +
    'are only readable per target, there is no route that fetches one by its own id.'),
  threat_id: z.string().uuid().optional().describe(
    'The threat\'s own UUID, as returned in "id" by list and create. Required for update and ' +
    'delete, which are addressed by the row rather than by the scope target. Passing a scope ' +
    'target id here fails as though the threat did not exist, so check which one you have.'),

  category: STRIDE.optional().describe(
    'Which STRIDE category the threat belongs to. Required on create, and on list it narrows to ' +
    'that one category. Spoofing is impersonation, tampering is unauthorised modification, ' +
    'repudiation is acting without an audit trail, information_disclosure is exposure of data, ' +
    'denial_of_service is denying use to legitimate users, and elevation_of_privilege is gaining ' +
    'permissions you were not granted.'),
  url: z.string().optional().describe(
    'Where this threat would be exploited, e.g. https://app.example.com/api/v1/users/123. ' +
    'Required on create. This is the field that ties the model back to the endpoint corpus.'),
  one_sentence: z.string().optional().describe(
    'ONE sentence naming who does what to which object and what they get. This is the headline a ' +
    'reader sees before anything else, so it must stand alone without the steps below it.'),
  summary: z.string().optional().describe(
    'A short paragraph expanding the one-sentence description: the mechanism, the precondition an ' +
    'attacker needs, and why it matters on this target. Prose, not a numbered procedure; the steps ' +
    'field already holds the procedure.'),
  attack_id: z.enum(ATTACK_IDS).optional().describe(
    'The Possible Attacks entry this threat is an instance of, e.g. "xss". REQUIRED on create. ' +
    'It must be an attack weaponized to achieve this STRIDE category, and the API ' +
    'refuses the pairing otherwise: ' +
    Object.entries(ATTACKS_BY_CATEGORY).map(([c, ids]) => `${c} -> ${ids.join('|')}`).join('; ')),
  attack_custom_name: z.string().max(120).optional().describe(
    'An ad hoc attack name, for a threat that is not an instance of anything in the catalogue. ' +
    'Mutually exclusive with attack_id: give one or the other, never both. It is stored on the ' +
    'threat only and is NOT added to the Possible Attacks catalogue.'),
  authenticated: z.boolean().optional().describe(
    'Whether the attacker must already hold an authenticated session to execute this attack. ' +
    'true renders a red "Auth Required" badge, false a green "Unauthenticated" badge. ' +
    'Omit it to leave the question open: the badge is then hidden entirely, because a green ' +
    '"Unauthenticated" on an unexamined threat asserts reachability nobody has established.'),
  severity: SEVERITY.optional().describe(
    'critical, high, moderate, low or informational. Rendered as a colour-coded badge at the top of ' +
    'the accordion, so it is the first thing a reader sorts on. Leave unset rather than guessing: ' +
    'an unset severity reads as "not yet triaged", and a guessed one reads as a decision.'),
  test_status: TEST_STATUS.optional().describe(
    'Whether this threat has been tested against the target yet, and what happened. ' +
    'untested is the default on create and means nobody has run it. validated means the attack ' +
    'worked. rejected means it was run and did not. It drives the colour of the entry in the ' +
    'Threat Model Results UI, grey, green and red respectively, so a model full of grey is a model ' +
    'nobody has acted on. On update this is PRESERVED when omitted, so editing a threat\'s prose ' +
    'will not quietly reset a result somebody spent time establishing; pass it explicitly to change it.'),
  mechanism: z.string().optional().describe(
    'The application mechanism under attack, e.g. "Password Reset" or "Generate Pre-signed URL". ' +
    'The modal offers these from the mechanisms already documented on this target, so list ' +
    'collection:"mechanisms" first and reuse a name from there rather than inventing a synonym.'),
  target_object: z.string().optional().describe(
    'The object the attack is after, e.g. "Session Object" or "IAM Role/Policy". Same convention ' +
    'as mechanism: these come from collection:"notable_objects" on this target.'),
  steps: z.array(z.string()).optional().describe(
    'The attack, one step per entry, in the order they are carried out. Stored as JSON text, which ' +
    'this tool encodes for you; sending a bare list to the API directly would be rejected as a bad ' +
    'request because the column decodes into a string.'),
  security_controls: z.array(z.object({
    control: z.string().describe(
      'The control name, e.g. "Rate Limiting". Taken from the control notes documented on this ' +
      'target, so list collection:"security_controls" and keep the naming consistent.'),
    explanation: z.string().optional().describe(
      'What the control actually does to this attack: prevents it outright, only slows it down, or ' +
      'merely records that it happened. That distinction is the entire reason the field exists.'),
  })).optional().describe(
    'The controls that stand between an attacker and this threat, with what each one does to it. ' +
    'Not to be confused with the security_controls collection in manage_threat_model_notes: that ' +
    'one is the catalogue of controls on the target, this one is the subset affecting this threat.'),
  impact_customer_data: z.string().optional().describe(
    'What happens to customer data if this works. Free prose, and the first thing a triager reads.'),
  impact_attacker_scope: z.string().optional().describe(
    'What the attacker can reach afterwards that they could not reach before. This is where a ' +
    'single-account bug and a whole-tenant bug stop looking alike.'),
  impact_company_reputation: z.string().optional().describe(
    'What this costs the business if it becomes public. Free prose.'),

  pattern: z.string().optional().describe(
    'list: substring match across the URL, the mechanism and the target object.'),
  detail: z.enum(['compact', 'full']).optional().describe(
    `compact (default) gives every field but clips each impact assessment to ${BODY_PREVIEW} ` +
    `chars. full raises that to ${BODY_LIMIT} per field, which on a full model is a lot of prose, ` +
    'so narrow with category or pattern first.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function manageThreatModel(params) {
  const full = params.detail === 'full';

  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      let rows = await fetchThreats(params.target_id);

      if (params.category) rows = rows.filter((t) => t.category === params.category);
      if (params.pattern) {
        const needle = params.pattern.replace(/\*/g, '').toLowerCase();
        rows = rows.filter((t) =>
          (t.url || '').toLowerCase().includes(needle) ||
          (t.mechanism || '').toLowerCase().includes(needle) ||
          (t.target_object || '').toLowerCase().includes(needle));
      }

      // The modal shows a badge per STRIDE tab, and the counts answer the question people actually
      // open this with: which categories have been thought about and which are still blank.
      const by_category = {};
      for (const t of rows) {
        const key = t.category || 'uncategorised';
        by_category[key] = (by_category[key] || 0) + 1;
      }

      const projected = rows.map((t) => compactThreat(t, full));
      return { by_category, ...limitResults(projected, clampLimit(params.max_results)) };
    }

    case 'create': {
      if (!params.target_id) return { error: 'create needs target_id' };
      if (!params.category) return { error: 'create needs category' };
      if (!params.url) return { error: 'create needs url' };
      const out = await apiPost(`/threat-model/${params.target_id}`, threatBody(params));
      return compactThreat(out, full);
    }

    case 'update': {
      if (!params.threat_id) return { error: 'update needs threat_id, not target_id' };

      let body = threatBody(params);
      const missing = THREAT_FIELDS.filter((f) => body[f] === undefined);
      if (missing.length) {
        // The handler sets all nine columns from the payload, so anything left out of the body is
        // written back as an empty string. Refusing to send a partial update without the scope
        // target id is the difference between changing one field and quietly erasing eight.
        if (!params.target_id) {
          return {
            error: 'update replaces the whole threat, so it needs target_id as well to read the ' +
                   'current row back and merge your changes over it',
            would_be_cleared: missing,
          };
        }
        const current = await findThreat(params.target_id, params.threat_id);
        if (!current) {
          return { error: 'no threat with that threat_id on this scope target' };
        }
        body = { ...threatRowToBody(current), ...body };
      }

      try {
        return compactThreat(await apiPut(`/threat-model/${params.threat_id}`, body), full);
      } catch (err) {
        return idError(err, 'threat_id');
      }
    }

    case 'delete': {
      if (!params.threat_id) return { error: 'delete needs threat_id, not target_id' };
      try {
        await apiDelete(`/threat-model/${params.threat_id}`);
      } catch (err) {
        return idError(err, 'threat_id');
      }
      return { deleted: true, threat_id: params.threat_id };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === The four note collections =================================================================

// One routing table rather than four near-identical handlers. Each entry says where the collection
// lives, which column carries the grouping name and which carries the free text, and which columns
// the PUT touches, because that last one is what decides whether an update has to read the row back
// first to avoid blanking a column the caller never mentioned.
const COLLECTIONS = {
  application_questions: {
    label: 'answer',
    listPath: (targetID) => `/application-questions/${targetID}/answers`,
    rowPath: (rowID) => `/application-questions/answers/${rowID}`,
    nameField: 'question',
    contentField: 'answer',
    usesURL: false,
    createRequires: ['name', 'content'],
    // The PUT sets the answer and nothing else, so the question a row hangs off cannot be edited
    // and there is nothing here that a partial update could lose.
    updateFields: ['answer'],
  },
  mechanisms: {
    label: 'example',
    listPath: (targetID) => `/mechanisms/${targetID}/examples`,
    rowPath: (rowID) => `/mechanisms/examples/${rowID}`,
    nameField: 'mechanism',
    contentField: 'notes',
    usesURL: true,
    createRequires: ['name', 'url'],
    // Sets url and notes together. The mechanism name itself is fixed at create time.
    updateFields: ['url', 'notes'],
  },
  notable_objects: {
    label: 'object',
    listPath: (targetID) => `/notable-objects/${targetID}`,
    rowPath: (rowID) => `/notable-objects/${rowID}`,
    nameField: 'object_name',
    contentField: 'object_json',
    usesURL: false,
    createRequires: ['name'],
    // The only collection where the name is editable, because the PUT sets it alongside the JSON.
    updateFields: ['object_name', 'object_json'],
  },
  security_controls: {
    label: 'note',
    listPath: (targetID) => `/security-controls/${targetID}/notes`,
    rowPath: (rowID) => `/security-controls/notes/${rowID}`,
    nameField: 'control_name',
    contentField: 'note',
    usesURL: false,
    createRequires: ['name', 'content'],
    updateFields: ['note'],
  },
};

const manageThreatModelNotesSchema = z.object({
  collection: z.enum(['application_questions', 'mechanisms', 'notable_objects', 'security_controls'])
    .describe(
      'Which of the four collections to work on. ' +
      'application_questions: answers to the reconnaissance questions about how the application is ' +
      'built and behaves. Many answers per question are allowed and normal. ' +
      'mechanisms: worked examples of an action the application performs, each one a URL plus notes ' +
      'on what it does, filed under a mechanism name like "Password Reset". ' +
      'notable_objects: the data structures the application moves around, each one a pasted JSON ' +
      'example filed under an object name like "User Object". ' +
      'security_controls: notes on a control the target has in place, filed under the control name.'),

  action: z.enum(['list', 'create', 'update', 'delete']).describe(
    'list: every row in the collection on a target, with a count per grouping name. ' +
    'create: add a row under a grouping name. The names are free text and are not checked against ' +
    'the lists the modals offer, so a typo makes a new group rather than an error. ' +
    'update: change a row. For mechanisms and notable_objects the route replaces more than one ' +
    'column, so pass target_id as well and the current row is read back and merged. ' +
    'delete: remove one row permanently.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list and create, which are addressed by scope target. ' +
    'Also needed on a partial update of mechanisms or notable_objects, where it is what lets the ' +
    'current row be read back: these rows are only readable per target, there is no route that ' +
    'fetches one by its own id.'),
  row_id: z.string().uuid().optional().describe(
    'The row\'s own UUID, as returned in "id" by list and create. Required for update and delete, ' +
    'which are addressed by the row rather than by the scope target. This is the answer_id, ' +
    'example_id, object_id or note_id in the underlying route depending on the collection. Passing ' +
    'a scope target id here fails as though the row did not exist, so check which one you have.'),

  name: z.string().optional().describe(
    'The grouping key, which is a different column per collection: the question text for ' +
    'application_questions, the mechanism name for mechanisms, the object name for ' +
    'notable_objects, the control name for security_controls. Required on create. On list it ' +
    'narrows to that one group. On update it is only settable for notable_objects, which is the ' +
    'one collection whose route lets the name change; everywhere else the row keeps the group it ' +
    'was created under.'),
  content: z.string().optional().describe(
    'The body of the row, again a different column per collection: the answer for ' +
    'application_questions, the notes for mechanisms, the JSON example for notable_objects, the ' +
    'note for security_controls. Required on create for application_questions and ' +
    'security_controls, and required on update for those two since it is the only column their ' +
    'route writes. For notable_objects this is stored as text and is never parsed or validated, so ' +
    'malformed JSON is accepted and comes back exactly as it went in.'),
  url: z.string().optional().describe(
    'mechanisms only: the URL the example lives at. Required on create, and required by the route ' +
    'on update, which is why a mechanisms update that changes only the notes needs target_id so ' +
    'the existing URL can be read back and sent with it.'),

  pattern: z.string().optional().describe(
    'list: substring match across the grouping name, the body and the URL.'),
  detail: z.enum(['compact', 'full']).optional().describe(
    `compact (default) clips the body of each row to ${BODY_PREVIEW} chars, which is enough to ` +
    `recognise the row you want. full raises that to ${BODY_LIMIT}. A pasted object structure or a ` +
    'long answer is most of the payload here, so list compact and read full on what matters.'),
  max_results: z.number().optional().describe('Maximum rows (default 50, max 1000)'),
});

async function manageThreatModelNotes(params) {
  const spec = COLLECTIONS[params.collection];
  if (!spec) return { error: `unknown collection: ${params.collection}` };
  const full = params.detail === 'full';

  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      let rows = await fetchRows(spec, params.target_id);

      if (params.name) rows = rows.filter((r) => r[spec.nameField] === params.name);
      if (params.pattern) {
        const needle = params.pattern.replace(/\*/g, '').toLowerCase();
        rows = rows.filter((r) =>
          String(r[spec.nameField] || '').toLowerCase().includes(needle) ||
          String(r[spec.contentField] || '').toLowerCase().includes(needle) ||
          String(r.url || '').toLowerCase().includes(needle));
      }

      // What the modals render as a badge next to each name in the sidebar. It is also the cheapest
      // way to see which groups exist at all, since the names are free text and only the ones
      // somebody has written against are in the database.
      const groups = {};
      for (const r of rows) {
        const key = r[spec.nameField] || '(unnamed)';
        groups[key] = (groups[key] || 0) + 1;
      }

      const projected = rows.map((r) => compactRow(r, spec, full));
      return { groups, ...limitResults(projected, clampLimit(params.max_results)) };
    }

    case 'create': {
      if (!params.target_id) return { error: 'create needs target_id' };
      for (const required of spec.createRequires) {
        if (!params[required]) {
          return { error: `create needs ${required} for ${params.collection}` };
        }
      }
      const body = { [spec.nameField]: params.name };
      if (params.content !== undefined) body[spec.contentField] = params.content;
      if (spec.usesURL) body.url = params.url;

      const out = await apiPost(spec.listPath(params.target_id), body);
      return clean({
        ...compactRow(out, spec, full),
        // Named advisory, not note, and the collision it avoids is real: security_controls stores
        // its body in a column called note, so an advisory under the same key overwrote the note
        // that had just been created and the caller got a response with the content missing.
        advisory: params.collection === 'notable_objects'
          ? 'Object names are not unique in the database but the modal shows one row per name, so ' +
            'check the existing rows before creating a second one under the same name.'
          : undefined,
      });
    }

    case 'update': {
      if (!params.row_id) return { error: 'update needs row_id, not target_id' };

      const supplied = {};
      for (const field of spec.updateFields) {
        const value = valueFor(field, spec, params);
        if (value !== undefined) supplied[field] = value;
      }
      const missing = spec.updateFields.filter((f) => supplied[f] === undefined);

      let body = supplied;
      if (missing.length) {
        // A collection whose route writes exactly one column has nothing to merge: the caller
        // simply has to say what the new value is.
        if (spec.updateFields.length === 1) {
          return { error: `update needs ${paramNameFor(missing[0], spec)} for ${params.collection}` };
        }
        // More than one column, so the columns the caller did not mention would be written back as
        // empty strings. Read the row and merge instead of erasing them.
        if (!params.target_id) {
          return {
            error: `update on ${params.collection} replaces every editable column, so it needs ` +
                   'target_id as well to read the current row back and merge your changes over it',
            would_be_cleared: missing.map((f) => paramNameFor(f, spec)),
          };
        }
        const current = await findRow(spec, params.target_id, params.row_id);
        if (!current) {
          return { error: `no ${spec.label} with that row_id on this scope target` };
        }
        body = {};
        for (const field of spec.updateFields) {
          body[field] = supplied[field] !== undefined ? supplied[field] : (current[field] || '');
        }
      }

      try {
        return compactRow(await apiPut(spec.rowPath(params.row_id), body), spec, full);
      } catch (err) {
        return idError(err, 'row_id');
      }
    }

    case 'delete': {
      if (!params.row_id) return { error: 'delete needs row_id, not target_id' };
      try {
        await apiDelete(spec.rowPath(params.row_id));
      } catch (err) {
        return idError(err, 'row_id');
      }
      return { deleted: true, collection: params.collection, row_id: params.row_id };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === projections ===============================================================================

function compactThreat(t, full) {
  if (!t || typeof t !== 'object') return t;
  const limit = full ? BODY_LIMIT : BODY_PREVIEW;
  return clean({
    id: t.id,
    category: t.category,
    url: t.url,
    mechanism: t.mechanism,
    target_object: t.target_object,
    steps: parseList(t.steps),
    security_controls: parseList(t.security_controls),
    impact_customer_data: clip(t.impact_customer_data, limit),
    impact_attacker_scope: clip(t.impact_attacker_scope, limit),
    impact_company_reputation: clip(t.impact_company_reputation, limit),
    // Never clipped and always shown: it is one short word and it is the field that says whether
    // anyone has acted on this threat.
    test_status: t.test_status || 'untested',
    // The three reader-facing fields. one_sentence and severity are never clipped: they are the
    // headline and the badge, and a clipped headline is worse than none. summary IS clipped like
    // the other prose, but it must be projected: omitting it made every read-back show the field as
    // absent, so a caller that had just written it could not confirm the write landed.
    one_sentence: t.one_sentence || '',
    summary: clip(t.summary, limit),
    severity: t.severity || '',
    // Passed through as-is, including null: the reader has to be able to tell
    // "not decided" from "no credential needed".
    authenticated: t.authenticated === undefined ? null : t.authenticated,
    attack_id: t.attack_id || '',
    attack_custom_name: t.attack_custom_name || '',
    attack_name: t.attack_name || '',
    created_at: t.created_at,
    updated_at: t.updated_at,
  });
}

function compactRow(row, spec, full) {
  if (!row || typeof row !== 'object') return row;
  return clean({
    id: row.id,
    [spec.nameField]: row[spec.nameField],
    // Only mechanisms carry a URL. On the other three the key is undefined and clean drops it.
    url: row.url,
    [spec.contentField]: clip(row[spec.contentField], full ? BODY_LIMIT : BODY_PREVIEW),
    created_at: row.created_at,
    updated_at: row.updated_at,
  });
}

// === helpers ===================================================================================

// Go encodes a query that matched nothing as JSON null rather than as an empty array, because the
// handlers build a nil slice and hand it straight to the encoder. Every read here has to survive
// that, since a target with no threats yet is the normal starting state.
async function fetchThreats(targetID) {
  const rows = await apiGet(`/threat-model/${targetID}`);
  return Array.isArray(rows) ? rows : [];
}

async function fetchRows(spec, targetID) {
  const rows = await apiGet(spec.listPath(targetID));
  return Array.isArray(rows) ? rows : [];
}

async function findThreat(targetID, threatID) {
  const rows = await fetchThreats(targetID);
  return rows.find((t) => t.id === threatID);
}

async function findRow(spec, targetID, rowID) {
  const rows = await fetchRows(spec, targetID);
  return rows.find((r) => r.id === rowID);
}

// Builds the threat payload out of whatever the caller supplied, leaving anything they did not
// mention absent so the update path can tell a deliberate blanking from an omission.
function threatBody(params) {
  const body = {};
  if (params.category !== undefined) body.category = params.category;
  if (params.url !== undefined) body.url = params.url;
  if (params.mechanism !== undefined) body.mechanism = params.mechanism;
  if (params.target_object !== undefined) body.target_object = params.target_object;
  if (params.steps !== undefined) body.steps = JSON.stringify(params.steps);
  if (params.security_controls !== undefined) {
    body.security_controls = JSON.stringify(params.security_controls);
  }
  if (params.impact_customer_data !== undefined) {
    body.impact_customer_data = params.impact_customer_data;
  }
  if (params.impact_attacker_scope !== undefined) {
    body.impact_attacker_scope = params.impact_attacker_scope;
  }
  if (params.impact_company_reputation !== undefined) {
    body.impact_company_reputation = params.impact_company_reputation;
  }
  if (params.one_sentence !== undefined) body.one_sentence = params.one_sentence;
  if (params.summary !== undefined) body.summary = params.summary;
  if (params.severity !== undefined) body.severity = params.severity;
  if (params.authenticated !== undefined) body.authenticated = params.authenticated;
  if (params.attack_id !== undefined) body.attack_id = params.attack_id;
  if (params.attack_custom_name !== undefined) body.attack_custom_name = params.attack_custom_name;
  if (params.test_status !== undefined) body.test_status = params.test_status;
  return body;
}

// The stored row in the shape the PUT expects. steps and security_controls stay as the JSON text
// they are stored as, so a merge that does not touch them round-trips them byte for byte rather
// than re-encoding somebody else's formatting.
function threatRowToBody(t) {
  const body = {};
  for (const field of THREAT_FIELDS) {
    // `|| ''` is wrong for a tri-state boolean: it turns a legitimate `false` into `''`, which the
    // API cannot decode into a *bool. Undecided (null/undefined) is omitted so the stored NULL
    // survives rather than being restated as a decision.
    if (field === 'authenticated') {
      if (typeof t[field] === 'boolean') body[field] = t[field];
      continue;
    }
    body[field] = t[field] || '';
  }
  return body;
}

// Maps a database column back to the parameter the caller sets it with. Only ever asked about the
// three columns a route writes, which are always the name, the body, or the mechanism URL.
function valueFor(field, spec, params) {
  if (field === 'url') return params.url;
  if (field === spec.nameField) return params.name;
  if (field === spec.contentField) return params.content;
  return undefined;
}

function paramNameFor(field, spec) {
  if (field === 'url') return 'url';
  if (field === spec.nameField) return 'name';
  return 'content';
}

// steps and security_controls are JSON text in the database because that is what the modal writes
// with JSON.stringify. Parsing on the way out gives the caller a list instead of a string they have
// to decode themselves. A row written by hand, or by an older build, can be plain prose, and handing
// that back raw is better than handing back nothing.
function parseList(text) {
  if (typeof text !== 'string' || !text) return undefined;
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed.length ? parsed : undefined;
    return parsed || undefined;
  } catch {
    return clip(text, BODY_LIMIT);
  }
}

// Both update paths and both delete paths funnel through here. The hint exists because a wrong id
// is indistinguishable from a deleted row in what these routes return: DELETE answers 404 "not
// found", and the update handlers scan the RETURNING row and treat no-rows as a query failure, so a
// bad id surfaces as a 500 that reads like the server broke. Neither says "that was a scope target
// id", which is the mistake this asymmetry invites.
function idError(err, idParam) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  return clean({
    error: clip((m ? m[2] : raw).trim(), BODY_PREVIEW),
    http_status: status,
    hint: status === 404 || status === 500
      ? `No row matched. ${idParam} is the row's own id, the "id" field returned by list and ` +
        'create, not the scope target id that addresses list and create themselves.'
      : undefined,
  });
}

// Shallow, and applied to the rows built above rather than to anything returned untouched. Most
// columns in these tables are optional free text, so an unstripped row is mostly empty strings.
// false and 0 survive, because both mean something wherever they turn up.
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

module.exports = {
  manageThreatModelSchema, manageThreatModel,
  manageThreatModelNotesSchema, manageThreatModelNotes,
};
