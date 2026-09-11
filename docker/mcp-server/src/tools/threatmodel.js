const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');
// Only resolveLimit. This file has its own clip() with different semantics for an empty string, and
// importing the shared one under the same name would silently change every projection in here.
const { resolveLimit } = require('../utils/clip');

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
//
// THE THREAT NOTES BREAK BOTH OF THOSE RULES, on purpose, and that asymmetry is the third thing that
// will bite. They are addressed by the THREAT for list and add and by the NOTE's own id for update
// and delete, which is the same asymmetry one level down and a different pair of ids to confuse. And
// their PUT is COALESCE-guarded in Go rather than replacing the row, so update_note sends only the
// fields the caller supplied and there is no read-back merge here at all. Copying the merge dance
// from the threat update into the note update would not just be redundant, it would reintroduce the
// race the SQL guard removes.

const STRIDE = z.enum(['spoofing', 'tampering', 'repudiation', 'information_disclosure',
                       'denial_of_service', 'elevation_of_privilege']);

// The ceiling on any single stored field, applied per column. Object structures get pasted in whole
// and an impact assessment is three paragraphs of prose, so none of this is hypothetical.
const BODY_LIMIT = 2000;
// What a compact row shows of a long field. Enough to tell two answers apart and to recognise the
// one you are looking for before spending a full read on it.
const BODY_PREVIEW = 600;

// The threat-note listing budgets, which are smaller than the threat ones for the reason notes.js
// gives about scope-target notes: a note body is prose somebody typed, so it has no upper bound, and
// a threat under active testing collects them. A listing exists to find the note you mean, not to
// read it, so the preview is sized to recognise one.
const NOTE_PREVIEW_CHARS = 240;
const NOTE_LIST_DEFAULT = 25;

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

// What happened when somebody tested the threat, which is a different question from whether anybody
// looked at it. The Go handler preserves this column when the PUT omits it, so an update that only
// edits prose cannot silently reset a result somebody spent time establishing.
//
// The fourth value is not a fourth shade of the same thing. A test that could not be SETTLED - a
// precondition that could not be met, a refusal whose shape did not say why, a control arm that did
// not pass - leaves the claim standing, so recording it as rejected buries a finding nobody
// disproved. Before this value existed those results went into untested instead, which reads as
// "nobody has been here" and was wrong in the other direction: 30 rows on the reference target were
// parked there having actually been worked on.
const TEST_STATUS = z.enum(['untested', 'validated', 'rejected', 'not_enough_info']);
const SEVERITY = z.enum(['critical', 'high', 'moderate', 'low', 'informational']);

// The accordion header is `<attack name> - <mechanism> on <target object>`. These two caps keep that
// header readable, and they must match the ones the modal enforces in
// client/src/modals/ThreatModelModal.js: a value this tool accepts but the form refuses is a row the
// operator can read and cannot edit.
const MAX_ATTACK_CUSTOM_NAME = 65;
const MAX_THREAT_NAME = 125;

// mechanism and target_object are capped individually by the schema, but what a reader actually sees
// is the two of them composed, and two in-range values can still compose an out-of-range title. So
// the real check runs on the assembled body: on create that is the payload, on update it is the
// payload laid over the stored row, which is the only point at which BOTH halves are known. Checking
// params alone would pass an update that sends a long mechanism against an already-long stored
// target_object.
// `previous` is the row as it stands before the change, on update only. A row already over the cap
// stays editable as long as the change does not make it LONGER: 68 of the 252 rows on the reference
// target predate this cap, one of them at 845 characters, and a strict check would have refused
// every one of their test_status updates too - failing the "go settle the untested ones" pass on a
// title length nobody was touching. Create has no previous, so create is strict.
function threatNameError(body, previous) {
  const compose = (b) =>
    `${b.mechanism || ''}${b.target_object ? ` on ${b.target_object}` : ''}`;
  const name = compose(body);
  if (name.length <= MAX_THREAT_NAME) return null;
  if (previous && name.length <= compose(previous).length) return null;
  return {
    error: `mechanism and target_object compose the threat name "<mechanism> on <target_object>", ` +
           `which is capped at ${MAX_THREAT_NAME} characters together. This one is ${name.length}. ` +
           'Shorten both and move the detail into one_sentence or summary, which are uncapped.',
    threat_name: name,
  };
}

const manageThreatModelSchema = z.object({
  action: z.enum(['list', 'create', 'update', 'delete',
                  'list_flow_links', 'link_flow', 'unlink_flow',
                  'list_notes', 'add_note', 'update_note', 'delete_note']).describe(
    'list: every threat documented on a target, with a count per STRIDE category so you can see ' +
    'which parts of the model are empty before reading any of it. ' +
    'create: add one threat under one STRIDE category. ' +
    'update: change a threat. The route replaces every column, so pass target_id as well and the ' +
    'current row is read back and merged underneath whatever you supply. ' +
    'delete: remove one threat. There is no soft delete and no restore here, it is gone. ' +
    'THE FLOW LINKS: a threat is a claim, and the request sequence that demonstrates it is the ' +
    'evidence. These three attach one to the other. ' +
    'link_flow: record that a flow demonstrates a threat. Takes a threat_id, a flow_id and an ' +
    'optional note saying what the flow shows. Linking the same pair twice UPDATES the note ' +
    'rather than making a second link. ' +
    'list_flow_links: every flow mapped to a threat on this target, each with the threat\'s ' +
    'mechanism and STRIDE category and the flow\'s own name, narrowable to one threat or one flow. ' +
    'unlink_flow: remove one mapping. The flow and the threat both survive; only the mapping goes. ' +
    'THE THREAT NOTES: a note is a title and a body of free prose hung on ONE threat. It is where ' +
    'the working goes - what you tried, what came back, which precondition you could not meet, what ' +
    'to try next - none of which has a column on the threat itself and all of which is lost when it ' +
    'only exists in a conversation. Not to be confused with manage_threat_model_notes, which is the ' +
    'four supporting collections for the model as a whole, or with manage_notes, which is a note on ' +
    'the whole scope target. ' +
    'list_notes: every note on one threat, most recently edited first, each with a CLIPPED preview ' +
    'of its body rather than the body. Takes threat_id. ' +
    'add_note: attach a note to a threat. Takes threat_id and note_title, note_content optional. ' +
    'update_note: change a note\'s title or its body or both. Takes note_id and at least one of ' +
    'note_title and note_content; whatever you leave out is PRESERVED by the route itself. ' +
    'delete_note: remove one note. Takes note_id. There is no restore, and deleting the THREAT ' +
    'deletes its notes with it.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list and create, which are addressed by scope target, and ' +
    'for all three flow-link actions, whose route is addressed by scope target too. ' +
    'Also wanted on update, where it is what lets the current row be read back and merged: threats ' +
    'are only readable per target, there is no route that fetches one by its own id.'),
  threat_id: z.string().uuid().optional().describe(
    'The threat\'s own UUID, as returned in "id" by list and create. Required for update and ' +
    'delete, which are addressed by the row rather than by the scope target. Passing a scope ' +
    'target id here fails as though the threat did not exist, so check which one you have. ' +
    'Required for link_flow and unlink_flow, and optional on list_flow_links, where it narrows to ' +
    'one threat\'s evidence. The threat MUST belong to target_id: the server checks, and a threat ' +
    'from another engagement is refused with threat_not_found rather than linked across targets. ' +
    'Also required for list_notes and add_note, which address a threat\'s notes by the threat they ' +
    'hang on. It is NOT used by update_note or delete_note: those take note_id.'),

  flow_id: z.string().optional().describe(
    'link_flow / unlink_flow, and optional on list_flow_links to narrow to one flow. ' +
    'A FLOW ID IS NOT ALWAYS A UUID and this field is deliberately not validated as one. A ' +
    'DETECTED flow - the majority of them, 46 of 49 on the reference target - has the composite id ' +
    '<session>~<tab>~<root capture>, which is provenance rather than a row anywhere; a BUILT flow ' +
    'has a plain UUID in request_flows. Both are linkable and the server derives which kind it is ' +
    'from the shape, counting the "~" separators. Get either from manage_detected_flows ' +
    'action:"list", which now returns both kinds with a kind field on every row. ' +
    'THE SERVER DOES NOT CHECK THAT THE FLOW EXISTS - it cannot, because half of these ids are not ' +
    'keys - so this tool resolves it against the target\'s flow list and tells you when it does ' +
    'not resolve. A link to a flow nobody can open is still stored, because a detected id can ' +
    'retire when the captures re-segment and deleting the operator\'s mapping over a segmentation ' +
    'heuristic would lose more than it saves.'),
  note: z.string().optional().describe(
    'link_flow: what this flow shows about the threat, e.g. "steps 3-5 read another account\'s ' +
    'order after the parent check passes". Free text, optional, and stored on the LINK rather than ' +
    'on either side, so it can say something that is only true of the pairing. Re-linking the same ' +
    'threat and flow OVERWRITES the note on the route, so omitting it here re-reads the existing ' +
    'one and sends it back rather than blanking it; pass "" when you actually mean to erase it. ' +
    'THIS IS THE FLOW-LINK NOTE AND NOTHING ELSE. The threat notes use note_title and note_content; ' +
    'the two are unrelated and sharing a field would have coupled the upsert-overwrite rule above to ' +
    'a write that does not have it.'),

  // The threat-note parameters. Kept apart from `note` above for the reason its own description
  // gives, and deliberately NOT added to THREAT_FIELDS: these are not threat_model columns, and a
  // threat update that thought they were would look partial, force a read-back, and then post keys
  // the threat PUT has never heard of.
  note_id: z.string().uuid().optional().describe(
    'A threat note\'s own UUID, the "id" returned by list_notes and add_note. Required for ' +
    'update_note and delete_note, which are addressed by the note rather than by the threat. ' +
    'A THREAT ID HERE REPORTS AS THE NOTE NOT EXISTING rather than as the wrong kind of id, and so ' +
    'does a note_id from manage_notes: that tool\'s note_id is a note on a whole SCOPE TARGET, a ' +
    'different table entirely, and a 404 is all either of them will tell you. Check which one you ' +
    'are holding before concluding the note was deleted.'),
  note_title: z.string().optional().describe(
    'The threat note\'s title, which is what identifies it in a listing since list_notes returns ' +
    'previews rather than bodies. Required on add_note and rejected if it is only whitespace. On ' +
    'update_note it replaces the existing title; omit it and the existing one is kept. There is no ' +
    'way to blank a title: a note with no title cannot be found again.'),
  note_content: z.string().optional().describe(
    'The threat note\'s body. Optional on add_note, where it defaults to empty, because a titled ' +
    'placeholder is a normal note. On update_note it replaces the body wholesale, and an explicit ' +
    'empty string is honoured as a deliberate blanking while OMITTING it preserves what is there. ' +
    'That distinction is real here: the Go route is COALESCE-guarded per column, so this tool sends ' +
    'only the fields you supplied and nothing reads the row back first.'),

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
  attack_custom_name: z.string().max(MAX_ATTACK_CUSTOM_NAME).optional().describe(
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
    'untested is the default on create and means nobody has run it. ' +
    'validated means the attack worked. ' +
    'rejected means it WAS run and the attack did not work: the claim is disproved. ' +
    'not_enough_info means it was run or attempted and the result could not be SETTLED - the ' +
    'precondition could not be met, the refusal did not say whether it was the control or the ' +
    'input, the control arm did not pass, the account needed did not exist. ' +
    'DO NOT record an unsettled test as rejected. Unsettled is not disproved: the threat is still ' +
    'open work, and filing it under rejected is how a real finding disappears. Equally do not leave ' +
    'it in untested, which claims nobody has looked. ' +
    'It drives the colour of the entry in the Threat Model Results UI - grey, green, red and amber ' +
    'respectively - so a model full of grey is a model nobody has acted on and a wall of amber is a ' +
    'list of things to go back to. On update this is PRESERVED when omitted, so editing a threat\'s ' +
    'prose will not quietly reset a result somebody spent time establishing; pass it explicitly to ' +
    'change it.'),
  mechanism: z.string().max(MAX_THREAT_NAME).optional().describe(
    'The application mechanism under attack, e.g. "Password Reset" or "Generate Pre-signed URL". ' +
    'The modal offers these from the mechanisms already documented on this target, so list ' +
    'collection:"mechanisms" first and reuse a name from there rather than inventing a synonym. ' +
    `This and target_object compose the threat name as "<mechanism> on <target_object>", which is ` +
    `capped at ${MAX_THREAT_NAME} characters TOGETHER. Keep both short and descriptive; the prose ` +
    'belongs in one_sentence and summary, not in the title.'),
  target_object: z.string().max(MAX_THREAT_NAME).optional().describe(
    'The object the attack is after, e.g. "Session Object" or "IAM Role/Policy". Same convention ' +
    `as mechanism: these come from collection:"notable_objects" on this target, and the two share ` +
    `one ${MAX_THREAT_NAME}-character budget.`),
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
    'so narrow with category or pattern first. ' +
    `On list_notes it is what turns a ${NOTE_PREVIEW_CHARS}-character preview into the body: there ` +
    'is no get_note action, so full (or max_note_content_chars) is how a note is actually read.'),
  max_results: z.number().optional().describe(
    'Maximum rows (default 50, max 1000). Applies to list and to list_flow_links. ' +
    `On list_notes the default is ${NOTE_LIST_DEFAULT}, since a threat accumulates notes and each ` +
    'one carries prose.'),
  max_note_content_chars: z.number().optional().describe(
    'list_notes: how much of each note body to return, overriding the preview and the detail ' +
    'setting. It is a PER ROW budget and is divided by the number of notes returned, so raising it ' +
    'on a threat holding twenty notes does not multiply by twenty. Narrow with max_results first ' +
    'when you want one long note in full.'),
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
      const createBody = threatBody(params);
      const createNameError = threatNameError(createBody);
      if (createNameError) return createNameError;
      const out = await apiPost(`/threat-model/${params.target_id}`, createBody);
      return compactThreat(out, full);
    }

    case 'update': {
      if (!params.threat_id) return { error: 'update needs threat_id, not target_id' };

      let body = threatBody(params);
      // Held so the name cap can be judged against the row as it stands. It is only populated on the
      // merge path, which is also the only path a caller who is not touching the name takes.
      let previousBody = null;
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
        previousBody = threatRowToBody(current);
        body = { ...previousBody, ...body };
      }

      // After the merge, so the cap is checked against the row as it will exist rather than against
      // the fragment the caller sent.
      const updateNameError = threatNameError(body, previousBody);
      if (updateNameError) return updateNameError;

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

    case 'list_flow_links': {
      if (!params.target_id) return { error: 'list_flow_links needs target_id' };
      let body;
      try {
        body = await apiGet(`/flow-threat-links/${params.target_id}`);
      } catch (err) {
        return idError(err, 'target_id');
      }
      let links = Array.isArray(body.links) ? body.links : [];
      // The route takes no filters. Its own source comment says it narrows to one threat or one
      // flow and the query it runs does not, so the narrowing is done here rather than sent as a
      // parameter that would be ignored while looking like it worked.
      if (params.threat_id) links = links.filter((l) => l.threat_id === params.threat_id);
      if (params.flow_id) links = links.filter((l) => l.flow_id === params.flow_id);

      const flows = links.length ? await loadFlowIndex(params.target_id) : null;
      const rows = links.map((l) => decorateLink(l, flows));
      const orphans = rows.filter((r) => r.flow_exists === false).length;

      return {
        scope_target_id: params.target_id,
        ...limitResults(rows, clampLimit(params.max_results)),
        filtered_by: clean({ threat_id: params.threat_id, flow_id: params.flow_id }),
        note: 'A link says this flow is the sequence that demonstrates that threat. threat_title ' +
          'is the threat\'s mechanism, falling back to its one-sentence description. flow_name is ' +
          'the operator-given name where there is one, and the "(Automated Flow Detected)" ' +
          'placeholder where there is not - which is a default, not a title anybody chose.',
        orphan_note: orphans
          ? `${orphans} link(s) point at a flow that is NOT in this target's current flow list, ` +
            'marked flow_exists:false. The API returns those exactly like live ones, so they are ' +
            'checked here. A detected flow id is derived from the captures and retires when they ' +
            're-segment, so this usually means the flow moved rather than that the link was wrong; ' +
            're-list the flows and re-link, or unlink_flow if it is genuinely stale.'
          : undefined,
      };
    }

    case 'link_flow': {
      if (!params.target_id) return { error: 'link_flow needs target_id' };
      if (!params.threat_id) return { error: 'link_flow needs threat_id' };
      if (!params.flow_id || !String(params.flow_id).trim()) {
        return { error: 'link_flow needs flow_id, from manage_detected_flows action:"list"' };
      }

      // The route's upsert sets note = EXCLUDED.note, so a re-link that carries no note writes an
      // empty one over whatever was there. Reading it back first is the difference between editing
      // a mapping and silently erasing the sentence that explained it.
      let note = params.note;
      let existing;
      try {
        const current = await apiGet(`/flow-threat-links/${params.target_id}`);
        existing = (Array.isArray(current.links) ? current.links : []).find(
          (l) => l.threat_id === params.threat_id && l.flow_id === params.flow_id);
      } catch {
        existing = undefined;
      }
      if (note === undefined) note = (existing && existing.note) || '';

      let res;
      try {
        res = await apiPost(`/flow-threat-links/${params.target_id}`, {
          threat_id: params.threat_id,
          flow_id: params.flow_id,
          note,
        });
      } catch (err) {
        return linkError(err, params);
      }

      const flows = await loadFlowIndex(params.target_id);
      const flow = flows ? flows.get(params.flow_id) : undefined;
      return clean({
        linked: true,
        threat_id: res.threat_id || params.threat_id,
        flow_id: res.flow_id || params.flow_id,
        // Derived by the server from the id's shape when not supplied: exactly two "~" separators
        // means detected, anything else means built.
        flow_kind: res.flow_kind,
        flow_name: flow ? flow.name : undefined,
        flow_label: flow ? flow.label : undefined,
        note,
        replaced_note: existing !== undefined ? true : undefined,
        note_text: res.note_text,
        warning: flows && !flow
          ? 'THAT FLOW IS NOT IN THIS TARGET\'S FLOW LIST. The link was stored anyway, because ' +
            'flow_id is not a foreign key - a detected flow id is provenance rather than a row - ' +
            'so nothing rejected it. Check the id against manage_detected_flows action:"list": a ' +
            'typo and a retired id look identical from here.'
          : undefined,
      });
    }

    case 'unlink_flow': {
      if (!params.target_id) return { error: 'unlink_flow needs target_id' };
      if (!params.threat_id) return { error: 'unlink_flow needs threat_id' };
      if (!params.flow_id) return { error: 'unlink_flow needs flow_id' };
      let res;
      try {
        res = await apiPost(`/flow-threat-links/${params.target_id}`, {
          threat_id: params.threat_id,
          flow_id: params.flow_id,
          remove: true,
        });
      } catch (err) {
        return linkError(err, params);
      }
      const removed = Number(res.removed) || 0;
      return {
        removed,
        threat_id: params.threat_id,
        flow_id: params.flow_id,
        note: removed
          ? 'The mapping is gone. The threat and the flow both survive; only the link was removed.'
          : 'No link matched that threat and flow on this target, so nothing changed. The removal ' +
            'is keyed on all three of scope target, threat and flow, so a mismatch in any one of ' +
            'them reads as zero rather than as an error.',
      };
    }

    case 'list_notes': {
      if (!params.threat_id) return { error: 'list_notes needs threat_id' };
      let rows;
      try {
        rows = await threatNotesFor(params.threat_id);
      } catch (err) {
        return noteError(err, 'threat_id');
      }
      // Per row, so it is divided by the row count rather than granted to each of them. A threat
      // under active testing collects notes, and a budget that multiplied by the count would make
      // raising it on the busiest threat the most expensive thing a caller could do.
      const limit = resolveLimit(
        params.max_note_content_chars, full ? BODY_LIMIT : NOTE_PREVIEW_CHARS, rows.length);
      const projected = rows.map((n) => previewNote(n, limit));
      return {
        threat_id: params.threat_id,
        ...limitResults(projected, clampLimit(params.max_results, NOTE_LIST_DEFAULT)),
      };
    }

    case 'add_note': {
      if (!params.threat_id) return { error: 'add_note needs threat_id' };
      // The server applies the same rule and answers 400. Checking here costs nothing and says why.
      if (!params.note_title || !params.note_title.trim()) {
        return { error: 'add_note needs a note_title with something in it; whitespace alone is rejected' };
      }
      try {
        const out = await apiPost('/threat-notes', {
          threat_id: params.threat_id,
          title: params.note_title,
          content: params.note_content !== undefined ? params.note_content : '',
        });
        return { created: true, ...fullNote(out) };
      } catch (err) {
        return noteError(err, 'threat_id');
      }
    }

    case 'update_note': {
      if (!params.note_id) return { error: 'update_note needs note_id, not threat_id' };
      if (params.note_title === undefined && params.note_content === undefined) {
        return {
          error: 'update_note needs a note_title or a note_content, otherwise there is nothing ' +
                 'to change',
        };
      }
      if (params.note_title !== undefined && !params.note_title.trim()) {
        return { error: 'note_title cannot be blanked; a note is identified by its title' };
      }

      // ONLY the supplied fields. The Go handler is COALESCE-guarded per column, so an omitted key
      // preserves what is stored and there is nothing to read back and merge. That is the opposite
      // of the threat PUT above, and of manage_notes, which has to read the row first precisely
      // because its route writes both columns unconditionally.
      const body = {};
      if (params.note_title !== undefined) body.title = params.note_title;
      // undefined is "not supplied"; "" is a caller emptying the body on purpose and must survive.
      if (params.note_content !== undefined) body.content = params.note_content;

      try {
        return { updated: true, ...fullNote(await apiPut(`/threat-notes/${params.note_id}`, body)) };
      } catch (err) {
        return noteError(err, 'note_id');
      }
    }

    case 'delete_note': {
      if (!params.note_id) return { error: 'delete_note needs note_id, not threat_id' };
      try {
        await apiDelete(`/threat-notes/${params.note_id}`);
      } catch (err) {
        return noteError(err, 'note_id');
      }
      return { deleted: true, note_id: params.note_id };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === Threat notes ==============================================================================
//
// A note is a title and a body hung on one threat. Nothing scans them and nothing else reads them,
// which is the point: everything else stored against a threat is a field with a meaning, and the
// working that connects two of those fields has had nowhere to live.
//
// Two things differ from the scope-target notes in manage_notes and both are deliberate. The Go PUT
// preserves a column the payload omits, so there is no read-back merge here. And there is no route
// that fetches a note by its own id, but there is also no need for one: list_notes on the threat is
// the read, which is why the previews can be raised to the full body rather than needing a get.

// The route always answers {"notes":[...]}, but a missing key would turn into `undefined.map` two
// frames away from the cause, so it is normalised once here. Note that this is NOT the Go nil-slice
// problem fetchThreats has to survive: this handler builds a non-nil slice on purpose.
async function threatNotesFor(threatID) {
  const body = await apiGet(`/threat-notes/${threatID}`);
  return Array.isArray(body && body.notes) ? body.notes : [];
}

// Built by hand rather than through clean(), because clean drops '' and content_chars:0 and an empty
// body are exactly the facts a caller needs here. The same reason notes.js does it this way: an
// absent preview and an empty preview read identically in JSON, and only one of them means "nothing
// was written".
function previewNote(n, limit) {
  const content = typeof n.content === 'string' ? n.content : '';
  const row = {
    id: n.id,
    title: n.title,
    content_chars: content.length,
    updated_at: n.updated_at,
  };
  if (content) {
    row.preview = clip(content, limit);
    // Compared against the budget rather than against the returned string: clip appends a marker, so
    // a body just over the limit comes back LONGER than it started and a length test would say it
    // was not clipped.
    row.clipped = content.length > limit;
  }
  return row;
}

// What a write returns. Never clipped: a create or an update echoes back exactly one note whose body
// the caller just supplied, so there is no multiplier and nothing to save by trimming it.
function fullNote(n) {
  if (!n || typeof n !== 'object') return {};
  const content = typeof n.content === 'string' ? n.content : '';
  return {
    id: n.id,
    threat_id: n.threat_id,
    title: n.title,
    content,
    content_chars: content.length,
    created_at: n.created_at,
    updated_at: n.updated_at,
  };
}

// Kept apart from idError because the hint has to name the right one of THREE ids a caller could be
// holding: the scope target, the threat, and the note. idError only knows about two of them, and a
// hint that says "not the scope target id" to somebody who passed a threat id is worse than none.
function noteError(err, idParam) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  const out = { error: clip((m ? m[2] : raw).trim(), BODY_PREVIEW) };
  if (status !== undefined) out.http_status = status;
  if (status === 404 && idParam === 'note_id') {
    out.hint = 'Nothing matched. note_id is the NOTE\'s own id, the "id" returned by list_notes and ' +
      'add_note. A threat_id here reports the same way, and so does a note_id from manage_notes, ' +
      'which belongs to a different table entirely.';
  }
  if (status === 400 && idParam === 'threat_id') {
    out.hint = 'The route rejects a missing or malformed threat_id, a threat that does not exist, ' +
      'and a title that is empty once trimmed. Confirm the threat with action:"list" on its scope ' +
      'target: notes are deleted with their threat, so a threat that has been removed takes them ' +
      'with it and there is no restore.';
  }
  return out;
}

// === Flow -> threat links ======================================================================
//
// A threat is a claim about what the application would let somebody do. A flow is a recorded or
// assembled sequence of requests. Mapping one onto the other is what turns "this endpoint probably
// resolves orders globally" into "run this flow and watch it happen", and it is the only thing that
// makes a threat model checkable rather than a document.
//
// Two properties of the underlying table shape everything here.
//
// flow_id IS NOT A FOREIGN KEY, and cannot be. A built flow is a UUID in request_flows; a DETECTED
// flow id is "<session>~<tab>~<root capture>", a composite string that describes where the flow came
// from rather than naming a row. One constraint could only ever cover half of them, and the detected
// half is the half an operator most wants to attach, because it is a record of real traffic. The
// consequence is that the server accepts a link to a flow that does not exist - measured: linking
// "deadbeef-0000-0000-0000-000000000000" succeeds - so every read and write here resolves the id
// against the target's live flow list and says when it did not resolve.
//
// THE THREAT SIDE IS A REAL FOREIGN KEY with ON DELETE CASCADE, so deleting a threat takes its links
// with it and there is no way to end up with a mapping to a threat that is gone.

// loadFlowIndex reads the target's flows once, keyed by id, so a list of links can be checked
// without one request per link. Both kinds are in that one response.
//
// Returns null when the flow list could not be read AT ALL, which is not the same as a target with
// no flows: substituting an empty map would mark every link as an orphan and send somebody hunting
// for a problem that is in the reader rather than in the data.
async function loadFlowIndex(targetID) {
  let body;
  try {
    body = await apiGet(`/replay-request/${targetID}/flows?limit=1000`);
  } catch {
    return null;
  }
  const index = new Map();
  for (const f of (Array.isArray(body.flows) ? body.flows : [])) {
    if (f && f.id) index.set(f.id, f);
  }
  return index;
}

// decorateLink adds what the link row cannot know: whether the flow is still there, and what it is
// called now. The API fills flow_name for a detected link from the stored-names table and otherwise
// substitutes the "(Automated Flow Detected)" placeholder, so a link to a retired flow comes back
// looking exactly like a link to a live one.
function decorateLink(l, flows) {
  const flow = flows ? flows.get(l.flow_id) : undefined;
  return clean({
    threat_id: l.threat_id,
    threat_title: l.threat_title,
    category: l.category,
    mechanism: l.mechanism,
    flow_id: l.flow_id,
    flow_kind: l.flow_kind,
    // The name as the link route reports it, and the name the flow list currently shows. They
    // differ when a built flow was renamed, because the link route only looks names up for the
    // detected kind.
    flow_name: (flow && flow.name) || l.flow_name,
    flow_label: flow ? flow.label : undefined,
    flow_exists: flows ? Boolean(flow) : undefined,
    note: l.note,
    link_id: l.id,
  });
}

// linkError translates the two failures this route actually produces. Kept apart from idError
// because the interesting one, threat_not_found, is about which TARGET the threat is on rather than
// about the id being wrong, and reporting it as "no row matched" sends the reader after the wrong
// thing.
function linkError(err, params) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  const tail = (m ? m[2] : raw).trim();
  let code;
  let message = tail;
  try {
    const parsed = JSON.parse(tail);
    if (parsed && typeof parsed === 'object') {
      code = parsed.error;
      message = parsed.message || parsed.error || tail;
    }
  } catch {
    // Not JSON; the raw text is the message.
  }
  const out = clean({ error: clip(message, BODY_PREVIEW), http_status: status, code });
  if (code === 'threat_not_found') {
    out.hint = 'The threat exists or it does not, but either way it is not on THIS scope target, ' +
      'and the server checks that on purpose: a link made across targets would render on a target ' +
      'whose flows have nothing to do with it. Confirm the threat with action:"list" on this ' +
      'target_id, and check you passed the threat\'s own id rather than a scope target id.';
  } else if (code === 'ids_required') {
    out.hint = 'Both threat_id and flow_id are required, and both are trimmed before use, so a ' +
      'whitespace-only value counts as missing.';
  }
  out.threat_id = params.threat_id;
  out.flow_id = params.flow_id;
  return out;
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
  // Exported for the title-cap suite. The over-budget-but-shrinking branch is the one worth pinning:
  // it is what keeps the 68 pre-cap rows editable.
  threatNameError, MAX_THREAT_NAME, MAX_ATTACK_CUSTOM_NAME,
};
