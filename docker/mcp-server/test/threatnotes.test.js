const test = require('node:test');
const assert = require('node:assert');

// Ad hoc notes on ONE threat, as four actions on manage_threat_model rather than a fifth tool.
//
// The assertions that matter here are about the request bodies, not the projections. The Go route is
// COALESCE-guarded per column, which means update_note must send ONLY the fields the caller
// supplied: a helpful `content: ''` alongside a title change would be accepted by every layer and
// would silently erase the body. Nothing 500s, nothing logs, and the operator finds out by opening
// the note. manage_notes cannot make that mistake because its route rewrites both columns and the
// tool is forced to read the row back first; this one can, which is why it is pinned.
//
// The other half is the id asymmetry. list_notes and add_note are addressed by the THREAT,
// update_note and delete_note by the NOTE. A caller holding the wrong one gets a 404 that says the
// note does not exist, so the required-param checks have to fire before the request goes out.

const SENT = [];

// Flipped by the failure test. It has to be a flag the stub reads rather than a swapped-in function,
// because the tool module destructures the api helpers at import time and holds those references:
// reassigning the export afterwards changes nothing the tool can see.
let failDelete = false;

const NOTES = [
  {
    id: 'aaaaaaaa-0000-0000-0000-000000000001',
    threat_id: '11111111-1111-1111-1111-111111111111',
    title: 'Control arm never passed',
    content: 'y'.repeat(900),
    created_at: '2026-09-01T10:00:00Z',
    updated_at: '2026-09-02T10:00:00Z',
  },
  // A titled note with an empty body. Normal, and the case where a projection that drops empty
  // strings makes "nothing was written" and "the tool forgot the field" look identical.
  {
    id: 'aaaaaaaa-0000-0000-0000-000000000002',
    threat_id: '11111111-1111-1111-1111-111111111111',
    title: 'Come back to this once staging has a second account',
    content: '',
    created_at: '2026-09-01T09:00:00Z',
    updated_at: '2026-09-01T09:00:00Z',
  },
];

let stubbed = null;
try {
  const apiPath = require.resolve('../src/api.js');
  const stub = {
    apiGet: async (p) => {
      SENT.push({ method: 'GET', path: p });
      if (/^\/threat-notes\//.test(p)) return { notes: NOTES };
      if (/^\/threat-model\//.test(p)) return [];
      throw new Error(`API GET ${p} failed (404): not found`);
    },
    apiPost: async (p, body) => {
      SENT.push({ method: 'POST', path: p, body });
      return {
        id: 'aaaaaaaa-0000-0000-0000-000000000009',
        threat_id: body.threat_id,
        title: body.title,
        content: body.content,
        created_at: '2026-09-10T00:00:00Z',
        updated_at: '2026-09-10T00:00:00Z',
      };
    },
    apiPut: async (p, body) => {
      SENT.push({ method: 'PUT', path: p, body });
      // Mirrors the COALESCE guard: a field the payload omits keeps its stored value.
      return { ...NOTES[0], ...body, updated_at: '2026-09-10T00:00:00Z' };
    },
    apiDelete: async (p) => {
      SENT.push({ method: 'DELETE', path: p });
      if (failDelete) throw new Error(`API DELETE ${p} failed (404): no such note`);
      return {};
    },
    apiPatch: async () => ({}),
  };
  require.cache[apiPath] = { id: apiPath, filename: apiPath, loaded: true, exports: stub };
  stubbed = true;
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

let tm = null;
try {
  tm = require('../src/tools/threatmodel');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

const maybe = tm ? test : test.skip;
const wired = tm && stubbed ? test : test.skip;

const THREAT = '11111111-1111-1111-1111-111111111111';
const NOTE = 'aaaaaaaa-0000-0000-0000-000000000001';

const call = (params) => tm.manageThreatModel(params);
const lastOf = (method) => [...SENT].reverse().find((s) => s.method === method);

// === The schema ================================================================================

maybe('the four note actions are offered and the seven existing ones survive', () => {
  const actions = [...tm.manageThreatModelSchema.shape.action._def.values];
  for (const action of ['list_notes', 'add_note', 'update_note', 'delete_note']) {
    assert.ok(actions.includes(action), `manage_threat_model is missing ${action}`);
  }
  for (const action of ['list', 'create', 'update', 'delete',
    'list_flow_links', 'link_flow', 'unlink_flow']) {
    assert.ok(actions.includes(action), `adding the note actions dropped ${action}`);
  }
});

maybe('the note parameters are their own, not the flow-link note', () => {
  const shape = tm.manageThreatModelSchema.shape;
  for (const param of ['note_id', 'note_title', 'note_content']) {
    assert.ok(param in shape, `${param} is missing, so the note actions cannot be called`);
  }
  // `note` is the flow-LINK note and carries re-link overwrite semantics. Sharing it would couple
  // two unrelated writes, so its description has to keep saying which one it is.
  assert.ok('note' in shape, 'the flow-link note parameter was removed');
  assert.match(shape.note.description, /FLOW-LINK NOTE/,
    'the flow-link note must say it is not the threat note');
  assert.match(shape.note_id.description, /manage_notes/,
    'note_id must warn that manage_notes has a different note_id');
});

maybe('the action description teaches all four note actions', () => {
  const d = tm.manageThreatModelSchema.shape.action.description;
  for (const action of ['list_notes', 'add_note', 'update_note', 'delete_note']) {
    assert.match(d, new RegExp(`${action}:`), `${action} is undocumented, so nobody will call it`);
  }
  assert.match(d, /manage_threat_model_notes/,
    'the description must separate these from the similarly named tool');
});

// === list_notes ================================================================================

wired('list_notes refuses to run without the threat id', async () => {
  const out = await call({ action: 'list_notes' });
  assert.match(out.error, /threat_id/);
});

wired('list_notes reads the threat, not the scope target', async () => {
  SENT.length = 0;
  await call({ action: 'list_notes', threat_id: THREAT });
  const get = lastOf('GET');
  assert.equal(get.path, `/threat-notes/${THREAT}`);
});

wired('list_notes previews the bodies rather than returning them', async () => {
  const out = await call({ action: 'list_notes', threat_id: THREAT });
  assert.equal(out.threat_id, THREAT);
  assert.equal(out.total, 2);
  const long = out.data.find((n) => n.id === NOTE);
  assert.equal(long.content_chars, 900, 'the true length must survive the clipping');
  assert.equal(long.clipped, true);
  assert.ok(long.preview.length < 900, 'the whole body came back from a listing');
});

wired('an empty body is reported as empty rather than as absent', async () => {
  const out = await call({ action: 'list_notes', threat_id: THREAT });
  const blank = out.data.find((n) => n.id === 'aaaaaaaa-0000-0000-0000-000000000002');
  assert.equal(blank.content_chars, 0,
    'content_chars must always be present, or an empty note and a forgotten field read the same');
  assert.ok(!('preview' in blank), 'an empty body should have no preview at all');
  assert.ok(blank.title, 'the title is what identifies a note and must never be dropped');
});

wired('detail full is how a note is actually read, since there is no get_note', async () => {
  const out = await call({ action: 'list_notes', threat_id: THREAT, detail: 'full' });
  const long = out.data.find((n) => n.id === NOTE);
  assert.equal(long.clipped, false, 'a 900 character note should come back whole at detail full');
  assert.equal(long.preview.length, 900);
});

// === add_note ==================================================================================

wired('add_note refuses a missing threat id and a missing or whitespace title', async () => {
  assert.match((await call({ action: 'add_note', note_title: 'x' })).error, /threat_id/);
  assert.match((await call({ action: 'add_note', threat_id: THREAT })).error, /note_title/);
  assert.match((await call({ action: 'add_note', threat_id: THREAT, note_title: '   ' })).error,
    /whitespace/);
});

wired('add_note posts the threat id, the title and an empty body by default', async () => {
  SENT.length = 0;
  const out = await call({ action: 'add_note', threat_id: THREAT, note_title: 'Blocked on MFA' });
  const post = lastOf('POST');
  assert.equal(post.path, '/threat-notes');
  assert.deepEqual(post.body, { threat_id: THREAT, title: 'Blocked on MFA', content: '' });
  assert.equal(out.created, true);
  assert.equal(out.id, 'aaaaaaaa-0000-0000-0000-000000000009');
  assert.equal(out.content_chars, 0);
});

wired('add_note sends the body it was given', async () => {
  SENT.length = 0;
  await call({
    action: 'add_note', threat_id: THREAT,
    note_title: 'Blocked on MFA', note_content: 'The reset step needs a code we cannot receive.',
  });
  assert.equal(lastOf('POST').body.content, 'The reset step needs a code we cannot receive.');
});

// === update_note, and the blanking trap ========================================================

wired('update_note refuses without a note id, and refuses an empty change', async () => {
  assert.match((await call({ action: 'update_note', note_title: 'x' })).error, /note_id/);
  const nothing = await call({ action: 'update_note', note_id: NOTE });
  assert.match(nothing.error, /note_title or a note_content/);
});

wired('update_note refuses to blank a title', async () => {
  const out = await call({ action: 'update_note', note_id: NOTE, note_title: '  ' });
  assert.match(out.error, /cannot be blanked/);
});

wired('update_note sends ONLY the title when only the title changed', async () => {
  SENT.length = 0;
  await call({ action: 'update_note', note_id: NOTE, note_title: 'Control arm passed on retry' });
  const put = lastOf('PUT');
  assert.equal(put.path, `/threat-notes/${NOTE}`);
  assert.equal(put.body.title, 'Control arm passed on retry');
  // THE WHOLE POINT. The route preserves a column the payload omits, so sending content here at any
  // value would overwrite a body the caller never mentioned.
  assert.ok(!('content' in put.body),
    'update_note sent a content field it was not given, which blanks the body it is guarding');
});

wired('update_note sends ONLY the content when only the content changed', async () => {
  SENT.length = 0;
  await call({ action: 'update_note', note_id: NOTE, note_content: 'Retried with a second account.' });
  const put = lastOf('PUT');
  assert.equal(put.body.content, 'Retried with a second account.');
  assert.ok(!('title' in put.body),
    'update_note sent a title it was not given, which renames a note nobody asked to rename');
});

wired('an explicit empty content is honoured as a deliberate blanking', async () => {
  SENT.length = 0;
  const out = await call({ action: 'update_note', note_id: NOTE, note_content: '' });
  const put = lastOf('PUT');
  assert.ok('content' in put.body,
    'an explicit "" must reach the route; dropping it turns a blanking into a no-op');
  assert.equal(put.body.content, '');
  assert.equal(out.updated, true);
  assert.equal(out.content_chars, 0);
});

wired('a read-back merge is never attempted, because the route does not need one', async () => {
  SENT.length = 0;
  await call({ action: 'update_note', note_id: NOTE, note_title: 'Renamed' });
  assert.ok(!SENT.some((s) => s.method === 'GET'),
    'update_note read the note back first, which is the race the SQL guard exists to remove');
});

// === delete_note ===============================================================================

wired('delete_note refuses without a note id', async () => {
  assert.match((await call({ action: 'delete_note', threat_id: THREAT })).error, /note_id/);
});

wired('delete_note deletes by the note id and says which one went', async () => {
  SENT.length = 0;
  const out = await call({ action: 'delete_note', note_id: NOTE });
  assert.equal(lastOf('DELETE').path, `/threat-notes/${NOTE}`);
  assert.deepEqual(out, { deleted: true, note_id: NOTE });
});

// === failures ==================================================================================

wired('a 404 on a note id says which of the three ids it might be', async () => {
  failDelete = true;
  try {
    const out = await call({ action: 'delete_note', note_id: NOTE });
    assert.equal(out.http_status, 404);
    assert.match(out.hint, /manage_notes/,
      'the hint has to name the other tool whose note_id looks identical from here');
    assert.ok(!out.deleted, 'a failed delete must not report itself as a deletion');
  } finally {
    failDelete = false;
  }
});
