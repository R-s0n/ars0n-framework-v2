const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');
const { clip, resolveLimit, DEFAULTS } = require('../utils/clip');

// Free-text notes attached to a scope target: what you worked out, what you already tried, what to
// come back to. Nothing else reads them, which is the point. Everything else the framework stores
// is a scanner artefact with a schema, and the reasoning that connects two artefacts has had
// nowhere to live.
//
// list is deliberately not a bulk read. A note body is prose an operator typed, so the length is
// unbounded and a target accumulates them over a whole engagement; a list that returned every body
// in full is one long-running engagement away from filling the response cap with text the caller
// did not ask for. So list previews and get reads. The preview is sized to recognise a note you
// already know about, not to read one.
//
// The addressing is asymmetric and it will catch a caller out: list and create are addressed by the
// SCOPE TARGET, get, update and delete by the NOTE's own id. There is also no route that fetches a
// note by its id alone, so anything needing to read one back resolves it through the target's list.

// What a row in a listing shows of a note body. Small on purpose: the title is what identifies a
// note, and the preview only has to confirm you have the right one before spending a get on it.
const PREVIEW_CHARS = 240;
// How many notes a listing returns before it starts truncating.
const LIST_DEFAULT = 25;

const manageNotesSchema = z.object({
  action: z.enum(['list', 'get', 'create', 'update', 'delete']).describe(
    'list: the notes on a target, newest edit first, each with a CLIPPED preview of its body ' +
    'rather than the body. Use it to find the note you want. ' +
    'get: one note with its full content. ' +
    'create: add a note to a target. ' +
    'update: change a note\'s title or content. Either one alone is enough; the other is read back ' +
    'and preserved. ' +
    'delete: remove a note. There is no restore.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for list, get and create. Optional but worth passing on ' +
    'update: without it the note has to be found by asking every target for its notes, which is ' +
    'one request per target.'),
  note_id: z.string().uuid().optional().describe(
    'The note\'s own UUID, the "id" returned by list, get and create. Required for get, update and ' +
    'delete. A scope target id here does not report as the wrong kind of id, it reports as the ' +
    'note not existing, so check which one you are holding.'),

  title: z.string().optional().describe(
    'The note title, which is what identifies it in a listing. Required on create and rejected if ' +
    'it is only whitespace. On update it replaces the existing title; omit it to keep it.'),
  content: z.string().optional().describe(
    'The note body. Optional on create, where it defaults to empty. On update it replaces the ' +
    'existing body wholesale, and an explicit empty string is honoured as a deliberate blanking ' +
    'rather than treated as "not supplied".'),

  pattern: z.string().optional().describe(
    'list: case-insensitive substring match over the title and the body. The body is searched in ' +
    'full even though only a preview comes back, so this finds notes whose match sits past the ' +
    'preview cut.'),
  max_results: z.number().optional().describe(
    `list: how many notes to return. Default ${LIST_DEFAULT}.`),
  max_content_chars: z.number().optional().describe(
    `How much note body to return: per row on list (default ${PREVIEW_CHARS}), for the whole note ` +
    `on get (default ${DEFAULTS.single}). Raise it on get when a note is longer than the default ` +
    'and you need the rest of it.'),
});

async function manageNotes(params) {
  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };

      let rows;
      try {
        rows = await notesFor(params.target_id);
      } catch (err) {
        return apiError(err, 'target_id');
      }
      if (params.pattern) {
        const needle = params.pattern.toLowerCase();
        rows = rows.filter((n) =>
          String(n.title || '').toLowerCase().includes(needle) ||
          String(n.content || '').toLowerCase().includes(needle));
      }

      // The budget is PER ROW, so it is divided by the row count rather than granted to each of
      // them. Without that, raising it on a target holding forty notes multiplies by forty.
      const limit = resolveLimit(params.max_content_chars, PREVIEW_CHARS, rows.length);
      const projected = rows.map((n) => previewRow(n, limit));
      // The API hands back the whole set, so rows.length really is the total here.
      return limitResults(projected, clampLimit(params.max_results, LIST_DEFAULT));
    }

    case 'get': {
      if (!params.target_id || !params.note_id) {
        return { error: 'get needs target_id and note_id' };
      }
      let note;
      try {
        note = (await notesFor(params.target_id)).find((n) => n.id === params.note_id);
      } catch (err) {
        return apiError(err, 'target_id');
      }
      if (!note) return await missing(params.note_id, params.target_id);
      return fullNote(note, resolveLimit(params.max_content_chars, DEFAULTS.single));
    }

    case 'create': {
      if (!params.target_id) return { error: 'create needs target_id' };
      // The server applies the same rule and answers 400. Checking here costs nothing and says why.
      if (!params.title || !params.title.trim()) {
        return { error: 'create needs a title with something in it; whitespace alone is rejected' };
      }
      try {
        const out = await apiPost('/notes', {
          scope_target_id: params.target_id,
          title: params.title,
          content: params.content !== undefined ? params.content : '',
        });
        return { created: true, ...fullNote(out, DEFAULTS.single) };
      } catch (err) {
        return apiError(err, 'target_id');
      }
    }

    case 'update': {
      if (!params.note_id) return { error: 'update needs note_id, not target_id' };
      if (params.title === undefined && params.content === undefined) {
        return { error: 'update needs a title or a content, otherwise there is nothing to change' };
      }
      if (params.title !== undefined && !params.title.trim()) {
        return { error: 'title cannot be blanked; a note is identified by its title' };
      }

      // PUT writes both columns unconditionally, so sending one field would blank the other. The
      // undefined test matters: content:"" is a caller emptying a note on purpose and has to survive.
      let body = { title: params.title, content: params.content };
      if (body.title === undefined || body.content === undefined) {
        const current = await findNote(params.note_id, params.target_id);
        // findNote has already looked everywhere, so there is nowhere left for it to be.
        if (!current) return notFound(params.note_id);
        if (body.title === undefined) body.title = current.title || '';
        if (body.content === undefined) body.content = current.content || '';
      }

      try {
        return { updated: true, ...fullNote(await apiPut(`/notes/${params.note_id}`, body), DEFAULTS.single) };
      } catch (err) {
        return apiError(err, 'note_id');
      }
    }

    case 'delete': {
      if (!params.note_id) return { error: 'delete needs note_id, not target_id' };
      try {
        await apiDelete(`/notes/${params.note_id}`);
      } catch (err) {
        return apiError(err, 'note_id');
      }
      return { deleted: true, note_id: params.note_id };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === fetching ==================================================================================

// The route always answers {"notes":[...]}, but a missing key would turn into `undefined.find` two
// frames away from the cause, so it is normalised once here.
async function notesFor(targetId) {
  const body = await apiGet(`/notes/${targetId}`);
  return Array.isArray(body && body.notes) ? body.notes : [];
}

// Nothing fetches a note by its own id, so a caller who has only the note id can still be served by
// asking each target for its notes. That is one request per scope target, which is why target_id is
// worth passing and why it is tried first.
async function findNote(noteId, targetId) {
  if (targetId) {
    const hit = (await notesFor(targetId)).find((n) => n.id === noteId);
    if (hit) return hit;
  }
  return sweepForNote(noteId, targetId);
}

// skip is the target already known not to hold the note, so the sweep does not ask it twice.
async function sweepForNote(noteId, skip) {
  for (const t of await scopeTargets()) {
    if (t.id === skip) continue;
    const hit = (await notesFor(t.id)).find((n) => n.id === noteId);
    if (hit) return hit;
  }
  return null;
}

async function scopeTargets() {
  const body = await apiGet('/scopetarget/read');
  const rows = Array.isArray(body) ? body : (Array.isArray(body && body.targets) ? body.targets : []);
  return rows.filter((t) => t && t.id);
}

// A note that is not on the target you named is usually a note on a different one, and saying so is
// the difference between a caller correcting the id and a caller concluding the note was deleted.
async function missing(noteId, targetId) {
  if (targetId) {
    // Straight to the sweep: the caller's target has just been read and does not hold it.
    const elsewhere = await sweepForNote(noteId, targetId);
    if (elsewhere) {
      return {
        error: 'that note exists but belongs to a different scope target',
        note_id: noteId,
        actual_target_id: elsewhere.scope_target_id,
      };
    }
  }
  return notFound(noteId);
}

function notFound(noteId) {
  return { error: 'no note with that note_id', note_id: noteId };
}

// === projections ===============================================================================

function previewRow(n, limit) {
  const content = typeof n.content === 'string' ? n.content : '';
  const row = {
    id: n.id,
    title: n.title,
    content_chars: content.length,
    updated_at: n.updated_at,
  };
  // An empty body is worth showing as an absent preview rather than an empty string, because those
  // read the same in JSON and only one of them means "nothing was written here".
  if (content) {
    row.preview = clip(content, limit);
    row.clipped = content.length > limit;
  }
  return row;
}

function fullNote(n, limit) {
  const content = typeof n.content === 'string' ? n.content : '';
  return {
    id: n.id,
    scope_target_id: n.scope_target_id,
    title: n.title,
    content: clip(content, limit),
    // Compared against the budget rather than against the returned string: clip appends a marker,
    // so a body just over the limit comes back LONGER than it started and a length test would say
    // it was not clipped.
    clipped: content.length > limit,
    content_chars: content.length,
    created_at: n.created_at,
    updated_at: n.updated_at,
  };
}

// The API helpers flatten a failure into one message string. Pulling the status back out is what
// lets a 404 be reported as the wrong id rather than as the server being down.
function apiError(err, idParam) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  const out = { error: clip((m ? m[2] : raw).trim(), PREVIEW_CHARS) };
  if (status !== undefined) out.http_status = status;
  if (status === 404 && idParam === 'note_id') {
    out.hint = 'Nothing matched. note_id is the note\'s own id, the "id" field returned by list, ' +
               'get and create, not the scope target id that addresses list and create.';
  }
  if (status === 400 && idParam === 'target_id') {
    out.hint = 'A create is rejected when scope_target_id is missing or the title is empty once ' +
               'trimmed. Check the target still exists: notes are deleted with their target.';
  }
  return out;
}

module.exports = { manageNotesSchema, manageNotes };
