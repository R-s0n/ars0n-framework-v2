import { useState } from 'react';
import { Button, Form, Spinner } from 'react-bootstrap';

// Ad hoc notes on ONE threat: what the operator worked out while reading and testing it.
//
// WHY IT LIVES IN THE ACCORDION BODY AND NOT IN THE THREAT MODEL MODAL. That modal is the AUTHORING
// form - it owns an isEditing state and a Save button that writes the whole threat through a
// full-replace PUT. A note is written while READING and TESTING, which is what this accordion is:
// it is already where the flow links, the severity badges and the TESTED? buttons live. A second
// independent Save inside the authoring form would invite clicking the wrong one and losing the form.
//
// WHY IT SITS BETWEEN THE FLOW LINKS AND THE VERDICT ROW. Order of thought: the evidence (which
// flows demonstrate this), then the operator's own reasoning about it, then the verdict. The verdict
// row must stay last and immediately findable at the bottom, which is also why this block is
// COLLAPSED BY DEFAULT - an expanded notes list on every threat would push the buttons people click
// most off the bottom of a body that already runs one-sentence, summary, steps, impact and controls.
//
// COLLAPSED ALSO MEANS UNFETCHED. The list route is keyed by threat_id with no bulk form, so the
// alternative to lazy loading is one request per threat: 193 of them on the live target to draw
// blocks nobody opened. The consequence has to be accepted rather than worked around: the toggle
// cannot show a count until the notes have been read, so it says "Notes" and gains "(n)" afterwards.
// It must never say "0 notes" before the read, because that is an assertion, not a placeholder.

// The new-note form is the same one editor as an edit, held under a sentinel id so "one editor open
// at a time" covers adding too. Without it, an add form and an edit form could be open together and
// the Save button under each would be ambiguous about which draft it belonged to.
const ADDING = '__new__';

// "3d ago" answers the only question the list asks of a timestamp, which is whether this note is
// current. The exact time stays one hover away. Anything unparseable prints nothing at all rather
// than the string "Invalid Date", which reads like a corrupted note.
const relativeTime = (value) => {
  const t = Date.parse(value);
  if (!Number.isFinite(t)) return '';
  const seconds = Math.round((Date.now() - t) / 1000);
  if (seconds < 45) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(t).toISOString().slice(0, 10);
};

const exactTime = (value) => {
  const t = Date.parse(value);
  return Number.isFinite(t) ? new Date(t).toLocaleString() : '';
};

// How much body text is shown before the row offers to expand. A note is unbounded prose and several
// long ones stacked inside an accordion body would bury the threat they are about.
const PREVIEW_CHARS = 320;

// Presentational, like ThreatFlowLinks: every read and every write is the caller's, and each writer
// must resolve TRUTHY ON SUCCESS. That return value is the only thing that decides whether a draft
// may be thrown away, and a failed save that cleared the editor would destroy the paragraph the
// operator just wrote.
//
// `loaded` is a separate prop from `notes` on purpose. An empty array cannot distinguish "nothing has
// been read yet" from "this threat genuinely has no notes", and `error` is the third case again -
// three sentences that must never collapse into one.
const ThreatNotes = ({
  threat,
  notes = [],
  loaded = false,
  loading = false,
  error = '',
  actionError = '',
  busy = false,
  onOpen,
  onCreate,
  onUpdate,
  onDelete,
}) => {
  const threatId = threat && threat.id;
  const [open, setOpen] = useState(false);
  // Which note is being edited, or ADDING. One at a time, for the same reason ThreatFlowLinks keeps
  // one note editor: this block is nested inside an accordion body that already carries the threat's
  // whole write-up, and several open textareas would bury it.
  const [editing, setEditing] = useState('');
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  // Set once the operator has tried to save, so the missing-title message appears in response to an
  // action rather than nagging at an empty form the moment it opens.
  const [triedSave, setTriedSave] = useState(false);
  // Which note has been asked to be deleted. Inline rather than a modal: a dialog stacked over an
  // accordion body is more friction than this deserves, and the second click is the whole point -
  // there is no restore anywhere in this application.
  const [confirmId, setConfirmId] = useState('');
  // Which note bodies the operator has expanded past the preview, keyed by the note's own id and
  // never by index, so a list that reorders after a save cannot expand a different note.
  const [expanded, setExpanded] = useState({});

  const titleMissing = title.trim() === '';

  const closeEditor = () => {
    setEditing('');
    setTitle('');
    setContent('');
    setTriedSave(false);
  };

  const toggle = () => {
    const next = !open;
    setOpen(next);
    // Read on the FIRST open only. Re-reading on every collapse and expand would be a request per
    // click for a list nothing else on the page writes. A failed read leaves `loaded` false, so
    // re-opening after a failure retries, which is the retry path.
    if (next && !loaded && !loading && onOpen) onOpen(threatId);
  };

  const startAdd = () => {
    setEditing(ADDING);
    setTitle('');
    setContent('');
    setTriedSave(false);
    setConfirmId('');
  };

  const startEdit = (note) => {
    setEditing(String(note.id));
    setTitle(String(note.title || ''));
    setContent(String(note.content || ''));
    setTriedSave(false);
    setConfirmId('');
  };

  const save = async () => {
    setTriedSave(true);
    // Validated inline. The title is what the note is findable by later, and a wall of "Untitled
    // note" rows is a list you cannot read, so an empty one is refused rather than defaulted.
    if (titleMissing) return;
    const trimmed = title.trim();
    let ok = false;
    if (editing === ADDING) {
      if (!onCreate) return;
      ok = await onCreate(threatId, trimmed, content);
    } else {
      if (!onUpdate) return;
      // Both fields, because the editor loaded both and the operator saw both. The server preserves
      // an omitted key rather than blanking it, so sending content explicitly is what makes clearing
      // a body possible at all.
      ok = await onUpdate(threatId, editing, { title: trimmed, content });
    }
    if (ok) closeEditor();
  };

  const remove = async (note) => {
    if (!onDelete) return;
    const ok = await onDelete(threatId, note.id);
    if (ok) {
      setConfirmId('');
      if (editing === String(note.id)) closeEditor();
    }
  };

  const editor = (
    <div className="mt-2 px-2 py-2" style={{ backgroundColor: '#212529', border: '1px solid #343a40', borderRadius: '0.25rem' }}>
      <Form.Control
        size="sm"
        data-bs-theme="dark"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        placeholder="Note title"
        aria-label="Note title"
        isInvalid={triedSave && titleMissing}
        className="mb-2"
        style={{ fontSize: '0.8rem' }}
      />
      {triedSave && titleMissing && (
        <div className="text-warning mb-2" style={{ fontSize: '0.7rem' }}>
          A note needs a title. It is what this note is findable by later.
        </div>
      )}
      <Form.Control
        as="textarea"
        rows={4}
        size="sm"
        data-bs-theme="dark"
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="What you worked out about this threat"
        aria-label="Note content"
        style={{ fontSize: '0.78rem' }}
      />
      <div className="d-flex align-items-center flex-wrap mt-2" style={{ gap: '0.6rem' }}>
        <Button
          variant="outline-light"
          size="sm"
          style={{ fontSize: '0.72rem' }}
          disabled={busy}
          onClick={save}
        >
          {busy ? <Spinner animation="border" size="sm" /> : (editing === ADDING ? 'Save note' : 'Save changes')}
        </Button>
        <Button
          variant="link"
          size="sm"
          className="p-0 text-white-50 text-decoration-none"
          style={{ fontSize: '0.72rem' }}
          disabled={busy}
          onClick={closeEditor}
        >
          Cancel
        </Button>
        <span className="text-white-50" style={{ fontSize: '0.68rem' }}>
          A note with no body is fine. The title on its own is a note.
        </span>
      </div>
    </div>
  );

  return (
    <div className="mt-3 pt-3 border-top border-secondary">
      <div className="d-flex align-items-center flex-wrap" style={{ gap: '0.6rem' }}>
        <Button
          variant="link"
          size="sm"
          className="p-0 text-decoration-none"
          style={{ fontSize: '0.72rem', letterSpacing: '0.04em', color: '#8ab4f8' }}
          onClick={toggle}
          aria-expanded={open}
          title="Your own notes on this threat. Stored on the threat, and deleted with it."
        >
          <i className={`bi ${open ? 'bi-chevron-down' : 'bi-chevron-right'} me-1`} />
          {/* The count appears only once the read has happened. Before that the toggle says nothing
              about how many notes there are, because it does not know and "0" would be a claim. */}
          NOTES{loaded ? ` (${notes.length})` : ''}
        </Button>
        {loading && <Spinner animation="border" size="sm" variant="secondary" />}
        {/* Gated on NO editor being open, not just on the add editor. startAdd() overwrites title
            and content unconditionally, so offering this while a note is being edited would throw
            that edit away on a single click with nothing said. "One editor at a time" has to be
            enforced at both entry points or it is not a rule, it is a coincidence. */}
        {open && onCreate && editing === '' && (
          <Button
            variant="outline-light"
            size="sm"
            style={{ fontSize: '0.72rem' }}
            disabled={busy}
            onClick={startAdd}
          >
            Add note
          </Button>
        )}
      </div>

      {open && (
        <div className="mt-2">
          {editing === ADDING && editor}

          {actionError && (
            <div className="text-danger mt-2" style={{ fontSize: '0.76rem' }}>
              {actionError}
            </div>
          )}

          {/* Three states, never collapsed into one. A failed read rendered as "no notes yet" would
              tell the operator this threat has nothing written on it when the truth is that nobody
              knows, and that is a claim about the server this screen cannot make. */}
          {error ? (
            <div className="text-warning mt-2" style={{ fontSize: '0.78rem' }}>
              The notes for this threat could not be read, so they are unknown: {error}
              <Button
                variant="link"
                size="sm"
                className="p-0 ms-2 text-decoration-none"
                style={{ fontSize: '0.72rem', color: '#8ab4f8' }}
                disabled={loading}
                onClick={() => onOpen && onOpen(threatId)}
              >
                Try again
              </Button>
            </div>
          ) : !loaded ? (
            !loading && (
              <div className="text-white-50 fst-italic mt-2" style={{ fontSize: '0.78rem' }}>
                Notes for this threat have not been read yet.
              </div>
            )
          ) : notes.length === 0 ? (
            <div className="text-white-50 fst-italic mt-2" style={{ fontSize: '0.78rem' }}>
              No notes on this threat yet.
            </div>
          ) : (
            <div className="mt-2">
              {notes.map((note) => {
                const id = String(note.id);
                const body = String(note.content == null ? '' : note.content);
                const long = body.length > PREVIEW_CHARS;
                const shown = long && !expanded[id] ? `${body.slice(0, PREVIEW_CHARS)}...` : body;
                return (
                  <div
                    key={id}
                    className="mb-2 px-2 py-2"
                    style={{
                      backgroundColor: '#212529',
                      border: '1px solid #343a40',
                      borderRadius: '0.25rem',
                    }}
                  >
                    <div className="d-flex align-items-start justify-content-between" style={{ gap: '0.5rem' }}>
                      <div className="flex-grow-1" style={{ minWidth: 0 }}>
                        <div className="text-white fw-semibold" style={{ fontSize: '0.82rem', wordBreak: 'break-word' }}>
                          {note.title}
                        </div>
                        <div className="text-white-50" style={{ fontSize: '0.68rem' }} title={exactTime(note.updated_at)}>
                          edited {relativeTime(note.updated_at)}
                        </div>
                      </div>
                      {editing !== id && (
                        <div className="d-flex align-items-center flex-shrink-0" style={{ gap: '0.4rem' }}>
                          {/* Disabled rather than hidden while another editor is open, because a
                              control that vanishes reads as a control that does not exist. The
                              reason is in the tooltip. Without this, startEdit() on a second note
                              silently replaces the draft in the first one, and the same for a note
                              being edited while the add form is open. Delete is deliberately NOT
                              gated: removing a different note leaves the open draft untouched, and
                              remove() already closes the editor when it is that note's own. */}
                          {onUpdate && (
                            <Button
                              variant="link"
                              size="sm"
                              className="p-0 text-decoration-none"
                              style={{ fontSize: '0.7rem', color: '#8ab4f8' }}
                              disabled={busy || editing !== ''}
                              title={editing !== ''
                                ? 'Save or cancel the note you have open first.'
                                : undefined}
                              onClick={() => startEdit(note)}
                            >
                              Edit
                            </Button>
                          )}
                          {/* The one destructive control in this block, and the only place a second
                              click is asked for. Nothing in this application restores a deleted row. */}
                          {onDelete && (confirmId === id ? (
                            <>
                              <span className="text-warning" style={{ fontSize: '0.68rem' }}>
                                Delete for good?
                              </span>
                              <Button
                                variant="danger"
                                size="sm"
                                style={{ fontSize: '0.7rem' }}
                                disabled={busy}
                                onClick={() => remove(note)}
                              >
                                {busy ? <Spinner animation="border" size="sm" /> : 'Delete'}
                              </Button>
                              <Button
                                variant="link"
                                size="sm"
                                className="p-0 text-white-50 text-decoration-none"
                                style={{ fontSize: '0.7rem' }}
                                disabled={busy}
                                onClick={() => setConfirmId('')}
                              >
                                Keep
                              </Button>
                            </>
                          ) : (
                            <Button
                              variant="link"
                              size="sm"
                              className="p-0 text-decoration-none"
                              style={{ fontSize: '0.7rem', color: '#f1959b' }}
                              disabled={busy}
                              onClick={() => setConfirmId(id)}
                            >
                              Delete
                            </Button>
                          ))}
                        </div>
                      )}
                    </div>

                    {editing === id ? editor : body && (
                      <>
                        <div
                          className="text-white-50 mt-1"
                          style={{ fontSize: '0.76rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
                        >
                          {shown}
                        </div>
                        {long && (
                          <Button
                            variant="link"
                            size="sm"
                            className="p-0 text-decoration-none"
                            style={{ fontSize: '0.68rem', color: '#8ab4f8' }}
                            onClick={() => setExpanded((prev) => ({ ...prev, [id]: !prev[id] }))}
                          >
                            {expanded[id] ? 'Show less' : 'Show more'}
                          </Button>
                        )}
                      </>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ThreatNotes;
