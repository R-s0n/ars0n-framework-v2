import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { Modal, Row, Col, Button, Spinner, Badge, ListGroup, Form, Alert } from 'react-bootstrap';

// A note the user has started but never POSTed has no server id yet. It carries this sentinel so
// selection, dirty tracking and the empty states can treat it exactly like a saved note, and so an
// abandoned draft never reaches the database.
const NEW_NOTE_ID = '__new__';

function formatTimestamp(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
}

// The API hands back notes ordered by updated_at DESC. Saving changes that order, so the list is
// re-sorted here rather than refetched, which keeps it identical to what a reload would show
// without a round trip that would make the just-saved note flicker.
function sortByUpdated(list) {
  return [...list].sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));
}

const NotesModal = ({ show, handleClose, scopeTargets, activeTarget }) => {
  const [targetId, setTargetId] = useState('');
  const [notes, setNotes] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);
  // Set when the user tried to move away from unsaved edits. It holds the navigation that was
  // blocked so it can be replayed once they answer, rather than silently dropping what they typed.
  const [pendingNav, setPendingNav] = useState(null);

  const targets = useMemo(() => (Array.isArray(scopeTargets) ? scopeTargets : []), [scopeTargets]);

  const isNew = selectedId === NEW_NOTE_ID;
  const selectedNote = useMemo(
    () => (isNew ? null : notes.find((n) => n.id === selectedId) || null),
    [notes, selectedId, isNew]
  );

  // A brand new note is dirty the moment anything is typed into it; a saved one only when it no
  // longer matches the copy the server returned.
  const isDirty = useMemo(() => {
    if (isNew) return title.trim() !== '' || content !== '';
    if (!selectedNote) return false;
    return title !== (selectedNote.title || '') || content !== (selectedNote.content || '');
  }, [isNew, selectedNote, title, content]);

  // The unsaved draft is shown at the top of the list without being pushed into `notes`, so a
  // refetch can never resurrect it and its label can track the title field as it is typed.
  const listItems = useMemo(() => {
    if (!isNew) return notes;
    return [{ id: NEW_NOTE_ID, title: title.trim(), updated_at: null }, ...notes];
  }, [notes, isNew, title]);

  const prevShow = useRef(false);
  useEffect(() => {
    // Only on the closed-to-open transition. Following activeTarget at any other time would swap
    // the target out from under an open editor.
    if (show && !prevShow.current) {
      setTargetId(activeTarget?.id || '');
      setSelectedId(null);
      setTitle('');
      setContent('');
      setError('');
      setPendingNav(null);
      setConfirmDelete(false);
    }
    prevShow.current = show;
  }, [show, activeTarget]);

  const fetchNotes = useCallback(async (id) => {
    if (!id) {
      setNotes([]);
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`/api/notes/${id}`);
      if (!res.ok) throw new Error(`Could not load notes for this target (${res.status}).`);
      const data = await res.json();
      setNotes(sortByUpdated(Array.isArray(data?.notes) ? data.notes : []));
    } catch (e) {
      console.error('[Notes] fetchNotes failed:', e);
      setError(e.message);
      setNotes([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (show) fetchNotes(targetId);
  }, [show, targetId, fetchNotes]);

  const performNav = useCallback((nav) => {
    if (!nav) return;
    setError('');
    if (nav.kind === 'note') {
      setSelectedId(nav.note.id);
      setTitle(nav.note.title || '');
      setContent(nav.note.content || '');
    } else if (nav.kind === 'new') {
      setSelectedId(NEW_NOTE_ID);
      setTitle('');
      setContent('');
    } else if (nav.kind === 'target') {
      setTargetId(nav.targetId);
      setSelectedId(null);
      setTitle('');
      setContent('');
    } else if (nav.kind === 'close') {
      setSelectedId(null);
      setTitle('');
      setContent('');
      handleClose();
    }
  }, [handleClose]);

  const requestNav = useCallback((nav) => {
    if (isDirty) setPendingNav(nav);
    else performNav(nav);
  }, [isDirty, performNav]);

  // Returns whether the save landed, because "Save and Continue" must not navigate away on a
  // failure that would take the unsaved text with it.
  const handleSave = useCallback(async () => {
    const trimmed = title.trim();
    if (!targetId) {
      setError('Select a scope target before saving.');
      return false;
    }
    if (!trimmed) {
      setError('A note needs a title before it can be saved.');
      return false;
    }
    setSaving(true);
    setError('');
    try {
      const res = isNew
        ? await fetch('/api/notes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope_target_id: targetId, title: trimmed, content }),
          })
        : await fetch(`/api/notes/${selectedId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title: trimmed, content }),
          });
      if (res.status === 404) {
        // Someone deleted it elsewhere. Resync the list but keep the text on screen so it can be
        // copied out or re-created rather than vanishing with the failed request.
        await fetchNotes(targetId);
        throw new Error('This note no longer exists on the server. Your text is still here, save it as a new note.');
      }
      if (!res.ok) throw new Error(`Save failed (${res.status}).`);
      const saved = await res.json();
      setNotes((prev) => sortByUpdated([saved, ...prev.filter((n) => n.id !== saved.id)]));
      setSelectedId(saved.id);
      setTitle(saved.title || '');
      setContent(saved.content || '');
      return true;
    } catch (e) {
      console.error('[Notes] save failed:', e);
      setError(e.message);
      return false;
    } finally {
      setSaving(false);
    }
  }, [title, content, targetId, isNew, selectedId, fetchNotes]);

  const handleDeleteConfirmed = useCallback(async () => {
    // An unsaved draft was never sent anywhere, so discarding it is purely local.
    if (isNew) {
      setConfirmDelete(false);
      setSelectedId(null);
      setTitle('');
      setContent('');
      return;
    }
    if (!selectedNote) return;
    setDeleting(true);
    try {
      const res = await fetch(`/api/notes/${selectedNote.id}`, { method: 'DELETE' });
      // A 404 means it is already gone, which is the state we were asking for anyway.
      if (!res.ok && res.status !== 404) throw new Error(`Delete failed (${res.status}).`);
      setNotes((prev) => prev.filter((n) => n.id !== selectedNote.id));
      setSelectedId(null);
      setTitle('');
      setContent('');
    } catch (e) {
      console.error('[Notes] delete failed:', e);
      setError(e.message);
    } finally {
      setDeleting(false);
      setConfirmDelete(false);
    }
  }, [isNew, selectedNote]);

  // Ctrl/Cmd+S is reflex in anything with a textarea. Without this the browser's own save dialog
  // opens over the modal and the note stays unsaved.
  const handleEditorKeyDown = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      if (isDirty && !saving) handleSave();
    }
  };

  const hasSelection = isNew || !!selectedNote;

  return (
    <>
      <Modal
        data-bs-theme="dark"
        show={show}
        onHide={() => requestNav({ kind: 'close' })}
        size="xl"
        dialogClassName="modal-90w"
        scrollable
      >
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">Notes</Modal.Title>
        </Modal.Header>
        <Modal.Body className="text-white" style={{ minHeight: '72vh' }}>
          {error && (
            <Alert variant="danger" className="py-2" dismissible onClose={() => setError('')}>
              {error}
            </Alert>
          )}

          <Row className="mb-3">
            <Col md={6}>
              <Form.Label className="text-white-50 small text-uppercase mb-1">Scope Target</Form.Label>
              <Form.Select
                value={targetId}
                onChange={(e) => requestNav({ kind: 'target', targetId: e.target.value })}
              >
                <option value="">Select a scope target…</option>
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    [{t.type}] {t.scope_target}
                  </option>
                ))}
              </Form.Select>
            </Col>
          </Row>

          {!targetId ? (
            <div className="text-center text-white-50 py-5">
              <i className="bi bi-journal-text d-block mb-2" style={{ fontSize: '2rem' }}></i>
              Choose a scope target above to see and write its notes.
            </div>
          ) : (
            <Row>
              {/* LEFT: note titles, newest updated first */}
              <Col md={4} className="border-end border-secondary" style={{ maxHeight: '64vh', overflowY: 'auto' }}>
                <Button
                  variant="outline-danger"
                  size="sm"
                  className="w-100 mb-2"
                  onClick={() => requestNav({ kind: 'new' })}
                >
                  <i className="bi bi-plus-lg me-1"></i>New Note
                </Button>

                {loading ? (
                  <div className="text-center py-3">
                    <Spinner size="sm" animation="border" variant="danger" />
                  </div>
                ) : listItems.length === 0 ? (
                  <div className="text-white-50 small fst-italic">
                    No notes for this target yet. Click <strong>New Note</strong> to write the first one.
                  </div>
                ) : (
                  <ListGroup variant="flush">
                    {listItems.map((n) => {
                      const sel = n.id === selectedId;
                      return (
                        <ListGroup.Item
                          key={n.id}
                          action
                          onClick={() =>
                            n.id === NEW_NOTE_ID ? undefined : requestNav({ kind: 'note', note: n })
                          }
                          className={`text-white py-2 border-secondary ${sel ? 'border-start border-danger border-3' : ''}`}
                          style={{ backgroundColor: sel ? '#2b2b2b' : 'transparent' }}
                        >
                          <div className="d-flex justify-content-between align-items-center gap-2">
                            <span className={`text-truncate ${n.title ? '' : 'fst-italic text-white-50'}`} title={n.title}>
                              {n.title || 'Untitled note'}
                            </span>
                            {sel && isDirty && (
                              <Badge bg="danger" className="flex-shrink-0">Unsaved</Badge>
                            )}
                          </div>
                          <div className="text-white-50" style={{ fontSize: '0.68rem' }}>
                            {n.id === NEW_NOTE_ID ? 'Not saved yet' : formatTimestamp(n.updated_at)}
                          </div>
                        </ListGroup.Item>
                      );
                    })}
                  </ListGroup>
                )}
              </Col>

              {/* RIGHT: the editor */}
              <Col md={8}>
                {!hasSelection ? (
                  <div className="text-center text-white-50 py-5">
                    {notes.length === 0
                      ? 'Nothing written for this target yet. Click New Note to start one.'
                      : 'Select a note on the left to read or edit it, or click New Note.'}
                  </div>
                ) : (
                  <div onKeyDown={handleEditorKeyDown}>
                    <div className="d-flex justify-content-between align-items-center mb-1">
                      <span className="text-white-50 small text-uppercase">
                        {isNew ? 'New Note' : 'Editing Note'}
                      </span>
                      <span className="d-flex align-items-center gap-2">
                        {isDirty && <Badge bg="danger">Unsaved changes</Badge>}
                        {!isNew && selectedNote && (
                          <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
                            Last saved {formatTimestamp(selectedNote.updated_at)}
                          </span>
                        )}
                      </span>
                    </div>

                    <Form.Control
                      className="mb-2"
                      placeholder="Note title"
                      value={title}
                      onChange={(e) => setTitle(e.target.value)}
                    />
                    <Form.Control
                      as="textarea"
                      placeholder="Write your note here…"
                      value={content}
                      onChange={(e) => setContent(e.target.value)}
                      style={{
                        height: 'calc(64vh - 150px)',
                        minHeight: '260px',
                        resize: 'vertical',
                        fontSize: '0.9rem',
                      }}
                    />

                    <div className="d-flex justify-content-between align-items-center mt-2">
                      <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
                        Ctrl+S saves.
                      </span>
                      <span className="d-flex gap-2">
                        <Button
                          variant="outline-danger"
                          size="sm"
                          disabled={deleting || saving}
                          onClick={() => setConfirmDelete(true)}
                        >
                          <i className="bi bi-trash me-1"></i>
                          {isNew ? 'Discard' : 'Delete'}
                        </Button>
                        <Button variant="danger" size="sm" disabled={saving || !isDirty} onClick={handleSave}>
                          {saving ? <Spinner size="sm" animation="border" /> : 'Save'}
                        </Button>
                      </span>
                    </div>
                  </div>
                )}
              </Col>
            </Row>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="outline-secondary" onClick={() => requestNav({ kind: 'close' })}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal show={confirmDelete} onHide={() => setConfirmDelete(false)} centered data-bs-theme="dark">
        <Modal.Header closeButton className="bg-dark border-danger">
          <Modal.Title className="text-danger">{isNew ? 'Discard Note' : 'Confirm Delete'}</Modal.Title>
        </Modal.Header>
        <Modal.Body className="bg-dark text-white">
          {isNew ? (
            <>Discard this unsaved note? Nothing in it has been written to the database.</>
          ) : (
            <>
              Delete <strong>{selectedNote?.title}</strong>? This cannot be undone.
            </>
          )}
        </Modal.Body>
        <Modal.Footer className="bg-dark border-danger">
          <Button variant="outline-secondary" onClick={() => setConfirmDelete(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={handleDeleteConfirmed} disabled={deleting}>
            {deleting ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" />
                Deleting...
              </>
            ) : (
              isNew ? 'Discard' : 'Delete'
            )}
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal show={!!pendingNav} onHide={() => setPendingNav(null)} centered data-bs-theme="dark">
        <Modal.Header closeButton className="bg-dark border-danger">
          <Modal.Title className="text-danger">Unsaved Changes</Modal.Title>
        </Modal.Header>
        <Modal.Body className="bg-dark text-white">
          <strong>{title.trim() || 'Untitled note'}</strong> has edits that have not been saved.
          Leaving now throws them away.
          {error && <div className="text-danger small mt-2">{error}</div>}
        </Modal.Body>
        <Modal.Footer className="bg-dark border-danger">
          <Button variant="outline-secondary" onClick={() => setPendingNav(null)}>
            Keep Editing
          </Button>
          <Button
            variant="outline-danger"
            onClick={() => {
              const nav = pendingNav;
              setPendingNav(null);
              performNav(nav);
            }}
          >
            Discard Changes
          </Button>
          <Button
            variant="danger"
            disabled={saving}
            onClick={async () => {
              const nav = pendingNav;
              // Only leave once the save is confirmed, otherwise the failure would take the text
              // with it and the warning would have been a lie.
              if (await handleSave()) {
                setPendingNav(null);
                performNav(nav);
              }
            }}
          >
            {saving ? <Spinner size="sm" animation="border" /> : 'Save and Continue'}
          </Button>
        </Modal.Footer>
      </Modal>
    </>
  );
};

export default NotesModal;
