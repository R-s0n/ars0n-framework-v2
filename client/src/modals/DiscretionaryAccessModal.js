import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Row, Col, Button, Form, Spinner, Badge, ListGroup, Alert } from 'react-bootstrap';

// Discretionary access control: access a holder can pass on, up to their own level.
//
// A Figma board is the canonical shape. The creator is an admin, an admin can invite someone as an
// admin or as a user, a user can only invite other users. The bug being modelled is a user who
// manages to hand out admin, so the screen is arranged around one question per level: what can this
// level create, and what must it never be able to create. That question is answered with two rows
// of chips rather than a number, because a rank and a ceiling side by side are easy to read past.

// Ranks are stored as plain integers and the ladder reads top down from the most powerful, so the
// row above is always the level an escalation would be reaching for.
function byRankDesc(levels) {
  return [...levels].sort((a, b) => {
    const ar = Number.isFinite(a.rank) ? a.rank : 0;
    const br = Number.isFinite(b.rank) ? b.rank : 0;
    if (ar !== br) return br - ar;
    return String(a.name || '').localeCompare(String(b.name || ''));
  });
}

// The server derives what each level may hand out, because the rule belongs in one place and the
// same rule has to hold when something other than this modal reads the model. The local fallback
// below only exists so a payload that predates the field still renders the right answer instead of
// an empty column, and it applies exactly the rule the schema comment states: a level may grant any
// level whose rank is at or below its ceiling.
function grantableNames(level, levels) {
  const fromServer = level.grantable_levels || level.can_grant_levels;
  if (Array.isArray(fromServer)) {
    return fromServer.map((g) => (typeof g === 'string' ? g : (g && g.name))).filter(Boolean);
  }
  if (level.can_grant === false) return [];
  const ceiling = level.grant_ceiling_rank;
  // A missing ceiling is not the same as a ceiling of zero. Nothing has been recorded, so the level
  // is unbounded until someone says otherwise, and unbounded is flagged in the UI rather than
  // quietly treated as safe.
  if (ceiling === null || ceiling === undefined || ceiling === '') {
    return levels.map((l) => l.name);
  }
  return levels
    .filter((l) => (Number.isFinite(l.rank) ? l.rank : 0) <= Number(ceiling))
    .map((l) => l.name);
}

const DiscretionaryAccessModal = ({ show, handleClose, scopeTargetId }) => {
  const [objects, setObjects] = useState([]);
  const [selectedObjectId, setSelectedObjectId] = useState(null);

  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const [newObjectName, setNewObjectName] = useState('');
  const [editingObjectId, setEditingObjectId] = useState(null);
  const [editingObjectName, setEditingObjectName] = useState('');

  // Text fields commit on blur rather than on every keystroke, so an in progress edit lives here
  // until it is worth a request. Selects and switches write straight through, since one click is
  // already a finished decision.
  const [drafts, setDrafts] = useState({});
  const [newLevel, setNewLevel] = useState({ name: '', rank: '', description: '' });

  const fetchObjects = useCallback(async () => {
    if (!scopeTargetId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/authz/dac/${scopeTargetId}`);
      if (!res.ok) throw new Error(`Request failed (${res.status})`);
      const data = await res.json();
      const list = Array.isArray(data) ? data : [];
      setObjects(list);
      setSelectedObjectId((prev) => (prev && list.some((o) => o.id === prev)
        ? prev
        : (list[0] ? list[0].id : null)));
      setDrafts({});
    } catch (e) {
      console.error('[DiscretionaryAccess] fetchObjects failed:', e);
      setError(`Could not load discretionary objects: ${e.message}`);
      setObjects([]);
    } finally {
      setLoading(false);
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (show && scopeTargetId) fetchObjects();
    if (!show) {
      setSelectedObjectId(null);
      setNewObjectName('');
      setEditingObjectId(null);
      setDrafts({});
      setNewLevel({ name: '', rank: '', description: '' });
      setError('');
      setNotice('');
    }
  }, [show, scopeTargetId, fetchObjects]);

  const selectedObject = useMemo(
    () => objects.find((o) => o.id === selectedObjectId) || null,
    [objects, selectedObjectId]
  );

  const levels = useMemo(
    () => byRankDesc(Array.isArray(selectedObject && selectedObject.levels) ? selectedObject.levels : []),
    [selectedObject]
  );

  // Distinct ranks, highest first, for the ceiling picker. The ceiling is stored as a number but
  // choosing it by level name is the only way the choice reads as the sentence it represents:
  // "may hand out anything at or below user".
  const ceilingOptions = useMemo(() => {
    const seen = new Set();
    const out = [];
    levels.forEach((l) => {
      const r = Number.isFinite(l.rank) ? l.rank : 0;
      if (seen.has(r)) return;
      seen.add(r);
      out.push({ rank: r, name: l.name });
    });
    return out;
  }, [levels]);

  // ---- objects ------------------------------------------------------------

  const createObject = async () => {
    const name = newObjectName.trim();
    if (!name || !scopeTargetId) return;
    setBusy(true);
    setError('');
    try {
      const res = await fetch(`/api/authz/dac/${scopeTargetId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, description: '', notes: '' }),
      });
      if (!res.ok) throw new Error((await res.text()) || `Create failed (${res.status})`);
      const created = await res.json();
      setNewObjectName('');
      await fetchObjects();
      if (created && created.id) setSelectedObjectId(created.id);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const updateObject = async (object, patch) => {
    setBusy(true);
    try {
      const res = await fetch(`/api/authz/dac/object/${object.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: object.name,
          description: object.description || '',
          notes: object.notes || '',
          ...patch,
        }),
      });
      if (!res.ok) throw new Error((await res.text()) || `Update failed (${res.status})`);
      await fetchObjects();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const deleteObject = async (object) => {
    if (!window.confirm(`Delete "${object.name}"? Every level recorded under it goes with it.`)) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/authz/dac/object/${object.id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error((await res.text()) || `Delete failed (${res.status})`);
      if (selectedObjectId === object.id) setSelectedObjectId(null);
      await fetchObjects();
      setNotice(`Deleted ${object.name}.`);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const commitObjectRename = async () => {
    const id = editingObjectId;
    const value = editingObjectName.trim();
    setEditingObjectId(null);
    const object = objects.find((o) => o.id === id);
    if (!object || !value || value === object.name) return;
    await updateObject(object, { name: value });
  };

  // ---- levels -------------------------------------------------------------

  const draftFor = (level) => ({
    name: level.name,
    rank: String(Number.isFinite(level.rank) ? level.rank : 0),
    description: level.description || '',
    ...(drafts[level.id] || {}),
  });

  const setDraft = (levelId, patch) => setDrafts((prev) => ({
    ...prev,
    [levelId]: { ...(prev[levelId] || {}), ...patch },
  }));

  const putLevel = async (level, body) => {
    setBusy(true);
    setError('');
    try {
      const res = await fetch(`/api/authz/dac/level/${level.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error((await res.text()) || `Update failed (${res.status})`);
      setDrafts((prev) => {
        const copy = { ...prev };
        delete copy[level.id];
        return copy;
      });
      await fetchObjects();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const updateLevel = (level, patch) => {
    const d = draftFor(level);
    const parsedRank = parseInt(d.rank, 10);
    return putLevel(level, {
      name: d.name.trim() || level.name,
      rank: Number.isFinite(parsedRank) ? parsedRank : 0,
      grant_ceiling_rank: level.grant_ceiling_rank,
      can_grant: level.can_grant !== false,
      description: d.description,
      ...patch,
    });
  };

  const createLevel = async () => {
    const name = newLevel.name.trim();
    if (!name || !selectedObject) return;
    const parsed = parseInt(newLevel.rank, 10);
    const highest = levels.reduce((m, l) => Math.max(m, Number.isFinite(l.rank) ? l.rank : 0), -1);
    const rank = Number.isFinite(parsed) ? parsed : highest + 1;
    setBusy(true);
    setError('');
    try {
      const res = await fetch(`/api/authz/dac/object/${selectedObject.id}/levels`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          rank,
          // A new level defaults to granting its own level and nothing higher, which is the Figma
          // rule and the safe reading. Anything looser has to be an explicit choice, because a
          // ceiling above a level's own rank is escalation by design and should never be a default.
          grant_ceiling_rank: rank,
          can_grant: true,
          description: newLevel.description,
        }),
      });
      if (!res.ok) throw new Error((await res.text()) || `Create failed (${res.status})`);
      setNewLevel({ name: '', rank: '', description: '' });
      await fetchObjects();
      setNotice(`Added ${name} at rank ${rank}, granting up to itself. Widen the ceiling only if the application really lets it.`);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const deleteLevel = async (level) => {
    if (!window.confirm(`Delete the level "${level.name}"?`)) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/authz/dac/level/${level.id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error((await res.text()) || `Delete failed (${res.status})`);
      await fetchObjects();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  // Reordering here is not cosmetic. Rank is the thing the model is about, so moving a level swaps
  // the two ranks for real.
  //
  // The ceiling is stored as a rank number rather than a pointer to a level, so a swap would
  // otherwise leave "may grant its own level" pointing at whoever now occupies that number. When a
  // level's ceiling equals its own rank, that is a statement about itself, so the ceiling travels
  // with it. A ceiling deliberately set to some other level is left exactly where it was.
  const moveLevel = async (index, delta) => {
    const target = index + delta;
    if (target < 0 || target >= levels.length) return;
    const a = levels[index];
    const b = levels[target];
    const aRank = Number.isFinite(a.rank) ? a.rank : 0;
    const bRank = Number.isFinite(b.rank) ? b.rank : 0;

    // Two levels sharing a rank cannot be swapped, so the promoted one is pushed one clear of the
    // other instead. Without this, arrow clicks on a freshly imported ladder do nothing at all.
    const aNew = aRank === bRank ? (delta < 0 ? bRank + 1 : bRank - 1) : bRank;
    const bNew = aRank === bRank ? bRank : aRank;

    const carry = (level, oldRank, newRank) => (
      level.grant_ceiling_rank === oldRank ? newRank : level.grant_ceiling_rank
    );

    setBusy(true);
    setError('');
    try {
      await Promise.all([
        fetch(`/api/authz/dac/level/${a.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: a.name,
            rank: aNew,
            grant_ceiling_rank: carry(a, aRank, aNew),
            can_grant: a.can_grant !== false,
            description: a.description || '',
          }),
        }),
        fetch(`/api/authz/dac/level/${b.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: b.name,
            rank: bNew,
            grant_ceiling_rank: carry(b, bRank, bNew),
            can_grant: b.can_grant !== false,
            description: b.description || '',
          }),
        }),
      ]);
      await fetchObjects();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  // ---- rendering ----------------------------------------------------------

  const renderLevel = (level, index) => {
    const d = draftFor(level);
    const canGrant = level.can_grant !== false;
    const rank = Number.isFinite(level.rank) ? level.rank : 0;
    const ceiling = level.grant_ceiling_rank;
    const unbounded = canGrant && (ceiling === null || ceiling === undefined || ceiling === '');
    const grantable = grantableNames(level, levels);
    const grantableSet = new Set(grantable);
    const blocked = levels.map((l) => l.name).filter((n) => !grantableSet.has(n));
    const grantsAbove = canGrant && (unbounded
      ? levels.some((l) => (Number.isFinite(l.rank) ? l.rank : 0) > rank)
      : Number(ceiling) > rank);

    return (
      <div key={level.id} className="border border-secondary rounded p-2 mb-2">
        <Row className="g-2 align-items-end">
          <Col xs="auto" className="d-flex flex-column" style={{ fontSize: '0.75rem' }}>
            <i
              role="button"
              className="bi bi-arrow-up text-white-50"
              title="Promote: swap ranks with the level above"
              onClick={() => moveLevel(index, -1)}
              style={{ opacity: index === 0 ? 0.25 : 1 }}
            />
            <i
              role="button"
              className="bi bi-arrow-down text-white-50"
              title="Demote: swap ranks with the level below"
              onClick={() => moveLevel(index, 1)}
              style={{ opacity: index === levels.length - 1 ? 0.25 : 1 }}
            />
          </Col>
          <Col md={3}>
            <Form.Label className="text-white small mb-1">Level</Form.Label>
            <Form.Control
              size="sm"
              value={d.name}
              onChange={(e) => setDraft(level.id, { name: e.target.value })}
              onBlur={() => { if (d.name.trim() && d.name !== level.name) updateLevel(level, {}); }}
              onKeyDown={(e) => { if (e.key === 'Enter') e.currentTarget.blur(); }}
            />
          </Col>
          <Col md={2}>
            <Form.Label className="text-white small mb-1">Rank</Form.Label>
            <Form.Control
              size="sm"
              type="number"
              value={d.rank}
              onChange={(e) => setDraft(level.id, { rank: e.target.value })}
              onBlur={() => { if (String(rank) !== d.rank) updateLevel(level, {}); }}
              onKeyDown={(e) => { if (e.key === 'Enter') e.currentTarget.blur(); }}
            />
          </Col>
          <Col md={2} className="d-flex align-items-center">
            <Form.Check
              type="switch"
              id={`dac-can-grant-${level.id}`}
              className="text-white small mt-3"
              label="Can grant"
              checked={canGrant}
              onChange={(e) => updateLevel(level, { can_grant: e.target.checked })}
            />
          </Col>
          <Col md={3}>
            <Form.Label className="text-white small mb-1">Grant ceiling</Form.Label>
            <Form.Select
              size="sm"
              disabled={!canGrant}
              value={ceiling === null || ceiling === undefined ? '' : String(ceiling)}
              onChange={(e) => updateLevel(level, {
                grant_ceiling_rank: e.target.value === '' ? null : parseInt(e.target.value, 10),
              })}
            >
              <option value="">No ceiling recorded</option>
              {ceilingOptions.map((o) => (
                <option key={o.rank} value={String(o.rank)}>
                  up to {o.name} (rank {o.rank})
                </option>
              ))}
            </Form.Select>
          </Col>
          <Col md={1} className="d-flex align-items-center justify-content-end">
            <i
              role="button"
              className="bi bi-trash text-danger mt-3"
              title="Delete level"
              onClick={() => deleteLevel(level)}
            />
          </Col>
        </Row>

        {/* The answer to the only question this screen asks, spelled out for every level so it can
            be read without doing arithmetic on two numbers. */}
        <div className="d-flex flex-wrap align-items-center gap-2 mt-2">
          <span className="text-white-50" style={{ fontSize: '0.72rem', minWidth: '108px' }}>
            {level.name} may create
          </span>
          {!canGrant ? (
            <span className="text-white-50 fst-italic" style={{ fontSize: '0.72rem' }}>
              nothing, this level cannot hand out access at all
            </span>
          ) : grantable.length === 0 ? (
            <span className="text-white-50 fst-italic" style={{ fontSize: '0.72rem' }}>
              nothing at or below the ceiling
            </span>
          ) : (
            grantable.map((n) => (
              <Badge key={n} bg="success" style={{ fontWeight: 500 }}>{n}</Badge>
            ))
          )}
        </div>
        {blocked.length > 0 && (
          <div className="d-flex flex-wrap align-items-center gap-2 mt-1">
            <span className="text-white-50" style={{ fontSize: '0.72rem', minWidth: '108px' }}>
              must not create
            </span>
            {blocked.map((n) => (
              <span
                key={n}
                style={{
                  border: '1px solid #dc3545',
                  color: '#ff8a8a',
                  borderRadius: '4px',
                  padding: '1px 8px',
                  fontSize: '0.7rem',
                  fontWeight: 600,
                }}
              >
                {n}
              </span>
            ))}
            <span className="text-white-50" style={{ fontSize: '0.68rem' }}>
              a grant that lands here is the escalation
            </span>
          </div>
        )}
        {unbounded && (
          <div className="text-warning mt-1" style={{ fontSize: '0.7rem' }}>
            No ceiling recorded, so this level is treated as able to hand out anything, including
            levels above itself. Pin the ceiling down before testing, otherwise nothing it grants can
            be called a violation.
          </div>
        )}
        {grantsAbove && !unbounded && (
          <div className="text-warning mt-1" style={{ fontSize: '0.7rem' }}>
            This level can grant above its own rank. That is escalation by design, so record why the
            application allows it.
          </div>
        )}
      </div>
    );
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Discretionary Access Control</Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '72vh' }}>
        {!scopeTargetId ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <>
            {error && <Alert variant="danger" dismissible onClose={() => setError('')}>{error}</Alert>}
            {notice && <Alert variant="info" dismissible onClose={() => setNotice('')} className="py-2 small">{notice}</Alert>}

            <Row>
              {/* LEFT: the things access is held over */}
              <Col md={3} className="border-end border-secondary" style={{ maxHeight: '68vh', overflowY: 'auto' }}>
                <div className="text-white-50 small text-uppercase mb-2">Objects</div>
                <div className="d-flex gap-2 mb-2">
                  <Form.Control
                    size="sm"
                    placeholder="Board, document, project"
                    value={newObjectName}
                    onChange={(e) => setNewObjectName(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); createObject(); } }}
                  />
                  <Button size="sm" variant="outline-danger" disabled={busy || !newObjectName.trim()} onClick={createObject}>
                    <i className="bi bi-plus-lg" />
                  </Button>
                </div>

                {loading ? (
                  <div className="text-center py-3"><Spinner size="sm" animation="border" variant="danger" /></div>
                ) : objects.length === 0 ? (
                  <div className="text-white-50 small fst-italic">
                    Nothing recorded yet. An object is whatever access is held over and then passed
                    on: a board, a workspace, a shared document.
                  </div>
                ) : (
                  <ListGroup variant="flush">
                    {objects.map((o) => {
                      const count = Array.isArray(o.levels) ? o.levels.length : 0;
                      const isEditing = editingObjectId === o.id;
                      return (
                        <ListGroup.Item
                          key={o.id}
                          action={!isEditing}
                          active={o.id === selectedObjectId}
                          onClick={() => { if (!isEditing) setSelectedObjectId(o.id); }}
                          className="bg-dark text-white py-2"
                        >
                          {isEditing ? (
                            <Form.Control
                              size="sm"
                              autoFocus
                              value={editingObjectName}
                              onChange={(e) => setEditingObjectName(e.target.value)}
                              onBlur={commitObjectRename}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') { e.preventDefault(); commitObjectRename(); }
                                if (e.key === 'Escape') setEditingObjectId(null);
                              }}
                            />
                          ) : (
                            <div className="d-flex justify-content-between align-items-center">
                              <span className="text-truncate me-2" title={o.description || o.name}>{o.name}</span>
                              <span className="d-flex align-items-center gap-2 flex-shrink-0">
                                <Badge bg="secondary">{count}</Badge>
                                <i
                                  role="button"
                                  className="bi bi-pencil text-white-50"
                                  title="Rename"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setEditingObjectId(o.id);
                                    setEditingObjectName(o.name);
                                  }}
                                />
                                <i
                                  role="button"
                                  className="bi bi-trash text-danger"
                                  title="Delete"
                                  onClick={(e) => { e.stopPropagation(); deleteObject(o); }}
                                />
                              </span>
                            </div>
                          )}
                        </ListGroup.Item>
                      );
                    })}
                  </ListGroup>
                )}
              </Col>

              {/* RIGHT: the ladder for the selected object */}
              <Col md={9} style={{ maxHeight: '68vh', overflowY: 'auto' }}>
                {!selectedObject ? (
                  <div className="text-center text-white-50 py-5">
                    Select an object to model who can hand out what.
                  </div>
                ) : (
                  <>
                    <div className="d-flex justify-content-between align-items-center mb-2">
                      <span className="text-white-50 small text-uppercase">
                        Levels on {selectedObject.name}, most powerful first
                      </span>
                      <Button size="sm" variant="outline-secondary" disabled={loading || busy} onClick={fetchObjects}>
                        {loading ? <Spinner size="sm" animation="border" /> : 'Reload'}
                      </Button>
                    </div>

                    <div className="text-white-50 mb-2" style={{ fontSize: '0.72rem' }}>
                      Rank is how much the level holds, the ceiling is how far down the ladder it may
                      hand out. A level may grant anything at or below its ceiling, so admin with a
                      ceiling of admin can create more admins, and user with a ceiling of user cannot.
                      A user who manages to create an admin is the escalation this records.
                    </div>

                    {/* These two are uncontrolled so typing does not fire a request per keystroke.
                        The key is the object id on purpose: an uncontrolled input keeps its first
                        defaultValue forever, so without it, switching objects would leave the
                        previous object's description sitting in the box. */}
                    <Row className="g-2 mb-3">
                      <Col md={5}>
                        <Form.Label className="text-white small mb-1">Description</Form.Label>
                        <Form.Control
                          size="sm"
                          placeholder="What this object is in the application"
                          defaultValue={selectedObject.description || ''}
                          key={`desc-${selectedObject.id}`}
                          onBlur={(e) => {
                            if (e.target.value !== (selectedObject.description || '')) {
                              updateObject(selectedObject, { description: e.target.value });
                            }
                          }}
                        />
                      </Col>
                      <Col md={7}>
                        <Form.Label className="text-white small mb-1">Notes</Form.Label>
                        <Form.Control
                          size="sm"
                          placeholder="Which endpoint issues the invite, which account was used, anything a re-read needs"
                          defaultValue={selectedObject.notes || ''}
                          key={`notes-${selectedObject.id}`}
                          onBlur={(e) => {
                            if (e.target.value !== (selectedObject.notes || '')) {
                              updateObject(selectedObject, { notes: e.target.value });
                            }
                          }}
                        />
                      </Col>
                    </Row>

                    {levels.length === 0 ? (
                      <div className="text-white-50 small fst-italic mb-3">
                        No levels yet. Start with the level the creator gets, then add the ones it can
                        invite.
                      </div>
                    ) : (
                      levels.map((l, i) => renderLevel(l, i))
                    )}

                    <div className="border border-secondary rounded p-2">
                      <div className="text-white-50 small text-uppercase mb-2">Add level</div>
                      <Row className="g-2 align-items-end">
                        <Col md={3}>
                          <Form.Label className="text-white small mb-1">Name</Form.Label>
                          <Form.Control
                            size="sm"
                            placeholder="admin, editor, viewer"
                            value={newLevel.name}
                            onChange={(e) => setNewLevel({ ...newLevel, name: e.target.value })}
                            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); createLevel(); } }}
                          />
                        </Col>
                        <Col md={2}>
                          <Form.Label className="text-white small mb-1">Rank</Form.Label>
                          <Form.Control
                            size="sm"
                            type="number"
                            placeholder={String(levels.reduce((m, l) => Math.max(m, Number.isFinite(l.rank) ? l.rank : 0), -1) + 1)}
                            value={newLevel.rank}
                            onChange={(e) => setNewLevel({ ...newLevel, rank: e.target.value })}
                          />
                        </Col>
                        <Col md={5}>
                          <Form.Label className="text-white small mb-1">Description</Form.Label>
                          <Form.Control
                            size="sm"
                            placeholder="What this level is allowed to do with the object itself"
                            value={newLevel.description}
                            onChange={(e) => setNewLevel({ ...newLevel, description: e.target.value })}
                          />
                        </Col>
                        <Col md={2}>
                          <Button
                            size="sm"
                            variant="danger"
                            className="w-100"
                            disabled={busy || !newLevel.name.trim()}
                            onClick={createLevel}
                          >
                            {busy ? <Spinner size="sm" animation="border" /> : 'Add'}
                          </Button>
                        </Col>
                      </Row>
                      <div className="text-white-50 mt-1" style={{ fontSize: '0.7rem' }}>
                        A new level starts able to hand out its own level and nothing higher. Widen
                        the ceiling only when the application really allows it, because a ceiling
                        above a level's own rank is escalation the vendor built on purpose.
                      </div>
                    </div>
                  </>
                )}
              </Col>
            </Row>
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
};

export default DiscretionaryAccessModal;
