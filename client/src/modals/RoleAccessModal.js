import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Row, Col, Button, Form, Spinner, Badge, Alert } from 'react-bootstrap';

// Role based access control, modelled as a grid: roles down one axis, actions across the other,
// one verdict per cell.
//
// The whole reason this screen exists is the third value. An application that greys out a button
// looks identical whether the role was simply never granted the action or whether the action must
// never be reachable by that role under any circumstances. Only the second one is a finding, so
// the operator has to state which it is before testing, not after. Everything below is built to
// make that distinction impossible to miss.

const CELL_ORDER = ['can_do', 'cannot_do', 'forbidden_to_do'];

// Forbidden To Do is deliberately the loudest thing on the screen. Can Do is a muted green because
// a permitted action is the boring case, Can Not Do is grey because it is the default, and
// Forbidden To Do is solid red with a brighter outline because it is the only cell whose violation
// is worth writing up.
const VALUE_META = {
  can_do: {
    label: 'Can Do',
    short: 'CAN',
    bg: '#146c43',
    color: '#ffffff',
    border: 'transparent',
    weight: 500,
  },
  cannot_do: {
    label: 'Can Not Do',
    short: 'CANNOT',
    bg: '#343a40',
    color: '#adb5bd',
    border: '#495057',
    weight: 400,
  },
  forbidden_to_do: {
    label: 'Forbidden To Do',
    short: 'FORBIDDEN',
    bg: '#dc3545',
    color: '#ffffff',
    border: '#ff8a8a',
    weight: 700,
  },
};

// A cell with no row in the matrix has not been recorded yet. That is not the same statement as
// "this role cannot do this", and drawing it as a verdict would mean an untouched grid reads as a
// finished model. It gets its own washed out look and its own label.
const UNSET_META = {
  label: 'Not recorded',
  short: '-',
  bg: 'transparent',
  color: '#6c757d',
  border: '#343a40',
  weight: 400,
};

const cellKey = (roleId, actionId) => `${roleId}|${actionId}`;

// Roles and actions both default sort_order to 0 in the schema, so ordering has to fall back to
// the order the server sent rather than pretending the column is populated.
function bySortOrder(list) {
  return list
    .map((item, index) => ({ item, index }))
    .sort((a, b) => {
      const ao = Number.isFinite(a.item.sort_order) ? a.item.sort_order : 0;
      const bo = Number.isFinite(b.item.sort_order) ? b.item.sort_order : 0;
      if (ao !== bo) return ao - bo;
      return a.index - b.index;
    })
    .map((x) => x.item);
}

const RoleAccessModal = ({ show, handleClose, scopeTargetId }) => {
  const [roles, setRoles] = useState([]);
  const [actions, setActions] = useState([]);
  const [matrix, setMatrix] = useState([]);

  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  // Only the cells the operator actually touched. This is what gets sent, and its size is what the
  // pending counter reports, so a save can never quietly rewrite a cell nobody looked at.
  const [pending, setPending] = useState({});

  const [newRole, setNewRole] = useState('');
  const [newAction, setNewAction] = useState('');
  const [editing, setEditing] = useState(null); // { kind: 'role' | 'action', id, value }
  const [selected, setSelected] = useState(null); // { roleId, actionId }

  const fetchAll = useCallback(async () => {
    if (!scopeTargetId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/authz/rbac/${scopeTargetId}`);
      if (!res.ok) throw new Error(`Request failed (${res.status})`);
      const data = await res.json();
      setRoles(bySortOrder(Array.isArray(data.roles) ? data.roles : []));
      setActions(bySortOrder(Array.isArray(data.actions) ? data.actions : []));
      setMatrix(Array.isArray(data.matrix) ? data.matrix : []);
    } catch (e) {
      console.error('[RoleAccess] fetchAll failed:', e);
      setError(`Could not load the role matrix: ${e.message}`);
      setRoles([]);
      setActions([]);
      setMatrix([]);
    } finally {
      setLoading(false);
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (show && scopeTargetId) fetchAll();
    if (!show) {
      setPending({});
      setEditing(null);
      setSelected(null);
      setNewRole('');
      setNewAction('');
      setError('');
      setNotice('');
    }
  }, [show, scopeTargetId, fetchAll]);

  const saved = useMemo(() => {
    const map = {};
    matrix.forEach((c) => {
      // recorded comes from updated_at, not from the cell being present.
      //
      // The server sends a DENSE matrix: every role crossed with every action, with cells nobody
      // has touched carrying cannot_do and a null updated_at. So "the key is missing" never happens
      // against the real server, and keying the not-recorded state off a missing key made the
      // washed-out cell, its legend entry and its select option all unreachable. The distinction
      // is still worth drawing, because a role deliberately marked cannot_do and one nobody has
      // considered yet are different states to an operator, so it is driven off the field the
      // server actually provides for it.
      map[cellKey(c.role_id, c.action_id)] = {
        value: c.value,
        notes: c.notes || '',
        recorded: c.updated_at != null,
      };
    });
    return map;
  }, [matrix]);

  const cellState = useCallback((roleId, actionId) => {
    const key = cellKey(roleId, actionId);
    if (pending[key]) return { ...pending[key], dirty: true, recorded: true };
    if (saved[key]) return { ...saved[key], dirty: false };
    // Only reachable if the server ever stops sending a dense matrix. Kept so a sparse response
    // degrades to "not recorded" rather than to a crash.
    return { value: null, notes: '', dirty: false, recorded: false };
  }, [pending, saved]);

  const pendingCount = Object.keys(pending).length;

  // Writing a cell back to exactly what the server already holds removes it from the batch rather
  // than queueing a write that changes nothing. Without this, cycling a cell three times back to
  // where it started would still count as a pending change and still be sent.
  const setCell = useCallback((roleId, actionId, value, notes) => {
    const key = cellKey(roleId, actionId);
    setPending((prev) => {
      const base = saved[key];
      const nextNotes = notes !== undefined ? notes : (prev[key] ? prev[key].notes : (base ? base.notes : ''));
      if (base && base.value === value && (base.notes || '') === (nextNotes || '')) {
        const copy = { ...prev };
        delete copy[key];
        return copy;
      }
      return { ...prev, [key]: { role_id: roleId, action_id: actionId, value, notes: nextNotes || '' } };
    });
  }, [saved]);

  // Click cycles forward, shift click cycles back. A blank cell always lands on Can Do first: there
  // is no way to send "not recorded" through the matrix endpoint, so blank is a starting state the
  // cycle leaves rather than a value it can return to.
  const cycleCell = (roleId, actionId, backwards) => {
    const current = cellState(roleId, actionId);
    let next;
    if (!current.value) {
      next = backwards ? CELL_ORDER[CELL_ORDER.length - 1] : CELL_ORDER[0];
    } else {
      const i = CELL_ORDER.indexOf(current.value);
      const step = backwards ? -1 : 1;
      next = CELL_ORDER[(i + step + CELL_ORDER.length) % CELL_ORDER.length];
    }
    setSelected({ roleId, actionId });
    setCell(roleId, actionId, next);
  };

  const saveMatrix = async () => {
    if (pendingCount === 0 || !scopeTargetId) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await fetch(`/api/authz/rbac/${scopeTargetId}/matrix`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cells: Object.values(pending) }),
      });
      if (!res.ok) throw new Error((await res.text()) || `Save failed (${res.status})`);
      const count = pendingCount;
      setPending({});
      await fetchAll();
      setNotice(`${count} cell(s) saved.`);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  // ---- roles and actions --------------------------------------------------

  const addItem = async (kind, name) => {
    const trimmed = name.trim();
    if (!trimmed || !scopeTargetId) return;
    setBusy(true);
    setError('');
    try {
      const list = kind === 'role' ? roles : actions;
      const res = await fetch(`/api/authz/rbac/${scopeTargetId}/${kind}s`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: trimmed, description: '', sort_order: list.length }),
      });
      if (!res.ok) throw new Error((await res.text()) || `Create failed (${res.status})`);
      if (kind === 'role') setNewRole(''); else setNewAction('');
      await fetchAll();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const renameItem = async () => {
    if (!editing) return;
    const { kind, id, value } = editing;
    const list = kind === 'role' ? roles : actions;
    const item = list.find((x) => x.id === id);
    setEditing(null);
    if (!item || !value.trim() || value.trim() === item.name) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/authz/rbac/${kind}/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: value.trim(),
          description: item.description || '',
          sort_order: Number.isFinite(item.sort_order) ? item.sort_order : 0,
        }),
      });
      if (!res.ok) throw new Error((await res.text()) || `Rename failed (${res.status})`);
      await fetchAll();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const deleteItem = async (kind, item) => {
    const noun = kind === 'role' ? 'role' : 'action';
    if (!window.confirm(`Delete the ${noun} "${item.name}"? Every cell in its ${kind === 'role' ? 'row' : 'column'} goes with it.`)) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/authz/rbac/${kind}/${item.id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error((await res.text()) || `Delete failed (${res.status})`);
      // Any queued edit that pointed at the deleted row or column would be sent against an id the
      // server no longer has, so drop those before the next save.
      setPending((prev) => {
        const copy = {};
        Object.entries(prev).forEach(([k, v]) => {
          const stale = kind === 'role' ? v.role_id === item.id : v.action_id === item.id;
          if (!stale) copy[k] = v;
        });
        return copy;
      });
      setSelected(null);
      await fetchAll();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  // sort_order defaults to 0 on every row, so swapping two values is a no-op that looks like a bug.
  // Renumbering the whole list from its new displayed order is the only move that actually sticks.
  const moveItem = async (kind, index, delta) => {
    const list = kind === 'role' ? roles : actions;
    const target = index + delta;
    if (target < 0 || target >= list.length) return;
    const reordered = [...list];
    const [lifted] = reordered.splice(index, 1);
    reordered.splice(target, 0, lifted);

    if (kind === 'role') setRoles(reordered); else setActions(reordered);

    setBusy(true);
    try {
      await Promise.all(reordered.map((item, i) => {
        if ((Number.isFinite(item.sort_order) ? item.sort_order : 0) === i) return Promise.resolve();
        return fetch(`/api/authz/rbac/${kind}/${item.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: item.name, description: item.description || '', sort_order: i }),
        });
      }));
      await fetchAll();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  // ---- rendering ----------------------------------------------------------

  const forbiddenCount = useMemo(() => {
    let n = 0;
    roles.forEach((r) => actions.forEach((a) => {
      if (cellState(r.id, a.id).value === 'forbidden_to_do') n += 1;
    }));
    return n;
  }, [roles, actions, cellState]);

  const selectedInfo = useMemo(() => {
    if (!selected) return null;
    const role = roles.find((r) => r.id === selected.roleId);
    const action = actions.find((a) => a.id === selected.actionId);
    if (!role || !action) return null;
    return { role, action, ...cellState(role.id, action.id) };
  }, [selected, roles, actions, cellState]);

  // The role column is sticky, which means it scrolls over the cells to its right. Sticky cells
  // need an opaque background or the content underneath shows through, and table-bordered borders
  // are painted by the cell that scrolls away, so the right hand edge is drawn with an inset shadow
  // instead of a border.
  const stickyCol = {
    position: 'sticky',
    left: 0,
    zIndex: 2,
    backgroundColor: '#212529',
    boxShadow: 'inset -1px 0 0 #495057',
    minWidth: '190px',
    maxWidth: '190px',
  };

  const stickyHead = { position: 'sticky', top: 0, zIndex: 3, backgroundColor: '#212529' };
  const stickyCorner = { ...stickyCol, ...stickyHead, zIndex: 4 };

  const renderNameCell = (kind, item, index, list) => {
    const isEditing = editing && editing.kind === kind && editing.id === item.id;
    if (isEditing) {
      return (
        <Form.Control
          size="sm"
          autoFocus
          value={editing.value}
          onChange={(e) => setEditing({ ...editing, value: e.target.value })}
          onBlur={renameItem}
          onKeyDown={(e) => {
            if (e.key === 'Enter') { e.preventDefault(); renameItem(); }
            if (e.key === 'Escape') setEditing(null);
          }}
        />
      );
    }
    return (
      <div className="d-flex align-items-center justify-content-between gap-1">
        {/* minWidth 0 is what makes text-truncate work here: a flex item refuses to shrink below
            its content width without it, so a long action name would push the arrows off the cell
            instead of ellipsing. */}
        <span
          role="button"
          className="text-white text-truncate"
          style={{ minWidth: 0 }}
          title={item.description ? `${item.name}: ${item.description}` : `${item.name} (click to rename)`}
          onClick={() => setEditing({ kind, id: item.id, value: item.name })}
        >
          {item.name}
        </span>
        <span className="d-flex align-items-center flex-shrink-0" style={{ fontSize: '0.7rem' }}>
          <i
            role="button"
            className={`bi ${kind === 'role' ? 'bi-arrow-up' : 'bi-arrow-left'} text-white-50 px-1`}
            title="Move earlier"
            onClick={() => moveItem(kind, index, -1)}
            style={{ opacity: index === 0 ? 0.25 : 1 }}
          />
          <i
            role="button"
            className={`bi ${kind === 'role' ? 'bi-arrow-down' : 'bi-arrow-right'} text-white-50 px-1`}
            title="Move later"
            onClick={() => moveItem(kind, index, 1)}
            style={{ opacity: index === list.length - 1 ? 0.25 : 1 }}
          />
          <i
            role="button"
            className="bi bi-trash text-danger px-1"
            title={`Delete ${kind}`}
            onClick={() => deleteItem(kind, item)}
          />
        </span>
      </div>
    );
  };

  const renderCell = (role, action) => {
    const state = cellState(role.id, action.id);
    // A cell the server has never had written to it renders as not-recorded even though it carries
    // a cannot_do value, because "nobody has decided" and "decided this role may not" are different
    // things to an operator working out what still needs modelling.
    const meta = (state.value && state.recorded !== false) ? VALUE_META[state.value] : UNSET_META;
    const isSelected = selected && selected.roleId === role.id && selected.actionId === action.id;
    return (
      <td
        key={action.id}
        className="p-1 align-middle text-center"
        style={{ minWidth: '124px', backgroundColor: '#212529' }}
      >
        <div
          role="button"
          onClick={(e) => cycleCell(role.id, action.id, e.shiftKey)}
          title={`${role.name} / ${action.name}: ${meta.label}. Click to cycle, shift click to go back.`}
          style={{
            backgroundColor: meta.bg,
            color: meta.color,
            fontWeight: meta.weight,
            border: `1px solid ${meta.border}`,
            outline: isSelected ? '2px solid #0dcaf0' : 'none',
            borderRadius: '4px',
            padding: '4px 2px',
            fontSize: '0.68rem',
            letterSpacing: state.value === 'forbidden_to_do' ? '0.06em' : 'normal',
            position: 'relative',
            userSelect: 'none',
          }}
        >
          {state.value === 'forbidden_to_do' && <i className="bi bi-shield-exclamation me-1" />}
          {meta.short}
          {/* An unsaved cell has to be findable in a grid that may be far wider than the screen,
              so the pending marker lives on the cell itself and not only in the counter. */}
          {state.dirty && (
            <span
              title="Unsaved"
              style={{
                position: 'absolute',
                top: '1px',
                right: '3px',
                width: '5px',
                height: '5px',
                borderRadius: '50%',
                backgroundColor: '#ffc107',
              }}
            />
          )}
          {state.notes && <i className="bi bi-sticky-fill ms-1" style={{ fontSize: '0.6rem', opacity: 0.8 }} />}
        </div>
      </td>
    );
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Role Based Access Control</Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '72vh' }}>
        {!scopeTargetId ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <>
            {error && <Alert variant="danger" dismissible onClose={() => setError('')}>{error}</Alert>}
            {notice && <Alert variant="info" dismissible onClose={() => setNotice('')} className="py-2 small">{notice}</Alert>}

            <Row className="g-2 align-items-end mb-3">
              <Col md={3}>
                <Form.Label className="text-white small mb-1">Add role</Form.Label>
                <Form.Control
                  size="sm"
                  placeholder="e.g. viewer, editor, billing admin"
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addItem('role', newRole); } }}
                />
              </Col>
              <Col md="auto">
                <Button size="sm" variant="outline-danger" disabled={busy || !newRole.trim()} onClick={() => addItem('role', newRole)}>
                  <i className="bi bi-plus-lg me-1" />Role
                </Button>
              </Col>
              <Col md={3}>
                <Form.Label className="text-white small mb-1">Add action</Form.Label>
                <Form.Control
                  size="sm"
                  placeholder="e.g. delete invoice, export users"
                  value={newAction}
                  onChange={(e) => setNewAction(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addItem('action', newAction); } }}
                />
              </Col>
              <Col md="auto">
                <Button size="sm" variant="outline-danger" disabled={busy || !newAction.trim()} onClick={() => addItem('action', newAction)}>
                  <i className="bi bi-plus-lg me-1" />Action
                </Button>
              </Col>
              <Col className="d-flex align-items-center justify-content-end gap-2">
                {pendingCount > 0 && (
                  <Badge bg="warning" text="dark">{pendingCount} unsaved cell{pendingCount === 1 ? '' : 's'}</Badge>
                )}
                <Button size="sm" variant="danger" disabled={busy || pendingCount === 0} onClick={saveMatrix}>
                  {busy
                    ? <Spinner size="sm" animation="border" />
                    : (pendingCount === 0 ? 'Save changes' : `Save ${pendingCount} change${pendingCount === 1 ? '' : 's'}`)}
                </Button>
                <Button size="sm" variant="outline-secondary" disabled={busy || pendingCount === 0} onClick={() => setPending({})}>
                  Discard
                </Button>
                <Button size="sm" variant="outline-secondary" disabled={loading || busy} onClick={fetchAll}>
                  {loading ? <Spinner size="sm" animation="border" /> : 'Reload'}
                </Button>
              </Col>
            </Row>

            {/* The legend carries the point of the whole screen, so it sits above the grid rather
                than under it. */}
            <div className="border border-secondary rounded p-2 mb-2">
              <div className="d-flex flex-wrap align-items-center gap-3">
                {CELL_ORDER.map((v) => (
                  <span key={v} className="d-flex align-items-center gap-2">
                    <span style={{
                      backgroundColor: VALUE_META[v].bg,
                      color: VALUE_META[v].color,
                      border: `1px solid ${VALUE_META[v].border}`,
                      fontWeight: VALUE_META[v].weight,
                      borderRadius: '4px',
                      padding: '2px 8px',
                      fontSize: '0.68rem',
                    }}>
                      {v === 'forbidden_to_do' && <i className="bi bi-shield-exclamation me-1" />}
                      {VALUE_META[v].short}
                    </span>
                    <span className="text-white-50 small">{VALUE_META[v].label}</span>
                  </span>
                ))}
                <span className="d-flex align-items-center gap-2">
                  <span style={{
                    color: UNSET_META.color,
                    border: `1px solid ${UNSET_META.border}`,
                    borderRadius: '4px',
                    padding: '2px 10px',
                    fontSize: '0.68rem',
                  }}>-</span>
                  <span className="text-white-50 small">Not recorded yet</span>
                </span>
                <span className="text-white-50 small ms-auto">
                  {roles.length} role(s), {actions.length} action(s), {forbiddenCount} forbidden cell(s)
                </span>
              </div>
              <div className="text-white-50 mt-2" style={{ fontSize: '0.72rem' }}>
                Forbidden To Do is drawn loudest because it is the only value whose violation is a
                finding. Can Not Do is an action the role was simply never given, so reaching it is
                usually a permissions bug. Forbidden To Do must never be reachable by that role for
                any reason, and an application that only greys the button out looks exactly the same
                in both cases. Click a cell to cycle it, shift click to go back.
              </div>
            </div>

            {loading ? (
              <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
            ) : roles.length === 0 || actions.length === 0 ? (
              <div className="text-white-50 small fst-italic py-4 text-center">
                Add at least one role and one action to build the matrix. Roles are who the
                application thinks is asking; actions are the individual things it decides about.
              </div>
            ) : (
              // The grid gets its own scroll container so a matrix wider than the screen never
              // drags the modal body sideways with it.
              <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '46vh', border: '1px solid #495057', borderRadius: '4px' }}>
                <table className="table table-dark table-bordered mb-0" style={{ fontSize: '0.75rem', width: 'auto', minWidth: '100%' }}>
                  <thead>
                    <tr>
                      <th style={stickyCorner} className="align-middle">
                        <span className="text-white-50 text-uppercase" style={{ fontSize: '0.68rem' }}>Role / Action</span>
                      </th>
                      {actions.map((a, i) => (
                        <th key={a.id} style={{ ...stickyHead, minWidth: '124px' }} className="align-middle">
                          {renderNameCell('action', a, i, actions)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {roles.map((r, i) => (
                      <tr key={r.id}>
                        <td style={stickyCol} className="align-middle">
                          {renderNameCell('role', r, i, roles)}
                        </td>
                        {actions.map((a) => renderCell(r, a))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* The selected cell gets a detail strip so a value can be picked directly rather than
                cycled to, and so the per cell note has somewhere to live without a second modal. */}
            {selectedInfo && (
              <div className="border border-secondary rounded p-2 mt-2">
                <Row className="g-2 align-items-end">
                  <Col md={3}>
                    <div className="text-white-50 text-uppercase" style={{ fontSize: '0.66rem' }}>Selected cell</div>
                    <div className="text-white text-truncate" title={`${selectedInfo.role.name} / ${selectedInfo.action.name}`}>
                      {selectedInfo.role.name} <span className="text-white-50">/</span> {selectedInfo.action.name}
                    </div>
                  </Col>
                  <Col md={3}>
                    <Form.Label className="text-white small mb-1">Verdict</Form.Label>
                    <Form.Select
                      size="sm"
                      value={selectedInfo.value || ''}
                      onChange={(e) => setCell(selectedInfo.role.id, selectedInfo.action.id, e.target.value)}
                    >
                      <option value="" disabled>Not recorded</option>
                      {CELL_ORDER.map((v) => <option key={v} value={v}>{VALUE_META[v].label}</option>)}
                    </Form.Select>
                  </Col>
                  <Col md={6}>
                    <Form.Label className="text-white small mb-1">Note</Form.Label>
                    <Form.Control
                      size="sm"
                      placeholder="Where this was confirmed, which account proved it, what the UI does"
                      value={selectedInfo.notes}
                      onChange={(e) => setCell(
                        selectedInfo.role.id,
                        selectedInfo.action.id,
                        selectedInfo.value || 'cannot_do',
                        e.target.value
                      )}
                    />
                  </Col>
                </Row>
              </div>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        {pendingCount > 0 && (
          <span className="text-warning small me-auto">
            {pendingCount} cell(s) still unsaved. Closing loses them.
          </span>
        )}
        <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
};

export default RoleAccessModal;
