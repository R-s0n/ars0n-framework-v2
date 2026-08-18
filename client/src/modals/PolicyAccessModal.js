import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { Modal, Row, Col, Button, ButtonGroup, Form, Spinner, Badge, ListGroup, Alert, Table } from 'react-bootstrap';

// Policy based access control, modelled at the level the application actually configures it: an
// entity that owns a list of permissions, and instances of that entity that each carry their own
// setting for every one of them.
//
// The three way value is the whole point of the screen. allow and deny are obvious, unset is the one
// that finds bugs: a permission that was never granted and a permission that was granted and then
// revoked are different code paths in most implementations, and they fail differently. Collapsing
// unset into deny in the model means the difference is never tested for.

const VALUES = [
  { value: 'allow', label: 'Allow', variant: 'success' },
  { value: 'deny', label: 'Deny', variant: 'danger' },
  { value: 'unset', label: 'Unset', variant: 'secondary' },
];

const VALUE_META = VALUES.reduce((acc, v) => { acc[v.value] = v; return acc; }, {});

const EMPTY_ENTITY_FORM = { name: '', description: '', notes: '' };
const EMPTY_PERMISSION_FORM = { id: null, key: '', name: '', description: '' };
const EMPTY_INSTANCE_FORM = { id: null, name: '', subject: '', description: '', notes: '' };

// The key is what the application calls the permission and it has to be unique per entity, but
// typing both a name and a key for twenty permissions is where an operator gives up. Derive it from
// the name when the box is left empty, and leave it alone the moment anything is typed in it.
function slugKey(name) {
  return String(name || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

function orderPermissions(list) {
  return [...(list || [])].sort((a, b) => {
    const sa = a.sort_order == null ? 0 : a.sort_order;
    const sb = b.sort_order == null ? 0 : b.sort_order;
    if (sa !== sb) return sa - sb;
    // Ties are common, because everything created before anyone reordered carries the same default.
    // Falling back to creation time keeps the list from shuffling on every refetch.
    return String(a.created_at || '').localeCompare(String(b.created_at || ''));
  });
}

function settingsOf(instance) {
  if (!instance) return {};
  const out = {};
  (instance.settings || []).forEach((s) => {
    out[s.permission_id] = { value: s.value || 'unset', notes: s.notes || '' };
  });
  return out;
}

const PolicyAccessModal = ({ show, handleClose, scopeTargetId }) => {
  const [entities, setEntities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const [selectedEntityId, setSelectedEntityId] = useState(null);
  const [selectedInstanceId, setSelectedInstanceId] = useState(null);

  const [entityForm, setEntityForm] = useState(EMPTY_ENTITY_FORM);
  const [renamingEntityId, setRenamingEntityId] = useState(null);
  const [renameDraft, setRenameDraft] = useState('');
  // Which rename is still open, held in a ref rather than in state because the commit runs from
  // both Enter and blur and has to be able to see the cancellation the other one just made. State
  // would still read the old value inside those handlers, so Escape would save anyway and Enter
  // would fire the write twice.
  const renameGuard = useRef(null);

  const [permissionForm, setPermissionForm] = useState(EMPTY_PERMISSION_FORM);
  const [keyTouched, setKeyTouched] = useState(false);
  const [instanceForm, setInstanceForm] = useState(EMPTY_INSTANCE_FORM);

  // The grid is edited locally and saved in one shot, so it has to remember which instance it
  // belongs to. Without that, refetching after an unrelated change would drop another instance's
  // values into the open one.
  const [draft, setDraft] = useState({ instanceId: null, values: {} });
  const [dirty, setDirty] = useState(false);

  const selectedEntity = useMemo(
    () => entities.find((e) => e.id === selectedEntityId) || null,
    [entities, selectedEntityId]
  );

  const permissions = useMemo(
    () => orderPermissions(selectedEntity ? selectedEntity.permissions : []),
    [selectedEntity]
  );

  const instances = useMemo(
    () => (selectedEntity && Array.isArray(selectedEntity.instances) ? selectedEntity.instances : []),
    [selectedEntity]
  );

  const selectedInstance = useMemo(
    () => instances.find((i) => i.id === selectedInstanceId) || null,
    [instances, selectedInstanceId]
  );

  const fetchPolicy = useCallback(async () => {
    if (!scopeTargetId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/authz/policy/${scopeTargetId}`);
      const data = res.ok ? await res.json() : [];
      const list = Array.isArray(data) ? data : [];
      setEntities(list);
      setSelectedEntityId((prev) => (prev && list.some((e) => e.id === prev)
        ? prev
        : (list[0] ? list[0].id : null)));
    } catch (e) {
      console.error('[PolicyAccess] fetchPolicy failed:', e);
      setError(`Could not load policy entities: ${e.message}`);
      setEntities([]);
    } finally {
      setLoading(false);
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (show && scopeTargetId) fetchPolicy();
    if (!show) {
      setSelectedEntityId(null);
      setSelectedInstanceId(null);
      setEntityForm(EMPTY_ENTITY_FORM);
      setPermissionForm(EMPTY_PERMISSION_FORM);
      setInstanceForm(EMPTY_INSTANCE_FORM);
      setDraft({ instanceId: null, values: {} });
      setDirty(false);
      setError('');
      setNotice('');
    }
  }, [show, scopeTargetId, fetchPolicy]);

  // Switching entity invalidates the instance, and every editor below it.
  useEffect(() => {
    setSelectedInstanceId(null);
    setPermissionForm(EMPTY_PERMISSION_FORM);
    setKeyTouched(false);
    setInstanceForm(EMPTY_INSTANCE_FORM);
  }, [selectedEntityId]);

  // Build the grid. A permission added while an instance is open triggers a refetch, and rebuilding
  // from scratch there would throw away three way choices that have not been saved yet, so an open
  // draft for the same instance is merged over rather than replaced.
  useEffect(() => {
    if (!selectedInstance) {
      setDraft({ instanceId: null, values: {} });
      setDirty(false);
      return;
    }
    const stored = settingsOf(selectedInstance);
    setDraft((prev) => {
      const keep = prev.instanceId === selectedInstance.id ? prev.values : {};
      const values = {};
      permissions.forEach((p) => {
        values[p.id] = keep[p.id] || stored[p.id] || { value: 'unset', notes: '' };
      });
      return { instanceId: selectedInstance.id, values };
    });
    if (draft.instanceId !== selectedInstance.id) setDirty(false);
    // draft.instanceId is read to decide whether this is a switch or a refresh, and including draft
    // itself in the deps would loop on every setDraft.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedInstance, permissions]);

  // Only the create calls have a body worth reading, and even those are the one field {id}. A write
  // that succeeded but answered with nothing is still a success, so a parse failure is swallowed
  // rather than surfaced as an error over work that already landed.
  const send = async (url, method, body) => {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error((await res.text()) || `Request failed (${res.status})`);
    return res.json().catch(() => ({}));
  };

  const post = (url, body) => send(url, 'POST', body);
  const put = (url, body) => send(url, 'PUT', body);
  const del = (url) => send(url, 'DELETE', null);

  const run = async (fn, successNotice) => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await fn();
      if (successNotice) setNotice(successNotice);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  // ---- entities ----------------------------------------------------------

  const createEntity = () => run(async () => {
    if (!entityForm.name.trim()) return;
    const created = await post(`/api/authz/policy/${scopeTargetId}`, {
      name: entityForm.name.trim(),
      description: entityForm.description,
      notes: entityForm.notes,
    });
    setEntityForm(EMPTY_ENTITY_FORM);
    await fetchPolicy();
    if (created && created.id) setSelectedEntityId(created.id);
  }, 'Entity created. Enumerate its permissions next, one per action the admin screen exposes.');

  const startRename = (entity) => {
    renameGuard.current = entity.id;
    setRenamingEntityId(entity.id);
    setRenameDraft(entity.name || '');
  };

  const cancelRename = () => {
    renameGuard.current = null;
    setRenamingEntityId(null);
  };

  const commitRename = (entity) => run(async () => {
    if (renameGuard.current !== entity.id) return;
    renameGuard.current = null;
    const name = renameDraft.trim();
    setRenamingEntityId(null);
    if (!name || name === entity.name) return;
    // The handler writes every column from the body, so the fields that are not being renamed have
    // to be sent back as they are or they get blanked.
    await put(`/api/authz/policy/entity/${entity.id}`, {
      name,
      description: entity.description || '',
      notes: entity.notes || '',
    });
    await fetchPolicy();
  });

  const deleteEntity = (id) => run(async () => {
    await del(`/api/authz/policy/entity/${id}`);
    if (selectedEntityId === id) setSelectedEntityId(null);
    await fetchPolicy();
  });

  // ---- permissions -------------------------------------------------------

  const savePermission = () => run(async () => {
    const name = permissionForm.name.trim();
    if (!name || !selectedEntity) return;
    const key = (permissionForm.key.trim() || slugKey(name));
    if (permissionForm.id) {
      const existing = permissions.find((p) => p.id === permissionForm.id);
      await put(`/api/authz/policy/permission/${permissionForm.id}`, {
        key,
        name,
        description: permissionForm.description,
        sort_order: existing && existing.sort_order != null ? existing.sort_order : 0,
      });
    } else {
      await post(`/api/authz/policy/entity/${selectedEntity.id}/permissions`, {
        key,
        name,
        description: permissionForm.description,
        sort_order: permissions.length,
      });
    }
    setPermissionForm(EMPTY_PERMISSION_FORM);
    setKeyTouched(false);
    await fetchPolicy();
  });

  const deletePermission = (id) => run(async () => {
    await del(`/api/authz/policy/permission/${id}`);
    if (permissionForm.id === id) setPermissionForm(EMPTY_PERMISSION_FORM);
    await fetchPolicy();
  });

  // Moving a row rewrites sort_order for everything whose position changed rather than swapping two
  // values. Rows created before anyone reordered all share the same default, and a swap between two
  // rows that both read zero moves nothing.
  const movePermission = (index, delta) => run(async () => {
    const target = index + delta;
    if (target < 0 || target >= permissions.length) return;
    const reordered = [...permissions];
    const [moved] = reordered.splice(index, 1);
    reordered.splice(target, 0, moved);
    for (let i = 0; i < reordered.length; i += 1) {
      const p = reordered[i];
      if (p.sort_order === i) continue;
      // Sequential rather than parallel: these are ordering writes on the same list, and firing
      // them at once means the last response decides what the order ended up being.
      // eslint-disable-next-line no-await-in-loop
      await put(`/api/authz/policy/permission/${p.id}`, {
        key: p.key,
        name: p.name,
        description: p.description || '',
        sort_order: i,
      });
    }
    await fetchPolicy();
  });

  // ---- instances ---------------------------------------------------------

  const saveInstance = () => run(async () => {
    const name = instanceForm.name.trim();
    if (!name || !selectedEntity) return;
    const body = {
      name,
      subject: instanceForm.subject,
      description: instanceForm.description,
      notes: instanceForm.notes,
    };
    if (instanceForm.id) {
      await put(`/api/authz/policy/instance/${instanceForm.id}`, body);
    } else {
      const created = await post(`/api/authz/policy/entity/${selectedEntity.id}/instances`, body);
      if (created && created.id) setSelectedInstanceId(created.id);
    }
    setInstanceForm(EMPTY_INSTANCE_FORM);
    await fetchPolicy();
  });

  const deleteInstance = (id) => run(async () => {
    await del(`/api/authz/policy/instance/${id}`);
    if (selectedInstanceId === id) setSelectedInstanceId(null);
    if (instanceForm.id === id) setInstanceForm(EMPTY_INSTANCE_FORM);
    await fetchPolicy();
  });

  // ---- the grid ----------------------------------------------------------

  const setCell = (permissionId, patch) => {
    setDraft((prev) => ({
      instanceId: prev.instanceId,
      values: {
        ...prev.values,
        [permissionId]: { ...(prev.values[permissionId] || { value: 'unset', notes: '' }), ...patch },
      },
    }));
    setDirty(true);
  };

  const saveSettings = () => run(async () => {
    if (!selectedInstance) return;
    // The whole array goes up every time, including the rows left on unset. A partial save would
    // leave a permission that was flipped back to unset still reading deny on the server, which is
    // exactly the distinction this screen exists to keep.
    const settings = permissions.map((p) => {
      const cell = draft.values[p.id] || { value: 'unset', notes: '' };
      return { permission_id: p.id, value: cell.value, notes: cell.notes };
    });
    await put(`/api/authz/policy/instance/${selectedInstance.id}/settings`, { settings });
    setDirty(false);
    await fetchPolicy();
  }, 'Settings saved.');

  const tally = useMemo(() => {
    const counts = { allow: 0, deny: 0, unset: 0 };
    permissions.forEach((p) => {
      const cell = draft.values[p.id];
      const v = cell && VALUE_META[cell.value] ? cell.value : 'unset';
      counts[v] += 1;
    });
    return counts;
  }, [permissions, draft]);

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Policy Based Access Control</Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '72vh' }}>
        {!scopeTargetId ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <>
            {error && <Alert variant="danger" dismissible onClose={() => setError('')}>{error}</Alert>}
            {notice && (
              <Alert variant="info" dismissible onClose={() => setNotice('')} className="py-2 small">
                {notice}
              </Alert>
            )}

            <div className="text-white-50 small mb-3">
              An application where an admin turns each action on or off by hand. Model the entity, list
              every permission it can hold one at a time, then record the real instances and the
              configuration each of them shipped with. What is on this screen is what should be refused
              later.
            </div>

            <Row>
              {/* LEFT: entities */}
              <Col md={3} className="border-end border-secondary" style={{ maxHeight: '64vh', overflowY: 'auto' }}>
                <div className="text-white-50 small text-uppercase mb-2">Policy entities</div>

                <Form.Control
                  size="sm"
                  className="mb-1"
                  placeholder="New entity name, then Enter"
                  value={entityForm.name}
                  disabled={busy}
                  onChange={(e) => setEntityForm({ ...entityForm, name: e.target.value })}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); createEntity(); } }}
                />
                <Form.Control
                  size="sm"
                  className="mb-2"
                  style={{ fontSize: '0.72rem' }}
                  placeholder="Description (optional)"
                  value={entityForm.description}
                  disabled={busy}
                  onChange={(e) => setEntityForm({ ...entityForm, description: e.target.value })}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); createEntity(); } }}
                />

                {loading ? (
                  <div className="text-center py-3"><Spinner size="sm" animation="border" variant="danger" /></div>
                ) : entities.length === 0 ? (
                  <div className="text-white-50 small fst-italic">
                    No entities yet. An entity is the thing permissions attach to: a project, a
                    workspace, an API key, a service account.
                  </div>
                ) : (
                  <ListGroup variant="flush">
                    {entities.map((e) => (
                      <ListGroup.Item
                        key={e.id}
                        action
                        active={e.id === selectedEntityId}
                        onClick={() => setSelectedEntityId(e.id)}
                        className="bg-dark text-white py-2"
                      >
                        {renamingEntityId === e.id ? (
                          <Form.Control
                            size="sm"
                            autoFocus
                            value={renameDraft}
                            onClick={(ev) => ev.stopPropagation()}
                            onChange={(ev) => setRenameDraft(ev.target.value)}
                            onBlur={() => commitRename(e)}
                            onKeyDown={(ev) => {
                              if (ev.key === 'Enter') { ev.preventDefault(); commitRename(e); }
                              if (ev.key === 'Escape') cancelRename();
                            }}
                          />
                        ) : (
                          <div className="d-flex justify-content-between align-items-center">
                            <span className="text-truncate me-2">{e.name}</span>
                            <span className="d-flex align-items-center gap-2 flex-shrink-0">
                              <Badge bg="secondary" title="permissions">
                                {(e.permissions || []).length}
                              </Badge>
                              <Badge bg="dark" className="border border-secondary" title="instances">
                                {(e.instances || []).length}
                              </Badge>
                              <i
                                role="button"
                                className="bi bi-pencil text-white-50"
                                title="Rename"
                                onClick={(ev) => { ev.stopPropagation(); startRename(e); }}
                              />
                              <i
                                role="button"
                                className="bi bi-trash text-danger"
                                title="Delete entity"
                                onClick={(ev) => { ev.stopPropagation(); deleteEntity(e.id); }}
                              />
                            </span>
                          </div>
                        )}
                        {e.description && (
                          <div className="text-white-50 text-truncate" style={{ fontSize: '0.66rem' }}>
                            {e.description}
                          </div>
                        )}
                      </ListGroup.Item>
                    ))}
                  </ListGroup>
                )}
              </Col>

              {/* MIDDLE: permissions for the selected entity */}
              <Col md={4} className="border-end border-secondary" style={{ maxHeight: '64vh', overflowY: 'auto' }}>
                {!selectedEntity ? (
                  <div className="text-center text-white-50 py-5">
                    Select an entity to list its permissions.
                  </div>
                ) : (
                  <>
                    <div className="text-white-50 small text-uppercase mb-1">
                      Permissions on {selectedEntity.name}
                    </div>
                    <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem' }}>
                      Every action the admin screen can grant, one row each. Order them the way the
                      application presents them, it makes a missing one easier to spot.
                    </div>

                    <Row className="g-2 mb-2">
                      <Col md={6}>
                        <Form.Control
                          size="sm"
                          placeholder="Permission name"
                          value={permissionForm.name}
                          onChange={(e) => setPermissionForm({ ...permissionForm, name: e.target.value })}
                        />
                      </Col>
                      <Col md={6}>
                        <Form.Control
                          size="sm"
                          style={{ fontFamily: 'monospace', fontSize: '0.72rem' }}
                          placeholder={permissionForm.name && !keyTouched
                            ? slugKey(permissionForm.name)
                            : 'key'}
                          value={permissionForm.key}
                          onChange={(e) => {
                            setKeyTouched(true);
                            setPermissionForm({ ...permissionForm, key: e.target.value });
                          }}
                        />
                      </Col>
                      <Col md={12}>
                        <Form.Control
                          size="sm"
                          placeholder="What this permission actually lets the holder do"
                          value={permissionForm.description}
                          onChange={(e) => setPermissionForm({ ...permissionForm, description: e.target.value })}
                        />
                      </Col>
                      <Col md={12} className="d-flex gap-2">
                        <Button
                          size="sm"
                          variant="danger"
                          disabled={busy || !permissionForm.name.trim()}
                          onClick={savePermission}
                        >
                          {permissionForm.id ? 'Save permission' : 'Add permission'}
                        </Button>
                        {permissionForm.id && (
                          <Button
                            size="sm"
                            variant="outline-secondary"
                            disabled={busy}
                            onClick={() => { setPermissionForm(EMPTY_PERMISSION_FORM); setKeyTouched(false); }}
                          >
                            Cancel
                          </Button>
                        )}
                      </Col>
                    </Row>

                    {permissions.length === 0 ? (
                      <div className="text-white-50 small fst-italic">
                        None yet. Add them one by one, the way the application lists them.
                      </div>
                    ) : (
                      <ListGroup variant="flush">
                        {permissions.map((p, idx) => (
                          <ListGroup.Item
                            key={p.id}
                            className="bg-dark text-white py-1"
                            active={permissionForm.id === p.id}
                          >
                            <div className="d-flex justify-content-between align-items-center">
                              <span className="text-truncate me-2">
                                <span className="d-block text-truncate">{p.name}</span>
                                <code className="text-info" style={{ fontSize: '0.66rem' }}>{p.key}</code>
                              </span>
                              <span className="d-flex align-items-center gap-2 flex-shrink-0">
                                <i
                                  role="button"
                                  className={`bi bi-arrow-up ${idx === 0 ? 'text-secondary' : 'text-white-50'}`}
                                  title="Move up"
                                  onClick={() => { if (idx > 0) movePermission(idx, -1); }}
                                />
                                <i
                                  role="button"
                                  className={`bi bi-arrow-down ${idx === permissions.length - 1 ? 'text-secondary' : 'text-white-50'}`}
                                  title="Move down"
                                  onClick={() => { if (idx < permissions.length - 1) movePermission(idx, 1); }}
                                />
                                <i
                                  role="button"
                                  className="bi bi-pencil text-white-50"
                                  title="Edit"
                                  onClick={() => {
                                    setKeyTouched(true);
                                    setPermissionForm({
                                      id: p.id,
                                      key: p.key || '',
                                      name: p.name || '',
                                      description: p.description || '',
                                    });
                                  }}
                                />
                                <i
                                  role="button"
                                  className="bi bi-trash text-danger"
                                  title="Delete permission"
                                  onClick={() => deletePermission(p.id)}
                                />
                              </span>
                            </div>
                            {p.description && (
                              <div className="text-white-50 text-truncate" style={{ fontSize: '0.66rem' }}>
                                {p.description}
                              </div>
                            )}
                          </ListGroup.Item>
                        ))}
                      </ListGroup>
                    )}
                  </>
                )}
              </Col>

              {/* RIGHT: instances, and the settings grid for whichever one is open */}
              <Col md={5} style={{ maxHeight: '64vh', overflowY: 'auto' }}>
                {!selectedEntity ? (
                  <div className="text-center text-white-50 py-5">
                    Select an entity to record instances of it.
                  </div>
                ) : (
                  <>
                    <div className="text-white-50 small text-uppercase mb-1">
                      Instances of {selectedEntity.name}
                    </div>
                    <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem' }}>
                      One row per real, configured thing: this project, that API key. The subject is
                      whoever holds it.
                    </div>

                    <Row className="g-2 mb-2">
                      <Col md={5}>
                        <Form.Control
                          size="sm"
                          placeholder="Instance name"
                          value={instanceForm.name}
                          onChange={(e) => setInstanceForm({ ...instanceForm, name: e.target.value })}
                        />
                      </Col>
                      <Col md={4}>
                        <Form.Control
                          size="sm"
                          placeholder="Subject (who holds it)"
                          value={instanceForm.subject}
                          onChange={(e) => setInstanceForm({ ...instanceForm, subject: e.target.value })}
                        />
                      </Col>
                      <Col md={3} className="d-flex gap-1">
                        <Button
                          size="sm"
                          variant="danger"
                          className="flex-grow-1"
                          disabled={busy || !instanceForm.name.trim()}
                          onClick={saveInstance}
                        >
                          {instanceForm.id ? 'Save' : 'Add'}
                        </Button>
                        {instanceForm.id && (
                          <Button
                            size="sm"
                            variant="outline-secondary"
                            disabled={busy}
                            onClick={() => setInstanceForm(EMPTY_INSTANCE_FORM)}
                          >
                            X
                          </Button>
                        )}
                      </Col>
                      <Col md={12}>
                        <Form.Control
                          size="sm"
                          style={{ fontSize: '0.72rem' }}
                          placeholder="Notes: how this instance was configured, and by whom"
                          value={instanceForm.notes}
                          onChange={(e) => setInstanceForm({ ...instanceForm, notes: e.target.value })}
                        />
                      </Col>
                    </Row>

                    {instances.length === 0 ? (
                      <div className="text-white-50 small fst-italic mb-3">
                        No instances yet.
                      </div>
                    ) : (
                      <ListGroup variant="flush" className="mb-3">
                        {instances.map((i) => (
                          <ListGroup.Item
                            key={i.id}
                            action
                            active={i.id === selectedInstanceId}
                            onClick={() => setSelectedInstanceId(i.id)}
                            className="bg-dark text-white py-1"
                          >
                            <div className="d-flex justify-content-between align-items-center">
                              <span className="text-truncate me-2">
                                {i.name}
                                {i.subject && (
                                  <span className="text-white-50 ms-2" style={{ fontSize: '0.68rem' }}>
                                    {i.subject}
                                  </span>
                                )}
                              </span>
                              <span className="d-flex align-items-center gap-2 flex-shrink-0">
                                <Badge bg="secondary" title="permissions configured on this instance">
                                  {(i.settings || []).filter((s) => s.value && s.value !== 'unset').length}
                                  /{permissions.length}
                                </Badge>
                                <i
                                  role="button"
                                  className="bi bi-pencil text-white-50"
                                  title="Edit"
                                  onClick={(ev) => {
                                    ev.stopPropagation();
                                    setInstanceForm({
                                      id: i.id,
                                      name: i.name || '',
                                      subject: i.subject || '',
                                      description: i.description || '',
                                      notes: i.notes || '',
                                    });
                                  }}
                                />
                                <i
                                  role="button"
                                  className="bi bi-trash text-danger"
                                  title="Delete instance"
                                  onClick={(ev) => { ev.stopPropagation(); deleteInstance(i.id); }}
                                />
                              </span>
                            </div>
                          </ListGroup.Item>
                        ))}
                      </ListGroup>
                    )}

                    {selectedInstance && (
                      <>
                        <div className="d-flex justify-content-between align-items-center mb-1">
                          <span className="text-white-50 small text-uppercase">
                            {selectedInstance.name} configuration
                          </span>
                          <span className="d-flex align-items-center gap-2">
                            <Badge bg="success">{tally.allow} allow</Badge>
                            <Badge bg="danger">{tally.deny} deny</Badge>
                            <Badge bg="secondary">{tally.unset} unset</Badge>
                          </span>
                        </div>
                        <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem' }}>
                          Unset is not Deny. Deny means the application was told no and holds a record
                          saying so. Unset means it was never asked, so nothing was written down. Those
                          are different code paths in most implementations: one checks a stored refusal,
                          the other falls through to a default, and the default is where the bug lives.
                          Keep them apart here or the difference never gets tested.
                        </div>

                        {permissions.length === 0 ? (
                          <div className="text-white-50 small fst-italic">
                            Add permissions to this entity first, the grid is built from them.
                          </div>
                        ) : (
                          <>
                            <Table size="sm" variant="dark" bordered className="mb-2" style={{ fontSize: '0.72rem' }}>
                              <thead>
                                <tr>
                                  <th style={{ width: '38%' }}>Permission</th>
                                  <th style={{ width: '30%' }}>Value</th>
                                  <th>Note</th>
                                </tr>
                              </thead>
                              <tbody>
                                {permissions.map((p) => {
                                  const cell = draft.values[p.id] || { value: 'unset', notes: '' };
                                  return (
                                    <tr key={p.id}>
                                      <td>
                                        <span className="d-block text-truncate" title={p.description || p.name}>
                                          {p.name}
                                        </span>
                                        <code className="text-info" style={{ fontSize: '0.64rem' }}>{p.key}</code>
                                      </td>
                                      <td>
                                        <ButtonGroup size="sm">
                                          {VALUES.map((v) => (
                                            <Button
                                              key={v.value}
                                              className="py-0 px-2"
                                              style={{ fontSize: '0.68rem' }}
                                              variant={cell.value === v.value ? v.variant : `outline-${v.variant}`}
                                              onClick={() => setCell(p.id, { value: v.value })}
                                            >
                                              {v.label}
                                            </Button>
                                          ))}
                                        </ButtonGroup>
                                      </td>
                                      <td>
                                        <Form.Control
                                          size="sm"
                                          className="py-0"
                                          style={{ fontSize: '0.7rem' }}
                                          placeholder="what this looked like in the UI"
                                          value={cell.notes}
                                          onChange={(e) => setCell(p.id, { notes: e.target.value })}
                                        />
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </Table>

                            <div className="d-flex align-items-center gap-2">
                              <Button
                                size="sm"
                                variant="danger"
                                disabled={busy || !dirty}
                                onClick={saveSettings}
                              >
                                {busy ? <Spinner size="sm" animation="border" /> : 'Save settings'}
                              </Button>
                              <span className="text-white-50 small">
                                {dirty
                                  ? 'Unsaved changes. Saving writes every row, including the ones left on Unset.'
                                  : 'Saved.'}
                              </span>
                            </div>
                          </>
                        )}
                      </>
                    )}
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

export default PolicyAccessModal;
