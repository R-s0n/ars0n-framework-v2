import { useState, useEffect, useCallback } from 'react';
import { Modal, Row, Col, Button, Form, Spinner, Badge, ListGroup } from 'react-bootstrap';
import AuthFlowChart from '../components/AuthFlowChart';

const CATEGORY_LABELS = { register: 'Register', login: 'Login', mfa_otp: 'MFA/OTP', reset: 'Reset' };

const AUTH_TYPES = [
  { value: '', label: '— none —' },
  { value: 'password', label: 'Username / Password' },
  { value: 'basic', label: 'HTTP Basic / Digest' },
  { value: 'magic_link', label: 'Magic Link' },
  { value: 'otp', label: 'Email / SMS OTP' },
  { value: 'passkey', label: 'Passkey / WebAuthn' },
  { value: 'oauth', label: 'OAuth 2.0' },
  { value: 'oidc', label: 'OpenID Connect' },
  { value: 'saml', label: 'SAML SSO' },
  { value: 'social', label: 'Social Login' },
  { value: 'jwt', label: 'JWT / Bearer' },
  { value: 'api_key', label: 'API Key' },
  { value: 'session_cookie', label: 'Session Cookie' },
  { value: 'ldap', label: 'LDAP / AD' },
  { value: 'kerberos', label: 'Kerberos' },
  { value: 'mtls', label: 'Client Cert (mTLS)' },
  { value: 'mfa', label: 'MFA / 2FA' },
  { value: 'biometric', label: 'Biometric' },
];

const RAW_REQUEST_PLACEHOLDER = `POST /login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username":"user","password":"pass"}`;

function statusVariant(status) {
  if (!status) return 'secondary';
  if (status >= 200 && status < 300) return 'success';
  if (status >= 300 && status < 400) return 'info';
  if (status >= 400 && status < 500) return 'warning';
  if (status >= 500) return 'danger';
  return 'secondary';
}

// Reconstruct a readable raw response from a step's captured status/headers/body.
function buildRawResponse(step) {
  if (!step) return '';
  let raw = '';
  if (step.error) raw += `[send error] ${step.error}\n\n`;
  if (step.response_status) raw += `HTTP ${step.response_status}\n`;
  if (step.response_headers) {
    Object.entries(step.response_headers).forEach(([k, vals]) => {
      (Array.isArray(vals) ? vals : [vals]).forEach((v) => { raw += `${k}: ${v}\n`; });
    });
  }
  raw += '\n';
  raw += step.response_body || '';
  return raw.trim();
}

const AuthFlowModal = ({ show, handleClose, category, activeTarget, onFlowsChange }) => {
  const [flows, setFlows] = useState([]);
  const [selectedFlowId, setSelectedFlowId] = useState(null);
  const [steps, setSteps] = useState([]);
  const [selectedStepId, setSelectedStepId] = useState(null);

  const [loadingFlows, setLoadingFlows] = useState(false);
  const [loadingSteps, setLoadingSteps] = useState(false);
  const [busy, setBusy] = useState(false);

  const [newFlowName, setNewFlowName] = useState('');
  const [flowForm, setFlowForm] = useState({ name: '', description: '', auth_type: '', base_url: '' });
  const [addStepName, setAddStepName] = useState('');
  const [addStepRaw, setAddStepRaw] = useState('');
  const [editRaw, setEditRaw] = useState('');

  const categoryLabel = CATEGORY_LABELS[category] || category || '';
  const selectedFlow = flows.find((f) => f.id === selectedFlowId) || null;
  const selectedStep = steps.find((s) => s.id === selectedStepId) || null;

  const fetchFlows = useCallback(async (keepSelection) => {
    if (!activeTarget || !category) return;
    setLoadingFlows(true);
    try {
      const res = await fetch(`/api/auth-flows/${activeTarget.id}?category=${encodeURIComponent(category)}`);
      const data = res.ok ? await res.json() : [];
      const list = Array.isArray(data) ? data : [];
      setFlows(list);
      setSelectedFlowId((prev) => {
        if (keepSelection && prev && list.some((f) => f.id === prev)) return prev;
        return list.length ? list[0].id : null;
      });
    } catch (e) {
      console.error('[AuthFlow] fetchFlows failed:', e);
      setFlows([]);
    } finally {
      setLoadingFlows(false);
    }
  }, [activeTarget, category]);

  const fetchSteps = useCallback(async (flowId, keepStep) => {
    if (!flowId) { setSteps([]); setSelectedStepId(null); return; }
    setLoadingSteps(true);
    try {
      const res = await fetch(`/api/auth-flows/flow/${flowId}/steps`);
      const data = res.ok ? await res.json() : [];
      const list = Array.isArray(data) ? data : [];
      setSteps(list);
      setSelectedStepId((prev) => {
        if (keepStep && prev && list.some((s) => s.id === prev)) return prev;
        return list.length ? list[0].id : null;
      });
    } catch (e) {
      console.error('[AuthFlow] fetchSteps failed:', e);
      setSteps([]);
    } finally {
      setLoadingSteps(false);
    }
  }, []);

  // Load flows when the modal opens (or target/category changes).
  useEffect(() => {
    if (show && activeTarget && category) fetchFlows(false);
    if (!show) { setSelectedFlowId(null); setSteps([]); setSelectedStepId(null); }
  }, [show, activeTarget, category, fetchFlows]);

  // Load steps + sync the flow-detail form whenever the selected flow changes.
  useEffect(() => {
    fetchSteps(selectedFlowId, false);
    const f = flows.find((x) => x.id === selectedFlowId);
    if (f) setFlowForm({ name: f.name || '', description: f.description || '', auth_type: f.auth_type || '', base_url: f.base_url || '' });
  }, [selectedFlowId, flows, fetchSteps]);

  // Keep the editable raw-request textarea in sync with the selected step.
  useEffect(() => { setEditRaw(selectedStep ? selectedStep.raw_request : ''); }, [selectedStepId]); // eslint-disable-line react-hooks/exhaustive-deps

  const notifyChange = () => { if (onFlowsChange) onFlowsChange(); };

  const createFlow = async () => {
    if (!newFlowName.trim() || !activeTarget) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/auth-flows/${activeTarget.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category, name: newFlowName.trim() }),
      });
      if (res.ok) {
        const created = await res.json();
        setNewFlowName('');
        await fetchFlows(true);
        if (created && created.id) setSelectedFlowId(created.id);
        notifyChange();
      }
    } finally { setBusy(false); }
  };

  const deleteFlow = async (flowId) => {
    if (!window.confirm('Delete this auth flow and all its steps?')) return;
    setBusy(true);
    try {
      await fetch(`/api/auth-flows/flow/${flowId}`, { method: 'DELETE' });
      if (selectedFlowId === flowId) setSelectedFlowId(null);
      await fetchFlows(true);
      notifyChange();
    } finally { setBusy(false); }
  };

  const saveFlow = async () => {
    if (!selectedFlowId) return;
    setBusy(true);
    try {
      await fetch(`/api/auth-flows/flow/${selectedFlowId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(flowForm),
      });
      await fetchFlows(true);
    } finally { setBusy(false); }
  };

  const addStep = async () => {
    if (!selectedFlowId || !addStepRaw.trim()) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/auth-flows/flow/${selectedFlowId}/steps`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: addStepName.trim(), raw_request: addStepRaw, replay: true }),
      });
      if (res.ok) {
        const created = await res.json();
        setAddStepName('');
        setAddStepRaw('');
        await fetchSteps(selectedFlowId, true);
        if (created && created.id) setSelectedStepId(created.id);
        await fetchFlows(true); // refresh step counts in the left list
        notifyChange();
      }
    } finally { setBusy(false); }
  };

  const saveStep = async () => {
    if (!selectedStepId) return;
    setBusy(true);
    try {
      await fetch(`/api/auth-flows/steps/${selectedStepId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_request: editRaw }),
      });
      await fetchSteps(selectedFlowId, true);
    } finally { setBusy(false); }
  };

  const replayStep = async () => {
    if (!selectedStepId) return;
    setBusy(true);
    try {
      await fetch(`/api/auth-flows/steps/${selectedStepId}/replay`, { method: 'POST' });
      await fetchSteps(selectedFlowId, true);
    } finally { setBusy(false); }
  };

  const deleteStep = async (stepId) => {
    setBusy(true);
    try {
      await fetch(`/api/auth-flows/steps/${stepId}`, { method: 'DELETE' });
      if (selectedStepId === stepId) setSelectedStepId(null);
      await fetchSteps(selectedFlowId, true);
      await fetchFlows(true);
      notifyChange();
    } finally { setBusy(false); }
  };

  const runFlow = async () => {
    if (!selectedFlowId) return;
    setBusy(true);
    try {
      await fetch(`/api/auth-flows/flow/${selectedFlowId}/replay`, { method: 'POST' });
      await fetchSteps(selectedFlowId, true);
    } finally { setBusy(false); }
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">{categoryLabel} Auth Flows</Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '70vh' }}>
        {!activeTarget ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <Row>
            {/* LEFT: flow list */}
            <Col md={4} className="border-end border-secondary">
              <div className="d-flex gap-2 mb-3">
                <Form.Control
                  size="sm"
                  placeholder={`New ${categoryLabel} flow name…`}
                  value={newFlowName}
                  onChange={(e) => setNewFlowName(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') createFlow(); }}
                />
                <Button size="sm" variant="outline-danger" onClick={createFlow} disabled={busy || !newFlowName.trim()}>
                  New Flow
                </Button>
              </div>
              {loadingFlows ? (
                <div className="text-center py-3"><Spinner size="sm" animation="border" variant="danger" /></div>
              ) : flows.length === 0 ? (
                <div className="text-white-50 small fst-italic">No {categoryLabel.toLowerCase()} flows yet.</div>
              ) : (
                <ListGroup variant="flush">
                  {flows.map((f) => (
                    <ListGroup.Item
                      key={f.id}
                      action
                      active={f.id === selectedFlowId}
                      onClick={() => setSelectedFlowId(f.id)}
                      className="bg-dark text-white d-flex justify-content-between align-items-center"
                    >
                      <span className="text-truncate">
                        {f.name}
                        {f.auth_type ? <span className="text-white-50 small"> · {f.auth_type}</span> : null}
                      </span>
                      <span className="d-flex align-items-center gap-2">
                        <Badge bg="secondary">{f.step_count || 0}</Badge>
                        <i
                          role="button"
                          className="bi bi-trash text-danger"
                          title="Delete flow"
                          onClick={(e) => { e.stopPropagation(); deleteFlow(f.id); }}
                        />
                      </span>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              )}
            </Col>

            {/* RIGHT: selected flow detail */}
            <Col md={8}>
              {!selectedFlow ? (
                <div className="text-center text-white-50 py-5">
                  Select a flow on the left, or create one to start documenting the {categoryLabel.toLowerCase()} request/response flow.
                </div>
              ) : (
                <>
                  {/* Flow metadata */}
                  <Row className="g-2 mb-3">
                    <Col md={5}>
                      <Form.Label className="text-white small mb-1">Flow name</Form.Label>
                      <Form.Control size="sm" value={flowForm.name}
                        onChange={(e) => setFlowForm({ ...flowForm, name: e.target.value })} />
                    </Col>
                    <Col md={4}>
                      <Form.Label className="text-white small mb-1">Auth type</Form.Label>
                      <Form.Select size="sm" value={flowForm.auth_type}
                        onChange={(e) => setFlowForm({ ...flowForm, auth_type: e.target.value })}>
                        {AUTH_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                      </Form.Select>
                    </Col>
                    <Col md={3} className="d-flex align-items-end">
                      <Button size="sm" variant="outline-secondary" className="w-100" onClick={saveFlow} disabled={busy}>
                        Save
                      </Button>
                    </Col>
                    <Col md={8}>
                      <Form.Label className="text-white small mb-1">Base URL (where steps are sent)</Form.Label>
                      <Form.Control size="sm" placeholder="https://example.com (defaults to each request's Host)"
                        value={flowForm.base_url}
                        onChange={(e) => setFlowForm({ ...flowForm, base_url: e.target.value })} />
                    </Col>
                    <Col md={4} className="d-flex align-items-end gap-2">
                      <Button size="sm" variant="outline-danger" className="w-100" onClick={runFlow} disabled={busy || !steps.length}>
                        {busy ? <Spinner size="sm" animation="border" /> : 'Run Flow'}
                      </Button>
                      <Button size="sm" variant="outline-secondary" className="w-100" disabled title="Coming soon: record this flow with the browser extension">
                        Record
                      </Button>
                    </Col>
                  </Row>

                  <Row>
                    {/* Flow chart */}
                    <Col md={5} className="border-end border-secondary">
                      <div className="text-white-50 small text-uppercase mb-1">Flow</div>
                      {loadingSteps
                        ? <div className="text-center py-3"><Spinner size="sm" animation="border" variant="danger" /></div>
                        : <AuthFlowChart steps={steps} selectedStepId={selectedStepId} onSelectStep={setSelectedStepId} />}
                    </Col>

                    {/* Step detail */}
                    <Col md={7}>
                      {selectedStep ? (
                        <>
                          <div className="d-flex justify-content-between align-items-center mb-1">
                            <span className="text-white-50 small text-uppercase">
                              Step {selectedStep.step_order} — Request
                            </span>
                            <span className="d-flex gap-2">
                              <Button size="sm" variant="outline-secondary" onClick={saveStep} disabled={busy}>Save</Button>
                              <Button size="sm" variant="outline-danger" onClick={replayStep} disabled={busy}>Replay</Button>
                              <Button size="sm" variant="outline-danger" onClick={() => deleteStep(selectedStep.id)} disabled={busy}>Delete</Button>
                            </span>
                          </div>
                          <Form.Control as="textarea" rows={8} value={editRaw}
                            onChange={(e) => setEditRaw(e.target.value)}
                            style={{ fontFamily: 'monospace', fontSize: '0.75rem' }} />

                          <div className="text-white-50 small text-uppercase mt-3 mb-1 d-flex justify-content-between">
                            <span>Response</span>
                            {selectedStep.response_status
                              ? <Badge bg={statusVariant(selectedStep.response_status)}>{selectedStep.response_status}</Badge>
                              : <Badge bg="secondary">not sent</Badge>}
                          </div>
                          <pre className="bg-black text-white p-2 rounded"
                            style={{ fontSize: '0.72rem', maxHeight: '260px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {buildRawResponse(selectedStep) || '(no response captured yet — click Replay)'}
                          </pre>
                        </>
                      ) : (
                        <div className="text-white-50 small fst-italic py-3">Select or add a step to see its request and response.</div>
                      )}

                      {/* Add step */}
                      <div className="border-top border-secondary mt-3 pt-3">
                        <div className="text-white-50 small text-uppercase mb-2">Add step</div>
                        <Form.Control size="sm" className="mb-2" placeholder="Step name (optional), e.g. Submit credentials"
                          value={addStepName} onChange={(e) => setAddStepName(e.target.value)} />
                        <Form.Control as="textarea" rows={6} className="mb-2" placeholder={RAW_REQUEST_PLACEHOLDER}
                          value={addStepRaw} onChange={(e) => setAddStepRaw(e.target.value)}
                          style={{ fontFamily: 'monospace', fontSize: '0.75rem' }} />
                        <Button size="sm" variant="danger" onClick={addStep} disabled={busy || !addStepRaw.trim()}>
                          {busy ? <Spinner size="sm" animation="border" /> : 'Add & Send'}
                        </Button>
                        <span className="text-white-50 small ms-2">Paste a raw HTTP request — the app sends it and records the response.</span>
                      </div>
                    </Col>
                  </Row>
                </>
              )}
            </Col>
          </Row>
        )}
      </Modal.Body>
    </Modal>
  );
};

export default AuthFlowModal;
