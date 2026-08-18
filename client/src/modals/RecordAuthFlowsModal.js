import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { Modal, Button, Nav, Form, Spinner, Badge, ListGroup, Alert, Row, Col } from 'react-bootstrap';

// Records a real authentication against the target with the browser extension, and reviews what
// was already captured.
//
// The framework never drives the browser here. The operator opens the recording, logs in by hand
// with their own credentials, MFA device, and mailbox, and the extension streams every request it
// sees into the open recording. That is the only way a flow ends up with the headers, cookies, and
// anti-CSRF values the application actually issued, which is exactly what a synthesised login
// request never has.

const CATEGORIES = [
  { value: 'register', label: 'Register' },
  { value: 'login', label: 'Login' },
  { value: 'mfa_otp', label: 'MFA/OTP' },
  { value: 'magic_link', label: 'Magic Link' },
  { value: 'reset', label: 'Reset' },
];

const CATEGORY_LABELS = CATEGORIES.reduce((acc, c) => ({ ...acc, [c.value]: c.label }), {});

// The extension heartbeats every few seconds while a recording is open. If nothing has been heard
// for this long the recording row is still 'active' in the database but no browser is feeding it,
// which is the state that makes an operator sit and watch a counter that will never move.
const STALE_AFTER_MS = 30000;

// Requests the browser makes on its own account. Excluding them is the single biggest cleanup on a
// recording: a login page pulls in dozens of images and bundles that have nothing to do with the
// auth exchange, and every one of them would otherwise become a replayed step.
const NOISE_RESOURCE_TYPES = ['image', 'font', 'stylesheet', 'script', 'media', 'other'];

function statusVariant(status) {
  if (!status) return 'secondary';
  if (status >= 200 && status < 300) return 'success';
  if (status >= 300 && status < 400) return 'info';
  if (status >= 400 && status < 500) return 'warning';
  return 'danger';
}

function formatWhen(value) {
  if (!value) return '';
  try {
    return new Date(value).toLocaleString();
  } catch (_) {
    return '';
  }
}

function msSince(value) {
  if (!value) return Infinity;
  const t = new Date(value).getTime();
  if (Number.isNaN(t)) return Infinity;
  return Date.now() - t;
}

// A flow row does not carry the request itself, only the raw text of it. The list wants a
// "POST https://host/login" summary, so pull the request line and the Host header back out.
function summariseRawRequest(raw) {
  if (!raw) return { method: '', url: '' };
  const lines = String(raw).split(/\r?\n/);
  const requestLine = (lines[0] || '').trim().split(/\s+/);
  const method = requestLine[0] || '';
  const target = requestLine[1] || '';
  let host = '';
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) break; // header block ends at the first blank line
    const match = /^host:\s*(.+)$/i.exec(lines[i]);
    if (match) { host = match[1].trim(); break; }
  }
  if (/^https?:\/\//i.test(target)) return { method, url: target };
  return { method, url: host ? `${host}${target}` : target };
}

const RecordAuthFlowsModal = ({ show, handleClose, scopeTargetId, scopeTargetUrl }) => {
  const [activeTab, setActiveTab] = useState('login');

  const [flows, setFlows] = useState([]);
  const [recordings, setRecordings] = useState([]);
  const [loadingList, setLoadingList] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState('');

  const [activeRecording, setActiveRecording] = useState(null);
  const [recordName, setRecordName] = useState('');

  // One selection covers both kinds of row, because a flow and the recording it came from are
  // never open at the same time and the detail pane can only show one of them.
  const [selection, setSelection] = useState(null); // { kind: 'flow' | 'recording', id }
  const [steps, setSteps] = useState([]);
  const [requests, setRequests] = useState([]);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [previewId, setPreviewId] = useState(null);

  const pollRef = useRef(null);

  const tabLabel = CATEGORY_LABELS[activeTab] || activeTab;

  const fetchLists = useCallback(async () => {
    if (!scopeTargetId) return;
    setLoadingList(true);
    setError('');
    try {
      const [flowRes, recRes] = await Promise.all([
        fetch(`/api/auth-flows/${scopeTargetId}`),
        fetch(`/api/auth-recording/target/${scopeTargetId}`),
      ]);
      const flowData = flowRes.ok ? await flowRes.json() : [];
      const recData = recRes.ok ? await recRes.json() : [];
      setFlows(Array.isArray(flowData) ? flowData : []);
      setRecordings(Array.isArray(recData) ? recData : []);
      if (!flowRes.ok && !recRes.ok) setError('Could not load auth flows or recordings from the framework.');
    } catch (e) {
      setError('Could not reach the framework: ' + e.message);
    } finally {
      setLoadingList(false);
    }
  }, [scopeTargetId]);

  const fetchActive = useCallback(async () => {
    if (!scopeTargetId) return;
    try {
      const res = await fetch(`/api/auth-recording/active/${scopeTargetId}`);
      if (!res.ok) return; // a transient failure keeps the last known state so Stop does not vanish
      const data = await res.json();
      setActiveRecording(data && data.recording ? data.recording : null);
    } catch (_) {
      // Same reasoning: a dropped poll is not evidence that the recording ended.
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (!show) {
      setSelection(null);
      setSteps([]);
      setRequests([]);
      setPreviewId(null);
      setNotice('');
      return;
    }
    fetchLists();
    fetchActive();
  }, [show, fetchLists, fetchActive]);

  // The extension writes straight into the framework, so the only way this window learns that
  // another request was captured is to ask. Polling stops with the modal.
  useEffect(() => {
    if (!show || !scopeTargetId) return undefined;
    pollRef.current = setInterval(fetchActive, 3000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = null;
    };
  }, [show, scopeTargetId, fetchActive]);

  // Default the recording name per tab, but never stomp on a name the operator is typing.
  useEffect(() => {
    setRecordName((prev) => (prev.trim() ? prev : `${CATEGORY_LABELS[activeTab] || activeTab} recording`));
  }, [activeTab]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadFlowSteps = useCallback(async (flowId) => {
    setLoadingDetail(true);
    try {
      const res = await fetch(`/api/auth-flows/flow/${flowId}/steps`);
      const data = res.ok ? await res.json() : [];
      setSteps(Array.isArray(data) ? data : []);
    } catch (e) {
      setSteps([]);
      setError('Could not load flow steps: ' + e.message);
    } finally {
      setLoadingDetail(false);
    }
  }, []);

  const loadRecordingRequests = useCallback(async (recordingId) => {
    setLoadingDetail(true);
    try {
      const res = await fetch(`/api/auth-recording/${recordingId}/requests`);
      const data = res.ok ? await res.json() : [];
      setRequests(Array.isArray(data) ? data : []);
    } catch (e) {
      setRequests([]);
      setError('Could not load recorded requests: ' + e.message);
    } finally {
      setLoadingDetail(false);
    }
  }, []);

  const select = (kind, id) => {
    setSelection({ kind, id });
    setPreviewId(null);
    setSteps([]);
    setRequests([]);
    if (kind === 'flow') loadFlowSteps(id);
    else loadRecordingRequests(id);
  };

  const startRecording = async () => {
    if (!scopeTargetId) return;
    setBusy('start');
    setError('');
    setNotice('');
    try {
      const res = await fetch('/api/auth-recording/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope_target_id: scopeTargetId,
          name: recordName.trim() || `${tabLabel} recording`,
          category: activeTab,
          base_url: scopeTargetUrl || '',
        }),
      });
      if (!res.ok) {
        setError((await res.text()) || `Could not start the recording (${res.status})`);
        return;
      }
      await fetchActive();
      setNotice('Recording is open. Switch to the browser and sign in yourself, the extension is capturing.');
    } catch (e) {
      setError('Could not start the recording: ' + e.message);
    } finally {
      setBusy('');
    }
  };

  const stopRecording = async () => {
    if (!activeRecording) return;
    setBusy('stop');
    setError('');
    try {
      const res = await fetch('/api/auth-recording/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recording_id: activeRecording.id }),
      });
      if (!res.ok) {
        setError((await res.text()) || `Could not stop the recording (${res.status})`);
        return;
      }
      const result = await res.json();
      setActiveRecording(null);
      await fetchLists();
      // Stopping imports the recording, so drop the operator on whatever it produced rather than
      // making them hunt for it in the list.
      if (result && result.auth_flow_id) {
        select('flow', result.auth_flow_id);
        setNotice(`Recording stopped with ${result.request_count || 0} request(s) captured, and imported as a flow.`);
      } else {
        if (result && result.recording_id) select('recording', result.recording_id);
        setNotice(`Recording stopped with ${result && result.request_count ? result.request_count : 0} request(s) captured.`);
      }
    } catch (e) {
      setError('Could not stop the recording: ' + e.message);
    } finally {
      setBusy('');
    }
  };

  const deleteFlow = async (flowId) => {
    if (!window.confirm('Delete this auth flow and all of its steps?')) return;
    setBusy('delete-flow');
    try {
      const res = await fetch(`/api/auth-flows/flow/${flowId}`, { method: 'DELETE' });
      if (!res.ok) { setError(`Could not delete the flow (${res.status})`); return; }
      setSelection(null);
      setSteps([]);
      await fetchLists();
      setNotice('Flow deleted. The recording it came from is untouched, so it can be imported again.');
    } catch (e) {
      setError('Could not delete the flow: ' + e.message);
    } finally {
      setBusy('');
    }
  };

  const deleteRecording = async (recordingId) => {
    if (!window.confirm('Delete this recording and every request captured in it?')) return;
    setBusy('delete-recording');
    try {
      const res = await fetch(`/api/auth-recording/${recordingId}`, { method: 'DELETE' });
      if (!res.ok) { setError(`Could not delete the recording (${res.status})`); return; }
      setSelection(null);
      setRequests([]);
      await fetchLists();
      setNotice('Recording deleted. Any flow already imported from it stays.');
    } catch (e) {
      setError('Could not delete the recording: ' + e.message);
    } finally {
      setBusy('');
    }
  };

  // Include state lives on the server because the import reads it there. The local list is only
  // updated once the write is confirmed, so a failed PATCH cannot leave the checkbox lying about
  // what will be imported.
  const patchIncluded = async (ids, included) => {
    if (!selection || selection.kind !== 'recording' || ids.length === 0) return;
    setBusy('include');
    try {
      const res = await fetch(`/api/auth-recording/${selection.id}/requests`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids, included }),
      });
      if (!res.ok) { setError(`Could not update the request selection (${res.status})`); return; }
      const idSet = new Set(ids);
      setRequests((prev) => prev.map((r) => (idSet.has(r.id) ? { ...r, included } : r)));
    } catch (e) {
      setError('Could not update the request selection: ' + e.message);
    } finally {
      setBusy('');
    }
  };

  const dropStaticAssets = () => {
    const ids = requests
      .filter((r) => r.included && NOISE_RESOURCE_TYPES.includes(String(r.resource_type || '').toLowerCase()))
      .map((r) => r.id);
    if (ids.length === 0) {
      setNotice('Nothing to drop, no included request looks like a static asset.');
      return;
    }
    patchIncluded(ids, false);
  };

  const reimportRecording = async (recording) => {
    setBusy('import');
    setError('');
    try {
      const res = await fetch(`/api/auth-recording/${recording.id}/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: recording.name, category: recording.category }),
      });
      if (!res.ok) { setError((await res.text()) || `Import failed (${res.status})`); return; }
      const result = await res.json();
      await fetchLists();
      if (result && result.auth_flow_id) select('flow', result.auth_flow_id);
      setNotice(`Imported ${result && result.steps ? result.steps : 0} step(s) from the included requests.`);
    } catch (e) {
      setError('Import failed: ' + e.message);
    } finally {
      setBusy('');
    }
  };

  const tabFlows = useMemo(
    () => flows.filter((f) => f.category === activeTab),
    [flows, activeTab]
  );
  const tabRecordings = useMemo(
    () => recordings.filter((r) => r.category === activeTab),
    [recordings, activeTab]
  );

  const selectedFlow = selection && selection.kind === 'flow'
    ? flows.find((f) => f.id === selection.id) || null : null;
  const selectedRecording = selection && selection.kind === 'recording'
    ? recordings.find((r) => r.id === selection.id) || null : null;

  const recordingStale = activeRecording && msSince(activeRecording.last_seen_at) > STALE_AFTER_MS;
  const activeInAnotherTab = activeRecording && activeRecording.category !== activeTab;
  const includedCount = requests.filter((r) => r.included).length;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-record-circle me-2" />
          Record Auth Flows
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '70vh' }}>
        {!scopeTargetId ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <>
            <Nav variant="pills" className="mb-3">
              {CATEGORIES.map((c) => {
                const flowCount = flows.filter((f) => f.category === c.value).length;
                const recCount = recordings.filter((r) => r.category === c.value).length;
                return (
                  <Nav.Item key={c.value}>
                    <Nav.Link
                      active={activeTab === c.value}
                      onClick={() => { setActiveTab(c.value); setSelection(null); setSteps([]); setRequests([]); }}
                      className={activeTab === c.value ? 'bg-danger' : 'text-danger'}
                    >
                      {c.label} ({flowCount + recCount})
                    </Nav.Link>
                  </Nav.Item>
                );
              })}
            </Nav>

            {error && <Alert variant="danger" dismissible onClose={() => setError('')} className="py-2">{error}</Alert>}
            {notice && <Alert variant="info" dismissible onClose={() => setNotice('')} className="py-2 small">{notice}</Alert>}

            {/* Record with the extension */}
            <div className="border border-secondary rounded p-3 mb-3">
              <div className="d-flex justify-content-between align-items-center mb-2">
                <span className="text-white-50 small text-uppercase">Record with extension</span>
                <Badge bg="secondary">{tabLabel}</Badge>
              </div>

              {activeRecording ? (
                <>
                  <div className="d-flex align-items-center gap-3 flex-wrap">
                    <Spinner animation="grow" size="sm" variant="danger" />
                    <div>
                      <div className="fw-bold">{activeRecording.name}</div>
                      <div className="text-white-50 small">
                        {CATEGORY_LABELS[activeRecording.category] || activeRecording.category}
                        {activeRecording.started_at ? ` · started ${formatWhen(activeRecording.started_at)}` : ''}
                      </div>
                    </div>
                    <div className="ms-auto d-flex align-items-center gap-3">
                      <div className="text-end">
                        <div className="fs-4 fw-bold text-danger">{activeRecording.request_count || 0}</div>
                        <div className="text-white-50 small">requests captured</div>
                      </div>
                      <Button variant="outline-danger" onClick={stopRecording} disabled={busy === 'stop'}>
                        {busy === 'stop' ? <Spinner size="sm" animation="border" /> : 'Stop Recording'}
                      </Button>
                    </div>
                  </div>
                  {recordingStale ? (
                    <Alert variant="warning" className="py-2 small mt-3 mb-0">
                      The extension has not checked in for over {Math.round(STALE_AFTER_MS / 1000)} seconds. The
                      recording is still open on this side, but nothing is feeding it. Check that the extension is
                      installed, enabled on this target, and that the browser tab is open.
                    </Alert>
                  ) : (
                    <div className="text-white-50 small mt-3">
                      Go to the browser and drive the {tabLabel.toLowerCase()} flow yourself: type the credentials,
                      answer the MFA prompt, click the emailed link. Everything the browser sends is captured as it
                      happens. Come back and hit Stop when the flow is finished.
                    </div>
                  )}
                </>
              ) : (
                <>
                  <Row className="g-2 align-items-end">
                    <Col md={7}>
                      <Form.Label className="text-white small mb-1">Recording name</Form.Label>
                      <Form.Control
                        size="sm"
                        className="bg-dark text-white border-secondary"
                        value={recordName}
                        onChange={(e) => setRecordName(e.target.value)}
                        placeholder={`${tabLabel} recording`}
                      />
                    </Col>
                    <Col md={5}>
                      <Button
                        variant="danger"
                        className="w-100"
                        onClick={startRecording}
                        disabled={busy === 'start'}
                      >
                        {busy === 'start' ? <Spinner size="sm" animation="border" /> : <><i className="bi bi-record-circle me-2" />Start Recording</>}
                      </Button>
                    </Col>
                  </Row>
                  <div className="text-white-50 small mt-2">
                    Starting opens a recording against {scopeTargetUrl || 'this target'} in the {tabLabel} category.
                    The extension polls the framework, sees it, and streams every request the browser makes into it.
                    Nothing is automated: you sign in by hand and the capture follows along.
                  </div>
                </>
              )}

              {activeInAnotherTab && (
                <Alert variant="secondary" className="py-2 small mt-3 mb-0">
                  This recording was started under {CATEGORY_LABELS[activeRecording.category] || activeRecording.category}.
                  Only one recording is open per target, so stop it before recording a {tabLabel.toLowerCase()} flow.
                </Alert>
              )}
            </div>

            <Row>
              {/* LEFT: flows and recordings in this category */}
              <Col md={5} className="border-end border-secondary">
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <span className="text-white-50 small text-uppercase">{tabLabel} flows and recordings</span>
                  <Button size="sm" variant="outline-secondary" onClick={fetchLists} disabled={loadingList}>
                    {loadingList ? <Spinner size="sm" animation="border" /> : 'Refresh'}
                  </Button>
                </div>

                {loadingList ? (
                  <div className="text-center py-4"><Spinner animation="border" variant="danger" /></div>
                ) : tabFlows.length === 0 && tabRecordings.length === 0 ? (
                  <div className="text-white-50 small fst-italic py-3">
                    Nothing captured for {tabLabel.toLowerCase()} yet. Record one above, or write the requests out by
                    hand in Manual Auth Flows.
                  </div>
                ) : (
                  <ListGroup variant="flush" style={{ maxHeight: '46vh', overflowY: 'auto' }}>
                    {tabFlows.map((f) => {
                      // Older rows predate the source column, so fall back to the link back to a
                      // recording before assuming a flow was typed by hand.
                      const source = f.source || (f.recording_id ? 'recorded' : 'manual');
                      return (
                        <ListGroup.Item
                          key={`flow-${f.id}`}
                          action
                          active={selection && selection.kind === 'flow' && selection.id === f.id}
                          onClick={() => select('flow', f.id)}
                          className="bg-dark text-white border-secondary"
                        >
                          <div className="d-flex align-items-center gap-2">
                            <Badge bg={source === 'recorded' ? 'danger' : 'secondary'}>{source}</Badge>
                            <span className="text-truncate flex-grow-1">{f.name}</span>
                            <Badge bg="secondary" title="Steps">{f.step_count || 0}</Badge>
                          </div>
                          <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                            flow · captured {formatWhen(f.created_at)}
                          </div>
                        </ListGroup.Item>
                      );
                    })}

                    {tabRecordings.map((r) => (
                      <ListGroup.Item
                        key={`rec-${r.id}`}
                        action
                        active={selection && selection.kind === 'recording' && selection.id === r.id}
                        onClick={() => select('recording', r.id)}
                        className="bg-dark text-white border-secondary"
                      >
                        <div className="d-flex align-items-center gap-2">
                          <Badge bg={r.status === 'active' ? 'danger' : 'dark'} className={r.status === 'active' ? '' : 'border border-secondary text-white-50'}>
                            {r.status || 'stopped'}
                          </Badge>
                          <span className="text-truncate flex-grow-1">{r.name}</span>
                          <Badge bg="secondary" title="Captured requests">{r.request_count || 0}</Badge>
                        </div>
                        <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                          recording · captured {formatWhen(r.started_at || r.created_at)}
                          {r.auth_flow_id ? ' · imported' : ' · not imported'}
                        </div>
                      </ListGroup.Item>
                    ))}
                  </ListGroup>
                )}
              </Col>

              {/* RIGHT: detail for whatever is selected */}
              <Col md={7}>
                {!selection ? (
                  <div className="text-center text-white-50 py-5">
                    Select a flow to see its ordered steps, or a recording to pick which captured requests become
                    steps.
                  </div>
                ) : loadingDetail ? (
                  <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
                ) : selection.kind === 'flow' ? (
                  <>
                    <div className="d-flex justify-content-between align-items-center mb-2">
                      <span className="text-white-50 small text-uppercase">
                        {selectedFlow ? selectedFlow.name : 'Flow'} · {steps.length} step(s)
                      </span>
                      <Button
                        size="sm"
                        variant="outline-danger"
                        onClick={() => deleteFlow(selection.id)}
                        disabled={busy === 'delete-flow'}
                      >
                        Delete Flow
                      </Button>
                    </div>
                    {steps.length === 0 ? (
                      <div className="text-white-50 small fst-italic">This flow has no steps.</div>
                    ) : (
                      <ListGroup variant="flush" style={{ maxHeight: '46vh', overflowY: 'auto' }}>
                        {steps.map((s) => {
                          const summary = summariseRawRequest(s.raw_request);
                          return (
                            <ListGroup.Item key={s.id} className="bg-dark text-white border-secondary py-2">
                              <div className="d-flex align-items-center gap-2">
                                <Badge bg="secondary">{s.step_order}</Badge>
                                <Badge bg="dark" className="border border-secondary">{summary.method || '?'}</Badge>
                                <code className="text-info text-truncate flex-grow-1" style={{ fontSize: '0.75rem' }} title={summary.url}>
                                  {summary.url || '(unparsed request)'}
                                </code>
                                <Badge bg={statusVariant(s.response_status)}>{s.response_status || '-'}</Badge>
                              </div>
                              {s.name ? <div className="text-white-50" style={{ fontSize: '0.7rem' }}>{s.name}</div> : null}
                              {s.error ? <div className="text-danger" style={{ fontSize: '0.7rem' }}>{s.error}</div> : null}
                            </ListGroup.Item>
                          );
                        })}
                      </ListGroup>
                    )}
                  </>
                ) : (
                  <>
                    <div className="d-flex justify-content-between align-items-center mb-2 flex-wrap gap-2">
                      <span className="text-white-50 small text-uppercase">
                        {selectedRecording ? selectedRecording.name : 'Recording'} · {includedCount}/{requests.length} included
                      </span>
                      <div className="d-flex gap-2">
                        <Button size="sm" variant="outline-secondary" onClick={dropStaticAssets} disabled={busy === 'include'}>
                          Drop static assets
                        </Button>
                        <Button
                          size="sm"
                          variant="outline-danger"
                          onClick={() => selectedRecording && reimportRecording(selectedRecording)}
                          disabled={busy === 'import' || includedCount === 0 || !selectedRecording}
                        >
                          {busy === 'import' ? <Spinner size="sm" animation="border" /> : 'Re-import'}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline-danger"
                          onClick={() => deleteRecording(selection.id)}
                          disabled={busy === 'delete-recording'}
                        >
                          Delete
                        </Button>
                      </div>
                    </div>
                    <div className="text-white-50 small mb-2">
                      Only the ticked requests become steps. Re-import builds a fresh flow from the current
                      selection, so trimming the noise and importing again is cheaper than editing the steps later.
                    </div>

                    {requests.length === 0 ? (
                      <div className="text-white-50 small fst-italic">
                        No requests captured in this recording.
                      </div>
                    ) : (
                      <>
                        <ListGroup variant="flush" style={{ maxHeight: '30vh', overflowY: 'auto' }}>
                          {requests.map((req) => (
                            <ListGroup.Item
                              key={req.id}
                              className="bg-dark text-white border-secondary py-2"
                              style={{ cursor: 'pointer' }}
                              active={previewId === req.id}
                              onClick={() => setPreviewId(previewId === req.id ? null : req.id)}
                            >
                              <div className="d-flex align-items-center gap-2">
                                <Form.Check
                                  type="checkbox"
                                  checked={!!req.included}
                                  onChange={() => patchIncluded([req.id], !req.included)}
                                  onClick={(e) => e.stopPropagation()}
                                  aria-label={`Include ${req.method} ${req.url}`}
                                />
                                <Badge bg="secondary">{req.seq}</Badge>
                                <Badge bg="dark" className="border border-secondary">{req.method}</Badge>
                                <code className="text-info text-truncate flex-grow-1" style={{ fontSize: '0.72rem' }} title={req.url}>
                                  {req.url}
                                </code>
                                {req.resource_type ? (
                                  <span className="text-white-50" style={{ fontSize: '0.65rem' }}>{req.resource_type}</span>
                                ) : null}
                                <Badge bg={statusVariant(req.response_status)}>{req.response_status || '-'}</Badge>
                              </div>
                            </ListGroup.Item>
                          ))}
                        </ListGroup>

                        <div className="text-white-50 small text-uppercase mt-3 mb-1">Raw request</div>
                        {!previewId ? (
                          <div className="text-white-50 small fst-italic">
                            Click a row to see exactly what was captured, headers, cookies and body included.
                          </div>
                        ) : (
                          <pre
                            className="bg-black text-white p-2 rounded"
                            style={{ fontSize: '0.72rem', maxHeight: '18vh', overflowY: 'auto', whiteSpace: 'pre-wrap' }}
                          >
                            {(requests.find((r) => r.id === previewId) || {}).raw_request || '(nothing captured)'}
                          </pre>
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
        <span className="text-white-50 small me-auto">
          Recorded steps keep the response the target actually returned. Nothing is re-sent until a flow is replayed.
        </span>
        <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
};

export default RecordAuthFlowsModal;
