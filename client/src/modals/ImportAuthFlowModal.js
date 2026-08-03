import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Button, Form, Spinner, Badge, ListGroup, Alert } from 'react-bootstrap';

// Builds an auth flow out of requests the manual crawl already recorded.
//
// Typing a login sequence by hand means re-deriving headers, cookies, CSRF tokens, and the exact
// body from memory. The crawl captured all of it. This picker surfaces the requests that look like
// part of an auth exchange, in the order they happened, and turns the chosen ones into steps with
// the response that was actually observed attached.

const CATEGORY_LABELS = { register: 'Register', login: 'Login', mfa_otp: 'MFA/OTP', reset: 'Reset' };

function statusVariant(status) {
  if (!status) return 'secondary';
  if (status >= 200 && status < 300) return 'success';
  if (status >= 300 && status < 400) return 'info';
  if (status >= 400 && status < 500) return 'warning';
  return 'danger';
}

function formatTime(value) {
  if (!value) return '';
  try {
    return new Date(value).toLocaleTimeString();
  } catch (_) {
    return '';
  }
}

const ImportAuthFlowModal = ({ show, handleClose, category, activeTarget, onImported }) => {
  const [candidates, setCandidates] = useState([]);
  const [selectedIds, setSelectedIds] = useState([]);
  const [previewId, setPreviewId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [flowName, setFlowName] = useState('');
  const [onlyThisCategory, setOnlyThisCategory] = useState(true);

  const categoryLabel = CATEGORY_LABELS[category] || category || '';

  const fetchCandidates = useCallback(async () => {
    if (!activeTarget) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/manual-crawl/captures/target/${activeTarget.id}/auth-candidates`);
      if (!res.ok) {
        setError(`Could not load recorded requests (${res.status})`);
        setCandidates([]);
        return;
      }
      const data = await res.json();
      setCandidates(Array.isArray(data) ? data : []);
    } catch (e) {
      setError('Could not reach the framework: ' + e.message);
      setCandidates([]);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);

  useEffect(() => {
    if (show) {
      fetchCandidates();
      setSelectedIds([]);
      setPreviewId(null);
      setFlowName(`${categoryLabel} (from manual crawl)`);
    }
  }, [show, fetchCandidates, categoryLabel]);

  // The classifier's guess is a filter, not a rule: an app that posts credentials to an
  // unconventional path should still be importable, so the filter can be switched off.
  const visible = useMemo(() => {
    if (!onlyThisCategory) return candidates;
    const matching = candidates.filter((c) => c.suggested_category === category);
    return matching.length ? matching : candidates;
  }, [candidates, category, onlyThisCategory]);

  const noneMatchedCategory = useMemo(
    () => onlyThisCategory && candidates.length > 0 && !candidates.some((c) => c.suggested_category === category),
    [candidates, category, onlyThisCategory]
  );

  const preview = useMemo(
    () => candidates.find((c) => c.capture_id === previewId) || null,
    [candidates, previewId]
  );

  const toggle = (id) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
    setPreviewId(id);
  };

  const doImport = async () => {
    if (!activeTarget || selectedIds.length === 0) return;
    setBusy(true);
    setError('');
    try {
      const res = await fetch(`/api/auth-flows/${activeTarget.id}/from-captures`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          category,
          name: flowName.trim() || `${categoryLabel} (from manual crawl)`,
          // Ordering is by capture timestamp on the server, so the sequence matches what happened
          // rather than the order the boxes were ticked.
          capture_ids: selectedIds,
        }),
      });
      if (!res.ok) {
        const text = await res.text();
        setError(text || `Import failed (${res.status})`);
        return;
      }
      const created = await res.json();
      if (onImported) onImported(created);
      handleClose();
    } catch (e) {
      setError('Import failed: ' + e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Import {categoryLabel} Flow from Manual Crawl</Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '60vh' }}>
        {!activeTarget ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <>
            <div className="d-flex gap-2 align-items-center mb-3">
              <Form.Control
                size="sm"
                placeholder="Flow name"
                value={flowName}
                onChange={(e) => setFlowName(e.target.value)}
                style={{ maxWidth: '340px' }}
              />
              <Form.Check
                type="switch"
                id="only-this-category"
                label={`Only ${categoryLabel}-looking requests`}
                checked={onlyThisCategory}
                onChange={(e) => setOnlyThisCategory(e.target.checked)}
                className="small"
              />
              <span className="ms-auto text-white-50 small">
                {selectedIds.length} selected
              </span>
              <Button variant="outline-secondary" size="sm" onClick={fetchCandidates} disabled={loading}>
                Refresh
              </Button>
            </div>

            {error && <Alert variant="danger" className="py-2">{error}</Alert>}

            {noneMatchedCategory && (
              <Alert variant="info" className="py-2 small">
                Nothing was classified as {categoryLabel}, so every auth-looking request is shown.
                Pick the ones that belong to this flow.
              </Alert>
            )}

            {loading ? (
              <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
            ) : candidates.length === 0 ? (
              <Alert variant="secondary" className="py-3">
                No recorded requests look like part of an authentication exchange. Record a manual
                crawl through the login (or registration, MFA, or reset) flow first, then come back.
              </Alert>
            ) : (
              <div className="d-flex gap-3" style={{ minHeight: '45vh' }}>
                <div style={{ flex: '1 1 55%', maxHeight: '55vh', overflowY: 'auto' }}>
                  <ListGroup variant="flush">
                    {visible.map((c) => (
                      <ListGroup.Item
                        key={c.capture_id}
                        className="bg-dark text-white py-2 border-secondary"
                        style={{ cursor: 'pointer' }}
                        onClick={() => toggle(c.capture_id)}
                        active={c.capture_id === previewId}
                      >
                        <div className="d-flex align-items-start gap-2">
                          <Form.Check
                            type="checkbox"
                            checked={selectedIds.includes(c.capture_id)}
                            onChange={() => toggle(c.capture_id)}
                            onClick={(e) => e.stopPropagation()}
                            className="mt-1"
                          />
                          <div className="flex-grow-1 text-truncate">
                            <div className="d-flex align-items-center gap-2">
                              <Badge bg="secondary">{c.method}</Badge>
                              <code className="text-info text-truncate" style={{ fontSize: '0.78rem' }} title={c.url}>
                                {c.endpoint}
                              </code>
                            </div>
                            <div className="text-white-50" style={{ fontSize: '0.68rem' }}>
                              {c.reason}
                            </div>
                          </div>
                          <div className="d-flex align-items-center gap-2 flex-shrink-0">
                            {c.has_body && <Badge bg="success" title="Has a request body">body</Badge>}
                            {c.sets_cookie && <Badge bg="info" title="Response sets a cookie">cookie</Badge>}
                            <Badge bg={statusVariant(c.status_code)}>{c.status_code || '-'}</Badge>
                            <small className="text-white-50">{formatTime(c.timestamp)}</small>
                          </div>
                        </div>
                      </ListGroup.Item>
                    ))}
                  </ListGroup>
                </div>

                <div style={{ flex: '1 1 45%' }}>
                  <div className="text-white-50 small text-uppercase mb-1">Raw request</div>
                  {!preview ? (
                    <div className="text-white-50 small fst-italic">
                      Select a request to see exactly what will be imported as a step.
                    </div>
                  ) : (
                    <pre
                      className="bg-black text-white p-2 rounded"
                      style={{ fontSize: '0.72rem', maxHeight: '52vh', overflowY: 'auto', whiteSpace: 'pre-wrap' }}
                    >
                      {preview.raw_request}
                    </pre>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <span className="text-white-50 small me-auto">
          Steps keep the response that was recorded. Nothing is re-sent until you hit Replay.
        </span>
        <Button variant="outline-secondary" onClick={handleClose}>Cancel</Button>
        <Button variant="danger" onClick={doImport} disabled={busy || selectedIds.length === 0}>
          {busy ? <Spinner size="sm" animation="border" /> : `Import ${selectedIds.length || ''} step${selectedIds.length === 1 ? '' : 's'}`}
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ImportAuthFlowModal;
