import { useState, useMemo } from 'react';
import { Modal, Button, Badge, Table, Alert, Spinner, Card, Collapse } from 'react-bootstrap';

const parseResult = (scan) => {
  if (!scan || !scan.result) return null;
  try {
    return typeof scan.result === 'string' ? JSON.parse(scan.result) : scan.result;
  } catch {
    return null;
  }
};

// Human-readable rows for the recommended FFUF config (keys match FFUFConfig / the config modal).
const RECO_LABELS = {
  rateLimit: (v) => ['Rate limit', v > 0 ? `${v} req/s` : 'Unlimited'],
  threads: (v) => ['Threads', String(v)],
  delay: (v) => ['Delay between requests', v ? `${v}s` : 'None'],
  autoCalibrate: (v) => ['Auto-calibrate filters', v ? 'Enabled' : 'Disabled'],
  filterStatusCodes: (v) => ['Filter status codes', v],
  filterSize: (v) => ['Filter response size', `${v} bytes`],
  filterLines: (v) => ['Filter lines', v],
  filterWords: (v) => ['Filter words', v],
  stopOnAll: (v) => ['Stop on all errors', v ? 'Enabled' : 'Disabled'],
  stopOn403: (v) => ['Stop on 403', v ? 'Enabled' : 'Disabled'],
  http2: (v) => ['HTTP/2', v ? 'Enabled' : 'Disabled'],
  headers: (v) => ['Extra headers', Array.isArray(v) ? v.map((h) => `${h.name}: ${h.value}`).join('; ') : ''],
};

export const WAFProbeResultsModal = ({ show, handleClose, activeTarget, mostRecentWAFProbeScan }) => {
  const [applying, setApplying] = useState(false);
  const [applyErr, setApplyErr] = useState(null);
  const [showLog, setShowLog] = useState(false);

  const probe = useMemo(() => parseResult(mostRecentWAFProbeScan), [mostRecentWAFProbeScan]);

  const handleApply = async () => {
    if (!activeTarget) return;
    setApplying(true);
    setApplyErr(null);
    try {
      const res = await fetch(`/api/waf-probe/apply/${activeTarget.id}`, { method: 'POST' });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || 'Failed to apply recommendations');
      }
      handleClose();
    } catch (e) {
      setApplyErr(e.message || 'Failed to apply recommendations');
    } finally {
      setApplying(false);
    }
  };

  const status = mostRecentWAFProbeScan?.status;
  const recommendations = probe?.recommendations || {};
  const recoKeys = Object.keys(recommendations);

  return (
    <Modal show={show} onHide={handleClose} size="xl" data-bs-theme="dark" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-shield-shaded me-2" />
          WAF Probe Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {!probe && (
          <Alert variant="secondary">
            {status === 'error'
              ? `The probe failed: ${mostRecentWAFProbeScan?.error || 'unknown error'}`
              : 'No completed WAF probe results yet. Run a WAF Probe scan first.'}
          </Alert>
        )}

        {probe && (
          <>
            {applyErr && <Alert variant="danger" dismissible onClose={() => setApplyErr(null)}>{applyErr}</Alert>}

            {/* WAF detection */}
            <Card className="bg-dark border-danger mb-3">
              <Card.Body>
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <h5 className="text-white mb-0"><i className="bi bi-shield-lock me-2" />WAF Detection</h5>
                  {probe.waf?.detected
                    ? <Badge bg="danger">WAF Detected ({probe.waf.confidence})</Badge>
                    : <Badge bg="success">No WAF Detected</Badge>}
                </div>
                {probe.waf?.vendors?.length > 0 && (
                  <p className="text-white mb-2">
                    Vendor(s): {probe.waf.vendors.map((v, i) => <Badge key={i} bg="warning" text="dark" className="me-1">{v}</Badge>)}
                  </p>
                )}
                <ul className="text-white-50 small mb-0">
                  {(probe.waf?.evidence || []).map((e, i) => <li key={i}>{e}</li>)}
                </ul>
              </Card.Body>
            </Card>

            {/* Rate limiting */}
            <Card className="bg-dark border-danger mb-3">
              <Card.Body>
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <h5 className="text-white mb-0"><i className="bi bi-speedometer2 me-2" />Rate Limiting</h5>
                  {probe.rate_limit?.limited
                    ? <Badge bg="danger">Rate Limited</Badge>
                    : <Badge bg="success">No Rate Limit Hit</Badge>}
                </div>
                <Table borderless size="sm" className="text-white-50 mb-2">
                  <tbody>
                    <tr><td>Safe request rate</td><td className="text-white">{probe.rate_limit?.safe_rps ? `${probe.rate_limit.safe_rps} req/s` : 'unlimited'}</td></tr>
                    <tr><td>Block threshold</td><td className="text-white">{probe.rate_limit?.threshold_rps ? `~${probe.rate_limit.threshold_rps} req/s` : 'not reached'}</td></tr>
                    <tr><td>Max sustained</td><td className="text-white">{probe.rate_limit?.max_sustained_rps ?? '—'} req/s</td></tr>
                    <tr><td>Requests sent</td><td className="text-white">{probe.rate_limit?.requests_sent ?? '—'}</td></tr>
                  </tbody>
                </Table>
                <p className="text-white-50 small mb-0">{probe.rate_limit?.evidence}</p>
              </Card.Body>
            </Card>

            {/* Baseline + block signature */}
            <Card className="bg-dark border-secondary mb-3">
              <Card.Body>
                <h6 className="text-white mb-2">Baseline &amp; Block Signature</h6>
                <div className="text-white-50 small">
                  Baseline: <span className="text-white">{probe.baseline?.status}</span> · {probe.baseline?.size}B · {probe.baseline?.ms}ms
                  {probe.baseline?.notfound_status ? <> · not-found: <span className="text-white">{probe.baseline.notfound_status}</span> ({probe.baseline.notfound_size}B)</> : null}
                  {probe.block_signature
                    ? <> · block: <span className="text-danger">{probe.block_signature.status}</span> ({probe.block_signature.size}B)</>
                    : <> · block signature: none</>}
                </div>
              </Card.Body>
            </Card>

            {/* Recommended FFUF config */}
            <Card className="bg-dark border-danger mb-3">
              <Card.Body>
                <h5 className="text-white mb-3"><i className="bi bi-magic me-2" />Recommended FFUF Configuration</h5>
                {recoKeys.length === 0 ? (
                  <p className="text-white-50 mb-0">No specific recommendations — defaults are fine for this target.</p>
                ) : (
                  <Table striped bordered hover size="sm" variant="dark" className="mb-0">
                    <thead><tr><th>Setting</th><th>Recommended</th></tr></thead>
                    <tbody>
                      {recoKeys.map((k) => {
                        const fmt = RECO_LABELS[k];
                        const [label, value] = fmt ? fmt(recommendations[k]) : [k, String(recommendations[k])];
                        return <tr key={k}><td>{label}</td><td className="text-danger">{value}</td></tr>;
                      })}
                    </tbody>
                  </Table>
                )}
              </Card.Body>
            </Card>

            {/* Notes */}
            {probe.notes?.length > 0 && (
              <Alert variant="dark" className="border-secondary">
                <strong className="text-white">Why:</strong>
                <ul className="text-white-50 small mb-0 mt-1">
                  {probe.notes.map((n, i) => <li key={i}>{n}</li>)}
                </ul>
              </Alert>
            )}

            {/* Raw probe log */}
            <Button variant="outline-secondary" size="sm" onClick={() => setShowLog((s) => !s)} className="mb-2">
              <i className={`bi bi-chevron-${showLog ? 'down' : 'right'} me-1`} />
              Raw probe log ({probe.probe_log?.length || 0})
            </Button>
            <Collapse in={showLog}>
              <div>
                <Table size="sm" variant="dark" className="small">
                  <thead><tr><th>Phase</th><th>Target</th><th>Status</th><th>Size</th><th>ms</th><th>Note</th></tr></thead>
                  <tbody>
                    {(probe.probe_log || []).map((row, i) => (
                      <tr key={i}>
                        <td>{row.phase}</td><td className="text-truncate" style={{ maxWidth: 220 }}>{row.url}</td>
                        <td>{row.status}</td><td>{row.size}</td><td>{row.ms}</td><td>{row.note || ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            </Collapse>
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>Close</Button>
        <Button
          variant="danger"
          onClick={handleApply}
          disabled={applying || !probe || recoKeys.length === 0}
        >
          {applying ? <><Spinner animation="border" size="sm" className="me-2" />Applying...</> : <><i className="bi bi-check2-all me-2" />Apply All to FFUF</>}
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default WAFProbeResultsModal;
