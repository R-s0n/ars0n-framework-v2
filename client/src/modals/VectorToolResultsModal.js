import { Modal, Button, Spinner, Alert, Nav, Badge, Accordion, Form } from 'react-bootstrap';
import { useState, useEffect, useCallback, useMemo } from 'react';

// What an XSS scan found, and what it never tested.
//
// The second tab is the point of this screen. domdig handed a header vector scans its query string,
// finds nothing and exits 0; xssFuzz handed a body vector does the same. Without the skipped list
// beside the findings, "0 findings" reads as "nothing there" for a table that was mostly never sent.
// So the count in the header is eligible-of-total, and every skipped vector carries the reason.
//
// Findings are also not flattened into one word. dalfox v3 has no headless browser, so its V means
// "the payload reached an executable position in a parsed response", not that anything ran. domdig's
// findings DID run, in Chromium. Labelling both "vulnerable" would overstate one and understate the
// other, so the tool's own class is kept and spelled out by the server.

const KIND_STYLE = {
  V: { bg: 'danger', label: 'V' },
  A: { bg: 'warning', label: 'A' },
  R: { bg: 'secondary', label: 'R' },
  I: { bg: 'dark', label: 'I' },
};

const TRIAGE_ORDER = ['new', 'interesting', 'dismissed'];

const Exchange = ({ request, response }) => {
  const [side, setSide] = useState('request');
  if (!request && !response) {
    return (
      <div className="text-white-50" style={{ fontSize: '0.78rem' }}>
        No raw exchange was captured for this finding.
      </div>
    );
  }
  const body = side === 'request' ? request : response;
  return (
    <div>
      <Nav variant="pills" activeKey={side} onSelect={(k) => k && setSide(k)} className="mb-2 gap-2">
        <Nav.Item><Nav.Link eventKey="request" className="py-0 px-2" style={{ fontSize: '0.75rem' }}>Request</Nav.Link></Nav.Item>
        <Nav.Item><Nav.Link eventKey="response" className="py-0 px-2" style={{ fontSize: '0.75rem' }}>Response</Nav.Link></Nav.Item>
      </Nav>
      <pre
        className="p-2 mb-0 rounded"
        style={{
          background: 'rgba(0,0,0,0.35)', color: 'rgba(255,255,255,0.75)',
          fontSize: '0.72rem', maxHeight: '320px', overflow: 'auto', whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
        }}
      >
        {body || `Nothing was captured for the ${side}.`}
      </pre>
    </div>
  );
};

function VectorToolResultsModal({ show, handleClose, activeTarget, tool, category }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [findings, setFindings] = useState([]);
  const [skipped, setSkipped] = useState([]);
  const [status, setStatus] = useState(null);
  const [tab, setTab] = useState('findings');
  const [pointFilter, setPointFilter] = useState('');
  const [kindFilter, setKindFilter] = useState('');
  const [triageFilter, setTriageFilter] = useState('');

  const toolKey = tool?.key;

  const load = useCallback(async () => {
    if (!activeTarget || !toolKey) return;
    setLoading(true);
    setError('');
    try {
      const [resultsRes, statusRes] = await Promise.all([
        fetch(`/api/${category}/${activeTarget.id}/${toolKey}/results`),
        fetch(`/api/${category}/${activeTarget.id}/${toolKey}/status`),
      ]);
      if (!resultsRes.ok) {
        setError('Could not load these results.');
        return;
      }
      const data = await resultsRes.json();
      setFindings(data.findings || []);
      setSkipped(data.skipped || []);
      if (statusRes.ok) setStatus(await statusRes.json());
    } catch (err) {
      setError('Could not load these results: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget, toolKey, category]);

  useEffect(() => { if (show) load(); }, [show, load]);

  const setTriage = async (id, triage) => {
    // Updated locally first so the badge responds immediately; a triage call that fails reloads and
    // puts the truth back rather than leaving the screen showing something the server did not store.
    setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, triage } : f)));
    try {
      const res = await fetch(`/api/${category}/finding/${id}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ triage }),
      });
      if (!res.ok) await load();
    } catch {
      await load();
    }
  };

  const points = useMemo(
    () => [...new Set(findings.map((f) => f.insertion_point).filter(Boolean))].sort(),
    [findings],
  );
  const kinds = useMemo(
    () => [...new Set(findings.map((f) => f.kind).filter(Boolean))].sort(),
    [findings],
  );

  const shown = useMemo(() => findings.filter((f) => (
    (!pointFilter || f.insertion_point === pointFilter)
    && (!kindFilter || f.kind === kindFilter)
    && (!triageFilter || (f.triage || 'new') === triageFilter)
  )), [findings, pointFilter, kindFilter, triageFilter]);

  const skippedByReason = useMemo(() => {
    const groups = {};
    skipped.forEach((s) => {
      const key = s.reason || 'No reason recorded.';
      (groups[key] = groups[key] || []).push(s);
    });
    return Object.entries(groups).sort((a, b) => b[1].length - a[1].length);
  }, [skipped]);

  const eligibility = status?.eligibility;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">{tool?.name || 'XSS'} findings</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ minHeight: '60vh' }}>
        {loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : (
          <>
            {error && <Alert variant="danger" className="py-2">{error}</Alert>}

            {eligibility && (
              <div className="mb-3 d-flex gap-4 flex-wrap align-items-baseline">
                <div>
                  <div className="text-white" style={{ fontSize: '1.6rem', fontWeight: 600, lineHeight: 1 }}>
                    {findings.length}
                  </div>
                  <div className="text-white-50" style={{ fontSize: '0.72rem' }}>findings</div>
                </div>
                <div>
                  <div className="text-white" style={{ fontSize: '1.6rem', fontWeight: 600, lineHeight: 1 }}>
                    {eligibility.eligible}
                    <span className="text-white-50" style={{ fontSize: '1rem' }}>
                      /{eligibility.total}
                    </span>
                  </div>
                  <div className="text-white-50" style={{ fontSize: '0.72rem' }}>vectors tested</div>
                </div>
                {skipped.length > 0 && (
                  <div>
                    <div className="text-warning" style={{ fontSize: '1.6rem', fontWeight: 600, lineHeight: 1 }}>
                      {skipped.length}
                    </div>
                    <div className="text-white-50" style={{ fontSize: '0.72rem' }}>never tested</div>
                  </div>
                )}
              </div>
            )}

            <Nav variant="tabs" activeKey={tab} onSelect={(k) => k && setTab(k)} className="mb-3">
              <Nav.Item>
                <Nav.Link eventKey="findings">Findings ({findings.length})</Nav.Link>
              </Nav.Item>
              <Nav.Item>
                <Nav.Link eventKey="skipped">Not tested ({skipped.length})</Nav.Link>
              </Nav.Item>
            </Nav>

            {tab === 'findings' && (
              <>
                <div className="d-flex gap-2 mb-3 flex-wrap">
                  <Form.Select
                    size="sm" style={{ maxWidth: '180px' }}
                    value={pointFilter} onChange={(e) => setPointFilter(e.target.value)}
                  >
                    <option value="">All insertion points</option>
                    {points.map((p) => <option key={p} value={p}>{p}</option>)}
                  </Form.Select>
                  <Form.Select
                    size="sm" style={{ maxWidth: '220px' }}
                    value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}
                  >
                    <option value="">All confidence classes</option>
                    {kinds.map((k) => <option key={k} value={k}>{k}</option>)}
                  </Form.Select>
                  <Form.Select
                    size="sm" style={{ maxWidth: '160px' }}
                    value={triageFilter} onChange={(e) => setTriageFilter(e.target.value)}
                  >
                    <option value="">All triage</option>
                    {TRIAGE_ORDER.map((t) => <option key={t} value={t}>{t}</option>)}
                  </Form.Select>
                </div>

                {shown.length === 0 ? (
                  <div className="text-white-50 py-4 text-center" style={{ fontSize: '0.85rem' }}>
                    {findings.length === 0
                      ? `No findings recorded. ${skipped.length > 0
                        ? `Check the Not tested tab: ${skipped.length} vectors were never sent.`
                        : ''}`
                      : 'No findings match these filters.'}
                  </div>
                ) : (
                  <Accordion alwaysOpen>
                    {shown.map((f, i) => {
                      const kind = KIND_STYLE[f.kind] || { bg: 'secondary', label: f.kind };
                      const triage = f.triage || 'new';
                      return (
                        <Accordion.Item eventKey={String(i)} key={f.id}>
                          <Accordion.Header>
                            <div className="d-flex align-items-center gap-2 flex-wrap w-100 pe-3">
                              <Badge bg={kind.bg}>{kind.label}</Badge>
                              <Badge bg="dark" className="border border-secondary text-white-50">
                                {f.insertion_point}
                              </Badge>
                              {f.param && (
                                <code className="text-danger" style={{ fontSize: '0.78rem' }}>
                                  {f.param}
                                </code>
                              )}
                              <span className="text-white-50" style={{ fontSize: '0.78rem' }}>
                                {f.method} {f.domain}{f.vector_path}
                              </span>
                              <Badge
                                bg={triage === 'interesting' ? 'warning' : triage === 'dismissed' ? 'dark' : 'secondary'}
                                className="ms-auto"
                              >
                                {triage}
                              </Badge>
                            </div>
                          </Accordion.Header>
                          <Accordion.Body>
                            <div className="mb-2 text-white" style={{ fontSize: '0.82rem' }}>
                              {f.kind_label}
                            </div>
                            {f.confidence && (
                              <div className="text-white-50 mb-2" style={{ fontSize: '0.75rem' }}>
                                {f.confidence}
                                {f.detection_method ? ` (${f.detection_method})` : ''}
                                {f.inject_type ? ` in ${f.inject_type}` : ''}
                              </div>
                            )}
                            {f.payload && (
                              <pre
                                className="p-2 rounded mb-2"
                                style={{
                                  background: 'rgba(0,0,0,0.35)', color: '#ff8a95',
                                  fontSize: '0.75rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                }}
                              >{f.payload}</pre>
                            )}
                            {f.url && (
                              <div className="text-white-50 mb-2" style={{ fontSize: '0.72rem', wordBreak: 'break-all' }}>
                                {f.url}
                              </div>
                            )}
                            {f.evidence && (
                              <div className="text-white-50 mb-3" style={{ fontSize: '0.75rem' }}>
                                {f.evidence}
                              </div>
                            )}
                            <Exchange request={f.raw_request} response={f.raw_response} />
                            <div className="d-flex gap-2 mt-3">
                              {TRIAGE_ORDER.map((t) => (
                                <Button
                                  key={t} size="sm"
                                  variant={triage === t ? 'danger' : 'outline-secondary'}
                                  onClick={() => setTriage(f.id, t)}
                                >
                                  {t}
                                </Button>
                              ))}
                            </div>
                          </Accordion.Body>
                        </Accordion.Item>
                      );
                    })}
                  </Accordion>
                )}
              </>
            )}

            {tab === 'skipped' && (
              skipped.length === 0 ? (
                <div className="text-white-50 py-4 text-center" style={{ fontSize: '0.85rem' }}>
                  Every attack vector was tested by {tool?.name}.
                </div>
              ) : (
                <>
                  <div className="text-white-50 mb-3" style={{ fontSize: '0.8rem' }}>
                    These vectors were never sent, so they are not clean, they are unknown. Grouped by
                    the reason {tool?.name} could not reach them.
                  </div>
                  <Accordion alwaysOpen>
                    {skippedByReason.map(([reason, rows], i) => (
                      <Accordion.Item eventKey={String(i)} key={reason}>
                        <Accordion.Header>
                          <div className="d-flex align-items-center gap-2 w-100 pe-3">
                            <Badge bg="warning" text="dark">{rows.length}</Badge>
                            <span className="text-white-50" style={{ fontSize: '0.8rem' }}>
                              {reason}
                            </span>
                          </div>
                        </Accordion.Header>
                        <Accordion.Body>
                          {rows.map((s) => (
                            <div
                              key={s.vector_id}
                              className="d-flex gap-2 align-items-baseline py-1"
                              style={{ fontSize: '0.76rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}
                            >
                              <Badge bg="dark" className="border border-secondary text-white-50">
                                {s.insertion_point}
                              </Badge>
                              <span className="text-white-50">{s.method}</span>
                              <span className="text-white-50" style={{ wordBreak: 'break-all' }}>
                                {s.domain}{s.path}
                              </span>
                            </div>
                          ))}
                        </Accordion.Body>
                      </Accordion.Item>
                    ))}
                  </Accordion>
                </>
              )
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={load} disabled={loading}>Refresh</Button>
        <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
}

export default VectorToolResultsModal;
