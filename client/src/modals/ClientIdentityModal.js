import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Row, Col, Button, Spinner, Badge, ListGroup, Form } from 'react-bootstrap';

// ---- helpers -------------------------------------------------------------

// Build a raw HTTP request string from a consolidated endpoint (method + path/query + Host + headers).
function buildRawRequest(ep) {
  if (!ep) return '';
  let host = ep.domain || '';
  let pathQ = ep.path || '/';
  try {
    const u = new URL(ep.url);
    host = u.host.replace(/:443$/, '').replace(/:80$/, '');
    pathQ = (u.pathname || '/') + (u.search || '');
  } catch (_) { /* fall back to fields above */ }

  let raw = `${ep.method || 'GET'} ${pathQ} HTTP/1.1\n`;
  raw += `Host: ${host}\n`;
  if (ep.headers && typeof ep.headers === 'object') {
    Object.entries(ep.headers).forEach(([k, v]) => {
      raw += `${k}: ${Array.isArray(v) ? v.join(', ') : v}\n`;
    });
  }
  raw += '\n';
  return raw;
}

function b64urlDecode(s) {
  try {
    let b = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    // decodeURIComponent(escape()) handles UTF-8 payloads
    return decodeURIComponent(escape(window.atob(b)));
  } catch (_) { return null; }
}

function isMostlyPrintable(s) {
  if (!s) return false;
  const printable = (s.match(/[\x20-\x7E]/g) || []).length;
  return printable / s.length > 0.85;
}

function prettyMaybe(s) {
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch (_) { return s; }
}

// Find JWTs and decodable base64/base64url blobs anywhere in the raw request.
function decodeArtifacts(raw) {
  if (!raw) return [];
  const out = [];
  const seen = new Set();

  // JWTs: three base64url segments separated by dots, header+payload must be JSON.
  const jwtRe = /([A-Za-z0-9_-]{6,})\.([A-Za-z0-9_-]{6,})\.([A-Za-z0-9_-]{4,})/g;
  let m;
  while ((m = jwtRe.exec(raw)) !== null) {
    const token = m[0];
    if (seen.has(token)) continue;
    const header = b64urlDecode(m[1]);
    const payload = b64urlDecode(m[2]);
    if (header && payload && header.trim().startsWith('{') && payload.trim().startsWith('{')) {
      seen.add(token);
      out.push({
        type: 'JWT',
        original: token,
        decoded: `// header\n${prettyMaybe(header)}\n\n// payload\n${prettyMaybe(payload)}`,
      });
    }
  }

  // Generic base64 / base64url tokens (>= 16 chars) that decode to printable text.
  const b64Re = /[A-Za-z0-9_\-+/]{16,}={0,2}/g;
  while ((m = b64Re.exec(raw)) !== null) {
    const tok = m[0];
    if (seen.has(tok)) continue;
    if (out.some((a) => a.original.indexOf(tok) !== -1)) continue; // part of a JWT already shown
    const dec = b64urlDecode(tok);
    if (dec && dec.length >= 3 && dec !== tok && isMostlyPrintable(dec)) {
      seen.add(tok);
      out.push({ type: 'base64', original: tok, decoded: prettyMaybe(dec) });
    }
  }

  return out;
}

function getSelectionText() {
  return (window.getSelection && window.getSelection().toString().trim()) || '';
}

function sourceBadge(source) {
  if (source === 'decoded') return <Badge bg="info">decoded</Badge>;
  if (source === 'auto') return <Badge bg="success">auto</Badge>;
  return <Badge bg="secondary">request</Badge>;
}

// ---- component -----------------------------------------------------------

const ClientIdentityModal = ({ show, handleClose, activeTarget }) => {
  const [endpoints, setEndpoints] = useState([]);
  const [selectedEndpointId, setSelectedEndpointId] = useState(null);
  const [identifiers, setIdentifiers] = useState([]);
  const [loadingEndpoints, setLoadingEndpoints] = useState(false);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState('');

  const selectedEndpoint = useMemo(
    () => endpoints.find((e) => e.id === selectedEndpointId) || null,
    [endpoints, selectedEndpointId]
  );
  const rawRequest = useMemo(() => buildRawRequest(selectedEndpoint), [selectedEndpoint]);
  const artifacts = useMemo(() => decodeArtifacts(rawRequest), [rawRequest]);

  const endpointIdentifiers = useMemo(() => {
    if (!selectedEndpoint) return [];
    return identifiers.filter(
      (i) => i.endpoint_url === selectedEndpoint.url && i.method === selectedEndpoint.method
    );
  }, [identifiers, selectedEndpoint]);

  const identifierCountFor = useCallback(
    (ep) => identifiers.filter((i) => i.endpoint_url === ep.url && i.method === ep.method).length,
    [identifiers]
  );

  const filteredEndpoints = useMemo(() => {
    const f = filter.trim().toLowerCase();
    if (!f) return endpoints;
    return endpoints.filter((e) => (e.url || '').toLowerCase().includes(f));
  }, [endpoints, filter]);

  const fetchEndpoints = useCallback(async () => {
    if (!activeTarget) return;
    setLoadingEndpoints(true);
    try {
      const res = await fetch(`/api/consolidated-endpoints/${activeTarget.id}`);
      const data = res.ok ? await res.json() : [];
      const list = Array.isArray(data) ? data : [];
      setEndpoints(list);
      setSelectedEndpointId((prev) => (prev && list.some((e) => e.id === prev) ? prev : (list[0] ? list[0].id : null)));
    } catch (e) {
      console.error('[ClientIdentity] fetchEndpoints failed:', e);
      setEndpoints([]);
    } finally {
      setLoadingEndpoints(false);
    }
  }, [activeTarget]);

  const fetchIdentifiers = useCallback(async () => {
    if (!activeTarget) return;
    try {
      const res = await fetch(`/api/authz/client-identifiers/${activeTarget.id}`);
      const data = res.ok ? await res.json() : [];
      setIdentifiers(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('[ClientIdentity] fetchIdentifiers failed:', e);
      setIdentifiers([]);
    }
  }, [activeTarget]);

  useEffect(() => {
    if (show && activeTarget) {
      fetchEndpoints();
      fetchIdentifiers();
    }
    if (!show) { setSelectedEndpointId(null); setFilter(''); }
  }, [show, activeTarget, fetchEndpoints, fetchIdentifiers]);

  const addSelection = async (source) => {
    const value = getSelectionText();
    if (!value || !selectedEndpoint || !activeTarget) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/authz/client-identifiers/${activeTarget.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpoint_url: selectedEndpoint.url,
          method: selectedEndpoint.method || 'GET',
          value,
          source,
          label: '',
        }),
      });
      if (res.ok) {
        const created = await res.json();
        setIdentifiers((prev) => [...prev, created]);
        if (window.getSelection) window.getSelection().removeAllRanges();
      }
    } finally { setBusy(false); }
  };

  const deleteIdentifier = async (id) => {
    setBusy(true);
    try {
      await fetch(`/api/authz/client-identifiers/id/${id}`, { method: 'DELETE' });
      setIdentifiers((prev) => prev.filter((i) => i.id !== id));
    } finally { setBusy(false); }
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Client Identity — IDOR &amp; Access-Control Targets</Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '72vh' }}>
        {!activeTarget ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <Row>
            {/* LEFT: endpoints */}
            <Col md={3} className="border-end border-secondary" style={{ maxHeight: '72vh', overflowY: 'auto' }}>
              <Form.Control
                size="sm"
                className="mb-2"
                placeholder="Filter endpoints…"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
              {loadingEndpoints ? (
                <div className="text-center py-3"><Spinner size="sm" animation="border" variant="danger" /></div>
              ) : filteredEndpoints.length === 0 ? (
                <div className="text-white-50 small fst-italic">
                  No discovered endpoints yet. Run the URL workflow / consolidate endpoints first.
                </div>
              ) : (
                <ListGroup variant="flush">
                  {filteredEndpoints.map((ep) => {
                    const count = identifierCountFor(ep);
                    return (
                      <ListGroup.Item
                        key={ep.id}
                        action
                        active={ep.id === selectedEndpointId}
                        onClick={() => setSelectedEndpointId(ep.id)}
                        className="bg-dark text-white py-2"
                      >
                        <div className="d-flex justify-content-between align-items-center">
                          <span className="badge bg-secondary me-1">{ep.method || 'GET'}</span>
                          {count > 0 && <Badge bg="danger" title={`${count} identifier(s)`}>{count}</Badge>}
                        </div>
                        <div className="text-info text-truncate" style={{ fontFamily: 'monospace', fontSize: '0.72rem' }} title={ep.url}>
                          {ep.path || ep.url}
                        </div>
                      </ListGroup.Item>
                    );
                  })}
                </ListGroup>
              )}
            </Col>

            {/* MIDDLE: raw request + identifiers */}
            <Col md={5} className="border-end border-secondary">
              {!selectedEndpoint ? (
                <div className="text-center text-white-50 py-5">Select an endpoint to inspect its request.</div>
              ) : (
                <>
                  <div className="d-flex justify-content-between align-items-center mb-1">
                    <span className="text-white-50 small text-uppercase">Raw HTTP Request</span>
                    <span className="d-flex gap-2">
                      <Button size="sm" variant="outline-secondary" disabled
                        title="Coming soon: automatically detect unique identifiers in this request">
                        Auto-detect IDs
                      </Button>
                      <Button size="sm" variant="danger" disabled={busy} onClick={() => addSelection('request')}>
                        Add selection
                      </Button>
                    </span>
                  </div>
                  <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                    Highlight a value (an ID in the path/query, a token, etc.) then click <strong>Add selection</strong>.
                  </div>
                  <pre
                    className="bg-black text-white p-2 rounded mt-1"
                    style={{ fontSize: '0.75rem', maxHeight: '300px', overflowY: 'auto', whiteSpace: 'pre-wrap', userSelect: 'text' }}
                  >
                    {rawRequest}
                  </pre>

                  <div className="text-white-50 small text-uppercase mt-3 mb-1">
                    Unique Identifiers (IDOR targets)
                  </div>
                  {endpointIdentifiers.length === 0 ? (
                    <div className="text-white-50 small fst-italic">None yet for this endpoint.</div>
                  ) : (
                    <ListGroup variant="flush">
                      {endpointIdentifiers.map((i) => (
                        <ListGroup.Item key={i.id} className="bg-dark text-white d-flex justify-content-between align-items-center py-1">
                          <span className="text-truncate" style={{ fontFamily: 'monospace', fontSize: '0.75rem' }} title={i.value}>
                            {i.value}
                          </span>
                          <span className="d-flex align-items-center gap-2">
                            {sourceBadge(i.source)}
                            <i role="button" className="bi bi-trash text-danger" title="Remove"
                              onClick={() => deleteIdentifier(i.id)} />
                          </span>
                        </ListGroup.Item>
                      ))}
                    </ListGroup>
                  )}
                </>
              )}
            </Col>

            {/* RIGHT: decoded base64 / JWT */}
            <Col md={4} style={{ maxHeight: '72vh', overflowY: 'auto' }}>
              <div className="d-flex justify-content-between align-items-center mb-1">
                <span className="text-white-50 small text-uppercase">Decoded (Base64 / JWT)</span>
                <Button size="sm" variant="danger" disabled={busy} onClick={() => addSelection('decoded')}>
                  Add selection
                </Button>
              </div>
              {artifacts.length === 0 ? (
                <div className="text-white-50 small fst-italic">
                  No base64 / JWT data found in this request. When a request contains a JWT or base64 value
                  (e.g. an Authorization header or token), its decoded contents appear here — highlight a
                  claim and click <strong>Add selection</strong>.
                </div>
              ) : (
                artifacts.map((a, idx) => (
                  <div key={idx} className="mb-3">
                    <div className="d-flex align-items-center gap-2 mb-1">
                      <Badge bg={a.type === 'JWT' ? 'warning' : 'info'} text={a.type === 'JWT' ? 'dark' : undefined}>{a.type}</Badge>
                      <span className="text-white-50 text-truncate" style={{ fontFamily: 'monospace', fontSize: '0.68rem' }} title={a.original}>
                        {a.original.length > 40 ? a.original.slice(0, 40) + '…' : a.original}
                      </span>
                    </div>
                    <pre
                      className="bg-black text-white p-2 rounded"
                      style={{ fontSize: '0.72rem', maxHeight: '220px', overflowY: 'auto', whiteSpace: 'pre-wrap', userSelect: 'text' }}
                    >
                      {a.decoded}
                    </pre>
                  </div>
                ))
              )}
            </Col>
          </Row>
        )}
      </Modal.Body>
    </Modal>
  );
};

export default ClientIdentityModal;
