import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Row, Col, Button, Form, Spinner, Badge, ListGroup, Alert } from 'react-bootstrap';

// A client identity pattern is one answer to the question "how does this application decide who is
// asking", pinned to a single real request and the response it produced. The category is the field
// everything else hangs off, because it is what decides whether an IDOR attempt is a five second
// edit or a signature attack, so it is ranked, colour coded and used to group the list rather than
// being buried as one more select in the form.

const CATEGORIES = [
  {
    value: 'parameter',
    label: 'Parameter',
    variant: 'danger',
    blurb: 'The identifier rides in a query string, a path segment or a body field, so the caller '
      + 'sets it outright. Nothing has to be defeated first: put someone else\'s value in and see '
      + 'whose data comes back. Start here.',
  },
  {
    value: 'signed_token',
    label: 'Signed token',
    variant: 'warning',
    blurb: 'The identifier lives inside a signed token, usually a JWT. It cannot be moved until the '
      + 'signature stops being checked, so the work is on the algorithm, the key or the verification '
      + 'path, and only then on the identifier.',
  },
  {
    value: 'user_context_object',
    label: 'User context object',
    variant: 'secondary',
    blurb: 'The server resolves the session itself and passes a built identity downstream. The caller '
      + 'contributes none of it, so there is nothing in the request to swap. Anything found here comes '
      + 'from confusing the resolver, not from editing the request.',
  },
];

const CATEGORY_META = CATEGORIES.reduce((acc, c) => { acc[c.value] = c; return acc; }, {});

const LOCATIONS = [
  { value: '', label: 'Not recorded' },
  { value: 'query', label: 'Query parameter' },
  { value: 'path', label: 'Path segment' },
  { value: 'body', label: 'Body field' },
  { value: 'header', label: 'Header' },
  { value: 'cookie', label: 'Cookie' },
  { value: 'token_claim', label: 'Token claim' },
  { value: 'server_side', label: 'Server side only' },
];

const LOCATION_LABEL = LOCATIONS.reduce((acc, l) => { acc[l.value] = l.label; return acc; }, {});

const EMPTY_FORM = {
  id: null,
  name: '',
  category: 'parameter',
  description: '',
  raw_request: '',
  identifier_location: '',
  identifier_name: '',
  identifier_value: '',
  notes: '',
};

const RAW_REQUEST_PLACEHOLDER = `GET /api/v1/accounts/8412/invoices HTTP/1.1
Host: app.example.com
Cookie: session=...
Accept: application/json

`;

function hostFromUrl(u) {
  if (!u) return '';
  try {
    return new URL(u.includes('://') ? u : `https://${u}`).host;
  } catch (_) {
    return String(u).replace(/^https?:\/\//, '').split('/')[0];
  }
}

function statusVariant(status) {
  const s = Number(status || 0);
  if (!s) return 'secondary';
  if (s < 300) return 'success';
  if (s < 400) return 'info';
  if (s === 401 || s === 403) return 'warning';
  return 'danger';
}

// Render the stored response the way it came off the wire. Headers are a jsonb object on the row,
// so a value can be a list when the target repeated a header, and joining is closer to the truth
// than picking one.
function buildRawResponse(p) {
  if (!p) return '';
  if (!p.response_status && !p.response_body) return '';
  const lines = [`HTTP/1.1 ${p.response_status || 0}`];
  const headers = p.response_headers;
  if (headers && typeof headers === 'object') {
    Object.entries(headers).forEach(([k, v]) => {
      lines.push(`${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
    });
  }
  lines.push('');
  if (p.response_body) lines.push(p.response_body);
  return lines.join('\n');
}

function rawRequestFromCandidate(candidate, fallbackHost) {
  let host = fallbackHost || '';
  let pathQ = candidate.endpoint_url || '/';
  try {
    const u = new URL(candidate.endpoint_url);
    host = u.host;
    pathQ = (u.pathname || '/') + (u.search || '');
  } catch (_) { /* keep the raw string, it is still better than an empty box */ }
  return `${candidate.method || 'GET'} ${pathQ} HTTP/1.1\nHost: ${host}\n\n`;
}

// Work out where an auto-detected value actually sat, so the prefilled form starts from a claim
// rather than from blanks. The point of guessing at all is that location and category are the two
// fields an operator is most likely to leave alone, and a wrong default that looks filled in is
// worse than an empty one, so anything not positively found in the URL stays unset.
function guessPlacement(candidate) {
  const value = String(candidate.value || '');
  if (!value) return { identifier_location: '', identifier_name: '', category: 'parameter' };

  try {
    const u = new URL(candidate.endpoint_url);
    let matchedParam = '';
    u.searchParams.forEach((v, k) => { if (v === value && !matchedParam) matchedParam = k; });
    if (matchedParam) {
      return { identifier_location: 'query', identifier_name: matchedParam, category: 'parameter' };
    }
    const segments = (u.pathname || '').split('/').filter(Boolean);
    const idx = segments.indexOf(value);
    if (idx !== -1) {
      // The segment before the id is what the id refers to, so it is the closest thing to a name
      // this location has: /accounts/8412 makes the identifier "accounts".
      return {
        identifier_location: 'path',
        identifier_name: idx > 0 ? segments[idx - 1] : '',
        category: 'parameter',
      };
    }
  } catch (_) { /* not a parseable URL, fall through to the source based guess */ }

  // "decoded" means the auto-detector lifted this out of a JWT or base64 blob rather than reading
  // it off the request line, which is exactly the signed token case.
  if (candidate.source === 'decoded') {
    return { identifier_location: 'token_claim', identifier_name: '', category: 'signed_token' };
  }
  return { identifier_location: '', identifier_name: '', category: 'parameter' };
}

const ClientIdentityPatternsModal = ({ show, handleClose, scopeTargetId, scopeTargetUrl }) => {
  const [patterns, setPatterns] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [replayingId, setReplayingId] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const [form, setForm] = useState(EMPTY_FORM);
  const [selectedId, setSelectedId] = useState(null);
  // Keyed by pattern id so switching rows does not carry another row's replay banner with it. Each
  // entry records what the status was before the replay, which is the whole reason this exists: a
  // pattern that used to answer 200 and now answers 403 is a session that died, not a finding.
  const [replayInfo, setReplayInfo] = useState({});

  const targetHost = useMemo(() => hostFromUrl(scopeTargetUrl), [scopeTargetUrl]);

  const selectedPattern = useMemo(
    () => patterns.find((p) => p.id === selectedId) || null,
    [patterns, selectedId]
  );

  const fetchPatterns = useCallback(async () => {
    if (!scopeTargetId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/authz/identity-patterns/${scopeTargetId}`);
      const data = res.ok ? await res.json() : [];
      setPatterns(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('[IdentityPatterns] fetchPatterns failed:', e);
      setError(`Could not load identity patterns: ${e.message}`);
      setPatterns([]);
    } finally {
      setLoading(false);
    }
  }, [scopeTargetId]);

  const fetchCandidates = useCallback(async () => {
    if (!scopeTargetId) return;
    try {
      const res = await fetch(`/api/authz/client-identifiers/${scopeTargetId}`);
      const data = res.ok ? await res.json() : [];
      setCandidates(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('[IdentityPatterns] fetchCandidates failed:', e);
      setCandidates([]);
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (show && scopeTargetId) {
      fetchPatterns();
      fetchCandidates();
    }
    if (!show) {
      setForm(EMPTY_FORM);
      setSelectedId(null);
      setReplayInfo({});
      setError('');
      setNotice('');
    }
  }, [show, scopeTargetId, fetchPatterns, fetchCandidates]);

  const grouped = useMemo(() => CATEGORIES.map((c) => ({
    ...c,
    // Anything the server hands back with an unrecognised category would otherwise vanish from the
    // screen entirely, so it lands under Parameter, the group an operator reads first.
    rows: patterns.filter((p) => (CATEGORY_META[p.category] ? p.category : 'parameter') === c.value),
  })), [patterns]);

  const setField = (patch) => setForm((prev) => ({ ...prev, ...patch }));

  const newPattern = () => {
    setForm(EMPTY_FORM);
    setSelectedId(null);
    setError('');
    setNotice('');
  };

  const editPattern = (p) => {
    setSelectedId(p.id);
    setForm({
      id: p.id,
      name: p.name || '',
      category: CATEGORY_META[p.category] ? p.category : 'parameter',
      description: p.description || '',
      raw_request: p.raw_request || '',
      identifier_location: p.identifier_location || '',
      identifier_name: p.identifier_name || '',
      identifier_value: p.identifier_value || '',
      notes: p.notes || '',
    });
    setError('');
    setNotice('');
  };

  const canSave = form.name.trim() !== '' && form.category !== '';

  const savePattern = async () => {
    if (!canSave || !scopeTargetId) return;
    setBusy(true);
    setError('');
    setNotice('');
    const body = {
      name: form.name.trim(),
      category: form.category,
      description: form.description,
      raw_request: form.raw_request,
      identifier_location: form.identifier_location,
      identifier_name: form.identifier_name,
      identifier_value: form.identifier_value,
      notes: form.notes,
    };
    try {
      const url = form.id
        ? `/api/authz/identity-patterns/id/${form.id}`
        : `/api/authz/identity-patterns/${scopeTargetId}`;
      const res = await fetch(url, {
        method: form.id ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error((await res.text()) || `Request failed (${res.status})`);
      const created = await res.json();
      await fetchPatterns();
      if (!form.id && created && created.id) {
        setForm((prev) => ({ ...prev, id: created.id }));
        setSelectedId(created.id);
        setNotice('Pattern saved. Replay it to attach the response the target gives right now.');
      } else {
        setNotice('Pattern updated.');
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const deletePattern = async (id) => {
    setBusy(true);
    setError('');
    try {
      const res = await fetch(`/api/authz/identity-patterns/id/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error((await res.text()) || `Delete failed (${res.status})`);
      setPatterns((prev) => prev.filter((p) => p.id !== id));
      setReplayInfo((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
      if (selectedId === id) newPattern();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  // Replay sends the stored raw request again and overwrites the stored response with what came
  // back. That overwrite is the reason for the banner below: without it the panel silently changes
  // under the operator and a fresh 403 reads like it was always there.
  const replayPattern = async (p) => {
    setReplayingId(p.id);
    setError('');
    try {
      const res = await fetch(`/api/authz/identity-patterns/id/${p.id}/replay`, { method: 'POST' });
      if (!res.ok) throw new Error((await res.text()) || `Replay failed (${res.status})`);
      const result = await res.json();
      const previousStatus = p.response_status || 0;
      setPatterns((prev) => prev.map((row) => (row.id === p.id ? { ...row, ...result } : row)));
      setReplayInfo((prev) => ({
        ...prev,
        [p.id]: {
          at: new Date(),
          previousStatus,
          status: result.response_status || 0,
          timeMs: result.response_time_ms || 0,
          changed: previousStatus !== 0 && previousStatus !== (result.response_status || 0),
        },
      }));
      setSelectedId(p.id);
    } catch (e) {
      setError(e.message);
    } finally {
      setReplayingId(null);
    }
  };

  // Pull a detected identifier into the create form. The candidate already knows the endpoint, the
  // verb and the value it was seen with, so the only thing left for the operator is the category
  // call, which is the one judgement no detector can make for them.
  const applyCandidate = (c) => {
    const placement = guessPlacement(c);
    setSelectedId(null);
    setForm({
      ...EMPTY_FORM,
      name: `${c.method || 'GET'} ${c.label || c.value}`.slice(0, 120),
      category: placement.category,
      description: c.label ? `Auto-detected: ${c.label}` : 'Auto-detected identifier',
      raw_request: rawRequestFromCandidate(c, targetHost),
      identifier_location: placement.identifier_location,
      identifier_name: placement.identifier_name,
      identifier_value: c.value || '',
    });
    setNotice('Prefilled from a detected identifier. Confirm the category before saving, it is the '
      + 'field that decides how this gets attacked.');
  };

  const rawResponse = buildRawResponse(selectedPattern);
  const selectedReplay = selectedId ? replayInfo[selectedId] : null;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Client Identity Patterns{targetHost ? ` - ${targetHost}` : ''}
        </Modal.Title>
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

            <div className="d-flex flex-wrap gap-2 align-items-center mb-3">
              <Button size="sm" variant="outline-danger" onClick={newPattern} disabled={busy}>
                <i className="bi bi-plus-lg me-1" />New pattern
              </Button>
              <Button size="sm" variant="outline-secondary" onClick={fetchPatterns} disabled={loading || busy}>
                {loading ? <Spinner size="sm" animation="border" /> : 'Refresh list'}
              </Button>
              <span className="text-white-50 small ms-auto">
                {patterns.length} pattern(s):{' '}
                {grouped.map((g) => `${g.rows.length} ${g.label.toLowerCase()}`).join(', ')}
              </span>
            </div>

            <Row>
              {/* LEFT: patterns, grouped by how much of the identity the caller controls */}
              <Col md={4} className="border-end border-secondary" style={{ maxHeight: '66vh', overflowY: 'auto' }}>
                {loading ? (
                  <div className="text-center py-3"><Spinner size="sm" animation="border" variant="danger" /></div>
                ) : patterns.length === 0 ? (
                  <div className="text-white-50 small fst-italic">
                    Nothing modelled yet. Record one request per way this application works out who is
                    asking, then say which of the three shapes it is.
                  </div>
                ) : (
                  grouped.map((group) => (
                    <div key={group.value} className="mb-3">
                      <div className="d-flex align-items-center gap-2">
                        <Badge bg={group.variant}>{group.label}</Badge>
                        <span className="text-white-50 small">{group.rows.length}</span>
                      </div>
                      <div className="text-white-50 mb-1" style={{ fontSize: '0.68rem' }}>
                        {group.blurb}
                      </div>
                      {group.rows.length === 0 ? (
                        <div className="text-white-50 fst-italic" style={{ fontSize: '0.68rem' }}>
                          None recorded.
                        </div>
                      ) : (
                        <ListGroup variant="flush">
                          {group.rows.map((p) => (
                            <ListGroup.Item
                              key={p.id}
                              action
                              active={p.id === selectedId}
                              onClick={() => editPattern(p)}
                              className="bg-dark text-white py-2"
                            >
                              <div className="d-flex justify-content-between align-items-center">
                                <span className="text-truncate me-2">{p.name}</span>
                                <span className="d-flex align-items-center gap-1 flex-shrink-0">
                                  {p.response_status
                                    ? <Badge bg={statusVariant(p.response_status)}>{p.response_status}</Badge>
                                    : <Badge bg="secondary">not sent</Badge>}
                                  <Button
                                    size="sm"
                                    variant="outline-danger"
                                    className="py-0 px-1"
                                    style={{ fontSize: '0.66rem' }}
                                    disabled={replayingId === p.id || !p.raw_request}
                                    title={p.raw_request
                                      ? 'Send the stored request again and replace the stored response'
                                      : 'No raw request stored, so there is nothing to send'}
                                    onClick={(e) => { e.stopPropagation(); replayPattern(p); }}
                                  >
                                    {replayingId === p.id
                                      ? <Spinner size="sm" animation="border" />
                                      : 'Replay'}
                                  </Button>
                                  <i
                                    role="button"
                                    className="bi bi-trash text-danger ms-1"
                                    title="Delete pattern"
                                    onClick={(e) => { e.stopPropagation(); deletePattern(p.id); }}
                                  />
                                </span>
                              </div>
                              <div
                                className="text-info text-truncate"
                                style={{ fontFamily: 'monospace', fontSize: '0.7rem' }}
                                title={p.identifier_value}
                              >
                                {p.identifier_name || p.identifier_value || '(no identifier recorded)'}
                              </div>
                              <div className="text-white-50" style={{ fontSize: '0.66rem' }}>
                                {LOCATION_LABEL[p.identifier_location] || 'location not recorded'}
                                {replayInfo[p.id] ? ' | refreshed just now' : ''}
                              </div>
                            </ListGroup.Item>
                          ))}
                        </ListGroup>
                      )}
                    </div>
                  ))
                )}
              </Col>

              {/* MIDDLE: the editor plus whatever the target last answered */}
              <Col md={5} className="border-end border-secondary" style={{ maxHeight: '66vh', overflowY: 'auto' }}>
                <div className="text-white-50 small text-uppercase mb-2">
                  {form.id ? 'Edit pattern' : 'New pattern'}
                </div>

                <Row className="g-2">
                  <Col md={7}>
                    <Form.Label className="text-white small mb-1">Name</Form.Label>
                    <Form.Control
                      size="sm"
                      placeholder="e.g. Invoice fetch by account id"
                      value={form.name}
                      onChange={(e) => setField({ name: e.target.value })}
                    />
                  </Col>
                  <Col md={5}>
                    <Form.Label className="text-white small mb-1">Category</Form.Label>
                    <Form.Select
                      size="sm"
                      value={form.category}
                      onChange={(e) => setField({ category: e.target.value })}
                    >
                      {CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                    </Form.Select>
                  </Col>
                  <Col md={12}>
                    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                      {CATEGORY_META[form.category] ? CATEGORY_META[form.category].blurb : ''}
                    </div>
                  </Col>

                  <Col md={12}>
                    <Form.Label className="text-white small mb-1">Description</Form.Label>
                    <Form.Control
                      size="sm"
                      placeholder="What the server does with this to decide the caller is who they say"
                      value={form.description}
                      onChange={(e) => setField({ description: e.target.value })}
                    />
                  </Col>

                  <Col md={12}>
                    <Form.Label className="text-white small mb-1">Raw HTTP request</Form.Label>
                    <Form.Control
                      as="textarea"
                      rows={8}
                      style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                      placeholder={RAW_REQUEST_PLACEHOLDER}
                      value={form.raw_request}
                      onChange={(e) => setField({ raw_request: e.target.value })}
                    />
                    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                      One real request, exactly as it went out. Replay sends these bytes back, so a
                      hand-edited header here changes what gets measured.
                    </div>
                  </Col>

                  <Col md={4}>
                    <Form.Label className="text-white small mb-1">Identifier location</Form.Label>
                    <Form.Select
                      size="sm"
                      value={form.identifier_location}
                      onChange={(e) => setField({ identifier_location: e.target.value })}
                    >
                      {LOCATIONS.map((l) => <option key={l.value || 'blank'} value={l.value}>{l.label}</option>)}
                    </Form.Select>
                  </Col>
                  <Col md={4}>
                    <Form.Label className="text-white small mb-1">Identifier name</Form.Label>
                    <Form.Control
                      size="sm"
                      placeholder="account_id, sub, X-User-Id"
                      value={form.identifier_name}
                      onChange={(e) => setField({ identifier_name: e.target.value })}
                    />
                  </Col>
                  <Col md={4}>
                    <Form.Label className="text-white small mb-1">Identifier value</Form.Label>
                    <Form.Control
                      size="sm"
                      style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                      placeholder="8412"
                      value={form.identifier_value}
                      onChange={(e) => setField({ identifier_value: e.target.value })}
                    />
                  </Col>
                  <Col md={12}>
                    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                      Server side means the value never appears in the request at all. Recording that is
                      worth as much as recording a value: it says there is nothing here to swap.
                    </div>
                  </Col>

                  <Col md={12}>
                    <Form.Label className="text-white small mb-1">Notes</Form.Label>
                    <Form.Control
                      size="sm"
                      placeholder="Which account this was captured as, what happened when the value was moved"
                      value={form.notes}
                      onChange={(e) => setField({ notes: e.target.value })}
                    />
                  </Col>

                  <Col md={12} className="d-flex align-items-center gap-2 mt-2">
                    <Button variant="danger" size="sm" onClick={savePattern} disabled={busy || !canSave}>
                      {busy ? <Spinner size="sm" animation="border" /> : (form.id ? 'Save changes' : 'Create pattern')}
                    </Button>
                    {form.id && (
                      <>
                        <Button
                          variant="outline-danger"
                          size="sm"
                          disabled={replayingId === form.id || !form.raw_request}
                          onClick={() => selectedPattern && replayPattern(selectedPattern)}
                        >
                          {replayingId === form.id ? <Spinner size="sm" animation="border" /> : 'Replay'}
                        </Button>
                        <Button variant="outline-secondary" size="sm" onClick={newPattern} disabled={busy}>
                          Cancel edit
                        </Button>
                      </>
                    )}
                    {!canSave && (
                      <span className="text-white-50 small">A name and a category are required.</span>
                    )}
                  </Col>
                </Row>

                {selectedPattern && (
                  <div className="mt-3">
                    <div className="d-flex justify-content-between align-items-center mb-1">
                      <span className="text-white-50 small text-uppercase">Stored response</span>
                      <span className="d-flex align-items-center gap-2">
                        {selectedPattern.response_time_ms
                          ? <span className="text-white-50" style={{ fontSize: '0.68rem' }}>
                              {selectedPattern.response_time_ms} ms
                            </span>
                          : null}
                        {selectedPattern.response_status
                          ? <Badge bg={statusVariant(selectedPattern.response_status)}>
                              {selectedPattern.response_status}
                            </Badge>
                          : <Badge bg="secondary">not sent</Badge>}
                      </span>
                    </div>
                    {selectedReplay && (
                      <Alert
                        variant={selectedReplay.changed ? 'warning' : 'success'}
                        className="py-2 small mb-2"
                      >
                        Replayed at {selectedReplay.at.toLocaleTimeString()}, {selectedReplay.timeMs} ms.
                        The response below is what the target answered just now and it has replaced what
                        was stored on this pattern.
                        {selectedReplay.changed
                          ? ` The status moved from ${selectedReplay.previousStatus} to ${selectedReplay.status}, so either the session behind this request has changed or the endpoint has.`
                          : ' The status is unchanged.'}
                      </Alert>
                    )}
                    <pre
                      className="bg-black text-white p-2 rounded"
                      style={{
                        fontSize: '0.72rem', maxHeight: '260px', overflowY: 'auto',
                        whiteSpace: 'pre-wrap', userSelect: 'text',
                      }}
                    >
                      {rawResponse || '(nothing captured yet, click Replay)'}
                    </pre>
                  </div>
                )}
              </Col>

              {/* RIGHT: the detector's output, waiting to be promoted into a modelled pattern */}
              <Col md={3} style={{ maxHeight: '66vh', overflowY: 'auto' }}>
                <div className="d-flex justify-content-between align-items-center mb-1">
                  <span className="text-white-50 small text-uppercase">Detected identifiers</span>
                  <Button size="sm" variant="outline-secondary" className="py-0 px-1"
                    style={{ fontSize: '0.66rem' }} onClick={fetchCandidates}>
                    Reload
                  </Button>
                </div>
                <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem' }}>
                  Values the auto-detector pulled out of recorded traffic. Each one already carries an
                  endpoint, a verb and the value it was seen with, so promoting one leaves only the
                  category to decide.
                </div>
                {candidates.length === 0 ? (
                  <div className="text-white-50 small fst-italic">
                    None yet. Run Auto-detect IDs in Client Identity first.
                  </div>
                ) : (
                  <ListGroup variant="flush">
                    {candidates.map((c) => (
                      <ListGroup.Item key={c.id} className="bg-dark text-white py-2">
                        <div className="d-flex justify-content-between align-items-center">
                          <Badge bg="secondary">{c.method || 'GET'}</Badge>
                          <Button
                            size="sm"
                            variant="outline-danger"
                            className="py-0 px-1"
                            style={{ fontSize: '0.66rem' }}
                            onClick={() => applyCandidate(c)}
                          >
                            Use as pattern
                          </Button>
                        </div>
                        <div
                          className="text-info text-truncate"
                          style={{ fontFamily: 'monospace', fontSize: '0.7rem' }}
                          title={c.value}
                        >
                          {c.value}
                        </div>
                        <div
                          className="text-white-50 text-truncate"
                          style={{ fontSize: '0.66rem' }}
                          title={c.endpoint_url}
                        >
                          {c.label ? `${c.label} | ` : ''}{c.endpoint_url}
                        </div>
                      </ListGroup.Item>
                    ))}
                  </ListGroup>
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

export default ClientIdentityPatternsModal;
