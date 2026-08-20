import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Row, Col, Button, Form, Spinner, Badge, Alert, Table } from 'react-bootstrap';

// The operations half of session tokens. Manage Sessions is where a token is defined, this is where
// you find out whether it still works and put it back to work when it does not.
//
// The one thing this screen has to make impossible to get wrong is the difference between a token
// that is switched off and a token that has expired. Both produce unauthenticated scans, and they
// have completely different fixes, so the active switch and the validation verdict sit next to each
// other on every row instead of in separate columns of a summary table.

const TYPE_LABEL = {
  header: 'Header',
  cookie: 'Cookie',
  api_key: 'API Key',
  bearer: 'Bearer',
  query: 'Query parameter',
};

// The server has not settled on a single word for a token the target rejected, so match the whole
// family rather than one spelling. Anything unrecognised counts as "not known to be stale", which
// keeps Refresh all expired from replaying a login flow against a session that was working fine.
const REJECTED_STATUSES = new Set(['expired', 'not_honoured', 'invalid', 'unauthorized', 'rejected', 'failed', 'revoked']);

function statusVariant(status) {
  const s = String(status || '').toLowerCase();
  if (!s) return 'secondary';
  if (s === 'valid' || s === 'ok' || s === 'active' || s === 'refreshed' || s === 'success') return 'success';
  // Deliberately not in REJECTED_STATUSES above: a companion is a routing cookie, never graded on
  // its own, so "Refresh all expired" must not replay a login flow on its account.
  if (s === 'companion') return 'info';
  if (REJECTED_STATUSES.has(s)) return 'danger';
  if (s === 'error' || s === 'unknown' || s === 'inconclusive') return 'warning';
  return 'secondary';
}

function isExpired(t) {
  if (t.expires_at) {
    const exp = new Date(t.expires_at).getTime();
    if (!isNaN(exp) && exp <= Date.now()) return true;
  }
  return REJECTED_STATUSES.has(String(t.last_validation_status || '').toLowerCase());
}

// A single line showing where the token goes on the wire. This duplicates the preview logic in
// ManageSessionsModal on purpose: the two modals are independent, and a row here only needs the
// one-line form, not the whole request sketch.
function wireSummary(t) {
  const value = t.token_value || '';
  const shown = value.length <= 24 ? value : `${value.slice(0, 20)}...`;
  const prefix = t.value_prefix || '';
  switch (t.token_type) {
    case 'bearer':
      return `Authorization: Bearer ${shown}`;
    case 'api_key':
      return `${t.header_name || 'X-API-Key'}: ${prefix}${shown}`;
    case 'cookie':
      return `Cookie: ${t.cookie_name || 'session'}=${shown}`;
    case 'query':
      return `?${t.param_name || 'token'}=${shown}`;
    case 'header':
    default:
      return `${t.header_name || 'Authorization'}: ${prefix}${shown}`;
  }
}

function whenText(iso) {
  if (!iso) return 'never';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? 'never' : d.toLocaleString();
}

const RefreshSessionModal = ({ show, handleClose, scopeTargetId, scopeTargetUrl }) => {
  const [tokens, setTokens] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  // Keyed by token id so a slow validate on one row never blanks the buttons on the others.
  const [rowBusy, setRowBusy] = useState({});
  const [results, setResults] = useState({});
  const [events, setEvents] = useState({});
  const [expanded, setExpanded] = useState({});
  const [bulk, setBulk] = useState('');
  const [bulkProgress, setBulkProgress] = useState('');

  const targetHost = useMemo(() => {
    if (!scopeTargetUrl) return '';
    try {
      return new URL(scopeTargetUrl.includes('://') ? scopeTargetUrl : `https://${scopeTargetUrl}`).host;
    } catch (_) {
      return String(scopeTargetUrl).replace(/^https?:\/\//, '').split('/')[0];
    }
  }, [scopeTargetUrl]);

  const fetchTokens = useCallback(async () => {
    if (!scopeTargetId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/session-tokens/target/${scopeTargetId}`);
      const data = res.ok ? await res.json() : [];
      setTokens(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('[RefreshSession] fetchTokens failed:', e);
      setError(`Could not load session tokens: ${e.message}`);
      setTokens([]);
    } finally {
      setLoading(false);
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (show && scopeTargetId) fetchTokens();
    if (!show) {
      setResults({});
      setEvents({});
      setExpanded({});
      setError('');
      setNotice('');
      setBulk('');
      setBulkProgress('');
    }
  }, [show, scopeTargetId, fetchTokens]);

  const markBusy = (id, what) => setRowBusy((prev) => ({ ...prev, [id]: what }));
  const clearBusy = (id) => setRowBusy((prev) => { const next = { ...prev }; delete next[id]; return next; });

  const loadEvents = useCallback(async (id) => {
    try {
      const res = await fetch(`/api/session-tokens/${id}/events`);
      const data = res.ok ? await res.json() : [];
      setEvents((prev) => ({ ...prev, [id]: Array.isArray(data) ? data : [] }));
    } catch (e) {
      console.error('[RefreshSession] loadEvents failed:', e);
      setEvents((prev) => ({ ...prev, [id]: [] }));
    }
  }, []);

  const toggleExpanded = (id) => {
    const willOpen = !expanded[id];
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
    // Only fetch the history when the row is actually opened. Loading it for every token up front
    // turns a list of twenty into twenty-one requests before the operator has clicked anything.
    // The fetch is deliberately outside the state updater, which React is free to run twice.
    if (willOpen && !events[id]) loadEvents(id);
  };

  const toggleActive = async (t) => {
    const nextActive = !(t.is_active !== false);
    markBusy(t.id, 'activate');
    setError('');
    try {
      const res = await fetch(`/api/session-tokens/${t.id}/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: nextActive }),
      });
      if (!res.ok) throw new Error((await res.text()) || `Request failed (${res.status})`);
      await fetchTokens();
    } catch (e) {
      setError(e.message);
    } finally {
      clearBusy(t.id);
    }
  };

  // Returns the verdict so the bulk actions can count outcomes without re-reading state that has
  // not been committed yet.
  const validateToken = useCallback(async (id) => {
    markBusy(id, 'validate');
    try {
      const res = await fetch(`/api/session-tokens/${id}/validate`, { method: 'POST' });
      if (!res.ok) throw new Error((await res.text()) || `Validate failed (${res.status})`);
      const data = await res.json();
      setResults((prev) => ({ ...prev, [id]: { kind: 'validate', ...data } }));
      if (events[id]) await loadEvents(id);
      return data;
    } catch (e) {
      setResults((prev) => ({ ...prev, [id]: { kind: 'validate', status: 'error', detail: e.message } }));
      return { status: 'error', detail: e.message };
    } finally {
      clearBusy(id);
    }
  }, [events, loadEvents]);

  const refreshToken = useCallback(async (id) => {
    markBusy(id, 'refresh');
    try {
      const res = await fetch(`/api/session-tokens/${id}/refresh`, { method: 'POST' });
      if (!res.ok) throw new Error((await res.text()) || `Refresh failed (${res.status})`);
      const data = await res.json();
      setResults((prev) => ({ ...prev, [id]: { kind: 'refresh', ...data } }));
      if (events[id]) await loadEvents(id);
      return data;
    } catch (e) {
      setResults((prev) => ({ ...prev, [id]: { kind: 'refresh', status: 'error', detail: e.message } }));
      return { status: 'error', detail: e.message };
    } finally {
      clearBusy(id);
    }
  }, [events, loadEvents]);

  const validateOne = async (id) => {
    setError('');
    await validateToken(id);
    await fetchTokens();
  };

  const refreshOne = async (id) => {
    setError('');
    await refreshToken(id);
    await fetchTokens();
  };

  // Both bulk actions run one token at a time on purpose. Validation puts a real request on the
  // target and refresh replays a whole login flow, so firing them in parallel is a burst of
  // authentication traffic that trips rate limiting and teaches the target what your tooling looks
  // like. Sequential is slower and stays boring.
  const validateAll = async () => {
    if (tokens.length === 0) return;
    setBulk('validate');
    setError('');
    setNotice('');
    let valid = 0;
    let bad = 0;
    for (let i = 0; i < tokens.length; i += 1) {
      setBulkProgress(`Validating ${i + 1} of ${tokens.length}: ${tokens[i].name}`);
      const out = await validateToken(tokens[i].id);
      if (statusVariant(out && out.status) === 'success') valid += 1; else bad += 1;
    }
    setBulkProgress('');
    setBulk('');
    await fetchTokens();
    setNotice(`Validated ${tokens.length} token(s): ${valid} still good, ${bad} not.`);
  };

  const staleTokens = useMemo(() => tokens.filter(isExpired), [tokens]);

  const refreshAllExpired = async () => {
    const eligible = staleTokens.filter((t) => t.auth_flow_id);
    const skipped = staleTokens.length - eligible.length;
    if (eligible.length === 0) {
      setNotice(skipped > 0
        ? `${skipped} token(s) look expired but have no auth flow linked, so there is nothing to replay. Link a flow in Manage Sessions.`
        : 'Nothing is expired. Validate first if you want a fresh verdict.');
      return;
    }
    setBulk('refresh');
    setError('');
    setNotice('');
    let ok = 0;
    for (let i = 0; i < eligible.length; i += 1) {
      setBulkProgress(`Refreshing ${i + 1} of ${eligible.length}: ${eligible[i].name}`);
      const out = await refreshToken(eligible[i].id);
      if (out && out.new_value_set) ok += 1;
    }
    setBulkProgress('');
    setBulk('');
    await fetchTokens();
    setNotice(`Replayed ${eligible.length} flow(s), ${ok} produced a new token value.`
      + (skipped > 0 ? ` ${skipped} skipped with no flow linked.` : ''));
  };

  const activeCount = tokens.filter((t) => t.is_active !== false).length;
  const anyBusy = bulk !== '' || Object.keys(rowBusy).length > 0;

  const renderResult = (id) => {
    const r = results[id];
    if (!r) return null;
    const variant = statusVariant(r.status);
    return (
      <div className="mt-2 p-2 rounded" style={{ border: '1px solid #444' }}>
        <div className="d-flex align-items-center gap-2">
          <Badge bg={variant}>{r.kind === 'refresh' ? 'refresh' : 'validate'}: {r.status || 'no status'}</Badge>
          {r.kind === 'refresh' && (
            r.new_value_set
              ? <Badge bg="success">new value stored</Badge>
              : <Badge bg="dark" className="border border-secondary text-white-50">value unchanged</Badge>
          )}
        </div>
        {r.detail && <div className="text-white small mt-1">{r.detail}</div>}
        {/* Evidence is the response the verdict was read off. A verdict with no evidence behind it
            is a verdict an operator has to take on faith, which is exactly what gets a scan run
            unauthenticated for an hour. */}
        {r.evidence && (
          <pre
            className="bg-black text-white p-2 rounded mt-2 mb-0"
            style={{ fontSize: '0.7rem', maxHeight: '180px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}
          >
            {typeof r.evidence === 'string' ? r.evidence : JSON.stringify(r.evidence, null, 2)}
          </pre>
        )}
      </div>
    );
  };

  const renderEvents = (id) => {
    const list = events[id];
    if (!list) return <div className="text-white-50 small py-2"><Spinner size="sm" animation="border" /> loading history</div>;
    if (list.length === 0) {
      return <div className="text-white-50 small fst-italic py-2">No history yet. Test validity or refresh to start one.</div>;
    }
    return (
      <Table size="sm" variant="dark" bordered className="mt-2 mb-0" style={{ fontSize: '0.72rem' }}>
        <thead>
          <tr>
            <th style={{ width: '160px' }}>When</th>
            <th style={{ width: '90px' }}>Kind</th>
            <th style={{ width: '110px' }}>Status</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {list.map((ev) => (
            <tr key={ev.id}>
              <td className="text-white-50">{whenText(ev.created_at)}</td>
              <td>{ev.kind}</td>
              <td><Badge bg={statusVariant(ev.status)}>{ev.status}</Badge></td>
              <td>
                {ev.detail}
                {ev.evidence && (
                  <pre
                    className="bg-black text-white p-1 rounded mt-1 mb-0"
                    style={{ fontSize: '0.68rem', maxHeight: '120px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}
                  >
                    {typeof ev.evidence === 'string' ? ev.evidence : JSON.stringify(ev.evidence, null, 2)}
                  </pre>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
    );
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Refresh Sessions{targetHost ? ` - ${targetHost}` : ''}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '70vh' }}>
        {!scopeTargetId ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <>
            {error && <Alert variant="danger" dismissible onClose={() => setError('')}>{error}</Alert>}
            {notice && <Alert variant="info" dismissible onClose={() => setNotice('')} className="py-2 small">{notice}</Alert>}

            <div className="d-flex flex-wrap gap-2 align-items-center mb-2">
              <Button size="sm" variant="outline-danger" onClick={validateAll} disabled={anyBusy || tokens.length === 0}>
                {bulk === 'validate' ? <Spinner size="sm" animation="border" /> : 'Validate all'}
              </Button>
              <Button size="sm" variant="outline-danger" onClick={refreshAllExpired} disabled={anyBusy || tokens.length === 0}>
                {bulk === 'refresh' ? <Spinner size="sm" animation="border" /> : `Refresh all expired (${staleTokens.length})`}
              </Button>
              <Button size="sm" variant="outline-secondary" onClick={fetchTokens} disabled={loading || anyBusy}>
                {loading ? <Spinner size="sm" animation="border" /> : 'Reload'}
              </Button>
              <span className="text-white-50 small ms-auto">
                {tokens.length} token(s), {activeCount} active
              </span>
            </div>

            {bulkProgress && (
              <div className="text-white-50 small mb-2">
                <Spinner size="sm" animation="border" className="me-2" />
                {bulkProgress}. Running one at a time so the target does not see a burst of logins.
              </div>
            )}

            {/* Said once, at the top, rather than repeated on every row. */}
            <div className="text-white-50 small mb-3">
              Active tokens are the ones every other tool attaches to its requests. Switching one off
              leaves it stored but unused, and the scans that would have used it go out unauthenticated.
            </div>

            {loading && tokens.length === 0 ? (
              <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
            ) : tokens.length === 0 ? (
              <Alert variant="warning" className="py-2 small">
                No session tokens for this target yet. Create one in Manage Sessions, or paste a raw
                cookie there, then come back to test and refresh it.
              </Alert>
            ) : (
              tokens.map((t) => {
                const stale = isExpired(t);
                const active = t.is_active !== false;
                const busyWhat = rowBusy[t.id];
                return (
                  <div key={t.id} className="bg-dark border border-secondary rounded mb-2 p-3">
                    <Row className="align-items-center g-2">
                      <Col md={3}>
                        <div className="d-flex align-items-center gap-2">
                          <Form.Check
                            type="switch"
                            id={`active-${t.id}`}
                            checked={active}
                            disabled={anyBusy}
                            onChange={() => toggleActive(t)}
                            title={active ? 'Active. Tools are sending this token.' : 'Off. Tools ignore this token.'}
                          />
                          <span className="text-truncate">
                            <span className="d-block text-truncate">{t.name}</span>
                            <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
                              {TYPE_LABEL[t.token_type] || t.token_type}
                            </span>
                          </span>
                        </div>
                      </Col>

                      <Col md={3}>
                        <div
                          className="text-info text-truncate"
                          style={{ fontFamily: 'monospace', fontSize: '0.7rem' }}
                          title={wireSummary(t)}
                        >
                          {wireSummary(t)}
                        </div>
                        <div className="text-white-50 text-truncate" style={{ fontSize: '0.68rem' }}>
                          {(t.scope_domains && t.scope_domains.length > 0)
                            ? t.scope_domains.join(', ')
                            : `${targetHost || 'target domain'} only`}
                        </div>
                      </Col>

                      <Col md={2}>
                        {/* The flow is what refresh replays, so a token without one has a dead Refresh
                            button and the row should say why before it is clicked. */}
                        {t.auth_flow_id ? (
                          <span className="text-white-50" style={{ fontSize: '0.72rem' }}>
                            flow: <span className="text-white">{t.auth_flow_name || 'linked'}</span>
                          </span>
                        ) : (
                          <span className="text-warning" style={{ fontSize: '0.72rem' }}>
                            no flow linked, cannot refresh
                          </span>
                        )}
                      </Col>

                      <Col md={2}>
                        <div className="d-flex align-items-center gap-1 flex-wrap">
                          <Badge bg={statusVariant(t.last_validation_status)}>
                            {t.last_validation_status || 'never checked'}
                          </Badge>
                          {stale && <Badge bg="danger">expired</Badge>}
                        </div>
                        <div className="text-white-50" style={{ fontSize: '0.66rem' }}>
                          checked {whenText(t.last_validated_at)}
                          {t.expires_at ? ` | expires ${whenText(t.expires_at)}` : ''}
                        </div>
                      </Col>

                      <Col md={2} className="d-flex justify-content-end gap-1 flex-wrap">
                        <Button
                          size="sm"
                          variant="outline-danger"
                          disabled={anyBusy}
                          onClick={() => validateOne(t.id)}
                          title="Sends one request with this token attached and reads the answer"
                        >
                          {busyWhat === 'validate' ? <Spinner size="sm" animation="border" /> : 'Test'}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline-danger"
                          disabled={anyBusy || !t.auth_flow_id}
                          onClick={() => refreshOne(t.id)}
                          title={t.auth_flow_id
                            ? 'Replays the linked auth flow and stores the token it issues'
                            : 'Link an auth flow in Manage Sessions to enable this'}
                        >
                          {busyWhat === 'refresh' ? <Spinner size="sm" animation="border" /> : 'Refresh'}
                        </Button>
                        <Button size="sm" variant="outline-secondary" disabled={anyBusy} onClick={() => toggleExpanded(t.id)}>
                          {expanded[t.id] ? 'Hide' : 'History'}
                        </Button>
                      </Col>
                    </Row>

                    {t.last_validation_detail && !results[t.id] && (
                      <div className="text-white-50 small mt-2">{t.last_validation_detail}</div>
                    )}

                    {renderResult(t.id)}

                    {expanded[t.id] && (
                      <div className="mt-2 border-top border-secondary pt-2">
                        <div className="d-flex justify-content-between align-items-center">
                          <span className="text-white-50 small text-uppercase">Event history</span>
                          <Button size="sm" variant="outline-secondary" disabled={anyBusy} onClick={() => loadEvents(t.id)}>
                            Reload history
                          </Button>
                        </div>
                        {renderEvents(t.id)}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
};

export default RefreshSessionModal;
