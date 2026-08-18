import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Row, Col, Button, Form, Spinner, Badge, ListGroup, Alert, Table } from 'react-bootstrap';

// Session tokens are the credentials every other tool in the framework replays. Getting one wrong
// is expensive in a way that is easy to miss: the scan still runs, it just runs unauthenticated and
// quietly reports a smaller attack surface. So this modal is built around a live preview of the
// exact bytes that go on the wire, and every other control on the screen feeds that preview.

const TOKEN_TYPES = [
  { value: 'header', label: 'Header' },
  { value: 'cookie', label: 'Cookie' },
  { value: 'api_key', label: 'API Key' },
  { value: 'bearer', label: 'Bearer' },
  { value: 'query', label: 'Query parameter' },
];

const TYPE_LABEL = TOKEN_TYPES.reduce((acc, t) => { acc[t.value] = t.label; return acc; }, {});

const FLOW_CATEGORY_LABELS = {
  register: 'Register',
  login: 'Login',
  mfa_otp: 'MFA / OTP',
  magic_link: 'Magic link',
  reset: 'Reset',
};

// Sensible starting points per type. They only fill fields that are still blank when the operator
// switches type, so flipping between Header and Bearer to compare the preview never eats a value
// that was already typed in.
const TYPE_DEFAULTS = {
  header: { header_name: 'Authorization', value_prefix: 'Bearer ' },
  bearer: { header_name: 'Authorization', value_prefix: 'Bearer ' },
  api_key: { header_name: 'X-API-Key', value_prefix: '' },
  cookie: { cookie_name: 'session', value_prefix: '' },
  query: { param_name: 'token', value_prefix: '' },
};

const SAMESITE_OPTIONS = ['', 'Lax', 'Strict', 'None'];

const EMPTY_FORM = {
  id: null,
  name: '',
  auth_flow_id: '',
  token_type: 'header',
  header_name: 'Authorization',
  cookie_name: '',
  param_name: '',
  value_prefix: 'Bearer ',
  token_value: '',
  scope_domains: [],
  cookie_path: '/',
  cookie_domain: '',
  cookie_secure: true,
  cookie_httponly: true,
  cookie_samesite: 'Lax',
  expires_at: '',
  is_active: true,
  notes: '',
};

const RAW_PASTE_PLACEHOLDER = `Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax
or
Cookie: session=abc123; csrftoken=xyz789
or
session=abc123; csrftoken=xyz789`;

function hostFromUrl(u) {
  if (!u) return '';
  try {
    return new URL(u.includes('://') ? u : `https://${u}`).host;
  } catch (_) {
    return String(u).replace(/^https?:\/\//, '').split('/')[0];
  }
}

// datetime-local speaks local wall-clock time with no zone, and the column stores an instant. Shift
// by the offset before trimming the Z form, otherwise a token set to expire at 17:00 local shows up
// in the box as whatever 17:00 UTC happens to be locally and drifts a little further every edit.
function toLocalInput(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

function fromLocalInput(local) {
  if (!local) return null;
  const d = new Date(local);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

// Build the request sketch shown in the preview panel. This is deliberately the whole first few
// lines of a request rather than just the header: the query-parameter type does not produce a
// header at all, and showing only a header would make that type look broken.
function buildWire(form, host, reveal) {
  const value = form.token_value || '';
  const shown = reveal || value.length <= 28 ? value : `${value.slice(0, 24)}...`;
  const prefix = form.value_prefix || '';
  const target = host || 'target-host';

  let requestLine = 'GET /api/me HTTP/1.1';
  let headerLine = '';
  let location = 'request header';

  switch (form.token_type) {
    case 'bearer':
      // Bearer is Header with both fields pinned, so nobody ships "authorization: bearer" or drops
      // the space after the scheme. That is the whole reason it exists as a separate type.
      headerLine = `Authorization: Bearer ${shown}`;
      break;
    case 'api_key':
      headerLine = `${form.header_name || 'X-API-Key'}: ${prefix}${shown}`;
      break;
    case 'cookie':
      headerLine = `Cookie: ${form.cookie_name || 'session'}=${shown}`;
      break;
    case 'query':
      requestLine = `GET /api/me?${form.param_name || 'token'}=${shown} HTTP/1.1`;
      location = 'query string';
      break;
    case 'header':
    default:
      headerLine = `${form.header_name || 'Authorization'}: ${prefix}${shown}`;
      break;
  }

  const lines = [requestLine, `Host: ${target}`];
  if (headerLine) lines.push(headerLine);
  return { text: lines.join('\n'), headerLine, location };
}

function validationVariant(status) {
  const s = String(status || '').toLowerCase();
  if (!s) return 'secondary';
  if (s === 'valid' || s === 'ok' || s === 'active') return 'success';
  // not_honoured is one of the four verdicts the server actually emits, and it is the most
  // actionable of them: the target answered identically with and without the credential. Leaving it
  // out made it fall through to the same grey badge as a token nobody has checked yet.
  if (s === 'expired' || s === 'not_honoured' || s === 'invalid' || s === 'unauthorized'
      || s === 'rejected' || s === 'failed') return 'danger';
  if (s === 'error' || s === 'unknown' || s === 'inconclusive') return 'warning';
  return 'secondary';
}

const ManageSessionsModal = ({ show, handleClose, scopeTargetId, scopeTargetUrl }) => {
  const [tokens, setTokens] = useState([]);
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const [form, setForm] = useState(EMPTY_FORM);
  const [domainDraft, setDomainDraft] = useState('');
  const [reveal, setReveal] = useState(false);

  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasteRaw, setPasteRaw] = useState('');
  const [pasteFlowId, setPasteFlowId] = useState('');
  const [pasteName, setPasteName] = useState('');
  const [pasteResult, setPasteResult] = useState(null);

  const targetHost = useMemo(() => hostFromUrl(scopeTargetUrl), [scopeTargetUrl]);
  const wire = useMemo(() => buildWire(form, form.scope_domains[0] || targetHost, reveal),
    [form, targetHost, reveal]);

  // A prefix that does not end in a space concatenates straight onto the value, which produces
  // "BearereyJhbGc..." and a 401 nobody can explain. The preview above already shows it, this just
  // names it so it is not read past.
  const prefixNeedsSpace = useMemo(() => {
    if (form.token_type !== 'header' && form.token_type !== 'api_key') return false;
    const p = form.value_prefix || '';
    return p.length > 0 && !p.endsWith(' ');
  }, [form.token_type, form.value_prefix]);

  const fetchTokens = useCallback(async () => {
    if (!scopeTargetId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/session-tokens/target/${scopeTargetId}`);
      const data = res.ok ? await res.json() : [];
      setTokens(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('[ManageSessions] fetchTokens failed:', e);
      setError(`Could not load session tokens: ${e.message}`);
      setTokens([]);
    } finally {
      setLoading(false);
    }
  }, [scopeTargetId]);

  const fetchFlows = useCallback(async () => {
    if (!scopeTargetId) return;
    try {
      const res = await fetch(`/api/auth-flows/${scopeTargetId}`);
      const data = res.ok ? await res.json() : [];
      setFlows(Array.isArray(data) ? data : []);
    } catch (e) {
      console.error('[ManageSessions] fetchFlows failed:', e);
      setFlows([]);
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (show && scopeTargetId) {
      fetchTokens();
      fetchFlows();
    }
    if (!show) {
      setForm(EMPTY_FORM);
      setDomainDraft('');
      setReveal(false);
      setPasteOpen(false);
      setPasteRaw('');
      setPasteResult(null);
      setError('');
      setNotice('');
    }
  }, [show, scopeTargetId, fetchTokens, fetchFlows]);

  const flowsById = useMemo(() => {
    const m = {};
    flows.forEach((f) => { m[f.id] = f; });
    return m;
  }, [flows]);

  // The list endpoint joins the flow name, but a token echoed straight back from a create call does
  // not carry it. Falling back to the locally loaded flows keeps the row from reading "unlinked"
  // for the second between saving and reloading.
  const flowNameOf = useCallback((t) => {
    if (t.auth_flow_name) return t.auth_flow_name;
    const f = flowsById[t.auth_flow_id];
    return f ? f.name : '';
  }, [flowsById]);

  const savedForForm = useMemo(
    () => (form.id ? tokens.find((t) => t.id === form.id) || null : null),
    [tokens, form.id]
  );

  const setField = (patch) => setForm((prev) => ({ ...prev, ...patch }));

  const changeType = (nextType) => {
    const defaults = TYPE_DEFAULTS[nextType] || {};
    setForm((prev) => {
      const patch = { token_type: nextType };
      // Bearer pins its wiring rather than defaulting it, and the difference is not cosmetic.
      //
      // Switching an existing API key token (header_name "X-Api-Key") to Bearer used to leave that
      // name in place because it was truthy, while the preview, the list row and the help text all
      // said "Authorization". The header-name field is hidden for this type, so the stale value was
      // invisible in the UI and the request went out as "X-Api-Key: Bearer <value>".
      if (nextType === 'bearer') {
        return { ...prev, ...patch, ...defaults };
      }
      Object.entries(defaults).forEach(([k, v]) => {
        // Only fill what is still empty. Someone comparing two types in the preview should not lose
        // the header name they just typed.
        if (!prev[k]) patch[k] = v;
      });
      return { ...prev, ...patch };
    });
  };

  const addDomain = (raw) => {
    const d = hostFromUrl(String(raw || '').trim().replace(/,$/, ''));
    if (!d) return;
    setForm((prev) => (prev.scope_domains.includes(d)
      ? prev
      : { ...prev, scope_domains: [...prev.scope_domains, d] }));
    setDomainDraft('');
  };

  const removeDomain = (d) => setForm((prev) => ({
    ...prev,
    scope_domains: prev.scope_domains.filter((x) => x !== d),
  }));

  const editToken = (t) => {
    setForm({
      id: t.id,
      name: t.name || '',
      auth_flow_id: t.auth_flow_id || '',
      token_type: t.token_type || 'header',
      header_name: t.header_name || '',
      cookie_name: t.cookie_name || '',
      param_name: t.param_name || '',
      value_prefix: t.value_prefix || '',
      token_value: t.token_value || '',
      scope_domains: Array.isArray(t.scope_domains) ? t.scope_domains : [],
      cookie_path: t.cookie_path || '',
      cookie_domain: t.cookie_domain || '',
      cookie_secure: t.cookie_secure !== false,
      cookie_httponly: t.cookie_httponly !== false,
      cookie_samesite: t.cookie_samesite || '',
      expires_at: toLocalInput(t.expires_at),
      is_active: t.is_active !== false,
      notes: t.notes || '',
    });
    setDomainDraft('');
    setReveal(false);
    setError('');
    setNotice('');
  };

  const newToken = () => {
    setForm(EMPTY_FORM);
    setDomainDraft('');
    setReveal(false);
    setError('');
    setNotice('');
  };

  const canSave = form.name.trim() !== '' && form.token_value.trim() !== '' && form.auth_flow_id !== '';

  const saveToken = async () => {
    if (!canSave || !scopeTargetId) return;
    setBusy(true);
    setError('');
    setNotice('');

    // Commit whatever is sitting in the domain box. Typing a domain and hitting Save without
    // pressing Enter first used to drop it silently, and the token then went out on every host.
    const pending = hostFromUrl(domainDraft.trim());
    const domains = pending && !form.scope_domains.includes(pending)
      ? [...form.scope_domains, pending]
      : form.scope_domains;

    const body = {
      name: form.name.trim(),
      auth_flow_id: form.auth_flow_id,
      token_type: form.token_type,
      header_name: form.header_name,
      cookie_name: form.cookie_name,
      param_name: form.param_name,
      value_prefix: form.value_prefix,
      token_value: form.token_value,
      scope_domains: domains,
      cookie_path: form.cookie_path,
      cookie_domain: form.cookie_domain,
      cookie_secure: form.cookie_secure,
      cookie_httponly: form.cookie_httponly,
      cookie_samesite: form.cookie_samesite,
      expires_at: fromLocalInput(form.expires_at),
      is_active: form.is_active,
      notes: form.notes,
    };

    try {
      const url = form.id ? `/api/session-tokens/${form.id}` : `/api/session-tokens/target/${scopeTargetId}`;
      const res = await fetch(url, {
        method: form.id ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error((await res.text()) || `Request failed (${res.status})`);
      const created = await res.json();
      await fetchTokens();
      setDomainDraft('');
      if (!form.id && created && created.id) {
        setForm((prev) => ({ ...prev, id: created.id, scope_domains: domains }));
        setNotice('Token saved. It is now available to every tool that sends authenticated requests.');
      } else {
        setForm((prev) => ({ ...prev, scope_domains: domains }));
        setNotice('Token updated.');
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const deleteToken = async (id) => {
    if (!window.confirm('Delete this session token? Tools using it will fall back to unauthenticated requests.')) return;
    setBusy(true);
    try {
      await fetch(`/api/session-tokens/${id}`, { method: 'DELETE' });
      if (form.id === id) setForm(EMPTY_FORM);
      await fetchTokens();
      setNotice('Token deleted.');
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const parseRaw = async () => {
    if (!pasteRaw.trim() || !pasteFlowId || !scopeTargetId) return;
    setBusy(true);
    setError('');
    setPasteResult(null);
    try {
      const res = await fetch(`/api/session-tokens/target/${scopeTargetId}/parse`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw: pasteRaw, auth_flow_id: pasteFlowId, name: pasteName.trim() }),
      });
      if (!res.ok) throw new Error((await res.text()) || `Parse failed (${res.status})`);
      const data = await res.json();
      const parsed = Array.isArray(data) ? data : (data.tokens || []);
      setPasteResult(parsed);
      await fetchTokens();
      if (parsed.length === 0) {
        setNotice('Nothing recognisable in that text. A Set-Cookie line, a Cookie header, or a bare name=value list all work.');
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const copyWire = async () => {
    const text = wire.headerLine || wire.text;
    try {
      await navigator.clipboard.writeText(text);
      setNotice('Copied the line above. Paste it straight into a proxy repeater tab to sanity check it.');
    } catch (_) {
      // Clipboard access is refused in some browser contexts. The line is already on screen and
      // selectable, so this is not worth an error banner.
    }
  };

  const flowOptions = useMemo(() => {
    const groups = {};
    flows.forEach((f) => {
      const key = f.category || 'other';
      if (!groups[key]) groups[key] = [];
      groups[key].push(f);
    });
    return Object.entries(groups);
  }, [flows]);

  const renderFlowSelect = (value, onChange, controlId) => (
    <Form.Select size="sm" id={controlId} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">Select the flow that issues this token</option>
      {flowOptions.map(([cat, list]) => (
        <optgroup key={cat} label={FLOW_CATEGORY_LABELS[cat] || cat}>
          {list.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}
        </optgroup>
      ))}
    </Form.Select>
  );

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Manage Sessions{targetHost ? ` - ${targetHost}` : ''}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '72vh' }}>
        {!scopeTargetId ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <>
            {error && <Alert variant="danger" dismissible onClose={() => setError('')}>{error}</Alert>}
            {notice && <Alert variant="info" dismissible onClose={() => setNotice('')} className="py-2 small">{notice}</Alert>}

            <div className="d-flex flex-wrap gap-2 align-items-center mb-3">
              <Button size="sm" variant="outline-danger" onClick={newToken} disabled={busy}>
                <i className="bi bi-plus-lg me-1" />New token
              </Button>
              <Button size="sm" variant="outline-danger" onClick={() => setPasteOpen(!pasteOpen)} disabled={busy}>
                <i className="bi bi-clipboard me-1" />Paste raw cookie
              </Button>
              <Button size="sm" variant="outline-secondary" onClick={fetchTokens} disabled={loading || busy}>
                {loading ? <Spinner size="sm" animation="border" /> : 'Refresh list'}
              </Button>
              <span className="text-white-50 small ms-auto">
                {tokens.length} token(s), {tokens.filter((t) => t.is_active !== false).length} active
              </span>
            </div>

            {flows.length === 0 && (
              <Alert variant="warning" className="py-2 small">
                No auth flows exist for this target yet. Every token has to be tied to the flow that
                issues it, so create a login flow under Authentication first, then come back here.
              </Alert>
            )}

            {pasteOpen && (
              <div className="border border-secondary rounded p-3 mb-3">
                <div className="text-white-50 small text-uppercase mb-2">Paste raw cookie</div>
                <div className="text-white-50 small mb-2">
                  Paste a <code className="text-white">Set-Cookie</code> response line, a whole{' '}
                  <code className="text-white">Cookie</code> request header, or a bare{' '}
                  <code className="text-white">a=1; b=2</code> string. Every cookie in it becomes its own
                  token, with the flags and the scope taken from the text rather than guessed.
                </div>
                <Form.Control
                  as="textarea"
                  rows={4}
                  className="mb-2"
                  style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                  placeholder={RAW_PASTE_PLACEHOLDER}
                  value={pasteRaw}
                  onChange={(e) => setPasteRaw(e.target.value)}
                />
                <Row className="g-2 mb-2">
                  <Col md={5}>
                    <Form.Label className="text-white small mb-1">Auth flow (required)</Form.Label>
                    {renderFlowSelect(pasteFlowId, setPasteFlowId, 'paste-flow')}
                  </Col>
                  <Col md={4}>
                    <Form.Label className="text-white small mb-1">Name prefix (optional)</Form.Label>
                    <Form.Control
                      size="sm"
                      placeholder="e.g. admin session"
                      value={pasteName}
                      onChange={(e) => setPasteName(e.target.value)}
                    />
                  </Col>
                  <Col md={3} className="d-flex align-items-end">
                    <Button
                      size="sm"
                      variant="danger"
                      className="w-100"
                      onClick={parseRaw}
                      disabled={busy || !pasteRaw.trim() || !pasteFlowId}
                    >
                      {busy ? <Spinner size="sm" animation="border" /> : 'Parse and create'}
                    </Button>
                  </Col>
                </Row>

                {pasteResult && pasteResult.length > 0 && (
                  <Table size="sm" variant="dark" bordered className="mb-0" style={{ fontSize: '0.75rem' }}>
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Cookie</th>
                        <th>Flags</th>
                        <th>Path</th>
                        <th>Scope</th>
                        <th>Expires</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pasteResult.map((t) => (
                        <tr key={t.id || t.cookie_name}>
                          <td>{t.name}</td>
                          <td><code className="text-white">{t.cookie_name}</code></td>
                          <td>
                            {t.cookie_secure && <Badge bg="success" className="me-1">Secure</Badge>}
                            {t.cookie_httponly && <Badge bg="success" className="me-1">HttpOnly</Badge>}
                            {t.cookie_samesite && <Badge bg="secondary">SameSite={t.cookie_samesite}</Badge>}
                            {!t.cookie_secure && !t.cookie_httponly && !t.cookie_samesite && (
                              <span className="text-white-50">none set</span>
                            )}
                          </td>
                          <td><code className="text-white">{t.cookie_path || '/'}</code></td>
                          <td>
                            {(t.scope_domains && t.scope_domains.length > 0)
                              ? t.scope_domains.join(', ')
                              : (t.cookie_domain || targetHost || 'target domain')}
                          </td>
                          <td>{t.expires_at ? new Date(t.expires_at).toLocaleString() : 'session'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                )}
              </div>
            )}

            <Row>
              {/* LEFT: saved tokens */}
              <Col md={4} className="border-end border-secondary" style={{ maxHeight: '64vh', overflowY: 'auto' }}>
                <div className="text-white-50 small text-uppercase mb-2">Saved tokens</div>
                {loading ? (
                  <div className="text-center py-3"><Spinner size="sm" animation="border" variant="danger" /></div>
                ) : tokens.length === 0 ? (
                  <div className="text-white-50 small fst-italic">
                    No session tokens yet. Create one on the right, or paste a raw cookie above.
                  </div>
                ) : (
                  <ListGroup variant="flush">
                    {tokens.map((t) => {
                      const summary = buildWire({
                        token_type: t.token_type,
                        header_name: t.header_name,
                        cookie_name: t.cookie_name,
                        param_name: t.param_name,
                        value_prefix: t.value_prefix,
                        token_value: t.token_value || '',
                      }, '', false);
                      return (
                        <ListGroup.Item
                          key={t.id}
                          action
                          active={t.id === form.id}
                          onClick={() => editToken(t)}
                          className="bg-dark text-white py-2"
                        >
                          <div className="d-flex justify-content-between align-items-center">
                            <span className="text-truncate me-2">{t.name}</span>
                            <span className="d-flex align-items-center gap-1 flex-shrink-0">
                              <Badge bg="secondary">{TYPE_LABEL[t.token_type] || t.token_type}</Badge>
                              {t.is_active !== false
                                ? <Badge bg="success">active</Badge>
                                : <Badge bg="dark" className="border border-secondary text-white-50">off</Badge>}
                              <i
                                role="button"
                                className="bi bi-trash text-danger ms-1"
                                title="Delete token"
                                onClick={(e) => { e.stopPropagation(); deleteToken(t.id); }}
                              />
                            </span>
                          </div>
                          <div
                            className="text-info text-truncate"
                            style={{ fontFamily: 'monospace', fontSize: '0.7rem' }}
                            title={summary.headerLine || summary.text}
                          >
                            {summary.headerLine || summary.text.split('\n')[0]}
                          </div>
                          <div className="text-white-50" style={{ fontSize: '0.66rem' }}>
                            {flowNameOf(t) || 'no flow linked'}
                            {t.last_validation_status ? ` | last check: ${t.last_validation_status}` : ''}
                          </div>
                        </ListGroup.Item>
                      );
                    })}
                  </ListGroup>
                )}
              </Col>

              {/* RIGHT: editor plus the wire preview */}
              <Col md={8} style={{ maxHeight: '64vh', overflowY: 'auto' }}>
                {/* The preview sits above the fields, not below them. It is the answer to the only
                    question that matters here, so it should not need scrolling to. */}
                <div className="border border-secondary rounded p-2 mb-3">
                  <div className="d-flex justify-content-between align-items-center mb-1">
                    <span className="text-white-50 small text-uppercase">How this will be sent on the wire</span>
                    <span className="d-flex align-items-center gap-2">
                      <Badge bg="secondary">{wire.location}</Badge>
                      <Form.Check
                        type="switch"
                        id="reveal-token-value"
                        className="text-white-50 small"
                        label="Show full value"
                        checked={reveal}
                        onChange={(e) => setReveal(e.target.checked)}
                      />
                      <Button size="sm" variant="outline-secondary" onClick={copyWire}>Copy</Button>
                    </span>
                  </div>
                  <pre
                    className="bg-black text-white p-2 rounded mb-1"
                    style={{ fontSize: '0.78rem', whiteSpace: 'pre-wrap', userSelect: 'text', marginBottom: 0 }}
                  >
                    {wire.text}
                  </pre>
                  {prefixNeedsSpace && (
                    <div className="text-warning" style={{ fontSize: '0.72rem' }}>
                      The prefix has no trailing space, so it runs straight into the value. Add a space
                      after it unless the target really expects them joined.
                    </div>
                  )}
                  {!form.token_value && (
                    <div className="text-white-50" style={{ fontSize: '0.72rem' }}>
                      No value yet. The preview updates as you type.
                    </div>
                  )}
                </div>

                <Row className="g-2">
                  <Col md={6}>
                    <Form.Label className="text-white small mb-1">Name</Form.Label>
                    <Form.Control
                      size="sm"
                      placeholder="e.g. admin session, low-priv user"
                      value={form.name}
                      onChange={(e) => setField({ name: e.target.value })}
                    />
                  </Col>
                  <Col md={6}>
                    <Form.Label className="text-white small mb-1">Type</Form.Label>
                    <Form.Select size="sm" value={form.token_type} onChange={(e) => changeType(e.target.value)}>
                      {TOKEN_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                    </Form.Select>
                  </Col>

                  {/* Only the fields the chosen type actually puts on the wire. Showing a cookie name
                      box next to a Bearer token invites someone to fill it in and then wonder why it
                      never appears in the preview. */}
                  {(form.token_type === 'header' || form.token_type === 'api_key') && (
                    <>
                      <Col md={6}>
                        <Form.Label className="text-white small mb-1">Header name</Form.Label>
                        <Form.Control
                          size="sm"
                          placeholder="Authorization"
                          value={form.header_name}
                          onChange={(e) => setField({ header_name: e.target.value })}
                        />
                      </Col>
                      <Col md={6}>
                        <Form.Label className="text-white small mb-1">Value prefix</Form.Label>
                        <Form.Control
                          size="sm"
                          placeholder="Bearer "
                          value={form.value_prefix}
                          onChange={(e) => setField({ value_prefix: e.target.value })}
                        />
                      </Col>
                    </>
                  )}

                  {form.token_type === 'bearer' && (
                    <Col md={12}>
                      <div className="text-white-50 small">
                        Bearer pins the header to <code className="text-white">Authorization</code> and the
                        prefix to <code className="text-white">Bearer </code>. Use the Header type instead if
                        the target wants anything else.
                      </div>
                    </Col>
                  )}

                  {form.token_type === 'cookie' && (
                    <Col md={6}>
                      <Form.Label className="text-white small mb-1">Cookie name</Form.Label>
                      <Form.Control
                        size="sm"
                        placeholder="session"
                        value={form.cookie_name}
                        onChange={(e) => setField({ cookie_name: e.target.value })}
                      />
                    </Col>
                  )}

                  {form.token_type === 'query' && (
                    <Col md={6}>
                      <Form.Label className="text-white small mb-1">Query parameter name</Form.Label>
                      <Form.Control
                        size="sm"
                        placeholder="token"
                        value={form.param_name}
                        onChange={(e) => setField({ param_name: e.target.value })}
                      />
                    </Col>
                  )}

                  <Col md={12}>
                    <Form.Label className="text-white small mb-1">Value</Form.Label>
                    <Form.Control
                      as="textarea"
                      rows={3}
                      style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                      placeholder="Paste the token exactly as the application issued it, with no prefix"
                      value={form.token_value}
                      onChange={(e) => setField({ token_value: e.target.value })}
                    />
                    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                      Leave the scheme out of this box. The prefix field adds it, so the same value can be
                      reused if the header ever changes.
                    </div>
                  </Col>

                  {/* Cookie attributes. They do not change what is sent on a request, they record what
                      the application set, which is what makes a missing Secure or HttpOnly flag
                      reportable later. */}
                  {form.token_type === 'cookie' && (
                    <>
                      <Col md={3}>
                        <Form.Label className="text-white small mb-1">Cookie path</Form.Label>
                        <Form.Control
                          size="sm"
                          placeholder="/"
                          value={form.cookie_path}
                          onChange={(e) => setField({ cookie_path: e.target.value })}
                        />
                      </Col>
                      <Col md={3}>
                        <Form.Label className="text-white small mb-1">Cookie domain</Form.Label>
                        <Form.Control
                          size="sm"
                          placeholder={targetHost || 'example.com'}
                          value={form.cookie_domain}
                          onChange={(e) => setField({ cookie_domain: e.target.value })}
                        />
                      </Col>
                      <Col md={3}>
                        <Form.Label className="text-white small mb-1">SameSite</Form.Label>
                        <Form.Select
                          size="sm"
                          value={form.cookie_samesite}
                          onChange={(e) => setField({ cookie_samesite: e.target.value })}
                        >
                          {SAMESITE_OPTIONS.map((s) => (
                            <option key={s || 'none'} value={s}>{s || 'not set'}</option>
                          ))}
                        </Form.Select>
                      </Col>
                      <Col md={3} className="d-flex align-items-end gap-3">
                        <Form.Check
                          type="switch"
                          id="cookie-secure"
                          className="text-white small"
                          label="Secure"
                          checked={form.cookie_secure}
                          onChange={(e) => setField({ cookie_secure: e.target.checked })}
                        />
                        <Form.Check
                          type="switch"
                          id="cookie-httponly"
                          className="text-white small"
                          label="HttpOnly"
                          checked={form.cookie_httponly}
                          onChange={(e) => setField({ cookie_httponly: e.target.checked })}
                        />
                      </Col>
                    </>
                  )}

                  <Col md={12}>
                    <Form.Label className="text-white small mb-1">Scoped to domains</Form.Label>
                    <div className="border border-secondary rounded p-2 d-flex flex-wrap gap-1 align-items-center">
                      {form.scope_domains.map((d) => (
                        <Badge bg="danger" key={d} className="d-flex align-items-center gap-1">
                          {d}
                          <i role="button" className="bi bi-x" title="Remove" onClick={() => removeDomain(d)} />
                        </Badge>
                      ))}
                      <Form.Control
                        size="sm"
                        className="border-0 bg-transparent text-white flex-grow-1"
                        style={{ minWidth: '160px', boxShadow: 'none' }}
                        placeholder={form.scope_domains.length === 0
                          ? `empty means ${targetHost || "the target's own domain"} only`
                          : 'add another host, then press Enter'}
                        value={domainDraft}
                        onChange={(e) => {
                          // A pasted list is common, so a comma commits the chip the same way Enter does.
                          if (e.target.value.endsWith(',')) addDomain(e.target.value);
                          else setDomainDraft(e.target.value);
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') { e.preventDefault(); addDomain(domainDraft); }
                          if (e.key === 'Backspace' && domainDraft === '' && form.scope_domains.length > 0) {
                            removeDomain(form.scope_domains[form.scope_domains.length - 1]);
                          }
                        }}
                        onBlur={() => addDomain(domainDraft)}
                      />
                    </div>
                    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                      The token is only attached to requests going to these hosts. Widening this sends your
                      session to third parties, so add a host only when you know the application does too.
                    </div>
                  </Col>

                  <Col md={6}>
                    <Form.Label className="text-white small mb-1">Auth flow (required)</Form.Label>
                    {renderFlowSelect(form.auth_flow_id, (v) => setField({ auth_flow_id: v }), 'token-flow')}
                    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                      The link is what makes this token refreshable. When it expires, Refresh replays this
                      flow and lifts the new value out of the response. A token with no flow can only ever be
                      pasted in again by hand.
                    </div>
                  </Col>
                  <Col md={3}>
                    <Form.Label className="text-white small mb-1">Expires at</Form.Label>
                    <Form.Control
                      size="sm"
                      type="datetime-local"
                      value={form.expires_at}
                      onChange={(e) => setField({ expires_at: e.target.value })}
                    />
                    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                      Optional. Drives Refresh all expired.
                    </div>
                  </Col>
                  <Col md={3} className="d-flex align-items-center">
                    <Form.Check
                      type="switch"
                      id="token-active"
                      className="text-white small mt-3"
                      label="Active"
                      checked={form.is_active}
                      onChange={(e) => setField({ is_active: e.target.checked })}
                    />
                  </Col>

                  <Col md={12}>
                    <Form.Label className="text-white small mb-1">Notes</Form.Label>
                    <Form.Control
                      size="sm"
                      placeholder="Which account this belongs to, what role it has, anything a re-read needs"
                      value={form.notes}
                      onChange={(e) => setField({ notes: e.target.value })}
                    />
                  </Col>

                  <Col md={12} className="d-flex align-items-center gap-2 mt-3">
                    <Button variant="danger" size="sm" onClick={saveToken} disabled={busy || !canSave}>
                      {busy ? <Spinner size="sm" animation="border" /> : (form.id ? 'Save changes' : 'Create token')}
                    </Button>
                    {form.id && (
                      <Button variant="outline-secondary" size="sm" onClick={newToken} disabled={busy}>
                        Cancel edit
                      </Button>
                    )}
                    {form.id && (
                      <Button variant="outline-danger" size="sm" onClick={() => deleteToken(form.id)} disabled={busy}>
                        Delete
                      </Button>
                    )}
                    {!canSave && (
                      <span className="text-white-50 small">
                        A name, a value and an auth flow are all required.
                      </span>
                    )}
                    {/* The verdict lives on the saved row rather than in the form, because the form
                        holds what is being typed and a validation result is something the server
                        measured. Read it from the list so an unsaved edit cannot appear validated. */}
                    {savedForForm && savedForForm.last_validation_status && (
                      <span className="d-flex align-items-center gap-2">
                        <Badge bg={validationVariant(savedForForm.last_validation_status)}>
                          {savedForForm.last_validation_status}
                        </Badge>
                        <span className="text-white-50 small">
                          {savedForForm.last_validated_at
                            ? `checked ${new Date(savedForForm.last_validated_at).toLocaleString()}`
                            : ''}
                          . Test and refresh live in Refresh Sessions.
                        </span>
                      </span>
                    )}
                  </Col>
                </Row>
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

export default ManageSessionsModal;
