import { useState, useEffect, useCallback, useRef } from 'react';
import { Modal, Button, Form, Spinner, Badge, ListGroup, Alert, Row, Col } from 'react-bootstrap';

// Writes an auth flow out by hand, one raw HTTP request per step, and edits flows that already
// exist.
//
// Two things make this worth its own modal. The first is that operators do not have raw requests
// lying around, they have curl commands copied out of devtools or a proxy, so a step accepts either
// and the curl is converted here rather than on the server. The second is that the replay engine
// parses a step with Go's http.ReadRequest, which is strict in ways a hand-typed request usually is
// not: a request line without "HTTP/1.1" is rejected outright, and a body with no Content-Length is
// silently read as zero bytes, which turns a login step into an empty POST that looks like the
// credentials were wrong. Both are repaired before the step is saved.

const CATEGORIES = [
  { value: 'register', label: 'Register' },
  { value: 'login', label: 'Login' },
  { value: 'mfa_otp', label: 'MFA/OTP' },
  { value: 'magic_link', label: 'Magic Link' },
  { value: 'reset', label: 'Reset' },
];

const CATEGORY_LABELS = CATEGORIES.reduce((acc, c) => ({ ...acc, [c.value]: c.label }), {});

const AUTH_TYPES = [
  { value: '', label: '(none)' },
  { value: 'password', label: 'Username / Password' },
  { value: 'magic_link', label: 'Magic Link' },
  { value: 'otp', label: 'Email / SMS OTP' },
  { value: 'oauth', label: 'OAuth 2.0' },
  { value: 'oidc', label: 'OpenID Connect' },
  { value: 'saml', label: 'SAML SSO' },
  { value: 'jwt', label: 'JWT / Bearer' },
  { value: 'api_key', label: 'API Key' },
  { value: 'session_cookie', label: 'Session Cookie' },
  { value: 'mfa', label: 'MFA / 2FA' },
];

const RAW_PLACEHOLDER = `POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"username":"user","password":"pass"}

or paste a curl command copied from devtools`;

// Matches a request line. The target has to look like a request target rather than just being the
// second word on the line: without that check, any line of prose is accepted as a request and the
// step is saved as garbage that only fails at replay time.
const REQUEST_LINE_RE = /^([A-Za-z]+)\s+((?:\/|\*|https?:\/\/)\S*)(?:\s+(HTTP\/[\d.]+))?$/;

// Long options that consume the next argument. They are listed so their value is skipped rather
// than mistaken for the bare URL: "curl -o out.html https://host/" would otherwise take out.html
// as the target.
const VALUE_FLAGS = new Set([
  '-o', '--output', '-x', '--proxy', '-m', '--max-time', '--connect-timeout', '-w', '--write-out',
  '-T', '--upload-file', '--cert', '--key', '--resolve', '--retry', '-D', '--dump-header',
  '--cacert', '--capath', '-E', '--interface', '--limit-rate', '-F', '--form', '--form-string',
  '--proto', '--max-redirs', '--cookie-jar', '-c',
]);

function byteLength(text) {
  return new TextEncoder().encode(text || '').length;
}

// Splits a shell command into argv. Quotes matter more than usual here because a copied curl
// carries the whole JSON body inside one quoted argument, and a naive split on whitespace would
// tear it into pieces.
function tokenizeCurl(input) {
  // Trailing whitespace after the continuation backslash is common in copied commands, so collapse
  // it here rather than leaving a stray backslash in the middle of the argument list.
  const text = String(input || '').replace(/\\[ \t]*\r?\n/g, ' ').replace(/\r/g, '');
  const out = [];
  let current = '';
  let quote = null;
  let quoted = false; // so an intentionally empty argument survives

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      // Only double quotes process escapes in a shell, which is how a copied command carries
      // embedded quotes inside a JSON body.
      if (ch === '\\' && quote === '"' && i + 1 < text.length) {
        current += text[i + 1];
        i += 1;
        continue;
      }
      if (ch === quote) { quote = null; continue; }
      current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; quoted = true; continue; }
    if (/\s/.test(ch)) {
      if (current || quoted) { out.push(current); current = ''; quoted = false; }
      continue;
    }
    if (ch === '\\' && i + 1 < text.length && /\s/.test(text[i + 1])) {
      // A trailing backslash that survived the continuation collapse, drop it.
      continue;
    }
    current += ch;
  }
  if (current || quoted) out.push(current);
  return out;
}

function looksLikeUrl(token) {
  if (!token) return false;
  if (/^https?:\/\//i.test(token)) return true;
  return /^[\w.-]+\.[a-z]{2,}(?::\d+)?(?:[/?#]|$)/i.test(token);
}

// Converts a curl command into the raw HTTP request the replay engine expects. Handles the flags
// that actually carry request content: -X, -H, -d and its variants, --url, -b, plus -u, -A and -e
// which are shorthands for headers. Everything else is presentational and is dropped.
function curlToRaw(input) {
  const argv = tokenizeCurl(input);
  let i = 0;
  if (argv.length && /^curl(\.exe)?$/i.test(argv[0])) i = 1;

  let method = '';
  let url = '';
  const headerArgs = [];
  const cookieArgs = [];
  const bodyParts = [];

  for (; i < argv.length; i++) {
    let token = argv[i];
    let inlineValue = null;
    if (token.startsWith('--') && token.includes('=')) {
      const eq = token.indexOf('=');
      inlineValue = token.slice(eq + 1);
      token = token.slice(0, eq);
    }
    const value = () => {
      if (inlineValue !== null) return inlineValue;
      i += 1;
      return i < argv.length ? argv[i] : '';
    };

    if (token === '-X' || token === '--request') {
      method = value().toUpperCase();
    } else if (token === '-H' || token === '--header') {
      headerArgs.push(value());
    } else if (token === '-d' || token === '--data' || token === '--data-raw'
               || token === '--data-binary' || token === '--data-ascii') {
      bodyParts.push(value());
    } else if (token === '--data-urlencode') {
      // curl encodes only the value half of name=value, so match that instead of encoding the
      // whole argument and corrupting the separator.
      const raw = value();
      const eq = raw.indexOf('=');
      bodyParts.push(eq > 0
        ? `${raw.slice(0, eq)}=${encodeURIComponent(raw.slice(eq + 1))}`
        : encodeURIComponent(raw));
    } else if (token === '--url') {
      url = value();
    } else if (token === '-b' || token === '--cookie') {
      cookieArgs.push(value());
    } else if (token === '-A' || token === '--user-agent') {
      headerArgs.push(`User-Agent: ${value()}`);
    } else if (token === '-e' || token === '--referer') {
      headerArgs.push(`Referer: ${value()}`);
    } else if (token === '-u' || token === '--user') {
      headerArgs.push(`Authorization: Basic ${btoa(value())}`);
    } else if (VALUE_FLAGS.has(token)) {
      value(); // consumed and discarded, see VALUE_FLAGS
    } else if (token.startsWith('-')) {
      // Switches such as -k, -s, -i, -L and --compressed change how curl behaves, not what is sent.
    } else if (!url && looksLikeUrl(token)) {
      url = token;
    }
  }

  if (!url) throw new Error('no URL found in the curl command');
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;

  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    throw new Error(`could not parse the URL ${url}`);
  }

  const body = bodyParts.join('&');
  if (!method) method = body ? 'POST' : 'GET';

  const cookies = cookieArgs.filter(Boolean);
  const headers = [];
  let hasContentType = false;
  headerArgs.forEach((h) => {
    const eq = h.indexOf(':');
    if (eq < 0) return;
    const name = h.slice(0, eq).trim();
    const lower = name.toLowerCase();
    // Host and Content-Length are derived from the URL and the body below. Keeping the copied ones
    // is how a request ends up claiming a length that does not match what it carries.
    // Accept-Encoding goes with Host and Content-Length. The replay client negotiates compression
    // itself, and asking for a codec it then fails to decode turns a readable response into binary
    // noise in response_body. captureBridgeUtils.go, background.js and ManualCrawlResultsModal.js
    // all strip it for the same reason.
    if (lower === 'host' || lower === 'content-length' || lower === 'accept-encoding') return;
    if (lower === 'cookie') { cookies.push(h.slice(eq + 1).trim()); return; }
    if (lower === 'content-type') hasContentType = true;
    headers.push(`${name}: ${h.slice(eq + 1).trim()}`);
  });

  if (cookies.length) headers.push(`Cookie: ${cookies.join('; ')}`);
  // curl's own default for -d, and the wrong one to leave out: many login endpoints reject a body
  // sent with no content type.
  if (body && !hasContentType) headers.push('Content-Type: application/x-www-form-urlencoded');
  if (body) headers.push(`Content-Length: ${byteLength(body)}`);

  const target = `${parsed.pathname || '/'}${parsed.search || ''}`;
  const lines = [`${method} ${target} HTTP/1.1`, `Host: ${parsed.host}`, ...headers];
  return `${lines.join('\n')}\n\n${body}`;
}

// Splits a pasted raw request into its three parts. The header block ends at the first blank line,
// which is also how the parser on the server sees it.
function splitRaw(text) {
  const lines = String(text || '').replace(/\r\n/g, '\n').split('\n');
  const requestLine = (lines.shift() || '').trim();
  const headers = [];
  let idx = 0;
  while (idx < lines.length && lines[idx].trim() !== '') {
    headers.push(lines[idx]);
    idx += 1;
  }
  const body = lines.slice(idx + 1).join('\n');
  return { requestLine, headers, body };
}

function detectFormat(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed) return 'empty';
  if (/^curl(\.exe)?\b/i.test(trimmed)) return 'curl';
  const first = trimmed.split('\n')[0].trim();
  if (REQUEST_LINE_RE.test(first)) return 'raw';
  return 'unknown';
}

// Repairs the two things that make a hand-typed request fail on replay for reasons that look like
// the target's fault rather than the request's.
function normalizeRaw(text) {
  const { requestLine, headers, body } = splitRaw(text);
  const match = REQUEST_LINE_RE.exec(requestLine);
  if (!match) throw new Error(`request line is not "METHOD /path HTTP/1.1": ${requestLine}`);

  const fixedLine = `${match[1].toUpperCase()} ${match[2]} ${match[3] || 'HTTP/1.1'}`;
  const kept = headers.filter((h) => !/^(content-length|accept-encoding):/i.test(h));
  const chunked = headers.some((h) => /^transfer-encoding:/i.test(h));
  if (body.length > 0 && !chunked) kept.push(`Content-Length: ${byteLength(body)}`);

  return `${[fixedLine, ...kept].join('\n')}\n\n${body}`;
}

// What the operator is told before saving. These are warnings rather than blockers because the
// conversion fixes them anyway, but seeing why the text changed beats being surprised by it.
function lintRaw(text) {
  const notes = [];
  const format = detectFormat(text);
  if (format !== 'raw') return notes;
  const { requestLine, headers, body } = splitRaw(text);
  const match = REQUEST_LINE_RE.exec(requestLine);
  if (match && !match[3]) notes.push('No HTTP version on the request line, HTTP/1.1 will be added.');
  if (body.length > 0 && !headers.some((h) => /^content-length:/i.test(h))
      && !headers.some((h) => /^transfer-encoding:/i.test(h))) {
    notes.push('Body with no Content-Length, one will be added so the body is actually sent.');
  }
  if (!headers.some((h) => /^host:/i.test(h))) {
    notes.push('No Host header, the flow base URL decides where this is sent.');
  }
  return notes;
}

// One conversion path for both formats, so what is stored is always raw HTTP. The curl text itself
// is never persisted: the replay engine does not speak it.
function toRawRequest(text) {
  return detectFormat(text) === 'curl' ? curlToRaw(text) : normalizeRaw(text);
}

const ManualAuthFlowModal = ({ show, handleClose, scopeTargetId, scopeTargetUrl }) => {
  const [flows, setFlows] = useState([]);
  const [loadingFlows, setLoadingFlows] = useState(false);
  const [editingId, setEditingId] = useState(null); // null means a flow that does not exist yet
  const [form, setForm] = useState({ name: '', category: 'login', base_url: '', description: '', auth_type: '' });
  const [steps, setSteps] = useState([]);
  const [removedStepIds, setRemovedStepIds] = useState([]);
  const [replayOnSave, setReplayOnSave] = useState(false);
  const [previewKey, setPreviewKey] = useState(null);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  // Step rows need a stable identity for React while they are unsaved and reorderable, and the
  // server id cannot provide it.
  const keyCounter = useRef(0);
  const newStep = (overrides = {}) => {
    keyCounter.current += 1;
    return { key: `s${keyCounter.current}`, id: null, name: '', text: '', ...overrides };
  };

  const resetToNew = useCallback(() => {
    setEditingId(null);
    setForm({ name: '', category: 'login', base_url: scopeTargetUrl || '', description: '', auth_type: '' });
    setSteps([newStep()]);
    setRemovedStepIds([]);
    setPreviewKey(null);
    setError('');
  }, [scopeTargetUrl]); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchFlows = useCallback(async () => {
    if (!scopeTargetId) return;
    setLoadingFlows(true);
    try {
      const res = await fetch(`/api/auth-flows/${scopeTargetId}`);
      const data = res.ok ? await res.json() : [];
      setFlows(Array.isArray(data) ? data : []);
      if (!res.ok) setError(`Could not load existing flows (${res.status})`);
    } catch (e) {
      setError('Could not reach the framework: ' + e.message);
    } finally {
      setLoadingFlows(false);
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (!show) return;
    fetchFlows();
    resetToNew();
    setNotice('');
  }, [show, fetchFlows, resetToNew]);

  const loadFlowForEdit = async (flow) => {
    setError('');
    setNotice('');
    setEditingId(flow.id);
    setForm({
      name: flow.name || '',
      category: flow.category || 'login',
      base_url: flow.base_url || '',
      description: flow.description || '',
      auth_type: flow.auth_type || '',
    });
    setRemovedStepIds([]);
    setPreviewKey(null);
    try {
      const res = await fetch(`/api/auth-flows/flow/${flow.id}/steps`);
      const data = res.ok ? await res.json() : [];
      const list = Array.isArray(data) ? data : [];
      setSteps(list.length
        ? list.map((s) => newStep({ id: s.id, name: s.name || '', text: s.raw_request || '' }))
        : [newStep()]);
    } catch (e) {
      setSteps([newStep()]);
      setError('Could not load the flow steps: ' + e.message);
    }
  };

  const updateStep = (key, patch) => {
    setSteps((prev) => prev.map((s) => (s.key === key ? { ...s, ...patch } : s)));
  };

  const moveStep = (index, delta) => {
    setSteps((prev) => {
      const target = index + delta;
      if (target < 0 || target >= prev.length) return prev;
      const next = [...prev];
      const [moved] = next.splice(index, 1);
      next.splice(target, 0, moved);
      return next;
    });
  };

  const removeStep = (key) => {
    setSteps((prev) => {
      const victim = prev.find((s) => s.key === key);
      // A step that exists on the server has to be deleted there too, and only on save, so a
      // removal can still be abandoned by closing the modal.
      if (victim && victim.id) setRemovedStepIds((ids) => [...ids, victim.id]);
      const next = prev.filter((s) => s.key !== key);
      return next.length ? next : [newStep()];
    });
    if (previewKey === key) setPreviewKey(null);
  };

  const deleteFlow = async (flowId) => {
    if (!window.confirm('Delete this auth flow and all of its steps?')) return;
    try {
      const res = await fetch(`/api/auth-flows/flow/${flowId}`, { method: 'DELETE' });
      if (!res.ok) { setError(`Could not delete the flow (${res.status})`); return; }
      if (editingId === flowId) resetToNew();
      await fetchFlows();
      setNotice('Flow deleted.');
    } catch (e) {
      setError('Could not delete the flow: ' + e.message);
    }
  };

  const save = async () => {
    if (!scopeTargetId) return;
    setError('');
    setNotice('');

    if (!form.name.trim()) { setError('Give the flow a name.'); return; }

    // Convert every step before writing anything. A half-saved flow with one bad step is worse
    // than a flow that refused to save, because the bad step is the one nobody notices.
    const filled = steps.filter((s) => s.text.trim());
    if (filled.length === 0) { setError('Add at least one step with a request in it.'); return; }

    const converted = [];
    for (let i = 0; i < filled.length; i++) {
      try {
        converted.push({ ...filled[i], raw: toRawRequest(filled[i].text) });
      } catch (e) {
        setError(`Step ${i + 1} could not be converted: ${e.message}`);
        return;
      }
    }

    setSaving(true);
    try {
      let flowId = editingId;
      const payload = {
        category: form.category,
        name: form.name.trim(),
        description: form.description,
        auth_type: form.auth_type,
        base_url: form.base_url.trim(),
      };

      if (flowId) {
        const res = await fetch(`/api/auth-flows/flow/${flowId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!res.ok) { setError((await res.text()) || `Could not update the flow (${res.status})`); return; }
      } else {
        const res = await fetch(`/api/auth-flows/${scopeTargetId}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!res.ok) { setError((await res.text()) || `Could not create the flow (${res.status})`); return; }
        const created = await res.json();
        flowId = created.id;
      }

      for (const id of removedStepIds) {
        await fetch(`/api/auth-flows/steps/${id}`, { method: 'DELETE' });
      }

      for (let i = 0; i < converted.length; i++) {
        const step = converted[i];
        const order = i + 1;
        if (step.id) {
          await fetch(`/api/auth-flows/steps/${step.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: step.name, raw_request: step.raw, step_order: order }),
          });
        } else {
          const res = await fetch(`/api/auth-flows/flow/${flowId}/steps`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: step.name, raw_request: step.raw, replay: replayOnSave }),
          });
          if (res.ok) {
            // A new step is appended at the end by the server. When it was inserted in the middle
            // of the list, its order has to be corrected or the flow replays out of sequence.
            const createdStep = await res.json();
            if (createdStep && createdStep.id && createdStep.step_order !== order) {
              await fetch(`/api/auth-flows/steps/${createdStep.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ step_order: order }),
              });
            }
          }
        }
      }

      await fetchFlows();
      // Reload from the server so every row carries its real id, otherwise a second save would
      // create duplicates of the steps just written.
      await loadFlowForEdit({ id: flowId, ...payload });
      setNotice(`Saved ${converted.length} step(s).${replayOnSave ? ' Each new step was sent as it was saved.' : ''}`);
    } catch (e) {
      setError('Save failed: ' + e.message);
    } finally {
      setSaving(false);
    }
  };

  const previewStep = steps.find((s) => s.key === previewKey) || null;
  let previewText = '';
  if (previewStep) {
    try {
      previewText = toRawRequest(previewStep.text);
    } catch (e) {
      previewText = `Could not convert this step: ${e.message}`;
    }
  }

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-pencil-square me-2" />
          Manual Auth Flow
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '70vh' }}>
        {!scopeTargetId ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <Row>
            {/* LEFT: existing flows, so this modal edits as well as creates */}
            <Col md={4} className="border-end border-secondary">
              <div className="d-flex justify-content-between align-items-center mb-2">
                <span className="text-white-50 small text-uppercase">Existing flows</span>
                <Button size="sm" variant="outline-secondary" onClick={fetchFlows} disabled={loadingFlows}>
                  {loadingFlows ? <Spinner size="sm" animation="border" /> : 'Refresh'}
                </Button>
              </div>
              <Button variant="outline-danger" size="sm" className="w-100 mb-3" onClick={resetToNew}>
                <i className="bi bi-plus-lg me-1" />New Flow
              </Button>

              {loadingFlows ? (
                <div className="text-center py-3"><Spinner animation="border" variant="danger" /></div>
              ) : flows.length === 0 ? (
                <div className="text-white-50 small fst-italic">
                  No auth flows yet. Fill in the form and add the requests that make up the flow.
                </div>
              ) : (
                <ListGroup variant="flush" style={{ maxHeight: '58vh', overflowY: 'auto' }}>
                  {flows.map((f) => (
                    <ListGroup.Item
                      key={f.id}
                      action
                      active={editingId === f.id}
                      onClick={() => loadFlowForEdit(f)}
                      className="bg-dark text-white border-secondary"
                    >
                      <div className="d-flex align-items-center gap-2">
                        <span className="text-truncate flex-grow-1">{f.name}</span>
                        <Badge bg="secondary">{f.step_count || 0}</Badge>
                        <i
                          role="button"
                          className="bi bi-trash text-danger"
                          title="Delete flow"
                          onClick={(e) => { e.stopPropagation(); deleteFlow(f.id); }}
                        />
                      </div>
                      <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                        {CATEGORY_LABELS[f.category] || f.category}
                        {f.auth_type ? ` · ${f.auth_type}` : ''}
                      </div>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              )}
            </Col>

            {/* RIGHT: the editor */}
            <Col md={8}>
              {error && <Alert variant="danger" dismissible onClose={() => setError('')} className="py-2">{error}</Alert>}
              {notice && <Alert variant="info" dismissible onClose={() => setNotice('')} className="py-2 small">{notice}</Alert>}

              <Row className="g-2 mb-3">
                <Col md={6}>
                  <Form.Label className="text-white small mb-1">Flow name</Form.Label>
                  <Form.Control
                    size="sm"
                    className="bg-dark text-white border-secondary"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    placeholder="Password login"
                  />
                </Col>
                <Col md={3}>
                  <Form.Label className="text-white small mb-1">Category</Form.Label>
                  <Form.Select
                    size="sm"
                    className="bg-dark text-white border-secondary"
                    value={form.category}
                    onChange={(e) => setForm({ ...form, category: e.target.value })}
                  >
                    {CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                  </Form.Select>
                </Col>
                <Col md={3}>
                  <Form.Label className="text-white small mb-1">Auth type</Form.Label>
                  <Form.Select
                    size="sm"
                    className="bg-dark text-white border-secondary"
                    value={form.auth_type}
                    onChange={(e) => setForm({ ...form, auth_type: e.target.value })}
                  >
                    {AUTH_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </Form.Select>
                </Col>
                <Col md={6}>
                  <Form.Label className="text-white small mb-1">Base URL</Form.Label>
                  <Form.Control
                    size="sm"
                    className="bg-dark text-white border-secondary"
                    value={form.base_url}
                    onChange={(e) => setForm({ ...form, base_url: e.target.value })}
                    placeholder={scopeTargetUrl || 'https://example.com'}
                  />
                  <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                    Where the steps are sent. Left empty, each step goes to its own Host header.
                  </div>
                </Col>
                <Col md={6}>
                  <Form.Label className="text-white small mb-1">Description</Form.Label>
                  <Form.Control
                    size="sm"
                    className="bg-dark text-white border-secondary"
                    value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                    placeholder="What this flow proves, and which account it uses"
                  />
                </Col>
              </Row>

              <div className="d-flex justify-content-between align-items-center mb-2">
                <span className="text-white-50 small text-uppercase">
                  Steps {editingId ? '(editing an existing flow)' : '(new flow)'}
                </span>
                <div className="d-flex align-items-center gap-3">
                  {/* Off by default: a flow being typed out is usually incomplete, and sending step
                      three before step two exists returns a failure that says nothing about the
                      target. Replay the finished flow in one go from the Auth Flows view instead. */}
                  <Form.Check
                    type="switch"
                    id="replay-on-save"
                    className="text-white-50 small"
                    label="Send each new step as it is saved"
                    checked={replayOnSave}
                    onChange={(e) => setReplayOnSave(e.target.checked)}
                  />
                  <Button size="sm" variant="outline-danger" onClick={() => setSteps((prev) => [...prev, newStep()])}>
                    <i className="bi bi-plus-lg me-1" />Add Step
                  </Button>
                </div>
              </div>

              <div style={{ maxHeight: '42vh', overflowY: 'auto' }}>
                {steps.map((step, index) => {
                  const format = detectFormat(step.text);
                  const notes = lintRaw(step.text);
                  return (
                    <div key={step.key} className="border border-secondary rounded p-2 mb-2">
                      <div className="d-flex align-items-center gap-2 mb-2">
                        <Badge bg="secondary">{index + 1}</Badge>
                        <Form.Control
                          size="sm"
                          className="bg-dark text-white border-secondary"
                          style={{ maxWidth: '260px' }}
                          placeholder="Step name (optional)"
                          value={step.name}
                          onChange={(e) => updateStep(step.key, { name: e.target.value })}
                        />
                        {format === 'curl' && <Badge bg="info">curl, converted on save</Badge>}
                        {format === 'raw' && <Badge bg="success">raw HTTP request</Badge>}
                        {format === 'unknown' && <Badge bg="warning" text="dark">not recognised</Badge>}
                        <div className="ms-auto d-flex gap-1">
                          <Button size="sm" variant="outline-secondary" title="Move up"
                            onClick={() => moveStep(index, -1)} disabled={index === 0}>
                            <i className="bi bi-arrow-up" />
                          </Button>
                          <Button size="sm" variant="outline-secondary" title="Move down"
                            onClick={() => moveStep(index, 1)} disabled={index === steps.length - 1}>
                            <i className="bi bi-arrow-down" />
                          </Button>
                          <Button size="sm" variant="outline-secondary" title="Preview the raw request that will be saved"
                            onClick={() => setPreviewKey(previewKey === step.key ? null : step.key)}
                            disabled={!step.text.trim()}>
                            <i className="bi bi-eye" />
                          </Button>
                          <Button size="sm" variant="outline-danger" title="Remove step"
                            onClick={() => removeStep(step.key)}>
                            <i className="bi bi-trash" />
                          </Button>
                        </div>
                      </div>
                      <Form.Control
                        as="textarea"
                        rows={7}
                        className="bg-dark text-white border-secondary"
                        style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                        placeholder={RAW_PLACEHOLDER}
                        value={step.text}
                        onChange={(e) => updateStep(step.key, { text: e.target.value })}
                      />
                      {format === 'unknown' && step.text.trim() && (
                        <div className="text-warning" style={{ fontSize: '0.7rem' }}>
                          This is neither a curl command nor a request line like "POST /login HTTP/1.1". It will be
                          rejected on save.
                        </div>
                      )}
                      {notes.map((n, ni) => (
                        <div key={ni} className="text-white-50" style={{ fontSize: '0.7rem' }}>{n}</div>
                      ))}
                    </div>
                  );
                })}
              </div>

              {previewStep && (
                <>
                  <div className="text-white-50 small text-uppercase mt-2 mb-1">
                    What will be stored for this step
                  </div>
                  <pre
                    className="bg-black text-white p-2 rounded"
                    style={{ fontSize: '0.72rem', maxHeight: '20vh', overflowY: 'auto', whiteSpace: 'pre-wrap' }}
                  >
                    {previewText}
                  </pre>
                </>
              )}
            </Col>
          </Row>
        )}
      </Modal.Body>
      <Modal.Footer>
        <span className="text-white-50 small me-auto">
          Steps are stored as raw HTTP. A curl command is converted first, so what runs is exactly what is shown in
          the preview.
        </span>
        <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
        <Button variant="danger" onClick={save} disabled={saving || !scopeTargetId}>
          {saving ? <Spinner size="sm" animation="border" /> : (editingId ? 'Save Changes' : 'Create Flow')}
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ManualAuthFlowModal;
