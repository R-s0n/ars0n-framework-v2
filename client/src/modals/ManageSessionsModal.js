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
  // What the row holds. A new token has none of the three, which is what makes the value box
  // required for it and optional on an edit.
  has_value: false,
  value_fingerprint: '',
  value_length: 0,
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

// storedCredentialSummary identifies the credential the row holds.
//
// A row with a credential and a row with none MUST NOT READ THE SAME: "no value stored" is why a
// scan on this target is going out unauthenticated, and it has the opposite fix to a row whose
// credential is fine. The fingerprint and the length are how two long opaque strings are told
// apart at a glance; the value itself is in the box and in the preview above it.
export function storedCredentialSummary(row) {
  if (!row || row.has_value !== true) return 'No value stored on this row.';
  const fingerprint = row.value_fingerprint && row.value_fingerprint !== 'none'
    ? row.value_fingerprint : 'unknown';
  const length = Number(row.value_length);
  const size = Number.isFinite(length) && length > 0 ? `, ${length} bytes` : '';
  return `A credential is stored: fingerprint ${fingerprint}${size}.`;
}

// credentialForWire is the credential, or a word saying there is not one. An absence is a fact the
// operator has to act on; it is not the value being withheld.
function credentialForWire(row) {
  if (row && row.token_value) return row.token_value;
  return row && row.has_value === true ? '<the stored credential>' : '<no value stored>';
}

// Build the request sketch shown in the preview panel. This is deliberately the whole first few
// lines of a request rather than just the header: the query-parameter type does not produce a
// header at all, and showing only a header would make that type look broken.
//
// THE CREDENTIAL IS IN IT, IN FULL. The preview is the exact bytes that go on the wire, which is
// what makes it worth copying into a repeater tab and what makes a captured credential provable.
// It draws whatever the box holds: the value the list served for a stored token, or the one the
// operator is part way through typing over it.
export function buildWire(form, host) {
  const shown = credentialForWire(form);
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
  // A companion is a routing cookie, not a credential, so it is never graded honoured or not. It
  // gets its own colour because the grey fallback reads as "nobody has checked this yet", and this
  // one has been checked: the answer is that the question does not apply.
  if (s === 'companion') return 'info';
  // not_honoured is one of the four verdicts the server actually emits, and it is the most
  // actionable of them: the target answered identically with and without the credential. Leaving it
  // out made it fall through to the same grey badge as a token nobody has checked yet.
  if (s === 'expired' || s === 'not_honoured' || s === 'invalid' || s === 'unauthorized'
      || s === 'rejected' || s === 'failed') return 'danger';
  if (s === 'error' || s === 'unknown' || s === 'inconclusive') return 'warning';
  return 'secondary';
}

// The verdicts that mean the target refused the token, matching RefreshSessionModal and the server's
// sessionTokenRejectedStatuses. A companion is deliberately absent: it is a routing cookie, never
// graded on its own, so it must not read as expired.
const REJECTED_STATUSES = new Set(['expired', 'not_honoured', 'invalid', 'unauthorized', 'rejected', 'failed', 'revoked']);

// keeperStatusVariant maps a session keeper's lifecycle state to a Bootstrap badge colour.
function keeperStatusVariant(status) {
  switch (status) {
    case 'live': return 'success';
    case 'needs_recapture': return 'warning';
    case 'error': return 'danger';
    case 'stopped': return 'secondary';
    default: return 'info'; // pending / seeding
  }
}

// isTokenExpired: the token's own clock has passed, or its last validation verdict was a rejection.
// This is the check Manage Sessions was missing, so an on-but-dead token read as a green "active".
function isTokenExpired(t) {
  if (t.expires_at) {
    const exp = new Date(t.expires_at).getTime();
    if (!Number.isNaN(exp) && exp <= Date.now()) return true;
  }
  return REJECTED_STATUSES.has(String(t.last_validation_status || '').toLowerCase());
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

  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasteRaw, setPasteRaw] = useState('');
  const [pasteFlowId, setPasteFlowId] = useState('');
  const [pasteName, setPasteName] = useState('');
  const [pasteResult, setPasteResult] = useState(null);

  // Durable session keepers: a framework-run headless browser that holds the IdP session and keeps
  // the bearer fresh on a loop so a short-lived token stops forcing a manual paste.
  const [keepers, setKeepers] = useState([]);
  const [keeperForm, setKeeperForm] = useState({ name: '', target_url: '', cadence_seconds: 600 });

  const targetHost = useMemo(() => hostFromUrl(scopeTargetUrl), [scopeTargetUrl]);
  const expiredActiveCount = useMemo(
    // Mirror the per-row "expired" badge, which excludes refresh secrets (a refresh token is not graded
    // as a credential), so the header count and the visible badges agree.
    () => tokens.filter((t) => t.is_active !== false && t.token_role !== 'refresh' && isTokenExpired(t)).length,
    [tokens],
  );
  const wire = useMemo(() => buildWire(form, form.scope_domains[0] || targetHost),
    [form, targetHost]);

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

  const fetchKeepers = useCallback(async () => {
    if (!scopeTargetId) return;
    try {
      const res = await fetch(`/api/session-keepers/target/${scopeTargetId}`);
      const data = res.ok ? await res.json() : {};
      setKeepers(Array.isArray(data.keepers) ? data.keepers : []);
    } catch (e) {
      console.error('[ManageSessions] fetchKeepers failed:', e);
      setKeepers([]);
    }
  }, [scopeTargetId]);

  const createKeeper = useCallback(async () => {
    if (!scopeTargetId) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/session-keepers/target/${scopeTargetId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: keeperForm.name.trim() || 'default',
          target_url: keeperForm.target_url.trim(),
          cadence_seconds: Number(keeperForm.cadence_seconds) || 600,
        }),
      });
      if (!res.ok) throw new Error(`framework returned ${res.status}`);
      setNotice('Session keeper created. It will hold the session and keep the bearer fresh.');
      setKeeperForm({ name: '', target_url: '', cadence_seconds: 600 });
      await fetchKeepers();
    } catch (e) {
      setError(`Could not create the keeper: ${e.message}`);
    } finally {
      setBusy(false);
    }
  }, [scopeTargetId, keeperForm, fetchKeepers]);

  const keeperAction = useCallback(async (id, action) => {
    setBusy(true);
    try {
      const method = action === 'delete' ? 'DELETE' : 'POST';
      const path = action === 'delete' ? `/api/session-keepers/${id}` : `/api/session-keepers/${id}/${action}`;
      const res = await fetch(path, { method });
      if (!res.ok) throw new Error(`framework returned ${res.status}`);
      if (action === 'adopt-cookies') {
        const data = await res.json().catch(() => ({}));
        setNotice(`Claimed ${data.claimed ?? 0} untagged cookie(s) for keeper "${data.account}" (now owns ${data.owned ?? 0}). The keeper will seed only these on its next reload.`);
      }
      await fetchKeepers();
      await fetchTokens();
    } catch (e) {
      setError(`Keeper ${action} failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  }, [fetchKeepers, fetchTokens]);

  useEffect(() => {
    if (show && scopeTargetId) {
      fetchTokens();
      fetchFlows();
      fetchKeepers();
    }
    if (!show) {
      setForm(EMPTY_FORM);
      setDomainDraft('');
      setPasteOpen(false);
      setPasteRaw('');
      setPasteFlowId('');
      setPasteName('');
      setPasteResult(null);
      setError('');
      setNotice('');
      setKeeperForm({ name: '', target_url: '', cadence_seconds: 600 });
    }
  }, [show, scopeTargetId, fetchTokens, fetchFlows, fetchKeepers]);

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
      // THE STORED CREDENTIAL, as the list serves it. The box shows what is there, so the operator
      // can read it, copy it and correct it, and a Save writes back exactly what it was given.
      // Emptying the box means "leave the stored credential alone", because the PUT then omits the
      // key entirely.
      token_value: t.token_value || '',
      has_value: t.has_value === true,
      value_fingerprint: t.value_fingerprint || '',
      value_length: Number(t.value_length) || 0,
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
    setError('');
    setNotice('');
  };

  const newToken = () => {
    setForm(EMPTY_FORM);
    setDomainDraft('');
    setError('');
    setNotice('');
  };

  // A NEW token needs a credential typed in; an EXISTING one already has one and the box is a
  // replace-it box. Requiring the value on an edit is what would force an operator to paste a live
  // credential into the browser to change a cookie path.
  //
  // The auth flow is NOT required. It enables replay-based refresh, but a session from an OAuth or
  // federated login has no replayable flow to link, and forcing one there would block storing the
  // session at all. A token with no flow is refreshed by pasting a fresh value instead, which the
  // refresh screen already handles ("no flow linked, cannot refresh").
  const canSave = form.name.trim() !== ''
    && (form.token_value.trim() !== '' || form.has_value === true);

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
    // THE KEY IS OMITTED, NOT SENT EMPTY. Every field of the server's write payload is a pointer
    // so that an update can tell "leave this alone" from "set this to empty", and blanking a
    // credential because the operator edited a cookie path is precisely the case that distinction
    // exists for. A typed value replaces the stored one; an empty box changes nothing.
    if (form.token_value.trim() !== '') {
      body.token_value = form.token_value;
    }

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
        // has_value is set because a create always carries a value (canSave requires it), and the POST
        // response is only {id}. Without this the row summary reads "No value stored" right after a
        // successful save while the value sits in the box.
        setForm((prev) => ({ ...prev, id: created.id, scope_domains: domains, has_value: true }));
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
    setError('');
    try {
      const res = await fetch(`/api/session-tokens/${id}`, { method: 'DELETE' });
      if (!res.ok && res.status !== 404) throw new Error((await res.text()) || `Delete failed (${res.status})`);
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
    // The flow is optional: pasting a fresh cookie is exactly how a session with no replayable flow
    // (an OAuth or federated login) is refreshed, so requiring a flow here would block that path.
    if (!pasteRaw.trim() || !scopeTargetId) return;
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
      <option value="">No flow (refresh by re-pasting a fresh value)</option>
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

            <div className="border border-secondary rounded p-2 mb-3" style={{ background: 'rgba(13,202,240,0.06)' }}>
              <div className="d-flex align-items-center mb-2">
                <strong className="text-info"><i className="bi bi-arrow-repeat me-1" />Session keepers</strong>
                <span className="text-white-50 small ms-2">a headless browser that keeps a short-lived bearer fresh, hands-free</span>
                <Button size="sm" variant="outline-secondary" className="ms-auto py-0 px-2" onClick={fetchKeepers} disabled={busy}>Refresh</Button>
              </div>
              <Alert variant="warning" className="py-1 px-2 small mb-2">
                A keeper holds your IdP session in a framework-run browser, including a long-lived refresh cookie that is an
                account-takeover credential for your own test account. It is stored like all captured material (not encrypted),
                and its egress is locked to the in-scope app plus classified auth hosts only. Capture the session cookies first
                (New token / Paste raw cookie); the keeper seeds from them and parks as <em>needs_recapture</em> when the IdP
                session finally dies. <strong>Two accounts (A and B) for one target:</strong> capture A, add keeper "A", click
                <em>Adopt cookies</em>; then capture B, add keeper "B", <em>Adopt cookies</em> again. Each keeper then seeds only
                its own account, so their sessions never collide. A single account needs no tagging.
              </Alert>
              {keepers.length > 0 && (
                <Table size="sm" variant="dark" bordered className="mb-2" style={{ fontSize: '0.75rem' }}>
                  <thead><tr><th>Account</th><th>Status</th><th>Last harvest</th><th>Target</th><th /></tr></thead>
                  <tbody>
                    {keepers.map((k) => (
                      <tr key={k.id}>
                        <td>{k.name}</td>
                        <td>
                          <Badge bg={keeperStatusVariant(k.status)}>{k.status}</Badge>
                          {!k.enabled && <Badge bg="secondary" className="ms-1">off</Badge>}
                          {k.last_error && <i className="bi bi-exclamation-triangle text-warning ms-1" title={k.last_error} />}
                        </td>
                        <td className="text-white-50">{k.last_harvest_at ? new Date(k.last_harvest_at).toLocaleTimeString() : 'none yet'}</td>
                        <td className="text-truncate" style={{ maxWidth: 160 }} title={k.target_url}>{hostFromUrl(k.target_url) || k.target_url}</td>
                        <td className="text-end" style={{ whiteSpace: 'nowrap' }}>
                          <Button size="sm" variant="outline-light" className="py-0 px-1 me-1" disabled={busy}
                            title="Claim the target's currently-untagged cookies for this account, so this keeper seeds only them. Do this right after capturing the session for this account."
                            onClick={() => keeperAction(k.id, 'adopt-cookies')}>Adopt cookies</Button>
                          {k.enabled
                            ? <Button size="sm" variant="outline-warning" className="py-0 px-1 me-1" disabled={busy} onClick={() => keeperAction(k.id, 'stop')}>Stop</Button>
                            : <Button size="sm" variant="outline-success" className="py-0 px-1 me-1" disabled={busy} onClick={() => keeperAction(k.id, 'start')}>Start</Button>}
                          <Button size="sm" variant="outline-danger" className="py-0 px-1" disabled={busy} onClick={() => keeperAction(k.id, 'delete')}>Delete</Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
              <Row className="g-1 align-items-end">
                <Col xs={3}>
                  <Form.Label className="small mb-0 text-white-50">Account label</Form.Label>
                  <Form.Control size="sm" placeholder="default" value={keeperForm.name}
                    onChange={(e) => setKeeperForm({ ...keeperForm, name: e.target.value })} />
                </Col>
                <Col xs={5}>
                  <Form.Label className="small mb-0 text-white-50">SPA URL (blank = target host)</Form.Label>
                  <Form.Control size="sm" placeholder="https://app.example.com" value={keeperForm.target_url}
                    onChange={(e) => setKeeperForm({ ...keeperForm, target_url: e.target.value })} />
                </Col>
                <Col xs={2}>
                  <Form.Label className="small mb-0 text-white-50">Reload (s)</Form.Label>
                  <Form.Control size="sm" type="number" min={120} value={keeperForm.cadence_seconds}
                    onChange={(e) => setKeeperForm({ ...keeperForm, cadence_seconds: e.target.value })} />
                </Col>
                <Col xs={2}>
                  <Button size="sm" variant="outline-info" className="w-100" disabled={busy} onClick={createKeeper}>Add keeper</Button>
                </Col>
              </Row>
            </div>

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
                {expiredActiveCount > 0 && (
                  <span className="text-danger"> ({expiredActiveCount} expired)</span>
                )}
              </span>
            </div>

            {flows.length === 0 && (
              <Alert variant="secondary" className="py-2 small">
                No auth flows exist for this target yet. You can still store and paste session tokens.
                Linking a token to a login flow is what lets Refresh Session re-mint it automatically;
                without one, refresh it by pasting a fresh value. A replayable login flow can be
                recorded or written under Authentication.
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
                    <Form.Label className="text-white small mb-1">Auth flow (optional)</Form.Label>
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
                      disabled={busy || !pasteRaw.trim()}
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
                        // The row draws the real request line, credential included. It is clipped
                        // to the column width by CSS and the whole line is on the title attribute,
                        // so nothing is cut out of the value.
                        token_value: t.token_value,
                        has_value: t.has_value === true,
                        value_fingerprint: t.value_fingerprint,
                        value_length: t.value_length,
                      }, '');
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
                              {t.token_role === 'companion' && (
                                <Badge bg="info" title="A routing / CSRF cookie, not a credential. Refreshed alongside the credential it accompanies, never graded on its own.">companion</Badge>
                              )}
                              {t.token_role === 'refresh' && (
                                <Badge bg="warning" text="dark" title="A refresh secret: spent to mint a fresh credential, never sent on a resource request and never graded on its own.">refresh secret</Badge>
                              )}
                              {t.credential_kind === 'oauth_access_token' && (
                                <Badge bg="dark" className="border border-info text-info" title="An OAuth access token captured from a token endpoint response.">OAuth access</Badge>
                              )}
                              {t.keeper_name && (
                                <Badge bg="dark" className="border border-light text-white-50" title={`Belongs to session-keeper account "${t.keeper_name}". Only that keeper seeds this cookie.`}>acct: {t.keeper_name}</Badge>
                              )}
                              {t.is_active !== false
                                ? <Badge bg={isTokenExpired(t) ? 'secondary' : 'success'}>active</Badge>
                                : <Badge bg="dark" className="border border-secondary text-white-50">off</Badge>}
                              {isTokenExpired(t) && t.token_role !== 'refresh' && <Badge bg="danger">expired</Badge>}
                              {t.auto_refresh && (
                                <Badge bg="dark" className="border border-info text-info" title="Opted into unattended refresh: the server renews it as it nears expiry (only while its flow stays a pure replay).">auto</Badge>
                              )}
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
                      {/* THERE IS NO "SHOW FULL VALUE" SWITCH. The preview already shows the full
                          value, so a switch would have nothing left to reveal. */}
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
                  <div className="text-white-50" style={{ fontSize: '0.72rem' }}>
                    {/* Which of the two this says decides what the operator does next: a row with
                        no credential at all is why the scans on this target are going out
                        unauthenticated. */}
                    {storedCredentialSummary(form)}
                    {form.has_value === true && !form.token_value
                      ? ' The Value box is empty, so a Save leaves what is stored alone.'
                      : ' The preview is the Value box, exactly as it will be sent.'}
                  </div>
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
                      placeholder={form.has_value === true
                        ? 'Empty leaves the stored credential alone. Paste a new one to replace it.'
                        : 'Paste the token exactly as the application issued it, with no prefix'}
                      value={form.token_value}
                      onChange={(e) => setField({ token_value: e.target.value })}
                    />
                    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                      {storedCredentialSummary(form)}
                      {' '}
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
                    <Form.Label className="text-white small mb-1">Auth flow (optional)</Form.Label>
                    {renderFlowSelect(form.auth_flow_id, (v) => setField({ auth_flow_id: v }), 'token-flow')}
                    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                      Linking a login flow is what lets Refresh Session re-mint this token automatically:
                      when it expires, Refresh replays the flow and lifts the new value out of the response.
                      Leave it blank for a session with no replayable flow (an OAuth or federated login) and
                      refresh it by pasting a fresh value instead.
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
                        {form.has_value === true
                          ? 'A name is required.'
                          : 'A name and a value are required.'}
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
