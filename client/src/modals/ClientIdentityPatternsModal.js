import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Row, Col, Button, Form, Spinner, Badge, ListGroup, Alert } from 'react-bootstrap';

// A client identity pattern is one answer to the question "how does this application decide who is
// asking", pinned to a single real request and the response it produced. The category is the field
// everything else hangs off, because it is what decides whether an IDOR attempt is a five second
// edit or a signature attack, so it is ranked, colour coded and used to group the list.
//
// Layout is a plain master-detail, the same shape as the other authorization modals: a narrow list
// of saved patterns on the left, and a wide detail panel on the right that edits the selected one
// and carries the education for its category. "New pattern" adds an unsaved draft at the top of the
// list and opens it in the detail panel; saving turns the draft into a real row. There is no
// auto-detect column here on purpose: identifier detection belongs to the consolidated attack
// vectors, not to this modal.

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

// The education layer the operator reads in the detail panel, one block per category: what it is,
// how to spot it in a captured request, the shapes it takes across tech stacks, how to actually
// test it for IDOR, and the single mistake that most often turns a non-finding into a false report.
// This is kept in sync with the manage_identity_patterns guidance the MCP server pushes to the
// model, so the human in the UI and the agent over MCP read the same thing.
const GUIDANCE = {
  parameter: {
    summary: 'The object or user id is a client-controlled value carried in the request (URL path, '
      + 'query string, body field, or GraphQL variable) and the server trusts it to choose the '
      + 'object. This is the strongest IDOR shape: testing it is just changing the value and '
      + 're-sending.',
    recognize: 'An id visible in the request that changes when you open a different object: '
      + '/accounts/8412/invoices, ?user_id=8412, {"orderId":"8412"}, or a GraphQL variable such as '
      + '{"kaid":"..."}. If you can see it and edit it, it is a parameter.',
    variants: [
      'REST numeric auto-increment id (sequential, trivially enumerable - highest value).',
      'UUID / GUID (not guessable; needs the id leaked elsewhere first).',
      'Hashid / slug / short code (sometimes reversible; often leak-dependent).',
      'GraphQL variable id, or a Relay global id (base64 of "Type:123" - decode, change, re-encode).',
      'Composite key (tenantId + objectId) where the server checks only one half.',
      'Mass assignment: an id in a write body (owner_id, account_id) that redirects the write to '
        + 'another tenant.',
    ],
    how_to_test: [
      'Capture the request as account A, swap the id to account B\'s object, resend, and READ THE '
        + 'BODY - a 200 with B\'s data is the finding; a 200 of nulls/your-own-data is not.',
      'Sequential ids: walk them (id-1, id+1) to confirm cross-account reach and scale.',
      'High-entropy ids (UUID/40-hex): first prove the id is obtainable (leaked in another response, '
        + 'a URL, a referrer, a log) - an unguessable id with no leak path is low severity.',
      'Try deleting the param, sending an array, or type-juggling (string vs int) to slip the check.',
    ],
    trap: 'Read the body, never the status. The classic false hit is a 200 that returns YOUR OWN '
      + 'data, an empty/placeholder object, or a soft-404 served as 200. A 403 is not always a miss, '
      + 'and a UUID you had to supply yourself (with no leak path) is not a weaponizable IDOR.',
  },
  signed_token: {
    summary: 'The identity is carried inside a token the client holds whose integrity is '
      + '(supposedly) cryptographically protected: a JWT, a signed or encrypted cookie, an '
      + 'HMAC-signed value, or a bearer/API key. The id cannot be moved until the token protection '
      + 'is defeated - so the bug is in the token handling first, the id second.',
    recognize: 'A JWT (three base64url segments split by dots), a framework session cookie carrying '
      + 'value.signature (Rails, Django, Express cookie-session, Laravel, Flask, ASP.NET), an '
      + 'Authorization: Bearer header, or a request parameter accompanied by a signature/HMAC.',
    variants: [
      'JWT alg:none (strip the signature) - the server accepts an unsigned token.',
      'JWT algorithm confusion: re-sign an RS256 token as HS256 using the public key as the HMAC key.',
      'Weak or leaked HMAC secret (brute/dictionary the JWT), or kid header path-traversal / SQLi.',
      'Signature simply not verified by the backend (the classic).',
      'Signed/encrypted cookie whose secret is disclosed (source leak, default key) - forge at will.',
      'Opaque/bearer token that is predictable, long-lived, or replayable across accounts.',
    ],
    how_to_test: [
      'Decode the token, change the identity claim (sub, user_id, tenant, kaid), and resend as-is - '
        + 'if accepted, verification is broken.',
      'Try alg:none and RS256->HS256 confusion; try a known/guessed secret.',
      'Replay another account\'s captured token verbatim to test binding/expiry.',
      'If the signature genuinely holds and no key is forgeable, the id is not movable here - pivot '
        + 'to another identifier on the same endpoint.',
    ],
    trap: 'A token being decodable is not a vulnerability - you need the signature actually '
      + 'unchecked, or a key you can forge with. And when you swap an external id, make sure the 200 '
      + 'is not just your own data scoped from the token\'s own sub; diff the body, never trust the '
      + 'status.',
  },
  user_context_object: {
    summary: 'The identity is NOT in the request payload at all. The server derives the acting user '
      + 'from ambient context (session cookie lookup, SSO / OAuth2 / OIDC claims, mTLS cert, '
      + 'API-gateway-injected header, or tenant/org context) and uses that to scope the query. The '
      + 'caller controls nothing, so there is nothing in the request to swap - the worst case for a '
      + 'classic IDOR.',
    recognize: 'The private read carries no id for its subject; the same bytes return different data '
      + 'purely because of the session cookie; responses describe "you" (isSelf:true, /me). Record '
      + 'this as server_side with no identifier value - that itself is evidence there is nothing to '
      + 'move.',
    variants: [
      'Session cookie resolved server-side to the user (opaque session store).',
      'OAuth2 / OIDC / SAML claims (sub, email) read from the validated token server-side.',
      'mTLS client certificate mapped to an identity.',
      'API-gateway-injected identity header (X-User-Id, X-Tenant-Id) the backend trusts.',
      'Multi-tenant/org context derived from the host or the session.',
    ],
    how_to_test: [
      'You cannot swap it in the request. Instead, look for a SIBLING op that does take a target id '
        + '(a report, an admin view) and test that one.',
      'If identity rides in a gateway-injected header, try setting that header yourself against the '
        + 'backend directly (SSRF, split-horizon, a dev host) - the backend may trust it.',
      'Test tenant/org scoping: change the org/tenant hint and see if the query crosses the boundary.',
      'Session fixation / confusion and token-vs-targetKaid binding on token-scoped reads.',
    ],
    trap: 'It usually is unexploitable for direct IDOR - do not force it. The finding, if any, is '
      + 'identity confusion (a trusted injected header, a sibling id-taking op), not an id edit. And '
      + 'swapping to a credential you minted for your own second account only proves the mechanism - '
      + 'it is not cross-account impact unless an attacker could actually obtain that artifact. '
      + 'Record the dead end and spend the hour on a parameter.',
  },
};

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

// The detail panel's education block for whichever category is selected in the form. Rendered big
// and readable, because on video this is what gets walked through, and in practice it is what keeps
// an operator from logging a user_context_object endpoint as an IDOR lead it can never be.
function CategoryGuidance({ category }) {
  const g = GUIDANCE[category];
  const meta = CATEGORY_META[category];
  if (!g || !meta) return null;
  return (
    <div className="bg-black rounded p-3 mb-3" style={{ border: '1px solid #343a40' }}>
      <div className="d-flex align-items-center gap-2 mb-2">
        <Badge bg={meta.variant}>{meta.label}</Badge>
        <span className="text-white-50 small text-uppercase" style={{ letterSpacing: '0.04em' }}>
          How this identity shape is attacked
        </span>
      </div>
      <div className="text-white small mb-2">{g.summary}</div>

      <div className="text-info text-uppercase mb-1" style={{ fontSize: '0.66rem' }}>Recognise it</div>
      <div className="text-white-50 small mb-2">{g.recognize}</div>

      <div className="text-info text-uppercase mb-1" style={{ fontSize: '0.66rem' }}>Variants across stacks</div>
      <ul className="text-white-50 small mb-2 ps-3">
        {g.variants.map((v, i) => <li key={i}>{v}</li>)}
      </ul>

      <div className="text-info text-uppercase mb-1" style={{ fontSize: '0.66rem' }}>How to test it for IDOR</div>
      <ul className="text-white-50 small mb-2 ps-3">
        {g.how_to_test.map((v, i) => <li key={i}>{v}</li>)}
      </ul>

      <div className="text-warning text-uppercase mb-1" style={{ fontSize: '0.66rem' }}>Biggest false-positive trap</div>
      <div className="text-white-50 small">{g.trap}</div>
    </div>
  );
}

const ClientIdentityPatternsModal = ({ show, handleClose, scopeTargetId, scopeTargetUrl }) => {
  const [patterns, setPatterns] = useState([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [replayingId, setReplayingId] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const [form, setForm] = useState(EMPTY_FORM);
  const [selectedId, setSelectedId] = useState(null);
  // True while a brand-new, unsaved pattern is open in the detail panel. It is what puts the
  // "New pattern (unsaved)" row at the top of the list and what makes the panel show instead of the
  // empty-state placeholder before anything has been saved.
  const [draftMode, setDraftMode] = useState(false);
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

  useEffect(() => {
    if (show && scopeTargetId) {
      fetchPatterns();
    }
    if (!show) {
      setForm(EMPTY_FORM);
      setSelectedId(null);
      setDraftMode(false);
      setReplayInfo({});
      setError('');
      setNotice('');
    }
  }, [show, scopeTargetId, fetchPatterns]);

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
    setDraftMode(true);
    setError('');
    setNotice('');
  };

  const editPattern = (p) => {
    setSelectedId(p.id);
    setDraftMode(false);
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

  const clearSelection = () => {
    setForm(EMPTY_FORM);
    setSelectedId(null);
    setDraftMode(false);
    setError('');
    setNotice('');
  };

  const canSave = form.name.trim() !== '' && form.category !== '';
  const panelOpen = draftMode || !!selectedId;

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
        setDraftMode(false);
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
      if (selectedId === id) clearSelection();
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
      setDraftMode(false);
    } catch (e) {
      setError(e.message);
    } finally {
      setReplayingId(null);
    }
  };

  const rawResponse = buildRawResponse(selectedPattern);
  const selectedReplay = selectedId ? replayInfo[selectedId] : null;

  const renderRow = (p) => (
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
            {replayingId === p.id ? <Spinner size="sm" animation="border" /> : 'Replay'}
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
  );

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

            <Row>
              {/* LEFT: the saved patterns, grouped by how much of the identity the caller controls */}
              <Col md={4} className="border-end border-secondary" style={{ maxHeight: '68vh', overflowY: 'auto' }}>
                <div className="d-flex align-items-center gap-2 mb-2">
                  <Button size="sm" variant="danger" onClick={newPattern} disabled={busy}>
                    <i className="bi bi-plus-lg me-1" />New pattern
                  </Button>
                  <Button size="sm" variant="outline-secondary" onClick={fetchPatterns} disabled={loading || busy}>
                    {loading ? <Spinner size="sm" animation="border" /> : 'Refresh'}
                  </Button>
                </div>
                <div className="text-white-50 small mb-2">
                  {patterns.length} saved{patterns.length
                    ? `: ${grouped.filter((g) => g.rows.length).map((g) => `${g.rows.length} ${g.label.toLowerCase()}`).join(', ')}`
                    : ''}
                </div>

                {draftMode && (
                  <ListGroup variant="flush" className="mb-2">
                    <ListGroup.Item active className="bg-dark text-white py-2">
                      <div className="d-flex justify-content-between align-items-center">
                        <span className="fst-italic">{form.name.trim() || 'New pattern'}</span>
                        <Badge bg="light" text="dark">unsaved</Badge>
                      </div>
                      <div className="text-white-50" style={{ fontSize: '0.66rem' }}>
                        Fill in the detail on the right, then Create pattern.
                      </div>
                    </ListGroup.Item>
                  </ListGroup>
                )}

                {loading ? (
                  <div className="text-center py-3"><Spinner size="sm" animation="border" variant="danger" /></div>
                ) : patterns.length === 0 && !draftMode ? (
                  <div className="text-white-50 small fst-italic">
                    Nothing modelled yet. Record one request per way this application works out who is
                    asking, then say which of the three shapes it is. New pattern to start.
                  </div>
                ) : (
                  grouped.map((group) => (
                    group.rows.length > 0 && (
                      <div key={group.value} className="mb-3">
                        <div className="d-flex align-items-center gap-2">
                          <Badge bg={group.variant}>{group.label}</Badge>
                          <span className="text-white-50 small">{group.rows.length}</span>
                        </div>
                        <ListGroup variant="flush">
                          {group.rows.map(renderRow)}
                        </ListGroup>
                      </div>
                    )
                  ))
                )}
              </Col>

              {/* RIGHT: the detail panel - editor, per-category education, and the stored response */}
              <Col md={8} style={{ maxHeight: '68vh', overflowY: 'auto' }}>
                {!panelOpen ? (
                  <div className="text-white-50 text-center py-5">
                    <i className="bi bi-arrow-left me-2" />
                    Select a pattern on the left to see and edit its detail, or
                    <Button variant="link" className="p-0 ms-1 align-baseline text-danger" onClick={newPattern}>
                      add a new one
                    </Button>.
                  </div>
                ) : (
                  <>
                    <div className="d-flex justify-content-between align-items-center mb-2">
                      <span className="text-white-50 small text-uppercase">
                        {form.id ? 'Edit pattern' : 'New pattern'}
                      </span>
                      <Button variant="outline-secondary" size="sm" className="py-0 px-2"
                        style={{ fontSize: '0.7rem' }} onClick={clearSelection} disabled={busy}>
                        Close
                      </Button>
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
                    </Row>

                    {/* The education block for the chosen category - the detail the operator reads */}
                    <div className="mt-3">
                      <CategoryGuidance category={form.category} />
                    </div>

                    <Row className="g-2">
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
                          <Button
                            variant="outline-danger"
                            size="sm"
                            disabled={replayingId === form.id || !form.raw_request}
                            onClick={() => selectedPattern && replayPattern(selectedPattern)}
                          >
                            {replayingId === form.id ? <Spinner size="sm" animation="border" /> : 'Replay'}
                          </Button>
                        )}
                        {form.id && (
                          <Button variant="outline-danger" size="sm" onClick={() => deletePattern(form.id)} disabled={busy}>
                            Delete
                          </Button>
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
                  </>
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
