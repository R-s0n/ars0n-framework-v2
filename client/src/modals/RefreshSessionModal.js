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
  // A refresh that paused for a code, or one that ran but produced nothing, is a "needs attention"
  // amber rather than a red failure or a green pass.
  if (s === 'needs_input' || s === 'no_token_found' || s === 'replay_failed' || s === 'no_flow'
      || s === 'error' || s === 'unknown' || s === 'inconclusive') return 'warning';
  return 'secondary';
}

// A short placeholder for the value a paused refresh is asking for.
function refreshInputPlaceholder(inputKind) {
  switch (String(inputKind || '').toLowerCase()) {
    case 'otp':
    case 'totp': return '6-digit code';
    case 'password': return 'password';
    case 'url': return 'the URL you landed on';
    case 'token': return 'token';
    default: return 'value';
  }
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
//
// THE CREDENTIAL IS IN IT, VERBATIM. The line is the exact bytes a scan puts on the wire, which is
// what makes it worth pasting into a repeater tab and what makes a captured credential provable.
// The row is truncated by CSS at the width of its column and the whole line is on the title
// attribute, so nothing is cut out of the value itself.
export function wireSummary(t) {
  const shown = credentialForWire(t);
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

// credentialForWire is the credential, or a word saying there is not one.
//
// A row that holds nothing and a row that holds a credential are DIFFERENT STATES and must not
// render the same: "no value stored" is the reason a scan is going out unauthenticated, and it is
// an absence rather than something withheld.
function credentialForWire(t) {
  if (t.token_value) return t.token_value;
  return t.has_value === true ? '<the stored credential>' : '<no value stored>';
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
  // The value being typed to answer a refresh that paused for input, keyed by token id.
  const [refreshInput, setRefreshInput] = useState({});
  // How each linked flow can be refreshed (replay / interactive / browser_only), keyed by flow id.
  const [flowClass, setFlowClass] = useState({});
  // The token id whose "paste a fresh value" box is open, and the text in it.
  const [pasteFor, setPasteFor] = useState(null);
  const [pasteText, setPasteText] = useState('');
  // The token id whose "re-capture from browser" panel is open, and when it was opened (so only a
  // capture newer than that counts, not a stale one).
  const [recaptureFor, setRecaptureFor] = useState(null);
  const [recaptureSince, setRecaptureSince] = useState(null);
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
      setRefreshInput({});
      setFlowClass({});
      setPasteFor(null);
      setPasteText('');
      setRecaptureFor(null);
      setRecaptureSince(null);
    }
  }, [show, scopeTargetId, fetchTokens]);

  // Classify each linked flow (replay / interactive / browser_only) so a row can say how it refreshes
  // before the operator clicks. One fetch per distinct flow, only for flows not classified yet.
  useEffect(() => {
    if (!show) return;
    const flowIds = [...new Set(tokens.map((t) => t.auth_flow_id).filter(Boolean))];
    flowIds.forEach(async (fid) => {
      if (flowClass[fid]) return;
      try {
        const res = await fetch(`/api/auth-flows/flow/${fid}/refresh-classification`);
        if (res.ok) {
          const data = await res.json();
          setFlowClass((prev) => ({ ...prev, [fid]: data }));
        }
      } catch (e) { /* a missing classification just omits the hint */ }
    });
  }, [show, tokens]); // eslint-disable-line react-hooks/exhaustive-deps

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
      // A refused refresh (e.g. no_flow) comes back non-200 but with a JSON {status, detail}. Prefer
      // that friendly detail over dumping the raw body as an error string.
      if (!res.ok) {
        const raw = await res.text();
        let msg = raw || `Refresh failed (${res.status})`;
        try { const j = JSON.parse(raw); msg = j.detail || j.message || msg; } catch { /* keep raw */ }
        setResults((prev) => ({ ...prev, [id]: { kind: 'refresh', status: 'error', detail: msg } }));
        return { status: 'error', detail: msg };
      }
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

  // Answer a refresh that paused for a value (an MFA/OTP code). Submits the value, which resumes the
  // run server-side; the run may complete, or pause again for a further value.
  const provideRefreshInput = useCallback(async (id, runId, value, stepId) => {
    markBusy(id, 'refresh');
    try {
      const res = await fetch(`/api/session-refresh-runs/${runId}/input`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // step_id echoes the pause we were shown, so a stale/double submit lands on the right step or is
        // rejected instead of answering a later pause the run may have advanced to.
        body: JSON.stringify(stepId ? { value, step_id: stepId } : { value }),
      });
      const raw = await res.text();
      let data;
      try { data = JSON.parse(raw); } catch { data = { status: 'error', detail: raw }; }
      if (!res.ok) data = { kind: 'refresh', status: 'error', detail: data.error || data.detail || raw };
      setResults((prev) => ({ ...prev, [id]: { kind: 'refresh', ...data } }));
      setRefreshInput((prev) => ({ ...prev, [id]: '' }));
      if (data.status !== 'needs_input') {
        if (events[id]) await loadEvents(id);
        await fetchTokens();
      }
      return data;
    } catch (e) {
      setResults((prev) => ({ ...prev, [id]: { kind: 'refresh', status: 'error', detail: e.message } }));
      return { status: 'error', detail: e.message };
    } finally {
      clearBusy(id);
    }
  }, [events, loadEvents, fetchTokens]);

  // Refresh a session by pasting a fresh value. This is the working refresh for a token with no
  // replayable flow (an OAuth / federated / Cloudflare session): the operator copies a current Cookie
  // header (or Set-Cookie / Authorization) from their logged-in browser and it upserts every matching
  // token in place, companions included. Same endpoint Manage Sessions' paste uses.
  const pasteFreshValue = async (tokenId) => {
    const raw = pasteText.trim();
    if (!raw) return;
    markBusy(tokenId, 'refresh');
    setError('');
    try {
      const res = await fetch(`/api/session-tokens/target/${scopeTargetId}/parse`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw }),
      });
      const body = await res.text();
      if (!res.ok) {
        let msg = body || `Paste failed (${res.status})`;
        try { const j = JSON.parse(body); msg = j.error || j.detail || msg; } catch { /* keep raw */ }
        setError(msg);
        return;
      }
      let count = 0;
      try { const j = JSON.parse(body); count = (j.tokens || []).length; } catch { /* ignore */ }
      setPasteFor(null);
      setPasteText('');
      await fetchTokens();
      setNotice(`Updated ${count || ''} token value(s) from the paste. The values were replaced in place.`);
    } catch (e) {
      setError('Paste failed: ' + e.message);
    } finally {
      clearBusy(tokenId);
    }
  };

  // Refresh from the live browser: read the freshest session the extension captured for this host and
  // upsert it. `since` is when the operator opened the panel, so only a capture from their new login
  // counts. This is the working refresh for OAuth / federated / Cloudflare sessions.
  const recaptureSession = async (tokenId, since) => {
    markBusy(tokenId, 'refresh');
    setError('');
    try {
      const res = await fetch(`/api/session-tokens/${tokenId}/refresh-recapture`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(since ? { since } : {}),
      });
      const raw = await res.text();
      let data;
      try { data = JSON.parse(raw); } catch { data = { status: 'error', detail: raw }; }
      if (!res.ok) { setError(data.error || data.detail || `Re-capture failed (${res.status})`); return; }
      setResults((prev) => ({ ...prev, [tokenId]: { kind: 'refresh', ...data } }));
      if (data.status === 'recaptured') {
        setRecaptureFor(null);
        setRecaptureSince(null);
        if (events[tokenId]) await loadEvents(tokenId);
        await fetchTokens();
      }
    } catch (e) {
      setError('Re-capture failed: ' + e.message);
    } finally {
      clearBusy(tokenId);
    }
  };

  // Opt a token into (or out of) unattended refresh. The server only ever acts on the flag when the
  // flow is a pure replay and a hand refresh has already worked, so the toggle is a request, not a
  // guarantee; the row copy says as much. A partial PUT (only auto_refresh) is safe here because the
  // server merges onto the stored row.
  const toggleAutoRefresh = async (id, next) => {
    markBusy(id, 'autorefresh');
    setError('');
    try {
      const res = await fetch(`/api/session-tokens/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auto_refresh: next }),
      });
      if (!res.ok) {
        const body = await res.text();
        setError(body || `Could not change auto-refresh (${res.status})`);
        return;
      }
      await fetchTokens();
    } catch (e) {
      setError('Could not change auto-refresh: ' + e.message);
    } finally {
      clearBusy(id);
    }
  };

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
        ? `${skipped} token(s) look expired but have no auth flow linked, so there is nothing to replay. Link a login flow in Manage Sessions, or, for an OAuth/federated session with no replayable flow, paste a fresh value there.`
        : 'Nothing is expired. Validate first if you want a fresh verdict.');
      return;
    }
    setBulk('refresh');
    setError('');
    setNotice('');
    let ok = 0;
    let needsInputCount = 0;
    for (let i = 0; i < eligible.length; i += 1) {
      setBulkProgress(`Refreshing ${i + 1} of ${eligible.length}: ${eligible[i].name}`);
      const out = await refreshToken(eligible[i].id);
      if (out && out.status === 'needs_input') {
        // A flow that pauses for a code cannot be answered mid-sweep (the sweep holds every control
        // busy), and leaving it paused would keep a live session hanging. Cancel it and tell the
        // operator to refresh that one individually, where they can enter the code.
        needsInputCount += 1;
        if (out.run_id) {
          try { await fetch(`/api/session-refresh-runs/${out.run_id}/cancel`, { method: 'POST' }); } catch (e) { /* ignore */ }
        }
        setResults((prev) => { const n = { ...prev }; delete n[eligible[i].id]; return n; });
      } else if (out && out.new_value_set) {
        ok += 1;
      }
    }
    setBulkProgress('');
    setBulk('');
    await fetchTokens();
    setNotice(`Replayed ${eligible.length} flow(s), ${ok} produced a new token value.`
      + (needsInputCount > 0 ? ` ${needsInputCount} need a code – refresh those individually.` : '')
      + (skipped > 0 ? ` ${skipped} skipped with no flow linked.` : ''));
  };

  // Capture OAuth tokens from the corpus: promote the freshest token endpoint response into a durable
  // access-token credential + a linked refresh secret. A no-op on a BFF app whose tokens never reach the
  // browser (the server says so plainly), so it is safe to offer for any target.
  const captureOAuthTokens = async () => {
    setBulk('capture_oauth');
    setError('');
    setNotice('');
    try {
      const res = await fetch(`/api/session-tokens/target/${scopeTargetId}/capture-oauth`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      const raw = await res.text();
      let data;
      try { data = JSON.parse(raw); } catch { data = { detail: raw }; }
      if (!res.ok) { setError(data.error || data.detail || `Capture failed (${res.status})`); return; }
      await fetchTokens();
      setNotice(data.detail || (data.status === 'captured' ? 'Captured OAuth tokens.' : 'No OAuth tokens found in the corpus.'));
    } catch (e) {
      setError('Capture failed: ' + e.message);
    } finally {
      setBulk('');
    }
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
          {r.kind === 'refresh' && r.status !== 'needs_input' && (
            r.new_value_set
              ? <Badge bg="success">new value stored</Badge>
              : <Badge bg="dark" className="border border-secondary text-white-50">value unchanged</Badge>
          )}
        </div>
        {r.detail && <div className="text-white small mt-1">{r.detail}</div>}
        {/* A refresh that paused: for a push "approve" it just needs Continue; otherwise a value. */}
        {r.status === 'needs_input' && r.input_request && r.run_id && (
          <div className="mt-2">
            <div className="d-flex gap-2 align-items-start">
              {r.input_request.no_value ? (
                <Button
                  size="sm"
                  variant="danger"
                  disabled={anyBusy}
                  onClick={() => provideRefreshInput(id, r.run_id, '', r.input_request.step_id)}
                >
                  {rowBusy[id] === 'refresh' ? <Spinner size="sm" animation="border" /> : 'Continue'}
                </Button>
              ) : (
                <>
                  <Form.Control
                    size="sm"
                    autoFocus
                    type={r.input_request.input_kind === 'password' ? 'password' : 'text'}
                    placeholder={refreshInputPlaceholder(r.input_request.input_kind)}
                    value={refreshInput[id] || ''}
                    disabled={anyBusy}
                    onChange={(e) => setRefreshInput((prev) => ({ ...prev, [id]: e.target.value }))}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && (refreshInput[id] || '').trim()) {
                        provideRefreshInput(id, r.run_id, (refreshInput[id] || '').trim(), r.input_request.step_id);
                      }
                    }}
                    style={{ maxWidth: r.input_request.input_kind === 'url' ? '420px' : '260px' }}
                  />
                  <Button
                    size="sm"
                    variant="danger"
                    disabled={anyBusy || !(refreshInput[id] || '').trim()}
                    onClick={() => provideRefreshInput(id, r.run_id, (refreshInput[id] || '').trim(), r.input_request.step_id)}
                  >
                    Submit
                  </Button>
                </>
              )}
              <Button
                size="sm"
                variant="outline-secondary"
                disabled={anyBusy}
                onClick={async () => {
                  // Clear the prompt regardless: a failed cancel POST must not leave the box stuck. The
                  // server-side run, if it survives, is cancelled by the next refresh of this token anyway.
                  try {
                    await fetch(`/api/session-refresh-runs/${r.run_id}/cancel`, { method: 'POST' });
                  } catch (e) {
                    /* network error: still clear the box below */
                  } finally {
                    setResults((prev) => { const n = { ...prev }; delete n[id]; return n; });
                  }
                }}
              >
                Cancel
              </Button>
            </div>
            <div className="text-white-50 mt-1" style={{ fontSize: '0.68rem' }}>
              The refresh replayed up to this step and is holding a live session; enter the value and it
              continues from here.
            </div>
          </div>
        )}
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
              <Button size="sm" variant="outline-danger" onClick={captureOAuthTokens} disabled={anyBusy}
                title="Promote the freshest OAuth token endpoint response in the crawl into a durable access token + linked refresh secret. A no-op on a BFF app whose tokens never reach the browser.">
                {bulk === 'capture_oauth' ? <Spinner size="sm" animation="border" /> : 'Capture OAuth tokens'}
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
                        {t.refresh_flow_id && (
                          <div
                            className={t.refresh_transport === 'browser_only' ? 'text-warning' : 'text-info'}
                            style={{ fontSize: '0.66rem' }}
                            title="This token has a dedicated headless refresh flow (an OAuth refresh grant); refresh replays it instead of the login flow."
                          >
                            refresh via {t.refresh_strategy || 'flow'}
                            {t.refresh_transport ? ` (${t.refresh_transport === 'browser_only' ? 'browser only' : t.refresh_transport})` : ''}
                          </div>
                        )}
                        {t.auth_flow_id ? (
                          <>
                            <span className="text-white-50" style={{ fontSize: '0.72rem' }}>
                              flow: <span className="text-white">{t.auth_flow_name || 'linked'}</span>
                            </span>
                            {flowClass[t.auth_flow_id] && flowClass[t.auth_flow_id].kind !== 'replay' && (
                              <div
                                className={flowClass[t.auth_flow_id].kind === 'browser_only' ? 'text-warning' : 'text-info'}
                                style={{ fontSize: '0.66rem' }}
                                title={flowClass[t.auth_flow_id].note}
                              >
                                {flowClass[t.auth_flow_id].kind === 'browser_only'
                                  ? 'browser-only, re-paste or re-capture'
                                  : 'needs a code on refresh'}
                              </div>
                            )}
                            {/* Auto-refresh is only offered on a pure replay: the only flow the server
                                can renew with nobody watching. On anything else the checkbox would be a
                                promise the server will not keep. */}
                            {flowClass[t.auth_flow_id] && flowClass[t.auth_flow_id].kind === 'replay' && (
                              <Form.Check
                                type="switch"
                                id={`auto-refresh-${t.id}`}
                                className="mt-1"
                                checked={t.auto_refresh === true}
                                disabled={anyBusy}
                                onChange={(e) => toggleAutoRefresh(t.id, e.target.checked)}
                                label={
                                  <span
                                    className="text-white-50"
                                    style={{ fontSize: '0.66rem' }}
                                    title={t.last_refreshed_at
                                      ? 'The server renews this token on its own as it nears expiry. Only fires because this flow is a pure replay and a refresh has already worked once.'
                                      : 'Turns on unattended renewal once a refresh has worked at least once by hand. Until then the server leaves it alone.'}
                                  >
                                    auto-refresh
                                    {t.auto_refresh && !t.last_refreshed_at ? ' (arms after first manual refresh)' : ''}
                                  </span>
                                }
                              />
                            )}
                          </>
                        ) : (
                          <span className="text-warning" style={{ fontSize: '0.72rem' }}>
                            no flow linked, refresh by pasting a fresh value
                          </span>
                        )}
                        {t.token_role === 'companion' && (
                          <div className="text-info" style={{ fontSize: '0.66rem' }}
                            title="A companion is not a credential (a load-balancer or CSRF cookie). It is refreshed alongside the credential it accompanies, never graded on its own.">
                            companion, refreshes with the credential
                          </div>
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
                            : 'No replayable flow linked. Link a login flow in Manage Sessions, or, for an OAuth/federated session, paste a fresh value there.'}
                        >
                          {busyWhat === 'refresh' ? <Spinner size="sm" animation="border" /> : 'Refresh'}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline-danger"
                          disabled={anyBusy}
                          onClick={() => {
                            const opening = recaptureFor !== t.id;
                            setRecaptureFor(opening ? t.id : null);
                            setRecaptureSince(opening ? new Date().toISOString() : null);
                          }}
                          title="Refresh from your live browser: log in there with the extension recording, and the framework pulls the fresh session it captured. The way to refresh an OAuth / federated / Cloudflare session."
                        >
                          Browser
                        </Button>
                        <Button
                          size="sm"
                          variant="outline-danger"
                          disabled={anyBusy}
                          onClick={() => { setPasteFor(pasteFor === t.id ? null : t.id); setPasteText(''); }}
                          title="Refresh by pasting a fresh value copied from your logged-in browser. Works for any session, including OAuth/federated ones with no replayable flow."
                        >
                          Paste
                        </Button>
                        <Button size="sm" variant="outline-secondary" disabled={anyBusy} onClick={() => toggleExpanded(t.id)}>
                          {expanded[t.id] ? 'Hide' : 'History'}
                        </Button>
                      </Col>
                    </Row>

                    {recaptureFor === t.id && (
                      <div className="mt-2 border-top border-secondary pt-2">
                        <div className="text-white-50 small mb-1">
                          Refresh from your live browser, the way an OAuth / federated / Cloudflare session
                          has to be renewed:
                        </div>
                        <ol className="text-white-50 small mb-2" style={{ fontSize: '0.72rem', paddingLeft: '1.1rem' }}>
                          <li>In your browser, with the extension recording (Manual Crawling or Record Auth Flows), log in / reload an authenticated page so a request with the fresh session cookies is captured.</li>
                          <li>Come back and press <span className="text-white">Pull latest session</span>. Only a capture from after you opened this panel is used.</li>
                        </ol>
                        <Button size="sm" variant="danger" disabled={anyBusy} onClick={() => recaptureSession(t.id, recaptureSince)}>
                          {busyWhat === 'refresh' ? <Spinner size="sm" animation="border" /> : 'Pull latest session'}
                        </Button>
                        <Button size="sm" variant="outline-secondary" className="ms-2" disabled={anyBusy} onClick={() => { setRecaptureFor(null); setRecaptureSince(null); }}>
                          Cancel
                        </Button>
                      </div>
                    )}

                    {pasteFor === t.id && (
                      <div className="mt-2 border-top border-secondary pt-2">
                        <div className="text-white-50 small mb-1">
                          Paste a fresh <code className="text-white">Cookie</code> header (or a{' '}
                          <code className="text-white">Set-Cookie</code> / <code className="text-white">Authorization</code>)
                          from your logged-in browser. Every value in it replaces the matching stored token in place.
                        </div>
                        <Form.Control
                          as="textarea"
                          rows={3}
                          className="bg-black text-white border-secondary"
                          style={{ fontFamily: 'monospace', fontSize: '0.72rem' }}
                          placeholder={'Cookie: __Host-app_session=...; other=...'}
                          value={pasteText}
                          disabled={anyBusy}
                          onChange={(e) => setPasteText(e.target.value)}
                        />
                        <div className="d-flex gap-2 mt-1">
                          <Button size="sm" variant="danger" disabled={anyBusy || !pasteText.trim()} onClick={() => pasteFreshValue(t.id)}>
                            {busyWhat === 'refresh' ? <Spinner size="sm" animation="border" /> : 'Update from paste'}
                          </Button>
                          <Button size="sm" variant="outline-secondary" disabled={anyBusy} onClick={() => { setPasteFor(null); setPasteText(''); }}>
                            Cancel
                          </Button>
                        </div>
                      </div>
                    )}

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
