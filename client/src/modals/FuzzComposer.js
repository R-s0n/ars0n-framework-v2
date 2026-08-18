import { useState, useEffect, useCallback, useRef } from 'react';
import { Alert, Badge, Button, Form, Spinner } from 'react-bootstrap';

// The fuzz composer: endpoints on the left, the request you are building in the middle, the scan
// flow permanently on the right.
//
// The middle column edits RAW HTTP TEXT, because that is the artifact both tools consume
// (ffuf -request, x8 -r). Marking a position inserts a {{pNN}} token into the text, so a payload can
// go anywhere a byte can go: inside a path segment, inside a JWT, inside one field of a JSON body.
// A structured form could not express those, and it would also mean a second representation that
// eventually disagrees with what gets sent.
//
// Every preview shown here is rendered by the server with the same function that builds the real
// command, so what you read is what runs.

const BUILTIN_WORDLISTS = [
  { id: 'builtin-small', label: 'built-in: small' },
  { id: 'builtin-default', label: 'built-in: default (5000)' },
  { id: 'builtin-large', label: 'built-in: large' },
  { id: 'builtin-headers', label: 'built-in: header names' },
  { id: 'builtin-cookies', label: 'built-in: cookie names' },
];

const ENCODERS = ['', 'urlencode', 'b64encode', 'hexencode'];

const MODE_HELP = {
  clusterbomb: 'Every combination of every list. Requests multiply, so two 2,500-word lists is 6.25 million.',
  pitchfork: 'Lists advance together by index. ffuf RECYCLES a shorter list from the start rather than stopping, so unequal lengths are refused here.',
  sniper: 'One position at a time, the others resting at their real value. Takes a single wordlist.',
};

const BLANK_REQUEST = 'GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n';

export const FuzzComposer = ({ tool, targetId, onRunStateChange }) => {
  const [endpoints, setEndpoints] = useState([]);
  const [steps, setSteps] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [draft, setDraft] = useState('');
  const [preview, setPreview] = useState(null);
  const [wordlists, setWordlists] = useState(BUILTIN_WORDLISTS);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [run, setRun] = useState(null);
  const rawRef = useRef(null);

  const selected = steps.find((s) => s.id === selectedId) || null;

  const loadFlow = useCallback(async () => {
    if (!targetId) return;
    try {
      const res = await fetch(`/api/fuzz/${targetId}/flow?tool=${tool}`);
      if (res.ok) {
        const data = await res.json();
        setSteps(data.steps || []);
        return data.steps || [];
      }
    } catch (err) {
      setError('Could not load the flow: ' + err.message);
    }
    return [];
  }, [targetId, tool]);

  useEffect(() => {
    if (!targetId) return;
    (async () => {
      setLoading(true);
      try {
        const [epRes, wlRes] = await Promise.all([
          fetch(`/api/fuzz/${targetId}/endpoints`),
          fetch('/api/ffuf-wordlists'),
        ]);
        if (epRes.ok) setEndpoints((await epRes.json()).endpoints || []);
        if (wlRes.ok) {
          const custom = await wlRes.json();
          const list = Array.isArray(custom) ? custom : custom.wordlists || [];
          setWordlists([...BUILTIN_WORDLISTS,
            ...list.map((w) => ({ id: w.id, label: w.name || w.id }))]);
        }
        await loadFlow();
      } finally {
        setLoading(false);
      }
    })();
  }, [targetId, loadFlow]);

  // Keep the editor in sync when a different step is selected, but never clobber what the operator
  // is currently typing.
  useEffect(() => {
    if (selected) setDraft(selected.raw_request || '');
  }, [selectedId]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadPreview = useCallback(async (stepId) => {
    if (!stepId) return;
    try {
      const res = await fetch(`/api/fuzz/steps/${stepId}/preview`);
      if (res.ok) setPreview(await res.json());
    } catch { /* preview is advisory; the run refuses on its own */ }
  }, []);

  useEffect(() => { if (selectedId) loadPreview(selectedId); }, [selectedId, loadPreview]);

  const saveStep = async (stepId, body, reload = true) => {
    setBusy(true);
    try {
      const res = await fetch(`/api/fuzz/steps/${stepId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        setError(e.message || 'That change could not be saved');
        return null;
      }
      const updated = await res.json();
      if (reload) {
        await loadFlow();
        await loadPreview(stepId);
      }
      return updated;
    } catch (err) {
      setError('That change could not be saved: ' + err.message);
      return null;
    } finally {
      setBusy(false);
    }
  };

  const addStep = async (body) => {
    setBusy(true);
    setError('');
    try {
      const res = await fetch(`/api/fuzz/${targetId}/steps`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool, ...body }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        setError(e.message || 'Could not add that step');
        return;
      }
      const step = await res.json();
      await loadFlow();
      setSelectedId(step.id);
      setDraft(step.raw_request || '');
    } catch (err) {
      setError('Could not add that step: ' + err.message);
    } finally {
      setBusy(false);
    }
  };

  const removeStep = async (id) => {
    await fetch(`/api/fuzz/steps/${id}`, { method: 'DELETE' });
    const remaining = await loadFlow();
    if (selectedId === id) setSelectedId(remaining.length ? remaining[0].id : null);
  };

  const move = async (id, delta) => {
    const order = steps.map((s) => s.id);
    const i = order.indexOf(id);
    const j = i + delta;
    if (i < 0 || j < 0 || j >= order.length) return;
    [order[i], order[j]] = [order[j], order[i]];
    setBusy(true);
    await fetch(`/api/fuzz/${targetId}/steps/reorder`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step_ids: order }),
    });
    await loadFlow();
    setBusy(false);
  };

  // Marking inserts the token at the cursor. The next free number is used so tokens stay unique
  // even after some have been deleted by hand.
  const markPosition = () => {
    const el = rawRef.current;
    if (!el) return;
    const used = new Set((draft.match(/\{\{p(\d{1,2})\}\}/g) || [])
      .map((t) => parseInt(t.replace(/\D/g, ''), 10)));
    let n = 1;
    while (used.has(n)) n += 1;
    const token = `{{p${String(n).padStart(2, '0')}}}`;
    const start = el.selectionStart ?? draft.length;
    const end = el.selectionEnd ?? start;
    // Replacing a selection keeps the original text as the sniper resting value, which is what a
    // non-fuzzed position sends.
    const next = draft.slice(0, start) + token + draft.slice(end);
    const restingValue = draft.slice(start, end);
    setDraft(next);
    saveStep(selectedId, {
      raw_request: next,
      positions: [{ token, resting_value: restingValue, wordlist: 'builtin-small' }],
    });
  };

  const setPosition = (token, patch) => {
    if (!selected) return;
    const positions = (selected.positions || []).map((p) =>
      p.token === token ? { ...p, ...patch } : p);
    saveStep(selected.id, { raw_request: draft, positions });
  };

  const runFlow = async (acknowledge = false) => {
    setBusy(true);
    setError('');
    try {
      const res = await fetch(`/api/fuzz/${targetId}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool, acknowledge }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 409 && data.acknowledgeable) {
        // The ceiling exists because clusterbomb multiplies and ffuf starts without complaint.
        if (window.confirm(data.reason + '\n\nRun it anyway?')) return runFlow(true);
        return;
      }
      if (!res.ok) {
        setError(data.message || data.reason || 'The flow could not start');
        return;
      }
      setRun({ id: data.run_id, status: 'running', steps_done: 0, steps_total: data.steps });
      if (onRunStateChange) onRunStateChange(true);
      pollRun(data.run_id);
    } catch (err) {
      setError('The flow could not start: ' + err.message);
    } finally {
      setBusy(false);
    }
  };

  const pollRun = (runId) => {
    const tick = async () => {
      try {
        const res = await fetch(`/api/fuzz/runs/${runId}`);
        if (!res.ok) return;
        const data = await res.json();
        setRun(data);
        if (['running', 'pending'].includes(data.status)) {
          setTimeout(tick, 3000);
        } else if (onRunStateChange) {
          onRunStateChange(false);
        }
      } catch { /* the next poll will retry */ }
    };
    setTimeout(tick, 1500);
  };

  if (loading) {
    return <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>;
  }

  const rendered = preview && preview.rendered;

  return (
    <div className="d-flex flex-column" style={{ height: '100%', minHeight: 0 }}>
      {error && (
        <Alert variant="dark" className="border border-danger text-danger py-2"
               onClose={() => setError('')} dismissible>{error}</Alert>
      )}

      <div className="d-flex flex-grow-1" style={{ minHeight: 0, gap: '0.5rem' }}>
        {/* LEFT: what you can start a round from. */}
        <div className="border border-secondary rounded d-flex flex-column"
             style={{ width: '280px', minWidth: '240px' }}>
          <div className="px-2 py-1 border-bottom border-secondary d-flex justify-content-between align-items-center"
               style={{ backgroundColor: '#2b2b2b' }}>
            <span className="text-light small">Endpoints</span>
            <Button size="sm" variant="link" className="p-0 text-danger small" disabled={busy}
                    onClick={() => addStep({ raw_request: BLANK_REQUEST, scheme: 'https',
                                             name: 'blank request' })}>
              blank
            </Button>
          </div>
          <div style={{ overflowY: 'auto' }}>
            {endpoints.length === 0 && (
              <div className="text-white-50 small p-3">
                No valid endpoints yet. Run Consolidate and Investigate first, or start from a blank
                request.
              </div>
            )}
            {endpoints.map((e) => (
              <div key={e.id} className="px-2 py-1 border-bottom border-secondary"
                   style={{ cursor: 'pointer' }}
                   title={e.url}
                   onClick={() => addStep({ seed_endpoint_id: e.id, name: e.path.slice(0, 40) })}>
                <div className="text-truncate">
                  <Badge bg="dark" className={`border me-1 ${e.method === 'GET'
                    ? 'border-secondary text-light' : 'border-danger text-danger'}`}
                    style={{ fontSize: '0.55rem' }}>{e.method}</Badge>
                  <code className="text-white-50 small">{e.path}</code>
                </div>
                <div className="text-white-50" style={{ fontSize: '0.68rem' }}>{e.host}</div>
              </div>
            ))}
          </div>
        </div>

        {/* CENTRE: the request being built. */}
        <div className="flex-grow-1 border border-secondary rounded p-2 d-flex flex-column"
             style={{ minWidth: 0, overflowY: 'auto' }}>
          {!selected ? (
            <div className="text-white-50 small">
              Pick an endpoint on the left to start a round from what the application really sent,
              or add a blank request.
            </div>
          ) : (
            <>
              <div className="d-flex justify-content-between align-items-center mb-2">
                <Form.Control size="sm" style={{ maxWidth: '260px' }}
                  value={selected.name || ''} placeholder="round name"
                  onChange={(e) => setSteps((prev) => prev.map((s) =>
                    s.id === selected.id ? { ...s, name: e.target.value } : s))}
                  onBlur={(e) => saveStep(selected.id, { name: e.target.value })}
                  data-bs-theme="dark" />
                <div className="d-flex align-items-center gap-2">
                  <Form.Select size="sm" style={{ width: '150px' }} value={selected.ffuf_mode || 'clusterbomb'}
                    onChange={(e) => saveStep(selected.id, { ffuf_mode: e.target.value })}
                    data-bs-theme="dark">
                    <option value="clusterbomb">clusterbomb</option>
                    <option value="pitchfork">pitchfork</option>
                    <option value="sniper">sniper</option>
                  </Form.Select>
                  <Button size="sm" variant="outline-danger" disabled={busy} onClick={markPosition}>
                    Mark position
                  </Button>
                </div>
              </div>
              <div className="text-white-50 small mb-2">{MODE_HELP[selected.ffuf_mode || 'clusterbomb']}</div>

              <Form.Control as="textarea" ref={rawRef} rows={14}
                className="bg-dark text-light border-secondary"
                style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onBlur={() => saveStep(selected.id, { raw_request: draft })}
                data-bs-theme="dark" />
              <div className="text-white-50 small mt-1 mb-2">
                Select the text you want to replace, then Mark position. The selected text becomes the
                resting value that sniper sends while it is fuzzing somewhere else.
              </div>

              {(selected.positions || []).length > 0 && (
                <table className="table table-dark table-sm align-middle mb-2">
                  <thead>
                    <tr className="text-white-50">
                      <th>Position</th><th>Where</th><th>Wordlist</th><th>Encoder</th><th>Resting value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.positions.map((p) => (
                      <tr key={p.token}>
                        <td><code className="text-danger small">{p.token}</code></td>
                        <td className="text-white-50 small">{p.role}</td>
                        <td>
                          <Form.Select size="sm" value={p.wordlist || ''} disabled={busy}
                            onChange={(e) => setPosition(p.token, { wordlist: e.target.value })}
                            data-bs-theme="dark">
                            <option value="">choose a wordlist</option>
                            {wordlists.map((w) => <option key={w.id} value={w.id}>{w.label}</option>)}
                          </Form.Select>
                        </td>
                        <td>
                          <Form.Select size="sm" value={p.encoder || ''} disabled={busy}
                            onChange={(e) => setPosition(p.token, { encoder: e.target.value })}
                            data-bs-theme="dark">
                            {ENCODERS.map((x) => <option key={x} value={x}>{x || 'none'}</option>)}
                          </Form.Select>
                        </td>
                        <td>
                          <Form.Control size="sm" value={p.resting_value || ''} disabled={busy}
                            onChange={(e) => setPosition(p.token, { resting_value: e.target.value })}
                            data-bs-theme="dark" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              {rendered && (
                <>
                  {rendered.errors.map((e, i) => (
                    <Alert key={i} variant="dark" className="border border-danger text-danger py-1 small mb-1">
                      {e}
                    </Alert>
                  ))}
                  {rendered.warnings.map((wn, i) => (
                    <Alert key={i} variant="dark" className="border border-secondary text-light py-1 small mb-1">
                      {wn}
                    </Alert>
                  ))}
                  <div className="text-white-50 small mt-1">
                    Host <code className="text-light">{rendered.host}</code> &middot;{' '}
                    <strong className="text-light">{rendered.estimated_requests.toLocaleString()}</strong> requests
                  </div>
                  <div className="text-white-50 small mt-2 mb-1">Command</div>
                  <pre className="text-light small p-2 rounded"
                       style={{ backgroundColor: '#1e1e1e', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {rendered.command}
                  </pre>
                </>
              )}
            </>
          )}
        </div>

        {/* RIGHT: the flow, always visible. */}
        <div className="border border-secondary rounded d-flex flex-column"
             style={{ width: '300px', minWidth: '260px' }}>
          <div className="px-2 py-1 border-bottom border-secondary"
               style={{ backgroundColor: '#2b2b2b' }}>
            <span className="text-light small">Scan flow</span>
            <Badge bg="dark" className="ms-2 border border-secondary text-white-50"
                   style={{ fontSize: '0.65rem' }}>{steps.length}</Badge>
          </div>

          <div className="flex-grow-1" style={{ overflowY: 'auto' }}>
            {steps.length === 0 && (
              <div className="text-white-50 small p-3">
                Nothing in the flow yet. Rounds run in this order, one after another.
              </div>
            )}
            {steps.map((s, i) => (
              <div key={s.id}
                   className={`px-2 py-1 border-bottom border-secondary ${s.id === selectedId ? 'bg-secondary bg-opacity-25' : ''}`}
                   style={{ cursor: 'pointer', opacity: s.enabled ? 1 : 0.45 }}
                   onClick={() => setSelectedId(s.id)}>
                <div className="d-flex align-items-center">
                  <span className="text-white-50 small me-2">{i + 1}</span>
                  <div className="flex-grow-1 text-truncate">
                    <div className="text-light small text-truncate">{s.name || 'unnamed round'}</div>
                    <div className="text-white-50" style={{ fontSize: '0.68rem' }}>
                      {s.ffuf_mode || 'clusterbomb'} &middot; {(s.positions || []).length} position(s)
                    </div>
                  </div>
                </div>
                <div className="d-flex gap-2 mt-1">
                  <Button size="sm" variant="link" className="p-0 text-white-50" style={{ fontSize: '0.7rem' }}
                          disabled={busy || i === 0} onClick={(e) => { e.stopPropagation(); move(s.id, -1); }}>up</Button>
                  <Button size="sm" variant="link" className="p-0 text-white-50" style={{ fontSize: '0.7rem' }}
                          disabled={busy || i === steps.length - 1}
                          onClick={(e) => { e.stopPropagation(); move(s.id, 1); }}>down</Button>
                  <Button size="sm" variant="link" className="p-0 text-white-50" style={{ fontSize: '0.7rem' }}
                          disabled={busy}
                          onClick={(e) => { e.stopPropagation(); saveStep(s.id, { enabled: !s.enabled }); }}>
                    {s.enabled ? 'disable' : 'enable'}
                  </Button>
                  <Button size="sm" variant="link" className="p-0 text-danger" style={{ fontSize: '0.7rem' }}
                          disabled={busy}
                          onClick={(e) => { e.stopPropagation(); removeStep(s.id); }}>remove</Button>
                </div>
              </div>
            ))}
          </div>

          <div className="p-2 border-top border-secondary">
            {run && (
              <div className="text-white-50 small mb-2">
                {run.status === 'running'
                  ? `running: step ${run.steps_done + 1} of ${run.steps_total}`
                  : `${run.status}: ${run.findings_new} new finding(s)`}
                {(run.steps || []).some((st) => st.status === 'skipped_out_of_scope') && (
                  <div className="text-danger">A step was skipped as out of scope.</div>
                )}
              </div>
            )}
            <Button variant="danger" className="w-100" disabled={busy || steps.length === 0
              || (run && run.status === 'running')} onClick={() => runFlow(false)}>
              {run && run.status === 'running'
                ? <><Spinner animation="border" size="sm" className="me-2" />Running</>
                : `Run ${tool} flow`}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FuzzComposer;
