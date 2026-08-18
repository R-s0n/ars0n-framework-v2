import { Modal, Button, Form, Badge, Spinner, Alert } from 'react-bootstrap';
import { useState, useEffect, useCallback } from 'react';

// Every unique attack vector for a target, and the place to disagree with the list.
//
// Consolidation builds these from what the tools found. This is where the operator corrects it, and
// the corrections stick: an edited or deleted vector is never rebuilt by the next consolidation,
// because a list that undoes your judgement is a list you stop curating.
//
// The confidence marks matter more here than anywhere else. Three of the upstream sources cannot
// observe what they report: crawlers and archives have no verb and consolidation writes GET; the
// consolidated parameter table holds the union of every name ever seen on an endpoint rather than a
// set seen together; and Arjun guesses its insertion point from the verb. A row built on any of those
// says so, because the assumed ones are where a wasted afternoon comes from.

const ACCENT = '#dc3545';

// What a signal means, in the words an operator would use. Shown as a badge on the row because the
// reason a vector is worth testing is more useful than the fact that it exists.
const SIGNAL_LABEL = {
  jwt: ['JWT', 'Carries a JSON Web Token. Algorithm confusion, an unverified signature and a swapped subject all live here.'],
  uuid: ['ID', 'Carries an object identifier. Swapping it for one belonging to another account is the access-control test.'],
  numeric_id: ['NUM ID', 'Carries a numeric identifier, which is enumerable as well as swappable.'],
  high_entropy: ['TOKEN', 'Carries a high-entropy value, so it identifies or authorises something.'],
  custom_header: ['CUSTOM', 'Headers the application invented rather than the browser, so the application reads them back.'],
};

const POINT_TONE = {
  query: 'border-danger text-danger',
  body: 'border-danger text-danger',
  header: 'border-secondary text-light',
  cookie: 'border-secondary text-light',
  path: 'border-secondary text-white-50',
};

// A mark shown only when a value was ASSUMED rather than measured. Absence means observed, which is
// the common case and does not need saying.
const Assumed = ({ when, children }) => (when ? (
  <span className="text-white-50" style={{ fontSize: '0.65rem' }} title={children}>
    {' '}assumed
  </span>
) : null);

function AttackVectorsModal({ show, handleClose, activeTarget, onChanged }) {
  const [vectors, setVectors] = useState([]);
  const [counts, setCounts] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [pointFilter, setPointFilter] = useState('');
  const [hostFilter, setHostFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [signalFilter, setSignalFilter] = useState('');
  const [editing, setEditing] = useState(null);
  const [busy, setBusy] = useState(false);
  // Expanded rows and what each one loaded. Fetched on expand rather than with the list: rendering a
  // request per vector for rows nobody opens is work thrown away.
  const [expanded, setExpanded] = useState({});
  const [requests, setRequests] = useState({});
  const [noteDrafts, setNoteDrafts] = useState({});
  const [savingNote, setSavingNote] = useState('');

  const load = useCallback(async () => {
    if (!activeTarget) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/attack-vectors/${activeTarget.id}`);
      if (!res.ok) {
        setError('Could not load attack vectors.');
        return;
      }
      const data = await res.json();
      setVectors(data.vectors || []);
      setCounts({ total: data.total, hosts: data.hosts, manual: data.manual });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);

  useEffect(() => { if (show) load(); }, [show, load]);

  const mutate = async (fn) => {
    setBusy(true);
    setError('');
    try {
      const res = await fn();
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.message || 'That change could not be saved.');
        return false;
      }
      await load();
      if (onChanged) onChanged();
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const toggleRow = async (v) => {
    const open = !expanded[v.id];
    setExpanded((prev) => ({ ...prev, [v.id]: open }));
    setNoteDrafts((prev) => (v.id in prev ? prev : { ...prev, [v.id]: v.notes || '' }));
    if (!open || requests[v.id]) return;
    try {
      const res = await fetch(`/api/attack-vectors/item/${v.id}/request`);
      const data = res.ok
        ? await res.json()
        : { error: 'The request for this vector could not be rendered.' };
      setRequests((prev) => ({ ...prev, [v.id]: data }));
    } catch (err) {
      setRequests((prev) => ({ ...prev, [v.id]: { error: err.message } }));
    }
  };

  const saveNote = async (v) => {
    setSavingNote(v.id);
    try {
      const res = await fetch(`/api/attack-vectors/item/${v.id}/notes`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notes: noteDrafts[v.id] ?? '' }),
      });
      if (!res.ok) {
        setError('That note could not be saved.');
        return;
      }
      // Kept in local state rather than reloading the whole list, so the row does not jump under the
      // cursor while the operator is still typing in the one below it.
      setVectors((prev) => prev.map((x) => (
        x.id === v.id ? { ...x, notes: noteDrafts[v.id] } : x)));
      if (onChanged) onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setSavingNote('');
    }
  };

  const remove = (v) => mutate(() => fetch(`/api/attack-vectors/item/${v.id}`, { method: 'DELETE' }));

  const saveEdit = async () => {
    const ok = await mutate(() => fetch(`/api/attack-vectors/item/${editing.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: editing.method,
        domain: editing.domain,
        path: editing.path,
        insertion_point: editing.insertion_point,
        parameters: String(editing.parametersText || '')
          .split(',').map((p) => p.trim()).filter(Boolean),
        notes: editing.notes,
      }),
    }));
    if (ok) setEditing(null);
  };

  const tally = (values) => {
    const c = new Map();
    values.forEach((v) => c.set(v, (c.get(v) || 0) + 1));
    return [...c.entries()].sort((a, b) => b[1] - a[1]);
  };
  const pointOptions = tally(vectors.map((v) => v.insertion_point));
  const hostOptions = tally(vectors.map((v) => v.domain));
  const sourceOptions = tally(vectors.flatMap((v) => v.sources || []));
  const signalOptions = tally(vectors.flatMap((v) => v.signals || []));

  const term = search.toLowerCase();
  const shown = vectors.filter((v) => {
    if (pointFilter && v.insertion_point !== pointFilter) return false;
    if (hostFilter && v.domain !== hostFilter) return false;
    if (sourceFilter && !(v.sources || []).includes(sourceFilter)) return false;
    if (signalFilter && !(v.signals || []).includes(signalFilter)) return false;
    if (!term) return true;
    return `${v.domain}${v.path}${v.method}${(v.parameters || []).join(',')}`
      .toLowerCase().includes(term);
  });

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Unique Attack Vectors</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ overflowY: 'auto' }}>
        {error && <Alert variant="danger" className="py-2 small">{error}</Alert>}

        <div className="d-flex flex-wrap gap-2 align-items-center mb-3">
          <Form.Control size="sm" style={{ maxWidth: '280px' }} data-bs-theme="dark"
            className="custom-input"
            placeholder="Search host, path or parameter"
            value={search} onChange={(e) => setSearch(e.target.value)} />

          <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
            value={pointFilter} onChange={(e) => setPointFilter(e.target.value)}>
            <option value="">Any insertion point</option>
            {pointOptions.map(([p, n]) => <option key={p} value={p}>{p} ({n})</option>)}
          </Form.Select>

          <Form.Select size="sm" style={{ width: 'auto', maxWidth: '260px' }} data-bs-theme="dark"
            value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}>
            <option value="">Any host</option>
            {hostOptions.map(([h, n]) => <option key={h} value={h}>{h} ({n})</option>)}
          </Form.Select>

          <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
            value={signalFilter} onChange={(e) => setSignalFilter(e.target.value)}
            title="What the value looks like: a token, an identifier, a header the application invented.">
            <option value="">Any signal</option>
            {signalOptions.map(([sig, n]) => (
              <option key={sig} value={sig}>{(SIGNAL_LABEL[sig] || [sig])[0]} ({n})</option>
            ))}
          </Form.Select>

          <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
            value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
            <option value="">Any source</option>
            {sourceOptions.map(([s, n]) => <option key={s} value={s}>{s} ({n})</option>)}
          </Form.Select>

          <span className="text-white-50 ms-auto small">
            showing {shown.length} of {vectors.length}
            {counts.hosts ? ` · ${counts.hosts} host${counts.hosts === 1 ? '' : 's'}` : ''}
            {counts.manual ? ` · ${counts.manual} by hand` : ''}
          </span>
        </div>

        {loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : shown.length === 0 ? (
          <Alert variant="dark" className="border-secondary text-white-50">
            No attack vectors yet. Run <strong>Consolidate</strong> to build them from everything the
            crawls, the archives, Arjun, x8 and FFUF found, or add one by hand.
          </Alert>
        ) : (
          <table className="table table-dark table-sm align-middle">
            <thead>
              <tr className="text-white-50" style={{ fontSize: '0.72rem', textTransform: 'uppercase' }}>
                <th>Verb</th><th>Host</th><th>Path</th><th>Insertion</th><th>Parameters</th>
                <th>Signals / Sources</th><th style={{ width: '150px' }}></th>
              </tr>
            </thead>
            <tbody>
              {shown.flatMap((v) => [
                <tr key={v.id} onClick={() => toggleRow(v)} style={{ cursor: 'pointer' }}>
                  <td className="text-light small">
                    <span className="text-white-50 me-1" style={{ fontSize: '0.7rem' }}>
                      {expanded[v.id] ? '▾' : '▸'}
                    </span>
                    {v.method}
                    <Assumed when={v.method_confidence === 'implied'}>
                      No tool observed a verb for this row, so GET was assumed.
                    </Assumed>
                  </td>
                  <td className="text-white-50 small">{v.domain}</td>
                  <td className="text-truncate" style={{ maxWidth: '300px' }} title={v.path}>
                    <code className="text-light small">{v.path}</code>
                  </td>
                  <td>
                    <Badge bg="dark" className={`border ${POINT_TONE[v.insertion_point] || ''}`}>
                      {v.insertion_point}
                    </Badge>
                    <Assumed when={v.insertion_confidence === 'implied'}>
                      Arjun derives the place from the verb rather than measuring it.
                    </Assumed>
                  </td>
                  <td className="text-truncate" style={{ maxWidth: '280px' }}
                    title={(v.parameters || []).join(', ')}>
                    <code className="text-light small">
                      {(v.parameters || []).join(', ') || '—'}
                    </code>
                    <Assumed when={v.parameters_origin === 'union'}>
                      Every parameter ever seen on this endpoint, not a combination observed in one
                      request.
                    </Assumed>
                  </td>
                  <td className="text-white-50" style={{ fontSize: '0.7rem' }}>
                    {(v.signals || []).map((sig) => {
                      const [label, why] = SIGNAL_LABEL[sig] || [sig, sig];
                      const strong = sig === 'jwt' || sig === 'uuid' || sig === 'numeric_id';
                      return (
                        <Badge key={sig} bg="dark" title={why}
                          className={`border me-1 ${strong ? 'border-danger text-danger' : 'border-secondary text-white-50'}`}
                          style={{ fontSize: '0.6rem' }}>{label}</Badge>
                      );
                    })}
                    {(v.sources || []).join(', ')}
                    {v.manual_added && <Badge bg="dark" className="border border-danger text-danger ms-1"
                      style={{ fontSize: '0.6rem' }}>by hand</Badge>}
                  </td>
                  <td className="text-end" onClick={(e) => e.stopPropagation()}>
                    <Button size="sm" variant="outline-secondary" className="me-1" disabled={busy}
                      onClick={() => setEditing({
                        ...v, parametersText: (v.parameters || []).join(', '),
                      })}>
                      Edit
                    </Button>
                    <Button size="sm" variant="outline-danger" disabled={busy}
                      onClick={() => remove(v)}>
                      Delete
                    </Button>
                  </td>
                </tr>,
                expanded[v.id] && (
                  <tr key={`${v.id}-detail`}>
                    <td colSpan={7} className="p-3" style={{ backgroundColor: '#161616' }}>
                      <VectorDetail
                        vector={v}
                        request={requests[v.id]}
                        note={noteDrafts[v.id] ?? ''}
                        onNoteChange={(text) => setNoteDrafts((prev) => ({ ...prev, [v.id]: text }))}
                        onSaveNote={() => saveNote(v)}
                        saving={savingNote === v.id}
                      />
                    </td>
                  </tr>
                ),
              ])}
            </tbody>
          </table>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={load} disabled={loading}>Refresh</Button>
        <Button variant="secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>

      {/* Editing re-keys the row, because the key IS the identity: a vector whose parameters changed
          is a different vector, and the server refuses an edit that collides with one already in the
          list rather than quietly merging two rows into one. */}
      <Modal show={!!editing} onHide={() => setEditing(null)} data-bs-theme="dark" centered>
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">Edit Attack Vector</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {editing && (
            <>
              <div className="row g-2">
                <div className="col-4">
                  <Form.Label className="text-white small">Verb</Form.Label>
                  <Form.Select size="sm" className="bg-dark text-white border-secondary"
                    value={editing.method}
                    onChange={(e) => setEditing({ ...editing, method: e.target.value })}>
                    {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </Form.Select>
                </div>
                <div className="col-8">
                  <Form.Label className="text-white small">Host</Form.Label>
                  <Form.Control size="sm" className="bg-dark text-white border-secondary custom-input"
                    value={editing.domain}
                    onChange={(e) => setEditing({ ...editing, domain: e.target.value })} />
                </div>
              </div>
              <Form.Label className="text-white small mt-2">Path</Form.Label>
              <Form.Control size="sm" className="bg-dark text-white border-secondary custom-input"
                value={editing.path}
                onChange={(e) => setEditing({ ...editing, path: e.target.value })} />
              <div className="row g-2 mt-2">
                <div className="col-5">
                  <Form.Label className="text-white small">Insertion point</Form.Label>
                  <Form.Select size="sm" className="bg-dark text-white border-secondary"
                    value={editing.insertion_point}
                    onChange={(e) => setEditing({ ...editing, insertion_point: e.target.value })}>
                    {['query', 'body', 'header', 'cookie', 'path'].map((p) => (
                      <option key={p} value={p}>{p}</option>
                    ))}
                  </Form.Select>
                </div>
                <div className="col-7">
                  <Form.Label className="text-white small">Parameters</Form.Label>
                  <Form.Control size="sm" className="bg-dark text-white border-secondary custom-input"
                    placeholder="comma separated"
                    value={editing.parametersText}
                    onChange={(e) => setEditing({ ...editing, parametersText: e.target.value })} />
                </div>
              </div>
              <Form.Label className="text-white small mt-2">Note</Form.Label>
              <Form.Control size="sm" className="bg-dark text-white border-secondary custom-input"
                value={editing.notes || ''}
                onChange={(e) => setEditing({ ...editing, notes: e.target.value })} />
              <div className="text-white-50 mt-2" style={{ fontSize: '0.72rem' }}>
                Saving marks this vector as yours: it keeps your values through every future
                consolidation, and nothing about it is reported as assumed any more.
              </div>
            </>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="outline-secondary" onClick={() => setEditing(null)}>Cancel</Button>
          <Button variant="danger" onClick={saveEdit} disabled={busy}>Save</Button>
        </Modal.Footer>
      </Modal>
    </Modal>
  );
}

// One expanded vector: the request it describes, and the operator's notes on it.
//
// The request comes from the server already split into spans, and the spans it marked as
// user-controlled are drawn in the accent colour. Rendering from parts rather than from a string with
// markers in it means a parameter named with a quote or an angle bracket cannot break the view or be
// mistaken for framework text.
const VectorDetail = ({ vector, request, note, onNoteChange, onSaveNote, saving }) => {
  const copy = () => { navigator.clipboard?.writeText(request?.raw || ''); };

  return (
    <div className="row g-3">
      <div className="col-lg-7">
        <div className="d-flex justify-content-between align-items-baseline mb-1">
          <span className="text-danger small fw-bold">
            {request?.reconstructed ? 'The request this vector describes' : 'The request as recorded'}
          </span>
          {request?.raw && (
            <Button size="sm" variant="link" className="p-0 text-white-50"
              style={{ fontSize: '0.72rem' }} onClick={copy}>copy</Button>
          )}
        </div>

        {!request ? (
          <div className="text-white-50 small">
            <Spinner animation="border" size="sm" /> rendering
          </div>
        ) : request.error ? (
          <div className="text-white-50 small">{request.error}</div>
        ) : (
          <pre className="text-light small p-2 rounded mb-2" style={{
            backgroundColor: '#0d0d0d', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            maxHeight: '320px', overflowY: 'auto',
          }}>
            {(request.parts || []).map((p, i) => (p.input ? (
              <span key={i} title={p.param ? `${p.param} is user-controlled` : 'user-controlled'}
                style={{
                  color: ACCENT,
                  fontWeight: 700,
                  backgroundColor: 'rgba(220,53,69,0.14)',
                  borderRadius: '2px',
                }}>{p.text}</span>
            ) : <span key={i}>{p.text}</span>))}
          </pre>
        )}

        {request?.note && (
          <div className="text-white-50 fst-italic" style={{ fontSize: '0.72rem' }}>
            {request.note}
          </div>
        )}
      </div>

      <div className="col-lg-5">
        <div className="text-danger small fw-bold mb-1">Notes</div>
        <Form.Control
          as="textarea"
          rows={6}
          className="bg-dark text-white border-secondary custom-input"
          style={{ fontSize: '0.8rem' }}
          placeholder="What you tried, what came back, what to test next."
          value={note}
          onChange={(e) => onNoteChange(e.target.value)}
        />
        <div className="d-flex justify-content-between align-items-center mt-2">
          <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
            {vector.sources?.length ? `found by ${vector.sources.join(', ')}` : ''}
          </span>
          <Button size="sm" variant="danger" onClick={onSaveNote} disabled={saving}>
            {saving ? <Spinner animation="border" size="sm" /> : 'Save Note'}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default AttackVectorsModal;
