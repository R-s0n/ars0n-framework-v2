import { Modal, Button, Form, Badge, Spinner, Alert, Nav } from 'react-bootstrap';
import { Fragment, useState, useEffect, useCallback } from 'react';
import ReflectionResultsPanel, { survivedSummary } from './ReflectionResultsPanel';
import {
  reflectionBadge, vectorGrade, vectorReflectionStatus, probeAsVector, REFLECTION_FILTERS,
  matchesReflectionFilter, GRADE_LABEL,
} from '../data/reflectionGrades';

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
  // Toned like query and body rather than like the ambient points, because a fragment is chosen by
  // whoever composes the link. It is also the only point no HTTP tool can test, so a row wearing
  // this badge is a row only domdig will ever have touched.
  fragment: 'border-warning text-warning',
};

// What the reflection probe found, as a word and then a colour.
//
// Never a bare colour, and never omitted for a vector that has not been probed. "Not Probed",
// "Blocked", "Probe Error" and "Needs Browser" are four different reasons the framework cannot
// answer the question, and an empty cell for any of them would be read as clean. The colours come
// from the shared vocabulary so this list, the tool config modal and the workflow card agree.
const ReflectionBadge = ({ vector }) => {
  const b = reflectionBadge(vector);
  return (
    <span
      title={b.why}
      style={{
        display: 'inline-block',
        fontSize: '0.6rem',
        lineHeight: 1.5,
        padding: '0 0.4em',
        borderRadius: '0.25rem',
        border: `1px solid ${b.border}`,
        background: b.background,
        color: b.color,
        whiteSpace: 'nowrap',
      }}
    >
      {b.label}
    </span>
  );
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
  // Two views of the same probe, and they are not redundant. The vector list is the roll-up the
  // operator scans FROM; the probe list is the per-input evidence they read AFTER Investigate. A
  // tab rather than a fourth modal: same data, same target, and the reflection filter over there
  // is the thing the operator is usually holding when they want this.
  const [tab, setTab] = useState('vectors');
  // Bumped by the footer's Refresh so the button is not dead on the probe tab: the panel keys off
  // it and refetches. A button that does nothing on one tab teaches the operator to distrust it.
  const [reloadKey, setReloadKey] = useState(0);
  const [counts, setCounts] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [pointFilter, setPointFilter] = useState('');
  const [hostFilter, setHostFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [signalFilter, setSignalFilter] = useState('');
  // Alongside pointFilter rather than folded into it: an operator narrowing to query vectors and an
  // operator narrowing to the ones that reflect are asking two different questions, and the useful
  // move is usually both at once.
  const [reflectionFilter, setReflectionFilter] = useState('');
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
        // Sent only for a fragment vector. The server clears it on every other point anyway, and
        // sending the old hash along with a move to query would ask it to keep something it is
        // about to drop.
        fragment: editing.insertion_point === 'fragment' ? (editing.fragment || '') : '',
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
  // Counted the same way the other filters are, and an option with no rows is left out, so the list
  // never offers a choice that empties the table. The one exception it deliberately keeps is "Never
  // probed": on a target nobody has probed that is every row, and the operator needs to be able to
  // find them.
  const reflectionOptions = REFLECTION_FILTERS
    .map((f) => [f.key, f.label, vectors.filter(f.match).length])
    .filter((o) => o[2] > 0);

  const highCandidates = vectors.filter((v) => vectorGrade(v) === 'xss_candidate_high').length;

  const term = search.toLowerCase();
  const shown = vectors.filter((v) => {
    if (!matchesReflectionFilter(v, reflectionFilter)) return false;
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
        <Nav variant="tabs" activeKey={tab} onSelect={(k) => k && setTab(k)} className="mb-3">
          <Nav.Item>
            <Nav.Link eventKey="vectors">Attack Vectors</Nav.Link>
          </Nav.Item>
          <Nav.Item>
            <Nav.Link eventKey="probes"
              title="Every input the reflection probe touched, worst first, including the ones it could not answer for.">
              Reflection Results
            </Nav.Link>
          </Nav.Item>
        </Nav>

        {/* Mounted only when opened, so the probe rows are not fetched for an operator who came
            here to edit a vector. */}
        {tab === 'probes' && (
          <ReflectionResultsPanel key={reloadKey} activeTarget={activeTarget} />
        )}

        {tab === 'vectors' && (
        <>
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

          <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
            value={reflectionFilter} onChange={(e) => setReflectionFilter(e.target.value)}
            title="What the reflection probe found: whether a canary sent through this vector came back, and whether the response was something a browser renders.">
            <option value="">Any reflection result</option>
            {reflectionOptions.map(([key, label, n]) => (
              <option key={key} value={key}>{label} ({n})</option>
            ))}
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
            {/* The headline figure, in the accent colour, because it is the one number on this
                screen that says where to start. Suppressed at zero rather than shown as "0 XSS
                High", which would read as a probe result on a target nobody has probed. */}
            {highCandidates > 0 && (
              <span className="text-danger">
                {` · ${highCandidates} ${GRADE_LABEL.xss_candidate_high}`}
              </span>
            )}
          </span>
        </div>

        {loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : shown.length === 0 ? (
          // Two different empty tables, and only one of them is fixed by consolidating. Telling an
          // operator who has filtered to "XSS High only" to go and run Consolidate sends them to
          // redo work already done; the list is full, their filter matched nothing.
          <Alert variant="dark" className="border-secondary text-white-50">
            {vectors.length === 0 ? (
              <>
                No attack vectors yet. Run <strong>Consolidate</strong> to build them from everything
                the crawls, the archives, Arjun, x8 and FFUF found, or add one by hand.
              </>
            ) : (
              <>
                None of the {vectors.length} attack vectors match these filters.
              </>
            )}
          </Alert>
        ) : (
          <table className="table table-dark table-sm align-middle">
            <thead>
              <tr className="text-white-50" style={{ fontSize: '0.72rem', textTransform: 'uppercase' }}>
                <th>Verb</th><th>Host</th><th>Path</th><th>Insertion</th><th>Reflection</th>
                <th>Parameters</th>
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
                  <td className="text-truncate" style={{ maxWidth: '300px' }}
                    title={v.fragment ? `${v.path}#${v.fragment}` : v.path}>
                    <code className="text-light small">{v.path}</code>
                    {/* Without this, two fragment vectors on one path are two identical looking rows:
                        the hash is the only thing that tells #/billing from #/profile. */}
                    {v.fragment ? <code className="text-warning small">#{v.fragment}</code> : null}
                  </td>
                  <td>
                    <Badge bg="dark" className={`border ${POINT_TONE[v.insertion_point] || ''}`}>
                      {v.insertion_point}
                    </Badge>
                    <Assumed when={v.insertion_confidence === 'implied'}>
                      Arjun derives the place from the verb rather than measuring it.
                    </Assumed>
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <ReflectionBadge vector={v} />
                    {/* The content type sits under the badge for a reflecting row, because it is
                        the difference between XSS High and XSS Low and the operator should not
                        have to hover to learn which one they are looking at. */}
                    {v.reflection_content_type
                      && vectorReflectionStatus(v).startsWith('reflected_') && (
                      <div className="text-white-50" style={{ fontSize: '0.6rem' }}>
                        {String(v.reflection_content_type).split(';')[0]}
                      </div>
                    )}
                  </td>
                  <td className="text-truncate" style={{ maxWidth: '280px' }}
                    title={(v.parameters || []).join(', ')}>
                    <code className="text-light small">
                      {(v.parameters || []).join(', ') || 'none'}
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
                    {/* Eight, not seven: the Reflection column above is counted here too, and a
                        colSpan short by one leaves an empty cell that shifts the whole detail row. */}
                    <td colSpan={8} className="p-3" style={{ backgroundColor: '#161616' }}>
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
        </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" disabled={loading}
          onClick={() => { load(); setReloadKey((k) => k + 1); }}>Refresh</Button>
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
                    {['query', 'body', 'header', 'cookie', 'path', 'fragment'].map((p) => (
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
              {editing.insertion_point === 'fragment' ? (
                <>
                  <Form.Label className="text-white small mt-2">Fragment</Form.Label>
                  <Form.Control size="sm" className="bg-dark text-white border-secondary custom-input"
                    placeholder="/billing, or access_token=...&token_type=..."
                    value={editing.fragment || ''}
                    onChange={(e) => setEditing({ ...editing, fragment: e.target.value })} />
                  <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem' }}>
                    The part after the #, as the browser holds it. It is what domdig is pointed at,
                    so a fragment vector without one tests nothing and is refused. A route carrying
                    its own query, #/connect/edit?tab=x, fills the parameters in for you.
                  </div>
                </>
              ) : null}
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
// Exported for the test that pins the Survived column. The vector-detail table is the other
// renderer of a probe row, and it is the one that used to print a yellow dash for a blocked
// input and for a clean one alike.
export const VectorDetail = ({ vector, request, note, onNoteChange, onSaveNote, saving }) => {
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

        {/* THE PROBE'S OWN ROWS, one per parameter, when the list endpoint carried them.
            The vector's badge is a roll-up of these, and a roll-up hides the useful part: a vector
            with five parameters where exactly one reflects is a vector with one thing to test. The
            evidence snippet is the proof that the canary really came back, which is what stops a
            status being taken on faith. */}
        {(vector.reflection_probes || []).length > 0 && (
          <div className="mt-3">
            <div className="text-danger small fw-bold mb-1">What the reflection probe found</div>
            <table className="table table-dark table-sm mb-0" style={{ fontSize: '0.72rem' }}>
              <thead>
                <tr className="text-white-50">
                  <th>Input</th><th>Result</th><th>How</th><th>Survived</th><th>Answered</th>
                </tr>
              </thead>
              <tbody>
                {vector.reflection_probes.map((p, i) => {
                  // The SAME reader one tab over uses. A blocked row and a row that was sent
                  // and came back clean both have an empty survived list, and this column used
                  // to print a yellow dash for both: the one case where nothing is known read
                  // exactly like the one case where everything is.
                  const surv = survivedSummary(p.survived, p.status);
                  return (
                  <Fragment key={`${p.parameter || 'path'}-${i}`}>
                    <tr>
                      <td className="text-light">
                        <code>{p.parameter || (p.insertion_point === 'path' ? 'path segment' : 'value')}</code>
                      </td>
                      {/* probeAsVector, never a hand-built object: this call site used to pass
                          status and content type alone, so the badge re-derived a grade from two
                          of the four fields it needs and showed XSS High on every raw reflection,
                          including the ones the server graded low or chain. */}
                      <td><ReflectionBadge vector={probeAsVector(p)} /></td>
                      {/* Which pass answered this input. A passive row was read out of an exchange
                          the crawl already stored and cost the target nothing; an active row is a
                          canary that was sent. Two different claims, so the table says which
                          rather than leaving it to be guessed from the status. */}
                      <td className="text-white-50">
                        {p.evidence_source === 'passive' ? 'stored' : 'probe'}
                      </td>
                      {/* The characters that came back unencoded, printed literally, then WHICH
                          KIND they are. An angle bracket opens a tag and a lone quote does not,
                          and a dash on a row nothing was ever sent to is not a clean result. */}
                      <td title={surv.note}
                        style={{ color: surv.markup ? '#dc3545' : 'rgba(255,255,255,0.5)' }}>
                        <code style={{ color: 'inherit' }}>{surv.chars.join(' ') || '-'}</code>
                        {surv.markup && surv.chars.length > 0 && (
                          <span className="ms-1" style={{ fontSize: '0.65rem' }}>opens a tag</span>
                        )}
                        {surv.weak && (
                          <span className="ms-1" style={{ fontSize: '0.65rem' }}>quotes only</span>
                        )}
                        {!surv.measured && (
                          <span className="ms-1 text-warning" style={{ fontSize: '0.65rem' }}>not measured</span>
                        )}
                      </td>
                      <td className="text-white-50">
                        {p.http_status ? `${p.http_status} ` : ''}
                        {String(p.content_type || '').split(';')[0] || '-'}
                      </td>
                    </tr>
                    {/* WHY, AND ONLY HERE. The reason an input was refused, blocked, or answered
                        without a request is a fact about that one input, so it sits under that one
                        input. It used to be summarised onto the Consolidate card as a paragraph,
                        where it described nothing in particular and was too long to read. */}
                    {p.detail && (
                      <tr>
                        <td colSpan={5} className="text-white-50 fst-italic pt-0"
                          style={{ fontSize: '0.68rem', borderTop: 'none' }}>
                          {p.detail}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                  );
                })}
              </tbody>
            </table>
            {vector.reflection_probes.some((p) => p.evidence) && (
              <pre className="text-light small p-2 rounded mt-2 mb-0" style={{
                backgroundColor: '#0d0d0d', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                fontSize: '0.7rem', maxHeight: '140px', overflowY: 'auto',
              }}>
                {vector.reflection_probes
                  .filter((p) => p.evidence)
                  .map((p) => `${p.parameter || 'path'}: ${p.evidence}`)
                  .join('\n')}
              </pre>
            )}
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
