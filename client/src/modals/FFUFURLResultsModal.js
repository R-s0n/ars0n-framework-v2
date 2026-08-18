import { useState, useEffect, useCallback } from 'react';
import { Modal, Button, Badge, Form, Alert, Spinner } from 'react-bootstrap';

// Accumulated fuzz findings for a target.
//
// These do not reset between runs. A finding is identified by the step, the URL and the payload, so
// re-running a flow bumps times_seen on something already known and inserts only what is genuinely
// new. That is what makes "what appeared since last time" answerable, and it is why the status and
// size are deliberately NOT part of a finding's identity: a 403 that becomes a 200 is the same
// finding changing, which is the most interesting thing this can report.

const STATUS_TONE = (status) => {
  if (status >= 500) return 'border-danger text-danger';
  if (status >= 400) return 'border-secondary text-white-50';
  if (status >= 300) return 'border-secondary text-light';
  return 'border-danger text-danger'; // 2xx on a fuzzed position is the interesting case
};

// PAGE_SIZE is asked for explicitly. The API's own default is smaller, and reading a page while
// printing its length as the total is the exact bug this file used to have: 5080 stored rows were
// reported as "200 of 200 findings", which is the page agreeing with itself.
const PAGE_SIZE = 1000;

const PRE = {
  backgroundColor: '#0d0d0d',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
  maxHeight: '320px',
  overflowY: 'auto',
};

// One expanded finding: the request that produced it, with the payload's span marked, and a curl to
// replay it.
//
// The request is rendered from parts rather than from a string with markers in it, so a payload
// containing angle brackets or quotes cannot break the view or be mistaken for framework text.
// highlightPayload marks the payload inside bytes the framework did not compose, so the operator can
// see where it landed in the request ffuf really sent. Split on the value rather than injecting
// markup, so a payload containing angle brackets cannot break the view.
const highlightPayload = (text, positions) => {
  // The position that carried the payload wins. In sniper the others are sitting at resting values
  // that are also present in these bytes, and marking the longest of them would point at the one part
  // of the request that did not change.
  const carried = (positions || []).filter((p) => p.carried).map((p) => p.value).filter(Boolean);
  const value = carried.length
    ? carried.sort((a, b) => b.length - a.length)[0]
    : (positions || []).map((p) => p.value).filter(Boolean).sort((a, b) => b.length - a.length)[0];
  if (!value || !text.includes(value)) return text;
  const out = [];
  text.split(value).forEach((chunk, i) => {
    if (i > 0) {
      out.push(
        <span key={`h${i}`} style={{
          backgroundColor: 'rgba(220,53,69,0.35)',
          outline: '1px solid rgba(220,53,69,0.8)',
          borderRadius: '2px',
        }}>{value}</span>,
      );
    }
    out.push(<span key={`t${i}`}>{chunk}</span>);
  });
  return out;
};

// The word that was actually sent, without the keyword bookkeeping around it.
//
// A payload is stored as ffuf reported it: "FUZZP01=admin", or "FUZZP01=a&FUZZP02=b" when a step
// fuzzes more than one position, or "FUZZ=admin" in sniper mode where ffuf names every slot the same.
// The keyword is the framework's own generated label and tells the operator nothing; the word is the
// whole content of the column.
//
// Split on the keyword boundary rather than on "&", because a wordlist entry may itself contain both
// "&" and "=", and anything that does not match the shape is shown UNCHANGED rather than mangled.
const payloadWords = (payload) => {
  if (!payload) return '';
  const parts = String(payload).split(/(?:^|&)(?:FUZZP\d+|FUZZ)=/).filter((p) => p !== '');
  return parts.length ? parts.join('  ·  ') : payload;
};

// The triage states, and how each is drawn.
//
// Interesting is the only one in the accent colour: it is the operator's own mark that a row deserves
// more work, and it should stand out from both the untouched rows and the ones already written off.
// Dismissed is deliberately dim rather than red, because it is a routine outcome and colouring it
// like a problem trains the eye to ignore the colour.
const TRIAGE_STYLE = {
  new: { className: 'border-secondary text-white-50', label: 'new' },
  interesting: { className: 'border-danger text-danger', label: 'interesting' },
  dismissed: { className: 'border-secondary text-white-50', label: 'dismissed', dim: true },
};

const TriageBadge = ({ state, className = '' }) => {
  const s = TRIAGE_STYLE[state] || TRIAGE_STYLE.new;
  return (
    <Badge
      bg="dark"
      className={`border ${s.className} ${className}`}
      style={{ fontSize: '0.65rem', letterSpacing: '0.05em', opacity: s.dim ? 0.6 : 1 }}
      title={`This finding is marked ${s.label}`}
    >
      {s.label}
    </Badge>
  );
};

// How many rows survived their control, for the filter labels.
const tallyTriage = (findings) => {
  const counts = { new: 0, interesting: 0, dismissed: 0 };
  (findings || []).forEach((f) => { counts[f.triage || 'new'] += 1; });
  return counts;
};

const tallyVerdicts = (findings) => {
  const counts = { same: 0, differs: 0, none: 0 };
  (findings || []).forEach((f) => { counts[f.baseline_verdict || 'none'] += 1; });
  return counts;
};

// What a column sorts on. Kept beside the table so a column added to one is not forgotten in the
// other, and numeric columns sort as numbers rather than as the strings they render to.
const sortValue = (f, key) => {
  switch (key) {
    case 'http_status': return f.http_status || 0;
    case 'response_size': return f.response_size || 0;
    case 'first_seen': return new Date(f.first_seen || 0).getTime();
    case 'step_ordinal': return f.step_ordinal >= 0 ? f.step_ordinal : 9999;
    case 'payload': return payloadWords(f.payload).toLowerCase();
    case 'method': return (f.method || '').toLowerCase();
    default: return (f.url || '').toLowerCase();
  }
};

const FindingDetail = ({ detail, onTriage }) => {
  // Which exchange the panes show. Hooks run before the early returns below, because a component may
  // not call a different number of them on different renders.
  const [pane, setPane] = useState('ffuf');

  if (!detail) {
    return <div className="text-white-50 small"><Spinner animation="border" size="sm" /> loading</div>;
  }
  if (detail.error) {
    return <div className="text-danger small">{detail.error}</div>;
  }

  const copy = (text) => { navigator.clipboard?.writeText(text); };
  const r = detail.response || {};
  const baseline = detail.baseline;
  const showBaseline = pane === 'baseline' && baseline;

  // Which exchange the panes below are showing. The ffuf request and the control differ by exactly
  // one thing, the payload, so they are the same view twice rather than two different views.
  const exchange = showBaseline
    ? {
      request: baseline.request,
      response: baseline.response,
      truncated: baseline.truncated,
      total_bytes: baseline.total_bytes,
    }
    : detail.evidence;

  return (
    <>
      <BaselineCompare detail={detail} />

      <div className="row g-3">
      <div className="col-lg-7">
        {/* The captured exchange when the run recorded one. It beats the reconstruction on every
            axis: it is what went on the wire rather than what the framework believes went on the
            wire, and it is the only thing that carries a response body. */}
        {(detail.evidence || baseline) ? (
          <>
            {/* Tabs rather than two stacked panes. The interesting comparison is between the same
                lines of two responses, and that is a thing you flip between rather than scroll. */}
            {baseline && (
              <div className="d-flex gap-1 mb-2">
                {[['ffuf', 'FFUF'], ['baseline', `Baseline (${baseline.canary || 'canary'})`]]
                  .map(([key, label]) => (
                    <Button key={key} size="sm"
                      variant={pane === key ? 'danger' : 'outline-secondary'}
                      onClick={() => setPane(key)}>{label}</Button>
                  ))}
              </div>
            )}
            {detail.evidence?.stale && !showBaseline && (
              <div className="text-warning small mb-1">
                These bytes are from an earlier run than the numbers above.
              </div>
            )}
            <div className="d-flex justify-content-between align-items-baseline">
              <span className="text-danger small fw-bold">
                {showBaseline ? 'The request the baseline sent' : 'The request ffuf sent'}
              </span>
              {!showBaseline && detail.evidence?.request_truncated && (
                <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
                  first {detail.evidence.request.length} of {detail.evidence.request_total_bytes} bytes
                </span>
              )}
            </div>
            <pre className="text-light small p-2 rounded mb-2" style={PRE}>
              {showBaseline
                ? highlightPayload(exchange?.request || '', [{ carried: true, value: baseline.canary }])
                : highlightPayload(exchange?.request || '', detail.positions)}
            </pre>
            <div className="d-flex justify-content-between align-items-baseline">
              <span className="text-danger small fw-bold">
                {showBaseline ? 'What the baseline got back' : 'The response it got back'}
              </span>
              {exchange?.truncated && (
                <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
                  first {(exchange.response || '').length} of {exchange.total_bytes} bytes
                </span>
              )}
            </div>
            <pre className="text-light small p-2 rounded mb-2" style={PRE}>
              {exchange?.response}
            </pre>
            {!showBaseline && detail.evidence?.note && (
              <div className="text-white-50 fst-italic mb-2" style={{ fontSize: '0.72rem' }}>
                {detail.evidence.note}
              </div>
            )}
          </>
        ) : null}
        <div className="text-danger small fw-bold mb-1">
          {detail.evidence ? 'The step template, with the position marked' : 'The request that produced this'}
        </div>
        {detail.request_parts ? (
          <pre className="text-light small p-2 rounded mb-2" style={PRE}>
            {detail.request_parts.map((p, i) => {
              if (!p.injected) return <span key={i}>{p.text}</span>;
              // A marked position that did not carry this payload is drawn as an outline only. It is
              // still a position, but for THIS request it was just a resting value like any other
              // byte around it, and filling it in red claims otherwise.
              const style = p.carried
                ? {
                  backgroundColor: 'rgba(220,53,69,0.35)',
                  outline: '1px solid rgba(220,53,69,0.8)',
                  borderRadius: '2px',
                }
                : {
                  outline: '1px dashed rgba(255,255,255,0.35)',
                  borderRadius: '2px',
                  opacity: 0.75,
                };
              const title = p.carried
                ? `${p.token} (${p.role}) carried this payload`
                : `${p.token} (${p.role}) held its resting value for this request`;
              return <span key={i} title={title} style={style}>{p.text}</span>;
            })}
          </pre>
        ) : (
          <div className="text-white-50 small mb-2">{detail.request_note}</div>
        )}
        {detail.position_note && (
          <div className="text-warning fst-italic mb-2" style={{ fontSize: '0.72rem' }}>
            {detail.position_note}
          </div>
        )}
        {detail.response_note && (
          <div className="text-white-50 fst-italic mb-2" style={{ fontSize: '0.72rem' }}>
            {detail.response_note}
          </div>
        )}
        {detail.curl && (
          <>
            <div className="d-flex justify-content-between align-items-baseline">
              <span className="text-danger small fw-bold">Replay it</span>
              <Button size="sm" variant="link" className="p-0 text-white-50"
                style={{ fontSize: '0.72rem' }} onClick={() => copy(detail.curl)}>copy</Button>
            </div>
            <pre className="text-light p-2 rounded" style={{ ...PRE, fontSize: '0.72rem' }}>
              {detail.curl}
            </pre>
          </>
        )}
      </div>

      <div className="col-lg-5">
        <div className="text-danger small fw-bold mb-1">Where the payload landed</div>
        {(detail.positions || []).map((p) => (
          <div key={p.token} className="mb-2 small" style={{ opacity: p.carried ? 1 : 0.65 }}>
            <code className={p.carried ? 'text-danger' : 'text-white-50'}>{p.token}</code>
            <span className="text-white-50"> is </span>
            <span className="text-light">{p.where}</span>
            <div className="text-white-50" style={{ fontSize: '0.72rem' }}>
              value <code className="text-light">{p.value === '' ? '(empty)' : p.value}</code>
              {p.wordlist && p.carried
                ? <> from wordlist <code className="text-white-50">{p.wordlist}</code></>
                : null}
            </div>
          </div>
        ))}

        <div className="text-danger small fw-bold mb-1 mt-3">What came back</div>
        <div className="small text-white-50">
          <div>status <span className="text-light">{r.http_status}</span>,{' '}
            {r.size} bytes, {r.words} words, {r.lines} lines</div>
          {r.content_type && <div>content-type <span className="text-light">{r.content_type}</span></div>}
          {r.redirect_location && <div>redirects to <span className="text-light">{r.redirect_location}</span></div>}
        </div>

        <div className="text-danger small fw-bold mb-1 mt-3">Verdict</div>
        <div className="d-flex gap-1 mb-2">
          {['interesting', 'dismissed', 'new'].map((state) => (
            <Button key={state} size="sm"
              variant={detail.triage === state ? 'danger' : 'outline-secondary'}
              onClick={() => onTriage(detail.id, state)}>
              {state}
            </Button>
          ))}
        </div>
        <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
          Dismissed findings drop out of the default list and out of the notable count, so a wall of
          known noise stops being reread on every visit.
        </div>

        {detail.run_detail && (
          <div className="small text-white-50 mt-2" style={{ fontSize: '0.72rem' }}>
            <span className="text-danger">Run note:</span> {detail.run_detail}
          </div>
        )}
        {detail.command && (
          <details className="mt-2">
            <summary className="text-white-50 small" style={{ cursor: 'pointer' }}>
              the ffuf command that ran
            </summary>
            <pre className="text-light p-2 rounded mt-1" style={{ ...PRE, fontSize: '0.7rem' }}>
              {detail.command}
            </pre>
          </details>
        )}
      </div>
      </div>
    </>
  );
};

// The finding beside its control, which is the comparison that decides whether the row means
// anything.
//
// A status and a size on their own are not evidence. /admin answering 403 is only interesting if a
// value that cannot exist answers something else; when both answer 403 at the same length the
// endpoint is not distinguishing them and the row is the target's catch-all wearing a finding's
// clothes. Put at the very top because it is the first question to ask, not the last.
const BaselineCompare = ({ detail }) => {
  const b = detail.baseline;
  const r = detail.response || {};

  // The triage mark rides at the top whether or not a control exists, because "have I already looked
  // at this and written it off" is a question about the row itself, not about the comparison.
  if (!b) {
    return (
      <div className="d-flex align-items-start gap-2 mb-3">
        <TriageBadge state={detail.triage} />
        <div className="text-white-50" style={{ fontSize: '0.72rem' }}>
          {detail.baseline_note}
        </div>
      </div>
    );
  }

  const same = b.verdict === 'same';
  const cell = (label, value, muted) => (
    <div className="pe-4">
      <div className="text-white-50" style={{ fontSize: '0.65rem', letterSpacing: '0.06em' }}>
        {label.toUpperCase()}
      </div>
      <div style={{
        fontSize: '1.05rem',
        fontWeight: 700,
        fontVariantNumeric: 'tabular-nums',
        color: muted ? 'rgba(255,255,255,0.55)' : '#f2f2f2',
      }}>{value}</div>
    </div>
  );

  return (
    <div
      className="rounded p-2 mb-3"
      style={{
        // Red means "this row survived its control". A row that matches its baseline is the wall, and
        // colouring that like a finding is how an operator learns to ignore the colour.
        border: `1px solid ${same ? 'rgba(255,255,255,0.15)' : 'rgba(220,53,69,0.55)'}`,
        backgroundColor: same ? 'transparent' : 'rgba(220,53,69,0.07)',
      }}
    >
      <div className="d-flex align-items-center flex-wrap">
        {/* The server sends http_status and size on the finding, and http_status and response_size on
            the baseline. Reading the wrong name here is invisible in a build and shows as a dash on
            every row, which is how "FFUF status" read as unknown while the number sat in the payload.
            `??` rather than `||` throughout: a status of 0 and a size of 0 are real measurements, and
            a zero-length body is exactly the kind of answer worth noticing. */}
        {cell('FFUF status', r.http_status ?? '-', false)}
        {cell('Baseline status', b.http_status ?? '-', same)}
        {cell('FFUF size', r.size == null ? '-' : r.size.toLocaleString(), false)}
        {cell('Baseline size', b.response_size == null ? '-' : b.response_size.toLocaleString(), same)}
        <div className="ms-auto text-end d-flex align-items-center gap-2">
          <TriageBadge state={detail.triage} />
          <Badge bg="dark" className={`border ${same ? 'border-secondary text-white-50' : 'border-danger text-danger'}`}>
            {same ? 'same as baseline' : 'differs from baseline'}
          </Badge>
        </div>
      </div>
      <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem', lineHeight: 1.35 }}>
        {b.note}
      </div>
    </div>
  );
};

export const FFUFURLResultsModal = ({ show, handleClose, activeTarget, onFindingsChanged }) => {
  const [findings, setFindings] = useState([]);
  const [total, setTotal] = useState(0);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('');
  // Filters, all built from the rows actually loaded so a select can never offer a status, a method
  // or a step that would match nothing.
  const [statusFilter, setStatusFilter] = useState('');
  const [methodFilter, setMethodFilter] = useState('');
  const [stepFilter, setStepFilter] = useState('');
  const [minSize, setMinSize] = useState('');
  const [maxSize, setMaxSize] = useState('');
  // The control comparison as a filter. On a real flow this is the difference between reading 344
  // rows and reading the 283 that answered differently from a value that cannot exist.
  const [baselineFilter, setBaselineFilter] = useState('');
  // Empty means the default view: everything except what has been written off. Dismissed rows are
  // fetched either way so they can be filtered back in, which is the whole point of marking them.
  const [triageFilter, setTriageFilter] = useState('');
  // Status ascending puts the 200s at the top, which is where a content-discovery run is read from:
  // a 2xx on a fuzzed position is the finding, and the 403s and 404s below it are the wall.
  const [sort, setSort] = useState({ key: 'http_status', dir: 'asc' });
  // Expanded rows, and the detail fetched for each. Detail is loaded on demand rather than with the
  // list: it reconstructs a request per finding, and pulling that for a thousand rows nobody opens
  // would be waste.
  const [expanded, setExpanded] = useState({});
  const [details, setDetails] = useState({});

  // Declared before its callers. `load` is a const, so naming it in a dependency array that runs
  // earlier in the same scope reads it inside the temporal dead zone and throws on EVERY render,
  // which does not fail the build and takes the whole modal down at runtime.
  const load = useCallback(async () => {
    if (!activeTarget) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(
        `/api/fuzz/${activeTarget.id}/findings?tool=ffuf&limit=${PAGE_SIZE}&triage=all`);
      if (!res.ok) {
        setError('Could not load findings');
        return;
      }
      const data = await res.json();
      setFindings(data.findings || []);
      // The real row count, which is not the number of rows in this response.
      setTotal(typeof data.total === 'number' ? data.total : (data.findings || []).length);
      setTruncated(!!data.truncated);
    } catch (err) {
      setError('Could not load findings: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);

  const setTriage = useCallback(async (id, state) => {
    try {
      await fetch('/api/fuzz/findings/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_ids: [id], triage: state }),
      });
      // Both are refreshed: the panel so the chosen state is reflected, the list because dismissing
      // removes the row from the default view and the count has to agree with what is on screen.
      const res = await fetch(`/api/fuzz/findings/${id}`);
      if (res.ok) {
        const data = await res.json();
        setDetails((prev) => ({ ...prev, [id]: data }));
      }
      await load();
      // The card outside this modal is showing counts fetched independently, and dismissing a row
      // changes both of them.
      if (onFindingsChanged) onFindingsChanged();
    } catch (err) {
      setError('Could not save that verdict: ' + err.message);
    }
  }, [load, onFindingsChanged]);

  const toggleRow = useCallback(async (id) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
    if (details[id]) return;
    try {
      const res = await fetch(`/api/fuzz/findings/${id}`);
      // Resolved before the updater runs: a setState callback is not async, so awaiting inside it is
      // a syntax error rather than a race.
      const data = res.ok ? await res.json() : { error: 'Could not load this finding' };
      setDetails((prev) => ({ ...prev, [id]: data }));
    } catch (err) {
      setDetails((prev) => ({ ...prev, [id]: { error: err.message } }));
    }
  }, [details]);

  useEffect(() => { if (show) load(); }, [show, load]);

  const term = filter.toLowerCase();
  const lo = minSize === '' ? null : Number(minSize);
  const hi = maxSize === '' ? null : Number(maxSize);

  const shown = findings.filter((f) => {
    if (term
      && !(f.url || '').toLowerCase().includes(term)
      && !(f.payload || '').toLowerCase().includes(term)
      && !String(f.http_status).includes(term)) return false;
    if (statusFilter && String(f.http_status) !== statusFilter) return false;
    if (methodFilter && f.method !== methodFilter) return false;
    if (stepFilter && String(f.step_ordinal) !== stepFilter) return false;
    if (triageFilter === '' && f.triage === 'dismissed') return false;
    if (triageFilter && triageFilter !== 'all' && f.triage !== triageFilter) return false;
    if (baselineFilter && (f.baseline_verdict || 'none') !== baselineFilter) return false;
    if (lo !== null && (f.response_size || 0) < lo) return false;
    if (hi !== null && (f.response_size || 0) > hi) return false;
    return true;
  }).sort((a, b) => {
    const dir = sort.dir === 'asc' ? 1 : -1;
    const va = sortValue(a, sort.key);
    const vb = sortValue(b, sort.key);
    if (va < vb) return -1 * dir;
    if (va > vb) return 1 * dir;
    // Same key, so fall to something stable. Without it the list reshuffles on every re-render and
    // a row an operator is reading moves out from under them.
    return (a.url || '').localeCompare(b.url || '');
  });

  // Options counted from what is loaded. Offering a value that matches nothing is how a filter
  // teaches an operator to distrust it.
  const tally = (values) => {
    const counts = new Map();
    values.forEach((v) => counts.set(v, (counts.get(v) || 0) + 1));
    return [...counts.entries()].sort((x, y) => y[1] - x[1]);
  };
  const statusOptions = tally(findings.map((f) => String(f.http_status || '')).filter(Boolean));
  const methodOptions = tally(findings.map((f) => f.method).filter(Boolean));
  const stepOptions = tally(findings.filter((f) => f.step_ordinal >= 0)
    .map((f) => String(f.step_ordinal)));
  const baselineCounts = tallyVerdicts(findings);
  const triageCounts = tallyTriage(findings);
  const filtersOn = !!(statusFilter || methodFilter || stepFilter || minSize || maxSize || filter
    || baselineFilter || triageFilter);
  const clearFilters = () => {
    setFilter('');
    setStatusFilter('');
    setMethodFilter('');
    setStepFilter('');
    setMinSize('');
    setMaxSize('');
    setBaselineFilter('');
    setTriageFilter('');
  };

  const toggleSort = (key) => setSort((prev) => (
    prev.key === key
      ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
      // A new column starts in the direction that puts its interesting end first: smallest status
      // (the 2xx), but largest size and most recent time.
      : { key, dir: key === 'http_status' || key === 'url' || key === 'payload' ? 'asc' : 'desc' }
  ));

  const SortHead = ({ label, sortKey, className = '' }) => (
    <th className={`${className} user-select-none`} style={{ cursor: 'pointer' }}
      onClick={() => toggleSort(sortKey)}>
      {label}
      <span className="ms-1" style={{ opacity: sort.key === sortKey ? 1 : 0.25 }}>
        {sort.key === sortKey ? (sort.dir === 'asc' ? '▲' : '▼') : '↕'}
      </span>
    </th>
  );

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-list-check me-2" />
          FFUF Findings
        </Modal.Title>
      </Modal.Header>

      <Modal.Body>
        {loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : error ? (
          <Alert variant="dark" className="border border-danger text-danger py-2">{error}</Alert>
        ) : findings.length === 0 ? (
          <Alert variant="dark" className="border border-secondary text-light py-3">
            Nothing found yet. Build a scan flow in <strong>Config</strong>, then hit{' '}
            <strong>Scan</strong>. Findings accumulate here across every run rather than being
            replaced.
          </Alert>
        ) : (
          <>
            <div className="d-flex flex-wrap gap-2 align-items-center mb-2">
              <Form.Control size="sm" style={{ maxWidth: '260px' }}
                placeholder="Filter by url, payload or status"
                value={filter} onChange={(e) => setFilter(e.target.value)} data-bs-theme="dark" />

              <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
                value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                <option value="">Any status</option>
                {statusOptions.map(([s, n]) => <option key={s} value={s}>{s} ({n})</option>)}
              </Form.Select>

              <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
                value={methodFilter} onChange={(e) => setMethodFilter(e.target.value)}>
                <option value="">Any method</option>
                {methodOptions.map(([m, n]) => <option key={m} value={m}>{m} ({n})</option>)}
              </Form.Select>

              <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
                value={triageFilter} onChange={(e) => setTriageFilter(e.target.value)}
                title="Your own mark on a row. Dismissed rows are hidden by default and can be brought back here.">
                <option value="">Not dismissed</option>
                <option value="new">New ({triageCounts.new})</option>
                <option value="interesting">Interesting ({triageCounts.interesting})</option>
                <option value="dismissed">Dismissed ({triageCounts.dismissed})</option>
                <option value="all">All ({findings.length})</option>
              </Form.Select>

              <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
                value={baselineFilter} onChange={(e) => setBaselineFilter(e.target.value)}
                title="Whether the response differs from the same request carrying a value that cannot exist.">
                <option value="">Any baseline</option>
                <option value="differs">Differs from baseline ({baselineCounts.differs})</option>
                <option value="same">Same as baseline ({baselineCounts.same})</option>
                <option value="none">No baseline yet ({baselineCounts.none})</option>
              </Form.Select>

              <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
                value={stepFilter} onChange={(e) => setStepFilter(e.target.value)}>
                <option value="">Any step</option>
                {stepOptions.map(([s, n]) => <option key={s} value={s}>step {s} ({n})</option>)}
              </Form.Select>

              {/* Size as a range rather than a list. The point of filtering on size is excluding one
                  uniform wall or isolating the few responses that carry a body, and neither is a
                  value you can pick off a menu. */}
              <Form.Control size="sm" type="number" min={0} style={{ width: '110px' }}
                data-bs-theme="dark" placeholder="min size"
                value={minSize} onChange={(e) => setMinSize(e.target.value)} />
              <Form.Control size="sm" type="number" min={0} style={{ width: '110px' }}
                data-bs-theme="dark" placeholder="max size"
                value={maxSize} onChange={(e) => setMaxSize(e.target.value)} />

              {filtersOn && (
                <Button size="sm" variant="outline-secondary" onClick={clearFilters}>Clear</Button>
              )}

              <div className="text-white-50 small ms-auto">
                showing {shown.length} of {filtersOn ? findings.length : total} finding{total === 1 ? '' : 's'}
                {filtersOn && total > findings.length && (
                  <span className="text-warning"> (filtering the {findings.length} loaded, not all {total})</span>
                )}
                {truncated && (
                  <span className="text-danger">
                    {' '}&middot; only the first {findings.length} are loaded
                  </span>
                )}
              </div>
            </div>

            <div style={{ maxHeight: '75vh', overflowY: 'auto' }}>
              <table className="table table-dark table-sm align-middle">
                <thead>
                  {/* Every column sorts. Step is last because it groups rows rather than ranking
                      them: which step found something matters once you have decided the row is
                      worth reading, not before. */}
                  <tr className="text-white-50">
                    <SortHead label="Status" sortKey="http_status" />
                    <SortHead label="Method" sortKey="method" />
                    <SortHead label="URL" sortKey="url" />
                    <SortHead label="Payload" sortKey="payload" />
                    <SortHead label="Size" sortKey="response_size" className="text-end" />
                    <SortHead label="First seen" sortKey="first_seen" />
                    <SortHead label="Step" sortKey="step_ordinal" />
                  </tr>
                </thead>
                <tbody>
                  {shown.map((f) => [
                    <tr key={f.id} onClick={() => toggleRow(f.id)} style={{ cursor: 'pointer' }}>
                      <td>
                        <span className="text-white-50 me-1" style={{ fontSize: '0.7rem' }}>
                          {expanded[f.id] ? '▾' : '▸'}
                        </span>
                        <Badge bg="dark" className={`border ${STATUS_TONE(f.http_status)}`}>
                          {f.http_status || '-'}
                        </Badge>
                        {/* The control, on the row rather than only inside the expanded panel. The
                            question "is this the wall" is asked of every row while scanning the list,
                            and answering it one expansion at a time is not scanning. */}
                        {typeof f.baseline_http_status === 'number' && (
                          <span
                            className={f.baseline_verdict === 'same' ? 'text-white-50 ms-1' : 'text-danger ms-1'}
                            style={{ fontSize: '0.7rem' }}
                            title={`baseline (${'rs0n'}) answered ${f.baseline_http_status}`}
                          >
                            vs {f.baseline_http_status}
                          </span>
                        )}
                        {/* A finding whose answer moved is the whole reason status is kept out of a
                            finding's identity, so it is called out on the row rather than buried. */}
                        {f.changed && (
                          <Badge bg="dark" className="border border-danger text-danger ms-1"
                            title={`was ${f.previous_http_status} / ${f.previous_response_size} bytes`}
                            style={{ fontSize: '0.6rem' }}>
                            was {f.previous_http_status}
                          </Badge>
                        )}
                        {f.triage === 'interesting' && (
                          <Badge bg="dark" className="border border-danger text-danger ms-1"
                            style={{ fontSize: '0.6rem' }} title="marked interesting">★</Badge>
                        )}
                        {f.triage === 'dismissed' && (
                          <Badge bg="dark" className="border border-secondary text-white-50 ms-1"
                            style={{ fontSize: '0.6rem', opacity: 0.6 }} title="marked dismissed">
                            dismissed
                          </Badge>
                        )}
                      </td>
                      <td className="text-white-50 small">{f.method}</td>
                      <td className="text-truncate" style={{ maxWidth: '420px' }} title={f.url}>
                        <code className="text-light small">{f.url}</code>
                      </td>
                      {/* The word, not the keyword. The raw payload stays on the tooltip and in the
                          expanded detail, which is where the position it landed in is named. */}
                      <td className="text-truncate" style={{ maxWidth: '260px' }} title={f.payload}>
                        <code className="text-light small">{payloadWords(f.payload)}</code>
                      </td>
                      <td className="text-end text-white-50 small">
                        {f.response_size}
                        {typeof f.baseline_response_size === 'number' && (
                          <span
                            className={f.baseline_verdict === 'same' ? 'text-white-50 ms-1' : 'text-danger ms-1'}
                            style={{ fontSize: '0.7rem', opacity: 0.85 }}
                            title={`baseline (rs0n) returned ${f.baseline_response_size} bytes`}
                          >
                            vs {f.baseline_response_size}
                          </span>
                        )}
                      </td>
                      <td className="text-white-50 small">
                        {new Date(f.first_seen).toLocaleString()}
                      </td>
                      {/* Which step produced it, last. Without it, rows from four steps against three
                          hosts are one undifferentiated list. */}
                      <td className="text-white-50 small" title={f.step_name || ''}>
                        {f.step_ordinal >= 0 ? f.step_ordinal : '-'}
                      </td>
                    </tr>,
                    expanded[f.id] && (
                      <tr key={`${f.id}-detail`}>
                        <td colSpan={7} className="p-3" style={{ backgroundColor: '#161616' }}>
                          <FindingDetail detail={details[f.id]} onTriage={setTriage} />
                        </td>
                      </tr>
                    ),
                  ])}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Modal.Body>

      <Modal.Footer>
        <Button variant="outline-danger" onClick={load} disabled={loading}>Refresh</Button>
        <Button variant="secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
};

export default FFUFURLResultsModal;
