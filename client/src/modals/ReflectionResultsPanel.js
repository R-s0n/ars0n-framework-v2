import { useState, useEffect, useCallback } from 'react';
import { Form, Spinner, Alert } from 'react-bootstrap';
import {
  reflectionBadge, vectorGrade, survivedMarkup, reflectionStatusRank, probeAsVector,
  GRADE_ORDER, GRADE_LABEL, REFLECTION_BADGE, REFLECTION_STATUS_RANK,
} from '../data/reflectionGrades';

// EVERY PROBE ROW THE INVESTIGATE PASS WROTE, worst first, with the filters that narrow it.
//
// The vector list one tab over is a ROLL-UP: one badge per vector, taken from its most interesting
// input. That is the right unit for choosing what to scan and the wrong unit for reading evidence.
// A vector with twenty-two inputs where one reflected and twenty-one were never sent wears one
// badge, and the twenty-one are invisible. This panel is the other view: one row per input, which is
// what GET /attack-vectors/{id}/reflection-probe/results has always returned and nothing in the
// client has ever asked for.
//
// THE RULE THIS SCREEN EXISTS TO KEEP is that NOT KNOWING IS NOT CLEAN. blocked, error,
// needs_browser, not_probed, is_credential and probe_refused are six different reasons the
// framework cannot answer, and the server grades all of them xss_unknown. They are counted on their
// own line, in their own colour, with the reason spelled out per status, so a target that refused
// every probe can never be read as a target with nothing on it.
//
// NOTHING IS RE-DERIVED HERE. The server sends `grade` per row and `vector_grade` per vector, both
// computed by XSSCandidateGrade in Go, and vectorGrade() below prefers that value. The local
// fallback in reflectionGrades.js is for an api container older than the field. Go is the authority.

// The four sort and filter helpers are exported so the test file can pin the ordering and the
// bucketing without mounting a table.

// Re-exported, not redefined: the shape a probe row takes when the shared reflection vocabulary
// reads it now lives in that vocabulary, because the vector list renders these rows too.
export { probeAsVector };

export const probeGrade = (p) => vectorGrade(probeAsVector(p));

// Worst first: the shared status ranking decides, and the grade only breaks a tie inside one status.
// That ordering is what puts blocked and error ABOVE not_reflected: a probe the target ate outranks
// a probe that came back empty, because one of them is news and the other is not.
export const byProbeInterest = (a, b) => {
  const ra = reflectionStatusRank(a && a.status);
  const rb = reflectionStatusRank(b && b.status);
  if (ra !== rb) return ra - rb;
  const gi = (p) => {
    const i = GRADE_ORDER.indexOf(probeGrade(p));
    return i === -1 ? GRADE_ORDER.length : i;
  };
  return gi(a) - gi(b);
};

export const sortProbes = (rows) => (rows || []).slice().sort(byProbeInterest);

// WHAT CAME BACK UNENCODED, and whether it is the character that matters.
//
// Measured on the first real run: 13 of 14 raw reflections survived only the single quote, because
// JSON escapes the double quote and the backslash and nothing else. A quote comes back from every
// JSON endpoint that echoes anything, so a row showing one is showing the response format rather
// than the application. An angle bracket is what opens a tag.
//
// A survived list that is not an array was never recorded, and that is treated as markup, exactly
// the way survivedMarkup() treats it: hiding a real candidate costs more than one look at a row.

// THE STATUSES WHERE THERE IS NO RESPONSE BODY TO HAVE MEASURED, and what to say instead.
//
// The server COALESCEs survived to an empty array, so a row where nothing was ever sent arrives
// looking exactly like a row that was sent and came back clean. Branching on the array alone put
// "Nothing came back unencoded." on the tooltip and on the first line of the expanded detail for
// blocked, not_probed, is_credential and probe_refused: a statement about a target nobody asked.
// The caption below depends on whether anything was sent, which is the fact the row actually has.
export const NOT_MEASURED_NOTE = {
  blocked: 'The probe was rejected before it reached the application, so there is no response '
    + 'body to have measured. Unknown, not clean.',
  error: 'The probe never completed, so there is no response body to have measured. Unknown, '
    + 'not clean.',
  needs_browser: 'A fragment never leaves the browser, so an HTTP probe had nothing to measure. '
    + 'domdig is the tool that can answer this.',
  is_credential: 'Nothing was sent: this input is the credential for this host, and a canary '
    + 'there throws the session away rather than testing the input.',
  probe_refused: 'Nothing was sent: the probe declined this request. The row detail says why.',
  not_probed: 'Nothing was sent. This input has never been probed.',
};

// Only these four statuses mean a response body was read and the characters in it counted.
// Anything else, INCLUDING A STATUS NEWER THAN THIS BUILD, has no measurement to report: an
// unrecognised status falling through to the clean sentence is the same defect one release later.
export const MEASURED_STATUSES = [
  'reflected_raw', 'reflected_observed', 'reflected_encoded', 'not_reflected',
];

export const survivedSummary = (survived, status) => {
  const s = String(status || 'not_probed');
  const recorded = Array.isArray(survived)
    ? survived.filter((c) => typeof c === 'string' && c !== '') : null;

  // Nothing recorded AND nothing measured: say which, rather than reporting the target clean.
  if (!MEASURED_STATUSES.includes(s) && !(recorded && recorded.length)) {
    return {
      chars: [], markup: false, weak: false, measured: false,
      note: NOT_MEASURED_NOTE[s] || 'No response body was measured for this input, so nothing '
        + 'here is a statement about the target.',
    };
  }
  if (!Array.isArray(survived)) {
    return {
      chars: [], markup: true, weak: false, measured: true,
      note: 'Not recorded. Counted as markup, the same way the grade counts it.',
    };
  }
  const chars = recorded;
  if (chars.length === 0) {
    return {
      chars: [], markup: false, weak: false, measured: true,
      // reflected_observed is the PASSIVE pass, where nothing was sent either. Its empty list
      // means the crawl's own value carried no dangerous character, not that one was encoded.
      note: s === 'reflected_observed'
        ? 'The value was found in a stored response. No dangerous character was in it to come '
          + 'back unencoded, because the crawl never sent one.'
        : 'The probe was sent and nothing came back unencoded.',
    };
  }
  if (survivedMarkup(chars)) {
    return {
      chars, markup: true, weak: false, measured: true,
      note: 'An angle bracket survived. That is the character that opens a tag.',
    };
  }
  return {
    chars, markup: false, weak: true, measured: true,
    note: 'No angle bracket. A lone quote is what JSON escaping always returns, and it cannot open '
      + 'a tag. It still matters for breaking out of an attribute or a JS string.',
  };
};

// WHICH PASS PRODUCED THE ROW, because the two are different strengths of claim and the status
// alone does not say which.
export const EVIDENCE_SOURCE = {
  passive: {
    label: 'stored',
    why: 'Read out of a request and response the crawl had already stored. NO TRAFFIC WAS SENT for '
      + 'this row, and the value is one the crawl happened to send, so no dangerous character was '
      + 'ever tested. It proves the input is echoed and nothing about the encoding.',
  },
  active: {
    label: 'probe',
    why: 'A canary this framework generated was sent to the target, and this is what came back. The '
      + 'characters in Survived are the ones that really made the round trip.',
  },
};

export const evidenceSource = (s) => EVIDENCE_SOURCE[String(s || 'active')] || EVIDENCE_SOURCE.active;

export const filterProbes = (rows, f) => {
  const q = f || {};
  const term = String(q.search || '').trim().toLowerCase();
  return (rows || []).filter((p) => {
    if (q.grade && probeGrade(p) !== q.grade) return false;
    if (q.status && (p.status || 'not_probed') !== q.status) return false;
    if (q.point && (p.insertion_point || '') !== q.point) return false;
    if (q.source && (p.evidence_source || 'active') !== q.source) return false;
    if (!term) return true;
    return `${p.domain || ''}${p.path || ''}${p.parameter || ''}${p.method || ''}`
      .toLowerCase().includes(term);
  });
};

// Counts in fixed key order, so a zero renders as a zero instead of vanishing from the line.
// notKnown is the count of rows the framework could not answer for, taken from the SERVER'S grade
// rather than from a list of status names kept here, so a status added to Go later lands in the
// right bucket without this file being edited.
export const summarise = (rows) => {
  const grades = {};
  GRADE_ORDER.forEach((g) => { grades[g] = 0; });
  const statuses = {};
  const notKnownStatuses = {};
  (rows || []).forEach((p) => {
    const g = probeGrade(p);
    grades[g] = (grades[g] || 0) + 1;
    const s = p.status || 'not_probed';
    statuses[s] = (statuses[s] || 0) + 1;
    if (g === 'xss_unknown') notKnownStatuses[s] = (notKnownStatuses[s] || 0) + 1;
  });
  return {
    total: (rows || []).length,
    grades,
    statuses,
    notKnown: grades.xss_unknown || 0,
    // Ranked, so the most interesting unknown is named first when the line only has room for a few.
    notKnownBreakdown: Object.entries(notKnownStatuses)
      .sort((a, b) => reflectionStatusRank(a[0]) - reflectionStatusRank(b[0])),
  };
};

// A ceiling on rendered rows, not on loaded ones. The counts above are computed over everything, so
// narrowing the filters never changes what the target is reported to have done.
export const MAX_ROWS = 300;

const GradeBadge = ({ probe }) => {
  const b = reflectionBadge(probeAsVector(probe));
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

function ReflectionResultsPanel({ activeTarget }) {
  const [probes, setProbes] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [grade, setGrade] = useState('');
  const [status, setStatus] = useState('');
  const [point, setPoint] = useState('');
  const [source, setSource] = useState('');
  const [open, setOpen] = useState({});

  // Fetched ONCE, unfiltered, and narrowed in the browser. The endpoint takes ?status, ?grade and
  // ?insertion_point, and using them here would mean the counts on the summary line described only
  // the rows that survived the filter, which is the same silent-clean reading this panel exists to
  // prevent: "0 blocked" while filtered to XSS High is not a fact about the target.
  const load = useCallback(async () => {
    if (!activeTarget) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/attack-vectors/${activeTarget.id}/reflection-probe/results`);
      if (!res.ok) {
        setError('Could not load reflection probe results.');
        return;
      }
      const data = await res.json();
      setProbes(data.probes || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);

  useEffect(() => { load(); }, [load]);

  const total = summarise(probes);
  const shownAll = sortProbes(filterProbes(probes, { search, grade, status, point, source }));
  const shown = shownAll.slice(0, MAX_ROWS);

  const tally = (values) => {
    const c = new Map();
    values.forEach((v) => c.set(v, (c.get(v) || 0) + 1));
    return [...c.entries()];
  };
  const pointOptions = tally(probes.map((p) => p.insertion_point || '')).sort((a, b) => b[1] - a[1]);
  const sentCount = probes.filter((p) => (p.evidence_source || 'active') === 'active').length;
  const gradeOptions = GRADE_ORDER
    .map((g) => [g, GRADE_LABEL[g] || g, total.grades[g] || 0])
    .filter((o) => o[2] > 0);
  const statusOptions = REFLECTION_STATUS_RANK
    .map((s) => [s, (REFLECTION_BADGE[s] || {}).label || s, total.statuses[s] || 0])
    .filter((o) => o[2] > 0);

  if (loading) {
    return <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>;
  }
  if (error) {
    return <Alert variant="danger" className="py-2 small">{error}</Alert>;
  }
  if (probes.length === 0) {
    return (
      <Alert variant="dark" className="border-secondary text-white-50">
        No reflection probe rows yet. Run <strong>Investigate</strong> on the Consolidate Attack
        Vectors card to find out what each input does with a canary.
      </Alert>
    );
  }

  return (
    <div>
      <div className="d-flex flex-wrap gap-2 align-items-center mb-3">
        <Form.Control size="sm" style={{ maxWidth: '280px' }} data-bs-theme="dark"
          className="custom-input"
          placeholder="Search host, path or parameter"
          value={search} onChange={(e) => setSearch(e.target.value)} />

        <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
          value={grade} onChange={(e) => setGrade(e.target.value)}
          title="How weaponisable the reflection is. The server computes this; the client only shows it.">
          <option value="">Any grade</option>
          {gradeOptions.map(([key, label, n]) => (
            <option key={key} value={key}>{label} ({n})</option>
          ))}
        </Form.Select>

        <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
          value={status} onChange={(e) => setStatus(e.target.value)}
          title="What the probe actually observed for this one input.">
          <option value="">Any probe result</option>
          {statusOptions.map(([key, label, n]) => (
            <option key={key} value={key}>{label} ({n})</option>
          ))}
        </Form.Select>

        <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
          value={point} onChange={(e) => setPoint(e.target.value)}>
          <option value="">Any insertion point</option>
          {pointOptions.map(([p, n]) => <option key={p} value={p}>{p || 'unknown'} ({n})</option>)}
        </Form.Select>

        <Form.Select size="sm" style={{ width: 'auto' }} data-bs-theme="dark"
          value={source} onChange={(e) => setSource(e.target.value)}
          title="Whether the row came from a canary that was sent, or from a request and response the crawl had already stored.">
          <option value="">Sent or stored</option>
          <option value="active">From a probe sent ({sentCount})</option>
          <option value="passive">From stored traffic ({probes.length - sentCount})</option>
        </Form.Select>

        <span className="text-white-50 ms-auto small">
          showing {shown.length}
          {shownAll.length > shown.length ? ` of ${shownAll.length} matching` : ''}
          {` · ${total.total} input${total.total === 1 ? '' : 's'} probed`}
          {/* THE LINE THIS PANEL IS FOR. Never suppressed at zero when rows exist: "0 not known"
              is itself the answer to the question, and an absent counter would be read as one. */}
          <span style={{ color: '#fd7e14' }}>
            {` · ${total.notKnown} not known`}
            {total.notKnownBreakdown.length > 0 && ` (${total.notKnownBreakdown
              .map(([s, n]) => `${((REFLECTION_BADGE[s] || {}).label || s).toLowerCase()} ${n}`)
              .join(', ')})`}
          </span>
        </span>
      </div>

      {shownAll.length === 0 ? (
        <Alert variant="dark" className="border-secondary text-white-50">
          None of the {probes.length} probe rows match these filters.
        </Alert>
      ) : (
        <table className="table table-dark table-sm align-middle" style={{ fontSize: '0.78rem' }}>
          <thead>
            <tr className="text-white-50" style={{ fontSize: '0.72rem', textTransform: 'uppercase' }}>
              <th>Grade</th><th>Input</th><th>Where</th><th>Survived</th><th>How</th>
              <th>Answered</th>
            </tr>
          </thead>
          <tbody>
            {shown.flatMap((p, i) => {
              const key = `${p.vector_id}-${p.insertion_point}-${p.parameter}-${i}`;
              const surv = survivedSummary(p.survived, p.status);
              const src = evidenceSource(p.evidence_source);
              return [
                <tr key={key} style={{ cursor: 'pointer' }}
                  onClick={() => setOpen((prev) => ({ ...prev, [key]: !prev[key] }))}>
                  <td><GradeBadge probe={p} /></td>
                  <td className="text-light">
                    <span className="text-white-50 me-1" style={{ fontSize: '0.7rem' }}>
                      {open[key] ? '▾' : '▸'}
                    </span>
                    <code>{p.parameter || (p.insertion_point === 'path' ? 'path segment' : 'value')}</code>
                    <span className="text-white-50 ms-1" style={{ fontSize: '0.68rem' }}>
                      {p.insertion_point}
                    </span>
                  </td>
                  <td className="text-white-50" style={{ wordBreak: 'break-all' }}>
                    {p.method} {p.domain}{p.path}{p.fragment ? `#${p.fragment}` : ''}
                  </td>
                  {/* The characters printed literally, then WHICH KIND they are. A quote and an
                      angle bracket are not the same news and the row says so in words. */}
                  <td title={surv.note}
                    style={{ color: surv.markup ? '#dc3545' : 'rgba(255,255,255,0.5)' }}>
                    <code style={{ color: 'inherit' }}>{surv.chars.join(' ') || '-'}</code>
                    {surv.markup && surv.chars.length > 0 && (
                      <span className="ms-1" style={{ fontSize: '0.65rem' }}>opens a tag</span>
                    )}
                    {surv.weak && (
                      <span className="ms-1" style={{ fontSize: '0.65rem' }}>quotes only</span>
                    )}
                  </td>
                  <td className="text-white-50" title={src.why}>{src.label}</td>
                  <td className="text-white-50">
                    {p.http_status ? `${p.http_status} ` : ''}
                    {String(p.content_type || '').split(';')[0] || '-'}
                    {p.auth_applied && (
                      <span className="ms-1" style={{ fontSize: '0.65rem' }}
                        title="The probe carried this target's session, so the response is what a logged-in user sees.">
                        authed
                      </span>
                    )}
                  </td>
                </tr>,
                open[key] && (
                  <tr key={`${key}-detail`}>
                    <td colSpan={6} className="pt-0" style={{ borderTop: 'none' }}>
                      <div className="text-white-50 mb-1" style={{ fontSize: '0.7rem' }}>
                        {surv.note}
                      </div>
                      {p.detail && (
                        <div className="text-white-50 fst-italic mb-1" style={{ fontSize: '0.7rem' }}>
                          {p.detail}
                        </div>
                      )}
                      {p.probe_url && (
                        <div className="text-light mb-1" style={{ fontSize: '0.7rem', wordBreak: 'break-all' }}>
                          <code>{p.probe_url}</code>
                        </div>
                      )}
                      {p.evidence ? (
                        <pre className="text-light p-2 rounded mb-1" style={{
                          backgroundColor: '#0d0d0d', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                          fontSize: '0.7rem', maxHeight: '160px', overflowY: 'auto',
                        }}>{p.evidence}</pre>
                      ) : (
                        <div className="text-white-50 fst-italic mb-1" style={{ fontSize: '0.7rem' }}>
                          No response snippet was kept for this row.
                        </div>
                      )}
                      <div className="text-white-50" style={{ fontSize: '0.68rem' }}>
                        {p.canary ? `canary ${p.canary} · ` : ''}
                        {p.probed_at || 'never probed'}
                      </div>
                    </td>
                  </tr>
                ),
              ].filter(Boolean);
            })}
          </tbody>
        </table>
      )}

      {shownAll.length > shown.length && (
        <div className="text-white-50 small">
          {shownAll.length - shown.length} more rows match. Narrow the filters to see them.
        </div>
      )}
    </div>
  );
}

export default ReflectionResultsPanel;
