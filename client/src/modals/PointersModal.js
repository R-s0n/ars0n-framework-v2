import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Button, Form, Spinner, Alert } from 'react-bootstrap';

// WHERE TO SPEND THE NEXT HOUR, and which tool to point at it.
//
// A POINTER IS NOT A FINDING. A finding says "this is vulnerable". A pointer says "there is
// evidence this vector MAY be vulnerable to this class, so it is worth testing deeply". It exists
// because the framework has more confirmation scanners than anyone can run: sqlmap alone spends
// around 1690 requests on ONE vector, and there are 218 vectors on the target this screen was
// built against. The list is the triage; the detail pane is the evidence the operator judges it on.
//
// THE RULE THIS SCREEN KEEPS is the one the reflection panel keeps: NOT KNOWING IS NOT CLEAN, and
// the absence of a pointer is not the absence of risk. On the measured target 43 pointers sit
// beside 186 vectors that no source ever answered for and 1714 probe rows that are unknown rather
// than clean. A screen that showed only the 43 would read as "the other 186 are fine". That is why
// the coverage strip is above both panes, on every state of this modal, and never behind a toggle.
//
// NOTHING IS RE-DERIVED HERE. The server ranks, grades, names the rule, builds the attack path and
// chooses the next tool, in server/utils/pointersAPI.go. This file arranges what it sends. The one
// thing computed in the browser is which characters to highlight, and that is drawn from the
// pointer's own url and path template rather than guessed.

const ACCENT = '#dc3545';
const UNKNOWN = '#fd7e14';

const num = (x) => Number(x || 0);

// A ceiling on rendered rows, not on loaded ones. The counts and the coverage strip are computed
// by the server over everything, so narrowing the filters never changes what the target is
// reported to have done.
export const MAX_ROWS = 300;

// HOW THE EVIDENCE WAS ESTABLISHED, in one sentence each, because "strength" as a bare word invites
// the reading that a strong pointer is a confirmed bug. The order matches the server's
// strength_order, and the server sends strength_rank so the sort and the label cannot drift.
export const STRENGTH_NOTE = {
  delta_checked: 'A probe was sent and the response was compared against a baseline. The strongest '
    + 'evidence this framework produces on its own.',
  tool_reported: 'A scanner reported it on this run and the framework holds what it reported.',
  probe_observed: 'A probe was sent and something came back. No baseline was compared, so the '
    + 'response may be what that endpoint always does.',
  prior_finding: 'A tool flagged this vector on an earlier scan. That is a lead about the past, '
    + 'not a measurement of the application today.',
  passive_echo: 'Nothing was sent. The value was found in a response the crawl had already stored, '
    + 'so the encoding was never tested.',
  unattributed: 'The source did not record how this was established.',
};

// The two strengths that mean a request went out and the framework holds the answer are the ones
// worth the accent. A prior finding and a passive echo are leads, and a lead that looks like a hit
// is how an hour gets spent in the wrong place.
export const strengthTone = (p) => {
  const s = String((p && p.strength) || '');
  if (s === 'delta_checked' || s === 'tool_reported') return ACCENT;
  if (s === 'probe_observed') return UNKNOWN;
  return 'rgba(255,255,255,0.55)';
};

// WHERE THE BYTES CAME FROM. The server sends its own note on most blobs; this is the fallback and
// the short label beside it. reconstructed and captured are different claims and the pane says
// which every time, because a composed request read as a recording is this project's oldest trap.
export const ORIGIN_NOTE = {
  captured: 'Recorded on the wire. These are the bytes that were really sent or really came back.',
  reconstructed: 'Composed by the framework from the vector and the finding. Not a recording: send '
    + 'it and read the response before quoting it.',
  none: 'Nothing was recorded for this pointer.',
  evidence_snippet: 'A window around the match in a stored response, not the whole body.',
  evidence_phrase: 'The phrase the tool reported, not a response body.',
  triage_fidelity_container: 'Recorded by the triage container as the probe went out.',
};

export const originNote = (blob) => {
  const b = blob || {};
  if (b.note) return b.note;
  return ORIGIN_NOTE[String(b.origin || 'none')] || ORIGIN_NOTE.none;
};

// --- filtering and ordering ---------------------------------------------------------------------

// The list is fetched ONCE and unfiltered, and narrowed here. The endpoint takes ?attack_class,
// ?source, ?grade and ?insertion_point, and using them would mean the counts on the coverage strip
// described only the rows that survived the filter. "0 unknown" while filtered to XSS is not a
// fact about the target, and that reading is the whole thing this screen exists to prevent.
export const filterPointers = (rows, f) => {
  const q = f || {};
  const term = String(q.search || '').trim().toLowerCase();
  return (rows || []).filter((p) => {
    if (q.attackClass && p.attack_class !== q.attackClass) return false;
    if (q.source && p.source !== q.source) return false;
    if (!term) return true;
    const hay = `${p.url || ''} ${p.parameter || ''} ${p.insertion_point || ''} `
      + `${p.attack_class || ''} ${p.attack_class_label || ''} ${p.method || ''} `
      + `${p.next_tool || ''} ${p.domain || ''} ${p.path || ''}`;
    return hay.toLowerCase().includes(term);
  });
};

// Worst first is the SERVER'S order: EvidenceRank, then severity inside the band, then deliverable.
// Sorting on rank rather than trusting array order costs nothing and means a filtered list, a
// re-fetch and a cached list can never disagree about which pointer is first.
export const rankPointers = (rows) => (rows || []).slice()
  .sort((a, b) => num(a && a.rank) - num(b && b.rank));

// --- the marker ---------------------------------------------------------------------------------

export const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// WHAT TO HIGHLIGHT IN THE REQUEST AND THE RESPONSE.
//
// The eye has to land on the evidence without reading a 4KB request. The terms are taken from the
// pointer itself and never invented: the parameter name, the value that parameter carries in the
// recorded url, and the value of every path segment the server templated as a placeholder. That
// last one is the whole trick for a path pointer: the server records the path as
// /api/v1/accounts/{uuid}/trade_account/margin and the url with the real uuid in it, so the
// difference between the two IS the attacker-controlled value, and it is the string that came back
// in the response.
export const markerTerms = (p) => {
  if (!p) return [];
  const terms = [];
  const param = String(p.parameter || '').trim();
  if (param) terms.push(param);

  let url = null;
  try { url = new URL(String(p.url || '')); } catch (e) { url = null; }

  if (url && param) {
    const v = url.searchParams.get(param);
    if (v) terms.push(v);
  }

  const tmpl = String(p.path || '').split('/');
  const real = url ? String(url.pathname || '').split('/') : [];
  if (tmpl.length > 1 && tmpl.length === real.length) {
    tmpl.forEach((seg, i) => {
      if (!/^\{.+\}$/.test(seg) || !real[i]) return;
      let value = real[i];
      try { value = decodeURIComponent(value); } catch (e) { value = real[i]; }
      terms.push(value);
    });
  }

  // Two characters is the floor. A one character term matches most of a request and highlights
  // nothing useful.
  return [...new Set(terms.map((t) => String(t)).filter((t) => t.length >= 2))];
};

// Returns the text cut into runs, each marked hit or not, so the highlighter can be tested without
// mounting anything.
export const splitOnTerms = (text, terms) => {
  const t = text == null ? '' : String(text);
  const list = (terms || [])
    .filter((x) => typeof x === 'string' && x.length >= 2)
    .sort((a, b) => b.length - a.length);
  if (!t || list.length === 0) return [{ text: t, hit: false }];
  let re;
  try {
    re = new RegExp(list.map(escapeRe).join('|'), 'gi');
  } catch (e) {
    return [{ text: t, hit: false }];
  }
  const out = [];
  let last = 0;
  let m = re.exec(t);
  while (m !== null) {
    if (m[0].length === 0) {
      re.lastIndex += 1;
    } else {
      if (m.index > last) out.push({ text: t.slice(last, m.index), hit: false });
      out.push({ text: m[0], hit: true });
      last = m.index + m[0].length;
    }
    m = re.exec(t);
  }
  if (last < t.length) out.push({ text: t.slice(last), hit: false });
  return out.length ? out : [{ text: t, hit: false }];
};

// --- coverage -------------------------------------------------------------------------------

// WHAT WAS EXAMINED AND WHAT WAS NOT, one chip per source, always rendered. A zero is printed as a
// zero: an absent counter reads as "not a thing", and a zero reads as "nothing found there yet".
export const coverageChips = (coverage) => {
  const c = coverage || {};
  const v = c.vectors || {};
  const r = c.reflection || {};
  const f = c.findings || {};
  const t = c.triage || {};

  const reasons = Object.entries(r.unknown_by_reason || {})
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${String(k).replace(/_/g, ' ')} ${n}`)
    .join(', ');

  return [
    {
      key: 'vectors',
      text: `${num(v.total)} vectors: ${num(v.with_pointer)} with a pointer, `
        + `${num(v.unknown)} with no conclusion`,
      unknown: num(v.unknown) > 0,
      why: 'A vector with no conclusion was never answered by any source. That is a gap in '
        + 'coverage, not a vector that came back clean.',
    },
    {
      key: 'reflection',
      text: `${num(r.probe_rows)} probe rows: ${num(r.unknown)} unknown`
        + (reasons ? ` (${reasons})` : ''),
      unknown: num(r.unknown) > 0,
      why: 'Unknown means the probe could not answer for that input: a credential it refused to '
        + 'burn, an error, or an input nothing was ever sent to.',
    },
    {
      key: 'findings',
      text: `${num(f.rows)} stored findings: ${num(f.pointers)} kept, `
        + `${num(f.excluded_canary)} positive control, ${num(f.excluded_dismissed)} dismissed`,
      unknown: false,
      why: f.note || '',
    },
    {
      key: 'triage',
      text: String(t.status || '') === 'no_run_yet'
        ? 'triage: no run yet, 0 verdicts'
        : `triage ${t.status || 'unknown'}: ${num(t.verdicts)} verdicts, `
          + `${num(t.payload_unproven)} payload unproven`,
      unknown: String(t.status || '') !== 'completed' || num(t.payload_unproven) > 0,
      why: t.note || '',
    },
  ];
};

// AN EMPTY LIST IS TWO COMPLETELY DIFFERENT STATES and they must never render the same. Nothing
// scanned means there is no evidence; scanned and nothing found means every source that ran came
// back without a lead, which is still not a clean bill while unknowns remain.
export const emptyState = (coverage) => {
  const c = coverage || {};
  const r = c.reflection || {};
  const f = c.findings || {};
  const t = c.triage || {};
  const probed = num(r.probe_rows);
  const rows = num(f.rows);
  const verdicts = num(t.verdicts);

  if (probed === 0 && rows === 0 && verdicts === 0) {
    return {
      kind: 'never_scanned',
      title: 'Nothing has been scanned on this target yet.',
      detail: 'Run Investigate on the Consolidate Attack Vectors card. An empty list here means no '
        + 'evidence exists, not that the target has nothing on it.',
    };
  }

  const parts = [];
  if (probed) parts.push(`${probed} probe row${probed === 1 ? '' : 's'}`);
  if (rows) parts.push(`${rows} stored finding${rows === 1 ? '' : 's'}`);
  if (verdicts) parts.push(`${verdicts} triage verdict${verdicts === 1 ? '' : 's'}`);
  const unknown = num(r.unknown);

  return {
    kind: 'scanned_nothing_found',
    title: `No pointer from ${parts.join(', ')}.`,
    detail: unknown > 0
      ? `${unknown} of those probe rows are unknown rather than clean, so this is a gap in `
        + 'coverage rather than a clean result.'
      : 'Every source that has run came back without a lead. The strip above says which sources '
        + 'have not run.',
  };
};

// --- small pieces -------------------------------------------------------------------------------

const Chip = ({ text, why, tone }) => (
  <span
    title={why || undefined}
    style={{
      display: 'inline-block',
      fontSize: '0.68rem',
      lineHeight: 1.5,
      padding: '0 0.45em',
      borderRadius: '0.25rem',
      border: `1px solid ${tone}`,
      color: tone,
      whiteSpace: 'nowrap',
    }}
  >
    {text}
  </span>
);

const Highlighted = ({ text, terms, style }) => (
  <pre
    style={{
      backgroundColor: '#0d0d0d',
      color: '#e9ecef',
      whiteSpace: 'pre-wrap',
      wordBreak: 'break-all',
      fontSize: '0.7rem',
      padding: '0.5rem',
      borderRadius: '0.25rem',
      marginBottom: '0.25rem',
      ...style,
    }}
  >
    {splitOnTerms(text, terms).map((run, i) => (run.hit ? (
      <mark
        key={`h${i}`}
        style={{ backgroundColor: 'rgba(220,53,69,0.35)', color: '#fff', padding: 0 }}
      >
        {run.text}
      </mark>
    ) : (
      <span key={`t${i}`}>{run.text}</span>
    )))}
  </pre>
);

const Section = ({ title, children }) => (
  <div className="mb-3">
    <div
      className="text-white-50 mb-1"
      style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}
    >
      {title}
    </div>
    {children}
  </div>
);

// THE ATTACK PATH AS A PATH. The server sends the entry, what the value reaches, what an attacker
// could do from there and which tool answers the open question. A paragraph would carry the same
// words and none of the shape: the point of drawing it is that the operator can see how far the
// evidence actually goes before the conditional starts.
const PathNode = ({ label, tone, last, children }) => (
  <div className="d-flex" style={{ gap: '0.6rem' }}>
    <div className="d-flex flex-column align-items-center" style={{ width: '12px', flexShrink: 0 }}>
      <span
        style={{
          width: '9px',
          height: '9px',
          borderRadius: '50%',
          marginTop: '0.3rem',
          background: tone,
          flexShrink: 0,
        }}
      />
      {!last && <span style={{ width: '1px', flexGrow: 1, background: 'rgba(255,255,255,0.2)' }} />}
    </div>
    <div style={{ paddingBottom: last ? 0 : '0.7rem', minWidth: 0, flexGrow: 1 }}>
      <div className="text-white-50" style={{ fontSize: '0.68rem' }}>{label}</div>
      <div className="text-light" style={{ fontSize: '0.78rem', wordBreak: 'break-word' }}>
        {children}
      </div>
    </div>
  </div>
);

export const AttackPath = ({ pointer, path }) => {
  const p = path || {};
  const v = pointer || {};
  const next = p.next || {};
  const attacks = p.possible_attacks || [];
  return (
    <div>
      <PathNode label="Input the attacker controls" tone={ACCENT}>
        {p.entry || 'The server did not record an entry point for this pointer.'}
        <div className="mt-1 d-flex gap-1 flex-wrap">
          <Chip text={v.insertion_point || 'unrecorded'} tone="rgba(255,255,255,0.55)" />
          {v.parameter && <Chip text={v.parameter} tone="rgba(255,255,255,0.55)" />}
        </div>
      </PathNode>

      <PathNode label="Where it travels" tone={ACCENT}>
        <code style={{ color: '#e9ecef' }}>{v.method} {v.url}</code>
      </PathNode>

      <PathNode label="Where it lands, and what the evidence shows" tone={ACCENT}>
        {p.reaches || v.rule}
        {!p.deliverable && (
          <div style={{ color: UNKNOWN }}>
            {p.delivery_note || v.delivery_note
              || 'An attacker cannot put a value here, so this class cannot be delivered from this '
                + 'insertion point.'}
          </div>
        )}
      </PathNode>

      <PathNode label="What an attacker could do from there, IF the class confirms" tone={UNKNOWN}>
        {attacks.length === 0 ? (
          <span className="text-white-50">
            The server has no consequence mapped for this class yet.
          </span>
        ) : (
          <ul className="mb-0 ps-3">
            {attacks.map((a, i) => <li key={`a${i}`}>{a}</li>)}
          </ul>
        )}
      </PathNode>

      <PathNode label="Point this next" tone={UNKNOWN} last>
        {next.tool
          ? <strong className="text-danger">{next.tool}</strong>
          : <span className="text-white-50">No tool.</span>}
        {next.reason && <span> {next.reason}</span>}
        {next.vector_id && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.7rem' }}>
            vector {next.vector_id} · {next.insertion_point || 'unrecorded'}
            {next.parameter ? ` · ${next.parameter}` : ''}
          </div>
        )}
      </PathNode>
    </div>
  );
};

const Blob = ({ title, blob, terms, emptyNote }) => {
  const b = blob || {};
  const raw = String(b.raw || '');
  return (
    <Section title={title}>
      <div className="text-white-50 mb-1" style={{ fontSize: '0.68rem' }}>
        <Chip text={b.origin || 'none'} tone={b.origin === 'captured' ? ACCENT : UNKNOWN} />
        <span className="ms-2">{originNote(b)}</span>
      </div>
      {raw
        ? <Highlighted text={raw} terms={terms} style={{ maxHeight: '260px', overflowY: 'auto' }} />
        : (
          <div className="text-white-50 fst-italic" style={{ fontSize: '0.72rem' }}>
            {emptyNote}
          </div>
        )}
    </Section>
  );
};

// --- the detail pane ------------------------------------------------------------------------

export const PointerDetail = ({ detail, loading, error }) => {
  const copy = (text) => { if (navigator.clipboard) navigator.clipboard.writeText(text || ''); };

  if (loading) {
    return <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>;
  }
  if (error) {
    return <Alert variant="danger" className="py-2 small">{error}</Alert>;
  }
  if (!detail) {
    return (
      <div className="text-white-50 py-5 text-center" style={{ fontSize: '0.8rem' }}>
        Select a pointer to read its evidence.
      </div>
    );
  }

  const p = detail.pointer || {};
  const terms = markerTerms(p);
  const baseline = detail.baseline || {};
  const rule = detail.rule || {};
  const grade = detail.grade || {};
  const repro = detail.reproduction || null;
  const explain = detail.explain || null;
  const reproText = (repro && (repro.curl || repro.raw_request))
    || (detail.request && detail.request.raw) || '';

  return (
    <div>
      <div className="mb-2">
        <div className="d-flex align-items-center gap-2 flex-wrap">
          <span className="text-danger" style={{ fontWeight: 600 }}>
            {p.attack_class_label || p.attack_class}
          </span>
          <Chip text={p.strength} why={STRENGTH_NOTE[p.strength]} tone={strengthTone(p)} />
          <Chip
            text={p.delta_checked ? 'delta checked' : 'no baseline compared'}
            why={p.delta_checked
              ? 'A baseline request was sent and the two responses were compared.'
              : 'Nothing was compared, so the response may be what this endpoint always does.'}
            tone={p.delta_checked ? ACCENT : UNKNOWN}
          />
          <span className="text-white-50" style={{ fontSize: '0.72rem' }}>rank {p.rank}</span>
        </div>
        <code
          className="text-light d-block mt-1"
          style={{ fontSize: '0.74rem', wordBreak: 'break-all' }}
        >
          {p.method} {p.url}
        </code>
      </div>

      <Section title="Attack path">
        <AttackPath pointer={p} path={detail.attack_path} />
      </Section>

      <Blob
        title="Request"
        blob={detail.request}
        terms={terms}
        emptyNote="No request bytes were recorded for this pointer."
      />
      <Blob
        title="Response"
        blob={detail.response}
        terms={terms}
        emptyNote="No response was recorded for this pointer, so there is nothing here to read."
      />

      <Section title="Baseline">
        <div style={{ fontSize: '0.75rem', color: baseline.compared ? '#e9ecef' : UNKNOWN }}>
          {baseline.compared ? 'Compared. ' : 'Not compared. '}
          {baseline.what}
        </div>
      </Section>

      <Section title="The rule that fired">
        <div className="text-light" style={{ fontSize: '0.75rem' }}>{rule.fired}</div>
        {rule.means && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.73rem' }}>
            <strong>Means:</strong> {rule.means}
          </div>
        )}
        {rule.did_not_establish && (
          <div className="mt-1" style={{ fontSize: '0.73rem', color: UNKNOWN }}>
            <strong>Did not establish:</strong> {rule.did_not_establish}
          </div>
        )}
      </Section>

      <Section title="Provenance and grade">
        <div className="text-light" style={{ fontSize: '0.75rem' }}>{p.source_detail}</div>
        <div className="text-white-50 mt-1" style={{ fontSize: '0.73rem' }}>
          Grade <code className="text-light">{grade.value || p.grade || 'none'}</code>
          {'. '}{grade.source || p.grade_source}
          {grade.why ? ` ${grade.why}` : ''}
        </div>
        <div className="text-white-50 mt-1" style={{ fontSize: '0.73rem' }}>
          {STRENGTH_NOTE[p.strength] || STRENGTH_NOTE.unattributed}
        </div>
        <div className="text-white-50 mt-1" style={{ fontSize: '0.73rem' }}>{p.why_ranked}</div>
      </Section>

      {explain && (explain.what_it_proved || explain.what_it_did_not_prove) && (
        <Section title="What the tool proved">
          {explain.what_it_proved && (
            <div className="text-light" style={{ fontSize: '0.73rem' }}>
              {explain.what_it_proved}
            </div>
          )}
          {explain.what_it_did_not_prove && (
            <div className="mt-1" style={{ fontSize: '0.73rem', color: UNKNOWN }}>
              {explain.what_it_did_not_prove}
            </div>
          )}
          {explain.false_positive_looks_like && (
            <div className="text-white-50 mt-1" style={{ fontSize: '0.73rem' }}>
              <strong>A false positive looks like:</strong> {explain.false_positive_looks_like}
            </div>
          )}
        </Section>
      )}

      <Section title="Reproduce by hand">
        {reproText ? (
          <>
            <Highlighted
              text={reproText}
              terms={terms}
              style={{ maxHeight: '200px', overflowY: 'auto' }}
            />
            <Button size="sm" variant="outline-danger" onClick={() => copy(reproText)}>Copy</Button>
          </>
        ) : (
          <div className="text-white-50 fst-italic" style={{ fontSize: '0.73rem' }}>
            Nothing recorded to reproduce from.
          </div>
        )}
        {repro && repro.steps && repro.steps.length > 0 && (
          <ul className="text-white-50 mt-2 mb-0 ps-3" style={{ fontSize: '0.73rem' }}>
            {repro.steps.map((s, i) => <li key={`s${i}`}>{s}</li>)}
          </ul>
        )}
        {repro && repro.caveat && (
          <div className="mt-1" style={{ fontSize: '0.72rem', color: UNKNOWN }}>{repro.caveat}</div>
        )}
      </Section>
    </div>
  );
};

// --- the modal ------------------------------------------------------------------------------

function PointersModal({ show, handleClose, activeTarget }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [attackClass, setAttackClass] = useState('');
  const [source, setSource] = useState('');
  const [selected, setSelected] = useState('');
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');

  const targetId = activeTarget && activeTarget.id;

  const load = useCallback(async () => {
    if (!show || !targetId) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/attack-vectors/${targetId}/pointers`);
      if (!res.ok) {
        setError('Could not load pointers.');
        return;
      }
      setData(await res.json());
    } catch (err) {
      setError(`Could not load pointers: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [show, targetId]);

  useEffect(() => { load(); }, [load]);

  const pointers = useMemo(() => rankPointers((data && data.pointers) || []), [data]);
  const shownAll = useMemo(
    () => filterPointers(pointers, { search, attackClass, source }),
    [pointers, search, attackClass, source],
  );
  const shown = useMemo(() => shownAll.slice(0, MAX_ROWS), [shownAll]);

  // The selection follows the list. A pointer filtered out of view leaves no detail pane open
  // beside it, because a detail that no longer matches the list is the fastest way to read the
  // wrong evidence for the wrong vector.
  useEffect(() => {
    if (shown.length === 0) { setSelected(''); return; }
    if (!shown.some((p) => p.id === selected)) setSelected(shown[0].id);
  }, [shown, selected]);

  useEffect(() => {
    let cancelled = false;
    const chosen = pointers.find((p) => p.id === selected);
    if (!chosen || !targetId) { setDetail(null); return undefined; }
    const url = chosen.detail_url
      ? `/api${chosen.detail_url}`
      : `/api/attack-vectors/${targetId}/pointers/${chosen.id}`;
    setDetailLoading(true);
    setDetailError('');
    fetch(url)
      .then(async (res) => {
        if (cancelled) return;
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          setDetail(null);
          setDetailError(body.message || 'Could not load this pointer.');
          return;
        }
        const body = await res.json();
        if (!cancelled) setDetail(body);
      })
      .catch((err) => { if (!cancelled) setDetailError(err.message); })
      .finally(() => { if (!cancelled) setDetailLoading(false); });
    return () => { cancelled = true; };
  }, [selected, pointers, targetId]);

  const counts = (data && data.counts) || {};
  const coverage = (data && data.coverage) || {};
  const labels = ((data && data.vocabulary) || {}).class_labels || {};
  const classOptions = Object.entries(counts.by_attack_class || {}).sort((a, b) => b[1] - a[1]);
  const sourceOptions = Object.entries(counts.by_source || {}).sort((a, b) => b[1] - a[1]);
  const empty = emptyState(coverage);

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Pointers</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* THE COVERAGE STRIP. Above both panes, on every state, never behind a toggle: the
            pointers below are what was found, and this is what was looked at. */}
        <div className="mb-2 pb-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.12)' }}>
          <div className="text-light" style={{ fontSize: '0.78rem' }}>
            {coverage.headline || 'No coverage has been reported for this target yet.'}
          </div>
          <div className="d-flex flex-wrap gap-2 mt-1">
            {coverageChips(coverage).map((c) => (
              <Chip
                key={c.key}
                text={c.text}
                why={c.why}
                tone={c.unknown ? UNKNOWN : 'rgba(255,255,255,0.55)'}
              />
            ))}
          </div>
        </div>

        {loading && (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        )}
        {!loading && error && <Alert variant="danger" className="py-2 small">{error}</Alert>}

        {!loading && !error && (
          <div className="d-flex" style={{ gap: '1rem', flexGrow: 1, minHeight: 0 }}>
            {/* LEFT: every pointer, worst first, each row answering "is this the one" without a
                click: the class, the vector, how the evidence was established, and what to run. */}
            <div
              style={{ width: '38%', minWidth: '320px', display: 'flex', flexDirection: 'column' }}
            >
              <div className="d-flex flex-wrap gap-2 mb-2">
                <Form.Control
                  size="sm"
                  style={{ maxWidth: '190px' }}
                  data-bs-theme="dark"
                  className="custom-input"
                  placeholder="Search url, parameter or tool"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <Form.Select
                  size="sm"
                  style={{ width: 'auto' }}
                  data-bs-theme="dark"
                  value={attackClass}
                  onChange={(e) => setAttackClass(e.target.value)}
                >
                  <option value="">Any attack class</option>
                  {classOptions.map(([k, n]) => (
                    <option key={k} value={k}>{labels[k] || k} ({n})</option>
                  ))}
                </Form.Select>
                <Form.Select
                  size="sm"
                  style={{ width: 'auto' }}
                  data-bs-theme="dark"
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  title="Which evidence bus the pointer came from. A source at zero has produced nothing, which is not the same as having found nothing."
                >
                  <option value="">Any source</option>
                  {sourceOptions.map(([k, n]) => (
                    <option key={k} value={k}>{String(k).replace(/_/g, ' ')} ({n})</option>
                  ))}
                </Form.Select>
              </div>

              <div className="text-white-50 mb-1" style={{ fontSize: '0.7rem' }}>
                {shown.length} of {pointers.length} pointers
                {shownAll.length > shown.length
                  ? `, ${shownAll.length - shown.length} more match` : ''}
              </div>

              <div style={{ overflowY: 'auto', flexGrow: 1 }}>
                {pointers.length === 0 && (
                  <Alert variant="dark" className="border-secondary text-white-50 py-2">
                    <div className="text-light">{empty.title}</div>
                    <div style={{ fontSize: '0.75rem' }}>{empty.detail}</div>
                  </Alert>
                )}
                {pointers.length > 0 && shownAll.length === 0 && (
                  <Alert variant="dark" className="border-secondary text-white-50 py-2">
                    None of the {pointers.length} pointers match these filters.
                  </Alert>
                )}
                {shown.map((p) => (
                  <div
                    key={p.id}
                    data-pointer-id={p.id}
                    onClick={() => setSelected(p.id)}
                    style={{
                      cursor: 'pointer',
                      padding: '0.4rem 0.5rem',
                      borderLeft: `3px solid ${p.id === selected ? ACCENT : 'transparent'}`,
                      background: p.id === selected ? 'rgba(220,53,69,0.12)' : 'transparent',
                      borderBottom: '1px solid rgba(255,255,255,0.06)',
                    }}
                  >
                    <div className="d-flex align-items-center gap-2">
                      <span className="text-white-50" style={{ fontSize: '0.68rem' }}>{p.rank}</span>
                      <span
                        className="text-danger"
                        style={{ fontSize: '0.75rem', fontWeight: 600 }}
                      >
                        {p.attack_class_label || p.attack_class}
                      </span>
                      <span
                        className="ms-auto"
                        style={{ fontSize: '0.65rem', color: strengthTone(p) }}
                        title={STRENGTH_NOTE[p.strength] || STRENGTH_NOTE.unattributed}
                      >
                        {p.strength}
                      </span>
                    </div>
                    <div
                      className="text-light"
                      style={{ fontSize: '0.72rem', wordBreak: 'break-all' }}
                    >
                      {p.method} {p.path || p.url}
                    </div>
                    <div className="text-white-50" style={{ fontSize: '0.67rem' }}>
                      {p.insertion_point || 'unrecorded'}
                      {p.parameter ? ` · ${p.parameter}` : ''}
                      {` · ${p.grade || 'no grade'}`}
                      {p.next_tool ? ` · run ${p.next_tool}` : ''}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* RIGHT: the evidence for the highlighted pointer. */}
            <div style={{ flexGrow: 1, overflowY: 'auto', minWidth: 0 }}>
              <PointerDetail detail={detail} loading={detailLoading} error={detailError} />
            </div>
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" disabled={loading} onClick={load}>Refresh</Button>
        <Button variant="secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
}

export default PointersModal;
