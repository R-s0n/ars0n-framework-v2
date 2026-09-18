import { Modal, Button, Form, Nav, Spinner, Alert, Badge } from 'react-bootstrap';
import { useState, useEffect, useCallback, useMemo } from 'react';
import VirtualizedList from '../components/VirtualizedList';

// WHAT THE INVESTIGATE RUN WILL DO, before it does it: which endpoints it is aimed at, and how
// hard it probes each attack class once it gets there.
//
// Two tabs because they answer two different questions and are stored in two different places.
// The endpoint list is per-target selection (sparse, absence means selected) and saves as you
// click. The Investigate settings are one document PUT whole, because this form has just shown
// the operator every field and a partial write to a full-document endpoint is how seven columns
// got wiped on fifty-eight rows in this codebase once already.
//
// NOTHING HERE LISTS AN ATTACK CLASS, A TIER, A RISK, AN ENCODER OR A DETECTION MODE. All of it
// arrives in `vocabulary` from GET /triage/{id}/settings, built from the classifier register.
// Ten classes are offered today out of twenty-seven planned, and a hardcoded list is a screen
// that goes stale the day class eleven lands, which reads to the operator as a class that was
// covered when it was never offered.
//
// THE ELEVENTH REGISTERED CLASS IS NOT ONE. triageclasses/example.go is a placeholder that plans
// nothing and can only emit not_planned, and it shipped here as a row in the list, on by default,
// under the heading "11 of 11 classes enabled". The server drops it from the vocabulary now
// (TriageClassIsReserved), so this screen renders whatever it is handed and the fix reaches every
// other consumer too.
//
// AND THE LEVELS A CONTROL OFFERS ARE THE CLASS'S OWN. Depth already followed that rule; the risk
// ceiling did not, and rendered R0 to R3 for every class while nosql, lfi and rfi declare only R0
// probes and ssti and xss-r only R1. "Up to R2" on a class whose every probe is R0 refuses
// nothing at all, and the only thing it changes is what the operator believes was bought.

const ACCENT = '#dc3545';

// The endpoint selection reply has been misread once already: an agent assumed a key named
// "items", read zero selected and cancelled a correctly configured twenty-nine vector scan. The
// shape is asserted rather than trusted, and the failure names the keys that actually arrived so
// the next person sees what the server said instead of an empty list.
export const SELECTION_KEYS = ['vectors', 'selected', 'eligible', 'total', 'scan_will_run'];

export const assertSelectionShape = (body) => {
  if (!body || typeof body !== 'object') return 'The selection endpoint returned no object.';
  if (!Array.isArray(body.vectors)) {
    const keys = Object.keys(body).sort().join(', ') || 'none';
    return `The selection endpoint returned no vectors array. Keys received: ${keys}. Expected ${SELECTION_KEYS.join(', ')}.`;
  }
  return '';
};

// The host, which is what "sorted by domain" means here. A row whose URL will not parse is kept
// under its raw prefix rather than dropped: an unparseable URL is still a vector that will be
// scanned, and hiding it would understate the run.
export const domainOf = (url) => {
  const raw = String(url || '').trim();
  if (!raw) return 'unknown host';
  try {
    return new URL(raw.includes('://') ? raw : `https://${raw}`).host || 'unknown host';
  } catch {
    return raw.split('/')[0] || 'unknown host';
  }
};

export const matchesSearch = (v, term) => {
  const q = String(term || '').trim().toLowerCase();
  if (!q) return true;
  return [v.url, v.method, v.parameters, v.insertion_point, domainOf(v.url)]
    .some((f) => String(f || '').toLowerCase().includes(q));
};

// Grouped by host, hosts alphabetical, rows inside a host left in the server's order (insertion
// point, then URL). `items` is the whole group and `shown` is what the search left, so the group
// header keeps reporting the real counts: a filter that also changed those numbers would let an
// operator read "2 of 2 selected" on a host with ninety vectors.
export const groupByDomain = (vectors, term) => {
  const byHost = new Map();
  (vectors || []).forEach((v) => {
    const host = domainOf(v.url);
    if (!byHost.has(host)) byHost.set(host, []);
    byHost.get(host).push(v);
  });
  return [...byHost.keys()].sort().map((domain) => {
    const items = byHost.get(domain);
    return {
      domain,
      items,
      shown: items.filter((v) => matchesSearch(v, term)),
      selected: items.filter((v) => v.selected).length,
      eligible: items.filter((v) => v.eligible).length,
    };
  });
};

// Validation is addressed per field by the server precisely so the form can put each problem next
// to the control that caused it. This is the index that makes that a lookup.
export const problemsByField = (validation) => {
  const out = {};
  const push = (p, level) => {
    if (!p || !p.field) return;
    if (!out[p.field]) out[p.field] = [];
    out[p.field].push({ ...p, level });
  };
  ((validation && validation.errors) || []).forEach((p) => push(p, 'error'));
  ((validation && validation.warnings) || []).forEach((p) => push(p, 'warning'));
  return out;
};

// The risk levels worth offering as a ceiling for one class.
//
// The ceiling is a REFUSAL, so a level above everything the class declares refuses nothing. Same
// rule the depth control already applies: a class with one level gets no control, because a
// control that changes nothing invites the belief that the depth was chosen.
//
// THE STORED VALUE IS ALWAYS INCLUDED, even when the class does not declare it. A select whose
// value matches none of its options renders BLANK, and a blank ceiling reads as no ceiling. A
// document saved before this change holds R2 on a class whose probes are all R0, so that value
// has to stay visible and choosable until the operator moves off it. The server warns separately
// when a ceiling actually refuses probes, and never clamps one down, because clamping would
// narrow the run on the day the class gains a deeper probe.
export const RISK_ORDER = ['R0', 'R1', 'R2', 'R3'];

export const riskChoicesFor = (c, stored) => {
  const rank = (r) => {
    const i = RISK_ORDER.indexOf(r);
    return i < 0 ? RISK_ORDER.length : i;
  };
  const set = new Set((c && c.risks) || []);
  if (stored) set.add(stored);
  return [...set].sort((a, b) => rank(a) - rank(b) || String(a).localeCompare(String(b)));
};

const Problems = ({ index, field }) => {
  const rows = (index && index[field]) || [];
  if (!rows.length) return null;
  return (
    <div style={{ fontSize: '0.72rem' }}>
      {rows.map((p, i) => (
        <div key={`${p.code}-${i}`} style={{ color: p.level === 'error' ? ACCENT : '#ffc107' }}>
          {p.message}
        </div>
      ))}
    </div>
  );
};

const NumberField = ({ label, field, value, step, onChange, index, help }) => (
  <Form.Group className="mb-2">
    <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.78rem' }}>{label}</Form.Label>
    <Form.Control
      type="number"
      size="sm"
      step={step || 1}
      value={value === undefined || value === null ? '' : value}
      onChange={(e) => onChange(e.target.value === '' ? 0 : Number(e.target.value))}
      aria-label={label}
    />
    {help && <div className="text-white-50" style={{ fontSize: '0.7rem' }}>{help}</div>}
    <Problems index={index} field={field} />
  </Form.Group>
);

// ---------------------------------------------------------------------------------------------
// TAB 1: WHICH ENDPOINTS THE RUN IS AIMED AT
// ---------------------------------------------------------------------------------------------

export const EndpointSelection = ({ targetId }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [reading, setReading] = useState('');
  const [term, setTerm] = useState('');
  const [collapsed, setCollapsed] = useState({});

  const url = `/api/attack-vectors/${targetId}/selection`;

  const load = useCallback(async () => {
    if (!targetId) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/attack-vectors/${targetId}/selection`);
      if (!res.ok) {
        setError(`Could not load the endpoint list (HTTP ${res.status}).`);
        setData(null);
        return;
      }
      const body = await res.json();
      const bad = assertSelectionShape(body);
      if (bad) {
        setError(bad);
        setData(null);
        return;
      }
      setData(body);
    } catch (err) {
      setError(`Could not load the endpoint list: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [targetId]);

  useEffect(() => { load(); }, [load]);

  // Reloaded rather than patched from the reply's counts, because switching an endpoint off
  // rewrites the reason on the row underneath it. The reply's own sentence is kept, because it is
  // the server explaining the gap between selected and eligible in its own words.
  const post = async (body) => {
    setBusy(true);
    setError('');
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        setError(`Could not save the selection (HTTP ${res.status}).`);
        return;
      }
      const reply = await res.json();
      setReading(reply.reading || '');
      await load();
    } catch (err) {
      setError(`Could not save the selection: ${err.message}`);
    } finally {
      setBusy(false);
    }
  };

  const vectors = useMemo(() => (data && data.vectors) || [], [data]);
  const groups = useMemo(() => groupByDomain(vectors, term), [vectors, term]);

  // Flattened so one virtual list can carry headers and rows. Virtualised only past a threshold:
  // the measured target has 218 vectors across many hosts, and below that a plain list is cheaper
  // and keeps the whole group visible to a find-in-page.
  const flat = useMemo(() => {
    const rows = [];
    groups.forEach((g) => {
      if (term && g.shown.length === 0) return;
      rows.push({ kind: 'group', group: g, key: `g:${g.domain}` });
      if (collapsed[g.domain]) return;
      g.shown.forEach((v) => rows.push({ kind: 'vector', vector: v, key: `v:${v.vector_id}` }));
    });
    return rows;
  }, [groups, collapsed, term]);

  if (loading && !data) {
    return <div className="text-center py-3"><Spinner animation="border" size="sm" variant="danger" /></div>;
  }

  if (error && !data) {
    return <Alert variant="dark" className="border border-danger text-light py-2 small">{error}</Alert>;
  }

  if (!data || !data.total) {
    return (
      <Alert variant="dark" className="border border-secondary text-light py-2 small">
        No attack vectors yet for this target. Consolidate endpoints and build the attack vector
        table first, and every vector it produces is selected for Investigate by default.
      </Alert>
    );
  }

  const switchedOff = data.total - data.selected;
  const gap = data.selected_but_unreachable || 0;

  const renderGroup = (g) => (
    <div className="d-flex justify-content-between align-items-center px-2 py-1"
         style={{ backgroundColor: '#2b2b2b' }}>
      <div className="d-flex align-items-center gap-2">
        <Button size="sm" variant="link" className="p-0 text-white-50"
                onClick={() => setCollapsed((c) => ({ ...c, [g.domain]: !c[g.domain] }))}
                aria-label={`Collapse ${g.domain}`}>
          {collapsed[g.domain] ? '+' : '-'}
        </Button>
        <span className="text-white" style={{ fontSize: '0.82rem', fontWeight: 600 }}>{g.domain}</span>
        <span className="text-white-50" style={{ fontSize: '0.72rem' }}>
          {g.selected} of {g.items.length} selected
        </span>
      </div>
      <div className="d-flex gap-2">
        <Button size="sm" variant="link" className="p-0 text-danger" disabled={busy}
                onClick={() => post({ vector_ids: g.items.map((v) => v.vector_id), enabled: true })}>
          All
        </Button>
        <span className="text-white-50">|</span>
        <Button size="sm" variant="link" className="p-0 text-white-50" disabled={busy}
                onClick={() => post({ vector_ids: g.items.map((v) => v.vector_id), enabled: false })}>
          None
        </Button>
      </div>
    </div>
  );

  const renderVector = (v) => (
    <div className="px-2 py-1 d-flex align-items-start gap-2"
         style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
      <Form.Check
        type="checkbox"
        checked={!!v.selected}
        disabled={busy}
        onChange={() => post({ vector_ids: [v.vector_id], enabled: !v.selected })}
        aria-label={`${v.method} ${v.url} ${v.insertion_point}`}
      />
      <div className="flex-grow-1" style={{ minWidth: 0 }}>
        <div className="text-break" style={{ fontSize: '0.75rem' }}>
          <Badge bg="dark" className="border border-secondary text-white-50 me-1">{v.method}</Badge>
          <span className="text-white">{v.url}</span>
        </div>
        <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
          {v.insertion_point}
          {v.parameters ? `: ${v.parameters}` : ''}
          {/* An ineligible row says why in the server's words. Deselected by the operator and
              unreachable by the run are both ineligible and look identical without it. */}
          {v.reason && <span style={{ color: v.deselected_by_operator ? undefined : '#ffc107' }}> {v.reason}</span>}
        </div>
      </div>
    </div>
  );

  const renderRow = (row) => (row.kind === 'group' ? renderGroup(row.group) : renderVector(row.vector));

  return (
    <div>
      {/* The headline counts are the SERVER'S, not a sum over the rows. What will be sent first,
          then what was chosen: reading only the second is how a scan comes back believed to have
          covered everything. */}
      <div className="mb-3 p-3 rounded" style={{ background: 'rgba(255,255,255,0.03)' }}>
        <div className="d-flex align-items-baseline gap-2 flex-wrap">
          <span className="text-white" style={{ fontSize: '1.5rem', fontWeight: 600, lineHeight: 1 }}>
            {data.eligible}
          </span>
          <span className="text-white" style={{ fontSize: '0.95rem' }}>
            {data.scan_will_run || `of ${data.total} vectors will be scanned`}
          </span>
        </div>
        <div className="mt-2" style={{ fontSize: '0.8rem' }}>
          <span className="text-white-50">
            {data.selected} of {data.total} selected
            {switchedOff > 0 ? `, ${switchedOff} switched off here.` : '.'}
          </span>{' '}
          {gap > 0 ? (
            <span style={{ color: '#ffc107' }}>
              {gap} selected {gap === 1 ? 'vector' : 'vectors'} will not be sent. Each one below says why.
            </span>
          ) : (
            <span className="text-white-50">Every selected vector will be sent.</span>
          )}
        </div>
        {reading && (
          <div className="text-white-50 mt-2" style={{ fontSize: '0.75rem' }}>{reading}</div>
        )}
        <div className="text-white-50 mt-2" style={{ fontSize: '0.72rem' }}>
          Each change here is saved as you make it.
        </div>
      </div>

      <div className="d-flex justify-content-between align-items-center gap-2 mb-2 flex-wrap">
        <Form.Control
          size="sm"
          style={{ maxWidth: '22rem' }}
          placeholder="Filter by host, path, parameter or method"
          value={term}
          onChange={(e) => setTerm(e.target.value)}
          aria-label="Filter endpoints"
        />
        <div className="d-flex gap-2">
          <Button size="sm" variant="link" className="p-0 text-danger" disabled={busy}
                  onClick={() => post({ all: true, enabled: true })}>
            Select all
          </Button>
          <span className="text-white-50">|</span>
          <Button size="sm" variant="link" className="p-0 text-white-50" disabled={busy}
                  onClick={() => post({ all: true, enabled: false })}>
            None
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="dark" className="border border-danger text-danger py-1 small"
               onClose={() => setError('')} dismissible>
          {error}
        </Alert>
      )}

      {term && flat.length === 0 && (
        <Alert variant="dark" className="border border-secondary text-white-50 py-2 small">
          No endpoint matches that filter. The selection is unchanged.
        </Alert>
      )}

      <div data-testid="endpoint-rows" className="border border-secondary rounded">
        {flat.length > 120 ? (
          <VirtualizedList
            items={flat}
            renderItem={renderRow}
            itemKey={(row) => row.key}
            estimatedItemSize={44}
            height="48vh"
          />
        ) : (
          flat.map((row) => <div key={row.key}>{renderRow(row)}</div>)
        )}
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------------------------
// TAB 2: HOW HARD THE RUN PROBES
// ---------------------------------------------------------------------------------------------

const newPayloadID = (existing) => {
  const used = new Set((existing || []).map((p) => p.id));
  let n = existing ? existing.length + 1 : 1;
  while (used.has(`cp-${n}`)) n += 1;
  return `cp-${n}`;
};

// One custom payload. The three rules that make a payload a probe rather than a guess are all
// enforced by the server and all surfaced here at the field that broke them: it belongs to
// exactly one class, it declares how a hit is told from a miss, and it survives the encoder for
// every insertion point it names.
const PayloadEditor = ({ payload, index, vocabulary, check, fieldIndex, onChange, onRemove }) => {
  const classes = (vocabulary && vocabulary.classes) || [];
  const info = classes.find((c) => c.key === payload.class);
  const modes = (vocabulary && vocabulary.detection_modes) || [];
  const mode = modes.find((m) => m.mode === (payload.detection && payload.detection.mode));
  const field = `custom_payloads[${index}]`;
  const set = (patch) => onChange({ ...payload, ...patch });
  const setDetection = (patch) => set({ detection: { ...(payload.detection || {}), ...patch } });

  return (
    <div className="border border-secondary rounded p-2 mb-2">
      <div className="d-flex justify-content-between align-items-center mb-2">
        <div className="d-flex align-items-center gap-2">
          <Form.Check
            type="switch"
            id={`cp-enabled-${payload.id}`}
            checked={!!payload.enabled}
            onChange={(e) => set({ enabled: e.target.checked })}
            aria-label={`Enable payload ${payload.id}`}
          />
          <span className="text-white" style={{ fontSize: '0.8rem', fontWeight: 600 }}>{payload.id}</span>
          {check && check.probe_id && (
            <code className="text-white-50" style={{ fontSize: '0.68rem' }}>{check.probe_id}</code>
          )}
        </div>
        <Button size="sm" variant="link" className="p-0 text-white-50" onClick={onRemove}>Remove</Button>
      </div>

      <div className="d-flex gap-2 flex-wrap mb-2">
        <Form.Group style={{ minWidth: '12rem' }}>
          <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Attack class</Form.Label>
          {/* One class, chosen. There is deliberately no "all": two classes shipping the same
              bytes cannot be told apart when one is blocked, so a block on either records the
              other as clean for a test it never ran. */}
          <Form.Select size="sm" value={payload.class || ''}
                       onChange={(e) => set({ class: e.target.value, points: [] })}
                       aria-label={`Attack class for ${payload.id}`}>
            <option value="">Choose one class</option>
            {classes.map((c) => (
              <option key={c.key} value={c.key}>{c.name} ({c.probe_count} probes)</option>
            ))}
          </Form.Select>
          <Problems index={fieldIndex} field={`${field}.class`} />
        </Form.Group>

        <Form.Group className="flex-grow-1" style={{ minWidth: '14rem' }}>
          <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Label</Form.Label>
          <Form.Control size="sm" value={payload.label || ''}
                        onChange={(e) => set({ label: e.target.value })}
                        aria-label={`Label for ${payload.id}`} />
        </Form.Group>
      </div>

      <Form.Group className="mb-2">
        <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Payload</Form.Label>
        <Form.Control as="textarea" rows={2} size="sm" value={payload.payload || ''}
                      onChange={(e) => set({ payload: e.target.value })}
                      aria-label={`Payload bytes for ${payload.id}`} />
        <Problems index={fieldIndex} field={`${field}.payload`} />
      </Form.Group>

      <div className="d-flex gap-2 flex-wrap mb-2">
        <Form.Group style={{ minWidth: '8rem' }}>
          <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Encoding</Form.Label>
          <Form.Select size="sm" value={payload.encoding || 'utf8'}
                       onChange={(e) => set({ encoding: e.target.value })}
                       aria-label={`Encoding for ${payload.id}`}>
            {((vocabulary && vocabulary.encodings) || []).map((e) => <option key={e} value={e}>{e}</option>)}
          </Form.Select>
        </Form.Group>
        <Form.Group style={{ minWidth: '10rem' }}>
          <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Encoder</Form.Label>
          <Form.Select size="sm" value={payload.encoder || ''}
                       onChange={(e) => set({ encoder: e.target.value })}
                       aria-label={`Encoder for ${payload.id}`}>
            {((vocabulary && vocabulary.encoders) || []).map((e) => (
              <option key={e || 'default'} value={e}>{e || "the slot's default"}</option>
            ))}
          </Form.Select>
        </Form.Group>
        <Form.Group style={{ minWidth: '8rem' }}>
          <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Marker</Form.Label>
          <Form.Select size="sm" value={payload.marker_pos || 'prefix'}
                       onChange={(e) => set({ marker_pos: e.target.value })}
                       aria-label={`Marker position for ${payload.id}`}>
            {((vocabulary && vocabulary.marker_positions) || []).map((m) => <option key={m} value={m}>{m}</option>)}
          </Form.Select>
          <Problems index={fieldIndex} field={`${field}.marker_pos`} />
        </Form.Group>
        <Form.Group style={{ minWidth: '8rem' }}>
          <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Tier</Form.Label>
          <Form.Select size="sm" value={payload.tier || ''}
                       onChange={(e) => set({ tier: e.target.value })}
                       aria-label={`Tier for ${payload.id}`}>
            <option value="">opt_in</option>
            {((vocabulary && vocabulary.tiers) || []).map((t) => <option key={t} value={t}>{t}</option>)}
          </Form.Select>
          <Problems index={fieldIndex} field={`${field}.tier`} />
        </Form.Group>
        <Form.Group style={{ minWidth: '7rem' }}>
          <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Risk</Form.Label>
          <Form.Select size="sm" value={payload.risk || ''}
                       onChange={(e) => set({ risk: e.target.value })}
                       aria-label={`Risk for ${payload.id}`}>
            <option value="">R1</option>
            {((vocabulary && vocabulary.risks) || []).map((r) => <option key={r} value={r}>{r}</option>)}
          </Form.Select>
          <Problems index={fieldIndex} field={`${field}.risk`} />
        </Form.Group>
      </div>

      <Form.Group className="mb-2">
        <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Insertion points</Form.Label>
        <div className="d-flex gap-3 flex-wrap">
          {((vocabulary && vocabulary.slot_kinds) || []).map((k) => {
            const why = info && info.unreachable ? info.unreachable[k] : '';
            return (
              <Form.Check
                key={k}
                type="checkbox"
                id={`cp-point-${payload.id}-${k}`}
                label={k}
                className="text-white-50"
                style={{ fontSize: '0.78rem' }}
                disabled={!info || !!why}
                title={why || ''}
                checked={(payload.points || []).includes(k)}
                onChange={(e) => set({
                  points: e.target.checked
                    ? [...(payload.points || []), k]
                    : (payload.points || []).filter((p) => p !== k),
                })}
              />
            );
          })}
        </div>
        <Problems index={fieldIndex} field={`${field}.points`} />
      </Form.Group>

      <div className="d-flex gap-2 flex-wrap mb-1">
        <Form.Group className="flex-grow-1" style={{ minWidth: '16rem' }}>
          <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>
            How a hit is told from a miss
          </Form.Label>
          {/* Required, and inherit is an option rather than the default. A payload that silently
              inherits an oracle it was never checked against is how a custom probe becomes a
              permanent unknown nobody notices. */}
          <Form.Select size="sm" value={(payload.detection && payload.detection.mode) || ''}
                       onChange={(e) => setDetection({ mode: e.target.value })}
                       aria-label={`Detection mode for ${payload.id}`}>
            <option value="">Choose one</option>
            {modes.map((m) => <option key={m.mode} value={m.mode}>{m.label}</option>)}
          </Form.Select>
          <Problems index={fieldIndex} field={`${field}.detection.mode`} />
        </Form.Group>

        {mode && mode.requires === 'pattern' && (
          <Form.Group className="flex-grow-1" style={{ minWidth: '14rem' }}>
            <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Pattern</Form.Label>
            <Form.Control size="sm" value={(payload.detection && payload.detection.pattern) || ''}
                          onChange={(e) => setDetection({ pattern: e.target.value })}
                          aria-label={`Detection pattern for ${payload.id}`} />
            <Problems index={fieldIndex} field={`${field}.detection.pattern`} />
          </Form.Group>
        )}
        {mode && mode.requires === 'statuses' && (
          <Form.Group style={{ minWidth: '12rem' }}>
            <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Statuses</Form.Label>
            <Form.Control size="sm" placeholder="500, 503"
                          value={((payload.detection && payload.detection.statuses) || []).join(', ')}
                          onChange={(e) => setDetection({
                            statuses: e.target.value.split(',')
                              .map((s) => Number(s.trim()))
                              .filter((n) => !Number.isNaN(n) && n !== 0),
                          })}
                          aria-label={`Detection statuses for ${payload.id}`} />
            <Problems index={fieldIndex} field={`${field}.detection.statuses`} />
          </Form.Group>
        )}
        {mode && mode.requires === 'delay_ms' && (
          <Form.Group style={{ minWidth: '10rem' }}>
            <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.75rem' }}>Delay (ms)</Form.Label>
            <Form.Control type="number" size="sm"
                          value={(payload.detection && payload.detection.delay_ms) || 0}
                          onChange={(e) => setDetection({ delay_ms: Number(e.target.value) })}
                          aria-label={`Detection delay for ${payload.id}`} />
            <Problems index={fieldIndex} field={`${field}.detection.delay_ms`} />
          </Form.Group>
        )}
      </div>

      <Problems index={fieldIndex} field={`${field}.id`} />

      {/* WHAT THE REAL ENCODER DID WITH THESE BYTES, per insertion point. Delivered is not enough:
          a cookie value carrying a semicolon is delivered and then split by any RFC 6265 parser,
          so the application reads a shorter string than the one sent. */}
      {check && check.delivery && check.delivery.length > 0 && (
        <div className="mt-2 pt-2" style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}>
          {check.delivery.map((d, i) => (
            <div key={`${d.point}-${d.media}-${i}`} style={{ fontSize: '0.7rem' }}>
              <span className="text-white-50">
                {d.point}{d.media ? ` (${d.media})` : ''} via {d.encoder || 'default'}:
              </span>{' '}
              <span style={{ color: d.proven ? '#7bc47f' : '#ffc107' }}>
                {d.proven ? `arrives ${d.survived}` : `${d.survived || 'not delivered'}${d.detail ? `, ${d.detail}` : ''}`}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export const InvestigateSettings = ({ targetId, onEnabledCount, registerSave }) => {
  const [cfg, setCfg] = useState(null);
  const [vocabulary, setVocabulary] = useState(null);
  const [validation, setValidation] = useState(null);
  const [retired, setRetired] = useState([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    if (!targetId) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/triage/${targetId}/settings`);
      if (!res.ok) {
        setError(`Could not load the Investigate settings (HTTP ${res.status}).`);
        return;
      }
      const body = await res.json();
      setCfg(body.settings || null);
      setVocabulary(body.vocabulary || null);
      setValidation(body.validation || null);
      setRetired(body.retired_classes || []);
    } catch (err) {
      setError(`Could not load the Investigate settings: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [targetId]);

  useEffect(() => { load(); }, [load]);

  const save = useCallback(async () => {
    if (!cfg) return;
    setSaving(true);
    setError('');
    setSaved(false);
    try {
      const res = await fetch(`/api/triage/${targetId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings: cfg }),
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) {
        // Nothing was written. The typed document is kept so the operator can fix the field the
        // server named rather than losing the edit and starting again.
        setValidation((body && body.validation) || null);
        setError((body && (body.message || body.error)) || `The settings were refused (HTTP ${res.status}).`);
        return;
      }
      setCfg(body.settings || cfg);
      setValidation(body.validation || null);
      setRetired(body.retired_classes || []);
      setSaved(true);
    } catch (err) {
      setError(`Could not save the Investigate settings: ${err.message}`);
    } finally {
      setSaving(false);
    }
  }, [cfg, targetId]);

  useEffect(() => { if (registerSave) registerSave({ save, saving, ready: !!cfg }); }, [registerSave, save, saving, cfg]);

  const enabledCount = (validation && validation.enabled_classes ? validation.enabled_classes.length : 0);
  useEffect(() => { if (onEnabledCount) onEnabledCount(enabledCount); }, [onEnabledCount, enabledCount]);

  const fieldIndex = useMemo(() => problemsByField(validation), [validation]);
  const payloadChecks = useMemo(() => {
    const out = {};
    ((validation && validation.payloads) || []).forEach((p) => { out[p.index] = p; });
    return out;
  }, [validation]);

  if (loading && !cfg) {
    return <div className="text-center py-3"><Spinner animation="border" size="sm" variant="danger" /></div>;
  }
  if (!cfg) {
    return <Alert variant="dark" className="border border-danger text-light py-2 small">{error || 'No settings.'}</Alert>;
  }

  const classes = (vocabulary && vocabulary.classes) || [];
  const setClass = (key, patch) => setCfg({
    ...cfg,
    classes: { ...cfg.classes, [key]: { ...(cfg.classes[key] || {}), ...patch } },
  });
  const setPacing = (patch) => setCfg({ ...cfg, pacing: { ...cfg.pacing, ...patch } });
  const setOOB = (patch) => setCfg({ ...cfg, oob: { ...cfg.oob, ...patch } });
  const payloads = cfg.custom_payloads || [];
  const setPayloads = (next) => setCfg({ ...cfg, custom_payloads: next });

  return (
    <div>
      {error && (
        <Alert variant="dark" className="border border-danger text-danger py-2 small"
               onClose={() => setError('')} dismissible>
          {error}
        </Alert>
      )}
      {saved && !error && (
        <Alert variant="dark" className="border border-secondary text-white-50 py-1 small"
               onClose={() => setSaved(false)} dismissible>
          Saved. {enabledCount} {enabledCount === 1 ? 'class' : 'classes'} will run.
        </Alert>
      )}
      {/* A class the register dropped and a placeholder that was never an attack class both
          land here, and the honest thing they have in common is that nothing would run them. */}
      {retired.length > 0 && (
        <Alert variant="dark" className="border border-secondary text-light py-2 small">
          Removed from this document because nothing would run them: {retired.join(', ')}.
        </Alert>
      )}

      {/* This tab configured a run it did not drive: the document was stored under
          vector_tool_settings and nothing read it. StartTriageRun now loads it
          (LoadTriageSettings, server/utils/triageRun.go) and StartInvestigateHandler chains the
          triage pass onto the reflection passes, so the screen says what the button does instead
          of implying it. One line, not a banner. */}
      <div className="text-white-50 mb-3" style={{ fontSize: '0.78rem' }}>
        Investigate runs its two reflection passes first and then the classifiers configured here.
      </div>

      <div className="d-flex align-items-end gap-3 flex-wrap mb-3">
        <Form.Group style={{ minWidth: '10rem' }}>
          <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.78rem' }}>Default depth</Form.Label>
          <Form.Select size="sm" value={cfg.tier || ''} onChange={(e) => setCfg({ ...cfg, tier: e.target.value })}
                       aria-label="Default depth">
            {((vocabulary && vocabulary.tiers) || []).map((t) => <option key={t} value={t}>{t}</option>)}
          </Form.Select>
          <Problems index={fieldIndex} field="tier" />
        </Form.Group>
        <div className="text-white-50" style={{ fontSize: '0.78rem' }}>
          {enabledCount} of {classes.length} classes enabled.
        </div>
      </div>

      <div className="mb-3">
        <div className="text-white mb-2" style={{ fontSize: '0.85rem', fontWeight: 600 }}>Attack classes</div>
        <Problems index={fieldIndex} field="classes" />
        {classes.map((c) => {
          const cs = cfg.classes[c.key] || {};
          const riskChoices = riskChoicesFor(c, cs.max_risk);
          return (
            <div key={c.key} className="d-flex align-items-center gap-2 flex-wrap px-2 py-1"
                 style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
              <Form.Check
                type="switch"
                id={`class-${c.key}`}
                checked={!!cs.enabled}
                onChange={(e) => setClass(c.key, { enabled: e.target.checked })}
                aria-label={`Enable ${c.name}`}
              />
              <span className="text-white" style={{ fontSize: '0.82rem', minWidth: '6rem' }}>{c.name}</span>
              <span className="text-white-50" style={{ fontSize: '0.7rem', minWidth: '5rem' }}>
                {c.probe_count} probes
              </span>
              {/* A class with one tier gets no control, because a control that changes nothing
                  invites the belief that the depth was chosen. */}
              {c.tiers.length > 1 ? (
                <Form.Select size="sm" style={{ width: 'auto' }} value={cs.tier || ''}
                             onChange={(e) => setClass(c.key, { tier: e.target.value })}
                             aria-label={`Depth for ${c.name}`}>
                  {c.tiers.map((t) => <option key={t} value={t}>{t}</option>)}
                </Form.Select>
              ) : (
                <span className="text-white-50" style={{ fontSize: '0.72rem' }}>{c.tiers[0] || 'no tier'}</span>
              )}
              {/* The same rule as the depth control to its left, applied to the ceiling: the
                  levels are the ones this class declares probes at, and a class with one of them
                  gets no control at all. */}
              {riskChoices.length > 1 ? (
                <Form.Select size="sm" style={{ width: 'auto' }} value={cs.max_risk || ''}
                             onChange={(e) => setClass(c.key, { max_risk: e.target.value })}
                             aria-label={`Maximum risk for ${c.name}`}>
                  {riskChoices.map((r) => <option key={r} value={r}>up to {r}</option>)}
                </Form.Select>
              ) : (
                <span className="text-white-50" style={{ fontSize: '0.72rem' }}>
                  {riskChoices.length ? `up to ${riskChoices[0]}` : 'no risk tier'}
                </span>
              )}
              <span className="d-flex gap-1 flex-wrap">
                {(c.points || []).map((p) => (
                  <Badge key={p} bg="dark" className="border border-secondary text-white-50">{p}</Badge>
                ))}
                {Object.keys(c.unreachable || {}).map((p) => (
                  <Badge key={p} bg="dark" className="border border-secondary text-white-50"
                         style={{ opacity: 0.5 }} title={c.unreachable[p]}>
                    {p} never
                  </Badge>
                ))}
              </span>
              <Problems index={fieldIndex} field={`classes.${c.key}.tier`} />
              <Problems index={fieldIndex} field={`classes.${c.key}.max_risk`} />
            </div>
          );
        })}
      </div>

      <div className="mb-3">
        <div className="text-white mb-2" style={{ fontSize: '0.85rem', fontWeight: 600 }}>Pacing</div>
        <div className="d-flex gap-3 flex-wrap">
          <div style={{ minWidth: '9rem' }}>
            <NumberField label="Requests per second" field="pacing.requests_per_second" step="0.01"
                         value={cfg.pacing.requests_per_second} index={fieldIndex}
                         onChange={(v) => setPacing({ requests_per_second: v })} />
          </div>
          <div style={{ minWidth: '8rem' }}>
            <NumberField label="Concurrency" field="pacing.concurrency"
                         value={cfg.pacing.concurrency} index={fieldIndex}
                         onChange={(v) => setPacing({ concurrency: v })} />
          </div>
          <div style={{ minWidth: '9rem' }}>
            <NumberField label="Probes per slot" field="pacing.per_slot_probes"
                         value={cfg.pacing.per_slot_probes} index={fieldIndex}
                         onChange={(v) => setPacing({ per_slot_probes: v })} />
          </div>
          <div style={{ minWidth: '9rem' }}>
            <NumberField label="Probes per run" field="pacing.per_run_probes"
                         value={cfg.pacing.per_run_probes} index={fieldIndex}
                         onChange={(v) => setPacing({ per_run_probes: v })} />
          </div>
          <div style={{ minWidth: '9rem' }}>
            <NumberField label="Mutating allowance" field="pacing.mutating_allowance"
                         value={cfg.pacing.mutating_allowance} index={fieldIndex}
                         onChange={(v) => setPacing({ mutating_allowance: v })} />
          </div>
          <div style={{ minWidth: '9rem' }}>
            <NumberField label="Browser allowance" field="pacing.browser_allowance"
                         value={cfg.pacing.browser_allowance} index={fieldIndex}
                         onChange={(v) => setPacing({ browser_allowance: v })} />
          </div>
        </div>
        <Form.Check
          type="switch"
          id="respect-target-budget"
          className="text-white-50"
          style={{ fontSize: '0.78rem' }}
          label="Pace to the target's own rate-limit headers"
          checked={!!cfg.pacing.respect_target_budget}
          onChange={(e) => setPacing({ respect_target_budget: e.target.checked })}
        />
        <Problems index={fieldIndex} field="pacing.respect_target_budget" />
      </div>

      <div className="mb-3">
        <div className="text-white mb-2" style={{ fontSize: '0.85rem', fontWeight: 600 }}>Out-of-band callbacks</div>
        <div className="d-flex gap-3 flex-wrap align-items-start">
          <Form.Group style={{ minWidth: '11rem' }}>
            <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.78rem' }}>Collaborator</Form.Label>
            <Form.Select size="sm" value={cfg.oob.mode || ''} onChange={(e) => setOOB({ mode: e.target.value })}
                         aria-label="Collaborator mode">
              {((vocabulary && vocabulary.oob_modes) || []).map((m) => (
                <option key={m || 'none'} value={m}>{m || 'none'}</option>
              ))}
            </Form.Select>
            <Problems index={fieldIndex} field="oob.mode" />
          </Form.Group>
          <Form.Group className="flex-grow-1" style={{ minWidth: '14rem' }}>
            <Form.Label className="text-white-50 mb-1" style={{ fontSize: '0.78rem' }}>Base host</Form.Label>
            <Form.Control size="sm" value={cfg.oob.base || ''} onChange={(e) => setOOB({ base: e.target.value })}
                          aria-label="Collaborator base host" />
            <Problems index={fieldIndex} field="oob.base" />
          </Form.Group>
          <div style={{ minWidth: '9rem' }}>
            <NumberField label="Grace (seconds)" field="oob.grace_seconds"
                         value={cfg.oob.grace_seconds} index={fieldIndex}
                         onChange={(v) => setOOB({ grace_seconds: v })} />
          </div>
          <Form.Check
            type="switch"
            id="oob-serves-content"
            className="text-white-50 mt-4"
            style={{ fontSize: '0.78rem' }}
            label="The collaborator serves content"
            checked={!!cfg.oob.serves_content}
            onChange={(e) => setOOB({ serves_content: e.target.checked })}
          />
        </div>
      </div>

      <div className="mb-2">
        <div className="d-flex justify-content-between align-items-center mb-2">
          <div className="text-white" style={{ fontSize: '0.85rem', fontWeight: 600 }}>Your payloads</div>
          <Button size="sm" variant="outline-danger"
                  onClick={() => setPayloads([...payloads, {
                    id: newPayloadID(payloads),
                    class: '',
                    label: '',
                    payload: '',
                    encoding: 'utf8',
                    points: [],
                    encoder: '',
                    tier: '',
                    risk: '',
                    marker_pos: 'prefix',
                    detection: { mode: '' },
                    enabled: true,
                    notes: '',
                  }])}>
            Add payload
          </Button>
        </div>
        {payloads.length === 0 ? (
          <div className="text-white-50" style={{ fontSize: '0.75rem' }}>
            A payload belongs to exactly one class and declares how a hit is told from a miss.
          </div>
        ) : payloads.map((p, i) => (
          <PayloadEditor
            key={p.id || i}
            payload={p}
            index={i}
            vocabulary={vocabulary}
            check={payloadChecks[i]}
            fieldIndex={fieldIndex}
            onChange={(next) => setPayloads(payloads.map((x, j) => (j === i ? next : x)))}
            onRemove={() => setPayloads(payloads.filter((x, j) => j !== i))}
          />
        ))}
      </div>

      {/* The registry's own isolation failures, if any. Not the operator's doing and they do not
          block a save, but a run refuses to start on them. */}
      {validation && (validation.registry_violations || []).length > 0 && (
        <Alert variant="dark" className="border border-danger text-danger py-2 small">
          The shipped probe registry has {validation.registry_violations.length} isolation
          {validation.registry_violations.length === 1 ? ' violation' : ' violations'}. A run
          refuses to start until they are fixed.
        </Alert>
      )}
      {validation && (validation.isolation_checks_not_run || []).length > 0 && (
        <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
          {validation.isolation_checks_not_run.length} isolation checks are not implemented yet, so
          they have not passed.
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------------------------

function AttackVectorConfigureModal({ show, handleClose, activeTarget }) {
  const [tab, setTab] = useState('endpoints');
  const [saver, setSaver] = useState(null);
  const targetId = activeTarget && activeTarget.id;

  // Reset to the first tab each time it opens, so the screen an operator lands on matches the
  // button they pressed rather than wherever they were last.
  useEffect(() => { if (show) setTab('endpoints'); }, [show]);

  const registerSave = useCallback((s) => setSaver(s), []);

  return (
    <Modal show={show} onHide={handleClose} size="xl" data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Configure Investigate</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ maxHeight: '75vh', overflowY: 'auto' }}>
        <Nav variant="tabs" activeKey={tab} onSelect={(k) => k && setTab(k)} className="mb-3">
          <Nav.Item>
            <Nav.Link eventKey="endpoints" style={tab === 'endpoints' ? { color: ACCENT } : {}}>
              Endpoints
            </Nav.Link>
          </Nav.Item>
          <Nav.Item>
            <Nav.Link eventKey="settings" style={tab === 'settings' ? { color: ACCENT } : {}}>
              Investigate settings
            </Nav.Link>
          </Nav.Item>
        </Nav>

        {!targetId ? (
          <Alert variant="dark" className="border border-secondary text-light py-2 small">
            No active target.
          </Alert>
        ) : (
          <>
            {/* Both tabs stay mounted once visited so an edit in progress on the settings form is
                not thrown away by a trip to the endpoint list. */}
            <div hidden={tab !== 'endpoints'}>
              <EndpointSelection targetId={targetId} />
            </div>
            <div hidden={tab !== 'settings'}>
              <InvestigateSettings targetId={targetId} registerSave={registerSave} />
            </div>
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>Close</Button>
        {/* Only the settings tab has anything to save: the endpoint selection writes as it is
            clicked, and a Save button beside it would read as the selection being unsaved. */}
        {tab === 'settings' && (
          <Button variant="danger" disabled={!saver || !saver.ready || saver.saving}
                  onClick={() => saver && saver.save()}>
            {saver && saver.saving ? 'Saving...' : 'Save'}
          </Button>
        )}
      </Modal.Footer>
    </Modal>
  );
}

export default AttackVectorConfigureModal;
