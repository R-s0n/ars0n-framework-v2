import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Modal, Button, Form, InputGroup, Spinner, ProgressBar, Table, Alert } from 'react-bootstrap';

// Detect Flows: active flow detection. This modal sends requests to the target.
//
// The operator picks the verbs, the rate, the budget and the timeout, and presses Run. The dry run
// is a preview they can ask for at any point; it is not a gate.
//
// One thing this screen does NOT let the operator choose, because it is correctness rather than
// preference:
//
//   SCOPE. A host marked in_scope=false is never contacted, on the original endpoint and again on
//   every redirect destination. That boundary belongs to the bug bounty programme.
//
// The verb is the operator's. Any syntactically valid method token is sendable and any combination
// is legal.

const MONO = 'Menlo, Consolas, "Courier New", monospace';

// What the UI opens with, matching DefaultFlowDetectionConfig() in flowDetectionActive.go.
//
// EVERY quick-pick verb is on by default, not just GET. The verb an endpoint was observed answering
// is also the selection filter, so a GET-only default silently narrowed every run to a third of the
// corpus and made the writes look untested when they had simply never been asked for.
const DEFAULT_CONFIG = {
  methods: ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'],
  rps: 1,
  max_requests: 250,
  follow_redirects: true,
  max_redirects: 5,
  timeout_s: 15,
  include_query: false,
  send_recorded_bodies: true,
};

// Ceilings copied from the server so the inputs cannot ask for something that will be silently
// clamped. A control that reports one number while the run uses another is the field-translation
// failure this framework has already been bitten by.
const MAX_RPS = 10;
const HARD_MAX_REQUESTS = 5000;
const HARD_MAX_REDIRECTS = 10;
const MAX_TIMEOUT_S = 60;

// The quick picks, not the whole vocabulary. The transport sends any syntactically valid method
// token, so these seven are here because they are the ones typed most often; anything else goes in
// through the box next to them. Any combination is legal and all seven start selected.
const METHODS = [
  { name: 'GET', note: 'Request the endpoint.' },
  { name: 'HEAD', note: 'Headers only, no response body.' },
  { name: 'OPTIONS', note: 'Ask the endpoint which verbs it allows.' },
  { name: 'POST', note: 'Sends the recorded body when the corpus has one.' },
  { name: 'PUT', note: 'Sends the recorded body when the corpus has one.' },
  { name: 'PATCH', note: 'Sends the recorded body when the corpus has one.' },
  { name: 'DELETE', note: 'Sends the recorded body when the corpus has one.' },
];

// RFC 9110 method = token = 1*tchar. The SHAPE is what gets validated, never the spelling: PROPFIND,
// LOCK, REPORT and an application's own verb are all legal here, and a curated list of seven would
// only mean the framework could not test the endpoints that answer them.
const METHOD_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

const LIVE_STATUSES = ['pending', 'running', 'cancelling'];
const TERMINAL_STATUSES = ['completed', 'cancelled', 'aborted', 'error'];

// Every reason code FlowDetectionSkip can carry, and what each one means to the operator. Grouped
// rather than listed flat, because "your rule caught this" and "this is outside scope" call for
// completely different reactions.
const SKIP_REASONS = [
  {
    code: 'exclusion',
    title: 'Excluded by one of your rules',
    blurb: 'You wrote a rule that matched. The pattern and your own reason are on each row.',
    variant: 'text-info',
  },
  {
    code: 'host_excluded',
    title: 'Host marked out of scope on this target',
    blurb: 'Somebody ticked in_scope=false for this host. It is never requested, never followed as a '
      + 'redirect destination, and no configuration here can override it.',
    variant: 'text-warning',
  },
  {
    code: 'out_of_scope',
    title: 'Outside the scope boundary',
    blurb: 'The host is not inside this target\'s declared scope.',
    variant: 'text-warning',
  },
  {
    code: 'method',
    title: 'Recorded with a verb this run is not sending',
    blurb: 'The verb filter runs against the verb the endpoint was OBSERVED with, so a GET-only run '
      + 'never invents a GET for an endpoint only ever seen as a POST.',
    variant: 'text-white-50',
  },
  {
    code: 'unusable_url',
    title: 'Not a usable http(s) URL',
    blurb: 'The stored row does not parse into something that can be requested.',
    variant: 'text-white-50',
  },
  {
    code: 'over_budget',
    title: 'Past the request budget',
    blurb: 'The budget was reached before this endpoint\'s turn. It is listed as a skip rather than '
      + 'quietly cut off the end of the list. Raise the budget to include it.',
    variant: 'text-white-50',
  },
];

const RENDER_CAP = 200;

function formatSeconds(total) {
  const n = Number(total);
  if (!Number.isFinite(n) || n < 0) return 'unknown';
  if (n < 60) return `${Math.round(n)} s`;
  const minutes = Math.floor(n / 60);
  const seconds = Math.round(n % 60);
  if (minutes < 60) return seconds ? `${minutes} m ${seconds} s` : `${minutes} m`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} m`;
}

function formatTimestamp(value) {
  if (!value) return null;
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return String(value);
  return at.toLocaleString();
}

function errorMessage(data, body, status) {
  if (data && typeof data.message === 'string' && data.message) return data.message;
  if (data && typeof data.error === 'string' && data.error) return data.error;
  if (body && body.length < 400) return body;
  return `Request failed (${status})`;
}

async function requestJSON(url, options) {
  const res = await fetch(url, options);
  const body = await res.text();
  let data = null;
  try {
    data = body ? JSON.parse(body) : null;
  } catch (err) {
    data = null;
  }
  return { ok: res.ok, status: res.status, data, body };
}

// The identity of a configuration, used to tell whether the plan on screen was computed for what is
// currently in the form. Methods are sorted because a set has no order.
function configKey(cfg) {
  if (!cfg) return '';
  return JSON.stringify({
    methods: [...(cfg.methods || [])].map((m) => String(m).toUpperCase()).sort(),
    rps: Number(cfg.rps),
    max_requests: Number(cfg.max_requests),
    follow_redirects: Boolean(cfg.follow_redirects),
    max_redirects: Number(cfg.max_redirects),
    timeout_s: Number(cfg.timeout_s),
    include_query: Boolean(cfg.include_query),
    send_recorded_bodies: cfg.send_recorded_bodies !== false,
  });
}

// The three verbs a recorded body is never replayed with, which is what decides whether the body
// toggle is worth showing at all. Stated as the exception rather than as a list of the verbs that
// DO carry one, so a method this file has never heard of gets the control instead of losing it.
const NO_RECORDED_BODY = ['GET', 'HEAD', 'OPTIONS'];

// The wire body is the config as typed. There is no acknowledgement field and nothing derived: the
// server reads exactly the keys this screen shows, so what the operator set is what is sent.
function wireConfig(cfg) {
  return { ...cfg };
}

// Reads the detection source off a flow row whichever shape the flows endpoint reports it in, and
// returns '' when it reports none. '' is never treated as 'passive': the run summary would then
// claim flows changed from passive to both on a build that never said passive in the first place.
function flowSourceOf(flow, sourcesById) {
  if (!flow) return '';
  const direct = flow.detection_source || flow.source || '';
  const mapped = sourcesById && flow.id ? sourcesById[flow.id] : '';
  const value = String(direct || mapped || '').trim().toLowerCase();
  if (value === 'passive' || value === 'active' || value === 'both') return value;
  return '';
}

const Field = ({ label, hint, children }) => (
  <div className="mb-2">
    <div className="text-white-50" style={{ fontSize: '0.68rem' }}>{label}</div>
    {children}
    {hint && <div className="text-white-50 mt-1" style={{ fontSize: '0.64rem' }}>{hint}</div>}
  </div>
);

export const DetectFlowsModal = ({ show, handleClose, activeTarget }) => {
  const targetId = activeTarget && activeTarget.id;

  const [config, setConfig] = useState(DEFAULT_CONFIG);
  // Read by the callbacks below so they do not have to depend on `config` and be rebuilt (and
  // re-trigger their effects) on every keystroke in a number box.
  const configRef = useRef(config);
  configRef.current = config;

  const [customMethod, setCustomMethod] = useState('');
  const [customMethodError, setCustomMethodError] = useState('');

  const [plan, setPlan] = useState(null);
  const [planKey, setPlanKey] = useState('');
  const [planError, setPlanError] = useState('');
  const [planning, setPlanning] = useState(false);
  const planSeq = useRef(0);

  const [exclusions, setExclusions] = useState([]);
  const [exclusionsError, setExclusionsError] = useState('');
  const [exclusionsLoading, setExclusionsLoading] = useState(false);
  const [newPattern, setNewPattern] = useState('');
  const [newReason, setNewReason] = useState('');
  const [addError, setAddError] = useState('');
  const [adding, setAdding] = useState(false);
  const [pendingDeleteId, setPendingDeleteId] = useState('');
  const reasonRef = useRef(null);

  const [status, setStatus] = useState(null);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState('');
  const [cancelError, setCancelError] = useState('');
  const [summary, setSummary] = useState(null);

  const [showAllTargets, setShowAllTargets] = useState(false);
  const [showAllSkipped, setShowAllSkipped] = useState(false);

  // The before-picture, taken at the moment the run starts. Without it the completion summary can
  // report a total and nothing else, and "how many of these are new" is the question being asked.
  const snapshotRef = useRef(null);
  const startedRunIdRef = useRef('');
  const prevStatusRef = useRef('');

  const runStatus = (status && status.status) || 'idle';
  const isLive = LIVE_STATUSES.includes(runStatus);

  /* ----------------------------------------------------------------- loaders */

  const loadExclusions = useCallback(async () => {
    if (!targetId) return;
    setExclusionsLoading(true);
    try {
      const { ok, status: code, data, body } = await requestJSON(
        `/api/flow-detection/${targetId}/exclusions`
      );
      if (!ok) {
        setExclusionsError(errorMessage(data, body, code));
        return;
      }
      setExclusions(Array.isArray(data && data.exclusions) ? data.exclusions : []);
      setExclusionsError('');
    } catch (err) {
      setExclusionsError(`Could not reach the framework: ${err.message}`);
    } finally {
      setExclusionsLoading(false);
    }
  }, [targetId]);

  // The preview. A separate URL from /run, so no value in the body can turn it into live traffic.
  const runDryRun = useCallback(async (override) => {
    if (!targetId) return;
    const cfg = override || configRef.current;
    const key = configKey(cfg);
    const seq = planSeq.current + 1;
    planSeq.current = seq;
    setPlanning(true);
    setPlanError('');
    try {
      const { ok, status: code, data, body } = await requestJSON(
        `/api/flow-detection/${targetId}/dry-run`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(wireConfig(cfg)),
        }
      );
      if (seq !== planSeq.current) return;
      if (!ok || !data) {
        // The plan is dropped, not kept and re-labelled. A refused configuration has no plan, and
        // leaving the last one on screen next to a disabled button invites the operator to believe
        // they are looking at what would be sent.
        setPlan(null);
        setPlanKey('');
        setPlanError(errorMessage(data, body, code));
        return;
      }
      setPlan(data);
      setPlanKey(key);
      setPlanError('');
      setShowAllTargets(false);
      setShowAllSkipped(false);
    } catch (err) {
      if (seq === planSeq.current) {
        setPlan(null);
        setPlanKey('');
        setPlanError(`Could not reach the framework: ${err.message}`);
      }
    } finally {
      if (seq === planSeq.current) setPlanning(false);
    }
  }, [targetId]);

  const fetchStatus = useCallback(async () => {
    if (!targetId) return;
    try {
      const { ok, data } = await requestJSON(`/api/flow-detection/${targetId}/status`);
      if (ok && data) setStatus(data);
    } catch (err) {
      // A dropped poll is not worth an error banner over a running scan. The next tick corrects it,
      // and the run is on the server regardless of whether this browser can see it.
    }
  }, [targetId]);

  // Every flow this target has, with its detection source, as one comparable object.
  const fetchFlowSnapshot = useCallback(async () => {
    if (!targetId) return null;
    try {
      const { ok, data } = await requestJSON(`/api/replay-request/${targetId}/flows?limit=2000`);
      if (!ok || !data || !Array.isArray(data.flows)) return null;
      const sources = {};
      let sourcesReported = false;
      data.flows.forEach((f) => {
        if (!f || !f.id) return;
        const src = flowSourceOf(f, data.detection_sources);
        if (src) sourcesReported = true;
        sources[f.id] = src;
      });
      return {
        ids: data.flows.map((f) => f && f.id).filter(Boolean),
        sources,
        total: Number(data.total) || data.flows.length,
        truncated: Boolean(data.truncated),
        sourcesReported,
      };
    } catch (err) {
      return null;
    }
  }, [targetId]);

  /* -------------------------------------------------------------------- open */

  useEffect(() => {
    if (!show || !targetId) return;
    setConfig(DEFAULT_CONFIG);
    setCustomMethod('');
    setCustomMethodError('');
    setPlan(null);
    setPlanKey('');
    setPlanError('');
    setNewPattern('');
    setNewReason('');
    setAddError('');
    setPendingDeleteId('');
    setStartError('');
    setCancelError('');
    setSummary(null);
    setShowAllTargets(false);
    setShowAllSkipped(false);
    snapshotRef.current = null;
    startedRunIdRef.current = '';
    prevStatusRef.current = '';
    loadExclusions();
    fetchStatus();
    // Opening previews the default configuration so the endpoint list is populated. It sends
    // nothing, and it is not a precondition for Run.
    runDryRun(DEFAULT_CONFIG);
  }, [show, targetId, loadExclusions, fetchStatus, runDryRun]);

  /* ------------------------------------------------------------------ polling */

  useEffect(() => {
    if (!show || !isLive) return undefined;
    const timer = setInterval(fetchStatus, 1500);
    return () => clearInterval(timer);
  }, [show, isLive, fetchStatus]);

  const buildSummary = useCallback(async () => {
    const before = snapshotRef.current;
    const after = await fetchFlowSnapshot();
    if (!after) {
      setSummary({ unavailable: 'The flow list could not be read after the run, so nothing can be compared.' });
      return;
    }
    if (!before) {
      setSummary({
        total: after.total,
        truncated: after.truncated,
        noBefore: true,
      });
      return;
    }
    const beforeIds = new Set(before.ids);
    const newIds = after.ids.filter((id) => !beforeIds.has(id));
    const nowBoth = after.ids.filter((id) => (
      before.sources[id] === 'passive' && after.sources[id] === 'both'
    ));
    setSummary({
      total: after.total,
      before: before.total,
      newCount: newIds.length,
      bothCount: nowBoth.length,
      // The counts above are only meaningful if both snapshots actually carried a source. Reported
      // rather than assumed, so a zero never has to be read as "nothing was promoted" when it means
      // "this build never said".
      sourcesReported: Boolean(before.sourcesReported && after.sourcesReported),
      truncated: Boolean(before.truncated || after.truncated),
    });
  }, [fetchFlowSnapshot]);

  // Terminal transition. Only summarised for a run this modal started, because a summary needs the
  // before-picture and only the code that pressed the button has one.
  useEffect(() => {
    const now = runStatus;
    const was = prevStatusRef.current;
    prevStatusRef.current = now;
    if (!now || now === was) return;
    if (!TERMINAL_STATUSES.includes(now) || !LIVE_STATUSES.includes(was)) return;
    if (!startedRunIdRef.current) return;
    if (status && status.run_id && status.run_id !== startedRunIdRef.current) return;
    buildSummary();
    // The corpus changed, so the plan on screen describes a corpus that no longer exists.
    runDryRun();
  }, [runStatus, status, buildSummary, runDryRun]);

  /* ------------------------------------------------------------------ config */

  const patch = (changes) => {
    setConfig((prev) => ({ ...prev, ...changes }));
    setStartError('');
  };

  const toggleMethod = (name) => {
    setConfig((prev) => {
      const has = prev.methods.includes(name);
      // Never leave the set empty. The server reads an empty list as "unspecified" and falls back to
      // the full default set, so an empty row would mean the exact opposite of what it shows: nothing
      // ticked next to a plan sending every verb. The last tick stays.
      const next = has ? prev.methods.filter((m) => m !== name) : [...prev.methods, name];
      if (!next.length) return prev;
      return { ...prev, methods: next };
    });
    setStartError('');
  };

  // The SHAPE is checked, never the spelling. A rejection here means the characters cannot go on a
  // request line at all, not that this file has never heard of the verb.
  const addCustomMethod = () => {
    const raw = customMethod.trim();
    if (!raw) return;
    const name = raw.toUpperCase();
    if (!METHOD_TOKEN.test(name)) {
      setCustomMethodError(`"${raw}" is not a valid HTTP method token. No spaces, no quotes, no separators.`);
      return;
    }
    setConfig((prev) => (prev.methods.includes(name)
      ? prev
      : { ...prev, methods: [...prev.methods, name] }));
    setCustomMethod('');
    setCustomMethodError('');
    setStartError('');
  };

  const numberPatch = (key, raw, { min, max, integer }) => {
    const value = integer ? parseInt(raw, 10) : parseFloat(raw);
    if (!Number.isFinite(value)) return;
    patch({ [key]: Math.min(max, Math.max(min, value)) });
  };

  /* -------------------------------------------------------------- exclusions */

  const addExclusion = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!targetId || adding) return;
    const pattern = newPattern.trim();
    const reason = newReason.trim();
    if (!pattern) {
      setAddError('A pattern is required. Use a path (/account/verify), a host (api.example.com), or both.');
      return;
    }
    if (!reason) {
      setAddError('A reason is required, for example "sends a verification code to the account '
        + 'owner". The API requires one too.');
      return;
    }
    setAdding(true);
    setAddError('');
    try {
      const { ok, status: code, data, body } = await requestJSON(
        `/api/flow-detection/${targetId}/exclusions`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pattern, reason }),
        }
      );
      if (!ok) {
        setAddError(errorMessage(data, body, code));
        return;
      }
      setExclusions(Array.isArray(data && data.exclusions) ? data.exclusions : exclusions);
      setNewPattern('');
      setNewReason('');
      // The plan on screen was computed under the old ruleset, so it is recomputed rather than left
      // to be trusted. This is the review loop: exclude, watch the target list shrink, repeat.
      runDryRun();
    } catch (err) {
      setAddError(`Could not reach the framework: ${err.message}`);
    } finally {
      setAdding(false);
    }
  };

  const deleteExclusion = async (id) => {
    setPendingDeleteId('');
    try {
      const { ok, status: code, data, body } = await requestJSON(
        `/api/flow-detection/exclusions/${id}`,
        { method: 'DELETE' }
      );
      if (!ok) {
        setExclusionsError(errorMessage(data, body, code));
        return;
      }
      await loadExclusions();
      runDryRun();
    } catch (err) {
      setExclusionsError(`Could not reach the framework: ${err.message}`);
    }
  };

  const excludeTarget = (row) => {
    const host = String((row && row.host) || '').trim();
    const path = String((row && row.path) || '/').trim();
    setNewPattern(host ? `${host}${path}` : path);
    setAddError('');
    if (reasonRef.current && reasonRef.current.focus) reasonRef.current.focus();
  };

  /* --------------------------------------------------------------- the gate */

  const currentKey = configKey(config);
  const planIsForThisConfig = Boolean(plan) && planKey === currentKey;
  const requestCount = plan ? Number(plan.request_count) || 0 : 0;

  // Run is pressable without a preview. The only things that block it are the absence of a target
  // and a run already being in flight; everything else is the server's answer to give.
  const gateReason = useMemo(() => {
    if (!targetId) return 'No target selected.';
    if (isLive) return 'A run is already in progress.';
    return '';
  }, [targetId, isLive]);

  const canRun = gateReason === '' && !starting;

  const startRun = async () => {
    if (!canRun) return;
    setStarting(true);
    setStartError('');
    setCancelError('');
    setSummary(null);
    try {
      // Taken BEFORE the request that starts the run, so the comparison cannot include flows the run
      // itself produced.
      snapshotRef.current = await fetchFlowSnapshot();
      const { ok, status: code, data, body } = await requestJSON(
        `/api/flow-detection/${targetId}/run`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(wireConfig(config)),
        }
      );
      if (!ok || !data || !data.run_id) {
        setStartError(errorMessage(data, body, code));
        snapshotRef.current = null;
        return;
      }
      startedRunIdRef.current = data.run_id;
      prevStatusRef.current = 'running';
      setStatus({
        run_id: data.run_id,
        session_id: data.session_id,
        status: 'running',
        planned: Number(data.planned) || 0,
        sent: 0,
        errors: 0,
        excluded: Number(data.excluded) || 0,
        redirects: 0,
      });
      // Deliberately NOT followed by an immediate status poll. The 202 above is the authoritative
      // "this run exists and is running"; a poll fired in the same tick can only ever agree with it
      // or, if anything about the read goes wrong, replace a known-live run with an 'idle' that puts
      // the send button back under the operator's cursor. The 1.5s poll takes over from here.
    } catch (err) {
      setStartError(`Could not reach the framework: ${err.message}`);
      snapshotRef.current = null;
    } finally {
      setStarting(false);
    }
  };

  const cancelRun = async () => {
    if (!targetId) return;
    setCancelError('');
    try {
      const { ok, status: code, data, body } = await requestJSON(
        `/api/flow-detection/${targetId}/cancel`,
        { method: 'POST' }
      );
      if (!ok) {
        setCancelError(errorMessage(data, body, code));
        return;
      }
      setStatus((prev) => ({ ...(prev || {}), status: 'cancelling' }));
      fetchStatus();
    } catch (err) {
      setCancelError(`Could not reach the framework: ${err.message}`);
    }
  };

  /* ------------------------------------------------------------------ render */

  const skippedGroups = useMemo(() => {
    const rows = (plan && Array.isArray(plan.skipped)) ? plan.skipped : [];
    return SKIP_REASONS
      .map((reason) => ({ ...reason, rows: rows.filter((r) => r && r.reason === reason.code) }))
      .filter((group) => group.rows.length > 0);
  }, [plan]);

  const bodyTakingSelected = useMemo(
    () => (config.methods || []).some((m) => !NO_RECORDED_BODY.includes(String(m).toUpperCase())),
    [config.methods]
  );

  // Whatever the operator picked that is not one of the quick picks, so a custom verb is visible and
  // removable instead of living only in the config object.
  const extraMethods = useMemo(
    () => (config.methods || [])
      .map((m) => String(m).toUpperCase())
      .filter((m) => !METHODS.some((q) => q.name === m))
      .sort(),
    [config.methods]
  );

  const renderMethods = () => (
    <Field
      label="METHODS"
      hint="The verb is also the selection filter: a run only touches endpoints already observed
            answering that verb, so it never invents a request nobody has seen."
    >
      <div className="d-flex flex-wrap gap-3 mt-1">
        {METHODS.map((m) => (
          <Form.Check
            key={m.name}
            type="checkbox"
            id={`detect-method-${m.name}`}
            className="text-white"
            style={{ fontSize: '0.75rem' }}
            label={<span style={{ fontFamily: MONO }}>{m.name}</span>}
            checked={config.methods.includes(m.name)}
            disabled={isLive}
            onChange={() => toggleMethod(m.name)}
            title={m.note}
          />
        ))}
      </div>

      {extraMethods.length > 0 && (
        <div className="d-flex flex-wrap gap-2 mt-2">
          {extraMethods.map((m) => (
            <Button
              key={m}
              size="sm"
              variant="outline-info"
              className="py-0 px-2"
              style={{ fontFamily: MONO, fontSize: '0.7rem' }}
              disabled={isLive}
              onClick={() => toggleMethod(m)}
              title="Remove this verb from the run."
            >
              {m}<i className="bi bi-x ms-1" />
            </Button>
          ))}
        </div>
      )}

      <div className="d-flex align-items-center gap-2 mt-2" style={{ maxWidth: '22rem' }}>
        <Form.Control
          size="sm"
          className="bg-dark text-white border-secondary"
          style={{ fontFamily: MONO, fontSize: '0.72rem' }}
          placeholder="PROPFIND, REPORT, your own verb"
          value={customMethod}
          disabled={isLive}
          onChange={(e) => { setCustomMethod(e.target.value); setCustomMethodError(''); }}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addCustomMethod(); } }}
        />
        <Button
          size="sm"
          variant="outline-light"
          style={{ fontSize: '0.72rem' }}
          disabled={isLive || !customMethod.trim()}
          onClick={addCustomMethod}
        >
          Add
        </Button>
      </div>
      {customMethodError && (
        <div className="text-danger mt-1" style={{ fontSize: '0.68rem' }}>{customMethodError}</div>
      )}

      {bodyTakingSelected && (
        <Form.Check
          type="checkbox"
          id="detect-send-bodies"
          className="text-white mt-2"
          style={{ fontSize: '0.72rem' }}
          label={<span>Send the recorded request body when the corpus has one</span>}
          checked={config.send_recorded_bodies !== false}
          disabled={isLive}
          onChange={() => setConfig((prev) => ({
            ...prev, send_recorded_bodies: prev.send_recorded_bodies === false,
          }))}
          title="Off sends an empty body, which most endpoints answer 400 or 415."
        />
      )}
    </Field>
  );

  const renderRate = () => (
    <>
      <div className="d-flex gap-2">
        <Field label="REQUESTS PER SECOND">
          <Form.Control
            type="number"
            size="sm"
            min={0.1}
            max={MAX_RPS}
            step={0.1}
            value={config.rps}
            disabled={isLive}
            onChange={(e) => numberPatch('rps', e.target.value, { min: 0.1, max: MAX_RPS })}
            className="bg-dark text-white border-secondary"
            data-bs-theme="dark"
          />
        </Field>
        <Field label="TOTAL REQUEST BUDGET">
          <Form.Control
            type="number"
            size="sm"
            min={1}
            max={HARD_MAX_REQUESTS}
            step={10}
            value={config.max_requests}
            disabled={isLive}
            onChange={(e) => numberPatch('max_requests', e.target.value, { min: 1, max: HARD_MAX_REQUESTS, integer: true })}
            className="bg-dark text-white border-secondary"
            data-bs-theme="dark"
          />
        </Field>
        <Field label="TIMEOUT (s)">
          <Form.Control
            type="number"
            size="sm"
            min={1}
            max={MAX_TIMEOUT_S}
            value={config.timeout_s}
            disabled={isLive}
            onChange={(e) => numberPatch('timeout_s', e.target.value, { min: 1, max: MAX_TIMEOUT_S, integer: true })}
            className="bg-dark text-white border-secondary"
            data-bs-theme="dark"
          />
        </Field>
      </div>
      <div className="text-white-50 mb-2" style={{ fontSize: '0.64rem' }}>
        Paced per host with jitter, up to {MAX_RPS} rps and {HARD_MAX_REQUESTS.toLocaleString()}{' '}
        requests. The run aborts on its own if the target starts answering 429 or 503, if the
        connection collapses, or if latency degrades.
      </div>

      <div className="d-flex gap-2 align-items-end">
        <Field
          label="REDIRECTS"
          hint="Followed by default. Every destination is checked against your exclusions and the
                scope again before it is requested."
        >
          <Form.Check
            type="switch"
            id="detect-follow-redirects"
            className="text-white"
            style={{ fontSize: '0.72rem' }}
            label="Follow redirects"
            checked={config.follow_redirects}
            disabled={isLive}
            onChange={(e) => patch({ follow_redirects: e.target.checked })}
          />
        </Field>
        <Field label="MAX HOPS">
          <Form.Control
            type="number"
            size="sm"
            min={0}
            max={HARD_MAX_REDIRECTS}
            value={config.max_redirects}
            disabled={isLive || !config.follow_redirects}
            onChange={(e) => numberPatch('max_redirects', e.target.value, { min: 0, max: HARD_MAX_REDIRECTS, integer: true })}
            className="bg-dark text-white border-secondary"
            style={{ width: '90px' }}
            data-bs-theme="dark"
          />
        </Field>
      </div>

      <div className="mt-1">
        <Form.Check
          type="checkbox"
          id="detect-include-query"
          className="text-white"
          style={{ fontSize: '0.72rem' }}
          checked={config.include_query}
          disabled={isLive}
          onChange={(e) => patch({ include_query: e.target.checked })}
          label={
            <span>
              Send the recorded query string
              <span className="text-white-50 d-block" style={{ fontSize: '0.66rem' }}>
                Off by default. Stored queries carry the values a real browser sent, tokens included.
                The preview shows the full URL either way.
              </span>
            </span>
          }
        />
      </div>
    </>
  );

  const renderExclusions = () => (
    <div className="border border-secondary rounded p-2 mt-3">
      <div className="d-flex align-items-center mb-2">
        <span className="text-white-50" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
          EXCLUSIONS
        </span>
        {exclusionsLoading && <Spinner animation="border" size="sm" variant="danger" className="ms-2" />}
        <span className="text-white-50 ms-auto" style={{ fontSize: '0.65rem' }}>
          {exclusions.length} rule{exclusions.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="text-white-50 mb-2" style={{ fontSize: '0.66rem' }}>
        Endpoints matching a rule here are never requested. A rule with no wildcard matches the whole
        subtree on a segment boundary, so <code className="text-info">/home</code> covers{' '}
        <code className="text-info">/home/settings</code> but not{' '}
        <code className="text-info">/homepage</code>. Checked on every endpoint and again on every
        redirect destination.
      </div>

      <Form onSubmit={addExclusion}>
        <InputGroup size="sm" className="mb-1">
          <InputGroup.Text className="bg-dark border-secondary text-white-50" style={{ fontSize: '0.65rem' }}>
            pattern
          </InputGroup.Text>
          <Form.Control
            value={newPattern}
            onChange={(e) => { setNewPattern(e.target.value); setAddError(''); }}
            placeholder="api.example.com/account/verify"
            spellCheck={false}
            disabled={adding}
            className="bg-dark text-white border-secondary"
            style={{ fontFamily: MONO, fontSize: '0.7rem' }}
            data-bs-theme="dark"
          />
        </InputGroup>
        <InputGroup size="sm" className="mb-1">
          <InputGroup.Text className="bg-dark border-secondary text-white-50" style={{ fontSize: '0.65rem' }}>
            reason
          </InputGroup.Text>
          <Form.Control
            ref={reasonRef}
            value={newReason}
            onChange={(e) => { setNewReason(e.target.value); setAddError(''); }}
            placeholder="sends a verification code to the account owner"
            disabled={adding}
            className="bg-dark text-white border-secondary"
            style={{ fontSize: '0.7rem' }}
            data-bs-theme="dark"
          />
          <Button type="submit" variant="outline-danger" disabled={adding}>
            {adding ? <Spinner animation="border" size="sm" /> : 'Exclude'}
          </Button>
        </InputGroup>
        {addError && (
          <div className="text-danger mb-1" style={{ fontSize: '0.68rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {addError}
          </div>
        )}
      </Form>

      {exclusionsError && (
        <div className="text-danger mb-1" style={{ fontSize: '0.68rem' }}>
          <i className="bi bi-exclamation-triangle me-1" />
          {exclusionsError}
        </div>
      )}

      <div style={{ maxHeight: '220px', overflowY: 'auto' }}>
        {exclusions.length === 0 ? (
          <div className="text-white-50 fst-italic" style={{ fontSize: '0.68rem' }}>
            No exclusions. Every in-scope endpoint the verb filter selects will be requested.
          </div>
        ) : exclusions.map((rule) => (
          <div key={rule.id} className="border-top border-secondary py-1">
            <div className="d-flex align-items-start">
              <code className="text-info flex-grow-1" style={{ fontSize: '0.7rem', wordBreak: 'break-all' }}>
                {rule.pattern}
              </code>
              {pendingDeleteId === rule.id ? (
                <span className="d-flex gap-1 flex-shrink-0">
                  <Button
                    size="sm"
                    variant="danger"
                    className="py-0 px-1"
                    style={{ fontSize: '0.62rem' }}
                    onClick={() => deleteExclusion(rule.id)}
                  >
                    Remove
                  </Button>
                  <Button
                    size="sm"
                    variant="outline-secondary"
                    className="py-0 px-1"
                    style={{ fontSize: '0.62rem' }}
                    onClick={() => setPendingDeleteId('')}
                  >
                    Keep
                  </Button>
                </span>
              ) : (
                <Button
                  size="sm"
                  variant="outline-secondary"
                  className="py-0 px-1 flex-shrink-0"
                  style={{ fontSize: '0.62rem' }}
                  disabled={isLive}
                  onClick={() => setPendingDeleteId(rule.id)}
                  title="Delete this rule. The endpoints it matched become reachable by the next run."
                >
                  <i className="bi bi-trash" />
                </Button>
              )}
            </div>
            <div className="text-white-50" style={{ fontSize: '0.66rem' }}>{rule.reason}</div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderCost = () => {
    if (planError) {
      return (
        <Alert variant="danger" className="py-2 mb-2" style={{ fontSize: '0.75rem' }}>
          <i className="bi bi-exclamation-triangle me-2" />
          {planError}
        </Alert>
      );
    }
    if (!plan) {
      return (
        <div className="text-white-50 fst-italic p-3" style={{ fontSize: '0.75rem' }}>
          {planning ? 'Working out what would be sent.' : 'No dry run yet.'}
        </div>
      );
    }
    const stale = !planIsForThisConfig;
    return (
      <div
        className="border rounded p-2 mb-2"
        style={{ borderColor: stale ? '#ffc107' : '#495057', background: '#212529' }}
      >
        {stale && (
          <div className="text-warning mb-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-info-circle me-1" />
            Preview is for the previous configuration. Run it again to refresh these numbers.
          </div>
        )}
        <div className="d-flex flex-wrap gap-4">
          <div>
            <div className="text-danger fw-bold" style={{ fontSize: '1.5rem', lineHeight: 1.1 }}>
              {Number(plan.request_count || 0).toLocaleString()}
            </div>
            <div className="text-white-50" style={{ fontSize: '0.65rem' }}>requests would be sent</div>
          </div>
          <div>
            <div className="text-white" style={{ fontSize: '1.1rem', lineHeight: 1.4 }}>
              {Number(plan.rps || 0)} /s
            </div>
            <div className="text-white-50" style={{ fontSize: '0.65rem' }}>per host, jittered</div>
          </div>
          <div>
            <div className="text-white" style={{ fontSize: '1.1rem', lineHeight: 1.4 }}>
              {formatSeconds(plan.estimated_seconds)}
            </div>
            <div className="text-white-50" style={{ fontSize: '0.65rem' }}>if nothing redirects</div>
          </div>
          <div>
            <div className="text-warning" style={{ fontSize: '1.1rem', lineHeight: 1.4 }}>
              {Number(plan.max_requests_worst_case || 0).toLocaleString()} · {formatSeconds(plan.estimated_seconds_worst_case)}
            </div>
            {/* Read off the PLAN's own config, never the live one. When the plan is stale those two
                disagree, and a worst case labelled with a hop count the plan was not computed with
                is a number that describes nothing. */}
            <div className="text-white-50" style={{ fontSize: '0.65rem' }}>
              worst case, if every request redirects the full{' '}
              {Number((plan.config && plan.config.max_redirects) || 0)} hops
            </div>
          </div>
          <div>
            <div className="text-info" style={{ fontSize: '1.1rem', lineHeight: 1.4 }}>
              {Number(plan.skipped_count || 0).toLocaleString()}
            </div>
            <div className="text-white-50" style={{ fontSize: '0.65rem' }}>refused, listed below</div>
          </div>
        </div>
        {/* THE BODY REPORT. "Sent your POSTs" and "sent your POSTs empty" are different runs and
            only one of them tested anything, so the counts are shown rather than left in the JSON.
            Hidden entirely when the run sends no body-taking verb, because a line that is always
            there is a line nobody reads. */}
        {Number(plan.body_taking_count || 0) > 0 && (
          <div className="text-white-50 mt-2" style={{ fontSize: '0.68rem' }}>
            <span className="text-white">{Number(plan.bodies_attached || 0).toLocaleString()}</span>
            {' of '}
            <span className="text-white">{Number(plan.body_taking_count || 0).toLocaleString()}</span>
            {' body-taking request(s) carry a recorded body'}
            {Number(plan.bodies_empty || 0) > 0 && (
              <span className="text-warning">
                {`; ${Number(plan.bodies_empty).toLocaleString()} go out empty`}
              </span>
            )}
            {plan.bodies_enabled === false && (
              <span className="text-warning">{' (bodies are switched off for this run)'}</span>
            )}
          </div>
        )}
        {plan.warning && (
          <div className="text-warning mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {plan.warning}
          </div>
        )}
        <div className="text-white-50 mt-2" style={{ fontSize: '0.65rem' }}>
          Scope boundary: <span className="text-info">{plan.scope_boundary || 'not reported'}</span>
          {Array.isArray(plan.denied_hosts) && plan.denied_hosts.length > 0 && (
            <span className="ms-2">
              Hosts marked out of scope and never requested:{' '}
              <span className="text-warning">{plan.denied_hosts.join(', ')}</span>
            </span>
          )}
        </div>
        {Array.isArray(plan.exclusion_patterns) && plan.exclusion_patterns.length > 0 && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.65rem' }}>
            Rules in force: {plan.exclusion_patterns.map((p) => (
              <code key={p} className="text-info me-2">{p}</code>
            ))}
          </div>
        )}
      </div>
    );
  };

  const renderTargets = () => {
    if (!plan) return null;
    const rows = Array.isArray(plan.targets) ? plan.targets : [];
    const shown = showAllTargets ? rows : rows.slice(0, RENDER_CAP);
    return (
      <div className="border border-secondary rounded mb-2">
        <div className="px-2 py-1 border-bottom border-secondary d-flex align-items-center">
          <span className="text-white" style={{ fontSize: '0.72rem' }}>
            WOULD BE REQUESTED
          </span>
          <span className="text-white-50 ms-auto" style={{ fontSize: '0.66rem' }}>
            {rows.length.toLocaleString()}
          </span>
        </div>
        {rows.length === 0 ? (
          <div className="text-white-50 fst-italic p-2" style={{ fontSize: '0.72rem' }}>
            Nothing would be sent with this configuration.
          </div>
        ) : (
          <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
            <Table size="sm" variant="dark" className="mb-0" style={{ fontSize: '0.68rem' }}>
              <tbody>
                {shown.map((row, idx) => (
                  <tr key={`${row.method}-${row.url}-${idx}`}>
                    <td style={{ width: '58px', fontFamily: MONO }} className="text-warning">
                      {row.method}
                    </td>
                    <td style={{ fontFamily: MONO, wordBreak: 'break-all' }} className="text-white-50">
                      {row.url}
                    </td>
                    <td style={{ width: '92px' }} className="text-white-50">{row.source}</td>
                    <td style={{ width: '78px' }}>
                      <Button
                        size="sm"
                        variant="outline-danger"
                        className="py-0 px-1"
                        style={{ fontSize: '0.6rem' }}
                        onClick={() => excludeTarget(row)}
                        title="Prefill an exclusion for this endpoint. You still have to say why."
                      >
                        Exclude
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            {!showAllTargets && rows.length > RENDER_CAP && (
              <div className="text-center py-2 border-top border-secondary">
                <span className="text-warning" style={{ fontSize: '0.7rem' }}>
                  Showing the first {RENDER_CAP} of {rows.length.toLocaleString()}. This is a display
                  cap; all {rows.length.toLocaleString()} would be sent.
                </span>
                <Button
                  size="sm"
                  variant="outline-warning"
                  className="ms-2 py-0 px-2"
                  style={{ fontSize: '0.68rem' }}
                  onClick={() => setShowAllTargets(true)}
                >
                  Show all
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  const renderSkipped = () => {
    if (!plan) return null;
    const total = Number(plan.skipped_count || 0);
    return (
      <div className="border border-info rounded">
        <div className="px-2 py-1 border-bottom border-secondary d-flex align-items-center">
          <span className="text-info" style={{ fontSize: '0.72rem' }}>WOULD NOT BE REQUESTED</span>
          <span className="text-white-50 ms-auto" style={{ fontSize: '0.66rem' }}>
            {total.toLocaleString()}
          </span>
        </div>
        {skippedGroups.length === 0 ? (
          <div className="text-white-50 fst-italic p-2" style={{ fontSize: '0.72rem' }}>
            Nothing was refused. Every candidate endpoint is in the list above.
          </div>
        ) : (
          <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
            {skippedGroups.map((group) => {
              const shown = showAllSkipped ? group.rows : group.rows.slice(0, 40);
              return (
                <div key={group.code} className="border-bottom border-secondary p-2">
                  <div className={group.variant} style={{ fontSize: '0.7rem' }}>
                    <strong>{group.title}</strong>
                    <span className="text-white-50 ms-2">{group.rows.length.toLocaleString()}</span>
                  </div>
                  <div className="text-white-50 mb-1" style={{ fontSize: '0.64rem' }}>{group.blurb}</div>
                  {shown.map((row, idx) => (
                    <div key={`${row.url}-${idx}`} style={{ fontSize: '0.66rem' }}>
                      <code className="text-white-50" style={{ wordBreak: 'break-all' }}>
                        {row.method} {row.url}
                      </code>
                      {row.pattern && (
                        <span className="text-info ms-1">
                          matched <code className="text-info">{row.pattern}</code>
                        </span>
                      )}
                      {row.detail && <span className="text-white-50 ms-1">— {row.detail}</span>}
                    </div>
                  ))}
                  {!showAllSkipped && group.rows.length > 40 && (
                    <Button
                      size="sm"
                      variant="link"
                      className="p-0 text-info text-decoration-underline"
                      style={{ fontSize: '0.66rem' }}
                      onClick={() => setShowAllSkipped(true)}
                    >
                      show all {group.rows.length.toLocaleString()}
                    </Button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  const renderProgress = () => {
    if (!status || runStatus === 'idle') return null;
    const planned = Number(status.planned) || 0;
    const sent = Number(status.sent) || 0;
    // planned counts ENDPOINTS; sent counts REQUESTS, and a followed redirect is another request.
    // So sent legitimately runs past planned, and "12 of 2 sent" under a pinned bar reads as a
    // broken counter rather than as redirects being followed. Said instead of hidden.
    const overshot = sent > planned && planned > 0;
    const pct = planned > 0 ? Math.min(100, Math.round((sent / planned) * 100)) : 0;
    const terminal = TERMINAL_STATUSES.includes(runStatus);
    const variant = runStatus === 'aborted' || runStatus === 'error'
      ? 'danger'
      : (runStatus === 'cancelled' ? 'secondary' : (terminal ? 'success' : 'danger'));
    return (
      <div className="border border-secondary rounded p-2 mb-2" style={{ background: '#212529' }}>
        <div className="d-flex align-items-center mb-1">
          <span className={`badge bg-${variant} me-2`} style={{ fontSize: '0.65rem' }}>
            {runStatus}
          </span>
          <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
            {sent.toLocaleString()} request{sent === 1 ? '' : 's'} sent
            {' '}of {planned.toLocaleString()} endpoint{planned === 1 ? '' : 's'} planned
            {Number(status.errors) > 0 && (
              <span className="text-warning ms-2">{Number(status.errors).toLocaleString()} errors</span>
            )}
            {Number(status.redirects) > 0 && (
              <span className="text-info ms-2">{Number(status.redirects).toLocaleString()} redirects followed</span>
            )}
            {Number(status.excluded) > 0 && (
              <span className="ms-2">{Number(status.excluded).toLocaleString()} excluded</span>
            )}
          </span>
          {isLive && <Spinner animation="border" size="sm" variant="danger" className="ms-auto" />}
        </div>
        <ProgressBar now={pct} variant={variant} striped={overshot} style={{ height: '6px' }} />
        {overshot && (
          <div className="text-info mt-1" style={{ fontSize: '0.64rem' }}>
            More requests than endpoints, because every redirect hop this run followed is another
            request. That is the scanner working, not a miscount.
          </div>
        )}
        {status.started_at && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.64rem' }}>
            started {formatTimestamp(status.started_at)}
            {status.completed_at && ` · finished ${formatTimestamp(status.completed_at)}`}
          </div>
        )}
        {status.abort_reason && (
          <div className="text-danger mt-1" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-octagon me-1" />
            Aborted: {status.abort_reason}
          </div>
        )}
        {status.last_error && (
          <div className="text-warning mt-1" style={{ fontSize: '0.68rem' }}>
            Last error: {status.last_error}
          </div>
        )}
        {runStatus === 'cancelled' && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.66rem' }}>
            Cancelling is not a discard. Everything the run already reached was kept, so the flows it
            found are still there.
          </div>
        )}
      </div>
    );
  };

  const renderSummary = () => {
    if (!summary) return null;
    if (summary.unavailable) {
      return (
        <Alert variant="warning" className="py-2 mb-2" style={{ fontSize: '0.72rem' }}>
          {summary.unavailable}
        </Alert>
      );
    }
    return (
      <div className="border border-success rounded p-2 mb-2" style={{ background: '#1a2620' }}>
        <div className="text-success mb-1" style={{ fontSize: '0.75rem' }}>
          <i className="bi bi-check2-circle me-2" />
          What changed
        </div>
        {summary.noBefore ? (
          <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
            {Number(summary.total).toLocaleString()} flows now. The before-picture could not be taken
            when the run started, so there is nothing honest to compare it against.
          </div>
        ) : (
          <div className="text-white" style={{ fontSize: '0.72rem' }}>
            <div>
              <strong>{Number(summary.total).toLocaleString()}</strong> flows now, up from{' '}
              <strong>{Number(summary.before).toLocaleString()}</strong>.
            </div>
            <div>
              <strong className="text-info">{Number(summary.newCount).toLocaleString()}</strong> new
              flow{summary.newCount === 1 ? '' : 's'} this run found.
            </div>
            {summary.sourcesReported ? (
              <div>
                <strong className="text-danger">{Number(summary.bothCount).toLocaleString()}</strong>{' '}
                previously-passive flow{summary.bothCount === 1 ? '' : 's'} now marked{' '}
                <span className="text-danger">Both</span>: your browser and this scanner agree they
                are real.
              </div>
            ) : (
              <div className="text-white-50" style={{ fontSize: '0.68rem' }}>
                This build&apos;s flow list does not report a detection source, so how many flows are
                now marked Both could not be worked out. Nothing is being guessed.
              </div>
            )}
            {summary.truncated && (
              <div className="text-warning" style={{ fontSize: '0.66rem' }}>
                The comparison covers the first 2,000 flows only.
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  const body = () => {
    if (!targetId) {
      return <div className="text-white-50 small p-3">No target selected.</div>;
    }
    return (
      <div className="d-flex flex-grow-1 p-2" style={{ minHeight: 0 }}>
        {/* Left: what the run is allowed to do. */}
        <div
          className="me-2"
          style={{ width: '38%', minWidth: '380px', minHeight: 0, overflowY: 'auto' }}
        >
          <div className="border border-secondary rounded p-2">
            <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
              CONFIGURATION
            </div>
            {renderMethods()}
            {renderRate()}
          </div>
          {renderExclusions()}
        </div>

        {/* Right: what that means, in endpoints. */}
        <div className="flex-grow-1" style={{ minWidth: 0, minHeight: 0, overflowY: 'auto' }}>
          {renderProgress()}
          {renderSummary()}
          {renderCost()}
          {renderTargets()}
          {renderSkipped()}
        </div>
      </div>
    );
  };

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-broadcast-pin me-2" />
          Detect Flows
          {activeTarget && activeTarget.scope_target && (
            <span className="text-white-50 ms-2" style={{ fontSize: '0.9rem' }}>{activeTarget.scope_target}</span>
          )}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="d-flex flex-column p-0" style={{ minHeight: 0, overflow: 'hidden' }}>
        {body()}
      </Modal.Body>

      <Modal.Footer className="d-flex align-items-center">
        <div className="text-white-50 me-auto" style={{ fontSize: '0.68rem', maxWidth: '55%' }}>
          {gateReason || (
            planIsForThisConfig
              ? `Preview matches this configuration: ${requestCount.toLocaleString()} requests.`
              : 'Dry run for a preview, or Run detection to send.'
          )}
          {startError && (
            <div className="text-danger mt-1" style={{ fontSize: '0.7rem' }}>
              <i className="bi bi-exclamation-triangle me-1" />
              {startError}
            </div>
          )}
          {cancelError && (
            <div className="text-danger mt-1" style={{ fontSize: '0.7rem' }}>
              <i className="bi bi-exclamation-triangle me-1" />
              {cancelError}
            </div>
          )}
        </div>

        <Button
          variant="outline-info"
          disabled={!targetId || planning || isLive}
          onClick={() => runDryRun()}
          title="Preview what a run would request. Sends nothing."
        >
          {planning
            ? <><Spinner animation="border" size="sm" className="me-2" />Dry run</>
            : <><i className="bi bi-eye me-2" />Dry run</>}
        </Button>

        {isLive ? (
          <Button variant="warning" onClick={cancelRun}>
            <i className="bi bi-stop-circle me-2" />
            Cancel run
          </Button>
        ) : (
          <Button
            variant="danger"
            disabled={!canRun}
            onClick={startRun}
            title={gateReason || 'Send the selected verbs to the in-scope endpoints on this target.'}
          >
            {starting
              ? <><Spinner animation="border" size="sm" className="me-2" />Starting</>
              : (
                <>
                  <i className="bi bi-broadcast-pin me-2" />
                  Run detection
                  {/* The count comes off the plan, and only when the plan is for what is in the form
                      now. Labelling the button with a stale number would promise a size the run is
                      not going to be. */}
                  {planIsForThisConfig && ` — ${requestCount.toLocaleString()} requests`}
                </>
              )}
          </Button>
        )}

        <Button variant="secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
};

export default DetectFlowsModal;
