import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Modal, Button, Form, InputGroup, Spinner, Alert } from 'react-bootstrap';

// Configure: what active detection is allowed to touch on THIS target, and what every request it
// sends has to carry.
//
// This modal sends nothing. It is the only one of the five buttons on the Request Flow Replay card
// that cannot produce traffic, which is why it sits on the far left: it is where you decide, before
// Detect Flows is where you act. Opening it, editing it and saving it are all writes to this
// framework's own database.
//
// THREE SECTIONS, THREE DIFFERENT KINDS OF STATEMENT.
//
//   ENDPOINTS is scoping. Which of the endpoints already discovered on this target may a detection
//   run request. Everything is ticked by default, because the corpus is the corpus, and unticking is
//   how you say "not this one, not today".
//
//   ENGAGEMENT RULES are the programme's requirements. DailyPay wants
//   `X-HackerOne-DailyPay-Research: rs0n2` on every request or their SOC reads the traffic as an
//   attack. Assurant wants `<H1-rs0n2>` appended to a real browser User-Agent and caps you at 45
//   requests per minute. Swan and Transmit ask for neither. Before this screen there was ONE global
//   custom header and ONE global rate limit in Settings, shared by every target, so switching
//   programmes meant remembering to go and change them, and forgetting meant sending unlabelled
//   traffic to a programme whose brief says the label is mandatory. Every field here is per target,
//   and falls back to the global setting when this target does not override it. Which of those two
//   things is happening is printed next to the field, on every field, always.
//
//   ALWAYS TRUE is neither. Three rules the server enforces whatever is configured here: scope,
//   the rate limit, and the execution cap on conditional flows. Listed so the operator knows where
//   the fixed edges are, not as a caution.
//
// THE ONE DISTINCTION THIS FILE EXISTS TO PROTECT: an EXCLUSION is not a deselection.
//
//   A deselection is scoping. You did not want that endpoint in this pass. Tick it back on whenever
//   you like; it is a checkbox and it behaves like one.
//
//   An exclusion is a safety statement with a written reason, made in Detect Flows, enforced by the
//   server on every endpoint AND on every redirect destination. `/account/verify` is on that list
//   because requesting it texts a one-time code to a real customer.
//
//   If those two shared a checkbox, somebody skimming this screen could tick that box back on and
//   send a text message to a stranger. So excluded rows have NO CHECKBOX AT ALL. There is nothing in
//   that position to click: a padlock, the rule that matched, and the reason somebody wrote for it.
//   Removing it is done where it was written, deliberately, with a confirm step.

const MONO = 'Menlo, Consolas, "Courier New", monospace';

// Ceilings copied from the server (server/utils/flowDetectionActive.go) so no input here can ask for
// a value that gets silently clamped somewhere else. A control that reports one number while the run
// uses another is the failure this framework has already been bitten by.
const MAX_RPS = 10;
const HARD_MAX_REQUESTS = 5000;
const HARD_MAX_REDIRECTS = 10;
const MAX_TIMEOUT_S = 60;

// What the framework does when neither this target nor global settings say otherwise. These mirror
// DefaultFlowDetectionConfig(); they are the third rung of the provenance ladder and are labelled as
// such on screen rather than presented as somebody's choice.
const ENGAGEMENT_DEFAULTS = {
  custom_header_name: '',
  custom_header_value: '',
  user_agent: '',
  user_agent_mode: 'replace',
  rps: 1,
  timeout_s: 15,
  max_requests: 250,
  max_redirects: 5,
  send_cookies: false,
  notes: '',
};

// The User-Agent the framework sends when nobody has set one. Mirrors engagementDefaultUserAgent in
// server/utils/engagementConfig.go, which mirrors NewScanClient's own fallback. Only used as the
// BASE an appended tag is shown against, so that "append" can be previewed honestly on a target
// whose global Settings User-Agent is empty.
const DEFAULT_FRAMEWORK_USER_AGENT = 'ars0n-framework/2.0 (+authorized-testing)';

const FIELD_LABELS = {
  custom_header_name: 'header name',
  custom_header_value: 'header value',
  user_agent: 'User-Agent',
  user_agent_mode: 'User-Agent mode',
  rps: 'rate limit',
  timeout_s: 'timeout',
  max_requests: 'request budget',
  max_redirects: 'redirect depth',
  send_cookies: 'send cookies',
  notes: 'programme notes',
};

// The configuration the fallback preview is asked for when this build has no endpoint-selection API.
// It is the detection default, and the dry-run route sends nothing whatever is in this body.
const PREVIEW_CONFIG = {
  methods: ['GET'],
  rps: 1,
  max_requests: HARD_MAX_REQUESTS,
  follow_redirects: true,
  max_redirects: 5,
  timeout_s: 15,
  include_query: false,
};

// A header field-name, as RFC 7230 defines a token. Checked here because a name with a space or a
// colon in it does not become a header, it becomes a malformed request that some servers answer with
// a 400 and others quietly drop, and either way the programme never sees the label it asked for.
const HEADER_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

// How many endpoint rows are drawn before the list asks whether you really want the rest. A display
// cap only, and said as one: the selection covers every row whether or not it is on screen.
const RENDER_CAP = 400;

// The two locked states. Neither is a checkbox. They are separated because "somebody wrote a rule
// about this endpoint" and "this host is outside what you are allowed to touch" are different facts
// and call for different actions.
const LOCK_EXCLUSION = 'exclusion';
const LOCK_SCOPE = 'scope';

// THE FIELD NAMES THE SERVER ACTUALLY USES, for the per-target engagement config.
//
// The left-hand names are this screen's; the right-hand names are the API's. They differ, and the
// first cut of this file used its own names on the wire, so every engagement field it sent was
// ignored. One map, read in both directions, rather than the names being spelled out at each call
// site where only some of them would get corrected.
const ENGAGEMENT_API_FIELD = {
  custom_header_name: 'custom_header_name',
  custom_header_value: 'custom_header_value',
  user_agent: 'custom_user_agent',
  user_agent_mode: 'user_agent_mode',
  rps: 'max_rps',
  timeout_s: 'request_timeout_s',
  max_requests: 'max_requests_per_run',
  max_redirects: 'max_redirects',
  send_cookies: 'send_cookies',
  notes: 'programme_notes',
};

const ENGAGEMENT_LOCAL_FIELD = Object.fromEntries(
  Object.entries(ENGAGEMENT_API_FIELD).map(([local, api]) => [api, local])
);

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

function statusVariant(status) {
  const code = Number(status);
  if (!code) return 'secondary';
  if (code < 300) return 'success';
  if (code < 400) return 'info';
  if (code < 500) return 'warning';
  return 'danger';
}

// Splits a URL into the host and path the grouping needs. Falls back to the raw string rather than
// dropping the row: an endpoint this parser cannot read is still an endpoint somebody recorded, and
// hiding it would understate what a run would reach.
function splitUrl(url) {
  const raw = String(url || '');
  try {
    const parsed = new URL(raw);
    return { host: parsed.host, path: `${parsed.pathname}${parsed.search}` || '/' };
  } catch (err) {
    return { host: '', path: raw };
  }
}

// THE ROW KEY IS THE SERVER'S endpoint_key AND NOTHING ELSE.
//
// It is the string the selection API stores and matches on - `GET|api.example.com|/account/verify` -
// and it is deliberately COARSER than the URL: the server strips query strings before sending, so
// fifty rows of /search?q=<fifty things> are one request and must be one key.
//
// Inventing a local key from the method and URL, which an earlier cut of this file did, produces a
// string the server has never heard of. Deselecting then writes a row that matches no endpoint, the
// save returns 200, and the endpoint is sent anyway. So a row WITHOUT a server key is not given a
// made-up one: it gets a local-only key marked as such, and saveability is decided on whether every
// row carries a real one.
const LOCAL_KEY_PREFIX = 'local:';

function rowKey(raw, url, method) {
  if (raw && raw.endpoint_key) return String(raw.endpoint_key);
  return `${LOCAL_KEY_PREFIX}${String(method || 'GET').toUpperCase()} ${String(url || '')}`;
}

// The reasons the server gives for not sending a row, and which of them is a LOCK rather than the
// operator's own toggle.
//
// `deselected` is deliberately absent: that is the checkbox, not a padlock. So are `method`,
// `unusable_url` and `over_budget`, which a dry run can also report - those are artefacts of the
// configuration the preview was run with, and rendering them here would label an endpoint as blocked
// when all that happened is the preview asked for GET.
const LOCK_BY_REASON = {
  exclusion: { kind: LOCK_EXCLUSION, label: 'EXCLUDED' },
  host_excluded: { kind: LOCK_SCOPE, label: 'OUT OF SCOPE' },
  out_of_scope: { kind: LOCK_SCOPE, label: 'OUT OF SCOPE' },
};

// One endpoint row, in the shape this file draws, out of either of the two sources it can read.
//
// The field names below are the ones GET /flow-config/{target}/endpoints actually emits. They were
// wrong in the first cut - it read `excluded`, `in_scope`, `last_status`, `source` and `key`, none of
// which exist - and the effect was not a blank column but a silent loss of the whole locking model:
// every excluded endpoint rendered as an ordinary ticked checkbox.
function normalizeRow(raw) {
  const url = String((raw && raw.url) || '');
  const method = String((raw && raw.method) || 'GET').toUpperCase();
  const parsed = splitUrl(url);
  const host = String((raw && raw.host) || parsed.host || 'unknown host');
  const path = String((raw && raw.path) || parsed.path || '/');

  const reason = String((raw && raw.not_sent_reason) || '');
  const found = LOCK_BY_REASON[reason];
  const lock = found
    ? {
      kind: found.kind,
      label: found.label,
      pattern: String((raw && raw.pattern) || ''),
      reason: String((raw && raw.detail) || ''),
    }
    : null;

  // EVERY status the crawl recorded, not "the last one". The server stores status_codes as a SET and
  // says so: the array carries no order, so the final element is not the most recent observation and
  // labelling one "last status" would be a number that looks like a fact and is not.
  const statuses = Array.isArray(raw && raw.observed_status_codes)
    ? raw.observed_status_codes.map(Number).filter((n) => Number.isFinite(n) && n > 0)
    : [];

  const sources = Array.isArray(raw && raw.sources)
    ? raw.sources.map(String).filter(Boolean)
    : (raw && raw.source ? [String(raw.source)] : []);

  return {
    key: rowKey(raw, url, method),
    hasServerKey: Boolean(raw && raw.endpoint_key),
    url,
    method,
    host,
    path,
    sources,
    statuses,
    lock,
    // Absent means selected. The default is every endpoint ticked, so only a stored "no" turns one
    // off, and an endpoint discovered after the last save arrives ticked like all the others.
    selected: !(raw && raw.selected === false),
  };
}

// The same row, out of a dry-run plan. The plan is the fallback source: it is computed by the server
// under the real exclusion rules and the real scope, so the locked rows in it are the server's
// judgement and not a pattern matcher reimplemented in the browser.
function normalizeFallbackRows(plan) {
  const rows = [];
  const targets = (plan && Array.isArray(plan.targets)) ? plan.targets : [];
  targets.forEach((t) => {
    rows.push(normalizeRow({ ...t, selected: true }));
  });
  let setAside = 0;
  const skipped = (plan && Array.isArray(plan.skipped)) ? plan.skipped : [];
  skipped.forEach((s) => {
    if (!LOCK_BY_REASON[s && s.reason]) {
      setAside += 1;
      return;
    }
    // A dry-run skip names the reason in `reason`; the endpoints API names it in `not_sent_reason`.
    // Translated here rather than teaching normalizeRow two spellings, so there is exactly one place
    // that knows what a lock is.
    rows.push(normalizeRow({ ...s, not_sent_reason: s.reason }));
  });
  return { rows, setAside };
}

/* ------------------------------------------------------------------ provenance */

const PROVENANCE_STYLE = {
  target: { cls: 'text-danger border-danger', icon: 'bi-pin-angle-fill', text: 'set for this target' },
  global: { cls: 'text-info border-info', icon: 'bi-globe2', text: 'inherited from global settings' },
  default: { cls: 'text-white-50 border-secondary', icon: 'bi-dash-circle', text: 'framework default' },
};

function displayValue(field, value) {
  if (value === undefined || value === null || value === '') return 'not set';
  if (field === 'send_cookies') return value ? 'on' : 'off';
  if (field === 'rps') return `${value} req/s`;
  if (field === 'timeout_s') return `${value} s`;
  if (field === 'user_agent_mode') return value === 'append' ? 'append' : 'replace';
  return String(value);
}

/* ---------------------------------------------------------------------- pieces */

const Field = ({ label, provenance, hint, children }) => (
  <div className="mb-3">
    <div className="d-flex align-items-center flex-wrap mb-1" style={{ gap: '0.4rem' }}>
      <span className="text-white-50" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
        {label}
      </span>
      {provenance}
    </div>
    {children}
    {hint && <div className="text-white-50 mt-1" style={{ fontSize: '0.64rem' }}>{hint}</div>}
  </div>
);

const Rail = ({ icon, headline, children }) => (
  <div className="d-flex border-bottom border-secondary py-2">
    <div className="text-success flex-shrink-0 text-center" style={{ width: '34px' }}>
      <i className={`bi ${icon}`} style={{ fontSize: '1.05rem' }} />
    </div>
    <div style={{ minWidth: 0 }}>
      <div className="text-white" style={{ fontSize: '0.8rem' }}>{headline}</div>
      <div className="text-white-50 mt-1" style={{ fontSize: '0.7rem', lineHeight: 1.5 }}>{children}</div>
    </div>
  </div>
);

export const FlowConfigureModal = ({ show, handleClose, activeTarget }) => {
  const targetId = activeTarget && activeTarget.id;

  const [section, setSection] = useState('endpoints');

  // Endpoints.
  const [rows, setRows] = useState([]);
  const [deselected, setDeselected] = useState(() => new Set());
  const [savedDeselected, setSavedDeselected] = useState('[]');
  const [endpointsLoading, setEndpointsLoading] = useState(false);
  const [endpointsError, setEndpointsError] = useState('');
  const [endpointsSource, setEndpointsSource] = useState('');
  const [selectionSavable, setSelectionSavable] = useState(true);
  const [selectionNote, setSelectionNote] = useState('');
  const [selectionModel, setSelectionModel] = useState('');
  const [fallbackSetAside, setFallbackSetAside] = useState(0);
  const [filterText, setFilterText] = useState('');
  const [showAllRows, setShowAllRows] = useState(false);
  const endpointsSeq = useRef(0);

  // Engagement.
  const [overrides, setOverrides] = useState({});
  const [savedOverrides, setSavedOverrides] = useState('{}');
  const [inherited, setInherited] = useState({});
  const [baseUserAgent, setBaseUserAgent] = useState('');
  const [engagementLoading, setEngagementLoading] = useState(false);
  const [engagementError, setEngagementError] = useState('');
  const [engagementAvailable, setEngagementAvailable] = useState(true);
  const [engagementNote, setEngagementNote] = useState('');

  // Save.
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [saveNotice, setSaveNotice] = useState('');
  const [confirmDiscard, setConfirmDiscard] = useState(false);

  /* ----------------------------------------------------------------- loaders */

  const loadEndpoints = useCallback(async () => {
    if (!targetId) return;
    const seq = endpointsSeq.current + 1;
    endpointsSeq.current = seq;
    setEndpointsLoading(true);
    setEndpointsError('');
    try {
      const primary = await requestJSON(`/api/flow-config/${targetId}/endpoints`);
      if (seq !== endpointsSeq.current) return;

      if (primary.ok && primary.data && Array.isArray(primary.data.endpoints)) {
        const normalized = primary.data.endpoints.map(normalizeRow);
        // The per-row `selected` flag IS the deselection list: the server derives it from
        // flow_endpoint_deselections, which is the table it enforces. A row that is not sendable for
        // some other reason still carries an honest `selected`, so the lock filter here is only about
        // which rows this screen lets you toggle.
        const off = new Set(normalized.filter((r) => !r.selected && !r.lock).map((r) => r.key));
        setRows(normalized);
        setDeselected(off);
        setSavedDeselected(JSON.stringify([...off].sort()));
        setEndpointsSource('api');
        // Savable only if every row carries the server's own endpoint_key. Without one there is
        // nothing to send that the server would recognise, and a save that cannot land must not be
        // offered as though it could.
        setSelectionSavable(normalized.every((r) => r.hasServerKey));
        setSelectionNote('');
        // The server states its own selection model on every response. Shown as calm descriptive
        // copy, not as the warning Alert below, because it is how the screen works rather than a
        // problem with it.
        setSelectionModel(String(primary.data.selection_model || ''));
        setFallbackSetAside(0);
        return;
      }

      // No selection API on this build. The dry run is a real, server-computed answer to "what would
      // a run consider", it sends nothing, and it carries the server's own exclusion decisions, so it
      // is a better fallback than an empty screen. What it cannot do is remember a selection, and
      // that is said rather than discovered on the first save.
      const preview = await requestJSON(`/api/flow-detection/${targetId}/dry-run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(PREVIEW_CONFIG),
      });
      if (seq !== endpointsSeq.current) return;

      if (!preview.ok || !preview.data) {
        setRows([]);
        setEndpointsSource('');
        setEndpointsError(
          primary.status === 404
            ? `This build has no endpoint selection API, and the detection preview it fell back to also failed: ${errorMessage(preview.data, preview.body, preview.status)}`
            : errorMessage(primary.data, primary.body, primary.status)
        );
        return;
      }

      const { rows: fallbackRows, setAside } = normalizeFallbackRows(preview.data);
      setRows(fallbackRows);
      setDeselected(new Set());
      setSavedDeselected('[]');
      setEndpointsSource('preview');
      setSelectionSavable(false);
      setSelectionModel('');
      setSelectionNote(
        'This server build does not expose the endpoint selection API '
        + '(/flow-config/{target}/endpoints), so the list below is read out of a detection preview '
        + 'and a selection made here cannot be saved. Everything shown is still real: the preview is '
        + 'computed by the server under your exclusion rules and this target\'s scope, and it sends '
        + 'no requests. Recorded response statuses are not part of a preview, so that column is empty.'
      );
      setFallbackSetAside(setAside);
    } catch (err) {
      if (seq === endpointsSeq.current) {
        setRows([]);
        setEndpointsSource('');
        setEndpointsError(`Could not reach the framework: ${err.message}`);
      }
    } finally {
      if (seq === endpointsSeq.current) setEndpointsLoading(false);
    }
  }, [targetId]);

  const loadEngagement = useCallback(async () => {
    if (!targetId) return;
    setEngagementLoading(true);
    setEngagementError('');
    try {
      const { ok, status, data, body } = await requestJSON(`/api/flow-config/${targetId}/engagement`);
      if (ok && data) {
        // `overrides` is the raw row, in API field names, and it is NULL for every field this target
        // does not override. Only the non-null ones become entries here, because presence in this
        // object is what this screen means by "set for this target".
        const rawOverrides = (data.overrides && typeof data.overrides === 'object') ? data.overrides : {};
        const nextOverrides = {};
        Object.entries(rawOverrides).forEach(([apiField, value]) => {
          const local = ENGAGEMENT_LOCAL_FIELD[apiField];
          if (!local || value === null || value === undefined) return;
          nextOverrides[local] = value;
        });

        // Provenance comes from the server's own per-field source map, which is the only thing that
        // can tell "I set this here" from "this leaked in from global Settings". Reconstructing it in
        // the browser would be a second opinion about the same question.
        const effective = (data.effective && typeof data.effective === 'object') ? data.effective : {};
        const source = (effective.source && typeof effective.source === 'object') ? effective.source : {};
        const next = {};
        Object.keys(ENGAGEMENT_DEFAULTS).forEach((field) => {
          const apiField = ENGAGEMENT_API_FIELD[field];
          const value = effective[apiField];
          next[field] = {
            value: (value === undefined || value === null) ? ENGAGEMENT_DEFAULTS[field] : value,
            source: source[apiField] === 'global' ? 'global' : 'default',
          };
        });

        // send_cookies is NOT NULLABLE in the schema, so it is present on every row that exists at
        // all, including rows saved for some unrelated reason. Only `true` counts as an override,
        // matching how the server reports its provenance: false is the default and nobody arrives at
        // it deliberately, so a target saved for a rate cap must not come back claiming somebody
        // turned cookies off here on purpose.
        if (!rawOverrides.send_cookies) delete nextOverrides.send_cookies;

        setOverrides(nextOverrides);
        setSavedOverrides(JSON.stringify(nextOverrides, Object.keys(ENGAGEMENT_DEFAULTS).sort()));
        setInherited(next);
        // The base an appended tag is glued onto: the global browser User-Agent when Settings has
        // one, otherwise the framework's own. Taken from the global block rather than from
        // effective_user_agent, which already HAS the tag on the end.
        setBaseUserAgent(String(
          (data.global && data.global.custom_user_agent) || DEFAULT_FRAMEWORK_USER_AGENT
        ));
        setEngagementAvailable(true);
        setEngagementNote('');
        return;
      }
      // Same shape of message the version editor uses for a missing route, and for the same reason:
      // "Request failed (404)" over a form reads as "your input is broken" rather than "this server
      // cannot store this".
      const missing = status === 404 && !(data && data.error);
      setEngagementAvailable(false);
      setOverrides({});
      setSavedOverrides('{}');
      const fallbackInherited = {};
      Object.keys(ENGAGEMENT_DEFAULTS).forEach((field) => {
        fallbackInherited[field] = { value: ENGAGEMENT_DEFAULTS[field], source: 'default' };
      });
      setInherited(fallbackInherited);
      setEngagementNote(
        missing
          ? 'This server build does not expose the per-target engagement API '
            + '(/flow-config/{target}/engagement), so nothing in this section can be saved. Until it '
            + 'does, the global custom header, User-Agent and rate limit in Settings are what every '
            + 'target gets, including this one. The values below are the framework defaults.'
          : `The engagement configuration could not be read: ${errorMessage(data, body, status)}`
      );
    } catch (err) {
      setEngagementAvailable(false);
      setEngagementError(`Could not reach the framework: ${err.message}`);
    } finally {
      setEngagementLoading(false);
    }
  }, [targetId]);

  useEffect(() => {
    if (!show || !targetId) return;
    setSection('endpoints');
    setFilterText('');
    setShowAllRows(false);
    setSaveError('');
    setSaveNotice('');
    setConfirmDiscard(false);
    setEngagementError('');
    loadEndpoints();
    loadEngagement();
  }, [show, targetId, loadEndpoints, loadEngagement]);

  /* -------------------------------------------------------------- selection */

  const selectableRows = useMemo(() => rows.filter((r) => !r.lock), [rows]);
  const lockedRows = useMemo(() => rows.filter((r) => r.lock), [rows]);
  const excludedCount = useMemo(
    () => lockedRows.filter((r) => r.lock.kind === LOCK_EXCLUSION).length,
    [lockedRows]
  );
  const selectedCount = useMemo(
    () => selectableRows.filter((r) => !deselected.has(r.key)).length,
    [selectableRows, deselected]
  );

  const filtered = useMemo(() => {
    const needle = filterText.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((r) => (
      `${r.method} ${r.host}${r.path} ${r.url} ${r.statuses.join(' ')} ${r.sources.join(' ')}`
        .toLowerCase()
        .includes(needle)
    ));
  }, [rows, filterText]);

  const groups = useMemo(() => {
    const byHost = new Map();
    filtered.forEach((r) => {
      if (!byHost.has(r.host)) byHost.set(r.host, []);
      byHost.get(r.host).push(r);
    });
    return [...byHost.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([host, list]) => ({
        host,
        rows: [...list].sort((a, b) => (
          a.path.localeCompare(b.path) || a.method.localeCompare(b.method)
        )),
      }));
  }, [filtered]);

  // The cap is applied across the whole list, not per host, so the number on screen is the number of
  // rows drawn and a host is never silently cut in half.
  const cappedGroups = useMemo(() => {
    if (showAllRows || filtered.length <= RENDER_CAP) return groups;
    const out = [];
    let budget = RENDER_CAP;
    for (let i = 0; i < groups.length && budget > 0; i += 1) {
      const take = groups[i].rows.slice(0, budget);
      budget -= take.length;
      out.push({ host: groups[i].host, rows: take });
    }
    return out;
  }, [groups, filtered.length, showAllRows]);

  const setRowSelected = (key, on) => {
    setDeselected((prev) => {
      const next = new Set(prev);
      if (on) next.delete(key); else next.add(key);
      return next;
    });
    setSaveNotice('');
  };

  // Bulk actions act on WHAT IS ON SCREEN, and their labels say so whenever a filter is narrowing
  // that. "Select all" that quietly reaches past the filter and undoes twenty deliberate decisions is
  // the kind of control people stop trusting after using it once.
  const setShownSelected = (on) => {
    const keys = filtered.filter((r) => !r.lock).map((r) => r.key);
    setDeselected((prev) => {
      const next = new Set(prev);
      keys.forEach((k) => { if (on) next.delete(k); else next.add(k); });
      return next;
    });
    setSaveNotice('');
  };

  const setHostSelected = (hostRows, on) => {
    const keys = hostRows.filter((r) => !r.lock).map((r) => r.key);
    setDeselected((prev) => {
      const next = new Set(prev);
      keys.forEach((k) => { if (on) next.delete(k); else next.add(k); });
      return next;
    });
    setSaveNotice('');
  };

  /* ------------------------------------------------------------- engagement */

  const valueOf = useCallback((field) => {
    if (Object.prototype.hasOwnProperty.call(overrides, field)) return overrides[field];
    const entry = inherited[field];
    return entry ? entry.value : ENGAGEMENT_DEFAULTS[field];
  }, [overrides, inherited]);

  const provenanceOf = useCallback((field) => {
    if (Object.prototype.hasOwnProperty.call(overrides, field)) return 'target';
    const entry = inherited[field];
    return (entry && entry.source === 'global') ? 'global' : 'default';
  }, [overrides, inherited]);

  // Setting a field makes it a target override, and it stays one even when the value equals what it
  // would have inherited. "I chose this for this programme" and "nobody chose, so it came from
  // Settings" are different statements, and the second one changes under you when somebody edits
  // Settings for a different target.
  const setField = (field, value) => {
    setOverrides((prev) => ({ ...prev, [field]: value }));
    setSaveNotice('');
    setSaveError('');
  };

  const clearField = (field) => {
    setOverrides((prev) => {
      const next = { ...prev };
      delete next[field];
      return next;
    });
    setSaveNotice('');
    setSaveError('');
  };

  const setNumberField = (field, raw, { min, max, integer }) => {
    const parsed = integer ? parseInt(raw, 10) : parseFloat(raw);
    if (!Number.isFinite(parsed)) return;
    setField(field, Math.min(max, Math.max(min, parsed)));
  };

  const headerName = String(valueOf('custom_header_name') || '').trim();
  const headerValue = String(valueOf('custom_header_value') || '');
  const uaMode = valueOf('user_agent_mode') === 'append' ? 'append' : 'replace';
  const uaText = String(valueOf('user_agent') || '');
  const sendCookies = Boolean(valueOf('send_cookies'));
  const rps = Number(valueOf('rps')) || 0;

  const headerProblem = useMemo(() => {
    if (!headerName && !headerValue.trim()) return '';
    if (!headerName) {
      return 'There is a header value with no header name. Nothing will be sent: a value on its own '
        + 'is not a header.';
    }
    if (!HEADER_TOKEN.test(headerName)) {
      return `"${headerName}" is not a legal header name. Use letters, digits and - _ . only, with no `
        + 'spaces and no colon: the colon is added for you.';
    }
    if (!headerValue.trim()) {
      return 'There is a header name with no value. Most programmes are matching on the value (your '
        + 'researcher handle), so an empty one is the same as not sending it.';
    }
    return '';
  }, [headerName, headerValue]);

  // EVERYTHING THE SERVER WILL REFUSE IS REFUSED HERE FIRST, so a save that cannot succeed is never
  // offered. A half-header is not a warning on this screen, it is a blocked save: the server returns
  // a 400 for both halves of it, and a button that reliably produces an error is a button that
  // teaches people to ignore errors.
  const headerBlocksSave = Boolean(headerProblem);

  const effectiveUA = useMemo(() => {
    if (uaMode === 'append') {
      const tag = uaText.trim();
      if (!tag) return { text: baseUserAgent, unknownBase: !baseUserAgent, appended: '' };
      return { text: baseUserAgent, unknownBase: !baseUserAgent, appended: tag };
    }
    return { text: uaText.trim(), unknownBase: false, appended: '' };
  }, [uaMode, uaText, baseUserAgent]);

  /* ------------------------------------------------------------------ dirty */

  const currentDeselectedKey = useMemo(
    () => JSON.stringify([...deselected].sort()),
    [deselected]
  );
  const currentOverridesKey = useMemo(
    () => JSON.stringify(overrides, Object.keys(ENGAGEMENT_DEFAULTS).sort()),
    [overrides]
  );

  const selectionDirty = selectionSavable && currentDeselectedKey !== savedDeselected;
  const engagementDirty = engagementAvailable && currentOverridesKey !== savedOverrides;
  const dirty = selectionDirty || engagementDirty;

  const saveBlockedReason = useMemo(() => {
    if (!targetId) return 'No target selected.';
    if (!dirty) return 'Nothing has changed.';
    if (headerBlocksSave) return `Fix the custom header first. ${headerProblem}`;
    return '';
  }, [targetId, dirty, headerBlocksSave, headerProblem]);

  const save = async () => {
    if (saveBlockedReason || saving) return;
    setSaving(true);
    setSaveError('');
    setSaveNotice('');
    const done = [];
    const failed = [];
    try {
      if (selectionDirty) {
        // THE SELECTION API TAKES A DELTA, NOT A LIST.
        //
        // flow_endpoint_deselections stores what was taken OUT, so a save is two statements: insert
        // the ones newly unticked, delete the ones newly re-ticked. Sending only the current
        // deselected set would never remove a row, and an endpoint re-ticked here would go on being
        // skipped by every run while the screen showed it ticked.
        const before = new Set(JSON.parse(savedDeselected));
        const now = [...deselected];
        // A locally-invented key matches no endpoint on the server, so sending one would write a
        // deselection row that never suppresses anything while the save returned 200. Belt and
        // braces: selectionSavable is already false wherever these can occur.
        const real = (k) => !k.startsWith(LOCAL_KEY_PREFIX);
        const toDeselect = now.filter((k) => real(k) && !before.has(k));
        const toReselect = [...before].filter((k) => real(k) && !deselected.has(k));

        let selectionFailed = '';
        for (const [keys, selected] of [[toDeselect, false], [toReselect, true]]) {
          if (!keys.length || selectionFailed) continue;
          // eslint-disable-next-line no-await-in-loop
          const { ok, status, data, body } = await requestJSON(
            `/api/flow-config/${targetId}/endpoints/selection`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ endpoint_keys: keys, selected }),
            }
          );
          if (!ok) selectionFailed = errorMessage(data, body, status);
        }

        if (selectionFailed) {
          failed.push(`endpoint selection: ${selectionFailed}`);
        } else {
          setSavedDeselected(JSON.stringify(now.sort()));
          done.push(`${selectedCount.toLocaleString()} of ${selectableRows.length.toLocaleString()} endpoints selected`);
        }
      }

      if (engagementDirty) {
        // CLEARING IS A DELETE, NOT AN OMISSION.
        //
        // The PUT is deliberately COALESCE-based on the server: a field the body does not mention is
        // left exactly as it was, because a partial update that wipes what it did not mention is a
        // bug this codebase has already shipped once. That makes omission the wrong way to clear an
        // override, so a field removed on this screen gets an explicit DELETE.
        const before = JSON.parse(savedOverrides);
        const cleared = Object.keys(before).filter(
          (f) => !Object.prototype.hasOwnProperty.call(overrides, f)
        );

        let engagementFailed = '';

        for (const field of cleared) {
          if (engagementFailed) continue;
          // eslint-disable-next-line no-await-in-loop
          const { ok, status, data, body } = await requestJSON(
            `/api/flow-config/${targetId}/engagement/${ENGAGEMENT_API_FIELD[field]}`,
            { method: 'DELETE' }
          );
          if (!ok) engagementFailed = `${FIELD_LABELS[field]}: ${errorMessage(data, body, status)}`;
        }

        if (!engagementFailed && Object.keys(overrides).length) {
          const payload = {};
          Object.entries(overrides).forEach(([field, value]) => {
            payload[ENGAGEMENT_API_FIELD[field]] = value;
          });
          // acknowledge_state_risk is a required companion field on the API, not a second question
          // for the operator: the PUT is refused without it whenever send_cookies is true. Ticking
          // the checkbox is the decision, so the flag is derived from it here.
          if (payload.send_cookies) payload.acknowledge_state_risk = true;

          const { ok, status, data, body } = await requestJSON(
            `/api/flow-config/${targetId}/engagement`,
            {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
            }
          );
          if (!ok) engagementFailed = errorMessage(data, body, status);
        }

        if (engagementFailed) {
          failed.push(`engagement rules: ${engagementFailed}`);
        } else {
          setSavedOverrides(currentOverridesKey);
          const count = Object.keys(overrides).length;
          done.push(count === 0
            ? 'no engagement overrides: this target inherits everything'
            : `${count} engagement field${count === 1 ? '' : 's'} set for this target`);
        }
      }
    } catch (err) {
      failed.push(`could not reach the framework: ${err.message}`);
    } finally {
      setSaving(false);
    }
    // Whatever happened, the screen is re-read from the server rather than trusted to match what was
    // just sent. A save that was partly refused must not leave the operator looking at the values
    // they typed as though they had stuck.
    if (failed.length) {
      loadEndpoints();
      loadEngagement();
    }
    // Both halves are reported. A save where the selection stuck and the header did not must never
    // read as a single green tick, because the operator would then run believing the programme's
    // mandatory header is going out.
    if (done.length) setSaveNotice(`Saved: ${done.join('; ')}.`);
    if (failed.length) setSaveError(`Not saved - ${failed.join('; ')}.`);
  };

  const attemptClose = () => {
    if (dirty && !confirmDiscard) {
      setConfirmDiscard(true);
      return;
    }
    setConfirmDiscard(false);
    handleClose();
  };

  /* ----------------------------------------------------------------- render */

  const renderProvenance = (field) => {
    const state = provenanceOf(field);
    const style = PROVENANCE_STYLE[state];
    const entry = inherited[field];
    const fallbackText = displayValue(field, entry ? entry.value : ENGAGEMENT_DEFAULTS[field]);
    const fallbackWord = entry && entry.source === 'global' ? 'global settings' : 'the framework default';
    return (
      <span className="d-inline-flex align-items-center flex-wrap" style={{ gap: '0.35rem' }}>
        <span
          className={`badge bg-dark border ${style.cls}`}
          style={{ fontSize: '0.58rem', fontWeight: 600, letterSpacing: '0.02em' }}
          title={state === 'target'
            ? 'This value is stored against this target only. Other targets are unaffected, and changing global Settings will not change it.'
            : `Nothing is stored for this target, so the value comes from ${fallbackWord} and follows it if it changes.`}
        >
          <i className={`bi ${style.icon} me-1`} />
          {style.text}
        </span>
        {state === 'target' ? (
          <Button
            variant="link"
            className="p-0 text-info text-decoration-underline"
            style={{ fontSize: '0.62rem', lineHeight: 1.2 }}
            onClick={() => clearField(field)}
            title={`Stop overriding the ${FIELD_LABELS[field]} for this target and go back to ${fallbackWord}.`}
          >
            clear override, use {fallbackWord} ({fallbackText})
          </Button>
        ) : (
          <span className="text-white-50" style={{ fontSize: '0.62rem' }}>
            {fallbackText}
          </span>
        )}
      </span>
    );
  };

  const renderEndpointRow = (row, id) => {
    if (row.lock) {
      const isExclusion = row.lock.kind === LOCK_EXCLUSION;
      return (
        <div
          key={row.key}
          className="px-2 py-1"
          style={{
            borderLeft: `3px solid ${isExclusion ? '#dc3545' : '#ffc107'}`,
            background: isExclusion ? '#2b1d20' : '#2b2619',
            marginBottom: '2px',
          }}
        >
          <div className="d-flex align-items-start">
            {/* Where the checkbox would be there is a padlock. Nothing in this position is clickable,
                because the only way to undo this is where the reason for it was written. */}
            <span
              className={`flex-shrink-0 text-center ${isExclusion ? 'text-danger' : 'text-warning'}`}
              style={{ width: '22px' }}
              title={isExclusion
                ? 'Excluded by a safety rule. Not a checkbox: remove it in Detect Flows, where the reason was written.'
                : 'This host is out of scope for this target. Nothing on this screen can make it reachable.'}
            >
              <i className="bi bi-shield-lock-fill" />
            </span>
            <span
              className={`badge bg-dark border me-2 flex-shrink-0 ${isExclusion ? 'border-danger text-danger' : 'border-warning text-warning'}`}
              style={{ fontSize: '0.55rem', letterSpacing: '0.04em' }}
            >
              {row.lock.label}
            </span>
            <span
              className="flex-grow-1"
              style={{
                fontFamily: MONO,
                fontSize: '0.68rem',
                wordBreak: 'break-all',
                textDecoration: 'line-through',
                textDecorationColor: isExclusion ? '#dc3545' : '#ffc107',
                minWidth: 0,
              }}
            >
              <span className="text-white-50 me-2">{row.method}</span>
              <span className="text-white-50">{row.path}</span>
            </span>
          </div>
          <div className="ps-4" style={{ fontSize: '0.64rem' }}>
            {row.lock.pattern && (
              <span className="text-white-50 me-2">
                matched <code className="text-info">{row.lock.pattern}</code>
              </span>
            )}
            <span className={isExclusion ? 'text-danger' : 'text-warning'}>
              {row.lock.reason || (isExclusion
                ? 'No reason was recorded with this rule.'
                : 'This host is marked out of scope on this target.')}
            </span>
          </div>
        </div>
      );
    }

    const on = !deselected.has(row.key);
    return (
      <div
        key={row.key}
        className="px-2 py-1"
        style={{
          borderLeft: `3px solid ${on ? '#495057' : 'transparent'}`,
          background: on ? 'transparent' : '#1b1e21',
          opacity: on ? 1 : 0.62,
          marginBottom: '2px',
        }}
      >
        <Form.Check
          type="checkbox"
          id={id}
          checked={on}
          onChange={(e) => setRowSelected(row.key, e.target.checked)}
          label={
            <span className="d-flex align-items-center flex-wrap" style={{ gap: '0.4rem', minWidth: 0 }}>
              <span
                className={on ? 'text-warning' : 'text-white-50'}
                style={{ fontFamily: MONO, fontSize: '0.66rem', minWidth: '46px' }}
              >
                {row.method}
              </span>
              <span
                className={on ? 'text-info' : 'text-white-50'}
                style={{ fontFamily: MONO, fontSize: '0.68rem', wordBreak: 'break-all', minWidth: 0 }}
              >
                {row.path}
              </span>
              {/* EVERY status recorded, not one billed as "the last". The server keeps status_codes
                  as an unordered set, so there is no most-recent element to show and picking one
                  would be a number that looks like a fact and is not. */}
              {row.statuses.length ? (
                row.statuses.map((code) => (
                  <span
                    key={code}
                    className={`badge bg-${statusVariant(code)}`}
                    style={{ fontSize: '0.55rem' }}
                    title="A status the crawl recorded for this endpoint. These are a set, not a history: there is no order and no latest."
                  >
                    {code}
                  </span>
                ))
              ) : (
                <span
                  className="text-white-50"
                  style={{ fontSize: '0.58rem' }}
                  title="No response status is recorded for this endpoint. Not the same as a failure: nothing was stored."
                >
                  no status recorded
                </span>
              )}
              {row.sources.length > 0 && (
                <span className="text-white-50" style={{ fontSize: '0.58rem' }}>
                  {row.sources.join(' + ')}
                </span>
              )}
              {!on && (
                <span className="text-white-50 fst-italic" style={{ fontSize: '0.58rem' }}>
                  not in this run
                </span>
              )}
            </span>
          }
        />
      </div>
    );
  };

  const renderEndpoints = () => {
    if (endpointsLoading && rows.length === 0) {
      return (
        <div className="text-white-50 p-3" style={{ fontSize: '0.78rem' }}>
          <Spinner animation="border" size="sm" variant="danger" className="me-2" />
          Reading every endpoint discovered on this target.
        </div>
      );
    }
    if (endpointsError) {
      return (
        <Alert variant="danger" className="py-2 m-3" style={{ fontSize: '0.75rem' }}>
          <i className="bi bi-exclamation-triangle me-2" />
          {endpointsError}
          <div className="mt-2">
            <Button size="sm" variant="outline-light" onClick={loadEndpoints}>Try again</Button>
          </div>
        </Alert>
      );
    }

    const filteredSelectable = filtered.filter((r) => !r.lock).length;
    const filtering = filterText.trim() !== '';

    return (
      <div className="d-flex flex-column h-100" style={{ minHeight: 0 }}>
        <div className="p-3 border-bottom border-secondary">
          <div className="text-white" style={{ fontSize: '0.86rem' }}>
            Which endpoints active detection may touch
          </div>
          <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem', lineHeight: 1.55 }}>
            Everything discovered on this target, ticked. Untick what you do not want a detection run
            to request. This is scoping, and it is reversible with one click, which is exactly what
            makes it a different thing from an exclusion.
            {selectionModel && <span className="d-block mt-1">{selectionModel}</span>}
          </div>

          {selectionNote && (
            <Alert variant="warning" className="py-2 mt-2 mb-0" style={{ fontSize: '0.7rem' }}>
              <i className="bi bi-info-circle me-2" />
              {selectionNote}
              {fallbackSetAside > 0 && (
                <div className="mt-1">
                  {fallbackSetAside.toLocaleString()} more recorded endpoint
                  {fallbackSetAside === 1 ? ' is' : 's are'} not listed, because the preview set them
                  aside for reasons that belong to the run rather than to the endpoint - recorded with
                  a verb the preview was not sending, or an unusable URL. They are not blocked, and
                  they are not hidden from Detect Flows.
                </div>
              )}
            </Alert>
          )}

          <div className="d-flex align-items-center flex-wrap mt-2" style={{ gap: '0.5rem' }}>
            <InputGroup size="sm" style={{ maxWidth: '360px' }}>
              <InputGroup.Text className="bg-dark border-secondary text-white-50">
                <i className="bi bi-funnel" />
              </InputGroup.Text>
              <Form.Control
                value={filterText}
                onChange={(e) => { setFilterText(e.target.value); setShowAllRows(false); }}
                placeholder="host, path, method or status"
                spellCheck={false}
                className="bg-dark text-white border-secondary"
                style={{ fontFamily: MONO, fontSize: '0.72rem' }}
                data-bs-theme="dark"
                aria-label="Filter the endpoint list"
              />
              {filtering && (
                <Button variant="outline-secondary" onClick={() => setFilterText('')} title="Clear the filter">
                  <i className="bi bi-x" />
                </Button>
              )}
            </InputGroup>

            <Button
              size="sm"
              variant="outline-info"
              onClick={() => setShownSelected(true)}
              disabled={filteredSelectable === 0}
              title="Tick every endpoint currently listed. Excluded rows are untouched: they are not checkboxes."
            >
              {filtering
                ? `Select all ${filteredSelectable.toLocaleString()} shown`
                : 'Select all'}
            </Button>
            <Button
              size="sm"
              variant="outline-secondary"
              onClick={() => setShownSelected(false)}
              disabled={filteredSelectable === 0}
              title="Untick every endpoint currently listed."
            >
              {filtering
                ? `Deselect all ${filteredSelectable.toLocaleString()} shown`
                : 'Select none'}
            </Button>
            {filtering && (
              <span className="text-warning" style={{ fontSize: '0.64rem' }}>
                These two buttons only touch the {filteredSelectable.toLocaleString()} row
                {filteredSelectable === 1 ? '' : 's'} the filter is showing. Anything filtered out
                keeps whatever you already decided for it.
              </span>
            )}
          </div>

          <div className="d-flex align-items-baseline flex-wrap mt-2" style={{ gap: '0.75rem' }}>
            <span className="text-white" style={{ fontSize: '0.95rem' }}>
              <strong className={selectedCount === selectableRows.length ? 'text-info' : 'text-warning'}>
                {selectedCount.toLocaleString()}
              </strong>
              <span className="text-white-50"> of </span>
              <strong>{selectableRows.length.toLocaleString()}</strong>
              <span className="text-white-50" style={{ fontSize: '0.7rem' }}> selectable endpoints selected</span>
            </span>
            <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
              <i className="bi bi-shield-lock-fill text-danger me-1" />
              {excludedCount.toLocaleString()} excluded by a safety rule
            </span>
            <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
              <i className="bi bi-shield-lock-fill text-warning me-1" />
              {(lockedRows.length - excludedCount).toLocaleString()} out of scope
            </span>
            <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
              {rows.length.toLocaleString()} rows in total
              {endpointsSource === 'preview' && ' (from the detection preview)'}
            </span>
            {filtering && (
              <span className="text-info" style={{ fontSize: '0.7rem' }}>
                filter showing {filtered.length.toLocaleString()}
              </span>
            )}
          </div>

          <div className="d-flex flex-wrap mt-2" style={{ gap: '1.25rem', fontSize: '0.64rem' }}>
            <span className="text-white-50">
              <span
                className="d-inline-block align-middle me-1"
                style={{ width: '10px', height: '10px', background: '#495057' }}
              />
              ticked - a run may request it
            </span>
            <span className="text-white-50">
              <span
                className="d-inline-block align-middle me-1"
                style={{ width: '10px', height: '10px', background: '#1b1e21', border: '1px solid #495057' }}
              />
              unticked - your scoping decision, tick it back any time
            </span>
            <span className="text-danger">
              <i className="bi bi-shield-lock-fill me-1" />
              excluded - a written safety rule, no checkbox, changed only in Detect Flows
            </span>
          </div>
        </div>

        <div className="flex-grow-1 p-2" style={{ overflowY: 'auto', minHeight: 0 }}>
          {rows.length === 0 ? (
            <div className="text-white-50 fst-italic p-3" style={{ fontSize: '0.76rem' }}>
              No endpoints have been discovered on this target yet. Run the URL workflow, consolidate
              endpoints, or crawl the target, and they will appear here.
            </div>
          ) : filtered.length === 0 ? (
            <div className="text-white-50 fst-italic p-3" style={{ fontSize: '0.76rem' }}>
              Nothing matches that filter. The {rows.length.toLocaleString()} rows are still there and
              their selection is unchanged.
            </div>
          ) : (
            <>
              {cappedGroups.map((group, gi) => {
                const hostSelectable = group.rows.filter((r) => !r.lock);
                const hostOn = hostSelectable.filter((r) => !deselected.has(r.key)).length;
                return (
                  <div key={group.host} className="mb-3">
                    <div
                      className="d-flex align-items-center px-2 py-1 border-bottom border-secondary"
                      style={{ position: 'sticky', top: 0, background: '#212529', zIndex: 1 }}
                    >
                      <span className="text-white" style={{ fontSize: '0.74rem', fontFamily: MONO }}>
                        {group.host}
                      </span>
                      <span className="text-white-50 ms-2" style={{ fontSize: '0.64rem' }}>
                        {hostOn.toLocaleString()} of {hostSelectable.length.toLocaleString()} selected
                        {group.rows.length !== hostSelectable.length
                          && ` · ${(group.rows.length - hostSelectable.length).toLocaleString()} locked`}
                      </span>
                      <span className="ms-auto d-flex" style={{ gap: '0.35rem' }}>
                        <Button
                          size="sm"
                          variant="link"
                          className="p-0 text-info text-decoration-underline"
                          style={{ fontSize: '0.64rem' }}
                          disabled={hostSelectable.length === 0}
                          onClick={() => setHostSelected(group.rows, true)}
                        >
                          all
                        </Button>
                        <Button
                          size="sm"
                          variant="link"
                          className="p-0 text-white-50 text-decoration-underline"
                          style={{ fontSize: '0.64rem' }}
                          disabled={hostSelectable.length === 0}
                          onClick={() => setHostSelected(group.rows, false)}
                        >
                          none
                        </Button>
                      </span>
                    </div>
                    {group.rows.map((row, ri) => renderEndpointRow(row, `fcm-ep-${gi}-${ri}`))}
                  </div>
                );
              })}
              {!showAllRows && filtered.length > RENDER_CAP && (
                <div className="text-center py-2 border-top border-secondary">
                  <span className="text-warning" style={{ fontSize: '0.7rem' }}>
                    Showing the first {RENDER_CAP.toLocaleString()} of {filtered.length.toLocaleString()}.
                    This is a display cap only - your selection covers all
                    {' '}{filtered.length.toLocaleString()}, drawn or not.
                  </span>
                  <Button
                    size="sm"
                    variant="outline-warning"
                    className="ms-2 py-0 px-2"
                    style={{ fontSize: '0.68rem' }}
                    onClick={() => setShowAllRows(true)}
                  >
                    Draw all
                  </Button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    );
  };

  const renderPreviewLine = () => (
    <div
      className="border border-secondary rounded p-2"
      style={{ background: '#161a1d', fontFamily: MONO, fontSize: '0.68rem', lineHeight: 1.6 }}
    >
      <div className="text-white-50">GET /some/path HTTP/1.1</div>
      <div className="text-white-50">Host: <span className="text-info">{(activeTarget && activeTarget.scope_target) || 'target-host'}</span></div>
      <div>
        <span className="text-white-50">User-Agent: </span>
        {effectiveUA.text
          ? <span className="text-info">{effectiveUA.text}</span>
          : (
            <span className="text-white-50 fst-italic">
              {effectiveUA.unknownBase && uaMode === 'append'
                ? '«whatever User-Agent this run would otherwise send - this screen was not told what it is»'
                : '«unchanged: the framework\'s own User-Agent»'}
            </span>
          )}
        {effectiveUA.appended && <span className="text-warning"> {effectiveUA.appended}</span>}
      </div>
      {headerName && headerValue.trim() ? (
        <div>
          <span className="text-warning">{headerName}</span>
          <span className="text-white-50">: </span>
          <span className="text-warning">{headerValue}</span>
        </div>
      ) : (
        <div className="text-white-50 fst-italic">
          «no programme header - check the brief before you run anything»
        </div>
      )}
      <div>
        {sendCookies ? (
          <span className="text-danger">Cookie: your saved session for this target</span>
        ) : (
          <span className="text-white-50 fst-italic">«no Cookie header: this run is anonymous»</span>
        )}
      </div>
    </div>
  );

  const renderEngagement = () => (
    <div className="p-3" style={{ overflowY: 'auto', minHeight: 0 }}>
      <div className="text-white" style={{ fontSize: '0.86rem' }}>
        What every request to this target has to carry
      </div>
      <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem', lineHeight: 1.55, maxWidth: '900px' }}>
        Programmes disagree, and they disagree in writing. One asks for
        <code className="text-info mx-1">X-HackerOne-DailyPay-Research: rs0n2</code>
        on every request or the SOC treats your traffic as an attack. The next asks for a tag appended
        to a real browser User-Agent and caps you at 45 requests a minute. The next asks for neither.
        These fields are stored against <strong className="text-white">this target</strong>, so
        switching targets is not something you have to remember to do. Anything you do not set here is
        inherited from global Settings, and every field says which of those two it currently is.
      </div>

      {engagementNote && (
        <Alert variant="warning" className="py-2 mt-2 mb-0" style={{ fontSize: '0.7rem' }}>
          <i className="bi bi-exclamation-triangle me-2" />
          {engagementNote}
        </Alert>
      )}
      {engagementError && (
        <Alert variant="danger" className="py-2 mt-2 mb-0" style={{ fontSize: '0.72rem' }}>
          <i className="bi bi-exclamation-triangle me-2" />
          {engagementError}
        </Alert>
      )}

      <div className="d-flex flex-wrap mt-3" style={{ gap: '1.5rem' }}>
        <div style={{ flex: '1 1 460px', minWidth: '340px' }}>
          <div className="border border-secondary rounded p-3 mb-3">
            <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
              PROGRAMME HEADER
            </div>

            <Field
              label="HEADER NAME"
              provenance={renderProvenance('custom_header_name')}
            >
              <Form.Control
                size="sm"
                value={String(valueOf('custom_header_name') || '')}
                onChange={(e) => setField('custom_header_name', e.target.value)}
                placeholder="X-HackerOne-DailyPay-Research"
                spellCheck={false}
                disabled={!engagementAvailable}
                className="bg-dark text-white border-secondary"
                style={{ fontFamily: MONO, fontSize: '0.72rem' }}
                data-bs-theme="dark"
              />
            </Field>

            <Field
              label="HEADER VALUE"
              provenance={renderProvenance('custom_header_value')}
              hint="Usually your researcher handle, exactly as the brief writes it. It is what the
                    programme greps their logs for when they want to tell you apart from an attacker."
            >
              <Form.Control
                size="sm"
                value={String(valueOf('custom_header_value') || '')}
                onChange={(e) => setField('custom_header_value', e.target.value)}
                placeholder="rs0n2"
                spellCheck={false}
                disabled={!engagementAvailable}
                className="bg-dark text-white border-secondary"
                style={{ fontFamily: MONO, fontSize: '0.72rem' }}
                data-bs-theme="dark"
              />
            </Field>

            {headerProblem && (
              <div className={headerBlocksSave ? 'text-danger' : 'text-warning'} style={{ fontSize: '0.68rem' }}>
                <i className="bi bi-exclamation-triangle me-1" />
                {headerProblem}
              </div>
            )}
          </div>

          <div className="border border-secondary rounded p-3 mb-3">
            <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
              USER-AGENT
            </div>

            <Field
              label="MODE"
              provenance={renderProvenance('user_agent_mode')}
              hint="Append is for the programme that wants a tag on the end of a normal browser
                    User-Agent, so their WAF still sees a browser. Replace is for the one that wants a
                    specific string and nothing else."
            >
              <div className="d-flex" style={{ gap: '1.25rem' }}>
                <Form.Check
                  type="radio"
                  id="fcm-ua-replace"
                  name="fcm-ua-mode"
                  className="text-white"
                  style={{ fontSize: '0.74rem' }}
                  label="Replace the User-Agent"
                  checked={uaMode === 'replace'}
                  disabled={!engagementAvailable}
                  onChange={() => setField('user_agent_mode', 'replace')}
                />
                <Form.Check
                  type="radio"
                  id="fcm-ua-append"
                  name="fcm-ua-mode"
                  className="text-white"
                  style={{ fontSize: '0.74rem' }}
                  label="Append a tag to it"
                  checked={uaMode === 'append'}
                  disabled={!engagementAvailable}
                  onChange={() => setField('user_agent_mode', 'append')}
                />
              </div>
            </Field>

            <Field
              label={uaMode === 'append' ? 'TAG TO APPEND' : 'FULL USER-AGENT'}
              provenance={renderProvenance('user_agent')}
              hint={uaMode === 'append'
                ? 'Appended after a single space. The preview on the right shows the whole string.'
                : 'Sent as the entire User-Agent. Leave it empty to send the framework\'s own.'}
            >
              <Form.Control
                size="sm"
                value={uaText}
                onChange={(e) => setField('user_agent', e.target.value)}
                placeholder={uaMode === 'append' ? '<H1-rs0n2>' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... <H1-rs0n2>'}
                spellCheck={false}
                disabled={!engagementAvailable}
                className="bg-dark text-white border-secondary"
                style={{ fontFamily: MONO, fontSize: '0.72rem' }}
                data-bs-theme="dark"
              />
            </Field>
          </div>

          <div className="border border-secondary rounded p-3 mb-3">
            <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
              PACE AND BUDGET
            </div>
            <div className="text-white-50 mb-2" style={{ fontSize: '0.66rem' }}>
              These are this target&apos;s values. Detect Flows opens on them and can go lower for a
              single run; it cannot go above the framework ceilings ({MAX_RPS} req/s,{' '}
              {HARD_MAX_REQUESTS.toLocaleString()} requests, {MAX_TIMEOUT_S} s,{' '}
              {HARD_MAX_REDIRECTS} hops).
            </div>

            <Field
              label="RATE LIMIT"
              provenance={renderProvenance('rps')}
              hint={`= ${Math.round(rps * 60).toLocaleString()} requests per minute, which is the unit
                     most briefs are written in. Paced per host, with jitter.`}
            >
              <InputGroup size="sm" style={{ maxWidth: '220px' }}>
                <Form.Control
                  type="number"
                  min={0.1}
                  max={MAX_RPS}
                  step={0.05}
                  value={valueOf('rps')}
                  disabled={!engagementAvailable}
                  onChange={(e) => setNumberField('rps', e.target.value, { min: 0.1, max: MAX_RPS })}
                  className="bg-dark text-white border-secondary"
                  data-bs-theme="dark"
                />
                <InputGroup.Text className="bg-dark border-secondary text-white-50" style={{ fontSize: '0.66rem' }}>
                  req/s
                </InputGroup.Text>
              </InputGroup>
            </Field>

            <div className="d-flex flex-wrap" style={{ gap: '1rem' }}>
              <Field label="REQUEST TIMEOUT" provenance={renderProvenance('timeout_s')}>
                <InputGroup size="sm" style={{ maxWidth: '160px' }}>
                  <Form.Control
                    type="number"
                    min={1}
                    max={MAX_TIMEOUT_S}
                    value={valueOf('timeout_s')}
                    disabled={!engagementAvailable}
                    onChange={(e) => setNumberField('timeout_s', e.target.value, { min: 1, max: MAX_TIMEOUT_S, integer: true })}
                    className="bg-dark text-white border-secondary"
                    data-bs-theme="dark"
                  />
                  <InputGroup.Text className="bg-dark border-secondary text-white-50" style={{ fontSize: '0.66rem' }}>
                    s
                  </InputGroup.Text>
                </InputGroup>
              </Field>

              <Field label="MAX REQUESTS PER RUN" provenance={renderProvenance('max_requests')}>
                <Form.Control
                  type="number"
                  size="sm"
                  min={1}
                  max={HARD_MAX_REQUESTS}
                  step={10}
                  value={valueOf('max_requests')}
                  disabled={!engagementAvailable}
                  onChange={(e) => setNumberField('max_requests', e.target.value, { min: 1, max: HARD_MAX_REQUESTS, integer: true })}
                  className="bg-dark text-white border-secondary"
                  style={{ maxWidth: '140px' }}
                  data-bs-theme="dark"
                />
              </Field>

              <Field
                label="REDIRECT DEPTH"
                provenance={renderProvenance('max_redirects')}
                hint="Every hop is re-checked against scope and exclusions before it is requested."
              >
                <Form.Control
                  type="number"
                  size="sm"
                  min={0}
                  max={HARD_MAX_REDIRECTS}
                  value={valueOf('max_redirects')}
                  disabled={!engagementAvailable}
                  onChange={(e) => setNumberField('max_redirects', e.target.value, { min: 0, max: HARD_MAX_REDIRECTS, integer: true })}
                  className="bg-dark text-white border-secondary"
                  style={{ maxWidth: '110px' }}
                  data-bs-theme="dark"
                />
              </Field>
            </div>
          </div>
        </div>

        <div style={{ flex: '1 1 380px', minWidth: '330px' }}>
          <div className="border border-info rounded p-3 mb-3">
            <div className="text-info mb-2" style={{ fontSize: '0.72rem' }}>
              <i className="bi bi-eye me-2" />
              What every request will look like
            </div>
            {renderPreviewLine()}
            <div className="text-white-50 mt-2" style={{ fontSize: '0.64rem' }}>
              Built from the values on the left, whether they are set for this target or inherited.
              This is the one place to check before you hand the run to a programme that is watching
              its logs for you.
            </div>
          </div>

          <div className="border border-secondary rounded p-3 mb-3">
            <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
              SESSION
            </div>
            <Form.Check
              type="checkbox"
              id="fcm-send-cookies"
              className="text-white"
              style={{ fontSize: '0.74rem' }}
              checked={sendCookies}
              disabled={!engagementAvailable}
              onChange={(e) => setField('send_cookies', e.target.checked)}
              label={
                <span>
                  Send my saved session cookies
                  <span className="text-white-50 d-block" style={{ fontSize: '0.66rem' }}>
                    Requests go out as your logged-in user. Applies to the Request Flow Builder and
                    Replay Requests; active detection has no cookie jar and ignores it.
                  </span>
                </span>
              }
            />
            <div className="mt-2 ps-4">{renderProvenance('send_cookies')}</div>
          </div>

          <div className="border border-secondary rounded p-3">
            <Field
              label="PROGRAMME NOTES"
              provenance={renderProvenance('notes')}
              hint="Free text, kept with this target. The place for the sentence out of the brief that
                    you will not remember in three weeks: the required header, the testing window, the
                    subdomain they asked you to leave alone."
            >
              <Form.Control
                as="textarea"
                rows={7}
                value={String(valueOf('notes') || '')}
                onChange={(e) => setField('notes', e.target.value)}
                placeholder={'Rate cap: 45 req/min (brief section 4).\nUA must carry <H1-rs0n2>.\nNo testing against payments.* per the programme page.'}
                spellCheck={false}
                disabled={!engagementAvailable}
                className="bg-dark text-white border-secondary"
                style={{ fontSize: '0.72rem', lineHeight: 1.5 }}
                data-bs-theme="dark"
              />
            </Field>
          </div>
        </div>
      </div>
    </div>
  );

  const renderRails = () => (
    <div className="p-3" style={{ overflowY: 'auto', minHeight: 0 }}>
      <div className="text-white" style={{ fontSize: '0.86rem' }}>
        Enforced by the server, not by this screen
      </div>
      <div className="text-white-50 mt-1 mb-3" style={{ fontSize: '0.72rem', lineHeight: 1.55, maxWidth: '900px' }}>
        Three rules hold whatever is configured here or in Detect Flows. They are enforced in
        <code className="text-info mx-1">server/utils/flowDetectionActive.go</code>
        and <code className="text-info me-1">server/utils/detectedFlowRun.go</code>.
      </div>

      <div className="border border-success rounded px-3 py-1" style={{ maxWidth: '900px' }}>
        <Rail icon="bi-slash-circle" headline="A host marked out of scope is never contacted.">
          Checked on the original endpoint and again on every redirect destination, so a redirect
          cannot walk a run onto a host you did not allow. No run configuration overrides it. Those
          hosts appear in the endpoint list padlocked, so you can see they were considered and
          refused.
        </Rail>

        <Rail icon="bi-speedometer2" headline="The engagement rate limit paces every request.">
          This target&apos;s rate limit is applied per host with jitter, and a run may go slower than
          it but never faster. The ceilings are {MAX_RPS} req/s and{' '}
          {HARD_MAX_REQUESTS.toLocaleString()} requests per run. A run aborts on its own if the target
          starts answering 429 or 503.
        </Rail>

        <Rail icon="bi-arrow-repeat" headline="Conditional flows are bounded by an execution cap.">
          The budget counts steps EXECUTED, not steps defined, so a flow with a backwards edge cannot
          spin inside it. A run stops at the cap and says which cap it hit and what its value was.
          This target&apos;s request budget lowers it further when it is the smaller number.
        </Rail>
      </div>
    </div>
  );

  const NAV = [
    {
      id: 'endpoints',
      icon: 'bi-list-check',
      title: 'Endpoints',
      blurb: 'What a run may touch',
      badge: rows.length
        ? `${selectedCount.toLocaleString()}/${selectableRows.length.toLocaleString()}`
        : '',
    },
    {
      id: 'engagement',
      icon: 'bi-file-earmark-ruled',
      title: 'Engagement rules',
      blurb: 'What every request carries',
      badge: Object.keys(overrides).length
        ? `${Object.keys(overrides).length} set here`
        : 'all inherited',
    },
    {
      id: 'rails',
      icon: 'bi-shield-lock',
      title: 'Always true',
      blurb: 'Not configurable, by design',
      badge: '',
    },
  ];

  const renderBody = () => {
    if (!targetId) {
      return <div className="text-white-50 small p-3">No target selected.</div>;
    }
    return (
      <div className="d-flex flex-grow-1" style={{ minHeight: 0 }}>
        <div
          className="border-end border-secondary d-flex flex-column p-2"
          style={{ width: '250px', flexShrink: 0, overflowY: 'auto' }}
        >
          {NAV.map((item) => {
            const active = section === item.id;
            return (
              <Button
                key={item.id}
                variant={active ? 'danger' : 'outline-secondary'}
                className="text-start mb-2"
                onClick={() => setSection(item.id)}
              >
                <div style={{ fontSize: '0.78rem' }}>
                  <i className={`bi ${item.icon} me-2`} />
                  {item.title}
                </div>
                <div className="text-white-50" style={{ fontSize: '0.64rem' }}>
                  {item.blurb}
                </div>
                {item.badge && (
                  <div
                    className={active ? 'text-white' : 'text-info'}
                    style={{ fontSize: '0.62rem', fontFamily: MONO }}
                  >
                    {item.badge}
                  </div>
                )}
              </Button>
            );
          })}

          <div className="text-white-50 mt-2" style={{ fontSize: '0.64rem', lineHeight: 1.5 }}>
            <i className="bi bi-info-circle me-1" />
            Nothing on this screen sends a request. It decides what Detect Flows is allowed to do when
            you get there.
          </div>

          {(engagementLoading || endpointsLoading) && (
            <div className="text-white-50 mt-2" style={{ fontSize: '0.64rem' }}>
              <Spinner animation="border" size="sm" variant="danger" className="me-2" />
              loading
            </div>
          )}
        </div>

        <div className="flex-grow-1 d-flex flex-column" style={{ minWidth: 0, minHeight: 0 }}>
          {section === 'endpoints' && renderEndpoints()}
          {section === 'engagement' && renderEngagement()}
          {section === 'rails' && renderRails()}
        </div>
      </div>
    );
  };

  return (
    <Modal show={show} onHide={attemptClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-sliders me-2" />
          Configure
          {activeTarget && activeTarget.scope_target && (
            <span className="text-white-50 ms-2" style={{ fontSize: '0.9rem' }}>
              {activeTarget.scope_target}
            </span>
          )}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="d-flex flex-column p-0" style={{ minHeight: 0, overflow: 'hidden' }}>
        {renderBody()}
      </Modal.Body>

      <Modal.Footer className="d-flex align-items-center">
        <div className="text-white-50 me-auto" style={{ fontSize: '0.68rem', maxWidth: '60%' }}>
          {saveError ? (
            <span className="text-danger">
              <i className="bi bi-exclamation-triangle me-1" />
              {saveError}
            </span>
          ) : saveNotice ? (
            <span className="text-info">
              <i className="bi bi-check2 me-1" />
              {saveNotice}
            </span>
          ) : dirty ? (
            <span className="text-warning">
              <i className="bi bi-pencil me-1" />
              Unsaved changes
              {selectionDirty && ' to the endpoint selection'}
              {selectionDirty && engagementDirty && ' and'}
              {engagementDirty && ' to the engagement rules'}
              . They apply to detection runs only once saved.
            </span>
          ) : (
            <span>
              {saveBlockedReason === 'Nothing has changed.'
                ? 'Saved and up to date. Detect Flows will open on these values.'
                : saveBlockedReason}
            </span>
          )}
        </div>

        {confirmDiscard ? (
          <>
            <span className="text-warning me-2" style={{ fontSize: '0.7rem' }}>
              Close and lose the unsaved changes?
            </span>
            <Button variant="outline-secondary" onClick={() => setConfirmDiscard(false)}>
              Keep editing
            </Button>
            <Button variant="warning" onClick={() => { setConfirmDiscard(false); handleClose(); }}>
              Discard and close
            </Button>
          </>
        ) : (
          <>
            <Button
              variant="danger"
              disabled={Boolean(saveBlockedReason) || saving}
              onClick={save}
              title={saveBlockedReason || 'Store this configuration against this target.'}
            >
              {saving
                ? <><Spinner animation="border" size="sm" className="me-2" />Saving</>
                : <><i className="bi bi-save me-2" />Save configuration</>}
            </Button>
            <Button variant="secondary" onClick={attemptClose}>Close</Button>
          </>
        )}
      </Modal.Footer>
    </Modal>
  );
};

export default FlowConfigureModal;
