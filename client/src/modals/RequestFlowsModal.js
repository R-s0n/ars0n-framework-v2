import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Modal, Form, InputGroup, Button, Spinner, ProgressBar } from 'react-bootstrap';
import RequestFlowChart from '../components/RequestFlowChart';

// Request Flows: the flow view, standing on its own.
//
// A flow is one navigation and everything it pulled: the redirects it followed, the requests the
// page issued, in the order they happened. This modal is the whole of that view. It used to be a tab
// beside the repeater; it is not any more, and two consequences of the split are the reason most of
// this file exists.
//
//   DOUBLE-CLICK IS GONE. In the tabbed modal, double-clicking a node moved the capture into the
//   repeater tab. There is no repeater tab now, so the gesture has no destination inside this modal.
//   It is replaced by ONE explicit button, "Replay Single Request", on the selected node's details
//   panel, which calls the onOpenInRepeater prop. RequestFlowChart is deliberately handed
//   onOpenInRepeater={undefined}, which disables its double-click handler and its own in-chart
//   button, so there is exactly one way to do this and it is a labelled button. See the banner over
//   the chart: the component's built-in hint text still mentions double-click and cannot be edited
//   from here, so the banner says plainly that it does not apply.
//
//   ANY BYTE OF ANY REQUEST IS EDITABLE. Selecting a node loads the request as raw bytes into an
//   editor, and saving creates a NEW VERSION through /replay-request/{target}/versions. Nothing is
//   overwritten: the observed request is the immutable original, every save is a child of the
//   version it was edited from, and the picker walks back to any of them. That is the flow-level
//   equivalent of what the repeater does to a single request, and it is why an edit here needs no
//   undo.
//
// RUNNING THE FLOW. Everything above reads and edits; this next part SENDS. A detected flow is a
// reading of history with no step rows of its own, so it runs one way only: LINEARLY, in the order
// the requests were captured. There are no conditions and no branches here, and there is nowhere to
// hang them. That is what the builder is for, and "Edit as flow" in the header is the one click that
// gets there.
//
//   THE RUN BUTTON IS IN THE FLOW HEADER, over the diagram, not in the node panel. It acts on the
//   whole flow, so it sits with the whole flow.
//
//   IT OPENS ON A DRY RUN. The first click arms nothing: it asks the server what would be sent, in
//   what order, how many requests, and which steps are skipped and why. Sending is a SECOND,
//   deliberate click on a differently-labelled button. The same shape DetectFlowsModal uses, because
//   the operator has met it once already and a safety gate that changes shape between screens is a
//   gate nobody reads. Change anything about the configuration and the plan is invalidated: a dry
//   run of a different configuration is not evidence about this one.
//
//   YOUR EDITS ARE WHAT GETS SENT. If you edited a request and saved a version, the run sends THAT
//   version, not the bytes the target originally saw. Silently sending the original after somebody
//   edited it is the worst outcome available here, so the version each step will send is chosen
//   explicitly, listed in the dry run, counted in the header, named on the selected node, and sent
//   to the server as an explicit capture_id -> version_id pair rather than left to a default at the
//   far end.
//
//   RESULTS LAND ON THE GRAPH. The graph is already the mental model of the flow, so the results go
//   on it rather than into a second list beside it: each node's badge becomes that step's result as
//   the run progresses. Announced by a banner, and revertible to the captured statuses with one
//   toggle, because the two are different facts and must never be confused.
//
// Two rules the fetches follow, both carried over because they were learned the hard way:
//
//   A query the parser cannot read keeps the previous list on screen. A blanked list makes a syntax
//   error look like a search that matched nothing.
//
//   A failed load of a DIFFERENT flow does not leave the previous graph on screen pretending to be
//   the one that was clicked.

const FLOW_LIMIT = 200;

const MONO = 'Menlo, Consolas, "Courier New", monospace';

// One frozen empty array, so "no flow loaded" hands the chart the same identity every render and it
// does not lay the whole tree out again for nothing.
const EMPTY_LIST = [];

const FLOW_QUERY_EXAMPLES = [
  'method = POST',
  'status >= 400',
  'has:header.authorization',
  'resource_type = xhr',
  'path ^= /api',
  'is_direct = true',
];

// The three detection sources a flow can carry, as the backend names them
// (server/utils/flowDetectionActive.go: FlowSourcePassive / FlowSourceActive / FlowSourceBoth).
const SOURCE_PASSIVE = 'passive';
const SOURCE_ACTIVE = 'active';
const SOURCE_BOTH = 'both';

const SOURCE_TITLES = {
  [SOURCE_PASSIVE]: 'Passive: every request in this flow was recorded by your own browser during a '
    + 'manual crawl. The framework sent nothing to produce it.',
  [SOURCE_ACTIVE]: 'Active: every request in this flow was sent by the framework during a flow '
    + 'detection run. Nobody browsed this.',
  [SOURCE_BOTH]: 'Both: this route was recorded in your browser AND reproduced by active detection. '
    + 'The two agree that it is real, and the active pass is repeatable.',
};

/* ------------------------------------------------------------------ running a flow */

// Every URL this modal sends to, built in one place. A previous pass shipped a modal wired to a
// route that did not exist and there was no single line to check it against; this is that line.
//
//   POST /api/replay-request/flow/{flow_id}/run                  dry run and send, per `dry_run`
//   GET  /api/replay-request/flow/{flow_id}/run/{run_id}         progress and per-step results
//   POST /api/replay-request/flow/{flow_id}/run/{run_id}/cancel  stop one in flight
//
// Those three are the contract this modal was written against. If the server answers 404 on any of
// them, the failure is reported with the URL in it rather than as a generic error, so a route
// mismatch reads as a route mismatch.
//
// THE REQUEST BODY, verbatim from DetectedFlowRunOptions in server/utils/detectedFlowRun.go:
//
//   overrides            {capture_id: raw request bytes}. THE ONLY channel for an edited request.
//                        There is no version_id at the far end: the server never reads
//                        replay_request_versions, so bytes an operator edited reach the target
//                        only by being put in here.
//   dry_run              a pointer server-side; omitted means TRUE. Always sent explicitly.
//   include_all          send the subresources the diagram hides
//   skip_state_changing  narrow the run to its read-only steps. OFF by default: a replay that
//                        silently omitted the flow's POST would report green on a run that did not
//                        test the flow at all.
//   stop_on_error, max_steps   not sent; the server's defaults are the ones this screen describes.
const runURL = (flowId) => `/api/replay-request/flow/${encodeURIComponent(flowId)}/run`;
const runStatusURL = (flowId, runId) => (
  `/api/replay-request/flow/${encodeURIComponent(flowId)}/run/${encodeURIComponent(runId)}`
);
const runCancelURL = (flowId, runId) => `${runStatusURL(flowId, runId)}/cancel`;

const RUN_POLL_MS = 1000;

const RUN_LIVE_STATUSES = ['pending', 'queued', 'starting', 'running', 'sending', 'cancelling'];
const RUN_TERMINAL_STATUSES = [
  'completed', 'complete', 'finished', 'done', 'succeeded',
  'cancelled', 'canceled', 'aborted', 'stopped', 'error', 'failed', 'capped',
];

// How a step's result is painted on its node in the graph. The pill is drawn INSIDE the chart's own
// status badge and sized to cover it exactly (see runStateBadge), because RequestFlowChart is a
// shared component this file does not own and has no result prop to hand these to. The one channel
// it does render straight from node data is the status badge, so that is the channel the results
// travel down.
const RUN_STATE_PAINT = {
  pending: { bg: '#343a40', fg: '#adb5bd', word: 'pending' },
  running: { bg: '#0dcaf0', fg: '#04252b', word: 'sending' },
  skipped: { bg: '#ffc107', fg: '#332701', word: 'skipped' },
  failed: { bg: '#dc3545', fg: '#ffffff', word: 'failed' },
  never_ran: { bg: '#5a4300', fg: '#ffc107', word: 'never ran' },
  sent_no_status: { bg: '#495057', fg: '#e9ecef', word: 'sent, no status' },
};

const RUN_LEGEND = [
  { key: 'sent', label: 'the response status', hint: 'The request was sent and answered. The number is the status the target returned to THIS run, not the one that was captured.' },
  { key: 'running', label: 'sending', hint: 'In flight right now.' },
  { key: 'pending', label: 'pending', hint: 'Queued, not sent yet.' },
  { key: 'skipped', label: 'skipped', hint: 'The server refused to send this one and said why. Nothing left the framework for it.' },
  { key: 'failed', label: 'failed', hint: 'Sending was attempted and did not produce a response.' },
  { key: 'never_ran', label: 'never ran', hint: 'The run finished without ever reaching this step. Not the same as passing.' },
];

function statusVariant(status) {
  const code = Number(status);
  if (!code) return 'secondary';
  if (code < 300) return 'success';
  if (code < 400) return 'info';
  if (code < 500) return 'warning';
  return 'danger';
}

// "2xx" / "4xx" from the flow summary, same colours the node badges use.
function statusClassVariant(key) {
  const first = String(key || '').trim().charAt(0);
  if (first === '2') return 'success';
  if (first === '3') return 'info';
  if (first === '4') return 'warning';
  if (first === '5') return 'danger';
  return 'secondary';
}

function formatBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDuration(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  if (n < 1000) return `${Math.round(n)} ms`;
  return `${(n / 1000).toFixed(1)} s`;
}

function formatTimestamp(value) {
  if (!value) return null;
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return String(value);
  return at.toLocaleString();
}

// Bytes, not characters. A request whose body is UTF-8 is longer on the wire than it looks in a
// textarea, and Content-Length is the one number in this editor that has to be counted the way the
// server counts it.
function byteLength(text) {
  const s = String(text == null ? '' : text);
  try {
    return new TextEncoder().encode(s).length;
  } catch (err) {
    return s.length;
  }
}

// The label the backend builds is "POST /path". Splitting the verb off lets it be coloured the same
// way every other request line in the framework colours it.
function splitLabel(label) {
  const text = String(label == null ? '' : label).trim();
  const space = text.indexOf(' ');
  if (space > 0) {
    const head = text.slice(0, space);
    if (/^[A-Z]+$/.test(head)) return { method: head, rest: text.slice(space + 1) };
  }
  return { method: '', rest: text || '/' };
}

// Pulls a human message out of whatever the framework returned. Handlers answer with {error,message};
// the flows endpoint answers a bad query with its full shape plus `error`.
function errorMessage(data, body, status) {
  if (data && typeof data.message === 'string' && data.message) return data.message;
  if (data && typeof data.error === 'string' && data.error) return data.error;
  if (body && body.length < 400) return body;
  return `Request failed (${status})`;
}

// A 404 on one of the two run routes is not "your request is broken", it is "this server build does
// not have the route this screen was written against". Said in those words, with the URL, because
// the alternative is an operator debugging their flow when the mismatch is in the wiring.
function routeErrorMessage(url, data, body, status) {
  if (status === 404 && !(data && data.error)) {
    return `This server build has no ${url}. The run controls in this modal are written against `
      + 'POST /api/replay-request/flow/{flow_id}/run and '
      + 'GET /api/replay-request/flow/{flow_id}/run/{run_id}. Nothing was sent to the target.';
  }
  return errorMessage(data, body, status);
}

// One fetch helper for every call in this file, because every one of them needs the same three
// things: the status, the parsed body when it is JSON, and the raw text when it is not. A proxy that
// answers an unregistered route with an HTML 404 page is the case that makes the third necessary.
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

// The server's own comparison form (normalizeVersionBytes in replayRequestVersions.go): line endings
// unified, trailing newlines dropped, and nothing else. Deliberately does NOT recompute
// Content-Length, because a deliberately wrong Content-Length is the entire content of a smuggling
// probe and must count as a change.
function normalizeVersionBytes(raw) {
  return String(raw == null ? '' : raw)
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\n+$/, '');
}

// Reads the detection source off a flow row, whichever shape the flows endpoint reports it in, and
// returns '' when it reports none. '' means "not reported", never "passive": guessing here would put
// a confident badge on a flow the framework may well have generated itself.
function detectionSourceOf(flow, sourcesById) {
  if (!flow) return '';
  const direct = flow.detection_source || flow.source || '';
  const mapped = sourcesById && flow.id ? sourcesById[flow.id] : '';
  const value = String(direct || mapped || '').trim().toLowerCase();
  if (value === SOURCE_PASSIVE || value === SOURCE_ACTIVE || value === SOURCE_BOTH) return value;
  return '';
}

/* ----------------------------------------------------- versions: what will be sent */

// Versions come back oldest-first within a capture (the API sorts is_original DESC, created_at ASC),
// but a merged-in save has to land in the same order, so this sorts rather than trusting arrival.
function sortVersions(list) {
  return list.slice().sort((a, b) => {
    if (Boolean(a.is_original) !== Boolean(b.is_original)) return a.is_original ? -1 : 1;
    const at = new Date(a.created_at || 0).getTime();
    const bt = new Date(b.created_at || 0).getTime();
    if (at !== bt) return at - bt;
    return String(a.id).localeCompare(String(b.id));
  });
}

function versionsByCapture(list) {
  const map = {};
  (Array.isArray(list) ? list : []).forEach((v) => {
    const cid = v && v.capture_id ? String(v.capture_id) : '';
    if (!cid) return; // typed from scratch, belongs to no capture in any flow
    if (!map[cid]) map[cid] = [];
    map[cid].push(v);
  });
  Object.keys(map).forEach((cid) => { map[cid] = sortVersions(map[cid]); });
  return map;
}

// THE ONE RULE that decides which bytes a step sends, used by the run AND by the editor so the two
// can never disagree on screen:
//
//   1. whatever the operator explicitly picked in the version picker for this request, else
//   2. the NEWEST saved edit, because an operator who edited and moved on meant the edit, else
//   3. the original as captured.
//
// Rule 2 is the important one. Defaulting to the original would mean an operator who edited three
// requests and pressed Run watched the target receive the unedited bytes with nothing on screen
// saying so.
function chooseVersion(list, explicitId) {
  const rows = Array.isArray(list) ? list : [];
  if (explicitId) {
    const picked = rows.find((v) => v && String(v.id) === String(explicitId));
    if (picked) return picked;
  }
  const edits = rows.filter((v) => v && !v.is_original);
  if (edits.length) return edits[edits.length - 1];
  return rows.find((v) => v && v.is_original) || rows[0] || null;
}

/* ------------------------------------------------------------- run result reading */

// Everything below reads the run payload defensively. This modal and the run endpoint were built in
// parallel, so a field this does not recognise must never be quietly rendered as a reassuring
// default: an unrecognised state is shown VERBATIM and an unreadable payload raises a banner saying
// the run is happening but cannot be read here.

function firstOf(obj, keys) {
  for (let i = 0; i < keys.length; i += 1) {
    const v = obj ? obj[keys[i]] : undefined;
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

const SENT_WORDS = ['sent', 'ok', 'success', 'succeeded', 'done', 'complete', 'completed', 'responded'];
const SKIP_WORDS = ['skipped', 'skip', 'disarmed', 'excluded', 'not_sent', 'refused'];
const FAIL_WORDS = ['failed', 'fail', 'error', 'errored', 'timeout', 'timed_out'];
const RUNNING_WORDS = ['running', 'sending', 'in_flight', 'in_progress', 'active'];
const PENDING_WORDS = ['pending', 'queued', 'waiting', 'not_started', 'planned'];

function normalizeStepState(raw, statusCode) {
  const s = String(raw == null ? '' : raw).trim().toLowerCase();
  if (SENT_WORDS.includes(s)) return 'sent';
  if (SKIP_WORDS.includes(s)) return 'skipped';
  if (FAIL_WORDS.includes(s)) return 'failed';
  if (RUNNING_WORDS.includes(s)) return 'running';
  if (PENDING_WORDS.includes(s) || s === '') {
    // A step with a real status code is a step that was answered, whatever it is still labelled.
    return Number(statusCode) > 0 ? 'sent' : 'pending';
  }
  return s; // unknown. Shown as the server worded it, never mapped onto something calmer.
}

// The first key that holds a real number. `status` is in both this list and the state list below,
// because a server can legitimately call the response code `status` OR call the step's own state
// `status`, and reading one as the other turns every step into a wrong colour. Numbers here, words
// there, and neither list steals from the other.
function numberOf(obj, keys) {
  for (let i = 0; i < keys.length; i += 1) {
    const v = obj ? obj[keys[i]] : undefined;
    if (v === undefined || v === null || v === '') continue;
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return 0;
}

function stateOf(step, statusCode) {
  // THE RUN ENDPOINT'S OWN SHAPE FIRST. A DetectedFlowRunStep carries no state word at all: it says
  // what happened through will_send, skip_reason, executed and error. Reading only a word left every
  // refused step painted "pending" for the life of the run, and a run that skipped 33 subresources
  // showed 33 requests apparently still queued after it had finished.
  if (step && typeof step.will_send === 'boolean' && !step.will_send && !step.executed) {
    // "not_reached" is the run stopping before it got here. That is not the same thing as a request
    // the plan deliberately left out, and painting them with one word would hide the stop.
    return String(step.skip_reason || '') === 'not_reached' ? 'never_ran' : 'skipped';
  }
  if (step && step.error) return 'failed';
  if (step && step.executed === true) return Number(statusCode) > 0 ? 'sent' : 'running';

  const keys = ['state', 'outcome', 'result', 'step_status', 'status_text', 'status'];
  for (let i = 0; i < keys.length; i += 1) {
    const v = step ? step[keys[i]] : undefined;
    if (v === undefined || v === null || v === '' || typeof v === 'number') continue;
    const text = String(v).trim();
    if (text === '' || /^\d+$/.test(text)) continue;
    return normalizeStepState(text, statusCode);
  }
  return normalizeStepState('', statusCode);
}

// Turns the run payload into { status, steps: [...], byCapture, counts, ... }. `readable` is false
// when there is no per-step array to be found at all, which is a wiring problem the operator has to
// be told about rather than a run with nothing in it.
function readRunPayload(data) {
  const raw = data || {};
  // The run report nests its counts, its caps and its rules under `plan`, and carries the live step
  // list at the top level (the server strips the plan's own copy on the wire so a 50-step flow is
  // not serialised twice on every poll). Both are searched, top level first.
  const planPart = raw.plan && typeof raw.plan === 'object' ? raw.plan : {};
  const status = String(firstOf(raw, ['status', 'state', 'run_status']) || '').trim().toLowerCase();
  const rawSteps = firstOf(raw, ['steps', 'results', 'step_results', 'executions', 'outcomes']);
  const readable = Array.isArray(rawSteps);

  const steps = (readable ? rawSteps : []).map((s, i) => {
    const captureId = String(firstOf(s, [
      'capture_id', 'captureId', 'source_capture_id', 'node_id', 'nodeId', 'id',
    ]) || '');
    const statusCode = numberOf(s, ['status_code', 'statusCode', 'response_status', 'status']);
    return {
      key: `${captureId || 'step'}-${i}`,
      index: numberOf(s, ['index', 'order', 'step_order']) || (i + 1),
      captureId,
      state: stateOf(s, statusCode),
      statusCode,
      durationMs: numberOf(s, ['duration_ms', 'durationMs', 'elapsed_ms']),
      sizeBytes: numberOf(s, ['response_bytes', 'size_bytes', 'response_size', 'size', 'bytes']),
      error: String(firstOf(s, ['error', 'error_message', 'message', 'failure']) || ''),
      // skip_detail is the SENTENCE and skip_reason is the code. The sentence is what an operator
      // can act on, so it is preferred and the code is kept beside it for grouping.
      reason: String(firstOf(s, ['skip_detail', 'reason', 'skip_reason', 'skipped_reason', 'why']) || ''),
      reasonCode: String(firstOf(s, ['skip_reason', 'skipped_reason']) || ''),
      versionId: String(firstOf(s, ['version_id', 'versionId']) || ''),
      method: String(firstOf(s, ['method']) || ''),
      url: String(firstOf(s, ['url', 'path']) || ''),
    };
  });

  // Executions, not definitions. A linear detected-flow run is one execution per request, but if the
  // server ever reports a capture twice the LAST one is the current truth and the repeat is counted
  // so it can be said out loud rather than silently collapsed.
  const byCapture = {};
  let repeats = 0;
  steps.forEach((s) => {
    if (!s.captureId) return;
    if (byCapture[s.captureId]) repeats += 1;
    byCapture[s.captureId] = s;
  });

  const counts = { sent: 0, skipped: 0, failed: 0, running: 0, pending: 0, other: 0 };
  steps.forEach((s) => {
    if (counts[s.state] === undefined) counts.other += 1;
    else counts[s.state] += 1;
  });

  // TWO FIELDS, not one. `stopped_by` is the machine code for the cap that fired
  // (max_executed_steps, per_step_execution_cap, engagement_request_budget, stop_on_error,
  // cancelled) and `stopped_detail` is the sentence that names it in words. The sentence is what
  // gets shown; the code is kept so it can be shown beside it rather than translated here into
  // something the server did not say.
  const stopCode = String(firstOf(raw, [
    'stopped_by', 'stopped_reason', 'stop_reason', 'abort_reason', 'cap_hit', 'halt_reason',
    'ended_reason',
  ]) || '');
  const stopDetail = String(firstOf(raw, ['stopped_detail', 'stop_detail']) || '');
  const stopReason = stopDetail || stopCode;

  return {
    readable,
    status,
    terminal: RUN_TERMINAL_STATUSES.includes(status),
    // A status word neither list recognises is NOT quietly treated as finished. The modal keeps
    // polling and keeps the Send button locked, because concluding "it must be done" and letting a
    // second run start on top of a first is the failure that actually costs something.
    unrecognisedStatus: status !== ''
      && !RUN_LIVE_STATUSES.includes(status)
      && !RUN_TERMINAL_STATUSES.includes(status),
    steps,
    byCapture,
    repeats,
    counts,
    stopReason,
    stopCode,
    // Server-reported totals win over what can be counted from the step list: the server knows about
    // executions this browser may never have polled. The last two live under `plan`.
    sentTotal: Number(firstOf(raw, ['sent', 'requests_sent', 'executed'])),
    skippedTotal: Number(firstOf(planPart, ['skipped', 'skipped_count'])),
    plannedTotal: Number(firstOf(planPart, ['planned', 'request_count', 'total_steps'])),
    startedAt: firstOf(raw, ['started_at', 'startedAt']),
    completedAt: firstOf(raw, ['completed_at', 'finished_at', 'completedAt']),
    lastError: String(firstOf(raw, ['last_error', 'error']) || ''),
  };
}

// The dry run answers in the SAME envelope a real run does: the counts, the caps and the rules sit
// under `plan`, and the ordered step list sits at the top level because the server strips the plan's
// own copy of it on the wire. Flattened once, here, so nothing downstream has to know that.
function readPlanPayload(data) {
  const raw = data || {};
  const planPart = raw.plan && typeof raw.plan === 'object' ? raw.plan : {};
  const steps = Array.isArray(raw.steps) ? raw.steps
    : (Array.isArray(planPart.steps) ? planPart.steps : []);
  return { ...planPart, steps };
}

function elapsedText(startedAt, completedAt, fallbackStartMs) {
  let start = startedAt ? new Date(startedAt).getTime() : NaN;
  if (Number.isNaN(start)) start = fallbackStartMs || NaN;
  if (!start || Number.isNaN(start)) return null;
  let end = completedAt ? new Date(completedAt).getTime() : NaN;
  if (Number.isNaN(end)) end = Date.now();
  if (end < start) return null;
  return formatDuration(end - start);
}

/* --------------------------------------------------------------------- components */

// Passive and Active are single pills. BOTH is a two-segment pill, because it is the interesting
// one: it says the route was seen in a browser AND reproduced by the scanner, which is two facts,
// and a third grey pill would bury the one row an operator actually wants to find.
const SourceBadge = ({ source }) => {
  if (source === SOURCE_BOTH) {
    return (
      <span
        className="d-inline-flex align-items-center rounded overflow-hidden me-1 align-middle"
        style={{ fontSize: '0.56rem', border: '1px solid #dc3545', lineHeight: 1.7 }}
        title={SOURCE_TITLES[SOURCE_BOTH]}
      >
        <span style={{ background: '#495057', color: '#e9ecef', padding: '0 5px' }}>
          <i className="bi bi-eye me-1" />
          passive
        </span>
        <span style={{ background: '#dc3545', color: '#fff', fontWeight: 700, padding: '0 5px' }}>
          <i className="bi bi-broadcast-pin me-1" />
          active
        </span>
      </span>
    );
  }
  if (source === SOURCE_ACTIVE) {
    return (
      <span
        className="badge bg-dark border border-danger text-danger me-1"
        style={{ fontSize: '0.6rem' }}
        title={SOURCE_TITLES[SOURCE_ACTIVE]}
      >
        <i className="bi bi-broadcast-pin me-1" />
        Active
      </span>
    );
  }
  if (source === SOURCE_PASSIVE) {
    return (
      <span
        className="badge bg-dark border border-secondary text-white-50 me-1"
        style={{ fontSize: '0.6rem' }}
        title={SOURCE_TITLES[SOURCE_PASSIVE]}
      >
        <i className="bi bi-eye me-1" />
        Passive
      </span>
    );
  }
  return null;
};

const DetailRow = ({ label, mono, children }) => (
  <div className="d-flex mb-1" style={{ fontSize: '0.72rem' }}>
    <div className="text-white-50 flex-shrink-0" style={{ width: '86px' }}>{label}</div>
    <div
      className="text-white"
      style={{ minWidth: 0, wordBreak: 'break-all', fontFamily: mono ? MONO : undefined }}
    >
      {children}
    </div>
  </div>
);

// The result pill that gets posted into a node's status badge.
//
// RequestFlowChart is shared and not owned by this file, and it has no prop for run results. The one
// channel it renders straight from node data is `node.status_code`, which it drops into a badge as
// {node.status_code || '?'}. React renders an element there perfectly well, so a result that has no
// status number travels down that channel as this element instead. The negative margins are the
// badge's own padding (.35em .65em), so the pill covers the grey badge exactly rather than sitting
// as a second pill inside the first. Anything numeric is passed as a plain number, so a real status
// code keeps the chart's own 2xx/3xx/4xx/5xx colouring.
//
// One consequence, stated because it is visible: a redirect connector labels itself "302 redirect"
// from its PARENT's status_code, and a parent painted with one of these elements has no number to
// read, so its connector says "redirect" alone while the graph is in run mode. That only happens for
// steps this run did not send, where there is no run status to label it with anyway.
function runStateBadge(paintKey, overrideWord) {
  const paint = RUN_STATE_PAINT[paintKey] || { bg: '#495057', fg: '#ffffff', word: paintKey };
  return (
    <span
      style={{
        display: 'inline-block',
        margin: '-0.35em -0.65em',
        padding: '0.35em 0.65em',
        borderRadius: 'inherit',
        background: paint.bg,
        color: paint.fg,
        fontWeight: 700,
        letterSpacing: '0.02em',
      }}
    >
      {overrideWord || paint.word}
    </span>
  );
}

const RunLegendChip = ({ item }) => {
  if (item.key === 'sent') {
    return (
      <span className="d-inline-flex align-items-center me-3" title={item.hint}>
        <span className="badge bg-success me-1" style={{ fontSize: '0.55rem' }}>200</span>
        <span className="text-white-50" style={{ fontSize: '0.64rem' }}>{item.label}</span>
      </span>
    );
  }
  const paint = RUN_STATE_PAINT[item.key];
  return (
    <span className="d-inline-flex align-items-center me-3" title={item.hint}>
      <span
        className="me-1"
        style={{
          background: paint.bg,
          color: paint.fg,
          fontSize: '0.55rem',
          fontWeight: 700,
          borderRadius: 3,
          padding: '1px 5px',
        }}
      >
        {paint.word}
      </span>
    </span>
  );
};

export const RequestFlowsModal = ({
  show,
  handleClose,
  activeTarget,
  onOpenInRepeater,
  onEditAsFlow,
}) => {
  const targetId = activeTarget && activeTarget.id;

  // Flow list.
  const [flowQuery, setFlowQuery] = useState('');
  const [flows, setFlows] = useState([]);
  const [flowSources, setFlowSources] = useState(null);
  const [flowsTotal, setFlowsTotal] = useState(0);
  const [flowsTruncated, setFlowsTruncated] = useState(false);
  const [flowsError, setFlowsError] = useState('');
  const [flowsSearching, setFlowsSearching] = useState(false);
  const [flowsLoaded, setFlowsLoaded] = useState(false);
  const flowsSeq = useRef(0);

  // Selected flow and its graph.
  const [selectedFlowId, setSelectedFlowId] = useState(null);
  const [flowDetail, setFlowDetail] = useState(null);
  const [flowDetailError, setFlowDetailError] = useState('');
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [showAllResources, setShowAllResources] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const detailSeq = useRef(0);

  // The editor for the selected request.
  const [editorCaptureId, setEditorCaptureId] = useState(null);
  const [editorLoading, setEditorLoading] = useState(false);
  const [editorError, setEditorError] = useState('');
  const [versions, setVersions] = useState([]);
  const [versionsAvailable, setVersionsAvailable] = useState(true);
  const [versionsNote, setVersionsNote] = useState('');
  const [selectedVersionId, setSelectedVersionId] = useState('');
  const [draft, setDraft] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [saveNotice, setSaveNotice] = useState('');
  const editorSeq = useRef(0);

  // Which bytes each request in the flow will send. `flowVersions` is every version this target has,
  // grouped by capture, so the run can be described without opening each request one at a time.
  // `versionChoice` is only the operator's EXPLICIT picks; everything else falls through to
  // chooseVersion, and the two are kept apart so a default never masquerades as a decision.
  const [flowVersions, setFlowVersions] = useState(null);
  const [flowVersionsError, setFlowVersionsError] = useState('');
  const [versionChoice, setVersionChoice] = useState({});
  // Read by loadEditor, which must not be rebuilt every time an unrelated request's version pick
  // changes: rebuilding it re-runs the load and throws away whatever bytes are in the textarea.
  const versionChoiceRef = useRef({});
  useEffect(() => { versionChoiceRef.current = versionChoice; }, [versionChoice]);

  // The run.
  const [runPanelOpen, setRunPanelOpen] = useState(false);
  const [skipStateChanging, setSkipStateChanging] = useState(false);
  const [plan, setPlan] = useState(null);
  const [planKey, setPlanKey] = useState('');
  const [planError, setPlanError] = useState('');
  const [planning, setPlanning] = useState(false);
  const [planShowAllSteps, setPlanShowAllSteps] = useState(false);
  const planSeq = useRef(0);

  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState('');
  const [runId, setRunId] = useState('');
  const [runFlowId, setRunFlowId] = useState('');
  const [runFlowLabel, setRunFlowLabel] = useState('');
  const [run, setRun] = useState(null);
  const [runPollError, setRunPollError] = useState('');
  const [graphShowsRun, setGraphShowsRun] = useState(true);
  const [cancelling, setCancelling] = useState(false);
  const [cancelNotice, setCancelNotice] = useState('');
  const runStartedAtRef = useRef(0);

  // Promoting the flow into the builder.
  const [promoting, setPromoting] = useState(false);
  const [promoteError, setPromoteError] = useState('');
  const [promoteNotice, setPromoteNotice] = useState('');

  // Fresh open, fresh state, and the same on a target switch. Every piece of it: a version list left
  // over from another target would offer to parent an edit onto a request from somewhere else.
  useEffect(() => {
    setFlowQuery('');
    setFlows([]);
    setFlowSources(null);
    setFlowsTotal(0);
    setFlowsTruncated(false);
    setFlowsError('');
    setFlowsLoaded(false);
    setSelectedFlowId(null);
    setFlowDetail(null);
    setFlowDetailError('');
    setShowAllResources(false);
    setSelectedNodeId(null);
    setEditorCaptureId(null);
    setEditorError('');
    setVersions([]);
    setVersionsAvailable(true);
    setVersionsNote('');
    setSelectedVersionId('');
    setDraft('');
    setBaseUrl('');
    setSaveError('');
    setSaveNotice('');
    setFlowVersions(null);
    setFlowVersionsError('');
    setVersionChoice({});
    setRunPanelOpen(false);
    setSkipStateChanging(false);
    setPlan(null);
    setPlanKey('');
    setPlanError('');
    setPlanShowAllSteps(false);
    setStartError('');
    setRunId('');
    setRunFlowId('');
    setRunFlowLabel('');
    setRun(null);
    setRunPollError('');
    setGraphShowsRun(true);
    setPromoteError('');
    setPromoteNotice('');
    runStartedAtRef.current = 0;
  }, [show, targetId]);

  /* ------------------------------------------------------------------ flows */

  const runFlowSearch = useCallback(async (text) => {
    if (!targetId) return;
    const seq = flowsSeq.current + 1;
    flowsSeq.current = seq;
    setFlowsSearching(true);
    try {
      const { ok, status, data, body } = await requestJSON(
        `/api/replay-request/${targetId}/flows?q=${encodeURIComponent(text)}&limit=${FLOW_LIMIT}`
      );
      if (seq !== flowsSeq.current) return;

      // A query the parser cannot read keeps the previous list on screen. Blanking it would make a
      // syntax error look like a search that matched nothing.
      if (!ok) {
        setFlowsError(errorMessage(data, body, status));
        return;
      }
      if (data && typeof data.error === 'string' && data.error) {
        setFlowsError(data.error);
        return;
      }
      const rows = Array.isArray(data && data.flows) ? data.flows : [];
      setFlows(rows);
      setFlowSources(data && typeof data.detection_sources === 'object' ? data.detection_sources : null);
      setFlowsTotal(Number.isFinite(Number(data && data.total)) ? Number(data.total) : rows.length);
      setFlowsTruncated(Boolean(data && data.truncated));
      setFlowsError('');
      setFlowsLoaded(true);
    } catch (err) {
      if (seq === flowsSeq.current) setFlowsError(`Could not reach the framework: ${err.message}`);
    } finally {
      if (seq === flowsSeq.current) setFlowsSearching(false);
    }
  }, [targetId]);

  // Debounced, because the box is a live filter over the whole capture corpus.
  useEffect(() => {
    if (!show || !targetId) return undefined;
    const timer = setTimeout(() => { runFlowSearch(flowQuery); }, 300);
    return () => clearTimeout(timer);
  }, [show, targetId, flowQuery, runFlowSearch]);

  // The graph for the selected flow. No query goes with it: the endpoint has no filter parameter
  // because a partially filtered flow is not the flow.
  useEffect(() => {
    if (!show || !selectedFlowId) return;
    const seq = detailSeq.current + 1;
    detailSeq.current = seq;
    setLoadingDetail(true);
    (async () => {
      try {
        const { ok, status, data, body } = await requestJSON(
          `/api/replay-request/flow/${encodeURIComponent(selectedFlowId)}?show_all=${showAllResources}`
        );
        if (seq !== detailSeq.current) return;

        if (!ok || !data || !Array.isArray(data.nodes)) {
          setFlowDetailError(errorMessage(data, body, status));
          // A failed toggle must not destroy a graph that is already right. A failed load of a
          // DIFFERENT flow must not leave the previous one on screen pretending to be it.
          setFlowDetail((prev) => (
            prev && prev.flow && prev.flow.id === selectedFlowId ? prev : null
          ));
          return;
        }
        setFlowDetail(data);
        setFlowDetailError('');
      } catch (err) {
        if (seq === detailSeq.current) {
          setFlowDetailError(`Could not reach the framework: ${err.message}`);
        }
      } finally {
        if (seq === detailSeq.current) setLoadingDetail(false);
      }
    })();
  }, [show, selectedFlowId, showAllResources]);

  const selectFlow = (flowId) => {
    if (flowId === selectedFlowId) return;
    setSelectedFlowId(flowId);
    setSelectedNodeId(null);
    setFlowDetailError('');
    // The plan belongs to the flow it was computed for. Carrying it across would put a request count
    // for one flow under the Send button of another.
    setPlan(null);
    setPlanKey('');
    setPlanError('');
    setPlanShowAllSteps(false);
    setStartError('');
    setRunPanelOpen(false);
    setPromoteError('');
    setPromoteNotice('');
  };

  /* --------------------------------------------------------------- versions */

  // Every version this target has, in one call. The endpoint returns the whole set when it is asked
  // without a capture_id, which is what makes "which bytes will each of these 20 requests send" a
  // question answerable before the run rather than one request at a time.
  const loadFlowVersions = useCallback(async () => {
    if (!targetId) return;
    try {
      const { ok, status, data, body } = await requestJSON(
        `/api/replay-request/${targetId}/versions`
      );
      if (!ok || !data || !Array.isArray(data.versions)) {
        setFlowVersions({ byCapture: {}, count: 0 });
        setFlowVersionsError(errorMessage(data, body, status));
        return;
      }
      setFlowVersions({ byCapture: versionsByCapture(data.versions), count: data.versions.length });
      setFlowVersionsError('');
    } catch (err) {
      setFlowVersions({ byCapture: {}, count: 0 });
      setFlowVersionsError(`Could not read your saved edits: ${err.message}`);
    }
  }, [targetId]);

  useEffect(() => {
    if (!show || !targetId) return;
    loadFlowVersions();
  }, [show, targetId, loadFlowVersions]);

  // Folds a version list for one capture into the target-wide map, so the editor and the run never
  // hold two different opinions about what exists.
  const mergeVersions = useCallback((captureId, list) => {
    setFlowVersions((prev) => {
      const byCapture = { ...((prev && prev.byCapture) || {}) };
      byCapture[String(captureId)] = sortVersions(Array.isArray(list) ? list : []);
      let count = 0;
      Object.keys(byCapture).forEach((k) => { count += byCapture[k].length; });
      return { byCapture, count };
    });
  }, []);

  /* ----------------------------------------------------------------- editor */

  // Loads the selected request's bytes and its version tree together.
  //
  // The GET on /versions is not a read-only call by accident of implementation: it MATERIALISES the
  // capture's original if it does not exist yet, which is how the immutable "this is what the target
  // actually sent" row comes into being. That is why the editor asks for it on selection rather than
  // on the first save.
  const loadEditor = useCallback(async (captureId) => {
    if (!targetId || !captureId) return;
    const seq = editorSeq.current + 1;
    editorSeq.current = seq;

    setEditorLoading(true);
    setEditorError('');
    setSaveError('');
    setSaveNotice('');
    setVersionsNote('');

    let rawResult = null;
    let versionResult = null;
    try {
      [rawResult, versionResult] = await Promise.all([
        requestJSON(`/api/replay-request/capture/${encodeURIComponent(captureId)}/raw`),
        requestJSON(`/api/replay-request/${targetId}/versions?capture_id=${encodeURIComponent(captureId)}`),
      ]);
    } catch (err) {
      if (seq !== editorSeq.current) return;
      setEditorError(`Could not reach the framework: ${err.message}`);
      setEditorLoading(false);
      return;
    }
    if (seq !== editorSeq.current) return;

    if (!rawResult.ok || !rawResult.data) {
      setEditorError(errorMessage(rawResult.data, rawResult.body, rawResult.status));
      setVersions([]);
      setSelectedVersionId('');
      setDraft('');
      setBaseUrl('');
      setEditorLoading(false);
      return;
    }

    const capture = rawResult.data;
    let list = [];
    let available = true;
    let note = '';

    if (versionResult.ok && versionResult.data && Array.isArray(versionResult.data.versions)) {
      list = sortVersions(versionResult.data.versions);
      mergeVersions(captureId, list);
    } else if (versionResult.status === 404 && !(versionResult.data && versionResult.data.error)) {
      // The route is not registered on this build. Said plainly, because "Request failed (404)" over
      // an editor reads as "your request is broken" rather than "this server cannot save versions".
      available = false;
      note = 'This server build does not expose the request version API '
        + '(/replay-request/{target}/versions), so edits here cannot be saved. The bytes below are '
        + 'the request as it was captured and are still yours to read and copy.';
    } else {
      available = false;
      note = `The version list could not be read: ${errorMessage(versionResult.data, versionResult.body, versionResult.status)}`;
    }

    // Opens on the version THE RUN WOULD SEND, not unconditionally on the original. The editor and
    // the run share chooseVersion for exactly this reason: an editor sitting on "Original" while the
    // run is about to send an edit is a screen that lies about what will happen.
    const start = chooseVersion(list, versionChoiceRef.current[String(captureId)]) || null;

    setVersions(list);
    setVersionsAvailable(available);
    setVersionsNote(note);
    setSelectedVersionId(start ? String(start.id) : '');
    // Falls back to the capture's own bytes whenever there is no version row to start from, so the
    // editor is never empty for a request the graph is displaying.
    setDraft(start ? String(start.raw_request || '') : String(capture.raw_request || ''));
    setBaseUrl(start ? String(start.base_url || '') : String(capture.base_url || ''));
    setEditorLoading(false);
  }, [targetId, mergeVersions]);

  // Selection drives the editor. Cleared rather than left stale when nothing is selected: an editor
  // still holding the previous request's bytes would save an edit onto the wrong capture.
  useEffect(() => {
    if (!show) return;
    const id = selectedNodeId ? String(selectedNodeId) : null;
    setEditorCaptureId(id);
    if (!id) {
      editorSeq.current += 1;
      setEditorLoading(false);
      setEditorError('');
      setVersions([]);
      setVersionsAvailable(true);
      setVersionsNote('');
      setSelectedVersionId('');
      setDraft('');
      setBaseUrl('');
      setSaveError('');
      setSaveNotice('');
      return;
    }
    loadEditor(id);
  }, [show, selectedNodeId, loadEditor]);

  const selectedVersion = useMemo(() => (
    versions.find((v) => v && String(v.id) === String(selectedVersionId)) || null
  ), [versions, selectedVersionId]);

  // Same rule the server applies when it refuses a duplicate row: bytes compared in normalised form,
  // base_url compared trimmed. Computed here so an unchanged request never travels to the API just to
  // come back as a 409 the operator has to read.
  const dirty = useMemo(() => {
    if (!selectedVersion) return String(draft || '').trim() !== '';
    return normalizeVersionBytes(draft) !== normalizeVersionBytes(selectedVersion.raw_request)
      || String(baseUrl || '').trim() !== String(selectedVersion.base_url || '').trim();
  }, [draft, baseUrl, selectedVersion]);

  // Picking a version is a DECISION about what the run sends, not just about what is on screen, so it
  // is recorded in versionChoice and it invalidates any plan computed before it.
  const pickVersion = (versionId) => {
    const next = versions.find((v) => v && String(v.id) === String(versionId));
    if (!next) return;
    setSelectedVersionId(String(next.id));
    setDraft(String(next.raw_request || ''));
    setBaseUrl(String(next.base_url || ''));
    setSaveError('');
    setSaveNotice('');
    if (editorCaptureId) {
      setVersionChoice((prev) => ({ ...prev, [String(editorCaptureId)]: String(next.id) }));
    }
  };

  const revertDraft = () => {
    if (!selectedVersion) return;
    setDraft(String(selectedVersion.raw_request || ''));
    setBaseUrl(String(selectedVersion.base_url || ''));
    setSaveError('');
    setSaveNotice('');
  };

  // Save is always "save as a new version", never an overwrite. The version it was edited from is
  // sent as parent_version_id, so the history stays a tree and the original stays reachable. The
  // server generates the label from the diff; nothing is invented here.
  const saveVersion = async () => {
    if (!targetId || !editorCaptureId || saving) return;
    setSaving(true);
    setSaveError('');
    setSaveNotice('');
    try {
      const { ok, status, data, body } = await requestJSON(
        `/api/replay-request/${targetId}/versions`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            capture_id: editorCaptureId,
            parent_version_id: selectedVersionId || '',
            raw_request: draft,
            base_url: baseUrl,
          }),
        }
      );

      if (ok && data && data.id) {
        const next = sortVersions([
          ...versions.filter((v) => v && String(v.id) !== String(data.id)),
          data,
        ]);
        setVersions(next);
        setSelectedVersionId(String(data.id));
        setDraft(String(data.raw_request || ''));
        setBaseUrl(String(data.base_url || ''));
        // A saved edit is what the run must send, and the plan on screen was computed before it
        // existed. Both facts recorded here, in one place.
        mergeVersions(editorCaptureId, next);
        setVersionChoice((prev) => ({ ...prev, [String(editorCaptureId)]: String(data.id) }));
        setSaveNotice(`Saved as a new version: "${data.label || 'edited'}". This is now the version a `
          + 'run of this flow will send for this request.');
        return;
      }

      // 409 identical_to_parent is not a failure and must not read like one. The operator's bytes are
      // already saved, under the version they were edited from, and that version is selected for them.
      if (status === 409 && data && data.error === 'identical_to_parent') {
        setSaveNotice(data.message || 'That is byte-identical to the version it was edited from, so no new version was created.');
        if (data.existing && data.existing.id) {
          const next = sortVersions(
            versions.some((v) => v && String(v.id) === String(data.existing.id))
              ? versions
              : [...versions, data.existing]
          );
          setVersions(next);
          setSelectedVersionId(String(data.existing.id));
          setDraft(String(data.existing.raw_request || ''));
          setBaseUrl(String(data.existing.base_url || ''));
          mergeVersions(editorCaptureId, next);
          setVersionChoice((prev) => ({ ...prev, [String(editorCaptureId)]: String(data.existing.id) }));
        }
        return;
      }

      setSaveError(errorMessage(data, body, status));
    } catch (err) {
      setSaveError(`Could not reach the framework: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  /* ------------------------------------------------------------------ derived */

  // Memoised off flowDetail rather than rebuilt inline, so a re-render for an unrelated reason
  // cannot hand the chart new array identities and make it lay the whole tree out again.
  const nodes = useMemo(() => (
    flowDetail && Array.isArray(flowDetail.nodes) ? flowDetail.nodes : EMPTY_LIST
  ), [flowDetail]);
  const edges = useMemo(() => (
    flowDetail && Array.isArray(flowDetail.edges) ? flowDetail.edges : EMPTY_LIST
  ), [flowDetail]);
  const flowSummary = (flowDetail && flowDetail.flow) || null;

  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null;
    return nodes.find((n) => n && String(n.id) === String(selectedNodeId)) || null;
  }, [nodes, selectedNodeId]);

  // One line at the top of the list rather than a mystery pill on every row: if this build's flows
  // endpoint does not report a source, say so once and badge nothing.
  const anySourceReported = useMemo(
    () => flows.some((flow) => detectionSourceOf(flow, flowSources) !== ''),
    [flows, flowSources]
  );

  const selectedFlowSource = useMemo(() => {
    const row = flows.find((f) => f && f.id === selectedFlowId);
    return detectionSourceOf(row, flowSources);
  }, [flows, flowSources, selectedFlowId]);

  /* ------------------------------------------------- what this run would send */

  // Per node: which version its bytes come from, and whether that is an edit or the capture.
  const sendPlan = useMemo(() => {
    const byCapture = (flowVersions && flowVersions.byCapture) || {};
    return nodes.map((node) => {
      const captureId = String(node.id);
      const list = byCapture[captureId] || [];
      const chosen = chooseVersion(list, versionChoice[captureId]);
      const edited = Boolean(chosen && !chosen.is_original);
      return {
        captureId,
        node,
        version: chosen,
        versionId: chosen ? String(chosen.id) : '',
        edited,
        explicit: Boolean(versionChoice[captureId]),
      };
    });
  }, [nodes, flowVersions, versionChoice]);

  const sendPlanByCapture = useMemo(() => {
    const map = {};
    sendPlan.forEach((row) => { map[row.captureId] = row; });
    return map;
  }, [sendPlan]);

  const editedCount = useMemo(
    () => sendPlan.filter((row) => row.edited).length,
    [sendPlan]
  );

  // The identity of everything that decides what a run would do. The Send button is only unlocked
  // for a plan whose key matches this, which is what makes "edit a request after the dry run" put
  // the gate back up instead of sending bytes nobody previewed.
  const configKey = useMemo(() => JSON.stringify({
    flow: selectedFlowId || '',
    all: Boolean(showAllResources),
    skipWrites: Boolean(skipStateChanging),
    steps: sendPlan.map((row) => `${row.captureId}:${row.versionId}`),
  }), [selectedFlowId, showAllResources, skipStateChanging, sendPlan]);

  // THE ONLY WAY AN EDIT REACHES THE TARGET.
  //
  // The run endpoint takes `overrides`, a map of capture id to the raw bytes to send, and it reads
  // nothing else: it never looks at replay_request_versions and there is no version_id at the far
  // end. So the chosen version's bytes are sent here in full. A request with no saved edit is left
  // out entirely, which is not a shortcut - the server then sends the capture's own bytes, and those
  // are the same bytes.
  //
  // An empty edit is passed through rather than filtered out. The server answers it with a 400 that
  // names the capture, which is the right outcome: dropping it would silently send the recording in
  // place of what the operator wrote.
  const overridesPayload = useMemo(() => {
    const out = {};
    sendPlan.forEach((row) => {
      if (!row.edited || !row.version) return;
      out[row.captureId] = String(row.version.raw_request == null ? '' : row.version.raw_request);
    });
    return out;
  }, [sendPlan]);

  /* ------------------------------------------------------------- the dry run */

  const runDryRun = useCallback(async () => {
    if (!selectedFlowId) return;
    const key = configKey;
    const seq = planSeq.current + 1;
    planSeq.current = seq;
    setPlanning(true);
    setPlanError('');
    try {
      const url = runURL(selectedFlowId);
      const { ok, status, data, body } = await requestJSON(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dry_run: true,
          include_all: Boolean(showAllResources),
          skip_state_changing: Boolean(skipStateChanging),
          overrides: overridesPayload,
        }),
      });
      if (seq !== planSeq.current) return;
      if (!ok || !data) {
        // The plan is dropped, not kept and re-labelled. A refused configuration has no plan, and
        // leaving the last one on screen next to a disabled button invites the operator to believe
        // they are looking at what would be sent.
        setPlan(null);
        setPlanKey('');
        setPlanError(routeErrorMessage(url, data, body, status));
        return;
      }
      setPlan(readPlanPayload(data));
      setPlanKey(key);
      setPlanError('');
      setPlanShowAllSteps(false);
    } catch (err) {
      if (seq === planSeq.current) {
        setPlan(null);
        setPlanKey('');
        setPlanError(`Could not reach the framework: ${err.message}`);
      }
    } finally {
      if (seq === planSeq.current) setPlanning(false);
    }
  }, [selectedFlowId, showAllResources, skipStateChanging, overridesPayload, configKey]);

  // Opening the run panel IS the dry run. There is no path through this modal that starts by
  // sending, and the button that opens the panel is not the button that sends.
  const openRunPanel = () => {
    if (!selectedFlowId) return;
    setRunPanelOpen(true);
    setStartError('');
    // Picks up edits saved from anywhere else since this modal opened, so the plan describes the
    // bytes that exist now.
    loadFlowVersions();
    runDryRun();
  };

  // Any change to the configuration invalidates the plan, exactly as it does in Detect Flows.
  const planIsForThisConfig = Boolean(plan) && planKey === configKey;

  // The count of requests the run would send. Read from the plan when the server reports one, and
  // otherwise not invented: an unknown count shows as unknown rather than as the node count, which
  // would be this modal guessing on the server's behalf.
  const plannedCount = useMemo(() => {
    if (!plan) return null;
    const n = Number(firstOf(plan, ['request_count', 'planned', 'will_send', 'send_count']));
    return Number.isFinite(n) ? n : null;
  }, [plan]);

  const planSteps = useMemo(() => {
    if (!plan) return [];
    const rows = firstOf(plan, ['steps', 'targets', 'requests', 'plan']);
    if (!Array.isArray(rows)) return [];
    return rows.map((s, i) => {
      const captureId = String(firstOf(s, ['capture_id', 'captureId', 'node_id', 'id']) || '');
      const skipReason = String(firstOf(s, ['skip_reason', 'skipped_reason', 'reason']) || '');
      const willSend = (() => {
        const explicit = firstOf(s, ['will_send', 'send', 'enabled']);
        if (typeof explicit === 'boolean') return explicit;
        const skipped = firstOf(s, ['skipped', 'skip']);
        if (typeof skipped === 'boolean') return !skipped;
        return skipReason === '';
      })();
      return {
        key: `${captureId || 'plan'}-${i}`,
        index: Number(firstOf(s, ['order', 'index', 'step_order'])) || (i + 1),
        captureId,
        method: String(firstOf(s, ['method']) || ''),
        url: String(firstOf(s, ['url', 'path']) || ''),
        willSend,
        skipReason,
        // The code says which rule refused it; the sentence says why, and the server writes one for
        // every single skip. Both are carried so the row can be short and its tooltip complete.
        skipDetail: String(firstOf(s, ['skip_detail', 'skip_pattern']) || ''),
      };
    });
  }, [plan]);

  const planSkipped = useMemo(() => planSteps.filter((s) => !s.willSend), [planSteps]);

  const planSkippedByCapture = useMemo(() => {
    const map = {};
    planSkipped.forEach((s) => { if (s.captureId) map[s.captureId] = s; });
    return map;
  }, [planSkipped]);

  // The caps the server will actually judge this run against. `step_budget` is its name for the
  // executed-step budget; `budget_source` says WHOSE number it is, which matters because "default"
  // and "engagement" call for different actions from the operator when a run stops on it.
  //
  // There is no per-step cap or retry cap here on purpose: a detected flow is linear, so those are 1
  // and 0 and the server does not report them. They read as null and are not rendered, rather than
  // being invented from the builder's numbers, which belong to a different runner.
  const planCaps = useMemo(() => {
    if (!plan) return null;
    const maxSteps = Number(firstOf(plan, ['step_budget', 'max_executed_steps', 'max_steps']));
    const perStep = Number(firstOf(plan, ['per_step_execution_cap', 'max_per_step_executions', 'per_step_cap']));
    const retries = Number(firstOf(plan, ['max_retries', 'retry_cap']));
    const rps = Number(firstOf(plan, ['rps', 'requests_per_second']));
    const timeout = Number(firstOf(plan, ['timeout_s', 'timeout_seconds']));
    const seconds = Number(firstOf(plan, ['estimated_seconds', 'eta_seconds']));
    return {
      maxSteps: Number.isFinite(maxSteps) ? maxSteps : null,
      budgetSource: String(firstOf(plan, ['budget_source']) || ''),
      perStep: Number.isFinite(perStep) ? perStep : null,
      retries: Number.isFinite(retries) ? retries : null,
      rps: Number.isFinite(rps) ? rps : null,
      timeout: Number.isFinite(timeout) ? timeout : null,
      seconds: Number.isFinite(seconds) ? seconds : null,
    };
  }, [plan]);

  /* -------------------------------------------------------------- sending it */

  // Live means "started and not known to have finished". Deliberately NOT "the status word is in the
  // live list": a status this modal does not recognise leaves the run treated as running, so an
  // unknown word can never unlock the Send button underneath a run that is still going.
  const runIsLive = Boolean(runId) && !(run && run.terminal);

  // Send is pressable without a preview. The dry run stays one click away and the panel opens on it,
  // which is where its value is; making it a gate added a ceremony and no protection, since the
  // server judges every step again at send time from the same function the preview called.
  //
  // What still blocks: no flow chosen, and a run already in flight. Both are states in which there
  // is nothing coherent to send.
  const gateReason = useMemo(() => {
    if (!selectedFlowId) return 'Pick a flow first.';
    if (runIsLive) {
      return runFlowId && runFlowId !== selectedFlowId
        ? 'A run is already in progress on another flow. Wait for it to finish.'
        : 'A run is already in progress.';
    }
    return '';
  }, [selectedFlowId, runIsLive, runFlowId]);

  const canSend = gateReason === '' && !starting;

  const startRun = async () => {
    if (!canSend || !selectedFlowId) return;
    setStarting(true);
    setStartError('');
    setRunPollError('');
    setCancelNotice('');
    try {
      const url = runURL(selectedFlowId);
      const { ok, status, data, body } = await requestJSON(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dry_run: false,
          include_all: Boolean(showAllResources),
          skip_state_changing: Boolean(skipStateChanging),
          overrides: overridesPayload,
        }),
      });
      const id = data ? String(firstOf(data, ['run_id', 'runId', 'id']) || '') : '';
      if (!ok || !id) {
        setStartError(
          ok
            ? 'The run was accepted but no run_id came back, so its progress cannot be followed. '
              + 'Treat the flow as possibly sent and check the target before running it again.'
            : routeErrorMessage(url, data, body, status)
        );
        return;
      }
      runStartedAtRef.current = Date.now();
      setRunId(id);
      setRunFlowId(selectedFlowId);
      setRunFlowLabel((flowSummary && flowSummary.label) || '');
      setGraphShowsRun(true);
      // The 202 is an acknowledgement, not a result set. It is seeded with an EMPTY step list rather
      // than with whatever it happened to contain, so "no per-step list came back" cannot fire as a
      // wiring warning one tick after starting a run that simply has no results yet. The poll below
      // fires immediately and replaces this.
      setRun(readRunPayload({
        ...data,
        status: firstOf(data, ['status', 'state']) || 'running',
        steps: Array.isArray(firstOf(data, ['steps', 'results', 'step_results'])) ? data.steps : [],
      }));
    } catch (err) {
      setStartError(`Could not reach the framework: ${err.message}`);
    } finally {
      setStarting(false);
    }
  };

  // STOPPING A RUN IN FLIGHT.
  //
  // A run of a real flow is a sequence of requests to a live bug bounty target, paced at the
  // programme's rate, and it can be forty of them. Without this the operator who realises at request
  // three that they armed the state-changing box has no way to stop it from a screen that started
  // it, and closing the modal does not help: the run is on the server.
  //
  // The steps already sent are KEPT, which is the server's behaviour and worth saying: cancel is
  // usually pressed because something worth reading just appeared.
  const cancelRun = async () => {
    if (!runId || !runFlowId || cancelling) return;
    setCancelling(true);
    setCancelNotice('');
    try {
      const url = runCancelURL(runFlowId, runId);
      const { ok, status, data, body } = await requestJSON(url, { method: 'POST' });
      if (!ok) {
        setRunPollError(routeErrorMessage(url, data, body, status));
        return;
      }
      setCancelNotice((data && data.message)
        || 'Cancelling. The steps already sent are kept.');
    } catch (err) {
      setRunPollError(`Could not reach the framework: ${err.message}`);
    } finally {
      setCancelling(false);
    }
  };

  // Whether the run has finished, in a ref rather than read out of state inside the poll. `run` is a
  // new object on every tick, so an effect that depended on it would re-run, fire an immediate poll,
  // set state, and re-run again: a tight request loop against the framework, which is exactly the
  // shape of thing the caps in this feature exist to prevent.
  const runTerminalRef = useRef(false);
  useEffect(() => { runTerminalRef.current = Boolean(run && run.terminal); }, [run]);

  // Polls until the server calls it terminal. Keeps polling even if the operator selects a different
  // flow: the run exists on the server whatever this browser is looking at, and dropping the poll
  // would leave it finishing unobserved.
  useEffect(() => {
    if (!show || !runId || !runFlowId) return undefined;
    let stopped = false;
    let timer = null;
    const tick = async () => {
      if (stopped) return;
      try {
        const url = runStatusURL(runFlowId, runId);
        const { ok, status, data, body } = await requestJSON(url);
        if (stopped) return;
        if (!ok || !data) {
          setRunPollError(routeErrorMessage(url, data, body, status));
          return;
        }
        setRunPollError('');
        setRun(readRunPayload(data));
      } catch (err) {
        if (!stopped) setRunPollError(`Could not reach the framework: ${err.message}`);
      }
    };
    tick();
    timer = setInterval(() => {
      if (runTerminalRef.current) {
        clearInterval(timer);
        return;
      }
      tick();
    }, RUN_POLL_MS);
    return () => { stopped = true; clearInterval(timer); };
  }, [show, runId, runFlowId]);

  const runOnThisFlow = Boolean(runId) && runFlowId === selectedFlowId;

  // A terminal run that left requests THE PLAN SAID IT WOULD SEND unattempted, with no reason given.
  // This is the case the whole run panel exists to refuse to paper over: "flow ended" with nothing
  // said is how an operator concludes the target is broken when it was their own flow that stopped.
  //
  // Counted against the plan's own will-send list, never against every node in the graph. A flow
  // whose subresources were legitimately never in the run would otherwise raise this alarm on every
  // single run, and an alarm that fires every time is one nobody reads.
  const unexplainedStop = useMemo(() => {
    if (!run || !run.terminal || !run.readable || run.stopReason) return 0;
    const neverReported = planSteps.length
      ? planSteps.filter((s) => s.willSend && s.captureId && !run.byCapture[s.captureId]).length
      : 0;
    return run.counts.pending + neverReported;
  }, [run, planSteps]);

  /* ------------------------------------------------------- results on the graph */

  // Three states this graph can be in, and it says which one it is in every time it is not the
  // first: as captured, a plan under review, or a run's results. A run outranks a plan, because a
  // result is a fact and a plan is a forecast.
  const graphMode = (() => {
    if (runOnThisFlow) {
      // A run whose per-step list could not be read has NO results, so it must not paint the graph.
      // Painting every node "pending" off an unreadable payload would be this modal inventing a
      // result set and then warning, one panel higher, that it has none.
      const usable = graphShowsRun && run && run.readable;
      return usable ? 'run' : 'captured';
    }
    const reviewing = runPanelOpen && plan && planIsForThisConfig && planSkipped.length > 0;
    return reviewing ? 'plan' : 'captured';
  })();

  const graphNodes = useMemo(() => {
    if (graphMode === 'captured') return nodes;

    if (graphMode === 'plan') {
      // Under review the captured statuses stay, because they are what the operator is reading the
      // flow by. Only the steps that will NOT be sent are repainted, since that is the one fact the
      // plan adds to the picture.
      return nodes.map((node) => {
        const skip = planSkippedByCapture[String(node.id)];
        if (!skip) return node;
        return { ...node, status_code: runStateBadge('skipped') };
      });
    }

    return nodes.map((node) => {
      const captureId = String(node.id);
      const result = run && run.byCapture ? run.byCapture[captureId] : null;

      if (!result) {
        // No result reported for this request. While the run is live that is "not yet"; once it is
        // terminal it is "this never ran", which is a different and much louder thing.
        const key = run && run.terminal ? 'never_ran' : 'pending';
        return { ...node, status_code: runStateBadge(key), size: undefined, duration_ms: undefined };
      }

      const known = RUN_STATE_PAINT[result.state] || result.state === 'sent';
      if (result.state === 'sent') {
        return {
          ...node,
          // A real status code goes down as a number, so the chart's own 2xx/3xx/4xx/5xx colouring
          // does the work and the run's result reads in the palette the operator already knows.
          status_code: result.statusCode > 0 ? result.statusCode : runStateBadge('sent_no_status'),
          size: result.sizeBytes > 0 ? result.sizeBytes : undefined,
          duration_ms: result.durationMs > 0 ? result.durationMs : undefined,
        };
      }
      return {
        ...node,
        status_code: known
          ? runStateBadge(result.state)
          : runStateBadge('unknown', result.state),
        size: undefined,
        duration_ms: result.durationMs > 0 ? result.durationMs : undefined,
      };
    });
  }, [graphMode, nodes, planSkippedByCapture, run]);

  /* ------------------------------------------------------------- edit as flow */

  // The bridge to conditionals. A detected flow has no step rows, so it cannot carry a condition; a
  // built flow can. This is the one click from "I detected this" to "I want to branch on it", and it
  // exists here because nobody discovers that the builder can seed itself from a detected flow by
  // opening the builder and looking at an empty list.
  const editAsFlow = async () => {
    if (!selectedFlowId || !targetId || promoting) return;
    setPromoting(true);
    setPromoteError('');
    setPromoteNotice('');
    try {
      const { ok, status, data, body } = await requestJSON(
        `/api/request-flow-builder/${targetId}/from-flow`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            flow_id: selectedFlowId,
            include_all: Boolean(showAllResources),
            // Deliberately NOT passed through from this modal's run option. Seeding writes steps
            // that sit in the builder until somebody presses replay; arming them from a checkbox
            // ticked for a different action would arm requests nobody reviewed in the builder.
            arm_write_steps: false,
          }),
        }
      );
      if (!ok || !data || !data.flow) {
        setPromoteError(errorMessage(data, body, status));
        return;
      }
      const built = data.flow;
      if (onEditAsFlow) {
        onEditAsFlow(String(built.id), built);
        setPromoteNotice(`Opened "${built.name}" in the Request Flow Builder.`);
        return;
      }
      const disabled = Number(data.disabled_count) || 0;
      setPromoteNotice(
        `Built "${built.name}" with ${Number(built.step_count || (data.steps || []).length) || 0} step(s). `
        + (disabled > 0
          ? `${disabled} arrived turned OFF because they are POST/PUT/PATCH/DELETE carrying the body that was recorded. `
          : '')
        + 'Open Request Flow Builder to add conditions and branches to it. This view has no way to '
        + 'open the builder for you.'
      );
    } catch (err) {
      setPromoteError(`Could not reach the framework: ${err.message}`);
    } finally {
      setPromoting(false);
    }
  };

  /* ------------------------------------------------------------------ render */

  const renderStatusSummary = (summary) => {
    const entries = Object.entries(summary || {}).filter(([, count]) => Number(count) > 0);
    if (!entries.length) return null;
    entries.sort((a, b) => a[0].localeCompare(b[0]));
    return entries.map(([key, count]) => (
      <span key={key} className={`badge bg-${statusClassVariant(key)} me-1`} style={{ fontSize: '0.62rem' }}>
        {key} {count}
      </span>
    ));
  };

  const renderFlowRow = (flow) => {
    const selected = flow.id === selectedFlowId;
    const { method, rest } = splitLabel(flow.label);
    const duration = formatDuration(flow.duration_ms);
    const source = detectionSourceOf(flow, flowSources);
    const owningRun = runId && runFlowId === flow.id;
    return (
      <div
        key={flow.id}
        role="button"
        tabIndex={0}
        onClick={() => selectFlow(flow.id)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectFlow(flow.id); }
        }}
        className="rfl-flow-row px-2 py-2 border-bottom border-secondary"
        style={{
          cursor: 'pointer',
          borderLeft: `3px solid ${selected ? '#dc3545' : 'transparent'}`,
          backgroundColor: selected ? '#2b3035' : 'transparent',
        }}
        title={`${flow.label || ''}\n${flow.host || ''}\n${flow.request_count} requests recorded`}
      >
        <div className="text-truncate" style={{ fontFamily: MONO, fontSize: '0.75rem' }}>
          {method && <span className="fw-bold text-warning me-1">{method}</span>}
          <span className="text-info">{rest}</span>
        </div>
        <div className="text-white-50 text-truncate" style={{ fontSize: '0.68rem' }}>
          {flow.host || 'unknown host'}
        </div>
        <div className="mt-1 d-flex flex-wrap align-items-center">
          {owningRun && (
            <span
              className={`badge bg-${runIsLive ? 'danger' : 'secondary'} me-1`}
              style={{ fontSize: '0.62rem' }}
              title={runIsLive ? 'A run of this flow is in progress.' : 'This flow was run in this session.'}
            >
              <i className="bi bi-play-fill me-1" />
              {runIsLive ? 'running' : 'ran'}
            </span>
          )}
          {source && <SourceBadge source={source} />}
          {renderStatusSummary(flow.status_summary)}
          {flow.has_redirects && (
            <span className="badge bg-info me-1" style={{ fontSize: '0.62rem' }}>
              <i className="bi bi-signpost-split me-1" />redirects
            </span>
          )}
          {flow.has_body && (
            <span className="badge bg-secondary me-1" style={{ fontSize: '0.62rem' }}>body</span>
          )}
          {flow.root_kind === 'burst' && (
            <span
              className="badge bg-dark border border-secondary text-white-50"
              style={{ fontSize: '0.62rem' }}
              title="No navigation rooted this one. It was cut out of a tab that never navigated, using an idle gap, so its boundaries are a heuristic rather than a page load."
            >
              burst
            </span>
          )}
        </div>
        <div className="text-white-50 mt-1" style={{ fontSize: '0.65rem' }}>
          {flow.request_count} request{flow.request_count === 1 ? '' : 's'}
          {Number(flow.hidden_count) > 0 && (
            <span className="text-warning ms-1">
              ({flow.shown_count} shown, {flow.hidden_count} subresources hidden)
            </span>
          )}
          {duration && <span className="ms-1">· {duration}</span>}
        </div>
        <div className="text-white-50" style={{ fontSize: '0.63rem' }}>
          {formatTimestamp(flow.started_at)}
        </div>
      </div>
    );
  };

  const renderVersionPicker = () => {
    if (!versions.length) return null;
    return (
      <Form.Select
        size="sm"
        value={selectedVersionId}
        onChange={(e) => pickVersion(e.target.value)}
        className="bg-dark text-white border-secondary"
        style={{ fontSize: '0.7rem' }}
        data-bs-theme="dark"
        aria-label="Which saved version of this request to edit, and to send when the flow runs"
      >
        {versions.map((v) => (
          <option key={v.id} value={v.id}>
            {v.is_original ? 'Original (as captured)' : v.label || 'edited'}
            {v.summary ? ` — ${v.summary}` : ''}
          </option>
        ))}
      </Form.Select>
    );
  };

  const renderEditor = () => {
    if (!selectedNode) return null;
    const original = selectedVersion && selectedVersion.is_original;
    return (
      <div className="border-top border-secondary mt-3 pt-2">
        <div className="d-flex align-items-center mb-2">
          <span className="text-white-50" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
            RAW REQUEST
          </span>
          {editorLoading && <Spinner animation="border" size="sm" variant="danger" className="ms-2" />}
          <span className="text-white-50 ms-auto" style={{ fontSize: '0.65rem' }}>
            {byteLength(draft).toLocaleString()} bytes
          </span>
        </div>

        {versions.length > 0 && (
          <div className="mb-2">
            {renderVersionPicker()}
            <div className="text-white-50 mt-1" style={{ fontSize: '0.64rem' }}>
              {versions.length === 1
                ? 'One version: the request as it was captured.'
                : `${versions.length} versions. The original is what the target actually sent and cannot be changed.`}
            </div>
            <div className="text-info mt-1" style={{ fontSize: '0.64rem' }}>
              <i className="bi bi-play-circle me-1" />
              Running the flow sends the version selected here for this request.
            </div>
          </div>
        )}

        {editorError && (
          <div className="text-danger mb-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {editorError}
          </div>
        )}
        {versionsNote && (
          <div className="text-warning mb-2" style={{ fontSize: '0.68rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {versionsNote}
          </div>
        )}

        <Form.Control
          as="textarea"
          value={draft}
          onChange={(e) => { setDraft(e.target.value); setSaveNotice(''); setSaveError(''); }}
          spellCheck={false}
          disabled={editorLoading}
          rows={14}
          className="bg-dark text-white border-secondary"
          style={{
            fontFamily: MONO,
            fontSize: '0.7rem',
            whiteSpace: 'pre',
            overflowWrap: 'normal',
            overflowX: 'auto',
            lineHeight: 1.35,
          }}
          data-bs-theme="dark"
          aria-label="Raw HTTP request. Every byte is editable."
        />

        <InputGroup size="sm" className="mt-2">
          <InputGroup.Text
            className="bg-dark border-secondary text-white-50"
            style={{ fontSize: '0.66rem' }}
            title="Where these bytes get sent when the request line carries a path rather than an absolute URL."
          >
            base URL
          </InputGroup.Text>
          <Form.Control
            value={baseUrl}
            onChange={(e) => { setBaseUrl(e.target.value); setSaveNotice(''); setSaveError(''); }}
            placeholder="https://host"
            spellCheck={false}
            disabled={editorLoading}
            className="bg-dark text-white border-secondary"
            style={{ fontFamily: MONO, fontSize: '0.68rem' }}
            data-bs-theme="dark"
          />
        </InputGroup>

        {saveError && (
          <div className="text-danger mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {saveError}
          </div>
        )}
        {saveNotice && (
          <div className="text-info mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-info-circle me-1" />
            {saveNotice}
          </div>
        )}

        {/* Only once there is a version to be different FROM. Without that guard this fires the
            instant a request with no version rows is selected, which reads as "you have unsaved
            changes" to an operator who has typed nothing. */}
        {dirty && selectedVersion && (
          <div className="text-warning mt-2" style={{ fontSize: '0.68rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            These bytes are not saved. A run of this flow sends SAVED versions, so unsaved edits go
            nowhere. Save them first.
          </div>
        )}

        <div className="d-flex gap-2 mt-2">
          <Button
            size="sm"
            variant="danger"
            className="flex-grow-1"
            disabled={!versionsAvailable || !dirty || saving || editorLoading}
            onClick={saveVersion}
            title={
              !versionsAvailable
                ? 'The version API is not available on this server build.'
                : (dirty
                  ? 'Save these bytes as a new version, edited from the one selected above. Nothing is overwritten.'
                  : 'Nothing has changed since the selected version.')
            }
          >
            {saving
              ? <><Spinner animation="border" size="sm" className="me-2" />Saving</>
              : <><i className="bi bi-save me-2" />Save as new version</>}
          </Button>
          <Button
            size="sm"
            variant="outline-secondary"
            disabled={!dirty || saving || !selectedVersion}
            onClick={revertDraft}
            title="Throw away the unsaved edits and go back to the selected version's bytes."
          >
            Discard edits
          </Button>
        </div>

        <div className="text-white-50 mt-2" style={{ fontSize: '0.64rem' }}>
          {original
            ? 'Editing the original as it was captured. Saving creates a child version; the original itself is never changed.'
            : 'Saving creates a new version below the one selected above. Nothing is ever overwritten, so every earlier version stays reachable.'}
        </div>
      </div>
    );
  };

  // What THIS request will send, and what it did when it was sent. On the node panel because that is
  // where the operator is when they wonder about one request; the whole-flow answer is on the graph.
  const renderNodeRunState = () => {
    if (!selectedNode) return null;
    const captureId = String(selectedNode.id);
    const send = sendPlanByCapture[captureId];
    const result = run && run.byCapture ? run.byCapture[captureId] : null;
    const skip = planSkippedByCapture[captureId];
    if (!send && !result && !skip) return null;
    return (
      <div className="border-top border-secondary mt-3 pt-2">
        <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
          WHEN THE FLOW RUNS
        </div>
        {send && (
          <DetailRow label="Will send">
            {send.edited ? (
              <span className="text-warning">
                <i className="bi bi-pencil-fill me-1" />
                your edited version{send.version && send.version.label ? ` "${send.version.label}"` : ''}
                {send.explicit ? ' (you picked it)' : ' (your newest edit)'}
              </span>
            ) : (
              <span className="text-white-50">
                the request exactly as captured
                {send.versionId ? '' : ' (no saved version exists for it yet)'}
              </span>
            )}
          </DetailRow>
        )}
        {skip && (
          <DetailRow label="Dry run">
            <span className="text-warning">
              skipped
              {skip.skipDetail || skip.skipReason
                ? `: ${skip.skipDetail || skip.skipReason}`
                : ', and the server did not say why'}
            </span>
          </DetailRow>
        )}
        {result && (
          <>
            <DetailRow label="Result">
              <span className={result.state === 'sent' ? 'text-success' : 'text-warning'}>
                {result.state}
              </span>
              {result.statusCode > 0 && (
                <span className={`badge bg-${statusVariant(result.statusCode)} ms-2`}>
                  {result.statusCode}
                </span>
              )}
            </DetailRow>
            {result.durationMs > 0 && (
              <DetailRow label="Took">{formatDuration(result.durationMs)}</DetailRow>
            )}
            {result.reason && <DetailRow label="Reason">{result.reason}</DetailRow>}
            {result.error && (
              <DetailRow label="Error"><span className="text-danger">{result.error}</span></DetailRow>
            )}
          </>
        )}
      </div>
    );
  };

  const renderDetails = () => {
    if (!flowSummary) {
      return (
        <div className="text-white-50 small p-3 fst-italic">
          Pick a flow on the left to draw it.
        </div>
      );
    }
    const flowDuration = formatDuration(flowSummary.duration_ms);
    const nodeSize = selectedNode ? formatBytes(selectedNode.size) : null;
    const nodeDuration = selectedNode ? formatDuration(selectedNode.duration_ms) : null;
    return (
      <div className="p-2">
        <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
          FLOW
        </div>
        {selectedFlowSource && (
          <div className="mb-2"><SourceBadge source={selectedFlowSource} /></div>
        )}
        <DetailRow label="Started by" mono>{flowSummary.label}</DetailRow>
        <DetailRow label="Host">{flowSummary.host || 'unknown'}</DetailRow>
        <DetailRow label="Started">{formatTimestamp(flowSummary.started_at) || 'unknown'}</DetailRow>
        {flowDuration && <DetailRow label="Duration">{flowDuration}</DetailRow>}
        <DetailRow label="Requests">
          {flowSummary.request_count}
          {Number(flowSummary.hidden_count) > 0 && (
            <span className="text-warning ms-1">
              ({flowSummary.shown_count} shown by default, {flowSummary.hidden_count} hidden)
            </span>
          )}
        </DetailRow>
        <DetailRow label="Statuses">{renderStatusSummary(flowSummary.status_summary) || 'none recorded'}</DetailRow>
        <DetailRow label="Rooted by">
          {flowSummary.root_kind === 'burst' ? (
            <span className="text-warning">
              an idle gap, not a navigation. This tab never navigated, so the boundaries are a
              heuristic.
            </span>
          ) : (
            'a navigation'
          )}
        </DetailRow>
        <DetailRow label="Your edits">
          {editedCount > 0 ? (
            <span className="text-warning">
              {editedCount} of {nodes.length} request{nodes.length === 1 ? '' : 's'} will send bytes
              you edited
            </span>
          ) : (
            <span className="text-white-50">none; every request would go as captured</span>
          )}
        </DetailRow>

        <div className="border-top border-secondary mt-3 pt-2">
          <div className="text-white-50 mb-2" style={{ fontSize: '0.68rem', letterSpacing: '0.04em' }}>
            SELECTED REQUEST
          </div>
          {!selectedNode ? (
            <div className="text-white-50 fst-italic" style={{ fontSize: '0.72rem' }}>
              Click a request in the graph to see it, edit its bytes, and replay it.
            </div>
          ) : (
            <>
              <DetailRow label="Method" mono>
                <span className="fw-bold text-warning">{selectedNode.method || '?'}</span>
              </DetailRow>
              <DetailRow label="URL" mono>{selectedNode.url || selectedNode.path || 'unknown'}</DetailRow>
              <DetailRow label="Status">
                {selectedNode.status_code ? (
                  <span className={`badge bg-${statusVariant(selectedNode.status_code)}`}>
                    {selectedNode.status_code}
                  </span>
                ) : (
                  <span className="text-white-50">no response recorded</span>
                )}
                <span className="text-white-50 ms-1">when it was captured</span>
              </DetailRow>
              <DetailRow label="Sent at">{formatTimestamp(selectedNode.timestamp) || 'unknown'}</DetailRow>
              <DetailRow label="Took">{nodeDuration || 'not recorded'}</DetailRow>
              {/* Says which size this is. A capture whose response body was never stored reports
                  zero here, and zero bytes and "not recorded" are not the same fact. */}
              <DetailRow label="Response">
                {nodeSize || '0 B'}
                <span className="text-white-50 ms-1">of response body stored</span>
              </DetailRow>
              <DetailRow label="Type">{selectedNode.resource_type || 'unknown'}</DetailRow>
              <DetailRow label="Initiator">{selectedNode.initiator || 'not recorded'}</DetailRow>
              <DetailRow label="Mime">{selectedNode.mime_type || 'not recorded'}</DetailRow>
              <DetailRow label="Body">
                {selectedNode.has_body ? (
                  <span className="text-warning">carried a request body</span>
                ) : (
                  <span className="text-white-50">no request body</span>
                )}
              </DetailRow>

              {/* The one and only way to move this request into the repeater. */}
              <Button
                size="sm"
                variant="outline-danger"
                className="w-100 mt-2"
                disabled={!onOpenInRepeater}
                onClick={() => onOpenInRepeater && onOpenInRepeater(String(selectedNode.id))}
                title={onOpenInRepeater
                  ? 'Open this exact request in the Replay Requests repeater and send it.'
                  : 'No repeater is wired to this view, so there is nowhere to send this request from.'}
              >
                <i className="bi bi-arrow-repeat me-2" />
                Replay Single Request
              </Button>
              {!onOpenInRepeater && (
                <div className="text-white-50 mt-1" style={{ fontSize: '0.64rem' }}>
                  This view was opened without a repeater to hand requests to.
                </div>
              )}

              {renderNodeRunState()}
              {renderEditor()}
            </>
          )}
        </div>
      </div>
    );
  };

  /* -------------------------------------------------------------- run panel */

  const renderPlanSteps = () => {
    if (!planSteps.length) {
      return (
        <div className="text-warning mt-2" style={{ fontSize: '0.68rem' }}>
          <i className="bi bi-exclamation-triangle me-1" />
          The dry run came back without a per-request list, so what would be sent cannot be shown
          request by request here. The counts above are the server&apos;s own.
        </div>
      );
    }
    const rows = planShowAllSteps ? planSteps : planSteps.slice(0, 12);
    return (
      <div className="mt-2">
        <div style={{ maxHeight: '210px', overflowY: 'auto' }}>
          {rows.map((step) => {
            const send = sendPlanByCapture[step.captureId];
            return (
              <div
                key={step.key}
                className="d-flex align-items-center gap-2 py-1 border-bottom border-secondary"
                style={{ fontSize: '0.66rem' }}
              >
                <span className="text-white-50" style={{ width: 20, textAlign: 'right' }}>
                  {step.index}
                </span>
                <span
                  className="badge bg-dark border border-secondary text-white-50"
                  style={{ fontSize: '0.55rem', minWidth: 44 }}
                >
                  {step.method || (send && send.node && send.node.method) || '?'}
                </span>
                <code
                  className="text-info flex-grow-1 text-truncate"
                  style={{ fontSize: '0.66rem', minWidth: 0 }}
                  title={step.url || (send && send.node && send.node.url) || ''}
                >
                  {step.url || (send && send.node && (send.node.path || send.node.url)) || 'unknown'}
                </code>
                {send && send.edited && (
                  <span
                    className="badge bg-warning text-dark"
                    style={{ fontSize: '0.55rem' }}
                    title={`Your edited bytes will be sent: "${(send.version && send.version.label) || 'edited'}"`}
                  >
                    <i className="bi bi-pencil-fill me-1" />
                    edited
                  </span>
                )}
                {step.willSend ? (
                  <span className="text-success" style={{ minWidth: 84, textAlign: 'right' }}>
                    will send
                  </span>
                ) : (
                  <span
                    className="text-warning text-truncate"
                    style={{ minWidth: 84, textAlign: 'right' }}
                    title={step.skipDetail || step.skipReason || 'The server did not say why.'}
                  >
                    skipped{step.skipReason ? `: ${step.skipReason}` : ''}
                  </span>
                )}
              </div>
            );
          })}
        </div>
        {planSteps.length > rows.length && (
          <Button
            size="sm"
            variant="link"
            className="p-0 mt-1 text-info text-decoration-underline"
            style={{ fontSize: '0.66rem' }}
            onClick={() => setPlanShowAllSteps(true)}
          >
            show all {planSteps.length.toLocaleString()}
          </Button>
        )}
      </div>
    );
  };

  const renderRunProgress = () => {
    if (!runOnThisFlow || !run) return null;
    const sent = Number.isFinite(run.sentTotal) ? run.sentTotal : run.counts.sent;
    const planned = Number.isFinite(run.plannedTotal) && run.plannedTotal > 0
      ? run.plannedTotal
      : (plannedCount || run.steps.length || nodes.length);
    const pct = planned > 0 ? Math.min(100, Math.round((sent / planned) * 100)) : 0;
    const variant = run.terminal
      ? (run.stopReason || run.counts.failed > 0 ? 'warning' : 'success')
      : 'danger';
    const elapsed = elapsedText(run.startedAt, run.completedAt, runStartedAtRef.current);
    return (
      <div className="border border-secondary rounded p-2 mt-2" style={{ background: '#212529' }}>
        <div className="d-flex align-items-center mb-1 flex-wrap gap-2">
          <span className={`badge bg-${variant}`} style={{ fontSize: '0.65rem' }}>
            {run.status || 'unknown'}
          </span>
          <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
            {sent.toLocaleString()} sent of {planned.toLocaleString()} planned
            {run.counts.skipped > 0 && (
              <span className="text-warning ms-2">{run.counts.skipped.toLocaleString()} skipped</span>
            )}
            {run.counts.failed > 0 && (
              <span className="text-danger ms-2">{run.counts.failed.toLocaleString()} failed</span>
            )}
            {elapsed && <span className="ms-2">{elapsed} elapsed</span>}
          </span>
          {runIsLive && (
            <span className="ms-auto d-inline-flex align-items-center gap-2">
              <Button
                size="sm"
                variant="outline-warning"
                disabled={cancelling}
                onClick={cancelRun}
                style={{ fontSize: '0.66rem', padding: '0.1rem 0.5rem' }}
                title="Stop this run. The requests already sent stay on the graph; nothing further is sent."
              >
                {cancelling
                  ? <><Spinner animation="border" size="sm" className="me-1" />Cancelling</>
                  : <><i className="bi bi-stop-circle me-1" />Cancel run</>}
              </Button>
              <Spinner animation="border" size="sm" variant="danger" />
            </span>
          )}
        </div>
        <ProgressBar now={pct} variant={variant} style={{ height: '6px' }} />

        {cancelNotice && (
          <div className="text-warning mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-stop-circle me-1" />
            {cancelNotice}
          </div>
        )}

        {run.stopReason && (
          <div className="text-danger mt-2" style={{ fontSize: '0.72rem' }}>
            <i className="bi bi-exclamation-octagon me-1" />
            <strong>Stopped early:</strong> {run.stopReason}
            {/* The cap's own code, beside the sentence rather than instead of it. The sentence is
                what the operator acts on; the code is what they quote when it needs explaining. */}
            {run.stopCode && run.stopCode !== run.stopReason && (
              <code className="text-warning ms-2" style={{ fontSize: '0.66rem' }}>{run.stopCode}</code>
            )}
          </div>
        )}
        {run.terminal && !run.stopReason && unexplainedStop > 0 && (
          <div className="text-warning mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            This run ended with {unexplainedStop.toLocaleString()} request
            {unexplainedStop === 1 ? '' : 's'} never attempted, and the server gave no reason. Treat
            that as unexplained, not as those requests passing.
          </div>
        )}
        {run.unrecognisedStatus && (
          <div className="text-warning mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            The server reports this run&apos;s status as{' '}
            <code className="text-warning">{run.status}</code>, which this view does not recognise as
            either running or finished. It is being treated as STILL RUNNING, so no second run can be
            started on top of it. If it really has finished, dismiss it once it stops changing.
          </div>
        )}
        {run.repeats > 0 && (
          <div className="text-info mt-1" style={{ fontSize: '0.66rem' }}>
            {run.repeats.toLocaleString()} request{run.repeats === 1 ? ' was' : 's were'} executed
            more than once. The graph shows each one&apos;s LAST result.
          </div>
        )}
        {!run.readable && (
          <div className="text-warning mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            The run is on the server, but this view could not find a per-step list in what it
            answered (it looked for <code>steps</code>, <code>results</code>,{' '}
            <code>step_results</code>). Nothing on the graph below is a result, so read it as the
            captured statuses only.
          </div>
        )}
        {run.lastError && (
          <div className="text-warning mt-1" style={{ fontSize: '0.68rem' }}>
            Last error: {run.lastError}
          </div>
        )}
        {runPollError && (
          <div className="text-danger mt-1" style={{ fontSize: '0.68rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {runPollError}
          </div>
        )}
        {run.terminal && (
          <div className="text-white-50 mt-2" style={{ fontSize: '0.66rem' }}>
            Finished{run.completedAt ? ` ${formatTimestamp(run.completedAt)}` : ''}. The results stay
            on the graph until you dismiss this run.
          </div>
        )}
      </div>
    );
  };

  const renderRunPanel = () => {
    if (!runPanelOpen && !runOnThisFlow) return null;
    return (
      <div className="border-bottom border-secondary p-2" style={{ background: '#191c1f' }}>
        <div className="d-flex align-items-center mb-2">
          <span className="text-danger" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
            <i className="bi bi-play-circle me-1" />
            RUN THIS FLOW
          </span>
          {/* While a run is live this panel is the only place its progress and its stop reason are
              shown, so it cannot be dismissed out from under one. Once the run is over, dismissing
              clears the results and puts the graph back to the captured statuses, which is stated
              rather than left to be discovered. */}
          <Button
            size="sm"
            variant="link"
            className="ms-auto p-0 text-white-50 text-decoration-none"
            style={{ fontSize: '0.7rem' }}
            disabled={runOnThisFlow && runIsLive}
            onClick={() => {
              if (runOnThisFlow) {
                setRunId('');
                setRunFlowId('');
                setRunFlowLabel('');
                setRun(null);
                setRunPollError('');
                setCancelNotice('');
                runStartedAtRef.current = 0;
              }
              setRunPanelOpen(false);
            }}
            title={runOnThisFlow && runIsLive
              ? 'A run is in progress. This panel stays open until it finishes.'
              : (runOnThisFlow
                ? 'Dismiss this run. The results disappear from the graph and it goes back to the captured statuses.'
                : 'Close the run panel. Nothing has been sent.')}
          >
            {runOnThisFlow && !runIsLive
              ? <span style={{ fontSize: '0.7rem' }}>dismiss run <i className="bi bi-x-lg" /></span>
              : <i className="bi bi-x-lg" />}
          </Button>
        </div>

        <div className="text-white-50 mb-2" style={{ fontSize: '0.72rem' }}>
          The steps are sent in the order they were captured. A detected flow has no conditions and
          no branches: it is a straight line. Use <span className="text-warning">Edit as flow</span>
          {' '}to branch on a response.
        </div>

        {/* A NARROWING, not a permission. Every step sends by default, including the writes, which
            is what makes the run a replay of the flow rather than a replay of its reads. Ticking
            this drops the POST, PUT, PATCH and DELETE steps. */}
        <Form.Check
          type="checkbox"
          id="rfl-skip-state-changing"
          className="text-white mb-2"
          style={{ fontSize: '0.72rem' }}
          checked={skipStateChanging}
          disabled={runIsLive}
          onChange={() => setSkipStateChanging((prev) => !prev)}
          label={
            <span>
              Skip the POST, PUT, PATCH and DELETE steps
              <span className="text-white-50 d-block" style={{ fontSize: '0.68rem' }}>
                Off by default, so the whole flow runs with the bodies that were recorded.
              </span>
            </span>
          }
        />

        <div className="d-flex align-items-center gap-2 flex-wrap">
          <Button
            size="sm"
            variant="outline-info"
            disabled={!selectedFlowId || planning || runIsLive}
            onClick={runDryRun}
            title="Work out what would be sent. Sends nothing."
          >
            {planning
              ? <><Spinner animation="border" size="sm" className="me-2" />Dry run</>
              : <><i className="bi bi-eye me-2" />Dry run again</>}
          </Button>
          <Button
            size="sm"
            variant="danger"
            disabled={!canSend}
            onClick={startRun}
            title={canSend
              ? (planIsForThisConfig
                ? `Send ${(plannedCount || 0).toLocaleString()} requests to this target now.`
                : 'Send this flow to the target now. Dry run first if you want the count.')
              : gateReason}
          >
            {starting
              ? <><Spinner animation="border" size="sm" className="me-2" />Starting</>
              : (
                <>
                  <i className="bi bi-broadcast-pin me-2" />
                  {canSend && planIsForThisConfig
                    ? `Send ${(plannedCount || 0).toLocaleString()} request${plannedCount === 1 ? '' : 's'} now`
                    : 'Send'}
                </>
              )}
          </Button>
          <span className="text-white-50" style={{ fontSize: '0.68rem', flex: '1 1 240px' }}>
            {/* The count when there is a preview to take it from, and nothing at all when there is
                not. The dry run is a preview, so its absence is not a warning to print. */}
            {gateReason || (planIsForThisConfig
              ? `${(plannedCount || 0).toLocaleString()} step${plannedCount === 1 ? '' : 's'} in the last dry run of this configuration.`
              : '')}
          </span>
        </div>

        {startError && (
          <div className="text-danger mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {startError}
          </div>
        )}
        {planError && (
          <div className="text-danger mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {planError}
          </div>
        )}

        {plan && (
          <div className="mt-2 border border-secondary rounded p-2" style={{ background: '#212529' }}>
            {!planIsForThisConfig && (
              <div className="text-warning mb-2" style={{ fontSize: '0.7rem' }}>
                <i className="bi bi-exclamation-triangle me-1" />
                This preview is for the previous configuration. Run the dry run again to see what
                would be sent now.
              </div>
            )}
            <div className="d-flex flex-wrap gap-3" style={{ fontSize: '0.7rem' }}>
              <span className="text-white-50">
                would send{' '}
                <span className="text-white fw-bold">
                  {plannedCount === null ? 'an unreported number of' : plannedCount.toLocaleString()}
                </span>{' '}
                request{plannedCount === 1 ? '' : 's'}
              </span>
              {planSkipped.length > 0 && (
                <span className="text-white-50">
                  skips <span className="text-warning fw-bold">{planSkipped.length.toLocaleString()}</span>
                </span>
              )}
              {planCaps && planCaps.rps !== null && (
                <span className="text-white-50">
                  rate <span className="text-white">{planCaps.rps}/s</span>
                </span>
              )}
              {planCaps && planCaps.seconds !== null && (
                <span className="text-white-50">
                  about <span className="text-white">{formatDuration(planCaps.seconds * 1000)}</span>
                </span>
              )}
              {planCaps && planCaps.maxSteps !== null && (
                <span
                  className="text-white-50"
                  title="Executions, not definitions. A run that reaches this many executed steps stops and says so."
                >
                  step budget <span className="text-white">{planCaps.maxSteps.toLocaleString()}</span>
                  {planCaps.budgetSource === 'engagement' && (
                    <span className="text-warning ms-1">(this programme&apos;s cap)</span>
                  )}
                  {planCaps.budgetSource === 'ceiling' && (
                    <span className="text-warning ms-1">(the framework&apos;s ceiling)</span>
                  )}
                </span>
              )}
            </div>

            <div className="mt-2" style={{ fontSize: '0.7rem' }}>
              {editedCount > 0 ? (
                <span className="text-warning">
                  <i className="bi bi-pencil-fill me-1" />
                  <strong>{editedCount}</strong> of {nodes.length} request
                  {nodes.length === 1 ? '' : 's'} will be sent as the bytes YOU edited, not as they
                  were captured. They are marked <span className="badge bg-warning text-dark" style={{ fontSize: '0.55rem' }}>edited</span> below.
                </span>
              ) : (
                <span className="text-white-50">
                  Every request goes exactly as captured; none of them has a saved edit.
                </span>
              )}
              {flowVersionsError && (
                <div className="text-danger mt-1" style={{ fontSize: '0.68rem' }}>
                  <i className="bi bi-exclamation-triangle me-1" />
                  Your saved edits could not be read ({flowVersionsError}), so this run would send
                  every request as captured. Fix that before sending if you meant to send edits.
                </div>
              )}
            </div>

            {String(firstOf(plan, ['warning', 'note']) || '') !== '' && (
              <div className="text-warning mt-2" style={{ fontSize: '0.7rem' }}>
                <i className="bi bi-exclamation-triangle me-1" />
                {String(firstOf(plan, ['warning', 'note']))}
              </div>
            )}

            {renderPlanSteps()}
          </div>
        )}

        {renderRunProgress()}
      </div>
    );
  };

  const renderGraphModeBanner = () => {
    if (graphMode === 'captured') {
      if (runOnThisFlow && run && run.readable) {
        return (
          <div
            className="px-2 py-1 border-bottom border-secondary text-white-50"
            style={{ fontSize: '0.68rem' }}
          >
            Showing the statuses as CAPTURED, not this run&apos;s results.
            <Button
              size="sm"
              variant="link"
              className="p-0 ms-2 align-baseline text-info text-decoration-underline"
              style={{ fontSize: '0.68rem' }}
              onClick={() => setGraphShowsRun(true)}
            >
              show the run&apos;s results
            </Button>
          </div>
        );
      }
      // No offer to switch when the run reported no per-step list. There is nothing to switch to,
      // and the run panel above has already said so in full.
      if (runOnThisFlow && run && !run.readable) {
        return (
          <div
            className="px-2 py-1 border-bottom border-secondary text-warning"
            style={{ fontSize: '0.68rem' }}
          >
            <i className="bi bi-exclamation-triangle me-1" />
            A run happened, but it reported no per-request results, so this graph is still the
            CAPTURED statuses. Nothing below is a result of that run.
          </div>
        );
      }
      return null;
    }

    if (graphMode === 'plan') {
      return (
        <div
          className="px-2 py-1 border-bottom border-secondary text-warning"
          style={{ fontSize: '0.68rem' }}
        >
          <i className="bi bi-eye me-1" />
          Dry run under review. The {planSkipped.length.toLocaleString()} request
          {planSkipped.length === 1 ? '' : 's'} the run would NOT send are marked{' '}
          <span style={{ background: '#ffc107', color: '#332701', fontWeight: 700, borderRadius: 3, padding: '0 4px' }}>skipped</span>{' '}
          below. Every other node still shows the status it was captured with. Nothing has been sent.
        </div>
      );
    }

    return (
      <div className="px-2 py-1 border-bottom border-secondary" style={{ fontSize: '0.68rem' }}>
        <div className="d-flex flex-wrap align-items-center gap-1">
          <span className="text-danger me-2">
            <i className="bi bi-broadcast-pin me-1" />
            Each node now shows THIS RUN&apos;s result, not the status it was captured with.
          </span>
          {RUN_LEGEND.map((item) => <RunLegendChip key={item.key} item={item} />)}
          <Button
            size="sm"
            variant="link"
            className="p-0 ms-auto align-baseline text-info text-decoration-underline"
            style={{ fontSize: '0.68rem' }}
            onClick={() => setGraphShowsRun(false)}
          >
            show captured statuses instead
          </Button>
        </div>
        {editedCount > 0 && (
          <div className="text-warning mt-1">
            <i className="bi bi-pencil-fill me-1" />
            {editedCount} of these requests {editedCount === 1 ? 'was' : 'were'} sent as bytes you
            edited, not as captured.
          </div>
        )}
      </div>
    );
  };

  const renderBody = () => {
    if (!targetId) {
      return <div className="text-white-50 small p-3">No target selected.</div>;
    }
    const runElsewhere = Boolean(runId) && runFlowId !== selectedFlowId;
    return (
      <div className="d-flex flex-grow-1 p-2" style={{ minHeight: 0 }}>
        {/* Left: the flows, filtered by the query language the capture list uses. */}
        <div
          className="d-flex flex-column border border-secondary rounded me-2"
          style={{ width: '25%', minWidth: '270px', minHeight: 0 }}
        >
          <div className="p-2 border-bottom border-secondary">
            <InputGroup size="sm">
              <InputGroup.Text className="bg-dark border-secondary text-white-50">
                {flowsSearching
                  ? <Spinner animation="border" size="sm" variant="danger" />
                  : <i className="bi bi-search" />}
              </InputGroup.Text>
              <Form.Control
                value={flowQuery}
                onChange={(e) => setFlowQuery(e.target.value)}
                placeholder="method = POST AND status >= 400"
                spellCheck={false}
                style={{ fontFamily: MONO, fontSize: '0.75rem' }}
                data-bs-theme="dark"
                aria-label="Filter flows"
              />
              {flowQuery !== '' && (
                <Button variant="outline-secondary" onClick={() => setFlowQuery('')} title="Clear the query">
                  <i className="bi bi-x" />
                </Button>
              )}
            </InputGroup>
            {flowsError && (
              <div className="text-danger mt-1" style={{ fontSize: '0.72rem' }}>
                <i className="bi bi-exclamation-triangle me-1" />
                {flowsError}
              </div>
            )}
            <div className="text-white-50 mt-1" style={{ fontSize: '0.68rem' }}>
              {flows.length.toLocaleString()} of {Math.max(flowsTotal, flows.length).toLocaleString()} flows
              {flowsTruncated && (
                <span className="text-warning ms-1">
                  (truncated at {FLOW_LIMIT}, narrow the query to see the rest)
                </span>
              )}
            </div>
            <div className="text-white-50 mt-1" style={{ fontSize: '0.66rem' }}>
              The query matches requests; a flow containing a match is listed whole.
            </div>
            {/* Said once, not as a mystery pill on every row. */}
            {flowsLoaded && flows.length > 0 && !anySourceReported && (
              <div className="text-white-50 mt-1" style={{ fontSize: '0.66rem' }}>
                <i className="bi bi-info-circle me-1" />
                This build&apos;s flow list does not report a detection source, so no
                Passive/Active/Both badge is shown. Nothing is being guessed.
              </div>
            )}
            <div className="mt-1">
              {FLOW_QUERY_EXAMPLES.map((example) => (
                <code
                  key={example}
                  className="text-info me-2"
                  style={{ fontSize: '0.66rem', cursor: 'pointer' }}
                  role="button"
                  tabIndex={0}
                  onClick={() => setFlowQuery(example)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setFlowQuery(example); }
                  }}
                >
                  {example}
                </code>
              ))}
            </div>
          </div>

          <div className="flex-grow-1" style={{ overflowY: 'auto', overflowX: 'hidden', minHeight: 0 }}>
            {flows.length === 0 ? (
              <div className="text-white-50 small p-3">
                {flowsSearching || !flowsLoaded
                  ? 'Loading flows.'
                  : 'No flows matched. Flows are built out of manual crawl captures and active detection captures, so crawl this target or run Detect Flows first.'}
              </div>
            ) : (
              flows.map(renderFlowRow)
            )}
          </div>
        </div>

        {/* Middle: the graph, and the controls that act on the whole flow. */}
        <div
          className="d-flex flex-column border border-secondary rounded me-2 flex-grow-1"
          style={{ minWidth: 0, minHeight: 0 }}
        >
          {/* The flow header. RUN FLOW lives here, over the diagram it acts on, rather than in the
              node panel: it is the primary action of this modal and it operates on the whole flow,
              not on whichever request happens to be selected. */}
          <div className="d-flex align-items-center gap-2 px-2 py-2 border-bottom border-secondary flex-wrap">
            <span className="text-white-50" style={{ fontSize: '0.72rem' }}>REQUEST FLOW</span>
            {loadingDetail && <Spinner animation="border" size="sm" variant="danger" />}

            <Button
              size="sm"
              variant={runPanelOpen ? 'outline-danger' : 'danger'}
              disabled={!selectedFlowId}
              onClick={openRunPanel}
              title={selectedFlowId
                ? 'Open the run panel. This click sends nothing: sending is a second button inside '
                  + 'the panel, next to the dry run.'
                : 'Pick a flow first.'}
            >
              <i className="bi bi-play-fill me-1" />
              Run flow
            </Button>

            <Button
              size="sm"
              variant="outline-info"
              disabled={!selectedFlowId || promoting}
              onClick={editAsFlow}
              title="Copy this detected flow into the Request Flow Builder as editable, ordered steps.
That is where conditions and branches live: a detected flow is a reading of history and has no step rows to hang a condition on."
            >
              {promoting
                ? <><Spinner animation="border" size="sm" className="me-1" />Building</>
                : <><i className="bi bi-diagram-2 me-1" />Edit as flow</>}
            </Button>

            {nodes.length > 0 && (
              <span
                className={`badge ${editedCount > 0 ? 'bg-warning text-dark' : 'bg-dark border border-secondary text-white-50'}`}
                style={{ fontSize: '0.62rem' }}
                title={editedCount > 0
                  ? 'A run of this flow sends your edited bytes for these requests, not the ones the target originally saw.'
                  : 'No request in this flow has a saved edit, so a run would send all of them as captured.'}
              >
                {editedCount > 0 ? (
                  <><i className="bi bi-pencil-fill me-1" />{editedCount} edited of {nodes.length}</>
                ) : (
                  <>{nodes.length} requests, none edited</>
                )}
              </span>
            )}

            {flowSummary && (
              <span className="text-white-50 ms-auto text-truncate" style={{ fontSize: '0.7rem', maxWidth: '30%' }}>
                {flowSummary.host}
              </span>
            )}
          </div>

          {(promoteError || promoteNotice) && (
            <div
              className={`px-2 py-1 border-bottom border-secondary ${promoteError ? 'text-danger' : 'text-info'}`}
              style={{ fontSize: '0.7rem' }}
            >
              <i className={`bi ${promoteError ? 'bi-exclamation-triangle' : 'bi-diagram-2'} me-1`} />
              {promoteError || promoteNotice}
            </div>
          )}

          {runElsewhere && runIsLive && (
            <div className="px-2 py-1 border-bottom border-secondary text-warning" style={{ fontSize: '0.68rem' }}>
              <i className="bi bi-broadcast-pin me-1" />
              A run is still in progress on another flow{runFlowLabel ? ` (${runFlowLabel})` : ''}.
              Select it again to watch it. Nothing here will send while it is running.
            </div>
          )}

          {renderRunPanel()}

          {/* RequestFlowChart is a shared component and its own hint line still offers double-click.
              It is wired off here, so the offer is wrong, and an affordance that does nothing is
              worse than no affordance. Corrected in the one place the operator reads first. */}
          {selectedFlowId && (
            <div
              className="px-2 py-1 border-bottom border-secondary text-white-50"
              style={{ fontSize: '0.68rem' }}
            >
              <i className="bi bi-mouse2 me-1" />
              Click a request to select it. Double-click does nothing in this view, whatever the
              chart&apos;s own hint says: use <span className="text-danger">Replay Single Request</span>{' '}
              on the right.
            </div>
          )}
          {renderGraphModeBanner()}
          {flowDetailError && (
            <div className="text-danger px-2 py-1 border-bottom border-secondary" style={{ fontSize: '0.72rem' }}>
              <i className="bi bi-exclamation-triangle me-1" />
              {flowDetailError}
            </div>
          )}
          <div className="flex-grow-1 p-2" style={{ overflowY: 'auto', minHeight: 0 }}>
            {!selectedFlowId ? (
              <div className="text-center text-white-50 py-5 fst-italic">
                Pick a flow on the left. Each one is a navigation and everything it pulled: the
                redirects it followed, the requests the page issued, in the order they happened.
              </div>
            ) : !flowDetail ? (
              <div className="text-center text-white-50 py-5 fst-italic">
                {loadingDetail ? 'Loading the flow.' : 'That flow could not be drawn.'}
              </div>
            ) : (
              // Keyed on the flow so per-flow view state does not leak between flows. Without it,
              // clicking "draw all" on one large flow leaves the node cap disabled for every flow
              // selected afterwards, which reads as the cap being broken rather than remembered.
              <RequestFlowChart
                key={selectedFlowId || 'none'}
                nodes={graphNodes}
                edges={edges}
                selectedId={selectedNodeId}
                onSelect={(id) => setSelectedNodeId(id === null || id === undefined ? null : String(id))}
                // Deliberately undefined: it disables the chart's double-click handler AND its own
                // in-chart button, leaving "Replay Single Request" as the single way in.
                onOpenInRepeater={undefined}
                hiddenCount={flowDetail.hidden_count}
                showAll={Boolean(flowDetail.show_all)}
                onToggleShowAll={() => setShowAllResources((prev) => !prev)}
                redirectsPromised={Boolean(flowDetail.flow && flowDetail.flow.has_redirects)}
              />
            )}
          </div>
        </div>

        {/* Right: what the click selected, and its bytes. */}
        <div
          className="d-flex flex-column border border-secondary rounded"
          style={{ width: '34%', minWidth: '360px', minHeight: 0 }}
        >
          <div className="px-2 py-1 border-bottom border-secondary">
            <span className="text-white-50" style={{ fontSize: '0.72rem' }}>DETAILS AND EDITOR</span>
          </div>
          <div className="flex-grow-1" style={{ overflowY: 'auto', minHeight: 0 }}>
            {renderDetails()}
          </div>
        </div>
      </div>
    );
  };

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-diagram-3 me-2" />
          Request Flows
          {activeTarget && activeTarget.scope_target && (
            <span className="text-white-50 ms-2" style={{ fontSize: '0.9rem' }}>{activeTarget.scope_target}</span>
          )}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="d-flex flex-column p-0" style={{ minHeight: 0, overflow: 'hidden' }}>
        <style>{`.rfl-flow-row:hover { background-color: #2b3035 !important; }`}</style>
        {renderBody()}
      </Modal.Body>
    </Modal>
  );
};

export default RequestFlowsModal;
