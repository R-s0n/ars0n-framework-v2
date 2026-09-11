import { useMemo } from 'react';

// BuiltFlowRunMap: the map of a BUILT flow, drawn from the trace of the run that produced it.
//
// ---------------------------------------------------------------------------
// Why this is not RequestFlowChart
// ---------------------------------------------------------------------------
//
// RequestFlowChart draws a detected flow, and a detected flow is a TREE of captures: one parent per
// node, edges that mean redirect / initiator / CORS preflight / timestamp guess. Three things about
// it are actively wrong for a run:
//
//   1. IT COLLAPSES REPEATS. buildRows keys nodes by id in a Map and counts a second node with the
//      same id as a duplicate, dropping it. A step entered twice by a goto, or retried, has the same
//      step_id both times - so the second pass through the loop would silently disappear, which is
//      exactly the fact a loop-protected runner exists to make visible.
//
//   2. IT CANNOT SAY WHAT HAPPENED. Its edge vocabulary is redirect/initiator/preflight/sequence.
//      A run's edges are continue / goto / stop / fail / retry, each one a DECISION with the
//      condition that fired attached to it. Forcing those five into "sequence" would throw away the
//      branch actually taken, which is the whole content of the map.
//
//   3. IT BREAKS CYCLES BY DELETING THEM. Its walk deletes the parent link that closes a loop so the
//      depth-first layout terminates. A goto that jumps backwards IS a loop, and here it is the
//      finding, not a layout problem.
//
// So this is a straight vertical sequence in EXECUTION order - which is what a run is - and every
// connector carries the decision that produced it. Nothing is deduplicated: a step that ran three
// times is three cards, numbered.
//
// ---------------------------------------------------------------------------
// What it will not do
// ---------------------------------------------------------------------------
//
// It draws ONE run, the one it was handed, and it never merges runs or fills a gap from the flow's
// current steps. A step in the flow that is not in this trace is listed separately and called what
// it is, because "not on this run's path" and "passed" are different facts and the second one is the
// dangerous mistake.
//
// The names, statuses and messages on the cards are the ones the RUN recorded, not the step rows as
// they read now. On a stale flow those differ, and the run's own record is the honest one: it is
// what actually went out.

const CARD_BG = '#212529';
const BORDER_COLOR = '#495057';
const SELECTED_COLOR = '#dc3545';

// One entry per action the runner can record (server/utils/flowConditions.go: FlowActionContinue,
// FlowActionGoto, FlowActionStop, FlowActionFail, FlowActionRetry). An action outside this set is
// drawn with its own word rather than mapped onto the nearest one, because inventing a meaning for
// an action this file has not met is how a new branch type reads as a plain continue.
const ACTIONS = {
  continue: {
    color: '#8a94a6', icon: 'bi-arrow-down', word: 'continue',
    hint: 'The run moved on to the next step in order.',
  },
  goto: {
    color: '#0dcaf0', icon: 'bi-signpost-split', word: 'goto',
    hint: 'A condition matched and jumped the run to a named step instead of the next one.',
  },
  retry: {
    color: '#fd7e14', icon: 'bi-arrow-repeat', word: 'retry',
    hint: 'A condition asked for this same step to be sent again. The next card is the same step, one attempt later.',
  },
  stop: {
    color: '#adb5bd', icon: 'bi-slash-circle', word: 'stop',
    hint: 'A condition ended the run here, deliberately. Everything after this was never reached.',
  },
  fail: {
    color: '#dc3545', icon: 'bi-x-octagon', word: 'fail',
    hint: 'A condition ended the run here and called it a failure. Everything after this was never reached.',
  },
};

const OUTCOME_VARIANTS = {
  completed: 'success',
  stopped: 'secondary',
  capped: 'warning',
  failed: 'danger',
};

function actionOf(name) {
  const key = String(name || '').trim().toLowerCase();
  return ACTIONS[key] || null;
}

function statusVariant(status) {
  const code = Number(status);
  if (!code) return 'secondary';
  if (code < 300) return 'success';
  if (code < 400) return 'info';
  if (code < 500) return 'warning';
  return 'danger';
}

function formatBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatMs(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return null;
  if (n < 1000) return `${Math.round(n)} ms`;
  return `${(n / 1000).toFixed(1)} s`;
}

function formatWhen(value) {
  if (!value) return null;
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return String(value);
  // The zero time Go writes for "never" must never be printed as a date. It reaches a client as
  // 0001-01-01T00:00:00Z and renders as a plausible-looking timestamp in the year 1.
  if (at.getUTCFullYear() < 1970) return null;
  return at.toLocaleString();
}

// The ordinal suffix, so "2nd time through this step" reads as English rather than "2th".
function ordinal(n) {
  const num = Number(n);
  if (!Number.isFinite(num)) return String(n);
  const mod100 = num % 100;
  if (mod100 >= 11 && mod100 <= 13) return `${num}th`;
  switch (num % 10) {
    case 1: return `${num}st`;
    case 2: return `${num}nd`;
    case 3: return `${num}rd`;
    default: return `${num}th`;
  }
}

// The connector between one card and the next, and the whole point of the map: it says WHY the run
// went where it went. Rendered from the entry ABOVE it, because the action is recorded on the step
// that decided it.
function Connector({ entry, backwards }) {
  const spec = actionOf(entry.action);
  const color = spec ? spec.color : '#6c757d';
  const word = spec ? spec.word : (String(entry.action || '').trim() || 'no action recorded');
  const matched = String(entry.matched_when || '').trim();
  // matched_condition is -1 when no condition matched at all. That is not a failure - a step with
  // no conditions simply continues - but it is a different fact from a condition that fired, and the
  // two must not read the same.
  const fellThrough = Number(entry.matched_condition) < 0;

  const target = String(entry.action_target_name || entry.action_target || '').trim();

  return (
    <div className="d-flex" style={{ minHeight: '2rem' }}>
      <div style={{ width: '2rem', display: 'flex', justifyContent: 'center' }}>
        <div style={{ width: '2px', backgroundColor: color, opacity: 0.85 }} />
      </div>
      <div className="d-flex align-items-center flex-wrap py-1" style={{ gap: '0.35rem' }}>
        <span
          className="badge"
          style={{ backgroundColor: color, color: '#101418', fontSize: '0.6rem' }}
          title={spec ? spec.hint : 'The runner recorded an action this view does not know. It is printed as it came.'}
        >
          <i className={`bi ${spec ? spec.icon : 'bi-question-circle'} me-1`} />
          {word}
          {target ? ` → ${target}` : ''}
        </span>
        {backwards && (
          <span
            className="badge bg-warning text-dark"
            style={{ fontSize: '0.6rem' }}
            title="This jump goes BACKWARDS, to a step at or before the one that decided it. The flow loops here, and only the run caps end it."
          >
            <i className="bi bi-arrow-counterclockwise me-1" />
            loops back
          </span>
        )}
        {matched ? (
          <code className="text-info" style={{ fontSize: '0.63rem' }} title="The condition that matched this response.">
            {matched}
          </code>
        ) : (
          fellThrough && (
            <span
              className="text-white-50 fst-italic"
              style={{ fontSize: '0.63rem' }}
              title="No condition on that step matched this response, so the run fell through to the next step in order."
            >
              no condition matched
            </span>
          )
        )}
      </div>
    </div>
  );
}

// The end of the map. A run does not just stop: it completed, or a condition stopped it, or a cap
// ended it. "flow ended" with no reason is how an operator concludes the target is broken when it
// was their own flow, so the reason is printed here in the server's own words.
function Terminator({ run }) {
  const outcome = String(run.outcome || '').trim().toLowerCase();
  const variant = OUTCOME_VARIANTS[outcome] || 'secondary';
  const detail = String(run.stop_detail || '').trim();
  const reason = String(run.stop_reason || '').trim();
  return (
    <div className="d-flex">
      <div style={{ width: '2rem', display: 'flex', justifyContent: 'center' }}>
        <div style={{ width: '2px', height: '1rem', backgroundColor: BORDER_COLOR }} />
      </div>
      <div className="pb-1">
        <span className={`badge bg-${variant}`} style={{ fontSize: '0.62rem' }}>
          <i className="bi bi-flag-fill me-1" />
          run {outcome || 'ended'}
        </span>
        {detail && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.66rem' }}>{detail}</div>
        )}
        {!detail && reason && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.66rem' }}>{reason}</div>
        )}
      </div>
    </div>
  );
}

// One execution of one step.
function TraceCard({ entry, selected, onSelect }) {
  const sent = entry.sent !== false;
  const status = Number(entry.status) || 0;
  const size = formatBytes(entry.size_bytes);
  const took = formatMs(entry.time_ms);
  const attempt = Number(entry.attempt) || 1;
  const executions = Number(entry.executions) || 1;
  const problems = Array.isArray(entry.condition_problems) ? entry.condition_problems : [];
  const notes = Array.isArray(entry.notes) ? entry.notes : [];
  const substituted = Array.isArray(entry.substituted) ? entry.substituted : [];
  const captured = Array.isArray(entry.captured) ? entry.captured : [];
  const stepId = String(entry.step_id || '');

  // The reason nothing went out, when nothing went out. A card that shows no status and no reason
  // is indistinguishable from one whose response was lost.
  const notSentReason = String(entry.refusal || entry.skip_reason || entry.error || '').trim();

  return (
    <div className="d-flex">
      <div
        className="text-white-50 d-flex justify-content-center pt-1"
        style={{ width: '2rem', fontSize: '0.62rem', flexShrink: 0 }}
        title="Position in the run. This is execution order, not step order: a step reached twice appears twice."
      >
        {entry.sequence}
      </div>
      <div
        role={onSelect ? 'button' : undefined}
        tabIndex={onSelect ? 0 : undefined}
        onClick={onSelect ? () => onSelect(stepId) : undefined}
        onKeyDown={onSelect ? (e) => {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(stepId); }
        } : undefined}
        className="rounded px-2 py-1 flex-grow-1"
        style={{
          backgroundColor: CARD_BG,
          border: `1px solid ${selected ? SELECTED_COLOR : BORDER_COLOR}`,
          cursor: onSelect ? 'pointer' : 'default',
          minWidth: 0,
        }}
      >
        <div className="d-flex align-items-center" style={{ gap: '0.35rem' }}>
          <span className="text-white-50" style={{ fontSize: '0.62rem' }} title="The step's position in the flow.">
            step {entry.step_order}
          </span>
          <span className="text-white text-truncate flex-grow-1" style={{ fontSize: '0.74rem', minWidth: 0 }}>
            {String(entry.step_name || '').trim() || '(unnamed step)'}
          </span>
          {sent && status > 0 && (
            <span className={`badge bg-${statusVariant(status)}`} style={{ fontSize: '0.6rem' }}>
              {status}
            </span>
          )}
          {sent && status === 0 && (
            <span className="badge bg-dark border border-secondary text-white-50" style={{ fontSize: '0.6rem' }}
              title="Sent, but no status came back.">
              sent, no status
            </span>
          )}
          {!sent && (
            <span className="badge bg-warning text-dark" style={{ fontSize: '0.6rem' }}
              title="Nothing left the framework for this step on this run.">
              not sent
            </span>
          )}
        </div>

        <div className="d-flex flex-wrap align-items-center mt-1" style={{ gap: '0.3rem', fontSize: '0.62rem' }}>
          {attempt > 1 && (
            <span
              className="badge bg-warning text-dark"
              title="A retry. The same step was sent again after a condition asked for it."
            >
              attempt {attempt}
            </span>
          )}
          {executions > 1 && (
            <span
              className="badge bg-info text-dark"
              title="This run has now entered this step more than once, by a goto or a retry. Each entry is its own card."
            >
              {ordinal(executions)} time through
            </span>
          )}
          {took && <span className="text-white-50">{took}</span>}
          {size && <span className="text-white-50">{size}</span>}
          {captured.length > 0 && (
            <span className="text-info" title="Values this step pulled out of its response for later steps to use.">
              <i className="bi bi-download me-1" />
              captured {captured.length}
            </span>
          )}
          {substituted.length > 0 && (
            <span className="text-info" title={`Placeholders filled in before sending: ${substituted.join(', ')}`}>
              <i className="bi bi-braces me-1" />
              filled {substituted.length}
            </span>
          )}
        </div>

        {notSentReason && (
          <div className="text-warning mt-1" style={{ fontSize: '0.64rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {notSentReason}
          </div>
        )}
        {entry.message && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.64rem' }}>{entry.message}</div>
        )}
        {problems.map((problem) => (
          <div key={problem} className="text-danger mt-1" style={{ fontSize: '0.63rem' }}>
            <i className="bi bi-exclamation-octagon me-1" />
            {problem}
          </div>
        ))}
        {notes.length > 0 && (
          <ul className="text-white-50 mt-1 mb-0 ps-3" style={{ fontSize: '0.62rem' }}>
            {notes.map((note) => <li key={note}>{note}</li>)}
          </ul>
        )}
      </div>
    </div>
  );
}

// Is this goto a jump BACKWARDS - that is, does it close a loop?
//
// Read from the goto's OWN declared target, not from whatever card happens to come next. Inferring
// it from the next entry gets the one run that matters wrong: the runner checks its caps at the top
// of the loop and returns WITHOUT appending another entry (flowConditions.go), so when a backwards
// goto spins a step until it exhausts the per-step, max-execution or wall-clock cap, that goto is
// the LAST entry in the trace and has no next. Those capped runs are precisely the ones whose
// finding IS the cycle, so guessing from the next card hides the loop exactly where it is the point.
//
// seenBefore is the strongest signal and needs no step table: if the target has already executed in
// this run, the run is provably returning to where it has been.
function isBackwardsGoto(entry, next, orderById, seenBefore) {
  const spec = actionOf(entry.action);
  if (!spec || spec.word !== 'goto') return false;

  const target = String(entry.action_target || '').trim();
  if (target) {
    if (seenBefore) return true;
    const to = Number(orderById.get(target));
    if (Number.isFinite(to)) return to <= Number(entry.step_order);
  }
  // Last resort, for a trace recorded before the runner named its targets.
  return Boolean(next) && Number(next.step_order) <= Number(entry.step_order);
}

// steps is the flow's steps AS THEY ARE NOW, used for one thing only: naming the ones this run does
// not account for. It never supplies a card.
const BuiltFlowRunMap = ({ run, steps, stale, selectedStepId, onSelect }) => {
  const trace = useMemo(
    () => (Array.isArray(run && run.trace) ? run.trace.slice() : [])
      .sort((a, b) => Number(a.sequence) - Number(b.sequence)),
    [run]
  );

  // Steps in the flow that this run's trace says nothing about. On a CURRENT run that means the run
  // never reached them; on a stale one it may also mean they were added after it ran. Both readings
  // are given, because guessing which one applies would be this view inventing history.
  const unreached = useMemo(() => {
    const ran = new Set(trace.map((e) => String(e.step_id)));
    return (Array.isArray(steps) ? steps : [])
      .filter((s) => s && !ran.has(String(s.id)))
      .sort((a, b) => Number(a.step_order) - Number(b.step_order));
  }, [trace, steps]);

  // Step order by step id, so a goto's target can be placed relative to the step that jumped. The
  // trace fills in anything the current step list does not carry, which keeps this working when the
  // steps were not loaded and on a stale run whose target step has since been deleted.
  const orderById = useMemo(() => {
    const m = new Map();
    (Array.isArray(steps) ? steps : []).forEach((s) => {
      if (s && s.id !== undefined && s.id !== null) m.set(String(s.id), Number(s.step_order));
    });
    trace.forEach((e) => {
      const id = String(e.step_id || '');
      if (id && !m.has(id)) m.set(id, Number(e.step_order));
    });
    return m;
  }, [trace, steps]);

  if (!run) return null;

  const started = formatWhen(run.started_at);
  const warnings = Array.isArray(run.warnings) ? run.warnings : [];
  const sentCount = Number(run.requests_sent);
  const execCount = Number(run.executions);

  if (trace.length === 0) {
    // A run row with an empty trace is a real thing: the run was refused before its first step, or
    // the trace failed to encode when it was stored. Either way there is no map, and saying so is
    // better than an empty frame that reads as a flow with no steps.
    return (
      <div className="text-white-50 py-4 text-center" style={{ fontSize: '0.72rem' }}>
        <i className="bi bi-slash-circle d-block mb-2" style={{ fontSize: '1.4rem' }} />
        This run recorded no steps{started ? ` (it ran at ${started})` : ''}, so there is nothing to
        draw from it. {String(run.stop_detail || run.stop_reason || '').trim()}
      </div>
    );
  }

  return (
    <div>
      <div className="d-flex flex-wrap align-items-center mb-2" style={{ gap: '0.4rem', fontSize: '0.66rem' }}>
        <span className="text-white-50" style={{ letterSpacing: '0.04em' }}>THE RUN</span>
        {started && <span className="text-white-50">{started}</span>}
        {Number.isFinite(sentCount) && (
          <span className="badge bg-dark border border-secondary text-white-50" style={{ fontSize: '0.6rem' }}>
            {sentCount} request{sentCount === 1 ? '' : 's'} sent
          </span>
        )}
        {Number.isFinite(execCount) && execCount !== trace.length && (
          <span
            className="badge bg-dark border border-secondary text-white-50"
            style={{ fontSize: '0.6rem' }}
            title="The runner's own count of step executions. It differs from the number of cards only if part of the trace was not recorded."
          >
            {execCount} executions
          </span>
        )}
        {run.run_id && (
          <span className="text-white-50 font-monospace" style={{ fontSize: '0.6rem' }} title="The run this map is drawn from.">
            {String(run.run_id).slice(0, 8)}
          </span>
        )}
      </div>

      {stale && (
        <div
          className="border border-warning rounded px-2 py-1 mb-2 text-warning"
          style={{ fontSize: '0.68rem' }}
        >
          <i className="bi bi-clock-history me-1" />
          This map is from that run and a step has been edited since. It is a true record of what was
          sent then, and it is NOT what would be sent now. Run the flow again to make it current.
        </div>
      )}

      {warnings.map((warning) => (
        <div key={warning} className="text-warning mb-1" style={{ fontSize: '0.66rem' }}>
          <i className="bi bi-exclamation-triangle me-1" />
          {warning}
        </div>
      ))}

      {trace.map((entry, i) => {
        const next = i < trace.length - 1 ? trace[i + 1] : null;
        const target = String(entry.action_target || '').trim();
        const seenBefore = Boolean(target)
          && trace.slice(0, i + 1).some((e) => String(e.step_id || '') === target);
        return (
          <div key={`${entry.sequence}-${entry.step_id}`}>
            <TraceCard
              entry={entry}
              selected={Boolean(selectedStepId) && String(selectedStepId) === String(entry.step_id)}
              onSelect={onSelect}
            />
            <Connector
              entry={entry}
              backwards={isBackwardsGoto(entry, next, orderById, seenBefore)}
            />
          </div>
        );
      })}

      <Terminator run={run} />

      {unreached.length > 0 && (
        <div className="border-top border-secondary mt-3 pt-2">
          <div className="text-white-50" style={{ fontSize: '0.66rem' }}>
            <i className="bi bi-dash-circle me-1" />
            {unreached.length} step{unreached.length === 1 ? '' : 's'} in this flow
            {unreached.length === 1 ? ' is' : ' are'} not in this run&apos;s trace. That is not the
            same as passing: the run either branched around
            {unreached.length === 1 ? ' it' : ' them'}, or stopped first
            {stale ? ', or the step was added after the run' : ''}.
          </div>
          {unreached.map((step) => (
            <div key={step.id} className="text-white-50 mt-1 ps-3 text-truncate" style={{ fontSize: '0.65rem' }}>
              step {step.step_order} &middot; {String(step.name || '').trim() || '(unnamed step)'}
              {step.enabled === false && (
                <span className="badge bg-secondary ms-1" style={{ fontSize: '0.55rem' }}
                  title="Turned off, so a run skips it and it can never appear in a trace.">
                  off
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default BuiltFlowRunMap;
