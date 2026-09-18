import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Modal, Button, Form, InputGroup, Spinner, Badge, OverlayTrigger, Tooltip } from 'react-bootstrap';

// Request Flow Builder: the operator assembles a flow by hand.
//
// The passive detector reconstructs what the browser DID. The repeater replays one request. Neither
// lets an operator say "these four requests, in this order, with the token step two captured carried
// into step three, and I want to change the third one". That is what this screen is for, and it is
// the shape almost every access-control and business-logic test actually takes.
//
// Three columns, left to right, in the order the work happens:
//
//   FLOWS   the builder flows on this target. Two ways to make one: start empty, or copy a detected
//           flow in as editable steps. The second is the one that gets used.
//   STEPS   the ordered requests. Add, move, duplicate, delete, arm and disarm.
//   STEP    the selected step's raw bytes in a monospace editor, its variables, and its response.
//
// Four things this file exists to protect:
//
//   1. AN UNRESOLVED {{af:NAME}} IS NEVER A SURPRISE. A flow whose whole point is carrying a token
//      from step two into step three fails silently when step two's capture never fires and step
//      three sends the literal placeholder. The server refuses that send rather than making it, but
//      the operator still has to be told BEFORE they hit replay, on the step, naming the step that
//      was supposed to produce the value. buildVariableModel is that analysis and it runs over the
//      LIVE editor buffer, so the warning appears while the placeholder is still being typed.
//
//   2. WHAT IS IN THE EDITOR IS WHAT GETS SAVED. Nothing here reformats, re-orders headers or trims
//      whitespace. The one exception is the line terminator, because a browser textarea normalises
//      every terminator in its value to a bare LF; handleBufferChange puts the CRs back to match the
//      style the step was loaded with. Same rule, and the same reason, as the repeater.
//
//   3. UNSAVED BYTES ARE NOT THROWN AWAY BY A CLICK. Selecting another step, another flow, or
//      closing the modal with an edited buffer asks first.
//
//   4. A FLOW THAT CAN LOOP SAYS SO BEFORE IT RUNS, AND A RUN THAT LOOPED SAYS WHY IT STOPPED.
//      Conditions turn a straight line into a decision tree, and a goto that points backwards is a
//      loop. A loop against a live programme is a denial of service, which is out of scope on every
//      programme this framework is pointed at. So: the graph is walked at AUTHORING time and a cycle
//      is named the moment the goto that closes it is picked; the caps that will stop it are printed
//      next to the run button rather than discovered by hitting one; and every run comes back with a
//      trace that says which condition matched on each execution and, when a cap fired, which cap.
//      "Flow ended" with no reason is how an operator concludes the target is broken when it was
//      their own flow.

const BUILDER = '/api/request-flow-builder';

const MONO = 'Menlo, Consolas, "Courier New", monospace';

const DETECTED_FLOW_LIMIT = 200;
const CAPTURE_LIMIT = 300;

// The server's placeholder grammar, character for character:
//   authFlowVarPattern = \{\{af:([A-Za-z0-9_]{1,64})(?:\|(raw|url|json))?\}\}
// Copied rather than approximated, because a client regex that matched MORE than the server's would
// report a reference the server does not see, and one that matched less would miss the failure this
// panel exists to catch.
const VAR_PATTERN = /\{\{af:([A-Za-z0-9_]{1,64})(?:\|(raw|url|json))?\}\}/g;

const EXTRACTION_SOURCES = ['body', 'header', 'cookie'];
const EXTRACTION_DECODINGS = ['none', 'html', 'url'];

// ---------------------------------------------------------------------------
// Conditions: the vocabulary
//
// Structured controls, not an expression box. The operator is choosing from a small known set of
// fields, operators and actions, and a dropdown cannot produce a syntax error at 2am. The escape
// hatch is one field value (`raw`) that hands over a free-text expression, for the cases the
// dropdowns genuinely cannot say.
//
// ON SCREEN a rule is
//   { otherwise, field, key, op, value, expr, action, goto_step_id, message }
//
// ON THE WIRE it is the server's FlowCondition, which is a different thing entirely:
//   { when, then, target, message }
// where `when` is one string in the server's own expression grammar (`status == 302`,
// `header.Location ~ /login`, `*` for the catch-all) and `then` is the bare action word.
//
// conditionsToWire / conditionsFromWire below are the only two places that know both, and every
// call in and out of this screen goes through them. They exist because the two shapes share no
// field name at all: a rule sent in screen shape is stored as four empty strings, which is a step
// whose branching silently does nothing.
// ---------------------------------------------------------------------------

const CONDITION_FIELDS = [
  { value: 'status', label: 'status', hint: 'the response status code' },
  { value: 'header', label: 'header', hint: 'one response header, by name' },
  { value: 'body', label: 'body', hint: 'the response body' },
  { value: 'size', label: 'body size', hint: 'the response body length in bytes' },
  { value: 'time_ms', label: 'response time', hint: 'milliseconds the response took' },
  { value: 'raw', label: 'raw expression', hint: 'the escape hatch: an expression the server parses' },
];

const CONDITION_OPS = [
  { value: '==', label: 'is', needsValue: true },
  { value: '!=', label: 'is not', needsValue: true },
  { value: '>', label: '>', needsValue: true },
  { value: '>=', label: '>=', needsValue: true },
  { value: '<', label: '<', needsValue: true },
  { value: '<=', label: '<=', needsValue: true },
  { value: 'contains', label: 'contains', needsValue: true },
  { value: 'not_contains', label: 'does not contain', needsValue: true },
  { value: 'matches', label: 'matches (RE2)', needsValue: true },
  { value: 'exists', label: 'is present', needsValue: false },
];

// Which operators each field offers. Narrow on purpose: `status contains` is not a question anybody
// means to ask, and offering it is offering a way to write a rule that never fires.
//
// THERE IS NO "is absent". The server treats a header that was not sent as ABSENT rather than as "",
// and absent matches nothing at all - not even `!=` or `does not contain`. So there is no expression
// in the grammar that is true when a header is missing, and offering the operator one would be
// offering a rule that can never fire. Test for the header being PRESENT and put what you wanted for
// the missing case in the OTHERWISE row.
const FIELD_OPS = {
  status: ['==', '!=', '>', '>=', '<', '<='],
  time_ms: ['>', '>=', '<', '<=', '==', '!='],
  size: ['>', '>=', '<', '<=', '==', '!='],
  header: ['exists', '==', '!=', 'contains', 'not_contains', 'matches'],
  body: ['contains', 'not_contains', 'matches', '==', '!='],
  raw: [],
};

// The screen's operator names, and the server's. `exists` has no operator of its own: it is written
// as a regular expression that matches any value the header could hold, which is true when the
// header is there and false when it is not, because absent never matches.
const OP_TO_WIRE = {
  '==': '==', '!=': '!=', '>': '>', '>=': '>=', '<': '<', '<=': '<=',
  contains: '~', not_contains: '!~', matches: '=~', exists: '=~',
};
const OP_FROM_WIRE = {
  '==': '==', '!=': '!=', '>': '>', '>=': '>=', '<': '<', '<=': '<=',
  '~': 'contains', '!~': 'not_contains', '=~': 'matches',
};
const EXISTS_PATTERN = '(?s).*';

const CONDITION_ACTIONS = [
  { value: 'continue', label: 'continue', variant: 'secondary', describe: () => 'continue to the next step' },
  { value: 'goto', label: 'go to step', variant: 'info', describe: null },
  { value: 'retry', label: 'retry this step', variant: 'warning', describe: () => 'retry this step' },
  { value: 'stop', label: 'stop the run', variant: 'secondary', describe: null },
  { value: 'fail', label: 'fail the run', variant: 'danger', describe: null },
];

// The loop protection the server enforces, mirrored here so it can be PRINTED next to the run
// button. These are fallbacks and they match ResolveFlowRunCaps' defaults exactly; the real numbers
// come off the flow's own `caps` object and win. They are not settings, and there is no control
// anywhere in this screen that turns one off.
const DEFAULT_LIMITS = {
  max_executed_steps: 50,
  max_per_step: 10,
  max_retries: 3,
  retry_delay_ms: 1000,
  wall_clock_s: 600,
};

// The server's field names for the same four numbers (FlowRunCaps in flowConditions.go). Read
// through this rather than assumed, because a cap printed from a default while the server enforces
// another is a promise this screen cannot keep.
const CAP_FIELDS = {
  max_executed_steps: 'max_executions',
  max_per_step: 'per_step_max_executions',
  max_retries: 'retry_cap',
  retry_delay_ms: 'retry_delay_ms',
  wall_clock_s: 'wall_clock_s',
};

// Which cap fired, in the words the operator has to be told. Keyed by the server's own stop_reason
// codes (FlowStop* in flowConditions.go) so a run that stopped says the same thing the run bar
// promised it would say.
const CAP_LABELS = {
  max_executed_steps: 'executed-step budget',
  per_step_execution_cap: 'per-step execution cap',
  retry_cap: 'retry cap',
  wall_clock: 'wall-clock limit',
  engagement_request_budget: "programme's request budget",
};

// The stop reasons that are NOT caps: the flow did what it was told. These must not be rendered as
// "this run hit a cap", which would send the operator hunting for a loop that is not there.
const NON_CAP_STOPS = {
  completed: '',
  stopped_by_condition: 'A condition stopped the run.',
  failed_by_condition: 'A condition failed the run.',
  goto_target_missing: 'A goto named a step that is not in this flow, so the run could not continue.',
};

const STATUS_MIN = 100;
const STATUS_MAX = 599;

const EMPTY_RULES = [];

// One text style shared by the editor and every raw pane, so bytes look the same wherever they are.
const MONO_STYLE = {
  fontFamily: MONO,
  fontSize: '0.78rem',
  lineHeight: '1.35',
  padding: '0.5rem',
  margin: 0,
  border: 'none',
  letterSpacing: 'normal',
  tabSize: 4,
  whiteSpace: 'pre',
};

const EMPTY_STEPS = [];

function statusVariant(status) {
  const code = Number(status);
  if (!code) return 'secondary';
  if (code < 300) return 'success';
  if (code < 400) return 'info';
  if (code < 500) return 'warning';
  return 'danger';
}

function statusClassVariant(key) {
  const first = String(key || '').trim().charAt(0);
  if (first === '2') return 'success';
  if (first === '3') return 'info';
  if (first === '4') return 'warning';
  if (first === '5') return 'danger';
  return 'secondary';
}

function formatTimestamp(value) {
  if (!value) return null;
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return String(value);
  return at.toLocaleString();
}

function byteLength(text) {
  if (!text) return 0;
  try {
    return new TextEncoder().encode(text).length;
  } catch (err) {
    return text.length;
  }
}

// Reads the request line off bytes that may be mid-edit and may not parse. Same tolerance as the
// server's requestFlowMethodOf: a step being typed still has to render in the list.
function parseRequestLine(raw) {
  const text = String(raw == null ? '' : raw);
  const firstLine = text.split(/\r\n|\n|\r/, 1)[0] || '';
  const bits = firstLine.trim().split(/\s+/);
  const method = (bits[0] || '').toUpperCase();
  const target = bits[1] || '';
  return { method, target };
}

// Every distinct {{af:NAME}} in these bytes, in the order they first appear.
function parsePlaceholders(raw) {
  const text = String(raw == null ? '' : raw);
  if (!text.includes('{{af:')) return [];
  const names = [];
  const seen = new Set();
  VAR_PATTERN.lastIndex = 0;
  let match = VAR_PATTERN.exec(text);
  while (match) {
    if (!seen.has(match[1])) {
      seen.add(match[1]);
      names.push(match[1]);
    }
    match = VAR_PATTERN.exec(text);
  }
  return names;
}

// ---------------------------------------------------------------------------
// The variable model
//
// Variables ARE the flow. A list of requests with no values carried between them is the repeater run
// four times. So every reference is classified against every definition, and the four ways a
// reference can be broken are named separately, because the fix is different for each one:
//
//   provider_off  the capture exists but its step is disarmed, so it will never run.  Arm it.
//   too_late      the capture exists but on a LATER step.                             Move it.
//   self          the step captures the value out of its own response, which does not
//                 exist yet at the moment the request is sent.                        Split it.
//   undefined     nothing captures it at all.                                         Add a rule.
//
// "N unresolved" would be true and useless. Naming the step that was supposed to produce the value
// is the difference between a warning and an instruction.
// ---------------------------------------------------------------------------

function buildVariableModel(steps, overrides) {
  const rawOf = (step) => (
    overrides && Object.prototype.hasOwnProperty.call(overrides, step.id)
      ? overrides[step.id]
      : (step.raw_request || '')
  );

  // name -> every step that captures it, in flow order.
  const definitions = new Map();
  steps.forEach((step) => {
    (step.extractions || []).forEach((rule) => {
      if (!rule || !rule.name) return;
      const list = definitions.get(rule.name) || [];
      list.push({
        stepId: step.id,
        order: step.step_order,
        stepName: step.name || '',
        enabled: !!step.enabled,
        optional: !!rule.optional,
      });
      definitions.set(rule.name, list);
    });
  });

  const byStep = new Map();
  let brokenSteps = 0;

  steps.forEach((step) => {
    const refs = parsePlaceholders(rawOf(step)).map((name) => {
      const all = definitions.get(name) || [];

      // Latest earlier ARMED definition wins: a disarmed step is skipped on replay, so its captures
      // never fire and it cannot be the provider of anything.
      const live = all.filter((d) => d.order < step.step_order && d.enabled);
      if (live.length) {
        const provider = live[live.length - 1];
        return { name, state: provider.optional ? 'optional' : 'ok', provider };
      }
      const off = all.filter((d) => d.order < step.step_order && !d.enabled);
      if (off.length) return { name, state: 'provider_off', provider: off[off.length - 1] };
      const self = all.filter((d) => d.order === step.step_order);
      if (self.length) return { name, state: 'self', provider: self[0] };
      const later = all.filter((d) => d.order > step.step_order);
      if (later.length) return { name, state: 'too_late', provider: later[0] };
      return { name, state: 'undefined', provider: null };
    });

    // What this step can legitimately reach for: every name an earlier armed step captures.
    const available = [];
    const seen = new Set();
    steps.forEach((earlier) => {
      if (earlier.step_order >= step.step_order || !earlier.enabled) return;
      (earlier.extractions || []).forEach((rule) => {
        if (!rule || !rule.name || seen.has(rule.name)) return;
        seen.add(rule.name);
        available.push({ name: rule.name, order: earlier.step_order, optional: !!rule.optional });
      });
    });

    const broken = refs.filter((r) => r.state !== 'ok' && r.state !== 'optional').length;
    if (broken > 0) brokenSteps += 1;
    byStep.set(step.id, { refs, available, broken });
  });

  return { definitions, byStep, brokenSteps };
}

function referenceProblem(ref) {
  const at = ref.provider ? `step ${ref.provider.order}` : '';
  switch (ref.state) {
    case 'ok':
      return '';
    case 'optional':
      return `captured by ${at}, by a rule marked optional. If it does not match, this step is refused rather than sent with a blank value.`;
    case 'provider_off':
      return `the only step that captures this is ${at}, and that step is turned OFF, so it never runs. Turn it on.`;
    case 'self':
      return 'this step captures this value out of its OWN response, which does not exist yet when the request is sent. Capture it on an earlier step.';
    case 'too_late':
      return `captured by ${at}, which runs AFTER this one. Move that step earlier.`;
    default:
      return 'nothing in this flow captures this value. The replay refuses this step rather than sending the literal placeholder at the target.';
  }
}

// ---------------------------------------------------------------------------
// The condition model
//
// Three questions, answered without the network, over the LIVE editor state so every answer lands
// while the operator is still looking at the thing that caused it:
//
//   IS THIS RULE VALID?      A goto with nothing picked, a header test with no header name, a
//                            comparison with nothing to compare against. These block the save,
//                            because a half-written rule saved is a rule that fires wrong.
//
//   CAN THIS RULE EVER RUN?  First match wins, so `status >= 400` above `status == 403` means the
//                            403 rule is dead code. Proved rather than guessed: for `status` the
//                            matched set is computed exactly over 100..599 and tested for containment
//                            in what the rules above it already cover. Nothing is claimed unreachable
//                            unless it is.
//
//   DOES THIS GOTO CLOSE A LOOP?  The flow's steps plus its gotos form a graph. Fallthrough edges
//                            only ever point forward, so a cycle must contain a backward or self
//                            goto. Found by walk, reported by NAME, at the moment the goto is picked.
//                            Never blocked: a bounded retry loop is a legitimate thing to build. The
//                            operator just has to know they built one before they run it.
// ---------------------------------------------------------------------------

function fieldSpec(field) {
  return CONDITION_FIELDS.find((f) => f.value === field) || CONDITION_FIELDS[0];
}

function opSpec(op) {
  return CONDITION_OPS.find((o) => o.value === op) || null;
}

function actionSpec(action) {
  return CONDITION_ACTIONS.find((a) => a.value === action) || CONDITION_ACTIONS[0];
}

function opsForField(field) {
  const allowed = FIELD_OPS[field] || FIELD_OPS.status;
  return allowed.map((value) => opSpec(value)).filter(Boolean);
}

function blankRule() {
  return {
    otherwise: false,
    field: 'status',
    key: '',
    op: '==',
    value: '',
    expr: '',
    action: 'continue',
    goto_step_id: '',
    message: '',
  };
}

function catchAllRule() {
  return { ...blankRule(), otherwise: true, field: '', op: '' };
}

// ---------------------------------------------------------------------------
// Screen shape <-> wire shape
// ---------------------------------------------------------------------------

// How a value is written into an expression.
//
// The server takes everything after the operator, trims it, and strips ONE surrounding pair of
// matching quotes. There is no escape character, so quoting is used only where leaving it out would
// change the value, and never otherwise: an empty value (which is a parse error unquoted), a value
// with leading or trailing space (which would be trimmed away), and a value that already begins and
// ends with the same quote character (which would be unwrapped). Everything else, spaces and all,
// goes through as typed, because the server does not split the value on whitespace.
function quoteConditionValue(value) {
  const text = String(value == null ? '' : value);
  const wrapped = text.length >= 2
    && ((text[0] === '"' && text[text.length - 1] === '"')
      || (text[0] === "'" && text[text.length - 1] === "'"));
  if (text !== '' && text.trim() === text && !wrapped) return text;
  if (!text.includes('"')) return `"${text}"`;
  if (!text.includes("'")) return `'${text}'`;
  // Both quote characters are in the value, so there is no pair that can wrap it. Sent bare: the
  // server trims the ends, which is the only difference, and saying nothing would be worse than a
  // value whose surrounding spaces were dropped.
  return text;
}

function unquoteConditionValue(value) {
  const text = String(value == null ? '' : value).trim();
  if (text.length >= 2
    && ((text[0] === '"' && text[text.length - 1] === '"')
      || (text[0] === "'" && text[text.length - 1] === "'"))) {
    return text.slice(1, -1);
  }
  return text;
}

// One screen rule -> the server's `when` string.
function ruleToWhen(rule) {
  if (!rule) return '';
  // The catch-all keeps whatever spelling it arrived with (`*` or `else`), so re-saving an
  // untouched flow does not rewrite it and light up the unsaved badge.
  if (rule.otherwise) return rule.expr || '*';
  if (rule.field === 'raw') return String(rule.expr || '').trim();

  const field = rule.field === 'header' ? `header.${String(rule.key || '').trim()}` : rule.field;
  if (rule.op === 'exists') return `${field} =~ ${EXISTS_PATTERN}`;
  const op = OP_TO_WIRE[rule.op];
  if (!op) return '';
  return `${field} ${op} ${quoteConditionValue(rule.value)}`;
}

// The full list, in evaluation order, in the shape AddRequestFlowStep and UpdateRequestFlowStep
// decode. `target` is emitted for a goto and for nothing else: the server refuses a condition that
// names a target its action cannot use.
function conditionsToWire(rules) {
  return (Array.isArray(rules) ? rules : EMPTY_RULES).map((rule) => {
    const action = String((rule && rule.action) || 'continue');
    const out = { when: ruleToWhen(rule), then: action };
    if (action === 'goto' && rule.goto_step_id) out.target = String(rule.goto_step_id);
    if (rule && rule.message) out.message = String(rule.message);
    return out;
  });
}

// Only the shapes this screen's dropdowns can produce are decoded back into them. A step reference
// (`step.Login.status`), a quoted field, or anything hand-typed stays in the raw-expression box
// EXACTLY as the server holds it, which is the only way an expression this screen cannot draw
// survives being opened and saved again.
const WHEN_PATTERN = /^(status|body|size|time_ms|header\.[^\s=!<>~]+)\s*(>=|<=|==|!=|!~|=~|>|<|~)\s*([\s\S]*)$/;

function whenToRule(when) {
  const text = String(when == null ? '' : when).trim();
  if (!text) return { ...blankRule(), field: 'raw', expr: '' };
  if (text === '*' || text.toLowerCase() === 'else') {
    return { ...catchAllRule(), expr: text };
  }

  const match = WHEN_PATTERN.exec(text);
  if (!match) return { ...blankRule(), field: 'raw', expr: text };

  let field = match[1];
  let key = '';
  if (field.toLowerCase().startsWith('header.')) {
    key = field.slice('header.'.length).replace(/^["']|["']$/g, '');
    field = 'header';
  }
  let op = OP_FROM_WIRE[match[2]];
  let value = unquoteConditionValue(match[3]);
  if (field === 'header' && op === 'matches' && value === EXISTS_PATTERN) {
    op = 'exists';
    value = '';
  }
  // An operator the field does not offer (`body > 5`) is legal in the grammar and unrepresentable in
  // these dropdowns. Kept as raw rather than forced into a control that would rewrite it on save.
  if (!op || !(FIELD_OPS[field] || []).includes(op)) {
    return { ...blankRule(), field: 'raw', expr: text };
  }
  return { ...blankRule(), field, key, op, value };
}

// The server's FlowCondition list -> screen rules. `target` is resolved to a step id so the goto
// picker has something to select: the server accepts an id OR a name, and a flow authored elsewhere
// may well carry the name.
function conditionsFromWire(list, steps) {
  const rows = Array.isArray(list) ? list : EMPTY_RULES;
  if (!rows.length) return EMPTY_RULES;
  const all = Array.isArray(steps) ? steps : EMPTY_STEPS;
  const byName = new Map();
  all.forEach((step) => {
    const name = String((step && step.name) || '').trim().toLowerCase();
    if (!name) return;
    // Two steps of the same name is an ambiguity the server REFUSES rather than resolves, so it is
    // left unresolved here too and the goto reads as pointing at nothing.
    byName.set(name, byName.has(name) ? null : step.id);
  });

  return rows.map((cond) => {
    const rule = whenToRule(cond && cond.when);
    const action = String((cond && cond.then) || 'continue').trim().toLowerCase();
    rule.action = CONDITION_ACTIONS.some((a) => a.value === action) ? action : 'continue';
    rule.message = String((cond && cond.message) || '');
    if (rule.action === 'goto') {
      const target = String((cond && cond.target) || '').trim();
      const known = all.some((step) => step && step.id === target);
      rule.goto_step_id = known ? target : (byName.get(target.toLowerCase()) || target);
    }
    return rule;
  });
}

// Same reason canonicalExtractions exists: the server marks most of these `omitempty`, so a rule
// saved with otherwise:false and an empty message comes back with neither key. A naive stringify
// comparison then latches the "unsaved" badge on for the rest of the session.
function canonicalConditions(rules) {
  return JSON.stringify((rules || []).map((rule) => ({
    otherwise: !!rule.otherwise,
    field: rule.otherwise ? '' : (rule.field || 'status'),
    key: rule.key || '',
    op: rule.otherwise ? '' : (rule.op || ''),
    value: rule.value == null ? '' : String(rule.value),
    expr: rule.expr || '',
    action: rule.action || 'continue',
    goto_step_id: rule.goto_step_id || '',
    message: rule.message || '',
  })));
}

function stepLabel(step) {
  if (!step) return 'a step that is not in this flow';
  const name = step.name || parseRequestLine(step.raw_request).target || '';
  return `step ${step.step_order}${name ? ` (${name})` : ''}`;
}

function describeWhen(rule) {
  if (!rule) return '';
  if (rule.otherwise) return 'OTHERWISE';
  if (rule.field === 'raw') return `WHEN ${rule.expr || '(no expression)'}`;
  const spec = opSpec(rule.op);
  const left = rule.field === 'header'
    ? `header ${rule.key || '(no name)'}`
    : fieldSpec(rule.field).label;
  if (spec && !spec.needsValue) return `WHEN ${left} ${spec.label}`;
  const value = (rule.value == null || rule.value === '') ? '(no value)' : rule.value;
  return `WHEN ${left} ${rule.op || '?'} ${value}`;
}

function describeThen(rule, labelOf) {
  if (!rule) return '';
  switch (rule.action) {
    case 'goto':
      return `go to ${rule.goto_step_id ? labelOf(rule.goto_step_id) : '(no step picked)'}`;
    case 'retry':
      return 'retry this step';
    case 'stop':
      return rule.message ? `stop the run: "${rule.message}"` : 'stop the run';
    case 'fail':
      return rule.message ? `fail the run: "${rule.message}"` : 'fail the run';
    default:
      return 'continue';
  }
}

function describeCondition(rule, labelOf) {
  return `${describeWhen(rule)} THEN ${describeThen(rule, labelOf)}`;
}

// Every status code this rule matches, as a flat mask over 100..599. Null when the rule cannot be
// modelled, and null is the honest answer: an unmodelled rule contributes nothing to coverage, so
// the only mistake it can cause is failing to report an unreachable rule, never inventing one.
function statusMask(op, value) {
  const target = Number(String(value == null ? '' : value).trim());
  if (!Number.isFinite(target)) return null;
  const mask = new Uint8Array(STATUS_MAX - STATUS_MIN + 1);
  for (let code = STATUS_MIN; code <= STATUS_MAX; code += 1) {
    let hit;
    switch (op) {
      case '==': hit = code === target; break;
      case '!=': hit = code !== target; break;
      case '>': hit = code > target; break;
      case '>=': hit = code >= target; break;
      case '<': hit = code < target; break;
      case '<=': hit = code <= target; break;
      default: return null;
    }
    if (hit) mask[code - STATUS_MIN] = 1;
  }
  return mask;
}

function maskIsEmpty(mask) {
  for (let i = 0; i < mask.length; i += 1) if (mask[i]) return false;
  return true;
}

function maskCoveredBy(mask, cover) {
  for (let i = 0; i < mask.length; i += 1) if (mask[i] && !cover[i]) return false;
  return true;
}

// The identity of a rule's left-hand side, for the "you already wrote this one" check. Actions are
// deliberately not part of it: two rules with the same test and different actions is exactly the
// mistake worth reporting, because only the first one will ever fire.
// The separator is a character no header name, operator or operator-typed value can contain, so two
// different rules cannot collide into one key. Built at runtime rather than written as a literal NUL
// byte in the source, which some tooling treats as the end of the file.
const RULE_KEY_SEP = String.fromCharCode(0);

function ruleTestKey(rule) {
  if (rule.otherwise) return 'otherwise';
  if (rule.field === 'raw') return `raw${RULE_KEY_SEP}${rule.expr || ''}`;
  return [
    rule.field || '', rule.key || '', rule.op || '',
    rule.value == null ? '' : String(rule.value),
  ].join(RULE_KEY_SEP);
}

// One step's rules, judged. Returns issues keyed by rule index plus the counts the badges need.
function analyzeConditionRules(rules, stepsById, selfStepId) {
  const list = Array.isArray(rules) ? rules : EMPTY_RULES;
  const issues = [];
  const add = (index, level, text, kind) => { issues.push({ index, level, text, kind: kind || '' }); };

  let catchAllAt = -1;
  const statusCover = new Uint8Array(STATUS_MAX - STATUS_MIN + 1);
  const statusRules = [];
  const seenTests = new Map();
  let blanketAt = -1;

  list.forEach((rule, index) => {
    const spec = opSpec(rule.op);

    // ---- validity ----------------------------------------------------------
    if (rule.otherwise) {
      if (catchAllAt >= 0) {
        add(index, 'error', `A flow step can only have one OTHERWISE. Rule ${catchAllAt + 1} is already it, `
          + 'and this one can never run. Delete one of them.');
      } else {
        catchAllAt = index;
        if (index !== list.length - 1) {
          add(index, 'error', `OTHERWISE has to be the LAST rule, because it always matches. `
            + `Rule${list.length - index > 2 ? 's' : ''} ${index + 2}${list.length - index > 2 ? `-${list.length}` : ''} below it can never run. Move it to the bottom.`);
        }
      }
    } else if (rule.field === 'raw') {
      if (!String(rule.expr || '').trim()) {
        add(index, 'error', 'This rule is a raw expression with nothing in it.');
      }
    } else {
      if (rule.field === 'header' && !String(rule.key || '').trim()) {
        add(index, 'error', 'This rule tests a header but does not say which header.');
      }
      if (!spec) {
        add(index, 'error', `"${rule.op}" is not an operator this field understands.`);
      } else if (spec.needsValue && String(rule.value == null ? '' : rule.value).trim() === '') {
        add(index, 'error', 'This rule has nothing to compare against. Fill in the value.');
      } else if (spec.needsValue && ['>', '<', '>=', '<='].includes(rule.op)
        && !Number.isFinite(Number(String(rule.value).trim()))) {
        // The server refuses this at save time. Caught here so the reason arrives while the
        // operator is still looking at the box, rather than as a 400 after they press Save.
        add(index, 'error', `${rule.op} only compares numbers, and "${String(rule.value).trim()}" is `
          + 'not one. Use "is" or "contains" to compare text.');
      }
      if (spec && rule.op === 'matches' && String(rule.value || '').trim()) {
        try {
          // eslint-disable-next-line no-new
          new RegExp(String(rule.value));
        } catch (err) {
          add(index, 'warn', `This pattern does not parse as a regular expression here (${err.message}). `
            + 'The server uses RE2, which is close but not identical, so check it before you rely on it.');
        }
      }
    }

    // ---- the action --------------------------------------------------------
    if (rule.action === 'goto') {
      if (!rule.goto_step_id) {
        add(index, 'error', 'This rule says go to a step but no step is picked.');
      } else if (!stepsById.has(rule.goto_step_id)) {
        add(index, 'error', 'This rule points at a step that is not in this flow any more. It was '
          + 'probably deleted. Pick a step that exists, or delete the rule.');
      } else {
        const target = stepsById.get(rule.goto_step_id);
        if (!target.enabled) {
          add(index, 'warn', `${stepLabel(target)} is turned OFF, so jumping there sends nothing and its `
            + 'captures never fire. Arm it, or pick a different step.');
        }
        if (rule.goto_step_id === selfStepId) {
          add(index, 'warn', 'This goes to the step it is on, which is a loop. The per-step execution '
            + 'cap will stop it, mid-flow, rather than it running forever. Use "retry this step" if a '
            + 'bounded retry is what you meant: that one is capped on purpose and waits between tries.');
        }
      }
    }
    if ((rule.action === 'fail' || rule.action === 'stop') && !String(rule.message || '').trim()) {
      add(index, 'warn', 'No reason given. A run that stops here will say so with nothing to say why, '
        + 'which reads like the target broke rather than like your rule fired.');
    }

    // ---- reachability ------------------------------------------------------
    if (blanketAt >= 0) {
      add(index, 'warn', `This rule can never run: rule ${blanketAt + 1} above it matches everything.`, 'unreachable');
    } else {
      const dupeAt = seenTests.get(ruleTestKey(rule));
      if (dupeAt != null) {
        add(index, 'warn', `This rule can never run: rule ${dupeAt + 1} above it asks exactly the same `
          + 'question, and the first match wins.', 'unreachable');
      } else if (rule.field === 'status' && spec) {
        const mask = statusMask(rule.op, rule.value);
        if (mask && !maskIsEmpty(mask)) {
          if (maskCoveredBy(mask, statusCover)) {
            const single = statusRules.find((prior) => maskCoveredBy(mask, prior.mask));
            add(index, 'warn', single
              ? `This rule can never run: rule ${single.index + 1} (${describeWhen(single.rule).replace(/^WHEN /, '')}) `
                + 'already matches every status this one could.'
              : 'This rule can never run: the status rules above it already match every status this one could.',
            'unreachable');
          }
        } else if (mask && maskIsEmpty(mask)) {
          add(index, 'warn', 'This rule matches no status code at all, so it can never fire.', 'unreachable');
        }
      }
    }

    if (rule.otherwise) blanketAt = blanketAt >= 0 ? blanketAt : index;
    if (seenTests.get(ruleTestKey(rule)) == null) seenTests.set(ruleTestKey(rule), index);
    if (!rule.otherwise && rule.field === 'status' && spec) {
      const mask = statusMask(rule.op, rule.value);
      if (mask) {
        statusRules.push({ index, rule, mask });
        for (let i = 0; i < mask.length; i += 1) if (mask[i]) statusCover[i] = 1;
      }
    }
  });

  const byIndex = new Map();
  issues.forEach((issue) => {
    const list2 = byIndex.get(issue.index) || [];
    list2.push(issue);
    byIndex.set(issue.index, list2);
  });

  return {
    rules: list,
    issues,
    byIndex,
    errors: issues.filter((i) => i.level === 'error').length,
    warnings: issues.filter((i) => i.level === 'warn').length,
    hasCatchAll: catchAllAt >= 0,
    catchAllAt,
  };
}

// The flow's graph, and any cycle in it.
//
// Edges: an explicit `goto`, an explicit `continue` to the next step, and the implicit fallthrough to
// the next step that exists whenever no rule is guaranteed to match. `retry` is NOT an edge: it is a
// self-loop by definition and it is the one loop the server bounds on purpose, so reporting it would
// put a cycle warning on every flow that uses the feature and train the operator to ignore the panel.
function findConditionCycles(steps) {
  const order = steps.map((s) => s.id);
  const known = new Set(order);
  const edges = new Map();

  steps.forEach((step, i) => {
    const next = i + 1 < order.length ? order[i + 1] : null;
    const out = [];
    let alwaysMatches = false;
    (step.conditions || EMPTY_RULES).forEach((rule) => {
      if (rule.otherwise) alwaysMatches = true;
      if (rule.action === 'goto' && rule.goto_step_id && known.has(rule.goto_step_id)) {
        out.push(rule.goto_step_id);
      } else if (rule.action === 'continue' && next) {
        out.push(next);
      }
    });
    if (!alwaysMatches && next) out.push(next);
    edges.set(step.id, Array.from(new Set(out)));
  });

  const colour = new Map();
  const path = [];
  const cycles = [];
  const seen = new Set();

  const visit = (id) => {
    colour.set(id, 1);
    path.push(id);
    (edges.get(id) || []).forEach((next) => {
      const state = colour.get(next) || 0;
      if (state === 1) {
        const from = path.indexOf(next);
        if (from >= 0) {
          const loop = path.slice(from).concat([next]);
          const key = Array.from(new Set(loop)).sort().join('|');
          if (!seen.has(key)) {
            seen.add(key);
            cycles.push(loop);
          }
        }
      } else if (state === 0) {
        visit(next);
      }
    });
    path.pop();
    colour.set(id, 2);
  };

  order.forEach((id) => { if (!colour.get(id)) visit(id); });
  return cycles;
}

// Everything the conditions UI needs, over the projected flow: the saved steps with the rules
// currently in the editor swapped in for the selected one, so picking a goto target warns about the
// loop it just closed before anything is saved.
function buildConditionModel(steps, selectedStepId, liveRules) {
  const projected = steps.map((step) => ({
    ...step,
    conditions: (step.id === selectedStepId ? liveRules : step.conditions) || EMPTY_RULES,
  }));
  const byId = new Map(projected.map((step) => [step.id, step]));
  const labelOf = (id) => stepLabel(byId.get(id));

  const byStep = new Map();
  let errorSteps = 0;
  let warnSteps = 0;
  let ruleCount = 0;

  projected.forEach((step) => {
    const analysis = analyzeConditionRules(step.conditions, byId, step.id);
    ruleCount += (step.conditions || EMPTY_RULES).length;
    if (analysis.errors > 0) errorSteps += 1;
    else if (analysis.warnings > 0) warnSteps += 1;
    byStep.set(step.id, analysis);
  });

  const cyclesByStep = new Map();
  const cycles = findConditionCycles(projected).map((loop) => {
    const entry = {
      ids: Array.from(new Set(loop)),
      text: loop.map(labelOf).join(' → '),
    };
    entry.ids.forEach((id) => {
      const list = cyclesByStep.get(id) || [];
      list.push(entry);
      cyclesByStep.set(id, list);
    });
    return entry;
  });

  return { byStep, cycles, cyclesByStep, errorSteps, warnSteps, ruleCount, labelOf, steps: projected };
}

// ---------------------------------------------------------------------------
// The trace
//
// A branching run is unexplainable without one. The server sends it; this normalises whatever it
// sent into one shape, and when it sent nothing, reconstructs what it can from the step rows and
// SAYS that is what it did rather than presenting a guess as a record.
// ---------------------------------------------------------------------------

function pick(row, ...names) {
  for (let i = 0; i < names.length; i += 1) {
    const value = row[names[i]];
    if (value !== undefined && value !== null) return value;
  }
  return null;
}

function normalizeTrace(data, steps) {
  const byId = new Map(steps.map((step) => [step.id, step]));
  // Resolved against the steps THIS RUN returned, so the record keeps naming what it named at the
  // time even after the flow is edited underneath it.
  const labelOf = (id) => stepLabel(byId.get(id));

  // THE TRACE IS UNDER `run`. The replay answers with {flow, steps, refused_hosts, scope_boundary,
  // run, outcome, stop_reason, stop_detail}; the executions are run.trace. The top level is searched
  // too, because outcome/stop_reason/stop_detail ARE lifted out of run for exactly this reason.
  const runPart = (data && data.run && typeof data.run === 'object') ? data.run : {};
  const rawRows = Array.isArray(runPart.trace) ? runPart.trace
    : Array.isArray(data && data.trace) ? data.trace
      : Array.isArray(data && data.executions) ? data.executions : null;

  // stop_reason is the CODE (max_executed_steps, per_step_execution_cap, retry_cap, wall_clock,
  // engagement_request_budget, and the non-cap endings) and stop_detail is the sentence that names
  // it in words. Both are carried: the code decides which explanation to draw, the sentence is the
  // explanation the server itself wrote.
  const capCode = String(pick(data || {}, 'stop_reason', 'stopped_reason', 'cap_hit', 'stopped_by')
    || pick(runPart, 'stop_reason') || '');
  const stopReason = String(pick(data || {}, 'stop_detail', 'stopped_detail')
    || pick(runPart, 'stop_detail') || '');
  const outcome = String(pick(data || {}, 'outcome') || pick(runPart, 'outcome') || '');

  const rows = (rawRows || []).map((row, i) => {
    const stepId = String(pick(row, 'step_id', 'stepId') || '');
    const step = byId.get(stepId) || null;
    // `matched_condition` is the INDEX of the rule that fired, and -1 when none did. It is not the
    // rule object: the rule the server evaluated reaches this screen as `matched_when`, the
    // expression text, which is why the row below carries that rather than a reconstructed rule.
    const matchedIndexRaw = pick(row, 'matched_condition', 'matched_condition_index',
      'condition_index', 'matched_index', 'rule_index');
    const matchedIndex = matchedIndexRaw == null ? null : Number(matchedIndexRaw);
    const { method, target } = parseRequestLine(step ? step.raw_request : '');
    return {
      matchedWhen: String(pick(row, 'matched_when') || ''),
      conditionProblems: Array.isArray(row.condition_problems) ? row.condition_problems : EMPTY_RULES,
      seq: Number(pick(row, 'seq', 'sequence', 'n') || i + 1),
      stepId,
      stepOrder: Number(pick(row, 'step_order', 'stepOrder') || (step ? step.step_order : 0)),
      stepName: String(pick(row, 'name', 'step_name') || (step ? step.name : '') || ''),
      method: String(pick(row, 'method') || method || ''),
      target: String(pick(row, 'target', 'path', 'url') || target || ''),
      attempt: Number(pick(row, 'attempt', 'try') || 1),
      status: pick(row, 'status', 'response_status', 'status_code'),
      timeMs: pick(row, 'time_ms', 'response_time_ms', 'duration_ms'),
      skipped: !!pick(row, 'skipped'),
      skipReason: String(pick(row, 'skip_reason', 'refusal', 'reason') || ''),
      error: String(pick(row, 'error') || ''),
      matchedIndex: Number.isFinite(matchedIndex) && matchedIndex >= 0 ? matchedIndex : null,
      action: String(pick(row, 'action') || ''),
      // `action_target` is the step a goto went to. `action_target_name` is its name at the time,
      // which is what the row falls back to when the step has since been deleted and there is
      // nothing left to look up.
      gotoStepId: String(pick(row, 'action_target', 'goto_step_id', 'next_step_id') || ''),
      gotoStepName: String(pick(row, 'action_target_name') || ''),
      message: String(pick(row, 'message', 'note') || ''),
      delayMs: pick(row, 'delay_ms', 'waited_ms'),
    };
  });

  // Only a CAP gets the "this run hit a cap" panel. "completed", a condition that stopped or failed
  // the run, and a goto with no destination are endings, not caps, and drawing them as a loop that
  // ran out of budget sends the operator looking for a loop that is not there.
  const capLabel = CAP_LABELS[capCode] || '';

  if (rawRows) {
    return {
      at: new Date().toISOString(),
      rows,
      reconstructed: false,
      capCode,
      capLabel,
      outcome,
      stopReason,
      stopNote: NON_CAP_STOPS[capCode] || '',
      labelOf,
    };
  }

  // No trace came back. Rather than an empty panel that reads as "the run did nothing", show what
  // the step rows do prove: which steps ran, in order, and what they answered. Labelled as what it
  // is, because a reconstruction that is presented as a record is worse than no record.
  const reconstructed = steps
    .filter((step) => step.enabled || step.skipped || step.response_status || step.error)
    .map((step, i) => {
      const { method, target } = parseRequestLine(step.raw_request);
      return {
        seq: i + 1,
        stepId: step.id,
        stepOrder: step.step_order,
        stepName: step.name || '',
        method,
        target,
        attempt: 1,
        status: step.response_status,
        timeMs: step.response_time_ms,
        skipped: !!step.skipped,
        skipReason: step.skipped ? 'skipped by the run' : '',
        error: step.error || '',
        matchedIndex: null,
        matchedWhen: '',
        conditionProblems: EMPTY_RULES,
        action: '',
        gotoStepId: '',
        gotoStepName: '',
        message: '',
        delayMs: null,
      };
    });

  return {
    at: new Date().toISOString(),
    rows: reconstructed,
    reconstructed: true,
    capCode,
    capLabel,
    outcome,
    stopReason,
    stopNote: NON_CAP_STOPS[capCode] || '',
    labelOf,
  };
}

// Pulls a human message out of whatever the framework returned. Every handler in this feature answers
// a failure with {error: code, message: text}, so message comes first.
async function apiJSON(url, options) {
  const res = await fetch(url, options);
  const body = await res.text();
  let data = null;
  try { data = body ? JSON.parse(body) : null; } catch (err) { data = null; }
  if (!res.ok) {
    const message = (data && (data.message || data.error)) || body || `The framework returned ${res.status}`;
    const failure = new Error(message);
    failure.status = res.status;
    throw failure;
  }
  return data;
}

const jsonPost = (payload) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload),
});

const jsonPut = (payload) => ({
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload),
});

// Renders the stored response the way the repeater renders one: the status line, the headers as they
// came back, a blank line, then the body. A step that has never run says so rather than showing an
// empty pane that looks like an empty response.
function renderRawResponse(step) {
  if (!step) return '';
  const status = step.response_status;
  const headers = step.response_headers || {};
  const names = Object.keys(headers).sort((a, b) => a.localeCompare(b));
  if (!status && names.length === 0 && !step.response_body) return '';
  const lines = [`HTTP/1.1 ${status || 0}`];
  names.forEach((name) => {
    const values = Array.isArray(headers[name]) ? headers[name] : [headers[name]];
    values.forEach((value) => { lines.push(`${name}: ${value}`); });
  });
  lines.push('');
  lines.push(step.response_body || '');
  return lines.join('\n');
}

// Compares a rule set the way the SERVER stores it: every field present, in a fixed order.
//
// AuthFlowExtraction marks source_key, pattern, decode_as and optional `omitempty`, so a rule saved
// with optional false comes back with no `optional` key at all. A naive JSON.stringify comparison
// then reads {optional:false} as different from {} and the "unsaved" badge latches on the moment an
// operator turns an optional switch on and off again. A badge that is always lit is a badge nobody
// reads, which costs the one time it means something.
function canonicalExtractions(rules) {
  return JSON.stringify((rules || []).map((rule) => ({
    name: rule.name || '',
    source: rule.source || '',
    source_key: rule.source_key || '',
    pattern: rule.pattern || '',
    decode_as: rule.decode_as || 'none',
    optional: !!rule.optional,
  })));
}

const SectionHeading = ({ children, right }) => (
  <div className="d-flex align-items-center px-2 py-1 border-bottom border-secondary flex-shrink-0">
    <span className="text-white-50" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>{children}</span>
    {right && <div className="ms-auto d-flex align-items-center gap-2">{right}</div>}
  </div>
);

// initialFlowId is the receiving end of "Edit as flow" in the Request Flows modal: that screen
// creates a built flow out of a detected one and hands the new id over, so the operator arrives
// looking at their flow rather than at a list they have to find it in. Ignored when absent, which is
// every other way this modal is opened.
export const RequestFlowBuilderModal = ({ show, handleClose, activeTarget, initialFlowId }) => {
  const targetId = activeTarget && activeTarget.id;

  // Which screen the main area is showing. 'build' is the three columns; the other two take the
  // whole width because both are a list the operator has to read before picking from it, and a
  // picker squeezed into a 260px column is a picker nobody uses.
  const [mode, setMode] = useState('build');

  // Left column.
  const [flows, setFlows] = useState([]);
  const [flowsLoading, setFlowsLoading] = useState(false);
  const [flowsError, setFlowsError] = useState('');
  const [selectedFlowId, setSelectedFlowId] = useState(null);
  const [creating, setCreating] = useState(false);
  const [newFlowName, setNewFlowName] = useState('');

  // Middle and right columns.
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [selectedStepId, setSelectedStepId] = useState(null);
  const detailSeq = useRef(0);

  // The editor.
  const [buffer, setBuffer] = useState('');
  const [loadedBuffer, setLoadedBuffer] = useState('');
  const [eol, setEol] = useState('CRLF');
  const [rawMode, setRawMode] = useState(false);
  const [stepName, setStepName] = useState('');
  const [extractions, setExtractions] = useState([]);
  // The selected step's condition rules, live. Edited here, analysed here, saved with the bytes.
  const [conditions, setConditions] = useState([]);
  // Which of the two panels under the editor is showing. Both carry their own warning count on the
  // tab, so a problem in the one that is hidden is still visible.
  const [stepPanel, setStepPanel] = useState('variables');
  const editorRef = useRef(null);
  // What the editor was last loaded FROM: the step id and the stored content itself, not just the
  // id. See the load effect for why the content has to be in it.
  const loadedKeyRef = useRef(null);

  // Flow-level fields.
  const [baseUrl, setBaseUrl] = useState('');
  const [loadedBaseUrl, setLoadedBaseUrl] = useState('');

  // Action feedback. `notice` is what the server said (the seed summary, the replay note);
  // `actionError` is what went wrong. Both are dismissible and neither is an alert.
  const [notice, setNotice] = useState('');
  const [actionError, setActionError] = useState('');
  const [busy, setBusy] = useState('');
  const [lastRun, setLastRun] = useState(null);
  const [dryRun, setDryRun] = useState(null);
  const [trace, setTrace] = useState(null);
  const [traceOpen, setTraceOpen] = useState(true);

  // Seed picker.
  const [detectedQuery, setDetectedQuery] = useState('');
  const [detectedFlows, setDetectedFlows] = useState([]);
  const [detectedLoading, setDetectedLoading] = useState(false);
  const [detectedError, setDetectedError] = useState('');
  const [seedFlowId, setSeedFlowId] = useState(null);
  const [seedName, setSeedName] = useState('');
  const [seedIncludeAll, setSeedIncludeAll] = useState(false);
  const detectedSeq = useRef(0);

  // Capture picker.
  const [captureQuery, setCaptureQuery] = useState('');
  const [captures, setCaptures] = useState([]);
  const [capturesLoading, setCapturesLoading] = useState(false);
  const [capturesError, setCapturesError] = useState('');
  const captureSeq = useRef(0);

  // THE ONE PLACE THE WIRE SHAPE IS TRANSLATED IN. Every step row keeps its bytes, its extractions
  // and its response exactly as the server sent them; only `conditions` is rewritten, from the
  // server's {when,then,target,message} into the rules the controls below are built from. From here
  // down, "a condition" means a screen rule everywhere, and conditionsToWire in saveStep is the only
  // way back out.
  const steps = useMemo(() => {
    const rows = detail && Array.isArray(detail.steps) ? detail.steps : EMPTY_STEPS;
    if (!rows.length) return EMPTY_STEPS;
    return rows.map((step) => ({
      ...step,
      conditions: conditionsFromWire(step && step.conditions, rows),
    }));
  }, [detail]);

  const selectedStep = useMemo(
    () => steps.find((s) => s.id === selectedStepId) || null,
    [steps, selectedStepId]
  );

  const dirty = selectedStep
    ? (buffer !== loadedBuffer
      || stepName !== (selectedStep.name || '')
      || canonicalExtractions(extractions) !== canonicalExtractions(selectedStep.extractions)
      || canonicalConditions(conditions) !== canonicalConditions(selectedStep.conditions))
    : false;

  // The loop protection actually in force.
  //
  // The server publishes it as `caps` (FlowRunCaps), under its own field names, on the preview and
  // on the flow detail. Those numbers win; the constants are a fallback for a build that does not
  // send them. Either way these are facts to be printed, not settings, and nothing on this screen
  // turns one off.
  const limits = useMemo(() => {
    const caps = (dryRun && dryRun.caps) || (detail && detail.caps) || null;
    const out = { ...DEFAULT_LIMITS };
    if (caps) {
      Object.keys(CAP_FIELDS).forEach((ours) => {
        const value = Number(caps[CAP_FIELDS[ours]]);
        if (Number.isFinite(value) && value > 0) out[ours] = value;
      });
    }
    return out;
  }, [detail, dryRun]);

  // Held in a ref so the guard can be read from callbacks that must not re-arm on every keystroke.
  const dirtyRef = useRef(false);
  useEffect(() => { dirtyRef.current = dirty; }, [dirty]);

  const confirmDiscard = useCallback(() => {
    if (!dirtyRef.current) return true;
    return window.confirm('This step has unsaved edits. Discard them?');
  }, []);

  // The analysis, run over the LIVE buffer for the step being edited so a placeholder typed a second
  // ago is judged, not the copy last written to the database.
  const variableModel = useMemo(() => {
    const overrides = {};
    if (selectedStepId) {
      overrides[selectedStepId] = buffer;
    }
    // The extraction rules being edited count too: adding a capture on step two should clear the
    // warning on step three before it is saved, otherwise the operator saves blind.
    const projected = steps.map((s) => (
      s.id === selectedStepId ? { ...s, extractions } : s
    ));
    return buildVariableModel(projected, overrides);
  }, [steps, selectedStepId, buffer, extractions]);

  // The same trick, for conditions: the rules in the editor are projected onto the saved flow, so a
  // goto picked a second ago is judged rather than the copy last written to the database.
  const conditionModel = useMemo(
    () => buildConditionModel(steps, selectedStepId, conditions),
    [steps, selectedStepId, conditions]
  );

  const stepConditions = selectedStepId ? conditionModel.byStep.get(selectedStepId) : null;
  const stepCycles = selectedStepId ? (conditionModel.cyclesByStep.get(selectedStepId) || EMPTY_RULES) : EMPTY_RULES;

  // Why the save is refused, in one sentence, next to the button. A structural error saved is a rule
  // that fires wrong against a live target, and the server's rejection arrives too late to be useful.
  const conditionBlocker = useMemo(() => {
    if (!stepConditions || stepConditions.errors === 0) return '';
    const first = stepConditions.issues.find((issue) => issue.level === 'error');
    return first ? `Rule ${first.index + 1}: ${first.text}` : '';
  }, [stepConditions]);

  const previewByStep = useMemo(() => {
    const map = new Map();
    const rows = (detail && Array.isArray(detail.preview)) ? detail.preview : [];
    rows.forEach((row) => { map.set(row.step_id, row); });
    return map;
  }, [detail]);

  // What a replay would actually send, derived from the server's own preview rows so this cannot
  // disagree with the dry run.
  const sendSummary = useMemo(() => {
    const rows = (detail && Array.isArray(detail.preview)) ? detail.preview : [];
    const sendable = rows.filter((row) => row.enabled && !row.refusal);
    const hosts = Array.from(new Set(sendable.map((row) => row.host).filter(Boolean))).sort();
    return {
      willSend: sendable.length,
      skipped: rows.length - sendable.length,
      outOfScope: rows.filter((row) => !row.in_scope).length,
      hosts,
    };
  }, [detail]);

  // -------------------------------------------------------------------------
  // Loaders
  // -------------------------------------------------------------------------

  const loadFlows = useCallback(async (selectId) => {
    if (!targetId) return;
    setFlowsLoading(true);
    try {
      const data = await apiJSON(`${BUILDER}/${targetId}/flows`);
      const rows = Array.isArray(data && data.flows) ? data.flows : [];
      setFlows(rows);
      setFlowsError('');
      if (selectId) setSelectedFlowId(selectId);
    } catch (err) {
      setFlowsError(err.message);
    } finally {
      setFlowsLoading(false);
    }
  }, [targetId]);

  const loadFlowDetail = useCallback(async (flowId) => {
    if (!flowId) return;
    const seq = detailSeq.current + 1;
    detailSeq.current = seq;
    setDetailLoading(true);
    try {
      const data = await apiJSON(`${BUILDER}/flow/${flowId}`);
      if (seq !== detailSeq.current) return;
      setDetail(data);
      setDetailError('');
      setBaseUrl((data.flow && data.flow.base_url) || '');
      setLoadedBaseUrl((data.flow && data.flow.base_url) || '');
    } catch (err) {
      if (seq !== detailSeq.current) return;
      setDetailError(err.message);
      // A failed load of a DIFFERENT flow must not leave the previous one on screen pretending to
      // be it, and a failed refresh of the SAME flow must not destroy what is already right.
      setDetail((prev) => (prev && prev.flow && prev.flow.id === flowId ? prev : null));
    } finally {
      if (seq === detailSeq.current) setDetailLoading(false);
    }
  }, []);

  const loadDetectedFlows = useCallback(async (text) => {
    if (!targetId) return;
    const seq = detectedSeq.current + 1;
    detectedSeq.current = seq;
    setDetectedLoading(true);
    try {
      const data = await apiJSON(
        `/api/replay-request/${targetId}/flows?q=${encodeURIComponent(text)}&limit=${DETECTED_FLOW_LIMIT}`
      );
      if (seq !== detectedSeq.current) return;
      if (data && typeof data.error === 'string' && data.error) {
        setDetectedError(data.error);
        return;
      }
      setDetectedFlows(Array.isArray(data && data.flows) ? data.flows : []);
      setDetectedError('');
    } catch (err) {
      if (seq === detectedSeq.current) setDetectedError(err.message);
    } finally {
      if (seq === detectedSeq.current) setDetectedLoading(false);
    }
  }, [targetId]);

  const loadCaptures = useCallback(async (text) => {
    if (!targetId) return;
    const seq = captureSeq.current + 1;
    captureSeq.current = seq;
    setCapturesLoading(true);
    try {
      const data = await apiJSON(
        `/api/replay-request/${targetId}/captures?q=${encodeURIComponent(text)}&limit=${CAPTURE_LIMIT}`
      );
      if (seq !== captureSeq.current) return;
      if (data && typeof data.error === 'string' && data.error) {
        setCapturesError(data.error);
        return;
      }
      const rows = Array.isArray(data)
        ? data
        : ((data && (data.captures || data.results || data.rows)) || []);
      setCaptures(rows);
      setCapturesError('');
    } catch (err) {
      if (seq === captureSeq.current) setCapturesError(err.message);
    } finally {
      if (seq === captureSeq.current) setCapturesLoading(false);
    }
  }, [targetId]);

  // Fresh open, fresh target, fresh everything. A previous target's flow left on screen is a request
  // sent to the wrong host the moment somebody hits Replay.
  useEffect(() => {
    setMode('build');
    setFlows([]);
    setFlowsError('');
    // The handover wins over the reset. Opening with an initialFlowId means somebody just built
    // this flow and asked to edit it; clearing it here and letting the list load empty would drop
    // them exactly where the handover exists to avoid.
    setSelectedFlowId(show ? (initialFlowId || null) : null);
    setCreating(false);
    setNewFlowName('');
    setDetail(null);
    setDetailError('');
    setSelectedStepId(null);
    setBuffer('');
    setLoadedBuffer('');
    setStepName('');
    setExtractions([]);
    setConditions([]);
    setStepPanel('variables');
    setBaseUrl('');
    setLoadedBaseUrl('');
    setRawMode(false);
    setNotice('');
    setActionError('');
    setLastRun(null);
    setDryRun(null);
    setTrace(null);
    setTraceOpen(true);
    setDetectedFlows([]);
    setDetectedQuery('');
    setSeedFlowId(null);
    setSeedName('');
    setSeedIncludeAll(false);
    setCaptures([]);
    setCaptureQuery('');
    if (show && targetId) loadFlows();
  }, [show, targetId, initialFlowId, loadFlows]);

  useEffect(() => {
    if (!show || !selectedFlowId) return;
    loadFlowDetail(selectedFlowId);
  }, [show, selectedFlowId, loadFlowDetail]);

  // Debounced, because both boxes filter the whole capture corpus.
  useEffect(() => {
    if (!show || mode !== 'seed') return undefined;
    const timer = setTimeout(() => { loadDetectedFlows(detectedQuery); }, 300);
    return () => clearTimeout(timer);
  }, [show, mode, detectedQuery, loadDetectedFlows]);

  useEffect(() => {
    if (!show || mode !== 'capture') return undefined;
    const timer = setTimeout(() => { loadCaptures(captureQuery); }, 300);
    return () => clearTimeout(timer);
  }, [show, mode, captureQuery, loadCaptures]);

  // Loading a step into the editor.
  //
  // The guard is the whole point of this effect and it keys on the step's CONTENT, not on its id.
  // Keying on the id alone is wrong in both directions:
  //
  //   Too sticky. After a save, the framework hands back what it actually STORED, which is not what
  //   was sent to it unless raw mode was on: normalizeRawRequest repairs the framing and recomputes
  //   Content-Length. With an id guard, the re-fetch that follows the save renders once while the
  //   flow is still the pre-save copy, that render re-arms the guard against the OLD bytes, and the
  //   server's version arrives to find the guard already satisfied. The pane then shows bytes that
  //   are not what will be sent, with no "unsaved" marker, which is exactly the thing invariant 3
  //   exists to prevent.
  //
  //   Too eager. Nulling the guard by hand to defeat that, which is what an id guard forces, throws
  //   away an unsaved buffer every time anything refreshes the flow: a replay, an arm, a move.
  //
  // Content answers both. A refresh that did not change this step's stored bytes, name or capture
  // rules is not a reload, so an edit in progress survives a replay of the whole flow. A refresh
  // that DID change them is the framework telling the operator what it stored, and that always wins,
  // because the alternative is showing them their own copy of bytes the framework rewrote.
  useEffect(() => {
    if (!selectedStep) {
      loadedKeyRef.current = null;
      setBuffer('');
      setLoadedBuffer('');
      setStepName('');
      setExtractions([]);
      setConditions([]);
      return;
    }
    const raw = selectedStep.raw_request || '';
    const key = [
      selectedStep.id,
      raw,
      selectedStep.name || '',
      canonicalExtractions(selectedStep.extractions),
      canonicalConditions(selectedStep.conditions),
    ].join('\u0000');
    if (loadedKeyRef.current === key) return;
    loadedKeyRef.current = key;
    setBuffer(raw);
    setLoadedBuffer(raw);
    setEol(raw.includes('\r\n') ? 'CRLF' : 'LF');
    setStepName(selectedStep.name || '');
    setExtractions((selectedStep.extractions || []).map((rule) => ({ ...rule })));
    // Merged onto a blank rule so a server row that omits an empty field still arrives with every
    // control bound to a defined value, rather than React flipping an input from uncontrolled to
    // controlled the first time it is touched.
    setConditions((selectedStep.conditions || []).map((rule) => ({ ...blankRule(), ...rule })));
  }, [selectedStep]);

  // -------------------------------------------------------------------------
  // Actions
  // -------------------------------------------------------------------------

  const run = useCallback(async (label, fn) => {
    setBusy(label);
    setActionError('');
    try {
      await fn();
    } catch (err) {
      setActionError(err.message);
    } finally {
      setBusy('');
    }
  }, []);

  const selectFlow = (flowId) => {
    if (flowId === selectedFlowId) return;
    if (!confirmDiscard()) return;
    setSelectedFlowId(flowId);
    setSelectedStepId(null);
    setNotice('');
    setActionError('');
    setLastRun(null);
    setDryRun(null);
    // A trace belongs to the flow that produced it. Left on screen across a flow change it is a
    // record of somebody else's run wearing this flow's name.
    setTrace(null);
  };

  const selectStep = (stepId) => {
    if (stepId === selectedStepId) return;
    if (!confirmDiscard()) return;
    setSelectedStepId(stepId);
  };

  const createBlankFlow = () => run('create', async () => {
    const name = newFlowName.trim();
    if (!name) {
      setActionError('A flow needs a name. The list is how you find it again.');
      return;
    }
    const flow = await apiJSON(`${BUILDER}/${targetId}/flows`, jsonPost({ name, description: '', base_url: '' }));
    setCreating(false);
    setNewFlowName('');
    setNotice('Empty flow created. Set a Base URL on it, then add steps from the capture list or by hand.');
    setSelectedStepId(null);
    await loadFlows(flow && flow.id);
  });

  const seedFromDetectedFlow = () => run('seed', async () => {
    if (!seedFlowId) {
      setActionError('Pick a detected flow to copy.');
      return;
    }
    const data = await apiJSON(`${BUILDER}/${targetId}/from-flow`, jsonPost({
      flow_id: seedFlowId,
      name: seedName.trim(),
      include_all: seedIncludeAll,
    }));
    setMode('build');
    setSeedFlowId(null);
    setSeedName('');
    setSeedIncludeAll(false);
    setCreating(false);
    setNewFlowName('');
    setSelectedStepId(null);
    // Whatever the server says about the seed goes on screen and stays until dismissed.
    setNotice((data && data.note) || 'Flow copied in. Every step is editable.');
    await loadFlows(data && data.flow && data.flow.id);
  });

  const deleteFlow = (flow) => {
    if (!window.confirm(`Delete "${flow.name}" and its ${flow.step_count} step(s)? This cannot be undone.`)) return;
    run('delete-flow', async () => {
      await apiJSON(`${BUILDER}/flow/${flow.id}`, { method: 'DELETE' });
      if (flow.id === selectedFlowId) {
        setSelectedFlowId(null);
        setSelectedStepId(null);
        setDetail(null);
      }
      await loadFlows();
    });
  };

  const saveBaseUrl = () => run('base-url', async () => {
    await apiJSON(`${BUILDER}/flow/${selectedFlowId}`, jsonPut({ base_url: baseUrl }));
    setLoadedBaseUrl(baseUrl);
    await loadFlowDetail(selectedFlowId);
    await loadFlows();
  });

  // Every "add" moves the selection to the new step, so each one asks before abandoning bytes the
  // operator typed into the step they are leaving.
  const selectNewStep = (step) => {
    if (!step) return;
    setSelectedStepId(step.id);
  };

  const addBlankStep = () => {
    if (!confirmDiscard()) return;
    // A step with no Host header cannot be sent, and the server refuses to store one rather than
    // keeping bytes that will never work. So the template takes its Host from the flow's base URL,
    // and when there is none the operator is told what to fill in instead of being handed a parse
    // error from the other end.
    let host = '';
    try { host = new URL(baseUrl).host; } catch (err) { host = ''; }
    if (!host) {
      setActionError('Set this flow\'s Base URL first. A step needs a Host header, and a blank step '
        + 'takes it from there.');
      return;
    }
    const raw = `GET / HTTP/1.1\r\nHost: ${host}\r\nAccept: */*\r\n\r\n`;
    run('add-step', async () => {
      const data = await apiJSON(`${BUILDER}/flow/${selectedFlowId}/steps`, jsonPost({
        name: 'GET /', raw_request: raw,
      }));
      await loadFlowDetail(selectedFlowId);
      selectNewStep(data && data.step);
    });
  };

  const addStepFromCapture = (captureId) => {
    if (!confirmDiscard()) return;
    run('add-step', async () => {
      const data = await apiJSON(`${BUILDER}/flow/${selectedFlowId}/steps`,
        jsonPost({ capture_id: captureId }));
      setMode('build');
      await loadFlowDetail(selectedFlowId);
      selectNewStep(data && data.step);
      setNotice('');
    });
  };

  const duplicateStep = (step) => {
    if (!confirmDiscard()) return;
    // The copy inherits the original's on/off state verbatim. That switch is the operator's, and a
    // duplicate that quietly changed it would be this screen editing their flow behind their back.
    run('duplicate', async () => {
      const data = await apiJSON(`${BUILDER}/flow/${selectedFlowId}/steps`, jsonPost({
        name: `${step.name || 'step'} (copy)`,
        raw_request: step.raw_request,
        extractions: step.extractions || [],
        enabled: step.enabled,
      }));
      await loadFlowDetail(selectedFlowId);
      selectNewStep(data && data.step);
      setNotice('The copy was added at the END of the flow. Move it where you want it.');
    });
  };

  const deleteStep = (step) => {
    if (!window.confirm(`Delete step ${step.step_order} (${step.name || 'unnamed'})?`)) return;
    run('delete-step', async () => {
      await apiJSON(`${BUILDER}/steps/${step.id}`, { method: 'DELETE' });
      if (step.id === selectedStepId) {
        setSelectedStepId(null);
      }
      await loadFlowDetail(selectedFlowId);
      await loadFlows();
    });
  };

  const moveStep = (step, delta) => run('move', async () => {
    const to = step.step_order + delta;
    if (to < 1 || to > steps.length) return;
    await apiJSON(`${BUILDER}/steps/${step.id}/move`, jsonPost({ to_position: to }));
    await loadFlowDetail(selectedFlowId);
  });

  // Arming a step touches only the `enabled` column, so the editor is deliberately left alone: the
  // bytes on screen are still this step's bytes and there is nothing to re-read.
  const toggleStep = (step) => run('toggle', async () => {
    await apiJSON(`${BUILDER}/steps/${step.id}`, jsonPut({ enabled: !step.enabled }));
    await loadFlowDetail(selectedFlowId);
    await loadFlows();
  });

  // The one place the editor is reloaded UNCONDITIONALLY, and it has to be: unless raw mode is on,
  // the server normalises what it stores, so the bytes it now holds are not necessarily the bytes
  // that were sent to it. Showing the operator their own copy afterwards would hide a Content-Length
  // the framework rewrote.
  const saveStep = () => run('save-step', async () => {
    await apiJSON(`${BUILDER}/steps/${selectedStepId}`, jsonPut({
      name: stepName,
      raw_request: buffer,
      extractions,
      // Translated on the way out. The server decodes []FlowCondition; a screen rule posted as-is
      // decodes into an empty condition on every field, which is a step that reads as branching in
      // this list and runs straight through at the target.
      conditions: conditionsToWire(conditions),
      raw_mode: rawMode,
    }));
    await loadFlowDetail(selectedFlowId);
    await loadFlows();
  });

  const previewFlow = () => run('preview', async () => {
    const data = await apiJSON(`${BUILDER}/flow/${selectedFlowId}/preview`);
    setDryRun({ ...data, at: new Date().toISOString() });
  });

  const replayFlow = () => run('replay-flow', async () => {
    const data = await apiJSON(`${BUILDER}/flow/${selectedFlowId}/replay`, jsonPost({}));
    setDetail((prev) => ({
      ...(prev || {}),
      flow: data.flow,
      steps: data.steps,
      scope_boundary: data.scope_boundary,
      // The replay does not return preview rows, and keeping the old ones would be right anyway:
      // nothing about the flow's shape changed, only its responses.
      preview: (prev && prev.preview) || [],
    }));
    setLastRun({
      at: new Date().toISOString(),
      refused_hosts: (data && data.refused_hosts) || [],
      scope_boundary: data && data.scope_boundary,
    });
    // The trace is the record of what the run DID, execution by execution. Opened automatically,
    // because it is the answer to the question the operator just asked by pressing the button, and a
    // branching run read without it is a list of statuses in an order nobody can account for.
    setTrace(normalizeTrace(data, Array.isArray(data && data.steps) ? data.steps : EMPTY_STEPS));
    setTraceOpen(true);
    await loadFlows();
  });

  const replayStep = (step) => run('replay-step', async () => {
    const data = await apiJSON(`${BUILDER}/steps/${step.id}/replay`, jsonPost({}));
    await loadFlowDetail(selectedFlowId);
    if (data && data.replay_error) {
      setActionError(`${data.replay_error} ${data.replay_note || ''}`.trim());
    }
  });

  // -------------------------------------------------------------------------
  // Editor plumbing
  // -------------------------------------------------------------------------

  // The browser hands back an LF-only value no matter what the buffer held, so the CRs go back in to
  // match the terminator style the step was loaded with. Without this, the first keystroke in a CRLF
  // request silently rewrites every line ending in it.
  const handleBufferChange = (event) => {
    const typed = event.target.value;
    setBuffer(eol === 'CRLF'
      ? typed.replace(/\r\n|\r|\n/g, '\r\n')
      : typed.replace(/\r\n|\r/g, '\n'));
  };

  const changeEol = (next) => {
    setEol(next);
    setBuffer((prev) => (next === 'CRLF'
      ? prev.replace(/\r\n|\r|\n/g, '\r\n')
      : prev.replace(/\r\n|\r/g, '\n')));
  };

  const insertPlaceholder = (name) => {
    const area = editorRef.current;
    const token = `{{af:${name}}}`;
    if (!area) {
      setBuffer((prev) => prev + token);
      return;
    }
    const start = area.selectionStart;
    const end = area.selectionEnd;
    setBuffer((prev) => prev.slice(0, start) + token + prev.slice(end));
    window.requestAnimationFrame(() => {
      area.focus();
      area.setSelectionRange(start + token.length, start + token.length);
    });
  };

  const updateExtraction = (index, patch) => {
    setExtractions((prev) => prev.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)));
  };

  const addExtraction = () => {
    setExtractions((prev) => prev.concat([{
      name: '', source: 'body', source_key: '', pattern: '', decode_as: 'none', optional: false,
    }]));
  };

  const removeExtraction = (index) => {
    setExtractions((prev) => prev.filter((_, i) => i !== index));
  };

  // -------------------------------------------------------------------------
  // Condition plumbing
  //
  // The catch-all can only ever be last, and that is enforced HERE rather than reported afterwards:
  // a new rule is inserted above it, it cannot be moved, nothing can be moved past it, and there can
  // only be one. An operator cannot get the order wrong by clicking, so the only way to see the
  // "OTHERWISE has to be last" error is data that came from somewhere else.
  // -------------------------------------------------------------------------

  const catchAllIndex = conditions.findIndex((rule) => rule && rule.otherwise);

  const updateCondition = (index, patch) => {
    setConditions((prev) => prev.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)));
  };

  // Changing the field re-points the operator at an operator that field understands. Leaving a stale
  // `contains` on a status field would render a rule that reads fine and matches nothing.
  const changeConditionField = (index, field) => {
    const allowed = FIELD_OPS[field] || [];
    setConditions((prev) => prev.map((rule, i) => {
      if (i !== index) return rule;
      const keepOp = allowed.includes(rule.op) ? rule.op : (allowed[0] || '');
      return { ...rule, field, op: keepOp, key: field === 'header' ? rule.key : '' };
    }));
  };

  const addCondition = () => {
    setConditions((prev) => {
      const at = prev.findIndex((rule) => rule && rule.otherwise);
      const rule = blankRule();
      if (at < 0) return prev.concat([rule]);
      return prev.slice(0, at).concat([rule], prev.slice(at));
    });
    setStepPanel('conditions');
  };

  const addCatchAll = () => {
    setConditions((prev) => (prev.some((rule) => rule && rule.otherwise)
      ? prev
      : prev.concat([catchAllRule()])));
    setStepPanel('conditions');
  };

  const removeCondition = (index) => {
    setConditions((prev) => prev.filter((_, i) => i !== index));
  };

  // Only reachable from data this screen could not have produced: nothing here can put a rule below
  // the catch-all. It exists so the error has a fix next to it rather than being a dead end.
  const moveCatchAllLast = () => {
    setConditions((prev) => {
      const at = prev.findIndex((rule) => rule && rule.otherwise);
      if (at < 0 || at === prev.length - 1) return prev;
      const next = prev.slice();
      const [moved] = next.splice(at, 1);
      next.push(moved);
      return next;
    });
  };

  const moveCondition = (index, delta) => {
    setConditions((prev) => {
      const to = index + delta;
      if (to < 0 || to >= prev.length) return prev;
      if (prev[index] && prev[index].otherwise) return prev;
      if (prev[to] && prev[to].otherwise) return prev;
      const next = prev.slice();
      const [moved] = next.splice(index, 1);
      next.splice(to, 0, moved);
      return next;
    });
  };

  const requestClose = () => {
    if (!confirmDiscard()) return;
    handleClose();
  };

  // -------------------------------------------------------------------------
  // Render: left column, the flows
  // -------------------------------------------------------------------------

  const renderFlowRow = (flow) => {
    const selected = flow.id === selectedFlowId;
    return (
      <div
        key={flow.id}
        className="rfb-row px-2 py-2 border-bottom border-secondary"
        style={{
          cursor: 'pointer',
          borderLeft: `3px solid ${selected ? '#dc3545' : 'transparent'}`,
          backgroundColor: selected ? '#2b3035' : 'transparent',
        }}
        onClick={() => selectFlow(flow.id)}
      >
        <div className="d-flex align-items-start">
          <div className="flex-grow-1" style={{ minWidth: 0 }}>
            <div className="text-light text-truncate" style={{ fontSize: '0.78rem' }} title={flow.name}>
              {flow.name}
            </div>
            <div className="text-white-50 mt-1" style={{ fontSize: '0.66rem' }}>
              {flow.step_count} step{flow.step_count === 1 ? '' : 's'}
              {flow.step_count > 0 && (
                <span className={flow.enabled_count < flow.step_count ? 'text-warning ms-1' : 'ms-1'}>
                  · {flow.enabled_count} armed
                </span>
              )}
            </div>
            <div className="mt-1">
              <Badge
                bg="dark"
                className="border border-secondary text-white-50"
                style={{ fontSize: '0.58rem' }}
                title={flow.source === 'detected_flow'
                  ? `Copied from the detected flow ${flow.seeded_from_flow_id || ''}`
                  : 'How this flow was made'}
              >
                {flow.source === 'detected_flow' ? 'from detected flow'
                  : flow.source === 'captures' ? 'from captures' : 'built by hand'}
              </Badge>
            </div>
            <div className="text-white-50 mt-1" style={{ fontSize: '0.62rem' }}>
              {formatTimestamp(flow.updated_at)}
            </div>
          </div>
          <Button
            size="sm"
            variant="outline-secondary"
            className="border-0 ms-1 flex-shrink-0"
            title="Delete this flow"
            onClick={(e) => { e.stopPropagation(); deleteFlow(flow); }}
          >
            <i className="bi bi-trash" style={{ fontSize: '0.7rem' }} />
          </Button>
        </div>
      </div>
    );
  };

  const renderFlowsColumn = () => (
    <div
      className="d-flex flex-column border border-secondary rounded me-2"
      style={{ width: '19%', minWidth: '235px', minHeight: 0 }}
    >
      <SectionHeading
        right={flowsLoading ? <Spinner animation="border" size="sm" variant="danger" /> : null}
      >
        FLOWS
      </SectionHeading>

      <div className="p-2 border-bottom border-secondary">
        {!creating ? (
          <Button size="sm" variant="danger" className="w-100" onClick={() => setCreating(true)}>
            <i className="bi bi-plus-lg me-2" />New flow
          </Button>
        ) : (
          <>
            <Form.Control
              size="sm"
              value={newFlowName}
              onChange={(e) => setNewFlowName(e.target.value)}
              placeholder="Name it"
              style={{ fontSize: '0.75rem' }}
              data-bs-theme="dark"
            />
            <div className="d-grid gap-1 mt-2">
              <Button
                size="sm"
                variant="outline-light"
                disabled={busy === 'create'}
                onClick={createBlankFlow}
              >
                {busy === 'create'
                  ? <Spinner animation="border" size="sm" />
                  : <><i className="bi bi-file-earmark me-2" />Start empty</>}
              </Button>
              {/* The path that will actually get used. The operator has already looked at a diagram
                  of the flow they want; this copies it in rather than making them rebuild it. */}
              <Button
                size="sm"
                variant="danger"
                onClick={() => { setSeedName(newFlowName.trim()); setMode('seed'); }}
              >
                <i className="bi bi-diagram-3 me-2" />Build from a detected flow
              </Button>
              <Button
                size="sm"
                variant="outline-secondary"
                onClick={() => { setCreating(false); setNewFlowName(''); }}
              >
                Cancel
              </Button>
            </div>
          </>
        )}
        {flowsError && (
          <div className="text-danger mt-2" style={{ fontSize: '0.7rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />{flowsError}
          </div>
        )}
      </div>

      <div className="flex-grow-1" style={{ overflowY: 'auto', overflowX: 'hidden', minHeight: 0 }}>
        {flows.length === 0 ? (
          <div className="text-white-50 small p-3">
            {flowsLoading
              ? 'Loading.'
              : 'No flows on this target yet. Build one from a detected flow: it copies that flow\'s requests in as editable steps.'}
          </div>
        ) : (
          flows.map(renderFlowRow)
        )}
      </div>
    </div>
  );

  // -------------------------------------------------------------------------
  // Render: middle column, the steps
  // -------------------------------------------------------------------------

  const renderStepRow = (step) => {
    const selected = step.id === selectedStepId;
    const { method, target } = parseRequestLine(step.raw_request);
    const vars = variableModel.byStep.get(step.id);
    const rules = conditionModel.byStep.get(step.id);
    const inCycle = (conditionModel.cyclesByStep.get(step.id) || EMPTY_RULES).length > 0;
    const preview = previewByStep.get(step.id);
    const outOfScope = preview && !preview.in_scope;
    return (
      <div
        key={step.id}
        className="rfb-row px-2 py-2 border-bottom border-secondary"
        style={{
          cursor: 'pointer',
          borderLeft: `3px solid ${selected ? '#dc3545' : 'transparent'}`,
          backgroundColor: selected ? '#2b3035' : 'transparent',
          opacity: step.enabled ? 1 : 0.65,
        }}
        onClick={() => selectStep(step.id)}
      >
        <div className="d-flex align-items-center">
          <span className="text-white-50 me-2" style={{ fontSize: '0.66rem', minWidth: '16px' }}>
            {step.step_order}
          </span>
          <span
            className="me-2"
            onClick={(e) => e.stopPropagation()}
            title={step.enabled
              ? 'Armed. This step is sent when the flow is replayed.'
              : 'Turned off. This step keeps its place and is skipped, and its captures never fire.'}
          >
            <Form.Check
              type="switch"
              id={`rfb-step-${step.id}`}
              checked={!!step.enabled}
              disabled={busy === 'toggle'}
              onChange={() => toggleStep(step)}
            />
          </span>
          <span className="fw-bold text-warning me-1" style={{ fontFamily: MONO, fontSize: '0.7rem' }}>
            {method || '?'}
          </span>
          <span
            className="text-info flex-grow-1 text-truncate"
            style={{ fontFamily: MONO, fontSize: '0.7rem' }}
            title={target}
          >
            {target || '/'}
          </span>
          {step.response_status ? (
            <Badge bg={statusVariant(step.response_status)} className="ms-1" style={{ fontSize: '0.56rem' }}>
              {step.response_status}
            </Badge>
          ) : (
            <Badge bg="dark" className="border border-secondary text-white-50 ms-1" style={{ fontSize: '0.56rem' }}>
              not run
            </Badge>
          )}
        </div>

        {step.name && step.name !== `${method} ${target}` && (
          <div className="text-white-50 text-truncate ps-4" style={{ fontSize: '0.66rem' }}>
            {step.name}
          </div>
        )}

        <div className="ps-4 mt-1 d-flex flex-wrap gap-1">
          {vars && vars.broken > 0 && (
            <Badge bg="warning" text="dark" style={{ fontSize: '0.56rem' }}>
              <i className="bi bi-exclamation-triangle me-1" />
              {vars.broken} unresolved
            </Badge>
          )}
          {(step.extractions || []).length > 0 && (
            <Badge bg="info" style={{ fontSize: '0.56rem' }}>
              <i className="bi bi-download me-1" />
              captures {(step.extractions || []).map((r) => r.name).filter(Boolean).join(', ')}
            </Badge>
          )}
          {rules && rules.rules.length > 0 && (
            <Badge
              bg={rules.errors > 0 ? 'danger' : rules.warnings > 0 ? 'warning' : 'dark'}
              text={rules.errors === 0 && rules.warnings > 0 ? 'dark' : undefined}
              className={rules.errors === 0 && rules.warnings === 0 ? 'border border-secondary text-white-50' : ''}
              style={{ fontSize: '0.56rem' }}
              title={rules.rules
                .map((rule, i) => `${i + 1}. ${describeCondition(rule, conditionModel.labelOf)}`)
                .join('\n')}
            >
              <i className="bi bi-signpost-split me-1" />
              {rules.rules.length} rule{rules.rules.length === 1 ? '' : 's'}
            </Badge>
          )}
          {inCycle && (
            <Badge
              bg="warning"
              text="dark"
              style={{ fontSize: '0.56rem' }}
              title={(conditionModel.cyclesByStep.get(step.id) || EMPTY_RULES).map((c) => c.text).join('\n')}
            >
              <i className="bi bi-arrow-repeat me-1" />in a loop
            </Badge>
          )}
          {outOfScope && (
            <Badge bg="danger" style={{ fontSize: '0.56rem' }}>out of scope</Badge>
          )}
          {step.source_capture_id && (
            <Badge bg="dark" className="border border-secondary text-white-50" style={{ fontSize: '0.56rem' }}>
              recorded
            </Badge>
          )}
          {step.error && (
            <Badge bg="danger" style={{ fontSize: '0.56rem' }} title={step.error}>
              <i className="bi bi-x-octagon me-1" />error
            </Badge>
          )}
          {step.skipped && (
            <Badge bg="secondary" style={{ fontSize: '0.56rem' }}>skipped last run</Badge>
          )}
        </div>
      </div>
    );
  };

  const renderStepsColumn = () => (
    <div
      className="d-flex flex-column border border-secondary rounded me-2"
      style={{ width: '25%', minWidth: '300px', minHeight: 0 }}
    >
      <SectionHeading right={detailLoading ? <Spinner animation="border" size="sm" variant="danger" /> : null}>
        STEPS
      </SectionHeading>

      {!selectedFlowId ? (
        <div className="text-white-50 small p-3 fst-italic">
          Pick a flow on the left, or make one.
        </div>
      ) : (
        <>
          <div className="p-2 border-bottom border-secondary">
            <InputGroup size="sm" className="mb-2">
              <InputGroup.Text className="bg-dark border-secondary text-white-50" style={{ fontSize: '0.68rem' }}>
                Base URL
              </InputGroup.Text>
              <Form.Control
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://host"
                spellCheck={false}
                style={{ fontFamily: MONO, fontSize: '0.7rem' }}
                data-bs-theme="dark"
              />
              <Button
                variant={baseUrl !== loadedBaseUrl ? 'danger' : 'outline-secondary'}
                disabled={baseUrl === loadedBaseUrl || busy === 'base-url'}
                onClick={saveBaseUrl}
                title="Where a step with no Host header is sent. A step's own Host header always wins, so a flow that crosses hosts still works."
              >
                <i className="bi bi-check-lg" />
              </Button>
            </InputGroup>

            <div className="d-flex gap-1">
              <Button
                size="sm"
                variant="outline-light"
                className="flex-grow-1"
                disabled={busy === 'add-step'}
                onClick={() => setMode('capture')}
                title="Pick a recorded request and copy its bytes in as a new step."
              >
                <i className="bi bi-clipboard-plus me-1" />From capture
              </Button>
              <Button
                size="sm"
                variant="outline-secondary"
                disabled={busy === 'add-step'}
                onClick={addBlankStep}
                title="Add an empty GET against this flow's Base URL, to type by hand."
              >
                <i className="bi bi-plus-lg" />
              </Button>
            </div>
          </div>

          <div className="flex-grow-1" style={{ overflowY: 'auto', overflowX: 'hidden', minHeight: 0 }}>
            {steps.length === 0 ? (
              <div className="text-white-50 small p-3">
                {detailLoading ? 'Loading.' : 'No steps yet. Add one from the capture list, or by hand.'}
              </div>
            ) : (
              steps.map(renderStepRow)
            )}
          </div>

          {/* Reordering and the destructive actions, on the step that is selected. Up and down
              rather than drag: the order is the flow's meaning and a mis-drop is expensive. */}
          <div className="d-flex align-items-center gap-1 px-2 py-2 border-top border-secondary flex-shrink-0">
            <Button
              size="sm"
              variant="outline-secondary"
              disabled={!selectedStep || selectedStep.step_order <= 1 || busy === 'move'}
              onClick={() => selectedStep && moveStep(selectedStep, -1)}
              title="Move this step one earlier"
            >
              <i className="bi bi-arrow-up" />
            </Button>
            <Button
              size="sm"
              variant="outline-secondary"
              disabled={!selectedStep || selectedStep.step_order >= steps.length || busy === 'move'}
              onClick={() => selectedStep && moveStep(selectedStep, 1)}
              title="Move this step one later"
            >
              <i className="bi bi-arrow-down" />
            </Button>
            <Button
              size="sm"
              variant="outline-secondary"
              disabled={!selectedStep || busy === 'duplicate'}
              onClick={() => selectedStep && duplicateStep(selectedStep)}
              title="Copy this step to the end of the flow."
            >
              <i className="bi bi-files" />
            </Button>
            <Button
              size="sm"
              variant="outline-danger"
              disabled={!selectedStep || busy === 'delete-step'}
              onClick={() => selectedStep && deleteStep(selectedStep)}
              title="Delete this step"
            >
              <i className="bi bi-trash" />
            </Button>
            <span className="text-white-50 ms-auto" style={{ fontSize: '0.66rem' }}>
              {steps.length} step{steps.length === 1 ? '' : 's'}
            </span>
          </div>
        </>
      )}
    </div>
  );

  // -------------------------------------------------------------------------
  // Render: the variables panel
  //
  // The reason this feature exists. A flow is a list of requests plus the values carried between
  // them, and a carried value that does not arrive is the failure mode that looks like a working
  // flow: the request goes out, the target answers 403, and the operator spends an hour on the
  // target instead of on the flow.
  // -------------------------------------------------------------------------

  const renderVariablesBody = () => {
    const vars = selectedStepId ? variableModel.byStep.get(selectedStepId) : null;
    const refs = (vars && vars.refs) || [];
    const available = (vars && vars.available) || [];
    return (
      <>
        <div className="px-2 py-1 border-bottom border-secondary text-white-50" style={{ fontSize: '0.66rem' }}>
          values carried between steps as <code className="text-danger">{'{{af:NAME}}'}</code>
        </div>

        <div className="p-2">
          <div className="text-light fw-bold mb-1" style={{ fontSize: '0.7rem' }}>
            This step sends
          </div>
          {!selectedStep ? (
            <div className="text-white-50 fst-italic mb-2" style={{ fontSize: '0.7rem' }}>
              No step selected.
            </div>
          ) : refs.length === 0 ? (
            <div className="text-white-50 fst-italic mb-2" style={{ fontSize: '0.7rem' }}>
              No placeholders in these bytes. This step sends exactly what is in the editor.
            </div>
          ) : (
            <div className="mb-2">
              {refs.map((ref) => {
                const good = ref.state === 'ok';
                const soft = ref.state === 'optional';
                const variant = good ? 'success' : soft ? 'info' : 'warning';
                return (
                  <div key={ref.name} className="d-flex mb-1" style={{ fontSize: '0.7rem' }}>
                    <Badge bg={variant} text={variant === 'warning' ? 'dark' : undefined}
                           className="me-2 flex-shrink-0" style={{ fontSize: '0.6rem' }}>
                      <i className={`bi ${good ? 'bi-check-lg' : 'bi-exclamation-triangle'} me-1`} />
                      {`{{af:${ref.name}}}`}
                    </Badge>
                    <span className={good ? 'text-white-50' : soft ? 'text-info' : 'text-warning'}>
                      {good
                        ? `filled in from step ${ref.provider.order}${ref.provider.stepName ? ` (${ref.provider.stepName})` : ''}`
                        : referenceProblem(ref)}
                    </span>
                  </div>
                );
              })}
            </div>
          )}

          <div className="text-light fw-bold mb-1" style={{ fontSize: '0.7rem' }}>
            Available here
          </div>
          {available.length === 0 ? (
            <div className="text-white-50 fst-italic mb-2" style={{ fontSize: '0.7rem' }}>
              No earlier armed step captures anything yet. Add a capture below, on the step whose
              response holds the value.
            </div>
          ) : (
            <div className="mb-2">
              {available.map((entry) => (
                <code
                  key={entry.name}
                  className="text-info me-2"
                  style={{ fontSize: '0.7rem', cursor: 'pointer' }}
                  title={`Captured by step ${entry.order}${entry.optional ? ', by an optional rule' : ''}. Click to insert at the caret.`}
                  onClick={() => insertPlaceholder(entry.name)}
                >
                  {`{{af:${entry.name}}}`}
                </code>
              ))}
            </div>
          )}

          <div className="d-flex align-items-center mb-1">
            <span className="text-light fw-bold" style={{ fontSize: '0.7rem' }}>
              This step captures
            </span>
            <Button
              size="sm"
              variant="outline-secondary"
              className="ms-auto py-0"
              style={{ fontSize: '0.66rem' }}
              disabled={!selectedStep}
              onClick={addExtraction}
            >
              <i className="bi bi-plus-lg me-1" />Add capture
            </Button>
          </div>

          {extractions.length === 0 ? (
            <div className="text-white-50 fst-italic" style={{ fontSize: '0.7rem' }}>
              Nothing. Add a rule to take a value out of this step's response and make it available to
              every later step.
            </div>
          ) : (
            extractions.map((rule, index) => (
              <div key={index} className="border border-secondary rounded p-2 mb-2">
                <div className="d-flex gap-1 mb-1">
                  <Form.Control
                    size="sm"
                    value={rule.name || ''}
                    onChange={(e) => updateExtraction(index, { name: e.target.value })}
                    placeholder="NAME"
                    spellCheck={false}
                    style={{ fontFamily: MONO, fontSize: '0.7rem', width: '150px' }}
                    data-bs-theme="dark"
                    title="What later steps refer to as {{af:NAME}}. Letters, digits and underscore."
                  />
                  <Form.Select
                    size="sm"
                    value={rule.source || 'body'}
                    onChange={(e) => updateExtraction(index, { source: e.target.value })}
                    style={{ fontSize: '0.7rem', width: '95px' }}
                    data-bs-theme="dark"
                  >
                    {EXTRACTION_SOURCES.map((source) => (
                      <option key={source} value={source}>{source}</option>
                    ))}
                  </Form.Select>
                  {(rule.source === 'header' || rule.source === 'cookie') && (
                    <Form.Control
                      size="sm"
                      value={rule.source_key || ''}
                      onChange={(e) => updateExtraction(index, { source_key: e.target.value })}
                      placeholder={rule.source === 'cookie' ? 'cookie name' : 'header name'}
                      spellCheck={false}
                      style={{ fontFamily: MONO, fontSize: '0.7rem' }}
                      data-bs-theme="dark"
                    />
                  )}
                  <Form.Select
                    size="sm"
                    value={rule.decode_as || 'none'}
                    onChange={(e) => updateExtraction(index, { decode_as: e.target.value })}
                    style={{ fontSize: '0.7rem', width: '85px' }}
                    data-bs-theme="dark"
                    title="Decoding applied to the captured value. none is the default, because html decoding corrupts URL shaped values."
                  >
                    {EXTRACTION_DECODINGS.map((decoding) => (
                      <option key={decoding} value={decoding}>{decoding}</option>
                    ))}
                  </Form.Select>
                  <Button
                    size="sm"
                    variant="outline-danger"
                    className="border-0"
                    onClick={() => removeExtraction(index)}
                    title="Remove this capture"
                  >
                    <i className="bi bi-x-lg" />
                  </Button>
                </div>
                <Form.Control
                  size="sm"
                  value={rule.pattern || ''}
                  onChange={(e) => updateExtraction(index, { pattern: e.target.value })}
                  placeholder={'name="csrf" value="([^"]+)"'}
                  spellCheck={false}
                  style={{ fontFamily: MONO, fontSize: '0.7rem' }}
                  data-bs-theme="dark"
                  title="RE2. Capture group 1 is the value. Required for a body capture, optional for a header or cookie."
                />
                <Form.Check
                  type="switch"
                  id={`rfb-optional-${index}`}
                  className="text-white-50 mt-1"
                  style={{ fontSize: '0.68rem' }}
                  label="optional: may legitimately match nothing"
                  checked={!!rule.optional}
                  onChange={(e) => updateExtraction(index, { optional: e.target.checked })}
                />
              </div>
            ))
          )}
        </div>
      </>
    );
  };

  // -------------------------------------------------------------------------
  // Render: the conditions panel
  //
  // The other half of what makes a flow a flow. Variables carry values forward; conditions decide
  // whether the flow goes forward at all, or somewhere else, or stops. Every control is a dropdown
  // over a closed set, so the shapes that exist are the shapes the server can evaluate.
  // -------------------------------------------------------------------------

  const renderConditionIssues = (index) => {
    const list = (stepConditions && stepConditions.byIndex.get(index)) || EMPTY_RULES;
    if (list.length === 0) return null;
    return (
      <div className="mt-1 ps-3">
        {list.map((issue, i) => (
          <div
            key={`${issue.level}-${i}`}
            className={issue.level === 'error' ? 'text-danger' : 'text-warning'}
            style={{ fontSize: '0.66rem' }}
          >
            <i className={`bi ${issue.level === 'error' ? 'bi-x-octagon' : 'bi-exclamation-triangle'} me-1`} />
            {issue.text}
          </div>
        ))}
      </div>
    );
  };

  const renderConditionRule = (rule, index) => {
    const issues = (stepConditions && stepConditions.byIndex.get(index)) || EMPTY_RULES;
    const hasError = issues.some((issue) => issue.level === 'error');
    const hasWarn = issues.some((issue) => issue.level === 'warn');
    const isCatchAll = !!rule.otherwise;
    const spec = opSpec(rule.op);
    const needsValue = !spec || spec.needsValue;
    const action = actionSpec(rule.action);
    // Dimmed, not hidden: a rule that can never run is still a rule the operator wrote, and hiding
    // it removes the only clue about why the branch they expected never happened.
    const dead = issues.some((issue) => issue.kind === 'unreachable');

    return (
      <div
        key={index}
        className="border rounded p-2 mb-2"
        style={{
          borderColor: hasError ? '#dc3545' : hasWarn ? '#997404' : '#495057',
          backgroundColor: isCatchAll ? '#1b1e21' : 'transparent',
          opacity: dead ? 0.72 : 1,
        }}
      >
        <div className="d-flex align-items-center gap-1 flex-wrap">
          <Badge
            bg={hasError ? 'danger' : 'dark'}
            className={hasError ? '' : 'border border-secondary text-white-50'}
            style={{ fontSize: '0.58rem', minWidth: '20px' }}
            title="Rules are tried top to bottom and the first one that matches wins."
          >
            {index + 1}
          </Badge>

          {isCatchAll ? (
            <>
              <span
                className="text-white-50 fw-bold"
                style={{ fontSize: '0.7rem', letterSpacing: '0.04em' }}
                title="Matches when nothing above it did. It can only be the last rule, so nothing can be added below it."
              >
                OTHERWISE
              </span>
              {index !== conditions.length - 1 && (
                <Button
                  size="sm"
                  variant="outline-danger"
                  className="py-0"
                  style={{ fontSize: '0.66rem' }}
                  onClick={moveCatchAllLast}
                >
                  <i className="bi bi-arrow-bar-down me-1" />Move to the bottom
                </Button>
              )}
            </>
          ) : (
            <>
              <span className="text-white-50" style={{ fontSize: '0.66rem' }}>WHEN</span>
              <Form.Select
                size="sm"
                value={rule.field || 'status'}
                onChange={(e) => changeConditionField(index, e.target.value)}
                style={{ fontSize: '0.7rem', width: '128px' }}
                data-bs-theme="dark"
                title={fieldSpec(rule.field).hint}
              >
                {CONDITION_FIELDS.map((field) => (
                  <option key={field.value} value={field.value}>{field.label}</option>
                ))}
              </Form.Select>

              {rule.field === 'header' && (
                <Form.Control
                  size="sm"
                  value={rule.key || ''}
                  onChange={(e) => updateCondition(index, { key: e.target.value })}
                  placeholder="Location"
                  spellCheck={false}
                  style={{ fontFamily: MONO, fontSize: '0.7rem', width: '130px' }}
                  data-bs-theme="dark"
                />
              )}

              {rule.field === 'raw' ? (
                <Form.Control
                  size="sm"
                  value={rule.expr || ''}
                  onChange={(e) => updateCondition(index, { expr: e.target.value })}
                  placeholder="step.Login.header.Location ~ /dashboard"
                  spellCheck={false}
                  style={{ fontFamily: MONO, fontSize: '0.7rem', flex: '1 1 240px', minWidth: '180px' }}
                  data-bs-theme="dark"
                  title={'The escape hatch, for a test the dropdowns cannot say. The server parses this, '
                    + 'so a typo here IS a syntax error and it is reported when the flow is saved.\n\n'
                    + 'ONE test per rule; there is no "and" or "or". Write the second test as a second '
                    + 'rule.\n\n'
                    + 'fields: status, body, size, time_ms, header.<name>, and any of those against an '
                    + 'earlier step as step.<name-or-id>.<field> - quote a step name with spaces: '
                    + 'step."GET /login".status\n'
                    + 'operators: == != > < >= <= (numbers), ~ !~ (contains, case-insensitive), '
                    + '=~ (RE2 regular expression)'}
                />
              ) : (
                <>
                  <Form.Select
                    size="sm"
                    value={rule.op || ''}
                    onChange={(e) => updateCondition(index, { op: e.target.value })}
                    style={{ fontSize: '0.7rem', width: '140px' }}
                    data-bs-theme="dark"
                    title={rule.field === 'header'
                      ? 'There is no "is absent". A header the target did not send is ABSENT, and '
                        + 'absent matches nothing at all - not even "is not" or "does not contain". '
                        + 'Test that it IS present, and put the missing case in an OTHERWISE row.'
                      : undefined}
                  >
                    {opsForField(rule.field).map((op) => (
                      <option key={op.value} value={op.value}>{op.label}</option>
                    ))}
                  </Form.Select>
                  {needsValue && (
                    <Form.Control
                      size="sm"
                      value={rule.value == null ? '' : rule.value}
                      onChange={(e) => updateCondition(index, { value: e.target.value })}
                      placeholder={rule.field === 'status' ? '200'
                        : rule.field === 'time_ms' ? '2000'
                          : rule.field === 'size' ? '0' : 'text'}
                      spellCheck={false}
                      style={{
                        fontFamily: MONO,
                        fontSize: '0.7rem',
                        width: rule.field === 'status' || rule.field === 'time_ms' || rule.field === 'size'
                          ? '84px'
                          : '160px',
                      }}
                      data-bs-theme="dark"
                    />
                  )}
                </>
              )}
            </>
          )}

          <span className="text-white-50 ms-1" style={{ fontSize: '0.66rem' }}>THEN</span>
          <Form.Select
            size="sm"
            value={rule.action || 'continue'}
            onChange={(e) => updateCondition(index, { action: e.target.value })}
            className={`border-${action.variant}`}
            style={{ fontSize: '0.7rem', width: '140px' }}
            data-bs-theme="dark"
          >
            {CONDITION_ACTIONS.map((entry) => (
              <option key={entry.value} value={entry.value}>{entry.label}</option>
            ))}
          </Form.Select>

          {/* Never a free-text id. The operator picks a step out of this flow, so the only way to
              get a dangling goto is to delete the step it points at, and that is reported. */}
          {rule.action === 'goto' && (
            <Form.Select
              size="sm"
              value={rule.goto_step_id || ''}
              onChange={(e) => updateCondition(index, { goto_step_id: e.target.value })}
              style={{ fontSize: '0.7rem', maxWidth: '260px' }}
              data-bs-theme="dark"
            >
              <option value="">pick a step</option>
              {steps.map((step) => (
                <option key={step.id} value={step.id}>{stepLabel(step)}</option>
              ))}
            </Form.Select>
          )}

          {(rule.action === 'fail' || rule.action === 'stop') && (
            <Form.Control
              size="sm"
              value={rule.message || ''}
              onChange={(e) => updateCondition(index, { message: e.target.value })}
              placeholder="why, e.g. login rejected"
              style={{ fontSize: '0.7rem', flex: '1 1 160px', minWidth: '140px' }}
              data-bs-theme="dark"
              title="What the run says when it stops here. Without it the trace says the run ended and nothing else."
            />
          )}

          {rule.action === 'retry' && (
            <span className="text-white-50" style={{ fontSize: '0.66rem' }}>
              up to {limits.max_retries}x, {limits.retry_delay_ms}ms apart
            </span>
          )}

          <div className="ms-auto d-flex gap-1 flex-shrink-0">
            <Button
              size="sm"
              variant="outline-secondary"
              className="border-0 py-0"
              disabled={isCatchAll || index === 0}
              onClick={() => moveCondition(index, -1)}
              title="Try this rule earlier"
            >
              <i className="bi bi-arrow-up" style={{ fontSize: '0.68rem' }} />
            </Button>
            <Button
              size="sm"
              variant="outline-secondary"
              className="border-0 py-0"
              disabled={isCatchAll
                || index === conditions.length - 1
                || (catchAllIndex >= 0 && index === catchAllIndex - 1)}
              onClick={() => moveCondition(index, 1)}
              title={catchAllIndex >= 0 && index === catchAllIndex - 1
                ? 'This is already the last rule that can be tried. OTHERWISE has to stay at the bottom.'
                : 'Try this rule later'}
            >
              <i className="bi bi-arrow-down" style={{ fontSize: '0.68rem' }} />
            </Button>
            <Button
              size="sm"
              variant="outline-danger"
              className="border-0 py-0"
              onClick={() => removeCondition(index)}
              title="Delete this rule"
            >
              <i className="bi bi-x-lg" style={{ fontSize: '0.68rem' }} />
            </Button>
          </div>
        </div>

        {renderConditionIssues(index)}
      </div>
    );
  };

  const renderConditionsBody = () => (
    <>
      <div className="px-2 py-1 border-bottom border-secondary text-white-50" style={{ fontSize: '0.66rem' }}>
        Tried top to bottom, first match wins. A step with no rules, or whose rules all miss, just
        continues to the next step.
      </div>

      <div className="p-2">
        {!selectedStep ? (
          <div className="text-white-50 fst-italic" style={{ fontSize: '0.7rem' }}>
            No step selected.
          </div>
        ) : (
          <>
            {/* The cycle warning, on the step whose goto closed it, the moment it was picked.
                Not blocked: a bounded retry loop is a legitimate thing to build. */}
            {stepCycles.length > 0 && (
              <div
                className="border border-warning rounded p-2 mb-2 text-warning"
                style={{ fontSize: '0.68rem', backgroundColor: '#2b2410' }}
              >
                <div className="fw-bold mb-1">
                  <i className="bi bi-arrow-repeat me-1" />
                  This step is in a loop. A goto in this flow points back into it:
                </div>
                {stepCycles.map((cycle, i) => (
                  <div key={i} className="text-light mb-1" style={{ fontFamily: MONO, fontSize: '0.68rem' }}>
                    {cycle.text}
                  </div>
                ))}
                <div className="text-white-50">
                  A run can go round this. It is allowed, because a bounded retry loop is a real thing
                  to build, and the caps below the run button will stop it. But it will stop MID-FLOW
                  and the rest of the flow will not run. If a retry is what you meant, the
                  "retry this step" action is capped on purpose and waits between tries.
                </div>
              </div>
            )}

            {conditions.length === 0 ? (
              <div className="text-white-50 fst-italic mb-2" style={{ fontSize: '0.7rem' }}>
                No rules. This step always continues to the next one. Add a rule to branch on what
                came back: a 302 to a login page and a 200 with the data on it are different answers
                and a flow that treats them the same tests nothing.
              </div>
            ) : (
              conditions.map(renderConditionRule)
            )}

            <div className="d-flex gap-1">
              <Button
                size="sm"
                variant="outline-secondary"
                className="py-0"
                style={{ fontSize: '0.68rem' }}
                onClick={addCondition}
              >
                <i className="bi bi-plus-lg me-1" />Add rule
              </Button>
              <Button
                size="sm"
                variant="outline-secondary"
                className="py-0"
                style={{ fontSize: '0.68rem' }}
                disabled={catchAllIndex >= 0}
                onClick={addCatchAll}
                title={catchAllIndex >= 0
                  ? `This step already has an OTHERWISE, as rule ${catchAllIndex + 1}. There can only be one, and it is always last.`
                  : 'Add the catch-all: what to do when none of the rules above matched. It goes at the bottom and stays there.'}
              >
                <i className="bi bi-three-dots me-1" />Add OTHERWISE
              </Button>
            </div>
          </>
        )}
      </div>
    </>
  );

  const renderStepPanels = () => {
    const vars = selectedStepId ? variableModel.byStep.get(selectedStepId) : null;
    const brokenVars = (vars && vars.broken) || 0;
    const ruleErrors = (stepConditions && stepConditions.errors) || 0;
    const ruleWarnings = ((stepConditions && stepConditions.warnings) || 0) + stepCycles.length;

    const tab = (key, label, count, errorCount, warnCount) => (
      <button
        type="button"
        className={`btn btn-sm border-0 rounded-0 px-3 py-1 ${stepPanel === key ? 'text-light' : 'text-white-50'}`}
        style={{
          fontSize: '0.72rem',
          letterSpacing: '0.04em',
          borderBottom: `2px solid ${stepPanel === key ? '#dc3545' : 'transparent'}`,
          backgroundColor: 'transparent',
        }}
        onClick={() => setStepPanel(key)}
      >
        {label}
        {count > 0 && <span className="text-white-50 ms-1">({count})</span>}
        {errorCount > 0 && (
          <i className="bi bi-x-octagon-fill text-danger ms-1" style={{ fontSize: '0.62rem' }} />
        )}
        {errorCount === 0 && warnCount > 0 && (
          <i className="bi bi-exclamation-triangle-fill text-warning ms-1" style={{ fontSize: '0.62rem' }} />
        )}
      </button>
    );

    return (
      <div className="border-top border-secondary flex-shrink-0" style={{ maxHeight: '44%', overflowY: 'auto' }}>
        {/* Both counts live on the tabs, so a problem in the panel that is hidden is still visible. */}
        <div
          className="d-flex align-items-center border-bottom border-secondary position-sticky top-0"
          style={{ backgroundColor: '#212529', zIndex: 2 }}
        >
          {tab('variables', 'VARIABLES', (extractions || []).length, 0, brokenVars)}
          {tab('conditions', 'CONDITIONS', conditions.length, ruleErrors, ruleWarnings)}
        </div>
        {stepPanel === 'conditions' ? renderConditionsBody() : renderVariablesBody()}
      </div>
    );
  };

  // -------------------------------------------------------------------------
  // Render: right column, the step
  // -------------------------------------------------------------------------

  const renderStepColumn = () => {
    const preview = selectedStepId ? previewByStep.get(selectedStepId) : null;
    const responseText = renderRawResponse(selectedStep);
    return (
      <div className="d-flex flex-grow-1" style={{ minWidth: 0, minHeight: 0 }}>
        {/* The bytes. */}
        <div
          className="d-flex flex-column border border-secondary rounded me-2"
          style={{ width: '55%', minWidth: 0, minHeight: 0 }}
        >
          <div className="d-flex align-items-center px-2 py-1 border-bottom border-secondary flex-shrink-0">
            <span className="text-white-50" style={{ fontSize: '0.72rem' }}>REQUEST</span>
            {dirty && <span className="text-warning ms-2" style={{ fontSize: '0.68rem' }}>unsaved</span>}
            <Form.Control
              size="sm"
              value={stepName}
              onChange={(e) => setStepName(e.target.value)}
              placeholder="step name"
              disabled={!selectedStep}
              className="ms-auto"
              style={{ fontSize: '0.7rem', width: '220px' }}
              data-bs-theme="dark"
            />
          </div>

          {preview && preview.refusal && (
            <div
              className="text-warning px-2 py-1 border-bottom border-secondary flex-shrink-0"
              style={{ fontSize: '0.7rem', backgroundColor: '#2b2410' }}
            >
              <i className="bi bi-exclamation-triangle me-1" />
              {preview.refusal}
            </div>
          )}

          <div className="flex-grow-1" style={{ position: 'relative', minHeight: 0, backgroundColor: '#1e1e1e' }}>
            <textarea
              ref={editorRef}
              value={buffer}
              onChange={handleBufferChange}
              disabled={!selectedStep}
              wrap="off"
              spellCheck={false}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              placeholder="Select a step on the left, or add one."
              style={{
                ...MONO_STYLE,
                position: 'absolute',
                top: 0, left: 0, right: 0, bottom: 0,
                width: '100%',
                height: '100%',
                resize: 'none',
                outline: 'none',
                overflow: 'auto',
                backgroundColor: 'transparent',
                color: '#d0d0d0',
                caretColor: '#f8f9fa',
              }}
            />
          </div>

          {renderStepPanels()}

          <div className="d-flex align-items-center gap-2 px-2 py-2 border-top border-secondary flex-wrap flex-shrink-0">
            {/* The block, and the reason, in one place. A rule with no goto target or nothing to
                compare against is not a rule yet, and saving it puts a half-written decision in front
                of a live target. Enforced here rather than left to the server's rejection, which
                arrives after the operator has moved on. */}
            <Button
              size="sm"
              variant={dirty ? (conditionBlocker ? 'outline-danger' : 'danger') : 'outline-secondary'}
              disabled={!selectedStep || !dirty || !!conditionBlocker || busy === 'save-step'}
              onClick={saveStep}
              title={conditionBlocker || 'Save this step\'s bytes, captures and conditions.'}
            >
              {busy === 'save-step'
                ? <><Spinner animation="border" size="sm" className="me-2" />Saving</>
                : <><i className="bi bi-save me-2" />Save step</>}
            </Button>
            <Button
              size="sm"
              variant="outline-danger"
              disabled={!selectedStep || !selectedStep.enabled || dirty || busy === 'replay-step'}
              onClick={() => selectedStep && replayStep(selectedStep)}
              title={selectedStep && !selectedStep.enabled
                ? 'This step is turned off, so it is not sent.'
                : 'Send just this step. Cookies and captured values come from the responses the earlier steps already recorded, so nothing earlier is re-sent. Conditions are NOT evaluated: one step is one request, and there is nowhere to branch to.'}
            >
              {busy === 'replay-step'
                ? <><Spinner animation="border" size="sm" className="me-2" />Sending</>
                : <><i className="bi bi-send me-2" />Replay step</>}
            </Button>

            <OverlayTrigger
              placement="top"
              overlay={(
                <Tooltip>
                  Raw mode saves the bytes exactly as typed, without repairing the headers or
                  recomputing Content-Length. Required for a deliberate Content-Length /
                  Transfer-Encoding disagreement, and wrong for everything else.
                </Tooltip>
              )}
            >
              <span>
                <Form.Check
                  type="switch"
                  id="rfb-raw-mode"
                  className={rawMode ? 'text-warning' : 'text-white-50'}
                  style={{ fontSize: '0.72rem' }}
                  label="Raw mode"
                  checked={rawMode}
                  onChange={(e) => setRawMode(e.target.checked)}
                />
              </span>
            </OverlayTrigger>

            <Form.Select
              size="sm"
              value={eol}
              onChange={(e) => changeEol(e.target.value)}
              disabled={!selectedStep}
              style={{ width: '90px', fontSize: '0.7rem' }}
              data-bs-theme="dark"
              title="The terminator every line in this buffer carries. A browser textarea cannot hold a bare CR, so edits are written back in the style chosen here."
            >
              <option value="CRLF">CRLF</option>
              <option value="LF">LF</option>
            </Form.Select>

            <span className="text-white-50 ms-auto" style={{ fontSize: '0.68rem' }}>
              {byteLength(buffer).toLocaleString()} bytes
            </span>

            {/* A disabled button does not raise a tooltip, so the reason it is disabled is printed. */}
            {conditionBlocker && (
              <div className="w-100 text-danger" style={{ fontSize: '0.68rem' }}>
                <i className="bi bi-x-octagon me-1" />
                Cannot save: {conditionBlocker}{' '}
                <Button
                  size="sm"
                  variant="link"
                  className="text-danger p-0 align-baseline"
                  style={{ fontSize: '0.68rem' }}
                  onClick={() => setStepPanel('conditions')}
                >
                  Show it
                </Button>
              </div>
            )}
          </div>
        </div>

        {/* The response. */}
        <div
          className="d-flex flex-column border border-secondary rounded"
          style={{ width: '45%', minWidth: 0, minHeight: 0 }}
        >
          <div className="d-flex align-items-center px-2 py-1 border-bottom border-secondary flex-shrink-0">
            <span className="text-white-50" style={{ fontSize: '0.72rem' }}>LAST RESPONSE</span>
            {selectedStep && selectedStep.response_status ? (
              <Badge bg={statusVariant(selectedStep.response_status)} className="ms-2" style={{ fontSize: '0.6rem' }}>
                {selectedStep.response_status}
              </Badge>
            ) : null}
            {selectedStep && selectedStep.response_time_ms != null && (
              <span className="text-white-50 ms-2" style={{ fontSize: '0.68rem' }}>
                {Math.round(selectedStep.response_time_ms).toLocaleString()} ms
              </span>
            )}
          </div>

          {selectedStep && selectedStep.error && (
            <div
              className="text-danger px-2 py-1 border-bottom border-secondary flex-shrink-0"
              style={{ fontSize: '0.7rem', backgroundColor: '#2b1215', maxHeight: '20%', overflowY: 'auto' }}
            >
              <i className="bi bi-exclamation-octagon me-1" />
              {selectedStep.error}
            </div>
          )}

          {/* What the last run actually did with this step's placeholders and captures. Stored
              nowhere, so it only appears after a replay in this session, and it says which values
              were substituted rather than leaving "did the token arrive" to be inferred. */}
          {selectedStep && (selectedStep.captured || selectedStep.substituted) && (
            <div className="px-2 py-1 border-bottom border-secondary flex-shrink-0" style={{ fontSize: '0.68rem' }}>
              {Array.isArray(selectedStep.substituted) && selectedStep.substituted.length > 0 && (
                <div className="text-white-50">
                  filled in:{' '}
                  {selectedStep.substituted.map((name) => (
                    <code key={name} className="text-success me-1">{`{{af:${name}}}`}</code>
                  ))}
                </div>
              )}
              {Array.isArray(selectedStep.captured) && selectedStep.captured.map((outcome) => (
                <div key={outcome.name} className={outcome.matched ? 'text-success' : 'text-warning'}>
                  <i className={`bi ${outcome.matched ? 'bi-check-lg' : 'bi-exclamation-triangle'} me-1`} />
                  {outcome.name}: {outcome.matched
                    ? `captured ${outcome.value ? `"${outcome.value.slice(0, 80)}"` : 'a value'}`
                    : (outcome.problem || 'matched nothing')}
                </div>
              ))}
            </div>
          )}

          <div className="flex-grow-1" style={{ overflow: 'auto', minHeight: 0, backgroundColor: '#1e1e1e' }}>
            {responseText ? (
              <pre style={{ ...MONO_STYLE, color: '#d0d0d0' }}>{responseText}</pre>
            ) : (
              <div className="text-white-50 p-3" style={{ fontSize: '0.75rem' }}>
                {selectedStep
                  ? 'This step has not run yet. Replay the step, or the whole flow.'
                  : 'No step selected.'}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  // -------------------------------------------------------------------------
  // Render: the seed picker
  // -------------------------------------------------------------------------

  const renderSeedPicker = () => (
    <div className="d-flex flex-column flex-grow-1 p-3" style={{ minHeight: 0 }}>
      <div className="d-flex align-items-center mb-2 flex-shrink-0">
        <Button size="sm" variant="outline-secondary" onClick={() => setMode('build')}>
          <i className="bi bi-arrow-left me-2" />Back
        </Button>
        <div className="ms-3">
          <div className="text-light" style={{ fontSize: '0.85rem' }}>Build from a detected flow</div>
          <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
            The flow's requests are copied in as editable steps, in the order the browser made them.
            Nothing is sent by copying.
          </div>
        </div>
      </div>

      <div className="d-flex flex-grow-1" style={{ minHeight: 0 }}>
        <div
          className="d-flex flex-column border border-secondary rounded me-3 flex-grow-1"
          style={{ minWidth: 0, minHeight: 0 }}
        >
          <div className="p-2 border-bottom border-secondary">
            <InputGroup size="sm">
              <InputGroup.Text className="bg-dark border-secondary text-white-50">
                {detectedLoading
                  ? <Spinner animation="border" size="sm" variant="danger" />
                  : <i className="bi bi-search" />}
              </InputGroup.Text>
              <Form.Control
                value={detectedQuery}
                onChange={(e) => setDetectedQuery(e.target.value)}
                placeholder="method = POST AND status >= 400"
                spellCheck={false}
                style={{ fontFamily: MONO, fontSize: '0.75rem' }}
                data-bs-theme="dark"
              />
            </InputGroup>
            {detectedError && (
              <div className="text-danger mt-1" style={{ fontSize: '0.72rem' }}>
                <i className="bi bi-exclamation-triangle me-1" />{detectedError}
              </div>
            )}
            <div className="text-white-50 mt-1" style={{ fontSize: '0.66rem' }}>
              The query matches requests; a flow containing a match is listed whole. Same language as
              the Replay Requests search box.
            </div>
          </div>

          <div className="flex-grow-1" style={{ overflowY: 'auto', minHeight: 0 }}>
            {detectedFlows.length === 0 ? (
              <div className="text-white-50 small p-3">
                {detectedLoading
                  ? 'Loading flows.'
                  : 'No detected flows. They are built out of manual crawl captures, so run a crawl on this target first.'}
              </div>
            ) : (
              detectedFlows.map((flow) => {
                const selected = flow.id === seedFlowId;
                return (
                  <div
                    key={flow.id}
                    className="rfb-row px-2 py-2 border-bottom border-secondary"
                    style={{
                      cursor: 'pointer',
                      borderLeft: `3px solid ${selected ? '#dc3545' : 'transparent'}`,
                      backgroundColor: selected ? '#2b3035' : 'transparent',
                    }}
                    onClick={() => setSeedFlowId(flow.id)}
                  >
                    <div className="text-truncate" style={{ fontFamily: MONO, fontSize: '0.75rem' }}>
                      <span className="text-info">{flow.label}</span>
                    </div>
                    <div className="text-white-50 text-truncate" style={{ fontSize: '0.68rem' }}>
                      {flow.host || 'unknown host'}
                    </div>
                    <div className="mt-1">
                      {Object.entries(flow.status_summary || {})
                        .filter(([, count]) => Number(count) > 0)
                        .sort((a, b) => a[0].localeCompare(b[0]))
                        .map(([key, count]) => (
                          <span
                            key={key}
                            className={`badge bg-${statusClassVariant(key)} me-1`}
                            style={{ fontSize: '0.6rem' }}
                          >
                            {key} {count}
                          </span>
                        ))}
                    </div>
                    <div className="text-white-50 mt-1" style={{ fontSize: '0.65rem' }}>
                      {flow.request_count} request{flow.request_count === 1 ? '' : 's'}
                      {Number(flow.hidden_count) > 0 && (
                        <span className="text-warning ms-1">
                          ({flow.shown_count} significant, {flow.hidden_count} subresources)
                        </span>
                      )}
                      <span className="ms-1">· {formatTimestamp(flow.started_at)}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        <div
          className="d-flex flex-column border border-secondary rounded p-2"
          style={{ width: '360px', flexShrink: 0, overflowY: 'auto' }}
        >
          <div className="text-white-50 mb-2" style={{ fontSize: '0.7rem', letterSpacing: '0.04em' }}>
            THE NEW FLOW
          </div>

          <Form.Control
            size="sm"
            value={seedName}
            onChange={(e) => setSeedName(e.target.value)}
            placeholder="Name (blank takes the flow's own label)"
            className="mb-2"
            style={{ fontSize: '0.75rem' }}
            data-bs-theme="dark"
          />

          <Form.Check
            type="switch"
            id="rfb-include-all"
            className="text-white-50 mb-2"
            style={{ fontSize: '0.73rem' }}
            label="Include subresources"
            checked={seedIncludeAll}
            onChange={(e) => setSeedIncludeAll(e.target.checked)}
          />
          <div className="text-white-50 mb-3" style={{ fontSize: '0.66rem' }}>
            Off, this copies the requests the diagram shows: the navigation and the significant
            requests. On, it also brings in the images, stylesheets and fonts, which is usually noise.
          </div>

          <Button
            variant="danger"
            disabled={!seedFlowId || busy === 'seed'}
            onClick={seedFromDetectedFlow}
          >
            {busy === 'seed'
              ? <><Spinner animation="border" size="sm" className="me-2" />Copying</>
              : <><i className="bi bi-diagram-3 me-2" />Copy this flow in</>}
          </Button>
          {actionError && (
            <div className="text-danger mt-2" style={{ fontSize: '0.7rem' }}>
              <i className="bi bi-exclamation-triangle me-1" />{actionError}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  // -------------------------------------------------------------------------
  // Render: the capture picker
  // -------------------------------------------------------------------------

  const renderCapturePicker = () => (
    <div className="d-flex flex-column flex-grow-1 p-3" style={{ minHeight: 0 }}>
      <div className="d-flex align-items-center mb-2 flex-shrink-0">
        <Button size="sm" variant="outline-secondary" onClick={() => setMode('build')}>
          <i className="bi bi-arrow-left me-2" />Back
        </Button>
        <div className="ms-3">
          <div className="text-light" style={{ fontSize: '0.85rem' }}>Add a step from a recorded request</div>
          <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
            The request's bytes are copied to the end of the flow, exactly as they were recorded.
          </div>
        </div>
      </div>

      <div className="d-flex flex-column border border-secondary rounded flex-grow-1" style={{ minHeight: 0 }}>
        <div className="p-2 border-bottom border-secondary">
          <InputGroup size="sm">
            <InputGroup.Text className="bg-dark border-secondary text-white-50">
              {capturesLoading
                ? <Spinner animation="border" size="sm" variant="danger" />
                : <i className="bi bi-search" />}
            </InputGroup.Text>
            <Form.Control
              value={captureQuery}
              onChange={(e) => setCaptureQuery(e.target.value)}
              placeholder="path ^= /api AND method = POST"
              spellCheck={false}
              style={{ fontFamily: MONO, fontSize: '0.75rem' }}
              data-bs-theme="dark"
            />
          </InputGroup>
          {capturesError && (
            <div className="text-danger mt-1" style={{ fontSize: '0.72rem' }}>
              <i className="bi bi-exclamation-triangle me-1" />{capturesError}
            </div>
          )}
          {/* A refused add leaves the operator on THIS screen, because the mode only switches back
              once the step exists. So the reason has to be readable from here. */}
          {actionError && (
            <div className="text-danger mt-1" style={{ fontSize: '0.72rem' }}>
              <i className="bi bi-exclamation-octagon me-1" />{actionError}
            </div>
          )}
          {busy === 'add-step' && (
            <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem' }}>
              <Spinner animation="border" size="sm" variant="danger" className="me-2" />
              Adding the step.
            </div>
          )}
        </div>

        <div className="flex-grow-1" style={{ overflowY: 'auto', minHeight: 0 }}>
          {captures.length === 0 ? (
            <div className="text-white-50 small p-3">
              {capturesLoading
                ? 'Searching.'
                : 'Nothing matched. Captures come from the manual crawl, so run one on this target first.'}
            </div>
          ) : (
            captures.map((capture) => (
              <div
                key={capture.id}
                className="rfb-row d-flex align-items-center px-2 py-1 border-bottom border-secondary"
                style={{ cursor: 'pointer' }}
                onClick={() => addStepFromCapture(capture.id)}
                title="Add this request as a step"
              >
                <Badge
                  bg="dark"
                  className="border border-secondary text-white-50 me-2"
                  style={{ fontSize: '0.58rem', minWidth: '46px' }}
                >
                  {(capture.method || 'GET').toUpperCase()}
                </Badge>
                <code className="flex-grow-1 text-truncate text-white-50" style={{ fontSize: '0.72rem' }}>
                  {capture.url}
                </code>
                <Badge
                  bg={statusVariant(capture.status_code != null ? capture.status_code : capture.status)}
                  className="ms-2"
                  style={{ fontSize: '0.56rem' }}
                >
                  {capture.status_code != null ? capture.status_code : (capture.status || '?')}
                </Badge>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );

  // -------------------------------------------------------------------------
  // Render: the build screen
  // -------------------------------------------------------------------------

  const renderBanners = () => (
    <>
      {detailError && (
        <div className="text-danger px-3 py-1 border-bottom border-secondary" style={{ fontSize: '0.72rem' }}>
          <i className="bi bi-exclamation-triangle me-1" />{detailError}
        </div>
      )}
      {actionError && (
        <div className="d-flex align-items-start text-danger px-3 py-1 border-bottom border-secondary"
             style={{ fontSize: '0.72rem', backgroundColor: '#2b1215' }}>
          <i className="bi bi-exclamation-octagon me-2 mt-1" />
          <div className="flex-grow-1">{actionError}</div>
          <Button size="sm" variant="link" className="text-white-50 py-0" onClick={() => setActionError('')}>
            <i className="bi bi-x-lg" />
          </Button>
        </div>
      )}
      {notice && (
        <div className="d-flex align-items-start text-warning px-3 py-2 border-bottom border-secondary"
             style={{ fontSize: '0.73rem', backgroundColor: '#2b2410' }}>
          <i className="bi bi-info-circle me-2 mt-1" />
          <div className="flex-grow-1">{notice}</div>
          <Button size="sm" variant="link" className="text-white-50 py-0" onClick={() => setNotice('')}>
            <i className="bi bi-x-lg" />
          </Button>
        </div>
      )}
      {dryRun && (
        <div className="d-flex align-items-start text-info px-3 py-2 border-bottom border-secondary"
             style={{ fontSize: '0.73rem', backgroundColor: '#11242b' }}>
          <i className="bi bi-eye me-2 mt-1" />
          <div className="flex-grow-1">
            Dry run: <strong>{dryRun.request_count}</strong> request(s) would be sent
            {Array.isArray(dryRun.hosts) && dryRun.hosts.length > 0 && <> to {dryRun.hosts.join(', ')}</>}
            , <strong>{dryRun.skipped_count}</strong> would not.
            {dryRun.scope_boundary && (
              <span className="text-white-50 ms-1">In scope: {dryRun.scope_boundary}.</span>
            )}
            {/* ON A BRANCHING FLOW THAT COUNT IS ONE PATH, NOT A TOTAL. The preview cannot know
                which steps run, because that depends on responses that have not happened, and the
                server says so in branch_note. Shown in full: a number presented as a total when it
                is really an upper bound on one path is how a run planned against a rate cap
                exceeds it. */}
            {dryRun.branch_note && (
              <div className="text-warning mt-1">
                <i className="bi bi-diagram-3 me-1" />
                {dryRun.branch_note}
              </div>
            )}
            {Array.isArray(dryRun.cycle_warnings) && dryRun.cycle_warnings.length > 0 && (
              <div className="text-warning mt-1">
                <i className="bi bi-arrow-repeat me-1" />
                {dryRun.cycle_warnings.join(' ')}
              </div>
            )}
            {Array.isArray(dryRun.steps) && dryRun.steps.filter((s) => s.refusal).length > 0 && (
              <ul className="mb-0 mt-1 ps-3">
                {dryRun.steps.filter((s) => s.refusal).map((s) => (
                  <li key={s.step_id} className="text-white-50">
                    Step {s.step_order} {s.name ? `(${s.name})` : ''}: {s.refusal}
                  </li>
                ))}
              </ul>
            )}
          </div>
          <Button size="sm" variant="link" className="text-white-50 py-0" onClick={() => setDryRun(null)}>
            <i className="bi bi-x-lg" />
          </Button>
        </div>
      )}
      {lastRun && Array.isArray(lastRun.refused_hosts) && lastRun.refused_hosts.length > 0 && (
        <div className="text-danger px-3 py-1 border-bottom border-secondary" style={{ fontSize: '0.72rem' }}>
          <i className="bi bi-shield-exclamation me-1" />
          Refused, outside this target's scope: {lastRun.refused_hosts.join(', ')}.
          {lastRun.scope_boundary && <span className="text-white-50 ms-1">In scope: {lastRun.scope_boundary}.</span>}
        </div>
      )}
    </>
  );

  const renderRunBar = () => {
    if (!selectedFlowId) return null;
    return (
      <div className="d-flex align-items-center gap-2 px-3 py-2 border-bottom border-secondary flex-shrink-0 flex-wrap">
        <Button
          size="sm"
          variant="outline-info"
          disabled={steps.length === 0 || busy === 'preview'}
          onClick={previewFlow}
          title="Ask the framework exactly what a replay would send, without sending anything."
        >
          {busy === 'preview'
            ? <><Spinner animation="border" size="sm" className="me-2" />Checking</>
            : <><i className="bi bi-eye me-2" />Dry run</>}
        </Button>
        <Button
          size="sm"
          variant="danger"
          disabled={steps.length === 0 || sendSummary.willSend === 0 || busy === 'replay-flow'}
          onClick={replayFlow}
        >
          {busy === 'replay-flow'
            ? <><Spinner animation="border" size="sm" className="me-2" />Replaying</>
            : <><i className="bi bi-play-fill me-2" />Replay flow</>}
        </Button>

        {/* What the button will do, spelled out next to it rather than discovered afterwards. */}
        <span className="text-white-50" style={{ fontSize: '0.72rem' }}>
          sends <strong className="text-light">{sendSummary.willSend}</strong> of {steps.length} step(s)
          {sendSummary.skipped > 0 && <span className="ms-1">· {sendSummary.skipped} skipped</span>}
          {sendSummary.hosts.length > 0 && <span className="ms-1">· {sendSummary.hosts.join(', ')}</span>}
        </span>

        {trace && !traceOpen && (
          <Button
            size="sm"
            variant="outline-light"
            onClick={() => setTraceOpen(true)}
            title="What the last run actually did, execution by execution."
          >
            <i className="bi bi-list-ol me-2" />Trace
          </Button>
        )}

        {variableModel.brokenSteps > 0 && (
          <span className="text-warning" style={{ fontSize: '0.72rem' }}>
            <i className="bi bi-exclamation-triangle me-1" />
            {variableModel.brokenSteps} step(s) reference a value nothing earlier captures. Those steps
            are refused rather than sent with the placeholder in them.
          </span>
        )}

        {conditionModel.errorSteps > 0 && (
          <span className="text-danger" style={{ fontSize: '0.72rem' }}>
            <i className="bi bi-x-octagon me-1" />
            {conditionModel.errorSteps} step(s) have a condition that is not finished: a goto with no
            target, or a test with nothing to compare against.
          </span>
        )}

        {conditionModel.cycles.length > 0 && (
          <span
            className="text-warning"
            style={{ fontSize: '0.72rem' }}
            title={conditionModel.cycles.map((cycle) => cycle.text).join('\n')}
          >
            <i className="bi bi-arrow-repeat me-1" />
            {conditionModel.cycles.length} loop{conditionModel.cycles.length === 1 ? '' : 's'} in this
            flow's gotos: {conditionModel.cycles[0].text}
            {conditionModel.cycles.length > 1 && <> and {conditionModel.cycles.length - 1} more</>}.
            A run that goes round one stops on a cap, mid-flow.
          </span>
        )}

        {detail && detail.scope_boundary && (
          <span className="text-white-50 ms-auto" style={{ fontSize: '0.68rem' }}>
            in scope: {detail.scope_boundary}
          </span>
        )}

        {/* The loop protection in force, as plain fact, next to the button that will hit it. Not
            settings: there is no control here that turns one off, because a flow that loops against a
            live programme is a denial of service and that is out of scope on every programme this
            framework is pointed at. An operator who cannot see the limits writes a flow that hits one
            and concludes the tool is broken. */}
        <div className="w-100 d-flex align-items-center gap-2 text-white-50" style={{ fontSize: '0.68rem' }}>
          <i className="bi bi-shield-check" />
          <span>
            Loop protection, always on:{' '}
            <strong className="text-light">{limits.max_executed_steps}</strong> executed steps per run
            {' · '}<strong className="text-light">{limits.max_per_step}</strong> executions of any one step
            {' · '}<strong className="text-light">{limits.max_retries}</strong> retries, {limits.retry_delay_ms}ms apart.
          </span>
          <OverlayTrigger
            placement="bottom"
            overlay={(
              <Tooltip>
                The budget counts EXECUTIONS, not steps: a four-step flow that loops is four
                definitions and unbounded executions, and it is the executions that reach the target.
                A run that hits any of these stops there and the trace names which one it hit. The
                engagement rate limit applies to every request either way. None of it is configurable.
              </Tooltip>
            )}
          >
            <i className="bi bi-question-circle" style={{ cursor: 'help' }} />
          </OverlayTrigger>
        </div>
      </div>
    );
  };

  // -------------------------------------------------------------------------
  // Render: the trace
  //
  // A branching run is unexplainable without this. Each execution in the order it happened, with the
  // step, the attempt, the status, WHICH condition matched and what that condition did. The matched
  // condition is the loud element on the row, because it is the answer to the only question a
  // branching run raises: why did it go there.
  //
  // A run that stopped on a cap says which cap, in the same words the run bar used. "Flow ended" with
  // no reason is how an operator concludes the target is broken when it was their own flow.
  // -------------------------------------------------------------------------

  const renderTraceRow = (row) => {
    const action = row.action ? actionSpec(row.action) : null;
    // WHAT MATCHED, IN THE SERVER'S OWN WORDS. The execution carries `matched_when`, the expression
    // text as it was evaluated, and not the rule object: rebuilding a rule from a shape the server
    // never sends produced an empty "WHEN ? THEN continue" on every row that branched. When the
    // expression is there it is shown verbatim; when it is not, the row says which rule number
    // fired, which is still an answer.
    const matchedText = row.matchedWhen
      ? `WHEN ${row.matchedWhen}`
      : (row.matchedIndex != null ? `rule ${row.matchedIndex + 1} matched` : '');
    const jumpedTo = row.gotoStepId
      ? (trace.labelOf(row.gotoStepId) || row.gotoStepName || 'another step')
      : (row.gotoStepName || '');
    const outcome = !row.action ? ''
      : row.action === 'goto'
        ? `went to ${jumpedTo || 'another step'}`
        : row.action === 'retry'
          ? `retried this step${row.delayMs ? ` after ${row.delayMs}ms` : ''}`
          : row.action === 'fail'
            ? `failed the run${row.message ? `: "${row.message}"` : ''}`
            : row.action === 'stop'
              ? `stopped the run${row.message ? `: "${row.message}"` : ''}`
              : 'continued to the next step';

    return (
      <div
        key={`${row.seq}-${row.stepId}-${row.attempt}`}
        className="d-flex align-items-baseline gap-2 px-2 py-1 border-bottom border-secondary"
        style={{ fontSize: '0.7rem', opacity: row.skipped ? 0.7 : 1 }}
      >
        <span className="text-white-50 flex-shrink-0" style={{ width: '30px' }}>#{row.seq}</span>
        <span className="text-white-50 flex-shrink-0" style={{ width: '52px' }}>step {row.stepOrder}</span>
        <span className="fw-bold text-warning flex-shrink-0" style={{ fontFamily: MONO, width: '52px' }}>
          {row.method || '?'}
        </span>
        <span
          className="text-info text-truncate"
          style={{ fontFamily: MONO, flex: '1 1 160px', minWidth: 0 }}
          title={`${row.target}${row.stepName ? ` - ${row.stepName}` : ''}`}
        >
          {row.target || '/'}
        </span>

        {row.attempt > 1 ? (
          <Badge bg="warning" text="dark" className="flex-shrink-0" style={{ fontSize: '0.56rem' }}>
            attempt {row.attempt}
          </Badge>
        ) : (
          <span className="text-white-50 flex-shrink-0" style={{ width: '58px', fontSize: '0.62rem' }}>
            attempt 1
          </span>
        )}

        {row.skipped ? (
          <Badge bg="secondary" className="flex-shrink-0" style={{ fontSize: '0.56rem' }}>skipped</Badge>
        ) : (
          <Badge bg={statusVariant(row.status)} className="flex-shrink-0" style={{ fontSize: '0.56rem', minWidth: '34px' }}>
            {row.status || '-'}
          </Badge>
        )}

        <span className="text-white-50 flex-shrink-0 text-end" style={{ width: '58px', fontSize: '0.62rem' }}>
          {row.timeMs == null ? '' : `${Math.round(row.timeMs).toLocaleString()} ms`}
        </span>

        <span className="text-white-50 flex-shrink-0">→</span>

        {/* The reason this panel exists. */}
        <span style={{ flex: '2 1 280px', minWidth: 0 }}>
          {row.skipped ? (
            <span className="text-secondary fst-italic">
              {row.skipReason || 'skipped: this step was turned off, or the run refused it'}
            </span>
          ) : row.matchedIndex != null ? (
            <>
              <Badge
                bg={action ? action.variant : 'secondary'}
                text={action && action.variant === 'warning' ? 'dark' : undefined}
                className="me-1"
                style={{ fontSize: '0.56rem' }}
              >
                rule {row.matchedIndex + 1}
              </Badge>
              {/* The test and what it did, side by side. The server sends them as two fields
                  (matched_when and action/action_target/message) and neither is the whole answer:
                  the expression without the outcome does not say where the run went. */}
              {matchedText && (
                <code className="text-light me-1" style={{ fontSize: '0.66rem' }}>{matchedText}</code>
              )}
              <span className="text-light">{outcome || 'matched'}</span>
              {row.delayMs != null && row.action === 'retry' && (
                <span className="text-white-50 ms-1">- waited {Math.round(row.delayMs)}ms</span>
              )}
            </>
          ) : (
            <span className="text-white-50 fst-italic">
              no rule matched{row.action ? ` - ${outcome}` : ' - continued to the next step'}
            </span>
          )}
          {/* A condition that could NOT be judged - a regex that will not compile, a number
              compared against text, a reference to a step that never ran. Shown because a rule that
              silently never matches looks exactly like one whose case never happened. */}
          {row.conditionProblems && row.conditionProblems.length > 0 && (
            <span
              className="text-warning ms-2"
              title={row.conditionProblems.join('\n')}
            >
              <i className="bi bi-exclamation-triangle me-1" />
              {row.conditionProblems.length} condition
              {row.conditionProblems.length === 1 ? '' : 's'} could not be judged
            </span>
          )}
          {row.error && (
            <span className="text-danger ms-2">
              <i className="bi bi-exclamation-octagon me-1" />{row.error}
            </span>
          )}
        </span>
      </div>
    );
  };

  const renderTracePanel = () => {
    if (!trace || !traceOpen) return null;
    const distinctSteps = new Set(trace.rows.map((row) => row.stepId)).size;
    return (
      <div
        className="d-flex flex-column border-bottom border-secondary flex-shrink-0"
        style={{ maxHeight: '42%', minHeight: 0, backgroundColor: '#1b1e21' }}
      >
        <div className="d-flex align-items-center px-3 py-1 border-bottom border-secondary flex-shrink-0">
          <span className="text-white-50" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
            RUN TRACE
          </span>
          <span className="text-white-50 ms-2" style={{ fontSize: '0.7rem' }}>
            {trace.rows.length} execution{trace.rows.length === 1 ? '' : 's'} across {distinctSteps} step
            {distinctSteps === 1 ? '' : 's'} · {formatTimestamp(trace.at)}
          </span>
          {trace.reconstructed && (
            <Badge
              bg="dark"
              className="border border-secondary text-white-50 ms-2"
              style={{ fontSize: '0.56rem' }}
              title="The framework returned no trace for this run, so this is what the step results prove: which steps have a response and what it was. It is not a record of the order things happened in, and it cannot show which condition matched."
            >
              reconstructed, not recorded
            </Badge>
          )}
          <Button
            size="sm"
            variant="link"
            className="text-white-50 py-0 ms-auto"
            onClick={() => setTraceOpen(false)}
            title="Collapse the trace. It stays available from the Trace button."
          >
            <i className="bi bi-chevron-up" />
          </Button>
          <Button
            size="sm"
            variant="link"
            className="text-white-50 py-0"
            onClick={() => setTrace(null)}
            title="Discard this trace"
          >
            <i className="bi bi-x-lg" />
          </Button>
        </div>

        <div className="flex-grow-1" style={{ overflowY: 'auto', overflowX: 'hidden', minHeight: 0 }}>
          {trace.rows.length === 0 ? (
            <div className="text-white-50 p-3" style={{ fontSize: '0.72rem' }}>
              The run sent nothing. Every step was turned off, or refused before it was sent.
            </div>
          ) : (
            trace.rows.map(renderTraceRow)
          )}
        </div>

        {/* A run that hit a cap says which one, in the words the run bar used. `capLabel` is set
            only for the five stop codes that ARE caps; a run stopped by its own condition, or by a
            goto with no destination, is an ending and not a loop, and gets the second panel. */}
        {trace.capLabel ? (
          <div
            className="px-3 py-2 border-top border-secondary text-danger flex-shrink-0"
            style={{ fontSize: '0.73rem', backgroundColor: '#2b1215' }}
          >
            <i className="bi bi-stop-circle me-2" />
            <strong>STOPPED: this run hit the {trace.capLabel}.</strong>{' '}
            {trace.capCode === 'retry_cap'
              ? `A step retried ${limits.max_retries} times and still matched its retry rule.`
              : trace.capCode === 'per_step_execution_cap'
                ? `One step was executed ${limits.max_per_step} times, which is the most any single step may run.`
                : trace.capCode === 'wall_clock'
                  ? `A run may not last longer than ${limits.wall_clock_s} seconds, however slowly it is paced.`
                  : trace.capCode === 'engagement_request_budget'
                    ? 'That is this programme\'s own request budget for one run, not the framework\'s: '
                      + 'lowering it is a change to the engagement config for this target.'
                    : `${limits.max_executed_steps} executions is the budget for one run, and it counts executions rather than steps.`}
            {trace.capCode !== 'engagement_request_budget' && trace.capCode !== 'wall_clock' && (
              <>
                {' '}The rest of the flow did NOT run. This is a loop in the flow, not a fault in the
                target: follow the gotos above and find the one that goes backwards.
              </>
            )}
            {/* The server's own sentence, verbatim. It names the step and the number. */}
            {trace.stopReason && <div className="text-white-50 mt-1">{trace.stopReason}</div>}
          </div>
        ) : (trace.stopReason || trace.stopNote) ? (
          <div
            className="px-3 py-2 border-top border-secondary text-warning flex-shrink-0"
            style={{ fontSize: '0.73rem', backgroundColor: '#2b2410' }}
          >
            <i className="bi bi-info-circle me-2" />
            {trace.stopNote && <span className="me-1">{trace.stopNote}</span>}
            {trace.stopReason || `The run ended: ${trace.capCode.replace(/_/g, ' ')}.`}
          </div>
        ) : null}
      </div>
    );
  };

  const renderBuild = () => {
    if (!targetId) {
      return <div className="text-white-50 small p-3">No target selected.</div>;
    }
    return (
      <>
        {renderRunBar()}
        {renderBanners()}
        {renderTracePanel()}
        <div className="d-flex flex-grow-1 p-2" style={{ minHeight: 0 }}>
          {renderFlowsColumn()}
          {renderStepsColumn()}
          {renderStepColumn()}
        </div>
      </>
    );
  };

  const flowTitle = detail && detail.flow ? detail.flow.name : null;

  return (
    <Modal show={show} onHide={requestClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-tools me-2" />
          Request Flow Builder
          {activeTarget && activeTarget.scope_target && (
            <span className="text-white-50 ms-2" style={{ fontSize: '0.9rem' }}>
              {activeTarget.scope_target}
            </span>
          )}
          {flowTitle && mode === 'build' && (
            <span className="text-light ms-2" style={{ fontSize: '0.85rem' }}>/ {flowTitle}</span>
          )}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="d-flex flex-column p-0" style={{ minHeight: 0, overflow: 'hidden' }}>
        <style>{`
          .rfb-row:hover { background-color: #2b3035 !important; }
        `}</style>
        {mode === 'seed' ? renderSeedPicker()
          : mode === 'capture' ? renderCapturePicker()
            : renderBuild()}
      </Modal.Body>
    </Modal>
  );
};

export default RequestFlowBuilderModal;
