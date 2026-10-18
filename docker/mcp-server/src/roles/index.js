// THE AGENT ROLE REGISTRY: a methodology-anchored catalogue of hunt roles, pulled by id or served as
// an overview, with a one-line hint for the step a role owns.
//
// Cloned in spirit from src/workflows/index.js, which is where the all-or-nothing load, the collision
// refusal, the dead-cross-reference check, the refuse-not-truncate read ceiling and the age/staleness
// derivation all come from. The one thing this registry adds that the workflow book does not need is a
// TOTAL one-role-per-step index: hintForStep has to be deterministic, so no two roles may claim the
// same primary methodology step.
//
// WHY THE DEFINITIONS LIVE IN THE REPO AND NOT IN POSTGRES. Same reasoning as the workflow book: roles
// are versioned knowledge, diffable and reviewable in a pull request and present in a fresh clone
// before anything is running. A per-install Postgres role board would let two operators silently hold
// different roles, and there is NO board here: assign/release is session-scoped advisory state only.
//
// TOOL SCOPING IS ADVISORY. The allowed/encouraged/off_limits lists are advice a role carries, not a
// gate. The client still sees every tool. The one hard gate in the server is the operator GOAL_GATE.

const steps = require('../guidance/steps');
const { validate, DATE_PATTERN } = require('./schema');

// Every per-phase definition module. Adding a role to one of these files is the whole registration:
// assemble() validates it and refuses the load if it is malformed, so a role cannot be half-added.
const DEFINITIONS = [].concat(
  require('./recon'),
  require('./mapping'),
  require('./scanning'),
  require('./bypass'),
  require('./analysis'),
  require('./support'));

// The sections a caller can ask for individually, in the order they are presented. mandate first
// because it is what tells a reader whether this is the role they want; definition_of_done and handoff
// last because they are what tells them when to stop and who is next.
const SECTIONS = ['mandate', 'rule', 'boundaries', 'criteria', 'definition_of_done', 'handoff'];

// The overview fields, which are what `list` returns per role and what every `get` carries whatever
// section was asked for. A section read with no idea what the role is for is advice with no addressee.
const OVERVIEW_FIELDS = ['id', 'title', 'pillar', 'primary_step', 'scope_target_types', 'mandate'];

// A deliberate ceiling on one `get`, in characters, roughly 5k tokens. It is NOT a truncation budget.
// A truncated role reads exactly like a complete one, which is the failure the whole methodology layer
// exists to avoid, so a role over the ceiling is refused with its section sizes instead of being cut.
const GET_CHAR_CEILING = 20000;

// 90 days, a judgement rather than a measurement, the same as the workflow book. The real invalidator
// is a methodology revision or a tool release, which no date arithmetic can see; 90 days is simply the
// point past which nobody remembers whether the run these numbers came from is the run happening now.
const STALE_AFTER_DAYS = 90;

function measure(value) {
  return JSON.stringify(value === undefined ? null : value).length;
}

// ALL OR NOTHING. A role that fails validation takes the whole registry down at require time, the same
// way src/workflows/index.js throws on a malformed workflow and src/guidance/index.js throws on a
// domain collision. Skipping the bad one and serving the rest is the exact failure this layer records:
// a partial load that reports success, where a caller asking for a dropped role gets "unknown role"
// and reads it as "nobody has written that one yet".
//
// `assemble` is exported so a test can drive the collision refusals with fixtures rather than by
// breaking a real role file.
function assemble(definitions = DEFINITIONS) {
  const all = {};
  const stepIndex = {};
  const problems = [];

  for (const def of definitions) {
    const found = validate(def);
    if (found.length > 0) {
      problems.push(...found);
      continue;
    }
    if (all[def.id]) {
      problems.push(`${def.id} is defined twice, so one of the two would be discarded`);
      continue;
    }
    all[def.id] = def;
  }

  // THE TOTAL ONE-ROLE-PER-STEP INDEX. The primary anchor (anchors[0]) is the step the role owns and
  // the only one that produces a hint; later anchors are advisory metadata and are not indexed. Two
  // roles claiming the same non-ANY, non-CONFIG primary step would make hintForStep non-deterministic,
  // so it is a load failure, not a last-writer-wins. ANY and CONFIG never produce a hint and never
  // collide, so they are skipped. Built here, after keying, so the collision message can name both ids.
  for (const def of Object.values(all)) {
    const primary = def.anchors && def.anchors[0] && def.anchors[0].step;
    if (!primary || primary === steps.ANY || primary === steps.CONFIG) continue;
    if (stepIndex[primary]) {
      problems.push(`two roles anchor step "${primary}": ${stepIndex[primary]}, ${def.id} ` +
        '(one role per step is required so the step hint is deterministic)');
      continue;
    }
    stepIndex[primary] = def.id;
  }

  // HANDOFF POINTERS MUST RESOLVE. The schema can only see one role at a time, so it checks that a
  // handoff item is well formed and stops there; whether its `to` names a real role is a question about
  // the registry and can only be asked here, once everything is keyed. A dead handoff pointer is worse
  // than most dead pointers: get() answers an unknown id with the list of ids that do exist, which
  // reads as "nobody has written that one yet", so a reader sent there by a handoff has been told the
  // opposite of the truth. A handoff pointing at its own role is a loop and is refused too.
  for (const def of Object.values(all)) {
    for (const h of def.handoff || []) {
      const to = h && h.to;
      if (to === def.id) {
        problems.push(`${def.id}.handoff points at itself`);
      } else if (!all[to]) {
        problems.push(`${def.id}.handoff names "${to}", which is not a role in this registry ` +
          `(known: ${Object.keys(all).sort().join(', ')})`);
      }
    }
  }

  if (problems.length > 0) {
    throw new Error(`role registry: ${problems.length} problem(s), nothing was loaded: ` +
      problems.join('; '));
  }
  return all;
}

const ALL = assemble();

// The step index rebuilt from the loaded registry. assemble() already proved it has no collisions, so
// this fold cannot throw; it exists so hintForStep and the tests can read the mapping directly. ANY and
// CONFIG are excluded exactly as in assemble().
function buildStepIndex(all) {
  const index = {};
  for (const def of Object.values(all)) {
    const primary = def.anchors && def.anchors[0] && def.anchors[0].step;
    if (!primary || primary === steps.ANY || primary === steps.CONFIG) continue;
    index[primary] = def.id;
  }
  return index;
}

const STEP_INDEX = buildStepIndex(ALL);

function dateIn(text) {
  const found = DATE_PATTERN.exec(String(text === undefined || text === null ? '' : text));
  return found ? found[0] : null;
}

// HOW OLD THIS ROLE IS, ON EVERY READ, WITHOUT ANYONE ASKING. Copied from the workflow book. A role
// carries measured_on; the age is read off it, and a role past the threshold carries one sentence
// telling the reader to re-measure before acting on its numbers. `now` is a parameter so a test can
// drive staleness at a fixed date rather than against the real clock.
function ageOf(def, now = new Date()) {
  const dates = [dateIn(def.measured_on), dateIn(def.updated)].filter(Boolean).sort();
  const asOf = dates[dates.length - 1];
  if (!asOf) return null;
  const then = Date.UTC(Number(asOf.slice(0, 4)), Number(asOf.slice(5, 7)) - 1, Number(asOf.slice(8, 10)));
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const ageDays = Math.max(0, Math.round((today - then) / 86400000));
  return { as_of: asOf, age_days: ageDays, stale: ageDays >= STALE_AFTER_DAYS };
}

function overviewOf(def, now) {
  const out = {};
  out.id = def.id;
  out.title = def.title;
  out.pillar = def.pillar;
  out.primary_step = (def.anchors && def.anchors[0] && def.anchors[0].step) || null;
  out.scope_target_types = def.scope_target_types;
  out.mandate = def.mandate;
  const age = ageOf(def, now);
  if (age) {
    out.as_of = age.as_of;
    out.age_days = age.age_days;
    if (age.stale) {
      out.staleness = `Measured ${age.age_days} days ago. Re-measure this role against the ` +
        'methodology and the tools you are running before you act on its numbers.';
    }
  }
  return out;
}

// The value of one section, used both to build a `get` body and to size it for the refusal.
function sectionValue(def, key) {
  switch (key) {
    case 'mandate': return def.mandate;
    case 'rule': return def.rule;
    case 'boundaries': return {
      allowed_tools: def.allowed_tools,
      encouraged_tools: def.encouraged_tools,
      off_limits_tools: def.off_limits_tools,
    };
    case 'criteria': return { entry_criteria: def.entry_criteria, exit_criteria: def.exit_criteria };
    case 'definition_of_done': return def.definition_of_done;
    case 'handoff': return def.handoff;
    default: return undefined;
  }
}

function addSection(body, def, key) {
  switch (key) {
    case 'mandate':
      body.mandate = def.mandate;
      break;
    case 'rule':
      if (def.rule !== undefined) body.rule = def.rule;
      break;
    case 'boundaries':
      body.allowed_tools = def.allowed_tools;
      body.encouraged_tools = def.encouraged_tools;
      body.off_limits_tools = def.off_limits_tools;
      break;
    case 'criteria':
      body.entry_criteria = def.entry_criteria;
      body.exit_criteria = def.exit_criteria;
      break;
    case 'definition_of_done':
      body.definition_of_done = def.definition_of_done;
      break;
    case 'handoff':
      body.handoff = def.handoff;
      break;
    default:
      break;
  }
}

// The index. Overview rows an operator chooses a role on, filtered by a case-insensitive substring
// over id, title, pillar and mandate.
function list(query, now) {
  const needle = typeof query === 'string' ? query.trim().toLowerCase() : '';
  const rows = [];
  for (const def of Object.values(ALL)) {
    if (needle) {
      const haystack = [def.id, def.title, def.pillar, def.mandate]
        .filter(Boolean).join(' ').toLowerCase();
      if (!haystack.includes(needle)) continue;
    }
    rows.push(overviewOf(def, now));
  }
  rows.sort((a, b) => a.id.localeCompare(b.id));
  return rows;
}

// One role, whole or by section. An unknown id is answered with the ids that DO exist rather than with
// an error, because the caller is an agent that guessed an id and the useful next move is the list.
function get(id, section = 'all', now) {
  const def = ALL[id];
  if (!def) {
    return {
      error: 'unknown role',
      requested: id,
      known_roles: Object.keys(ALL).sort(),
      note: 'Role ids are stable kebab case. Call list to see what each one is for.',
    };
  }

  const wanted = SECTIONS.includes(section) ? [section] : SECTIONS;
  const body = { ...overviewOf(def, now) };
  for (const key of wanted) addSection(body, def, key);

  // The refusal, not a truncation. See GET_CHAR_CEILING. Only a full read can exceed it, so only a
  // full read is measured; a single section is always servable.
  if (section === 'all' && measure(body) > GET_CHAR_CEILING) {
    const sizes = {};
    for (const key of SECTIONS) sizes[key] = measure(sectionValue(def, key));
    return {
      ...overviewOf(def, now),
      error: 'this role is larger than one read',
      chars: measure(body),
      ceiling: GET_CHAR_CEILING,
      section_chars: sizes,
      note: 'Ask for one section at a time. Nothing is truncated here on purpose: a cut role reads ' +
        'exactly like a complete one.',
    };
  }

  return body;
}

// The one-line hint for the step a tool result is tagged with. Returns a plain string or null. It
// no-ops on no step, on the Any/Configuration pseudo-steps, and on any step no role owns, so it can
// ride every tool result without ever emitting a wrong-phase hint. The hyphen in the template is a
// plain hyphen.
function hintForStep(step) {
  if (!step || step === steps.ANY || step === steps.CONFIG) return null;
  const id = STEP_INDEX[step];
  if (!id) return null;
  const def = ALL[id];
  const mandate = String(def.mandate || '').split(/(?<=[.!?])\s/)[0];
  return `Role for this step: ${def.id} (${def.title}) - ${mandate}`;
}

module.exports = {
  ALL,
  STEP_INDEX,
  SECTIONS,
  GET_CHAR_CEILING,
  STALE_AFTER_DAYS,
  ageOf,
  list,
  get,
  hintForStep,
  // Exported so a test can drive the collision and dead-pointer refusals with fixtures rather than by
  // breaking a real role file.
  assemble,
  validate,
};
