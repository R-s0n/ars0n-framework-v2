const { validate, DATE_PATTERN } = require('./schema');

const xssCampaign = require('./xss-campaign');
const sqliCampaign = require('./sqli-campaign');

// THE WORKFLOW BOOK: stored campaign runbooks, pulled by name when an operator starts that kind of
// work.
//
// WHY THIS IS NOT THE GUIDANCE LAYER, AND DOES NOT REPLACE IT. `lies` is PUSHED: ../guidance attaches
// it to every tool result whether or not anyone asked, because the measured failure it exists for is
// an agent not knowing a step exists, and not knowing a step exists is exactly the state in which
// you do not ask about it. A workflow is the opposite shape. It is long, it is about a whole
// campaign rather than one call, and it is only useful to someone who has already decided to run
// that campaign. Attaching one to every result would cost thousands of characters per call to teach
// something the caller is usually not doing. So it is PULLED, by name, once, at the start.
//
// The two layers meet at the guidance entries for list_workflows and get_workflow in
// ../guidance/workflow.js, which are what tells a caller this store exists.
//
// WHY THE DEFINITIONS LIVE IN THE REPO AND NOT IN POSTGRES. They are versioned knowledge, the same
// kind as the guidance layer: they have to be diffable, reviewable in a pull request, and present in
// a fresh clone before anything is running. A Postgres store would make them per install and
// unversioned, so two operators would silently hold different advice and neither could see the
// difference. It is the same reasoning that put the guidance registry in four .js files.
//
// IT DOES NOT TRACK EXECUTION STATE. Nothing here records that a workflow was started, how far it
// got, or what it found. Live scan state already lives in the scan tables and is already served by
// get_scan_status, manage_xss action=results and get_tool_output. A second copy would be a second
// source of truth, and the two would disagree the first time a scan was cancelled outside the
// workflow. This is a knowledge store and it is read-only.

// Every definition module. Adding one here is the whole registration: assemble() validates it and
// refuses the load if it is malformed, so a new workflow cannot be half-added.
const DEFINITIONS = [xssCampaign, sqliCampaign];

// The sections a caller can ask for individually, in the order they are presented.
//
// `gotchas` is last in the object and FIRST in the reading order the descriptions recommend, which
// is deliberate: the steps are the cheap part and the gotchas are the product.
const SECTIONS = ['overview', 'preconditions', 'steps', 'lessons', 'gotchas'];

// The overview fields, which are what `list` returns per workflow and what every `get` carries
// whatever section was asked for. A section read with no idea what the workflow is for is a page of
// advice with no addressee.
const OVERVIEW_FIELDS = ['name', 'title', 'purpose', 'reach_for_it_when', 'not_for', 'measured_on',
  'cost', 'updated', 'related'];

// ALL OR NOTHING. A definition that fails validation takes the whole registry down at require time,
// the same way ../guidance/index.js throws on a domain collision.
//
// The alternative, skipping the bad one and serving the rest, is the exact failure this store is
// written to record: a partial load that reports success. A caller asking for a workflow that was
// silently dropped gets "unknown workflow" and reads it as "nobody has written that one yet", which
// is a different and much more comfortable claim than "it is written and it is broken". This is a
// static registry: if it loads once it loads every time, and the test suite loads it.
function assemble(definitions = DEFINITIONS) {
  const all = {};
  const problems = [];
  for (const def of definitions) {
    const found = validate(def);
    if (found.length > 0) {
      problems.push(...found);
      continue;
    }
    if (all[def.name]) {
      problems.push(`${def.name} is defined twice, so one of the two would be discarded`);
      continue;
    }
    all[def.name] = def;
  }
  // `related` NAMES MUST EXIST. The schema can only see one definition at a time, so it checks that
  // related is a list of names and stops there; whether those names resolve is a question about the
  // registry and can only be asked here, once everything is keyed.
  //
  // A dead pointer is worse in this store than in most. get() answers an unknown name with the list
  // of names that do exist, which reads as "nobody has written that one yet", and a reader who was
  // sent there by a related field has been told the opposite of the truth: the workflow they were
  // pointed at is the one that was misspelled. Checked after the loop rather than inside it so a
  // forward reference to a workflow later in DEFINITIONS is fine.
  for (const def of Object.values(all)) {
    for (const name of def.related || []) {
      if (name === def.name) {
        problems.push(`${def.name}.related points at itself`);
      } else if (!all[name]) {
        problems.push(`${def.name}.related names "${name}", which is not a workflow in this ` +
          `registry (known: ${Object.keys(all).sort().join(', ')})`);
      }
    }
  }
  if (problems.length > 0) {
    throw new Error(`workflow registry: ${problems.length} problem(s), nothing was loaded: ` +
      problems.join('; '));
  }
  return all;
}

const ALL = assemble();

// A deliberate ceiling on one `get`, in characters, roughly 10k tokens.
//
// It is NOT a truncation budget. A truncated gotcha list reads exactly like a complete one, which is
// the failure mode every entry in the seed workflow is about, so a workflow over the ceiling is
// refused with its section sizes instead of being cut.
//
// MEASURED on the seed: xss-campaign serialises whole to 24,103 characters, of which gotchas is
// 11,814 across 15 entries, steps 5,544, lessons 3,058 and preconditions 1,979. A first draft of
// this constant was 24,000 and it refused the only workflow in the store by 103 characters, which is
// how the number below came to be measured rather than guessed. 40,000 leaves the seed room to grow
// by about two thirds; a workflow that outgrows it is a workflow that wants splitting in two, not a
// higher ceiling, because nobody reads 15k tokens of runbook before starting work.
const GET_CHAR_CEILING = 40000;

function measure(value) {
  return JSON.stringify(value === undefined ? null : value).length;
}

// HOW OLD THIS ADVICE IS, ON EVERY READ, WITHOUT ANYONE ASKING FOR IT.
//
// measured_on and updated were carried from the first version of this store and they read perfectly
// well, which is the problem: "2026-09-17" on a card is not a signal, it is a fact the reader has to
// subtract today from, and nobody does that for an entry that looks fine. THIS PROJECT HAS ALREADY
// PAID FOR EXACTLY THAT. A stored note said sqlmap had no --flush-session. It was true when it was
// written and false when it was acted on, and nothing about the note looked any different on the day
// it stopped being true.
//
// So age_days is DERIVED and attached to every list row and every get, and a workflow past the
// threshold also carries one sentence telling the reader to re-measure before acting on its numbers.
// One sentence, only on the stale ones: a warning attached to every entry is furniture, and an entry
// that is three days old does not need advice about its own freshness.
//
// 90 DAYS, AND IT IS A JUDGEMENT RATHER THAN A MEASUREMENT. The real invalidator here is not the
// calendar: it is a container rebuild or a tool release, either of which can falsify a flag claim
// the day after it was measured, and no date arithmetic can see that. 90 days is simply the point
// past which nobody remembers whether the image these numbers came from is the image running now.
// Sized against what the store actually claims: ghauri 1.4.3 behaviour, composer line numbers such
// as sqliCompose.go:84, and one oracle image.
const STALE_AFTER_DAYS = 90;

function dateIn(text) {
  const found = DATE_PATTERN.exec(String(text === undefined || text === null ? '' : text));
  return found ? found[0] : null;
}

// The age is read off the LATEST date the entry claims, which is `updated` when a workflow has been
// revised and `measured_on` when it has not. Sorting the two rather than preferring one means an
// `updated` line left behind by a copy paste cannot make an entry look older than its own
// measurement, and a revision always wins over the original run.
//
// `now` is a parameter so the behaviour can be driven at a fixed date in a test. A staleness rule
// tested only against the real clock is a rule that passes for 90 days and then starts failing.
function ageOf(def, now = new Date()) {
  const dates = [dateIn(def.measured_on), dateIn(def.updated)].filter(Boolean).sort();
  const asOf = dates[dates.length - 1];
  if (!asOf) return null;
  const then = Date.UTC(Number(asOf.slice(0, 4)), Number(asOf.slice(5, 7)) - 1, Number(asOf.slice(8, 10)));
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  // Clamped at zero. A workflow dated tomorrow is a clock disagreement, and "-1 days old" reads as
  // a bug in this file rather than as a note about the entry.
  const ageDays = Math.max(0, Math.round((today - then) / 86400000));
  return { as_of: asOf, age_days: ageDays, stale: ageDays >= STALE_AFTER_DAYS };
}

function overviewOf(def, now) {
  const out = {};
  for (const field of OVERVIEW_FIELDS) {
    if (def[field] !== undefined) out[field] = def[field];
  }
  const age = ageOf(def, now);
  if (age) {
    out.as_of = age.as_of;
    out.age_days = age.age_days;
    if (age.stale) {
      out.staleness = `Measured ${age.age_days} days ago. Re-measure the numbers in this ` +
        'workflow against the containers you are running before you plan a campaign on them.';
    }
  }
  return out;
}

// The index. Counts rather than contents, because the counts are what an operator chooses on: a
// workflow with 14 gotchas is a different proposition from one with 1.
function list(query, now) {
  const needle = typeof query === 'string' ? query.trim().toLowerCase() : '';
  const rows = [];
  for (const def of Object.values(ALL)) {
    if (needle) {
      const haystack = [def.name, def.title, def.purpose, def.reach_for_it_when, def.not_for]
        .filter(Boolean).join(' ').toLowerCase();
      if (!haystack.includes(needle)) continue;
    }
    rows.push({
      ...overviewOf(def, now),
      steps: def.steps.length,
      preconditions: def.preconditions.length,
      lessons: def.lessons.length,
      gotchas: def.gotchas.length,
      chars: measure(def),
    });
  }
  rows.sort((a, b) => a.name.localeCompare(b.name));
  return rows;
}

// One workflow, whole or by section.
//
// An unknown name is answered with the names that DO exist rather than with an error, because the
// caller is an agent that guessed a name and the useful next move is the list, not a stack trace.
function get(name, section = 'all', now) {
  const def = ALL[name];
  if (!def) {
    return {
      error: 'unknown workflow',
      requested: name,
      known_workflows: Object.keys(ALL).sort(),
      note: 'Workflow names are stable kebab case ids. Call list_workflows for what each one is for.',
    };
  }

  const wanted = SECTIONS.includes(section) ? [section] : SECTIONS;
  const body = { ...overviewOf(def, now) };
  for (const key of wanted) {
    if (key === 'overview') continue;
    body[key] = def[key];
  }

  // The refusal, not a truncation. See GET_CHAR_CEILING.
  if (section === 'all' && measure(body) > GET_CHAR_CEILING) {
    const sizes = {};
    for (const key of SECTIONS) {
      sizes[key] = key === 'overview' ? measure(overviewOf(def, now)) : measure(def[key]);
    }
    return {
      ...overviewOf(def, now),
      error: 'this workflow is larger than one read',
      chars: measure(body),
      ceiling: GET_CHAR_CEILING,
      section_chars: sizes,
      note: 'Ask for one section at a time. Nothing is truncated here on purpose: a cut list of ' +
        'gotchas reads exactly like a complete one. Read gotchas first, then steps.',
    };
  }

  return body;
}

module.exports = {
  ALL,
  SECTIONS,
  OVERVIEW_FIELDS,
  GET_CHAR_CEILING,
  STALE_AFTER_DAYS,
  ageOf,
  list,
  get,
  // Exported so a test can drive the all-or-nothing rule with a deliberately malformed definition
  // rather than by breaking a real one.
  assemble,
  validate,
};
