// THE SHAPE OF AN AGENT ROLE, and the validator that refuses one that is not that shape.
//
// Cloned in spirit from src/workflows/schema.js. A role here is a methodology-anchored hunt mandate:
// what this role is for, which methodology step it owns, which tools it may reach for (advisory only),
// when it enters and exits, what "done" MEASURES, and who it hands off to. The validator exists to
// stop the two failures that quietly rot a store like this:
//
//   AN UNMEASURED DEFINITION OF DONE. "The scan is complete" reads like a finish line and certifies
//   nothing. So definition_of_done.measured must carry a digit and be long enough to name a count, a
//   ratio or a duration, the same blunt rule the workflow book uses. A role that cannot say how many
//   of what it covered cannot tell a tested-clean verdict from an untested one.
//
//   AN UNDATEABLE ROLE. The store reports the age of every role on every read. A role whose
//   measured_on carries no YYYY-MM-DD date would be the one entry silently exempt from that, so it is
//   refused at load.
//
// UNKNOWN KEYS ARE REFUSED. A role with persona:, backstory: or a mistyped field would otherwise load
// cleanly and serve a role with a section silently missing, and a reader cannot see an absence. There
// is NO persona or backstory field: a role is a mandate, not a character.
//
// validate returns a list of problem strings. It NEVER throws and it never returns a repaired
// definition: assemble() in index.js is the only caller that matters and it refuses the whole load.

const steps = require('../guidance/steps');

// A stable name is the address an operator types, so it has to survive a rename of the title and be
// safe as a filename and as a JSON key. Kebab case, no leading digit.
const NAME_PATTERN = /^[a-z][a-z0-9-]{2,48}$/;

// Evidence must carry a numeral. A definition of done with no number is a claim, not a measurement.
const MEASUREMENT_PATTERN = /[0-9]/;

// A date the reader can be shown, so every role can be aged on read.
const DATE_PATTERN = /\b(20\d\d)-(0\d|1[0-2])-([0-2]\d|3[01])\b/;

// The scope kinds a role may declare, matching the three target types plus a wildcard for roles that
// apply to any target.
const SCOPE_TARGET_TYPES = new Set(['Company', 'Wildcard', 'URL', '*']);

// Below this, a prose field is a label rather than a statement.
const MIN_PROSE_CHARS = 24;

// Below this, a measured field is a gesture at evidence rather than evidence.
const MIN_MEASUREMENT_CHARS = 20;

// The top level shape. `prose` fields must be a usable string of at least MIN_PROSE_CHARS; `tool_lists`
// must be arrays of strings (may be empty); the rest have bespoke checks below. Anything not named
// here is a typo and is refused.
const TOP_LEVEL = {
  required: ['id', 'title', 'pillar', 'scope_target_types', 'anchors', 'mandate', 'allowed_tools',
    'encouraged_tools', 'off_limits_tools', 'entry_criteria', 'exit_criteria', 'definition_of_done',
    'handoff', 'measured_on'],
  optional: ['rule', 'updated'],
  prose: ['title', 'mandate', 'entry_criteria', 'exit_criteria'],
  tool_lists: ['allowed_tools', 'encouraged_tools', 'off_limits_tools'],
};

// An anchor says WHERE in the methodology this role sits. Only `step` is validated, and it must be a
// real step: the vocabulary is the single source of truth in src/guidance/steps.js. scanner_section
// and vuln_class are free parameterization text used by the vector scanner and bypass roles.
const ANCHOR = {
  required: ['step'],
  optional: ['scanner_section', 'vuln_class'],
};

// A handoff names who picks the work up next, under what condition, and what artifact carries across.
// The `to` is only cross-checked against the live registry in assemble(), never here, because the
// schema can only see one role at a time.
const HANDOFF = {
  required: ['to', 'when', 'artifact'],
  optional: [],
};

function isUsableString(value, min) {
  return typeof value === 'string' && value.trim().length >= min;
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

function checkAnchor(problems, where, item, index) {
  const at = `${where}.anchors[${index}]`;
  if (item === null || typeof item !== 'object' || Array.isArray(item)) {
    problems.push(`${at} is not an object`);
    return;
  }
  const known = new Set([...ANCHOR.required, ...ANCHOR.optional]);
  for (const key of Object.keys(item)) {
    if (!known.has(key)) {
      problems.push(`${at} has unknown field "${key}" (allowed: ${[...known].sort().join(', ')})`);
    }
  }
  if (!isUsableString(item.step, 1)) {
    problems.push(`${at}.step is missing or not a usable string`);
  } else if (!steps.ALLOWED_STEPS.has(item.step)) {
    problems.push(`${at}.step "${item.step}" is not one of the methodology steps in ` +
      'src/guidance/steps.js, so an agent told it would not know where it is');
  }
  for (const field of ANCHOR.optional) {
    if (item[field] === undefined) continue;
    if (!isUsableString(item[field], 1)) {
      problems.push(`${at}.${field} is present but is not a usable string`);
    }
  }
}

function checkHandoff(problems, where, item, index) {
  const at = `${where}.handoff[${index}]`;
  if (item === null || typeof item !== 'object' || Array.isArray(item)) {
    problems.push(`${at} is not an object`);
    return;
  }
  const known = new Set([...HANDOFF.required, ...HANDOFF.optional]);
  for (const key of Object.keys(item)) {
    if (!known.has(key)) {
      problems.push(`${at} has unknown field "${key}" (allowed: ${[...known].sort().join(', ')})`);
    }
  }
  for (const field of HANDOFF.required) {
    if (!isUsableString(item[field], 1)) {
      problems.push(`${at}.${field} is missing or not a usable string`);
    }
  }
}

function checkDefinitionOfDone(problems, where, dod) {
  const at = `${where}.definition_of_done`;
  if (dod === null || typeof dod !== 'object' || Array.isArray(dod)) {
    problems.push(`${at} is missing or is not an object`);
    return;
  }
  const known = new Set(['measured', 'source']);
  for (const key of Object.keys(dod)) {
    if (!known.has(key)) {
      problems.push(`${at} has unknown field "${key}" (allowed: ${[...known].sort().join(', ')})`);
    }
  }
  if (!isUsableString(dod.source, MIN_PROSE_CHARS)) {
    problems.push(`${at}.source is missing or shorter than ${MIN_PROSE_CHARS} characters`);
  }
  // The measured rule. A done signal with no number is a claim and not a measurement, so it is
  // refused the same way an unevidenced gotcha is in the workflow book.
  if (!isUsableString(dod.measured, MIN_MEASUREMENT_CHARS)) {
    if (isUsableString(dod.measured, MIN_PROSE_CHARS)) {
      problems.push(`${at}.measured is too short to be a measurement ` +
        `(needs ${MIN_MEASUREMENT_CHARS} characters, has ${dod.measured.trim().length})`);
    } else {
      problems.push(`${at}.measured is missing or shorter than ${MIN_MEASUREMENT_CHARS} characters`);
    }
    return;
  }
  if (!MEASUREMENT_PATTERN.test(dod.measured)) {
    problems.push(`${at}.measured contains no number, so it is a claim and not a measurement. ` +
      'Write the count, ratio or duration that separates done from not done.');
  }
}

function validate(def) {
  const problems = [];
  if (def === null || typeof def !== 'object' || Array.isArray(def)) {
    return ['definition is not an object'];
  }
  const where = typeof def.id === 'string' && def.id ? def.id : '<unnamed>';

  const known = new Set([...TOP_LEVEL.required, ...TOP_LEVEL.optional]);
  for (const key of Object.keys(def)) {
    if (!known.has(key)) {
      problems.push(`${where} has unknown field "${key}" (allowed: ${[...known].sort().join(', ')})`);
    }
  }

  if (!isUsableString(def.id, 3) || !NAME_PATTERN.test(def.id)) {
    problems.push(`${where}.id must be kebab case, 3 to 49 characters, starting with a letter`);
  }

  for (const field of TOP_LEVEL.prose) {
    if (!isUsableString(def[field], MIN_PROSE_CHARS)) {
      problems.push(`${where}.${field} is missing or shorter than ${MIN_PROSE_CHARS} characters`);
    }
  }

  // pillar is free text (recon, mapping, scanning, bypass, analysis, support), so it only has to be a
  // usable string. The near-duplicate labels are not enforced here on purpose; the pillar is a hint,
  // not an index key.
  if (!isUsableString(def.pillar, 1)) {
    problems.push(`${where}.pillar is missing or not a usable string`);
  }

  // rule is optional, but if present it has to be a statement rather than a label.
  if (def.rule !== undefined && !isUsableString(def.rule, MIN_PROSE_CHARS)) {
    problems.push(`${where}.rule is present but is shorter than ${MIN_PROSE_CHARS} characters`);
  }

  // scope_target_types must be a non-empty array drawn from the allowed set.
  if (!Array.isArray(def.scope_target_types) || def.scope_target_types.length === 0) {
    problems.push(`${where}.scope_target_types is missing or empty`);
  } else {
    for (const t of def.scope_target_types) {
      if (!SCOPE_TARGET_TYPES.has(t)) {
        problems.push(`${where}.scope_target_types has "${t}", not one of ` +
          `${[...SCOPE_TARGET_TYPES].join(', ')}`);
      }
    }
  }

  // The three tool lists are advisory, so they may be empty, but they must be arrays of strings: a
  // string left where a list belongs would read as one tool named by its every character.
  for (const field of TOP_LEVEL.tool_lists) {
    if (!isStringArray(def[field])) {
      problems.push(`${where}.${field} must be an array of tool-name strings (may be empty)`);
    }
  }

  // anchors is the required where-am-I. A role with no anchor cannot be placed in the methodology.
  if (!Array.isArray(def.anchors) || def.anchors.length === 0) {
    problems.push(`${where}.anchors is missing or empty`);
  } else {
    def.anchors.forEach((item, i) => checkAnchor(problems, where, item, i));
  }

  // handoff may be empty (a terminal role hands off to nobody) but must be an array of well formed
  // items when present.
  if (!Array.isArray(def.handoff)) {
    problems.push(`${where}.handoff must be an array (may be empty)`);
  } else {
    def.handoff.forEach((item, i) => checkHandoff(problems, where, item, i));
  }

  checkDefinitionOfDone(problems, where, def.definition_of_done);

  // measured_on is the provenance of the role: which corpus, which day. A role with no date cannot be
  // aged, and a stale scanner mandate is a liability.
  if (!isUsableString(def.measured_on, MIN_PROSE_CHARS)) {
    problems.push(`${where}.measured_on is missing or shorter than ${MIN_PROSE_CHARS} characters`);
  } else {
    if (!MEASUREMENT_PATTERN.test(def.measured_on)) {
      problems.push(`${where}.measured_on carries no number, so it names no date and no corpus size`);
    }
    if (!DATE_PATTERN.test(def.measured_on)) {
      problems.push(`${where}.measured_on carries no YYYY-MM-DD date, so this role could not be aged ` +
        'and would be the one entry whose staleness a reader cannot see');
    }
  }

  // updated is optional, but ageOf() reads it as a candidate latest date (the same freshen path the
  // sibling workflows store supports), so if a maintainer adds it, it must carry a parseable date.
  // Without this check a dateless `updated` would feed a bad value into ageOf; with the key missing
  // from the allowed set entirely it would brick the whole registry load, so it must be allowed AND
  // dated, not merely tolerated.
  if (def.updated !== undefined &&
      (!isUsableString(def.updated, MIN_PROSE_CHARS) || !DATE_PATTERN.test(def.updated))) {
    problems.push(`${where}.updated is present but is not a dated (YYYY-MM-DD) statement of at least ` +
      `${MIN_PROSE_CHARS} characters`);
  }

  return problems;
}

module.exports = {
  validate,
  NAME_PATTERN,
  DATE_PATTERN,
  MEASUREMENT_PATTERN,
  SCOPE_TARGET_TYPES,
  MIN_PROSE_CHARS,
  MIN_MEASUREMENT_CHARS,
  TOP_LEVEL,
};
