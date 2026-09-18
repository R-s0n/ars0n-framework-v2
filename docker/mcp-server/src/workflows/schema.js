// THE SHAPE OF A WORKFLOW, and the validator that refuses one that is not that shape.
//
// A workflow here is not a runbook. A runbook is the cheap part: "run dalfox, then domdig, then
// xssFuzz, unauthenticated and then authenticated" is one sentence and nobody has ever got it wrong.
// The XSS campaign that produced the first entry in this store cost four restarts, and not one of
// them would have been prevented by a list of steps. Every one was configuration that FAILED OPEN:
// a tool told something it did not understand, exiting 0, reporting nothing, and being recorded as
// clean. Measured on that run: 21 of 30 clean verdicts were on routes that answer 401 without a
// credential, and a prior run of the same section spent 53 vectors and 48,859 requests finding
// nothing because one setting blinded the tool.
//
// So the schema forces the two things a runbook omits and which are the whole point:
//
//   LESSONS   what the last run learned, each carrying the measurement that produced it
//   GOTCHAS   how this goes wrong, each carrying the measurement, what the wrong answer LOOKS LIKE,
//             and the fix
//
// A GOTCHA WITHOUT EVIDENCE IS REFUSED, NOT WARNED ABOUT. `measured` is required on every lesson and
// every gotcha and it must contain a digit. That rule is blunt on purpose. The failure mode of a
// knowledge store like this is that it fills up with plausible advice nobody measured, at which
// point it is a blog post and a reader cannot tell which half to trust. Requiring a numeral means an
// author has to write down the count, the duration, the ratio or the exit code they actually saw. If
// a real observation genuinely has no number in it, write the number you did see: "0 of 215
// vectors", "3 of 41 endpoints", "both runs, 3.2s and 3.5s". That is house style anyway.
//
// A DIGIT IS NOT EVIDENCE, AND THAT RULE ON ITS OWN WAS NOT ENOUGH. The store's promise is MEASURED;
// the enforcement above is only NUMERIC. Two fabricated numbers shipped in the SQLi entry and both
// satisfied it comfortably. One said a tool "spends 133 requests against the oracle": 133 was never
// a request count, it is the resume denominator on one line of the campaign log, "7 already settled,
// 133 to do", misread off a progress counter. The other said "40 requests at /api/v1/assets left the
// counters unchanged": no such experiment was ever run, and it was self-refuting anyway, since if the
// probed endpoint's own counter did not move the test distinguishes nothing. Both read as evidence.
// Both had digits. Neither could be checked without going and looking, and nothing made anyone go.
//
// So `source` is required alongside `measured`, and it must carry an ADDRESS: somewhere a reader can
// OPEN to re-check the number. Four forms, because four kinds of artifact produced everything in this
// book, and all four reduce to a path with a line or an id:
//   a campaign artifact     sqli/campaign.log:33, sqli/WORKFLOW-sqli-campaign.md:30
//   an operator memory note memory/sqli-tooling.md:69
//   a source file and line  server/utils/sqliCompose.go:84
//   a database row          Postgres scan b7fe528f-6e7a-41e1-81fc-eb437cd58c92
//
// WHAT THIS CATCHES AND WHAT IT DOES NOT, because overstating it would be the same defect again.
// It catches the unsourceable claim: the 40-request experiment has no artifact to address, so it
// cannot be written down, and both fabricated claims shipped with no `source` at all and would have
// been refused at load. It does NOT catch a sourced misreading. An author who writes
// "sqli/campaign.log:33" beside "133 requests" satisfies every check here and is still wrong, because
// separating a true number from a false one needs the artifact, which the validator cannot read: the
// campaign scratchpad is not in the image, and Postgres is not up at load. A load-time check cannot
// do it. What it can do is force the author to the artifact, and the artifact is where the 133 claim
// dies, because the line it points at says "133 to do". test/workflows.test.js carries the half that
// CAN be mechanically resolved: every address pointing into this repo must name a file that exists
// and a line that exists in it.

// An address a reader can open: a path with a line number, or a UUID naming a database row. The
// line number is the point. "campaign.log" sends a reader to an 8KB file; "campaign.log:33" sends
// them to the sentence, which is the only version of this that gets checked.
const SOURCE_ADDRESS = new RegExp(
  '(?:[A-Za-z0-9_.-]+[/\\\\])*[A-Za-z0-9_.-]+\\.[A-Za-z0-9]{1,8}:\\d+'
  + '|\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b');
//
// A STEP IS do/assert/verify/looks_like, NOT A COMMAND. The unit comes straight from the campaign
// write-up, because when every tool in a section exits 0 on a misconfiguration the command is the
// least interesting part of the step:
//   do          the call
//   assert      a precondition checked BEFORE the call that would catch the misconfiguration
//   verify      a postcondition checked AFTER that separates "tested and clean" from "not tested"
//   looks_like  what the wrong answer looks like, since it never looks like an error
// `do` and `verify` are required. A step with no postcondition is a step whose result cannot be
// distinguished from a step that never ran, which is the exact defect this store exists to record.
//
// UNKNOWN KEYS ARE REFUSED. A definition with `gotchya:` or `lesson_learned:` would otherwise load
// cleanly and serve a workflow with a section silently missing, and a reader cannot see an absence.
// Refusing the typo is the only way the store can promise that what it serves is what was written.

// A stable name is the address an operator types, so it has to survive a rename of the title and be
// safe as a filename and as a JSON key. Kebab case, no leading digit.
const NAME_PATTERN = /^[a-z][a-z0-9-]{2,48}$/;

// Evidence must carry a numeral. See the note above: this is the whole mechanism that keeps the
// store measured rather than merely confident.
const MEASUREMENT_PATTERN = /[0-9]/;

// A DATE THE READER CAN BE SHOWN, not just a date a human can read. measured_on and updated are
// prose, and prose carries the target and the corpus size as well as the day, so the day is found
// inside it rather than stored beside it. It has to be found, though: the store reports the age of
// every entry on every read, and an entry whose date cannot be parsed would be the one entry that
// is silently exempt from that. This project has already been bitten once by a note that was true
// when written and false when acted on, so an undateable workflow is refused at load.
const DATE_PATTERN = /\b(20\d\d)-(0\d|1[0-2])-([0-2]\d|3[01])\b/;

// Below this, a `measured` field is a gesture at evidence rather than evidence. "3 vectors" is 9
// characters and says nothing about of what, out of how many, or when.
const MIN_MEASUREMENT_CHARS = 20;

// Below this, a prose field is a label rather than a statement. Sized off the shortest real sentence
// in the seed workflow, "Report clean, untested and oracle rows separately." at 48 characters.
const MIN_PROSE_CHARS = 24;

// THE ADDRESS RULE DID NOT REACH THE FIELDS THAT WERE ACTUALLY WRONG. `measured` and `source` live
// on lessons and gotchas, and the two numbers this store got wrong in its next round were nowhere
// near either: the per-vector durations sat in the top-level `cost` field, and the token-lifetime
// range sat in a step's `verify`. Neither field required a source, so the guard built to stop
// exactly this class of error could not see the two places the class occurred.
//
// So a NUMBER IN A COST OR IN A POSTCONDITION IS A MEASUREMENT TOO, and is addressed like one.
// Those two fields, and not every field, because they are the two that report what the run
// PRODUCED: `cost` is what it spent, and `verify` is the line that separates a tested vector from
// an untested one. A reader acts on both. A number in a `do` or a `looks_like` is describing the
// work rather than certifying it, and holding those to the same rule would make the rule noise.
//
// The address may sit ANYWHERE in the same item, so a step whose `verify` already quotes a scan id
// needs nothing added; `cost` has no sibling at the top level, so it carries its own.
const NUMERIC_ADDRESS_NOTE = 'states a number and names no address a reader can open, so the ' +
  'number beside it can only be trusted. Give a file and a line (sqli/campaign.log:33, ' +
  'server/utils/sqliCompose.go:84) or the id of a database row.';

// The top level shape. `required` is checked for a usable string or a non-empty array; `optional` is
// checked only if present; anything else is a typo and is refused. `numeric_address` names the
// fields that must carry an address of their own once they carry a number.
const TOP_LEVEL = {
  required: ['name', 'title', 'purpose', 'reach_for_it_when', 'measured_on',
    'preconditions', 'steps', 'lessons', 'gotchas'],
  optional: ['not_for', 'cost', 'related', 'updated'],
  arrays: ['preconditions', 'steps', 'lessons', 'gotchas'],
  numeric_address: ['cost'],
};

// The item shapes, one per array section. `evidence` names the fields inside an item that must carry
// a measurement; it is what makes an unevidenced gotcha a load failure rather than a style note.
// `address` names the fields that must say WHERE the measurement can be re-checked.
const ITEM = {
  preconditions: {
    required: ['check', 'why'],
    optional: ['how'],
    evidence: [],
    address: [],
    numeric_address: [],
  },
  steps: {
    required: ['do', 'verify'],
    optional: ['tool', 'assert', 'looks_like', 'source'],
    evidence: [],
    address: [],
    numeric_address: ['verify'],
  },
  lessons: {
    required: ['lesson', 'measured', 'source'],
    optional: ['cost'],
    evidence: ['measured'],
    address: ['source'],
    numeric_address: [],
  },
  gotchas: {
    required: ['gotcha', 'symptom', 'measured', 'source', 'fix'],
    optional: ['blast_radius'],
    evidence: ['measured'],
    address: ['source'],
    numeric_address: [],
  },
};

// An address ANYWHERE in an item satisfies the numeric-address rule for that item, because a step
// that already quotes a scan id in its postcondition has done the thing the rule asks for.
function itemCarriesAddress(item) {
  return Object.values(item).some((v) => typeof v === 'string' && SOURCE_ADDRESS.test(v));
}

function isUsableString(value, min) {
  return typeof value === 'string' && value.trim().length >= min;
}

// Every problem is reported with a PATH, because a definition is a few hundred lines and "steps is
// malformed" sends the author reading all of it.
function checkItem(problems, where, section, item, index) {
  const at = `${where}.${section}[${index}]`;
  if (item === null || typeof item !== 'object' || Array.isArray(item)) {
    problems.push(`${at} is not an object`);
    return;
  }
  const shape = ITEM[section];
  const known = new Set([...shape.required, ...shape.optional]);
  for (const key of Object.keys(item)) {
    if (!known.has(key)) {
      problems.push(`${at} has unknown field "${key}" (allowed: ${[...known].sort().join(', ')})`);
    }
  }
  for (const field of shape.required) {
    if (!isUsableString(item[field], MIN_PROSE_CHARS)) {
      problems.push(`${at}.${field} is missing or shorter than ${MIN_PROSE_CHARS} characters`);
    }
  }
  for (const field of shape.optional) {
    if (item[field] === undefined) continue;
    if (!isUsableString(item[field], MIN_PROSE_CHARS)) {
      problems.push(`${at}.${field} is present but is not usable text`);
    }
  }
  // The evidence rule. Checked after the required-field check so a missing `measured` is reported
  // once, as missing, rather than twice.
  for (const field of shape.evidence) {
    const value = item[field];
    if (!isUsableString(value, MIN_MEASUREMENT_CHARS)) {
      if (isUsableString(value, MIN_PROSE_CHARS)) {
        problems.push(`${at}.${field} is too short to be a measurement ` +
          `(needs ${MIN_MEASUREMENT_CHARS} characters, has ${value.trim().length})`);
      }
      continue;
    }
    if (!MEASUREMENT_PATTERN.test(value)) {
      problems.push(`${at}.${field} contains no number, so it is a claim and not a measurement. ` +
        'Write the count, duration or ratio that was actually observed.');
    }
  }
  // The address rule. A number with nowhere to check it is the shape both fabricated measurements
  // in this store took, so a `source` that names no openable place is refused the same way an
  // unevidenced gotcha is. Reported only when the field is present and long enough, so a missing
  // source is reported once, as missing.
  for (const field of shape.address || []) {
    const value = item[field];
    if (!isUsableString(value, MIN_PROSE_CHARS)) continue;
    if (!SOURCE_ADDRESS.test(value)) {
      problems.push(`${at}.${field} names no address a reader can open, so the measurement beside ` +
        'it can only be trusted. Give a file and a line (sqli/campaign.log:33, ' +
        'server/utils/sqliCompose.go:84) or the id of a database row.');
    }
  }
  // The numeric-address rule, which is the address rule reaching the fields that carry a number
  // without carrying a `measured` beside it. See the note above TOP_LEVEL.
  for (const field of shape.numeric_address || []) {
    const value = item[field];
    if (!isUsableString(value, MIN_PROSE_CHARS)) continue;
    if (!MEASUREMENT_PATTERN.test(value)) continue;
    if (itemCarriesAddress(item)) continue;
    problems.push(`${at}.${field} ${NUMERIC_ADDRESS_NOTE}`);
  }
}

// validate returns the list of problems. It NEVER throws and it never returns a partially repaired
// definition: the caller decides what a problem means, and the only caller that matters, assemble(),
// refuses the whole load.
function validate(def) {
  const problems = [];
  if (def === null || typeof def !== 'object' || Array.isArray(def)) {
    return ['definition is not an object'];
  }
  const where = typeof def.name === 'string' && def.name ? def.name : '<unnamed>';

  const known = new Set([...TOP_LEVEL.required, ...TOP_LEVEL.optional]);
  for (const key of Object.keys(def)) {
    if (!known.has(key)) {
      problems.push(`${where} has unknown field "${key}" (allowed: ${[...known].sort().join(', ')})`);
    }
  }

  if (!isUsableString(def.name, 3) || !NAME_PATTERN.test(def.name)) {
    problems.push(`${where}.name must be kebab case, 3 to 49 characters, starting with a letter`);
  }
  for (const field of ['title', 'purpose', 'reach_for_it_when', 'measured_on']) {
    if (!isUsableString(def[field], MIN_PROSE_CHARS)) {
      problems.push(`${where}.${field} is missing or shorter than ${MIN_PROSE_CHARS} characters`);
    }
  }
  // measured_on is the provenance of the whole workflow: which target, which corpus, which day. A
  // workflow with no provenance cannot be aged out, and a two year old scanner lesson is a liability.
  if (isUsableString(def.measured_on, MIN_PROSE_CHARS) && !MEASUREMENT_PATTERN.test(def.measured_on)) {
    problems.push(`${where}.measured_on carries no number, so it names no date and no corpus size`);
  }
  if (isUsableString(def.measured_on, MIN_PROSE_CHARS) && !DATE_PATTERN.test(def.measured_on)) {
    problems.push(`${where}.measured_on carries no YYYY-MM-DD date, so this workflow could not be ` +
      'aged and would be the one entry whose staleness a reader cannot see');
  }
  for (const field of ['not_for', 'cost', 'updated']) {
    if (def[field] === undefined) continue;
    if (!isUsableString(def[field], MIN_PROSE_CHARS)) {
      problems.push(`${where}.${field} is present but is not usable text`);
    }
  }
  // `updated` is what the age is read off when it is present, so an updated line with no date in
  // it would silently hand the reader the ORIGINAL measurement date on a workflow somebody has
  // since revised, which understates and overstates freshness in turn.
  if (isUsableString(def.updated, MIN_PROSE_CHARS) && !DATE_PATTERN.test(def.updated)) {
    problems.push(`${where}.updated carries no YYYY-MM-DD date, so it cannot say when`);
  }
  // `cost` is the other home of a measurement outside lessons and gotchas, and unlike a step it has
  // no sibling field to hold the address, so it carries its own.
  for (const field of TOP_LEVEL.numeric_address) {
    const value = def[field];
    if (!isUsableString(value, MIN_PROSE_CHARS)) continue;
    if (!MEASUREMENT_PATTERN.test(value)) continue;
    if (SOURCE_ADDRESS.test(value)) continue;
    problems.push(`${where}.${field} ${NUMERIC_ADDRESS_NOTE}`);
  }
  if (def.related !== undefined) {
    if (!Array.isArray(def.related) || def.related.some((n) => !isUsableString(n, 3))) {
      problems.push(`${where}.related must be a list of workflow names`);
    }
  }

  for (const section of TOP_LEVEL.arrays) {
    const rows = def[section];
    if (!Array.isArray(rows) || rows.length === 0) {
      problems.push(`${where}.${section} is missing or empty`);
      continue;
    }
    rows.forEach((item, i) => checkItem(problems, where, section, item, i));
  }

  return problems;
}

module.exports = {
  validate,
  NUMERIC_ADDRESS_NOTE,
  NAME_PATTERN,
  DATE_PATTERN,
  MEASUREMENT_PATTERN,
  SOURCE_ADDRESS,
  MIN_MEASUREMENT_CHARS,
  MIN_PROSE_CHARS,
  TOP_LEVEL,
  ITEM,
};
