// The one place that reads a tool option's SCHEMA and decides what it means.
//
// WHY THIS FILE EXISTS. The Wildcard and Company settings screens were rendering an
// <Alert variant="danger"> under every option that carried a `danger` sentence. On the live API that
// is 130 of 175 Wildcard options and 172 of 207 Company options, so both screens were walls of red
// error boxes describing tools that were working perfectly. The red was also redundant: the server
// already carries min / max / min_items / choices / requires_key / inert_when_key on every option and
// already refuses a bad value with a 400 that names it. Prose describing a constraint is not a
// validation, and it is certainly not an error.
//
// So the rules here are:
//   1. The CONTROL enforces the constraint, so an invalid value is hard to enter at all.
//   2. Client-side validation is instant, inline, and silent while the value is fine.
//   3. The SERVER remains the authority. Its 400 is attributed to the field it names.
//   4. A caveat is help text.
//   5. A visible warning is reserved for the few options that act on the live estate, throw real
//      findings away, or silently defeat another setting. Measured against the whole registry, that
//      is 20 of 294 danger sentences - under one per tool. See hazardOf.
//
// Nothing in this file names a tool, a flag or an option key. Everything is read from the vocabulary
// the server serves, exactly as before.

export const isTruthy = (v) => v === true || v === 'true';

// Every list option is held as an ARRAY in form state, whatever shape it arrived in. The server
// accepts either a comma separated string or an array, and holding one shape in the client means the
// list controls, the validation and the payload builder cannot disagree about what is in the list.
export const asList = (v) => {
  if (Array.isArray(v)) return v.map((x) => String(x)).filter((s) => s !== '');
  if (v === undefined || v === null || v === '') return [];
  return String(v).split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
};

export const isNumericKind = (kind) => kind === 'int' || kind === 'float';

// The step a number input should move in. int moves in whole numbers; float is left free so the
// browser does not reject 0.5 for a pause that means "no pause at all" at 0.
export const stepFor = (meta) => (meta.kind === 'int' ? 1 : meta.kind === 'float' ? 'any' : undefined);

const unitSuffix = (meta) => (meta.unit ? ` ${meta.unit}` : '');

const entries = (n) => `${n} entr${Number(n) === 1 ? 'y' : 'ies'}`;

// validateOptionValue answers ONE question: is what is currently in this field a value the server
// would refuse? It mirrors ValidateWildcardSettings (server/utils/wildcardTools.go), which the
// Company registry shares, so the client never refuses something the server would accept and never
// accepts something the server would refuse without saying why first.
//
// An EMPTY field is always valid. Empty means "not set", the payload builder omits it, and the
// server therefore never validates it. That is why nothing is shown for a field nobody has filled in.
export function validateOptionValue(meta, raw) {
  if (!meta || !meta.kind) return '';
  const choices = meta.choices || [];

  if (meta.kind === 'bool') return ''; // the control offers three states and no fourth one exists

  if (meta.kind === 'enum') {
    const v = String(raw ?? '');
    if (v === '') return '';
    if (choices.some((c) => c === v)) return '';
    return `This tool accepts only: ${choices.join(', ')}.`;
  }

  if (meta.kind === 'list') {
    const items = asList(raw);
    if (items.length === 0) return '';
    if (meta.min_items !== undefined && items.length < Number(meta.min_items)) {
      return `Needs at least ${entries(meta.min_items)}, or leave it empty to use the default.`;
    }
    if (choices.length > 0) {
      const bad = items.filter((i) => !choices.some((c) => String(c).toLowerCase() === i.toLowerCase()));
      if (bad.length > 0) {
        // Deliberately an error rather than a warning: the measured tools with a name list DROP an
        // unrecognised name silently and still exit 0, so a typo here is a coverage change with no
        // symptom anywhere.
        return `${bad.join(', ')} ${bad.length === 1 ? 'is not a name' : 'are not names'} this tool knows. An unknown name is dropped silently, so the setting would not do what it says.`;
      }
    }
    return '';
  }

  if (isNumericKind(meta.kind)) {
    const text = String(raw ?? '').trim();
    if (text === '') return '';
    const n = Number(text);
    if (!Number.isFinite(n)) return 'Needs to be a number.';
    if (meta.kind === 'int' && !Number.isInteger(n)) return 'Needs to be a whole number.';
    if (meta.min !== undefined && n < Number(meta.min)) {
      return `Needs to be at least ${meta.min}${unitSuffix(meta)}.`;
    }
    if (meta.max !== undefined && n > Number(meta.max)) {
      return `Needs to be at most ${meta.max}${unitSuffix(meta)}.`;
    }
    return '';
  }

  return '';
}

// Every field that is currently wrong, keyed by option. Inert fields are skipped: they are disabled,
// they are not sent, and refusing to save because of a value the operator cannot even edit would be
// a dead end.
export function invalidFields(options, values, isInert) {
  const out = {};
  Object.entries(options || {}).forEach(([key, meta]) => {
    if (isInert && isInert(key)) return;
    const problem = validateOptionValue(meta, values[key]);
    if (problem) out[key] = problem;
  });
  return out;
}

// The payload the save posts. An empty field is omitted rather than sent as zero or "", because on
// this endpoint an absent key means "the tool's own behaviour" and a present one means "the operator
// chose this".
export function buildSettingsPayload(options, values) {
  const payload = {};
  Object.entries(options || {}).forEach(([key, meta]) => {
    const raw = values[key];
    if (meta.kind === 'bool') {
      if (raw === 'true' || raw === true) payload[key] = true;
      else if (raw === 'false' || raw === false) payload[key] = false;
      return;
    }
    if (meta.kind === 'list') {
      const items = asList(raw);
      if (items.length) payload[key] = items;
      return;
    }
    const text = String(raw ?? '').trim();
    if (text === '') return;
    if (isNumericKind(meta.kind)) {
      const n = Number(text);
      if (!Number.isFinite(n)) return;
      // float exists precisely so that 0.5 is not truncated to 0, which for a pause between requests
      // means "no pause at all". Only int is rounded.
      payload[key] = meta.kind === 'float' ? n : Math.trunc(n);
      return;
    }
    payload[key] = text;
  });
  return payload;
}

// --------------------------------------------------------------------------------------------
// The server's refusal, put on the field it names.
// --------------------------------------------------------------------------------------------

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// attributeServerMessage splits a 400 body across the fields it is about.
//
// The server joins one sentence per bad value with a space, and every one of those sentences starts
// with the option key followed by is / must / needs / does not (see validateWildcardValue). Matching
// that grammar at a sentence boundary is what keeps a key MENTIONED inside another option's
// explanation from stealing the rest of the message. Anything that is not attributable - a refused
// framework-owned flag, an unknown key, a scope refusal - comes back as `rest` and is shown once at
// the top, because it is about the request rather than about one field.
export function attributeServerMessage(message, options) {
  const text = String(message || '').trim();
  const keys = Object.keys(options || {});
  if (!text || keys.length === 0) return { fields: {}, rest: text };

  const starts = [];
  keys.forEach((key) => {
    const re = new RegExp(`(^|[.!?]\\s+)(${escapeRe(key)})\\s+(is|must|needs|does not)\\b`);
    const m = re.exec(text);
    if (m) starts.push({ key, at: m.index + m[1].length });
  });
  if (starts.length === 0) return { fields: {}, rest: text };

  starts.sort((a, b) => a.at - b.at);
  const fields = {};
  starts.forEach((s, i) => {
    const end = i + 1 < starts.length ? starts[i + 1].at : text.length;
    fields[s.key] = text.slice(s.at, end).trim();
  });
  return { fields, rest: text.slice(0, starts[0].at).trim() };
}

// --------------------------------------------------------------------------------------------
// Hazard: the small set of options that deserve a visible warning.
// --------------------------------------------------------------------------------------------
//
// The `danger` field is present on most options and is mostly a caveat: a tradeoff, a coverage note,
// a reminder that the semantics were never proven. Those are help text. Three things are not:
//
//   acts     - the scan DOES something to the live estate, or goes somewhere a passive-only program
//              puts out of scope. Submitting forms on a production site creates records and sends
//              mail; that is not recoverable by re-running the scan.
//   discards - a real finding is thrown away before it is ever stored, and nothing says so.
//   defeats  - the option silently nullifies a DIFFERENT setting, so an operator who changes that
//              other setting sees no change at all and has no way to tell why.
//
// The patterns below were run over every danger sentence in the registry (294 of them, across the
// Wildcard registry and all five Company registries) and match 20. Under one per tool. If a change
// here starts flagging most options, the change is wrong: a warning everything carries is a warning
// nobody reads, which is the bug this file was written to remove.
//
// meta.hazard, if the server ever declares one, wins over all of this. Reading prose is a fallback,
// not a preference.
// HAZARD_RULES was the prose classifier. Deleted rather than left dormant: it was wrong on
// 4 of the 20 fields it marked, and a disabled heuristic is an invitation to switch it back on.


// A hazard line is shown ONLY when the server declares one. There is no keyword matching.
//
// It used to fall back to regexing the English of meta.danger, and that produced four wrong labels
// out of twenty, every one of them loud and confident:
//
//   restrictToCompanyTlds  "NOT IMPLEMENTED. An over-narrow list silently deletes real findings"
//   requireWhoisMatch      "NOT IMPLEMENTED, and it depends on WHOIS data"
//     Both matched a "deletes findings" rule and rendered "Throws real findings away". An option
//     that does nothing cannot throw anything away, and making a NOT-IMPLEMENTED option the loudest
//     thing on its field is the exact failure this whole repair exists to undo.
//
//   katanaDepth            "...so this is the option most likely to be set by someone who then sees
//                           no change at all."
//     Matched a "no change at all" rule and rendered "Silently overrides another setting". It
//     overrides nothing. It was also inverted: the field is suppressed when inert, so the line
//     appeared only in the case where the sentence is FALSE.
//
//   matchSubdomains        contains the phrase "destroys evidence"
//     Rendered "Destructive", which reads as "this deletes things on the target". It is a whitelist.
//
// The root cause is that the rule read prose. Prose is written to explain, not to be parsed, and a
// classifier over it is guessing with total confidence. The registry already knows which options are
// genuinely hazardous, so the registry says so: set Hazard on the option and it is shown, leave it
// unset and it is not. Wrong-and-quiet beats wrong-and-shouting.
export function hazardOf(meta) {
  if (!meta) return null;
  if (typeof meta.hazard === 'string' && meta.hazard.trim() !== '') {
    return { kind: 'declared', label: meta.hazard.trim(), text: meta.danger || '' };
  }
  return null;
}

// The min / max / at-least summary shown beside the label, so the constraint is legible BEFORE a
// value is typed rather than only after one is refused.
export function constraintSummary(meta) {
  if (!meta) return '';
  return [
    meta.min !== undefined ? `min ${meta.min}` : '',
    meta.max !== undefined ? `max ${meta.max}` : '',
    meta.min_items !== undefined ? `at least ${entries(meta.min_items)}` : '',
  ].filter(Boolean).join(', ');
}
