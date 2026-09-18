const recon = require('./recon');
const scanning = require('./scanning');
const workflow = require('./workflow');
const data = require('./data');

// The guidance registry: what this framework knows about its own tools, keyed by tool name and
// refined by action.
//
// get_methodology, whats_next, get_attack_vector_model and get_tool_guidance already exist and they
// work. The problem is that they are PULL. The measured failure that motivates this file is recorded
// at the top of tools/methodology.js: an agent built a ten-step fuzzing flow that fuzzed parameters,
// headers and cookies against endpoints it ALREADY KNEW, never put FUZZ in a path, never ran content
// discovery, so /admin was never requested and the whole access-bypass section had nothing to work
// on. Nothing in that sequence errored and nothing looked wrong. The agent never asked, because not
// knowing a step exists is exactly the state in which you do not ask about it.
//
// So guidance rides along with the result instead of waiting to be requested. This file is the
// lookup half of that; the wrapper in ../index.js is the attaching half.
//
// The four domain files are authored separately and are the product. Everything here is assembly:
// merge them, refuse to paper over a collision, and derive the compact reminder line.

// A tool belongs to exactly one domain. Two domains claiming the same tool means two different
// authors wrote two different answers for it and one of them is about to be silently discarded, so
// this throws rather than picking. It is a static registry: if it loads once it loads every time,
// and the test suite loads it.
function assemble() {
  const all = {};
  const owner = {};
  const collisions = [];
  for (const [domain, entries] of Object.entries({ recon, scanning, workflow, data })) {
    for (const [name, entry] of Object.entries(entries)) {
      if (owner[name]) {
        collisions.push(`${name} (in ${owner[name]} and ${domain})`);
        continue;
      }
      owner[name] = domain;
      all[name] = entry;
    }
  }
  if (collisions.length > 0) {
    throw new Error(`guidance registry: ${collisions.length} tool name(s) defined in more than one ` +
      `domain file, so one answer would be discarded: ${collisions.join(', ')}`);
  }
  return { all, owner };
}

const { all: ALL, owner: DOMAIN_OF } = assemble();

// Tools that are DELIBERATELY not in the registry, with the reason.
//
// This exists so the test that asserts "every registered tool has an entry" fails when someone adds
// a tool and forgets, instead of being weakened to a warning. A name goes in here only when it would
// be teaching itself; anything else that lands here is a gap, not an exemption.
const EXEMPT = {
  browse_knowledge_base: 'the knowledge base tools ARE the teaching layer. Their own descriptions ' +
    'carry the whole lesson (which files are prose and which are corpora, why a search hit proves ' +
    'only that the words appear), and a guidance block restating it on every call would double the ' +
    'cost of the cheapest tools here for no new information.',
  read_knowledge_file: 'same reason as browse_knowledge_base. Its response already reports its own ' +
    'truncation and a next_offset, which is the only thing a caller could act on.',
  search_knowledge_base: 'same reason as browse_knowledge_base. The warning that matters, that a ' +
    'hit proves the words are in the corpus and not that the finding applies to this target, is ' +
    'already on every response it returns.',
};

// The fields that are attached to a tool result, in the order they are attached.
//
// `derived` and `actions` are registry bookkeeping and are deliberately not shipped. `derived` says
// whether a human verified the text, which is a fact about this file rather than about the target,
// and `actions` is the table lookup() consumes to produce the merged entry in the first place.
// `rule` sits right after `tool` because it is a standing constraint on how the tool may be used,
// not a caveat about what it returns: a reader needs it before they act, not after. Only entries
// that define it pay for it, since lookup() copies a field only when the entry has one.
const ATTACHED_FIELDS = ['step', 'tool', 'rule', 'vuln', 'lies', 'next', 'learn'];

// `lies` is a LIST, and it is the one field that does not follow the override rule below.
//
// A tool lies in more than one way. ghauri exiting 0 on a flag it does not understand and the runner
// writing "clean" is one lie; the same tool reporting a vector count that counts rows it skipped is
// another; neither replaces the other and an author who learns the second should not have to choose.
// Before this, the field held a single string, so the second lie was either appended to the first
// into one unreadable paragraph or silently lost. It now holds one string per distinct way the tool
// misleads, and a plain string is read as a one element list so the entries authored before this
// change need no edit.
const LIES_FIELD = 'lies';

// Read a `lies` value in either shape and return a clean array. Anything that is not a non-empty
// string is dropped rather than rendered: a null or a number in this list would be attached to a
// response as a lesson, and a lesson that reads "null" is worse than a missing one.
function asLies(value) {
  const raw = Array.isArray(value) ? value : [value];
  const out = [];
  for (const item of raw) {
    if (typeof item !== 'string') continue;
    const text = item.trim();
    if (text.length > 0) out.push(text);
  }
  return out;
}

// Merge the per-action override over the tool entry. An override is partial by design: an action
// usually changes what the call PROVES and what comes next while sitting at the same methodology
// step, so anything it does not restate is inherited rather than dropped.
//
// `lies` ACCUMULATES INSTEAD OF REPLACING, and it is the only field that does. step, tool, next and
// learn describe WHERE YOU ARE, so an action that restates one is correcting the tool-level answer
// for that call and replacing it is right. A lie is a fact about the TOOL, and it stays true when
// you call one particular action: ghauri does not stop exiting 0 on a bad flag because you asked for
// the eligibility view. So an action that has learned its own lie gets it IN ADDITION to the
// tool-level ones. Replacing was the old behaviour and it silently dropped the general lesson at
// exactly the moment a caller was deepest into one specific action.
//
// MOST SPECIFIC FIRST: the action's own lies lead, then the tool-level ones. This ordering is a
// DELIVERY decision, not a stylistic one, and it is the whole of the fix for the defect the first
// version of this shipped with. compactLine() repeats exactly one lie, lies[0], and the session
// brief is tracked per TOOL (guidance/session.js), so the full entry goes out once and every later
// call gets the one-line reminder. Ordering tool-level first therefore meant the tool-level lie led
// every reminder and an action-specific lie reached a caller only if that action happened to be the
// first call of the session. MEASURED on this registry: 156 action overrides define lies and the
// action lie led 0 of the 343 compact lines. For a tool with 8 actions that is 7 lessons delivered
// on no call at all. Leading with the action's own lie costs nothing, because the tool-level lie is
// in the full entry that already went out on the session's first call for this tool whatever action
// that was, while the action lie has been delivered zero times. Repeat the one nobody has heard.
//
// Deduped on exact trimmed text, first occurrence wins, because an action override that repeats a
// tool lie to give it emphasis would otherwise print it twice and read as two separate problems.
//
// Returns null for an unknown tool. Null means attach nothing at all, which matters: an empty object
// on a response would read as "the framework has nothing to say about this tool", and a tool with no
// entry is a tool nobody has written guidance for yet, which is a different claim.
function lookup(toolName, action) {
  const entry = ALL[toolName];
  if (!entry || typeof entry !== 'object') return null;

  const actions = entry.actions;
  const candidate = action && actions ? actions[action] : null;
  const override = candidate && typeof candidate === 'object' ? candidate : null;

  // One pass over ATTACHED_FIELDS rather than a base pass and then an override pass, so the attached
  // keys always come out in the declared order. Two passes put a field the override introduces and
  // the base never defined at the end of the object, after `learn`, which is not where a reader of
  // the JSON expects to find a `rule`.
  const merged = {};
  for (const field of ATTACHED_FIELDS) {
    if (field === LIES_FIELD) {
      const lies = [];
      const seen = new Set();
      // Action lies first, then tool-level. See the MOST SPECIFIC FIRST note above: lies[0] is what
      // the compact reminder repeats on every call after the first, and the action's lie is the one
      // that has not already been delivered in full.
      for (const lie of [...asLies(override && override[field]), ...asLies(entry[field])]) {
        if (seen.has(lie)) continue;
        seen.add(lie);
        lies.push(lie);
      }
      if (lies.length > 0) merged[field] = lies;
      continue;
    }
    const fromOverride = override && typeof override[field] === 'string' && override[field].length > 0
      ? override[field]
      : null;
    const fromEntry = typeof entry[field] === 'string' && entry[field].length > 0 ? entry[field] : null;
    const value = fromOverride || fromEntry;
    if (value) merged[field] = value;
  }

  return Object.keys(merged).length > 0 ? merged : null;
}

// Abbreviations whose full stop does not end a sentence. Short list on purpose: it only needs to
// cover what the four domain files actually write, and a miss costs a shorter compact line rather
// than a wrong one.
const ABBREVIATIONS = new Set(['e.g', 'i.e', 'etc', 'vs', 'cf', 'approx', 'no', 'fig']);

// Below this many characters a "sentence" is almost always a fragment ("204.", "200 OK."), so the
// scan keeps going rather than emitting a lead that says nothing.
const MIN_SENTENCE = 24;

// The compact reminder's ceiling, in characters, roughly 50 tokens.
//
// It is enforced rather than hoped for. MEASURED without it: the mean line was 217 characters and
// 213 of the 343 compact lines were over 200, the worst being run_endpoint_scan at 394. That is
// the cost that repeats, on every call after the first, for the whole length of a scan loop, and a
// reminder that is half the size of the lesson is not a reminder.
const COMPACT_MAX = 200;

// Words a hard cut must not end on. Every one of them promises a clause that is no longer there.
const DANGLING_TAIL = /[\s,;:]+(?:so|and|but|or|because|which|that|than|then|when|while|where|if|as|a|an|the|to|of|in|on|for|from|with|by|is|are|was|were|be|it|its|this|these|those|not|no|one|only|still|even|also)$/i;

function firstSentence(text) {
  const s = String(text || '').trim();
  const terminator = /[.!?](?=\s|$)/g;
  let match;
  while ((match = terminator.exec(s)) !== null) {
    const end = match.index + 1;
    const lastWord = (s.slice(0, match.index).match(/[A-Za-z.]+$/) || [''])[0].toLowerCase();
    if (ABBREVIATIONS.has(lastWord)) continue;
    if (end < MIN_SENTENCE) continue;
    return s.slice(0, end);
  }
  return s;
}

function terminate(s) {
  return /[.!?]$/.test(s) ? s : `${s}.`;
}

// Shorten the lead sentence to fit what is left of the budget after step and next, which are never
// touched: they are the two parts a caller acts on, and they are short.
//
// Two stages, in this order, because they degrade differently. A colon or semicolon in these entries
// almost always separates the claim from its worked example ("both mean every verdict would be wrong
// in the same direction: the saved credentials are not honoured, so..."), so cutting there keeps a
// whole thought. Only when even the claim is too long does it hard cut, at a word boundary, with an
// ellipsis that says so.
//
// A PREFIX OF A SENTENCE CAN MEAN THE OPPOSITE OF THE SENTENCE, which is the risk being taken here:
// "the run is recorded as clean, but nothing was sent" truncates to something reassuring. Two things
// bound it. The ellipsis is always present, so the line never presents itself as complete. And this
// string is only ever sent AFTER the full entry has gone to the same session, so the unclipped
// sentence is already upstream in the caller's context rather than lost. If a future entry cannot
// survive that, shorten its lies field, do not raise the ceiling.
function fitLead(sentence, budget) {
  const s = String(sentence || '').trim();
  if (!s) return '';
  // Nothing useful fits. Emitting a three word fragment would be worse than emitting the step and
  // the next tools on their own.
  if (budget < MIN_SENTENCE) return '';
  if (terminate(s).length <= budget) return terminate(s);

  const clause = s.match(/^([^:;]{24,})[:;]\s/);
  if (clause && terminate(clause[1]).length <= budget) return terminate(clause[1]);

  const room = budget - 4; // the " ..." that marks the cut
  let cut = s.slice(0, room);
  const lastSpace = cut.lastIndexOf(' ');
  if (lastSpace >= MIN_SENTENCE) cut = cut.slice(0, lastSpace);
  cut = cut.replace(/[\s,;:.]+$/, '');

  // Drop a trailing word that was leading somewhere. A cut landing on "so a" or "because the"
  // spends four of the last characters announcing that the point is missing, and ", so a ..." reads
  // worse than stopping at the last complete idea. Loops because these arrive in pairs.
  let trimmed = true;
  while (trimmed && cut.length > MIN_SENTENCE) {
    trimmed = false;
    const next = cut.replace(DANGLING_TAIL, '');
    if (next !== cut) { cut = next.replace(/[\s,;:.]+$/, ''); trimmed = true; }
  }
  return `${cut} ...`;
}

// The compact reminder, DERIVED from the entry rather than authored alongside it.
//
// Authoring a second short string per tool would mean 143 more strings that can disagree with the
// long ones, and they would, the first time someone edited one and not the other. So: the step, then
// the first sentence of `lies` if there is one else the first sentence of `tool`, then the next
// tools. `lies` wins because after the first call the thing worth repeating is not what the tool
// does, it is how its answer misleads.
//
// EXACTLY ONE LIE LEADS, AND IT IS THE FIRST. An entry can carry several and the whole set went out
// on the first call; this is the reminder on calls two through n and it has 200 characters for
// everything including the step and the next pointer. Two lies would not fit, and picking by length
// or by recency would make the reminder change which lesson it repeats as the entry is edited.
//
// Which one lies[0] IS, is decided in lookup() and it is the most specific one: the lie the action
// being called added, if it added one, otherwise the tool's own. That is not a tie-break, it is the
// delivery rule. The entry this function is handed was already looked up WITH the current action
// (../index.js calls lookup(toolName, params.action) and compactLine on the result), so the lead is
// a lesson about the call that is actually running. The tool-level lie does not need the repeat: the
// brief is tracked per tool, so it went out in full on the session's first call for this tool no
// matter which action that was, whereas the action's lie has been delivered zero times unless that
// first call happened to be the same action. MEASURED before this rule: 156 action overrides define
// lies and their lie led 0 of the 343 compact lines.
//
// A caller on an action with no lies of its own still gets the tool-level lie, unchanged.
//
// step and next are spent first and in full. They are the two parts a caller ACTS on, they are short
// (the longest step and next together come to 139 characters, on run_scan), and a reminder that has
// dropped where you are or what comes next has stopped being a reminder. Whatever is left of
// COMPACT_MAX goes to the lead, which is the part that can be shortened without becoming useless.
function compactLine(entry) {
  if (!entry || typeof entry !== 'object') return '';
  const step = entry.step ? terminate(entry.step) : '';
  const next = entry.next ? terminate(`Next: ${entry.next}`) : '';

  const fixed = [step, next].filter(Boolean);
  // Every part that is kept costs its own length plus the space joining it to the previous one.
  const spent = fixed.join(' ').length + (fixed.length > 0 ? 1 : 0);
  // asLies() here as well as in lookup() because compactLine is exported and is called on
  // hand-built entries by the tests and by anything that composes an entry without going through
  // the registry. Those still write `lies` as a bare string, and a reminder that silently lost its
  // lead because the shape was the older one would be the exact failure this layer exists to avoid.
  const lead = fitLead(firstSentence(asLies(entry.lies)[0] || entry.tool || ''), COMPACT_MAX - spent);

  return [step, lead, next].filter(Boolean).join(' ');
}

module.exports = {
  lookup,
  compactLine,
  ALL,
  DOMAIN_OF,
  EXEMPT,
  ATTACHED_FIELDS,
  COMPACT_MAX,
  LIES_FIELD,
  // Exported so a test, and any future reader of an entry, can normalise a `lies` field written in
  // either shape without reimplementing the string-is-a-one-element-list rule.
  asLies,
  // Exported so a test can exercise the derivation directly rather than through a whole entry.
  firstSentence,
  fitLead,
};
