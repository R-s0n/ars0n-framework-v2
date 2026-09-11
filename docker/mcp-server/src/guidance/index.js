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
const ATTACHED_FIELDS = ['step', 'tool', 'vuln', 'lies', 'next', 'learn'];

// Merge the per-action override over the tool entry. An override is partial by design: an action
// usually changes what the call PROVES and what comes next while sitting at the same methodology
// step, so anything it does not restate is inherited rather than dropped.
//
// Returns null for an unknown tool. Null means attach nothing at all, which matters: an empty object
// on a response would read as "the framework has nothing to say about this tool", and a tool with no
// entry is a tool nobody has written guidance for yet, which is a different claim.
function lookup(toolName, action) {
  const entry = ALL[toolName];
  if (!entry || typeof entry !== 'object') return null;

  const merged = {};
  for (const field of ATTACHED_FIELDS) {
    if (typeof entry[field] === 'string' && entry[field].length > 0) merged[field] = entry[field];
  }

  const override = action && entry.actions ? entry.actions[action] : null;
  if (override && typeof override === 'object') {
    for (const field of ATTACHED_FIELDS) {
      if (typeof override[field] === 'string' && override[field].length > 0) merged[field] = override[field];
    }
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
// It is enforced rather than hoped for. MEASURED without it: the mean line was 218 characters and
// 215 of the 337 tool/action pairs were over 200, the worst being run_endpoint_scan at 401. That is
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
  const lead = fitLead(firstSentence(entry.lies || entry.tool || ''), COMPACT_MAX - spent);

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
  // Exported so a test can exercise the derivation directly rather than through a whole entry.
  firstSentence,
  fitLead,
};
