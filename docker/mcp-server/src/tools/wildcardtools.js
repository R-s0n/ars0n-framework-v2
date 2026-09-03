const { z } = require('zod');
const { apiGet, apiPost } = require('../api');
const { isFull, dropEmpty, detailDescription } = require('../utils/detail');

// The Wildcard workflow's tool configuration, as seen from the agent side.
//
// ONE STORE, TWO EDITORS. The Settings screen and this tool write the same wildcard_tool_settings
// rows through the same handlers, and both GENERATE what they show from the vocabulary the server
// serves alongside the values. That is why there is no option list in this file: option_reference
// returns the server's own map, the same one a scan would read, so the two surfaces cannot drift.
// Adding an option in server/utils/wildcardOptions.go makes it appear in the UI and become settable
// here in the same commit.
//
// WHY THE PROVENANCE FIELD IS CARRIED THROUGH EVERY PROJECTION IN THIS FILE. Some of this vocabulary
// was probed against the real installed container flag by flag ("measured"); some was read off the
// command line the runner already executes, which proves the image accepts the flag and nothing about
// what a different VALUE does ("runner"); some was accepted by the tool with its semantics unproven
// ("unverified"). Those are three different claims. An option nobody proved must not be handed to an
// agent looking like one somebody did, so provenance survives compaction even when the prose does not.
//
// WHY THIS WORKFLOW NEEDS THE DANGER NOTES MORE THAN MOST. Its tools do not fail loudly. The dominant
// failure is exit 0, empty stdout, and a row stored as a successful scan, which is indistinguishable
// from a target that genuinely had nothing. amass -silent produces zero bytes on BOTH streams and is
// recorded as success; subfinder -recursive took a 23362-subdomain domain to exactly zero; gau --fp
// discards all output; cewl -m 40 emits no words; shuffledns exits 0 on a missing wordlist. Those
// facts live in the option's danger note, and compact carries the headline of each so an agent that
// never asks for full still cannot walk into one blind.

// Fields whose value is prose rather than data. They are what makes this vocabulary worth reading and
// also what makes it too large to return in bulk, so compact reports their size and, for two of the
// three, a headline.
//
// MEASURED AGAINST THE REAL REGISTRY. Pretty-printed, the server's whole reply is 197231 characters,
// and nuclei alone is 43 options. Headlining all three fields put a compact nuclei listing at 26238
// characters, over the cap and only 15% smaller than the 30845 it costs in full, which is not a
// compact mode at all. `why` is the one that is dropped: it argues for WANTING an option, where
// danger says how it ruins a scan silently and placeholder says what the tool does when the field is
// empty. Those two are what stop a mistake, so they keep a headline and `why` keeps only its size.
// That took the same listing to 21474 characters.
const HEADLINE_BUDGET = { danger: 220, placeholder: 160, why: 0 };
const PROSE_FIELDS = [
  ['why', 'why'],
  ['danger', 'danger'],
  ['placeholder', 'default_behaviour'],
];

// The character budget for one action's rows, leaving room for the wrapper fields around them. Rows
// over this are downgraded and the reason stated, rather than returned and discarded, because a
// response that exceeds the output cap gives the caller nothing usable at all.
//
// The number comes from this repo's own evidence rather than a guess: the manage_attack_vectors
// listing that actually failed measured 41243 characters, and detail.test.js asserts a compact
// listing under 30000. 28000 leaves room for the wrapper under that. On the real registry exactly two
// things exceed it, both genuinely oversized: every tool's runner notes at once (29225) and all 43
// nuclei options in full (30845). Everything else returns full prose.
const ROW_BUDGET = 28000;

// firstSentence is the headline of a prose field.
//
// Split on a full stop FOLLOWED BY WHITESPACE, so "crt.sh", "example.com" and "v4.2.0" stay intact.
// These notes are written headline-first ("VERIFIED SILENT-NOTHING, TWO WAYS, AND SINGLE VALUE
// ONLY."), so the first sentence is reliably the part an agent must not miss.
function firstSentence(text, max = 200) {
  if (typeof text !== 'string') return undefined;
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  const match = trimmed.match(/\.(\s|$)/);
  if (match && match.index + 1 <= max) return trimmed.slice(0, match.index + 1);
  if (trimmed.length <= max) return trimmed;
  const clipped = trimmed.slice(0, max);
  const lastSpace = clipped.lastIndexOf(' ');
  return `${clipped.slice(0, lastSpace > 40 ? lastSpace : max)}...`;
}

// compactOption projects one entry of the server's option map.
//
// compact keeps everything a caller needs to CHOOSE and VALIDATE a value (kind, flag, unit, bounds,
// choices, the keys that make it inert, provenance) and replaces the three prose fields with a
// headline plus their size. full returns the prose instead.
//
// The unit is never dropped at either level. amass -timeout is in MINUTES and the runner passes 60,
// meaning one hour; a caller that reads it as seconds and sends 300 has asked for a five-hour scan.
function compactOption(key, meta, full = false) {
  const row = {
    option: key,
    label: meta.label,
    kind: meta.kind,
    group: meta.group,
    flag: meta.flag,
    unit: meta.unit,
    provenance: meta.provenance,
    repeatable: meta.repeatable || undefined,
    min: meta.min,
    max: meta.max,
    requires_key: meta.requires_key,
    inert_when_key: meta.inert_when_key,
    shadowed_by: meta.shadowed_by,
  };

  // A long choice list is data, not prose, so it is counted rather than clipped: a caller that needs
  // the 50 subfinder source names can ask for full, and one that does not should not pay for them.
  const choices = Array.isArray(meta.choices) ? meta.choices : [];
  if (choices.length && (full || choices.length <= 12)) row.choices = choices;
  else if (choices.length) row.choice_count = choices.length;

  // No flag is a real answer rather than a gap, and it means two different things worth telling
  // apart: a framework-level switch that changes what the runner DOES, and an option on a tool that
  // has no command line at all (ctl is native Go). Either way nothing is composed for it.
  if (!meta.flag) {
    row.no_flag = 'This setting composes no command-line argument. It either switches runner '
      + 'behaviour rather than an argument, or belongs to a tool with no command line, in which case '
      + 'honouring it needs runner code. The danger note says which.';
  }

  for (const [field, name] of PROSE_FIELDS) {
    const value = meta[field];
    if (typeof value !== 'string' || !value) continue;
    if (full) {
      row[name] = value;
      continue;
    }
    const budget = HEADLINE_BUDGET[field];
    if (!budget) {
      // No headline for this field, but the size is still reported, so a caller can tell prose that
      // exists and was left out from prose that was never written.
      row[`${name}_chars`] = value.length;
      continue;
    }
    Object.assign(row, headlined(name, value, budget));
  }
  return dropEmpty(row);
}

// headlined emits either the whole note or a headline plus the size, and never both.
//
// MEASURED DEFECT THIS FIXES: emitting headline+size unconditionally made a compact owned-flag
// listing for nuclei 11195 characters against 10473 for full. Most of those reasons are one short
// sentence, so the headline reproduced the whole note and the size field was pure overhead. A
// compact mode that costs more than full is not compact.
//
// The rule is the note's own length rather than where its first full stop falls: a note that already
// fits the headline budget is returned WHOLE, because headlining it can only lose information while
// costing the same or more.
//
// The field NAME carries the distinction: a plain `danger` is the complete note, `danger_headline`
// means there is more, and `danger_chars` says how much more.
function headlined(name, value, budget) {
  const text = value.trim();
  if (text.length <= budget) return { [name]: text };
  return { [`${name}_headline`]: firstSentence(text, budget), [`${name}_chars`]: text.length };
}

// projectRows returns rows at the requested detail, or at compact with a stated reason when full
// would not fit.
//
// NOT SILENT TRUNCATION. Measured on the real registry: detail:"full" for all 43 nuclei options
// serialises to 30845 characters, which the caller would not receive. Downgrading and SAYING SO,
// with the size and the way to get what was asked for, is the only version of this that leaves the
// caller better off than an empty response.
const NARROW_BY_OPTION = 'Narrow with group, provenance or option to get the full prose for the ones '
  + 'you care about.';
const NARROW_BY_TOOL = 'Pass tool to get one tool\'s full entry, including its runner notes.';

function projectRows(keys, project, full, narrowing = NARROW_BY_OPTION, budget = ROW_BUDGET) {
  const rows = keys.map((k) => project(k, full));
  if (!full) return { rows, detail: 'compact' };
  const chars = JSON.stringify(rows, null, 2).length;
  if (chars <= budget) return { rows, detail: 'full' };
  return {
    rows: keys.map((k) => project(k, false)),
    detail: 'compact',
    downgraded_from_full: `detail:"full" for all ${keys.length} of these serialises to ${chars} `
      + `characters, past the output cap, so compact rows were returned instead. ${narrowing}`,
  };
}

// compactTool projects one registry entry. notes is the long prose about the runner and is the single
// heaviest field in the registry, so it is sized in compact and returned in full.
function compactTool(tool, full = false) {
  const row = {
    tool: tool.key,
    name: tool.name,
    step: tool.step,
    phase: tool.phase,
    version: tool.version,
    invocation: tool.invocation,
    groups: tool.groups && tool.groups.length ? tool.groups : undefined,
    option_count: Object.keys(tool.options || {}).length,
    owned_flag_count: Object.keys(tool.owned_flags || {}).length,
    runner_reads_settings: tool.runner_reads_settings,
    limitation: tool.limitation,
    delegates_to: tool.delegates_to,
  };
  // Which of the two it is decides whether a file-path option can ever work. amass runs as
  // `docker run --rm caffix/amass` with NO volume mount, so every path inside that container is
  // unreachable, which is why its file-path flags are owned with that reason rather than shipped.
  if (tool.container) row.runs_in_container = tool.container;
  if (tool.image) row.runs_as_ephemeral_image = tool.image;
  if (tool.binary) row.binary = tool.binary;

  if (full) {
    if (tool.notes) row.notes = tool.notes;
  } else if (tool.notes) {
    row.notes_chars = tool.notes.length;
  }
  return dropEmpty(row);
}

// compactOwnedFlag projects one owned flag. The reason IS the diagnostic: it says whether the flag is
// set by the runner, blacklisted because of what it does, broken in the installed build, or blocked
// on a volume mount that does not exist.
function compactOwnedFlag(flag, reason, full = false) {
  if (full) return { flag, reason };
  return dropEmpty({ flag, ...headlined('reason', reason, 220) });
}

// parseRefusal recovers the server's own words out of the Error apiPost throws.
//
// The refusal reason is the whole diagnostic here. The save endpoint refuses three things and names
// which: a flag the runner owns, a key the vocabulary does not contain, and a value the vocabulary
// cannot accept. Losing that to a generic "request failed" would leave a caller with a 400 and no
// idea which of its keys was the problem or what it could have said instead.
function parseRefusal(error) {
  const message = (error && error.message) || '';
  const match = message.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  if (!match) return null;
  const status = parseInt(match[1], 10);
  const body = match[2].trim();
  const out = { http_status: status };
  try {
    const parsed = JSON.parse(body);
    if (parsed && typeof parsed === 'object') {
      if (parsed.error) out.refusal_code = parsed.error;
      out.reason = parsed.message || body;
      return out;
    }
  } catch {
    // Not JSON. The raw body is still the server's own words, so it is returned rather than dropped.
  }
  out.reason = body;
  return out;
}

const REFUSAL_HINTS = {
  framework_owned: 'This flag is set by the runner itself. It is refused rather than stored, because '
    + 'a stored setting that is then displaced at run time is how an operator comes to believe a scan '
    + 'did something it did not. Call action owned_flags for the full list and the reason on each.',
  unknown_option: 'Nothing reads this key, so it is refused rather than kept. The reason above lists '
    + 'the valid keys for this tool; action option_reference returns them with their types and bounds.',
  invalid_value: 'The vocabulary type-checks and range-checks before storing, because a value that '
    + 'the tool rejects at run time reports an error long after the caller was told it was saved.',
  unsafe_value: 'Refused because of what this TARGET is, not because of the type. Two of these were '
    + 'measured to empty a scan while it still exited 0: an amass blacklist entry equal to or a parent '
    + 'of the scope target, and a subfinder proxy or resolver pointing at loopback, which inside the '
    + 'container means the container and not your host.',
  no_vocabulary: 'This tool has nothing to configure, and the reason above says why. For assetfinder '
    + 'and sublist3r an empty vocabulary is the measured answer rather than a gap; for httpx the '
    + 'configuration lives in the existing httpx_configs store instead.',
  unknown_tool: 'Call action tools for the registry.',
};

async function fetchRegistry() {
  const registry = await apiGet('/wildcard-tools');
  return {
    tools: Array.isArray(registry.tools) ? registry.tools : [],
    provenance_meaning: registry.provenance_meaning,
    owned_flags_meaning: registry.owned_flags_meaning,
  };
}

// Looked up against the LIVE registry rather than a list in this file, so a tool added on the server
// is reachable here without a second edit, and an unknown key gets the same known-tools sentence the
// HTTP handlers produce instead of a schema error that names nothing.
function findTool(registry, key) {
  const found = registry.tools.find((t) => t.key === key);
  if (found) return { tool: found };
  return {
    error: `No Wildcard workflow tool called ${key}. Known tools: `
      + `${registry.tools.map((t) => t.key).join(', ')}.`,
  };
}

async function resolveTargetId(params) {
  if (params.target_id) return params.target_id;
  const targets = await apiGet('/scopetarget/read');
  const active = (Array.isArray(targets) ? targets : []).find((t) => t.active);
  return active ? active.id : null;
}

// The sentence for the tools whose runner does not read this store yet. A stored setting nothing
// reads is how a caller comes to believe a scan behaved differently than it did.
//
// DELIBERATELY NOT A BLANKET CLAIM, and derived from runner_reads_settings per tool rather than
// asserted. Runners are being wired one at a time, so any fixed sentence about "nothing reads this"
// starts true and silently becomes a lie. This one names the tools it applies to, which means it
// cannot outlive the fact it describes.
function pendingWiringNote(tools) {
  const unwired = tools.filter((t) => t.runner_reads_settings === false).map((t) => t.tool || t.key);
  if (unwired.length === 0) return undefined;
  return `The runner does not read this store yet for: ${unwired.join(', ')}. For those, settings `
    + 'save, validate and compose (see would_add_args) but the next scan still uses the hardcoded '
    + 'command line, so treat a saved setting as a reviewed intention rather than as applied scan '
    + 'behaviour. runner_reads_settings on each tool is the authority, and the tools it is true for '
    + 'take effect on the next scan.';
}

const ACTIONS = ['tools', 'option_reference', 'owned_flags', 'settings', 'save_settings'];

const manageWildcardToolsSchema = z.object({
  action: z.enum(ACTIONS).describe(
    'tools: the registry. Every Wildcard workflow tool in step order, what it runs as, how many '
    + 'options and owned flags it has, and whether it has a vocabulary at all. START HERE. '
    + 'option_reference: every setting one tool honours, with its flag, kind, group, bounds, what the '
    + 'tool does when it is unset, and PROVENANCE. This is the server\'s own vocabulary, the same map '
    + 'a scan reads, so it can never drift from what the Settings screen shows. Omit tool to get an '
    + 'index of option keys per tool; filter with group, provenance or option. '
    + 'owned_flags: the flags the RUNNER sets, each with the reason it is refused. These are NOT '
    + 'options. Read this before concluding a flag is missing: several are absent because they are '
    + 'broken in the installed build, not because nobody added them. '
    + 'settings: the stored settings for one tool on one target, with the command-line arguments they '
    + 'would compose and any that cannot take effect. Omit tool for every tool\'s settings at once. '
    + 'save_settings: MERGE settings into the store. A null value removes a key; replace: true makes '
    + 'the payload authoritative. A refusal comes back with the server\'s reason verbatim.'),
  target_id: z.string().optional().describe(
    'Scope target id. Defaults to the active target. Not needed for tools, option_reference or '
    + 'owned_flags, which describe the workflow rather than a target.'),
  tool: z.string().optional().describe(
    'Which Wildcard tool. In step order: amass, sublist3r, assetfinder, gau, ctl, subfinder, httpx, '
    + 'shuffledns, cewl, gospider, subdomainizer, nuclei-screenshot, metadata, nuclei. The tools '
    + 'action is the authority on that list; an unknown key is answered with the registry\'s own keys.'),
  group: z.string().optional().describe(
    'option_reference only: return one group of a tool\'s options, e.g. "Runtime" or "Scope Filters". '
    + 'The group names for a tool are in its registry entry. Use this rather than detail:"full" on a '
    + 'tool with many options.'),
  provenance: z.enum(['measured', 'runner', 'unverified']).optional().describe(
    'option_reference only: filter by how the entry was established. measured = probed against the '
    + 'installed container and the behaviour observed, so its danger note describes something that was '
    + 'actually seen. runner = the flag is on the command line the runner already executes, so the '
    + 'image accepts it, but what a DIFFERENT value does was not measured. unverified = accepted, or '
    + 'read out of the installed source, with its semantics unproven.'),
  option: z.string().optional().describe(
    'option_reference only: one option key, returned in full whatever detail says. The way to read one '
    + 'option\'s reasoning without pulling the whole tool.'),
  settings: z.record(z.any()).optional().describe(
    'save_settings only. Keyed by the option keys option_reference lists, NOT by flag. A null value '
    + 'removes that key. Lists accept either an array of strings or a comma separated string.'),
  replace: z.boolean().optional().describe(
    'save_settings only: make the payload authoritative rather than merging it into what is stored. '
    + 'Default false, so sending one setting never blanks the rest.'),
  detail: z.enum(['compact', 'full']).optional().describe(detailDescription(
    'returns each option\'s flag, kind, bounds, provenance and the HEADLINE of its danger and default '
    + 'behaviour, plus how many characters the full prose runs to.',
    'returns the complete why, danger and default-behaviour text, which is where the measured '
    + 'behaviour of that flag is actually written.')),
});

async function manageWildcardTools(params) {
  switch (params.action) {
    case 'tools':
      return toolsAction(params);
    case 'option_reference':
      return optionReferenceAction(params);
    case 'owned_flags':
      return ownedFlagsAction(params);
    case 'settings':
      return settingsAction(params);
    case 'save_settings':
      return saveSettingsAction(params);
    default:
      return { error: `unknown action: ${params.action}` };
  }
}

async function toolsAction(params) {
  const registry = await fetchRegistry();
  const full = isFull(params);
  let tools = registry.tools;
  if (params.tool) {
    const found = findTool(registry, params.tool);
    if (found.error) return { error: found.error };
    tools = [found.tool];
  }
  // The notes are the heaviest field in the registry: all fourteen at detail:"full" measures 29225
  // characters, past the budget, so it downgrades and says so rather than returning nothing.
  const projected = projectRows(tools, (t, f) => compactTool(t, f), full, NARROW_BY_TOOL);
  const rows = projected.rows;
  const out = {
    workflow: 'wildcard',
    tools: rows,
    detail: projected.detail,
    downgraded_from_full: projected.downgraded_from_full,
    provenance_meaning: registry.provenance_meaning,
    note: 'One store, two editors: these are the same settings the Wildcard Settings screen writes, '
      + 'in the same rows, so a change made here is visible there and the other way round. Neither '
      + 'surface carries its own option list.',
  };
  if (rows.some((t) => t.option_count === 0)) {
    out.tools_with_no_vocabulary = 'A zero option_count is an answer, not a gap, and the tool\'s '
      + 'limitation says which kind: assetfinder has exactly one flag and the runner sets it, '
      + 'sublist3r no longer shells out to anything, and httpx delegates to the httpx_configs store '
      + 'that is already wired. Saving to one of these is refused with that reason.';
  }
  out.pending_wiring = pendingWiringNote(rows);
  return dropEmpty(out);
}

async function optionReferenceAction(params) {
  const registry = await fetchRegistry();
  const full = isFull(params);

  // Without a tool this is an INDEX rather than a dump. The full vocabulary is 167 options of dense
  // prose across fourteen tools; returned in one response it exceeds the output cap and the caller
  // gets nothing usable at all.
  if (!params.tool) {
    return {
      tools: registry.tools.map((t) => dropEmpty({
        tool: t.key,
        name: t.name,
        phase: t.phase,
        groups: t.groups,
        option_keys: Object.keys(t.options || {}).sort(),
        option_count: Object.keys(t.options || {}).length,
        limitation: t.limitation,
        delegates_to: t.delegates_to,
      })),
      provenance_meaning: registry.provenance_meaning,
      note: 'This is the index. Pass tool to read one tool\'s options, and narrow further with group, '
        + 'provenance or option. The whole vocabulary in one response does not fit the output cap.',
    };
  }

  const found = findTool(registry, params.tool);
  if (found.error) return { error: found.error };
  const tool = found.tool;
  const options = tool.options || {};

  // One option, always in full. A caller asking about a single key wants the reasoning, and one
  // option's prose is never the thing that blows the budget.
  if (params.option) {
    const meta = options[params.option];
    if (!meta) {
      return {
        error: `${tool.name} has no option called ${params.option}. Its options are: `
          + `${Object.keys(options).sort().join(', ') || 'none'}.`,
      };
    }
    return {
      tool: tool.key,
      option: compactOption(params.option, meta, true),
      provenance_meaning: registry.provenance_meaning,
    };
  }

  let keys = Object.keys(options).sort();
  const filters = {};
  if (params.group) {
    const wanted = params.group.toLowerCase();
    keys = keys.filter((k) => (options[k].group || '').toLowerCase() === wanted);
    filters.group = params.group;
    if (keys.length === 0) {
      return {
        error: `${tool.name} has no option group called ${params.group}. Its groups are: `
          + `${(tool.groups || []).join(', ') || 'none'}.`,
      };
    }
  }
  if (params.provenance) {
    keys = keys.filter((k) => options[k].provenance === params.provenance);
    filters.provenance = params.provenance;
    if (keys.length === 0) {
      // An empty array would be dropped as saying nothing, and "no options key at all" reads like a
      // bug rather than like an answer. So the counts by provenance are returned instead, which is
      // the question behind the filter anyway.
      const counts = {};
      for (const k of Object.keys(options)) {
        const p = options[k].provenance || 'unrecorded';
        counts[p] = (counts[p] || 0) + 1;
      }
      return {
        tool: tool.key,
        returned: 0,
        message: `No ${tool.name} option was established as "${params.provenance}".`,
        options_by_provenance: counts,
      };
    }
  }

  const projected = projectRows(keys, (k, f) => compactOption(k, options[k], f), full);

  const out = {
    tool: tool.key,
    name: tool.name,
    step: tool.step,
    phase: tool.phase,
    groups: tool.groups,
    invocation: tool.invocation,
    runner_reads_settings: tool.runner_reads_settings,
    filters: Object.keys(filters).length ? filters : undefined,
    returned: keys.length,
    option_count: Object.keys(options).length,
    detail: projected.detail,
    downgraded_from_full: projected.downgraded_from_full,
    options: projected.rows,
    provenance_meaning: registry.provenance_meaning,
    owned_flag_count: Object.keys(tool.owned_flags || {}).length,
    note: 'These keys are what save_settings takes. They are UI identifiers, not flags: send '
      + '"timeoutMinutes", not "-timeout". A flag the runner owns is refused; action owned_flags '
      + 'lists those with the reason for each.',
  };
  if (tool.limitation) out.limitation = tool.limitation;
  if (tool.delegates_to) out.delegates_to = tool.delegates_to;
  out.pending_wiring = pendingWiringNote([tool]);
  if (!full && keys.length > 20) {
    out.narrowing = 'This tool has many options. Filter with group or provenance, or read one key '
      + 'in full with option, rather than asking for detail:"full" across all of them.';
  }
  return dropEmpty(out);
}

async function ownedFlagsAction(params) {
  const registry = await fetchRegistry();
  const full = isFull(params);

  if (!params.tool) {
    return {
      tools: registry.tools.map((t) => ({
        tool: t.key,
        owned_flag_count: Object.keys(t.owned_flags || {}).length,
        flags: Object.keys(t.owned_flags || {}).sort(),
      })),
      owned_flags_meaning: registry.owned_flags_meaning,
      note: 'Pass tool to read the reason on each. The reason is the useful part: it says whether the '
        + 'flag is set by the runner, blacklisted for what it does, broken in the installed build, or '
        + 'blocked because the container has no volume mount for a path to live in.',
    };
  }

  const found = findTool(registry, params.tool);
  if (found.error) return { error: found.error };
  const tool = found.tool;
  const owned = tool.owned_flags || {};
  const flags = Object.keys(owned).sort();
  const projected = projectRows(flags, (f, isFullRow) => compactOwnedFlag(f, owned[f], isFullRow), full);
  return dropEmpty({
    tool: tool.key,
    name: tool.name,
    owned_flag_count: flags.length,
    detail: projected.detail,
    downgraded_from_full: projected.downgraded_from_full,
    owned_flags: projected.rows,
    owned_flags_meaning: registry.owned_flags_meaning,
    note: 'These are NOT options and sending one to save_settings is refused with the reason above. '
      + 'A flag never appears in both lists: an option and an owned flag naming the same flag would '
      + 'make every save 400 with nothing on screen to explain it.',
  });
}

async function settingsAction(params) {
  const targetId = await resolveTargetId(params);
  if (!targetId) return { error: 'No target_id given and no active target set.' };
  const full = isFull(params);

  // Every tool at once. Already a summary shape on the server, so it is returned close to as-is.
  if (!params.tool) {
    const data = await apiGet(`/wildcard-tools/${targetId}/settings`);
    const tools = Array.isArray(data.tools) ? data.tools : [];
    const out = {
      scope_target_id: targetId,
      tools,
      configured_tools: tools.filter((t) => t.configured_count > 0).map((t) => t.tool),
      note: 'configured_count is how many keys are stored, option_count how many exist. An empty '
        + 'settings object means the tool runs on its own defaults, which its option placeholders '
        + 'describe. Pass tool for one tool\'s values plus the arguments they would compose.',
    };
    out.pending_wiring = pendingWiringNote(tools);
    return dropEmpty(out);
  }

  const data = await apiGet(`/wildcard-tools/${targetId}/${params.tool}/settings`);
  const options = data.options || {};
  const owned = data.owned_flags || {};

  const out = {
    scope_target_id: targetId,
    tool: data.tool,
    tool_name: data.tool_name,
    step: data.step,
    phase: data.phase,
    invocation: data.invocation,
    settings: data.settings || {},
    configured_count: Object.keys(data.settings || {}).length,
    option_count: Object.keys(options).length,
    owned_flag_count: Object.keys(owned).length,
    groups: data.groups,
    runner_reads_settings: data.runner_reads_settings,
    // What these settings would put on the command line, shown rather than described. A settings
    // surface that cannot show what it will run is one the caller has to take on trust.
    would_add_args: data.would_add_args || [],
    compose_warnings: data.compose_warnings,
    // Stored but unable to take effect, given the rest of the settings. This is the answer to "I set
    // the resolver concurrency and nothing changed": subfinder -t is documented "(-active only)".
    inert: data.inert,
    limitation: data.limitation,
    delegates_to: data.delegates_to,
    pending_wiring: data.pending_wiring,
  };
  if (full) {
    // The vocabulary for the keys that ARE SET, rather than all of them. A caller reading settings
    // wants to know what the stored values do, and the whole vocabulary is what option_reference is
    // for: repeating all 43 nuclei options here measured 25730 characters, past the cap, for a
    // response whose subject was the two keys somebody had configured.
    const set = Object.keys(data.settings || {}).filter((k) => options[k]).sort();
    const projected = projectRows(set, (k, f) => compactOption(k, options[k], f), true, NARROW_BY_OPTION);
    out.configured_options = projected.rows;
    out.configured_options_detail = projected.detail;
    out.downgraded_from_full = projected.downgraded_from_full;
    if (data.notes) out.notes = data.notes;
    out.note = 'configured_options describes only the keys that are set. action option_reference '
      + 'returns the whole vocabulary for this tool.';
  } else {
    if (data.notes) out.notes_chars = data.notes.length;
    out.note = 'Values only. action option_reference returns the vocabulary these keys come from, '
      + 'with what each does and what the tool does when it is unset.';
  }
  if (!(out.would_add_args || []).length && Object.keys(data.settings || {}).length) {
    out.composes_nothing = 'These settings add no command-line arguments. That is expected for a '
      + 'tool whose options carry no flag, either because the setting switches runner behaviour or '
      + 'because the tool has no command line at all. Anything else means the values were dropped, '
      + 'and compose_warnings and inert say which.';
  }
  // A stored key the vocabulary no longer contains cannot be composed and nothing reads it, so it is
  // named rather than left sitting in the response looking configured.
  const orphaned = Object.keys(data.settings || {}).filter((k) => !options[k]);
  if (orphaned.length && Object.keys(options).length) {
    out.stored_but_unknown = orphaned;
    out.stored_but_unknown_warning = `${orphaned.join(', ')} ${orphaned.length === 1 ? 'is' : 'are'} `
      + 'stored but not in this tool\'s vocabulary, so nothing reads them and they compose no '
      + 'arguments. Send them as null to remove them.';
  }
  const trimmed = dropEmpty(out);
  // Re-attached after dropEmpty, because an EMPTY args list is an answer: it says these settings
  // compose nothing. Dropping it would leave that indistinguishable from a response that never
  // computed it.
  trimmed.would_add_args = out.would_add_args || [];
  return trimmed;
}

async function saveSettingsAction(params) {
  // Validated before the target is resolved, so a missing argument is answered without a round trip
  // and without depending on there being an active target.
  if (!params.tool) return { error: 'tool is required for save_settings.' };
  if (!params.settings) {
    return {
      error: 'settings is required for save_settings. It is keyed by the option keys '
        + 'option_reference lists, not by flag. Send a key as null to remove it.',
    };
  }
  const targetId = await resolveTargetId(params);
  if (!targetId) return { error: 'No target_id given and no active target set.' };

  try {
    const data = await apiPost(`/wildcard-tools/${targetId}/${params.tool}/settings`, {
      settings: params.settings,
      replace: params.replace === true,
    });
    const out = {
      saved: data.saved === true,
      scope_target_id: targetId,
      tool: data.tool || params.tool,
      settings: data.settings,
      would_add_args: data.would_add_args || [],
      compose_warnings: data.compose_warnings,
      inert: data.inert,
      inert_warning: data.inert_warning,
      pending_wiring: data.pending_wiring,
      replaced: params.replace === true ? true : undefined,
    };
    const trimmed = dropEmpty(out);
    // Same reason as on the read: composing nothing is a result, not an absence.
    trimmed.would_add_args = out.would_add_args || [];
    return trimmed;
  } catch (error) {
    const refusal = parseRefusal(error);
    // A refusal that loses the server's wording leaves the caller with a status code and no idea
    // which key was wrong, so the message is returned exactly as the server wrote it.
    if (!refusal) throw error;
    return dropEmpty({
      saved: false,
      refused: true,
      tool: params.tool,
      refusal_code: refusal.refusal_code,
      http_status: refusal.http_status,
      reason: refusal.reason,
      what_this_means: REFUSAL_HINTS[refusal.refusal_code],
      note: 'Nothing was stored. The refusal names what was wrong: the whole point of refusing rather '
        + 'than storing is that a setting nothing reads, or one the runner overwrites, changes '
        + 'nothing while reading as configured.',
    });
  }
}

module.exports = {
  manageWildcardToolsSchema,
  manageWildcardTools,
  // Exported for tests: these are the pure projections, and the shape they produce is what decides
  // whether a listing fits the output cap.
  firstSentence,
  compactOption,
  compactTool,
  compactOwnedFlag,
  headlined,
  pendingWiringNote,
  projectRows,
  parseRefusal,
  ACTIONS,
  ROW_BUDGET,
};
