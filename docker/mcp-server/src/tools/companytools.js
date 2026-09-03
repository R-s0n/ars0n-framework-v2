const { z } = require('zod');
const { apiGet, apiPost } = require('../api');
const { isFull, dropEmpty, detailDescription } = require('../utils/detail');

// The Company workflow's tool configuration, as seen from the agent side.
//
// ONE STORE, TWO EDITORS, exactly as the Wildcard surface works. The Company Settings screen and
// this tool write the same company_tool_settings rows through the same Go handlers, and both
// GENERATE what they show from the vocabulary the server serves alongside the values. That is why
// there is no option list in this file: option_reference returns the server's own map, the same one
// a scan would read. Adding an option in server/utils/companyOptions*.go makes it appear in the UI
// and become settable here in the same commit, and there is no second list to forget.
//
// THE PROJECTIONS ARE IMPORTED FROM wildcardtools.js RATHER THAN COPIED, and that is the same
// decision the server made when it declared CompanyTool a type ALIAS of WildcardTool instead of a
// second struct. The two registries serve the identical shape - options with provenance, prose and
// bounds; owned flags with a reason each - so a second compactOption here would be a second thing to
// keep in step, which is the exact failure this whole design exists to prevent. What IS company
// specific is wrapped around them below, and it is only three things: two fields that exist solely
// for this registry (min_items, inert_when_values), the settings store a tool's values actually live
// in, and the separate table that owns its target selection.
//
// WHY THE MEASURED PROSE MATTERS MORE HERE THAN ANYWHERE ELSE IN THIS SERVER. An agent has no other
// way to learn that ip_port_scan's three timeouts are in MILLISECONDS while amass's is in MINUTES
// and is applied PER DOMAIN, or that a host-discovery port list that is too narrow makes live hosts
// read as dead. Both mistakes are silent: this workflow's tools do not fail, they exit 0, print
// nothing, and get stored as a successful scan that found nothing. So danger and default-behaviour
// keep a headline even in compact, and the unit is never dropped at either level.
const {
  compactOption,
  compactTool,
  compactOwnedFlag,
  headlined,
  pendingWiringNote,
  projectRows,
  parseRefusal,
  ROW_BUDGET,
} = require('./wildcardtools');

// The narrowing advice attached to a downgraded response. Stated rather than implied, because a
// downgrade that does not say how to get what was asked for leaves the caller worse off than a
// refusal would.
const NARROW_BY_OPTION = 'Narrow with group, provenance or option to get the full prose for the ones '
  + 'you care about.';
const NARROW_BY_TOOL = 'Pass tool to get one tool\'s full entry, including its runner notes.';
const NARROW_BY_FLAG = 'Pass tool to read one tool\'s owned flags rather than all thirteen.';

// hasCommandLine is DERIVED from the vocabulary rather than listed here.
//
// Five of the thirteen Company tools have no command line at all: the on-prem live web server scan
// is first-party Go inside the api container, and crt.sh, SecurityTrails, Shodan and Censys are
// single HTTP requests. A list of those five in this file would be a second copy of something the
// server owns and would go stale the day a sixth is added or one of the five grows a binary. An
// option that composes an argument is one that carries a flag, so "does this tool have a command
// line" is answerable from the map itself.
function hasCommandLine(tool) {
  return Object.values((tool && tool.options) || {}).some((meta) => Boolean(meta && meta.flag));
}

// The sentence that replaces sixty-one repetitions of itself.
//
// compactOption attaches a no_flag explanation to EVERY option that composes no argument. That is
// right for a tool like metabigor, where two of its four options are framework switches sitting
// beside two real flags and the difference is genuinely surprising. It is wrong for a tool where
// NOTHING has a flag: ip_port_scan, ctl_company, securitytrails_company, shodan_company and
// censys_company carry 61 flagless options between them, and repeating a 250-character sentence on
// each of them spends roughly fifteen kilobytes restating one fact the tool's own limitation
// already states. So for those tools the per-row sentence is dropped and this is said once.
const NO_COMMAND_LINE = 'THIS TOOL HAS NO COMMAND LINE, so none of these options is a flag and none '
  + 'of them composes an argument: would_add_args is correctly empty for every setting. They are '
  + 'values the RUNNER reads directly. Do not look for a binary or try to pass CLI syntax. The '
  + 'tool\'s limitation says what it is instead (Go inside the api container, or a single HTTP '
  + 'request), and several of these options are marked NOT IMPLEMENTED in their danger note, which '
  + 'means the runner does not read them yet either.';

// companyOption projects one option, then adds the two fields that exist ONLY for this registry.
//
// Both were added to the shared Go type for the Company workflow and no Wildcard option sets either,
// which is why the shared projection does not carry them and why they are added here rather than
// there.
//
// min_items is a save-time floor on a LIST, and every one of the four that has it was measured to
// empty a scan while the tool still exits 0: an empty ip_port_scan hostDiscoveryPorts makes
// isHostAlive return false for every address, an empty webPorts makes the port scan find nothing, an
// empty shodan enabledQueries never enters the query loop, and an empty sourceFields makes every
// match yield nothing. All four are then stored as a successful scan with zero results. A caller
// that cannot see the floor will try to "disable" a phase by emptying its list and be refused with
// no idea why the empty list was the problem.
//
// inert_when_values is inertness that depends on a VALUE rather than on a switch being on:
// github-subdomains.py has no -a and no -r, so those two options are dead when that script is
// selected, and the gating value is a script name rather than a boolean.
function companyOption(key, meta, full = false, toolHasCommandLine = true) {
  const row = compactOption(key, meta, full);
  if (!toolHasCommandLine) delete row.no_flag;
  if (meta.min_items !== undefined && meta.min_items !== null) row.min_items = meta.min_items;
  if (Array.isArray(meta.inert_when_values) && meta.inert_when_values.length) {
    row.inert_when_values = meta.inert_when_values;
  }
  return row;
}

// settingsStoreFor answers WHICH TABLE a tool's settings actually live in, from the server's own
// settings_stores block rather than from a constant here.
//
// It is not a formality. nuclei is registered in the Company registry but its settings are read from
// and written to wildcard_tool_settings, because ONE nuclei runner serves both workflows and it
// loads by scope target id alone without ever reading the target's type. Writing a company target's
// nuclei settings anywhere else would leave the runner reading an empty row, so the scan would
// behave exactly as if nothing had been configured. That is also why nuclei is the only Company tool
// reporting runner_reads_settings true today.
function settingsStoreFor(key, stores) {
  const shared = (stores && stores.shared) || {};
  return shared[key] || (stores && stores.default) || undefined;
}

// companyTool projects one registry entry and answers the two questions the shared projection does
// not: where the values are stored, and where the "which targets" question is answered.
//
// TARGET SELECTION IS A DIFFERENT SCREEN AND A DIFFERENT TABLE for six of these tools, and saying so
// on the tool's own row is the difference between an agent looking for the domain picker and an
// agent concluding the feature is missing. The note is worth its characters: for ip_port_scan it
// records that amass_intel_configs.selected_network_ranges LOOKS like it filters that scan's targets
// and is not read by it, and for cloud_enum it records the one real overlap in the workflow, twelve
// columns mapping to 23 flags that are all declared framework-owned for that reason.
function companyTool(tool, full = false, stores = {}, selection = {}) {
  const row = compactTool(tool, full);
  row.settings_store = settingsStoreFor(tool.key, stores);
  if (!hasCommandLine(tool) && Object.keys(tool.options || {}).length > 0) {
    row.composes_no_arguments = true;
  }
  const sel = selection[tool.key];
  if (sel) {
    if (sel.table) row.target_selection_store = sel.table;
    if (Array.isArray(sel.owned_flags) && sel.owned_flags.length) {
      row.target_selection_owned_flag_count = sel.owned_flags.length;
    }
    if (sel.note) {
      if (full) row.target_selection_note = sel.note;
      else Object.assign(row, headlined('target_selection_note', sel.note, 200));
    }
  }
  return dropEmpty(row);
}

// compactSettingsRow projects one entry of the every-tool settings listing.
//
// The server sends these close to their final shape, but five of the thirteen carry a limitation of
// several hundred characters and repeating all of them costs more than the values the caller asked
// for. inert and advisories are NEVER sized away at either level: they are the answer to "I set this
// and nothing happened" and "this is set, is in effect, and is doing less than it looks like".
function compactSettingsRow(entry, full = false) {
  const row = {
    tool: entry.tool,
    tool_name: entry.tool_name,
    step: entry.step,
    phase: entry.phase,
    settings: entry.settings && Object.keys(entry.settings).length ? entry.settings : undefined,
    // Defaulted rather than left to arrive, because ZERO is an answer here: it says this tool runs
    // on its own defaults, which its option placeholders describe. dropEmpty keeps 0, so the only
    // way this vanishes is if the server omitted it, and an absent count reads like a bug.
    configured_count: entry.configured_count || 0,
    option_count: entry.option_count,
    runner_reads_settings: entry.runner_reads_settings,
    settings_store: entry.settings_store,
    delegates_to: entry.delegates_to,
    inert: entry.inert,
    advisories: entry.advisories,
  };
  if (entry.limitation) {
    if (full) row.limitation = entry.limitation;
    else Object.assign(row, headlined('limitation', entry.limitation, 220));
  }
  return dropEmpty(row);
}

// What each refusal MEANS, beyond the server's own wording.
//
// The server names what was wrong and this says why it is refused rather than stored. Every one of
// these exists because a stored setting that changes nothing is indistinguishable, afterwards, from
// a setting that worked - and in this workflow so is a scan that was silenced.
const REFUSAL_HINTS = {
  framework_owned: 'This flag or value is set by the runner itself. It is refused rather than '
    + 'stored, because a stored setting that is then displaced at run time is how an operator comes '
    + 'to believe a scan did something it did not. Several are owned because they were MEASURED to '
    + 'do nothing or to empty a scan: amass -exclude and -include still queried every source, '
    + 'metabigor -x and --proxy were both silently ignored, and metabigor -v is load bearing for '
    + 'PARSING rather than cosmetic - without it not one output line matches the parser and the '
    + 'scan stores zero rows as a success. Read them with action option_reference, owned_flags true.',
  unknown_option: 'Nothing reads this key, so it is refused rather than kept. Keys are UI '
    + 'identifiers, NOT flags: send "timeoutMinutes", not "-timeout". The reason above lists the '
    + 'valid keys for this tool.',
  invalid_value: 'The vocabulary type-checks and range-checks before storing, because a value the '
    + 'tool rejects at run time reports an error long after the caller was told it was saved. Note '
    + 'the floors: dnsx retries has a floor of 1 because `-retry 0` exits 1 and the runner treats a '
    + 'non-zero exit as a per-domain failure it skips with `continue`, so a saved 0 would silently '
    + 'drop EVERY domain and still finish the scan as success.',
  unsafe_value: 'Refused because of what this VALUE is against this TARGET, not because of its '
    + 'type. Each of these was measured to empty a scan while the tool still exits 0: a resolver '
    + 'that is a file path (dnsx documents -r as "file or comma separated", the path does not exist '
    + 'inside the container, and it exits 0 with zero bytes of stdout), a resolver or proxy on '
    + 'loopback (127.0.0.1 means the TOOL\'S container, where nothing is listening), a port-list '
    + 'entry that is not a port (the list is a Go slice inside the scanner, not a command line, so a '
    + 'bad entry is not a parse error - it is a port silently never dialled), an AWS account id that '
    + 'is not exactly 12 digits (the sqs service runs and produces nothing), a katana header with no '
    + 'colon, and an amass blacklist entry equal to or a DNS parent of a domain the scan is '
    + 'configured to enumerate (that empties the domain\'s entire enumeration, and the runner skips '
    + 'the failed domain with `continue` and still stores the scan as success).',
  no_vocabulary: 'This tool has nothing to configure and the reason above says why. No Company tool '
    + 'is in that state today.',
  unknown_tool: 'Call action tools for the registry.',
  invalid_body: 'The request body did not decode. settings must be an object keyed by option key.',
  invalid_settings: 'The merged settings could not be encoded for storage.',
};

async function fetchRegistry() {
  const registry = await apiGet('/company-tools');
  return {
    tools: Array.isArray(registry.tools) ? registry.tools : [],
    provenance_meaning: registry.provenance_meaning,
    owned_flags_meaning: registry.owned_flags_meaning,
    no_command_line_note: registry.no_command_line_note,
    settings_stores: registry.settings_stores || {},
    target_selection_stores: registry.target_selection_stores || {},
  };
}

// Looked up against the LIVE registry rather than a list in this file, so a tool added on the server
// is reachable here without a second edit, and an unknown key is answered with the registry's own
// keys instead of a schema error that names nothing.
function findTool(registry, key) {
  const found = registry.tools.find((t) => t.key === key);
  if (found) return { tool: found };
  return {
    error: `No Company workflow tool called ${key}. Known tools, in step order: `
      + `${registry.tools.map((t) => t.key).join(', ')}.`,
  };
}

async function resolveTargetId(params) {
  if (params.target_id) return params.target_id;
  const targets = await apiGet('/scopetarget/read');
  const active = (Array.isArray(targets) ? targets : []).find((t) => t.active);
  return active ? active.id : null;
}

const ACTIONS = ['tools', 'option_reference', 'settings', 'save_settings'];

const manageCompanyToolsSchema = z.object({
  action: z.enum(ACTIONS).describe(
    'tools: the registry. Every Company workflow tool in step order, what it runs as, how many '
    + 'options and owned flags it has, which table its settings live in, and which OTHER table owns '
    + 'its target selection. START HERE. '
    + 'option_reference: every setting one tool honours, with its flag (where it has one), kind, '
    + 'group, bounds, what the tool does when it is unset, and PROVENANCE. This is the server\'s own '
    + 'vocabulary, the same map the Settings screen renders, so the two can never drift. Omit tool '
    + 'to get an index of option keys per tool; filter with group, provenance or option; pass '
    + 'owned_flags true to read the flags the RUNNER sets instead, each with the reason it is '
    + 'refused. '
    + 'settings: the stored settings for one tool on one target, with the arguments they would '
    + 'compose, anything stored that cannot take effect (inert) and anything in effect that does '
    + 'less than it looks like (advisories). Omit tool for every tool at once. '
    + 'save_settings: MERGE settings into the store. A null value removes a key; replace true makes '
    + 'the payload authoritative. A refusal comes back with the server\'s reason verbatim.'),
  target_id: z.string().optional().describe(
    'Scope target id, and it must be a COMPANY scope target. Defaults to the active target. Not '
    + 'needed for tools or option_reference, which describe the workflow rather than a target.'),
  tool: z.string().optional().describe(
    'Which Company tool. In step order: amass_intel, metabigor_company, ip_port_scan, ctl_company, '
    + 'securitytrails_company, github_recon, shodan_company, censys_company, amass_enum_company, '
    + 'dnsx_company, cloud_enum, katana_company, nuclei. The tools action is the authority on that '
    + 'list; an unknown key is answered with the registry\'s own keys.'),
  group: z.string().optional().describe(
    'option_reference only: return one group of a tool\'s options, e.g. "Host Discovery", "Range '
    + 'Coverage" or "Rate & Concurrency". The group names for a tool are in its registry entry. Use '
    + 'this rather than detail:"full" on katana_company (46 options) or nuclei (43).'),
  provenance: z.enum(['measured', 'runner', 'unverified']).optional().describe(
    'option_reference only: filter by how the entry was established. measured = probed against the '
    + 'installed container or the live API and the behaviour observed, so the danger note describes '
    + 'something that was actually seen. runner = taken from the command line or request the runner '
    + 'issues today, so the value is certainly accepted, but what a DIFFERENT value does was not '
    + 'measured. unverified = accepted, or read out of the installed source, with its semantics '
    + 'unproven. Four of these tools could not be measured past a 401 because no API key is '
    + 'configured in this deployment, and crt.sh answered 502 to every probe, so their vocabularies '
    + 'are largely unverified and say so.'),
  option: z.string().optional().describe(
    'option_reference only: one option key, returned in full whatever detail says. The way to read '
    + 'one option\'s reasoning without pulling the whole tool.'),
  owned_flags: z.boolean().optional().describe(
    'option_reference only: return the flags and values the RUNNER owns instead of the settable '
    + 'options. These are NOT options and sending one is refused. The reason on each is the '
    + 'diagnostic: it says whether the flag is runner-set, blacklisted for what it does, absent from '
    + 'this subcommand, broken in the installed build, or blocked on a volume mount that does not '
    + 'exist. Read this before concluding a flag is missing. Omit tool for the per-tool counts.'),
  settings: z.record(z.any()).optional().describe(
    'save_settings only. Keyed by the option keys option_reference lists, NOT by flag. A null value '
    + 'removes that key. Lists accept either an array of strings or a comma separated string.'),
  replace: z.boolean().optional().describe(
    'save_settings only: make the payload authoritative rather than merging it into what is stored. '
    + 'Default false, so sending one setting never blanks the rest. The Settings screen sends true, '
    + 'because a form that has just shown every field IS the whole state.'),
  detail: z.enum(['compact', 'full']).optional().describe(detailDescription(
    'returns each option\'s flag, kind, unit, bounds, provenance and the HEADLINE of its danger and '
    + 'default behaviour, plus how many characters the full prose runs to.',
    'returns the complete why, danger and default-behaviour text, which is where the measured '
    + 'behaviour of that option is actually written.')),
});

async function manageCompanyTools(params) {
  switch (params.action) {
    case 'tools':
      return toolsAction(params);
    case 'option_reference':
      return optionReferenceAction(params);
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
  // The per-tool notes are by far the heaviest field in this registry - several of them run to
  // thousands of characters of measured findings - so asking for all thirteen in full will not fit
  // and downgrades with the reason rather than returning nothing.
  const projected = projectRows(
    tools,
    (t, f) => companyTool(t, f, registry.settings_stores, registry.target_selection_stores),
    full,
    NARROW_BY_TOOL,
  );
  const rows = projected.rows;
  const out = {
    workflow: 'company',
    tools: rows,
    detail: projected.detail,
    downgraded_from_full: projected.downgraded_from_full,
    provenance_meaning: registry.provenance_meaning,
    note: 'One store, two editors: these are the same settings the Company Settings screen writes, '
      + 'in the same rows, so a change made here is visible there and the other way round. Neither '
      + 'surface carries its own option list.',
  };
  if (rows.some((t) => t.composes_no_arguments)) {
    out.tools_with_no_command_line = registry.no_command_line_note;
  }
  if (rows.some((t) => t.target_selection_store)) {
    out.target_selection_is_a_different_store = 'target_selection_store names the EXISTING table '
      + 'that answers "which domains, ranges or servers does this tool scan". It is a different '
      + 'screen and a different vocabulary, and the flags it owns are declared framework-owned here '
      + 'so the same setting can never be written in two places. If you are looking for the domain '
      + 'picker, it is there, not in these settings.';
  }
  // Which table each tool's values live in, and the one exception, from the server rather than from
  // a constant here.
  if (registry.settings_stores && registry.settings_stores.note) {
    out.settings_stores = registry.settings_stores;
  }
  out.pending_wiring = pendingWiringNote(rows);
  return dropEmpty(out);
}

async function optionReferenceAction(params) {
  const registry = await fetchRegistry();
  const full = isFull(params);
  if (params.owned_flags) return ownedFlagsView(registry, params, full);

  // Without a tool this is an INDEX rather than a dump. The whole vocabulary is 207 options of dense
  // measured prose across thirteen tools; returned in one response it exceeds the output cap and the
  // caller gets nothing usable at all.
  if (!params.tool) {
    return {
      tools: registry.tools.map((t) => dropEmpty({
        tool: t.key,
        name: t.name,
        step: t.step,
        phase: t.phase,
        groups: t.groups,
        option_keys: Object.keys(t.options || {}).sort(),
        option_count: Object.keys(t.options || {}).length,
        owned_flag_count: Object.keys(t.owned_flags || {}).length,
        settings_store: settingsStoreFor(t.key, registry.settings_stores),
        composes_no_arguments: !hasCommandLine(t) && Object.keys(t.options || {}).length > 0
          ? true : undefined,
        delegates_to: t.delegates_to,
      })),
      provenance_meaning: registry.provenance_meaning,
      note: 'This is the index. Pass tool to read one tool\'s options, and narrow further with '
        + 'group, provenance or option. The whole vocabulary in one response does not fit the output '
        + 'cap. Keys are UI identifiers, not flags.',
    };
  }

  const found = findTool(registry, params.tool);
  if (found.error) return { error: found.error };
  const tool = found.tool;
  const options = tool.options || {};
  const cli = hasCommandLine(tool);

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
    return dropEmpty({
      tool: tool.key,
      option: companyOption(params.option, meta, true, cli),
      no_command_line: cli ? undefined : NO_COMMAND_LINE,
      provenance_meaning: registry.provenance_meaning,
    });
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
      // bug rather than like an answer. The counts by provenance are the question behind the filter
      // anyway, and for this registry they are worth seeing: four of these tools could not be
      // measured past a 401.
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

  const projected = projectRows(
    keys,
    (k, f) => companyOption(k, options[k], f, cli),
    full,
    NARROW_BY_OPTION,
  );

  const out = {
    tool: tool.key,
    name: tool.name,
    step: tool.step,
    phase: tool.phase,
    groups: tool.groups,
    invocation: tool.invocation,
    runner_reads_settings: tool.runner_reads_settings,
    settings_store: settingsStoreFor(tool.key, registry.settings_stores),
    filters: Object.keys(filters).length ? filters : undefined,
    returned: keys.length,
    option_count: Object.keys(options).length,
    detail: projected.detail,
    downgraded_from_full: projected.downgraded_from_full,
    options: projected.rows,
    provenance_meaning: registry.provenance_meaning,
    owned_flag_count: Object.keys(tool.owned_flags || {}).length,
    note: 'These keys are what save_settings takes. They are UI identifiers, not flags: send '
      + '"timeoutMinutes", not "-timeout". A flag the runner owns is refused; pass owned_flags true '
      + 'to list those with the reason for each.',
  };
  if (!cli) out.no_command_line = NO_COMMAND_LINE;
  if (tool.limitation) out.limitation = tool.limitation;
  if (tool.delegates_to) out.delegates_to = tool.delegates_to;
  const selection = registry.target_selection_stores[tool.key];
  if (selection) out.target_selection = selection;
  out.pending_wiring = pendingWiringNote([tool]);
  if (!full && keys.length > 20) {
    out.narrowing = 'This tool has many options. Filter with group or provenance, or read one key '
      + 'in full with option, rather than asking for detail:"full" across all of them.';
  }
  return dropEmpty(out);
}

// The owned-flag view of option_reference. Not a separate action, because it answers the same
// question the option reference answers - what can and cannot be set on this tool - from the other
// side. The reason on each flag is the whole point: it is the difference between "nobody added this"
// and "this was measured to do nothing in the installed build".
function ownedFlagsView(registry, params, full) {
  // group, provenance and option describe OPTIONS and an owned flag has none of the three. Accepting
  // one and quietly ignoring it would be a filter that does nothing, which is the same defect class
  // as a setting nothing reads - and the caller would read the unfiltered list as a filtered one.
  const inapplicable = ['group', 'provenance', 'option'].filter((k) => params[k] !== undefined);
  if (inapplicable.length) {
    return {
      error: `${inapplicable.join(', ')} ${inapplicable.length === 1 ? 'does' : 'do'} not apply when `
        + 'owned_flags is true: an owned flag is a refusal with a reason, not an option, so it '
        + 'carries no group, no provenance and no option key. Drop '
        + `${inapplicable.length === 1 ? 'it' : 'them'} to read the owned flags, or drop owned_flags `
        + 'to filter the options.',
    };
  }
  if (!params.tool) {
    return {
      tools: registry.tools.map((t) => ({
        tool: t.key,
        owned_flag_count: Object.keys(t.owned_flags || {}).length,
        flags: Object.keys(t.owned_flags || {}).sort(),
      })),
      owned_flags_meaning: registry.owned_flags_meaning,
      note: 'Pass tool to read the reason on each. Note that several entries here are not flags at '
        + 'all: a tool with no command line owns VALUES instead, such as crt.sh\'s output=json and '
        + 'the on-prem scanner\'s hardcoded per-IP port concurrency, and the reason says why each is '
        + 'unreachable rather than merely defaulted.',
    };
  }
  const found = findTool(registry, params.tool);
  if (found.error) return { error: found.error };
  const tool = found.tool;
  const owned = tool.owned_flags || {};
  const flags = Object.keys(owned).sort();
  const projected = projectRows(
    flags,
    (f, isFullRow) => compactOwnedFlag(f, owned[f], isFullRow),
    full,
    NARROW_BY_FLAG,
  );
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
      + 'make every save 400 with nothing on screen to explain it. That is why cloud_enum\'s '
      + 'mutationsPreset and bruteListPreset carry no flag at all - -m and -b already belong to '
      + 'cloud_enum_configs.',
  });
}

async function settingsAction(params) {
  const targetId = await resolveTargetId(params);
  if (!targetId) return { error: 'No target_id given and no active target set.' };
  const full = isFull(params);

  // Every tool at once.
  if (!params.tool) {
    const data = await apiGet(`/company-tools/${targetId}/settings`);
    const tools = Array.isArray(data.tools) ? data.tools : [];
    const projected = projectRows(tools, (t, f) => compactSettingsRow(t, f), full, NARROW_BY_TOOL);
    const out = {
      scope_target_id: targetId,
      tools: projected.rows,
      detail: projected.detail,
      downgraded_from_full: projected.downgraded_from_full,
      configured_tools: tools.filter((t) => t.configured_count > 0).map((t) => t.tool),
      note: 'configured_count is how many keys are stored, option_count how many exist. An empty '
        + 'settings object means the tool runs on its own defaults, which its option placeholders '
        + 'describe. Pass tool for one tool\'s values plus the arguments they would compose.',
    };
    // An advisory on a tool with NOTHING configured is not noise, it is the most useful line in the
    // response: the on-prem scanner's own defaults already disagree with each other, and nothing
    // anywhere else says so.
    const advised = tools.filter((t) => t.advisories && Object.keys(t.advisories).length);
    if (advised.length) {
      out.advisories_note = 'An advisory is a setting that IS in effect and does less than it looks '
        + 'like, which is different from inert. Some fire at the DEFAULTS with nothing configured: '
        + `${advised.map((t) => t.tool).join(', ')}.`;
    }
    out.pending_wiring = pendingWiringNote(tools);
    return dropEmpty(out);
  }

  const data = await apiGet(`/company-tools/${targetId}/${params.tool}/settings`);
  const options = data.options || {};
  const owned = data.owned_flags || {};
  const cli = hasCommandLine({ options });

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
    settings_store: data.settings_store,
    settings_store_note: data.settings_store_note,
    // What these settings would put on the command line, shown rather than described. A settings
    // surface that cannot show what it will run is one the caller has to take on trust.
    would_add_args: data.would_add_args || [],
    compose_warnings: data.compose_warnings,
    // Stored but unable to take effect, given the rest of the settings. The answer to "I set the
    // certificate-grab ports and nothing changed": amass intel's -p does nothing without -active.
    inert: data.inert,
    // In effect, and doing something other than what it looks like. Deliberately not the same thing.
    advisories: data.advisories,
    target_selection: data.target_selection,
    limitation: data.limitation,
    delegates_to: data.delegates_to,
    pending_wiring: data.pending_wiring,
  };
  if (!cli && Object.keys(options).length) out.no_command_line = NO_COMMAND_LINE;
  if (full) {
    // The vocabulary for the keys that ARE SET, rather than all of them. A caller reading settings
    // wants to know what the stored values do; the whole vocabulary is what option_reference is for,
    // and repeating katana's 46 options here would spend the entire budget describing keys nobody
    // configured.
    const set = Object.keys(data.settings || {}).filter((k) => options[k]).sort();
    const projected = projectRows(
      set,
      (k, f) => companyOption(k, options[k], f, cli),
      true,
      NARROW_BY_OPTION,
    );
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
    out.composes_nothing = 'These settings add no command-line arguments. That is EXPECTED for a '
      + 'tool with no command line, and for framework-level switches on a tool that has one. '
      + 'Anything else means the values were dropped, and compose_warnings and inert say which.';
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
    const data = await apiPost(`/company-tools/${targetId}/${params.tool}/settings`, {
      settings: params.settings,
      replace: params.replace === true,
    });
    const out = {
      saved: data.saved === true,
      scope_target_id: targetId,
      tool: data.tool || params.tool,
      settings: data.settings,
      settings_store: data.settings_store,
      settings_store_note: data.settings_store_note,
      would_add_args: data.would_add_args || [],
      compose_warnings: data.compose_warnings,
      inert: data.inert,
      inert_warning: data.inert_warning,
      // Saved, in effect, and doing less than it looks like. Reported at the moment of saving
      // because that is the only point at which it is useful.
      advisories: data.advisories,
      advisory_warning: data.advisory_warning,
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
      note: 'Nothing was stored. The refusal names what was wrong: the whole point of refusing '
        + 'rather than storing is that a setting nothing reads, or one the runner overwrites, '
        + 'changes nothing while reading as configured.',
    });
  }
}

module.exports = {
  manageCompanyToolsSchema,
  manageCompanyTools,
  // Exported for tests: these are the pure projections, and the shape they produce is what decides
  // whether a listing fits the output cap.
  companyOption,
  companyTool,
  compactSettingsRow,
  hasCommandLine,
  settingsStoreFor,
  ACTIONS,
  NO_COMMAND_LINE,
  REFUSAL_HINTS,
  ROW_BUDGET,
};
