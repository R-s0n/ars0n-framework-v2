const { z } = require('zod');
const { apiGet, apiPost } = require('../api');
const { resolveVectorIdsByLabel } = require('./attackvectors');
const reflection = require('../utils/reflection');

// Which attack vectors each vector-testing scanner runs against, and the control to change it.
//
// This is the per-vector twin of manage_param_enum. paramenum decides which ENDPOINTS the
// hidden-parameter tools brute-force; this decides which consolidated ATTACK VECTORS each of the
// twelve sections' scanners is pointed at. Running the scanners was already reachable through
// manage_xss and its eleven siblings, and eligibility already reported a count. What was missing was
// the operator's half of that number: an agent could see that Dalfox would send to 78 vectors but
// had no way to see which 78, and no way to narrow or restore the list.
//
// THE REASON THIS FILE EXISTS AT ALL IS THAT THERE ARE TWO COUNTS AND THEY ARE NOT THE SAME NUMBER.
// selected is the operator's choice; eligible is what the scan actually sends. On the reference
// target Dalfox is selected for 215 vectors and will send to 78. A surface that reports one number
// lets someone believe a scan covered 215 vectors when 137 of them were never touched. Every
// description below is written to stop an agent collapsing the two when it summarises coverage.
//
// SELECTION IS STORED SPARSELY, AS DESELECTIONS ONLY. Absence of a row means selected, so the
// default is everything and a newly consolidated vector is picked up by the next scan without
// anyone opting it in. Selecting a vector DELETES its row rather than storing enabled=true, so
// there is exactly one representation of "on" and no way for two of them to disagree.

// The twelve sections and the scanners each one owns, mirroring the registry in vectortools.js and
// the category loop in server/main.go.
//
// Kept here so the pairing can be checked BEFORE the request goes out. The server cannot do this
// check: its handler resolves the tool key from a global registry, so a category that is registered
// but does not own the named tool answers 200 with the right data from the wrong URL. Measured:
// GET /sqli/{target}/dalfox/selection returns Dalfox's selection with HTTP 200. A wrong category is
// therefore not reliably a visible error, which is exactly why it is taken as an argument here
// rather than guessed from the tool name.
const CATEGORY_TOOLS = {
  'xss': ['dalfox', 'domdig', 'xssfuzz'],
  'sqli': ['sqlmap', 'ghauri', 'sqlidetector'],
  'cmdi': ['commix', 'sstimap', 'tinja'],
  'redirect-ssrf': ['nuclei-dast', 'recollapse', 'ssrfmap'],
  'lfi': ['lfimap', 'lfihunt'],
  'cache': ['wcvs', 'cacheboom'],
  'smuggling': ['smugglex', 'http2smugl'],
  'access-bypass': ['nomore403', 'forbidden'],
  'graphql': ['graphql-cop', 'clairvoyance', 'graphw00f'],
  'sensitive-leak': ['snallygaster', 'mantra', 'trufflehog'],
  'exposed-git': ['git-dumper', 'gittools'],
  'misc': ['upload-bypass', 'jwt-tool', 'pphack'],
};

const CATEGORIES = Object.keys(CATEGORY_TOOLS);
const ALL_TOOLS = [...new Set(Object.values(CATEGORY_TOOLS).flat())];

const manageVectorSelectionSchema = z.object({
  action: z.enum(['list', 'select', 'deselect', 'select_all', 'deselect_all', 'select_only']).describe(
    'select_only: make the selection EXACTLY the set you name, for every tool named, in one call. ' +
    'Takes vector_ids, or a grade, or a reflection_status. It deselects everything and then selects ' +
    'the resolved set, so it is the action behind "scan only the vectors carrying the XSS label". ' +
    'It is not a filter and it is not additive: anything outside the set is switched OFF for that ' +
    'tool and stays off until you select it again, which is the point and is also the thing to ' +
    'remember when a later sweep of that tool reads as suspiciously clean. ' +
    'list: every attack vector this tool has, each with its method, URL, insertion point, ' +
    'parameters, whether it is selected, whether it is eligible, and when it is not eligible the ' +
    'reason. Also returns the four counts that matter, described under target_id below: total, ' +
    'selected, eligible and selected_but_unreachable. READ THIS BEFORE RUNNING A SCAN and before ' +
    'reporting coverage to anyone, because eligible is the only one of the four that describes what ' +
    'was actually sent. ' +
    'select / deselect: switch specific vectors on or off for ONE tool, by vector_ids. Deselecting ' +
    'is the only one of the two that can ever reduce what a scan sends. Selecting can only restore ' +
    'a vector you previously switched off: it cannot make a vector eligible that the tool is unable ' +
    'to reach, because those two are different mechanisms and only the first one lives here. ' +
    'select_all: clear every deselection for this tool, returning it to the default of all vectors. ' +
    'deselect_all: switch off every vector this tool has, which sets the scan to zero. A run after ' +
    'this sends nothing and completes successfully, so it will look like a clean result rather than ' +
    'like a scan that never happened. ' +
    'Both bulk actions resolve against the vectors THIS tool actually has, from the same row source ' +
    'the scan reads, so they can never write rows for vectors that are not on the list you read.'),

  target_id: z.string().optional().describe(
    'Scope target UUID. Defaults to the active target, as in manage_xss and its siblings. ' +
    'THE FOUR COUNTS THE list ACTION RETURNS FOR THIS TARGET, AND WHAT EACH ONE MEANS, because ' +
    'confusing them is the single most likely way to misreport a scan: ' +
    'total is every consolidated attack vector in this section for this target. ' +
    'selected is what the operator chose. Stored sparsely as deselections only, so absence means ' +
    'selected and the default is ALL of them; a vector consolidated after you last looked is ' +
    'selected without anyone opting it in. ' +
    'eligible is what the scan WILL ACTUALLY SEND. It is always less than or equal to selected, ' +
    'and it is smaller whenever the tool cannot reach an insertion point you selected or a setting ' +
    'leaves that point switched off. ' +
    'selected_but_unreachable is the gap between the two, and it is the number to quote when ' +
    'someone asks what a scan missed. ' +
    'Measured on the reference target: Dalfox reports total 215, selected 215, eligible 78, ' +
    'selected_but_unreachable 137. Saying that scan covered 215 vectors overstates it by 137. ' +
    'Say "78 of 215", or say both numbers, but never report selected as coverage.'),

  category: z.enum(CATEGORIES).describe(
    'Which vector-testing section the tool belongs to. REQUIRED, and deliberately not inferred from ' +
    'the tool name, because the route is /{category}/{target_id}/{tool}/selection and a wrong ' +
    'category fails in two different ways, one of them silent. ' +
    'A category outside these twelve is not a registered route at all, so it 404s at the router ' +
    'with a bare "404 page not found" before any handler runs, which reads like the feature does ' +
    'not exist rather than like a bad guess. ' +
    'Worse, a category that IS one of the twelve but does not own the named tool returns HTTP 200: ' +
    'the handler resolves the tool from a global registry and never checks that it belongs to the ' +
    'prefix it was reached through. GET /sqli/{target}/dalfox/selection answers 200 with Dalfox ' +
    'data. So guessing wrong does not reliably announce itself. This tool checks the pairing ' +
    'locally and refuses rather than letting a mismatched route look like it worked. ' +
    'The tools each section owns: ' +
    Object.entries(CATEGORY_TOOLS).map(([c, t]) => `${c}: ${t.join(', ')}`).join('. ') + '.'),

  tool: z.enum(ALL_TOOLS).optional().describe(
    'Which scanner the selection belongs to. SELECTION IS PER TOOL: deselecting a vector for sqlmap ' +
    'leaves Ghauri and SQLiDetector still scanning it, and there is no global off switch here. ' +
    'Required for every action unless you pass tools instead, because there is no such thing as ' +
    'the selection for a section. ' +
    'Must be a tool the given category owns; a name that exists in a different section is rejected ' +
    'here rather than sent, since the server would answer 200 for it.'),

  // Selection is per tool and the operator's unit of work is a SECTION ("all three XSS tools"). One
  // call per tool is three chances to point two tools at one set and the third at another, and a
  // mismatched selection across a section is invisible afterwards: each tool reports its own
  // coverage honestly and nothing compares them.
  tools: z.array(z.enum(ALL_TOOLS)).optional().describe(
    'Apply the action to several scanners in one call, e.g. all three XSS tools. Every name must ' +
    'belong to the given category. Use this instead of tool when you are setting up a section, so ' +
    'the three tools cannot end up pointed at three different sets. ' +
    'On list with more than one tool the per-vector rows are left out and only the coverage counts ' +
    'come back, because the same 200 vectors repeated per tool is what pushes a listing past the ' +
    'MCP output cap. Ask for one tool when you want the rows.'),

  // --- resolving a selection from the reflection probe's label ----------------------------------
  grade: z.union([z.string(), z.array(z.string())]).optional().describe(
    'select, deselect and select_only: resolve the vector ids from the XSS label the reflection ' +
    'probe put on them, instead of passing ids. ' +
    `One or more of ${reflection.GRADES.join(', ')}. ` +
    'xss_candidate_high is reflected raw into an HTML response AT AN INPUT AN ATTACKER CAN PUT ' +
    'IN A LINK (query, path, fragment). It is the priority set. ' +
    'xss_candidate_chain is the same reflection at a cookie, header or body input: it renders, and ' +
    'only the victim\'s own browser sets it, so it is self-XSS until a chain is named. Keep ' +
    'scanning these, since those chains are what turn them into findings. ' +
    'xss_candidate_low is reflected raw into a NON-HTML response: a real reflection with no way to ' +
    'render it (measured: /api/v1/echo returns <svg onload=alert(1)> byte for byte, pinned to ' +
    'application/json). Selecting low as well as high is a reasonable choice for a cheap tool and a ' +
    'waste of a 7-minutes-per-vector one. ' +
    'xss_unknown is blocked, error, needs_browser or not_probed, and it is the bucket that must ' +
    'not be read as safe: a narrowing that excludes it leaves those vectors UNTESTED, not clean. ' +
    'THE GRADE NOW RANKS DELIVERY AS WELL AS RENDERABILITY: a cookie or header vector can no ' +
    'longer come back xss_candidate_high, it comes back xss_candidate_chain, which is the ' +
    'weaponisability rule expressed as a label. Ordering a run on the grade is therefore the same ' +
    'decision the rule asks for. It is still not a licence to DESELECT chain rows: the chain is ' +
    'what makes them findings, and you cannot find a chain for a reflection nobody measured.'),
  reflection_status: z.union([z.string(), z.array(z.string())]).optional().describe(
    'select, deselect and select_only: resolve the vector ids from the probe status instead of the ' +
    `grade. One or more of ${reflection.STATUSES.join(', ')}. ` +
    'Use this to point a tool at what is NOT known rather than at what is: selecting blocked and ' +
    'error is how you re-cover the inputs a WAF ate, and selecting needs_browser is the domdig ' +
    'list, since a fragment never reaches the server and no HTTP tool can answer for it.'),

  vector_ids: z.array(z.string()).optional().describe(
    'select / deselect: the attack vector UUIDs to switch, as returned in vectors[].vector_id by ' +
    'the list action. Ignored by select_all and deselect_all, which cover every vector the tool ' +
    'has. Note that deselecting a vector that is already ineligible is counted in updated and does ' +
    'move selected, but does NOT move eligible, because that vector was never going to be sent. ' +
    'Measured: deselecting 3 body vectors Dalfox does not send returned updated 3, now_selected ' +
    '212, now_eligible still 78. Deselecting 3 eligible vectors instead returned now_selected 212 ' +
    'and now_eligible 75. Both are correct; only the second one changed what the scan will do.'),
});

async function resolveTargetId(params) {
  if (params.target_id) return params.target_id;
  const targets = await apiGet('/scopetarget/read');
  const active = (Array.isArray(targets) ? targets : []).find((t) => t.active);
  return active ? active.id : null;
}

// The coverage block, one tool's worth. Pulled out of the list action because select_only and the
// bulk actions report it too now: a selection change whose answer does not say what the scan will
// SEND leaves the caller to guess, and the guess is always `selected`.
function coverageOf(data) {
  return {
    total: data.total,
    selected: data.selected,
    eligible: data.eligible,
    selected_but_unreachable: data.selected_but_unreachable,
    what_a_scan_sends: data.eligible,
    reading: `${data.eligible} of ${data.total} vectors will be sent. `
      + `${data.selected} are selected, so ${data.selected_but_unreachable} selected vectors `
      + `will NOT be tested and are unknown rather than clean.`,
  };
}

async function manageVectorSelection(params) {
  const { category } = params;

  if (!category) return { error: `category is required. One of: ${CATEGORIES.join(', ')}.` };

  // Refuse a mismatched pair rather than sending it. The server would answer 200 from the wrong
  // prefix, so this is the only place the mistake can be caught.
  const owned = CATEGORY_TOOLS[category];
  if (!owned) {
    return { error: `no section called ${category}. One of: ${CATEGORIES.join(', ')}.` };
  }

  // tools wins over tool when both are given, and the union is NOT taken. A caller that passed both
  // meant the list; silently adding the singleton would write a selection for a tool the caller did
  // not name, and a selection written by accident is invisible at run time.
  const wanted = Array.isArray(params.tools) && params.tools.length > 0
    ? [...new Set(params.tools)]
    : (params.tool ? [params.tool] : []);
  if (wanted.length === 0) {
    return {
      error: 'tool or tools is required. Selection is per tool, not per section: there is no '
        + `selection for ${category} as a whole. Pass tools: [${owned.map((t) => `"${t}"`).join(', ')}] `
        + 'to set all of them in one call.',
    };
  }
  const strangers = wanted.filter((t) => !owned.includes(t));
  if (strangers.length > 0) {
    const homes = strangers.map((t) => {
      const home = CATEGORIES.find((c) => CATEGORY_TOOLS[c].includes(t));
      return home ? `${t} belongs to category "${home}"` : `${t} is in no section`;
    });
    return {
      error: `${strangers.join(', ')} is not a ${category} scanner. ${category} has: `
        + `${owned.join(', ')}. ${homes.join('. ')}.`
        + ' Sending this pair anyway would return HTTP 200 with data read through the wrong route,'
        + ' so it is refused here.',
    };
  }

  const targetId = await resolveTargetId(params);
  if (!targetId) return { error: 'No target_id given and no active target set.' };

  const pathFor = (t) => `/${category}/${targetId}/${encodeURIComponent(t)}/selection`;

  // The ids are resolved ONCE and reused for every tool, which is the whole reason tools is a list.
  // Resolving per tool would mean N reads of the same corpus and, if the probe were still running,
  // N different answers: three scanners in one section pointed at three different sets, with
  // nothing afterwards that compares them.
  const byLabel = params.grade !== undefined || params.reflection_status !== undefined;
  let resolved = null;
  if (byLabel) {
    if (!['select', 'deselect', 'select_only'].includes(params.action)) {
      return {
        error: 'grade and reflection_status only resolve ids for select, deselect and select_only. '
          + `${params.action} does not take a vector set.`,
      };
    }
    if (params.vector_ids && params.vector_ids.length > 0) {
      return {
        error: 'pass vector_ids OR a label (grade / reflection_status), not both. Two id sources '
          + 'would have to be merged or one ignored, and either choice is silent.',
      };
    }
    resolved = await resolveVectorIdsByLabel(targetId, params);
    if (resolved.error) return resolved;
  }

  const ids = resolved ? resolved.vector_ids : params.vector_ids;

  switch (params.action) {
    case 'list': {
      const results = [];
      for (const t of wanted) results.push({ tool: t, data: await apiGet(pathFor(t)) });

      // One tool: the rows, as before. Several: the counts only. The same 200 vector rows repeated
      // per tool is exactly the multiplier that put the attack vector listing over the MCP output
      // cap at forty rows, and the question a caller asks of three tools at once is "are they
      // pointed at the same thing", which is a count.
      if (results.length === 1) {
        const { data } = results[0];
        return {
          ...data,
          // The API's own scan_will_run reads "78 of 215 vectors", whose denominator is total rather
          // than selected: after deselecting 3 eligible vectors it reads "75 of 215" while selected
          // is 212. Spelled out here so the two numbers cannot be read off that string wrongly.
          coverage: coverageOf(data),
          note: 'eligible is what gets sent, selected is what was chosen. Report eligible as coverage. '
            + 'In vectors[], deselected_by_operator:true means you switched it off and select will '
            + 'restore it; deselected_by_operator:false with eligible:false means the tool itself '
            + 'cannot reach that insertion point or a setting has it off, which this action cannot '
            + 'change. Fix those through the section tool\'s save_settings, or use a tool that reaches '
            + 'the point. The reason field on each vector says which case it is.',
        };
      }

      const coverage = {};
      for (const { tool: t, data } of results) coverage[t] = coverageOf(data);
      return {
        tools: wanted,
        coverage,
        // Named rather than left to be spotted. Three tools in a section are normally set up
        // together, so a difference in `selected` between them is nearly always a selection written
        // by one call and not the others, and that is not visible in any single tool's own report.
        selection_matches_across_tools:
          new Set(results.map(({ data }) => data.selected)).size === 1,
        what_a_scan_sends: results.map(({ data }) => data.eligible),
        note: 'Per-vector rows are omitted because more than one tool was asked for. Ask for one '
          + 'tool to get them. A false selection_matches_across_tools means these scanners are '
          + 'pointed at different vector sets, which no single tool\'s own coverage can show you.',
      };
    }

    case 'select':
    case 'deselect': {
      if (!ids || !ids.length) {
        if (resolved) {
          return {
            error: `the label resolved to 0 vectors, so ${params.action} would change nothing.`,
            resolution: resolved,
            fix: 'Check the census with manage_attack_vectors action "reflection". A label that '
              + 'matches nothing usually means the probe has not run over those insertion points '
              + 'yet, not that nothing reflects.',
          };
        }
        return {
          error: `${params.action} needs vector_ids, or a grade / reflection_status to resolve them `
            + `from. Use list to get ids, or ${params.action}_all to cover every vector.`,
        };
      }
      const enabled = params.action === 'select';
      const results = {};
      for (const t of wanted) {
        results[t] = await apiPost(pathFor(t), { vector_ids: ids, enabled });
      }
      return {
        tools: wanted,
        vectors_in_set: ids.length,
        resolution: resolved || undefined,
        results,
        note: enabled
          ? 'select can only restore a vector you previously switched off. It cannot make a vector '
            + 'eligible that the tool cannot reach, so read now_eligible and not now_selected.'
          : 'Deselecting an already ineligible vector counts in updated and moves selected but not '
            + 'eligible, because that vector was never going to be sent.',
      };
    }

    // The action behind "scan all attack vectors with the XSS label". Deselect everything, then
    // select the resolved set, per tool, in that order.
    //
    // ORDER MATTERS AND SO DOES FAILING CLOSED. deselect_all sets the scan to zero, and a run after
    // a zero selection sends nothing and completes successfully, which reads as a clean result
    // rather than as a scan that never happened. So an empty set is refused BEFORE the first write
    // rather than leaving a tool cleared with nothing switched back on.
    case 'select_only': {
      if (!ids || !ids.length) {
        return {
          error: 'select_only needs a non-empty set: vector_ids, or a grade / reflection_status '
            + 'that resolves to at least one vector.',
          resolution: resolved || undefined,
          fix: 'Refused before anything was written. Clearing the selection and then selecting '
            + 'nothing would leave these tools sending zero vectors, and a zero-vector run '
            + 'completes successfully and reads as clean. Use deselect_all if switching the scan '
            + 'off is what you actually want.',
        };
      }
      const results = {};
      for (const t of wanted) {
        const cleared = await apiPost(pathFor(t), { all: true, enabled: false });
        const selected = await apiPost(pathFor(t), { vector_ids: ids, enabled: true });
        results[t] = {
          cleared_updated: cleared.updated,
          selected_updated: selected.updated,
          now_selected: selected.now_selected,
          now_eligible: selected.now_eligible,
          // The gap, per tool, because it is the number that is about to be misreported. The set
          // was chosen by a label that says nothing about which tool can reach which insertion
          // point, so a tool silently drops the part of it that it cannot send.
          selected_but_unreachable: typeof selected.now_selected === 'number'
            && typeof selected.now_eligible === 'number'
            ? selected.now_selected - selected.now_eligible
            : undefined,
        };
      }
      return {
        tools: wanted,
        vectors_in_set: ids.length,
        resolution: resolved || undefined,
        results,
        note: 'The selection for these tools is now EXACTLY this set. Everything else is switched '
          + 'off and stays off until you select it again or call select_all, so a later sweep of '
          + 'one of these tools is scanning this set and not the corpus. '
          + 'now_eligible is what a run will send and it can be smaller than the set, because the '
          + 'label ranks how the response reflects, not which tool can reach the insertion point.',
        untested_is_not_clean: 'Everything outside this set is now UNTESTED by these tools. That '
          + 'includes every vector the probe could not answer for: blocked, error, not_probed, and '
          + 'needs_browser, which is every fragment. Narrowing is a budget decision, not a verdict.',
      };
    }

    case 'select_all':
    case 'deselect_all': {
      const results = {};
      for (const t of wanted) {
        results[t] = await apiPost(pathFor(t), {
          all: true,
          enabled: params.action === 'select_all',
        });
      }
      return {
        tools: wanted,
        results,
        note: params.action === 'deselect_all'
          ? 'These tools are now set to zero vectors. A run afterwards sends nothing and completes '
            + 'successfully, so it reads as a clean result rather than as a scan that never ran.'
          : 'Every deselection is cleared, so these tools are back to the default of all vectors. '
            + 'eligible is still what a run sends.',
      };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

module.exports = { manageVectorSelectionSchema, manageVectorSelection, CATEGORY_TOOLS };
