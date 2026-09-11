const { z } = require('zod');
const { apiGet, apiPost } = require('../api');

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
  action: z.enum(['list', 'select', 'deselect', 'select_all', 'deselect_all']).describe(
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

  tool: z.enum(ALL_TOOLS).describe(
    'Which scanner the selection belongs to. SELECTION IS PER TOOL: deselecting a vector for sqlmap ' +
    'leaves Ghauri and SQLiDetector still scanning it, and there is no global off switch here. ' +
    'Required for every action, because there is no such thing as the selection for a section. ' +
    'Must be a tool the given category owns; a name that exists in a different section is rejected ' +
    'here rather than sent, since the server would answer 200 for it.'),

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

async function manageVectorSelection(params) {
  const { category, tool } = params;

  if (!category) return { error: `category is required. One of: ${CATEGORIES.join(', ')}.` };
  if (!tool) return { error: 'tool is required. Selection is per tool, not per section.' };

  // Refuse a mismatched pair rather than sending it. The server would answer 200 from the wrong
  // prefix, so this is the only place the mistake can be caught.
  const owned = CATEGORY_TOOLS[category];
  if (!owned) {
    return { error: `no section called ${category}. One of: ${CATEGORIES.join(', ')}.` };
  }
  if (!owned.includes(tool)) {
    const home = CATEGORIES.find((c) => CATEGORY_TOOLS[c].includes(tool));
    return {
      error: `${tool} is not a ${category} scanner. ${category} has: ${owned.join(', ')}.`
        + (home ? ` ${tool} belongs to category "${home}".` : '')
        + ' Sending this pair anyway would return HTTP 200 with data read through the wrong route,'
        + ' so it is refused here.',
    };
  }

  const targetId = await resolveTargetId(params);
  if (!targetId) return { error: 'No target_id given and no active target set.' };

  const path = `/${category}/${targetId}/${encodeURIComponent(tool)}/selection`;

  switch (params.action) {
    case 'list': {
      const data = await apiGet(path);
      return {
        ...data,
        // The API's own scan_will_run reads "78 of 215 vectors", whose denominator is total rather
        // than selected: after deselecting 3 eligible vectors it reads "75 of 215" while selected
        // is 212. Spelled out here so the two numbers cannot be read off that string wrongly.
        coverage: {
          total: data.total,
          selected: data.selected,
          eligible: data.eligible,
          selected_but_unreachable: data.selected_but_unreachable,
          what_a_scan_sends: data.eligible,
          reading: `${data.eligible} of ${data.total} vectors will be sent. `
            + `${data.selected} are selected, so ${data.selected_but_unreachable} selected vectors `
            + `will NOT be tested and are unknown rather than clean.`,
        },
        note: 'eligible is what gets sent, selected is what was chosen. Report eligible as coverage. '
          + 'In vectors[], deselected_by_operator:true means you switched it off and select will '
          + 'restore it; deselected_by_operator:false with eligible:false means the tool itself '
          + 'cannot reach that insertion point or a setting has it off, which this action cannot '
          + 'change. Fix those through the section tool\'s save_settings, or use a tool that reaches '
          + 'the point. The reason field on each vector says which case it is.',
      };
    }

    case 'select':
    case 'deselect': {
      if (!params.vector_ids || !params.vector_ids.length) {
        return { error: `${params.action} needs vector_ids. Use list to get them, or ${params.action}_all to cover every vector.` };
      }
      return apiPost(path, {
        vector_ids: params.vector_ids,
        enabled: params.action === 'select',
      });
    }

    case 'select_all':
    case 'deselect_all':
      return apiPost(path, {
        all: true,
        enabled: params.action === 'select_all',
      });

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

module.exports = { manageVectorSelectionSchema, manageVectorSelection, CATEGORY_TOOLS };
