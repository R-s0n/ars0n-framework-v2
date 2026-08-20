const { z } = require('zod');
const { apiGet, apiPost } = require('../api');

// The XSS scanners: what each one can actually reach, how it is configured, and what a run found.
//
// SETTINGS ARE THE SAME STORE THE UI WRITES. A value changed here appears in the Config modal
// immediately and the other way round, because there is one copy on the server rather than a UI copy
// and an agent copy. That is also why there is no local list of flags in this file: option_reference
// returns the server's own vocabulary, which is the same map the command composer reads.
//
// THE ONE THING TO UNDERSTAND BEFORE RUNNING ANYTHING: only Dalfox can reach every insertion point.
// domdig fuzzes the query string and the URL hash; its cookie and header flags set STATIC values for
// authentication and it navigates rather than issuing a POST. xssFuzz calls requests.get and nothing
// else. Handed a header, body, cookie or path vector, either one scans the query string, finds
// nothing and exits 0, so "no findings" from them is not evidence about those vectors. eligibility
// reports how many of the target's vectors each tool can test, and results lists the untested ones
// with the reason, which is why both exist.

const buildSchema = (tools) => z.object({
  action: z.enum(['eligibility', 'option_reference', 'settings', 'save_settings',
    'section_settings', 'save_section_settings',
    'run', 'status', 'results', 'triage']).describe(
    'eligibility: how many of this target\'s attack vectors each tool can actually test, which ' +
    'insertion points it can reach, and which settings are currently blinding it. START HERE, ' +
    'because two of the three tools cover only query parameters and report clean for everything ' +
    'else. ' +
    'option_reference: every setting a tool honours, with its flag, type and what the tool does ' +
    'when it is not set. This is the server\'s own vocabulary, so it never drifts from what a scan ' +
    'reads. ' +
    'settings: the stored settings for one tool on this target. ' +
    'save_settings: MERGE settings into the store. Send a key as null to remove it. Pass ' +
    'replace: true to make the payload authoritative. Refused if it names a flag the runner owns. ' +
    'section_settings: the settings that belong to the SECTION rather than to any one tool, which ' +
    'is where the out-of-band webhook pair lives. A tool that requires one reports every vector as ' +
    'skipped until it is set, so check here first when eligibility is 0 of everything. ' +
    'save_section_settings: MERGE into that section store. Nuclei DAST and REcollapse need BOTH ' +
    'listeningWebhookURL (where the target calls out to) and resultsWebhookURL (the API the runner ' +
    'reads the hits back from); one without the other counts as unconfigured. ' +
    'run: scan every eligible attack vector with one tool, one vector at a time. ' +
    'status: how a run is going, including which vector of how many. ' +
    'results: the findings AND the vectors that were never sent, with the reason for each. ' +
    'triage: mark one finding new, interesting or dismissed.'),
  target_id: z.string().optional().describe('Scope target id. Defaults to the active target.'),
  tool: z.enum(tools).optional().describe(
    'Which scanner. Required for everything except eligibility, which covers all of them when omitted.'),
  settings: z.record(z.any()).optional().describe(
    'Settings to store, keyed by the option keys option_reference lists. A null value removes a key.'),
  replace: z.boolean().optional().describe(
    'Make the settings payload authoritative rather than merging it into what is stored.'),
  finding_id: z.string().optional().describe('Finding to triage.'),
  triage: z.enum(['new', 'interesting', 'dismissed']).optional(),
});



async function resolveTargetId(params) {
  if (params.target_id) return params.target_id;
  const targets = await apiGet('/scopetarget/read');
  const active = (Array.isArray(targets) ? targets : []).find((t) => t.active);
  return active ? active.id : null;
}

async function manageVectorTools(category, tools, params) {
  const targetId = await resolveTargetId(params);
  if (!targetId && params.action !== 'option_reference' && params.action !== 'triage') {
    return { error: 'No target_id given and no active target set.' };
  }

  switch (params.action) {
    case 'option_reference': {
      const registry = await apiGet(`/${category}/tools`);
      const tools = (registry.tools || []).filter((t) => !params.tool || t.key === params.tool);
      return {
        tools: tools.map((t) => ({
          tool: t.key,
          name: t.name,
          insertion_points_it_can_reach: t.insertion_points,
          limitation: t.limitation || undefined,
          groups: t.groups,
          options: t.options,
          // Named so an agent does not waste a round trip trying to set one and getting a 400.
          flags_the_framework_sets: t.owned_flags,
        })),
      };
    }

    case 'eligibility': {
      const wanted = params.tool ? [params.tool] : tools;
      const reports = await Promise.all(
        wanted.map((tool) => apiGet(`/${category}/${targetId}/${tool}/status`).catch(() => null)),
      );
      return {
        tools: reports.filter(Boolean).map((r) => ({
          tool: r.tool,
          eligible: r.eligibility?.eligible ?? 0,
          total: r.eligibility?.total ?? 0,
          can_reach: r.eligibility?.reachable || [],
          cannot_reach: r.eligibility?.unreachable || [],
          skipped_by_insertion_point: r.eligibility?.skipped_by_point || {},
          blinded_by_current_settings: r.eligibility?.blinded || {},
          limitation: r.eligibility?.limitation || undefined,
        })),
        note: 'cannot_reach vectors are never sent. A tool reporting no findings says nothing '
          + 'about them.',
      };
    }

    case 'settings': {
      if (!params.tool) return { error: 'tool is required for settings.' };
      return apiGet(`/${category}/${targetId}/${params.tool}/settings`);
    }

    case 'save_settings': {
      if (!params.tool) return { error: 'tool is required for save_settings.' };
      if (!params.settings) return { error: 'settings is required for save_settings.' };
      return apiPost(`/${category}/${targetId}/${params.tool}/settings`, {
        settings: params.settings,
        replace: params.replace === true,
      });
    }

    // Section settings belong to the SECTION, not to a tool, so they take no tool argument. They
    // were unreachable from here until now: nuclei-dast and REcollapse both declare
    // RequiresSectionSetting: "listeningWebhookURL", so with no way to set it every vector was
    // reported skipped and eligibility read 0 of 53 with nothing an agent could do about it.
    case 'section_settings':
      return apiGet(`/${category}/${targetId}/section-settings`);

    case 'save_section_settings': {
      if (!params.settings) return { error: 'settings is required for save_section_settings.' };
      // The server REPLACES this store wholesale, so a merge has to happen here or setting one half
      // of the webhook pair would silently delete the other half.
      let merged = params.settings;
      if (params.replace !== true) {
        const current = await apiGet(`/${category}/${targetId}/section-settings`).catch(() => null);
        merged = { ...((current && current.settings) || {}), ...params.settings };
      }
      for (const [key, value] of Object.entries(merged)) {
        if (value === null) delete merged[key];
      }
      return apiPost(`/${category}/${targetId}/section-settings`, { settings: merged });
    }

    case 'run': {
      if (!params.tool) return { error: 'tool is required for run.' };
      return apiPost(`/${category}/${targetId}/${params.tool}/scan`, {});
    }

    case 'status': {
      if (!params.tool) return { error: 'tool is required for status.' };
      return apiGet(`/${category}/${targetId}/${params.tool}/status`);
    }

    case 'results': {
      if (!params.tool) return { error: 'tool is required for results.' };
      const data = await apiGet(`/${category}/${targetId}/${params.tool}/results`);
      return {
        ...data,
        note: data.skipped && data.skipped.length
          ? `${data.skipped.length} attack vectors were never sent to ${params.tool}. They are `
            + 'unknown, not clean. Each carries the reason in skipped[].reason.'
          : undefined,
      };
    }

    case 'triage': {
      if (!params.finding_id) return { error: 'finding_id is required for triage.' };
      if (!params.triage) return { error: 'triage is required.' };
      return apiPost(`/${category}/finding/${params.finding_id}/triage`, { triage: params.triage });
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// One pair per section. The schema differs only in which tool names are valid, and the handler is
// the same code, because the API routes are the same shape under a different prefix.
const XSS_TOOLS = ['dalfox', 'domdig', 'xssfuzz'];
const SQLI_TOOLS = ['sqlmap', 'ghauri', 'sqlidetector'];
const CACHE_TOOLS = ['wcvs', 'cacheboom'];
const CMDI_TOOLS = ['commix', 'sstimap', 'tinja'];
const REDIRECT_TOOLS = ['nuclei-dast', 'recollapse', 'ssrfmap'];
const LFI_TOOLS = ['lfimap', 'lfihunt'];
const SMUGGLING_TOOLS = ['smugglex', 'http2smugl'];
const BYPASS_TOOLS = ['nomore403', 'forbidden'];
const GRAPHQL_TOOLS = ['graphql-cop', 'clairvoyance', 'graphw00f'];
const LEAK_TOOLS = ['snallygaster', 'mantra', 'trufflehog'];
const GIT_TOOLS = ['git-dumper', 'gittools'];
const MISC_TOOLS = ['upload-bypass', 'jwt-tool', 'pphack'];

const manageXSSSchema = buildSchema(XSS_TOOLS);
const manageSQLiSchema = buildSchema(SQLI_TOOLS);
const manageCacheSchema = buildSchema(CACHE_TOOLS);
const manageCmdiSchema = buildSchema(CMDI_TOOLS);
const manageRedirectSchema = buildSchema(REDIRECT_TOOLS);
const manageLfiSchema = buildSchema(LFI_TOOLS);
const manageSmugglingSchema = buildSchema(SMUGGLING_TOOLS);
const manageBypassSchema = buildSchema(BYPASS_TOOLS);
const manageGraphqlSchema = buildSchema(GRAPHQL_TOOLS);
const manageLeakSchema = buildSchema(LEAK_TOOLS);
const manageGitSchema = buildSchema(GIT_TOOLS);
const manageMiscSchema = buildSchema(MISC_TOOLS);

const manageXSS = (params) => manageVectorTools('xss', XSS_TOOLS, params);
const manageSQLi = (params) => manageVectorTools('sqli', SQLI_TOOLS, params);
const manageCache = (params) => manageVectorTools('cache', CACHE_TOOLS, params);
const manageCmdi = (params) => manageVectorTools('cmdi', CMDI_TOOLS, params);
const manageRedirect = (params) => manageVectorTools('redirect-ssrf', REDIRECT_TOOLS, params);
const manageLfi = (params) => manageVectorTools('lfi', LFI_TOOLS, params);
const manageSmuggling = (params) => manageVectorTools('smuggling', SMUGGLING_TOOLS, params);
const manageBypass = (params) => manageVectorTools('access-bypass', BYPASS_TOOLS, params);
const manageGraphql = (params) => manageVectorTools('graphql', GRAPHQL_TOOLS, params);
const manageLeak = (params) => manageVectorTools('sensitive-leak', LEAK_TOOLS, params);
const manageGit = (params) => manageVectorTools('exposed-git', GIT_TOOLS, params);
const manageMisc = (params) => manageVectorTools('misc', MISC_TOOLS, params);

module.exports = {
  manageXSSSchema, manageXSS,
  manageSQLiSchema, manageSQLi,
  manageCacheSchema, manageCache,
  manageCmdiSchema, manageCmdi,
  manageRedirectSchema, manageRedirect,
  manageLfiSchema, manageLfi,
  manageSmugglingSchema, manageSmuggling,
  manageBypassSchema, manageBypass,
  manageGraphqlSchema, manageGraphql,
  manageLeakSchema, manageLeak,
  manageGitSchema, manageGit,
  manageMiscSchema, manageMisc,
};
