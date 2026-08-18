const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiDelete } = require('../api');

// The ffuf fuzz flow: the steps a target is set up to fuzz, what a run of them found, and what to
// change before running them again.
//
// This exists because the whole loop an operator actually performs was unreachable from here. MCP
// could START ffuf (run_scan "ffuf_url") and could write an "ffuf configuration"
// (manage_tool_config "ffuf"), but both of those drive the LEGACY implementation whose three tables
// hold zero rows. The live implementation is the fuzz flow, and none of its endpoints were exposed,
// so an agent asked to review results, adjust the configuration and re-scan could do none of the
// three: the review could not see the findings, the adjustment wrote a config no scan reads, and the
// re-scan started a different scanner.
//
// The order these actions are meant to be used in is the order they are listed: findings to see what
// came back, steps to see what produced it, save_step to change it, preview to price the change,
// then run and status. summary is the one to start from, because a content-discovery run returns
// thousands of rows and the first question is never "which row" but "is this a set of discoveries or
// one response repeated".

const manageFuzzSchema = z.object({
  action: z.enum(['summary', 'findings', 'finding', 'triage', 'steps', 'option_reference',
    'seed_endpoints', 'save_step', 'delete_step', 'preview', 'run', 'status', 'cancel',
    'settings', 'save_settings']).describe(
    'summary: the shape of the stored findings per step, with an assessment of whether each step ' +
    'measured discoveries or one repeated response, and the option that would exclude that ' +
    'response. START HERE. ' +
    'findings: the rows themselves, filterable by step, status, size and payload, ordered so the ' +
    'rarely-seen and the 2xx come first. ' +
    'steps: every step of the flow with its raw request, positions, wordlists and options. ' +
    'option_reference: every option key a step honours and what each does, including ffuf\'s ' +
    'default matcher, which is the usual reason a scan reports one finding per word. ' +
    'seed_endpoints: discovered endpoints a new step can be seeded from. ' +
    'save_step: create a step, or MERGE a patch into an existing one when step_id is given. ' +
    'delete_step: remove a step. Its findings survive with no step attached. ' +
    'preview: the exact ffuf command and request bytes a step will send, plus its request count and ' +
    'every reason it would refuse to run. Costs nothing, so use it before run. ' +
    'run: execute every enabled ffuf step in order. ' +
    'finding: ONE finding expanded, with the request and response bytes ffuf actually sent and ' +
    'received, where in the request the payload landed, and a curl to replay it. This is the action ' +
    'to use before deciding whether a row matters. ' +
    'triage: mark findings new, interesting or dismissed, in bulk. Dismissed rows drop out of the ' +
    'default list and out of the notable count, which is how a wall of known noise stops being ' +
    'reread every time. ' +
    'status: how a run is going, per step, including what each step suppressed as baseline and how ' +
    'many steps were refused before it started. ' +
    'cancel: stop a running flow. The step in flight is signalled inside its container, no further ' +
    'steps start, and findings already stored are kept. ' +
    'settings: the flow-wide ffuf settings, which every step inherits unless it sets the same key ' +
    'itself, plus which steps are overriding one. These are the SAME settings the Settings modal ' +
    'in the UI edits, in the same store, so a change made either way is visible to the other. ' +
    'save_settings: change them. Merges by default, so sending one key leaves the rest alone; ' +
    'send a key as null to clear it.'),

  target_id: z.string().uuid().optional().describe(
    'The scope target UUID. Required for every action except preview, delete_step and status, which ' +
    'identify their subject directly.'),

  // --- findings / summary -----------------------------------------------------------------------
  step_id: z.string().uuid().optional().describe(
    'Restrict to one step, or name the step to save, preview or delete.'),
  status: z.string().optional().describe(
    'findings: keep only these HTTP statuses. Same syntax as ffuf -mc, so "200,301" or "200-299".'),
  exclude_status: z.string().optional().describe(
    'findings: drop these HTTP statuses, e.g. "401,403" to look past an auth wall.'),
  min_size: z.number().optional().describe('findings: minimum response size in bytes.'),
  max_size: z.number().optional().describe('findings: maximum response size in bytes.'),
  search: z.string().optional().describe('findings: substring match on the URL or the payload.'),
  since_run: z.string().uuid().optional().describe(
    'findings: only what this run saw FIRST, which is how to read a re-run without the previously ' +
    'known rows drowning it.'),
  triage: z.string().optional().describe(
    'findings: filter by triage state. Default hides dismissed rows; pass "all" for everything or ' +
    '"dismissed" for just those. triage action: the state to set, one of new, interesting, dismissed.'),
  finding_id: z.string().uuid().optional().describe('finding: which finding to expand.'),
  finding_ids: z.array(z.string().uuid()).optional().describe(
    'triage: the findings to mark. Takes a list because dismissing a page of noise one row at a ' +
    'time is a workflow nobody finishes.'),
  notes: z.string().optional().describe('triage: a note stored against every finding named.'),
  settings: z.record(z.any()).optional().describe(
    'save_settings: the flow-wide ffuf option keys to change, e.g. {"threads": 5, "filterStatus": ' +
    '"404"}. Same vocabulary a step takes in its own options; see option_reference. A key sent as ' +
    'null is ' +
    'cleared. A step that sets the same key still wins over the flow default.'),
  replace: z.boolean().optional().describe(
    'save_settings: make the payload authoritative instead of merging it, discarding any setting ' +
    'not named. Default false.'),
  limit: z.number().optional().describe('findings: rows to return, default 200, max 2000.'),
  offset: z.number().optional().describe('findings: rows to skip.'),

  // --- save_step --------------------------------------------------------------------------------
  raw_request: z.string().optional().describe(
    'save_step: the full raw HTTP request, with {{p01}}, {{p02}} ... marking the positions to fuzz. ' +
    'The Host header decides where the request is actually sent and is checked against the target\'s ' +
    'scope on every save and every run. A token in the text with no matching position is an error ' +
    'rather than literal text, and a position whose token is not in the text does nothing.'),
  seed_endpoint_id: z.string().uuid().optional().describe(
    'save_step: build the raw request from a discovered endpoint instead of writing it by hand. ' +
    'BEWARE: the seed freezes the captured request, including any Authorization header, which will ' +
    'expire. A step whose token has expired returns the same auth error to every payload and that ' +
    'reads as thousands of findings.'),
  name: z.string().optional().describe('save_step: a label for the step.'),
  scheme: z.string().optional().describe('save_step: http or https. Defaults to https.'),
  ffuf_mode: z.string().optional().describe(
    'save_step: clusterbomb (every combination, one wordlist per position), pitchfork (lists ' +
    'advanced in lockstep, requires equal lengths) or sniper (one wordlist, one position at a time, ' +
    'the others held at their resting value).'),
  enabled: z.boolean().optional().describe('save_step: whether a run includes this step.'),
  options: z.record(z.any()).optional().describe(
    'save_step: ffuf options for this step. MERGED over what is stored, so send only what changes; ' +
    'pass replace_options:true to set the whole object. Call option_reference for the keys. An ' +
    'unknown key is reported back rather than silently ignored.'),
  replace_options: z.boolean().optional().describe(
    'save_step: replace the options object instead of merging into it.'),
  positions: z.array(z.object({
    token: z.string().describe('The {{pNN}} token this configures.'),
    wordlist: z.string().optional().describe(
      'Wordlist id: builtin-default, builtin-small, builtin-large, builtin-headers, builtin-cookies, ' +
      'or the uuid of one uploaded through manage_wordlists. A raw path is NOT accepted.'),
    resting_value: z.string().optional().describe(
      'sniper only: what this position holds while another is being fuzzed. It should be the ' +
      'endpoint\'s real value, or the request means something different from the one that worked.'),
    encoder: z.string().optional().describe('e.g. urlencode.'),
  })).optional().describe('save_step: per-position configuration, matched by token.'),

  // --- run --------------------------------------------------------------------------------------
  acknowledge: z.boolean().optional().describe(
    'run: proceed even though the flow is over the request ceiling. Read the refusal first; it ' +
    'reports the count.'),
  run_id: z.string().uuid().optional().describe('status: which run.'),
});

async function manageFuzz(params) {
  const {
    action, target_id: targetID, step_id: stepID, run_id: runID,
  } = params;

  const needTarget = () => {
    if (!targetID) throw new Error(`action "${action}" requires target_id`);
    return targetID;
  };

  switch (action) {
    case 'option_reference': {
      const [opts, states] = await Promise.all([
        apiGet('/fuzz/option-reference'),
        apiGet('/fuzz/triage-states'),
      ]);
      return { ...opts, triage_states: states.states, triage_note: states.note };
    }

    case 'settings': {
      return apiGet(`/fuzz/${needTarget()}/settings`);
    }

    case 'save_settings': {
      if (!params.settings || typeof params.settings !== 'object') {
        throw new Error('save_settings requires settings, an object of option keys. Call ' +
          'option_reference or settings first to see which keys exist.');
      }
      // Merge by default: this store is shared with the UI, and a tool that replaced the whole
      // object would silently discard settings a human set in the Settings modal.
      return apiPost(`/fuzz/${needTarget()}/settings`, {
        settings: params.settings,
        replace: params.replace === true,
      });
    }

    case 'finding': {
      if (!params.finding_id) throw new Error('finding requires finding_id');
      return apiGet(`/fuzz/findings/${params.finding_id}`);
    }

    case 'triage': {
      if (!params.finding_ids || params.finding_ids.length === 0) {
        throw new Error('triage requires finding_ids');
      }
      if (!params.triage) throw new Error('triage requires a triage state');
      const body = { finding_ids: params.finding_ids, triage: params.triage };
      if (params.notes !== undefined) body.notes = params.notes;
      return apiPost('/fuzz/findings/triage', body);
    }

    case 'cancel': {
      if (!runID) throw new Error('cancel requires run_id');
      return apiPost(`/fuzz/runs/${runID}/cancel`, {});
    }

    case 'summary': {
      // limit=1 because the summary is computed over the whole filtered set server-side; the rows
      // are not the point here and pulling 200 of them to ignore them is waste.
      const q = buildFindingsQuery({ ...params, limit: 1 });
      const res = await apiGet(`/fuzz/${needTarget()}/findings${q}`);
      return {
        total_findings: res.total,
        by_status: res.summary ? res.summary.by_status : undefined,
        by_step: res.summary ? res.summary.by_step : undefined,
        next: 'Read the assessment on each step. Where one is offered, recommended_option is an ' +
          'options patch for save_step that would exclude that response at source, so the next ' +
          'run spends its requests on something else.',
      };
    }

    case 'findings': {
      const res = await apiGet(`/fuzz/${needTarget()}/findings${buildFindingsQuery(params)}`);
      return res;
    }

    case 'steps': {
      const res = await apiGet(`/fuzz/${needTarget()}/flow?tool=ffuf`);
      const steps = (res.steps || []).filter((s) => !stepID || s.id === stepID);
      return {
        flow_id: res.flow_id,
        scope: res.scope,
        steps: steps.map((s) => ({
          ...s,
          // Called out because it is the failure that looks like success: a frozen credential makes
          // every payload return the same response and the run reports it as findings.
          carries_authorization: /^\s*(authorization|cookie|x-api-key)\s*:/im.test(s.raw_request || ''),
        })),
        note: steps.length === 0
          ? 'This target has no ffuf steps. Use seed_endpoints then save_step.'
          : 'options {} means no matcher and no filter, so ffuf uses its default matcher of ' +
            '200,204,301,302,307,401,403,405,500. Any endpoint that answers 401 or 403 uniformly ' +
            'then produces one finding per wordlist word.',
      };
    }

    case 'seed_endpoints':
      return apiGet(`/fuzz/${needTarget()}/endpoints`);

    case 'save_step': {
      const body = {
        tool: 'ffuf',
        name: params.name,
        raw_request: params.raw_request,
        seed_endpoint_id: params.seed_endpoint_id,
        scheme: params.scheme,
        ffuf_mode: params.ffuf_mode,
        positions: params.positions,
      };
      if (params.enabled !== undefined) body.enabled = params.enabled;

      if (stepID) {
        // Merge, for the same reason manage_tool_config merges: the handler full-replaces the
        // options object, so a bare {"filterStatus":"401"} would drop the threads and rate an
        // operator had already set.
        const flow = await apiGet(`/fuzz/${needTarget()}/flow?tool=ffuf`);
        const current = (flow.steps || []).find((s) => s.id === stepID);
        if (!current) throw new Error(`step ${stepID} is not in this target's flow`);
        if (params.options) {
          body.options = params.replace_options
            ? params.options
            : { ...(current.options || {}), ...params.options };
        }
        const saved = await apiPut(`/fuzz/steps/${stepID}`, body);
        return { saved: true, merged: !params.replace_options, step: saved };
      }
      if (params.options) body.options = params.options;
      const created = await apiPost(`/fuzz/${needTarget()}/steps`, body);
      return { created: true, step: created };
    }

    case 'delete_step': {
      if (!stepID) throw new Error('delete_step requires step_id');
      return apiDelete(`/fuzz/steps/${stepID}`);
    }

    case 'preview': {
      if (!stepID) throw new Error('preview requires step_id');
      const res = await apiGet(`/fuzz/steps/${stepID}/preview`);
      const r = res.rendered || {};
      return {
        runnable: res.runnable,
        host: r.host,
        estimated_requests: r.estimated_requests,
        needs_acknowledgement: r.needs_acknowledgement,
        command: r.command,
        request_bytes: r.raw,
        warnings: r.warnings,
        errors: r.errors,
        options: res.step ? res.step.options : undefined,
        unrecognised_options: res.step ? res.step.unrecognised_options : undefined,
      };
    }

    case 'run': {
      const res = await apiPost(`/fuzz/${needTarget()}/run`,
        { tool: 'ffuf', acknowledge: !!params.acknowledge });
      return res;
    }

    case 'status': {
      if (!runID) throw new Error('status requires run_id');
      return apiGet(`/fuzz/runs/${runID}`);
    }

    default:
      throw new Error(`unknown action ${action}`);
  }
}

function buildFindingsQuery(params) {
  const q = new URLSearchParams();
  q.set('tool', 'ffuf');
  const map = {
    step_id: 'step_id', status: 'status', exclude_status: 'exclude_status',
    min_size: 'min_size', max_size: 'max_size', search: 'search', since_run: 'since_run',
    triage: 'triage', limit: 'limit', offset: 'offset',
  };
  for (const [key, param] of Object.entries(map)) {
    const v = params[key];
    if (v !== undefined && v !== null && v !== '') q.set(param, String(v));
  }
  return `?${q.toString()}`;
}

module.exports = { manageFuzzSchema, manageFuzz };
