const { z } = require('zod');
const { apiGet, apiPost } = require('../api');

// The Hidden Attack Vector Fuzzing cards: which endpoints Arjun and x8 brute-force for hidden
// parameters, and which of them each tool is set to run against.
//
// Running the tools was already reachable through run_scan. What was not is the decision
// underneath it, which is the part that actually matters: the corpus is not "every URL we know
// about", it is the endpoints Validate confirmed are real, and an operator narrows that further
// per tool. Without this an agent could start a scan but had no way to see or change what it would
// touch, which on the reference target is the difference between 25 endpoints and 808.

const manageParamEnumSchema = z.object({
  action: z.enum(['targets', 'select', 'deselect', 'select_all', 'deselect_all',
                  'preview', 'set_mode']).describe(
    'targets: the valid endpoints this tool would scan, grouped by HTTP verb, each with its host, ' +
    'path, whether it is on an adjacent host, its Investigate interest score, and whether it is ' +
    'currently selected. Also reports total_runs, which is NOT the endpoint count: Arjun scans a ' +
    'body-bearing endpoint twice, form-encoded then JSON, because an API route usually only ' +
    'answers the second. ' +
    'select / deselect: turn specific endpoints on or off for one tool. ' +
    'select_all / deselect_all: the same across every visible endpoint, or just one verb when ' +
    'verb is given. ' +
    'preview: what the scan will actually send. Returns one pass per Arjun mode, each with the ' +
    'exact command and a full HTTP request per endpoint, built server-side by the same code the ' +
    'runner uses. Read this before starting a scan. ' +
    'set_mode: move endpoints between Arjun modes. Arjun -m takes GET, POST, JSON and XML, which ' +
    'are request SHAPES rather than HTTP verbs, and endpoints are categorised automatically from ' +
    'the Content-Type their recorded request carried. Override when the guess is wrong: a route ' +
    'that only parses a JSON body ignores every form-encoded candidate and answers identically, so ' +
    'the wrong mode reads as "no parameters" when nothing was ever really tested.'),

  target_id: z.string().uuid().describe('The URL scope target UUID'),

  tool: z.enum(['arjun', 'x8']).describe(
    'Which tool the selection belongs to. Selection is per tool, so excluding an endpoint from ' +
    'Arjun leaves x8 still scanning it. Required for every action.'),

  endpoint_ids: z.array(z.string().uuid()).optional().describe(
    'select / deselect: the consolidated endpoint UUIDs, as returned by targets.'),

  verb: z.string().optional().describe(
    'select_all / deselect_all: restrict to one HTTP verb, e.g. POST. Omit to cover every verb.'),

  mode: z.enum(['GET', 'POST', 'JSON', 'XML', 'query', 'body', 'headers', 'cookies', ''])
    .optional().describe(
    'set_mode: the category to move the endpoints into. The valid values differ per tool because ' +
    'the two vary along different axes. ' +
    'ARJUN takes GET, POST, JSON or XML: body ENCODINGS, chosen from the Content-Type the recorded ' +
    'request carried. A route that parses only JSON ignores every form-encoded candidate, so the ' +
    'wrong one reads as "no parameters" when nothing was really tested. ' +
    'X8 takes query, body, headers or cookies: injection PLACES, with the verb kept as-is. x8 uses ' +
    'query for GET and body for POST/PUT/PATCH/DELETE on its own, and the framework adds --invert ' +
    'when you cross to the other one. headers and cookies are never automatic. ' +
    'Empty string returns the endpoints to automatic categorisation rather than pinning them.'),

  all: z.boolean().optional().describe(
    'preview: include endpoints this tool is NOT set to scan, each flagged with enabled:false. ' +
    'Default false, so a plain preview shows only what will actually be sent.'),

  include_scripts: z.boolean().optional().describe(
    'Include content_class=script endpoints, meaning JavaScript bundles. Off by default because a ' +
    'bundle has no server-side parameter surface; on the reference target they are 34 of the 80 ' +
    'valid endpoints, so including them triples the request count for nothing reachable. ' +
    'IMPORTANT for select_all and deselect_all: this must match what you last read with targets, ' +
    'because the bulk action covers exactly the endpoints that filter makes visible.'),
});

async function manageParamEnum(params) {
  const { target_id: targetId, tool } = params;
  if (!tool) return { error: 'tool is required (arjun or x8)' };

  const includeScripts = params.include_scripts === true;

  switch (params.action) {
    case 'preview':
      return apiGet(
        `/param-enum/${targetId}/preview?tool=${encodeURIComponent(tool)}` +
        `&all=${params.all === true}`);

    case 'set_mode': {
      if (!params.endpoint_ids || !params.endpoint_ids.length) {
        return { error: 'set_mode needs endpoint_ids' };
      }
      if (params.mode === undefined) {
        return { error: 'set_mode needs mode (GET, POST, JSON, XML, or empty for automatic)' };
      }
      return apiPost(`/param-enum/${targetId}/selection`, {
        tool,
        endpoint_ids: params.endpoint_ids,
        mode: params.mode,
      });
    }

    case 'targets':
      return apiGet(
        `/param-enum/${targetId}/targets?tool=${encodeURIComponent(tool)}` +
        `&include_scripts=${includeScripts}`);

    case 'select':
    case 'deselect': {
      if (!params.endpoint_ids || !params.endpoint_ids.length) {
        return { error: `${params.action} needs endpoint_ids` };
      }
      return apiPost(`/param-enum/${targetId}/selection`, {
        tool,
        endpoint_ids: params.endpoint_ids,
        enabled: params.action === 'select',
        include_scripts: includeScripts,
      });
    }

    case 'select_all':
    case 'deselect_all':
      return apiPost(`/param-enum/${targetId}/selection`, {
        tool,
        all: true,
        verb: params.verb,
        enabled: params.action === 'select_all',
        include_scripts: includeScripts,
      });

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

module.exports = { manageParamEnumSchema, manageParamEnum };
