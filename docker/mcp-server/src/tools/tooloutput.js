const { z } = require('zod');
const { apiGet } = require('../api');
const { resolveLimit } = require('../utils/clip');
const { clampLimit } = require('../utils/truncate');
const { DISCOVERY_TOOL_KEYS } = require('../utils/discoveryTools');

// What a discovery tool actually printed.
//
// The measured failure this exists for: LinkFinder ran four times against http://10.0.0.18:3000 and
// every run stored "Usage: python linkfinder.py [Options] use -h for help" next to the exact argv
// that produced it. Neither string was reachable from here. check_scan_status needs a scan id the
// workflow never hands back, most of the discovery status routes do not select stdout or stderr at
// all, and there was no way to ask a target "what have you executed and what did it say". So the
// wrong flag was found by changing configuration and re-running until the symptom moved, four times,
// to recover a string that had been in the database since the first attempt.
//
// The vector scanners already had this: vector_scan_traces stores argv and stdout per exec and
// GetVectorTrace serves it whole. server/utils/toolOutputAPI.go is the same thing for the thirty
// seven discovery scan tables, and this is its tool.
//
// Nothing here runs anything. Every field is a read of what a completed run already stored.

// Declared as an enum rather than a free string so a typo is answered here instead of becoming a 404
// an agent reads as "this target has never run that tool". The list itself lives in utils, where the
// parity test against the Go registry can reach it without pulling in zod.
const TOOL_KEYS = DISCOVERY_TOOL_KEYS;

// Per field, on a single-run read. Three fields can come back (stdout, stderr, result), so the
// default worst case is twelve thousand characters, which fits comfortably under the output cap. A
// caller chasing a specific string raises it, or asks for the tail.
const OUTPUT_DEFAULT = 4000;
const OUTPUT_FIELDS = ['stdout', 'stderr', 'result'];

// The ceiling ListDiscoveryToolRuns enforces. Mirrored here so the filtered form can ask for the
// whole window without sending a number the server will silently reduce.
const SERVER_RUN_LIMIT = 500;

const getToolOutputSchema = z.object({
  action: z.enum(['runs', 'run', 'tools']).describe(
    'runs: every discovery scan this target has executed, newest first, with the command it ran and ' +
    'the SIZE of what it printed. START HERE: it is the only place that answers "what has actually ' +
    'been run against this target and did any of it fail". Each row carries a diagnosis. ' +
    'run: ONE run, with stdout, stderr, error and the exact command verbatim. This is what you read ' +
    'when a scan reported something you do not believe. ' +
    'tools: the tool keys this surface knows and the table each one reads.'),

  target_id: z.string().uuid().optional().describe('The scope target UUID. Required for runs.'),
  scan_id: z.string().uuid().optional().describe(
    'The scan UUID, from action "runs". Required for run.'),
  tool: z.enum(TOOL_KEYS).optional().describe(
    'runs: only this tool\'s runs. run: which table to look in, and it may be omitted, in which ' +
    'case every table is searched for the scan id. Omitting it is the normal thing to do when the ' +
    'id came out of a workflow response or a log line rather than out of action "runs".'),

  only_problems: z.boolean().optional().describe(
    'runs: return only the runs whose diagnosis is not "ok", i.e. the ones that failed, printed a ' +
    'usage message, or finished having stored nothing at all. This is the fast form of "why is ' +
    'there no data from X".'),
  max_results: z.number().optional().describe('runs: maximum rows (default 50, max 500).'),

  max_chars: z.number().int().positive().optional().describe(
    `run: characters of stdout, stderr and result to return, per field. Default ${OUTPUT_DEFAULT}. ` +
    'The true length is always reported as stdout_chars / stderr_chars / result_chars whether or ' +
    'not it was clipped.'),
  from: z.enum(['head', 'tail']).optional().describe(
    'run: which end of the output to keep when it is clipped. head (default) is right for a usage ' +
    'message or an argument rejection, which is the first thing a tool prints. tail is right for a ' +
    'crash or a run that stopped part way, which is the last.'),
});

// A run row is only worth opening if something about it is wrong or surprising, so the diagnosis is
// what the listing is sorted through.
//
// DEFINED BY EXCLUSION, and that is the whole point. This used to be an allowlist,
// {usage_error, failed, no_output}, hand-copied from the Go side. When toolOutputAPI.go gained
// "unreachable_or_usage" for LinkFinder's ambiguous banner, the Go side counted four such runs in
// needs_attention and this filter dropped every one of them: the response said "needs_attention: 5"
// and returned 1 row.
//
// A filter whose job is to surface failures, quietly discarding a failure because nobody updated a
// list in a second language, is the same fail-open shape as a scan that never ran being recorded
// clean. Listing what is FINE means a new diagnosis defaults to visible, which is the safe direction.
const HEALTHY_DIAGNOSES = new Set(['ok', 'running']);
const isProblemDiagnosis = (d) => !HEALTHY_DIAGNOSES.has(String(d || '').trim());

async function getToolOutput(params) {
  switch (params.action) {
    case 'tools':
      return apiGet('/tool-output/tools');

    case 'runs': {
      if (!params.target_id) return { error: 'runs needs target_id' };
      const want = Math.min(clampLimit(params.max_results, 50), SERVER_RUN_LIMIT);

      // only_problems filters AFTER the server's ORDER BY created_at DESC LIMIT, so asking for the
      // newest fifty and keeping the failures among them would answer "nothing failed" for a target
      // whose failing runs are older than its last fifty. That is the same silent zero this whole
      // tool exists to expose, so the filtered form asks for the full window and clamps afterwards.
      const problemsOnly = params.only_problems === true;
      const q = new URLSearchParams();
      if (params.tool) q.set('tool', params.tool);
      q.set('limit', String(problemsOnly ? SERVER_RUN_LIMIT : want));
      const result = await apiGet(`/tool-output/runs/${params.target_id}?${q.toString()}`);

      const all = Array.isArray(result.runs) ? result.runs : [];
      const matching = problemsOnly ? all.filter((r) => isProblemDiagnosis(r.diagnosis)) : all;
      const runs = matching.slice(0, want);
      const out = {
        ...result,
        runs,
        returned: runs.length,
        scanned: all.length,
        next: 'Open any row with action "run" and its scan_id. diagnosis "usage_error" means the ' +
          'tool rejected its own arguments and tested nothing. "unreachable_or_usage" means the ' +
          'tool printed a banner that could be either bad arguments or an input it could not ' +
          'fetch, so check whether other tools failed in the same window before changing anything.',
      };
      // Say so when the filter itself dropped rows, rather than letting `returned` quietly
      // contradict the server's own needs_attention count.
      if (matching.length > runs.length) {
        out.omitted_by_limit = matching.length - runs.length;
      }
      return out;
    }

    case 'run': {
      if (!params.scan_id) {
        return { error: 'run needs scan_id (get one from action "runs")' };
      }
      const q = new URLSearchParams();
      // The budget is resolved here rather than server side on purpose: the Go handler serves a run
      // whole by default, the way GetVectorTrace serves a trace whole, and a context window sized
      // default belongs to the client that has the context window.
      const budget = resolveLimit(params.max_chars, OUTPUT_DEFAULT, OUTPUT_FIELDS.length);
      q.set('max_chars', String(budget));
      if (params.from === 'tail') q.set('from', 'tail');

      const tool = params.tool || 'any';
      // The server does the clipping, because only it knows which end the caller asked for and it is
      // the side holding the whole string. Re-clipping here would cut the marker the server appended
      // and produce a body that claims to be truncated twice. The command is never clipped at all:
      // it is the shortest field and the one every usage error is a statement about.
      return apiGet(`/tool-output/run/${encodeURIComponent(tool)}/${params.scan_id}?${q.toString()}`);
    }

    default:
      return { error: `unknown action ${params.action}` };
  }
}

// isProblemDiagnosis is exported so the rule can be asserted directly. It was a private allowlist
// that silently dropped a whole class of failure, and a rule like that needs a test that names it.
module.exports = { getToolOutputSchema, getToolOutput, TOOL_KEYS, isProblemDiagnosis };
