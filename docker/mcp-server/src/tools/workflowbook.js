const { z } = require('zod');
const workflows = require('../workflows');

// THE WORKFLOW BOOK TOOLS. Two of them, for the same reason browse_knowledge_base and
// read_knowledge_file are two: an index and a read are different questions, and folding them into
// one `action` enum makes the agent pick a verb before it knows what exists.
//
// This file is thin on purpose. The registry in ../workflows does the assembling, the validating and
// the budget refusal; everything here is the schema an agent reads to decide whether to call, plus
// the shaping of what comes back. The descriptions matter more than the code: an agent picks a tool
// by reading its description, and a description that fails to say "the gotchas are the product" gets
// this store used as a list of steps, which is the one thing it is not.
//
// The file is named workflowbook.js and not workflows.js because ./workflows.js already exists and
// holds run_wildcard_workflow, run_company_workflow and run_url_workflow. Those START scans. These
// return prose. Two files with one name would have made that collision invisible in an import list.

const listWorkflowsSchema = z.object({
  query: z.string().optional().describe(
    'Case-insensitive substring filter over the name, title, purpose and when-to-reach-for-it text. ' +
    'Omit it: the book is small enough to read whole, and the point of the index is to see what ' +
    'exists rather than to confirm what you already guessed.'),
});

const getWorkflowSchema = z.object({
  name: z.string().describe(
    'The stable workflow name from list_workflows, for example "xss-campaign". An unrecognised name ' +
    'is answered with the names that do exist rather than with an error.'),

  section: z.enum(['all', ...workflows.SECTIONS]).optional().describe(
    'Which part to return, default "all". ' +
    'gotchas: how this goes wrong, each with the measurement, what the wrong answer looks like, and ' +
    'the fix. READ THIS FIRST. ' +
    'steps: the ordered do/assert/verify/looks_like units with the tool calls. ' +
    'lessons: what the last run learned, each with the measurement and the source that can be ' +
    'reopened to check it. ' +
    'preconditions: what must be true before step one, and why. ' +
    'overview: what it is for, when to reach for it, what it cost and what it was measured on. ' +
    'Every section comes back with the overview attached, because a page of advice with no ' +
    'addressee is not usable. Ask for one section only when "all" refuses on size.'),
});

async function listWorkflows(params = {}) {
  const rows = workflows.list(params.query);
  return {
    workflows: rows,
    count: rows.length,
    total: Object.keys(workflows.ALL).length,
    // Said on the index rather than only in the tool description, because this is the line that
    // decides whether the next call is useful. The steps in these entries are one sentence each and
    // were never the hard part; the gotchas are the measured cost of getting them wrong.
    how_to_read_one:
      'get_workflow name=<name>. Read the gotchas before the steps: every one of them is a way a ' +
      'tool reported success without doing the work, and none of them is visible in a result.',
    note: rows.length === 0 && params.query
      ? `No workflow matches ${JSON.stringify(params.query)}. Call again with no query to see all ` +
        `${Object.keys(workflows.ALL).length}.`
      : undefined,
  };
}

async function getWorkflow(params = {}) {
  const section = params.section || 'all';
  const body = workflows.get(params.name, section);
  if (body.error) return body;
  return {
    ...body,
    section,
    // A workflow is a record of one campaign against one target on one day, and measured_on says
    // which. Stating that on every read is the difference between a lesson and a rule: the counts
    // here are evidence that this failure mode is real, not a promise about your corpus.
    provenance:
      'Every count in this workflow was measured on the run named in measured_on. Treat the ' +
      'failure modes as real and the numbers as that run, not as yours.',
  };
}

module.exports = {
  listWorkflowsSchema,
  listWorkflows,
  getWorkflowSchema,
  getWorkflow,
};
