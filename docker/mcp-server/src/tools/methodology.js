const { z } = require('zod');
const { apiGet } = require('../api');

// THE EXPERIENCED HUNTER'S CONTEXT, delivered to whoever is driving.
//
// The framework already held this knowledge in the Help Me Learn modals, where only a human clicking
// an accordion could reach it. An AI operating the same framework through this server saw tool
// descriptions and nothing else: no ordering, no sense of which step matters, no idea what a real
// hunter does first.
//
// That produced a measurable failure. On the first full engagement the fuzzing flow was built as ten
// steps that fuzzed parameters, headers and cookies against endpoints that were ALREADY KNOWN. Not
// one step put FUZZ in the path. Content discovery at the web root, the first command of any
// engagement, never ran. /admin was therefore never requested, never returned its 403, never entered
// any table, and the whole access-bypass section had nothing to work on. The wordlist shipped with
// the framework and its fourth line is "admin".
//
// FOUR WAYS IN, because different questions want different answers:
//   get_methodology       - how does a step work, and in what order do the steps go
//   whats_next            - what should I do on THIS target right now, decided from its actual data
//   get_attack_vector_model - the taxonomy the whole framework is built on
//   get_tool_guidance     - what does this specific tool prove, and how does it lie
//
// The content is served by the Go API so the client and this server cannot drift apart. The
// vocabulary follows rs0n's DEFCON 32 Bug Bounty Village workshop, which this framework implements:
// its central data structure IS that methodology's definition of an Injection Attack Vector.

const methodologySchema = z.object({
  step: z.string().optional().describe(
    'One step key: manual-crawl, content-discovery, archive-discovery, parameter-discovery, ' +
    'consolidate-vectors, vector-scanning, access-bypass, threat-model. Omit for the whole ' +
    'workflow in the order it is meant to be run.'),
});

const whatsNextSchema = z.object({
  target_id: z.string().describe('The scope target to assess.'),
});

const attackVectorModelSchema = z.object({});

const toolGuidanceSchema = z.object({
  tool: z.string().optional().describe(
    'Tool key, e.g. dalfox, sqlmap, ghauri, forbidden, pphack. Omit for every tool that has guidance.'),
  kind: z.string().optional().describe(
    'Optional finding kind for a more specific answer, e.g. V for a dalfox verified finding.'),
});

async function stepGuidance(stepKey) {
  try {
    const step = await apiGet(`/methodology/${stepKey}`);
    return {
      why: step.why,
      do_first: step.do_first,
      common_mistakes: step.common_mistakes,
      prerequisites: step.prerequisites || [],
    };
  } catch (err) {
    // Guidance is advisory. A tool must never fail because the methodology could not be read.
    return undefined;
  }
}

function register(server) {
  server.tool(
    'get_methodology',
    'The bug bounty methodology this framework implements, as an ordered workflow with the reasoning ' +
    'for each step, the opening moves, and the mistakes that have actually been made on real ' +
    'engagements. CALL THIS BEFORE PLANNING WORK on a target. It is the difference between running ' +
    'the tools the framework offers and running them in the order that finds things: content ' +
    'discovery at the web root comes before parameter fuzzing, and skipping it leaves the access ' +
    'control sections with no targets at all. Vocabulary follows rs0n\'s DEFCON 32 Bug Bounty ' +
    'Village methodology, which this framework is an implementation of.',
    methodologySchema.shape,
    async (params) => {
      const data = params.step ? await apiGet(`/methodology/${params.step}`) : await apiGet('/methodology');
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    });

  server.tool(
    'whats_next',
    'WHAT TO DO NEXT ON THIS TARGET, decided from the target\'s actual stored data rather than from ' +
    'a checklist. Reads what has and has not happened, then returns blockers and gaps in priority ' +
    'order with a concrete action for each. START HERE when picking up a target, and call it again ' +
    'whenever you are unsure what to do next or a section reports nothing. It catches the failures ' +
    'that look like success: a fuzzing flow that never fuzzed a path, an insertion point with zero ' +
    'vectors that will make every tool report clean, scans that stopped early and do not count, and ' +
    'an access-bypass section with no targets because content discovery never ran.',
    whatsNextSchema.shape,
    async (params) => {
      const data = await apiGet(`/methodology/${params.target_id}/advice`);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    });

  server.tool(
    'get_attack_vector_model',
    'The taxonomy this entire framework is built on, and the vocabulary to think in. An INJECTION ' +
    'attack vector is the unique combination of HTTP verb, domain:port, endpoint and injection ' +
    'point, which is exactly the identity the attack_vectors table keys on: two requests differing ' +
    'only in the VALUE sent are the same vector. A LOGIC attack vector is one of four things: an ' +
    'overly complex mechanism, a database query using an id from the HTTP request, granular access ' +
    'controls, or a hacky implementation. Also returns the five insertion points and the catalogue ' +
    'of what ffuf is actually used for. Read this before deciding what to test.',
    attackVectorModelSchema.shape,
    async () => {
      const [methodology, purposes] = await Promise.all([
        apiGet('/methodology'),
        apiGet('/attack-vector-model'),
      ]);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ ...purposes, workflow: methodology.steps.map((s) => ({
            order: s.order, key: s.key, title: s.title, stage: s.stage, pillar_note: s.why,
          })) }, null, 2),
        }],
      };
    });

  server.tool(
    'get_tool_guidance',
    'What a specific scanner actually PROVES, what it explicitly does not prove, what a false ' +
    'positive from it looks like, and how to validate its output by hand. Call this before acting ' +
    'on any finding and before believing any clean result. Every tool in this framework fails open: ' +
    'given an argument it does not understand it exits having tested nothing and the run is recorded ' +
    'as clean, so knowing each tool\'s specific failure mode is the difference between a result and ' +
    'a guess.',
    toolGuidanceSchema.shape,
    async (params) => {
      const q = params.tool ? `?tool=${encodeURIComponent(params.tool)}` +
        (params.kind ? `&kind=${encodeURIComponent(params.kind)}` : '') : '';
      const data = await apiGet(`/tool-guidance${q}`);
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    });
}

module.exports = { register, stepGuidance };
