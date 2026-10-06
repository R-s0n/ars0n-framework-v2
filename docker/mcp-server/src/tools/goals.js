const { z } = require('zod');
const { apiGet, apiPost, apiPut, apiPatch, apiDelete } = require('../api');

// THE ENGAGEMENT GOAL for a scope target: the one specific, PoC-backed objective the hunter is trying
// to reach, and the finish line the never-give-up layer otherwise lacks. A goal is a red-team "flag"
// (PTES/MITRE Engage): a human-readable objective plus a GIVEN/WHEN/THEN success_criteria that is
// binary and checkable against captured artifacts, not prose.
//
// THE STATE MACHINE, and who may move it. draft -> active (operator activates; exactly one active per
// target, which is what opens the hunt gate) -> candidate (the HUNTER claims it, attaching the PoC
// artifacts) -> verified (an ISOLATED ADVERSARIAL VERIFY TURN confirms the criteria against the
// artifacts) -> met (the OPERATOR signs off, and ONLY the operator). This tool deliberately does NOT
// expose a way for the AI to write 'met' or 'abandoned': achieving a goal is the operator's call, and
// abandoning one is a stop the never-give-up discipline reserves for the operator too. The hunter's
// ceiling is 'candidate'; the verifier's is 'verified'.
//
// WHY VERIFY IS A SEPARATE STEP. Agents reward-hack and declare success without a real PoC. So the
// verdict must come from a turn that is adversarial and sees ONLY the artifacts, never the hunter's
// narration. The tool cannot force a fresh context, so the guidance says to run verify as an isolated
// turn (ideally a subagent) instructed to assume the hunter is gaming it. verify records the verdict;
// a 'pass' needs the artifacts to actually demonstrate the gain, a 'fail' routes back to 'active' with
// the open criteria named so the loop continues.

const manageGoalsSchema = z.object({
  action: z.enum(['list', 'get', 'create', 'update', 'delete', 'activate', 'propose', 'verify']).describe(
    'list: every goal on a target, active one first, plus which is active. ' +
    'get: one goal in full (its criteria and any attached evidence). ' +
    'create: add a goal (always starts as draft and inactive). ' +
    'update: edit a goal\'s descriptive fields (title/description/vuln_class/asset_scope/' +
    'success_criteria/requires_poc/min_severity). It does NOT change status. ' +
    'delete: remove a goal (usually an operator action). ' +
    'activate: make this goal the single ACTIVE goal for its target, which is what opens the hunt ' +
    'gate. A draft becomes active. ' +
    'propose: the HUNTER claims the goal is reached - sets status candidate and REQUIRES ' +
    'candidate_evidence (the captured request/response artifact ids plus numbered repro steps). This ' +
    'is as far as the hunter may move a goal. ' +
    'verify: record the verdict of an ISOLATED ADVERSARIAL verify turn (run it in a fresh context, or ' +
    'a subagent, that sees only the artifacts and is told to assume the hunter is gaming it). ' +
    'verdict:"pass" -> status verified (awaiting the operator sign-off that alone sets met); ' +
    'verdict:"fail" -> status back to active with verifier_notes naming what is still unproven. ' +
    'There is NO action that sets met: that is the operator\'s sign-off alone.'),

  target_id: z.string().uuid().optional().describe('The scope target UUID. Required for list, get and create.'),
  goal_id: z.string().uuid().optional().describe(
    'The goal\'s own UUID, the "id" from list/create. Required for get, update, delete, activate, ' +
    'propose and verify.'),

  title: z.string().optional().describe('Create/update: a short name for the objective.'),
  description: z.string().optional().describe('Create/update: the human-readable objective (the red-team "flag").'),
  vuln_class: z.string().optional().describe(
    'Create/update: the attack class the goal is about (idor, xss, ssrf, sqli, auth-bypass, ...). ' +
    'Biases the goal-aware next-step guidance toward that class.'),
  asset_scope: z.string().optional().describe(
    'Create/update: WHOSE data or which protected resource the goal is about (e.g. "another account\'s ' +
    'KYC"). Ties to the standing rule that the line is whose data.'),
  success_criteria: z.string().optional().describe(
    'Create/update: the success criterion as a GIVEN/WHEN/THEN statement, binary and checkable against ' +
    'captured artifacts. Example: "GIVEN account A\'s session and account B\'s object id, WHEN A requests ' +
    'B\'s /details, THEN the response body contains B\'s SSN (a value A is not authorized to see)." ' +
    'Avoid "could"/"may": a goal is met by demonstrated gain, not by a mechanism being present.'),
  requires_poc: z.boolean().optional().describe(
    'Create/update: whether reaching this goal requires a proof of concept. Defaults TRUE and should ' +
    'stay true unless the operator deliberately sets a non-PoC goal; a goal is not met by a mechanism, ' +
    'only by a demonstrated attacker gain.'),
  min_severity: z.string().optional().describe(
    'Create/update: the severity band the goal targets (e.g. "moderate"; CVSS 3.1 4.0-6.9). A label, ' +
    'not the pass/fail - the real test is the success_criteria artifact.'),

  candidate_evidence: z.string().optional().describe(
    'propose: REQUIRED. The proof the goal is reached - the captured request/response artifact ids ' +
    '(from replay_request / the corpus), the matched expected value, the baseline/differential request ' +
    'showing the authz boundary, and the numbered reproduction steps. Prose claims without artifacts ' +
    'are not acceptable.'),
  verdict: z.enum(['pass', 'fail']).optional().describe(
    'verify: REQUIRED. "pass" only if the attached artifacts actually demonstrate the success_criteria ' +
    '(and a PoC exists when requires_poc); otherwise "fail". "vulnerable IF X" with X unproven is a fail.'),
  verifier_notes: z.string().optional().describe(
    'verify: what the adversarial check found - for a pass, why the artifacts prove the gain; for a ' +
    'fail, exactly which criterion is unmet or which precondition is unproven, so the loop knows where ' +
    'to go next.'),

  max_results: z.number().optional().describe('list: how many goals to return. Default 50.'),
});

async function goalsFor(targetId) {
  const body = await apiGet(`/goals/${targetId}`);
  return {
    goals: Array.isArray(body && body.goals) ? body.goals : [],
    active_goal: body && body.active_goal ? body.active_goal : null,
  };
}

function apiError(err, idParam) {
  const raw = String(err && err.message ? err.message : err);
  const m = raw.match(/failed \((\d+)\):\s*([\s\S]*)$/);
  const status = m ? Number(m[1]) : undefined;
  const out = { error: (m ? m[2] : raw).trim().slice(0, 240) };
  if (status !== undefined) out.http_status = status;
  if (status === 404 && idParam === 'goal_id') {
    out.hint = 'goal_id is the goal\'s own id from list/create, not the scope target id.';
  }
  return out;
}

async function manageGoals(params) {
  switch (params.action) {
    case 'list': {
      if (!params.target_id) return { error: 'list needs target_id' };
      try {
        const { goals, active_goal } = await goalsFor(params.target_id);
        const limit = typeof params.max_results === 'number' ? params.max_results : 50;
        return { active_goal, count: goals.length, goals: goals.slice(0, limit) };
      } catch (err) { return apiError(err, 'target_id'); }
    }

    case 'get': {
      if (!params.target_id || !params.goal_id) return { error: 'get needs target_id and goal_id' };
      try {
        const goal = (await goalsFor(params.target_id)).goals.find((g) => g.id === params.goal_id);
        return goal || { error: 'no goal with that goal_id on that target', goal_id: params.goal_id };
      } catch (err) { return apiError(err, 'target_id'); }
    }

    case 'create': {
      if (!params.target_id) return { error: 'create needs target_id' };
      if (!params.title || !params.title.trim()) {
        return { error: 'create needs a title with something in it' };
      }
      try {
        const out = await apiPost('/goals', {
          scope_target_id: params.target_id,
          title: params.title,
          description: params.description,
          vuln_class: params.vuln_class,
          asset_scope: params.asset_scope,
          success_criteria: params.success_criteria,
          requires_poc: params.requires_poc,
          min_severity: params.min_severity,
        });
        return { created: true, goal: out,
          note: 'Created as draft. Call action:"activate" to make it the active goal and open the hunt gate.' };
      } catch (err) { return apiError(err, 'target_id'); }
    }

    case 'update': {
      if (!params.goal_id) return { error: 'update needs goal_id' };
      // Descriptive fields only. Status moves through activate/propose/verify (and the operator), never
      // a free update, so the hunter cannot write itself to met.
      const body = {};
      for (const k of ['title', 'description', 'vuln_class', 'asset_scope', 'success_criteria',
        'requires_poc', 'min_severity']) {
        if (params[k] !== undefined) body[k] = params[k];
      }
      if (Object.keys(body).length === 0) return { error: 'update needs at least one field to change' };
      try {
        return { updated: true, goal: await apiPut(`/goals/${params.goal_id}`, body) };
      } catch (err) { return apiError(err, 'goal_id'); }
    }

    case 'delete': {
      if (!params.goal_id) return { error: 'delete needs goal_id' };
      try {
        await apiDelete(`/goals/${params.goal_id}`);
        return { deleted: true, goal_id: params.goal_id };
      } catch (err) { return apiError(err, 'goal_id'); }
    }

    case 'activate': {
      if (!params.goal_id) return { error: 'activate needs goal_id' };
      try {
        return { activated: true, goal: await apiPatch(`/goals/${params.goal_id}/activate`, {}) };
      } catch (err) { return apiError(err, 'goal_id'); }
    }

    case 'propose': {
      if (!params.goal_id) return { error: 'propose needs goal_id' };
      if (!params.candidate_evidence || !params.candidate_evidence.trim()) {
        return { error: 'propose REQUIRES candidate_evidence: the captured artifact ids, the matched ' +
          'value, the baseline/differential request, and numbered repro steps. A goal is not reached ' +
          'by a prose claim.' };
      }
      try {
        const goal = await apiPut(`/goals/${params.goal_id}`, {
          status: 'candidate',
          candidate_evidence: params.candidate_evidence,
        });
        return { proposed: true, goal,
          next: 'Now run action:"verify" as an ISOLATED adversarial turn (fresh context or a subagent ' +
            'that sees only the artifacts, instructed to assume the hunter is gaming it). You can reach ' +
            'candidate; only the operator can sign off to met.' };
      } catch (err) { return apiError(err, 'goal_id'); }
    }

    case 'verify': {
      if (!params.goal_id) return { error: 'verify needs goal_id' };
      if (params.verdict !== 'pass' && params.verdict !== 'fail') {
        return { error: 'verify needs verdict "pass" or "fail"' };
      }
      // pass -> verified (awaiting the operator sign-off that alone sets met). fail -> back to active so
      // the loop continues against the open criteria. verify NEVER sets met.
      const status = params.verdict === 'pass' ? 'verified' : 'active';
      try {
        const goal = await apiPut(`/goals/${params.goal_id}`, {
          status,
          verifier_verdict: params.verdict,
          verifier_notes: params.verifier_notes,
        });
        const note = params.verdict === 'pass'
          ? 'Verified. This is a PROPOSAL, not a win: the goal is NOT met until the operator signs off. '
            + 'Surface it for operator confirmation; do not treat verified as done.'
          : 'Verifier rejected the claim. Status is back to active. Keep hunting against the open '
            + 'criteria named in verifier_notes; a fail closes this attempt, not the goal.';
        return { verified: params.verdict === 'pass', goal, note };
      } catch (err) { return apiError(err, 'goal_id'); }
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

module.exports = { manageGoalsSchema, manageGoals };
