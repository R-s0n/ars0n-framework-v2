// The never-give-up layer (Layer 1, Tier A: the heartbeat).
//
// THE PROBLEM THIS EXISTS FOR. An AI driving this framework repeatedly reaches an invalid terminal
// state after shallow work and stops: "clean", "exhausted", "well-defended", "the only surface left",
// "nothing more I can do solo", "I'll wait". It confuses "I ran out of the moves I thought of" with
// "the target has nothing left", and reports the second. In bug bounty that is always wrong: the
// search space is fractal and effectively unbounded. Another header, parameter, value, encoding,
// endpoint, verb, wordlist, host, path depth, auth state, timing or chain ALWAYS exists. Real
// engagements run for days, weeks, months across many targets. "Exhausted" is a feeling that arrives
// at hour two; the bug arrives around hour forty.
//
// WHY A PUSH, NOT A PULL. The documented root cause is that the AI does NOT call the help tools when
// it concludes done: not knowing a next move exists is exactly the state in which you do not ask for
// one. So the reframe must arrive UNBIDDEN, riding every tool result through attachGuidance() in
// index.js, keyed to rotate per session so it does not become wallpaper.
//
// THE HONESTY-LAYER GUARD (do not break this). A per-SCAN verdict like "0 findings, sent to N vectors"
// is TRUE and is protected by the lies / counts-that-are-not-counts / vector-runner-fail-open
// discipline elsewhere. This heartbeat is ENGAGEMENT scope, attached as a SEPARATE keep_hunting field.
// It must never rewrite, suppress, or contradict an honest per-scan result. It reframes the TARGET
// conclusion, not the scan's own count.
//
// THE LEGITIMATE-PAUSE DISCRIMINATOR. Some pauses are real: the operator must create a second account,
// paste credentials, provide an APK, or rule on scope (the AI cannot do these). Those are allowed, but
// only surfaced together with the next un-blocked move, and only after no parallel un-blocked axis
// remains (one almost always does). A disproven hypothesis or an operator-blocked lead closes THAT
// ITEM, never the target. The louder Tier-B block (added in a later step) states this; the heartbeat
// just keeps the pressure on.
//
// Style: no em dashes anywhere in this file (the guidance test asserts it). Each line <= 160 chars.

// The rotating reframe pool. Each line is a complete thought that reframes stopping as the error.
const HEARTBEAT = [
  'Clean is not a finding, it is the absence of one. You tested one shape of one input in one state. That is tier one of twelve.',
  'Exhausted is a feeling, not a fact. It arrives at hour two. The bug arrives around hour forty. Keep going.',
  'The search space is fractal: every endpoint hides params, every param hides values, every value hides an encoding, every encoding hides a parser.',
  'A WAF blocking your payload confirms the param reaches something sensitive. You found a live wire, not a wall.',
  '"No other way" has never once been true on a real web app. Another header, param, value, verb, host, path depth or auth state always exists.',
  'You did not find a clean target. You found the edge of your current wordlist. Load another one.',
  'Re-test after every redeploy. The code you proved safe yesterday is not the code shipping today. Safe has a timestamp.',
  '"I do not know what to do" has one correct response: enumerate more. New headers, params, values, endpoints, states. Always available, never empty.',
  'An unguessable id is not an authorized one. A random id makes the work finding the leak channel, not stopping.',
  'Stopping is the one move that is always wrong. Every other move at least gathers information.',
  'A guard that held on fifteen endpoints says nothing about the sixteenth. Authorization is per handler, not transitive. Test the next one.',
  'Needing the operator for one thing is not being blocked on everything. Name the blocker AND the next un-blocked move in the same breath.',
  'You have done minutes of an unbounded search. Do not hand a target back as tested. There is always another pod.',
  'A negative result is data about your test, not a verdict on the target. Change the test: new value class, new encoding, new insertion point.',
];

// The standing anti-quit constraint, delivered in full the first time a decide/wrap-up tool is used
// in a session (the `rule` field never reaches the compact line, so it costs its length exactly
// once). This is the one-time framing; the heartbeat above is the repeating pressure. Applied to the
// tools where a "nothing left" conclusion is born: whats_next, get_methodology,
// get_attack_vector_model, get_target_summary, get_scope_overview. No em dashes.
const NO_EXHAUSTED_RULE =
  'There is no "exhausted" state for a live target. The search space is fractal: another header, ' +
  'parameter, value, encoding, endpoint, verb, wordlist, host, path depth, auth state, timing or ' +
  'chain always exists. If you believe a target is clean, a section is done, or there is nothing ' +
  'more to try, that belief is the signal to ENUMERATE MORE, not to stop or report done. A guard ' +
  'that held on fifteen handlers says nothing about the sixteenth; coverage is per handler, not ' +
  'transitive. A disproven hypothesis, or a lead that genuinely needs the operator (a second ' +
  'account, an APK, a scope ruling, which the AI cannot do itself), closes only THAT item and must ' +
  'be surfaced together with the next un-blocked move in the same breath; it never ends the target. ' +
  'Real engagements run for days and weeks across many targets, logging hundreds of attempts before ' +
  'the first finding. When you do not know what to do, the answer is always to enumerate deeper: new ' +
  'headers, params, values, endpoints, states. Call get_attack_playbook for the per-class next move. ' +
  'This is the operational engine of Ebb and flow.';

// The standing session-is-a-depreciating-asset rule, delivered in full the first time a session tool
// is used in a session. Sibling of NO_EXHAUSTED_RULE: that one says never stop hunting, this one says
// the authenticated half of hunting rots unless you keep it alive. Attached to check_session_tokens
// and manage_session_tokens. No em dashes.
const SESSION_DECAY_RULE =
  'A session is a depreciating asset, not a fact you establish once. VALIDATE it before every ' +
  'authenticated sweep (check_session_tokens validate): an expired token turns every endpoint into a ' +
  'login wall and the scan will fingerprint that wall as the application and report it clean. ' +
  'Short-lived bearers (OAuth access tokens are often 5 to 15 minutes) must be RE-CAPTURED ' +
  'proactively, not only when something breaks: if the browser tab stays logged in with the manual ' +
  'crawl recording, the credential is being refreshed in the browser continuously, so re-run ' +
  'capture_oauth (or recapture) to pull the current one. KEEP THE SECOND ACCOUNT CURRENT: ' +
  'cross-account authorization testing needs account A and B both live at once, and a dead B turns ' +
  'every id-swap into a 401 that reads as "protected". Bridge a live browser session into the ' +
  'framework THROUGH THE CORPUS (capture_oauth / recapture), never by reading the token in ' +
  'JavaScript, because the browser extension redacts it. And a 403 while the anonymous control gets ' +
  '401 is a LIVE session hitting an authorization boundary, not an expired one, so do not refresh on ' +
  'it. When you do not know how to refresh a given auth type, call get_session_refresh_playbook with ' +
  'the type (password, oauth-oidc, saml, magic-link, password-mfa, ...) for the exact action.';

// The standing goal-discipline rule, delivered in full the first time manage_goals is used in a
// session. Hunting is goal-directed: the target needs ONE active, PoC-backed objective before you
// start, everything converges on it, and it is the only legitimate finish line. No em dashes.
const GOAL_RULE =
  'Hunting is goal-directed. Before you start, the target needs ONE ACTIVE goal: a specific, ' +
  'PoC-backed objective written as a GIVEN/WHEN/THEN success_criteria (set it with manage_goals, then ' +
  'activate it). When the goal gate is on, the scan and attack tools will not run without it. ' +
  'Everything you do then converges on that one goal, and it is the ONE legitimate finish line: there ' +
  'is no "done" until it is met, and blocked==0 && gaps==0 or any "nothing left" feeling is never ' +
  'done while the goal is unmet. You may move a goal only as far as candidate, and only by attaching ' +
  'the captured request/response artifacts that prove the criteria, never a prose claim. A SEPARATE ' +
  'adversarial verify turn (fresh context, artifact-only, assume the hunter is gaming it) records the ' +
  'verdict; a pass is a PROPOSAL, not a win. ONLY THE OPERATOR signs off to met: you can never mark ' +
  'your own goal met. A failed verify closes that attempt, not the goal, so keep hunting the open ' +
  'criteria. Achieving the goal (with its PoC) is the sanctioned stop; an operator abort is the only ' +
  'other one.';

// Return the heartbeat line for a rotation index. Handles any integer (including negatives) safely.
function heartbeat(idx) {
  const n = HEARTBEAT.length;
  const i = Number.isInteger(idx) ? ((idx % n) + n) % n : 0;
  return HEARTBEAT[i];
}

// ============================================================================================
// LAYER 1b: the LOUD block. The heartbeat is constant low pressure; this is what fires at the
// exact moment a "nothing left" conclusion is forming, which is (a) a summary/results tool
// returning an empty or clean body, or (b) a run of such results in a row. It replaces the
// one-line heartbeat with an object the model cannot read past: the reframe, three untried axes,
// the next concrete move, and the legitimate-pause carve-out.
// ============================================================================================

// The twelve universal enumeration axes. "I do not know what to do" is always one of these, and at
// least one is untried on any real target. Short, concrete, rotated three at a time so the block
// never shows the same trio twice running. No em dashes.
const AXES = [
  'Wordlists: one list finding nothing means try five more. raft, assetnote, the tech-specific list, a custom one built from the target JS.',
  'Content discovery at EVERY path depth, recursively. The 403 on /admin is a finding; the directory you never requested is the bug.',
  'HTTP headers: X-Forwarded-For/-Host/-Proto, X-Original-URL, X-Rewrite-URL, method-override, and every X-* name the target JS itself sends.',
  'Hidden params per endpoint (arjun/x8, a different wordlist each run), then the magic set: debug, admin, is_admin, role, preview=1, test, internal.',
  'Values: encodings, double-encoding, polyglots, type juggling, boundary and overflow, unicode normalization, and an OOB canary in every field.',
  'Verbs and method-override: HEAD, OPTIONS, PUT, PATCH, DELETE, and X-HTTP-Method-Override on an endpoint that only answered GET.',
  'Content-types and body shapes: JSON vs form vs multipart vs XML, array-wrap and nested-object spellings of the same parameter.',
  'Hosts and vhosts: siblings, staging, internal names from certs/JS/env files, and the Host header swapped to each.',
  'Archived and historical URLs (wayback, gau, commoncrawl): endpoints and params the live crawl never saw because the UI no longer links them.',
  'Re-read the JS and any mobile/APK build: lazy chunks, dead feature-flagged routes, legacy and internal API versions, hardcoded endpoints.',
  'Auth states and roles: unauthenticated, a second account, a lower-privilege role, an expired or cross-tenant token, no token at all.',
  'Timing, sequence and state: race conditions, mass-assignment, steps out of order, replay, and re-testing after every redeploy.',
];

// Pick three distinct axes starting at a rotating offset, so successive loud blocks walk the list.
function pickAxes(offset, k = 3) {
  const n = AXES.length;
  const start = Number.isInteger(offset) ? ((offset % n) + n) % n : 0;
  const out = [];
  for (let i = 0; i < k && i < n; i++) out.push(AXES[(start + i) % n]);
  return out;
}

// The tools where a "nothing left" conclusion is actually born: the target/scope summaries, the
// methodology/advice reads, and every scan/vector RESULTS read. The loud block fires on these when
// the body looks empty or clean. (The heartbeat still rides every other tool.)
const TERMINAL_PRONE = new Set([
  'whats_next', 'get_methodology', 'get_attack_vector_model',
  'get_target_summary', 'get_scope_overview', 'get_scope_stats', 'get_attack_surface',
  'get_endpoint_scan_results', 'get_endpoint_scan_status', 'query_consolidated_endpoints',
  'query_endpoints', 'get_discovered_endpoints', 'get_nuclei_finding_summary', 'query_nuclei_findings',
  'get_authz_summary', 'manage_threat_model', 'manage_attack_vectors', 'get_waf_probe_results',
  'get_tool_output', 'get_scan_results', 'get_scan_history',
  // the twelve per-class vector tools, on their results/status reads
  'manage_xss', 'manage_sqli', 'manage_cmdi', 'manage_redirect', 'manage_lfi', 'manage_cache',
  'manage_smuggling', 'manage_access_bypass', 'manage_graphql', 'manage_sensitive_leak',
  'manage_exposed_git', 'manage_misc', 'manage_param_enum', 'manage_fuzz',
]);

// Build the loud block. targetId (if known) makes the "next move" one-click; axisOffset rotates the
// three axes shown. Returns a plain object attached in place of the heartbeat string.
function loudBlock(targetId, axisOffset, goal) {
  const idPart = targetId ? ` target_id:${targetId}` : '';
  const block = {
    reframe: 'A clean or empty result is coverage of ONE axis, not a finished target. "Done" is not a ' +
      'real state for a live target; an empty section is the signal to enumerate deeper, not a verdict.',
    verify_the_negative: 'Before you trust this as clean, confirm the run exercised the target: a live ' +
      'positive control, a session that is not expired (read the token exp), request count greater than ' +
      'zero. A clean row on a dead session or an unsent scan measured the wall, not the app.',
    you_have_not_tried: pickAxes(axisOffset),
    next_move: 'Go back to enumeration now: manage_fuzz for new endpoints and FUZZ-in-path content ' +
      'discovery, manage_param_enum for hidden params, then the header and value axes by hand. Or call ' +
      `whats_next${idPart} for the target-specific next move. The next move is always available.`,
    not_a_stop: 'If you are genuinely blocked on the operator (a second account, an APK, a scope ruling, ' +
      'which you cannot do yourself), say so AND give the next un-blocked move in the same breath. A ' +
      'blocker closes one lead, never the target, and a parallel un-blocked axis almost always remains.',
  };
  // When a goal is active, the escalation anchors to it: this empty result is not "done" because the
  // goal is unmet, and the next axis should be aimed at proving its success_criteria.
  if (goal && goal.title) {
    const crit = typeof goal.success_criteria === 'string' ? goal.success_criteria : '';
    block.your_goal = {
      title: goal.title,
      status: goal.status,
      success_criteria: crit.length > 240 ? `${crit.slice(0, 240)} ...` : crit,
      reminder: 'There is an ACTIVE GOAL and it is unmet, so this empty result is definitively not ' +
        'done. Aim the next axis at proving the success_criteria above. The goal is reached only via ' +
        'propose then an isolated verify then the operator sign-off; you cannot mark it met yourself.',
    };
  }
  return block;
}

module.exports = {
  HEARTBEAT, heartbeat, NO_EXHAUSTED_RULE, SESSION_DECAY_RULE, GOAL_RULE,
  AXES, pickAxes, TERMINAL_PRONE, loudBlock,
};
