// Which tools have already been taught, per MCP session.
//
// The delivery model is progressive: the first call to a tool in a session gets the whole guidance
// object, every later call gets a one-line reminder. A scan loop that calls manage_sqli forty times
// should pay for the lesson once. Without this, guidance is a tax on exactly the workflows that run
// the most tools, and the first thing anyone would do is ask for it to be turned off.
//
// The set is per session and not per process because two agents connected at once are two different
// students. createServer() already runs once per SSE connection, so an instance-local set would have
// been nearly right, but the MCP SDK hands every tool handler an `extra` carrying the transport's
// sessionId (server/mcp.js executeToolHandler -> shared/protocol.js, which sets
// sessionId: capturedTransport?.sessionId), so keying on the real thing costs nothing and survives
// any future change to how servers are created.
//
// FALLBACK, and why it is shaped this way. When no session id reaches us the whole process shares
// one key. That is a real compromise: two anonymous agents would share a briefed-set and the second
// would get compact lines for tools it has never seen. It is bounded by the same inactivity expiry
// as everything else, so the worst case is one under-taught tool inside a two hour window, and the
// alternative (no memory at all) means re-sending the full object on every call in every loop. Note
// the failure direction that is NOT acceptable: an unrecognised or changed session id must land on a
// key with no history, which re-teaches. It must never land on someone else's set, or on a state
// where a tool is considered taught to an agent that never saw it.

// Two hours of inactivity and the session is forgotten. Long enough that a working session is never
// re-taught mid-engagement, short enough that the process-wide fallback key cannot accumulate a
// stale briefed-set across a lunch break.
const IDLE_MS = 2 * 60 * 60 * 1000;

// Sweep only when the map has grown enough to be worth walking. Sessions are cheap (a Set of tool
// name strings) and connections are few, so this is about never letting a long-lived container leak
// rather than about reclaiming meaningful memory.
const SWEEP_AT = 64;

const FALLBACK_KEY = '__no_session_id__';

// Hard cap on distinct sessions. The lazy idle-2h sweep does not bound reconnect churn (each SSE
// reconnect mints a new sessionId), so an LRU eviction of the oldest entry caps the Map regardless of
// idle age. The default is above the ~1000-agent fleet target so one-agent-per-connection sessions are
// not evicted (and re-taught, ledgers reset) mid-run; MCP_MAX_SESSIONS overrides. The LRU scan stays
// trivial at a few thousand entries.
const MAX_SESSIONS = (() => {
  const n = parseInt(process.env.MCP_MAX_SESSIONS, 10);
  return Number.isFinite(n) && n > 0 ? n : 2048;
})();

// sessionId -> {
//   briefed:Set, heartbeatIdx, consecutiveEmpty, lastSeen,
//   assignedRoleId:string|null,
//   ledger: { charsOut, charsIn, callCount, byTier:{}, byTopic:{},
//             byTool:{ [tool]:{tier,topic,charsOut,calls} }, strategy:string|null, lastTargetId:string|null }
// }
const sessions = new Map();

function newLedger() {
  return { charsOut: 0, charsIn: 0, callCount: 0, byTier: {}, byTopic: {},
    byTool: {}, strategy: null, lastTargetId: null };
}

function sweep(now) {
  for (const [key, state] of sessions) {
    if (now - state.lastSeen > IDLE_MS) sessions.delete(key);
  }
}

function stateFor(sessionId, now) {
  const key = typeof sessionId === 'string' && sessionId.length > 0 ? sessionId : FALLBACK_KEY;
  let state = sessions.get(key);
  if (state && now - state.lastSeen > IDLE_MS) {
    // Expired rather than absent, but the two mean the same thing to a caller: no history, so teach.
    sessions.delete(key);
    state = undefined;
  }
  if (!state) {
    if (sessions.size >= SWEEP_AT) sweep(now);
    // LRU cap: if still at the hard max after the idle sweep, evict the oldest-seen session.
    if (sessions.size >= MAX_SESSIONS) {
      let oldestKey; let oldest = Infinity;
      for (const [k, s] of sessions) { if (s.lastSeen < oldest) { oldest = s.lastSeen; oldestKey = k; } }
      if (oldestKey !== undefined) sessions.delete(oldestKey);
    }
    state = { briefed: new Set(), heartbeatIdx: 0, consecutiveEmpty: 0, lastSeen: now,
      assignedRoleId: null, ledger: newLedger() };
    sessions.set(key, state);
  }
  state.lastSeen = now;
  return state;
}

// True the first time this session sees this tool, false afterwards. Records the brief as a side
// effect, so the caller must not call it until it is certain it is going to attach something: a
// brief consumed on a call that attached nothing is a lesson the agent never received.
function firstBrief(sessionId, toolName, now = Date.now()) {
  const state = stateFor(sessionId, now);
  if (state.briefed.has(toolName)) return false;
  state.briefed.add(toolName);
  return true;
}

// The next rotation index for the keep-hunting heartbeat, per session. Rotates so two consecutive
// tool results never show the same reframe line (a repeated line reads as wallpaper and is scrolled
// past). Keyed and expired exactly like the briefed-set, so it survives a session the same way and a
// forgotten or changed session restarts the rotation rather than inheriting someone else's position.
function nextHeartbeat(sessionId, now = Date.now()) {
  const state = stateFor(sessionId, now);
  state.heartbeatIdx = (state.heartbeatIdx || 0) + 1;
  return state.heartbeatIdx;
}

// Track the run of consecutive empty/clean tool results, which is the pattern that precedes giving
// up (hit nothing, hit nothing again, conclude the target is dead). isEmpty=true increments the run,
// a productive result resets it to zero. Returns the current run length. This is deliberately a
// CONSECUTIVE counter, not a total: one quiet call is normal, a run of them is the quit signal, and a
// single productive result clears it. Conservative on purpose (the operator's alert-rarity rule): the
// loud block should be rare enough to still mean something.
function recordEmpty(sessionId, isEmpty, now = Date.now()) {
  const state = stateFor(sessionId, now);
  state.consecutiveEmpty = isEmpty ? (state.consecutiveEmpty || 0) + 1 : 0;
  return state.consecutiveEmpty;
}

// True if this session has seen this tool, without recording anything. For tests and diagnostics.
function hasBriefed(sessionId, toolName) {
  const key = typeof sessionId === 'string' && sessionId.length > 0 ? sessionId : FALLBACK_KEY;
  const state = sessions.get(key);
  if (!state) return false;
  if (Date.now() - state.lastSeen > IDLE_MS) return false;
  return state.briefed.has(toolName);
}

function forget(sessionId) {
  const key = typeof sessionId === 'string' && sessionId.length > 0 ? sessionId : FALLBACK_KEY;
  sessions.delete(key);
}

function reset() {
  sessions.clear();
}

// THE IDENTITY SEAM. The single documented swap-point for future SaaS auth. Today it returns the
// transport sessionId (string) or undefined; stateFor applies FALLBACK_KEY as before, so behaviour is
// unchanged. A SaaS build swaps the body to return an authenticated principal/tenant claim.
function principalFor(extra, _params) {
  return extra && typeof extra === 'object' && typeof extra.sessionId === 'string'
    ? extra.sessionId : undefined;
}

// Metering. Called from attachGuidance inside a try/catch (fail-open). chars is a FLOOR estimate of
// server OUTPUT bytes (chars/4 for a token floor); it NEVER gates anything. Stores counts+keys only,
// NEVER captured bodies.
function recordOut(sessionId, { tier, topic, tool, chars }, now = Date.now()) {
  const L = stateFor(sessionId, now).ledger;
  const n = Number(chars) || 0;
  L.charsOut += n; L.callCount += 1;
  L.byTier[tier] = (L.byTier[tier] || 0) + n;
  L.byTopic[topic] = (L.byTopic[topic] || 0) + n;
  const prev = L.byTool[tool] || { tier, topic, charsOut: 0, calls: 0 };
  prev.tier = tier; prev.topic = topic; prev.charsOut += n; prev.calls += 1;
  L.byTool[tool] = prev;
}

// Head fields (keep_hunting, role_hint, goal, guidance) ride EVERY result and are cross-cutting, not
// per-tool evictable, so they update the tier and topic totals but never byTool (which forgetWhere
// drops from). This is what makes by_tier reflect the always-on PERMANENT/SCOPE_TARGET head cost
// instead of folding it into the emitting tool's tier.
function recordHead(sessionId, { tier, topic, chars }, now = Date.now()) {
  const L = stateFor(sessionId, now).ledger;
  const n = Number(chars) || 0;
  if (n <= 0) return;
  L.charsOut += n;
  L.byTier[tier] = (L.byTier[tier] || 0) + n;
  L.byTopic[topic] = (L.byTopic[topic] || 0) + n;
}

// Record a strategy label for the budget report WITHOUT evicting. The advisory (gate off) path uses
// this so budget().strategy actually reflects what was set; setting a label is not a reclaim, so no
// tier is cleared and the keep-hunting counters are untouched.
function recordStrategy(sessionId, strategyId, now = Date.now()) {
  stateFor(sessionId, now).ledger.strategy = strategyId || null;
}

// Read-only budget snapshot for manage_context action:budget.
function budget(sessionId, now = Date.now()) {
  const L = stateFor(sessionId, now).ledger;
  return {
    chars_out: L.charsOut,
    est_tokens_floor: Math.ceil(L.charsOut / 4),
    call_count: L.callCount,
    by_tier: { ...L.byTier },
    by_topic: { ...L.byTopic },
    by_tool: Object.fromEntries(Object.entries(L.byTool).map(([k, v]) => [k, { ...v }])),
    strategy: L.strategy,
    last_target_id: L.lastTargetId,
    note: 'FLOOR, server-output-only estimate (chars/4). Early-return guards bypass metering, so this '
      + 'is a floor not a total; it never gates eviction.',
  };
}

// Selective forget. Clears briefed Set AND ledger meta in lockstep for every tool whose descriptor
// matches the predicate, so a forgotten tool re-teaches (full entry) on its next call. Returns the
// count forgotten. predicate({ tool, tier, topic }) -> boolean.
function forgetWhere(sessionId, predicate, now = Date.now()) {
  const state = stateFor(sessionId, now);
  const L = state.ledger;
  let forgotten = 0;
  for (const [tool, meta] of Object.entries(L.byTool)) {
    if (!predicate({ tool, tier: meta.tier, topic: meta.topic })) continue;
    // lockstep: remove from briefed so it re-teaches, and remove its ledger accounting.
    state.briefed.delete(tool);
    L.charsOut -= meta.charsOut;
    L.byTier[meta.tier] = Math.max(0, (L.byTier[meta.tier] || 0) - meta.charsOut);
    L.byTopic[meta.topic] = Math.max(0, (L.byTopic[meta.topic] || 0) - meta.charsOut);
    delete L.byTool[tool];
    forgotten += 1;
  }
  if (L.charsOut < 0) L.charsOut = 0;
  return forgotten;
}

// Session role state (advisory; no board).
function assignRole(sessionId, roleId, now = Date.now()) { stateFor(sessionId, now).assignedRoleId = roleId; }
function releaseRole(sessionId, now = Date.now()) { stateFor(sessionId, now).assignedRoleId = null; }
function assignedRole(sessionId, now = Date.now()) { return stateFor(sessionId, now).assignedRoleId; }

// Eviction path 1: explicit target switch. Clears SCOPE_TARGET + STRATEGY, keeps PERMANENT, records
// the new target, and returns a handoff summary. memory is required lazily to avoid a load cycle.
function switchTarget(sessionId, targetId, now = Date.now()) {
  const memory = require('./memory');
  const L = stateFor(sessionId, now).ledger;
  // Re-activating the SAME target is idempotent, not a switch. Dropping this target's freshly taught
  // SCOPE_TARGET/STRATEGY lessons and nulling its strategy on a no-op would be pure state loss, so a
  // repeat activate_target for the current target carries everything over unchanged.
  if (targetId && L.lastTargetId === targetId) {
    return { target_id: targetId, carried_over: ['unchanged: same target re-activated'], dropped: [] };
  }
  const carried_over = ['PERMANENT (methodology, goal frame, keep_hunting, role_hint)'];
  const dropped = [];
  const n = forgetWhere(sessionId, (d) =>
    d.tier === memory.TIERS.SCOPE_TARGET || d.tier === memory.TIERS.STRATEGY, now);
  if (n > 0) dropped.push(`${n} SCOPE_TARGET/STRATEGY tool lesson(s) stop re-serving and will re-teach`);
  L.lastTargetId = targetId || null;
  L.strategy = null;
  return { target_id: targetId || null, carried_over, dropped };
}

// Eviction path 2: strategy change. Clears STRATEGY only, keeps PERMANENT + SCOPE_TARGET. Returns a
// compaction/handoff summary naming carried_over vs DROP. Does NOT reset consecutiveEmpty (anti-thrash:
// a strategy switch must never silence the keep-hunting layer).
function setStrategy(sessionId, strategyId, now = Date.now()) {
  const memory = require('./memory');
  const L = stateFor(sessionId, now).ledger;
  const n = forgetWhere(sessionId, (d) => d.tier === memory.TIERS.STRATEGY, now);
  L.strategy = strategyId || null;
  return {
    strategy: L.strategy,
    carried_over: ['PERMANENT', 'SCOPE_TARGET (goal, recon/data lessons)'],
    dropped: n > 0 ? [`${n} STRATEGY tool lesson(s) stop re-serving and will re-teach`] : [],
  };
}

module.exports = {
  firstBrief,
  nextHeartbeat,
  recordEmpty,
  hasBriefed,
  forget,
  reset,
  principalFor,
  recordOut,
  recordHead,
  recordStrategy,
  budget,
  forgetWhere,
  assignRole,
  releaseRole,
  assignedRole,
  switchTarget,
  setStrategy,
  IDLE_MS,
  MAX_SESSIONS,
  FALLBACK_KEY,
  // Exported for the test that checks the map does not grow without bound.
  _sessions: sessions,
};
