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

// sessionId -> { briefed: Set<string>, lastSeen: number }
const sessions = new Map();

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
    state = { briefed: new Set(), lastSeen: now };
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

module.exports = {
  firstBrief,
  hasBriefed,
  forget,
  reset,
  IDLE_MS,
  FALLBACK_KEY,
  // Exported for the test that checks the map does not grow without bound.
  _sessions: sessions,
};
