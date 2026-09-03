// Session state and the durable capture queue.
//
// Everything lives in chrome.storage.session so it survives the browser terminating the MV3
// service worker. Module-level values are a cache, never the source of truth.
//
// The queue doubles as the merge buffer. A capture is enqueued immediately (so it is durable the
// moment it exists) but carries a `_mergeUntil` deadline; while that deadline is in the future,
// records arriving from another capture source for the same request merge into it instead of
// creating a duplicate row. The flush only ships entries whose deadline has passed.

export const STATE_KEY = 'crawlState';
export const QUEUE_KEY = 'crawlQueue';

export const MERGE_WINDOW_MS = 2500;
export const MAX_QUEUE_LENGTH = 5000;

// chrome.storage.session holds about 10 MB. Captures now carry request and response bodies, so the
// queue is bounded by bytes as well as by item count: a handful of large JSON responses would
// otherwise blow the quota, and a rejected write means the capture is lost entirely.
export const QUEUE_BYTE_LIMIT = 4 * 1024 * 1024;
// Past this, stop waiting for the debounce and ship immediately.
export const QUEUE_FLUSH_BYTES = 768 * 1024;

export function approximateSize(value) {
  try {
    return JSON.stringify(value).length;
  } catch (error) {
    return 0;
  }
}

// Strips the bodies from a capture while keeping everything that identifies it. Used when the queue
// is over budget: an endpoint recorded without its body is still worth far more than no record.
export function shedBodies(capture) {
  if (!capture.postData && !capture.responseBody) return capture;
  return {
    ...capture,
    postData: '',
    responseBody: '',
    requestBodyTruncated: Boolean(capture.postData) || capture.requestBodyTruncated,
    responseBodyTruncated: Boolean(capture.responseBody) || capture.responseBodyTruncated,
  };
}

export const EMPTY_STATE = {
  active: false,
  sessionId: null,
  scopeTargetId: null,
  targetUrl: null,
  scopeHosts: [],
  // Authored scope rules for this target, parsed. When non-empty these are the WHOLE boundary and
  // scopeHosts is not consulted, so a deny cannot be overridden by the host list.
  scopeRules: [],
  // Set only when a rule the framework accepted could not be parsed here, which means the two
  // evaluators disagree. Surfaced in the popup because recording by a different boundary than the
  // scanners enforce must never be a console-only fact.
  scopeRulesError: null,
  settings: null,
  apiBase: 'http://localhost/api',
  startedAt: null,
  lastHeartbeatAt: null,
  lastError: null,
  deepCapture: { enabled: false, attachedTabs: [], errors: [] },
  // Hosts seen but rejected by the scope filter, with a hit count. Surfaced in the popup so a
  // cross-domain API is a visible, one-click fix rather than silent data loss.
  observedOutOfScope: {},
  stats: {
    requestCount: 0,
    endpointCount: 0,
    queuedCount: 0,
    failedCount: 0,
    bodiesShed: 0,
    withResponseBody: 0,
  },
};

let stateCache = null;
let stateLoad = null;
let writeChain = Promise.resolve();

export async function getState() {
  if (stateCache) return stateCache;
  if (!stateLoad) {
    stateLoad = chrome.storage.session
      .get([STATE_KEY])
      .then((stored) => {
        stateCache = mergeDefaults(stored[STATE_KEY]);
        return stateCache;
      })
      .catch(() => {
        stateCache = { ...EMPTY_STATE };
        return stateCache;
      })
      .finally(() => {
        stateLoad = null;
      });
  }
  return stateLoad;
}

function mergeDefaults(stored) {
  const base = { ...EMPTY_STATE, ...(stored || {}) };
  base.stats = { ...EMPTY_STATE.stats, ...(base.stats || {}) };
  base.deepCapture = { ...EMPTY_STATE.deepCapture, ...(base.deepCapture || {}) };
  base.observedOutOfScope = { ...(base.observedOutOfScope || {}) };
  return base;
}

// Every storage mutation runs through one chain so concurrent event handlers cannot interleave a
// read-modify-write and lose an update.
export function runExclusive(fn) {
  const next = writeChain.then(fn);
  writeChain = next.then(
    () => {},
    () => {}
  );
  return next;
}

export function updateState(patch) {
  return runExclusive(async () => {
    const current = await getState();
    stateCache = { ...current, ...patch };
    await chrome.storage.session.set({ [STATE_KEY]: stateCache });
    return stateCache;
  });
}

export function mutateStats(fn) {
  return runExclusive(async () => {
    const current = await getState();
    stateCache = { ...current, stats: fn(current.stats) };
    await chrome.storage.session.set({ [STATE_KEY]: stateCache });
    return stateCache;
  });
}

export function clearState() {
  return runExclusive(async () => {
    stateCache = { ...EMPTY_STATE };
    await chrome.storage.session.set({ [STATE_KEY]: stateCache, [QUEUE_KEY]: [] });
    return stateCache;
  });
}

export function setState(next) {
  return runExclusive(async () => {
    stateCache = mergeDefaults(next);
    await chrome.storage.session.set({ [STATE_KEY]: stateCache });
    return stateCache;
  });
}

/* ------------------------------------------------------------------ out-of-scope observation */

export const OBSERVED_HOST_LIMIT = 60;
export const OBSERVED_HOST_KEEP = 40;

// Key order is first-seen order and must stay that way. The popup renders this map as a list with
// an Add button per row; ordering it by hit count meant rows reshuffled every time a count ticked
// and the button moved out from under the pointer. Trimming picks *which* hosts to keep by count,
// then rebuilds the map in the original order so surviving rows never move.
export function trimObservedHosts(observed) {
  const keys = Object.keys(observed);
  if (keys.length <= OBSERVED_HOST_LIMIT) return observed;

  const keep = new Set(
    [...keys].sort((a, b) => observed[b] - observed[a]).slice(0, OBSERVED_HOST_KEEP)
  );

  const trimmed = {};
  keys.forEach((key) => {
    if (keep.has(key)) trimmed[key] = observed[key];
  });
  return trimmed;
}

// Folds a batch of [host, count] pairs into the observed-out-of-scope tally. Capped so a page full
// of third-party beacons cannot grow state without bound; the most-seen hosts are the ones worth
// showing, because those are the ones likely to be the app's own API.
export function noteOutOfScopeHost(entries) {
  return runExclusive(async () => {
    const current = await getState();
    if (!current.active) return current;

    const observed = { ...current.observedOutOfScope };
    entries.forEach(([host, count]) => {
      observed[host] = (observed[host] || 0) + count;
    });

    stateCache = { ...current, observedOutOfScope: trimObservedHosts(observed) };

    await chrome.storage.session.set({ [STATE_KEY]: stateCache });
    return stateCache;
  });
}

/* ------------------------------------------------------------------ queue */

async function readQueue() {
  const stored = await chrome.storage.session.get([QUEUE_KEY]);
  return stored[QUEUE_KEY] || [];
}

// Adds a capture, or merges it into a recent entry describing the same request. `patch` fields
// only overwrite when the incoming source has better information, which is why bodies are applied
// with the "first non-empty wins, higher-precedence source overrides" rule below.
export function enqueueOrMerge(capture, sourcePrecedence) {
  return runExclusive(async () => {
    const current = await getState();
    if (!current.active) return { merged: false, queueLength: 0 };

    const queue = await readQueue();
    const now = Date.now();

    let merged = false;
    let gainedResponseBody = false;

    for (let i = queue.length - 1; i >= 0; i--) {
      const entry = queue[i];
      if (entry._mergeKey !== capture._mergeKey) continue;
      if (entry._mergeUntil <= now) break; // older entries are already sealed
      if ((entry.sources || []).includes(capture.sources[0])) continue;

      const before = Boolean(entry.responseBody);
      queue[i] = mergeCaptures(entry, capture, sourcePrecedence);
      gainedResponseBody = !before && Boolean(queue[i].responseBody);
      merged = true;
      break;
    }

    if (!merged) {
      queue.push({ ...capture, _mergeUntil: now + MERGE_WINDOW_MS });
      gainedResponseBody = Boolean(capture.responseBody);
    }

    let dropped = 0;
    if (queue.length > MAX_QUEUE_LENGTH) {
      dropped = queue.length - MAX_QUEUE_LENGTH;
      queue.splice(0, dropped);
    }

    // Bring the queue under the byte budget by shedding bodies from the oldest entries first, and
    // only dropping whole records if that is not enough. Losing a body is recoverable; losing the
    // fact that an endpoint exists is not.
    let bytes = approximateSize(queue);
    let shed = 0;
    for (let i = 0; i < queue.length && bytes > QUEUE_BYTE_LIMIT; i++) {
      if (!queue[i].postData && !queue[i].responseBody) continue;
      queue[i] = shedBodies(queue[i]);
      shed++;
      bytes = approximateSize(queue);
    }
    while (queue.length > 1 && bytes > QUEUE_BYTE_LIMIT) {
      queue.shift();
      dropped++;
      bytes = approximateSize(queue);
    }

    const written = await writeQueueSafely(queue);
    if (!written.ok) {
      // The write was rejected anyway (quota, most likely). Keep only the newest records rather
      // than letting the whole queue, and this capture with it, disappear.
      const salvage = queue.slice(-25).map(shedBodies);
      dropped += queue.length - salvage.length;
      const retry = await writeQueueSafely(salvage);
      if (!retry.ok) {
        await chrome.storage.session.set({ [QUEUE_KEY]: [] }).catch(() => {});
        dropped += salvage.length;
      }
    }

    const state = await getState();
    stateCache = {
      ...state,
      stats: {
        ...state.stats,
        requestCount: merged ? state.stats.requestCount : state.stats.requestCount + 1,
        queuedCount: queue.length,
        failedCount: state.stats.failedCount + dropped,
        bodiesShed: (state.stats.bodiesShed || 0) + shed,
        withResponseBody: state.stats.withResponseBody + (gainedResponseBody ? 1 : 0),
      },
    };
    await chrome.storage.session.set({ [STATE_KEY]: stateCache }).catch(() => {});

    return { merged, queueLength: queue.length, bytes };
  });
}

async function writeQueueSafely(queue) {
  try {
    await chrome.storage.session.set({ [QUEUE_KEY]: queue });
    return { ok: true };
  } catch (error) {
    console.warn('[MANUAL-CRAWL] Queue write rejected:', error && error.message);
    return { ok: false, error };
  }
}

function isEmptyValue(value) {
  if (value === undefined || value === null || value === '') return true;
  if (typeof value === 'object' && !Object.keys(value).length) return true;
  return false;
}

// Merges two records describing the same request. Non-empty always beats empty; when both sides
// have a value the higher-precedence source wins (debugger > hook > webrequest).
export function mergeCaptures(existing, incoming, sourcePrecedence) {
  const rank = (source) => sourcePrecedence.indexOf(source);
  const existingRank = Math.max(-1, ...(existing.sources || []).map(rank));
  const incomingRank = Math.max(-1, ...(incoming.sources || []).map(rank));
  const incomingWins = incomingRank > existingRank;

  const pick = (a, b) => {
    if (isEmptyValue(a) && isEmptyValue(b)) return a;
    if (isEmptyValue(a)) return b;
    if (isEmptyValue(b)) return a;
    return incomingWins ? b : a;
  };

  // Union of both header maps; the higher-precedence source wins on a conflicting name.
  const unionHeaders = (a, b) =>
    incomingWins ? { ...(a || {}), ...(b || {}) } : { ...(b || {}), ...(a || {}) };

  return {
    _mergeKey: existing._mergeKey,
    _mergeUntil: existing._mergeUntil,
    sources: Array.from(new Set([...(existing.sources || []), ...(incoming.sources || [])])),
    url: existing.url,
    method: existing.method,
    timestamp: existing.timestamp,
    // Any non-zero status beats zero: an aborted webRequest record has none, but the page hook or
    // the debugger may still have observed the real response.
    statusCode: existing.statusCode || incoming.statusCode || 0,
    headers: unionHeaders(existing.headers, incoming.headers),
    responseHeaders: unionHeaders(existing.responseHeaders, incoming.responseHeaders),
    postData: pick(existing.postData, incoming.postData),
    responseBody: pick(existing.responseBody, incoming.responseBody),
    postParams: pick(existing.postParams, incoming.postParams),
    getParams: pick(existing.getParams, incoming.getParams),
    bodyType: pick(existing.bodyType, incoming.bodyType),
    mimeType: pick(existing.mimeType, incoming.mimeType) || 'unknown',
    endpoint: pick(existing.endpoint, incoming.endpoint),
    graphqlOperation: pick(existing.graphqlOperation, incoming.graphqlOperation),
    resourceType: pick(existing.resourceType, incoming.resourceType),
    initiator: pick(existing.initiator, incoming.initiator),
    tabId:
      existing.tabId !== null && existing.tabId !== undefined && existing.tabId !== -1
        ? existing.tabId
        : incoming.tabId,
    redirectChain: (existing.redirectChain || []).length
      ? existing.redirectChain
      : incoming.redirectChain || [],
    error: pick(existing.error, incoming.error),
    durationMs: existing.durationMs || incoming.durationMs || 0,
    requestBodyTruncated: Boolean(existing.requestBodyTruncated || incoming.requestBodyTruncated),
    responseBodyTruncated: Boolean(existing.responseBodyTruncated || incoming.responseBodyTruncated),
  };
}

// Returns the leading run of entries whose merge window has closed, bounded by both a count and a
// byte budget. The queue is append-only with a constant window, so it is already ordered by
// deadline and a prefix is always correct.
//
// The byte budget matters: forty captures each carrying a large response body is a multi-megabyte
// upload that stalls or times out, and a failed batch used to be discarded outright.
export function takeReady(queue, now, limit, byteLimit) {
  const ready = [];
  let bytes = 0;
  for (const entry of queue) {
    if (entry._mergeUntil > now) break;
    const size = approximateSize(entry);
    // Always take at least one, so a single oversized capture cannot wedge the queue forever.
    if (ready.length > 0 && byteLimit && bytes + size > byteLimit) break;
    ready.push(entry);
    bytes += size;
    if (ready.length >= limit) break;
  }
  return ready;
}

export function stripInternal(capture) {
  const clean = { ...capture };
  delete clean._mergeKey;
  delete clean._mergeUntil;
  return clean;
}

export function withQueue(fn) {
  return runExclusive(async () => {
    const queue = await readQueue();
    const result = await fn(queue);
    return result;
  });
}

export async function persistQueue(queue) {
  await chrome.storage.session.set({ [QUEUE_KEY]: queue });
}

export async function loadQueue() {
  return readQueue();
}
