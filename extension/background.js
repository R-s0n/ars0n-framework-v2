// Ars0n Framework manual crawl service worker.
//
// Three capture sources feed one durable queue:
//
//   webrequest  always on. Metadata, real headers (including cookies), status, redirects, errors.
//               Sees everything the browser sends, but never a body.
//   hook        always on. The page's own fetch/XHR/sendBeacon, with request and response bodies.
//               This is what makes a JavaScript-driven API surface visible at all.
//   debugger    opt-in. Everything else with bodies: navigations, subresources, form posts,
//               worker traffic. Costs the Chrome automation banner and conflicts with DevTools.
//
// Records from different sources describing the same request are merged in the queue rather than
// stored twice; see lib/state.js for the merge window.
//
// The controlling constraint remains that an MV3 service worker is terminated after roughly 30
// seconds of inactivity, so session state lives in chrome.storage.session and module-level values
// are only a cache.
//
// A second, unrelated session also lives in this worker: auth flow recording. It shares the
// webRequest event stream and nothing else. See the "auth flow recording" section near the bottom.

import {
  EMPTY_STATE,
  QUEUE_FLUSH_BYTES,
  approximateSize,
  getState,
  setState,
  updateState,
  mutateStats,
  clearState,
  runExclusive,
  enqueueOrMerge,
  noteOutOfScopeHost,
  takeReady,
  stripInternal,
  loadQueue,
  persistQueue,
} from './lib/state.js';

import {
  normalizeTargetUrl,
  normalizeHostEntry,
  buildScopeHosts,
  hostInScope,
  isStaticMedia,
  buildEndpointName,
  deriveGraphQLOperation,
  lowerHeaderMap,
  headerValue,
  parseParams,
  parseQueryParams,
  truncateBody,
  isTextualMime,
  mergeKey,
} from './lib/scope.js';

import {
  configureDeepCapture,
  syncAttachments,
  detachAll,
  detachFromTab,
} from './lib/deepcapture.js';

const KEEPALIVE_ALARM = 'ars0n-crawl-keepalive';
const FLUSH_BATCH_SIZE = 40;
// Cap a single upload so a batch of body-carrying captures stays a reasonable POST.
const FLUSH_BATCH_BYTES = 3 * 1024 * 1024;
const FLUSH_DEBOUNCE_MS = 1200;
const HEARTBEAT_INTERVAL_MS = 20000;
const PENDING_TTL_MS = 120000;
// 128 KB per body. chrome.storage.session is a ~10 MB budget shared by the whole queue, so a
// larger default meant a handful of captures could exhaust it and start losing records.
const DEFAULT_MAX_BODY_BYTES = 131072;
const DEFAULT_FRAMEWORK_URL = 'http://localhost';

// Later entries win when two sources disagree about the same field.
const SOURCE_PRECEDENCE = ['webrequest', 'hook', 'debugger'];

let flushTimer = null;
let flushInFlight = null;

// In-flight webRequest records being assembled across event stages. Deliberately in-memory: they
// are short-lived, and every stage can reconstruct a usable record on its own if an earlier stage
// was missed during a worker cold start.
const pending = new Map();
const seenEndpoints = new Set();

// Hosts rejected by the scope filter, counted in memory and folded into persisted state on a timer.
// Writing storage on every rejected request would mean a storage write per third-party beacon on
// an ad-heavy page.
const outOfScopeBuffer = new Map();
let outOfScopeFlushTimer = null;

function noteOutOfScope(hostname) {
  outOfScopeBuffer.set(hostname, (outOfScopeBuffer.get(hostname) || 0) + 1);
  if (outOfScopeFlushTimer) return;
  outOfScopeFlushTimer = setTimeout(() => {
    outOfScopeFlushTimer = null;
    void flushOutOfScope();
  }, 3000);
}

async function flushOutOfScope() {
  if (outOfScopeBuffer.size === 0) return;
  const batch = Array.from(outOfScopeBuffer.entries());
  outOfScopeBuffer.clear();
  await noteOutOfScopeHost(batch);
}

/* ------------------------------------------------------------------ capture config */

function maxBodyBytes(state) {
  const configured = state.settings && state.settings.maxBodyBytes;
  return typeof configured === 'number' && configured > 0 ? configured : DEFAULT_MAX_BODY_BYTES;
}

function captureResponseBodies(state) {
  return !(state.settings && state.settings.captureResponseBodies === false);
}

// Shared predicate so all three sources agree on what is in scope.
function shouldCapture(url, state) {
  if (!state.active || !state.scopeHosts.length) return { capture: false };

  let parsed;
  try {
    parsed = new URL(url);
  } catch (error) {
    return { capture: false };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:' &&
      parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
    return { capture: false };
  }

  // Never record our own traffic to the framework API.
  try {
    if (parsed.origin === new URL(state.apiBase).origin) return { capture: false };
  } catch (error) {
    /* apiBase malformed; fall through */
  }

  if (!hostInScope(parsed.hostname, state.scopeHosts)) {
    return { capture: false, outOfScopeHost: parsed.hostname.toLowerCase() };
  }

  if (state.settings && !state.settings.captureStatic && isStaticMedia(parsed.pathname)) {
    return { capture: false };
  }

  return { capture: true };
}

/* ------------------------------------------------------------------ queue plumbing */

// Normalizes a record from any source into the shape the framework stores, then queues it.
async function submitCapture(raw, source) {
  const state = await getState();
  if (!state.active || !state.sessionId) return;

  const check = shouldCapture(raw.url, state);
  if (!check.capture) {
    if (check.outOfScopeHost) noteOutOfScope(check.outOfScopeHost);
    return;
  }

  const limit = maxBodyBytes(state);
  const requestBody = truncateBody(raw.postData || '', limit);
  const responseBody = truncateBody(raw.responseBody || '', limit);

  const method = String(raw.method || 'GET').toUpperCase();
  const graphqlOperation = deriveGraphQLOperation(raw.url, requestBody.body);
  const endpoint = buildEndpointName(raw.url, method, requestBody.body);

  const endpointKey = `${method}:${endpoint}`;
  if (!seenEndpoints.has(endpointKey)) seenEndpoints.add(endpointKey);

  const requestContentType = headerValue(raw.headers, 'content-type') || raw.bodyType || '';
  const responseContentType = headerValue(raw.responseHeaders, 'content-type') || raw.mimeType || '';

  const capture = {
    _mergeKey: mergeKey(method, raw.url),
    sources: [source],
    url: raw.url,
    endpoint,
    method,
    statusCode: raw.statusCode || 0,
    headers: raw.headers || {},
    responseHeaders: raw.responseHeaders || {},
    postData: requestBody.body,
    requestBodyTruncated: Boolean(raw.requestBodyTruncated) || requestBody.truncated,
    responseBody: responseBody.body,
    responseBodyTruncated: Boolean(raw.responseBodyTruncated) || responseBody.truncated,
    getParams: parseQueryParams(raw.url),
    postParams: parseParams(requestBody.body, requestContentType),
    bodyType: requestContentType,
    mimeType: responseContentType || 'unknown',
    graphqlOperation: graphqlOperation || '',
    resourceType: raw.resourceType || '',
    initiator: raw.initiator || '',
    redirectChain: raw.redirectChain || [],
    error: raw.error || '',
    durationMs: raw.durationMs || 0,
    tabId: raw.tabId === undefined ? null : raw.tabId,
    timestamp: new Date(raw.timestamp || Date.now()).toISOString(),
  };

  const result = await enqueueOrMerge(capture, SOURCE_PRECEDENCE).catch((error) => {
    console.error('[MANUAL-CRAWL] Failed to queue capture:', error);
    return null;
  });

  // Ship early when the queue is heavy rather than waiting out the debounce, so bodies spend as
  // little time as possible occupying the session-storage budget.
  scheduleFlush(result && result.bytes > QUEUE_FLUSH_BYTES ? 0 : undefined);
}

function scheduleFlush(delayMs) {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    void flushQueue();
  }, delayMs || FLUSH_DEBOUNCE_MS);
}

// Returns the in-flight flush when one is already running, so callers that need the queue drained
// (Stop, in particular) actually wait for it instead of returning early and losing the tail.
function flushQueue(options) {
  if (flushInFlight) return flushInFlight;
  flushInFlight = runFlush(options || {}).finally(() => {
    flushInFlight = null;
  });
  return flushInFlight;
}

async function runFlush(options) {
  try {
    const state = await getState();
    if (!state.active || !state.sessionId) return;

    for (;;) {
      const queue = await loadQueue();
      if (queue.length === 0) break;

      // `force` ignores the merge window so Stop does not strand the last couple of seconds.
      const now = options.force ? Number.MAX_SAFE_INTEGER : Date.now();
      const batch = takeReady(queue, now, FLUSH_BATCH_SIZE, FLUSH_BATCH_BYTES);
      if (batch.length === 0) {
        // The head of the queue is still inside its merge window. Come back exactly when it opens
        // rather than waiting for the next keepalive tick, which would delay uploads by ~30s.
        const waitMs = Math.max(250, queue[0]._mergeUntil - Date.now() + 50);
        scheduleFlush(waitMs);
        break;
      }

      let result;
      try {
        result = await postJSON(`${state.apiBase}/manual-crawl/capture/batch`, {
          sessionId: state.sessionId,
          captures: batch.map(stripInternal),
        });
      } catch (error) {
        await updateState({ lastError: 'Framework unreachable: ' + error.message });
        break;
      }

      if (result.ok) {
        await dropFromQueue(batch.length);
        const rejected = result.body.rejected || 0;
        await mutateStats((stats) => ({
          ...stats,
          requestCount: result.body.requestCount ?? stats.requestCount,
          endpointCount: result.body.endpointCount ?? stats.endpointCount,
          failedCount: stats.failedCount + rejected,
        }));
        await updateState({
          lastError: rejected
            ? `${rejected} capture(s) could not be stored by the framework`
            : null,
          lastHeartbeatAt: Date.now(),
        });
        continue;
      }

      if (result.status === 404 || result.status === 409) {
        console.warn('[MANUAL-CRAWL] Session rejected by framework:', result.body);
        // The queue is kept, not dropped.
        //
        // A 409 means the framework has marked this session abandoned, which happens whenever the
        // heartbeat goes quiet: the machine slept, the MV3 worker was suspended past its alarm, or
        // somebody opened the results modal, which fires /manual-crawl/cleanup. None of those mean
        // the operator stopped browsing, and all of them used to end with every unflushed capture
        // being deleted here while the tooling said "Nothing that was captured is lost".
        //
        // Holding the queue costs a little storage and lets the next started session flush it.
        const kept = await loadQueue();
        console.warn(
          `[MANUAL-CRAWL] Keeping ${kept.length} unflushed capture(s); ` +
          'they will be sent when a new recording session starts.');
        await stopCaptureSession({
          notifyFramework: false,
          flushFirst: false,
          reason: result.body.message || 'Capture session is no longer active on the framework',
        });
        break;
      }

      console.error('[MANUAL-CRAWL] Batch rejected:', result.status, result.body);
      await dropFromQueue(batch.length);
      await mutateStats((stats) => ({
        ...stats,
        failedCount: stats.failedCount + batch.length,
      }));
      await updateState({
        lastError: `Framework rejected ${batch.length} captures (${result.status})`,
      });
    }
  } finally {
    void broadcastState();
  }
}

async function dropFromQueue(count) {
  const remaining = await runExclusive(async () => {
    const queue = await loadQueue();
    const next = queue.slice(count);
    await persistQueue(next);
    return next;
  });
  await mutateStats((stats) => ({ ...stats, queuedCount: remaining.length }));
}

async function postJSON(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  let body = {};
  try {
    body = await response.json();
  } catch (error) {
    /* non-JSON error page */
  }

  return { ok: response.ok, status: response.status, body: body || {} };
}

/* ------------------------------------------------------------------ heartbeat */

async function sendHeartbeat(force) {
  const state = await getState();
  if (!state.active || !state.sessionId) return;

  const since = Date.now() - (state.lastHeartbeatAt || 0);
  if (!force && since < HEARTBEAT_INTERVAL_MS) return;

  let result;
  try {
    result = await postJSON(`${state.apiBase}/manual-crawl/heartbeat`, {
      sessionId: state.sessionId,
      stats: state.stats,
      // So the framework can show which hosts were seen but not captured; the user is usually
      // looking at the results modal, not the extension popup.
      observedOutOfScope: state.observedOutOfScope || {},
    });
  } catch (error) {
    await updateState({ lastError: 'Framework unreachable: ' + error.message });
    return;
  }

  if (result.ok) {
    await mutateStats((stats) => ({
      ...stats,
      requestCount: result.body.requestCount ?? stats.requestCount,
      endpointCount: result.body.endpointCount ?? stats.endpointCount,
    }));
    await updateState({ lastHeartbeatAt: Date.now(), lastError: null });
    void broadcastState();
    return;
  }

  if (result.status === 404 || result.status === 409) {
    await stopCaptureSession({
      notifyFramework: false,
      flushFirst: false,
      reason: result.body.message || 'Capture session is no longer active on the framework',
    });
  }
}

/* ------------------------------------------------------------------ session control */

// One writer for the toolbar badge. The crawl and the auth recorder are independent sessions and
// either can be running alone, so the badge is derived from both rather than each session writing
// it directly: stopping a crawl used to blank the badge, which would have hidden a recording that
// was still running.
async function applyBadge() {
  const [crawl, auth] = await Promise.all([getState(), getAuthState()]);
  const text = crawl.active ? 'REC' : auth.active ? 'AUTH' : '';
  await chrome.action.setBadgeText({ text });
  if (text) await chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
}

async function startCaptureSession(settings, frameworkUrl) {
  try {
    const baseUrl = (frameworkUrl || DEFAULT_FRAMEWORK_URL).replace(/\/+$/, '');
    const apiBase = baseUrl + '/api';

    const targetUrlObj = normalizeTargetUrl(settings && settings.targetUrl);
    if (!targetUrlObj) {
      throw new Error(`Target "${settings && settings.targetUrl}" is not a usable URL`);
    }
    if (!settings.scopeTargetId) throw new Error('No scope target selected');

    const scopeHosts = buildScopeHosts(targetUrlObj, settings);
    console.log('[MANUAL-CRAWL] Starting session. In-scope hosts:', scopeHosts);

    const result = await postJSON(`${apiBase}/manual-crawl/start`, {
      targetUrl: targetUrlObj.origin,
      scopeTargetId: settings.scopeTargetId,
    });
    if (!result.ok) throw new Error(result.body.message || `Framework returned ${result.status}`);

    pending.clear();
    seenEndpoints.clear();

    await runExclusive(() => persistQueue([]));
    await setState({
      ...EMPTY_STATE,
      active: true,
      sessionId: result.body.sessionId,
      scopeTargetId: result.body.scopeTargetId || settings.scopeTargetId,
      targetUrl: targetUrlObj.origin,
      scopeHosts,
      settings,
      apiBase,
      startedAt: Date.now(),
      lastHeartbeatAt: Date.now(),
      deepCapture: { enabled: Boolean(settings.deepCapture), attachedTabs: [], errors: [] },
    });

    await chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.5 });
    await applyBadge();

    if (settings.deepCapture) await refreshDeepCapture();
    await pushConfigToPages();
    void broadcastState();

    console.log('[MANUAL-CRAWL] Session started:', result.body.sessionId);
    return { success: true, sessionId: result.body.sessionId, scopeHosts };
  } catch (error) {
    console.error('[MANUAL-CRAWL] Failed to start session:', error);
    await detachAll();
    await clearState();
    await applyBadge();
    await pushConfigToPages();
    void broadcastState();
    return { success: false, error: error.message };
  }
}

async function stopCaptureSession(options) {
  const opts = options || {};
  const state = await getState();
  const stats = { ...state.stats };

  try {
    if (state.active && state.sessionId) {
      if (opts.flushFirst !== false) {
        // Wait out any flush already running (it would otherwise swallow the force), then ship
        // everything, including records still inside their merge window.
        await flushQueue();
        await flushQueue({ force: true });
      }
      if (opts.notifyFramework !== false) {
        try {
          await postJSON(`${state.apiBase}/manual-crawl/stop`, { sessionId: state.sessionId, stats });
        } catch (error) {
          console.warn('[MANUAL-CRAWL] Could not notify framework of stop:', error.message);
        }
      }
    }
  } finally {
    await chrome.alarms.clear(KEEPALIVE_ALARM);
    await detachAll();
    pending.clear();
    seenEndpoints.clear();
    await clearState();
    if (opts.reason) await updateState({ lastError: opts.reason });
    await applyBadge();
    await pushConfigToPages();
    void broadcastState();
  }

  console.log('[MANUAL-CRAWL] Session stopped. Final stats:', stats);
  return { success: true, stats, reason: opts.reason || null };
}

// Recomputes scope from current settings and pushes it everywhere it is enforced.
async function applyScopeChange(settingsPatch) {
  const state = await getState();
  const settings = { ...(state.settings || {}), ...settingsPatch };
  const targetUrlObj = normalizeTargetUrl(state.targetUrl);
  const scopeHosts = buildScopeHosts(targetUrlObj, settings);

  // A host that just came into scope is no longer "observed out of scope".
  const observed = { ...state.observedOutOfScope };
  Object.keys(observed).forEach((host) => {
    if (hostInScope(host, scopeHosts)) delete observed[host];
  });

  await updateState({ settings, scopeHosts, observedOutOfScope: observed });
  await pushConfigToPages();
  if (state.deepCapture && state.deepCapture.enabled) await refreshDeepCapture();
  void broadcastState();
  return scopeHosts;
}

/* ------------------------------------------------------------------ deep capture wiring */

configureDeepCapture({
  onCapture: (record) => void submitCapture(record, 'debugger'),
  getConfig: async () => {
    const state = await getState();
    const limit = maxBodyBytes(state);
    return {
      active: state.active,
      captureResponseBodies: captureResponseBodies(state),
      inScope: (url) => shouldCapture(url, state).capture,
      isTextualMime,
      truncate: (body) => truncateBody(body, limit),
    };
  },
});

async function refreshDeepCapture() {
  const state = await getState();
  if (!state.active || !state.deepCapture.enabled) {
    await detachAll();
    await updateState({ deepCapture: { ...state.deepCapture, attachedTabs: [], errors: [] } });
    return;
  }

  const result = await syncAttachments(state.scopeHosts);
  await updateState({
    deepCapture: { ...state.deepCapture, attachedTabs: result.attached, errors: result.errors },
  });
  void broadcastState();
}

/* ------------------------------------------------------------------ webRequest source */

function sweepPending() {
  const cutoff = Date.now() - PENDING_TTL_MS;
  for (const [requestId, record] of pending) {
    if (record.timestamp < cutoff) pending.delete(requestId);
  }
}

// Every stage can create the pending record. If the worker was cold-started partway through a
// request, later stages still produce a usable capture instead of dropping it entirely.
function touchPending(details) {
  let record = pending.get(details.requestId);
  if (!record) {
    record = {
      requestId: details.requestId,
      url: details.url,
      method: String(details.method || 'GET').toUpperCase(),
      tabId: typeof details.tabId === 'number' ? details.tabId : null,
      timestamp: Date.now(),
      postData: '',
      headers: {},
      responseHeaders: {},
      statusCode: 0,
      resourceType: details.type || '',
      redirectChain: [],
    };
    pending.set(details.requestId, record);
  }
  return record;
}

function parseWebRequestBody(requestBody) {
  if (!requestBody) return '';

  if (requestBody.formData) {
    const formData = {};
    for (const [key, values] of Object.entries(requestBody.formData)) {
      formData[key] = values.length === 1 ? values[0] : values;
    }
    return JSON.stringify(formData);
  }

  if (requestBody.raw && requestBody.raw.length > 0) {
    try {
      const decoder = new TextDecoder('utf-8');
      // A body can arrive split across several elements.
      return requestBody.raw
        .map((chunk) => (chunk && chunk.bytes ? decoder.decode(new Uint8Array(chunk.bytes)) : ''))
        .join('');
    } catch (error) {
      console.error('[MANUAL-CRAWL] Error decoding raw request body:', error);
    }
  }

  return '';
}

async function guardedStage(details, mutate, noteRejection) {
  const state = await getState();
  const check = shouldCapture(details.url, state);
  if (!check.capture) {
    // Counted only on the first lifecycle stage; otherwise one rejected request would be tallied
    // four or five times.
    if (noteRejection && check.outOfScopeHost) noteOutOfScope(check.outOfScopeHost);
    return null;
  }
  return mutate(touchPending(details));
}

// Capture is scoped by host, not by tab. Requests issued by a page's own service worker arrive
// with tabId -1, and OAuth popups and target="_blank" flows arrive on a different tab; filtering
// by tab id discarded all of them.
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    void (async () => {
      sweepPending();
      await guardedStage(
        details,
        (record) => {
          record.postData = parseWebRequestBody(details.requestBody);
        },
        true
      );
    })();
  },
  { urls: ['<all_urls>'] },
  ['requestBody']
);

// 'extraHeaders' is required for Chrome to expose Cookie on requests and Set-Cookie on responses.
chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    void guardedStage(details, (record) => {
      record.headers = lowerHeaderMap(details.requestHeaders);
    });
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders', 'extraHeaders']
);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    void guardedStage(details, (record) => {
      record.statusCode = details.statusCode;
      record.responseHeaders = lowerHeaderMap(details.responseHeaders);
    });
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders', 'extraHeaders']
);

// A redirect keeps the same requestId, so without this the intermediate hops vanish and only the
// final destination is recorded.
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    void guardedStage(details, (record) => {
      record.redirectChain = record.redirectChain || [];
      record.redirectChain.push({
        location: details.redirectUrl,
        statusCode: details.statusCode,
        from: details.url,
      });
    });
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders', 'extraHeaders']
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    void (async () => {
      const record = await guardedStage(details, (entry) => {
        if (!entry.statusCode) entry.statusCode = details.statusCode;
        return entry;
      });
      if (!record) return;
      pending.delete(details.requestId);
      await submitCapture(toRawRecord(record), 'webrequest');
    })();
  },
  { urls: ['<all_urls>'] }
);

// Aborted and failed requests used to be discarded. Single-page apps cancel in-flight fetches
// constantly (route changes, React strict-mode double effects, request de-duplication), and those
// cancelled calls are still real endpoints worth testing.
chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    void (async () => {
      const record = pending.get(details.requestId);
      pending.delete(details.requestId);
      if (!record) return;

      const state = await getState();
      if (!shouldCapture(details.url, state).capture) return;

      record.error = details.error || 'request failed';
      await submitCapture(toRawRecord(record), 'webrequest');
    })();
  },
  { urls: ['<all_urls>'] }
);

function toRawRecord(record) {
  return {
    url: record.url,
    method: record.method,
    statusCode: record.statusCode,
    headers: record.headers,
    responseHeaders: record.responseHeaders,
    postData: record.postData,
    responseBody: '',
    mimeType: headerValue(record.responseHeaders, 'content-type'),
    resourceType: record.resourceType,
    redirectChain: record.redirectChain || [],
    error: record.error || '',
    durationMs: Date.now() - record.timestamp,
    tabId: record.tabId,
    timestamp: record.timestamp,
  };
}

/* ------------------------------------------------------------------ page hook source */

// The one place the page hook's configuration is decided, because two independent sessions can
// want it on. The manual crawl owns it whenever it is running, exactly as before. When only an auth
// recording is running the hook is switched on for the hosts that recording has already seen:
// webRequest cannot read a response body, and the login response carrying the session token is the
// entire point of recording an auth flow. Hook records that arrive with no crawl running are
// dropped by submitCapture and used only as a body source by the recorder.
async function buildHookConfig() {
  const state = await getState();
  if (state.active) {
    return {
      active: true,
      scopeHosts: state.scopeHosts || [],
      maxBodyBytes: maxBodyBytes(state),
      captureResponseBodies: captureResponseBodies(state),
    };
  }

  const auth = await getAuthState();
  if (auth.active) {
    return {
      active: true,
      scopeHosts: auth.observedHosts || [],
      maxBodyBytes: AUTH_MAX_BODY_BYTES,
      captureResponseBodies: true,
    };
  }

  return {
    active: false,
    scopeHosts: [],
    maxBodyBytes: maxBodyBytes(state),
    captureResponseBodies: captureResponseBodies(state),
  };
}

// Pushes the current scope to every page hook. The hook does no work while inactive, so this is
// also how capture is switched off inside pages.
async function pushConfigToPages() {
  const config = await buildHookConfig();

  try {
    const tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
    tabs.forEach((tab) => {
      chrome.tabs.sendMessage(tab.id, { action: 'hookConfig', config }).catch(() => {});
    });
  } catch (error) {
    /* tabs unavailable */
  }
  return config;
}

/* ------------------------------------------------------------------ auth flow recording */

// Recording an authentication flow is a second, completely independent session. It shares the
// service worker and the webRequest event stream with the manual crawl and nothing else: its own
// storage keys, its own queue, its own alarm, its own write chain, its own endpoints. Either can be
// started and stopped while the other runs, and neither needs the other to be active.
//
// The capture rule is the inverse of the crawl's: while recording, every request the browser makes
// is recorded, in order, with no scope filter at all. That is deliberate. A real login leaves the
// target's domain almost immediately (an identity provider, an MFA vendor, a magic-link
// redirector), and the hop that hands the session back is exactly the one worth replaying, so a
// host filter would record half a flow and the half it dropped would be the interesting half.

const AUTH_KEEPALIVE_ALARM = 'ars0n-auth-recording-keepalive';
const AUTH_STATE_KEY = 'authRecordingState';
const AUTH_QUEUE_KEY = 'authRecordingQueue';

const AUTH_CATEGORIES = ['register', 'login', 'mfa_otp', 'magic_link', 'reset'];

const AUTH_FLUSH_BATCH_SIZE = 25;
const AUTH_FLUSH_BATCH_BYTES = 3 * 1024 * 1024;
const AUTH_FLUSH_DEBOUNCE_MS = 1500;
const AUTH_HEARTBEAT_INTERVAL_MS = 20000;
// A finished record waits this long before it is uploaded, so a response body arriving late from
// the page hook still lands on the row it belongs to instead of being dropped.
const AUTH_SETTLE_MS = 1500;
const AUTH_MAX_BODY_BYTES = 131072;
// Smaller than the crawl's budget because both queues share the same ~10 MB of session storage and
// the crawl is the one that runs for hours; a recording is a couple of minutes long.
const AUTH_QUEUE_BYTE_LIMIT = 2 * 1024 * 1024;
const AUTH_MAX_QUEUE_LENGTH = 3000;
const AUTH_PENDING_TTL_MS = 120000;
const AUTH_BODY_STASH_TTL_MS = 30000;
const AUTH_BODY_STASH_LIMIT = 80;
const AUTH_HOST_LIMIT = 40;
const AUTH_SEQ_BLOCK = 100;
const AUTH_SEQ_REFILL_AT = 32;

const EMPTY_AUTH_STATE = {
  // Set when this recording was started in the framework UI rather than in the popup. Adopted
  // recordings watch for the UI stopping them; ones started here are stopped from here.
  adopted: false,
  active: false,
  recordingId: null,
  scopeTargetId: null,
  name: '',
  category: 'login',
  baseUrl: '',
  apiBase: 'http://localhost/api',
  // High-water mark for sequence numbers, reserved in blocks. See allocateAuthSeq.
  nextSeq: 1,
  // Hosts this recording has already touched. Only used to switch the page hook on for them when
  // no manual crawl is running; see buildHookConfig.
  observedHosts: [],
  startedAt: null,
  lastHeartbeatAt: null,
  lastError: null,
  stats: { requestCount: 0, queuedCount: 0, failedCount: 0 },
};

// In-flight webRequest records, keyed by requestId. Separate from the crawl's `pending` map on
// purpose: the crawl only creates a pending record for requests that pass its scope filter, and the
// recorder has to see the ones it rejects.
const authPending = new Map();

// Response bodies from the page hook, keyed by method+url, waiting for the webRequest record that
// they belong to. webRequest never sees a body and the hook never sees the real request headers, so
// neither source is complete on its own.
const authBodyStash = new Map();

let authFlushTimer = null;
let authFlushInFlight = null;
let authSeqCursor = 0;
let authSeqCeiling = 0;
let authSeqReserving = null;

/* --------------------------------------------------------------- auth state storage */

let authStateCache = null;
let authStateLoad = null;
let authWriteChain = Promise.resolve();

// A write chain of its own, not the crawl's. Sharing one would let a slow auth upload hold up a
// crawl capture, and the whole point of this section is that the two cannot interfere.
function authExclusive(fn) {
  const next = authWriteChain.then(fn);
  authWriteChain = next.then(
    () => {},
    () => {}
  );
  return next;
}

function mergeAuthDefaults(stored) {
  const base = { ...EMPTY_AUTH_STATE, ...(stored || {}) };
  base.stats = { ...EMPTY_AUTH_STATE.stats, ...(base.stats || {}) };
  base.observedHosts = Array.isArray(base.observedHosts) ? base.observedHosts : [];
  return base;
}

async function getAuthState() {
  if (authStateCache) return authStateCache;
  if (!authStateLoad) {
    authStateLoad = chrome.storage.session
      .get([AUTH_STATE_KEY])
      .then((stored) => {
        authStateCache = mergeAuthDefaults(stored[AUTH_STATE_KEY]);
        return authStateCache;
      })
      .catch(() => {
        authStateCache = { ...EMPTY_AUTH_STATE };
        return authStateCache;
      })
      .finally(() => {
        authStateLoad = null;
      });
  }
  return authStateLoad;
}

// Writes without taking the chain, so it is safe to call from inside authExclusive. Calling
// updateAuthState there instead would deadlock: the inner write would wait on the outer one.
async function writeAuthState(next) {
  authStateCache = mergeAuthDefaults(next);
  await chrome.storage.session.set({ [AUTH_STATE_KEY]: authStateCache }).catch(() => {});
  return authStateCache;
}

function setAuthState(next) {
  return authExclusive(() => writeAuthState(next));
}

function updateAuthState(patch) {
  return authExclusive(async () => {
    const current = await getAuthState();
    return writeAuthState({ ...current, ...patch });
  });
}

// For patches that have to be computed from the current value, so a capture landing mid-upload
// cannot have its count overwritten by a stale read.
function mutateAuthState(fn) {
  return authExclusive(async () => {
    const current = await getAuthState();
    return writeAuthState(fn(current));
  });
}

function clearAuthState() {
  return authExclusive(async () => {
    authSeqCursor = 0;
    authSeqCeiling = 0;
    await chrome.storage.session.set({ [AUTH_QUEUE_KEY]: [] }).catch(() => {});
    return writeAuthState({ ...EMPTY_AUTH_STATE });
  });
}

async function loadAuthQueue() {
  const stored = await chrome.storage.session.get([AUTH_QUEUE_KEY]);
  return stored[AUTH_QUEUE_KEY] || [];
}

async function persistAuthQueue(queue) {
  try {
    await chrome.storage.session.set({ [AUTH_QUEUE_KEY]: queue });
  } catch (error) {
    // Almost certainly the session storage quota, shared with the crawl queue. Say so rather than
    // swallowing it: the symptom is otherwise a recording that quietly stops growing.
    console.warn('[AUTH-RECORDING] Queue write rejected:', error && error.message);
  }
}

/* --------------------------------------------------------------- sequence numbers */

// The worker owns the sequence number so that ordering survives batching: uploads can be retried,
// split, or arrive out of order, and the framework still knows what happened in what order.
//
// The number is allocated when a request *starts*, not when it finishes, because completion order
// is not request order and an auth flow read back in completion order can be nonsense. Allocation
// is synchronous by design: two webRequest stages for the same request can be in flight at once,
// and an await between "do we have a record" and "store the record" would let both create one.
//
// Blocks are reserved in session storage up front so a service worker restart mid-recording can
// never hand the same number out twice, which would collide with UNIQUE(recording_id, seq). The
// cost is a gap in the numbering after a restart, and nothing reads the numbers as a dense range.
function reserveAuthSeqBlock() {
  if (authSeqReserving) return authSeqReserving;
  authSeqReserving = authExclusive(async () => {
    const current = await getAuthState();
    const from = Math.max(current.nextSeq || 1, authSeqCursor);
    await writeAuthState({ ...current, nextSeq: from + AUTH_SEQ_BLOCK });
    // The new range begins where the last one ended, so a refill that arrives while the current
    // block still has room just extends the run. Moving the cursor unconditionally would punch a
    // hole in the numbering on every refill instead of only after a restart.
    if (authSeqCursor >= authSeqCeiling) authSeqCursor = Math.max(authSeqCursor, from);
    authSeqCeiling = from + AUTH_SEQ_BLOCK;
  }).finally(() => {
    authSeqReserving = null;
  });
  return authSeqReserving;
}

function ensureAuthSeqBlock() {
  if (authSeqCeiling > authSeqCursor) return Promise.resolve();
  return reserveAuthSeqBlock();
}

function allocateAuthSeq() {
  const seq = authSeqCursor++;
  // Refill well before the block runs out, so allocation never has to wait on storage.
  if (authSeqCursor + AUTH_SEQ_REFILL_AT >= authSeqCeiling) void reserveAuthSeqBlock();
  return seq;
}

/* --------------------------------------------------------------- capture predicate */

function authShouldRecord(url, state) {
  if (!state.active || !state.recordingId) return false;

  let parsed;
  try {
    parsed = new URL(url);
  } catch (error) {
    return false;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;

  // There is no host filter here on purpose; see the note at the top of this section. The single
  // exclusion is our own traffic to the framework, which would otherwise record the upload that is
  // recording it and never stop growing.
  try {
    if (parsed.origin === new URL(state.apiBase).origin) return false;
  } catch (error) {
    /* apiBase malformed; fall through and record it */
  }

  return true;
}

// Sub-resources are still recorded, because "every request in order" is what makes the flow
// reconstructable, but they are marked so the framework's UI can hide them and the import does not
// turn a page's worth of images into auth flow steps. The user can flip this per request.
function isAuthRelevantResource(resourceType) {
  return !['image', 'font', 'media', 'stylesheet', 'csp_report', 'ping'].includes(
    String(resourceType || '')
  );
}

/* --------------------------------------------------------------- record assembly */

function sweepAuthPending() {
  const cutoff = Date.now() - AUTH_PENDING_TTL_MS;
  for (const [requestId, record] of authPending) {
    if (record.startedAt < cutoff) authPending.delete(requestId);
  }
}

// Every stage can create the record, so a worker cold start partway through a request still yields
// a usable row instead of a hole in the sequence.
function authTouch(details) {
  let record = authPending.get(details.requestId);
  if (!record) {
    record = {
      seq: allocateAuthSeq(),
      url: details.url,
      method: String(details.method || 'GET').toUpperCase(),
      startedAt: Date.now(),
      headers: {},
      postData: '',
      responseHeaders: {},
      setCookies: [],
      statusCode: 0,
      responseBody: '',
      resourceType: details.type || '',
    };
    authPending.set(details.requestId, record);
    return record;
  }

  // A redirect reuses the requestId, and the follow-up stages report the new URL and the method the
  // browser actually used for it.
  if (details.url) record.url = details.url;
  if (details.method) record.method = String(details.method).toUpperCase();
  if (details.type) record.resourceType = details.type;
  return record;
}

function applyAuthResponseHeaders(record, headerArray) {
  record.responseHeaders = lowerHeaderMap(headerArray);
  // lowerHeaderMap collapses duplicate names, and a response routinely sets several cookies at
  // once, so Set-Cookie is collected separately as a list. Those cookies are the session the flow
  // exists to produce; keeping only the last one would make the recording worthless.
  record.setCookies = (headerArray || [])
    .filter((header) => header && header.name && header.name.toLowerCase() === 'set-cookie')
    .map((header) => header.value || '');
}

function byteLength(text) {
  try {
    return new TextEncoder().encode(text).length;
  } catch (error) {
    return String(text).length;
  }
}

// Builds the wire-format request the replay engine parses back with http.ReadRequest. Getting this
// right here is what makes a recorded step replayable without a round of guessing on the server.
function buildRawRequest(method, url, headers, body) {
  let target = '/';
  let host = '';
  try {
    const parsed = new URL(url);
    target = (parsed.pathname || '/') + (parsed.search || '');
    host = parsed.host;
  } catch (error) {
    target = url;
  }

  const lines = [`${method} ${target} HTTP/1.1`];
  if (host) lines.push(`Host: ${host}`);

  Object.keys(headers || {}).forEach((name) => {
    const lower = name.toLowerCase();
    if (lower === 'host') return;
    // Content-Length is recomputed below: the stored body may have been truncated, and a length
    // that disagrees with the body makes the parse hang or fail.
    if (lower === 'content-length') return;
    // Chrome reports HTTP/2 pseudo-headers on some paths. They are not legal in an HTTP/1.1
    // request line block and http.ReadRequest rejects the whole request over one of them.
    if (lower.startsWith(':')) return;
    // The replay engine sends this request itself, so an encoding the browser negotiated would
    // describe a body we are storing decoded.
    if (lower === 'transfer-encoding' || lower === 'content-encoding' || lower === 'accept-encoding') return;
    lines.push(`${name}: ${headers[name]}`);
  });

  if (body) lines.push(`Content-Length: ${byteLength(body)}`);

  return lines.join('\r\n') + '\r\n\r\n' + (body || '');
}

function authStashKey(method, url) {
  return mergeKey(method, url);
}

function takeAuthStash(key) {
  const entry = authBodyStash.get(key);
  if (!entry) return null;
  authBodyStash.delete(key);
  if (Date.now() - entry.at > AUTH_BODY_STASH_TTL_MS) return null;
  return entry;
}

function buildAuthRow(record) {
  // A body the page hook already reported for this request, if it beat the webRequest completion.
  const stashed = takeAuthStash(authStashKey(record.method, record.url));
  if (stashed) {
    if (!record.responseBody) record.responseBody = stashed.responseBody || '';
    if (!record.postData) record.postData = stashed.postData || '';
  }

  const requestBody = truncateBody(record.postData || '', AUTH_MAX_BODY_BYTES);
  const responseBody = truncateBody(record.responseBody || '', AUTH_MAX_BODY_BYTES);

  let host = '';
  try {
    host = new URL(record.url).host;
  } catch (error) {
    /* unparseable url; the row still carries it verbatim */
  }

  return {
    seq: record.seq,
    method: record.method,
    url: record.url,
    host,
    raw_request: buildRawRequest(record.method, record.url, record.headers, requestBody.body),
    request_headers: record.headers || {},
    request_body: requestBody.body,
    response_status: record.statusCode || 0,
    response_headers: record.responseHeaders || {},
    response_body: responseBody.body,
    set_cookies: record.setCookies || [],
    resource_type: record.resourceType || '',
    duration_ms: Math.max(0, Date.now() - record.startedAt),
    included: isAuthRelevantResource(record.resourceType),
    occurred_at: new Date(record.startedAt).toISOString(),
    _settleUntil: Date.now() + AUTH_SETTLE_MS,
    _matchKey: authStashKey(record.method, record.url),
  };
}

function stripAuthInternal(row) {
  const clean = { ...row };
  delete clean._settleUntil;
  delete clean._matchKey;
  return clean;
}

function shedAuthBodies(row) {
  if (!row.request_body && !row.response_body) return row;
  return { ...row, request_body: '', response_body: '' };
}

async function enqueueAuthRequest(record) {
  const state = await getAuthState();
  if (!state.active || !state.recordingId) return;

  const row = buildAuthRow(record);
  let newHost = '';

  await authExclusive(async () => {
    const current = await getAuthState();
    if (!current.active) return;

    const queue = await loadAuthQueue();
    queue.push(row);

    let dropped = 0;
    if (queue.length > AUTH_MAX_QUEUE_LENGTH) {
      dropped = queue.length - AUTH_MAX_QUEUE_LENGTH;
      queue.splice(0, dropped);
    }

    // Same bargain the crawl queue makes: shed bodies from the oldest rows before dropping a row
    // outright, because a step recorded without its body can still be replayed and a missing step
    // breaks the sequence.
    let bytes = approximateSize(queue);
    for (let i = 0; i < queue.length && bytes > AUTH_QUEUE_BYTE_LIMIT; i++) {
      if (!queue[i].request_body && !queue[i].response_body) continue;
      queue[i] = shedAuthBodies(queue[i]);
      bytes = approximateSize(queue);
    }
    while (queue.length > 1 && bytes > AUTH_QUEUE_BYTE_LIMIT) {
      queue.shift();
      dropped++;
      bytes = approximateSize(queue);
    }

    await persistAuthQueue(queue);

    const observedHosts = current.observedHosts || [];
    if (row.host && !observedHosts.includes(row.host)) newHost = row.host;

    await writeAuthState({
      ...current,
      observedHosts: newHost ? [...observedHosts, newHost].slice(-AUTH_HOST_LIMIT) : observedHosts,
      stats: {
        ...current.stats,
        requestCount: current.stats.requestCount + 1,
        queuedCount: queue.length,
        failedCount: current.stats.failedCount + dropped,
      },
    });
  });

  // A host this recording had not seen before means the page hook is not yet reading bodies there.
  // Pushing the configuration again costs one message per tab and buys the response body of every
  // request after this one, which on an identity provider is the request that matters.
  if (newHost) await pushConfigToPages();

  scheduleAuthFlush();
  void broadcastAuthState();
}

// The page hook is the only source that can see a response body. Its records are never rows of
// their own: webRequest sees every request the browser makes, so a hook record always describes a
// request the recorder already has or is about to have, and enqueuing it separately would duplicate
// the step. It is matched onto a row still inside its settle window, or stashed for the row that is
// about to be built.
async function noteAuthHookRecord(record) {
  if (!record || !record.url) return;
  const state = await getAuthState();
  if (!state.active) return;
  if (!record.responseBody && !record.postData) return;

  const key = authStashKey(record.method, record.url);

  const patched = await authExclusive(async () => {
    const queue = await loadAuthQueue();
    const now = Date.now();
    for (let i = queue.length - 1; i >= 0; i--) {
      const row = queue[i];
      if (row._matchKey !== key) continue;
      if (row._settleUntil <= now) break; // already sealed, and older rows are older still
      if (row.response_body && row.request_body) return true;

      queue[i] = {
        ...row,
        response_body: row.response_body || truncateBody(record.responseBody || '', AUTH_MAX_BODY_BYTES).body,
        request_body: row.request_body || truncateBody(record.postData || '', AUTH_MAX_BODY_BYTES).body,
      };
      await persistAuthQueue(queue);
      return true;
    }
    return false;
  });

  if (patched) return;

  if (authBodyStash.size >= AUTH_BODY_STASH_LIMIT) {
    const oldest = authBodyStash.keys().next();
    if (!oldest.done) authBodyStash.delete(oldest.value);
  }
  authBodyStash.set(key, {
    responseBody: record.responseBody || '',
    postData: record.postData || '',
    at: Date.now(),
  });
}

/* --------------------------------------------------------------- auth webRequest source */

// These listeners are registered separately from the crawl's rather than sharing them. The two
// sessions have opposite filtering rules and independent lifecycles, and keeping the registrations
// apart is what guarantees that starting or stopping one cannot change what the other records.

async function authStage(details, mutate) {
  const state = await getAuthState();
  if (!authShouldRecord(details.url, state)) return null;
  await ensureAuthSeqBlock();
  // No await between here and storing the record: authTouch has to be atomic against the other
  // stages of the same request, which are running in their own callbacks.
  const record = authTouch(details);
  if (mutate) mutate(record);
  return record;
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    void (async () => {
      sweepAuthPending();
      await authStage(details, (record) => {
        const body = parseWebRequestBody(details.requestBody);
        if (body) record.postData = body;
      });
    })();
  },
  { urls: ['<all_urls>'] },
  ['requestBody']
);

// 'extraHeaders' is what makes Chrome expose Cookie here and Set-Cookie below, and a login flow is
// mostly cookies.
chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    void authStage(details, (record) => {
      record.headers = lowerHeaderMap(details.requestHeaders);
    });
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders', 'extraHeaders']
);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    void authStage(details, (record) => {
      record.statusCode = details.statusCode;
      applyAuthResponseHeaders(record, details.responseHeaders);
    });
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders', 'extraHeaders']
);

// Each redirect hop becomes its own recorded request. The crawl folds hops into a redirect chain,
// but an OAuth handshake *is* its redirects: the Location carrying the code and the Set-Cookie
// riding along with it are the substance of the flow, and a recording that stored only the final
// destination could not be replayed step by step.
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    void (async () => {
      const record = await authStage(details, (entry) => {
        entry.statusCode = details.statusCode;
        applyAuthResponseHeaders(entry, details.responseHeaders);
      });
      if (!record) return;
      // The redirected request reuses this requestId, so the hop has to be closed out here. The
      // stages that follow will create a fresh record, with a fresh sequence number, for the
      // destination.
      authPending.delete(details.requestId);
      await enqueueAuthRequest(record);
    })();
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders', 'extraHeaders']
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    void (async () => {
      const record = await authStage(details, (entry) => {
        if (!entry.statusCode) entry.statusCode = details.statusCode;
      });
      if (!record) return;
      authPending.delete(details.requestId);
      await enqueueAuthRequest(record);
    })();
  },
  { urls: ['<all_urls>'] }
);

// A cancelled or failed request is still part of the story of a login attempt, so it is recorded
// with whatever was observed rather than discarded.
chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    void (async () => {
      const record = authPending.get(details.requestId);
      authPending.delete(details.requestId);
      if (!record) return;

      const state = await getAuthState();
      if (!authShouldRecord(details.url, state)) return;
      await enqueueAuthRequest(record);
    })();
  },
  { urls: ['<all_urls>'] }
);

/* --------------------------------------------------------------- auth upload */

function scheduleAuthFlush(delayMs) {
  if (authFlushTimer) return;
  authFlushTimer = setTimeout(() => {
    authFlushTimer = null;
    void flushAuthQueue();
  }, delayMs || AUTH_FLUSH_DEBOUNCE_MS);
}

// Returns the in-flight flush when one is already running, so Stop actually waits for the queue to
// drain instead of returning early and stranding the tail of the flow.
function flushAuthQueue(options) {
  if (authFlushInFlight) return authFlushInFlight;
  authFlushInFlight = runAuthFlush(options || {}).finally(() => {
    authFlushInFlight = null;
  });
  return authFlushInFlight;
}

// The queue is appended to with a constant settle window, so it is already ordered by deadline and
// taking a prefix is always correct.
function takeSettledAuth(queue, now, limit, byteLimit) {
  const ready = [];
  let bytes = 0;
  for (const row of queue) {
    if (row._settleUntil > now) break;
    const size = approximateSize(row);
    // Always take at least one, so a single oversized row cannot wedge the queue forever.
    if (ready.length > 0 && byteLimit && bytes + size > byteLimit) break;
    ready.push(row);
    bytes += size;
    if (ready.length >= limit) break;
  }
  return ready;
}

async function dropFromAuthQueue(count) {
  const remaining = await authExclusive(async () => {
    const queue = await loadAuthQueue();
    const next = queue.slice(count);
    await persistAuthQueue(next);
    const current = await getAuthState();
    await writeAuthState({
      ...current,
      stats: { ...current.stats, queuedCount: next.length },
    });
    return next;
  });
  return remaining;
}

async function runAuthFlush(options) {
  try {
    const state = await getAuthState();
    if (!state.active || !state.recordingId) return;

    for (;;) {
      const queue = await loadAuthQueue();
      if (queue.length === 0) break;

      // `force` ignores the settle window so Stop does not strand the last second and a half, which
      // on a login flow is usually the response that carries the session.
      const now = options.force ? Number.MAX_SAFE_INTEGER : Date.now();
      const batch = takeSettledAuth(queue, now, AUTH_FLUSH_BATCH_SIZE, AUTH_FLUSH_BATCH_BYTES);
      if (batch.length === 0) {
        const waitMs = Math.max(250, queue[0]._settleUntil - Date.now() + 50);
        scheduleAuthFlush(waitMs);
        break;
      }

      let result;
      try {
        result = await postJSON(`${state.apiBase}/auth-recording/capture`, {
          recording_id: state.recordingId,
          requests: batch.map(stripAuthInternal),
        });
      } catch (error) {
        await updateAuthState({ lastError: 'Framework unreachable: ' + error.message });
        break;
      }

      if (result.ok) {
        await dropFromAuthQueue(batch.length);
        // The framework's running total is authoritative: it has seen every batch, including the
        // ones uploaded before this worker was last restarted.
        await mutateAuthState((current) => ({
          ...current,
          stats: {
            ...current.stats,
            requestCount: result.body.total ?? current.stats.requestCount,
          },
          lastError: null,
          lastHeartbeatAt: Date.now(),
        }));
        continue;
      }

      if (result.status === 404 || result.status === 409) {
        console.warn('[AUTH-RECORDING] Recording rejected by framework:', result.body);
        await stopAuthRecordingSession({
          notifyFramework: false,
          flushFirst: false,
          reason: result.body.message || 'This recording is no longer active on the framework',
        });
        break;
      }

      console.error('[AUTH-RECORDING] Batch rejected:', result.status, result.body);
      await dropFromAuthQueue(batch.length);
      await mutateAuthState((current) => ({
        ...current,
        stats: { ...current.stats, failedCount: current.stats.failedCount + batch.length },
        lastError: `Framework rejected ${batch.length} recorded request(s) (${result.status})`,
      }));
    }
  } finally {
    void broadcastAuthState();
  }
}

async function sendAuthHeartbeat(force) {
  const state = await getAuthState();
  if (!state.active || !state.recordingId) return;

  const since = Date.now() - (state.lastHeartbeatAt || 0);
  if (!force && since < AUTH_HEARTBEAT_INTERVAL_MS) return;

  let result;
  try {
    result = await postJSON(`${state.apiBase}/auth-recording/heartbeat`, {
      recording_id: state.recordingId,
    });
  } catch (error) {
    await updateAuthState({ lastError: 'Framework unreachable: ' + error.message });
    return;
  }

  if (result.ok) {
    await updateAuthState({ lastHeartbeatAt: Date.now(), lastError: null });
    void broadcastAuthState();
    return;
  }

  if (result.status === 404 || result.status === 409) {
    await stopAuthRecordingSession({
      notifyFramework: false,
      flushFirst: false,
      reason: result.body.message || 'This recording is no longer active on the framework',
    });
  }
}

/* --------------------------------------------------------------- auth session control */

async function startAuthRecordingSession(recording, frameworkUrl) {
  try {
    const existing = await getAuthState();
    if (existing.active) throw new Error('A recording is already running');

    const baseUrl = (frameworkUrl || DEFAULT_FRAMEWORK_URL).replace(/\/+$/, '');
    const apiBase = baseUrl + '/api';

    const name = String((recording && recording.name) || '').trim();
    if (!recording || !recording.scopeTargetId) throw new Error('No scope target selected');
    if (!name) throw new Error('Give the flow a name');
    const category = AUTH_CATEGORIES.includes(recording.category) ? recording.category : 'login';

    const result = await postJSON(`${apiBase}/auth-recording/start`, {
      scope_target_id: recording.scopeTargetId,
      name,
      category,
      base_url: recording.baseUrl || '',
    });
    if (!result.ok) throw new Error(result.body.message || `Framework returned ${result.status}`);

    const recordingId = result.body.recording_id;
    if (!recordingId) throw new Error('Framework did not return a recording id');

    authPending.clear();
    authBodyStash.clear();
    authSeqCursor = 0;
    authSeqCeiling = 0;

    let seedHost = '';
    try {
      if (recording.baseUrl) seedHost = new URL(recording.baseUrl).host;
    } catch (error) {
      /* no usable base url; the first captured request will seed it instead */
    }

    await authExclusive(() => persistAuthQueue([]));
    await setAuthState({
      ...EMPTY_AUTH_STATE,
      active: true,
      recordingId,
      scopeTargetId: recording.scopeTargetId,
      name,
      category,
      baseUrl: recording.baseUrl || '',
      apiBase,
      nextSeq: 1,
      observedHosts: seedHost ? [seedHost] : [],
      startedAt: Date.now(),
      lastHeartbeatAt: Date.now(),
    });
    await reserveAuthSeqBlock();

    await chrome.alarms.create(AUTH_KEEPALIVE_ALARM, { periodInMinutes: 0.5 });
    await applyBadge();
    await pushConfigToPages();
    void broadcastAuthState();

    console.log('[AUTH-RECORDING] Recording started:', recordingId);
    return { success: true, recordingId };
  } catch (error) {
    console.error('[AUTH-RECORDING] Failed to start recording:', error);
    return { success: false, error: error.message };
  }
}

async function stopAuthRecordingSession(options) {
  const opts = options || {};
  const state = await getAuthState();
  const stats = { ...state.stats };

  let summary = {
    recordingId: state.recordingId,
    requestCount: stats.requestCount,
    authFlowId: null,
  };

  try {
    if (state.active && state.recordingId) {
      if (opts.flushFirst !== false) {
        // Wait out any flush already running (it would otherwise swallow the force), then ship
        // everything, settle window included.
        await flushAuthQueue();
        await flushAuthQueue({ force: true });
      }
      if (opts.notifyFramework !== false) {
        try {
          const result = await postJSON(`${state.apiBase}/auth-recording/stop`, {
            recording_id: state.recordingId,
          });
          if (result.ok) {
            summary = {
              recordingId: result.body.recording_id || state.recordingId,
              requestCount: result.body.request_count ?? stats.requestCount,
              authFlowId: result.body.auth_flow_id || null,
            };
          }
        } catch (error) {
          console.warn('[AUTH-RECORDING] Could not notify framework of stop:', error.message);
        }
      }
    }
  } finally {
    await chrome.alarms.clear(AUTH_KEEPALIVE_ALARM);
    authPending.clear();
    authBodyStash.clear();
    await clearAuthState();
    if (opts.reason) await updateAuthState({ lastError: opts.reason });
    await applyBadge();
    await pushConfigToPages();
    void broadcastAuthState();
  }

  console.log('[AUTH-RECORDING] Recording stopped:', summary);
  return { success: true, ...summary, reason: opts.reason || null };
}

function publicAuthState(state) {
  return {
    active: state.active,
    recordingId: state.recordingId,
    scopeTargetId: state.scopeTargetId,
    name: state.name,
    category: state.category,
    baseUrl: state.baseUrl,
    startedAt: state.startedAt,
    stats: state.stats,
    lastError: state.lastError,
  };
}

// Only the popup listens for this. Content scripts receive messages over chrome.tabs.sendMessage,
// and none of them care about the recorder.
async function broadcastAuthState() {
  const state = await getAuthState();
  chrome.runtime
    .sendMessage({ action: 'authRecordingState', state: publicAuthState(state) })
    .catch(() => {});
}

// Restores the alarm and the sequence cursor after a worker restart, so a recording keeps running
// across the terminations MV3 does on its own schedule.
async function restoreAuthRecording() {
  const state = await getAuthState();
  if (!state.active || !state.recordingId) return;

  await reserveAuthSeqBlock();
  await chrome.alarms.create(AUTH_KEEPALIVE_ALARM, { periodInMinutes: 0.5 });
  await chrome.alarms.create(AUTH_DISCOVER_ALARM, { periodInMinutes: 0.5 });
  await flushAuthQueue();
  await sendAuthHeartbeat(true);
}

const AUTH_DISCOVER_ALARM = 'ars0n-auth-recording-discover';

/* Adopt a recording that was started from the framework UI.
 *
 * Start lives in two places: this popup, and the Record Auth Flows modal in the framework. The
 * modal's copy tells the operator "switch to the browser and sign in, the extension is capturing",
 * and without this poll that sentence was simply false. The worker only ever knew about recordings
 * it had started itself, so a recording begun in the UI collected nothing at all and the modal
 * happily displayed a request count of zero while the operator logged in.
 *
 * The page cannot message the worker (no externally_connectable in the manifest), so the worker has
 * to ask. It asks the same endpoint the modal polls. */
async function discoverAuthRecording() {
  const state = await getAuthState();
  if (state.active) return;

  const settings = await loadStoredSettings();
  const scopeTargetId = settings && settings.scopeTargetId;
  if (!scopeTargetId) return;

  const baseUrl = ((settings && settings.frameworkUrl) || DEFAULT_FRAMEWORK_URL).replace(/\/+$/, '');
  const apiBase = baseUrl + '/api';

  let recording = null;
  try {
    const res = await fetch(`${apiBase}/auth-recording/active/${scopeTargetId}`);
    if (!res.ok) return;
    const body = await res.json();
    recording = body && body.recording;
  } catch (error) {
    return; // The framework being unreachable is not worth logging every thirty seconds.
  }
  if (!recording || !recording.id) return;

  // Adopt it. Everything below mirrors startAuthRecordingSession except the POST, because the
  // recording already exists and starting a second one would flip this one to 'abandoned'.
  authPending.clear();
  authBodyStash.clear();
  authSeqCursor = 0;
  authSeqCeiling = 0;

  let seedHost = '';
  try {
    if (recording.base_url) seedHost = new URL(recording.base_url).host;
  } catch (error) {
    /* the first captured request will seed it instead */
  }

  await authExclusive(() => persistAuthQueue([]));
  await setAuthState({
    ...EMPTY_AUTH_STATE,
    active: true,
    adopted: true,
    recordingId: recording.id,
    scopeTargetId,
    name: recording.name || '',
    category: AUTH_CATEGORIES.includes(recording.category) ? recording.category : 'login',
    baseUrl: recording.base_url || '',
    apiBase,
    // Continue the sequence rather than restarting it. Anything already captured, by an earlier
    // worker lifetime or by the framework itself, keeps its place.
    nextSeq: Number(recording.request_count || 0) + 1,
    observedHosts: seedHost ? [seedHost] : [],
    startedAt: Date.now(),
    lastHeartbeatAt: Date.now(),
  });
  await reserveAuthSeqBlock();

  await chrome.alarms.create(AUTH_KEEPALIVE_ALARM, { periodInMinutes: 0.5 });
  await applyBadge();
  await pushConfigToPages();
  void broadcastAuthState();
  console.log('[AUTH-RECORDING] Adopted a recording started in the framework UI:', recording.id);
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== AUTH_DISCOVER_ALARM) return;
  void discoverAuthRecording().catch(() => {});
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== AUTH_KEEPALIVE_ALARM) return;
  void (async () => {
    const state = await getAuthState();
    if (!state.active) {
      await chrome.alarms.clear(AUTH_KEEPALIVE_ALARM);
      return;
    }
    sweepAuthPending();
    await flushAuthQueue();
    await sendAuthHeartbeat(false);

    // A recording stopped from the framework UI has to stop the worker too, or it keeps uploading
    // into a recording the operator considers finished.
    if (state.adopted) {
      try {
        const res = await fetch(`${state.apiBase}/auth-recording/active/${state.scopeTargetId}`);
        if (res.ok) {
          const body = await res.json();
          const live = body && body.recording;
          if (!live || live.id !== state.recordingId) {
            console.log('[AUTH-RECORDING] The adopted recording ended in the framework, stopping.');
            await flushAuthQueue();
            await setAuthState({ ...EMPTY_AUTH_STATE });
            await chrome.alarms.clear(AUTH_KEEPALIVE_ALARM);
            await applyBadge();
            await pushConfigToPages();
            void broadcastAuthState();
          }
        }
      } catch (error) {
        /* transient; the next tick tries again */
      }
    }
  })();
});

/* ------------------------------------------------------------------ keepalive */

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== KEEPALIVE_ALARM) return;
  void (async () => {
    const state = await getState();
    if (!state.active) {
      await chrome.alarms.clear(KEEPALIVE_ALARM);
      return;
    }
    sweepPending();
    await flushOutOfScope();
    await flushQueue();
    await sendHeartbeat(false);
    if (state.deepCapture.enabled) await refreshDeepCapture();
  })();
});

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'ars0n-keepalive') return;

  port.onMessage.addListener((message) => {
    void (async () => {
      const state = await getState();

      if (message && message.action === 'ping') {
        port.postMessage({ action: 'state', state: publicState(state) });
        if (state.active) await sendHeartbeat(false);
        // The two sessions heartbeat independently: a recording running without a crawl still has
        // to tell the framework it is alive.
        await sendAuthHeartbeat(false);
        return;
      }

      // The page hook reports through the isolated content script, which relays over this port.
      if (message && message.action === 'hookCapture' && message.record) {
        const tabId = port.sender && port.sender.tab ? port.sender.tab.id : null;
        await submitCapture({ ...message.record, tabId }, 'hook');
        await noteAuthHookRecord(message.record);
        return;
      }

      if (message && message.action === 'needConfig') {
        port.postMessage({ action: 'hookConfig', config: await buildHookConfig() });
      }
    })();
  });
});

/* ------------------------------------------------------------------ messaging */

function publicState(state) {
  return {
    active: state.active,
    sessionId: state.sessionId,
    scopeTargetId: state.scopeTargetId,
    targetUrl: state.targetUrl,
    scopeHosts: state.scopeHosts,
    stats: state.stats,
    startedAt: state.startedAt,
    lastHeartbeatAt: state.lastHeartbeatAt,
    lastError: state.lastError,
    deepCapture: state.deepCapture,
    observedOutOfScope: state.observedOutOfScope,
    extraHosts: (state.settings && state.settings.extraHosts) || [],
  };
}

async function broadcastState() {
  const state = await getState();
  const payload = { action: 'sessionState', state: publicState(state) };

  chrome.runtime.sendMessage(payload).catch(() => {});

  try {
    const tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
    tabs.forEach((tab) => chrome.tabs.sendMessage(tab.id, payload).catch(() => {}));
  } catch (error) {
    /* tabs may be unavailable during shutdown */
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) return false;

  if (message.action === 'startCapture') {
    startCaptureSession(message.settings, message.frameworkUrl)
      .then(sendResponse)
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.action === 'stopCapture') {
    stopCaptureSession({ notifyFramework: true })
      .then(sendResponse)
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.action === 'getSessionState') {
    // Fold in anything observed since the last tick so the popup's out-of-scope list is current
    // the moment it is opened.
    flushOutOfScope()
      .then(getState)
      .then((state) => sendResponse({ success: true, state: publicState(state) }))
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  // The page hook's report path when a port is not available (for example a frame that loaded
  // before the keepalive port connected).
  if (message.action === 'hookCapture' && message.record) {
    const tabId = sender && sender.tab ? sender.tab.id : null;
    Promise.all([
      submitCapture({ ...message.record, tabId }, 'hook'),
      noteAuthHookRecord(message.record),
    ])
      .then(() => sendResponse({ success: true }))
      .catch(() => sendResponse({ success: false }));
    return true;
  }

  if (message.action === 'getHookConfig') {
    buildHookConfig()
      .then((config) => sendResponse({ success: true, config }))
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.action === 'updateSettings') {
    getState()
      .then(async (state) => {
        if (!state.active) {
          sendResponse({ success: true });
          return;
        }
        await applyScopeChange(message.settings || {});
        sendResponse({ success: true });
      })
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  // Adds a host that was seen but rejected, without interrupting the recording.
  if (message.action === 'addScopeHost') {
    getState()
      .then(async (state) => {
        const host = normalizeHostEntry(message.host);
        if (!host) {
          sendResponse({ success: false, error: 'Not a usable hostname' });
          return;
        }
        const existing = (state.settings && state.settings.extraHosts) || [];
        if (existing.includes(host)) {
          sendResponse({ success: true, scopeHosts: state.scopeHosts });
          return;
        }
        const extraHosts = [...existing, host];
        await chrome.storage.local.set({ extraHosts });
        const scopeHosts = await applyScopeChange({ extraHosts });
        sendResponse({ success: true, scopeHosts });
      })
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.action === 'removeScopeHost') {
    getState()
      .then(async (state) => {
        const host = normalizeHostEntry(message.host);
        const existing = (state.settings && state.settings.extraHosts) || [];
        const extraHosts = existing.filter((h) => h !== host);
        await chrome.storage.local.set({ extraHosts });
        const scopeHosts = await applyScopeChange({ extraHosts });
        sendResponse({ success: true, scopeHosts });
      })
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.action === 'setDeepCapture') {
    getState()
      .then(async (state) => {
        const enabled = Boolean(message.enabled);
        await chrome.storage.local.set({ deepCapture: enabled });
        await updateState({
          settings: { ...(state.settings || {}), deepCapture: enabled },
          deepCapture: { ...state.deepCapture, enabled },
        });
        await refreshDeepCapture();
        const next = await getState();
        sendResponse({ success: true, deepCapture: next.deepCapture });
      })
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.action === 'updateFrameworkUrl') {
    const baseUrl = (message.frameworkUrl || DEFAULT_FRAMEWORK_URL).replace(/\/+$/, '');
    Promise.all([
      chrome.storage.local.set({ frameworkUrl: baseUrl }),
      updateState({ apiBase: baseUrl + '/api' }),
      updateAuthState({ apiBase: baseUrl + '/api' }),
    ])
      .then(() => sendResponse({ success: true }))
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.action === 'startAuthRecording') {
    startAuthRecordingSession(message.recording, message.frameworkUrl)
      .then(sendResponse)
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.action === 'stopAuthRecording') {
    stopAuthRecordingSession({ notifyFramework: true })
      .then(sendResponse)
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (message.action === 'getAuthRecordingState') {
    getAuthState()
      .then((state) => sendResponse({ success: true, state: publicAuthState(state) }))
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  return false;
});

/* ------------------------------------------------------------------ lifecycle */

// Restore the badge, alarms, and debugger attachments after a worker restart so the runtime state
// matches the real session rather than whatever it happened to be before.
async function restoreRuntimeSurface() {
  await applyBadge();
  // Restored first and unconditionally: a recording can be running with no crawl behind it, and the
  // early return below would otherwise leave it without its alarm.
  await restoreAuthRecording();

  const state = await getState();
  if (!state.active) return;

  await chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.5 });
  await pushConfigToPages();
  if (state.deepCapture.enabled) await refreshDeepCapture();
  await flushQueue();
  await sendHeartbeat(true);
}

chrome.runtime.onStartup.addListener(() => void restoreRuntimeSurface());
chrome.runtime.onInstalled.addListener(() => void restoreRuntimeSurface());

// Keep deep capture and the page hooks aligned with where the user actually browsed.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== 'complete' && !changeInfo.url) return;
  void (async () => {
    // The hook may need configuring for either session, including a recording running on its own.
    const config = await buildHookConfig();
    if (config.active) {
      chrome.tabs.sendMessage(tabId, { action: 'hookConfig', config }).catch(() => {});
    }

    const state = await getState();
    if (!state.active) return;

    chrome.tabs.sendMessage(tabId, { action: 'sessionState', state: publicState(state) }).catch(() => {});

    if (state.deepCapture.enabled) await refreshDeepCapture();
  })();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void detachFromTab(tabId);
});

void restoreRuntimeSurface();

console.log('[MANUAL-CRAWL] Service worker ready (webrequest + page hook + optional deep capture)');
console.log('[AUTH-RECORDING] Recorder ready (independent session, no scope filter)');
