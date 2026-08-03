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

import {
  EMPTY_STATE,
  QUEUE_FLUSH_BYTES,
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
        await runExclusive(() => persistQueue([]));
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
    await chrome.action.setBadgeText({ text: 'REC' });
    await chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });

    if (settings.deepCapture) await refreshDeepCapture();
    await pushConfigToPages();
    void broadcastState();

    console.log('[MANUAL-CRAWL] Session started:', result.body.sessionId);
    return { success: true, sessionId: result.body.sessionId, scopeHosts };
  } catch (error) {
    console.error('[MANUAL-CRAWL] Failed to start session:', error);
    await detachAll();
    await clearState();
    await chrome.action.setBadgeText({ text: '' });
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
    await chrome.action.setBadgeText({ text: '' });
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

// Pushes the current scope to every page hook. The hook does no work while inactive, so this is
// also how capture is switched off inside pages.
async function pushConfigToPages() {
  const state = await getState();
  const config = {
    active: state.active,
    scopeHosts: state.scopeHosts || [],
    maxBodyBytes: maxBodyBytes(state),
    captureResponseBodies: captureResponseBodies(state),
  };

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
        return;
      }

      // The page hook reports through the isolated content script, which relays over this port.
      if (message && message.action === 'hookCapture' && message.record) {
        const tabId = port.sender && port.sender.tab ? port.sender.tab.id : null;
        await submitCapture({ ...message.record, tabId }, 'hook');
        return;
      }

      if (message && message.action === 'needConfig') {
        const config = {
          active: state.active,
          scopeHosts: state.scopeHosts || [],
          maxBodyBytes: maxBodyBytes(state),
          captureResponseBodies: captureResponseBodies(state),
        };
        port.postMessage({ action: 'hookConfig', config });
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
    submitCapture({ ...message.record, tabId }, 'hook')
      .then(() => sendResponse({ success: true }))
      .catch(() => sendResponse({ success: false }));
    return true;
  }

  if (message.action === 'getHookConfig') {
    getState()
      .then((state) =>
        sendResponse({
          success: true,
          config: {
            active: state.active,
            scopeHosts: state.scopeHosts || [],
            maxBodyBytes: maxBodyBytes(state),
            captureResponseBodies: captureResponseBodies(state),
          },
        })
      )
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
    ])
      .then(() => sendResponse({ success: true }))
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true;
  }

  return false;
});

/* ------------------------------------------------------------------ lifecycle */

// Restore the badge, alarms, and debugger attachments after a worker restart so the runtime state
// matches the real session rather than whatever it happened to be before.
async function restoreRuntimeSurface() {
  const state = await getState();
  await chrome.action.setBadgeText({ text: state.active ? 'REC' : '' });
  if (!state.active) return;

  await chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
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
    const state = await getState();
    if (!state.active) return;

    const config = {
      active: true,
      scopeHosts: state.scopeHosts || [],
      maxBodyBytes: maxBodyBytes(state),
      captureResponseBodies: captureResponseBodies(state),
    };
    chrome.tabs.sendMessage(tabId, { action: 'hookConfig', config }).catch(() => {});
    chrome.tabs.sendMessage(tabId, { action: 'sessionState', state: publicState(state) }).catch(() => {});

    if (state.deepCapture.enabled) await refreshDeepCapture();
  })();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void detachFromTab(tabId);
});

void restoreRuntimeSurface();

console.log('[MANUAL-CRAWL] Service worker ready (webrequest + page hook + optional deep capture)');
