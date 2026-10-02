// Opt-in deep capture via the Chrome DevTools Protocol.
//
// webRequest gives metadata but no bodies. The page hook gives bodies but only for traffic the
// page's own JavaScript issues (fetch/XHR/beacon). Deep capture closes the remaining gap: document
// navigations, subresources, form posts, and requests from workers, complete with request and
// response bodies.
//
// The cost is visible and real, which is why it is opt-in:
//   - Chrome shows the "being controlled by automated software" banner while attached
//   - only one debugger client per tab, so it cannot attach while DevTools is open on that tab
//
// Attach failures are reported per tab rather than failing the session, so losing one tab to an
// open DevTools window does not stop the recording.

import { BASE64_BODY_PREFIX } from './scope.js';

const DEBUGGER_VERSION = '1.3';

// Response bodies must be fetched while the request is still in the debugger's buffer, so records
// are held only briefly between loadingFinished and the getResponseBody round trip.
const inflight = new Map(); // `${tabId}:${requestId}` -> partial record

let attached = new Set();
let onCapture = null;
let getConfig = null;
let listenersBound = false;

export function configureDeepCapture(options) {
  onCapture = options.onCapture;
  getConfig = options.getConfig;
  bindListeners();
}

function bindListeners() {
  if (listenersBound) return;
  listenersBound = true;

  chrome.debugger.onEvent.addListener(handleDebuggerEvent);
  chrome.debugger.onDetach.addListener((source, reason) => {
    if (source.tabId === undefined) return;
    attached.delete(source.tabId);
    console.log('[MANUAL-CRAWL] Deep capture detached from tab', source.tabId, reason);
  });
}

export function getAttachedTabs() {
  return Array.from(attached);
}

export async function attachToTab(tabId) {
  if (attached.has(tabId)) return { ok: true };

  try {
    await chrome.debugger.attach({ tabId }, DEBUGGER_VERSION);
  } catch (error) {
    const message = String(error && error.message ? error.message : error);
    // Chrome uses the SAME "Another debugger is already attached to the tab with id: N" message
    // (lowercase "already attached") for two very different situations: a tab WE still hold from a
    // previous worker lifetime (attached is in-memory and resets on SW restart), and a tab a FOREIGN
    // debugger owns (the operator's DevTools panel, or another extension). Only the first is ours to
    // adopt. Probe by trying Network.enable: it succeeds only for the client that is actually
    // attached, so claim the tab ONLY when it succeeds. For a foreign owner it fails, and we must NOT
    // add the tab to `attached` — otherwise attachToTab's has() short-circuit (above) marks it
    // attached forever while capturing nothing, and syncAttachments never retries it even after the
    // DevTools window closes. Returning the error keeps it retryable so it recovers when the conflict
    // clears, which is the documented invariant that one open DevTools window must not stop recording.
    if (/already attached/i.test(message)) {
      try {
        await chrome.debugger.sendCommand({ tabId }, 'Network.enable', {
          maxTotalBufferSize: 20000000,
          maxResourceBufferSize: 10000000,
        });
        attached.add(tabId);
        return { ok: true };
      } catch (enableError) {
        return { ok: false, error: message };
      }
    }
    return { ok: false, error: message };
  }

  try {
    await chrome.debugger.sendCommand({ tabId }, 'Network.enable', {
      maxTotalBufferSize: 20000000,
      maxResourceBufferSize: 10000000,
    });
    attached.add(tabId);
    return { ok: true };
  } catch (error) {
    try {
      await chrome.debugger.detach({ tabId });
    } catch (detachError) {
      /* ignore */
    }
    return { ok: false, error: String(error && error.message ? error.message : error) };
  }
}

export async function detachFromTab(tabId) {
  if (!attached.has(tabId)) return;
  attached.delete(tabId);
  try {
    await chrome.debugger.detach({ tabId });
  } catch (error) {
    /* the tab may already be gone */
  }
}

export async function detachAll() {
  const tabs = Array.from(attached);
  attached = new Set();
  inflight.clear();
  await Promise.all(
    tabs.map(async (tabId) => {
      try {
        await chrome.debugger.detach({ tabId });
      } catch (error) {
        /* ignore */
      }
    })
  );
}

// Attaches to every open tab whose URL is in scope, and reports which ones refused.
//
// Takes either a host list or a predicate. The predicate form exists because scope can now be
// authored as rules, and attaching the debugger by a boundary the capture path does not share would
// put the "being debugged" banner on sites the operator has excluded.
export async function syncAttachments(scopeHostsOrPredicate) {
  const inScopeFor = typeof scopeHostsOrPredicate === 'function'
    ? scopeHostsOrPredicate
    : (host) => (scopeHostsOrPredicate || []).some(
        (scope) => host === scope || host.endsWith('.' + scope));

  const errors = [];
  let tabs = [];
  try {
    tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
  } catch (error) {
    return { attached: getAttachedTabs(), errors: [{ tabId: null, error: String(error) }] };
  }

  const wanted = new Set();
  for (const tab of tabs) {
    if (!tab.id || !tab.url) continue;
    let host;
    try {
      host = new URL(tab.url).hostname.toLowerCase();
    } catch (error) {
      continue;
    }
    if (!inScopeFor(host)) continue;

    wanted.add(tab.id);
    const result = await attachToTab(tab.id);
    if (!result.ok) {
      errors.push({ tabId: tab.id, url: tab.url, error: result.error });
    }
  }

  // Release tabs that navigated out of scope so the automation banner disappears from pages we no
  // longer care about.
  for (const tabId of Array.from(attached)) {
    if (!wanted.has(tabId)) await detachFromTab(tabId);
  }

  return { attached: getAttachedTabs(), errors };
}

/* ------------------------------------------------------------------ CDP events */

function handleDebuggerEvent(source, method, params) {
  const tabId = source.tabId;
  if (tabId === undefined || !attached.has(tabId)) return;
  void routeEvent(tabId, method, params).catch(() => {});
}

async function routeEvent(tabId, method, params) {
  const config = getConfig ? await getConfig() : null;
  if (!config || !config.active) return;

  const key = `${tabId}:${params.requestId}`;

  if (method === 'Network.requestWillBeSent') {
    const request = params.request || {};
    if (!config.inScope(request.url)) return;

    // A redirect reuses the same requestId, so the previous hop is emitted before it is replaced.
    if (params.redirectResponse) {
      const previous = inflight.get(key);
      const chain = (previous && previous.redirectChain) || [];
      chain.push({
        location: request.url,
        statusCode: params.redirectResponse.status,
        from: params.redirectResponse.url,
      });
      inflight.set(key, {
        ...(previous || {}),
        redirectChain: chain,
      });
    }

    const existing = inflight.get(key) || {};
    inflight.set(key, {
      ...existing,
      tabId,
      url: request.url,
      method: String(request.method || 'GET').toUpperCase(),
      headers: lowerKeys(request.headers),
      postData: request.postData || '',
      hasPostData: Boolean(request.hasPostData),
      resourceType: (params.type || '').toLowerCase() || 'other',
      initiator: params.initiator && params.initiator.type ? params.initiator.type : '',
      startedAt: Date.now(),
      redirectChain: existing.redirectChain || [],
    });
    return;
  }

  if (method === 'Network.responseReceived') {
    const record = inflight.get(key);
    if (!record) return;
    const response = params.response || {};
    record.statusCode = response.status || 0;
    record.responseHeaders = lowerKeys(response.headers);
    record.mimeType = response.mimeType || '';
    record.resourceType = (params.type || record.resourceType || '').toLowerCase();
    inflight.set(key, record);
    return;
  }

  if (method === 'Network.loadingFinished') {
    const record = inflight.get(key);
    inflight.delete(key);
    if (!record) return;
    await emitRecord(tabId, params.requestId, record, config, null);
    return;
  }

  if (method === 'Network.loadingFailed') {
    const record = inflight.get(key);
    inflight.delete(key);
    if (!record) return;
    const reason = params.canceled ? 'canceled' : params.errorText || 'loading failed';
    await emitRecord(tabId, params.requestId, record, config, reason);
    return;
  }

  if (method === 'Network.webSocketCreated') {
    const url = params.url;
    if (!config.inScope(url)) return;
    onCapture({
      tabId,
      url,
      method: 'WEBSOCKET',
      headers: {},
      responseHeaders: {},
      postData: '',
      responseBody: '',
      statusCode: 101,
      mimeType: 'websocket',
      resourceType: 'websocket',
      initiator: 'websocket',
      redirectChain: [],
      durationMs: 0,
      error: '',
    });
  }
}

async function emitRecord(tabId, requestId, record, config, errorText) {
  // The request body can be omitted from requestWillBeSent when it is large; fetch it explicitly.
  if (record.hasPostData && !record.postData) {
    try {
      const result = await chrome.debugger.sendCommand({ tabId }, 'Network.getRequestPostData', { requestId });
      if (result && result.postData) record.postData = result.postData;
    } catch (error) {
      /* body no longer retained */
    }
  }

  let responseBody = '';
  let responseBodyTruncated = false;
  let responseBodyBlob = null;

  // Deep capture is the ONLY source that sees an <img>, <video> or @font-face load: those are not
  // fetch or XHR, so the page hook never observes them, and webRequest never carries a body. If an
  // IDOR that answers with another user's photo is to be provable from the capture table, the bytes
  // have to be taken here.
  const isMedia = !config.isTextualMime(record.mimeType);
  const wantBody = !errorText && config.captureResponseBodies &&
    (!isMedia || config.captureMediaBodies !== false);

  if (wantBody) {
    try {
      const result = await chrome.debugger.sendCommand({ tabId }, 'Network.getResponseBody', { requestId });
      if (result && typeof result.body === 'string') {
        // base64Encoded is set for a payload the debugger could not hand over as text. The
        // debugger has already given us every byte; storing "[base64 N chars]" in its place threw
        // away the one copy we will ever have.
        if (isMedia && result.base64Encoded) {
          responseBodyBlob = config.buildMediaBlob(
            config.base64ToBytes(result.body), record.mimeType, config.maxMediaBytes);
        } else if (result.base64Encoded) {
          // The base64 is kept verbatim, prefixed so a reader knows to decode it, and the prefix is
          // the only thing added.
          const trimmed = config.truncate(BASE64_BODY_PREFIX + result.body);
          responseBody = trimmed.body;
          responseBodyTruncated = trimmed.truncated;
        } else {
          // A media content type the debugger handed over AS TEXT, which is what image/svg+xml is.
          // It is text, so it is stored as text and stays greppable and readable.
          const trimmed = config.truncate(result.body);
          responseBody = trimmed.body;
          responseBodyTruncated = trimmed.truncated;
        }
      }
    } catch (error) {
      /* body evicted from the debugger buffer before we asked */
    }
  }

  const requestBody = config.truncate(record.postData || '');

  onCapture({
    tabId,
    url: record.url,
    method: record.method,
    statusCode: record.statusCode || 0,
    headers: record.headers || {},
    responseHeaders: record.responseHeaders || {},
    postData: requestBody.body,
    requestBodyTruncated: requestBody.truncated,
    responseBody,
    responseBodyTruncated,
    responseBodyBlob,
    mimeType: record.mimeType || '',
    resourceType: record.resourceType || '',
    initiator: record.initiator || '',
    redirectChain: record.redirectChain || [],
    durationMs: record.startedAt ? Date.now() - record.startedAt : 0,
    error: errorText || '',
  });
}

function lowerKeys(headers) {
  const result = {};
  Object.keys(headers || {}).forEach((key) => {
    result[key.toLowerCase()] = headers[key];
  });
  return result;
}
