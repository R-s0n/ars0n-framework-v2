// Isolated-world content script. Three jobs:
//
//   1. Relay between the MAIN-world page hook (injected.js) and the service worker. The hook has no
//      chrome.* access, so every capture it produces comes through here.
//   2. Hold a long-lived port to the worker and ping it. Port activity resets the MV3 idle timer,
//      which is what actually keeps the worker (and therefore the capture session) alive while the
//      user browses.
//   3. Draw the RECORDING overlay, driven by state pushed from the worker rather than a storage
//      flag, so it cannot keep claiming to record after the session has died.

const CHANNEL = '__ars0n_capture__';
const CONTROL = '__ars0n_control__';

const KEEPALIVE_PING_MS = 20000;
// Chrome force-disconnects a port after five minutes, so reconnect comfortably inside that window.
const PORT_RECONNECT_MS = 240000;

// Only the top frame holds the keepalive port and draws the overlay. Subframes still relay their
// captures, but over sendMessage: a page with twenty iframes must not open twenty ports each
// pinging every twenty seconds.
const IS_TOP_FRAME = window.top === window;

let recordingIndicator = null;
let keepalivePort = null;
let pingTimer = null;
let reconnectTimer = null;
let lastConfig = null;
let lastState = null;

/* ------------------------------------------------------------------ page hook relay */

window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.__ars0n !== CHANNEL || !data.record) return;

  // Prefer the port (cheap, and it keeps the worker awake); fall back to sendMessage if the port
  // is momentarily down so a capture is never dropped just because we were reconnecting.
  if (keepalivePort) {
    try {
      keepalivePort.postMessage({ action: 'hookCapture', record: data.record });
      return;
    } catch (error) {
      keepalivePort = null;
    }
  }

  try {
    chrome.runtime.sendMessage({ action: 'hookCapture', record: data.record }).catch(() => {});
  } catch (error) {
    /* extension context invalidated */
  }
});

function sendConfigToPage(config) {
  if (!config) return;
  lastConfig = config;
  try {
    window.postMessage({ __ars0n: CONTROL, config }, '*');
  } catch (error) {
    /* ignore */
  }
}

async function requestConfig() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getHookConfig' });
    if (response && response.success) sendConfigToPage(response.config);
  } catch (error) {
    /* worker asleep or context invalidated; the port ping will retry */
  }
}

/* ------------------------------------------------------------------ indicator */

function createRecordingIndicator() {
  if (recordingIndicator) return;
  // At document_start the root element may not exist yet; renderState is re-run on DOMContentLoaded.
  if (!document.documentElement) return;

  recordingIndicator = document.createElement('div');
  recordingIndicator.id = 'ars0n-recording-indicator';
  recordingIndicator.innerHTML = `
    <div style="
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      border: 4px solid #dc3545;
      pointer-events: none;
      z-index: 2147483647;
      box-shadow: inset 0 0 20px rgba(220, 53, 69, 0.3);
    "></div>
    <div id="ars0n-stats-badge" style="
      position: fixed;
      top: 10px;
      right: 10px;
      background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
      color: white;
      padding: 12px 16px;
      border-radius: 8px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 13px;
      font-weight: 600;
      z-index: 2147483647;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      pointer-events: none;
      display: flex;
      align-items: center;
      gap: 8px;
    ">
      <div style="
        width: 8px;
        height: 8px;
        background: #fff;
        border-radius: 50%;
        animation: ars0n-pulse 2s ease-in-out infinite;
      "></div>
      <span>RECORDING</span>
      <span style="
        margin-left: 8px;
        padding-left: 8px;
        border-left: 1px solid rgba(255, 255, 255, 0.3);
      " id="ars0n-endpoint-count">0 endpoints</span>
    </div>
    <style>
      @keyframes ars0n-pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.3; }
      }
    </style>
  `;

  document.documentElement.appendChild(recordingIndicator);
}

function removeRecordingIndicator() {
  if (recordingIndicator) {
    recordingIndicator.remove();
    recordingIndicator = null;
  }
}

function renderState(state) {
  lastState = state;

  if (!state || !state.active) {
    removeRecordingIndicator();
    // The page hook is deliberately NOT disarmed here.
    //
    // This function only ever sees the manual crawl's state, but the hook serves two recorders: the
    // crawl and a standalone auth-flow recording. Turning it off whenever the crawl was idle killed
    // response-body capture for auth recordings within about twenty seconds of every page load,
    // which is precisely when the interesting bodies (the token-issuing responses) arrive. The
    // symptom was an auth recording that captured requests but almost no response bodies, with
    // nothing anywhere reporting a problem.
    //
    // Arming is owned by the `hookConfig` message, which background.js computes from BOTH recorders
    // in pageHookConfig(). That is the only thing entitled to decide, so it is the only thing that
    // decides.
    return;
  }

  if (!IS_TOP_FRAME) return;

  createRecordingIndicator();
  const badge = document.getElementById('ars0n-endpoint-count');
  if (badge && state.stats) {
    const count = state.stats.endpointCount || 0;
    const label = count === 1 ? 'endpoint' : 'endpoints';
    const queued = state.stats.queuedCount ? ` (${state.stats.queuedCount} queued)` : '';
    badge.textContent = `${count} ${label}${queued}`;
  }
}

/* ------------------------------------------------------------------ keepalive port */

function connectKeepalive() {
  try {
    keepalivePort = chrome.runtime.connect({ name: 'ars0n-keepalive' });
  } catch (error) {
    teardown();
    return;
  }

  keepalivePort.onMessage.addListener((message) => {
    if (!message) return;
    if (message.action === 'state') renderState(message.state);
    if (message.action === 'hookConfig') sendConfigToPage(message.config);
  });

  keepalivePort.onDisconnect.addListener(() => {
    keepalivePort = null;
    setTimeout(connectKeepalive, 1000);
  });

  ping();
  try {
    keepalivePort.postMessage({ action: 'needConfig' });
  } catch (error) {
    /* will retry on the next ping */
  }
}

function ping() {
  if (!keepalivePort) return;
  try {
    keepalivePort.postMessage({ action: 'ping' });
  } catch (error) {
    keepalivePort = null;
  }
}

function teardown() {
  clearInterval(pingTimer);
  clearInterval(reconnectTimer);
  removeRecordingIndicator();
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message) return false;
  if (message.action === 'sessionState') {
    renderState(message.state);
    sendResponse({ success: true });
  }
  if (message.action === 'hookConfig') {
    sendConfigToPage(message.config);
    sendResponse({ success: true });
  }
  return false;
});

function initialize() {
  // Runs at document_start so the hook is configured before the page issues its first request.
  void requestConfig();

  if (!IS_TOP_FRAME) {
    // Subframes only need the hook configured and their captures relayed.
    chrome.runtime
      .sendMessage({ action: 'getSessionState' })
      .then((response) => {
        if (response && response.success) lastState = response.state;
      })
      .catch(() => {});
    return;
  }

  connectKeepalive();

  // The overlay cannot be drawn before the document root exists, so redraw once it does.
  document.addEventListener('DOMContentLoaded', () => renderState(lastState));

  pingTimer = setInterval(ping, KEEPALIVE_PING_MS);

  // Proactively cycle the port before Chrome's five-minute cap disconnects it.
  reconnectTimer = setInterval(() => {
    if (keepalivePort) {
      try {
        keepalivePort.disconnect();
      } catch (error) {
        /* already gone */
      }
      keepalivePort = null;
    }
    connectKeepalive();
  }, PORT_RECONNECT_MS);

  chrome.runtime
    .sendMessage({ action: 'getSessionState' })
    .then((response) => {
      if (response && response.success) renderState(response.state);
    })
    .catch(() => {});
}

initialize();
