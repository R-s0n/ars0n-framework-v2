// Popup UI.
//
// The capture state shown here is always read from the service worker, never from a storage flag.
// The previous version mirrored `isCapturing` into chrome.storage.local and rendered that, so after
// the worker was terminated the popup kept showing "Capturing" with frozen counts while nothing was
// actually being recorded.

const DEFAULT_FRAMEWORK_URL = 'http://localhost';
const POLL_INTERVAL_MS = 2000;

// The categories the framework stores on an auth flow. The values are the ones the API expects; the
// labels are what the user reads.
const AUTH_CATEGORY_LABELS = {
  register: 'Register',
  login: 'Login',
  mfa_otp: 'MFA/OTP',
  magic_link: 'Magic Link',
  reset: 'Reset',
};

// Mirror of lib/scope.js looksLikeAuthHost. popup.html loads popup.js as a classic script and cannot
// import the ES module, so the seed identity-provider patterns are duplicated here exactly, the same
// way extraHostsByTarget mirrors the worker's shape. Used ONLY to show a quiet "(IdP?)" hint on a
// dropped host so the operator notices it might be an auth host; it never classifies or sends
// anything. An auth service not on this list still works - it just gets no hint.
const AUTH_HOST_HINT_PATTERNS = [
  'cognito-idp.*.amazonaws.com', 'cognito-identity.*.amazonaws.com', '*.amazoncognito.com',
  'accounts.google.com', 'oauth2.googleapis.com', 'identitytoolkit.googleapis.com',
  'securetoken.googleapis.com',
  'login.microsoftonline.com', 'login.microsoft.com', 'login.live.com', '*.b2clogin.com',
  '*.okta.com', '*.oktapreview.com', '*.okta-emea.com',
  '*.auth0.com',
  '*.pingone.com', '*.pingidentity.com', '*.onelogin.com',
  'appleid.apple.com',
  'www.facebook.com', 'graph.facebook.com', 'github.com', 'gitlab.com',
  'login.salesforce.com', 'test.salesforce.com', '*.my.salesforce.com',
  '*.clerk.accounts.dev', '*.supabase.co', '*.supabase.in', 'api.stytch.com', '*.stytch.com',
  'api.workos.com', '*.frontegg.com', '*.fusionauth.io', '*.descope.com',
  '*.duosecurity.com',
];
function looksLikeAuthHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.+$/, '').split(':')[0];
  if (!host) return false;
  const esc = (s) => String(s).replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  return AUTH_HOST_HINT_PATTERNS.some((pattern) => {
    if (pattern.startsWith('*.')) {
      const base = pattern.slice(2);
      return host === base || host.endsWith('.' + base);
    }
    if (pattern.includes('*')) {
      return new RegExp('^' + pattern.split('*').map(esc).join('[^.]+') + '$').test(host);
    }
    return host === pattern || host.endsWith('.' + pattern);
  });
}

let sessionState = {
  active: false,
  scopeHosts: [],
  extraHosts: [],
  authHosts: [],
  observedOutOfScope: {},
  deepCapture: { enabled: false, attachedTabs: [], errors: [] },
  stats: { requestCount: 0, endpointCount: 0, queuedCount: 0, failedCount: 0, withResponseBody: 0 },
};
// Auth flow recording is its own session in the worker, so the popup keeps its own copy of it and
// never infers one from the other.
let authState = {
  active: false,
  recordingId: null,
  scopeTargetId: null,
  name: '',
  category: 'login',
  stats: { requestCount: 0, queuedCount: 0, failedCount: 0 },
  lastError: null,
};
let frameworkUrl = DEFAULT_FRAMEWORK_URL;
let availableTargets = [];
let isConnected = false;
let targetsLoaded = false;
// The 2s poll is async and setInterval does not wait for the previous tick, so a slow tick could
// stack on the next one. This guard makes it skip rather than overlap.
let pollInFlight = false;
// Extra scope hosts, keyed by scope target id. Never a flat list: a host added while testing one
// target must not still be in scope when the next recording starts against a different one, which
// is what a single shared array used to do. popup.js keeps its own copy of this shape rather than
// importing lib/scope.js because popup.html loads it as a classic script and it cannot use ES
// imports; lib/scope.js holds the canonical helpers for the service worker and both are tested.
let extraHostsByTarget = {};
// The retired global list. Parked, not adopted, and not read as scope. See loadSettings.
let legacyExtraHosts = [];
// Errors raised by a user action stay visible until the next action, so the 2s state poll cannot
// wipe a message the user has not read yet.
let localError = null;
// The recorder's own error and result lines, kept apart from the crawl's so a stopped recording
// cannot overwrite a capture error the user has not read, or the other way round.
let authError = null;
let authResult = null;
let authSectionOpen = false;
let authSectionAutoOpened = false;

document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  initializeEventListeners();
  // Register the retry poll BEFORE the first connection check so that even if that check is slow
  // (its fetches are time-bounded but not instant), the poll is already installed and can recover.
  setInterval(pollTick, POLL_INTERVAL_MS);
  await refreshSessionState();
  await refreshAuthState();
  await checkFrameworkConnection();
  await loadScopeRules();
  await loadAuthHosts();
});

// One poll tick. Non-reentrant, and it retries the TARGET load whenever we are connected but have
// no targets loaded — not only when disconnected. The old guard was `if (!isConnected)`, which
// never re-ran the target fetch once /api/health had succeeded, so a single stalled or failed
// /api/scopetarget/read left the dropdown stuck on "Loading targets…" until the popup was reloaded.
async function pollTick() {
  if (pollInFlight) return;
  pollInFlight = true;
  try {
    await refreshSessionState();
    await refreshAuthState();
    if (!isConnected) await checkFrameworkConnection();
    else if (!targetsLoaded) await loadURLTargets();
  } finally {
    pollInFlight = false;
  }
}

function initializeEventListeners() {
  document.getElementById('startCaptureBtn').addEventListener('click', startCapture);
  document.getElementById('stopCaptureBtn').addEventListener('click', stopCapture);
  document.getElementById('openFrameworkBtn').addEventListener('click', openFramework);
  document.getElementById('helpLink').addEventListener('click', openHelp);
  document.getElementById('toggleSettingsBtn').addEventListener('click', toggleSettings);
  document.getElementById('saveSettingsBtn').addEventListener('click', saveFrameworkUrl);
  document.getElementById('includeSubdomains').addEventListener('change', saveSettings);
  document.getElementById('captureStatic').addEventListener('change', saveSettings);
  document.getElementById('captureResponseBodies').addEventListener('change', saveSettings);
  document.getElementById('captureMediaBodies').addEventListener('change', saveSettings);
  document.getElementById('deepCapture').addEventListener('change', toggleDeepCapture);
  // Scope belongs to a target, so changing the target changes which extra hosts apply. Without
  // this the list keeps showing the previous target's hosts, which is the thing that made the old
  // global list look correct while it was quietly widening scope.
  document.getElementById('targetSelect').addEventListener('change', () => {
    lastScopeSignature = null;
    updateUI();
    // Rules belong to a target too, so they are reloaded for the same reason the host list is.
    void loadScopeRules();
    void loadAuthHosts();
  });
  wireScopeRules();
  document.getElementById('addHostBtn').addEventListener('click', () => {
    const input = document.getElementById('addHostInput');
    void addHost(input.value).then(() => {
      input.value = '';
    });
  });
  document.getElementById('addHostInput').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    const input = event.target;
    void addHost(input.value).then(() => {
      input.value = '';
    });
  });
  // The blue "Auth" button beside Add classifies a typed host as an auth host (recorded for refresh,
  // never scanned) rather than bringing it into scope. It is for a custom auth host the capturer has
  // not surfaced on its own, so the operator does not have to wait for it to appear in a list.
  document.getElementById('addAuthHostBtn').addEventListener('click', () => {
    const input = document.getElementById('addHostInput');
    void addAuthHost(input.value).then(() => {
      input.value = '';
    });
  });

  document.getElementById('authFlowToggle').addEventListener('click', () => {
    setAuthSectionOpen(!authSectionOpen);
  });
  document.getElementById('startAuthRecordingBtn').addEventListener('click', startAuthRecording);
  document.getElementById('stopAuthRecordingBtn').addEventListener('click', stopAuthRecording);
  // Remembered across popup closes: the popup is torn down every time it loses focus, and retyping
  // the flow name before every recording gets old fast.
  document.getElementById('authFlowName').addEventListener('change', saveAuthFlowFields);
  document.getElementById('authFlowCategory').addEventListener('change', saveAuthFlowFields);
}

// The scope target the popup is acting on. Extra hosts hang off this, so with nothing selected
// there is no bucket to read and the scope is the target's own host alone.
function selectedTargetId() {
  const el = document.getElementById('targetSelect');
  return (el && el.value) || null;
}

function currentExtraHosts() {
  const targetId = selectedTargetId();
  if (!targetId) return [];
  const hosts = extraHostsByTarget[targetId];
  return Array.isArray(hosts) ? hosts : [];
}

async function loadSettings() {
  const result = await chrome.storage.local.get([
    'includeSubdomains',
    'captureStatic',
    'captureResponseBodies',
    'captureMediaBodies',
    'deepCapture',
    'extraHostsByTarget',
    'extraHosts',
    'extraHostsLegacy',
    'frameworkUrl',
    'authFlowName',
    'authFlowCategory',
  ]);

  document.getElementById('includeSubdomains').checked = result.includeSubdomains !== false;
  // Static assets are captured by default: JavaScript files are among the highest-value artifacts
  // in the URL workflow (LinkFinder reads them), and excluding them by default meant the most
  // useful responses were being thrown away.
  document.getElementById('captureStatic').checked = result.captureStatic !== false;
  document.getElementById('captureResponseBodies').checked = result.captureResponseBodies !== false;
  document.getElementById('captureMediaBodies').checked = result.captureMediaBodies !== false;
  document.getElementById('deepCapture').checked = Boolean(result.deepCapture);

  const storedMap = result.extraHostsByTarget;
  extraHostsByTarget =
    storedMap && typeof storedMap === 'object' && !Array.isArray(storedMap) ? storedMap : {};

  // One-time retirement of the old global list. The legacy hosts are NOT adopted by any target:
  // there is no record of which target they were typed for, because the recording state that knew
  // lives in chrome.storage.session and does not survive a browser restart. Attaching them to
  // whichever target happens to be selected would recreate exactly the leak this shape removes.
  // They are moved aside rather than deleted, so nothing an operator typed is destroyed.
  legacyExtraHosts = Array.isArray(result.extraHostsLegacy) ? result.extraHostsLegacy : [];
  const orphaned = Array.isArray(result.extraHosts) ? result.extraHosts : [];
  if (orphaned.length) {
    legacyExtraHosts = Array.from(new Set([...legacyExtraHosts, ...orphaned]));
    await chrome.storage.local.set({ extraHosts: [], extraHostsLegacy: legacyExtraHosts });
  }

  frameworkUrl = result.frameworkUrl || DEFAULT_FRAMEWORK_URL;
  document.getElementById('frameworkUrl').value = frameworkUrl;

  document.getElementById('authFlowName').value = result.authFlowName || '';
  document.getElementById('authFlowCategory').value = result.authFlowCategory || 'login';
}

async function saveAuthFlowFields() {
  await chrome.storage.local.set({
    authFlowName: document.getElementById('authFlowName').value.trim(),
    authFlowCategory: document.getElementById('authFlowCategory').value || 'login',
  });
}

function currentSettings() {
  return {
    includeSubdomains: document.getElementById('includeSubdomains').checked,
    captureStatic: document.getElementById('captureStatic').checked,
    captureResponseBodies: document.getElementById('captureResponseBodies').checked,
    captureMediaBodies: document.getElementById('captureMediaBodies').checked,
    deepCapture: document.getElementById('deepCapture').checked,
    extraHosts: currentExtraHosts(),
  };
}

async function saveSettings() {
  const settings = currentSettings();
  await chrome.storage.local.set({
    includeSubdomains: settings.includeSubdomains,
    captureStatic: settings.captureStatic,
    captureResponseBodies: settings.captureResponseBodies,
    captureMediaBodies: settings.captureMediaBodies,
  });

  if (sessionState.active) {
    // Deliberately WITHOUT extraHosts. Once recording has started the worker owns the session's
    // scope: addScopeHost and removeScopeHost maintain it in state.settings, and the worker's
    // handler spreads whatever patch it is given over that. Sending the popup's copy would let a
    // click on any of these three checkboxes overwrite the live capture boundary with whatever the
    // popup happened to have read, which narrows scope mid-recording and silently drops the
    // target's cross-domain traffic. The popup's list is for building the NEXT session, not
    // steering the running one.
    const { extraHosts, ...withoutScope } = settings;
    await sendToWorker({ action: 'updateSettings', settings: withoutScope });
    await refreshSessionState();
  }
}

// Deep capture can be turned on and off mid-session: attaching or detaching the debugger does not
// disturb the recording, so there is no reason to make the user restart to change their mind.
async function toggleDeepCapture() {
  const enabled = document.getElementById('deepCapture').checked;
  const response = await sendToWorker({ action: 'setDeepCapture', enabled });
  if (response && !response.success) {
    localError = response.error || 'Could not change deep capture';
  }
  await refreshSessionState();
}

// Auth hosts the popup knows about for the selected target, used for the list it renders when no
// recording is live. The server is the source of truth (an auth_host row), so this is refreshed from
// it after any change; during a recording the list renders from the worker's live state instead.
let authHostsForTarget = [];

// Classifies a host as an AUTH HOST: recorded from now on so the session it mints can be refreshed,
// and marked out of scope server-side (in_scope=false) so no scan ever touches it. Works whether or
// not a recording is live: during a recording it goes through the worker so the live capture picks it
// up immediately; otherwise it is persisted to the selected target for the next recording. This is
// what the "Auth" button beside the host input calls for a CUSTOM auth host, and what the per-row
// Auth button calls for one the capturer already observed.
async function addAuthHost(host) {
  const value = String(host || '').trim();
  if (!value) return;

  if (sessionState.active) {
    const response = await sendToWorker({ action: 'addAuthHost', host: value });
    if (response && response.success) localError = null;
    else localError = (response && response.error) || 'Could not classify as an auth host';
    await refreshSessionState();
    await loadAuthHosts();
    return;
  }

  const targetId = selectedTargetId();
  if (!targetId) {
    localError = 'Select a target first: an auth host belongs to one target.';
    updateUI();
    return;
  }
  try {
    const res = await fetchJSONWithTimeout(
      `${frameworkUrl}/api/manual-crawl/hosts/${targetId}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hosts: [value], auth_host: true, in_scope: false,
          auth_reason: 'classified as an auth host from the popup' }) },
      8000);
    if (!res.ok) throw new Error((res.body && res.body.message) || `framework returned ${res.status}`);
    localError = null;
  } catch (error) {
    localError = 'Could not classify as an auth host: ' + error.message;
  }
  await loadAuthHosts();
  updateUI();
}

// Removes an auth-host classification, both the live boundary (during a recording) and the server row.
async function removeAuthHost(host) {
  const value = String(host || '').trim();
  if (!value) return;

  if (sessionState.active) {
    await sendToWorker({ action: 'removeAuthHost', host: value });
    await refreshSessionState();
    await loadAuthHosts();
    return;
  }

  const targetId = selectedTargetId();
  if (targetId) {
    try {
      await fetchJSONWithTimeout(
        `${frameworkUrl}/api/manual-crawl/hosts/${targetId}`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hosts: [value], auth_host: false }) },
        8000);
    } catch (error) {
      /* best effort; the list refresh below reflects the true state either way */
    }
  }
  await loadAuthHosts();
  updateUI();
}

// Loads the classified auth hosts for the selected target from the server (the source of truth) so
// the list can be shown even before a recording starts. Called on target change and after a change.
async function loadAuthHosts() {
  const targetId = currentScopeTargetId();
  if (!targetId) {
    authHostsForTarget = [];
    renderAuthHosts();
    return;
  }
  try {
    const res = await fetchJSONWithTimeout(`${frameworkUrl}/api/manual-crawl/hosts/${targetId}`, {}, 8000);
    const hosts = (res.ok && res.body && Array.isArray(res.body.hosts)) ? res.body.hosts : [];
    authHostsForTarget = hosts.filter((h) => h && h.auth_host && h.host).map((h) => h.host);
  } catch (error) {
    authHostsForTarget = [];
  }
  renderAuthHosts();
}

// Renders the auth-host chips. During a recording the worker's live list is authoritative (the 2s
// poll keeps sessionState current); otherwise the server-loaded list is used. Each chip removes.
function renderAuthHosts() {
  const block = document.getElementById('authHostsBlock');
  const list = document.getElementById('authHostList');
  if (!block || !list) return;
  const hosts = sessionState.active ? (sessionState.authHosts || []) : authHostsForTarget;
  list.textContent = '';
  if (!hosts.length) {
    block.classList.add('d-none');
    return;
  }
  block.classList.remove('d-none');
  hosts.forEach((host) => {
    list.appendChild(chip(host, 'info', () => void removeAuthHost(host)));
  });
}

async function addHost(host) {
  const value = String(host || '').trim();
  if (!value) return;

  if (sessionState.active) {
    const response = await sendToWorker({ action: 'addScopeHost', host: value });
    if (response && response.success) {
      localError = null;
      const stored = await chrome.storage.local.get(['extraHostsByTarget']);
      extraHostsByTarget = stored.extraHostsByTarget || {};
    } else {
      localError = (response && response.error) || 'Could not add host';
    }
    await refreshSessionState();
    return;
  }

  // Not recording: remember it against THIS target for the next session.
  const targetId = selectedTargetId();
  if (!targetId) {
    localError = 'Select a target first: extra scope hosts belong to one target.';
    updateUI();
    return;
  }

  const normalized = value.replace(/^https?:\/\//i, '').replace(/^\*\./, '').split('/')[0].split(':')[0].toLowerCase();
  if (!normalized.includes('.')) {
    localError = 'Not a usable hostname';
    updateUI();
    return;
  }
  const current = currentExtraHosts();
  if (!current.includes(normalized)) {
    extraHostsByTarget = { ...extraHostsByTarget, [targetId]: [...current, normalized] };
    await chrome.storage.local.set({ extraHostsByTarget });
  }
  localError = null;
  updateUI();
}

async function removeHost(host) {
  if (sessionState.active) {
    await sendToWorker({ action: 'removeScopeHost', host });
    const stored = await chrome.storage.local.get(['extraHostsByTarget']);
    extraHostsByTarget = stored.extraHostsByTarget || {};
    await refreshSessionState();
    return;
  }
  const targetId = selectedTargetId();
  if (!targetId) return;

  extraHostsByTarget = {
    ...extraHostsByTarget,
    [targetId]: currentExtraHosts().filter((h) => h !== host),
  };
  await chrome.storage.local.set({ extraHostsByTarget });
  updateUI();
}

function sendToWorker(message) {
  return chrome.runtime.sendMessage(message).catch((error) => ({ success: false, error: error.message }));
}

// fetch() has no timeout, so a socket the framework accepts but never answers (its backend busy
// ingesting the recording's capture batches on the same localhost origin, a half-open socket after
// the machine slept) leaves the await pending forever — neither the success path nor the catch
// runs. That is the mechanism behind the popup wedging on "Loading targets…" with no recovery until
// reload. Bounding every framework fetch turns a stall into a reject the caller's catch handles and
// the poll retries. The default is deliberately generous so a legitimately slow-but-working
// localhost is not aborted mid-response.
function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || 8000);
  return fetch(url, { ...(options || {}), signal: controller.signal }).finally(() => clearTimeout(timer));
}

// fetchWithTimeout clears its abort timer the instant fetch() resolves (headers), so a caller that
// then awaited response.json() on a header-then-body stall hung FOREVER — and because loadURLTargets
// is awaited inside the non-reentrant pollTick, that stranded pollInFlight and froze the dropdown on
// "Loading targets…" with no recovery until the popup was reloaded. This keeps one AbortController
// armed across the body read too, so a stall rejects (the caller's catch runs, the poll retries)
// instead of hanging. Use it wherever a JSON body is awaited; the health check and DELETE read no
// body and stay on fetchWithTimeout.
async function fetchJSONWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || 8000);
  try {
    const res = await fetch(url, { ...(options || {}), signal: controller.signal });
    let body = null;
    try {
      body = await res.json();
    } catch (error) {
      if (error && error.name === 'AbortError') throw error;
      /* non-JSON body */
    }
    return { ok: res.ok, status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

/* ------------------------------------------------------------------ scope rendering */

function chip(text, variant, onRemove) {
  const span = document.createElement('span');
  span.className = `badge bg-${variant} d-inline-flex align-items-center gap-1`;
  span.style.fontSize = '10px';
  span.style.fontWeight = '500';
  span.appendChild(document.createTextNode(text));

  if (onRemove) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn-close btn-close-white';
    button.style.fontSize = '6px';
    button.setAttribute('aria-label', `Remove ${text}`);
    button.addEventListener('click', onRemove);
    span.appendChild(button);
  }
  return span;
}

// Showing the resolved scope, and everything just outside it, makes the most common "why did
// nothing get captured" case self-diagnosing: if the app's API host is sitting in the second list,
// one click fixes it without restarting the recording.
//
// The out-of-scope list is a click target that updates every two seconds while traffic is flowing,
// so it is reconciled rather than rebuilt. Three separate things used to make it unusable: rows
// were sorted by hit count so they reordered whenever a count ticked, the list was truncated so
// entries vanished and reappeared, and the whole thing was destroyed and recreated on every poll,
// which could swap a button out from under the pointer mid-click.

// host -> the live DOM nodes for that row, so counts update in place and rows never move.
const outOfScopeRows = new Map();
// Adds in flight, so the two-second poll cannot re-enable a button the user just pressed.
const pendingHostAdds = new Set();
const pendingAuthAdds = new Set();
let lastScopeSignature = null;

function renderScope() {
  const hosts = sessionState.active
    ? sessionState.scopeHosts || []
    : buildPreviewScope();
  const sessionExtras = sessionState.active ? sessionState.extraHosts || [] : currentExtraHosts();

  // Only rebuild the chips when they actually changed; otherwise the poll re-creates identical
  // nodes twice a second for no reason.
  const signature = JSON.stringify([hosts, sessionExtras]);
  if (signature !== lastScopeSignature) {
    lastScopeSignature = signature;
    const list = document.getElementById('scopeHostList');
    list.textContent = '';

    if (!hosts.length) {
      const empty = document.createElement('span');
      empty.className = 'text-muted small';
      empty.textContent = 'Select a target to see its scope.';
      list.appendChild(empty);
    } else {
      hosts.forEach((host) => {
        const isExtra = sessionExtras.includes(host);
        list.appendChild(
          chip(host, isExtra ? 'danger' : 'secondary', isExtra ? () => void removeHost(host) : null)
        );
      });
    }
  }

  renderOutOfScope();
  renderAuthHosts();
}

/* ------------------------------------------------------------------ scope rules */

// The popup never parses a rule itself.
//
// popup.js is loaded as a plain script, not a module, so it could not import the parser without
// breaking popup.test.mjs, which runs this file through vm. But the better reason is that every
// sentence shown here comes from /scope-rules/preview, which is the SAME evaluator that will
// enforce the rule. A locally computed sentence could differ from the enforced boundary, and a
// preview that disagrees with enforcement is worse than no preview.

let scopeRules = [];
let scopeRulesActive = false;
let previewTimer = null;
let lastPreviewText = '';

function currentScopeTargetId() {
  const select = document.getElementById('targetSelect');
  return (sessionState.active && sessionState.scopeTargetId)
    ? sessionState.scopeTargetId
    : (select ? select.value : '');
}

async function loadScopeRules() {
  const targetId = currentScopeTargetId();
  const list = document.getElementById('scopeRuleList');
  if (!list) return;

  if (!targetId) {
    scopeRules = [];
    scopeRulesActive = false;
    renderScopeRules();
    return;
  }
  try {
    const res = await fetchJSONWithTimeout(`${frameworkUrl}/api/scope-rules/${targetId}`, {}, 8000);
    if (!res.ok) throw new Error(`framework returned ${res.status}`);
    const body = res.body || {};
    scopeRules = body.rules || [];
    scopeRulesActive = !!body.rules_active;
  } catch (error) {
    scopeRules = [];
    scopeRulesActive = false;
  }
  renderScopeRules();
}

function renderScopeRules() {
  const list = document.getElementById('scopeRuleList');
  if (!list) return;
  list.textContent = '';

  const banner = document.getElementById('scopeRulesActive');
  if (banner) banner.classList.toggle('d-none', !scopeRulesActive);

  // A rule the framework accepted but the worker could not parse means the two evaluators disagree,
  // and the worker has fallen back to the host list. That must be visible here: recording by a
  // different boundary than the scanners enforce is not a console-only fact.
  const divergence = document.getElementById('scopeRulesDivergence');
  if (divergence) {
    const message = sessionState.scopeRulesError || '';
    divergence.textContent = message;
    divergence.classList.toggle('d-none', !message);
  }

  if (!scopeRules.length) {
    const empty = document.createElement('div');
    empty.className = 'text-muted';
    empty.style.fontSize = '11px';
    empty.textContent = 'No rules. The host list above is the boundary.';
    list.appendChild(empty);
    return;
  }

  scopeRules.forEach((rule) => {
    const row = document.createElement('div');
    row.className = 'd-flex align-items-start gap-2 mb-1';

    const dot = document.createElement('span');
    const effectBadge = rule.effect === 'deny' ? 'danger' : rule.effect === 'auth' ? 'info' : 'secondary';
    dot.className = `badge bg-${effectBadge} flex-shrink-0`;
    dot.style.fontSize = '9px';
    dot.textContent = rule.effect === 'deny' ? 'DENY' : rule.effect === 'auth' ? 'AUTH' : 'ALLOW';

    const text = document.createElement('div');
    text.className = 'flex-grow-1';
    text.style.fontSize = '11px';
    // The SENTENCE is the primary text, not the pattern. A chip reading "example.com" silently
    // means "and every subdomain", which is exactly what gets misread.
    text.textContent = rule.sentence;
    if (!rule.enabled) {
      text.textContent += '  (off)';
      text.classList.add('text-muted');
    }

    const code = document.createElement('div');
    code.className = 'text-muted';
    code.style.fontSize = '10px';
    code.textContent = rule.canonical;
    text.appendChild(code);

    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'btn btn-link btn-sm text-danger p-0 flex-shrink-0';
    remove.style.fontSize = '11px';
    remove.textContent = '✕';
    remove.title = 'Remove this rule';
    remove.addEventListener('click', () => void removeScopeRule(rule.id));

    row.appendChild(dot);
    row.appendChild(text);
    row.appendChild(remove);
    list.appendChild(row);
  });
}

async function previewScopeRule(typed) {
  const out = document.getElementById('scopeRulePreview');
  if (!out) return;
  if (!typed.trim()) {
    out.textContent = '';
    out.className = 'small mt-1';
    return;
  }
  try {
    const res = await fetchJSONWithTimeout(`${frameworkUrl}/api/scope-rules/preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scope_target_id: currentScopeTargetId(), typed }),
    }, 8000);
    const body = res.body || {};
    if (!body.ok) {
      out.className = 'small mt-1 text-danger';
      out.textContent = body.error || 'not a valid rule';
      return;
    }
    const bits = [body.rule.sentence];
    const added = (body.newly_allowed || []).length;
    const denied = (body.newly_denied || []).length;
    if (added) bits.push(`+${added} host${added === 1 ? '' : 's'} already seen`);
    if (denied) bits.push(`−${denied} currently in scope`);
    out.className = body.rule.blast === 'wide' ? 'small mt-1 text-warning' : 'small mt-1 text-muted';
    out.textContent = bits.join('  ·  ') + (body.warning ? '  ·  ' + body.warning : '');
  } catch (error) {
    out.className = 'small mt-1 text-muted';
    out.textContent = '';
  }
}

// Live preview for the input. A single rule gets the real server preview (the same evaluator that
// will enforce it). A pasted block of several rules cannot be previewed one-shot server-side, so it
// just reports how many are ready; each is validated for real when Add runs.
async function previewScopeInput(typed) {
  const out = document.getElementById('scopeRulePreview');
  if (!out) return;
  const rules = splitScopeRuleBlock(typed);
  if (rules.length === 0) {
    out.textContent = '';
    out.className = 'small mt-1';
    return;
  }
  if (rules.length === 1) {
    await previewScopeRule(rules[0]);
    return;
  }
  out.className = 'small mt-1 text-muted';
  out.textContent = `${rules.length} rules ready. Ctrl+Enter or Add to apply.`;
}

// Splits a pasted block into individual rule strings, so an operator can add many rules at once
// instead of one line at a time.
//
// Newlines are always a boundary: no rule spans two lines. Commas are a boundary too, EXCEPT on a
// line that is a regex rule, because a regex repetition like {1,3} contains a comma and splitting on
// it would break the pattern. A line whose body (after an optional leading "!") begins with
// re:/regex: is therefore kept whole. Blank pieces are dropped and exact duplicates collapse (a
// pasted block that overlaps an earlier one is common), preserving first-seen order. Pure and free
// of the DOM so popup.test.mjs can exercise it directly.
function splitScopeRuleBlock(text) {
  const out = [];
  const seen = new Set();
  const push = (piece) => {
    const rule = String(piece).trim();
    if (!rule) return;
    const key = rule.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push(rule);
  };
  String(text === null || text === undefined ? '' : text)
    .split(/\r\n|\r|\n/)
    .forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      // A regex rule may legitimately contain commas ({m,n}); never comma-split one.
      if (/^!?\s*(re|regex):/i.test(trimmed)) {
        push(trimmed);
        return;
      }
      trimmed.split(',').forEach(push);
    });
  return out;
}

// POSTs one typed rule and normalises the outcome. 428 means the rule is "wide" and needs a
// deliberate second act, whose token is the rule's own canonical text (see CreateScopeRule). The
// add is idempotent server-side (ON CONFLICT DO UPDATE), so re-sending an existing rule is a 201,
// not an error, which is why a re-pasted block does not report failures.
async function postScopeRule(targetId, typed, confirmWide) {
  try {
    const res = await fetchWithTimeout(`${frameworkUrl}/api/scope-rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scope_target_id: targetId, typed, confirm_wide: confirmWide || '' }),
    }, 8000);
    if (res.status === 428) {
      const message = await res.text();
      const canonical = (message.match(/confirm_wide exactly as "([^"]+)"/) || [])[1] || '';
      return { ok: false, wide: true, canonical, message };
    }
    if (!res.ok) {
      const message = (await res.text()) || `framework returned ${res.status}`;
      return { ok: false, message };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, message: error.message };
  }
}

// Adds every rule in the input. One line, one rule, or a whole pasted block all take the same path.
// Wide rules are collected and confirmed ONCE at the end rather than one prompt each, and on any
// failure the input is rewritten to just the lines that still need attention so nothing an operator
// typed is lost.
async function addScopeRule() {
  const input = document.getElementById('scopeRuleInput');
  const out = document.getElementById('scopeRulePreview');
  const targetId = currentScopeTargetId();
  const rules = splitScopeRuleBlock(input ? input.value : '');
  if (!rules.length) return;
  if (!targetId) {
    if (out) {
      out.className = 'small mt-1 text-danger';
      out.textContent = 'Select a target first.';
    }
    return;
  }

  if (out) {
    out.className = 'small mt-1 text-muted';
    out.textContent = `Adding ${rules.length} rule${rules.length === 1 ? '' : 's'}...`;
  }

  const applied = [];
  const failed = [];   // { typed, message }
  const needWide = [];  // { typed, canonical }

  for (const typed of rules) {
    const result = await postScopeRule(targetId, typed, '');
    if (result.ok) applied.push(typed);
    else if (result.wide) needWide.push({ typed, canonical: result.canonical });
    else failed.push({ typed, message: result.message });
  }

  // The wide rules, confirmed together: one dialog listing them, not N interruptions in a row.
  if (needWide.length) {
    const list = needWide.map((w) => '  ' + w.typed).join('\n');
    const ok = window.confirm(
      `${needWide.length} rule${needWide.length === 1 ? '' : 's'} can admit hosts nobody has seen `
      + `yet:\n\n${list}\n\nAdd ${needWide.length === 1 ? 'it' : 'them'} anyway? `
      + `(Bound with "within <domain>" to avoid this.)`);
    for (const w of needWide) {
      if (!ok) { failed.push({ typed: w.typed, message: 'skipped; needs confirmation' }); continue; }
      if (!w.canonical) { failed.push({ typed: w.typed, message: 'could not confirm' }); continue; }
      const result = await postScopeRule(targetId, w.typed, w.canonical);
      if (result.ok) applied.push(w.typed);
      else failed.push({ typed: w.typed, message: result.message || 'not added' });
    }
  }

  // Keep only what still needs attention; everything applied cleanly disappears from the box.
  if (input) input.value = failed.map((f) => f.typed).join('\n');
  lastPreviewText = input ? input.value : '';

  await loadScopeRules();
  // The worker holds its own parsed copy, so it has to be told the boundary moved.
  await sendToWorker({ action: 'refreshScopeRules' });

  renderScopeAddSummary(out, applied, failed);
}

// The outcome line under the input. Successes are counted; each failure is named with its own
// reason, so a single bad line in a large paste is findable rather than swallowed by a count.
function renderScopeAddSummary(out, applied, failed) {
  if (!out) return;
  const parts = [];
  if (applied.length) parts.push(`${applied.length} added`);
  if (failed.length) parts.push(`${failed.length} not added`);
  out.className = 'small mt-1 ' + (failed.length ? 'text-danger' : 'text-muted');
  out.textContent = parts.join('  ·  ') || 'Nothing to add.';
  failed.forEach((f) => {
    const line = document.createElement('div');
    line.style.fontSize = '10px';
    line.textContent = `${f.typed}: ${f.message}`;
    out.appendChild(line);
  });
}

async function removeScopeRule(ruleId) {
  try {
    await fetchWithTimeout(`${frameworkUrl}/api/scope-rules/${ruleId}`, { method: 'DELETE' }, 8000);
    await loadScopeRules();
    await sendToWorker({ action: 'refreshScopeRules' });
  } catch (error) {
    /* the list reloads on the next poll regardless */
  }
}

function wireScopeRules() {
  const input = document.getElementById('scopeRuleInput');
  const add = document.getElementById('scopeRuleAdd');
  const help = document.getElementById('scopeRulesHelpToggle');
  if (!input || !add) return;

  add.addEventListener('click', () => void addScopeRule());
  // This is a textarea now, so Enter inserts a newline and a block can be composed or pasted.
  // Ctrl/Cmd+Enter applies, matching the "send" convention of a multi-line field.
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      void addScopeRule();
    }
  });
  // Debounced so a preview request is not sent per keystroke.
  input.addEventListener('input', () => {
    const typed = input.value;
    if (typed === lastPreviewText) return;
    lastPreviewText = typed;
    if (previewTimer) clearTimeout(previewTimer);
    previewTimer = setTimeout(() => void previewScopeInput(typed), 300);
  });
  if (help) {
    help.addEventListener('click', (event) => {
      event.preventDefault();
      document.getElementById('scopeRulesHelp').classList.toggle('d-none');
    });
  }
}

function createOutOfScopeRow(host) {
  const row = document.createElement('div');
  row.className = 'd-flex align-items-center gap-2 px-2 py-1 rounded';

  const label = document.createElement('span');
  label.className = 'text-truncate flex-grow-1';
  label.style.fontSize = '11px';
  label.title = host;
  label.textContent = host;

  // A quiet "(IdP?)" hint on a host that matches a known identity-provider pattern. Suggestion only:
  // it never classifies or sends anything; the operator confirms with the Auth button.
  const hint = document.createElement('span');
  hint.className = 'text-info flex-shrink-0';
  hint.style.fontSize = '9px';
  if (looksLikeAuthHost(host)) {
    hint.textContent = 'IdP?';
    hint.title = 'Looks like an identity provider. Use "Auth" to record it for session refresh '
      + 'without ever scanning it.';
  }

  // The count lives in its own fixed-width cell. Inline in the label, it pushed the Add button
  // sideways every time it grew a digit.
  const count = document.createElement('span');
  count.className = 'text-muted text-end flex-shrink-0';
  count.style.fontSize = '10px';
  count.style.width = '38px';

  // "Auth" classifies the host as an auth host: recorded so the session it mints can be refreshed,
  // never scanned. "Add" brings it into scope for scanning. The two are distinct, and either removes
  // the row.
  const authButton = document.createElement('button');
  authButton.type = 'button';
  authButton.className = 'btn btn-outline-info btn-sm py-0 px-2 flex-shrink-0';
  authButton.style.fontSize = '10px';
  authButton.style.width = '46px';
  authButton.textContent = 'Auth';
  authButton.title = 'Classify as an auth host: recorded so the session can be refreshed, never scanned.';
  authButton.addEventListener('click', async () => {
    if (pendingAuthAdds.has(host)) return;
    pendingAuthAdds.add(host);
    renderOutOfScope();
    try {
      await addAuthHost(host);
    } finally {
      pendingAuthAdds.delete(host);
      renderOutOfScope();
    }
  });

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'btn btn-outline-danger btn-sm py-0 px-2 flex-shrink-0';
  button.style.fontSize = '10px';
  button.style.width = '46px';
  button.textContent = 'Add';
  button.addEventListener('click', async () => {
    if (pendingHostAdds.has(host)) return;
    pendingHostAdds.add(host);
    renderOutOfScope();
    try {
      await addHost(host);
    } finally {
      pendingHostAdds.delete(host);
      renderOutOfScope();
    }
  });

  row.appendChild(label);
  row.appendChild(hint);
  row.appendChild(count);
  row.appendChild(authButton);
  row.appendChild(button);

  return { row, count, button, authButton };
}

function renderOutOfScope() {
  const block = document.getElementById('outOfScopeBlock');
  const outList = document.getElementById('outOfScopeList');
  const observed = sessionState.observedOutOfScope || {};
  // Object key order is first-seen order, preserved by the service worker. New hosts append at the
  // bottom; nothing that is already on screen ever moves.
  const hosts = Object.keys(observed);

  if (!sessionState.active || hosts.length === 0) {
    block.classList.add('d-none');
    if (outOfScopeRows.size) {
      outOfScopeRows.forEach((entry) => entry.row.remove());
      outOfScopeRows.clear();
    }
    return;
  }

  block.classList.remove('d-none');

  // Drop rows for hosts that are gone (added to scope, or trimmed).
  const present = new Set(hosts);
  outOfScopeRows.forEach((entry, host) => {
    if (!present.has(host)) {
      entry.row.remove();
      outOfScopeRows.delete(host);
    }
  });

  hosts.forEach((host, index) => {
    let entry = outOfScopeRows.get(host);
    if (!entry) {
      entry = createOutOfScopeRow(host);
      outOfScopeRows.set(host, entry);
      outList.appendChild(entry.row);
    }

    const nextCount = String(observed[host]);
    if (entry.count.textContent !== nextCount) entry.count.textContent = nextCount;

    // A row that survives its own add means the add failed; the button has to come back.
    const pending = pendingHostAdds.has(host);
    if (entry.button.disabled !== pending) {
      entry.button.disabled = pending;
      entry.button.textContent = pending ? '…' : 'Add';
    }
    const authPending = pendingAuthAdds.has(host);
    if (entry.authButton && entry.authButton.disabled !== authPending) {
      entry.authButton.disabled = authPending;
      entry.authButton.textContent = authPending ? '…' : 'Auth';
    }

    // Alternating tint so a domain reads across to its own Add button on a long list.
    const shade = index % 2 === 1 ? 'rgba(220, 53, 69, 0.14)' : 'transparent';
    if (entry.row.style.backgroundColor !== shade) entry.row.style.backgroundColor = shade;
  });
}

// Before a session starts there is no worker-resolved scope, so mirror what the worker would
// compute for the currently selected target.
function buildPreviewScope() {
  const targetSelect = document.getElementById('targetSelect');
  const selected = targetSelect.options[targetSelect.selectedIndex];
  const targetUrl = selected && selected.getAttribute('data-url');
  const urlObj = normalizeTargetUrl(targetUrl);

  const hosts = [];
  if (urlObj) {
    const host = urlObj.hostname.toLowerCase();
    hosts.push(host);
    if (document.getElementById('includeSubdomains').checked) {
      const labels = host.split('.');
      if (labels.length > 2) hosts.push(labels.slice(-2).join('.'));
    }
  }
  currentExtraHosts().forEach((h) => {
    if (!hosts.includes(h)) hosts.push(h);
  });
  return hosts;
}

function renderDeepCaptureStatus() {
  const el = document.getElementById('deepCaptureStatus');
  const deep = sessionState.deepCapture;

  if (!sessionState.active || !deep || !deep.enabled) {
    el.classList.add('d-none');
    return;
  }

  el.classList.remove('d-none');
  el.textContent = '';

  const attached = document.createElement('div');
  attached.className = 'text-success';
  attached.style.fontSize = '11px';
  const count = (deep.attachedTabs || []).length;
  attached.textContent = `Attached to ${count} tab${count === 1 ? '' : 's'}`;
  el.appendChild(attached);

  // Attach failures are per tab, not fatal. The usual cause is DevTools already being open there,
  // and the user can only fix it if we say so.
  (deep.errors || []).slice(0, 3).forEach((error) => {
    const line = document.createElement('div');
    line.className = 'text-warning';
    line.style.fontSize = '10px';
    const reason = /already attached|Another debugger/i.test(error.error || '')
      ? 'DevTools is open on this tab'
      : error.error;
    line.textContent = `Tab ${error.tabId}: ${reason}`;
    el.appendChild(line);
  });
}

async function refreshSessionState() {
  const response = await sendToWorker({ action: 'getSessionState' });
  if (response && response.success && response.state) {
    sessionState = response.state;
  }
  updateUI();
}

async function refreshAuthState() {
  const response = await sendToWorker({ action: 'getAuthRecordingState' });
  if (response && response.success && response.state) {
    authState = response.state;
  }
  updateUI();
}

async function checkFrameworkConnection() {
  const indicator = document.getElementById('connectionIndicator');

  try {
    const response = await fetchWithTimeout(`${frameworkUrl}/api/health`, { method: 'GET', mode: 'cors' }, 6000);
    if (!response.ok) throw new Error('Framework not responding');

    isConnected = true;
    indicator.innerHTML = '<i class="bi bi-circle-fill text-success"></i> <span>Connected</span>';
    await loadURLTargets();
  } catch (error) {
    isConnected = false;
    availableTargets = [];
    targetsLoaded = false;
    indicator.innerHTML = '<i class="bi bi-circle-fill text-danger"></i> <span>Not Connected</span>';

    const targetSelect = document.getElementById('targetSelect');
    targetSelect.innerHTML = '<option value="">Cannot connect to framework</option>';
    updateUI();
  }
}

// Accepts targets stored with or without a scheme, which the capture path used to choke on: a
// scope target saved as "app.example.com" threw inside new URL() and silently dropped every
// request for the whole session.
function normalizeTargetUrl(raw) {
  if (!raw) return null;
  const trimmed = String(raw).trim();
  if (!trimmed) return null;
  try {
    return new URL(/^https?:\/\//i.test(trimmed) ? trimmed : 'https://' + trimmed);
  } catch (error) {
    return null;
  }
}

async function loadURLTargets() {
  const targetSelect = document.getElementById('targetSelect');

  try {
    const response = await fetchJSONWithTimeout(`${frameworkUrl}/api/scopetarget/read`, {}, 8000);
    if (!response.ok) throw new Error(`Failed to fetch targets: ${response.status}`);

    const allTargets = response.body;
    availableTargets = (allTargets || []).filter((t) => t.type === 'URL');

    if (availableTargets.length === 0) {
      targetsLoaded = false;
      targetSelect.innerHTML = '<option value="">No URL targets found - create one in the framework first</option>';
      updateUI();
      return;
    }

    const previousSelection = targetSelect.value;
    targetsLoaded = true;
    targetSelect.innerHTML =
      '<option value="">-- Select a target --</option>' +
      availableTargets
        .map((t) => {
          const targetUrl = t.scope_target || t.target || t.url || 'Unknown';
          return `<option value="${t.id}" data-url="${targetUrl}">${targetUrl}</option>`;
        })
        .join('');

    if (previousSelection) targetSelect.value = previousSelection;

    // While recording, pin the dropdown to the session's target so the popup cannot imply a
    // different target is being captured. Either session pins it, since either can be running
    // alone.
    if (sessionState.active && sessionState.scopeTargetId) {
      targetSelect.value = sessionState.scopeTargetId;
    } else if (authState.active && authState.scopeTargetId) {
      targetSelect.value = authState.scopeTargetId;
    } else if (!targetSelect.value) {
      await autoSelectTargetForCurrentTab(targetSelect);
    }

    updateUI();
  } catch (error) {
    targetsLoaded = false;
    targetSelect.innerHTML = '<option value="">Error: ' + error.message + '</option>';
    updateUI();
  }
}

async function autoSelectTargetForCurrentTab(targetSelect) {
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tabs || !tabs[0] || !tabs[0].url) return;

  const currentUrlObj = normalizeTargetUrl(tabs[0].url);
  if (!currentUrlObj) return;
  const currentHostname = currentUrlObj.hostname.replace(/^www\./, '');

  const matchingTarget = availableTargets.find((t) => {
    const targetUrlObj = normalizeTargetUrl(t.scope_target || t.target || t.url);
    if (!targetUrlObj) return false;
    return targetUrlObj.hostname.replace(/^www\./, '') === currentHostname;
  });

  if (matchingTarget) targetSelect.value = matchingTarget.id;
}

function updateUI() {
  const statusBadge = document.getElementById('captureStatus');
  const startBtn = document.getElementById('startCaptureBtn');
  const stopBtn = document.getElementById('stopCaptureBtn');
  const progressBar = document.getElementById('progressBar');
  const stats = sessionState.stats || {};

  if (sessionState.active) {
    statusBadge.textContent = 'Capturing';
    statusBadge.className = 'badge bg-success capturing';
    startBtn.classList.add('d-none');
    stopBtn.classList.remove('d-none');
    progressBar.style.width = '100%';
  } else {
    statusBadge.textContent = 'Idle';
    statusBadge.className = 'badge bg-secondary';
    startBtn.classList.remove('d-none');
    stopBtn.classList.add('d-none');
    progressBar.style.width = '0%';
  }

  document.getElementById('requestCount').textContent = stats.requestCount || 0;
  document.getElementById('endpointCount').textContent = stats.endpointCount || 0;
  document.getElementById('queuedCount').textContent = stats.queuedCount || 0;
  document.getElementById('bodyCount').textContent = stats.withResponseBody || 0;

  const failedRow = document.getElementById('failedRow');
  if (stats.failedCount) {
    failedRow.classList.remove('d-none');
    document.getElementById('failedCount').textContent = stats.failedCount;
  } else {
    failedRow.classList.add('d-none');
  }

  renderScope();
  renderDeepCaptureStatus();
  renderAuthFlow();

  if (localError) {
    showError(localError);
  } else if (sessionState.lastError) {
    showError(sessionState.lastError);
  } else {
    hideError();
  }

  // The dropdown is locked while recording so the popup cannot imply a different target is being
  // captured, and unlocked again as soon as the session ends. An auth recording locks it too: it is
  // filed against a scope target just like a crawl is.
  const targetSelect = document.getElementById('targetSelect');
  targetSelect.disabled = !targetsLoaded || sessionState.active || authState.active;
  startBtn.disabled = !isConnected || !targetsLoaded;
}

async function startCapture() {
  localError = null;

  if (!isConnected) {
    localError = 'Not connected to framework. Check connection settings.';
    updateUI();
    return;
  }

  const targetSelect = document.getElementById('targetSelect');
  const selectedOption = targetSelect.options[targetSelect.selectedIndex];
  const scopeTargetId = targetSelect.value;
  const targetUrl = selectedOption && selectedOption.getAttribute('data-url');

  if (!scopeTargetId || !targetUrl) {
    localError = 'Please select a target from the dropdown';
    updateUI();
    return;
  }

  const settings = { targetUrl, scopeTargetId, ...currentSettings() };

  const response = await sendToWorker({ action: 'startCapture', settings, frameworkUrl });

  if (response && response.success) {
    localError = null;
  } else {
    localError = (response && response.error) || 'Failed to start capture';
  }
  await refreshSessionState();
}

async function stopCapture() {
  localError = null;
  const response = await sendToWorker({ action: 'stopCapture' });
  await refreshSessionState();

  if (response && response.success) {
    const stats = response.stats || {};
    const statusDiv = document.getElementById('connectionStatus');
    const messageSpan = document.getElementById('connectionMessage');
    statusDiv.classList.remove('d-none', 'alert-danger');
    statusDiv.classList.add('alert-success');
    messageSpan.innerHTML = `<i class="bi bi-check-circle-fill me-2"></i>Capture stopped. ${stats.requestCount || 0} requests captured.`;
    setTimeout(() => statusDiv.classList.add('d-none'), 5000);
  } else {
    localError = (response && response.error) || 'Failed to stop capture';
    updateUI();
  }
}

/* ------------------------------------------------------------------ auth flow recording */

function categoryLabel(category) {
  return AUTH_CATEGORY_LABELS[category] || category || 'Login';
}

function setAuthSectionOpen(open) {
  authSectionOpen = open;
  const body = document.getElementById('authFlowBody');
  const toggle = document.getElementById('authFlowToggle');

  if (open) {
    body.classList.remove('d-none');
    toggle.classList.remove('collapsed');
  } else {
    body.classList.add('d-none');
    toggle.classList.add('collapsed');
  }
}

function renderAuthFlow() {
  const startBtn = document.getElementById('startAuthRecordingBtn');
  const stopBtn = document.getElementById('stopAuthRecordingBtn');
  const live = document.getElementById('authFlowLive');
  const nameInput = document.getElementById('authFlowName');
  const categorySelect = document.getElementById('authFlowCategory');
  const stats = authState.stats || {};

  // A recording that is already running has to be visible the moment the popup opens, or the
  // section reads as idle while traffic is being recorded. Done once, so collapsing it by hand
  // during a recording sticks.
  if (authState.active && !authSectionAutoOpened) {
    authSectionAutoOpened = true;
    setAuthSectionOpen(true);
  }

  if (authState.active) {
    startBtn.classList.add('d-none');
    stopBtn.classList.remove('d-none');
    live.classList.remove('d-none');
    nameInput.disabled = true;
    categorySelect.disabled = true;

    document.getElementById('authFlowLiveName').textContent = authState.name || 'Untitled flow';
    document.getElementById('authFlowLiveCategory').textContent = categoryLabel(authState.category);
    document.getElementById('authFlowCount').textContent = stats.requestCount || 0;

    const queuedRow = document.getElementById('authFlowQueuedRow');
    if (stats.queuedCount) {
      queuedRow.classList.remove('d-none');
      document.getElementById('authFlowQueued').textContent = stats.queuedCount;
    } else {
      queuedRow.classList.add('d-none');
    }
  } else {
    startBtn.classList.remove('d-none');
    stopBtn.classList.add('d-none');
    live.classList.add('d-none');
    nameInput.disabled = false;
    categorySelect.disabled = false;
    authSectionAutoOpened = false;
  }

  startBtn.disabled = !isConnected || !targetsLoaded;

  const errorEl = document.getElementById('authFlowError');
  const message = authError || authState.lastError;
  if (message) {
    errorEl.textContent = message;
    errorEl.classList.remove('d-none');
  } else {
    errorEl.classList.add('d-none');
  }

  const resultEl = document.getElementById('authFlowResult');
  if (authResult) {
    resultEl.textContent = authResult;
    resultEl.classList.remove('d-none');
  } else {
    resultEl.classList.add('d-none');
  }
}

async function startAuthRecording() {
  authError = null;
  authResult = null;

  if (!isConnected) {
    authError = 'Not connected to framework. Check connection settings.';
    updateUI();
    return;
  }

  const targetSelect = document.getElementById('targetSelect');
  const selectedOption = targetSelect.options[targetSelect.selectedIndex];
  const scopeTargetId = targetSelect.value;
  if (!scopeTargetId) {
    authError = 'Please select a target from the dropdown';
    updateUI();
    return;
  }

  const name = document.getElementById('authFlowName').value.trim();
  if (!name) {
    authError = 'Give the flow a name';
    updateUI();
    return;
  }

  const category = document.getElementById('authFlowCategory').value || 'login';
  // The flow's base URL is the target's origin, not the tab's: replay resolves every step against
  // it, and the tab may well be sitting on an identity provider by the time the user stops.
  const targetUrlObj = normalizeTargetUrl(selectedOption && selectedOption.getAttribute('data-url'));

  await saveAuthFlowFields();

  const response = await sendToWorker({
    action: 'startAuthRecording',
    frameworkUrl,
    recording: {
      scopeTargetId,
      name,
      category,
      baseUrl: targetUrlObj ? targetUrlObj.origin : '',
    },
  });

  if (!response || !response.success) {
    authError = (response && response.error) || 'Failed to start recording';
  }
  await refreshAuthState();
}

async function stopAuthRecording() {
  authError = null;
  const response = await sendToWorker({ action: 'stopAuthRecording' });

  if (response && response.success) {
    const count = response.requestCount || 0;
    const plural = count === 1 ? '' : 's';
    authResult = response.authFlowId
      ? `Saved as an auth flow. ${count} request${plural} recorded.`
      : `Recording saved with ${count} request${plural}. Import it from the framework to build the flow.`;
  } else {
    authError = (response && response.error) || 'Failed to stop recording';
  }
  await refreshAuthState();
}

/* ------------------------------------------------------------------ */

function openFramework() {
  chrome.tabs.create({ url: frameworkUrl || DEFAULT_FRAMEWORK_URL });
}

function toggleSettings() {
  document.getElementById('settingsPanel').classList.toggle('d-none');
}

async function saveFrameworkUrl() {
  const urlInput = document.getElementById('frameworkUrl');
  let url = urlInput.value.trim();

  if (!url) {
    localError = 'Please enter a framework URL';
    updateUI();
    return;
  }
  localError = null;
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
  url = url.replace(/\/+$/, '');

  frameworkUrl = url;
  urlInput.value = url;

  await chrome.storage.local.set({ frameworkUrl: url });
  await sendToWorker({ action: 'updateFrameworkUrl', frameworkUrl: url });

  document.getElementById('settingsPanel').classList.add('d-none');
  await checkFrameworkConnection();
}

function openHelp(e) {
  e.preventDefault();
  chrome.tabs.create({ url: 'https://github.com/R-s0n/ars0n-framework-v2#manual-crawling' });
}

function showError(message) {
  document.getElementById('errorMessage').textContent = message;
  document.getElementById('errorAlert').classList.remove('d-none');
}

function hideError() {
  document.getElementById('errorAlert').classList.add('d-none');
}

chrome.runtime.onMessage.addListener((message) => {
  if (message && message.action === 'sessionState') {
    sessionState = message.state;
    updateUI();
  }
  if (message && message.action === 'authRecordingState' && message.state) {
    authState = message.state;
    updateUI();
  }
  return false;
});
