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

let sessionState = {
  active: false,
  scopeHosts: [],
  extraHosts: [],
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
let extraHosts = [];
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
  await refreshSessionState();
  await refreshAuthState();
  await checkFrameworkConnection();

  setInterval(async () => {
    await refreshSessionState();
    await refreshAuthState();
    if (!isConnected) await checkFrameworkConnection();
  }, POLL_INTERVAL_MS);
});

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
  document.getElementById('deepCapture').addEventListener('change', toggleDeepCapture);
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

async function loadSettings() {
  const result = await chrome.storage.local.get([
    'includeSubdomains',
    'captureStatic',
    'captureResponseBodies',
    'deepCapture',
    'extraHosts',
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
  document.getElementById('deepCapture').checked = Boolean(result.deepCapture);

  extraHosts = Array.isArray(result.extraHosts) ? result.extraHosts : [];
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
    deepCapture: document.getElementById('deepCapture').checked,
    extraHosts,
  };
}

async function saveSettings() {
  const settings = currentSettings();
  await chrome.storage.local.set({
    includeSubdomains: settings.includeSubdomains,
    captureStatic: settings.captureStatic,
    captureResponseBodies: settings.captureResponseBodies,
  });

  if (sessionState.active) {
    await sendToWorker({ action: 'updateSettings', settings });
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

async function addHost(host) {
  const value = String(host || '').trim();
  if (!value) return;

  if (sessionState.active) {
    const response = await sendToWorker({ action: 'addScopeHost', host: value });
    if (response && response.success) {
      localError = null;
      const stored = await chrome.storage.local.get(['extraHosts']);
      extraHosts = stored.extraHosts || [];
    } else {
      localError = (response && response.error) || 'Could not add host';
    }
    await refreshSessionState();
    return;
  }

  // Not recording: just remember it for the next session.
  const normalized = value.replace(/^https?:\/\//i, '').replace(/^\*\./, '').split('/')[0].split(':')[0].toLowerCase();
  if (!normalized.includes('.')) {
    localError = 'Not a usable hostname';
    updateUI();
    return;
  }
  if (!extraHosts.includes(normalized)) {
    extraHosts = [...extraHosts, normalized];
    await chrome.storage.local.set({ extraHosts });
  }
  localError = null;
  updateUI();
}

async function removeHost(host) {
  if (sessionState.active) {
    await sendToWorker({ action: 'removeScopeHost', host });
    const stored = await chrome.storage.local.get(['extraHosts']);
    extraHosts = stored.extraHosts || [];
    await refreshSessionState();
    return;
  }
  extraHosts = extraHosts.filter((h) => h !== host);
  await chrome.storage.local.set({ extraHosts });
  updateUI();
}

function sendToWorker(message) {
  return chrome.runtime.sendMessage(message).catch((error) => ({ success: false, error: error.message }));
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
let lastScopeSignature = null;

function renderScope() {
  const hosts = sessionState.active
    ? sessionState.scopeHosts || []
    : buildPreviewScope();
  const sessionExtras = sessionState.active ? sessionState.extraHosts || [] : extraHosts;

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
}

function createOutOfScopeRow(host) {
  const row = document.createElement('div');
  row.className = 'd-flex align-items-center gap-2 px-2 py-1 rounded';

  const label = document.createElement('span');
  label.className = 'text-truncate flex-grow-1';
  label.style.fontSize = '11px';
  label.title = host;
  label.textContent = host;

  // The count lives in its own fixed-width cell. Inline in the label, it pushed the Add button
  // sideways every time it grew a digit.
  const count = document.createElement('span');
  count.className = 'text-muted text-end flex-shrink-0';
  count.style.fontSize = '10px';
  count.style.width = '38px';

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
  row.appendChild(count);
  row.appendChild(button);

  return { row, count, button };
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
  extraHosts.forEach((h) => {
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
    const response = await fetch(`${frameworkUrl}/api/health`, { method: 'GET', mode: 'cors' });
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
    const response = await fetch(`${frameworkUrl}/api/scopetarget/read`);
    if (!response.ok) throw new Error(`Failed to fetch targets: ${response.status}`);

    const allTargets = await response.json();
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
