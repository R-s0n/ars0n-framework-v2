let isCapturing = false;
let captureStats = {
  requestCount: 0,
  endpointCount: 0
};

let frameworkUrl = 'http://localhost';
let availableTargets = [];
let isConnected = false;

document.addEventListener('DOMContentLoaded', async () => {
  console.log('[POPUP] Extension popup opened');
  await loadSettings();
  await checkFrameworkConnection();
  await updateCaptureStatus();
  initializeEventListeners();
  
  setInterval(async () => {
    await updateCaptureStatus();
    if (!isConnected) {
      await checkFrameworkConnection();
    }
  }, 3000);
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
}

async function loadSettings() {
  const result = await chrome.storage.local.get([
    'includeSubdomains', 
    'captureStatic', 
    'frameworkUrl'
  ]);
  
  document.getElementById('includeSubdomains').checked = result.includeSubdomains !== false;
  document.getElementById('captureStatic').checked = result.captureStatic || false;
  
  frameworkUrl = result.frameworkUrl || 'http://localhost';
  document.getElementById('frameworkUrl').value = frameworkUrl;
}

async function saveSettings() {
  const settings = {
    includeSubdomains: document.getElementById('includeSubdomains').checked,
    captureStatic: document.getElementById('captureStatic').checked
  };
  
  await chrome.storage.local.set(settings);
  
  if (isCapturing) {
    chrome.runtime.sendMessage({ 
      action: 'updateSettings', 
      settings: settings 
    });
  }
}

async function checkFrameworkConnection() {
  const indicator = document.getElementById('connectionIndicator');
  const statusDiv = document.getElementById('connectionStatus');
  const messageSpan = document.getElementById('connectionMessage');
  const connectionText = document.getElementById('connectionText');
  
  statusDiv.classList.add('d-none');
  
  try {
    const response = await fetch(`${frameworkUrl}/api/health`, {
      method: 'GET',
      mode: 'cors'
    });
    
    if (response.ok) {
      isConnected = true;
      indicator.innerHTML = '<i class="bi bi-circle-fill text-success"></i> <span id="connectionText">Connected</span>';
      await loadURLTargets();
    } else {
      throw new Error('Framework not responding');
    }
  } catch (error) {
    isConnected = false;
    availableTargets = [];
    indicator.innerHTML = '<i class="bi bi-circle-fill text-danger"></i> <span id="connectionText">Not Connected</span>';
    
    const targetSelect = document.getElementById('targetSelect');
    targetSelect.innerHTML = '<option value="">Cannot connect to framework</option>';
    targetSelect.disabled = true;
    updateUI();
  }
}

async function loadURLTargets() {
  console.log('[POPUP] ========== LOADING URL TARGETS ==========');
  console.log('[POPUP] Framework URL:', frameworkUrl);
  
  const targetSelect = document.getElementById('targetSelect');
  
  try {
    const url = `${frameworkUrl}/api/scopetarget/read`;
    console.log('[POPUP] Fetching from:', url);
    
    const response = await fetch(url);
    console.log('[POPUP] Response status:', response.status);
    
    if (!response.ok) {
      const text = await response.text();
      console.error('[POPUP] Response error:', text);
      throw new Error(`Failed to fetch targets: ${response.status}`);
    }
    
    const allTargets = await response.json();
    console.log('[POPUP] All targets:', allTargets);
    
    availableTargets = allTargets.filter(t => t.type === 'URL');
    console.log('[POPUP] Filtered URL targets:', availableTargets);
    
    if (availableTargets.length === 0) {
      console.log('[POPUP] No URL targets found');
      targetSelect.innerHTML = '<option value="">No URL targets found - create one in the framework first</option>';
      targetSelect.disabled = true;
    } else {
      console.log('[POPUP] Populating dropdown with', availableTargets.length, 'targets');
      targetSelect.disabled = false;
      targetSelect.innerHTML = '<option value="">-- Select a target --</option>' +
        availableTargets.map(t => {
          console.log('[POPUP] Target object:', JSON.stringify(t));
          const targetUrl = t.scope_target || t.target || t.url || 'Unknown';
          console.log('[POPUP] Adding target:', t.id, targetUrl);
          return `<option value="${t.id}" data-url="${targetUrl}">${targetUrl}</option>`;
        }).join('');
      
      const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      if (tabs && tabs[0] && tabs[0].url) {
        const currentUrl = tabs[0].url;
        console.log('[POPUP] Current tab URL:', currentUrl);
        
        try {
          const currentUrlObj = new URL(currentUrl);
          const currentHostname = currentUrlObj.hostname.replace(/^www\./, '');
          const currentProtocol = currentUrlObj.protocol;
          console.log('[POPUP] Looking for match to:', currentProtocol + '//' + currentHostname, '(www ignored)');
          
          const matchingTarget = availableTargets.find(t => {
            const targetUrl = t.scope_target || t.target || t.url;
            if (!targetUrl) {
              console.log('[POPUP] Target has no URL:', t);
              return false;
            }
            
            try {
              let targetUrlToCheck = targetUrl;
              if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                targetUrlToCheck = 'https://' + targetUrl;
                console.log('[POPUP] Target missing protocol, assuming https:', targetUrlToCheck);
              }
              
              const targetUrlObj = new URL(targetUrlToCheck);
              const targetHostname = targetUrlObj.hostname.replace(/^www\./, '');
              const targetProtocol = targetUrlObj.protocol;
              
              const matches = (targetProtocol === currentProtocol) && (targetHostname === currentHostname);
              console.log('[POPUP] Comparing', targetProtocol + '//' + targetHostname, '===', currentProtocol + '//' + currentHostname, ':', matches);
              return matches;
            } catch (e) {
              console.log('[POPUP] Error parsing target URL:', targetUrl, e.message);
              return false;
            }
          });
          
          if (matchingTarget) {
            console.log('[POPUP] ✓ Auto-selecting matching target:', matchingTarget.id);
            targetSelect.value = matchingTarget.id;
          } else {
            console.log('[POPUP] No matching target found for current tab');
          }
        } catch (urlError) {
          console.log('[POPUP] Could not parse current tab URL:', urlError.message);
        }
      } else {
        console.log('[POPUP] No active tab found or tab has no URL');
      }
    }
    
    console.log('[POPUP] ✓ Targets loaded successfully');
    updateUI();
  } catch (error) {
    console.error('[POPUP] ✗ Error loading targets:', error);
    targetSelect.innerHTML = '<option value="">Error: ' + error.message + '</option>';
    targetSelect.disabled = true;
    updateUI();
  }
}

async function updateCaptureStatus() {
  const result = await chrome.storage.local.get(['isCapturing', 'captureStats', 'captureTabId']);
  
  isCapturing = result.isCapturing || false;
  captureStats = result.captureStats || { requestCount: 0, endpointCount: 0 };
  
  console.log('[POPUP] ========== CHECKING CAPTURE STATUS ==========');
  console.log('[POPUP] Storage state:', {
    isCapturing: result.isCapturing,
    captureStats: result.captureStats,
    captureTabId: result.captureTabId
  });
  console.log('[POPUP] Local state updated - isCapturing:', isCapturing, 'stats:', captureStats);
  
  if (result.captureTabId && result.isCapturing) {
    try {
      const tab = await chrome.tabs.get(result.captureTabId);
      console.log('[POPUP] Capture tab exists:', tab.id, tab.url);
    } catch (error) {
      console.log('[POPUP] ⚠ Capture tab no longer exists but session is active - NOT cleaning storage (may be navigating)');
    }
  }
  
  updateUI();
}

function updateUI() {
  const statusBadge = document.getElementById('captureStatus');
  const startBtn = document.getElementById('startCaptureBtn');
  const stopBtn = document.getElementById('stopCaptureBtn');
  const progressBar = document.getElementById('progressBar');
  
  console.log('[POPUP] updateUI called, isCapturing:', isCapturing);
  
  if (isCapturing) {
    statusBadge.textContent = 'Capturing';
    statusBadge.className = 'badge bg-success capturing';
    startBtn.classList.add('d-none');
    stopBtn.classList.remove('d-none');
    progressBar.style.width = '100%';
    console.log('[POPUP] UI updated to show Stop button');
  } else {
    statusBadge.textContent = 'Idle';
    statusBadge.className = 'badge bg-secondary';
    startBtn.classList.remove('d-none');
    stopBtn.classList.add('d-none');
    progressBar.style.width = '0%';
    console.log('[POPUP] UI updated to show Start button');
  }
  
  document.getElementById('requestCount').textContent = captureStats.requestCount || 0;
  document.getElementById('endpointCount').textContent = captureStats.endpointCount || 0;
  
  const targetSelect = document.getElementById('targetSelect');
  if (!isConnected || targetSelect.disabled || availableTargets.length === 0) {
    startBtn.disabled = true;
  } else {
    startBtn.disabled = false;
  }
}

async function startCapture() {
  console.log('[POPUP] ========== START CAPTURE CLICKED ==========');
  
  if (!isConnected) {
    showError('Not connected to framework. Check connection settings.');
    return;
  }
  
  const targetSelect = document.getElementById('targetSelect');
  const selectedOption = targetSelect.options[targetSelect.selectedIndex];
  const scopeTargetId = targetSelect.value;
  const targetUrl = selectedOption.getAttribute('data-url');
  
  console.log('[POPUP] Selected target:', scopeTargetId, targetUrl);
  console.log('[POPUP] Framework URL:', frameworkUrl);
  
  if (!scopeTargetId || !targetUrl) {
    showError('Please select a target from the dropdown');
    return;
  }
  
  try {
    const settings = {
      targetUrl: targetUrl,
      scopeTargetId: scopeTargetId,
      includeSubdomains: document.getElementById('includeSubdomains').checked,
      captureStatic: document.getElementById('captureStatic').checked
    };
    
    console.log('[POPUP] Settings:', settings);
    console.log('[POPUP] Sending startCapture message to background...');
    
    chrome.runtime.sendMessage({ 
      action: 'startCapture',
      settings: settings,
      frameworkUrl: frameworkUrl
    }, (response) => {
      console.log('[POPUP] ========== START CAPTURE RESPONSE ==========');
      console.log('[POPUP] Response:', response);
      
      if (chrome.runtime.lastError) {
        console.error('[POPUP] Runtime error:', chrome.runtime.lastError);
        showError('Extension error: ' + chrome.runtime.lastError.message);
        return;
      }
      
      if (response && response.success) {
        console.log('[POPUP] ✓ Capture started successfully');
        isCapturing = true;
        captureStats = { requestCount: 0, endpointCount: 0 };
        chrome.storage.local.set({ 
          isCapturing: true, 
          captureStats: captureStats 
        }, () => {
          console.log('[POPUP] ✓ Storage updated');
          updateUI();
        });
        hideError();
      } else {
        console.error('[POPUP] ✗ Failed to start capture:', response?.error);
        showError(response?.error || 'Failed to start capture');
      }
    });
  } catch (error) {
    console.error('[POPUP] ✗ Exception during startCapture:', error);
    showError('Error starting capture: ' + error.message);
  }
}

async function stopCapture() {
  console.log('[POPUP] ========== STOP CAPTURE CLICKED ==========');
  
  try {
    chrome.runtime.sendMessage({ action: 'stopCapture' }, (response) => {
      console.log('[POPUP] ========== STOP CAPTURE RESPONSE ==========');
      console.log('[POPUP] Response:', response);
      
      if (chrome.runtime.lastError) {
        console.error('[POPUP] Runtime error:', chrome.runtime.lastError);
        return;
      }
      
      if (response && response.success) {
        console.log('[POPUP] ✓ Capture stopped successfully');
        isCapturing = false;
        chrome.storage.local.set({ 
          isCapturing: false,
          captureStats: captureStats,
          captureTabId: null
        });
        updateUI();
        
        const statusDiv = document.getElementById('connectionStatus');
        const messageSpan = document.getElementById('connectionMessage');
        statusDiv.classList.remove('d-none', 'alert-danger');
        statusDiv.classList.add('alert-success');
        messageSpan.innerHTML = `<i class="bi bi-check-circle-fill me-2"></i>Capture stopped. ${captureStats.requestCount} requests captured.`;
        
        setTimeout(() => {
          statusDiv.classList.add('d-none');
        }, 5000);
      } else {
        showError(response?.error || 'Failed to stop capture');
      }
    });
  } catch (error) {
    showError('Error stopping capture: ' + error.message);
  }
}

function openFramework() {
  const baseUrl = frameworkUrl.replace(':8000', '').replace('/api', '');
  chrome.tabs.create({ url: baseUrl || 'http://localhost' });
}

function toggleSettings() {
  const settingsPanel = document.getElementById('settingsPanel');
  settingsPanel.classList.toggle('d-none');
}

async function saveFrameworkUrl() {
  const urlInput = document.getElementById('frameworkUrl');
  let url = urlInput.value.trim();
  
  if (!url) {
    showError('Please enter a framework URL');
    return;
  }
  
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }
  
  url = url.replace(/\/+$/, '');
  
  frameworkUrl = url;
  
  await chrome.storage.local.set({ frameworkUrl: url });
  
  document.getElementById('frameworkUrl').value = url;
  
  document.getElementById('settingsPanel').classList.add('d-none');
  
  await checkFrameworkConnection();
  
  chrome.runtime.sendMessage({ 
    action: 'updateFrameworkUrl', 
    frameworkUrl: url 
  });
}

function openHelp(e) {
  e.preventDefault();
  chrome.tabs.create({ url: 'https://github.com/R-s0n/ars0n-framework-v2#manual-crawling' });
}

function isValidUrl(string) {
  try {
    const url = new URL(string);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

function showError(message) {
  const errorAlert = document.getElementById('errorAlert');
  const errorMessage = document.getElementById('errorMessage');
  errorMessage.textContent = message;
  errorAlert.classList.remove('d-none');
}

function hideError() {
  document.getElementById('errorAlert').classList.add('d-none');
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'updateStats') {
    console.log('[POPUP] Received stats update:', message.stats);
    captureStats = message.stats;
    chrome.storage.local.set({ captureStats: captureStats });
    updateUI();
  }
});
