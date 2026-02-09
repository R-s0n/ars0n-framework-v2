let captureSession = {
  active: false,
  tabId: null,
  sessionId: null,
  scopeTargetId: null,
  settings: null,
  stats: {
    requestCount: 0,
    endpointCount: 0
  },
  capturedEndpoints: new Set(),
  pendingRequests: new Map()
};

let frameworkApiUrl = 'http://localhost/api';

async function loadFrameworkUrl() {
  const result = await chrome.storage.local.get(['frameworkUrl']);
  if (result.frameworkUrl) {
    frameworkApiUrl = result.frameworkUrl + '/api';
  }
}

loadFrameworkUrl();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'startCapture') {
    if (message.frameworkUrl) {
      frameworkApiUrl = message.frameworkUrl + '/api';
    }
    startCaptureSession(message.settings)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
  
  if (message.action === 'stopCapture') {
    stopCaptureSession()
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
  
  if (message.action === 'updateSettings') {
    captureSession.settings = message.settings;
    sendResponse({ success: true });
    return true;
  }
  
  if (message.action === 'updateFrameworkUrl') {
    frameworkApiUrl = message.frameworkUrl + '/api';
    chrome.storage.local.set({ frameworkUrl: message.frameworkUrl });
    sendResponse({ success: true });
    return true;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!captureSession.active || tabId !== captureSession.tabId) {
    return;
  }
  
  if (changeInfo.status === 'complete') {
    console.log('[MANUAL-CRAWL] Tab finished loading, re-injecting indicator');
    
    setTimeout(() => {
      chrome.tabs.sendMessage(tabId, { 
        action: 'showRecordingIndicator' 
      }).catch(err => {
        console.log('[MANUAL-CRAWL] Could not show indicator on page load');
      });
      
      chrome.tabs.sendMessage(tabId, {
        action: 'updateStats',
        stats: captureSession.stats
      }).catch(() => {});
    }, 500);
  }
});

async function startCaptureSession(settings) {
  try {
    console.log('[MANUAL-CRAWL] ========== STARTING CAPTURE SESSION ==========');
    console.log('[MANUAL-CRAWL] Settings:', settings);
    
    captureSession.active = true;
    captureSession.settings = settings;
    captureSession.stats = { requestCount: 0, endpointCount: 0 };
    captureSession.capturedEndpoints = new Set();
    captureSession.pendingRequests = new Map();
    
    console.log('[MANUAL-CRAWL] Getting current active tab...');
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      throw new Error('No active tab found');
    }
    
    captureSession.tabId = tab.id;
    console.log('[MANUAL-CRAWL] ✓ Using current tab:', tab.id, tab.url);
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    console.log('[MANUAL-CRAWL] Attaching debugger to tab', tab.id);
    await chrome.debugger.attach({ tabId: tab.id }, "1.3");
    console.log('[MANUAL-CRAWL] ✓ Debugger attached successfully');
    
    console.log('[MANUAL-CRAWL] Enabling Network domain...');
    await chrome.debugger.sendCommand(
      { tabId: tab.id },
      "Network.enable"
    );
    console.log('[MANUAL-CRAWL] ✓ Network domain enabled');
    
    chrome.debugger.onEvent.addListener(handleDebuggerEvent);
    console.log('[MANUAL-CRAWL] ✓ Event listener registered');
    
    chrome.debugger.onDetach.addListener(handleDebuggerDetach);
    console.log('[MANUAL-CRAWL] ✓ Detach listener registered');
    
    console.log('[MANUAL-CRAWL] Notifying framework at:', frameworkApiUrl);
    const notifyResult = await notifyFramework('start', { 
      targetUrl: settings.targetUrl,
      scopeTargetId: settings.scopeTargetId
    });
    console.log('[MANUAL-CRAWL] ✓ Framework notified, result:', notifyResult);
    
    if (!notifyResult.success) {
      throw new Error('Failed to start session on framework: ' + notifyResult.error);
    }
    
    captureSession.sessionId = notifyResult.data.sessionId;
    captureSession.scopeTargetId = notifyResult.data.scopeTargetId || settings.scopeTargetId;
    console.log('[MANUAL-CRAWL] ✓ Session ID:', captureSession.sessionId);
    console.log('[MANUAL-CRAWL] ✓ Scope Target ID:', captureSession.scopeTargetId);
    
    await chrome.storage.local.set({ 
      isCapturing: true,
      captureStats: captureSession.stats,
      captureTabId: tab.id,
      captureSessionId: captureSession.sessionId
    });
    console.log('[MANUAL-CRAWL] ✓ Storage state updated (isCapturing: true, tabId:', tab.id, ')');
    
    chrome.action.setBadgeText({ text: 'ON' });
    chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
    console.log('[MANUAL-CRAWL] ✓ Badge updated');
    
    setTimeout(() => {
      console.log('[MANUAL-CRAWL] Attempting to show recording indicator...');
      chrome.tabs.sendMessage(tab.id, { 
        action: 'showRecordingIndicator' 
      }).then(() => {
        console.log('[MANUAL-CRAWL] ✓ Recording indicator shown');
      }).catch(err => {
        console.log('[MANUAL-CRAWL] Could not show indicator yet:', err.message);
      });
    }, 1000);
    
    console.log('[MANUAL-CRAWL] ========== CAPTURE SESSION STARTED ==========');
    console.log('[MANUAL-CRAWL] Session state:', {
      active: captureSession.active,
      tabId: captureSession.tabId,
      targetUrl: settings.targetUrl
    });
    
    return { success: true };
  } catch (error) {
    console.error('[MANUAL-CRAWL] ========== ERROR STARTING SESSION ==========');
    console.error('[MANUAL-CRAWL] Error:', error);
    
    captureSession.active = false;
    captureSession.tabId = null;
    captureSession.sessionId = null;
    captureSession.scopeTargetId = null;
    captureSession.settings = null;
    
    await chrome.storage.local.set({ 
      isCapturing: false,
      captureStats: { requestCount: 0, endpointCount: 0 }
    });
    console.log('[MANUAL-CRAWL] ✓ Storage cleaned up after error');
    
    return { success: false, error: error.message };
  }
}

async function stopCaptureSession() {
  try {
    console.log('[MANUAL-CRAWL] Stopping capture session...');
    
    if (captureSession.tabId) {
      try {
        console.log('[MANUAL-CRAWL] Detaching debugger from tab', captureSession.tabId);
        await chrome.debugger.detach({ tabId: captureSession.tabId });
      } catch (error) {
        console.log('[MANUAL-CRAWL] Error detaching debugger:', error.message);
      }
    }
    
    chrome.debugger.onEvent.removeListener(handleDebuggerEvent);
    chrome.debugger.onDetach.removeListener(handleDebuggerDetach);
    
    console.log('[MANUAL-CRAWL] Notifying framework of stop...');
    await notifyFramework('stop', { 
      stats: captureSession.stats 
    });
    
    const finalStats = { ...captureSession.stats };
    console.log('[MANUAL-CRAWL] Final stats:', finalStats);
    
    captureSession.active = false;
    captureSession.tabId = null;
    captureSession.sessionId = null;
    captureSession.scopeTargetId = null;
    captureSession.settings = null;
    captureSession.capturedEndpoints = new Set();
    captureSession.pendingRequests = new Map();
    
    await chrome.storage.local.set({ 
      isCapturing: false,
      captureStats: finalStats,
      captureTabId: null,
      captureSessionId: null
    });
    console.log('[MANUAL-CRAWL] ✓ Storage updated, capture stopped');
    
    if (captureSession.tabId) {
      chrome.tabs.sendMessage(captureSession.tabId, {
        action: 'hideRecordingIndicator'
      }).catch(err => {
        console.log('[MANUAL-CRAWL] Could not hide indicator (tab may be closed)');
      });
    }
    
    chrome.action.setBadgeText({ text: '' });
    
    return { success: true, stats: finalStats };
  } catch (error) {
    console.error('[MANUAL-CRAWL] Error stopping session:', error);
    return { success: false, error: error.message };
  }
}

function handleDebuggerEvent(source, method, params) {
  if (!captureSession.active) {
    console.log('[MANUAL-CRAWL] Event received but session not active:', method);
    return;
  }
  
  console.log('[MANUAL-CRAWL] Debugger event:', method);
  
  if (method === 'Network.requestWillBeSent') {
    handleRequestWillBeSent(params);
  } else if (method === 'Network.responseReceived') {
    handleResponseReceived(params);
  } else if (method === 'Network.loadingFinished') {
    handleLoadingFinished(params);
  } else if (method === 'Network.loadingFailed') {
    handleLoadingFailed(params);
  }
}

async function handleDebuggerDetach(source, reason) {
  console.log('[MANUAL-CRAWL] ========== DEBUGGER DETACHED ==========');
  console.log('[MANUAL-CRAWL] Tab:', source.tabId, 'Reason:', reason);
  console.log('[MANUAL-CRAWL] Session active:', captureSession.active, 'Session tab:', captureSession.tabId);
  
  if (!captureSession.active) {
    console.log('[MANUAL-CRAWL] Session already inactive, ignoring detach');
    return;
  }
  
  if (source.tabId !== captureSession.tabId) {
    console.log('[MANUAL-CRAWL] Detach from different tab, ignoring');
    return;
  }
  
  if (reason === 'target_closed') {
    console.log('[MANUAL-CRAWL] Tab closed, stopping session');
    await stopCaptureSession();
    return;
  }
  
  if (reason === 'canceled_by_user') {
    console.log('[MANUAL-CRAWL] User canceled debugging (DevTools closed or manual), re-attaching...');
  } else {
    console.log('[MANUAL-CRAWL] Unexpected detach (reason: ' + reason + '), re-attaching...');
  }
  
  try {
    await new Promise(resolve => setTimeout(resolve, 500));
    
    const tab = await chrome.tabs.get(source.tabId);
    if (!tab) {
      console.log('[MANUAL-CRAWL] Tab no longer exists, stopping session');
      await stopCaptureSession();
      return;
    }
    
    console.log('[MANUAL-CRAWL] Re-attaching debugger to tab', source.tabId);
    await chrome.debugger.attach({ tabId: source.tabId }, "1.3");
    await chrome.debugger.sendCommand({ tabId: source.tabId }, "Network.enable");
    console.log('[MANUAL-CRAWL] ✓ Successfully re-attached debugger');
    
    setTimeout(() => {
      chrome.tabs.sendMessage(source.tabId, { 
        action: 'showRecordingIndicator' 
      }).catch(err => {
        console.log('[MANUAL-CRAWL] Could not show indicator after re-attach:', err.message);
      });
      
      chrome.tabs.sendMessage(source.tabId, {
        action: 'updateStats',
        stats: captureSession.stats
      }).catch(() => {});
    }, 500);
  } catch (error) {
    console.error('[MANUAL-CRAWL] ✗ Failed to re-attach debugger:', error);
    console.log('[MANUAL-CRAWL] Will try again on next navigation or manual restart');
  }
}

function handleRequestWillBeSent(params) {
  const request = params.request;
  const requestId = params.requestId;
  
  console.log('[MANUAL-CRAWL] Request detected:', request.method, request.url);
  
  if (!shouldCaptureRequest(request.url)) {
    return;
  }
  
  console.log('[MANUAL-CRAWL] ✓ Adding to pending requests:', request.method, request.url);
  
  captureSession.pendingRequests.set(requestId, {
    url: request.url,
    method: request.method,
    headers: request.headers,
    postData: request.postData,
    timestamp: params.timestamp,
    requestId: requestId
  });
  
  console.log('[MANUAL-CRAWL] Pending requests count:', captureSession.pendingRequests.size);
}

function handleResponseReceived(params) {
  const requestId = params.requestId;
  const response = params.response;
  
  if (!captureSession.pendingRequests.has(requestId)) {
    console.log('[MANUAL-CRAWL] Response for unknown request:', requestId);
    return;
  }
  
  console.log('[MANUAL-CRAWL] Response received:', response.status, response.url);
  
  const request = captureSession.pendingRequests.get(requestId);
  request.statusCode = response.status;
  request.responseHeaders = response.headers;
  request.mimeType = response.mimeType;
}

async function handleLoadingFinished(params) {
  const requestId = params.requestId;
  
  if (!captureSession.pendingRequests.has(requestId)) {
    console.log('[MANUAL-CRAWL] Loading finished for unknown request:', requestId);
    return;
  }
  
  console.log('[MANUAL-CRAWL] Loading finished for request:', requestId);
  
  const request = captureSession.pendingRequests.get(requestId);
  captureSession.pendingRequests.delete(requestId);
  
  console.log('[MANUAL-CRAWL] Processing request:', request.method, request.url);
  await processAndSendRequest(request);
}

function handleLoadingFailed(params) {
  const requestId = params.requestId;
  captureSession.pendingRequests.delete(requestId);
}

function shouldCaptureRequest(url) {
  if (!captureSession.settings) {
    console.log('[MANUAL-CRAWL] No settings, skipping:', url);
    return false;
  }
  
  try {
    const requestUrl = new URL(url);
    const targetUrl = new URL(captureSession.settings.targetUrl);
    
    console.log('[MANUAL-CRAWL] Checking URL:', requestUrl.hostname, 'vs target:', targetUrl.hostname);
    
    if (captureSession.settings.includeSubdomains) {
      if (!requestUrl.hostname.endsWith(targetUrl.hostname) && !requestUrl.hostname.includes(targetUrl.hostname.replace('www.', ''))) {
        console.log('[MANUAL-CRAWL] Hostname mismatch (with subdomains)');
        return false;
      }
    } else {
      if (requestUrl.hostname !== targetUrl.hostname) {
        console.log('[MANUAL-CRAWL] Hostname mismatch (exact)');
        return false;
      }
    }
    
    if (!captureSession.settings.captureStatic) {
      const staticExtensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot'];
      const pathname = requestUrl.pathname.toLowerCase();
      if (staticExtensions.some(ext => pathname.endsWith(ext))) {
        console.log('[MANUAL-CRAWL] Static file, skipping:', pathname);
        return false;
      }
    }
    
    console.log('[MANUAL-CRAWL] ✓ Should capture:', url);
    return true;
  } catch (error) {
    console.error('[MANUAL-CRAWL] Error in shouldCaptureRequest:', error);
    return false;
  }
}

async function processAndSendRequest(request) {
  try {
    const endpoint = extractEndpoint(request.url);
    const endpointKey = `${request.method}:${endpoint}`;
    
    const isNewEndpoint = !captureSession.capturedEndpoints.has(endpointKey);
    if (isNewEndpoint) {
      captureSession.capturedEndpoints.add(endpointKey);
      captureSession.stats.endpointCount++;
      console.log('[MANUAL-CRAWL] New endpoint discovered:', endpointKey);
    }
    
    captureSession.stats.requestCount++;
    
    if (!captureSession.sessionId) {
      console.error('[MANUAL-CRAWL] No session ID, cannot send capture data');
      return;
    }
    
    const captureData = {
      url: request.url,
      endpoint: endpoint,
      method: request.method,
      statusCode: request.statusCode || 0,
      headers: request.headers || {},
      responseHeaders: request.responseHeaders || {},
      timestamp: new Date(request.timestamp * 1000).toISOString(),
      mimeType: request.mimeType || 'unknown'
    };
    
    if (request.postData) {
      captureData.postData = request.postData;
    }
    
    console.log('[MANUAL-CRAWL] Sending to framework:', captureData);
    await sendToFramework(captureData);
    
    await chrome.storage.local.set({ 
      captureStats: captureSession.stats,
      isCapturing: true,
      captureTabId: captureSession.tabId
    });
    console.log('[MANUAL-CRAWL] ✓ Storage updated with stats:', captureSession.stats);
    
    chrome.runtime.sendMessage({
      action: 'updateStats',
      stats: captureSession.stats
    }).catch(err => {
      console.log('[MANUAL-CRAWL] Could not send message to popup (probably closed):', err.message);
    });
    
    if (captureSession.tabId) {
      chrome.tabs.sendMessage(captureSession.tabId, {
        action: 'updateStats',
        stats: captureSession.stats
      }).catch(err => {
        console.log('[MANUAL-CRAWL] Could not update page indicator:', err.message);
      });
    }
    
    console.log('[MANUAL-CRAWL] Stats updated:', captureSession.stats);
    
  } catch (error) {
    console.error('[MANUAL-CRAWL] Error processing request:', error);
  }
}

function extractEndpoint(url) {
  try {
    const urlObj = new URL(url);
    let endpoint = urlObj.pathname;
    
    endpoint = endpoint.replace(/\/\d+/g, '/{id}');
    endpoint = endpoint.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/{uuid}');
    endpoint = endpoint.replace(/\/[0-9a-f]{24}/gi, '/{objectid}');
    
    if (urlObj.search) {
      const params = Array.from(urlObj.searchParams.keys());
      if (params.length > 0) {
        endpoint += '?' + params.map(p => `${p}={value}`).join('&');
      }
    }
    
    return endpoint;
  } catch (error) {
    return url;
  }
}

async function sendToFramework(data) {
  try {
    console.log('[MANUAL-CRAWL] Sending to:', `${frameworkApiUrl}/manual-crawl/capture`);
    const response = await fetch(`${frameworkApiUrl}/manual-crawl/capture`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data)
    });
    
    if (!response.ok) {
      console.error('[MANUAL-CRAWL] Failed to send data to framework:', response.status, response.statusText);
      const text = await response.text();
      console.error('[MANUAL-CRAWL] Response:', text);
    } else {
      console.log('[MANUAL-CRAWL] Successfully sent to framework');
    }
  } catch (error) {
    console.error('[MANUAL-CRAWL] Error sending to framework:', error);
  }
}

async function notifyFramework(action, data) {
  try {
    const url = `${frameworkApiUrl}/manual-crawl/${action}`;
    console.log('[MANUAL-CRAWL] Notifying framework:', action);
    console.log('[MANUAL-CRAWL] URL:', url);
    console.log('[MANUAL-CRAWL] Data:', data);
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data)
    });
    
    console.log('[MANUAL-CRAWL] Framework response status:', response.status);
    
    if (!response.ok) {
      const text = await response.text();
      console.error(`[MANUAL-CRAWL] Failed to notify framework (${action}):`, response.status, text);
      return { success: false, error: `${response.status}: ${text}` };
    }
    
    const result = await response.json();
    console.log('[MANUAL-CRAWL] Framework response:', result);
    return { success: true, data: result };
  } catch (error) {
    console.error(`[MANUAL-CRAWL] Error notifying framework (${action}):`, error);
    return { success: false, error: error.message };
  }
}

chrome.tabs.onRemoved.addListener((tabId) => {
  if (captureSession.active && captureSession.tabId === tabId) {
    stopCaptureSession();
  }
});
