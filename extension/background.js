console.log('[MANUAL-CRAWL] ========== EXTENSION LOADED - VERSION 3.0 WITH WEBREQUEST API ==========');

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
  requestData: new Map()
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

function isDebuggableUrl(url) {
  if (!url) return false;
  
  const protectedPrefixes = [
    'chrome://',
    'chrome-extension://',
    'edge://',
    'about:',
    'view-source:',
    'chrome-search://',
    'devtools://'
  ];
  
  if (protectedPrefixes.some(prefix => url.startsWith(prefix))) {
    return false;
  }
  
  if (url.includes('chrome.google.com/webstore')) {
    return false;
  }
  
  if (url.includes('microsoftedge.microsoft.com/addons')) {
    return false;
  }
  
  return true;
}

async function startCaptureSession(settings) {
  try {
    console.log('[MANUAL-CRAWL] ========== STARTING CAPTURE SESSION ==========');
    console.log('[MANUAL-CRAWL] Settings:', settings);
    
    captureSession.active = true;
    captureSession.settings = settings;
    captureSession.stats = { requestCount: 0, endpointCount: 0 };
    captureSession.capturedEndpoints = new Set();
    captureSession.requestData = new Map();
    
    console.log('[MANUAL-CRAWL] Getting current active tab...');
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    
    let tab = tabs[0];
    console.log('[MANUAL-CRAWL] Initial tab found:', tab ? `ID: ${tab.id}, URL: ${tab.url}` : 'none');
    
    if (!tab || !isDebuggableUrl(tab.url)) {
      console.log('[MANUAL-CRAWL] First tab not debuggable, looking for alternative...');
      const allTabs = await chrome.tabs.query({ windowType: 'normal' });
      console.log('[MANUAL-CRAWL] All tabs:', allTabs.map(t => `ID: ${t.id}, URL: ${t.url}`));
      tab = allTabs.find(t => isDebuggableUrl(t.url));
      
      if (!tab) {
        throw new Error('No debuggable tab found. Please open a regular website (http:// or https://) in a tab before starting capture. Extension pages, Chrome internal pages, and browser stores cannot be debugged.');
      }
      
      console.log('[MANUAL-CRAWL] Found alternative debuggable tab:', tab.url);
    }
    
    captureSession.tabId = tab.id;
    console.log('[MANUAL-CRAWL] ✓ Using tab:', tab.id, tab.url);
    
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
    captureSession.requestData = new Map();
    
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

function parseRequestBody(requestBody) {
  if (!requestBody) {
    return null;
  }
  
  if (requestBody.formData) {
    const formData = {};
    for (const [key, values] of Object.entries(requestBody.formData)) {
      formData[key] = values.length === 1 ? values[0] : values;
    }
    return JSON.stringify(formData);
  }
  
  if (requestBody.raw && requestBody.raw.length > 0) {
    try {
      const bytes = requestBody.raw[0].bytes;
      if (bytes) {
        const decoder = new TextDecoder('utf-8');
        const uint8Array = new Uint8Array(bytes);
        return decoder.decode(uint8Array);
      }
    } catch (error) {
      console.error('[MANUAL-CRAWL] Error parsing raw request body:', error);
    }
  }
  
  return null;
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!captureSession.active || details.tabId !== captureSession.tabId) {
      return;
    }
    
    if (!shouldCaptureRequest(details.url)) {
      return;
    }
    
    console.log('[MANUAL-CRAWL] Request detected:', details.method, details.url);
    
    const requestBody = parseRequestBody(details.requestBody);
    if (requestBody) {
      console.log('[MANUAL-CRAWL] Request body captured (for ' + details.method + '):', requestBody.substring(0, 200));
    }
    
    captureSession.requestData.set(details.requestId, {
      url: details.url,
      method: details.method,
      timestamp: Date.now(),
      requestId: details.requestId,
      postData: requestBody
    });
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    if (!captureSession.active || details.tabId !== captureSession.tabId) {
      return;
    }
    
    const request = captureSession.requestData.get(details.requestId);
    if (request) {
      request.headers = {};
      details.requestHeaders?.forEach(header => {
        request.headers[header.name] = header.value;
      });
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!captureSession.active || details.tabId !== captureSession.tabId) {
      return;
    }
    
    const request = captureSession.requestData.get(details.requestId);
    if (request) {
      request.statusCode = details.statusCode;
      request.responseHeaders = {};
      details.responseHeaders?.forEach(header => {
        request.responseHeaders[header.name] = header.value;
      });
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (!captureSession.active || details.tabId !== captureSession.tabId) {
      return;
    }
    
    const request = captureSession.requestData.get(details.requestId);
    if (request) {
      console.log('[MANUAL-CRAWL] Request completed:', request.method, request.url);
      processAndSendRequest(request);
      captureSession.requestData.delete(details.requestId);
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    if (!captureSession.active || details.tabId !== captureSession.tabId) {
      return;
    }
    
    captureSession.requestData.delete(details.requestId);
  },
  { urls: ["<all_urls>"] }
);

function shouldCaptureRequest(url) {
  if (!captureSession.settings) {
    return false;
  }
  
  if (!isDebuggableUrl(url)) {
    return false;
  }
  
  try {
    const requestUrl = new URL(url);
    const targetUrl = new URL(captureSession.settings.targetUrl);
    
    if (captureSession.settings.includeSubdomains) {
      if (!requestUrl.hostname.endsWith(targetUrl.hostname) && !requestUrl.hostname.includes(targetUrl.hostname.replace('www.', ''))) {
        return false;
      }
    } else {
      if (requestUrl.hostname !== targetUrl.hostname) {
        return false;
      }
    }
    
    if (!captureSession.settings.captureStatic) {
      const staticExtensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot'];
      const pathname = requestUrl.pathname.toLowerCase();
      if (staticExtensions.some(ext => pathname.endsWith(ext))) {
        return false;
      }
    }
    
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
    
    const urlObj = new URL(request.url);
    const getParams = {};
    urlObj.searchParams.forEach((value, key) => {
      if (getParams[key]) {
        if (Array.isArray(getParams[key])) {
          getParams[key].push(value);
        } else {
          getParams[key] = [getParams[key], value];
        }
      } else {
        getParams[key] = value;
      }
    });
    
    const contentType = request.headers?.['content-type'] || request.headers?.['Content-Type'] || '';
    
    const captureData = {
      url: request.url,
      endpoint: endpoint,
      method: request.method,
      statusCode: request.statusCode || 0,
      headers: request.headers || {},
      responseHeaders: request.responseHeaders || {},
      timestamp: new Date(request.timestamp).toISOString(),
      mimeType: request.responseHeaders?.['content-type'] || 'unknown',
      getParams: Object.keys(getParams).length > 0 ? getParams : null,
      postParams: null,
      bodyType: contentType
    };
    
    if (request.postData) {
      captureData.postData = request.postData;
      
      if (contentType.includes('application/json')) {
        try {
          captureData.postParams = JSON.parse(request.postData);
        } catch (e) {
          console.log('[MANUAL-CRAWL] Could not parse JSON body');
        }
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        try {
          const params = new URLSearchParams(request.postData);
          const postParams = {};
          params.forEach((value, key) => {
            if (postParams[key]) {
              if (Array.isArray(postParams[key])) {
                postParams[key].push(value);
              } else {
                postParams[key] = [postParams[key], value];
              }
            } else {
              postParams[key] = value;
            }
          });
          captureData.postParams = postParams;
        } catch (e) {
          console.log('[MANUAL-CRAWL] Could not parse form data');
        }
      }
    }
    
    console.log('[MANUAL-CRAWL] Captured request data:');
    console.log('  URL:', captureData.url);
    console.log('  Method:', captureData.method);
    console.log('  Status:', captureData.statusCode);
    if (captureData.getParams) {
      console.log('  GET params:', captureData.getParams);
    }
    if (captureData.postParams) {
      console.log('  POST params:', captureData.postParams);
    }
    if (captureData.bodyType) {
      console.log('  Body type:', captureData.bodyType);
    }
    if (captureData.postData && !captureData.postParams) {
      console.log('  Raw body (first 200 chars):', captureData.postData.substring(0, 200));
    }
    
    await sendToFramework(captureData);
    
    await chrome.storage.local.set({ 
      captureStats: captureSession.stats,
      isCapturing: true,
      captureTabId: captureSession.tabId
    });
    
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
