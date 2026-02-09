let recordingIndicator = null;

function createRecordingIndicator() {
  if (recordingIndicator) return;
  
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
        animation: pulse 2s ease-in-out infinite;
      "></div>
      <span>RECORDING</span>
      <span style="
        margin-left: 8px;
        padding-left: 8px;
        border-left: 1px solid rgba(255, 255, 255, 0.3);
      " id="ars0n-endpoint-count">0 endpoints</span>
    </div>
    <style>
      @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.3; }
      }
    </style>
  `;
  
  document.documentElement.appendChild(recordingIndicator);
  console.log('[ARS0N] Recording indicator added to page');
}

function updateRecordingStats(stats) {
  const badge = document.getElementById('ars0n-endpoint-count');
  if (badge && stats) {
    const endpointText = stats.endpointCount === 1 ? 'endpoint' : 'endpoints';
    badge.textContent = `${stats.endpointCount} ${endpointText}`;
    console.log('[ARS0N] Stats updated on page:', stats);
  }
}

function removeRecordingIndicator() {
  if (recordingIndicator) {
    recordingIndicator.remove();
    recordingIndicator = null;
    console.log('[ARS0N] Recording indicator removed from page');
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[ARS0N] Content script received message:', message);
  
  if (message.action === 'showRecordingIndicator') {
    createRecordingIndicator();
    sendResponse({ success: true });
  } else if (message.action === 'updateStats') {
    updateRecordingStats(message.stats);
    sendResponse({ success: true });
  } else if (message.action === 'hideRecordingIndicator') {
    removeRecordingIndicator();
    sendResponse({ success: true });
  }
  
  return true;
});

function initializeIndicator() {
  try {
    chrome.storage.local.get(['isCapturing', 'captureStats', 'captureTabId'], (result) => {
      if (chrome.runtime.lastError) {
        console.log('[ARS0N-CONTENT] Extension context lost during init');
        return;
      }
      
      console.log('[ARS0N-CONTENT] Checking storage on page load:', result);
      console.log('[ARS0N-CONTENT] Current tab ID (from window):', window.location.href);
      
      if (result.isCapturing) {
        console.log('[ARS0N-CONTENT] Storage says capturing is active, showing indicator');
        createRecordingIndicator();
        updateRecordingStats(result.captureStats);
      } else {
        console.log('[ARS0N-CONTENT] Storage says capturing is NOT active');
        removeRecordingIndicator();
      }
    });
  } catch (error) {
    console.log('[ARS0N-CONTENT] Extension context invalidated during init');
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeIndicator);
} else {
  initializeIndicator();
}

setInterval(() => {
  try {
    chrome.storage.local.get(['isCapturing', 'captureStats', 'captureTabId'], (result) => {
      if (chrome.runtime.lastError) {
        console.log('[ARS0N-CONTENT] Extension context lost, stopping interval');
        return;
      }
      
      console.log('[ARS0N-CONTENT] Periodic check - isCapturing:', result.isCapturing, 'hasIndicator:', !!recordingIndicator);
      
      if (result.isCapturing) {
        if (!recordingIndicator) {
          console.log('[ARS0N-CONTENT] Re-creating missing indicator');
          createRecordingIndicator();
        }
        updateRecordingStats(result.captureStats);
      } else {
        if (recordingIndicator) {
          console.log('[ARS0N-CONTENT] Storage says not capturing, removing indicator');
          removeRecordingIndicator();
        }
      }
    });
  } catch (error) {
    console.log('[ARS0N-CONTENT] Extension context invalidated, stopping checks');
  }
}, 3000);
