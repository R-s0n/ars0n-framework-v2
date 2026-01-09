const initiateIPPortScan = async (scopeTargetId, autoScanSessionId = null) => {
  const API_BASE_URL = '/api';

  const payload = {
    scope_target_id: scopeTargetId
  };

  if (autoScanSessionId) {
    payload.auto_scan_session_id = autoScanSessionId;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/ip-port-scan/run`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(`HTTP error! status: ${response.status}, message: ${errorData}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error initiating IP/Port scan:', error);
    throw error;
  }
};

export default initiateIPPortScan; 