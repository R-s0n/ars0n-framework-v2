const initiateHttpxScan = async (
  activeTarget,
  monitorHttpxScanStatus,
  setIsHttpxScanning,
  setHttpxScans,
  setMostRecentHttpxScanStatus,
  setMostRecentHttpxScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  let fqdn = activeTarget.scope_target;
  if (activeTarget.type === 'Wildcard' && fqdn.startsWith('*.')) {
    fqdn = fqdn.substring(2);
  }
  
  try {
    const body = { fqdn };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    const response = await fetch(
      `/api/httpx/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate httpx scan');
    }

    const data = await response.json();
    console.log(data);
    setIsHttpxScanning(true);

    if (monitorHttpxScanStatus) {
      monitorHttpxScanStatus(
        activeTarget,
        setHttpxScans,
        setMostRecentHttpxScan,
        setIsHttpxScanning,
        setMostRecentHttpxScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('Error initiating httpx scan:', error);
    setIsHttpxScanning(false);
  }
}

export default initiateHttpxScan; 