const initiateSublist3rScan = async (
  activeTarget,
  monitorSublist3rScanStatus,
  setIsSublist3rScanning,
  setSublist3rScans,
  setMostRecentSublist3rScanStatus,
  setMostRecentSublist3rScan,
  autoScanSessionId
) => {
  if (!activeTarget || !activeTarget.scope_target) {
    console.error('No active target or invalid target format');
    return { success: false, error: 'No active target or invalid target format' };
  }

  const domain = activeTarget.scope_target.replace('*.', '');
  if (!domain) {
    console.error('Invalid domain');
    return { success: false, error: 'Invalid domain' };
  }

  try {
    setIsSublist3rScanning(true);
    const body = { fqdn: domain };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    const response = await fetch(
      `/api/sublist3r/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to initiate Sublist3r scan: ${errorText}`);
    }

    const data = await response.json();

    // Start monitoring the scan status if monitoring function is provided
    if (monitorSublist3rScanStatus) {
      monitorSublist3rScanStatus(
        activeTarget,
        setSublist3rScans,
        setMostRecentSublist3rScan,
        setIsSublist3rScanning,
        setMostRecentSublist3rScanStatus
      );
    }

    return { success: true, data };
  } catch (error) {
    console.error('Error initiating Sublist3r scan:', error);
    setIsSublist3rScanning(false);
    setMostRecentSublist3rScan(null);
    setMostRecentSublist3rScanStatus(null);
    return { success: false, error: error.message };
  }
};

export default initiateSublist3rScan; 