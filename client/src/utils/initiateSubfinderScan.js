const initiateSubfinderScan = async (
  activeTarget,
  monitorSubfinderScanStatus,
  setIsSubfinderScanning,
  setSubfinderScans,
  setMostRecentSubfinderScanStatus,
  setMostRecentSubfinderScan,
  autoScanSessionId
) => {
  if (!activeTarget || !activeTarget.scope_target) {
    console.error('No active target or invalid target format');
    return;
  }

  const domain = activeTarget.scope_target.replace('*.', '');
  if (!domain) {
    console.error('Invalid domain');
    return;
  }

  try {
    const body = { fqdn: domain };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    const response = await fetch(
      `/api/subfinder/run`,
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
      throw new Error(`Failed to initiate Subfinder scan: ${errorText}`);
    }

    const data = await response.json();
    setIsSubfinderScanning(true);

    if (monitorSubfinderScanStatus) {
      monitorSubfinderScanStatus(
        activeTarget,
        setSubfinderScans,
        setMostRecentSubfinderScan,
        setIsSubfinderScanning,
        setMostRecentSubfinderScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('Error initiating Subfinder scan:', error);
    setIsSubfinderScanning(false);
    setMostRecentSubfinderScan(null);
    setMostRecentSubfinderScanStatus(null);
  }
};

export default initiateSubfinderScan; 