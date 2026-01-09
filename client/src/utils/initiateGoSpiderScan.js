const initiateGoSpiderScan = async (
  activeTarget,
  monitorGoSpiderScanStatus,
  setIsGoSpiderScanning,
  setGoSpiderScans,
  setMostRecentGoSpiderScanStatus,
  setMostRecentGoSpiderScan,
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
    setIsGoSpiderScanning(true);
    const body = { fqdn: domain };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    const response = await fetch(
      `/api/gospider/run`,
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
      throw new Error(`Failed to initiate GoSpider scan: ${errorText}`);
    }

    const data = await response.json();

    if (monitorGoSpiderScanStatus) {
      monitorGoSpiderScanStatus(
        activeTarget,
        setGoSpiderScans,
        setMostRecentGoSpiderScan,
        setIsGoSpiderScanning,
        setMostRecentGoSpiderScanStatus
      );
    };

    return data;
  } catch (error) {
    console.error('Error initiating GoSpider scan:', error);
    setIsGoSpiderScanning(false);
    setMostRecentGoSpiderScan(null);
    setMostRecentGoSpiderScanStatus(null);
  }
};

export default initiateGoSpiderScan; 