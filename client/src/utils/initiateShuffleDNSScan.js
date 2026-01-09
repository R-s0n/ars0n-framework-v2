const initiateShuffleDNSScan = async (
  activeTarget,
  monitorShuffleDNSScanStatus,
  setIsShuffleDNSScanning,
  setShuffleDNSScans,
  setMostRecentShuffleDNSScanStatus,
  setMostRecentShuffleDNSScan,
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
      `/api/shuffledns/run`,
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
      throw new Error(`Failed to initiate ShuffleDNS scan: ${errorText}`);
    }

    const data = await response.json();
    setIsShuffleDNSScanning(true);

    if (monitorShuffleDNSScanStatus) {
      monitorShuffleDNSScanStatus(
        activeTarget,
        setShuffleDNSScans,
        setMostRecentShuffleDNSScan,
        setIsShuffleDNSScanning,
        setMostRecentShuffleDNSScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('Error initiating ShuffleDNS scan:', error);
    setIsShuffleDNSScanning(false);
    setMostRecentShuffleDNSScan(null);
    setMostRecentShuffleDNSScanStatus(null);
  }
};

export default initiateShuffleDNSScan; 