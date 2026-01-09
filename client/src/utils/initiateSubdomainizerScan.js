const initiateSubdomainizerScan = async (
  activeTarget,
  monitorSubdomainizerScanStatus,
  setIsSubdomainizerScanning,
  setSubdomainizerScans,
  setMostRecentSubdomainizerScanStatus,
  setMostRecentSubdomainizerScan,
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
    setIsSubdomainizerScanning(true);
    const body = { fqdn: domain };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    const response = await fetch(
      `/api/subdomainizer/run`,
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
      throw new Error(`Failed to initiate Subdomainizer scan: ${errorText}`);
    }

    const data = await response.json();

    if (monitorSubdomainizerScanStatus) {
      monitorSubdomainizerScanStatus(
        activeTarget,
        setSubdomainizerScans,
        setMostRecentSubdomainizerScan,
        setIsSubdomainizerScanning,
        setMostRecentSubdomainizerScanStatus
      );
    };

    return data;
  } catch (error) {
    console.error('Error initiating Subdomainizer scan:', error);
    setIsSubdomainizerScanning(false);
    setMostRecentSubdomainizerScan(null);
    setMostRecentSubdomainizerScanStatus(null);
  }
};

export default initiateSubdomainizerScan; 