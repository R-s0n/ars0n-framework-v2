const initiateSubfinderScan = async (
  activeTarget,
  monitorSubfinderScanStatus,
  setIsSubfinderScanning,
  setSubfinderScans,
  setMostRecentSubfinderScanStatus,
  setMostRecentSubfinderScan
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
    setIsSubfinderScanning(true);
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/subfinder/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fqdn: domain
        }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to initiate Subfinder scan: ${errorText}`);
    }

    const data = await response.json();

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