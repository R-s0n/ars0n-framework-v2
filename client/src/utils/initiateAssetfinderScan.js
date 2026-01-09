const initiateAssetfinderScan = async (
  activeTarget,
  monitorAssetfinderScanStatus,
  setIsAssetfinderScanning,
  setAssetfinderScans,
  setMostRecentAssetfinderScanStatus,
  setMostRecentAssetfinderScan,
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
    setIsAssetfinderScanning(true);
    const body = { fqdn: domain };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    const response = await fetch(
      `/api/assetfinder/run`,
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
      throw new Error(`Failed to initiate Assetfinder scan: ${errorText}`);
    }

    const data = await response.json();

    // Start monitoring the scan status
    if (monitorAssetfinderScanStatus) {
      monitorAssetfinderScanStatus(
        activeTarget,
        setAssetfinderScans,
        setMostRecentAssetfinderScan,
        setIsAssetfinderScanning,
        setMostRecentAssetfinderScanStatus
      );
    }

    return { success: true, data };
  } catch (error) {
    console.error('Error initiating Assetfinder scan:', error);
    setIsAssetfinderScanning(false);
    setMostRecentAssetfinderScan(null);
    setMostRecentAssetfinderScanStatus(null);
    return { success: false, error: error.message };
  }
};

export default initiateAssetfinderScan; 