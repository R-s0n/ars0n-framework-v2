const initiateCeWLScan = async (
  activeTarget,
  monitorCeWLScanStatus,
  setIsCeWLScanning,
  setCeWLScans,
  setMostRecentCeWLScanStatus,
  setMostRecentCeWLScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  try {
    setIsCeWLScanning(true);

    // Extract the domain from the scope target (remove the wildcard if present)
    const domain = activeTarget.scope_target.replace(/^\*\./, '');

    const body = { fqdn: domain };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;

    const response = await fetch(
      `/api/cewl/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate CeWL scan');
    }

    const data = await response.json();
    const scanId = data.scan_id;

    // Start monitoring the scan status
    if (monitorCeWLScanStatus) {
    monitorCeWLScanStatus(
      activeTarget,
      setCeWLScans,
        setMostRecentCeWLScan,
        setIsCeWLScanning,
        setMostRecentCeWLScanStatus
      );
    };

  } catch (error) {
    console.error('Error initiating CeWL scan:', error);
    setIsCeWLScanning(false);
  }
};

export default initiateCeWLScan; 