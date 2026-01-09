const initiateCTLScan = async (
  activeTarget,
  monitorCTLScanStatus,
  setIsCTLScanning,
  setCTLScans,
  setMostRecentCTLScanStatus,
  setMostRecentCTLScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  const domain = activeTarget.scope_target.replace('*.', '');

  try {
    const body = { fqdn: domain };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    const response = await fetch(
      `/api/ctl/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate CTL scan');
    }

    const data = await response.json();
    setIsCTLScanning(true);

    if (monitorCTLScanStatus) {
      monitorCTLScanStatus(
        activeTarget,
        setCTLScans,
        setMostRecentCTLScan,
        setIsCTLScanning,
        setMostRecentCTLScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('Error initiating CTL scan:', error);
    setIsCTLScanning(false);
  }
};

export default initiateCTLScan; 