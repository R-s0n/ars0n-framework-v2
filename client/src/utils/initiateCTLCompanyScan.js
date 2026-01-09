const initiateCTLCompanyScan = async (
  activeTarget,
  monitorCTLCompanyScanStatus,
  setIsCTLCompanyScanning,
  setCTLCompanyScans,
  setMostRecentCTLCompanyScanStatus,
  setMostRecentCTLCompanyScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  const companyName = activeTarget.scope_target;

  try {
    console.log('[CTL-COMPANY] Initiating CTL Company scan for:', companyName);
    
    const body = { company_name: companyName };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    
    const response = await fetch(
      `/api/ctl-company/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate CTL Company scan');
    }

    const data = await response.json();
    console.log('[CTL-COMPANY] Scan initiated with ID:', data.scan_id);
    setIsCTLCompanyScanning(true);

    if (monitorCTLCompanyScanStatus) {
      monitorCTLCompanyScanStatus(
        activeTarget,
        setCTLCompanyScans,
        setMostRecentCTLCompanyScan,
        setIsCTLCompanyScanning,
        setMostRecentCTLCompanyScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('[CTL-COMPANY] Error initiating CTL Company scan:', error);
    setIsCTLCompanyScanning(false);
  }
};

export default initiateCTLCompanyScan; 