const initiateShodanCompanyScan = async (
  activeTarget,
  monitorShodanCompanyScanStatus,
  setIsShodanCompanyScanning,
  setShodanCompanyScans,
  setMostRecentShodanCompanyScanStatus,
  setMostRecentShodanCompanyScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  const companyName = activeTarget.scope_target;

  try {
    console.log('[SHODAN-COMPANY] Initiating Shodan Company scan for:', companyName);
    
    const body = { company_name: companyName };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    
    const response = await fetch(
      `/api/shodan-company/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Shodan Company scan');
    }

    const data = await response.json();
    console.log('[SHODAN-COMPANY] Scan initiated with ID:', data.scan_id);
    setIsShodanCompanyScanning(true);

    if (monitorShodanCompanyScanStatus) {
      monitorShodanCompanyScanStatus(
        activeTarget,
        setShodanCompanyScans,
        setMostRecentShodanCompanyScan,
        setIsShodanCompanyScanning,
        setMostRecentShodanCompanyScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('[SHODAN-COMPANY] Error initiating Shodan Company scan:', error);
    setIsShodanCompanyScanning(false);
  }
};

export default initiateShodanCompanyScan; 