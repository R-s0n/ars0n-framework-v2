const initiateCensysCompanyScan = async (
  activeTarget,
  monitorCensysCompanyScanStatus,
  setIsCensysCompanyScanning,
  setCensysCompanyScans,
  setMostRecentCensysCompanyScanStatus,
  setMostRecentCensysCompanyScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  const companyName = activeTarget.scope_target;

  try {
    console.log('[CENSYS-COMPANY] Initiating Censys Company scan for:', companyName);
    
    const body = { company_name: companyName };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    
    const response = await fetch(
      `/api/censys-company/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Censys Company scan');
    }

    const data = await response.json();
    console.log('[CENSYS-COMPANY] Scan initiated with ID:', data.scan_id);
    setIsCensysCompanyScanning(true);

    if (monitorCensysCompanyScanStatus) {
      monitorCensysCompanyScanStatus(
        activeTarget,
        setCensysCompanyScans,
        setMostRecentCensysCompanyScan,
        setIsCensysCompanyScanning,
        setMostRecentCensysCompanyScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('[CENSYS-COMPANY] Error initiating Censys Company scan:', error);
    setIsCensysCompanyScanning(false);
  }
};

export default initiateCensysCompanyScan; 