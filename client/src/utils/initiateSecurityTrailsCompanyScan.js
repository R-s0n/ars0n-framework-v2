const initiateSecurityTrailsCompanyScan = async (
  activeTarget,
  monitorSecurityTrailsCompanyScanStatus,
  setIsSecurityTrailsCompanyScanning,
  setSecurityTrailsCompanyScans,
  setMostRecentSecurityTrailsCompanyScanStatus,
  setMostRecentSecurityTrailsCompanyScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  const companyName = activeTarget.scope_target;

  try {
    console.log('[SECURITYTRAILS-COMPANY] Initiating SecurityTrails Company scan for:', companyName);
    
    const body = { company_name: companyName };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    
    const response = await fetch(
      `/api/securitytrails-company/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate SecurityTrails Company scan');
    }

    const data = await response.json();
    console.log('[SECURITYTRAILS-COMPANY] Scan initiated with ID:', data.scan_id);
    setIsSecurityTrailsCompanyScanning(true);

    if (monitorSecurityTrailsCompanyScanStatus) {
      monitorSecurityTrailsCompanyScanStatus(
        activeTarget,
        setSecurityTrailsCompanyScans,
        setMostRecentSecurityTrailsCompanyScan,
        setIsSecurityTrailsCompanyScanning,
        setMostRecentSecurityTrailsCompanyScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('[SECURITYTRAILS-COMPANY] Error initiating SecurityTrails Company scan:', error);
    setIsSecurityTrailsCompanyScanning(false);
  }
};

export default initiateSecurityTrailsCompanyScan; 