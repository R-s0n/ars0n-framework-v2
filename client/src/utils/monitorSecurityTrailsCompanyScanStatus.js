const monitorSecurityTrailsCompanyScanStatus = async (
  activeTarget,
  setSecurityTrailsCompanyScans,
  setMostRecentSecurityTrailsCompanyScan,
  setIsSecurityTrailsCompanyScanning,
  setMostRecentSecurityTrailsCompanyScanStatus
) => {
  if (!activeTarget) return;

  try {
    console.log('[SECURITYTRAILS-COMPANY] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/securitytrails-company`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch SecurityTrails Company scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setSecurityTrailsCompanyScans([]);
      setMostRecentSecurityTrailsCompanyScan(null);
      setMostRecentSecurityTrailsCompanyScanStatus(null);
      setIsSecurityTrailsCompanyScanning(false);
      return;
    }

    console.log('[SECURITYTRAILS-COMPANY] Retrieved', scans.length, 'scans');
    setSecurityTrailsCompanyScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      console.log('[SECURITYTRAILS-COMPANY] Most recent scan status:', mostRecentScan.status);
      setMostRecentSecurityTrailsCompanyScan(mostRecentScan);
      setMostRecentSecurityTrailsCompanyScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsSecurityTrailsCompanyScanning(true);
        setTimeout(() => {
          monitorSecurityTrailsCompanyScanStatus(
            activeTarget,
            setSecurityTrailsCompanyScans,
            setMostRecentSecurityTrailsCompanyScan,
            setIsSecurityTrailsCompanyScanning,
            setMostRecentSecurityTrailsCompanyScanStatus
          );
        }, 5000);
      } else {
        setIsSecurityTrailsCompanyScanning(false);
      }
    } else {
      setMostRecentSecurityTrailsCompanyScan(null);
      setMostRecentSecurityTrailsCompanyScanStatus(null);
      setIsSecurityTrailsCompanyScanning(false);
    }
  } catch (error) {
    console.error('[SECURITYTRAILS-COMPANY] Error monitoring scan status:', error);
    setIsSecurityTrailsCompanyScanning(false);
    setMostRecentSecurityTrailsCompanyScan(null);
    setMostRecentSecurityTrailsCompanyScanStatus(null);
    setSecurityTrailsCompanyScans([]);
  }
};

export default monitorSecurityTrailsCompanyScanStatus; 