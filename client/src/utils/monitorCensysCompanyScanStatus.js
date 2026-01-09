const monitorCensysCompanyScanStatus = async (
  activeTarget,
  setCensysCompanyScans,
  setMostRecentCensysCompanyScan,
  setIsCensysCompanyScanning,
  setMostRecentCensysCompanyScanStatus
) => {
  if (!activeTarget) return;

  try {
    console.log('[CENSYS-COMPANY] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/censys-company`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch Censys Company scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setCensysCompanyScans([]);
      setMostRecentCensysCompanyScan(null);
      setMostRecentCensysCompanyScanStatus(null);
      setIsCensysCompanyScanning(false);
      return;
    }

    console.log('[CENSYS-COMPANY] Retrieved', scans.length, 'scans');
    setCensysCompanyScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      console.log('[CENSYS-COMPANY] Most recent scan status:', mostRecentScan.status);
      setMostRecentCensysCompanyScan(mostRecentScan);
      setMostRecentCensysCompanyScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsCensysCompanyScanning(true);
        setTimeout(() => {
          monitorCensysCompanyScanStatus(
            activeTarget,
            setCensysCompanyScans,
            setMostRecentCensysCompanyScan,
            setIsCensysCompanyScanning,
            setMostRecentCensysCompanyScanStatus
          );
        }, 5000);
      } else {
        setIsCensysCompanyScanning(false);
      }
    } else {
      setMostRecentCensysCompanyScan(null);
      setMostRecentCensysCompanyScanStatus(null);
      setIsCensysCompanyScanning(false);
    }
  } catch (error) {
    console.error('[CENSYS-COMPANY] Error monitoring scan status:', error);
    setIsCensysCompanyScanning(false);
    setMostRecentCensysCompanyScan(null);
    setMostRecentCensysCompanyScanStatus(null);
    setCensysCompanyScans([]);
  }
};

export default monitorCensysCompanyScanStatus; 