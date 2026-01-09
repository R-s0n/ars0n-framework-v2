const monitorCTLCompanyScanStatus = async (
  activeTarget,
  setCTLCompanyScans,
  setMostRecentCTLCompanyScan,
  setIsCTLCompanyScanning,
  setMostRecentCTLCompanyScanStatus
) => {
  if (!activeTarget) return;

  try {
    console.log('[CTL-COMPANY] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/ctl-company`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch CTL Company scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setCTLCompanyScans([]);
      setMostRecentCTLCompanyScan(null);
      setMostRecentCTLCompanyScanStatus(null);
      setIsCTLCompanyScanning(false);
      return;
    }

    console.log('[CTL-COMPANY] Retrieved', scans.length, 'scans');
    setCTLCompanyScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      console.log('[CTL-COMPANY] Most recent scan status:', mostRecentScan.status);
      setMostRecentCTLCompanyScan(mostRecentScan);
      setMostRecentCTLCompanyScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsCTLCompanyScanning(true);
        setTimeout(() => {
          monitorCTLCompanyScanStatus(
            activeTarget,
            setCTLCompanyScans,
            setMostRecentCTLCompanyScan,
            setIsCTLCompanyScanning,
            setMostRecentCTLCompanyScanStatus
          );
        }, 5000);
      } else {
        setIsCTLCompanyScanning(false);
      }
    } else {
      setMostRecentCTLCompanyScan(null);
      setMostRecentCTLCompanyScanStatus(null);
      setIsCTLCompanyScanning(false);
    }
  } catch (error) {
    console.error('[CTL-COMPANY] Error monitoring scan status:', error);
    setIsCTLCompanyScanning(false);
    setMostRecentCTLCompanyScan(null);
    setMostRecentCTLCompanyScanStatus(null);
    setCTLCompanyScans([]);
  }
};

export default monitorCTLCompanyScanStatus; 