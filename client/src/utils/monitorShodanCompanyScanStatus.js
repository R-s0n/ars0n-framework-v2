const monitorShodanCompanyScanStatus = async (
  activeTarget,
  setShodanCompanyScans,
  setMostRecentShodanCompanyScan,
  setIsShodanCompanyScanning,
  setMostRecentShodanCompanyScanStatus
) => {
  if (!activeTarget) return;

  try {
    console.log('[SHODAN-COMPANY] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/shodan-company`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch Shodan Company scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setShodanCompanyScans([]);
      setMostRecentShodanCompanyScan(null);
      setMostRecentShodanCompanyScanStatus(null);
      setIsShodanCompanyScanning(false);
      return;
    }

    console.log('[SHODAN-COMPANY] Retrieved', scans.length, 'scans');
    setShodanCompanyScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      console.log('[SHODAN-COMPANY] Most recent scan status:', mostRecentScan.status);
      setMostRecentShodanCompanyScan(mostRecentScan);
      setMostRecentShodanCompanyScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsShodanCompanyScanning(true);
        setTimeout(() => {
          monitorShodanCompanyScanStatus(
            activeTarget,
            setShodanCompanyScans,
            setMostRecentShodanCompanyScan,
            setIsShodanCompanyScanning,
            setMostRecentShodanCompanyScanStatus
          );
        }, 5000);
      } else {
        setIsShodanCompanyScanning(false);
      }
    } else {
      setMostRecentShodanCompanyScan(null);
      setMostRecentShodanCompanyScanStatus(null);
      setIsShodanCompanyScanning(false);
    }
  } catch (error) {
    console.error('[SHODAN-COMPANY] Error monitoring scan status:', error);
    setIsShodanCompanyScanning(false);
    setMostRecentShodanCompanyScan(null);
    setMostRecentShodanCompanyScanStatus(null);
    setShodanCompanyScans([]);
  }
};

export default monitorShodanCompanyScanStatus; 