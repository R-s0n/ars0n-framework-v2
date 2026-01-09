const monitorCTLScanStatus = async (
  activeTarget,
  setCTLScans,
  setMostRecentCTLScan,
  setIsCTLScanning,
  setMostRecentCTLScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/ctl`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch CTL scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setCTLScans([]);
      setMostRecentCTLScan(null);
      setMostRecentCTLScanStatus(null);
      setIsCTLScanning(false);
      return;
    }

    setCTLScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentCTLScan(mostRecentScan);
      setMostRecentCTLScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsCTLScanning(true);
        setTimeout(() => {
          monitorCTLScanStatus(
            activeTarget,
            setCTLScans,
            setMostRecentCTLScan,
            setIsCTLScanning,
            setMostRecentCTLScanStatus
          );
        }, 5000);
      } else {
        setIsCTLScanning(false);
      }
    } else {
      setMostRecentCTLScan(null);
      setMostRecentCTLScanStatus(null);
      setIsCTLScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring CTL scan status:', error);
    setIsCTLScanning(false);
    setMostRecentCTLScan(null);
    setMostRecentCTLScanStatus(null);
    setCTLScans([]);
  }
};

export default monitorCTLScanStatus; 