const monitorCeWLScanStatus = async (
  activeTarget,
  setCeWLScans,
  setMostRecentCeWLScan,
  setIsCeWLScanning,
  setMostRecentCeWLScanStatus
) => {
  if (!activeTarget || !activeTarget.id) {
    setIsCeWLScanning(false);
    setMostRecentCeWLScan(null);
    setMostRecentCeWLScanStatus(null);
    return;
  }

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/cewl`
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch CeWL scans: ${response.statusText}`);
    }

    const scans = await response.json();
    setCeWLScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentCeWLScan(mostRecentScan);
      setMostRecentCeWLScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsCeWLScanning(true);
        setTimeout(() => {
          monitorCeWLScanStatus(
            activeTarget,
            setCeWLScans,
            setMostRecentCeWLScan,
            setIsCeWLScanning,
            setMostRecentCeWLScanStatus
          );
        }, 5000);
      } else {
        setIsCeWLScanning(false);
      }
    } else {
      setMostRecentCeWLScan(null);
      setMostRecentCeWLScanStatus(null);
      setIsCeWLScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring CeWL scan status:', error);
    setIsCeWLScanning(false);
    setMostRecentCeWLScan(null);
    setMostRecentCeWLScanStatus(null);
  }
};

export default monitorCeWLScanStatus; 