const monitorGoSpiderScanStatus = async (
  activeTarget,
  setGoSpiderScans,
  setMostRecentGoSpiderScan,
  setIsGoSpiderScanning,
  setMostRecentGoSpiderScanStatus
) => {
  if (!activeTarget || !activeTarget.id) {
    setIsGoSpiderScanning(false);
    setMostRecentGoSpiderScan(null);
    setMostRecentGoSpiderScanStatus(null);
    return;
  }

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/gospider`
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch GoSpider scans: ${response.statusText}`);
    }

    const scans = await response.json();
    setGoSpiderScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentGoSpiderScan(mostRecentScan);
      setMostRecentGoSpiderScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsGoSpiderScanning(true);
        setTimeout(() => {
          monitorGoSpiderScanStatus(
            activeTarget,
            setGoSpiderScans,
            setMostRecentGoSpiderScan,
            setIsGoSpiderScanning,
            setMostRecentGoSpiderScanStatus
          );
        }, 5000);
      } else {
        setIsGoSpiderScanning(false);
      }
    } else {
      setMostRecentGoSpiderScan(null);
      setMostRecentGoSpiderScanStatus(null);
      setIsGoSpiderScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring GoSpider scan status:', error);
    setIsGoSpiderScanning(false);
    setMostRecentGoSpiderScan(null);
    setMostRecentGoSpiderScanStatus(null);
  }
};

export default monitorGoSpiderScanStatus; 