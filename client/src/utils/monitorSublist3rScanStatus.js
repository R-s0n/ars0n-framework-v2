const monitorSublist3rScanStatus = async (
  activeTarget,
  setSublist3rScans,
  setMostRecentSublist3rScan,
  setIsSublist3rScanning,
  setMostRecentSublist3rScanStatus
) => {
  if (!activeTarget || !activeTarget.id) {
    setIsSublist3rScanning(false);
    setMostRecentSublist3rScan(null);
    setMostRecentSublist3rScanStatus(null);
    return;
  }

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/sublist3r`
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch Sublist3r scans: ${response.statusText}`);
    }

    const scans = await response.json();
    setSublist3rScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentSublist3rScan(mostRecentScan);
      setMostRecentSublist3rScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsSublist3rScanning(true);
        setTimeout(() => {
          monitorSublist3rScanStatus(
            activeTarget,
            setSublist3rScans,
            setMostRecentSublist3rScan,
            setIsSublist3rScanning,
            setMostRecentSublist3rScanStatus
          );
        }, 5000);
      } else {
        setIsSublist3rScanning(false);
      }
    } else {
      setMostRecentSublist3rScan(null);
      setMostRecentSublist3rScanStatus(null);
      setIsSublist3rScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring Sublist3r scan status:', error);
    setIsSublist3rScanning(false);
    setMostRecentSublist3rScan(null);
    setMostRecentSublist3rScanStatus(null);
  }
};

export default monitorSublist3rScanStatus; 