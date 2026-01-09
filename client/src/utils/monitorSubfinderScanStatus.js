const monitorSubfinderScanStatus = async (
  activeTarget,
  setSubfinderScans,
  setMostRecentSubfinderScan,
  setIsSubfinderScanning,
  setMostRecentSubfinderScanStatus
) => {
  if (!activeTarget || !activeTarget.id) {
    setIsSubfinderScanning(false);
    setMostRecentSubfinderScan(null);
    setMostRecentSubfinderScanStatus(null);
    return;
  }

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/subfinder`
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch Subfinder scans: ${response.statusText}`);
    }

    const scans = await response.json();
    setSubfinderScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentSubfinderScan(mostRecentScan);
      setMostRecentSubfinderScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsSubfinderScanning(true);
        setTimeout(() => {
          monitorSubfinderScanStatus(
            activeTarget,
            setSubfinderScans,
            setMostRecentSubfinderScan,
            setIsSubfinderScanning,
            setMostRecentSubfinderScanStatus
          );
        }, 5000);
      } else {
        setIsSubfinderScanning(false);
      }
    } else {
      setMostRecentSubfinderScan(null);
      setMostRecentSubfinderScanStatus(null);
      setIsSubfinderScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring Subfinder scan status:', error);
    setIsSubfinderScanning(false);
    setMostRecentSubfinderScan(null);
    setMostRecentSubfinderScanStatus(null);
  }
};

export default monitorSubfinderScanStatus; 