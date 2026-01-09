const monitorShuffleDNSScanStatus = async (
  activeTarget,
  setShuffleDNSScans,
  setMostRecentShuffleDNSScan,
  setIsShuffleDNSScanning,
  setMostRecentShuffleDNSScanStatus
) => {
  if (!activeTarget || !activeTarget.id) {
    setIsShuffleDNSScanning(false);
    setMostRecentShuffleDNSScan(null);
    setMostRecentShuffleDNSScanStatus(null);
    return;
  }

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/shuffledns`
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch ShuffleDNS scans: ${response.statusText}`);
    }

    const scans = await response.json();
    setShuffleDNSScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentShuffleDNSScan(mostRecentScan);
      setMostRecentShuffleDNSScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsShuffleDNSScanning(true);
        setTimeout(() => {
          monitorShuffleDNSScanStatus(
            activeTarget,
            setShuffleDNSScans,
            setMostRecentShuffleDNSScan,
            setIsShuffleDNSScanning,
            setMostRecentShuffleDNSScanStatus
          );
        }, 5000);
      } else {
        setIsShuffleDNSScanning(false);
      }
    } else {
      setMostRecentShuffleDNSScan(null);
      setMostRecentShuffleDNSScanStatus(null);
      setIsShuffleDNSScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring ShuffleDNS scan status:', error);
    setIsShuffleDNSScanning(false);
    setMostRecentShuffleDNSScan(null);
    setMostRecentShuffleDNSScanStatus(null);
  }
};

export default monitorShuffleDNSScanStatus; 