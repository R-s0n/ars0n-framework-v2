const monitorSubdomainizerScanStatus = async (
  activeTarget,
  setSubdomainizerScans,
  setMostRecentSubdomainizerScan,
  setIsSubdomainizerScanning,
  setMostRecentSubdomainizerScanStatus
) => {
  if (!activeTarget || !activeTarget.id) {
    setIsSubdomainizerScanning(false);
    setMostRecentSubdomainizerScan(null);
    setMostRecentSubdomainizerScanStatus(null);
    return;
  }

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/subdomainizer`
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch Subdomainizer scans: ${response.statusText}`);
    }

    const scans = await response.json();
    setSubdomainizerScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentSubdomainizerScan(mostRecentScan);
      setMostRecentSubdomainizerScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsSubdomainizerScanning(true);
        setTimeout(() => {
          monitorSubdomainizerScanStatus(
            activeTarget,
            setSubdomainizerScans,
            setMostRecentSubdomainizerScan,
            setIsSubdomainizerScanning,
            setMostRecentSubdomainizerScanStatus
          );
        }, 5000);
      } else {
        setIsSubdomainizerScanning(false);
      }
    } else {
      setMostRecentSubdomainizerScan(null);
      setMostRecentSubdomainizerScanStatus(null);
      setIsSubdomainizerScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring Subdomainizer scan status:', error);
    setIsSubdomainizerScanning(false);
    setMostRecentSubdomainizerScan(null);
    setMostRecentSubdomainizerScanStatus(null);
  }
};

export default monitorSubdomainizerScanStatus; 