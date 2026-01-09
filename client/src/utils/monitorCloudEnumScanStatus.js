const monitorCloudEnumScanStatus = async (
  activeTarget,
  setCloudEnumScans,
  setMostRecentCloudEnumScan,
  setIsCloudEnumScanning,
  setMostRecentCloudEnumScanStatus
) => {
  if (!activeTarget) return;

  try {
    console.log('[CLOUD-ENUM] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/cloud-enum`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch Cloud Enum scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setCloudEnumScans([]);
      setMostRecentCloudEnumScan(null);
      setMostRecentCloudEnumScanStatus(null);
      setIsCloudEnumScanning(false);
      return;
    }

    console.log('[CLOUD-ENUM] Retrieved', scans.length, 'scans');
    setCloudEnumScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      console.log('[CLOUD-ENUM] Most recent scan status:', mostRecentScan.status);
      setMostRecentCloudEnumScan(mostRecentScan);
      setMostRecentCloudEnumScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsCloudEnumScanning(true);
        setTimeout(() => {
          monitorCloudEnumScanStatus(
            activeTarget,
            setCloudEnumScans,
            setMostRecentCloudEnumScan,
            setIsCloudEnumScanning,
            setMostRecentCloudEnumScanStatus
          );
        }, 5000);
      } else {
        setIsCloudEnumScanning(false);
      }
    } else {
      setMostRecentCloudEnumScan(null);
      setMostRecentCloudEnumScanStatus(null);
      setIsCloudEnumScanning(false);
    }
  } catch (error) {
    console.error('[CLOUD-ENUM] Error monitoring scan status:', error);
    setIsCloudEnumScanning(false);
    setMostRecentCloudEnumScan(null);
    setMostRecentCloudEnumScanStatus(null);
    setCloudEnumScans([]);
  }
};

export default monitorCloudEnumScanStatus; 