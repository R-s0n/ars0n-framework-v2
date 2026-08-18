import { pollTimeout } from './scanPolling';
const monitorAssetfinderScanStatus = async (
  activeTarget,
  setAssetfinderScans,
  setMostRecentAssetfinderScan,
  setIsAssetfinderScanning,
  setMostRecentAssetfinderScanStatus
) => {
  if (!activeTarget || !activeTarget.id) {
    setIsAssetfinderScanning(false);
    setMostRecentAssetfinderScan(null);
    setMostRecentAssetfinderScanStatus(null);
    return;
  }

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/assetfinder`
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch Assetfinder scans: ${response.statusText}`);
    }

    const scansPayload = await response.json();
    // A Go handler that returns a nil slice encodes it as JSON null rather than [],
    // and reading .length off null threw a TypeError that killed this poll loop.
    const scans = Array.isArray(scansPayload) ? scansPayload : [];
    setAssetfinderScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentAssetfinderScan(mostRecentScan);
      setMostRecentAssetfinderScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsAssetfinderScanning(true);
        pollTimeout(() => {
          monitorAssetfinderScanStatus(
            activeTarget,
            setAssetfinderScans,
            setMostRecentAssetfinderScan,
            setIsAssetfinderScanning,
            setMostRecentAssetfinderScanStatus
          );
        }, 5000);
      } else {
        setIsAssetfinderScanning(false);
      }
    } else {
      setMostRecentAssetfinderScan(null);
      setMostRecentAssetfinderScanStatus(null);
      setIsAssetfinderScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring Assetfinder scan status:', error);
    setIsAssetfinderScanning(false);
    setMostRecentAssetfinderScan(null);
    setMostRecentAssetfinderScanStatus(null);
  }
};

export default monitorAssetfinderScanStatus; 