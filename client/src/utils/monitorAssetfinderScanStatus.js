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

    const scans = await response.json();
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
        setTimeout(() => {
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