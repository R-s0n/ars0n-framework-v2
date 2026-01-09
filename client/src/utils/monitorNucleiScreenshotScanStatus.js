const monitorNucleiScreenshotScanStatus = async (
  activeTarget,
  setNucleiScreenshotScans,
  setMostRecentNucleiScreenshotScan,
  setIsNucleiScreenshotScanning,
  setMostRecentNucleiScreenshotScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/nuclei-screenshot`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch Nuclei screenshot scans');
    }

    const scans = await response.json();
    setNucleiScreenshotScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentNucleiScreenshotScan(mostRecentScan);
      setMostRecentNucleiScreenshotScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsNucleiScreenshotScanning(true);
        setTimeout(() => {
          monitorNucleiScreenshotScanStatus(
            activeTarget,
            setNucleiScreenshotScans,
            setMostRecentNucleiScreenshotScan,
            setIsNucleiScreenshotScanning,
            setMostRecentNucleiScreenshotScanStatus
          );
        }, 5000);
      } else {
        setIsNucleiScreenshotScanning(false);
      }
    }
  } catch (error) {
    console.error('Error monitoring Nuclei screenshot scan:', error);
    setIsNucleiScreenshotScanning(false);
  }
};

export default monitorNucleiScreenshotScanStatus; 