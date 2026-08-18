import { pollTimeout } from './scanPolling';
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

    const scansPayload = await response.json();
    // A Go handler that returns a nil slice encodes it as JSON null rather than [],
    // and reading .length off null threw a TypeError that killed this poll loop.
    const scans = Array.isArray(scansPayload) ? scansPayload : [];
    setNucleiScreenshotScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentNucleiScreenshotScan(mostRecentScan);
      setMostRecentNucleiScreenshotScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsNucleiScreenshotScanning(true);
        pollTimeout(() => {
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