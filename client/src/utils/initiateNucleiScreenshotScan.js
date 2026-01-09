const initiateNucleiScreenshotScan = async (
  activeTarget,
  monitorNucleiScreenshotScanStatus,
  setIsNucleiScreenshotScanning,
  setNucleiScreenshotScans,
  setMostRecentNucleiScreenshotScanStatus,
  setMostRecentNucleiScreenshotScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  try {
    const body = {};
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/nuclei-screenshot/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to start Nuclei screenshot scan');
    }

    const data = await response.json();
    setIsNucleiScreenshotScanning(true);

    if (monitorNucleiScreenshotScanStatus) {
      monitorNucleiScreenshotScanStatus(
        activeTarget,
        setNucleiScreenshotScans,
        setMostRecentNucleiScreenshotScan,
        setIsNucleiScreenshotScanning,
        setMostRecentNucleiScreenshotScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('Error starting Nuclei screenshot scan:', error);
    setIsNucleiScreenshotScanning(false);
  }
};

export default initiateNucleiScreenshotScan; 