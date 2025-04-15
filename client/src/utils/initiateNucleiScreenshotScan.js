const initiateNucleiScreenshotScan = async (activeTarget, monitorNucleiScreenshotScanStatus, setIsNucleiScreenshotScanning, setNucleiScreenshotScans, setMostRecentNucleiScreenshotScanStatus, setMostRecentNucleiScreenshotScan) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/nuclei-screenshot/run`,
      {
        method: 'POST',
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