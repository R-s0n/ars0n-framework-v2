const initiateNucleiScan = async (
  activeTarget,
  monitorNucleiScanStatus,
  setIsNucleiScanning,
  setNucleiScans,
  setMostRecentNucleiScanStatus,
  setMostRecentNucleiScan,
  setActiveNucleiScan
) => {
  if (!activeTarget || !activeTarget.id) {
    console.error('No active target specified for Nuclei scan');
    return;
  }

  setIsNucleiScanning(true);

  try {
    console.log(`Initiating Nuclei scan for ${activeTarget.scope_target}...`);

    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/nuclei/start`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to start Nuclei scan: ${errorText}`);
    }

    const result = await response.json();
    console.log('Nuclei scan initiated:', result);

    if (result.scan_id) {
      // Start monitoring the scan status
      monitorNucleiScanStatus(
        result.scan_id,
        setIsNucleiScanning,
        setNucleiScans,
        setMostRecentNucleiScanStatus,
        setMostRecentNucleiScan,
        activeTarget.id,
        setActiveNucleiScan
      );
    }

  } catch (error) {
    console.error('Error initiating Nuclei scan:', error);
    setIsNucleiScanning(false);
    
    // You might want to show an error message to the user here
    alert(`Failed to start Nuclei scan: ${error.message}`);
  }
};

export default initiateNucleiScan; 