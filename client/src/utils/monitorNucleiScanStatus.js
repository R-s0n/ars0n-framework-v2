const monitorNucleiScanStatus = async (
  scanId,
  setIsNucleiScanning,
  setNucleiScans,
  setMostRecentNucleiScanStatus,
  setMostRecentNucleiScan,
  scopeTargetId,
  setActiveNucleiScan
) => {
  const checkStatus = async () => {
    try {
      const response = await fetch(
        `/api/nuclei-scan/${scanId}/status`
      );

      if (!response.ok) {
        throw new Error(`Failed to get scan status: ${response.statusText}`);
      }

      const scanData = await response.json();
      console.log(`Nuclei scan ${scanId} status: ${scanData.status}`);

      // Update scan status
      setMostRecentNucleiScanStatus(scanData.status);

      if (scanData.status === 'success' || scanData.status === 'failed') {
        // Scan is complete
        setIsNucleiScanning(false);
        setMostRecentNucleiScan(scanData);
        
        // Set the completed scan as the active scan (for successful scans)
        if (scanData.status === 'success' && setActiveNucleiScan) {
          setActiveNucleiScan(scanData);
        }
        
        // Refresh the scans list
        await refreshNucleiScans(scopeTargetId, setNucleiScans);
        
        console.log(`Nuclei scan ${scanId} completed with status: ${scanData.status}`);
        
        if (scanData.status === 'failed' && scanData.error) {
          console.error(`Nuclei scan failed: ${scanData.error}`);
        }
        
        return; // Stop monitoring
      }

      // Continue monitoring if scan is still running
      // Check again after 3 seconds (increased from 1 second to reduce server load)
      setTimeout(checkStatus, 3000);

    } catch (error) {
      console.error('Error monitoring Nuclei scan status:', error);
      
      // Retry after 5 seconds on error (increased from 2 seconds)
      setTimeout(checkStatus, 5000);
    }
  };

  // Start monitoring
  checkStatus();
};

// Helper function to refresh the scans list
const refreshNucleiScans = async (scopeTargetId, setNucleiScans) => {
  try {
    const response = await fetch(
      `/api/scopetarget/${scopeTargetId}/scans/nuclei`
    );

    if (response.ok) {
      const scans = await response.json();
      if (Array.isArray(scans)) {
        setNucleiScans(scans);
      }
    }
  } catch (error) {
    console.error('Error refreshing Nuclei scans:', error);
  }
};

export default monitorNucleiScanStatus; 