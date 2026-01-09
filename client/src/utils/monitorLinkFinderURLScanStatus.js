const monitorLinkFinderURLScanStatus = async (
  activeTarget,
  setLinkFinderURLScans,
  setMostRecentLinkFinderURLScan,
  setIsLinkFinderURLScanning,
  setMostRecentLinkFinderURLScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/linkfinder-url`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch LinkFinder URL scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setLinkFinderURLScans([]);
      setMostRecentLinkFinderURLScan(null);
      setMostRecentLinkFinderURLScanStatus(null);
      setIsLinkFinderURLScanning(false);
      return;
    }

    setLinkFinderURLScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentLinkFinderURLScan(mostRecentScan);
      setMostRecentLinkFinderURLScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsLinkFinderURLScanning(true);
      } else {
        setIsLinkFinderURLScanning(false);
      }
    } else {
      setMostRecentLinkFinderURLScan(null);
      setMostRecentLinkFinderURLScanStatus(null);
      setIsLinkFinderURLScanning(false);
    }
  } catch (error) {
    console.error('[LINKFINDER-URL] Error monitoring scan status:', error);
    setIsLinkFinderURLScanning(false);
  }
};

export const monitorActiveScan = async (
  scanId, 
  setIsLinkFinderURLScanning, 
  setLinkFinderURLScans, 
  setMostRecentLinkFinderURLScan, 
  setMostRecentLinkFinderURLScanStatus,
  activeTarget = null
) => {
  const poll = async () => {
    try {
      const response = await fetch(
        `/api/linkfinder-url/status/${scanId}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch scan status');
      }
      
      const scanStatus = await response.json();
      setMostRecentLinkFinderURLScan(scanStatus);
      setMostRecentLinkFinderURLScanStatus(scanStatus.status);
      
      if (setLinkFinderURLScans) {
        setLinkFinderURLScans(prevScans => {
          const updatedScans = prevScans.map(scan => 
            scan.scan_id === scanId ? scanStatus : scan
          );
          
          if (!updatedScans.find(scan => scan.scan_id === scanId)) {
            updatedScans.unshift(scanStatus);
          }
          
          return updatedScans;
        });
      }
      
      if (scanStatus.status === 'success' || scanStatus.status === 'failed' || scanStatus.status === 'error') {
        setIsLinkFinderURLScanning(false);
        return scanStatus;
      } else if (scanStatus.status === 'pending' || scanStatus.status === 'running') {
        setTimeout(poll, 1000);
      }
    } catch (error) {
      console.error('Error monitoring LinkFinder URL scan:', error);
      setTimeout(poll, 2000);
    }
  };
  
  poll();
};

export default monitorLinkFinderURLScanStatus;

