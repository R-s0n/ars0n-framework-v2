const monitorWaybackURLsScanStatus = async (
  activeTarget,
  setWaybackURLsScans,
  setMostRecentWaybackURLsScan,
  setIsWaybackURLsScanning,
  setMostRecentWaybackURLsScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/waybackurls`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch WaybackURLs scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setWaybackURLsScans([]);
      setMostRecentWaybackURLsScan(null);
      setMostRecentWaybackURLsScanStatus(null);
      setIsWaybackURLsScanning(false);
      return;
    }

    setWaybackURLsScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentWaybackURLsScan(mostRecentScan);
      setMostRecentWaybackURLsScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsWaybackURLsScanning(true);
      } else {
        setIsWaybackURLsScanning(false);
      }
    } else {
      setMostRecentWaybackURLsScan(null);
      setMostRecentWaybackURLsScanStatus(null);
      setIsWaybackURLsScanning(false);
    }
  } catch (error) {
    console.error('[WAYBACKURLS] Error monitoring scan status:', error);
    setIsWaybackURLsScanning(false);
  }
};

export const monitorActiveScan = async (
  scanId, 
  setIsWaybackURLsScanning, 
  setWaybackURLsScans, 
  setMostRecentWaybackURLsScan, 
  setMostRecentWaybackURLsScanStatus,
  activeTarget = null
) => {
  const poll = async () => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/waybackurls/status/${scanId}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch scan status');
      }
      
      const scanStatus = await response.json();
      setMostRecentWaybackURLsScan(scanStatus);
      setMostRecentWaybackURLsScanStatus(scanStatus.status);
      
      if (setWaybackURLsScans) {
        setWaybackURLsScans(prevScans => {
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
        setIsWaybackURLsScanning(false);
        return scanStatus;
      } else if (scanStatus.status === 'pending' || scanStatus.status === 'running') {
        setTimeout(poll, 1000);
      }
    } catch (error) {
      console.error('Error monitoring WaybackURLs scan:', error);
      setTimeout(poll, 2000);
    }
  };
  
  poll();
};

export default monitorWaybackURLsScanStatus;

