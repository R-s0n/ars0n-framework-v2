const monitorGAUURLScanStatus = async (
  activeTarget,
  setGAUURLScans,
  setMostRecentGAUURLScan,
  setIsGAUURLScanning,
  setMostRecentGAUURLScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/gau-url`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch GAU URL scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setGAUURLScans([]);
      setMostRecentGAUURLScan(null);
      setMostRecentGAUURLScanStatus(null);
      setIsGAUURLScanning(false);
      return;
    }

    setGAUURLScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentGAUURLScan(mostRecentScan);
      setMostRecentGAUURLScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsGAUURLScanning(true);
      } else {
        setIsGAUURLScanning(false);
      }
    } else {
      setMostRecentGAUURLScan(null);
      setMostRecentGAUURLScanStatus(null);
      setIsGAUURLScanning(false);
    }
  } catch (error) {
    console.error('[GAU-URL] Error monitoring scan status:', error);
    setIsGAUURLScanning(false);
  }
};

export const monitorActiveScan = async (
  scanId, 
  setIsGAUURLScanning, 
  setGAUURLScans, 
  setMostRecentGAUURLScan, 
  setMostRecentGAUURLScanStatus,
  activeTarget = null
) => {
  const poll = async () => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/gau-url/status/${scanId}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch scan status');
      }
      
      const scanStatus = await response.json();
      setMostRecentGAUURLScan(scanStatus);
      setMostRecentGAUURLScanStatus(scanStatus.status);
      
      if (setGAUURLScans) {
        setGAUURLScans(prevScans => {
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
        setIsGAUURLScanning(false);
        return scanStatus;
      } else if (scanStatus.status === 'pending' || scanStatus.status === 'running') {
        setTimeout(poll, 1000);
      }
    } catch (error) {
      console.error('Error monitoring GAU URL scan:', error);
      setTimeout(poll, 2000);
    }
  };
  
  poll();
};

export default monitorGAUURLScanStatus;

