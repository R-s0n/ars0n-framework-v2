const monitorFFUFURLScanStatus = async (
  activeTarget,
  setFFUFURLScans,
  setMostRecentFFUFURLScan,
  setIsFFUFURLScanning,
  setMostRecentFFUFURLScanStatus
) => {
  if (!activeTarget) return;

  try {
    console.log('[FFUF-URL] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/ffuf-url`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch FFUF URL scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setFFUFURLScans([]);
      setMostRecentFFUFURLScan(null);
      setMostRecentFFUFURLScanStatus(null);
      setIsFFUFURLScanning(false);
      return;
    }

    console.log('[FFUF-URL] Retrieved', scans.length, 'scans');
    setFFUFURLScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      console.log('[FFUF-URL] Most recent scan status:', mostRecentScan.status);
      setMostRecentFFUFURLScan(mostRecentScan);
      setMostRecentFFUFURLScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        console.log('[FFUF-URL] Active scan detected, setting scanning state to true');
        setIsFFUFURLScanning(true);
      } else {
        setIsFFUFURLScanning(false);
      }
    } else {
      setMostRecentFFUFURLScan(null);
      setMostRecentFFUFURLScanStatus(null);
      setIsFFUFURLScanning(false);
    }
  } catch (error) {
    console.error('[FFUF-URL] Error monitoring scan status:', error);
    setIsFFUFURLScanning(false);
  }
};

export const monitorActiveScan = async (
  scanId, 
  setIsFFUFURLScanning, 
  setFFUFURLScans, 
  setMostRecentFFUFURLScan, 
  setMostRecentFFUFURLScanStatus,
  activeTarget = null
) => {
  const poll = async () => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/ffuf-url/status/${scanId}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch scan status');
      }
      
      const scanStatus = await response.json();
      setMostRecentFFUFURLScan(scanStatus);
      setMostRecentFFUFURLScanStatus(scanStatus.status);
      
      if (setFFUFURLScans) {
        setFFUFURLScans(prevScans => {
          const updatedScans = prevScans.map(scan => 
            scan.scan_id === scanId ? scanStatus : scan
          );
          
          if (!updatedScans.find(scan => scan.scan_id === scanId)) {
            updatedScans.unshift(scanStatus);
          }
          
          return updatedScans;
        });
      }
      
      if (scanStatus.status === 'success') {
        setIsFFUFURLScanning(false);
        
        if (activeTarget && setFFUFURLScans) {
          try {
            const refreshResponse = await fetch(
              `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/ffuf-url`
            );
            if (refreshResponse.ok) {
              const refreshedScans = await refreshResponse.json();
              if (Array.isArray(refreshedScans)) {
                setFFUFURLScans(refreshedScans);
                if (refreshedScans.length > 0) {
                  const mostRecentScan = refreshedScans[0];
                  setMostRecentFFUFURLScan(mostRecentScan);
                  setMostRecentFFUFURLScanStatus(mostRecentScan.status);
                }
              }
            }
          } catch (error) {
            console.error('Error refreshing scan list:', error);
          }
        }
        
        return scanStatus;
      } else if (scanStatus.status === 'failed' || scanStatus.status === 'error') {
        setIsFFUFURLScanning(false);
        console.error('FFUF URL scan failed:', scanStatus.error);
        return scanStatus;
      } else if (scanStatus.status === 'pending' || scanStatus.status === 'running') {
        setTimeout(poll, 1000);
      }
    } catch (error) {
      console.error('Error monitoring FFUF URL scan:', error);
      setTimeout(poll, 2000);
    }
  };
  
  poll();
};

export default monitorFFUFURLScanStatus;

