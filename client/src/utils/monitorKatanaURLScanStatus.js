const monitorKatanaURLScanStatus = async (
  activeTarget,
  setKatanaURLScans,
  setMostRecentKatanaURLScan,
  setIsKatanaURLScanning,
  setMostRecentKatanaURLScanStatus
) => {
  if (!activeTarget) return;

  try {
    console.log('[KATANA-URL] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/katana-url`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch Katana URL scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setKatanaURLScans([]);
      setMostRecentKatanaURLScan(null);
      setMostRecentKatanaURLScanStatus(null);
      setIsKatanaURLScanning(false);
      return;
    }

    console.log('[KATANA-URL] Retrieved', scans.length, 'scans');
    setKatanaURLScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      console.log('[KATANA-URL] Most recent scan status:', mostRecentScan.status);
      setMostRecentKatanaURLScan(mostRecentScan);
      setMostRecentKatanaURLScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        console.log('[KATANA-URL] Active scan detected, setting scanning state to true');
        setIsKatanaURLScanning(true);
      } else {
        setIsKatanaURLScanning(false);
      }
    } else {
      setMostRecentKatanaURLScan(null);
      setMostRecentKatanaURLScanStatus(null);
      setIsKatanaURLScanning(false);
    }
  } catch (error) {
    console.error('[KATANA-URL] Error monitoring scan status:', error);
    setIsKatanaURLScanning(false);
  }
};

export const monitorActiveScan = async (
  scanId, 
  setIsKatanaURLScanning, 
  setKatanaURLScans, 
  setMostRecentKatanaURLScan, 
  setMostRecentKatanaURLScanStatus,
  activeTarget = null
) => {
  const poll = async () => {
    try {
      const response = await fetch(
        `/api/katana-url/status/${scanId}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch scan status');
      }
      
      const scanStatus = await response.json();
      setMostRecentKatanaURLScan(scanStatus);
      setMostRecentKatanaURLScanStatus(scanStatus.status);
      
      if (setKatanaURLScans) {
        setKatanaURLScans(prevScans => {
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
        setIsKatanaURLScanning(false);
        
        if (activeTarget && setKatanaURLScans) {
          try {
            const refreshResponse = await fetch(
              `/api/scopetarget/${activeTarget.id}/scans/katana-url`
            );
            if (refreshResponse.ok) {
              const refreshedScans = await refreshResponse.json();
              if (Array.isArray(refreshedScans)) {
                setKatanaURLScans(refreshedScans);
                if (refreshedScans.length > 0) {
                  const mostRecentScan = refreshedScans[0];
                  setMostRecentKatanaURLScan(mostRecentScan);
                  setMostRecentKatanaURLScanStatus(mostRecentScan.status);
                }
              }
            }
          } catch (error) {
            console.error('Error refreshing scan list:', error);
          }
        }
        
        return scanStatus;
      } else if (scanStatus.status === 'failed' || scanStatus.status === 'error') {
        setIsKatanaURLScanning(false);
        console.error('Katana URL scan failed:', scanStatus.error);
        return scanStatus;
      } else if (scanStatus.status === 'pending' || scanStatus.status === 'running') {
        setTimeout(poll, 1000);
      }
    } catch (error) {
      console.error('Error monitoring Katana URL scan:', error);
      setTimeout(poll, 2000);
    }
  };
  
  poll();
};

export default monitorKatanaURLScanStatus;

