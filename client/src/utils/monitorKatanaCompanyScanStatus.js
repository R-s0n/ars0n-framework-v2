const monitorKatanaCompanyScanStatus = async (
  activeTarget,
  setKatanaCompanyScans,
  setMostRecentKatanaCompanyScan,
  setIsKatanaCompanyScanning,
  setMostRecentKatanaCompanyScanStatus,
  setKatanaCompanyCloudAssets = null
) => {
  if (!activeTarget) return;

  try {
    console.log('[KATANA-COMPANY] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/katana-company`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch Katana Company scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setKatanaCompanyScans([]);
      setMostRecentKatanaCompanyScan(null);
      setMostRecentKatanaCompanyScanStatus(null);
      setIsKatanaCompanyScanning(false);
      if (setKatanaCompanyCloudAssets) {
        setKatanaCompanyCloudAssets([]);
      }
      return;
    }

    console.log('[KATANA-COMPANY] Retrieved', scans.length, 'scans');
    setKatanaCompanyScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      console.log('[KATANA-COMPANY] Most recent scan status:', mostRecentScan.status);
      setMostRecentKatanaCompanyScan(mostRecentScan);
      setMostRecentKatanaCompanyScanStatus(mostRecentScan.status);

      // Check if the most recent scan is currently running
      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        console.log('[KATANA-COMPANY] Active scan detected, setting scanning state to true');
        setIsKatanaCompanyScanning(true);
      } else {
        setIsKatanaCompanyScanning(false);
        
        // Fetch cloud assets for completed scans
        if (setKatanaCompanyCloudAssets && mostRecentScan.status === 'success') {
          try {
            const assetsResponse = await fetch(
              `/api/katana-company/target/${activeTarget.id}/cloud-assets`
            );
            if (assetsResponse.ok) {
              const assets = await assetsResponse.json();
              setKatanaCompanyCloudAssets(assets || []);
            } else {
              setKatanaCompanyCloudAssets([]);
            }
          } catch (error) {
            console.error('[KATANA-COMPANY] Error fetching cloud assets:', error);
            setKatanaCompanyCloudAssets([]);
          }
        }
      }
    } else {
      setMostRecentKatanaCompanyScan(null);
      setMostRecentKatanaCompanyScanStatus(null);
      setIsKatanaCompanyScanning(false);
      if (setKatanaCompanyCloudAssets) {
        setKatanaCompanyCloudAssets([]);
      }
    }
  } catch (error) {
    console.error('[KATANA-COMPANY] Error monitoring scan status:', error);
    setIsKatanaCompanyScanning(false);
  }
};

// For active scan monitoring during scan execution
export const monitorActiveScan = async (
  scanId, 
  setIsKatanaCompanyScanning, 
  setKatanaCompanyScans, 
  setMostRecentKatanaCompanyScan, 
  setMostRecentKatanaCompanyScanStatus,
  setKatanaCompanyCloudAssets = null,
  activeTarget = null
) => {
  const poll = async () => {
    try {
      const response = await fetch(
        `/api/katana-company/status/${scanId}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch scan status');
      }
      
      const scanStatus = await response.json();
      setMostRecentKatanaCompanyScan(scanStatus);
      setMostRecentKatanaCompanyScanStatus(scanStatus.status);
      
      // Update scans list
      if (setKatanaCompanyScans) {
        setKatanaCompanyScans(prevScans => {
          const updatedScans = prevScans.map(scan => 
            scan.scan_id === scanId ? scanStatus : scan
          );
          
          // If scan not found in list, add it
          if (!updatedScans.find(scan => scan.scan_id === scanId)) {
            updatedScans.unshift(scanStatus);
          }
          
          return updatedScans;
        });
      }
      
      if (scanStatus.status === 'success') {
        setIsKatanaCompanyScanning(false);
        
        // Fetch accumulated cloud assets from the backend API
        if (setKatanaCompanyCloudAssets && activeTarget) {
          try {
            const assetsResponse = await fetch(
              `/api/katana-company/target/${activeTarget.id}/cloud-assets`
            );
            if (assetsResponse.ok) {
              const assets = await assetsResponse.json();
              setKatanaCompanyCloudAssets(assets || []);
            } else {
              console.error('Failed to fetch cloud assets');
              setKatanaCompanyCloudAssets([]);
            }
          } catch (error) {
            console.error('Error fetching cloud assets:', error);
            setKatanaCompanyCloudAssets([]);
          }
        }
        
        // Refresh the complete scan list when scan completes to ensure UI consistency
        if (activeTarget && setKatanaCompanyScans) {
          try {
            const refreshResponse = await fetch(
              `/api/scopetarget/${activeTarget.id}/scans/katana-company`
            );
            if (refreshResponse.ok) {
              const refreshedScans = await refreshResponse.json();
              if (Array.isArray(refreshedScans)) {
                setKatanaCompanyScans(refreshedScans);
                // Update the most recent scan from the refreshed data
                if (refreshedScans.length > 0) {
                  const mostRecentScan = refreshedScans.reduce((latest, scan) => {
                    const scanDate = new Date(scan.created_at);
                    return scanDate > new Date(latest.created_at) ? scan : latest;
                  }, refreshedScans[0]);
                  setMostRecentKatanaCompanyScan(mostRecentScan);
                  setMostRecentKatanaCompanyScanStatus(mostRecentScan.status);
                }
              }
            }
          } catch (error) {
            console.error('Error refreshing scan list:', error);
          }
        }
        
        return scanStatus;
      } else if (scanStatus.status === 'failed' || scanStatus.status === 'error') {
        setIsKatanaCompanyScanning(false);
        console.error('Katana Company scan failed:', scanStatus.error);
        return scanStatus;
      } else if (scanStatus.status === 'pending' || scanStatus.status === 'running') {
        // Continue polling - no timeout limits for long-running scans
        setTimeout(poll, 1000);
      }
    } catch (error) {
      console.error('Error monitoring Katana Company scan:', error);
      // Retry after error - no timeout limits
      setTimeout(poll, 2000);
    }
  };
  
  // Start polling immediately
  poll();
};

export default monitorKatanaCompanyScanStatus; 