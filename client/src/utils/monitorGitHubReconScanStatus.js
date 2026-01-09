const monitorGitHubReconScanStatus = async (
  activeTarget,
  setGitHubReconScans,
  setMostRecentGitHubReconScan,
  setIsGitHubReconScanning,
  setMostRecentGitHubReconScanStatus
) => {
  if (!activeTarget) return;

  try {
    console.log('[GITHUB-RECON] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/github-recon`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch GitHub Recon scans');
    }

    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setGitHubReconScans([]);
      setMostRecentGitHubReconScan(null);
      setMostRecentGitHubReconScanStatus(null);
      setIsGitHubReconScanning(false);
      return;
    }

    console.log('[GITHUB-RECON] Retrieved', scans.length, 'scans');
    setGitHubReconScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      console.log('[GITHUB-RECON] Most recent scan status:', mostRecentScan.status);
      setMostRecentGitHubReconScan(mostRecentScan);
      setMostRecentGitHubReconScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsGitHubReconScanning(true);
        setTimeout(() => {
          monitorGitHubReconScanStatus(
            activeTarget,
            setGitHubReconScans,
            setMostRecentGitHubReconScan,
            setIsGitHubReconScanning,
            setMostRecentGitHubReconScanStatus
          );
        }, 5000);
      } else {
        setIsGitHubReconScanning(false);
      }
    } else {
      setMostRecentGitHubReconScan(null);
      setMostRecentGitHubReconScanStatus(null);
      setIsGitHubReconScanning(false);
    }
  } catch (error) {
    console.error('[GITHUB-RECON] Error monitoring scan status:', error);
    setIsGitHubReconScanning(false);
    setMostRecentGitHubReconScan(null);
    setMostRecentGitHubReconScanStatus(null);
    setGitHubReconScans([]);
  }
};

export default monitorGitHubReconScanStatus; 