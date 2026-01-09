const initiateGitHubReconScan = async (
  activeTarget,
  monitorGitHubReconScanStatus,
  setIsGitHubReconScanning,
  setGitHubReconScans,
  setMostRecentGitHubReconScanStatus,
  setMostRecentGitHubReconScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  const companyName = activeTarget.scope_target;

  try {
    console.log('[GITHUB-RECON] Initiating GitHub Recon scan for:', companyName);
    
    const body = { company_name: companyName };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    
    const response = await fetch(
      `/api/github-recon/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate GitHub Recon scan');
    }

    const data = await response.json();
    console.log('[GITHUB-RECON] Scan initiated with ID:', data.scan_id);
    setIsGitHubReconScanning(true);

    if (monitorGitHubReconScanStatus) {
      monitorGitHubReconScanStatus(
        activeTarget,
        setGitHubReconScans,
        setMostRecentGitHubReconScan,
        setIsGitHubReconScanning,
        setMostRecentGitHubReconScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('[GITHUB-RECON] Error initiating GitHub Recon scan:', error);
    setIsGitHubReconScanning(false);
  }
};

export default initiateGitHubReconScan; 