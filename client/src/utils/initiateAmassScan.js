export const initiateAmassScan = async (activeTarget, monitorScanStatus, setIsScanning, setAmassScans, setMostRecentAmassScanStatus, setDnsRecords, setSubdomains, setCloudDomains, setMostRecentAmassScan, autoScanSessionId) => {
    if (!activeTarget) return;
    let fqdn = activeTarget.scope_target;
    if (activeTarget.type === 'Wildcard') {
      fqdn = fqdn.replace(/^\*\./, '');
    }
  
    try {
      const body = { fqdn };
      if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
      const response = await fetch(`/api/amass/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
  
      if (!response.ok) {
        throw new Error('Failed to initiate Amass scan');
      }
  
      setIsScanning(true);
      monitorScanStatus && monitorScanStatus(activeTarget, setAmassScans, setMostRecentAmassScan, setIsScanning, setMostRecentAmassScanStatus, setDnsRecords, setSubdomains, setCloudDomains);
    } catch (error) {
      console.error('Error initiating Amass scan:', error);
    }
  };

  export default initiateAmassScan