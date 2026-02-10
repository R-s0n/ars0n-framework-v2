import { monitorActiveScan } from './monitorGoSpiderURLScanStatus.js';

export const initiateGoSpiderURLScan = async (
  activeTarget, 
  setIsGoSpiderURLScanning, 
  setGoSpiderURLScans, 
  setMostRecentGoSpiderURLScan, 
  setMostRecentGoSpiderURLScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for GoSpider URL scan');
    return;
  }

  setIsGoSpiderURLScanning(true);

  try {
    const response = await fetch(
      `/api/gospider-url/run`, 
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: activeTarget.scope_target }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate GoSpider URL scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[GOSPIDER-URL] GoSpider URL scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsGoSpiderURLScanning,
      setGoSpiderURLScans,
      setMostRecentGoSpiderURLScan,
      setMostRecentGoSpiderURLScanStatus,
      activeTarget
    );

  } catch (error) {
    console.error('[GOSPIDER-URL] Error initiating GoSpider URL scan:', error);
    setIsGoSpiderURLScanning(false);
  }
};

export default initiateGoSpiderURLScan;
