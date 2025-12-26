import { monitorActiveScan } from './monitorFFUFURLScanStatus.js';

export const initiateFFUFURLScan = async (
  activeTarget, 
  setIsFFUFURLScanning, 
  setFFUFURLScans, 
  setMostRecentFFUFURLScan, 
  setMostRecentFFUFURLScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for FFUF URL scan');
    return;
  }

  setIsFFUFURLScanning(true);

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/ffuf-url/run`, 
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          scope_target_id: activeTarget.id,
          url: activeTarget.scope_target 
        }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate FFUF URL scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[FFUF-URL] FFUF URL scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsFFUFURLScanning,
      setFFUFURLScans,
      setMostRecentFFUFURLScan,
      setMostRecentFFUFURLScanStatus,
      activeTarget
    );

  } catch (error) {
    console.error('[FFUF-URL] Error initiating FFUF URL scan:', error);
    setIsFFUFURLScanning(false);
  }
};

export default initiateFFUFURLScan;

