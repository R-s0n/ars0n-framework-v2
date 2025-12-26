import { monitorActiveScan } from './monitorGAUURLScanStatus.js';

export const initiateGAUURLScan = async (
  activeTarget, 
  setIsGAUURLScanning, 
  setGAUURLScans, 
  setMostRecentGAUURLScan, 
  setMostRecentGAUURLScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for GAU URL scan');
    return;
  }

  setIsGAUURLScanning(true);

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/gau-url/run`, 
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: activeTarget.scope_target }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate GAU URL scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[GAU-URL] GAU URL scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsGAUURLScanning,
      setGAUURLScans,
      setMostRecentGAUURLScan,
      setMostRecentGAUURLScanStatus,
      activeTarget
    );

  } catch (error) {
    console.error('[GAU-URL] Error initiating GAU URL scan:', error);
    setIsGAUURLScanning(false);
  }
};

export default initiateGAUURLScan;

