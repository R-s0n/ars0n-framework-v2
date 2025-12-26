import { monitorActiveScan } from './monitorKatanaURLScanStatus.js';

export const initiateKatanaURLScan = async (
  activeTarget, 
  setIsKatanaURLScanning, 
  setKatanaURLScans, 
  setMostRecentKatanaURLScan, 
  setMostRecentKatanaURLScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for Katana URL scan');
    return;
  }

  setIsKatanaURLScanning(true);

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/katana-url/run`, 
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: activeTarget.scope_target }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Katana URL scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[KATANA-URL] Katana URL scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsKatanaURLScanning,
      setKatanaURLScans,
      setMostRecentKatanaURLScan,
      setMostRecentKatanaURLScanStatus,
      activeTarget
    );

  } catch (error) {
    console.error('[KATANA-URL] Error initiating Katana URL scan:', error);
    setIsKatanaURLScanning(false);
  }
};

export default initiateKatanaURLScan;

