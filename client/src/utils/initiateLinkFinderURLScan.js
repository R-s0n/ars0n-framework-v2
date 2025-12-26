import { monitorActiveScan } from './monitorLinkFinderURLScanStatus.js';

export const initiateLinkFinderURLScan = async (
  activeTarget, 
  setIsLinkFinderURLScanning, 
  setLinkFinderURLScans, 
  setMostRecentLinkFinderURLScan, 
  setMostRecentLinkFinderURLScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for LinkFinder URL scan');
    return;
  }

  setIsLinkFinderURLScanning(true);

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/linkfinder-url/run`, 
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: activeTarget.scope_target }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate LinkFinder URL scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[LINKFINDER-URL] LinkFinder URL scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsLinkFinderURLScanning,
      setLinkFinderURLScans,
      setMostRecentLinkFinderURLScan,
      setMostRecentLinkFinderURLScanStatus,
      activeTarget
    );

  } catch (error) {
    console.error('[LINKFINDER-URL] Error initiating LinkFinder URL scan:', error);
    setIsLinkFinderURLScanning(false);
  }
};

export default initiateLinkFinderURLScan;

