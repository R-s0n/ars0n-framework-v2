import { monitorActiveScan } from './monitorWaybackURLsScanStatus.js';

export const initiateWaybackURLsScan = async (
  activeTarget, 
  setIsWaybackURLsScanning, 
  setWaybackURLsScans, 
  setMostRecentWaybackURLsScan, 
  setMostRecentWaybackURLsScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for WaybackURLs scan');
    return;
  }

  setIsWaybackURLsScanning(true);

  try {
    const response = await fetch(
      `/api/waybackurls/run`, 
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: activeTarget.scope_target }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate WaybackURLs scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[WAYBACKURLS] WaybackURLs scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsWaybackURLsScanning,
      setWaybackURLsScans,
      setMostRecentWaybackURLsScan,
      setMostRecentWaybackURLsScanStatus,
      activeTarget
    );

  } catch (error) {
    console.error('[WAYBACKURLS] Error initiating WaybackURLs scan:', error);
    setIsWaybackURLsScanning(false);
  }
};

export default initiateWaybackURLsScan;

