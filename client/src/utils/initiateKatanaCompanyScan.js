import { monitorActiveScan } from './monitorKatanaCompanyScanStatus.js';

export const initiateKatanaCompanyScan = async (
  activeTarget, 
  domains, 
  setIsKatanaCompanyScanning, 
  setKatanaCompanyScans, 
  setMostRecentKatanaCompanyScan, 
  setMostRecentKatanaCompanyScanStatus, 
  setKatanaCompanyCloudAssets = null
) => {
  if (!activeTarget || !domains || domains.length === 0) {
    console.error('No active target or domains provided for Katana Company scan');
    return;
  }

  // Set scanning state immediately
  setIsKatanaCompanyScanning(true);

  try {
    const response = await fetch(
      `/api/katana-company/run/${activeTarget.id}`, 
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Katana Company scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[KATANA-COMPANY] Katana Company scan initiated with ID:', scanId);

    // Start monitoring the scan status
    monitorActiveScan(
      scanId,
      setIsKatanaCompanyScanning,
      setKatanaCompanyScans,
      setMostRecentKatanaCompanyScan,
      setMostRecentKatanaCompanyScanStatus,
      setKatanaCompanyCloudAssets,
      activeTarget
    );

  } catch (error) {
    console.error('[KATANA-COMPANY] Error initiating Katana Company scan:', error);
    setIsKatanaCompanyScanning(false);
  }
}; 