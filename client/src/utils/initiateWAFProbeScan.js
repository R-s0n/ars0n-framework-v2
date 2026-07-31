import { monitorActiveScan } from './monitorWAFProbeScanStatus.js';

export const initiateWAFProbeScan = async (
  activeTarget,
  setIsWAFProbeScanning,
  setWAFProbeScans,
  setMostRecentWAFProbeScan,
  setMostRecentWAFProbeScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for WAF probe scan');
    return;
  }

  setIsWAFProbeScanning(true);

  try {
    const response = await fetch(
      `/api/waf-probe/run`,
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
      throw new Error('Failed to initiate WAF probe scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[WAF-PROBE] WAF probe scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsWAFProbeScanning,
      setWAFProbeScans,
      setMostRecentWAFProbeScan,
      setMostRecentWAFProbeScanStatus,
      activeTarget
    );
  } catch (error) {
    console.error('[WAF-PROBE] Error initiating WAF probe scan:', error);
    setIsWAFProbeScanning(false);
  }
};

export default initiateWAFProbeScan;
