import { monitorActiveScan } from './monitorWAFProbeScanStatus.js';

export const initiateWAFProbeScan = async (
  activeTarget,
  setIsWAFProbeScanning,
  setWAFProbeScans,
  setMostRecentWAFProbeScan,
  setMostRecentWAFProbeScanStatus,
  // Optional inline override. Omitted, the backend uses the target's saved configuration, which is
  // what the plain Scan button does. Passed, it is what the Configure modal just saved.
  configOverride = null
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
          url: activeTarget.scope_target,
          ...(configOverride ? { config: configOverride } : {})
        }),
      }
    );

    if (!response.ok) {
      // The backend refuses a run whose config would not fit its own deadline, and says why.
      // Swallowing that message was v1's habit and it made a refusal look like an outage.
      throw new Error(await response.text() || 'Failed to initiate WAF probe scan');
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
