import { monitorActiveScan, monitorProbeRun } from './monitorWAFProbeScanStatus.js';

export const initiateWAFProbeScan = async (
  activeTarget,
  setIsWAFProbeScanning,
  setWAFProbeScans,
  setMostRecentWAFProbeScan,
  setMostRecentWAFProbeScanStatus,
  // Optional inline override. Omitted, the backend uses the target's saved configuration, which is
  // what the plain Scan button does. Passed, it is what the Configure modal just saved.
  configOverride = null,
  // Surfaces a refusal to the operator. Without it the backend's explanation of which budget is
  // short and by how much only reaches the console.
  onError = null
) => {
  if (!activeTarget) {
    console.error('No active target provided for WAF probe scan');
    return;
  }

  setIsWAFProbeScanning(true);

  // A configuration that names endpoints is a multi-endpoint run, even when it names exactly one.
  // Routing single-target runs through the same endpoint keeps one code path for the guards, the
  // per-endpoint labelling and the run view, rather than two that can disagree.
  let targets = (configOverride?.targets || []).filter((t) => t && t.url);

  // The plain Scan button passes no config, but the operator may still have chosen endpoints in the
  // Configure modal earlier. Reading the saved config here means Scan runs what they configured
  // rather than silently probing the scope target root instead.
  if (!configOverride) {
    try {
      const savedRes = await fetch(`/api/waf-probe/config/${activeTarget.id}`);
      if (savedRes.ok) {
        const saved = await savedRes.json();
        targets = (saved?.targets || []).filter((t) => t && t.url);
      }
    } catch {
      // Falling through to a single-endpoint run is the safe default: it probes less, not more.
    }
  }

  const isMulti = targets.length > 0;

  try {
    const response = await fetch(
      isMulti ? `/api/waf-probe/run-multi` : `/api/waf-probe/run`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(isMulti
          ? {
              scope_target_id: activeTarget.id,
              endpoints: targets.map((t) => ({ url: t.url, label: t.label || t.host || '' })),
              ...(configOverride ? { config: configOverride } : {}),
            }
          : {
              scope_target_id: activeTarget.id,
              url: activeTarget.scope_target,
              ...(configOverride ? { config: configOverride } : {}),
            }),
      }
    );

    if (!response.ok) {
      // The backend refuses a run whose config would not fit its own deadline, and says why.
      // Swallowing that message was v1's habit and it made a refusal look like an outage.
      throw new Error(await response.text() || 'Failed to initiate WAF probe scan');
    }

    const result = await response.json();

    if (isMulti) {
      console.log(`[WAF-PROBE] Run ${result.run_id} initiated across `
        + `${result.endpoint_count} endpoints, one at a time, `
        + `about ${result.estimated_seconds_total}s and `
        + `${result.estimated_requests_total} requests in total`);

      monitorProbeRun(
        result.run_id,
        setIsWAFProbeScanning,
        setWAFProbeScans,
        setMostRecentWAFProbeScan,
        setMostRecentWAFProbeScanStatus,
        activeTarget
      );
      return;
    }

    console.log('[WAF-PROBE] WAF probe scan initiated with ID:', result.scan_id);

    monitorActiveScan(
      result.scan_id,
      setIsWAFProbeScanning,
      setWAFProbeScans,
      setMostRecentWAFProbeScan,
      setMostRecentWAFProbeScanStatus,
      activeTarget
    );
  } catch (error) {
    console.error('[WAF-PROBE] Error initiating WAF probe scan:', error);
    setIsWAFProbeScanning(false);
    // The refusal text is the whole value of the guard: it names the knob and the number that
    // would have to change. Losing it to the console only is how a fixable refusal reads as a
    // broken tool.
    if (typeof onError === 'function') onError(error.message);
  }
};

export default initiateWAFProbeScan;
