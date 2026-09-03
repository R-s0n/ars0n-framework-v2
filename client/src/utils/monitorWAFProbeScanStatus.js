import { pollTimeout } from './scanPolling';

// The probe has four terminal states, not two. `partial` and `aborted` both carry a real result
// (the probe checkpoints after every phase and flushes on SIGTERM), so treating them as failures
// would throw away findings the operator already paid for in requests.
const TERMINAL = ['success', 'partial', 'aborted', 'error'];
const RUNNING = ['pending', 'running'];

export const isTerminalProbeStatus = (status) => TERMINAL.includes(status);
export const isRunningProbeStatus = (status) => RUNNING.includes(status);

const monitorWAFProbeScanStatus = async (
  activeTarget,
  setWAFProbeScans,
  setMostRecentWAFProbeScan,
  setIsWAFProbeScanning,
  setMostRecentWAFProbeScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/waf-probe`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch WAF probe scans');
    }

    const scansPayload = await response.json();
    // A Go handler that returns a nil slice encodes it as JSON null rather than [],
    // and reading .length off null threw a TypeError that killed this poll loop.
    const scans = Array.isArray(scansPayload) ? scansPayload : [];
    if (!Array.isArray(scans)) {
      setWAFProbeScans([]);
      setMostRecentWAFProbeScan(null);
      setMostRecentWAFProbeScanStatus(null);
      setIsWAFProbeScanning(false);
      return;
    }

    setWAFProbeScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentWAFProbeScan(mostRecentScan);
      setMostRecentWAFProbeScanStatus(mostRecentScan.status);

      setIsWAFProbeScanning(isRunningProbeStatus(mostRecentScan.status));
    } else {
      setMostRecentWAFProbeScan(null);
      setMostRecentWAFProbeScanStatus(null);
      setIsWAFProbeScanning(false);
    }
  } catch (error) {
    console.error('[WAF-PROBE] Error monitoring scan status:', error);
    setIsWAFProbeScanning(false);
  }
};

export const monitorActiveScan = async (
  scanId,
  setIsWAFProbeScanning,
  setWAFProbeScans,
  setMostRecentWAFProbeScan,
  setMostRecentWAFProbeScanStatus,
  activeTarget = null
) => {
  const poll = async () => {
    try {
      const response = await fetch(
        `/api/waf-probe/status/${scanId}`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch scan status');
      }

      const scanStatus = await response.json();
      setMostRecentWAFProbeScan(scanStatus);
      setMostRecentWAFProbeScanStatus(scanStatus.status);

      if (setWAFProbeScans) {
        setWAFProbeScans(prevScans => {
          const updatedScans = prevScans.map(scan =>
            scan.scan_id === scanId ? scanStatus : scan
          );
          if (!updatedScans.find(scan => scan.scan_id === scanId)) {
            updatedScans.unshift(scanStatus);
          }
          return updatedScans;
        });
      }

      if (isTerminalProbeStatus(scanStatus.status)) {
        setIsWAFProbeScanning(false);
        if (scanStatus.status === 'error') {
          console.error('[WAF-PROBE] Probe run failed:', scanStatus.error);
        }
        if (activeTarget && setWAFProbeScans) {
          try {
            const refreshResponse = await fetch(
              `/api/scopetarget/${activeTarget.id}/scans/waf-probe`
            );
            if (refreshResponse.ok) {
              const refreshedScans = await refreshResponse.json();
              if (Array.isArray(refreshedScans)) {
                setWAFProbeScans(refreshedScans);
                if (refreshedScans.length > 0) {
                  const mostRecentScan = refreshedScans[0];
                  setMostRecentWAFProbeScan(mostRecentScan);
                  setMostRecentWAFProbeScanStatus(mostRecentScan.status);
                }
              }
            }
          } catch (error) {
            console.error('Error refreshing WAF probe scan list:', error);
          }
        }
        return scanStatus;
      } else if (isRunningProbeStatus(scanStatus.status)) {
        pollTimeout(poll, 1000);
      } else {
        // An unrecognised status is not a reason to poll forever against a scan that will never
        // change; v1 did exactly that and left the card spinning until a reload.
        console.warn('[WAF-PROBE] Unrecognised scan status, stopping poll:', scanStatus.status);
        setIsWAFProbeScanning(false);
      }
    } catch (error) {
      console.error('Error monitoring WAF probe scan:', error);
      pollTimeout(poll, 2000);
    }
  };

  poll();
};

// A multi-endpoint run is N scans worked through one at a time, so no single scan's status answers
// "is the run finished". Polling the run instead does, and it lets the card show the most recent
// finished endpoint while the remaining ones are still being probed, rather than pinning the card to
// a scan that stays `pending` for most of the run and displays nothing.
export const monitorProbeRun = async (
  runId,
  setIsWAFProbeScanning,
  setWAFProbeScans,
  setMostRecentWAFProbeScan,
  setMostRecentWAFProbeScanStatus,
  activeTarget = null
) => {
  const refreshList = async () => {
    if (!activeTarget || !setWAFProbeScans) return;
    try {
      const res = await fetch(`/api/scopetarget/${activeTarget.id}/scans/waf-probe`);
      if (!res.ok) return;
      const scans = await res.json();
      if (Array.isArray(scans)) setWAFProbeScans(scans);
    } catch (error) {
      console.error('Error refreshing WAF probe scan list:', error);
    }
  };

  const poll = async () => {
    try {
      const res = await fetch(`/api/waf-probe/run/${runId}/results`);
      if (!res.ok) throw new Error('Failed to fetch run status');

      const run = await res.json();
      const endpoints = Array.isArray(run.endpoints) ? run.endpoints : [];

      // The last endpoint that actually produced something. Endpoints run in order, so this walks
      // forward as the run progresses and the card always shows the newest real result.
      const finished = endpoints.filter((e) => isTerminalProbeStatus(e.status) && e.result);
      if (finished.length > 0) {
        const latest = finished[finished.length - 1];
        setMostRecentWAFProbeScan(latest);
        setMostRecentWAFProbeScanStatus(latest.status);
      }

      await refreshList();

      if (run.in_progress) {
        setIsWAFProbeScanning(true);
        pollTimeout(poll, 3000);
        return;
      }

      setIsWAFProbeScanning(false);
      console.log(`[WAF-PROBE] Run ${runId} finished: `
        + `${run.completed_count}/${run.endpoint_count} endpoints, `
        + `${run.total_requests_sent || 0} requests`);
      return run;
    } catch (error) {
      console.error('Error monitoring WAF probe run:', error);
      pollTimeout(poll, 3000);
    }
  };

  poll();
};

export default monitorWAFProbeScanStatus;
