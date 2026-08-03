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

    const scans = await response.json();
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

export default monitorWAFProbeScanStatus;
