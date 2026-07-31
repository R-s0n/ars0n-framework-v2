import { pollTimeout } from './scanPolling';

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

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsWAFProbeScanning(true);
      } else {
        setIsWAFProbeScanning(false);
      }
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

      if (scanStatus.status === 'success') {
        setIsWAFProbeScanning(false);
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
      } else if (scanStatus.status === 'failed' || scanStatus.status === 'error') {
        setIsWAFProbeScanning(false);
        console.error('WAF probe scan failed:', scanStatus.error);
        return scanStatus;
      } else if (scanStatus.status === 'pending' || scanStatus.status === 'running') {
        pollTimeout(poll, 1000);
      }
    } catch (error) {
      console.error('Error monitoring WAF probe scan:', error);
      pollTimeout(poll, 2000);
    }
  };

  poll();
};

export default monitorWAFProbeScanStatus;
