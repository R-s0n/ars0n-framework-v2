import { pollTimeout } from './scanPolling';
const monitorGauScanStatus = async (
  activeTarget,
  setGauScans,
  setMostRecentGauScan,
  setIsGauScanning,
  setMostRecentGauScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/gau`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch GAU scans');
    }

    const scansPayload = await response.json();
    // A Go handler that returns a nil slice encodes it as JSON null rather than [],
    // and reading .length off null threw a TypeError that killed this poll loop.
    const scans = Array.isArray(scansPayload) ? scansPayload : [];
    setGauScans(scans || []);

    if (Array.isArray(scans) && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentGauScan(mostRecentScan);
      setMostRecentGauScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'processing') {
        setIsGauScanning(true);
        pollTimeout(() => {
          monitorGauScanStatus(
            activeTarget,
            setGauScans,
            setMostRecentGauScan,
            setIsGauScanning,
            setMostRecentGauScanStatus
          );
        }, 5000);
      } else {
        setIsGauScanning(false);
      }
    } else {
      setMostRecentGauScan(null);
      setMostRecentGauScanStatus(null);
      setIsGauScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring GAU scan status:', error);
    setIsGauScanning(false);
    setMostRecentGauScan(null);
    setMostRecentGauScanStatus(null);
  }
};

export default monitorGauScanStatus; 