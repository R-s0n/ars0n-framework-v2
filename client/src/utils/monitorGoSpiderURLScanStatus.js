export const monitorActiveScan = async (
  scanId,
  setIsGoSpiderURLScanning,
  setGoSpiderURLScans,
  setMostRecentGoSpiderURLScan,
  setMostRecentGoSpiderURLScanStatus,
  activeTarget
) => {
  try {
    const response = await fetch(`/api/gospider-url/status/${scanId}`);
    if (!response.ok) {
      throw new Error('Failed to fetch GoSpider URL scan status');
    }

    const scanStatus = await response.json();
    console.log('[GOSPIDER-URL] Scan status:', scanStatus.status);

    if (scanStatus.status === 'running' || scanStatus.status === 'pending') {
      setTimeout(
        () =>
          monitorActiveScan(
            scanId,
            setIsGoSpiderURLScanning,
            setGoSpiderURLScans,
            setMostRecentGoSpiderURLScan,
            setMostRecentGoSpiderURLScanStatus,
            activeTarget
          ),
        2000
      );
    } else if (scanStatus.status === 'success' || scanStatus.status === 'error') {
      setIsGoSpiderURLScanning(false);
      await monitorGoSpiderURLScanStatus(
        activeTarget,
        setGoSpiderURLScans,
        setMostRecentGoSpiderURLScan,
        setIsGoSpiderURLScanning,
        setMostRecentGoSpiderURLScanStatus
      );
    }
  } catch (error) {
    console.error('[GOSPIDER-URL] Error monitoring active scan:', error);
    setIsGoSpiderURLScanning(false);
  }
};

const monitorGoSpiderURLScanStatus = async (
  activeTarget,
  setGoSpiderURLScans,
  setMostRecentGoSpiderURLScan,
  setIsGoSpiderURLScanning,
  setMostRecentGoSpiderURLScanStatus
) => {
  if (!activeTarget || activeTarget.type !== 'URL') {
    return;
  }

  try {
    const response = await fetch(`/api/scopetarget/${activeTarget.id}/scans/gospider-url`);
    if (!response.ok) {
      throw new Error('Failed to fetch GoSpider URL scans');
    }

    const scans = await response.json();
    setGoSpiderURLScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentGoSpiderURLScan(mostRecentScan);
      setMostRecentGoSpiderURLScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'running' || mostRecentScan.status === 'pending') {
        setIsGoSpiderURLScanning(true);
        setTimeout(
          () =>
            monitorGoSpiderURLScanStatus(
              activeTarget,
              setGoSpiderURLScans,
              setMostRecentGoSpiderURLScan,
              setIsGoSpiderURLScanning,
              setMostRecentGoSpiderURLScanStatus
            ),
          2000
        );
      } else {
        setIsGoSpiderURLScanning(false);
      }
    } else {
      setIsGoSpiderURLScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring GoSpider URL scan status:', error);
    setIsGoSpiderURLScanning(false);
  }
};

export default monitorGoSpiderURLScanStatus;
