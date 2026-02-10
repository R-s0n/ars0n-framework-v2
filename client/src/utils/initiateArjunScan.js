export const monitorActiveScan = async (
  scanId,
  setIsArjunScanning,
  setArjunScans,
  setMostRecentArjunScan,
  setMostRecentArjunScanStatus,
  activeTarget
) => {
  try {
    const response = await fetch(`/api/arjun/status/${scanId}`);
    if (!response.ok) {
      throw new Error('Failed to fetch Arjun scan status');
    }

    const scanStatus = await response.json();
    console.log('[ARJUN] Scan status:', scanStatus.status);

    if (scanStatus.status === 'running' || scanStatus.status === 'pending') {
      setTimeout(
        () =>
          monitorActiveScan(
            scanId,
            setIsArjunScanning,
            setArjunScans,
            setMostRecentArjunScan,
            setMostRecentArjunScanStatus,
            activeTarget
          ),
        2000
      );
    } else if (scanStatus.status === 'success' || scanStatus.status === 'error') {
      setIsArjunScanning(false);
      await monitorArjunScanStatus(
        activeTarget,
        setArjunScans,
        setMostRecentArjunScan,
        setIsArjunScanning,
        setMostRecentArjunScanStatus
      );
    }
  } catch (error) {
    console.error('[ARJUN] Error monitoring active scan:', error);
    setIsArjunScanning(false);
  }
};

const monitorArjunScanStatus = async (
  activeTarget,
  setArjunScans,
  setMostRecentArjunScan,
  setIsArjunScanning,
  setMostRecentArjunScanStatus
) => {
  if (!activeTarget || activeTarget.type !== 'URL') {
    return;
  }

  try {
    const response = await fetch(`/api/scopetarget/${activeTarget.id}/scans/arjun`);
    if (!response.ok) {
      throw new Error('Failed to fetch Arjun scans');
    }

    const scans = await response.json();
    setArjunScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentArjunScan(mostRecentScan);
      setMostRecentArjunScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'running' || mostRecentScan.status === 'pending') {
        setIsArjunScanning(true);
        setTimeout(
          () =>
            monitorArjunScanStatus(
              activeTarget,
              setArjunScans,
              setMostRecentArjunScan,
              setIsArjunScanning,
              setMostRecentArjunScanStatus
            ),
          2000
        );
      } else {
        setIsArjunScanning(false);
      }
    } else {
      setIsArjunScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring Arjun scan status:', error);
    setIsArjunScanning(false);
  }
};

export const initiateArjunScan = async (
  activeTarget,
  setIsArjunScanning,
  setArjunScans,
  setMostRecentArjunScan,
  setMostRecentArjunScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for Arjun scan');
    return;
  }

  setIsArjunScanning(true);

  try {
    const response = await fetch(
      `/api/arjun/run`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope_target_id: activeTarget.id }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Arjun scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[ARJUN] Arjun scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsArjunScanning,
      setArjunScans,
      setMostRecentArjunScan,
      setMostRecentArjunScanStatus,
      activeTarget
    );

  } catch (error) {
    console.error('[ARJUN] Error initiating Arjun scan:', error);
    setIsArjunScanning(false);
  }
};

export default initiateArjunScan;
