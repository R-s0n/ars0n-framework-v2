export const monitorActiveScan = async (
  scanId,
  setIsX8Scanning,
  setX8Scans,
  setMostRecentX8Scan,
  setMostRecentX8ScanStatus,
  activeTarget
) => {
  try {
    const response = await fetch(`/api/x8/status/${scanId}`);
    if (!response.ok) {
      throw new Error('Failed to fetch x8 scan status');
    }

    const scanStatus = await response.json();
    console.log('[X8] Scan status:', scanStatus.status);

    if (scanStatus.status === 'running' || scanStatus.status === 'pending') {
      setTimeout(
        () =>
          monitorActiveScan(
            scanId,
            setIsX8Scanning,
            setX8Scans,
            setMostRecentX8Scan,
            setMostRecentX8ScanStatus,
            activeTarget
          ),
        2000
      );
    } else if (scanStatus.status === 'success' || scanStatus.status === 'error') {
      setIsX8Scanning(false);
      await monitorX8ScanStatus(
        activeTarget,
        setX8Scans,
        setMostRecentX8Scan,
        setIsX8Scanning,
        setMostRecentX8ScanStatus
      );
    }
  } catch (error) {
    console.error('[X8] Error monitoring active scan:', error);
    setIsX8Scanning(false);
  }
};

const monitorX8ScanStatus = async (
  activeTarget,
  setX8Scans,
  setMostRecentX8Scan,
  setIsX8Scanning,
  setMostRecentX8ScanStatus
) => {
  if (!activeTarget || activeTarget.type !== 'URL') {
    return;
  }

  try {
    const response = await fetch(`/api/scopetarget/${activeTarget.id}/scans/x8`);
    if (!response.ok) {
      throw new Error('Failed to fetch x8 scans');
    }

    const scans = await response.json();
    setX8Scans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentX8Scan(mostRecentScan);
      setMostRecentX8ScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'running' || mostRecentScan.status === 'pending') {
        setIsX8Scanning(true);
        setTimeout(
          () =>
            monitorX8ScanStatus(
              activeTarget,
              setX8Scans,
              setMostRecentX8Scan,
              setIsX8Scanning,
              setMostRecentX8ScanStatus
            ),
          2000
        );
      } else {
        setIsX8Scanning(false);
      }
    } else {
      setIsX8Scanning(false);
    }
  } catch (error) {
    console.error('Error monitoring x8 scan status:', error);
    setIsX8Scanning(false);
  }
};

export const initiateX8Scan = async (
  activeTarget,
  setIsX8Scanning,
  setX8Scans,
  setMostRecentX8Scan,
  setMostRecentX8ScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for x8 scan');
    return;
  }

  setIsX8Scanning(true);

  try {
    const response = await fetch(
      `/api/x8/run`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope_target_id: activeTarget.id }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate x8 scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[X8] x8 scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsX8Scanning,
      setX8Scans,
      setMostRecentX8Scan,
      setMostRecentX8ScanStatus,
      activeTarget
    );

  } catch (error) {
    console.error('[X8] Error initiating x8 scan:', error);
    setIsX8Scanning(false);
  }
};

export default initiateX8Scan;
