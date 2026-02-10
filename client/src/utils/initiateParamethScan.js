export const monitorActiveScan = async (
  scanId,
  setIsParamethScanning,
  setParamethScans,
  setMostRecentParamethScan,
  setMostRecentParamethScanStatus,
  activeTarget
) => {
  try {
    const response = await fetch(`/api/parameth/status/${scanId}`);
    if (!response.ok) {
      throw new Error('Failed to fetch parameth scan status');
    }

    const scanStatus = await response.json();
    console.log('[PARAMETH] Scan status:', scanStatus.status);

    if (scanStatus.status === 'running' || scanStatus.status === 'pending') {
      setTimeout(
        () =>
          monitorActiveScan(
            scanId,
            setIsParamethScanning,
            setParamethScans,
            setMostRecentParamethScan,
            setMostRecentParamethScanStatus,
            activeTarget
          ),
        2000
      );
    } else if (scanStatus.status === 'success' || scanStatus.status === 'error') {
      setIsParamethScanning(false);
      await monitorParamethScanStatus(
        activeTarget,
        setParamethScans,
        setMostRecentParamethScan,
        setIsParamethScanning,
        setMostRecentParamethScanStatus
      );
    }
  } catch (error) {
    console.error('[PARAMETH] Error monitoring active scan:', error);
    setIsParamethScanning(false);
  }
};

const monitorParamethScanStatus = async (
  activeTarget,
  setParamethScans,
  setMostRecentParamethScan,
  setIsParamethScanning,
  setMostRecentParamethScanStatus
) => {
  if (!activeTarget || activeTarget.type !== 'URL') {
    return;
  }

  try {
    const response = await fetch(`/api/scopetarget/${activeTarget.id}/scans/parameth`);
    if (!response.ok) {
      throw new Error('Failed to fetch parameth scans');
    }

    const scans = await response.json();
    setParamethScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentParamethScan(mostRecentScan);
      setMostRecentParamethScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'running' || mostRecentScan.status === 'pending') {
        setIsParamethScanning(true);
        setTimeout(
          () =>
            monitorParamethScanStatus(
              activeTarget,
              setParamethScans,
              setMostRecentParamethScan,
              setIsParamethScanning,
              setMostRecentParamethScanStatus
            ),
          2000
        );
      } else {
        setIsParamethScanning(false);
      }
    } else {
      setIsParamethScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring parameth scan status:', error);
    setIsParamethScanning(false);
  }
};

export const initiateParamethScan = async (
  activeTarget,
  setIsParamethScanning,
  setParamethScans,
  setMostRecentParamethScan,
  setMostRecentParamethScanStatus
) => {
  if (!activeTarget) {
    console.error('No active target provided for parameth scan');
    return;
  }

  setIsParamethScanning(true);

  try {
    const response = await fetch(
      `/api/parameth/run`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope_target_id: activeTarget.id }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate parameth scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('[PARAMETH] parameth scan initiated with ID:', scanId);

    monitorActiveScan(
      scanId,
      setIsParamethScanning,
      setParamethScans,
      setMostRecentParamethScan,
      setMostRecentParamethScanStatus,
      activeTarget
    );

  } catch (error) {
    console.error('[PARAMETH] Error initiating parameth scan:', error);
    setIsParamethScanning(false);
  }
};

export default initiateParamethScan;
