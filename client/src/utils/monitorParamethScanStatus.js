export { monitorActiveScan } from './initiateParamethScan';

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

export default monitorParamethScanStatus;
