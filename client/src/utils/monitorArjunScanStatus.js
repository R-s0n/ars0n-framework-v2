export { monitorActiveScan } from './initiateArjunScan';

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

export default monitorArjunScanStatus;
