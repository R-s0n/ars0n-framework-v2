export { monitorActiveScan } from './initiateX8Scan';

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

export default monitorX8ScanStatus;
