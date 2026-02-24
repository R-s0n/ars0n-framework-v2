import fetchHttpxScans from './fetchHttpxScans';

const monitorHttpxScanStatus = async (
  activeTarget,
  setHttpxScans,
  setMostRecentHttpxScan,
  setIsHttpxScanning,
  setMostRecentHttpxScanStatus
) => {
  if (!activeTarget) {
    setHttpxScans([]);
    setMostRecentHttpxScan(null);
    setIsHttpxScanning(false);
    setMostRecentHttpxScanStatus(null);
    return;
  }

  try {
    const scanDetails = await fetchHttpxScans(activeTarget, setHttpxScans, setMostRecentHttpxScan, setMostRecentHttpxScanStatus);
    
    if (scanDetails && scanDetails.status === 'pending') {
      setIsHttpxScanning(true);
      setTimeout(() => {
        monitorHttpxScanStatus(
          activeTarget,
          setHttpxScans,
          setMostRecentHttpxScan,
          setIsHttpxScanning,
          setMostRecentHttpxScanStatus
        );
      }, 5000);
    } else {
      setIsHttpxScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring httpx scan status:', error);
    setHttpxScans([]);
    setMostRecentHttpxScan(null);
    setIsHttpxScanning(false);
    setMostRecentHttpxScanStatus(null);
  }
};

export default monitorHttpxScanStatus; 