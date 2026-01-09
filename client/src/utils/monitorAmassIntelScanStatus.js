const monitorAmassIntelScanStatus = async (
  activeTarget,
  setAmassIntelScans,
  setMostRecentAmassIntelScan,
  setIsAmassIntelScanning,
  setMostRecentAmassIntelScanStatus,
  setAmassIntelNetworkRanges
) => {
  if (!activeTarget || !activeTarget.id) {
    setIsAmassIntelScanning(false);
    setMostRecentAmassIntelScan(null);
    setMostRecentAmassIntelScanStatus(null);
    setAmassIntelNetworkRanges([]);
    return;
  }

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/amass-intel`
    );
    if (!response.ok) {
      throw new Error('Failed to fetch Amass Intel scans');
    }
    const scans = await response.json();
    setAmassIntelScans(scans || []);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentAmassIntelScan(mostRecentScan);
      setMostRecentAmassIntelScanStatus(mostRecentScan.status);

      if (mostRecentScan.scan_id && setAmassIntelNetworkRanges) {
        try {
          const networkRangesResponse = await fetch(
            `/api/amass-intel/${mostRecentScan.scan_id}/networks`
          );
          if (networkRangesResponse.ok) {
            const networkRanges = await networkRangesResponse.json();
            setAmassIntelNetworkRanges(Array.isArray(networkRanges) ? networkRanges : []);
          }
        } catch (networkError) {
          console.error('Error fetching network ranges:', networkError);
          setAmassIntelNetworkRanges([]);
        }
      }

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsAmassIntelScanning(true);
        setTimeout(() => {
          monitorAmassIntelScanStatus(
            activeTarget,
            setAmassIntelScans,
            setMostRecentAmassIntelScan,
            setIsAmassIntelScanning,
            setMostRecentAmassIntelScanStatus,
            setAmassIntelNetworkRanges
          );
        }, 5000);
      } else {
        setIsAmassIntelScanning(false);
      }
    } else {
      setMostRecentAmassIntelScan(null);
      setMostRecentAmassIntelScanStatus(null);
      setIsAmassIntelScanning(false);
      setAmassIntelNetworkRanges([]);
    }
  } catch (error) {
    console.error('Error monitoring Amass Intel scan status:', error);
    setIsAmassIntelScanning(false);
    setMostRecentAmassIntelScan(null);
    setMostRecentAmassIntelScanStatus(null);
    setAmassIntelScans([]);
    setAmassIntelNetworkRanges([]);
  }
};

export default monitorAmassIntelScanStatus; 
