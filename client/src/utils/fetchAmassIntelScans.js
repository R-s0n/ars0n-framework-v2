const fetchAmassIntelScans = async (
  activeTarget,
  setAmassIntelScans,
  setMostRecentAmassIntelScan,
  setMostRecentAmassIntelScanStatus,
  setAmassIntelNetworkRanges
) => {
  if (!activeTarget || !activeTarget.id) return;

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/amass-intel`
    );
    if (!response.ok) {
      throw new Error('Failed to fetch Amass Intel scans');
    }
    const scans = await response.json();
    setAmassIntelScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentAmassIntelScan(mostRecentScan);
      setMostRecentAmassIntelScanStatus(mostRecentScan.status);
      
      // Fetch network ranges for the most recent scan
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
    } else {
      setAmassIntelNetworkRanges([]);
    }
  } catch (error) {
    console.error('Error fetching Amass Intel scans:', error);
    setAmassIntelNetworkRanges([]);
  }
};

export default fetchAmassIntelScans; 