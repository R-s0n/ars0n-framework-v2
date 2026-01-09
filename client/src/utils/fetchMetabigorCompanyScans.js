const fetchMetabigorCompanyScans = async (
  activeTarget,
  setMetabigorCompanyScans,
  setMostRecentMetabigorCompanyScan,
  setMostRecentMetabigorCompanyScanStatus,
  setMetabigorNetworkRanges
) => {
  if (!activeTarget || !activeTarget.id) return;

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/metabigor-company`
    );
    if (!response.ok) {
      throw new Error('Failed to fetch Metabigor Company scans');
    }
    const scans = await response.json();
    setMetabigorCompanyScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentMetabigorCompanyScan(mostRecentScan);
      setMostRecentMetabigorCompanyScanStatus(mostRecentScan.status);
      
      // Fetch network ranges for the most recent scan
      if (mostRecentScan.scan_id && setMetabigorNetworkRanges) {
        try {
          const networkRangesResponse = await fetch(
            `/api/metabigor-company/${mostRecentScan.scan_id}/networks`
          );
          if (networkRangesResponse.ok) {
            const networkRanges = await networkRangesResponse.json();
            setMetabigorNetworkRanges(Array.isArray(networkRanges) ? networkRanges : []);
          }
        } catch (networkError) {
          console.error('Error fetching Metabigor network ranges:', networkError);
          setMetabigorNetworkRanges([]);
        }
      }
    } else {
      setMetabigorNetworkRanges([]);
    }
  } catch (error) {
    console.error('Error fetching Metabigor Company scans:', error);
    setMetabigorNetworkRanges([]);
  }
};

export default fetchMetabigorCompanyScans; 