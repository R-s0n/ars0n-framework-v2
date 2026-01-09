const monitorMetabigorCompanyScanStatus = async (
  activeTarget,
  setMetabigorCompanyScans,
  setMostRecentMetabigorCompanyScan,
  setIsMetabigorCompanyScanning,
  setMostRecentMetabigorCompanyScanStatus,
  setMetabigorNetworkRanges
) => {
  if (!activeTarget || !activeTarget.id) {
    setIsMetabigorCompanyScanning(false);
    setMostRecentMetabigorCompanyScan(null);
    setMostRecentMetabigorCompanyScanStatus(null);
    setMetabigorNetworkRanges([]);
    return;
  }

  try {
    console.log('[METABIGOR-COMPANY] Monitoring scan status for target:', activeTarget.id);
    
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/metabigor-company`
    );
    if (!response.ok) {
      throw new Error('Failed to fetch Metabigor Company scans');
    }
    const scans = await response.json();
    if (!Array.isArray(scans)) {
      setMetabigorCompanyScans([]);
      setMostRecentMetabigorCompanyScan(null);
      setMostRecentMetabigorCompanyScanStatus(null);
      setIsMetabigorCompanyScanning(false);
      setMetabigorNetworkRanges([]);
      return;
    }

    console.log('[METABIGOR-COMPANY] Retrieved', scans.length, 'scans');
    setMetabigorCompanyScans(scans);

    if (scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      console.log('[METABIGOR-COMPANY] Most recent scan status:', mostRecentScan.status);
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

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setIsMetabigorCompanyScanning(true);
        setTimeout(() => {
          monitorMetabigorCompanyScanStatus(
            activeTarget,
            setMetabigorCompanyScans,
            setMostRecentMetabigorCompanyScan,
            setIsMetabigorCompanyScanning,
            setMostRecentMetabigorCompanyScanStatus,
            setMetabigorNetworkRanges
          );
        }, 5000);
      } else {
        setIsMetabigorCompanyScanning(false);
      }
    } else {
      setMostRecentMetabigorCompanyScan(null);
      setMostRecentMetabigorCompanyScanStatus(null);
      setIsMetabigorCompanyScanning(false);
      setMetabigorNetworkRanges([]);
    }
  } catch (error) {
    console.error('[METABIGOR-COMPANY] Error monitoring scan status:', error);
    setIsMetabigorCompanyScanning(false);
    setMostRecentMetabigorCompanyScan(null);
    setMostRecentMetabigorCompanyScanStatus(null);
    setMetabigorCompanyScans([]);
    setMetabigorNetworkRanges([]);
  }
};

export default monitorMetabigorCompanyScanStatus; 