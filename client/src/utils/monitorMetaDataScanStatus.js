const monitorMetaDataScanStatus = async (
  activeTarget,
  setMetaDataScans,
  setMostRecentMetaDataScan,
  setIsMetaDataScanning,
  setMostRecentMetaDataScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/metadata`
    );

    if (!response.ok) {
      throw new Error('Failed to get Nuclei SSL scans');
    }

    const scans = await response.json();
    setMetaDataScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentMetaDataScan(mostRecentScan);
      setMostRecentMetaDataScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setTimeout(() => {
          monitorMetaDataScanStatus(
            activeTarget,
            setMetaDataScans,
            setMostRecentMetaDataScan,
            setIsMetaDataScanning,
            setMostRecentMetaDataScanStatus
          );
        }, 5000);
      } else {
        setIsMetaDataScanning(false);
        // Fetch updated target URLs when scan completes
        try {
          const urlsResponse = await fetch(
            `/api/api/scope-targets/${activeTarget.id}/target-urls`
          );
          if (!urlsResponse.ok) {
            throw new Error('Failed to fetch target URLs');
          }
          const data = await urlsResponse.json();
          window.dispatchEvent(new CustomEvent('metadataScanComplete', { detail: data }));
        } catch (error) {
          console.error('Error fetching target URLs:', error);
        }
      }
    }
  } catch (error) {
    console.error('Error monitoring Nuclei SSL scan status:', error);
    setIsMetaDataScanning(false);
  }
};

const monitorCompanyMetaDataScanStatus = async (
  activeTarget,
  ipPortScanId,
  setCompanyMetaDataScans,
  setMostRecentCompanyMetaDataScan,
  setIsCompanyMetaDataScanning,
  setMostRecentCompanyMetaDataScanStatus
) => {
  if (!activeTarget || !ipPortScanId) return;

  try {
    const response = await fetch(
      `/api/ip-port-scan/${ipPortScanId}/metadata-scans`
    );

    if (!response.ok) {
      throw new Error('Failed to get Company metadata scans');
    }

    const scans = await response.json();
    setCompanyMetaDataScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentCompanyMetaDataScan(mostRecentScan);
      setMostRecentCompanyMetaDataScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setTimeout(() => {
          monitorCompanyMetaDataScanStatus(
            activeTarget,
            ipPortScanId,
            setCompanyMetaDataScans,
            setMostRecentCompanyMetaDataScan,
            setIsCompanyMetaDataScanning,
            setMostRecentCompanyMetaDataScanStatus
          );
        }, 5000);
      } else {
        setIsCompanyMetaDataScanning(false);
        // Fetch updated metadata results when scan completes
        try {
          const metadataResponse = await fetch(
            `/api/ip-port-scan/${ipPortScanId}/metadata-results`
          );
          if (!metadataResponse.ok) {
            throw new Error('Failed to fetch metadata results');
          }
          const data = await metadataResponse.json();
          window.dispatchEvent(new CustomEvent('companyMetadataScanComplete', { 
            detail: { 
              ipPortScanId: ipPortScanId,
              metadata: data 
            } 
          }));
        } catch (error) {
          console.error('Error fetching metadata results:', error);
        }
      }
    }
  } catch (error) {
    console.error('Error monitoring Company metadata scan status:', error);
    setIsCompanyMetaDataScanning(false);
  }
};

export { monitorCompanyMetaDataScanStatus };
export default monitorMetaDataScanStatus; 