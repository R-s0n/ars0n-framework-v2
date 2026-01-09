const monitorDNSxCompanyScanStatus = async (
  scanId, 
  setIsScanning, 
  setDNSxCompanyScans, 
  setMostRecentDNSxCompanyScan, 
  setMostRecentDNSxCompanyScanStatus,
  setDNSxCompanyDNSRecords = null
) => {
  const poll = async () => {
    try {
      const response = await fetch(
        `/api/dnsx-company/status/${scanId}`
      );
      
      if (response.ok) {
        const scan = await response.json();
        
        // Update the most recent scan
        setMostRecentDNSxCompanyScan(scan);
        setMostRecentDNSxCompanyScanStatus(scan.status);
        
        if (scan.status === 'success' || scan.status === 'error') {
          setIsScanning(false);
          
          // Fetch updated scan list
          if (setDNSxCompanyScans) {
            try {
              const scansResponse = await fetch(
                `/api/scopetarget/${scan.scope_target_id}/scans/dnsx-company`
              );
              if (scansResponse.ok) {
                const scansData = await scansResponse.json();
                setDNSxCompanyScans(scansData);
              }
            } catch (error) {
              console.error('Error fetching DNSx company scans:', error);
            }
          }

          // Fetch DNS records if the scan was successful
          if (scan.status === 'success' && setDNSxCompanyDNSRecords) {
            try {
              const recordsResponse = await fetch(
                `/api/dnsx-company/${scanId}/dns-records`
              );
              if (recordsResponse.ok) {
                const recordsData = await recordsResponse.json();
                setDNSxCompanyDNSRecords(recordsData);
              }
            } catch (error) {
              console.error('Error fetching DNSx DNS records:', error);
            }
          }
          
          return; // Stop polling
        }
        
        // Continue polling if still running
        setTimeout(poll, 2000);
      } else {
        console.error('Failed to fetch DNSx Company scan status');
        setIsScanning(false);
      }
    } catch (error) {
      console.error('Error polling DNSx Company scan status:', error);
      setIsScanning(false);
    }
  };
  
  // Start polling immediately
  poll();
};

export default monitorDNSxCompanyScanStatus;
export { monitorDNSxCompanyScanStatus }; 