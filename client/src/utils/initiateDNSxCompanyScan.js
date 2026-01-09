import { monitorDNSxCompanyScanStatus } from './monitorDNSxCompanyScanStatus';

export const initiateDNSxCompanyScan = async (activeTarget, domains, setIsScanning, setDNSxCompanyScans, setMostRecentDNSxCompanyScan, setMostRecentDNSxCompanyScanStatus, setDNSxCompanyDNSRecords = null) => {
  setIsScanning(true);
  
  try {
    const response = await fetch(
      `/api/dnsx-company/run/${activeTarget.id}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          domains: domains
        }),
      }
    );

    if (response.ok) {
      const result = await response.json();
      console.log('DNSx Company scan initiated:', result);
      
      // Start monitoring the scan status
      monitorDNSxCompanyScanStatus(
        result.scan_id, 
        setIsScanning, 
        setDNSxCompanyScans, 
        setMostRecentDNSxCompanyScan, 
        setMostRecentDNSxCompanyScanStatus,
        setDNSxCompanyDNSRecords
      );
    } else {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
  } catch (error) {
    console.error('Error initiating DNSx Company scan:', error);
    setIsScanning(false);
    // You might want to show an error notification here
  }
}; 