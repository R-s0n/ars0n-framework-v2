const monitorScanStatus = async (
  activeTarget,
  setAmassScans,
  setMostRecentAmassScan,
  setIsScanning,
  setMostRecentAmassScanStatus,
  setDnsRecords,
  setSubdomains,
  setCloudDomains
) => {
  if (!activeTarget) {
    setAmassScans([]);
    setMostRecentAmassScan(null);
    setIsScanning(false);
    setMostRecentAmassScanStatus(null);
    setDnsRecords([]);
    setSubdomains([]);
    setCloudDomains([]);
    return;
  }

  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/amass`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch Amass scans');
    }

    const scans = await response.json();
    setAmassScans(scans || []);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentAmassScan(mostRecentScan);
      setMostRecentAmassScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsScanning(true);
        setTimeout(() => {
          monitorScanStatus(
            activeTarget,
            setAmassScans,
            setMostRecentAmassScan,
            setIsScanning,
            setMostRecentAmassScanStatus,
            setDnsRecords,
            setSubdomains,
            setCloudDomains
          );
        }, 5000);
      } else {
        setIsScanning(false);
        // Fetch additional data when scan is complete
        if (mostRecentScan.status === 'success') {
          try {
            const [dnsResponse, subdomainsResponse, cloudResponse] = await Promise.all([
              fetch(`/api/amass/${mostRecentScan.scan_id}/dns`),
              fetch(`/api/amass/${mostRecentScan.scan_id}/subdomain`),
              fetch(`/api/amass/${mostRecentScan.scan_id}/cloud`)
            ]);

            if (!dnsResponse.ok || !subdomainsResponse.ok || !cloudResponse.ok) {
              throw new Error('One or more additional data fetches failed');
            }

            const [dnsData, subdomainsData, cloudData] = await Promise.all([
              dnsResponse.json(),
              subdomainsResponse.json(),
              cloudResponse.json()
            ]);

            setDnsRecords(dnsData || []);
            setSubdomains(subdomainsData || []);
            setCloudDomains(cloudData || []);
          } catch (error) {
            console.error('Error fetching additional Amass data:', error);
            setDnsRecords([]);
            setSubdomains([]);
            setCloudDomains([]);
          }
        }
      }
    } else {
      setMostRecentAmassScan(null);
      setMostRecentAmassScanStatus(null);
      setIsScanning(false);
      setDnsRecords([]);
      setSubdomains([]);
      setCloudDomains([]);
    }
  } catch (error) {
    console.error('Error monitoring Amass scan status:', error);
    setAmassScans([]);
    setMostRecentAmassScan(null);
    setIsScanning(false);
    setMostRecentAmassScanStatus(null);
    setDnsRecords([]);
    setSubdomains([]);
    setCloudDomains([]);
  }
};

export default monitorScanStatus;
