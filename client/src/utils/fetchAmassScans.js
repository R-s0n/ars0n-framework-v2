const fetchAmassScans = async (activeTarget, setAmassScans, setMostRecentAmassScan, setMostRecentAmassScanStatus, setDnsRecords, setSubdomains, setCloudDomains) => {
  
    try {
      const response = await fetch(
        `/api/scopetarget/${activeTarget.id}/scans/amass`
      );
      if (!response.ok) throw new Error('Failed to fetch Amass scans');
  
      const data = await response.json();
      
      setAmassScans(data || []);
      if (!Array.isArray(data) || data.length === 0) return null;
  
      const mostRecentScan = data.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, data[0]);
  
      const scanDetailsResponse = await fetch(
        `/api/amass/${mostRecentScan.scan_id}`
      );
      if (!scanDetailsResponse.ok) throw new Error('Failed to fetch Amass scan details');
  
      const scanDetails = await scanDetailsResponse.json();
      setMostRecentAmassScan(scanDetails);
      setMostRecentAmassScanStatus(scanDetails.status);
      const fetchDNSRecords = async () => {
        try {
          const dnsResponse = await fetch(`/api/amass/${scanDetails.scan_id}/dns`);
          if (dnsResponse.ok) {
            const dnsData = await dnsResponse.json();
            if (dnsData !== null) {
                setDnsRecords(dnsData);
            } else {
                setDnsRecords([]);
            }
          } else {
            throw new Error('Failed to fetch DNS records');
          }
        } catch (error) {
          console.error('Error fetching DNS records:', error);
          setDnsRecords([]);
        }
      };

      const fetchSubdomains = async () => {
        try {
          const subdomainResponse = await fetch(`/api/amass/${scanDetails.scan_id}/subdomain`);
          if (subdomainResponse.ok) {
            const subdomainsData = await subdomainResponse.json();
            setSubdomains(subdomainsData);
          } else {
            throw new Error('Failed to fetch subdomains');
          }
        } catch (error) {
          console.error('Error fetching subdomains:', error);
          setSubdomains([]);
        }
      };

      const fetchCloudDomains = async () => {
        try {
          const cloudResponse = await fetch(`/api/amass/${scanDetails.scan_id}/cloud`);
          if (cloudResponse.ok) {
            const cloudData = await cloudResponse.json();
            const formattedCloudDomains = [];
            if (cloudData.aws_domains) {
              formattedCloudDomains.push(...cloudData.aws_domains.map((name) => ({ type: 'AWS', name })));
            }
            if (cloudData.azure_domains) {
              formattedCloudDomains.push(...cloudData.azure_domains.map((name) => ({ type: 'Azure', name })));
            }
            if (cloudData.gcp_domains) {
              formattedCloudDomains.push(...cloudData.gcp_domains.map((name) => ({ type: 'GCP', name })));
            }
            setCloudDomains(formattedCloudDomains);
          } else {
            throw new Error('Failed to fetch cloud domains');
          }
        } catch (error) {
          console.error('Error fetching cloud domains:', error);
          setCloudDomains([]);
        }
      };

      fetchDNSRecords();
      fetchSubdomains();
      fetchCloudDomains();
      return scanDetails;
    } catch (error) {
      console.error('Error fetching Amass scan details:', error);
    }
  };
  
  export default fetchAmassScans;
  