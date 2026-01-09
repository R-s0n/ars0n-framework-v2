const fetchIPPortScans = async (activeTarget, setIPPortScans, setMostRecentIPPortScan, setMostRecentIPPortScanStatus) => {
  try {
    const response = await fetch(
      `/api/scopetarget/${activeTarget.id}/scans/ip-port`
    );
    if (!response.ok) throw new Error('Failed to fetch IP/Port scans');

    const data = await response.json();
    console.log('IP/Port scans API response:', data);
    const scans = data.scans || [];
    setIPPortScans(scans);
    if (scans.length === 0) {
      return null;
    }

    const mostRecentScan = scans.reduce((latest, scan) => {
      const scanDate = new Date(scan.created_at);
      return scanDate > new Date(latest.created_at) ? scan : latest;
    }, scans[0]);

    const scanDetailsResponse = await fetch(
      `/api/ip-port-scan/status/${mostRecentScan.scan_id}`
    );
    if (!scanDetailsResponse.ok) throw new Error('Failed to fetch IP/Port scan details');

    const scanDetails = await scanDetailsResponse.json();
    setMostRecentIPPortScan(scanDetails);
    setMostRecentIPPortScanStatus(scanDetails.status);

    return scanDetails;
  } catch (error) {
    console.error('Error fetching IP/Port scan details:', error);
  }
}

export default fetchIPPortScans; 