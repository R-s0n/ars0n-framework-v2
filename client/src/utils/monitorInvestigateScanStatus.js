import { pollTimeout } from './scanPolling';
const monitorInvestigateScanStatus = async (
  activeTarget,
  setInvestigateScans,
  setMostRecentInvestigateScan,
  setIsInvestigateScanning,
  setMostRecentInvestigateScanStatus
) => {
  if (!activeTarget || !activeTarget.id) {
    console.warn('No active target or target ID available for investigate monitoring');
    setIsInvestigateScanning(false);
    setMostRecentInvestigateScan(null);
    setMostRecentInvestigateScanStatus(null);
    return;
  }

  const targetId = activeTarget.id;

  try {
    const response = await fetch(
      `/api/scopetarget/${targetId}/scans/investigate`
    );
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to fetch investigate scans: ${response.status} ${response.statusText} - ${errorText}`);
    }
    
    const scansPayload = await response.json();
    // A Go handler that returns a nil slice encodes it as JSON null rather than [],
    // and reading .length off null threw a TypeError that killed this poll loop.
    const scans = Array.isArray(scansPayload) ? scansPayload : [];
    setInvestigateScans(scans || []);
    
    if (scans && Array.isArray(scans) && scans.length > 0) {
      const mostRecent = scans[0];
      setMostRecentInvestigateScan(mostRecent);
      setMostRecentInvestigateScanStatus(mostRecent.status);
      
      if (mostRecent.status === 'pending' || mostRecent.status === 'running') {
        setIsInvestigateScanning(true);
        pollTimeout(() => {
          monitorInvestigateScanStatus(
            activeTarget,
            setInvestigateScans,
            setMostRecentInvestigateScan,
            setIsInvestigateScanning,
            setMostRecentInvestigateScanStatus
          );
        }, 2000);
      } else {
        setIsInvestigateScanning(false);
      }
    } else {
      setMostRecentInvestigateScan(null);
      setMostRecentInvestigateScanStatus(null);
      setIsInvestigateScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring investigate scan status:', error);
    console.error(`Failed URL: /api/scopetarget/${targetId}/scans/investigate`);
    setIsInvestigateScanning(false);
    setMostRecentInvestigateScan(null);
    setMostRecentInvestigateScanStatus(null);
    setInvestigateScans([]);
  }
};

export default monitorInvestigateScanStatus; 