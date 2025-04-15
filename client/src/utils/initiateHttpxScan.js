const initiateHttpxScan = async (
  activeTarget,
  monitorHttpxScanStatus,
  setIsHttpxScanning,
  setHttpxScans,
  setMostRecentHttpxScanStatus,
  setMostRecentHttpxScan
) => {
  if (!activeTarget) return;

  let fqdn = activeTarget.scope_target;
  if (activeTarget.type === 'Wildcard' && fqdn.startsWith('*.')) {
    fqdn = fqdn.substring(2);
  }
  
  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/httpx/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ fqdn }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate httpx scan');
    }

    const data = await response.json();
    console.log(data);
    setIsHttpxScanning(true);

    if (monitorHttpxScanStatus) {
      monitorHttpxScanStatus(
        activeTarget,
        setHttpxScans,
        setMostRecentHttpxScan,
        setIsHttpxScanning,
        setMostRecentHttpxScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('Error initiating httpx scan:', error);
    setIsHttpxScanning(false);
  }
}

export default initiateHttpxScan; 