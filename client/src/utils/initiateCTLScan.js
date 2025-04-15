const initiateCTLScan = async (
  activeTarget,
  monitorCTLScanStatus,
  setIsCTLScanning,
  setCTLScans,
  setMostRecentCTLScanStatus,
  setMostRecentCTLScan
) => {
  if (!activeTarget) return;

  const domain = activeTarget.scope_target.replace('*.', '');

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/ctl/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fqdn: domain
        }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate CTL scan');
    }

    const data = await response.json();
    setIsCTLScanning(true);

    if (monitorCTLScanStatus) {
      monitorCTLScanStatus(
        activeTarget,
        setCTLScans,
        setMostRecentCTLScan,
        setIsCTLScanning,
        setMostRecentCTLScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('Error initiating CTL scan:', error);
    setIsCTLScanning(false);
  }
};

export default initiateCTLScan; 