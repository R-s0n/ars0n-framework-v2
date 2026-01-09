const initiateInvestigateScan = async (
  activeTarget,
  monitorInvestigateScanStatus,
  setIsInvestigateScanning,
  setInvestigateScans,
  setMostRecentInvestigateScanStatus,
  setMostRecentInvestigateScan
) => {
  if (!activeTarget || !activeTarget.id) {
    console.warn('No active target or target ID available for investigate scan');
    return;
  }

  const targetId = activeTarget.id;

  try {
    const body = { scope_target_id: targetId };
    const response = await fetch(
      `/api/investigate/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate investigate scan');
    }

    setIsInvestigateScanning(true);
    
    const responseData = await response.json();
    console.log('Investigate scan initiated:', responseData);

    monitorInvestigateScanStatus(
      activeTarget,
      setInvestigateScans,
      setMostRecentInvestigateScan,
      setIsInvestigateScanning,
      setMostRecentInvestigateScanStatus
    );

  } catch (error) {
    console.error('Error initiating investigate scan:', error);
    setIsInvestigateScanning(false);
  }
};

export default initiateInvestigateScan; 