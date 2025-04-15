const initiateMetaDataScan = async (
  activeTarget,
  monitorMetaDataScanStatus,
  setIsMetaDataScanning,
  setMetaDataScans,
  setMostRecentMetaDataScanStatus,
  setMostRecentMetaDataScan
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/metadata/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scope_target_id: activeTarget.id,
        }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Nuclei SSL scan');
    }

    setIsMetaDataScanning(true);
    
    if (monitorMetaDataScanStatus) {
      monitorMetaDataScanStatus(
        activeTarget,
        setMetaDataScans,
        setMostRecentMetaDataScan,
        setIsMetaDataScanning,
        setMostRecentMetaDataScanStatus
      );
    }
    
    return { success: true };
  } catch (error) {
    console.error('Error initiating Nuclei SSL scan:', error);
    setIsMetaDataScanning(false);
  }
};

export default initiateMetaDataScan; 