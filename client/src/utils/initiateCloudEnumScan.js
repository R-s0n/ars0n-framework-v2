const initiateCloudEnumScan = async (
  activeTarget,
  monitorCloudEnumScanStatus,
  setIsCloudEnumScanning,
  setCloudEnumScans,
  setMostRecentCloudEnumScanStatus,
  setMostRecentCloudEnumScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  const companyName = activeTarget.scope_target;

  try {
    console.log('[CLOUD-ENUM] Initiating Cloud Enum scan for:', companyName);
    
    const body = { company_name: companyName };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    
    const response = await fetch(
      `/api/cloud-enum/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Cloud Enum scan');
    }

    const data = await response.json();
    console.log('[CLOUD-ENUM] Scan initiated with ID:', data.scan_id);
    setIsCloudEnumScanning(true);

    if (monitorCloudEnumScanStatus) {
      monitorCloudEnumScanStatus(
        activeTarget,
        setCloudEnumScans,
        setMostRecentCloudEnumScan,
        setIsCloudEnumScanning,
        setMostRecentCloudEnumScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('[CLOUD-ENUM] Error initiating Cloud Enum scan:', error);
    setIsCloudEnumScanning(false);
  }
};

export default initiateCloudEnumScan; 