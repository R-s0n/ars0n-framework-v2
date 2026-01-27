const initiateMetaDataScan = async (
  activeTarget,
  monitorMetaDataScanStatus,
  setIsMetaDataScanning,
  setMetaDataScans,
  setMostRecentMetaDataScanStatus,
  setMostRecentMetaDataScan,
  autoScanSessionId,
  config = null
) => {
  if (!activeTarget) return;

  try {
    const body = { scope_target_id: activeTarget.id };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    if (config) {
      body.config = {
        url_ids: config.urls,
        steps: config.steps
      };
    }
    const response = await fetch(
      `/api/metadata/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
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

const initiateCompanyMetaDataScan = async (
  activeTarget,
  ipPortScanId,
  monitorCompanyMetaDataScanStatus,
  setIsCompanyMetaDataScanning,
  setCompanyMetaDataScans,
  setMostRecentCompanyMetaDataScanStatus,
  setMostRecentCompanyMetaDataScan
) => {
  if (!activeTarget || !ipPortScanId) return;

  try {
    const body = { 
      scope_target_id: activeTarget.id,
      ip_port_scan_id: ipPortScanId
    };
    
    const response = await fetch(
      `/api/metadata/run-company`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Company metadata scan');
    }

    setIsCompanyMetaDataScanning(true);
    
    if (monitorCompanyMetaDataScanStatus) {
      monitorCompanyMetaDataScanStatus(
        activeTarget,
        ipPortScanId,
        setCompanyMetaDataScans,
        setMostRecentCompanyMetaDataScan,
        setIsCompanyMetaDataScanning,
        setMostRecentCompanyMetaDataScanStatus
      );
    }
    
    return { success: true };
  } catch (error) {
    console.error('Error initiating Company metadata scan:', error);
    setIsCompanyMetaDataScanning(false);
  }
};

const cancelMetaDataScan = async (scanId) => {
  console.log('[DEBUG cancelMetaDataScan] Called with scanId:', scanId);
  
  if (!scanId) {
    console.error('[DEBUG cancelMetaDataScan] No scan ID provided for cancellation');
    return { success: false, error: 'No scan ID' };
  }

  try {
    const url = `/api/metadata/${scanId}/cancel`;
    console.log('[DEBUG cancelMetaDataScan] Making POST request to:', url);
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    console.log('[DEBUG cancelMetaDataScan] Response status:', response.status);
    console.log('[DEBUG cancelMetaDataScan] Response ok:', response.ok);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[DEBUG cancelMetaDataScan] Error response:', errorText);
      throw new Error(`Failed to cancel metadata scan: ${response.status} ${errorText}`);
    }

    const result = await response.json();
    console.log('[DEBUG cancelMetaDataScan] Success response:', result);
    console.log('Metadata scan cancellation requested');
    return { success: true };
  } catch (error) {
    console.error('[DEBUG cancelMetaDataScan] Exception:', error);
    console.error('Error cancelling metadata scan:', error);
    return { success: false, error: error.message };
  }
};

export { initiateCompanyMetaDataScan, cancelMetaDataScan };
export default initiateMetaDataScan; 