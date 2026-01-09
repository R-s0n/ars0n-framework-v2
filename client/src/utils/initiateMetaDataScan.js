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

export { initiateCompanyMetaDataScan };
export default initiateMetaDataScan; 