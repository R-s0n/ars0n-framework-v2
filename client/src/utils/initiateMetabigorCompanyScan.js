export const initiateMetabigorCompanyScan = async (
  activeTarget,
  monitorScanStatus,
  setIsScanning,
  setMetabigorCompanyScans,
  setMostRecentMetabigorCompanyScanStatus,
  setMostRecentMetabigorCompanyScan,
  setMetabigorNetworkRanges,
  autoScanSessionId
) => {
  if (!activeTarget || activeTarget.type !== 'Company') return;

  setMetabigorNetworkRanges([]);

  let companyName = activeTarget.scope_target;

  console.log(`Initiating Metabigor Company scan for: ${companyName}`);

  try {
    const body = { company_name: companyName };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;

    const response = await fetch(
      `/api/metabigor-company/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Metabigor Company scan');
    }

    const data = await response.json();
    console.log('Metabigor Company scan initiated:', data);

    setIsScanning(true);
    monitorScanStatus &&
      monitorScanStatus(
        activeTarget,
        setMetabigorCompanyScans,
        setMostRecentMetabigorCompanyScan,
        setIsScanning,
        setMostRecentMetabigorCompanyScanStatus,
        setMetabigorNetworkRanges
      );
  } catch (error) {
    console.error('Error initiating Metabigor Company scan:', error);
    setIsScanning(false);
  }
};

export default initiateMetabigorCompanyScan; 