import monitorAmassEnumCompanyScanStatus from './monitorAmassEnumCompanyScanStatus.js';

export const initiateAmassEnumCompanyScan = async (activeTarget, domains, setIsScanning, setAmassEnumCompanyScans, setMostRecentAmassEnumCompanyScan, setMostRecentAmassEnumCompanyScanStatus, setAmassEnumCompanyCloudDomains = null) => {
  if (!activeTarget || !domains || domains.length === 0) {
    console.error('No active target or domains provided for Amass Enum Company scan');
    return;
  }

  try {
    const response = await fetch(`/api/amass-enum-company/run/${activeTarget.id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domains }),
    });

    if (!response.ok) {
      throw new Error('Failed to initiate Amass Enum Company scan');
    }

    const result = await response.json();
    const scanId = result.scan_id;

    console.log('Amass Enum Company scan initiated with ID:', scanId);
    setIsScanning(true);

    // Start monitoring the scan status
    await monitorAmassEnumCompanyScanStatus(
      scanId,
      setIsScanning,
      setAmassEnumCompanyScans,
      setMostRecentAmassEnumCompanyScan,
      setMostRecentAmassEnumCompanyScanStatus,
      setAmassEnumCompanyCloudDomains,
      activeTarget
    );

  } catch (error) {
    console.error('Error initiating Amass Enum Company scan:', error);
    setIsScanning(false);
  }
};

export default initiateAmassEnumCompanyScan; 