const initiateGauScan = async (
  activeTarget,
  monitorGauScanStatus,
  setIsGauScanning,
  setGauScans,
  setMostRecentGauScanStatus,
  setMostRecentGauScan,
  autoScanSessionId
) => {
  if (!activeTarget) return;

  const domain = activeTarget.scope_target.replace('*.', '');

  try {
    const body = {
      fqdn: domain,
      options: {
        subs: true,
        json: true,
        blacklist: ['ttf', 'woff', 'woff2', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'css'],
        providers: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
        threads: 50,
        verbose: true
      }
    };
    if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
    const response = await fetch(
      `/api/gau/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate GAU scan');
    }

    const data = await response.json();
    setIsGauScanning(true);

    if (monitorGauScanStatus) {
      monitorGauScanStatus(
        activeTarget,
        setGauScans,
        setMostRecentGauScan,
        setIsGauScanning,
        setMostRecentGauScanStatus
      );
    }

    return data;
  } catch (error) {
    console.error('Error initiating GAU scan:', error);
    setIsGauScanning(false);
  }
};

export default initiateGauScan; 