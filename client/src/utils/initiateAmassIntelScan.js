export const initiateAmassIntelScan = async (activeTarget, monitorScanStatus, setIsScanning, setAmassIntelScans, setMostRecentAmassIntelScanStatus, setMostRecentAmassIntelScan, setAmassIntelNetworkRanges, autoScanSessionId) => {
    if (!activeTarget || activeTarget.type !== 'Company') return;
    
    setAmassIntelNetworkRanges([]);
    
    let companyName = activeTarget.scope_target;
    
    try {
        const body = { company_name: companyName };
        if (autoScanSessionId) body.auto_scan_session_id = autoScanSessionId;
        
        const response = await fetch(`/api/amass-intel/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        if (!response.ok) {
            throw new Error('Failed to initiate Amass Intel scan');
        }

        setIsScanning(true);
        monitorScanStatus && monitorScanStatus(activeTarget, setAmassIntelScans, setMostRecentAmassIntelScan, setIsScanning, setMostRecentAmassIntelScanStatus, setAmassIntelNetworkRanges);
    } catch (error) {
        console.error('Error initiating Amass Intel scan:', error);
    }
};

export default initiateAmassIntelScan; 