// Define the auto scan steps
const AUTO_SCAN_STEPS = {
  IDLE: 'idle',
  SUBLIST3R: 'sublist3r',
  ASSETFINDER: 'assetfinder',
  GAU: 'gau',
  CTL: 'ctl',
  SUBFINDER: 'subfinder',
  CONSOLIDATE: 'consolidate',
  HTTPX: 'httpx',
  NUCLEI_SCREENSHOT: 'nuclei-screenshot',
  METADATA: 'metadata',
  COMPLETED: 'completed'
};

// Define scan types - we're keeping this for compatibility even though all scan types will run the same steps
const SCAN_TYPES = {
  QUICK: 'quick',
  BALANCED: 'balanced',
  FULL: 'full',
  YOLO: 'yolo'
};

// Debug utility function
const debugTrace = (message) => {
  const timestamp = new Date().toISOString();
  console.log(`[TRACE ${timestamp}] ${message}`);
};

// Helper function to wait for a scan to complete
const waitForScanCompletion = async (scanType, targetId, setIsScanning, setMostRecentScanStatus) => {
  debugTrace(`waitForScanCompletion started for ${scanType}`);
  
  // Add a hard safety timeout in case the promise never resolves
  return Promise.race([
    new Promise((resolve) => {
      const startTime = Date.now();
      const maxWaitTime = 10 * 60 * 1000; // 10 minutes maximum wait
      const hardMaxWaitTime = 15 * 60 * 1000; // 15 minutes absolute maximum
      let attempts = 0;
      
      // Add a hard timeout as safety
      const hardTimeout = setTimeout(() => {
        debugTrace(`HARD TIMEOUT: ${scanType} scan exceeded maximum wait time of 15 minutes`);
        setIsScanning(false);
        resolve({ status: 'hard_timeout', message: 'Hard scan timeout exceeded' });
      }, hardMaxWaitTime);
      
      const checkStatus = async () => {
        attempts++;
        debugTrace(`Checking ${scanType} scan status - attempt #${attempts}`);
        try {
          // Check if we've been waiting too long
          if (Date.now() - startTime > maxWaitTime) {
            debugTrace(`${scanType} scan taking too long (${Math.round((Date.now() - startTime)/1000)}s), proceeding with next step`);
            setIsScanning(false);
            clearTimeout(hardTimeout); // Clear the hard timeout
            return resolve({ status: 'timeout', message: 'Scan timeout exceeded' });
          }
          
          const url = `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${targetId}/scans/${scanType}`;
          debugTrace(`Fetching scan status from: ${url}`);
          
          const response = await fetch(url);
          
          if (!response.ok) {
            debugTrace(`Failed to fetch ${scanType} scan status: ${response.status} ${response.statusText}`);
            
            // If we get a 404 or other error after multiple attempts, let's proceed rather than getting stuck
            if (attempts > 10) {
              debugTrace(`${scanType} scan failed to fetch status after ${attempts} attempts, proceeding with next step`);
              setIsScanning(false);
              clearTimeout(hardTimeout); // Clear the hard timeout
              return resolve({ status: 'error', message: 'Failed to fetch scan status' });
            }
            
            // If we get a 404 or other error, we'll check again after a delay
            setTimeout(checkStatus, 5000);
            return;
          }
          
          const scans = await response.json();
          debugTrace(`Retrieved ${scans?.length || 0} ${scanType} scans`);
          
          // Handle case where there are no scans after multiple attempts
          if (!scans || !Array.isArray(scans) || scans.length === 0) {
            debugTrace(`No ${scanType} scans found, will check again`);
            
            if (attempts > 10) {
              debugTrace(`${scanType} scan returned no scans after ${attempts} attempts, proceeding with next step`);
              setIsScanning(false);
              clearTimeout(hardTimeout); // Clear the hard timeout
              return resolve({ status: 'no_scans', message: 'No scans found' });
            }
            
            setTimeout(checkStatus, 5000);
            return;
          }
          
          // Find the most recent scan
          const mostRecentScan = scans.reduce((latest, scan) => {
            const scanDate = new Date(scan.created_at);
            return scanDate > new Date(latest.created_at) ? scan : latest;
          }, scans[0]);
          
          debugTrace(`Most recent ${scanType} scan status: ${mostRecentScan.status}, ID: ${mostRecentScan.id || 'unknown'}`);
          
          // Update status in UI
          setMostRecentScanStatus(mostRecentScan.status);
          
          if (mostRecentScan.status === 'completed' || 
              mostRecentScan.status === 'success' || 
              mostRecentScan.status === 'failed' || 
              mostRecentScan.status === 'error') {  // Also consider 'error' status as completed
            debugTrace(`${scanType} scan finished with status: ${mostRecentScan.status}`);
            setIsScanning(false);
            clearTimeout(hardTimeout); // Clear the hard timeout
            resolve(mostRecentScan);
          } else if (mostRecentScan.status === 'processing') {
            // The scan is complete but still processing large results (e.g., GAU with >1000 URLs)
            debugTrace(`${scanType} scan is still processing large results, checking again in 5 seconds`);
            setTimeout(checkStatus, 5000);
          } else {
            // Still pending or another status, check again after delay
            debugTrace(`${scanType} scan still pending (status: ${mostRecentScan.status}), checking again in 5 seconds`);
            setTimeout(checkStatus, 5000);
          }
        } catch (error) {
          debugTrace(`Error checking ${scanType} scan status: ${error.message}\n${error.stack}`);
          
          // If we have persistent errors after multiple attempts, proceed rather than getting stuck
          if (attempts > 10) {
            debugTrace(`${scanType} scan had persistent errors after ${attempts} attempts, proceeding with next step`);
            setIsScanning(false);
            clearTimeout(hardTimeout); // Clear the hard timeout
            return resolve({ status: 'persistent_error', message: 'Persistent errors checking scan status' });
          }
          
          // Don't reject immediately on errors, try again after a delay
          setTimeout(checkStatus, 5000);
        }
      };
      
      // Start checking status immediately
      checkStatus();
    }),
    // Add a separate timeout promise as a backstop
    new Promise((resolve) => {
      setTimeout(() => {
        debugTrace(`BACKUP TIMEOUT: ${scanType} scan timed out at 20 minutes absolute maximum`);
        setIsScanning(false);
        resolve({ status: 'absolute_timeout', message: 'Absolute timeout exceeded' });
      }, 20 * 60 * 1000); // 20 minutes absolute maximum
    })
  ]);
};

const startAutoScan = async (
  activeTarget,
  getAutoScanSteps,
  setIsAutoScanning,
  setAutoScanCurrentStep,
  setAutoScanTargetId,
  setIsGauScanning,
  setMostRecentGauScan,
  setMostRecentGauScanStatus,
  setIsCTLScanning,
  setMostRecentCTLScan,
  setMostRecentCTLScanStatus,
  setIsSubfinderScanning,
  setMostRecentSubfinderScan,
  setMostRecentSubfinderScanStatus,
  setIsConsolidating,
  handleConsolidate,
  setIsHttpxScanning,
  setMostRecentHttpxScan,
  setMostRecentHttpxScanStatus,
  setIsNucleiScreenshotScanning,
  setMostRecentNucleiScreenshotScan,
  setMostRecentNucleiScreenshotScanStatus,
  setIsMetaDataScanning,
  setMostRecentMetaDataScan,
  setMostRecentMetaDataScanStatus,
  startMetaDataScan,
  initiateSubfinderScan,
  initiateHttpxScan,
  initiateNucleiScreenshotScan,
  setSubfinderScans,
  setHttpxScans,
  setNucleiScreenshotScans,
  setMetaDataScans,
  monitorSubfinderScanStatus,
  monitorHttpxScanStatus,
  monitorNucleiScreenshotScanStatus,
  monitorMetaDataScanStatus,
  initiateMetaDataScan,
  initiateCTLScan,
  monitorCTLScanStatus,
  setCTLScans,
  setGauScans,
  scanType = SCAN_TYPES.QUICK
) => {
  if (!activeTarget) return;
  
  // Initialize auto scan state - don't clear previous state until we're done
  debugTrace(`Starting ${scanType} scan for target ID: ${activeTarget.id}`);
  setIsAutoScanning(true);
  setAutoScanCurrentStep(AUTO_SCAN_STEPS.IDLE);
  setAutoScanTargetId(activeTarget.id);
  
  localStorage.setItem('autoScanTargetId', activeTarget.id);
  localStorage.setItem('autoScanCurrentStep', AUTO_SCAN_STEPS.IDLE);
  localStorage.setItem('autoScanType', scanType);
  debugTrace(`localStorage initialized: autoScanTargetId=${activeTarget.id}, autoScanCurrentStep=${AUTO_SCAN_STEPS.IDLE}, autoScanType=${scanType}`);
  
  try {
    const steps = getAutoScanSteps();
    
    debugTrace(`Running a full scan with all ${steps.length} steps`);
    
    // Execute each step in sequence - always run all steps regardless of scan type
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      debugTrace(`Starting step ${i+1}/${steps.length}: ${step.name}`);
      
      // Make sure we update the current step in localStorage AND in state before executing the action
      try {
        setAutoScanCurrentStep(step.name);
        localStorage.setItem('autoScanCurrentStep', step.name);
        debugTrace(`Updated current step in localStorage to ${step.name}`);
        
        // Force a delay to ensure the state is updated before executing the action
        await new Promise(resolve => setTimeout(resolve, 100));
        
        await step.action();
        debugTrace(`Completed step ${step.name}`);
      } catch (error) {
        debugTrace(`Error in step ${step.name}: ${error.message}`);
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    debugTrace(`All steps completed`);
  } catch (error) {
    debugTrace(`ERROR during ${scanType} scan: ${error.message}`);
  } finally {
    // Only clear the localStorage at the very end when we're completely done
    debugTrace("Auto Scan session finalizing - setting state to COMPLETED");
    setIsAutoScanning(false);
    setAutoScanCurrentStep(AUTO_SCAN_STEPS.COMPLETED);
    localStorage.setItem('autoScanCurrentStep', AUTO_SCAN_STEPS.COMPLETED);
    debugTrace("localStorage updated: autoScanCurrentStep=" + AUTO_SCAN_STEPS.COMPLETED);
    debugTrace("Auto Scan session ended");
  }
};

export { startAutoScan, waitForScanCompletion, AUTO_SCAN_STEPS, SCAN_TYPES, debugTrace }; 