// Define the quick scan steps
const QUICK_SCAN_STEPS = {
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

const startQuickScan = async (
  activeTarget,
  getQuickScanSteps,
  setIsQuickScanning,
  setQuickScanCurrentStep,
  setQuickScanTargetId,
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
  setGauScans
) => {
  if (!activeTarget) return;
  
  // Initialize quick scan state - don't clear previous state until we're done
  debugTrace("Starting quick scan for target ID: " + activeTarget.id);
  setIsQuickScanning(true);
  setQuickScanCurrentStep(QUICK_SCAN_STEPS.IDLE);
  setQuickScanTargetId(activeTarget.id);
  
  localStorage.setItem('quickScanTargetId', activeTarget.id);
  localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.IDLE);
  debugTrace("localStorage initialized: quickScanTargetId=" + activeTarget.id + ", quickScanCurrentStep=" + QUICK_SCAN_STEPS.IDLE);
  
  try {
    const steps = getQuickScanSteps();
    
    try {
      await steps[0].action();
    } catch (error) {
      debugTrace(`Error in Sublist3r scan: ${error.message}`);
    }
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    try {
      await steps[1].action();
    } catch (error) {
      debugTrace(`Error in Assetfinder scan: ${error.message}`);
    }
    
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.GAU);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.GAU);
      debugTrace("localStorage updated: quickScanCurrentStep=" + QUICK_SCAN_STEPS.GAU);
      setIsGauScanning(true);
      
      const domain = activeTarget.scope_target.replace('*.', '');

      const scanResponse = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/gau/run`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            fqdn: domain,
            options: {
              subs: true,
              json: true,
              blacklist: ['ttf', 'woff', 'woff2', 'svg', 'png', 'jpg', 'jpeg', 'gif', 'css'],
              providers: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
              threads: 50,
              verbose: true
            }
          }),
        }
      );
              
      if (!scanResponse.ok) {
        throw new Error(`Failed to start GAU scan: ${scanResponse.status} ${scanResponse.statusText}`);
      }
      
      const scanData = await scanResponse.json();
      
      const placeholderScan = {
        id: scanData.scan_id,
        status: 'pending',
        created_at: new Date().toISOString()
      };

      setMostRecentGauScan(placeholderScan);
      setMostRecentGauScanStatus('pending');
      
      // Use the waitForScanCompletion function instead of custom polling
      const gauScanResult = await waitForScanCompletion(
        'gau',
        activeTarget.id,
        setIsGauScanning,
        setMostRecentGauScanStatus
      );
      
      debugTrace("GAU scan and processing completed");
      
      // Explicitly fetch the updated GAU scan results to refresh the UI
      try {
        const gauScansResponse = await fetch(
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/gau`
        );
        
        if (gauScansResponse.ok) {
          const gauScans = await gauScansResponse.json();
          if (gauScans && gauScans.length > 0) {
            // Find most recent scan
            const mostRecentScan = gauScans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, gauScans[0]);
            
            // Update state with the most recent scan which has the complete results
            setMostRecentGauScan(mostRecentScan);
            setGauScans(gauScans);
            debugTrace(`Updated GAU scan results with latest data`);
          }
        }
      } catch (updateError) {
        debugTrace(`Error updating GAU scan results: ${updateError.message}`);
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in GAU scan: ${error.message}`);
      debugTrace(`GAU scan encountered an error but continuing with next step: ${error.message}`);
      // Don't return or throw - allow scan to continue to next step
    }
    
    debugTrace("Moving to CTL scan...");
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.CTL);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.CTL);
      debugTrace("localStorage updated: quickScanCurrentStep=" + QUICK_SCAN_STEPS.CTL);
      setIsCTLScanning(true);
      
      try {
        await initiateCTLScan(
          activeTarget,
          monitorCTLScanStatus,
          setIsCTLScanning,
          setCTLScans,
          setMostRecentCTLScanStatus,
          setMostRecentCTLScan
        );
        
        debugTrace("CTL scan initiated, waiting for completion...");
        await waitForScanCompletion(
          'ctl',
          activeTarget.id,
          setIsCTLScanning,
          setMostRecentCTLScanStatus
        );
        
        debugTrace("CTL scan completed successfully");
      } catch (innerError) {
        debugTrace(`Error during CTL scan execution: ${innerError.message}`);
        // Ensure we set scanning to false if there was an error
        setIsCTLScanning(false);
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in CTL scan outer block: ${error.message}`);
      debugTrace(`CTL scan outer block error but continuing with next step: ${error.message}`);
      // Don't return or throw - allow scan to continue to next step
    }
    
    debugTrace("Moving to Subfinder scan...");
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.SUBFINDER);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.SUBFINDER);
      debugTrace("localStorage updated: quickScanCurrentStep=" + QUICK_SCAN_STEPS.SUBFINDER);
      
      try {
        await initiateSubfinderScan(
          activeTarget,
          monitorSubfinderScanStatus,
          setIsSubfinderScanning,
          setSubfinderScans,
          setMostRecentSubfinderScanStatus,
          setMostRecentSubfinderScan
        );
        
        debugTrace("Subfinder scan initiated, waiting for completion...");
        await waitForScanCompletion(
          'subfinder',
          activeTarget.id,
          setIsSubfinderScanning,
          setMostRecentSubfinderScanStatus
        );
        
        debugTrace("Subfinder scan completed successfully");
      } catch (innerError) {
        debugTrace(`Error during Subfinder scan execution: ${innerError.message}`);
        // Ensure we set scanning to false if there was an error
        setIsSubfinderScanning(false);
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in Subfinder scan outer block: ${error.message}`);
      debugTrace(`Subfinder scan encountered an error but continuing with next step: ${error.message}`);
      // Don't return or throw - allow scan to continue to next step
    }
    
    debugTrace("Moving to Consolidate step...");
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.CONSOLIDATE);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.CONSOLIDATE);
      debugTrace("localStorage updated: quickScanCurrentStep=" + QUICK_SCAN_STEPS.CONSOLIDATE);
      setIsConsolidating(true);
      
      await handleConsolidate();
      
      setIsConsolidating(false);
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in Consolidation: ${error.message}`);
      debugTrace(`Consolidation encountered an error but continuing with next step: ${error.message}`);
      setIsConsolidating(false); // Ensure this is set to false even on error
    }
    
    debugTrace("Moving to HTTPX scan...");
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.HTTPX);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.HTTPX);
      debugTrace("localStorage updated: quickScanCurrentStep=" + QUICK_SCAN_STEPS.HTTPX);
      
      try {
        await initiateHttpxScan(
          activeTarget,
          monitorHttpxScanStatus,
          setIsHttpxScanning,
          setHttpxScans,
          setMostRecentHttpxScanStatus,
          setMostRecentHttpxScan
        );
        
        debugTrace("HTTPX scan initiated, waiting for completion...");
        await waitForScanCompletion(
          'httpx',
          activeTarget.id,
          setIsHttpxScanning,
          setMostRecentHttpxScanStatus
        );
        
        debugTrace("HTTPX scan completed successfully");
      } catch (innerError) {
        debugTrace(`Error during HTTPX scan execution: ${innerError.message}`);
        // Ensure we set scanning to false if there was an error
        setIsHttpxScanning(false);
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in HTTPX scan outer block: ${error.message}`);
      debugTrace(`HTTPX scan encountered an error but continuing with next step: ${error.message}`);
    }
    
    debugTrace("Moving to Nuclei Screenshot scan...");
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.NUCLEI_SCREENSHOT);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.NUCLEI_SCREENSHOT);
      debugTrace("localStorage updated: quickScanCurrentStep=" + QUICK_SCAN_STEPS.NUCLEI_SCREENSHOT);
      
      try {
        await initiateNucleiScreenshotScan(
          activeTarget,
          monitorNucleiScreenshotScanStatus,
          setIsNucleiScreenshotScanning,
          setNucleiScreenshotScans,
          setMostRecentNucleiScreenshotScanStatus,
          setMostRecentNucleiScreenshotScan
        );
        
        debugTrace("Nuclei Screenshot scan initiated, waiting for completion...");
        await waitForScanCompletion(
          'nuclei-screenshot',
          activeTarget.id,
          setIsNucleiScreenshotScanning,
          setMostRecentNucleiScreenshotScanStatus
        );
        
        debugTrace("Nuclei Screenshot scan completed successfully");
      } catch (innerError) {
        debugTrace(`Error during Nuclei Screenshot scan execution: ${innerError.message}`);
        setIsNucleiScreenshotScanning(false);
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in Nuclei Screenshot scan outer block: ${error.message}`);
      debugTrace(`Nuclei Screenshot scan encountered an error but continuing with next step: ${error.message}`);
    }
    
    debugTrace("Moving to Metadata scan...");
    try {
      setQuickScanCurrentStep(QUICK_SCAN_STEPS.METADATA);
      localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.METADATA);
      debugTrace("localStorage updated: quickScanCurrentStep=" + QUICK_SCAN_STEPS.METADATA);
      
      try {
        await initiateMetaDataScan(
          activeTarget,
          monitorMetaDataScanStatus,
          setIsMetaDataScanning,
          setMetaDataScans,
          setMostRecentMetaDataScanStatus,
          setMostRecentMetaDataScan
        );
        
        debugTrace("Metadata scan initiated, waiting for completion...");
        await waitForScanCompletion(
          'metadata',
          activeTarget.id,
          setIsMetaDataScanning,
          setMostRecentMetaDataScanStatus
        );
        
        debugTrace("Metadata scan completed successfully");
      } catch (innerError) {
        debugTrace(`Error during Metadata scan execution: ${innerError.message}`);
        setIsMetaDataScanning(false);
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error in Metadata scan outer block: ${error.message}`);
      debugTrace(`Metadata scan encountered an error but continuing to finish quick scan: ${error.message}`);
    }
    
    debugTrace("All quick scan steps completed");
  } catch (error) {
    debugTrace(`ERROR during manual Quick Scan: ${error.message}`);
  } finally {
    // Only clear the localStorage at the very end when we're completely done
    debugTrace("Quick Scan session finalizing - setting state to COMPLETED");
    setIsQuickScanning(false);
    setQuickScanCurrentStep(QUICK_SCAN_STEPS.COMPLETED);
    localStorage.setItem('quickScanCurrentStep', QUICK_SCAN_STEPS.COMPLETED);
    debugTrace("localStorage updated: quickScanCurrentStep=" + QUICK_SCAN_STEPS.COMPLETED);
    debugTrace("Quick Scan session ended");
  }
};

export { startQuickScan, waitForScanCompletion, QUICK_SCAN_STEPS, debugTrace }; 