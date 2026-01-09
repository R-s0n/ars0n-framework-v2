import { AUTO_SCAN_STEPS, waitForScanCompletion, debugTrace, waitForCeWLAndShuffleDNSCustom, updateAutoScanState } from './wildcardAutoScan';
import initiateGauScan from './initiateGauScan';
import initiateCTLScan from './initiateCTLScan';
import initiateSubfinderScan from './initiateSubfinderScan';
import initiateHttpxScan from './initiateHttpxScan';
import initiateShuffleDNSScan from './initiateShuffleDNSScan';
import initiateCeWLScan from './initiateCeWLScan';
import initiateNucleiScreenshotScan from './initiateNucleiScreenshotScan';
import initiateMetaDataScan from './initiateMetaDataScan';
import fetchHttpxScans from './fetchHttpxScans';
import initiateGoSpiderScan from './initiateGoSpiderScan';
import initiateSubdomainizerScan from './initiateSubdomainizerScan';
import initiateAmassScan from './initiateAmassScan';
import { getHttpxResultsCount } from './miscUtils';

const getAutoScanSteps = (
  activeTarget,
  setAutoScanCurrentStep,
  // Scanning states
  setIsScanning,
  setIsSublist3rScanning,
  setIsAssetfinderScanning,
  setIsGauScanning,
  setIsCTLScanning,
  setIsSubfinderScanning,
  setIsConsolidating,
  setIsHttpxScanning,
  setIsShuffleDNSScanning,
  setIsCeWLScanning,
  setIsGoSpiderScanning,
  setIsSubdomainizerScanning,
  setIsNucleiScreenshotScanning,
  setIsMetaDataScanning,
  // Scans state updaters
  setAmassScans,
  setSublist3rScans,
  setAssetfinderScans,
  setGauScans,
  setCTLScans,
  setSubfinderScans,
  setHttpxScans,
  setShuffleDNSScans,
  setCeWLScans,
  setGoSpiderScans,
  setSubdomainizerScans,
  setNucleiScreenshotScans,
  setMetaDataScans,
  setSubdomains,
  setShuffleDNSCustomScans,
  // Most recent scan updaters
  setMostRecentAmassScan,
  setMostRecentSublist3rScan,
  setMostRecentAssetfinderScan,
  setMostRecentGauScan,
  setMostRecentCTLScan,
  setMostRecentSubfinderScan,
  setMostRecentHttpxScan,
  setMostRecentShuffleDNSScan,
  setMostRecentCeWLScan,
  setMostRecentGoSpiderScan,
  setMostRecentSubdomainizerScan,
  setMostRecentNucleiScreenshotScan,
  setMostRecentMetaDataScan,
  setMostRecentShuffleDNSCustomScan,
  // Status updaters
  setMostRecentAmassScanStatus,
  setMostRecentSublist3rScanStatus,
  setMostRecentAssetfinderScanStatus,
  setMostRecentGauScanStatus,
  setMostRecentCTLScanStatus,
  setMostRecentSubfinderScanStatus,
  setMostRecentHttpxScanStatus,
  setMostRecentShuffleDNSScanStatus,
  setMostRecentCeWLScanStatus,
  setMostRecentGoSpiderScanStatus,
  setMostRecentSubdomainizerScanStatus,
  setMostRecentNucleiScreenshotScanStatus,
  setMostRecentMetaDataScanStatus,
  setMostRecentShuffleDNSCustomScanStatus,
  // Other functions
  handleConsolidate,
  config,
  autoScanSessionId
) => {
  const steps = [
    { name: AUTO_SCAN_STEPS.AMASS, action: async () => {
      if (config && config.amass === false) {
        console.log('[AutoScan] Step: amass is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: amass is ENABLED. Running.');
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.AMASS);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.AMASS);
      
      try {
        // Start the scan
        await initiateAmassScan(
          activeTarget,
          null, // Don't use the built-in monitor function
          setIsScanning,
          setAmassScans,
          setMostRecentAmassScanStatus,
          null, // setDnsRecords - not needed for Auto Scan workflow
          null, // setSubdomains - we'll consolidate later
          null, // setCloudDomains - not needed for Auto Scan workflow
          setMostRecentAmassScan,
          autoScanSessionId
        );
        
        // Wait for scan completion
        const completedScan = await waitForScanCompletion(
          'amass',
          activeTarget.id,
          setIsScanning,
          setMostRecentAmassScanStatus,
          setMostRecentAmassScan
        );
        
        // Explicitly fetch the latest results to update UI
        const response = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/amass`
        );
        
        if (response.ok) {
          const scans = await response.json();
          setAmassScans(scans || []);
          
          if (Array.isArray(scans) && scans.length > 0) {
            // Find the most recent scan
            const mostRecentScan = scans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, scans[0]);
            
            // Update the UI state
            setMostRecentAmassScan(mostRecentScan);
            setMostRecentAmassScanStatus(mostRecentScan.status);
          }
        }
        
        console.log('[AutoScan] Step: amass completed.');
      } catch (error) {
        console.error('[AutoScan] Step: amass ERROR:', error);
      }
    }},
    { name: AUTO_SCAN_STEPS.SUBLIST3R, action: async () => {
      if (config && config.sublist3r === false) {
        console.log('[AutoScan] Step: sublist3r is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: sublist3r is ENABLED. Running.');
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.SUBLIST3R);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.SUBLIST3R);
      setIsSublist3rScanning(true);
      
      try {
        const domain = activeTarget.scope_target.replace('*.', '');
        const scanResponse = await fetch(
          `/api/sublist3r/run`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              fqdn: domain,
              auto_scan_session_id: autoScanSessionId
            }),
          }
        );
        
        if (!scanResponse.ok) {
          throw new Error(`Failed to start Sublist3r scan: ${scanResponse.status} ${scanResponse.statusText}`);
        }
        
        const scanData = await scanResponse.json();
        
        const placeholderScan = {
          id: scanData.scan_id,
          status: 'pending',
          created_at: new Date().toISOString()
        };
        setMostRecentSublist3rScan(placeholderScan);
        setMostRecentSublist3rScanStatus('pending');
        
        let isComplete = false;
        let attempts = 0;
        const maxAttempts = 60; // 5 minute timeout (60 x 5 seconds)
        
        while (!isComplete && attempts < maxAttempts) {
          attempts++;
          await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
          
          
          const statusResponse = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans/sublist3r`
          );
          
          if (!statusResponse.ok) {
            debugTrace(`Failed to fetch scan status: ${statusResponse.status} ${statusResponse.statusText}`);
            continue; // Try again
          }
          
          const scans = await statusResponse.json();
          
          if (!scans || !Array.isArray(scans) || scans.length === 0) {
            debugTrace("No scans found, will try again");
            continue;
          }
          
          const mostRecentScan = scans.reduce((latest, scan) => {
            const scanDate = new Date(scan.created_at);
            return scanDate > new Date(latest.created_at) ? scan : latest;
          }, scans[0]);
                    
          setMostRecentSublist3rScan(mostRecentScan);
          setMostRecentSublist3rScanStatus(mostRecentScan.status);
          
          if (mostRecentScan.status === 'completed' || mostRecentScan.status === 'success' || mostRecentScan.status === 'failed') {
            isComplete = true;
            setIsSublist3rScanning(false);
          }
        }
        
        if (!isComplete) {
          debugTrace("Sublist3r scan timed out, moving to next step anyway");
        }
        
        setIsSublist3rScanning(false);
        
        console.log('[AutoScan] Step: sublist3r completed.');
        return { success: true };
      } catch (error) {
        debugTrace(`Error with Sublist3r scan: ${error.message}`);
        setIsSublist3rScanning(false);
        console.error('[AutoScan] Step: sublist3r ERROR:', error);
        return { success: false, error: error.message };
      }
    }},
    { name: AUTO_SCAN_STEPS.ASSETFINDER, action: async () => {
      if (config && config.assetfinder === false) {
        console.log('[AutoScan] Step: assetfinder is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: assetfinder is ENABLED. Running.');
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.ASSETFINDER);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.ASSETFINDER);
      setIsAssetfinderScanning(true);
      
      try {
        debugTrace("Initiating Assetfinder scan directly via API...");
        
        // 1. Start the scan
        const domain = activeTarget.scope_target.replace('*.', '');
        const scanResponse = await fetch(
          `/api/assetfinder/run`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              fqdn: domain,
              auto_scan_session_id: autoScanSessionId
            }),
          }
        );
        
        if (!scanResponse.ok) {
          throw new Error(`Failed to start Assetfinder scan: ${scanResponse.status} ${scanResponse.statusText}`);
        }
        
        const scanData = await scanResponse.json();
        
        // Create a placeholder scan object to update UI immediately
        const placeholderScan = {
          id: scanData.scan_id,
          status: 'pending',
          created_at: new Date().toISOString()
        };
        setMostRecentAssetfinderScan(placeholderScan);
        setMostRecentAssetfinderScanStatus('pending');
        
        let isComplete = false;
        let attempts = 0;
        const maxAttempts = 60; // 5 minute timeout (60 x 5 seconds)
        
        while (!isComplete && attempts < maxAttempts) {
          attempts++;
          await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
                    
          const statusResponse = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans/assetfinder`
          );
          
          if (!statusResponse.ok) {
            debugTrace(`Failed to fetch scan status: ${statusResponse.status} ${statusResponse.statusText}`);
            continue; // Try again
          }
          
          const scans = await statusResponse.json();
          
          if (!scans || !Array.isArray(scans) || scans.length === 0) {
            debugTrace("No scans found, will try again");
            continue;
          }
          
          const mostRecentScan = scans.reduce((latest, scan) => {
            const scanDate = new Date(scan.created_at);
            return scanDate > new Date(latest.created_at) ? scan : latest;
          }, scans[0]);
                    
          setMostRecentAssetfinderScan(mostRecentScan);
          setMostRecentAssetfinderScanStatus(mostRecentScan.status);
          
          if (mostRecentScan.status === 'completed' || mostRecentScan.status === 'success' || mostRecentScan.status === 'failed') {
            isComplete = true;
            setIsAssetfinderScanning(false);
          }
        }
        
        if (!isComplete) {
          debugTrace("Assetfinder scan timed out, moving to next step anyway");
        }
        
        setIsAssetfinderScanning(false);
        
        console.log('[AutoScan] Step: assetfinder completed.');
        return { success: true };
      } catch (error) {
        debugTrace(`Error with Assetfinder scan: ${error.message}`);
        setIsAssetfinderScanning(false);
        console.error('[AutoScan] Step: assetfinder ERROR:', error);
        return { success: false, error: error.message };
      }
    }},
    { name: AUTO_SCAN_STEPS.GAU, action: async () => {
      if (config && config.gau === false) {
        console.log('[AutoScan] Step: gau is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: gau is ENABLED. Running.');
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.GAU);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.GAU);
      
      try {
        // Start the scan
        await initiateGauScan(
          activeTarget,
          null, // Don't use the built-in monitor function
          setIsGauScanning,
          setGauScans,
          setMostRecentGauScanStatus,
          setMostRecentGauScan,
          autoScanSessionId
        );
        
        // Wait for scan completion
        const completedScan = await waitForScanCompletion(
          'gau',
          activeTarget.id,
          setIsGauScanning,
          setMostRecentGauScanStatus,
          setMostRecentGauScan
        );
        
        // Explicitly fetch the latest results to update UI
        const response = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/gau`
        );
        
        if (response.ok) {
          const scans = await response.json();
          setGauScans(scans || []);
          
          if (Array.isArray(scans) && scans.length > 0) {
            // Find the most recent scan
            const mostRecentScan = scans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, scans[0]);
            
            // Update the UI state
            setMostRecentGauScan(mostRecentScan);
            setMostRecentGauScanStatus(mostRecentScan.status);
          }
        }
        
        console.log('[AutoScan] Step: gau completed.');
      } catch (error) {
        console.error('[AutoScan] Step: gau ERROR:', error);
      }
    }},
    { name: AUTO_SCAN_STEPS.CTL, action: async () => {
      if (config && config.ctl === false) {
        console.log('[AutoScan] Step: ctl is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: ctl is ENABLED. Running.');
      console.log("Starting CTL scan...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.CTL);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.CTL);
      
      try {
        // Start the scan
        await initiateCTLScan(
          activeTarget,
          null,
          setIsCTLScanning,
          setCTLScans,
          setMostRecentCTLScanStatus,
          setMostRecentCTLScan,
          autoScanSessionId
        );
        
        // Wait for scan completion
        const completedScan = await waitForScanCompletion(
          'ctl',
          activeTarget.id,
          setIsCTLScanning,
          setMostRecentCTLScanStatus,
          setMostRecentCTLScan
        );
        
        // Explicitly fetch the latest results to update UI
        const response = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/ctl`
        );
        
        if (response.ok) {
          const scans = await response.json();
          setCTLScans(scans || []);
          
          if (Array.isArray(scans) && scans.length > 0) {
            // Find the most recent scan
            const mostRecentScan = scans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, scans[0]);
            
            // Update the UI state
            setMostRecentCTLScan(mostRecentScan);
            setMostRecentCTLScanStatus(mostRecentScan.status);
          }
        }
        
        console.log('[AutoScan] Step: ctl completed.');
      } catch (error) {
        console.error('[AutoScan] Step: ctl ERROR:', error);
      }
    }},
    { name: AUTO_SCAN_STEPS.SUBFINDER, action: async () => {
      if (config && config.subfinder === false) {
        console.log('[AutoScan] Step: subfinder is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: subfinder is ENABLED. Running.');
      console.log("Starting Subfinder scan...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.SUBFINDER);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.SUBFINDER);
      
      try {
        // Start the scan
        await initiateSubfinderScan(
          activeTarget,
          null,
          setIsSubfinderScanning,
          setSubfinderScans,
          setMostRecentSubfinderScanStatus,
          setMostRecentSubfinderScan,
          autoScanSessionId
        );
        
        // Wait for scan completion
        const completedScan = await waitForScanCompletion(
          'subfinder',
          activeTarget.id,
          setIsSubfinderScanning,
          setMostRecentSubfinderScanStatus,
          setMostRecentSubfinderScan
        );
        
        // Explicitly fetch the latest results to update UI
        const response = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/subfinder`
        );
        
        if (response.ok) {
          const scans = await response.json();
          setSubfinderScans(scans || []);
          
          if (Array.isArray(scans) && scans.length > 0) {
            // Find the most recent scan
            const mostRecentScan = scans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, scans[0]);
            
            // Update the UI state
            setMostRecentSubfinderScan(mostRecentScan);
            setMostRecentSubfinderScanStatus(mostRecentScan.status);
          }
        }
        
        console.log('[AutoScan] Step: subfinder completed.');
      } catch (error) {
        console.error('[AutoScan] Step: subfinder ERROR:', error);
      }
    }},
    { name: AUTO_SCAN_STEPS.CONSOLIDATE, action: async () => {
      if (config && config.consolidate_httpx_round1 === false) {
        console.log('[AutoScan] Step: consolidate_httpx_round1 is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: consolidate_httpx_round1 is ENABLED. Running.');
      console.log("Starting Consolidation process...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.CONSOLIDATE);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.CONSOLIDATE);
      
      try {
        // Add a short delay before starting consolidation to ensure all previous operations are fully complete
        debugTrace("Adding a 3-second buffer before starting consolidation...");
        await new Promise(resolve => setTimeout(resolve, 3000));
        debugTrace("Buffer completed, starting consolidation");
        
        setIsConsolidating(true);
        
        // Perform the consolidation
        await handleConsolidate();
        
        // After consolidation is complete, fetch updated data
        try {
          // Fetch updated subdomain data to refresh UI
          const subdomainsResponse = await fetch(
            `/api/consolidated-subdomains/${activeTarget.id}`,
            {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
            }
        );
          
          if (subdomainsResponse.ok) {
            const data = await subdomainsResponse.json();
            setSubdomains(data.subdomains || []);
            
            // Check if consolidated subdomains exceed the limit
            if (data.subdomains && 
                Array.isArray(data.subdomains) && 
                config && 
                config.maxConsolidatedSubdomains && 
                data.subdomains.length > config.maxConsolidatedSubdomains) {
              
              console.log(`[AutoScan] Consolidated subdomains (${data.subdomains.length}) exceed the configured limit (${config.maxConsolidatedSubdomains}). Pausing the scan.`);
              
              // Pause the scan by updating the server state
              await fetch(
                `/api/api/auto-scan-state/${activeTarget.id}`,
                {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ 
                    current_step: AUTO_SCAN_STEPS.CONSOLIDATE,
                    is_paused: true,
                    is_cancelled: false
                  })
                }
              );
            }
          }
          
          // Fetch updated scan data
          const scansResponse = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans`
          );
          
          if (scansResponse.ok) {
            const scans = await scansResponse.json();
            // Update UI with consolidation results if there's state for it
            // (You may need to add state variables for this if they don't exist)
          }
        } catch (error) {
          console.error("Error fetching updated data after consolidation:", error);
        }
        
        setIsConsolidating(false);
        console.log('[AutoScan] Step: consolidate_httpx_round1 completed.');
      } catch (error) {
        console.error('[AutoScan] Step: consolidate_httpx_round1 ERROR:', error);
        setIsConsolidating(false);
      }
    }},
    { name: AUTO_SCAN_STEPS.HTTPX, action: async () => {
      if (config && config.consolidate_httpx_round1 === false) {
        console.log('[AutoScan] Step: consolidate_httpx_round1 is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: consolidate_httpx_round1 is ENABLED. Running.');
      console.log("Starting HTTPX Scan on consolidated subdomains...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.HTTPX);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.HTTPX);
      
      try {
        // Start the scan
        await initiateHttpxScan(
          activeTarget,
          null,
          setIsHttpxScanning,
          setHttpxScans,
          setMostRecentHttpxScanStatus,
          setMostRecentHttpxScan,
          autoScanSessionId
        );
        
        // Wait for scan completion - explicitly pass setMostRecentHttpxScan
        await waitForScanCompletion(
          'httpx',
          activeTarget.id,
          setIsHttpxScanning,
          setMostRecentHttpxScanStatus,
          setMostRecentHttpxScan
        );
        
        // Add a short buffer before fetching results
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Use the fetchHttpxScans function - this is what happens on page refresh
        const scanDetails = await fetchHttpxScans(
          activeTarget, 
          setHttpxScans, 
          setMostRecentHttpxScan, 
          setMostRecentHttpxScanStatus
        );

        console.error(scanDetails);
        
        let liveWebServersCount = 0;
        if (scanDetails) {
          // Get the count of live web servers directly from scanDetails
          liveWebServersCount = getHttpxResultsCount(scanDetails);
        }
              
        // Fix config if it's using PascalCase instead of camelCase
        if (config && config.MaxLiveWebServers !== undefined && config.maxLiveWebServers === undefined) {
          config.maxLiveWebServers = config.MaxLiveWebServers;
        }
        
        if (config && 
            config.maxLiveWebServers && 
            liveWebServersCount > config.maxLiveWebServers) {
          
          console.log(`[AutoScan] Live web servers (${liveWebServersCount}) exceed the configured limit (${config.maxLiveWebServers}). Pausing the scan.`);
          
          // Pause the scan by updating the server state
          try {
            console.log("[AutoScan] DEBUG: Sending pause request to server");
            const pauseResponse = await fetch(
              `/api/api/auto-scan-state/${activeTarget.id}`,
              {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                  current_step: AUTO_SCAN_STEPS.HTTPX,
                  is_paused: true,
                  is_cancelled: false
                })
              }
            );
            
            console.log("[AutoScan] DEBUG: Pause request status:", pauseResponse.status);
            if (!pauseResponse.ok) {
              console.log("[AutoScan] DEBUG: Pause request failed:", await pauseResponse.text());
            } else {
              console.log("[AutoScan] DEBUG: Pause request successful");
            }
          } catch (error) {
            console.log("[AutoScan] DEBUG: Error sending pause request:", error);
          }
        }
        
        // Force a reset of the scanning state
        setIsHttpxScanning(false);
        
        console.log('[AutoScan] Step: consolidate_httpx_round1 completed.');
      } catch (error) {
        console.error('[AutoScan] Step: consolidate_httpx_round1 ERROR:', error);
        setIsHttpxScanning(false);
      }
    }},
    { name: AUTO_SCAN_STEPS.SHUFFLEDNS, action: async () => {
      if (config && config.shuffledns === false) {
        console.log('[AutoScan] Step: shuffledns is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: shuffledns is ENABLED. Running.');
      console.log("Starting ShuffleDNS Scan...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.SHUFFLEDNS);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.SHUFFLEDNS);
      
      try {
        // Start the scan
        await initiateShuffleDNSScan(
          activeTarget,
          null,
          setIsShuffleDNSScanning,
          setShuffleDNSScans,
          setMostRecentShuffleDNSScanStatus,
          setMostRecentShuffleDNSScan,
          autoScanSessionId
        );
        
        // Wait for scan completion
        const completedScan = await waitForScanCompletion(
          'shuffledns',
          activeTarget.id,
          setIsShuffleDNSScanning,
          setMostRecentShuffleDNSScanStatus,
          setMostRecentShuffleDNSScan
        );
        
        // Explicitly fetch the latest results to update UI
        const response = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/shuffledns`
        );
        
        if (response.ok) {
          const scans = await response.json();
          setShuffleDNSScans(scans || []);
          
          if (Array.isArray(scans) && scans.length > 0) {
            // Find the most recent scan
            const mostRecentScan = scans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, scans[0]);
            
            // Update the UI state
            setMostRecentShuffleDNSScan(mostRecentScan);
            setMostRecentShuffleDNSScanStatus(mostRecentScan.status);
          }
        }
        
        console.log('[AutoScan] Step: shuffledns completed.');
      } catch (error) {
        console.error('[AutoScan] Step: shuffledns ERROR:', error);
      }
    }},
    { name: AUTO_SCAN_STEPS.SHUFFLEDNS_CEWL, action: async () => {
      if (config && config.cewl === false) {
        console.log('[AutoScan] Step: cewl is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: cewl is ENABLED. Running.');
      console.log("Starting ShuffleDNS w/ Custom Wordlist Scan...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.SHUFFLEDNS_CEWL);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.SHUFFLEDNS_CEWL);
      
      try {
        // Start the CeWL scan
        await initiateCeWLScan(
          activeTarget,
          null,
          setIsCeWLScanning,
          setCeWLScans,
          setMostRecentCeWLScanStatus,
          setMostRecentCeWLScan,
          autoScanSessionId
        );
        
        // Wait for both CeWL scan AND ShuffleDNS custom scan to complete
        await waitForCeWLAndShuffleDNSCustom(
          activeTarget,
          setIsCeWLScanning,
          setMostRecentCeWLScanStatus,
          setMostRecentCeWLScan,
          setMostRecentShuffleDNSCustomScanStatus,
          setMostRecentShuffleDNSCustomScan,
          autoScanSessionId
        );
        
        // Explicitly fetch the latest CeWL results to update UI
        const cewlResponse = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/cewl`
        );
        
        if (cewlResponse.ok) {
          const cewlScans = await cewlResponse.json();
          setCeWLScans(cewlScans || []);
          
          if (Array.isArray(cewlScans) && cewlScans.length > 0) {
            // Find the most recent CeWL scan
            const mostRecentCeWLScan = cewlScans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, cewlScans[0]);
            
            // Update the UI state
            setMostRecentCeWLScan(mostRecentCeWLScan);
            setMostRecentCeWLScanStatus(mostRecentCeWLScan.status);
          }
        }
        
        // Fetch ShuffleDNS custom scans
        const shuffleDNSCustomResponse = await fetch(
          `/api/api/scope-targets/${activeTarget.id}/shufflednscustom-scans`
        );
        
        if (shuffleDNSCustomResponse.ok) {
          const shuffleDNSCustomScans = await shuffleDNSCustomResponse.json();
          setShuffleDNSCustomScans(shuffleDNSCustomScans || []);
          
          if (Array.isArray(shuffleDNSCustomScans) && shuffleDNSCustomScans.length > 0) {
            // Find the most recent ShuffleDNS custom scan
            const mostRecentScan = shuffleDNSCustomScans[0]; // Already ordered by created_at DESC
            
            // Update the UI state
            setMostRecentShuffleDNSCustomScan(mostRecentScan);
            setMostRecentShuffleDNSCustomScanStatus(mostRecentScan.status);
          }
        }
        
        // Add a 5-second delay before proceeding to consolidation to ensure all processes are fully completed
        debugTrace("Adding a 5-second buffer before proceeding to consolidation...");
        await new Promise(resolve => setTimeout(resolve, 5000));
        debugTrace("Buffer completed, proceeding to next step");
        
        console.log('[AutoScan] Step: cewl completed.');
      } catch (error) {
        console.error('[AutoScan] Step: cewl ERROR:', error);
      }
    }},
    { name: AUTO_SCAN_STEPS.CONSOLIDATE_ROUND2, action: async () => {
      if (config && config.consolidate_httpx_round2 === false) {
        console.log('[AutoScan] Step: consolidate_httpx_round2 is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: consolidate_httpx_round2 is ENABLED. Running.');
      console.log("Starting Consolidation process (Round 2)...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.CONSOLIDATE_ROUND2);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.CONSOLIDATE_ROUND2);
      
      try {
        // Add a short delay before starting consolidation to ensure all previous operations are fully complete
        debugTrace("Adding a 3-second buffer before starting consolidation (Round 2)...");
        await new Promise(resolve => setTimeout(resolve, 3000));
        debugTrace("Buffer completed, starting consolidation (Round 2)");
        
        setIsConsolidating(true);
        
        // Perform the consolidation
        await handleConsolidate();
        
        // After consolidation is complete, fetch updated data
        try {
          // Fetch updated subdomain data to refresh UI
          const subdomainsResponse = await fetch(
            `/api/consolidated-subdomains/${activeTarget.id}`
          );
          
          if (subdomainsResponse.ok) {
            const data = await subdomainsResponse.json();
            setSubdomains(data.subdomains || []);
            
            // Check if consolidated subdomains exceed the limit
            if (data.subdomains && 
                Array.isArray(data.subdomains) && 
                config && 
                config.maxConsolidatedSubdomains && 
                data.subdomains.length > config.maxConsolidatedSubdomains) {
              
              console.log(`[AutoScan] Consolidated subdomains (${data.subdomains.length}) exceed the configured limit (${config.maxConsolidatedSubdomains}). Pausing the scan.`);
              
              // Pause the scan by updating the server state
              await fetch(
                `/api/api/auto-scan-state/${activeTarget.id}`,
                {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ 
                    current_step: AUTO_SCAN_STEPS.CONSOLIDATE_ROUND2,
                    is_paused: true,
                    is_cancelled: false
                  })
                }
              );
            }
          }
          
          // Fetch updated scan data
          const scansResponse = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans`
          );
          
          if (scansResponse.ok) {
            const scans = await scansResponse.json();
            // Update UI with consolidation results if there's state for it
          }
        } catch (error) {
          console.error("Error fetching updated data after consolidation (Round 2):", error);
        }
        
        setIsConsolidating(false);
        console.log('[AutoScan] Step: consolidate_httpx_round2 completed.');
      } catch (error) {
        console.error('[AutoScan] Step: consolidate_httpx_round2 ERROR:', error);
        setIsConsolidating(false);
      }
    }},
    { name: AUTO_SCAN_STEPS.HTTPX_ROUND2, action: async () => {
      if (config && config.consolidate_httpx_round2 === false) {
        console.log('[AutoScan] Step: consolidate_httpx_round2 is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: consolidate_httpx_round2 is ENABLED. Running.');
      console.log("Starting HTTPX scan for Live Web Servers (Round 2)...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.HTTPX_ROUND2);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.HTTPX_ROUND2);
      
      try {
        // Start the scan
        await initiateHttpxScan(
          activeTarget,
          null,
          setIsHttpxScanning,
          setHttpxScans,
          setMostRecentHttpxScanStatus,
          setMostRecentHttpxScan,
          autoScanSessionId
        );
        
        // Wait for scan completion - pass setMostRecentHttpxScan so it gets updated
        await waitForScanCompletion(
          'httpx',
          activeTarget.id,
          setIsHttpxScanning,
          setMostRecentHttpxScanStatus,
          setMostRecentHttpxScan
        );
        
        // Add a short buffer before fetching results
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Use the fetchHttpxScans function - this is what happens on page refresh
        const scanDetails = await fetchHttpxScans(
          activeTarget, 
          setHttpxScans, 
          setMostRecentHttpxScan, 
          setMostRecentHttpxScanStatus
        );
        
        let liveWebServersCount = 0;
        if (scanDetails) {
          // Get the count of live web servers directly from scanDetails
          liveWebServersCount = getHttpxResultsCount(scanDetails);
        }
        
        console.log(`[AutoScan] Live web servers check (Round 2): count=${liveWebServersCount}, limit=${config?.maxLiveWebServers}`);
        
        if (config && 
            config.maxLiveWebServers && 
            liveWebServersCount > config.maxLiveWebServers) {
          
          console.log(`[AutoScan] Live web servers (${liveWebServersCount}) exceed the configured limit (${config.maxLiveWebServers}). Pausing the scan.`);
          
          // Pause the scan by updating the server state
          await fetch(
            `/api/api/auto-scan-state/${activeTarget.id}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                current_step: AUTO_SCAN_STEPS.HTTPX_ROUND2,
                is_paused: true,
                is_cancelled: false
              })
            }
          );
        }
        
        // Force a reset of the scanning state
        setIsHttpxScanning(false);
        
        console.log('[AutoScan] Step: consolidate_httpx_round2 completed.');
      } catch (error) {
        console.error('[AutoScan] Step: consolidate_httpx_round2 ERROR:', error);
        setIsHttpxScanning(false);
      }
    }},
    { name: AUTO_SCAN_STEPS.GOSPIDER, action: async () => {
      if (config && config.gospider === false) {
        console.log('[AutoScan] Step: gospider is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: gospider is ENABLED. Running.');
      console.log("Starting GoSpider Scan...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.GOSPIDER);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.GOSPIDER);
      
      try {
        // Start the scan
        await initiateGoSpiderScan(
          activeTarget,
          null, // Don't use the built-in monitor function
          setIsGoSpiderScanning,
          setGoSpiderScans,
          setMostRecentGoSpiderScanStatus,
          setMostRecentGoSpiderScan,
          autoScanSessionId
        );
        
        // Wait for scan completion
        const completedScan = await waitForScanCompletion(
          'gospider',
          activeTarget.id,
          setIsGoSpiderScanning,
          setMostRecentGoSpiderScanStatus,
          setMostRecentGoSpiderScan
        );
        
        // Explicitly fetch the latest results to update UI
        const response = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/gospider`
        );
        
        if (response.ok) {
          const scans = await response.json();
          setGoSpiderScans(scans || []);
          
          if (Array.isArray(scans) && scans.length > 0) {
            // Find the most recent scan
            const mostRecentScan = scans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, scans[0]);
            
            // Update the UI state
            setMostRecentGoSpiderScan(mostRecentScan);
            setMostRecentGoSpiderScanStatus(mostRecentScan.status);
          }
        }
        
        console.log('[AutoScan] Step: gospider completed.');
      } catch (error) {
        console.error('[AutoScan] Step: gospider ERROR:', error);
      }
    }},
    { name: AUTO_SCAN_STEPS.SUBDOMAINIZER, action: async () => {
      if (config && config.subdomainizer === false) {
        console.log('[AutoScan] Step: subdomainizer is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: subdomainizer is ENABLED. Running.');
      console.log("Starting Subdomainizer Scan...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.SUBDOMAINIZER);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.SUBDOMAINIZER);
      
      try {
        // Start the scan
        await initiateSubdomainizerScan(
          activeTarget,
          null, // Don't use the built-in monitor function
          setIsSubdomainizerScanning,
          setSubdomainizerScans,
          setMostRecentSubdomainizerScanStatus,
          setMostRecentSubdomainizerScan,
          autoScanSessionId
        );
        
        // Wait for scan completion
        const completedScan = await waitForScanCompletion(
          'subdomainizer',
          activeTarget.id,
          setIsSubdomainizerScanning,
          setMostRecentSubdomainizerScanStatus,
          setMostRecentSubdomainizerScan
        );
        
        // Explicitly fetch the latest results to update UI
        const response = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/subdomainizer`
        );
        
        if (response.ok) {
          const scans = await response.json();
          setSubdomainizerScans(scans || []);
          
          if (Array.isArray(scans) && scans.length > 0) {
            // Find the most recent scan
            const mostRecentScan = scans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, scans[0]);
            
            // Update the UI state
            setMostRecentSubdomainizerScan(mostRecentScan);
            setMostRecentSubdomainizerScanStatus(mostRecentScan.status);
          }
        }
        
        console.log('[AutoScan] Step: subdomainizer completed.');
      } catch (error) {
        console.error('[AutoScan] Step: subdomainizer ERROR:', error);
      }
    }},
    { name: AUTO_SCAN_STEPS.CONSOLIDATE_ROUND3, action: async () => {
      if (config && config.consolidate_httpx_round3 === false) {
        console.log('[AutoScan] Step: consolidate_httpx_round3 is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: consolidate_httpx_round3 is ENABLED. Running.');
      console.log("Starting Consolidation process (Round 3)...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.CONSOLIDATE_ROUND3);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.CONSOLIDATE_ROUND3);
      
      try {
        // Add a short delay before starting consolidation to ensure all previous operations are fully complete
        debugTrace("Adding a 3-second buffer before starting consolidation (Round 3)...");
        await new Promise(resolve => setTimeout(resolve, 3000));
        debugTrace("Buffer completed, starting consolidation (Round 3)");
        
        setIsConsolidating(true);
        
        // Perform the consolidation
        await handleConsolidate();
        
        // After consolidation is complete, fetch updated data
        try {
          // Fetch updated subdomain data to refresh UI
          const subdomainsResponse = await fetch(
            `/api/consolidated-subdomains/${activeTarget.id}`
          );
          
          if (subdomainsResponse.ok) {
            const data = await subdomainsResponse.json();
            setSubdomains(data.subdomains || []);
            
            // Check if consolidated subdomains exceed the limit
            if (data.subdomains && 
                Array.isArray(data.subdomains) && 
                config && 
                config.maxConsolidatedSubdomains && 
                data.subdomains.length > config.maxConsolidatedSubdomains) {
              
              console.log(`[AutoScan] Consolidated subdomains (${data.subdomains.length}) exceed the configured limit (${config.maxConsolidatedSubdomains}). Pausing the scan.`);
              
              // Pause the scan by updating the server state
              await fetch(
                `/api/api/auto-scan-state/${activeTarget.id}`,
                {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ 
                    current_step: AUTO_SCAN_STEPS.CONSOLIDATE_ROUND3,
                    is_paused: true,
                    is_cancelled: false
                  })
                }
              );
            }
          }
          
          // Fetch updated scan data
          const scansResponse = await fetch(
            `/api/scopetarget/${activeTarget.id}/scans`
          );
          
          if (scansResponse.ok) {
            const scans = await scansResponse.json();
            // Update UI with consolidation results if there's state for it
          }
        } catch (error) {
          console.error("Error fetching updated data after consolidation (Round 3):", error);
        }
        
        setIsConsolidating(false);
        console.log('[AutoScan] Step: consolidate_httpx_round3 completed.');
      } catch (error) {
        console.error('[AutoScan] Step: consolidate_httpx_round3 ERROR:', error);
        setIsConsolidating(false);
      }
    }},
    { name: AUTO_SCAN_STEPS.HTTPX_ROUND3, action: async () => {
      if (config && config.consolidate_httpx_round3 === false) {
        console.log('[AutoScan] Step: consolidate_httpx_round3 is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: consolidate_httpx_round3 is ENABLED. Running.');
      console.log("Starting HTTPX scan for Live Web Servers (Round 3)...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.HTTPX_ROUND3);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.HTTPX_ROUND3);
      
      try {
        // Start the scan
        await initiateHttpxScan(
          activeTarget,
          null,
          setIsHttpxScanning,
          setHttpxScans,
          setMostRecentHttpxScanStatus,
          setMostRecentHttpxScan,
          autoScanSessionId
        );
        
        // Wait for scan completion - pass setMostRecentHttpxScan so it gets updated
        await waitForScanCompletion(
          'httpx',
          activeTarget.id,
          setIsHttpxScanning,
          setMostRecentHttpxScanStatus,
          setMostRecentHttpxScan
        );
        
        // Add a short buffer before fetching results
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Use the fetchHttpxScans function - this is what happens on page refresh
        const scanDetails = await fetchHttpxScans(
          activeTarget, 
          setHttpxScans, 
          setMostRecentHttpxScan, 
          setMostRecentHttpxScanStatus
        );
        
        let liveWebServersCount = 0;
        if (scanDetails) {
          // Get the count of live web servers directly from scanDetails
          liveWebServersCount = getHttpxResultsCount(scanDetails);
        }
        
        console.log(`[AutoScan] Live web servers check (Round 3): count=${liveWebServersCount}, limit=${config?.maxLiveWebServers}`);
        
        if (config && 
            config.maxLiveWebServers && 
            liveWebServersCount > config.maxLiveWebServers) {
          
          console.log(`[AutoScan] Live web servers (${liveWebServersCount}) exceed the configured limit (${config.maxLiveWebServers}). Pausing the scan.`);
          
          // Pause the scan by updating the server state
          await fetch(
            `/api/api/auto-scan-state/${activeTarget.id}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                current_step: AUTO_SCAN_STEPS.HTTPX_ROUND3,
                is_paused: true,
                is_cancelled: false
              })
            }
          );
        }
        
        // Force a reset of the scanning state
        setIsHttpxScanning(false);
        
        console.log('[AutoScan] Step: consolidate_httpx_round3 completed.');
      } catch (error) {
        console.error('[AutoScan] Step: consolidate_httpx_round3 ERROR:', error);
        setIsHttpxScanning(false);
      }
    }},
    { name: AUTO_SCAN_STEPS.NUCLEI_SCREENSHOT, action: async () => {
      if (config && config.nuclei_screenshot === false) {
        console.log('[AutoScan] Step: nuclei_screenshot is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: nuclei_screenshot is ENABLED. Running.');
      console.log("Starting Nuclei Screenshot Scan...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.NUCLEI_SCREENSHOT);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.NUCLEI_SCREENSHOT);
      
      try {
        // Start the scan
        await initiateNucleiScreenshotScan(
          activeTarget,
          null,
          setIsNucleiScreenshotScanning,
          setNucleiScreenshotScans,
          setMostRecentNucleiScreenshotScanStatus,
          setMostRecentNucleiScreenshotScan,
          autoScanSessionId
        );
        
        // Wait for scan completion
        const completedScan = await waitForScanCompletion(
          'nuclei-screenshot',
          activeTarget.id,
          setIsNucleiScreenshotScanning,
          setMostRecentNucleiScreenshotScanStatus,
          setMostRecentNucleiScreenshotScan
        );
        
        // Explicitly fetch the latest results to update UI
        const response = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/nuclei-screenshot`
        );
        
        if (response.ok) {
          const scans = await response.json();
          setNucleiScreenshotScans(scans || []);
          
          if (Array.isArray(scans) && scans.length > 0) {
            // Find the most recent scan
            const mostRecentScan = scans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, scans[0]);
            
            // Update the UI state
            setMostRecentNucleiScreenshotScan(mostRecentScan);
            setMostRecentNucleiScreenshotScanStatus(mostRecentScan.status);
          }
        }
        
        console.log('[AutoScan] Step: nuclei_screenshot completed.');
      } catch (error) {
        console.error('[AutoScan] Step: nuclei_screenshot ERROR:', error);
      }
    }},
    { name: AUTO_SCAN_STEPS.METADATA, action: async () => {
      if (config && config.metadata === false) {
        console.log('[AutoScan] Step: metadata is DISABLED in config. Skipping.');
        return;
      }
      console.log('[AutoScan] Step: metadata is ENABLED. Running.');
      console.log("Starting MetaData Scan...");
      setAutoScanCurrentStep(AUTO_SCAN_STEPS.METADATA);
      await updateAutoScanState(activeTarget.id, AUTO_SCAN_STEPS.METADATA);
      
      try {
        // Start the scan
        await initiateMetaDataScan(
          activeTarget,
          null,
          setIsMetaDataScanning,
          setMetaDataScans,
          setMostRecentMetaDataScanStatus,
          setMostRecentMetaDataScan,
          autoScanSessionId
        );
        
        // Wait for scan completion
        const completedScan = await waitForScanCompletion(
          'metadata',
          activeTarget.id,
          setIsMetaDataScanning,
          setMostRecentMetaDataScanStatus,
          setMostRecentMetaDataScan
        );
        
        // Explicitly fetch the latest results to update UI
        const response = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/metadata`
        );
        
        if (response.ok) {
          const scans = await response.json();
          setMetaDataScans(scans || []);
          
          if (Array.isArray(scans) && scans.length > 0) {
            // Find the most recent scan
            const mostRecentScan = scans.reduce((latest, scan) => {
              const scanDate = new Date(scan.created_at);
              return scanDate > new Date(latest.created_at) ? scan : latest;
            }, scans[0]);
            
            // Update the UI state
            setMostRecentMetaDataScan(mostRecentScan);
            setMostRecentMetaDataScanStatus(mostRecentScan.status);
            
            // Also fetch the actual metadata results to populate UI
            if (mostRecentScan.id) {
              try {
                const metadataResponse = await fetch(
                  `/api/scopetarget/${activeTarget.id}/metadata`
                );
                
                if (metadataResponse.ok) {
                  const metadataData = await metadataResponse.json();
                  // We don't need to set additional metadata state here
                  // The scan object itself is already updated through setMostRecentMetaDataScan
                }
              } catch (metadataError) {
                console.error("Error fetching metadata results:", metadataError);
              }
            }
          }
        }
        
        console.log('[AutoScan] Step: metadata completed.');
      } catch (error) {
        console.error('[AutoScan] Step: metadata ERROR:', error);
      }
    }}
  ];
  if (config) {
    return steps.filter(step => config[step.name] !== false);
  }
  return steps;
};

export default getAutoScanSteps;