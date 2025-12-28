import { Row, Col, Button, Card, Alert, Spinner, ProgressBar } from 'react-bootstrap';
import { useState, useEffect, useRef, memo, useMemo } from 'react';
import AutoScanConfigModal from '../modals/autoScanConfigModal';
import { getHttpxResultsCount } from '../utils/miscUtils';

const ManageScopeTargets = memo(function ManageScopeTargets({ 
  handleOpen, 
  handleActiveModalOpen, 
  activeTarget, 
  scopeTargets, 
  getTypeIcon,
  onAutoScan,
  isAutoScanning,
  isAutoScanPaused,
  isAutoScanPausing,
  isAutoScanCancelling,
  setIsAutoScanPausing,
  setIsAutoScanCancelling,
  autoScanCurrentStep,
  mostRecentGauScanStatus,
  consolidatedSubdomains = [],
  mostRecentHttpxScan,
  onOpenAutoScanHistory
}) {
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [autoScanConfig, setAutoScanConfig] = useState(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [scanStartTime, setScanStartTime] = useState(null);
  const [scanEndTime, setScanEndTime] = useState(null);
  const [elapsed, setElapsed] = useState('');
  const [finalDuration, setFinalDuration] = useState('');
  const prevIsAutoScanning = useRef(isAutoScanning);
  const intervalRef = useRef(null);
  const [displayStatus, setDisplayStatus] = useState('idle');
  const resetTimeoutRef = useRef(null);
  const [isResuming, setIsResuming] = useState(false);

  useEffect(() => {
    const fetchConfig = async () => {
      setConfigLoading(true);
      try {
        const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-config`);
        if (response.ok) {
          const data = await response.json();
          setAutoScanConfig(data);
          console.log('[AutoScanConfig] Fetched from backend:', data);
        }
      } catch (e) {
        const fallback = {
          amass: true, sublist3r: true, assetfinder: true, gau: true, ctl: true, subfinder: true, consolidate_httpx_round1: true, shuffledns: true, cewl: true, consolidate_httpx_round2: true, gospider: true, subdomainizer: true, consolidate_httpx_round3: true, nuclei_screenshot: true, metadata: true, maxConsolidatedSubdomains: 2500, maxLiveWebServers: 500
        };
        setAutoScanConfig(fallback);
        console.log('[AutoScanConfig] Fallback to defaults:', fallback);
      } finally {
        setConfigLoading(false);
      }
    };
    fetchConfig();
  }, []);

  useEffect(() => {
    if (!prevIsAutoScanning.current && isAutoScanning) {
      // Scan starting
      setScanStartTime(new Date());
      setScanEndTime(null);
      setFinalDuration('');
      setDisplayStatus('running');
      
      // Clear any pending reset timeout
      if (resetTimeoutRef.current) {
        clearTimeout(resetTimeoutRef.current);
        resetTimeoutRef.current = null;
      }
    } else if (prevIsAutoScanning.current && !isAutoScanning) {
      // Scan completing
      setScanEndTime(new Date());
      setDisplayStatus('completed');
      
      if (scanStartTime) {
        const now = new Date();
        const diff = now - new Date(scanStartTime);
        const mins = Math.floor(diff / 60000);
        const secs = Math.floor((diff % 60000) / 1000);
        setFinalDuration(`${mins}m ${secs < 10 ? '0' : ''}${secs}s`);
      }
      
      // Set a timeout to reset status to idle after 5 seconds
      resetTimeoutRef.current = setTimeout(() => {
        setDisplayStatus('idle');
        setScanStartTime(null);
        setScanEndTime(null);
        setFinalDuration('');
        console.log('Reset to idle status after 5-second delay');
      }, 5000);
    }
    
    // Update displayStatus based on pause state
    if (isAutoScanning && isAutoScanPaused) {
      setDisplayStatus('paused');
    } else if (isAutoScanning && !isAutoScanPaused) {
      setDisplayStatus('running');
    }
    
    prevIsAutoScanning.current = isAutoScanning;
  }, [isAutoScanning, scanStartTime, isAutoScanPaused]);

  // Clean up timeout on unmount
  useEffect(() => {
    return () => {
      if (resetTimeoutRef.current) {
        clearTimeout(resetTimeoutRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (isAutoScanning && scanStartTime) {
      intervalRef.current = setInterval(() => {
        const now = scanEndTime ? new Date(scanEndTime) : new Date();
        const diff = now - new Date(scanStartTime);
        const mins = Math.floor(diff / 60000);
        const secs = Math.floor((diff % 60000) / 1000);
        setElapsed(`${mins}m ${secs < 10 ? '0' : ''}${secs}s`);
      }, 1000);
      return () => clearInterval(intervalRef.current);
    } else {
      setElapsed('');
      clearInterval(intervalRef.current);
    }
  }, [isAutoScanning, scanStartTime, scanEndTime]);

  // Add a useEffect to reset the UI when autoScanCurrentStep changes to idle
  useEffect(() => {
    if (autoScanCurrentStep === 'idle' && !isAutoScanning) {
      // This means a scan is about to start or has been reset
      setDisplayStatus('idle');
      setScanStartTime(null);
      setScanEndTime(null);
      setFinalDuration('');
      setElapsed('');
      
      // Clear any pending reset timeout
      if (resetTimeoutRef.current) {
        clearTimeout(resetTimeoutRef.current);
        resetTimeoutRef.current = null;
      }
    }
  }, [autoScanCurrentStep, isAutoScanning]);

  const handleConfigure = async () => {
    // Fetch latest config before showing the modal
    setConfigLoading(true);
    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-config`);
      if (response.ok) {
        const data = await response.json();
        setAutoScanConfig(data);
        console.log('[AutoScanConfig] Fetched fresh config before opening modal:', data);
      }
    } catch (e) {
      console.error('[AutoScanConfig] Error fetching config:', e);
    } finally {
      setConfigLoading(false);
      setShowConfigModal(true);
    }
  };

  const handleConfigSave = async (config) => {
    setConfigLoading(true);
    console.log('[AutoScanConfig] Saving config to backend:', config);
    try {
      // The config is already saved by the modal, just update our local state
      setAutoScanConfig(config);
      setShowConfigModal(false);
      console.log('[AutoScanConfig] Updated local config from modal:', config);
    } finally {
      setConfigLoading(false);
    }
  };

  const handlePause = async () => {
    if (!activeTarget || !activeTarget.id) return;
    
    if (!isAutoScanPaused) {
      // Pause the scan
      setIsAutoScanPausing(true);
      try {
        const response = await fetch(
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-state/${activeTarget.id}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
              current_step: autoScanCurrentStep,
              is_paused: true,
              is_cancelled: false
            })
          }
        );
        if (!response.ok) {
          console.error('Error pausing auto scan:', await response.text());
          setIsAutoScanPausing(false);
        }
      } catch (error) {
        console.error('Error pausing auto scan:', error);
        setIsAutoScanPausing(false);
      }
    } else {
      // Resume the scan - set resuming state immediately
      setIsResuming(true);
      try {
        const response = await fetch(
          `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-state/${activeTarget.id}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
              current_step: autoScanCurrentStep,
              is_paused: false,
              is_cancelled: false
            })
          }
        );
        if (!response.ok) {
          console.error('Error resuming auto scan:', await response.text());
          setIsResuming(false);
        }
        
        // Poll to detect when the scan actually resumes
        const checkInterval = setInterval(async () => {
          try {
            const statusResponse = await fetch(
              `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-state/${activeTarget.id}`
            );
            
            if (statusResponse.ok) {
              const data = await statusResponse.json();
              if (!data.is_paused) {
                setIsResuming(false);
                clearInterval(checkInterval);
              }
            }
          } catch (error) {
            console.error('Error checking auto scan state:', error);
          }
        }, 1000);
        
        // Clear the interval after 10 seconds maximum
        setTimeout(() => {
          clearInterval(checkInterval);
          setIsResuming(false); // Reset resuming state after timeout
        }, 10000);
      } catch (error) {
        console.error('Error resuming auto scan:', error);
        setIsResuming(false);
      }
    }
  };

  const handleCancel = async () => {
    if (!activeTarget || !activeTarget.id) return;
    
    setIsAutoScanCancelling(true);
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-state/${activeTarget.id}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            current_step: autoScanCurrentStep,
            is_paused: false,
            is_cancelled: true
          })
        }
      );
      
      if (!response.ok) {
        console.error('Error cancelling auto scan:', await response.text());
        setIsAutoScanCancelling(false);
      } else {
        // Poll status to check if scan has already completed
        const checkInterval = setInterval(async () => {
          try {
            const statusResponse = await fetch(
              `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/auto-scan-state/${activeTarget.id}`
            );
            
            if (statusResponse.ok) {
              const data = await statusResponse.json();
              if (data.current_step === 'completed' || !isAutoScanning) {
                setIsAutoScanCancelling(false);
                clearInterval(checkInterval);
              }
            }
          } catch (error) {
            console.error('Error checking auto scan state:', error);
          }
        }, 1000);
        
        // Clear the interval after 10 seconds maximum
        setTimeout(() => {
          clearInterval(checkInterval);
        }, 10000);
      }
    } catch (error) {
      console.error('Error cancelling auto scan:', error);
      setIsAutoScanCancelling(false);
    }
  };

  const formatStepName = (stepKey) => {
    // If this is a step for a disabled tool, don't show it
    if (autoScanConfig) {
      const stepConfigMapping = {
        'amass': 'amass',
        'sublist3r': 'sublist3r',
        'assetfinder': 'assetfinder',
        'gau': 'gau',
        'ctl': 'ctl',
        'subfinder': 'subfinder',
        'consolidate': 'consolidate_httpx_round1',
        'httpx': 'consolidate_httpx_round1',
        'shuffledns': 'shuffledns',
        'shuffledns_cewl': 'cewl',
        'consolidate_round2': 'consolidate_httpx_round2',
        'httpx_round2': 'consolidate_httpx_round2',
        'gospider': 'gospider',
        'subdomainizer': 'subdomainizer',
        'consolidate_round3': 'consolidate_httpx_round3',
        'httpx_round3': 'consolidate_httpx_round3',
        'nuclei-screenshot': 'nuclei_screenshot',
        'metadata': 'metadata'
      };
      
      const configKey = stepConfigMapping[stepKey];
      if (configKey && autoScanConfig[configKey] === false) {
        return 'away from responsibilities...';
      }
    }
    
    if (!stepKey) return 'Processing';
    
    // Replace underscores with spaces and capitalize words
    return stepKey
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
      .replace('Httpx', 'HTTPX')
      .replace('Sublist3r', 'Sublist3r')
      .replace('Subdomainizer', 'Subdomainizer')
      .replace('Cewl', 'CeWL')
      .replace('Ctl', 'CTL')
      .replace('Gau', 'GAU')
      .replace('Nuclei-screenshot', 'Nuclei Screenshot');
  };

  const currentProgress = useMemo(() => {
    // If the display status is idle, always return 0
    if (displayStatus === 'idle' || !autoScanConfig || !autoScanCurrentStep || autoScanCurrentStep === 'idle') return 0;
    
    // If the display status is completed, return 100 for 5 seconds before resetting
    if (displayStatus === 'completed') return 100;
    
    // Define the full step sequence in execution order
    const fullStepSequence = [
      'amass', 'sublist3r', 'assetfinder', 'gau', 'ctl', 'subfinder',
      'consolidate', 'httpx', 
      'shuffledns', 'shuffledns_cewl',
      'consolidate_round2', 'httpx_round2',
      'gospider', 'subdomainizer',
      'consolidate_round3', 'httpx_round3',
      'nuclei-screenshot', 'metadata', 'completed'
    ];
    
    // Map steps to their config keys
    const stepToConfigKeyMap = {
      'amass': 'amass', 
      'sublist3r': 'sublist3r', 
      'assetfinder': 'assetfinder', 
      'gau': 'gau', 
      'ctl': 'ctl', 
      'subfinder': 'subfinder',
      'consolidate': 'consolidate_httpx_round1',
      'httpx': 'consolidate_httpx_round1',
      'shuffledns': 'shuffledns',
      'shuffledns_cewl': 'cewl',
      'consolidate_round2': 'consolidate_httpx_round2',
      'httpx_round2': 'consolidate_httpx_round2',
      'gospider': 'gospider',
      'subdomainizer': 'subdomainizer',
      'consolidate_round3': 'consolidate_httpx_round3',
      'httpx_round3': 'consolidate_httpx_round3',
      'nuclei-screenshot': 'nuclei_screenshot',
      'metadata': 'metadata'
    };
    
    // Get the position of the current step in the full sequence
    const currentStepIndex = fullStepSequence.indexOf(autoScanCurrentStep);
    if (currentStepIndex === -1) return 0; // Step not found in sequence
    
    
    // Filter and sort enabled steps
    let enabledSteps = [];
    for (const [stepName, configKey] of Object.entries(stepToConfigKeyMap)) {
      if (autoScanConfig[configKey] === true) {
        // Only add steps once (avoid duplicates like consolidate/httpx)
        if (!enabledSteps.includes(stepName) && 
            (!stepName.includes('httpx') || !enabledSteps.includes(stepName.replace('httpx', 'consolidate')))) {
          enabledSteps.push(stepName);
        }
      }
    }
    
    // Sort enabled steps by their order in the full sequence
    enabledSteps.sort((a, b) => 
      fullStepSequence.indexOf(a) - fullStepSequence.indexOf(b));
    
    // If no enabled steps, return 0
    if (enabledSteps.length === 0) return 0;
    
    // Count how many enabled steps have been completed
    let completedEnabledSteps = 0;
    for (let i = 0; i < enabledSteps.length; i++) {
      const enabledStep = enabledSteps[i];
      const enabledStepIndex = fullStepSequence.indexOf(enabledStep);
      
      if (currentStepIndex > enabledStepIndex) {
        // We've passed this enabled step
        completedEnabledSteps++;
      } else if (currentStepIndex === enabledStepIndex) {
        // We're on this enabled step - count it as halfway done
        completedEnabledSteps += 0.5;
        break;
      } else {
        // We haven't reached this enabled step yet
        break;
      }
    }
    
    // Calculate progress as a percentage of enabled steps completed
    const progress = Math.round((completedEnabledSteps / enabledSteps.length) * 100);
    
    // Add debug logging for troubleshooting
    console.log(`[Progress] Current step: ${autoScanCurrentStep}, index: ${currentStepIndex}`);
    console.log(`[Progress] Enabled steps (${enabledSteps.length}):`, enabledSteps);
    console.log(`[Progress] Completed steps: ${completedEnabledSteps}, Progress: ${progress}%`);
    
    // Cap at 95% until completed
    return Math.min(progress, 95);
  }, [displayStatus, autoScanConfig, autoScanCurrentStep]);

  // Add CSS for flashing text
  const flashingTextStyle = `
    @keyframes flash {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    .flashing-text {
      animation: flash 1s linear infinite;
      font-weight: bold;
    }
  `;

  return (
    <>
      <style>{flashingTextStyle}</style>
      <Row className="mb-3">
        <Col>
          <h3 className="text-secondary">Active Scope Target</h3>
        </Col>
        <Col className="text-end">
          <Button 
            variant="outline-danger" 
            onClick={handleOpen}
            disabled={isAutoScanning}
          >
            Add Scope Target
          </Button>
          <Button 
            variant="outline-danger" 
            onClick={handleActiveModalOpen} 
            className="ms-2"
            disabled={isAutoScanning}
          >
            Select Active Target
          </Button>
        </Col>
      </Row>
      <Row className="mb-3">
        <Col>
          {activeTarget && (
            <Card variant="outline-danger">
              <Card.Body>
                <Card.Text className="d-flex justify-content-between text-danger">
                  <span style={{ fontSize: '22px' }}>
                    <strong>{activeTarget.scope_target}</strong>
                  </span>
                  <span>
                    <img src={getTypeIcon(activeTarget.type)} alt={activeTarget.type} style={{ width: '30px' }} />
                  </span>
                </Card.Text>
                
                {/* Only show auto scan UI for Wildcard targets */}
                {activeTarget.type === 'Wildcard' && (
                  <>
                    {/* Auto Scan Status Section */}
                    <div className="mb-3">
                      <div className="d-flex justify-content-between align-items-center mb-1 w-100">
                        <div className="d-flex flex-column">
                          <div className="d-flex align-items-center mb-1">
                            <span className={`fw-bold text-${displayStatus === 'running' ? 'danger' : displayStatus === 'completed' ? 'success' : 'secondary'}`}>
                              Auto Scan Status: {displayStatus === 'running' ? 'Running' : displayStatus === 'completed' ? 'Completed' : 'Idle'}
                            </span>
                            {displayStatus === 'running' && <Spinner animation="border" size="sm" variant="danger" className="ms-2" />}
                          </div>
                          <div className="mb-1">
                            <span className="text-white-50">Start Time: </span>
                            <span className="text-white">{scanStartTime ? new Date(scanStartTime).toLocaleTimeString() : '--:--:-- --'}</span>
                          </div>
                          {isAutoScanning ? (
                            <div className="mb-1">
                              <span className="text-white-50">Elapsed: </span>
                              <span className="text-white">{elapsed || '0m 00s'}</span>
                            </div>
                          ) : (
                            <div className="mb-1">
                              <span className="text-white-50">Duration: </span>
                              <span className="text-white">{finalDuration || (scanEndTime ? '0m 00s' : '--')}</span>
                            </div>
                          )}
                        </div>
                        <div className="text-end" style={{ minWidth: 180 }}>
                          <div className={
                            isAutoScanPaused && 
                            consolidatedSubdomains.length > (autoScanConfig?.maxConsolidatedSubdomains ?? 2500) 
                              ? "text-danger mb-2 flashing-text" 
                              : "text-white-50 mb-2"
                          }>
                            Consolidated Subdomains: {consolidatedSubdomains.length} / {autoScanConfig?.maxConsolidatedSubdomains ?? 2500}
                          </div>
                          <div className={
                            isAutoScanPaused && 
                            getHttpxResultsCount(mostRecentHttpxScan) > (autoScanConfig?.maxLiveWebServers ?? 500) 
                              ? "text-danger mb-2 flashing-text" 
                              : "text-white-50 mb-2"
                          }>
                            Live Web Servers: {getHttpxResultsCount(mostRecentHttpxScan)} / {autoScanConfig?.maxLiveWebServers ?? 500}
                          </div>
                        </div>
                      </div>
                      
                      {/* Auto Scan Status - Always shown */}
                      <div className="mt-3">
                        <div className="d-flex justify-content-between align-items-center mb-2">
                          <div className="text-white-50 small">
                            {displayStatus === 'running' ? (
                              <>
                                <span className="text-danger">●</span> Running {formatStepName(autoScanCurrentStep)}
                              </>
                            ) : displayStatus === 'completed' ? (
                              <>
                                <span className="text-success">●</span> Scan completed
                              </>
                            ) : displayStatus === 'paused' ? (
                              <>
                                <span className="text-warning">●</span> Scan paused {
                                  (isAutoScanPaused && 
                                   ((consolidatedSubdomains.length > (autoScanConfig?.maxConsolidatedSubdomains ?? 2500)) || 
                                    (getHttpxResultsCount(mostRecentHttpxScan) > (autoScanConfig?.maxLiveWebServers ?? 500)))) ? 
                                    <span className="text-warning ms-2">(Limits exceeded)</span> : 
                                    null
                                }
                              </>
                            ) : (
                              <>
                                <span className="text-secondary">●</span> Ready to scan
                              </>
                            )}
                          </div>
                          <div className="text-white-50 small">
                            {scanEndTime && (
                              <>
                                Duration: {finalDuration}
                              </>
                            )}
                          </div>
                        </div>

                        {/* Progress Bar - Always shown */}
                        <div className="mt-2">
                          <div className="d-flex justify-content-between mb-1">
                            <span className="text-white-50 small">Progress</span>
                            <span className="text-white small">
                              {displayStatus === 'idle' ? '0' : currentProgress}%
                            </span>
                          </div>
                          <ProgressBar 
                            now={currentProgress} 
                            variant="danger" 
                            className="bg-dark" 
                            style={{ height: '8px' }}
                          />
                        </div>
                      </div>
                    </div>
                    <div className="d-flex justify-content-between gap-2 mt-3">
                      <Button 
                        variant="outline-danger" 
                        className="flex-fill" 
                        onClick={onOpenAutoScanHistory}
                        disabled={activeTarget?.type !== 'Wildcard'}
                      >
                        Scan History
                      </Button>
                      <Button 
                        variant="outline-danger" 
                        className="flex-fill" 
                        onClick={handleConfigure}
                        disabled={activeTarget?.type !== 'Wildcard'}
                      >
                        Configure
                      </Button>
                      <Button 
                        variant="outline-danger" 
                        className="flex-fill" 
                        onClick={onAutoScan}
                        disabled={isAutoScanning || activeTarget?.type !== 'Wildcard'}
                      >
                        <div className="btn-content">
                          {isAutoScanning ? (
                            <Spinner animation="border" size="sm" variant="danger" />
                          ) : 'Auto Scan'}
                        </div>
                      </Button>
                      {isAutoScanPaused ? (
                        <Button 
                          variant="outline-danger" 
                          className="flex-fill" 
                          onClick={handlePause}
                          disabled={!isAutoScanning || isResuming}
                        >
                          {isResuming ? (
                            <div className="btn-content">
                              <span className="me-1">Resuming</span>
                              <Spinner animation="border" size="sm" />
                            </div>
                          ) : 'Resume'}
                        </Button>
                      ) : (
                        <Button 
                          variant="outline-danger" 
                          className="flex-fill" 
                          onClick={handlePause}
                          disabled={!isAutoScanning || isAutoScanCancelling}
                        >
                          {isAutoScanPausing ? (
                            <div className="btn-content">
                              <span className="me-1">Pausing</span>
                              <Spinner animation="border" size="sm" />
                            </div>
                          ) : 'Pause'}
                        </Button>
                      )}
                      <Button 
                        variant="outline-danger" 
                        className="flex-fill" 
                        onClick={handleCancel}
                        disabled={!isAutoScanning || isAutoScanPaused}
                      >
                        {isAutoScanCancelling ? (
                          <div className="btn-content">
                            <span className="me-1">Cancelling</span>
                            <Spinner animation="border" size="sm" />
                          </div>
                        ) : 'Cancel'}
                      </Button>
                    </div>
                  </>
                )}
              </Card.Body>
            </Card>
          )}
        </Col>
      </Row>
      {scopeTargets.length === 0 && (
        <Alert variant="danger" className="mt-3">
          No scope targets available. Please add a new target.
        </Alert>
      )}

      <AutoScanConfigModal
        show={showConfigModal}
        handleClose={() => setShowConfigModal(false)}
        onSave={handleConfigSave}
        config={autoScanConfig}
        loading={configLoading}
      />
    </>
  );
});

export default ManageScopeTargets;
