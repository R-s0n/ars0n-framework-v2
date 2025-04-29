import { Row, Col, Button, Card, Alert } from 'react-bootstrap';

function ManageScopeTargets({ 
  handleOpen, 
  handleActiveModalOpen, 
  activeTarget, 
  scopeTargets, 
  getTypeIcon,
  onAutoScan,
  onBalancedScan,
  onFullScan,
  onYOLOScan,
  isAutoScanning,
  autoScanCurrentStep,
  mostRecentGauScanStatus
}) {
  // Helper function to display a human-readable step name
  const formatStepName = (stepKey) => {
    if (!stepKey) return "";
    
    // Special case for GAU when it's processing
    if (stepKey === 'gau' && mostRecentGauScanStatus === 'processing') {
      return "GAU (Processing Large Results)";
    }
    
    // Convert snake_case or camelCase to words with spaces
    const words = stepKey
      .replace(/([A-Z])/g, ' $1') // Insert space before capital letters
      .replace(/_/g, ' ') // Replace underscores with spaces
      .toLowerCase()
      .split(' ')
      .filter(word => word.length > 0)
      .map(word => word.charAt(0).toUpperCase() + word.slice(1)) // Capitalize first letter
      .join(' ');
      
    return words;
  };

  // Get a user-friendly name for the current scan
  const getScanStatusText = () => {
    if (!isAutoScanning) {
      return "No scan running";
    }
    
    if (autoScanCurrentStep === 'idle' || !autoScanCurrentStep) {
      return "Preparing...";
    } else if (autoScanCurrentStep === 'completed') {
      return "Scan Complete";
    } else {
      return `Running: ${formatStepName(autoScanCurrentStep)}`;
    }
  };
  
  // Get which scan button is currently active based on localStorage
  const getActiveScanType = () => {
    if (!isAutoScanning) return "";
    const scanType = localStorage.getItem('autoScanType') || 'quick';
    return scanType.charAt(0).toUpperCase() + scanType.slice(1); // Capitalize first letter
  };

  return (
    <>
      <Row className="mb-3">
        <Col>
          <h3 className="text-secondary">Active Scope Target</h3>
        </Col>
        <Col className="text-end">
          <Button variant="outline-danger" onClick={handleOpen}>
            Add Scope Target
          </Button>
          <Button variant="outline-danger" onClick={handleActiveModalOpen} className="ms-2">
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
                
                {/* Status indicator - always visible */}
                <div className="text-center mb-3">
                  <span className="text-danger">
                    {isAutoScanning ? `${getActiveScanType()} Scan: ${getScanStatusText()}` : "Ready to scan"}
                  </span>
                </div>
                {/* Man, this is shit code...  "outline-danger" : "outline-danger"  I gotta fix this in beta */}
                <div className="d-flex justify-content-between gap-2">
                  <Button 
                    variant={isAutoScanning && getActiveScanType() === 'Quick' ? "outline-danger" : "outline-danger"}
                    className="flex-fill" 
                    onClick={onAutoScan}
                    disabled={isAutoScanning}
                  >
                    <div className="btn-content">
                      {isAutoScanning && getActiveScanType() === 'Quick' ? (
                        <>
                          <div className="spinner"></div>
                          {/* <span className="ms-2">Quick Scan</span> */}
                        </>
                      ) : 'Quick Scan'}
                    </div>
                  </Button>
                  <Button 
                    variant={isAutoScanning && getActiveScanType() === 'Balanced' ? "outline-danger" : "outline-danger"}
                    className="flex-fill" 
                    onClick={onBalancedScan}
                    disabled={isAutoScanning}
                  >
                    <div className="btn-content">
                      {isAutoScanning && getActiveScanType() === 'Balanced' ? (
                        <>
                          <div className="spinner"></div>
                          {/* <span className="ms-2">Balanced Scan</span> */}
                        </>
                      ) : 'Balanced Scan'}
                    </div>
                  </Button>
                  <Button 
                    variant={isAutoScanning && getActiveScanType() === 'Full' ? "outline-danger" : "outline-danger"}
                    className="flex-fill" 
                    onClick={onFullScan}
                    disabled={isAutoScanning}
                  >
                    <div className="btn-content">
                      {isAutoScanning && getActiveScanType() === 'Full' ? (
                        <>
                          <div className="spinner"></div>
                          {/* <span className="ms-2">Full Scan</span> */}
                        </>
                      ) : 'Full Scan'}
                    </div>
                  </Button>
                  <Button 
                    variant={isAutoScanning && getActiveScanType() === 'Yolo' ? "outline-danger" : "outline-danger"}
                    className="flex-fill" 
                    onClick={onYOLOScan}
                    disabled={isAutoScanning}
                  >
                    <div className="btn-content">
                      {isAutoScanning && getActiveScanType() === 'Yolo' ? (
                        <>
                          <div className="spinner"></div>
                          {/* <span className="ms-2">YOLO Scan</span> */}
                        </>
                      ) : 'YOLO Scan'}
                    </div>
                  </Button>
                </div>
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
    </>
  );
}

export default ManageScopeTargets;
