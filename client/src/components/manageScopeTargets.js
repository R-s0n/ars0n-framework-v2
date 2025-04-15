import { Row, Col, Button, Card, Alert } from 'react-bootstrap';

function ManageScopeTargets({ 
  handleOpen, 
  handleActiveModalOpen, 
  activeTarget, 
  scopeTargets, 
  getTypeIcon,
  onQuickScan,
  onBalancedScan,
  onFullScan,
  onYOLOScan,
  isQuickScanning,
  quickScanCurrentStep,
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
                <div className="d-flex justify-content-between gap-2 mt-3">
                  <Button 
                    variant="outline-danger" 
                    className="flex-fill" 
                    onClick={onQuickScan}
                    disabled={isQuickScanning}
                  >
                    <div className="btn-content">
                      {isQuickScanning ? (
                        <>
                          <div className="spinner"></div>
                          {quickScanCurrentStep && quickScanCurrentStep !== 'idle' && quickScanCurrentStep !== 'completed' && (
                            <span className="ms-2">{formatStepName(quickScanCurrentStep)}</span>
                          )}
                        </>
                      ) : 'Quick Scan'}
                    </div>
                  </Button>
                  <Button variant="outline-danger" className="flex-fill" onClick={onBalancedScan}>Balanced Scan</Button>
                  <Button variant="outline-danger" className="flex-fill" onClick={onFullScan}>Full Scan</Button>
                  <Button variant="outline-danger" className="flex-fill" onClick={onYOLOScan}>YOLO Scan</Button>
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
