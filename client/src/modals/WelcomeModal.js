import { Modal, Button, Card, Row, Col } from 'react-bootstrap';
import { FaPlus, FaFileImport, FaRocket, FaFileUpload, FaPlug } from 'react-icons/fa';
import 'bootstrap-icons/font/bootstrap-icons.css';

function WelcomeModal({ show, handleClose, onAddScopeTarget, onImportData, onUploadConfig, onUseAPI }) {
  return (
    <Modal
      show={show}
      onHide={handleClose}
      backdrop="static"
      keyboard={false}
      animation={true}
      size="lg"
      centered
      data-bs-theme="dark"
    >
      <Modal.Header className="flex-column align-items-center border-0 pb-0">
        <img
          src="/images/logo.avif"
          alt="Logo"
          style={{ width: '80px', height: '80px', marginBottom: '10px' }}
        />
        <Modal.Title className="w-100 text-center text-danger mb-2">
          Welcome to Ars0n Framework v2 <span style={{ fontSize: '0.7rem' }} className="text-muted">beta</span>
        </Modal.Title>
      </Modal.Header>
      
      <Modal.Body className="px-4 pb-3">
        <div className="text-center mb-3">
          <h6 className="text-white mb-2">
            <FaRocket className="me-2 text-danger" />
            Ready to Get Started?
          </h6>
          <p className="text-white-50 mb-3 small">
            No scope targets are currently configured. Choose an option below to begin.
          </p>
        </div>

        <Row className="g-3">
          <Col md={6}>
            <Card 
              className="h-100 border-2 border-danger hover-card"
              onClick={onAddScopeTarget}
              style={{ 
                cursor: 'pointer',
                transition: 'all 0.3s ease-in-out'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-3px)';
                e.currentTarget.style.boxShadow = '0 6px 20px rgba(220, 53, 69, 0.3)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <Card.Body className="text-center p-3">
                <div className="mb-2">
                  <FaPlus size={32} className="text-danger" />
                </div>
                <h6 className="text-white mb-2">Add Scope Target</h6>
                <p className="text-white-50 mb-2" style={{ fontSize: '0.85rem' }}>
                  Create a new scope target. Choose from Company, Wildcard, or URL.
                </p>
                <div className="d-flex justify-content-center flex-wrap gap-2 mb-2">
                  <img src="/images/Company.png" alt="Company" style={{ width: '22px', height: '22px' }} />
                  <img src="/images/Wildcard.png" alt="Wildcard" style={{ width: '22px', height: '22px' }} />
                  <img src="/images/URL.png" alt="URL" style={{ width: '22px', height: '22px' }} />
                </div>
                <Button 
                  variant="danger" 
                  size="sm"
                  className="w-100"
                  onClick={(e) => {
                    e.stopPropagation();
                    onAddScopeTarget();
                  }}
                >
                  <FaPlus className="me-1" style={{ fontSize: '0.85rem' }} />
                  <span style={{ fontSize: '0.85rem' }}>Create Target</span>
                </Button>
              </Card.Body>
            </Card>
          </Col>

          <Col md={6}>
            <Card 
              className="h-100 border-2 border-danger hover-card"
              onClick={onImportData}
              style={{ 
                cursor: 'pointer',
                transition: 'all 0.3s ease-in-out'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-3px)';
                e.currentTarget.style.boxShadow = '0 6px 20px rgba(220, 53, 69, 0.3)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <Card.Body className="text-center p-3">
                <div className="mb-2">
                  <FaFileImport size={32} className="text-danger" />
                </div>
                <h6 className="text-white mb-2">Import Scan Data</h6>
                <p className="text-white-50 mb-2" style={{ fontSize: '0.85rem' }}>
                  Restore a previous session by importing a .rs0n database file.
                </p>
                <div className="mb-2">
                  <div className="d-inline-flex align-items-center bg-dark rounded px-2 py-1">
                    <FaFileImport className="text-white me-1" size={14} />
                    <span className="text-white-50" style={{ fontSize: '0.8rem' }}>.rs0n format</span>
                  </div>
                </div>
                <Button 
                  variant="danger" 
                  size="sm"
                  className="w-100"
                  onClick={(e) => {
                    e.stopPropagation();
                    onImportData();
                  }}
                >
                  <FaFileImport className="me-1" style={{ fontSize: '0.85rem' }} />
                  <span style={{ fontSize: '0.85rem' }}>Import Database</span>
                </Button>
              </Card.Body>
            </Card>
          </Col>

          <Col md={6}>
            <Card 
              className="h-100 border-2 border-danger hover-card"
              onClick={onUploadConfig}
              style={{ 
                cursor: 'pointer',
                transition: 'all 0.3s ease-in-out'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-3px)';
                e.currentTarget.style.boxShadow = '0 6px 20px rgba(220, 53, 69, 0.3)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <Card.Body className="text-center p-3">
                <div className="mb-2">
                  <FaFileUpload size={32} className="text-danger" />
                </div>
                <h6 className="text-white mb-2">Upload Configuration</h6>
                <p className="text-white-50 mb-2" style={{ fontSize: '0.85rem' }}>
                  Import scope from HackerOne, Bugcrowd, YesWeHack, or Intigriti.
                </p>
                <div className="mb-2">
                  <div className="d-inline-flex align-items-center bg-dark rounded px-2 py-1">
                    <FaFileUpload className="text-white me-1" size={14} />
                    <span className="text-white-50" style={{ fontSize: '0.8rem' }}>Burp/CSV</span>
                  </div>
                </div>
                <Button 
                  variant="danger" 
                  size="sm"
                  className="w-100"
                  onClick={(e) => {
                    e.stopPropagation();
                    onUploadConfig();
                  }}
                >
                  <FaFileUpload className="me-1" style={{ fontSize: '0.85rem' }} />
                  <span style={{ fontSize: '0.85rem' }}>Upload Config</span>
                </Button>
              </Card.Body>
            </Card>
          </Col>

          <Col md={6}>
            <Card 
              className="h-100 border-2 border-danger hover-card"
              onClick={onUseAPI}
              style={{ 
                cursor: 'pointer',
                transition: 'all 0.3s ease-in-out'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-3px)';
                e.currentTarget.style.boxShadow = '0 6px 20px rgba(220, 53, 69, 0.3)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <Card.Body className="text-center p-3">
                <div className="mb-2">
                  <FaPlug size={32} className="text-danger" />
                </div>
                <h6 className="text-white mb-2">Use API Integration</h6>
                <p className="text-white-50 mb-2" style={{ fontSize: '0.85rem' }}>
                  Connect to bug bounty platform APIs to automatically import targets.
                </p>
                <div className="mb-2">
                  <div className="d-inline-flex align-items-center bg-dark rounded px-2 py-1">
                    <FaPlug className="text-white me-1" size={14} />
                    <span className="text-white-50" style={{ fontSize: '0.8rem' }}>API sync</span>
                  </div>
                </div>
                <Button 
                  variant="danger" 
                  size="sm"
                  className="w-100"
                  onClick={(e) => {
                    e.stopPropagation();
                    onUseAPI();
                  }}
                >
                  <FaPlug className="me-1" style={{ fontSize: '0.85rem' }} />
                  <span style={{ fontSize: '0.85rem' }}>Connect API</span>
                </Button>
              </Card.Body>
            </Card>
          </Col>
        </Row>


      </Modal.Body>
    </Modal>
  );
}

export default WelcomeModal; 