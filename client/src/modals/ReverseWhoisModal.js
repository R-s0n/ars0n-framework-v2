import React, { useState } from 'react';
import { Modal, Row, Col, Button, Form, InputGroup, Alert, Card } from 'react-bootstrap';

const ReverseWhoisModal = ({ show, handleClose, companyName, onDomainAdd, error, onClearError }) => {
  const [newDomain, setNewDomain] = useState('');

  const handleAddDomain = () => {
    if (newDomain.trim()) {
      onDomainAdd(newDomain.trim());
      setNewDomain('');
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleAddDomain();
    }
  };

  const handleDomainInputChange = (e) => {
    setNewDomain(e.target.value);
    if (error && onClearError) {
      onClearError();
    }
  };

  const openViewDNS = () => {
    const viewDNSUrl = `https://viewdns.info/reversewhois/?q=${encodeURIComponent(companyName)}`;
    window.open(viewDNSUrl, '_blank');
  };

  const openWhoxy = () => {
    const whoxyUrl = `https://www.whoxy.com/reverse-whois/`;
    window.open(whoxyUrl, '_blank');
  };

  return (
    <Modal 
      show={show} 
      onHide={handleClose} 
      size="lg" 
      data-bs-theme="dark"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Reverse Whois Lookup - {companyName}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="mb-4">
          <h5 className="text-danger mb-3">Choose a Reverse Whois Service</h5>
          <p className="text-white-50 small mb-4">
            <i className="bi bi-info-circle me-2"></i>
            These services cannot be embedded due to security controls on their websites. 
            Click the buttons below to open them in new tabs.
          </p>
          
          <Row className="g-3 mb-4">
            <Col md={6}>
              <Card className="h-100 bg-dark border-secondary">
                <Card.Body className="d-flex flex-column">
                  <Card.Title className="text-danger">ViewDNS</Card.Title>
                  <Card.Text className="text-white small flex-grow-1">
                    Free reverse WHOIS lookup service that searches for domains registered 
                    with the same contact information as your target company.
                  </Card.Text>
                  <Button 
                    variant="outline-danger" 
                    size="sm"
                    onClick={openViewDNS}
                    className="mt-auto"
                  >
                    <i className="bi bi-box-arrow-up-right me-2"></i>
                    Open ViewDNS
                  </Button>
                </Card.Body>
              </Card>
            </Col>
            
            <Col md={6}>
              <Card className="h-100 bg-dark border-secondary">
                <Card.Body className="d-flex flex-column">
                  <Card.Title className="text-danger">Whoxy</Card.Title>
                  <Card.Text className="text-white small flex-grow-1">
                    Professional WHOIS and reverse WHOIS lookup service. Once opened, 
                    click the <strong>"Company Name"</strong> button and search for <strong>{companyName}</strong>{' '}
                    to find domains registered by the company.
                  </Card.Text>
                  <Button 
                    variant="outline-danger" 
                    size="sm"
                    onClick={openWhoxy}
                    className="mt-auto"
                  >
                    <i className="bi bi-box-arrow-up-right me-2"></i>
                    Open Whoxy
                  </Button>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </div>
        
        <div>
          <h5 className="text-danger mb-3">Add Discovered Domain</h5>
          <p className="text-white-50 small mb-3">
            After reviewing the results from either service above, manually add any domains 
            that belong to <strong>{companyName}</strong> using the form below.
          </p>
          {error && (
            <Alert variant="danger" className="mb-3">
              <small>{error}</small>
            </Alert>
          )}
          <InputGroup>
            <Form.Control
              type="text"
              placeholder="Enter domain (e.g., example.com)"
              value={newDomain}
              onChange={handleDomainInputChange}
              onKeyPress={handleKeyPress}
              className="bg-dark text-white border-secondary"
            />
            <Button 
              variant="outline-danger" 
              onClick={handleAddDomain}
              disabled={!newDomain.trim()}
            >
              Add Domain
            </Button>
          </InputGroup>
          <small className="text-white-50 mt-2 d-block">
            Add domains you discover through reverse whois lookup that belong to {companyName}
          </small>
        </div>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ReverseWhoisModal; 