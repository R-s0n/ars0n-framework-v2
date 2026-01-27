import { useState, useEffect, useMemo } from 'react';
import { Modal, Button, Form, Table, Badge, OverlayTrigger, Tooltip, InputGroup, Row, Col, Alert } from 'react-bootstrap';

const ConfigureMetaDataModal = ({ 
  show, 
  handleClose, 
  targetURLs = [],
  onSaveConfig,
  currentConfig
}) => {
  const [selectedURLs, setSelectedURLs] = useState(new Set());
  const [selectedSteps, setSelectedSteps] = useState({
    screenshots: true,
    katana: false,
    ffuf: false,
    technology: true,
    ssl: true
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [selectAll, setSelectAll] = useState(true);

  const standardSteps = [
    { 
      key: 'screenshots', 
      label: 'Screenshots',
      description: 'Capture visual screenshots of web applications for manual analysis'
    },
    { 
      key: 'technology', 
      label: 'Technology Detection',
      description: 'Identify frameworks, CMS platforms, server software, and third-party services'
    },
    { 
      key: 'ssl', 
      label: 'SSL/TLS Analysis',
      description: 'Certificate details, encryption settings, and potential vulnerabilities'
    }
  ];

  const advancedSteps = [
    { 
      key: 'katana', 
      label: 'Katana - Crawl for Endpoints',
      description: 'Fast web crawler for discovering hidden endpoints and content'
    },
    { 
      key: 'ffuf', 
      label: 'FFuf - Fuzz for Endpoints',
      description: 'Fast web fuzzer with support for multiple protocols and advanced filtering'
    }
  ];

  useEffect(() => {
    if (show) {
      if (currentConfig) {
        setSelectedURLs(new Set(currentConfig.urls || []));
        setSelectedSteps(currentConfig.steps || {
          screenshots: true,
          katana: false,
          ffuf: false,
          technology: true,
          ssl: true
        });
        setSelectAll(currentConfig.urls?.length === targetURLs.length);
      } else if (targetURLs.length > 0) {
        const allURLIds = new Set(targetURLs.map(url => url.id));
        setSelectedURLs(allURLIds);
        setSelectAll(true);
        setSelectedSteps({
          screenshots: true,
          katana: false,
          ffuf: false,
          technology: true,
          ssl: true
        });
      }
    }
  }, [show, targetURLs, currentConfig]);

  const filteredURLs = useMemo(() => {
    if (!searchTerm) return targetURLs;
    const lower = searchTerm.toLowerCase();
    return targetURLs.filter(url => 
      url.url.toLowerCase().includes(lower) ||
      (url.title && url.title.toLowerCase().includes(lower))
    );
  }, [targetURLs, searchTerm]);

  const handleToggleURL = (urlId) => {
    setSelectedURLs(prev => {
      const newSet = new Set(prev);
      if (newSet.has(urlId)) {
        newSet.delete(urlId);
      } else {
        newSet.add(urlId);
      }
      setSelectAll(newSet.size === targetURLs.length);
      return newSet;
    });
  };

  const handleToggleAll = () => {
    if (selectAll) {
      setSelectedURLs(new Set());
      setSelectAll(false);
    } else {
      const allURLIds = new Set(targetURLs.map(url => url.id));
      setSelectedURLs(allURLIds);
      setSelectAll(true);
    }
  };

  const handleToggleStep = (stepKey) => {
    setSelectedSteps(prev => ({
      ...prev,
      [stepKey]: !prev[stepKey]
    }));
  };

  const handleSaveConfig = () => {
    const config = {
      urls: Array.from(selectedURLs),
      steps: selectedSteps
    };
    onSaveConfig(config);
    handleClose();
  };

  const atLeastOneStepSelected = Object.values(selectedSteps).some(v => v);

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleClose} 
      size="xl"
      dialogClassName="modal-90w"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Configure Metadata Scan</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Row>
          <Col md={6}>
            <h5 className="text-danger mb-3">Select Scan Steps</h5>
            
            <div className="mb-4">
              <h6 className="text-white mb-3">Standard Scans</h6>
              <Form>
                {standardSteps.map(step => (
                  <div key={step.key} className="mb-3">
                    <Form.Check
                      type="checkbox"
                      id={`step-${step.key}`}
                      checked={selectedSteps[step.key]}
                      onChange={() => handleToggleStep(step.key)}
                      label={
                        <div>
                          <div className="text-white fw-bold">{step.label}</div>
                          <div className="text-white-50 small">{step.description}</div>
                        </div>
                      }
                    />
                  </div>
                ))}
              </Form>
            </div>

            <div className="border-top border-secondary pt-4 mb-4">
              <div className="d-flex align-items-center mb-3">
                <h6 className="text-warning mb-0 me-2">Advanced Scans</h6>
                <i className="bi bi-exclamation-triangle-fill text-warning"></i>
              </div>
              <Alert variant="warning" className="py-2 px-3 mb-3" style={{ fontSize: '0.85rem' }}>
                <i className="bi bi-clock-history me-2"></i>
                <strong>Warning:</strong> These scans can significantly increase scan time (10x-100x longer). 
                Use selectively for high-value targets.
              </Alert>
              <Form>
                {advancedSteps.map(step => (
                  <div key={step.key} className="mb-3">
                    <Form.Check
                      type="checkbox"
                      id={`step-${step.key}`}
                      checked={selectedSteps[step.key]}
                      onChange={() => handleToggleStep(step.key)}
                      label={
                        <div>
                          <div className="text-white fw-bold">{step.label}</div>
                          <div className="text-white-50 small">{step.description}</div>
                        </div>
                      }
                    />
                  </div>
                ))}
              </Form>
            </div>

            {!atLeastOneStepSelected && (
              <Alert variant="danger">
                <i className="bi bi-exclamation-triangle me-2"></i>
                Please select at least one scan step
              </Alert>
            )}
          </Col>

          <Col md={6}>
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h5 className="text-danger mb-0">Select Target URLs</h5>
              <Badge bg="secondary">
                {selectedURLs.size} of {targetURLs.length} selected
              </Badge>
            </div>

            <InputGroup className="mb-3">
              <InputGroup.Text>
                <i className="bi bi-search"></i>
              </InputGroup.Text>
              <Form.Control
                type="text"
                placeholder="Search URLs or titles..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
              {searchTerm && (
                <Button 
                  variant="outline-secondary" 
                  onClick={() => setSearchTerm('')}
                >
                  <i className="bi bi-x"></i>
                </Button>
              )}
            </InputGroup>

            <div className="mb-3">
              <Form.Check
                type="checkbox"
                id="select-all"
                checked={selectAll}
                onChange={handleToggleAll}
                label={<span className="fw-bold">Select All URLs</span>}
              />
            </div>

            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
              <Table striped hover size="sm" className="mb-0">
                <thead className="sticky-top bg-dark">
                  <tr>
                    <th style={{ width: '50px' }}>
                      <Form.Check
                        type="checkbox"
                        checked={selectAll}
                        onChange={handleToggleAll}
                      />
                    </th>
                    <th>URL</th>
                    <th style={{ width: '100px' }} className="text-center">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredURLs.map(url => (
                    <tr key={url.id}>
                      <td>
                        <Form.Check
                          type="checkbox"
                          checked={selectedURLs.has(url.id)}
                          onChange={() => handleToggleURL(url.id)}
                        />
                      </td>
                      <td>
                        <OverlayTrigger
                          placement="top"
                          overlay={<Tooltip>{url.url}</Tooltip>}
                        >
                          <div 
                            className="text-truncate" 
                            style={{ maxWidth: '300px', cursor: 'pointer' }}
                          >
                            {url.url}
                          </div>
                        </OverlayTrigger>
                        {url.title && (
                          <div className="text-white-50 small text-truncate" style={{ maxWidth: '300px' }}>
                            {url.title}
                          </div>
                        )}
                      </td>
                      <td className="text-center">
                        <Badge bg={url.status_code >= 200 && url.status_code < 300 ? 'success' : 'warning'}>
                          {url.status_code || 'N/A'}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                  {filteredURLs.length === 0 && (
                    <tr>
                      <td colSpan="3" className="text-center text-white-50">
                        No URLs match your search
                      </td>
                    </tr>
                  )}
                </tbody>
              </Table>
            </div>
          </Col>
        </Row>
      </Modal.Body>
      <Modal.Footer>
        <div className="d-flex justify-content-between w-100 align-items-center">
          <div className="text-white-50">
            <i className="bi bi-info-circle me-2"></i>
            {selectedURLs.size > 0 && atLeastOneStepSelected ? (
              <span>
                Configuration: {selectedURLs.size} URL{selectedURLs.size !== 1 ? 's' : ''} with{' '}
                {Object.values(selectedSteps).filter(v => v).length} step{Object.values(selectedSteps).filter(v => v).length !== 1 ? 's' : ''}
              </span>
            ) : (
              <span>Select at least one URL and one scan step</span>
            )}
          </div>
          <div>
            <Button variant="secondary" onClick={handleClose} className="me-2">
              Cancel
            </Button>
            <Button 
              variant="danger" 
              onClick={handleSaveConfig}
              disabled={selectedURLs.size === 0 || !atLeastOneStepSelected}
            >
              <i className="bi bi-save me-2"></i>
              Save Configuration
            </Button>
          </div>
        </div>
      </Modal.Footer>
    </Modal>
  );
};

export default ConfigureMetaDataModal;
