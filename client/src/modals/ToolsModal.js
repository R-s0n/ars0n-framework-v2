import { useState, useEffect } from 'react';
import { Modal, Button, Form, Row, Col, Spinner, Nav, Tab, Alert, ProgressBar } from 'react-bootstrap';

const styles = {
  navLink: {
    color: '#dc3545 !important',
  },
  navLinkActive: {
    backgroundColor: '#dc3545 !important',
    color: '#fff !important',
  },
  formControl: {
    '&:focus': {
      borderColor: '#dc3545',
      boxShadow: '0 0 0 0.2rem rgba(220, 53, 69, 0.25)',
    },
  },
};

function ToolsModal({ show, handleClose, initialTab = 'burp-populator' }) {
  const [activeTab, setActiveTab] = useState(initialTab);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);
  
  const [allSettings, setAllSettings] = useState(null);
  const [burpProxyIP, setBurpProxyIP] = useState('127.0.0.1');
  const [burpProxyPort, setBurpProxyPort] = useState(8080);
  const [rawInput, setRawInput] = useState('');
  const [parsedDomains, setParsedDomains] = useState([]);
  const [verifyStatus, setVerifyStatus] = useState(null);
  const [protocol, setProtocol] = useState('https');
  const [populating, setPopulating] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0 });

  useEffect(() => {
    if (show) {
      fetchSettings();
      setError(null);
      setSuccessMessage(null);
      setVerifyStatus(null);
    }
  }, [show]);

  useEffect(() => {
    setActiveTab(initialTab);
  }, [initialTab]);

  const fetchSettings = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/user/settings`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch settings');
      }
      
      const data = await response.json();
      setAllSettings(data);
      
      if (data.burp_proxy_ip) {
        setBurpProxyIP(data.burp_proxy_ip);
      }
      if (data.burp_proxy_port) {
        setBurpProxyPort(data.burp_proxy_port);
      }
    } catch (error) {
      console.error('Error fetching settings:', error);
      setError('Failed to load Burp Suite settings. Using defaults.');
    } finally {
      setLoading(false);
    }
  };

  const saveSettings = async () => {
    setSaving(true);
    setError(null);
    setSuccessMessage(null);
    
    try {
      const updatedSettings = {
        ...allSettings,
        burp_proxy_ip: burpProxyIP,
        burp_proxy_port: parseInt(burpProxyPort),
      };

      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/user/settings`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(updatedSettings),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save settings');
      }

      setSuccessMessage('Burp Suite proxy settings saved successfully!');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (error) {
      console.error('Error saving settings:', error);
      setError('Failed to save Burp Suite settings. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const parseDomainsFromInput = (input) => {
    if (!input || input.trim() === '') {
      return [];
    }

    let separatedItems = input.split(/[\n,]+/);
    
    const urls = separatedItems
      .map(item => item.trim())
      .filter(item => item.length > 0)
      .map(item => {
        let cleaned = item.replace(/^(https?:\/\/|ftp:\/\/|ftps:\/\/)/i, '');
        return cleaned;
      })
      .filter(url => url.length > 0);

    return [...new Set(urls)];
  };

  const handleVerify = () => {
    setVerifyStatus(null);
    setError(null);
    
    const allUrls = parseDomainsFromInput(rawInput);
    
    if (allUrls.length === 0) {
      setVerifyStatus({
        success: false,
        message: 'No valid URLs found. Please check your input.',
      });
      setParsedDomains([]);
      return;
    }

    const urlPattern = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*|\[[0-9a-fA-F:]+\])(:[0-9]+)?(\/.*)?$/;
    const validUrls = allUrls.filter(url => urlPattern.test(url));

    if (validUrls.length === 0) {
      setVerifyStatus({
        success: false,
        message: 'No valid URLs found. Please check your input.',
      });
      setParsedDomains([]);
      return;
    }

    setParsedDomains(validUrls);
    setVerifyStatus({
      success: true,
      message: `Successfully parsed ${validUrls.length} unique URL(s).${allUrls.length > validUrls.length ? ` (${allUrls.length - validUrls.length} invalid URL(s) removed)` : ''}`,
    });
  };

  const handlePopulateBurpsuite = async () => {
    setError(null);
    setSuccessMessage(null);
    
    if (parsedDomains.length === 0) {
      setError('Please verify your URL list first.');
      return;
    }

    let urls = [];
    if (protocol === 'Both') {
      urls = [
        ...parsedDomains.map(url => `https://${url}`),
        ...parsedDomains.map(url => `http://${url}`)
      ];
    } else {
      urls = parsedDomains.map(url => `${protocol}://${url}`);
    }

    setPopulating(true);
    setProgress({ current: 0, total: urls.length });

    let successCount = 0;
    let errorCount = 0;

    try {
      for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        
        try {
          const response = await fetch(
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/burpsuite/populate`,
            {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({ urls: [url] }),
            }
          );

          if (!response.ok) {
            const errorData = await response.text();
            console.error(`Failed to populate URL ${i + 1}/${urls.length}: ${url}`, errorData);
            errorCount++;
          } else {
            successCount++;
          }
        } catch (err) {
          console.error(`Error populating URL ${i + 1}/${urls.length}: ${url}`, err);
          errorCount++;
        }

        setProgress({ current: i + 1, total: urls.length });
      }

      if (errorCount === 0) {
        setSuccessMessage(`Successfully populated Burpsuite with ${urls.length} URL(s)!`);
      } else {
        setSuccessMessage(`Populated Burpsuite: ${successCount} successful, ${errorCount} failed out of ${urls.length} total.`);
      }
    } catch (err) {
      console.error('Error populating Burpsuite:', err);
      setError(`Failed to populate Burpsuite: ${err.message}`);
    } finally {
      setPopulating(false);
      setProgress({ current: 0, total: 0 });
    }
  };

  return (
    <Modal 
      show={show} 
      onHide={handleClose} 
      size="xl"
      data-bs-theme="dark"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Tools & Utilities</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {loading ? (
          <div className="text-center py-4">
            <Spinner animation="border" variant="danger" />
            <p className="text-white mt-3">Loading...</p>
          </div>
        ) : (
          <Tab.Container activeKey={activeTab} onSelect={setActiveTab}>
            <Row>
              <Col sm={3}>
                <Nav variant="pills" className="flex-column">
                  <Nav.Item>
                    <Nav.Link 
                      eventKey="burp-populator"
                      className={activeTab === 'burp-populator' ? 'active' : ''}
                    >
                      Burp Populator
                    </Nav.Link>
                  </Nav.Item>
                </Nav>
              </Col>
              <Col sm={9}>
                <Tab.Content>
                  <Tab.Pane eventKey="burp-populator">
                    <h5 className="text-danger mb-4">Burp Suite Populator</h5>
                    
                    {error && (
                      <Alert variant="danger" dismissible onClose={() => setError(null)}>
                        {error}
                      </Alert>
                    )}
                    
                    {successMessage && (
                      <Alert variant="success" dismissible onClose={() => setSuccessMessage(null)}>
                        {successMessage}
                      </Alert>
                    )}

                    <div className="mb-4">
                      <h6 className="text-white mb-3">Burp Suite Proxy Settings</h6>
                      <Row>
                        <Col md={6}>
                          <Form.Group className="mb-3">
                            <Form.Label className="text-white">Proxy IP Address</Form.Label>
                            <Form.Control
                              type="text"
                              value={burpProxyIP}
                              onChange={(e) => setBurpProxyIP(e.target.value)}
                              className="custom-input"
                              placeholder="127.0.0.1"
                            />
                          </Form.Group>
                        </Col>
                        <Col md={6}>
                          <Form.Group className="mb-3">
                            <Form.Label className="text-white">Proxy Port</Form.Label>
                            <Form.Control
                              type="number"
                              value={burpProxyPort}
                              onChange={(e) => setBurpProxyPort(e.target.value)}
                              className="custom-input"
                              placeholder="8080"
                            />
                          </Form.Group>
                        </Col>
                      </Row>
                      <Button 
                        variant="outline-danger" 
                        size="sm"
                        onClick={saveSettings}
                        disabled={saving}
                      >
                        {saving ? 'Saving...' : 'Save Proxy Settings'}
                      </Button>
                    </div>

                    <hr className="border-secondary" />

                    <div className="mb-4">
                      <h6 className="text-white mb-3">URL List</h6>
                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">
                          Paste URLs (separated by newlines or commas)
                        </Form.Label>
                        <Form.Control
                          as="textarea"
                          rows={10}
                          value={rawInput}
                          onChange={(e) => {
                            setRawInput(e.target.value);
                            setVerifyStatus(null);
                            setParsedDomains([]);
                          }}
                          className="custom-input"
                          placeholder="example.com/path?param=value&#10;https://another-example.com/endpoint&#10;http://test.org/api, domain.net/search?q=test"
                          style={{ fontFamily: 'monospace' }}
                        />
                      </Form.Group>
                      
                      <div className="d-flex gap-2">
                        <Button 
                          variant="outline-danger" 
                          onClick={handleVerify}
                        >
                          <i className="bi bi-check-circle me-2"></i>
                          Verify List
                        </Button>
                        <Button 
                          variant="outline-secondary" 
                          onClick={() => {
                            setRawInput('');
                            setVerifyStatus(null);
                            setParsedDomains([]);
                          }}
                        >
                          <i className="bi bi-x-circle me-2"></i>
                          Clear
                        </Button>
                      </div>

                      {verifyStatus && (
                        <Alert 
                          variant={verifyStatus.success ? 'success' : 'warning'} 
                          className="mt-3"
                        >
                          {verifyStatus.message}
                        </Alert>
                      )}
                    </div>

                    {parsedDomains.length > 0 && (
                      <div className="mb-4">
                        <h6 className="text-white mb-3">Parsed URLs ({parsedDomains.length})</h6>
                        <div 
                          className="p-3 rounded" 
                          style={{ 
                            backgroundColor: '#212529', 
                            maxHeight: '200px', 
                            overflowY: 'auto',
                            fontFamily: 'monospace',
                            fontSize: '0.9em'
                          }}
                        >
                          {parsedDomains.map((url, idx) => (
                            <div key={idx} className="text-white">
                              {url}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <hr className="border-secondary" />

                    <div className="mb-4">
                      <h6 className="text-white mb-3">Protocol Selection</h6>
                      <Form.Group>
                        <div className="d-flex gap-3">
                          <Form.Check
                            type="radio"
                            id="protocol-https"
                            label="HTTPS"
                            name="protocol"
                            value="https"
                            checked={protocol === 'https'}
                            onChange={(e) => setProtocol(e.target.value)}
                            className="text-white"
                          />
                          <Form.Check
                            type="radio"
                            id="protocol-http"
                            label="HTTP"
                            name="protocol"
                            value="http"
                            checked={protocol === 'http'}
                            onChange={(e) => setProtocol(e.target.value)}
                            className="text-white"
                          />
                          <Form.Check
                            type="radio"
                            id="protocol-both"
                            label="Both"
                            name="protocol"
                            value="Both"
                            checked={protocol === 'Both'}
                            onChange={(e) => setProtocol(e.target.value)}
                            className="text-white"
                          />
                        </div>
                      </Form.Group>
                    </div>

                    {populating && progress.total > 0 && (
                      <div className="mb-3">
                        <div className="d-flex justify-content-between mb-2">
                          <span className="text-white">
                            Progress: {progress.current} / {progress.total} URLs
                          </span>
                          <span className="text-white">
                            {Math.round((progress.current / progress.total) * 100)}%
                          </span>
                        </div>
                        <ProgressBar 
                          now={(progress.current / progress.total) * 100} 
                          variant="danger"
                          animated
                          striped
                        />
                      </div>
                    )}
                  </Tab.Pane>
                </Tab.Content>
              </Col>
            </Row>
          </Tab.Container>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button 
          variant="danger" 
          onClick={handlePopulateBurpsuite}
          disabled={populating || parsedDomains.length === 0}
        >
          {populating ? (
            <>
              <Spinner animation="border" size="sm" className="me-2" />
              Populating Burpsuite...
            </>
          ) : (
            <>
              <i className="bi bi-arrow-repeat me-2"></i>
              Populate Burpsuite
            </>
          )}
        </Button>
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

const styleSheet = `
  .nav-pills .nav-link.active {
    background-color: #dc3545 !important;
    color: #fff !important;
  }

  .nav-pills .nav-link:not(.active) {
    color: #dc3545 !important;
  }

  .nav-pills .nav-link:hover:not(.active) {
    color: #dc3545 !important;
    background-color: rgba(220, 53, 69, 0.1) !important;
  }

  .custom-input {
    background-color: #343a40 !important;
    border: 1px solid #495057;
    color: #fff !important;
  }

  .custom-input:focus {
    border-color: #dc3545 !important;
    box-shadow: 0 0 0 0.2rem rgba(220, 53, 69, 0.25) !important;
  }

  .custom-input::placeholder {
    color: #6c757d !important;
  }
`;

const styleElement = document.createElement('style');
styleElement.textContent = styleSheet;
document.head.appendChild(styleElement);

export default ToolsModal;

