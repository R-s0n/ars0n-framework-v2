import { useState, useEffect } from 'react';
import { Modal, Button, Form, Row, Col, Spinner, Accordion, Nav, Tab } from 'react-bootstrap';

// Add this CSS at the top of your component
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

function SettingsModal({ show, handleClose }) {
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [activeTab, setActiveTab] = useState('rate-limits');

  useEffect(() => {
    if (show) {
      fetchSettings();
      setSaveSuccess(false);
    }
  }, [show]);

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
      
      // Default settings
      const defaultSettings = {
        amass_rate_limit: 10,
        httpx_rate_limit: 150,
        subfinder_rate_limit: 20,
        gau_rate_limit: 10,
        sublist3r_rate_limit: 10,
        ctl_rate_limit: 10,
        shuffledns_rate_limit: 10000,
        cewl_rate_limit: 10,
        gospider_rate_limit: 5,
        subdomainizer_rate_limit: 5,
        nuclei_screenshot_rate_limit: 20
      };
      
      // Check if data is empty or missing expected properties
      const hasSettings = data && Object.keys(data).length > 0;
      
      // Use data if it has settings, otherwise use defaults
      setSettings(hasSettings ? data : defaultSettings);
    } catch (error) {
      console.error('Error fetching settings:', error);
      setError('Failed to load settings. Please try again.');
      // Set default values if fetch fails
      setSettings({
        amass_rate_limit: 10,
        httpx_rate_limit: 150,
        subfinder_rate_limit: 20,
        gau_rate_limit: 10,
        sublist3r_rate_limit: 10,
        ctl_rate_limit: 10,
        shuffledns_rate_limit: 10000,
        cewl_rate_limit: 10,
        gospider_rate_limit: 5,
        subdomainizer_rate_limit: 5,
        nuclei_screenshot_rate_limit: 20
      });
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (field, value) => {
    setSaveSuccess(false);
    setSettings(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleSave = async () => {
    try {
      setLoading(true);
      setSaveSuccess(false);
      setError(null);
      
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/user/settings`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(settings),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save settings');
      }

      setSaveSuccess(true);
      setTimeout(() => {
        handleClose();
      }, 1500);
    } catch (error) {
      console.error('Error saving settings:', error);
      setError('Failed to save settings. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const renderSlider = (tool, label, min, max, step, description) => (
    <Form.Group as={Row} className="mb-4 align-items-center">
      <Form.Label column sm={4} className="text-white">
        {label} Rate Limit
      </Form.Label>
      <Col sm={6}>
        <Form.Range
          min={min}
          max={max}
          step={step}
          value={settings[`${tool}_rate_limit`] || min}
          onChange={(e) => handleChange(`${tool}_rate_limit`, e.target.value)}
        />
        <p className="text-white-50 small mt-1">{description}</p>
      </Col>
      <Col sm={2} className="text-white text-center">
        {settings[`${tool}_rate_limit`] || min}
      </Col>
    </Form.Group>
  );

  // Tool descriptions
  const toolDescriptions = {
    amass: "Controls requests per second for DNS queries. Higher values may trigger rate limiting by DNS servers.",
    httpx: "Limits concurrent HTTP requests. Higher values increase speed but may trigger WAF blocks or IP bans.",
    subfinder: "Controls API request rate for passive sources. Higher values may exceed API rate limits.",
    gau: "Limits requests to archive.org and other sources. Higher values may trigger temporary IP blocks.",
    sublist3r: "Controls API request rate for multiple sources. Higher values may exceed API rate limits.",
    ctl: "Controls requests to Certificate Transparency logs. IMPORTANT: Values above 10 may result in temporary IP blocks from CT log providers.",
    shuffledns: "Controls concurrent massdns resolves. Default is 10000 as per shuffledns documentation.",
    cewl: "Limits requests when crawling web pages for words. Higher values may trigger WAF blocks.",
    gospider: "Controls concurrent crawling threads. Higher values may trigger anti-bot measures.",
    subdomainizer: "Limits requests when analyzing JavaScript files. Higher values may trigger rate limiting.",
    nuclei_screenshot: "Controls concurrent screenshot requests. Higher values increase speed but may trigger anti-bot measures."
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Settings</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {loading ? (
          <div className="text-center py-4">
            <Spinner animation="border" variant="danger" />
            <p className="text-white mt-3">Loading settings...</p>
          </div>
        ) : error ? (
          <div className="alert alert-danger">{error}</div>
        ) : saveSuccess ? (
          <div className="alert alert-success">Settings saved successfully!</div>
        ) : (
          <Tab.Container activeKey={activeTab} onSelect={setActiveTab}>
            <Row>
              <Col sm={3}>
                <Nav variant="pills" className="flex-column">
                  <Nav.Item>
                    <Nav.Link 
                      eventKey="rate-limits"
                      className={`text-danger ${activeTab === 'rate-limits' ? 'active' : ''}`}
                      style={{
                        ...(activeTab === 'rate-limits' ? styles.navLinkActive : styles.navLink),
                      }}
                    >
                      Rate Limits
                    </Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link 
                      eventKey="custom-http"
                      className={`text-danger ${activeTab === 'custom-http' ? 'active' : ''}`}
                      style={{
                        ...(activeTab === 'custom-http' ? styles.navLinkActive : styles.navLink),
                      }}
                    >
                      Custom HTTP
                    </Nav.Link>
                  </Nav.Item>
                </Nav>
              </Col>
              <Col sm={9}>
                <Tab.Content>
                  <Tab.Pane eventKey="rate-limits">
            <h5 className="text-danger mb-3">Tool Rate Limits</h5>
            <p className="text-white-50 small mb-4">
              Adjust the rate limits for each tool to balance between speed and avoiding rate limiting by target servers.
              Higher values = faster scans, but may trigger rate limiting or IP blocks.
            </p>
            
            <Accordion className="mb-4">
              <Accordion.Item eventKey="0">
                <Accordion.Header>About Rate Limiting</Accordion.Header>
                <Accordion.Body>
                  <p className="text-white-50 small">
                    Rate limiting controls how aggressively each tool sends requests to target servers or APIs. 
                    Setting appropriate rate limits is crucial for:
                  </p>
                  <ul className="text-white-50 small">
                    <li><strong>Avoiding IP blocks:</strong> Many services will temporarily block your IP if you send too many requests too quickly</li>
                    <li><strong>Bypassing WAFs:</strong> Web Application Firewalls often trigger on high-volume scanning</li>
                    <li><strong>Respecting API limits:</strong> Many tools use APIs with strict rate limits</li>
                    <li><strong>Staying stealthy:</strong> Lower rate limits help avoid detection during security testing</li>
                  </ul>
                  <p className="text-white-50 small">
                    <strong>Note:</strong> The exact implementation of rate limiting varies by tool. Some use requests per second, 
                    others use concurrent connections, and some use a combination of both.
                  </p>
                </Accordion.Body>
              </Accordion.Item>
            </Accordion>
            
            {renderSlider('amass', 'Amass', 1, 50, 1, toolDescriptions.amass)}
            {renderSlider('httpx', 'HTTPX', 50, 500, 10, toolDescriptions.httpx)}
            {renderSlider('subfinder', 'Subfinder', 1, 100, 1, toolDescriptions.subfinder)}
            {renderSlider('gau', 'GAU', 1, 50, 1, toolDescriptions.gau)}
            {renderSlider('sublist3r', 'Sublist3r', 1, 50, 1, toolDescriptions.sublist3r)}
            {renderSlider('ctl', 'CTL', 1, 50, 1, toolDescriptions.ctl)}
            {renderSlider('shuffledns', 'ShuffleDNS', 1000, 20000, 1000, toolDescriptions.shuffledns)}
            {renderSlider('cewl', 'CeWL', 1, 50, 1, toolDescriptions.cewl)}
            {renderSlider('gospider', 'GoSpider', 1, 20, 1, toolDescriptions.gospider)}
            {renderSlider('subdomainizer', 'Subdomainizer', 1, 20, 1, toolDescriptions.subdomainizer)}
            {renderSlider('nuclei_screenshot', 'Nuclei Screenshot', 1, 100, 1, toolDescriptions.nuclei_screenshot)}
                  </Tab.Pane>
                  <Tab.Pane eventKey="custom-http">
                    <h5 className="text-danger mb-3">Custom HTTP Settings</h5>
                    <p className="text-white-50 small mb-4">
                      Configure custom HTTP headers and user agent strings that will be used by the tools when making requests.
                    </p>
                    
                    <Accordion className="mb-4">
                      <Accordion.Item eventKey="0">
                        <Accordion.Header>About Custom HTTP Settings</Accordion.Header>
                        <Accordion.Body>
                          <p className="text-white-50 small">
                            Custom HTTP headers and User Agents are only applicable to tools that make direct HTTP requests. 
                            These settings will be used by the following tools:
                          </p>
                          <ul className="text-white-50 small">
                            <li>
                              <strong>HTTPX:</strong> Supports both custom headers and user agents
                              <br/>
                              <span className="fst-italic">Used for: HTTP request fingerprinting and web server discovery</span>
                            </li>
                            <li>
                              <strong>GoSpider:</strong> Supports both custom headers and user agents
                              <br/>
                              <span className="fst-italic">Used for: Web crawling and JavaScript analysis</span>
                            </li>
                            <li>
                              <strong>Nuclei:</strong> Supports custom headers (user agent via header)
                              <br/>
                              <span className="fst-italic">Used for: Taking screenshots of web applications</span>
                            </li>
                            <li>
                              <strong>CeWL:</strong> Supports custom user agent only
                              <br/>
                              <span className="fst-italic">Used for: Web crawling to generate custom wordlists</span>
                            </li>
                          </ul>
                          <p className="text-white-50 small mt-3">
                            <strong>Tools that don't use HTTP settings:</strong>
                          </p>
                          <ul className="text-white-50 small">
                            <li>
                              <strong>Amass:</strong> Focuses on DNS enumeration and network mapping
                              <br/>
                              <span className="fst-italic">Doesn't make direct HTTP requests - uses DNS protocols and APIs</span>
                            </li>
                            <li>
                              <strong>Subfinder:</strong> Performs passive subdomain enumeration
                              <br/>
                              <span className="fst-italic">Uses APIs and search engines rather than direct HTTP requests</span>
                            </li>
                            <li>
                              <strong>ShuffleDNS:</strong> DNS resolver and subdomain brute-forcer
                              <br/>
                              <span className="fst-italic">Works at the DNS protocol level, not HTTP</span>
                            </li>
                            <li>
                              <strong>Sublist3r:</strong> Passive subdomain enumeration
                              <br/>
                              <span className="fst-italic">Uses search engine APIs rather than direct HTTP requests</span>
                            </li>
                            <li>
                              <strong>Subdomainizer:</strong> Parses JavaScript files locally after downloading
                              <br/>
                              <span className="fst-italic">Uses basic Python requests without custom HTTP settings</span>
                            </li>
                            <li>
                              <strong>GAU:</strong> URL fetching from web archives
                              <br/>
                              <span className="fst-italic">Uses its own HTTP client settings, doesn't support custom headers/UA</span>
                            </li>
                          </ul>
                          <p className="text-white-50 small mt-3">
                            <strong>Note:</strong> Tools that don't support custom HTTP settings typically operate at the DNS level 
                            or use third-party APIs for data collection. These tools focus on network-level reconnaissance rather 
                            than direct web application interaction.
                          </p>
                        </Accordion.Body>
                      </Accordion.Item>
                    </Accordion>
                    
                    <Form.Group className="mb-4">
                      <Form.Label className="text-white">Custom User Agent</Form.Label>
                      <Form.Control
                        type="text"
                        placeholder="Example: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                        value={settings.custom_user_agent || ''}
                        onChange={(e) => handleChange('custom_user_agent', e.target.value)}
                        className="custom-input"
                      />
                    </Form.Group>

                    <Form.Group className="mb-4">
                      <Form.Label className="text-white">Custom Header</Form.Label>
                      <Form.Control
                        type="text"
                        placeholder="Example: X-Custom-Header: my-custom-value"
                        value={settings.custom_header || ''}
                        onChange={(e) => handleChange('custom_header', e.target.value)}
                        className="custom-input"
                      />
                    </Form.Group>
                  </Tab.Pane>
                </Tab.Content>
              </Col>
            </Row>
          </Tab.Container>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Cancel
        </Button>
        <Button 
          variant="danger" 
          onClick={handleSave} 
          disabled={loading || saveSuccess}
        >
          {loading ? 'Saving...' : saveSuccess ? 'Saved!' : 'Save Settings'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

// Add this CSS as a style tag in your component or in your global CSS file
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

// Add the styles to the document
const styleElement = document.createElement('style');
styleElement.textContent = styleSheet;
document.head.appendChild(styleElement);

export default SettingsModal; 