import { useState, useEffect } from 'react';
import { Modal, Button, Form, Row, Col, Spinner, Nav, Tab, Alert, ProgressBar } from 'react-bootstrap';
import jsyaml from 'js-yaml';

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

function ToolsModal({ show, handleClose, initialTab = 'url-populator', initialUrls = '' }) {
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

  const [apiSpec, setApiSpec] = useState(null);
  const [apiSpecFile, setApiSpecFile] = useState(null);
  const [apiKey, setApiKey] = useState('');
  const [apiProxyIP, setApiProxyIP] = useState('127.0.0.1');
  const [apiProxyPort, setApiProxyPort] = useState(8080);
  const [parsedEndpoints, setParsedEndpoints] = useState([]);
  const [apiPopulating, setApiPopulating] = useState(false);
  const [apiProgress, setApiProgress] = useState({ current: 0, total: 0 });
  const [showManualInputModal, setShowManualInputModal] = useState(false);
  const [manualInputsNeeded, setManualInputsNeeded] = useState([]);
  const [manualInputValues, setManualInputValues] = useState({});

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

  useEffect(() => {
    if (show && initialUrls) {
      setRawInput(initialUrls);
      setActiveTab('url-populator');
    }
  }, [show, initialUrls]);

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
        setSuccessMessage(`Successfully populated with ${urls.length} URL(s)!`);
      } else {
        setSuccessMessage(`Populated: ${successCount} successful, ${errorCount} failed out of ${urls.length} total.`);
      }
    } catch (err) {
      console.error('Error populating:', err);
      setError(`Failed to populate: ${err.message}`);
    } finally {
      setPopulating(false);
      setProgress({ current: 0, total: 0 });
    }
  };

  const handleApiSpecUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setError(null);
    setApiSpecFile(file);

    try {
      const text = await file.text();
      let spec;

      if (file.name.endsWith('.json')) {
        spec = JSON.parse(text);
      } else if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) {
        spec = jsyaml.load(text);
      } else {
        throw new Error('Unsupported file format. Please upload a JSON or YAML file.');
      }

      setApiSpec(spec);
      const endpoints = parseOpenApiSpec(spec);
      setParsedEndpoints(endpoints);
      
      if (endpoints.length === 0) {
        setError('No endpoints found in the OpenAPI specification.');
      }
    } catch (err) {
      console.error('Error parsing OpenAPI spec:', err);
      setError(`Failed to parse OpenAPI spec: ${err.message}`);
      setApiSpecFile(null);
      setApiSpec(null);
      setParsedEndpoints([]);
    }
  };

  const parseOpenApiSpec = (spec) => {
    const endpoints = [];
    const basePath = spec.basePath || '';
    const servers = spec.servers || [];
    const baseUrl = servers.length > 0 ? servers[0].url : '';

    const paths = spec.paths || {};
    
    Object.keys(paths).forEach(path => {
      const pathItem = paths[path];
      const methods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];
      
      methods.forEach(method => {
        if (pathItem[method]) {
          const operation = pathItem[method];
          endpoints.push({
            path: basePath + path,
            method: method,
            summary: operation.summary || '',
            description: operation.description || '',
            parameters: operation.parameters || [],
            requestBody: operation.requestBody || null,
            baseUrl: baseUrl,
            operationId: operation.operationId || `${method}_${path}`,
            security: operation.security || spec.security || []
          });
        }
      });
    });

    return endpoints;
  };

  const generateRequestBody = (endpoint) => {
    if (!endpoint.requestBody) return null;

    const content = endpoint.requestBody.content;
    if (!content) return null;

    const contentType = Object.keys(content)[0];
    const schema = content[contentType]?.schema;
    
    if (!schema) return null;

    return generateBodyFromSchema(schema, endpoint);
  };

  const generateBodyFromSchema = (schema, endpoint) => {
    if (schema.example) return schema.example;
    if (schema.examples && schema.examples.length > 0) return schema.examples[0];

    if (schema.type === 'object') {
      const obj = {};
      const properties = schema.properties || {};
      
      Object.keys(properties).forEach(key => {
        const prop = properties[key];
        
        if (prop.example !== undefined) {
          obj[key] = prop.example;
        } else if (prop.default !== undefined) {
          obj[key] = prop.default;
        } else if (prop.type === 'string') {
          obj[key] = prop.enum ? prop.enum[0] : `example_${key}`;
        } else if (prop.type === 'number' || prop.type === 'integer') {
          obj[key] = prop.minimum !== undefined ? prop.minimum : 0;
        } else if (prop.type === 'boolean') {
          obj[key] = false;
        } else if (prop.type === 'array') {
          obj[key] = [];
        } else if (prop.type === 'object') {
          obj[key] = generateBodyFromSchema(prop, endpoint);
        }
      });
      
      return obj;
    } else if (schema.type === 'array') {
      if (schema.items) {
        return [generateBodyFromSchema(schema.items, endpoint)];
      }
      return [];
    } else if (schema.type === 'string') {
      return schema.example || schema.default || 'example_string';
    } else if (schema.type === 'number' || schema.type === 'integer') {
      return schema.example || schema.default || 0;
    } else if (schema.type === 'boolean') {
      return schema.example !== undefined ? schema.example : false;
    }

    return null;
  };

  const needsManualInput = (endpoint, generatedBody) => {
    if (!endpoint.requestBody) return false;

    const content = endpoint.requestBody.content;
    if (!content) return false;

    const contentType = Object.keys(content)[0];
    const schema = content[contentType]?.schema;
    
    if (!schema || !schema.properties) return false;

    const required = schema.required || [];
    
    for (const key of required) {
      const prop = schema.properties[key];
      if (!prop.example && !prop.default && !generatedBody?.[key]) {
        return true;
      }
    }

    return false;
  };

  const handleProcessApiSpec = async () => {
    setError(null);
    setSuccessMessage(null);
    
    if (!apiSpec || parsedEndpoints.length === 0) {
      setError('Please upload a valid OpenAPI specification first.');
      return;
    }

    const endpointsNeedingInput = [];
    
    for (const endpoint of parsedEndpoints) {
      const generatedBody = generateRequestBody(endpoint);
      
      if (needsManualInput(endpoint, generatedBody)) {
        const content = endpoint.requestBody.content;
        const contentType = Object.keys(content)[0];
        const schema = content[contentType]?.schema;
        const required = schema.required || [];
        const properties = schema.properties || {};
        
        const inputs = [];
        for (const key of required) {
          const prop = properties[key];
          if (!prop.example && !prop.default) {
            inputs.push({
              key: key,
              type: prop.type || 'string',
              description: prop.description || '',
              example: prop.example || '',
              enum: prop.enum || null,
              required: true
            });
          }
        }
        
        if (inputs.length > 0) {
          endpointsNeedingInput.push({
            endpoint: endpoint,
            inputs: inputs,
            generatedBody: generatedBody
          });
        }
      }
    }

    if (endpointsNeedingInput.length > 0) {
      setManualInputsNeeded(endpointsNeedingInput);
      setShowManualInputModal(true);
      return;
    }

    await processApiEndpoints(parsedEndpoints);
  };

  const processApiEndpoints = async (endpoints) => {
    setApiPopulating(true);
    setApiProgress({ current: 0, total: endpoints.length });

    let successCount = 0;
    let errorCount = 0;

    try {
      for (let i = 0; i < endpoints.length; i++) {
        const endpoint = endpoints[i];
        
        try {
          const generatedBody = generateRequestBody(endpoint);
          
          const requestData = {
            method: endpoint.method,
            path: endpoint.path,
            baseUrl: endpoint.baseUrl,
            body: generatedBody,
            apiKey: apiKey,
            proxyIP: apiProxyIP,
            proxyPort: parseInt(apiProxyPort),
            parameters: endpoint.parameters,
            manualInputValues: manualInputValues[endpoint.operationId] || {}
          };

          const response = await fetch(
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api-populator/process`,
            {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(requestData),
            }
          );

          if (!response.ok) {
            const errorData = await response.text();
            console.error(`Failed to process endpoint ${i + 1}/${endpoints.length}: ${endpoint.method.toUpperCase()} ${endpoint.path}`, errorData);
            errorCount++;
          } else {
            successCount++;
          }
        } catch (err) {
          console.error(`Error processing endpoint ${i + 1}/${endpoints.length}: ${endpoint.method.toUpperCase()} ${endpoint.path}`, err);
          errorCount++;
        }

        setApiProgress({ current: i + 1, total: endpoints.length });
      }

      if (errorCount === 0) {
        setSuccessMessage(`Successfully processed ${endpoints.length} endpoint(s)!`);
      } else {
        setSuccessMessage(`Processed: ${successCount} successful, ${errorCount} failed out of ${endpoints.length} total.`);
      }
    } catch (err) {
      console.error('Error processing API endpoints:', err);
      setError(`Failed to process API endpoints: ${err.message}`);
    } finally {
      setApiPopulating(false);
      setApiProgress({ current: 0, total: 0 });
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
                      eventKey="url-populator"
                      className={activeTab === 'url-populator' ? 'active' : ''}
                    >
                      URL Populator
                    </Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link 
                      eventKey="api-populator"
                      className={activeTab === 'api-populator' ? 'active' : ''}
                    >
                      API Populator
                    </Nav.Link>
                  </Nav.Item>
                </Nav>
              </Col>
              <Col sm={9}>
                <Tab.Content>
                  <Tab.Pane eventKey="url-populator">
                    <h5 className="text-danger mb-4">URL Populator</h5>
                    
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

                  <Tab.Pane eventKey="api-populator">
                    <h5 className="text-danger mb-4">API Populator</h5>
                    
                    <Alert variant="warning" className="mb-4">
                      <strong>Experimental Feature:</strong> This tool is currently under active development and may have limitations or unexpected behavior. Please use with caution.
                    </Alert>
                    
                    {error && activeTab === 'api-populator' && (
                      <Alert variant="danger" dismissible onClose={() => setError(null)}>
                        {error}
                      </Alert>
                    )}
                    
                    {successMessage && activeTab === 'api-populator' && (
                      <Alert variant="success" dismissible onClose={() => setSuccessMessage(null)}>
                        {successMessage}
                      </Alert>
                    )}

                    <div className="mb-4">
                      <h6 className="text-white mb-3">Proxy Settings</h6>
                      <Row>
                        <Col md={6}>
                          <Form.Group className="mb-3">
                            <Form.Label className="text-white">Proxy IP Address</Form.Label>
                            <Form.Control
                              type="text"
                              value={apiProxyIP}
                              onChange={(e) => setApiProxyIP(e.target.value)}
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
                              value={apiProxyPort}
                              onChange={(e) => setApiProxyPort(e.target.value)}
                              className="custom-input"
                              placeholder="8080"
                            />
                          </Form.Group>
                        </Col>
                      </Row>
                    </div>

                    <hr className="border-secondary" />

                    <div className="mb-4">
                      <h6 className="text-white mb-3">API Configuration</h6>
                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">API Key</Form.Label>
                        <Form.Control
                          type="text"
                          value={apiKey}
                          onChange={(e) => setApiKey(e.target.value)}
                          className="custom-input"
                          placeholder="Enter your API key"
                        />
                      </Form.Group>

                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">Upload OpenAPI Specification (JSON or YAML)</Form.Label>
                        <Form.Control
                          type="file"
                          accept=".json,.yaml,.yml"
                          onChange={handleApiSpecUpload}
                          className="custom-input"
                        />
                        {apiSpecFile && (
                          <Form.Text className="text-success">
                            <i className="bi bi-check-circle me-2"></i>
                            File loaded: {apiSpecFile.name}
                          </Form.Text>
                        )}
                      </Form.Group>
                    </div>

                    {parsedEndpoints.length > 0 && (
                      <div className="mb-4">
                        <h6 className="text-white mb-3">Parsed Endpoints ({parsedEndpoints.length})</h6>
                        <div 
                          className="p-3 rounded" 
                          style={{ 
                            backgroundColor: '#212529', 
                            maxHeight: '300px', 
                            overflowY: 'auto',
                            fontFamily: 'monospace',
                            fontSize: '0.85em'
                          }}
                        >
                          {parsedEndpoints.map((endpoint, idx) => (
                            <div key={idx} className="mb-2 pb-2 border-bottom border-secondary">
                              <div className="text-white">
                                <span className="badge bg-primary me-2">{endpoint.method.toUpperCase()}</span>
                                <span>{endpoint.path}</span>
                              </div>
                              {endpoint.summary && (
                                <div className="text-muted small mt-1">{endpoint.summary}</div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {apiPopulating && apiProgress.total > 0 && (
                      <div className="mb-3">
                        <div className="d-flex justify-content-between mb-2">
                          <span className="text-white">
                            Progress: {apiProgress.current} / {apiProgress.total} Endpoints
                          </span>
                          <span className="text-white">
                            {Math.round((apiProgress.current / apiProgress.total) * 100)}%
                          </span>
                        </div>
                        <ProgressBar 
                          now={(apiProgress.current / apiProgress.total) * 100} 
                          variant="danger"
                          animated
                          striped
                        />
                      </div>
                    )}

                    <div className="d-flex gap-2">
                      <Button 
                        variant="danger" 
                        onClick={handleProcessApiSpec}
                        disabled={apiPopulating || !apiSpecFile}
                      >
                        {apiPopulating ? (
                          <>
                            <Spinner animation="border" size="sm" className="me-2" />
                            Processing...
                          </>
                        ) : (
                          <>
                            <i className="bi bi-play-fill me-2"></i>
                            Process
                          </>
                        )}
                      </Button>
                      <Button 
                        variant="outline-secondary" 
                        onClick={() => {
                          setApiSpecFile(null);
                          setApiSpec(null);
                          setParsedEndpoints([]);
                          setApiKey('');
                        }}
                        disabled={apiPopulating}
                      >
                        <i className="bi bi-x-circle me-2"></i>
                        Clear
                      </Button>
                    </div>
                  </Tab.Pane>
                </Tab.Content>
              </Col>
            </Row>
          </Tab.Container>
        )}
      </Modal.Body>
      <Modal.Footer>
        {activeTab === 'url-populator' && (
          <Button 
            variant="danger" 
            onClick={handlePopulateBurpsuite}
            disabled={populating || parsedDomains.length === 0}
          >
            {populating ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" />
                Populating...
              </>
            ) : (
              <>
                <i className="bi bi-arrow-repeat me-2"></i>
                Populate
              </>
            )}
          </Button>
        )}
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>

      <Modal
        show={showManualInputModal}
        onHide={() => setShowManualInputModal(false)}
        size="lg"
        data-bs-theme="dark"
      >
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">Manual Input Required</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Alert variant="info">
            Some endpoints require manual input for required parameters that don't have default or example values in the OpenAPI specification.
          </Alert>
          
          {manualInputsNeeded.map((item, idx) => (
            <div key={idx} className="mb-4 p-3 border border-secondary rounded">
              <h6 className="text-white mb-3">
                <span className="badge bg-primary me-2">{item.endpoint.method.toUpperCase()}</span>
                {item.endpoint.path}
              </h6>
              
              {item.inputs.map((input, inputIdx) => (
                <Form.Group key={inputIdx} className="mb-3">
                  <Form.Label className="text-white">
                    {input.key}
                    {input.required && <span className="text-danger ms-1">*</span>}
                  </Form.Label>
                  
                  {input.description && (
                    <Form.Text className="text-muted d-block mb-2">
                      {input.description}
                    </Form.Text>
                  )}
                  
                  {input.type && (
                    <Form.Text className="text-info d-block mb-2">
                      Type: {input.type}
                      {input.example && ` | Example: ${input.example}`}
                    </Form.Text>
                  )}
                  
                  {input.enum ? (
                    <Form.Select
                      className="custom-input"
                      value={manualInputValues[item.endpoint.operationId]?.[input.key] || ''}
                      onChange={(e) => {
                        setManualInputValues(prev => ({
                          ...prev,
                          [item.endpoint.operationId]: {
                            ...(prev[item.endpoint.operationId] || {}),
                            [input.key]: e.target.value
                          }
                        }));
                      }}
                    >
                      <option value="">Select {input.key}</option>
                      {input.enum.map((option, optIdx) => (
                        <option key={optIdx} value={option}>{option}</option>
                      ))}
                    </Form.Select>
                  ) : input.type === 'boolean' ? (
                    <Form.Check
                      type="checkbox"
                      className="text-white"
                      checked={manualInputValues[item.endpoint.operationId]?.[input.key] || false}
                      onChange={(e) => {
                        setManualInputValues(prev => ({
                          ...prev,
                          [item.endpoint.operationId]: {
                            ...(prev[item.endpoint.operationId] || {}),
                            [input.key]: e.target.checked
                          }
                        }));
                      }}
                      label={input.key}
                    />
                  ) : input.type === 'number' || input.type === 'integer' ? (
                    <Form.Control
                      type="number"
                      className="custom-input"
                      value={manualInputValues[item.endpoint.operationId]?.[input.key] || ''}
                      onChange={(e) => {
                        setManualInputValues(prev => ({
                          ...prev,
                          [item.endpoint.operationId]: {
                            ...(prev[item.endpoint.operationId] || {}),
                            [input.key]: parseFloat(e.target.value)
                          }
                        }));
                      }}
                      placeholder={`Enter ${input.key}`}
                    />
                  ) : (
                    <Form.Control
                      type="text"
                      className="custom-input"
                      value={manualInputValues[item.endpoint.operationId]?.[input.key] || ''}
                      onChange={(e) => {
                        setManualInputValues(prev => ({
                          ...prev,
                          [item.endpoint.operationId]: {
                            ...(prev[item.endpoint.operationId] || {}),
                            [input.key]: e.target.value
                          }
                        }));
                      }}
                      placeholder={`Enter ${input.key}`}
                    />
                  )}
                </Form.Group>
              ))}
            </div>
          ))}
        </Modal.Body>
        <Modal.Footer>
          <Button
            variant="danger"
            onClick={() => {
              setShowManualInputModal(false);
              processApiEndpoints(parsedEndpoints);
            }}
          >
            <i className="bi bi-play-fill me-2"></i>
            Process with Manual Input
          </Button>
          <Button
            variant="secondary"
            onClick={() => {
              setShowManualInputModal(false);
              setManualInputsNeeded([]);
              setManualInputValues({});
            }}
          >
            Cancel
          </Button>
        </Modal.Footer>
      </Modal>
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

