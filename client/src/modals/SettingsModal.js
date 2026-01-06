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

function SettingsModal({ show, handleClose, initialTab = 'rate-limits', onApiKeyDeleted }) {
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [activeTab, setActiveTab] = useState(initialTab);
  const [apiKeys, setApiKeys] = useState([]);
  const [apiKeyLoading, setApiKeyLoading] = useState(false);
  const [newApiKey, setNewApiKey] = useState({
    toolName: '',
    name: '',
    apiKey: '',
    appId: '',
    appSecret: ''
  });
  const [saving, setSaving] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [toastVariant, setToastVariant] = useState('success');

  const [aiApiKeys, setAiApiKeys] = useState([]);
  const [aiApiKeyLoading, setAiApiKeyLoading] = useState(false);
  const [newAiApiKey, setNewAiApiKey] = useState({
    provider: '',
    name: '',
    apiKey: '',
    organizationId: '',
    projectId: '',
    endpoint: ''
  });

  useEffect(() => {
    if (show) {
      fetchSettings();
      fetchApiKeys();
      fetchAiApiKeys();
      setSaveSuccess(false);
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
        nuclei_screenshot_rate_limit: 20,
        burp_proxy_ip: '127.0.0.1',
        burp_proxy_port: 8080,
        burp_api_ip: '127.0.0.1',
        burp_api_port: 1337,
        burp_api_key: ''
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
        nuclei_screenshot_rate_limit: 20,
        burp_proxy_ip: '127.0.0.1',
        burp_proxy_port: 8080,
        burp_api_ip: '127.0.0.1',
        burp_api_port: 1337,
        burp_api_key: ''
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
    setSaving(true);
    try {
      if (activeTab === 'api-keys') {
        // For API keys, just close the modal after successful save
        await handleCreateApiKey();
        handleClose();
      } else {
        // For other settings, show the success toast
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

        setShowToast(true);
        setTimeout(() => {
          setShowToast(false);
          handleClose();
        }, 2000);
      }
    } catch (error) {
      console.error('Error saving settings:', error);
      setShowToast(true);
      setToastMessage('Error saving settings');
      setToastVariant('danger');
    } finally {
      setSaving(false);
    }
  };

  const fetchApiKeys = async () => {
    setApiKeyLoading(true);
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/api-keys`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch API keys');
      }
      
      const data = await response.json();
      setApiKeys(data || []);
    } catch (error) {
      console.error('Error fetching API keys:', error);
      setError('Failed to load API keys. Please try again.');
    } finally {
      setApiKeyLoading(false);
    }
  };

  const fetchAiApiKeys = async () => {
    setAiApiKeyLoading(true);
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/ai-api-keys`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch AI API keys');
      }
      
      const data = await response.json();
      setAiApiKeys(data || []);
    } catch (error) {
      console.error('Error fetching AI API keys:', error);
      setError('Failed to load AI API keys. Please try again.');
    } finally {
      setAiApiKeyLoading(false);
    }
  };

  const getKeyFieldsForTool = (toolName) => {
    switch (toolName) {
      case 'Censys':
        return [
          { name: 'app_id', label: 'App ID', type: 'text' },
          { name: 'app_secret', label: 'App Secret', type: 'text' }
        ];
      default:
        return [
          { name: 'api_key', label: 'API Key', type: 'text' }
        ];
    }
  };

  const getAiKeyFieldsForProvider = (provider) => {
    switch (provider) {
      case 'OpenAI':
        return [
          { name: 'api_key', label: 'API Key', type: 'text', required: true },
          { name: 'organization_id', label: 'Organization ID', type: 'text', required: false }
        ];
      case 'Anthropic':
        return [
          { name: 'api_key', label: 'API Key', type: 'text', required: true }
        ];
      case 'Google':
        return [
          { name: 'api_key', label: 'API Key', type: 'text', required: true },
          { name: 'project_id', label: 'Project ID', type: 'text', required: false }
        ];
      case 'Azure OpenAI':
        return [
          { name: 'api_key', label: 'API Key', type: 'text', required: true },
          { name: 'endpoint', label: 'Endpoint URL', type: 'text', required: true }
        ];
      case 'Cohere':
      case 'Hugging Face':
      case 'Replicate':
      case 'Together AI':
      case 'Perplexity':
      case 'Mistral AI':
      default:
        return [
          { name: 'api_key', label: 'API Key', type: 'text', required: true }
        ];
    }
  };

  const handleCreateApiKey = async () => {
    if (!newApiKey.toolName || !newApiKey.name) {
      setToastMessage('Please fill in all required fields');
      setToastVariant('danger');
      setShowToast(true);
      return;
    }

    // Validate key values based on tool type
    if ((newApiKey.toolName === 'SecurityTrails' || newApiKey.toolName === 'GitHub' || newApiKey.toolName === 'Shodan') && !newApiKey.apiKey) {
      setToastMessage('API Key is required for this tool');
      setToastVariant('danger');
      setShowToast(true);
      return;
    }

    if (newApiKey.toolName === 'Censys' && (!newApiKey.appId || !newApiKey.appSecret)) {
      setToastMessage('App ID and App Secret are required for Censys');
      setToastVariant('danger');
      setShowToast(true);
      return;
    }

    // Check if this is the first key for this tool
    const existingKeysForTool = apiKeys.filter(key => key.tool_name === newApiKey.toolName);
    const isFirstKeyForTool = existingKeysForTool.length === 0;
    const hasExistingSelection = localStorage.getItem(`selectedApiKey_${newApiKey.toolName}`);

    try {
      const keyValues = {};
      
      if (newApiKey.toolName === 'SecurityTrails' || newApiKey.toolName === 'GitHub' || newApiKey.toolName === 'Shodan') {
        keyValues.api_key = newApiKey.apiKey;
      } else if (newApiKey.toolName === 'Censys') {
        keyValues.app_id = newApiKey.appId;
        keyValues.app_secret = newApiKey.appSecret;
      }

      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/api-keys`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            tool_name: newApiKey.toolName,
            api_key_name: newApiKey.name,
            key_values: keyValues,
          }),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to create API key');
      }

      // If this is the first key for the tool OR there's no existing selection, make it the default
      if (isFirstKeyForTool || !hasExistingSelection) {
        localStorage.setItem(`selectedApiKey_${newApiKey.toolName}`, newApiKey.name);
        
        // Notify parent component about the new default selection
        if (newApiKey.toolName === 'SecurityTrails') {
          onApiKeyDeleted?.(); // This will trigger a re-check of all API keys
        } else if (newApiKey.toolName === 'GitHub') {
          onApiKeyDeleted?.();
        } else if (newApiKey.toolName === 'Censys') {
          onApiKeyDeleted?.();
        } else if (newApiKey.toolName === 'Shodan') {
          onApiKeyDeleted?.();
        }
      }

      // Reset form
      setNewApiKey({
        toolName: '',
        name: '',
        apiKey: '',
        appId: '',
        appSecret: ''
      });

      // Refresh the API keys list
      await fetchApiKeys();

      setToastMessage(`API key "${newApiKey.name}" created successfully${(isFirstKeyForTool || !hasExistingSelection) ? ' and set as default' : ''}`);
      setToastVariant('success');
      setShowToast(true);
    } catch (error) {
      console.error('Error creating API key:', error);
      setToastMessage(error.message || 'Error creating API key');
      setToastVariant('danger');
      setShowToast(true);
    }
  };

  const handleCreateAiApiKey = async () => {
    if (!newAiApiKey.provider || !newAiApiKey.name) {
      setToastMessage('Please fill in all required fields');
      setToastVariant('danger');
      setShowToast(true);
      return;
    }

    // Validate required fields based on provider
    const requiredFields = getAiKeyFieldsForProvider(newAiApiKey.provider).filter(field => field.required);
    for (const field of requiredFields) {
      const fieldValue = getAiFieldValue(field.name);
      if (!fieldValue) {
        setToastMessage(`${field.label} is required for ${newAiApiKey.provider}`);
        setToastVariant('danger');
        setShowToast(true);
        return;
      }
    }

    try {
      const keyValues = {};
      
      // Build key values based on provider
      if (newAiApiKey.apiKey) keyValues.api_key = newAiApiKey.apiKey;
      if (newAiApiKey.organizationId) keyValues.organization_id = newAiApiKey.organizationId;
      if (newAiApiKey.projectId) keyValues.project_id = newAiApiKey.projectId;
      if (newAiApiKey.endpoint) keyValues.endpoint = newAiApiKey.endpoint;

      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/ai-api-keys`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            provider: newAiApiKey.provider,
            api_key_name: newAiApiKey.name,
            key_values: keyValues,
          }),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to create AI API key');
      }

      // Reset form
      setNewAiApiKey({
        provider: '',
        name: '',
        apiKey: '',
        organizationId: '',
        projectId: '',
        endpoint: ''
      });

      // Refresh the AI API keys list
      await fetchAiApiKeys();

      setToastMessage(`AI API key "${newAiApiKey.name}" created successfully`);
      setToastVariant('success');
      setShowToast(true);
    } catch (error) {
      console.error('Error creating AI API key:', error);
      setToastMessage(error.message || 'Error creating AI API key');
      setToastVariant('danger');
      setShowToast(true);
    }
  };

  const getAiFieldValue = (fieldName) => {
    switch (fieldName) {
      case 'api_key':
        return newAiApiKey.apiKey;
      case 'organization_id':
        return newAiApiKey.organizationId;
      case 'project_id':
        return newAiApiKey.projectId;
      case 'endpoint':
        return newAiApiKey.endpoint || '';
      default:
        return '';
    }
  };

  const handleAiFieldChange = (fieldName, value) => {
    switch (fieldName) {
      case 'api_key':
        setNewAiApiKey(prev => ({ ...prev, apiKey: value }));
        break;
      case 'organization_id':
        setNewAiApiKey(prev => ({ ...prev, organizationId: value }));
        break;
      case 'project_id':
        setNewAiApiKey(prev => ({ ...prev, projectId: value }));
        break;
      case 'endpoint':
        setNewAiApiKey(prev => ({ ...prev, endpoint: value }));
        break;
    }
  };

  const handleDeleteApiKey = async (id) => {
    try {
      // Find the key being deleted to check if it's currently selected
      const keyToDelete = apiKeys.find(key => key.id === id);
      const selectedKeyName = keyToDelete ? localStorage.getItem(`selectedApiKey_${keyToDelete.tool_name}`) : null;
      
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/api-keys/${id}`,
        {
          method: 'DELETE',
        }
      );

      if (!response.ok) {
        throw new Error('Failed to delete API key');
      }

      // If the deleted key was the selected one, remove it from localStorage
      if (keyToDelete && selectedKeyName === keyToDelete.api_key_name) {
        localStorage.removeItem(`selectedApiKey_${keyToDelete.tool_name}`);
      }

      // Notify parent component to re-check API keys
      onApiKeyDeleted?.();

      // Refresh the API keys list
      await fetchApiKeys();
    } catch (error) {
      console.error('Error deleting API key:', error);
      setShowToast(true);
      setToastMessage('Error deleting API key');
      setToastVariant('danger');
    }
  };

  const handleDeleteAiApiKey = async (id) => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/ai-api-keys/${id}`,
        {
          method: 'DELETE',
        }
      );

      if (!response.ok) {
        throw new Error('Failed to delete AI API key');
      }

      // Refresh the AI API keys list
      await fetchAiApiKeys();

      setToastMessage('AI API key deleted successfully');
      setToastVariant('success');
      setShowToast(true);
    } catch (error) {
      console.error('Error deleting AI API key:', error);
      setShowToast(true);
      setToastMessage('Error deleting AI API key');
      setToastVariant('danger');
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

  const truncateApiKey = (key, maxLength = 20) => {
    if (!key || key.length <= maxLength) {
      return key;
    }
    
    const prefixLength = Math.floor(maxLength / 3);
    const suffixLength = Math.floor(maxLength / 3);
    const prefix = key.substring(0, prefixLength);
    const suffix = key.substring(key.length - suffixLength);
    
    return `${prefix}...${suffix}`;
  };

  const renderApiKeyValue = (apiKey) => {
    if (apiKey.tool_name === 'Censys') {
      return `${truncateApiKey(apiKey.key_values.app_id)}:${truncateApiKey(apiKey.key_values.app_secret)}`;
    }
    return truncateApiKey(apiKey.key_values.api_key);
  };

  return (
    <Modal 
      show={show} 
      onHide={handleClose} 
      size="xl"
      data-bs-theme="dark"
    >
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
                  <Nav.Item>
                    <Nav.Link 
                      eventKey="api-keys"
                      className={`text-danger ${activeTab === 'api-keys' ? 'active' : ''}`}
                      style={{
                        ...(activeTab === 'api-keys' ? styles.navLinkActive : styles.navLink),
                      }}
                    >
                      API Keys
                    </Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link 
                      eventKey="burp-suite"
                      className={`text-danger ${activeTab === 'burp-suite' ? 'active' : ''}`}
                      style={{
                        ...(activeTab === 'burp-suite' ? styles.navLinkActive : styles.navLink),
                      }}
                    >
                      Burp Suite
                    </Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link 
                      eventKey="ai-api-keys"
                      className={`text-danger ${activeTab === 'ai-api-keys' ? 'active' : ''}`}
                      style={{
                        ...(activeTab === 'ai-api-keys' ? styles.navLinkActive : styles.navLink),
                      }}
                    >
                      AI API Keys
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
                  <Tab.Pane eventKey="api-keys">
                    <h5 className="text-danger mb-3">API Keys Management</h5>
                    <p className="text-white-50 small mb-4">
                      Manage API keys for the Domain Discovery tools. These keys will be used to enhance the capabilities of the tools.
                    </p>
                    
                    <div className="mb-4">
                      <h6 className="text-white mb-3">Add New API Key</h6>
                      <Row className="mb-3">
                        <Col md={6}>
                          <Form.Group>
                            <Form.Label className="text-white">Tool</Form.Label>
                            <Form.Select
                              value={newApiKey.toolName}
                              onChange={(e) => setNewApiKey(prev => ({ ...prev, toolName: e.target.value }))}
                              className="custom-input"
                            >
                              <option value="">Select a tool</option>
                              <option value="SecurityTrails">SecurityTrails</option>
                              <option value="Censys">Censys</option>
                              <option value="Shodan">Shodan</option>
                              <option value="GitHub">GitHub</option>
                            </Form.Select>
                          </Form.Group>
                        </Col>
                        <Col md={6}>
                          <Form.Group>
                            <Form.Label className="text-white">Key Name</Form.Label>
                            <Form.Control
                              type="text"
                              value={newApiKey.name}
                              onChange={(e) => setNewApiKey(prev => ({ ...prev, name: e.target.value }))}
                              placeholder="Enter a name for this API key"
                              className="custom-input"
                            />
                          </Form.Group>
                        </Col>
                      </Row>
                      <Row className="mb-3">
                        {getKeyFieldsForTool(newApiKey.toolName).map((field) => {
                          const getFieldValue = (fieldName) => {
                            switch (fieldName) {
                              case 'api_key':
                                return newApiKey.apiKey;
                              case 'app_id':
                                return newApiKey.appId;
                              case 'app_secret':
                                return newApiKey.appSecret;
                              default:
                                return '';
                            }
                          };

                          const handleFieldChange = (fieldName, value) => {
                            switch (fieldName) {
                              case 'api_key':
                                setNewApiKey(prev => ({ ...prev, apiKey: value }));
                                break;
                              case 'app_id':
                                setNewApiKey(prev => ({ ...prev, appId: value }));
                                break;
                              case 'app_secret':
                                setNewApiKey(prev => ({ ...prev, appSecret: value }));
                                break;
                            }
                          };

                          return (
                            <Col key={field.name} md={field.name === 'api_key' ? 12 : 6}>
                              <Form.Group>
                                <Form.Label className="text-white">{field.label}</Form.Label>
                                <Form.Control
                                  type={field.type}
                                  value={getFieldValue(field.name)}
                                  onChange={(e) => handleFieldChange(field.name, e.target.value)}
                                  placeholder={`Enter ${field.label}`}
                                  className="custom-input"
                                />
                              </Form.Group>
                            </Col>
                          );
                        })}
                      </Row>
                      <Button 
                        variant="danger" 
                        onClick={handleCreateApiKey}
                        disabled={apiKeyLoading}
                      >
                        {apiKeyLoading ? 'Adding...' : 'Add API Key'}
                      </Button>
                    </div>

                    <div className="mb-4">
                      <h6 className="text-white mb-3">Existing API Keys</h6>
                      {apiKeyLoading ? (
                        <div className="text-center py-3">
                          <div className="spinner-border text-danger" role="status">
                            <span className="visually-hidden">Loading...</span>
                          </div>
                        </div>
                      ) : apiKeys.length === 0 ? (
                        <p className="text-white-50">No API keys configured yet.</p>
                      ) : (
                        <div className="list-group" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                          {apiKeys.map((apiKey) => (
                            <div key={apiKey.id} className="list-group-item bg-dark border-secondary d-flex justify-content-between align-items-center">
                              <div style={{ minWidth: 0, flex: 1 }}>
                                <strong className="text-danger">{apiKey.tool_name}</strong>
                                <br />
                                <span className="text-white">
                                  {apiKey.api_key_name}: {
                                    apiKey.tool_name === 'Censys' 
                                      ? `${truncateApiKey(apiKey.key_values.app_id)}:${truncateApiKey(apiKey.key_values.app_secret)}`
                                      : truncateApiKey(apiKey.key_values.api_key)
                                  }
                                </span>
                                <br />
                                <small className="text-white-50">
                                  Added: {new Date(apiKey.created_at).toLocaleDateString()}
                                </small>
                              </div>
                              <Button 
                                variant="outline-danger" 
                                size="sm"
                                onClick={() => handleDeleteApiKey(apiKey.id)}
                                disabled={apiKeyLoading}
                                style={{ flexShrink: 0, marginLeft: '10px' }}
                              >
                                Delete
                              </Button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </Tab.Pane>
                  <Tab.Pane eventKey="burp-suite">
                    <h5 className="text-danger mb-3">Burp Suite Configuration</h5>
                    <p className="text-white-50 small mb-4">
                      Configure your Burp Suite proxy and API settings for integration with the reconnaissance tools.
                    </p>
                    
                    <Accordion className="mb-4">
                      <Accordion.Item eventKey="0">
                        <Accordion.Header>About Burp Suite Integration</Accordion.Header>
                        <Accordion.Body>
                          <p className="text-white-50 small">
                            Burp Suite integration allows you to route HTTP traffic through your Burp proxy for analysis 
                            and to use Burp's API for advanced features:
                          </p>
                          <ul className="text-white-50 small">
                            <li><strong>Proxy Settings:</strong> Route tool traffic through Burp for request inspection and modification</li>
                            <li><strong>API Integration:</strong> Use Burp's REST API for automated scanning and analysis</li>
                            <li><strong>Traffic Analysis:</strong> Capture and analyze all HTTP requests from reconnaissance tools</li>
                            <li><strong>Custom Extensions:</strong> Leverage Burp extensions for enhanced functionality</li>
                          </ul>
                          <p className="text-white-50 small">
                            <strong>Note:</strong> Make sure Burp Suite is running and the proxy/API are properly configured 
                            before using these settings.
                          </p>
                        </Accordion.Body>
                      </Accordion.Item>
                    </Accordion>
                    
                    <Row>
                      <Col md={6}>
                        <h6 className="text-white mb-3">Proxy Configuration</h6>
                        <Form.Group className="mb-3">
                          <Form.Label className="text-white">Proxy IP Address</Form.Label>
                          <Form.Control
                            type="text"
                            placeholder="127.0.0.1"
                            value={settings.burp_proxy_ip || ''}
                            onChange={(e) => handleChange('burp_proxy_ip', e.target.value)}
                            className="custom-input"
                          />
                          <Form.Text className="text-white-50">
                            IP address where Burp proxy is listening (default: 127.0.0.1)
                          </Form.Text>
                        </Form.Group>

                        <Form.Group className="mb-3">
                          <Form.Label className="text-white">Proxy Port</Form.Label>
                          <Form.Control
                            type="number"
                            placeholder="8080"
                            value={settings.burp_proxy_port || ''}
                            onChange={(e) => handleChange('burp_proxy_port', parseInt(e.target.value) || '')}
                            className="custom-input"
                            min="1"
                            max="65535"
                          />
                          <Form.Text className="text-white-50">
                            Port where Burp proxy is listening (default: 8080)
                          </Form.Text>
                        </Form.Group>
                      </Col>

                      <Col md={6}>
                        <h6 className="text-white mb-3">API Configuration</h6>
                        <Form.Group className="mb-3">
                          <Form.Label className="text-white">API IP Address</Form.Label>
                          <Form.Control
                            type="text"
                            placeholder="127.0.0.1"
                            value={settings.burp_api_ip || ''}
                            onChange={(e) => handleChange('burp_api_ip', e.target.value)}
                            className="custom-input"
                          />
                          <Form.Text className="text-white-50">
                            IP address where Burp API is listening (default: 127.0.0.1)
                          </Form.Text>
                        </Form.Group>

                        <Form.Group className="mb-3">
                          <Form.Label className="text-white">API Port</Form.Label>
                          <Form.Control
                            type="number"
                            placeholder="1337"
                            value={settings.burp_api_port || ''}
                            onChange={(e) => handleChange('burp_api_port', parseInt(e.target.value) || '')}
                            className="custom-input"
                            min="1"
                            max="65535"
                          />
                          <Form.Text className="text-white-50">
                            Port where Burp API is listening (default: 1337)
                          </Form.Text>
                        </Form.Group>
                      </Col>
                    </Row>

                    <Form.Group className="mb-4">
                      <Form.Label className="text-white">API Key</Form.Label>
                      <Form.Control
                        type="text"
                        placeholder="Enter your Burp Suite API key (optional)"
                        value={settings.burp_api_key || ''}
                        onChange={(e) => handleChange('burp_api_key', e.target.value)}
                        className="custom-input"
                      />
                      <Form.Text className="text-white-50">
                        API key for authenticating with Burp Suite's REST API (leave empty if not required)
                      </Form.Text>
                    </Form.Group>
                  </Tab.Pane>
                  <Tab.Pane eventKey="ai-api-keys">
                    <h5 className="text-danger mb-3">AI API Keys Management</h5>
                    <p className="text-white-50 small mb-4">
                      Manage API keys for AI services like OpenAI, Anthropic, Google, and others for enhanced automation and analysis capabilities.
                    </p>
                    
                    <Accordion className="mb-4">
                      <Accordion.Item eventKey="0">
                        <Accordion.Header>About AI Integration</Accordion.Header>
                        <Accordion.Body>
                          <p className="text-white-50 small">
                            AI API integration enables advanced automation and analysis features:
                          </p>
                          <ul className="text-white-50 small">
                            <li><strong>Automated Analysis:</strong> Use AI to analyze reconnaissance results and identify patterns</li>
                            <li><strong>Content Generation:</strong> Generate reports, summaries, and documentation automatically</li>
                            <li><strong>Smart Filtering:</strong> Use AI to prioritize and categorize findings</li>
                            <li><strong>Natural Language Queries:</strong> Query your data using natural language</li>
                            <li><strong>Enhanced Reporting:</strong> Generate executive summaries and technical reports</li>
                          </ul>
                          <p className="text-white-50 small">
                            <strong>Supported Providers:</strong> OpenAI (GPT), Anthropic (Claude), Google (Gemini), Azure OpenAI, Cohere, Hugging Face, Replicate, Together AI, Perplexity, and Mistral AI.
                          </p>
                        </Accordion.Body>
                      </Accordion.Item>
                    </Accordion>
                    
                    <div className="mb-4">
                      <h6 className="text-white mb-3">Add New AI API Key</h6>
                      <Row className="mb-3">
                        <Col md={6}>
                          <Form.Group>
                            <Form.Label className="text-white">AI Provider</Form.Label>
                            <Form.Select
                              value={newAiApiKey.provider}
                              onChange={(e) => setNewAiApiKey(prev => ({ ...prev, provider: e.target.value }))}
                              className="custom-input"
                            >
                              <option value="">Select an AI provider</option>
                              <option value="OpenAI">OpenAI (GPT)</option>
                              <option value="Anthropic">Anthropic (Claude)</option>
                              <option value="Google">Google (Gemini)</option>
                              <option value="Azure OpenAI">Azure OpenAI</option>
                              <option value="Cohere">Cohere</option>
                              <option value="Hugging Face">Hugging Face</option>
                              <option value="Replicate">Replicate</option>
                              <option value="Together AI">Together AI</option>
                              <option value="Perplexity">Perplexity</option>
                              <option value="Mistral AI">Mistral AI</option>
                            </Form.Select>
                          </Form.Group>
                        </Col>
                        <Col md={6}>
                          <Form.Group>
                            <Form.Label className="text-white">Key Name</Form.Label>
                            <Form.Control
                              type="text"
                              value={newAiApiKey.name}
                              onChange={(e) => setNewAiApiKey(prev => ({ ...prev, name: e.target.value }))}
                              placeholder="Enter a name for this API key"
                              className="custom-input"
                            />
                          </Form.Group>
                        </Col>
                      </Row>
                      <Row className="mb-3">
                        {getAiKeyFieldsForProvider(newAiApiKey.provider).map((field) => (
                          <Col key={field.name} md={field.name === 'api_key' ? 12 : 6}>
                            <Form.Group>
                              <Form.Label className="text-white">
                                {field.label}
                                {field.required && <span className="text-danger">*</span>}
                              </Form.Label>
                              <Form.Control
                                type={field.type}
                                value={getAiFieldValue(field.name)}
                                onChange={(e) => handleAiFieldChange(field.name, e.target.value)}
                                placeholder={`Enter ${field.label}`}
                                className="custom-input"
                              />
                            </Form.Group>
                          </Col>
                        ))}
                      </Row>
                      <Button 
                        variant="danger" 
                        onClick={handleCreateAiApiKey}
                        disabled={aiApiKeyLoading}
                      >
                        {aiApiKeyLoading ? 'Adding...' : 'Add AI API Key'}
                      </Button>
                    </div>

                    <div className="mb-4">
                      <h6 className="text-white mb-3">Existing AI API Keys</h6>
                      {aiApiKeyLoading ? (
                        <div className="text-center py-3">
                          <div className="spinner-border text-danger" role="status">
                            <span className="visually-hidden">Loading...</span>
                          </div>
                        </div>
                      ) : aiApiKeys.length === 0 ? (
                        <p className="text-white-50">No AI API keys configured yet.</p>
                      ) : (
                        <div className="list-group" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                          {aiApiKeys.map((aiApiKey) => (
                            <div key={aiApiKey.id} className="list-group-item bg-dark border-secondary d-flex justify-content-between align-items-center">
                              <div style={{ minWidth: 0, flex: 1 }}>
                                <strong className="text-danger">{aiApiKey.provider}</strong>
                                <br />
                                <span className="text-white">
                                  {aiApiKey.api_key_name}: {truncateApiKey(aiApiKey.key_values.api_key)}
                                  {aiApiKey.key_values.organization_id && (
                                    <><br /><small className="text-white-50">Org: {truncateApiKey(aiApiKey.key_values.organization_id, 15)}</small></>
                                  )}
                                  {aiApiKey.key_values.project_id && (
                                    <><br /><small className="text-white-50">Project: {truncateApiKey(aiApiKey.key_values.project_id, 15)}</small></>
                                  )}
                                  {aiApiKey.key_values.endpoint && (
                                    <><br /><small className="text-white-50">Endpoint: {truncateApiKey(aiApiKey.key_values.endpoint, 30)}</small></>
                                  )}
                                </span>
                                <br />
                                <small className="text-white-50">
                                  Added: {new Date(aiApiKey.created_at).toLocaleDateString()}
                                </small>
                              </div>
                              <Button 
                                variant="outline-danger" 
                                size="sm"
                                onClick={() => handleDeleteAiApiKey(aiApiKey.id)}
                                disabled={aiApiKeyLoading}
                                style={{ flexShrink: 0, marginLeft: '10px' }}
                              >
                                Delete
                              </Button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
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
          disabled={loading || saving}
        >
          {loading ? 'Saving...' : saving ? 'Saving...' : 'Save Settings'}
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