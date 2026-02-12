import { Modal, Button, Form, Spinner, Row, Col } from 'react-bootstrap';
import { useState, useEffect } from 'react';

function AutoScanConfigModal({ show, handleClose, config, onSave, loading: externalLoading }) {
  const tools = [
    { id: 'amass', name: 'Amass' },
    { id: 'sublist3r', name: 'Sublist3r' },
    { id: 'assetfinder', name: 'Assetfinder' },
    { id: 'gau', name: 'GAU' },
    { id: 'ctl', name: 'CTL' },
    { id: 'subfinder', name: 'Subfinder' },
    { id: 'consolidate_httpx_round1', name: 'Consolidate & Live Web Servers (Round 1)' },
    { id: 'shuffledns', name: 'ShuffleDNS' },
    { id: 'cewl', name: 'CeWL' },
    { id: 'consolidate_httpx_round2', name: 'Consolidate & Live Web Servers (Round 2)' },
    { id: 'gospider', name: 'GoSpider' },
    { id: 'subdomainizer', name: 'Subdomainizer' },
    { id: 'consolidate_httpx_round3', name: 'Consolidate & Live Web Servers (Round 3)' },
    { id: 'metadata', name: 'Metadata' }
  ];

  const defaultConfig = {
    amass: true, sublist3r: true, assetfinder: true, gau: true, ctl: true, subfinder: true, consolidate_httpx_round1: true, shuffledns: true, cewl: true, consolidate_httpx_round2: true, gospider: true, subdomainizer: true, consolidate_httpx_round3: true, metadata: true, maxConsolidatedSubdomains: 2500, maxLiveWebServers: 500
  };

  const scanProfiles = {
    custom: {
      name: "Custom Scan",
      editable: true,
      config: { ...defaultConfig }
    },
    quick: {
      name: "Quick Scan",
      editable: false,
      config: {
        amass: false, 
        sublist3r: true, 
        assetfinder: true, 
        gau: true, 
        ctl: true, 
        subfinder: true, 
        consolidate_httpx_round1: true, 
        shuffledns: false, 
        cewl: false, 
        consolidate_httpx_round2: false, 
        gospider: false, 
        subdomainizer: false, 
        consolidate_httpx_round3: false, 
        metadata: true
      }
    },
    quickNoReport: {
      name: "Quick Scan No Report",
      editable: false,
      config: {
        amass: false, 
        sublist3r: true, 
        assetfinder: true, 
        gau: true, 
        ctl: true, 
        subfinder: true, 
        consolidate_httpx_round1: true, 
        shuffledns: false, 
        cewl: false, 
        consolidate_httpx_round2: false, 
        gospider: false, 
        subdomainizer: false, 
        consolidate_httpx_round3: false, 
        metadata: false
      }
    },
    balanced: {
      name: "Balanced Scan",
      editable: false,
      config: {
        amass: true, 
        sublist3r: true, 
        assetfinder: true, 
        gau: true, 
        ctl: true, 
        subfinder: true, 
        consolidate_httpx_round1: true, 
        shuffledns: true, 
        cewl: false, 
        consolidate_httpx_round2: true, 
        gospider: true, 
        subdomainizer: false, 
        consolidate_httpx_round3: true, 
        metadata: true
      }
    },
    noAmass: {
      name: "No Amass",
      editable: false,
      config: {
        amass: false, 
        sublist3r: true, 
        assetfinder: true, 
        gau: true, 
        ctl: true, 
        subfinder: true, 
        consolidate_httpx_round1: true, 
        shuffledns: true, 
        cewl: true, 
        consolidate_httpx_round2: true, 
        gospider: true, 
        subdomainizer: true, 
        consolidate_httpx_round3: true, 
        metadata: true
      }
    },
    noReport: {
      name: "No Report",
      editable: false,
      config: {
        amass: true, 
        sublist3r: true, 
        assetfinder: true, 
        gau: true, 
        ctl: true, 
        subfinder: true, 
        consolidate_httpx_round1: true, 
        shuffledns: true, 
        cewl: true, 
        consolidate_httpx_round2: true, 
        gospider: true, 
        subdomainizer: true, 
        consolidate_httpx_round3: true, 
        metadata: false
      }
    }
  };

  const [localConfig, setLocalConfig] = useState(defaultConfig);
  const [loading, setLoading] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [error, setError] = useState(null);
  const [selectedProfile, setSelectedProfile] = useState('custom');

  // Use external loading state if provided
  const isLoading = externalLoading || loading;

  useEffect(() => {
    if (config) {
      setLocalConfig({ ...defaultConfig, ...config });
    }
    setSaveSuccess(false);
    setError(null);
    setLoading(false);
    setSelectedProfile('custom');
  }, [config, show]);

  if (!localConfig) {
    return (
      <Modal show={show} onHide={handleClose} centered data-bs-theme="dark" size="lg">
        <Modal.Body className="bg-dark text-center">
          <Spinner animation="border" variant="danger" />
        </Modal.Body>
      </Modal>
    );
  }

  const handleCheckboxChange = (toolId) => {
    setLocalConfig((prev) => ({ ...prev, [toolId]: !prev[toolId] }));
  };

  const handleSliderChange = (key, value) => {
    setLocalConfig((prev) => ({ ...prev, [key]: value }));
  };

  const handleProfileChange = (e) => {
    const profile = e.target.value;
    setSelectedProfile(profile);
    
    if (profile === 'custom') {
      // Keep current settings if switching back to custom
      return;
    }
    
    // Apply the profile's tool configuration
    const toolConfig = scanProfiles[profile].config;
    
    // Update only the tool settings, preserving max values
    setLocalConfig(prev => ({
      ...prev,
      ...toolConfig
    }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setSaveSuccess(false);
    setError(null);
    try {
      const configToSend = {
        ...localConfig,
        nuclei_screenshot: localConfig.metadata
      };
      
      const response = await fetch(
        `/api/api/auto-scan-config`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(configToSend)
        }
      );
      if (!response.ok) {
        throw new Error('Failed to save configuration');
      }
      const savedConfig = await response.json();
      
      // Call the onSave callback with the saved configuration
      if (onSave) {
        onSave(savedConfig);
      }
      
      setSaveSuccess(true);
      setTimeout(() => {
        handleClose();
      }, 750);
    } catch (err) {
      setError('Failed to save configuration. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Split tools into two columns
  const leftColumnTools = tools.slice(0, Math.ceil(tools.length / 2));
  const rightColumnTools = tools.slice(Math.ceil(tools.length / 2));

  return (
    <Modal show={show} onHide={handleClose} centered data-bs-theme="dark" size="lg">
      <Modal.Header closeButton className="border-secondary">
        <Modal.Title className="text-danger">Auto Scan Configuration</Modal.Title>
      </Modal.Header>
      <Form onSubmit={handleSubmit}>
        <Modal.Body className="bg-dark">
          {error && <div className="alert alert-danger">{error}</div>}
          {saveSuccess && <div className="alert alert-success">Configuration saved successfully!</div>}
          
          <Form.Group className="mb-3">
            <Form.Label className="text-danger">Scan Profile</Form.Label>
            <Form.Select 
              value={selectedProfile} 
              onChange={handleProfileChange}
              className="bg-dark text-white border-secondary"
            >
              {Object.keys(scanProfiles).map(key => (
                <option key={key} value={key}>{scanProfiles[key].name}</option>
              ))}
            </Form.Select>
          </Form.Group>
          
          <hr className="text-secondary" />
          
          <Row>
            <Col md={6}>
              <Form.Group className="mb-3">
                {leftColumnTools.map((tool) => (
                  <Form.Check
                    key={tool.id}
                    type="checkbox"
                    id={tool.id}
                    name={tool.id}
                    label={tool.name}
                    checked={!!localConfig[tool.id]}
                    onChange={() => handleCheckboxChange(tool.id)}
                    className="mb-2 text-danger custom-checkbox"
                  />
                ))}
              </Form.Group>
            </Col>
            <Col md={6}>
              <Form.Group className="mb-3">
                {rightColumnTools.map((tool) => (
                  <Form.Check
                    key={tool.id}
                    type="checkbox"
                    id={tool.id}
                    name={tool.id}
                    label={tool.name}
                    checked={!!localConfig[tool.id]}
                    onChange={() => handleCheckboxChange(tool.id)}
                    className="mb-2 text-danger custom-checkbox"
                  />
                ))}
              </Form.Group>
            </Col>
          </Row>
          
          <hr className="text-secondary" />
          
          <Form.Group className="mb-4">
            <div className="d-flex justify-content-between align-items-center">
              <Form.Label className="text-danger mb-0">Max Consolidated Subdomains</Form.Label>
              <span className="text-white">{localConfig.maxConsolidatedSubdomains}</span>
            </div>
            <Form.Range
              min={10}
              max={10000}
              step={100}
              value={localConfig.maxConsolidatedSubdomains}
              onChange={e => handleSliderChange('maxConsolidatedSubdomains', Number(e.target.value))}
            />
          </Form.Group>
          <Form.Group className="mb-2">
            <div className="d-flex justify-content-between align-items-center">
              <Form.Label className="text-danger mb-0">Max Live Web Servers</Form.Label>
              <span className="text-white">{localConfig.maxLiveWebServers}</span>
            </div>
            <Form.Range
              min={5}
              max={2500}
              step={50}
              value={localConfig.maxLiveWebServers}
              onChange={e => handleSliderChange('maxLiveWebServers', Number(e.target.value))}
            />
          </Form.Group>
        </Modal.Body>
        <Modal.Footer className="border-secondary">
          <Button variant="outline-secondary" onClick={handleClose} disabled={isLoading}>
            Cancel
          </Button>
          <Button variant="outline-danger" type="submit" disabled={isLoading || saveSuccess}>
            {isLoading ? 'Saving...' : saveSuccess ? 'Saved!' : 'Save Configuration'}
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
}

export default AutoScanConfigModal; 