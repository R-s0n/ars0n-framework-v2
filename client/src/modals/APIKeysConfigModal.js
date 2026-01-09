import { useState, useEffect } from 'react';
import { Modal, Button, Form, Row, Col } from 'react-bootstrap';

function APIKeysConfigModal({ show, handleClose, onOpenSettings, onApiKeySelected }) {
  const [apiKeys, setApiKeys] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedKeys, setSelectedKeys] = useState({});

  const tools = [
    { name: 'SecurityTrails', displayName: 'SecurityTrails' },
    { name: 'GitHub', displayName: 'GitHub Recon Tools' },
    { name: 'Shodan', displayName: 'Shodan CLI / API' },
    { name: 'Censys', displayName: 'Censys CLI / API' }
  ];

  // Load selected keys from localStorage
  const loadSelectedKeysFromStorage = () => {
    const selectedKeysFromStorage = {};
    tools.forEach(tool => {
      const storedKeyName = localStorage.getItem(`selectedApiKey_${tool.name}`);
      if (storedKeyName && storedKeyName !== 'null') {
        selectedKeysFromStorage[tool.name] = storedKeyName;
      }
    });
    return selectedKeysFromStorage;
  };

  // Save selected key to localStorage
  const saveSelectedKeyToStorage = (toolName, keyName) => {
    if (keyName) {
      localStorage.setItem(`selectedApiKey_${toolName}`, keyName);
    } else {
      localStorage.removeItem(`selectedApiKey_${toolName}`);
    }
  };

  // Get the actual key ID from the key name
  const getKeyIdFromName = (toolName, keyName) => {
    if (!keyName) return '';
    const toolKeys = apiKeys.filter(key => key.tool_name === toolName);
    const foundKey = toolKeys.find(key => key.api_key_name === keyName);
    return foundKey ? foundKey.id : '';
  };

  useEffect(() => {
    if (show) {
      fetchApiKeys();
    }
  }, [show]);

  useEffect(() => {
    if (apiKeys.length > 0) {
      // Load selections from localStorage and validate they still exist
      const storedSelections = loadSelectedKeysFromStorage();
      const validatedSelections = {};
      
      tools.forEach(tool => {
        const storedKeyName = storedSelections[tool.name];
        if (storedKeyName) {
          const keyExists = apiKeys.some(key => 
            key.tool_name === tool.name && key.api_key_name === storedKeyName
          );
          if (keyExists) {
            validatedSelections[tool.name] = storedKeyName;
          } else {
            // Remove invalid key from localStorage
            localStorage.removeItem(`selectedApiKey_${tool.name}`);
          }
        }
      });
      
      setSelectedKeys(validatedSelections);
      
      // Notify parent of current selections
      notifyParentOfSelections(validatedSelections);
    }
  }, [apiKeys]);

  const fetchApiKeys = async () => {
    setLoading(true);
    try {
      const response = await fetch(
        `/api/api/api-keys`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch API keys');
      }
      
      const data = await response.json();
      setApiKeys(data || []);
    } catch (error) {
      console.error('Error fetching API keys:', error);
    } finally {
      setLoading(false);
    }
  };

  const getKeysForTool = (toolName) => {
    return apiKeys.filter(key => key.tool_name === toolName);
  };

  const notifyParentOfSelections = (selections) => {
    // Notify parent for each tool that has a selection
    Object.entries(selections).forEach(([toolName, keyName]) => {
      if (keyName) {
        const selectedKey = apiKeys.find(key => 
          key.tool_name === toolName && key.api_key_name === keyName
        );
        if (selectedKey) {
          const hasValidKey = validateKeyForTool(toolName, selectedKey);
          if (toolName === 'SecurityTrails') {
            onApiKeySelected?.(hasValidKey, 'securitytrails');
          } else if (toolName === 'Censys') {
            onApiKeySelected?.(hasValidKey, 'censys');
          } else if (toolName === 'GitHub') {
            onApiKeySelected?.(hasValidKey, 'github');
          } else if (toolName === 'Shodan') {
            onApiKeySelected?.(hasValidKey, 'shodan');
          }
        }
      }
    });
  };

  const validateKeyForTool = (toolName, selectedKey) => {
    if (toolName === 'SecurityTrails' || toolName === 'GitHub' || toolName === 'Shodan') {
      return selectedKey?.key_values?.api_key ? true : false;
    } else if (toolName === 'Censys') {
      return selectedKey?.key_values?.app_id && selectedKey?.key_values?.app_secret ? true : false;
    }
    return false;
  };

  const handleKeySelect = (toolName, keyName) => {
    const newSelections = {
      ...selectedKeys,
      [toolName]: keyName || undefined
    };
    
    // Remove undefined values
    Object.keys(newSelections).forEach(key => {
      if (newSelections[key] === undefined) {
        delete newSelections[key];
      }
    });
    
    setSelectedKeys(newSelections);
    
    // Save to localStorage
    saveSelectedKeyToStorage(toolName, keyName);

    // Notify parent when SecurityTrails, Censys, GitHub, or Shodan key is selected
    if ((toolName === 'SecurityTrails' || toolName === 'Censys' || toolName === 'GitHub' || toolName === 'Shodan') && keyName) {
      const selectedKey = apiKeys.find(key => 
        key.tool_name === toolName && key.api_key_name === keyName
      );
      const hasValidKey = validateKeyForTool(toolName, selectedKey);
      if (toolName === 'SecurityTrails') {
        onApiKeySelected?.(hasValidKey, 'securitytrails');
      } else if (toolName === 'Censys') {
        onApiKeySelected?.(hasValidKey, 'censys');
      } else if (toolName === 'GitHub') {
        onApiKeySelected?.(hasValidKey, 'github');
      } else if (toolName === 'Shodan') {
        onApiKeySelected?.(hasValidKey, 'shodan');
      }
    } else if (!keyName) {
      // Notify parent that key was deselected
      if (toolName === 'SecurityTrails') {
        onApiKeySelected?.(false, 'securitytrails');
      } else if (toolName === 'Censys') {
        onApiKeySelected?.(false, 'censys');
      } else if (toolName === 'GitHub') {
        onApiKeySelected?.(false, 'github');
      } else if (toolName === 'Shodan') {
        onApiKeySelected?.(false, 'shodan');
      }
    }
  };

  const handleModalClose = () => {
    handleClose();
  };

  const handleOpenSettingsModal = () => {
    handleModalClose();
    onOpenSettings();
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleModalClose} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Configure API Keys</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <style>
          {`
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
          `}
        </style>
        <p className="text-white-50 small mb-4">
          Select which API key to use for each tool. Your selection will be remembered. If no API key is available for a tool, you can add one using the Settings modal.
        </p>
        
        {loading ? (
          <div className="text-center py-4">
            <div className="spinner-border text-danger" role="status">
              <span className="visually-hidden">Loading...</span>
            </div>
          </div>
        ) : (
          <Row className="g-3">
            {tools.map((tool) => {
              const toolKeys = getKeysForTool(tool.name);
              
              return (
                <Col md={6} key={tool.name}>
                  <div className="border border-secondary rounded p-3">
                    <h6 className="text-danger mb-3">{tool.displayName}</h6>
                    
                    {toolKeys.length === 0 ? (
                      <div className="text-center">
                        <p className="text-white-50 small mb-3">No API keys available for this tool</p>
                        <Button 
                          variant="outline-danger" 
                          size="sm"
                          onClick={handleOpenSettingsModal}
                        >
                          Add API Key
                        </Button>
                      </div>
                    ) : (
                      <Form.Group>
                        <div className="d-flex justify-content-between align-items-center mb-2">
                          <Form.Label className="text-white small mb-0">Select API Key:</Form.Label>
                          {selectedKeys[tool.name] && (
                            <span className="text-success small">
                              <i className="fas fa-check-circle me-1"></i>Active
                            </span>
                          )}
                        </div>
                        <Form.Select
                          value={selectedKeys[tool.name] || ''}
                          onChange={(e) => handleKeySelect(tool.name, e.target.value)}
                          className="custom-input"
                        >
                          <option value="">-- No Key Selected --</option>
                          {toolKeys.map((key) => (
                            <option key={key.id} value={key.api_key_name}>
                              {key.api_key_name}
                              {selectedKeys[tool.name] === key.api_key_name ? ' ✓' : ''}
                            </option>
                          ))}
                        </Form.Select>
                      </Form.Group>
                    )}
                  </div>
                </Col>
              );
            })}
          </Row>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleModalClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default APIKeysConfigModal; 