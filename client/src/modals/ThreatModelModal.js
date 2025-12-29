import { useState, useEffect } from 'react';
import { Modal, Button, Form, ListGroup, Badge, Spinner, Alert, Card, Nav, Tab } from 'react-bootstrap';

const STRIDE_CATEGORIES = [
  {
    key: 'spoofing',
    label: '(S)poofing',
    description: 'Threats involving impersonation of users, systems, or data'
  },
  {
    key: 'tampering',
    label: '(T)ampering',
    description: 'Threats involving malicious modification of data or code'
  },
  {
    key: 'repudiation',
    label: '(R)epudiation',
    description: 'Threats where users deny performing actions without proper logging'
  },
  {
    key: 'information_disclosure',
    label: '(I)nformation Disclosure',
    description: 'Threats involving exposure of sensitive information'
  },
  {
    key: 'denial_of_service',
    label: '(D)enial of Service',
    description: 'Threats that prevent legitimate users from accessing the system'
  },
  {
    key: 'elevation_of_privilege',
    label: '(E)levation of Privilege',
    description: 'Threats where attackers gain unauthorized elevated permissions'
  }
];

export const ThreatModelModal = ({ 
  show, 
  handleClose, 
  activeTarget,
  mechanisms,
  notableObjects,
  securityControls
}) => {
  const [activeTab, setActiveTab] = useState('spoofing');
  const [threats, setThreats] = useState({});
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  
  const [isEditing, setIsEditing] = useState(false);
  const [editedThreat, setEditedThreat] = useState({
    url: '',
    mechanism: '',
    target_object: '',
    steps: [''],
    security_controls: [{control: '', explanation: ''}],
    impact_customer_data: '',
    impact_attacker_scope: '',
    impact_company_reputation: ''
  });

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [threatToDelete, setThreatToDelete] = useState(null);

  useEffect(() => {
    if (show && activeTarget) {
      fetchThreats();
      setActiveTab('spoofing');
      setSelectedThreat(null);
    }
  }, [show, activeTarget]);

  useEffect(() => {
    if (selectedThreat) {
      const threat = threats[activeTab]?.find(t => t.id === selectedThreat);
      if (threat) {
        setEditedThreat({
          url: threat.url || '',
          mechanism: threat.mechanism || '',
          target_object: threat.target_object || '',
          steps: threat.steps ? JSON.parse(threat.steps) : [''],
          security_controls: threat.security_controls ? JSON.parse(threat.security_controls) : [{control: '', explanation: ''}],
          impact_customer_data: threat.impact_customer_data || '',
          impact_attacker_scope: threat.impact_attacker_scope || '',
          impact_company_reputation: threat.impact_company_reputation || ''
        });
        setIsEditing(false);
      }
    }
  }, [selectedThreat, threats, activeTab]);

  const fetchThreats = async () => {
    if (!activeTarget) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/threat-model/${activeTarget.id}`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch threats');
      }

      const data = await response.json();
      const threatsMap = {};
      
      STRIDE_CATEGORIES.forEach(cat => {
        threatsMap[cat.key] = [];
      });

      if (Array.isArray(data)) {
        data.forEach(threat => {
          if (threatsMap[threat.category]) {
            threatsMap[threat.category].push(threat);
          }
        });
      }

      setThreats(threatsMap);
    } catch (error) {
      console.error('Error fetching threats:', error);
      setError('Failed to load threat model');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveThreat = async () => {
    if (!activeTarget || !editedThreat.url.trim()) {
      setError('URL is required');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      const stepsFiltered = editedThreat.steps.filter(s => s.trim());
      const securityControlsFiltered = editedThreat.security_controls.filter(sc => sc.control.trim() || sc.explanation.trim());
      
      const payload = {
        category: activeTab,
        url: editedThreat.url.trim(),
        mechanism: editedThreat.mechanism.trim(),
        target_object: editedThreat.target_object.trim(),
        steps: JSON.stringify(stepsFiltered),
        security_controls: JSON.stringify(securityControlsFiltered),
        impact_customer_data: editedThreat.impact_customer_data.trim(),
        impact_attacker_scope: editedThreat.impact_attacker_scope.trim(),
        impact_company_reputation: editedThreat.impact_company_reputation.trim()
      };

      const method = selectedThreat ? 'PUT' : 'POST';
      const url = selectedThreat
        ? `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/threat-model/${selectedThreat}`
        : `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/threat-model/${activeTarget.id}`;

      const response = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error('Failed to save threat');
      }

      const savedThreat = await response.json();
      
      setThreats(prev => {
        const updated = { ...prev };
        if (selectedThreat) {
          updated[activeTab] = updated[activeTab].map(t => 
            t.id === selectedThreat ? savedThreat : t
          );
        } else {
          updated[activeTab] = [...(updated[activeTab] || []), savedThreat];
        }
        return updated;
      });

      setSelectedThreat(savedThreat.id);
      setIsEditing(false);
    } catch (error) {
      console.error('Error saving threat:', error);
      setError('Failed to save threat');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteClick = (threatId) => {
    setThreatToDelete(threatId);
    setShowDeleteConfirm(true);
  };

  const handleConfirmDelete = async () => {
    if (!threatToDelete) return;

    setSaving(true);
    setError(null);
    setShowDeleteConfirm(false);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/threat-model/${threatToDelete}`,
        {
          method: 'DELETE'
        }
      );

      if (!response.ok) {
        throw new Error('Failed to delete threat');
      }

      setThreats(prev => {
        const updated = { ...prev };
        updated[activeTab] = updated[activeTab].filter(t => t.id !== threatToDelete);
        return updated;
      });

      if (selectedThreat === threatToDelete) {
        setSelectedThreat(null);
      }
    } catch (error) {
      console.error('Error deleting threat:', error);
      setError('Failed to delete threat');
    } finally {
      setSaving(false);
      setThreatToDelete(null);
    }
  };

  const handleCancelDelete = () => {
    setShowDeleteConfirm(false);
    setThreatToDelete(null);
  };

  const handleStartEdit = () => {
    setIsEditing(true);
  };

  const handleCancelEdit = () => {
    setIsEditing(false);
    if (selectedThreat) {
      const threat = threats[activeTab]?.find(t => t.id === selectedThreat);
      if (threat) {
        setEditedThreat({
          url: threat.url || '',
          mechanism: threat.mechanism || '',
          target_object: threat.target_object || '',
          steps: threat.steps ? JSON.parse(threat.steps) : [''],
          security_controls: threat.security_controls ? JSON.parse(threat.security_controls) : [{control: '', explanation: ''}],
          impact_customer_data: threat.impact_customer_data || '',
          impact_attacker_scope: threat.impact_attacker_scope || '',
          impact_company_reputation: threat.impact_company_reputation || ''
        });
      }
    }
  };

  const handleAddNewThreat = () => {
    setSelectedThreat(null);
    setEditedThreat({
      url: '',
      mechanism: '',
      target_object: '',
      steps: [''],
      security_controls: [{control: '', explanation: ''}],
      impact_customer_data: '',
      impact_attacker_scope: '',
      impact_company_reputation: ''
    });
    setIsEditing(true);
  };

  const handleAddStep = () => {
    setEditedThreat(prev => ({
      ...prev,
      steps: [...prev.steps, '']
    }));
  };

  const handleRemoveStep = (index) => {
    setEditedThreat(prev => ({
      ...prev,
      steps: prev.steps.filter((_, i) => i !== index)
    }));
  };

  const handleStepChange = (index, value) => {
    setEditedThreat(prev => ({
      ...prev,
      steps: prev.steps.map((step, i) => i === index ? value : step)
    }));
  };

  const handleAddSecurityControl = () => {
    setEditedThreat(prev => ({
      ...prev,
      security_controls: [...prev.security_controls, {control: '', explanation: ''}]
    }));
  };

  const handleRemoveSecurityControl = (index) => {
    setEditedThreat(prev => ({
      ...prev,
      security_controls: prev.security_controls.filter((_, i) => i !== index)
    }));
  };

  const handleSecurityControlChange = (index, field, value) => {
    setEditedThreat(prev => ({
      ...prev,
      security_controls: prev.security_controls.map((sc, i) => 
        i === index ? { ...sc, [field]: value } : sc
      )
    }));
  };

  const currentThreats = threats[activeTab] || [];
  const mechanismsList = mechanisms && Array.isArray(mechanisms) ? mechanisms : [];
  const objectsList = notableObjects && Array.isArray(notableObjects) ? notableObjects : [];
  const securityControlsList = securityControls && Array.isArray(securityControls) ? securityControls : [];

  return (
    <>
    <Modal 
      show={show} 
      onHide={handleClose} 
      fullscreen
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">
          STRIDE Threat Model
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="p-0">
        <Tab.Container activeKey={activeTab} onSelect={(k) => { setActiveTab(k); setSelectedThreat(null); }}>
          <div style={{ borderBottom: '1px solid #dc3545' }}>
            <Nav variant="tabs" className="px-3" style={{ borderBottom: 'none' }}>
              {STRIDE_CATEGORIES.map((cat) => (
                <Nav.Item key={cat.key}>
                  <Nav.Link 
                    eventKey={cat.key}
                    className={activeTab === cat.key ? 'text-white bg-danger' : 'text-danger'}
                    style={{
                      border: 'none',
                      borderBottom: activeTab === cat.key ? '3px solid #dc3545' : '3px solid transparent',
                      backgroundColor: activeTab === cat.key ? '#dc3545' : 'transparent'
                    }}
                  >
                    {cat.label}
                    {threats[cat.key] && threats[cat.key].length > 0 && (
                      <Badge bg="light" text="dark" className="ms-2">
                        {threats[cat.key].length}
                      </Badge>
                    )}
                  </Nav.Link>
                </Nav.Item>
              ))}
            </Nav>
          </div>

          <div className="d-flex h-100" style={{ height: 'calc(100vh - 180px)' }}>
            <div 
              className="border-end border-danger" 
              style={{ 
                width: '450px', 
                minWidth: '450px',
                maxWidth: '450px',
                flexShrink: 0,
                overflowY: 'auto', 
                backgroundColor: '#1a1a1a' 
              }}
            >
              <div className="p-3 bg-dark border-bottom border-danger d-flex justify-content-between align-items-center">
                <h6 className="text-danger mb-0">
                  {STRIDE_CATEGORIES.find(c => c.key === activeTab)?.label} Threats
                </h6>
                <Button 
                  variant="outline-danger" 
                  size="sm"
                  onClick={handleAddNewThreat}
                >
                  Add New
                </Button>
              </div>
              
              <ListGroup variant="flush">
                {currentThreats.map((threat, index) => {
                  const isSelected = selectedThreat === threat.id;
                  return (
                    <ListGroup.Item
                      key={threat.id}
                      action
                      active={isSelected}
                      onClick={() => setSelectedThreat(threat.id)}
                      className={`bg-dark text-white ${isSelected ? 'border-start border-3 border-danger' : ''}`}
                      style={{ 
                        cursor: 'pointer',
                        backgroundColor: isSelected ? '#2a1a1a !important' : undefined,
                        border: 'none',
                        borderBottom: '1px solid #333'
                      }}
                    >
                      <div className="d-flex justify-content-between align-items-start" style={{ gap: '8px' }}>
                        <div style={{ flex: '1 1 auto', minWidth: 0 }}>
                          <div className="small fw-bold text-truncate mb-1">
                            {threat.mechanism || 'Untitled Threat'}
                          </div>
                          <div className="small text-white-50 text-truncate">
                            {threat.target_object || 'No target specified'}
                          </div>
                        </div>
                      </div>
                    </ListGroup.Item>
                  );
                })}
                {currentThreats.length === 0 && (
                  <ListGroup.Item className="bg-dark text-white-50 text-center py-4">
                    No threats documented yet
                  </ListGroup.Item>
                )}
              </ListGroup>
            </div>

            <div className="flex-fill p-4" style={{ overflowY: 'auto' }}>
              {loading ? (
                <div className="text-center py-5">
                  <Spinner animation="border" variant="danger">
                    <span className="visually-hidden">Loading...</span>
                  </Spinner>
                </div>
              ) : selectedThreat || isEditing ? (
                <>
                  {error && (
                    <Alert variant="danger" dismissible onClose={() => setError(null)}>
                      {error}
                    </Alert>
                  )}

                  {isEditing ? (
                    <div>
                      <h5 className="text-danger mb-4">
                        {selectedThreat ? 'Edit Threat' : 'New Threat'}
                      </h5>

                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">URL <span className="text-danger">*</span></Form.Label>
                        <Form.Control
                          type="text"
                          value={editedThreat.url}
                          onChange={(e) => setEditedThreat(prev => ({ ...prev, url: e.target.value }))}
                          placeholder="https://example.com/endpoint"
                          data-bs-theme="dark"
                        />
                        <Form.Text className="text-white-50">
                          The URL where this threat could be exploited
                        </Form.Text>
                      </Form.Group>

                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">Mechanism</Form.Label>
                        <Form.Select
                          value={editedThreat.mechanism}
                          onChange={(e) => setEditedThreat(prev => ({ ...prev, mechanism: e.target.value }))}
                          data-bs-theme="dark"
                        >
                          <option value="">Select a mechanism...</option>
                          {mechanismsList.map((mech, idx) => (
                            <option key={idx} value={mech}>
                              {mech}
                            </option>
                          ))}
                        </Form.Select>
                        <Form.Text className="text-white-50">
                          The application mechanism being targeted
                        </Form.Text>
                      </Form.Group>

                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">Target Object</Form.Label>
                        <Form.Select
                          value={editedThreat.target_object}
                          onChange={(e) => setEditedThreat(prev => ({ ...prev, target_object: e.target.value }))}
                          data-bs-theme="dark"
                        >
                          <option value="">Select a target object...</option>
                          {objectsList.map((obj, idx) => (
                            <option key={idx} value={obj}>
                              {obj}
                            </option>
                          ))}
                        </Form.Select>
                        <Form.Text className="text-white-50">
                          The object that would be the target of the attack
                        </Form.Text>
                      </Form.Group>

                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">Attack Steps</Form.Label>
                        {editedThreat.steps.map((step, index) => (
                          <div key={index} className="d-flex gap-2 mb-2">
                            <Form.Control
                              type="text"
                              value={step}
                              onChange={(e) => handleStepChange(index, e.target.value)}
                              placeholder={`Step ${index + 1}...`}
                              data-bs-theme="dark"
                            />
                            <Button
                              variant="outline-danger"
                              size="sm"
                              onClick={() => handleRemoveStep(index)}
                              disabled={editedThreat.steps.length === 1}
                              style={{ minWidth: '40px' }}
                            >
                              -
                            </Button>
                          </div>
                        ))}
                        <Button
                          variant="outline-success"
                          size="sm"
                          onClick={handleAddStep}
                          className="mt-2"
                        >
                          + Add Step
                        </Button>
                        <Form.Text className="text-white-50 d-block mt-2">
                          Step-by-step instructions for executing the attack
                        </Form.Text>
                      </Form.Group>

                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">Affected Security Controls</Form.Label>
                        {editedThreat.security_controls.map((sc, index) => (
                          <div key={index} className="mb-3 p-3 border border-secondary rounded">
                            <div className="d-flex gap-2 mb-2 align-items-center">
                              <Form.Select
                                value={sc.control}
                                onChange={(e) => handleSecurityControlChange(index, 'control', e.target.value)}
                                data-bs-theme="dark"
                                size="sm"
                              >
                                <option value="">Select a security control...</option>
                                {securityControlsList.map((ctrl, idx) => (
                                  <option key={idx} value={ctrl}>
                                    {ctrl}
                                  </option>
                                ))}
                              </Form.Select>
                              <Button
                                variant="outline-danger"
                                size="sm"
                                onClick={() => handleRemoveSecurityControl(index)}
                                disabled={editedThreat.security_controls.length === 1}
                                style={{ minWidth: '40px' }}
                              >
                                -
                              </Button>
                            </div>
                            <Form.Control
                              as="textarea"
                              rows={2}
                              value={sc.explanation}
                              onChange={(e) => handleSecurityControlChange(index, 'explanation', e.target.value)}
                              placeholder="How does this control affect the attack? Does it prevent, mitigate, or detect it?"
                              data-bs-theme="dark"
                              size="sm"
                            />
                          </div>
                        ))}
                        <Button
                          variant="outline-success"
                          size="sm"
                          onClick={handleAddSecurityControl}
                          className="mt-2"
                        >
                          + Add Security Control
                        </Button>
                        <Form.Text className="text-white-50 d-block mt-2">
                          Document security controls that affect this threat and how they impact the attack
                        </Form.Text>
                      </Form.Group>

                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">Impact on Customer Data</Form.Label>
                        <Form.Control
                          as="textarea"
                          rows={3}
                          value={editedThreat.impact_customer_data}
                          onChange={(e) => setEditedThreat(prev => ({ ...prev, impact_customer_data: e.target.value }))}
                          placeholder="Describe how customer data could be affected..."
                          data-bs-theme="dark"
                        />
                      </Form.Group>

                      <Form.Group className="mb-3">
                        <Form.Label className="text-white">Impact on Attacker Scope</Form.Label>
                        <Form.Control
                          as="textarea"
                          rows={3}
                          value={editedThreat.impact_attacker_scope}
                          onChange={(e) => setEditedThreat(prev => ({ ...prev, impact_attacker_scope: e.target.value }))}
                          placeholder="Describe what access or capabilities the attacker would gain..."
                          data-bs-theme="dark"
                        />
                      </Form.Group>

                      <Form.Group className="mb-4">
                        <Form.Label className="text-white">Impact on Company Reputation</Form.Label>
                        <Form.Control
                          as="textarea"
                          rows={3}
                          value={editedThreat.impact_company_reputation}
                          onChange={(e) => setEditedThreat(prev => ({ ...prev, impact_company_reputation: e.target.value }))}
                          placeholder="Describe how this could affect the company's reputation..."
                          data-bs-theme="dark"
                        />
                      </Form.Group>

                      <div className="d-flex gap-2">
                        <Button
                          variant="success"
                          onClick={handleSaveThreat}
                          disabled={saving || !editedThreat.url.trim()}
                        >
                          {saving ? (
                            <>
                              <Spinner animation="border" size="sm" className="me-2" />
                              Saving...
                            </>
                          ) : (
                            'Save Threat'
                          )}
                        </Button>
                        <Button
                          variant="secondary"
                          onClick={handleCancelEdit}
                          disabled={saving}
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <div>
                      <div className="mb-4 d-flex justify-content-between align-items-center">
                        <h5 className="text-danger mb-0">Threat Details</h5>
                        <div className="d-flex gap-2">
                          <Button
                            variant="outline-warning"
                            size="sm"
                            onClick={handleStartEdit}
                          >
                            Edit
                          </Button>
                          <Button
                            variant="outline-danger"
                            size="sm"
                            onClick={() => handleDeleteClick(selectedThreat)}
                          >
                            Delete
                          </Button>
                        </div>
                      </div>

                      <Card className="bg-dark border-secondary mb-3">
                        <Card.Body>
                          <h6 className="text-danger">URL</h6>
                          <a 
                            href={editedThreat.url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-info text-break"
                          >
                            {editedThreat.url}
                          </a>
                        </Card.Body>
                      </Card>

                      {editedThreat.mechanism && (
                        <Card className="bg-dark border-secondary mb-3">
                          <Card.Body>
                            <h6 className="text-danger">Mechanism</h6>
                            <p className="text-white mb-0">{editedThreat.mechanism}</p>
                          </Card.Body>
                        </Card>
                      )}

                      {editedThreat.target_object && (
                        <Card className="bg-dark border-secondary mb-3">
                          <Card.Body>
                            <h6 className="text-danger">Target Object</h6>
                            <p className="text-white mb-0">{editedThreat.target_object}</p>
                          </Card.Body>
                        </Card>
                      )}

                      {editedThreat.steps && editedThreat.steps.length > 0 && editedThreat.steps[0] && (
                        <Card className="bg-dark border-secondary mb-3">
                          <Card.Body>
                            <h6 className="text-danger">Attack Steps</h6>
                            <ol className="text-white mb-0">
                              {editedThreat.steps.map((step, index) => (
                                step && <li key={index}>{step}</li>
                              ))}
                            </ol>
                          </Card.Body>
                        </Card>
                      )}

                      {editedThreat.security_controls && editedThreat.security_controls.length > 0 && 
                       editedThreat.security_controls.some(sc => sc.control || sc.explanation) && (
                        <Card className="bg-dark border-secondary mb-3">
                          <Card.Body>
                            <h6 className="text-danger">Affected Security Controls</h6>
                            {editedThreat.security_controls.map((sc, index) => (
                              (sc.control || sc.explanation) && (
                                <div key={index} className="mb-3 pb-3 border-bottom border-secondary last:border-0">
                                  {sc.control && (
                                    <div className="fw-bold text-warning mb-1">{sc.control}</div>
                                  )}
                                  {sc.explanation && (
                                    <div className="text-white small">{sc.explanation}</div>
                                  )}
                                </div>
                              )
                            ))}
                          </Card.Body>
                        </Card>
                      )}

                      <h6 className="text-danger mt-4 mb-3">Impact Assessment</h6>

                      {editedThreat.impact_customer_data && (
                        <Card className="bg-dark border-secondary mb-3">
                          <Card.Body>
                            <h6 className="text-warning">Customer Data</h6>
                            <p className="text-white mb-0" style={{ whiteSpace: 'pre-wrap' }}>
                              {editedThreat.impact_customer_data}
                            </p>
                          </Card.Body>
                        </Card>
                      )}

                      {editedThreat.impact_attacker_scope && (
                        <Card className="bg-dark border-secondary mb-3">
                          <Card.Body>
                            <h6 className="text-warning">Attacker Scope</h6>
                            <p className="text-white mb-0" style={{ whiteSpace: 'pre-wrap' }}>
                              {editedThreat.impact_attacker_scope}
                            </p>
                          </Card.Body>
                        </Card>
                      )}

                      {editedThreat.impact_company_reputation && (
                        <Card className="bg-dark border-secondary mb-3">
                          <Card.Body>
                            <h6 className="text-warning">Company Reputation</h6>
                            <p className="text-white mb-0" style={{ whiteSpace: 'pre-wrap' }}>
                              {editedThreat.impact_company_reputation}
                            </p>
                          </Card.Body>
                        </Card>
                      )}
                    </div>
                  )}
                </>
              ) : (
                <div className="py-4 px-4">
                  <Card className="bg-dark border-danger">
                  <Card.Body>
                    <h4 className="text-danger mb-4">STRIDE Threat Modeling</h4>
                    
                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">What is STRIDE?</h5>
                        <p>
                          STRIDE is a threat modeling methodology developed by Microsoft that helps identify and 
                          categorize security threats to applications. Each letter represents a different category 
                          of security threat.
                        </p>
                      </div>

                      <div className="text-white mb-4">
                        <h5 className="text-danger mb-3">STRIDE Categories</h5>
                        
                        <div className="mb-3">
                          <h6 className="text-info">(S)poofing</h6>
                          <p className="mb-2">
                            Threats involving impersonation of users, systems, or data. Examples include:
                          </p>
                          <ul className="small">
                            <li>Impersonating another user by stealing session tokens</li>
                            <li>Spoofing IP addresses or email headers</li>
                            <li>Bypassing authentication mechanisms</li>
                          </ul>
                        </div>

                        <div className="mb-3">
                          <h6 className="text-info">(T)ampering</h6>
                          <p className="mb-2">
                            Threats involving malicious modification of data or code. Examples include:
                          </p>
                          <ul className="small">
                            <li>Modifying data in transit or at rest</li>
                            <li>Manipulating prices or user privileges</li>
                            <li>Altering configuration files or database records</li>
                          </ul>
                        </div>

                        <div className="mb-3">
                          <h6 className="text-info">(R)epudiation</h6>
                          <p className="mb-2">
                            Threats where users deny performing actions without proper logging. Examples include:
                          </p>
                          <ul className="small">
                            <li>Performing actions without adequate audit trails</li>
                            <li>Deleting or modifying log files</li>
                            <li>Denying financial transactions or data modifications</li>
                          </ul>
                        </div>

                        <div className="mb-3">
                          <h6 className="text-info">(I)nformation Disclosure</h6>
                          <p className="mb-2">
                            Threats involving exposure of sensitive information. Examples include:
                          </p>
                          <ul className="small">
                            <li>Unauthorized access to sensitive data</li>
                            <li>Information leakage through error messages</li>
                            <li>Exposing PII, credentials, or business secrets</li>
                          </ul>
                        </div>

                        <div className="mb-3">
                          <h6 className="text-info">(D)enial of Service</h6>
                          <p className="mb-2">
                            Threats that prevent legitimate users from accessing the system. Examples include:
                          </p>
                          <ul className="small">
                            <li>Resource exhaustion attacks</li>
                            <li>Application crashes or hangs</li>
                            <li>Account lockouts or service disruptions</li>
                          </ul>
                        </div>

                        <div className="mb-3">
                          <h6 className="text-info">(E)levation of Privilege</h6>
                          <p className="mb-2">
                            Threats where attackers gain unauthorized elevated permissions. Examples include:
                          </p>
                          <ul className="small">
                            <li>Bypassing authorization checks</li>
                            <li>Privilege escalation from user to admin</li>
                            <li>Accessing restricted functionality or data</li>
                          </ul>
                        </div>
                      </div>

                      <div className="text-white mb-4">
                        <h5 className="text-danger mb-3">How to use this tool</h5>
                        <ol className="mb-2">
                          <li className="mb-2">
                            <strong>Select a STRIDE category</strong> - Choose the tab that best matches the type of threat
                          </li>
                          <li className="mb-2">
                            <strong>Document threats</strong> - Add specific threats you identify for each category
                          </li>
                          <li className="mb-2">
                            <strong>Link to your recon</strong> - Connect threats to mechanisms and objects you've already documented
                          </li>
                          <li className="mb-2">
                            <strong>Detail the attack</strong> - Provide step-by-step instructions for exploiting the threat
                          </li>
                          <li className="mb-2">
                            <strong>Assess impact</strong> - Document the potential business impact across multiple dimensions
                          </li>
                        </ol>
                      </div>

                      <Alert variant="info" className="mb-0">
                        <strong>Get started:</strong> Select a STRIDE category tab above, then click "Add New" to 
                        document your first threat. Start with the mechanisms and objects you've already identified 
                        during reconnaissance.
                      </Alert>
                    </Card.Body>
                  </Card>
                </div>
              )}
            </div>
          </div>
        </Tab.Container>
      </Modal.Body>
      <Modal.Footer className="bg-dark border-danger">
        <Button variant="outline-danger" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>

    <Modal 
      show={showDeleteConfirm} 
      onHide={handleCancelDelete}
      centered
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">Confirm Delete</Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark text-white">
        Are you sure you want to delete this threat? This action cannot be undone.
      </Modal.Body>
      <Modal.Footer className="bg-dark border-danger">
        <Button variant="outline-secondary" onClick={handleCancelDelete}>
          Cancel
        </Button>
        <Button variant="danger" onClick={handleConfirmDelete} disabled={saving}>
          {saving ? (
            <>
              <Spinner animation="border" size="sm" className="me-2" />
              Deleting...
            </>
          ) : (
            'Delete'
          )}
        </Button>
      </Modal.Footer>
    </Modal>
    </>
  );
};

