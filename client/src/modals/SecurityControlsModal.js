import { useState, useEffect } from 'react';
import { Modal, Button, Form, ListGroup, Badge, Spinner, Alert, Card } from 'react-bootstrap';

const SECURITY_CONTROLS = [
  {
    category: 'Network & Transport Security',
    controls: [
      'HTTPS Enforcement',
      'HTTP Strict Transport Security (HSTS)',
      'TLS Version Support',
      'Certificate Pinning',
      'Mixed Content Prevention',
      'Secure Cookie Flag',
      'HttpOnly Cookie Flag',
      'SameSite Cookie Attribute'
    ]
  },
  {
    category: 'Content Security',
    controls: [
      'Content Security Policy (CSP)',
      'X-Content-Type-Options',
      'X-Frame-Options',
      'Cross-Origin Resource Policy (CORP)',
      'Cross-Origin Embedder Policy (COEP)',
      'Cross-Origin Opener Policy (COOP)',
      'Referrer-Policy',
      'Permissions-Policy'
    ]
  },
  {
    category: 'Application Layer Protection',
    controls: [
      'Web Application Firewall (WAF)',
      'DDoS Protection',
      'Bot Detection',
      'Rate Limiting',
      'IP Whitelisting/Blacklisting',
      'Geo-blocking',
      'Request Size Limits',
      'File Upload Restrictions'
    ]
  },
  {
    category: 'Authentication Controls',
    controls: [
      'Password Complexity Requirements',
      'Multi-Factor Authentication (MFA)',
      'Account Lockout Policy',
      'Session Timeout',
      'Concurrent Session Limits',
      'Password Reset Security',
      'Brute Force Protection',
      'OAuth/OIDC Implementation'
    ]
  },
  {
    category: 'Input Validation & Sanitization',
    controls: [
      'Server-Side Input Validation',
      'SQL Injection Prevention',
      'XSS Prevention',
      'Command Injection Prevention',
      'Path Traversal Prevention',
      'XML External Entity (XXE) Prevention',
      'Server-Side Request Forgery (SSRF) Prevention',
      'Template Injection Prevention'
    ]
  },
  {
    category: 'Access Control',
    controls: [
      'Authorization Checks',
      'Role-Based Access Control (RBAC)',
      'Attribute-Based Access Control (ABAC)',
      'Principle of Least Privilege',
      'Object-Level Authorization',
      'Function-Level Authorization',
      'Insecure Direct Object Reference (IDOR) Prevention',
      'Privilege Escalation Prevention'
    ]
  },
  {
    category: 'Data Protection',
    controls: [
      'Data Encryption at Rest',
      'Data Encryption in Transit',
      'Sensitive Data Masking',
      'PII Protection',
      'Credit Card Data Protection (PCI DSS)',
      'Database Encryption',
      'Secure Key Management',
      'Data Loss Prevention (DLP)'
    ]
  },
  {
    category: 'API Security',
    controls: [
      'API Authentication',
      'API Rate Limiting',
      'API Input Validation',
      'API Versioning',
      'CORS Configuration',
      'API Key Rotation',
      'GraphQL Query Depth Limiting',
      'REST API Security Headers'
    ]
  },
  {
    category: 'Session Management',
    controls: [
      'Secure Session Generation',
      'Session Fixation Prevention',
      'Session Token Entropy',
      'Session Invalidation on Logout',
      'Absolute Session Timeout',
      'Idle Session Timeout',
      'Token Refresh Mechanism',
      'Concurrent Session Management'
    ]
  },
  {
    category: 'Error Handling & Logging',
    controls: [
      'Generic Error Messages',
      'Stack Trace Suppression',
      'Security Event Logging',
      'Audit Trail',
      'Log Integrity Protection',
      'Sensitive Data Redaction in Logs',
      'Centralized Logging',
      'Real-time Security Monitoring'
    ]
  },
  {
    category: 'File & Upload Security',
    controls: [
      'File Type Validation',
      'File Size Limits',
      'Malware Scanning',
      'Content-Type Verification',
      'Safe File Storage Location',
      'Executable Upload Prevention',
      'Image Processing Sanitization',
      'PDF Security Checks'
    ]
  },
  {
    category: 'Business Logic Security',
    controls: [
      'Race Condition Prevention',
      'Transaction Integrity',
      'Price Manipulation Prevention',
      'Workflow Bypass Prevention',
      'Business Rule Enforcement',
      'State Transition Validation',
      'Quantity/Amount Limits',
      'Duplicate Transaction Prevention'
    ]
  },
  {
    category: 'Third-Party & Integration Security',
    controls: [
      'Third-Party Script Validation',
      'Subresource Integrity (SRI)',
      'Supply Chain Security',
      'Webhook Signature Verification',
      'API Partner Authentication',
      'OAuth Scope Restrictions',
      'Dependency Vulnerability Scanning',
      'CDN Security Configuration'
    ]
  },
  {
    category: 'Cryptography',
    controls: [
      'Strong Encryption Algorithms',
      'Secure Random Number Generation',
      'Salt for Password Hashing',
      'Password Hashing (bcrypt/Argon2)',
      'JWT Signature Verification',
      'Asymmetric Encryption for Sensitive Data',
      'Cryptographic Protocol Security',
      'Deprecated Algorithm Prevention'
    ]
  },
  {
    category: 'Compliance & Privacy',
    controls: [
      'GDPR Compliance',
      'CCPA Compliance',
      'Data Retention Policies',
      'Right to be Forgotten',
      'Consent Management',
      'Privacy Policy Enforcement',
      'Data Minimization',
      'Cross-Border Data Transfer Controls'
    ]
  },
  {
    category: 'Cloud Security',
    controls: [
      'Cloud Storage Bucket Access Controls',
      'S3 Bucket Public Access Block',
      'Cloud IAM Least Privilege',
      'Cloud Resource Tagging',
      'Cloud Security Groups/Firewalls',
      'VPC/Network Segmentation',
      'Cloud Audit Logging',
      'Cloud Secrets Manager Integration',
      'Serverless Function Permissions',
      'Cloud Storage Encryption',
      'Cloud Database Security',
      'Cloud API Gateway Security'
    ]
  },
  {
    category: 'Container & Orchestration Security',
    controls: [
      'Container Image Scanning',
      'Container Runtime Security',
      'Pod Security Policies',
      'Network Policies (Kubernetes)',
      'Service Mesh Security',
      'Container Registry Access Control',
      'Secrets Management for Containers',
      'Container Resource Limits'
    ]
  },
  {
    category: 'Secrets & Credential Management',
    controls: [
      'Secrets Rotation',
      'No Hardcoded Credentials',
      'Environment Variable Protection',
      'Secrets Vault Integration',
      'API Key Rotation',
      'Certificate Management',
      'Service Account Key Management',
      'Database Credential Rotation'
    ]
  },
  {
    category: 'OSINT & Information Disclosure Prevention',
    controls: [
      'GitHub/GitLab Secret Scanning',
      'Source Code Access Control',
      'Build Artifact Protection',
      'Debug Endpoint Protection',
      'Error Message Sanitization',
      'Internal Path Disclosure Prevention',
      'Server Header Suppression',
      'Version Information Hiding',
      'Backup File Protection',
      'Configuration File Protection',
      'Source Map Protection'
    ]
  },
  {
    category: 'GraphQL Security',
    controls: [
      'GraphQL Query Depth Limiting',
      'GraphQL Query Complexity Analysis',
      'GraphQL Introspection Disabling (Production)',
      'GraphQL Rate Limiting',
      'GraphQL Authorization per Field',
      'GraphQL Batching Limits',
      'GraphQL Persisted Queries'
    ]
  },
  {
    category: 'CI/CD Security',
    controls: [
      'Pipeline Secret Management',
      'Code Signing',
      'Build Environment Isolation',
      'Artifact Integrity Verification',
      'Dependency Scanning in Pipeline',
      'Branch Protection Rules',
      'Merge Approval Requirements',
      'Automated Security Testing in Pipeline'
    ]
  },
  {
    category: 'Monitoring & Incident Response',
    controls: [
      'Security Information and Event Management (SIEM)',
      'Intrusion Detection System (IDS)',
      'Intrusion Prevention System (IPS)',
      'Anomaly Detection',
      'Threat Intelligence Integration',
      'Automated Incident Response',
      'Security Playbooks',
      'Forensic Logging'
    ]
  }
];

export const SecurityControlsModal = ({ 
  show, 
  handleClose, 
  activeTarget 
}) => {
  const [selectedControl, setSelectedControl] = useState(null);
  const [notes, setNotes] = useState({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editingNoteId, setEditingNoteId] = useState(null);
  const [newNoteText, setNewNoteText] = useState('');
  const [editNoteText, setEditNoteText] = useState('');
  const [error, setError] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [noteToDelete, setNoteToDelete] = useState(null);
  const [showAddControl, setShowAddControl] = useState(false);
  const [newControlName, setNewControlName] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    if (show && activeTarget) {
      fetchNotes();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    if (selectedControl && notes[selectedControl]) {
      setNewNoteText('');
    }
  }, [selectedControl, notes]);

  const fetchNotes = async () => {
    if (!activeTarget) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/security-controls/${activeTarget.id}/notes`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch notes');
      }

      const data = await response.json();
      const notesMap = {};
      
      if (Array.isArray(data)) {
        data.forEach(note => {
          if (!notesMap[note.control_name]) {
            notesMap[note.control_name] = [];
          }
          notesMap[note.control_name].push(note);
        });
      }

      setNotes(notesMap);
    } catch (error) {
      console.error('Error fetching notes:', error);
      setError('Failed to load notes');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveNote = async () => {
    if (!selectedControl || !newNoteText.trim() || !activeTarget) return;

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/security-controls/${activeTarget.id}/notes`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            control_name: selectedControl,
            note: newNoteText.trim()
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save note');
      }

      const savedNote = await response.json();
      
      setNotes(prev => {
        const updated = { ...prev };
        if (!updated[selectedControl]) {
          updated[selectedControl] = [];
        }
        updated[selectedControl].push(savedNote);
        return updated;
      });

      setNewNoteText('');
    } catch (error) {
      console.error('Error saving note:', error);
      setError('Failed to save note');
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateNote = async (noteId) => {
    if (!editNoteText.trim()) return;

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/security-controls/notes/${noteId}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            note: editNoteText.trim()
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to update note');
      }

      const updatedNote = await response.json();
      
      setNotes(prev => {
        const updated = { ...prev };
        if (updated[selectedControl]) {
          updated[selectedControl] = updated[selectedControl].map(n => 
            n.id === noteId ? updatedNote : n
          );
        }
        return updated;
      });

      setEditingNoteId(null);
      setEditNoteText('');
    } catch (error) {
      console.error('Error updating note:', error);
      setError('Failed to update note');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteClick = (noteId) => {
    setNoteToDelete(noteId);
    setShowDeleteConfirm(true);
  };

  const handleConfirmDelete = async () => {
    if (!noteToDelete) return;

    setSaving(true);
    setError(null);
    setShowDeleteConfirm(false);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/security-controls/notes/${noteToDelete}`,
        {
          method: 'DELETE'
        }
      );

      if (!response.ok) {
        throw new Error('Failed to delete note');
      }

      setNotes(prev => {
        const updated = { ...prev };
        if (updated[selectedControl]) {
          updated[selectedControl] = updated[selectedControl].filter(n => n.id !== noteToDelete);
        }
        return updated;
      });
    } catch (error) {
      console.error('Error deleting note:', error);
      setError('Failed to delete note');
    } finally {
      setSaving(false);
      setNoteToDelete(null);
    }
  };

  const handleCancelDelete = () => {
    setShowDeleteConfirm(false);
    setNoteToDelete(null);
  };

  const handleStartEdit = (note) => {
    setEditingNoteId(note.id);
    setEditNoteText(note.note);
  };

  const handleCancelEdit = () => {
    setEditingNoteId(null);
    setEditNoteText('');
  };

  const handleAddCustomControl = () => {
    if (!newControlName.trim()) return;
    setSelectedControl(newControlName.trim());
    setShowAddControl(false);
    setNewControlName('');
  };

  const getControlCategory = (control) => {
    for (const category of SECURITY_CONTROLS) {
      if (category.controls.includes(control)) {
        return category.category;
      }
    }
    return 'Unknown';
  };

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
          Security Controls
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="p-0">
        <div className="d-flex h-100" style={{ height: 'calc(100vh - 120px)' }}>
          <div 
            className="border-end border-danger" 
            style={{ 
              width: '400px', 
              minWidth: '400px',
              maxWidth: '400px',
              flexShrink: 0,
              overflowY: 'auto', 
              backgroundColor: '#1a1a1a' 
            }}
          >
            <div className="p-3 bg-dark border-bottom border-danger d-flex justify-content-between align-items-center">
              <h6 className="text-danger mb-0">Controls by Category</h6>
              <Button 
                variant="outline-danger" 
                size="sm"
                onClick={() => setShowAddControl(true)}
              >
                Add Custom
              </Button>
            </div>
            <div className="p-3 border-bottom border-secondary">
              <Form.Control
                type="text"
                placeholder="Search controls..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                data-bs-theme="dark"
                size="sm"
              />
            </div>
            {SECURITY_CONTROLS.map((category, catIndex) => {
              const filteredControls = category.controls.filter(c => 
                c.toLowerCase().includes(searchTerm.toLowerCase())
              );
              if (filteredControls.length === 0) return null;
              return (
              <div key={catIndex} className="border-bottom border-secondary">
                <div className="p-2 bg-dark">
                  <strong className="text-danger small">{category.category}</strong>
                </div>
                <ListGroup variant="flush">
                  {filteredControls.map((control, cIndex) => {
                    const hasNotes = notes[control] && notes[control].length > 0;
                    const isSelected = selectedControl === control;
                    return (
                      <ListGroup.Item
                        key={cIndex}
                        action
                        active={isSelected}
                        onClick={() => setSelectedControl(control)}
                        className={`bg-dark text-white ${isSelected ? 'border-start border-3 border-danger' : ''}`}
                        style={{ 
                          cursor: 'pointer',
                          backgroundColor: isSelected ? '#2a1a1a !important' : undefined,
                          border: 'none',
                          borderBottom: '1px solid #333'
                        }}
                      >
                        <div className="d-flex justify-content-between align-items-start" style={{ gap: '8px' }}>
                          <span className="small" style={{ flex: '1 1 auto', minWidth: 0, wordWrap: 'break-word' }}>{control}</span>
                          {hasNotes && (
                            <Badge bg="success" className="flex-shrink-0" style={{ minWidth: '24px', textAlign: 'center' }}>
                              {notes[control].length}
                            </Badge>
                          )}
                        </div>
                      </ListGroup.Item>
                    );
                  })}
                </ListGroup>
              </div>
              );
            })}
            {(() => {
              const allControlNames = SECURITY_CONTROLS.flatMap(cat => cat.controls);
              const customControls = Object.keys(notes).filter(c => !allControlNames.includes(c)).sort();
              const filteredCustomControls = customControls.filter(c => 
                c.toLowerCase().includes(searchTerm.toLowerCase())
              );
              if (filteredCustomControls.length > 0) {
                return (
                  <div className="border-bottom border-secondary">
                    <div className="p-2 bg-dark">
                      <strong className="text-danger small">Custom Controls</strong>
                    </div>
                    <ListGroup variant="flush">
                      {filteredCustomControls.map((control, cIndex) => {
                        const hasNotes = notes[control] && notes[control].length > 0;
                        const isSelected = selectedControl === control;
                        return (
                          <ListGroup.Item
                            key={cIndex}
                            action
                            active={isSelected}
                            onClick={() => setSelectedControl(control)}
                            className={`bg-dark text-white ${isSelected ? 'border-start border-3 border-danger' : ''}`}
                            style={{ 
                              cursor: 'pointer',
                              backgroundColor: isSelected ? '#2a1a1a !important' : undefined,
                              border: 'none',
                              borderBottom: '1px solid #333'
                            }}
                          >
                            <div className="d-flex justify-content-between align-items-start" style={{ gap: '8px' }}>
                              <span className="small" style={{ flex: '1 1 auto', minWidth: 0, wordWrap: 'break-word' }}>{control}</span>
                              {hasNotes && (
                                <Badge bg="success" className="flex-shrink-0" style={{ minWidth: '24px', textAlign: 'center' }}>
                                  {notes[control].length}
                                </Badge>
                              )}
                            </div>
                          </ListGroup.Item>
                        );
                      })}
                    </ListGroup>
                  </div>
                );
              }
              return null;
            })()}
          </div>

          <div className="flex-fill p-4" style={{ overflowY: 'auto' }}>
            {loading ? (
              <div className="text-center py-5">
                <Spinner animation="border" variant="danger">
                  <span className="visually-hidden">Loading...</span>
                </Spinner>
              </div>
            ) : selectedControl ? (
              <>
                {error && (
                  <Alert variant="danger" dismissible onClose={() => setError(null)}>
                    {error}
                  </Alert>
                )}

                <div className="mb-4">
                  <h5 className="text-danger mb-2">{selectedControl}</h5>
                  <Badge bg="secondary" className="mb-3">
                    {getControlCategory(selectedControl)}
                  </Badge>
                </div>

                <div className="mb-4">
                  <h6 className="text-white mb-3">Notes & Findings</h6>
                  {notes[selectedControl] && notes[selectedControl].length > 0 ? (
                    <div className="space-y-3">
                      {notes[selectedControl].map((note) => (
                        <div key={note.id} className="border border-secondary rounded p-3 mb-3 bg-dark">
                          {editingNoteId === note.id ? (
                            <div>
                              <Form.Control
                                as="textarea"
                                rows={4}
                                value={editNoteText}
                                onChange={(e) => setEditNoteText(e.target.value)}
                                className="mb-2"
                                data-bs-theme="dark"
                              />
                              <div className="d-flex gap-2">
                                <Button
                                  variant="success"
                                  size="sm"
                                  onClick={() => handleUpdateNote(note.id)}
                                  disabled={saving || !editNoteText.trim()}
                                >
                                  {saving ? <Spinner animation="border" size="sm" /> : 'Save'}
                                </Button>
                                <Button
                                  variant="secondary"
                                  size="sm"
                                  onClick={handleCancelEdit}
                                  disabled={saving}
                                >
                                  Cancel
                                </Button>
                              </div>
                            </div>
                          ) : (
                            <div>
                              <p className="text-white mb-2" style={{ whiteSpace: 'pre-wrap' }}>{note.note}</p>
                              <div className="d-flex gap-2">
                                <Button
                                  variant="outline-warning"
                                  size="sm"
                                  onClick={() => handleStartEdit(note)}
                                >
                                  Edit
                                </Button>
                                <Button
                                  variant="outline-danger"
                                  size="sm"
                                  onClick={() => handleDeleteClick(note.id)}
                                >
                                  Delete
                                </Button>
                              </div>
                              {note.created_at && (
                                <small className="text-white-50 d-block mt-2">
                                  {new Date(note.created_at).toLocaleString()}
                                </small>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-white-50">No notes yet. Add your first note below.</p>
                  )}
                </div>

                <div className="border-top border-secondary pt-4">
                  <h6 className="text-white mb-3">Add New Note</h6>
                  <Form.Control
                    as="textarea"
                    rows={5}
                    value={newNoteText}
                    onChange={(e) => setNewNoteText(e.target.value)}
                    placeholder="Document your findings about this security control: Is it present? How is it configured? Any weaknesses or bypasses discovered? Version information? Testing observations?"
                    className="mb-3"
                    data-bs-theme="dark"
                  />
                  <Button
                    variant="danger"
                    onClick={handleSaveNote}
                    disabled={saving || !newNoteText.trim()}
                  >
                    {saving ? (
                      <>
                        <Spinner animation="border" size="sm" className="me-2" />
                        Saving...
                      </>
                    ) : (
                      'Save Note'
                    )}
                  </Button>
                </div>
              </>
            ) : (
              <div className="py-4 px-4">
                <Card className="bg-dark border-danger">
                  <Card.Body>
                    <h4 className="text-danger mb-4">Security Controls</h4>
                    
                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">Defensive Posture Assessment</h5>
                      <p>
                        Security Controls represent the defensive layer that mitigates STRIDE threats. Documenting what controls 
                        exist, how they're configured, and their weaknesses is essential for accurate threat modeling. Missing or 
                        misconfigured controls directly translate to exploitable threats, while strong controls reduce threat impact 
                        and likelihood.
                      </p>
                    </div>

                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">Controls as Threat Mitigations</h5>
                      <ul className="mb-2">
                        <li><strong>Spoofing</strong> - Authentication controls (MFA, session management) prevent identity theft</li>
                        <li><strong>Tampering</strong> - Integrity controls (checksums, signatures, validation) detect/prevent data modification</li>
                        <li><strong>Repudiation</strong> - Audit logging and monitoring ensure accountability and non-repudiation</li>
                        <li><strong>Information Disclosure</strong> - Encryption, access controls, and data masking protect sensitive data</li>
                        <li><strong>Denial of Service</strong> - Rate limiting, resource quotas, and DDoS protection maintain availability</li>
                        <li><strong>Elevation of Privilege</strong> - Authorization controls and privilege separation limit unauthorized access</li>
                      </ul>
                    </div>

                    <div className="text-white mb-3">
                      <h5 className="text-danger mb-3">Threat Modeling Workflow</h5>
                      <ol className="mb-2">
                        <li className="mb-2">
                          <strong>Enumerate controls</strong> - Identify which security controls are present or absent
                        </li>
                        <li className="mb-2">
                          <strong>Assess implementation</strong> - Document configuration, strength, and any weaknesses
                        </li>
                        <li className="mb-2">
                          <strong>Identify gaps</strong> - Missing controls indicate unmitigated threats in your model
                        </li>
                        <li className="mb-2">
                          <strong>Test bypasses</strong> - Weak or bypassable controls remain exploitable threats
                        </li>
                        <li className="mb-2">
                          <strong>Map to threats</strong> - Reference controls when assessing threat likelihood and impact
                        </li>
                      </ol>
                    </div>

                    <Alert variant="info" className="mb-0 mt-4">
                      <strong>Get started:</strong> Select a security control from the left sidebar to begin documenting. 
                      We've included 100+ security controls across 15 categories covering the complete security spectrum.
                    </Alert>
                  </Card.Body>
                </Card>
              </div>
            )}
          </div>
        </div>
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
        Are you sure you want to delete this note? This action cannot be undone.
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

    <Modal 
      show={showAddControl} 
      onHide={() => setShowAddControl(false)}
      centered
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">Add Custom Security Control</Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark">
        <Form.Group>
          <Form.Label className="text-white">Control Name</Form.Label>
          <Form.Control
            type="text"
            value={newControlName}
            onChange={(e) => setNewControlName(e.target.value)}
            placeholder="e.g., Custom Validation Rule, Special Protection"
            data-bs-theme="dark"
            onKeyPress={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleAddCustomControl();
              }
            }}
          />
          <Form.Text className="text-white-50">
            Enter a descriptive name for this custom security control
          </Form.Text>
        </Form.Group>
      </Modal.Body>
      <Modal.Footer className="bg-dark border-danger">
        <Button variant="outline-secondary" onClick={() => setShowAddControl(false)}>
          Cancel
        </Button>
        <Button 
          variant="danger" 
          onClick={handleAddCustomControl} 
          disabled={!newControlName.trim()}
        >
          Add Control
        </Button>
      </Modal.Footer>
    </Modal>
    </>
  );
};

