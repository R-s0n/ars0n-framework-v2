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
            <div className="p-3 bg-dark border-bottom border-danger">
              <h6 className="text-danger mb-0">Controls by Category</h6>
            </div>
            {SECURITY_CONTROLS.map((category, catIndex) => (
              <div key={catIndex} className="border-bottom border-secondary">
                <div className="p-2 bg-dark">
                  <strong className="text-danger small">{category.category}</strong>
                </div>
                <ListGroup variant="flush">
                  {category.controls.map((control, cIndex) => {
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
            ))}
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
                    <h4 className="text-danger mb-4">Welcome to Security Controls</h4>
                    
                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">What is this?</h5>
                      <p>
                        Security Controls documents the security mechanisms, protections, and defenses implemented 
                        in the target application. By tracking which controls are present, how they're configured, 
                        and their effectiveness, you build a complete picture of the application's security posture.
                      </p>
                    </div>

                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">Why document security controls?</h5>
                      <ul className="mb-2">
                        <li>Identifies which security layers are present vs. missing</li>
                        <li>Reveals misconfigurations that weaken otherwise strong controls</li>
                        <li>Documents bypass techniques you've discovered</li>
                        <li>Helps prioritize testing based on security gaps</li>
                        <li>Shows security patterns and implementation consistency</li>
                        <li>Provides evidence for reports about security posture</li>
                      </ul>
                    </div>

                    <div className="text-white mb-3">
                      <h5 className="text-danger mb-3">How to use this</h5>
                      <ol className="mb-2">
                        <li className="mb-2">
                          <strong>Test for control presence</strong> - Check if each security control exists
                        </li>
                        <li className="mb-2">
                          <strong>Document configuration</strong> - Record how it's implemented and configured
                        </li>
                        <li className="mb-2">
                          <strong>Note effectiveness</strong> - Is it working properly? Any weaknesses?
                        </li>
                        <li className="mb-2">
                          <strong>Record bypasses</strong> - Document any techniques to circumvent the control
                        </li>
                        <li className="mb-2">
                          <strong>Track multiple findings</strong> - Add multiple notes as you discover more
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
    </>
  );
};

