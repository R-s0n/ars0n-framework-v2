import { useState, useEffect } from 'react';
import { Modal, Button, Form, ListGroup, Badge, Spinner, Alert, Accordion, Card } from 'react-bootstrap';

const MECHANISMS = [
  {
    category: 'Authentication & Session Management',
    mechanisms: [
      'Login',
      'Logout',
      'Registration/Signup',
      'Password Reset',
      'Forgot Password',
      'Email Verification',
      'Two-Factor Authentication (2FA) Setup',
      'Two-Factor Authentication (2FA) Verification',
      'Social Login (OAuth)',
      'Single Sign-On (SSO)',
      'Remember Me',
      'Session Timeout',
      'Force Logout (All Devices)',
      'Login with Magic Link',
      'Biometric Authentication'
    ]
  },
  {
    category: 'User Profile & Account Management',
    mechanisms: [
      'Change Username',
      'Change Email Address',
      'Change Password',
      'Update Profile Picture',
      'Update Profile Information',
      'Change Phone Number',
      'Add/Remove Linked Accounts',
      'Delete Account',
      'Deactivate Account',
      'Export User Data',
      'Account Recovery',
      'Privacy Settings',
      'Notification Preferences',
      'Language/Locale Settings'
    ]
  },
  {
    category: 'Authorization & Access Control',
    mechanisms: [
      'Role Assignment',
      'Permission Grant/Revoke',
      'Access Token Generation',
      'API Key Management',
      'Invitation System',
      'Join Organization/Workspace',
      'Leave Organization/Workspace',
      'Transfer Ownership',
      'Delegate Access',
      'Impersonation (Admin)',
      'Temporary Access Grant',
      'Access Request Approval'
    ]
  },
  {
    category: 'Data Operations',
    mechanisms: [
      'Create Record',
      'Read/View Record',
      'Update Record',
      'Delete Record',
      'Bulk Create',
      'Bulk Update',
      'Bulk Delete',
      'Import Data',
      'Export Data',
      'Search/Filter',
      'Sort Records',
      'Archive Record',
      'Restore Archived Record',
      'Duplicate Record',
      'Share Record',
      'Version History/Audit Trail'
    ]
  },
  {
    category: 'File & Media Operations',
    mechanisms: [
      'Upload File',
      'Download File',
      'Delete File',
      'Share File',
      'File Preview',
      'Generate File URL',
      'Upload Avatar/Image',
      'Image Resize/Crop',
      'File Conversion',
      'Bulk Upload',
      'Folder Management',
      'File Permissions',
      'Generate Shareable Link',
      'Revoke File Access'
    ]
  },
  {
    category: 'Communication',
    mechanisms: [
      'Send Message',
      'Delete Message',
      'Edit Message',
      'Reply to Message',
      'Send Email',
      'Send SMS',
      'Send Push Notification',
      'Subscribe to Notifications',
      'Unsubscribe from Notifications',
      'Create Comment',
      'Delete Comment',
      'Report Content',
      'Block User',
      'Unblock User',
      'Mark as Read/Unread'
    ]
  },
  {
    category: 'Payment & Billing',
    mechanisms: [
      'Add Payment Method',
      'Remove Payment Method',
      'Process Payment',
      'Apply Discount Code',
      'Subscribe to Plan',
      'Cancel Subscription',
      'Update Subscription',
      'Refund Payment',
      'View Invoice',
      'Download Receipt',
      'Update Billing Address',
      'Add Credits',
      'Transfer Funds',
      'Payout Request',
      'Recurring Payment Setup'
    ]
  },
  {
    category: 'E-commerce & Shopping',
    mechanisms: [
      'Add to Cart',
      'Remove from Cart',
      'Update Cart Quantity',
      'Apply Coupon',
      'Checkout',
      'Place Order',
      'Cancel Order',
      'Return Order',
      'Track Order',
      'Add to Wishlist',
      'Remove from Wishlist',
      'Write Review',
      'Vote on Review',
      'Save for Later',
      'Compare Products'
    ]
  },
  {
    category: 'Admin & Moderation',
    mechanisms: [
      'User Suspension',
      'User Ban',
      'Content Moderation',
      'Feature Flag Toggle',
      'System Configuration',
      'Backup Creation',
      'Data Migration',
      'Bulk User Actions',
      'Log Viewing',
      'Analytics Dashboard Access',
      'Impersonate User',
      'Override Settings',
      'Manual Verification',
      'Force Password Reset',
      'Clear Cache'
    ]
  },
  {
    category: 'Social & Collaboration',
    mechanisms: [
      'Follow User',
      'Unfollow User',
      'Send Friend Request',
      'Accept/Reject Friend Request',
      'Share Post',
      'Like/React to Content',
      'Repost/Retweet',
      'Create Group',
      'Join Group',
      'Leave Group',
      'Invite to Group',
      'Tag User',
      'Mention User',
      'Create Poll',
      'Vote in Poll'
    ]
  },
  {
    category: 'Search & Discovery',
    mechanisms: [
      'Global Search',
      'Filtered Search',
      'Autocomplete/Suggestions',
      'Advanced Search',
      'Save Search',
      'Search History',
      'Trending/Popular',
      'Recommendations',
      'Category Browsing',
      'Tag-based Discovery'
    ]
  },
  {
    category: 'Webhooks & Integrations',
    mechanisms: [
      'Create Webhook',
      'Update Webhook',
      'Delete Webhook',
      'Test Webhook',
      'View Webhook Logs',
      'OAuth Authorization',
      'OAuth Token Refresh',
      'Revoke OAuth Access',
      'API Rate Limiting',
      'Generate API Documentation'
    ]
  },
  {
    category: 'Workflow & Automation',
    mechanisms: [
      'Create Automation Rule',
      'Trigger Workflow',
      'Schedule Task',
      'Cancel Scheduled Task',
      'Approve Request',
      'Reject Request',
      'Multi-step Form Submission',
      'Save Draft',
      'Resume Draft',
      'Template Creation',
      'Apply Template'
    ]
  },
  {
    category: 'Real-time Features',
    mechanisms: [
      'WebSocket Connection',
      'Live Chat',
      'Presence Status Update',
      'Real-time Notifications',
      'Live Collaboration/Co-editing',
      'Video Call Initiation',
      'Screen Sharing',
      'Live Streaming',
      'Real-time Data Sync'
    ]
  },
  {
    category: 'Security Features',
    mechanisms: [
      'CAPTCHA Verification',
      'Rate Limit Enforcement',
      'Suspicious Activity Detection',
      'Security Questions Setup',
      'Trusted Device Management',
      'Login History',
      'Active Sessions Management',
      'IP Whitelist/Blacklist',
      'Download Security Logs',
      'Report Security Issue'
    ]
  },
  {
    category: 'Cloud & Storage Operations',
    mechanisms: [
      'S3/Blob Storage Upload',
      'S3/Blob Storage Download',
      'Generate Pre-signed URL',
      'Bucket/Container Listing',
      'Cloud Function Invocation',
      'Lambda/Function Trigger',
      'Queue Message Publishing',
      'Event Bus Publishing',
      'CDN Cache Purge',
      'Object Versioning',
      'Bucket Policy Update',
      'CORS Configuration Update'
    ]
  },
  {
    category: 'GraphQL Operations',
    mechanisms: [
      'GraphQL Query',
      'GraphQL Mutation',
      'GraphQL Subscription',
      'Introspection Query',
      'Batch Query Execution',
      'Field Aliasing',
      'Fragment Usage',
      'Variable Binding',
      'Directive Application',
      'Schema Stitching Request'
    ]
  },
  {
    category: 'CI/CD & Development',
    mechanisms: [
      'Trigger Build/Deployment',
      'View Build Logs',
      'Rollback Deployment',
      'Environment Variable Update',
      'Secret Management',
      'Feature Flag Management',
      'A/B Test Configuration',
      'Debug Mode Toggle',
      'Performance Profiling',
      'Error Tracking Configuration'
    ]
  },
  {
    category: 'Infrastructure & Monitoring',
    mechanisms: [
      'Health Check Endpoint',
      'Metrics Export',
      'Log Aggregation Query',
      'Trace Viewing',
      'Alert Configuration',
      'Dashboard Creation',
      'Resource Scaling',
      'Configuration Reload',
      'Service Discovery Query',
      'Status Page Update'
    ]
  }
];

export const MechanismsModal = ({ 
  show, 
  handleClose, 
  activeTarget 
}) => {
  const [selectedMechanism, setSelectedMechanism] = useState(null);
  const [examples, setExamples] = useState({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editingExampleId, setEditingExampleId] = useState(null);
  const [newExampleUrl, setNewExampleUrl] = useState('');
  const [newExampleNotes, setNewExampleNotes] = useState('');
  const [editExampleUrl, setEditExampleUrl] = useState('');
  const [editExampleNotes, setEditExampleNotes] = useState('');
  const [error, setError] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [exampleToDelete, setExampleToDelete] = useState(null);
  const [showAddMechanism, setShowAddMechanism] = useState(false);
  const [newMechanismName, setNewMechanismName] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    if (show && activeTarget) {
      fetchExamples();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    if (selectedMechanism && examples[selectedMechanism]) {
      setNewExampleUrl('');
      setNewExampleNotes('');
    }
  }, [selectedMechanism, examples]);

  const fetchExamples = async () => {
    if (!activeTarget) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/mechanisms/${activeTarget.id}/examples`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch examples');
      }

      const data = await response.json();
      const examplesMap = {};
      
      if (Array.isArray(data)) {
        data.forEach(example => {
          if (!examplesMap[example.mechanism]) {
            examplesMap[example.mechanism] = [];
          }
          examplesMap[example.mechanism].push(example);
        });
      }

      setExamples(examplesMap);
    } catch (error) {
      console.error('Error fetching examples:', error);
      setError('Failed to load examples');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveExample = async () => {
    if (!selectedMechanism || !newExampleUrl.trim() || !activeTarget) return;

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/mechanisms/${activeTarget.id}/examples`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mechanism: selectedMechanism,
            url: newExampleUrl.trim(),
            notes: newExampleNotes.trim()
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save example');
      }

      const savedExample = await response.json();
      
      setExamples(prev => {
        const updated = { ...prev };
        if (!updated[selectedMechanism]) {
          updated[selectedMechanism] = [];
        }
        updated[selectedMechanism].push(savedExample);
        return updated;
      });

      setNewExampleUrl('');
      setNewExampleNotes('');
    } catch (error) {
      console.error('Error saving example:', error);
      setError('Failed to save example');
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateExample = async (exampleId) => {
    if (!editExampleUrl.trim()) return;

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/mechanisms/examples/${exampleId}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: editExampleUrl.trim(),
            notes: editExampleNotes.trim()
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to update example');
      }

      const updatedExample = await response.json();
      
      setExamples(prev => {
        const updated = { ...prev };
        if (updated[selectedMechanism]) {
          updated[selectedMechanism] = updated[selectedMechanism].map(e => 
            e.id === exampleId ? updatedExample : e
          );
        }
        return updated;
      });

      setEditingExampleId(null);
      setEditExampleUrl('');
      setEditExampleNotes('');
    } catch (error) {
      console.error('Error updating example:', error);
      setError('Failed to update example');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteClick = (exampleId) => {
    setExampleToDelete(exampleId);
    setShowDeleteConfirm(true);
  };

  const handleConfirmDelete = async () => {
    if (!exampleToDelete) return;

    setSaving(true);
    setError(null);
    setShowDeleteConfirm(false);

    try {
      const response = await fetch(
        `/api/mechanisms/examples/${exampleToDelete}`,
        {
          method: 'DELETE'
        }
      );

      if (!response.ok) {
        throw new Error('Failed to delete example');
      }

      setExamples(prev => {
        const updated = { ...prev };
        if (updated[selectedMechanism]) {
          updated[selectedMechanism] = updated[selectedMechanism].filter(e => e.id !== exampleToDelete);
        }
        return updated;
      });
    } catch (error) {
      console.error('Error deleting example:', error);
      setError('Failed to delete example');
    } finally {
      setSaving(false);
      setExampleToDelete(null);
    }
  };

  const handleCancelDelete = () => {
    setShowDeleteConfirm(false);
    setExampleToDelete(null);
  };

  const handleStartEdit = (example) => {
    setEditingExampleId(example.id);
    setEditExampleUrl(example.url);
    setEditExampleNotes(example.notes || '');
  };

  const handleCancelEdit = () => {
    setEditingExampleId(null);
    setEditExampleUrl('');
    setEditExampleNotes('');
  };

  const handleAddCustomMechanism = () => {
    if (!newMechanismName.trim()) return;
    setSelectedMechanism(newMechanismName.trim());
    setShowAddMechanism(false);
    setNewMechanismName('');
  };

  const getMechanismCategory = (mechanism) => {
    for (const category of MECHANISMS) {
      if (category.mechanisms.includes(mechanism)) {
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
          Mechanisms
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
              <h6 className="text-danger mb-0">Mechanisms by Category</h6>
              <Button 
                variant="outline-danger" 
                size="sm"
                onClick={() => setShowAddMechanism(true)}
              >
                Add Custom
              </Button>
            </div>
            <div className="p-3 border-bottom border-secondary">
              <Form.Control
                type="text"
                placeholder="Search mechanisms..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                data-bs-theme="dark"
                size="sm"
              />
            </div>
            {MECHANISMS.map((category, catIndex) => {
              const filteredMechanisms = category.mechanisms.filter(m => 
                m.toLowerCase().includes(searchTerm.toLowerCase())
              );
              if (filteredMechanisms.length === 0) return null;
              return (
              <div key={catIndex} className="border-bottom border-secondary">
                <div className="p-2 bg-dark">
                  <strong className="text-danger small">{category.category}</strong>
                </div>
                <ListGroup variant="flush">
                  {filteredMechanisms.map((mechanism, mIndex) => {
                    const hasExamples = examples[mechanism] && examples[mechanism].length > 0;
                    const isSelected = selectedMechanism === mechanism;
                    return (
                      <ListGroup.Item
                        key={mIndex}
                        action
                        active={isSelected}
                        onClick={() => setSelectedMechanism(mechanism)}
                        className={`bg-dark text-white ${isSelected ? 'border-start border-3 border-danger' : ''}`}
                        style={{ 
                          cursor: 'pointer',
                          backgroundColor: isSelected ? '#2a1a1a !important' : undefined,
                          border: 'none',
                          borderBottom: '1px solid #333'
                        }}
                      >
                        <div className="d-flex justify-content-between align-items-start" style={{ gap: '8px' }}>
                          <span className="small" style={{ flex: '1 1 auto', minWidth: 0, wordWrap: 'break-word' }}>{mechanism}</span>
                          {hasExamples && (
                            <Badge bg="success" className="flex-shrink-0" style={{ minWidth: '24px', textAlign: 'center' }}>
                              {examples[mechanism].length}
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
              const allMechanismNames = MECHANISMS.flatMap(cat => cat.mechanisms);
              const customMechanisms = Object.keys(examples).filter(m => !allMechanismNames.includes(m)).sort();
              const filteredCustomMechanisms = customMechanisms.filter(m => 
                m.toLowerCase().includes(searchTerm.toLowerCase())
              );
              if (filteredCustomMechanisms.length > 0) {
                return (
                  <div className="border-bottom border-secondary">
                    <div className="p-2 bg-dark">
                      <strong className="text-danger small">Custom Mechanisms</strong>
                    </div>
                    <ListGroup variant="flush">
                      {filteredCustomMechanisms.map((mechanism, mIndex) => {
                        const hasExamples = examples[mechanism] && examples[mechanism].length > 0;
                        const isSelected = selectedMechanism === mechanism;
                        return (
                          <ListGroup.Item
                            key={mIndex}
                            action
                            active={isSelected}
                            onClick={() => setSelectedMechanism(mechanism)}
                            className={`bg-dark text-white ${isSelected ? 'border-start border-3 border-danger' : ''}`}
                            style={{ 
                              cursor: 'pointer',
                              backgroundColor: isSelected ? '#2a1a1a !important' : undefined,
                              border: 'none',
                              borderBottom: '1px solid #333'
                            }}
                          >
                            <div className="d-flex justify-content-between align-items-start" style={{ gap: '8px' }}>
                              <span className="small" style={{ flex: '1 1 auto', minWidth: 0, wordWrap: 'break-word' }}>{mechanism}</span>
                              {hasExamples && (
                                <Badge bg="success" className="flex-shrink-0" style={{ minWidth: '24px', textAlign: 'center' }}>
                                  {examples[mechanism].length}
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
            ) : selectedMechanism ? (
              <>
                {error && (
                  <Alert variant="danger" dismissible onClose={() => setError(null)}>
                    {error}
                  </Alert>
                )}

                <div className="mb-4">
                  <h5 className="text-danger mb-2">{selectedMechanism}</h5>
                  <Badge bg="secondary" className="mb-3">
                    {getMechanismCategory(selectedMechanism)}
                  </Badge>
                </div>

                <div className="mb-4">
                  <h6 className="text-white mb-3">Examples</h6>
                  {examples[selectedMechanism] && examples[selectedMechanism].length > 0 ? (
                    <div className="space-y-3">
                      {examples[selectedMechanism].map((example) => (
                        <div key={example.id} className="border border-secondary rounded p-3 mb-3 bg-dark">
                          {editingExampleId === example.id ? (
                            <div>
                              <Form.Group className="mb-2">
                                <Form.Label className="text-white small">URL</Form.Label>
                                <Form.Control
                                  type="text"
                                  value={editExampleUrl}
                                  onChange={(e) => setEditExampleUrl(e.target.value)}
                                  data-bs-theme="dark"
                                  placeholder="https://example.com/mechanism"
                                />
                              </Form.Group>
                              <Form.Group className="mb-3">
                                <Form.Label className="text-white small">Notes</Form.Label>
                                <Form.Control
                                  as="textarea"
                                  rows={3}
                                  value={editExampleNotes}
                                  onChange={(e) => setEditExampleNotes(e.target.value)}
                                  data-bs-theme="dark"
                                  placeholder="Add any relevant notes about this mechanism..."
                                />
                              </Form.Group>
                              <div className="d-flex gap-2">
                                <Button
                                  variant="success"
                                  size="sm"
                                  onClick={() => handleUpdateExample(example.id)}
                                  disabled={saving || !editExampleUrl.trim()}
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
                              <div className="mb-2">
                                <strong className="text-white small d-block mb-1">URL:</strong>
                                <a 
                                  href={example.url} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  className="text-info text-break"
                                >
                                  {example.url}
                                </a>
                              </div>
                              {example.notes && (
                                <div className="mb-2">
                                  <strong className="text-white small d-block mb-1">Notes:</strong>
                                  <p className="text-white mb-0" style={{ whiteSpace: 'pre-wrap' }}>{example.notes}</p>
                                </div>
                              )}
                              <div className="d-flex gap-2 mt-3">
                                <Button
                                  variant="outline-warning"
                                  size="sm"
                                  onClick={() => handleStartEdit(example)}
                                >
                                  Edit
                                </Button>
                                <Button
                                  variant="outline-danger"
                                  size="sm"
                                  onClick={() => handleDeleteClick(example.id)}
                                >
                                  Delete
                                </Button>
                              </div>
                              {example.created_at && (
                                <small className="text-white-50 d-block mt-2">
                                  {new Date(example.created_at).toLocaleString()}
                                </small>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-white-50">No examples yet. Add your first example below.</p>
                  )}
                </div>

                <div className="border-top border-secondary pt-4">
                  <h6 className="text-white mb-3">Add New Example</h6>
                  <Form.Group className="mb-3">
                    <Form.Label className="text-white">URL</Form.Label>
                    <Form.Control
                      type="text"
                      value={newExampleUrl}
                      onChange={(e) => setNewExampleUrl(e.target.value)}
                      placeholder="https://example.com/mechanism"
                      data-bs-theme="dark"
                    />
                  </Form.Group>
                  <Form.Group className="mb-3">
                    <Form.Label className="text-white">Notes</Form.Label>
                    <Form.Control
                      as="textarea"
                      rows={4}
                      value={newExampleNotes}
                      onChange={(e) => setNewExampleNotes(e.target.value)}
                      placeholder="Add any relevant notes about this mechanism, parameters observed, behaviors, etc."
                      data-bs-theme="dark"
                    />
                  </Form.Group>
                  <Button
                    variant="danger"
                    onClick={handleSaveExample}
                    disabled={saving || !newExampleUrl.trim()}
                  >
                    {saving ? (
                      <>
                        <Spinner animation="border" size="sm" className="me-2" />
                        Saving...
                      </>
                    ) : (
                      'Save Example'
                    )}
                  </Button>
                </div>
              </>
            ) : (
              <div className="py-4 px-4">
                <Card className="bg-dark border-danger">
                  <Card.Body>
                    <h4 className="text-danger mb-4">Mechanisms</h4>
                    
                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">Attack Surface Mapping</h5>
                      <p>
                        Mechanisms are specific actions and operations users can perform in the application. Each documented 
                        mechanism becomes a potential attack vector in your STRIDE threat model. By cataloging these mechanisms 
                        with URLs and implementation details, you create a comprehensive attack surface map that feeds directly 
                        into threat identification.
                      </p>
                    </div>

                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">Application to STRIDE Threat Modeling</h5>
                      <ul className="mb-2">
                        <li><strong>Spoofing</strong> - Authentication mechanisms reveal impersonation opportunities (login, SSO, session management)</li>
                        <li><strong>Tampering</strong> - Data operation mechanisms show what can be modified (updates, file uploads, API calls)</li>
                        <li><strong>Repudiation</strong> - Action mechanisms without logging create deniability risks (delete, modify, admin actions)</li>
                        <li><strong>Information Disclosure</strong> - Read/view mechanisms expose data leakage vectors (search, export, API responses)</li>
                        <li><strong>Denial of Service</strong> - Resource-intensive mechanisms can be abused (bulk operations, imports, processing)</li>
                        <li><strong>Elevation of Privilege</strong> - Authorization mechanisms reveal privilege boundaries (role changes, access grants)</li>
                      </ul>
                    </div>

                    <div className="text-white mb-3">
                      <h5 className="text-danger mb-3">Threat Modeling Workflow</h5>
                      <ol className="mb-2">
                        <li className="mb-2">Document mechanisms as you discover them during reconnaissance</li>
                        <li className="mb-2">Note URLs, parameters, and observed behaviors for each mechanism</li>
                        <li className="mb-2">Group related mechanisms to identify complex attack chains</li>
                        <li className="mb-2">Reference mechanisms when creating threats in the Threat Model tab</li>
                        <li className="mb-2">Each mechanism should map to one or more STRIDE threat categories</li>
                      </ol>
                    </div>

                    <Alert variant="info" className="mb-0 mt-4">
                      <strong>Get started:</strong> Select any mechanism from the left sidebar to begin documenting. 
                      We've included 150+ common mechanisms across 15 categories to help you cover the entire application.
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
        Are you sure you want to delete this example? This action cannot be undone.
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
      show={showAddMechanism} 
      onHide={() => setShowAddMechanism(false)}
      centered
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">Add Custom Mechanism</Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark">
        <Form.Group>
          <Form.Label className="text-white">Mechanism Name</Form.Label>
          <Form.Control
            type="text"
            value={newMechanismName}
            onChange={(e) => setNewMechanismName(e.target.value)}
            placeholder="e.g., Custom API Operation, Special Feature"
            data-bs-theme="dark"
            onKeyPress={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleAddCustomMechanism();
              }
            }}
          />
          <Form.Text className="text-white-50">
            Enter a descriptive name for this custom mechanism
          </Form.Text>
        </Form.Group>
      </Modal.Body>
      <Modal.Footer className="bg-dark border-danger">
        <Button variant="outline-secondary" onClick={() => setShowAddMechanism(false)}>
          Cancel
        </Button>
        <Button 
          variant="danger" 
          onClick={handleAddCustomMechanism} 
          disabled={!newMechanismName.trim()}
        >
          Add Mechanism
        </Button>
      </Modal.Footer>
    </Modal>
    </>
  );
};

