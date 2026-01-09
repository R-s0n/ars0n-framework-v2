import { useState, useEffect } from 'react';
import { Modal, Button, Form, ListGroup, Badge, Spinner, Alert, Card } from 'react-bootstrap';

const DEFAULT_OBJECTS = [
  'User Object',
  'Session Object',
  'Authentication Token (JWT)',
  'API Response',
  'API Error Response',
  'Profile Object',
  'Settings Object',
  'Permissions/Roles Object',
  'Organization/Workspace Object',
  'Team/Group Object',
  'Notification Object',
  'Message Object',
  'Payment Object',
  'Subscription Object',
  'Invoice Object',
  'Product Object',
  'Cart Object',
  'Order Object',
  'Transaction Object',
  'File/Document Object',
  'Comment Object',
  'Post/Content Object',
  'Analytics Event Object',
  'Webhook Payload',
  'Configuration Object',
  'Cloud Metadata Object',
  'S3 Bucket Policy',
  'IAM Role/Policy',
  'Cloud Function Config',
  'Container/Pod Spec',
  'Secret/Credential Object',
  'Environment Variables',
  'GraphQL Schema',
  'GraphQL Query Response',
  'GraphQL Error Object',
  'Build/Deployment Config',
  'CI/CD Pipeline Object',
  'Debug/Trace Object',
  'Metrics/Monitoring Data',
  'Log Entry Object',
  'Health Check Response',
  'Feature Flag Object',
  'A/B Test Configuration',
  'Rate Limit Object',
  'Queue Message',
  'Event/Stream Object',
  'Webhook Delivery Object',
  'OAuth Token Response',
  'SAML Assertion',
  'Certificate Object',
  'DNS Record Object'
];

export const NotableObjectsModal = ({ 
  show, 
  handleClose, 
  activeTarget 
}) => {
  const [selectedObject, setSelectedObject] = useState(null);
  const [objects, setObjects] = useState({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editedJson, setEditedJson] = useState('');
  const [error, setError] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [objectToDelete, setObjectToDelete] = useState(null);
  const [showAddObject, setShowAddObject] = useState(false);
  const [newObjectName, setNewObjectName] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    if (show && activeTarget) {
      fetchObjects();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    if (selectedObject && objects[selectedObject]) {
      setEditedJson(objects[selectedObject].object_json || '');
      setIsEditing(false);
    }
  }, [selectedObject, objects]);

  const fetchObjects = async () => {
    if (!activeTarget) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/notable-objects/${activeTarget.id}`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch objects');
      }

      const data = await response.json();
      const objectsMap = {};
      
      if (Array.isArray(data)) {
        data.forEach(obj => {
          objectsMap[obj.object_name] = obj;
        });
      }

      setObjects(objectsMap);
    } catch (error) {
      console.error('Error fetching objects:', error);
      setError('Failed to load objects');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveObject = async () => {
    if (!selectedObject || !activeTarget) return;

    let jsonToSave = editedJson.trim();
    
    if (jsonToSave) {
      try {
        JSON.parse(jsonToSave);
      } catch (e) {
        setError('Invalid JSON format. Please check your syntax.');
        return;
      }
    }

    setSaving(true);
    setError(null);

    try {
      const method = objects[selectedObject] ? 'PUT' : 'POST';
      const url = objects[selectedObject]
        ? `/api/notable-objects/${objects[selectedObject].id}`
        : `/api/notable-objects/${activeTarget.id}`;

      const response = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          object_name: selectedObject,
          object_json: jsonToSave
        })
      });

      if (!response.ok) {
        throw new Error('Failed to save object');
      }

      const savedObject = await response.json();
      
      setObjects(prev => ({
        ...prev,
        [selectedObject]: savedObject
      }));

      setIsEditing(false);
    } catch (error) {
      console.error('Error saving object:', error);
      setError('Failed to save object');
    } finally {
      setSaving(false);
    }
  };

  const handleAddNewObject = async () => {
    if (!newObjectName.trim() || !activeTarget) return;

    const objectName = newObjectName.trim();

    if (objects[objectName]) {
      setError('An object with this name already exists');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/notable-objects/${activeTarget.id}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            object_name: objectName,
            object_json: ''
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to create object');
      }

      const savedObject = await response.json();
      
      setObjects(prev => ({
        ...prev,
        [objectName]: savedObject
      }));

      setSelectedObject(objectName);
      setShowAddObject(false);
      setNewObjectName('');
      setIsEditing(true);
    } catch (error) {
      console.error('Error creating object:', error);
      setError('Failed to create object');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteClick = (objectName) => {
    setObjectToDelete(objectName);
    setShowDeleteConfirm(true);
  };

  const handleConfirmDelete = async () => {
    if (!objectToDelete || !objects[objectToDelete]) return;

    setSaving(true);
    setError(null);
    setShowDeleteConfirm(false);

    try {
      const response = await fetch(
        `/api/notable-objects/${objects[objectToDelete].id}`,
        {
          method: 'DELETE'
        }
      );

      if (!response.ok) {
        throw new Error('Failed to delete object');
      }

      setObjects(prev => {
        const updated = { ...prev };
        delete updated[objectToDelete];
        return updated;
      });

      if (selectedObject === objectToDelete) {
        setSelectedObject(null);
      }
    } catch (error) {
      console.error('Error deleting object:', error);
      setError('Failed to delete object');
    } finally {
      setSaving(false);
      setObjectToDelete(null);
    }
  };

  const handleCancelDelete = () => {
    setShowDeleteConfirm(false);
    setObjectToDelete(null);
  };

  const handleStartEdit = () => {
    setIsEditing(true);
    setEditedJson(objects[selectedObject]?.object_json || '');
  };

  const handleCancelEdit = () => {
    setIsEditing(false);
    setEditedJson(objects[selectedObject]?.object_json || '');
  };

  const allObjectNames = [...new Set([...DEFAULT_OBJECTS, ...Object.keys(objects)])].sort();
  const filteredObjectNames = allObjectNames.filter(name => 
    name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatJson = (jsonString) => {
    try {
      if (!jsonString || !jsonString.trim()) return '';
      const parsed = JSON.parse(jsonString);
      return JSON.stringify(parsed, null, 2);
    } catch (e) {
      return jsonString;
    }
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
          Notable Objects
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="p-0">
        <div className="d-flex h-100" style={{ height: 'calc(100vh - 120px)' }}>
          <div 
            className="border-end border-danger" 
            style={{ 
              width: '350px', 
              minWidth: '350px',
              maxWidth: '350px',
              flexShrink: 0,
              overflowY: 'auto', 
              backgroundColor: '#1a1a1a' 
            }}
          >
            <div className="p-3 bg-dark border-bottom border-danger d-flex justify-content-between align-items-center">
              <h6 className="text-danger mb-0">Object Types</h6>
              <Button 
                variant="outline-danger" 
                size="sm"
                onClick={() => setShowAddObject(true)}
              >
                Add New
              </Button>
            </div>
            <div className="p-3 border-bottom border-secondary">
              <Form.Control
                type="text"
                placeholder="Search objects..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                data-bs-theme="dark"
                size="sm"
              />
            </div>
            <ListGroup variant="flush">
              {filteredObjectNames.map((objectName, index) => {
                const hasData = objects[objectName] && objects[objectName].object_json;
                const isSelected = selectedObject === objectName;
                return (
                  <ListGroup.Item
                    key={index}
                    action
                    active={isSelected}
                    onClick={() => setSelectedObject(objectName)}
                    className={`bg-dark text-white ${isSelected ? 'border-start border-3 border-danger' : ''}`}
                    style={{ 
                      cursor: 'pointer',
                      backgroundColor: isSelected ? '#2a1a1a !important' : undefined,
                      border: 'none',
                      borderBottom: '1px solid #333'
                    }}
                  >
                    <div className="d-flex justify-content-between align-items-center" style={{ gap: '8px' }}>
                      <span className="small" style={{ flex: '1 1 auto', minWidth: 0, wordWrap: 'break-word' }}>
                        {objectName}
                      </span>
                      {hasData && (
                        <Badge bg="success" className="flex-shrink-0" style={{ minWidth: '20px', textAlign: 'center' }}>
                          ✓
                        </Badge>
                      )}
                    </div>
                  </ListGroup.Item>
                );
              })}
            </ListGroup>
          </div>

          <div className="flex-fill p-4" style={{ overflowY: 'auto' }}>
            {loading ? (
              <div className="text-center py-5">
                <Spinner animation="border" variant="danger">
                  <span className="visually-hidden">Loading...</span>
                </Spinner>
              </div>
            ) : selectedObject ? (
              <>
                {error && (
                  <Alert variant="danger" dismissible onClose={() => setError(null)}>
                    {error}
                  </Alert>
                )}

                <div className="mb-4">
                  <div className="d-flex justify-content-between align-items-center">
                    <h5 className="text-danger mb-0">{selectedObject}</h5>
                    {objects[selectedObject] && (
                      <Button
                        variant="outline-danger"
                        size="sm"
                        onClick={() => handleDeleteClick(selectedObject)}
                      >
                        Delete Object Type
                      </Button>
                    )}
                  </div>
                </div>

                {isEditing ? (
                  <div>
                    <Form.Group className="mb-3">
                      <Form.Label className="text-white">
                        JSON Object Structure
                        <small className="text-white-50 ms-2">(Paste example JSON with key/value pairs)</small>
                      </Form.Label>
                      <Form.Control
                        as="textarea"
                        rows={20}
                        value={editedJson}
                        onChange={(e) => setEditedJson(e.target.value)}
                        data-bs-theme="dark"
                        placeholder={`{\n  "id": "12345",\n  "username": "example_user",\n  "email": "user@example.com",\n  "created_at": "2024-01-01T00:00:00Z"\n}`}
                        style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
                      />
                      <Form.Text className="text-white-50">
                        Paste an example of this object from the application. Include all relevant fields and their data types.
                      </Form.Text>
                    </Form.Group>
                    <div className="d-flex gap-2">
                      <Button
                        variant="success"
                        onClick={handleSaveObject}
                        disabled={saving}
                      >
                        {saving ? (
                          <>
                            <Spinner animation="border" size="sm" className="me-2" />
                            Saving...
                          </>
                        ) : (
                          'Save'
                        )}
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={handleCancelEdit}
                        disabled={saving}
                      >
                        Cancel
                      </Button>
                      {editedJson && (
                        <Button
                          variant="outline-info"
                          onClick={() => setEditedJson(formatJson(editedJson))}
                        >
                          Format JSON
                        </Button>
                      )}
                    </div>
                  </div>
                ) : (
                  <div>
                    {objects[selectedObject] && objects[selectedObject].object_json ? (
                      <div>
                        <div className="mb-3 d-flex justify-content-between align-items-center">
                          <h6 className="text-white mb-0">Object Structure</h6>
                          <Button
                            variant="outline-warning"
                            size="sm"
                            onClick={handleStartEdit}
                          >
                            Edit
                          </Button>
                        </div>
                        <pre 
                          className="bg-dark text-white p-3 border border-secondary rounded" 
                          style={{ 
                            maxHeight: '600px', 
                            overflowY: 'auto',
                            fontFamily: 'monospace',
                            fontSize: '0.9rem'
                          }}
                        >
                          {formatJson(objects[selectedObject].object_json)}
                        </pre>
                        {objects[selectedObject].updated_at && (
                          <small className="text-white-50 d-block mt-2">
                            Last updated: {new Date(objects[selectedObject].updated_at).toLocaleString()}
                          </small>
                        )}
                      </div>
                    ) : (
                      <div>
                        <Alert variant="info">
                          No JSON structure documented yet for this object type.
                        </Alert>
                        <Button
                          variant="danger"
                          onClick={handleStartEdit}
                        >
                          Add Object Structure
                        </Button>
                      </div>
                    )}
                  </div>
                )}
              </>
            ) : (
              <div className="py-4 px-4">
                <Card className="bg-dark border-danger">
                  <Card.Body>
                    <h4 className="text-danger mb-4">Notable Objects</h4>
                    
                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">Threat Target Identification</h5>
                      <p>
                        Notable Objects define what attackers can target in your threat model. Each documented object represents 
                        a potential asset that can be spoofed, tampered with, disclosed, or manipulated. By capturing actual data 
                        structures with their fields and data types, you identify exactly what needs protection and what an attacker 
                        might seek to compromise.
                      </p>
                    </div>

                    <div className="text-white mb-4">
                      <h5 className="text-danger mb-3">Objects as STRIDE Threat Targets</h5>
                      <ul className="mb-2">
                        <li><strong>Spoofing</strong> - Identity objects (User, Session, Token) can be forged or stolen</li>
                        <li><strong>Tampering</strong> - Any object field can be modified; privileged fields (role, permissions) are critical targets</li>
                        <li><strong>Repudiation</strong> - Objects lacking audit fields (created_by, modified_at) enable denial of actions</li>
                        <li><strong>Information Disclosure</strong> - Sensitive object fields (PII, credentials, secrets) can be exposed</li>
                        <li><strong>Denial of Service</strong> - Large objects or expensive operations can exhaust resources</li>
                        <li><strong>Elevation of Privilege</strong> - Authorization objects (Role, Permission) control access levels</li>
                      </ul>
                    </div>

                    <div className="text-white mb-3">
                      <h5 className="text-danger mb-3">Threat Modeling Workflow</h5>
                      <ol className="mb-2">
                        <li className="mb-2">
                          <strong>Capture object structures</strong> - Document real JSON from API responses, storage, or network traffic
                        </li>
                        <li className="mb-2">
                          <strong>Identify sensitive fields</strong> - Mark fields containing PII, credentials, or business-critical data
                        </li>
                        <li className="mb-2">
                          <strong>Map to threats</strong> - Each object becomes a target in your threat model entries
                        </li>
                        <li className="mb-2">
                          <strong>Analyze relationships</strong> - ID fields reveal how objects link together in attack chains
                        </li>
                        <li className="mb-2">
                          <strong>Track changes</strong> - Update objects as you discover new fields or behaviors
                        </li>
                      </ol>
                    </div>

                    <div className="text-white mb-3">
                      <h5 className="text-danger mb-3">Example</h5>
                      <p className="mb-2">When you select "User Object", you might document:</p>
                      <pre 
                        className="bg-secondary p-3 rounded text-white" 
                        style={{ fontSize: '0.85rem' }}
                      >
{`{
  "id": "usr_abc123",
  "username": "testuser",
  "email": "test@example.com",
  "role": "user",
  "is_admin": false,
  "created_at": "2024-01-01T00:00:00Z",
  "permissions": ["read", "write"],
  "organization_id": "org_xyz789"
}`}
                      </pre>
                    </div>

                    <Alert variant="info" className="mb-0 mt-4">
                      <strong>Get started:</strong> Select an object type from the left sidebar or click "Add New" to 
                      create a custom object type. Then paste an example JSON structure from the application.
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
      show={showAddObject} 
      onHide={() => setShowAddObject(false)}
      centered
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">Add New Object Type</Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark">
        <Form.Group>
          <Form.Label className="text-white">Object Name</Form.Label>
          <Form.Control
            type="text"
            value={newObjectName}
            onChange={(e) => setNewObjectName(e.target.value)}
            placeholder="e.g., Custom API Response, Widget Object"
            data-bs-theme="dark"
            onKeyPress={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleAddNewObject();
              }
            }}
          />
          <Form.Text className="text-white-50">
            Enter a descriptive name for this object type
          </Form.Text>
        </Form.Group>
      </Modal.Body>
      <Modal.Footer className="bg-dark border-danger">
        <Button variant="outline-secondary" onClick={() => setShowAddObject(false)}>
          Cancel
        </Button>
        <Button 
          variant="danger" 
          onClick={handleAddNewObject} 
          disabled={saving || !newObjectName.trim()}
        >
          {saving ? (
            <>
              <Spinner animation="border" size="sm" className="me-2" />
              Creating...
            </>
          ) : (
            'Create Object Type'
          )}
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
        Are you sure you want to delete <strong>{objectToDelete}</strong>? This will remove the entire object type and its JSON structure. This action cannot be undone.
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

