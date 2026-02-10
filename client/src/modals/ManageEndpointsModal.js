import React, { useState, useEffect } from 'react';
import { Modal, Button, Nav, Badge, Form, InputGroup, Accordion, Spinner, Alert } from 'react-bootstrap';

const ManageEndpointsModal = ({ show, onHide, scopeTargetId }) => {
  const [endpoints, setEndpoints] = useState([]);
  const [filteredEndpoints, setFilteredEndpoints] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [investigationResults, setInvestigationResults] = useState([]);

  useEffect(() => {
    if (show && scopeTargetId) {
      loadEndpoints();
      loadInvestigationResults();
    }
  }, [show, scopeTargetId]);

  useEffect(() => {
    applyFilters();
  }, [endpoints, activeTab, searchTerm]);

  const loadEndpoints = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`/api/consolidated-endpoints/${scopeTargetId}`);
      if (response.ok) {
        const data = await response.json();
        setEndpoints(data || []);
      } else {
        setError('Failed to load endpoints');
      }
    } catch (err) {
      setError('Error connecting to framework: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadInvestigationResults = async () => {
    try {
      const response = await fetch(`/api/endpoint-investigation/${scopeTargetId}/results`);
      if (response.ok) {
        const data = await response.json();
        setInvestigationResults(data || []);
      }
    } catch (err) {
      console.log('No investigation results available yet');
    }
  };

  const applyFilters = () => {
    let filtered = [...endpoints];

    if (activeTab === 'direct') {
      filtered = filtered.filter(ep => ep.is_direct);
    } else if (activeTab === 'adjacent') {
      filtered = filtered.filter(ep => !ep.is_direct);
    }

    if (searchTerm) {
      const lowerSearch = searchTerm.toLowerCase();
      filtered = filtered.filter(ep => 
        ep.url.toLowerCase().includes(lowerSearch) ||
        ep.domain.toLowerCase().includes(lowerSearch) ||
        ep.path.toLowerCase().includes(lowerSearch) ||
        ep.method.toLowerCase().includes(lowerSearch)
      );
    }

    setFilteredEndpoints(filtered);
  };

  const getMethodBadgeColor = (method) => {
    const colors = {
      'GET': 'primary',
      'POST': 'success',
      'PUT': 'warning',
      'DELETE': 'danger',
      'PATCH': 'info',
      'OPTIONS': 'secondary'
    };
    return colors[method] || 'secondary';
  };

  const getStatusBadgeColor = (status) => {
    if (status >= 200 && status < 300) return 'success';
    if (status >= 300 && status < 400) return 'info';
    if (status >= 400 && status < 500) return 'warning';
    if (status >= 500) return 'danger';
    return 'secondary';
  };

  const directCount = endpoints.filter(ep => ep.is_direct).length;
  const adjacentCount = endpoints.filter(ep => !ep.is_direct).length;

  return (
    <Modal show={show} onHide={onHide} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-diagram-3 me-2"></i>
          Manage Consolidated Endpoints
        </Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ overflowY: 'auto' }}>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        <div className="mb-3 d-flex justify-content-between align-items-center">
          <div>
            <Badge bg="danger" className="me-2">
              Total: {endpoints.length}
            </Badge>
            <Badge bg="danger" className="me-2" style={{ opacity: 0.7 }}>
              Direct: {directCount}
            </Badge>
            <Badge bg="danger" style={{ opacity: 0.5 }}>
              Adjacent: {adjacentCount}
            </Badge>
            {investigationResults.length > 0 && (
              <Badge bg="success" className="ms-2">
                <i className="bi bi-check-circle me-1"></i>
                {investigationResults.length} Investigated
              </Badge>
            )}
          </div>
          <Button 
            variant="outline-danger" 
            size="sm" 
            onClick={loadEndpoints}
            disabled={loading}
          >
            {loading ? (
              <><Spinner animation="border" size="sm" className="me-2" />Refreshing...</>
            ) : (
              <><i className="bi bi-arrow-clockwise me-2"></i>Refresh</>
            )}
          </Button>
        </div>

        <InputGroup className="mb-3">
          <InputGroup.Text className="bg-dark text-white border-secondary">
            <i className="bi bi-search"></i>
          </InputGroup.Text>
          <Form.Control
            type="text"
            placeholder="Search endpoints..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-dark text-white border-secondary"
          />
          {searchTerm && (
            <Button 
              variant="outline-secondary" 
              onClick={() => setSearchTerm('')}
            >
              Clear
            </Button>
          )}
        </InputGroup>

        <Nav variant="pills" className="mb-3">
          <Nav.Item>
            <Nav.Link 
              active={activeTab === 'all'} 
              onClick={() => setActiveTab('all')}
              className={activeTab === 'all' ? 'bg-danger' : 'text-danger'}
            >
              All ({endpoints.length})
            </Nav.Link>
          </Nav.Item>
          <Nav.Item>
            <Nav.Link 
              active={activeTab === 'direct'} 
              onClick={() => setActiveTab('direct')}
              className={activeTab === 'direct' ? 'bg-danger' : 'text-danger'}
            >
              Direct ({directCount})
            </Nav.Link>
          </Nav.Item>
          <Nav.Item>
            <Nav.Link 
              active={activeTab === 'adjacent'} 
              onClick={() => setActiveTab('adjacent')}
              className={activeTab === 'adjacent' ? 'bg-danger' : 'text-danger'}
            >
              Adjacent ({adjacentCount})
            </Nav.Link>
          </Nav.Item>
        </Nav>

        {loading ? (
          <div className="text-center py-5">
            <Spinner animation="border" variant="danger" />
            <p className="mt-3">Loading endpoints...</p>
          </div>
        ) : filteredEndpoints.length === 0 ? (
          <Alert variant="warning">
            No endpoints found. Run endpoint discovery tools or use Manual Crawling to capture requests.
          </Alert>
        ) : (
          <EndpointAccordion 
            endpoints={filteredEndpoints} 
            getMethodBadgeColor={getMethodBadgeColor}
            getStatusBadgeColor={getStatusBadgeColor}
            showOrigin={activeTab === 'adjacent'}
            investigationResults={investigationResults}
          />
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

const EndpointAccordion = ({ endpoints, getMethodBadgeColor, getStatusBadgeColor, showOrigin = false, investigationResults = [] }) => {
  const getInvestigationData = (endpointId) => {
    return investigationResults.find(result => result.endpoint_id === endpointId);
  };

  return (
    <Accordion>
      {endpoints.map((endpoint, idx) => {
        const investigation = getInvestigationData(endpoint.id);
        const hasInvestigation = !!investigation;
        
        return (
        <Accordion.Item eventKey={idx.toString()} key={endpoint.id} className="bg-dark border-secondary">
          <Accordion.Header className="bg-dark">
            <div className="d-flex w-100 align-items-center justify-content-between me-3">
              <div style={{ flex: '0 0 80px' }}>
                <Badge bg={getMethodBadgeColor(endpoint.method)}>
                  {endpoint.method}
                </Badge>
              </div>
              <div style={{ flex: '1 1 auto' }} className="text-truncate">
                <small>
                  <strong className="text-danger">{endpoint.domain}</strong>
                  <span className="text-white">{endpoint.path}</span>
                  {hasInvestigation && (
                    <Badge bg="success" className="ms-2" style={{ fontSize: '0.7em' }}>
                      <i className="bi bi-check-circle me-1"></i>Investigated
                    </Badge>
                  )}
                </small>
              </div>
              <div style={{ flex: '0 0 120px' }} className="text-end">
                {endpoint.status_codes && endpoint.status_codes.length > 0 ? (
                  endpoint.status_codes.slice(0, 2).map((code, idx) => (
                    <Badge key={idx} bg={getStatusBadgeColor(code)} className="me-1">
                      {code}
                    </Badge>
                  ))
                ) : (
                  <Badge bg="secondary">N/A</Badge>
                )}
              </div>
              <div style={{ flex: '0 0 300px' }} className="text-start">
                {endpoint.parameters && endpoint.parameters.length > 0 ? (
                  <small>
                    {endpoint.parameters.slice(0, 3).map((param, pidx) => (
                      <Badge key={pidx} bg="danger" className="me-1" style={{ opacity: 0.8 }}>
                        {param.param_name}
                      </Badge>
                    ))}
                    {endpoint.parameters.length > 3 && (
                      <Badge bg="danger" style={{ opacity: 0.6 }}>
                        +{endpoint.parameters.length - 3}
                      </Badge>
                    )}
                  </small>
                ) : (
                  <small className="text-muted">No params</small>
                )}
              </div>
              <div style={{ flex: '0 0 100px' }} className="text-end">
                <Badge bg="secondary">
                  {endpoint.request_count} reqs
                </Badge>
              </div>
            </div>
          </Accordion.Header>
          <Accordion.Body className="bg-dark text-white">
            <div className="mb-3">
              <strong className="text-danger">Full URL:</strong><br />
              <code className="text-white">{endpoint.url}</code>
            </div>

            <div className="row mb-3">
              <div className="col-md-4">
                <strong className="text-danger">Type:</strong><br />
                <Badge bg="danger" style={{ opacity: endpoint.is_direct ? 1 : 0.6 }}>
                  {endpoint.is_direct ? 'Direct' : 'Adjacent'}
                </Badge>
              </div>
              <div className="col-md-4">
                <strong className="text-danger">Domain:</strong><br />
                <code className="text-white">{endpoint.domain}</code>
              </div>
              <div className="col-md-4">
                <strong className="text-danger">Sources:</strong><br />
                {endpoint.sources?.map((source, idx) => (
                  <Badge key={idx} bg="secondary" className="me-1">
                    {source}
                  </Badge>
                ))}
              </div>
            </div>

            {showOrigin && endpoint.origin_url && (
              <div className="mb-3">
                <strong className="text-danger">Origin URL:</strong><br />
                <code className="text-white">{endpoint.origin_url}</code>
              </div>
            )}

            {endpoint.parameters && endpoint.parameters.length > 0 && (
              <div className="mb-3">
                <strong className="text-danger">Parameters ({endpoint.parameters.length}):</strong>
                <div className="mt-2" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                  <table className="table table-dark table-sm table-bordered">
                    <thead>
                      <tr>
                        <th style={{ width: '100px' }}>Type</th>
                        <th>Name</th>
                        <th>Example Values</th>
                        <th style={{ width: '80px' }}>Frequency</th>
                      </tr>
                    </thead>
                    <tbody>
                      {endpoint.parameters.map((param, idx) => (
                        <tr key={idx}>
                          <td>
                            <Badge bg="danger" style={{ opacity: param.param_type === 'query' ? 1 : 0.7 }}>
                              {param.param_type}
                            </Badge>
                          </td>
                          <td><code className="text-white">{param.param_name}</code></td>
                          <td>
                            <small>
                              {param.example_values && param.example_values.length > 0 ? (
                                param.example_values.slice(0, 3).map((val, vidx) => (
                                  <Badge key={vidx} bg="secondary" className="me-1 mb-1">
                                    {val.length > 30 ? val.substring(0, 30) + '...' : val}
                                  </Badge>
                                ))
                              ) : (
                                <span className="text-muted">No examples</span>
                              )}
                              {param.example_values && param.example_values.length > 3 && (
                                <Badge bg="danger" className="ms-1">+{param.example_values.length - 3} more</Badge>
                              )}
                            </small>
                          </td>
                          <td className="text-center">
                            <Badge bg="danger">{param.frequency}</Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {hasInvestigation && (
              <>
                <hr style={{ borderColor: '#444' }} />
                <h6 className="text-danger mb-3">
                  <i className="bi bi-search me-2"></i>Investigation Results
                </h6>

                {investigation.security_headers && (
                  <div className="mb-3">
                    <strong className="text-danger">Security Headers:</strong>
                    <div className="mt-2">
                      {investigation.security_headers.missing && investigation.security_headers.missing.length > 0 && (
                        <div className="mb-2">
                          <Badge bg="warning" className="me-1">Missing:</Badge>
                          {investigation.security_headers.missing.map((header, idx) => (
                            <Badge key={idx} bg="secondary" className="me-1">{header}</Badge>
                          ))}
                        </div>
                      )}
                      {investigation.security_headers.strict_transport_security && (
                        <div className="mb-1"><small><strong>HSTS:</strong> {investigation.security_headers.strict_transport_security}</small></div>
                      )}
                      {investigation.security_headers.content_security_policy && (
                        <div className="mb-1"><small><strong>CSP:</strong> {investigation.security_headers.content_security_policy.substring(0, 100)}...</small></div>
                      )}
                      {investigation.security_headers.x_frame_options && (
                        <div className="mb-1"><small><strong>X-Frame-Options:</strong> {investigation.security_headers.x_frame_options}</small></div>
                      )}
                    </div>
                  </div>
                )}

                {investigation.technologies && investigation.technologies.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Technologies Detected:</strong><br />
                    {investigation.technologies.map((tech, idx) => (
                      <Badge key={idx} bg="info" className="me-1 mt-1">{tech}</Badge>
                    ))}
                  </div>
                )}

                {investigation.cookies && investigation.cookies.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Cookies ({investigation.cookies.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '200px', overflowY: 'auto' }}>
                      <table className="table table-dark table-sm table-bordered">
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Secure</th>
                            <th>HttpOnly</th>
                            <th>SameSite</th>
                          </tr>
                        </thead>
                        <tbody>
                          {investigation.cookies.map((cookie, idx) => (
                            <tr key={idx}>
                              <td><code>{cookie.name}</code></td>
                              <td>{cookie.secure ? <Badge bg="success">Yes</Badge> : <Badge bg="danger">No</Badge>}</td>
                              <td>{cookie.httponly ? <Badge bg="success">Yes</Badge> : <Badge bg="danger">No</Badge>}</td>
                              <td><Badge bg="secondary">{cookie.samesite || 'None'}</Badge></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {investigation.secrets && investigation.secrets.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">
                      <i className="bi bi-exclamation-triangle me-1"></i>
                      Potential Secrets Found ({investigation.secrets.length}):
                    </strong>
                    <div className="mt-2">
                      {investigation.secrets.map((secret, idx) => (
                        <div key={idx} className="mb-1">
                          <Badge bg="danger" className="me-2">{secret.type}</Badge>
                          <code className="text-white">{secret.value}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {investigation.misconfigurations && investigation.misconfigurations.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">
                      <i className="bi bi-shield-exclamation me-1"></i>
                      Misconfigurations ({investigation.misconfigurations.length}):
                    </strong>
                    <div className="mt-2">
                      {investigation.misconfigurations.map((misconfig, idx) => (
                        <div key={idx} className="mb-1">
                          <Badge bg="warning" className="me-2">{idx + 1}</Badge>
                          <small>{misconfig}</small>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {investigation.forms && investigation.forms.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Forms Found ({investigation.forms.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '200px', overflowY: 'auto' }}>
                      {investigation.forms.map((form, idx) => (
                        <div key={idx} className="mb-2 p-2 border border-secondary rounded">
                          <div>
                            <Badge bg="primary" className="me-2">{form.method}</Badge>
                            {form.action && <code className="text-white">{form.action}</code>}
                            {form.has_file && <Badge bg="warning" className="ms-2">File Upload</Badge>}
                          </div>
                          <div className="mt-1">
                            <small>Fields: {form.fields.join(', ')}</small>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {investigation.apis && investigation.apis.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">API Endpoints Found ({investigation.apis.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '150px', overflowY: 'auto' }}>
                      {investigation.apis.map((api, idx) => (
                        <div key={idx}><code className="text-white">{api}</code></div>
                      ))}
                    </div>
                  </div>
                )}

                {investigation.input_fields && investigation.input_fields.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Input Fields ({investigation.input_fields.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '150px', overflowY: 'auto' }}>
                      {investigation.input_fields.slice(0, 10).map((field, idx) => (
                        <Badge key={idx} bg="secondary" className="me-1 mb-1">
                          {field.name} ({field.type})
                        </Badge>
                      ))}
                      {investigation.input_fields.length > 10 && (
                        <Badge bg="danger">+{investigation.input_fields.length - 10} more</Badge>
                      )}
                    </div>
                  </div>
                )}

                {investigation.comments && investigation.comments.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Comments Found ({investigation.comments.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '150px', overflowY: 'auto' }}>
                      {investigation.comments.slice(0, 5).map((comment, idx) => (
                        <div key={idx} className="mb-1">
                          <small className="text-muted">{comment}</small>
                        </div>
                      ))}
                      {investigation.comments.length > 5 && (
                        <Badge bg="danger">+{investigation.comments.length - 5} more</Badge>
                      )}
                    </div>
                  </div>
                )}

                {investigation.cors && (
                  <div className="mb-3">
                    <strong className="text-danger">CORS Configuration:</strong>
                    <div className="mt-2">
                      <div className="mb-1"><small><strong>Allow-Origin:</strong> {investigation.cors.allow_origin}</small></div>
                      {investigation.cors.allow_methods && (
                        <div className="mb-1"><small><strong>Allow-Methods:</strong> {investigation.cors.allow_methods}</small></div>
                      )}
                      {investigation.cors.allow_credentials && (
                        <div className="mb-1">
                          <Badge bg="warning">Credentials Enabled</Badge>
                        </div>
                      )}
                      {investigation.cors.misconfigured && investigation.cors.issues && (
                        <div className="mt-2">
                          <Badge bg="danger" className="me-2">Misconfigured</Badge>
                          {investigation.cors.issues.map((issue, idx) => (
                            <div key={idx} className="ms-3 mt-1"><small>{issue}</small></div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="row mt-3">
                  <div className="col-md-4">
                    <strong className="text-danger">Response Time:</strong><br />
                    <Badge bg="info">{investigation.response_time_ms}ms</Badge>
                  </div>
                  <div className="col-md-4">
                    <strong className="text-danger">Response Size:</strong><br />
                    <Badge bg="info">{Math.round(investigation.response_size / 1024)}KB</Badge>
                  </div>
                  <div className="col-md-4">
                    <strong className="text-danger">Server:</strong><br />
                    <code className="text-white">{investigation.server || 'N/A'}</code>
                  </div>
                </div>
              </>
            )}

            <hr style={{ borderColor: '#444' }} />
            
            <div className="row">
              <div className="col-md-6">
                <strong className="text-danger">First Seen:</strong><br />
                <small>{new Date(endpoint.first_seen).toLocaleString()}</small>
              </div>
              <div className="col-md-6">
                <strong className="text-danger">Last Seen:</strong><br />
                <small>{new Date(endpoint.last_seen).toLocaleString()}</small>
              </div>
            </div>
          </Accordion.Body>
        </Accordion.Item>
        );
      })}
    </Accordion>
  );
};

export default ManageEndpointsModal;
