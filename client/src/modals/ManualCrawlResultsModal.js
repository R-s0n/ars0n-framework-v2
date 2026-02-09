import React, { useState, useEffect } from 'react';
import { Modal, Button, Accordion, Badge, Alert, Spinner, Tabs, Tab } from 'react-bootstrap';

const ManualCrawlResultsModal = ({ show, onHide, scopeTargetId }) => {
  const [sessions, setSessions] = useState([]);
  const [captures, setCaptures] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('endpoints');
  const [allSessions, setAllSessions] = useState([]);

  useEffect(() => {
    if (show && scopeTargetId) {
      loadSessions();
      loadAllSessions();
      loadAllCaptures();
    }
  }, [show, scopeTargetId]);

  const handleRefresh = () => {
    loadSessions();
    loadAllSessions();
    loadAllCaptures();
  };

  const loadSessions = async () => {
    try {
      const response = await fetch(`/api/manual-crawl/sessions/${scopeTargetId}`);
      if (response.ok) {
        const data = await response.json();
        setSessions(data || []);
      } else {
        setError('Failed to load sessions');
      }
    } catch (err) {
      setError('Error connecting to framework: ' + err.message);
    }
  };

  const loadAllSessions = async () => {
    try {
      await fetch('/api/manual-crawl/cleanup', { method: 'POST' });
      
      const response = await fetch('/api/manual-crawl/sessions/all');
      if (response.ok) {
        const data = await response.json();
        setAllSessions(data || []);
      }
    } catch (err) {
      console.error('Error loading all sessions:', err);
    }
  };

  const getParameterSignature = (capture) => {
    const getParamNames = capture.get_params 
      ? Object.keys(capture.get_params).sort().join(',') 
      : '';
    
    let bodySignature = '';
    if (capture.post_params) {
      bodySignature = Object.keys(capture.post_params).sort().join(',');
    } else if (capture.post_data) {
      bodySignature = `RAW_BODY:${capture.body_type || 'unknown'}`;
    }
    
    if (getParamNames && bodySignature) {
      return `GET:${getParamNames}|BODY:${bodySignature}`;
    } else if (getParamNames) {
      return `GET:${getParamNames}`;
    } else if (bodySignature) {
      return `BODY:${bodySignature}`;
    }
    return 'NO_PARAMS';
  };

  const groupCapturesByEndpoint = (captures) => {
    const grouped = {};
    
    captures.forEach(capture => {
      const paramSignature = getParameterSignature(capture);
      const key = `${capture.method}:${capture.endpoint}:${paramSignature}`;
      
      if (!grouped[key]) {
        grouped[key] = {
          ...capture,
          paramSignature: paramSignature
        };
      } else {
        if (new Date(capture.timestamp) > new Date(grouped[key].timestamp)) {
          grouped[key] = {
            ...capture,
            paramSignature: paramSignature
          };
        }
      }
    });
    
    return Object.values(grouped).sort((a, b) => 
      new Date(b.timestamp) - new Date(a.timestamp)
    );
  };

  const loadAllCaptures = async () => {
    setLoading(true);
    setError('');
    try {
      const allCaptures = [];
      for (const session of sessions) {
        const response = await fetch(`/api/manual-crawl/captures/${session.id}`);
        if (response.ok) {
          const data = await response.json();
          allCaptures.push(...(data || []));
        }
      }
      const uniqueEndpoints = groupCapturesByEndpoint(allCaptures);
      setCaptures(uniqueEndpoints);
    } catch (err) {
      setError('Error loading captures: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadSessionCaptures = async (sessionId) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/manual-crawl/captures/${sessionId}`);
      if (response.ok) {
        const data = await response.json();
        const uniqueEndpoints = groupCapturesByEndpoint(data || []);
        setCaptures(uniqueEndpoints);
        setActiveTab('endpoints');
      }
    } catch (err) {
      setError('Error loading captures: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (sessions.length > 0 && captures.length === 0 && activeTab === 'endpoints') {
      loadAllCaptures();
    }
  }, [sessions]);

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  const getStatusBadge = (status) => {
    const variants = {
      'active': 'success',
      'completed': 'info',
      'failed': 'danger'
    };
    return <Badge bg={variants[status] || 'secondary'}>{status}</Badge>;
  };

  const getMethodBadge = (method) => {
    const variants = {
      'GET': 'primary',
      'POST': 'success',
      'PUT': 'warning',
      'DELETE': 'danger',
      'PATCH': 'info'
    };
    return <Badge bg={variants[method] || 'secondary'}>{method}</Badge>;
  };

  const buildRawRequest = (capture) => {
    let raw = `${capture.method} ${new URL(capture.url).pathname}${new URL(capture.url).search} HTTP/1.1\n`;
    raw += `Host: ${new URL(capture.url).hostname}\n`;
    
    if (capture.headers) {
      Object.entries(capture.headers).forEach(([key, value]) => {
        raw += `${key}: ${value}\n`;
      });
    }
    
    raw += '\n';
    if (capture.post_data) {
      raw += capture.post_data;
    }
    
    return raw;
  };

  const buildRawResponse = (capture) => {
    let raw = `HTTP/1.1 ${capture.status_code} ${capture.status_code < 400 ? 'OK' : 'Error'}\n`;
    
    if (capture.response_headers) {
      Object.entries(capture.response_headers).forEach(([key, value]) => {
        raw += `${key}: ${value}\n`;
      });
    }
    
    raw += '\n';
    if (capture.response_body) {
      raw += capture.response_body;
    } else {
      raw += '(Response body not captured)';
    }
    
    return raw;
  };

  return (
    <Modal show={show} onHide={onHide} size="xl" fullscreen="lg-down">
      <style>
        {`
          .accordion-button {
            background-color: #343a40 !important;
            color: white !important;
          }
          .accordion-button:not(.collapsed) {
            background-color: #343a40 !important;
            color: white !important;
          }
          .accordion-button:focus {
            box-shadow: none !important;
          }
          .accordion-button::after {
            filter: invert(1);
          }
          .list-group-item-action:hover {
            background-color: #3a3a3a !important;
          }
          .list-group-item-action:focus {
            background-color: #3a3a3a !important;
          }
          .nav-tabs {
            border-bottom: 1px solid #495057;
          }
          .nav-tabs .nav-link {
            color: #adb5bd;
            background-color: transparent;
            border: none;
          }
          .nav-tabs .nav-link:hover {
            color: white;
            border: none;
          }
          .nav-tabs .nav-link.active {
            color: #dc3545;
            background-color: transparent;
            border: none;
            border-bottom: 2px solid #dc3545;
          }
        `}
      </style>
      <Modal.Header closeButton className="bg-dark text-white">
        <Modal.Title>
          <i className="bi bi-cursor-fill me-2"></i>
          Manual Crawling Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark text-white" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
        {error && (
          <Alert variant="danger" onClose={() => setError('')} dismissible>
            {error}
          </Alert>
        )}

        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="mb-3"
        >
          <Tab eventKey="endpoints" title={`Endpoints (${captures.length})`}>
            {loading ? (
              <div className="text-center py-5">
                <Spinner animation="border" variant="danger" />
                <p className="mt-3">Loading endpoints...</p>
              </div>
            ) : captures.length === 0 ? (
              <>
                <Alert variant="info">
                  <i className="bi bi-info-circle me-2"></i>
                  No endpoints captured yet. Start the Chrome extension and begin capturing to see results here.
                </Alert>
                {allSessions.length > 0 && (
                  <Alert variant="warning">
                    <strong><i className="bi bi-exclamation-triangle me-2"></i>Found {allSessions.length} session(s) for other targets:</strong>
                    <ul className="mt-2 mb-0 small">
                      {allSessions.map(s => (
                        <li key={s.id}>
                          <code>{s.target_url}</code> - {s.request_count} requests, {s.endpoint_count} endpoints
                          <Badge bg={s.status === 'active' ? 'success' : 'secondary'} className="ms-2">{s.status}</Badge>
                        </li>
                      ))}
                    </ul>
                  </Alert>
                )}
              </>
            ) : (
              <Accordion>
                {captures.map((capture, index) => (
                  <Accordion.Item 
                    eventKey={index.toString()} 
                    key={capture.id} 
                    className="border-secondary mb-2"
                    style={{ backgroundColor: '#2b2b2b' }}
                  >
                    <Accordion.Header style={{ backgroundColor: '#343a40' }}>
                      <div className="d-flex justify-content-between align-items-center w-100 me-3">
                        <div className="d-flex align-items-center flex-grow-1">
                          {getMethodBadge(capture.method)}
                          <code className="text-info ms-2" style={{ fontSize: '0.9rem' }}>
                            {capture.endpoint}
                          </code>
                          {capture.get_params && Object.keys(capture.get_params).length > 0 && (
                            <Badge bg="primary" className="ms-2" style={{ fontSize: '0.7rem' }}>
                              ?{Object.keys(capture.get_params).join(', ')}
                            </Badge>
                          )}
                          {capture.post_params && Object.keys(capture.post_params).length > 0 && (
                            <Badge bg="success" className="ms-2" style={{ fontSize: '0.7rem' }}>
                              body: {Object.keys(capture.post_params).join(', ')}
                            </Badge>
                          )}
                          {!capture.post_params && capture.post_data && (
                            <Badge bg="warning" className="ms-2" style={{ fontSize: '0.7rem' }}>
                              body: {capture.body_type || 'raw'}
                            </Badge>
                          )}
                        </div>
                        <div className="d-flex align-items-center">
                          <Badge bg={capture.status_code < 400 ? 'success' : 'danger'} className="me-2">
                            {capture.status_code}
                          </Badge>
                          <small className="text-light">{formatDate(capture.timestamp)}</small>
                        </div>
                      </div>
                    </Accordion.Header>
                    <Accordion.Body className="text-white" style={{ backgroundColor: '#2b2b2b' }}>
                      <div className="mb-3">
                        <strong className="text-warning d-block mb-1">Full URL:</strong>
                        <code className="text-info small">{capture.url}</code>
                      </div>

                      {capture.get_params && Object.keys(capture.get_params).length > 0 && (
                        <div className="mb-3">
                          <strong className="text-warning d-block mb-1">
                            <i className="bi bi-question-circle me-1"></i>
                            GET Parameters:
                          </strong>
                          <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.85rem', maxHeight: '150px', overflowY: 'auto' }}>
                            {JSON.stringify(capture.get_params, null, 2)}
                          </pre>
                        </div>
                      )}

                      {(capture.post_params || capture.post_data) && (
                        <div className="mb-3">
                          <strong className="text-success d-block mb-1">
                            <i className="bi bi-file-earmark-text me-1"></i>
                            Request Body:
                            {capture.body_type && (
                              <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.7rem' }}>
                                {capture.body_type}
                              </Badge>
                            )}
                          </strong>
                          {capture.post_params ? (
                            <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.85rem', maxHeight: '150px', overflowY: 'auto' }}>
                              {JSON.stringify(capture.post_params, null, 2)}
                            </pre>
                          ) : (
                            <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.85rem', maxHeight: '150px', overflowY: 'auto' }}>
                              {capture.post_data}
                            </pre>
                          )}
                        </div>
                      )}

                      <div className="row mb-3">
                        <div className="col-md-6">
                          <strong className="text-info d-block mb-1">
                            <i className="bi bi-box-arrow-up-right me-1"></i>
                            Request Headers:
                          </strong>
                          {capture.headers && Object.keys(capture.headers).length > 0 ? (
                            <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.75rem', maxHeight: '150px', overflowY: 'auto' }}>
                              {JSON.stringify(capture.headers, null, 2)}
                            </pre>
                          ) : (
                            <div className="text-light small" style={{ opacity: 0.6 }}>No headers captured</div>
                          )}
                        </div>
                        <div className="col-md-6">
                          <strong className="text-info d-block mb-1">
                            <i className="bi bi-box-arrow-in-down me-1"></i>
                            Response Headers:
                          </strong>
                          {capture.response_headers && Object.keys(capture.response_headers).length > 0 ? (
                            <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.75rem', maxHeight: '150px', overflowY: 'auto' }}>
                              {JSON.stringify(capture.response_headers, null, 2)}
                            </pre>
                          ) : (
                            <div className="text-light small" style={{ opacity: 0.6 }}>No headers captured</div>
                          )}
                        </div>
                      </div>

                      <div className="row">
                        <div className="col-md-6 mb-3">
                          <strong className="text-warning d-block mb-1">
                            <i className="bi bi-code-square me-1"></i>
                            Raw HTTP Request:
                          </strong>
                          <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.75rem', maxHeight: '300px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {buildRawRequest(capture)}
                          </pre>
                        </div>
                        <div className="col-md-6 mb-3">
                          <strong className="text-success d-block mb-1">
                            <i className="bi bi-reply me-1"></i>
                            Raw HTTP Response:
                          </strong>
                          <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.75rem', maxHeight: '300px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {buildRawResponse(capture)}
                          </pre>
                        </div>
                      </div>
                    </Accordion.Body>
                  </Accordion.Item>
                ))}
              </Accordion>
            )}
          </Tab>

          <Tab eventKey="sessions" title={`Sessions (${sessions.length})`}>
            {sessions.length === 0 ? (
              <Alert variant="info">
                <i className="bi bi-info-circle me-2"></i>
                No capture sessions found for this target.
              </Alert>
            ) : (
              <div className="list-group">
                {sessions.map((session) => (
                  <div
                    key={session.id}
                    className="list-group-item list-group-item-action text-white border-secondary mb-2"
                    onClick={() => loadSessionCaptures(session.id)}
                    style={{ cursor: 'pointer', backgroundColor: '#2b2b2b' }}
                  >
                    <div className="d-flex justify-content-between align-items-center">
                      <div>
                        <h6 className="mb-1 text-white">
                          {getStatusBadge(session.status)}
                          <span className="ms-2 text-info">{session.target_url}</span>
                        </h6>
                        <small className="text-light" style={{ opacity: 0.7 }}>
                          Started: {formatDate(session.started_at)}
                          {session.ended_at && ` | Ended: ${formatDate(session.ended_at)}`}
                        </small>
                      </div>
                      <div>
                        <Badge bg="info" className="me-2">{session.request_count || 0} requests</Badge>
                        <Badge bg="success">{session.endpoint_count || 0} endpoints</Badge>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer className="bg-dark text-white">
        <Button variant="outline-info" onClick={handleRefresh}>
          <i className="bi bi-arrow-clockwise me-1"></i>
          Refresh
        </Button>
        <Button variant="outline-secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ManualCrawlResultsModal;
