import React, { useState, useEffect } from 'react';
import { Modal, Button, Table, Badge, Tabs, Tab, Alert, Spinner } from 'react-bootstrap';

const ManualCrawlResultsModal = ({ show, onHide, scopeTargetId }) => {
  const [sessions, setSessions] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [captures, setCaptures] = useState([]);
  const [endpoints, setEndpoints] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('sessions');
  const [allSessions, setAllSessions] = useState([]);

  useEffect(() => {
    if (show && scopeTargetId) {
      loadSessions();
      loadEndpoints();
      loadAllSessions();
    }
  }, [show, scopeTargetId]);

  const handleRefresh = () => {
    loadSessions();
    loadEndpoints();
    loadAllSessions();
    if (selectedSession) {
      loadCaptures(selectedSession);
    }
  };

  const loadSessions = async () => {
    setLoading(true);
    setError('');
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
    } finally {
      setLoading(false);
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

  const loadEndpoints = async () => {
    try {
      const response = await fetch(`/api/manual-crawl/endpoints/${scopeTargetId}`);
      if (response.ok) {
        const data = await response.json();
        setEndpoints(data || []);
      }
    } catch (err) {
      console.error('Error loading endpoints:', err);
    }
  };

  const loadCaptures = async (sessionId) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/manual-crawl/captures/${sessionId}`);
      if (response.ok) {
        const data = await response.json();
        setCaptures(data || []);
        setSelectedSession(sessionId);
        setActiveTab('captures');
      }
    } catch (err) {
      setError('Error loading captures: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

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

  return (
    <Modal show={show} onHide={onHide} size="xl">
      <Modal.Header closeButton className="bg-dark text-white">
        <Modal.Title>
          <i className="bi bi-cursor-fill me-2"></i>
          Manual Crawling Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark text-white">
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
          <Tab eventKey="sessions" title={`Sessions (${sessions.length})`}>
            {loading && activeTab === 'sessions' ? (
              <div className="text-center py-5">
                <Spinner animation="border" variant="danger" />
                <p className="mt-3">Loading sessions...</p>
              </div>
            ) : sessions.length === 0 ? (
              <>
                <Alert variant="info">
                  <i className="bi bi-info-circle me-2"></i>
                  No capture sessions found for this target. Start the Chrome extension and begin capturing to see results here.
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
                    <div className="mt-3 small">
                      <i className="bi bi-info-circle me-1"></i>
                      These sessions are for different targets. The extension auto-creates targets based on the crawled domain. To view these results, find the corresponding target in your scope list.
                    </div>
                  </Alert>
                )}
              </>
            ) : (
              <Table striped bordered hover variant="dark">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Target URL</th>
                    <th>Started</th>
                    <th>Ended</th>
                    <th>Requests</th>
                    <th>Endpoints</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr key={session.id}>
                      <td>{getStatusBadge(session.status)}</td>
                      <td>
                        <small className="text-info">{session.target_url}</small>
                      </td>
                      <td>
                        <small>{formatDate(session.started_at)}</small>
                      </td>
                      <td>
                        <small>{formatDate(session.ended_at)}</small>
                      </td>
                      <td>
                        <Badge bg="info">{session.request_count || 0}</Badge>
                      </td>
                      <td>
                        <Badge bg="success">{session.endpoint_count || 0}</Badge>
                      </td>
                      <td>
                        <Button
                          variant="outline-danger"
                          size="sm"
                          onClick={() => loadCaptures(session.id)}
                        >
                          <i className="bi bi-eye me-1"></i>
                          View Details
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Tab>

          <Tab eventKey="endpoints" title={`Endpoints (${endpoints.length})`}>
            {endpoints.length === 0 ? (
              <Alert variant="info">
                <i className="bi bi-info-circle me-2"></i>
                No endpoints discovered yet.
              </Alert>
            ) : (
              <Table striped bordered hover variant="dark">
                <thead>
                  <tr>
                    <th>Method</th>
                    <th>Endpoint</th>
                    <th>Request Count</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((endpoint, idx) => (
                    <tr key={idx}>
                      <td>{getMethodBadge(endpoint.method)}</td>
                      <td>
                        <code className="text-warning">{endpoint.endpoint}</code>
                      </td>
                      <td>
                        <Badge bg="info">{endpoint.request_count}</Badge>
                      </td>
                      <td>
                        <small>{formatDate(endpoint.first_seen)}</small>
                      </td>
                      <td>
                        <small>{formatDate(endpoint.last_seen)}</small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Tab>

          <Tab eventKey="captures" title="Request Details" disabled={!selectedSession}>
            {loading ? (
              <div className="text-center py-5">
                <Spinner animation="border" variant="danger" />
                <p className="mt-3">Loading request details...</p>
              </div>
            ) : captures.length === 0 ? (
              <Alert variant="info">
                <i className="bi bi-info-circle me-2"></i>
                Select a session to view captured requests.
              </Alert>
            ) : (
              <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
                <Table striped bordered hover variant="dark" size="sm">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Method</th>
                      <th>URL</th>
                      <th>Status</th>
                      <th>Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {captures.map((capture) => (
                      <tr key={capture.id}>
                        <td>
                          <small>{formatDate(capture.timestamp)}</small>
                        </td>
                        <td>{getMethodBadge(capture.method)}</td>
                        <td>
                          <small className="text-info">{capture.url}</small>
                        </td>
                        <td>
                          <Badge bg={capture.status_code < 400 ? 'success' : 'danger'}>
                            {capture.status_code}
                          </Badge>
                        </td>
                        <td>
                          <small className="text-muted">{capture.mime_type}</small>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
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
