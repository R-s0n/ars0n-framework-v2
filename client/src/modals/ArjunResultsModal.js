import { useState, useEffect } from 'react';
import { Modal, Button, Table, Spinner, Alert, Badge, Form, InputGroup } from 'react-bootstrap';

export const ArjunResultsModal = ({ show, handleClose, activeTarget, mostRecentArjunScan }) => {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    if (show && mostRecentArjunScan && mostRecentArjunScan.scan_id) {
      loadResults();
    }
  }, [show, mostRecentArjunScan]);

  const loadResults = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/arjun/results/${mostRecentArjunScan.scan_id}`);
      if (response.ok) {
        const data = await response.json();
        setResults(data || []);
      }
    } catch (error) {
      console.error('Error loading Arjun results:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredResults = results.filter(r =>
    r.endpoint_url.toLowerCase().includes(searchTerm.toLowerCase()) ||
    r.parameter_name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const groupedResults = filteredResults.reduce((acc, result) => {
    if (!acc[result.endpoint_url]) {
      acc[result.endpoint_url] = [];
    }
    acc[result.endpoint_url].push(result);
    return acc;
  }, {});

  return (
    <Modal show={show} onHide={handleClose} size="xl" data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-search me-2"></i>
          Arjun Scan Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {loading ? (
          <div className="text-center py-5">
            <Spinner animation="border" variant="danger" />
            <p className="text-white mt-3">Loading results...</p>
          </div>
        ) : (
          <>
            {mostRecentArjunScan && (
              <Alert variant="secondary" className="mb-3">
                <div className="d-flex justify-content-between">
                  <div>
                    <strong>Status:</strong>{' '}
                    <Badge bg={mostRecentArjunScan.status === 'success' ? 'success' : 'warning'}>
                      {mostRecentArjunScan.status}
                    </Badge>
                  </div>
                  <div>
                    <strong>Parameters Found:</strong> {mostRecentArjunScan.parameters_found || 0}
                  </div>
                  <div>
                    <strong>Endpoints Scanned:</strong> {mostRecentArjunScan.processed_endpoints || 0}
                  </div>
                </div>
                {mostRecentArjunScan.execution_time && (
                  <div className="mt-2">
                    <strong>Execution Time:</strong> {mostRecentArjunScan.execution_time}
                  </div>
                )}
              </Alert>
            )}

            <Form.Group className="mb-3">
              <InputGroup>
                <Form.Control
                  type="text"
                  placeholder="Search endpoints or parameters..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  data-bs-theme="dark"
                />
              </InputGroup>
            </Form.Group>

            {Object.keys(groupedResults).length > 0 ? (
              <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
                {Object.entries(groupedResults).map(([endpoint, params]) => (
                  <div key={endpoint} className="mb-4">
                    <h6 className="text-info">{endpoint}</h6>
                    <Table striped bordered hover variant="dark" size="sm">
                      <thead>
                        <tr>
                          <th>Parameter Name</th>
                          <th>Type</th>
                          <th>Confidence</th>
                          <th>Example Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {params.map((param, idx) => (
                          <tr key={idx}>
                            <td><code>{param.parameter_name}</code></td>
                            <td>
                              <Badge bg="info">{param.parameter_type}</Badge>
                            </td>
                            <td>
                              <Badge bg="success">{param.confidence}</Badge>
                            </td>
                            <td><code>{param.example_value || 'N/A'}</code></td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </div>
                ))}
              </div>
            ) : (
              <Alert variant="warning">
                No parameters found in this scan.
              </Alert>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};
