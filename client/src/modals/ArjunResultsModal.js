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

  const term = searchTerm.toLowerCase();
  const filteredResults = results.filter(r =>
    r.endpoint_url.toLowerCase().includes(term) ||
    r.parameter_name.toLowerCase().includes(term) ||
    (r.http_method || '').toLowerCase().includes(term)
  );

  // Keyed by verb AND url. A hidden parameter on POST /accounts is a different finding from one
  // on GET /accounts, and grouping by url alone hid the body-side result behind the query-side one.
  const groupedResults = filteredResults.reduce((acc, result) => {
    const key = `${result.http_method || 'GET'} ${result.endpoint_url}`;
    if (!acc[key]) {
      acc[key] = [];
    }
    acc[key].push(result);
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
              <Alert variant="dark" className="mb-3 border border-secondary text-light">
                <div className="d-flex justify-content-between">
                  <div>
                    <strong>Status:</strong>{' '}
                    <Badge bg="dark" className={`border ${mostRecentArjunScan.status === 'success'
                      ? 'border-secondary text-light' : 'border-danger text-danger'}`}>
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
                {Object.entries(groupedResults).map(([key, params]) => (
                  <div key={key} className="mb-4">
                    <h6 className="d-flex align-items-center gap-2">
                      <Badge bg="dark" className={`border ${
                        (params[0].http_method || 'GET') === 'GET'
                          ? 'border-secondary text-light' : 'border-danger text-danger'}`}>
                        {params[0].http_method || 'GET'}
                      </Badge>
                      <span className="text-light">{params[0].endpoint_url}</span>
                    </h6>
                    <Table striped bordered hover variant="dark" size="sm">
                      <thead>
                        <tr>
                          <th>Parameter Name</th>
                          <th>Where</th>
                          <th>Confidence</th>
                          <th>Found by</th>
                        </tr>
                      </thead>
                      <tbody>
                        {params.map((param, idx) => (
                          <tr key={idx}>
                            <td><code className="text-light">{param.parameter_name}</code></td>
                            <td>
                              <Badge bg="dark" className="border border-secondary text-light">
                                {param.parameter_type}
                              </Badge>
                            </td>
                            <td>
                              <Badge bg="dark" className={`border ${
                                param.confidence === 'high'
                                  ? 'border-danger text-danger' : 'border-secondary text-white-50'}`}>
                                {param.confidence || 'unknown'}
                              </Badge>
                            </td>
                            {/* Which pass produced it. Arjun scans a body endpoint twice, form
                                then JSON, so the group is what tells those two apart. */}
                            <td className="text-white-50 small">{param.verb_group || '-'}</td>
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
