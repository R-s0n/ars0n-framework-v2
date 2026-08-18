import { useState, useEffect } from 'react';
import { Modal, Button, Table, Spinner, Alert, Badge, Form, InputGroup } from 'react-bootstrap';

export const X8ResultsModal = ({ show, handleClose, activeTarget, mostRecentX8Scan }) => {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  // The per-pass outcome, which is the only place a zero-finding run explains itself.
  const [detail, setDetail] = useState(null);
  const [showCommand, setShowCommand] = useState(false);

  useEffect(() => {
    if (show && mostRecentX8Scan && mostRecentX8Scan.scan_id) {
      loadResults();
    }
  }, [show, mostRecentX8Scan]);

  const loadResults = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/x8/results/${mostRecentX8Scan.scan_id}`);
      if (response.ok) {
        const data = await response.json();
        setResults(data || []);
      }
      // Fetched separately because the scans list carries only the headline counts. This is what
      // answers "it says zero, did it actually run": each pass reports its own endpoint count,
      // findings and, when it failed, x8's own error text.
      const statusRes = await fetch(`/api/x8/status/${mostRecentX8Scan.scan_id}`);
      if (statusRes.ok) {
        const status = await statusRes.json();
        let groups = [];
        try {
          groups = (JSON.parse(status.result || '{}').groups) || [];
        } catch (err) {
          groups = [];
        }
        // Scans from before the summary moved to `result` hold that JSON blob in `error`. Rendering
        // it as a red failure banner would report a successful old scan as broken, so a payload that
        // is obviously the summary is read as one instead.
        let legacyError = status.error || '';
        if (legacyError.trim().startsWith('{')) {
          try {
            const parsed = JSON.parse(legacyError);
            if (parsed.groups) {
              if (groups.length === 0) groups = parsed.groups;
              legacyError = '';
            }
          } catch (err) { /* not the summary, so leave it as the error it claims to be */ }
        }
        setDetail({ groups, error: legacyError, command: status.command || '',
                    stdout: status.stdout || '' });
      }
    } catch (error) {
      console.error('Error loading x8 results:', error);
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
          x8 Scan Results
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
            {mostRecentX8Scan && (
              <Alert variant="dark" className="mb-3 border border-secondary text-light">
                <div className="d-flex justify-content-between">
                  <div>
                    <strong>Status:</strong>{' '}
                    <Badge bg="dark" className={`border ${mostRecentX8Scan.status === 'success'
                      ? 'border-secondary text-light' : 'border-danger text-danger'}`}>
                      {mostRecentX8Scan.status}
                    </Badge>
                  </div>
                  <div>
                    <strong>Parameters Found:</strong> {mostRecentX8Scan.parameters_found || 0}
                  </div>
                  <div>
                    <strong>Endpoints Scanned:</strong> {mostRecentX8Scan.processed_endpoints || 0}
                  </div>
                </div>
                {mostRecentX8Scan.execution_time && (
                  <div className="mt-2">
                    <strong>Execution Time:</strong> {mostRecentX8Scan.execution_time}
                  </div>
                )}
              </Alert>
            )}

            {detail && detail.error && (
              <Alert variant="dark" className="mb-3 border border-danger text-danger py-2 small">
                {detail.error}
              </Alert>
            )}

            {detail && detail.groups.length > 0 && (
              <div className="mb-3">
                <div className="text-white-50 small mb-1">Passes</div>
                <Table bordered hover variant="dark" size="sm" className="mb-1">
                  <thead>
                    <tr>
                      <th>Pass</th>
                      <th>Endpoints</th>
                      <th>Found</th>
                      <th>Outcome</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.groups.map((g, i) => (
                      <tr key={i}>
                        <td className="text-light">{g.label}</td>
                        <td className="text-white-50">{g.endpoints}</td>
                        <td className={g.found > 0 ? 'text-danger' : 'text-white-50'}>{g.found}</td>
                        <td className={g.failed ? 'text-danger small' : 'text-white-50 small'}>
                          {g.failed ? 'failed: ' : ''}{g.detail || 'ok'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
                <Button size="sm" variant="link" className="p-0 text-danger"
                        onClick={() => setShowCommand((v) => !v)}>
                  {showCommand ? 'Hide' : 'Show'} the commands that ran
                </Button>
                {showCommand && (
                  <pre className="text-light small p-2 rounded mt-1"
                       style={{ backgroundColor: '#1e1e1e', whiteSpace: 'pre-wrap',
                                wordBreak: 'break-all', maxHeight: '180px', overflowY: 'auto' }}>
                    {detail.command || '(none recorded)'}
                  </pre>
                )}
              </div>
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
                          <th>Value</th>
                          <th>Why</th>
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
                            {/* The value x8 sent when the response changed. For its non-random
                                custom parameters this is the finding: admin=true is the lead, not
                                the name "admin". Blank when x8 used a random value. */}
                            <td>
                              {param.example_value
                                ? <code className="text-danger">{param.example_value}</code>
                                : <span className="text-white-50 small">random</span>}
                            </td>
                            {/* x8's own reason: Reflected (value echoed), Code (status changed),
                                Text (body changed), NotReflected. */}
                            <td className="text-white-50 small">{param.detection_reason || '-'}</td>
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
              <Alert variant="dark" className="border border-secondary text-light">
                No hidden parameters were stored for this scan. The Passes table above says whether
                each pass actually ran: a pass that failed, or one that tested no URL, is not the
                same result as a pass that found nothing.
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
