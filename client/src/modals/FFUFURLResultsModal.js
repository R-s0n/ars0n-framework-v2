import { Modal, Table, Badge, Spinner, Alert } from 'react-bootstrap';
import { useState, useEffect } from 'react';

export const FFUFURLResultsModal = ({ show, handleClose, activeTarget, mostRecentFFUFURLScan }) => {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (show && mostRecentFFUFURLScan) {
      loadResults();
    }
  }, [show, mostRecentFFUFURLScan]);

  const loadResults = async () => {
    setLoading(true);
    try {
      if (mostRecentFFUFURLScan?.result) {
        let parsedResults = [];
        
        if (typeof mostRecentFFUFURLScan.result === 'string') {
          try {
            const parsed = JSON.parse(mostRecentFFUFURLScan.result);
            parsedResults = parsed.endpoints || parsed.results || [];
          } catch (e) {
            console.error('Error parsing FFUF results:', e);
          }
        } else if (typeof mostRecentFFUFURLScan.result === 'object') {
          parsedResults = mostRecentFFUFURLScan.result.endpoints || mostRecentFFUFURLScan.result.results || [];
        }

        parsedResults.sort((a, b) => {
          const statusA = parseInt(a.status) || 0;
          const statusB = parseInt(b.status) || 0;
          return statusA - statusB;
        });

        setResults(parsedResults);
      }
    } catch (error) {
      console.error('Error loading FFUF results:', error);
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  const getStatusCodeColor = (status) => {
    const code = parseInt(status);
    if (code >= 200 && code < 300) return { bg: 'success', text: 'white' };
    if (code >= 300 && code < 400) return { bg: 'info', text: 'white' };
    if (code === 401 || code === 403) return { bg: 'warning', text: 'dark' };
    if (code >= 400 && code < 500) return { bg: 'secondary', text: 'white' };
    if (code >= 500) return { bg: 'danger', text: 'white' };
    return { bg: 'dark', text: 'white' };
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <Modal show={show} onHide={handleClose} size="xl" data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-search me-2" />
          FFUF Scan Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {loading ? (
          <div className="text-center p-5">
            <Spinner animation="border" variant="danger" />
            <p className="text-white mt-3">Loading results...</p>
          </div>
        ) : results.length === 0 ? (
          <Alert variant="warning">
            No endpoints discovered. Try adjusting your wordlist or scan configuration.
          </Alert>
        ) : (
          <>
            <div className="mb-3">
              <h5 className="text-white">
                Target: <span className="text-danger">{activeTarget?.scope_target}</span>
              </h5>
              <p className="text-white-50">
                Found <Badge bg="danger">{results.length}</Badge> endpoints
              </p>
            </div>

            <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
              <Table striped bordered hover variant="dark" className="mb-0">
                <thead style={{ position: 'sticky', top: 0, backgroundColor: '#212529', zIndex: 1 }}>
                  <tr>
                    <th style={{ width: '100px' }} className="text-center">Status</th>
                    <th>Path</th>
                    <th style={{ width: '100px' }} className="text-center">Size</th>
                    <th style={{ width: '100px' }} className="text-center">Words</th>
                    <th style={{ width: '100px' }} className="text-center">Lines</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((result, index) => {
                    const statusColor = getStatusCodeColor(result.status);
                    return (
                      <tr key={index}>
                        <td className="text-center">
                          <Badge 
                            bg={statusColor.bg} 
                            className={`text-${statusColor.text}`}
                          >
                            {result.status}
                          </Badge>
                        </td>
                        <td className="font-monospace">
                          <a 
                            href={`${activeTarget?.scope_target}/${result.path}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-danger text-decoration-none"
                          >
                            /{result.path}
                          </a>
                        </td>
                        <td className="text-center text-white-50">
                          {formatBytes(result.size || 0)}
                        </td>
                        <td className="text-center text-white-50">
                          {result.words || 0}
                        </td>
                        <td className="text-center text-white-50">
                          {result.lines || 0}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>
            </div>
          </>
        )}
      </Modal.Body>
    </Modal>
  );
};

export default FFUFURLResultsModal;

