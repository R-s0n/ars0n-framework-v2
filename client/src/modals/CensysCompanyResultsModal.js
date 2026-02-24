import React from 'react';
import { Modal, Table, Button } from 'react-bootstrap';
import { copyToClipboard } from '../utils/miscUtils';

export const CensysCompanyResultsModal = ({ 
  show, 
  handleClose, 
  scan,
  setShowToast 
}) => {
  const formatResults = (results) => {
    if (!results?.result) return [];
    try {
      const parsed = JSON.parse(results.result);
      return parsed.domains || [];
    } catch (error) {
      return [];
    }
  };

  const handleCopy = async () => {
    if (scan?.result) {
      try {
        const parsed = JSON.parse(scan.result);
        const domains = parsed.domains.join('\n');
        const success = await copyToClipboard(domains);
        if (success && setShowToast) {
          setShowToast(true);
          setTimeout(() => setShowToast(false), 3000);
        }
      } catch (error) {
        console.error('Error copying results:', error);
      }
    }
  };

  const results = formatResults(scan);

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleClose} 
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>
          Censys Company Results - {results.length} Domains Found
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {scan ? (
          <>
            <div className="mb-3">
              <Table striped bordered hover variant="dark" size="sm">
                <thead>
                  <tr>
                    <th>Scan Details</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><strong>Company Name</strong></td>
                    <td>{scan.company_name || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td><strong>Status</strong></td>
                    <td>
                      <span className={`badge ${
                        scan.status === 'success' ? 'bg-success' : 
                        scan.status === 'error' ? 'bg-danger' : 
                        'bg-warning'
                      }`}>
                        {scan.status}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Execution Time</strong></td>
                    <td>{scan.execution_time || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td><strong>Scan ID</strong></td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                      {scan.scan_id || 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Created At</strong></td>
                    <td>{scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}</td>
                  </tr>
                </tbody>
              </Table>
            </div>

            {scan.error && (
              <div className="alert alert-danger mb-3">
                <h6 className="mb-2">Error</h6>
                {scan.error.includes('401') || scan.error.includes('Unauthorized') ? (
                  <>
                    <p className="mb-2">Censys API authentication failed.</p>
                    <p className="mb-0 small">Please check your Censys API credentials in the API Keys configuration.</p>
                  </>
                ) : (
                  <p className="mb-0">{scan.error}</p>
                )}
              </div>
            )}

            {results.length > 0 ? (
              <>
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h6 className="text-danger mb-0">Domains ({results.length})</h6>
                  <Button variant="outline-danger" size="sm" onClick={handleCopy}>
                    Copy All Domains
                  </Button>
                </div>
                <Table striped bordered hover variant="dark" size="sm">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Domain</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((domain, index) => (
                      <tr key={index}>
                        <td>{index + 1}</td>
                        <td style={{ fontFamily: 'monospace' }}>{domain}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </>
            ) : (
              <div className="text-center text-muted py-4">
                <i className="bi bi-search fs-1"></i>
                <p className="mt-2">No domains found</p>
                {scan.status === 'success' && (
                  <small>The scan completed successfully but no domains were discovered for this company.</small>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="text-center text-muted py-4">
            <i className="bi bi-exclamation-triangle fs-1"></i>
            <p className="mt-2">No scan results available</p>
            <small>Please run a Censys Company scan first.</small>
          </div>
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

export const CensysCompanyHistoryModal = ({ 
  show, 
  handleClose, 
  scans 
}) => {
  const getDomainCount = (scan) => {
    if (!scan?.result) return 0;
    try {
      const parsed = JSON.parse(scan.result);
      return parsed.domains?.length || 0;
    } catch (error) {
      return 0;
    }
  };

  const getErrorDisplay = (error) => {
    if (!error) return null;
    if (error.includes('401') || error.includes('Unauthorized')) {
      return (
        <span className="text-danger" title="API authentication failed">
          <i className="bi bi-key-fill me-1"></i>
          Auth Error
        </span>
      );
    }
    return (
      <span className="text-danger" title={error}>
        <i className="bi bi-exclamation-triangle-fill me-1"></i>
        Error
      </span>
    );
  };

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleClose} 
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>Censys Company Scan History</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {scans && scans.length > 0 ? (
          <Table striped bordered hover variant="dark">
            <thead>
              <tr>
                <th>Company Name</th>
                <th>Status</th>
                <th>Domains Found</th>
                <th>Execution Time</th>
                <th>Created At</th>
                <th>Scan ID</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.scan_id}>
                  <td>{scan.company_name || 'N/A'}</td>
                  <td>
                    {scan.status === 'error' ? (
                      getErrorDisplay(scan.error)
                    ) : (
                      <span className={`badge ${
                        scan.status === 'success' ? 'bg-success' : 
                        scan.status === 'error' ? 'bg-danger' : 
                        'bg-warning'
                      }`}>
                        {scan.status}
                      </span>
                    )}
                  </td>
                  <td>{getDomainCount(scan)}</td>
                  <td>{scan.execution_time || 'N/A'}</td>
                  <td>{scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>{scan.scan_id || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <div className="text-center text-muted py-4">
            <i className="bi bi-clock-history fs-1"></i>
            <p className="mt-2">No scan history available</p>
            <small>Run a Censys Company scan to see results here.</small>
          </div>
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