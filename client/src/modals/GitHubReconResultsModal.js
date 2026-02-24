import React from 'react';
import { Modal, Table } from 'react-bootstrap';

export const GitHubReconResultsModal = ({ 
  show, 
  handleClose, 
  scan,
  setShowToast 
}) => {
  const formatResults = (results) => {
    try {
      // Handle null, undefined, or empty string cases
      if (!results || results === '' || results === 'undefined' || results === 'null') {
        return [];
      }
      
      const parsedResults = JSON.parse(results);
      
      // Handle different possible result structures
      if (Array.isArray(parsedResults)) {
        // If results is already an array of domains
        return parsedResults;
      } else if (parsedResults.domains && Array.isArray(parsedResults.domains)) {
        // If results has a domains property with an array
        return parsedResults.domains.map(domain => {
          // Handle both string domains and object domains
          return typeof domain === 'string' ? domain : domain.domain || domain;
        });
      } else if (typeof parsedResults === 'object' && parsedResults !== null) {
        // If results is an object but doesn't have domains property
        return [];
      }
      
      return [];
    } catch (error) {
      console.error('Error parsing results:', error);
      return [];
    }
  };

  const handleCopy = async () => {
    if (!scan?.result) return;
    try {
      const domains = formatResults(scan.result);
      const text = domains.join('\n');
      await navigator.clipboard.writeText(text);
      setShowToast(true);
    } catch (error) {
      console.error('[GITHUB-RECON] Error copying results:', error);
    }
  };

  const results = formatResults(scan?.result);

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleClose} 
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>
          GitHub Recon Results - {results.length} Domains Found
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

            <div className="mb-3">
              <div className="d-flex justify-content-between align-items-center mb-2">
                <h5>Results</h5>
                <button 
                  className="btn btn-outline-light btn-sm"
                  onClick={handleCopy}
                >
                  Copy All
                </button>
              </div>
              {results.length > 0 ? (
                <Table striped bordered hover variant="dark" size="sm">
                  <thead>
                    <tr>
                      <th>Domain</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((domain, index) => (
                      <tr key={index}>
                        <td>{domain}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              ) : (
                <p className="text-muted">No results found</p>
              )}
            </div>

            {scan.error && (
              <div className="mb-3">
                <h5 className="text-danger">Error</h5>
                <pre className="bg-dark text-light p-3 rounded" style={{ maxHeight: '200px', overflow: 'auto' }}>
                  {scan.error}
                </pre>
              </div>
            )}

            {scan.stdout && (
              <div className="mb-3">
                <h5>Output</h5>
                <pre className="bg-dark text-light p-3 rounded" style={{ maxHeight: '200px', overflow: 'auto' }}>
                  {scan.stdout}
                </pre>
              </div>
            )}
          </>
        ) : (
          <p className="text-muted">No scan data available</p>
        )}
      </Modal.Body>
    </Modal>
  );
};

export const GitHubReconHistoryModal = ({ 
  show, 
  handleClose, 
  scans 
}) => {
  const getDomainCount = (scan) => {
    if (!scan?.result) return 0;
    try {
      // Handle null, undefined, or empty string cases
      if (!scan.result || scan.result === '' || scan.result === 'undefined' || scan.result === 'null') {
        return 0;
      }
      
      const parsed = JSON.parse(scan.result);
      
      // Handle different possible result structures
      if (Array.isArray(parsed)) {
        return parsed.length;
      } else if (parsed.domains && Array.isArray(parsed.domains)) {
        return parsed.domains.length;
      }
      
      return 0;
    } catch (error) {
      return 0;
    }
  };

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleClose} 
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>GitHub Recon Scan History</Modal.Title>
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
                    <span className={`badge ${
                      scan.status === 'success' ? 'bg-success' : 
                      scan.status === 'error' ? 'bg-danger' : 
                      'bg-warning'
                    }`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>{getDomainCount(scan)}</td>
                  <td>{scan.execution_time || 'N/A'}</td>
                  <td>{scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                    {scan.scan_id || 'N/A'}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <p className="text-muted">No scans found</p>
        )}
      </Modal.Body>
    </Modal>
  );
}; 