import React from 'react';
import { Modal, Table, Button } from 'react-bootstrap';
import { copyToClipboard } from '../utils/miscUtils';

export const SecurityTrailsCompanyResultsModal = ({ 
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
        const domains = parsed.domains.map(d => d.hostname).join('\n');
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
          SecurityTrails Company Results - {results.length} Domains Found
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
                {scan.error.includes('rate limit exceeded') ? (
                  <>
                    <p className="mb-2">SecurityTrails API rate limit has been exceeded.</p>
                    <p className="mb-0 small">Please upgrade your SecurityTrails plan or try again later.</p>
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
                <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                  <Table striped bordered hover variant="dark" size="sm">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Domain</th>
                        <th>Host Provider</th>
                        <th>Created Date</th>
                        <th>Expires Date</th>
                        <th>Registrar</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.map((domain, index) => (
                        <tr key={index}>
                          <td>{index + 1}</td>
                          <td style={{ fontFamily: 'monospace' }}>{domain.hostname}</td>
                          <td>{domain.host_provider?.join(', ') || 'N/A'}</td>
                          <td>{domain.whois?.created_date ? new Date(domain.whois.created_date).toLocaleDateString() : 'N/A'}</td>
                          <td>{domain.whois?.expires_date ? new Date(domain.whois.expires_date).toLocaleDateString() : 'N/A'}</td>
                          <td>{domain.whois?.registrar || 'N/A'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                </div>
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
            <small>Please run a SecurityTrails Company scan first.</small>
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

export const SecurityTrailsCompanyHistoryModal = ({ 
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

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleClose} 
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>SecurityTrails Company Scan History</Modal.Title>
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
                  <td style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>{scan.scan_id || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <div className="text-center text-muted py-4">
            <i className="bi bi-clock-history fs-1"></i>
            <p className="mt-2">No scan history available</p>
            <small>Run a SecurityTrails Company scan to see results here.</small>
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