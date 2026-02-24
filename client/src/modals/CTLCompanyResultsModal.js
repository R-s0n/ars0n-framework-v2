import React from 'react';
import { Modal, Table, Button } from 'react-bootstrap';
import { copyToClipboard } from '../utils/miscUtils';

export const CTLCompanyResultsModal = ({ 
  showCTLCompanyResultsModal, 
  handleCloseCTLCompanyResultsModal, 
  ctlCompanyResults,
  setShowToast 
}) => {
  const formatResults = (results) => {
    if (!results?.result) return [];
    return results.result.split('\n').filter(line => line.trim());
  };

  const handleCopy = async () => {
    if (ctlCompanyResults?.result) {
      const success = await copyToClipboard(ctlCompanyResults.result);
      if (success && setShowToast) {
        setShowToast(true);
        setTimeout(() => setShowToast(false), 3000);
      }
    }
  };

  const results = formatResults(ctlCompanyResults);

  return (
    <Modal 
      data-bs-theme="dark" 
      show={showCTLCompanyResultsModal} 
      onHide={handleCloseCTLCompanyResultsModal} 
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>
          CTL Company Results - {results.length} Domains Found
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {ctlCompanyResults ? (
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
                    <td>{ctlCompanyResults.company_name || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td><strong>Status</strong></td>
                    <td>
                      <span className={`badge ${
                        ctlCompanyResults.status === 'success' ? 'bg-success' : 
                        ctlCompanyResults.status === 'error' ? 'bg-danger' : 
                        'bg-warning'
                      }`}>
                        {ctlCompanyResults.status}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Execution Time</strong></td>
                    <td>{ctlCompanyResults.execution_time || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td><strong>Scan ID</strong></td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                      {ctlCompanyResults.scan_id || 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Created At</strong></td>
                    <td>{ctlCompanyResults.created_at ? new Date(ctlCompanyResults.created_at).toLocaleString() : 'N/A'}</td>
                  </tr>
                </tbody>
              </Table>
            </div>

            {ctlCompanyResults.status === 'error' && ctlCompanyResults.error && (
              <div className="mb-3">
                <h6 className="text-danger">Error Details:</h6>
                <pre className="bg-dark text-danger p-2 rounded" style={{ fontSize: '0.9em' }}>
                  {ctlCompanyResults.error}
                </pre>
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
                </div>
              </>
            ) : (
              <div className="text-center text-muted py-4">
                <i className="bi bi-search fs-1"></i>
                <p className="mt-2">No domains found</p>
                {ctlCompanyResults.status === 'success' && (
                  <small>The scan completed successfully but no domains were discovered for this company.</small>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="text-center text-muted py-4">
            <i className="bi bi-exclamation-triangle fs-1"></i>
            <p className="mt-2">No scan results available</p>
            <small>Please run a CTL Company scan first.</small>
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleCloseCTLCompanyResultsModal}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export const CTLCompanyHistoryModal = ({ 
  showCTLCompanyHistoryModal, 
  handleCloseCTLCompanyHistoryModal, 
  ctlCompanyScans 
}) => {
  return (
    <Modal 
      data-bs-theme="dark" 
      show={showCTLCompanyHistoryModal} 
      onHide={handleCloseCTLCompanyHistoryModal} 
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>CTL Company Scan History</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {ctlCompanyScans && ctlCompanyScans.length > 0 ? (
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
              {ctlCompanyScans.map((scan, index) => (
                <tr key={index}>
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
                  <td>
                    {scan.result ? scan.result.split('\n').filter(line => line.trim()).length : 0}
                  </td>
                  <td>{scan.execution_time || 'N/A'}</td>
                  <td>{scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8em' }}>
                    {scan.scan_id || 'N/A'}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <div className="text-center text-muted py-4">
            <i className="bi bi-clock-history fs-1"></i>
            <p className="mt-2">No CTL Company scan history found</p>
            <small>Run your first CTL Company scan to see history here.</small>
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleCloseCTLCompanyHistoryModal}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}; 