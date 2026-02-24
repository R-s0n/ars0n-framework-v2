import { useState } from 'react';
import { Modal, Button, Table, Spinner, Badge } from 'react-bootstrap';

export const DNSxCompanyHistoryModal = ({ 
  show, 
  handleClose, 
  scans 
}) => {
  const [loading, setLoading] = useState(false);

  const getDNSRecordCount = (scan) => {
    if (!scan.result || scan.result === 'null' || scan.result === '') {
      return 0;
    }

    try {
      const result = JSON.parse(scan.result);
      return result.length || 0;
    } catch (error) {
      return 0;
    }
  };

  const getScannedDomainsCount = (scan) => {
    if (!scan.domains || !Array.isArray(scan.domains)) {
      return 0;
    }
    return scan.domains.length;
  };

  const getScannedDomains = (scan) => {
    if (!scan.domains || !Array.isArray(scan.domains)) {
      return [];
    }
    return scan.domains;
  };

  const getRecordTypeBreakdown = (scan) => {
    if (!scan.result || scan.result === 'null' || scan.result === '') {
      return {};
    }

    try {
      const result = JSON.parse(scan.result);
      const breakdown = {};
      
      result.forEach(record => {
        const type = record.record_type || 'Unknown';
        breakdown[type] = (breakdown[type] || 0) + 1;
      });
      
      return breakdown;
    } catch (error) {
      return {};
    }
  };

  const renderRecordTypeBadges = (scan) => {
    const breakdown = getRecordTypeBreakdown(scan);
    const entries = Object.entries(breakdown);
    
    if (entries.length === 0) {
      return <span className="text-muted small">No records</span>;
    }

    return entries.map(([type, count]) => {
      let variant = 'secondary';
      switch (type) {
        case 'A': variant = 'success'; break;
        case 'AAAA': variant = 'info'; break;
        case 'CNAME': variant = 'warning'; break;
        case 'MX': variant = 'danger'; break;
        case 'NS': variant = 'primary'; break;
        case 'TXT': variant = 'secondary'; break;
        case 'PTR': variant = 'dark'; break;
        case 'SRV': variant = 'purple'; break;
      }
      
      return (
        <Badge key={type} bg={variant} className="me-1">
          {type}: {count}
        </Badge>
      );
    });
  };

  return (
    <Modal show={show} onHide={handleClose} size="xl" className="text-white">
      <Modal.Header closeButton className="bg-dark border-secondary">
        <Modal.Title className="text-danger">
          <i className="bi bi-dns me-2"></i>
          DNSx Company Scan History
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark text-white" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
        {loading ? (
          <div className="text-center py-4">
            <Spinner animation="border" role="status" variant="danger">
              <span className="visually-hidden">Loading...</span>
            </Spinner>
          </div>
        ) : (
          <>
            {scans && scans.length > 0 ? (
              <Table striped bordered hover variant="dark" responsive>
                <thead>
                  <tr>
                    <th>Scan ID</th>
                    <th>Domains Scanned</th>
                    <th>DNS Records Found</th>
                    <th>Record Types</th>
                    <th>Status</th>
                    <th>Started</th>
                    <th>Execution Time</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan, index) => (
                    <tr key={index}>
                      <td>
                        <code className="text-info small">
                          {scan.scan_id?.substring(0, 8)}...
                        </code>
                      </td>
                      <td>
                        <div className="d-flex align-items-center">
                          <span className="me-2">{getScannedDomainsCount(scan)}</span>
                          {getScannedDomainsCount(scan) > 0 && (
                            <div className="text-muted small">
                              {getScannedDomains(scan).slice(0, 2).map((domain, i) => (
                                <div key={i}>{domain}</div>
                              ))}
                              {getScannedDomainsCount(scan) > 2 && (
                                <div>+{getScannedDomainsCount(scan) - 2} more...</div>
                              )}
                            </div>
                          )}
                        </div>
                      </td>
                      <td>
                        <Badge bg="info" className="me-1">
                          {getDNSRecordCount(scan)}
                        </Badge>
                      </td>
                      <td>
                        <div style={{ maxWidth: '200px' }}>
                          {renderRecordTypeBadges(scan)}
                        </div>
                      </td>
                      <td>
                        <Badge 
                          bg={scan.status === 'success' ? 'success' : 
                              scan.status === 'running' ? 'warning' : 
                              scan.status === 'pending' ? 'info' : 'danger'}
                        >
                          {scan.status}
                        </Badge>
                      </td>
                      <td className="small text-muted">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td className="small">
                        {scan.execution_time?.String || 'N/A'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <div className="text-center py-5">
                <div className="text-white-50 mb-3">
                  <i className="bi bi-clock-history" style={{ fontSize: '3rem' }}></i>
                </div>
                <h5 className="text-white-50 mb-3">No Scan History</h5>
                <p className="text-white-50">
                  No DNSx Company scans have been run yet for this target.
                </p>
              </div>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer className="bg-dark border-secondary">
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}; 