import React from 'react';
import { Card, Table, Badge } from 'react-bootstrap';

const CensysCompanyScanResults = ({ scan }) => {
  if (!scan) return null;

  const renderStatus = (status) => {
    switch (status) {
      case 'success':
        return <Badge bg="success">Completed</Badge>;
      case 'pending':
        return <Badge bg="warning">Pending</Badge>;
      case 'error':
        return <Badge bg="danger">Failed</Badge>;
      default:
        return <Badge bg="secondary">{status}</Badge>;
    }
  };

  const renderResults = () => {
    if (scan.status === 'pending') {
      return (
        <div className="text-center p-4">
          <div className="spinner-border text-danger" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-2">Scan in progress...</p>
        </div>
      );
    }

    if (scan.status === 'error') {
      return (
        <div className="p-3">
          <h5 className="text-danger">Scan Failed</h5>
          <p className="text-muted">{scan.error || 'Unknown error occurred'}</p>
        </div>
      );
    }

    if (!scan.result) {
      return (
        <div className="p-3">
          <p className="text-muted">No results available</p>
        </div>
      );
    }

    try {
      const parsedResults = JSON.parse(scan.result);
      const domains = parsedResults.domains || [];

      return (
        <div className="p-3">
          <h5 className="text-danger mb-3">Domains Found: {domains.length}</h5>
          {domains.length > 0 ? (
            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
              <Table striped bordered hover variant="dark" size="sm">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Domain</th>
                  </tr>
                </thead>
                <tbody>
                  {domains.map((domain, index) => (
                    <tr key={index}>
                      <td>{index + 1}</td>
                      <td style={{ fontFamily: 'monospace' }}>{domain}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          ) : (
            <p className="text-muted">No domains found for this company.</p>
          )}
        </div>
      );
    } catch (error) {
      return (
        <div className="p-3">
          <p className="text-danger">Error parsing results</p>
        </div>
      );
    }
  };

  return (
    <Card className="bg-dark text-white">
      <Card.Header className="d-flex justify-content-between align-items-center">
        <span>Censys Company Scan</span>
        {renderStatus(scan.status)}
      </Card.Header>
      <Card.Body>
        {renderResults()}
      </Card.Body>
    </Card>
  );
};

export default CensysCompanyScanResults; 