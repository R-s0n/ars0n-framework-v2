import React from 'react';
import { Card, Table, Badge, Spinner } from 'react-bootstrap';

const SecurityTrailsCompanyScanResults = ({ scan }) => {
  if (!scan) return null;

  const renderStatus = (status) => {
    switch (status) {
      case 'completed':
        return <Badge bg="success">Completed</Badge>;
      case 'pending':
        return <Badge bg="warning">Pending</Badge>;
      case 'failed':
        return <Badge bg="danger">Failed</Badge>;
      default:
        return <Badge bg="secondary">{status}</Badge>;
    }
  };

  const renderResults = () => {
    if (scan.status === 'pending') {
      return (
        <div className="text-center p-4">
          <Spinner animation="border" role="status">
            <span className="visually-hidden">Loading...</span>
          </Spinner>
          <p className="mt-2">Scan in progress...</p>
        </div>
      );
    }

    if (scan.status === 'failed') {
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
      const results = JSON.parse(scan.result);
      if (!results.domains || results.domains.length === 0) {
        return (
          <div className="p-3">
            <p className="text-muted">No domains found</p>
          </div>
        );
      }

      return (
        <Table striped bordered hover responsive>
          <thead>
            <tr>
              <th>Domain</th>
              <th>First Seen</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {results.domains.map((domain, index) => (
              <tr key={index}>
                <td>{domain.hostname}</td>
                <td>{new Date(domain.first_seen).toLocaleDateString()}</td>
                <td>{new Date(domain.last_seen).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </Table>
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
    <Card className="mb-4">
      <Card.Header className="d-flex justify-content-between align-items-center">
        <h5 className="mb-0">SecurityTrails Company Scan Results</h5>
        {renderStatus(scan.status)}
      </Card.Header>
      <Card.Body>
        {renderResults()}
      </Card.Body>
      <Card.Footer className="text-muted">
        <small>
          Scan ID: {scan.scan_id} | 
          Started: {new Date(scan.created_at).toLocaleString()} | 
          Execution Time: {scan.execution_time}ms
        </small>
      </Card.Footer>
    </Card>
  );
};

export default SecurityTrailsCompanyScanResults; 