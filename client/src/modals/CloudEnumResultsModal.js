import React from 'react';
import { Modal, Table, Button, Badge } from 'react-bootstrap';
import { copyToClipboard } from '../utils/miscUtils';

export const CloudEnumResultsModal = ({
  showCloudEnumResultsModal,
  handleCloseCloudEnumResultsModal,
  cloudEnumResults,
  setShowToast
}) => {
  const formatResults = (results) => {
    if (!results?.result) return [];
    
    try {
      // Backend stores results as JSON array string, not newline-delimited JSON
      const cloudAssets = JSON.parse(results.result);
      
      // Ensure it's an array and filter valid entries
      if (Array.isArray(cloudAssets)) {
        return cloudAssets.filter(asset => asset.platform && asset.target);
      }
      
      return [];
    } catch (error) {
      console.error('Error parsing cloud_enum results:', error);
      console.log('Raw result data:', results.result);
      return [];
    }
  };

  const handleCopy = async () => {
    if (cloudEnumResults?.result) {
      const success = await copyToClipboard(cloudEnumResults.result);
      if (success && setShowToast) {
        setShowToast(true);
        setTimeout(() => setShowToast(false), 3000);
      }
    }
  };

  const results = formatResults(cloudEnumResults);
  
  // Group results by platform
  const groupedResults = results.reduce((acc, asset) => {
    const platform = asset.platform.toUpperCase();
    if (!acc[platform]) acc[platform] = [];
    acc[platform].push(asset);
    return acc;
  }, {});

  const getPlatformColor = (platform) => {
    switch (platform.toLowerCase()) {
      case 'aws': return 'warning';
      case 'azure': return 'info';
      case 'gcp': return 'success';
      default: return 'secondary';
    }
  };

  const getAccessColor = (access) => {
    switch (access?.toLowerCase()) {
      case 'public': return 'danger';
      case 'protected': return 'warning';
      case 'private': return 'success';
      default: return 'secondary';
    }
  };

  return (
    <Modal
      data-bs-theme="dark"
      show={showCloudEnumResultsModal}
      onHide={handleCloseCloudEnumResultsModal}
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>
          Cloud Enum Results - {results.length} Assets Found
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {cloudEnumResults ? (
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
                    <td>{cloudEnumResults.company_name || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td><strong>Status</strong></td>
                    <td>
                      <span className={`badge ${
                        cloudEnumResults.status === 'success' ? 'bg-success' :
                        cloudEnumResults.status === 'error' ? 'bg-danger' :
                        'bg-warning'
                      }`}>
                        {cloudEnumResults.status}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Execution Time</strong></td>
                    <td>{cloudEnumResults.execution_time || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td><strong>Scan ID</strong></td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                      {cloudEnumResults.scan_id || 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Created At</strong></td>
                    <td>{cloudEnumResults.created_at ? new Date(cloudEnumResults.created_at).toLocaleString() : 'N/A'}</td>
                  </tr>
                </tbody>
              </Table>
            </div>

            {cloudEnumResults.status === 'error' && cloudEnumResults.error && (
              <div className="mb-3">
                <h6 className="text-danger">Error Details:</h6>
                <pre className="bg-dark text-danger p-2 rounded" style={{ fontSize: '0.9em' }}>
                  {cloudEnumResults.error}
                </pre>
              </div>
            )}

            {results.length > 0 ? (
              <>
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h6 className="text-danger mb-0">Cloud Assets ({results.length})</h6>
                  <Button variant="outline-danger" size="sm" onClick={handleCopy}>
                    Copy All Results
                  </Button>
                </div>
                
                {Object.keys(groupedResults).map(platform => (
                  <div key={platform} className="mb-4">
                    <div className="d-flex align-items-center mb-2">
                      <Badge bg={getPlatformColor(platform)} className="me-2">
                        {platform}
                      </Badge>
                      <span className="text-muted">({groupedResults[platform].length} assets)</span>
                    </div>
                    
                    <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                      <Table striped bordered hover variant="dark" size="sm">
                        <thead>
                          <tr>
                            <th>#</th>
                            <th>Asset Type</th>
                            <th>Target</th>
                            <th>Access</th>
                          </tr>
                        </thead>
                        <tbody>
                          {groupedResults[platform].map((asset, index) => (
                            <tr key={index}>
                              <td>{index + 1}</td>
                              <td>{asset.msg || 'N/A'}</td>
                              <td style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                                <a href={asset.target} target="_blank" rel="noopener noreferrer" className="text-info">
                                  {asset.target}
                                </a>
                              </td>
                              <td>
                                <Badge bg={getAccessColor(asset.access)}>
                                  {asset.access || 'Unknown'}
                                </Badge>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </Table>
                    </div>
                  </div>
                ))}
              </>
            ) : (
              <div className="text-center text-muted py-4">
                <i className="bi bi-cloud fs-1"></i>
                <p className="mt-2">No cloud assets found</p>
                {cloudEnumResults.status === 'success' && (
                  <small>The scan completed successfully but no cloud assets were discovered for this company.</small>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="text-center text-muted py-4">
            <i className="bi bi-exclamation-triangle fs-1"></i>
            <p className="mt-2">No scan results available</p>
            <small>Please run a Cloud Enum scan first.</small>
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleCloseCloudEnumResultsModal}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export const CloudEnumHistoryModal = ({
  showCloudEnumHistoryModal,
  handleCloseCloudEnumHistoryModal,
  cloudEnumScans
}) => {
  const getAssetCount = (result) => {
    if (!result) return 0;
    try {
      const lines = result.split('\n').filter(line => line.trim());
      let count = 0;
      lines.forEach(line => {
        try {
          const parsed = JSON.parse(line);
          if (parsed.platform && parsed.target) count++;
        } catch (e) {
          // Skip non-JSON lines
        }
      });
      return count;
    } catch (error) {
      return 0;
    }
  };

  return (
    <Modal
      data-bs-theme="dark"
      show={showCloudEnumHistoryModal}
      onHide={handleCloseCloudEnumHistoryModal}
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>Cloud Enum Scan History</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {cloudEnumScans && cloudEnumScans.length > 0 ? (
          <Table striped bordered hover variant="dark">
            <thead>
              <tr>
                <th>Company Name</th>
                <th>Status</th>
                <th>Assets Found</th>
                <th>Execution Time</th>
                <th>Created At</th>
                <th>Scan ID</th>
              </tr>
            </thead>
            <tbody>
              {cloudEnumScans.map((scan, index) => (
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
                  <td>{getAssetCount(scan.result)}</td>
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
            <p className="mt-2">No scan history available</p>
            <small>Cloud Enum scans will appear here once they're completed.</small>
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleCloseCloudEnumHistoryModal}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}; 