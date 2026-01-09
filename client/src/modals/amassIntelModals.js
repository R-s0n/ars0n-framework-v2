import React, { useState, useEffect } from 'react';
import { Modal, Table, Nav, Row, Col } from 'react-bootstrap';
import { MdCopyAll } from 'react-icons/md';

export const AmassIntelResultsModal = ({ 
  showAmassIntelResultsModal, 
  handleCloseAmassIntelResultsModal, 
  amassIntelResults,
  setShowToast 
}) => {
  const [activeTab, setActiveTab] = useState('networks');
  const [networkRanges, setNetworkRanges] = useState([]);
  const [asnData, setAsnData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (showAmassIntelResultsModal && amassIntelResults && amassIntelResults.scan_id) {
      fetchAmassIntelData(amassIntelResults.scan_id);
    } else if (showAmassIntelResultsModal && amassIntelResults) {
      if (amassIntelResults.status === 'error') {
        setError('Scan failed. Please check the scan details and try again.');
        setLoading(false);
      } else if (!amassIntelResults.scan_id) {
        setError('No scan ID available for this scan.');
        setLoading(false);
      }
    }
  }, [showAmassIntelResultsModal, amassIntelResults]);

  const fetchAmassIntelData = async (scanId) => {
    setLoading(true);
    setError(null);
    setNetworkRanges([]);
    setAsnData([]);

    try {
      const networkResponse = await fetch(
        `/api/amass-intel/${scanId}/networks`
      );
      
      if (networkResponse.ok) {
        const networkData = await networkResponse.json();
        setNetworkRanges(Array.isArray(networkData) ? networkData : []);
      } else {
        console.warn('Failed to fetch network ranges:', networkResponse.status);
        setNetworkRanges([]);
      }

      const asnResponse = await fetch(
        `/api/amass-intel/${scanId}/asn`
      );
      
      if (asnResponse.ok) {
        const asnDataResult = await asnResponse.json();
        setAsnData(Array.isArray(asnDataResult) ? asnDataResult : []);
      } else {
        console.warn('Failed to fetch ASN data:', asnResponse.status);
        setAsnData([]);
      }

    } catch (error) {
      console.error('Error fetching Amass Intel data:', error);
      setError('Failed to fetch scan results. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyText = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 3000);
    } catch (err) {
      console.error('Failed to copy text:', err);
    }
  };

  const getResultCount = () => {
    if (!amassIntelResults || amassIntelResults.status === 'error') return 0;
    return networkRanges.length + asnData.length;
  };

  const getExecutionTime = () => {
    if (!amassIntelResults || !amassIntelResults.execution_time) return 'N/A';
    return amassIntelResults.execution_time;
  };

  const getScanStatus = () => {
    if (!amassIntelResults) return 'Unknown';
    return amassIntelResults.status || 'Unknown';
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    try {
      return new Date(dateString).toLocaleString();
    } catch (error) {
      return 'Invalid Date';
    }
  };

  const renderContent = () => {
    if (amassIntelResults && amassIntelResults.status === 'error') {
      return (
        <div className="text-center py-5">
          <div className="text-danger mb-3">
            <i className="bi bi-exclamation-triangle" style={{ fontSize: '3rem' }}></i>
          </div>
          <h5 className="text-danger mb-3">Scan Failed</h5>
          <p className="text-muted mb-3">
            The Amass Intel scan encountered an error and could not complete successfully.
          </p>
          {amassIntelResults.stderr && (
            <div className="alert alert-danger small text-start mt-3">
              <strong>Error Details:</strong><br />
              {amassIntelResults.stderr}
            </div>
          )}
        </div>
      );
    }

    if (loading) {
      return (
        <div className="text-center py-5">
          <div className="spinner-border text-danger mb-3" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="text-muted">Loading scan results...</p>
        </div>
      );
    }

    if (error) {
      return (
        <div className="text-center py-5">
          <div className="text-warning mb-3">
            <i className="bi bi-exclamation-triangle" style={{ fontSize: '3rem' }}></i>
          </div>
          <h5 className="text-warning mb-3">Error</h5>
          <p className="text-muted">{error}</p>
        </div>
      );
    }

    if (networkRanges.length === 0 && asnData.length === 0) {
      return (
        <div className="text-center py-5">
          <div className="text-muted mb-3">
            <i className="bi bi-cloud" style={{ fontSize: '3rem' }}></i>
          </div>
          <h5 className="text-muted mb-3">No Network Ranges Found</h5>
          <p className="text-muted">
            The scan completed successfully but found no network ranges or ASN data. This typically indicates:
          </p>
          <ul className="list-unstyled text-muted small">
            <li>• <strong>Cloud-First Infrastructure:</strong> Company likely uses cloud providers (AWS, Azure, GCP)</li>
            <li>• <strong>No Direct ASN Ownership:</strong> Infrastructure hosted under cloud provider ASNs</li>
            <li>• <strong>Modern Architecture:</strong> Serverless, containerized, or fully managed services</li>
            <li>• <strong>Attack Surface:</strong> Focus on web applications, APIs, and cloud services instead</li>
          </ul>
          <div className="alert alert-info mt-3">
            <small>
              <i className="bi bi-info-circle me-2"></i>
              <strong>Recommendation:</strong> Consider using subdomain enumeration, cloud asset discovery, or web application testing tools for cloud-native targets.
            </small>
          </div>
        </div>
      );
    }

    return (
      <>
        <Nav variant="tabs" className="mb-3">
          <Nav.Item>
            <Nav.Link 
              active={activeTab === 'networks'} 
              onClick={() => setActiveTab('networks')}
              className={activeTab === 'networks' ? 'text-danger' : 'text-white'}
            >
              Network Ranges ({networkRanges.length})
            </Nav.Link>
          </Nav.Item>
          <Nav.Item>
            <Nav.Link 
              active={activeTab === 'asn'} 
              onClick={() => setActiveTab('asn')}
              className={activeTab === 'asn' ? 'text-danger' : 'text-white'}
            >
              ASN Data ({asnData.length})
            </Nav.Link>
          </Nav.Item>
        </Nav>

        {activeTab === 'networks' && (
          <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
            {networkRanges.length > 0 ? (
              <Table striped bordered hover variant="dark" className="mb-0">
                <thead>
                  <tr>
                    <th>CIDR Block</th>
                    <th>ASN</th>
                    <th>Organization</th>
                    <th>Description</th>
                    <th>Country</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {networkRanges.map((network) => (
                    <tr key={network.id}>
                      <td className="font-monospace">{network.cidr_block}</td>
                      <td className="font-monospace">{network.asn || 'N/A'}</td>
                      <td>{network.organization || 'N/A'}</td>
                      <td>{network.description || 'N/A'}</td>
                      <td>
                        {network.country ? (
                          <span className="badge bg-secondary">{network.country}</span>
                        ) : 'N/A'}
                      </td>
                      <td>
                        <button 
                          onClick={() => handleCopyText(network.cidr_block)}
                          className="btn btn-sm btn-outline-danger"
                          title="Copy CIDR block"
                        >
                          <MdCopyAll size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <div className="text-center py-4">
                <p className="text-muted">No network ranges found.</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'asn' && (
          <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
            {asnData.length > 0 ? (
              <Table striped bordered hover variant="dark" className="mb-0">
                <thead>
                  <tr>
                    <th>ASN Number</th>
                    <th>Organization</th>
                    <th>Description</th>
                    <th>Country</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {asnData.map((asn, index) => (
                    <tr key={index}>
                      <td className="font-monospace">AS{asn.asn_number}</td>
                      <td>{asn.organization || 'N/A'}</td>
                      <td>{asn.description || 'N/A'}</td>
                      <td>
                        {asn.country ? (
                          <span className="badge bg-secondary">{asn.country}</span>
                        ) : 'N/A'}
                      </td>
                      <td>
                        <button 
                          onClick={() => handleCopyText(`AS${asn.asn_number}`)}
                          className="btn btn-sm btn-outline-danger"
                          title="Copy ASN"
                        >
                          <MdCopyAll size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <div className="text-center py-4">
                <p className="text-muted">No ASN data found.</p>
              </div>
            )}
          </div>
        )}
      </>
    );
  };

  return (
    <Modal 
      data-bs-theme="dark" 
      show={showAmassIntelResultsModal} 
      onHide={handleCloseAmassIntelResultsModal} 
      size="xl"
      dialogClassName="modal-90w"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Amass Intel Results - Network Ranges
          {amassIntelResults && (
            <span className="text-white fs-6 ms-3">
              Company: {amassIntelResults.company_name}
            </span>
          )}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {amassIntelResults && (
          <Row className="mb-3">
            <Col md={3}>
              <small className="text-white-50">Status:</small>
              <div className={`text-${getScanStatus() === 'success' ? 'success' : getScanStatus() === 'error' ? 'danger' : 'warning'}`}>
                {getScanStatus()}
              </div>
            </Col>
            <Col md={3}>
              <small className="text-white-50">Execution Time:</small>
              <div className="text-white">{getExecutionTime()}</div>
            </Col>
            <Col md={3}>
              <small className="text-white-50">Network Ranges:</small>
              <div className="text-danger fw-bold">{networkRanges.length}</div>
            </Col>
            <Col md={3}>
              <small className="text-white-50">ASN Records:</small>
              <div className="text-info fw-bold">{asnData.length}</div>
            </Col>
          </Row>
        )}

        {renderContent()}
      </Modal.Body>
    </Modal>
  );
};

export const AmassIntelHistoryModal = ({ 
  showAmassIntelHistoryModal, 
  handleCloseAmassIntelHistoryModal, 
  amassIntelScans 
}) => {
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusBadge = (status) => {
    const statusColors = {
      'success': 'success',
      'running': 'primary',
      'pending': 'warning',
      'error': 'danger'
    };
    return <span className={`badge bg-${statusColors[status] || 'secondary'}`}>{status}</span>;
  };

  return (
    <Modal 
      show={showAmassIntelHistoryModal} 
      onHide={handleCloseAmassIntelHistoryModal} 
      size="xl"
      className="text-white"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">Amass Intel Scan History - Network Discovery</Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark">
        {amassIntelScans && amassIntelScans.length > 0 ? (
          <Table striped bordered hover variant="dark" className="mb-0">
            <thead>
              <tr>
                <th>Company Name</th>
                <th>Status</th>
                <th>Execution Time</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {amassIntelScans.map((scan, index) => (
                <tr key={index}>
                  <td>{scan.company_name}</td>
                  <td>{getStatusBadge(scan.status)}</td>
                  <td>{scan.execution_time || 'N/A'}</td>
                  <td>{formatDate(scan.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <div className="text-center py-4">
            <p className="text-muted">No Amass Intel scans found.</p>
          </div>
        )}
      </Modal.Body>
    </Modal>
  );
}; 