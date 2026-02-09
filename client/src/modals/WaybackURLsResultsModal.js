import { useState, useEffect } from 'react';
import { Modal, Button, Table, Badge, Spinner, Alert, Form, InputGroup, Tabs, Tab, Accordion } from 'react-bootstrap';

export const WaybackURLsResultsModal = ({ 
  show, 
  handleClose, 
  activeTarget, 
  mostRecentWaybackURLsScan 
}) => {
  const [directEndpoints, setDirectEndpoints] = useState([]);
  const [adjacentEndpoints, setAdjacentEndpoints] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const [searchFilters, setSearchFilters] = useState([{ searchTerm: '', isNegative: false }]);
  const [activeTab, setActiveTab] = useState('direct');

  useEffect(() => {
    if (show && mostRecentWaybackURLsScan && mostRecentWaybackURLsScan.scan_id) {
      parseResults();
    }
  }, [show, mostRecentWaybackURLsScan]);

  const parseResults = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/discovered-endpoints/${mostRecentWaybackURLsScan.scan_id}?scan_type=waybackurls`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch endpoints');
      }

      const endpoints = await response.json();
      
      const direct = endpoints.filter(ep => ep.is_direct);
      const adjacent = endpoints.filter(ep => !ep.is_direct);
      
      setDirectEndpoints(direct);
      setAdjacentEndpoints(adjacent);
    } catch (error) {
      console.error('Error parsing WaybackURLs results:', error);
      setError('Failed to parse scan results');
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadgeColor = (statusCode) => {
    if (!statusCode) return 'secondary';
    if (statusCode >= 200 && statusCode < 300) return 'success';
    if (statusCode >= 300 && statusCode < 400) return 'info';
    if (statusCode >= 400 && statusCode < 500) return 'warning';
    if (statusCode >= 500) return 'danger';
    return 'secondary';
  };

  const getFilteredEndpoints = (endpoints) => {
    const filtered = endpoints.filter(item => {
      const activeFilters = searchFilters.filter(filter => filter.searchTerm.trim() !== '');
      
      if (activeFilters.length > 0) {
        return activeFilters.every(filter => {
          const searchTerm = filter.searchTerm.toLowerCase();
          const itemContainsSearch = 
            (item.url && item.url.toLowerCase().includes(searchTerm)) ||
            (item.domain && item.domain.toLowerCase().includes(searchTerm)) ||
            (item.path && item.path.toLowerCase().includes(searchTerm)) ||
            (item.normalized_path && item.normalized_path.toLowerCase().includes(searchTerm));
          return filter.isNegative ? !itemContainsSearch : itemContainsSearch;
        });
      }
      
      return true;
    });

    return filtered;
  };

  const addSearchFilter = () => {
    setSearchFilters([...searchFilters, { searchTerm: '', isNegative: false }]);
  };

  const removeSearchFilter = (index) => {
    if (searchFilters.length > 1) {
      const newFilters = searchFilters.filter((_, i) => i !== index);
      setSearchFilters(newFilters);
    }
  };

  const updateSearchFilter = (index, field, value) => {
    const newFilters = [...searchFilters];
    newFilters[index][field] = value;
    setSearchFilters(newFilters);
  };

  const clearFilters = () => {
    setSearchFilters([{ searchTerm: '', isNegative: false }]);
  };

  const renderEndpoints = (endpoints) => {
    if (endpoints.length === 0) {
      return (
        <div className="text-center py-5">
          <div className="text-white-50 mb-3">
            <i className="bi bi-clock-history" style={{ fontSize: '3rem' }}></i>
          </div>
          <h5 className="text-white-50 mb-3">No Endpoints Found</h5>
        </div>
      );
    }

    const filtered = getFilteredEndpoints(endpoints);

    return (
      <>
        <div className="mb-3">
          <small className="text-white-50">
            Showing {filtered.length} of {endpoints.length} endpoints
          </small>
        </div>

        <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
          <Accordion>
            {filtered.map((endpoint, index) => (
              <Accordion.Item eventKey={index.toString()} key={endpoint.id}>
                <Accordion.Header>
                  <div className="d-flex justify-content-between align-items-center w-100 me-3">
                    <span className="text-info" style={{ fontFamily: 'monospace', fontSize: '0.9rem', flex: 1, wordBreak: 'break-all' }}>
                      {endpoint.url}
                    </span>
                    {endpoint.status_code && (
                      <Badge bg={getStatusBadgeColor(endpoint.status_code)} className="ms-2">
                        {endpoint.status_code}
                      </Badge>
                    )}
                  </div>
                </Accordion.Header>
                <Accordion.Body>
                  <Table size="sm" variant="dark" className="mb-0">
                    <tbody>
                      <tr>
                        <td width="20%"><strong>Domain:</strong></td>
                        <td>{endpoint.domain}</td>
                      </tr>
                      <tr>
                        <td><strong>Path:</strong></td>
                        <td style={{ fontFamily: 'monospace' }}>{endpoint.path}</td>
                      </tr>
                      <tr>
                        <td><strong>Normalized:</strong></td>
                        <td style={{ fontFamily: 'monospace' }}>{endpoint.normalized_path}</td>
                      </tr>
                    </tbody>
                  </Table>
                  
                  {endpoint.parameters && endpoint.parameters.length > 0 && (
                    <>
                      <h6 className="mt-3 mb-2 text-white">Parameters:</h6>
                      <Table size="sm" variant="dark" striped>
                        <thead>
                          <tr>
                            <th width="20%">Type</th>
                            <th width="30%">Name</th>
                            <th>Example Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {endpoint.parameters.map((param, idx) => (
                            <tr key={idx}>
                              <td>
                                <Badge bg={param.type === 'query' ? 'info' : 'warning'}>
                                  {param.type}
                                </Badge>
                              </td>
                              <td><code>{param.name}</code></td>
                              <td><code>{param.example_value || 'N/A'}</code></td>
                            </tr>
                          ))}
                        </tbody>
                      </Table>
                    </>
                  )}
                </Accordion.Body>
              </Accordion.Item>
            ))}
          </Accordion>
        </div>

        {filtered.length === 0 && endpoints.length > 0 && (
          <div className="text-center py-4">
            <i className="bi bi-funnel text-white-50" style={{ fontSize: '2rem' }}></i>
            <h6 className="text-white-50 mt-2">No endpoints match the current filters</h6>
            <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
              Clear Filters
            </Button>
          </div>
        )}
      </>
    );
  };

  const renderResults = () => {
    if (loading) {
      return (
        <div className="text-center py-4">
          <Spinner animation="border" role="status" variant="danger">
            <span className="visually-hidden">Loading...</span>
          </Spinner>
        </div>
      );
    }

    if (error) {
      return (
        <Alert variant="danger">
          {error}
        </Alert>
      );
    }

    return (
      <>
        <div className="mb-3">
          <div className="d-flex justify-content-between align-items-center mb-2">
            <Form.Label className="text-white small mb-0">Search Filters</Form.Label>
            <div>
              <Button 
                variant="outline-success" 
                size="sm" 
                onClick={addSearchFilter}
                className="me-2"
              >
                Add Filter
              </Button>
              <Button 
                variant="outline-danger" 
                size="sm" 
                onClick={clearFilters}
              >
                Clear Filters
              </Button>
            </div>
          </div>
          {searchFilters.map((filter, index) => (
            <div key={index} className="mb-2">
              <InputGroup size="sm">
                <Form.Select
                  value={filter.isNegative ? 'negative' : 'positive'}
                  onChange={(e) => updateSearchFilter(index, 'isNegative', e.target.value === 'negative')}
                  style={{ maxWidth: '120px' }}
                  data-bs-theme="dark"
                >
                  <option value="positive">Contains</option>
                  <option value="negative">Excludes</option>
                </Form.Select>
                <Form.Control
                  type="text"
                  placeholder="Search URLs, domains, or paths..."
                  value={filter.searchTerm}
                  onChange={(e) => updateSearchFilter(index, 'searchTerm', e.target.value)}
                  data-bs-theme="dark"
                />
                {searchFilters.length > 1 && (
                  <Button 
                    variant="outline-danger" 
                    size="sm"
                    onClick={() => removeSearchFilter(index)}
                  >
                    ×
                  </Button>
                )}
              </InputGroup>
            </div>
          ))}
        </div>

        <Tabs activeKey={activeTab} onSelect={(k) => setActiveTab(k)} className="mb-3">
          <Tab eventKey="direct" title={`Direct (${directEndpoints.length})`}>
            {renderEndpoints(directEndpoints)}
          </Tab>
          <Tab eventKey="adjacent" title={`Adjacent (${adjacentEndpoints.length})`}>
            {renderEndpoints(adjacentEndpoints)}
          </Tab>
        </Tabs>
      </>
    );
  };

  return (
    <Modal 
      show={show} 
      onHide={handleClose} 
      size="xl" 
      data-bs-theme="dark"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-clock-history me-2" />
          WaybackURLs Scan Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {mostRecentWaybackURLsScan && (
          <div className="mb-3">
            <div className="d-flex justify-content-between align-items-center">
              <div>
                <h6 className="text-white mb-1">
                  Latest Scan: {mostRecentWaybackURLsScan.scan_id?.substring(0, 8)}...
                </h6>
                <div className="text-white-50 small">
                  Status: <Badge className={`${
                    mostRecentWaybackURLsScan.status === 'success' ? 'bg-success' : 
                    mostRecentWaybackURLsScan.status === 'error' ? 'bg-danger' : 
                    'bg-warning'
                  }`}>
                    {mostRecentWaybackURLsScan.status}
                  </Badge>
                  {mostRecentWaybackURLsScan.created_at && (
                    <span className="ms-2">
                      • {new Date(mostRecentWaybackURLsScan.created_at).toLocaleString()}
                    </span>
                  )}
                  {mostRecentWaybackURLsScan.execution_time && (
                    <span className="ms-2">
                      • Duration: {mostRecentWaybackURLsScan.execution_time}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {renderResults()}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};
