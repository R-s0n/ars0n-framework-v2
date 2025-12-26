import { useState, useEffect } from 'react';
import { Modal, Button, Table, Badge, Spinner, Alert, Form, InputGroup } from 'react-bootstrap';

export const LinkFinderURLResultsModal = ({ 
  show, 
  handleClose, 
  activeTarget, 
  mostRecentLinkFinderURLScan 
}) => {
  const [endpoints, setEndpoints] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const [searchFilters, setSearchFilters] = useState([{ searchTerm: '', isNegative: false }]);
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });

  useEffect(() => {
    if (show && mostRecentLinkFinderURLScan && mostRecentLinkFinderURLScan.result) {
      parseResults();
    }
  }, [show, mostRecentLinkFinderURLScan]);

  const parseResults = () => {
    setLoading(true);
    setError(null);

    try {
      if (!mostRecentLinkFinderURLScan.result) {
        setEndpoints([]);
        setLoading(false);
        return;
      }

      const lines = mostRecentLinkFinderURLScan.result.split('\n')
        .filter(line => line.trim())
        .map(line => line.trim())
        .filter(line => line.length > 0);

      const endpointList = lines.map((line, index) => {
        const endpoint = {
          id: index,
          endpoint: line,
          url: extractURL(line),
          path: extractPath(line),
          parameters: extractParameters(line)
        };
        return endpoint;
      });

      setEndpoints(endpointList);
    } catch (error) {
      console.error('Error parsing LinkFinder results:', error);
      setError('Failed to parse scan results');
    } finally {
      setLoading(false);
    }
  };

  const extractURL = (line) => {
    if (line.startsWith('http://') || line.startsWith('https://')) {
      return line.split('?')[0];
    }
    return line;
  };

  const extractPath = (line) => {
    try {
      const urlObj = new URL(line);
      return urlObj.pathname;
    } catch {
      const parts = line.split('?')[0].split('/');
      return parts.length > 1 ? '/' + parts.slice(1).join('/') : '/';
    }
  };

  const extractParameters = (line) => {
    try {
      const urlObj = new URL(line);
      return urlObj.search;
    } catch {
      const parts = line.split('?');
      return parts.length > 1 ? '?' + parts[1] : '';
    }
  };

  const getFilteredEndpoints = () => {
    const filtered = endpoints.filter(item => {
      const activeFilters = searchFilters.filter(filter => filter.searchTerm.trim() !== '');
      
      if (activeFilters.length > 0) {
        return activeFilters.every(filter => {
          const searchTerm = filter.searchTerm.toLowerCase();
          const itemContainsSearch = 
            (item.endpoint && item.endpoint.toLowerCase().includes(searchTerm)) ||
            (item.url && item.url.toLowerCase().includes(searchTerm)) ||
            (item.path && item.path.toLowerCase().includes(searchTerm)) ||
            (item.parameters && item.parameters.toLowerCase().includes(searchTerm));
          return filter.isNegative ? !itemContainsSearch : itemContainsSearch;
        });
      }
      
      return true;
    });

    return getSortedEndpoints(filtered);
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

  const handleSort = (key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  const getSortedEndpoints = (endpointList) => {
    if (!sortConfig.key) return endpointList;

    return [...endpointList].sort((a, b) => {
      let aValue = a[sortConfig.key];
      let bValue = b[sortConfig.key];

      if (typeof aValue === 'string') {
        aValue = aValue.toLowerCase();
        bValue = bValue.toLowerCase();
      }

      if (aValue < bValue) {
        return sortConfig.direction === 'asc' ? -1 : 1;
      }
      if (aValue > bValue) {
        return sortConfig.direction === 'asc' ? 1 : -1;
      }
      return 0;
    });
  };

  const getSortIcon = (columnKey) => {
    if (sortConfig.key !== columnKey) {
      return <i className="bi bi-arrow-down-up text-white-50 ms-1" style={{ fontSize: '0.8rem' }}></i>;
    }
    return sortConfig.direction === 'asc' 
      ? <i className="bi bi-arrow-up text-white ms-1" style={{ fontSize: '0.8rem' }}></i>
      : <i className="bi bi-arrow-down text-white ms-1" style={{ fontSize: '0.8rem' }}></i>;
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

    if (endpoints.length === 0) {
      return (
        <div className="text-center py-5">
          <div className="text-white-50 mb-3">
            <i className="bi bi-code-slash" style={{ fontSize: '3rem' }}></i>
          </div>
          <h5 className="text-white-50 mb-3">No Endpoints Found</h5>
          <p className="text-white-50">
            The scan completed but no endpoints were discovered in JavaScript files.
          </p>
        </div>
      );
    }

    const filteredEndpoints = getFilteredEndpoints();

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
                  placeholder="Search endpoints, URLs, paths, or parameters..."
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

        <div className="mb-3">
          <small className="text-white-50">
            Showing {filteredEndpoints.length} of {endpoints.length} endpoints
          </small>
        </div>

        <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
          <style>
            {`
              .sortable-header:hover {
                background-color: rgba(220, 53, 69, 0.2) !important;
                transition: background-color 0.15s ease-in-out;
              }
            `}
          </style>
          <Table variant="dark" hover size="sm" style={{ tableLayout: 'fixed', width: '100%' }}>
            <thead style={{ position: 'sticky', top: 0, zIndex: 10 }}>
              <tr>
                <th 
                  className="sortable-header"
                  style={{ 
                    backgroundColor: 'var(--bs-dark)', 
                    width: '50%', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => handleSort('endpoint')}
                >
                  Endpoint{getSortIcon('endpoint')}
                </th>
                <th 
                  className="sortable-header"
                  style={{ 
                    backgroundColor: 'var(--bs-dark)', 
                    width: '30%', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => handleSort('path')}
                >
                  Path{getSortIcon('path')}
                </th>
                <th 
                  className="sortable-header"
                  style={{ 
                    backgroundColor: 'var(--bs-dark)', 
                    width: '20%', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => handleSort('parameters')}
                >
                  Parameters{getSortIcon('parameters')}
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredEndpoints.map((item) => (
                <tr key={item.id}>
                  <td className="text-info" style={{ fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all' }}>
                    {item.endpoint}
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all' }}>
                    {item.path}
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all' }}>
                    {item.parameters || '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>

        {filteredEndpoints.length === 0 && endpoints.length > 0 && (
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

  return (
    <Modal 
      show={show} 
      onHide={handleClose} 
      size="xl" 
      data-bs-theme="dark"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-code-slash me-2" />
          LinkFinder URL Scan Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {mostRecentLinkFinderURLScan && (
          <div className="mb-3">
            <div className="d-flex justify-content-between align-items-center">
              <div>
                <h6 className="text-white mb-1">
                  Latest Scan: {mostRecentLinkFinderURLScan.scan_id?.substring(0, 8)}...
                </h6>
                <div className="text-white-50 small">
                  Status: <Badge className={`${
                    mostRecentLinkFinderURLScan.status === 'success' ? 'bg-success' : 
                    mostRecentLinkFinderURLScan.status === 'error' ? 'bg-danger' : 
                    'bg-warning'
                  }`}>
                    {mostRecentLinkFinderURLScan.status}
                  </Badge>
                  {mostRecentLinkFinderURLScan.created_at && (
                    <span className="ms-2">
                      • {new Date(mostRecentLinkFinderURLScan.created_at).toLocaleString()}
                    </span>
                  )}
                  {mostRecentLinkFinderURLScan.execution_time && (
                    <span className="ms-2">
                      • Duration: {mostRecentLinkFinderURLScan.execution_time}
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

