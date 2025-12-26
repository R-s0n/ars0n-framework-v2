import { useState, useEffect } from 'react';
import { Modal, Button, Table, Badge, Spinner, Alert, Form, InputGroup } from 'react-bootstrap';

export const GAUURLResultsModal = ({ 
  show, 
  handleClose, 
  activeTarget, 
  mostRecentGAUURLScan 
}) => {
  const [urls, setUrls] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const [searchFilters, setSearchFilters] = useState([{ searchTerm: '', isNegative: false }]);
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });

  useEffect(() => {
    if (show && mostRecentGAUURLScan && mostRecentGAUURLScan.result) {
      parseResults();
    }
  }, [show, mostRecentGAUURLScan]);

  const parseResults = () => {
    setLoading(true);
    setError(null);

    try {
      if (!mostRecentGAUURLScan.result) {
        setUrls([]);
        setLoading(false);
        return;
      }

      const lines = mostRecentGAUURLScan.result.split('\n')
        .filter(line => line.trim())
        .map(line => line.trim())
        .filter(line => line.length > 0);

      const urlList = [];
      lines.forEach((line, index) => {
        try {
          const jsonData = JSON.parse(line);
          urlList.push({
            id: index,
            url: jsonData.url || line,
            domain: extractDomain(jsonData.url || line),
            path: extractPath(jsonData.url || line),
            timestamp: jsonData.timestamp || null,
            source: jsonData.source || 'unknown'
          });
        } catch {
          urlList.push({
            id: index,
            url: line,
            domain: extractDomain(line),
            path: extractPath(line),
            timestamp: null,
            source: 'unknown'
          });
        }
      });

      setUrls(urlList);
    } catch (error) {
      console.error('Error parsing GAU results:', error);
      setError('Failed to parse scan results');
    } finally {
      setLoading(false);
    }
  };

  const extractDomain = (url) => {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return url.split('/')[0] || url;
    }
  };

  const extractPath = (url) => {
    try {
      const urlObj = new URL(url);
      return urlObj.pathname + urlObj.search;
    } catch {
      const parts = url.split('/');
      return parts.length > 1 ? '/' + parts.slice(1).join('/') : '/';
    }
  };

  const getFilteredUrls = () => {
    const filtered = urls.filter(item => {
      const activeFilters = searchFilters.filter(filter => filter.searchTerm.trim() !== '');
      
      if (activeFilters.length > 0) {
        return activeFilters.every(filter => {
          const searchTerm = filter.searchTerm.toLowerCase();
          const itemContainsSearch = 
            (item.url && item.url.toLowerCase().includes(searchTerm)) ||
            (item.domain && item.domain.toLowerCase().includes(searchTerm)) ||
            (item.path && item.path.toLowerCase().includes(searchTerm)) ||
            (item.source && item.source.toLowerCase().includes(searchTerm));
          return filter.isNegative ? !itemContainsSearch : itemContainsSearch;
        });
      }
      
      return true;
    });

    return getSortedUrls(filtered);
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

  const getSortedUrls = (urlList) => {
    if (!sortConfig.key) return urlList;

    return [...urlList].sort((a, b) => {
      let aValue = a[sortConfig.key];
      let bValue = b[sortConfig.key];

      if (sortConfig.key === 'timestamp') {
        aValue = aValue || '';
        bValue = bValue || '';
      } else if (typeof aValue === 'string') {
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

  const getSourceBadge = (source) => {
    const sourceLower = (source || 'unknown').toLowerCase();
    if (sourceLower.includes('wayback')) {
      return <Badge bg="info">Wayback</Badge>;
    }
    if (sourceLower.includes('commoncrawl') || sourceLower.includes('common')) {
      return <Badge bg="success">CommonCrawl</Badge>;
    }
    if (sourceLower.includes('otx') || sourceLower.includes('alienvault')) {
      return <Badge bg="warning">OTX</Badge>;
    }
    return <Badge bg="secondary">{source || 'Unknown'}</Badge>;
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

    if (urls.length === 0) {
      return (
        <div className="text-center py-5">
          <div className="text-white-50 mb-3">
            <i className="bi bi-globe" style={{ fontSize: '3rem' }}></i>
          </div>
          <h5 className="text-white-50 mb-3">No URLs Found</h5>
          <p className="text-white-50">
            The scan completed but no URLs were discovered from AlienVault OTX, Wayback Machine, or Common Crawl.
          </p>
        </div>
      );
    }

    const filteredUrls = getFilteredUrls();

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
                  placeholder="Search URLs, domains, paths, or sources..."
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
            Showing {filteredUrls.length} of {urls.length} URLs
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
                    width: '35%', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => handleSort('url')}
                >
                  URL{getSortIcon('url')}
                </th>
                <th 
                  className="sortable-header"
                  style={{ 
                    backgroundColor: 'var(--bs-dark)', 
                    width: '25%', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => handleSort('domain')}
                >
                  Domain{getSortIcon('domain')}
                </th>
                <th 
                  className="sortable-header"
                  style={{ 
                    backgroundColor: 'var(--bs-dark)', 
                    width: '25%', 
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
                    width: '15%', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => handleSort('source')}
                >
                  Source{getSortIcon('source')}
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredUrls.map((item) => (
                <tr key={item.id}>
                  <td className="text-info" style={{ fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all' }}>
                    <a href={item.url} target="_blank" rel="noopener noreferrer" className="text-info text-decoration-none">
                      {item.url}
                    </a>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                    {item.domain}
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all' }}>
                    {item.path}
                  </td>
                  <td>
                    {getSourceBadge(item.source)}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>

        {filteredUrls.length === 0 && urls.length > 0 && (
          <div className="text-center py-4">
            <i className="bi bi-funnel text-white-50" style={{ fontSize: '2rem' }}></i>
            <h6 className="text-white-50 mt-2">No URLs match the current filters</h6>
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
          <i className="bi bi-globe me-2" />
          GAU URL Scan Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {mostRecentGAUURLScan && (
          <div className="mb-3">
            <div className="d-flex justify-content-between align-items-center">
              <div>
                <h6 className="text-white mb-1">
                  Latest Scan: {mostRecentGAUURLScan.scan_id?.substring(0, 8)}...
                </h6>
                <div className="text-white-50 small">
                  Status: <Badge className={`${
                    mostRecentGAUURLScan.status === 'success' ? 'bg-success' : 
                    mostRecentGAUURLScan.status === 'error' ? 'bg-danger' : 
                    'bg-warning'
                  }`}>
                    {mostRecentGAUURLScan.status}
                  </Badge>
                  {mostRecentGAUURLScan.created_at && (
                    <span className="ms-2">
                      • {new Date(mostRecentGAUURLScan.created_at).toLocaleString()}
                    </span>
                  )}
                  {mostRecentGAUURLScan.execution_time && (
                    <span className="ms-2">
                      • Duration: {mostRecentGAUURLScan.execution_time}
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

