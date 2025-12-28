import { Modal, Table, Form, Row, Col, Button, Pagination, OverlayTrigger, Tooltip } from 'react-bootstrap';
import { useState, useEffect, useMemo } from 'react';

export const HttpxResultsModal = ({ showHttpxResultsModal, handleCloseHttpxResultsModal, httpxResults }) => {
  const [sortColumn, setSortColumn] = useState('');
  const [sortDirection, setSortDirection] = useState('asc');
  const [filters, setFilters] = useState({
    url: '',
    statusCode: '',
    title: '',
    webServer: '',
    technologies: '',
    contentLength: ''
  });
  const [addingUrls, setAddingUrls] = useState(new Set());
  const [existingScopeTargets, setExistingScopeTargets] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(25);

  const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8443';

  useEffect(() => {
    if (showHttpxResultsModal) {
      fetchExistingScopeTargets();
    }
  }, [showHttpxResultsModal]);

  useEffect(() => {
    setCurrentPage(1);
  }, [filters, sortColumn, sortDirection]);

  const fetchExistingScopeTargets = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/scopetarget/read`);
      if (response.ok) {
        const data = await response.json();
        setExistingScopeTargets(data);
      }
    } catch (error) {
      console.error('HttpxResultsModal: Error fetching scope targets:', error);
    }
  };

  const isUrlAlreadyScopeTarget = (url) => {
    return existingScopeTargets.some(
      target => target.type === 'URL' && target.scope_target === url
    );
  };

  const handleAddAsScopeTarget = async (result) => {
    if (addingUrls.has(result.url)) return;
    
    setAddingUrls(prev => new Set(prev).add(result.url));
    
    try {
      const payload = {
        type: 'URL',
        mode: 'Passive',
        scope_target: result.url,
        active: false,
      };
      
      const response = await fetch(`${API_BASE_URL}/scopetarget/add`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to add URL as scope target: ${response.status} - ${errorText}`);
      }
      
      await fetchExistingScopeTargets();
    } catch (error) {
      alert(`Failed to add ${result.url} as scope target: ${error.message}`);
    } finally {
      setAddingUrls(prev => {
        const newSet = new Set(prev);
        newSet.delete(result.url);
        return newSet;
      });
    }
  };

  const handleFilterChange = (filterKey, value) => {
    setFilters(prev => ({
      ...prev,
      [filterKey]: value
    }));
  };

  const clearFilters = () => {
    setFilters({
      url: '',
      statusCode: '',
      title: '',
      webServer: '',
      technologies: '',
      contentLength: ''
    });
  };

  const handleSort = (column) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const renderSortIcon = (column) => {
    if (sortColumn !== column) {
      return <i className="bi bi-arrow-down-up text-muted ms-1"></i>;
    }
    return sortDirection === 'asc' ? 
      <i className="bi bi-arrow-up text-primary ms-1"></i> : 
      <i className="bi bi-arrow-down text-primary ms-1"></i>;
  };

  const parseResults = (results) => {
    if (!results) {
      return [];
    }

    // Handle the new response format where result is nested in a String property
    const scanResults = results.result?.String;
    if (!scanResults) {
      return [];
    }

    try {
      const parsed = scanResults
        .split('\n')
        .filter(line => line.trim())
        .map(line => {
          try {
            return JSON.parse(line);
          } catch (e) {
            console.error("[ERROR] Failed to parse line:", line, e);
            return null;
          }
        })
        .filter(result => result !== null);
      
      return parsed;
    } catch (error) {
      console.error("[ERROR] Error parsing httpx results:", error);
      return [];
    }
  };

  const getStatusStyle = (status) => {
    const styles = {
      backgroundColor: '#FFFFFF', // Default white
      color: '#000000',          // Default black text
      padding: '0.2em 0.5em',    // Smaller padding
      fontSize: '0.85em',        // Slightly smaller font
      fontWeight: '700',
      lineHeight: '1',
      textAlign: 'center',
      whiteSpace: 'nowrap',
      verticalAlign: 'baseline',
      borderRadius: '0.25rem',   // Slightly smaller border radius
      display: 'inline-block'
    };

    switch (status) {
      case 200:
        styles.backgroundColor = '#32CD32'; // Lime Green
        styles.color = '#000000';
        break;
      case 301:
        styles.backgroundColor = '#87CEEB'; // Sky Blue
        styles.color = '#000000';
        break;
      case 302:
        styles.backgroundColor = '#1E90FF'; // Dodger Blue
        styles.color = '#000000';
        break;
      case 304:
        styles.backgroundColor = '#E6E6FA'; // Light Purple
        styles.color = '#000000';
        break;
      case 400:
        styles.backgroundColor = '#FF0000'; // Bright Red
        styles.color = '#FFFFFF';
        break;
      case 401:
        styles.backgroundColor = '#FF7F50'; // Coral
        styles.color = '#FFFFFF';
        break;
      case 403:
        styles.backgroundColor = '#8B0000'; // Dark Red
        styles.color = '#FFFFFF';
        break;
      case 404:
        styles.backgroundColor = '#FFDAB9'; // Peach
        styles.color = '#000000';
        break;
      case 418:
        styles.backgroundColor = '#FF69B4'; // Hot Pink
        styles.color = '#FFFFFF';
        break;
      case 500:
        styles.backgroundColor = '#DAA520'; // Dark Yellow
        styles.color = '#FFFFFF';
        break;
      case 503:
        styles.backgroundColor = '#FF4500'; // Pumpkin Orange
        styles.color = '#FFFFFF';
        break;
      default:
        styles.backgroundColor = '#FFFFFF'; // White
        styles.color = '#000000';
        break;
    }

    return styles;
  };

  const parsedResults = parseResults(httpxResults);

  const filteredAndSortedResults = useMemo(() => {
    let filtered = parsedResults.filter(result => {
      if (filters.url && !result.url?.toLowerCase().includes(filters.url.toLowerCase())) {
        return false;
      }
      
      if (filters.statusCode) {
        const statusCode = result.status_code;
        if (filters.statusCode === '2xx' && (statusCode < 200 || statusCode >= 300)) return false;
        if (filters.statusCode === '3xx' && (statusCode < 300 || statusCode >= 400)) return false;
        if (filters.statusCode === '4xx' && (statusCode < 400 || statusCode >= 500)) return false;
        if (filters.statusCode === '5xx' && (statusCode < 500 || statusCode >= 600)) return false;
        if (filters.statusCode === 'no_response' && statusCode) return false;
      }
      
      if (filters.title && !result.title?.toLowerCase().includes(filters.title.toLowerCase())) {
        return false;
      }
      
      if (filters.webServer && !result.webserver?.toLowerCase().includes(filters.webServer.toLowerCase())) {
        return false;
      }
      
      if (filters.technologies) {
        const techString = result.tech ? result.tech.join(' ') : '';
        if (!techString.toLowerCase().includes(filters.technologies.toLowerCase())) {
          return false;
        }
      }
      
      if (filters.contentLength) {
        const contentLength = result.content_length || 0;
        if (filters.contentLength === 'small' && contentLength >= 10000) return false;
        if (filters.contentLength === 'medium' && (contentLength < 10000 || contentLength >= 100000)) return false;
        if (filters.contentLength === 'large' && contentLength < 100000) return false;
      }
      
      return true;
    });

    if (!sortColumn) return filtered;

    return filtered.sort((a, b) => {
      let valueA, valueB;

      switch (sortColumn) {
        case 'url':
          valueA = a.url || '';
          valueB = b.url || '';
          break;
        case 'statusCode':
          valueA = a.status_code || 0;
          valueB = b.status_code || 0;
          break;
        case 'title':
          valueA = a.title || '';
          valueB = b.title || '';
          break;
        case 'webServer':
          valueA = a.webserver || '';
          valueB = b.webserver || '';
          break;
        case 'contentLength':
          valueA = a.content_length || 0;
          valueB = b.content_length || 0;
          break;
        default:
          return 0;
      }

      if (valueA < valueB) return sortDirection === 'asc' ? -1 : 1;
      if (valueA > valueB) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }, [parsedResults, filters, sortColumn, sortDirection]);

  const totalPages = Math.ceil(filteredAndSortedResults.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedResults = filteredAndSortedResults.slice(startIndex, endIndex);

  const handlePageChange = (pageNumber) => {
    setCurrentPage(pageNumber);
  };

  const renderPagination = () => {
    if (totalPages <= 1) return null;

    const items = [];
    const maxPagesToShow = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxPagesToShow / 2));
    let endPage = Math.min(totalPages, startPage + maxPagesToShow - 1);

    if (endPage - startPage + 1 < maxPagesToShow) {
      startPage = Math.max(1, endPage - maxPagesToShow + 1);
    }

    items.push(
      <Pagination.First key="first" onClick={() => handlePageChange(1)} disabled={currentPage === 1} />
    );
    items.push(
      <Pagination.Prev key="prev" onClick={() => handlePageChange(currentPage - 1)} disabled={currentPage === 1} />
    );

    if (startPage > 1) {
      items.push(<Pagination.Ellipsis key="ellipsis-start" disabled />);
    }

    for (let page = startPage; page <= endPage; page++) {
      items.push(
        <Pagination.Item
          key={page}
          active={page === currentPage}
          onClick={() => handlePageChange(page)}
        >
          {page}
        </Pagination.Item>
      );
    }

    if (endPage < totalPages) {
      items.push(<Pagination.Ellipsis key="ellipsis-end" disabled />);
    }

    items.push(
      <Pagination.Next key="next" onClick={() => handlePageChange(currentPage + 1)} disabled={currentPage === totalPages} />
    );
    items.push(
      <Pagination.Last key="last" onClick={() => handlePageChange(totalPages)} disabled={currentPage === totalPages} />
    );

    return <Pagination>{items}</Pagination>;
  };

  return (
    <Modal data-bs-theme="dark" show={showHttpxResultsModal} onHide={handleCloseHttpxResultsModal} fullscreen>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Live Web Servers</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {filteredAndSortedResults.length > 0 && (
          <div className="mb-4">
            <Row className="mb-3">
              <Col md={4}>
                <Form.Label>Filter by URL</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Search URL..."
                  value={filters.url}
                  onChange={(e) => handleFilterChange('url', e.target.value)}
                />
              </Col>
              <Col md={2}>
                <Form.Label>Status Code</Form.Label>
                <Form.Select
                  value={filters.statusCode}
                  onChange={(e) => handleFilterChange('statusCode', e.target.value)}
                >
                  <option value="">All</option>
                  <option value="2xx">2xx (Success)</option>
                  <option value="3xx">3xx (Redirect)</option>
                  <option value="4xx">4xx (Client Error)</option>
                  <option value="5xx">5xx (Server Error)</option>
                  <option value="no_response">No Response</option>
                </Form.Select>
              </Col>
              <Col md={3}>
                <Form.Label>Filter by Title</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Search title..."
                  value={filters.title}
                  onChange={(e) => handleFilterChange('title', e.target.value)}
                />
              </Col>
              <Col md={3}>
                <Form.Label>Web Server</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Search web server..."
                  value={filters.webServer}
                  onChange={(e) => handleFilterChange('webServer', e.target.value)}
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={4}>
                <Form.Label>Technologies</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Search technologies..."
                  value={filters.technologies}
                  onChange={(e) => handleFilterChange('technologies', e.target.value)}
                />
              </Col>
              <Col md={3}>
                <Form.Label>Content Length</Form.Label>
                <Form.Select
                  value={filters.contentLength}
                  onChange={(e) => handleFilterChange('contentLength', e.target.value)}
                >
                  <option value="">All</option>
                  <option value="small">Small (&lt; 10KB)</option>
                  <option value="medium">Medium (10KB - 100KB)</option>
                  <option value="large">Large (&gt; 100KB)</option>
                </Form.Select>
              </Col>
              <Col md={3} className="d-flex align-items-end">
                <Button variant="outline-secondary" onClick={clearFilters} className="w-100">
                  Clear Filters
                </Button>
              </Col>
            </Row>
            <div className="mb-3">
              <div className="d-flex align-items-center gap-3 flex-wrap">
                <span className="text-muted">Sort by:</span>
                <Button
                  variant="link"
                  className="p-0 text-white text-decoration-none"
                  onClick={() => handleSort('url')}
                >
                  URL {renderSortIcon('url')}
                </Button>
                <Button
                  variant="link"
                  className="p-0 text-white text-decoration-none"
                  onClick={() => handleSort('statusCode')}
                >
                  Status Code {renderSortIcon('statusCode')}
                </Button>
                <Button
                  variant="link"
                  className="p-0 text-white text-decoration-none"
                  onClick={() => handleSort('title')}
                >
                  Title {renderSortIcon('title')}
                </Button>
                <Button
                  variant="link"
                  className="p-0 text-white text-decoration-none"
                  onClick={() => handleSort('webServer')}
                >
                  Web Server {renderSortIcon('webServer')}
                </Button>
                <Button
                  variant="link"
                  className="p-0 text-white text-decoration-none"
                  onClick={() => handleSort('contentLength')}
                >
                  Content Length {renderSortIcon('contentLength')}
                </Button>
              </div>
            </div>
            <div className="mb-2 d-flex justify-content-between align-items-center">
              <small className="text-muted">
                Showing {startIndex + 1}-{Math.min(endIndex, filteredAndSortedResults.length)} of {filteredAndSortedResults.length} filtered results
                {filteredAndSortedResults.length !== parsedResults.length && 
                  ` (${parsedResults.length} total)`
                }
              </small>
              {totalPages > 1 && (
                <small className="text-muted">
                  Page {currentPage} of {totalPages}
                </small>
              )}
            </div>
          </div>
        )}
        {filteredAndSortedResults.length === 0 ? (
          <div className="text-center py-4 text-white-50">
            {parsedResults.length > 0 
              ? 'No results match the current filters' 
              : 'No live web servers found.'}
          </div>
        ) : (
          <>
            <Table striped bordered hover responsive>
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Status Code</th>
                  <th>Title</th>
                  <th>Web Server</th>
                  <th>Technologies</th>
                  <th>Content Length</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedResults.map((result, index) => (
                  <tr key={index}>
                    <td>
                      <a 
                        href={result.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-danger text-decoration-none"
                      >
                        {result.url}
                      </a>
                    </td>
                    <td>
                      <span style={getStatusStyle(result.status_code)}>
                        {result.status_code}
                      </span>
                    </td>
                    <td>{result.title || '-'}</td>
                    <td>{result.webserver || '-'}</td>
                    <td>
                      {result.tech ? (
                        <div className="d-flex flex-wrap gap-1">
                          {result.tech.map((tech, i) => (
                            <span 
                              key={i} 
                              style={{
                                backgroundColor: '#6c757d',
                                color: '#fff',
                                padding: '0.2em 0.5em',
                                fontWeight: '700',
                                lineHeight: '1',
                                textAlign: 'center',
                                whiteSpace: 'nowrap',
                                verticalAlign: 'baseline',
                                borderRadius: '0.25rem',
                                display: 'inline-block'
                              }}
                            >
                              {tech}
                            </span>
                          ))}
                        </div>
                      ) : '-'}
                    </td>
                    <td>{result.content_length || '-'}</td>
                    <td>
                      {isUrlAlreadyScopeTarget(result.url) ? (
                        <OverlayTrigger
                          placement="top"
                          overlay={<Tooltip>Already added as URL Scope Target</Tooltip>}
                        >
                          <Button
                            variant="outline-secondary"
                            size="sm"
                            disabled
                          >
                            <i className="bi bi-check-circle"></i>
                          </Button>
                        </OverlayTrigger>
                      ) : (
                        <OverlayTrigger
                          placement="top"
                          overlay={<Tooltip>Add as URL Scope Target</Tooltip>}
                        >
                          <Button
                            variant="outline-success"
                            size="sm"
                            onClick={() => handleAddAsScopeTarget(result)}
                            disabled={addingUrls.has(result.url)}
                          >
                            {addingUrls.has(result.url) ? (
                              <i className="bi bi-hourglass-split"></i>
                            ) : (
                              <i className="bi bi-plus-circle"></i>
                            )}
                          </Button>
                        </OverlayTrigger>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            {filteredAndSortedResults.length > 0 && (
              <div className="d-flex justify-content-center mt-4">
                {renderPagination()}
              </div>
            )}
          </>
        )}
      </Modal.Body>
    </Modal>
  );
}; 