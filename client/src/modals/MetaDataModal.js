import { Modal, Badge, Accordion, Form, Row, Col, Button, OverlayTrigger, Tooltip, Pagination, Spinner } from 'react-bootstrap';
import { useEffect, useState, useMemo, memo } from 'react';

const MetaDataModal = memo(({
  showMetaDataModal,
  handleCloseMetaDataModal,
  targetURLs = [],
  setTargetURLs,
  fetchScopeTargets
}) => {
  const [sortColumn, setSortColumn] = useState('');
  const [sortDirection, setSortDirection] = useState('asc');
  const [filters, setFilters] = useState({
    url: '',
    statusCode: '',
    sslIssues: '',
    webServer: '',
    technologies: '',
    contentLength: ''
  });
  const [addingUrls, setAddingUrls] = useState(new Set());
  const [deletingUrls, setDeletingUrls] = useState(new Set());
  const [existingScopeTargets, setExistingScopeTargets] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(25);
  const [isLoading, setIsLoading] = useState(true);
  const [lightboxImage, setLightboxImage] = useState(null);

  useEffect(() => {
    const handleMetadataScanComplete = (event) => {
      setTargetURLs(event.detail);
    };

    window.addEventListener('metadataScanComplete', handleMetadataScanComplete);

    return () => {
      window.removeEventListener('metadataScanComplete', handleMetadataScanComplete);
    };
  }, [setTargetURLs]);

  useEffect(() => {
    if (showMetaDataModal) {
      setIsLoading(true);
      fetchExistingScopeTargets();
    } else {
      setIsLoading(true);
      setCurrentPage(1);
    }
  }, [showMetaDataModal]);

  useEffect(() => {
    if (showMetaDataModal && Array.isArray(targetURLs) && targetURLs.length > 0) {
      requestAnimationFrame(() => {
        setIsLoading(false);
      });
    }
  }, [showMetaDataModal, targetURLs]);

  useEffect(() => {
    setCurrentPage(1);
  }, [filters, sortColumn, sortDirection]);

  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === 'Escape' && lightboxImage) {
        setLightboxImage(null);
      }
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [lightboxImage]);

  const fetchExistingScopeTargets = async () => {
    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/read`);
      if (response.ok) {
        const data = await response.json();
        setExistingScopeTargets(data);
      }
    } catch (error) {
    }
  };

  const isUrlAlreadyScopeTarget = (url) => {
    return existingScopeTargets.some(
      target => target.type === 'URL' && target.scope_target === url
    );
  };

  const getStatusCodeColor = (statusCode) => {
    if (!statusCode) return { bg: 'secondary', text: 'white' };
    if (statusCode >= 200 && statusCode < 300) return { bg: 'success', text: 'dark' };
    if (statusCode >= 300 && statusCode < 400) return { bg: 'info', text: 'dark' };
    if (statusCode === 401 || statusCode === 403) return { bg: 'danger', text: 'white' };
    if (statusCode >= 400 && statusCode < 500) return { bg: 'warning', text: 'dark' };
    if (statusCode >= 500) return { bg: 'danger', text: 'white' };
    return { bg: 'secondary', text: 'white' };
  };

  const getSafeValue = (value) => {
    if (!value) return '';
    if (typeof value === 'object' && 'String' in value) {
      return value.String || '';
    }
    return value;
  };

  const getSSLIssues = (url) => {
    const sslIssues = [];
    if (url.has_deprecated_tls) sslIssues.push('Deprecated TLS');
    if (url.has_expired_ssl) sslIssues.push('Expired SSL');
    if (url.has_mismatched_ssl) sslIssues.push('Mismatched SSL');
    if (url.has_revoked_ssl) sslIssues.push('Revoked SSL');
    if (url.has_self_signed_ssl) sslIssues.push('Self-Signed SSL');
    if (url.has_untrusted_root_ssl) sslIssues.push('Untrusted Root');
    return sslIssues;
  };

  const getSSLIssuesCount = (url) => {
    return getSSLIssues(url).length;
  };

  const hasSSLIssue = (url, issueType) => {
    const sslIssues = getSSLIssues(url);
    if (issueType === 'has_issues') return sslIssues.length > 0;
    if (issueType === 'no_issues') return sslIssues.length === 0;
    return sslIssues.includes(issueType);
  };

  const getKatanaUrlsCount = (url) => {
    if (!url.katana_results) return 0;
    if (Array.isArray(url.katana_results)) return url.katana_results.length;
    if (typeof url.katana_results === 'string') {
      try {
        const parsed = JSON.parse(url.katana_results);
        return Array.isArray(parsed) ? parsed.length : 0;
      } catch {
        return 0;
      }
    }
    return 0;
  };

  const getFfufEndpointsCount = (url) => {
    if (!url.ffuf_results) return 0;
    if (typeof url.ffuf_results === 'object' && url.ffuf_results.endpoints) {
      return url.ffuf_results.endpoints.length;
    }
    if (typeof url.ffuf_results === 'string') {
      try {
        const parsed = JSON.parse(url.ffuf_results);
        return parsed.endpoints ? parsed.endpoints.length : 0;
      } catch {
        return 0;
      }
    }
    return 0;
  };

  const getTechnologiesCount = (url) => {
    if (url.technologies && Array.isArray(url.technologies)) {
      return url.technologies.length;
    }
    const findings = Array.isArray(url.findings_json) ? url.findings_json : [];
    return findings.length;
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
      sslIssues: '',
      webServer: '',
      technologies: '',
      contentLength: ''
    });
  };

  const handleDeleteUrl = async (urlId) => {
    if (deletingUrls.has(urlId)) return;
    
    setDeletingUrls(prev => new Set(prev).add(urlId));
    
    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/target-urls/${urlId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete URL from database');
      }

      const updatedUrls = targetURLs.filter(url => url.id !== urlId);
      setTargetURLs(updatedUrls);
    } catch (error) {
      alert(`Failed to delete URL: ${error.message}`);
    } finally {
      setDeletingUrls(prev => {
        const newSet = new Set(prev);
        newSet.delete(urlId);
        return newSet;
      });
    }
  };

  const handleAddAsScopeTarget = async (url) => {
    if (addingUrls.has(url.id)) return;
    
    setAddingUrls(prev => new Set(prev).add(url.id));
    
    try {
      const payload = {
        type: 'URL',
        mode: 'Passive',
        scope_target: url.url,
        active: false,
      };
      
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/add`, {
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
      
      if (fetchScopeTargets) {
        await fetchScopeTargets();
      }
    } catch (error) {
      alert(`Failed to add ${url.url} as scope target: ${error.message}`);
    } finally {
      setAddingUrls(prev => {
        const newSet = new Set(prev);
        newSet.delete(url.id);
        return newSet;
      });
    }
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

  const filteredAndSortedUrls = useMemo(() => {
    const urls = Array.isArray(targetURLs) ? targetURLs : [];
    
    let filtered = urls.filter(url => {
      if (filters.url && !url.url?.toLowerCase().includes(filters.url.toLowerCase())) {
        return false;
      }
      
      if (filters.statusCode) {
        const statusCode = url.status_code;
        if (filters.statusCode === '2xx' && (statusCode < 200 || statusCode >= 300)) return false;
        if (filters.statusCode === '3xx' && (statusCode < 300 || statusCode >= 400)) return false;
        if (filters.statusCode === '4xx' && (statusCode < 400 || statusCode >= 500)) return false;
        if (filters.statusCode === '5xx' && (statusCode < 500 || statusCode >= 600)) return false;
        if (filters.statusCode === 'no_response' && statusCode) return false;
      }
      
      if (filters.sslIssues && !hasSSLIssue(url, filters.sslIssues)) {
        return false;
      }
      
      if (filters.webServer) {
        const webServer = getSafeValue(url.web_server) || '';
        if (!webServer.toLowerCase().includes(filters.webServer.toLowerCase())) {
          return false;
        }
      }
      
      if (filters.technologies) {
        const techString = url.technologies ? url.technologies.join(' ') : '';
        const findings = Array.isArray(url.findings_json) ? url.findings_json : [];
        const findingsString = findings.map(f => f.info?.name || f.template || '').join(' ');
        const allTech = (techString + ' ' + findingsString).toLowerCase();
        if (!allTech.includes(filters.technologies.toLowerCase())) {
          return false;
        }
      }
      
      if (filters.contentLength) {
        const contentLength = url.content_length || 0;
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
        case 'sslIssues':
          valueA = getSSLIssuesCount(a);
          valueB = getSSLIssuesCount(b);
          break;
        case 'webServer':
          valueA = getSafeValue(a.web_server) || '';
          valueB = getSafeValue(b.web_server) || '';
          break;
        case 'contentLength':
          valueA = a.content_length || 0;
          valueB = b.content_length || 0;
          break;
        case 'katanaUrls':
          valueA = getKatanaUrlsCount(a);
          valueB = getKatanaUrlsCount(b);
          break;
        case 'ffufEndpoints':
          valueA = getFfufEndpointsCount(a);
          valueB = getFfufEndpointsCount(b);
          break;
        case 'technologies':
          valueA = getTechnologiesCount(a);
          valueB = getTechnologiesCount(b);
          break;
        default:
          return 0;
      }

      if (valueA < valueB) return sortDirection === 'asc' ? -1 : 1;
      if (valueA > valueB) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }, [targetURLs, filters, sortColumn, sortDirection]);

  const totalPages = Math.ceil(filteredAndSortedUrls.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedUrls = filteredAndSortedUrls.slice(startIndex, endIndex);

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
    <Modal
      data-bs-theme="dark"
      show={showMetaDataModal}
      onHide={handleCloseMetaDataModal}
      size="xl"
      fullscreen={true}
      backdrop="static"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Metadata Results</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {isLoading ? (
          <div className="d-flex justify-content-center align-items-center" style={{ minHeight: '400px' }}>
            <div className="text-center">
              <Spinner animation="border" variant="danger" />
              <p className="text-white mt-3">Loading Metadata Results...</p>
            </div>
          </div>
        ) : (
          <>
        {filteredAndSortedUrls.length > 0 && (
          <div className="mb-4">
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label>Filter by URL</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Search URL..."
                  value={filters.url}
                  onChange={(e) => handleFilterChange('url', e.target.value)}
                />
              </Col>
              <Col md={3}>
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
                <Form.Label>SSL Issues</Form.Label>
                <Form.Select
                  value={filters.sslIssues}
                  onChange={(e) => handleFilterChange('sslIssues', e.target.value)}
                >
                  <option value="">All</option>
                  <option value="has_issues">Has Issues</option>
                  <option value="no_issues">No Issues</option>
                  <option value="Deprecated TLS">Deprecated TLS</option>
                  <option value="Expired SSL">Expired SSL</option>
                  <option value="Mismatched SSL">Mismatched SSL</option>
                  <option value="Revoked SSL">Revoked SSL</option>
                  <option value="Self-Signed SSL">Self-Signed SSL</option>
                  <option value="Untrusted Root">Untrusted Root</option>
                </Form.Select>
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={4}>
                <Form.Label>Web Server</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Search web server..."
                  value={filters.webServer}
                  onChange={(e) => handleFilterChange('webServer', e.target.value)}
                />
              </Col>
              <Col md={4}>
                <Form.Label>Technologies</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Search technologies..."
                  value={filters.technologies}
                  onChange={(e) => handleFilterChange('technologies', e.target.value)}
                />
              </Col>
              <Col md={2}>
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
              <Col md={2} className="d-flex align-items-end">
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
                  onClick={() => handleSort('sslIssues')}
                >
                  SSL Issues {renderSortIcon('sslIssues')}
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
                <Button
                  variant="link"
                  className="p-0 text-white text-decoration-none"
                  onClick={() => handleSort('katanaUrls')}
                >
                  Katana URLs {renderSortIcon('katanaUrls')}
                </Button>
                <Button
                  variant="link"
                  className="p-0 text-white text-decoration-none"
                  onClick={() => handleSort('ffufEndpoints')}
                >
                  Ffuf Endpoints {renderSortIcon('ffufEndpoints')}
                </Button>
                <Button
                  variant="link"
                  className="p-0 text-white text-decoration-none"
                  onClick={() => handleSort('technologies')}
                >
                  Technologies {renderSortIcon('technologies')}
                </Button>
              </div>
            </div>
            <div className="mb-2 d-flex justify-content-between align-items-center">
              <small className="text-muted">
                Showing {startIndex + 1}-{Math.min(endIndex, filteredAndSortedUrls.length)} of {filteredAndSortedUrls.length} filtered results
                {filteredAndSortedUrls.length !== (Array.isArray(targetURLs) ? targetURLs.length : 0) && 
                  ` (${Array.isArray(targetURLs) ? targetURLs.length : 0} total)`
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
        <div className="mb-4">
            {filteredAndSortedUrls.length === 0 ? (
              <div className="text-center text-muted">
                {Array.isArray(targetURLs) && targetURLs.length > 0 
                  ? 'No results match the current filters' 
                  : 'No metadata results available'}
              </div>
            ) : (
              paginatedUrls.map((url, urlIndex) => {
                const sslIssues = getSSLIssues(url);

                const findings = Array.isArray(url.findings_json) ? url.findings_json : [];
                
                // Process katana results
                let katanaUrls = [];
                if (url.katana_results) {
                  if (Array.isArray(url.katana_results)) {
                    katanaUrls = url.katana_results;
                  } else if (typeof url.katana_results === 'string') {
                    try {
                      const parsed = JSON.parse(url.katana_results);
                      katanaUrls = Array.isArray(parsed) ? parsed : [];
                    } catch (error) {
                    }
                  }
                }

                let ffufEndpoints = [];
                if (url.ffuf_results) {
                  if (typeof url.ffuf_results === 'object' && url.ffuf_results.endpoints) {
                    ffufEndpoints = url.ffuf_results.endpoints;
                  } else if (typeof url.ffuf_results === 'string') {
                    try {
                      const parsed = JSON.parse(url.ffuf_results);
                      ffufEndpoints = parsed.endpoints || [];
                    } catch (error) {
                    }
                  }
                }

                return (
                <Accordion key={url.id} className="mb-3">
                  <Accordion.Item eventKey="0">
                    <Accordion.Header>
                      <div className="d-flex justify-content-between align-items-center w-100 me-3">
                        <div className="d-flex align-items-center">
                          <Badge 
                            bg={getStatusCodeColor(url.status_code).bg}
                            className={`me-2 text-${getStatusCodeColor(url.status_code).text}`}
                            style={{ fontSize: '0.8em' }}
                          >
                            {url.status_code}
                          </Badge>
                          {url.screenshot && (
                            <img 
                              src={`data:image/png;base64,${url.screenshot}`}
                              alt="Thumbnail"
                              className="me-2"
                              style={{ 
                                width: '40px',
                                height: '40px',
                                objectFit: 'cover',
                                borderRadius: '4px',
                                border: '1px solid #444'
                              }}
                            />
                          )}
                          <span>{url.url}</span>
                        </div>
                        <div className="d-flex align-items-center gap-2">
                          <Badge 
                            bg="dark" 
                            className="text-white"
                            style={{ fontSize: '0.8em' }}
                          >
                            {katanaUrls.length} Crawled URLs
                          </Badge>
                          <Badge 
                            bg="dark" 
                            className="text-white"
                            style={{ fontSize: '0.8em' }}
                          >
                            {ffufEndpoints.length} Endpoints
                          </Badge>
                          {findings.length > 0 && (
                            <Badge 
                              bg="secondary" 
                              style={{ fontSize: '0.8em' }}
                            >
                              {findings.length} Technologies
                            </Badge>
                          )}
                          {sslIssues.length > 0 ? (
                            sslIssues.map((issue, index) => (
                              <Badge 
                                key={index} 
                                bg="danger" 
                                style={{ fontSize: '0.8em' }}
                              >
                                {issue}
                              </Badge>
                            ))
                          ) : (
                            <Badge 
                              bg="success" 
                              style={{ fontSize: '0.8em' }}
                            >
                              No SSL Issues
                            </Badge>
                          )}
                          {isUrlAlreadyScopeTarget(url.url) ? (
                            <OverlayTrigger
                              placement="top"
                              overlay={<Tooltip>Already added as URL Scope Target</Tooltip>}
                            >
                              <Button
                                variant="outline-secondary"
                                size="sm"
                                disabled
                                style={{ padding: '0.25rem 0.5rem' }}
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
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleAddAsScopeTarget(url);
                                }}
                                disabled={addingUrls.has(url.id)}
                                style={{ padding: '0.25rem 0.5rem' }}
                              >
                                {addingUrls.has(url.id) ? (
                                  <i className="bi bi-hourglass-split"></i>
                                ) : (
                                  <i className="bi bi-plus-circle"></i>
                                )}
                              </Button>
                            </OverlayTrigger>
                          )}
                          <OverlayTrigger
                            placement="top"
                            overlay={<Tooltip>Delete from results</Tooltip>}
                          >
                            <Button
                              variant="outline-danger"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDeleteUrl(url.id);
                              }}
                              disabled={deletingUrls.has(url.id)}
                              style={{ padding: '0.25rem 0.5rem' }}
                            >
                              {deletingUrls.has(url.id) ? (
                                <i className="bi bi-hourglass-split"></i>
                              ) : (
                                <i className="bi bi-trash"></i>
                              )}
                            </Button>
                          </OverlayTrigger>
                        </div>
                      </div>
                    </Accordion.Header>
                    <Accordion.Body>
                      <div className="mb-4 pb-3 border-bottom">
                        <h6 className="text-danger mb-2">URL</h6>
                        <div className="d-flex align-items-center gap-2">
                          <a 
                            href={url.url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-info text-decoration-none d-flex align-items-center gap-2"
                            style={{ fontSize: '1.1em' }}
                          >
                            <i className="bi bi-box-arrow-up-right"></i>
                            <span style={{ wordBreak: 'break-all' }}>{url.url}</span>
                          </a>
                        </div>
                      </div>
                      {url.screenshot && (
                        <div className="mb-4 pb-3 border-bottom">
                          <h6 className="text-danger mb-2">Screenshot</h6>
                          <OverlayTrigger
                            placement="top"
                            overlay={<Tooltip>Click to view full size</Tooltip>}
                          >
                            <img 
                              src={`data:image/png;base64,${url.screenshot}`}
                              alt="Page Screenshot"
                              onClick={() => setLightboxImage(url.screenshot)}
                              style={{ 
                                maxWidth: '100%',
                                height: 'auto',
                                maxHeight: '300px',
                                objectFit: 'contain',
                                cursor: 'pointer',
                                border: '1px solid #444',
                                borderRadius: '4px',
                                transition: 'transform 0.2s, box-shadow 0.2s',
                              }}
                              onMouseOver={(e) => {
                                e.currentTarget.style.transform = 'scale(1.02)';
                                e.currentTarget.style.boxShadow = '0 0 15px rgba(220, 53, 69, 0.5)';
                              }}
                              onMouseOut={(e) => {
                                e.currentTarget.style.transform = 'scale(1)';
                                e.currentTarget.style.boxShadow = 'none';
                              }}
                            />
                          </OverlayTrigger>
                        </div>
                      )}
                      <div className="mb-4">
                        <h6 className="text-danger mb-3">Server Information</h6>
                        <div className="ms-3">
                          <p className="mb-1"><strong>Title:</strong> {getSafeValue(url.title) || 'N/A'}</p>
                          <p className="mb-1"><strong>Web Server:</strong> {getSafeValue(url.web_server) || 'N/A'}</p>
                          <p className="mb-1"><strong>Content Length:</strong> {url.content_length}</p>
                          {url.technologies && url.technologies.length > 0 && (
                            <p className="mb-1">
                              <strong>Technologies:</strong>{' '}
                              {url.technologies.map((tech, index) => (
                                <Badge 
                                  key={index} 
                                  bg="secondary" 
                                  className="me-1"
                                  style={{ fontSize: '0.8em' }}
                                >
                                  {tech}
                                </Badge>
                              ))}
                            </p>
                          )}
                        </div>
                      </div>
                      {(() => {
                        const dnsRecordTypes = [
                          { 
                            title: 'A Records', 
                            records: url.dns_a_records || [],
                            description: 'Maps hostnames to IPv4 addresses',
                            badge: 'bg-primary'
                          },
                          { 
                            title: 'AAAA Records', 
                            records: url.dns_aaaa_records || [],
                            description: 'Maps hostnames to IPv6 addresses',
                            badge: 'bg-info'
                          },
                          { 
                            title: 'CNAME Records', 
                            records: url.dns_cname_records || [],
                            description: 'Canonical name records - Maps one domain name (alias) to another (canonical name)',
                            badge: 'bg-success'
                          },
                          { 
                            title: 'MX Records', 
                            records: url.dns_mx_records || [],
                            description: 'Mail exchange records - Specifies mail servers responsible for receiving email',
                            badge: 'bg-warning'
                          },
                          { 
                            title: 'TXT Records', 
                            records: url.dns_txt_records || [],
                            description: 'Text records - Holds human/machine-readable text data, often used for domain verification',
                            badge: 'bg-secondary'
                          },
                          { 
                            title: 'NS Records', 
                            records: url.dns_ns_records || [],
                            description: 'Nameserver records - Delegates a DNS zone to authoritative nameservers',
                            badge: 'bg-danger'
                          },
                          { 
                            title: 'PTR Records', 
                            records: url.dns_ptr_records || [],
                            description: 'Pointer records - Maps IP addresses to hostnames (reverse DNS)',
                            badge: 'bg-dark'
                          },
                          { 
                            title: 'SRV Records', 
                            records: url.dns_srv_records || [],
                            description: 'Service records - Specifies location of servers for specific services',
                            badge: 'bg-info'
                          }
                        ];

                        const hasAnyDNSRecords = dnsRecordTypes.some(
                          recordType => recordType.records && recordType.records.length > 0
                        );

                        return hasAnyDNSRecords ? (
                          <div>
                            <h6 className="text-danger mb-3">DNS Records</h6>
                            <div className="ms-3">
                              {dnsRecordTypes.map((recordType, index) => {
                                if (!recordType.records || recordType.records.length === 0) return null;
                                return (
                                  <div key={index} className="mb-3">
                                    <p className="mb-2">
                                      <Badge bg={recordType.badge.split('-')[1]} className="me-2">
                                        {recordType.title}
                                      </Badge>
                                      <small className="text-muted">{recordType.description}</small>
                                    </p>
                                    <div className="bg-dark p-2 rounded">
                                      {recordType.records.map((record, recordIndex) => (
                                        <div key={recordIndex} className="mb-1 font-monospace small">
                                          {record}
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        ) : null;
                      })()}
                      {findings.length > 0 && (
                        <div>
                          <h6 className="text-danger mb-3">Technology Stack</h6>
                          <div className="ms-3">
                            {findings.map((finding, index) => (
                              <div key={index} className="mb-2 text-white">
                                {finding.info?.name || finding.template} -- {finding['matcher-name']?.toUpperCase()}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {(() => {
                        let headers = {};
                        try {
                          if (url.http_response_headers) {
                            if (typeof url.http_response_headers === 'string') {
                              headers = JSON.parse(url.http_response_headers);
                            } else {
                              headers = url.http_response_headers;
                            }
                          }
                        } catch (error) {
                        }

                        if (Object.keys(headers).length > 0) {
                          return (
                            <div className="mb-4">
                              <h6 className="text-danger mb-3">Response Headers</h6>
                              <div className="ms-3">
                                <div className="bg-dark p-3 rounded">
                                  {Object.entries(headers).map(([key, value], index) => (
                                    <div key={index} className="mb-2 font-monospace small">
                                      <span className="text-info">{key}:</span>{' '}
                                      <span className="text-white">{Array.isArray(value) ? value.join(', ') : value}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          );
                        }
                        return null;
                      })()}
                      <div>
                        <h6 className="text-danger mb-3">Crawled URLs</h6>
                        <div className="ms-3">
                          <Accordion>
                            <Accordion.Item eventKey="0">
                              <Accordion.Header>
                                <div className="d-flex align-items-center justify-content-between w-100">
                                  <div>
                                    <span className="text-white">
                                      Katana Results
                                    </span>
                                    <br/>
                                    <small className="text-muted">URLs discovered through crawling</small>
                                  </div>
                                  <Badge 
                                    bg={katanaUrls.length > 0 ? "info" : "secondary"}
                                    className="ms-2"
                                    style={{ fontSize: '0.8em' }}
                                  >
                                    {katanaUrls.length} URLs
                                  </Badge>
                                </div>
                              </Accordion.Header>
                              <Accordion.Body>
                                {katanaUrls.length > 0 ? (
                                  <div 
                                    className="bg-dark p-3 rounded font-monospace" 
                                    style={{ 
                                      maxHeight: '300px', 
                                      overflowY: 'auto',
                                      fontSize: '0.85em'
                                    }}
                                  >
                                    {katanaUrls.map((crawledUrl, index) => (
                                      <div key={index} className="mb-2 d-flex align-items-center">
                                        <span className="me-2">•</span>
                                        <span style={{ wordBreak: 'break-all' }}>
                                          <a 
                                            href={crawledUrl} 
                                            target="_blank" 
                                            rel="noopener noreferrer" 
                                            className="text-info text-decoration-none"
                                          >
                                            {crawledUrl}
                                          </a>
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-muted text-center py-3">
                                    No URLs were discovered during crawling
                                  </div>
                                )}
                              </Accordion.Body>
                            </Accordion.Item>
                          </Accordion>
                        </div>
                      </div>
                      <div className="mt-4">
                        <h6 className="text-danger mb-3">Discovered Endpoints</h6>
                        <div className="ms-3">
                          <Accordion>
                            <Accordion.Item eventKey="0">
                              <Accordion.Header>
                                <div className="d-flex align-items-center justify-content-between w-100">
                                  <div>
                                    <span className="text-white">
                                      Ffuf Results
                                    </span>
                                    <br/>
                                    <small className="text-muted">Endpoints discovered through fuzzing</small>
                                  </div>
                                  <Badge 
                                    bg={ffufEndpoints.length > 0 ? "dark" : "secondary"}
                                    className="ms-2 text-white"
                                    style={{ fontSize: '0.8em' }}
                                  >
                                    {ffufEndpoints.length} Endpoints
                                  </Badge>
                                </div>
                              </Accordion.Header>
                              <Accordion.Body>
                                {ffufEndpoints.length > 0 ? (
                                  <div 
                                    className="bg-dark p-3 rounded font-monospace" 
                                    style={{ 
                                      maxHeight: '300px', 
                                      overflowY: 'auto',
                                      fontSize: '0.85em'
                                    }}
                                  >
                                    {ffufEndpoints.map((endpoint, index) => (
                                      <div key={index} className="mb-2 d-flex align-items-center">
                                        <Badge 
                                          bg={getStatusCodeColor(endpoint.status).bg}
                                          className={`me-2 text-${getStatusCodeColor(endpoint.status).text}`}
                                          style={{ fontSize: '0.8em', minWidth: '3em' }}
                                        >
                                          {endpoint.status}
                                        </Badge>
                                        <span style={{ wordBreak: 'break-all' }}>
                                          <a 
                                            href={`${url.url}/${endpoint.path}`} 
                                            target="_blank" 
                                            rel="noopener noreferrer" 
                                            className="text-info text-decoration-none"
                                          >
                                            /{endpoint.path}
                                          </a>
                                          <span className="ms-2 text-muted">
                                            <small>
                                              ({endpoint.size} bytes, {endpoint.words} words, {endpoint.lines} lines)
                                            </small>
                                          </span>
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-muted text-center py-3">
                                    No endpoints were discovered during fuzzing
                                  </div>
                                )}
                              </Accordion.Body>
                            </Accordion.Item>
                          </Accordion>
                        </div>
                      </div>
                    </Accordion.Body>
                  </Accordion.Item>
                </Accordion>
                );
              })
            )}
        </div>
        {filteredAndSortedUrls.length > 0 && (
          <div className="d-flex justify-content-center mt-4">
            {renderPagination()}
          </div>
        )}
          </>
        )}
      </Modal.Body>
      
      {lightboxImage && (
        <div 
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.95)',
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            animation: 'fadeIn 0.2s ease-in'
          }}
          onClick={() => setLightboxImage(null)}
        >
          <div 
            style={{
              position: 'relative',
              maxWidth: '95vw',
              maxHeight: '95vh',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setLightboxImage(null)}
              style={{
                position: 'absolute',
                top: '-40px',
                right: '-40px',
                backgroundColor: 'transparent',
                border: 'none',
                color: 'white',
                fontSize: '32px',
                cursor: 'pointer',
                width: '40px',
                height: '40px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'color 0.2s',
              }}
              onMouseOver={(e) => e.currentTarget.style.color = '#dc3545'}
              onMouseOut={(e) => e.currentTarget.style.color = 'white'}
            >
              ×
            </button>
            <img 
              src={`data:image/png;base64,${lightboxImage}`}
              alt="Screenshot - Full Size"
              style={{ 
                maxWidth: '100%',
                maxHeight: '95vh',
                objectFit: 'contain',
                borderRadius: '8px',
                boxShadow: '0 0 30px rgba(220, 53, 69, 0.5)',
                animation: 'zoomIn 0.2s ease-out'
              }}
            />
          </div>
          <div
            style={{
              position: 'absolute',
              bottom: '20px',
              left: '50%',
              transform: 'translateX(-50%)',
              color: 'rgba(255, 255, 255, 0.7)',
              fontSize: '14px',
              textAlign: 'center'
            }}
          >
            Click anywhere or press ESC to close
          </div>
        </div>
      )}
    </Modal>
  );
});

export default MetaDataModal; 