import { useState, useEffect, useMemo } from 'react';
import { Modal, Button, Tab, Tabs, Table, Badge, Spinner, Alert, Accordion, Form, Row, Col, Pagination, OverlayTrigger, Tooltip } from 'react-bootstrap';
import { MdCopyAll } from 'react-icons/md';

const LiveWebServersResultsModal = ({ show, onHide, activeTarget, consolidatedNetworkRanges, mostRecentIPPortScan }) => {
  const [activeTab, setActiveTab] = useState('network-ranges');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [liveWebServers, setLiveWebServers] = useState([]);
  const [discoveredIPs, setDiscoveredIPs] = useState([]);
  const [scanData, setScanData] = useState(null);
  const [metadataResults, setMetadataResults] = useState([]);
  const [metadataScans, setMetadataScans] = useState([]);
  const [metadataLoading, setMetadataLoading] = useState(false);
  const [sortColumn, setSortColumn] = useState('');
  const [sortDirection, setSortDirection] = useState('asc');
  const [filters, setFilters] = useState({
    url: '',
    hostname: '',
    statusCode: '',
    port: '',
    protocol: '',
    technologies: ''
  });
  const [addingUrls, setAddingUrls] = useState(new Set());
  const [existingScopeTargets, setExistingScopeTargets] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(25);

  const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8443';

  useEffect(() => {
    if (show && mostRecentIPPortScan && mostRecentIPPortScan.scan_id) {
      fetchIPPortScanData();
      fetchMetadataData();
      fetchExistingScopeTargets();
    }
  }, [show, mostRecentIPPortScan]);

  useEffect(() => {
    setCurrentPage(1);
  }, [filters, sortColumn, sortDirection]);

  const fetchIPPortScanData = async () => {
    if (!mostRecentIPPortScan || !mostRecentIPPortScan.scan_id) return;
    
    setLoading(true);
    console.log('LiveWebServersResultsModal: Starting fetchIPPortScanData for scanId:', mostRecentIPPortScan.scan_id);
    
    try {
      // Fetch scan info
      const scanResponse = await fetch(`${API_BASE_URL}/ip-port-scan/status/${mostRecentIPPortScan.scan_id}`);
      if (scanResponse.ok) {
        const scanInfo = await scanResponse.json();
        setScanData(scanInfo);
      }

      // Fetch live web servers
      const webServersResponse = await fetch(`${API_BASE_URL}/ip-port-scan/${mostRecentIPPortScan.scan_id}/live-web-servers`);
      if (webServersResponse.ok) {
        const webServers = await webServersResponse.json();
        setLiveWebServers(webServers || []);
      }

      // Fetch discovered IPs
      const ipsResponse = await fetch(`${API_BASE_URL}/ip-port-scan/${mostRecentIPPortScan.scan_id}/discovered-ips`);
      if (ipsResponse.ok) {
        const ips = await ipsResponse.json();
        setDiscoveredIPs(ips || []);
      }
    } catch (error) {
      console.error('LiveWebServersResultsModal: Error fetching IP/Port scan data:', error);
      setError('Failed to load IP/Port scan data');
    } finally {
      setLoading(false);
    }
  };

  const fetchMetadataData = async () => {
    if (!mostRecentIPPortScan || !mostRecentIPPortScan.scan_id) return;
    
    setMetadataLoading(true);
    console.log('LiveWebServersResultsModal: Fetching metadata for scanId:', mostRecentIPPortScan.scan_id);
    
    try {
      // Fetch metadata scans
      const scansResponse = await fetch(`${API_BASE_URL}/ip-port-scan/${mostRecentIPPortScan.scan_id}/metadata-scans`);
      if (scansResponse.ok) {
        const scans = await scansResponse.json();
        setMetadataScans(scans || []);
      }

      // Fetch metadata results
      const resultsResponse = await fetch(`${API_BASE_URL}/ip-port-scan/${mostRecentIPPortScan.scan_id}/metadata-results`);
      if (resultsResponse.ok) {
        const results = await resultsResponse.json();
        setMetadataResults(results || []);
      }
    } catch (error) {
      console.error('LiveWebServersResultsModal: Error fetching metadata data:', error);
    } finally {
      setMetadataLoading(false);
    }
  };

  const fetchExistingScopeTargets = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/scopetarget/read`);
      if (response.ok) {
        const data = await response.json();
        setExistingScopeTargets(data);
      }
    } catch (error) {
      console.error('LiveWebServersResultsModal: Error fetching scope targets:', error);
    }
  };

  const isUrlAlreadyScopeTarget = (url) => {
    return existingScopeTargets.some(
      target => target.type === 'URL' && target.scope_target === url
    );
  };

  const handleAddAsScopeTarget = async (server) => {
    if (addingUrls.has(server.url)) return;
    
    setAddingUrls(prev => new Set(prev).add(server.url));
    
    try {
      const payload = {
        type: 'URL',
        mode: 'Passive',
        scope_target: server.url,
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
      alert(`Failed to add ${server.url} as scope target: ${error.message}`);
    } finally {
      setAddingUrls(prev => {
        const newSet = new Set(prev);
        newSet.delete(server.url);
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
      hostname: '',
      statusCode: '',
      port: '',
      protocol: '',
      technologies: ''
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

  const handleCopyText = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      console.error('Failed to copy text:', err);
    }
  };

  const getScanTypeBadgeVariant = (scanType) => {
    switch (scanType?.toLowerCase()) {
      case 'net':
        return 'primary';
      case 'netd':
        return 'info';
      case 'asn':
        return 'success';
      default:
        return 'secondary';
    }
  };

  const getSourceBadgeVariant = (source) => {
    switch (source?.toLowerCase()) {
      case 'amass_intel':
        return 'danger';
      case 'metabigor':
        return 'warning';
      case 'amass_intel, metabigor':
        return 'success';
      default:
        return 'secondary';
    }
  };

  const renderSourceBadges = (source) => {
    if (source === 'amass_intel, metabigor') {
      return (
        <div className="d-flex gap-1">
          <Badge bg="danger" className="small">Amass Intel</Badge>
          <Badge bg="warning" className="small">Metabigor</Badge>
        </div>
      );
    } else if (source === 'amass_intel') {
      return <Badge bg="danger">Amass Intel</Badge>;
    } else if (source === 'metabigor') {
      return <Badge bg="warning">Metabigor</Badge>;
    } else {
      return <Badge bg="secondary">{source}</Badge>;
    }
  };

  const getStatusColor = (statusCode) => {
    if (!statusCode) return 'secondary';
    if (statusCode >= 200 && statusCode < 300) return 'success';
    if (statusCode >= 300 && statusCode < 400) return 'info';
    if (statusCode >= 400 && statusCode < 500) return 'warning';
    if (statusCode >= 500) return 'danger';
    return 'secondary';
  };

  const formatResponseTime = (responseTime) => {
    if (!responseTime) return 'N/A';
    return `${responseTime}ms`;
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return 'N/A';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const filteredAndSortedServers = useMemo(() => {
    let filtered = liveWebServers.filter(server => {
      if (filters.url && !server.url?.toLowerCase().includes(filters.url.toLowerCase())) {
        return false;
      }
      
      if (filters.hostname && !server.hostname?.toLowerCase().includes(filters.hostname.toLowerCase())) {
        return false;
      }
      
      if (filters.statusCode) {
        const statusCode = server.status_code;
        if (filters.statusCode === '2xx' && (statusCode < 200 || statusCode >= 300)) return false;
        if (filters.statusCode === '3xx' && (statusCode < 300 || statusCode >= 400)) return false;
        if (filters.statusCode === '4xx' && (statusCode < 400 || statusCode >= 500)) return false;
        if (filters.statusCode === '5xx' && (statusCode < 500 || statusCode >= 600)) return false;
        if (filters.statusCode === 'no_response' && statusCode) return false;
      }
      
      if (filters.port && server.port && !server.port.toString().includes(filters.port)) {
        return false;
      }
      
      if (filters.protocol && !server.protocol?.toLowerCase().includes(filters.protocol.toLowerCase())) {
        return false;
      }
      
      if (filters.technologies) {
        const techString = server.technologies ? server.technologies.join(' ') : '';
        if (!techString.toLowerCase().includes(filters.technologies.toLowerCase())) {
          return false;
        }
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
        case 'hostname':
          valueA = a.hostname || '';
          valueB = b.hostname || '';
          break;
        case 'statusCode':
          valueA = a.status_code || 0;
          valueB = b.status_code || 0;
          break;
        case 'port':
          valueA = a.port || 0;
          valueB = b.port || 0;
          break;
        case 'protocol':
          valueA = a.protocol || '';
          valueB = b.protocol || '';
          break;
        case 'title':
          valueA = a.title || '';
          valueB = b.title || '';
          break;
        case 'server':
          valueA = a.server_header || '';
          valueB = b.server_header || '';
          break;
        default:
          return 0;
      }

      if (valueA < valueB) return sortDirection === 'asc' ? -1 : 1;
      if (valueA > valueB) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }, [liveWebServers, filters, sortColumn, sortDirection]);

  const totalPages = Math.ceil(filteredAndSortedServers.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedServers = filteredAndSortedServers.slice(startIndex, endIndex);

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
    <Modal show={show} onHide={onHide} size="xl" className="modal-90w">
      <Modal.Header closeButton className="bg-dark text-white">
        <Modal.Title>Live Web Servers Results</Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark text-white">
        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="mb-3"
          variant="pills"
        >
          <Tab eventKey="network-ranges" title={`Consolidated Network Ranges (${consolidatedNetworkRanges?.length || 0})`}>
            <div className="mb-3">
              <h5 className="text-danger">Consolidated Network Ranges</h5>
              <p className="text-white-50 small">
                Unique network ranges discovered from Amass Intel and Metabigor scans, deduplicated by CIDR block and ASN combination.
              </p>
            </div>

            {loading && (
              <div className="text-center py-4">
                <Spinner animation="border" variant="danger" />
                <p className="mt-2">Loading network ranges...</p>
              </div>
            )}

            {error && (
              <Alert variant="danger" className="mb-3">
                {error}
              </Alert>
            )}

            {!loading && !error && (
              <>
                <div className="mb-3">
                  <span className="text-white-50">
                    Total Network Ranges: <strong className="text-danger">{consolidatedNetworkRanges?.length || 0}</strong>
                  </span>
                </div>

                {consolidatedNetworkRanges && consolidatedNetworkRanges.length > 0 ? (
                  <div className="table-responsive">
                    <Table striped bordered hover variant="dark" className="mb-0">
                      <thead>
                        <tr>
                          <th>CIDR Block</th>
                          <th>ASN</th>
                          <th>Organization</th>
                          <th>Description/Scan Type</th>
                          <th>Country</th>
                          <th>Source</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {consolidatedNetworkRanges.map((range, index) => (
                          <tr key={index}>
                            <td>
                              <code className="text-danger">{range.cidr_block}</code>
                            </td>
                            <td>
                              <code className="text-info">{range.asn || 'N/A'}</code>
                            </td>
                            <td className="text-truncate" style={{ maxWidth: '200px' }}>
                              {range.organization || 'N/A'}
                            </td>
                            <td>
                              {range.source === 'amass_intel' ? (
                                <span className="text-white-50">{range.description || 'N/A'}</span>
                              ) : (
                                <Badge 
                                  bg={getScanTypeBadgeVariant(range.scan_type)}
                                  className="text-uppercase"
                                >
                                  {range.scan_type || 'N/A'}
                                </Badge>
                              )}
                            </td>
                            <td>
                              {range.country ? (
                                <Badge bg="secondary">{range.country}</Badge>
                              ) : (
                                <span className="text-white-50">N/A</span>
                              )}
                            </td>
                            <td>
                              {renderSourceBadges(range.source)}
                            </td>
                            <td>
                              <Button
                                variant="outline-danger"
                                size="sm"
                                onClick={() => handleCopyText(range.cidr_block)}
                                title="Copy CIDR block"
                              >
                                <MdCopyAll />
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </div>
                ) : (
                  <div className="text-center py-5">
                    <div className="text-white-50">
                      <h6>No consolidated network ranges found</h6>
                      <p className="small">
                        Run Amass Intel or Metabigor scans, then click "Consolidate" to see network ranges here.
                      </p>
                    </div>
                  </div>
                )}
              </>
            )}
          </Tab>

          <Tab eventKey="discovered-ips" title={`Discovered IPs (${discoveredIPs.length})`}>
            <div className="mb-3">
              <h5 className="text-danger">Discovered IPs</h5>
              <p className="text-white-50 small">
                Live IP addresses discovered within the consolidated network ranges via IP/Port scanning.
              </p>
            </div>

            {loading ? (
              <div className="text-center py-4">
                <Spinner animation="border" variant="danger" />
                <p className="mt-2">Loading discovered IPs...</p>
              </div>
            ) : (
              <div className="table-responsive">
                <Table striped bordered hover variant="dark" size="sm">
                  <thead>
                    <tr>
                      <th>IP Address</th>
                      <th>Hostname</th>
                      <th>Network Range</th>
                      <th>Discovered At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {discoveredIPs.map((ip, index) => (
                      <tr key={index}>
                        <td><code className="text-info">{ip.ip_address}</code></td>
                        <td className="text-truncate" style={{ maxWidth: '250px' }} title={ip.hostname}>
                          {ip.hostname ? (
                            <code className="text-warning">{ip.hostname}</code>
                          ) : (
                            <span className="text-muted">N/A</span>
                          )}
                        </td>
                        <td><code className="text-warning">{ip.network_range}</code></td>
                        <td>{new Date(ip.discovered_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
                {discoveredIPs.length === 0 && (
                  <div className="text-center py-4 text-white-50">
                    {mostRecentIPPortScan ? 'No discovered IPs found.' : 'Run an IP/Port scan to see discovered IPs here.'}
                  </div>
                )}
              </div>
            )}
          </Tab>

          <Tab eventKey="live-servers" title={`Live Web Servers (${liveWebServers.length})`}>
            <div className="mb-3">
              <h5 className="text-danger">Live Web Servers</h5>
              <p className="text-white-50 small">
                Active web servers discovered within the consolidated network ranges via IP/Port scanning.
              </p>
            </div>

            {loading ? (
              <div className="text-center py-4">
                <Spinner animation="border" variant="danger" />
                <p className="mt-2">Loading live web servers...</p>
              </div>
            ) : (
              <>
                {filteredAndSortedServers.length > 0 && (
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
                      <Col md={4}>
                        <Form.Label>Filter by Hostname</Form.Label>
                        <Form.Control
                          type="text"
                          placeholder="Search hostname..."
                          value={filters.hostname}
                          onChange={(e) => handleFilterChange('hostname', e.target.value)}
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
                      <Col md={2}>
                        <Form.Label>Port</Form.Label>
                        <Form.Control
                          type="text"
                          placeholder="Port..."
                          value={filters.port}
                          onChange={(e) => handleFilterChange('port', e.target.value)}
                        />
                      </Col>
                    </Row>
                    <Row className="mb-3">
                      <Col md={4}>
                        <Form.Label>Protocol</Form.Label>
                        <Form.Control
                          type="text"
                          placeholder="Search protocol..."
                          value={filters.protocol}
                          onChange={(e) => handleFilterChange('protocol', e.target.value)}
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
                      <Col md={4} className="d-flex align-items-end">
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
                          onClick={() => handleSort('hostname')}
                        >
                          Hostname {renderSortIcon('hostname')}
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
                          onClick={() => handleSort('port')}
                        >
                          Port {renderSortIcon('port')}
                        </Button>
                        <Button
                          variant="link"
                          className="p-0 text-white text-decoration-none"
                          onClick={() => handleSort('protocol')}
                        >
                          Protocol {renderSortIcon('protocol')}
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
                          onClick={() => handleSort('server')}
                        >
                          Server {renderSortIcon('server')}
                        </Button>
                      </div>
                    </div>
                    <div className="mb-2 d-flex justify-content-between align-items-center">
                      <small className="text-muted">
                        Showing {startIndex + 1}-{Math.min(endIndex, filteredAndSortedServers.length)} of {filteredAndSortedServers.length} filtered results
                        {filteredAndSortedServers.length !== liveWebServers.length && 
                          ` (${liveWebServers.length} total)`
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
                <div className="table-responsive">
                  {filteredAndSortedServers.length === 0 ? (
                    <div className="text-center py-4 text-white-50">
                      {liveWebServers.length > 0 
                        ? 'No results match the current filters' 
                        : mostRecentIPPortScan 
                          ? 'No live web servers found.' 
                          : 'Run an IP/Port scan to see live web servers here.'}
                    </div>
                  ) : (
                    <Table striped bordered hover variant="dark" size="sm">
                      <thead>
                        <tr>
                          <th>URL</th>
                          <th>IP Address</th>
                          <th>Hostname</th>
                          <th>Port</th>
                          <th>Protocol</th>
                          <th>Status</th>
                          <th>Title</th>
                          <th>Server</th>
                          <th>Technologies</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {paginatedServers.map((server, index) => (
                          <tr key={index}>
                            <td>
                              <a 
                                href={server.url} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="text-info text-decoration-none"
                                style={{ fontSize: '0.85em' }}
                              >
                                {server.url}
                              </a>
                            </td>
                            <td><code className="text-info">{server.ip_address}</code></td>
                            <td className="text-truncate" style={{ maxWidth: '200px' }} title={server.hostname}>
                              {server.hostname ? (
                                <code className="text-warning">{server.hostname}</code>
                              ) : (
                                <span className="text-muted">N/A</span>
                              )}
                            </td>
                            <td>{server.port}</td>
                            <td>{server.protocol}</td>
                            <td>
                              <Badge bg={getStatusColor(server.status_code)}>
                                {server.status_code || 'N/A'}
                              </Badge>
                            </td>
                            <td className="text-truncate" style={{ maxWidth: '200px' }} title={server.title}>
                              {server.title || 'N/A'}
                            </td>
                            <td className="text-truncate" style={{ maxWidth: '150px' }} title={server.server_header}>
                              {server.server_header || 'N/A'}
                            </td>
                            <td>
                              {server.technologies && server.technologies.length > 0 ? (
                                <div>
                                  {server.technologies.slice(0, 2).map((tech, i) => (
                                    <Badge key={i} bg="secondary" className="me-1 mb-1">
                                      {tech}
                                    </Badge>
                                  ))}
                                  {server.technologies.length > 2 && (
                                    <Badge bg="outline-secondary">+{server.technologies.length - 2}</Badge>
                                  )}
                                </div>
                              ) : (
                                'N/A'
                              )}
                            </td>
                            <td>
                              {isUrlAlreadyScopeTarget(server.url) ? (
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
                                    onClick={() => handleAddAsScopeTarget(server)}
                                    disabled={addingUrls.has(server.url)}
                                  >
                                    {addingUrls.has(server.url) ? (
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
                  )}
                </div>
                {filteredAndSortedServers.length > 0 && (
                  <div className="d-flex justify-content-center mt-4">
                    {renderPagination()}
                  </div>
                )}
              </>
            )}
          </Tab>

          <Tab eventKey="metadata" title="Metadata">
            <div className="mb-3">
              <h5 className="text-danger">Metadata & Analysis</h5>
              <p className="text-white-50 small">
                Detailed metadata information for discovered web servers and assets.
              </p>
            </div>

            {metadataLoading ? (
              <div className="text-center py-4">
                <Spinner animation="border" variant="danger" />
                <p className="mt-2">Loading metadata...</p>
              </div>
            ) : (
              <div>
                {metadataResults.length === 0 ? (
                  <div className="text-center py-5">
                    <div className="text-white-50">
                      <h6>No Metadata Results</h6>
                      <p className="small">
                        {metadataScans.length === 0 
                          ? 'Click "Gather Metadata" to start collecting detailed information about your live web servers.'
                          : 'Metadata scan completed but no results were found. This may indicate no live web servers were available for scanning.'
                        }
                      </p>
                      {metadataScans.length === 0 && (
                        <ul className="list-unstyled small mt-3">
                          <li>• SSL/TLS certificate information</li>
                          <li>• HTTP response headers and security headers</li>
                          <li>• Technology stack detection details</li>
                          <li>• DNS records and subdomain information</li>
                          <li>• Content analysis and file discovery</li>
                        </ul>
                      )}
                    </div>
                  </div>
                ) : (
                  <div>
                    <div className="mb-3">
                      <span className="text-white-50">
                        Total URLs with metadata: <strong className="text-danger">{metadataResults.length}</strong>
                      </span>
                    </div>

                    {metadataResults.map((url, urlIndex) => {
                      const sslIssues = [];
                      if (url.has_deprecated_tls) sslIssues.push('Deprecated TLS');
                      if (url.has_expired_ssl) sslIssues.push('Expired SSL');
                      if (url.has_mismatched_ssl) sslIssues.push('Mismatched SSL');
                      if (url.has_revoked_ssl) sslIssues.push('Revoked SSL');
                      if (url.has_self_signed_ssl) sslIssues.push('Self-Signed SSL');
                      if (url.has_untrusted_root_ssl) sslIssues.push('Untrusted Root');

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
                            console.error('Error parsing katana results:', error);
                          }
                        }
                      }

                      // Process ffuf results
                      let ffufEndpoints = [];
                      if (url.ffuf_results) {
                        if (typeof url.ffuf_results === 'object' && url.ffuf_results.endpoints) {
                          ffufEndpoints = url.ffuf_results.endpoints;
                        } else if (typeof url.ffuf_results === 'string') {
                          try {
                            const parsed = JSON.parse(url.ffuf_results);
                            ffufEndpoints = parsed.endpoints || [];
                          } catch (error) {
                            console.error('Error parsing ffuf results:', error);
                          }
                        }
                      }

                      const findings = Array.isArray(url.findings_json) ? url.findings_json : [];

                      return (
                        <Accordion key={url.id || urlIndex} className="mb-3" data-bs-theme="dark">
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
                                </div>
                              </div>
                            </Accordion.Header>
                            <Accordion.Body>
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
                                  <div className="mb-4">
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
                                <div className="mb-4">
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
                                  console.error('Error parsing response headers:', error);
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

                              <div className="mb-4">
                                <h6 className="text-danger mb-3">Crawled URLs</h6>
                                <div className="ms-3">
                                  <Accordion data-bs-theme="dark">
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
                                  <Accordion data-bs-theme="dark">
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

                              {sslIssues.length > 0 && (
                                <div className="mt-4">
                                  <h6 className="text-danger mb-3">SSL/TLS Issues</h6>
                                  <div className="ms-3">
                                    {sslIssues.map((issue, index) => (
                                      <Badge key={index} bg="danger" className="me-1 mb-1">
                                        {issue}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </Accordion.Body>
                          </Accordion.Item>
                        </Accordion>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer className="bg-dark">
        <Button variant="outline-danger" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default LiveWebServersResultsModal; 