import { useState, useEffect } from 'react';
import { Modal, Button, Tab, Tabs, Table, Badge, Spinner, Alert, Accordion, Form, InputGroup } from 'react-bootstrap';
import { fetchDNSxRawResults } from '../utils/fetchDNSxRawResults';

export const DNSxCompanyResultsModal = ({ 
  show, 
  handleClose, 
  activeTarget, 
  mostRecentDNSxCompanyScan 
}) => {
  const [dnsRecords, setDNSRecords] = useState([]);
  const [rawResults, setRawResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [rawResultsLoading, setRawResultsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [rawResultsError, setRawResultsError] = useState(null);
  const [activeTab, setActiveTab] = useState('dns-records');
  
  // Filter states
  const [searchFilters, setSearchFilters] = useState([{ searchTerm: '', isNegative: false }]);
  
  // Sort states
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });

  useEffect(() => {
    if (show && mostRecentDNSxCompanyScan && mostRecentDNSxCompanyScan.scan_id) {
      fetchDNSRecords();
    }
  }, [show, mostRecentDNSxCompanyScan]);

  useEffect(() => {
    if (show && mostRecentDNSxCompanyScan && mostRecentDNSxCompanyScan.scan_id) {
      fetchRawResults();
    }
  }, [show, mostRecentDNSxCompanyScan]);

  const fetchDNSRecords = async () => {
    if (!mostRecentDNSxCompanyScan || !mostRecentDNSxCompanyScan.scan_id) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/dnsx-company/${mostRecentDNSxCompanyScan.scan_id}/dns-records`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch DNS records');
      }

      const records = await response.json();
      setDNSRecords(records || []);
    } catch (error) {
      console.error('Error fetching DNS records:', error);
      setError('Failed to load DNS records');
    } finally {
      setLoading(false);
    }
  };

  const fetchRawResults = async () => {
    if (!mostRecentDNSxCompanyScan || !mostRecentDNSxCompanyScan.scan_id) return;

    setRawResultsLoading(true);
    setRawResultsError(null);

    try {
      const results = await fetchDNSxRawResults(mostRecentDNSxCompanyScan.scan_id);
      setRawResults(results || []);
    } catch (error) {
      console.error('Error fetching raw results:', error);
      setRawResultsError('Failed to load raw results');
    } finally {
      setRawResultsLoading(false);
    }
  };

  const getRecordTypeBadge = (type) => {
    switch (type) {
      case 'A':
        return <Badge bg="success">A</Badge>;
      case 'AAAA':
        return <Badge bg="info">AAAA</Badge>;
      case 'CNAME':
        return <Badge bg="warning">CNAME</Badge>;
      case 'MX':
        return <Badge bg="danger">MX</Badge>;
      case 'NS':
        return <Badge bg="primary">NS</Badge>;
      case 'TXT':
        return <Badge bg="secondary">TXT</Badge>;
      case 'PTR':
        return <Badge bg="dark">PTR</Badge>;
      case 'SRV':
        return <Badge bg="purple">SRV</Badge>;
      default:
        return <Badge bg="secondary">{type}</Badge>;
    }
  };

  const getFilteredDNSRecords = () => {
    const filtered = dnsRecords.filter(record => {
      const activeFilters = searchFilters.filter(filter => filter.searchTerm.trim() !== '');
      
      if (activeFilters.length > 0) {
        return activeFilters.every(filter => {
          const searchTerm = filter.searchTerm.toLowerCase();
          const recordContainsSearch = 
            (record.domain && record.domain.toLowerCase().includes(searchTerm)) ||
            (record.record && record.record.toLowerCase().includes(searchTerm)) ||
            (record.record_type && record.record_type.toLowerCase().includes(searchTerm)) ||
            (record.type && record.type.toLowerCase().includes(searchTerm));
          return filter.isNegative ? !recordContainsSearch : recordContainsSearch;
        });
      }
      
      return true;
    });

    return getSortedRecords(filtered);
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

  const getSortedRecords = (records) => {
    if (!sortConfig.key) return records;

    return [...records].sort((a, b) => {
      let aValue = a[sortConfig.key];
      let bValue = b[sortConfig.key];

      // Handle different data types
      if (sortConfig.key === 'created_at') {
        aValue = new Date(aValue);
        bValue = new Date(bValue);
      } else if (sortConfig.key === 'record_type' || sortConfig.key === 'type') {
        // For record type, use the type field consistently
        aValue = a.record_type || a.type;
        bValue = b.record_type || b.type;
      }

      // Convert to strings for comparison if not dates
      if (!(aValue instanceof Date)) {
        aValue = String(aValue || '').toLowerCase();
        bValue = String(bValue || '').toLowerCase();
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

  const getDNSRecordsTabTitle = () => {
    const filteredCount = getFilteredDNSRecords().length;
    const totalCount = dnsRecords.length;
    const hasActiveFilters = searchFilters.some(filter => filter.searchTerm.trim() !== '');
    
    if (hasActiveFilters) {
      return `DNS Records (${filteredCount}/${totalCount})`;
    }
    return `DNS Records (${totalCount})`;
  };

  const renderDNSRecords = () => {
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

    if (dnsRecords.length === 0) {
      return (
        <div className="text-center py-5">
          <div className="text-white-50 mb-3">
            <i className="bi bi-dns" style={{ fontSize: '3rem' }}></i>
          </div>
          <h5 className="text-white-50 mb-3">No DNS Records Found</h5>
          <p className="text-white-50">
            The scan completed but no DNS records were discovered. This could mean:
          </p>
          <ul className="list-unstyled text-white-50 small">
            <li>• The domains may not have standard DNS records</li>
            <li>• DNS resolution may have failed</li>
            <li>• The domains may be configured with minimal DNS setup</li>
          </ul>
        </div>
      );
    }

    const filteredRecords = getFilteredDNSRecords();

    return (
      <>
        {/* Filter Controls */}
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
                  placeholder="Search domains, records, or types..."
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
            Showing {filteredRecords.length} of {dnsRecords.length} DNS records
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
                    width: '15%', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => handleSort('record_type')}
                >
                  Type{getSortIcon('record_type')}
                </th>
                <th 
                  className="sortable-header"
                  style={{ 
                    backgroundColor: 'var(--bs-dark)', 
                    width: '40%', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => handleSort('record')}
                >
                  Record{getSortIcon('record')}
                </th>
                <th 
                  className="sortable-header"
                  style={{ 
                    backgroundColor: 'var(--bs-dark)', 
                    width: '20%', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                  onClick={() => handleSort('created_at')}
                >
                  Discovered{getSortIcon('created_at')}
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredRecords.map((record, index) => (
                <tr key={index}>
                  <td className="text-info" style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                    {record.domain}
                  </td>
                  <td>
                    {getRecordTypeBadge(record.record_type || record.type)}
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                    {record.record}
                  </td>
                  <td className="text-white-50 small">
                    {record.created_at ? new Date(record.created_at).toLocaleString() : 'N/A'}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>

        {filteredRecords.length === 0 && dnsRecords.length > 0 && (
          <div className="text-center py-4">
            <i className="bi bi-funnel text-white-50" style={{ fontSize: '2rem' }}></i>
            <h6 className="text-white-50 mt-2">No DNS records match the current filters</h6>
            <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
              Clear Filters
            </Button>
          </div>
        )}
      </>
    );
  };

  const renderRawResults = () => {
    if (rawResultsLoading) {
      return (
        <div className="text-center py-4">
          <Spinner animation="border" role="status" variant="danger">
            <span className="visually-hidden">Loading...</span>
          </Spinner>
        </div>
      );
    }

    if (rawResultsError) {
      return (
        <Alert variant="danger">
          {rawResultsError}
        </Alert>
      );
    }

    if (rawResults.length === 0) {
      return (
        <div className="text-center py-5">
          <div className="text-white-50 mb-3">
            <i className="bi bi-file-text" style={{ fontSize: '3rem' }}></i>
          </div>
          <h5 className="text-white-50">No Raw Results Available</h5>
          <p className="text-white-50">
            Raw scan output is not available for this scan.
          </p>
        </div>
      );
    }

    return (
      <Accordion data-bs-theme="dark">
        {rawResults.map((result, index) => (
          <Accordion.Item eventKey={index.toString()} key={index} className="bg-dark border-secondary">
            <Accordion.Header className="bg-dark">
              <div className="d-flex justify-content-between align-items-center w-100 me-3">
                <div className="d-flex align-items-center">
                  <Badge bg="info" className="me-2">Domain</Badge>
                  <span className="text-white font-monospace">{result.domain}</span>
                </div>
                <div className="text-white-50 small">
                  {result.created_at ? new Date(result.created_at).toLocaleString() : 'N/A'}
                </div>
              </div>
            </Accordion.Header>
            <Accordion.Body className="bg-dark">
              <div className="bg-black p-3 rounded border border-secondary">
                <pre className="text-white-50 mb-0 small" style={{ 
                  whiteSpace: 'pre-wrap', 
                  maxHeight: '300px', 
                  overflow: 'auto',
                  fontSize: '0.8rem'
                }}>
                  {result.raw_output || 'No output available'}
                </pre>
              </div>
            </Accordion.Body>
          </Accordion.Item>
        ))}
      </Accordion>
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
          <i className="bi bi-dns me-2" />
          DNSx Company Scan Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {mostRecentDNSxCompanyScan && (
          <div className="mb-3">
            <div className="d-flex justify-content-between align-items-center">
              <div>
                <h6 className="text-white mb-1">
                  Latest Scan: {mostRecentDNSxCompanyScan.scan_id}
                </h6>
                <div className="text-white-50 small">
                  Status: <Badge className={`${
                    mostRecentDNSxCompanyScan.status === 'success' ? 'bg-success' : 
                    mostRecentDNSxCompanyScan.status === 'error' ? 'bg-danger' : 
                    'bg-warning'
                  }`}>
                    {mostRecentDNSxCompanyScan.status}
                  </Badge>
                  {mostRecentDNSxCompanyScan.created_at && (
                    <span className="ms-2">
                      • {new Date(mostRecentDNSxCompanyScan.created_at).toLocaleString()}
                    </span>
                  )}
                  {mostRecentDNSxCompanyScan.execution_time && (
                    <span className="ms-2">
                      • Duration: {mostRecentDNSxCompanyScan.execution_time}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        <Tabs
          activeKey={activeTab}
          onSelect={(key) => setActiveTab(key)}
          className="mb-3"
          variant="pills"
        >
          <Tab eventKey="dns-records" title={getDNSRecordsTabTitle()}>
            {renderDNSRecords()}
          </Tab>
          <Tab eventKey="raw-results" title={`Raw Results (${rawResults.length})`}>
            {renderRawResults()}
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}; 