import { useState, useEffect } from 'react';
import { Modal, Button, Tab, Tabs, Table, Badge, Spinner, Alert, Accordion, Form, InputGroup } from 'react-bootstrap';
import { fetchAmassEnumRawResults } from '../utils/fetchAmassEnumRawResults';

export const AmassEnumCompanyResultsModal = ({ 
  show, 
  handleClose, 
  activeTarget, 
  mostRecentAmassEnumCompanyScan 
}) => {
  const [cloudDomains, setCloudDomains] = useState([]);
  const [rawResults, setRawResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [rawResultsLoading, setRawResultsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [rawResultsError, setRawResultsError] = useState(null);
  const [activeTab, setActiveTab] = useState('cloud-domains');
  const [copySuccess, setCopySuccess] = useState(false);
  
  // Filter states
  const [searchFilters, setSearchFilters] = useState([{ searchTerm: '', isNegative: false }]);

  useEffect(() => {
    if (show && mostRecentAmassEnumCompanyScan && mostRecentAmassEnumCompanyScan.scan_id) {
      fetchCloudDomains();
    }
  }, [show, mostRecentAmassEnumCompanyScan]);

  useEffect(() => {
    if (show && mostRecentAmassEnumCompanyScan && mostRecentAmassEnumCompanyScan.scan_id) {
      fetchRawResults();
    }
  }, [show, mostRecentAmassEnumCompanyScan]);

  const fetchCloudDomains = async () => {
    if (!mostRecentAmassEnumCompanyScan || !mostRecentAmassEnumCompanyScan.scan_id) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass-enum-company/${mostRecentAmassEnumCompanyScan.scan_id}/cloud-domains`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch cloud domains');
      }

      const domains = await response.json();
      setCloudDomains(domains || []);
    } catch (error) {
      console.error('Error fetching cloud domains:', error);
      setError('Failed to load cloud domains');
    } finally {
      setLoading(false);
    }
  };

  const fetchRawResults = async () => {
    if (!mostRecentAmassEnumCompanyScan || !mostRecentAmassEnumCompanyScan.scan_id) return;

    setRawResultsLoading(true);
    setRawResultsError(null);

    try {
      const results = await fetchAmassEnumRawResults(mostRecentAmassEnumCompanyScan.scan_id);
      setRawResults(results || []);
    } catch (error) {
      console.error('Error fetching raw results:', error);
      setRawResultsError('Failed to load raw results');
    } finally {
      setRawResultsLoading(false);
    }
  };

  const getCloudProviderBadge = (type) => {
    switch (type) {
      case 'aws':
        return <Badge bg="warning">AWS</Badge>;
      case 'gcp':
        return <Badge bg="info">GCP</Badge>;
      case 'azure':
        return <Badge bg="primary">Azure</Badge>;
      default:
        return <Badge bg="secondary">Other</Badge>;
    }
  };

  const getFilteredCloudDomains = () => {
    return cloudDomains.filter(domain => {
      const activeFilters = searchFilters.filter(filter => filter.searchTerm.trim() !== '');
      
      if (activeFilters.length > 0) {
        return activeFilters.every(filter => {
          const domainContainsSearch = domain.domain.toLowerCase().includes(filter.searchTerm.toLowerCase());
          return filter.isNegative ? !domainContainsSearch : domainContainsSearch;
        });
      }
      
      return true;
    });
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

  const getCloudDomainsTabTitle = () => {
    const filteredCount = getFilteredCloudDomains().length;
    const totalCount = cloudDomains.length;
    const hasActiveFilters = searchFilters.some(filter => filter.searchTerm.trim() !== '');
    
    if (hasActiveFilters) {
      return `Cloud Domains (${filteredCount}/${totalCount})`;
    }
    return `Cloud Domains (${totalCount})`;
  };

  const copyFilteredCloudDomains = async () => {
    const filteredDomains = getFilteredCloudDomains();
    const domains = filteredDomains.map(domain => domain.domain).join('\n');

    try {
      await navigator.clipboard.writeText(domains);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const renderCloudDomains = () => {
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

    if (cloudDomains.length === 0) {
      return (
        <div className="text-center py-5">
          <div className="text-white-50 mb-3">
            <i className="bi bi-cloud" style={{ fontSize: '3rem' }}></i>
          </div>
          <h5 className="text-white-50 mb-3">No Cloud Domains Found</h5>
          <p className="text-white-50">
            The scan completed but no cloud domains were discovered. This could mean:
          </p>
          <ul className="list-unstyled text-white-50 small">
            <li>• The domains don't use cloud services</li>
            <li>• Cloud assets are using custom domain names</li>
            <li>• The DNS enumeration didn't find cloud-hosted subdomains</li>
          </ul>
        </div>
      );
    }

    const filteredDomains = getFilteredCloudDomains();

    const filteredCount = filteredDomains.length;
    const totalCount = cloudDomains.length;
    const hasActiveFilters = searchFilters.some(filter => filter.searchTerm.trim() !== '');
    const titleText = hasActiveFilters 
      ? `Cloud Domains (${filteredCount}/${totalCount})`
      : `Cloud Domains (${totalCount})`;

    return (
      <>
        <div className="mb-3">
          <div className="d-flex justify-content-between align-items-center mb-2">
            <h5 className="text-light mb-0">{titleText}</h5>
            <Button
              variant={copySuccess ? "success" : "outline-secondary"}
              size="sm"
              onClick={copyFilteredCloudDomains}
            >
              {copySuccess ? (
                <>
                  <i className="bi bi-check-circle me-1"></i>
                  Copied!
                </>
              ) : (
                <>
                  <i className="bi bi-clipboard me-1"></i>
                  Copy Filtered Cloud Domains to Clipboard
                </>
              )}
            </Button>
          </div>
        </div>

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
            <div key={index} className={index > 0 ? "mt-2" : ""}>
              <InputGroup>
                <Form.Control
                  type="text"
                  placeholder="Search cloud domains..."
                  value={filter.searchTerm}
                  onChange={(e) => updateSearchFilter(index, 'searchTerm', e.target.value)}
                  data-bs-theme="dark"
                />
                <InputGroup.Text className="bg-dark border-secondary">
                  <Form.Check
                    type="checkbox"
                    id={`negative-search-checkbox-${index}`}
                    label="Negative Search"
                    checked={filter.isNegative}
                    onChange={(e) => updateSearchFilter(index, 'isNegative', e.target.checked)}
                    className="text-white-50 small m-0"
                    disabled={!filter.searchTerm}
                  />
                </InputGroup.Text>
                {filter.searchTerm && (
                  <Button 
                    variant="outline-secondary" 
                    onClick={() => updateSearchFilter(index, 'searchTerm', '')}
                    title="Clear this search"
                  >
                    ×
                  </Button>
                )}
                {searchFilters.length > 1 && (
                  <Button 
                    variant="outline-danger" 
                    onClick={() => removeSearchFilter(index)}
                    title="Remove this filter"
                  >
                    🗑️
                  </Button>
                )}
              </InputGroup>
            </div>
          ))}
        </div>

        {/* Results Summary */}
        <div className="mb-3 d-flex justify-content-between align-items-center">
          <small className="text-white-50">
            Showing {filteredDomains.length} of {cloudDomains.length} cloud domains
            {(() => {
              const activeFilters = searchFilters.filter(filter => filter.searchTerm.trim() !== '');
              if (activeFilters.length > 0) {
                const filterDescriptions = activeFilters.map(filter => 
                  `${filter.isNegative ? 'excluding' : 'including'} "${filter.searchTerm}"`
                );
                return (
                  <span className="text-warning">
                    {' '}({filterDescriptions.join(', ')})
                  </span>
                );
              }
              return null;
            })()}
          </small>
        </div>

        {/* Results Table */}
        {filteredDomains.length === 0 ? (
          <div className="text-center py-4">
            <div className="text-white-50 mb-3">
              <i className="bi bi-funnel" style={{ fontSize: '2rem' }}></i>
            </div>
            <h6 className="text-white-50">No domains match your filters</h6>
            <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
              Clear Filters
            </Button>
          </div>
        ) : (
          <Table striped bordered hover responsive variant="dark">
            <thead>
              <tr>
                <th>Cloud Domain</th>
                <th>Original Domain</th>
                <th>Provider</th>
                <th>Discovered</th>
              </tr>
            </thead>
            <tbody>
              {filteredDomains.map((domain, index) => (
                <tr key={index}>
                  <td className="font-monospace" style={{ fontSize: '0.875rem' }}>
                    <a 
                      href={`https://${domain.domain}`} 
                      target="_blank" 
                      rel="noopener noreferrer" 
                      className="text-decoration-none text-warning"
                      style={{ cursor: 'pointer' }}
                    >
                      {domain.domain}
                    </a>
                  </td>
                  <td className="font-monospace" style={{ fontSize: '0.875rem' }}>
                    {domain.root_domain ? (
                      <a 
                        href={`https://${domain.root_domain}`} 
                        target="_blank" 
                        rel="noopener noreferrer" 
                        className="text-decoration-none text-warning"
                        style={{ cursor: 'pointer' }}
                      >
                        {domain.root_domain}
                      </a>
                    ) : (
                      'N/A'
                    )}
                  </td>
                  <td>{getCloudProviderBadge(domain.type)}</td>
                  <td style={{ fontSize: '0.875rem' }}>{new Date(domain.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </>
    );
  };

  const renderRawResults = () => {
    if (rawResultsLoading) {
      return (
        <div className="text-center py-4">
          <Spinner animation="border" role="status" variant="danger">
            <span className="visually-hidden">Loading raw results...</span>
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
          <h5 className="text-white-50 mb-3">No Raw Results Available</h5>
          <p className="text-white-50">
            Raw scan results are not available for this scan.
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
                <span className="font-monospace text-white">{result.domain}</span>
                <small className="text-white-50">
                  {new Date(result.created_at).toLocaleString()}
                </small>
              </div>
            </Accordion.Header>
            <Accordion.Body className="bg-dark">
              <div className="bg-black text-light p-3 rounded border border-secondary" style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: '#00ff00' }}>
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
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Amass Enum Company Results</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="mb-3"
          variant="pills"
        >
          <Tab eventKey="cloud-domains" title={getCloudDomainsTabTitle()}>
            {renderCloudDomains()}
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

export default AmassEnumCompanyResultsModal; 