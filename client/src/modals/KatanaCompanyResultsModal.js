import React, { useState, useEffect, useMemo } from 'react';
import { Modal, Table, Badge, Alert, Tabs, Tab, Card, Row, Col, Button, Spinner, Form, InputGroup } from 'react-bootstrap';

const KatanaCompanyResultsModal = ({ show, handleClose, activeTarget, mostRecentKatanaCompanyScan }) => {
  const [cloudAssets, setCloudAssets] = useState([]);
  const [allAvailableDomains, setAllAvailableDomains] = useState([]);
  const [baseDomains, setBaseDomains] = useState([]);
  const [wildcardDomains, setWildcardDomains] = useState([]);
  const [liveWebServers, setLiveWebServers] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const [lastLoadedScanId, setLastLoadedScanId] = useState(null);

  const [searchFilters, setSearchFilters] = useState([{ searchTerm: '', isNegative: false }]);
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });
  const [copySuccess, setCopySuccess] = useState(false);

  // Combine all available domains like the config modal
  const combinedDomains = useMemo(() => {
    const combined = [];
    
    // Add consolidated company domains
    baseDomains.forEach(domain => {
      combined.push({
        domain,
        type: 'root',
        source: 'Company Domains',
        isWildcardTarget: wildcardDomains.some(wd => wd.rootDomain === domain)
      });
    });
    
    // Add wildcard discovered domains
    wildcardDomains.forEach(wd => {
      wd.discoveredDomains.forEach(discoveredDomain => {
        if (!combined.some(item => item.domain === discoveredDomain)) {
          combined.push({
            domain: discoveredDomain,
            type: 'wildcard',
            source: 'Wildcard Results',
            rootDomain: wd.wildcardTarget || wd.rootDomain
          });
        }
      });
    });
    
    // Add live web servers
    liveWebServers.forEach(server => {
      const domain = server.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      if (!combined.some(item => item.domain === domain)) {
        combined.push({
          domain: domain,
          type: 'live',
          source: 'Live Web Servers',
          url: server
        });
      }
    });
    
    return combined.sort((a, b) => a.domain.localeCompare(b.domain));
  }, [baseDomains, wildcardDomains, liveWebServers]);

  useEffect(() => {
    // Only load results when modal opens OR when we get a different scan_id
    if (show && mostRecentKatanaCompanyScan?.scan_id && 
        mostRecentKatanaCompanyScan.scan_id !== lastLoadedScanId) {
      loadResults();
      setLastLoadedScanId(mostRecentKatanaCompanyScan.scan_id);
    }
    
    // Load domains when modal opens
    if (show && activeTarget?.id) {
      loadAllAvailableDomains();
    }
  }, [show, mostRecentKatanaCompanyScan?.scan_id, activeTarget?.id]);

  // Update allAvailableDomains when combinedDomains changes
  useEffect(() => {
    setAllAvailableDomains(combinedDomains);
  }, [combinedDomains]);

  // Load wildcard domains and live web servers when baseDomains changes
  useEffect(() => {
    if (baseDomains.length > 0) {
      fetchWildcardDomains();
      fetchLiveWebServers();
    }
  }, [baseDomains]);

  const loadResults = async () => {
    if (!activeTarget?.id) return;

    setIsLoading(true);
    setError('');
    
    try {
      const assetsResponse = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/katana-company/target/${activeTarget.id}/cloud-assets`
      );

      if (!assetsResponse.ok) {
        throw new Error('Failed to fetch cloud assets');
      }

      const assets = await assetsResponse.json();

      setCloudAssets(assets || []);
    } catch (error) {
      console.error('Error fetching Katana Company results:', error);
      setError('Failed to load cloud assets');
    } finally {
      setIsLoading(false);
    }
  };

  const loadAllAvailableDomains = async () => {
    if (!activeTarget?.id) return;
    
    try {
      // Use the same endpoint as the config modal
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/consolidated-company-domains/${activeTarget.id}`
      );
      
      if (response.ok) {
        const data = await response.json();
        if (data.domains && Array.isArray(data.domains)) {
          setBaseDomains(data.domains);
        } else {
          setBaseDomains([]);
        }
      } else {
        console.warn('Failed to fetch consolidated company domains');
        setBaseDomains([]);
      }
    } catch (error) {
      console.error('Error fetching all available domains:', error);
      setBaseDomains([]);
    }
  };

  const fetchWildcardDomains = async () => {
    if (!activeTarget?.id) return;

    try {
      // Get all scope targets to find which root domains have been added as wildcard targets
      const scopeTargetsResponse = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/read`
      );
      
      if (!scopeTargetsResponse.ok) {
        throw new Error('Failed to fetch scope targets');
      }

      const scopeTargetsData = await scopeTargetsResponse.json();
      
      // Check if response is directly an array or has a targets property
      const targets = Array.isArray(scopeTargetsData) ? scopeTargetsData : scopeTargetsData.targets;
      
      // Ensure we have valid targets data
      if (!targets || !Array.isArray(targets)) {
        console.log('No valid targets data found:', scopeTargetsData);
        setWildcardDomains([]);
        return;
      }

      const wildcardTargets = targets.filter(target => {
        if (!target || target.type !== 'Wildcard') return false;
        
        // Remove *. prefix from wildcard target to match with base domains
        const rootDomainFromWildcard = target.scope_target.startsWith('*.') 
          ? target.scope_target.substring(2) 
          : target.scope_target;
        
        const isMatch = baseDomains.includes(rootDomainFromWildcard);
        
        return isMatch;
      });

      const wildcardDomainsData = [];

      // For each wildcard target, fetch its live web servers
      for (const wildcardTarget of wildcardTargets) {
        try {
          const liveWebServersResponse = await fetch(
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/scope-targets/${wildcardTarget.id}/target-urls`
          );

          if (liveWebServersResponse.ok) {
            const liveWebServersData = await liveWebServersResponse.json();
            
            // Check if response is directly an array or has a target_urls property
            const targetUrls = Array.isArray(liveWebServersData) ? liveWebServersData : liveWebServersData.target_urls;
            
            // Ensure we have valid target_urls data
            if (!targetUrls || !Array.isArray(targetUrls)) {
              continue;
            }

            const discoveredDomains = Array.from(new Set(
              targetUrls
                .map(url => {
                  try {
                    if (!url || !url.url) return null;
                    const urlObj = new URL(url.url);
                    return urlObj.hostname;
                  } catch {
                    return null;
                  }
                })
                .filter(domain => domain && domain !== wildcardTarget.scope_target)
            ));

            if (discoveredDomains.length > 0) {
              const rootDomainFromWildcard = wildcardTarget.scope_target.startsWith('*.') 
                ? wildcardTarget.scope_target.substring(2) 
                : wildcardTarget.scope_target;
              
              wildcardDomainsData.push({
                rootDomain: rootDomainFromWildcard,
                wildcardTarget: wildcardTarget.scope_target,
                discoveredDomains
              });
            }
          }
        } catch (error) {
          console.error(`Error fetching live web servers for ${wildcardTarget.scope_target}:`, error);
        }
      }

      setWildcardDomains(wildcardDomainsData);
    } catch (error) {
      console.error('Error fetching wildcard domains:', error);
      setWildcardDomains([]);
    }
  };

  const fetchLiveWebServers = async () => {
    if (!activeTarget?.id) return;

    try {
      // Fetch live web servers from IP port scans
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/ip-port-scans/${activeTarget.id}`
      );
      
      if (response.ok) {
        const data = await response.json();
        
        if (data && Array.isArray(data) && data.length > 0) {
          // Get the most recent scan
          const latestScan = data[0];
          
          if (latestScan && latestScan.scan_id) {
            // Fetch live web servers for the latest scan
            const liveWebServersResponse = await fetch(
              `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/live-web-servers/${latestScan.scan_id}`
            );
            
            if (liveWebServersResponse.ok) {
              const liveWebServersData = await liveWebServersResponse.json();
              
              if (liveWebServersData && Array.isArray(liveWebServersData)) {
                const urls = liveWebServersData.map(server => server.url).filter(url => url);
                setLiveWebServers(urls);
              } else {
                setLiveWebServers([]);
              }
            } else {
              setLiveWebServers([]);
            }
          } else {
            setLiveWebServers([]);
          }
        } else {
          setLiveWebServers([]);
        }
      } else {
        setLiveWebServers([]);
      }
    } catch (error) {
      console.error('Error fetching live web servers:', error);
      setLiveWebServers([]);
    }
  };

  const getServiceBadgeVariant = (service) => {
    if (service.includes('aws')) return 'warning';
    if (service.includes('gcp')) return 'info';
    if (service.includes('azure')) return 'primary';
    return 'secondary';
  };

  const copyCloudAssetDomains = async () => {
    const domains = cloudAssets.map(asset => {
      return asset.url.replace(/^https?:\/\//, '');
    }).join('\n');

    try {
      await navigator.clipboard.writeText(domains);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const copySingleDomain = async (domain) => {
    try {
      await navigator.clipboard.writeText(domain);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const getServiceName = (service) => {
    const parts = service.split('_');
    if (parts.length >= 2) {
      return `${parts[0].toUpperCase()} ${parts[1]}`;
    }
    return service.toUpperCase();
  };

  const getFilteredCloudAssets = () => {
    const filtered = cloudAssets.filter(asset => {
      const activeFilters = searchFilters.filter(filter => filter.searchTerm.trim() !== '');
      
      if (activeFilters.length > 0) {
        return activeFilters.every(filter => {
          const searchTerm = filter.searchTerm.toLowerCase();
          const cloudAssetFQDN = asset.url.replace(/^https?:\/\//, '');
          const sourceURL = asset.source_url || asset.url;
          const serviceName = getServiceName(asset.service);
          
          const assetContainsSearch = 
            (asset.service && asset.service.toLowerCase().includes(searchTerm)) ||
            (serviceName && serviceName.toLowerCase().includes(searchTerm)) ||
            (cloudAssetFQDN && cloudAssetFQDN.toLowerCase().includes(searchTerm)) ||
            (sourceURL && sourceURL.toLowerCase().includes(searchTerm));
          return filter.isNegative ? !assetContainsSearch : assetContainsSearch;
        });
      }
      
      return true;
    });

    return getSortedAssets(filtered);
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

  const getSortedAssets = (assets) => {
    if (!sortConfig.key) return assets;

    return [...assets].sort((a, b) => {
      let aValue, bValue;

      if (sortConfig.key === 'service') {
        aValue = getServiceName(a.service);
        bValue = getServiceName(b.service);
      } else if (sortConfig.key === 'cloudAsset') {
        aValue = a.url.replace(/^https?:\/\//, '');
        bValue = b.url.replace(/^https?:\/\//, '');
      } else if (sortConfig.key === 'source') {
        aValue = a.source_url || a.url;
        bValue = b.source_url || b.url;
      } else {
        aValue = a[sortConfig.key];
        bValue = b[sortConfig.key];
      }

      aValue = String(aValue || '').toLowerCase();
      bValue = String(bValue || '').toLowerCase();

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

  const getCloudAssetsTitle = () => {
    const filteredCount = getFilteredCloudAssets().length;
    const totalCount = cloudAssets.length;
    const hasActiveFilters = searchFilters.some(filter => filter.searchTerm.trim() !== '');
    
    if (hasActiveFilters) {
      return `Cloud Assets (${filteredCount}/${totalCount})`;
    }
    return `Cloud Assets (${totalCount})`;
  };

  const handleModalClose = () => {
    setError('');
    setAllAvailableDomains([]);
    setBaseDomains([]);
    setWildcardDomains([]);
    setLiveWebServers([]);
    setLastLoadedScanId(null);
    setSearchFilters([{ searchTerm: '', isNegative: false }]);
    setSortConfig({ key: null, direction: 'asc' });
    handleClose();
  };

  return (
    <>
      <style>
        {`
          .katana-modal-wide .modal-dialog {
            max-width: 1400px;
            width: 95vw;
          }
        `}
      </style>
      <Modal 
        show={show} 
        onHide={handleModalClose} 
        backdrop={true}
        className="text-light katana-modal-wide"
        contentClassName="bg-dark border-secondary"
      >
      <Modal.Header closeButton className="bg-dark border-secondary">
        <Modal.Title className="text-light">
          Katana Company Scan Results - Cloud Asset Enumeration
          {activeTarget && (
            <div className="text-light fs-6 fw-normal mt-1" style={{ opacity: 0.8 }}>
              {activeTarget.scope_target}
            </div>
          )}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark text-light">
        {error && <Alert variant="danger" className="bg-danger bg-opacity-10 border-danger text-light">{error}</Alert>}
        
        {cloudAssets.length > 0 && (
          <div className="mb-3 d-flex justify-content-end">
            <Button
              variant={copySuccess ? "success" : "outline-secondary"}
              size="sm"
              onClick={copyCloudAssetDomains}
            >
              {copySuccess ? (
                <>
                  <i className="bi bi-check-circle me-1"></i>
                  Copied!
                </>
              ) : (
                <>
                  <i className="bi bi-clipboard me-1"></i>
                  Copy All Cloud Domains to Clipboard
                </>
              )}
            </Button>
          </div>
        )}
        
        {(mostRecentKatanaCompanyScan || cloudAssets.length > 0) && (
          <div className="mb-3">
            <Row>
              <Col md={6}>
                <Card className="h-100 bg-dark border-secondary">
                  <Card.Body>
                    <Card.Title className="fs-6 text-light">Scan Progress</Card.Title>
                    <div className="d-flex align-items-center">
                      <div className="flex-grow-1">
                        <p className="mb-1 text-light"><strong>Total Domains:</strong> {allAvailableDomains.length}</p>
                        <p className="mb-1 text-light"><strong>Latest Scan:</strong> {mostRecentKatanaCompanyScan?.execution_time || 'N/A'}</p>
                      </div>
                    </div>
                  </Card.Body>
                </Card>
              </Col>
              <Col md={6}>
                <Card className="h-100 bg-dark border-secondary">
                  <Card.Body>
                    <Card.Title className="fs-6 text-light">Discovery Summary</Card.Title>
                    <div className="d-flex align-items-center">
                      <div className="flex-grow-1">
                        <p className="mb-1 text-light"><strong>Cloud Assets:</strong> {cloudAssets.length}</p>
                        <p className="mb-1 text-light"><strong>AWS:</strong> <Badge bg="warning" style={{ backgroundColor: '#d35400', color: '#fff' }}>{cloudAssets.filter(a => a.service.includes('aws')).length}</Badge></p>
                        <p className="mb-0 text-light"><strong>GCP:</strong> <Badge bg="info">{cloudAssets.filter(a => a.service.includes('gcp')).length}</Badge> <strong>Azure:</strong> <Badge bg="primary">{cloudAssets.filter(a => a.service.includes('azure')).length}</Badge></p>
                      </div>
                      <div className="ms-3">
                        {cloudAssets.length > 0 && (
                          <div className="position-relative d-flex align-items-center justify-content-center" style={{ width: '80px', height: '80px' }}>
                            <svg width="80" height="80" viewBox="0 0 42 42" className="position-absolute">
                              {(() => {
                                const awsCount = cloudAssets.filter(a => a.service.includes('aws')).length;
                                const gcpCount = cloudAssets.filter(a => a.service.includes('gcp')).length;
                                const azureCount = cloudAssets.filter(a => a.service.includes('azure')).length;
                                const total = cloudAssets.length;
                                
                                const awsPercent = (awsCount / total) * 100;
                                const gcpPercent = (gcpCount / total) * 100;
                                const azurePercent = (azureCount / total) * 100;
                                
                                let offset = 25; // Start at top
                                const elements = [];
                                
                                // AWS segment (orange)
                                if (awsCount > 0) {
                                  elements.push(
                                    <circle 
                                      key="aws"
                                      cx="21" 
                                      cy="21" 
                                      r="15.9" 
                                      fill="transparent" 
                                      stroke="#ffc107" 
                                      strokeWidth="3"
                                      strokeDasharray={`${awsPercent.toFixed(1)} ${100 - awsPercent.toFixed(1)}`}
                                      strokeDashoffset={offset}
                                      transform="rotate(-90 21 21)"
                                      style={{ transition: 'stroke-dasharray 0.6s ease-in-out' }}
                                    />
                                  );
                                  offset += awsPercent;
                                }
                                
                                // GCP segment (blue)
                                if (gcpCount > 0) {
                                  elements.push(
                                    <circle 
                                      key="gcp"
                                      cx="21" 
                                      cy="21" 
                                      r="15.9" 
                                      fill="transparent" 
                                      stroke="#0dcaf0" 
                                      strokeWidth="3"
                                      strokeDasharray={`${gcpPercent.toFixed(1)} ${100 - gcpPercent.toFixed(1)}`}
                                      strokeDashoffset={offset}
                                      transform="rotate(-90 21 21)"
                                      style={{ transition: 'stroke-dasharray 0.6s ease-in-out' }}
                                    />
                                  );
                                  offset += gcpPercent;
                                }
                                
                                // Azure segment (purple)
                                if (azureCount > 0) {
                                  elements.push(
                                    <circle 
                                      key="azure"
                                      cx="21" 
                                      cy="21" 
                                      r="15.9" 
                                      fill="transparent" 
                                      stroke="#6f42c1" 
                                      strokeWidth="3"
                                      strokeDasharray={`${azurePercent.toFixed(1)} ${100 - azurePercent.toFixed(1)}`}
                                      strokeDashoffset={offset}
                                      transform="rotate(-90 21 21)"
                                      style={{ transition: 'stroke-dasharray 0.6s ease-in-out' }}
                                    />
                                  );
                                }
                                
                                return elements;
                              })()}
                            </svg>
                            <div className="position-absolute text-center">
                              <div className="text-light fw-bold" style={{ fontSize: '16px' }}>
                                {cloudAssets.length}
                              </div>
                              <div className="text-light" style={{ fontSize: '10px', opacity: 0.7 }}>
                                Assets
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </Card.Body>
                </Card>
              </Col>
            </Row>
          </div>
        )}

        <div className="mb-3">
          <h5 className="text-light">{getCloudAssetsTitle()}</h5>
          {isLoading ? (
            <div className="text-center py-4 text-light">Loading cloud assets...</div>
          ) : cloudAssets.length > 0 ? (
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
                        placeholder="Search service, asset, or source..."
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
                  Showing {getFilteredCloudAssets().length} of {cloudAssets.length} cloud assets
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
                <Table responsive size="sm" variant="dark" className="border-secondary" style={{ tableLayout: 'fixed', width: '100%' }}>
                  <thead style={{ position: 'sticky', top: 0, zIndex: 10 }}>
                    <tr>
                      <th 
                        className="sortable-header"
                        style={{ 
                          backgroundColor: 'var(--bs-dark)', 
                          width: '15%', 
                          cursor: 'pointer',
                          userSelect: 'none'
                        }}
                        onClick={() => handleSort('service')}
                      >
                        Service{getSortIcon('service')}
                      </th>
                      <th 
                        className="sortable-header"
                        style={{ 
                          backgroundColor: 'var(--bs-dark)', 
                          width: '42.5%', 
                          cursor: 'pointer',
                          userSelect: 'none'
                        }}
                        onClick={() => handleSort('cloudAsset')}
                      >
                        Cloud Asset{getSortIcon('cloudAsset')}
                      </th>
                      <th 
                        className="sortable-header"
                        style={{ 
                          backgroundColor: 'var(--bs-dark)', 
                          width: '42.5%', 
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
                    {getFilteredCloudAssets().map((asset, index) => {
                      const cloudAssetFQDN = asset.url.replace(/^https?:\/\//, '');
                      const sourceURL = asset.source_url || asset.url;
                      
                      return (
                        <tr key={index}>
                          <td>
                            <Badge 
                              bg={getServiceBadgeVariant(asset.service)}
                              style={asset.service.includes('aws') ? { backgroundColor: '#d35400', color: '#fff' } : {}}
                            >
                              {getServiceName(asset.service)}
                            </Badge>
                          </td>
                          <td>
                            <code 
                              className="text-warning" 
                              style={{ 
                                fontFamily: 'monospace', 
                                fontSize: '0.875rem',
                                cursor: 'pointer',
                                userSelect: 'none'
                              }}
                              onClick={() => copySingleDomain(cloudAssetFQDN)}
                              title="Click to copy to clipboard"
                            >
                              {cloudAssetFQDN}
                            </code>
                          </td>
                          <td>
                            <a href={sourceURL} target="_blank" rel="noopener noreferrer" className="text-decoration-none text-info">
                              <code className="text-info small" style={{ fontFamily: 'monospace' }}>{sourceURL}</code>
                            </a>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </Table>
              </div>

              {getFilteredCloudAssets().length === 0 && cloudAssets.length > 0 && (
                <div className="text-center py-4">
                  <i className="bi bi-funnel text-white-50" style={{ fontSize: '2rem' }}></i>
                  <h6 className="text-white-50 mt-2">No cloud assets match the current filters</h6>
                  <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
                    Clear Filters
                  </Button>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-4 text-light" style={{ opacity: 0.7 }}>
              No cloud assets found.
            </div>
          )}
        </div>

        {!isLoading && cloudAssets.length === 0 && mostRecentKatanaCompanyScan && (
          <Alert variant="info" className="bg-info bg-opacity-10 border-info text-light">
            <Alert.Heading className="text-light">No Cloud Assets Found</Alert.Heading>
            <p>The Katana scan completed but didn't discover any cloud assets. This could mean:</p>
            <ul>
              <li>The scanned domains don't use cloud services</li>
              <li>Cloud assets are not publicly exposed</li>
              <li>The domains require authentication to access cloud resources</li>
              <li>Cloud assets are referenced in non-crawlable content</li>
            </ul>
          </Alert>
        )}
      </Modal.Body>
    </Modal>
    </>
  );
};

export default KatanaCompanyResultsModal; 