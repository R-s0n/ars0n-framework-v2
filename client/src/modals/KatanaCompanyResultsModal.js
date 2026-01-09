import React, { useState, useEffect, useMemo } from 'react';
import { Modal, Table, Badge, Alert, Button, Spinner, Form, InputGroup } from 'react-bootstrap';

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
        `/api/katana-company/target/${activeTarget.id}/cloud-assets`
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
        `/api/consolidated-company-domains/${activeTarget.id}`
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
        `/api/scopetarget/read`
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
            `/api/api/scope-targets/${wildcardTarget.id}/target-urls`
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
        `/api/ip-port-scans/${activeTarget.id}`
      );
      
      if (response.ok) {
        const data = await response.json();
        
        if (data && Array.isArray(data) && data.length > 0) {
          // Get the most recent scan
          const latestScan = data[0];
          
          if (latestScan && latestScan.scan_id) {
            // Fetch live web servers for the latest scan
            const liveWebServersResponse = await fetch(
              `/api/live-web-servers/${latestScan.scan_id}`
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

  const getCloudProviderBadge = (service) => {
    if (service.includes('aws')) return <Badge bg="warning">AWS</Badge>;
    if (service.includes('gcp')) return <Badge bg="info">GCP</Badge>;
    if (service.includes('azure')) return <Badge bg="primary">Azure</Badge>;
    return <Badge bg="secondary">Other</Badge>;
  };

  const copyFilteredCloudAssetDomains = async () => {
    const filteredAssets = getFilteredCloudAssets();
    const domains = filteredAssets.map(asset => {
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


  const getFilteredCloudAssets = () => {
    const filtered = cloudAssets.filter(asset => {
      const activeFilters = searchFilters.filter(filter => filter.searchTerm.trim() !== '');
      
      if (activeFilters.length > 0) {
        return activeFilters.every(filter => {
          const searchTerm = filter.searchTerm.toLowerCase();
          const cloudAssetFQDN = asset.url.replace(/^https?:\/\//, '');
          const rootDomain = asset.root_domain || '';
          
          const assetContainsSearch = 
            (cloudAssetFQDN && cloudAssetFQDN.toLowerCase().includes(searchTerm)) ||
            (rootDomain && rootDomain.toLowerCase().includes(searchTerm)) ||
            (asset.service && asset.service.toLowerCase().includes(searchTerm));
          return filter.isNegative ? !assetContainsSearch : assetContainsSearch;
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
    handleClose();
  };

  return (
    <Modal 
      show={show} 
      onHide={handleModalClose} 
      fullscreen
      data-bs-theme="dark"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Katana Company Results</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && <Alert variant="danger">{error}</Alert>}
        
        <div className="mb-3">
          <div className="d-flex justify-content-between align-items-center mb-2">
            <h5 className="text-light mb-0">{getCloudAssetsTitle()}</h5>
            <Button
              variant={copySuccess ? "success" : "outline-secondary"}
              size="sm"
              onClick={copyFilteredCloudAssetDomains}
            >
              {copySuccess ? (
                <>
                  <i className="bi bi-check-circle me-1"></i>
                  Copied!
                </>
              ) : (
                <>
                  <i className="bi bi-clipboard me-1"></i>
                  Copy Filtered Cloud Asset Domains to Clipboard
                </>
              )}
            </Button>
          </div>
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

              <div className="mb-3">
                <small className="text-white-50">
                  Showing {getFilteredCloudAssets().length} of {cloudAssets.length} cloud assets
                </small>
              </div>

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
                  {getFilteredCloudAssets().map((asset, index) => {
                    const cloudAssetFQDN = asset.url.replace(/^https?:\/\//, '');
                    
                    return (
                      <tr key={index}>
                        <td className="font-monospace" style={{ fontSize: '0.875rem' }}>
                          <a 
                            href={`https://${cloudAssetFQDN}`} 
                            target="_blank" 
                            rel="noopener noreferrer" 
                            className="text-decoration-none text-warning"
                            style={{ cursor: 'pointer' }}
                          >
                            {cloudAssetFQDN}
                          </a>
                        </td>
                        <td className="font-monospace" style={{ fontSize: '0.875rem' }}>
                          {asset.root_domain ? (
                            <a 
                              href={`https://${asset.root_domain}`} 
                              target="_blank" 
                              rel="noopener noreferrer" 
                              className="text-decoration-none text-warning"
                              style={{ cursor: 'pointer' }}
                            >
                              {asset.root_domain}
                            </a>
                          ) : (
                            'N/A'
                          )}
                        </td>
                        <td>{getCloudProviderBadge(asset.service)}</td>
                        <td style={{ fontSize: '0.875rem' }}>{new Date(asset.created_at || asset.last_scanned_at).toLocaleString()}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>

              {getFilteredCloudAssets().length === 0 && cloudAssets.length > 0 && (
                <div className="text-center py-4">
                  <div className="text-white-50 mb-3">
                    <i className="bi bi-funnel" style={{ fontSize: '2rem' }}></i>
                  </div>
                  <h6 className="text-white-50">No domains match your filters</h6>
                  <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
                    Clear Filters
                  </Button>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-5">
              <div className="text-white-50 mb-3">
                <i className="bi bi-cloud" style={{ fontSize: '3rem' }}></i>
              </div>
              <h5 className="text-white-50 mb-3">No Cloud Assets Found</h5>
              <p className="text-white-50">
                The scan completed but no cloud assets were discovered. This could mean:
              </p>
              <ul className="list-unstyled text-white-50 small">
                <li>• The domains don't use cloud services</li>
                <li>• Cloud assets are not publicly exposed</li>
                <li>• The domains require authentication to access cloud resources</li>
                <li>• Cloud assets are referenced in non-crawlable content</li>
              </ul>
            </div>
          )}
        </div>

        {!isLoading && cloudAssets.length === 0 && mostRecentKatanaCompanyScan && (
          <div className="text-center py-5">
            <div className="text-white-50 mb-3">
              <i className="bi bi-cloud" style={{ fontSize: '3rem' }}></i>
            </div>
            <h5 className="text-white-50 mb-3">No Cloud Assets Found</h5>
            <p className="text-white-50">
              The Katana scan completed but didn't discover any cloud assets. This could mean:
            </p>
            <ul className="list-unstyled text-white-50 small">
              <li>• The scanned domains don't use cloud services</li>
              <li>• Cloud assets are not publicly exposed</li>
              <li>• The domains require authentication to access cloud resources</li>
              <li>• Cloud assets are referenced in non-crawlable content</li>
            </ul>
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleModalClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default KatanaCompanyResultsModal; 