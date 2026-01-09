import { useState, useRef, useCallback, useEffect, useMemo } from 'react';
import { Modal, Table, Button, Spinner, Alert, Row, Col, Form, InputGroup } from 'react-bootstrap';
import { FaCheck, FaTimes } from 'react-icons/fa';

const DNSxConfigModal = ({ 
  show, 
  handleClose, 
  consolidatedCompanyDomains = [], 
  activeTarget,
  onSaveConfig
}) => {
  const [selectedDomains, setSelectedDomains] = useState(new Set());
  const [filters, setFilters] = useState({
    domain: ''
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [estimatedTime, setEstimatedTime] = useState(0);
  const [localDomains, setLocalDomains] = useState([]);
  const [loadingDomains, setLoadingDomains] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStartIndex, setDragStartIndex] = useState(null);
  const [dragMode, setDragMode] = useState('select');

  const [wildcardDomains, setWildcardDomains] = useState([]);
  const [loadingWildcardDomains, setLoadingWildcardDomains] = useState(false);
  const [scannedDomains, setScannedDomains] = useState(new Set());
  const [loadingScanStatus, setLoadingScanStatus] = useState(false);
  const tableRef = useRef(null);

  // Use consolidated domains from props, or fallback to locally fetched ones
  const baseDomains = consolidatedCompanyDomains.length > 0 ? consolidatedCompanyDomains : localDomains;
  
  // Always combine base domains with wildcard domains
  const domainsToUse = useMemo(() => {
    const combined = [...baseDomains.map(domain => ({
      domain,
      type: 'root',
      isWildcardTarget: wildcardDomains.some(wd => wd.rootDomain === domain)
    }))];
    
    // Add wildcard discovered domains
    wildcardDomains.forEach(wd => {
      wd.discoveredDomains.forEach(discoveredDomain => {
        if (!combined.some(item => item.domain === discoveredDomain)) {
          combined.push({
            domain: discoveredDomain,
            type: 'wildcard',
            rootDomain: wd.wildcardTarget || wd.rootDomain
          });
        }
      });
    });
    
    return combined.sort((a, b) => a.domain.localeCompare(b.domain));
  }, [baseDomains, wildcardDomains]);

  useEffect(() => {
    if (show) {
      loadSavedConfig();
      // If no domains provided via props, fetch them
      if (consolidatedCompanyDomains.length === 0) {
        fetchConsolidatedDomains();
      }
    }
  }, [show, activeTarget]);

  useEffect(() => {
    setEstimatedTime(selectedDomains.size);
  }, [selectedDomains]);

  useEffect(() => {
    if (baseDomains.length > 0) {
      fetchWildcardDomains();
      fetchScanStatus();
    }
  }, [baseDomains]);

  const fetchConsolidatedDomains = async () => {
    if (!activeTarget?.id) return;

    setLoadingDomains(true);
    try {
      const response = await fetch(
        `/api/consolidated-company-domains/${activeTarget.id}`
      );
      
      if (response.ok) {
        const data = await response.json();
        if (data.domains && Array.isArray(data.domains)) {
          setLocalDomains(data.domains);
        }
      }
    } catch (error) {
      console.error('Error fetching consolidated domains:', error);
      setError('Failed to load domains. Please try again.');
    } finally {
      setLoadingDomains(false);
    }
  };

  const loadSavedConfig = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `/api/dnsx-config/${activeTarget.id}`
      );
      
      if (response.ok) {
        const config = await response.json();
        if (config.domains && Array.isArray(config.domains)) {
          setSelectedDomains(new Set(config.domains));
        }
        

        
        // If wildcard domains were saved, we'll need to reconstruct the wildcard data structure
        if (config.wildcard_domains && Array.isArray(config.wildcard_domains) && config.wildcard_domains.length > 0) {
          // For now, we'll fetch fresh wildcard data since the saved format is just domain strings
          // The actual wildcard domains structure will be built by fetchWildcardDomains
        }
      }
    } catch (error) {
      console.error('Error loading DNSx config:', error);
    }
  };

  const fetchWildcardDomains = async () => {
    if (!activeTarget?.id) return;

    setLoadingWildcardDomains(true);
    console.log('fetchWildcardDomains - baseDomains:', baseDomains);
    
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

      console.log('All targets:', targets);

      const wildcardTargets = targets.filter(target => {
        if (!target || target.type !== 'Wildcard') return false;
        
        // Remove *. prefix from wildcard target to match with base domains
        const rootDomainFromWildcard = target.scope_target.startsWith('*.') 
          ? target.scope_target.substring(2) 
          : target.scope_target;
        
        const isMatch = baseDomains.includes(rootDomainFromWildcard);
        console.log(`Checking wildcard target ${target.scope_target} -> ${rootDomainFromWildcard}, match: ${isMatch}`);
        
        return isMatch;
      });

      console.log(`Found ${wildcardTargets.length} matching wildcard targets:`, wildcardTargets.map(t => t.scope_target));

      const wildcardDomainsData = [];

      // For each wildcard target, fetch its live web servers
      for (const wildcardTarget of wildcardTargets) {
        console.log(`Fetching live web servers for wildcard target: ${wildcardTarget.scope_target} (ID: ${wildcardTarget.id})`);
        try {
          const liveWebServersResponse = await fetch(
            `/api/api/scope-targets/${wildcardTarget.id}/target-urls`
          );

          console.log(`Live web servers response status for ${wildcardTarget.scope_target}:`, liveWebServersResponse.status);

          if (liveWebServersResponse.ok) {
            const liveWebServersData = await liveWebServersResponse.json();
            console.log(`Live web servers data for ${wildcardTarget.scope_target}:`, liveWebServersData);
            
            // Check if response is directly an array or has a target_urls property
            const targetUrls = Array.isArray(liveWebServersData) ? liveWebServersData : (liveWebServersData?.target_urls || null);
            
            // Ensure we have valid target_urls data
            if (!targetUrls || !Array.isArray(targetUrls)) {
              console.log(`No valid target_urls data for ${wildcardTarget.scope_target}:`, liveWebServersData);
              continue;
            }

            console.log(`Processing ${targetUrls.length} target URLs for ${wildcardTarget.scope_target}`);

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

            console.log(`Discovered domains for ${wildcardTarget.scope_target}:`, discoveredDomains);

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

      console.log('Final wildcardDomainsData:', wildcardDomainsData);
      setWildcardDomains(wildcardDomainsData);
    } catch (error) {
      console.error('Error fetching wildcard domains:', error);
      setError('Failed to load wildcard domains. Please try again.');
    } finally {
      setLoadingWildcardDomains(false);
    }
  };

  const fetchScanStatus = async () => {
    if (!activeTarget?.id) return;

    setLoadingScanStatus(true);
    try {
      const response = await fetch(
        `/api/scopetarget/${activeTarget.id}/scans/dnsx-company`
      );
      
      if (response.ok) {
        const scans = await response.json();
        const scannedSet = new Set();
        
        // Extract domains from successful scans
        scans.forEach(scan => {
          if (scan.status === 'success' && scan.domains && Array.isArray(scan.domains)) {
            scan.domains.forEach(domain => scannedSet.add(domain));
          }
        });
        
        setScannedDomains(scannedSet);
      }
    } catch (error) {
      console.error('Error fetching DNSx scan status:', error);
    } finally {
      setLoadingScanStatus(false);
    }
  };

  const handleSaveConfig = async () => {
    if (!activeTarget?.id) {
      setError('No active target selected');
      return;
    }

    setSaving(true);
    setError('');

    try {
      const config = {
        domains: Array.from(selectedDomains),
        include_wildcard_results: true,
        wildcard_domains: wildcardDomains.map(wd => wd.rootDomain).filter(domain => domain),
        created_at: new Date().toISOString()
      };

      const response = await fetch(
        `/api/dnsx-config/${activeTarget.id}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(config),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save configuration');
      }

      if (onSaveConfig) {
        onSaveConfig(config);
      }

      handleClose();
    } catch (error) {
      console.error('Error saving DNSx config:', error);
      setError('Failed to save configuration. Please try again.');
    } finally {
      setSaving(false);
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
      domain: ''
    });
  };

  const handleDomainSelect = (domain, index) => {
    const newSelected = new Set(selectedDomains);
    if (newSelected.has(domain)) {
      newSelected.delete(domain);
    } else {
      newSelected.add(domain);
    }
    setSelectedDomains(newSelected);
  };

  const handleMouseDown = (domain, index, event) => {
    if (event.button !== 0) return;
    
    setIsDragging(true);
    setDragStartIndex(index);
    
    const newSelected = new Set(selectedDomains);
    const wasSelected = newSelected.has(domain);
    
    if (wasSelected) {
      newSelected.delete(domain);
      setDragMode('deselect');
    } else {
      newSelected.add(domain);
      setDragMode('select');
    }
    
    setSelectedDomains(newSelected);
    event.preventDefault();
  };

  const handleMouseEnter = useCallback((domain, index) => {
    if (!isDragging || dragStartIndex === null) return;
    
    const filteredDomains = getFilteredAndSortedDomains();
    const startIndex = Math.min(dragStartIndex, index);
    const endIndex = Math.max(dragStartIndex, index);
    
    const newSelected = new Set(selectedDomains);
    for (let i = startIndex; i <= endIndex; i++) {
      if (i < filteredDomains.length) {
        const domainAtIndex = typeof filteredDomains[i] === 'string' ? filteredDomains[i] : filteredDomains[i].domain;
        if (dragMode === 'select') {
          newSelected.add(domainAtIndex);
        } else {
          newSelected.delete(domainAtIndex);
        }
      }
    }
    setSelectedDomains(newSelected);
  }, [isDragging, dragStartIndex, selectedDomains, dragMode]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
    setDragStartIndex(null);
    setDragMode('select');
  }, []);

  useEffect(() => {
    if (isDragging) {
      document.addEventListener('mouseup', handleMouseUp);
      return () => {
        document.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [isDragging, handleMouseUp]);

  const handleSelectAll = () => {
    const filteredDomains = getFilteredAndSortedDomains();
    const allDomains = filteredDomains.map(item => typeof item === 'string' ? item : item.domain);
    setSelectedDomains(new Set([...selectedDomains, ...allDomains]));
  };

  const handleDeselectAll = () => {
    const filteredDomains = getFilteredAndSortedDomains();
    const filteredDomainsSet = new Set(filteredDomains.map(item => typeof item === 'string' ? item : item.domain));
    const newSelectedDomains = new Set([...selectedDomains].filter(domain => !filteredDomainsSet.has(domain)));
    setSelectedDomains(newSelectedDomains);
  };

  const handleSelectScanned = () => {
    const filteredDomains = getFilteredAndSortedDomains();
    const newSelected = new Set();
    
    filteredDomains.forEach(item => {
      const domain = typeof item === 'string' ? item : item.domain;
      if (scannedDomains.has(domain)) {
        newSelected.add(domain);
      }
    });
    
    setSelectedDomains(newSelected);
  };

  const handleSelectUnscanned = () => {
    const filteredDomains = getFilteredAndSortedDomains();
    const newSelected = new Set();
    
    filteredDomains.forEach(item => {
      const domain = typeof item === 'string' ? item : item.domain;
      if (!scannedDomains.has(domain)) {
        newSelected.add(domain);
      }
    });
    
    setSelectedDomains(newSelected);
  };

  const getFilteredAndSortedDomains = () => {
    let filteredDomains = domainsToUse.filter(item => {
      const domain = typeof item === 'string' ? item : item.domain;
      if (!domain) return false;
      
      if (filters.domain && !domain.toLowerCase().includes(filters.domain.toLowerCase())) {
        return false;
      }
      
      return true;
    });

    return filteredDomains;
  };

  const handleCloseModal = () => {
    setError('');
    setIsDragging(false);
    setDragStartIndex(null);
    setDragMode('select');
    handleClose();
  };

  const filteredDomains = getFilteredAndSortedDomains();

  return (
    <Modal 
      show={show} 
      onHide={handleCloseModal} 
      size="xl" 
      data-bs-theme="dark"
      className="modal-90w"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-search me-2" />
          Configure DNSx - DNS Enumeration
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        <div className="mb-4">
          <Alert variant="info">
            <div className="d-flex align-items-center">
              <i className="bi bi-info-circle-fill me-2" />
              <div>
                <strong>DNSx Configuration:</strong> Select root domains to scan with DNSx for comprehensive DNS enumeration and record discovery.
                Selected domains: <strong>{selectedDomains.size}</strong> 
                | Estimated time: <strong>{estimatedTime === 1 ? '~1 minute' : `~${estimatedTime} minutes`}</strong>
              </div>
            </div>
          </Alert>
        </div>

        {domainsToUse.length === 0 ? (
          <div className="text-center py-4">
            {loadingDomains ? (
              <>
                <div className="spinner-border text-danger mb-3" role="status">
                  <span className="visually-hidden">Loading...</span>
                </div>
                <h5 className="text-white-50">Loading Consolidated Domains...</h5>
                <p className="text-white-50">
                  Fetching consolidated company domains for DNSx scanning...
                </p>
              </>
            ) : (
              <>
                <i className="bi bi-diagram-3 text-white-50" style={{ fontSize: '3rem' }} />
                <h5 className="text-white-50 mt-3">No Consolidated Domains Available</h5>
                <p className="text-white-50">
                  Run domain consolidation first to populate available domains for DNSx scanning.
                </p>
              </>
            )}
          </div>
        ) : (
          <>
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h6 className="mb-0 text-white">
                Select root domains for DNSx scanning 
                <span className="text-light ms-2">({selectedDomains.size}/{domainsToUse.length})</span>
              </h6>
            </div>

            <Row className="mb-3">
              <Col className="d-flex align-items-end gap-2">
                <Form.Group className="flex-grow-1">
                  <Form.Label className="text-white-50 small">Filter by Domain</Form.Label>
                  <InputGroup>
                    <InputGroup.Text>
                      <i className="bi bi-search" />
                    </InputGroup.Text>
                    <Form.Control
                      type="text"
                      placeholder="Search domains..."
                      value={filters.domain}
                      onChange={(e) => handleFilterChange('domain', e.target.value)}
                      data-bs-theme="dark"
                    />
                  </InputGroup>
                </Form.Group>
                <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
                  Clear Filter
                </Button>
              </Col>
            </Row>

            <div className="d-flex align-items-center mb-3" style={{ gap: '8px' }}>
              <div className="d-flex w-100" style={{ gap: '8px' }}>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={handleSelectAll}
                  disabled={filteredDomains.length === 0}
                  className="flex-fill"
                >
                  <FaCheck className="me-1" />
                  Select All
                </Button>
                <Button
                  variant="outline-danger"
                  size="sm"
                  onClick={handleDeselectAll}
                  disabled={selectedDomains.size === 0}
                  className="flex-fill"
                >
                  <FaTimes className="me-1" />
                  Deselect All
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={handleSelectScanned}
                  disabled={filteredDomains.length === 0 || loadingScanStatus}
                  className="flex-fill"
                >
                  <i className="bi bi-check-circle me-1" />
                  Select Scanned
                </Button>
                <Button
                  variant="outline-danger"
                  size="sm"
                  onClick={handleSelectUnscanned}
                  disabled={filteredDomains.length === 0 || loadingScanStatus}
                  className="flex-fill"
                >
                  <i className="bi bi-question-circle me-1" />
                  Select Unscanned
                </Button>
              </div>
              
              {loadingScanStatus && (
                <Spinner size="sm" animation="border" variant="light" />
              )}
            </div>

            <div className="mb-3">
              <small className="text-white-50">
                Showing {filteredDomains.length} of {domainsToUse.length} domains
              </small>
            </div>

            <div 
              style={{ 
                maxHeight: '400px', 
                overflowY: 'auto',
                border: '1px solid var(--bs-border-color)',
                borderRadius: '0.375rem'
              }}
              ref={tableRef}
            >
              <style>
                {`
                  .form-check-input:checked {
                    background-color: #dc3545 !important;
                    border-color: #dc3545 !important;
                  }
                  .form-check-input:focus {
                    border-color: #dc3545 !important;
                    box-shadow: 0 0 0 0.25rem rgba(220, 53, 69, 0.25) !important;
                  }
                `}
              </style>
              <Table hover variant="dark" size="sm" className="mb-0">
                <thead style={{ position: 'sticky', top: 0, zIndex: 10 }}>
                  <tr>
                    <th width="40" style={{ backgroundColor: 'var(--bs-dark)' }}>
                      <Form.Check
                        type="checkbox"
                        checked={filteredDomains.length > 0 && filteredDomains.every(item => {
                          const domain = typeof item === 'string' ? item : item.domain;
                          return selectedDomains.has(domain);
                        })}
                        onChange={(e) => {
                          if (e.target.checked) {
                            handleSelectAll();
                          } else {
                            handleDeselectAll();
                          }
                        }}
                      />
                    </th>
                    <th style={{ backgroundColor: 'var(--bs-dark)', width: '50%' }}>Domain</th>
                    <th style={{ backgroundColor: 'var(--bs-dark)', width: '30%' }}>Type</th>
                    <th style={{ backgroundColor: 'var(--bs-dark)', width: '20%' }}>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDomains.map((item, index) => {
                    const domain = typeof item === 'string' ? item : item.domain;
                    const domainType = typeof item === 'string' ? 'root' : item.type;
                    const isWildcardTarget = typeof item === 'string' ? false : item.isWildcardTarget;
                    const rootDomain = typeof item === 'string' ? null : item.rootDomain;
                    const isSelected = selectedDomains.has(domain);
                    
                    const getTypeBadge = () => {
                      if (domainType === 'wildcard') {
                        return <span className="badge bg-info text-dark">Wildcard Result</span>;
                      } else if (isWildcardTarget) {
                        return <span className="badge bg-warning text-dark">Root Domain (Wildcard Target)</span>;
                      } else {
                        return <span className="badge bg-success">Root Domain</span>;
                      }
                    };

                    const getSource = () => {
                      if (domainType === 'wildcard') {
                        // Find the wildcard target that discovered this domain
                        const wildcardInfo = wildcardDomains.find(wd => 
                          wd.discoveredDomains.includes(domain)
                        );
                        return (
                          <small className="text-white-50">
                            From: {wildcardInfo?.wildcardTarget || rootDomain}
                          </small>
                        );
                      } else if (isWildcardTarget) {
                        return (
                          <small className="text-white-50">
                            Company Domains
                          </small>
                        );
                      } else {
                        return (
                          <small className="text-white-50">
                            Company Domains
                          </small>
                        );
                      }
                    };
                    
                    return (
                      <tr 
                        key={domain}
                        style={{
                          backgroundColor: isSelected 
                            ? 'rgba(220, 53, 69, 0.25)' 
                            : 'transparent',
                          cursor: 'pointer',
                          userSelect: 'none',
                          transition: 'background-color 0.15s ease-in-out'
                        }}
                        onMouseDown={(e) => handleMouseDown(domain, index, e)}
                        onMouseEnter={() => handleMouseEnter(domain, index)}
                      >
                        <td>
                          <Form.Check
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => handleDomainSelect(domain, index)}
                            onClick={(e) => e.stopPropagation()}
                          />
                        </td>
                        <td 
                          style={{ 
                            fontFamily: 'monospace',
                            fontSize: '0.875rem'
                          }}
                        >
                          {domain}
                        </td>
                        <td>
                          {getTypeBadge()}
                        </td>
                        <td>
                          {getSource()}
                          {scannedDomains.has(domain) && (
                            <div className="mt-1">
                              <span className="badge bg-success text-dark" style={{ fontSize: '0.7rem' }}>
                                <i className="bi bi-check-circle me-1" />
                                Scanned
                              </span>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>
            </div>

            {filteredDomains.length === 0 && (
              <div className="text-center py-4">
                <i className="bi bi-funnel text-white-50" style={{ fontSize: '2rem' }} />
                <h6 className="text-white-50 mt-2">No domains match the current filters</h6>
                <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
                  Clear Filters
                </Button>
              </div>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <div className="d-flex justify-content-between align-items-center w-100">
          <div className="text-white-50 small">
            {selectedDomains.size > 0 && (
              <>
                <i className="bi bi-clock me-1" />
                Estimated time: {estimatedTime === 1 ? '~1 minute' : `~${estimatedTime} minutes`}
              </>
            )}
          </div>
          <div>
            <Button variant="secondary" onClick={handleCloseModal} className="me-2">
              Cancel
            </Button>
            <Button 
              variant="danger" 
              onClick={handleSaveConfig}
              disabled={saving || selectedDomains.size === 0}
            >
              {saving ? (
                <>
                  <Spinner animation="border" size="sm" className="me-2" />
                  Saving...
                </>
              ) : (
                <>
                  <i className="bi bi-save me-2" />
                  Save Configuration ({selectedDomains.size} domains)
                </>
              )}
            </Button>
          </div>
        </div>
      </Modal.Footer>
    </Modal>
  );
};

export default DNSxConfigModal; 