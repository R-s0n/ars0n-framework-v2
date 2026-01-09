import { useState, useEffect, useMemo, useRef } from 'react';
import { Modal, Button, Badge, ListGroup, Row, Col, Card, Alert, Pagination, Table } from 'react-bootstrap';
import { copyToClipboard } from '../utils/miscUtils';

export const NucleiResultsModal = ({ 
  show, 
  handleClose, 
  scan,
  scans,
  activeNucleiScan,
  setActiveNucleiScan,
  setShowToast 
}) => {
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [templateFilter, setTemplateFilter] = useState('all');
  const [showScanSelector, setShowScanSelector] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const findingsListRef = useRef(null);
  
  const FINDINGS_PER_PAGE = 50;

  const formatResults = (results) => {
    console.log('[NucleiResultsModal] Formatting results:', results);
    
    if (!results?.result) {
      console.log('[NucleiResultsModal] No result data found');
      return [];
    }
    
    try {
      let findings = [];
      if (typeof results.result === 'string') {
        console.log('[NucleiResultsModal] Parsing string result');
        findings = JSON.parse(results.result);
      } else if (Array.isArray(results.result)) {
        console.log('[NucleiResultsModal] Result is already an array');
        findings = results.result;
      }
      
      console.log('[NucleiResultsModal] Parsed findings:', findings);
      console.log('[NucleiResultsModal] Findings count:', Array.isArray(findings) ? findings.length : 0);
      
      if (Array.isArray(findings) && findings.length > 0) {
        console.log('[NucleiResultsModal] Sample finding:', findings[0]);
        console.log('[NucleiResultsModal] Sample finding severity:', findings[0].info?.severity);
      }
      
      return Array.isArray(findings) ? findings : [];
    } catch (error) {
      console.error('Error parsing Nuclei results:', error);
      return [];
    }
  };

  useEffect(() => {
    if (scan) {
      const formattedResults = formatResults(scan);
      setFindings(formattedResults);
      setCurrentPage(1);
      if (formattedResults.length > 0) {
        setSelectedFinding(formattedResults[0]);
        setSelectedIndex(0);
      } else {
        setSelectedFinding(null);
        setSelectedIndex(0);
      }
    } else {
      setFindings([]);
      setSelectedFinding(null);
      setSelectedIndex(0);
      setCurrentPage(1);
    }
  }, [scan]);

  const handleCopy = async () => {
    if (scan?.result) {
      try {
        const exportText = findings.map(f => 
          `[${f.info?.severity?.toUpperCase() || 'INFO'}] ${f.info?.name || 'Unknown'} - ${f.host || f.matched}\n` +
          `Template: ${f['template-id'] || 'N/A'}\n` +
          `Matcher: ${f['matcher-name'] || 'N/A'}\n` +
          `${f.info?.description ? `Description: ${f.info.description}\n` : ''}` +
          `---\n`
        ).join('\n');
        
        const success = await copyToClipboard(exportText);
        if (success && setShowToast) {
          setShowToast(true);
          setTimeout(() => setShowToast(false), 3000);
        }
      } catch (error) {
        console.error('Error copying results:', error);
      }
    }
  };

  const handleCopyFinding = async (finding) => {
    try {
      const exportText = 
        `[${finding.info?.severity?.toUpperCase() || 'INFO'}] ${finding.info?.name || 'Unknown'}\n` +
        `Template: ${finding['template-id'] || 'N/A'}\n` +
        `Target: ${finding.host || finding.matched || 'N/A'}\n` +
        `IP: ${finding.ip || 'N/A'}\n` +
        `Port: ${finding.port || 'N/A'}\n` +
        `Matched At: ${finding['matched-at'] || 'N/A'}\n` +
        `Type: ${finding.type || 'N/A'}\n` +
        `Matcher: ${finding['matcher-name'] || 'N/A'}\n` +
        `Extractor: ${finding.extractor_name || 'N/A'}\n` +
        `Matcher Status: ${finding['matcher-status'] !== undefined ? finding['matcher-status'] : 'N/A'}\n` +
        `Timestamp: ${finding.timestamp || 'N/A'}\n` +
        `${finding.info?.description ? `Description: ${finding.info.description}\n` : ''}` +
        `${finding.info?.reference ? `References: ${finding.info.reference.join(', ')}\n` : ''}` +
        `${finding.info?.tags ? `Tags: ${finding.info.tags.join(', ')}\n` : ''}` +
        `${finding['extracted-results'] && finding['extracted-results'].length > 0 ? `Extracted Results: ${finding['extracted-results'].join(', ')}\n` : ''}` +
        `${finding['curl-command'] ? `Curl Command: ${finding['curl-command']}\n` : ''}` +
        `${finding.request ? `Request: ${finding.request}\n` : ''}` +
        `${finding.response ? `Response: ${finding.response}\n` : ''}`;
      
      const success = await copyToClipboard(exportText);
      if (success && setShowToast) {
        setShowToast(true);
        setTimeout(() => setShowToast(false), 3000);
      }
    } catch (error) {
      console.error('Error copying finding:', error);
    }
  };

  const getSeverityBadge = (severity) => {
    const severityMap = {
      'critical': 'danger',
      'high': 'warning',
      'medium': 'info', 
      'low': 'success',
      'info': 'secondary'
    };
    return severityMap[severity?.toLowerCase()] || 'secondary';
  };

  const getSeverityIcon = (severity) => {
    const iconMap = {
      'critical': 'exclamation-triangle-fill',
      'high': 'exclamation-triangle',
      'medium': 'exclamation-circle',
      'low': 'info-circle',
      'info': 'info-circle-fill'
    };
    return iconMap[severity?.toLowerCase()] || 'info-circle';
  };

  const groupBySeverity = (findings) => {
    const grouped = findings.reduce((acc, finding) => {
      let severity = finding.info?.severity?.toLowerCase() || 'info';
      
      if (severity === 'unknown') {
        severity = 'info';
      }
      
      if (!acc[severity]) acc[severity] = [];
      acc[severity].push(finding);
      return acc;
    }, {});
    
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const sortedGrouped = {};
    severityOrder.forEach(severity => {
      if (grouped[severity]) {
        sortedGrouped[severity] = grouped[severity];
      }
    });
    
    return sortedGrouped;
  };

  const getAvailableCategories = useMemo(() => {
    const categories = new Set();
    findings.forEach(finding => {
      if (finding.info?.tags && finding.info.tags.length > 0) {
        finding.info.tags.forEach(tag => categories.add(tag));
      }
    });
    return Array.from(categories).sort();
  }, [findings]);

  const getAvailableTemplates = useMemo(() => {
    const templates = new Set();
    findings.forEach(finding => {
      const templateName = finding.info?.name || finding['template-id'] || 'Unknown';
      if (templateName && templateName !== 'Unknown') {
        templates.add(templateName);
      }
    });
    return Array.from(templates).sort();
  }, [findings]);

  const getScanDetails = (scan) => {
    if (!scan) return null;
    
    const findingsCount = (() => {
      if (!scan.result) return 0;
      try {
        let findings = [];
        if (typeof scan.result === 'string') {
          findings = JSON.parse(scan.result);
        } else if (Array.isArray(scan.result)) {
          findings = scan.result;
        }
        return Array.isArray(findings) ? findings.length : 0;
      } catch (error) {
        return 0;
      }
    })();

    const targetsCount = scan.targets?.length || 0;
    const templatesCount = scan.templates?.length || 0;
    
    return {
      findingsCount,
      targetsCount,
      templatesCount,
      scanId: scan.scan_id || scan.id,
      createdAt: scan.created_at,
      status: scan.status
    };
  };

  const handleScanSelect = (selectedScan) => {
    setActiveNucleiScan(selectedScan);
    setShowScanSelector(false);
  };

  const scrollToSelectedFinding = () => {
    if (findingsListRef.current && selectedFinding) {
      const selectedElement = findingsListRef.current.querySelector('.list-group-item.active');
      if (selectedElement) {
        selectedElement.scrollIntoView({
          behavior: 'smooth',
          block: 'nearest',
          inline: 'nearest'
        });
      }
    }
  };

  const filteredFindings = useMemo(() => {
    let filtered = findings;

    if (searchTerm) {
      const isNegativeSearch = searchTerm.startsWith('-');
      const searchValue = isNegativeSearch ? searchTerm.substring(1) : searchTerm;
      
      filtered = filtered.filter(finding => {
        const searchableText = [
          finding.info?.name || '',
          finding.host || '',
          finding.matched || '',
          finding['template-id'] || '',
          finding.info?.description || '',
          finding.info?.tags?.join(' ') || ''
        ].join(' ').toLowerCase();
        
        const matches = searchableText.includes(searchValue.toLowerCase());
        return isNegativeSearch ? !matches : matches;
      });
    }

    if (severityFilter !== 'all') {
      filtered = filtered.filter(finding => {
        const severity = finding.info?.severity?.toLowerCase() || 'info';
        return severity === severityFilter || (severity === 'unknown' && severityFilter === 'info');
      });
    }

    if (categoryFilter !== 'all') {
      filtered = filtered.filter(finding => {
        return finding.info?.tags?.includes(categoryFilter);
      });
    }

    if (templateFilter !== 'all') {
      filtered = filtered.filter(finding => {
        const templateName = finding.info?.name || finding['template-id'] || 'Unknown';
        return templateName === templateFilter;
      });
    }

    return filtered;
  }, [findings, searchTerm, severityFilter, categoryFilter, templateFilter]);

  const filteredGroupedFindings = useMemo(() => {
    return groupBySeverity(filteredFindings);
  }, [filteredFindings]);

  const allFindings = useMemo(() => {
    const findings = [];
    Object.entries(filteredGroupedFindings).forEach(([severity, severityFindings]) => {
      severityFindings.forEach(finding => {
        findings.push({ ...finding, severity });
      });
    });
    return findings;
  }, [filteredGroupedFindings]);

  const totalPages = Math.ceil(allFindings.length / FINDINGS_PER_PAGE);
  
  const paginatedFindings = useMemo(() => {
    const startIndex = (currentPage - 1) * FINDINGS_PER_PAGE;
    const endIndex = startIndex + FINDINGS_PER_PAGE;
    return allFindings.slice(startIndex, endIndex);
  }, [allFindings, currentPage]);

  const paginatedGroupedFindings = useMemo(() => {
    return groupBySeverity(paginatedFindings);
  }, [paginatedFindings]);

  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(totalPages);
    }
  }, [totalPages, currentPage]);

  useEffect(() => {
    if (show && allFindings.length > 0 && !selectedFinding) {
      setSelectedFinding(allFindings[0]);
      setSelectedIndex(0);
    }
  }, [show, allFindings, selectedFinding]);

  useEffect(() => {
    if (selectedFinding) {
      scrollToSelectedFinding();
    }
  }, [selectedFinding]);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (showScanSelector && !event.target.closest('.position-relative')) {
        setShowScanSelector(false);
      }
    };

    if (showScanSelector) {
      document.addEventListener('click', handleClickOutside);
    }

    return () => {
      document.removeEventListener('click', handleClickOutside);
    };
  }, [showScanSelector]);

  useEffect(() => {
    const handleGlobalKeyDown = (event) => {
      if (!show) return;
      
      if (paginatedFindings.length === 0) return;

      switch (event.key) {
        case 'ArrowDown':
          event.preventDefault();
          const currentIndexInPage = paginatedFindings.findIndex(f => 
            f.info?.name === selectedFinding?.info?.name && 
            f.host === selectedFinding?.host &&
            f['template-id'] === selectedFinding?.['template-id']
          );
          
          if (currentIndexInPage < paginatedFindings.length - 1) {
            const nextFinding = paginatedFindings[currentIndexInPage + 1];
            setSelectedFinding(nextFinding);
            const globalIndex = allFindings.findIndex(f => 
              f.info?.name === nextFinding.info?.name && 
              f.host === nextFinding.host &&
              f['template-id'] === nextFinding['template-id']
            );
            setSelectedIndex(globalIndex);
          } else if (currentPage < totalPages) {
            setCurrentPage(currentPage + 1);
            setTimeout(() => {
              if (allFindings[(currentPage) * FINDINGS_PER_PAGE]) {
                setSelectedFinding(allFindings[(currentPage) * FINDINGS_PER_PAGE]);
                setSelectedIndex((currentPage) * FINDINGS_PER_PAGE);
              }
            }, 100);
          }
          break;
        case 'ArrowUp':
          event.preventDefault();
          const currentIndexInPageUp = paginatedFindings.findIndex(f => 
            f.info?.name === selectedFinding?.info?.name && 
            f.host === selectedFinding?.host &&
            f['template-id'] === selectedFinding?.['template-id']
          );
          
          if (currentIndexInPageUp > 0) {
            const prevFinding = paginatedFindings[currentIndexInPageUp - 1];
            setSelectedFinding(prevFinding);
            const globalIndex = allFindings.findIndex(f => 
              f.info?.name === prevFinding.info?.name && 
              f.host === prevFinding.host &&
              f['template-id'] === prevFinding['template-id']
            );
            setSelectedIndex(globalIndex);
          } else if (currentPage > 1) {
            setCurrentPage(currentPage - 1);
            setTimeout(() => {
              const newPageStartIndex = (currentPage - 2) * FINDINGS_PER_PAGE;
              const lastInPrevPage = Math.min(newPageStartIndex + FINDINGS_PER_PAGE - 1, allFindings.length - 1);
              if (allFindings[lastInPrevPage]) {
                setSelectedFinding(allFindings[lastInPrevPage]);
                setSelectedIndex(lastInPrevPage);
              }
            }, 100);
          }
          break;
        case 'Home':
          event.preventDefault();
          if (allFindings.length > 0) {
            setCurrentPage(1);
            setTimeout(() => {
              setSelectedIndex(0);
              setSelectedFinding(allFindings[0]);
            }, 100);
          }
          break;
        case 'End':
          event.preventDefault();
          if (allFindings.length > 0) {
            setCurrentPage(totalPages);
            setTimeout(() => {
              const lastIndex = allFindings.length - 1;
              setSelectedIndex(lastIndex);
              setSelectedFinding(allFindings[lastIndex]);
            }, 100);
          }
          break;
      }
    };

    if (show) {
      document.addEventListener('keydown', handleGlobalKeyDown);
    }

    return () => {
      document.removeEventListener('keydown', handleGlobalKeyDown);
    };
  }, [show, paginatedFindings, allFindings, selectedFinding, currentPage, totalPages]);

  const renderPagination = () => {
    if (totalPages <= 1) return null;

    const maxPagesToShow = 7;
    let startPage = Math.max(1, currentPage - Math.floor(maxPagesToShow / 2));
    let endPage = Math.min(totalPages, startPage + maxPagesToShow - 1);

    if (endPage - startPage < maxPagesToShow - 1) {
      startPage = Math.max(1, endPage - maxPagesToShow + 1);
    }

    const pages = [];
    
    for (let i = startPage; i <= endPage; i++) {
      pages.push(
        <Pagination.Item
          key={i}
          active={i === currentPage}
          onClick={() => {
            setCurrentPage(i);
            if (findingsListRef.current) {
              findingsListRef.current.scrollTop = 0;
            }
          }}
        >
          {i}
        </Pagination.Item>
      );
    }

    return (
      <div className="d-flex justify-content-center align-items-center my-3">
        <Pagination size="sm" className="mb-0">
          <Pagination.First 
            onClick={() => setCurrentPage(1)} 
            disabled={currentPage === 1}
          />
          <Pagination.Prev 
            onClick={() => setCurrentPage(Math.max(1, currentPage - 1))} 
            disabled={currentPage === 1}
          />
          
          {startPage > 1 && (
            <>
              <Pagination.Item onClick={() => setCurrentPage(1)}>1</Pagination.Item>
              {startPage > 2 && <Pagination.Ellipsis disabled />}
            </>
          )}
          
          {pages}
          
          {endPage < totalPages && (
            <>
              {endPage < totalPages - 1 && <Pagination.Ellipsis disabled />}
              <Pagination.Item onClick={() => setCurrentPage(totalPages)}>{totalPages}</Pagination.Item>
            </>
          )}
          
          <Pagination.Next 
            onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))} 
            disabled={currentPage === totalPages}
          />
          <Pagination.Last 
            onClick={() => setCurrentPage(totalPages)} 
            disabled={currentPage === totalPages}
          />
        </Pagination>
        <div className="ms-3">
          <small className="text-muted">
            Showing {((currentPage - 1) * FINDINGS_PER_PAGE) + 1}-{Math.min(currentPage * FINDINGS_PER_PAGE, allFindings.length)} of {allFindings.length}
          </small>
        </div>
      </div>
    );
  };

  const renderFindingsList = () => {
    if (filteredFindings.length === 0) {
      return (
        <div className="text-center text-muted p-4">
          <i className="bi bi-search fs-1 mb-3 d-block"></i>
          <p>{findings.length === 0 ? 'No security findings detected in this scan.' : 'No findings match the current filters.'}</p>
        </div>
      );
    }

    return (
      <>
        <div ref={findingsListRef} style={{ height: '65vh', overflowY: 'auto' }}>
          {Object.entries(paginatedGroupedFindings).map(([severity, severityFindings]) => (
            <div key={severity} className="mb-3">
              <div className="d-flex align-items-center mb-2">
                <Badge bg={getSeverityBadge(severity)} className="me-2">
                  {severity.toUpperCase()}
                </Badge>
                <small className="text-muted">
                  {severityFindings.length} finding{severityFindings.length !== 1 ? 's' : ''} on this page
                </small>
              </div>
              
              <ListGroup variant="flush">
                {severityFindings.map((finding, index) => {
                  const findingIndex = allFindings.findIndex(f => 
                    f.info?.name === finding.info?.name && 
                    f.host === finding.host && 
                    f['template-id'] === finding['template-id'] &&
                    f.matched === finding.matched &&
                    f['matched-at'] === finding['matched-at'] &&
                    f.ip === finding.ip &&
                    f.port === finding.port &&
                    f.info?.severity === finding.info?.severity &&
                    f['matcher-name'] === finding['matcher-name'] &&
                    f.timestamp === finding.timestamp
                  );
                  const isSelected = selectedFinding && 
                    selectedFinding.info?.name === finding.info?.name && 
                    selectedFinding.host === finding.host && 
                    selectedFinding['template-id'] === finding['template-id'] &&
                    selectedFinding.matched === finding.matched &&
                    selectedFinding['matched-at'] === finding['matched-at'] &&
                    selectedFinding.ip === finding.ip &&
                    selectedFinding.port === finding.port &&
                    selectedFinding.info?.severity === finding.info?.severity &&
                    selectedFinding['matcher-name'] === finding['matcher-name'] &&
                    selectedFinding.timestamp === finding.timestamp;
                  
                  return (
                    <ListGroup.Item
                      key={`${severity}-${index}-${findingIndex}`}
                      action
                      active={isSelected}
                      onClick={() => {
                        setSelectedFinding(finding);
                        setSelectedIndex(findingIndex);
                      }}
                      className="py-2 border-0 mb-1"
                      style={{ 
                        backgroundColor: isSelected ? 
                          (severity === 'critical' ? 'rgba(220, 53, 69, 0.25)' : 
                           severity === 'high' ? 'rgba(255, 193, 7, 0.25)' : 
                           severity === 'medium' ? 'rgba(13, 202, 240, 0.25)' : 
                           severity === 'low' ? 'rgba(25, 135, 84, 0.25)' : 
                           'rgba(108, 117, 125, 0.25)') : 
                          'rgba(255, 255, 255, 0.05)',
                        borderRadius: '4px',
                        border: isSelected ? 
                          (severity === 'critical' ? '2px solid #dc3545' : 
                           severity === 'high' ? '2px solid #ffc107' : 
                           severity === 'medium' ? '2px solid #0dcaf0' : 
                           severity === 'low' ? '2px solid #198754' : 
                           '2px solid #6c757d') : 
                          '2px solid transparent'
                      }}
                    >
                    <div className="d-flex align-items-start">
                      <i className={`bi bi-${getSeverityIcon(severity)} text-${getSeverityBadge(severity) === 'danger' ? 'danger' : getSeverityBadge(severity) === 'warning' ? 'warning' : 'info'} me-2 mt-1`}></i>
                      <div className="flex-grow-1">
                        <div className="fw-bold">
                          {finding.info?.name || finding.template_id || 'Unknown'}
                        </div>
                        <div className="text-muted small">
                          {finding.host || finding.matched || 'Unknown target'}
                        </div>
                        <div className="text-muted small">
                          {finding['template-id']}
                        </div>
                        <div className="text-info small">
                          <i className="bi bi-gear me-1"></i>
                          {finding['matcher-name'] || 'N/A'}
                        </div>
                      </div>
                    </div>
                  </ListGroup.Item>
                  );
                })}
              </ListGroup>
            </div>
          ))}
        </div>
        {renderPagination()}
      </>
    );
  };

  const renderFindingDetails = () => {
    if (!selectedFinding) {
      return (
        <div className="text-center text-muted p-4">
          <i className="bi bi-arrow-left fs-1 mb-3 d-block"></i>
          <p>Select a finding from the left to view details</p>
        </div>
      );
    }

    const finding = selectedFinding;
    const severity = finding.info?.severity?.toLowerCase() || 'info';

    return (
      <div style={{ height: '75vh', overflowY: 'auto' }}>
        <Card className="bg-dark border-secondary">
          <Card.Header className="d-flex justify-content-between align-items-center">
            <div className="d-flex align-items-center">
              <Badge bg={getSeverityBadge(severity)} className="me-2">
                {severity.toUpperCase()}
              </Badge>
              <span className="fw-bold">{finding.info?.name || finding.template_id || 'Unknown'}</span>
            </div>
            <Button 
              variant="outline-light" 
              size="sm" 
              onClick={() => handleCopyFinding(finding)}
              title="Copy finding details"
            >
              <i className="bi bi-clipboard"></i>
            </Button>
          </Card.Header>
          
          <Card.Body>
            <Row>
              <Col md={6}>
                <div className="mb-3">
                  <h6 className="text-light mb-2">
                    <i className="bi bi-bullseye me-2"></i>Target
                  </h6>
                  <div className="bg-secondary rounded p-2">
                    <div className="text-light">{finding.host || finding.matched || 'Unknown'}</div>
                    {finding.ip && finding.ip !== finding.host && (
                      <div className="text-muted small">IP: {finding.ip}</div>
                    )}
                    {finding.port && (
                      <div className="text-muted small">Port: {finding.port}</div>
                    )}
                    <div className="text-muted small">Matched At: {finding['matched-at'] || 'N/A'}</div>
                  </div>
                </div>
              </Col>
              
              <Col md={6}>
                <div className="mb-3">
                  <h6 className="text-light mb-2">
                    <i className="bi bi-file-code me-2"></i>Template
                  </h6>
                  <div className="bg-secondary rounded p-2">
                    <div className="text-light">{finding['template-id'] || 'Unknown'}</div>
                    {finding.template_path && (
                      <div className="text-muted small">Path: {finding.template_path}</div>
                    )}
                    {finding.type && (
                      <div className="text-muted small">Type: {finding.type}</div>
                    )}
                    <div className="text-info small fw-bold">Matcher: {finding['matcher-name'] || 'N/A'}</div>
                    <div className="text-muted small">Matcher Status: 
                      <Badge bg={finding['matcher-status'] ? 'success' : 'danger'} className="ms-1">
                        {finding['matcher-status'] ? 'True' : 'False'}
                      </Badge>
                    </div>
                  </div>
                </div>
              </Col>
            </Row>

            {finding.timestamp && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-clock me-2"></i>Timestamp
                </h6>
                <div className="bg-secondary rounded p-2">
                  <div className="text-light">{new Date(finding.timestamp).toLocaleString()}</div>
                  <div className="text-muted small">{finding.timestamp}</div>
                </div>
              </div>
            )}

            {finding.info?.description && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-info-circle me-2"></i>Description
                </h6>
                <Alert variant="info" className="mb-0">
                  {finding.info.description}
                </Alert>
              </div>
            )}

            {finding.info?.reference && finding.info.reference.length > 0 && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-link-45deg me-2"></i>References
                </h6>
                <div className="bg-secondary rounded p-2">
                  {finding.info.reference.map((ref, index) => (
                    <div key={index} className="mb-1">
                      <a 
                        href={ref} 
                        target="_blank" 
                        rel="noopener noreferrer" 
                        className="text-info text-decoration-none"
                      >
                        <i className="bi bi-link-45deg me-1"></i>
                        {ref}
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {finding.info?.tags && finding.info.tags.length > 0 && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-tags me-2"></i>Tags
                </h6>
                <div>
                  {finding.info.tags.map((tag, index) => (
                    <Badge key={index} bg="secondary" className="me-1 mb-1">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {finding.info?.classification && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-diagram-3 me-2"></i>Classification
                </h6>
                <div className="bg-secondary rounded p-2">
                  {Object.entries(finding.info.classification).map(([key, value]) => (
                    <div key={key} className="mb-1">
                      <span className="text-muted">{key.toUpperCase()}:</span>
                      <span className="text-light ms-2">{Array.isArray(value) ? value.join(', ') : value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="mb-3">
              <h6 className="text-light mb-2">
                <i className="bi bi-search me-2"></i>Extracted Results
              </h6>
              <div className="bg-secondary rounded p-2">
                {finding['extracted-results'] && finding['extracted-results'].length > 0 ? (
                  finding['extracted-results'].map((result, index) => (
                    <div key={index} className="mb-2">
                      <div className="text-muted small mb-1">Result {index + 1}:</div>
                      <code className="text-warning d-block p-2 bg-dark rounded">{result}</code>
                    </div>
                  ))
                ) : (
                  <div className="text-muted">No extracted results</div>
                )}
              </div>
            </div>

            {finding['curl-command'] && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-terminal me-2"></i>Curl Command
                </h6>
                <div className="bg-dark rounded p-2">
                  <code className="text-success small">{finding['curl-command']}</code>
                </div>
              </div>
            )}

            {finding.request && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-arrow-up me-2"></i>Request
                </h6>
                <div className="bg-dark rounded p-2">
                  <pre className="text-info small mb-0" style={{ whiteSpace: 'pre-wrap' }}>{finding.request}</pre>
                </div>
              </div>
            )}

            {finding.response && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-arrow-down me-2"></i>Response
                </h6>
                <div className="bg-dark rounded p-2">
                  <pre className="text-success small mb-0" style={{ whiteSpace: 'pre-wrap' }}>{finding.response}</pre>
                </div>
              </div>
            )}
          </Card.Body>
        </Card>
      </div>
    );
  };

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleClose} 
      size="xl"
      className="nuclei-results-modal"
      dialogClassName="modal-fullscreen"
      style={{ margin: 0 }}
      tabIndex={0}
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>
          <i className="bi bi-shield-exclamation me-2"></i>
          Nuclei Scan Results - {findings.length} Finding{findings.length !== 1 ? 's' : ''}
        </Modal.Title>
      </Modal.Header>
      
      <Modal.Body className="p-0">
        <div className="bg-dark border-bottom px-3 py-3">
          <Row className="g-2">
            <Col md={3}>
              <div className="input-group input-group-sm">
                <span className="input-group-text bg-secondary border-secondary">
                  <i className="bi bi-search"></i>
                </span>
                <input
                  type="text"
                  className="form-control bg-dark text-light border-secondary"
                  placeholder="Search findings (use -term for negative search)"
                  value={searchTerm}
                  onChange={(e) => {
                    setSearchTerm(e.target.value);
                    setCurrentPage(1);
                  }}
                />
                {searchTerm && (
                  <button
                    className="btn btn-outline-secondary btn-sm"
                    onClick={() => {
                      setSearchTerm('');
                      setCurrentPage(1);
                    }}
                  >
                    <i className="bi bi-x"></i>
                  </button>
                )}
              </div>
            </Col>
            <Col md={2}>
              <select
                className="form-select form-select-sm bg-dark text-light border-secondary"
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value);
                  setCurrentPage(1);
                }}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </Col>
            <Col md={2}>
              <select
                className="form-select form-select-sm bg-dark text-light border-secondary"
                value={categoryFilter}
                onChange={(e) => {
                  setCategoryFilter(e.target.value);
                  setCurrentPage(1);
                }}
              >
                <option value="all">All Categories</option>
                {getAvailableCategories.map(category => (
                  <option key={category} value={category}>{category}</option>
                ))}
              </select>
            </Col>
            <Col md={3}>
              <select
                className="form-select form-select-sm bg-dark text-light border-secondary"
                value={templateFilter}
                onChange={(e) => {
                  setTemplateFilter(e.target.value);
                  setCurrentPage(1);
                }}
              >
                <option value="all">All Templates</option>
                {getAvailableTemplates.map(template => (
                  <option key={template} value={template}>{template}</option>
                ))}
              </select>
            </Col>
            <Col md={2}>
              <div className="d-flex justify-content-between align-items-center">
                <small className="text-muted">
                  {filteredFindings.length} of {findings.length}
                </small>
                <Button 
                  variant="outline-secondary" 
                  size="sm" 
                  onClick={() => {
                    setSearchTerm('');
                    setSeverityFilter('all');
                    setCategoryFilter('all');
                    setTemplateFilter('all');
                    setCurrentPage(1);
                  }}
                  disabled={!searchTerm && severityFilter === 'all' && categoryFilter === 'all' && templateFilter === 'all'}
                  title="Clear all filters"
                >
                  <i className="bi bi-x-circle"></i>
                </Button>
              </div>
            </Col>
          </Row>
        </div>
        
        <div className="bg-dark border-bottom px-3 py-2">
          <div className="position-relative">
            {(() => {
              const scanDetails = getScanDetails(scan);
              if (!scanDetails) return null;
              return (
                <div 
                  className="d-flex align-items-center justify-content-between w-100 cursor-pointer"
                  onClick={() => setShowScanSelector(!showScanSelector)}
                  style={{ cursor: 'pointer' }}
                >
                  <div className="d-flex align-items-center flex-wrap">
                    <small className="text-muted me-3">
                      <strong>Scan ID:</strong> {scanDetails.scanId}
                    </small>
                    <Badge bg="secondary" className="me-2">
                      {scanDetails.targetsCount} targets
                    </Badge>
                    <Badge bg="secondary" className="me-2">
                      {scanDetails.templatesCount} templates
                    </Badge>
                    <Badge bg={scanDetails.findingsCount > 0 ? 'danger' : 'success'} className="me-2">
                      {scanDetails.findingsCount} findings
                    </Badge>
                  </div>
                  <div className="d-flex align-items-center">
                    <small className="text-muted me-2">
                      <strong>Executed:</strong> {scanDetails.createdAt ? new Date(scanDetails.createdAt).toLocaleString() : 'Unknown'}
                    </small>
                    <i className={`bi bi-chevron-${showScanSelector ? 'up' : 'down'} text-muted`}></i>
                  </div>
                </div>
              );
            })()}
            {showScanSelector && scans && scans.length > 0 && (
              <div 
                className="position-absolute top-100 start-0 bg-dark border border-secondary rounded shadow-lg"
                style={{ 
                  zIndex: 1000, 
                  minWidth: '500px',
                  maxHeight: '400px',
                  overflowY: 'auto'
                }}
              >
                <div className="p-2">
                  <div className="text-light mb-2">
                    <strong>Select Scan to View:</strong>
                  </div>
                  {scans.map((scanItem, index) => {
                    const details = getScanDetails(scanItem);
                    const isActive = activeNucleiScan?.scan_id === scanItem.scan_id || activeNucleiScan?.id === scanItem.id;
                    const getStatusStyle = (status) => {
                      switch (status) {
                        case 'success':
                          return {
                            bgClass: 'bg-success bg-opacity-25 border border-success',
                            icon: 'bi-check-circle-fill text-success',
                            textClass: 'text-success'
                          };
                        case 'failed':
                          return {
                            bgClass: 'bg-danger bg-opacity-25 border border-danger',
                            icon: 'bi-x-circle-fill text-danger',
                            textClass: 'text-danger'
                          };
                        case 'pending':
                        case 'running':
                          return {
                            bgClass: 'bg-warning bg-opacity-25 border border-warning',
                            icon: 'bi-hourglass-split text-warning',
                            textClass: 'text-warning'
                          };
                        default:
                          return {
                            bgClass: 'bg-secondary bg-opacity-10 border border-secondary',
                            icon: 'bi-question-circle text-secondary',
                            textClass: 'text-secondary'
                          };
                      }
                    };
                    const statusStyle = getStatusStyle(details?.status);
                    return (
                      <div
                        key={scanItem.scan_id || scanItem.id}
                        className={`p-2 rounded mb-1 ${statusStyle.bgClass}`}
                        style={{ cursor: 'pointer' }}
                        onClick={() => handleScanSelect(scanItem)}
                      >
                        <div>
                          <div className="d-flex align-items-center">
                            <i className={`${statusStyle.icon} me-2`}></i>
                            <small className="text-light me-2">
                              <strong>ID:</strong> {details?.scanId}
                            </small>
                            <Badge bg={details?.status === 'success' ? 'success' : details?.status === 'failed' ? 'danger' : 'warning'} className="me-2">
                              {details?.status}
                            </Badge>
                          </div>
                          <div className="mt-1">
                            <Badge bg="secondary" className="me-1">
                              {details?.targetsCount} targets
                            </Badge>
                            <Badge bg="secondary" className="me-1">
                              {details?.templatesCount} templates
                            </Badge>
                            <Badge bg={details?.findingsCount > 0 ? 'danger' : 'success'} className="me-1">
                              {details?.findingsCount} findings
                            </Badge>
                          </div>
                          <div className="mt-1">
                            <small className="text-muted">
                              {details?.createdAt ? new Date(details.createdAt).toLocaleString() : 'Unknown'}
                            </small>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
        
        <Row className="g-0">
          <Col md={4} className="border-end">
            <div className="p-3">
              <div className="d-flex justify-content-between align-items-center mb-3">
                <h6 className="text-light mb-0">
                  <i className="bi bi-list-ul me-2"></i>Findings
                </h6>
                <small className="text-muted">
                  <i className="bi bi-keyboard me-1"></i>
                  Use ↑↓ arrows
                </small>
              </div>
              {renderFindingsList()}
            </div>
          </Col>
          
          <Col md={8}>
            <div className="p-3">
              <h6 className="text-light mb-3">
                <i className="bi bi-info-circle me-2"></i>Details
              </h6>
              {renderFindingDetails()}
            </div>
          </Col>
        </Row>
      </Modal.Body>
      
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export const NucleiHistoryModal = ({ 
  show, 
  handleClose, 
  scans 
}) => {
  const getFindingsCount = (scan) => {
    if (!scan?.result) return 0;
    try {
      if (typeof scan.result === 'string') {
        const parsed = JSON.parse(scan.result);
        return Array.isArray(parsed) ? parsed.length : 0;
      }
      return Array.isArray(scan.result) ? scan.result.length : 0;
    } catch (error) {
      return 0;
    }
  };

  const getErrorDisplay = (error) => {
    if (!error) return null;
    if (error.includes('timeout')) {
      return (
        <span className="text-warning" title="Scan timed out">
          <i className="bi bi-clock-fill me-1"></i>
          Timeout
        </span>
      );
    }
    return (
      <span className="text-danger" title={error}>
        <i className="bi bi-exclamation-triangle-fill me-1"></i>
        Error
      </span>
    );
  };

  const getStatusBadge = (status) => {
    const statusMap = {
      'success': 'success',
      'running': 'primary',
      'pending': 'warning',
      'failed': 'danger',
      'timeout': 'warning'
    };
    return statusMap[status] || 'secondary';
  };

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleClose} 
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className='text-danger'>
          <i className="bi bi-clock-history me-2"></i>
          Nuclei Scan History
        </Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ maxHeight: '70vh', overflowY: 'auto' }}>
        {scans && scans.length > 0 ? (
          <Table striped bordered hover variant="dark">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Targets</th>
                <th>Templates</th>
                <th>Started</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td>
                    <code className="text-info">{scan.id}</code>
                  </td>
                  <td>
                    <Badge bg={getStatusBadge(scan.status)}>
                      {scan.status}
                    </Badge>
                    {scan.error && (
                      <div className="mt-1">
                        {getErrorDisplay(scan.error)}
                      </div>
                    )}
                  </td>
                  <td>
                    <Badge bg={getFindingsCount(scan) > 0 ? 'danger' : 'success'}>
                      {getFindingsCount(scan)}
                    </Badge>
                  </td>
                  <td>
                    <Badge bg="info">
                      {scan.targets?.length || 0}
                    </Badge>
                  </td>
                  <td>
                    <Badge bg="secondary">
                      {scan.templates?.length || 0}
                    </Badge>
                  </td>
                  <td>
                    <small>
                      {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Unknown'}
                    </small>
                  </td>
                  <td>
                    <small>
                      {scan.execution_time ? `${scan.execution_time}s` : 'N/A'}
                    </small>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <div className="text-center text-muted p-4">
            <i className="bi bi-clock-history fs-1 mb-3 d-block"></i>
            <p>No Nuclei scans found for this target.</p>
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};
