import { Modal, Container, Row, Col, Table, Badge, Card, Button, OverlayTrigger, Tooltip, Spinner } from 'react-bootstrap';
import { useState, useEffect, useMemo, memo } from 'react';

const calculateROIScore = (targetURL) => {
  let score = 50;
  
  const sslIssues = [
    targetURL.has_deprecated_tls,
    targetURL.has_expired_ssl,
    targetURL.has_mismatched_ssl,
    targetURL.has_revoked_ssl,
    targetURL.has_self_signed_ssl,
    targetURL.has_untrusted_root_ssl
  ].filter(Boolean).length;
  
  if (sslIssues > 0) {
    score += sslIssues * 25;
  }
  
  let katanaCount = 0;
  if (targetURL.katana_results) {
    if (Array.isArray(targetURL.katana_results)) {
      katanaCount = targetURL.katana_results.length;
    } else if (typeof targetURL.katana_results === 'string') {
      if (targetURL.katana_results.startsWith('[') || targetURL.katana_results.startsWith('{')) {
        try {
          const parsed = JSON.parse(targetURL.katana_results);
          katanaCount = Array.isArray(parsed) ? parsed.length : 1;
        } catch {
          katanaCount = targetURL.katana_results.split('\n').filter(line => line.trim()).length;
        }
      } else {
        katanaCount = targetURL.katana_results.split('\n').filter(line => line.trim()).length;
      }
    }
  }

  if (katanaCount > 0) {
    score += katanaCount;
  }

  let ffufCount = 0;
  if (targetURL.ffuf_results) {
    if (typeof targetURL.ffuf_results === 'object') {
      ffufCount = targetURL.ffuf_results.endpoints?.length || Object.keys(targetURL.ffuf_results).length || 0;
    } else if (typeof targetURL.ffuf_results === 'string') {
      try {
        const parsed = JSON.parse(targetURL.ffuf_results);
        ffufCount = parsed.endpoints?.length || Object.keys(parsed).length || 0;
      } catch {
        ffufCount = targetURL.ffuf_results.split('\n').filter(line => line.trim()).length;
      }
    }
  }
  
  if (ffufCount > 3) {
    const extraEndpoints = ffufCount - 3;
    const fuzzPoints = Math.min(15, extraEndpoints * 3);
    score += fuzzPoints;
  }
  
  const techCount = targetURL.technologies?.length || 0;
  if (techCount > 0) {
    score += techCount * 3;
  }
  
  if (targetURL.status_code === 200 && katanaCount > 10) {
    try {
      let headers = null;
      if (typeof targetURL.http_response_headers === 'string' && targetURL.http_response_headers.trim()) {
        headers = JSON.parse(targetURL.http_response_headers);
      } else if (typeof targetURL.http_response_headers === 'object') {
        headers = targetURL.http_response_headers;
      }
      
      if (headers) {
        const hasCSP = Object.keys(headers).some(header => 
          header.toLowerCase() === 'content-security-policy'
        );
        
        if (!hasCSP) {
          score += 10;
        }
      }
    } catch (error) {
    }
  }
  
  try {
    let headers = null;
    if (typeof targetURL.http_response_headers === 'string' && targetURL.http_response_headers.trim()) {
      headers = JSON.parse(targetURL.http_response_headers);
    } else if (typeof targetURL.http_response_headers === 'object') {
      headers = targetURL.http_response_headers;
    }
    
    if (headers) {
      const hasCachingHeaders = Object.keys(headers).some(header => {
        const headerLower = header.toLowerCase();
        return ['cache-control', 'etag', 'expires', 'vary'].includes(headerLower);
      });
      
      if (hasCachingHeaders) {
        score += 10;
      }
    }
  } catch (error) {
  }
  
  const finalScore = Math.max(0, Math.round(score));
  
  return finalScore;
};

const TargetSection = memo(({ targetURL, roiScore, onDelete, onAddAsScope, isDeleting, isAdding, isAlreadyScope }) => {
  const [showLightbox, setShowLightbox] = useState(false);

  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === 'Escape' && showLightbox) {
        setShowLightbox(false);
      }
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [showLightbox]);

  const processedData = useMemo(() => {
    let httpResponse = '';
    try {
      if (targetURL.http_response) {
        if (typeof targetURL.http_response === 'string') {
          httpResponse = targetURL.http_response;
        } else if (targetURL.http_response.String) {
          httpResponse = targetURL.http_response.String;
        }
      }
    } catch (error) {
    }
    const truncatedResponse = httpResponse.split('\n').slice(0, 25).join('\n');

    let httpHeaders = {};
    try {
      if (targetURL.http_response_headers) {
        if (typeof targetURL.http_response_headers === 'string') {
          httpHeaders = JSON.parse(targetURL.http_response_headers);
        } else {
          httpHeaders = targetURL.http_response_headers;
        }
      }
    } catch (error) {
    }

    const title = targetURL.title || '';
    const webServer = targetURL.web_server || '';
    const technologies = Array.isArray(targetURL.technologies) ? targetURL.technologies : [];

    let katanaResults = 0;
    if (targetURL.katana_results) {
      if (Array.isArray(targetURL.katana_results)) {
        katanaResults = targetURL.katana_results.length;
      } else if (typeof targetURL.katana_results === 'string') {
        if (targetURL.katana_results.startsWith('[') || targetURL.katana_results.startsWith('{')) {
          try {
            const parsed = JSON.parse(targetURL.katana_results);
            katanaResults = Array.isArray(parsed) ? parsed.length : 1;
          } catch {
            katanaResults = targetURL.katana_results.split('\n').filter(line => line.trim()).length;
          }
        } else {
          katanaResults = targetURL.katana_results.split('\n').filter(line => line.trim()).length;
        }
      }
    }

    let ffufResults = 0;
    if (targetURL.ffuf_results) {
      if (typeof targetURL.ffuf_results === 'object') {
        ffufResults = targetURL.ffuf_results.endpoints?.length || Object.keys(targetURL.ffuf_results).length || 0;
      } else if (typeof targetURL.ffuf_results === 'string') {
        try {
          const parsed = JSON.parse(targetURL.ffuf_results);
          ffufResults = parsed.endpoints?.length || Object.keys(parsed).length || 0;
        } catch {
          ffufResults = targetURL.ffuf_results.split('\n').filter(line => line.trim()).length;
        }
      }
    }

    return { truncatedResponse, httpHeaders, title, webServer, technologies, katanaResults, ffufResults };
  }, [targetURL]);

  const { truncatedResponse, httpHeaders, title, webServer, technologies, katanaResults, ffufResults } = processedData;

  // Calculate ROI score based on the same logic as the backend
  const calculateLocalROIScore = () => {
    let score = 50;
    
    const sslIssues = [
      targetURL.has_deprecated_tls,
      targetURL.has_expired_ssl,
      targetURL.has_mismatched_ssl,
      targetURL.has_revoked_ssl,
      targetURL.has_self_signed_ssl,
      targetURL.has_untrusted_root_ssl
    ].filter(Boolean).length;
    
    if (sslIssues > 0) {
      score += sslIssues * 25;
    }
    
    if (katanaResults > 0) {
      score += katanaResults;
    }
    
    if (targetURL.status_code === 404) {
      score += 50;
    } else if (ffufResults > 0) {
      score += ffufResults * 2;
    }
    
    const techCount = targetURL.technologies?.length || 0;
    if (techCount > 0) {
      score += techCount * 3;
    }
    
    if (targetURL.status_code === 200 && katanaResults > 10) {
      try {
        let headers = null;
        if (typeof targetURL.http_response_headers === 'string' && targetURL.http_response_headers.trim()) {
          headers = JSON.parse(targetURL.http_response_headers);
        } else if (typeof targetURL.http_response_headers === 'object') {
          headers = targetURL.http_response_headers;
        }
        
        if (headers) {
          const hasCSP = Object.keys(headers).some(header =>
            header.toLowerCase() === 'content-security-policy'
          );
          
          if (!hasCSP) {
            score += 10;
          }
        }
      } catch (error) {
      }
    }
    
    try {
      let headers = null;
      if (typeof targetURL.http_response_headers === 'string' && targetURL.http_response_headers.trim()) {
        headers = JSON.parse(targetURL.http_response_headers);
      } else if (typeof targetURL.http_response_headers === 'object') {
        headers = targetURL.http_response_headers;
      }
      
      if (headers) {
        const hasCachingHeaders = Object.keys(headers).some(header => {
          const headerLower = header.toLowerCase();
          return ['cache-control', 'etag', 'expires', 'vary'].includes(headerLower);
        });
        
        if (hasCachingHeaders) {
          score += 10;
        }
      }
    } catch (error) {
    }
    
    const finalScore = Math.max(0, Math.round(score));
    
    return finalScore;
  };

  // Use the calculated score if the database score is 0 or undefined
  const displayScore = targetURL.roi_score || calculateLocalROIScore();

  return (
    <div className="mb-3 pb-3 border-bottom border-danger">
      <Row className="mb-3">
        <Col md={8}>
          <Card className="bg-dark border-danger">
            <Card.Body className="p-3">
              <div className="d-flex justify-content-between align-items-center mb-4">
                <div className="d-flex align-items-center flex-grow-1">
                  <div className="display-4 text-danger me-3">{displayScore}</div>
                  <div className="h3 mb-0 text-white">
                    <a href={targetURL.url} target="_blank" rel="noopener noreferrer">{targetURL.url}</a>
                    {targetURL.screenshot && targetURL.screenshot.trim() !== '' && (
                      <OverlayTrigger
                        placement="top"
                        overlay={<Tooltip>Screenshot captured</Tooltip>}
                      >
                        <i className="bi bi-camera-fill text-success ms-2" style={{ fontSize: '0.7em' }}></i>
                      </OverlayTrigger>
                    )}
                  </div>
                </div>
                <div className="d-flex align-items-center gap-2 ms-3">
                  {isAlreadyScope ? (
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
                        onClick={() => onAddAsScope(targetURL)}
                        disabled={isAdding}
                        style={{ padding: '0.25rem 0.5rem' }}
                      >
                        {isAdding ? (
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
                      onClick={() => onDelete(targetURL.id)}
                      disabled={isDeleting}
                      style={{ padding: '0.25rem 0.5rem' }}
                    >
                      {isDeleting ? (
                        <i className="bi bi-hourglass-split"></i>
                      ) : (
                        <i className="bi bi-trash"></i>
                      )}
                    </Button>
                  </OverlayTrigger>
                </div>
              </div>
              <Table className="table-dark">
                <tbody>
                  <tr>
                    <td className="fw-bold">Response Code:</td>
                    <td>{targetURL.status_code || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Page Title:</td>
                    <td>{title || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Server Type:</td>
                    <td>{webServer || 'N/A'}</td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Response Size:</td>
                    <td>{targetURL.content_length || 0} bytes</td>
                  </tr>
                  <tr>
                    <td className="fw-bold">Tech Stack:</td>
                    <td>
                      {technologies.length > 0 ? (
                        technologies.map((tech, index) => (
                          <Badge key={index} bg="danger" className="me-1">
                            {typeof tech === 'string' ? tech : ''}
                          </Badge>
                        ))
                      ) : (
                        'N/A'
                      )}
                    </td>
                  </tr>
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Col>
        <Col md={4}>
          {targetURL.screenshot && (
            <Card className="bg-dark border-danger h-100">
              <Card.Body className="p-2 d-flex align-items-center justify-content-center">
                <OverlayTrigger
                  placement="top"
                  overlay={<Tooltip>Click to view full size</Tooltip>}
                >
                  <img 
                    src={`data:image/png;base64,${targetURL.screenshot}`}
                    alt="Target Screenshot"
                    className="img-fluid"
                    onClick={() => setShowLightbox(true)}
                    style={{ 
                      maxHeight: '180px',
                      maxWidth: '100%',
                      objectFit: 'contain',
                      margin: 'auto',
                      display: 'block',
                      cursor: 'pointer',
                      transition: 'transform 0.2s',
                    }}
                    onMouseOver={(e) => e.currentTarget.style.transform = 'scale(1.05)'}
                    onMouseOut={(e) => e.currentTarget.style.transform = 'scale(1)'}
                  />
                </OverlayTrigger>
              </Card.Body>
            </Card>
          )}
        </Col>
      </Row>

      <Row className="mb-3">
        <Col>
          <Card className="bg-dark border-danger">
            <Card.Body className="p-3">
              <h5 className="text-danger mb-2">SSL/TLS Security Issues</h5>
              <div className="d-flex flex-wrap gap-2">
                {Object.entries({
                  'Deprecated TLS': targetURL.has_deprecated_tls,
                  'Expired SSL': targetURL.has_expired_ssl,
                  'Mismatched SSL': targetURL.has_mismatched_ssl,
                  'Revoked SSL': targetURL.has_revoked_ssl,
                  'Self-Signed SSL': targetURL.has_self_signed_ssl,
                  'Untrusted Root': targetURL.has_untrusted_root_ssl,
                  'Wildcard TLS': targetURL.has_wildcard_tls
                }).map(([name, value]) => (
                  <Badge 
                    key={name} 
                    bg={value ? 'danger' : 'secondary'}
                    className="p-2"
                  >
                    {value ? '❌' : '✓'} {name}
                  </Badge>
                ))}
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row className="mb-3">
        <Col md={6}>
          <Card className="bg-dark border-danger h-100">
            <Card.Body className="p-3">
              <h5 className="text-danger mb-2">DNS Analysis</h5>
              <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                <Table className="table-dark">
                  <tbody>
                    {[
                      ['A', targetURL.dns_a_records],
                      ['AAAA', targetURL.dns_aaaa_records],
                      ['CNAME', targetURL.dns_cname_records],
                      ['MX', targetURL.dns_mx_records],
                      ['TXT', targetURL.dns_txt_records],
                      ['NS', targetURL.dns_ns_records],
                      ['PTR', targetURL.dns_ptr_records],
                      ['SRV', targetURL.dns_srv_records]
                    ].map(([type, records]) => records && Array.isArray(records) && records.length > 0 && (
                      <tr key={type}>
                        <td className="fw-bold" style={{ width: '100px' }}>{type}:</td>
                        <td>{records.join(', ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col md={6}>
          <Card className="bg-dark border-danger h-100">
            <Card.Body className="p-3">
              <h5 className="text-danger mb-2">Attack Surface Analysis</h5>
              <Table className="table-dark">
                <tbody>
                  <tr>
                    <td>Crawl Results:</td>
                    <td>{katanaResults}</td>
                  </tr>
                  <tr>
                    <td>Endpoint Brute-Force Results:</td>
                    <td>{ffufResults}</td>
                  </tr>
                </tbody>
              </Table>
              <h5 className="text-danger mt-3 mb-2">Response Headers</h5>
              <div style={{ maxHeight: '150px', overflowY: 'auto' }}>
                <Table className="table-dark">
                  <tbody>
                    {Object.entries(httpHeaders || {}).map(([key, value]) => (
                      <tr key={key}>
                        <td className="fw-bold" style={{ width: '150px' }}>{key}:</td>
                        <td>{typeof value === 'string' ? value : JSON.stringify(value)}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row>
        <Col>
          <Card className="bg-dark border-danger">
            <Card.Body className="p-3">
              <h5 className="text-danger mb-2">Response Preview</h5>
              <pre className="bg-dark text-white p-2 border border-danger rounded" style={{ maxHeight: '150px', overflowY: 'auto', fontSize: '0.85rem' }}>
                {truncatedResponse}
              </pre>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {showLightbox && targetURL.screenshot && (
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
          onClick={() => setShowLightbox(false)}
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
              onClick={() => setShowLightbox(false)}
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
              src={`data:image/png;base64,${targetURL.screenshot}`}
              alt="Target Screenshot - Full Size"
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
    </div>
  );
});

const ROIReport = memo(({ show, onHide, targetURLs = [], setTargetURLs, fetchScopeTargets }) => {
  const safeTargetURLs = targetURLs || [];
  
  const [currentPage, setCurrentPage] = useState(1);
  const [deletingUrls, setDeletingUrls] = useState(new Set());
  const [addingUrls, setAddingUrls] = useState(new Set());
  const [existingScopeTargets, setExistingScopeTargets] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  
  const itemsPerPage = 1;

  useEffect(() => {
    if (show) {
      setIsLoading(true);
      fetchExistingScopeTargets();
    } else {
      setIsLoading(true);
      setCurrentPage(1);
    }
  }, [show]);

  const fetchExistingScopeTargets = async () => {
    try {
      const response = await fetch(`/api/scopetarget/read`);
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

  const handleDeleteUrl = async (urlId) => {
    if (deletingUrls.has(urlId)) return;
    
    setDeletingUrls(prev => new Set(prev).add(urlId));
    
    try {
      const response = await fetch(`/api/api/target-urls/${urlId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete URL from database');
      }

      const updatedUrls = safeTargetURLs.filter(url => url.id !== urlId);
      if (setTargetURLs) {
        setTargetURLs(updatedUrls);
      }
      
      if (currentPage > 1 && updatedUrls.length <= (currentPage - 1) * itemsPerPage) {
        setCurrentPage(currentPage - 1);
      }
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
      
      const response = await fetch(`/api/scopetarget/add`, {
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
  
  const sortedTargets = useMemo(() => {
    if (show && Array.isArray(safeTargetURLs) && safeTargetURLs.length > 0) {
      return [...safeTargetURLs]
        .map(target => ({
          ...target,
          _calculatedScore: target.roi_score || calculateROIScore(target),
          _hasScreenshot: target.screenshot && target.screenshot.trim() !== ''
        }))
        .sort((a, b) => {
          if (a._hasScreenshot && !b._hasScreenshot) return -1;
          if (!a._hasScreenshot && b._hasScreenshot) return 1;
          return b._calculatedScore - a._calculatedScore;
        });
    }
    return [];
  }, [show, safeTargetURLs]);

  useEffect(() => {
    if (show && Array.isArray(safeTargetURLs) && safeTargetURLs.length > 0) {
      setIsLoading(false);
    }
  }, [show, safeTargetURLs]);

  const totalPages = Math.ceil(sortedTargets.length / itemsPerPage);
  const currentTarget = sortedTargets[currentPage - 1];

  const handlePreviousPage = () => {
    setCurrentPage(prev => Math.max(prev - 1, 1));
  };

  const handleNextPage = () => {
    setCurrentPage(prev => Math.min(prev + 1, totalPages));
  };

  const PaginationControls = () => (
    <div className="d-flex justify-content-between align-items-center mb-3">
      <Button 
        variant="outline-danger" 
        onClick={handlePreviousPage}
        disabled={currentPage === 1}
      >
        ← Previous
      </Button>
      <span className="text-white">
        Page {currentPage} of {totalPages}
      </span>
      <Button 
        variant="outline-danger" 
        onClick={handleNextPage}
        disabled={currentPage === totalPages}
      >
        Next →
      </Button>
    </div>
  );

  return (
    <Modal 
      show={show} 
      onHide={onHide} 
      size="xl" 
      fullscreen={true}
      backdrop="static"
      className="bg-dark text-white"
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">Bug Bounty Target ROI Analysis</Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark">
        <Container fluid>
          {isLoading ? (
            <div className="d-flex justify-content-center align-items-center" style={{ minHeight: '400px' }}>
              <div className="text-center">
                <Spinner animation="border" variant="danger" />
                <p className="text-white mt-3">Loading ROI Analysis...</p>
              </div>
            </div>
          ) : (
            <>
              <PaginationControls />
              {currentTarget && (
                <TargetSection 
                  key={currentTarget.id} 
                  targetURL={currentTarget} 
                  roiScore={currentTarget._calculatedScore || currentTarget.roi_score}
                  onDelete={handleDeleteUrl}
                  onAddAsScope={handleAddAsScopeTarget}
                  isDeleting={deletingUrls.has(currentTarget.id)}
                  isAdding={addingUrls.has(currentTarget.id)}
                  isAlreadyScope={isUrlAlreadyScopeTarget(currentTarget.url)}
                />
              )}
              <PaginationControls />
            </>
          )}
        </Container>
      </Modal.Body>
    </Modal>
  );
});

export default ROIReport; 