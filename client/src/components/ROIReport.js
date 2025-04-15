import { Modal, Container, Row, Col, Table, Badge, Card } from 'react-bootstrap';

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
      const headers = typeof targetURL.http_response_headers === 'string' 
        ? JSON.parse(targetURL.http_response_headers)
        : targetURL.http_response_headers;
      
      const hasCSP = Object.keys(headers || {}).some(header => 
        header.toLowerCase() === 'content-security-policy'
      );
      
      if (!hasCSP) {
        score += 10;
      }
    } catch (error) {
      console.error('Error checking CSP header:', error);
    }
  }
  
  try {
    const headers = typeof targetURL.http_response_headers === 'string'
      ? JSON.parse(targetURL.http_response_headers)
      : targetURL.http_response_headers;
    
    const hasCachingHeaders = Object.keys(headers || {}).some(header => {
      const headerLower = header.toLowerCase();
      return ['cache-control', 'etag', 'expires', 'vary'].includes(headerLower);
    });
    
    if (hasCachingHeaders) {
      score += 10;
    }
  } catch (error) {
    console.error('Error checking caching headers:', error);
  }
  
  const finalScore = Math.max(0, Math.round(score));
  
  return finalScore;
};

const TargetSection = ({ targetURL, roiScore }) => {

  // Process HTTP response
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
    console.error('Error processing HTTP response:', error);
  }
  const truncatedResponse = httpResponse.split('\n').slice(0, 25).join('\n');

  // Process HTTP headers
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
    console.error('Error processing HTTP headers:', error);
  }

  // Process title and web server
  const title = targetURL.title || '';
  const webServer = targetURL.web_server || '';

  // Process technologies
  const technologies = Array.isArray(targetURL.technologies) ? targetURL.technologies : [];

  // Handle katana results - could be string, array, or JSON string
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

  // Handle ffuf results - could be object, string, or JSON string
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
        const headers = typeof targetURL.http_response_headers === 'string'
          ? JSON.parse(targetURL.http_response_headers)
          : targetURL.http_response_headers;
        
        const hasCSP = Object.keys(headers || {}).some(header =>
          header.toLowerCase() === 'content-security-policy'
        );
        
        if (!hasCSP) {
          score += 10;
        }
      } catch (error) {
        console.error('Error checking CSP header:', error);
      }
    }
    
    try {
      const headers = typeof targetURL.http_response_headers === 'string'
        ? JSON.parse(targetURL.http_response_headers)
        : targetURL.http_response_headers;
      
      const hasCachingHeaders = Object.keys(headers || {}).some(header => {
        const headerLower = header.toLowerCase();
        return ['cache-control', 'etag', 'expires', 'vary'].includes(headerLower);
      });
      
      if (hasCachingHeaders) {
        score += 10;
      }
    } catch (error) {
      console.error('Error checking caching headers:', error);
    }
    
    const finalScore = Math.max(0, Math.round(score));
    
    return finalScore;
  };

  // Use the calculated score if the database score is 0 or undefined
  const displayScore = targetURL.roi_score || calculateLocalROIScore();

  return (
    <div className="mb-5 pb-4 border-bottom border-danger">
      <Row className="mb-4">
        <Col md={8}>
          <Card className="bg-dark border-danger">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center mb-4">
                <div className="d-flex align-items-center">
                  <div className="display-4 text-danger me-3">{displayScore}</div>
                  <div className="h3 mb-0 text-white"><a href={targetURL.url} target="_blank" rel="noopener noreferrer">{targetURL.url}</a></div>
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
                <img 
                  src={`data:image/png;base64,${targetURL.screenshot}`}
                  alt="Target Screenshot"
                  className="img-fluid"
                  style={{ 
                    maxHeight: '200px',
                    maxWidth: '100%',
                    objectFit: 'contain',
                    margin: 'auto',
                    display: 'block'
                  }}
                />
              </Card.Body>
            </Card>
          )}
        </Col>
      </Row>

      <Row className="mb-4">
        <Col>
          <Card className="bg-dark border-danger">
            <Card.Body>
              <h4 className="text-danger">SSL/TLS Security Issues</h4>
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

      <Row className="mb-4">
        <Col md={6}>
          <Card className="bg-dark border-danger h-100">
            <Card.Body>
              <h4 className="text-danger">DNS Analysis</h4>
              <div style={{ maxHeight: '350px', overflowY: 'auto' }}>
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
                    ].map(([type, records]) => records && records.length > 0 && (
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
            <Card.Body>
              <h4 className="text-danger">Attack Surface Analysis</h4>
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
              <h4 className="text-danger mt-4">Response Headers</h4>
              <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                <Table className="table-dark">
                  <tbody>
                    {Object.entries(httpHeaders).map(([key, value]) => (
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
            <Card.Body>
              <h4 className="text-danger">Response Preview</h4>
              <pre className="bg-dark text-white p-3 border border-danger rounded" style={{ maxHeight: '200px', overflowY: 'auto' }}>
                {truncatedResponse}
              </pre>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

const ROIReport = ({ show, onHide, targetURLs = [] }) => {
  const sortedTargets = Array.isArray(targetURLs) 
    ? [...targetURLs].sort((a, b) => b.roi_score - a.roi_score)
    : [];

  return (
    <Modal show={show} onHide={onHide} size="xl" className="bg-dark text-white">
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger">Bug Bounty Target ROI Analysis</Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark">
        <Container fluid>
          {sortedTargets.map((target, index) => (
            <TargetSection 
              key={target.id || index} 
              targetURL={target} 
              roiScore={target.roi_score}
            />
          ))}
        </Container>
      </Modal.Body>
    </Modal>
  );
};

export default ROIReport; 