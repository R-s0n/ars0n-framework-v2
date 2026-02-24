import React, { useState } from 'react';
import { Modal, Row, Col, Button, ListGroup, Form, InputGroup, Alert } from 'react-bootstrap';

const GoogleDorkingModal = ({ show, handleClose, companyName, onDomainAdd, error, onClearError }) => {
  const [newDomain, setNewDomain] = useState('');
  const [currentSearchUrl, setCurrentSearchUrl] = useState('');
  const [iframeError, setIframeError] = useState(false);

  const dorkPatterns = [
    {
      category: "Direct Domain Patterns",
      patterns: [
        { name: "Primary .com", query: `"${companyName}.com"` },
        { name: "Primary .net", query: `"${companyName}.net"` },
        { name: "Primary .org", query: `"${companyName}.org"` },
        { name: "Primary .app", query: `"${companyName}.app"` },
        { name: "Primary .io", query: `"${companyName}.io"` },
        { name: "Primary .co", query: `"${companyName}.co"` },
        { name: "Primary .us", query: `"${companyName}.us"` },
        { name: "Primary .biz", query: `"${companyName}.biz"` }
      ]
    },
    {
      category: "Subdomain Discovery",
      patterns: [
        { name: "All .com subdomains", query: `site:*.${companyName}.com` },
        { name: "All .net subdomains", query: `site:*.${companyName}.net` },
        { name: "All .org subdomains", query: `site:*.${companyName}.org` },
        { name: "All .app subdomains", query: `site:*.${companyName}.app` },
        { name: "All .io subdomains", query: `site:*.${companyName}.io` }
      ]
    },
    {
      category: "Domain Variations",
      patterns: [
        { name: "Company + domain", query: `"${companyName}" "domain" ".com"` },
        { name: "Company + website", query: `"${companyName}" "website" ".com"` },
        { name: "Company in URL", query: `"${companyName}" inurl:${companyName}` },
        { name: "Company plural", query: `"${companyName}s.com"` },
        { name: "Company with 'the'", query: `"the${companyName}.com"` },
        { name: "Company with 'my'", query: `"my${companyName}.com"` },
        { name: "Company with 'get'", query: `"get${companyName}.com"` },
        { name: "Company with 'go'", query: `"go${companyName}.com"` }
      ]
    },
    {
      category: "Official Website References",
      patterns: [
        { name: "Visit our website", query: `"${companyName}" "visit our website"` },
        { name: "Official website", query: `"${companyName}" "official website"` },
        { name: "Company website", query: `"${companyName}" "company website"` },
        { name: "Homepage references", query: `"${companyName}" "homepage"` },
        { name: "WWW references", query: `"${companyName}" "www."` },
        { name: "HTTPS references", query: `"${companyName}" "https://"` },
        { name: "URL references", query: `"${companyName}" "url"` }
      ]
    },
    {
      category: "Business & Marketing",
      patterns: [
        { name: "Press releases", query: `"${companyName}" "press release" site:*.com` },
        { name: "About us pages", query: `"${companyName}" inurl:about site:*.com` },
        { name: "Contact pages", query: `"${companyName}" inurl:contact site:*.com` },
        { name: "Careers pages", query: `"${companyName}" inurl:careers site:*.com` },
        { name: "Investor relations", query: `"${companyName}" "investor relations"` },
        { name: "News mentions", query: `"${companyName}" "news" site:*.com` }
      ]
    },
    {
      category: "Technical Discovery",
      patterns: [
        { name: "SSL certificates", query: `"${companyName}" site:crt.sh` },
        { name: "DNS records", query: `"${companyName}" "DNS" "record"` },
        { name: "Whois data", query: `"${companyName}" "whois" "domain"` },
        { name: "Domain registration", query: `"${companyName}" "domain registration"` },
        { name: "Certificate transparency", query: `"${companyName}" "certificate transparency"` }
      ]
    },
    {
      category: "Brand Variations",
      patterns: [
        { name: "No spaces", query: `"${companyName.replace(/\s+/g, '')}.com"` },
        { name: "With dashes", query: `"${companyName.replace(/\s+/g, '-')}.com"` },
        { name: "With underscores", query: `"${companyName.replace(/\s+/g, '_')}.com"` },
        { name: "Abbreviated", query: `"${companyName.split(' ').map(word => word[0]).join('').toLowerCase()}.com"` },
        { name: "First word only", query: `"${companyName.split(' ')[0]}.com"` },
        { name: "Last word only", query: `"${companyName.split(' ').slice(-1)[0]}.com"` }
      ]
    },
    {
      category: "International Domains",
      patterns: [
        { name: "UK domains", query: `"${companyName}" site:*.co.uk` },
        { name: "Canadian domains", query: `"${companyName}" site:*.ca` },
        { name: "Australian domains", query: `"${companyName}" site:*.com.au` },
        { name: "German domains", query: `"${companyName}" site:*.de` },
        { name: "French domains", query: `"${companyName}" site:*.fr` },
        { name: "European domains", query: `"${companyName}" site:*.eu` },
        { name: "Japanese domains", query: `"${companyName}" site:*.jp` },
        { name: "Brazilian domains", query: `"${companyName}" site:*.br` },
        { name: "Spanish domains", query: `"${companyName}" site:*.es` },
        { name: "Italian domains", query: `"${companyName}" site:*.it` },
        { name: "Dutch domains", query: `"${companyName}" site:*.nl` },
        { name: "Swiss domains", query: `"${companyName}" site:*.ch` },
        { name: "Swedish domains", query: `"${companyName}" site:*.se` },
        { name: "Indian domains", query: `"${companyName}" site:*.in` }
      ]
    },
    {
      category: "Social & Email Discovery",
      patterns: [
        { name: "Email domains", query: `"@${companyName}.com"` },
        { name: "Contact emails", query: `"contact@${companyName}"` },
        { name: "Info emails", query: `"info@${companyName}"` },
        { name: "Support emails", query: `"support@${companyName}"` },
        { name: "Social media links", query: `"${companyName}" "follow us" site:*.com` },
        { name: "LinkedIn company", query: `"${companyName}" site:linkedin.com` }
      ]
    },
    {
      category: "File & Document Discovery",
      patterns: [
        { name: "PDF documents", query: `"${companyName}" filetype:pdf site:*.com` },
        { name: "Word documents", query: `"${companyName}" filetype:doc site:*.com` },
        { name: "Excel files", query: `"${companyName}" filetype:xls site:*.com` },
        { name: "Privacy policies", query: `"${companyName}" "privacy policy" site:*.com` },
        { name: "Terms of service", query: `"${companyName}" "terms of service" site:*.com` },
        { name: "Annual reports", query: `"${companyName}" "annual report" filetype:pdf` }
      ]
    },
    {
      category: "WHOIS & Registration Patterns",
      patterns: [
        { name: "Registrant Organization", query: `"Registrant Organization" "${companyName}"` },
        { name: "Registrant Name", query: `"Registrant Name" "${companyName}"` },
        { name: "Registered to", query: `"Registered to" "${companyName}"` },
        { name: "Domain Owner", query: `"Domain Owner" "${companyName}"` },
        { name: "Domain registered by", query: `"Domain registered by" "${companyName}"` }
      ]
    },
    {
      category: "Reverse WHOIS & Domain Databases",
      patterns: [
        { name: "DomainTools WHOIS", query: `"${companyName}" site:whois.domaintools.com` },
        { name: "WHOIS.com", query: `"${companyName}" site:whois.com` },
        { name: "DomainBigData", query: `"${companyName}" site:domainbigdata.com` },
        { name: "SecurityTrails", query: `"${companyName}" site:securitytrails.com` },
        { name: "WhoXY", query: `"${companyName}" site:whoxy.com` }
      ]
    },
    {
      category: "Modern TLDs & Extensions",
      patterns: [
        { name: "AI domains", query: `"${companyName}" site:*.ai` },
        { name: "XYZ domains", query: `"${companyName}" site:*.xyz` },
        { name: "Tech domains", query: `"${companyName}" site:*.tech` },
        { name: "Cloud domains", query: `"${companyName}" site:*.cloud` },
        { name: "Inc domains", query: `"${companyName}" site:*.inc` },
        { name: "Me domains", query: `"${companyName}" site:*.me` },
        { name: "TV domains", query: `"${companyName}" site:*.tv` },
        { name: "Info domains", query: `"${companyName}" site:*.info` },
        { name: "Pro domains", query: `"${companyName}" site:*.pro` },
        { name: "Site domains", query: `"${companyName}" site:*.site` },
        { name: "Online domains", query: `"${companyName}" site:*.online` },
        { name: "Store domains", query: `"${companyName}" site:*.store` },
        { name: "Shop domains", query: `"${companyName}" site:*.shop` },
        { name: "Dev domains", query: `"${companyName}" site:*.dev` }
      ]
    },
    {
      category: "Domain Portfolio & Brand Protection",
      patterns: [
        { name: "Domain portfolio", query: `"${companyName}" "domain portfolio"` },
        { name: "Our domains", query: `"${companyName}" "our domains"` },
        { name: "Brand protection", query: `"${companyName}" "brand protection"` },
        { name: "List of domains", query: `"${companyName}" "list of domains"` },
        { name: "All our domains", query: `"${companyName}" "all our domains"` },
        { name: "Subsidiary domains", query: `"${companyName}" "subsidiary domains"` },
        { name: "Acquired domains", query: `"${companyName}" "acquired domains"` }
      ]
    },
    {
      category: "Public Filings & Legal",
      patterns: [
        { name: "Intellectual property", query: `"${companyName}" "intellectual property"` },
        { name: "Trademark domain", query: `"${companyName}" "trademark" "domain"` },
        { name: "Legal domain", query: `"${companyName}" "legal" "domain"` },
        { name: "Terms and conditions", query: `"${companyName}" "terms and conditions" "domain"` }
      ]
    },
    {
      category: "DNS & Certificate Transparency",
      patterns: [
        { name: "Google Transparency", query: `"${companyName}" site:transparencyreport.google.com` },
        { name: "Censys", query: `"${companyName}" site:censys.io` },
        { name: "Shodan", query: `"${companyName}" site:shodan.io` },
        { name: "VirusTotal", query: `"${companyName}" site:virustotal.com` }
      ]
    },
    {
      category: "Press Releases & News",
      patterns: [
        { name: "Launches new domain", query: `"${companyName}" "launches new domain"` },
        { name: "Announces new website", query: `"${companyName}" "announces new website"` },
        { name: "Acquires domain", query: `"${companyName}" "acquires domain"` }
      ]
    },
    {
      category: "Public Code & Configuration Leaks",
      patterns: [
        { name: "GitHub README", query: `"${companyName}" site:github.com inurl:README` },
        { name: "GitHub config", query: `"${companyName}" site:github.com inurl:config` },
        { name: "Pastebin", query: `"${companyName}" site:pastebin.com` },
        { name: "GitLab", query: `"${companyName}" site:gitlab.com` },
        { name: "Bitbucket", query: `"${companyName}" site:bitbucket.org` },
        { name: "ENV files", query: `"${companyName}" "domain" filetype:env` },
        { name: "JSON files", query: `"${companyName}" "domain" filetype:json` },
        { name: "YAML files", query: `"${companyName}" "domain" filetype:yaml` },
        { name: "XML files", query: `"${companyName}" "domain" filetype:xml` }
      ]
    },
    {
      category: "Analytics & Tracking",
      patterns: [
        { name: "Google Analytics", query: `"${companyName}" "Google Analytics" "UA-" site:*.com` },
        { name: "Google Tag Manager", query: `"${companyName}" "Google Tag Manager" "GTM-" site:*.com` },
        { name: "Analytics.js", query: `"${companyName}" "analytics.js" site:*.com` },
        { name: "Tracking ID", query: `"${companyName}" "tracking ID" site:*.com` }
      ]
    },
    {
      category: "Archive & Historical Data",
      patterns: [
        { name: "Web Archive", query: `"${companyName}" site:web.archive.org` },
        { name: "Archive.org", query: `"${companyName}" site:archive.org` },
        { name: "Archive.is", query: `"${companyName}" site:archive.is` },
        { name: "Wayback Machine", query: `"${companyName}" site:waybackmachine.org` }
      ]
    },
    {
      category: "Domain Sale & Auction Sites",
      patterns: [
        { name: "Sedo", query: `"${companyName}" site:sedo.com` },
        { name: "Afternic", query: `"${companyName}" site:afternic.com` },
        { name: "Dan.com", query: `"${companyName}" site:dan.com` },
        { name: "GoDaddy", query: `"${companyName}" site:godaddy.com` },
        { name: "Namecheap", query: `"${companyName}" site:namecheap.com` },
        { name: "Flippa", query: `"${companyName}" site:flippa.com` }
      ]
    },
    {
      category: "Security & Threat Intelligence",
      patterns: [
        { name: "VirusTotal", query: `"${companyName}" site:virustotal.com` },
        { name: "AbuseIPDB", query: `"${companyName}" site:abuseipdb.com` },
        { name: "ThreatCrowd", query: `"${companyName}" site:threatcrowd.org` },
        { name: "Hybrid Analysis", query: `"${companyName}" site:hybrid-analysis.com` }
      ]
    },
    {
      category: "App Stores & Mobile",
      patterns: [
        { name: "Google Play Store", query: `"${companyName}" site:play.google.com` },
        { name: "Apple App Store", query: `"${companyName}" site:apps.apple.com` },
        { name: "App website", query: `"${companyName}" "app website"` },
        { name: "Download our app", query: `"${companyName}" "download our app"` }
      ]
    },
    {
      category: "CDN & Hosting",
      patterns: [
        { name: "CDN references", query: `"${companyName}" "cdn" site:*.com` },
        { name: "Hosted by", query: `"${companyName}" "hosted by" site:*.com` },
        { name: "CloudFront", query: `"${companyName}" "cloudfront.net"` },
        { name: "Azure Websites", query: `"${companyName}" "azurewebsites.net"` },
        { name: "Heroku", query: `"${companyName}" "herokuapp.com"` }
      ]
    },
    {
      category: "Advanced Discovery Patterns",
      patterns: [
        { name: "Redirects to", query: `"${companyName}" "redirects to"` },
        { name: "Formerly known as", query: `"${companyName}" "formerly known as"` },
        { name: "Previously at", query: `"${companyName}" "previously at"` },
        { name: "Parent company", query: `"${companyName}" "parent company"` },
        { name: "Sister company", query: `"${companyName}" "sister company"` }
      ]
    }
  ];

  const loadSearchInIframe = (query) => {
    setIframeError(false);
    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}&igu=1`;
    setCurrentSearchUrl(searchUrl);
  };

  const openGoogleSearchInNewTab = (query) => {
    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
    window.open(searchUrl, '_blank');
  };

  const handleIframeError = () => {
    setIframeError(true);
  };

  const handleAddDomain = () => {
    if (newDomain.trim()) {
      onDomainAdd(newDomain.trim());
      setNewDomain('');
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleAddDomain();
    }
  };

  const handleDomainInputChange = (e) => {
    setNewDomain(e.target.value);
    if (error && onClearError) {
      onClearError();
    }
  };

  return (
    <Modal 
      show={show} 
      onHide={handleClose} 
      size="xl" 
      data-bs-theme="dark"
      dialogClassName="modal-90w"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Manual Google Dorking - {companyName}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ height: '70vh', overflow: 'hidden' }}>
        <Row style={{ height: '100%' }}>
          <Col md={4} style={{ height: '100%', overflowY: 'auto', paddingRight: '15px' }}>
            <h5 className="text-danger mb-3">Google Dork Patterns</h5>
            {dorkPatterns.map((category, categoryIndex) => (
              <div key={categoryIndex} className="mb-4">
                <h6 className="text-secondary mb-2">{category.category}</h6>
                <ListGroup variant="flush">
                  {category.patterns.map((pattern, patternIndex) => (
                    <ListGroup.Item 
                      key={patternIndex}
                      className="bg-dark border-secondary p-2"
                      style={{ cursor: 'pointer' }}
                      onClick={() => loadSearchInIframe(pattern.query)}
                    >
                      <div className="d-flex justify-content-between align-items-center">
                        <small className="text-white fw-bold">{pattern.name}</small>
                        <div className="d-flex gap-1">
                          <Button 
                            variant="outline-danger" 
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              loadSearchInIframe(pattern.query);
                            }}
                            title="Load in iframe"
                          >
                            Load
                          </Button>
                          <Button 
                            variant="outline-secondary" 
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              openGoogleSearchInNewTab(pattern.query);
                            }}
                            title="Open in new tab"
                          >
                            <i className="bi bi-box-arrow-up-right"></i>
                          </Button>
                        </div>
                      </div>
                      <div className="text-white-50 small mt-1">
                        {pattern.query}
                      </div>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              </div>
            ))}
          </Col>
          
          <Col md={8} style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <div style={{ flex: 1, marginBottom: '20px', position: 'relative' }}>
              {iframeError && (
                <Alert variant="warning" className="mb-2">
                  <small>
                    <i className="bi bi-exclamation-triangle me-2"></i>
                    Google blocks iframe embedding. Use the <i className="bi bi-box-arrow-up-right"></i> button to open in a new tab.
                  </small>
                </Alert>
              )}
              
              {currentSearchUrl ? (
                <iframe
                  src={currentSearchUrl}
                  style={{ 
                    width: '100%', 
                    height: '100%', 
                    border: '1px solid #6c757d', 
                    borderRadius: '8px',
                    backgroundColor: 'white'
                  }}
                  title="Google Search Results"
                  onError={handleIframeError}
                  onLoad={(e) => {
                    // Check if iframe loaded successfully
                    try {
                      const iframe = e.target;
                      // If we can't access the content, it means it was blocked
                      if (!iframe.contentWindow || !iframe.contentWindow.location) {
                        handleIframeError();
                      }
                    } catch (error) {
                      handleIframeError();
                    }
                  }}
                />
              ) : (
                <div style={{ 
                  height: '100%', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  border: '2px dashed #6c757d', 
                  borderRadius: '8px' 
                }}>
                  <div className="text-center">
                    <h4 className="text-danger mb-3">Google Search Results</h4>
                    <p className="text-white mb-3">
                      Click any Google Dork pattern on the left to load the search results here.
                    </p>
                    <p className="text-white-50 small">
                      Review the search results for domains owned by <strong>{companyName}</strong> and add them using the form below.
                    </p>
                    <div className="text-danger mt-4">
                      <i className="bi bi-search" style={{ fontSize: '3rem' }}></i>
                    </div>
                  </div>
                </div>
              )}
            </div>
            
            <div className="border-top pt-3">
              <h5 className="text-danger mb-3">Add Discovered Domain</h5>
              {error && (
                <Alert variant="danger" className="mb-3">
                  <small>{error}</small>
                </Alert>
              )}
              <InputGroup>
                <Form.Control
                  type="text"
                  placeholder="Enter domain (e.g., example.com)"
                  value={newDomain}
                  onChange={handleDomainInputChange}
                  onKeyPress={handleKeyPress}
                  className="bg-dark text-white border-secondary"
                />
                <Button 
                  variant="outline-danger" 
                  onClick={handleAddDomain}
                  disabled={!newDomain.trim()}
                >
                  Add Domain
                </Button>
              </InputGroup>
              <small className="text-white-50 mt-2 d-block">
                Add domains you discover through Google dorking that belong to {companyName}
              </small>
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

export default GoogleDorkingModal; 