import { useState, useEffect } from 'react';
import { Modal, Button, Badge } from 'react-bootstrap';
import { MdZoomOutMap, MdCloseFullscreen } from 'react-icons/md';

// Add helper function to handle NullString values
const getNullStringValue = (field) => {
  if (!field) return null;
  return field.String || null;
};

const ScreenshotResultsModal = ({
  showScreenshotResultsModal,
  handleCloseScreenshotResultsModal,
  activeTarget,
  onPopulateBurp
}) => {
  const [targetURLs, setTargetURLs] = useState([]);
  const [expandedIndex, setExpandedIndex] = useState(null);
  const [copySuccess, setCopySuccess] = useState(false);

  useEffect(() => {
    const fetchTargetURLs = async () => {
      if (!activeTarget) return;
      
      try {
        const response = await fetch(
          `/api/api/scope-targets/${activeTarget.id}/target-urls`
        );
        if (!response.ok) {
          throw new Error('Failed to fetch target URLs');
        }
        const data = await response.json();
        const safeData = data || [];
        const sortedData = safeData.sort((a, b) => {
          if (!a.status_code && !b.status_code) return 0;
          if (!a.status_code) return 1;
          if (!b.status_code) return -1;
          return a.status_code - b.status_code;
        });
        setTargetURLs(sortedData);
      } catch (error) {
        console.error('Error fetching target URLs:', error);
      }
    };

    if (showScreenshotResultsModal) {
      fetchTargetURLs();
    }
  }, [showScreenshotResultsModal, activeTarget]);

  const handleExpand = (index) => {
    setExpandedIndex(expandedIndex === index ? null : index);
  };

  const getStatusCodeColor = (statusCode) => {
    if (!statusCode) return { bg: 'secondary', text: 'white' };
    if (statusCode >= 200 && statusCode < 300) return { bg: 'success', text: 'dark' };
    if (statusCode >= 300 && statusCode < 400) return { bg: 'info', text: 'dark' };
    if (statusCode === 401 || statusCode === 403) return { bg: 'danger', text: 'white' };
    if (statusCode >= 400 && statusCode < 500) return { bg: 'warning', text: 'dark' };
    if (statusCode >= 500) return { bg: 'danger', text: 'white' };
    return { bg: 'secondary', text: 'white' };
  };

  const handleCopyAllUrls = () => {
    const urls = targetURLs.map(item => item.url).filter(url => url).join('\n');
    if (urls) {
      navigator.clipboard.writeText(urls).then(() => {
        setCopySuccess(true);
        setTimeout(() => setCopySuccess(false), 2000);
      }).catch(err => {
        console.error('Failed to copy URLs:', err);
      });
    }
  };

  const handlePopulateBurp = () => {
    const urls = targetURLs.map(item => item.url).filter(url => url).join('\n');
    if (urls && onPopulateBurp) {
      onPopulateBurp(urls);
      handleCloseScreenshotResultsModal();
    }
  };

  return (
    <Modal data-bs-theme="dark" show={showScreenshotResultsModal} onHide={handleCloseScreenshotResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Screenshot Results</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {targetURLs.length > 0 && (
          <div className="d-flex gap-2 mb-3">
            <Button 
              variant="outline-info" 
              size="sm" 
              onClick={handleCopyAllUrls}
            >
              {copySuccess ? 'Copied!' : 'Copy All URLs'}
            </Button>
            <Button 
              variant="outline-danger" 
              size="sm" 
              onClick={handlePopulateBurp}
              disabled={!onPopulateBurp}
            >
              Populate Burp with All URLs
            </Button>
          </div>
        )}
        <div className="screenshot-list">
          {targetURLs.map((targetURL, index) => (
            <div key={index} className="screenshot-item mb-4">
              <div className="d-flex flex-column mb-2">
                <div className="d-flex justify-content-between align-items-center">
                  <h6 className="text-white mb-0 text-break flex-grow-1">
                    <a 
                      href={targetURL.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-white text-decoration-none hover-underline"
                      style={{ 
                        ':hover': { 
                          textDecoration: 'underline !important' 
                        } 
                      }}
                    >
                      {targetURL.url}
                    </a>
                  </h6>
                  <button
                    onClick={() => handleExpand(index)}
                    className="btn btn-outline-danger btn-sm ms-2"
                    style={{ minWidth: '32px', height: '32px', padding: '4px' }}
                  >
                    {expandedIndex === index ? <MdCloseFullscreen size={20} /> : <MdZoomOutMap size={20} />}
                  </button>
                </div>
                <div className="d-flex flex-wrap gap-2 align-items-center mt-2">
                  {targetURL.status_code && (
                    <Badge 
                      bg={getStatusCodeColor(targetURL.status_code).bg} 
                      className={`fs-7 text-${getStatusCodeColor(targetURL.status_code).text}`}
                    >
                      Status: {targetURL.status_code}
                    </Badge>
                  )}
                  {getNullStringValue(targetURL.web_server) && (
                    <Badge bg="secondary" className="fs-7">
                      Server: {getNullStringValue(targetURL.web_server)}
                    </Badge>
                  )}
                  {targetURL.technologies && targetURL.technologies.map((tech, techIndex) => (
                    <Badge key={techIndex} bg="info" className="fs-7 text-dark">
                      {getNullStringValue(tech)}
                    </Badge>
                  ))}
                  {getNullStringValue(targetURL.title) && (
                    <span className="text-muted small">
                      {getNullStringValue(targetURL.title)}
                    </span>
                  )}
                  {targetURL.newly_discovered && (
                    <Badge bg="success" className="fs-7 text-dark">New</Badge>
                  )}
                  {targetURL.no_longer_live && (
                    <Badge bg="danger" className="fs-7">Offline</Badge>
                  )}
                </div>
              </div>
              {targetURL.screenshot && (
                <div 
                  style={{ 
                    height: expandedIndex === index ? '500px' : '150px',
                    overflow: 'hidden',
                    border: '1px solid #333',
                    borderRadius: '4px',
                    transition: 'height 0.3s ease-in-out'
                  }}
                >
                  {console.log('[DEBUG] Screenshot data:', targetURL.screenshot)}
                  <img 
                    src={`data:image/png;base64,${targetURL.screenshot}`} 
                    alt={`Screenshot of ${targetURL.url}`}
                    style={{ 
                      width: '100%',
                      height: expandedIndex === index ? '500px' : '150px',
                      objectFit: 'contain',
                      backgroundColor: '#1a1a1a',
                      transition: 'height 0.3s ease-in-out'
                    }}
                  />
                </div>
              )}
            </div>
          ))}
        </div>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-danger" onClick={handleCloseScreenshotResultsModal}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ScreenshotResultsModal; 