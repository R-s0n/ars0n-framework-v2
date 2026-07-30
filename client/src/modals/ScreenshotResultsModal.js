import { useState, useMemo } from 'react';
import { Modal, Button, Badge } from 'react-bootstrap';
import { MdZoomOutMap, MdCloseFullscreen } from 'react-icons/md';
import VirtualizedList from '../components/VirtualizedList';
import useTargetURLs from '../hooks/useTargetURLs';

// Add helper function to handle NullString values
const getNullStringValue = (field) => {
  if (!field) return null;
  return field.String || null;
};

// G1.4: resolve a screenshot to a renderable src without shipping base64 inline. Prefers an
// inline base64 blob if one is present (back-compat with the full payload), otherwise points at
// the on-demand endpoint when the lean list flagged has_screenshot.
const getScreenshotSrc = (item) => {
  if (item.screenshot) return `data:image/png;base64,${item.screenshot}`;
  if (item.has_screenshot && item.id) return `/api/api/target-urls/${item.id}/screenshot`;
  return null;
};

const ScreenshotResultsModal = ({
  showScreenshotResultsModal,
  handleCloseScreenshotResultsModal,
  activeTarget,
  onPopulateBurp
}) => {
  const [expandedIndex, setExpandedIndex] = useState(null);
  const [copySuccess, setCopySuccess] = useState(false);

  // G1.7: react-query loads the lean list (id/url/status/server/tech/title + has_screenshot);
  // images are lazy-loaded per row. Keyed to the active target with cancel-on-switch + caching.
  const { data: rawTargetURLs = [] } = useTargetURLs(activeTarget?.id, {
    projection: 'lean',
    enabled: showScreenshotResultsModal,
  });

  const targetURLs = useMemo(
    () =>
      [...rawTargetURLs].sort((a, b) => {
        if (!a.status_code && !b.status_code) return 0;
        if (!a.status_code) return 1;
        if (!b.status_code) return -1;
        return a.status_code - b.status_code;
      }),
    [rawTargetURLs]
  );

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
        <VirtualizedList
          items={targetURLs}
          height="65vh"
          estimatedItemSize={240}
          itemKey={(item, index) => item.id || index}
          renderItem={(targetURL, index) => (
            <div className="screenshot-item pb-4">
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
              {getScreenshotSrc(targetURL) && (
                <div
                  style={{
                    height: expandedIndex === index ? '500px' : '150px',
                    overflow: 'hidden',
                    border: '1px solid #333',
                    borderRadius: '4px',
                    transition: 'height 0.3s ease-in-out'
                  }}
                >
                  <img
                    src={getScreenshotSrc(targetURL)}
                    loading="lazy"
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
          )}
        />
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