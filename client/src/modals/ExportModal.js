import { Modal, Button, Card, Spinner } from 'react-bootstrap';
import { useState } from 'react';

function ExportModal({ show, handleClose }) {
  const [selectedOptions, setSelectedOptions] = useState({
    amass: true,
    subdomains: true,
    roi: true
  });

  const [isExporting, setIsExporting] = useState(false);

  const handleOptionClick = (option) => {
    setSelectedOptions(prev => ({
      ...prev,
      [option]: !prev[option]
    }));
  };

  const handleSelectAll = () => {
    setSelectedOptions(Object.keys(selectedOptions).reduce((acc, key) => {
      acc[key] = true;
      return acc;
    }, {}));
  };

  const handleDeselectAll = () => {
    setSelectedOptions(Object.keys(selectedOptions).reduce((acc, key) => {
      acc[key] = false;
      return acc;
    }, {}));
  };

  const handleExport = async () => {
    try {
      setIsExporting(true);
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/export-data`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(selectedOptions)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Export failed: ${errorText}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `export-${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.zip`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      handleClose();
    } catch (error) {
      console.error('Export failed:', error);
      alert('Failed to export data. Please try again. Error: ' + error.message);
    } finally {
      setIsExporting(false);
    }
  };

  const exportOptions = [
    {
      id: 'amass',
      label: 'Amass Results',
      description: 'Exports comprehensive scan data including subdomains, DNS records, IP addresses, ASNs, subnets, service providers, and cloud assets (AWS, Azure, GCP). Each record includes scan metadata, execution time, and command details.'
    },
    {
      id: 'subdomains',
      label: 'Subdomain Discovery Results',
      description: 'Consolidated export of all subdomain discovery tools including results from Sublist3r, Assetfinder, GAU, CTL, Subfinder, ShuffleDNS, GoSpider, and Subdomainizer. Also includes consolidated unique subdomains and live web servers.'
    },
    {
      id: 'roi',
      label: 'ROI Analysis',
      description: 'Exports target analysis data including vulnerability indicators, SSL/TLS issues, HTTP response details, DNS records, technologies, content length, and ROI scores. Each record includes comprehensive target metadata and security assessment metrics.'
    }
  ];

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Export Data</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="mb-4">
          <p className="text-white-50 mb-0">
            Select the data you want to export. All options are selected by default.
          </p>
        </div>
        <div className="d-flex flex-column gap-3" style={{ maxHeight: '60vh', overflowY: 'auto' }}>
          {exportOptions.map((option) => (
            <Card 
              key={option.id} 
              className={`bg-dark border ${selectedOptions[option.id] ? 'border-danger' : 'border-secondary'}`}
              onClick={() => handleOptionClick(option.id)}
              style={{ 
                cursor: 'pointer',
                transition: 'all 0.2s ease-in-out'
              }}
            >
              <Card.Body className="py-3">
                <div>
                  <h6 className={`mb-1 ${selectedOptions[option.id] ? 'text-danger' : 'text-white'}`}>
                    {option.label}
                  </h6>
                  <p className="text-white-50 small mb-0">
                    {option.description}
                  </p>
                </div>
              </Card.Body>
            </Card>
          ))}
        </div>
      </Modal.Body>
      <Modal.Footer>
        <div className="d-flex gap-2 me-auto">
          <Button variant="outline-light" onClick={handleSelectAll}>
            Select All
          </Button>
          <Button variant="outline-light" onClick={handleDeselectAll}>
            Deselect All
          </Button>
        </div>
        <div className="d-flex gap-2">
          <Button variant="secondary" onClick={handleClose} disabled={isExporting}>
            Cancel
          </Button>
          <Button 
            variant="danger" 
            onClick={handleExport}
            disabled={!Object.values(selectedOptions).some(value => value) || isExporting}
          >
            {isExporting ? (
              <>
                <Spinner
                  as="span"
                  animation="border"
                  size="sm"
                  role="status"
                  aria-hidden="true"
                  className="me-2"
                />
                Exporting...
              </>
            ) : (
              'Export to CSV'
            )}
          </Button>
        </div>
      </Modal.Footer>
    </Modal>
  );
}

export default ExportModal; 