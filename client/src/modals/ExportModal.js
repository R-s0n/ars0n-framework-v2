import { Modal, Button, Card, Spinner, Tab, Tabs, Form, Table, Badge } from 'react-bootstrap';
import { useState, useEffect } from 'react';

function ExportModal({ show, handleClose }) {
  const [activeTab, setActiveTab] = useState('csv');
  
  const [selectedOptions, setSelectedOptions] = useState({
    amass: true,
    httpx: true,
    gau: true,
    sublist3r: true,
    assetfinder: true,
    ctl: true,
    subfinder: true,
    shuffledns: true,
    gospider: true,
    subdomainizer: true,
    roi: true,
    subdomains: true,
    cloud_enum: true,
    metabigor_company: true,
    katana_company: true,
    dnsx_company: true,
    securitytrails_company: true,
    github_recon: true,
    shodan_company: true,
    censys_company: true,
    amass_enum_company: true,
    amass_intel: true,
    nuclei: true,
    cewl: true,
    ip_port_scans: true,
    consolidated_attack_surface: true
  });
  
  const [isExporting, setIsExporting] = useState(false);
  
  const [scopeTargets, setScopeTargets] = useState([]);
  const [selectedScopeTargets, setSelectedScopeTargets] = useState(new Set());
  const [loadingScopeTargets, setLoadingScopeTargets] = useState(false);
  const [isDatabaseExporting, setIsDatabaseExporting] = useState(false);

  useEffect(() => {
    if (show && activeTab === 'database') {
      fetchScopeTargets();
    }
  }, [show, activeTab]);

  const fetchScopeTargets = async () => {
    setLoadingScopeTargets(true);
    try {
      const response = await fetch(`/api/api/scope-targets-for-export`);
      if (response.ok) {
        const targets = await response.json();
        setScopeTargets(targets);
        
        const allIds = new Set(targets.map(target => target.id));
        setSelectedScopeTargets(allIds);
      } else {
        console.error('Failed to fetch scope targets');
      }
    } catch (error) {
      console.error('Error fetching scope targets:', error);
    } finally {
      setLoadingScopeTargets(false);
    }
  };

  const handleOptionClick = (option) => {
    setSelectedOptions(prev => ({
      ...prev,
      [option]: !prev[option]
    }));
  };

  const handleSelectAll = () => {
    if (activeTab === 'csv') {
      setSelectedOptions(Object.keys(selectedOptions).reduce((acc, key) => {
        acc[key] = true;
        return acc;
      }, {}));
    } else if (activeTab === 'database') {
      const allIds = new Set(scopeTargets.map(target => target.id));
      setSelectedScopeTargets(allIds);
    }
  };

  const handleDeselectAll = () => {
    if (activeTab === 'csv') {
      setSelectedOptions(Object.keys(selectedOptions).reduce((acc, key) => {
        acc[key] = false;
        return acc;
      }, {}));
    } else if (activeTab === 'database') {
      setSelectedScopeTargets(new Set());
    }
  };

  const handleScopeTargetToggle = (targetId) => {
    setSelectedScopeTargets(prev => {
      const newSet = new Set(prev);
      if (newSet.has(targetId)) {
        newSet.delete(targetId);
      } else {
        newSet.add(targetId);
      }
      return newSet;
    });
  };

  const handleExport = async () => {
    try {
      setIsExporting(true);
      const response = await fetch(`/api/api/export-data`, {
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

  const handleDatabaseExport = async () => {
    if (selectedScopeTargets.size === 0) {
      alert('Please select at least one scope target to export.');
      return;
    }

    try {
      setIsDatabaseExporting(true);
      const response = await fetch(`/api/api/database-export`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ scope_target_ids: Array.from(selectedScopeTargets) })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Database export failed: ${errorText}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rs0n-export-${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.rs0n`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      handleClose();
    } catch (error) {
      console.error('Database export failed:', error);
      alert('Failed to export database. Please try again. Error: ' + error.message);
    } finally {
      setIsDatabaseExporting(false);
    }
  };

  const exportOptions = [
    {
      id: 'amass',
      label: 'Amass (Wildcard)',
      description: 'Comprehensive wildcard subdomain discovery including DNS records, IP addresses, ASNs, subnets, service providers, and cloud assets.'
    },
    {
      id: 'httpx',
      label: 'HTTPX',
      description: 'HTTP probing results for discovered domains and subdomains.'
    },
    {
      id: 'gau',
      label: 'GAU (Get All URLs)',
      description: 'URL discovery from archived sources like Wayback Machine and CommonCrawl.'
    },
    {
      id: 'sublist3r',
      label: 'Sublist3r',
      description: 'Subdomain enumeration using search engines and public APIs.'
    },
    {
      id: 'assetfinder',
      label: 'Assetfinder',
      description: 'Asset discovery tool for finding domains and subdomains.'
    },
    {
      id: 'ctl',
      label: 'Certificate Transparency Logs',
      description: 'Subdomain discovery through SSL certificate transparency logs.'
    },
    {
      id: 'subfinder',
      label: 'Subfinder',
      description: 'Passive subdomain discovery using multiple data sources.'
    },
    {
      id: 'shuffledns',
      label: 'ShuffleDNS',
      description: 'DNS bruteforce tool for subdomain enumeration.'
    },
    {
      id: 'gospider',
      label: 'GoSpider',
      description: 'Web crawler for discovering URLs and endpoints.'
    },
    {
      id: 'subdomainizer',
      label: 'Subdomainizer',
      description: 'Subdomain discovery through JavaScript files and external sources.'
    },
    {
      id: 'cewl',
      label: 'CeWL',
      description: 'Custom word list generation from web crawling.'
    },
    {
      id: 'cloud_enum',
      label: 'Cloud Enum',
      description: 'Multi-cloud asset enumeration for AWS, Azure, and Google Cloud platforms.'
    },
    {
      id: 'metabigor_company',
      label: 'Metabigor Company',
      description: 'Network intelligence gathering including ASN and IP range discovery for companies.'
    },
    {
      id: 'katana_company',
      label: 'Katana Company',
      description: 'Advanced web crawling for cloud asset discovery and endpoint enumeration.'
    },
    {
      id: 'dnsx_company',
      label: 'DNSx Company',
      description: 'Advanced DNS toolkit for company domain resolution and record discovery.'
    },
    {
      id: 'securitytrails_company',
      label: 'SecurityTrails Company',
      description: 'Historical DNS data and passive domain intelligence.'
    },
    {
      id: 'github_recon',
      label: 'GitHub Recon',
      description: 'GitHub organization reconnaissance for domain and asset discovery.'
    },
    {
      id: 'shodan_company',
      label: 'Shodan Company',
      description: 'Internet-connected device and service discovery for companies.'
    },
    {
      id: 'censys_company',
      label: 'Censys Company',
      description: 'Internet-wide scanning platform for asset discovery and monitoring.'
    },
    {
      id: 'amass_enum_company',
      label: 'Amass Enum Company',
      description: 'Company-focused subdomain enumeration with cloud asset discovery.'
    },
    {
      id: 'amass_intel',
      label: 'Amass Intel',
      description: 'Network intelligence gathering for ASN and IP range discovery.'
    },
    {
      id: 'nuclei',
      label: 'Nuclei',
      description: 'Vulnerability scanning with customizable templates.'
    },
    {
      id: 'ip_port_scans',
      label: 'IP/Port Scans',
      description: 'Network range scanning for live IPs and open ports.'
    },
    {
      id: 'consolidated_attack_surface',
      label: 'Consolidated Attack Surface',
      description: 'Comprehensive attack surface mapping including all discovered assets.'
    },
    {
      id: 'subdomains',
      label: 'Consolidated Subdomains',
      description: 'All subdomain discovery results consolidated across multiple tools.'
    },
    {
      id: 'roi',
      label: 'ROI Analysis',
      description: 'Target analysis with vulnerability indicators, SSL/TLS issues, and security metrics.'
    }
  ];

  const renderCSVExport = () => (
    <>
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
    </>
  );

  const renderDatabaseExport = () => (
    <>
      <div className="mb-4">
        <p className="text-white-50 mb-2">
          Export complete database for selected scope targets. This includes all scan results, configurations, and related data.
        </p>
        <div className="d-flex justify-content-between align-items-center">
          <span className="text-white">
            <strong>{selectedScopeTargets.size}</strong> of <strong>{scopeTargets.length}</strong> targets selected
          </span>
          <Badge bg="info" className="p-2">
            File format: .rs0n (compressed)
          </Badge>
        </div>
      </div>

      {loadingScopeTargets ? (
        <div className="text-center py-4">
          <Spinner animation="border" variant="danger" />
          <p className="text-white mt-3">Loading scope targets...</p>
        </div>
      ) : (
        <div style={{ maxHeight: '50vh', overflowY: 'auto' }}>
          <Table striped variant="dark" hover>
            <thead>
              <tr>
                <th style={{ width: '40px' }}>
                  <Form.Check
                    type="checkbox"
                    checked={selectedScopeTargets.size === scopeTargets.length && scopeTargets.length > 0}
                    onChange={() => {
                      if (selectedScopeTargets.size === scopeTargets.length) {
                        setSelectedScopeTargets(new Set());
                      } else {
                        setSelectedScopeTargets(new Set(scopeTargets.map(target => target.id)));
                      }
                    }}
                  />
                </th>
                <th>Type</th>
                <th>Scope Target</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {scopeTargets.map((target) => (
                <tr key={target.id}>
                  <td>
                    <Form.Check
                      type="checkbox"
                      checked={selectedScopeTargets.has(target.id)}
                      onChange={() => handleScopeTargetToggle(target.id)}
                    />
                  </td>
                  <td>
                    <Badge bg={target.type === 'Company' ? 'warning' : target.type === 'Wildcard' ? 'info' : 'secondary'}>
                      {target.type}
                    </Badge>
                  </td>
                  <td className="text-white">{target.scope_target}</td>
                  <td>
                    <Badge bg={target.active ? 'success' : 'secondary'}>
                      {target.active ? 'Active' : 'Inactive'}
                    </Badge>
                  </td>
                  <td className="text-white-50 small">
                    {new Date(target.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
    </>
  );

  const isDisabled = () => {
    if (activeTab === 'csv') {
      return !Object.values(selectedOptions).some(value => value) || isExporting;
    } else if (activeTab === 'database') {
      return selectedScopeTargets.size === 0 || isDatabaseExporting || loadingScopeTargets;
    }
    return true;
  };

  const getButtonText = () => {
    if (activeTab === 'csv') {
      return isExporting ? (
        <>
          <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
          Exporting...
        </>
      ) : 'Export to CSV';
    } else if (activeTab === 'database') {
      return isDatabaseExporting ? (
        <>
          <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
          Exporting...
        </>
      ) : 'Export Database (.rs0n)';
    }
  };

  const handleButtonClick = () => {
    if (activeTab === 'csv') {
      handleExport();
    } else if (activeTab === 'database') {
      handleDatabaseExport();
    }
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Export Data</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="mb-3"
          variant="pills"
        >
          <Tab eventKey="csv" title="CSV Export">
            {renderCSVExport()}
          </Tab>
          <Tab eventKey="database" title="Database Export">
            {renderDatabaseExport()}
          </Tab>
        </Tabs>
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
          <Button 
            variant="secondary" 
            onClick={handleClose} 
            disabled={isExporting || isDatabaseExporting}
          >
            Cancel
          </Button>
          <Button 
            variant="danger" 
            onClick={handleButtonClick}
            disabled={isDisabled()}
          >
            {getButtonText()}
          </Button>
        </div>
      </Modal.Footer>
    </Modal>
  );
}

export default ExportModal; 