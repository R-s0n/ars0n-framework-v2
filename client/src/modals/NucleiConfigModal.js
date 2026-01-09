import { useState, useRef, useEffect } from 'react';
import { Modal, Button, Spinner, Alert, Row, Col, Form, Badge, Tab, Tabs, Table, InputGroup } from 'react-bootstrap';
import { FaSearch, FaUpload, FaTrash } from 'react-icons/fa';

const NucleiConfigModal = ({ 
  show, 
  handleClose, 
  activeTarget,
  onSaveConfig
}) => {
  const [activeTab, setActiveTab] = useState('targets');
  const [selectedCategory, setSelectedCategory] = useState('live_web_servers');
  const [selectedTargets, setSelectedTargets] = useState(new Set());
  const [selectedTemplates, setSelectedTemplates] = useState(new Set());
  const [selectedSeverities, setSelectedSeverities] = useState(new Set(['critical', 'high', 'medium', 'low', 'info']));
  const [attackSurfaceAssets, setAttackSurfaceAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const [scannedTargets, setScannedTargets] = useState(new Set());
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [uploadedTemplates, setUploadedTemplates] = useState([]);
  const [uploadingTemplates, setUploadingTemplates] = useState(false);
  const fileInputRef = useRef(null);

  const categories = [
    { key: 'asns', name: 'ASNs', icon: 'bi-diagram-3' },
    { key: 'network_ranges', name: 'Network Ranges', icon: 'bi-router' },
    { key: 'ip_addresses', name: 'IP Addresses', icon: 'bi-hdd-network' },
    { key: 'live_web_servers', name: 'Live Web Servers', icon: 'bi-server' },
    { key: 'cloud_assets', name: 'Cloud Assets', icon: 'bi-cloud' },
    { key: 'fqdns', name: 'Domain Names', icon: 'bi-globe' }
  ];

  const templateCategories = [
    { key: 'cves', name: 'CVEs', description: 'Common Vulnerabilities and Exposures', icon: 'bi-shield-exclamation' },
    { key: 'vulnerabilities', name: 'Vulnerabilities', description: 'General vulnerability templates', icon: 'bi-bug' },
    { key: 'exposures', name: 'Exposures', description: 'Information disclosure templates', icon: 'bi-eye' },
    { key: 'technologies', name: 'Technologies', description: 'Technology detection templates', icon: 'bi-gear' },
    { key: 'misconfiguration', name: 'Misconfigurations', description: 'Common misconfigurations', icon: 'bi-exclamation-triangle' },
    { key: 'takeovers', name: 'Takeovers', description: 'Subdomain takeover templates', icon: 'bi-arrow-repeat' },
    { key: 'network', name: 'Network', description: 'Network-based templates', icon: 'bi-hdd-network' },
    { key: 'dns', name: 'DNS', description: 'DNS-related templates', icon: 'bi-globe' },
    { key: 'headless', name: 'Headless', description: 'Browser-based templates', icon: 'bi-window' },
    { key: 'custom', name: 'Custom Templates', description: `Upload your own Nuclei templates (${uploadedTemplates.length} uploaded)`, icon: 'bi-upload' }
  ];

  const severityCategories = [
    { key: 'critical', name: 'Critical', description: 'Critical severity vulnerabilities', icon: 'bi-shield-exclamation', color: 'danger' },
    { key: 'high', name: 'High', description: 'High severity vulnerabilities', icon: 'bi-exclamation-triangle-fill', color: 'warning' },
    { key: 'medium', name: 'Medium', description: 'Medium severity vulnerabilities', icon: 'bi-exclamation-circle-fill', color: 'info' },
    { key: 'low', name: 'Low', description: 'Low severity vulnerabilities', icon: 'bi-info-circle-fill', color: 'success' },
    { key: 'info', name: 'Info', description: 'Informational findings', icon: 'bi-lightbulb', color: 'light' }
  ];

  useEffect(() => {
    if (show) {
      loadSavedConfig();
      fetchAttackSurfaceAssets();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    fetchScannedTargets();
  }, [attackSurfaceAssets]);

  const fetchAttackSurfaceAssets = async () => {
    if (!activeTarget?.id) return;

    setLoadingAssets(true);
    try {
      const response = await fetch(
        `/api/attack-surface-assets/${activeTarget.id}`
      );
      
      if (response.ok) {
        const data = await response.json();
        setAttackSurfaceAssets(data.assets || []);
      } else {
        setError('Failed to load attack surface assets. Please consolidate the attack surface first.');
      }
    } catch (error) {
      console.error('Error fetching attack surface assets:', error);
      setError('Failed to load attack surface assets. Please try again.');
    } finally {
      setLoadingAssets(false);
    }
  };

  const fetchScannedTargets = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `/api/scopetarget/${activeTarget.id}/scans/nuclei`
      );
      
      if (response.ok) {
        const scans = await response.json();
        const scannedSet = new Set();
        
        scans.forEach(scan => {
          if (scan.status === 'success' && scan.targets && Array.isArray(scan.targets)) {
            scan.targets.forEach(target => scannedSet.add(target));
          }
        });
        
        setScannedTargets(scannedSet);
      }
    } catch (error) {
      console.error('Error fetching scanned targets:', error);
    }
  };

  const loadSavedConfig = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `/api/nuclei-config/${activeTarget.id}`
      );
      
      if (response.ok) {
        const config = await response.json();
        if (config.targets && Array.isArray(config.targets)) {
          setSelectedTargets(new Set(config.targets));
        }
        if (config.templates && Array.isArray(config.templates)) {
          setSelectedTemplates(new Set(config.templates));
        } else {
          const defaultTemplates = ['cves', 'vulnerabilities', 'exposures', 'technologies', 'misconfiguration', 'takeovers', 'network', 'dns', 'headless'];
          setSelectedTemplates(new Set(defaultTemplates));
        }
        if (config.severities && Array.isArray(config.severities)) {
          setSelectedSeverities(new Set(config.severities));
        } else {
          const defaultSeverities = ['critical', 'high', 'medium', 'low', 'info'];
          setSelectedSeverities(new Set(defaultSeverities));
        }
        if (config.uploaded_templates && Array.isArray(config.uploaded_templates)) {
          setUploadedTemplates(config.uploaded_templates);
        }
      }
    } catch (error) {
      console.error('Error loading Nuclei config:', error);
      const defaultTemplates = ['cves', 'vulnerabilities', 'exposures', 'technologies', 'misconfiguration', 'takeovers', 'network', 'dns', 'headless'];
      setSelectedTemplates(new Set(defaultTemplates));
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
        targets: Array.from(selectedTargets),
        templates: Array.from(selectedTemplates),
        severities: Array.from(selectedSeverities),
        uploaded_templates: uploadedTemplates,
        created_at: new Date().toISOString()
      };

      const response = await fetch(
        `/api/nuclei-config/${activeTarget.id}`,
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
      console.error('Error saving Nuclei config:', error);
      setError('Failed to save configuration. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const getAssetsForCategory = (category) => {
    return attackSurfaceAssets.filter(asset => {
      switch (category) {
        case 'asns':
          return asset.asset_type === 'asn';
        case 'network_ranges':
          return asset.asset_type === 'network_range';
        case 'ip_addresses':
          return asset.asset_type === 'ip_address';
        case 'live_web_servers':
          return asset.asset_type === 'live_web_server';
        case 'cloud_assets':
          return asset.asset_type === 'cloud_asset';
        case 'fqdns':
          return asset.asset_type === 'fqdn';
        default:
          return false;
      }
    });
  };

  const getFilteredAssets = () => {
    const categoryAssets = getAssetsForCategory(selectedCategory);
    if (!searchFilter) return categoryAssets;
    
    return categoryAssets.filter(asset => {
      const searchText = searchFilter.toLowerCase();
      return (
        asset.asset_identifier.toLowerCase().includes(searchText) ||
        (asset.domain && asset.domain.toLowerCase().includes(searchText)) ||
        (asset.url && asset.url.toLowerCase().includes(searchText)) ||
        (asset.ip_address && asset.ip_address.toLowerCase().includes(searchText)) ||
        (asset.asn_number && asset.asn_number.toLowerCase().includes(searchText)) ||
        (asset.cidr_block && asset.cidr_block.toLowerCase().includes(searchText))
      );
    });
  };

  const handleTargetSelect = (targetId) => {
    const newSelected = new Set(selectedTargets);
    if (newSelected.has(targetId)) {
      newSelected.delete(targetId);
    } else {
      newSelected.add(targetId);
    }
    setSelectedTargets(newSelected);
  };

  const handleTemplateSelect = (templateKey) => {
    const newSelected = new Set(selectedTemplates);
    if (newSelected.has(templateKey)) {
      newSelected.delete(templateKey);
    } else {
      newSelected.add(templateKey);
    }
    setSelectedTemplates(newSelected);
  };

  const handleSeveritySelect = (severityKey) => {
    const newSelected = new Set(selectedSeverities);
    if (newSelected.has(severityKey)) {
      newSelected.delete(severityKey);
    } else {
      newSelected.add(severityKey);
    }
    setSelectedSeverities(newSelected);
  };

  const handleSelectAllCategory = () => {
    const categoryAssets = getFilteredAssets();
    const newSelected = new Set(selectedTargets);
    categoryAssets.forEach(asset => newSelected.add(asset.id));
    setSelectedTargets(newSelected);
  };

  const handleDeselectAllCategory = () => {
    const categoryAssets = getFilteredAssets();
    const newSelected = new Set(selectedTargets);
    categoryAssets.forEach(asset => newSelected.delete(asset.id));
    setSelectedTargets(newSelected);
  };

  const handleSelectUnscanned = () => {
    const categoryAssets = getFilteredAssets();
    const newSelected = new Set(selectedTargets);
    categoryAssets.forEach(asset => {
      if (!scannedTargets.has(asset.id)) {
        newSelected.add(asset.id);
      }
    });
    setSelectedTargets(newSelected);
  };

  const handleClearAll = () => {
    setSelectedTargets(new Set());
  };

  const handleSelectAllTemplates = () => {
    setSelectedTemplates(new Set(templateCategories.map(cat => cat.key)));
  };

  const handleSelectNoTemplates = () => {
    setSelectedTemplates(new Set());
  };

  const handleSelectAllSeverities = () => {
    setSelectedSeverities(new Set(severityCategories.map(sev => sev.key)));
  };

  const handleSelectNoSeverities = () => {
    setSelectedSeverities(new Set());
  };

  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setUploadingTemplates(true);
    const newTemplates = [];

    for (const file of files) {
      if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) {
        try {
          const content = await file.text();
          newTemplates.push({
            id: Date.now() + Math.random(),
            name: file.name,
            size: file.size,
            content: content,
            uploaded_at: new Date().toISOString()
          });
        } catch (error) {
          console.error('Error reading file:', file.name, error);
        }
      }
    }

    setUploadedTemplates(prev => [...prev, ...newTemplates]);
    setUploadingTemplates(false);
    
    if (newTemplates.length > 0) {
      setSelectedTemplates(prev => new Set([...prev, 'custom']));
    }
    
    event.target.value = '';
  };

  const handleRemoveTemplate = (templateId) => {
    setUploadedTemplates(prev => prev.filter(template => template.id !== templateId));
  };

  const handleUploadClick = (event) => {
    event.stopPropagation();
    fileInputRef.current?.click();
  };

  const getAssetDisplayText = (asset) => {
    switch (asset.asset_type) {
      case 'asn':
        return `AS${asset.asn_number} - ${asset.asn_organization || 'Unknown'}`;
      case 'network_range':
        return `${asset.cidr_block} (${asset.subnet_size || 0} IPs)`;
      case 'ip_address':
        return `${asset.ip_address} ${asset.ip_type ? `(${asset.ip_type})` : ''}`;
      case 'live_web_server':
        return `${asset.url || asset.domain || asset.ip_address} ${asset.port ? `:${asset.port}` : ''}`;
      case 'cloud_asset':
        return `${asset.asset_identifier} (${asset.cloud_provider || 'Unknown'})`;
      case 'fqdn':
        return asset.fqdn || asset.domain || asset.asset_identifier;
      default:
        return asset.asset_identifier;
    }
  };

  const getAssetBadgeColor = (asset) => {
    switch (asset.asset_type) {
      case 'asn': return 'primary';
      case 'network_range': return 'info';
      case 'ip_address': return 'warning';
      case 'live_web_server': return 'success';
      case 'cloud_asset': return 'danger';
      case 'fqdn': return 'secondary';
      default: return 'dark';
    }
  };

  const handleCloseModal = () => {
    setError('');
    setSearchFilter('');
    setSelectedCategory('live_web_servers');
    setActiveTab('targets');
    handleClose();
  };

  const renderTargetSelection = () => {
    const categoryAssets = getAssetsForCategory(selectedCategory);
    const filteredAssets = getFilteredAssets();
    const selectedInCategory = filteredAssets.filter(asset => selectedTargets.has(asset.id)).length;
    const unscannedCount = filteredAssets.filter(asset => !scannedTargets.has(asset.id)).length;

    return (
      <Row className="h-100">
        <Col md={2} className="border-end pe-0">
          <div className="d-flex flex-column h-100">
            <h6 className="text-danger mb-3 px-2">Categories</h6>
            <div className="flex-grow-1 overflow-auto">
              {categories.map(category => {
                const assetCount = getAssetsForCategory(category.key).length;
                return (
                  <button
                    key={category.key}
                    className={`btn w-100 text-start py-2 px-2 mb-1 d-flex align-items-center ${
                      selectedCategory === category.key ? 'btn-danger' : 'btn-outline-secondary'
                    }`}
                    onClick={() => setSelectedCategory(category.key)}
                    style={{ border: 'none', borderRadius: '0' }}
                  >
                    <i className={`${category.icon} me-2`} />
                    <span className="flex-grow-1 small text-truncate">{category.name}</span>
                    <Badge 
                      bg={selectedCategory === category.key ? 'light' : 'secondary'}
                      text={selectedCategory === category.key ? 'dark' : 'light'}
                      className="ms-1"
                    >
                      {assetCount}
                    </Badge>
                  </button>
                );
              })}
            </div>
          </div>
        </Col>
        
        <Col md={10} className="ps-0">
          <div className="d-flex flex-column h-100">
            <div className="px-3 pb-3 border-bottom">
              <div className="d-flex justify-content-between align-items-center mb-3">
                <h6 className="text-danger mb-0">
                  {categories.find(c => c.key === selectedCategory)?.name || 'Assets'}
                  <Badge bg="secondary" className="ms-2">{filteredAssets.length} shown</Badge>
                  {selectedInCategory > 0 && (
                    <Badge bg="success" className="ms-2">{selectedInCategory} selected</Badge>
                  )}
                </h6>
                
                <div className="btn-group btn-group-sm">
                  <Button 
                    variant="outline-success" 
                    size="sm" 
                    onClick={handleSelectAllCategory}
                    disabled={filteredAssets.length === 0}
                  >
                    <i className="bi bi-check-square me-1"></i>
                    Select Page
                  </Button>
                  <Button 
                    variant="outline-secondary" 
                    size="sm" 
                    onClick={handleDeselectAllCategory}
                    disabled={selectedInCategory === 0}
                  >
                    <i className="bi bi-square me-1"></i>
                    Deselect Page
                  </Button>
                  <Button 
                    variant="outline-info" 
                    size="sm" 
                    onClick={handleSelectUnscanned}
                    disabled={unscannedCount === 0}
                  >
                    <i className="bi bi-hourglass-split me-1"></i>
                    Unscanned ({unscannedCount})
                  </Button>
                  <Button 
                    variant="outline-danger" 
                    size="sm" 
                    onClick={handleClearAll}
                    disabled={selectedTargets.size === 0}
                  >
                    <i className="bi bi-x-circle me-1"></i>
                    Clear All ({selectedTargets.size})
                  </Button>
                </div>
              </div>

              <InputGroup size="sm">
                <InputGroup.Text>
                  <FaSearch />
                </InputGroup.Text>
                <Form.Control
                  type="text"
                  placeholder="Search assets..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  data-bs-theme="dark"
                />
                {searchFilter && (
                  <Button 
                    variant="outline-secondary" 
                    onClick={() => setSearchFilter('')}
                  >
                    <i className="bi bi-x"></i>
                  </Button>
                )}
              </InputGroup>
            </div>

            <div className="flex-grow-1 overflow-auto px-3 py-2">
              {loadingAssets ? (
                <div className="text-center py-5">
                  <Spinner animation="border" variant="danger" />
                  <div className="mt-2">Loading attack surface assets...</div>
                </div>
              ) : filteredAssets.length === 0 ? (
                <div className="text-center text-muted py-5">
                  <i className="bi bi-inbox fs-1"></i>
                  <div className="mt-2">
                    {searchFilter ? 'No assets match your search' : 'No assets found in this category'}
                  </div>
                </div>
              ) : (
                <Table striped hover variant="dark" size="sm" className="mb-0">
                  <thead className="sticky-top bg-dark">
                    <tr>
                      <th width="40" className="text-center">
                        <Form.Check
                          type="checkbox"
                          checked={filteredAssets.length > 0 && 
                                   filteredAssets.every(asset => selectedTargets.has(asset.id))}
                          indeterminate={
                            selectedInCategory > 0 && 
                            selectedInCategory < filteredAssets.length
                          }
                          onChange={(e) => {
                            if (e.target.checked) {
                              handleSelectAllCategory();
                            } else {
                              handleDeselectAllCategory();
                            }
                          }}
                        />
                      </th>
                      <th>Asset</th>
                      <th width="120">Type</th>
                      <th width="100">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAssets.map(asset => (
                      <tr 
                        key={asset.id}
                        style={{ 
                          cursor: 'pointer',
                          backgroundColor: selectedTargets.has(asset.id) ? 'rgba(25, 135, 84, 0.15)' : 'inherit'
                        }}
                        onClick={() => handleTargetSelect(asset.id)}
                      >
                        <td className="text-center" onClick={(e) => e.stopPropagation()}>
                          <Form.Check
                            type="checkbox"
                            checked={selectedTargets.has(asset.id)}
                            onChange={() => handleTargetSelect(asset.id)}
                          />
                        </td>
                        <td>
                          <div style={{ wordBreak: 'break-all' }}>
                            {getAssetDisplayText(asset)}
                          </div>
                        </td>
                        <td>
                          <Badge bg={getAssetBadgeColor(asset)}>
                            {asset.asset_type.replace('_', ' ').toUpperCase()}
                          </Badge>
                        </td>
                        <td>
                          {scannedTargets.has(asset.id) ? (
                            <Badge bg="success">
                              <i className="bi bi-check-circle me-1"></i>
                              Scanned
                            </Badge>
                          ) : (
                            <Badge bg="secondary">
                              <i className="bi bi-hourglass-split me-1"></i>
                              Unscanned
                            </Badge>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </div>
          </div>
        </Col>
      </Row>
    );
  };

  const renderTemplateSelection = () => (
    <div className="h-100 d-flex flex-column">
      <div className="mb-3 pb-3 border-bottom">
        <div className="d-flex justify-content-between align-items-center">
          <h6 className="text-danger mb-0">Nuclei Template Categories</h6>
          <div className="btn-group btn-group-sm">
            <Button variant="outline-success" size="sm" onClick={handleSelectAllTemplates}>
              <i className="bi bi-check-all me-1"></i>
              Select All
            </Button>
            <Button variant="outline-secondary" size="sm" onClick={handleSelectNoTemplates}>
              <i className="bi bi-square me-1"></i>
              Select None
            </Button>
          </div>
        </div>
      </div>

      <div className="flex-grow-1 overflow-auto">
        <Row className="row-cols-1 row-cols-md-2 g-3 mb-4">
          {templateCategories.map(template => (
            <Col key={template.key}>
              <div 
                className={`card h-100 position-relative ${selectedTemplates.has(template.key) ? 'border-danger bg-danger bg-opacity-10' : 'border-secondary'}`}
                style={{ cursor: 'pointer' }}
                onClick={() => handleTemplateSelect(template.key)}
              >
                <div className="card-body p-3">
                  <div className="d-flex align-items-start h-100">
                    <div className="d-flex align-items-center justify-content-center me-3" style={{ width: '50px', minWidth: '50px' }}>
                      <i className={`${template.icon} text-danger`} style={{ fontSize: '1.8rem' }}></i>
                    </div>
                    <div className="flex-grow-1 d-flex flex-column justify-content-center">
                      <div className="d-flex align-items-center mb-1">
                        <Form.Check 
                          type="checkbox" 
                          checked={selectedTemplates.has(template.key)}
                          onChange={() => handleTemplateSelect(template.key)}
                          onClick={(e) => e.stopPropagation()}
                          className="me-2"
                        />
                        <h6 className="card-title mb-0">{template.name}</h6>
                      </div>
                      <p className="card-text text-muted small mb-0">
                        {template.description}
                      </p>
                    </div>
                  </div>
                  {template.key === 'custom' && (
                    <div className="position-absolute top-0 end-0 p-2">
                      <Button 
                        variant="outline-danger" 
                        size="sm" 
                        onClick={handleUploadClick}
                        disabled={uploadingTemplates}
                      >
                        {uploadingTemplates ? (
                          <>
                            <Spinner animation="border" size="sm" className="me-1" />
                            Uploading...
                          </>
                        ) : (
                          <>
                            <FaUpload className="me-1" />
                            Upload
                          </>
                        )}
                      </Button>
                      <input
                        ref={fileInputRef}
                        type="file"
                        multiple
                        accept=".yaml,.yml"
                        onChange={handleFileUpload}
                        style={{ display: 'none' }}
                      />
                    </div>
                  )}
                </div>
              </div>
            </Col>
          ))}
        </Row>

        <div className="mb-3 pb-3 border-top pt-3">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="text-danger mb-0">Template Severity Levels</h6>
            <div className="btn-group btn-group-sm">
              <Button variant="outline-success" size="sm" onClick={handleSelectAllSeverities}>
                <i className="bi bi-check-all me-1"></i>
                Select All
              </Button>
              <Button variant="outline-secondary" size="sm" onClick={handleSelectNoSeverities}>
                <i className="bi bi-square me-1"></i>
                Select None
              </Button>
            </div>
          </div>
        </div>

        <Row className="g-3 mb-4">
          {severityCategories.map(severity => (
            <Col key={severity.key} xs={12} md={6}>
              <div 
                className={`card h-100 ${selectedSeverities.has(severity.key) ? `border-${severity.color} bg-${severity.color} bg-opacity-10` : 'border-secondary'}`}
                style={{ cursor: 'pointer' }}
                onClick={() => handleSeveritySelect(severity.key)}
              >
                <div className="card-body p-3">
                  <div className="d-flex align-items-center">
                    <Form.Check 
                      type="checkbox" 
                      checked={selectedSeverities.has(severity.key)}
                      onChange={() => handleSeveritySelect(severity.key)}
                      onClick={(e) => e.stopPropagation()}
                      className="me-3"
                    />
                    <div className="d-flex align-items-center justify-content-center me-3" style={{ width: '40px', minWidth: '40px' }}>
                      <i className={`${severity.icon} text-${severity.color}`} style={{ fontSize: '1.5rem' }}></i>
                    </div>
                    <div className="flex-grow-1">
                      <h6 className="card-title mb-1">{severity.name}</h6>
                      <p className="card-text text-muted small mb-0">
                        {severity.description}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </Col>
          ))}
        </Row>

        {uploadedTemplates.length > 0 && (
          <div className="mt-4">
            <h6 className="text-danger mb-3">Uploaded Custom Templates</h6>
            <Table striped bordered hover variant="dark" size="sm">
              <thead>
                <tr>
                  <th>Template Name</th>
                  <th>Size</th>
                  <th>Uploaded</th>
                  <th width="80">Actions</th>
                </tr>
              </thead>
              <tbody>
                {uploadedTemplates.map(template => (
                  <tr key={template.id}>
                    <td>
                      <div style={{ wordBreak: 'break-all' }}>
                        <i className="bi bi-file-code me-2"></i>
                        {template.name}
                      </div>
                    </td>
                    <td>
                      <Badge bg="info">
                        {(template.size / 1024).toFixed(1)} KB
                      </Badge>
                    </td>
                    <td>
                      <small className="text-muted">
                        {new Date(template.uploaded_at).toLocaleDateString()}
                      </small>
                    </td>
                    <td>
                      <Button
                        variant="outline-danger"
                        size="sm"
                        onClick={() => handleRemoveTemplate(template.id)}
                        title="Remove template"
                      >
                        <FaTrash />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <Modal 
      show={show} 
      onHide={handleCloseModal} 
      data-bs-theme="dark"
      dialogClassName="modal-fullscreen"
      style={{ margin: 0 }}
    >
      <Modal.Header closeButton className="border-bottom border-secondary">
        <Modal.Title className="text-danger">
          <i className="bi bi-shield-shaded me-2" />
          Configure Nuclei Security Scan
          <Badge bg="secondary" className="ms-3 fs-6">
            {selectedTargets.size} targets
          </Badge>
          <Badge bg="secondary" className="ms-2 fs-6">
            {selectedTemplates.size} templates
          </Badge>
          <Badge bg="secondary" className="ms-2 fs-6">
            {selectedSeverities.size} severities
          </Badge>
        </Modal.Title>
      </Modal.Header>
      
      <Modal.Body className="p-0 d-flex flex-column" style={{ height: 'calc(100vh - 140px)' }}>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')} className="m-3 mb-0">
            {error}
          </Alert>
        )}

        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="px-3 pt-3"
          variant="pills"
        >
          <Tab 
            eventKey="targets" 
            title={
              <span>
                <i className="bi bi-bullseye me-2"></i>
                Select Targets
                {selectedTargets.size > 0 && (
                  <Badge bg="success" className="ms-2">{selectedTargets.size}</Badge>
                )}
              </span>
            }
          >
            <div className="h-100 py-3">
              {renderTargetSelection()}
            </div>
          </Tab>
          <Tab 
            eventKey="templates" 
            title={
              <span>
                <i className="bi bi-file-code me-2"></i>
                Select Templates
                {selectedTemplates.size > 0 && (
                  <Badge bg="success" className="ms-2">{selectedTemplates.size}</Badge>
                )}
              </span>
            }
          >
            <div className="h-100 py-3 px-3">
              {renderTemplateSelection()}
            </div>
          </Tab>
        </Tabs>
      </Modal.Body>
      
      <Modal.Footer className="border-top border-secondary">
        <div className="d-flex justify-content-between align-items-center w-100">
          <div className="text-muted small">
            <i className="bi bi-info-circle me-2"></i>
            Configure targets and templates, then save to enable scanning
          </div>
          <div>
            <Button variant="secondary" onClick={handleCloseModal} className="me-2">
              Cancel
            </Button>
            <Button 
              variant="danger" 
              onClick={handleSaveConfig}
              disabled={saving || selectedTargets.size === 0 || selectedTemplates.size === 0}
            >
              {saving ? (
                <>
                  <Spinner animation="border" size="sm" className="me-2" />
                  Saving...
                </>
              ) : (
                <>
                  <i className="bi bi-check-circle me-2"></i>
                  Save Configuration
                </>
              )}
            </Button>
          </div>
        </div>
      </Modal.Footer>
    </Modal>
  );
};

export default NucleiConfigModal;
