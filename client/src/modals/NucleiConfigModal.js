import { useState, useRef, useEffect, useCallback } from 'react';
import { Modal, Button, Spinner, Alert, Row, Col, Form, Badge, Tab, Tabs, Table, InputGroup, Accordion } from 'react-bootstrap';
import { FaSearch, FaUpload, FaTrash } from 'react-icons/fa';

const NucleiConfigModal = ({ 
  show, 
  handleClose, 
  activeTarget,
  onSaveConfig,
  mode
}) => {
  const [activeTab, setActiveTab] = useState('targets');
  const [selectedCategory, setSelectedCategory] = useState('live_web_servers');
  const [selectedTargets, setSelectedTargets] = useState(new Set());
  const [selectedTemplates, setSelectedTemplates] = useState(new Set(['cves', 'vulnerabilities', 'exposures', 'technologies', 'misconfiguration', 'takeovers', 'network', 'dns', 'headless']));
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

  const [allTemplates, setAllTemplates] = useState([]);
  const [templateDirectories, setTemplateDirectories] = useState([]);
  const [loadingTemplates, setLoadingTemplates] = useState(false);
  const [templateSearchFilter, setTemplateSearchFilter] = useState('');
  const [selectedTemplateIDs, setSelectedTemplateIDs] = useState(new Set());
  const [selectedBrowserDir, setSelectedBrowserDir] = useState('');

  const [excludeIDs, setExcludeIDs] = useState(new Set());
  const [excludeTags, setExcludeTags] = useState(new Set());
  const [excludeSearchFilter, setExcludeSearchFilter] = useState('');
  const [excludeTagInput, setExcludeTagInput] = useState('');
  const [excludeIdInput, setExcludeIdInput] = useState('');

  const [advancedConfig, setAdvancedConfig] = useState({
    rate_limit: 150,
    bulk_size: 25,
    concurrency: 25,
    timeout: 10,
    retries: 1,
    max_host_error: 30,
    follow_redirects: false,
    follow_host_redirects: false,
    max_redirects: 10,
    custom_headers: [],
    proxy: '',
    no_interactsh: false,
    interactsh_server: '',
    interactsh_token: '',
    headless: false,
    headless_bulk_size: 10,
    headless_concurrency: 10,
    scan_strategy: 'auto',
    stop_at_first_match: false,
    protocol_types: [],
    template_condition: '',
    author_filter: [],
    system_resolvers: false,
    leave_default_ports: false,
  });
  const [headerInput, setHeaderInput] = useState('');
  const [authorInput, setAuthorInput] = useState('');

  const isWildcard = mode === 'wildcard';

  const categories = isWildcard ? [
    { key: 'live_web_servers', name: 'Live Web Servers', icon: 'bi-server' },
  ] : [
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

  const protocolOptions = ['dns', 'file', 'http', 'headless', 'tcp', 'workflow', 'ssl', 'websocket', 'whois', 'code', 'javascript'];
  const scanStrategyOptions = ['auto', 'host-spray', 'template-spray'];

  useEffect(() => {
    if (show) {
      loadSavedConfig();
      if (isWildcard) {
        fetchWildcardTargets();
      } else {
        fetchAttackSurfaceAssets();
      }
    }
  }, [show, activeTarget]);

  useEffect(() => {
    fetchScannedTargets();
  }, [attackSurfaceAssets]);

  const fetchWildcardTargets = async () => {
    if (!activeTarget?.id) return;
    setLoadingAssets(true);
    try {
      const response = await fetch(`/api/scopetarget/${activeTarget.id}/wildcard-nuclei-targets`);
      if (response.ok) {
        const data = await response.json();
        const targets = (data.targets || []).map(t => ({
          ...t,
          asset_type: 'live_web_server',
        }));
        setAttackSurfaceAssets(targets);
      } else {
        setError('Failed to load live web servers. Please run an HTTPX scan first.');
      }
    } catch (err) {
      console.error('Error fetching wildcard targets:', err);
      setError('Failed to load live web servers. Please try again.');
    } finally {
      setLoadingAssets(false);
    }
  };

  const fetchAttackSurfaceAssets = async () => {
    if (!activeTarget?.id) return;
    setLoadingAssets(true);
    try {
      const response = await fetch(`/api/attack-surface-assets/${activeTarget.id}`);
      if (response.ok) {
        const data = await response.json();
        setAttackSurfaceAssets(data.assets || []);
      } else {
        setError('Failed to load attack surface assets. Please consolidate the attack surface first.');
      }
    } catch (err) {
      console.error('Error fetching attack surface assets:', err);
      setError('Failed to load attack surface assets. Please try again.');
    } finally {
      setLoadingAssets(false);
    }
  };

  const fetchScannedTargets = async () => {
    if (!activeTarget?.id) return;
    try {
      const response = await fetch(`/api/scopetarget/${activeTarget.id}/scans/nuclei`);
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
    } catch (err) {
      console.error('Error fetching scanned targets:', err);
    }
  };

  const fetchNucleiTemplateList = useCallback(async () => {
    if (allTemplates.length > 0) return;
    setLoadingTemplates(true);
    try {
      const response = await fetch('/api/nuclei-templates');
      if (response.ok) {
        const data = await response.json();
        setAllTemplates(data.templates || []);
        setTemplateDirectories(data.directories || []);
      }
    } catch (err) {
      console.error('Error fetching nuclei templates:', err);
    } finally {
      setLoadingTemplates(false);
    }
  }, [allTemplates.length]);

  const ALL_TEMPLATE_CATEGORIES = ['cves', 'vulnerabilities', 'exposures', 'technologies', 'misconfiguration', 'takeovers', 'network', 'dns', 'headless'];
  const ALL_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

  const loadSavedConfig = async () => {
    if (!activeTarget?.id) return;
    try {
      const response = await fetch(`/api/nuclei-config/${activeTarget.id}`);
      if (response.ok) {
        const config = await response.json();
        if (config.targets && Array.isArray(config.targets) && config.targets.length > 0) {
          setSelectedTargets(new Set(config.targets));
        }
        if (config.templates && Array.isArray(config.templates) && config.templates.length > 0) {
          setSelectedTemplates(new Set(config.templates));
        } else {
          setSelectedTemplates(new Set(ALL_TEMPLATE_CATEGORIES));
        }
        if (config.severities && Array.isArray(config.severities) && config.severities.length > 0) {
          setSelectedSeverities(new Set(config.severities));
        } else {
          setSelectedSeverities(new Set(ALL_SEVERITIES));
        }
        if (config.uploaded_templates && Array.isArray(config.uploaded_templates)) {
          setUploadedTemplates(config.uploaded_templates);
        }
        if (config.template_ids && Array.isArray(config.template_ids)) {
          setSelectedTemplateIDs(new Set(config.template_ids));
        }
        if (config.exclude_ids && Array.isArray(config.exclude_ids)) {
          setExcludeIDs(new Set(config.exclude_ids));
        }
        if (config.exclude_tags && Array.isArray(config.exclude_tags)) {
          setExcludeTags(new Set(config.exclude_tags));
        }
        if (config.advanced_config && typeof config.advanced_config === 'object') {
          setAdvancedConfig(prev => ({ ...prev, ...config.advanced_config }));
        }
      }
    } catch (err) {
      console.error('Error loading Nuclei config:', err);
      setSelectedTemplates(new Set(ALL_TEMPLATE_CATEGORIES));
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
        target_mode: isWildcard ? 'httpx' : 'attack_surface',
        template_ids: Array.from(selectedTemplateIDs),
        exclude_ids: Array.from(excludeIDs),
        exclude_tags: Array.from(excludeTags),
        advanced_config: advancedConfig,
        created_at: new Date().toISOString()
      };
      const response = await fetch(`/api/nuclei-config/${activeTarget.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });
      if (!response.ok) throw new Error('Failed to save configuration');
      if (onSaveConfig) onSaveConfig(config);
      handleCloseModal();
    } catch (err) {
      console.error('Error saving Nuclei config:', err);
      setError('Failed to save configuration. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const getAssetsForCategory = (category) => {
    return attackSurfaceAssets.filter(asset => {
      switch (category) {
        case 'asns': return asset.asset_type === 'asn';
        case 'network_ranges': return asset.asset_type === 'network_range';
        case 'ip_addresses': return asset.asset_type === 'ip_address';
        case 'live_web_servers': return asset.asset_type === 'live_web_server';
        case 'cloud_assets': return asset.asset_type === 'cloud_asset';
        case 'fqdns': return asset.asset_type === 'fqdn';
        default: return false;
      }
    });
  };

  const getFilteredAssets = () => {
    const categoryAssets = getAssetsForCategory(selectedCategory);
    if (!searchFilter) return categoryAssets;
    return categoryAssets.filter(asset => {
      const searchText = searchFilter.toLowerCase();
      return (
        (asset.asset_identifier && asset.asset_identifier.toLowerCase().includes(searchText)) ||
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
    categoryAssets.forEach(asset => newSelected.add(isWildcard ? asset.url : asset.id));
    setSelectedTargets(newSelected);
  };

  const handleDeselectAllCategory = () => {
    const categoryAssets = getFilteredAssets();
    const newSelected = new Set(selectedTargets);
    categoryAssets.forEach(asset => newSelected.delete(isWildcard ? asset.url : asset.id));
    setSelectedTargets(newSelected);
  };

  const handleSelectUnscanned = () => {
    const categoryAssets = getFilteredAssets();
    const newSelected = new Set(selectedTargets);
    categoryAssets.forEach(asset => {
      const key = isWildcard ? asset.url : asset.id;
      if (!scannedTargets.has(key)) {
        newSelected.add(key);
      }
    });
    setSelectedTargets(newSelected);
  };

  const handleClearAll = () => setSelectedTargets(new Set());

  const handleSelectAllTemplates = () => setSelectedTemplates(new Set(templateCategories.map(cat => cat.key)));
  const handleSelectNoTemplates = () => setSelectedTemplates(new Set());
  const handleSelectAllSeverities = () => setSelectedSeverities(new Set(severityCategories.map(sev => sev.key)));
  const handleSelectNoSeverities = () => setSelectedSeverities(new Set());

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
        } catch (err) {
          console.error('Error reading file:', file.name, err);
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
    if (isWildcard) return asset.url || asset.asset_identifier;
    switch (asset.asset_type) {
      case 'asn': return `AS${asset.asn_number} - ${asset.asn_organization || 'Unknown'}`;
      case 'network_range': return `${asset.cidr_block} (${asset.subnet_size || 0} IPs)`;
      case 'ip_address': return `${asset.ip_address} ${asset.ip_type ? `(${asset.ip_type})` : ''}`;
      case 'live_web_server': return `${asset.url || asset.domain || asset.ip_address} ${asset.port ? `:${asset.port}` : ''}`;
      case 'cloud_asset': return `${asset.asset_identifier} (${asset.cloud_provider || 'Unknown'})`;
      case 'fqdn': return asset.fqdn || asset.domain || asset.asset_identifier;
      default: return asset.asset_identifier;
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
    setTemplateSearchFilter('');
    setSelectedCategory('live_web_servers');
    setActiveTab('targets');
    handleClose();
  };

  const handleTemplateIDSelect = (templateId) => {
    const newSelected = new Set(selectedTemplateIDs);
    if (newSelected.has(templateId)) {
      newSelected.delete(templateId);
    } else {
      newSelected.add(templateId);
    }
    setSelectedTemplateIDs(newSelected);
  };

  const addExcludeTag = () => {
    if (excludeTagInput.trim()) {
      setExcludeTags(prev => new Set([...prev, excludeTagInput.trim()]));
      setExcludeTagInput('');
    }
  };

  const removeExcludeTag = (tag) => {
    setExcludeTags(prev => {
      const next = new Set(prev);
      next.delete(tag);
      return next;
    });
  };

  const addExcludeId = () => {
    if (excludeIdInput.trim()) {
      setExcludeIDs(prev => new Set([...prev, excludeIdInput.trim()]));
      setExcludeIdInput('');
    }
  };

  const removeExcludeId = (id) => {
    setExcludeIDs(prev => {
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
  };

  const updateAdvancedConfig = (key, value) => {
    setAdvancedConfig(prev => ({ ...prev, [key]: value }));
  };

  const addCustomHeader = () => {
    if (headerInput.trim() && headerInput.includes(':')) {
      updateAdvancedConfig('custom_headers', [...(advancedConfig.custom_headers || []), headerInput.trim()]);
      setHeaderInput('');
    }
  };

  const removeCustomHeader = (index) => {
    updateAdvancedConfig('custom_headers', (advancedConfig.custom_headers || []).filter((_, i) => i !== index));
  };

  const addAuthorFilter = () => {
    if (authorInput.trim()) {
      updateAdvancedConfig('author_filter', [...(advancedConfig.author_filter || []), authorInput.trim()]);
      setAuthorInput('');
    }
  };

  const removeAuthorFilter = (index) => {
    updateAdvancedConfig('author_filter', (advancedConfig.author_filter || []).filter((_, i) => i !== index));
  };

  const getFilteredBrowserTemplates = () => {
    let filtered = allTemplates;
    if (selectedBrowserDir) {
      filtered = filtered.filter(t => t.directory === selectedBrowserDir || t.directory?.startsWith(selectedBrowserDir + '/'));
    }
    if (templateSearchFilter) {
      const search = templateSearchFilter.toLowerCase();
      filtered = filtered.filter(t =>
        t.id?.toLowerCase().includes(search) ||
        t.path?.toLowerCase().includes(search)
      );
    }
    return filtered.slice(0, 500);
  };

  const getTopLevelDirs = () => {
    const dirs = new Map();
    allTemplates.forEach(t => {
      if (t.directory) {
        const topLevel = t.directory.split('/')[0];
        dirs.set(topLevel, (dirs.get(topLevel) || 0) + 1);
      }
    });
    return Array.from(dirs.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  };

  const getSubDirs = (parentDir) => {
    const dirs = new Map();
    allTemplates.forEach(t => {
      if (t.directory && t.directory.startsWith(parentDir + '/')) {
        const rest = t.directory.slice(parentDir.length + 1);
        const nextLevel = rest.split('/')[0];
        const fullPath = parentDir + '/' + nextLevel;
        dirs.set(fullPath, (dirs.get(fullPath) || 0) + 1);
      }
    });
    return Array.from(dirs.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  };

  const hasAnyTemplateOrCategory = () => {
    return selectedTemplates.size > 0 || selectedTemplateIDs.size > 0;
  };

  const renderTargetSelection = () => {
    const filteredAssets = getFilteredAssets();
    const selectedInCategory = filteredAssets.filter(asset => selectedTargets.has(isWildcard ? asset.url : asset.id)).length;
    const unscannedCount = filteredAssets.filter(asset => !scannedTargets.has(isWildcard ? asset.url : asset.id)).length;

    return (
      <Row className="h-100">
        {!isWildcard && (
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
        )}
        
        <Col md={isWildcard ? 12 : 10} className="ps-0">
          <div className="d-flex flex-column h-100">
            <div className="px-3 pb-3 border-bottom">
              <div className="d-flex justify-content-between align-items-center mb-3">
                <h6 className="text-danger mb-0">
                  {isWildcard ? 'Live Web Servers (from HTTPX)' : (categories.find(c => c.key === selectedCategory)?.name || 'Assets')}
                  <Badge bg="secondary" className="ms-2">{filteredAssets.length} shown</Badge>
                  {selectedInCategory > 0 && (
                    <Badge bg="success" className="ms-2">{selectedInCategory} selected</Badge>
                  )}
                </h6>
                
                <div className="btn-group btn-group-sm">
                  <Button variant="outline-success" size="sm" onClick={handleSelectAllCategory} disabled={filteredAssets.length === 0}>
                    <i className="bi bi-check-square me-1"></i>Select Page
                  </Button>
                  <Button variant="outline-secondary" size="sm" onClick={handleDeselectAllCategory} disabled={selectedInCategory === 0}>
                    <i className="bi bi-square me-1"></i>Deselect Page
                  </Button>
                  <Button variant="outline-info" size="sm" onClick={handleSelectUnscanned} disabled={unscannedCount === 0}>
                    <i className="bi bi-hourglass-split me-1"></i>Unscanned ({unscannedCount})
                  </Button>
                  <Button variant="outline-danger" size="sm" onClick={handleClearAll} disabled={selectedTargets.size === 0}>
                    <i className="bi bi-x-circle me-1"></i>Clear All ({selectedTargets.size})
                  </Button>
                </div>
              </div>

              <InputGroup size="sm">
                <InputGroup.Text><FaSearch /></InputGroup.Text>
                <Form.Control
                  type="text"
                  placeholder={isWildcard ? "Search live web servers..." : "Search assets..."}
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  data-bs-theme="dark"
                />
                {searchFilter && (
                  <Button variant="outline-secondary" onClick={() => setSearchFilter('')}>
                    <i className="bi bi-x"></i>
                  </Button>
                )}
              </InputGroup>
            </div>

            <div className="flex-grow-1 overflow-auto px-3 py-2">
              {loadingAssets ? (
                <div className="text-center py-5">
                  <Spinner animation="border" variant="danger" />
                  <div className="mt-2">Loading {isWildcard ? 'live web servers' : 'attack surface assets'}...</div>
                </div>
              ) : filteredAssets.length === 0 ? (
                <div className="text-center text-muted py-5">
                  <i className="bi bi-inbox fs-1"></i>
                  <div className="mt-2">
                    {searchFilter ? 'No assets match your search' : (isWildcard ? 'No live web servers found. Run an HTTPX scan first.' : 'No assets found in this category')}
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
                                   filteredAssets.every(asset => selectedTargets.has(isWildcard ? asset.url : asset.id))}
                          onChange={(e) => {
                            if (e.target.checked) handleSelectAllCategory();
                            else handleDeselectAllCategory();
                          }}
                        />
                      </th>
                      <th>Asset</th>
                      {!isWildcard && <th width="120">Type</th>}
                      <th width="100">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAssets.map(asset => {
                      const key = isWildcard ? asset.url : asset.id;
                      return (
                        <tr 
                          key={key}
                          style={{ cursor: 'pointer', backgroundColor: selectedTargets.has(key) ? 'rgba(25, 135, 84, 0.15)' : 'inherit' }}
                          onClick={() => handleTargetSelect(key)}
                        >
                          <td className="text-center" onClick={(e) => e.stopPropagation()}>
                            <Form.Check type="checkbox" checked={selectedTargets.has(key)} onChange={() => handleTargetSelect(key)} />
                          </td>
                          <td><div style={{ wordBreak: 'break-all' }}>{getAssetDisplayText(asset)}</div></td>
                          {!isWildcard && (
                            <td><Badge bg={getAssetBadgeColor(asset)}>{asset.asset_type.replace('_', ' ').toUpperCase()}</Badge></td>
                          )}
                          <td>
                            {scannedTargets.has(key) ? (
                              <Badge bg="success"><i className="bi bi-check-circle me-1"></i>Scanned</Badge>
                            ) : (
                              <Badge bg="secondary"><i className="bi bi-hourglass-split me-1"></i>Unscanned</Badge>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </Table>
              )}
            </div>
          </div>
        </Col>
      </Row>
    );
  };

  const renderTemplateBrowser = () => {
    const filteredTemplates = getFilteredBrowserTemplates();
    const topDirs = getTopLevelDirs();
    const subDirs = selectedBrowserDir ? getSubDirs(selectedBrowserDir) : [];
    const selectedInView = filteredTemplates.filter(t => selectedTemplateIDs.has(t.id)).length;

    return (
      <div className="h-100 d-flex flex-column">
        <div className="mb-3 pb-3 border-bottom">
          <div className="d-flex justify-content-between align-items-center mb-2">
            <h6 className="text-danger mb-0">
              Individual Template Selection
              <Badge bg="info" className="ms-2">{allTemplates.length} available</Badge>
              {selectedTemplateIDs.size > 0 && <Badge bg="success" className="ms-2">{selectedTemplateIDs.size} selected</Badge>}
            </h6>
            <div className="btn-group btn-group-sm">
              {!loadingTemplates && allTemplates.length === 0 && (
                <Button variant="outline-danger" size="sm" onClick={fetchNucleiTemplateList}>
                  <i className="bi bi-arrow-clockwise me-1"></i>Load Templates
                </Button>
              )}
              {selectedTemplateIDs.size > 0 && (
                <Button variant="outline-secondary" size="sm" onClick={() => setSelectedTemplateIDs(new Set())}>
                  <i className="bi bi-x-circle me-1"></i>Clear Selected
                </Button>
              )}
            </div>
          </div>
          <InputGroup size="sm">
            <InputGroup.Text><FaSearch /></InputGroup.Text>
            <Form.Control
              type="text"
              placeholder="Search templates by ID or path..."
              value={templateSearchFilter}
              onChange={(e) => setTemplateSearchFilter(e.target.value)}
              onFocus={fetchNucleiTemplateList}
              data-bs-theme="dark"
            />
            {templateSearchFilter && (
              <Button variant="outline-secondary" onClick={() => setTemplateSearchFilter('')}>
                <i className="bi bi-x"></i>
              </Button>
            )}
          </InputGroup>
        </div>

        {loadingTemplates ? (
          <div className="text-center py-5">
            <Spinner animation="border" variant="danger" />
            <div className="mt-2">Loading templates from Nuclei container...</div>
          </div>
        ) : allTemplates.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="bi bi-collection fs-1"></i>
            <div className="mt-2">Click "Load Templates" or start typing to browse available templates</div>
          </div>
        ) : (
          <Row className="flex-grow-1 overflow-hidden">
            <Col md={3} className="border-end overflow-auto h-100">
              <div className="py-2">
                <button
                  className={`btn btn-sm w-100 text-start mb-1 ${!selectedBrowserDir ? 'btn-danger' : 'btn-outline-secondary'}`}
                  onClick={() => setSelectedBrowserDir('')}
                  style={{ border: 'none', borderRadius: '4px' }}
                >
                  <i className="bi bi-folder me-2"></i>All Templates
                  <Badge bg="secondary" className="ms-2 float-end">{allTemplates.length}</Badge>
                </button>
                {topDirs.map(([dir, count]) => (
                  <div key={dir}>
                    <button
                      className={`btn btn-sm w-100 text-start mb-1 ${selectedBrowserDir === dir ? 'btn-danger' : 'btn-outline-secondary'}`}
                      onClick={() => setSelectedBrowserDir(selectedBrowserDir === dir ? '' : dir)}
                      style={{ border: 'none', borderRadius: '4px' }}
                    >
                      <i className={`bi ${selectedBrowserDir === dir ? 'bi-folder2-open' : 'bi-folder'} me-2`}></i>
                      <span className="small">{dir}</span>
                      <Badge bg="secondary" className="ms-2 float-end">{count}</Badge>
                    </button>
                    {selectedBrowserDir === dir && subDirs.length > 0 && subDirs.map(([subDir, subCount]) => (
                      <button
                        key={subDir}
                        className="btn btn-sm w-100 text-start mb-1 btn-outline-secondary ps-4"
                        onClick={() => setSelectedBrowserDir(subDir)}
                        style={{ border: 'none', borderRadius: '4px', fontSize: '0.8rem' }}
                      >
                        <i className="bi bi-folder me-1"></i>
                        {subDir.split('/').pop()}
                        <Badge bg="secondary" className="ms-1 float-end">{subCount}</Badge>
                      </button>
                    ))}
                  </div>
                ))}
              </div>
            </Col>
            <Col md={9} className="overflow-auto h-100">
              <div className="py-2">
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <small className="text-muted">
                    Showing {filteredTemplates.length} of {allTemplates.length} templates
                    {filteredTemplates.length >= 500 && ' (limited to 500)'}
                  </small>
                  {filteredTemplates.length > 0 && (
                    <div className="btn-group btn-group-sm">
                      <Button variant="outline-success" size="sm" onClick={() => {
                        const newSelected = new Set(selectedTemplateIDs);
                        filteredTemplates.forEach(t => newSelected.add(t.id));
                        setSelectedTemplateIDs(newSelected);
                      }}>Select Shown</Button>
                      <Button variant="outline-secondary" size="sm" onClick={() => {
                        const newSelected = new Set(selectedTemplateIDs);
                        filteredTemplates.forEach(t => newSelected.delete(t.id));
                        setSelectedTemplateIDs(newSelected);
                      }}>Deselect Shown</Button>
                    </div>
                  )}
                </div>
                <Table striped hover variant="dark" size="sm" className="mb-0">
                  <thead className="sticky-top bg-dark">
                    <tr>
                      <th width="40" className="text-center">
                        <Form.Check type="checkbox"
                          checked={filteredTemplates.length > 0 && filteredTemplates.every(t => selectedTemplateIDs.has(t.id))}
                          onChange={(e) => {
                            const newSelected = new Set(selectedTemplateIDs);
                            filteredTemplates.forEach(t => e.target.checked ? newSelected.add(t.id) : newSelected.delete(t.id));
                            setSelectedTemplateIDs(newSelected);
                          }}
                        />
                      </th>
                      <th>Template ID</th>
                      <th>Path</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredTemplates.map(template => (
                      <tr
                        key={template.path}
                        style={{ cursor: 'pointer', backgroundColor: selectedTemplateIDs.has(template.id) ? 'rgba(25, 135, 84, 0.15)' : 'inherit' }}
                        onClick={() => handleTemplateIDSelect(template.id)}
                      >
                        <td className="text-center" onClick={(e) => e.stopPropagation()}>
                          <Form.Check type="checkbox" checked={selectedTemplateIDs.has(template.id)} onChange={() => handleTemplateIDSelect(template.id)} />
                        </td>
                        <td><code className="text-danger">{template.id}</code></td>
                        <td><small className="text-muted">{template.path}</small></td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            </Col>
          </Row>
        )}
      </div>
    );
  };

  const renderTemplateSelection = () => (
    <div className="h-100 d-flex flex-column">
      <Tabs defaultActiveKey="categories" className="mb-3" variant="pills">
        <Tab eventKey="categories" title={<span><i className="bi bi-grid me-1"></i>Categories{selectedTemplates.size > 0 && <Badge bg="success" className="ms-2">{selectedTemplates.size}</Badge>}</span>}>
          <div className="mb-3 pb-3 border-bottom">
            <div className="d-flex justify-content-between align-items-center">
              <h6 className="text-danger mb-0">Nuclei Template Categories</h6>
              <div className="btn-group btn-group-sm">
                <Button variant="outline-success" size="sm" onClick={handleSelectAllTemplates}>
                  <i className="bi bi-check-all me-1"></i>Select All
                </Button>
                <Button variant="outline-secondary" size="sm" onClick={handleSelectNoTemplates}>
                  <i className="bi bi-square me-1"></i>Select None
                </Button>
              </div>
            </div>
          </div>

          <div className="overflow-auto" style={{ maxHeight: 'calc(100vh - 400px)' }}>
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
                          <p className="card-text text-muted small mb-0">{template.description}</p>
                        </div>
                      </div>
                      {template.key === 'custom' && (
                        <div className="position-absolute top-0 end-0 p-2">
                          <Button variant="outline-danger" size="sm" onClick={handleUploadClick} disabled={uploadingTemplates}>
                            {uploadingTemplates ? (
                              <><Spinner animation="border" size="sm" className="me-1" />Uploading...</>
                            ) : (
                              <><FaUpload className="me-1" />Upload</>
                            )}
                          </Button>
                          <input ref={fileInputRef} type="file" multiple accept=".yaml,.yml" onChange={handleFileUpload} style={{ display: 'none' }} />
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
                    <i className="bi bi-check-all me-1"></i>Select All
                  </Button>
                  <Button variant="outline-secondary" size="sm" onClick={handleSelectNoSeverities}>
                    <i className="bi bi-square me-1"></i>Select None
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
                        <Form.Check type="checkbox" checked={selectedSeverities.has(severity.key)} onChange={() => handleSeveritySelect(severity.key)} onClick={(e) => e.stopPropagation()} className="me-3" />
                        <div className="d-flex align-items-center justify-content-center me-3" style={{ width: '40px', minWidth: '40px' }}>
                          <i className={`${severity.icon} text-${severity.color}`} style={{ fontSize: '1.5rem' }}></i>
                        </div>
                        <div className="flex-grow-1">
                          <h6 className="card-title mb-1">{severity.name}</h6>
                          <p className="card-text text-muted small mb-0">{severity.description}</p>
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
                        <td><div style={{ wordBreak: 'break-all' }}><i className="bi bi-file-code me-2"></i>{template.name}</div></td>
                        <td><Badge bg="info">{(template.size / 1024).toFixed(1)} KB</Badge></td>
                        <td><small className="text-muted">{new Date(template.uploaded_at).toLocaleDateString()}</small></td>
                        <td><Button variant="outline-danger" size="sm" onClick={() => handleRemoveTemplate(template.id)} title="Remove template"><FaTrash /></Button></td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
          </div>
        </Tab>

        <Tab eventKey="browser" title={<span><i className="bi bi-search me-1"></i>Individual Templates{selectedTemplateIDs.size > 0 && <Badge bg="success" className="ms-2">{selectedTemplateIDs.size}</Badge>}</span>}>
          {renderTemplateBrowser()}
        </Tab>
      </Tabs>
    </div>
  );

  const renderExclusions = () => (
    <div className="h-100 d-flex flex-column overflow-auto">
      <div className="px-3 py-3">
        <h6 className="text-danger mb-3">Exclude Templates by ID</h6>
        <p className="text-muted small mb-3">Exclude specific templates from the scan. These template IDs will be skipped even if they match selected categories.</p>
        <InputGroup className="mb-3" size="sm">
          <Form.Control
            type="text"
            placeholder="Enter template ID to exclude (e.g., CVE-2021-1234)"
            value={excludeIdInput}
            onChange={(e) => setExcludeIdInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addExcludeId()}
            data-bs-theme="dark"
          />
          <Button variant="outline-danger" onClick={addExcludeId} disabled={!excludeIdInput.trim()}>
            <i className="bi bi-plus-circle me-1"></i>Add
          </Button>
        </InputGroup>
        <div className="d-flex flex-wrap gap-2 mb-4">
          {Array.from(excludeIDs).map(id => (
            <Badge key={id} bg="danger" className="d-flex align-items-center px-3 py-2" style={{ fontSize: '0.85rem' }}>
              <code className="me-2">{id}</code>
              <i className="bi bi-x-circle" style={{ cursor: 'pointer' }} onClick={() => removeExcludeId(id)}></i>
            </Badge>
          ))}
          {excludeIDs.size === 0 && <span className="text-muted small">No template IDs excluded</span>}
        </div>

        <hr className="border-secondary" />

        <h6 className="text-danger mb-3">Exclude Templates by Tag</h6>
        <p className="text-muted small mb-3">Exclude all templates matching specific tags.</p>
        <InputGroup className="mb-3" size="sm">
          <Form.Control
            type="text"
            placeholder="Enter tag to exclude (e.g., dos, fuzz, intrusive)"
            value={excludeTagInput}
            onChange={(e) => setExcludeTagInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addExcludeTag()}
            data-bs-theme="dark"
          />
          <Button variant="outline-warning" onClick={addExcludeTag} disabled={!excludeTagInput.trim()}>
            <i className="bi bi-plus-circle me-1"></i>Add
          </Button>
        </InputGroup>
        <div className="d-flex flex-wrap gap-2">
          {Array.from(excludeTags).map(tag => (
            <Badge key={tag} bg="warning" text="dark" className="d-flex align-items-center px-3 py-2" style={{ fontSize: '0.85rem' }}>
              <code className="me-2">{tag}</code>
              <i className="bi bi-x-circle" style={{ cursor: 'pointer' }} onClick={() => removeExcludeTag(tag)}></i>
            </Badge>
          ))}
          {excludeTags.size === 0 && <span className="text-muted small">No tags excluded</span>}
        </div>
      </div>
    </div>
  );

  const renderAdvancedSettings = () => (
    <div className="h-100 overflow-auto px-3 py-3">
      <Accordion defaultActiveKey="0" flush>
        <Accordion.Item eventKey="0">
          <Accordion.Header><i className="bi bi-speedometer2 me-2 text-danger"></i>Rate Limiting &amp; Concurrency</Accordion.Header>
          <Accordion.Body>
            <Row className="g-3">
              <Col md={4}>
                <Form.Group>
                  <Form.Label className="small text-muted">Rate Limit (req/sec)</Form.Label>
                  <Form.Control type="number" size="sm" value={advancedConfig.rate_limit} onChange={(e) => updateAdvancedConfig('rate_limit', parseInt(e.target.value) || 150)} data-bs-theme="dark" />
                  <Form.Text className="text-muted">Max requests per second (-rl)</Form.Text>
                </Form.Group>
              </Col>
              <Col md={4}>
                <Form.Group>
                  <Form.Label className="small text-muted">Bulk Size</Form.Label>
                  <Form.Control type="number" size="sm" value={advancedConfig.bulk_size} onChange={(e) => updateAdvancedConfig('bulk_size', parseInt(e.target.value) || 25)} data-bs-theme="dark" />
                  <Form.Text className="text-muted">Hosts per template (-bs)</Form.Text>
                </Form.Group>
              </Col>
              <Col md={4}>
                <Form.Group>
                  <Form.Label className="small text-muted">Concurrency</Form.Label>
                  <Form.Control type="number" size="sm" value={advancedConfig.concurrency} onChange={(e) => updateAdvancedConfig('concurrency', parseInt(e.target.value) || 25)} data-bs-theme="dark" />
                  <Form.Text className="text-muted">Templates in parallel (-c)</Form.Text>
                </Form.Group>
              </Col>
            </Row>
          </Accordion.Body>
        </Accordion.Item>

        <Accordion.Item eventKey="1">
          <Accordion.Header><i className="bi bi-gear me-2 text-danger"></i>Timeouts &amp; Retries</Accordion.Header>
          <Accordion.Body>
            <Row className="g-3">
              <Col md={4}>
                <Form.Group>
                  <Form.Label className="small text-muted">Timeout (seconds)</Form.Label>
                  <Form.Control type="number" size="sm" value={advancedConfig.timeout} onChange={(e) => updateAdvancedConfig('timeout', parseInt(e.target.value) || 10)} data-bs-theme="dark" />
                  <Form.Text className="text-muted">Request timeout (-timeout)</Form.Text>
                </Form.Group>
              </Col>
              <Col md={4}>
                <Form.Group>
                  <Form.Label className="small text-muted">Retries</Form.Label>
                  <Form.Control type="number" size="sm" value={advancedConfig.retries} onChange={(e) => updateAdvancedConfig('retries', parseInt(e.target.value) || 1)} data-bs-theme="dark" />
                  <Form.Text className="text-muted">Retry failed requests (-retries)</Form.Text>
                </Form.Group>
              </Col>
              <Col md={4}>
                <Form.Group>
                  <Form.Label className="small text-muted">Max Host Errors</Form.Label>
                  <Form.Control type="number" size="sm" value={advancedConfig.max_host_error} onChange={(e) => updateAdvancedConfig('max_host_error', parseInt(e.target.value) || 30)} data-bs-theme="dark" />
                  <Form.Text className="text-muted">Skip host after N errors (-mhe)</Form.Text>
                </Form.Group>
              </Col>
            </Row>
          </Accordion.Body>
        </Accordion.Item>

        <Accordion.Item eventKey="2">
          <Accordion.Header><i className="bi bi-arrow-right-circle me-2 text-danger"></i>HTTP Configuration</Accordion.Header>
          <Accordion.Body>
            <Row className="g-3 mb-3">
              <Col md={4}>
                <Form.Check type="switch" label="Follow Redirects (-fr)" checked={advancedConfig.follow_redirects} onChange={(e) => updateAdvancedConfig('follow_redirects', e.target.checked)} />
              </Col>
              <Col md={4}>
                <Form.Check type="switch" label="Follow Host Redirects (-fhr)" checked={advancedConfig.follow_host_redirects} onChange={(e) => updateAdvancedConfig('follow_host_redirects', e.target.checked)} />
              </Col>
              <Col md={4}>
                <Form.Group>
                  <Form.Label className="small text-muted">Max Redirects</Form.Label>
                  <Form.Control type="number" size="sm" value={advancedConfig.max_redirects} onChange={(e) => updateAdvancedConfig('max_redirects', parseInt(e.target.value) || 10)} data-bs-theme="dark" />
                </Form.Group>
              </Col>
            </Row>
            <Row className="g-3 mb-3">
              <Col md={6}>
                <Form.Check type="switch" label="Leave Default Ports (-ldp)" checked={advancedConfig.leave_default_ports} onChange={(e) => updateAdvancedConfig('leave_default_ports', e.target.checked)} />
              </Col>
              <Col md={6}>
                <Form.Check type="switch" label="Stop at First Match (-spm)" checked={advancedConfig.stop_at_first_match} onChange={(e) => updateAdvancedConfig('stop_at_first_match', e.target.checked)} />
              </Col>
            </Row>
            <hr className="border-secondary" />
            <h6 className="text-danger small mb-3">Custom Headers (-H)</h6>
            <InputGroup className="mb-2" size="sm">
              <Form.Control type="text" placeholder="Header:Value (e.g., Authorization: Bearer token)" value={headerInput} onChange={(e) => setHeaderInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addCustomHeader()} data-bs-theme="dark" />
              <Button variant="outline-danger" onClick={addCustomHeader} disabled={!headerInput.trim() || !headerInput.includes(':')}>Add</Button>
            </InputGroup>
            <div className="d-flex flex-wrap gap-2">
              {(advancedConfig.custom_headers || []).map((header, i) => (
                <Badge key={i} bg="secondary" className="d-flex align-items-center px-2 py-2">
                  <code className="me-2 small">{header}</code>
                  <i className="bi bi-x-circle" style={{ cursor: 'pointer' }} onClick={() => removeCustomHeader(i)}></i>
                </Badge>
              ))}
            </div>
          </Accordion.Body>
        </Accordion.Item>

        <Accordion.Item eventKey="3">
          <Accordion.Header><i className="bi bi-shield-lock me-2 text-danger"></i>Proxy &amp; Network</Accordion.Header>
          <Accordion.Body>
            <Row className="g-3">
              <Col md={6}>
                <Form.Group>
                  <Form.Label className="small text-muted">HTTP Proxy (-proxy)</Form.Label>
                  <Form.Control type="text" size="sm" placeholder="http://127.0.0.1:8080" value={advancedConfig.proxy} onChange={(e) => updateAdvancedConfig('proxy', e.target.value)} data-bs-theme="dark" />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group>
                  <Form.Label className="small text-muted">Scan Strategy (-ss)</Form.Label>
                  <Form.Select size="sm" value={advancedConfig.scan_strategy} onChange={(e) => updateAdvancedConfig('scan_strategy', e.target.value)} data-bs-theme="dark">
                    {scanStrategyOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                  </Form.Select>
                </Form.Group>
              </Col>
            </Row>
            <Row className="g-3 mt-2">
              <Col md={6}>
                <Form.Check type="switch" label="Use System Resolvers (-sr)" checked={advancedConfig.system_resolvers} onChange={(e) => updateAdvancedConfig('system_resolvers', e.target.checked)} />
              </Col>
            </Row>
          </Accordion.Body>
        </Accordion.Item>

        <Accordion.Item eventKey="4">
          <Accordion.Header><i className="bi bi-broadcast me-2 text-danger"></i>Interactsh (OAST)</Accordion.Header>
          <Accordion.Body>
            <Form.Check type="switch" label="Disable Interactsh (-ni)" className="mb-3" checked={advancedConfig.no_interactsh} onChange={(e) => updateAdvancedConfig('no_interactsh', e.target.checked)} />
            <Row className="g-3">
              <Col md={6}>
                <Form.Group>
                  <Form.Label className="small text-muted">Custom Server (-iserver)</Form.Label>
                  <Form.Control type="text" size="sm" placeholder="https://your-interactsh-server.com" value={advancedConfig.interactsh_server} onChange={(e) => updateAdvancedConfig('interactsh_server', e.target.value)} disabled={advancedConfig.no_interactsh} data-bs-theme="dark" />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group>
                  <Form.Label className="small text-muted">Auth Token (-itoken)</Form.Label>
                  <Form.Control type="password" size="sm" placeholder="Interactsh auth token" value={advancedConfig.interactsh_token} onChange={(e) => updateAdvancedConfig('interactsh_token', e.target.value)} disabled={advancedConfig.no_interactsh} data-bs-theme="dark" />
                </Form.Group>
              </Col>
            </Row>
          </Accordion.Body>
        </Accordion.Item>

        <Accordion.Item eventKey="5">
          <Accordion.Header><i className="bi bi-window-stack me-2 text-danger"></i>Headless Browser</Accordion.Header>
          <Accordion.Body>
            <Form.Check type="switch" label="Enable Headless Mode (-headless)" className="mb-3" checked={advancedConfig.headless} onChange={(e) => updateAdvancedConfig('headless', e.target.checked)} />
            <Row className="g-3">
              <Col md={6}>
                <Form.Group>
                  <Form.Label className="small text-muted">Headless Bulk Size (-hbs)</Form.Label>
                  <Form.Control type="number" size="sm" value={advancedConfig.headless_bulk_size} onChange={(e) => updateAdvancedConfig('headless_bulk_size', parseInt(e.target.value) || 10)} disabled={!advancedConfig.headless} data-bs-theme="dark" />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group>
                  <Form.Label className="small text-muted">Headless Concurrency (-headc)</Form.Label>
                  <Form.Control type="number" size="sm" value={advancedConfig.headless_concurrency} onChange={(e) => updateAdvancedConfig('headless_concurrency', parseInt(e.target.value) || 10)} disabled={!advancedConfig.headless} data-bs-theme="dark" />
                </Form.Group>
              </Col>
            </Row>
          </Accordion.Body>
        </Accordion.Item>

        <Accordion.Item eventKey="6">
          <Accordion.Header><i className="bi bi-funnel me-2 text-danger"></i>Advanced Filtering</Accordion.Header>
          <Accordion.Body>
            <Form.Group className="mb-3">
              <Form.Label className="small text-muted">Protocol Types (-pt)</Form.Label>
              <div className="d-flex flex-wrap gap-2">
                {protocolOptions.map(pt => (
                  <Form.Check key={pt} type="checkbox" label={pt} inline
                    checked={(advancedConfig.protocol_types || []).includes(pt)}
                    onChange={(e) => {
                      const current = advancedConfig.protocol_types || [];
                      updateAdvancedConfig('protocol_types', e.target.checked ? [...current, pt] : current.filter(p => p !== pt));
                    }}
                  />
                ))}
              </div>
            </Form.Group>
            <Form.Group className="mb-3">
              <Form.Label className="small text-muted">Template Condition Expression (-tc)</Form.Label>
              <Form.Control type="text" size="sm" placeholder="e.g., contains(tags,'cve') && contains(tags,'ssrf')" value={advancedConfig.template_condition} onChange={(e) => updateAdvancedConfig('template_condition', e.target.value)} data-bs-theme="dark" />
              <Form.Text className="text-muted">DSL expression to filter templates</Form.Text>
            </Form.Group>
            <Form.Group>
              <Form.Label className="small text-muted">Author Filter (-a)</Form.Label>
              <InputGroup className="mb-2" size="sm">
                <Form.Control type="text" placeholder="Filter by author name" value={authorInput} onChange={(e) => setAuthorInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addAuthorFilter()} data-bs-theme="dark" />
                <Button variant="outline-danger" onClick={addAuthorFilter} disabled={!authorInput.trim()}>Add</Button>
              </InputGroup>
              <div className="d-flex flex-wrap gap-2">
                {(advancedConfig.author_filter || []).map((author, i) => (
                  <Badge key={i} bg="info" className="d-flex align-items-center px-2 py-2">
                    {author}
                    <i className="bi bi-x-circle ms-2" style={{ cursor: 'pointer' }} onClick={() => removeAuthorFilter(i)}></i>
                  </Badge>
                ))}
              </div>
            </Form.Group>
          </Accordion.Body>
        </Accordion.Item>
      </Accordion>
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
          {isWildcard && <Badge bg="info" className="ms-3 fs-6">Wildcard Mode</Badge>}
          <Badge bg="secondary" className="ms-3 fs-6">{selectedTargets.size} targets</Badge>
          <Badge bg="secondary" className="ms-2 fs-6">{selectedTemplates.size + selectedTemplateIDs.size} templates</Badge>
          <Badge bg="secondary" className="ms-2 fs-6">{selectedSeverities.size} severities</Badge>
          {excludeIDs.size + excludeTags.size > 0 && (
            <Badge bg="warning" text="dark" className="ms-2 fs-6">{excludeIDs.size + excludeTags.size} exclusions</Badge>
          )}
        </Modal.Title>
      </Modal.Header>
      
      <Modal.Body className="p-0 d-flex flex-column" style={{ height: 'calc(100vh - 140px)' }}>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')} className="m-3 mb-0">{error}</Alert>
        )}

        <Tabs activeKey={activeTab} onSelect={(k) => setActiveTab(k)} className="px-3 pt-3" variant="pills">
          <Tab 
            eventKey="targets" 
            title={<span><i className="bi bi-bullseye me-2"></i>{isWildcard ? 'Live Web Servers' : 'Select Targets'}{selectedTargets.size > 0 && <Badge bg="success" className="ms-2">{selectedTargets.size}</Badge>}</span>}
          >
            <div className="h-100 py-3">{renderTargetSelection()}</div>
          </Tab>
          <Tab 
            eventKey="templates" 
            title={<span><i className="bi bi-file-code me-2"></i>Select Templates{(selectedTemplates.size + selectedTemplateIDs.size) > 0 && <Badge bg="success" className="ms-2">{selectedTemplates.size + selectedTemplateIDs.size}</Badge>}</span>}
          >
            <div className="h-100 py-3 px-3">{renderTemplateSelection()}</div>
          </Tab>
          <Tab 
            eventKey="exclusions" 
            title={<span><i className="bi bi-x-circle me-2"></i>Exclusions{(excludeIDs.size + excludeTags.size) > 0 && <Badge bg="warning" text="dark" className="ms-2">{excludeIDs.size + excludeTags.size}</Badge>}</span>}
          >
            <div className="h-100 py-3">{renderExclusions()}</div>
          </Tab>
          <Tab 
            eventKey="advanced" 
            title={<span><i className="bi bi-sliders me-2"></i>Advanced Settings</span>}
          >
            <div className="h-100 py-3">{renderAdvancedSettings()}</div>
          </Tab>
        </Tabs>
      </Modal.Body>
      
      <Modal.Footer className="border-top border-secondary">
        <div className="d-flex justify-content-between align-items-center w-100">
          <div className="text-muted small">
            <i className="bi bi-info-circle me-2"></i>
            Configure targets, templates, and advanced settings, then save to enable scanning
          </div>
          <div>
            <Button variant="secondary" onClick={handleCloseModal} className="me-2">Cancel</Button>
            <Button 
              variant="danger" 
              onClick={handleSaveConfig}
              disabled={saving || !hasAnyTemplateOrCategory()}
            >
              {saving ? (
                <><Spinner animation="border" size="sm" className="me-2" />Saving...</>
              ) : (
                <><i className="bi bi-check-circle me-2"></i>Save Configuration</>
              )}
            </Button>
          </div>
        </div>
      </Modal.Footer>
    </Modal>
  );
};

export default NucleiConfigModal;
