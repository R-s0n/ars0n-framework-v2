import { useState, useRef, useEffect } from 'react';
import { Modal, Button, Spinner, Alert, Row, Col, Form, Badge } from 'react-bootstrap';
import { FaTrash, FaPlus, FaUpload, FaCogs } from 'react-icons/fa';

const CloudEnumConfigModal = ({ 
  show, 
  handleClose, 
  activeTarget,
  onSaveConfig
}) => {
  const [keywords, setKeywords] = useState(['']);
  const [newKeyword, setNewKeyword] = useState('');
  const [customMutationsFile, setCustomMutationsFile] = useState(null);
  const [customBruteFile, setCustomBruteFile] = useState(null);
  const [threads, setThreads] = useState(5);
  const [enabledPlatforms, setEnabledPlatforms] = useState({
    aws: true,
    azure: true,
    gcp: true
  });
  const [customDnsServer, setCustomDnsServer] = useState('');
  const [dnsResolverMode, setDnsResolverMode] = useState('multiple');
  const [resolverConfig, setResolverConfig] = useState('default');
  const [customResolverFile, setCustomResolverFile] = useState(null);
  const [additionalResolvers, setAdditionalResolvers] = useState('');
  
  // Service and Region Selection
  const [selectedServices, setSelectedServices] = useState({
    aws: ['s3'],
    azure: ['storage-accounts'],
    gcp: ['gcp-buckets']
  });
  const [selectedRegions, setSelectedRegions] = useState({
    aws: ['us-east-1'],
    azure: ['eastus'],
    gcp: ['us-central1']
  });
  
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [buildingMutations, setBuildingMutations] = useState(false);
  const [buildingBrute, setBuildingBrute] = useState(false);
  
  const mutationsFileRef = useRef(null);
  const bruteFileRef = useRef(null);
  const resolverFileRef = useRef(null);

  // Available services and regions
  const availableServices = {
    aws: [
      's3', 'aws-apps', 'rds', 'dynamodb', 'cloudwatch', 'lambda', 'sqs', 'sns', 'iam', 
      'secrets-manager', 'cloudformation', 'appsync', 'eks', 'efs', 'workspaces', 
      'elastic-transcoder', 'workdocs', 'emr', 'elastic-beanstalk', 'cognito', 'cloud9', 
      'lightsail', 'workmail', 'redshift', 'cloudtrail', 'data-pipeline', 'kms', 'iot-core', 
      'systems-manager', 'xray', 'batch', 'snowball', 'inspector', 'kinesis', 'step-functions', 
      'sagemaker', 'redshift-spectrum', 'quicksight', 'cloudfront'
    ],
    azure: [
      'storage-accounts', 'blob-storage', 'key-vault', 'app-management', 'databases', 
      'virtual-machines', 'web-apps', 'cognitive-services', 'active-directory', 'service-bus', 
      'api-management', 'aks', 'monitor', 'logic-apps', 'redis-cache', 'container-registry', 
      'virtual-networks', 'cdn', 'event-grid', 'data-lake-storage', 'cognitive-search', 
      'iot-hub', 'cosmos-db', 'sql-database'
    ],
    gcp: [
      'gcp-buckets', 'firebase', 'app-engine', 'cloud-functions', 'pub-sub', 'bigquery', 
      'spanner', 'cloud-sql', 'vision-api', 'identity-platform', 'firestore', 'datastore', 
      'text-to-speech', 'ai-platform', 'compute-engine'
    ]
  };

  const availableRegions = {
    aws: [
      'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-west-1', 
      'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1', 'eu-south-1', 'ap-south-1', 
      'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 
      'sa-east-1', 'af-south-1', 'me-south-1', 'ap-east-1'
    ],
    azure: [
      'eastus', 'eastus2', 'westus', 'westus2', 'centralus', 'northcentralus', 'southcentralus', 
      'westcentralus', 'canadacentral', 'canadaeast', 'northeurope', 'westeurope', 'uksouth', 
      'ukwest', 'francecentral', 'germanywestcentral', 'norwayeast', 'switzerlandnorth', 
      'southeastasia', 'eastasia', 'australiaeast', 'australiasoutheast', 'japaneast', 
      'japanwest', 'koreacentral', 'southafricanorth', 'uaenorth', 'brazilsouth', 'southindia', 
      'centralindia', 'westindia'
    ],
    gcp: [
      'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4', 
      'northamerica-northeast1', 'southamerica-east1', 'europe-north1', 'europe-west1', 
      'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6', 'asia-east1', 
      'asia-east2', 'asia-northeast1', 'asia-northeast2', 'asia-northeast3', 'asia-south1', 
      'asia-southeast1', 'asia-southeast2', 'australia-southeast1'
    ]
  };

  useEffect(() => {
    if (show) {
      loadSavedConfig();
    }
  }, [show, activeTarget]);

  const loadSavedConfig = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `/api/cloud-enum-config/${activeTarget.id}`
      );
      
      if (response.ok) {
        const config = await response.json();
        setKeywords(config.keywords && config.keywords.length > 0 ? config.keywords : [activeTarget.scope_target || '']);
        setThreads(config.threads || 5);
        setEnabledPlatforms(config.enabled_platforms || { aws: true, azure: true, gcp: true });
        setCustomDnsServer(config.custom_dns_server || '');
        setDnsResolverMode(config.dns_resolver_mode || 'single');
        setResolverConfig(config.resolver_config || 'default');
        setAdditionalResolvers(config.additional_resolvers || '');
        setSelectedServices(config.selected_services || { aws: ['s3'], azure: ['storage-accounts'], gcp: ['gcp-buckets'] });
        setSelectedRegions(config.selected_regions || { aws: ['us-east-1'], azure: ['eastus'], gcp: ['us-central1'] });
      } else {
        // Default to using company name as first keyword
        setKeywords([activeTarget.scope_target || '']);
      }
    } catch (error) {
      console.error('Error loading CloudEnum config:', error);
      setKeywords([activeTarget.scope_target || '']);
    }
  };

  const handleBuildWordlist = async (type) => {
    if (!activeTarget?.id) {
      setError('No active target selected');
      return;
    }

    if (type === 'mutations') {
      setBuildingMutations(true);
    } else if (type === 'brute') {
      setBuildingBrute(true);
    }

    try {
      const response = await fetch(
        `/api/api/build-wordlist/${activeTarget.id}/${type}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          }
        }
      );

      if (!response.ok) {
        throw new Error('Failed to build wordlist');
      }

      const blob = await response.blob();
      const file = new File([blob], `${type}_${activeTarget.scope_target || 'wordlist'}.txt`, { type: 'text/plain' });

      if (type === 'mutations') {
        setCustomMutationsFile(file);
      } else if (type === 'brute') {
        setCustomBruteFile(file);
      }

    } catch (error) {
      console.error(`Error building ${type} wordlist:`, error);
      setError(`Failed to build ${type} wordlist. Please try again.`);
    } finally {
      if (type === 'mutations') {
        setBuildingMutations(false);
      } else if (type === 'brute') {
        setBuildingBrute(false);
      }
    }
  };

  const handleSaveConfig = async () => {
    if (!activeTarget?.id) {
      setError('No active target selected');
      return;
    }

    const validKeywords = keywords.filter(k => k.trim().length > 0);
    if (validKeywords.length === 0) {
      setError('At least one keyword is required');
      return;
    }

    setSaving(true);
    setError('');

    try {
      const formData = new FormData();
      
      const config = {
        keywords: validKeywords,
        threads: threads,
        enabled_platforms: enabledPlatforms,
        custom_dns_server: customDnsServer,
        dns_resolver_mode: dnsResolverMode,
        resolver_config: resolverConfig,
        additional_resolvers: additionalResolvers,
        selected_services: selectedServices,
        selected_regions: selectedRegions,
        created_at: new Date().toISOString()
      };

      formData.append('config', JSON.stringify(config));
      
      if (customMutationsFile) {
        formData.append('mutations_file', customMutationsFile);
      }
      
      if (customBruteFile) {
        formData.append('brute_file', customBruteFile);
      }
      
      if (customResolverFile) {
        formData.append('resolver_file', customResolverFile);
      }

      const response = await fetch(
        `/api/cloud-enum-config/${activeTarget.id}`,
        {
          method: 'POST',
          body: formData,
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
      console.error('Error saving CloudEnum config:', error);
      setError('Failed to save configuration. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const addKeyword = () => {
    if (newKeyword.trim() && !keywords.includes(newKeyword.trim())) {
      setKeywords([...keywords, newKeyword.trim()]);
      setNewKeyword('');
    }
  };

  const removeKeyword = (index) => {
    const newKeywords = keywords.filter((_, i) => i !== index);
    setKeywords(newKeywords.length > 0 ? newKeywords : ['']);
  };

  const updateKeyword = (index, value) => {
    const newKeywords = [...keywords];
    newKeywords[index] = value;
    setKeywords(newKeywords);
  };

  const addKeywordRow = () => {
    setKeywords([...keywords, '']);
  };

  const handleFileSelect = (fileType, event) => {
    const file = event.target.files[0];
    if (file) {
      if (fileType === 'mutations') {
        setCustomMutationsFile(file);
      } else if (fileType === 'brute') {
        setCustomBruteFile(file);
      } else if (fileType === 'resolvers') {
        setCustomResolverFile(file);
      }
    }
  };

  const handleCloseModal = () => {
    setError('');
    handleClose();
  };

  const presetDnsServers = [
    { label: 'Default', value: '' },
    { label: 'Google DNS', value: '8.8.8.8' },
    { label: 'Cloudflare DNS', value: '1.1.1.1' },
    { label: 'Quad9 DNS', value: '9.9.9.9' },
    { label: 'OpenDNS', value: '208.67.222.222' }
  ];

  const getTotalResolverCount = () => {
    if (resolverConfig === 'default') {
      return 118;
    } else if (resolverConfig === 'custom') {
      return 1;
    } else if (resolverConfig === 'hybrid') {
      return 118 + additionalResolvers.split('\n').filter(Boolean).length;
    }
    return 0;
  };

  const getPerformanceEstimate = () => {
    if (resolverConfig === 'default') {
      return '118 resolvers';
    } else if (resolverConfig === 'custom') {
      return 'Custom resolver list';
    } else if (resolverConfig === 'hybrid') {
      return `${getTotalResolverCount()} total resolvers`;
    }
    return 'Unknown';
  };

  // Helper functions for service and region selection
  const toggleService = (platform, service) => {
    setSelectedServices(prev => ({
      ...prev,
      [platform]: prev[platform].includes(service) 
        ? prev[platform].filter(s => s !== service)
        : [...prev[platform], service]
    }));
  };

  const toggleRegion = (platform, region) => {
    setSelectedRegions(prev => ({
      ...prev,
      [platform]: prev[platform].includes(region) 
        ? prev[platform].filter(r => r !== region)
        : [...prev[platform], region]
    }));
  };

  const selectAllServices = (platform) => {
    setSelectedServices(prev => ({
      ...prev,
      [platform]: availableServices[platform]
    }));
  };

  const selectAllRegions = (platform) => {
    setSelectedRegions(prev => ({
      ...prev,
      [platform]: availableRegions[platform]
    }));
  };

  const clearAllServices = (platform) => {
    setSelectedServices(prev => ({
      ...prev,
      [platform]: []
    }));
  };

  const clearAllRegions = (platform) => {
    setSelectedRegions(prev => ({
      ...prev,
      [platform]: []
    }));
  };

  const formatServiceName = (service) => {
    return service.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
  };

  const formatRegionName = (region) => {
    return region.charAt(0).toUpperCase() + region.slice(1);
  };

  return (
    <>
      <style>
        {`
          .form-switch .form-check-input:checked {
            background-color: #dc3545 !important;
            border-color: #dc3545 !important;
          }
          .form-switch .form-check-input:focus {
            border-color: #dc3545 !important;
            box-shadow: 0 0 0 0.25rem rgba(220, 53, 69, 0.25) !important;
          }
          .form-check-input[type="radio"]:checked {
            background-color: #dc3545 !important;
            border-color: #dc3545 !important;
          }
          .form-check-input[type="radio"]:focus {
            border-color: #dc3545 !important;
            box-shadow: 0 0 0 0.25rem rgba(220, 53, 69, 0.25) !important;
          }
          .form-range::-webkit-slider-thumb {
            background: #dc3545 !important;
          }
          .form-range::-moz-range-thumb {
            background: #dc3545 !important;
            border: none !important;
          }
          .form-range:focus::-webkit-slider-thumb {
            box-shadow: 0 0 0 1px #fff, 0 0 0 0.25rem rgba(220, 53, 69, 0.25) !important;
          }
          .form-range:focus::-moz-range-thumb {
            box-shadow: 0 0 0 1px #fff, 0 0 0 0.25rem rgba(220, 53, 69, 0.25) !important;
          }
        `}
      </style>
      <Modal 
        show={show} 
        onHide={handleCloseModal} 
        size="xl" 
        data-bs-theme="dark"
        className="modal-90w"
      >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-cloud me-2" />
          Configure Cloud Enum - Advanced Settings
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        <div className="mb-4">
          <div className="text-white-50">
            <i className="bi bi-info-circle me-2" />
            <strong>Cloud Enum Configuration:</strong> Customize keywords, wordlists, and scanning parameters for comprehensive cloud asset discovery.
          </div>
        </div>

        <Row>
          <Col lg={6}>
            {/* Keywords Section */}
            <div className="mb-4">
              <h6 className="text-danger mb-3">
                <i className="bi bi-tags me-2" />
                Target Keywords
              </h6>
              
              <div className="mb-3">
                {keywords.map((keyword, index) => (
                  <div key={index} className="d-flex mb-2">
                    <Form.Control
                      type="text"
                      placeholder="Enter keyword (e.g., company name)"
                      value={keyword}
                      onChange={(e) => updateKeyword(index, e.target.value)}
                      data-bs-theme="dark"
                      className="me-2"
                    />
                    {keywords.length > 1 && (
                      <Button 
                        variant="outline-danger" 
                        size="sm"
                        onClick={() => removeKeyword(index)}
                      >
                        <FaTrash />
                      </Button>
                    )}
                  </div>
                ))}
              </div>

              <div className="d-flex mb-3">
                <Form.Control
                  type="text"
                  placeholder="Add new keyword..."
                  value={newKeyword}
                  onChange={(e) => setNewKeyword(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && addKeyword()}
                  data-bs-theme="dark"
                  className="me-2"
                />
                <Button variant="outline-danger" onClick={addKeyword} disabled={!newKeyword.trim()}>
                  <FaPlus />
                </Button>
              </div>

              <small className="text-white-50">
                Multiple keywords increase discovery chances. Common variations will be automatically tested.
              </small>
            </div>



            {/* DNS Configuration */}
            <div className="mb-4">
              <h6 className="text-danger mb-3">
                <i className="bi bi-router me-2" />
                DNS Configuration
              </h6>
              
              {/* DNS Resolver Mode Selection */}
              <div className="mb-3">
                <Form.Label className="text-white-50 small">DNS Resolver Mode</Form.Label>
                <div className="mb-2">
                  <Form.Check
                    type="radio"
                    id="dns-mode-single"
                    name="dnsMode"
                    label={
                      <div>
                        <strong>Single DNS Server</strong>
                        <small className="d-block text-white-50">Use one DNS resolver (slower)</small>
                      </div>
                    }
                    checked={dnsResolverMode === 'single'}
                    onChange={() => setDnsResolverMode('single')}
                    className="text-white"
                    style={{
                      '--bs-form-check-input-checked-color': '#fff',
                      '--bs-form-check-input-checked-bg-color': '#dc3545',
                      '--bs-form-check-input-checked-border-color': '#dc3545'
                    }}
                  />
                  <Form.Check
                    type="radio"
                    id="dns-mode-multiple"
                    name="dnsMode"
                    label={
                      <div>
                        <strong>Multiple DNS Resolvers</strong> <Badge bg="success" className="ms-1">Recommended</Badge>
                        <small className="d-block text-white-50">Use 118+ resolvers (~3-5x faster)</small>
                      </div>
                    }
                    checked={dnsResolverMode === 'multiple'}
                    onChange={() => setDnsResolverMode('multiple')}
                    className="text-white"
                    style={{
                      '--bs-form-check-input-checked-color': '#fff',
                      '--bs-form-check-input-checked-bg-color': '#dc3545',
                      '--bs-form-check-input-checked-border-color': '#dc3545'
                    }}
                  />
                </div>
              </div>

              {/* Single DNS Server Selection */}
              {dnsResolverMode === 'single' && (
                <Form.Group className="mb-3">
                  <Form.Label className="text-white-50 small">DNS Server</Form.Label>
                  <Form.Select
                    value={customDnsServer}
                    onChange={(e) => setCustomDnsServer(e.target.value)}
                    data-bs-theme="dark"
                  >
                    {presetDnsServers.map(server => (
                      <option key={server.value} value={server.value}>
                        {server.label} {server.value && `(${server.value})`}
                      </option>
                    ))}
                  </Form.Select>
                </Form.Group>
              )}

              {/* Multiple DNS Resolvers Configuration */}
              {dnsResolverMode === 'multiple' && (
                <div>
                  <div className="mb-3">
                    <Form.Label className="text-white-50 small">Resolver Configuration</Form.Label>
                    <div className="mb-2">
                      <Form.Check
                        type="radio"
                        id="resolvers-default"
                        name="resolverConfig"
                        label={
                          <div>
                            <strong>Default Resolver List</strong>
                            <small className="d-block text-white-50">Optimized list from major DNS providers</small>
                          </div>
                        }
                        checked={resolverConfig === 'default'}
                        onChange={() => setResolverConfig('default')}
                        className="text-white"
                        style={{
                          '--bs-form-check-input-checked-color': '#fff',
                          '--bs-form-check-input-checked-bg-color': '#dc3545',
                          '--bs-form-check-input-checked-border-color': '#dc3545'
                        }}
                      />
                      <Form.Check
                        type="radio"
                        id="resolvers-custom"
                        name="resolverConfig"
                        label={
                          <div>
                            <strong>Custom Resolver List</strong>
                            <small className="d-block text-white-50">Upload your own resolver file</small>
                          </div>
                        }
                        checked={resolverConfig === 'custom'}
                        onChange={() => setResolverConfig('custom')}
                        className="text-white"
                        style={{
                          '--bs-form-check-input-checked-color': '#fff',
                          '--bs-form-check-input-checked-bg-color': '#dc3545',
                          '--bs-form-check-input-checked-border-color': '#dc3545'
                        }}
                      />
                      <Form.Check
                        type="radio"
                        id="resolvers-hybrid"
                        name="resolverConfig"
                        label={
                          <div>
                            <strong>Hybrid Mode</strong>
                            <small className="d-block text-white-50">Default list + additional resolvers</small>
                          </div>
                        }
                        checked={resolverConfig === 'hybrid'}
                        onChange={() => setResolverConfig('hybrid')}
                        className="text-white"
                        style={{
                          '--bs-form-check-input-checked-color': '#fff',
                          '--bs-form-check-input-checked-bg-color': '#dc3545',
                          '--bs-form-check-input-checked-border-color': '#dc3545'
                        }}
                      />
                    </div>
                  </div>

                  {/* Custom Resolver File Upload */}
                  {resolverConfig === 'custom' && (
                    <div className="mb-3">
                      <Form.Label className="text-white-50 small">Custom Resolver File</Form.Label>
                      <div className="d-flex">
                        <Form.Control
                          type="text"
                          value={customResolverFile ? customResolverFile.name : 'No file selected'}
                          readOnly
                          data-bs-theme="dark"
                          className="me-2"
                          placeholder="Upload resolver file (one IP per line)"
                        />
                        <Button 
                          variant="outline-danger" 
                          onClick={() => resolverFileRef.current?.click()}
                        >
                          <FaUpload className="me-1" />
                          Upload
                        </Button>
                      </div>
                      <input
                        type="file"
                        ref={resolverFileRef}
                        onChange={(e) => handleFileSelect('resolvers', e)}
                        accept=".txt,.lst"
                        style={{ display: 'none' }}
                      />
                      <small className="text-white-50 d-block mt-1">
                        One DNS resolver IP per line (e.g., 8.8.8.8)
                      </small>
                    </div>
                  )}

                  {/* Additional Resolvers for Hybrid Mode */}
                  {resolverConfig === 'hybrid' && (
                    <div className="mb-3">
                      <Form.Label className="text-white-50 small">Additional DNS Resolvers</Form.Label>
                      <Form.Control
                        as="textarea"
                        rows={4}
                        placeholder="Add additional DNS resolvers (one per line)&#10;Example:&#10;8.8.8.8&#10;1.1.1.1&#10;9.9.9.9"
                        value={additionalResolvers}
                        onChange={(e) => setAdditionalResolvers(e.target.value)}
                        data-bs-theme="dark"
                        className="mb-2"
                      />
                      <small className="text-white-50">
                        These will be added to the default 118 resolvers. Total: {getTotalResolverCount()} resolvers
                      </small>
                    </div>
                  )}

                  {/* DNS Performance Estimate */}
                  <div className="mb-3">
                    <Alert variant="success" className="py-2">
                      <div className="d-flex align-items-center">
                        <i className="bi bi-speedometer2 me-2" />
                        <div>
                          <strong>Performance Boost:</strong> {getPerformanceEstimate()}
                          <br />
                          <small>Using {getTotalResolverCount()} DNS resolvers for maximum speed and reliability</small>
                        </div>
                      </div>
                    </Alert>
                  </div>
                </div>
              )}
            </div>

            {/* Custom Wordlists */}
            <div className="mb-4">
              <h6 className="text-danger mb-3">
                <i className="bi bi-file-text me-2" />
                Custom Wordlists
              </h6>
              
              {/* Mutations File */}
              <div className="mb-3">
                <Form.Label className="text-white-50 small">Custom Mutations File</Form.Label>
                <div className="d-flex">
                  <Form.Control
                    type="text"
                    value={customMutationsFile ? customMutationsFile.name : 'No file selected'}
                    readOnly
                    data-bs-theme="dark"
                    className="me-2"
                    placeholder="Default mutations will be used"
                  />
                  <Button 
                    variant="outline-danger" 
                    onClick={() => handleBuildWordlist('mutations')}
                    disabled={buildingMutations}
                    className="me-1"
                  >
                    {buildingMutations ? (
                      <>
                        <Spinner animation="border" size="sm" className="me-1" />
                        Building...
                      </>
                    ) : (
                      <>
                        <FaCogs className="me-1" />
                        Build
                      </>
                    )}
                  </Button>
                  <Button 
                    variant="outline-danger" 
                    onClick={() => mutationsFileRef.current?.click()}
                  >
                    <FaUpload className="me-1" />
                    Upload
                  </Button>
                </div>
                <input
                  type="file"
                  ref={mutationsFileRef}
                  onChange={(e) => handleFileSelect('mutations', e)}
                  accept=".txt,.lst"
                  style={{ display: 'none' }}
                />
                <small className="text-white-50 d-block mt-1">
                  Build from discovered domains or upload custom keyword mutations for enhanced discovery
                </small>
              </div>

              {/* Brute Force File */}
              <div className="mb-3">
                <Form.Label className="text-white-50 small">Custom Brute Force Wordlist</Form.Label>
                <div className="d-flex">
                  <Form.Control
                    type="text"
                    value={customBruteFile ? customBruteFile.name : 'No file selected'}
                    readOnly
                    data-bs-theme="dark"
                    className="me-2"
                    placeholder="Default wordlist will be used"
                  />
                  <Button 
                    variant="outline-danger" 
                    onClick={() => handleBuildWordlist('brute')}
                    disabled={buildingBrute}
                    className="me-1"
                  >
                    {buildingBrute ? (
                      <>
                        <Spinner animation="border" size="sm" className="me-1" />
                        Building...
                      </>
                    ) : (
                      <>
                        <FaCogs className="me-1" />
                        Build
                      </>
                    )}
                  </Button>
                  <Button 
                    variant="outline-danger" 
                    onClick={() => bruteFileRef.current?.click()}
                  >
                    <FaUpload className="me-1" />
                    Upload
                  </Button>
                </div>
                <input
                  type="file"
                  ref={bruteFileRef}
                  onChange={(e) => handleFileSelect('brute', e)}
                  accept=".txt,.lst"
                  style={{ display: 'none' }}
                />
                <small className="text-white-50 d-block mt-1">
                  Build from discovered domains or upload custom brute force list for Azure container names
                </small>
              </div>
            </div>
          </Col>

          <Col lg={6}>
            {/* Performance Settings */}
            <div className="mb-4">
              <h6 className="text-danger mb-3">
                <i className="bi bi-speedometer2 me-2" />
                Performance Settings
              </h6>
              
              <Form.Group>
                <Form.Label className="text-white-50 small">Thread Count: {threads}</Form.Label>
                <Form.Range
                  min="1"
                  max="20"
                  value={threads}
                  onChange={(e) => setThreads(parseInt(e.target.value))}
                  className="custom-range"
                />
                <div className="d-flex justify-content-between">
                  <small className="text-white-50">1 (Slow)</small>
                  <small className="text-white-50">20 (Fast)</small>
                </div>
              </Form.Group>
            </div>

            {/* Platform Selection */}
            <div className="mb-4">
              <h6 className="text-danger mb-3">
                <i className="bi bi-cloud-check me-2" />
                Target Platforms
              </h6>
              
              <div className="mb-3">
                {Object.entries(enabledPlatforms).map(([platform, enabled]) => (
                  <Form.Check
                    key={platform}
                    type="switch"
                    id={`platform-${platform}`}
                    label={platform === 'aws' ? 'Amazon Web Services' : platform === 'azure' ? 'Microsoft Azure' : 'Google Cloud Platform'}
                    checked={enabled}
                    onChange={(e) => setEnabledPlatforms(prev => ({ ...prev, [platform]: e.target.checked }))}
                    className="text-white mb-2"
                  />
                ))}
              </div>
              
              <small className="text-white-50">
                Disable platforms to speed up scans when you know the target's preferences.
              </small>
            </div>

            {/* Service and Region Selection */}
            <div className="mb-4">
              <h6 className="text-danger mb-3">
                <i className="bi bi-gear me-2" />
                Service & Region Selection
              </h6>
              
              {Object.entries(enabledPlatforms).map(([platform, enabled]) => (
                enabled && (
                  <div key={platform} className="mb-3">
                    <h6 className="text-white mb-2">
                      {platform === 'aws' ? 'Amazon Web Services' : platform === 'azure' ? 'Microsoft Azure' : 'Google Cloud Platform'}
                    </h6>
                    
                    <div className="row">
                      {/* Services */}
                      <div className="col-md-6">
                        <div className="mb-3">
                          <div className="d-flex justify-content-between align-items-center mb-2">
                            <small className="text-white-50 fw-bold">Services ({selectedServices[platform].length}/{availableServices[platform].length})</small>
                            <div>
                              <Button variant="outline-success" size="sm" onClick={() => selectAllServices(platform)} className="me-1">
                                All
                              </Button>
                              <Button variant="outline-secondary" size="sm" onClick={() => clearAllServices(platform)}>
                                None
                              </Button>
                            </div>
                          </div>
                          <div className="border rounded p-2" style={{ maxHeight: '120px', overflowY: 'auto' }}>
                            {availableServices[platform].map(service => (
                              <Form.Check
                                key={service}
                                type="checkbox"
                                id={`service-${platform}-${service}`}
                                label={formatServiceName(service)}
                                checked={selectedServices[platform].includes(service)}
                                onChange={() => toggleService(platform, service)}
                                className="text-white-50 small"
                              />
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* Regions */}
                      <div className="col-md-6">
                        <div className="mb-3">
                          <div className="d-flex justify-content-between align-items-center mb-2">
                            <small className="text-white-50 fw-bold">Regions ({selectedRegions[platform].length}/{availableRegions[platform].length})</small>
                            <div>
                              <Button variant="outline-success" size="sm" onClick={() => selectAllRegions(platform)} className="me-1">
                                All
                              </Button>
                              <Button variant="outline-secondary" size="sm" onClick={() => clearAllRegions(platform)}>
                                None
                              </Button>
                            </div>
                          </div>
                          <div className="border rounded p-2" style={{ maxHeight: '120px', overflowY: 'auto' }}>
                            {availableRegions[platform].map(region => (
                              <Form.Check
                                key={region}
                                type="checkbox"
                                id={`region-${platform}-${region}`}
                                label={formatRegionName(region)}
                                checked={selectedRegions[platform].includes(region)}
                                onChange={() => toggleRegion(platform, region)}
                                className="text-white-50 small"
                              />
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )
              ))}
              
              <small className="text-white-50">
                <i className="bi bi-info-circle me-1" />
                Leave services/regions empty to scan all available. Specific selections reduce scan time and focus on your target infrastructure.
              </small>
            </div>
          </Col>
        </Row>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleCloseModal} className="me-2">
          Cancel
        </Button>
        <Button 
          variant="danger" 
          onClick={handleSaveConfig}
          disabled={saving || keywords.filter(k => k.trim()).length === 0}
        >
          {saving ? (
            <>
              <Spinner animation="border" size="sm" className="me-2" />
              Saving...
            </>
          ) : (
            <>
              <i className="bi bi-save me-2" />
              Save Configuration
            </>
          )}
        </Button>
      </Modal.Footer>
    </Modal>
    </>
  );
};

export default CloudEnumConfigModal; 