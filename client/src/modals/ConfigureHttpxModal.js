import { useState, useEffect } from 'react';
import { Modal, Button, Form, Row, Col, Badge, Tab, Tabs, InputGroup } from 'react-bootstrap';

const DEFAULT_PORTS = [80, 443, 7547, 8089, 8085, 8443, 8080, 4567, 7170, 8008, 2083, 8000, 2082, 8081, 2087, 2086, 8888, 8880, 60000, 40000, 9080, 5985, 9100, 2096, 3000, 1024, 30005, 81, 21, 5000, 2095];

const DEFAULT_MATCH_CODES = "100,101,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,426,428,429,431,451,500,501,502,503,504,505,506,507,508,510,511";

const COMMON_PORTS = [
  { port: 80, label: "HTTP" },
  { port: 443, label: "HTTPS" },
  { port: 8080, label: "HTTP Alt" },
  { port: 8443, label: "HTTPS Alt" },
  { port: 8000, label: "HTTP Dev" },
  { port: 8888, label: "HTTP Alt" },
  { port: 3000, label: "Node/React" },
  { port: 5000, label: "Flask/Dev" },
  { port: 8081, label: "HTTP Alt" },
  { port: 9080, label: "HTTP Alt" },
  { port: 81, label: "HTTP Alt" },
  { port: 21, label: "FTP" },
  { port: 2083, label: "cPanel SSL" },
  { port: 2082, label: "cPanel" },
  { port: 2087, label: "WHM SSL" },
  { port: 2086, label: "WHM" },
  { port: 2095, label: "Webmail" },
  { port: 2096, label: "Webmail SSL" },
  { port: 8880, label: "HTTP Alt" },
  { port: 8008, label: "HTTP Alt" },
  { port: 8085, label: "HTTP Alt" },
  { port: 8089, label: "Splunk" },
  { port: 7547, label: "CWMP" },
  { port: 4567, label: "Sinatra" },
  { port: 7170, label: "HTTP Alt" },
  { port: 5985, label: "WinRM" },
  { port: 9100, label: "Print" },
  { port: 1024, label: "Reserved" },
  { port: 30005, label: "HTTP Alt" },
  { port: 40000, label: "HTTP Alt" },
  { port: 60000, label: "HTTP Alt" },
  { port: 9443, label: "HTTPS Alt" },
  { port: 4443, label: "HTTPS Alt" },
  { port: 8444, label: "HTTPS Alt" },
  { port: 9090, label: "Web Console" },
  { port: 8181, label: "HTTP Alt" },
  { port: 8282, label: "HTTP Alt" },
  { port: 3443, label: "HTTPS Alt" },
  { port: 10443, label: "HTTPS Alt" },
  { port: 4444, label: "HTTP Alt" },
  { port: 5443, label: "HTTPS Alt" },
  { port: 7443, label: "HTTPS Alt" },
  { port: 8880, label: "HTTP Alt" },
  { port: 10000, label: "Webmin" },
  { port: 8834, label: "Nessus" },
  { port: 9200, label: "Elasticsearch" },
  { port: 5601, label: "Kibana" },
  { port: 3001, label: "Dev Server" },
  { port: 4200, label: "Angular" },
  { port: 8088, label: "HTTP Alt" },
];

const getDefaultConfig = () => ({
  ports: [...DEFAULT_PORTS],
  threads: 50,
  rateLimit: 150,
  timeout: 10,
  retries: 2,
  matchCodes: DEFAULT_MATCH_CODES,
  probes: {
    statusCode: true,
    title: true,
    techDetect: true,
    server: true,
    contentLength: true,
    location: false,
    favicon: false,
    jarm: false,
    responseTime: false,
    lineCount: false,
    wordCount: false,
    method: false,
    websocket: false,
    ip: false,
    cname: false,
    asn: false,
    cdn: true,
    probe: false,
  },
  filters: {
    filterCode: "",
    filterLength: "",
    filterLineCount: "",
    filterWordCount: "",
    filterString: "",
    filterRegex: "",
    filterCdn: "",
    filterResponseTime: "",
    filterCondition: "",
    filterDuplicates: false,
  },
  matchers: {
    matchLength: "",
    matchLineCount: "",
    matchWordCount: "",
    matchString: "",
    matchRegex: "",
    matchCdn: "",
    matchResponseTime: "",
    matchCondition: "",
    matchFavicon: "",
  },
  misc: {
    followRedirects: false,
    maxRedirects: 10,
    probeAllIps: false,
    tlsProbe: false,
    cspProbe: false,
    tlsGrab: false,
    pipeline: false,
    http2: false,
    vhost: false,
    noFallback: false,
    noFallbackScheme: false,
    maxHostError: 30,
  },
  headless: {
    screenshot: false,
    screenshotTimeout: 10,
  },
  extractors: {
    extractRegex: "",
    extractPreset: "",
    extractFqdn: false,
  },
  customHeaders: "",
  httpProxy: "",
  resolvers: "",
  path: "",
  requestMethods: "",
  body: "",
});

const ConfigureHttpxModal = ({
  show,
  handleClose,
  httpxConfig,
  onSaveConfig,
}) => {
  const [activeTab, setActiveTab] = useState('ports');
  const [config, setConfig] = useState(getDefaultConfig());
  const [newPort, setNewPort] = useState('');
  const [portRange, setPortRange] = useState({ start: '', end: '' });

  useEffect(() => {
    if (show && httpxConfig) {
      setConfig({ ...getDefaultConfig(), ...httpxConfig });
    } else if (show) {
      setConfig(getDefaultConfig());
    }
  }, [show, httpxConfig]);

  const handleSave = () => {
    onSaveConfig(config);
    handleClose();
  };

  const handleReset = () => {
    setConfig(getDefaultConfig());
  };

  const addPort = () => {
    const port = parseInt(newPort, 10);
    if (port && port > 0 && port <= 65535 && !config.ports.includes(port)) {
      setConfig(prev => ({ ...prev, ports: [...prev.ports, port].sort((a, b) => a - b) }));
      setNewPort('');
    }
  };

  const addPortRange = () => {
    const start = parseInt(portRange.start, 10);
    const end = parseInt(portRange.end, 10);
    if (start && end && start > 0 && end <= 65535 && start <= end) {
      const newPorts = [];
      for (let i = start; i <= end; i++) {
        if (!config.ports.includes(i)) {
          newPorts.push(i);
        }
      }
      if (newPorts.length > 0) {
        setConfig(prev => ({ ...prev, ports: [...prev.ports, ...newPorts].sort((a, b) => a - b) }));
      }
      setPortRange({ start: '', end: '' });
    }
  };

  const removePort = (port) => {
    setConfig(prev => ({ ...prev, ports: prev.ports.filter(p => p !== port) }));
  };

  const toggleCommonPort = (port) => {
    if (config.ports.includes(port)) {
      removePort(port);
    } else {
      setConfig(prev => ({ ...prev, ports: [...prev.ports, port].sort((a, b) => a - b) }));
    }
  };

  const clearAllPorts = () => {
    setConfig(prev => ({ ...prev, ports: [] }));
  };

  const resetDefaultPorts = () => {
    setConfig(prev => ({ ...prev, ports: [...DEFAULT_PORTS] }));
  };

  const setMinimalPorts = () => {
    setConfig(prev => ({ ...prev, ports: [80, 443] }));
  };

  const setWebPorts = () => {
    setConfig(prev => ({ ...prev, ports: [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9090] }));
  };

  const updateProbe = (key, value) => {
    setConfig(prev => ({ ...prev, probes: { ...prev.probes, [key]: value } }));
  };

  const updateFilter = (key, value) => {
    setConfig(prev => ({ ...prev, filters: { ...prev.filters, [key]: value } }));
  };

  const updateMatcher = (key, value) => {
    setConfig(prev => ({ ...prev, matchers: { ...prev.matchers, [key]: value } }));
  };

  const updateMisc = (key, value) => {
    setConfig(prev => ({ ...prev, misc: { ...prev.misc, [key]: value } }));
  };

  const updateHeadless = (key, value) => {
    setConfig(prev => ({ ...prev, headless: { ...prev.headless, [key]: value } }));
  };

  const updateExtractor = (key, value) => {
    setConfig(prev => ({ ...prev, extractors: { ...prev.extractors, [key]: value } }));
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Configure HTTPX Scan</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Tabs activeKey={activeTab} onSelect={setActiveTab} className="mb-3">
          <Tab eventKey="ports" title="Ports">
            <div className="mb-3">
              <div className="d-flex gap-2 mb-3">
                <Button variant="outline-secondary" size="sm" onClick={resetDefaultPorts}>Default Ports ({DEFAULT_PORTS.length})</Button>
                <Button variant="outline-info" size="sm" onClick={setMinimalPorts}>Minimal (80, 443)</Button>
                <Button variant="outline-info" size="sm" onClick={setWebPorts}>Common Web (10)</Button>
                <Button variant="outline-danger" size="sm" onClick={clearAllPorts}>Clear All</Button>
              </div>

              <div className="mb-3">
                <Form.Label className="text-white">Active Ports ({config.ports.length})</Form.Label>
                <div className="d-flex flex-wrap gap-1 p-2 border border-secondary rounded" style={{ maxHeight: '150px', overflowY: 'auto' }}>
                  {config.ports.length === 0 ? (
                    <span className="text-muted fst-italic">No ports selected</span>
                  ) : (
                    config.ports.map(port => (
                      <Badge
                        key={port}
                        bg="danger"
                        className="d-flex align-items-center gap-1"
                        style={{ cursor: 'pointer', fontSize: '0.85em' }}
                        onClick={() => removePort(port)}
                      >
                        {port} <i className="bi bi-x"></i>
                      </Badge>
                    ))
                  )}
                </div>
              </div>

              <Row className="mb-3">
                <Col md={4}>
                  <Form.Label className="text-white">Add Single Port</Form.Label>
                  <InputGroup>
                    <Form.Control
                      type="number"
                      min="1"
                      max="65535"
                      placeholder="e.g. 8080"
                      value={newPort}
                      onChange={(e) => setNewPort(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && addPort()}
                    />
                    <Button variant="outline-danger" onClick={addPort}>Add</Button>
                  </InputGroup>
                </Col>
                <Col md={8}>
                  <Form.Label className="text-white">Add Port Range</Form.Label>
                  <InputGroup>
                    <Form.Control
                      type="number"
                      min="1"
                      max="65535"
                      placeholder="Start"
                      value={portRange.start}
                      onChange={(e) => setPortRange(prev => ({ ...prev, start: e.target.value }))}
                    />
                    <InputGroup.Text>to</InputGroup.Text>
                    <Form.Control
                      type="number"
                      min="1"
                      max="65535"
                      placeholder="End"
                      value={portRange.end}
                      onChange={(e) => setPortRange(prev => ({ ...prev, end: e.target.value }))}
                    />
                    <Button variant="outline-danger" onClick={addPortRange}>Add Range</Button>
                  </InputGroup>
                </Col>
              </Row>

              <Form.Label className="text-white">Quick Toggle Common Ports</Form.Label>
              <div className="d-flex flex-wrap gap-1">
                {COMMON_PORTS.map(({ port, label }) => (
                  <Badge
                    key={port}
                    bg={config.ports.includes(port) ? 'danger' : 'secondary'}
                    style={{ cursor: 'pointer', fontSize: '0.8em' }}
                    onClick={() => toggleCommonPort(port)}
                  >
                    {port} ({label})
                  </Badge>
                ))}
              </div>
            </div>
          </Tab>

          <Tab eventKey="performance" title="Performance">
            <Row className="mb-3">
              <Col md={4}>
                <Form.Label className="text-white">Threads (-t)</Form.Label>
                <Form.Control
                  type="number"
                  min="1"
                  max="500"
                  value={config.threads}
                  onChange={(e) => setConfig(prev => ({ ...prev, threads: parseInt(e.target.value, 10) || 50 }))}
                />
                <Form.Text className="text-muted">Number of concurrent threads (default: 50)</Form.Text>
              </Col>
              <Col md={4}>
                <Form.Label className="text-white">Rate Limit (-rl)</Form.Label>
                <Form.Control
                  type="number"
                  min="1"
                  max="10000"
                  value={config.rateLimit}
                  onChange={(e) => setConfig(prev => ({ ...prev, rateLimit: parseInt(e.target.value, 10) || 150 }))}
                />
                <Form.Text className="text-muted">Max requests per second (default: 150)</Form.Text>
              </Col>
              <Col md={4}>
                <Form.Label className="text-white">Timeout (-timeout)</Form.Label>
                <Form.Control
                  type="number"
                  min="1"
                  max="300"
                  value={config.timeout}
                  onChange={(e) => setConfig(prev => ({ ...prev, timeout: parseInt(e.target.value, 10) || 10 }))}
                />
                <Form.Text className="text-muted">Request timeout in seconds (default: 10)</Form.Text>
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={4}>
                <Form.Label className="text-white">Retries (-retries)</Form.Label>
                <Form.Control
                  type="number"
                  min="0"
                  max="10"
                  value={config.retries}
                  onChange={(e) => setConfig(prev => ({ ...prev, retries: parseInt(e.target.value, 10) || 0 }))}
                />
                <Form.Text className="text-muted">Number of retries (default: 2)</Form.Text>
              </Col>
              <Col md={4}>
                <Form.Label className="text-white">Max Host Errors (-maxhr)</Form.Label>
                <Form.Control
                  type="number"
                  min="1"
                  max="1000"
                  value={config.misc.maxHostError}
                  onChange={(e) => updateMisc('maxHostError', parseInt(e.target.value, 10) || 30)}
                />
                <Form.Text className="text-muted">Max errors per host before skipping (default: 30)</Form.Text>
              </Col>
              <Col md={4}>
                <Form.Label className="text-white">Max Redirects (-maxr)</Form.Label>
                <Form.Control
                  type="number"
                  min="0"
                  max="100"
                  value={config.misc.maxRedirects}
                  onChange={(e) => updateMisc('maxRedirects', parseInt(e.target.value, 10) || 10)}
                />
                <Form.Text className="text-muted">Max redirects to follow per host (default: 10)</Form.Text>
              </Col>
            </Row>
          </Tab>

          <Tab eventKey="probes" title="Probes">
            <p className="text-muted mb-3">Select which data probes to enable during the scan.</p>
            <Row>
              {[
                { key: 'statusCode', label: 'Status Code (-sc)', desc: 'Display response status code' },
                { key: 'title', label: 'Page Title (-title)', desc: 'Display page title' },
                { key: 'techDetect', label: 'Tech Detect (-td)', desc: 'Detect technologies via Wappalyzer' },
                { key: 'server', label: 'Web Server (-server)', desc: 'Display server name' },
                { key: 'contentLength', label: 'Content Length (-cl)', desc: 'Display response content length' },
                { key: 'location', label: 'Location (-location)', desc: 'Display redirect location' },
                { key: 'favicon', label: 'Favicon (-favicon)', desc: 'Display favicon hash' },
                { key: 'jarm', label: 'JARM (-jarm)', desc: 'Display JARM fingerprint' },
                { key: 'responseTime', label: 'Response Time (-rt)', desc: 'Display response time' },
                { key: 'lineCount', label: 'Line Count (-lc)', desc: 'Display body line count' },
                { key: 'wordCount', label: 'Word Count (-wc)', desc: 'Display body word count' },
                { key: 'method', label: 'Method (-method)', desc: 'Display HTTP method' },
                { key: 'websocket', label: 'WebSocket (-ws)', desc: 'Display WebSocket support' },
                { key: 'ip', label: 'IP (-ip)', desc: 'Display host IP address' },
                { key: 'cname', label: 'CNAME (-cname)', desc: 'Display host CNAME' },
                { key: 'asn', label: 'ASN (-asn)', desc: 'Display ASN information' },
                { key: 'cdn', label: 'CDN (-cdn)', desc: 'Display CDN/WAF in use' },
                { key: 'probe', label: 'Probe (-probe)', desc: 'Display probe status' },
              ].map(({ key, label, desc }) => (
                <Col md={4} key={key} className="mb-2">
                  <Form.Check
                    type="switch"
                    id={`probe-${key}`}
                    label={<span className="text-white">{label}</span>}
                    checked={config.probes[key]}
                    onChange={(e) => updateProbe(key, e.target.checked)}
                  />
                  <Form.Text className="text-muted" style={{ fontSize: '0.75em' }}>{desc}</Form.Text>
                </Col>
              ))}
            </Row>
          </Tab>

          <Tab eventKey="matchers" title="Matchers">
            <p className="text-muted mb-3">Configure response matchers to include only matching results.</p>
            <Row className="mb-3">
              <Col md={12}>
                <Form.Label className="text-white">Match Status Codes (-mc)</Form.Label>
                <Form.Control
                  as="textarea"
                  rows={2}
                  value={config.matchCodes}
                  onChange={(e) => setConfig(prev => ({ ...prev, matchCodes: e.target.value }))}
                  placeholder="Comma-separated status codes (e.g. 200,301,302,403)"
                />
                <Form.Text className="text-muted">Leave empty to match all status codes</Form.Text>
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Match Content Length (-ml)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchers.matchLength}
                  onChange={(e) => updateMatcher('matchLength', e.target.value)}
                  placeholder="e.g. 100,102"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">Match Line Count (-mlc)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchers.matchLineCount}
                  onChange={(e) => updateMatcher('matchLineCount', e.target.value)}
                  placeholder="e.g. 423,532"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Match Word Count (-mwc)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchers.matchWordCount}
                  onChange={(e) => updateMatcher('matchWordCount', e.target.value)}
                  placeholder="e.g. 43,55"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">Match Favicon (-mfc)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchers.matchFavicon}
                  onChange={(e) => updateMatcher('matchFavicon', e.target.value)}
                  placeholder="Favicon hash"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Match String (-ms)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchers.matchString}
                  onChange={(e) => updateMatcher('matchString', e.target.value)}
                  placeholder="e.g. admin"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">Match Regex (-mr)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchers.matchRegex}
                  onChange={(e) => updateMatcher('matchRegex', e.target.value)}
                  placeholder="e.g. admin.*panel"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Match CDN (-mcdn)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchers.matchCdn}
                  onChange={(e) => updateMatcher('matchCdn', e.target.value)}
                  placeholder="e.g. cloudfront, fastly"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">Match Response Time (-mrt)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchers.matchResponseTime}
                  onChange={(e) => updateMatcher('matchResponseTime', e.target.value)}
                  placeholder="e.g. < 1"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={12}>
                <Form.Label className="text-white">Match Condition (-mdc)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchers.matchCondition}
                  onChange={(e) => updateMatcher('matchCondition', e.target.value)}
                  placeholder="DSL expression condition"
                />
              </Col>
            </Row>
          </Tab>

          <Tab eventKey="filters" title="Filters">
            <p className="text-muted mb-3">Configure response filters to exclude matching results.</p>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Filter Status Codes (-fc)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filters.filterCode}
                  onChange={(e) => updateFilter('filterCode', e.target.value)}
                  placeholder="e.g. 403,401"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">Filter Content Length (-fl)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filters.filterLength}
                  onChange={(e) => updateFilter('filterLength', e.target.value)}
                  placeholder="e.g. 23,33"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Filter Line Count (-flc)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filters.filterLineCount}
                  onChange={(e) => updateFilter('filterLineCount', e.target.value)}
                  placeholder="e.g. 423,532"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">Filter Word Count (-fwc)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filters.filterWordCount}
                  onChange={(e) => updateFilter('filterWordCount', e.target.value)}
                  placeholder="e.g. 423,532"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Filter String (-fs)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filters.filterString}
                  onChange={(e) => updateFilter('filterString', e.target.value)}
                  placeholder="e.g. admin"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">Filter Regex (-fe)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filters.filterRegex}
                  onChange={(e) => updateFilter('filterRegex', e.target.value)}
                  placeholder="e.g. admin"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Filter CDN (-fcdn)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filters.filterCdn}
                  onChange={(e) => updateFilter('filterCdn', e.target.value)}
                  placeholder="e.g. cloudfront, fastly"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">Filter Response Time (-frt)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filters.filterResponseTime}
                  onChange={(e) => updateFilter('filterResponseTime', e.target.value)}
                  placeholder="e.g. > 1"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Filter Condition (-fdc)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filters.filterCondition}
                  onChange={(e) => updateFilter('filterCondition', e.target.value)}
                  placeholder="DSL expression condition"
                />
              </Col>
              <Col md={6} className="d-flex align-items-end">
                <Form.Check
                  type="switch"
                  id="filter-duplicates"
                  label={<span className="text-white">Filter Duplicates (-fd)</span>}
                  checked={config.filters.filterDuplicates}
                  onChange={(e) => updateFilter('filterDuplicates', e.target.checked)}
                />
              </Col>
            </Row>
          </Tab>

          <Tab eventKey="extractors" title="Extractors">
            <p className="text-muted mb-3">Configure extractors to pull specific data from responses.</p>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Extract Regex (-er)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.extractors.extractRegex}
                  onChange={(e) => updateExtractor('extractRegex', e.target.value)}
                  placeholder="Regex pattern to extract"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">Extract Preset (-ep)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.extractors.extractPreset}
                  onChange={(e) => updateExtractor('extractPreset', e.target.value)}
                  placeholder="url, ipv4, mail"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={6}>
                <Form.Check
                  type="switch"
                  id="extract-fqdn"
                  label={<span className="text-white">Extract FQDNs (-efqdn)</span>}
                  checked={config.extractors.extractFqdn}
                  onChange={(e) => updateExtractor('extractFqdn', e.target.checked)}
                />
                <Form.Text className="text-muted">Extract domains and subdomains from response</Form.Text>
              </Col>
            </Row>
          </Tab>

          <Tab eventKey="misc" title="Miscellaneous">
            <p className="text-muted mb-3">Additional scan configuration options.</p>
            <Row className="mb-3">
              {[
                { key: 'followRedirects', label: 'Follow Redirects (-fr)', desc: 'Follow HTTP redirects' },
                { key: 'probeAllIps', label: 'Probe All IPs (-pa)', desc: 'Probe all IPs for same host' },
                { key: 'tlsProbe', label: 'TLS Probe (-tls-probe)', desc: 'Probe extracted TLS domains' },
                { key: 'cspProbe', label: 'CSP Probe (-csp-probe)', desc: 'Probe extracted CSP domains' },
                { key: 'tlsGrab', label: 'TLS Grab (-tls-grab)', desc: 'Perform TLS data grabbing' },
                { key: 'pipeline', label: 'Pipeline (-pipeline)', desc: 'Check HTTP1.1 pipeline support' },
                { key: 'http2', label: 'HTTP/2 (-http2)', desc: 'Check HTTP/2 support' },
                { key: 'vhost', label: 'VHost (-vhost)', desc: 'Check VHost support' },
                { key: 'noFallback', label: 'No Fallback (-nf)', desc: 'Display both HTTPS and HTTP' },
                { key: 'noFallbackScheme', label: 'No Fallback Scheme (-nfs)', desc: 'Probe with input scheme only' },
              ].map(({ key, label, desc }) => (
                <Col md={4} key={key} className="mb-2">
                  <Form.Check
                    type="switch"
                    id={`misc-${key}`}
                    label={<span className="text-white">{label}</span>}
                    checked={config.misc[key]}
                    onChange={(e) => updateMisc(key, e.target.checked)}
                  />
                  <Form.Text className="text-muted" style={{ fontSize: '0.75em' }}>{desc}</Form.Text>
                </Col>
              ))}
            </Row>

            <hr className="border-secondary" />
            <Row className="mb-3">
              <Col md={6}>
                <Form.Label className="text-white">Custom Headers (-H)</Form.Label>
                <Form.Control
                  as="textarea"
                  rows={2}
                  value={config.customHeaders}
                  onChange={(e) => setConfig(prev => ({ ...prev, customHeaders: e.target.value }))}
                  placeholder="One per line: Header-Name: Header-Value"
                />
              </Col>
              <Col md={6}>
                <Form.Label className="text-white">HTTP Proxy (-proxy)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.httpProxy}
                  onChange={(e) => setConfig(prev => ({ ...prev, httpProxy: e.target.value }))}
                  placeholder="e.g. http://127.0.0.1:8080"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={4}>
                <Form.Label className="text-white">Resolvers (-r)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.resolvers}
                  onChange={(e) => setConfig(prev => ({ ...prev, resolvers: e.target.value }))}
                  placeholder="Comma-separated resolvers"
                />
              </Col>
              <Col md={4}>
                <Form.Label className="text-white">Path (-path)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.path}
                  onChange={(e) => setConfig(prev => ({ ...prev, path: e.target.value }))}
                  placeholder="Path(s) to probe"
                />
              </Col>
              <Col md={4}>
                <Form.Label className="text-white">Request Methods (-x)</Form.Label>
                <Form.Control
                  type="text"
                  value={config.requestMethods}
                  onChange={(e) => setConfig(prev => ({ ...prev, requestMethods: e.target.value }))}
                  placeholder="e.g. GET,POST or 'all'"
                />
              </Col>
            </Row>
            <Row className="mb-3">
              <Col md={12}>
                <Form.Label className="text-white">Request Body (-body)</Form.Label>
                <Form.Control
                  as="textarea"
                  rows={2}
                  value={config.body}
                  onChange={(e) => setConfig(prev => ({ ...prev, body: e.target.value }))}
                  placeholder="POST body to include"
                />
              </Col>
            </Row>

            <hr className="border-secondary" />
            <h6 className="text-white mb-3">Headless Browser</h6>
            <Row className="mb-3">
              <Col md={4}>
                <Form.Check
                  type="switch"
                  id="headless-screenshot"
                  label={<span className="text-white">Screenshot (-ss)</span>}
                  checked={config.headless.screenshot}
                  onChange={(e) => updateHeadless('screenshot', e.target.checked)}
                />
              </Col>
              <Col md={4}>
                <Form.Label className="text-white">Screenshot Timeout (-st)</Form.Label>
                <Form.Control
                  type="number"
                  min="1"
                  max="300"
                  value={config.headless.screenshotTimeout}
                  onChange={(e) => updateHeadless('screenshotTimeout', parseInt(e.target.value, 10) || 10)}
                  disabled={!config.headless.screenshot}
                />
              </Col>
            </Row>
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={handleReset}>Reset to Defaults</Button>
        <Button variant="secondary" onClick={handleClose}>Cancel</Button>
        <Button variant="danger" onClick={handleSave}>Save Configuration</Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ConfigureHttpxModal;
