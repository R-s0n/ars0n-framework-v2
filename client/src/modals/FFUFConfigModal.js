import { useState, useEffect, useRef } from 'react';
import { Modal, Button, Form, Tab, Tabs, Alert, Spinner, Badge, InputGroup } from 'react-bootstrap';

export const FFUFConfigModal = ({ 
  show, 
  handleClose, 
  activeTarget 
}) => {
  const [activeTab, setActiveTab] = useState('endpoints');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [uploadingWordlist, setUploadingWordlist] = useState(false);
  const fileInputRef = useRef(null);

  const [config, setConfig] = useState({
    url: activeTarget?.scope_target || '',
    method: 'GET',
    headers: [],
    cookies: '',
    postData: '',

    // What the single Scan button runs. Endpoints on, the other two opt-in: they are a different
    // kind of traffic and worth choosing deliberately.
    fuzzEndpoints: true,
    fuzzHeaders: false,
    fuzzCookies: false,
    headerWordlistId: 'builtin-headers',
    cookieWordlistId: 'builtin-cookies',
    headerFuzzValue: 'ars0nprobe',
    cookieFuzzValue: 'ars0nprobe',

    http2: false,
    // On, because a target that redirects everything to a login page reports nothing useful
    // otherwise. It is a switch on the Advanced tab when that is the wrong call.
    followRedirects: true,
    timeout: 10,

    wordlistId: 'builtin-default',
    customWordlist: null,
    wordlistName: '',
    extensions: '',
    keyword: 'FUZZ',
    
    matchStatusCodes: '200-299,301,302,307,401,403,405,500',
    matchLines: '',
    matchSize: '',
    matchWords: '',
    matchRegex: '',
    matcherMode: 'or',
    
    filterStatusCodes: '',
    filterLines: '',
    filterSize: '',
    filterWords: '',
    filterRegex: '',
    filterMode: 'or',
    
    threads: 40,
    rateLimit: '',
    delay: '',
    maxTime: '',
    verbose: false,
    // On by default. Without it, a target that answers every path with the same shell returns the
    // entire wordlist as "findings"; with it, only responses that differ are reported.
    autoCalibrate: true,
    recursion: false,
    recursionDepth: '',
    
    proxyURL: '',
    clientCert: '',
    clientKey: '',
    
    // Off. `-sa` aborts the whole run on the first spurious error, which against anything behind a
    // WAF means the scan ends in the first few seconds and reports nothing.
    stopOnAll: false,
    stopOn403: false,
    stopOnErrors: false
  });

  const [availableWordlists, setAvailableWordlists] = useState([]);

  useEffect(() => {
    if (show && activeTarget) {
      loadConfig();
      loadAvailableWordlists();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    if (activeTarget?.scope_target) {
      const targetUrl = activeTarget.scope_target.endsWith('/') 
        ? `${activeTarget.scope_target}FUZZ`
        : `${activeTarget.scope_target}/FUZZ`;
      setConfig(prev => ({ ...prev, url: targetUrl }));
    }
  }, [activeTarget]);

  const loadConfig = async () => {
    if (!activeTarget) return;

    setLoading(true);
    setError('');

    try {
      const response = await fetch(
        `/api/ffuf-config/${activeTarget.id}`
      );

      if (response.ok) {
        const data = await response.json();
        if (data && Object.keys(data).length > 0) {
          // A null in the stored config must not overwrite a working default. Go marshals an empty
          // slice as null, so `headers: null` arrived here, replaced the default `[]`, and the
          // first .map() on it threw and unmounted the modal: that is why Configure opened blank.
          const merged = { ...data };
          Object.keys(merged).forEach((k) => {
            if (merged[k] === null || merged[k] === undefined) delete merged[k];
          });
          // An empty wordlist id is never a choice anyone made: it is what a config written by the
          // WAF Probe's Apply looks like. Letting it through leaves Save permanently disabled on a
          // target the operator never configured by hand.
          if (!merged.wordlistId) delete merged.wordlistId;
          if (!merged.headerWordlistId) delete merged.headerWordlistId;
          if (!merged.cookieWordlistId) delete merged.cookieWordlistId;
          setConfig(prev => ({
            ...prev,
            ...merged,
            url: data.url || (activeTarget.scope_target
              ? (activeTarget.scope_target.endsWith('/')
                ? `${activeTarget.scope_target}FUZZ`
                : `${activeTarget.scope_target}/FUZZ`)
              : '')
          }));
        } else {
          const targetUrl = activeTarget.scope_target 
            ? (activeTarget.scope_target.endsWith('/') 
              ? `${activeTarget.scope_target}FUZZ`
              : `${activeTarget.scope_target}/FUZZ`)
            : '';
          setConfig(prev => ({ ...prev, url: targetUrl }));
        }
      }
    } catch (error) {
      console.error('Error loading FFUF config:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadAvailableWordlists = async () => {
    try {
      const response = await fetch(
        `/api/ffuf-wordlists`
      );

      if (response.ok) {
        const data = await response.json();
        setAvailableWordlists(data || []);
        
        if (data && data.length > 0 && !config.wordlistId) {
          setConfig(prev => ({
            ...prev,
            wordlistId: data[0].id,
            wordlistName: data[0].name
          }));
        }
      }
    } catch (error) {
      console.error('Error loading wordlists:', error);
    }
  };

  const handleSaveConfig = async () => {
    if (!activeTarget) return;

    setSaving(true);
    setError('');
    setSuccess('');

    try {
      const sanitizedConfig = {
        ...config,
        threads: typeof config.threads === 'number' ? config.threads : (parseInt(config.threads) || 40),
        rateLimit: typeof config.rateLimit === 'number' ? config.rateLimit : (parseInt(config.rateLimit) || 0),
        timeout: typeof config.timeout === 'number' ? config.timeout : (parseInt(config.timeout) || 10),
        maxTime: typeof config.maxTime === 'number' ? config.maxTime : (parseInt(config.maxTime) || 0),
        recursionDepth: typeof config.recursionDepth === 'number' ? config.recursionDepth : (parseInt(config.recursionDepth) || 0),
      };

      const response = await fetch(
        `/api/ffuf-config/${activeTarget.id}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(sanitizedConfig)
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save configuration');
      }

      setSuccess('Configuration saved successfully!');
      setTimeout(() => {
        handleClose();
      }, 500);
    } catch (error) {
      console.error('Error saving config:', error);
      setError('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setUploadingWordlist(true);
    setError('');

    try {
      const formData = new FormData();
      formData.append('wordlist', file);
      formData.append('name', file.name);

      const response = await fetch(
        `/api/ffuf-wordlists/upload`,
        {
          method: 'POST',
          body: formData
        }
      );

      if (!response.ok) {
        throw new Error('Failed to upload wordlist');
      }

      const uploadedWordlist = await response.json();
      await loadAvailableWordlists();
      
      setConfig(prev => ({
        ...prev,
        wordlistId: uploadedWordlist.id,
        wordlistName: uploadedWordlist.name
      }));

      setSuccess('Wordlist uploaded successfully!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (error) {
      console.error('Error uploading wordlist:', error);
      setError('Failed to upload wordlist');
    } finally {
      setUploadingWordlist(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const addHeader = () => {
    setConfig(prev => ({
      ...prev,
      headers: [...(prev.headers || []), { name: '', value: '' }]
    }));
  };

  const removeHeader = (index) => {
    setConfig(prev => ({
      ...prev,
      headers: (prev.headers || []).filter((_, i) => i !== index)
    }));
  };

  const updateHeader = (index, field, value) => {
    setConfig(prev => ({
      ...prev,
      headers: (prev.headers || []).map((h, i) => 
        i === index ? { ...h, [field]: value } : h
      )
    }));
  };

  if (loading) {
    return (
      <Modal show={show} onHide={handleClose} size="xl" data-bs-theme="dark">
        <Modal.Body className="text-center py-5">
          <Spinner animation="border" variant="danger" />
          <p className="text-white mt-3">Loading configuration...</p>
        </Modal.Body>
      </Modal>
    );
  }

  return (
    <Modal 
      show={show} 
      onHide={handleClose} 
      size="xl" 
      data-bs-theme="dark"
      scrollable
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-gear me-2" />
          FFUF Configuration
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        {success && (
          <Alert variant="success" dismissible onClose={() => setSuccess('')}>
            {success}
          </Alert>
        )}

        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="mb-3"
        >
          <Tab eventKey="endpoints" title={`Endpoints${config.fuzzEndpoints ? ' •' : ''}`}>
            <Form>
              <Form.Check
                type="switch"
                id="ffuf-fuzz-endpoints"
                className="mb-3"
                checked={!!config.fuzzEndpoints}
                onChange={(e) => setConfig({ ...config, fuzzEndpoints: e.target.checked })}
                label={<span className="text-white">Fuzz paths during a scan</span>}
              />
              <Form.Group className="mb-3">
                <Form.Label className="text-white">Target URL <Badge bg="danger">Required</Badge></Form.Label>
                <Form.Control
                  type="text"
                  value={config.url}
                  onChange={(e) => setConfig({ ...config, url: e.target.value })}
                  placeholder="https://example.com/FUZZ"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  Put FUZZ wherever the wordlist should be injected. It is honored as written, so
                  <code className="mx-1">https://host/api/v1/FUZZ</code> fuzzes a subdirectory and
                  <code className="mx-1">https://host/s?q=FUZZ</code> fuzzes a query value. Leave it
                  and the scope target gets <code>/FUZZ</code> appended.
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Upload New Wordlist</Form.Label>
                <div className="d-flex gap-2 align-items-center">
                  <Form.Control
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileUpload}
                    accept=".txt,.list"
                    data-bs-theme="dark"
                    disabled={uploadingWordlist}
                  />
                  {uploadingWordlist && (
                    <Spinner animation="border" size="sm" variant="danger" />
                  )}
                </div>
                <Form.Text className="text-white-50">
                  Upload a text file with one entry per line
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Select Wordlist <Badge bg="danger">Required</Badge></Form.Label>
                <Form.Select
                  value={config.wordlistId}
                  onChange={(e) => {
                    const selected = availableWordlists.find(w => w.id === e.target.value);
                    setConfig({ 
                      ...config, 
                      wordlistId: e.target.value,
                      wordlistName: selected ? selected.name : ''
                    });
                  }}
                  data-bs-theme="dark"
                >
                  {availableWordlists.length === 0 && (
                    <option value="">Loading wordlists...</option>
                  )}
                  {availableWordlists.length > 0 && !config.wordlistId && (
                    <option value="">-- Select a wordlist --</option>
                  )}
                  {availableWordlists.map((wordlist) => (
                    <option key={wordlist.id} value={wordlist.id}>
                      {wordlist.name} ({wordlist.size} entries)
                    </option>
                  ))}
                </Form.Select>
                {config.wordlistId?.startsWith('builtin-') && (
                  <Form.Text className="text-success">
                    Using a built-in wordlist. You can upload a custom wordlist above for more specific testing.
                  </Form.Text>
                )}
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">FUZZ Keyword</Form.Label>
                <Form.Control
                  type="text"
                  value={config.keyword}
                  onChange={(e) => setConfig({ ...config, keyword: e.target.value })}
                  placeholder="FUZZ"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  The keyword to replace with wordlist entries
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">File Extensions</Form.Label>
                <Form.Control
                  type="text"
                  value={config.extensions}
                  onChange={(e) => setConfig({ ...config, extensions: e.target.value })}
                  placeholder=".php,.html,.asp,.aspx"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  Comma-separated list. Will be appended to FUZZ keyword.
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">HTTP Method</Form.Label>
                <Form.Select
                  value={config.method}
                  onChange={(e) => setConfig({ ...config, method: e.target.value })}
                  data-bs-theme="dark"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                  <option value="HEAD">HEAD</option>
                  <option value="OPTIONS">OPTIONS</option>
                </Form.Select>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Custom Headers</Form.Label>
                {/* Guarded: a stored config with no headers comes back as null, and one throw here
                    unmounts the whole modal, which is what "Configure opens blank" was. */}
                {(config.headers || []).map((header, index) => (
                  <InputGroup key={index} className="mb-2">
                    <Form.Control
                      type="text"
                      placeholder="Header Name"
                      value={header.name}
                      onChange={(e) => updateHeader(index, 'name', e.target.value)}
                      data-bs-theme="dark"
                    />
                    <Form.Control
                      type="text"
                      placeholder="Header Value"
                      value={header.value}
                      onChange={(e) => updateHeader(index, 'value', e.target.value)}
                      data-bs-theme="dark"
                    />
                    <Button 
                      variant="outline-danger" 
                      onClick={() => removeHeader(index)}
                    >
                      ×
                    </Button>
                  </InputGroup>
                ))}
                <Button variant="outline-success" size="sm" onClick={addHeader}>
                  <i className="bi bi-plus me-1" />
                  Add Header
                </Button>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Cookies</Form.Label>
                <Form.Control
                  type="text"
                  value={config.cookies}
                  onChange={(e) => setConfig({ ...config, cookies: e.target.value })}
                  placeholder="NAME1=VALUE1; NAME2=VALUE2"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">POST Data</Form.Label>
                <Form.Control
                  as="textarea"
                  rows={3}
                  value={config.postData}
                  onChange={(e) => setConfig({ ...config, postData: e.target.value })}
                  placeholder='{"key": "FUZZ"}'
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  For POST/PUT requests. Can use FUZZ keyword.
                </Form.Text>
              </Form.Group>

              <Form.Check
                type="checkbox"
                label="Use HTTP/2"
                checked={config.http2}
                onChange={(e) => setConfig({ ...config, http2: e.target.checked })}
                className="text-white mb-2"
              />

              <Form.Check
                type="checkbox"
                label="Follow Redirects"
                checked={config.followRedirects}
                onChange={(e) => setConfig({ ...config, followRedirects: e.target.checked })}
                className="text-white"
              />
            </Form>
          </Tab>

          <Tab eventKey="headers" title={`Headers${config.fuzzHeaders ? ' •' : ''}`}>
            <Alert variant="dark" className="border-secondary">
              <i className="bi bi-info-circle me-2" />
              Sends every name in the wordlist as a request header against one unchanging URL, and
              reports the ones whose response differs. Because the URL never changes, this works on
              targets where path fuzzing cannot: a single-page app returns the same shell for every
              path, but it still behaves differently when it honors <code>X-Original-URL</code> or
              a debug header.
            </Alert>
            <Form>
              <Form.Check
                type="switch"
                id="ffuf-fuzz-headers"
                className="mb-3"
                checked={!!config.fuzzHeaders}
                onChange={(e) => setConfig({ ...config, fuzzHeaders: e.target.checked })}
                label={<span className="text-white">Fuzz header names during a scan</span>}
              />
              <Form.Group className="mb-3">
                <Form.Label className="text-white">Header Wordlist</Form.Label>
                <Form.Select
                  value={config.headerWordlistId}
                  onChange={(e) => setConfig({ ...config, headerWordlistId: e.target.value })}
                  data-bs-theme="dark"
                >
                  <option value="builtin-headers">Built-in header names ({'~'}140 entries)</option>
                  {availableWordlists.filter((w) => !String(w.id).startsWith('builtin-')).map((w) => (
                    <option key={w.id} value={w.id}>{w.name}</option>
                  ))}
                </Form.Select>
              </Form.Group>
              <Form.Group className="mb-3">
                <Form.Label className="text-white">Header Probe Value</Form.Label>
                <Form.Control
                  type="text"
                  value={config.headerFuzzValue}
                  onChange={(e) => setConfig({ ...config, headerFuzzValue: e.target.value })}
                  placeholder="ars0nprobe"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  The value paired with each fuzzed header name. A unique canary makes a reflected
                  or honored header easy to spot in the response.
                </Form.Text>
              </Form.Group>
            </Form>
          </Tab>

          <Tab eventKey="cookies" title={`Cookies${config.fuzzCookies ? ' •' : ''}`}>
            <Alert variant="dark" className="border-secondary">
              <i className="bi bi-info-circle me-2" />
              Sends every name in the wordlist as a cookie against one unchanging URL and reports
              the ones that change the response. This is how you find the <code>debug</code>,
              <code>is_admin</code> or feature-flag cookies an application reads but never sets.
            </Alert>
            <Form>
              <Form.Check
                type="switch"
                id="ffuf-fuzz-cookies"
                className="mb-3"
                checked={!!config.fuzzCookies}
                onChange={(e) => setConfig({ ...config, fuzzCookies: e.target.checked })}
                label={<span className="text-white">Fuzz cookie names during a scan</span>}
              />
              <Form.Group className="mb-3">
                <Form.Label className="text-white">Cookie Wordlist</Form.Label>
                <Form.Select
                  value={config.cookieWordlistId}
                  onChange={(e) => setConfig({ ...config, cookieWordlistId: e.target.value })}
                  data-bs-theme="dark"
                >
                  <option value="builtin-cookies">Built-in cookie names ({'~'}180 entries)</option>
                  {availableWordlists.filter((w) => !String(w.id).startsWith('builtin-')).map((w) => (
                    <option key={w.id} value={w.id}>{w.name}</option>
                  ))}
                </Form.Select>
                <Form.Text className="text-white-50">
                  The saved session cookie is not sent during this phase. Two values for one cookie
                  name would make any difference in the response unattributable.
                </Form.Text>
              </Form.Group>
              <Form.Group className="mb-3">
                <Form.Label className="text-white">Cookie Probe Value</Form.Label>
                <Form.Control
                  type="text"
                  value={config.cookieFuzzValue}
                  onChange={(e) => setConfig({ ...config, cookieFuzzValue: e.target.value })}
                  placeholder="ars0nprobe"
                  data-bs-theme="dark"
                />
              </Form.Group>
            </Form>
          </Tab>

          <Tab eventKey="matchers" title="Matchers">
            <Form>
              <Form.Group className="mb-3">
                <Form.Label className="text-white">Match Status Codes</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchStatusCodes}
                  onChange={(e) => setConfig({ ...config, matchStatusCodes: e.target.value })}
                  placeholder="200-299,301,302,307,401,403,405,500"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  Comma-separated status codes or ranges. Use "all" for everything.
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Match Lines</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchLines}
                  onChange={(e) => setConfig({ ...config, matchLines: e.target.value })}
                  placeholder="e.g., 100 or 50-100"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Match Response Size</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchSize}
                  onChange={(e) => setConfig({ ...config, matchSize: e.target.value })}
                  placeholder="e.g., 1024 or 500-2000"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Match Words</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchWords}
                  onChange={(e) => setConfig({ ...config, matchWords: e.target.value })}
                  placeholder="e.g., 50 or 20-100"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Match Regex</Form.Label>
                <Form.Control
                  type="text"
                  value={config.matchRegex}
                  onChange={(e) => setConfig({ ...config, matchRegex: e.target.value })}
                  placeholder="Regular expression pattern"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Matcher Mode</Form.Label>
                <Form.Select
                  value={config.matcherMode}
                  onChange={(e) => setConfig({ ...config, matcherMode: e.target.value })}
                  data-bs-theme="dark"
                >
                  <option value="or">OR (match any condition)</option>
                  <option value="and">AND (match all conditions)</option>
                </Form.Select>
              </Form.Group>
            </Form>
          </Tab>

          <Tab eventKey="filters" title="Filters">
            <Form>
              <Form.Group className="mb-3">
                <Form.Label className="text-white">Filter Status Codes</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filterStatusCodes}
                  onChange={(e) => setConfig({ ...config, filterStatusCodes: e.target.value })}
                  placeholder="e.g., 404,500"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Filter Lines</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filterLines}
                  onChange={(e) => setConfig({ ...config, filterLines: e.target.value })}
                  placeholder="e.g., 0 or 10-50"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Filter Response Size</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filterSize}
                  onChange={(e) => setConfig({ ...config, filterSize: e.target.value })}
                  placeholder="e.g., 42 or 100-500"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Filter Words</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filterWords}
                  onChange={(e) => setConfig({ ...config, filterWords: e.target.value })}
                  placeholder="e.g., 0 or 5-20"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Filter Regex</Form.Label>
                <Form.Control
                  type="text"
                  value={config.filterRegex}
                  onChange={(e) => setConfig({ ...config, filterRegex: e.target.value })}
                  placeholder="Regular expression pattern"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Filter Mode</Form.Label>
                <Form.Select
                  value={config.filterMode}
                  onChange={(e) => setConfig({ ...config, filterMode: e.target.value })}
                  data-bs-theme="dark"
                >
                  <option value="or">OR (filter if any condition matches)</option>
                  <option value="and">AND (filter if all conditions match)</option>
                </Form.Select>
              </Form.Group>
            </Form>
          </Tab>

          <Tab eventKey="advanced" title="Advanced">
            <Form>
              <Form.Group className="mb-3">
                <Form.Label className="text-white">Number of Threads</Form.Label>
                <Form.Control
                  type="number"
                  value={config.threads}
                  onChange={(e) => {
                    const val = e.target.value === '' ? '' : parseInt(e.target.value);
                    setConfig({ ...config, threads: val });
                  }}
                  onBlur={(e) => {
                    if (e.target.value === '' || parseInt(e.target.value) < 1) {
                      setConfig({ ...config, threads: 40 });
                    }
                  }}
                  min="1"
                  max="200"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  Number of concurrent requests (default: 40)
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Rate Limit (req/sec)</Form.Label>
                <Form.Control
                  type="number"
                  value={config.rateLimit}
                  onChange={(e) => {
                    const val = e.target.value === '' ? '' : parseInt(e.target.value);
                    setConfig({ ...config, rateLimit: val });
                  }}
                  onBlur={(e) => {
                    if (e.target.value === '' || parseInt(e.target.value) < 0) {
                      setConfig({ ...config, rateLimit: 0 });
                    }
                  }}
                  min="0"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  0 = no limit. Leave empty to reset to 0.
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Delay Between Requests</Form.Label>
                <Form.Control
                  type="text"
                  value={config.delay}
                  onChange={(e) => setConfig({ ...config, delay: e.target.value })}
                  placeholder="0.1 or 0.1-2.0 (leave empty for none)"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  Seconds or range (e.g., "0.1" or "0.1-2.0"). Leave empty for no delay.
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Timeout (seconds)</Form.Label>
                <Form.Control
                  type="number"
                  value={config.timeout}
                  onChange={(e) => {
                    const val = e.target.value === '' ? '' : parseInt(e.target.value);
                    setConfig({ ...config, timeout: val });
                  }}
                  onBlur={(e) => {
                    if (e.target.value === '' || parseInt(e.target.value) < 1) {
                      setConfig({ ...config, timeout: 10 });
                    }
                  }}
                  min="1"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Maximum Time (seconds)</Form.Label>
                <Form.Control
                  type="number"
                  value={config.maxTime}
                  onChange={(e) => {
                    const val = e.target.value === '' ? '' : parseInt(e.target.value);
                    setConfig({ ...config, maxTime: val });
                  }}
                  onBlur={(e) => {
                    if (e.target.value === '' || parseInt(e.target.value) < 0) {
                      setConfig({ ...config, maxTime: 0 });
                    }
                  }}
                  min="0"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  0 = no limit. Max running time for the entire scan. Leave empty to reset to 0.
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Proxy URL</Form.Label>
                <Form.Control
                  type="text"
                  value={config.proxyURL}
                  onChange={(e) => setConfig({ ...config, proxyURL: e.target.value })}
                  placeholder="http://127.0.0.1:8080 or socks5://127.0.0.1:8080"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Check
                type="checkbox"
                label="Verbose Output"
                checked={config.verbose}
                onChange={(e) => setConfig({ ...config, verbose: e.target.checked })}
                className="text-white mb-2"
              />

              <Form.Check
                type="checkbox"
                label="Auto-Calibrate Filters"
                checked={config.autoCalibrate}
                onChange={(e) => setConfig({ ...config, autoCalibrate: e.target.checked })}
                className="text-white mb-2"
              />

              <Form.Check
                type="checkbox"
                label="Recursive Scanning"
                checked={config.recursion}
                onChange={(e) => setConfig({ ...config, recursion: e.target.checked })}
                className="text-white mb-2"
              />

              <hr className="my-4" style={{ borderColor: '#444' }} />
              
              <h6 className="text-white mb-3">Error Handling</h6>
              
              <Form.Check
                type="checkbox"
                label="Stop on All Errors (-sa) - Recommended"
                checked={config.stopOnAll}
                onChange={(e) => setConfig({ ...config, stopOnAll: e.target.checked })}
                className="text-white mb-2"
              />
              <Form.Text className="text-white-50 d-block mb-3">
                Stops scanning on all error cases. Includes -sf and -se. Prevents wasting time on blocked/failing scans.
              </Form.Text>

              <Form.Check
                type="checkbox"
                label="Stop on 403 Forbidden (-sf)"
                checked={config.stopOn403}
                onChange={(e) => setConfig({ ...config, stopOn403: e.target.checked })}
                disabled={config.stopOnAll}
                className="text-white mb-2"
              />
              <Form.Text className="text-white-50 d-block mb-3">
                Stops when more than 95% of responses return 403 Forbidden. Useful when target is blocking requests.
              </Form.Text>

              <Form.Check
                type="checkbox"
                label="Stop on Spurious Errors (-se)"
                checked={config.stopOnErrors}
                onChange={(e) => setConfig({ ...config, stopOnErrors: e.target.checked })}
                disabled={config.stopOnAll}
                className="text-white mb-2"
              />
              <Form.Text className="text-white-50 d-block mb-3">
                Stops when spurious errors are detected during scanning.
              </Form.Text>

              {config.recursion && (
                <Form.Group className="mb-3 ms-4">
                  <Form.Label className="text-white">Recursion Depth</Form.Label>
                  <Form.Control
                    type="number"
                    value={config.recursionDepth}
                    onChange={(e) => {
                      const val = e.target.value === '' ? '' : parseInt(e.target.value);
                      setConfig({ ...config, recursionDepth: val });
                    }}
                    onBlur={(e) => {
                      if (e.target.value === '' || parseInt(e.target.value) < 0) {
                        setConfig({ ...config, recursionDepth: 0 });
                      }
                    }}
                    min="0"
                    data-bs-theme="dark"
                  />
                </Form.Group>
              )}
            </Form>
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Cancel
        </Button>
        <Button 
          variant="danger" 
          onClick={handleSaveConfig}
          disabled={saving || !config.url || !config.wordlistId}
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
  );
};

