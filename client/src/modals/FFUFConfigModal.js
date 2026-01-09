import { useState, useEffect, useRef } from 'react';
import { Modal, Button, Form, Tab, Tabs, Alert, Spinner, Badge, InputGroup } from 'react-bootstrap';

export const FFUFConfigModal = ({ 
  show, 
  handleClose, 
  activeTarget 
}) => {
  const [activeTab, setActiveTab] = useState('target');
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
    http2: false,
    followRedirects: false,
    timeout: 10,
    
    wordlistId: '',
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
    rateLimit: 0,
    delay: '',
    maxTime: 0,
    verbose: false,
    autoCalibrate: false,
    recursion: false,
    recursionDepth: 0,
    
    proxyURL: '',
    clientCert: '',
    clientKey: ''
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
      setConfig(prev => ({ ...prev, url: activeTarget.scope_target }));
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
          setConfig(prev => ({
            ...prev,
            ...data,
            url: activeTarget.scope_target || data.url
          }));
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
      const response = await fetch(
        `/api/ffuf-config/${activeTarget.id}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(config)
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save configuration');
      }

      setSuccess('Configuration saved successfully!');
      setTimeout(() => setSuccess(''), 3000);
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
      headers: [...prev.headers, { name: '', value: '' }]
    }));
  };

  const removeHeader = (index) => {
    setConfig(prev => ({
      ...prev,
      headers: prev.headers.filter((_, i) => i !== index)
    }));
  };

  const updateHeader = (index, field, value) => {
    setConfig(prev => ({
      ...prev,
      headers: prev.headers.map((h, i) => 
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
          <Tab eventKey="target" title="Target">
            <Form>
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
                  Use FUZZ keyword where you want to inject wordlist values
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
                {config.headers.map((header, index) => (
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

          <Tab eventKey="wordlist" title="Wordlist">
            <Form>
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
                  <option value="">-- Select a wordlist --</option>
                  {availableWordlists.map((wordlist) => (
                    <option key={wordlist.id} value={wordlist.id}>
                      {wordlist.name} ({wordlist.size} entries)
                    </option>
                  ))}
                </Form.Select>
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
                  onChange={(e) => setConfig({ ...config, threads: parseInt(e.target.value) || 40 })}
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
                  onChange={(e) => setConfig({ ...config, rateLimit: parseInt(e.target.value) || 0 })}
                  min="0"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  0 = no limit
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Delay Between Requests</Form.Label>
                <Form.Control
                  type="text"
                  value={config.delay}
                  onChange={(e) => setConfig({ ...config, delay: e.target.value })}
                  placeholder="0.1 or 0.1-2.0"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  Seconds or range (e.g., "0.1" or "0.1-2.0")
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Timeout (seconds)</Form.Label>
                <Form.Control
                  type="number"
                  value={config.timeout}
                  onChange={(e) => setConfig({ ...config, timeout: parseInt(e.target.value) || 10 })}
                  min="1"
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Maximum Time (seconds)</Form.Label>
                <Form.Control
                  type="number"
                  value={config.maxTime}
                  onChange={(e) => setConfig({ ...config, maxTime: parseInt(e.target.value) || 0 })}
                  min="0"
                  data-bs-theme="dark"
                />
                <Form.Text className="text-white-50">
                  0 = no limit. Max running time for the entire scan.
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

              {config.recursion && (
                <Form.Group className="mb-3 ms-4">
                  <Form.Label className="text-white">Recursion Depth</Form.Label>
                  <Form.Control
                    type="number"
                    value={config.recursionDepth}
                    onChange={(e) => setConfig({ ...config, recursionDepth: parseInt(e.target.value) || 0 })}
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

