import { useState, useEffect } from 'react';
import { Modal, Button, Form, Alert, Spinner } from 'react-bootstrap';

export const ArjunConfigModal = ({ show, handleClose, activeTarget }) => {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [config, setConfig] = useState({
    method: 'GET',
    headers: [],
    threads: 5,
    delay: 0,
    timeout: 10,
    chunkSize: 500,
    wordlist: '',
    passiveMode: false,
    stableDetection: true,
    jsonOutput: true,
    includeParams: '',
    excludeParams: ''
  });

  useEffect(() => {
    if (show && activeTarget) {
      loadConfig();
    }
  }, [show, activeTarget]);

  const loadConfig = async () => {
    if (!activeTarget) return;

    setLoading(true);
    setError('');

    try {
      const response = await fetch(`/api/arjun-config/${activeTarget.id}`);

      if (response.ok) {
        const data = await response.json();
        if (data && Object.keys(data).length > 0) {
          setConfig(prev => ({ ...prev, ...data }));
        }
      }
    } catch (error) {
      console.error('Error loading Arjun config:', error);
      setError('Failed to load configuration');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!activeTarget) return;

    setSaving(true);
    setError('');
    setSuccess('');

    try {
      const response = await fetch(`/api/arjun-config/${activeTarget.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });

      if (response.ok) {
        setSuccess('Configuration saved successfully');
        setTimeout(() => {
          setSuccess('');
          handleClose();
        }, 1500);
      } else {
        setError('Failed to save configuration');
      }
    } catch (error) {
      console.error('Error saving Arjun config:', error);
      setError('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const addHeader = () => {
    setConfig(prev => ({
      ...prev,
      headers: [...prev.headers, { key: '', value: '' }]
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
      headers: prev.headers.map((header, i) =>
        i === index ? { ...header, [field]: value } : header
      )
    }));
  };

  return (
    <Modal show={show} onHide={handleClose} size="lg" data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-gear me-2"></i>
          Arjun Configuration
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {loading ? (
          <div className="text-center py-4">
            <Spinner animation="border" variant="danger" />
          </div>
        ) : (
          <>
            {error && <Alert variant="danger">{error}</Alert>}
            {success && <Alert variant="success">{success}</Alert>}

            <Form>
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
                </Form.Select>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Threads</Form.Label>
                <Form.Control
                  type="number"
                  value={config.threads}
                  onChange={(e) => setConfig({ ...config, threads: parseInt(e.target.value) || 5 })}
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Delay (ms)</Form.Label>
                <Form.Control
                  type="number"
                  value={config.delay}
                  onChange={(e) => setConfig({ ...config, delay: parseInt(e.target.value) || 0 })}
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Timeout (seconds)</Form.Label>
                <Form.Control
                  type="number"
                  value={config.timeout}
                  onChange={(e) => setConfig({ ...config, timeout: parseInt(e.target.value) || 10 })}
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Chunk Size</Form.Label>
                <Form.Control
                  type="number"
                  value={config.chunkSize}
                  onChange={(e) => setConfig({ ...config, chunkSize: parseInt(e.target.value) || 500 })}
                  data-bs-theme="dark"
                />
                <Form.Text className="text-muted">
                  Number of parameters to test at once
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Check
                  type="checkbox"
                  label="Passive Mode"
                  checked={config.passiveMode}
                  onChange={(e) => setConfig({ ...config, passiveMode: e.target.checked })}
                  className="text-white"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Check
                  type="checkbox"
                  label="Stable Detection"
                  checked={config.stableDetection}
                  onChange={(e) => setConfig({ ...config, stableDetection: e.target.checked })}
                  className="text-white"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">
                  Custom Headers
                  <Button
                    variant="outline-success"
                    size="sm"
                    className="ms-2"
                    onClick={addHeader}
                  >
                    Add Header
                  </Button>
                </Form.Label>
                {config.headers.map((header, index) => (
                  <div key={index} className="d-flex gap-2 mb-2">
                    <Form.Control
                      type="text"
                      placeholder="Header Key"
                      value={header.key}
                      onChange={(e) => updateHeader(index, 'key', e.target.value)}
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
                  </div>
                ))}
              </Form.Group>
            </Form>
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Cancel
        </Button>
        <Button
          variant="danger"
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? <Spinner animation="border" size="sm" /> : 'Save Configuration'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
};
