import { useState, useEffect } from 'react';
import { Modal, Button, Form, Alert, Spinner } from 'react-bootstrap';

export const X8ConfigModal = ({ show, handleClose, activeTarget }) => {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [config, setConfig] = useState({
    method: 'GET',
    headers: [],
    bodyType: 'json',
    wordlist: '',
    maxDepth: 1,
    concurrency: 10,
    delay: 0,
    learnRequests: 9,
    verifyRequests: 3,
    checkReflection: true,
    disableColors: true,
    followRedirects: false,
    checkBooleans: true,
    valueSize: 5
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
      const response = await fetch(`/api/x8-config/${activeTarget.id}`);

      if (response.ok) {
        const data = await response.json();
        if (data && Object.keys(data).length > 0) {
          setConfig(prev => ({ ...prev, ...data }));
        }
      }
    } catch (error) {
      console.error('Error loading x8 config:', error);
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
      const response = await fetch(`/api/x8-config/${activeTarget.id}`, {
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
      console.error('Error saving x8 config:', error);
      setError('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal show={show} onHide={handleClose} size="lg" data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-gear me-2"></i>
          x8 Configuration
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
                <Form.Label className="text-white">Body Type</Form.Label>
                <Form.Select
                  value={config.bodyType}
                  onChange={(e) => setConfig({ ...config, bodyType: e.target.value })}
                  data-bs-theme="dark"
                >
                  <option value="json">JSON</option>
                  <option value="form">Form Data</option>
                  <option value="xml">XML</option>
                </Form.Select>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Concurrency</Form.Label>
                <Form.Control
                  type="number"
                  value={config.concurrency}
                  onChange={(e) => setConfig({ ...config, concurrency: parseInt(e.target.value) || 10 })}
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Learn Requests</Form.Label>
                <Form.Control
                  type="number"
                  value={config.learnRequests}
                  onChange={(e) => setConfig({ ...config, learnRequests: parseInt(e.target.value) || 9 })}
                  data-bs-theme="dark"
                />
                <Form.Text className="text-muted">
                  Number of requests to learn normal response behavior
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Verify Requests</Form.Label>
                <Form.Control
                  type="number"
                  value={config.verifyRequests}
                  onChange={(e) => setConfig({ ...config, verifyRequests: parseInt(e.target.value) || 3 })}
                  data-bs-theme="dark"
                />
                <Form.Text className="text-muted">
                  Number of requests to verify parameter detection
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Value Size</Form.Label>
                <Form.Control
                  type="number"
                  value={config.valueSize}
                  onChange={(e) => setConfig({ ...config, valueSize: parseInt(e.target.value) || 5 })}
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Check
                  type="checkbox"
                  label="Check Reflection Only"
                  checked={config.checkReflection}
                  onChange={(e) => setConfig({ ...config, checkReflection: e.target.checked })}
                  className="text-white"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Check
                  type="checkbox"
                  label="Check Boolean Values"
                  checked={config.checkBooleans}
                  onChange={(e) => setConfig({ ...config, checkBooleans: e.target.checked })}
                  className="text-white"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Check
                  type="checkbox"
                  label="Follow Redirects"
                  checked={config.followRedirects}
                  onChange={(e) => setConfig({ ...config, followRedirects: e.target.checked })}
                  className="text-white"
                />
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
