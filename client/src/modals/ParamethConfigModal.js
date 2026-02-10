import { useState, useEffect } from 'react';
import { Modal, Button, Form, Alert, Spinner } from 'react-bootstrap';

export const ParamethConfigModal = ({ show, handleClose, activeTarget }) => {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [config, setConfig] = useState({
    method: 'GET',
    headers: [],
    threads: 5,
    verbose: false,
    diff: 5,
    placeholder: 'test',
    wordlist: '',
    ignoreCodes: '',
    ignoreSizes: ''
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
      const response = await fetch(`/api/parameth-config/${activeTarget.id}`);

      if (response.ok) {
        const data = await response.json();
        if (data && Object.keys(data).length > 0) {
          setConfig(prev => ({ ...prev, ...data }));
        }
      }
    } catch (error) {
      console.error('Error loading parameth config:', error);
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
      const response = await fetch(`/api/parameth-config/${activeTarget.id}`, {
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
      console.error('Error saving parameth config:', error);
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
          parameth Configuration
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
                <Form.Label className="text-white">Diff Threshold</Form.Label>
                <Form.Control
                  type="number"
                  value={config.diff}
                  onChange={(e) => setConfig({ ...config, diff: parseInt(e.target.value) || 5 })}
                  data-bs-theme="dark"
                />
                <Form.Text className="text-muted">
                  Minimum response difference percentage to flag parameter
                </Form.Text>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Placeholder Value</Form.Label>
                <Form.Control
                  type="text"
                  value={config.placeholder}
                  onChange={(e) => setConfig({ ...config, placeholder: e.target.value })}
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Ignore Status Codes (comma-separated)</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="404,403"
                  value={config.ignoreCodes}
                  onChange={(e) => setConfig({ ...config, ignoreCodes: e.target.value })}
                  data-bs-theme="dark"
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Check
                  type="checkbox"
                  label="Verbose Output"
                  checked={config.verbose}
                  onChange={(e) => setConfig({ ...config, verbose: e.target.checked })}
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
