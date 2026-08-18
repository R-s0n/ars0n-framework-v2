import { Modal, Button, Form, Spinner, Alert } from 'react-bootstrap';
import { useState, useEffect, useCallback } from 'react';

// The webhook a whole section shares.
//
// Open redirect and SSRF needs two URLs and both tools in the section need the same pair, so it
// belongs to the section rather than to a tool: entering it twice is how two copies come to
// disagree, and a scan that sends payloads at one URL while checking another finds nothing and
// reports it as a clean result.
//
// The form is generated from what the server serves, the same way every Config modal in this
// workflow is, so a field added on the server appears here without this file changing.

function SectionWebhookModal({ show, handleClose, activeTarget, category, title }) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [fields, setFields] = useState([]);
  const [values, setValues] = useState({});
  const [note, setNote] = useState('');

  const load = useCallback(async () => {
    if (!activeTarget || !category) return;
    setLoading(true);
    setError('');
    setNotice('');
    try {
      const res = await fetch(`/api/${category}/${activeTarget.id}/section-settings`);
      if (!res.ok) {
        setError('Could not load the webhook settings for this target.');
        return;
      }
      const data = await res.json();
      setFields(data.fields || []);
      setNote(data.note || '');
      const asText = {};
      Object.entries(data.settings || {}).forEach(([k, v]) => { asText[k] = String(v ?? ''); });
      setValues(asText);
    } catch (err) {
      setError('Could not load the webhook settings: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget, category]);

  useEffect(() => { if (show) load(); }, [show, load]);

  const save = async () => {
    if (!activeTarget || !category) return;
    setSaving(true);
    setError('');
    setNotice('');
    try {
      const payload = {};
      Object.entries(values).forEach(([key, raw]) => {
        const text = String(raw ?? '').trim();
        if (text !== '') payload[key] = text;
      });
      const res = await fetch(`/api/${category}/${activeTarget.id}/section-settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings: payload }),
      });
      const data = await res.json();
      if (!res.ok) {
        // The server refuses a webhook that cannot work, and says which half is wrong. Showing that
        // verbatim is the point: a localhost callback URL fails silently at scan time otherwise.
        setError(data.message || 'Could not save the webhook settings.');
        return;
      }
      setNotice(data.configured
        ? 'Saved. The tools in this section can run now.'
        : 'Saved, but both URLs are needed before a scan can prove anything out of band.');
      await load();
    } catch (err) {
      setError('Could not save the webhook settings: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Configure Webhook</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {loading ? (
          <div className="text-center py-4"><Spinner animation="border" variant="danger" /></div>
        ) : (
          <>
            {error && <Alert variant="danger" className="py-2">{error}</Alert>}
            {notice && <Alert variant="secondary" className="py-2">{notice}</Alert>}

            <p className="text-white-50" style={{ fontSize: '0.82rem' }}>
              A server-side request forgery is proved by the target making a request to somewhere you
              control. {title} uses these two: the payloads point at the first, and the framework
              reads the second afterwards to find out which of them arrived.
            </p>

            <Form>
              {fields.map(({ key, field }) => (
                <Form.Group className="mb-3" key={key}>
                  <Form.Label className="text-white" style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                    {field.label}
                    {field.required && <span className="text-danger ms-1">*</span>}
                  </Form.Label>
                  <Form.Control
                    className="custom-input"
                    size="sm"
                    type="text"
                    placeholder={field.placeholder || ''}
                    value={values[key] ?? ''}
                    onChange={(e) => setValues((prev) => ({ ...prev, [key]: e.target.value }))}
                  />
                  {field.help && (
                    <Form.Text className="text-white-50" style={{ fontSize: '0.75rem' }}>
                      {field.help}
                    </Form.Text>
                  )}
                </Form.Group>
              ))}
            </Form>

            {note && (
              <div className="text-white-50 mt-2" style={{ fontSize: '0.75rem' }}>{note}</div>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={handleClose} disabled={saving}>Close</Button>
        <Button variant="danger" onClick={save} disabled={saving || loading}>
          {saving ? 'Saving...' : 'Save'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default SectionWebhookModal;
