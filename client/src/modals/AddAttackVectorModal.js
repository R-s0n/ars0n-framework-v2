import { Modal, Button, Form, Alert, Nav } from 'react-bootstrap';
import { useState, useEffect } from 'react';

// Adding an attack vector by hand.
//
// Two ways in, because operators arrive with the vector in two different shapes. Usually they have a
// REQUEST, copied out of a proxy, and taking it apart into a verb, a host, a path and a parameter
// list by hand is both tedious and a chance to transcribe it wrong; so paste it and the server parses
// it. Sometimes they only know the shape of the thing they want to test, and then the form is
// quicker than inventing a request around it.
//
// The parsing happens on the SERVER, not here. It is the same parser consolidation uses, so a vector
// typed by hand and one found by a tool are the same kind of thing and land on the same identity.

const ACCENT = '#dc3545';

const EXAMPLE = [
  'POST /cookieless/verify HTTP/1.1',
  'Host: dev-partner-auth.one.app',
  'Content-Type: application/json',
  '',
  '{"email":"a@b.test","device_id":"1234"}',
].join('\n');

function AddAttackVectorModal({ show, handleClose, activeTarget, onAdded }) {
  const [mode, setMode] = useState('raw');
  const [raw, setRaw] = useState('');
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [insertionPoint, setInsertionPoint] = useState('');
  const [parameters, setParameters] = useState('');
  const [notes, setNotes] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!show) return;
    setError('');
    setResult(null);
  }, [show]);

  const submit = async () => {
    if (!activeTarget) return;
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const body = mode === 'raw'
        ? { raw_request: raw, insertion_point: insertionPoint, notes }
        : {
          method,
          url,
          insertion_point: insertionPoint,
          parameters: parameters.split(',').map((p) => p.trim()).filter(Boolean),
          notes,
        };
      const res = await fetch(`/api/attack-vectors/${activeTarget.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.message || 'That could not be added as an attack vector.');
        return;
      }
      setResult(data);
      setRaw('');
      setUrl('');
      setParameters('');
      if (onAdded) onAdded();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal show={show} onHide={handleClose} size="lg" data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Add an Attack Vector</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="text-white-50 mb-3" style={{ fontSize: '0.8rem' }}>
          A vector is one request carrying user-controlled input: a verb, a host, a path, the
          parameters in play and the single place a payload goes.
        </div>

        <Nav variant="tabs" activeKey={mode} onSelect={(k) => k && setMode(k)} className="mb-3">
          <Nav.Item><Nav.Link eventKey="raw">Paste a request</Nav.Link></Nav.Item>
          <Nav.Item><Nav.Link eventKey="form">Fill in the parts</Nav.Link></Nav.Item>
        </Nav>

        {error && <Alert variant="danger" className="py-2 small">{error}</Alert>}

        {result && (
          <Alert variant="dark" className="py-2 small border-secondary text-white-50">
            {result.summary}
            {result.vectors > 1 && (
              <div className="mt-1">
                The request carried parameters in more than one place, so it describes {result.vectors}
                {' '}vectors. Each place a payload can go is its own vector.
              </div>
            )}
          </Alert>
        )}

        {mode === 'raw' ? (
          <>
            <Form.Label className="text-white small">
              The whole request, exactly as it goes on the wire.
            </Form.Label>
            <Form.Control
              as="textarea"
              rows={12}
              className="bg-dark text-white border-secondary font-monospace"
              style={{ fontSize: '0.78rem' }}
              placeholder={EXAMPLE}
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
            />
            <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem' }}>
              The Host header decides the host. The query string, the body and the cookies are each
              read for parameter names, and each one that has any becomes its own vector.
            </div>
          </>
        ) : (
          <>
            <div className="row g-2">
              <div className="col-md-3">
                <Form.Label className="text-white small">Verb</Form.Label>
                <Form.Select size="sm" className="bg-dark text-white border-secondary"
                  value={method} onChange={(e) => setMethod(e.target.value)}>
                  {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </Form.Select>
              </div>
              <div className="col-md-9">
                <Form.Label className="text-white small">URL</Form.Label>
                <Form.Control size="sm" className="bg-dark text-white border-secondary custom-input"
                  placeholder="https://host/path?a=1"
                  value={url} onChange={(e) => setUrl(e.target.value)} />
              </div>
            </div>
            <Form.Label className="text-white small mt-2">Parameters</Form.Label>
            <Form.Control size="sm" className="bg-dark text-white border-secondary custom-input"
              placeholder="comma separated, e.g. id, redirect_uri"
              value={parameters} onChange={(e) => setParameters(e.target.value)} />
            <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem' }}>
              Leave empty to take them from the URL's own query string.
            </div>
          </>
        )}

        <div className="row g-2 mt-3">
          <div className="col-md-4">
            <Form.Label className="text-white small">Insertion point</Form.Label>
            <Form.Select size="sm" className="bg-dark text-white border-secondary"
              value={insertionPoint} onChange={(e) => setInsertionPoint(e.target.value)}>
              <option value="">{mode === 'raw' ? 'every place it carries one' : 'choose one'}</option>
              {['query', 'body', 'header', 'cookie', 'path'].map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </Form.Select>
          </div>
          <div className="col-md-8">
            <Form.Label className="text-white small">Note</Form.Label>
            <Form.Control size="sm" className="bg-dark text-white border-secondary custom-input"
              placeholder="why this is worth testing"
              value={notes} onChange={(e) => setNotes(e.target.value)} />
          </div>
        </div>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
        <Button variant="danger" onClick={submit}
          disabled={busy || !activeTarget || (mode === 'raw' ? !raw.trim() : !url.trim())}>
          {busy ? 'Adding' : 'Add Vector'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default AddAttackVectorModal;
