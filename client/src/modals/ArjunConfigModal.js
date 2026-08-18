import { useState, useEffect, useCallback } from 'react';
import { Modal, Button, Form, Alert, Spinner, Badge, Nav } from 'react-bootstrap';

// Arjun configuration: four mode tabs, the endpoints in each, and what will be sent to the one you
// have selected.
//
// The tabs are Arjun's -m values, NOT HTTP verbs. GET, POST, JSON and XML are request SHAPES: a POST
// route that only parses a JSON body ignores every form-encoded candidate and answers identically,
// so testing it in the wrong shape reads as "no parameters" when the pass never spoke its language.
// Endpoints are categorised automatically from the Content-Type their recorded request carried, and
// the dropdown on the right is how that gets corrected.
//
// Everything on the right comes from /param-enum/{id}/preview, which the server builds with the same
// argument builders the runner uses. Nothing here reconstructs a command or a request in JavaScript,
// because a second implementation drifts and then describes a scan that never ran.

const MODE_HELP = {
  GET: 'Candidates go in the query string. Every GET endpoint lands here.',
  POST: 'Candidates go in a form-encoded body. Body endpoints land here when nothing said otherwise.',
  JSON: 'Candidates go in a JSON body, with Content-Type: application/json.',
  XML: 'Candidates go in an XML body. Arjun cannot run this mode without an --include template, so one is always sent.',
};

// Settings Arjun reads per invocation, so they can differ per mode.
const MODE_FIELDS = [
  { key: 'threads', label: 'Threads', type: 'number' },
  { key: 'delay', label: 'Delay (s)', type: 'number' },
  { key: 'timeout', label: 'Timeout (s)', type: 'number' },
  { key: 'chunkSize', label: 'Chunk size', type: 'number',
    help: 'Arjun forces 500 for every non-GET mode, so this only affects GET.' },
  { key: 'wordlist', label: 'Wordlist path', type: 'text', help: 'Inside the arjun container.' },
  { key: 'stableDetection', label: 'Stable detection', type: 'bool',
    help: 'Forces one thread and sleeps 3-9s per request. Measured at 5.7s each.' },
];

export const ArjunConfigModal = ({ show, handleClose, activeTarget }) => {
  const [config, setConfig] = useState({
    headers: [], threads: 5, delay: 0, timeout: 10, chunkSize: 500, wordlist: '',
    stableDetection: false, jsonOutput: true, includeParams: '', excludeParams: '',
    includeScripts: false, xmlTemplate: '<root>$arjun$</root>', verbs: {},
  });
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [mode, setMode] = useState('GET');
  const [selectedId, setSelectedId] = useState(null);
  const [showSettings, setShowSettings] = useState(false);

  const targetId = activeTarget && activeTarget.id;

  const loadPreview = useCallback(async () => {
    if (!targetId) return;
    try {
      const res = await fetch(`/api/param-enum/${targetId}/preview?tool=arjun&all=true`);
      if (res.ok) setPreview(await res.json());
    } catch (err) {
      setError('Could not load the endpoint list: ' + err.message);
    }
  }, [targetId]);

  useEffect(() => {
    if (!show || !targetId) return;
    (async () => {
      setLoading(true);
      setError('');
      try {
        const res = await fetch(`/api/arjun-config/${targetId}`);
        if (res.ok) {
          const data = await res.json();
          if (data && Object.keys(data).length > 0) setConfig((p) => ({ ...p, ...data }));
        }
        await loadPreview();
      } finally {
        setLoading(false);
      }
    })();
  }, [show, targetId, loadPreview]);

  const pass = preview ? preview.passes.find((p) => p.mode === mode) : null;
  const rows = pass ? pass.requests : [];
  const selected = rows.find((r) => r.endpoint_id === selectedId) || rows[0] || null;

  // GET and the body modes carry separate settings; POST, JSON and XML share one set, because they
  // are one decision about how hard to hit write routes rather than three.
  const overrideVerb = mode === 'GET' ? 'GET' : 'POST';
  const override = (config.verbs && config.verbs[overrideVerb]) || {};

  const setOverride = (key, value) => {
    setConfig((prev) => {
      const verbs = { ...(prev.verbs || {}) };
      const cur = { ...(verbs[overrideVerb] || {}) };
      if (value === undefined) delete cur[key]; else cur[key] = value;
      if (Object.keys(cur).length === 0) delete verbs[overrideVerb]; else verbs[overrideVerb] = cur;
      return { ...prev, verbs };
    });
  };

  const post = async (body, okMessage) => {
    setBusy(true);
    try {
      const res = await fetch(`/api/param-enum/${targetId}/selection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: 'arjun', include_scripts: !!config.includeScripts, ...body }),
      });
      if (!res.ok) { setError('That change could not be saved'); return; }
      await loadPreview();
      if (okMessage) { setSuccess(okMessage); setTimeout(() => setSuccess(''), 1800); }
    } catch (err) {
      setError('That change could not be saved: ' + err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    try {
      const res = await fetch(`/api/arjun-config/${targetId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });
      if (!res.ok) { setError('Failed to save configuration'); return; }
      setSuccess('Configuration saved');
      await loadPreview();
      setTimeout(() => setSuccess(''), 1800);
    } catch (err) {
      setError('Failed to save configuration: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-gear me-2" />
          Arjun Configuration
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="d-flex flex-column" style={{ overflow: 'hidden' }}>
        {loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : (
          <>
            {error && (
              <Alert variant="dark" className="border border-danger text-danger py-2"
                     onClose={() => setError('')} dismissible>{error}</Alert>
            )}
            {success && (
              <Alert variant="dark" className="border border-secondary text-light py-2">{success}</Alert>
            )}

            {!preview || !preview.total ? (
              <Alert variant="dark" className="border border-secondary text-light py-3">
                No valid endpoints yet. Parameter enumeration runs against endpoints Validate
                confirmed as real, so run <strong>Consolidate</strong> and then{' '}
                <strong>Investigate</strong> first.
              </Alert>
            ) : (
              <>
                <Nav variant="tabs" activeKey={mode}
                     onSelect={(k) => { setMode(k); setSelectedId(null); }} className="mb-2">
                  {(preview.passes || []).map((p) => (
                    <Nav.Item key={p.mode}>
                      <Nav.Link eventKey={p.mode}
                                className={mode === p.mode ? 'text-danger' : 'text-white-50'}>
                        {p.mode}
                        <Badge bg="dark" className="ms-2 border border-secondary text-white-50"
                               style={{ fontSize: '0.65rem' }}>
                          {p.endpoint_count}
                        </Badge>
                      </Nav.Link>
                    </Nav.Item>
                  ))}
                </Nav>

                <div className="d-flex justify-content-between align-items-start mb-2">
                  <div className="text-white-50 small" style={{ maxWidth: '70%' }}>{MODE_HELP[mode]}</div>
                  <Button size="sm" variant="link" className="p-0 text-danger"
                          onClick={() => setShowSettings((v) => !v)}>
                    {showSettings ? 'Hide' : 'Show'} {mode} settings
                  </Button>
                </div>

                {showSettings && (
                  <div className="border border-secondary rounded p-2 mb-2">
                    <div className="text-white-50 small mb-2">
                      Blank means inherited from the shared settings.
                      {overrideVerb === 'POST' && ' POST, JSON and XML share these.'}
                    </div>
                    <div className="row g-2">
                      {MODE_FIELDS.map((f) => {
                        const isSet = override[f.key] !== undefined;
                        return (
                          <div className="col-md-2" key={f.key}>
                            <Form.Label className="text-white small mb-1 d-flex justify-content-between w-100">
                              <span>{f.label}</span>
                              {isSet && (
                                <Button size="sm" variant="link" className="p-0 text-white-50"
                                        style={{ fontSize: '0.7rem' }}
                                        onClick={() => setOverride(f.key, undefined)}>reset</Button>
                              )}
                            </Form.Label>
                            {f.type === 'bool' ? (
                              <Form.Select size="sm" value={isSet ? String(override[f.key]) : ''}
                                onChange={(e) => setOverride(f.key,
                                  e.target.value === '' ? undefined : e.target.value === 'true')}
                                data-bs-theme="dark">
                                <option value="">inherited ({String(!!config[f.key])})</option>
                                <option value="true">on</option>
                                <option value="false">off</option>
                              </Form.Select>
                            ) : (
                              <Form.Control size="sm" type={f.type}
                                placeholder={`inherited (${config[f.key] === '' ? 'default' : config[f.key]})`}
                                value={isSet ? override[f.key] : ''}
                                onChange={(e) => {
                                  const raw = e.target.value;
                                  if (raw === '') return setOverride(f.key, undefined);
                                  setOverride(f.key, f.type === 'number' ? parseInt(raw, 10) || 0 : raw);
                                }}
                                data-bs-theme="dark" />
                            )}
                            {f.help && (
                              <Form.Text className="text-muted" style={{ fontSize: '0.7rem' }}>{f.help}</Form.Text>
                            )}
                          </div>
                        );
                      })}
                      {mode === 'XML' && (
                        <div className="col-md-4">
                          <Form.Label className="text-white small mb-1">XML template</Form.Label>
                          <Form.Control size="sm" value={config.xmlTemplate || ''}
                            onChange={(e) => setConfig({ ...config, xmlTemplate: e.target.value })}
                            data-bs-theme="dark" />
                          <Form.Text className="text-muted" style={{ fontSize: '0.7rem' }}>
                            Must contain $arjun$. Anything without it is replaced with the default,
                            because Arjun crashes on a template it cannot substitute into.
                          </Form.Text>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="d-flex flex-grow-1" style={{ minHeight: 0 }}>
                  {/* Left: the endpoints in this mode. */}
                  <div className="border border-secondary rounded me-2"
                       style={{ width: '360px', minWidth: '300px', overflowY: 'auto' }}>
                    {rows.length === 0 ? (
                      <div className="text-white-50 small p-3">
                        Nothing is categorised as {mode}. Move an endpoint here from another tab.
                      </div>
                    ) : rows.map((r) => {
                      const active = selected && r.endpoint_id === selected.endpoint_id;
                      return (
                        <div key={r.endpoint_id}
                             className={`d-flex align-items-center px-2 py-1 border-bottom border-secondary ${active ? 'bg-secondary bg-opacity-25' : ''}`}
                             style={{ cursor: 'pointer', opacity: r.enabled ? 1 : 0.45 }}
                             onClick={() => setSelectedId(r.endpoint_id)}>
                          <Form.Check type="checkbox" checked={r.enabled} disabled={busy}
                            onClick={(e) => e.stopPropagation()}
                            onChange={() => post({ endpoint_ids: [r.endpoint_id], enabled: !r.enabled })}
                            className="me-2" />
                          <div className="flex-grow-1 text-truncate">
                            <div className="text-truncate">
                              <Badge bg="dark" className={`border me-1 ${r.method === 'GET'
                                ? 'border-secondary text-light' : 'border-danger text-danger'}`}
                                style={{ fontSize: '0.55rem' }}>{r.method}</Badge>
                              <code className={active ? 'text-light small' : 'text-white-50 small'}>{r.path}</code>
                            </div>
                            <div className="text-white-50" style={{ fontSize: '0.7rem' }}>{r.host}</div>
                          </div>
                          {r.mode !== r.auto_mode && (
                            <span className="text-danger ms-1" title={`Moved from ${r.auto_mode}`}>*</span>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* Right: everything about the highlighted endpoint. */}
                  <div className="flex-grow-1 border border-secondary rounded p-3"
                       style={{ overflowY: 'auto', minWidth: 0 }}>
                    {!selected ? (
                      <div className="text-white-50 small">Select an endpoint on the left.</div>
                    ) : (
                      <>
                        <div className="d-flex justify-content-between align-items-start mb-3">
                          <div style={{ minWidth: 0 }}>
                            <code className="text-light">{selected.url}</code>
                            <div className="text-white-50 small mt-1">
                              Categorised automatically as <strong>{selected.auto_mode}</strong>
                              {selected.mode !== selected.auto_mode && (
                                <>, moved to <strong className="text-danger">{selected.mode}</strong></>
                              )}
                              {!selected.enabled && (
                                <> &middot; <span className="text-danger">not selected for scanning</span></>
                              )}
                            </div>
                          </div>
                          <div style={{ minWidth: '200px' }} className="ms-3">
                            <Form.Label className="text-white small mb-1">Mode</Form.Label>
                            <Form.Select size="sm" value={selected.mode} disabled={busy}
                              onChange={(e) => post(
                                { endpoint_ids: [selected.endpoint_id], mode: e.target.value },
                                `Moved to ${e.target.value || 'automatic'}`)}
                              data-bs-theme="dark">
                              {['GET', 'POST', 'JSON', 'XML'].map((m) => (
                                <option key={m} value={m}>{m}</option>
                              ))}
                              <option value="">Automatic ({selected.auto_mode})</option>
                            </Form.Select>
                          </div>
                        </div>

                        <div className="text-white-50 small mb-1">Request Arjun will send</div>
                        <pre className="text-light small p-2 rounded"
                             style={{ backgroundColor: '#1e1e1e', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                          {selected.raw}
                        </pre>

                        {pass && pass.command && (
                          <>
                            <div className="text-white-50 small mb-1 mt-3">Command for this pass</div>
                            <pre className="text-light small p-2 rounded"
                                 style={{ backgroundColor: '#1e1e1e', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                              {pass.command}
                            </pre>
                          </>
                        )}
                        {pass && <div className="text-white-50 small">{pass.note}</div>}
                        <div className="text-white-50 small mt-2">{preview.disclaimer}</div>
                      </>
                    )}
                  </div>
                </div>
              </>
            )}
          </>
        )}
      </Modal.Body>

      <Modal.Footer>
        <div className="me-auto">
          <Form.Check type="checkbox" label="Include JavaScript bundles" className="text-white-50"
            checked={!!config.includeScripts}
            onChange={(e) => setConfig({ ...config, includeScripts: e.target.checked })} />
        </div>
        <Button variant="secondary" onClick={handleClose}>Close</Button>
        <Button variant="danger" onClick={handleSave} disabled={saving}>
          {saving ? <Spinner animation="border" size="sm" /> : 'Save Settings'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ArjunConfigModal;
