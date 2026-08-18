import { useState, useEffect, useCallback } from 'react';
import { Modal, Button, Form, Alert, Spinner, Badge, Nav } from 'react-bootstrap';

// x8 configuration: four injection-place tabs, the endpoints in each, and what will be sent to the
// one you have selected.
//
// The tabs are NOT the same axis as Arjun's. Arjun's -m picks how a body is ENCODED, so its mode
// replaces the request shape. x8 keeps the endpoint's real verb (it takes several on -X) and varies
// WHERE the candidates go: the query string, the body, the headers, or the cookies. Encoding is a
// separate x8 setting that only applies once you are in the body.
//
// x8 already sends candidates to the query for GET and to the body for POST/PUT/PATCH/DELETE, so
// those are the automatic assignments. Crossing to the other one is what --invert exists for, and
// the modal sends it for you. Headers and cookies are never automatic: worth testing, but a
// deliberate extra pass rather than a default.

const PLACES = ['query', 'body', 'headers', 'cookies'];

const PLACE_HELP = {
  query: 'Candidates go in the query string. x8 does this by default for GET; a body verb sent here carries --invert.',
  body: 'Candidates go in the request body. x8 does this by default for POST, PUT, PATCH and DELETE; a GET sent here carries --invert.',
  headers: 'Header discovery. Candidates become request header names. x8 removes Content-Length and Host from the candidate list itself.',
  cookies: 'Candidates go into the Cookie header. A separate pass, never automatic.',
};

// Settings x8 reads per invocation, so they can differ per place. A header sweep wants very
// different pacing and a far lower max-per-request than a query sweep.
const PLACE_FIELDS = [
  { key: 'workers', label: 'Workers (-W)', type: 'number',
    help: 'Concurrent URL checks. x8 default is 1.' },
  { key: 'requestsPerUrl', label: 'Requests/URL (-c)', type: 'number',
    help: 'Concurrent requests within one URL. Also 1 by default, and a different knob from workers.' },
  { key: 'delay', label: 'Delay (ms)', type: 'number' },
  { key: 'timeout', label: 'Timeout (s)', type: 'number' },
  { key: 'learnRequests', label: 'Learn requests', type: 'number',
    help: 'Requests spent learning normal variation before testing.' },
  { key: 'maxParamsPerRequest', label: 'Max params/request', type: 'number',
    help: 'Blank uses x8 own per-place caps: 256 query, 64 headers, 512 body.' },
  { key: 'wordlist', label: 'Wordlist path', type: 'text',
    help: 'Path inside the x8 container. Blank uses this place default under /app/wordlists.' },
  { key: 'verify', label: 'Verify hits', type: 'bool' },
  { key: 'reflectedOnly', label: 'Reflected only', type: 'bool',
    help: 'DISABLES page comparison, x8 primary detector. Leave off unless you want reflection only.' },
  { key: 'strict', label: 'Strict', type: 'bool',
    help: 'Only report parameters that changed a different part of the page.' },
  { key: 'followRedirects', label: 'Follow redirects', type: 'bool' },
];

// Settings that apply to every pass, and the only place the base values can be changed.
//
// Without this block the per-place fields above could only ever say "inherited (10)" about a number
// the operator had no way to reach.
const SHARED_ONLY_FIELDS = [
  { key: 'disableCustomParameters', label: 'Disable custom parameters', type: 'bool',
    help: 'x8 also tests admin/bot/captcha/debug/disable/encryption/env/show/sso/test/waf with values like true and 1. Leave on unless you want the wordlist only.' },
  { key: 'mimicBrowser', label: 'Mimic browser', type: 'bool',
    help: 'Adds the default headers a browser sends.' },
  { key: 'disableColors', label: 'Disable colours', type: 'bool',
    help: 'Keeps ANSI escapes out of the stored output.' },
];

// The wordlist each place falls back to, mirroring DefaultX8WordlistFor on the server. Shown as the
// placeholder so the operator can see what a blank field means.
const PLACE_WORDLIST = {
  query: '/app/wordlists/param-names.txt',
  body: '/app/wordlists/param-names.txt',
  headers: '/app/wordlists/ffuf-headers.txt',
  cookies: '/app/wordlists/ffuf-cookies.txt',
};

// Headers sent with every request, which is how an x8 scan reaches anything behind a login.
//
// Stored as [{"Name":"value"}] because that is the shape the server's ParamHeaderLines renders
// straight to one -H per entry. It also reads the older [{"key":..,"value":..}] shape, so both load.
const headerEntries = (headers) =>
  (headers || []).map((h) => {
    const keys = Object.keys(h || {});
    const lower = keys.map((k) => k.toLowerCase());
    if (keys.length === 2 && lower.includes('value') && (lower.includes('key') || lower.includes('name'))) {
      const nameKey = keys[lower.indexOf(lower.includes('key') ? 'key' : 'name')];
      const valueKey = keys[lower.indexOf('value')];
      return { name: h[nameKey] || '', value: h[valueKey] || '' };
    }
    const first = keys[0] || '';
    return { name: first, value: first ? h[first] : '' };
  });

const entriesToHeaders = (entries) =>
  entries.filter((e) => e.name.trim() !== '').map((e) => ({ [e.name.trim()]: e.value }));

export const X8ConfigModal = ({ show, handleClose, activeTarget }) => {
  const [config, setConfig] = useState({
    headers: [], bodyType: 'json', bodyTemplate: '', wordlist: '',
    workers: 10, requestsPerUrl: 1, delay: 0, timeout: 15, learnRequests: 9,
    maxParamsPerRequest: 0, verify: true, reflectedOnly: false, strict: false,
    followRedirects: false, disableColors: true, disableCustomParameters: false,
    mimicBrowser: false, includeScripts: false, places: {},
  });
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [place, setPlace] = useState('query');
  const [selectedId, setSelectedId] = useState(null);
  const [showSettings, setShowSettings] = useState(false);
  const [headerRows, setHeaderRows] = useState([]);

  const targetId = activeTarget && activeTarget.id;

  const loadPreview = useCallback(async () => {
    if (!targetId) return;
    try {
      const res = await fetch(`/api/param-enum/${targetId}/preview?tool=x8&all=true`);
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
        const res = await fetch(`/api/x8-config/${targetId}`);
        if (res.ok) {
          const data = await res.json();
          if (data && Object.keys(data).length > 0) {
            setConfig((p) => ({ ...p, ...data }));
            setHeaderRows(headerEntries(data.headers));
          }
        }
        await loadPreview();
      } finally {
        setLoading(false);
      }
    })();
  }, [show, targetId, loadPreview]);

  // A place can hold two passes: the plain one and the inverted one, whose mode carries a "!".
  const passesHere = preview
    ? preview.passes.filter((p) => (p.mode || '').replace('!', '') === place)
    : [];
  const rows = passesHere.flatMap((p) => p.requests);
  const selected = rows.find((r) => r.endpoint_id === selectedId) || rows[0] || null;
  const selectedPass = selected
    ? passesHere.find((p) => p.requests.some((r) => r.endpoint_id === selected.endpoint_id))
    : passesHere[0];

  const override = (config.places && config.places[place]) || {};

  // Rows are held here rather than derived from config.headers, because a half-typed row has no
  // name yet and would be filtered out of the config the moment it was written back.
  const commitHeaderRows = (rows) => {
    setHeaderRows(rows);
    setConfig((prev) => ({ ...prev, headers: entriesToHeaders(rows) }));
  };
  const editHeader = (index, field, value) =>
    commitHeaderRows(headerRows.map((e, i) => (i === index ? { ...e, [field]: value } : e)));

  const setOverride = (key, value) => {
    setConfig((prev) => {
      const places = { ...(prev.places || {}) };
      const cur = { ...(places[place] || {}) };
      if (value === undefined) delete cur[key]; else cur[key] = value;
      if (Object.keys(cur).length === 0) delete places[place]; else places[place] = cur;
      return { ...prev, places };
    });
  };

  const post = async (body, okMessage) => {
    setBusy(true);
    try {
      const res = await fetch(`/api/param-enum/${targetId}/selection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: 'x8', include_scripts: !!config.includeScripts, ...body }),
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
      const res = await fetch(`/api/x8-config/${targetId}`, {
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

  const countFor = (p) => preview
    ? preview.passes.filter((x) => (x.mode || '').replace('!', '') === p)
        .reduce((n, x) => n + x.endpoint_count, 0)
    : 0;

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-gear me-2" />
          x8 Configuration
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
                <Nav variant="tabs" activeKey={place}
                     onSelect={(k) => { setPlace(k); setSelectedId(null); }} className="mb-2">
                  {PLACES.map((p) => (
                    <Nav.Item key={p}>
                      <Nav.Link eventKey={p} className={place === p ? 'text-danger' : 'text-white-50'}>
                        {p}
                        <Badge bg="dark" className="ms-2 border border-secondary text-white-50"
                               style={{ fontSize: '0.65rem' }}>
                          {countFor(p)}
                        </Badge>
                      </Nav.Link>
                    </Nav.Item>
                  ))}
                </Nav>

                <div className="d-flex justify-content-between align-items-start mb-2">
                  <div className="text-white-50 small" style={{ maxWidth: '70%' }}>{PLACE_HELP[place]}</div>
                  <Button size="sm" variant="link" className="p-0 text-danger"
                          onClick={() => setShowSettings((v) => !v)}>
                    {showSettings ? 'Hide' : 'Show'} {place} settings
                  </Button>
                </div>

                {showSettings && (
                  <div className="border border-secondary rounded p-2 mb-2"
                       style={{ maxHeight: '46vh', overflowY: 'auto' }}>
                    {/* Headers first: an x8 run with no Authorization or Cookie header tests the
                        logged-out application, and on an API that is a 401 on every request and a
                        clean report of zero hidden parameters. */}
                    <div className="text-danger small fw-bold mb-1">
                      Request headers, sent with every pass
                    </div>
                    <div className="text-white-50 small mb-2">
                      One <code>-H</code> per row. Send session cookies as a header named{' '}
                      <code>Cookie</code>; on the cookies tab x8 adds its candidates to that header
                      rather than replacing it, so an authenticated cookie sweep works.
                    </div>
                    {headerRows.length === 0 && (
                      <div className="text-white-50 small mb-2 fst-italic">
                        No headers. This scan will run unauthenticated.
                      </div>
                    )}
                    {headerRows.map((row, i) => (
                      <div className="row g-2 mb-1 align-items-center" key={i}>
                        <div className="col-md-3">
                          <Form.Control size="sm" placeholder="Authorization" value={row.name}
                            onChange={(e) => editHeader(i, 'name', e.target.value)}
                            data-bs-theme="dark" />
                        </div>
                        <div className="col-md-7">
                          <Form.Control size="sm" placeholder="Bearer eyJ..." value={row.value}
                            onChange={(e) => editHeader(i, 'value', e.target.value)}
                            data-bs-theme="dark" />
                        </div>
                        <div className="col-md-2">
                          <Button size="sm" variant="outline-secondary"
                            onClick={() => commitHeaderRows(headerRows.filter((_, j) => j !== i))}>
                            Remove
                          </Button>
                        </div>
                      </div>
                    ))}
                    <Button size="sm" variant="outline-danger" className="mb-3"
                      onClick={() => commitHeaderRows([...headerRows, { name: '', value: '' }])}>
                      Add header
                    </Button>

                    <div className="text-danger small fw-bold mb-2">Shared settings, every pass</div>
                    <div className="row g-2 mb-3">
                      {[...PLACE_FIELDS, ...SHARED_ONLY_FIELDS].map((f) => (
                        <div className="col-md-2" key={`shared-${f.key}`}>
                          <Form.Label className="text-white small mb-1">{f.label}</Form.Label>
                          {f.type === 'bool' ? (
                            <Form.Select size="sm" value={String(!!config[f.key])}
                              onChange={(e) => setConfig({ ...config, [f.key]: e.target.value === 'true' })}
                              data-bs-theme="dark">
                              <option value="true">on</option>
                              <option value="false">off</option>
                            </Form.Select>
                          ) : (
                            <Form.Control size="sm" type={f.type}
                              placeholder={f.key === 'wordlist' ? PLACE_WORDLIST[place] : 'x8 default'}
                              value={config[f.key] === undefined || config[f.key] === null ? '' : config[f.key]}
                              onChange={(e) => {
                                const raw = e.target.value;
                                setConfig({ ...config,
                                  [f.key]: f.type === 'number' ? (raw === '' ? 0 : parseInt(raw, 10) || 0) : raw });
                              }}
                              data-bs-theme="dark" />
                          )}
                        </div>
                      ))}
                      <div className="col-md-4">
                        <Form.Label className="text-white small mb-1">Body encoding (-t), shared</Form.Label>
                        <Form.Select size="sm" value={config.bodyType || 'json'}
                          onChange={(e) => setConfig({ ...config, bodyType: e.target.value })}
                          data-bs-theme="dark">
                          <option value="json">json</option>
                          <option value="urlencoded">urlencoded</option>
                        </Form.Select>
                        <Form.Text className="text-muted" style={{ fontSize: '0.7rem' }}>
                          Only sent for the body place. x8 uses it as the parameter template, so
                          sending it anywhere else writes JSON into the URL.
                        </Form.Text>
                      </div>
                      <div className="col-md-4">
                        <Form.Label className="text-white small mb-1">Body template (-b), shared</Form.Label>
                        <Form.Control size="sm" value={config.bodyTemplate || ''}
                          placeholder={'{"data":{%s}}'}
                          onChange={(e) => setConfig({ ...config, bodyTemplate: e.target.value })}
                          data-bs-theme="dark" />
                      </div>
                    </div>

                    <div className="text-danger small fw-bold mb-1">
                      {place} overrides
                    </div>
                    <div className="text-white-50 small mb-2">
                      Blank means inherited from the shared settings above.
                    </div>
                    <div className="row g-2">
                      {PLACE_FIELDS.map((f) => {
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
                                placeholder={`inherited (${
                                  f.key === 'wordlist'
                                    ? config.wordlist || PLACE_WORDLIST[place]
                                    : config[f.key] === '' ? 'default' : config[f.key]})`}
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

                      {/* Encoding and the body template only mean anything once there is a body. */}
                      {place === 'body' && (
                        <>
                          <div className="col-md-2">
                            <Form.Label className="text-white small mb-1">Body encoding (-t)</Form.Label>
                            <Form.Select size="sm"
                              value={override.bodyType !== undefined ? override.bodyType : ''}
                              onChange={(e) => setOverride('bodyType',
                                e.target.value === '' ? undefined : e.target.value)}
                              data-bs-theme="dark">
                              <option value="">inherited ({config.bodyType || 'urlencoded'})</option>
                              <option value="json">json</option>
                              <option value="urlencoded">urlencoded</option>
                            </Form.Select>
                          </div>
                          <div className="col-md-4">
                            <Form.Label className="text-white small mb-1 d-flex justify-content-between w-100">
                              <span>Body template (-b)</span>
                              {override.bodyTemplate !== undefined && (
                                <Button size="sm" variant="link" className="p-0 text-white-50"
                                        style={{ fontSize: '0.7rem' }}
                                        onClick={() => setOverride('bodyTemplate', undefined)}>reset</Button>
                              )}
                            </Form.Label>
                            {/* A per-place override like everything else in this block. It used to
                                write the shared value while sitting under the body tab, so the
                                control next to it behaved differently from it. */}
                            <Form.Control size="sm"
                              value={override.bodyTemplate !== undefined ? override.bodyTemplate : ''}
                              placeholder={config.bodyTemplate || '{"data":{%s}}'}
                              onChange={(e) => setOverride('bodyTemplate',
                                e.target.value === '' ? undefined : e.target.value)}
                              data-bs-theme="dark" />
                            <Form.Text className="text-muted" style={{ fontSize: '0.7rem' }}>
                              Must contain the {'{%s}'} marker, which is where candidates go. This is
                              how you reach parameters nested under a wrapper object instead of only
                              at the top level. Ignored without the marker.
                            </Form.Text>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                )}

                <div className="d-flex flex-grow-1" style={{ minHeight: 0 }}>
                  {/* Left: the endpoints injected into this place. */}
                  <div className="border border-secondary rounded me-2"
                       style={{ width: '360px', minWidth: '300px', overflowY: 'auto' }}>
                    {rows.length === 0 ? (
                      <div className="text-white-50 small p-3">
                        Nothing injects into the {place} yet. Move an endpoint here from another tab.
                      </div>
                    ) : rows.map((r) => {
                      const active = selected && r.endpoint_id === selected.endpoint_id;
                      const inverted = r.mode !== r.auto_mode;
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
                          {inverted && (
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
                              x8 would use <strong>{selected.auto_mode}</strong> for a {selected.method}
                              {selected.mode !== selected.auto_mode && (
                                <>, so sending it to <strong className="text-danger">{selected.mode}</strong> carries --invert</>
                              )}
                              {!selected.enabled && (
                                <> &middot; <span className="text-danger">not selected for scanning</span></>
                              )}
                            </div>
                          </div>
                          <div style={{ minWidth: '210px' }} className="ms-3">
                            <Form.Label className="text-white small mb-1">Injection place</Form.Label>
                            <Form.Select size="sm" value={selected.mode} disabled={busy}
                              onChange={(e) => post(
                                { endpoint_ids: [selected.endpoint_id], mode: e.target.value },
                                `Moved to ${e.target.value || 'automatic'}`)}
                              data-bs-theme="dark">
                              {PLACES.map((p) => <option key={p} value={p}>{p}</option>)}
                              <option value="">Automatic ({selected.auto_mode})</option>
                            </Form.Select>
                          </div>
                        </div>

                        <div className="text-white-50 small mb-1">Request x8 will send</div>
                        <pre className="text-light small p-2 rounded"
                             style={{ backgroundColor: '#1e1e1e', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                          {selected.raw}
                        </pre>

                        {selectedPass && selectedPass.command && (
                          <>
                            <div className="text-white-50 small mb-1 mt-3">Command for this pass</div>
                            <pre className="text-light small p-2 rounded"
                                 style={{ backgroundColor: '#1e1e1e', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                              {selectedPass.command}
                            </pre>
                          </>
                        )}
                        {selectedPass && <div className="text-white-50 small">{selectedPass.note}</div>}
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

export default X8ConfigModal;
