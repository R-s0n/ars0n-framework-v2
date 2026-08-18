import { useState, useEffect, useCallback } from 'react';
import { Alert, Badge, Button, Form, Nav, Spinner } from 'react-bootstrap';

// Per-verb settings, and the requests those settings produce.
//
// A GET pass and a POST pass are not the same job. A GET can run wide against a cache; a POST is
// writing into a body-parsing route that usually wants fewer threads and a longer timeout. Splitting
// them by tab is what makes that difference expressible instead of averaged away.
//
// Everything on the right of each tab comes from /param-enum/{id}/preview, which the server builds
// with the same resolver and argument builders the runner uses. Nothing here reconstructs a command
// or a request in JavaScript, because a second implementation would drift and then confidently
// describe a scan that never ran.

export const ParamVerbTabs = ({ tool, targetId, config, setConfig, fields }) => {
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeVerb, setActiveVerb] = useState(null);
  const [openRequest, setOpenRequest] = useState(null);

  const load = useCallback(async () => {
    if (!targetId) return;
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`/api/param-enum/${targetId}/preview?tool=${tool}`);
      if (!response.ok) {
        setError('Could not load the request preview');
        return;
      }
      setPreview(await response.json());
    } catch (err) {
      setError('Could not load the request preview: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [targetId, tool]);

  useEffect(() => { load(); }, [load]);

  // Reload when a saved setting would change what is sent. Debounced, because these fields are
  // typed into and one request per keystroke would hammer the API for no benefit.
  useEffect(() => {
    if (!preview) return;
    const t = setTimeout(load, 600);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(config.verbs || {})]);

  const verbs = preview ? [...new Set(preview.passes.map((p) => p.verb))] : [];
  const verb = activeVerb && verbs.includes(activeVerb) ? activeVerb : verbs[0];

  const overrideFor = (v) => (config.verbs && config.verbs[v]) || {};

  const setOverride = (v, key, value) => {
    setConfig((prev) => {
      const verbsCfg = { ...(prev.verbs || {}) };
      const current = { ...(verbsCfg[v] || {}) };
      if (value === undefined) {
        delete current[key];
      } else {
        current[key] = value;
      }
      if (Object.keys(current).length === 0) {
        delete verbsCfg[v];
      } else {
        verbsCfg[v] = current;
      }
      return { ...prev, verbs: verbsCfg };
    });
  };

  if (loading && !preview) {
    return <div className="text-center py-4"><Spinner animation="border" variant="danger" /></div>;
  }
  if (error && !preview) {
    return <Alert variant="dark" className="border border-secondary text-light py-2">{error}</Alert>;
  }
  if (!preview || !verbs.length) {
    return (
      <Alert variant="dark" className="border border-secondary text-light py-2 small">
        No valid endpoints yet, so there is nothing to configure per verb. Run{' '}
        <strong>Consolidate</strong> and then <strong>Investigate</strong> first.
      </Alert>
    );
  }

  const passes = preview.passes.filter((p) => p.verb === verb);
  const override = overrideFor(verb);

  return (
    <>
      <Nav variant="tabs" activeKey={verb} onSelect={(k) => { setActiveVerb(k); setOpenRequest(null); }}
           className="mb-3">
        {verbs.map((v) => {
          const forVerb = preview.passes.filter((p) => p.verb === v);
          const endpoints = forVerb.length ? forVerb[0].endpoint_count : 0;
          const edited = Object.keys(overrideFor(v)).length > 0;
          return (
            <Nav.Item key={v}>
              <Nav.Link eventKey={v} className={verb === v ? 'text-danger' : 'text-white-50'}>
                {v}
                <Badge bg="dark" className="ms-2 border border-secondary text-white-50"
                       style={{ fontSize: '0.65rem' }}>
                  {endpoints}
                </Badge>
                {/* Marks a verb the operator has deliberately tuned, so an inherited tab is not
                    mistaken for a configured one. */}
                {edited && <span className="text-danger ms-1" title="Has per-verb overrides">*</span>}
              </Nav.Link>
            </Nav.Item>
          );
        })}
      </Nav>

      <div className="row g-3">
        <div className="col-lg-5">
          <div className="text-white-50 small mb-2">
            Settings for the <strong className="text-light">{verb}</strong> pass
            {passes.length > 1 && ` (${passes.length} passes share them)`}. Blank means inherited
            from the shared settings below.
          </div>

          {fields.map((f) => {
            const isSet = override[f.key] !== undefined;
            const inherited = config[f.key];
            return (
              <Form.Group className="mb-2" key={f.key}>
                <div className="d-flex justify-content-between align-items-center">
                  <Form.Label className="text-white mb-1 small">{f.label}</Form.Label>
                  {isSet && (
                    <Button size="sm" variant="link" className="p-0 text-white-50 small"
                            onClick={() => setOverride(verb, f.key, undefined)}>
                      reset to shared
                    </Button>
                  )}
                </div>

                {f.type === 'bool' ? (
                  <Form.Select
                    size="sm"
                    value={isSet ? String(override[f.key]) : ''}
                    onChange={(e) => setOverride(verb, f.key,
                      e.target.value === '' ? undefined : e.target.value === 'true')}
                    data-bs-theme="dark"
                  >
                    <option value="">inherited ({String(!!inherited)})</option>
                    <option value="true">on</option>
                    <option value="false">off</option>
                  </Form.Select>
                ) : f.type === 'select' ? (
                  <Form.Select
                    size="sm"
                    value={isSet ? override[f.key] : ''}
                    onChange={(e) => setOverride(verb, f.key,
                      e.target.value === '' ? undefined : e.target.value)}
                    data-bs-theme="dark"
                  >
                    <option value="">inherited ({inherited || 'default'})</option>
                    {f.options.map((o) => <option key={o} value={o}>{o}</option>)}
                  </Form.Select>
                ) : (
                  <Form.Control
                    size="sm"
                    type={f.type}
                    placeholder={`inherited (${inherited === '' || inherited === undefined ? 'default' : inherited})`}
                    value={isSet ? override[f.key] : ''}
                    onChange={(e) => {
                      const raw = e.target.value;
                      if (raw === '') return setOverride(verb, f.key, undefined);
                      setOverride(verb, f.key, f.type === 'number' ? parseInt(raw, 10) || 0 : raw);
                    }}
                    data-bs-theme="dark"
                  />
                )}
                {f.help && <Form.Text className="text-muted">{f.help}</Form.Text>}
              </Form.Group>
            );
          })}
        </div>

        <div className="col-lg-7">
          {passes.map((p) => (
            <div key={p.label} className="border border-secondary rounded mb-3">
              <div className="px-2 py-1 d-flex justify-content-between align-items-center"
                   style={{ backgroundColor: '#2b2b2b' }}>
                <span className="text-light small">{p.label}</span>
                <span className="text-white-50 small">{p.endpoint_count} endpoints</span>
              </div>

              <div className="p-2">
                <div className="text-white-50 small mb-1">Command</div>
                <pre className="text-light small mb-2 p-2 rounded"
                     style={{ backgroundColor: '#1e1e1e', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {p.command}
                </pre>
                <div className="text-white-50 small mb-2">{p.note}</div>

                <div className="text-white-50 small mb-1">Requests</div>
                <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
                  {p.requests.map((req) => {
                    const key = p.label + req.endpoint_id;
                    return (
                      <div key={key} className="border-top border-secondary">
                        <Button
                          variant="link"
                          className="text-decoration-none text-start w-100 p-1 d-flex align-items-center"
                          onClick={() => setOpenRequest(openRequest === key ? null : key)}
                        >
                          <i className={`bi bi-chevron-${openRequest === key ? 'down' : 'right'} text-white-50 me-2`} />
                          <Badge bg="dark" className={`border me-2 ${req.method === 'GET'
                            ? 'border-secondary text-light' : 'border-danger text-danger'}`}
                            style={{ fontSize: '0.6rem' }}>
                            {req.method}
                          </Badge>
                          <code className="text-light small text-truncate">{req.url}</code>
                        </Button>
                        {openRequest === key && (
                          <pre className="text-light small m-2 p-2 rounded"
                               style={{ backgroundColor: '#1e1e1e', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                            {req.raw}
                          </pre>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          ))}

          <div className="text-white-50 small">{preview.disclaimer}</div>
        </div>
      </div>
    </>
  );
};

export default ParamVerbTabs;
