import { useState, useEffect, useCallback, useMemo } from 'react';
import { Modal, Button, Form, Tab, Tabs, Alert, Spinner, Badge, Accordion,
         InputGroup, Row, Col } from 'react-bootstrap';

// Configuration for the Target Behaviour Probe.
//
// Two principles shape this modal.
//
// The schema is fetched from the probe itself (`/waf-probe/config-schema`, which proxies
// `waf_probe.py --print-defaults`) rather than hardcoded here. A knob is therefore defined in
// exactly one place, and a probe container newer than this UI still renders correctly.
//
// The cost readout is recomputed on every change and shown persistently. An operator who can see
// that a configuration will send 900 requests over six minutes will not accidentally hammer a
// program that pays out, and wall clock is shown first because it is the binding constraint.

const PRESET_BLURBS = {
  passive: 'Read-only. No load, no payloads, no deliberate blocks. The quietest thing that still answers something.',
  safe: 'Full characterisation with zero payloads and zero sustained load.',
  standard: 'The default. Every test, at default depth and default budgets.',
  thorough: 'Every test at greater depth: more samples, wider payload and prefix lists, and the budget that needs. Expect deliberate blocks against your egress IP.',
};

const GROUP_ORDER = ['Gates', 'Baseline', 'Passive', 'Routing', 'Scanner Hazards',
                     'Protocol', 'Security Controls', 'Load'];

export const WAFProbeConfigModal = ({ show, handleClose, activeTarget, onSaved, onRunNow }) => {
  const [schema, setSchema] = useState(null);
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [estimate, setEstimate] = useState(null);
  const [estimating, setEstimating] = useState(false);
  const [tripLedger, setTripLedger] = useState(null);
  const [search, setSearch] = useState('');
  const [activeTab, setActiveTab] = useState('presets');

  // Memoised so the grouped/filtered test list below is not rebuilt on every unrelated render.
  const registry = useMemo(() => schema?.registry || [], [schema]);

  /* ---------------------------------------------------------------- load */

  const load = useCallback(async () => {
    if (!activeTarget) return;
    setLoading(true);
    setError('');
    try {
      const schemaRes = await fetch('/api/waf-probe/config-schema');
      if (!schemaRes.ok) {
        setError('The probe container is not reachable, so its configuration schema could not be '
                 + 'loaded. Start the framework with docker-compose and try again.');
        setLoading(false);
        return;
      }
      const schemaData = await schemaRes.json();
      setSchema(schemaData);

      const cfgRes = await fetch(`/api/waf-probe/config/${activeTarget.id}`);
      const saved = cfgRes.ok ? await cfgRes.json() : {};
      const base = JSON.parse(JSON.stringify(schemaData.defaults));
      const merged = saved && Object.keys(saved).length
        ? deepMerge(base, saved)
        : base;
      merged.target = merged.target || {};
      merged.target.url = activeTarget.scope_target || merged.target.url || '';
      setConfig(merged);

      const ledger = await fetch('/api/waf-probe/trip-ledger');
      if (ledger.ok) setTripLedger(await ledger.json());
    } catch (e) {
      setError('Could not load the probe configuration: ' + e.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);

  useEffect(() => {
    if (show) load();
    if (!show) { setSuccess(''); setError(''); setSearch(''); }
  }, [show, load]);

  /* ---------------------------------------------------------------- estimate */

  // Debounced so dragging a slider does not fire a request per pixel.
  useEffect(() => {
    if (!config || !activeTarget || !show) return;
    let cancelled = false;
    const timer = setTimeout(async () => {
      setEstimating(true);
      try {
        const res = await fetch(`/api/waf-probe/dry-run/${activeTarget.id}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: config.target?.url || '', config }),
        });
        if (!cancelled && res.ok) {
          const data = await res.json();
          setEstimate(data.estimate ? { ...data.estimate, problems: data.problems || [] } : null);
        }
      } catch (e) {
        if (!cancelled) setEstimate(null);
      } finally {
        if (!cancelled) setEstimating(false);
      }
    }, 500);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [config, activeTarget, show]);

  /* ---------------------------------------------------------------- mutation */

  const patch = (mutator) => {
    setConfig((prev) => {
      if (!prev) return prev;
      const next = JSON.parse(JSON.stringify(prev));
      mutator(next);
      // Any edit means the run is no longer a clean preset, and the result records that.
      next.preset_modified = true;
      return next;
    });
    setSuccess('');
  };

  const setGlobal = (key, value) => patch((c) => { c.global[key] = value; });
  const setTest = (id, key, value) => patch((c) => {
    c.tests[id] = c.tests[id] || {};
    c.tests[id][key] = value;
  });

  const applyPreset = (name) => {
    if (!schema?.presets?.[name]) return;
    setConfig((prev) => {
      const preset = JSON.parse(JSON.stringify(schema.presets[name]));
      // A preset changes what is measured, never what is measured against.
      preset.target = prev ? prev.target : preset.target;
      preset.preset = name;
      preset.preset_modified = false;
      return preset;
    });
    setSuccess('');
  };

  /* ---------------------------------------------------------------- save */

  const save = async ({ run } = {}) => {
    if (!activeTarget || !config) return;
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const res = await fetch(`/api/waf-probe/config/${activeTarget.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });
      if (!res.ok) throw new Error(await res.text() || 'Failed to save configuration');
      setSuccess('Configuration saved.');
      if (onSaved) onSaved(config);
      if (run && onRunNow) { onRunNow(config); handleClose(); }
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  /* ---------------------------------------------------------------- derived */

  const grouped = useMemo(() => {
    const out = {};
    registry.forEach((meta) => {
      if (search && !`${meta.name} ${meta.id} ${meta.question}`.toLowerCase()
        .includes(search.toLowerCase())) return;
      (out[meta.group] = out[meta.group] || []).push(meta);
    });
    return out;
  }, [registry, search]);

  const problems = estimate?.problems || [];
  const blockedByProblems = problems.length > 0;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl"
           dialogClassName="modal-90w" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-sliders me-2" />
          Configure Target Behaviour Probe
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="text-white" style={{ minHeight: '70vh' }}>
        {loading && (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        )}
        {error && <Alert variant="danger" dismissible onClose={() => setError('')}>{error}</Alert>}
        {success && <Alert variant="success" dismissible onClose={() => setSuccess('')}>{success}</Alert>}

        {config && schema && (
          <>
            {/* The honest cost readout. Wall clock first: it is the binding constraint. */}
            <div className="rounded p-2 mb-3 d-flex flex-wrap align-items-center gap-3"
                 style={{ border: '1px solid rgba(220,53,69,0.45)' }}>
              <Badge bg="danger">
                {config.preset}{config.preset_modified ? ' (modified)' : ''}
              </Badge>
              {estimating ? (
                <span className="text-white-50 small">
                  <Spinner size="sm" animation="border" className="me-2" />estimating…
                </span>
              ) : estimate ? (
                <>
                  <span><strong>{formatDuration(estimate.seconds)}</strong>
                    <span className="text-white-50 small"> wall clock</span></span>
                  <span><strong>{estimate.requests}</strong>
                    <span className="text-white-50 small"> requests</span></span>
                  <span><strong>{estimate.tests_enabled}</strong>
                    <span className="text-white-50 small"> of {registry.length} tests</span></span>
                  <span><strong>{estimate.peak_concurrency}</strong>
                    <span className="text-white-50 small"> peak concurrency</span></span>
                  <span><strong>{estimate.trip_budget}</strong>
                    <span className="text-white-50 small"> deliberate blocks allowed</span></span>
                </>
              ) : (
                <span className="text-white-50 small">Cost estimate unavailable.</span>
              )}
            </div>

            {problems.map((p, i) => (
              <Alert key={i} variant="warning" className="py-2 small">
                <i className="bi bi-exclamation-triangle me-2" />{p}
              </Alert>
            ))}

            <Tabs activeKey={activeTab} onSelect={(k) => setActiveTab(k)} className="mb-3">
              {/* ------------------------------------------------ presets */}
              <Tab eventKey="presets" title="Presets & Budget">
                <Row className="g-2 mb-4">
                  {(schema.presets ? Object.keys(schema.presets) : []).map((name) => (
                    <Col md={3} key={name}>
                      <div
                        role="button"
                        onClick={() => applyPreset(name)}
                        className={`rounded p-2 h-100 ${config.preset === name ? 'border border-danger' : 'border border-secondary'}`}
                      >
                        <div className="text-danger text-capitalize fw-bold">{name}</div>
                        <div className="text-white-50" style={{ fontSize: '0.72rem' }}>
                          {PRESET_BLURBS[name]}
                        </div>
                        <div className="small mt-2">
                          {schema.presets[name].global.request_budget} req ·
                          {' '}{formatDuration(schema.presets[name].global.wall_clock_seconds)} ·
                          {' '}{schema.presets[name].global.trip_budget} trips
                        </div>
                      </div>
                    </Col>
                  ))}
                </Row>

                <h6 className="text-danger">Budget ceilings</h6>
                <p className="text-white-50 small">
                  Any one of these ending the run is normal and produces a complete, readable
                  result rather than a failure.
                </p>
                <Row className="g-3">
                  <NumberKnob label="Request budget" help="Total requests including controls and canaries."
                    value={config.global.request_budget} min={25} max={20000}
                    onChange={(v) => setGlobal('request_budget', v)} />
                  <NumberKnob label="Wall clock (seconds)"
                    help="The binding constraint in practice. The backend timeout is derived from it."
                    value={config.global.wall_clock_seconds} min={30} max={1800}
                    onChange={(v) => setGlobal('wall_clock_seconds', v)} />
                  <NumberKnob label="Max concurrency" help="Global ceiling; overrides every per-test setting."
                    value={config.global.max_concurrency} min={1} max={64}
                    onChange={(v) => setGlobal('max_concurrency', v)} />
                  <NumberKnob label="Max request rate (req/s)"
                    help="Hard offered-rate ceiling. Clamped down by a declared policy, never up."
                    value={config.global.max_rps} min={0.5} max={50} step={0.5}
                    onChange={(v) => setGlobal('max_rps', v)} />
                  <NumberKnob label="Trip budget"
                    help="Deliberate blocks allowed across the whole run. Reputation cost is per egress IP and outlives this scan."
                    value={config.global.trip_budget} min={0} max={50}
                    onChange={(v) => setGlobal('trip_budget', v)} />
                  <NumberKnob label="Backend timeout (seconds)"
                    help="Must exceed the wall clock by at least 90s or the run is refused before it starts."
                    value={config.global.go_context_timeout_seconds} min={60} max={2400}
                    onChange={(v) => setGlobal('go_context_timeout_seconds', v)} />
                  <NumberKnob label="Characterisation rate (req/s)"
                    help="Aggregate offered rate for the concurrent characterisation phase."
                    value={config.global.characterisation_rps} min={0.2} max={20} step={0.1}
                    onChange={(v) => setGlobal('characterisation_rps', v)} />
                  <NumberKnob label="Phase cooldown (ms)"
                    help="Pause between phases so one phase's load cannot contaminate the next phase's measurement."
                    value={config.global.cooldown_between_phases_ms} min={0} max={60000} step={500}
                    onChange={(v) => setGlobal('cooldown_between_phases_ms', v)} />
                </Row>
              </Tab>

              {/* ------------------------------------------------ tests */}
              <Tab eventKey="tests" title={`Tests (${registry.filter((m) => config.tests[m.id]?.enabled).length}/${registry.length})`}>
                <Form.Control size="sm" className="mb-3" placeholder="Filter tests…"
                  value={search} onChange={(e) => setSearch(e.target.value)} />

                <Accordion alwaysOpen>
                  {GROUP_ORDER.filter((g) => grouped[g]).map((group) => (
                    <Accordion.Item eventKey={group} key={group} className="border-secondary mb-2"
                                    style={{ backgroundColor: '#2b2b2b' }}>
                      <Accordion.Header>
                        <span className="text-danger me-2">{group}</span>
                        <span className="text-white-50 small">
                          {grouped[group].filter((m) => config.tests[m.id]?.enabled).length}
                          {' of '}{grouped[group].length} enabled
                        </span>
                      </Accordion.Header>
                      <Accordion.Body style={{ backgroundColor: '#2b2b2b' }}>
                        {grouped[group].map((meta) => (
                          <TestRow key={meta.id} meta={meta} config={config}
                                   setTest={setTest} />
                        ))}
                      </Accordion.Body>
                    </Accordion.Item>
                  ))}
                </Accordion>
              </Tab>

              {/* ------------------------------------------------ safety */}
              <Tab eventKey="safety" title="Safety">
                <h6 className="text-danger">Egress reputation</h6>
                <p className="text-white-50 small">
                  A deliberate WAF block is the one cost this run charges to something other than
                  the target: Cloudflare, Akamai, DataDome and Imperva score clients across their
                  entire customer base, so blocks spent here degrade this egress address against
                  every other program for hours. That is what the trip budget on the Presets tab
                  bounds, and it is why the number is small by default rather than absent.
                </p>
                <div className="mb-4">
                  <Badge bg={tripLedger?.trips_24h ? 'warning' : 'secondary'}
                         text={tripLedger?.trips_24h ? 'dark' : undefined}>
                    {tripLedger ? tripLedger.trips_24h : '?'} block(s) spent from this address in
                    the last 24 hours
                  </Badge>
                  <span className="text-white-50 ms-2 small">
                    This run may spend up to {config.global.trip_budget} more.
                  </span>
                </div>

                <h6 className="text-danger">Abort rules</h6>
                <p className="text-white-50 small">
                  Each rule stops the run, or the current phase, when the target shows signs of
                  distress. Turning one off does not make the probe safer to run; it makes it
                  slower to notice.
                </p>
                {(config.global.abort_rules || []).map((rule, i) => (
                  <div key={rule.id} className="d-flex align-items-center gap-3 mb-2">
                    <Form.Check
                      type="switch"
                      id={`abort-${rule.id}`}
                      checked={!!rule.enabled}
                      onChange={(e) => patch((c) => { c.global.abort_rules[i].enabled = e.target.checked; })}
                      label={<span className="small">{rule.label || rule.id}</span>}
                    />
                    {rule.threshold !== undefined && (
                      <InputGroup size="sm" style={{ maxWidth: '150px' }}>
                        <InputGroup.Text>threshold</InputGroup.Text>
                        <Form.Control type="number" value={rule.threshold} step="0.1"
                          onChange={(e) => patch((c) => {
                            c.global.abort_rules[i].threshold = Number(e.target.value);
                          })} />
                      </InputGroup>
                    )}
                    <Badge bg="secondary">{rule.action}</Badge>
                  </div>
                ))}

                <h6 className="text-danger mt-4">Attribution</h6>
                <Row className="g-3">
                  <TextKnob label="Attribution header"
                    help="Sent on every request so the operator can point at their own traffic in the target's logs. It may not be empty."
                    value={config.global.attribution_header}
                    onChange={(v) => setGlobal('attribution_header', v)} />
                  <TextKnob label="User-Agent" help="Stable identifying UA on every request except the persona arm."
                    value={config.global.user_agent}
                    onChange={(v) => setGlobal('user_agent', v)} />
                  <TextKnob label="Marker prefix" help="Embedded in every random token the probe generates."
                    value={config.global.probe_token_prefix}
                    onChange={(v) => setGlobal('probe_token_prefix', v)} />
                </Row>

                <h6 className="text-danger mt-4">What this probe structurally cannot do</h6>
                <ul className="text-white-50 small">
                  <li>Send a payload that names a real file, command, or cloud metadata address.
                      Traversal targets a nonexistent filename; command injection names a
                      nonexistent binary; sensitive paths carry a random suffix.</li>
                  <li>Contact an out-of-band callback host, so nothing can be exfiltrated.</li>
                  <li>Send a request-smuggling payload: no Content-Length with Transfer-Encoding,
                      no partial chunk, no duplicated Host.</li>
                  <li>Send PUT, PATCH or DELETE. The only write is an empty POST to a path already
                      confirmed to be a 404.</li>
                  <li>Put a third-party hostname in a Host header, or follow a redirect off-site.</li>
                </ul>
                <p className="text-white-50 small">
                  This list is worth more to a program than a promise, because it describes what the
                  code cannot express rather than what the operator intends.
                </p>
              </Tab>

              {/* ------------------------------------------------ scope */}
              <Tab eventKey="scope" title="Scope & Auth">
                <Row className="g-3">
                  <TextKnob label="Target URL" value={config.target?.url || ''} wide
                    help="Defaults to the scope target. The probe reports the canonical URL if this one redirects."
                    onChange={(v) => patch((c) => { c.target.url = v; })} />
                </Row>

                <h6 className="text-danger mt-4">Credentials</h6>
                <Form.Select size="sm" style={{ maxWidth: '320px' }}
                  value={config.target?.auth?.source || 'ffuf_config'}
                  onChange={(e) => patch((c) => { c.target.auth.source = e.target.value; })}>
                  <option value="ffuf_config">Reuse the target's saved FFUF session</option>
                  <option value="inline">Enter headers and cookies here</option>
                  <option value="none">None (public view)</option>
                </Form.Select>
                <Form.Text className="text-white-50 d-block mt-2">
                  Reusing the FFUF session means the probe characterises the application the way the
                  scanners will actually see it. If that session has expired, the probe will
                  fingerprint the login wall instead and say so.
                </Form.Text>

                {config.target?.auth?.source === 'inline' && (
                  <Form.Group className="mt-3">
                    <Form.Label className="small">Cookie header</Form.Label>
                    <Form.Control size="sm" value={config.target.auth.cookies || ''}
                      onChange={(e) => patch((c) => { c.target.auth.cookies = e.target.value; })} />
                    <Form.Text className="text-white-50">
                      Redacted from every log, transcript and stored result.
                    </Form.Text>
                  </Form.Group>
                )}
              </Tab>
            </Tabs>
          </>
        )}
      </Modal.Body>

      <Modal.Footer>
        <span className="text-white-50 small me-auto">
          {blockedByProblems
            ? 'Resolve the warnings above before running.'
            : 'The estimate above is what this configuration will actually cost.'}
        </span>
        <Button variant="outline-secondary" onClick={handleClose}>Cancel</Button>
        <Button variant="outline-danger" onClick={() => save({ run: false })}
                disabled={saving || !config}>
          {saving ? <Spinner size="sm" animation="border" /> : 'Save'}
        </Button>
        <Button variant="danger" onClick={() => save({ run: true })}
                disabled={saving || !config || blockedByProblems}>
          <i className="bi bi-play-fill me-1" />Save &amp; Run
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

/* ------------------------------------------------------------------ pieces */

const TestRow = ({ meta, config, setTest }) => {
  const block = config.tests[meta.id] || {};
  const knobs = Object.keys(block).filter((k) => k !== 'enabled');

  return (
    <div className="mb-3 pb-2 border-bottom border-secondary">
      <div className="d-flex align-items-start gap-2">
        <Form.Check
          type="switch"
          id={`test-${meta.id}`}
          checked={!!block.enabled}
          disabled={meta.locked}
          onChange={(e) => setTest(meta.id, 'enabled', e.target.checked)}
        />
        <div className="flex-grow-1">
          <div className="d-flex align-items-center gap-2 flex-wrap">
            <span className={meta.locked ? 'text-white-50' : 'text-white'}>{meta.name}</span>
            <Badge bg="dark" className="border border-secondary text-white-50"
                   style={{ fontSize: '0.62rem' }}>
              {meta.cost} req · {meta.seconds}s
            </Badge>
            {meta.locked && (
              <Badge bg="secondary" style={{ fontSize: '0.62rem' }}
                     title="The probe is meaningless or unsafe without this test">
                always on
              </Badge>
            )}
          </div>
          <div className="text-white-50" style={{ fontSize: '0.72rem' }}>{meta.question}</div>

          {block.enabled && knobs.length > 0 && (
            <Row className="g-2 mt-1">
              {knobs.map((key) => (
                <Knob key={key} name={key} value={block[key]}
                      onChange={(v) => setTest(meta.id, key, v)} />
              ))}
            </Row>
          )}
        </div>
      </div>
    </div>
  );
};

// Renders whatever type the knob actually is, so the modal stays correct when the probe adds one.
const Knob = ({ name, value, onChange }) => {
  if (typeof value === 'boolean') {
    return (
      <Col md={4}>
        <Form.Check type="switch" id={`knob-${name}`} checked={value}
          onChange={(e) => onChange(e.target.checked)}
          label={<span className="small text-white-50">{humanise(name)}</span>} />
      </Col>
    );
  }
  if (typeof value === 'number') {
    return (
      <Col md={3}>
        <InputGroup size="sm">
          <InputGroup.Text style={{ fontSize: '0.7rem' }}>{humanise(name)}</InputGroup.Text>
          <Form.Control type="number" value={value} step={Number.isInteger(value) ? 1 : 0.1}
            onChange={(e) => onChange(Number(e.target.value))} />
        </InputGroup>
      </Col>
    );
  }
  if (Array.isArray(value)) {
    return (
      <Col md={6}>
        <InputGroup size="sm">
          <InputGroup.Text style={{ fontSize: '0.7rem' }}>{humanise(name)}</InputGroup.Text>
          <Form.Control value={value.join(', ')}
            onChange={(e) => onChange(e.target.value.split(',').map((s) => s.trim()).filter(Boolean))} />
        </InputGroup>
      </Col>
    );
  }
  if (typeof value === 'string') {
    return (
      <Col md={4}>
        <InputGroup size="sm">
          <InputGroup.Text style={{ fontSize: '0.7rem' }}>{humanise(name)}</InputGroup.Text>
          <Form.Control value={value} onChange={(e) => onChange(e.target.value)} />
        </InputGroup>
      </Col>
    );
  }
  return null;
};

const NumberKnob = ({ label, help, value, min, max, step = 1, onChange }) => (
  <Col md={4}>
    <Form.Label className="small mb-1">{label}</Form.Label>
    <Form.Control size="sm" type="number" value={value} min={min} max={max} step={step}
      onChange={(e) => onChange(Number(e.target.value))} />
    {help && <Form.Text className="text-white-50" style={{ fontSize: '0.7rem' }}>{help}</Form.Text>}
  </Col>
);

const TextKnob = ({ label, help, value, onChange, wide }) => (
  <Col md={wide ? 12 : 4}>
    <Form.Label className="small mb-1">{label}</Form.Label>
    <Form.Control size="sm" value={value || ''} onChange={(e) => onChange(e.target.value)} />
    {help && <Form.Text className="text-white-50" style={{ fontSize: '0.7rem' }}>{help}</Form.Text>}
  </Col>
);

/* ------------------------------------------------------------------ helpers */

function humanise(key) {
  return key.replace(/_/g, ' ');
}

function formatDuration(seconds) {
  if (!seconds && seconds !== 0) return '—';
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return s ? `${m}m ${s}s` : `${m}m`;
}

function deepMerge(base, overlay) {
  const out = Array.isArray(base) ? [...base] : { ...base };
  Object.keys(overlay || {}).forEach((k) => {
    const v = overlay[k];
    if (v && typeof v === 'object' && !Array.isArray(v) && out[k] && typeof out[k] === 'object'
        && !Array.isArray(out[k])) {
      out[k] = deepMerge(out[k], v);
    } else {
      out[k] = v;
    }
  });
  return out;
}

export default WAFProbeConfigModal;
