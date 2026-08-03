import { useState, useEffect, useCallback } from 'react';
import { Modal, Button, Form, Alert, Spinner, Row, Col, Badge } from 'react-bootstrap';

// One modal, three tools. Katana, GoSpider and LinkFinder differ in their flags but not in what an
// operator does here: load the saved config, change some values, save. Three near-identical files
// would drift, and the drift would land on whichever one was edited least.
//
// The probe banner at the top is the point of this modal existing. These three tools crawl the live
// target, so a rate the probe measured has to reach them or it was never applied to anything.

const RATE_HELP = {
  katana: 'Sent as -rl. Zero means no cap, which is katana\'s own default of 150/s.',
  gospider: 'GoSpider has no rate flag. Its offered rate is concurrency divided by delay, so pacing is set by the delay below.',
  linkfinder: 'LinkFinder has no pacing of its own. The framework waits this long between JavaScript files.',
};

export const CrawlerConfigModal = ({ show, handleClose, activeTarget, tool, onSaved }) => {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [probe, setProbe] = useState(null);

  const endpoint = `${tool}-url-config`;

  const load = useCallback(async () => {
    if (!activeTarget || !tool) return;
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await fetch(`/api/${endpoint}/${activeTarget.id}`);
      if (!res.ok) throw new Error('Failed to load configuration');
      setConfig(await res.json());

      // Read the newest probe verdict so the modal can show what was measured next to what is
      // currently set. Absence is normal and not an error.
      const scans = await fetch(`/api/scopetarget/${activeTarget.id}/scans/waf-probe`);
      if (scans.ok) {
        const list = await scans.json();
        const newest = Array.isArray(list) ? list.find((s) => s.result) : null;
        if (newest) {
          const parsed = typeof newest.result === 'string'
            ? JSON.parse(newest.result) : newest.result;
          setProbe(parsed?.verdict || null);
        } else {
          setProbe(null);
        }
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget, tool, endpoint]);

  useEffect(() => { if (show) load(); }, [show, load]);

  const set = (key, value) => {
    setConfig((prev) => ({ ...prev, [key]: value }));
    setSuccess('');
  };

  const save = async () => {
    if (!activeTarget || !config) return;
    setSaving(true);
    setError('');
    try {
      const res = await fetch(`/api/${endpoint}/${activeTarget.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });
      if (!res.ok) throw new Error(await res.text() || 'Failed to save');
      setSuccess('Configuration saved.');
      if (onSaved) onSaved(config);
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  // Translate the probe's measured rate into the knob this particular tool actually reads, using
  // the same arithmetic the backend uses when applying. Shown, not silently written: adopting a
  // measurement should be a click the operator makes.
  const probeSuggestion = () => {
    if (!config || !probe?.safe_rps) return null;
    const rps = probe.safe_rps;
    if (tool === 'katana') {
      const want = Math.max(1, Math.floor(rps));
      return config.rateLimit === want ? null
        : { label: `Set rate limit to ${want} req/s`, apply: () => set('rateLimit', want) };
    }
    if (tool === 'gospider') {
      const want = Math.max(1, Math.ceil((config.concurrent || 10) / rps));
      return config.delay === want ? null
        : { label: `Set delay to ${want}s for ~${rps} req/s at ${config.concurrent || 10} concurrent`,
            apply: () => set('delay', want) };
    }
    const want = Math.max(1, Math.round(1000 / rps));
    return config.requestDelayMs === want ? null
      : { label: `Set delay to ${want}ms between files for ~${rps} req/s`,
          apply: () => set('requestDelayMs', want) };
  };

  const suggestion = probeSuggestion();
  const title = { katana: 'Katana', gospider: 'GoSpider', linkfinder: 'LinkFinder' }[tool] || tool;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="lg" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Configure {title}</Modal.Title>
      </Modal.Header>

      <Modal.Body className="text-white">
        {loading && <div className="text-center py-4"><Spinner animation="border" variant="danger" /></div>}
        {error && <Alert variant="danger" dismissible onClose={() => setError('')}>{error}</Alert>}
        {success && <Alert variant="success" dismissible onClose={() => setSuccess('')}>{success}</Alert>}

        {config && (
          <>
            <div className="rounded p-2 mb-3" style={{ border: '1px solid rgba(220,53,69,0.45)' }}>
              {probe?.safe_rps ? (
                <div className="d-flex align-items-center flex-wrap gap-2">
                  <Badge bg={probe.safe_rps_confidence === 'measured' ? 'danger' : 'secondary'}>
                    probe: {probe.safe_rps} req/s
                  </Badge>
                  <span className="text-white-50 small">
                    {probe.safe_rps_confidence}
                    {probe.safe_rps_verified ? ' and validated' : ''}
                    {probe.safe_concurrency ? `, ${probe.safe_concurrency} safe concurrent` : ''}
                  </span>
                  {suggestion && (
                    <Button size="sm" variant="outline-danger" className="ms-auto"
                            onClick={suggestion.apply}>
                      {suggestion.label}
                    </Button>
                  )}
                  {!suggestion && (
                    <span className="text-success small ms-auto">Settings match the probe.</span>
                  )}
                </div>
              ) : (
                <span className="text-white-50 small">
                  No probe result for this target yet. Run the Routing &amp; WAF Probe first and
                  these settings can be paced to a measured rate instead of a guess.
                </span>
              )}
            </div>

            {tool === 'katana' && <KatanaFields config={config} set={set} />}
            {tool === 'gospider' && <GoSpiderFields config={config} set={set} />}
            {tool === 'linkfinder' && <LinkFinderFields config={config} set={set} />}

            <h6 className="text-danger mt-4">Authentication</h6>
            <Form.Check
              type="switch"
              id={`${tool}-ffuf-auth`}
              checked={!!config.useFFUFAuth}
              onChange={(e) => set('useFFUFAuth', e.target.checked)}
              label={<span className="small">Reuse this target&apos;s saved FFUF session</span>}
            />
            <Form.Text className="text-white-50">
              {tool === 'linkfinder'
                ? 'LinkFinder accepts cookies but not headers, so a token carried in an Authorization header cannot be passed to it.'
                : 'Sends the saved headers and cookie so the crawler sees the application rather than its login page.'}
            </Form.Text>

            <Row className="g-3 mt-1">
              <TextField label="Base URL override" wide value={config.baseUrl}
                onChange={(v) => set('baseUrl', v)}
                help="Set by the probe when the configured URL redirects elsewhere. Empty means use the scope target." />
            </Row>
          </>
        )}
      </Modal.Body>

      <Modal.Footer>
        <Button variant="outline-secondary" onClick={handleClose}>Cancel</Button>
        <Button variant="danger" onClick={save} disabled={saving || !config}>
          {saving ? <Spinner size="sm" animation="border" /> : 'Save'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

/* ------------------------------------------------------------------ per-tool fields */

const KatanaFields = ({ config, set }) => (
  <>
    <h6 className="text-danger">Pacing</h6>
    <Row className="g-3">
      <NumField label="Rate limit (req/s)" value={config.rateLimit} min={0} max={500}
        onChange={(v) => set('rateLimit', v)} help={RATE_HELP.katana} />
      <NumField label="Concurrency" value={config.concurrency} min={1} max={100}
        onChange={(v) => set('concurrency', v)} help="Concurrent fetchers (-c)." />
      <NumField label="Parallelism" value={config.parallelism} min={1} max={100}
        onChange={(v) => set('parallelism', v)} help="Concurrent inputs processed (-p)." />
    </Row>

    <h6 className="text-danger mt-4">Crawl</h6>
    <Row className="g-3">
      <NumField label="Depth" value={config.depth} min={1} max={20} onChange={(v) => set('depth', v)} />
      <NumField label="Timeout (s)" value={config.timeout} min={1} max={120} onChange={(v) => set('timeout', v)} />
      <NumField label="Retries" value={config.retry} min={0} max={10} onChange={(v) => set('retry', v)} />
      <NumField label="Max duration (s)" value={config.crawlDurationSeconds} min={0} max={7200}
        onChange={(v) => set('crawlDurationSeconds', v)} help="Zero means no limit." />
      <NumField label="Max response size" value={config.maxResponseSize} min={0} max={50000000}
        onChange={(v) => set('maxResponseSize', v)} />
      <TextField label="Known files" value={config.knownFiles} onChange={(v) => set('knownFiles', v)}
        help="all, robotstxt, sitemapxml" />
      <TextField label="Field scope" value={config.fieldScope} onChange={(v) => set('fieldScope', v)}
        help="dn, rdn, fqdn, or a regex" />
      <TextField label="Extension filter" value={config.extensionFilter}
        onChange={(v) => set('extensionFilter', v)} help="Comma separated, e.g. png,css,woff" />
    </Row>

    <h6 className="text-danger mt-4">Behaviour</h6>
    <Row className="g-2">
      <SwitchField id="k-jc" label="Parse JavaScript (-jc)" value={config.jsCrawl} onChange={(v) => set('jsCrawl', v)} />
      <SwitchField id="k-jsl" label="jsluice parsing (memory intensive)" value={config.jsluice} onChange={(v) => set('jsluice', v)} />
      <SwitchField id="k-iqp" label="Ignore duplicate query params" value={config.ignoreQueryParams} onChange={(v) => set('ignoreQueryParams', v)} />
      <SwitchField id="k-aff" label="Automatic form fill" value={config.automaticFormFill} onChange={(v) => set('automaticFormFill', v)} />
      <SwitchField id="k-hl" label="Headless crawling" value={config.headless} onChange={(v) => set('headless', v)} />
      <SwitchField id="k-xhr" label="Extract XHR requests" value={config.xhrExtraction} onChange={(v) => set('xhrExtraction', v)} />
      <SwitchField id="k-cb" label="Cache bust" value={config.cache_bust} onChange={(v) => set('cache_bust', v)} />
      <SwitchField id="k-rs" label="Reuse session" value={config.reuse_session} onChange={(v) => set('reuse_session', v)} />
    </Row>
  </>
);

const GoSpiderFields = ({ config, set }) => (
  <>
    <h6 className="text-danger">Pacing</h6>
    <Row className="g-3">
      <NumField label="Concurrent" value={config.concurrent} min={1} max={100}
        onChange={(v) => set('concurrent', v)} help="Max concurrent requests per matching domain (-c)." />
      <NumField label="Threads" value={config.threads} min={1} max={50}
        onChange={(v) => set('threads', v)} help="Sites run in parallel (-t)." />
      <NumField label="Delay (s)" value={config.delay} min={0} max={60}
        onChange={(v) => set('delay', v)} help={RATE_HELP.gospider} />
      <NumField label="Random extra delay (s)" value={config.randomDelay} min={0} max={60}
        onChange={(v) => set('randomDelay', v)} />
      <NumField label="Depth" value={config.depth} min={0} max={20}
        onChange={(v) => set('depth', v)} help="Zero means infinite recursion." />
      <NumField label="Timeout (s)" value={config.timeout} min={1} max={120} onChange={(v) => set('timeout', v)} />
    </Row>

    <h6 className="text-danger mt-4">Sources</h6>
    <Row className="g-2">
      <SwitchField id="g-sm" label="Crawl sitemap.xml" value={config.sitemap} onChange={(v) => set('sitemap', v)} />
      <SwitchField id="g-rb" label="Crawl robots.txt" value={config.robots} onChange={(v) => set('robots', v)} />
      <SwitchField id="g-js" label="Parse JavaScript" value={config.js} onChange={(v) => set('js', v)} />
      <SwitchField id="g-os" label="Third-party sources (-a)" value={config.otherSource} onChange={(v) => set('otherSource', v)} />
      <SwitchField id="g-ws" label="Include subdomains from third parties" value={config.includeSubs} onChange={(v) => set('includeSubs', v)} />
      <SwitchField id="g-ios" label="Crawl third-party URLs too (-r)" value={config.includeOtherSource} onChange={(v) => set('includeOtherSource', v)} />
      <SwitchField id="g-nr" label="Disable redirects" value={config.noRedirect} onChange={(v) => set('noRedirect', v)} />
      <SwitchField id="g-cb" label="Cache bust" value={config.cache_bust} onChange={(v) => set('cache_bust', v)} />
    </Row>

    <h6 className="text-danger mt-4">Scope</h6>
    <Row className="g-3">
      <TextField label="Blacklist regex" value={config.blacklist} onChange={(v) => set('blacklist', v)} />
      <TextField label="Whitelist regex" value={config.whitelist} onChange={(v) => set('whitelist', v)} />
      <TextField label="Whitelist domain" value={config.whitelistDomain} onChange={(v) => set('whitelistDomain', v)} />
      <TextField label="User-Agent" wide value={config.userAgent} onChange={(v) => set('userAgent', v)} />
    </Row>
  </>
);

const LinkFinderFields = ({ config, set }) => (
  <>
    <h6 className="text-danger">Input</h6>
    <Alert variant="dark" className="border-secondary small">
      LinkFinder is a regex over a body of text. Pointed at a target URL it fetches that one page
      and scans it, which on a single-page app means scanning an empty shell and never opening a
      bundle. Feeding it the JavaScript that the crawlers and the manual crawl already discovered is
      the job it was built for.
    </Alert>
    <Form.Select size="sm" style={{ maxWidth: '380px' }} value={config.inputSource || 'both'}
                 onChange={(e) => set('inputSource', e.target.value)}>
      <option value="both">Target page and discovered JavaScript (recommended)</option>
      <option value="discovered_js">Discovered JavaScript only</option>
      <option value="target">Target page only (the original behaviour)</option>
    </Form.Select>
    <Form.Text className="text-white-50 d-block mb-3">
      Discovered JavaScript comes from Katana, GoSpider and the manual crawl. If none of those have
      run, there is nothing for this mode to read and the scan will say so.
    </Form.Text>

    <Row className="g-3">
      <NumField label="Max JS files" value={config.maxJsFiles} min={1} max={500}
        onChange={(v) => set('maxJsFiles', v)}
        help="Each file is one fetch. A large bundle set is the main cost of this scan." />
      <NumField label="Delay between files (ms)" value={config.requestDelayMs} min={0} max={10000}
        onChange={(v) => set('requestDelayMs', v)} help={RATE_HELP.linkfinder} />
      <NumField label="Timeout (s)" value={config.timeout} min={1} max={120}
        onChange={(v) => set('timeout', v)} />
      <TextField label="Endpoint regex filter" wide value={config.regexFilter}
        onChange={(v) => set('regexFilter', v)} help="Passed to -r, e.g. ^/api/" />
    </Row>

    <h6 className="text-danger mt-4">Behaviour</h6>
    <Row className="g-2">
      <SwitchField id="l-d" label="Follow script tags on the target page (-d)"
        value={config.domainMode} onChange={(v) => set('domainMode', v)} />
      <SwitchField id="l-rel" label="Keep relative endpoints"
        value={config.includeRelative} onChange={(v) => set('includeRelative', v)} />
    </Row>
    <Form.Text className="text-white-50">
      Relative hits such as <code>v1/users</code> are resolved against the file they were found in,
      not the site root, because that is where a browser would resolve them.
    </Form.Text>
  </>
);

/* ------------------------------------------------------------------ inputs */

const NumField = ({ label, value, min, max, onChange, help }) => (
  <Col md={4}>
    <Form.Label className="small mb-1">{label}</Form.Label>
    <Form.Control size="sm" type="number" min={min} max={max} value={value ?? 0}
      onChange={(e) => onChange(Number(e.target.value))} />
    {help && <Form.Text className="text-white-50" style={{ fontSize: '0.7rem' }}>{help}</Form.Text>}
  </Col>
);

const TextField = ({ label, value, onChange, help, wide }) => (
  <Col md={wide ? 12 : 4}>
    <Form.Label className="small mb-1">{label}</Form.Label>
    <Form.Control size="sm" value={value || ''} onChange={(e) => onChange(e.target.value)} />
    {help && <Form.Text className="text-white-50" style={{ fontSize: '0.7rem' }}>{help}</Form.Text>}
  </Col>
);

const SwitchField = ({ id, label, value, onChange }) => (
  <Col md={6}>
    <Form.Check type="switch" id={id} checked={!!value}
      onChange={(e) => onChange(e.target.checked)}
      label={<span className="small">{label}</span>} />
  </Col>
);

export default CrawlerConfigModal;
