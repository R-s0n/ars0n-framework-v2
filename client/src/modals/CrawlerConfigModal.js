import { useState, useEffect, useCallback } from 'react';
import { Modal, Button, Form, Alert, Spinner, Row, Col, Badge } from 'react-bootstrap';

// One modal, five tools. Katana, GoSpider, LinkFinder, Waybackurls and GAU differ in their flags
// but not in what an operator does here: load the saved config, change some values, save. Five
// near-identical files would drift, and the drift would land on whichever one was edited least.
//
// The two archive tools are the odd ones. They never touch the target, so the probe banner, the
// FFUF session switch and the base URL override are all meaningless for them and are hidden
// rather than shown-and-ignored. What they get instead is the host picker: the question that
// matters for an archive tool is which hosts to ask about, not how fast to go.
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

      // What the probe recommends for this tool, already resolved into this tool's own field name
      // and units by the server. Absence is normal and not an error.
      //
      // Asking the server rather than recomputing it here is deliberate. This modal used to derive
      // the delay itself, which meant two copies of arithmetic that has to know that katana counts
      // requests per second, gospider counts whole seconds and linkfinder counts milliseconds. A
      // copy that drifts is how a rate ends up wrong by a factor of a thousand.
      const recs = await fetch(`/api/waf-probe/recommendations/${activeTarget.id}`);
      if (recs.ok) {
        const data = await recs.json();
        const mine = data?.status === 'ok'
          ? (data.tools || []).find((t) => t.tool === tool)
          : null;
        setProbe(mine ? { measured: data.measured, settings: mine.settings || [] } : null);
      } else {
        setProbe(null);
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

  // The settings the probe recommends for this tool that are not already set to that value. Shown,
  // not silently written: adopting a measurement should be a click the operator makes, and when it
  // is a click there is someone to notice if the number looks wrong.
  const suggestions = (probe?.settings || [])
    .filter((s) => config && String(config[s.setting] ?? '') !== String(s.value))
    .map((s) => ({
      key: s.setting,
      label: `Set ${s.setting} to ${s.value}${s.unit ? ` (${s.unit})` : ''}`,
      why: s.why,
      apply: () => set(s.setting, s.value),
    }));

  const applyAll = () => suggestions.forEach((s) => s.apply());
  const title = { katana: 'Katana', gospider: 'GoSpider', linkfinder: 'LinkFinder',
                  waybackurls: 'Waybackurls', gau: 'GAU' }[tool] || tool;
  const isArchiveTool = tool === 'waybackurls' || tool === 'gau';
  // The crawlers get the host picker too, but keep everything else: they DO touch the target,
  // so the probe banner, the saved-session switch and the base URL override all still apply.
  const hasHostPicker = isArchiveTool || tool === 'katana' || tool === 'gospider';

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
            {isArchiveTool ? (
              <div className="rounded p-2 mb-3" style={{ border: '1px solid rgba(220,53,69,0.45)' }}>
                <span className="text-white-50 small">
                  This tool queries public archives and never sends a request to the target, so the
                  probe&apos;s measured rate does not apply to it. Hosts below are queried one at a time.
                </span>
              </div>
            ) : (
            <div className="rounded p-2 mb-3" style={{ border: '1px solid rgba(220,53,69,0.45)' }}>
              {probe?.measured?.safe_rps ? (
                <>
                  <div className="d-flex align-items-center flex-wrap gap-2">
                    <Badge bg={probe.measured.confidence === 'measured' ? 'danger' : 'secondary'}>
                      probe: {probe.measured.safe_rps} req/s
                    </Badge>
                    <span className="text-white-50 small">
                      {probe.measured.confidence}
                      {probe.measured.verified ? ' and validated' : ''}
                      {probe.measured.safe_concurrency
                        ? `, ${probe.measured.safe_concurrency} safe concurrent` : ''}
                    </span>
                    {suggestions.length > 1 && (
                      <Button size="sm" variant="outline-danger" className="ms-auto"
                              onClick={applyAll}>
                        Fill in all {suggestions.length}
                      </Button>
                    )}
                    {suggestions.length === 0 && (
                      <span className="text-success small ms-auto">Settings match the probe.</span>
                    )}
                  </div>
                  {/* One button per setting, each naming its units. Filling a field in is still the
                      operator's action; nothing is saved until they press Save. */}
                  {suggestions.map((s) => (
                    <div key={s.key} className="d-flex align-items-center gap-2 mt-2">
                      <Button size="sm" variant="outline-danger" onClick={s.apply}>
                        {s.label}
                      </Button>
                      {s.why && <span className="text-white-50 small">{s.why}</span>}
                    </div>
                  ))}
                </>
              ) : (
                <span className="text-white-50 small">
                  No probe result for this target yet. Run the Routing &amp; WAF Probe first and
                  these settings can be paced to a measured rate instead of a guess.
                </span>
              )}
            </div>
            )}

            {tool === 'katana' && <KatanaFields config={config} set={set} />}
            {tool === 'gospider' && <GoSpiderFields config={config} set={set} />}
            {tool === 'linkfinder' && <LinkFinderFields config={config} set={set} />}
            {hasHostPicker && (
              <ArchiveHostPicker activeTarget={activeTarget} tool={tool} config={config} set={set} />
            )}
            {tool === 'waybackurls' && <WaybackurlsFields config={config} set={set} />}
            {tool === 'gau' && <GauFields config={config} set={set} />}

            {!isArchiveTool && (
            <>
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
    <Row className="g-3 mb-2">
      <NumField label="Timeout per host (minutes)" value={config.timeoutMinutes} min={1} max={240}
        onChange={(v) => set('timeoutMinutes', v)}
        help="Applies to each host separately. Hosts are crawled one at a time, so a six-host run can take six times this." />
    </Row>
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
    <Row className="g-3 mb-2">
      <NumField label="Timeout per host (minutes)" value={config.timeoutMinutes} min={1} max={240}
        onChange={(v) => set('timeoutMinutes', v)}
        help="Applies to each host separately. Hosts are crawled one at a time." />
    </Row>
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
      <NumField label="Max JS files (0 = no limit)" value={config.maxJsFiles} min={0} max={5000}
        onChange={(v) => set('maxJsFiles', v)}
        help="0 reads every JavaScript file discovered so far, which is the default. Any other value is a ceiling, and files past it are dropped newest-first without a warning, so prefer 0 unless a run is taking too long." />
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


/* ------------------------------------------------------------------ archive host picker */

// Which hosts the archive tools will be asked about.
//
// Default means the direct host plus every in-scope adjacent host, resolved when the scan runs
// rather than frozen here, so a host discovered by a later crawl is picked up without anyone
// remembering to revisit this modal. Custom freezes exactly what is ticked.
//
// Out-of-scope hosts never appear. An archive query does not touch the host, but the scope boundary
// is a decision about what this engagement covers, and widening it for one tool because that tool
// happens to be passive is how a boundary stops meaning anything.
const ArchiveHostPicker = ({ activeTarget, tool, config, set }) => {
  const live = tool === 'katana' || tool === 'gospider';
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      if (!activeTarget || !tool) return;
      setLoading(true);
      setErr('');
      try {
        const res = await fetch(`/api/scan-hosts/${tool}/${activeTarget.id}`);
        if (!res.ok) throw new Error('Could not load the host list');
        const data = await res.json();
        if (!cancelled) setTargets(data.targets || []);
      } catch (e) {
        if (!cancelled) setErr(e.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    run();
    return () => { cancelled = true; };
  }, [activeTarget, tool]);

  const custom = config.hostMode === 'custom';
  const selected = new Set(config.selectedHosts || []);

  const toggle = (host) => {
    const next = new Set(selected);
    if (next.has(host)) next.delete(host); else next.add(host);
    set('selectedHosts', Array.from(next));
  };

  // Switching to custom carries the current effective selection across, so the operator narrows a
  // full list rather than starting from nothing and accidentally saving a scan of one host.
  const setMode = (mode) => {
    if (mode === 'custom' && !(config.selectedHosts || []).length) {
      set('selectedHosts', targets.map((t) => t.host));
    }
    set('hostMode', mode);
  };

  const adjacent = targets.filter((t) => !t.is_direct).length;
  const chosen = custom ? targets.filter((t) => selected.has(t.host)).length : targets.length;

  return (
    <>
      <h6 className="text-danger mt-4">Hosts to query</h6>
      {err && <Alert variant="warning" className="py-2">{err}</Alert>}
      {loading && <Spinner size="sm" animation="border" variant="danger" />}

      <Form.Check
        type="radio"
        id={`${tool}-hosts-default`}
        name={`${tool}-hostmode`}
        checked={!custom}
        onChange={() => setMode('default')}
        label={<span className="small">
          Direct host and all in-scope adjacent hosts
          <span className="text-white-50"> ({targets.length} right now, {adjacent} adjacent)</span>
        </span>}
      />
      <Form.Check
        type="radio"
        id={`${tool}-hosts-custom`}
        name={`${tool}-hostmode`}
        checked={custom}
        onChange={() => setMode('custom')}
        label={<span className="small">Only the hosts I pick</span>}
      />
      <Form.Text className="text-white-50 d-block mb-2">
        {custom
          ? 'Frozen to this list. A host discovered by a later crawl will not be added on its own.'
          : 'Resolved when the scan runs, so a host a later crawl discovers is included automatically.'}
        {live && ' Hosts are crawled one at a time, and each one is re-checked against the scope '
          + 'and given only the credentials scoped to it.'}
      </Form.Text>

      {targets.length > 0 && (
        <div className="rounded p-2" style={{ border: '1px solid rgba(255,255,255,0.12)', maxHeight: '260px', overflowY: 'auto' }}>
          {targets.map((t) => (
            <div key={t.host} className="d-flex align-items-center gap-2 py-1">
              <Form.Check
                type="checkbox"
                id={`${tool}-host-${t.host}`}
                checked={custom ? selected.has(t.host) : true}
                disabled={!custom}
                onChange={() => toggle(t.host)}
                label={<span className="small">{t.host}</span>}
              />
              {t.is_direct
                ? <Badge bg="danger">direct</Badge>
                : <Badge bg="secondary">adjacent</Badge>}
              {t.crawl_requests > 0 && (
                <span className="text-white-50" style={{ fontSize: '0.75rem' }}>
                  {t.crawl_requests} crawl requests
                </span>
              )}
            </div>
          ))}
        </div>
      )}
      {custom && chosen === 0 && (
        <Alert variant="warning" className="py-2 mt-2 mb-0 small">
          Nothing is selected, so this scan will refuse to run rather than report zero endpoints.
        </Alert>
      )}
      {targets.length === 0 && !loading && !err && (
        <Form.Text className="text-white-50">
          No hosts yet. The direct host appears once this target has one, and adjacent hosts appear
          after a manual crawl has observed them.
        </Form.Text>
      )}
    </>
  );
};

const WaybackurlsFields = ({ config, set }) => (
  <>
    <h6 className="text-danger mt-4">Query</h6>
    <SwitchField id="wb-subs" label="Include subdomains of each host"
      value={config.includeSubdomains} onChange={(v) => set('includeSubdomains', v)} />
    <Form.Text className="text-white-50 d-block mb-2">
      Asks the CDX index for *.host/* instead of host/*. Ignored for any host carrying a non-default
      port, where the wildcard is not a pattern the index can match.
    </Form.Text>
    <Row className="g-3">
      <NumField label="Timeout per host (minutes)" value={config.timeoutMinutes} min={1} max={60}
        onChange={(v) => set('timeoutMinutes', v)}
        help="Applies to each host separately. Hosts are queried one at a time, so a twelve-host run can take twelve times this." />
    </Row>
  </>
);

const GauFields = ({ config, set }) => {
  const providers = config.providers || [];
  const toggleProvider = (name) => {
    const next = providers.includes(name)
      ? providers.filter((p) => p !== name)
      : [...providers, name];
    set('providers', next);
  };
  return (
    <>
      <h6 className="text-danger mt-4">Providers</h6>
      <div className="d-flex flex-wrap gap-3">
        {['wayback', 'commoncrawl', 'otx', 'urlscan'].map((name) => (
          <Form.Check key={name} type="checkbox" id={`gau-provider-${name}`}
            checked={providers.includes(name)}
            onChange={() => toggleProvider(name)}
            label={<span className="small">{name}</span>} />
        ))}
      </div>
      <Form.Text className="text-white-50 d-block mb-2">
        Leaving all four unticked falls back to all four. Dropping wayback measured as an 85% loss of
        archive surface, and duplicates are folded by consolidation anyway.
      </Form.Text>

      <h6 className="text-danger mt-4">Query</h6>
      <SwitchField id="gau-subs" label="Include subdomains of each host"
        value={config.includeSubdomains} onChange={(v) => set('includeSubdomains', v)} />
      <Form.Text className="text-white-50 d-block mb-2">
        Sends --subs. Ignored for any host carrying a non-default port.
      </Form.Text>
      <Row className="g-3">
        <NumField label="Threads" value={config.threads} min={1} max={50}
          onChange={(v) => set('threads', v)} help="gau --threads." />
        <NumField label="HTTP timeout (seconds)" value={config.timeoutSeconds} min={1} max={600}
          onChange={(v) => set('timeoutSeconds', v)} help="gau --timeout, per request to a provider." />
        <NumField label="Retries" value={config.retries} min={0} max={10}
          onChange={(v) => set('retries', v)} help="gau --retries." />
        <NumField label="Timeout per host (minutes)" value={config.timeoutMinutes} min={1} max={60}
          onChange={(v) => set('timeoutMinutes', v)}
          help="Bounds the whole gau process for one host, unlike the HTTP timeout above." />
        <TextField label="Skip extensions" wide value={(config.blacklist || []).join(', ')}
          onChange={(v) => set('blacklist', v.split(',').map((x) => x.trim()).filter(Boolean))}
          help="gau --blacklist. Comma separated, e.g. png, jpg, woff2." />
        <TextField label="From (YYYYMM)" value={config.fromDate} onChange={(v) => set('fromDate', v)}
          help="gau --from. Earliest crawl date to accept." />
        <TextField label="To (YYYYMM)" value={config.toDate} onChange={(v) => set('toDate', v)}
          help="gau --to. Latest crawl date to accept." />
      </Row>
    </>
  );
};

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
