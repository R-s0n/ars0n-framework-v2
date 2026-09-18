import { Modal, Button, Spinner, Alert, Nav, Badge, Accordion, Form } from 'react-bootstrap';
import { useState, useEffect, useCallback, useMemo } from 'react';

// What an XSS scan found, and what it never tested.
//
// The second tab is the point of this screen. domdig handed a header vector scans its query string,
// finds nothing and exits 0; xssFuzz handed a body vector does the same. Without the skipped list
// beside the findings, "0 findings" reads as "nothing there" for a table that was mostly never sent.
// So the count in the header is eligible-of-total, and every skipped vector carries the reason.
//
// Findings are also not flattened into one word. dalfox v3 has no headless browser, so its V means
// "the payload reached an executable position in a parsed response", not that anything ran. domdig's
// findings DID run, in Chromium. Labelling both "vulnerable" would overstate one and understate the
// other, so the tool's own class is kept and spelled out by the server.

// The confidence class, spelled out.
//
// This used to render the tool's own letter and nothing else: a badge reading "V", "A", "R" or "I"
// with the meaning available only after expanding the row. The paragraph above explains why the
// distinction between these classes is load-bearing, and then the screen threw the distinction away
// at exactly the moment an operator is scanning a list deciding what to open.
//
// "V" is the dangerous one to abbreviate. It reads as "verified" and it does not mean that: dalfox
// v3 has no headless browser, so V means the payload reached a position where it COULD execute in a
// parsed response, not that anything ran. domdig's findings did run, in Chromium. An operator who
// expands "V" learns that; an operator skimming twenty badges does not, and treats a maybe as a yes.
//
// So the badge carries a short label that cannot be misread, `detail` is the one-line meaning shown
// under it, and the letter is kept alongside because it is the tool's own vocabulary and appears in
// tool output the operator will go on to read.
const KIND_STYLE = {
  V: {
    bg: 'danger',
    label: 'Reached executable position',
    detail: 'The payload landed somewhere it could execute. Nothing was observed executing it.',
  },
  A: {
    bg: 'warning',
    label: 'Source to sink in JS',
    detail: 'A data flow was traced from an attacker-controlled source to a dangerous sink.',
  },
  R: {
    bg: 'secondary',
    label: 'Reflected only',
    detail: 'The input came back unencoded. That is not by itself an injection.',
  },
  I: {
    bg: 'dark',
    label: 'Informational',
    detail: 'Recorded as context. Not a claim that anything is exploitable.',
  },
};

// The injection sections use a descriptive class rather than a letter, so they need no expansion,
// only a colour that matches how much the class actually claims. Anything not listed falls back to
// grey, which is the honest default for a class this screen does not recognise.
const KIND_DETAIL_BY_NAME = {
  'boolean-based blind': {
    bg: 'danger',
    detail: 'The tool changed a true/false condition and the response changed with it.',
  },
  'time-based blind': {
    bg: 'danger',
    detail: 'The tool made the database pause and the response time followed.',
  },
  'union-based': { bg: 'danger', detail: 'The tool read data back through an appended UNION query.' },
  'error-based': { bg: 'danger', detail: 'The tool read data back out of a database error message.' },
  'stacked-queries': { bg: 'danger', detail: 'A second statement was accepted after the first.' },
  'error-signature': {
    bg: 'warning',
    detail: 'A database error appeared. That is a lead to confirm, not a confirmed injection.',
  },
};

// kindPresentation is the single place that decides how a confidence class is shown, so the badge,
// the filter dropdown and the legend can never disagree about what a class is called.
export const kindPresentation = (kind) => {
  const raw = String(kind == null ? '' : kind).trim();
  if (!raw) return { bg: 'secondary', label: 'Unclassified', detail: '', code: '' };

  const known = KIND_STYLE[raw];
  if (known) return { ...known, code: raw };

  const byName = KIND_DETAIL_BY_NAME[raw.toLowerCase()];
  // A descriptive class is already readable, so it is shown as the tool wrote it.
  return { bg: (byName && byName.bg) || 'secondary', label: raw, detail: (byName && byName.detail) || '', code: '' };
};

const TRIAGE_ORDER = ['new', 'interesting', 'dismissed'];

// The first line the server puts on a request it COMPOSED rather than recorded. Matched literally,
// exactly as the server matches it (vectorReproduce.go, reconstructedRequestBanner). If it ever
// changes there and not here, the strip below stops firing and the repeater is handed a request
// whose first line is a row of hashes.
const RECONSTRUCTED_BANNER = '#### RECONSTRUCTED REQUEST, NOT CAPTURED BYTES ####';

// finding.raw_request is returned "exactly as stored, banner and all", and for a composed request
// that banner is six or seven lines of '#' commentary in front of the request line. It is an
// annotation for a human reading a <pre>, not part of the request: handed to the repeater with the
// banner still on it the bytes do not parse as HTTP at all, and the send comes back "This does not
// parse as an HTTP request" for a request that is perfectly well formed underneath.
//
// So the banner comes off on the way to the editor and NOTHING ELSE DOES. No trimming, no header
// reordering, no re-terminating lines: what is left is the bytes the scanner sent or the framework
// composed, and the pane is byte-exact from here on.
//
// Deliberately the same shape as the server's SplitReconstructedRequest: drop the first line, then
// every '#' line that follows it, and keep everything from the first line that is neither.
export const stripReconstructedBanner = (raw) => {
  const text = typeof raw === 'string' ? raw : '';
  if (!text.replace(/^[\s]+/, '').startsWith(RECONSTRUCTED_BANNER)) return text;
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    if (i === 0 || lines[i].startsWith('#')) continue;
    return lines.slice(i).join('\n');
  }
  // A banner and nothing under it. There is no request here, and saying so by returning empty is
  // what makes the button hide itself rather than open an empty repeater.
  return '';
};

// Where to send it. The connection target only; the Host header in the bytes is preserved by the
// framework and is not touched here.
//
// This matters more than it looks. With no base_url the send falls back to the Host header AND
// ASSUMES HTTPS, so a finding on an http origin would be replayed over TLS against a different port
// and the response would be about a request the tool never made. The finding's own url is the origin
// the tool was aimed at, so that is what travels.
export const originOf = (url) => {
  try {
    return new URL(String(url)).origin;
  } catch (err) {
    return '';
  }
};

// A copyable block. Reproduction only helps if getting it out of the modal is one click: an
// operator who has to select 30 lines of a raw request by hand will not bother, and a finding
// nobody reproduces is a finding nobody can act on.
const CopyBlock = ({ label, value, hint, colour = 'rgba(255,255,255,0.75)' }) => {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  const copy = () => {
    const done = () => { setCopied(true); setTimeout(() => setCopied(false), 1500); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done).catch(() => {});
      return;
    }
    // Older browsers and any non-secure context, where navigator.clipboard is undefined.
    const el = document.createElement('textarea');
    el.value = value;
    document.body.appendChild(el);
    el.select();
    try { document.execCommand('copy'); done(); } catch (e) { /* nothing to do */ }
    document.body.removeChild(el);
  };
  return (
    <div className="mb-2">
      <div className="d-flex align-items-center justify-content-between mb-1">
        <span className="text-white-50" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
          {label}
        </span>
        <Button size="sm" variant={copied ? 'success' : 'outline-secondary'} onClick={copy}
          style={{ fontSize: '0.68rem', padding: '0 0.4rem' }}>
          {copied ? 'copied' : 'copy'}
        </Button>
      </div>
      {hint && (
        <div className="text-white-50 mb-1" style={{ fontSize: '0.7rem' }}>{hint}</div>
      )}
      <pre className="p-2 mb-0 rounded" style={{
        background: 'rgba(0,0,0,0.35)', color: colour, fontSize: '0.72rem',
        maxHeight: '260px', overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
      }}>{value}</pre>
    </div>
  );
};

// What the tool proved, and just as importantly what it did not. Every entry is hard-coded per
// tool and kind on the server, because the gap between "observed" and "proved" is where this
// project has repeatedly been misled.
// showSteps is false when the Reproduce block below already lists the procedure against this
// finding's real URL and headers. Rendering both put two numbered lists back to back saying the
// same five things, one of them generic, which is how the 403 bypass finding ended up unreadable.
// The concrete one always wins; this list is the fallback for a tool with no reproduction builder.
const Explain = ({ explain, showSteps = true }) => {
  if (!explain || !explain.title) return null;
  const Row = ({ label, text, tone }) => (text ? (
    <div className="mb-2">
      <div style={{ fontSize: '0.7rem', letterSpacing: '0.04em' }} className={tone || 'text-white-50'}>
        {label}
      </div>
      <div className="text-white" style={{ fontSize: '0.78rem' }}>{text}</div>
    </div>
  ) : null);
  return (
    <div className="p-2 mb-3 rounded" style={{ background: 'rgba(255,255,255,0.04)' }}>
      <div className="text-white mb-2" style={{ fontSize: '0.85rem', fontWeight: 600 }}>
        {explain.title}
      </div>
      <Row label="WHAT THIS PROVED" text={explain.what_it_proved} />
      <Row label="WHAT IT DID NOT PROVE" text={explain.what_it_did_not_prove} tone="text-warning" />
      <Row label="WHY IT MATTERS" text={explain.why_it_matters} />
      <Row label="A FALSE POSITIVE LOOKS LIKE" text={explain.false_positive_looks_like} tone="text-warning" />
      <Row label="SEVERITY" text={explain.severity_note} />
      {showSteps && explain.validation_steps && explain.validation_steps.length > 0 && (
        <div className="mt-2">
          <div className="text-white-50 mb-1" style={{ fontSize: '0.7rem', letterSpacing: '0.04em' }}>
            HOW TO VALIDATE THIS CLASS OF FINDING
          </div>
          <ol className="text-white ps-3 mb-0" style={{ fontSize: '0.78rem' }}>
            {explain.validation_steps.map((step, i) => <li key={i} className="mb-1">{step}</li>)}
          </ol>
        </div>
      )}
      {explain.references && explain.references.length > 0 && (
        <div className="mt-2" style={{ fontSize: '0.72rem' }}>
          {explain.references.map((r) => (
            <a key={r} href={r} target="_blank" rel="noopener noreferrer"
              className="text-info d-block" style={{ wordBreak: 'break-all' }}>{r}</a>
          ))}
        </div>
      )}
    </div>
  );
};

// Everything needed to check the finding WITHOUT this framework.
const Reproduce = ({ repro }) => {
  if (!repro || (!repro.url && !repro.curl && !repro.raw_request)) return null;
  return (
    <div className="p-2 mb-3 rounded" style={{ background: 'rgba(255,255,255,0.04)' }}>
      <div className="text-white mb-2" style={{ fontSize: '0.85rem', fontWeight: 600 }}>
        Reproduce it yourself
      </div>
      {repro.caveat && (
        <div className="text-warning mb-2" style={{ fontSize: '0.74rem' }}>{repro.caveat}</div>
      )}
      {repro.url && (
        <div className="mb-2">
          <div className="text-white-50 mb-1" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
            OPEN IN A BROWSER
          </div>
          <a href={repro.url} target="_blank" rel="noopener noreferrer" className="text-info"
            style={{ fontSize: '0.74rem', wordBreak: 'break-all' }}>{repro.url}</a>
        </div>
      )}
      <CopyBlock label="CURL" value={repro.curl} colour="#9ae6b4" />
      <CopyBlock label="RAW HTTP REQUEST" value={repro.raw_request}
        hint="Paste into Burp Repeater, or into any tool that takes raw request bytes." />
      {repro.steps && repro.steps.length > 0 && (
        <div className="mt-2">
          <div className="text-white-50 mb-1" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
            STEP BY STEP
          </div>
          <ol className="text-white ps-3 mb-0" style={{ fontSize: '0.78rem' }}>
            {repro.steps.map((step, i) => <li key={i} className="mb-1">{step}</li>)}
          </ol>
        </div>
      )}
    </div>
  );
};

const Exchange = ({ request, response }) => {
  const [side, setSide] = useState('request');
  if (!request && !response) {
    return (
      <div className="text-white-50" style={{ fontSize: '0.78rem' }}>
        No raw exchange was captured for this finding.
      </div>
    );
  }
  const body = side === 'request' ? request : response;
  return (
    <div>
      <Nav variant="pills" activeKey={side} onSelect={(k) => k && setSide(k)} className="mb-2 gap-2">
        <Nav.Item><Nav.Link eventKey="request" className="py-0 px-2" style={{ fontSize: '0.75rem' }}>Request</Nav.Link></Nav.Item>
        <Nav.Item><Nav.Link eventKey="response" className="py-0 px-2" style={{ fontSize: '0.75rem' }}>Response</Nav.Link></Nav.Item>
      </Nav>
      <pre
        className="p-2 mb-0 rounded"
        style={{
          background: 'rgba(0,0,0,0.35)', color: 'rgba(255,255,255,0.75)',
          fontSize: '0.72rem', maxHeight: '320px', overflow: 'auto', whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
        }}
      >
        {body || `Nothing was captured for the ${side}.`}
      </pre>
    </div>
  );
};

// The Send to Replay button, next to the bytes it is about.
//
// WHY IT IS HIDDEN RATHER THAN DISABLED when a finding has no request bytes.
//
// A disabled button would be the third thing on the same screen saying the same thing. The evidence
// note above already says this tool "recorded neither the request nor the response", and the
// Exchange block immediately below already says "No raw exchange was captured for this finding."
// Adding a greyed-out control with a tooltip repeating it does not inform anybody; it just puts a
// dead control on every row of a list that can be forty rows long, and a control an operator has
// learned is usually dead is a control they stop reading. The information is not lost by hiding the
// button, because the two sentences that explain the absence are still there. What is lost is a
// piece of furniture.
//
// Composed bytes still get a button, and say so on it. They are not a measurement, but sending them
// is precisely how an operator turns them into one, which is what the evidence note tells them to do.
const SendToReplay = ({ finding, onSend }) => {
  if (!onSend) return null;
  const bytes = stripReconstructedBanner(finding.raw_request);
  if (bytes.trim() === '') return null;
  const composed = finding.raw_request_origin === 'reconstructed';
  return (
    <Button
      size="sm"
      variant="outline-danger"
      onClick={() => onSend({
        raw_request: bytes,
        base_url: originOf(finding.url),
        label: `${finding.tool || 'a tool'} finding`,
      })}
      title={composed
        ? 'Loads these bytes into the repeater, ready to send. They were COMPOSED by the framework, '
          + 'not recorded, so sending them is how this finding gets a real response to read. '
          + 'Nothing is sent until you press Replay.'
        : 'Loads the bytes the scanner sent into the repeater, ready to send. '
          + 'Nothing is sent until you press Replay.'}
    >
      <i className="bi bi-arrow-repeat me-1" />
      Send to Replay
    </Button>
  );
};

function VectorToolResultsModal({
  show, handleClose, activeTarget, tool, category, onSendToRepeater,
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [findings, setFindings] = useState([]);
  const [skipped, setSkipped] = useState([]);
  const [untested, setUntested] = useState([]);
  const [traces, setTraces] = useState([]);
  const [scan, setScan] = useState(null);
  const [canary, setCanary] = useState(null);
  const [openTrace, setOpenTrace] = useState(null);
  const [status, setStatus] = useState(null);
  const [tab, setTab] = useState('findings');
  const [pointFilter, setPointFilter] = useState('');
  const [kindFilter, setKindFilter] = useState('');
  const [triageFilter, setTriageFilter] = useState('');

  const toolKey = tool?.key;

  const load = useCallback(async () => {
    if (!activeTarget || !toolKey) return;
    setLoading(true);
    setError('');
    try {
      const [resultsRes, statusRes] = await Promise.all([
        fetch(`/api/${category}/${activeTarget.id}/${toolKey}/results`),
        fetch(`/api/${category}/${activeTarget.id}/${toolKey}/status`),
      ]);
      if (!resultsRes.ok) {
        setError('Could not load these results.');
        return;
      }
      const data = await resultsRes.json();
      setFindings(data.findings || []);
      setSkipped(data.skipped || []);
      // UNTESTED is not SKIPPED and the two are kept apart all the way to the screen. Skipped means
      // the tool could never reach that insertion point, which is a bounded gap. Untested means the
      // run stopped partway and those vectors are simply unknown.
      setUntested(data.untested || []);
      setTraces(data.traces || []);
      setScan(data.scan || null);
      // The positive control, kept apart from findings all the way to the screen. Its hits used to
      // arrive inside data.findings looking exactly like findings on the operator's own target,
      // reproduction steps and all, pointing at the framework's oracle container.
      setCanary(data.canary || null);
      if (statusRes.ok) setStatus(await statusRes.json());
    } catch (err) {
      setError('Could not load these results: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget, toolKey, category]);

  useEffect(() => { if (show) load(); }, [show, load]);

  // Forwarded, and deliberately NOT paired with a handleClose() of our own.
  //
  // The parent closes this modal, records the bytes and opens the repeater in ONE commit, because
  // the repeater mounts with its handover prop already set or it mounts with nothing to load. Adding
  // a close here would be this modal changing a flag the parent is changing in the same breath, which
  // is a second writer to one piece of state for no gain. See handleOpenRawRequestInRepeater in
  // App.js, and the longer note above handleOpenCaptureInRepeater next to it.
  // Null, not a no-op function, when the parent did not wire it up: the button hides on a falsy
  // handler, and a handler that silently does nothing would render a button that silently does
  // nothing.
  const sendToRepeater = useMemo(
    () => (onSendToRepeater ? (payload) => onSendToRepeater(payload) : null),
    [onSendToRepeater],
  );

  const setTriage = async (id, triage) => {
    // Updated locally first so the badge responds immediately; a triage call that fails reloads and
    // puts the truth back rather than leaving the screen showing something the server did not store.
    setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, triage } : f)));
    try {
      const res = await fetch(`/api/${category}/finding/${id}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ triage }),
      });
      if (!res.ok) await load();
    } catch {
      await load();
    }
  };

  const points = useMemo(
    () => [...new Set(findings.map((f) => f.insertion_point).filter(Boolean))].sort(),
    [findings],
  );
  const kinds = useMemo(
    () => [...new Set(findings.map((f) => f.kind).filter(Boolean))].sort(),
    [findings],
  );

  const shown = useMemo(() => findings.filter((f) => (
    (!pointFilter || f.insertion_point === pointFilter)
    && (!kindFilter || f.kind === kindFilter)
    && (!triageFilter || (f.triage || 'new') === triageFilter)
  )), [findings, pointFilter, kindFilter, triageFilter]);

  const skippedByReason = useMemo(() => {
    const groups = {};
    skipped.forEach((s) => {
      const key = s.reason || 'No reason recorded.';
      (groups[key] = groups[key] || []).push(s);
    });
    return Object.entries(groups).sort((a, b) => b[1].length - a[1].length);
  }, [skipped]);

  const eligibility = status?.eligibility;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">{tool?.name || 'XSS'} findings</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ minHeight: '60vh' }}>
        {loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : (
          <>
            {error && <Alert variant="danger" className="py-2">{error}</Alert>}

            {eligibility && (
              <div className="mb-3 d-flex gap-4 flex-wrap align-items-baseline">
                <div>
                  <div className="text-white" style={{ fontSize: '1.6rem', fontWeight: 600, lineHeight: 1 }}>
                    {findings.length}
                  </div>
                  <div className="text-white-50" style={{ fontSize: '0.72rem' }}>findings</div>
                </div>
                <div>
                  <div className="text-white" style={{ fontSize: '1.6rem', fontWeight: 600, lineHeight: 1 }}>
                    {eligibility.eligible}
                    <span className="text-white-50" style={{ fontSize: '1rem' }}>
                      /{eligibility.total}
                    </span>
                  </div>
                  <div className="text-white-50" style={{ fontSize: '0.72rem' }}>vectors tested</div>
                </div>
                {skipped.length > 0 && (
                  <div>
                    <div className="text-warning" style={{ fontSize: '1.6rem', fontWeight: 600, lineHeight: 1 }}>
                      {skipped.length}
                    </div>
                    <div className="text-white-50" style={{ fontSize: '0.72rem' }}>never tested</div>
                  </div>
                )}
              </div>
            )}

            {/* THE VERDICT, above everything, because it decides what the numbers below are worth.
                A run that stopped partway and a run that finished and found nothing both render as
                "0 findings", and only one of them is a result. */}
            {/* The positive control. Shown whether or not it fired, because a control that is only
                mentioned on failure teaches people to read silence as success, which is the same
                mistake as reading "0 findings" as "0 vulnerabilities".
                Its hits are NOT in the findings list and never should have been: they are hits on
                the framework's own oracle container, not on this target. */}
            {canary && (
              <div className="p-2 mb-3 rounded d-flex align-items-start gap-2" style={{
                background: canary.fired ? 'rgba(25,135,84,0.10)' : 'rgba(255,193,7,0.10)',
                border: '1px solid ' + (canary.fired ? 'rgba(25,135,84,0.4)' : 'rgba(255,193,7,0.45)'),
                fontSize: '0.75rem',
              }}>
                <Badge bg={canary.fired ? 'success' : 'warning'} style={{ flexShrink: 0 }}>
                  {canary.fired ? 'Control fired' : 'No control hit'}
                </Badge>
                <span className="text-white-50">
                  {canary.meaning}
                  {canary.hit_count > 0 && (
                    <> {canary.hit_count} control hit(s) against {canary.host} are excluded from the
                    findings below.</>
                  )}
                </span>
              </div>
            )}

            {scan && scan.verdict === 'unverified' && (
              <div className="p-3 mb-3 rounded" style={{
                background: 'rgba(220,53,69,0.12)', border: '1px solid rgba(220,53,69,0.5)',
              }}>
                <div className="text-danger mb-2" style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                  This scan is UNVERIFIED, not clean
                </div>
                {scan.error && (
                  <div className="text-white" style={{ fontSize: '0.82rem' }}>{scan.error}</div>
                )}
                {!scan.error && untested.length > 0 && (
                  <div className="text-white" style={{ fontSize: '0.82rem' }}>
                    {untested.length} vector(s) were never completed, so their results are unknown
                    rather than clean. Re-run before treating this tool's output as coverage.
                  </div>
                )}
              </div>
            )}
            {scan && scan.verdict === 'clean' && findings.length === 0 && (
              <div className="p-3 mb-3 rounded" style={{
                background: 'rgba(25,135,84,0.10)', border: '1px solid rgba(25,135,84,0.4)',
              }}>
                <div className="text-success" style={{ fontSize: '0.85rem' }}>
                  This run finished every vector it was given and found nothing. That is a real
                  negative for the vectors it covered, which is not the same as the whole target:
                  check the Not tested tab for what it could never reach.
                </div>
              </div>
            )}

            <Nav variant="tabs" activeKey={tab} onSelect={(k) => k && setTab(k)} className="mb-3">
              <Nav.Item>
                <Nav.Link eventKey="findings">Findings ({findings.length})</Nav.Link>
              </Nav.Item>
              <Nav.Item>
                <Nav.Link eventKey="skipped">Not tested ({skipped.length})</Nav.Link>
              </Nav.Item>
              {untested.length > 0 && (
                <Nav.Item>
                  <Nav.Link eventKey="untested" className="text-danger">
                    Unknown ({untested.length})
                  </Nav.Link>
                </Nav.Item>
              )}
              <Nav.Item>
                <Nav.Link eventKey="traces">What ran ({traces.length})</Nav.Link>
              </Nav.Item>
            </Nav>

            {tab === 'untested' && (
              <>
                <div className="text-white-50 mb-3" style={{ fontSize: '0.8rem' }}>
                  These vectors were eligible and were going to be tested, and then the run stopped.
                  They are not skipped and they are not clean: nothing is known about them at all.
                  This is different from the Not tested tab, which lists vectors {tool?.name} could
                  never have reached in the first place.
                </div>
                <Accordion alwaysOpen>
                  {untested.map((u, i) => (
                    <Accordion.Item eventKey={String(i)} key={u.vector_id || u.target_url || i}>
                      <Accordion.Header>
                        <div className="d-flex align-items-center gap-2 w-100 pe-3">
                          <Badge bg="danger">unknown</Badge>
                          <span style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
                            {u.method} {u.domain}{u.path} {u.insertion_point && `(${u.insertion_point})`}
                          </span>
                        </div>
                      </Accordion.Header>
                      <Accordion.Body className="bg-dark">
                        <div className="text-white" style={{ fontSize: '0.82rem' }}>{u.reason}</div>
                      </Accordion.Body>
                    </Accordion.Item>
                  ))}
                </Accordion>
              </>
            )}

            {/* EXACTLY WHAT WE RAN. Every defect this section has had was diagnosed by re-running a
                tool by hand to see what it printed. The output used to be discarded the moment it
                was parsed, so this tab is the difference between a thirty second read and an
                afternoon of reconstruction. */}
            {tab === 'traces' && (
              traces.length === 0 ? (
                /* "No runs" used to be ambiguous between a run that never happened and one whose
                   output had been pruned, because pruning deleted the row. It no longer does: a
                   pruned run keeps its row and is badged below. So an empty list now means one
                   thing, and this says which. */
                <div className="text-white-50 py-4 text-center" style={{ fontSize: '0.85rem' }}>
                  No commands were executed for this scan. Retention never removes a row, only the
                  captured output, so this is not aged-out history: nothing ran. Check the Skipped
                  and Untested tabs for the reason.
                </div>
              ) : (
                <>
                  <div className="text-white-50 mb-3" style={{ fontSize: '0.8rem' }}>
                    One row per command actually executed, in order, with what came back. A scan that
                    finished suspiciously fast, or whose every row exited non-zero, did not test what
                    it appears to have tested.
                  </div>
                  <Accordion alwaysOpen>
                    {traces.map((t, i) => (
                      <Accordion.Item eventKey={String(i)} key={t.id}>
                        <Accordion.Header>
                          <div className="d-flex align-items-center gap-2 w-100 pe-3 flex-wrap">
                            <Badge bg={t.exit_detail && t.exit_detail.startsWith('0') ? 'secondary' : 'warning'}
                              text={t.exit_detail && t.exit_detail.startsWith('0') ? undefined : 'dark'}>
                              {t.timed_out ? 'timed out' : (t.exit_detail || 'exited').split(',')[0]}
                            </Badge>
                            {t.stdout_pruned && (
                              <Badge bg="dark" text="light">output aged out</Badge>
                            )}
                            <span className="text-white-50" style={{ fontSize: '0.75rem' }}>
                              {Math.round((t.duration_ms || 0) / 100) / 10}s, {t.stdout_bytes} bytes
                              {t.attempt > 1 && `, attempt ${t.attempt}`}
                              {t.run_label && `, ${t.run_label}`}
                            </span>
                            <span className="text-info" style={{ fontSize: '0.72rem', wordBreak: 'break-all' }}>
                              {t.target_url}
                            </span>
                          </div>
                        </Accordion.Header>
                        <Accordion.Body className="bg-dark">
                          <CopyBlock label="COMMAND" value={t.command} colour="#9ae6b4"
                            hint="Paste into a shell to re-run exactly what the framework ran." />
                          {openTrace && openTrace.id === t.id ? (
                            <CopyBlock label="OUTPUT" value={openTrace.stdout || '(no output)'}
                              hint={openTrace.stdout_truncated
                                ? 'Long output: the middle was dropped, both ends kept.' : undefined} />
                          ) : (
                            <Button variant="outline-secondary" size="sm" onClick={async () => {
                              try {
                                const res = await fetch(`/api/${category}/trace/${t.id}`);
                                if (res.ok) setOpenTrace(await res.json());
                              } catch (err) { /* the command above is still readable */ }
                            }}>
                              {t.stdout_pruned
                                ? `Output aged out (was ${t.stdout_bytes} bytes)`
                                : `Load output (${t.stdout_bytes} bytes)`}
                            </Button>
                          )}
                        </Accordion.Body>
                      </Accordion.Item>
                    ))}
                  </Accordion>
                </>
              )
            )}

            {tab === 'findings' && (
              <>
                <div className="d-flex gap-2 mb-3 flex-wrap">
                  <Form.Select
                    size="sm" style={{ maxWidth: '180px' }}
                    value={pointFilter} onChange={(e) => setPointFilter(e.target.value)}
                  >
                    <option value="">All insertion points</option>
                    {points.map((p) => <option key={p} value={p}>{p}</option>)}
                  </Form.Select>
                  <Form.Select
                    size="sm" style={{ maxWidth: '220px' }}
                    value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}
                  >
                    <option value="">All confidence classes</option>
                    {kinds.map((k) => (
                      <option key={k} value={k}>{kindPresentation(k).label}</option>
                    ))}
                  </Form.Select>
                  <Form.Select
                    size="sm" style={{ maxWidth: '160px' }}
                    value={triageFilter} onChange={(e) => setTriageFilter(e.target.value)}
                  >
                    <option value="">All triage</option>
                    {TRIAGE_ORDER.map((t) => <option key={t} value={t}>{t}</option>)}
                  </Form.Select>
                </div>

                {/* The legend covers only the classes actually present, so it stays short and never
                    explains a class this scan did not produce. It exists because the difference
                    between "could execute" and "did execute" decides whether a row is worth an
                    hour, and that difference used to be a single letter. */}
                {kinds.length > 0 && (
                  <div
                    className="mb-3 p-2 rounded"
                    style={{ background: 'rgba(255,255,255,0.04)', fontSize: '0.72rem' }}
                  >
                    <div className="text-white-50 mb-1">What these classes claim:</div>
                    {kinds.map((k) => {
                      const p = kindPresentation(k);
                      return (
                        <div key={k} className="d-flex align-items-start gap-2 mb-1">
                          <Badge bg={p.bg} style={{ flexShrink: 0 }}>
                            {p.label}{p.code ? ` (${p.code})` : ''}
                          </Badge>
                          <span className="text-white-50">
                            {p.detail || 'Reported by the tool under this class.'}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}

                {shown.length === 0 ? (
                  <div className="text-white-50 py-4 text-center" style={{ fontSize: '0.85rem' }}>
                    {findings.length === 0
                      ? `No findings recorded. ${skipped.length > 0
                        ? `Check the Not tested tab: ${skipped.length} vectors were never sent.`
                        : ''}`
                      : 'No findings match these filters.'}
                  </div>
                ) : (
                  <Accordion alwaysOpen>
                    {shown.map((f, i) => {
                      const kind = kindPresentation(f.kind);
                      const triage = f.triage || 'new';
                      return (
                        <Accordion.Item eventKey={String(i)} key={f.id}>
                          <Accordion.Header>
                            <div className="d-flex align-items-center gap-2 flex-wrap w-100 pe-3">
                              <Badge bg={kind.bg} title={kind.detail || undefined}>
                                {kind.label}{kind.code ? ` (${kind.code})` : ''}
                              </Badge>
                              <Badge bg="dark" className="border border-secondary text-white-50">
                                {f.insertion_point}
                              </Badge>
                              {f.param && (
                                <code className="text-danger" style={{ fontSize: '0.78rem' }}>
                                  {f.param}
                                </code>
                              )}
                              <span className="text-white-50" style={{ fontSize: '0.78rem' }}>
                                {f.method} {f.domain}{f.vector_path}
                              </span>
                              <Badge
                                bg={triage === 'interesting' ? 'warning' : triage === 'dismissed' ? 'dark' : 'secondary'}
                                className="ms-auto"
                              >
                                {triage}
                              </Badge>
                            </div>
                          </Accordion.Header>
                          <Accordion.Body>
                            <div className="mb-2 text-white" style={{ fontSize: '0.82rem' }}>
                              {f.kind_label}
                            </div>
                            {f.confidence && (
                              <div className="text-white-50 mb-2" style={{ fontSize: '0.75rem' }}>
                                {f.confidence}
                                {f.detection_method ? ` (${f.detection_method})` : ''}
                                {f.inject_type ? ` in ${f.inject_type}` : ''}
                              </div>
                            )}
                            {f.payload && (
                              <pre
                                className="p-2 rounded mb-2"
                                style={{
                                  background: 'rgba(0,0,0,0.35)', color: '#ff8a95',
                                  fontSize: '0.75rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                }}
                              >{f.payload}</pre>
                            )}
                            {f.url && (
                              <div className="text-white-50 mb-2" style={{ fontSize: '0.72rem', wordBreak: 'break-all' }}>
                                {f.url}
                              </div>
                            )}
                            {f.evidence && (
                              <div className="text-white-50 mb-3" style={{ fontSize: '0.75rem' }}>
                                {f.evidence}
                              </div>
                            )}
                            <Explain
                              explain={f.explain}
                              showSteps={!(f.reproduction && f.reproduction.steps
                                && f.reproduction.steps.length > 0)}
                            />
                            <Reproduce repro={f.reproduction} />
                            <div className="d-flex align-items-center justify-content-between mb-1 gap-2">
                              <span className="text-white-50" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                                WHAT THE SCANNER ACTUALLY SENT AND RECEIVED
                              </span>
                              {/* Here rather than down with the triage buttons: the operator decides
                                  to re-send after reading the request, and this is where they are
                                  when they decide it. */}
                              <SendToReplay finding={f} onSend={sendToRepeater} />
                            </div>
                            <Exchange request={f.raw_request} response={f.raw_response} />
                            <div className="d-flex gap-2 mt-3">
                              {TRIAGE_ORDER.map((t) => (
                                <Button
                                  key={t} size="sm"
                                  variant={triage === t ? 'danger' : 'outline-secondary'}
                                  onClick={() => setTriage(f.id, t)}
                                >
                                  {t}
                                </Button>
                              ))}
                            </div>
                          </Accordion.Body>
                        </Accordion.Item>
                      );
                    })}
                  </Accordion>
                )}
              </>
            )}

            {tab === 'skipped' && (
              skipped.length === 0 ? (
                <div className="text-white-50 py-4 text-center" style={{ fontSize: '0.85rem' }}>
                  Every attack vector was tested by {tool?.name}.
                </div>
              ) : (
                <>
                  <div className="text-white-50 mb-3" style={{ fontSize: '0.8rem' }}>
                    These vectors were never sent, so they are not clean, they are unknown. Grouped by
                    the reason {tool?.name} could not reach them.
                  </div>
                  <Accordion alwaysOpen>
                    {skippedByReason.map(([reason, rows], i) => (
                      <Accordion.Item eventKey={String(i)} key={reason}>
                        <Accordion.Header>
                          <div className="d-flex align-items-center gap-2 w-100 pe-3">
                            <Badge bg="warning" text="dark">{rows.length}</Badge>
                            <span className="text-white-50" style={{ fontSize: '0.8rem' }}>
                              {reason}
                            </span>
                          </div>
                        </Accordion.Header>
                        <Accordion.Body>
                          {rows.map((s) => (
                            <div
                              key={s.vector_id}
                              className="d-flex gap-2 align-items-baseline py-1"
                              style={{ fontSize: '0.76rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}
                            >
                              <Badge bg="dark" className="border border-secondary text-white-50">
                                {s.insertion_point}
                              </Badge>
                              <span className="text-white-50">{s.method}</span>
                              <span className="text-white-50" style={{ wordBreak: 'break-all' }}>
                                {s.domain}{s.path}
                              </span>
                            </div>
                          ))}
                        </Accordion.Body>
                      </Accordion.Item>
                    ))}
                  </Accordion>
                </>
              )
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={load} disabled={loading}>Refresh</Button>
        <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
}

export default VectorToolResultsModal;
