import { useState, useEffect, useMemo, useCallback } from 'react';
import { Modal, Button, Badge, Tabs, Tab, Alert, Spinner, Form, InputGroup,
         Table, Accordion, ListGroup } from 'react-bootstrap';
import VirtualizedList from '../components/VirtualizedList';

// Results for the combined endpoint scan.
//
// Validate leads, and not for cosmetic reasons. Investigate's output is only worth as much as the
// verdicts it selected on: a thousand richly enriched endpoints mean nothing if they are a thousand
// copies of one login page. So the first screen answers "can I trust these verdicts", and the
// calibration panel is deliberately above the endpoint list rather than buried in a details tab.
//
// Nothing here is a summary of a summary. Every count is clickable through to the rows behind it,
// because a verdict an operator cannot open is a verdict they have to take on faith.

const STATUS_META = {
  valid: {
    variant: 'success',
    label: 'Valid',
    blurb: 'A distinct resource that exists. Worth testing.',
  },
  unverified: {
    variant: 'warning',
    label: 'Unverified',
    blurb: 'Could not be told apart either way. Kept, and still tested downstream.',
  },
  ruled_out: {
    variant: 'secondary',
    label: 'Ruled out',
    blurb: 'Measured against a control and found to be this target’s catch-all, or gone.',
  },
  skipped: {
    variant: 'dark',
    label: 'Skipped',
    blurb: 'Never requested. Static assets, and paths a GET would change state on.',
  },
};

// Short labels for the reason codes. The full sentence lives on every row; this is for the
// breakdown table, where twenty raw codes read as noise.
const REASON_LABEL = {
  'valid.distinct': 'Content differs from the not-found control',
  'valid.auth_required': 'Behind authentication, which proves it exists',
  'valid.method_confirmed': 'The verb was confirmed without being sent',
  'ruled_out.hard_404': 'Real 404 from a target that uses real 404s',
  'ruled_out.gone': 'Answered 410 Gone',
  'ruled_out.catch_all': 'Identical to the not-found control for its own directory',
  'ruled_out.soft_404_echo': 'Answered 200 with the not-found body',
  'ruled_out.canonical_redirect': 'Redirects to the same path on the canonical host',
  'unverified.unreachable': 'The request did not complete',
  'unverified.rate_limited': 'The target throttled this run, so nothing was learned',
  'unverified.blocked': 'A WAF answered, so the application was never reached',
  'unverified.login_wall': 'The login page came back, which is about the session not the endpoint',
  'unverified.pending_auth': 'Behind a login and this run had no credentials',
  'unverified.spa_shell_ambiguous': 'Client-routed app: the server hands every path the same shell',
  'unverified.indistinguishable': 'The probe could not tell this target’s 404 from real content',
  'unverified.local_oracle_unstable': 'The directory’s control disagreed with itself',
  'unverified.opaque_body': 'Binary response, never fingerprinted from its contents',
  'unverified.unsafe_method': 'Records a write verb, which is never sent',
  'unverified.budget_exhausted': 'The run stopped before reaching it',
  'skipped.static_asset': 'Static asset, not measured',
  'skipped.destructive_heuristic': 'Requesting it would change state on the target',
  'skipped.out_of_scope': 'On another host, outside this scope target, so never requested',
};

const CONFIDENCE_META = {
  measured: { variant: 'success', help: 'This run observed it directly.' },
  inferred: { variant: 'info', help: 'Derived from something measured, but not re-verified.' },
  assumed: { variant: 'secondary', help: 'A conservative default. Not a measurement.' },
};

const SEVERITY = { p0: 'danger', p1: 'warning', p2: 'info', p3: 'secondary' };

const METHOD_VARIANT = {
  GET: 'primary', POST: 'success', PUT: 'warning',
  PATCH: 'warning', DELETE: 'danger', OPTIONS: 'info', HEAD: 'secondary',
};

// The calibration block, rendered as claims rather than as key/value pairs. "spa_shell: true" tells
// an operator nothing; "the server hands every path the same shell" tells them why two hundred rows
// came back unverified.
const describeCalibration = (cal) => {
  if (!cal || Object.keys(cal).length === 0) return [];
  const out = [];

  if (cal.baseline_ms) {
    out.push({ ok: true, text: `The base URL answered in ${cal.baseline_ms}ms, measured over three requests.` });
  }
  // Two different numbers, and saying so matters: an abort used to quote the base-URL figure while
  // comparing against something else entirely, which made the reason unarguable in the wrong way.
  if (cal.working_baseline_ms) {
    out.push({
      ok: true,
      text: `Under its own traffic this run measured a median of ${cal.working_baseline_ms}ms across ` +
            `the endpoints themselves. That is what "has this target slowed down" was judged against, ` +
            `not the base URL, which on a CDN-fronted app is a static shell and far faster than a real route.`,
    });
  } else if (cal.baseline_ms) {
    out.push({
      ok: true,
      text: 'The run was too short to establish a working latency baseline, so no slow-down rule ' +
            'could fire. Rate limiting and transport failures were still watched for.',
    });
  }
  out.push(cal.not_found_measured
    ? { ok: true, text: `A not-found reference was measured under this run’s own recipe (${cal.not_found_status || '?'}, ${cal.not_found_size || 0} bytes). Rule-outs are compared against it, not against the probe’s numbers.` }
    : { ok: false, text: 'No not-found reference could be measured, so every rule-out in this run is inferred rather than measured.' });

  if (cal.spa_shell) {
    out.push({ ok: false, text: 'Paths that cannot exist return the same HTML shell as the home page. This target routes in the browser, so server-side path enumeration cannot distinguish anything: HTML responses are reported as indistinguishable and kept. Its real surface is the JSON and script traffic.' });
  }
  if (cal.login_fingerprinted) {
    out.push({ ok: true, text: 'The login page was fingerprinted, so responses that are really a login wall are reported as such instead of as content.' });
  }
  {
    // Three states, not two. Null means the run could not tell, which is not the same as deciding
    // the session is dead, and saying so was wrong on every target whose root is a static shell.
    const probe = cal.credentials_probe_url ? ` (${cal.credentials_probe_url})` : '';
    if (cal.credentials_honoured === true) {
      out.push({ ok: true, text: `Credentialed and anonymous requests differed${probe}, so the saved session is being honoured.` });
    } else if (cal.credentials_honoured === false) {
      out.push({ ok: false, text: `Credentialed and anonymous requests returned the same page${probe}, so the saved session is probably not being honoured. Anything behind authentication is unverified rather than ruled out.` });
    } else if (cal.credentials_probe_url) {
      out.push({ ok: true, text: 'Whether the saved session is honoured could not be established: the only available probe was the base URL, which returns the same shell for every path on this target and so cannot differ by credential either. Credentials were still attached to every request. Once this run has recorded a route that refuses anonymous callers, the next run can test it properly.' });
    }
  }
  if (cal.scope) {
    out.push({
      ok: true,
      text: `Requests were confined to ${cal.scope}` +
            (cal.out_of_scope_hosts
              ? `. ${cal.out_of_scope_hosts} other host(s) appear in the corpus and were recorded ` +
                'without being contacted: an engagement for one target does not authorise sending ' +
                'traffic to a third party.'
              : '.'),
    });
  }
  if (cal.control_cap_hit) {
    out.push({
      ok: false,
      text: `${cal.control_cap_hit} endpoint(s) arrived after the per-directory not-found oracle hit ` +
            'its limit and were compared against the global not-found response instead. That is a ' +
            'weaker comparison, so those verdicts lean towards indistinguishable rather than ruled out.',
    });
  }
  if (typeof cal.control_families === 'number') {
    out.push({
      ok: (cal.unstable_families || 0) === 0,
      text: `${cal.control_families} directory-level not-found control${cal.control_families === 1 ? '' : 's'} measured` +
            ((cal.unstable_families || 0) > 0
              ? `, and ${cal.unstable_families} director${cal.unstable_families === 1 ? 'y' : 'ies'} whose control disagreed with itself. Endpoints in those have no oracle and were left unverified.`
              : '. Each endpoint was compared against a control from its own directory.'),
    });
  }
  return out;
};

const StatusBadge = ({ status }) => {
  const meta = STATUS_META[status] || { variant: 'secondary', label: status };
  return <Badge bg={meta.variant}>{meta.label}</Badge>;
};

const EndpointScanResultsModal = ({ show, handleClose, scopeTargetId }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('validate');

  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [reasonFilter, setReasonFilter] = useState('');
  // Expanded rows live here rather than in the row component: VirtualizedList unmounts rows that
  // scroll out of view, so row-local state would silently reset.
  const [expanded, setExpanded] = useState({});
  const [investigateSearch, setInvestigateSearch] = useState('');
  const [expandedFindings, setExpandedFindings] = useState({});

  const load = useCallback(async () => {
    if (!scopeTargetId) return;
    setLoading(true);
    setError('');
    try {
      const resp = await fetch(`/api/endpoint-scan/${scopeTargetId}/results`);
      if (!resp.ok) throw new Error(await resp.text() || 'Failed to load results');
      setData(await resp.json());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (show) {
      setExpanded({});
      setExpandedFindings({});
      load();
    }
  }, [show, load]);

  const validation = data?.validation || null;
  const rows = useMemo(() => data?.validation_results || [], [data]);
  const investigation = data?.investigation || null;

  const counts = useMemo(() => validation?.counts || {}, [validation]);
  const totalJudged = useMemo(
    () => Object.values(counts).reduce((a, b) => a + b, 0), [counts]);

  // Reason codes, ordered by how many endpoints they account for. The long tail is where the
  // interesting refusals live, but the operator needs the bulk explained first.
  const reasonBreakdown = useMemo(() => {
    const acc = {};
    rows.forEach((r) => {
      const key = r.reason_code || 'unknown';
      if (!acc[key]) acc[key] = { code: key, status: r.status, count: 0, measured: 0 };
      acc[key].count += 1;
      if (r.confidence === 'measured') acc[key].measured += 1;
    });
    return Object.values(acc).sort((a, b) => b.count - a.count);
  }, [rows]);

  const filteredRows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return rows.filter((r) => {
      if (statusFilter !== 'all' && r.status !== statusFilter) return false;
      if (reasonFilter && r.reason_code !== reasonFilter) return false;
      if (!needle) return true;
      return (r.url || '').toLowerCase().includes(needle) ||
             (r.method || '').toLowerCase().includes(needle) ||
             (r.reason_code || '').toLowerCase().includes(needle) ||
             (r.title || '').toLowerCase().includes(needle);
    });
  }, [rows, search, statusFilter, reasonFilter]);

  const calibrationClaims = useMemo(
    () => describeCalibration(validation?.calibration), [validation]);

  const investigatedEndpoints = useMemo(
    () => investigation?.endpoints || [], [investigation]);

  const filteredInvestigated = useMemo(() => {
    const needle = investigateSearch.trim().toLowerCase();
    if (!needle) return investigatedEndpoints;
    return investigatedEndpoints.filter((e) =>
      (e.url || '').toLowerCase().includes(needle) ||
      (e.title || '').toLowerCase().includes(needle) ||
      (e.signals || []).some((s) => (s.title || '').toLowerCase().includes(needle)));
  }, [investigatedEndpoints, investigateSearch]);

  const runStatusVariant = {
    success: 'success', partial: 'warning', aborted: 'danger', error: 'danger',
    running: 'info', pending: 'secondary',
  }[data?.status] || 'secondary';

  const toggle = (key) => setExpanded((prev) => ({ ...prev, [key]: !prev[key] }));

  // ---------------------------------------------------------------- rows

  const renderValidationRow = (row, index) => {
    const key = `${row.method}|${row.url}|${index}`;
    const isOpen = !!expanded[key];
    const conf = CONFIDENCE_META[row.confidence] || CONFIDENCE_META.assumed;

    return (
      <div
        className="border-bottom border-secondary px-2 py-2"
        style={{ cursor: 'pointer' }}
        onClick={() => toggle(key)}
      >
        <div className="d-flex align-items-center gap-2 flex-wrap">
          <Badge bg={METHOD_VARIANT[row.method] || 'secondary'} style={{ minWidth: '60px' }}>
            {row.method}
          </Badge>
          <StatusBadge status={row.status} />
          <span className="text-white font-monospace small text-break flex-grow-1"
                style={{ minWidth: '200px' }}>
            {row.url}
          </span>
          {row.http_status > 0 && (
            <Badge bg="dark" className="border border-secondary">{row.http_status}</Badge>
          )}
          {row.testable === false && (
            <Badge bg="dark" className="border border-secondary" title="Excluded from downstream testing">
              untestable
            </Badge>
          )}
          {(row.flags || []).map((f) => (
            <Badge key={f} bg="dark" className="border border-warning text-warning">{f}</Badge>
          ))}
        </div>

        <div className="d-flex align-items-center gap-2 mt-1 flex-wrap">
          <span className="text-muted" style={{ fontSize: '0.7rem' }}>
            {REASON_LABEL[row.reason_code] || row.reason_code}
          </span>
          <Badge bg={conf.variant} style={{ fontSize: '0.6rem' }}>{row.confidence}</Badge>
          {row.response_size > 0 && (
            <span className="text-muted" style={{ fontSize: '0.68rem' }}>
              {row.response_size} bytes · {row.response_ms}ms
            </span>
          )}
        </div>

        {isOpen && (
          <div className="mt-2 ps-2 border-start border-secondary">
            <div className="text-white-50 small mb-2">{row.reason}</div>
            <Table size="sm" borderless className="mb-0" style={{ fontSize: '0.72rem' }}>
              <tbody className="text-muted">
                <tr>
                  <td style={{ width: '150px' }}>Rule fired</td>
                  <td className="font-monospace text-white-50">{row.rule_fired || '-'}</td>
                </tr>
                <tr>
                  <td>Reason code</td>
                  <td className="font-monospace text-white-50">{row.reason_code}</td>
                </tr>
                <tr>
                  <td>Confidence</td>
                  <td className="text-white-50">{row.confidence} · {conf.help}</td>
                </tr>
                <tr>
                  <td>Would disprove it</td>
                  <td className="text-white-50">{row.falsifier || '-'}</td>
                </tr>
                {row.control_url && (
                  <tr>
                    <td>Compared against</td>
                    <td className="font-monospace text-white-50 text-break">{row.control_url}</td>
                  </tr>
                )}
                {row.location && (
                  <tr>
                    <td>Redirects to</td>
                    <td className="font-monospace text-white-50 text-break">{row.location}</td>
                  </tr>
                )}
                {row.title && (
                  <tr><td>Title</td><td className="text-white-50">{row.title}</td></tr>
                )}
                {row.content_type && (
                  <tr><td>Content type</td><td className="text-white-50">{row.content_type}</td></tr>
                )}
              </tbody>
            </Table>
          </div>
        )}
      </div>
    );
  };

  const renderInvestigatedRow = (ep, index) => {
    const key = `inv|${ep.endpoint_id || ep.url}|${index}`;
    const isOpen = !!expandedFindings[key];
    const signals = ep.signals || [];

    return (
      <div
        className="border-bottom border-secondary px-2 py-2"
        style={{ cursor: 'pointer' }}
        onClick={() => setExpandedFindings((p) => ({ ...p, [key]: !p[key] }))}
      >
        <div className="d-flex align-items-center gap-2 flex-wrap">
          <Badge bg={METHOD_VARIANT[ep.method] || 'secondary'} style={{ minWidth: '60px' }}>
            {ep.method}
          </Badge>
          <span className="text-white font-monospace small text-break flex-grow-1"
                style={{ minWidth: '200px' }}>
            {ep.url}
          </span>
          {ep.status_code > 0 && (
            <Badge bg="dark" className="border border-secondary">{ep.status_code}</Badge>
          )}
          {signals.length > 0 && (
            <Badge bg={signals.some((s) => s.severity === 'p0') ? 'danger'
                     : signals.some((s) => s.severity === 'p1') ? 'warning' : 'info'}>
              {signals.length} signal{signals.length === 1 ? '' : 's'}
            </Badge>
          )}
          <span className="text-muted" style={{ fontSize: '0.68rem' }}>
            score {ep.interest_score ?? 0}
          </span>
        </div>

        {(ep.title || ep.verb_not_replayed || !ep.authenticated) && (
          <div className="d-flex gap-2 mt-1 flex-wrap align-items-center">
            {ep.title && (
              <span className="text-muted" style={{ fontSize: '0.7rem' }}>{ep.title}</span>
            )}
            {ep.verb_not_replayed && (
              <Badge bg="dark" className="border border-warning text-warning"
                     title="The recorded verb was characterised with GET, never sent">
                {ep.verb_not_replayed} not sent
              </Badge>
            )}
            {!ep.authenticated && (
              <Badge bg="dark" className="border border-secondary text-muted">unauthenticated</Badge>
            )}
          </div>
        )}

        {isOpen && (
          <div className="mt-2 ps-2 border-start border-secondary">
            {signals.length === 0 && (
              <div className="text-muted small">
                Nothing specific to this endpoint. Anything true of most of the corpus was rolled
                up to the target findings above.
              </div>
            )}
            {signals.map((s, i) => (
              <div key={`${s.dedupe_key}|${i}`} className="mb-2">
                <div className="d-flex align-items-center gap-2">
                  <Badge bg={SEVERITY[s.severity] || 'secondary'}>{s.severity}</Badge>
                  <span className="text-white small">{s.title}</span>
                  <Badge bg="dark" className="border border-secondary text-muted"
                         style={{ fontSize: '0.6rem' }}>
                    {s.confidence}
                  </Badge>
                </div>
                <div className="text-white-50 ps-2" style={{ fontSize: '0.72rem' }}>{s.detail}</div>
                {s.evidence && (
                  <div className="text-muted font-monospace ps-2 text-break"
                       style={{ fontSize: '0.68rem' }}>
                    {s.evidence}
                  </div>
                )}
              </div>
            ))}

            {(ep.technologies || []).length > 0 && (
              <div className="mt-2">
                <span className="text-muted" style={{ fontSize: '0.7rem' }}>Technologies: </span>
                {ep.technologies.map((t) => (
                  <Badge key={t} bg="dark" className="border border-secondary me-1">{t}</Badge>
                ))}
              </div>
            )}
            {(ep.security_headers?.missing || []).length > 0 && (
              <div className="mt-1">
                <span className="text-muted" style={{ fontSize: '0.7rem' }}>Missing headers: </span>
                <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
                  {ep.security_headers.missing.join(', ')}
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  // ---------------------------------------------------------------- render

  const hasRun = data && data.status !== 'not_run';

  return (
    <Modal show={show} onHide={handleClose} size="xl" data-bs-theme="dark" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Endpoint Scan Results
          {hasRun && (
            <Badge bg={runStatusVariant} className="ms-3 align-middle" style={{ fontSize: '0.7rem' }}>
              {data.status}
            </Badge>
          )}
          {data?.execution_time && (
            <span className="text-muted ms-2" style={{ fontSize: '0.7rem' }}>
              {data.execution_time}
            </span>
          )}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body>
        {loading && (
          <div className="text-center py-5">
            <Spinner animation="border" variant="danger" />
          </div>
        )}
        {error && <Alert variant="danger">{error}</Alert>}

        {!loading && !error && !hasRun && (
          <Alert variant="secondary">
            No endpoint scan has run for this target yet. Consolidate, then click Investigate.
          </Alert>
        )}

        {!loading && !error && hasRun && (
          <>
            {data.error && <Alert variant="danger" className="py-2 small">{data.error}</Alert>}
            {data.note && <Alert variant="warning" className="py-2 small">{data.note}</Alert>}

            <Tabs activeKey={activeTab} onSelect={(k) => setActiveTab(k)} className="mb-3">
              {/* ------------------------------------------------ Validate */}
              <Tab eventKey="validate" title={
                <span>Validate {totalJudged > 0 && (
                  <Badge bg="danger" className="ms-1">{totalJudged}</Badge>)}</span>
              }>
                {!validation || validation.status === 'not_run' ? (
                  <Alert variant="secondary">This run has no validation phase recorded.</Alert>
                ) : (
                  <>
                    <div className="d-flex gap-2 mb-3 flex-wrap">
                      {['valid', 'unverified', 'ruled_out', 'skipped'].map((s) => {
                        const meta = STATUS_META[s];
                        const active = statusFilter === s;
                        return (
                          <div
                            key={s}
                            className={`flex-fill border rounded p-2 ${active ? 'border-danger' : 'border-secondary'}`}
                            style={{ cursor: 'pointer', minWidth: '150px' }}
                            onClick={() => { setStatusFilter(active ? 'all' : s); setReasonFilter(''); }}
                          >
                            <div className={`fw-bold fs-4 text-${meta.variant}`}>
                              {counts[s] ?? 0}
                            </div>
                            <div className="text-white small">{meta.label}</div>
                            <div className="text-muted" style={{ fontSize: '0.66rem' }}>
                              {meta.blurb}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* The trust panel. Everything above is only as good as what is in here. */}
                    <Accordion defaultActiveKey="0" className="mb-3">
                      <Accordion.Item eventKey="0">
                        <Accordion.Header>
                          What this run could and could not establish
                          {(validation.assumptions || []).length > 0 && (
                            <Badge bg="warning" className="ms-2">
                              {validation.assumptions.length} assumption
                              {validation.assumptions.length === 1 ? '' : 's'}
                            </Badge>
                          )}
                        </Accordion.Header>
                        <Accordion.Body>
                          <ListGroup variant="flush">
                            {calibrationClaims.map((c, i) => (
                              <ListGroup.Item key={i} className="bg-transparent px-0 py-1 border-0">
                                <span className={c.ok ? 'text-success' : 'text-warning'}>
                                  {c.ok ? '✓' : '!'}
                                </span>
                                <span className="text-white-50 ms-2 small">{c.text}</span>
                              </ListGroup.Item>
                            ))}
                          </ListGroup>

                          {(validation.assumptions || []).length > 0 && (
                            <>
                              <div className="text-warning small mt-3 mb-1">
                                Assumptions this run had to make:
                              </div>
                              <ListGroup variant="flush">
                                {validation.assumptions.map((a, i) => (
                                  <ListGroup.Item key={i} className="bg-transparent px-0 py-1 border-0">
                                    <span className="text-white-50 small">{a}</span>
                                  </ListGroup.Item>
                                ))}
                              </ListGroup>
                            </>
                          )}

                          <div className="text-muted mt-3" style={{ fontSize: '0.7rem' }}>
                            {validation.requests_sent} request
                            {validation.requests_sent === 1 ? '' : 's'} sent
                            {validation.execution_time ? ` in ${validation.execution_time}` : ''}
                            {validation.abort_reason ? ` · stopped: ${validation.abort_reason}` : ''}
                            {validation.processed_endpoints < validation.total_endpoints
                              ? ` · reached ${validation.processed_endpoints} of ${validation.total_endpoints}`
                              : ''}
                          </div>
                        </Accordion.Body>
                      </Accordion.Item>

                      <Accordion.Item eventKey="1">
                        <Accordion.Header>
                          Why each verdict was reached
                          <Badge bg="secondary" className="ms-2">{reasonBreakdown.length} rules</Badge>
                        </Accordion.Header>
                        <Accordion.Body className="p-0">
                          <Table size="sm" hover className="mb-0" style={{ fontSize: '0.75rem' }}>
                            <thead>
                              <tr className="text-muted">
                                <th style={{ width: '90px' }}>Verdict</th>
                                <th>Reason</th>
                                <th style={{ width: '70px' }} className="text-end">Count</th>
                                <th style={{ width: '90px' }} className="text-end">Measured</th>
                              </tr>
                            </thead>
                            <tbody>
                              {reasonBreakdown.map((r) => (
                                <tr
                                  key={r.code}
                                  style={{ cursor: 'pointer' }}
                                  className={reasonFilter === r.code ? 'table-active' : ''}
                                  onClick={() => {
                                    setReasonFilter(reasonFilter === r.code ? '' : r.code);
                                    setStatusFilter('all');
                                  }}
                                >
                                  <td><StatusBadge status={r.status} /></td>
                                  <td className="text-white-50">
                                    {REASON_LABEL[r.code] || r.code}
                                    <div className="text-muted font-monospace"
                                         style={{ fontSize: '0.65rem' }}>
                                      {r.code}
                                    </div>
                                  </td>
                                  <td className="text-end text-white">{r.count}</td>
                                  <td className="text-end text-muted">{r.measured}</td>
                                </tr>
                              ))}
                            </tbody>
                          </Table>
                        </Accordion.Body>
                      </Accordion.Item>
                    </Accordion>

                    <InputGroup className="mb-2" size="sm">
                      <Form.Control
                        placeholder="Filter by URL, method, reason code or title"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        data-bs-theme="dark"
                      />
                      <Form.Select
                        style={{ maxWidth: '160px' }}
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                      >
                        <option value="all">All verdicts</option>
                        <option value="valid">Valid</option>
                        <option value="unverified">Unverified</option>
                        <option value="ruled_out">Ruled out</option>
                        <option value="skipped">Skipped</option>
                      </Form.Select>
                      {(reasonFilter || statusFilter !== 'all' || search) && (
                        <Button variant="outline-secondary" onClick={() => {
                          setReasonFilter(''); setStatusFilter('all'); setSearch('');
                        }}>
                          Clear
                        </Button>
                      )}
                    </InputGroup>

                    {reasonFilter && (
                      <div className="text-muted mb-2" style={{ fontSize: '0.72rem' }}>
                        Showing only <span className="font-monospace">{reasonFilter}</span>
                      </div>
                    )}

                    <div className="text-muted mb-1" style={{ fontSize: '0.72rem' }}>
                      {filteredRows.length} of {rows.length} row{rows.length === 1 ? '' : 's'}
                      {' · click a row for the evidence and what would disprove it'}
                    </div>

                    {filteredRows.length === 0 ? (
                      <Alert variant="secondary" className="py-2 small">Nothing matches.</Alert>
                    ) : (
                      <VirtualizedList
                        items={filteredRows}
                        renderItem={renderValidationRow}
                        itemKey={(row, i) => `${row.method}|${row.url}|${i}`}
                        estimatedItemSize={64}
                        height="45vh"
                      />
                    )}
                  </>
                )}
              </Tab>

              {/* ------------------------------------------------ Investigate */}
              <Tab eventKey="investigate" title={
                <span>Investigate {investigatedEndpoints.length > 0 && (
                  <Badge bg="secondary" className="ms-1">{investigatedEndpoints.length}</Badge>)}</span>
              }>
                {!investigation || investigation.status === 'not_run' ? (
                  <Alert variant="secondary">
                    {data.note || 'The investigation phase did not run for this scan.'}
                  </Alert>
                ) : (
                  <>
                    <div className="mb-3 p-2 border border-secondary rounded">
                      <div className="text-white small mb-1">
                        {data.eligible_endpoints} endpoint
                        {data.eligible_endpoints === 1 ? '' : 's'} went into this phase, out of{' '}
                        {data.total_endpoints} consolidated.
                      </div>
                      <div className="text-muted" style={{ fontSize: '0.7rem' }}>
                        {Object.entries(data.eligible_breakdown || {})
                          .map(([verdict, n]) => `${n} ${verdict}`)
                          .join(' · ') || 'no breakdown recorded'}
                      </div>
                      <div className="text-muted mt-1" style={{ fontSize: '0.68rem' }}>
                        Anything Validate ruled out with a measured verdict was excluded, along with
                        static assets and paths a GET would change state on. Unverified endpoints are
                        included on purpose: unknown is not the same as ruled out.
                      </div>
                    </div>

                    {(investigation.target_findings || []).length > 0 && (
                      <>
                        <h6 className="text-danger">Target-level findings</h6>
                        <div className="text-muted mb-2" style={{ fontSize: '0.7rem' }}>
                          True of most of the corpus, so reported once here rather than once per
                          endpoint.
                        </div>
                        <ListGroup className="mb-3">
                          {investigation.target_findings.map((f, i) => (
                            <ListGroup.Item key={`${f.dedupe_key}|${i}`}
                                            className="bg-transparent border-secondary">
                              <div className="d-flex align-items-center gap-2">
                                <Badge bg={SEVERITY[f.severity] || 'secondary'}>{f.severity}</Badge>
                                <span className="text-white small">{f.title}</span>
                              </div>
                              <div className="text-white-50 mt-1" style={{ fontSize: '0.73rem' }}>
                                {f.detail}
                              </div>
                              {f.evidence && (
                                <div className="text-muted font-monospace text-break mt-1"
                                     style={{ fontSize: '0.68rem' }}>
                                  {f.evidence}
                                </div>
                              )}
                            </ListGroup.Item>
                          ))}
                        </ListGroup>
                      </>
                    )}

                    {(investigation.tier1_notes || []).length > 0 && (
                      <Accordion className="mb-3">
                        <Accordion.Item eventKey="0">
                          <Accordion.Header>
                            What the request-costing probes did
                            <Badge bg="secondary" className="ms-2">
                              {investigation.tier1_notes.length}
                            </Badge>
                          </Accordion.Header>
                          <Accordion.Body>
                            {investigation.tier1_notes.map((n, i) => (
                              <div key={i} className="text-white-50 small mb-1">{n}</div>
                            ))}
                          </Accordion.Body>
                        </Accordion.Item>
                      </Accordion>
                    )}

                    <InputGroup className="mb-2" size="sm">
                      <Form.Control
                        placeholder="Filter by URL, title or signal"
                        value={investigateSearch}
                        onChange={(e) => setInvestigateSearch(e.target.value)}
                        data-bs-theme="dark"
                      />
                    </InputGroup>

                    <div className="text-muted mb-1" style={{ fontSize: '0.72rem' }}>
                      {filteredInvestigated.length} endpoint
                      {filteredInvestigated.length === 1 ? '' : 's'}, ordered by what makes them
                      different from the rest of the corpus
                    </div>

                    {filteredInvestigated.length === 0 ? (
                      <Alert variant="secondary" className="py-2 small">Nothing matches.</Alert>
                    ) : (
                      <VirtualizedList
                        items={filteredInvestigated}
                        renderItem={renderInvestigatedRow}
                        itemKey={(ep, i) => `inv|${ep.endpoint_id || ep.url}|${i}`}
                        estimatedItemSize={64}
                        height="45vh"
                      />
                    )}
                  </>
                )}
              </Tab>

              {/* ------------------------------------------------ Run */}
              <Tab eventKey="run" title="Run">
                <Table size="sm" borderless style={{ fontSize: '0.8rem' }}>
                  <tbody className="text-muted">
                    <tr>
                      <td style={{ width: '220px' }}>Started</td>
                      <td className="text-white-50">
                        {data.created_at ? new Date(data.created_at).toLocaleString() : '-'}
                      </td>
                    </tr>
                    <tr>
                      <td>Total time</td>
                      <td className="text-white-50">{data.execution_time || '-'}</td>
                    </tr>
                    <tr>
                      <td>Consolidated endpoints</td>
                      <td className="text-white-50">{data.total_endpoints}</td>
                    </tr>
                    <tr>
                      <td>Phase 1: Validate</td>
                      <td className="text-white-50">
                        {validation
                          ? `${validation.status} · ${validation.processed_endpoints}/${validation.total_endpoints} judged · ${validation.requests_sent} requests`
                          : 'did not run'}
                      </td>
                    </tr>
                    <tr>
                      <td>Phase 2: Investigate</td>
                      <td className="text-white-50">
                        {investigation && investigation.status !== 'not_run'
                          ? `${investigation.status} · ${investigation.processed_endpoints}/${investigation.total_endpoints} enriched`
                          : 'did not run'}
                      </td>
                    </tr>
                  </tbody>
                </Table>

                <div className="text-muted mt-3" style={{ fontSize: '0.72rem' }}>
                  Validate runs first and Investigate only sees what it did not rule out. When
                  Validate aborts, Investigate is skipped rather than deferred: the pacing ladder
                  aborts because the target started throttling or slowed well past its baseline, and
                  Investigate sends more traffic per endpoint than Validate does.
                </div>
              </Tab>
            </Tabs>
          </>
        )}
      </Modal.Body>

      <Modal.Footer>
        <Button variant="outline-secondary" onClick={load} disabled={loading}>Refresh</Button>
        <Button variant="outline-danger" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
};

export default EndpointScanResultsModal;
