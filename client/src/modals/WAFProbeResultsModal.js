import { useState, useMemo, useEffect, useCallback } from 'react';
import { Modal, Button, Badge, Table, Alert, Spinner, Tabs, Tab, Accordion,
         ListGroup } from 'react-bootstrap';

// Results for the Target Behaviour Probe.
//
// The ordering is deliberate. An operator reads the top of this modal and then goes back to work,
// so the first screen answers only two questions: what rate can I scan at, and what is going to
// break. Everything else is one tab away.
//
// Recommendations are shown, not applied. The probe used to write its numbers into the tool configs
// directly, and when a translation was wrong nothing said so: a delay that did not fit the tool's
// field decoded to zero and the tool ran with no rate limit at all, while this modal reported the
// rate as applied. Reading a value off the screen and typing it in is slower and is honest, so each
// recommendation names the tool's own setting, its units, and the modal to set it in.

const POSTURE = {
  DEFENDED:           { variant: 'danger',    text: 'Defended' },
  PARTIALLY_DEFENDED: { variant: 'warning',   text: 'Partially defended' },
  OPEN:               { variant: 'success',   text: 'Open' },
  INCONCLUSIVE:       { variant: 'secondary', text: 'Inconclusive' },
  UNKNOWN:            { variant: 'secondary', text: 'Unknown' },
  REFUSED:            { variant: 'dark',      text: 'Refused' },
};

const TIER = { P0: 'danger', P1: 'warning', P2: 'info', P3: 'secondary' };

const CONFIDENCE_HELP = {
  measured: 'The probe observed this directly.',
  inferred: 'Derived from something the probe observed, but not re-verified against the target.',
  assumed: 'A conservative default. Not a measurement.',
};

const parseResult = (scan) => {
  if (!scan || !scan.result) return null;
  try {
    return typeof scan.result === 'string' ? JSON.parse(scan.result) : scan.result;
  } catch {
    return null;
  }
};

export const WAFProbeResultsModal = ({ show, handleClose, activeTarget,
                                       mostRecentWAFProbeScan, wafProbeScans = [] }) => {
  const [viewScan, setViewScan] = useState(null);
  const [tab, setTab] = useState('verdict');
  // Resolved server-side, because turning a measured rate into a tool's own setting means knowing
  // that arjun counts seconds and x8 counts milliseconds. Duplicating that here would let the two
  // drift, and a stale copy would hand the operator a number that is wrong by a factor of 1000.
  const [recs, setRecs] = useState(null);
  const [recsLoading, setRecsLoading] = useState(false);
  const [copied, setCopied] = useState('');
  // The sibling scans of a multi-endpoint run. A run probes each selected endpoint separately, so
  // "the result" for such a run is N results; this is what lets the operator move between them
  // without going back to the history tab and matching timestamps by eye.
  const [runData, setRunData] = useState(null);

  const scan = viewScan || mostRecentWAFProbeScan;
  const probe = useMemo(() => parseResult(scan), [scan]);

  const verdict = probe?.verdict || {};
  const findings = probe?.findings || [];
  const run = probe?.run || {};
  // Memoised because `rows` derives from it and an effect resets the apply selection when `rows`
  // changes. A fresh object literal every render would clear the operator's checkboxes each time
  // anything else on the page re-rendered.
  const recommendations = useMemo(() => probe?.recommendations || {}, [probe]);

  // Flatten the per-tool recommendation map into apply rows. Fields beginning with an underscore
  // are advisory notes for the launcher (gau and waybackurls query public archives, not the
  // target, so the rate budget does not apply to them) and are shown separately rather than
  // offered as settings to write.
  const { rows, notes } = useMemo(() => {
    const byTool = recommendations.by_tool || {};
    const outRows = [];
    const outNotes = [];
    Object.keys(byTool).forEach((tool) => {
      (byTool[tool] || []).forEach((rec, i) => {
        const entry = { key: `${tool}:${rec.field}:${i}`, tool, ...rec };
        if (String(rec.field).startsWith('_')) outNotes.push(entry);
        else outRows.push(entry);
      });
    });
    return { rows: outRows, notes: outNotes };
  }, [recommendations]);

  const suppressed = recommendations.suppressed || [];
  const rateChain = recommendations.rate_chain || probe?.verdict?.rate_chain || [];

  // Tied to the scan being viewed, not to the target's newest scan. Reading an older result and
  // seeing the newest scan's numbers would be the same confusion the old wholesale apply caused.
  const loadRecommendations = useCallback(async (scanID) => {
    if (!activeTarget) return;
    setRecsLoading(true);
    try {
      const url = scanID
        ? `/api/waf-probe/recommendations/${activeTarget.id}/${scanID}`
        : `/api/waf-probe/recommendations/${activeTarget.id}`;
      const res = await fetch(url);
      setRecs(res.ok ? await res.json() : null);
    } catch {
      setRecs(null);   // shown as "could not load", never as "no recommendations"
    } finally {
      setRecsLoading(false);
    }
  }, [activeTarget]);

  useEffect(() => {
    if (!show) return;
    setViewScan(null);
    setTab('verdict');
  }, [show]);

  useEffect(() => {
    if (!show) return;
    loadRecommendations(scan?.scan_id);
  }, [show, scan?.scan_id, loadRecommendations]);

  // Endpoints run strictly one at a time, so a run is in flight for as long as the sum of its
  // endpoints' durations. Polling while it is means the operator can leave this modal open and
  // watch it advance, rather than reopening it to find out whether it is still going.
  const runID = scan?.run_id || '';
  useEffect(() => {
    if (!show || !runID) { setRunData(null); return; }
    let cancelled = false;
    let timer = null;

    const poll = async () => {
      try {
        const res = await fetch(`/api/waf-probe/run/${runID}/results`);
        if (cancelled) return;
        if (res.ok) {
          const data = await res.json();
          setRunData(data);
          if (data.in_progress) timer = setTimeout(poll, 5000);
        }
      } catch {
        // A failed poll is not worth an error banner: the next one may succeed, and the results
        // already on screen stay valid regardless.
      }
    };
    poll();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [show, runID]);

  // Switching endpoints must carry run_id, or the poll above tears down the moment the operator
  // clicks a sibling and the strip disappears mid-run.
  const viewRunEndpoint = useCallback((row) => {
    setViewScan({ ...row, run_id: runID });
    setTab('verdict');
  }, [runID]);

  // Opening the modal mid-run lands on the newest scan, which in a multi-endpoint run is the LAST
  // endpoint: still queued, no result, an empty panel while earlier endpoints have real findings.
  // Fall forward to the most recent endpoint that actually produced something. Only when the
  // operator has not chosen one themselves, so this never overrides a click.
  useEffect(() => {
    if (!show || viewScan || probe || !runData) return;
    const finished = (runData.endpoints || []).filter((e) => e.result);
    if (finished.length > 0) viewRunEndpoint(finished[finished.length - 1]);
  }, [show, viewScan, probe, runData, viewRunEndpoint]);

  const copyTool = (tool, settings) => {
    const text = settings.map((s) =>
      `${s.setting} = ${formatValue(s.value)}${s.unit ? `   (${s.unit})` : ''}`).join('\n');
    navigator.clipboard?.writeText(text)
      .then(() => { setCopied(tool); setTimeout(() => setCopied(''), 1500); })
      .catch(() => { /* clipboard can be blocked; the values are on screen regardless */ });
  };

  const posture = POSTURE[verdict.posture] || POSTURE.UNKNOWN;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Target Behaviour Probe Results
          {/* Named in the title because every panel below describes one endpoint, and with several
              in a run it is otherwise easy to read one endpoint's verdict as the estate's. */}
          {scan?.endpoint_label && (
            <span className="text-white ms-2" style={{ fontSize: '0.85rem' }}>
              — {scan.endpoint_label}
            </span>
          )}
          {probe?.probe_version && (
            <span className="text-white-50 ms-2" style={{ fontSize: '0.8rem' }}>
              v{probe.probe_version}
            </span>
          )}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="text-white">
        {/* The run strip sits above everything, including the empty state, because when a run is
            still working through its endpoints the earlier ones already have results worth reading
            while the current one is measured. */}
        {runData && runData.endpoint_count > 1 && (
          <div className="rounded p-2 mb-3" style={{ border: '1px solid rgba(220,53,69,0.45)' }}>
            <div className="d-flex align-items-center gap-2 mb-2 flex-wrap">
              <span className="text-danger fw-bold small">
                Multi-endpoint run
              </span>
              <span className="text-white-50 small">
                {runData.completed_count} of {runData.endpoint_count} finished
                {' · '}{runData.total_requests_sent || 0} requests
                {' · '}{runData.total_trips_used || 0} deliberate blocks
              </span>
              {runData.in_progress && (
                <span className="text-white-50 small">
                  <Spinner size="sm" animation="border" className="me-2" />
                  probing one at a time
                </span>
              )}
            </div>
            <div className="d-flex flex-column gap-1">
              {(runData.endpoints || []).map((row, i) => {
                const rowPosture = POSTURE[row.posture] || POSTURE.UNKNOWN;
                const isCurrent = row.scan_id === scan?.scan_id;
                // Anything that is no longer queued or in flight has a result worth opening. An
                // aborted scan especially: an abort rule firing is the probe stopping itself
                // because it learned something, and everything measured up to that point stands.
                const done = row.status !== 'pending' && row.status !== 'running';
                return (
                  <div
                    key={row.scan_id}
                    role={done ? 'button' : undefined}
                    onClick={done ? () => viewRunEndpoint(row) : undefined}
                    className={`d-flex align-items-center gap-2 rounded px-2 py-1 ${isCurrent ? 'border border-danger' : ''}`}
                    style={{
                      backgroundColor: isCurrent ? 'rgba(220,53,69,0.12)' : 'transparent',
                      cursor: done ? 'pointer' : 'default',
                      opacity: done ? 1 : 0.65,
                    }}
                  >
                    <Badge bg="secondary">{i + 1}</Badge>
                    <span className="text-white small" style={{ minWidth: '150px' }}>
                      {row.endpoint_label || row.url}
                    </span>
                    {row.status === 'running' && (
                      <Badge bg="info" text="dark">running</Badge>
                    )}
                    {row.status === 'pending' && <Badge bg="dark">queued</Badge>}
                    {row.status === 'error' && <Badge bg="danger">failed</Badge>}
                    {row.status === 'aborted' && (
                      <Badge bg="warning" text="dark"
                             title="An abort rule stopped this scan early. What it measured before stopping is valid.">
                        stopped early
                      </Badge>
                    )}
                    {done && row.posture && (
                      <Badge bg={rowPosture.variant}>{rowPosture.text}</Badge>
                    )}
                    <span className="text-white-50 text-truncate"
                          style={{ fontSize: '0.7rem', flex: 1 }} title={row.url}>
                      {row.url}
                    </span>
                    {/* The safe rate is the number every later tool paces against, and it is per
                        host rather than per estate. Showing it inline is what makes the strip a
                        comparison rather than a list. */}
                    {rowRate(row) && (
                      <Badge bg="dark" className="border border-secondary text-white"
                             style={{ fontSize: '0.62rem' }}
                             title="Safe request rate measured for this endpoint">
                        {rowRate(row)}
                      </Badge>
                    )}
                    {row.requests_sent > 0 && (
                      <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
                        {row.requests_sent} req
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {!probe && (
          <Alert variant="secondary">
            {scan?.status === 'error'
              ? `The probe failed: ${scan.error || 'no detail was recorded'}`
              : scan?.status === 'running' || scan?.status === 'pending'
                ? 'This endpoint has not been probed yet. Its result appears here when it finishes.'
                : 'No probe result is available for this target yet. Run a scan from the card.'}
          </Alert>
        )}

        {probe && (
          <>
            {/* -------------------------------------------------- the five-second answer */}
            <div className="rounded p-3 mb-3" style={{ border: '1px solid rgba(220,53,69,0.45)' }}>
              <div className="d-flex align-items-center gap-2 mb-2 flex-wrap">
                <Badge bg={posture.variant}>{posture.text}</Badge>
                {run.status === 'partial' && <Badge bg="warning" text="dark">Partial result</Badge>}
                {run.status === 'aborted' && <Badge bg="warning" text="dark">Aborted</Badge>}
                <span className="text-white-50 small">
                  {run.tests_run?.length || 0} tests ran, {run.tests_skipped || 0} skipped,
                  {' '}{probe.budget?.requests_sent ?? scan?.requests_sent ?? 0} requests,
                  {' '}{run.duration_seconds}s
                </span>
              </div>
              <div style={{ fontSize: '1.05rem' }}>{verdict.headline}</div>

              <div className="d-flex gap-4 mt-3 flex-wrap">
                <Metric label="Safe rate"
                        value={verdict.safe_rps ? `${verdict.safe_rps} req/s` : 'not established'}
                        note={verdict.safe_rps_confidence
                          ? `${verdict.safe_rps_confidence}${verdict.safe_rps_verified ? ', validated' : ''}`
                          : null} />
                <Metric label="Safe concurrency"
                        value={verdict.safe_concurrency || 'not measured'} />
                <Metric label="First block"
                        value={verdict.time_to_first_block
                          ? `request #${verdict.time_to_first_block.request_n}`
                          : 'none observed'}
                        note={verdict.time_to_first_block?.phase} />
                <Metric label="Findings"
                        value={`${verdict.counts?.p0 || 0} critical / ${verdict.counts?.total || 0} total`} />
              </div>
            </div>

            {(run.status === 'partial' || run.status === 'aborted') && (
              <Alert variant="warning" className="py-2 small">
                This run did not finish. Everything below was measured before it stopped and is
                valid; what is missing is missing, not negative.
                {/* abort_reason is an object with rule_id, detail, phase and request_n. Rendering
                    it directly threw "Objects are not valid as a React child" and took the whole
                    modal down, so an aborted scan showed nothing at all. */}
                {formatAbortReason(run.abort_reason) && (
                  <> Reason: {formatAbortReason(run.abort_reason)}</>
                )}
                {run.stopped_phases?.length > 0 && <> Stopped phases: {run.stopped_phases.join(', ')}.</>}
              </Alert>
            )}
            {run.status === 'refused' && (
              <Alert variant="danger" className="py-2 small">
                The probe refused to start: {(run.problems || []).join('; ')}
              </Alert>
            )}

            <Tabs activeKey={tab} onSelect={setTab} className="mb-3">
              {/* -------------------------------------------------- verdict */}
              <Tab eventKey="verdict" title="Verdict">
                <h6 className="text-danger">What will break your automated scanning</h6>
                {(verdict.will_break || []).length === 0 ? (
                  <p className="text-white-50 small">
                    Nothing the probe measured will corrupt a scan of this target.
                  </p>
                ) : (
                  <ListGroup variant="flush" className="mb-3">
                    {verdict.will_break.map((w, i) => (
                      <ListGroup.Item key={i} className="bg-transparent text-white border-secondary">
                        <Badge bg={TIER[w.tier] || 'secondary'} className="me-2">{w.tier}</Badge>
                        {w.title}
                      </ListGroup.Item>
                    ))}
                  </ListGroup>
                )}

                {rateChain.length > 0 && (
                  <>
                    <h6 className="text-danger mt-4">How the safe rate was derived</h6>
                    <p className="text-white-50 small">
                      Every step that produced the number above, in order. A rate you cannot
                      audit is a rate you cannot defend to a program.
                    </p>
                    <Table size="sm" variant="dark" className="small">
                      <thead>
                        <tr><th>Step</th><th>Value</th><th>Source</th></tr>
                      </thead>
                      <tbody>
                        {rateChain.map((c, i) => (
                          <tr key={i}>
                            <td>{c.step}</td>
                            <td className="text-danger">{c.value ?? '-'}</td>
                            <td className="text-white-50">{c.source}</td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </>
                )}

                {(probe.skipped || []).length > 0 && (
                  <>
                    <h6 className="text-danger mt-4">Skipped ({probe.skipped.length})</h6>
                    <p className="text-white-50 small">
                      A test that did not run is listed here with its reason. A skip never means
                      the target passed that test.
                    </p>
                    <Table size="sm" variant="dark" className="small">
                      <tbody>
                        {probe.skipped.map((s, i) => (
                          <tr key={i}>
                            <td style={{ width: '30%' }}>{s.name || s.test || s.id}</td>
                            <td className="text-white-50">{s.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </>
                )}
              </Tab>

              {/* -------------------------------------------------- findings */}
              <Tab eventKey="findings" title={`Findings (${findings.length})`}>
                {findings.length === 0 && (
                  <p className="text-white-50 small">No findings were raised.</p>
                )}
                <Accordion alwaysOpen>
                  {findings.map((f, i) => (
                    <Accordion.Item eventKey={String(i)} key={f.id + i}
                                    className="border-secondary mb-2"
                                    style={{ backgroundColor: '#2b2b2b' }}>
                      <Accordion.Header>
                        <Badge bg={TIER[f.tier] || 'secondary'} className="me-2">{f.tier}</Badge>
                        <span className="me-2">{f.title}</span>
                        <Badge bg="dark" className="border border-secondary text-white-50"
                               style={{ fontSize: '0.62rem' }}
                               title={CONFIDENCE_HELP[f.confidence]}>
                          {f.confidence}
                        </Badge>
                      </Accordion.Header>
                      <Accordion.Body style={{ backgroundColor: '#2b2b2b' }}>
                        <p className="small">{f.detail}</p>
                        <div className="small text-white-50">
                          <div><strong>Evidence:</strong> {f.evidence_test}</div>
                          <div><strong>Affects:</strong> {(f.affected_tools || []).join(', ')}</div>
                          {/* The falsifier is the point. A badge that cannot be disproved is an
                              opinion, and this probe does not publish opinions. */}
                          <div className="mt-2"><strong>Would disprove this:</strong> {f.falsifier}</div>
                        </div>
                      </Accordion.Body>
                    </Accordion.Item>
                  ))}
                </Accordion>
              </Tab>

              {/* -------------------------------------------------- apply */}
              <Tab eventKey="apply"
                   title={`Recommendations (${recs?.tools?.reduce((n, t) => n + t.settings.length, 0) ?? rows.length})`}>
                <Alert variant="dark" className="border-secondary py-2 small">
                  Nothing here has been written to any tool configuration. Each row names the tool's
                  own setting and the units it counts in, so it can be typed into the modal listed
                  against that tool.
                </Alert>

                {recsLoading && <Spinner size="sm" animation="border" variant="danger" />}

                {!recsLoading && !recs && (
                  <Alert variant="warning" className="py-2 small">
                    The recommendations could not be loaded. The raw values are still in the
                    Findings and Test detail tabs.
                  </Alert>
                )}

                {!recsLoading && recs?.status === 'ok' && recs.tools?.length === 0 && (
                  <Alert variant="secondary" className="py-2 small">
                    This run produced no applicable settings.
                  </Alert>
                )}

                {!recsLoading && recs?.tools?.map((t) => (
                  <div key={t.tool} className="mb-3">
                    <div className="d-flex align-items-center gap-2 flex-wrap">
                      <h6 className="text-danger text-capitalize mb-0">{t.tool}</h6>
                      {t.where && (
                        <span className="text-white-50" style={{ fontSize: '0.75rem' }}>
                          {t.where}
                        </span>
                      )}
                      {t.settings.length > 0 && (
                        <Button variant="outline-secondary" size="sm" className="py-0 ms-auto"
                                style={{ fontSize: '0.7rem' }}
                                onClick={() => copyTool(t.tool, t.settings)}>
                          {copied === t.tool ? 'Copied' : 'Copy'}
                        </Button>
                      )}
                    </div>

                    {t.settings.length > 0 && (
                      <Table size="sm" variant="dark" className="small align-middle mt-2">
                        <thead>
                          <tr className="text-white-50">
                            <th style={{ width: '20%' }}>Setting</th>
                            <th style={{ width: '22%' }}>Set it to</th>
                            <th>Why</th>
                            <th style={{ width: '12%' }}>Confidence</th>
                          </tr>
                        </thead>
                        <tbody>
                          {t.settings.map((s, i) => (
                            <tr key={`${s.setting}:${i}`}>
                              <td><code className="text-white">{s.setting}</code></td>
                              <td>
                                <span className="text-danger fw-bold">{formatValue(s.value)}</span>
                                {/* The unit is the point. "delay 2" means two seconds to arjun and
                                    two milliseconds to x8, and that ambiguity is exactly what made
                                    the old automatic apply run a thousand times too fast. */}
                                {s.unit && (
                                  <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
                                    {s.unit}
                                  </div>
                                )}
                              </td>
                              <td className="text-white-50">
                                {s.why}
                                {!s.restrictive && (
                                  <Badge bg="warning" text="dark" className="ms-2"
                                         style={{ fontSize: '0.6rem' }}>loosening</Badge>
                                )}
                              </td>
                              <td title={CONFIDENCE_HELP[s.confidence]}>{s.confidence}</td>
                            </tr>
                          ))}
                        </tbody>
                      </Table>
                    )}

                    {/* Said out loud rather than silently dropped. The probe measuring a limit a
                        tool cannot honour is a real result: it means that tool has to be paced by
                        hand or left out of the run. */}
                    {t.notes?.map((n, i) => (
                      <div key={i} className="text-warning small ms-1 mt-1">{n}</div>
                    ))}
                  </div>
                ))}

                {notes.length > 0 && (
                  <>
                    <h6 className="text-danger mt-3">Exempt from these limits</h6>
                    <Table size="sm" variant="dark" className="small">
                      <tbody>
                        {notes.map((n) => (
                          <tr key={n.key}>
                            <td style={{ width: '25%' }} className="text-capitalize">{n.tool}</td>
                            <td className="text-white-50">{n.why}</td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </>
                )}

                {suppressed.length > 0 && (
                  <>
                    <h6 className="text-danger mt-3">Deliberately not recommended</h6>
                    <p className="text-white-50 small">
                      The probe had a candidate value for each of these and withheld it. A withheld
                      setting is a result, not a gap.
                    </p>
                    <Table size="sm" variant="dark" className="small">
                      <tbody>
                        {suppressed.map((s, i) => (
                          <tr key={i}>
                            <td style={{ width: '25%' }}>{s.field}</td>
                            <td className="text-white-50">{s.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </>
                )}
              </Tab>

              {/* -------------------------------------------------- raw tests */}
              <Tab eventKey="tests" title="Test detail">
                <Accordion alwaysOpen>
                  {Object.keys(probe.results || {}).sort().map((id, i) => (
                    <Accordion.Item eventKey={String(i)} key={id} className="border-secondary mb-2"
                                    style={{ backgroundColor: '#2b2b2b' }}>
                      <Accordion.Header>
                        <span className="me-2">{id}</span>
                        {probe.results[id]?.verdict && (
                          <Badge bg="dark" className="border border-secondary text-white-50"
                                 style={{ fontSize: '0.62rem' }}>
                            {probe.results[id].verdict}
                          </Badge>
                        )}
                      </Accordion.Header>
                      <Accordion.Body style={{ backgroundColor: '#2b2b2b' }}>
                        {probe.results[id]?.note && (
                          <p className="small">{probe.results[id].note}</p>
                        )}
                        <pre className="small text-white-50 mb-0"
                             style={{ maxHeight: '320px', overflow: 'auto' }}>
                          {JSON.stringify(probe.results[id], null, 2)}
                        </pre>
                      </Accordion.Body>
                    </Accordion.Item>
                  ))}
                </Accordion>
              </Tab>

              {/* -------------------------------------------------- history */}
              <Tab eventKey="history" title={`History (${wafProbeScans.length})`}>
                <Table size="sm" variant="dark" className="small align-middle">
                  <thead>
                    <tr><th>When</th><th>Endpoint</th><th>Status</th><th>Posture</th><th>Requests</th>
                        <th>Trips</th><th /></tr>
                  </thead>
                  <tbody>
                    {wafProbeScans.map((s) => (
                      <tr key={s.scan_id}
                          className={s.scan_id === scan?.scan_id ? 'table-active' : ''}>
                        <td>{new Date(s.created_at).toLocaleString()}</td>
                        {/* Without this column the history of a multi-endpoint run is N rows with
                            the same timestamp and no way to tell which host each one measured. */}
                        <td>{s.endpoint_label || <span className="text-white-50">-</span>}</td>
                        <td>{s.status}</td>
                        <td>{s.posture || '-'}</td>
                        <td>{s.requests_sent ?? '-'}</td>
                        <td>{s.trips_used ?? '-'}</td>
                        <td>
                          <Button size="sm" variant="outline-danger"
                                  disabled={s.scan_id === scan?.scan_id}
                                  onClick={() => { setViewScan(s); setTab('verdict'); }}>
                            View
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
                <p className="text-white-50 small">
                  Comparing two runs of the same target is how you tell a change in the application
                  from a change in your own egress reputation.
                </p>
              </Tab>

              {/* -------------------------------------------------- log */}
              <Tab eventKey="log" title="Request log">
                <p className="text-white-50 small">
                  Every request the probe sent, in order. Credentials are redacted at capture time,
                  so this log is safe to attach to a report.
                </p>
                <Table size="sm" variant="dark" className="small">
                  <thead>
                    <tr><th>#</th><th>Phase</th><th>Method</th><th>Path</th><th>Status</th>
                        <th>Class</th><th>ms</th></tr>
                  </thead>
                  <tbody>
                    {(probe.probe_log || []).slice(0, 500).map((e, i) => (
                      <tr key={i}>
                        <td>{e.n}</td><td>{e.phase}</td><td>{e.method}</td>
                        <td style={{ maxWidth: '280px', overflow: 'hidden',
                                     textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.path}</td>
                        <td>{e.status}</td>
                        <td>{e.class}</td>
                        <td>{e.ms}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
                {(probe.probe_log || []).length > 500 && (
                  <p className="text-white-50 small">
                    Showing the first 500 of {probe.probe_log.length} entries.
                  </p>
                )}
              </Tab>
            </Tabs>
          </>
        )}
      </Modal.Body>

      <Modal.Footer>
        {/* Clicking a sibling endpoint in the run strip also sets viewScan, and calling that a
            historical run would be wrong: it is one endpoint of the run being looked at. */}
        {viewScan && (
          runData && (runData.endpoints || []).some((e) => e.scan_id === viewScan.scan_id) ? (
            <span className="text-white-50 small me-auto">
              Viewing one endpoint of this run. The other endpoints are in the strip above.
            </span>
          ) : (
            <span className="text-warning small me-auto">
              Viewing a historical run from {new Date(viewScan.created_at).toLocaleString()}.
            </span>
          )
        )}
        <Button variant="outline-danger" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
};

/* ------------------------------------------------------------------ pieces */

const Metric = ({ label, value, note }) => (
  <div>
    <div className="text-white-50" style={{ fontSize: '0.7rem' }}>{label}</div>
    <div style={{ fontSize: '1.1rem' }}>{value}</div>
    {note && <div className="text-white-50" style={{ fontSize: '0.65rem' }}>{note}</div>}
  </div>
);

/* ------------------------------------------------------------------ helpers */

function formatValue(v) {
  if (v === null || v === undefined || v === '') return 'unset';
  if (typeof v === 'boolean') return v ? 'on' : 'off';
  if (Array.isArray(v)) {
    return v.map((x) => (x && x.name ? `${x.name}: ${x.value}` : String(x))).join('; ');
  }
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

// The safe rate for one endpoint of a run, read from its stored result. Marked when it is a
// conservative default rather than a measurement: the safe preset runs no load test, so its rate is
// an assumption, and a bare "5 req/s" would read as measured.
function rowRate(row) {
  if (!row?.result) return '';
  let parsed;
  try {
    parsed = typeof row.result === 'string' ? JSON.parse(row.result) : row.result;
  } catch {
    return '';
  }
  const v = parsed?.verdict || {};
  if (!v.safe_rps) return '';
  const assumed = v.safe_rps_confidence && v.safe_rps_confidence !== 'measured';
  return `${v.safe_rps} req/s${assumed ? ' (assumed)' : ''}`;
}

// The probe writes abort_reason as an object, but older results carry a bare string. Both have to
// render, and neither may be handed to React as-is.
function formatAbortReason(reason) {
  if (!reason) return '';
  if (typeof reason === 'string') return reason.endsWith('.') ? reason : `${reason}.`;
  const detail = reason.detail || reason.rule_id || '';
  if (!detail) return '';
  const where = [
    reason.phase ? `in ${reason.phase}` : '',
    reason.request_n ? `at request #${reason.request_n}` : '',
  ].filter(Boolean).join(' ');
  return where ? `${detail} (${where}).` : `${detail}.`;
}

export default WAFProbeResultsModal;
