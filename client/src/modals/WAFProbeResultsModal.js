import { useState, useMemo, useEffect, useCallback } from 'react';
import { Modal, Button, Badge, Table, Alert, Spinner, Tabs, Tab, Accordion,
         Form, ListGroup } from 'react-bootstrap';

// Results for the Target Behaviour Probe.
//
// The ordering is deliberate. An operator reads the top of this modal and then goes back to work,
// so the first screen answers only two questions: what rate can I scan at, and what is going to
// break. Everything else is one tab away.
//
// Apply is two-step and row-level. v1 applied "the newest successful scan" to FFUF wholesale, which
// meant reviewing an older result and clicking Apply silently wrote a different scan's numbers over
// settings the operator had chosen by hand, with no record of the previous value. Here the operator
// picks rows, sees exactly what will change, and every write is journalled and revertible.

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
                                       mostRecentWAFProbeScan, wafProbeScans = [],
                                       onApplied }) => {
  const [viewScan, setViewScan] = useState(null);
  const [selected, setSelected] = useState({});
  const [applyStep, setApplyStep] = useState('select');   // select | confirm | done
  const [applying, setApplying] = useState(false);
  const [applyErr, setApplyErr] = useState('');
  const [applyResult, setApplyResult] = useState(null);
  const [journal, setJournal] = useState([]);
  const [tab, setTab] = useState('verdict');

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

  const loadJournal = useCallback(async () => {
    if (!activeTarget) return;
    try {
      const res = await fetch(`/api/waf-probe/apply-journal/${activeTarget.id}`);
      if (res.ok) setJournal(await res.json());
    } catch { /* the journal is informational; its absence must not break the modal */ }
  }, [activeTarget]);

  useEffect(() => {
    if (!show) return;
    setViewScan(null);
    setApplyStep('select');
    setApplyErr('');
    setApplyResult(null);
    setTab('verdict');
    loadJournal();
  }, [show, loadJournal]);

  // Restrictive rows are pre-checked; loosening rows never are. Relaxing a setting on a tool's
  // advice should be a deliberate act, because the operator carries the consequence, not the probe.
  useEffect(() => {
    const next = {};
    rows.forEach((r) => { next[r.key] = !!r.restrictive; });
    setSelected(next);
  }, [rows]);

  const chosen = rows.filter((r) => selected[r.key]);

  const doApply = async () => {
    if (!activeTarget || !scan?.scan_id) return;
    setApplying(true);
    setApplyErr('');
    try {
      const res = await fetch(`/api/waf-probe/apply/${activeTarget.id}/${scan.scan_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rows: chosen.map((r) => ({
            tool: r.tool, field: r.field, value: r.value,
            finding_id: r.finding_id || '', confidence: r.confidence || '',
            bundle: r.bundle || '',
          })),
        }),
      });
      if (!res.ok) throw new Error(await res.text() || 'Failed to apply');
      setApplyResult(await res.json());
      setApplyStep('done');
      loadJournal();
      if (onApplied) onApplied();
    } catch (e) {
      setApplyErr(e.message);
    } finally {
      setApplying(false);
    }
  };

  const revert = async (entryId) => {
    try {
      const res = await fetch(`/api/waf-probe/revert/${entryId}`, { method: 'POST' });
      if (res.ok) {
        loadJournal();
        if (onApplied) onApplied();
      }
    } catch { /* leave the entry in place; a failed revert must not look like a success */ }
  };

  const posture = POSTURE[verdict.posture] || POSTURE.UNKNOWN;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Target Behaviour Probe Results
          {probe?.probe_version && (
            <span className="text-white-50 ms-2" style={{ fontSize: '0.8rem' }}>
              v{probe.probe_version}
            </span>
          )}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="text-white">
        {!probe && (
          <Alert variant="secondary">
            {scan?.status === 'error'
              ? `The probe failed: ${scan.error || 'no detail was recorded'}`
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

            {run.status === 'partial' && (
              <Alert variant="warning" className="py-2 small">
                This run did not finish. Everything below was measured before it stopped and is
                valid; what is missing is missing, not negative.
                {run.abort_reason && <> Reason: {run.abort_reason}.</>}
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
              <Tab eventKey="apply" title={`Apply (${rows.length})`}>
                {applyErr && <Alert variant="danger" className="py-2">{applyErr}</Alert>}

                {applyStep === 'done' ? (
                  <>
                    <Alert variant="success" className="py-2">
                      Applied {applyResult?.applied || 0} setting(s).
                      {Object.entries(applyResult?.by_tool || {})
                        .filter(([, v]) => v.error)
                        .map(([t, v]) => <div key={t} className="text-warning">{t}: {v.error}</div>)}
                    </Alert>
                    <Button variant="outline-secondary" size="sm"
                            onClick={() => { setApplyStep('select'); setApplyResult(null); }}>
                      Apply more
                    </Button>
                    <JournalTable journal={journal} onRevert={revert} />
                  </>
                ) : applyStep === 'confirm' ? (
                  <>
                    <Alert variant="dark" className="border-secondary py-2 small">
                      These {chosen.length} setting(s) will be written to your tool configurations
                      for this target. Every write is recorded below and can be reverted to its
                      previous value.
                    </Alert>
                    <Table size="sm" variant="dark" className="small">
                      <thead>
                        <tr><th>Tool</th><th>Setting</th><th>New value</th><th>Confidence</th></tr>
                      </thead>
                      <tbody>
                        {chosen.map((r) => (
                          <tr key={r.key}>
                            <td>{r.tool}</td>
                            <td>{r.field}</td>
                            <td className="text-danger">{formatValue(r.value)}</td>
                            <td>{r.confidence}</td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                    <Button variant="outline-secondary" size="sm" className="me-2"
                            onClick={() => setApplyStep('select')}>Back</Button>
                    <Button variant="danger" size="sm" onClick={doApply} disabled={applying}>
                      {applying ? <Spinner size="sm" animation="border" /> : 'Write these settings'}
                    </Button>
                  </>
                ) : (
                  <>
                    <p className="text-white-50 small">
                      Restrictive settings (which make a scan quieter or more accurate) are
                      pre-selected. Loosening settings are not, because relaxing a limit on a
                      tool's advice should be a deliberate choice.
                    </p>
                    {rows.length === 0 && (
                      <Alert variant="secondary" className="py-2 small">
                        This run produced no applicable settings.
                      </Alert>
                    )}
                    {groupByTool(rows).map(([tool, toolRows]) => (
                      <div key={tool} className="mb-3">
                        <h6 className="text-danger text-capitalize">{tool}</h6>
                        <Table size="sm" variant="dark" className="small align-middle">
                          <tbody>
                            {toolRows.map((r) => (
                              <tr key={r.key}>
                                <td style={{ width: '32px' }}>
                                  <Form.Check
                                    checked={!!selected[r.key]}
                                    onChange={(e) => setSelected((s) => ({ ...s, [r.key]: e.target.checked }))}
                                  />
                                </td>
                                <td style={{ width: '22%' }}>{r.field}</td>
                                <td style={{ width: '20%' }} className="text-danger">
                                  {formatValue(r.value)}
                                </td>
                                <td className="text-white-50">
                                  {r.why}
                                  {!r.restrictive && (
                                    <Badge bg="warning" text="dark" className="ms-2"
                                           style={{ fontSize: '0.6rem' }}>loosening</Badge>
                                  )}
                                  {r.bundle && (
                                    <Badge bg="dark" className="ms-2 border border-secondary text-white-50"
                                           style={{ fontSize: '0.6rem' }}
                                           title="These settings were measured together and are only correct together">
                                      bundle: {r.bundle}
                                    </Badge>
                                  )}
                                </td>
                                <td style={{ width: '12%' }} title={CONFIDENCE_HELP[r.confidence]}>
                                  {r.confidence}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </Table>
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
                          The probe had a candidate value for each of these and withheld it. A
                          withheld setting is a result, not a gap.
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

                    {rows.length > 0 && (
                      <Button variant="danger" size="sm" disabled={chosen.length === 0}
                              onClick={() => setApplyStep('confirm')}>
                        Review {chosen.length} change(s)
                      </Button>
                    )}
                    <JournalTable journal={journal} onRevert={revert} />
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
                    <tr><th>When</th><th>Status</th><th>Posture</th><th>Requests</th>
                        <th>Trips</th><th /></tr>
                  </thead>
                  <tbody>
                    {wafProbeScans.map((s) => (
                      <tr key={s.scan_id}
                          className={s.scan_id === scan?.scan_id ? 'table-active' : ''}>
                        <td>{new Date(s.created_at).toLocaleString()}</td>
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
        {viewScan && (
          <span className="text-warning small me-auto">
            Viewing a historical run from {new Date(viewScan.created_at).toLocaleString()}.
          </span>
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

const JournalTable = ({ journal, onRevert }) => {
  if (!journal || journal.length === 0) return null;
  return (
    <>
      <h6 className="text-danger mt-4">Applied by this probe ({journal.length})</h6>
      <Table size="sm" variant="dark" className="small align-middle">
        <thead>
          <tr><th>When</th><th>Tool</th><th>Setting</th><th>Was</th><th>Now</th><th /></tr>
        </thead>
        <tbody>
          {journal.map((e) => (
            <tr key={e.id}>
              <td>{new Date(e.applied_at).toLocaleString()}</td>
              <td>{e.tool}</td>
              <td>{e.field}</td>
              <td className="text-white-50">{formatValue(e.before)}</td>
              <td className="text-danger">{formatValue(e.after)}</td>
              <td>
                <Button size="sm" variant="outline-secondary" onClick={() => onRevert(e.id)}>
                  Revert
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
    </>
  );
};

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

function groupByTool(rows) {
  const map = {};
  rows.forEach((r) => { (map[r.tool] = map[r.tool] || []).push(r); });
  return Object.keys(map).sort().map((t) => [t, map[t]]);
}

export default WAFProbeResultsModal;
