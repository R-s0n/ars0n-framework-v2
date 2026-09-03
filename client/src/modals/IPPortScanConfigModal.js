import { useCallback, useEffect, useMemo, useState } from 'react';
import { Modal, Tab, Tabs, Alert, Badge, Button, Spinner, Table } from 'react-bootstrap';
import {
  useCompanyToolSettings,
  CompanyToolSettingsPane,
  CompanyToolReferencePane,
  CompanyToolSettingsFooter,
  CompanyToolStatusStrip,
} from './CompanyToolSettings';

// Configuration for Discover Live Web Servers (On-Prem).
//
// THERE IS NO NMAP. The operator asked for "the configurations for nmap" and there is no nmap
// container, nothing in docker-compose.yml, and no exec of an nmap binary anywhere: the scan is
// first-party Go inside the api container using net.DialTimeout. So the tabs below are named after
// what ACTUALLY runs - host discovery, port scanning, the web service probe, range coverage and
// concurrency - and every one of them is a group the SERVER declares. Not one option, flag or
// default is written in this file; they arrive from GET /company-tools/{id}/ip_port_scan/settings,
// the same vocabulary the MCP company tool renders, writing into the same row.
//
// The first tab answers "what will this scan actually touch", which is the question an operator
// opens this screen with. It is deliberately honest about a thing that is easy to get wrong: the
// runner takes EVERY consolidated network range for the target, and the address list it builds from
// each one is not the address list the CIDR implies.

const NUM_AT_START = /^\s*(\d+)/;

// The per-range default the registry's own placeholder states, read out of the server's text rather
// than repeated here. Returns null when it cannot be read, and the screen then says so instead of
// inventing a number.
const declaredDefault = (meta) => {
  const m = NUM_AT_START.exec(String(meta?.placeholder || ''));
  return m ? Number(m[1]) : null;
};

const parseCidr = (cidr) => {
  const s = String(cidr || '').trim();
  const slash = s.lastIndexOf('/');
  if (slash === -1) return null;
  const host = s.slice(0, slash);
  const prefix = Number(s.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0) return null;
  if (host.includes(':')) return { host, prefix, family: 6 };
  const octets = host.split('.');
  if (octets.length !== 4) return null;
  const nums = octets.map((o) => Number(o));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  if (prefix > 32) return null;
  return { host, prefix, family: 4, base: ((nums[0] * 256 + nums[1]) * 256 + nums[2]) * 256 + nums[3] };
};

const intToIPv4 = (n) => [
  Math.floor(n / 16777216) % 256,
  Math.floor(n / 65536) % 256,
  Math.floor(n / 256) % 256,
  n % 256,
].join('.');

// ENUMERATION CAP, mirrored from the registry's owned-flag entry
// "generateIPsFromCIDR maxIPs = 65536": anything wider than a /16 is cut to that many addresses
// BEFORE the per-range limit is applied, which is why a /12 and a /8 behave identically.
const ENUMERATION_CAP = 65536;

// What the scanner will really do with one CIDR. Every rule here is one the registry records in its
// notes and owned flags for this tool; the arithmetic is done on this screen because no endpoint
// serves it, and it is labelled as derived so it is never mistaken for a measurement of a past scan.
const coverageOf = (cidr, perRangeLimit) => {
  const parsed = parseCidr(cidr);
  if (!parsed) {
    return { usable: 0, scanned: 0, skipped: 0, note: 'Not a CIDR this screen could parse.' };
  }
  if (parsed.family === 6) {
    return {
      usable: 0,
      scanned: 0,
      skipped: 0,
      note: 'IPv6: the address generator returns an empty slice for any prefix that is not IPv4, so this range contributes ZERO probed addresses while still counting towards the range total.',
    };
  }
  const size = Math.pow(2, 32 - parsed.prefix);
  const capped = Math.min(size, ENUMERATION_CAP);
  const usable = Math.max(0, capped - 2);
  const scanned = perRangeLimit === null ? usable : Math.min(usable, perRangeLimit);
  const notes = [];
  if (usable === 0) {
    notes.push('The address loop starts at 1 and stops before the last address, so this prefix enumerates ZERO addresses. Nothing in it is ever dialled.');
  }
  if (size > ENUMERATION_CAP) {
    notes.push(`Wider than a /16: enumeration stops at ${ENUMERATION_CAP} addresses before the per-range limit is applied, so ${size.toLocaleString()} addresses become ${capped.toLocaleString()}.`);
  }
  if (scanned < usable) {
    notes.push(`Only the FIRST ${scanned.toLocaleString()} addresses in ascending order are probed. The remaining ${(usable - scanned).toLocaleString()} are never dialled and the scan still reports success.`);
  }
  return {
    usable,
    scanned,
    skipped: usable - scanned,
    first: usable > 0 ? intToIPv4(parsed.base + 1) : null,
    lastScanned: scanned > 0 ? intToIPv4(parsed.base + scanned) : null,
    firstSkipped: usable > scanned ? intToIPv4(parsed.base + scanned + 1) : null,
    lastUsable: usable > 0 ? intToIPv4(parsed.base + usable) : null,
    note: notes.join(' '),
  };
};

function TargetsPane({ ctl, activeTarget, onTrimNetworkRanges, onClose }) {
  const [ranges, setRanges] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    if (!activeTarget?.id) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/consolidated-network-ranges/${activeTarget.id}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setRanges(Array.isArray(body.network_ranges) ? body.network_ranges : []);
    } catch (err) {
      setError('Could not load the consolidated network ranges: ' + err.message);
      setRanges([]);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);

  useEffect(() => { load(); }, [load]);

  // The limit as it stands ON THE FORM, not as last saved, so changing it on the Range Coverage tab
  // is reflected here immediately and an operator can see what widening it buys before saving.
  const limitMeta = ctl.options?.maxIpsPerRange;
  const typed = String(ctl.values?.maxIpsPerRange ?? '').trim();
  const fallback = declaredDefault(limitMeta);
  const perRangeLimit = typed !== '' && Number.isFinite(Number(typed)) ? Math.trunc(Number(typed)) : fallback;
  const usingDefault = typed === '';

  const rows = useMemo(
    () => ranges.map((r) => ({ ...r, coverage: coverageOf(r.cidr_block, perRangeLimit) })),
    [ranges, perRangeLimit],
  );

  const totals = useMemo(() => rows.reduce((acc, r) => ({
    usable: acc.usable + r.coverage.usable,
    scanned: acc.scanned + r.coverage.scanned,
    dead: acc.dead + (r.coverage.usable === 0 ? 1 : 0),
  }), { usable: 0, scanned: 0, dead: 0 }), [rows]);

  return (
    <>
      <CompanyToolStatusStrip ctl={ctl} />

      {/* The one thing an operator must not get wrong about this step: this scan touches every range
          below, and nothing on this screen narrows that. One inline warning line rather than a box,
          because a box that is always there stops being read. The registry states it as an owned
          value ("consolidated_network_ranges (the target set)") and the reference tab carries the
          full reason. */}
      <div className="d-flex gap-2 mb-3" style={{ fontSize: '0.8rem', color: '#ffc107' }}>
        <i className="bi bi-exclamation-triangle-fill" style={{ lineHeight: '1.5' }} />
        <span>
          EVERY consolidated range below is scanned. There is no per-range tick box here because the
          runner does not read one: it selects every consolidated range for this target, unfiltered.
          The two levers that really change what is touched are <strong>Trim Network Ranges</strong>{' '}
          (remove ranges at the source, then Consolidate again) and{' '}
          <strong>Maximum addresses probed per network range</strong> on the Range Coverage tab.
        </span>
      </div>

      {error && <Alert variant="danger" className="py-2" style={{ fontSize: '0.8rem' }}>{error}</Alert>}

      {loading ? (
        <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
      ) : rows.length === 0 ? (
        <div className="text-center py-4">
          <i className="bi bi-diagram-3 text-white-50" style={{ fontSize: '3rem' }} />
          <h5 className="text-white-50 mt-3">No consolidated network ranges</h5>
          <p className="text-white-50" style={{ fontSize: '0.85rem' }}>
            Run Amass Intel and Metabigor, then Consolidate, before this scan has anything to probe.
          </p>
        </div>
      ) : (
        <>
          <div className="text-danger mb-3">
            <div className="row text-center">
              <div className="col">
                <h3 className="mb-0">{rows.length}</h3>
                <small className="text-white-50">Ranges<br />in scope</small>
              </div>
              <div className="col">
                <h3 className="mb-0">{totals.usable.toLocaleString()}</h3>
                <small className="text-white-50">Addresses<br />the ranges hold</small>
              </div>
              <div className="col">
                <h3 className="mb-0">{totals.scanned.toLocaleString()}</h3>
                <small className="text-white-50">Addresses<br />actually probed</small>
              </div>
              <div className="col">
                <h3 className="mb-0">{(totals.usable - totals.scanned).toLocaleString()}</h3>
                <small className="text-white-50">Addresses<br />silently skipped</small>
              </div>
              <div className="col">
                <h3 className="mb-0">{totals.dead}</h3>
                <small className="text-white-50">Ranges yielding<br />no address at all</small>
              </div>
            </div>
          </div>

          <div className="text-white-50 mb-2" style={{ fontSize: '0.75rem' }}>
            Per-range limit in effect: <strong>{perRangeLimit === null ? 'unknown' : perRangeLimit.toLocaleString()}</strong>
            {usingDefault
              ? ' (the runner default, because the Range Coverage tab leaves it unset)'
              : ' (from the Range Coverage tab, unsaved changes included)'}.
            The address counts below are worked out on this screen from each CIDR using the rules the
            registry records for this tool; open the last tab to read them. They describe what the
            NEXT scan would touch, not what a past scan did.
          </div>

          <div style={{ maxHeight: '380px', overflowY: 'auto', border: '1px solid var(--bs-border-color)', borderRadius: '0.375rem' }}>
            <Table hover variant="dark" size="sm" className="mb-0">
              <thead style={{ position: 'sticky', top: 0, zIndex: 10 }}>
                <tr>
                  <th style={{ backgroundColor: 'var(--bs-dark)' }}>CIDR</th>
                  <th style={{ backgroundColor: 'var(--bs-dark)' }}>Source</th>
                  <th style={{ backgroundColor: 'var(--bs-dark)' }}>Organisation</th>
                  <th style={{ backgroundColor: 'var(--bs-dark)' }} className="text-end">Probed / held</th>
                  <th style={{ backgroundColor: 'var(--bs-dark)' }}>Addresses reached</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={`${r.cidr_block}-${i}`}>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>
                      {r.cidr_block}
                      {r.asn ? <div className="text-white-50" style={{ fontSize: '0.7rem' }}>AS{String(r.asn).replace(/^AS/i, '')}</div> : null}
                    </td>
                    <td style={{ fontSize: '0.78rem' }}>{r.source || r.scan_type || '-'}</td>
                    <td style={{ fontSize: '0.78rem' }}>{r.organization || '-'}</td>
                    <td className="text-end" style={{ fontSize: '0.8rem' }}>
                      {r.coverage.usable === 0 ? (
                        <Badge bg="danger">0</Badge>
                      ) : (
                        <>
                          <span className={r.coverage.skipped > 0 ? 'text-warning' : 'text-white'}>
                            {r.coverage.scanned.toLocaleString()}
                          </span>
                          <span className="text-white-50"> / {r.coverage.usable.toLocaleString()}</span>
                        </>
                      )}
                    </td>
                    <td style={{ fontSize: '0.75rem' }}>
                      {r.coverage.scanned > 0 && (
                        <div style={{ fontFamily: 'monospace' }}>
                          {r.coverage.first} &ndash; {r.coverage.lastScanned}
                        </div>
                      )}
                      {r.coverage.skipped > 0 && (
                        <div className="text-warning" style={{ fontFamily: 'monospace' }}>
                          never dialled: {r.coverage.firstSkipped} &ndash; {r.coverage.lastUsable}
                        </div>
                      )}
                      {r.coverage.note && (
                        <div className="text-white-50" style={{ fontSize: '0.72rem' }}>{r.coverage.note}</div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </>
      )}

      <div className="d-flex gap-2 mt-3">
        <Button variant="outline-danger" size="sm" onClick={load} disabled={loading}>
          <i className="bi bi-arrow-clockwise me-1" />
          Reload ranges
        </Button>
        {onTrimNetworkRanges && (
          <Button
            variant="outline-danger"
            size="sm"
            onClick={() => { if (onClose) onClose(); onTrimNetworkRanges(); }}
          >
            <i className="bi bi-scissors me-1" />
            Trim Network Ranges
          </Button>
        )}
      </div>
    </>
  );
}

function IPPortScanConfigModal({ show, handleClose, activeTarget, onTrimNetworkRanges }) {
  const ctl = useCompanyToolSettings({ activeTarget, toolKey: 'ip_port_scan', show });
  const [tab, setTab] = useState('targets');

  useEffect(() => { if (show) setTab('targets'); }, [show]);

  return (
    <Modal
      show={show}
      onHide={handleClose}
      size="xl"
      data-bs-theme="dark"
      className="modal-90w"
      scrollable
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-hdd-network me-2" />
          Discover Live Web Servers (On-Prem) &mdash; configuration
        </Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ minHeight: '60vh' }}>
        {/* What the scanner REALLY is, so nobody hunts for nmap options that cannot exist. Context,
            not a problem, so it reads as quiet text. The wording is the registry's own (its version
            and runner fields) with a plain fallback for the case where the API does not have the
            Company registry yet. */}
        <div className="text-white-50 mb-3" style={{ fontSize: '0.78rem' }}>
          {ctl.data?.version || 'This scan is first-party Go inside the api container, not a packaged scanner.'}
          {ctl.data?.invocation ? <> Implemented in <code>{ctl.data.invocation}</code>.</> : null}
          {' '}It dials TCP with a plain connect: there is no nmap here, so there are no nmap options
          to set. The tabs are named after the phases this scanner actually has.
        </div>

        <Tabs activeKey={tab} onSelect={(k) => setTab(k || 'targets')} className="mb-3">
          <Tab eventKey="targets" title="Targets (ranges & addresses)">
            <TargetsPane
              ctl={ctl}
              activeTarget={activeTarget}
              onTrimNetworkRanges={onTrimNetworkRanges}
              onClose={handleClose}
            />
          </Tab>
          {ctl.sections.map((section) => (
            <Tab
              key={section.group}
              eventKey={`group:${section.group}`}
              title={`${section.group} (${section.keys.length})`}
            >
              <CompanyToolSettingsPane ctl={ctl} group={section.group} />
            </Tab>
          ))}
          <Tab eventKey="reference" title="What runs & what is fixed">
            <CompanyToolReferencePane ctl={ctl} />
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer>
        <CompanyToolSettingsFooter ctl={ctl} onClose={handleClose} />
      </Modal.Footer>
    </Modal>
  );
}

export default IPPortScanConfigModal;
