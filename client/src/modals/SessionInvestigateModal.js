import { useState, useEffect, useCallback } from 'react';
import { Modal, Row, Col, Button, Badge, Alert, Spinner, Form, Table } from 'react-bootstrap';

// WHAT THIS SCREEN IS FOR.
//
// Every authenticated scan outlives its session token and, until the token characterisation
// engine landed, nothing in the framework measured how long a token lives. Measured on a live
// target on 2026-09-20: the bearer was a fifteen minute JWT, six distinct tokens arrived in ten
// minutes of browsing, and a full triage run takes twenty nine minutes. The same endpoint in the
// same minute returned 401 for the token frozen in a stored request and 200 for the freshest one.
//
// So this is the screen that answers, for whatever application the operator is on: what
// credentials does it hand out, what kind of thing is each one, HOW LONG DOES IT LIVE, HOW DO WE
// KNOW THAT, and can it be renewed.
//
// THREE RULES THIS FILE IS BUILT AROUND.
//
// 1. THE CREDENTIAL IS RENDERED, VERBATIM. This is a bug bounty framework and a captured
//    credential IS the finding: a leaked token is proved by showing the token, and a screen that
//    prints a fingerprint where the bytes should be has destroyed the proof. The server serves
//    the value, so this screen shows it, unwrapped and selectable, with the fingerprint and the
//    byte length beside it because those are what tell two credentials apart at a glance.
//
// 2. AN UNKNOWN LIFETIME SAYS UNKNOWN AND LOOKS DIFFERENT FROM A KNOWN ONE. A dash, a blank or a
//    zero all read as "no expiry", which is the opposite of what an unmeasured lifetime means.
//    Every duration on this screen comes from the server already rendered for exactly that
//    reason, and summariseSessionTtl below refuses the three bad renderings even if the server
//    ever sends one.
//
// 3. NOTHING IS RE-DERIVED. The provenance, the evidence, the survival verdict and the choice of
//    which credential governs the scan are all the server's. A screen that recomputes any of them
//    can disagree with the runner about what is being sent, which is worse than no screen.

// TTL_UNKNOWN is the one spelling of an unmeasured lifetime, shared with the tests and with the
// Authentication card so no third rendering can appear.
export const TTL_UNKNOWN = 'UNKNOWN';

// The three renderings an operator reads as "no expiry". Any of them arriving in a lifetime field
// is treated as unmeasured rather than shown.
const READS_AS_NO_EXPIRY = new Set(['', '-', '0', '0s', 'null', 'undefined', 'n/a']);

// provenanceTone maps how a number was obtained to how confident the screen looks about it.
// Measured and typed-in must never share a colour: that distinction is the whole feature.
export function provenanceTone(provenance) {
  switch (String(provenance || '').toLowerCase()) {
    case 'parsed': return 'success';
    case 'probed': return 'success';
    case 'observed': return 'info';
    case 'declared': return 'warning';
    default: return 'secondary';
  }
}

const PROVENANCE_WORD = {
  parsed: 'Parsed',
  probed: 'Probed',
  observed: 'Observed',
  declared: 'Declared',
  unknown: 'Not measured',
};

// refreshTone keeps the four refresh states visually distinct. Only proven is a working option;
// available means a mechanism exists that nobody has exercised, which is not the same thing.
export function refreshTone(status) {
  switch (String(status || '').toLowerCase()) {
    case 'proven': return 'success';
    case 'available': return 'info';
    case 'mint_out_of_scope': return 'warning';
    default: return 'secondary';
  }
}

const REFRESH_WORD = {
  proven: 'Proven',
  available: 'Mechanism found, never exercised',
  mint_out_of_scope: 'Mint host is out of scope',
  not_observed: 'None observed',
  // NOT THE SAME FACT AS not_observed. That one is the ANSWER OF A SEARCH over the auth flows, the
  // captured corpus and the token's own grants (DetectRefreshCapability). This one is what a
  // credential carries before anything has looked, and the server names it rather than leaving the
  // field empty precisely so this map can tell the two apart: the fallback below is
  // REFRESH_WORD[s] || s || 'None observed', so without an entry here the badge printed the raw
  // snake_case token at the operator.
  not_characterised: 'Not characterised yet',
};

const REFRESH_MECHANISM_WORD = {
  oauth_refresh_token: 'OAuth refresh token',
  token_endpoint: 'Token endpoint',
  auth_flow_replay: 'Replay of a recorded auth flow',
  silent_renew_endpoint: 'Silent renew endpoint',
  server_reissue_on_use: 'Server reissues on use',
};

const SURVIVES_WORD = { yes: 'Yes', no: 'No', unknown: 'Unknown' };

function survivesTone(answer) {
  switch (String(answer || '').toLowerCase()) {
    case 'yes': return 'success';
    case 'no': return 'danger';
    default: return 'secondary';
  }
}

// summariseSessionTtl turns an investigation report into the Authentication card's tile.
//
// It is exported and tested on its own because the card is the part of this feature an operator
// sees without opening anything, and the one thing it may never do is present a lifetime nobody
// measured as though somebody had. Everything that is not a positively rendered duration comes
// back as the word UNKNOWN with known false, including a report that failed to load.
export function summariseSessionTtl(report) {
  const metric = report && report.ttl_metric;
  const unmeasured = (detail) => ({
    value: TTL_UNKNOWN,
    known: false,
    state: (metric && metric.state) || 'not_loaded',
    detail: detail || 'not characterised yet',
    explain: (metric && metric.explain)
      || 'Nothing has measured how long this application\'s credentials live. Open Investigate to characterise them.',
  });

  if (!metric) return unmeasured();

  const value = String(metric.value == null ? '' : metric.value).trim();
  if (!value || READS_AS_NO_EXPIRY.has(value.toLowerCase())) {
    return unmeasured(metric.detail);
  }
  return {
    value,
    known: !!metric.known,
    state: metric.state || (metric.known ? 'measured' : 'unknown'),
    detail: metric.detail || '',
    explain: metric.explain || '',
  };
}

// A DURATION ON THIS SCREEN IS ONE OF THREE THINGS AND THEY MAY NOT LOOK ALIKE.
//
//   measured  a settled lifetime somebody read: "15m"
//   bounded   a real quantity that is not a settled lifetime: "<=15m", the upper bound the server
//             publishes when a credential the same scan sends was never measured
//   word      a word standing in for a measurement nobody took: UNKNOWN, NO SESSION
//
// AND ONLY THE WORD MAY BE SHOUTED IN CAPITALS. text-uppercase used to be applied to everything
// with known false, and the server sends the upper bound with known false BECAUSE A BOUND IS NOT A
// MEASUREMENT. Measured before this rule existed:
//
//	x FAILFIRST A: a measured upper bound is not uppercased into a unit error
//	    Expected substring: not "text-uppercase"
//	    Received string:        "fs-6 fw-bold text-secondary text-uppercase"
//
// CSS rendered "<=15m" as "<=15M". Minutes and months differ by a factor of about 43,800, and
// this is the single number the whole feature exists to communicate.
//
// So the styling ASKS WHAT THE STRING IS rather than reading it off one boolean: a value carrying
// a digit is a quantity and is rendered exactly as the server wrote it. Nothing here parses the
// quantity or re-derives it; it only declines to rewrite it.
export const DURATION_MEASURED = 'measured';
export const DURATION_BOUNDED = 'bounded';
export const DURATION_WORD = 'word';

export function durationShape(value, known) {
  if (!/\d/.test(String(value == null ? '' : value))) return DURATION_WORD;
  return known ? DURATION_MEASURED : DURATION_BOUNDED;
}

const DURATION_CLASS = {
  // Large and in the card's accent colour: this is a lifetime somebody measured.
  [DURATION_MEASURED]: 'fs-4 fw-bold text-danger font-monospace',
  // The number is still there, because the bound is real information, but nothing about it is
  // styled as settled. Amber is the same colour this screen gives a declared, unverified figure.
  [DURATION_BOUNDED]: 'fs-5 fw-bold font-monospace',
  // Smaller, grey and spelled out, so an absence of measurement cannot be mistaken for a long one.
  [DURATION_WORD]: 'fs-6 fw-bold text-secondary text-uppercase',
};

function Duration({ value, known, testid }) {
  const shape = durationShape(value, known);
  return (
    <span
      data-testid={testid}
      data-ttl-known={known ? 'true' : 'false'}
      data-ttl-shape={shape}
      className={DURATION_CLASS[shape]}
      style={shape === DURATION_BOUNDED ? { color: '#ffc107' } : undefined}
    >
      {value}
    </span>
  );
}

// ---------------------------------------------------------------------------------------------
// WHAT THE RUNNER WOULD ACTUALLY PUT ON THE WIRE
// ---------------------------------------------------------------------------------------------
//
// THIS IS THE QUESTION THE CARD EXISTS FOR: will my scan be authenticated. Round 12 made the
// report read the runner's OWN credential source rather than restating session_tokens, because the
// working credential on a live engagement was in manual_crawl_captures and the stale one was in
// the vector. The payload has carried the answer since, and the screen rendered none of it:
//
//	x FAILFIRST B: the screen shows what the runner would actually put on the wire
//	    expect(received).not.toBeNull()   Received: null
//
// AND A SOURCE THAT COULD NOT BE CONSULTED IS NOT AN EMPTY ONE. There is no database handle in a
// unit test and no host on a target whose scope_target row will not read, and either way the
// honest answer is UNKNOWN. Rendering that as "0 credentials would go out" would be this screen
// asserting the runner sends nothing, which is the exact class of unread fact the feature exists
// to refuse. So the two states have different markup, different wording and a different colour,
// and the count is withheld entirely in the second.
export const WIRE_READ = 'read';
export const WIRE_NOT_READ = 'not_read';

// countOrUnknown keeps a missing count missing. Number(null) is 0 and Number(undefined) is NaN,
// so a plain Number() here is how an absent count becomes a confident zero.
function countOrUnknown(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

export function wireReading(report) {
  const w = (report && report.wire) || null;
  const counts = (report && report.counts) || {};
  if (!w || !w.known) {
    return {
      state: WIRE_NOT_READ,
      known: false,
      host: (w && w.host) || '',
      sources: [],
      onWire: null,
      fresh: null,
      expired: null,
      exhausted: false,
      note: '',
      why: (w && w.why_not_known)
        || (report
          ? 'this report carries no reading of the runner\'s credential source'
          : 'nothing has been loaded yet'),
    };
  }
  return {
    state: WIRE_READ,
    known: true,
    host: w.host || '',
    sources: Array.isArray(w.sources) ? w.sources : [],
    onWire: countOrUnknown(counts.on_wire),
    fresh: countOrUnknown(w.fresh),
    expired: countOrUnknown(w.expired),
    exhausted: !!w.exhausted,
    note: w.note || '',
    why: '',
  };
}

// The three answers to "does the runner send THIS credential". Unknown is not a no: see above.
export const ON_WIRE_YES = 'yes';
export const ON_WIRE_NO = 'no';
export const ON_WIRE_UNKNOWN = 'unknown';

export function credentialOnWire(credential, wireKnown) {
  if (!wireKnown) {
    return {
      answer: ON_WIRE_UNKNOWN,
      word: 'UNKNOWN',
      tone: 'secondary',
      // on_the_wire is a Go bool and arrives false whether the source said no or was never asked.
      // Reading that false as a no is how a screen states a fact nobody measured.
      note: 'the runner\'s credential source was not consulted, so whether this one goes out was not read',
    };
  }
  const c = credential || {};
  return c.on_the_wire
    ? { answer: ON_WIRE_YES, word: 'Yes', tone: 'success', note: c.wire_note || '' }
    : { answer: ON_WIRE_NO, word: 'No', tone: 'secondary', note: c.wire_note || '' };
}

// SOURCE_WORD turns the table name into the distinction that matters: a credential somebody typed
// into the Session Manager against one a real browser produced and the manual crawl caught. The
// server already sends its own label; this is the fallback for a source it has no word for.
const SOURCE_WORD = {
  session_tokens: 'stored in the Session Manager',
  manual_crawl_captures: 'captured from a real browser session',
};

function WirePanel({ wire }) {
  const border = wire.known ? 'border-secondary' : '';
  return (
    <div
      data-testid="wire-reading"
      data-wire-known={wire.known ? 'true' : 'false'}
      className={`border rounded p-2 mb-3 ${border}`}
      style={wire.known ? undefined : { borderColor: '#ffc107' }}
    >
      <div className="text-white-50 text-uppercase mb-1" style={{ fontSize: '0.68rem', letterSpacing: '0.05em' }}>
        What a scan would actually send
      </div>

      {wire.known ? (
        <div className="small text-white">
          <span className="font-monospace fw-bold" data-testid="wire-on-wire">
            {wire.onWire === null ? TTL_UNKNOWN : wire.onWire}
          </span>
          {/* "UNKNOWN credential(s) would go out" reads as credentials nobody recognises, which is
              a different and wrong fact. A missing count gets its own sentence shape. */}
          {wire.onWire === null
            ? ' is how many credentials would go out to '
            : ' credential(s) would go out to '}
          <span className="font-monospace">{wire.host || 'this target'}</span>,
          asked of the runner's own credential source rather than of the stored list.
          <div className="text-white-50" style={{ fontSize: '0.75rem' }}>
            {wire.sources.length > 0 && (
              <>Consulted: {wire.sources.map((s) => SOURCE_WORD[s] || s).join(', ')}. </>
            )}
            {wire.fresh === null
              ? 'How many candidates it held was not reported. '
              : `${wire.fresh} usable candidate(s). `}
            {wire.expired === null
              ? 'How many it rejected as expired was not reported.'
              : `${wire.expired} rejected because their own expiry had passed.`}
          </div>
          {wire.exhausted && (
            <div style={{ fontSize: '0.75rem', color: '#ffc107' }}>
              This source DID hold a usable credential for this host and holds none now, which is
              not the same as never having had one.
            </div>
          )}
          {wire.note && (
            <div className="text-white-50" style={{ fontSize: '0.75rem' }}>{wire.note}</div>
          )}
        </div>
      ) : (
        <div className="small" style={{ color: '#ffc107' }}>
          NOT READ: {wire.why}.
          <div className="text-white-50" style={{ fontSize: '0.75rem' }}>
            That is an absence of a reading and not a count of zero, so no number is shown here.
            Everything below is the stored credentials only, and the runner substitutes the
            freshest captured credential at send time: a credential this list does not show may be
            the one on the wire.
          </div>
        </div>
      )}
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div className="mb-2">
      <div className="text-white-50 text-uppercase" style={{ fontSize: '0.68rem', letterSpacing: '0.05em' }}>{label}</div>
      <div className="small text-white">{children}</div>
    </div>
  );
}

function CredentialPanel({ credential, runLabel, runSource, wireKnown }) {
  const c = credential;
  const provenance = String(c.ttl_provenance || 'unknown').toLowerCase();
  const onWire = credentialOnWire(c, wireKnown);

  return (
    <div
      data-testid={`credential-${c.token_id}`}
      className={`border rounded p-3 mb-3 ${c.governs ? 'border-danger' : 'border-secondary'}`}
    >
      <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
        <span className="fw-bold text-danger" data-governs={c.governs ? 'true' : undefined}>{c.name}</span>
        <Badge bg="dark" className="border border-secondary">{c.kind_label || c.kind}</Badge>
        <Badge bg="dark" className="border border-secondary">{c.carrier}</Badge>
        {c.governs && <Badge bg="danger">Governs the scan</Badge>}
        {c.sendable
          ? <Badge bg="success">Sent by scans</Badge>
          : <Badge bg="secondary">Not sent</Badge>}
        {!c.measured && <Badge bg="secondary">Not characterised</Badge>}
        {/* WHERE THIS CREDENTIAL CAME FROM. A row somebody typed into the Session Manager and one
            a real browser produced are different facts, and the second is the one the runner
            prefers at send time. */}
        {c.source_label && (
          <Badge bg="dark" className="border border-secondary" data-testid={`source-${c.token_id}`}>
            {c.source_label}
          </Badge>
        )}
        {c.stored === false && <Badge bg="dark" className="border border-secondary">Not in the Session Manager</Badge>}
      </div>

      {!c.sendable && c.not_sendable_reason && (
        <div className="small text-warning mb-2">Not sent: {c.not_sendable_reason}</div>
      )}

      {/* THE ANSWER TO "WILL MY SCAN SEND THIS ONE". It is the runner's own source that answers,
          not the Session Manager's rules above it, and where the two disagree the runner is what
          decides the bytes. An unconsulted source says UNKNOWN rather than borrowing the Go zero
          value of on_the_wire, which is false and means nothing. */}
      <div
        className="small mb-2"
        data-testid={`onwire-${c.token_id}`}
        data-on-wire={onWire.answer}
      >
        <span className="text-white-50">What the runner sends: </span>
        <Badge bg={onWire.tone}>{onWire.word}</Badge>
        {onWire.note && <span className="ms-2 text-white-50" style={{ fontSize: '0.75rem' }}>{onWire.note}</span>}
        {wireKnown && c.wire_expiry_source && (
          <div className="text-white-50" style={{ fontSize: '0.75rem' }}>
            The runner reads its expiry from {c.wire_expiry_source}
            {c.wire_expires_at ? `: ${c.wire_expires_at}` : ''}.
          </div>
        )}
        {c.observed_at && (
          <div className="text-white-50" style={{ fontSize: '0.75rem' }}>
            The row carrying it was written {c.observed_at}.
          </div>
        )}
      </div>

      {c.declared_disagrees && (
        <Alert variant="warning" className="py-2 small mb-2">
          {c.declared_disagreement}
        </Alert>
      )}

      <Row className="g-3">
        <Col md={4}>
          <Field label="Lifetime">
            <div className="d-flex align-items-center gap-2 flex-wrap">
              <Duration value={c.ttl_short} known={!!c.ttl_known} testid={`ttl-${c.token_id}`} />
              <Badge bg={provenanceTone(provenance)}>{PROVENANCE_WORD[provenance] || provenance}</Badge>
            </div>
            <div className="text-white-50 mt-1" style={{ fontSize: '0.75rem' }}>
              {c.ttl_known ? c.ttl_provenance_label : 'no lifetime has been measured for this credential'}
            </div>
            {c.ttl_evidence && (
              <div className="text-white-50 mt-1" style={{ fontSize: '0.75rem' }}>{c.ttl_evidence}</div>
            )}
          </Field>

          {c.ttl_floor_known && (
            <Field label="Observed floor">
              <span className="font-monospace">at least {c.ttl_floor_short}</span>
              <div className="text-white-50 mt-1" style={{ fontSize: '0.75rem' }}>
                A lower bound taken from captured traffic, never a lifetime.{' '}
                {c.observed_samples} distinct value(s) across {c.observed_requests} request(s).
                {c.observed_evidence ? ` ${c.observed_evidence}` : ''}
              </div>
            </Field>
          )}
        </Col>

        <Col md={4}>
          <Field label="Expiry">
            <div className="font-monospace">{c.expiry_display}</div>
            <div className="text-white-50 mt-1" style={{ fontSize: '0.75rem' }}>{c.expiry_style_label}</div>
            {c.expiry_evidence && (
              <div className="text-white-50" style={{ fontSize: '0.75rem' }}>{c.expiry_evidence}</div>
            )}
          </Field>
          <Field label="Life left">
            <span className={c.remaining_known ? 'font-monospace' : 'text-secondary text-uppercase'}>
              {c.remaining_short}
            </span>
          </Field>
          {c.rotation_known && (
            <Field label="Client swapped credential every">
              <span className="font-monospace">{c.rotation_short}</span>
              <div className="text-white-50 mt-1" style={{ fontSize: '0.75rem' }}>
                How often a new value arrived in captured traffic. This is the client's habit, not the server's lifetime.
              </div>
            </Field>
          )}
        </Col>

        <Col md={4}>
          {/* THE CREDENTIAL ITSELF. It is the evidence, so it is on screen in full: wrapped
              rather than truncated, selectable, and exactly the bytes the server read. The
              fingerprint and the length stay beside it because they are how one credential is
              told from another in a log line and against the runner's own reading. */}
          <Field label="Value">
            <div
              data-testid={`value-${c.token_id}`}
              className="font-monospace bg-black rounded p-2"
              style={{ fontSize: '0.72rem', wordBreak: 'break-all', maxHeight: '9rem', overflowY: 'auto', userSelect: 'text' }}
            >
              {c.value || 'this report carries no value for this credential'}
            </div>
            <div className="text-white-50 mt-1" style={{ fontSize: '0.75rem' }}>
              fingerprint <span className="font-monospace">{c.fingerprint}</span>, {c.value_length} bytes
              on the wire{c.scheme ? `, prefixed with "${c.scheme} " when it is sent` : ''}.
            </div>
          </Field>
          <Field label="Renewal">
            <Badge data-testid={`refresh-${c.token_id}`} bg={refreshTone(c.refresh && c.refresh.status)}>
              {REFRESH_WORD[c.refresh && c.refresh.status] || (c.refresh && c.refresh.status) || 'None observed'}
            </Badge>
            {c.refresh && c.refresh.mechanism && (
              <div className="mt-1">{REFRESH_MECHANISM_WORD[c.refresh.mechanism] || c.refresh.mechanism}</div>
            )}
            {c.refresh && c.refresh.mint_host && (
              <div className="text-white-50" style={{ fontSize: '0.75rem' }}>
                minted by {c.refresh.mint_host}
                {c.refresh.mint_in_scope ? ', inside this engagement' : ', outside this engagement'}
              </div>
            )}
            {c.refresh && Array.isArray(c.refresh.evidence) && c.refresh.evidence.map((e, i) => (
              <div key={i} className="text-white-50" style={{ fontSize: '0.75rem' }}>{e}</div>
            ))}
          </Field>
          {c.survives && (
            <Field label="Survives the run">
              <span data-testid={`survives-${c.token_id}`} data-answer={c.survives.answer}>
                <Badge bg={survivesTone(c.survives.answer)}>
                  {SURVIVES_WORD[c.survives.answer] || c.survives.answer}
                </Badge>
                <span className="ms-2 text-white-50" style={{ fontSize: '0.75rem' }}>{c.survives.why}</span>
              </span>
              {/* WHICH run. A survival verdict with no run named beside it is the thing that let
                  this screen and the Investigate settings screen disagree in silence. */}
              {runLabel && (
                <div className="text-white-50" data-run-source={runSource} style={{ fontSize: '0.72rem' }}>
                  asked about {runLabel}
                </div>
              )}
            </Field>
          )}
        </Col>
      </Row>

      {Array.isArray(c.claims) && c.claims.length > 0 && (
        <div className="mt-2">
          <div className="text-white-50 text-uppercase mb-1" style={{ fontSize: '0.68rem', letterSpacing: '0.05em' }}>
            What the credential says about itself
          </div>
          <Table size="sm" variant="dark" className="mb-0 small">
            <tbody>
              {c.claims.map((claim) => (
                <tr key={claim.name}>
                  <td className="text-white-50" style={{ width: '6rem' }}>{claim.name}</td>
                  <td className="font-monospace" style={{ wordBreak: 'break-all' }}>{claim.value}</td>
                  <td className="text-white-50">{claim.note}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}

      {c.kind_evidence && (
        <div className="text-white-50 mt-2" style={{ fontSize: '0.75rem' }}>How we know what it is: {c.kind_evidence}</div>
      )}

      {Array.isArray(c.warnings) && c.warnings.map((warning, i) => (
        <div key={i} className="text-warning mt-1" style={{ fontSize: '0.75rem' }}>{warning}</div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// THE RUN LENGTH THE SURVIVAL QUESTION IS ASKED ABOUT
// ---------------------------------------------------------------------------------------------
//
// THIS USED TO BE A HARDCODED 29 AND THAT WAS A SECOND SOURCE OF TRUTH.
//
// 29 minutes is what one full triage run took on one target on one day. The renewal gate on the
// Investigate settings screen asks the same survival question against TriageEstimatedRunDuration,
// which is the configured run's own budget at the configured run's own rate and is 20m1s on the
// shipped defaults. Two screens, one credential, two run lengths: a 25 minute credential survives
// on one and dies on the other, and neither says which number it used. Contradictory verdicts for
// the same session were reachable and nothing on either screen would have shown the operator why.
//
// So the measurement is asked for rather than assumed, and it comes from the server that derives
// it. The operator can still ask a what-if, and when they do, the screen says it is THEIR figure
// and not a measurement. The one thing that may not happen is a number appearing with no label
// saying where it came from, which is the defect this entire feature exists to end.
//
// AND AN UNREADABLE ESTIMATE IS UNKNOWN. If the settings could not be read there is no fallback
// constant to drop back to: falling back to 29 is how the old disagreement was invisible. The
// control says UNKNOWN, the measured option is unavailable, and the operator supplies a number
// that is then labelled as theirs.

// How the run length on screen was arrived at.
export const RUN_LENGTH_MEASURED = 'measured';
export const RUN_LENGTH_OPERATOR = 'operator';
export const RUN_LENGTH_UNKNOWN = 'unknown';

// runLengthFromServer reads the configured run's estimated length out of whichever server answer
// carries it.
//
// The investigate report is preferred when it carries one, because it is this screen's own
// payload and was computed for this question. The renewal gate is the fallback and the same
// arithmetic: both come from the settings document's pacing. Neither is trusted to be present.
//
// Minutes are rounded UP. The API this screen drives takes whole minutes, the estimate is 1201
// seconds, and rounding down would ask about a run one second shorter than the one that will be
// run. Up errs towards "it might not last", which is the direction that cannot produce a false
// assurance.
export function runLengthFromServer(report, gate) {
  const reported = Number(report && report.default_run_minutes);
  if (Number.isFinite(reported) && reported > 0) {
    return {
      minutes: Math.ceil(reported),
      known: true,
      source: RUN_LENGTH_MEASURED,
      basis: (report && report.run_length_basis) || '',
    };
  }
  const seconds = Number(gate && gate.evaluated && gate.run_estimate_seconds);
  if (Number.isFinite(seconds) && seconds > 0) {
    return {
      minutes: Math.ceil(seconds / 60),
      known: true,
      source: RUN_LENGTH_MEASURED,
      basis: (gate && gate.run_estimate_basis) || '',
    };
  }
  return { minutes: 0, known: false, source: RUN_LENGTH_UNKNOWN, basis: '' };
}

// runLengthQuestion is the whole answer to "what run is this screen asking about, and who said
// so". It is exported and tested on its own because it is the sentence that stops the two screens
// from disagreeing silently.
export function runLengthQuestion(measured, useOperatorFigure, operatorMinutes) {
  const typed = Math.floor(Number(operatorMinutes));
  const typedOK = Number.isFinite(typed) && typed > 0;

  if (useOperatorFigure || !measured.known) {
    return {
      minutes: typedOK ? typed : 0,
      known: typedOK,
      source: typedOK ? RUN_LENGTH_OPERATOR : RUN_LENGTH_UNKNOWN,
      label: typedOK
        ? `a ${typed} minute run, which is the figure you asked about and not a measurement`
        : 'no run length: nothing measured one and none was supplied, so the survival question cannot be asked',
      measuredUnavailable: !measured.known,
    };
  }
  return {
    minutes: measured.minutes,
    known: true,
    source: RUN_LENGTH_MEASURED,
    label: `the configured Investigate run${measured.basis ? `: ${measured.basis}` : ''}`,
    measuredUnavailable: false,
  };
}

const SessionInvestigateModal = ({ show, handleClose, scopeTargetId, scopeTargetUrl }) => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // The configured run's estimated length, as the server derives it, and whether it could be read
  // at all. There is deliberately no default: see the block comment above runLengthFromServer.
  const [renewalGate, setRenewalGate] = useState(null);
  const [runLengthError, setRunLengthError] = useState('');
  // The operator's what-if: off by default, and labelled as their question whenever it is on.
  const [useOwnFigure, setUseOwnFigure] = useState(false);
  const [ownMinutes, setOwnMinutes] = useState('');

  // The measured run length is fetched from the settings endpoint, which is where
  // TriageEstimatedRunDuration is served from. It is its OWN request with its OWN error state: a
  // settings endpoint that is down must not blank the credential report, and it must not silently
  // supply a number either.
  const loadRunLength = useCallback(async () => {
    if (!scopeTargetId) return;
    try {
      const res = await fetch(`/api/triage/${scopeTargetId}/settings`);
      if (!res.ok) throw new Error(`status ${res.status}`);
      const body = await res.json();
      const gate = (body && body.renewal_gate) || null;
      setRenewalGate(gate);
      setRunLengthError(gate && gate.evaluated && Number(gate.run_estimate_seconds) > 0
        ? ''
        : 'the Investigate settings did not carry an estimated run length');
    } catch (e) {
      setRenewalGate(null);
      setRunLengthError(`the configured run length could not be read: ${e.message}`);
    }
  }, [scopeTargetId]);

  const load = useCallback(async (minutes, reprofile) => {
    if (!scopeTargetId) return;
    setLoading(true);
    setError('');
    try {
      const n = Number(minutes);
      const query = Number.isInteger(n) && n > 0 ? `?run_minutes=${n}` : '';
      const url = `/api/session-tokens/target/${scopeTargetId}/investigate${reprofile ? '' : query}`;
      const res = reprofile
        ? await fetch(`/api/session-tokens/target/${scopeTargetId}/investigate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reprofile: true, run_minutes: Number.isInteger(n) && n > 0 ? n : undefined }),
        })
        : await fetch(url);
      if (!res.ok) {
        const detail = res.text ? await res.text() : '';
        throw new Error(String(detail || `status ${res.status}`).trim());
      }
      setReport(await res.json());
    } catch (e) {
      // Said out loud rather than left as an empty list. An empty screen here reads as "this
      // target has no credentials", which is a statement of fact we are in no position to make.
      setError(`The credentials could not be characterised: ${e.message}`);
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [scopeTargetId]);

  useEffect(() => {
    if (show && scopeTargetId) {
      loadRunLength();
      load(0, false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [show, scopeTargetId]);

  const measuredRun = runLengthFromServer(report, renewalGate);
  const question = runLengthQuestion(measuredRun, useOwnFigure, ownMinutes);
  const askAgain = () => load(question.known ? question.minutes : 0, false);

  const tile = summariseSessionTtl(report);
  const wire = wireReading(report);
  const targetHost = (() => {
    try { return scopeTargetUrl ? new URL(scopeTargetUrl).hostname : ''; } catch (e) { return scopeTargetUrl || ''; }
  })();

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          Investigate Authentication{targetHost ? ` - ${targetHost}` : ''}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '60vh' }}>
        {!scopeTargetId ? (
          <div className="text-center text-white-50 py-5">Select a scope target first.</div>
        ) : (
          <>
            <p className="text-white small fst-italic">
              What this application hands out as a credential, how long each one lives, and how we know that.
              A lifetime read out of the credential is a measurement; one an operator typed is a claim; one
              inferred from captured traffic is a lower bound. They are labelled differently here because acting
              on them is different. A lifetime nobody measured says UNKNOWN, which is not the same as a long one.
            </p>

            {error && <Alert variant="danger" className="py-2 small">{error}</Alert>}

            <div className="d-flex flex-wrap align-items-center gap-3 mb-3">
              <div>
                <div className="text-white-50 text-uppercase" style={{ fontSize: '0.68rem', letterSpacing: '0.05em' }}>
                  Session TTL
                </div>
                <Duration value={tile.value} known={tile.known} testid="tile-ttl" />
                {/* SAID IN WORDS AS WELL AS IN THE "<=". The state is the server's own, so this
                    is a rendering of a measurement and not a second opinion about one. */}
                {tile.state === 'measured_partial' && (
                  <div style={{ fontSize: '0.7rem', color: '#ffc107' }}>UPPER BOUND, NOT A LIFETIME</div>
                )}
                <div className="text-white-50" style={{ fontSize: '0.75rem' }}>{tile.detail}</div>
              </div>
              <div className="flex-grow-1 small text-white-50" style={{ minWidth: '18rem' }}>
                {tile.explain}
                {report && report.governing && (
                  <div className="mt-1">{report.governing.why_this_one}</div>
                )}
              </div>
              {/* THE RUN THE SURVIVAL VERDICTS ANSWER ABOUT. The measured option is the configured
                  Investigate run as the server estimates it, which is the SAME number the renewal
                  gate uses, so the two screens cannot give contradictory verdicts for the same
                  credential. The what-if is the operator's own and says so. */}
              <div style={{ minWidth: '17rem' }}>
                <div className="text-white-50 text-uppercase" style={{ fontSize: '0.68rem', letterSpacing: '0.05em' }}>
                  Survival is asked about
                </div>
                <Form.Check
                  type="radio"
                  id="session-investigate-run-measured"
                  name="session-investigate-run"
                  className="text-white-50 small"
                  label={measuredRun.known
                    ? `the configured Investigate run (${measuredRun.minutes} minutes)`
                    : 'the configured Investigate run (UNKNOWN)'}
                  disabled={!measuredRun.known}
                  checked={!useOwnFigure && measuredRun.known}
                  onChange={() => { setUseOwnFigure(false); load(measuredRun.minutes, false); }}
                />
                <Form.Check
                  type="radio"
                  id="session-investigate-run-own"
                  name="session-investigate-run"
                  className="text-white-50 small"
                  label="a run length I supply"
                  checked={useOwnFigure || !measuredRun.known}
                  onChange={() => setUseOwnFigure(true)}
                />
                {(useOwnFigure || !measuredRun.known) && (
                  <div className="d-flex align-items-center gap-2 mt-1">
                    <Form.Control
                      id="session-investigate-run-minutes"
                      type="number"
                      min={1}
                      size="sm"
                      style={{ width: '5.5rem' }}
                      value={ownMinutes}
                      placeholder="minutes"
                      aria-label="Run length I supply, in minutes"
                      onChange={(e) => setOwnMinutes(e.target.value)}
                      onBlur={askAgain}
                    />
                    <span className="small text-white-50">minutes, your figure</span>
                  </div>
                )}
                <div
                  data-testid="run-length-basis"
                  data-run-source={question.source}
                  className="text-white-50"
                  style={{ fontSize: '0.72rem' }}
                >
                  {question.label}
                </div>
                {!measuredRun.known && runLengthError && (
                  <div style={{ fontSize: '0.72rem', color: '#ffc107' }}>
                    The configured run length is UNKNOWN here: {runLengthError}. It is not guessed, so
                    the only run this screen can ask about is one you supply.
                  </div>
                )}
              </div>
              <div className="d-flex gap-2">
                <Button variant="outline-danger" size="sm" disabled={loading} onClick={askAgain}>
                  Refresh view
                </Button>
                <Button variant="danger" size="sm" disabled={loading}
                        onClick={() => load(question.known ? question.minutes : 0, true)}>
                  Re-measure
                </Button>
              </div>
            </div>

            {report && <WirePanel wire={wire} />}

            {report && report.counts && (
              <div className="small text-white-50 mb-3">
                {report.counts.total} credential(s) stored, {report.counts.active} switched on,{' '}
                {report.counts.sendable} would be sent. {report.counts.ttl_measured} of those have a measured
                lifetime and {report.counts.ttl_unknown} do not.{' '}
                {report.reprofiled ? 'Re-measured just now.' : 'Read from the last measurement.'}
              </div>
            )}

            {report && Array.isArray(report.notes) && report.notes.map((note, i) => (
              <Alert key={i} variant="dark" className="py-2 small border border-secondary">{note}</Alert>
            ))}

            {loading && (
              <div className="text-center py-4">
                <Spinner animation="border" variant="danger" size="sm" />
                <span className="ms-2 small text-white-50">Characterising credentials...</span>
              </div>
            )}

            {report && (report.credentials || []).map((c) => (
              <CredentialPanel key={c.token_id} credential={c}
                               runLabel={question.label} runSource={question.source}
                               wireKnown={wire.known} />
            ))}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={handleClose}>Close</Button>
      </Modal.Footer>
    </Modal>
  );
};

export default SessionInvestigateModal;
