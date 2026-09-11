import { useMemo, useState } from 'react';
import { Button, Form, Spinner } from 'react-bootstrap';

// The flows that DEMONSTRATE one threat, rendered inside that threat's accordion body.
//
// WHY IT LIVES ON THE THREAT. The question this answers is "what sequence shows this is real?", and
// that question is asked while reading the threat, not while browsing a flow list. It is in the
// expanded body rather than the collapsed header because the header already carries severity, auth
// and test status, and a fourth thing there would push the mechanism off the line.
//
// A DETECTED FLOW AND A BUILT FLOW ARE NOT THE SAME EVIDENCE and are never drawn the same:
//
//   detected - a record of traffic that actually happened. Its id is the composite
//              "<session>~<tab>~<root capture>" provenance string, NOT a UUID.
//   built    - ordered steps in the Request Flow Builder. Editable, and its steps may never have
//              been sent. Rendering it identically to a recording would overstate what it proves.
//
// NEVER VALIDATE A FLOW ID AS A UUID. Forty-six of the forty-nine flows on a real target are
// detected, and a UUID check rejects every one of them - the exact flows most worth attaching to a
// threat, because they are the traffic that shows the threat is reachable.

// The two titles the SERVER fills in when nobody has named a flow. Same strings as
// server/utils/detectedFlowNames.go (DefaultDetectedFlowName) and server/utils/flowThreatLinks.go
// (BuiltFlowSummaries). They are titles, but they are not names anybody chose.
export const DEFAULT_DETECTED_FLOW_NAME = '(Automated Flow Detected)';
export const DEFAULT_BUILT_FLOW_NAME = '(Untitled Built Flow)';

export const isPlaceholderFlowName = (name) => {
  const text = String(name == null ? '' : name).trim();
  return text === DEFAULT_DETECTED_FLOW_NAME || text === DEFAULT_BUILT_FLOW_NAME;
};

// `kind` from the server when it sends one; the id SHAPE otherwise. Two "~" separators is a detected
// flow's composite id, anything else is a built flow's UUID - the same rule the server derives with
// in SetFlowThreatLink, so a client fallback cannot disagree with what got stored.
export const flowKindOf = (flow) => {
  if (!flow) return '';
  const kind = String(flow.kind || flow.flow_kind || '').trim().toLowerCase();
  if (kind === 'built' || kind === 'detected') return kind;
  return String(flow.id || flow.flow_id || '').split('~').length === 3 ? 'detected' : 'built';
};

const KIND_BADGE = {
  detected: {
    label: 'detected',
    bg: '#14532d',
    fg: '#bbf7d0',
    title: 'A detected flow: a record of traffic that actually happened, captured from the browser '
      + 'or from a detection run. What it shows was really sent.',
  },
  built: {
    label: 'built',
    bg: '#1e3a5f',
    fg: '#bfdbfe',
    title: 'A built flow: ordered steps in the Request Flow Builder. It is editable and its steps '
      + 'may never have been sent, so it demonstrates an intended sequence rather than a recorded one.',
  },
};

// How many requests or steps a row is worth, using the same fallback the flow list uses:
// step_count is omitempty and absent on a flow with no steps, and BuiltFlowSummaries sets
// request_count to the same number, so the two never disagree. Only when BOTH are missing is the
// count unknown, and then nothing is printed rather than a zero that would read as "empty flow".
const flowSize = (flow) => {
  const n = Number.isFinite(Number(flow && flow.step_count))
    ? Number(flow.step_count)
    : Number(flow && flow.request_count);
  return Number.isFinite(n) && n >= 0 ? n : null;
};

const shortTime = (value) => {
  const t = Date.parse(value);
  if (!Number.isFinite(t)) return '';
  const d = new Date(t);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

// What to call a flow on screen.
//
// THE NAME LEADS ONLY WHEN SOMEBODY CHOSE IT. When the name is one of the server's placeholders it
// is demoted and the request line leads instead, because forty-six rows all beginning "(Automated
// Flow Detected)" cannot be told apart, and a picker whose options are indistinguishable is a picker
// that cannot be used. The placeholder is still shown - muted - so the row does not pretend the
// request line is a name.
export const describeFlow = (flow, link) => {
  const kind = flowKindOf(flow || link);
  const id = String((flow && flow.id) || (link && link.flow_id) || '');
  // link.flow_name is the server's own resolution and backs up a flow missing from the list.
  // GetFlowThreatLinks now fills it for BOTH kinds - it reads request_flows.name as well as
  // detected_flow_names and falls back to that kind's placeholder - but the fallback to the flow
  // list STAYS: measured against the running API on 2026-09-09, a link to a built flow still came
  // back with no flow_name at all, because that handler change is newer than the deployed binary. A
  // client that assumed the name was always there would render those links nameless. Everything
  // else about a flow needs the list regardless: the request line, host, size and start time live
  // nowhere else.
  const rawName = String((flow && flow.name) || (link && link.flow_name) || '').trim();
  const label = String((flow && flow.label) || '').trim();
  const placeholder = isPlaceholderFlowName(rawName);
  const named = Boolean(rawName) && !placeholder;

  let title = '';
  let detail = '';
  if (named) {
    title = rawName;
    detail = label;
  } else if (label) {
    title = label;
    detail = rawName;
  } else if (rawName) {
    title = rawName;
  }

  // NOTHING FALLS BACK TO THE RAW ID SILENTLY. A composite provenance string is not a name the
  // operator has ever seen, so when it is all there is, the row says so.
  //
  // A SERVER PLACEHOLDER IS NOT A RESOLUTION EITHER, and this got MORE important, not less, now that
  // flow_name is always sent: an unnamed link of either kind comes back carrying "(Automated Flow
  // Detected)" or "(Untitled Built Flow)" whether or not that flow is still in the list, so keying
  // this off "we have some title" declared 46 possible rows known when none of them were. A link
  // whose flow has been deleted, or which sits past the limit the list was fetched with, then
  // rendered as a bare placeholder with no host, no request line and no warning - a mapping the
  // operator can neither identify nor find out is unavailable. Known means the flow list resolved
  // it, or somebody actually named it.
  const known = Boolean(flow) || named;
  if (!title) title = id;

  const size = flow ? flowSize(flow) : null;
  const meta = [
    flow && flow.host ? String(flow.host) : '',
    size === null ? '' : `${size} ${kind === 'built' ? 'step' : 'request'}${size === 1 ? '' : 's'}`,
    flow ? shortTime(flow.started_at) : '',
  ].filter(Boolean).join('  ·  ');

  return { id, kind, title, detail, placeholder, named, known, meta };
};

// One line in the picker. Same ordering rule as the row: whatever actually distinguishes this flow
// comes first, then the counts and time that separate the several flows sharing a request line.
export const flowOptionLabel = (flow) => {
  const d = describeFlow(flow, null);
  const parts = [d.title];
  if (d.detail) parts.push(d.detail);
  if (d.meta) parts.push(d.meta);
  return parts.join('  -  ');
};

// Does this flow match what the operator typed into the picker's filter?
//
// A SUBSTRING, CASE-INSENSITIVE, OVER THE THREE FIELDS A FLOW IS RECOGNISED BY: the name somebody
// gave it, the request line that roots it, and the host. Deliberately NOT the Request Flows modal's
// query grammar - that grammar matches CAPTURES ("status >= 400"), a built flow has no captures to
// match, and needing to learn a language to find one row out of two hundred is the problem, not the
// solution.
export const flowMatchesFilter = (flow, needle) => {
  const q = String(needle == null ? '' : needle).trim().toLowerCase();
  if (!q) return true;
  if (!flow) return false;
  return [flow.name, flow.label, flow.host]
    .some((v) => String(v == null ? '' : v).toLowerCase().includes(q));
};

// What a "map this flow" write should actually do, given what the SERVER currently holds.
//
// THE CREATE ENDPOINT IS AN UPSERT THAT OVERWRITES THE NOTE - `DO UPDATE SET note = EXCLUDED.note` -
// so mapping a flow that is already mapped silently destroys the sentence explaining why it was
// mapped. Measured against the live API, one note-less POST turned a stored note into nothing.
//
// `links` MUST BE A FRESH SERVER READ, not the rendered list. The picker only offers flows that are
// not already linked, so a create can only ever land on an existing row when the rendered list did
// not know about it - a second tab, or a read that predates the other write. Resolving the note from
// the rendered list therefore resolves it to '' in exactly the case that matters, which is the wipe
// it was supposed to prevent.
//
// Returns 'skip' when the mapping already exists (the operator asked for it to be mapped, it is, and
// re-sending could only change the note), 'unknown' when the read failed, and 'create' otherwise.
export const linkWriteAction = (links, threatId, flowId) => {
  if (!Array.isArray(links)) return 'unknown';
  return links.some((l) => l
    && String(l.threat_id) === String(threatId)
    && String(l.flow_id) === String(flowId)) ? 'skip' : 'create';
};

const KindBadge = ({ kind }) => {
  const style = KIND_BADGE[kind] || KIND_BADGE.detected;
  return (
    <span
      title={style.title}
      style={{
        backgroundColor: style.bg,
        color: style.fg,
        fontSize: '0.62rem',
        fontWeight: 700,
        letterSpacing: '0.06em',
        padding: '0.1rem 0.4rem',
        borderRadius: '0.25rem',
        textTransform: 'uppercase',
        flexShrink: 0,
      }}
    >
      {style.label}
    </span>
  );
};

// onLink(threatId, flowId) -> truthy on success, onUnlink(threatId, flowId), and
// onSetNote(threatId, flowId, note) -> truthy on success. onSetNote is optional and the note
// controls are hidden without it, so a caller that has no writer never offers a control that cannot
// work. The note write goes through the SAME create endpoint as onLink, which upserts, so the caller
// owns the rule that adding a link must not blank a note that is already there.
const ThreatFlowLinks = ({
  threat,
  links = [],
  flowsById = {},
  flows = [],
  flowsTotal = 0,
  flowsLoading = false,
  flowsError = '',
  linksError = '',
  actionError = '',
  busy = false,
  onLink,
  onUnlink,
  onSetNote,
}) => {
  const [pick, setPick] = useState('');
  const [filter, setFilter] = useState('');
  // Which link's note is open for editing, keyed by flow id, and the text as typed. One at a time:
  // this sits inside an accordion body that already carries severity, scenarios and test status, and
  // several open editors would bury the threat itself.
  const [noteFor, setNoteFor] = useState('');
  const [noteDraft, setNoteDraft] = useState('');
  const threatId = threat && threat.id;
  const needle = filter.trim();

  const linkedIds = useMemo(() => new Set(links.map((l) => String(l.flow_id))), [links]);

  // Everything not already mapped, before the filter. Kept separate from the filtered set because
  // "nothing left to map" and "nothing matches what you typed" are different sentences and the
  // picker has to be able to say which one is true.
  const freeFlows = useMemo(
    () => flows.filter((f) => f && f.id && !linkedIds.has(String(f.id))),
    [flows, linkedIds]
  );

  const matching = useMemo(
    () => freeFlows.filter((f) => flowMatchesFilter(f, needle)),
    [freeFlows, needle]
  );

  // Built flows first, then detected, matching the order the flows endpoint itself returns them in
  // and the order the Request Flows modal lists them: an editable artefact you assembled on purpose
  // is the likelier answer to "what demonstrates this" than the hundredth recorded navigation.
  const options = useMemo(() => ({
    built: matching.filter((f) => flowKindOf(f) === 'built'),
    detected: matching.filter((f) => flowKindOf(f) !== 'built'),
  }), [matching]);

  const optionCount = matching.length;

  // A CHOICE IS ONLY VALID WHILE IT IS STILL ON SCREEN. Narrowing the filter after picking would
  // otherwise leave the previous selection attached to the button while the list no longer shows it,
  // and mapping a flow the operator can no longer see is a mapping nobody asked for. An id that no
  // longer matches counts as no choice at all.
  const pickable = pick && matching.some((f) => String(f.id) === pick) ? pick : '';

  const add = async () => {
    if (!pickable || !onLink) return;
    const ok = await onLink(threatId, pickable);
    // Cleared only on success, so a failed add leaves the choice in place to retry rather than
    // making the operator find the flow again.
    if (ok) setPick('');
  };

  const openNote = (link) => {
    setNoteFor(String(link.flow_id));
    setNoteDraft(String(link.note || ''));
  };

  const saveNote = async (link) => {
    if (!onSetNote) return;
    const ok = await onSetNote(threatId, link.flow_id, noteDraft.trim());
    // Closed only on success. A failed save keeps the typed text on screen instead of throwing away
    // the sentence the operator just wrote.
    if (ok) setNoteFor('');
  };

  return (
    <div className="mt-3 pt-3 border-top border-secondary">
      <div className="d-flex align-items-center flex-wrap mb-2" style={{ gap: '0.5rem' }}>
        <span className="text-white-50" style={{ fontSize: '0.72rem', letterSpacing: '0.04em' }}>
          DEMONSTRATED BY
        </span>
        {links.length > 0 && (
          <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
            {links.length} flow{links.length === 1 ? '' : 's'} mapped
          </span>
        )}
      </div>

      {/* A failed READ must not render as "nothing is mapped". That sentence would be a claim about
          the server that the client is in no position to make. */}
      {linksError ? (
        <div className="text-warning" style={{ fontSize: '0.78rem' }}>
          The flow mappings could not be read, so this threat's links are unknown: {linksError}
        </div>
      ) : links.length === 0 ? (
        <div className="text-white-50 fst-italic" style={{ fontSize: '0.78rem' }}>
          No flow is mapped to this threat yet.
        </div>
      ) : (
        <div className="mb-2">
          {links.map((link) => {
            const flow = flowsById[String(link.flow_id)];
            const d = describeFlow(flow, link);
            return (
              <div
                key={link.id || `${link.threat_id}:${link.flow_id}`}
                className="d-flex align-items-start justify-content-between mb-2 px-2 py-2"
                style={{
                  gap: '0.5rem',
                  backgroundColor: '#212529',
                  border: '1px solid #343a40',
                  borderRadius: '0.25rem',
                }}
              >
                <div className="flex-grow-1" style={{ minWidth: 0 }}>
                  <div className="d-flex align-items-center" style={{ gap: '0.4rem' }}>
                    <KindBadge kind={d.kind} />
                    <span
                      className={`text-truncate ${d.named ? 'text-white fw-semibold' : 'text-white-50 fst-italic'}`}
                      style={{ fontSize: '0.82rem' }}
                      title={d.id}
                    >
                      {d.title}
                    </span>
                  </div>
                  {d.detail && (
                    <div className="text-white-50 text-truncate" style={{ fontSize: '0.72rem' }}>
                      {d.detail}
                    </div>
                  )}
                  {d.meta && (
                    <div className="text-white-50 text-truncate" style={{ fontSize: '0.7rem' }}>
                      {d.meta}
                    </div>
                  )}
                  {/* A link to a flow the list does not contain is stated rather than hidden: the
                      flow may have been deleted, or it may be past the limit the list was fetched
                      with. Either way the mapping is real and the operator should know it points at
                      something this screen cannot show. */}
                  {!d.known && (
                    <div className="text-warning" style={{ fontSize: '0.7rem' }}>
                      This flow is not in the current flow list, so it cannot be identified here.
                      It may have been deleted, or it may sit past the limit the list was fetched with.
                    </div>
                  )}
                  {/* THE NOTE IS WHY THIS FLOW PROVES THIS THREAT, in the operator's own words. It
                      is the part of the mapping that still means something a month later, when
                      "these three requests" has stopped being self-explanatory. Editing is in place:
                      removing and re-adding the link to change a sentence would be a worse trade
                      than the one line of state this costs. */}
                  {noteFor === String(link.flow_id) ? (
                    <div className="mt-1">
                      <Form.Control
                        as="textarea"
                        rows={2}
                        size="sm"
                        data-bs-theme="dark"
                        value={noteDraft}
                        onChange={(e) => setNoteDraft(e.target.value)}
                        placeholder="Why this flow demonstrates this threat"
                        aria-label="Why this flow demonstrates this threat"
                        style={{ fontSize: '0.74rem' }}
                      />
                      <div className="d-flex align-items-center mt-1" style={{ gap: '0.6rem' }}>
                        <Button
                          variant="outline-light"
                          size="sm"
                          style={{ fontSize: '0.7rem' }}
                          disabled={busy}
                          onClick={() => saveNote(link)}
                        >
                          {busy ? <Spinner animation="border" size="sm" /> : 'Save note'}
                        </Button>
                        <Button
                          variant="link"
                          size="sm"
                          className="p-0 text-white-50 text-decoration-none"
                          style={{ fontSize: '0.7rem' }}
                          disabled={busy}
                          onClick={() => setNoteFor('')}
                        >
                          Cancel
                        </Button>
                        {link.note && (
                          <span className="text-white-50" style={{ fontSize: '0.68rem' }}>
                            Saving it empty clears the note.
                          </span>
                        )}
                      </div>
                    </div>
                  ) : (
                    <>
                      {link.note && (
                        <div
                          className="text-white-50"
                          style={{ fontSize: '0.72rem', whiteSpace: 'pre-wrap' }}
                        >
                          {link.note}
                        </div>
                      )}
                      {onSetNote && (
                        <Button
                          variant="link"
                          size="sm"
                          className="p-0 text-decoration-none"
                          style={{ fontSize: '0.7rem', color: '#8ab4f8' }}
                          disabled={busy}
                          onClick={() => openNote(link)}
                          title="Record why this flow demonstrates this threat. The note is stored on the mapping, not on the flow."
                        >
                          {link.note ? 'Edit note' : 'Add note'}
                        </Button>
                      )}
                    </>
                  )}
                </div>
                <Button
                  variant="outline-danger"
                  size="sm"
                  className="flex-shrink-0"
                  style={{ fontSize: '0.72rem' }}
                  disabled={busy}
                  onClick={() => onUnlink && onUnlink(threatId, link.flow_id)}
                  title="Remove this mapping. The flow itself is not deleted."
                >
                  Remove
                </Button>
              </div>
            );
          })}
        </div>
      )}

      {actionError && (
        <div className="text-danger mb-2" style={{ fontSize: '0.76rem' }}>
          {actionError}
        </div>
      )}

      {flowsError ? (
        <div className="text-warning" style={{ fontSize: '0.76rem' }}>
          The flow list could not be read, so nothing can be mapped right now: {flowsError}
        </div>
      ) : (
        <div className="d-flex align-items-center flex-wrap" style={{ gap: '0.5rem' }}>
          {/* A LIST OF 200 IN A DROPDOWN IS NOT A LIST YOU CAN USE. Narrows by name, request line and
              host, client-side over what was already fetched - it does not re-query, so it can only
              ever hide rows the picker already had. */}
          {(freeFlows.length > 1 || needle) && (
            <Form.Control
              size="sm"
              type="search"
              data-bs-theme="dark"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by name, request or host"
              aria-label="Filter the flows offered for mapping"
              disabled={busy || flowsLoading}
              style={{ fontSize: '0.78rem', maxWidth: '16rem' }}
            />
          )}
          <Form.Select
            size="sm"
            data-bs-theme="dark"
            aria-label="Map a request flow onto this threat"
            value={pickable}
            disabled={busy || flowsLoading || optionCount === 0}
            onChange={(e) => setPick(e.target.value)}
            style={{ fontSize: '0.78rem', maxWidth: '32rem' }}
          >
            <option value="">
              {flowsLoading
                ? 'Loading flows...'
                : freeFlows.length === 0
                  ? (flows.length === 0 ? 'No flows on this target' : 'Every flow is already mapped')
                  : optionCount === 0
                    ? `No flow matches "${needle}"`
                    : 'Map a flow to this threat...'}
            </option>
            {options.built.length > 0 && (
              <optgroup label={`Built flows (${options.built.length}) - editable steps, may never have been sent`}>
                {options.built.map((f) => (
                  <option key={f.id} value={f.id}>{flowOptionLabel(f)}</option>
                ))}
              </optgroup>
            )}
            {options.detected.length > 0 && (
              <optgroup label={`Detected flows (${options.detected.length}) - recorded traffic`}>
                {options.detected.map((f) => (
                  <option key={f.id} value={f.id}>{flowOptionLabel(f)}</option>
                ))}
              </optgroup>
            )}
          </Form.Select>
          <Button
            variant="outline-danger"
            size="sm"
            style={{ fontSize: '0.78rem' }}
            disabled={busy || !pickable}
            onClick={add}
          >
            {busy ? <Spinner animation="border" size="sm" /> : 'Map flow'}
          </Button>
          {/* What the filter itself removed, said separately from what the fetch never brought back,
              because they are two different reasons for the same missing row. */}
          {needle && freeFlows.length > 0 && (
            <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
              {optionCount} of {freeFlows.length} unmapped flow{freeFlows.length === 1 ? '' : 's'} match.
            </span>
          )}
          {/* The picker holds what was FETCHED. If the target has more flows than that, saying so is
              the difference between "the flow I want is not here" and "the flow I want was never
              offered" - and once a filter box exists, the difference between "my filter excluded it"
              and "it was never in the list to exclude". Stated whether or not a filter is typed, and
              stated MUTED rather than as a warning: it is a standing property of a big target, not
              an event, and a yellow line that is always there stops being read. */}
          {flowsTotal > flows.length && (
            <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
              Showing {flows.length} of {flowsTotal} flows on this target: the rest were never
              fetched, so a flow you cannot find here may be past that cap rather than filtered out.
            </span>
          )}
        </div>
      )}
    </div>
  );
};

export default ThreatFlowLinks;
