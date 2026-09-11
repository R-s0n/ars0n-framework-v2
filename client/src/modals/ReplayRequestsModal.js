import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Modal } from 'react-bootstrap';
import SingleRequestPane from '../components/SingleRequestPane';

// Replay Requests: the repeater, on its own.
//
// It used to be a tab inside Request Flow Replay. It is now one of the four buttons on the Request
// Flow Replay row and owns a modal of its own, so this file is chrome and one handover, nothing
// else. Every behaviour of the repeater lives in SingleRequestPane and is unchanged by the split:
// the sitemap and its query language, the byte-exact request editor, the raw response, the versions
// column, the line-ending view that is display only, and raw mode.
//
// The handover is the only thing here worth reading.
//
// THERE ARE TWO WAYS IN, AND ONE SLOT.
//
//   initialCaptureId   a request that IS in the crawl corpus, by id. The Request Flows modal sends
//                      one over when the operator picks a node.
//   initialRawRequest  raw bytes that are NOT in the corpus and never will be, so no id can stand
//                      for them. A tool finding is the case: the scanner composed or captured a
//                      request the crawl never saw, and the only thing that can travel is the bytes.
//                      Either a string, or { raw_request, base_url, label }.
//
// They share ONE pending slot rather than getting one each. Two slots would mean two load effects in
// the pane armed at the same time, and which of them won would depend on the order two useEffects
// happen to be declared in -- which is exactly the kind of thing that gets reordered by an edit that
// looks harmless. One slot makes "the last handover wins" true by construction. If both props ever
// arrive together the raw bytes win, because a capture id can be found again from the sitemap and
// bytes that are not in the corpus cannot.
//
// The pane treats a handover it has already loaded as "already loaded" and does nothing, which is
// right for a re-render and wrong for a second handover of the same request after the operator has
// clicked elsewhere in the pane's own sitemap. The prop would be unchanged, so nothing would happen
// and the button would look broken. Passing null for one commit and the value back on the next is
// the re-arm the pane documents, and handOver does it whenever the incoming handover is the one
// already pending.
//
// Closing unmounts the pane, because react-bootstrap does not render a Modal's children while it is
// hidden. That is deliberate here rather than tolerated: a repeater left mounted with a previous
// target's request in it is a request aimed at the wrong host the moment somebody hits Replay. It
// would also mean an edit typed in the last few seconds before the close is the one edit that never
// reaches the version store, so the pane saves on unmount as well as on idle. There is no "are you
// sure" on the way out: the edit is kept rather than queried, and the version is there on reopen.

// Two handovers are the same handover when they would put the same thing in the editor. Compared by
// value and not by identity, because the parent rebuilds the payload on every render and an identity
// comparison would call every re-render a new handover.
const sameHandover = (a, b) => {
  if (!a || !b) return false;
  if (a.kind !== b.kind) return false;
  if (a.kind === 'capture') return a.captureId === b.captureId;
  return a.raw_request === b.raw_request && a.base_url === b.base_url && a.label === b.label;
};

export const ReplayRequestsModal = ({
  show, handleClose, activeTarget, initialCaptureId, initialRawRequest,
}) => {
  const targetId = activeTarget && activeTarget.id;

  // A bare string is accepted as well as the object, because "hand me these bytes" is the whole of
  // what most callers mean and making them build a wrapper to say it would be ceremony.
  const rawText = typeof initialRawRequest === 'string'
    ? initialRawRequest
    : (initialRawRequest && typeof initialRawRequest.raw_request === 'string'
      ? initialRawRequest.raw_request : '');
  const rawBase = initialRawRequest && typeof initialRawRequest === 'object'
    ? String(initialRawRequest.base_url || '') : '';
  const rawLabel = initialRawRequest && typeof initialRawRequest === 'object'
    ? String(initialRawRequest.label || '') : '';

  // Whitespace is not a request. An empty string arriving here is "nothing was handed over", not
  // "load an empty editor", so it must not displace a capture id that was.
  // Field names are the ones the results API uses, all the way down to the pane, so nobody has to
  // remember which layer renamed what.
  // MEMOISED ON THE VALUES, NOT ON THE PROP'S IDENTITY, and that is deliberate even though it costs
  // the re-arm below.
  //
  // Keying on initialRawRequest instead was tried and REVERTED, because it breaks a safety property
  // that matters more: a commit which changes the scope target AND carries a handover must DROP the
  // handover, or one engagement's recorded request gets sent from another engagement's target. The
  // target-change effect clears pending first; with identity keying the handover effect then re-ran
  // and put the bytes straight back. There is a regression test for exactly this
  // ("switching target drops the handover rather than aiming it at the new host") and it failed.
  //
  // The cost is that sameHandover/rearmRef never fire for raw handovers: App creates a fresh object
  // per press, this collapses it, the effect's deps do not change, and handOver is not called again.
  // That machinery is therefore DEAD for raw handovers today. It is also unreachable: the repeater
  // is fullscreen, so closing it unmounts the pane and clears pending, and every handover is a first
  // one. If the results modal and the repeater are ever open together, the fix is a handover nonce
  // from App - a counter bumped per press and included in the deps - which re-arms without
  // resurrecting the cross-target leak, NOT identity keying.
  const incomingRaw = useMemo(() => (rawText.trim() === '' ? null : {
    kind: 'raw', raw_request: rawText, base_url: rawBase, label: rawLabel,
  }), [rawText, rawBase, rawLabel]);

  const incomingCapture = useMemo(() => {
    if (initialCaptureId === null || initialCaptureId === undefined || initialCaptureId === '') {
      return null;
    }
    return { kind: 'capture', captureId: String(initialCaptureId) };
  }, [initialCaptureId]);

  // What the pane is being asked to load. Null means "nothing handed over": the operator opens the
  // modal and picks from the sitemap themselves.
  const [pending, setPending] = useState(null);
  const rearmRef = useRef(null);
  const lastTargetRef = useRef(targetId);

  // Declared FIRST, and it does nothing on mount. Effects run in declaration order, so a commit
  // that changes the target and the handover together clears the old handover here and then takes
  // the new one below; the other order would drop the new one. Without the ref guard this fires on
  // mount and wipes the handover the modal was opened with, which is a Replay Requests button that
  // opens an empty editor.
  useEffect(() => {
    if (lastTargetRef.current === targetId) return;
    lastTargetRef.current = targetId;
    // A request read while another target was active belongs to that target. Loading it into an
    // editor pointed at this one is how another scope's request gets sent to this scope's host.
    // True of a finding's bytes as much as of a capture id: the finding names a host.
    setPending(null);
    rearmRef.current = null;
  }, [targetId]);

  const handOver = useCallback((next) => {
    if (!next) return;
    setPending((prev) => {
      if (sameHandover(prev, next)) {
        rearmRef.current = next;
        return null;
      }
      return next;
    });
  }, []);

  useEffect(() => {
    if (pending !== null || !rearmRef.current) return;
    const next = rearmRef.current;
    rearmRef.current = null;
    setPending(next);
  }, [pending]);

  // On open, and on every later change of the handover while open. Closing clears it so that
  // reopening with the same request is a fresh handover rather than a prop that happens not to have
  // changed.
  useEffect(() => {
    if (!show) {
      setPending(null);
      rearmRef.current = null;
      return;
    }
    handOver(incomingRaw || incomingCapture);
  }, [show, incomingRaw, incomingCapture, handOver]);

  return (
    <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-arrow-repeat me-2" />
          Replay Requests
          {activeTarget && activeTarget.scope_target && (
            <span className="text-white-50 ms-2" style={{ fontSize: '0.9rem' }}>
              {activeTarget.scope_target}
            </span>
          )}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body className="d-flex flex-column p-0" style={{ minHeight: 0, overflow: 'hidden' }}>
        {!targetId ? (
          <div className="text-white-50 p-4">
            No target selected. Pick a scope target first: the repeater sends to the hosts that
            target's crawl recorded, so without one there is nothing to send and nowhere to send it.
          </div>
        ) : (
          <SingleRequestPane
            activeTarget={activeTarget}
            loadCaptureId={pending && pending.kind === 'capture' ? pending.captureId : null}
            // The object in state, not a fresh one per render: the pane arms this effect on the
            // object's identity, and a new object every render would reload the editor forever.
            loadRawRequest={pending && pending.kind === 'raw' ? pending : null}
          />
        )}
      </Modal.Body>
    </Modal>
  );
};

export default ReplayRequestsModal;
