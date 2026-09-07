import { useCallback, useEffect, useRef, useState } from 'react';
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
// initialCaptureId is how another modal, the Request Flows one, sends a request over: it opens this
// modal with a capture id and expects that request in the editor. The pane treats a loadCaptureId it
// has already fetched as "already loaded" and does nothing, which is right for a re-render and wrong
// for a second handover of the same request after the operator has clicked elsewhere in the pane's
// own sitemap. The prop would be unchanged, so nothing would happen and the button would look
// broken. Passing null for one commit and the id back on the next is the re-arm the pane documents,
// and handOver does it whenever the incoming id is the one already pending.
//
// Closing unmounts the pane, because react-bootstrap does not render a Modal's children while it is
// hidden. That is deliberate here rather than tolerated: a repeater left mounted with a previous
// target's request in it is a request aimed at the wrong host the moment somebody hits Replay. It
// would also mean an edit typed in the last few seconds before the close is the one edit that never
// reaches the version store, so the pane saves on unmount as well as on idle. There is no "are you
// sure" on the way out: the edit is kept rather than queried, and the version is there on reopen.

export const ReplayRequestsModal = ({ show, handleClose, activeTarget, initialCaptureId }) => {
  const targetId = activeTarget && activeTarget.id;

  // What the pane is being asked to load. Null means "nothing handed over": the operator opens the
  // modal and picks from the sitemap themselves.
  const [pendingCaptureId, setPendingCaptureId] = useState(null);
  const rearmRef = useRef(null);
  const lastTargetRef = useRef(targetId);

  // Declared FIRST, and it does nothing on mount. Effects run in declaration order, so a commit
  // that changes the target and the capture together clears the old handover here and then takes
  // the new one below; the other order would drop the new one. Without the ref guard this fires on
  // mount and wipes the handover the modal was opened with, which is a Replay Requests button that
  // opens an empty editor.
  useEffect(() => {
    if (lastTargetRef.current === targetId) return;
    lastTargetRef.current = targetId;
    // A capture read while another target was active belongs to that target. Loading it into an
    // editor pointed at this one is how another scope's request gets sent to this scope's host.
    setPendingCaptureId(null);
    rearmRef.current = null;
  }, [targetId]);

  const handOver = useCallback((value) => {
    const id = value === null || value === undefined || value === '' ? null : String(value);
    if (id === null) return;
    setPendingCaptureId((prev) => {
      if (prev === id) {
        rearmRef.current = id;
        return null;
      }
      return id;
    });
  }, []);

  useEffect(() => {
    if (pendingCaptureId !== null || !rearmRef.current) return;
    const id = rearmRef.current;
    rearmRef.current = null;
    setPendingCaptureId(id);
  }, [pendingCaptureId]);

  // On open, and on every later change of the id while open. Closing clears it so that reopening
  // with the same id is a fresh handover rather than a prop that happens not to have changed.
  useEffect(() => {
    if (!show) {
      setPendingCaptureId(null);
      rearmRef.current = null;
      return;
    }
    handOver(initialCaptureId);
  }, [show, initialCaptureId, handOver]);

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
            loadCaptureId={pendingCaptureId}
          />
        )}
      </Modal.Body>
    </Modal>
  );
};

export default ReplayRequestsModal;
