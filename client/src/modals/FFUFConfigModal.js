import { Modal, Button } from 'react-bootstrap';
import { FuzzComposer } from './FuzzComposer';

// FFUF configuration is now a composer rather than a form.
//
// The old modal configured one scan with three fixed phases (endpoints, headers, cookies) and a
// single wordlist each. That could only ever fuzz the three things it had been written to fuzz, and
// two of its three buttons were stubs. A payload position is really just "somewhere in the request",
// so the composer edits the raw HTTP text and lets a marker go anywhere: inside a path segment,
// inside one field of a JSON body, inside a cookie, in a header name.
//
// The flow on the right is the series of rounds. They run in order, each independent: ffuf cannot
// pass anything from one round to the next, so ordering controls traffic rather than data.

export const FFUFConfigModal = ({ show, handleClose, activeTarget }) => (
  <Modal show={show} onHide={handleClose} fullscreen data-bs-theme="dark">
    <Modal.Header closeButton>
      <Modal.Title className="text-danger">
        <i className="bi bi-gear me-2" />
        FFUF Scan Flow
      </Modal.Title>
    </Modal.Header>

    <Modal.Body className="d-flex flex-column" style={{ overflow: 'hidden' }}>
      {!activeTarget ? (
        <div className="text-white-50">Select a target first.</div>
      ) : (
        <FuzzComposer tool="ffuf" targetId={activeTarget.id} />
      )}
    </Modal.Body>

    <Modal.Footer>
      <Button variant="secondary" onClick={handleClose}>Close</Button>
    </Modal.Footer>
  </Modal>
);

export default FFUFConfigModal;
