import { Modal, Button, Form, Spinner, ProgressBar, Badge } from 'react-bootstrap';
import { useState, useEffect } from 'react';

function WildfireModal({
  show,
  handleClose,
  scopeTargets,
  isWildfireRunning,
  wildfireProgress,
  onStartWildfire,
  onCancelWildfire
}) {
  const [selectedTargets, setSelectedTargets] = useState({});

  const wildcardTargets = (scopeTargets || []).filter(t => t.type === 'Wildcard');

  useEffect(() => {
    if (show && !isWildfireRunning) {
      const allSelected = {};
      wildcardTargets.forEach(t => {
        allSelected[t.id] = true;
      });
      setSelectedTargets(allSelected);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [show, scopeTargets]);

  const handleToggle = (id) => {
    if (isWildfireRunning) return;
    setSelectedTargets(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleSelectAll = () => {
    if (isWildfireRunning) return;
    const allSelected = {};
    wildcardTargets.forEach(t => { allSelected[t.id] = true; });
    setSelectedTargets(allSelected);
  };

  const handleDeselectAll = () => {
    if (isWildfireRunning) return;
    setSelectedTargets({});
  };

  const selectedCount = Object.values(selectedTargets).filter(Boolean).length;

  const handleStart = () => {
    const targets = wildcardTargets.filter(t => selectedTargets[t.id]);
    if (targets.length === 0) return;
    onStartWildfire(targets);
  };

  const currentTargetName = wildfireProgress?.currentTarget?.scope_target
    ? wildfireProgress.currentTarget.scope_target.replace('*.', '')
    : '';

  return (
    <Modal show={show} onHide={handleClose} centered data-bs-theme="dark" size="lg">
      <Modal.Header closeButton className="border-secondary">
        <Modal.Title className="text-danger d-flex align-items-center">
          <i className="bi bi-fire me-2"></i>
          Wildfire Scan
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark">
        {isWildfireRunning && wildfireProgress ? (
          <div>
            <div className="mb-3">
              <div className="d-flex justify-content-between align-items-center mb-2">
                <span className="text-white">
                  Scanning target {wildfireProgress.currentIndex + 1} of {wildfireProgress.totalTargets}
                </span>
                <Badge bg="danger">{currentTargetName}</Badge>
              </div>
              <ProgressBar
                now={((wildfireProgress.currentIndex) / wildfireProgress.totalTargets) * 100}
                variant="danger"
                animated
                className="mb-3"
              />
            </div>

            <div className="mb-3">
              {wildfireProgress.targets.map((t, idx) => {
                let statusIcon = 'bi-hourglass';
                let statusColor = 'text-secondary';
                if (idx < wildfireProgress.currentIndex) {
                  statusIcon = 'bi-check-circle-fill';
                  statusColor = 'text-success';
                } else if (idx === wildfireProgress.currentIndex) {
                  statusIcon = 'bi-arrow-right-circle-fill';
                  statusColor = 'text-danger';
                }
                return (
                  <div key={t.id} className={`d-flex align-items-center py-1 ${statusColor}`}>
                    <i className={`bi ${statusIcon} me-2`}></i>
                    <span>{t.scope_target.replace('*.', '')}</span>
                    {idx === wildfireProgress.currentIndex && (
                      <Spinner animation="border" size="sm" variant="danger" className="ms-2" />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div>
            <p className="text-white-50 mb-3">
              Wildfire will run Auto Scan on each selected Wildcard target sequentially using the current Auto Scan configuration.
            </p>

            {wildcardTargets.length === 0 ? (
              <div className="text-center text-white-50 py-4">
                No Wildcard scope targets found. Add Wildcard targets first.
              </div>
            ) : (
              <>
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <span className="text-danger">
                    {selectedCount} of {wildcardTargets.length} targets selected
                  </span>
                  <div>
                    <Button variant="link" size="sm" className="text-danger p-0 me-3" onClick={handleSelectAll}>
                      Select All
                    </Button>
                    <Button variant="link" size="sm" className="text-secondary p-0" onClick={handleDeselectAll}>
                      Deselect All
                    </Button>
                  </div>
                </div>

                <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                  {wildcardTargets.map(target => (
                    <Form.Check
                      key={target.id}
                      type="checkbox"
                      id={`wildfire-${target.id}`}
                      label={target.scope_target.replace('*.', '')}
                      checked={!!selectedTargets[target.id]}
                      onChange={() => handleToggle(target.id)}
                      className="mb-2 text-danger custom-checkbox"
                    />
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </Modal.Body>
      <Modal.Footer className="border-secondary">
        {isWildfireRunning ? (
          <>
            <Button variant="outline-secondary" onClick={handleClose}>
              Minimize
            </Button>
            <Button variant="outline-danger" onClick={onCancelWildfire}>
              Cancel Wildfire
            </Button>
          </>
        ) : (
          <>
            <Button variant="outline-secondary" onClick={handleClose}>
              Close
            </Button>
            <Button
              variant="outline-danger"
              onClick={handleStart}
              disabled={selectedCount === 0}
            >
              <i className="bi bi-fire me-1"></i>
              Start Wildfire ({selectedCount} targets)
            </Button>
          </>
        )}
      </Modal.Footer>
    </Modal>
  );
}

export default WildfireModal;
