import { useState, useEffect, useMemo } from 'react';
import { Modal, Row, Col, Badge, ListGroup } from 'react-bootstrap';
import { attacksForCategory, STRIDE_LABELS } from '../data/attacks';

// One reusable modal, driven by the STRIDE category the user opened. Left column lists the attacks
// that are weaponized to achieve this category; the middle explains how to execute and test the
// selected attack; the right column explains how it is weaponized for this category and the "why".
const PossibleAttacksModal = ({ show, handleClose, category }) => {
  const categoryLabel = STRIDE_LABELS[category] || category || '';
  const list = useMemo(() => (category ? attacksForCategory(category) : []), [category]);
  const [selectedId, setSelectedId] = useState(null);

  useEffect(() => {
    if (show) setSelectedId(list.length ? list[0].id : null);
  }, [show, category, list]);

  const attack = list.find((a) => a.id === selectedId) || null;
  const mapping = attack && attack.stride ? attack.stride[category] : null;
  const otherCategories = attack
    ? Object.keys(attack.stride || {}).filter((k) => k !== category)
    : [];

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" dialogClassName="modal-90w">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Possible Attacks: {categoryLabel}</Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-white" style={{ minHeight: '72vh' }}>
        {list.length === 0 ? (
          <div className="text-center text-white-50 py-5">
            No attacks documented for this category yet.
          </div>
        ) : (
          <Row>
            {/* LEFT: attack list */}
            <Col md={3} className="border-end border-secondary" style={{ maxHeight: '72vh', overflowY: 'auto' }}>
              <div className="text-white-50 small text-uppercase mb-2">
                Attacks ({list.length})
              </div>
              <ListGroup variant="flush">
                {list.map((a) => (
                  <ListGroup.Item
                    key={a.id}
                    action
                    active={a.id === selectedId}
                    onClick={() => setSelectedId(a.id)}
                    className="bg-dark text-white py-2"
                  >
                    <div className="fw-bold" style={{ fontSize: '0.9rem' }}>{a.name}</div>
                    {a.tags && a.tags.length > 0 && (
                      <div className="text-white-50" style={{ fontSize: '0.68rem' }}>{a.tags.join(', ')}</div>
                    )}
                  </ListGroup.Item>
                ))}
              </ListGroup>
            </Col>

            {/* MIDDLE: how to execute and test */}
            <Col md={6} className="border-end border-secondary" style={{ maxHeight: '72vh', overflowY: 'auto' }}>
              {!attack ? (
                <div className="text-white-50 py-5 text-center">Select an attack.</div>
              ) : (
                <>
                  <h5 className="text-danger mb-1">{attack.name}</h5>
                  <p className="text-white-50 fst-italic" style={{ fontSize: '0.85rem' }}>{attack.summary}</p>
                  {attack.executionContext && (
                    <div className="border border-danger rounded p-2 mb-3" style={{ background: 'rgba(220,53,69,0.08)' }}>
                      <div className="text-danger text-uppercase fw-bold" style={{ fontSize: '0.7rem', letterSpacing: '0.5px' }}>
                        Where it executes
                      </div>
                      <div className="fw-bold" style={{ fontSize: '0.85rem' }}>{attack.executionContext.where}</div>
                      <div className="text-white-50" style={{ fontSize: '0.8rem' }}>{attack.executionContext.detail}</div>
                    </div>
                  )}
                  {attack.howTo.map((section, i) => (
                    <div key={i} className="mb-3">
                      <div className="text-info text-uppercase" style={{ fontSize: '0.75rem', letterSpacing: '0.5px' }}>
                        {section.heading}
                      </div>
                      {(section.body || []).map((p, j) => (
                        <p key={j} className="mb-2" style={{ fontSize: '0.85rem' }}>{p}</p>
                      ))}
                      {(section.examples || []).map((ex, k) => (
                        <div key={k} className="mb-2">
                          <pre className="bg-black text-warning p-2 rounded mb-0"
                            style={{ fontSize: '0.75rem', whiteSpace: 'pre-wrap' }}>{ex.code}</pre>
                          {ex.note && (
                            <div className="text-white-50" style={{ fontSize: '0.72rem' }}>{ex.note}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  ))}
                </>
              )}
            </Col>

            {/* RIGHT: weaponization + why for this category */}
            <Col md={3} style={{ maxHeight: '72vh', overflowY: 'auto' }}>
              {!attack ? null : (
                <>
                  <div className="text-white-50 small text-uppercase mb-1">
                    Weaponized for {categoryLabel}
                  </div>
                  {Array.isArray(mapping && mapping.weaponization) ? (
                    <ul className="ps-3 mb-0" style={{ fontSize: '0.82rem' }}>
                      {mapping.weaponization.map((w, i) => (
                        <li key={i} className="mb-2">{w}</li>
                      ))}
                    </ul>
                  ) : (
                    <p style={{ fontSize: '0.82rem' }}>{mapping ? mapping.weaponization : ''}</p>
                  )}

                  <div className="text-white-50 small text-uppercase mb-1 mt-3">Why</div>
                  <p style={{ fontSize: '0.82rem' }}>{mapping ? mapping.why : ''}</p>

                  {otherCategories.length > 0 && (
                    <>
                      <div className="text-white-50 small text-uppercase mb-1 mt-3">Also weaponized as</div>
                      <div className="d-flex flex-wrap gap-1">
                        {otherCategories.map((k) => (
                          <Badge key={k} bg="secondary">{STRIDE_LABELS[k] || k}</Badge>
                        ))}
                      </div>
                    </>
                  )}
                </>
              )}
            </Col>
          </Row>
        )}
      </Modal.Body>
    </Modal>
  );
};

export default PossibleAttacksModal;
