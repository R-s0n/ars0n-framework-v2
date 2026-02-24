import { Modal, Button, Form, Card, Row, Col } from 'react-bootstrap';
import { useEffect } from 'react';
import { FaArrowLeft } from 'react-icons/fa';
import 'bootstrap-icons/font/bootstrap-icons.css';

function AddScopeTargetModal({ show, handleClose, selections, handleSelect, handleFormSubmit, errorMessage, showBackButton, onBackClick }) {
  useEffect(() => {
    if (show) {
      const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
      document.body.style.paddingRight = `${scrollbarWidth}px`;
    } else {
      document.body.style.paddingRight = '';
    }

    return () => {
      document.body.style.paddingRight = '';
    };
  }, [show]);

  const getPlaceholder = () => {
    switch (selections.type) {
      case 'Company':
        return 'Example: Google';
      case 'Wildcard':
        return 'Example: *.google.com';
      case 'URL':
        return 'Example: https://hackme.google.com';
      default:
        return 'Choose your scope target...';
    }
  };

  const handleSubmit = () => {
    if (handleFormSubmit && typeof handleFormSubmit === 'function') {
      handleFormSubmit();
    }
  };

  const targetTypes = [
    {
      type: 'Company',
      description: 'Any asset owned by an organization',
      disabled: false
    },
    {
      type: 'Wildcard',
      description: 'Any subdomain under the root domain',
      disabled: false
    },
    {
      type: 'URL',
      description: 'Any attack vector targeting a single domain',
      disabled: false
    }
  ];

  return (
    <Modal
      show={show}
      onHide={handleClose}
      backdrop="static"
      keyboard={false}
      animation={true}
      size="md"
      centered
      data-bs-theme="dark"
    >
      <Modal.Header closeButton className="flex-column align-items-center">
        <img
          src="/images/logo.avif"
          alt="Logo"
          style={{ width: '100px', height: '100px', marginBottom: '10px' }}
          centered
        />
        <div>
          {errorMessage && (
            <p className="text-danger m-0" style={{ fontSize: '0.9rem' }}>
              {errorMessage}
            </p>
          )}
        </div>
        <Modal.Title className="w-100 text-center text-secondary-emphasis">
          Ars0n Framework v2 <span style={{ fontSize: '0.7rem' }}>beta</span>
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Row className="g-3 mb-3">
          {targetTypes.map((target) => (
            <Col xs={12} key={target.type}>
              <Card
                className={`h-100 ${selections.type === target.type ? 'border-danger' : ''}`}
                onClick={() => !target.disabled && handleSelect('type', target.type)}
                style={{ 
                  cursor: target.disabled ? 'not-allowed' : 'pointer',
                  opacity: target.disabled ? 0.5 : 1
                }}
              >
                <Card.Body className="d-flex align-items-center">
                  <img
                    src={`/images/${target.type}.png`}
                    alt={target.type}
                    style={{ width: '50px', height: '50px', marginRight: '15px' }}
                  />
                  <div>
                    <h5 className="mb-1">{target.type}</h5>
                    <p className="mb-0 text-muted small">{target.description}</p>
                  </div>
                </Card.Body>
              </Card>
            </Col>
          ))}
        </Row>
        <h5 className="text-secondary">Scope Target</h5>
        <Form.Control
          type="text"
          className="custom-input"
          placeholder={getPlaceholder()}
          value={selections.inputText}
          onChange={(e) => handleSelect('inputText', e.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              handleFormSubmit();
            }
          }}
        />
      </Modal.Body>
      <Modal.Footer className="d-flex justify-content-between">
        {showBackButton && (
          <Button
            variant="outline-danger"
            onClick={onBackClick}
          >
            <FaArrowLeft className="me-1" />
            Back
          </Button>
        )}
        <Button variant="danger" onClick={handleSubmit} className={showBackButton ? '' : 'ms-auto'}>
          Let's Hack!
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default AddScopeTargetModal;
