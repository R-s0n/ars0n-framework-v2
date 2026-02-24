import React from 'react';
import { Modal, Button } from 'react-bootstrap';

const LearnMoreModal = ({ show, handleClose, lesson }) => {
  if (!lesson) return null;

  return (
    <Modal 
      show={show} 
      onHide={handleClose} 
      size="lg" 
      data-bs-theme="dark"
      centered
    >
      <Modal.Header closeButton className="bg-dark border-danger">
        <Modal.Title className="text-danger fs-4">
          <i className="fas fa-graduation-cap me-2"></i>
          {lesson.title}
        </Modal.Title>
      </Modal.Header>
      
      <Modal.Body className="bg-dark text-light">
        <div className="mb-4">
          <h5 className="text-danger mb-3">
            <i className="fas fa-info-circle me-2"></i>
            Overview
          </h5>
          <p className="lead">{lesson.overview}</p>
        </div>

        {lesson.sections && lesson.sections.map((section, index) => (
          <div key={index} className="mb-4">
            <h5 className="text-danger mb-3">
              <i className={`fas ${section.icon} me-2`}></i>
              {section.title}
            </h5>
            {section.content.map((paragraph, pIndex) => (
              <p key={pIndex} className="mb-3">{paragraph}</p>
            ))}
            
            {section.keyPoints && (
              <div className="mb-3">
                <h6 className="text-warning mb-2">Key Points:</h6>
                <ul className="text-light">
                  {section.keyPoints.map((point, pointIndex) => (
                    <li key={pointIndex} className="mb-1">{point}</li>
                  ))}
                </ul>
              </div>
            )}

            {section.examples && (
              <div className="mb-3">
                <h6 className="text-warning mb-2">Examples:</h6>
                <div className="bg-secondary p-3 rounded">
                  {section.examples.map((example, exIndex) => (
                    <div key={exIndex} className="mb-2">
                      <code className="text-info">{example.code}</code>
                      {example.description && (
                        <small className="d-block text-muted mt-1">{example.description}</small>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}

        {lesson.practicalTips && (
          <div className="mb-4">
            <h5 className="text-danger mb-3">
              <i className="fas fa-lightbulb me-2"></i>
              Practical Tips for Bug Bounty Hunters
            </h5>
            <div className="bg-dark border border-warning p-3 rounded">
              {lesson.practicalTips.map((tip, tipIndex) => (
                <div key={tipIndex} className="mb-2">
                  <i className="fas fa-arrow-right text-warning me-2"></i>
                  <span>{tip}</span>
                </div>
              ))}
            </div>
          </div>
        )}



        {lesson.furtherReading && (
          <div className="mb-4">
            <h5 className="text-danger mb-3">
              <i className="fas fa-book-open me-2"></i>
              Further Reading
            </h5>
            <ul className="list-unstyled">
              {lesson.furtherReading.map((resource, resIndex) => (
                <li key={resIndex} className="mb-2">
                  <a href={resource.url} target="_blank" rel="noopener noreferrer" className="text-info text-decoration-none">
                    <i className="fas fa-external-link-alt me-2"></i>
                    {resource.title}
                  </a>
                  {resource.description && (
                    <small className="d-block text-muted ms-4">{resource.description}</small>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </Modal.Body>
      
      <Modal.Footer className="bg-dark border-danger">
        <Button variant="outline-danger" onClick={handleClose}>
          <i className="fas fa-times me-2"></i>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default LearnMoreModal; 