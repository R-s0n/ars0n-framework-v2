import { useState, useEffect } from 'react';
import { Modal, Button, Form, ListGroup, Badge, Spinner, Alert } from 'react-bootstrap';

const QUESTIONS = [
  {
    category: 'Application Identity & Scope',
    questions: [
      'What is the primary function of the application?',
      'Is it consumer-facing, enterprise-facing, internal, or partner-facing?',
      'Is the application a single product or part of a larger platform?',
      'Are there multiple subdomains serving different functions?',
      'Are there multiple environments publicly accessible (prod, staging, beta)?',
      'Is the application region-specific or global?',
      'Are there mobile apps, desktop apps, or browser extensions associated with it?',
      'Is the web app a full product or a thin UI over APIs?',
      'Does the application expose public documentation or help portals?',
      'Is the app intended to be embedded or integrated into other sites?'
    ]
  },
  {
    category: 'Technology Stack & Frameworks',
    questions: [
      'What frontend framework is used?',
      'Is the app a Single Page Application?',
      'Is server-side rendering used?',
      'What backend language(s) are implied?',
      'Is the backend REST, GraphQL, or mixed?',
      'Are API versioning patterns present?',
      'Are build tools identifiable from assets?',
      'Are framework or library versions exposed?',
      'Are deprecated or end-of-life libraries in use?',
      'Are custom client-side frameworks present?'
    ]
  },
  {
    category: 'Hosting, Infrastructure & Delivery',
    questions: [
      'Is the application behind a CDN?',
      'Which CDN or edge provider is used?',
      'What server software is observable?',
      'Is a load balancer or reverse proxy in use?',
      'Is the app hosted in a public cloud?',
      'Can the cloud provider be identified?',
      'Are multiple services hosted on the same domain?',
      'Is virtual hosting used?',
      'Are containerization or serverless hints present?',
      'Are internal hostnames or regions leaked in responses?'
    ]
  },
  {
    category: 'Network & Transport Security',
    questions: [
      'Is HTTPS enforced everywhere?',
      'Is HSTS enabled?',
      'Which TLS versions are supported?',
      'Are weak cipher suites accepted?',
      'Is HTTP/2 or HTTP/3 used?',
      'Are cookies marked Secure?',
      'Are cookies marked HttpOnly?',
      'Is SameSite set on cookies?',
      'Are authentication cookies scoped to subdomains?',
      'Are multiple domains involved in session handling?'
    ]
  },
  {
    category: 'Traffic Controls & Abuse Protection',
    questions: [
      'Is a Web Application Firewall present?',
      'Can the WAF vendor be identified?',
      'Is bot detection or fingerprinting in use?',
      'Is rate limiting observable?',
      'Is CAPTCHA used anywhere in the app?',
      'Is CAPTCHA conditional or global?',
      'Are request challenges used (JS challenges, proof-of-work)?',
      'Are IP-based restrictions present?',
      'Does behavior differ for authenticated users?',
      'Are automated clients treated differently?'
    ]
  },
  {
    category: 'Authentication & Identity Model',
    questions: [
      'Is authentication required to access core functionality?',
      'What authentication methods are supported?',
      'Are third-party IdPs used?',
      'Is OAuth or OIDC used?',
      'Are multiple login methods available?',
      'Is MFA supported?',
      'Is MFA optional or mandatory?',
      'Are long-lived sessions used?',
      'Are refresh tokens observable client-side?',
      'Are authentication flows shared across domains?'
    ]
  },
  {
    category: 'Authorization, Roles & Data Model',
    questions: [
      'Are multiple user roles visible?',
      'Are role distinctions observable in the UI?',
      'Is the application multi-tenant?',
      'Are organizations, teams, or workspaces present?',
      'Are user identifiers exposed client-side?',
      'Are object identifiers exposed globally?',
      'Are shared resources visible?',
      'Are admin interfaces exposed?',
      'Are feature flags visible client-side?',
      'Are permissions enforced centrally or per-service?'
    ]
  },
  {
    category: 'Client-Side, Integrations & Policies',
    questions: [
      'What third-party scripts are loaded?',
      'Are analytics platforms present?',
      'Are customer support widgets present?',
      'Are payment providers integrated?',
      'Are external APIs called from the browser?',
      'Are API keys present client-side?',
      'Is a Content Security Policy present?',
      'Is the CSP strict or permissive?',
      'Is CORS implemented?',
      'Is source code or documentation publicly available?'
    ]
  }
];

export const ApplicationQuestionsModal = ({ 
  show, 
  handleClose, 
  activeTarget 
}) => {
  const [selectedQuestion, setSelectedQuestion] = useState(null);
  const [answers, setAnswers] = useState({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editingAnswerId, setEditingAnswerId] = useState(null);
  const [newAnswerText, setNewAnswerText] = useState('');
  const [editAnswerText, setEditAnswerText] = useState('');
  const [error, setError] = useState(null);

  useEffect(() => {
    if (show && activeTarget) {
      fetchAnswers();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    if (selectedQuestion && answers[selectedQuestion]) {
      setNewAnswerText('');
    }
  }, [selectedQuestion, answers]);

  const fetchAnswers = async () => {
    if (!activeTarget) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/application-questions/${activeTarget.id}/answers`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch answers');
      }

      const data = await response.json();
      const answersMap = {};
      
      if (Array.isArray(data)) {
        data.forEach(answer => {
          if (!answersMap[answer.question]) {
            answersMap[answer.question] = [];
          }
          answersMap[answer.question].push(answer);
        });
      }

      setAnswers(answersMap);
    } catch (error) {
      console.error('Error fetching answers:', error);
      setError('Failed to load answers');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveAnswer = async () => {
    if (!selectedQuestion || !newAnswerText.trim() || !activeTarget) return;

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/application-questions/${activeTarget.id}/answers`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            question: selectedQuestion,
            answer: newAnswerText.trim()
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save answer');
      }

      const savedAnswer = await response.json();
      
      setAnswers(prev => {
        const updated = { ...prev };
        if (!updated[selectedQuestion]) {
          updated[selectedQuestion] = [];
        }
        updated[selectedQuestion].push(savedAnswer);
        return updated;
      });

      setNewAnswerText('');
    } catch (error) {
      console.error('Error saving answer:', error);
      setError('Failed to save answer');
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateAnswer = async (answerId) => {
    if (!editAnswerText.trim()) return;

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/application-questions/answers/${answerId}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            answer: editAnswerText.trim()
          })
        }
      );

      if (!response.ok) {
        throw new Error('Failed to update answer');
      }

      const updatedAnswer = await response.json();
      
      setAnswers(prev => {
        const updated = { ...prev };
        if (updated[selectedQuestion]) {
          updated[selectedQuestion] = updated[selectedQuestion].map(a => 
            a.id === answerId ? updatedAnswer : a
          );
        }
        return updated;
      });

      setEditingAnswerId(null);
      setEditAnswerText('');
    } catch (error) {
      console.error('Error updating answer:', error);
      setError('Failed to update answer');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteAnswer = async (answerId) => {
    if (!window.confirm('Are you sure you want to delete this answer?')) return;

    setSaving(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/application-questions/answers/${answerId}`,
        {
          method: 'DELETE'
        }
      );

      if (!response.ok) {
        throw new Error('Failed to delete answer');
      }

      setAnswers(prev => {
        const updated = { ...prev };
        if (updated[selectedQuestion]) {
          updated[selectedQuestion] = updated[selectedQuestion].filter(a => a.id !== answerId);
        }
        return updated;
      });
    } catch (error) {
      console.error('Error deleting answer:', error);
      setError('Failed to delete answer');
    } finally {
      setSaving(false);
    }
  };

  const handleStartEdit = (answer) => {
    setEditingAnswerId(answer.id);
    setEditAnswerText(answer.answer);
  };

  const handleCancelEdit = () => {
    setEditingAnswerId(null);
    setEditAnswerText('');
  };

  const getQuestionCategory = (question) => {
    for (const category of QUESTIONS) {
      if (category.questions.includes(question)) {
        return category.category;
      }
    }
    return 'Unknown';
  };

  const allQuestions = QUESTIONS.flatMap(cat => cat.questions);

  return (
    <Modal 
      show={show} 
      onHide={handleClose} 
      fullscreen
      data-bs-theme="dark"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-question-circle me-2" />
          Application Questions
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="p-0">
        <div className="d-flex h-100" style={{ height: 'calc(100vh - 120px)' }}>
          <div className="border-end border-secondary" style={{ width: '400px', overflowY: 'auto' }}>
            <div className="p-3 bg-dark border-bottom border-secondary">
              <h6 className="text-white mb-0">Questions by Category</h6>
            </div>
            {QUESTIONS.map((category, catIndex) => (
              <div key={catIndex} className="border-bottom border-secondary">
                <div className="p-2 bg-secondary bg-opacity-25">
                  <strong className="text-white small">{category.category}</strong>
                </div>
                <ListGroup variant="flush">
                  {category.questions.map((question, qIndex) => {
                    const hasAnswers = answers[question] && answers[question].length > 0;
                    return (
                      <ListGroup.Item
                        key={qIndex}
                        action
                        active={selectedQuestion === question}
                        onClick={() => setSelectedQuestion(question)}
                        className="bg-dark border-secondary text-white"
                        style={{ cursor: 'pointer' }}
                      >
                        <div className="d-flex justify-content-between align-items-start">
                          <span className="small">{question}</span>
                          {hasAnswers && (
                            <Badge bg="success" className="ms-2">
                              {answers[question].length}
                            </Badge>
                          )}
                        </div>
                      </ListGroup.Item>
                    );
                  })}
                </ListGroup>
              </div>
            ))}
          </div>

          <div className="flex-fill p-4" style={{ overflowY: 'auto' }}>
            {loading ? (
              <div className="text-center py-5">
                <Spinner animation="border" variant="danger">
                  <span className="visually-hidden">Loading...</span>
                </Spinner>
              </div>
            ) : selectedQuestion ? (
              <>
                {error && (
                  <Alert variant="danger" dismissible onClose={() => setError(null)}>
                    {error}
                  </Alert>
                )}

                <div className="mb-4">
                  <h5 className="text-danger mb-2">{selectedQuestion}</h5>
                  <Badge bg="secondary" className="mb-3">
                    {getQuestionCategory(selectedQuestion)}
                  </Badge>
                </div>

                <div className="mb-4">
                  <h6 className="text-white mb-3">Previous Answers</h6>
                  {answers[selectedQuestion] && answers[selectedQuestion].length > 0 ? (
                    <div className="space-y-3">
                      {answers[selectedQuestion].map((answer) => (
                        <div key={answer.id} className="border border-secondary rounded p-3 mb-3 bg-dark">
                          {editingAnswerId === answer.id ? (
                            <div>
                              <Form.Control
                                as="textarea"
                                rows={3}
                                value={editAnswerText}
                                onChange={(e) => setEditAnswerText(e.target.value)}
                                className="mb-2"
                                data-bs-theme="dark"
                              />
                              <div className="d-flex gap-2">
                                <Button
                                  variant="success"
                                  size="sm"
                                  onClick={() => handleUpdateAnswer(answer.id)}
                                  disabled={saving || !editAnswerText.trim()}
                                >
                                  {saving ? <Spinner animation="border" size="sm" /> : 'Save'}
                                </Button>
                                <Button
                                  variant="secondary"
                                  size="sm"
                                  onClick={handleCancelEdit}
                                  disabled={saving}
                                >
                                  Cancel
                                </Button>
                              </div>
                            </div>
                          ) : (
                            <div>
                              <p className="text-white mb-2">{answer.answer}</p>
                              <div className="d-flex gap-2">
                                <Button
                                  variant="outline-warning"
                                  size="sm"
                                  onClick={() => handleStartEdit(answer)}
                                >
                                  <i className="bi bi-pencil me-1" />
                                  Edit
                                </Button>
                                <Button
                                  variant="outline-danger"
                                  size="sm"
                                  onClick={() => handleDeleteAnswer(answer.id)}
                                >
                                  <i className="bi bi-trash me-1" />
                                  Delete
                                </Button>
                              </div>
                              {answer.created_at && (
                                <small className="text-white-50 d-block mt-2">
                                  {new Date(answer.created_at).toLocaleString()}
                                </small>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-white-50">No answers yet. Add your first answer below.</p>
                  )}
                </div>

                <div className="border-top border-secondary pt-4">
                  <h6 className="text-white mb-3">Add New Answer</h6>
                  <Form.Control
                    as="textarea"
                    rows={4}
                    value={newAnswerText}
                    onChange={(e) => setNewAnswerText(e.target.value)}
                    placeholder="Enter your answer here..."
                    className="mb-3"
                    data-bs-theme="dark"
                  />
                  <Button
                    variant="danger"
                    onClick={handleSaveAnswer}
                    disabled={saving || !newAnswerText.trim()}
                  >
                    {saving ? (
                      <>
                        <Spinner animation="border" size="sm" className="me-2" />
                        Saving...
                      </>
                    ) : (
                      <>
                        <i className="bi bi-save me-2" />
                        Save Answer
                      </>
                    )}
                  </Button>
                </div>
              </>
            ) : (
              <div className="text-center py-5">
                <i className="bi bi-question-circle text-white-50" style={{ fontSize: '4rem' }}></i>
                <h5 className="text-white-50 mt-3">Select a Question</h5>
                <p className="text-white-50">
                  Choose a question from the list on the left to view and add answers.
                </p>
              </div>
            )}
          </div>
        </div>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

