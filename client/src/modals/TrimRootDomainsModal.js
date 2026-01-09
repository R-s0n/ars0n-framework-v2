import { useState, useRef, useCallback, useEffect } from 'react';
import { Modal, Button, Table, Form, Alert, Spinner } from 'react-bootstrap';
import { FaTrashAlt, FaCheck, FaTimes } from 'react-icons/fa';

const TrimRootDomainsModal = ({ 
  show, 
  handleClose, 
  activeTarget,
  onDomainsDeleted 
}) => {
  const [selectedTool, setSelectedTool] = useState('');
  const [toolDomains, setToolDomains] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedDomains, setSelectedDomains] = useState(new Set());
  const [deletingDomains, setDeletingDomains] = useState(new Set());
  const [deletingAll, setDeletingAll] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStartIndex, setDragStartIndex] = useState(null);
  const [dragMode, setDragMode] = useState('select');
  const tableRef = useRef(null);

  const tools = [
    { key: 'google_dorking', name: 'Google Dorking' },
    { key: 'ctl_company', name: 'Certificate Transparency' },
    { key: 'reverse_whois', name: 'Reverse Whois' },
    { key: 'securitytrails_company', name: 'SecurityTrails' },
    { key: 'github_recon', name: 'GitHub Recon' },
    { key: 'shodan_company', name: 'Shodan' },
    { key: 'censys_company', name: 'Censys' },
    { key: 'live_web_servers', name: 'Live Web Servers (ASN)' }
  ];

  useEffect(() => {
    if (show && !selectedTool && activeTarget) {
      const firstTool = tools[0].key;
      setSelectedTool(firstTool);
      fetchDomainsForTool(firstTool);
    }
  }, [show, activeTarget]);

  const fetchDomainsForTool = async (toolKey) => {
    if (!activeTarget) return;
    
    setLoading(true);
    setError('');
    
    try {
      const response = await fetch(
        `/api/api/company-domains/${activeTarget.id}/${toolKey}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch domains');
      }
      
      const data = await response.json();
      setToolDomains(data.domains || []);
    } catch (error) {
      console.error('Error fetching domains:', error);
      setError('Failed to fetch domains for this tool');
      setToolDomains([]);
    } finally {
      setLoading(false);
    }
  };

  const handleToolSelect = (toolKey) => {
    setSelectedTool(toolKey);
    setSelectedDomains(new Set());
    if (toolKey) {
      fetchDomainsForTool(toolKey);
    } else {
      setToolDomains([]);
    }
  };

  const handleDomainSelect = (domain, index) => {
    const newSelected = new Set(selectedDomains);
    if (newSelected.has(domain)) {
      newSelected.delete(domain);
    } else {
      newSelected.add(domain);
    }
    setSelectedDomains(newSelected);
  };

  const handleMouseDown = (domain, index, event) => {
    if (event.button !== 0) return;
    
    setIsDragging(true);
    setDragStartIndex(index);
    
    const newSelected = new Set(selectedDomains);
    const wasSelected = newSelected.has(domain);
    
    if (wasSelected) {
      newSelected.delete(domain);
      setDragMode('deselect');
    } else {
      newSelected.add(domain);
      setDragMode('select');
    }
    
    setSelectedDomains(newSelected);
    event.preventDefault();
  };

  const handleMouseEnter = useCallback((domain, index) => {
    if (!isDragging || dragStartIndex === null) return;
    
    const startIndex = Math.min(dragStartIndex, index);
    const endIndex = Math.max(dragStartIndex, index);
    
    const newSelected = new Set(selectedDomains);
    for (let i = startIndex; i <= endIndex; i++) {
      if (i < toolDomains.length) {
        if (dragMode === 'select') {
          newSelected.add(toolDomains[i]);
        } else {
          newSelected.delete(toolDomains[i]);
        }
      }
    }
    setSelectedDomains(newSelected);
  }, [isDragging, dragStartIndex, selectedDomains, toolDomains, dragMode]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
    setDragStartIndex(null);
    setDragMode('select');
  }, []);

  useEffect(() => {
    if (isDragging) {
      document.addEventListener('mouseup', handleMouseUp);
      return () => {
        document.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [isDragging, handleMouseUp]);

  const handleSelectAll = () => {
    setSelectedDomains(new Set(toolDomains));
  };

  const handleDeselectAll = () => {
    setSelectedDomains(new Set());
  };

  const deleteDomain = async (domain) => {
    setDeletingDomains(prev => new Set(prev).add(domain));
    
    try {
      const response = await fetch(
        `/api/api/company-domains/${activeTarget.id}/${selectedTool}/${encodeURIComponent(domain)}`,
        { method: 'DELETE' }
      );
      
      if (!response.ok) {
        throw new Error('Failed to delete domain');
      }
      
      setToolDomains(prev => prev.filter(d => d !== domain));
      setSelectedDomains(prev => {
        const newSet = new Set(prev);
        newSet.delete(domain);
        return newSet;
      });
      
      if (onDomainsDeleted) {
        onDomainsDeleted();
      }
    } catch (error) {
      console.error('Error deleting domain:', error);
      setError(`Failed to delete domain: ${domain}`);
    } finally {
      setDeletingDomains(prev => {
        const newSet = new Set(prev);
        newSet.delete(domain);
        return newSet;
      });
    }
  };

  const deleteSelectedDomains = async () => {
    if (selectedDomains.size === 0) return;
    
    setDeletingAll(true);
    const domainsToDelete = Array.from(selectedDomains);
    
    try {
      const deletePromises = domainsToDelete.map(async domain => {
        const response = await fetch(
          `/api/api/company-domains/${activeTarget.id}/${selectedTool}/${encodeURIComponent(domain)}`,
          { method: 'DELETE' }
        );
        
        if (!response.ok) {
          throw new Error(`Failed to delete domain: ${domain}`);
        }
        
        return domain;
      });
      
      const deletedDomains = await Promise.all(deletePromises);
      
      setToolDomains(prev => prev.filter(d => !selectedDomains.has(d)));
      setSelectedDomains(new Set());
      
      if (onDomainsDeleted) {
        onDomainsDeleted();
      }
      
      console.log(`Successfully deleted ${deletedDomains.length} domains`);
    } catch (error) {
      console.error('Error deleting selected domains:', error);
      setError(`Failed to delete some domains: ${error.message}`);
      
      fetchDomainsForTool(selectedTool);
    } finally {
      setDeletingAll(false);
    }
  };

  const deleteAllDomains = async () => {
    if (toolDomains.length === 0) return;
    
    console.log('[TRIM-MODAL] Delete All Domains - Selected Tool:', selectedTool);
    console.log('[TRIM-MODAL] Delete All Domains - Tool Domains Length:', toolDomains.length);
    
    setDeletingAll(true);
    
    try {
      const url = `/api/api/company-domains/${activeTarget.id}/${selectedTool}/all`;
      console.log('[TRIM-MODAL] Delete All Domains - URL:', url);
      
      const response = await fetch(url, { method: 'DELETE' });
      
      if (!response.ok) {
        throw new Error('Failed to delete all domains');
      }
      
      setToolDomains([]);
      setSelectedDomains(new Set());
      
      if (onDomainsDeleted) {
        onDomainsDeleted();
      }
    } catch (error) {
      console.error('Error deleting all domains:', error);
      setError('Failed to delete all domains');
    } finally {
      setDeletingAll(false);
    }
  };

  const handleModalClose = () => {
    setSelectedTool('');
    setToolDomains([]);
    setSelectedDomains(new Set());
    setError('');
    setIsDragging(false);
    setDragStartIndex(null);
    setDragMode('select');
    handleClose();
    
    if (onDomainsDeleted) {
      setTimeout(() => {
        onDomainsDeleted();
      }, 100);
    }
  };

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleModalClose} 
      size="xl"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Trim Root Domains</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>
        )}
        
        <div className="row">
          <div className="col-md-4">
            <h6 className="mb-3">Select Tool</h6>
            <div className="list-group">
              {tools.map(tool => (
                <button
                  key={tool.key}
                  className={`list-group-item list-group-item-action ${
                    selectedTool === tool.key ? 'active' : ''
                  }`}
                  onClick={() => handleToolSelect(tool.key)}
                  style={{ 
                    backgroundColor: selectedTool === tool.key ? 'var(--bs-danger)' : 'transparent',
                    borderColor: 'var(--bs-border-color)',
                    color: selectedTool === tool.key ? 'white' : 'var(--bs-body-color)',
                    transition: 'all 0.15s ease-in-out'
                  }}
                >
                  {tool.name}
                </button>
              ))}
            </div>
          </div>
          
          <div className="col-md-8">
            {selectedTool ? (
              <>
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h6 className="mb-0 text-white">
                    Domains from {tools.find(t => t.key === selectedTool)?.name} 
                    <span className="text-light ms-2">({toolDomains.length})</span>
                  </h6>
                </div>
                
                <div className="d-flex mb-3" style={{ gap: '8px' }}>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={handleDeselectAll}
                    disabled={selectedDomains.size === 0}
                    style={{ flex: 1 }}
                  >
                    <FaTimes className="me-1" />
                    De-Select All
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={handleSelectAll}
                    disabled={toolDomains.length === 0 || selectedDomains.size === toolDomains.length}
                    style={{ flex: 1 }}
                  >
                    <FaCheck className="me-1" />
                    Select All
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={deleteSelectedDomains}
                    disabled={selectedDomains.size === 0 || deletingAll}
                    style={{ flex: 1 }}
                  >
                    {deletingAll ? (
                      <Spinner animation="border" size="sm" className="me-1" />
                    ) : (
                      <FaTrashAlt className="me-1" />
                    )}
                    Delete Selected ({selectedDomains.size})
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={deleteAllDomains}
                    disabled={toolDomains.length === 0 || deletingAll}
                    style={{ flex: 1 }}
                  >
                    {deletingAll ? (
                      <Spinner animation="border" size="sm" className="me-1" />
                    ) : (
                      <FaTrashAlt className="me-1" />
                    )}
                    Delete All
                  </Button>
                </div>
                
                {loading ? (
                  <div className="text-center py-4">
                    <Spinner animation="border" />
                    <p className="mt-2">Loading domains...</p>
                  </div>
                ) : toolDomains.length > 0 ? (
                  <div 
                    style={{ 
                      maxHeight: '400px', 
                      overflowY: 'auto',
                      border: '1px solid var(--bs-border-color)',
                      borderRadius: '0.375rem'
                    }}
                    ref={tableRef}
                  >
                    <style>
                      {`
                        .form-check-input:checked {
                          background-color: #dc3545 !important;
                          border-color: #dc3545 !important;
                        }
                        .form-check-input:focus {
                          border-color: #dc3545 !important;
                          box-shadow: 0 0 0 0.25rem rgba(220, 53, 69, 0.25) !important;
                        }
                      `}
                    </style>
                    <Table hover variant="dark" size="sm" className="mb-0">
                      <thead style={{ position: 'sticky', top: 0, zIndex: 10 }}>
                        <tr>
                          <th width="40" style={{ backgroundColor: 'var(--bs-dark)' }}>
                            <Form.Check
                              type="checkbox"
                              checked={selectedDomains.size === toolDomains.length && toolDomains.length > 0}
                              onChange={selectedDomains.size === toolDomains.length ? handleDeselectAll : handleSelectAll}
                            />
                          </th>
                          <th style={{ backgroundColor: 'var(--bs-dark)' }}>Domain</th>
                          <th width="80" style={{ backgroundColor: 'var(--bs-dark)' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {toolDomains.map((domain, index) => (
                          <tr 
                            key={index}
                            style={{
                              backgroundColor: selectedDomains.has(domain) 
                                ? 'rgba(220, 53, 69, 0.25)' 
                                : 'transparent',
                              cursor: 'pointer',
                              userSelect: 'none',
                              transition: 'background-color 0.15s ease-in-out'
                            }}
                            onMouseDown={(e) => handleMouseDown(domain, index, e)}
                            onMouseEnter={() => handleMouseEnter(domain, index)}
                          >
                            <td>
                              <Form.Check
                                type="checkbox"
                                checked={selectedDomains.has(domain)}
                                onChange={() => handleDomainSelect(domain, index)}
                                onClick={(e) => e.stopPropagation()}
                              />
                            </td>
                            <td 
                              style={{ 
                                fontFamily: 'monospace',
                                fontSize: '0.875rem'
                              }}
                            >
                              {domain}
                            </td>
                            <td>
                              <Button
                                variant="outline-danger"
                                size="sm"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  deleteDomain(domain);
                                }}
                                disabled={deletingDomains.has(domain)}
                              >
                                {deletingDomains.has(domain) ? (
                                  <Spinner animation="border" size="sm" />
                                ) : (
                                  <FaTrashAlt />
                                )}
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </div>
                ) : (
                  <div className="text-center py-4">
                    <p className="text-muted">No domains found for this tool.</p>
                  </div>
                )}
              </>
            ) : (
              <div className="text-center py-5">
                <p className="text-muted">Select a tool from the left to view its discovered domains.</p>
              </div>
            )}
          </div>
        </div>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleModalClose}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default TrimRootDomainsModal; 