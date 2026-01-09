import { useState, useRef, useCallback, useEffect } from 'react';
import { Modal, Button, Table, Form, Alert, Spinner } from 'react-bootstrap';
import { FaTrashAlt, FaCheck, FaTimes } from 'react-icons/fa';
import { MdCopyAll } from 'react-icons/md';

const TrimNetworkRangesModal = ({ 
  show, 
  handleClose, 
  activeTarget,
  onNetworkRangesDeleted 
}) => {
  const [selectedTool, setSelectedTool] = useState('');
  const [toolNetworkRanges, setToolNetworkRanges] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedRanges, setSelectedRanges] = useState(new Set());
  const [deletingRanges, setDeletingRanges] = useState(new Set());
  const [deletingAll, setDeletingAll] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStartIndex, setDragStartIndex] = useState(null);
  const [dragMode, setDragMode] = useState('select');
  const tableRef = useRef(null);

  const tools = [
    { key: 'amass_intel', name: 'Amass Intel' },
    { key: 'metabigor', name: 'Metabigor' }
  ];

  useEffect(() => {
    if (show && !selectedTool && activeTarget) {
      const firstTool = tools[0].key;
      setSelectedTool(firstTool);
      fetchNetworkRangesForTool(firstTool);
    }
  }, [show, activeTarget]);

  const fetchNetworkRangesForTool = async (toolKey) => {
    if (!activeTarget) return;
    
    setLoading(true);
    setError('');
    
    try {
      let response;
      if (toolKey === 'amass_intel') {
        // For Amass Intel, we need to get the most recent scan first, then fetch its network ranges
        const scansResponse = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/amass-intel`
        );
        
        if (scansResponse.ok) {
          const scans = await scansResponse.json();
          if (scans && scans.length > 0) {
            const mostRecentScan = scans[0];
            response = await fetch(
              `/api/amass-intel/${mostRecentScan.scan_id}/networks`
            );
          } else {
            setToolNetworkRanges([]);
            setLoading(false);
            return;
          }
        } else {
          throw new Error('Failed to fetch Amass Intel scans');
        }
      } else if (toolKey === 'metabigor') {
        // For Metabigor, we need to get the most recent scan first, then fetch its network ranges
        const scansResponse = await fetch(
          `/api/scopetarget/${activeTarget.id}/scans/metabigor-company`
        );
        
        if (scansResponse.ok) {
          const scans = await scansResponse.json();
          if (scans && scans.length > 0) {
            const mostRecentScan = scans[0];
            response = await fetch(
              `/api/metabigor-company/${mostRecentScan.scan_id}/networks`
            );
          } else {
            setToolNetworkRanges([]);
            setLoading(false);
            return;
          }
        } else {
          throw new Error('Failed to fetch Metabigor scans');
        }
      }
      
      if (!response.ok) {
        throw new Error('Failed to fetch network ranges');
      }
      
      const data = await response.json();
      setToolNetworkRanges(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error('Error fetching network ranges:', error);
      setError('Failed to fetch network ranges for this tool');
      setToolNetworkRanges([]);
    } finally {
      setLoading(false);
    }
  };

  const handleToolSelect = (toolKey) => {
    setSelectedTool(toolKey);
    setSelectedRanges(new Set());
    if (toolKey) {
      fetchNetworkRangesForTool(toolKey);
    } else {
      setToolNetworkRanges([]);
    }
  };

  const handleRangeSelect = (range, index) => {
    const newSelected = new Set(selectedRanges);
    const rangeKey = range.id;
    if (newSelected.has(rangeKey)) {
      newSelected.delete(rangeKey);
    } else {
      newSelected.add(rangeKey);
    }
    setSelectedRanges(newSelected);
  };

  const handleMouseDown = (range, index, event) => {
    if (event.button !== 0) return;
    
    setIsDragging(true);
    setDragStartIndex(index);
    
    const newSelected = new Set(selectedRanges);
    const rangeKey = range.id;
    const wasSelected = newSelected.has(rangeKey);
    
    if (wasSelected) {
      newSelected.delete(rangeKey);
      setDragMode('deselect');
    } else {
      newSelected.add(rangeKey);
      setDragMode('select');
    }
    
    setSelectedRanges(newSelected);
    event.preventDefault();
  };

  const handleMouseEnter = useCallback((range, index) => {
    if (!isDragging || dragStartIndex === null) return;
    
    const startIndex = Math.min(dragStartIndex, index);
    const endIndex = Math.max(dragStartIndex, index);
    
    const newSelected = new Set(selectedRanges);
    for (let i = startIndex; i <= endIndex; i++) {
      if (i < toolNetworkRanges.length) {
        const currentRange = toolNetworkRanges[i];
        const rangeKey = currentRange.id;
        if (dragMode === 'select') {
          newSelected.add(rangeKey);
        } else {
          newSelected.delete(rangeKey);
        }
      }
    }
    setSelectedRanges(newSelected);
  }, [isDragging, dragStartIndex, selectedRanges, toolNetworkRanges, dragMode]);

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
    const newSelected = new Set();
    toolNetworkRanges.forEach(range => {
      const rangeKey = range.id;
      newSelected.add(rangeKey);
    });
    setSelectedRanges(newSelected);
  };

  const handleDeselectAll = () => {
    setSelectedRanges(new Set());
  };

  const handleCopyText = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      // Could add toast notification here if available
    } catch (err) {
      console.error('Failed to copy text:', err);
    }
  };

  const deleteNetworkRange = async (range) => {
    const rangeId = range.id;
    setDeletingRanges(prev => new Set(prev).add(rangeId));
    
    try {
      const response = await fetch(
        `/api/${selectedTool === 'amass_intel' ? 'amass-intel' : 'metabigor'}/network-range/${rangeId}`,
        { method: 'DELETE' }
      );
      
      if (!response.ok) {
        throw new Error('Failed to delete network range');
      }
      
      setToolNetworkRanges(prev => prev.filter(r => r.id !== rangeId));
      setSelectedRanges(prev => {
        const newSet = new Set(prev);
        newSet.delete(rangeId);
        return newSet;
      });
      
      if (onNetworkRangesDeleted) {
        onNetworkRangesDeleted();
      }
    } catch (error) {
      console.error('Error deleting network range:', error);
      setError(`Failed to delete network range: ${range.cidr_block}`);
    } finally {
      setDeletingRanges(prev => {
        const newSet = new Set(prev);
        newSet.delete(rangeId);
        return newSet;
      });
    }
  };

  const deleteSelectedRanges = async () => {
    if (selectedRanges.size === 0) return;
    
    setDeletingAll(true);
    const rangesToDelete = Array.from(selectedRanges);
    
    try {
      const deletePromises = rangesToDelete.map(async rangeId => {
        const response = await fetch(
          `/api/${selectedTool === 'amass_intel' ? 'amass-intel' : 'metabigor'}/network-range/${rangeId}`,
          { method: 'DELETE' }
        );
        
        if (!response.ok) {
          throw new Error(`Failed to delete network range: ${rangeId}`);
        }
        
        return rangeId;
      });
      
      const deletedRanges = await Promise.all(deletePromises);
      
      setToolNetworkRanges(prev => prev.filter(r => !selectedRanges.has(r.id)));
      setSelectedRanges(new Set());
      
      if (onNetworkRangesDeleted) {
        onNetworkRangesDeleted();
      }
      
      console.log(`Successfully deleted ${deletedRanges.length} network ranges`);
    } catch (error) {
      console.error('Error deleting selected network ranges:', error);
      setError(`Failed to delete some network ranges: ${error.message}`);
      
      fetchNetworkRangesForTool(selectedTool);
    } finally {
      setDeletingAll(false);
    }
  };

  const deleteAllRanges = async () => {
    if (toolNetworkRanges.length === 0) return;
    
    console.log('[TRIM-NETWORK-RANGES-MODAL] Delete All Ranges - Selected Tool:', selectedTool);
    console.log('[TRIM-NETWORK-RANGES-MODAL] Delete All Ranges - Tool Ranges Length:', toolNetworkRanges.length);
    
    setDeletingAll(true);
    
    try {
      const mostRecentScan = toolNetworkRanges[0];
      if (!mostRecentScan || !mostRecentScan.scan_id) {
        throw new Error('No scan ID available for deletion');
      }
      
      const url = `/api/${selectedTool === 'amass_intel' ? 'amass-intel' : 'metabigor'}/scan/${mostRecentScan.scan_id}/network-ranges`;
      console.log('[TRIM-NETWORK-RANGES-MODAL] Delete All Ranges - URL:', url);
      
      const response = await fetch(url, { method: 'DELETE' });
      
      if (!response.ok) {
        throw new Error('Failed to delete all network ranges');
      }
      
      setToolNetworkRanges([]);
      setSelectedRanges(new Set());
      
      if (onNetworkRangesDeleted) {
        onNetworkRangesDeleted();
      }
    } catch (error) {
      console.error('Error deleting all network ranges:', error);
      setError('Failed to delete all network ranges');
    } finally {
      setDeletingAll(false);
    }
  };

  const handleModalClose = () => {
    setSelectedTool('');
    setToolNetworkRanges([]);
    setSelectedRanges(new Set());
    setError('');
    setIsDragging(false);
    setDragStartIndex(null);
    setDragMode('select');
    handleClose();
    
    if (onNetworkRangesDeleted) {
      setTimeout(() => {
        onNetworkRangesDeleted();
      }, 100);
    }
  };

  return (
    <Modal 
      data-bs-theme="dark" 
      show={show} 
      onHide={handleModalClose} 
      size="xl"
      dialogClassName="modal-90w"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Trim Network Ranges</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>
        )}
        
        <div className="row">
          <div className="col-md-3">
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
          
          <div className="col-md-9">
            {selectedTool ? (
              <>
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h6 className="mb-0 text-white">
                    Network Ranges from {tools.find(t => t.key === selectedTool)?.name} 
                    <span className="text-light ms-2">({toolNetworkRanges.length})</span>
                  </h6>
                </div>
                
                <div className="d-flex mb-3" style={{ gap: '8px' }}>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={handleDeselectAll}
                    disabled={selectedRanges.size === 0}
                    style={{ flex: 1 }}
                  >
                    <FaTimes className="me-1" />
                    De-Select All
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={handleSelectAll}
                    disabled={toolNetworkRanges.length === 0 || selectedRanges.size === toolNetworkRanges.length}
                    style={{ flex: 1 }}
                  >
                    <FaCheck className="me-1" />
                    Select All
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={deleteSelectedRanges}
                    disabled={selectedRanges.size === 0 || deletingAll}
                    style={{ flex: 1 }}
                  >
                    {deletingAll ? (
                      <Spinner animation="border" size="sm" className="me-1" />
                    ) : (
                      <FaTrashAlt className="me-1" />
                    )}
                    Delete Selected ({selectedRanges.size})
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={deleteAllRanges}
                    disabled={toolNetworkRanges.length === 0 || deletingAll}
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
                    <p className="mt-2">Loading network ranges...</p>
                  </div>
                ) : toolNetworkRanges.length > 0 ? (
                  <div 
                    style={{ 
                      maxHeight: '500px', 
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
                    <Table striped bordered hover variant="dark" size="sm" className="mb-0">
                      <thead style={{ position: 'sticky', top: 0, zIndex: 10 }}>
                        <tr>
                          <th width="40" style={{ backgroundColor: 'var(--bs-dark)' }}>
                            <Form.Check
                              type="checkbox"
                              checked={selectedRanges.size === toolNetworkRanges.length && toolNetworkRanges.length > 0}
                              onChange={selectedRanges.size === toolNetworkRanges.length ? handleDeselectAll : handleSelectAll}
                            />
                          </th>
                          <th style={{ backgroundColor: 'var(--bs-dark)' }}>CIDR Block</th>
                          <th style={{ backgroundColor: 'var(--bs-dark)' }}>ASN</th>
                          <th style={{ backgroundColor: 'var(--bs-dark)' }}>Organization</th>
                          <th style={{ backgroundColor: 'var(--bs-dark)' }}>
                            {selectedTool === 'metabigor' ? 'Scan Type' : 'Description'}
                          </th>
                          <th style={{ backgroundColor: 'var(--bs-dark)' }}>Country</th>
                          <th width="100" style={{ backgroundColor: 'var(--bs-dark)' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {toolNetworkRanges.map((range, index) => {
                          const rangeId = range.id;
                          const isSelected = selectedRanges.has(rangeId);
                          return (
                            <tr 
                              key={rangeId}
                              style={{
                                backgroundColor: isSelected
                                  ? 'rgba(220, 53, 69, 0.25)' 
                                  : 'transparent',
                                cursor: 'pointer',
                                userSelect: 'none',
                                transition: 'background-color 0.15s ease-in-out'
                              }}
                              onMouseDown={(e) => handleMouseDown(range, index, e)}
                              onMouseEnter={() => handleMouseEnter(range, index)}
                            >
                              <td>
                                <Form.Check
                                  type="checkbox"
                                  checked={isSelected}
                                  onChange={() => handleRangeSelect(range, index)}
                                  onClick={(e) => e.stopPropagation()}
                                />
                              </td>
                              <td 
                                style={{ 
                                  fontFamily: 'monospace',
                                  fontSize: '0.875rem'
                                }}
                              >
                                {range.cidr_block || range.range || range}
                              </td>
                              <td 
                                style={{ 
                                  fontFamily: 'monospace',
                                  fontSize: '0.875rem'
                                }}
                              >
                                {range.asn || 'N/A'}
                              </td>
                              <td style={{ fontSize: '0.875rem' }}>
                                {range.organization || 'N/A'}
                              </td>
                              <td style={{ fontSize: '0.875rem' }}>
                                {selectedTool === 'metabigor' ? (
                                  range.scan_type ? (
                                    <span className="badge bg-info">{range.scan_type}</span>
                                  ) : 'N/A'
                                ) : (
                                  range.description || 'N/A'
                                )}
                              </td>
                              <td style={{ fontSize: '0.875rem' }}>
                                {range.country ? (
                                  <span className="badge bg-secondary">{range.country}</span>
                                ) : 'N/A'}
                              </td>
                              <td>
                                <div className="d-flex gap-1">
                                  <Button
                                    variant="outline-info"
                                    size="sm"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleCopyText(range.cidr_block);
                                    }}
                                    title="Copy CIDR block"
                                  >
                                    <MdCopyAll size={12} />
                                  </Button>
                                  <Button
                                    variant="outline-danger"
                                    size="sm"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      deleteNetworkRange(range);
                                    }}
                                    disabled={deletingRanges.has(rangeId)}
                                    title="Delete range"
                                  >
                                    {deletingRanges.has(rangeId) ? (
                                      <Spinner animation="border" size="sm" />
                                    ) : (
                                      <FaTrashAlt size={12} />
                                    )}
                                  </Button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </Table>
                  </div>
                ) : (
                  <div className="text-center py-4">
                    <p className="text-muted">No network ranges found for this tool.</p>
                  </div>
                )}
              </>
            ) : (
              <div className="text-center py-5">
                <p className="text-muted">Select a tool from the left to view its discovered network ranges.</p>
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

export default TrimNetworkRangesModal; 