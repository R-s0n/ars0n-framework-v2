import { useState, useRef, useCallback, useEffect } from 'react';
import { Modal, Table, Button, Spinner, Alert, Row, Col, Form, InputGroup } from 'react-bootstrap';
import { FaCheck, FaTimes } from 'react-icons/fa';

const AmassIntelConfigModal = ({ 
  show, 
  handleClose, 
  consolidatedNetworkRanges = [], 
  activeTarget,
  onSaveConfig
}) => {
  const [selectedNetworkRanges, setSelectedNetworkRanges] = useState(new Set());
  const [filters, setFilters] = useState({
    networkRange: ''
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [estimatedTime, setEstimatedTime] = useState(0);
  const [localNetworkRanges, setLocalNetworkRanges] = useState([]);
  const [loadingNetworkRanges, setLoadingNetworkRanges] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStartIndex, setDragStartIndex] = useState(null);
  const [dragMode, setDragMode] = useState('select');
  const tableRef = useRef(null);

  // Use consolidated network ranges from props, or fallback to locally fetched ones
  const networkRangesToUse = consolidatedNetworkRanges.length > 0 ? consolidatedNetworkRanges : localNetworkRanges;

  useEffect(() => {
    if (show) {
      loadSavedConfig();
      // If no network ranges provided via props, fetch them
      if (consolidatedNetworkRanges.length === 0) {
        fetchConsolidatedNetworkRanges();
      }
    }
  }, [show, activeTarget]);

  useEffect(() => {
    setEstimatedTime(selectedNetworkRanges.size * 2); // Estimate 2 hours per network range
  }, [selectedNetworkRanges]);

  const fetchConsolidatedNetworkRanges = async () => {
    if (!activeTarget?.id) return;

    setLoadingNetworkRanges(true);
    try {
      const response = await fetch(
        `/api/consolidated-network-ranges/${activeTarget.id}`
      );
      
      if (response.ok) {
        const data = await response.json();
        if (data.network_ranges && Array.isArray(data.network_ranges)) {
          setLocalNetworkRanges(data.network_ranges);
        }
      }
    } catch (error) {
      console.error('Error fetching consolidated network ranges:', error);
      setError('Failed to load network ranges. Please try again.');
    } finally {
      setLoadingNetworkRanges(false);
    }
  };

  const loadSavedConfig = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `/api/amass-intel-config/${activeTarget.id}`
      );
      
      if (response.ok) {
        const config = await response.json();
        if (config.network_ranges && Array.isArray(config.network_ranges)) {
          setSelectedNetworkRanges(new Set(config.network_ranges));
        }
      }
    } catch (error) {
      console.error('Error loading Amass Intel config:', error);
    }
  };

  const handleSaveConfig = async () => {
    if (!activeTarget?.id) {
      setError('No active target selected');
      return;
    }

    setSaving(true);
    setError('');

    try {
      const config = {
        network_ranges: Array.from(selectedNetworkRanges),
        created_at: new Date().toISOString()
      };

      const response = await fetch(
        `/api/amass-intel-config/${activeTarget.id}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(config),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save configuration');
      }

      if (onSaveConfig) {
        onSaveConfig(config);
      }

      handleClose();
    } catch (error) {
      console.error('Error saving Amass Intel config:', error);
      setError('Failed to save configuration. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleFilterChange = (filterKey, value) => {
    setFilters(prev => ({
      ...prev,
      [filterKey]: value
    }));
  };

  const clearFilters = () => {
    setFilters({
      networkRange: ''
    });
  };

  const handleNetworkRangeSelect = (networkRange, index) => {
    const newSelected = new Set(selectedNetworkRanges);
    if (newSelected.has(networkRange)) {
      newSelected.delete(networkRange);
    } else {
      newSelected.add(networkRange);
    }
    setSelectedNetworkRanges(newSelected);
  };

  const handleMouseDown = (networkRange, index, event) => {
    if (event.button !== 0) return;
    
    setIsDragging(true);
    setDragStartIndex(index);
    
    const newSelected = new Set(selectedNetworkRanges);
    const wasSelected = newSelected.has(networkRange);
    
    if (wasSelected) {
      newSelected.delete(networkRange);
      setDragMode('deselect');
    } else {
      newSelected.add(networkRange);
      setDragMode('select');
    }
    
    setSelectedNetworkRanges(newSelected);
    event.preventDefault();
  };

  const handleMouseEnter = useCallback((networkRange, index) => {
    if (!isDragging || dragStartIndex === null) return;
    
    const filteredNetworkRanges = getFilteredAndSortedNetworkRanges();
    const startIndex = Math.min(dragStartIndex, index);
    const endIndex = Math.max(dragStartIndex, index);
    
    const newSelected = new Set(selectedNetworkRanges);
    for (let i = startIndex; i <= endIndex; i++) {
      if (i < filteredNetworkRanges.length) {
        const networkRangeAtIndex = typeof filteredNetworkRanges[i] === 'string' ? filteredNetworkRanges[i] : filteredNetworkRanges[i].cidr_block;
        if (dragMode === 'select') {
          newSelected.add(networkRangeAtIndex);
        } else {
          newSelected.delete(networkRangeAtIndex);
        }
      }
    }
    setSelectedNetworkRanges(newSelected);
  }, [isDragging, dragStartIndex, selectedNetworkRanges, dragMode]);

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

  const selectAllFiltered = () => {
    const filteredNetworkRanges = getFilteredAndSortedNetworkRanges();
    const allNetworkRanges = filteredNetworkRanges.map(item => typeof item === 'string' ? item : item.cidr_block);
    setSelectedNetworkRanges(new Set([...selectedNetworkRanges, ...allNetworkRanges]));
  };

  const deselectAllFiltered = () => {
    const filteredNetworkRanges = getFilteredAndSortedNetworkRanges();
    const filteredNetworkRangesSet = new Set(filteredNetworkRanges.map(item => typeof item === 'string' ? item : item.cidr_block));
    const newSelectedNetworkRanges = new Set([...selectedNetworkRanges].filter(networkRange => !filteredNetworkRangesSet.has(networkRange)));
    setSelectedNetworkRanges(newSelectedNetworkRanges);
  };

  const handleSelectAll = () => {
    const filteredNetworkRanges = getFilteredAndSortedNetworkRanges();
    const allNetworkRanges = filteredNetworkRanges.map(item => typeof item === 'string' ? item : item.cidr_block);
    setSelectedNetworkRanges(new Set(allNetworkRanges));
  };

  const handleDeselectAll = () => {
    setSelectedNetworkRanges(new Set());
  };

  const getFilteredAndSortedNetworkRanges = () => {
    let filteredNetworkRanges = networkRangesToUse.filter(item => {
      const networkRange = typeof item === 'string' ? item : item.cidr_block;
      if (!networkRange) return false;
      
      if (filters.networkRange && !networkRange.toLowerCase().includes(filters.networkRange.toLowerCase())) {
        return false;
      }
      
      return true;
    });

    return filteredNetworkRanges;
  };

  const handleCloseModal = () => {
    setError('');
    setIsDragging(false);
    setDragStartIndex(null);
    setDragMode('select');
    handleClose();
  };

  const filteredNetworkRanges = getFilteredAndSortedNetworkRanges();

  return (
    <Modal 
      show={show} 
      onHide={handleCloseModal} 
      size="xl" 
      data-bs-theme="dark"
      className="modal-90w"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-cloud-arrow-down me-2" />
          Configure Amass Intel - Network Range Discovery
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        <div className="mb-4">
          <Alert variant="warning">
            <div className="d-flex align-items-center">
              <i className="bi bi-exclamation-triangle-fill me-2" />
              <div>
                <strong>Performance Warning:</strong> Amass Intel can take up to 2 hours per network range to complete.
                Selected network ranges: <strong>{selectedNetworkRanges.size}</strong> 
                | Estimated total time: <strong>{estimatedTime === 1 ? '~2 hours' : `~${estimatedTime} hours`}</strong>
              </div>
            </div>
          </Alert>
        </div>

        {networkRangesToUse.length === 0 ? (
          <div className="text-center py-4">
            {loadingNetworkRanges ? (
              <>
                <div className="spinner-border text-danger mb-3" role="status">
                  <span className="visually-hidden">Loading...</span>
                </div>
                <h5 className="text-white-50">Loading Network Ranges...</h5>
                <p className="text-white-50">
                  Fetching consolidated network ranges...
                </p>
              </>
            ) : (
              <>
                <i className="bi bi-diagram-3 text-white-50" style={{ fontSize: '3rem' }} />
                <h5 className="text-white-50 mt-3">No Network Ranges Available</h5>
                <p className="text-white-50">
                  Run the IP/Port scanning tools and consolidate the network ranges first.
                </p>
              </>
            )}
          </div>
        ) : (
          <>
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h6 className="mb-0 text-white">
                Select network ranges for Amass Intel cloud asset discovery 
                <span className="text-light ms-2">({selectedNetworkRanges.size}/{networkRangesToUse.length})</span>
              </h6>
            </div>

            <Row className="mb-3">
              <Col className="d-flex align-items-end gap-2">
                <Form.Group className="flex-grow-1">
                  <Form.Label className="text-white-50 small">Filter by Network Range</Form.Label>
                  <InputGroup>
                    <InputGroup.Text>
                      <i className="bi bi-search" />
                    </InputGroup.Text>
                    <Form.Control
                      type="text"
                      placeholder="Search network ranges..."
                      value={filters.networkRange}
                      onChange={(e) => handleFilterChange('networkRange', e.target.value)}
                      data-bs-theme="dark"
                    />
                  </InputGroup>
                </Form.Group>
                <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
                  Clear Filter
                </Button>
              </Col>
            </Row>

            <div className="d-flex mb-3" style={{ gap: '8px' }}>
              <Button
                variant="danger"
                size="sm"
                onClick={handleDeselectAll}
                disabled={selectedNetworkRanges.size === 0}
                style={{ flex: 1 }}
              >
                <FaTimes className="me-1" />
                De-Select All
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleSelectAll}
                disabled={filteredNetworkRanges.length === 0}
                style={{ flex: 1 }}
              >
                <FaCheck className="me-1" />
                Select All Filtered
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={selectAllFiltered}
                disabled={filteredNetworkRanges.length === 0}
                style={{ flex: 1 }}
              >
                <FaCheck className="me-1" />
                Select All Visible
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={deselectAllFiltered}
                disabled={selectedNetworkRanges.size === 0}
                style={{ flex: 1 }}
              >
                <FaTimes className="me-1" />
                Deselect All Visible
              </Button>
            </div>

            <div className="mb-3">
              <small className="text-white-50">
                Showing {filteredNetworkRanges.length} of {networkRangesToUse.length} network ranges
              </small>
            </div>

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
                        checked={filteredNetworkRanges.length > 0 && filteredNetworkRanges.every(item => {
                          const networkRange = typeof item === 'string' ? item : item.cidr_block;
                          return selectedNetworkRanges.has(networkRange);
                        })}
                        onChange={(e) => {
                          if (e.target.checked) {
                            handleSelectAll();
                          } else {
                            handleDeselectAll();
                          }
                        }}
                      />
                    </th>
                    <th style={{ backgroundColor: 'var(--bs-dark)' }}>Network Range</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredNetworkRanges.map((item, index) => {
                    const networkRange = typeof item === 'string' ? item : item.cidr_block;
                    const isSelected = selectedNetworkRanges.has(networkRange);
                    
                    return (
                      <tr 
                        key={index}
                        style={{
                          backgroundColor: isSelected 
                            ? 'rgba(220, 53, 69, 0.25)' 
                            : 'transparent',
                          cursor: 'pointer',
                          userSelect: 'none',
                          transition: 'background-color 0.15s ease-in-out'
                        }}
                        onMouseDown={(e) => handleMouseDown(networkRange, index, e)}
                        onMouseEnter={() => handleMouseEnter(networkRange, index)}
                      >
                        <td>
                          <Form.Check
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => handleNetworkRangeSelect(networkRange, index)}
                            onClick={(e) => e.stopPropagation()}
                          />
                        </td>
                        <td 
                          style={{ 
                            fontFamily: 'monospace',
                            fontSize: '0.875rem'
                          }}
                        >
                          {networkRange}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>
            </div>

            {filteredNetworkRanges.length === 0 && (
              <div className="text-center py-4">
                <i className="bi bi-funnel text-white-50" style={{ fontSize: '2rem' }} />
                <h6 className="text-white-50 mt-2">No network ranges match the current filters</h6>
                <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
                  Clear Filters
                </Button>
              </div>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <div className="d-flex justify-content-between align-items-center w-100">
          <div className="text-white-50 small">
            {selectedNetworkRanges.size > 0 && (
              <>
                <i className="bi bi-clock me-1" />
                Estimated scan time: {estimatedTime === 1 ? '~2 hours' : `~${estimatedTime} hours`}
              </>
            )}
          </div>
          <div>
            <Button variant="secondary" onClick={handleCloseModal} className="me-2">
              Cancel
            </Button>
            <Button 
              variant="danger" 
              onClick={handleSaveConfig}
              disabled={saving || selectedNetworkRanges.size === 0}
            >
              {saving ? (
                <>
                  <Spinner animation="border" size="sm" className="me-2" />
                  Saving...
                </>
              ) : (
                <>
                  <i className="bi bi-save me-2" />
                  Save Configuration ({selectedNetworkRanges.size} ranges)
                </>
              )}
            </Button>
          </div>
        </div>
      </Modal.Footer>
    </Modal>
  );
};

export default AmassIntelConfigModal; 