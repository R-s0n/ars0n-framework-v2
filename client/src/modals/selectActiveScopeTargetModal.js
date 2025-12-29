import { Modal, Button, Form, Table, Badge, InputGroup, ButtonGroup } from 'react-bootstrap';
import { useState, useMemo } from 'react';
import { FaSearch, FaTrash, FaCheckCircle, FaTimes, FaExclamationTriangle } from 'react-icons/fa';

function SelectActiveScopeTargetModal({
  showActiveModal,
  handleActiveModalClose,
  scopeTargets,
  activeTarget,
  handleActiveSelect,
  handleDelete,
}) {
  const [selectedTargets, setSelectedTargets] = useState(new Set());
  const [searchTerm, setSearchTerm] = useState('');
  const [sortColumn, setSortColumn] = useState('scope_target');
  const [sortDirection, setSortDirection] = useState('asc');
  const [filterType, setFilterType] = useState('all');
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [targetsToDelete, setTargetsToDelete] = useState([]);

  const handleSort = (column) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  const renderSortIcon = (column) => {
    if (sortColumn !== column) {
      return <i className="bi bi-arrow-down-up text-muted ms-1"></i>;
    }
    return sortDirection === 'asc' ? 
      <i className="bi bi-arrow-up text-danger ms-1"></i> : 
      <i className="bi bi-arrow-down text-danger ms-1"></i>;
  };

  const filteredAndSortedTargets = useMemo(() => {
    let filtered = scopeTargets.filter(target => {
      const matchesSearch = target.scope_target.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesType = filterType === 'all' || target.type === filterType;
      return matchesSearch && matchesType;
    });

    filtered.sort((a, b) => {
      let aVal, bVal;
      
      if (sortColumn === 'scope_target') {
        aVal = a.scope_target.toLowerCase();
        bVal = b.scope_target.toLowerCase();
      } else if (sortColumn === 'type') {
        aVal = a.type;
        bVal = b.type;
      } else if (sortColumn === 'mode') {
        aVal = a.mode || '';
        bVal = b.mode || '';
      }
      
      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    return filtered;
  }, [scopeTargets, searchTerm, filterType, sortColumn, sortDirection]);

  const toggleTargetSelection = (targetId) => {
    setSelectedTargets(prev => {
      const newSet = new Set(prev);
      if (newSet.has(targetId)) {
        newSet.delete(targetId);
      } else {
        newSet.add(targetId);
      }
      return newSet;
    });
  };

  const toggleAllTargets = () => {
    if (selectedTargets.size === filteredAndSortedTargets.length && filteredAndSortedTargets.length > 0) {
      setSelectedTargets(new Set());
    } else {
      setSelectedTargets(new Set(filteredAndSortedTargets.map(t => t.id)));
    }
  };

  const handleBulkDelete = () => {
    if (selectedTargets.size === 0) return;
    
    const targets = scopeTargets.filter(t => selectedTargets.has(t.id));
    setTargetsToDelete(targets);
    setShowDeleteConfirm(true);
  };

  const confirmDelete = () => {
    targetsToDelete.forEach(target => {
      handleDelete(target.id);
    });
    setSelectedTargets(new Set());
    setShowDeleteConfirm(false);
    setTargetsToDelete([]);
  };

  const cancelDelete = () => {
    setShowDeleteConfirm(false);
    setTargetsToDelete([]);
  };

  const handleSelectAndClose = () => {
    if (selectedTargets.size === 1) {
      const targetId = Array.from(selectedTargets)[0];
      const target = scopeTargets.find(t => t.id === targetId);
      if (target) {
        handleActiveSelect(target);
      }
    }
    handleActiveModalClose();
  };

  const handleRowClick = (target) => {
    handleActiveSelect(target);
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'Company':
        return '/images/Company.png';
      case 'Wildcard':
        return '/images/Wildcard.png';
      case 'URL':
        return '/images/URL.png';
      default:
        return null;
    }
  };

  return (
    <>
      <style>
        {`
          .form-check-input:checked {
            background-color: #dc3545 !important;
            border-color: #dc3545 !important;
          }
        `}
      </style>

      <Modal data-bs-theme="dark" show={showActiveModal} onHide={handleActiveModalClose} size="xl">
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">
            <FaCheckCircle className="me-2" />
            Manage Scope Targets
          </Modal.Title>
        </Modal.Header>
      <Modal.Body>
        <div className="mb-3">
          <div className="row g-2">
            <div className="col-md-6">
              <InputGroup>
                <InputGroup.Text>
                  <FaSearch />
                </InputGroup.Text>
                <Form.Control
                  type="text"
                  placeholder="Search scope targets..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                {searchTerm && (
                  <Button 
                    variant="outline-secondary" 
                    onClick={() => setSearchTerm('')}
                  >
                    <FaTimes />
                  </Button>
                )}
              </InputGroup>
            </div>
            <div className="col-md-6">
              <ButtonGroup className="w-100">
                <Button
                  variant={filterType === 'all' ? 'danger' : 'outline-danger'}
                  onClick={() => setFilterType('all')}
                >
                  All ({scopeTargets.length})
                </Button>
                <Button
                  variant={filterType === 'Company' ? 'danger' : 'outline-danger'}
                  onClick={() => setFilterType('Company')}
                >
                  Company ({scopeTargets.filter(t => t.type === 'Company').length})
                </Button>
                <Button
                  variant={filterType === 'Wildcard' ? 'danger' : 'outline-danger'}
                  onClick={() => setFilterType('Wildcard')}
                >
                  Wildcard ({scopeTargets.filter(t => t.type === 'Wildcard').length})
                </Button>
                <Button
                  variant={filterType === 'URL' ? 'danger' : 'outline-danger'}
                  onClick={() => setFilterType('URL')}
                >
                  URL ({scopeTargets.filter(t => t.type === 'URL').length})
                </Button>
              </ButtonGroup>
            </div>
          </div>
        </div>

        <div className="mb-3 d-flex justify-content-between align-items-center">
          <div className="text-white">
            <strong>{filteredAndSortedTargets.length}</strong> target{filteredAndSortedTargets.length !== 1 ? 's' : ''} shown
            {selectedTargets.size > 0 && (
              <span className="ms-2">
                | <strong>{selectedTargets.size}</strong> selected
              </span>
            )}
          </div>
          <div className="d-flex gap-2">
            {selectedTargets.size > 0 && (
              <Button 
                variant="outline-danger" 
                size="sm"
                onClick={handleBulkDelete}
              >
                <FaTrash className="me-1" />
                Delete {selectedTargets.size} Selected
              </Button>
            )}
            <Button 
              variant="outline-secondary" 
              size="sm"
              onClick={toggleAllTargets}
            >
              {selectedTargets.size === filteredAndSortedTargets.length && filteredAndSortedTargets.length > 0 ? 'Deselect All' : 'Select All'}
            </Button>
          </div>
        </div>

        <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
          <Table striped bordered hover variant="dark" size="sm">
            <thead style={{ position: 'sticky', top: 0, backgroundColor: '#212529', zIndex: 1 }}>
              <tr>
                <th style={{ width: '50px' }}>
                  <Form.Check
                    type="checkbox"
                    checked={selectedTargets.size === filteredAndSortedTargets.length && filteredAndSortedTargets.length > 0}
                    onChange={toggleAllTargets}
                  />
                </th>
                <th style={{ width: '60px' }}>Active</th>
                <th style={{ width: '120px', cursor: 'pointer' }} onClick={() => handleSort('type')}>
                  Type {renderSortIcon('type')}
                </th>
                <th style={{ cursor: 'pointer' }} onClick={() => handleSort('scope_target')}>
                  Scope Target {renderSortIcon('scope_target')}
                </th>
                <th style={{ width: '100px', cursor: 'pointer' }} onClick={() => handleSort('mode')}>
                  Mode {renderSortIcon('mode')}
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredAndSortedTargets.length === 0 ? (
                <tr>
                  <td colSpan="5" className="text-center text-muted py-4">
                    {searchTerm || filterType !== 'all' ? 'No scope targets match your filters' : 'No scope targets available'}
                  </td>
                </tr>
              ) : (
                filteredAndSortedTargets.map((target) => (
                  <tr 
                    key={target.id}
                    style={{ cursor: 'pointer' }}
                    className={activeTarget?.id === target.id ? 'table-danger' : ''}
                  >
                    <td onClick={(e) => e.stopPropagation()}>
                      <Form.Check
                        type="checkbox"
                        checked={selectedTargets.has(target.id)}
                        onChange={() => toggleTargetSelection(target.id)}
                      />
                    </td>
                    <td className="text-center" onClick={() => handleRowClick(target)}>
                      {activeTarget?.id === target.id && (
                        <Badge bg="danger">
                          <FaCheckCircle />
                        </Badge>
                      )}
                    </td>
                    <td onClick={() => handleRowClick(target)}>
                      <div className="d-flex align-items-center">
                        {getTypeIcon(target.type) && (
                          <img 
                            src={getTypeIcon(target.type)} 
                            alt={target.type} 
                            style={{ width: '20px', height: '20px', marginRight: '8px' }}
                          />
                        )}
                        <span>{target.type}</span>
                      </div>
                    </td>
                    <td className="font-monospace small" onClick={() => handleRowClick(target)}>
                      {target.scope_target}
                    </td>
                    <td onClick={() => handleRowClick(target)}>
                      <Badge bg={target.mode === 'Active' ? 'success' : 'secondary'}>
                        {target.mode || 'Passive'}
                      </Badge>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </Table>
        </div>

        {filteredAndSortedTargets.length > 0 && (
          <div className="mt-2 text-muted small">
            Tip: Click on a row to set it as active, or use checkboxes for bulk operations
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <div className="d-flex justify-content-between w-100">
          <div>
            {selectedTargets.size > 0 && (
              <Button 
                variant="danger" 
                onClick={handleBulkDelete}
              >
                <FaTrash className="me-2" />
                Delete {selectedTargets.size} Selected
              </Button>
            )}
          </div>
          <div className="d-flex gap-2">
            <Button variant="secondary" onClick={handleActiveModalClose}>
              Close
            </Button>
            {activeTarget && (
              <Button variant="danger" onClick={handleActiveModalClose}>
                Continue with {activeTarget.scope_target}
              </Button>
            )}
          </div>
        </div>
      </Modal.Footer>
    </Modal>

    <Modal 
      data-bs-theme="dark" 
      show={showDeleteConfirm} 
      onHide={cancelDelete} 
      centered
      size="md"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <FaExclamationTriangle className="me-2" />
          Confirm Delete
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="text-white">
          <p className="mb-3">
            Are you sure you want to delete <strong>{targetsToDelete.length}</strong> scope target{targetsToDelete.length !== 1 ? 's' : ''}?
          </p>
          
          {targetsToDelete.length > 0 && targetsToDelete.length <= 5 && (
            <div className="mb-3">
              <strong>Targets to be deleted:</strong>
              <ul className="mt-2">
                {targetsToDelete.map(target => (
                  <li key={target.id} className="font-monospace small">
                    {target.scope_target}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {targetsToDelete.length > 5 && (
            <div className="mb-3">
              <strong>First 5 targets to be deleted:</strong>
              <ul className="mt-2">
                {targetsToDelete.slice(0, 5).map(target => (
                  <li key={target.id} className="font-monospace small">
                    {target.scope_target}
                  </li>
                ))}
                <li className="text-muted">
                  ... and {targetsToDelete.length - 5} more
                </li>
              </ul>
            </div>
          )}

          <div className="alert alert-warning mb-0">
            <small>
              <FaExclamationTriangle className="me-2" />
              This action cannot be undone.
            </small>
          </div>
        </div>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={cancelDelete}>
          Cancel
        </Button>
        <Button variant="danger" onClick={confirmDelete}>
          <FaTrash className="me-2" />
          Delete {targetsToDelete.length} Target{targetsToDelete.length !== 1 ? 's' : ''}
        </Button>
      </Modal.Footer>
    </Modal>
    </>
  );
}

export default SelectActiveScopeTargetModal;
