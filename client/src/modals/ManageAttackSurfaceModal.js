import React, { useState, useEffect } from 'react';
import { Modal, Button, Form, Table, Nav, InputGroup, Spinner, Alert, Badge } from 'react-bootstrap';
import fetchAttackSurfaceAssets from '../utils/fetchAttackSurfaceAssets';

const ManageAttackSurfaceModal = ({ 
  show, 
  handleClose, 
  activeTarget,
  onAssetChange
}) => {
  const [attackSurfaceAssets, setAttackSurfaceAssets] = useState([]);
  const [filteredAssets, setFilteredAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('asn');
  const [newAssetInput, setNewAssetInput] = useState('');
  const [selectedAssets, setSelectedAssets] = useState(new Set());
  const [isAdding, setIsAdding] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [successMessage, setSuccessMessage] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');

  const assetTypes = [
    { key: 'asn', label: 'ASNs', placeholder: 'AS15169' },
    { key: 'network_range', label: 'Network Ranges', placeholder: '192.168.1.0/24' },
    { key: 'ip_address', label: 'IP Addresses', placeholder: '192.168.1.1' },
    { key: 'fqdn', label: 'Domain Names', placeholder: 'example.com' },
    { key: 'cloud_asset', label: 'Cloud Assets', placeholder: 's3.amazonaws.com/bucket-name' },
    { key: 'live_web_server', label: 'Live Web Servers', placeholder: 'https://example.com' }
  ];

  useEffect(() => {
    if (show && activeTarget) {
      loadAttackSurfaceAssets();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    filterAssetsByType();
  }, [attackSurfaceAssets, activeTab, searchTerm]);

  useEffect(() => {
    setSearchTerm('');
    setSelectedAssets(new Set());
  }, [activeTab]);

  const loadAttackSurfaceAssets = async () => {
    if (!activeTarget) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const data = await fetchAttackSurfaceAssets(activeTarget);
      setAttackSurfaceAssets(data.assets || []);
      setSelectedAssets(new Set());
    } catch (err) {
      setError('Failed to load attack surface assets');
      console.error('Error loading attack surface assets:', err);
    } finally {
      setLoading(false);
    }
  };

  const filterAssetsByType = () => {
    let filtered = attackSurfaceAssets.filter(asset => asset.asset_type === activeTab);
    
    if (searchTerm.trim()) {
      const search = searchTerm.toLowerCase();
      filtered = filtered.filter(asset => {
        const searchableText = [
          asset.asset_identifier,
          asset.asn_number,
          asset.asn_organization,
          asset.cidr_block,
          asset.ip_address,
          asset.fqdn,
          asset.url,
          asset.domain,
          asset.cloud_provider
        ].filter(Boolean).join(' ').toLowerCase();
        
        return searchableText.includes(search);
      });
    }
    
    setFilteredAssets(filtered);
  };

  const getAssetTypeCounts = () => {
    const counts = {};
    assetTypes.forEach(type => {
      counts[type.key] = attackSurfaceAssets.filter(asset => asset.asset_type === type.key).length;
    });
    return counts;
  };

  const handleAddAsset = async () => {
    if (!newAssetInput.trim() || !activeTarget) return;

    setIsAdding(true);
    setError(null);
    setSuccessMessage(null);

    const tempId = `temp-${Date.now()}`;
    const identifier = newAssetInput.trim();
    
    const optimisticAsset = {
      id: tempId,
      scope_target_id: activeTarget.id,
      asset_type: activeTab,
      asset_identifier: identifier,
      last_updated: new Date().toISOString(),
      ...(activeTab === 'asn' && { asn_number: identifier.replace('AS', '') }),
      ...(activeTab === 'network_range' && { cidr_block: identifier }),
      ...(activeTab === 'ip_address' && { ip_address: identifier }),
      ...(activeTab === 'fqdn' && { fqdn: identifier.toLowerCase() }),
      ...(activeTab === 'cloud_asset' && { domain: identifier.toLowerCase() }),
      ...(activeTab === 'live_web_server' && { 
        url: identifier.startsWith('http') ? identifier : `https://${identifier}` 
      })
    };

    setAttackSurfaceAssets(prev => [...prev, optimisticAsset]);
    setNewAssetInput('');

    try {
      const response = await fetch('/api/attack-surface-assets/add', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scope_target_id: activeTarget.id,
          asset_type: activeTab,
          asset_identifier: identifier
        }),
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(errorData || 'Failed to add asset');
      }

      const result = await response.json();
      
      setAttackSurfaceAssets(prev => 
        prev.map(asset => 
          asset.id === tempId 
            ? { ...asset, id: result.id } 
            : asset
        )
      );
      
      setSuccessMessage(`Asset added successfully`);
      setTimeout(() => setSuccessMessage(null), 3000);
      
      if (onAssetChange) {
        onAssetChange();
      }
    } catch (err) {
      setAttackSurfaceAssets(prev => prev.filter(asset => asset.id !== tempId));
      setError(`Failed to add asset: ${err.message}`);
      console.error('Error adding asset:', err);
      setTimeout(() => setError(null), 5000);
    } finally {
      setIsAdding(false);
    }
  };

  const handleDeleteAsset = async (assetId) => {
    if (!window.confirm('Are you sure you want to delete this asset?')) return;

    setIsDeleting(true);
    setError(null);
    setSuccessMessage(null);

    const assetToDelete = attackSurfaceAssets.find(a => a.id === assetId);
    setAttackSurfaceAssets(prev => prev.filter(asset => asset.id !== assetId));

    try {
      const response = await fetch(`/api/attack-surface-assets/${assetId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(errorData || 'Failed to delete asset');
      }

      setSuccessMessage('Asset deleted successfully');
      setTimeout(() => setSuccessMessage(null), 3000);
      
      if (onAssetChange) {
        onAssetChange();
      }
    } catch (err) {
      if (assetToDelete) {
        setAttackSurfaceAssets(prev => [...prev, assetToDelete]);
      }
      setError(`Failed to delete asset: ${err.message}`);
      console.error('Error deleting asset:', err);
      setTimeout(() => setError(null), 5000);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleDeleteSelected = async () => {
    if (selectedAssets.size === 0) return;
    
    if (!window.confirm(`Are you sure you want to delete ${selectedAssets.size} selected asset(s)?`)) return;

    setIsDeleting(true);
    setError(null);
    setSuccessMessage(null);

    const assetsToDelete = attackSurfaceAssets.filter(a => selectedAssets.has(a.id));
    const idsToDelete = Array.from(selectedAssets);
    
    setAttackSurfaceAssets(prev => prev.filter(asset => !selectedAssets.has(asset.id)));
    setSelectedAssets(new Set());

    try {
      const deletePromises = idsToDelete.map(assetId =>
        fetch(`/api/attack-surface-assets/${assetId}`, {
          method: 'DELETE',
        })
      );

      const results = await Promise.all(deletePromises);
      const failedDeletes = results.filter(r => !r.ok);

      if (failedDeletes.length > 0) {
        throw new Error(`Failed to delete ${failedDeletes.length} asset(s)`);
      }

      setSuccessMessage(`Successfully deleted ${idsToDelete.length} asset(s)`);
      setTimeout(() => setSuccessMessage(null), 3000);
      
      if (onAssetChange) {
        onAssetChange();
      }
    } catch (err) {
      setAttackSurfaceAssets(prev => [...prev, ...assetsToDelete]);
      setError(`Failed to delete selected assets: ${err.message}`);
      console.error('Error deleting selected assets:', err);
      setTimeout(() => setError(null), 5000);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleToggleAsset = (assetId) => {
    const newSelected = new Set(selectedAssets);
    if (newSelected.has(assetId)) {
      newSelected.delete(assetId);
    } else {
      newSelected.add(assetId);
    }
    setSelectedAssets(newSelected);
  };

  const handleSelectAll = () => {
    if (selectedAssets.size === filteredAssets.length) {
      setSelectedAssets(new Set());
    } else {
      setSelectedAssets(new Set(filteredAssets.map(asset => asset.id)));
    }
  };

  const handleSelectNone = () => {
    setSelectedAssets(new Set());
  };

  const renderAssetIdentifier = (asset) => {
    switch (asset.asset_type) {
      case 'asn':
        return (
          <div>
            <code>AS{asset.asn_number}</code>
            {asset.asn_organization && (
              <div className="small text-white-50">{asset.asn_organization}</div>
            )}
          </div>
        );
      case 'network_range':
        return <code>{asset.cidr_block}</code>;
      case 'ip_address':
        return <code>{asset.ip_address}</code>;
      case 'fqdn':
        return <code>{asset.fqdn}</code>;
      case 'cloud_asset':
        return <code className="text-info">{asset.asset_identifier}</code>;
      case 'live_web_server':
        return (
          <div>
            <a href={asset.url} target="_blank" rel="noopener noreferrer" className="text-info">
              {asset.url}
            </a>
            {asset.status_code && (
              <Badge variant={asset.status_code >= 200 && asset.status_code < 300 ? "success" : "warning"} className="ms-2">
                {asset.status_code}
              </Badge>
            )}
          </div>
        );
      default:
        return <code>{asset.asset_identifier}</code>;
    }
  };

  const getCurrentPlaceholder = () => {
    const type = assetTypes.find(t => t.key === activeTab);
    return type ? type.placeholder : '';
  };

  const counts = getAssetTypeCounts();

  return (
    <>
      <style>{`
        .modal-fullscreen .modal-dialog {
          max-width: 100vw !important;
          width: 100vw !important;
          height: 100vh !important;
          margin: 0 !important;
        }
        .modal-fullscreen .modal-content {
          height: 100vh !important;
          border-radius: 0 !important;
        }
        .modal-fullscreen .modal-body {
          overflow-y: auto !important;
          flex: 1 !important;
        }
        .nav-tabs .nav-link {
          color: #6c757d;
          border: none;
          border-bottom: 2px solid transparent;
          transition: all 0.2s ease;
        }
        .nav-tabs .nav-link:hover {
          color: #fff;
          border-bottom-color: #6c757d;
        }
        .nav-tabs .nav-link.active {
          color: #dc3545;
          border-bottom-color: #dc3545;
          background: transparent;
        }
        .nav-tabs {
          display: flex;
          width: 100%;
        }
        .nav-tabs .nav-item {
          flex: 1;
          text-align: center;
        }
        .nav-tabs .nav-link {
          width: 100%;
          text-align: center;
        }
        .table tbody tr {
          transition: opacity 0.2s ease;
        }
        .table tbody tr.deleting {
          opacity: 0.5;
        }
        @keyframes slideIn {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        .table tbody tr.new-item {
          animation: slideIn 0.3s ease;
        }
        .alert {
          animation: slideIn 0.3s ease;
        }
      `}</style>
      <Modal 
        show={show} 
        onHide={handleClose} 
        size="xl" 
        data-bs-theme="dark"
        dialogClassName="modal-fullscreen"
      >
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">Manage Attack Surface - {activeTarget?.scope_target}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {loading && (
            <div className="text-center py-4">
              <div className="spinner-border text-danger" role="status">
                <span className="visually-hidden">Loading...</span>
              </div>
              <p className="mt-2 text-white">Loading attack surface assets...</p>
            </div>
          )}

          {error && (
            <Alert variant="danger" dismissible onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {successMessage && (
            <Alert variant="success" dismissible onClose={() => setSuccessMessage(null)}>
              {successMessage}
            </Alert>
          )}

          {!loading && (
            <>
              <Nav variant="tabs" className="mb-4" activeKey={activeTab} onSelect={(k) => setActiveTab(k)}>
                {assetTypes.map((type) => {
                  const count = counts[type.key] || 0;
                  const badge = count > 0 ? (
                    <Badge bg="danger" className="ms-1">{count}</Badge>
                  ) : null;
                  
                  return (
                    <Nav.Item key={type.key}>
                      <Nav.Link eventKey={type.key}>
                        {type.label} {badge}
                      </Nav.Link>
                    </Nav.Item>
                  );
                })}
              </Nav>

              <div className="mb-4 p-3 bg-dark rounded border">
                <h6 className="text-white mb-3">
                  <i className="bi bi-plus-circle me-2"></i>
                  Add New Asset
                </h6>
                <InputGroup className="mb-2">
                  <Form.Control
                    type="text"
                    placeholder={getCurrentPlaceholder()}
                    value={newAssetInput}
                    onChange={(e) => setNewAssetInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter' && !isAdding && newAssetInput.trim()) {
                        handleAddAsset();
                      }
                    }}
                    data-bs-theme="dark"
                    disabled={isAdding}
                  />
                  <Button 
                    variant="success" 
                    onClick={handleAddAsset}
                    disabled={!newAssetInput.trim() || isAdding}
                  >
                    {isAdding ? (
                      <>
                        <Spinner animation="border" size="sm" className="me-2" />
                        Adding...
                      </>
                    ) : (
                      <>
                        <i className="bi bi-plus-lg me-2"></i>
                        Add
                      </>
                    )}
                  </Button>
                </InputGroup>
                <Form.Text className="text-white-50">
                  Enter the asset identifier and press Enter or click Add
                </Form.Text>
              </div>

              <div className="mb-3 p-3 bg-dark rounded border">
                <h6 className="text-white mb-3">
                  <i className="bi bi-search me-2"></i>
                  Search & Filter
                </h6>
                <InputGroup>
                  <InputGroup.Text className="bg-dark border-secondary">
                    <i className="bi bi-search text-white-50"></i>
                  </InputGroup.Text>
                  <Form.Control
                    type="text"
                    placeholder="Search assets..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    data-bs-theme="dark"
                  />
                  {searchTerm && (
                    <Button 
                      variant="outline-secondary" 
                      onClick={() => setSearchTerm('')}
                    >
                      <i className="bi bi-x-lg"></i>
                    </Button>
                  )}
                </InputGroup>
                {searchTerm && (
                  <Form.Text className="text-white-50">
                    Showing {filteredAssets.length} of {attackSurfaceAssets.filter(a => a.asset_type === activeTab).length} assets
                  </Form.Text>
                )}
              </div>

              {filteredAssets.length > 0 && (
                <>
                  <div className="mb-3 d-flex justify-content-between align-items-center">
                    <div>
                      <Button 
                        variant="outline-secondary" 
                        size="sm" 
                        onClick={handleSelectAll}
                        className="me-2"
                      >
                        {selectedAssets.size === filteredAssets.length ? 'Deselect All' : 'Select All'}
                      </Button>
                      <Button 
                        variant="outline-secondary" 
                        size="sm" 
                        onClick={handleSelectNone}
                        disabled={selectedAssets.size === 0}
                      >
                        Select None
                      </Button>
                    </div>
                    <div>
                      <Button 
                        variant="danger" 
                        size="sm" 
                        onClick={handleDeleteSelected}
                        disabled={selectedAssets.size === 0 || isDeleting}
                      >
                        {isDeleting ? (
                          <>
                            <Spinner animation="border" size="sm" className="me-2" />
                            Deleting...
                          </>
                        ) : (
                          <>
                            <i className="bi bi-trash me-2"></i>
                            Delete Selected ({selectedAssets.size})
                          </>
                        )}
                      </Button>
                    </div>
                  </div>

                  <div className="table-responsive" style={{ maxHeight: '50vh', overflowY: 'auto' }}>
                    <Table striped bordered hover variant="dark" style={{ tableLayout: 'fixed' }}>
                      <thead>
                        <tr>
                          <th style={{ width: '60px' }}>
                            <Form.Check
                              type="checkbox"
                              checked={selectedAssets.size === filteredAssets.length && filteredAssets.length > 0}
                              onChange={handleSelectAll}
                            />
                          </th>
                          <th style={{ width: 'auto' }}>Asset Identifier</th>
                          <th style={{ width: '200px' }}>Last Updated</th>
                          <th style={{ width: '100px' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredAssets.map((asset, index) => {
                          const isNew = asset.id && asset.id.toString().startsWith('temp-');
                          return (
                            <tr 
                              key={asset.id}
                              className={isNew ? 'new-item' : ''}
                            >
                              <td>
                                <Form.Check
                                  type="checkbox"
                                  checked={selectedAssets.has(asset.id)}
                                  onChange={() => handleToggleAsset(asset.id)}
                                  disabled={isNew}
                                />
                              </td>
                              <td style={{ wordBreak: 'break-all', overflowWrap: 'break-word' }}>
                                {renderAssetIdentifier(asset)}
                                {isNew && (
                                  <Spinner animation="border" size="sm" className="ms-2" variant="success" />
                                )}
                              </td>
                              <td style={{ whiteSpace: 'nowrap' }}>{new Date(asset.last_updated).toLocaleString()}</td>
                              <td className="text-center">
                                <Button
                                  variant="outline-danger"
                                  size="sm"
                                  onClick={() => handleDeleteAsset(asset.id)}
                                  disabled={isDeleting || isNew}
                                >
                                  <i className="bi bi-trash"></i>
                                </Button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </Table>
                  </div>
                </>
              )}

              {filteredAssets.length === 0 && !loading && (
                <div className="text-center py-4">
                  <i className="bi bi-inbox text-white-50" style={{ fontSize: '3rem' }}></i>
                  <p className="text-white-50 mt-3">
                    {searchTerm 
                      ? `No assets match "${searchTerm}". Try a different search term.`
                      : 'No assets found for this type. Add one above to get started.'
                    }
                  </p>
                  {searchTerm && (
                    <Button 
                      variant="outline-secondary" 
                      size="sm"
                      onClick={() => setSearchTerm('')}
                    >
                      Clear Search
                    </Button>
                  )}
                </div>
              )}
            </>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="outline-secondary" onClick={handleClose}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </>
  );
};

export default ManageAttackSurfaceModal;
