import { Modal, Button, Form, Spinner, Alert, Card, Tabs, Tab, ButtonGroup, Badge, Table } from 'react-bootstrap';
import { useState, useRef } from 'react';
import { FaArrowLeft, FaFileUpload, FaCheckCircle, FaExclamationTriangle, FaFile, FaTimes } from 'react-icons/fa';

function ConfigUploadModal({ show, handleClose, onSuccess, showBackButton, onBackClick }) {
  const [activeTab, setActiveTab] = useState('hackerone');
  const [fileType, setFileType] = useState('burp');
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [error, setError] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [parsedTargets, setParsedTargets] = useState([]);
  const [selectedTargets, setSelectedTargets] = useState(new Set());
  const fileInputRef = useRef(null);

  const COMMON_TLDS = ['com', 'net', 'org', 'io', 'app'];

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    handleFileSelection(file);
  };

  const handleFileSelection = (file) => {
    setError('');
    setUploadResult(null);
    
    if (file) {
      if (fileType === 'burp' && !file.name.endsWith('.json')) {
        setError('Invalid file type. Please select a JSON file for Burp configuration.');
        setSelectedFile(null);
        return;
      }
      
      if (fileType === 'csv' && !file.name.endsWith('.csv')) {
        setError('Invalid file type. Please select a CSV file.');
        setSelectedFile(null);
        return;
      }
      
      if (file.size > 50 * 1024 * 1024) {
        setError('File is too large. Maximum size is 50MB.');
        setSelectedFile(null);
        return;
      }
      
      setSelectedFile(file);
    }
  };

  const handleDragOver = (event) => {
    event.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (event) => {
    event.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragOver(false);
    
    const files = event.dataTransfer.files;
    if (files.length > 0) {
      handleFileSelection(files[0]);
    }
  };

  const expandTLDWildcard = (target) => {
    const expanded = [];
    
    if (target.type === 'Wildcard' && target.scope_target.endsWith('.*')) {
      const basePattern = target.scope_target.slice(0, -2);
      
      for (const tld of COMMON_TLDS) {
        expanded.push({
          ...target,
          scope_target: `${basePattern}.${tld}`,
          original: target.scope_target
        });
      }
    } else {
      expanded.push(target);
    }
    
    return expanded;
  };

  const parseBurpConfig = (jsonData) => {
    const scopeTargets = [];
    
    try {
      const include = jsonData?.target?.scope?.include || [];
      const seenHosts = new Set();
      
      for (const item of include) {
        if (!item.enabled || !item.host) continue;
        
        let host = item.host;
        host = host.replace(/^\^/, '').replace(/\$$/, '');
        host = host.replace(/\\\./g, '.');
        host = host.replace(/\.\*/g, '*');
        
        if (host.startsWith('.*\\.')) {
          host = '*.' + host.substring(4);
        }
        
        if (seenHosts.has(host)) continue;
        seenHosts.add(host);
        
        if (host.includes('*')) {
          const target = {
            type: 'Wildcard',
            scope_target: host,
            mode: 'Passive',
            active: false
          };
          
          const expandedTargets = expandTLDWildcard(target);
          scopeTargets.push(...expandedTargets);
        } else {
          const protocol = item.protocol || 'https';
          const port = item.port?.replace(/^\^/, '').replace(/\$$/, '') || '443';
          
          let url = `${protocol}://${host}`;
          if ((protocol === 'http' && port !== '80') || (protocol === 'https' && port !== '443')) {
            url += `:${port}`;
          }
          
          scopeTargets.push({
            type: 'URL',
            scope_target: url,
            mode: 'Passive',
            active: false
          });
        }
      }
    } catch (err) {
      throw new Error(`Failed to parse Burp configuration: ${err.message}`);
    }
    
    return scopeTargets;
  };

  const parseCSV = (csvText) => {
    const scopeTargets = [];
    
    try {
      const lines = csvText.split('\n');
      if (lines.length < 2) {
        throw new Error('CSV file is empty or invalid');
      }
      
      const headers = lines[0].split(',').map(h => h.trim());
      const identifierIndex = headers.indexOf('identifier');
      const assetTypeIndex = headers.indexOf('asset_type');
      
      if (identifierIndex === -1 || assetTypeIndex === -1) {
        throw new Error('CSV must contain "identifier" and "asset_type" columns');
      }
      
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        
        const columns = line.split(',');
        if (columns.length <= Math.max(identifierIndex, assetTypeIndex)) continue;
        
        const identifier = columns[identifierIndex].trim();
        const assetType = columns[assetTypeIndex].trim();
        
        if (!identifier || !assetType) continue;
        
        if (assetType === 'WILDCARD') {
          const target = {
            type: 'Wildcard',
            scope_target: identifier,
            mode: 'Passive',
            active: false
          };
          
          const expandedTargets = expandTLDWildcard(target);
          scopeTargets.push(...expandedTargets);
        } else if (assetType === 'URL') {
          scopeTargets.push({
            type: 'URL',
            scope_target: identifier,
            mode: 'Passive',
            active: false
          });
        }
      }
    } catch (err) {
      throw new Error(`Failed to parse CSV: ${err.message}`);
    }
    
    return scopeTargets;
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setError('Please select a file to upload.');
      return;
    }

    setIsUploading(true);
    setError('');
    setUploadResult(null);

    try {
      const fileContent = await selectedFile.text();
      let scopeTargets = [];

      if (fileType === 'burp') {
        const jsonData = JSON.parse(fileContent);
        scopeTargets = parseBurpConfig(jsonData);
      } else if (fileType === 'csv') {
        scopeTargets = parseCSV(fileContent);
      }

      if (scopeTargets.length === 0) {
        throw new Error('No valid scope targets found in the file');
      }

      const targetsWithIds = scopeTargets.map((target, idx) => ({
        ...target,
        id: `target-${idx}`
      }));

      setParsedTargets(targetsWithIds);
      setSelectedTargets(new Set(targetsWithIds.map(t => t.id)));
      setShowConfirmation(true);

    } catch (err) {
      console.error('Upload failed:', err);
      setError(`Upload failed: ${err.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const handleConfirmImport = async () => {
    setIsUploading(true);
    setError('');
    setUploadResult(null);

    try {
      const targetsToImport = parsedTargets.filter(t => selectedTargets.has(t.id));

      if (targetsToImport.length === 0) {
        throw new Error('No targets selected for import');
      }

      let successCount = 0;
      let failCount = 0;
      const errors = [];

      for (const target of targetsToImport) {
        try {
          const { id, original, ...targetData } = target;
          
          const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/add`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(targetData),
          });

          if (response.ok) {
            successCount++;
          } else {
            failCount++;
            const errorText = await response.text();
            errors.push(`${target.scope_target}: ${errorText}`);
          }
        } catch (err) {
          failCount++;
          errors.push(`${target.scope_target}: ${err.message}`);
        }
      }

      setUploadResult({
        total: targetsToImport.length,
        success: successCount,
        failed: failCount,
        errors: errors.slice(0, 5)
      });

      setShowConfirmation(false);
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }

      if (onSuccess && typeof onSuccess === 'function') {
        onSuccess({ imported_targets: successCount });
      }

    } catch (err) {
      console.error('Import failed:', err);
      setError(`Import failed: ${err.message}`);
    } finally {
      setIsUploading(false);
    }
  };

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
    if (selectedTargets.size === parsedTargets.length) {
      setSelectedTargets(new Set());
    } else {
      setSelectedTargets(new Set(parsedTargets.map(t => t.id)));
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setError('');
    setUploadResult(null);
    setIsDragOver(false);
    setShowConfirmation(false);
    setParsedTargets([]);
    setSelectedTargets(new Set());
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleModalClose = () => {
    handleReset();
    setActiveTab('hackerone');
    setFileType('burp');
    handleClose();
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const renderUnderConstruction = (platform) => (
    <div className="text-center py-5">
      <div className="mb-4">
        <i className="bi bi-cone-striped text-warning" style={{ fontSize: '80px' }}></i>
      </div>
      <h4 className="text-white mb-3">Under Construction</h4>
      <p className="text-white-50 mb-0">
        {platform} integration is coming soon! Stay tuned for updates.
      </p>
    </div>
  );

  const renderConfirmationView = () => (
    <>
      <Alert variant="info">
        <FaCheckCircle className="me-2" />
        <strong>Review Scope Targets</strong>
        <p className="mb-0 mt-2 small">
          {parsedTargets.length} target{parsedTargets.length !== 1 ? 's' : ''} found. 
          Review and uncheck any you don't want to import.
          {parsedTargets.some(t => t.original) && (
            <span className="d-block mt-1 text-warning">
              <i className="bi bi-info-circle me-1"></i>
              TLD wildcards (*.domain.*) have been expanded to common TLDs: {COMMON_TLDS.join(', ')}
            </span>
          )}
        </p>
      </Alert>

      <div className="mb-3 d-flex justify-content-between align-items-center">
        <div className="text-white">
          <strong>{selectedTargets.size}</strong> of <strong>{parsedTargets.length}</strong> selected
        </div>
        <Button 
          variant="outline-danger" 
          size="sm"
          onClick={toggleAllTargets}
        >
          {selectedTargets.size === parsedTargets.length ? 'Deselect All' : 'Select All'}
        </Button>
      </div>

      <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
        <Table striped bordered hover variant="dark" size="sm">
          <thead style={{ position: 'sticky', top: 0, backgroundColor: '#212529', zIndex: 1 }}>
            <tr>
              <th style={{ width: '50px' }}>
                <Form.Check
                  type="checkbox"
                  checked={selectedTargets.size === parsedTargets.length && parsedTargets.length > 0}
                  onChange={toggleAllTargets}
                />
              </th>
              <th>Type</th>
              <th>Scope Target</th>
              <th style={{ width: '80px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {parsedTargets.map((target) => (
              <tr key={target.id}>
                <td>
                  <Form.Check
                    type="checkbox"
                    checked={selectedTargets.has(target.id)}
                    onChange={() => toggleTargetSelection(target.id)}
                  />
                </td>
                <td>
                  <Badge bg={target.type === 'Wildcard' ? 'warning' : 'info'}>
                    {target.type}
                  </Badge>
                  {target.original && (
                    <Badge bg="secondary" className="ms-1" title={`Expanded from ${target.original}`}>
                      <i className="bi bi-arrow-down-up"></i>
                    </Badge>
                  )}
                </td>
                <td className="font-monospace small">{target.scope_target}</td>
                <td>
                  <Button
                    variant="link"
                    size="sm"
                    className="text-danger p-0"
                    onClick={() => toggleTargetSelection(target.id)}
                    title={selectedTargets.has(target.id) ? 'Deselect' : 'Select'}
                  >
                    {selectedTargets.has(target.id) ? <FaTimes /> : <FaCheckCircle />}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </div>
    </>
  );

  const renderHackerOneTab = () => (
    <>
      {error && (
        <Alert variant="danger" dismissible onClose={() => setError('')}>
          <FaExclamationTriangle className="me-2" />
          {error}
        </Alert>
      )}

      {uploadResult && (
        <Alert variant={uploadResult.failed > 0 ? 'warning' : 'success'} dismissible onClose={() => setUploadResult(null)}>
          <FaCheckCircle className="me-2" />
          <strong>Import Complete!</strong>
          <ul className="mt-2 mb-0">
            <li>Total targets processed: {uploadResult.total}</li>
            <li>Successfully imported: {uploadResult.success}</li>
            {uploadResult.failed > 0 && <li>Failed: {uploadResult.failed}</li>}
          </ul>
          {uploadResult.errors.length > 0 && (
            <div className="mt-2">
              <small>First few errors:</small>
              <ul className="mb-0">
                {uploadResult.errors.map((err, idx) => (
                  <li key={idx}><small>{err}</small></li>
                ))}
              </ul>
            </div>
          )}
        </Alert>
      )}

      {showConfirmation ? renderConfirmationView() : (
      <>
        <div className="mb-4">
          <h6 className="text-white mb-2">
            <FaFileUpload className="me-2" />
            HackerOne Scope Import
          </h6>
          <p className="text-white-50 small mb-3">
            Import scope targets from HackerOne using either a Burp Suite configuration file 
            or a CSV export from the platform.
          </p>
          
          <div className="mb-3">
            <ButtonGroup className="w-100">
              <Button
                variant={fileType === 'burp' ? 'danger' : 'outline-danger'}
                onClick={() => { setFileType('burp'); handleReset(); }}
                className="d-flex align-items-center justify-content-center"
              >
                <FaFile className="me-2" />
                Burp Configuration (JSON)
              </Button>
              <Button
                variant={fileType === 'csv' ? 'danger' : 'outline-danger'}
                onClick={() => { setFileType('csv'); handleReset(); }}
                className="d-flex align-items-center justify-content-center"
              >
                <FaFile className="me-2" />
                CSV Export
              </Button>
            </ButtonGroup>
          </div>
        </div>

        <Card 
          className={`mb-4 border-2 ${isDragOver ? 'border-danger bg-danger bg-opacity-10' : selectedFile ? 'border-success' : 'border-dashed border-secondary'}`}
          style={{ 
            cursor: 'pointer',
            transition: 'all 0.2s ease-in-out',
            borderStyle: selectedFile ? 'solid' : 'dashed'
          }}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <Card.Body className="text-center py-5">
            {selectedFile ? (
              <div>
                <FaCheckCircle className="text-success mb-3" size={48} />
                <h5 className="text-white mb-2">{selectedFile.name}</h5>
                <p className="text-white-50 mb-2">
                  Size: {formatFileSize(selectedFile.size)}
                </p>
                <Badge bg="success" className="p-2">
                  <FaFileUpload className="me-1" />
                  Ready to Upload
                </Badge>
              </div>
            ) : (
              <div>
                <FaFileUpload className={`mb-3 ${isDragOver ? 'text-danger' : 'text-white-50'}`} size={48} />
                <h5 className={`mb-2 ${isDragOver ? 'text-danger' : 'text-white'}`}>
                  {isDragOver ? `Drop your ${fileType === 'burp' ? 'JSON' : 'CSV'} file here` : `Select or drag a ${fileType === 'burp' ? 'JSON' : 'CSV'} file`}
                </h5>
                <p className="text-white-50 mb-0">
                  Click here or drag and drop your {fileType === 'burp' ? 'Burp configuration' : 'CSV export'} file
                </p>
              </div>
            )}
          </Card.Body>
        </Card>

        <Form.Control
          ref={fileInputRef}
          type="file"
          accept={fileType === 'burp' ? '.json' : '.csv'}
          onChange={handleFileSelect}
          style={{ display: 'none' }}
        />

        <Card className="bg-dark border-secondary">
          <Card.Body className="py-3">
            <h6 className="text-white mb-2">File Requirements:</h6>
            {fileType === 'burp' ? (
              <ul className="text-white-50 small mb-0">
                <li>Must be a valid Burp Suite JSON configuration file</li>
                <li>File must contain target scope with include rules</li>
                <li>Maximum file size: 50MB</li>
                <li>Wildcard domains and specific URLs will be automatically detected</li>
              </ul>
            ) : (
              <ul className="text-white-50 small mb-0">
                <li>Must be a valid CSV file with header row</li>
                <li>Required columns: identifier, asset_type</li>
                <li>Maximum file size: 50MB</li>
                <li>asset_type should be either WILDCARD or URL</li>
              </ul>
            )}
          </Card.Body>
        </Card>
      </>
      )}
    </>
  );

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

      <Modal data-bs-theme="dark" show={show} onHide={handleModalClose} size="lg">
        <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          {showConfirmation ? (
            <>
              <FaCheckCircle className="me-2" />
              Review & Confirm Targets
            </>
          ) : (
            <>
              <FaFileUpload className="me-2" />
              Upload Configuration File
            </>
          )}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="mb-4"
          variant="pills"
        >
          <Tab eventKey="hackerone" title="HackerOne" className="pt-3">
            {renderHackerOneTab()}
          </Tab>
          <Tab eventKey="bugcrowd" title="Bugcrowd" className="pt-3">
            {renderUnderConstruction('Bugcrowd')}
          </Tab>
          <Tab eventKey="yeswehack" title="YesWeHack" className="pt-3">
            {renderUnderConstruction('YesWeHack')}
          </Tab>
          <Tab eventKey="intigriti" title="Intigriti" className="pt-3">
            {renderUnderConstruction('Intigriti')}
          </Tab>
        </Tabs>
      </Modal.Body>
      
      <Modal.Footer>
        <div className="d-flex justify-content-between w-100">
          <div className="d-flex gap-2">
            {showConfirmation && activeTab === 'hackerone' ? (
              <Button
                variant="outline-danger"
                onClick={() => {
                  setShowConfirmation(false);
                  setParsedTargets([]);
                  setSelectedTargets(new Set());
                }}
                disabled={isUploading}
              >
                <FaArrowLeft className="me-1" />
                Back to File Selection
              </Button>
            ) : (
              <>
                {showBackButton && (
                  <Button
                    variant="outline-danger"
                    onClick={onBackClick}
                    disabled={isUploading}
                  >
                    <FaArrowLeft className="me-1" />
                    Back
                  </Button>
                )}
                {selectedFile && activeTab === 'hackerone' && (
                  <Button variant="outline-light" onClick={handleReset} disabled={isUploading}>
                    Clear Selection
                  </Button>
                )}
              </>
            )}
          </div>
          <div className="d-flex gap-2">
            <Button variant="secondary" onClick={handleModalClose} disabled={isUploading}>
              Cancel
            </Button>
            {activeTab === 'hackerone' && (
              showConfirmation ? (
                <Button 
                  variant="danger" 
                  onClick={handleConfirmImport}
                  disabled={selectedTargets.size === 0 || isUploading}
                >
                  {isUploading ? (
                    <>
                      <Spinner
                        as="span"
                        animation="border"
                        size="sm"
                        role="status"
                        aria-hidden="true"
                        className="me-2"
                      />
                      Importing...
                    </>
                  ) : (
                    <>
                      <FaCheckCircle className="me-2" />
                      Import {selectedTargets.size} Target{selectedTargets.size !== 1 ? 's' : ''}
                    </>
                  )}
                </Button>
              ) : (
                <Button 
                  variant="danger" 
                  onClick={handleUpload}
                  disabled={!selectedFile || isUploading}
                >
                  {isUploading ? (
                    <>
                      <Spinner
                        as="span"
                        animation="border"
                        size="sm"
                        role="status"
                        aria-hidden="true"
                        className="me-2"
                      />
                      Processing...
                    </>
                  ) : (
                    <>
                      <FaFileUpload className="me-2" />
                      Parse & Review
                    </>
                  )}
                </Button>
              )
            )}
          </div>
        </div>
      </Modal.Footer>
    </Modal>
    </>
  );
}

export default ConfigUploadModal;

