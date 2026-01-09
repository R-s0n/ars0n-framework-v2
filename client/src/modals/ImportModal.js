import { Modal, Button, Form, Spinner, Alert, Card, Badge, ButtonGroup } from 'react-bootstrap';
import { useState, useRef } from 'react';
import { FaUpload, FaFileImport, FaDatabase, FaCheckCircle, FaExclamationTriangle, FaArrowLeft, FaLink, FaFile } from 'react-icons/fa';

function ImportModal({ show, handleClose, onSuccess, showBackButton, onBackClick }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [importUrl, setImportUrl] = useState('');
  const [importMethod, setImportMethod] = useState('file'); // 'file' or 'url'
  const [isImporting, setIsImporting] = useState(false);
  const [importResult, setImportResult] = useState(null);
  const [error, setError] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    handleFileSelection(file);
  };

  const handleFileSelection = (file) => {
    setError('');
    setImportResult(null);
    
    if (file) {
      if (!file.name.endsWith('.rs0n')) {
        setError('Invalid file type. Please select a .rs0n file.');
        setSelectedFile(null);
        return;
      }
      
      if (file.size > 500 * 1024 * 1024) { // 500MB limit
        setError('File is too large. Maximum size is 500MB.');
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

  const handleImport = async () => {
    if (importMethod === 'file' && !selectedFile) {
      setError('Please select a file to import.');
      return;
    }

    if (importMethod === 'url' && !importUrl.trim()) {
      setError('Please enter a URL to import.');
      return;
    }

    if (importMethod === 'url' && !isValidUrl(importUrl.trim())) {
      setError('Please enter a valid URL.');
      return;
    }

    setIsImporting(true);
    setError('');
    setImportResult(null);

    try {
      let response;
      
      if (importMethod === 'file') {
        const formData = new FormData();
        formData.append('file', selectedFile);

        response = await fetch(`/api/api/database-import`, {
          method: 'POST',
          body: formData
        });
      } else {
        response = await fetch(`/api/api/database-import-url`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url: importUrl.trim() })
        });
      }

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Import failed: ${errorText}`);
      }

      const result = await response.json();
      setImportResult(result);
      setSelectedFile(null);
      setImportUrl('');
      
      // Reset file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      
      // Call success callback if provided
      if (onSuccess && typeof onSuccess === 'function') {
        onSuccess(result);
      }
      
    } catch (error) {
      console.error('Import failed:', error);
      setError(`Import failed: ${error.message}`);
    } finally {
      setIsImporting(false);
    }
  };

  const isValidUrl = (string) => {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setImportUrl('');
    setError('');
    setImportResult(null);
    setIsDragOver(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleModalClose = () => {
    handleReset();
    handleClose();
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleModalClose} size="lg">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <FaFileImport className="me-2" />
          Import Database
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            <FaExclamationTriangle className="me-2" />
            {error}
          </Alert>
        )}

        {importResult && (
          <Alert variant="success" dismissible onClose={() => setImportResult(null)}>
            <FaCheckCircle className="me-2" />
            <strong>Import Successful!</strong>
            <ul className="mt-2 mb-0">
              <li>Imported {importResult.imported_scope_targets} scope targets</li>
              <li>Processed {importResult.imported_tables} database tables</li>
              <li>Total records imported: {importResult.total_records}</li>
            </ul>
          </Alert>
        )}

        <div className="mb-4">
          <h6 className="text-white mb-2">
            <FaDatabase className="me-2" />
            Database Import
          </h6>
          <p className="text-white-50 small mb-3">
            Import a previously exported .rs0n database file to restore scope targets and all associated data. 
            This will merge the data with existing records, updating any conflicts.
          </p>
          
          {/* Import Method Toggle */}
          <div className="mb-3">
            <ButtonGroup className="w-100">
              <Button
                variant={importMethod === 'file' ? 'danger' : 'outline-danger'}
                onClick={() => setImportMethod('file')}
                className="d-flex align-items-center justify-content-center"
              >
                <FaFile className="me-2" />
                Upload File
              </Button>
              <Button
                variant={importMethod === 'url' ? 'danger' : 'outline-danger'}
                onClick={() => setImportMethod('url')}
                className="d-flex align-items-center justify-content-center"
              >
                <FaLink className="me-2" />
                Import from URL
              </Button>
            </ButtonGroup>
          </div>
        </div>

        {/* File Upload Area */}
        {importMethod === 'file' && (
          <>
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
                      <FaFileImport className="me-1" />
                      Ready to Import
                    </Badge>
                  </div>
                ) : (
                  <div>
                    <FaUpload className={`mb-3 ${isDragOver ? 'text-danger' : 'text-white-50'}`} size={48} />
                    <h5 className={`mb-2 ${isDragOver ? 'text-danger' : 'text-white'}`}>
                      {isDragOver ? 'Drop your .rs0n file here' : 'Select or drag a .rs0n file'}
                    </h5>
                    <p className="text-white-50 mb-0">
                      Click here or drag and drop your exported .rs0n database file
                    </p>
                  </div>
                )}
              </Card.Body>
            </Card>

            <Form.Control
              ref={fileInputRef}
              type="file"
              accept=".rs0n"
              onChange={handleFileSelect}
              style={{ display: 'none' }}
            />
          </>
        )}

        {/* URL Input Area */}
        {importMethod === 'url' && (
          <Card className="mb-4 border-2 border-dashed border-secondary">
            <Card.Body className="py-4">
              <div className="text-center mb-3">
                <FaLink className="text-white-50 mb-3" size={48} />
                <h5 className="text-white mb-2">Import from URL</h5>
                <p className="text-white-50 mb-3">
                  Enter the URL of a .rs0n database file to import
                </p>
              </div>
              
              <Form.Group>
                <Form.Label className="text-white">Database File URL</Form.Label>
                <Form.Control
                  type="url"
                  placeholder="https://example.com/database.rs0n"
                  value={importUrl}
                  onChange={(e) => setImportUrl(e.target.value)}
                  className="mb-3"
                />
              </Form.Group>

              {importUrl.trim() && isValidUrl(importUrl.trim()) && (
                <div className="text-center">
                  <Badge bg="success" className="p-2">
                    <FaCheckCircle className="me-1" />
                    Valid URL - Ready to Import
                  </Badge>
                </div>
              )}

              {importUrl.trim() && !isValidUrl(importUrl.trim()) && (
                <div className="text-center">
                  <Badge bg="danger" className="p-2">
                    <FaExclamationTriangle className="me-1" />
                    Invalid URL Format
                  </Badge>
                </div>
              )}
            </Card.Body>
          </Card>
        )}

        {/* Requirements */}
        <Card className="bg-dark border-secondary">
          <Card.Body className="py-3">
            <h6 className="text-white mb-2">
              {importMethod === 'file' ? 'File Requirements:' : 'URL Requirements:'}
            </h6>
            {importMethod === 'file' ? (
              <ul className="text-white-50 small mb-0">
                <li>File must have .rs0n extension</li>
                <li>Maximum file size: 500MB</li>
                <li>Must be a valid exported database file from this framework</li>
                <li>Import will merge data and update existing records</li>
              </ul>
            ) : (
              <ul className="text-white-50 small mb-0">
                <li>URL must point to a valid .rs0n file</li>
                <li>URL must be publicly accessible</li>
                <li>Maximum file size: 500MB</li>
                <li>Must be a valid exported database file from this framework</li>
                <li>Import will merge data and update existing records</li>
              </ul>
            )}
          </Card.Body>
        </Card>
      </Modal.Body>
      
      <Modal.Footer>
        <div className="d-flex justify-content-between w-100">
          <div className="d-flex gap-2">
            {showBackButton && (
              <Button
                variant="outline-danger"
                onClick={onBackClick}
                disabled={isImporting}
              >
                <FaArrowLeft className="me-1" />
                Back
              </Button>
            )}
            {((importMethod === 'file' && selectedFile) || (importMethod === 'url' && importUrl.trim())) && (
              <Button variant="outline-light" onClick={handleReset} disabled={isImporting}>
                Clear {importMethod === 'file' ? 'Selection' : 'URL'}
              </Button>
            )}
          </div>
          <div className="d-flex gap-2">
            <Button variant="secondary" onClick={handleModalClose} disabled={isImporting}>
              Cancel
            </Button>
            <Button 
              variant="danger" 
              onClick={handleImport}
              disabled={(importMethod === 'file' && !selectedFile) || (importMethod === 'url' && (!importUrl.trim() || !isValidUrl(importUrl.trim()))) || isImporting}
            >
              {isImporting ? (
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
                  <FaFileImport className="me-2" />
                  Import Database
                </>
              )}
            </Button>
          </div>
        </div>
      </Modal.Footer>
    </Modal>
  );
}

export default ImportModal; 