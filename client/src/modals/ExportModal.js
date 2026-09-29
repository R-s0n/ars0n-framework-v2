import { Modal, Button, Spinner, Tab, Tabs, Form, Table, Badge } from 'react-bootstrap';
import { useState, useEffect } from 'react';

function ExportModal({ show, handleClose }) {
  const [activeTab, setActiveTab] = useState('csv');
  
  // CSV export is now schema-driven and complete (one CSV per table, grouped by workflow), so the old
  // 26 per-tool checkboxes are gone. The only choices are which targets and whether to drop the long
  // recon tail. Coverage comes from the same engine as the .rs0n bundle, so it can never go stale.
  const [curatedOnly, setCuratedOnly] = useState(false);

  const [isExporting, setIsExporting] = useState(false);
  
  const [scopeTargets, setScopeTargets] = useState([]);
  const [selectedScopeTargets, setSelectedScopeTargets] = useState(new Set());
  const [loadingScopeTargets, setLoadingScopeTargets] = useState(false);
  const [isDatabaseExporting, setIsDatabaseExporting] = useState(false);

  // Both tabs choose scope targets now, so load them whenever the modal opens.
  useEffect(() => {
    if (show) {
      fetchScopeTargets();
    }
  }, [show]);

  const fetchScopeTargets = async () => {
    setLoadingScopeTargets(true);
    try {
      const response = await fetch(`/api/api/scope-targets-for-export`);
      if (response.ok) {
        const targets = await response.json();
        setScopeTargets(targets);
        
        const allIds = new Set(targets.map(target => target.id));
        setSelectedScopeTargets(allIds);
      } else {
        console.error('Failed to fetch scope targets');
      }
    } catch (error) {
      console.error('Error fetching scope targets:', error);
    } finally {
      setLoadingScopeTargets(false);
    }
  };


  // Both tabs select scope targets now, so these act on the same set.
  const handleSelectAll = () => {
    setSelectedScopeTargets(new Set(scopeTargets.map(target => target.id)));
  };

  const handleDeselectAll = () => {
    setSelectedScopeTargets(new Set());
  };

  const handleScopeTargetToggle = (targetId) => {
    setSelectedScopeTargets(prev => {
      const newSet = new Set(prev);
      if (newSet.has(targetId)) {
        newSet.delete(targetId);
      } else {
        newSet.add(targetId);
      }
      return newSet;
    });
  };

  const handleExport = async () => {
    if (selectedScopeTargets.size === 0) {
      alert('Please select at least one scope target to export.');
      return;
    }
    try {
      setIsExporting(true);
      const response = await fetch(`/api/api/export-data`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scope_target_ids: Array.from(selectedScopeTargets),
          curated_only: curatedOnly,
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Export failed: ${errorText}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ars0n-csv-export-${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.zip`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      handleClose();
    } catch (error) {
      console.error('Export failed:', error);
      alert('Failed to export data. Please try again. Error: ' + error.message);
    } finally {
      setIsExporting(false);
    }
  };

  const handleDatabaseExport = async () => {
    if (selectedScopeTargets.size === 0) {
      alert('Please select at least one scope target to export.');
      return;
    }

    try {
      setIsDatabaseExporting(true);
      const response = await fetch(`/api/api/database-export`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ scope_target_ids: Array.from(selectedScopeTargets) })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Database export failed: ${errorText}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rs0n-export-${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.rs0n`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      handleClose();
    } catch (error) {
      console.error('Database export failed:', error);
      alert('Failed to export database. Please try again. Error: ' + error.message);
    } finally {
      setIsDatabaseExporting(false);
    }
  };


  // Shared scope-target picker: both CSV and .rs0n export choose targets the same way now.
  const renderScopeTargetTable = () => (
    loadingScopeTargets ? (
      <div className="text-center py-4">
        <Spinner animation="border" variant="danger" />
        <p className="text-white mt-3">Loading scope targets...</p>
      </div>
    ) : (
      <div style={{ maxHeight: '50vh', overflowY: 'auto' }}>
        <Table striped variant="dark" hover>
          <thead>
            <tr>
              <th style={{ width: '40px' }}>
                <Form.Check
                  type="checkbox"
                  checked={selectedScopeTargets.size === scopeTargets.length && scopeTargets.length > 0}
                  onChange={() => {
                    if (selectedScopeTargets.size === scopeTargets.length) {
                      setSelectedScopeTargets(new Set());
                    } else {
                      setSelectedScopeTargets(new Set(scopeTargets.map(target => target.id)));
                    }
                  }}
                />
              </th>
              <th>Type</th>
              <th>Scope Target</th>
              <th>Status</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {scopeTargets.map((target) => (
              <tr key={target.id}>
                <td>
                  <Form.Check
                    type="checkbox"
                    checked={selectedScopeTargets.has(target.id)}
                    onChange={() => handleScopeTargetToggle(target.id)}
                  />
                </td>
                <td>
                  <Badge bg={target.type === 'Company' ? 'warning' : target.type === 'Wildcard' ? 'info' : 'secondary'}>
                    {target.type}
                  </Badge>
                </td>
                <td className="text-white">{target.scope_target}</td>
                <td>
                  <Badge bg={target.active ? 'success' : 'secondary'}>
                    {target.active ? 'Active' : 'Inactive'}
                  </Badge>
                </td>
                <td className="text-white-50 small">
                  {new Date(target.created_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </div>
    )
  );

  const renderCSVExport = () => (
    <>
      <div className="mb-3">
        <p className="text-white-50 mb-2">
          A ZIP of CSVs for the selected targets: one file per database table, grouped by workflow
          (auth, urls, findings, threat, config, recon), with a manifest. This covers everything the
          target holds, not just recon.
        </p>
        <div className="d-flex justify-content-between align-items-center">
          <span className="text-white">
            <strong>{selectedScopeTargets.size}</strong> of <strong>{scopeTargets.length}</strong> targets selected
          </span>
          <Form.Check
            type="switch"
            id="csv-curated-only"
            className="text-white-50"
            checked={curatedOnly}
            onChange={(e) => setCuratedOnly(e.target.checked)}
            label="Curated only (skip the long recon table dump)"
          />
        </div>
      </div>
      {renderScopeTargetTable()}
    </>
  );

  const renderDatabaseExport = () => (
    <>
      <div className="mb-4">
        <p className="text-white-50 mb-2">
          Export the complete database for the selected targets: every table and every FK-linked child
          row, so the whole target (recon and the full URL workflow) moves to another install intact.
        </p>
        <div className="d-flex justify-content-between align-items-center">
          <span className="text-white">
            <strong>{selectedScopeTargets.size}</strong> of <strong>{scopeTargets.length}</strong> targets selected
          </span>
          <Badge bg="info" className="p-2">
            File format: .rs0n (compressed)
          </Badge>
        </div>
      </div>
      {renderScopeTargetTable()}
    </>
  );

  const isDisabled = () => {
    if (activeTab === 'csv') {
      return selectedScopeTargets.size === 0 || isExporting || loadingScopeTargets;
    } else if (activeTab === 'database') {
      return selectedScopeTargets.size === 0 || isDatabaseExporting || loadingScopeTargets;
    }
    return true;
  };

  const getButtonText = () => {
    if (activeTab === 'csv') {
      return isExporting ? (
        <>
          <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
          Exporting...
        </>
      ) : 'Export to CSV';
    } else if (activeTab === 'database') {
      return isDatabaseExporting ? (
        <>
          <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
          Exporting...
        </>
      ) : 'Export Database (.rs0n)';
    }
  };

  const handleButtonClick = () => {
    if (activeTab === 'csv') {
      handleExport();
    } else if (activeTab === 'database') {
      handleDatabaseExport();
    }
  };

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Export Data</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="mb-3"
          variant="pills"
        >
          <Tab eventKey="csv" title="CSV Export">
            {renderCSVExport()}
          </Tab>
          <Tab eventKey="database" title="Database Export">
            {renderDatabaseExport()}
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer>
        <div className="d-flex gap-2 me-auto">
          <Button variant="outline-light" onClick={handleSelectAll}>
            Select All
          </Button>
          <Button variant="outline-light" onClick={handleDeselectAll}>
            Deselect All
          </Button>
        </div>
        <div className="d-flex gap-2">
          <Button 
            variant="secondary" 
            onClick={handleClose} 
            disabled={isExporting || isDatabaseExporting}
          >
            Cancel
          </Button>
          <Button 
            variant="danger" 
            onClick={handleButtonClick}
            disabled={isDisabled()}
          >
            {getButtonText()}
          </Button>
        </div>
      </Modal.Footer>
    </Modal>
  );
}

export default ExportModal; 