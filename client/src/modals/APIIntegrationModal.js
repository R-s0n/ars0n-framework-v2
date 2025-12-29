import { Modal, Button, Form, Spinner, Alert, Card, Tabs, Tab, Table, Badge, InputGroup, ButtonGroup } from 'react-bootstrap';
import { useState, useMemo } from 'react';
import { FaArrowLeft, FaPlug, FaCheckCircle, FaExclamationTriangle, FaSearch, FaRandom, FaList, FaKey, FaTimes } from 'react-icons/fa';

function APIIntegrationModal({ show, handleClose, onSuccess, showBackButton, onBackClick }) {
  const [activeTab, setActiveTab] = useState('hackerone');
  const [apiKey, setApiKey] = useState('');
  const [isTestingKey, setIsTestingKey] = useState(false);
  const [keyTestResult, setKeyTestResult] = useState(null);
  const [isKeyValid, setIsKeyValid] = useState(false);
  
  const [searchMode, setSearchMode] = useState('name');
  const [programName, setProgramName] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [searchResult, setSearchResult] = useState(null);
  const [searchError, setSearchError] = useState('');
  
  const [randomCriteria, setRandomCriteria] = useState({
    offersBounty: 'any',
    acceptsSubmissions: 'yes'
  });
  const [isLoadingRandom, setIsLoadingRandom] = useState(false);
  
  const [programs, setPrograms] = useState([]);
  const [isLoadingPrograms, setIsLoadingPrograms] = useState(false);
  const [selectedPrograms, setSelectedPrograms] = useState(new Set());
  const [programsFilter, setProgramsFilter] = useState('');
  const [sortColumn, setSortColumn] = useState('name');
  const [sortDirection, setSortDirection] = useState('asc');
  
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [parsedTargets, setParsedTargets] = useState([]);
  const [selectedTargets, setSelectedTargets] = useState(new Set());
  const [isImporting, setIsImporting] = useState(false);
  const [importResult, setImportResult] = useState(null);

  const testApiKey = async () => {
    if (!apiKey.trim()) {
      setKeyTestResult({ success: false, message: 'Please enter an API key' });
      return;
    }

    if (!apiKey.includes(':')) {
      setKeyTestResult({ success: false, message: 'Invalid format. Use: username:token' });
      return;
    }

    setIsTestingKey(true);
    setKeyTestResult(null);

    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/hackerone/test-key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ api_key: apiKey }),
      });

      const data = await response.json();

      if (data.success) {
        setKeyTestResult({ success: true, message: 'API key is valid!' });
        setIsKeyValid(true);
      } else {
        setKeyTestResult({ success: false, message: data.message || 'Invalid API credentials' });
        setIsKeyValid(false);
      }
    } catch (error) {
      setKeyTestResult({ success: false, message: `Connection error: ${error.message}` });
      setIsKeyValid(false);
    } finally {
      setIsTestingKey(false);
    }
  };

  const extractScopeTargets = (programData, includedData = []) => {
    const targets = [];
    
    try {
      console.log('Program data received:', programData);
      console.log('Included data:', includedData);
      
      let structuredScopes = [];
      
      const relationships = programData?.relationships || {};
      const scopeRefs = relationships?.structured_scopes?.data || [];
      console.log('Scope references count:', scopeRefs.length);
      
      if (includedData && includedData.length > 0) {
        structuredScopes = includedData.filter(item => item.type === 'structured-scope');
        console.log('Using included data, found scopes:', structuredScopes.length);
      } else if (scopeRefs.length > 0 && scopeRefs[0]?.attributes) {
        structuredScopes = scopeRefs;
        console.log('Using inline data from relationships');
      }
      
      console.log('Total structured scopes to process:', structuredScopes.length);
      
      for (const scope of structuredScopes) {
        const attrs = scope?.attributes || {};
        console.log('Scope:', attrs.asset_identifier, 'Type:', attrs.asset_type, 'Eligible:', attrs.eligible_for_submission);
        
        if (!attrs.eligible_for_submission) {
          console.log('Skipping scope (not eligible):', attrs.asset_identifier);
          continue;
        }
        
        const assetType = attrs.asset_type || '';
        const assetIdentifier = attrs.asset_identifier || '';
        
        if (!assetIdentifier) continue;
        
        if (assetType === 'WILDCARD') {
          targets.push({
            type: 'Wildcard',
            scope_target: assetIdentifier,
            mode: 'Passive',
            active: false
          });
        } else if (assetType === 'URL') {
          let url = assetIdentifier;
          if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = `https://${url}`;
          }
          targets.push({
            type: 'URL',
            scope_target: url,
            mode: 'Passive',
            active: false
          });
        }
      }
      console.log('Total eligible targets found:', targets.length);
    } catch (error) {
      console.error('Error extracting scope targets:', error);
    }
    
    return targets;
  };

  const searchByProgramName = async () => {
    if (!programName.trim()) {
      setSearchError('Please enter a program name');
      return;
    }

    if (!isKeyValid) {
      setSearchError('Please test and validate your API key first');
      return;
    }

    setIsSearching(true);
    setSearchError('');
    setSearchResult(null);

    try {
      let response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/hackerone/program?handle=${encodeURIComponent(programName.trim())}`, {
        method: 'GET',
        headers: {
          'X-HackerOne-API-Key': apiKey,
        },
      });

      if (response.status === 404) {
        const searchName = programName.trim().toLowerCase();
        const programsResponse = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/hackerone/programs?page[size]=100`, {
          method: 'GET',
          headers: {
            'X-HackerOne-API-Key': apiKey,
          },
        });

        if (programsResponse.status === 200) {
          const programsData = await programsResponse.json();
          const allPrograms = programsData.data || [];
          
          const matchedProgram = allPrograms.find(p => 
            p.attributes?.handle?.toLowerCase() === searchName ||
            p.attributes?.name?.toLowerCase() === searchName
          );

          if (matchedProgram) {
            const correctHandle = matchedProgram.attributes.handle;
            response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/hackerone/program?handle=${encodeURIComponent(correctHandle)}`, {
              method: 'GET',
              headers: {
                'X-HackerOne-API-Key': apiKey,
              },
            });
          } else {
            setSearchError(`Program "${programName}" not found`);
            return;
          }
        } else {
          setSearchError(`Program "${programName}" not found`);
          return;
        }
      }

      if (response.status === 200) {
        const data = await response.json();
        console.log('Raw API response:', data);
        console.log('Response keys:', Object.keys(data));
        
        const programData = data.data || data;
        const includedData = data.included || [];
        
        console.log('Program data:', programData);
        console.log('Included data:', includedData);
        
        const targets = extractScopeTargets(programData, includedData);
        
        if (targets.length === 0) {
          setSearchError('No eligible scope targets found for this program');
        } else {
          setSearchResult({
            program: programData,
            targets: targets
          });
          showTargetConfirmation(targets);
        }
      } else {
        setSearchError(`API error: ${response.status}`);
      }
    } catch (error) {
      setSearchError(`Error: ${error.message}`);
    } finally {
      setIsSearching(false);
    }
  };

  const fetchRandomProgram = async () => {
    if (!isKeyValid) {
      setSearchError('Please test and validate your API key first');
      return;
    }

    setIsLoadingRandom(true);
    setSearchError('');

    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/hackerone/programs?page[size]=100`, {
        method: 'GET',
        headers: {
          'X-HackerOne-API-Key': apiKey,
        },
      });

      if (response.status === 200) {
        const data = await response.json();
        let eligiblePrograms = data.data || [];
        
        if (randomCriteria.offersBounty === 'yes') {
          eligiblePrograms = eligiblePrograms.filter(p => p.attributes?.offers_bounties === true);
        } else if (randomCriteria.offersBounty === 'no') {
          eligiblePrograms = eligiblePrograms.filter(p => p.attributes?.offers_bounties === false);
        }
        
        if (randomCriteria.acceptsSubmissions === 'yes') {
          eligiblePrograms = eligiblePrograms.filter(p => p.attributes?.submission_state === 'open');
        }
        
        if (eligiblePrograms.length === 0) {
          setSearchError('No programs match your criteria');
          return;
        }
        
        const randomProgram = eligiblePrograms[Math.floor(Math.random() * eligiblePrograms.length)];
        const handle = randomProgram.attributes?.handle;
        
        const detailResponse = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/hackerone/program?handle=${encodeURIComponent(handle)}`, {
          method: 'GET',
          headers: {
            'X-HackerOne-API-Key': apiKey,
          },
        });
        
        if (detailResponse.status === 200) {
          const detailData = await detailResponse.json();
          const programData = detailData.data || detailData;
          const includedData = detailData.included || [];
          const targets = extractScopeTargets(programData, includedData);
          
          if (targets.length === 0) {
            setSearchError('Selected program has no eligible scope targets. Try again.');
          } else {
            setSearchResult({
              program: programData,
              targets: targets
            });
            showTargetConfirmation(targets);
          }
        }
      } else {
        setSearchError(`API error: ${response.status}`);
      }
    } catch (error) {
      setSearchError(`Error: ${error.message}`);
    } finally {
      setIsLoadingRandom(false);
    }
  };

  const fetchAllPrograms = async () => {
    if (!isKeyValid) {
      setSearchError('Please test and validate your API key first');
      return;
    }

    setIsLoadingPrograms(true);
    setSearchError('');
    setPrograms([]);

    try {
      let allPrograms = [];
      let page = 1;
      
      while (allPrograms.length < 500) {
        const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/hackerone/programs?page[number]=${page}&page[size]=100`, {
          method: 'GET',
          headers: {
            'X-HackerOne-API-Key': apiKey,
          },
        });

        if (response.status === 200) {
          const data = await response.json();
          const batch = data.data || [];
          
          if (batch.length === 0) break;
          
          allPrograms = allPrograms.concat(batch);
          page++;
          
          if (batch.length < 100) break;
        } else {
          setSearchError(`API error: ${response.status}`);
          break;
        }
      }
      
      setPrograms(allPrograms);
    } catch (error) {
      setSearchError(`Error: ${error.message}`);
    } finally {
      setIsLoadingPrograms(false);
    }
  };

  const fetchProgramDetails = async (handle) => {
    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/hackerone/program?handle=${encodeURIComponent(handle)}`, {
        method: 'GET',
        headers: {
          'X-HackerOne-API-Key': apiKey,
        },
      });

      if (response.status === 200) {
        const data = await response.json();
        const programData = data.data || data;
        const includedData = data.included || [];
        return extractScopeTargets(programData, includedData);
      }
    } catch (error) {
      console.error(`Error fetching details for ${handle}:`, error);
    }
    
    return [];
  };

  const handleImportSelectedPrograms = async () => {
    if (selectedPrograms.size === 0) {
      setSearchError('Please select at least one program');
      return;
    }

    setIsLoadingPrograms(true);
    setSearchError('');

    try {
      const allTargets = [];
      const selectedProgramList = programs.filter(p => selectedPrograms.has(p.id));
      
      for (const program of selectedProgramList) {
        const handle = program.attributes?.handle;
        if (handle) {
          const targets = await fetchProgramDetails(handle);
          allTargets.push(...targets);
        }
      }
      
      if (allTargets.length === 0) {
        setSearchError('No eligible scope targets found in selected programs');
      } else {
        showTargetConfirmation(allTargets);
      }
    } catch (error) {
      setSearchError(`Error: ${error.message}`);
    } finally {
      setIsLoadingPrograms(false);
    }
  };

  const showTargetConfirmation = (targets) => {
    const uniqueTargets = Array.from(new Map(targets.map(t => [t.scope_target, t])).values());
    const targetsWithIds = uniqueTargets.map((target, idx) => ({
      ...target,
      id: `target-${idx}`
    }));
    
    setParsedTargets(targetsWithIds);
    setSelectedTargets(new Set(targetsWithIds.map(t => t.id)));
    setShowConfirmation(true);
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

  const handleConfirmImport = async () => {
    setIsImporting(true);
    setSearchError('');
    setImportResult(null);

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
          const { id, ...targetData } = target;
          
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

      setImportResult({
        total: targetsToImport.length,
        success: successCount,
        failed: failCount,
        errors: errors.slice(0, 5)
      });

      setShowConfirmation(false);
      setParsedTargets([]);
      setSelectedTargets(new Set());

      if (onSuccess && typeof onSuccess === 'function') {
        onSuccess({ imported_targets: successCount });
      }

    } catch (err) {
      console.error('Import failed:', err);
      setSearchError(`Import failed: ${err.message}`);
    } finally {
      setIsImporting(false);
    }
  };

  const handleReset = () => {
    setProgramName('');
    setSearchResult(null);
    setSearchError('');
    setPrograms([]);
    setSelectedPrograms(new Set());
    setProgramsFilter('');
    setShowConfirmation(false);
    setParsedTargets([]);
    setSelectedTargets(new Set());
    setImportResult(null);
  };

  const handleModalClose = () => {
    handleReset();
    setActiveTab('hackerone');
    setSearchMode('name');
    setApiKey('');
    setIsKeyValid(false);
    setKeyTestResult(null);
    handleClose();
  };

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

  const filteredAndSortedPrograms = useMemo(() => {
    let filtered = programs.filter(program => {
      const name = program.attributes?.name?.toLowerCase() || '';
      const handle = program.attributes?.handle?.toLowerCase() || '';
      const search = programsFilter.toLowerCase();
      return name.includes(search) || handle.includes(search);
    });

    filtered.sort((a, b) => {
      let aVal, bVal;
      
      if (sortColumn === 'name') {
        aVal = a.attributes?.name?.toLowerCase() || '';
        bVal = b.attributes?.name?.toLowerCase() || '';
      } else if (sortColumn === 'bounty') {
        aVal = a.attributes?.offers_bounties ? 1 : 0;
        bVal = b.attributes?.offers_bounties ? 1 : 0;
      } else if (sortColumn === 'submissions') {
        aVal = a.attributes?.submission_state === 'open' ? 1 : 0;
        bVal = b.attributes?.submission_state === 'open' ? 1 : 0;
      }
      
      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    return filtered;
  }, [programs, programsFilter, sortColumn, sortDirection]);

  const toggleProgramSelection = (programId) => {
    setSelectedPrograms(prev => {
      const newSet = new Set(prev);
      if (newSet.has(programId)) {
        newSet.delete(programId);
      } else {
        newSet.add(programId);
      }
      return newSet;
    });
  };

  const toggleAllPrograms = () => {
    if (selectedPrograms.size === filteredAndSortedPrograms.length && filteredAndSortedPrograms.length > 0) {
      setSelectedPrograms(new Set());
    } else {
      setSelectedPrograms(new Set(filteredAndSortedPrograms.map(p => p.id)));
    }
  };

  const renderUnderConstruction = (platform) => (
    <div className="text-center py-5">
      <div className="mb-4">
        <i className="bi bi-cone-striped text-warning" style={{ fontSize: '80px' }}></i>
      </div>
      <h4 className="text-white mb-3">Under Construction</h4>
      <p className="text-white-50 mb-0">
        {platform} API integration is coming soon! Stay tuned for updates.
      </p>
    </div>
  );

  const renderConfirmationView = () => (
    <>
      <Alert variant="info">
        <FaCheckCircle className="me-2" />
        <strong>Review Scope Targets</strong>
        <p className="mb-0 mt-2 small">
          {parsedTargets.length} target{parsedTargets.length !== 1 ? 's' : ''} found from HackerOne. 
          Review and uncheck any you don't want to import.
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

  const renderHackerOneTab = () => {
    if (showConfirmation) {
      return renderConfirmationView();
    }

    return (
      <>
        {searchError && (
          <Alert variant="danger" dismissible onClose={() => setSearchError('')}>
            <FaExclamationTriangle className="me-2" />
            {searchError}
          </Alert>
        )}

        {importResult && (
          <Alert variant={importResult.failed > 0 ? 'warning' : 'success'} dismissible onClose={() => setImportResult(null)}>
            <FaCheckCircle className="me-2" />
            <strong>Import Complete!</strong>
            <ul className="mt-2 mb-0">
              <li>Total targets processed: {importResult.total}</li>
              <li>Successfully imported: {importResult.success}</li>
              {importResult.failed > 0 && <li>Failed: {importResult.failed}</li>}
            </ul>
            {importResult.errors.length > 0 && (
              <div className="mt-2">
                <small>First few errors:</small>
                <ul className="mb-0">
                  {importResult.errors.map((err, idx) => (
                    <li key={idx}><small>{err}</small></li>
                  ))}
                </ul>
              </div>
            )}
          </Alert>
        )}

        <Card className="mb-4 bg-dark border-secondary">
          <Card.Body>
            <h6 className="text-white mb-3">
              <FaKey className="me-2" />
              HackerOne API Key
            </h6>
            <Form.Group className="mb-3">
              <Form.Label className="text-white-50 small">
                API Key (format: username:token)
              </Form.Label>
              <InputGroup>
                <Form.Control
                  type="password"
                  placeholder="username:token"
                  value={apiKey}
                  onChange={(e) => {
                    setApiKey(e.target.value);
                    setIsKeyValid(false);
                    setKeyTestResult(null);
                  }}
                />
                <Button 
                  variant={keyTestResult?.success ? 'success' : 'outline-danger'}
                  onClick={testApiKey}
                  disabled={isTestingKey}
                >
                  {isTestingKey ? (
                    <Spinner animation="border" size="sm" />
                  ) : keyTestResult?.success ? (
                    <FaCheckCircle />
                  ) : (
                    'Test Key'
                  )}
                </Button>
              </InputGroup>
              {keyTestResult && (
                <Form.Text className={keyTestResult.success ? 'text-success' : 'text-danger'}>
                  {keyTestResult.message}
                </Form.Text>
              )}
            </Form.Group>
          </Card.Body>
        </Card>

        <div className="mb-4">
          <h6 className="text-white mb-3">Import Method</h6>
          <ButtonGroup className="w-100 mb-3">
            <Button
              variant={searchMode === 'name' ? 'danger' : 'outline-danger'}
              onClick={() => { setSearchMode('name'); handleReset(); }}
            >
              <FaSearch className="me-2" />
              Search by Name
            </Button>
            <Button
              variant={searchMode === 'random' ? 'danger' : 'outline-danger'}
              onClick={() => { setSearchMode('random'); handleReset(); }}
            >
              <FaRandom className="me-2" />
              Random Program
            </Button>
            <Button
              variant={searchMode === 'browse' ? 'danger' : 'outline-danger'}
              onClick={() => { setSearchMode('browse'); handleReset(); }}
            >
              <FaList className="me-2" />
              Browse All
            </Button>
          </ButtonGroup>
        </div>

        {searchMode === 'name' && (
          <Card className="border-secondary">
            <Card.Body>
              <h6 className="text-white mb-3">Search by Program Name</h6>
              <p className="text-white-50 small mb-3">
                Enter the program handle (e.g., "security", "gitlab", "shopify")
              </p>
              <InputGroup className="mb-3">
                <Form.Control
                  type="text"
                  placeholder="Enter program handle..."
                  value={programName}
                  onChange={(e) => setProgramName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !isSearching) {
                      searchByProgramName();
                    }
                  }}
                />
                <Button 
                  variant="danger" 
                  onClick={searchByProgramName}
                  disabled={!isKeyValid || isSearching || !programName.trim()}
                >
                  {isSearching ? (
                    <>
                      <Spinner animation="border" size="sm" className="me-2" />
                      Searching...
                    </>
                  ) : (
                    <>
                      <FaSearch className="me-2" />
                      Search
                    </>
                  )}
                </Button>
              </InputGroup>
            </Card.Body>
          </Card>
        )}

        {searchMode === 'random' && (
          <Card className="border-secondary">
            <Card.Body>
              <h6 className="text-white mb-3">Random Program Selection</h6>
              <p className="text-white-50 small mb-3">
                Get a random program based on your criteria
              </p>
              
              <Form.Group className="mb-3">
                <Form.Label className="text-white">Offers Bounty</Form.Label>
                <Form.Select
                  value={randomCriteria.offersBounty}
                  onChange={(e) => setRandomCriteria({...randomCriteria, offersBounty: e.target.value})}
                  className="bg-dark text-white"
                >
                  <option value="any">Any</option>
                  <option value="yes">Yes</option>
                  <option value="no">No</option>
                </Form.Select>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label className="text-white">Accepts Submissions</Form.Label>
                <Form.Select
                  value={randomCriteria.acceptsSubmissions}
                  onChange={(e) => setRandomCriteria({...randomCriteria, acceptsSubmissions: e.target.value})}
                  className="bg-dark text-white"
                >
                  <option value="any">Any</option>
                  <option value="yes">Yes (Open)</option>
                  <option value="no">No (Closed)</option>
                </Form.Select>
              </Form.Group>

              <Button 
                variant="danger" 
                className="w-100"
                onClick={fetchRandomProgram}
                disabled={!isKeyValid || isLoadingRandom}
              >
                {isLoadingRandom ? (
                  <>
                    <Spinner animation="border" size="sm" className="me-2" />
                    Finding Program...
                  </>
                ) : (
                  <>
                    <FaRandom className="me-2" />
                    Get Random Program
                  </>
                )}
              </Button>
            </Card.Body>
          </Card>
        )}

        {searchMode === 'browse' && (
          <Card className="border-secondary">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center mb-3">
                <h6 className="text-white mb-0">Browse All Programs</h6>
                <Button 
                  variant="danger" 
                  size="sm"
                  onClick={fetchAllPrograms}
                  disabled={!isKeyValid || isLoadingPrograms}
                >
                  {isLoadingPrograms ? (
                    <>
                      <Spinner animation="border" size="sm" className="me-2" />
                      Loading...
                    </>
                  ) : (
                    'Load Programs'
                  )}
                </Button>
              </div>

              {programs.length > 0 && (
                <>
                  <InputGroup className="mb-3">
                    <InputGroup.Text>
                      <FaSearch />
                    </InputGroup.Text>
                    <Form.Control
                      type="text"
                      placeholder="Filter programs..."
                      value={programsFilter}
                      onChange={(e) => setProgramsFilter(e.target.value)}
                    />
                    {programsFilter && (
                      <Button 
                        variant="outline-secondary" 
                        onClick={() => setProgramsFilter('')}
                      >
                        <FaTimes />
                      </Button>
                    )}
                  </InputGroup>

                  <div className="mb-3 d-flex justify-content-between align-items-center">
                    <div className="text-white small">
                      <strong>{filteredAndSortedPrograms.length}</strong> programs
                      {selectedPrograms.size > 0 && (
                        <span className="ms-2">| <strong>{selectedPrograms.size}</strong> selected</span>
                      )}
                    </div>
                    <div className="d-flex gap-2">
                      {selectedPrograms.size > 0 && (
                        <Button 
                          variant="outline-danger" 
                          size="sm"
                          onClick={handleImportSelectedPrograms}
                          disabled={isLoadingPrograms}
                        >
                          Import {selectedPrograms.size} Program{selectedPrograms.size !== 1 ? 's' : ''}
                        </Button>
                      )}
                      <Button 
                        variant="outline-secondary" 
                        size="sm"
                        onClick={toggleAllPrograms}
                      >
                        {selectedPrograms.size === filteredAndSortedPrograms.length && filteredAndSortedPrograms.length > 0 ? 'Deselect All' : 'Select All'}
                      </Button>
                    </div>
                  </div>

                  <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                    <Table striped bordered hover variant="dark" size="sm">
                      <thead style={{ position: 'sticky', top: 0, backgroundColor: '#212529', zIndex: 1 }}>
                        <tr>
                          <th style={{ width: '50px' }}>
                            <Form.Check
                              type="checkbox"
                              checked={selectedPrograms.size === filteredAndSortedPrograms.length && filteredAndSortedPrograms.length > 0}
                              onChange={toggleAllPrograms}
                            />
                          </th>
                          <th style={{ cursor: 'pointer' }} onClick={() => handleSort('name')}>
                            Program {renderSortIcon('name')}
                          </th>
                          <th style={{ width: '100px', cursor: 'pointer' }} onClick={() => handleSort('bounty')}>
                            Bounty {renderSortIcon('bounty')}
                          </th>
                          <th style={{ width: '120px', cursor: 'pointer' }} onClick={() => handleSort('submissions')}>
                            Submissions {renderSortIcon('submissions')}
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredAndSortedPrograms.length === 0 ? (
                          <tr>
                            <td colSpan="4" className="text-center text-muted py-4">
                              No programs match your filter
                            </td>
                          </tr>
                        ) : (
                          filteredAndSortedPrograms.map((program) => (
                            <tr key={program.id}>
                              <td onClick={(e) => e.stopPropagation()}>
                                <Form.Check
                                  type="checkbox"
                                  checked={selectedPrograms.has(program.id)}
                                  onChange={() => toggleProgramSelection(program.id)}
                                />
                              </td>
                              <td>
                                <div className="text-white">{program.attributes?.name}</div>
                                <div className="text-muted small">@{program.attributes?.handle}</div>
                              </td>
                              <td className="text-center">
                                {program.attributes?.offers_bounties ? (
                                  <Badge bg="success">Yes</Badge>
                                ) : (
                                  <Badge bg="secondary">No</Badge>
                                )}
                              </td>
                              <td className="text-center">
                                {program.attributes?.submission_state === 'open' ? (
                                  <Badge bg="success">Open</Badge>
                                ) : (
                                  <Badge bg="secondary">Closed</Badge>
                                )}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </Table>
                  </div>
                </>
              )}
            </Card.Body>
          </Card>
        )}
      </>
    );
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

      <Modal data-bs-theme="dark" show={show} onHide={handleModalClose} size="xl">
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">
            {showConfirmation ? (
              <>
                <FaCheckCircle className="me-2" />
                Review & Confirm Targets
              </>
            ) : (
              <>
                <FaPlug className="me-2" />
                API Integration
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
                  disabled={isImporting}
                >
                  <FaArrowLeft className="me-1" />
                  Back to Search
                </Button>
              ) : (
                <>
                  {showBackButton && (
                    <Button
                      variant="outline-danger"
                      onClick={onBackClick}
                    >
                      <FaArrowLeft className="me-1" />
                      Back
                    </Button>
                  )}
                </>
              )}
            </div>
            <div className="d-flex gap-2">
              <Button variant="secondary" onClick={handleModalClose} disabled={isImporting}>
                Close
              </Button>
              {activeTab === 'hackerone' && showConfirmation && (
                <Button 
                  variant="danger" 
                  onClick={handleConfirmImport}
                  disabled={selectedTargets.size === 0 || isImporting}
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
                      <FaCheckCircle className="me-2" />
                      Import {selectedTargets.size} Target{selectedTargets.size !== 1 ? 's' : ''}
                    </>
                  )}
                </Button>
              )}
            </div>
          </div>
        </Modal.Footer>
      </Modal>
    </>
  );
}

export default APIIntegrationModal;

