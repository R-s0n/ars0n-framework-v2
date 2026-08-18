import React, { useState, useEffect } from 'react';
import { Modal, Button, Nav, Badge, Form, InputGroup, Spinner, Alert } from 'react-bootstrap';
import VirtualizedList from '../components/VirtualizedList';
import useDebounce from '../hooks/useDebounce';

const ManageEndpointsModal = ({ show, onHide, scopeTargetId }) => {
  const [endpoints, setEndpoints] = useState([]);
  const [filteredEndpoints, setFilteredEndpoints] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  // Valid first, because it is the only tab whose rows have been shown to exist. The rest are
  // reachable in one click and none of them is where work starts.
  const [activeTab, setActiveTab] = useState('valid');
  const [searchTerm, setSearchTerm] = useState('');
  // Filters, all driven by values actually present in the loaded rows so a select can never offer a
  // status code or a host that would match nothing.
  const [statusFilter, setStatusFilter] = useState('');
  const [methodFilter, setMethodFilter] = useState('');
  const [paramFilter, setParamFilter] = useState('');
  const [classFilter, setClassFilter] = useState('');
  const [hostFilter, setHostFilter] = useState('');
  const [sortBy, setSortBy] = useState('params');
  const [investigationResults, setInvestigationResults] = useState([]);
  const [selected, setSelected] = useState({});
  const [showDeleted, setShowDeleted] = useState(false);
  const [busy, setBusy] = useState('');
  const [notice, setNotice] = useState('');
  const [addOpen, setAddOpen] = useState(false);
  const [addText, setAddText] = useState('');
  const [addNotes, setAddNotes] = useState('');
  // G1.10: debounce the search box so filtering the endpoint list runs after typing pauses, not
  // on every keystroke. The input stays bound to the immediate `searchTerm` state.
  const debouncedSearchTerm = useDebounce(searchTerm, 250);

  useEffect(() => {
    if (show && scopeTargetId) {
      loadEndpoints();
      loadInvestigationResults();
    }
  }, [show, scopeTargetId]);

  useEffect(() => {
    applyFilters();
  }, [endpoints, activeTab, debouncedSearchTerm, showDeleted,
      statusFilter, methodFilter, paramFilter, classFilter, hostFilter, sortBy]);

  const loadEndpoints = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`/api/consolidated-endpoints/${scopeTargetId}`);
      if (response.ok) {
        const data = await response.json();
        setEndpoints(data || []);
      } else {
        setError('Failed to load endpoints');
      }
    } catch (err) {
      setError('Error connecting to framework: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Every mutation goes through here so the list, the counts and the selection cannot drift apart.
  const mutate = async (path, body, label) => {
    setBusy(label);
    setError('');
    setNotice('');
    try {
      const response = await fetch(`/api/consolidated-endpoints/${scopeTargetId}/${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(await response.text() || 'Request failed');
      const result = await response.json();
      setSelected({});
      await loadEndpoints();
      return result;
    } catch (err) {
      setError(err.message);
      return null;
    } finally {
      setBusy('');
    }
  };

  const selectedIds = Object.keys(selected).filter((id) => selected[id]);

  const handleAdd = async () => {
    const result = await mutate('add', { urls: addText, notes: addNotes }, 'add');
    if (result) {
      const bits = [];
      if (result.added) bits.push(`${result.added} added`);
      if (result.restored) bits.push(`${result.restored} restored`);
      if (result.rejected?.length) bits.push(`${result.rejected.length} could not be parsed`);
      setNotice(bits.join(', ') || 'Nothing to add');
      setAddText('');
      setAddNotes('');
      setAddOpen(false);
    }
  };

  const handleDeleteSelected = async () => {
    const result = await mutate('delete', { ids: selectedIds }, 'delete');
    if (result) setNotice(`${result.deleted} endpoint(s) removed. Restore brings them back with their verdicts.`);
  };

  const handleSweepRuledOut = async () => {
    const result = await mutate('delete',
      { filter: 'ruled_out', reason: 'swept after validation' }, 'sweep');
    if (result) {
      setNotice(result.deleted > 0
        ? `${result.deleted} endpoint(s) removed. Only measured rule-outs are swept; anything pinned, manually added, or overridden was left alone.`
        : 'Nothing swept. Only rule-outs measured with confidence are eligible, and none qualified.');
    }
  };

  const handleRestoreAll = async () => {
    const result = await mutate('restore', { all: true }, 'restore');
    if (result) setNotice(`${result.restored} endpoint(s) restored.`);
  };

  const handleOverride = async (status) => {
    const result = await mutate('override', { ids: selectedIds, status }, 'override');
    if (result) {
      setNotice(status
        ? `${result.updated} endpoint(s) marked ${status} by you. Downstream tools follow your call over the scan's.`
        : `${result.updated} override(s) cleared.`);
    }
  };

  const loadInvestigationResults = async () => {
    try {
      const response = await fetch(`/api/endpoint-investigation/${scopeTargetId}/results`);
      if (response.ok) {
        const data = await response.json();
        // This payload used to be a bare array of endpoints. It became
        // { endpoints, target_findings, tier1_notes } when the investigation gained target-level
        // rollups, and scans stored before that change still hold the array. Accepting only one
        // shape breaks the other: handing the object straight to state makes the per-row lookup
        // below throw "investigationResults.find is not a function", which takes down the whole
        // modal rather than just the investigation section.
        setInvestigationResults(Array.isArray(data) ? data : (data?.endpoints || []));
      }
    } catch (err) {
      console.log('No investigation results available yet');
    }
  };

  // How many inputs an endpoint takes. The stored parameters are the authority; a query string on the
  // URL is counted too, because an endpoint captured with ?id= carries a parameter whether or not the
  // consolidation broke it out into a row.
  const paramCount = (ep) => {
    const stored = (ep.parameters || []).length;
    if (stored > 0) return stored;
    const q = (ep.url || '').split('?')[1];
    return q ? q.split('&').filter(Boolean).length : 0;
  };

  const applyFilters = () => {
    // Deleted rows are hidden rather than gone, and are only shown when asked for.
    let filtered = endpoints.filter(ep => showDeleted ? ep.deleted_at : !ep.deleted_at);

    // An operator override always wins over the scan's verdict.
    const verdictOf = (ep) => ep.override_status || ep.validation_status || 'not_validated';

    if (activeTab === 'direct') {
      filtered = filtered.filter(ep => ep.is_direct);
    } else if (activeTab === 'adjacent') {
      filtered = filtered.filter(ep => !ep.is_direct);
    } else if (activeTab === 'valid') {
      filtered = filtered.filter(ep => verdictOf(ep) === 'valid');
    } else if (activeTab === 'unverified') {
      filtered = filtered.filter(ep => verdictOf(ep) === 'unverified');
    } else if (activeTab === 'ruled_out') {
      filtered = filtered.filter(ep => verdictOf(ep) === 'ruled_out');
    }

    if (statusFilter) {
      filtered = statusFilter === 'none'
        ? filtered.filter(ep => (ep.status_codes || []).length === 0)
        : filtered.filter(ep => (ep.status_codes || []).map(String).includes(statusFilter));
    }
    if (methodFilter) {
      filtered = filtered.filter(ep => ep.method === methodFilter);
    }
    if (paramFilter) {
      filtered = paramFilter === 'with'
        ? filtered.filter(ep => paramCount(ep) > 0)
        : filtered.filter(ep => paramCount(ep) === 0);
    }
    if (classFilter) {
      filtered = filtered.filter(ep => (ep.content_class || '') === classFilter);
    }
    if (hostFilter) {
      filtered = filtered.filter(ep => ep.domain === hostFilter);
    }

    if (debouncedSearchTerm) {
      const lowerSearch = debouncedSearchTerm.toLowerCase();
      filtered = filtered.filter(ep =>
        ep.url.toLowerCase().includes(lowerSearch) ||
        ep.domain.toLowerCase().includes(lowerSearch) ||
        ep.path.toLowerCase().includes(lowerSearch) ||
        ep.method.toLowerCase().includes(lowerSearch)
      );
    }

    // Parameters first by default. An endpoint that takes input is a thing to test; one that does not
    // is a page, and a list ordered by path buries the forty that matter under a thousand that do not.
    const byPath = (a, b) => (a.path || '').localeCompare(b.path || '');
    const sorters = {
      params: (a, b) => paramCount(b) - paramCount(a) ||
        (b.request_count || 0) - (a.request_count || 0) || byPath(a, b),
      requests: (a, b) => (b.request_count || 0) - (a.request_count || 0) || byPath(a, b),
      status: (a, b) => ((a.status_codes || [])[0] || 9999) - ((b.status_codes || [])[0] || 9999) ||
        byPath(a, b),
      path: byPath,
    };
    filtered = [...filtered].sort(sorters[sortBy] || sorters.params);

    setFilteredEndpoints(filtered);
  };

  const getMethodBadgeColor = (method) => {
    const colors = {
      'GET': 'primary',
      'POST': 'success',
      'PUT': 'warning',
      'DELETE': 'danger',
      'PATCH': 'info',
      'OPTIONS': 'secondary'
    };
    return colors[method] || 'secondary';
  };

  const getStatusBadgeColor = (status) => {
    if (status >= 200 && status < 300) return 'success';
    if (status >= 300 && status < 400) return 'info';
    if (status >= 400 && status < 500) return 'warning';
    if (status >= 500) return 'danger';
    return 'secondary';
  };

  const live = endpoints.filter(ep => !ep.deleted_at);
  const deletedCount = endpoints.length - live.length;

  // Filter options, counted from the rows in hand. Offering a value that matches nothing is how a
  // filter teaches an operator to distrust it.
  const tally = (values) => {
    const counts = new Map();
    values.forEach((v) => counts.set(v, (counts.get(v) || 0) + 1));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  };
  const statusOptions = tally(live.flatMap(
    ep => ((ep.status_codes || []).length ? ep.status_codes.map(String) : ['none'])));
  const methodOptions = tally(live.map(ep => ep.method).filter(Boolean));
  const classOptions = tally(live.map(ep => ep.content_class).filter(Boolean));
  const hostOptions = tally(live.map(ep => ep.domain).filter(Boolean));
  const withParamsCount = live.filter(ep => paramCount(ep) > 0).length;

  const filtersActive = !!(statusFilter || methodFilter || paramFilter || classFilter || hostFilter);
  const clearFilters = () => {
    setStatusFilter('');
    setMethodFilter('');
    setParamFilter('');
    setClassFilter('');
    setHostFilter('');
  };
  const directCount = live.filter(ep => ep.is_direct).length;
  const adjacentCount = live.filter(ep => !ep.is_direct).length;
  const verdictOf = (ep) => ep.override_status || ep.validation_status || 'not_validated';
  const validCount = live.filter(ep => verdictOf(ep) === 'valid').length;
  const unverifiedCount = live.filter(ep => verdictOf(ep) === 'unverified').length;
  const ruledOutCount = live.filter(ep => verdictOf(ep) === 'ruled_out').length;

  return (
    <Modal show={show} onHide={onHide} fullscreen data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-diagram-3 me-2"></i>
          Manage Consolidated Endpoints
        </Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ overflowY: 'auto' }}>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        {notice && (
          <Alert variant="dark" dismissible onClose={() => setNotice('')}
            className="py-2 small border-secondary">
            {notice}
          </Alert>
        )}

        <div className="d-flex flex-wrap gap-2 mb-3 align-items-center">
          <Button size="sm" variant="outline-danger" onClick={() => setAddOpen(!addOpen)}>
            <i className="bi bi-plus-lg me-1" />Add endpoints
          </Button>
          <Button size="sm" variant="outline-danger" disabled={selectedIds.length === 0 || busy !== ''}
                  onClick={handleDeleteSelected}>
            Delete {selectedIds.length > 0 ? `(${selectedIds.length})` : ''}
          </Button>
          <Button size="sm" variant="outline-danger" disabled={selectedIds.length === 0 || busy !== ''}
                  onClick={() => handleOverride('valid')}>
            Mark valid
          </Button>
          <Button size="sm" variant="outline-secondary" disabled={selectedIds.length === 0 || busy !== ''}
                  onClick={() => handleOverride('')}>
            Clear override
          </Button>
          <Button size="sm" variant="outline-danger" disabled={ruledOutCount === 0 || busy !== ''}
                  onClick={handleSweepRuledOut}
                  title="Removes only rule-outs the scan measured with confidence. Pinned, manually added and overridden rows are never swept.">
            Sweep ruled out
          </Button>
          {deletedCount > 0 && (
            <>
              <Form.Check type="switch" id="show-deleted" className="text-white-50 ms-2"
                checked={showDeleted} onChange={(e) => setShowDeleted(e.target.checked)}
                label={`Show deleted (${deletedCount})`} />
              {showDeleted && (
                <Button size="sm" variant="outline-secondary" onClick={handleRestoreAll} disabled={busy !== ''}>
                  Restore all
                </Button>
              )}
            </>
          )}
          {busy && <Spinner animation="border" size="sm" variant="danger" />}
          <Button variant="outline-secondary" size="sm" className="ms-auto"
            onClick={loadEndpoints} disabled={loading}>
            {loading
              ? <><Spinner animation="border" size="sm" className="me-2" />Refreshing</>
              : <><i className="bi bi-arrow-clockwise me-2"></i>Refresh</>}
          </Button>
        </div>

        {addOpen && (
          <div className="border border-secondary rounded p-3 mb-3">
            <Form.Label className="text-white small">
              One per line. A bare path resolves against the scope target, and a line may carry its
              own verb.
            </Form.Label>
            <Form.Control as="textarea" rows={4} className="bg-dark text-white border-secondary mb-2"
              placeholder={'/api/internal/export' + String.fromCharCode(10) +
                           'POST /api/v1/impersonate' + String.fromCharCode(10) +
                           'https://other.host/admin'}
              value={addText} onChange={(e) => setAddText(e.target.value)} />
            <Form.Control size="sm" className="bg-dark text-white border-secondary mb-2"
              placeholder="Note (optional): where this came from"
              value={addNotes} onChange={(e) => setAddNotes(e.target.value)} />
            <Button size="sm" variant="danger" onClick={handleAdd}
                    disabled={!addText.trim() || busy !== ''}>
              Add
            </Button>
            <span className="text-white-50 small ms-3">
              Manually added endpoints survive every re-consolidation.
            </span>
          </div>
        )}

        <div className="d-flex flex-wrap gap-2 mb-3 align-items-center">
          <InputGroup style={{ width: '320px' }}>
            <InputGroup.Text className="bg-dark text-white border-secondary">
              <i className="bi bi-search"></i>
            </InputGroup.Text>
            <Form.Control
              type="text"
              placeholder="Search endpoints..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-dark text-white border-secondary"
            />
            {searchTerm && (
              <Button variant="outline-secondary" onClick={() => setSearchTerm('')}>Clear</Button>
            )}
          </InputGroup>

          {/* Every option below is built from the rows actually loaded, so a select can never offer a
              status code, a method or a host that would match nothing. */}
          <Form.Select size="sm" style={{ width: 'auto' }}
            className="bg-dark text-white border-secondary"
            value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">Any status</option>
            {statusOptions.map(([code, n]) => (
              <option key={code} value={code}>{code === 'none' ? 'No response' : code} ({n})</option>
            ))}
          </Form.Select>

          <Form.Select size="sm" style={{ width: 'auto' }}
            className="bg-dark text-white border-secondary"
            value={paramFilter} onChange={(e) => setParamFilter(e.target.value)}>
            <option value="">Any parameters</option>
            <option value="with">With parameters ({withParamsCount})</option>
            <option value="without">No parameters ({live.length - withParamsCount})</option>
          </Form.Select>

          <Form.Select size="sm" style={{ width: 'auto' }}
            className="bg-dark text-white border-secondary"
            value={methodFilter} onChange={(e) => setMethodFilter(e.target.value)}>
            <option value="">Any method</option>
            {methodOptions.map(([m, n]) => <option key={m} value={m}>{m} ({n})</option>)}
          </Form.Select>

          <Form.Select size="sm" style={{ width: 'auto' }}
            className="bg-dark text-white border-secondary"
            value={classFilter} onChange={(e) => setClassFilter(e.target.value)}
            title="What the response looked like. api and script are where routes and parameters live; page is usually the app shell.">
            <option value="">Any kind</option>
            {classOptions.map(([c, n]) => <option key={c} value={c}>{c} ({n})</option>)}
          </Form.Select>

          <Form.Select size="sm" style={{ width: 'auto', maxWidth: '260px' }}
            className="bg-dark text-white border-secondary"
            value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}>
            <option value="">Any host</option>
            {hostOptions.map(([h, n]) => <option key={h} value={h}>{h} ({n})</option>)}
          </Form.Select>

          <Form.Select size="sm" style={{ width: 'auto' }}
            className="bg-dark text-white border-secondary"
            value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
            <option value="params">Sort: parameters first</option>
            <option value="requests">Sort: most requests</option>
            <option value="status">Sort: status code</option>
            <option value="path">Sort: path</option>
          </Form.Select>

          {filtersActive && (
            <Button size="sm" variant="outline-secondary" onClick={clearFilters}>
              Clear filters
            </Button>
          )}
          <span className="text-white-50 ms-auto small">
            {filteredEndpoints.length} shown
          </span>
        </div>

        {/* Verdict first, provenance second. Valid is what has been shown to exist and is where work
            starts; Direct and Adjacent describe where a row came from, which matters later. */}
        <Nav variant="pills" className="mb-3">
          {[
            ['valid', 'Valid', validCount, 'Answered in a way the validation could tell apart from the target\'s catch-all.'],
            ['ruled_out', 'Ruled out', ruledOutCount, 'Measured as not existing. Sweep removes these.'],
            ['unverified', 'Unverified', unverifiedCount, 'Could not be told apart from the target\'s catch-all, usually a login wall. Still tested downstream.'],
            ['direct', 'Direct', directCount, 'Found on the scope target itself.'],
            ['adjacent', 'Adjacent', adjacentCount, 'Found on another host reached from this target.'],
            ['all', 'All', live.length, 'Every endpoint currently in scope, whatever its verdict.'],
          ].map(([key, label, count, hint]) => (
            <Nav.Item key={key}>
              <Nav.Link
                active={activeTab === key}
                onClick={() => setActiveTab(key)}
                className={activeTab === key ? 'bg-danger' : 'text-danger'}
                title={hint}
              >
                {label} ({count})
              </Nav.Link>
            </Nav.Item>
          ))}
        </Nav>

        {loading ? (
          <div className="text-center py-5">
            <Spinner animation="border" variant="danger" />
            <p className="mt-3">Loading endpoints...</p>
          </div>
        ) : filteredEndpoints.length === 0 ? (
          <Alert variant="warning">
            No endpoints found. Run endpoint discovery tools or use Manual Crawling to capture requests.
          </Alert>
        ) : (
          <EndpointAccordion 
            endpoints={filteredEndpoints} 
            selected={selected}
            onToggle={(id) => setSelected(prev => ({ ...prev, [id]: !prev[id] }))}
            getMethodBadgeColor={getMethodBadgeColor}
            getStatusBadgeColor={getStatusBadgeColor}
            showOrigin={activeTab === 'adjacent'}
            investigationResults={investigationResults}
          />
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

// The raw HTTP request for one endpoint.
//
// The bytes come from the SERVER, not from stitching the row's fields together here. The framework
// already renders an endpoint into a raw request for fuzz seeding, and that renderer knows things a
// client-side join would get wrong: which headers must be dropped because re-sending them would lie
// (content-length, accept-encoding, content-encoding), that Host is re-derived from the URL so the
// line deciding where the request goes cannot disagree with the target, that a header value carrying
// a line break has to be flattened rather than injected, and that header order must be stable or
// every re-render looks like an edit.
//
// Using it here means the request shown in this modal is byte for byte the request a fuzz step would
// be seeded with. A second renderer would eventually disagree with the first, and the operator would
// have no way to tell which one was lying.
const RawRequestPane = ({ endpointId }) => {
  const [state, setState] = useState({ loading: true });
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let live = true;
    setState({ loading: true });
    fetch(`/api/fuzz/seed/${endpointId}`)
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error('could not be rendered'))))
      .then((data) => { if (live) setState({ loading: false, seed: data }); })
      .catch((err) => { if (live) setState({ loading: false, error: err.message }); });
    return () => { live = false; };
  }, [endpointId]);

  const copy = () => {
    navigator.clipboard?.writeText(state.seed?.raw || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="mb-3">
      <div className="d-flex justify-content-between align-items-baseline mb-1">
        <strong className="text-danger">Raw request</strong>
        <div className="d-flex align-items-center gap-2">
          {state.seed?.known_params?.length > 0 && (
            <span className="text-white-50" style={{ fontSize: '0.72rem' }}>
              known parameters: {state.seed.known_params.join(', ')}
            </span>
          )}
          {state.seed?.raw && (
            <Button size="sm" variant="link" className="p-0 text-white-50"
              style={{ fontSize: '0.72rem' }} onClick={copy}>
              {copied ? 'copied' : 'copy'}
            </Button>
          )}
        </div>
      </div>

      {state.loading && (
        <div className="text-white-50 small"><Spinner animation="border" size="sm" /> rendering</div>
      )}
      {state.error && (
        <div className="text-white-50 small">
          This endpoint could not be rendered as a request ({state.error}). That happens when the URL
          it was recorded with is unusable.
        </div>
      )}
      {state.seed?.raw && (
        <pre
          className="text-light small p-2 rounded mb-0"
          style={{
            backgroundColor: '#0d0d0d',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            maxHeight: '260px',
            overflowY: 'auto',
          }}
        >{state.seed.raw}</pre>
      )}
      {/* Said plainly, because a request with no captured headers is a reconstruction from a URL a
          crawler reported, not a recording of traffic that was observed. */}
      {state.seed && !state.error && (state.seed.notes || []).map((note, i) => (
        <div key={i} className="text-white-50 mt-1" style={{ fontSize: '0.72rem' }}>{note}</div>
      ))}
    </div>
  );
};

// Verdict styling. Ruled out is deliberately muted rather than red: it is a routine outcome, not
// a problem, and colouring it like an error trains the operator to ignore the colour.
const VERDICT_STYLE = {
  valid: { bg: 'success', label: 'valid' },
  unverified: { bg: 'secondary', label: 'unverified' },
  ruled_out: { bg: 'dark', label: 'ruled out' },
  skipped: { bg: 'dark', label: 'skipped' },
  not_validated: { bg: 'dark', label: 'not validated' },
};

const EndpointAccordion = ({ endpoints, getMethodBadgeColor, getStatusBadgeColor, showOrigin = false,
                             investigationResults = [], selected = {}, onToggle = null }) => {
  const getInvestigationData = (endpointId) => {
    return investigationResults.find(result => result.endpoint_id === endpointId);
  };

  // G1.6: expand state lifted to the parent (was the Bootstrap Accordion's internal state) so a
  // row stays expanded when it scrolls out of and back into the virtualized window. Single open
  // at a time, matching the previous <Accordion> behavior.
  const [expandedId, setExpandedId] = useState(null);

  const renderEndpoint = (endpoint) => {
    const investigation = getInvestigationData(endpoint.id);
    const hasInvestigation = !!investigation;
    const isExpanded = expandedId === endpoint.id;

    return (
        <div className="bg-dark border border-secondary rounded mb-2">
          <div
            role="button"
            onClick={() => setExpandedId(isExpanded ? null : endpoint.id)}
            className="d-flex align-items-center p-3"
            style={{ cursor: 'pointer' }}
          >
            <div className="d-flex w-100 align-items-center justify-content-between me-3">
              {onToggle && (
                <div style={{ flex: '0 0 34px' }} onClick={(e) => e.stopPropagation()}>
                  <Form.Check
                    checked={!!selected[endpoint.id]}
                    onChange={() => onToggle(endpoint.id)}
                    aria-label={`Select ${endpoint.url}`}
                  />
                </div>
              )}
              <div style={{ flex: '0 0 80px' }}>
                <Badge bg={getMethodBadgeColor(endpoint.method)}>
                  {endpoint.method}
                </Badge>
              </div>
              <div style={{ flex: '0 0 130px' }}>
                {(() => {
                  const verdict = endpoint.override_status || endpoint.validation_status || 'not_validated';
                  const style = VERDICT_STYLE[verdict] || VERDICT_STYLE.not_validated;
                  return (
                    <Badge bg={style.bg}
                           className={style.bg === 'dark' ? 'border border-secondary text-white-50' : ''}
                           title={endpoint.validation_reason || ''}>
                      {style.label}
                      {endpoint.override_status ? ' (yours)' : ''}
                    </Badge>
                  );
                })()}
              </div>
              <div style={{ flex: '1 1 auto' }} className="text-truncate">
                <small>
                  <strong className="text-danger">{endpoint.domain}</strong>
                  <span className="text-white">{endpoint.path}</span>
                  {hasInvestigation && (
                    <Badge bg="success" className="ms-2" style={{ fontSize: '0.7em' }}>
                      <i className="bi bi-check-circle me-1"></i>Investigated
                    </Badge>
                  )}
                </small>
              </div>
              <div style={{ flex: '0 0 120px' }} className="text-end">
                {endpoint.status_codes && endpoint.status_codes.length > 0 ? (
                  endpoint.status_codes.slice(0, 2).map((code, idx) => (
                    <Badge key={idx} bg={getStatusBadgeColor(code)} className="me-1">
                      {code}
                    </Badge>
                  ))
                ) : (
                  <Badge bg="secondary">N/A</Badge>
                )}
              </div>
              <div style={{ flex: '0 0 300px' }} className="text-start">
                {endpoint.parameters && endpoint.parameters.length > 0 ? (
                  <small>
                    {endpoint.parameters.slice(0, 3).map((param, pidx) => (
                      <Badge key={pidx} bg="danger" className="me-1" style={{ opacity: 0.8 }}>
                        {param.param_name}
                      </Badge>
                    ))}
                    {endpoint.parameters.length > 3 && (
                      <Badge bg="danger" style={{ opacity: 0.6 }}>
                        +{endpoint.parameters.length - 3}
                      </Badge>
                    )}
                  </small>
                ) : (
                  <small className="text-muted">No params</small>
                )}
              </div>
              <div style={{ flex: '0 0 100px' }} className="text-end">
                <Badge bg="secondary">
                  {endpoint.request_count} reqs
                </Badge>
              </div>
            </div>
            <i className={`bi ${isExpanded ? 'bi-chevron-up' : 'bi-chevron-down'} text-white ms-2`}></i>
          </div>
          {isExpanded && (
          <div className="bg-dark text-white p-3 border-top border-secondary">
            {/* The request itself, first. Everything below is metadata ABOUT a request; this is the
                request, and it is the thing an operator is actually trying to picture. */}
            <RawRequestPane endpointId={endpoint.id} />

            <div className="mb-3">
              <strong className="text-danger">Full URL:</strong><br />
              <code className="text-white">{endpoint.url}</code>
            </div>

            {/* Why the scan decided what it decided, and what would prove it wrong. A verdict an
                operator cannot argue with is a verdict they cannot trust. */}
            {endpoint.validation_reason && (
              <div className="mb-3 p-2 rounded" style={{ border: '1px solid #444' }}>
                <div className="small">
                  <strong className="text-danger">Validation:</strong>{' '}
                  {endpoint.validation_reason}
                </div>
                <div className="text-white-50 mt-1" style={{ fontSize: '0.75rem' }}>
                  {endpoint.validation_confidence && (
                    <span className="me-3">confidence: {endpoint.validation_confidence}</span>
                  )}
                  {endpoint.validation_testable === false && (
                    <span className="me-3">excluded from downstream testing</span>
                  )}
                  {endpoint.validation_testable === null && (
                    <span className="me-3">still tested downstream</span>
                  )}
                  {endpoint.validation_reason_code && (
                    <span className="me-3">{endpoint.validation_reason_code}</span>
                  )}
                </div>
                {endpoint.override_status && (
                  <div className="text-warning mt-1" style={{ fontSize: '0.75rem' }}>
                    You overrode this to {endpoint.override_status}
                    {endpoint.override_note ? `: ${endpoint.override_note}` : ''}.
                  </div>
                )}
              </div>
            )}

            {(endpoint.manual_added || endpoint.deleted_at || endpoint.template_group_size > 1) && (
              <div className="mb-3 small text-white-50">
                {endpoint.manual_added && (
                  <div>Added by hand. Re-consolidating will not remove it.</div>
                )}
                {endpoint.deleted_at && (
                  <div className="text-warning">
                    Deleted{endpoint.deleted_reason ? `: ${endpoint.deleted_reason}` : ''}. The row
                    is retained and can be restored with its verdict intact.
                  </div>
                )}
                {endpoint.template_group_size > 1 && (
                  <div>
                    One of {endpoint.template_group_size} endpoints matching{' '}
                    <code className="text-white-50">{endpoint.templated_path}</code>.
                  </div>
                )}
              </div>
            )}

            <div className="row mb-3">
              <div className="col-md-4">
                <strong className="text-danger">Type:</strong><br />
                <Badge bg="danger" style={{ opacity: endpoint.is_direct ? 1 : 0.6 }}>
                  {endpoint.is_direct ? 'Direct' : 'Adjacent'}
                </Badge>
              </div>
              <div className="col-md-4">
                <strong className="text-danger">Domain:</strong><br />
                <code className="text-white">{endpoint.domain}</code>
              </div>
              <div className="col-md-4">
                <strong className="text-danger">Sources:</strong><br />
                {endpoint.sources?.map((source, idx) => (
                  <Badge key={idx} bg="secondary" className="me-1">
                    {source}
                  </Badge>
                ))}
              </div>
            </div>

            {showOrigin && endpoint.origin_url && (
              <div className="mb-3">
                <strong className="text-danger">Origin URL:</strong><br />
                <code className="text-white">{endpoint.origin_url}</code>
              </div>
            )}

            {endpoint.parameters && endpoint.parameters.length > 0 && (
              <div className="mb-3">
                <strong className="text-danger">Parameters ({endpoint.parameters.length}):</strong>
                <div className="mt-2" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                  <table className="table table-dark table-sm table-bordered">
                    <thead>
                      <tr>
                        <th style={{ width: '100px' }}>Type</th>
                        <th>Name</th>
                        <th>Example Values</th>
                        <th style={{ width: '80px' }}>Frequency</th>
                      </tr>
                    </thead>
                    <tbody>
                      {endpoint.parameters.map((param, idx) => (
                        <tr key={idx}>
                          <td>
                            <Badge bg="danger" style={{ opacity: param.param_type === 'query' ? 1 : 0.7 }}>
                              {param.param_type}
                            </Badge>
                          </td>
                          <td><code className="text-white">{param.param_name}</code></td>
                          <td>
                            <small>
                              {param.example_values && param.example_values.length > 0 ? (
                                param.example_values.slice(0, 3).map((val, vidx) => (
                                  <Badge key={vidx} bg="secondary" className="me-1 mb-1">
                                    {val.length > 30 ? val.substring(0, 30) + '...' : val}
                                  </Badge>
                                ))
                              ) : (
                                <span className="text-muted">No examples</span>
                              )}
                              {param.example_values && param.example_values.length > 3 && (
                                <Badge bg="danger" className="ms-1">+{param.example_values.length - 3} more</Badge>
                              )}
                            </small>
                          </td>
                          <td className="text-center">
                            <Badge bg="danger">{param.frequency}</Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {hasInvestigation && (
              <>
                <hr style={{ borderColor: '#444' }} />
                <h6 className="text-danger mb-3">
                  <i className="bi bi-search me-2"></i>Investigation Results
                </h6>

                {investigation.security_headers && (
                  <div className="mb-3">
                    <strong className="text-danger">Security Headers:</strong>
                    <div className="mt-2">
                      {investigation.security_headers.missing && investigation.security_headers.missing.length > 0 && (
                        <div className="mb-2">
                          <Badge bg="warning" className="me-1">Missing:</Badge>
                          {investigation.security_headers.missing.map((header, idx) => (
                            <Badge key={idx} bg="secondary" className="me-1">{header}</Badge>
                          ))}
                        </div>
                      )}
                      {investigation.security_headers.strict_transport_security && (
                        <div className="mb-1"><small><strong>HSTS:</strong> {investigation.security_headers.strict_transport_security}</small></div>
                      )}
                      {investigation.security_headers.content_security_policy && (
                        <div className="mb-1"><small><strong>CSP:</strong> {investigation.security_headers.content_security_policy.substring(0, 100)}...</small></div>
                      )}
                      {investigation.security_headers.x_frame_options && (
                        <div className="mb-1"><small><strong>X-Frame-Options:</strong> {investigation.security_headers.x_frame_options}</small></div>
                      )}
                    </div>
                  </div>
                )}

                {investigation.technologies && investigation.technologies.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Technologies Detected:</strong><br />
                    {investigation.technologies.map((tech, idx) => (
                      <Badge key={idx} bg="info" className="me-1 mt-1">{tech}</Badge>
                    ))}
                  </div>
                )}

                {investigation.cookies && investigation.cookies.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Cookies ({investigation.cookies.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '200px', overflowY: 'auto' }}>
                      <table className="table table-dark table-sm table-bordered">
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Secure</th>
                            <th>HttpOnly</th>
                            <th>SameSite</th>
                          </tr>
                        </thead>
                        <tbody>
                          {investigation.cookies.map((cookie, idx) => (
                            <tr key={idx}>
                              <td><code>{cookie.name}</code></td>
                              <td>{cookie.secure ? <Badge bg="success">Yes</Badge> : <Badge bg="danger">No</Badge>}</td>
                              <td>{cookie.httponly ? <Badge bg="success">Yes</Badge> : <Badge bg="danger">No</Badge>}</td>
                              <td><Badge bg="secondary">{cookie.samesite || 'None'}</Badge></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {investigation.secrets && investigation.secrets.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">
                      <i className="bi bi-exclamation-triangle me-1"></i>
                      Potential Secrets Found ({investigation.secrets.length}):
                    </strong>
                    <div className="mt-2">
                      {investigation.secrets.map((secret, idx) => (
                        <div key={idx} className="mb-1">
                          <Badge bg="danger" className="me-2">{secret.type}</Badge>
                          <code className="text-white">{secret.value}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {investigation.misconfigurations && investigation.misconfigurations.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">
                      <i className="bi bi-shield-exclamation me-1"></i>
                      Misconfigurations ({investigation.misconfigurations.length}):
                    </strong>
                    <div className="mt-2">
                      {investigation.misconfigurations.map((misconfig, idx) => (
                        <div key={idx} className="mb-1">
                          <Badge bg="warning" className="me-2">{idx + 1}</Badge>
                          <small>{misconfig}</small>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {investigation.forms && investigation.forms.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Forms Found ({investigation.forms.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '200px', overflowY: 'auto' }}>
                      {investigation.forms.map((form, idx) => (
                        <div key={idx} className="mb-2 p-2 border border-secondary rounded">
                          <div>
                            <Badge bg="primary" className="me-2">{form.method}</Badge>
                            {form.action && <code className="text-white">{form.action}</code>}
                            {form.has_file && <Badge bg="warning" className="ms-2">File Upload</Badge>}
                          </div>
                          <div className="mt-1">
                            <small>Fields: {form.fields.join(', ')}</small>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {investigation.apis && investigation.apis.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">API Endpoints Found ({investigation.apis.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '150px', overflowY: 'auto' }}>
                      {investigation.apis.map((api, idx) => (
                        <div key={idx}><code className="text-white">{api}</code></div>
                      ))}
                    </div>
                  </div>
                )}

                {investigation.input_fields && investigation.input_fields.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Input Fields ({investigation.input_fields.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '150px', overflowY: 'auto' }}>
                      {investigation.input_fields.slice(0, 10).map((field, idx) => (
                        <Badge key={idx} bg="secondary" className="me-1 mb-1">
                          {field.name} ({field.type})
                        </Badge>
                      ))}
                      {investigation.input_fields.length > 10 && (
                        <Badge bg="danger">+{investigation.input_fields.length - 10} more</Badge>
                      )}
                    </div>
                  </div>
                )}

                {investigation.comments && investigation.comments.length > 0 && (
                  <div className="mb-3">
                    <strong className="text-danger">Comments Found ({investigation.comments.length}):</strong>
                    <div className="mt-2" style={{ maxHeight: '150px', overflowY: 'auto' }}>
                      {investigation.comments.slice(0, 5).map((comment, idx) => (
                        <div key={idx} className="mb-1">
                          <small className="text-muted">{comment}</small>
                        </div>
                      ))}
                      {investigation.comments.length > 5 && (
                        <Badge bg="danger">+{investigation.comments.length - 5} more</Badge>
                      )}
                    </div>
                  </div>
                )}

                {investigation.cors && (
                  <div className="mb-3">
                    <strong className="text-danger">CORS Configuration:</strong>
                    <div className="mt-2">
                      <div className="mb-1"><small><strong>Allow-Origin:</strong> {investigation.cors.allow_origin}</small></div>
                      {investigation.cors.allow_methods && (
                        <div className="mb-1"><small><strong>Allow-Methods:</strong> {investigation.cors.allow_methods}</small></div>
                      )}
                      {investigation.cors.allow_credentials && (
                        <div className="mb-1">
                          <Badge bg="warning">Credentials Enabled</Badge>
                        </div>
                      )}
                      {investigation.cors.misconfigured && investigation.cors.issues && (
                        <div className="mt-2">
                          <Badge bg="danger" className="me-2">Misconfigured</Badge>
                          {investigation.cors.issues.map((issue, idx) => (
                            <div key={idx} className="ms-3 mt-1"><small>{issue}</small></div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="row mt-3">
                  <div className="col-md-4">
                    <strong className="text-danger">Response Time:</strong><br />
                    <Badge bg="info">{investigation.response_time_ms}ms</Badge>
                  </div>
                  <div className="col-md-4">
                    <strong className="text-danger">Response Size:</strong><br />
                    <Badge bg="info">{Math.round(investigation.response_size / 1024)}KB</Badge>
                  </div>
                  <div className="col-md-4">
                    <strong className="text-danger">Server:</strong><br />
                    <code className="text-white">{investigation.server || 'N/A'}</code>
                  </div>
                </div>
              </>
            )}

            <hr style={{ borderColor: '#444' }} />
            
            <div className="row">
              <div className="col-md-6">
                <strong className="text-danger">First Seen:</strong><br />
                <small>{new Date(endpoint.first_seen).toLocaleString()}</small>
              </div>
              <div className="col-md-6">
                <strong className="text-danger">Last Seen:</strong><br />
                <small>{new Date(endpoint.last_seen).toLocaleString()}</small>
              </div>
            </div>
          </div>
          )}
        </div>
    );
  };

  return (
    <VirtualizedList
      items={endpoints}
      height="60vh"
      estimatedItemSize={64}
      itemKey={(endpoint) => endpoint.id}
      renderItem={renderEndpoint}
    />
  );
};

export default ManageEndpointsModal;
