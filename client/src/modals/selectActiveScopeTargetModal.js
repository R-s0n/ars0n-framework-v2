import { Modal, Button, Form, InputGroup, Spinner } from 'react-bootstrap';
import { useState, useMemo, useEffect, useCallback } from 'react';
import {
  FaSearch, FaTrash, FaTimes, FaExclamationTriangle, FaSort, FaSortUp, FaSortDown, FaCheck,
} from 'react-icons/fa';

// Managing scope targets.
//
// The table is per TYPE, not a single list with a type column. The three workflows produce entirely
// different things, so one set of columns cannot describe them: the old table showed Subs / Live /
// Nuclei / Impact for every row, which are the Wildcard workflow's outputs, so a Company row read as
// 0 subdomains while holding 867 live web servers, and every URL row read as four zeros while holding
// a thousand endpoints. That is why the "All" tab is gone rather than merely unselected by default:
// there is no honest set of columns for a mixed list.
//
// The columns themselves come from the server, along with the numbers, so the labels and the values
// cannot drift apart. See GetScopeTargetMetrics.

const TYPES = ['Company', 'Wildcard', 'URL'];

// What the workflow behind each type is FOR, shown under the tabs. The counts only mean something if
// you know which pipeline produced them.
const TYPE_BLURB = {
  Company: 'Maps an organisation onto the infrastructure it owns: root domains, ranges, cloud, and what answers HTTP.',
  Wildcard: 'Expands one domain into subdomains, finds which are live, and scans them.',
  URL: 'Works a single host in depth: its endpoints, its parameters, and how it responds to them.',
};

const TYPE_ICON = {
  Company: '/images/Company.png',
  Wildcard: '/images/Wildcard.png',
  URL: '/images/URL.png',
};

const ACCENT = '#dc3545';

// A number that was never produced is not zero. "Nothing recorded" and "counted and found none" are
// different states and the table says so, because four zeros on a target you have worked for a week
// reads as failure rather than as a column that does not apply.
const MetricValue = ({ value, emphasis }) => {
  if (typeof value !== 'number') {
    return <span style={{ color: 'rgba(255,255,255,0.25)' }}>&mdash;</span>;
  }
  if (value === 0) {
    return <span style={{ color: 'rgba(255,255,255,0.35)' }}>0</span>;
  }
  return (
    <span style={{
      color: emphasis ? ACCENT : '#f2f2f2',
      fontWeight: emphasis ? 700 : 500,
    }}>{value.toLocaleString()}</span>
  );
};

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
  const [type, setType] = useState(activeTarget?.type || 'Company');
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [targetsToDelete, setTargetsToDelete] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [definitions, setDefinitions] = useState({});
  const [loading, setLoading] = useState(false);

  const countOfType = useCallback(
    (t) => scopeTargets.filter((s) => s.type === t).length, [scopeTargets]);

  // One request for every target's numbers. This used to be three requests PER TARGET plus parsing
  // nuclei's entire JSON report in the browser, so eleven targets meant thirty three round trips
  // before the first row could draw.
  const loadMetrics = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/scope-target-metrics');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data.metrics || {});
        setDefinitions(data.definitions || {});
      }
    } catch {
      // The table still lists and deletes targets without its numbers, so a failure here degrades
      // to em dashes rather than to an empty modal.
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!showActiveModal) return;
    loadMetrics();
    // Open on the type being worked on. Falling back to the first type that HAS targets means a user
    // with only wildcards never opens onto an empty Company table.
    const preferred = TYPES.includes(activeTarget?.type)
      ? activeTarget.type
      : TYPES.find((t) => countOfType(t) > 0) || 'Company';
    setType(preferred);
    setSelectedTargets(new Set());
    setSearchTerm('');
  }, [showActiveModal, activeTarget, countOfType, loadMetrics]);

  const columns = useMemo(() => definitions[type] || [], [definitions, type]);

  const handleSort = (column) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      // A metric sorts biggest-first on the first click. Nobody opens this looking for the target
      // with the fewest findings.
      setSortDirection(column === 'scope_target' ? 'asc' : 'desc');
    }
  };

  const SortIcon = ({ column }) => {
    if (sortColumn !== column) {
      return <FaSort className="ms-1" style={{ opacity: 0.25, fontSize: '0.7em' }} />;
    }
    const Icon = sortDirection === 'asc' ? FaSortUp : FaSortDown;
    return <Icon className="ms-1" style={{ color: ACCENT, fontSize: '0.7em' }} />;
  };

  const visibleTargets = useMemo(() => {
    const term = searchTerm.toLowerCase();
    const filtered = scopeTargets.filter((t) =>
      t.type === type && t.scope_target.toLowerCase().includes(term));

    filtered.sort((a, b) => {
      let aVal;
      let bVal;
      if (sortColumn === 'scope_target') {
        aVal = a.scope_target.toLowerCase();
        bVal = b.scope_target.toLowerCase();
      } else {
        // A target with nothing recorded sorts as -1 so it lands below a genuine zero rather than
        // being shuffled among the targets that have actually been counted.
        aVal = metrics[a.id]?.[sortColumn] ?? -1;
        bVal = metrics[b.id]?.[sortColumn] ?? -1;
      }
      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return a.scope_target.localeCompare(b.scope_target);
    });
    return filtered;
  }, [scopeTargets, type, searchTerm, sortColumn, sortDirection, metrics]);

  const allVisibleSelected =
    visibleTargets.length > 0 && visibleTargets.every((t) => selectedTargets.has(t.id));

  const toggleTargetSelection = (targetId) => {
    setSelectedTargets((prev) => {
      const next = new Set(prev);
      if (next.has(targetId)) next.delete(targetId);
      else next.add(targetId);
      return next;
    });
  };

  const toggleAllVisible = () => {
    setSelectedTargets(allVisibleSelected ? new Set() : new Set(visibleTargets.map((t) => t.id)));
  };

  // Switching type clears the selection. Carrying it across would leave targets selected that are no
  // longer on screen, and the delete button counts them.
  const switchType = (next) => {
    setType(next);
    setSelectedTargets(new Set());
  };

  const handleBulkDelete = () => {
    if (selectedTargets.size === 0) return;
    setTargetsToDelete(scopeTargets.filter((t) => selectedTargets.has(t.id)));
    setShowDeleteConfirm(true);
  };

  const confirmDelete = () => {
    targetsToDelete.forEach((target) => handleDelete(target.id));
    setSelectedTargets(new Set());
    setShowDeleteConfirm(false);
    setTargetsToDelete([]);
  };

  const cancelDelete = () => {
    setShowDeleteConfirm(false);
    setTargetsToDelete([]);
  };

  return (
    <>
      <style>
        {`
          .form-check-input:checked {
            background-color: ${ACCENT} !important;
            border-color: ${ACCENT} !important;
          }
          .st-table { width: 100%; border-collapse: separate; border-spacing: 0; }
          .st-table th {
            position: sticky; top: 0; z-index: 2;
            background: #191919;
            border-bottom: 1px solid rgba(255,255,255,0.10);
            padding: 0.6rem 0.75rem;
            font-size: 0.68rem; font-weight: 700;
            letter-spacing: 0.09em; text-transform: uppercase;
            color: rgba(255,255,255,0.45);
            white-space: nowrap; user-select: none;
          }
          .st-table th.sortable { cursor: pointer; }
          .st-table th.sortable:hover { color: rgba(255,255,255,0.8); }
          .st-table td {
            padding: 0.6rem 0.75rem;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            vertical-align: middle;
          }
          .st-row { cursor: pointer; transition: background-color 0.12s ease; }
          .st-row:hover { background-color: rgba(220,53,69,0.07); }
          .st-row.st-active { background-color: rgba(220,53,69,0.13); }
          .st-row.st-active td:first-child { box-shadow: inset 3px 0 0 ${ACCENT}; }
          .st-num { text-align: right; font-variant-numeric: tabular-nums; }
          .st-seg {
            display: flex; gap: 0.35rem; padding: 0.3rem;
            background: rgba(255,255,255,0.04); border-radius: 0.6rem;
          }
          .st-seg button {
            flex: 1 1 0; display: flex; align-items: center; justify-content: center; gap: 0.45rem;
            padding: 0.5rem 0.5rem; border: 0; border-radius: 0.45rem;
            background: transparent; color: rgba(255,255,255,0.55);
            font-size: 0.85rem; font-weight: 600; transition: all 0.12s ease;
          }
          .st-seg button:hover { color: #fff; background: rgba(255,255,255,0.06); }
          .st-seg button.active { background: ${ACCENT}; color: #fff; }
          .st-seg .st-seg-count {
            font-size: 0.72rem; padding: 0.05rem 0.4rem; border-radius: 0.6rem;
            background: rgba(0,0,0,0.25); font-variant-numeric: tabular-nums;
          }
          .st-pill {
            font-size: 0.6rem; font-weight: 700; letter-spacing: 0.08em;
            padding: 0.1rem 0.4rem; border-radius: 0.25rem;
            background: ${ACCENT}; color: #fff;
          }
        `}
      </style>

      <Modal data-bs-theme="dark" show={showActiveModal} onHide={handleActiveModalClose} size="xl">
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">Manage Scope Targets</Modal.Title>
        </Modal.Header>

        <Modal.Body>
          <div className="st-seg mb-2">
            {TYPES.map((t) => (
              <button
                key={t}
                type="button"
                className={t === type ? 'active' : ''}
                onClick={() => switchType(t)}
              >
                <img src={TYPE_ICON[t]} alt="" style={{ width: 18, height: 18 }} />
                {t}
                <span className="st-seg-count">{countOfType(t)}</span>
              </button>
            ))}
          </div>
          <div className="text-white-50 mb-3" style={{ fontSize: '0.78rem' }}>
            {TYPE_BLURB[type]}
          </div>

          <div className="d-flex gap-2 align-items-center mb-3">
            <InputGroup style={{ maxWidth: '380px' }}>
              <InputGroup.Text><FaSearch style={{ opacity: 0.6 }} /></InputGroup.Text>
              <Form.Control
                className="custom-input"
                type="text"
                placeholder={`Search ${type.toLowerCase()} targets`}
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
              {searchTerm && (
                <Button variant="outline-secondary" onClick={() => setSearchTerm('')}>
                  <FaTimes />
                </Button>
              )}
            </InputGroup>

            <div className="ms-auto d-flex align-items-center gap-2">
              {loading && <Spinner animation="border" size="sm" variant="danger" />}
              {selectedTargets.size > 0 && (
                <Button variant="danger" size="sm" onClick={handleBulkDelete}>
                  <FaTrash className="me-1" />
                  Delete {selectedTargets.size}
                </Button>
              )}
              <span className="text-white-50" style={{ fontSize: '0.78rem' }}>
                {visibleTargets.length} of {countOfType(type)}
              </span>
            </div>
          </div>

          <div style={{ maxHeight: '52vh', overflowY: 'auto', borderRadius: '0.5rem' }}>
            <table className="st-table">
              <thead>
                <tr>
                  <th style={{ width: 42 }}>
                    <Form.Check
                      type="checkbox"
                      checked={allVisibleSelected}
                      onChange={toggleAllVisible}
                      disabled={visibleTargets.length === 0}
                    />
                  </th>
                  <th className="sortable" onClick={() => handleSort('scope_target')}>
                    Scope Target <SortIcon column="scope_target" />
                  </th>
                  {columns.map((col) => (
                    <th
                      key={col.key}
                      className="sortable st-num"
                      style={{ width: 130 }}
                      title={col.hint}
                      onClick={() => handleSort(col.key)}
                    >
                      {col.label} <SortIcon column={col.key} />
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visibleTargets.length === 0 ? (
                  <tr>
                    <td colSpan={2 + columns.length} className="text-center text-white-50 py-5">
                      {searchTerm
                        ? `No ${type} target matches "${searchTerm}".`
                        : `No ${type} targets yet. Add one to start the ${type} workflow.`}
                    </td>
                  </tr>
                ) : (
                  visibleTargets.map((target) => {
                    const isActive = activeTarget?.id === target.id;
                    const values = metrics[target.id] || {};
                    return (
                      <tr
                        key={target.id}
                        className={`st-row${isActive ? ' st-active' : ''}`}
                        onClick={() => handleActiveSelect(target)}
                      >
                        <td onClick={(e) => e.stopPropagation()}>
                          <Form.Check
                            type="checkbox"
                            checked={selectedTargets.has(target.id)}
                            onChange={() => toggleTargetSelection(target.id)}
                          />
                        </td>
                        <td>
                          <div className="d-flex align-items-center gap-2">
                            <span
                              className="font-monospace"
                              style={{ fontSize: '0.85rem', color: isActive ? '#fff' : '#e6e6e6' }}
                            >
                              {target.scope_target}
                            </span>
                            {isActive && <span className="st-pill">ACTIVE</span>}
                          </div>
                        </td>
                        {columns.map((col) => (
                          <td key={col.key} className="st-num" title={col.hint}>
                            <MetricValue value={values[col.key]} emphasis={col.emphasis} />
                          </td>
                        ))}
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="mt-2 text-white-50" style={{ fontSize: '0.72rem' }}>
            Click a row to make it the active target. A dash means nothing has been recorded for that
            column yet; a zero means it was counted and there was none.
          </div>
        </Modal.Body>

        <Modal.Footer>
          <Button variant="outline-secondary" onClick={handleActiveModalClose}>Close</Button>
          {activeTarget && (
            <Button variant="danger" onClick={handleActiveModalClose}>
              <FaCheck className="me-2" />
              Continue with {activeTarget.scope_target}
            </Button>
          )}
        </Modal.Footer>
      </Modal>

      <Modal data-bs-theme="dark" show={showDeleteConfirm} onHide={cancelDelete} centered>
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">
            <FaExclamationTriangle className="me-2" />
            Delete {targetsToDelete.length} target{targetsToDelete.length !== 1 ? 's' : ''}
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="text-white mb-3" style={{ fontSize: '0.9rem' }}>
            Everything these targets have collected goes with them: scans, consolidated results and
            findings. This cannot be undone.
          </p>
          <div
            className="p-2 rounded"
            style={{
              backgroundColor: 'rgba(220,53,69,0.08)',
              border: '1px solid rgba(220,53,69,0.35)',
              maxHeight: '200px',
              overflowY: 'auto',
            }}
          >
            {targetsToDelete.map((target) => (
              <div key={target.id} className="font-monospace text-light" style={{ fontSize: '0.8rem' }}>
                {target.scope_target}
              </div>
            ))}
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="outline-secondary" onClick={cancelDelete}>Cancel</Button>
          <Button variant="danger" onClick={confirmDelete}>
            <FaTrash className="me-2" />
            Delete {targetsToDelete.length} target{targetsToDelete.length !== 1 ? 's' : ''}
          </Button>
        </Modal.Footer>
      </Modal>
    </>
  );
}

export default SelectActiveScopeTargetModal;
