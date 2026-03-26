import { Modal, Button, Form, Spinner, ProgressBar, Badge, Table, Row, Col, ListGroup, Card, Alert, Nav, Pagination } from 'react-bootstrap';
import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { copyToClipboard } from '../utils/miscUtils';

async function fetchStatsForTarget(targetId) {
  const s = { subdomains: 0, webServers: 0, nucleiTotal: 0, nucleiImpactful: 0 };
  try {
    const [subRes, httpxRes, nucleiRes] = await Promise.all([
      fetch(`/api/consolidated-subdomains/${targetId}`).catch(() => null),
      fetch(`/api/scopetarget/${targetId}/scans/httpx`).catch(() => null),
      fetch(`/api/scopetarget/${targetId}/scans/nuclei`).catch(() => null),
    ]);

    if (subRes?.ok) {
      const data = await subRes.json();
      s.subdomains = data.count || 0;
    }

    if (httpxRes?.ok) {
      const data = await httpxRes.json();
      if (data.scans && data.scans.length > 0) {
        const latest = data.scans.reduce((a, b) =>
          new Date(b.created_at) > new Date(a.created_at) ? b : a
        );
        if (latest.result) {
          s.webServers = latest.result.split('\n').filter(l => l.trim()).length;
        }
      }
    }

    if (nucleiRes?.ok) {
      const scans = await nucleiRes.json();
      if (Array.isArray(scans)) {
        const successScans = scans.filter(sc => sc.status === 'success' && sc.result);
        if (successScans.length > 0) {
          const latest = successScans.reduce((a, b) =>
            new Date(b.created_at) > new Date(a.created_at) ? b : a
          );
          try {
            const findings = JSON.parse(latest.result);
            if (Array.isArray(findings)) {
              s.nucleiTotal = findings.length;
              s.nucleiImpactful = findings.filter(f =>
                f.info?.severity && ['critical', 'high', 'medium'].includes(f.info.severity.toLowerCase())
              ).length;
            }
          } catch {}
        }
      }
    }
  } catch {}
  return s;
}

async function fetchNucleiFindingsForTarget(targetId, targetName) {
  try {
    const res = await fetch(`/api/scopetarget/${targetId}/scans/nuclei`);
    if (!res?.ok) return [];
    const scans = await res.json();
    if (!Array.isArray(scans)) return [];
    const successScans = scans.filter(sc => sc.status === 'success' && sc.result);
    if (successScans.length === 0) return [];
    const latest = successScans.reduce((a, b) =>
      new Date(b.created_at) > new Date(a.created_at) ? b : a
    );
    const findings = typeof latest.result === 'string' ? JSON.parse(latest.result) : latest.result;
    if (!Array.isArray(findings)) return [];
    return findings.map(f => ({ ...f, _scopeTarget: targetName, _scopeTargetId: targetId }));
  } catch {
    return [];
  }
}

const FULL_STEP_SEQUENCE = [
  'amass', 'sublist3r', 'assetfinder', 'gau', 'ctl', 'subfinder',
  'consolidate', 'httpx',
  'shuffledns', 'shuffledns_cewl',
  'consolidate_round2', 'httpx_round2',
  'gospider', 'subdomainizer',
  'consolidate_round3', 'httpx_round3',
  'nuclei-screenshot', 'metadata', 'nuclei', 'completed'
];

const STEP_TO_CONFIG_KEY = {
  'amass': 'amass',
  'sublist3r': 'sublist3r',
  'assetfinder': 'assetfinder',
  'gau': 'gau',
  'ctl': 'ctl',
  'subfinder': 'subfinder',
  'consolidate': 'consolidate_httpx_round1',
  'httpx': 'consolidate_httpx_round1',
  'shuffledns': 'shuffledns',
  'shuffledns_cewl': 'cewl',
  'consolidate_round2': 'consolidate_httpx_round2',
  'httpx_round2': 'consolidate_httpx_round2',
  'gospider': 'gospider',
  'subdomainizer': 'subdomainizer',
  'consolidate_round3': 'consolidate_httpx_round3',
  'httpx_round3': 'consolidate_httpx_round3',
  'nuclei-screenshot': 'nuclei_screenshot',
  'metadata': 'metadata',
  'nuclei': 'nuclei'
};

function formatStepName(stepKey, config) {
  if (config) {
    const configKey = STEP_TO_CONFIG_KEY[stepKey];
    if (configKey && config[configKey] === false) {
      return 'Skipping...';
    }
  }
  if (!stepKey) return 'Processing';
  return stepKey
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
    .replace('Httpx', 'HTTPX')
    .replace('Sublist3r', 'Sublist3r')
    .replace('Subdomainizer', 'Subdomainizer')
    .replace('Cewl', 'CeWL')
    .replace('Ctl', 'CTL')
    .replace('Gau', 'GAU')
    .replace('Nuclei-screenshot', 'Nuclei Screenshot');
}

function computeAutoScanProgress(currentStep, config) {
  if (!config || !currentStep || currentStep === 'idle') return 0;
  if (currentStep === 'completed') return 100;

  const currentStepIndex = FULL_STEP_SEQUENCE.indexOf(currentStep);
  if (currentStepIndex === -1) return 0;

  let enabledSteps = [];
  for (const [stepName, configKey] of Object.entries(STEP_TO_CONFIG_KEY)) {
    if (config[configKey] === true) {
      if (!enabledSteps.includes(stepName) &&
          (!stepName.includes('httpx') || !enabledSteps.includes(stepName.replace('httpx', 'consolidate')))) {
        enabledSteps.push(stepName);
      }
    }
  }

  enabledSteps.sort((a, b) =>
    FULL_STEP_SEQUENCE.indexOf(a) - FULL_STEP_SEQUENCE.indexOf(b));

  if (enabledSteps.length === 0) return 0;

  let completedEnabledSteps = 0;
  for (let i = 0; i < enabledSteps.length; i++) {
    const enabledStepIndex = FULL_STEP_SEQUENCE.indexOf(enabledSteps[i]);
    if (currentStepIndex > enabledStepIndex) {
      completedEnabledSteps++;
    } else if (currentStepIndex === enabledStepIndex) {
      completedEnabledSteps += 0.5;
      break;
    } else {
      break;
    }
  }

  const progress = Math.round((completedEnabledSteps / enabledSteps.length) * 100);
  return Math.min(progress, 95);
}

function WildfireModal({
  show,
  handleClose,
  scopeTargets,
  isWildfireRunning,
  wildfireProgress,
  onStartWildfire,
  onCancelWildfire,
  setShowToast,
  autoScanCurrentStep
}) {
  const [selectedTargets, setSelectedTargets] = useState({});
  const [targetStats, setTargetStats] = useState({});
  const [loadingStats, setLoadingStats] = useState(false);
  const prevCurrentIndexRef = useRef(-1);
  const wasRunningRef = useRef(false);
  const [activeTab, setActiveTab] = useState('scan');
  const [autoScanConfig, setAutoScanConfig] = useState(null);

  // Results tab state
  const [allNucleiFindings, setAllNucleiFindings] = useState([]);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [targetFilter, setTargetFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const findingsListRef = useRef(null);
  const FINDINGS_PER_PAGE = 50;

  const wildcardTargets = (scopeTargets || []).filter(t => t.type === 'Wildcard');

  const fetchAllStats = useCallback(async () => {
    const targets = (scopeTargets || []).filter(t => t.type === 'Wildcard');
    if (targets.length === 0) return;
    setLoadingStats(true);
    const stats = {};

    await Promise.all(targets.map(async (target) => {
      stats[target.id] = await fetchStatsForTarget(target.id);
    }));

    setTargetStats(stats);
    setLoadingStats(false);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeTargets]);

  const fetchAllNucleiFindings = useCallback(async () => {
    const targets = (scopeTargets || []).filter(t => t.type === 'Wildcard');
    if (targets.length === 0) return;
    setLoadingFindings(true);
    const results = await Promise.all(
      targets.map(t => fetchNucleiFindingsForTarget(t.id, t.scope_target))
    );
    const combined = results.flat();
    setAllNucleiFindings(combined);
    setLoadingFindings(false);
    if (combined.length > 0 && !selectedFinding) {
      setSelectedFinding(combined[0]);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeTargets]);

  useEffect(() => {
    if (show) {
      fetch('/api/api/auto-scan-config')
        .then(res => res.ok ? res.json() : null)
        .then(data => { if (data) setAutoScanConfig(data); })
        .catch(() => {});
    }
  }, [show]);

  useEffect(() => {
    if (show && !isWildfireRunning) {
      const allSelected = {};
      wildcardTargets.forEach(t => {
        allSelected[t.id] = true;
      });
      setSelectedTargets(allSelected);
      fetchAllStats();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [show, scopeTargets]);

  useEffect(() => {
    if (show && activeTab === 'results') {
      fetchAllNucleiFindings();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, show]);

  useEffect(() => {
    if (!isWildfireRunning && wasRunningRef.current && show) {
      fetchAllStats();
      if (activeTab === 'results') {
        fetchAllNucleiFindings();
      }
    }
    wasRunningRef.current = isWildfireRunning;
  }, [isWildfireRunning, show, fetchAllStats, fetchAllNucleiFindings, activeTab]);

  useEffect(() => {
    if (!wildfireProgress || !isWildfireRunning) {
      prevCurrentIndexRef.current = -1;
      return;
    }

    const currentIdx = wildfireProgress.currentIndex;
    const prevIdx = prevCurrentIndexRef.current;

    if (currentIdx > prevIdx && prevIdx >= 0) {
      const completedTarget = wildfireProgress.targets[prevIdx];
      if (completedTarget) {
        fetchStatsForTarget(completedTarget.id).then(stats => {
          setTargetStats(prev => ({ ...prev, [completedTarget.id]: stats }));
        });
      }
    }

    prevCurrentIndexRef.current = currentIdx;
  }, [wildfireProgress, isWildfireRunning]);

  const handleToggle = (id) => {
    if (isWildfireRunning) return;
    setSelectedTargets(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleSelectAll = () => {
    if (isWildfireRunning) return;
    const allSelected = {};
    wildcardTargets.forEach(t => { allSelected[t.id] = true; });
    setSelectedTargets(allSelected);
  };

  const handleDeselectAll = () => {
    if (isWildfireRunning) return;
    setSelectedTargets({});
  };

  const selectedCount = Object.values(selectedTargets).filter(Boolean).length;

  const handleStart = () => {
    const targets = wildcardTargets.filter(t => selectedTargets[t.id]);
    if (targets.length === 0) return;
    onStartWildfire(targets);
  };

  const currentTargetName = wildfireProgress?.currentTarget?.scope_target
    ? wildfireProgress.currentTarget.scope_target.replace('*.', '')
    : '';

  const renderStatCell = (value, colorClass) => {
    if (value === undefined || value === null) return <span className="text-muted">-</span>;
    return <span className={value > 0 ? colorClass : 'text-muted'}>{value}</span>;
  };

  // --- Results tab helpers ---

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };

  const getSeverityBadge = (severity) => {
    const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success', info: 'secondary' };
    return map[severity?.toLowerCase()] || 'secondary';
  };

  const getSeverityIcon = (severity) => {
    const map = { critical: 'exclamation-triangle-fill', high: 'exclamation-triangle', medium: 'exclamation-circle', low: 'info-circle', info: 'info-circle-fill' };
    return map[severity?.toLowerCase()] || 'info-circle';
  };

  const availableTargetNames = useMemo(() => {
    const names = new Set();
    allNucleiFindings.forEach(f => { if (f._scopeTarget) names.add(f._scopeTarget); });
    return Array.from(names).sort();
  }, [allNucleiFindings]);

  const filteredFindings = useMemo(() => {
    let filtered = [...allNucleiFindings];

    // Sort: impactful first (critical > high > medium > low > info)
    filtered.sort((a, b) => {
      const sa = severityOrder[a.info?.severity?.toLowerCase()] ?? 5;
      const sb = severityOrder[b.info?.severity?.toLowerCase()] ?? 5;
      return sa - sb;
    });

    if (searchTerm) {
      const isNeg = searchTerm.startsWith('-');
      const val = (isNeg ? searchTerm.substring(1) : searchTerm).toLowerCase();
      filtered = filtered.filter(f => {
        const text = [
          f.info?.name || '', f.host || '', f.matched || '', f['template-id'] || '',
          f.info?.description || '', f.info?.tags?.join(' ') || '', f._scopeTarget || ''
        ].join(' ').toLowerCase();
        const matches = text.includes(val);
        return isNeg ? !matches : matches;
      });
    }

    if (severityFilter !== 'all') {
      filtered = filtered.filter(f => {
        const s = f.info?.severity?.toLowerCase() || 'info';
        return s === severityFilter || (s === 'unknown' && severityFilter === 'info');
      });
    }

    if (targetFilter !== 'all') {
      filtered = filtered.filter(f => f._scopeTarget === targetFilter);
    }

    return filtered;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allNucleiFindings, searchTerm, severityFilter, targetFilter]);

  const groupBySeverity = (list) => {
    const grouped = {};
    list.forEach(f => {
      let s = f.info?.severity?.toLowerCase() || 'info';
      if (s === 'unknown') s = 'info';
      if (!grouped[s]) grouped[s] = [];
      grouped[s].push(f);
    });
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const sorted = {};
    order.forEach(s => { if (grouped[s]) sorted[s] = grouped[s]; });
    return sorted;
  };

  const totalPages = Math.ceil(filteredFindings.length / FINDINGS_PER_PAGE);

  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * FINDINGS_PER_PAGE;
    return filteredFindings.slice(start, start + FINDINGS_PER_PAGE);
  }, [filteredFindings, currentPage]);

  const paginatedGrouped = useMemo(() => groupBySeverity(paginatedFindings), [paginatedFindings]);

  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(totalPages);
    }
  }, [totalPages, currentPage]);

  const handleCopyFinding = async (finding) => {
    try {
      const exportText =
        `[${finding.info?.severity?.toUpperCase() || 'INFO'}] ${finding.info?.name || 'Unknown'}\n` +
        `Scope Target: ${finding._scopeTarget || 'N/A'}\n` +
        `Template: ${finding['template-id'] || 'N/A'}\n` +
        `Target: ${finding.host || finding.matched || 'N/A'}\n` +
        `Matcher: ${finding['matcher-name'] || 'N/A'}\n` +
        `${finding.info?.description ? `Description: ${finding.info.description}\n` : ''}` +
        `${finding['curl-command'] ? `Curl Command: ${finding['curl-command']}\n` : ''}`;
      const success = await copyToClipboard(exportText);
      if (success && setShowToast) {
        setShowToast(true);
        setTimeout(() => setShowToast(false), 3000);
      }
    } catch {}
  };

  const isFindingSelected = (finding) => {
    if (!selectedFinding) return false;
    return selectedFinding.info?.name === finding.info?.name &&
      selectedFinding.host === finding.host &&
      selectedFinding['template-id'] === finding['template-id'] &&
      selectedFinding.matched === finding.matched &&
      selectedFinding['matched-at'] === finding['matched-at'] &&
      selectedFinding.timestamp === finding.timestamp &&
      selectedFinding._scopeTargetId === finding._scopeTargetId;
  };

  const renderResultsPagination = () => {
    if (totalPages <= 1) return null;
    const maxPages = 7;
    let startPage = Math.max(1, currentPage - Math.floor(maxPages / 2));
    let endPage = Math.min(totalPages, startPage + maxPages - 1);
    if (endPage - startPage < maxPages - 1) startPage = Math.max(1, endPage - maxPages + 1);
    const pages = [];
    for (let i = startPage; i <= endPage; i++) {
      pages.push(
        <Pagination.Item key={i} active={i === currentPage} onClick={() => { setCurrentPage(i); if (findingsListRef.current) findingsListRef.current.scrollTop = 0; }}>
          {i}
        </Pagination.Item>
      );
    }
    return (
      <div className="d-flex justify-content-center align-items-center my-2">
        <Pagination size="sm" className="mb-0">
          <Pagination.First onClick={() => setCurrentPage(1)} disabled={currentPage === 1} />
          <Pagination.Prev onClick={() => setCurrentPage(Math.max(1, currentPage - 1))} disabled={currentPage === 1} />
          {startPage > 1 && (<><Pagination.Item onClick={() => setCurrentPage(1)}>1</Pagination.Item>{startPage > 2 && <Pagination.Ellipsis disabled />}</>)}
          {pages}
          {endPage < totalPages && (<>{endPage < totalPages - 1 && <Pagination.Ellipsis disabled />}<Pagination.Item onClick={() => setCurrentPage(totalPages)}>{totalPages}</Pagination.Item></>)}
          <Pagination.Next onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))} disabled={currentPage === totalPages} />
          <Pagination.Last onClick={() => setCurrentPage(totalPages)} disabled={currentPage === totalPages} />
        </Pagination>
        <div className="ms-3">
          <small className="text-muted">
            Showing {((currentPage - 1) * FINDINGS_PER_PAGE) + 1}-{Math.min(currentPage * FINDINGS_PER_PAGE, filteredFindings.length)} of {filteredFindings.length}
          </small>
        </div>
      </div>
    );
  };

  const renderResultsFindingsList = () => {
    if (loadingFindings) {
      return (
        <div className="text-center py-5">
          <Spinner animation="border" variant="danger" />
          <p className="text-muted mt-2">Loading findings from all targets...</p>
        </div>
      );
    }

    if (filteredFindings.length === 0) {
      return (
        <div className="text-center text-muted p-4">
          <i className="bi bi-search fs-1 mb-3 d-block"></i>
          <p>{allNucleiFindings.length === 0 ? 'No Nuclei findings across any wildcard target.' : 'No findings match the current filters.'}</p>
        </div>
      );
    }

    return (
      <>
        <div ref={findingsListRef} style={{ height: '65vh', overflowY: 'auto' }}>
          {Object.entries(paginatedGrouped).map(([severity, severityFindings]) => (
            <div key={severity} className="mb-3">
              <div className="d-flex align-items-center mb-2">
                <Badge bg={getSeverityBadge(severity)} className="me-2">
                  {severity.toUpperCase()}
                </Badge>
                <small className="text-muted">
                  {severityFindings.length} finding{severityFindings.length !== 1 ? 's' : ''} on this page
                </small>
              </div>
              <ListGroup variant="flush">
                {severityFindings.map((finding, index) => {
                  const isSelected = isFindingSelected(finding);
                  return (
                    <ListGroup.Item
                      key={`${severity}-${index}-${finding['template-id']}-${finding.host}`}
                      action
                      active={isSelected}
                      onClick={() => setSelectedFinding(finding)}
                      className="py-2 border-0 mb-1"
                      style={{
                        backgroundColor: isSelected ?
                          (severity === 'critical' ? 'rgba(220, 53, 69, 0.25)' :
                           severity === 'high' ? 'rgba(255, 193, 7, 0.25)' :
                           severity === 'medium' ? 'rgba(13, 202, 240, 0.25)' :
                           severity === 'low' ? 'rgba(25, 135, 84, 0.25)' :
                           'rgba(108, 117, 125, 0.25)') :
                          'rgba(255, 255, 255, 0.05)',
                        borderRadius: '4px',
                        border: isSelected ?
                          (severity === 'critical' ? '2px solid #dc3545' :
                           severity === 'high' ? '2px solid #ffc107' :
                           severity === 'medium' ? '2px solid #0dcaf0' :
                           severity === 'low' ? '2px solid #198754' :
                           '2px solid #6c757d') :
                          '2px solid transparent'
                      }}
                    >
                      <div className="d-flex align-items-start">
                        <i className={`bi bi-${getSeverityIcon(severity)} text-${getSeverityBadge(severity) === 'danger' ? 'danger' : getSeverityBadge(severity) === 'warning' ? 'warning' : 'info'} me-2 mt-1`}></i>
                        <div className="flex-grow-1">
                          <div className="fw-bold">
                            {finding.info?.name || finding['template-id'] || 'Unknown'}
                          </div>
                          <div className="text-muted small">
                            {finding.host || finding.matched || 'Unknown target'}
                          </div>
                          <div className="d-flex align-items-center gap-2">
                            <span className="text-muted small">{finding['template-id']}</span>
                            <Badge bg="dark" className="text-danger small" style={{ fontSize: '0.7em' }}>
                              {finding._scopeTarget ? finding._scopeTarget.replace('*.', '') : ''}
                            </Badge>
                          </div>
                          <div className="text-info small">
                            <i className="bi bi-gear me-1"></i>
                            {finding['matcher-name'] || 'N/A'}
                          </div>
                        </div>
                      </div>
                    </ListGroup.Item>
                  );
                })}
              </ListGroup>
            </div>
          ))}
        </div>
        {renderResultsPagination()}
      </>
    );
  };

  const renderResultsFindingDetails = () => {
    if (!selectedFinding) {
      return (
        <div className="text-center text-muted p-4">
          <i className="bi bi-arrow-left fs-1 mb-3 d-block"></i>
          <p>Select a finding from the left to view details</p>
        </div>
      );
    }

    const finding = selectedFinding;
    const severity = finding.info?.severity?.toLowerCase() || 'info';

    return (
      <div style={{ height: '75vh', overflowY: 'auto' }}>
        <Card className="bg-dark border-secondary">
          <Card.Header className="d-flex justify-content-between align-items-center">
            <div className="d-flex align-items-center">
              <Badge bg={getSeverityBadge(severity)} className="me-2">
                {severity.toUpperCase()}
              </Badge>
              <span className="fw-bold">{finding.info?.name || finding['template-id'] || 'Unknown'}</span>
            </div>
            <Button variant="outline-light" size="sm" onClick={() => handleCopyFinding(finding)} title="Copy finding details">
              <i className="bi bi-clipboard"></i>
            </Button>
          </Card.Header>
          <Card.Body>
            <div className="mb-3">
              <Badge bg="dark" className="text-danger border border-danger">
                <i className="bi bi-fire me-1"></i>
                {finding._scopeTarget ? finding._scopeTarget.replace('*.', '') : 'Unknown'}
              </Badge>
            </div>

            <Row>
              <Col md={6}>
                <div className="mb-3">
                  <h6 className="text-light mb-2">
                    <i className="bi bi-bullseye me-2"></i>Target
                  </h6>
                  <div className="bg-secondary rounded p-2">
                    <div className="text-light">{finding.host || finding.matched || 'Unknown'}</div>
                    {finding.ip && finding.ip !== finding.host && (
                      <div className="text-muted small">IP: {finding.ip}</div>
                    )}
                    {finding.port && (
                      <div className="text-muted small">Port: {finding.port}</div>
                    )}
                    <div className="text-muted small">Matched At: {finding['matched-at'] || 'N/A'}</div>
                  </div>
                </div>
              </Col>
              <Col md={6}>
                <div className="mb-3">
                  <h6 className="text-light mb-2">
                    <i className="bi bi-file-code me-2"></i>Template
                  </h6>
                  <div className="bg-secondary rounded p-2">
                    <div className="text-light">{finding['template-id'] || 'Unknown'}</div>
                    {finding.type && (
                      <div className="text-muted small">Type: {finding.type}</div>
                    )}
                    <div className="text-info small fw-bold">Matcher: {finding['matcher-name'] || 'N/A'}</div>
                    <div className="text-muted small">Matcher Status:
                      <Badge bg={finding['matcher-status'] ? 'success' : 'danger'} className="ms-1">
                        {finding['matcher-status'] ? 'True' : 'False'}
                      </Badge>
                    </div>
                  </div>
                </div>
              </Col>
            </Row>

            {finding.timestamp && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-clock me-2"></i>Timestamp
                </h6>
                <div className="bg-secondary rounded p-2">
                  <div className="text-light">{new Date(finding.timestamp).toLocaleString()}</div>
                  <div className="text-muted small">{finding.timestamp}</div>
                </div>
              </div>
            )}

            {finding.info?.description && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-info-circle me-2"></i>Description
                </h6>
                <Alert variant="info" className="mb-0">
                  {finding.info.description}
                </Alert>
              </div>
            )}

            {finding.info?.reference && finding.info.reference.length > 0 && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-link-45deg me-2"></i>References
                </h6>
                <div className="bg-secondary rounded p-2">
                  {finding.info.reference.map((ref, index) => (
                    <div key={index} className="mb-1">
                      <a href={ref} target="_blank" rel="noopener noreferrer" className="text-info text-decoration-none">
                        <i className="bi bi-link-45deg me-1"></i>{ref}
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {finding.info?.tags && finding.info.tags.length > 0 && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-tags me-2"></i>Tags
                </h6>
                <div>
                  {finding.info.tags.map((tag, index) => (
                    <Badge key={index} bg="secondary" className="me-1 mb-1">{tag}</Badge>
                  ))}
                </div>
              </div>
            )}

            {finding.info?.classification && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-diagram-3 me-2"></i>Classification
                </h6>
                <div className="bg-secondary rounded p-2">
                  {Object.entries(finding.info.classification).map(([key, value]) => (
                    <div key={key} className="mb-1">
                      <span className="text-muted">{key.toUpperCase()}:</span>
                      <span className="text-light ms-2">{Array.isArray(value) ? value.join(', ') : value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="mb-3">
              <h6 className="text-light mb-2">
                <i className="bi bi-search me-2"></i>Extracted Results
              </h6>
              <div className="bg-secondary rounded p-2">
                {finding['extracted-results'] && finding['extracted-results'].length > 0 ? (
                  finding['extracted-results'].map((result, index) => (
                    <div key={index} className="mb-2">
                      <div className="text-muted small mb-1">Result {index + 1}:</div>
                      <code className="text-warning d-block p-2 bg-dark rounded">{result}</code>
                    </div>
                  ))
                ) : (
                  <div className="text-muted">No extracted results</div>
                )}
              </div>
            </div>

            {finding['curl-command'] && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-terminal me-2"></i>Curl Command
                </h6>
                <div className="bg-dark rounded p-2">
                  <code className="text-success small">{finding['curl-command']}</code>
                </div>
              </div>
            )}

            {finding.request && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-arrow-up me-2"></i>Request
                </h6>
                <div className="bg-dark rounded p-2">
                  <pre className="text-info small mb-0" style={{ whiteSpace: 'pre-wrap' }}>{finding.request}</pre>
                </div>
              </div>
            )}

            {finding.response && (
              <div className="mb-3">
                <h6 className="text-light mb-2">
                  <i className="bi bi-arrow-down me-2"></i>Response
                </h6>
                <div className="bg-dark rounded p-2">
                  <pre className="text-success small mb-0" style={{ whiteSpace: 'pre-wrap' }}>{finding.response}</pre>
                </div>
              </div>
            )}
          </Card.Body>
        </Card>
      </div>
    );
  };

  const renderResultsTab = () => {
    return (
      <div>
        <div className="bg-dark border-bottom px-3 py-3">
          <Row className="g-2">
            <Col md={4}>
              <div className="input-group input-group-sm">
                <span className="input-group-text bg-secondary border-secondary">
                  <i className="bi bi-search"></i>
                </span>
                <input
                  type="text"
                  className="form-control bg-dark text-light border-secondary"
                  placeholder="Search findings (use -term to exclude)"
                  value={searchTerm}
                  onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                />
                {searchTerm && (
                  <button className="btn btn-outline-secondary btn-sm" onClick={() => { setSearchTerm(''); setCurrentPage(1); }}>
                    <i className="bi bi-x"></i>
                  </button>
                )}
              </div>
            </Col>
            <Col md={2}>
              <select
                className="form-select form-select-sm bg-dark text-light border-secondary"
                value={severityFilter}
                onChange={(e) => { setSeverityFilter(e.target.value); setCurrentPage(1); }}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </Col>
            <Col md={3}>
              <select
                className="form-select form-select-sm bg-dark text-light border-secondary"
                value={targetFilter}
                onChange={(e) => { setTargetFilter(e.target.value); setCurrentPage(1); }}
              >
                <option value="all">All Targets</option>
                {availableTargetNames.map(name => (
                  <option key={name} value={name}>{name.replace('*.', '')}</option>
                ))}
              </select>
            </Col>
            <Col md={3}>
              <div className="d-flex justify-content-between align-items-center h-100">
                <small className="text-muted">
                  {filteredFindings.length} of {allNucleiFindings.length} findings
                </small>
                <div className="d-flex gap-2">
                  <Button
                    variant="outline-secondary"
                    size="sm"
                    onClick={() => { setSearchTerm(''); setSeverityFilter('all'); setTargetFilter('all'); setCurrentPage(1); }}
                    disabled={!searchTerm && severityFilter === 'all' && targetFilter === 'all'}
                    title="Clear all filters"
                  >
                    <i className="bi bi-x-circle"></i>
                  </Button>
                  <Button variant="outline-danger" size="sm" onClick={fetchAllNucleiFindings} title="Refresh findings">
                    <i className="bi bi-arrow-clockwise"></i>
                  </Button>
                </div>
              </div>
            </Col>
          </Row>
        </div>
        <Row className="g-0">
          <Col md={4} className="border-end">
            <div className="p-3">
              <div className="d-flex justify-content-between align-items-center mb-3">
                <h6 className="text-light mb-0">
                  <i className="bi bi-list-ul me-2"></i>Findings
                </h6>
                <small className="text-muted">
                  <i className="bi bi-keyboard me-1"></i>Use arrow keys
                </small>
              </div>
              {renderResultsFindingsList()}
            </div>
          </Col>
          <Col md={8}>
            <div className="p-3">
              <h6 className="text-light mb-3">
                <i className="bi bi-info-circle me-2"></i>Details
              </h6>
              {renderResultsFindingDetails()}
            </div>
          </Col>
        </Row>
      </div>
    );
  };

  const renderScanTab = () => {
    if (isWildfireRunning && wildfireProgress) {
      const stepPercent = computeAutoScanProgress(autoScanCurrentStep, autoScanConfig);
      const stepLabel = formatStepName(autoScanCurrentStep, autoScanConfig);
      const isStepCompleted = autoScanCurrentStep === 'completed';
      const isStepIdle = !autoScanCurrentStep || autoScanCurrentStep === 'idle';

      return (
        <div className="p-3">
          <div className="mb-3">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <span className="text-white">
                Scanning target {wildfireProgress.currentIndex + 1} of {wildfireProgress.totalTargets}
              </span>
              <Badge bg="danger">{currentTargetName}</Badge>
            </div>
            <ProgressBar
              now={((wildfireProgress.currentIndex) / wildfireProgress.totalTargets) * 100}
              variant="danger"
              animated
              className="mb-3"
            />
          </div>

          <div className="mb-3 p-3 rounded" style={{ backgroundColor: 'rgba(220, 53, 69, 0.1)', border: '1px solid rgba(220, 53, 69, 0.3)' }}>
            <div className="d-flex justify-content-between align-items-center mb-2">
              <div className="d-flex align-items-center">
                {!isStepCompleted && !isStepIdle && <Spinner animation="border" size="sm" variant="danger" className="me-2" />}
                <span className="text-white-50 small me-2">
                  {isStepCompleted ? (
                    <><span className="text-success">●</span> Scan completed</>
                  ) : isStepIdle ? (
                    <><span className="text-secondary">●</span> Starting...</>
                  ) : (
                    <><span className="text-danger">●</span> Running {stepLabel}</>
                  )}
                </span>
              </div>
              <span className="text-white small">
                {stepPercent}%
              </span>
            </div>
            <ProgressBar
              now={stepPercent}
              variant="danger"
              animated={!isStepCompleted && !isStepIdle}
              className="bg-dark"
              style={{ height: '8px' }}
            />
          </div>

          <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
            <Table bordered variant="dark" size="sm">
              <thead style={{ position: 'sticky', top: 0, backgroundColor: '#212529', zIndex: 1 }}>
                <tr>
                  <th style={{ width: '30px' }}></th>
                  <th>Target</th>
                  <th style={{ width: '70px', textAlign: 'center' }}>Subs</th>
                  <th style={{ width: '70px', textAlign: 'center' }}>Live</th>
                  <th style={{ width: '70px', textAlign: 'center' }}>Nuclei</th>
                  <th style={{ width: '80px', textAlign: 'center' }}>Impact</th>
                </tr>
              </thead>
              <tbody>
                {wildfireProgress.targets.map((t, idx) => {
                  let statusIcon = 'bi-hourglass';
                  let statusColor = 'text-secondary';
                  const isCompleted = idx < wildfireProgress.currentIndex;
                  const isCurrent = idx === wildfireProgress.currentIndex;
                  if (isCompleted) {
                    statusIcon = 'bi-check-circle-fill';
                    statusColor = 'text-success';
                  } else if (isCurrent) {
                    statusIcon = 'bi-arrow-right-circle-fill';
                    statusColor = 'text-danger';
                  }
                  const stats = targetStats[t.id];
                  return (
                    <tr key={t.id}>
                      <td className={`text-center ${statusColor}`}>
                        {isCurrent ? (
                          <Spinner animation="border" size="sm" variant="danger" />
                        ) : (
                          <i className={`bi ${statusIcon}`}></i>
                        )}
                      </td>
                      <td className={`font-monospace small ${statusColor}`}>
                        {t.scope_target.replace('*.', '')}
                      </td>
                      <td className="text-center">
                        {isCompleted ? renderStatCell(stats?.subdomains, 'text-white') : <span className="text-muted">-</span>}
                      </td>
                      <td className="text-center">
                        {isCompleted ? renderStatCell(stats?.webServers, 'text-info') : <span className="text-muted">-</span>}
                      </td>
                      <td className="text-center">
                        {isCompleted ? renderStatCell(stats?.nucleiTotal, 'text-warning') : <span className="text-muted">-</span>}
                      </td>
                      <td className="text-center">
                        {isCompleted ? renderStatCell(stats?.nucleiImpactful, 'text-danger fw-bold') : <span className="text-muted">-</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          </div>
        </div>
      );
    }

    return (
      <div className="p-3">
        <p className="text-white-50 mb-3">
          Wildfire will run Auto Scan on each selected Wildcard target sequentially using the current Auto Scan configuration.
        </p>

        {wildcardTargets.length === 0 ? (
          <div className="text-center text-white-50 py-4">
            No Wildcard scope targets found. Add Wildcard targets first.
          </div>
        ) : (
          <>
            <div className="d-flex justify-content-between align-items-center mb-2">
              <span className="text-danger">
                {selectedCount} of {wildcardTargets.length} targets selected
              </span>
              <div>
                <Button variant="link" size="sm" className="text-danger p-0 me-3" onClick={handleSelectAll}>
                  Select All
                </Button>
                <Button variant="link" size="sm" className="text-secondary p-0" onClick={handleDeselectAll}>
                  Deselect All
                </Button>
              </div>
            </div>

            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
              <Table striped bordered hover variant="dark" size="sm">
                <thead style={{ position: 'sticky', top: 0, backgroundColor: '#212529', zIndex: 1 }}>
                  <tr>
                    <th style={{ width: '40px' }}></th>
                    <th>Target</th>
                    <th style={{ width: '70px', textAlign: 'center' }}>Subs</th>
                    <th style={{ width: '70px', textAlign: 'center' }}>Live</th>
                    <th style={{ width: '70px', textAlign: 'center' }}>Nuclei</th>
                    <th style={{ width: '80px', textAlign: 'center' }}>Impact</th>
                  </tr>
                </thead>
                <tbody>
                  {wildcardTargets.map(target => {
                    const stats = targetStats[target.id];
                    return (
                      <tr key={target.id} style={{ cursor: 'pointer' }} onClick={() => handleToggle(target.id)}>
                        <td onClick={(e) => e.stopPropagation()}>
                          <Form.Check
                            type="checkbox"
                            id={`wildfire-${target.id}`}
                            checked={!!selectedTargets[target.id]}
                            onChange={() => handleToggle(target.id)}
                            disabled={isWildfireRunning}
                          />
                        </td>
                        <td className="font-monospace small text-danger">
                          {target.scope_target.replace('*.', '')}
                        </td>
                        <td className="text-center">
                          {loadingStats ? <Spinner animation="border" size="sm" variant="secondary" /> :
                            <span className={stats?.subdomains > 0 ? 'text-white' : 'text-muted'}>{stats?.subdomains || 0}</span>
                          }
                        </td>
                        <td className="text-center">
                          {loadingStats ? <Spinner animation="border" size="sm" variant="secondary" /> :
                            <span className={stats?.webServers > 0 ? 'text-info' : 'text-muted'}>{stats?.webServers || 0}</span>
                          }
                        </td>
                        <td className="text-center">
                          {loadingStats ? <Spinner animation="border" size="sm" variant="secondary" /> :
                            <span className={stats?.nucleiTotal > 0 ? 'text-warning' : 'text-muted'}>{stats?.nucleiTotal || 0}</span>
                          }
                        </td>
                        <td className="text-center">
                          {loadingStats ? <Spinner animation="border" size="sm" variant="secondary" /> :
                            <span className={stats?.nucleiImpactful > 0 ? 'text-danger fw-bold' : 'text-muted'}>{stats?.nucleiImpactful || 0}</span>
                          }
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>
            </div>
          </>
        )}
      </div>
    );
  };

  return (
    <Modal
      show={show}
      onHide={handleClose}
      data-bs-theme="dark"
      size="xl"
      dialogClassName="modal-fullscreen"
      style={{ margin: 0 }}
    >
      <Modal.Header closeButton className="border-secondary">
        <Modal.Title className="text-danger d-flex align-items-center">
          <i className="bi bi-fire me-2"></i>
          Wildfire Scan
        </Modal.Title>
      </Modal.Header>
      <div className="bg-dark border-bottom border-secondary px-3">
        <Nav variant="tabs" activeKey={activeTab} onSelect={setActiveTab} className="border-0">
          <Nav.Item>
            <Nav.Link eventKey="scan" className={activeTab === 'scan' ? 'text-danger border-danger' : 'text-white-50'}>
              <i className="bi bi-fire me-1"></i>Scan
            </Nav.Link>
          </Nav.Item>
          <Nav.Item>
            <Nav.Link eventKey="results" className={activeTab === 'results' ? 'text-danger border-danger' : 'text-white-50'}>
              <i className="bi bi-shield-exclamation me-1"></i>
              Nuclei Results
              {allNucleiFindings.length > 0 && (
                <Badge bg="danger" className="ms-2">{allNucleiFindings.length}</Badge>
              )}
            </Nav.Link>
          </Nav.Item>
        </Nav>
      </div>
      <Modal.Body className="bg-dark p-0">
        {activeTab === 'scan' ? renderScanTab() : renderResultsTab()}
      </Modal.Body>
      <Modal.Footer className="border-secondary">
        {isWildfireRunning && activeTab === 'scan' ? (
          <>
            <Button variant="outline-secondary" onClick={handleClose}>
              Minimize
            </Button>
            <Button variant="outline-danger" onClick={onCancelWildfire}>
              Cancel Wildfire
            </Button>
          </>
        ) : (
          <>
            <Button variant="outline-secondary" onClick={handleClose}>
              Close
            </Button>
            {activeTab === 'scan' && (
              <Button
                variant="outline-danger"
                onClick={handleStart}
                disabled={selectedCount === 0 || isWildfireRunning}
              >
                <i className="bi bi-fire me-1"></i>
                Start Wildfire ({selectedCount} targets)
              </Button>
            )}
          </>
        )}
      </Modal.Footer>
    </Modal>
  );
}

export default WildfireModal;
