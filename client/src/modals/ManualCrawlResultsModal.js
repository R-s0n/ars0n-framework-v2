import React, { useState, useEffect } from 'react';
import { Modal, Button, ButtonGroup, Accordion, Badge, Alert, Spinner, Tabs, Tab } from 'react-bootstrap';

const ManualCrawlResultsModal = ({ show, onHide, scopeTargetId }) => {
  const [sessions, setSessions] = useState([]);
  const [captures, setCaptures] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('endpoints');
  const [allSessions, setAllSessions] = useState([]);
  const [copiedId, setCopiedId] = useState(null);
  // Direct = the scope target's own host. Adjacent = any other in-scope host, which is where an
  // application's API normally lives, so it gets its own view rather than being mixed in.
  const [scopeFilter, setScopeFilter] = useState('all');
  // The hosts this crawl observed, and what the framework is allowed to do with each.
  const [hosts, setHosts] = useState([]);
  const [scopeDescription, setScopeDescription] = useState('');
  const [hostsBusy, setHostsBusy] = useState(false);
  const [hostNotice, setHostNotice] = useState('');
  // Scope RULES: the pattern boundary. Once any rule exists it replaces the per-host in_scope
  // toggles below entirely, which the UI has to say out loud or the two look like they combine.
  const [scopeRules, setScopeRules] = useState([]);
  const [rulesActive, setRulesActive] = useState(false);
  const [ruleInput, setRuleInput] = useState('');
  const [rulePreview, setRulePreview] = useState(null);
  const [ruleBusy, setRuleBusy] = useState(false);
  const [ruleError, setRuleError] = useState('');

  useEffect(() => {
    if (show && scopeTargetId) {
      loadSessions();
      loadAllSessions();
      loadAllCaptures();
      loadHosts();
      loadScopeRules();
    }
  }, [show, scopeTargetId]);

  // Debounced so a preview request is not sent per keystroke. The preview comes from the server
  // because that is the evaluator which will actually enforce the rule; a sentence computed here
  // could differ from the enforced boundary, and a preview that disagrees is worse than none.
  useEffect(() => {
    if (!show) return undefined;
    const typed = ruleInput.trim();
    if (!typed) { setRulePreview(null); return undefined; }
    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const res = await fetch('/api/scope-rules/preview', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scope_target_id: scopeTargetId, typed }),
        });
        const body = await res.json();
        if (!cancelled) setRulePreview(body);
      } catch (err) {
        if (!cancelled) setRulePreview(null);
      }
    }, 300);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [ruleInput, show, scopeTargetId]);

  const handleRefresh = () => {
    loadSessions();
    loadAllSessions();
    loadAllCaptures();
    loadHosts();
    loadScopeRules();
  };

  const loadScopeRules = async () => {
    try {
      const response = await fetch(`/api/scope-rules/${scopeTargetId}`);
      if (!response.ok) return;
      const data = await response.json();
      setScopeRules(data.rules || []);
      setRulesActive(!!data.rules_active);
    } catch (err) {
      console.error('Error loading scope rules:', err);
    }
  };

  const addScopeRule = async () => {
    const typed = ruleInput.trim();
    if (!typed) return;
    setRuleBusy(true);
    setRuleError('');

    const send = (confirmWide) => fetch('/api/scope-rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scope_target_id: scopeTargetId, typed, confirm_wide: confirmWide || '' }),
    });

    try {
      let res = await send('');
      if (res.status === 428) {
        // A rule that can admit hosts nobody has seen is stored only on a second, deliberate act.
        // The confirmation is the rule's own canonical text, so an operator cannot confirm a
        // different rule from the one in front of them.
        const message = await res.text();
        const canonical = (message.match(/confirm_wide exactly as "([^"]+)"/) || [])[1];
        if (!canonical || !window.confirm(`${message}\n\nAdd it anyway?`)) {
          setRuleError('Not added. Add "within <domain>" to bound it.');
          setRuleBusy(false);
          return;
        }
        res = await send(canonical);
      }
      if (!res.ok) {
        setRuleError((await res.text()) || `Framework returned ${res.status}`);
        setRuleBusy(false);
        return;
      }
      setRuleInput('');
      setRulePreview(null);
      await loadScopeRules();
      await loadHosts();
    } catch (err) {
      setRuleError(err.message);
    } finally {
      setRuleBusy(false);
    }
  };

  const removeScopeRule = async (ruleId) => {
    setRuleBusy(true);
    try {
      await fetch(`/api/scope-rules/${ruleId}`, { method: 'DELETE' });
      await loadScopeRules();
      await loadHosts();
    } catch (err) {
      setRuleError(err.message);
    } finally {
      setRuleBusy(false);
    }
  };

  const loadHosts = async () => {
    try {
      const response = await fetch(`/api/manual-crawl/hosts/${scopeTargetId}`);
      if (!response.ok) return;
      const data = await response.json();
      setHosts(data.hosts || []);
      setScopeDescription(data.scope || '');
    } catch (err) {
      console.error('Error loading crawl hosts:', err);
    }
  };

  // Both host actions reload rather than patching local state, because the scope description the
  // header shows is computed server-side and would otherwise disagree with the rows under it.
  const setHostScope = async (hostList, inScope) => {
    if (!hostList.length) return;
    setHostsBusy(true);
    setHostNotice('');
    try {
      const response = await fetch(`/api/manual-crawl/hosts/${scopeTargetId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hosts: hostList, in_scope: inScope }),
      });
      if (!response.ok) {
        setError('Failed to update scope');
        return;
      }
      await loadHosts();
      setHostNotice(`${hostList.length} host${hostList.length === 1 ? '' : 's'} ${
        inScope ? 'included in' : 'excluded from'} scope.`);
    } catch (err) {
      setError('Error updating scope: ' + err.message);
    } finally {
      setHostsBusy(false);
    }
  };

  const promoteHosts = async (hostList) => {
    if (!hostList.length) return;
    setHostsBusy(true);
    setHostNotice('');
    try {
      const response = await fetch(`/api/manual-crawl/hosts/${scopeTargetId}/promote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hosts: hostList }),
      });
      if (!response.ok) {
        setError('Failed to add scope targets');
        return;
      }
      const data = await response.json();
      await loadHosts();
      const parts = [];
      if (data.created_count) parts.push(`${data.created_count} URL target${data.created_count === 1 ? '' : 's'} added`);
      if ((data.skipped || []).length) parts.push(`${data.skipped.length} already existed`);
      const failedCount = Object.keys(data.failed || {}).length;
      if (failedCount) parts.push(`${failedCount} failed`);
      setHostNotice(parts.join(', ') || 'Nothing to add.');
    } catch (err) {
      setError('Error adding scope targets: ' + err.message);
    } finally {
      setHostsBusy(false);
    }
  };

  const loadSessions = async () => {
    try {
      const response = await fetch(`/api/manual-crawl/sessions/${scopeTargetId}`);
      if (response.ok) {
        const data = await response.json();
        setSessions(data || []);
      } else {
        setError('Failed to load sessions');
      }
    } catch (err) {
      setError('Error connecting to framework: ' + err.message);
    }
  };

  const loadAllSessions = async () => {
    try {
      await fetch('/api/manual-crawl/cleanup', { method: 'POST' });
      
      const response = await fetch('/api/manual-crawl/sessions/all');
      if (response.ok) {
        const data = await response.json();
        setAllSessions(data || []);
      }
    } catch (err) {
      console.error('Error loading all sessions:', err);
    }
  };

  const getParameterSignature = (capture) => {
    const getParamNames = capture.get_params 
      ? Object.keys(capture.get_params).sort().join(',') 
      : '';
    
    let bodySignature = '';
    if (capture.post_params) {
      bodySignature = Object.keys(capture.post_params).sort().join(',');
    } else if (capture.post_data) {
      bodySignature = `RAW_BODY:${capture.body_type || 'unknown'}`;
    }
    
    if (getParamNames && bodySignature) {
      return `GET:${getParamNames}|BODY:${bodySignature}`;
    } else if (getParamNames) {
      return `GET:${getParamNames}`;
    } else if (bodySignature) {
      return `BODY:${bodySignature}`;
    }
    return 'NO_PARAMS';
  };

  const groupCapturesByEndpoint = (captures) => {
    const grouped = {};
    
    captures.forEach(capture => {
      const paramSignature = getParameterSignature(capture);
      // The host is part of the identity: /api/v1/users on the app host and on the API host are
      // two different endpoints, and collapsing them would hide the adjacent one entirely.
      let host = '';
      try {
        host = new URL(capture.url).hostname;
      } catch (_) { /* unparseable url */ }
      const key = `${host}:${capture.method}:${capture.endpoint}:${paramSignature}`;
      
      const candidate = { ...capture, paramSignature };
      const existing = grouped[key];

      if (!existing) {
        grouped[key] = candidate;
        return;
      }

      // Prefer the richest record for an endpoint, not merely the most recent one. A later
      // metadata-only capture would otherwise hide an earlier one that carries the bodies.
      const score = (c) => (c.response_body ? 2 : 0) + (c.post_data ? 1 : 0);
      const candidateScore = score(candidate);
      const existingScore = score(existing);

      if (
        candidateScore > existingScore ||
        (candidateScore === existingScore &&
          new Date(candidate.timestamp) > new Date(existing.timestamp))
      ) {
        grouped[key] = candidate;
      }
    });
    
    return Object.values(grouped).sort((a, b) => 
      new Date(b.timestamp) - new Date(a.timestamp)
    );
  };

  // One request for the whole target. This used to loop over the `sessions` state, which is empty
  // on the first render pass, so the initial load reliably showed nothing.
  const loadAllCaptures = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`/api/manual-crawl/captures/target/${scopeTargetId}`);
      if (!response.ok) {
        setError('Failed to load captures');
        return;
      }
      const data = await response.json();
      setCaptures(groupCapturesByEndpoint(data || []));
    } catch (err) {
      setError('Error loading captures: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadSessionCaptures = async (sessionId) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/manual-crawl/captures/${sessionId}`);
      if (response.ok) {
        const data = await response.json();
        const uniqueEndpoints = groupCapturesByEndpoint(data || []);
        setCaptures(uniqueEndpoints);
        setActiveTab('endpoints');
      }
    } catch (err) {
      setError('Error loading captures: ' + err.message);
    } finally {
      setLoading(false);
    }
  };


  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  // A session row can be 'active' in the database while its extension is gone, so live/stale is
  // decided by the heartbeat (`is_live`) rather than by status alone.
  const getStatusBadge = (session) => {
    const status = typeof session === 'string' ? session : session.status;
    const isLive = typeof session === 'string' ? status === 'active' : session.is_live;

    if (status === 'active') {
      return isLive
        ? <Badge bg="dark" className="border border-secondary text-light">recording</Badge>
        : <Badge bg="dark" className="border border-secondary text-white-50">stalled</Badge>;
    }
    return (
      <Badge bg="dark" className={`border ${status === 'failed'
        ? 'border-danger text-danger' : 'border-secondary text-white-50'}`}>
        {status}
      </Badge>
    );
  };

  // One palette for the whole modal: dark chips with a neutral outline, and the red accent reserved
  // for the things that actually need attention. A per-verb colour wheel made every row shout.
  const getMethodBadge = (method) => (
    <Badge bg="dark" className={`border ${method && method !== 'GET'
      ? 'border-danger text-danger' : 'border-secondary text-light'}`}>
      {method}
    </Badge>
  );

  const buildRawRequest = (capture) => {
    let raw = `${capture.method} ${new URL(capture.url).pathname}${new URL(capture.url).search} HTTP/1.1\n`;
    raw += `Host: ${new URL(capture.url).hostname}\n`;
    
    if (capture.headers) {
      Object.entries(capture.headers).forEach(([key, value]) => {
        raw += `${key}: ${value}\n`;
      });
    }
    
    raw += '\n';
    if (capture.post_data) {
      raw += capture.post_data;
    }
    
    return raw;
  };

  const buildRawResponse = (capture) => {
    let raw = `HTTP/1.1 ${capture.status_code} ${capture.status_code < 400 ? 'OK' : 'Error'}\n`;

    if (capture.response_headers) {
      Object.entries(capture.response_headers).forEach(([key, value]) => {
        raw += `${key}: ${value}\n`;
      });
    }

    raw += '\n';
    if (capture.response_body) {
      raw += capture.response_body;
      if (capture.response_body_truncated) {
        raw += '\n\n... (truncated at the extension body size limit)';
      }
    } else if (capture.error) {
      raw += `(No response: ${capture.error})`;
    } else if ((capture.sources || []).length && !hasBodySource(capture)) {
      // Explains the gap rather than leaving a blank pane: only the page hook and deep capture can
      // read a response body, so a webRequest-only record will never have one.
      raw += '(Response body not captured. This request was only seen by the network observer.\n' +
             ' Turn on Deep Capture in the extension to record bodies for navigations and\n' +
             ' non-JavaScript requests.)';
    } else {
      raw += '(Response body not captured)';
    }

    return raw;
  };

  const hasBodySource = (capture) =>
    (capture.sources || []).some((s) => s === 'hook' || s === 'debugger');

  // Single-quote shell escaping: end the quote, insert an escaped quote, reopen. Safe for the
  // arbitrary bytes that turn up in real cookies and bodies.
  const shellQuote = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;

  // A captured request is only useful if you can take it somewhere else. curl is the lowest common
  // denominator: it pastes into a terminal, into Burp, or into a report.
  const buildCurl = (capture) => {
    const parts = [`curl -i -X ${capture.method || 'GET'} ${shellQuote(capture.url)}`];

    Object.entries(capture.headers || {}).forEach(([key, value]) => {
      const lower = key.toLowerCase();
      // Recomputed by curl, or meaningless outside the original connection.
      if (['host', 'content-length', 'connection', 'accept-encoding'].includes(lower)) return;
      if (lower.startsWith(':')) return;
      parts.push(`  -H ${shellQuote(`${key}: ${Array.isArray(value) ? value.join(', ') : value}`)}`);
    });

    if (capture.post_data) {
      parts.push(`  --data-raw ${shellQuote(capture.post_data)}`);
    }

    return parts.join(' \\\n');
  };

  const copyCurl = async (capture) => {
    const command = buildCurl(capture);
    try {
      await navigator.clipboard.writeText(command);
      setCopiedId(capture.id);
      setTimeout(() => setCopiedId(null), 1500);
    } catch (err) {
      // Clipboard access can be denied; showing the command still lets the user copy it by hand.
      setError('Could not copy automatically. Command:\n' + command);
    }
  };

  const directCaptures = captures.filter((c) => c.is_direct);
  const adjacentCaptures = captures.filter((c) => !c.is_direct);
  const visibleCaptures =
    scopeFilter === 'direct' ? directCaptures : scopeFilter === 'adjacent' ? adjacentCaptures : captures;

  // Hosts represented in the adjacent bucket, so the API domain is visible at a glance.
  const adjacentHosts = Array.from(
    adjacentCaptures.reduce((set, c) => {
      try {
        set.add(new URL(c.url).hostname);
      } catch (_) { /* unparseable url */ }
      return set;
    }, new Set())
  );

  const hostOf = (capture) => {
    try {
      return new URL(capture.url).hostname;
    } catch (_) {
      return '';
    }
  };

  // Merged across every session for this target: a host dropped in an earlier session is still the
  // explanation for why its traffic is missing now.
  const droppedHosts = sessions.reduce((acc, session) => {
    Object.entries(session.observed_out_of_scope || {}).forEach(([host, count]) => {
      acc[host] = (acc[host] || 0) + count;
    });
    return acc;
  }, {});

  // Adjacent hosts that do not have a URL target yet, and hosts currently outside the scan
  // boundary. Both drive the bulk buttons, so they are derived once rather than inline.
  const promotableHosts = hosts
    .filter((h) => !h.is_direct && !h.existing_target_id)
    .map((h) => h.host);
  const excludedHosts = hosts
    .filter((h) => !h.within_target_domain && !h.in_scope)
    .map((h) => h.host);

  const SOURCE_LABELS = {
    webrequest: { label: 'network', variant: 'secondary', title: 'chrome.webRequest: headers, status, cookies' },
    hook: { label: 'page hook', variant: 'info', title: 'Page fetch/XHR hook: request and response bodies' },
    debugger: { label: 'deep', variant: 'primary', title: 'DevTools protocol: full request and response' },
  };

  return (
    <Modal show={show} onHide={onHide} fullscreen data-bs-theme="dark">
      <style>
        {`
          .accordion-button {
            background-color: #343a40 !important;
            color: white !important;
          }
          .accordion-button:not(.collapsed) {
            background-color: #343a40 !important;
            color: white !important;
          }
          .accordion-button:focus {
            box-shadow: none !important;
          }
          .accordion-button::after {
            filter: invert(1);
          }
          .list-group-item-action:hover {
            background-color: #3a3a3a !important;
          }
          .list-group-item-action:focus {
            background-color: #3a3a3a !important;
          }
          .nav-tabs {
            border-bottom: 1px solid #495057;
          }
          .nav-tabs .nav-link {
            color: #adb5bd;
            background-color: transparent;
            border: none;
          }
          .nav-tabs .nav-link:hover {
            color: white;
            border: none;
          }
          .nav-tabs .nav-link.active {
            color: #dc3545;
            background-color: transparent;
            border: none;
            border-bottom: 2px solid #dc3545;
          }
        `}
      </style>
      <Modal.Header closeButton className="bg-dark text-white">
        <Modal.Title>
          <i className="bi bi-cursor-fill me-2"></i>
          Manual Crawling Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body className="bg-dark text-white" style={{ overflowY: 'auto' }}>
        {error && (
          <Alert variant="danger" onClose={() => setError('')} dismissible>
            {error}
          </Alert>
        )}

        {/* The single most common reason for a thin capture list is that the app's API lives on a
            host outside the recording scope. The extension counts what it rejected; showing it
            here means the answer is where the question gets asked. */}
        {Object.keys(droppedHosts).length > 0 && (
          <div
            className="rounded p-2 mb-3"
            style={{ border: '1px solid rgba(255, 193, 7, 0.45)', backgroundColor: 'transparent' }}
          >
            <div className="d-flex align-items-start">
              <i className="bi bi-exclamation-triangle me-2 mt-1 text-warning"></i>
              <div className="flex-grow-1">
                <strong className="text-warning">Traffic was seen but not captured.</strong>
                <div className="small mt-1 text-light" style={{ opacity: 0.75 }}>
                  These hosts were requested while recording but are outside the capture scope. If
                  the application's API is among them, add it in the extension popup under
                  <em> Scope</em>, then record again.
                </div>
                <div className="d-flex flex-wrap gap-2 mt-2">
                  {Object.entries(droppedHosts)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 15)
                    .map(([host, count]) => (
                      <Badge key={host} bg="dark" className="border border-warning text-warning">
                        {host} <span className="text-white-50">({count})</span>
                      </Badge>
                    ))}
                </div>
              </div>
            </div>
          </div>
        )}

        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="mb-3"
        >
          <Tab eventKey="endpoints" title={`Endpoints (${captures.length})`}>
            {captures.length > 0 && (
              <div className="d-flex align-items-center flex-wrap gap-2 mb-3">
                <ButtonGroup size="sm">
                  <Button
                    variant={scopeFilter === 'all' ? 'danger' : 'outline-danger'}
                    onClick={() => setScopeFilter('all')}
                  >
                    All ({captures.length})
                  </Button>
                  <Button
                    variant={scopeFilter === 'direct' ? 'danger' : 'outline-danger'}
                    onClick={() => setScopeFilter('direct')}
                    title="Requests to the scope target's own host"
                  >
                    Direct ({directCaptures.length})
                  </Button>
                  <Button
                    variant={scopeFilter === 'adjacent' ? 'danger' : 'outline-danger'}
                    onClick={() => setScopeFilter('adjacent')}
                    title="Requests to other in-scope hosts, such as a separate API domain"
                  >
                    Adjacent ({adjacentCaptures.length})
                  </Button>
                </ButtonGroup>
                {adjacentHosts.length > 0 && (
                  <span className="small text-light" style={{ opacity: 0.7 }}>
                    Adjacent Hosts ({adjacentHosts.length}): {adjacentHosts.slice(0, 4).join(', ')}
                    {adjacentHosts.length > 4 ? ` +${adjacentHosts.length - 4} more` : ''}
                  </span>
                )}
              </div>
            )}
            {loading ? (
              <div className="text-center py-5">
                <Spinner animation="border" variant="danger" />
                <p className="mt-3">Loading endpoints...</p>
              </div>
            ) : captures.length === 0 ? (
              <>
                <Alert variant="dark" className="border border-secondary text-light">
                  <i className="bi bi-info-circle me-2"></i>
                  No endpoints captured yet. Start the Chrome extension and begin capturing to see results here.
                </Alert>
                {allSessions.length > 0 && (
                  <Alert variant="dark" className="border border-secondary text-light">
                    <strong><i className="bi bi-exclamation-triangle me-2"></i>Found {allSessions.length} session(s) for other targets:</strong>
                    <ul className="mt-2 mb-0 small">
                      {allSessions.map(s => (
                        <li key={s.id}>
                          <code>{s.target_url}</code> - {s.request_count} requests, {s.endpoint_count} endpoints
                          <Badge bg={s.status === 'active' ? 'success' : 'secondary'} className="ms-2">{s.status}</Badge>
                        </li>
                      ))}
                    </ul>
                  </Alert>
                )}
              </>
            ) : (
              <Accordion>
                {visibleCaptures.length === 0 && (
                  <Alert variant="dark" className="py-3 border border-secondary text-light">
                    {scopeFilter === 'adjacent'
                      ? 'No adjacent endpoints. Every captured request went to the target host itself. If the application calls an API on another domain, add that host in the extension popup under Scope and record again.'
                      : 'No direct endpoints. Every captured request went to another in-scope host.'}
                  </Alert>
                )}
                {visibleCaptures.map((capture, index) => (
                  <Accordion.Item 
                    eventKey={index.toString()} 
                    key={capture.id} 
                    className="border-secondary mb-2"
                    style={{ backgroundColor: '#2b2b2b' }}
                  >
                    <Accordion.Header style={{ backgroundColor: '#343a40' }}>
                      <div className="d-flex justify-content-between align-items-center w-100 me-3">
                        <div className="d-flex align-items-center flex-grow-1">
                          {getMethodBadge(capture.method)}
                          <Badge
                            bg="dark"
                            className="ms-2 border border-secondary text-white-50"
                            style={{ fontSize: '0.65rem' }}
                            title={capture.is_direct
                              ? "On the scope target's own host"
                              : 'On another host this application contacted'}
                          >
                            {capture.is_direct ? 'Direct' : 'Adjacent'}
                          </Badge>
                          {/* The host is what distinguishes one adjacent endpoint from another, so
                              a bare path would be ambiguous here. */}
                          {!capture.is_direct && (
                            <span className="text-white-50 ms-2" style={{ fontSize: '0.75rem' }}>
                              {hostOf(capture)}
                            </span>
                          )}
                          <code className="text-light ms-2" style={{ fontSize: '0.9rem' }}>
                            {capture.endpoint}
                          </code>
                          {capture.get_params && Object.keys(capture.get_params).length > 0 && (
                            <Badge bg="dark" className="ms-2 border border-secondary text-light" style={{ fontSize: '0.7rem' }}>
                              ?{Object.keys(capture.get_params).join(', ')}
                            </Badge>
                          )}
                          {capture.post_params && Object.keys(capture.post_params).length > 0 && (
                            <Badge bg="dark" className="ms-2 border border-secondary text-light" style={{ fontSize: '0.7rem' }}>
                              body: {Object.keys(capture.post_params).join(', ')}
                            </Badge>
                          )}
                          {!capture.post_params && capture.post_data && (
                            <Badge bg="dark" className="ms-2 border border-secondary text-light" style={{ fontSize: '0.7rem' }}>
                              body: {capture.body_type || 'raw'}
                            </Badge>
                          )}
                        </div>
                        <div className="d-flex align-items-center">
                          {capture.response_body && (
                            <Badge bg="dark" className="me-2 border border-secondary text-light" style={{ fontSize: '0.65rem' }} title="Response body captured">
                              <i className="bi bi-file-earmark-code" />
                            </Badge>
                          )}
                          {(capture.sources || []).map((source) => {
                            const meta = SOURCE_LABELS[source];
                            if (!meta) return null;
                            return (
                              <Badge
                                key={source}
                                bg="dark"
                                className="me-1 border border-secondary text-white-50"
                                style={{ fontSize: '0.6rem' }}
                                title={meta.title}
                              >
                                {meta.label}
                              </Badge>
                            );
                          })}
                          <Badge
                            bg="dark"
                            className={`me-2 border ${capture.error || capture.status_code >= 400
                              ? 'border-danger text-danger' : 'border-secondary text-light'}`}
                            title={capture.error || ''}
                          >
                            {capture.error ? 'failed' : capture.status_code || '-'}
                          </Badge>
                          <small className="text-light">{formatDate(capture.timestamp)}</small>
                        </div>
                      </div>
                    </Accordion.Header>
                    <Accordion.Body className="text-white" style={{ backgroundColor: '#2b2b2b' }}>
                      <div className="mb-3 d-flex justify-content-between align-items-start gap-2">
                        <div className="flex-grow-1">
                          <strong className="text-white-50 d-block mb-1">Full URL:</strong>
                          <code className="text-light small" style={{ wordBreak: 'break-all' }}>{capture.url}</code>
                        </div>
                        <Button
                          size="sm"
                          variant={copiedId === capture.id ? 'success' : 'outline-info'}
                          className="flex-shrink-0"
                          onClick={() => copyCurl(capture)}
                          title="Copy this request as a curl command, with its real headers and body"
                        >
                          <i className={`bi ${copiedId === capture.id ? 'bi-check-lg' : 'bi-terminal'} me-1`} />
                          {copiedId === capture.id ? 'Copied' : 'Copy as curl'}
                        </Button>
                      </div>

                      {(capture.graphql_operation || capture.resource_type || capture.initiator ||
                        capture.duration_ms > 0 || capture.error) && (
                        <div className="mb-3 d-flex flex-wrap gap-2 align-items-center">
                          {capture.graphql_operation && (
                            <Badge bg="dark" className="border border-secondary text-light">
                              GraphQL: {capture.graphql_operation}
                            </Badge>
                          )}
                          {capture.resource_type && (
                            <Badge bg="dark" className="border border-secondary text-light">
                              {capture.resource_type}
                            </Badge>
                          )}
                          {capture.initiator && (
                            <Badge bg="dark" className="border border-secondary text-light">
                              via {capture.initiator}
                            </Badge>
                          )}
                          {capture.duration_ms > 0 && (
                            <Badge bg="dark" className="border border-secondary text-light">
                              {capture.duration_ms} ms
                            </Badge>
                          )}
                          {capture.error && (
                            <Badge bg="dark" className="border border-danger text-danger">{capture.error}</Badge>
                          )}
                        </div>
                      )}

                      {capture.redirect_chain && capture.redirect_chain.length > 0 && (
                        <div className="mb-3">
                          <strong className="text-white-50 d-block mb-1">
                            <i className="bi bi-signpost-split me-1"></i>
                            Redirect Chain:
                          </strong>
                          <ul className="small mb-0 ps-3">
                            {capture.redirect_chain.map((hop, i) => (
                              <li key={i} className="text-light">
                                <Badge bg="dark" className="me-2 border border-secondary text-light">{hop.statusCode}</Badge>
                                <code className="text-light">{hop.location}</code>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {capture.get_params && Object.keys(capture.get_params).length > 0 && (
                        <div className="mb-3">
                          <strong className="text-white-50 d-block mb-1">
                            <i className="bi bi-question-circle me-1"></i>
                            GET Parameters:
                          </strong>
                          <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.85rem', maxHeight: '150px', overflowY: 'auto' }}>
                            {JSON.stringify(capture.get_params, null, 2)}
                          </pre>
                        </div>
                      )}

                      {(capture.post_params || capture.post_data) && (
                        <div className="mb-3">
                          <strong className="text-success d-block mb-1">
                            <i className="bi bi-file-earmark-text me-1"></i>
                            Request Body:
                            {capture.body_type && (
                              <Badge bg="dark" className="ms-2 border border-secondary text-light" style={{ fontSize: '0.7rem' }}>
                                {capture.body_type}
                              </Badge>
                            )}
                          </strong>
                          {capture.post_params ? (
                            <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.85rem', maxHeight: '150px', overflowY: 'auto' }}>
                              {JSON.stringify(capture.post_params, null, 2)}
                            </pre>
                          ) : (
                            <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.85rem', maxHeight: '150px', overflowY: 'auto' }}>
                              {capture.post_data}
                            </pre>
                          )}
                        </div>
                      )}

                      <div className="row mb-3">
                        <div className="col-md-6">
                          <strong className="text-white-50 d-block mb-1">
                            <i className="bi bi-box-arrow-up-right me-1"></i>
                            Request Headers:
                          </strong>
                          {capture.headers && Object.keys(capture.headers).length > 0 ? (
                            <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.75rem', maxHeight: '150px', overflowY: 'auto' }}>
                              {JSON.stringify(capture.headers, null, 2)}
                            </pre>
                          ) : (
                            <div className="text-light small" style={{ opacity: 0.6 }}>No headers captured</div>
                          )}
                        </div>
                        <div className="col-md-6">
                          <strong className="text-white-50 d-block mb-1">
                            <i className="bi bi-box-arrow-in-down me-1"></i>
                            Response Headers:
                          </strong>
                          {capture.response_headers && Object.keys(capture.response_headers).length > 0 ? (
                            <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.75rem', maxHeight: '150px', overflowY: 'auto' }}>
                              {JSON.stringify(capture.response_headers, null, 2)}
                            </pre>
                          ) : (
                            <div className="text-light small" style={{ opacity: 0.6 }}>No headers captured</div>
                          )}
                        </div>
                      </div>

                      <div className="row">
                        <div className="col-md-6 mb-3">
                          <strong className="text-white-50 d-block mb-1">
                            <i className="bi bi-code-square me-1"></i>
                            Raw HTTP Request:
                          </strong>
                          <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.75rem', maxHeight: '300px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {buildRawRequest(capture)}
                          </pre>
                        </div>
                        <div className="col-md-6 mb-3">
                          <strong className="text-success d-block mb-1">
                            <i className="bi bi-reply me-1"></i>
                            Raw HTTP Response:
                          </strong>
                          <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: '0.75rem', maxHeight: '300px', overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {buildRawResponse(capture)}
                          </pre>
                        </div>
                      </div>
                    </Accordion.Body>
                  </Accordion.Item>
                ))}
              </Accordion>
            )}
          </Tab>

          <Tab eventKey="hosts" title={`Hosts (${hosts.length})`}>
            <div className="mb-3">
              <div className="text-white-50 small mb-2">
                Every host this application contacted while you were recording. An adjacent host is
                one other than the scope target itself, which is normally where the API lives.
                In-scope hosts are the ones the endpoint scan is allowed to send requests to, so
                excluding a host here removes its endpoints from testing without deleting them.
              </div>
              {scopeDescription && !rulesActive && (
                <div className="small">
                  <span className="text-white-50">Current scan boundary: </span>
                  <code className="text-light">{scopeDescription}</code>
                </div>
              )}
            </div>

            {/* ---------------------------------------------------------- scope rules */}
            <div className="rounded p-3 mb-3" style={{ border: '1px solid rgba(220,53,69,0.45)' }}>
              <div className="d-flex align-items-center gap-2 mb-2">
                <span className="text-danger fw-bold small">Scope rules</span>
                {rulesActive && <Badge bg="danger">in force</Badge>}
              </div>

              <p className="text-white-50 small mb-2">
                A rule can name an exact host, a whole subtree, subdomains only, a substring or a
                regex, and it can deny as well as allow. A deny always wins, whatever else matches.
              </p>

              {rulesActive && (
                <Alert variant="warning" className="py-2 small mb-2">
                  Rules are the whole boundary. The per-host in/out toggles below are{' '}
                  <strong>not consulted</strong> while any rule exists, and neither is the crawl's
                  own observed-host list. Remove every rule to go back to the host list.
                </Alert>
              )}

              <div className="mb-2">
                {scopeRules.length === 0 ? (
                  <div className="text-white-50 small">
                    No rules. The host list below is the boundary.
                  </div>
                ) : scopeRules.map((rule) => (
                  <div key={rule.id} className="d-flex align-items-start gap-2 mb-1">
                    <Badge bg={rule.effect === 'deny' ? 'danger' : 'secondary'}
                           style={{ fontSize: '0.6rem' }}>
                      {rule.effect === 'deny' ? 'DENY' : 'ALLOW'}
                    </Badge>
                    <div className="flex-grow-1">
                      {/* The sentence is the primary text. A bare pattern is what gets misread. */}
                      <div className="small text-white">{rule.sentence}</div>
                      <code className="text-white-50" style={{ fontSize: '0.7rem' }}>
                        {rule.canonical}
                      </code>
                      {rule.blast === 'wide' && (
                        <Badge bg="warning" text="dark" className="ms-2"
                               style={{ fontSize: '0.6rem' }}
                               title="Can admit hosts nobody has seen yet">
                          wide
                        </Badge>
                      )}
                    </div>
                    <Button size="sm" variant="link" className="text-danger p-0"
                            disabled={ruleBusy}
                            onClick={() => removeScopeRule(rule.id)} title="Remove this rule">
                      <i className="bi bi-x-lg" />
                    </Button>
                  </div>
                ))}
              </div>

              <div className="d-flex gap-2">
                <input
                  type="text"
                  className="form-control form-control-sm bg-dark text-light border-secondary"
                  placeholder="e.g. *.example.com, =api.example.com, ~jivo within acme.io, !cdn.example.com"
                  value={ruleInput}
                  disabled={ruleBusy}
                  onChange={(e) => { setRuleInput(e.target.value); setRuleError(''); }}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addScopeRule(); } }}
                />
                <Button size="sm" variant="outline-danger" disabled={ruleBusy || !ruleInput.trim()}
                        onClick={addScopeRule}>
                  {ruleBusy ? <Spinner animation="border" size="sm" /> : 'Add'}
                </Button>
              </div>

              {ruleError && <div className="small text-danger mt-1">{ruleError}</div>}

              {rulePreview && !rulePreview.ok && (
                <div className="small text-danger mt-1">{rulePreview.error}</div>
              )}
              {rulePreview && rulePreview.ok && (
                <div className="small mt-2">
                  <div className={rulePreview.rule.blast === 'wide' ? 'text-warning' : 'text-info'}>
                    {rulePreview.rule.sentence}
                  </div>
                  <div className="text-white-50" style={{ fontSize: '0.72rem' }}>
                    {(rulePreview.newly_allowed || []).length > 0 && (
                      <span className="me-3">
                        would newly allow {rulePreview.newly_allowed.length} recorded host
                        {rulePreview.newly_allowed.length === 1 ? '' : 's'}:{' '}
                        {rulePreview.newly_allowed.slice(0, 4).join(', ')}
                        {rulePreview.newly_allowed.length > 4 ? '…' : ''}
                      </span>
                    )}
                    {(rulePreview.newly_denied || []).length > 0 && (
                      <span className="text-warning">
                        would remove {rulePreview.newly_denied.length} host
                        {rulePreview.newly_denied.length === 1 ? '' : 's'} currently in scope:{' '}
                        {rulePreview.newly_denied.slice(0, 4).join(', ')}
                        {rulePreview.newly_denied.length > 4 ? '…' : ''}
                      </span>
                    )}
                  </div>
                  {rulePreview.warning && (
                    <div className="text-warning mt-1" style={{ fontSize: '0.72rem' }}>
                      {rulePreview.warning}
                    </div>
                  )}
                </div>
              )}

              <details className="mt-2">
                <summary className="text-white-50 small" style={{ cursor: 'pointer' }}>syntax</summary>
                <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem', lineHeight: 1.7 }}>
                  <div><code>example.com</code> host and every subdomain</div>
                  <div><code>*.example.com</code> subdomains only, <em>not</em> example.com itself</div>
                  <div><code>=api.example.com</code> that exact host only</div>
                  <div><code>=app.example.com:8443</code> that host on that port only</div>
                  <div><code>~jivo</code> any host containing "jivo" (wide)</div>
                  <div><code>~jivo within acme.io</code> the same, bounded to one domain</div>
                  <div><code>{'re:prod-[0-9]+\\.acme\\.io'}</code> full-match regex</div>
                  <div><code>!cdn.example.com</code> deny that subtree</div>
                  <div><code>!=cdn.example.com</code> deny that exact host</div>
                </div>
              </details>
            </div>

            {hostNotice && (
              <Alert variant="dark" className="border border-secondary text-light py-2"
                     onClose={() => setHostNotice('')} dismissible>
                {hostNotice}
              </Alert>
            )}

            {hosts.length === 0 ? (
              <Alert variant="dark" className="py-3 border border-secondary text-light">
                No hosts recorded yet. Record a session with the extension first.
              </Alert>
            ) : (
              <>
                <div className="d-flex flex-wrap gap-2 mb-3">
                  <Button
                    size="sm"
                    variant="outline-danger"
                    disabled={hostsBusy || promotableHosts.length === 0}
                    onClick={() => promoteHosts(promotableHosts)}
                    title="Create a URL scope target for every adjacent host that does not have one"
                  >
                    {hostsBusy ? <Spinner animation="border" size="sm" className="me-1" /> : null}
                    Add all adjacent as URL targets ({promotableHosts.length})
                  </Button>
                  <Button
                    size="sm"
                    variant="outline-secondary"
                    disabled={hostsBusy || rulesActive || excludedHosts.length === 0}
                    title={rulesActive ? 'Scope rules are in force; per-host scope is not consulted' : undefined}
                    onClick={() => setHostScope(excludedHosts, true)}
                  >
                    Include all in scope ({excludedHosts.length})
                  </Button>
                </div>

                <div className="table-responsive">
                  <table className="table table-dark table-sm align-middle mb-0">
                    <thead>
                      <tr className="text-white-50">
                        <th>Host</th>
                        <th className="text-end">Requests</th>
                        <th className="text-end">Endpoints</th>
                        <th>Relation</th>
                        <th>Scope</th>
                        <th className="text-end">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {hosts.map((h) => (
                        <tr key={h.host}>
                          <td><code className="text-light">{h.host}</code></td>
                          <td className="text-end text-white-50">{h.requests}</td>
                          <td className="text-end text-white-50">{h.endpoints}</td>
                          <td>
                            <Badge bg="dark" className="border border-secondary text-white-50"
                                   style={{ fontSize: '0.65rem' }}>
                              {h.is_direct ? 'Direct' : 'Adjacent'}
                            </Badge>
                          </td>
                          <td>
                            {h.within_target_domain ? (
                              <span className="text-white-50 small"
                                    title="Inside the scope target's own domain, so always in scope">
                                always in scope
                              </span>
                            ) : (
                              <span className={`small ${h.in_scope ? 'text-light' : 'text-danger'}`}>
                                {h.in_scope ? 'in scope' : 'excluded'}
                                {h.decided && <span className="text-white-50"> (set)</span>}
                              </span>
                            )}
                          </td>
                          <td className="text-end">
                            {!h.within_target_domain && (
                              <Button
                                size="sm"
                                variant="link"
                                className={`p-0 me-3 ${h.in_scope ? 'text-white-50' : 'text-danger'}`}
                                disabled={hostsBusy || rulesActive}
                                title={rulesActive ? 'Scope rules are in force; per-host scope is not consulted' : undefined}
                                onClick={() => setHostScope([h.host], !h.in_scope)}
                              >
                                {h.in_scope ? 'Exclude' : 'Include'}
                              </Button>
                            )}
                            {h.existing_target_id ? (
                              <span className="text-white-50 small">target exists</span>
                            ) : (
                              <Button
                                size="sm"
                                variant="link"
                                className="p-0 text-danger"
                                disabled={hostsBusy}
                                onClick={() => promoteHosts([h.host])}
                              >
                                Add as URL target
                              </Button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </Tab>

          <Tab eventKey="sessions" title={`Sessions (${sessions.length})`}>
            {sessions.length === 0 ? (
              <Alert variant="dark" className="border border-secondary text-light">
                <i className="bi bi-info-circle me-2"></i>
                No capture sessions found for this target.
              </Alert>
            ) : (
              <div className="list-group">
                {sessions.map((session) => (
                  <div
                    key={session.id}
                    className="list-group-item list-group-item-action text-white border-secondary mb-2"
                    onClick={() => loadSessionCaptures(session.id)}
                    style={{ cursor: 'pointer', backgroundColor: '#2b2b2b' }}
                  >
                    <div className="d-flex justify-content-between align-items-center">
                      <div>
                        <h6 className="mb-1 text-white">
                          {getStatusBadge(session)}
                          <span className="ms-2 text-light">{session.target_url}</span>
                        </h6>
                        <small className="text-light" style={{ opacity: 0.7 }}>
                          Started: {formatDate(session.started_at)}
                          {session.ended_at && ` | Ended: ${formatDate(session.ended_at)}`}
                          {session.status === 'active' && !session.is_live && session.last_heartbeat_at &&
                            ` | Last heartbeat: ${formatDate(session.last_heartbeat_at)}`}
                        </small>
                      </div>
                      <div>
                        <Badge bg="dark" className="me-2 border border-secondary text-light">{session.request_count || 0} requests</Badge>
                        <Badge bg="dark" className="border border-secondary text-light">{session.endpoint_count || 0} endpoints</Badge>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer className="bg-dark text-white">
        <Button variant="outline-info" onClick={handleRefresh}>
          <i className="bi bi-arrow-clockwise me-1"></i>
          Refresh
        </Button>
        <Button variant="outline-secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default ManualCrawlResultsModal;
