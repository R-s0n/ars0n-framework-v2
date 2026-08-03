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

  useEffect(() => {
    if (show && scopeTargetId) {
      loadSessions();
      loadAllSessions();
      loadAllCaptures();
    }
  }, [show, scopeTargetId]);

  const handleRefresh = () => {
    loadSessions();
    loadAllSessions();
    loadAllCaptures();
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
        ? <Badge bg="success">recording</Badge>
        : <Badge bg="warning" text="dark">stalled</Badge>;
    }

    const variants = {
      'completed': 'info',
      'abandoned': 'warning',
      'failed': 'danger'
    };
    return <Badge bg={variants[status] || 'secondary'}>{status}</Badge>;
  };

  const getMethodBadge = (method) => {
    const variants = {
      'GET': 'primary',
      'POST': 'success',
      'PUT': 'warning',
      'DELETE': 'danger',
      'PATCH': 'info'
    };
    return <Badge bg={variants[method] || 'secondary'}>{method}</Badge>;
  };

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

  const SOURCE_LABELS = {
    webrequest: { label: 'network', variant: 'secondary', title: 'chrome.webRequest: headers, status, cookies' },
    hook: { label: 'page hook', variant: 'info', title: 'Page fetch/XHR hook: request and response bodies' },
    debugger: { label: 'deep', variant: 'primary', title: 'DevTools protocol: full request and response' },
  };

  return (
    <Modal show={show} onHide={onHide} size="xl" fullscreen="lg-down">
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
      <Modal.Body className="bg-dark text-white" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
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
                <Alert variant="info">
                  <i className="bi bi-info-circle me-2"></i>
                  No endpoints captured yet. Start the Chrome extension and begin capturing to see results here.
                </Alert>
                {allSessions.length > 0 && (
                  <Alert variant="warning">
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
                  <Alert variant="secondary" className="py-3">
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
                            bg="danger"
                            className="ms-2"
                            style={{ opacity: capture.is_direct ? 1 : 0.6, fontSize: '0.65rem' }}
                            title={capture.is_direct
                              ? "On the scope target's own host"
                              : 'On another in-scope host'}
                          >
                            {capture.is_direct ? 'Direct' : 'Adjacent'}
                          </Badge>
                          {/* The host is what distinguishes one adjacent endpoint from another, so
                              a bare path would be ambiguous here. */}
                          {!capture.is_direct && (
                            <span className="text-warning ms-2" style={{ fontSize: '0.75rem' }}>
                              {hostOf(capture)}
                            </span>
                          )}
                          <code className="text-info ms-2" style={{ fontSize: '0.9rem' }}>
                            {capture.endpoint}
                          </code>
                          {capture.get_params && Object.keys(capture.get_params).length > 0 && (
                            <Badge bg="primary" className="ms-2" style={{ fontSize: '0.7rem' }}>
                              ?{Object.keys(capture.get_params).join(', ')}
                            </Badge>
                          )}
                          {capture.post_params && Object.keys(capture.post_params).length > 0 && (
                            <Badge bg="success" className="ms-2" style={{ fontSize: '0.7rem' }}>
                              body: {Object.keys(capture.post_params).join(', ')}
                            </Badge>
                          )}
                          {!capture.post_params && capture.post_data && (
                            <Badge bg="warning" className="ms-2" style={{ fontSize: '0.7rem' }}>
                              body: {capture.body_type || 'raw'}
                            </Badge>
                          )}
                        </div>
                        <div className="d-flex align-items-center">
                          {capture.response_body && (
                            <Badge bg="info" className="me-2" style={{ fontSize: '0.65rem' }} title="Response body captured">
                              <i className="bi bi-file-earmark-code" />
                            </Badge>
                          )}
                          {(capture.sources || []).map((source) => {
                            const meta = SOURCE_LABELS[source];
                            if (!meta) return null;
                            return (
                              <Badge
                                key={source}
                                bg={meta.variant}
                                className="me-1"
                                style={{ fontSize: '0.6rem' }}
                                title={meta.title}
                              >
                                {meta.label}
                              </Badge>
                            );
                          })}
                          <Badge
                            bg={capture.error ? 'warning' : capture.status_code === 0 ? 'secondary' : capture.status_code < 400 ? 'success' : 'danger'}
                            text={capture.error ? 'dark' : undefined}
                            className="me-2"
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
                          <strong className="text-warning d-block mb-1">Full URL:</strong>
                          <code className="text-info small" style={{ wordBreak: 'break-all' }}>{capture.url}</code>
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
                            <Badge bg="dark" className="border border-info text-info">
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
                            <Badge bg="warning" text="dark">{capture.error}</Badge>
                          )}
                        </div>
                      )}

                      {capture.redirect_chain && capture.redirect_chain.length > 0 && (
                        <div className="mb-3">
                          <strong className="text-warning d-block mb-1">
                            <i className="bi bi-signpost-split me-1"></i>
                            Redirect Chain:
                          </strong>
                          <ul className="small mb-0 ps-3">
                            {capture.redirect_chain.map((hop, i) => (
                              <li key={i} className="text-light">
                                <Badge bg="secondary" className="me-2">{hop.statusCode}</Badge>
                                <code className="text-info">{hop.location}</code>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {capture.get_params && Object.keys(capture.get_params).length > 0 && (
                        <div className="mb-3">
                          <strong className="text-warning d-block mb-1">
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
                              <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.7rem' }}>
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
                          <strong className="text-info d-block mb-1">
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
                          <strong className="text-info d-block mb-1">
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
                          <strong className="text-warning d-block mb-1">
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

          <Tab eventKey="sessions" title={`Sessions (${sessions.length})`}>
            {sessions.length === 0 ? (
              <Alert variant="info">
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
                          <span className="ms-2 text-info">{session.target_url}</span>
                        </h6>
                        <small className="text-light" style={{ opacity: 0.7 }}>
                          Started: {formatDate(session.started_at)}
                          {session.ended_at && ` | Ended: ${formatDate(session.ended_at)}`}
                          {session.status === 'active' && !session.is_live && session.last_heartbeat_at &&
                            ` | Last heartbeat: ${formatDate(session.last_heartbeat_at)}`}
                        </small>
                      </div>
                      <div>
                        <Badge bg="info" className="me-2">{session.request_count || 0} requests</Badge>
                        <Badge bg="success">{session.endpoint_count || 0} endpoints</Badge>
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
