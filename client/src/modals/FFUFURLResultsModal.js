import { Modal, Table, Badge, Spinner, Alert, Tabs, Tab } from 'react-bootstrap';
import { useState, useEffect } from 'react';

export const FFUFURLResultsModal = ({ show, handleClose, activeTarget, mostRecentFFUFURLScan }) => {
  const [endpointResults, setEndpointResults] = useState([]);
  const [headerResults, setHeaderResults] = useState([]);
  const [cookieResults, setCookieResults] = useState([]);
  const [activeTab, setActiveTab] = useState('endpoints');
  const [loading, setLoading] = useState(true);
  // An empty result set is the same output whether the target has nothing to find or answers every
  // path identically. The backend now says which, and this is where it gets read.
  const [diagnosis, setDiagnosis] = useState('');
  const [preflight, setPreflight] = useState(null);
  const [phasesRun, setPhasesRun] = useState([]);
  const [phaseErrors, setPhaseErrors] = useState([]);

  useEffect(() => {
    if (show && mostRecentFFUFURLScan) {
      loadResults();
    }
  }, [show, mostRecentFFUFURLScan]);

  const loadResults = async () => {
    setLoading(true);
    try {
      let parsed = null;
      if (mostRecentFFUFURLScan?.result) {
        if (typeof mostRecentFFUFURLScan.result === 'string') {
          try {
            parsed = JSON.parse(mostRecentFFUFURLScan.result);
          } catch (e) {
            console.error('Error parsing FFUF results:', e);
          }
        } else if (typeof mostRecentFFUFURLScan.result === 'object') {
          parsed = mostRecentFFUFURLScan.result;
        }
      }

      const sortByStatus = (arr) =>
        [...(arr || [])].sort((a, b) => (parseInt(a.status) || 0) - (parseInt(b.status) || 0));

      setEndpointResults(sortByStatus(parsed ? (parsed.endpoints || parsed.results || []) : []));
      setHeaderResults(sortByStatus(parsed ? (parsed.headers || []) : []));
      setCookieResults(sortByStatus(parsed ? (parsed.cookies || []) : []));
      setDiagnosis(parsed?.diagnosis || '');
      setPreflight(parsed?.preflight || null);
      setPhasesRun(parsed?.phases_run || []);
      setPhaseErrors(parsed?.phase_errors || []);
    } catch (error) {
      console.error('Error loading FFUF results:', error);
      setEndpointResults([]);
      setHeaderResults([]);
      setCookieResults([]);
      setDiagnosis('');
      setPreflight(null);
      setPhasesRun([]);
      setPhaseErrors([]);
    } finally {
      setLoading(false);
    }
  };

  const getStatusCodeColor = (status) => {
    const code = parseInt(status);
    if (code >= 200 && code < 300) return { bg: 'success', text: 'white' };
    if (code >= 300 && code < 400) return { bg: 'info', text: 'white' };
    if (code === 401 || code === 403) return { bg: 'warning', text: 'dark' };
    if (code >= 400 && code < 500) return { bg: 'secondary', text: 'white' };
    if (code >= 500) return { bg: 'danger', text: 'white' };
    return { bg: 'dark', text: 'white' };
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const renderResultsTable = (rows, kind) => {
    if (loading) {
      return (
        <div className="text-center p-5">
          <Spinner animation="border" variant="danger" />
          <p className="text-white mt-3">Loading results...</p>
        </div>
      );
    }

    if (!rows || rows.length === 0) {
      // A phase that was never enabled and a phase that ran and found nothing are different
      // outcomes, and only one of them is about the target.
      if (phasesRun.length > 0 && !phasesRun.includes(kind)) {
        const label = kind === 'endpoints' ? 'Path' : kind === 'headers' ? 'Header' : 'Cookie';
        return (
          <Alert variant="secondary" className="mb-0">
            {label} fuzzing was not enabled for this scan. Turn it on in Configure and scan again.
          </Alert>
        );
      }
      return (
        <Alert variant="warning" className="mb-0">
          Nothing found. {diagnosis || 'The scan completed and this phase reported no findings.'}
        </Alert>
      );
    }

    const idHeader = kind === 'endpoints' ? 'Path' : kind === 'headers' ? 'Header' : 'Cookie';
    const noun = kind === 'endpoints' ? 'endpoints' : kind === 'headers' ? 'headers' : 'cookies';

    return (
      <>
        <div className="mb-3">
          <p className="text-white-50 mb-0">
            Found <Badge bg="danger">{rows.length}</Badge> {noun}
          </p>
        </div>
        <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
          <Table striped bordered hover variant="dark" className="mb-0">
            <thead style={{ position: 'sticky', top: 0, backgroundColor: '#212529', zIndex: 1 }}>
              <tr>
                <th style={{ width: '100px' }} className="text-center">Status</th>
                <th>{idHeader}</th>
                <th style={{ width: '100px' }} className="text-center">Size</th>
                <th style={{ width: '100px' }} className="text-center">Words</th>
                <th style={{ width: '100px' }} className="text-center">Lines</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((result, index) => {
                const statusColor = getStatusCodeColor(result.status);
                return (
                  <tr key={index}>
                    <td className="text-center">
                      <Badge bg={statusColor.bg} className={`text-${statusColor.text}`}>
                        {result.status}
                      </Badge>
                    </td>
                    <td className="font-monospace">
                      {kind === 'endpoints' ? (
                        <a
                          href={`${activeTarget?.scope_target}/${result.path}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-danger text-decoration-none"
                        >
                          /{result.path}
                        </a>
                      ) : (
                        <span className="text-danger">
                          {result.name || result.input || result.path || '(unknown)'}
                        </span>
                      )}
                    </td>
                    <td className="text-center text-white-50">{formatBytes(result.size || 0)}</td>
                    <td className="text-center text-white-50">{result.words || 0}</td>
                    <td className="text-center text-white-50">{result.lines || 0}</td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        </div>
      </>
    );
  };

  return (
    <Modal show={show} onHide={handleClose} size="xl" data-bs-theme="dark">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-search me-2" />
          FFUF Scan Results
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="mb-3">
          <h5 className="text-white mb-0">
            Target: <span className="text-danger">{activeTarget?.scope_target}</span>
          </h5>
        </div>

        {/* What the scan measured about the target before fuzzing it. This is the difference
            between "ffuf is broken" and "this target answers everything the same way". */}
        {preflight && (
          <Alert variant={preflight.indistinguishable ? 'warning' : 'dark'}
                 className="border-secondary py-2">
            <div className="small">
              <strong>
                {preflight.indistinguishable
                  ? 'This target answers every path identically'
                  : 'Baseline'}
              </strong>
              {preflight.baseline_status ? (
                <span className="text-white-50 ms-2">
                  root responds {preflight.baseline_status}, {preflight.baseline_size} bytes
                </span>
              ) : null}
            </div>
            {preflight.note && <div className="small mt-1">{preflight.note}</div>}
          </Alert>
        )}

        {diagnosis && (endpointResults.length + headerResults.length + cookieResults.length) > 0 && (
          <Alert variant="dark" className="border-secondary py-2 small">{diagnosis}</Alert>
        )}

        {phaseErrors.length > 0 && (
          <Alert variant="danger" className="py-2 small">
            {phaseErrors.map((e, i) => <div key={i}>{e}</div>)}
          </Alert>
        )}
        <Tabs activeKey={activeTab} onSelect={(k) => setActiveTab(k)} className="mb-3">
          <Tab eventKey="endpoints" title={`Endpoints (${endpointResults.length})`}>
            {renderResultsTable(endpointResults, 'endpoints')}
          </Tab>
          <Tab eventKey="headers" title={`Headers (${headerResults.length})`}>
            {renderResultsTable(headerResults, 'headers')}
          </Tab>
          <Tab eventKey="cookies" title={`Cookies (${cookieResults.length})`}>
            {renderResultsTable(cookieResults, 'cookies')}
          </Tab>
        </Tabs>
      </Modal.Body>
    </Modal>
  );
};

export default FFUFURLResultsModal;
