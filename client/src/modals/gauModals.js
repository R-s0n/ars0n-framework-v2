import { useMemo } from 'react';
import { Modal, Table, Nav, Tab, Alert } from 'react-bootstrap';

export const GauResultsModal = ({
  showGauResultsModal,
  handleCloseGauResultsModal,
  gauResults
}) => {
  const parseGauResults = (results) => {
    if (!results || !results.result) return [];
    try {
      return results.result.split('\n')
        .filter(line => line.trim())
        .map(line => JSON.parse(line));
    } catch (error) {
      console.error('Error parsing GAU results:', error);
      return [];
    }
  };

  const parsedResults = useMemo(() => gauResults ? parseGauResults(gauResults) : [], [gauResults]);

  const extractSubdomains = (results) => {
    const subdomainSet = new Set();
    results.forEach(result => {
      try {
        const url = new URL(result.url);
        subdomainSet.add(url.hostname);
      } catch (error) {
        console.error('Error parsing URL:', error);
      }
    });
    return Array.from(subdomainSet).sort();
  };

  const subdomains = useMemo(() => extractSubdomains(parsedResults), [parsedResults]);

  const endpoints = useMemo(() => {
    const endpointMap = new Map();
    parsedResults.forEach(result => {
      try {
        const url = new URL(result.url);
        const key = `${url.pathname}${url.search}`;
        if (!endpointMap.has(key)) {
          endpointMap.set(key, {
            path: url.pathname,
            query: url.search,
            methods: new Set([result.method]),
            statusCodes: new Set([result.status_code]),
            sources: new Set([result.source])
          });
        } else {
          const entry = endpointMap.get(key);
          entry.methods.add(result.method);
          entry.statusCodes.add(result.status_code);
          entry.sources.add(result.source);
        }
      } catch (error) {
        console.error('Error processing endpoint:', error);
      }
    });
    return Array.from(endpointMap.values());
  }, [parsedResults]);

  return (
    <Modal data-bs-theme="dark" show={showGauResultsModal} onHide={handleCloseGauResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">GAU Results</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {gauResults?.status === 'processing' && (
          <Alert variant="info" className="mb-3">
            <Alert.Heading>Processing Large Result Set</Alert.Heading>
            <p>
              GAU has found over 1000 URLs and is currently processing them to reduce the dataset. 
              The results will be available once processing is complete. This may take a few minutes for very large result sets.
            </p>
            <hr />
            <p className="mb-0">
              The system will automatically filter the results to show one URL per unique subdomain to make the results more manageable.
            </p>
          </Alert>
        )}
        
        <Tab.Container defaultActiveKey="subdomains">
          <Nav variant="tabs" className="mb-3">
            <Nav.Item>
              <Nav.Link eventKey="subdomains">Subdomains ({subdomains.length})</Nav.Link>
            </Nav.Item>
            <Nav.Item>
              <Nav.Link eventKey="endpoints">Endpoints ({endpoints.length})</Nav.Link>
            </Nav.Item>
            <Nav.Item>
              <Nav.Link eventKey="raw">Raw URLs ({parsedResults.length})</Nav.Link>
            </Nav.Item>
          </Nav>

          <Tab.Content>
            <Tab.Pane eventKey="subdomains">
              <Table striped bordered hover>
                <thead>
                  <tr>
                    <th>Subdomain</th>
                  </tr>
                </thead>
                <tbody>
                  {subdomains.map((subdomain, index) => (
                    <tr key={index}>
                      <td>{subdomain}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Tab.Pane>

            <Tab.Pane eventKey="endpoints">
              <Table striped bordered hover>
                <thead>
                  <tr>
                    <th>Path</th>
                    <th>Query Parameters</th>
                    <th>Methods</th>
                    <th>Status Codes</th>
                    <th>Sources</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((endpoint, index) => (
                    <tr key={index}>
                      <td>{endpoint.path}</td>
                      <td>{endpoint.query || 'N/A'}</td>
                      <td>{Array.from(endpoint.methods).join(', ') || 'N/A'}</td>
                      <td>{Array.from(endpoint.statusCodes).join(', ') || 'N/A'}</td>
                      <td>{Array.from(endpoint.sources).join(', ') || 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Tab.Pane>

            <Tab.Pane eventKey="raw">
              <Table striped bordered hover>
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Status Code</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {parsedResults.map((result, index) => (
                    <tr key={index}>
                      <td>
                        <a href={result.url} target="_blank" rel="noopener noreferrer" className="text-danger text-decoration-none">
                          {result.url}
                        </a>
                      </td>
                      <td>{result.method || 'N/A'}</td>
                      <td>{result.status_code || 'N/A'}</td>
                      <td>{result.source || 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Tab.Pane>
          </Tab.Content>
        </Tab.Container>
      </Modal.Body>
    </Modal>
  );
}; 