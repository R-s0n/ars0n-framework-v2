import { useMemo } from 'react';
import { Modal, Table } from 'react-bootstrap';

export const GoSpiderResultsModal = ({
  showGoSpiderResultsModal,
  handleCloseGoSpiderResultsModal,
  gospiderResults
}) => {
  const parseGoSpiderResults = (results) => {
    if (!results || (!results.result && !results.stdout)) return [];
    try {
      // First try to use the processed results
      if (results.result) {
        return results.result.split('\n').filter(line => line.trim());
      }
      
      // If no processed results, parse from stdout
      if (results.stdout) {
        const lines = results.stdout.split('\n');
        const subdomains = new Set();
        
        lines.forEach(line => {
          const parts = line.split(' ');
          if (parts.length > 2) {
            const urlParts = parts[2].split('/');
            if (urlParts.length > 2) {
              subdomains.add(urlParts[2]);
            }
          }
        });
        
        return Array.from(subdomains);
      }
      
      return [];
    } catch (error) {
      console.error('Error parsing GoSpider results:', error);
      return [];
    }
  };

  const parsedResults = useMemo(() => gospiderResults ? parseGoSpiderResults(gospiderResults) : [], [gospiderResults]);

  return (
    <Modal data-bs-theme="dark" show={showGoSpiderResultsModal} onHide={handleCloseGoSpiderResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">GoSpider Results</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Table striped bordered hover>
          <thead>
            <tr>
              <th>Subdomain</th>
            </tr>
          </thead>
          <tbody>
            {parsedResults.map((subdomain, index) => (
              <tr key={index}>
                <td>{subdomain}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Modal.Body>
    </Modal>
  );
}; 