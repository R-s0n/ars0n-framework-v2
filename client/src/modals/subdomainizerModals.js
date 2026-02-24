import { useMemo } from 'react';
import { Modal, Table } from 'react-bootstrap';

export const SubdomainizerResultsModal = ({
  showSubdomainizerResultsModal,
  handleCloseSubdomainizerResultsModal,
  subdomainizerResults
}) => {
  const parseSubdomainizerResults = (results) => {
    if (!results || (!results.result && !results.stdout)) return [];
    try {
      // First try to use the processed results
      if (results.result) {
        return results.result.split('\n').filter(line => line.trim());
      }
      
      // If no processed results, parse from stdout
      if (results.stdout) {
        return results.stdout.split('\n').filter(line => line.trim());
      }
      
      return [];
    } catch (error) {
      console.error('Error parsing Subdomainizer results:', error);
      return [];
    }
  };

  const parsedResults = useMemo(() => subdomainizerResults ? parseSubdomainizerResults(subdomainizerResults) : [], [subdomainizerResults]);

  return (
    <Modal data-bs-theme="dark" show={showSubdomainizerResultsModal} onHide={handleCloseSubdomainizerResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Subdomainizer Results</Modal.Title>
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