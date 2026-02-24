import { useMemo } from 'react';
import { Modal, Table } from 'react-bootstrap';

export const CeWLResultsModal = ({
  showCeWLResultsModal,
  handleCloseCeWLResultsModal,
  cewlResults
}) => {
  const parseCeWLResults = (results) => {
    if (!results || !results.result) return [];
    try {
      return results.result.split('\n')
        .filter(line => line.trim())
        .map(line => line.trim());
    } catch (error) {
      console.error('Error parsing CeWL results:', error);
      return [];
    }
  };

  const parsedResults = useMemo(() => cewlResults ? parseCeWLResults(cewlResults) : [], [cewlResults]);

  return (
    <Modal data-bs-theme="dark" show={showCeWLResultsModal} onHide={handleCloseCeWLResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">CeWL Generated Subdomains</Modal.Title>
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