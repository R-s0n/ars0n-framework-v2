import { useMemo } from 'react';
import { Modal, Table } from 'react-bootstrap';

export const CTLResultsModal = ({
  showCTLResultsModal,
  handleCloseCTLResultsModal,
  ctlResults
}) => {
  const parseCTLResults = (results) => {
    if (!results || !results.result) return [];
    try {
      return results.result.split('\n')
        .filter(line => line.trim())
        .map(line => line.trim());
    } catch (error) {
      console.error('Error parsing CTL results:', error);
      return [];
    }
  };

  const parsedResults = useMemo(() => ctlResults ? parseCTLResults(ctlResults) : [], [ctlResults]);

  return (
    <Modal data-bs-theme="dark" show={showCTLResultsModal} onHide={handleCloseCTLResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Certificate Transparency Logs Results</Modal.Title>
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