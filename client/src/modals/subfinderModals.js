import { useMemo } from 'react';
import { Modal, Table } from 'react-bootstrap';

export const SubfinderResultsModal = ({
  showSubfinderResultsModal,
  handleCloseSubfinderResultsModal,
  subfinderResults
}) => {
  const parseSubfinderResults = (results) => {
    if (!results || !results.result) return [];
    try {
      return results.result.split('\n')
        .filter(line => line.trim())
        .map(line => line.trim());
    } catch (error) {
      console.error('Error parsing Subfinder results:', error);
      return [];
    }
  };

  const parsedResults = useMemo(() => subfinderResults ? parseSubfinderResults(subfinderResults) : [], [subfinderResults]);

  return (
    <Modal data-bs-theme="dark" show={showSubfinderResultsModal} onHide={handleCloseSubfinderResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Subfinder Results</Modal.Title>
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