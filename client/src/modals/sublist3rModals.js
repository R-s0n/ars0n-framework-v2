import { useMemo } from 'react';
import { Modal, Table } from 'react-bootstrap';

export const Sublist3rResultsModal = ({
  showSublist3rResultsModal,
  handleCloseSublist3rResultsModal,
  sublist3rResults
}) => {
  const parseSublist3rResults = (results) => {
    if (!results || !results.result) return [];
    try {
      return results.result.split('\n')
        .filter(line => line.trim())
        .map(line => line.trim());
    } catch (error) {
      console.error('Error parsing Sublist3r results:', error);
      return [];
    }
  };

  const parsedResults = useMemo(() => sublist3rResults ? parseSublist3rResults(sublist3rResults) : [], [sublist3rResults]);

  return (
    <Modal data-bs-theme="dark" show={showSublist3rResultsModal} onHide={handleCloseSublist3rResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Sublist3r Results</Modal.Title>
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