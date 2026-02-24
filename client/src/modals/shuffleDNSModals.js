import { useMemo } from 'react';
import { Modal, Table } from 'react-bootstrap';

export const ShuffleDNSResultsModal = ({
  showShuffleDNSResultsModal,
  handleCloseShuffleDNSResultsModal,
  shuffleDNSResults
}) => {
  const parseShuffleDNSResults = (results) => {
    if (!results || !results.result) return [];
    try {
      return results.result.split('\n')
        .filter(line => line.trim())
        .map(line => line.trim());
    } catch (error) {
      console.error('Error parsing ShuffleDNS results:', error);
      return [];
    }
  };

  const parsedResults = useMemo(() => shuffleDNSResults ? parseShuffleDNSResults(shuffleDNSResults) : [], [shuffleDNSResults]);

  return (
    <Modal data-bs-theme="dark" show={showShuffleDNSResultsModal} onHide={handleCloseShuffleDNSResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">ShuffleDNS Results</Modal.Title>
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