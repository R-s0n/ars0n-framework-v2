import { useMemo } from 'react';
import { Modal, Table } from 'react-bootstrap';

export const AssetfinderResultsModal = ({
  showAssetfinderResultsModal,
  handleCloseAssetfinderResultsModal,
  assetfinderResults
}) => {
  const parseAssetfinderResults = (results) => {
    if (!results || !results.result) return [];
    try {
      return results.result.split('\n')
        .filter(line => line.trim())
        .map(line => line.trim());
    } catch (error) {
      console.error('Error parsing Assetfinder results:', error);
      return [];
    }
  };

  const parsedResults = useMemo(() => assetfinderResults ? parseAssetfinderResults(assetfinderResults) : [], [assetfinderResults]);

  return (
    <Modal data-bs-theme="dark" show={showAssetfinderResultsModal} onHide={handleCloseAssetfinderResultsModal} size="xl">
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Assetfinder Results</Modal.Title>
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