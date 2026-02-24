import React from 'react';
import { Modal, Table, Button } from 'react-bootstrap';
import { MdCopyAll } from 'react-icons/md';
import { copyToClipboard } from '../utils/miscUtils';

export const UniqueSubdomainsModal = ({
    showUniqueSubdomainsModal,
    handleCloseUniqueSubdomainsModal,
    consolidatedSubdomains,
    setShowToast
}) => {
    const handleCopyAll = async () => {
        const text = consolidatedSubdomains.join('\n');
        const success = await copyToClipboard(text);
        if (success) {
            setShowToast(true);
            setTimeout(() => setShowToast(false), 3000);
        }
    };

    const handleCopySubdomain = async (subdomain) => {
        const success = await copyToClipboard(subdomain);
        if (success) {
            setShowToast(true);
            setTimeout(() => setShowToast(false), 3000);
        }
    };

    return (
        <Modal data-bs-theme="dark" show={showUniqueSubdomainsModal} onHide={handleCloseUniqueSubdomainsModal} size="lg">
            <Modal.Header closeButton>
                <Modal.Title className="text-danger">
                    Unique Subdomains ({consolidatedSubdomains.length})
                    <Button 
                        variant="outline-danger" 
                        size="sm" 
                        className="ms-3"
                        onClick={handleCopyAll}
                        title="Copy all subdomains"
                    >
                        <MdCopyAll /> Copy All
                    </Button>
                </Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <Table striped bordered hover>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Subdomain</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {consolidatedSubdomains.map((subdomain, index) => (
                            <tr key={index}>
                                <td>{index + 1}</td>
                                <td>{subdomain}</td>
                                <td>
                                    <Button 
                                        variant="outline-danger" 
                                        size="sm"
                                        onClick={() => handleCopySubdomain(subdomain)}
                                        title="Copy subdomain"
                                    >
                                        <MdCopyAll />
                                    </Button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </Table>
            </Modal.Body>
        </Modal>
    );
}; 