import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Card, Table, Toast } from 'react-bootstrap';

const ScopeTargetDetails = () => {
    const [scopeTarget, setScopeTarget] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isSubfinderScanning, setIsSubfinderScanning] = useState(false);
    const [showToast, setShowToast] = useState(false);
    const [toastMessage, setToastMessage] = useState('');
    const [toastType, setToastType] = useState('success');
    const { id } = useParams();

    useEffect(() => {
        fetchScopeTarget();
    }, []);

    useEffect(() => {
        if (scopeTarget) {
            fetchScopeTarget();
        }
    }, [scopeTarget]);

    const fetchScopeTarget = async () => {
        try {
            const response = await fetch(`/api/scopetarget/${id}`);
            if (!response.ok) throw new Error('Failed to fetch scope target');
            const data = await response.json();
            setScopeTarget(data);
            setIsLoading(false);
        } catch (error) {
            console.error('Error fetching scope target:', error);
            setIsLoading(false);
        }
    };

    const toast = (message, type = 'success') => {
        setToastMessage(message);
        setToastType(type);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 3000);
    };

    const renderScanResults = (scans, toolName) => {
        if (!scans || scans.length === 0) return <p>No {toolName} scans found</p>;

        return (
            <div>
                <h5>{toolName} Scan Results</h5>
                <Table striped bordered hover>
                    <thead>
                        <tr>
                            <th>Scan ID</th>
                            <th>Status</th>
                            <th>Created At</th>
                        </tr>
                    </thead>
                    <tbody>
                        {scans.map(scan => (
                            <tr key={scan.id}>
                                <td>{scan.scan_id}</td>
                                <td>{scan.status}</td>
                                <td>{new Date(scan.created_at).toLocaleString()}</td>
                            </tr>
                        ))}
                    </tbody>
                </Table>
            </div>
        );
    };

    if (isLoading) {
        return <div>Loading...</div>;
    }

    if (!scopeTarget) {
        return <div>No active scope target found</div>;
    }

    return (
        <div>
            <h3>Active Scope Target Details</h3>
            <Card>
                <Card.Body>
                    <Card.Title>{scopeTarget.scope_target}</Card.Title>
                    <Card.Text>
                        Type: {scopeTarget.type}<br />
                        Mode: {scopeTarget.mode}
                    </Card.Text>
                </Card.Body>
            </Card>

            <Toast
                show={showToast}
                onClose={() => setShowToast(false)}
                style={{
                    position: 'fixed',
                    bottom: 20,
                    right: 20,
                    minWidth: '250px'
                }}
                className={`bg-${toastType}`}
            >
                <Toast.Header>
                    <strong className="me-auto">Notification</strong>
                </Toast.Header>
                <Toast.Body>{toastMessage}</Toast.Body>
            </Toast>
        </div>
    );
};

export default ScopeTargetDetails; 