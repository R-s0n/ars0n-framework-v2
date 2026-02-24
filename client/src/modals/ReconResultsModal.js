import { Modal, Table, Badge } from 'react-bootstrap';

export const ReconResultsModal = ({
    showReconResultsModal,
    handleCloseReconResultsModal,
    amassResults,
    sublist3rResults,
    assetfinderResults,
    gauResults,
    ctlResults,
    subfinderResults,
    shuffleDNSResults,
    gospiderResults,
    subdomainizerResults,
    cewlResults
}) => {
    const getSubdomainCount = (results, tool) => {
        if (!results) return 0;

        if (tool === 'amass') {
            try {
                if (Array.isArray(results.result)) {
                    return results.result.length;
                }
                return 0;
            } catch (e) {
                console.error('Error getting Amass subdomain count:', e);
                return 0;
            }
        }

        if (!results.result) return 0;

        if (tool === 'gau') {
            try {
                const lines = results.result.split('\n').filter(line => line.trim());
                const uniqueSubdomains = new Set();
                lines.forEach(line => {
                    try {
                        const data = JSON.parse(line);
                        if (data.url) {
                            const url = new URL(data.url);
                            uniqueSubdomains.add(url.hostname);
                        }
                    } catch (e) {}
                });
                return uniqueSubdomains.size;
            } catch (e) {
                return 0;
            }
        }

        if (tool === 'gospider') {
            try {
                const lines = results.result.split('\n').filter(line => line.trim());
                const uniqueSubdomains = new Set();
                
                lines.forEach(line => {
                    try {
                        // Extract any URLs from the line
                        const urlRegex = /https?:\/\/[^\s<>"']+/g;
                        const urls = line.match(urlRegex);
                        
                        if (urls) {
                            urls.forEach(url => {
                                try {
                                    const parsedUrl = new URL(url);
                                    uniqueSubdomains.add(parsedUrl.hostname);
                                } catch (e) {}
                            });
                        }
                        
                        // Also try to extract domains directly
                        const domainRegex = /[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}/g;
                        const domains = line.match(domainRegex);
                        
                        if (domains) {
                            domains.forEach(domain => {
                                uniqueSubdomains.add(domain);
                            });
                        }
                    } catch (e) {}
                });
                
                return uniqueSubdomains.size;
            } catch (e) {
                console.error('Error parsing GoSpider results:', e);
                return 0;
            }
        }

        if (tool === 'subdomainizer') {
            try {
                const lines = results.result.split('\n').filter(line => line.trim());
                const uniqueSubdomains = new Set();
                lines.forEach(line => {
                    try {
                        // Look for URLs or domain patterns
                        const urlMatch = line.match(/(?:https?:\/\/)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})/);
                        if (urlMatch && urlMatch[1]) {
                            uniqueSubdomains.add(urlMatch[1]);
                        }
                    } catch (e) {}
                });
                return uniqueSubdomains.size;
            } catch (e) {
                return 0;
            }
        }

        if (tool === 'cewl') {
            try {
                const lines = results.result.split('\n').filter(line => line.trim());
                return lines.length;
            } catch (e) {
                return 0;
            }
        }

        return results.result.split('\n').filter(line => line.trim()).length;
    };

    const formatExecutionTime = (timeStr) => {
        if (!timeStr) return 'N/A';
        
        try {
            // Handle Go's duration format (e.g., "1m30.5s", "15.2s", "1h2m30s")
            let hours = 0;
            let minutes = 0;
            let seconds = 0;
            let milliseconds = 0;

            // Extract hours if present
            const hourMatch = timeStr.match(/(\d+)h/);
            if (hourMatch) {
                hours = parseInt(hourMatch[1]);
                timeStr = timeStr.replace(hourMatch[0], '');
            }

            // Extract minutes if present
            const minMatch = timeStr.match(/(\d+)m/);
            if (minMatch) {
                minutes = parseInt(minMatch[1]);
                timeStr = timeStr.replace(minMatch[0], '');
            }

            // Extract seconds and milliseconds
            const secMatch = timeStr.match(/([\d.]+)s/);
            if (secMatch) {
                const secParts = secMatch[1].split('.');
                seconds = parseInt(secParts[0]);
                if (secParts[1]) {
                    milliseconds = parseInt(secParts[1].padEnd(3, '0'));
                }
            }

            let formattedTime = '';
            
            if (hours > 0) formattedTime += `${hours}h `;
            if (minutes > 0) formattedTime += `${minutes}m `;
            if (seconds > 0 || milliseconds > 0) {
                formattedTime += `${seconds}`;
                if (milliseconds > 0) formattedTime += `.${milliseconds.toString().padStart(3, '0')}`;
                formattedTime += 's';
            }

            return formattedTime.trim() || '0s';
        } catch (e) {
            return timeStr;
        }
    };

    const getStatusBadge = (status) => {
        if (!status) return <Badge bg="secondary">N/A</Badge>;

        const statusColors = {
            'success': 'success',
            'completed': 'success',
            'error': 'danger',
            'pending': 'warning'
        };

        return (
            <Badge bg={statusColors[status] || 'secondary'}>
                {status.charAt(0).toUpperCase() + status.slice(1)}
            </Badge>
        );
    };

    const tools = [
        { name: 'Amass', results: amassResults, link: 'https://github.com/owasp-amass/amass', tool: 'amass' },
        { name: 'Sublist3r', results: sublist3rResults, link: 'https://github.com/aboul3la/Sublist3r' },
        { name: 'Assetfinder', results: assetfinderResults, link: 'https://github.com/tomnomnom/assetfinder' },
        { name: 'GAU', results: gauResults, link: 'https://github.com/lc/gau', tool: 'gau' },
        { name: 'CTL', results: ctlResults, link: 'https://github.com/pdiscoveryio/ctl' },
        { name: 'Subfinder', results: subfinderResults, link: 'https://github.com/projectdiscovery/subfinder' },
        { name: 'ShuffleDNS', results: shuffleDNSResults, link: 'https://github.com/projectdiscovery/shuffledns' },
        { name: 'CeWL + ShuffleDNS', results: cewlResults, link: 'https://github.com/digininja/CeWL', tool: 'cewl' },
        { name: 'GoSpider', results: gospiderResults, link: 'https://github.com/jaeles-project/gospider', tool: 'gospider' },
        { name: 'Subdomainizer', results: subdomainizerResults, link: 'https://github.com/nsonaniya2010/SubDomainizer', tool: 'subdomainizer' }
    ];

    return (
        <Modal data-bs-theme="dark" show={showReconResultsModal} onHide={handleCloseReconResultsModal} size="lg">
            <Modal.Header closeButton>
                <Modal.Title className="text-danger">Reconnaissance Results</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <Table striped bordered hover>
                    <thead>
                        <tr>
                            <th>Tool</th>
                            <th className="text-center">Status</th>
                            <th className="text-center">Results</th>
                            <th className="text-center">Execution Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {tools.map((tool, index) => (
                            <tr key={index}>
                                <td>
                                    <a 
                                        href={tool.link}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-danger text-decoration-none"
                                    >
                                        {tool.name}
                                    </a>
                                </td>
                                <td className="text-center">
                                    {getStatusBadge(tool.results?.status)}
                                </td>
                                <td className="text-center">
                                    {getSubdomainCount(tool.results, tool.tool)}
                                    {tool.columnTitle ? ` ${tool.columnTitle}` : ' Subdomains'}
                                </td>
                                <td className="text-center">
                                    {formatExecutionTime(tool.results?.execution_time)}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </Table>
            </Modal.Body>
        </Modal>
    );
}; 