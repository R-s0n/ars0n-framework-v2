const consolidateCompanyDomains = async (activeTarget) => {
    if (!activeTarget || !activeTarget.id) {
        console.error('No active target available');
        return null;
    }

    try {
        const response = await fetch(
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/consolidate-company-domains/${activeTarget.id}`,
            {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
            }
        );

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error consolidating company domains:', error);
        return null;
    }
};

export default consolidateCompanyDomains; 