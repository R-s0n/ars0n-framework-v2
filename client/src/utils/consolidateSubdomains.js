const consolidateSubdomains = async (activeTarget) => {
    if (!activeTarget || !activeTarget.id) {
        console.error('No active target available');
        return null;
    }

    try {
        const response = await fetch(
            `/api/consolidate-subdomains/${activeTarget.id}`,
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
        console.error('Error consolidating subdomains:', error);
        return null;
    }
};

export default consolidateSubdomains; 