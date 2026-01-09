const fetchConsolidatedSubdomains = async (activeTarget, setConsolidatedSubdomains, setConsolidatedCount) => {
    if (!activeTarget || !activeTarget.id) {
        console.log('No active target available for fetching consolidated subdomains');
        setConsolidatedSubdomains([]);
        setConsolidatedCount(0);
        return;
    }

    try {
        const response = await fetch(
            `/api/consolidated-subdomains/${activeTarget.id}`
        );

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        setConsolidatedSubdomains(data.subdomains || []);
        setConsolidatedCount(data.count || 0);
    } catch (error) {
        console.error('Error fetching consolidated subdomains:', error);
        setConsolidatedSubdomains([]);
        setConsolidatedCount(0);
    }
};

export default fetchConsolidatedSubdomains; 