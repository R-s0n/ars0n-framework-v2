const fetchConsolidatedNetworkRanges = async (activeTarget, setConsolidatedNetworkRanges, setConsolidatedNetworkRangesCount) => {
    if (!activeTarget || !activeTarget.id) {
        console.log('No active target available for fetching consolidated network ranges');
        setConsolidatedNetworkRanges([]);
        setConsolidatedNetworkRangesCount(0);
        return;
    }

    try {
        const response = await fetch(
            `/api/consolidated-network-ranges/${activeTarget.id}`
        );

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        setConsolidatedNetworkRanges(data.network_ranges || []);
        setConsolidatedNetworkRangesCount(data.count || 0);
    } catch (error) {
        console.error('Error fetching consolidated network ranges:', error);
        setConsolidatedNetworkRanges([]);
        setConsolidatedNetworkRangesCount(0);
    }
};

export default fetchConsolidatedNetworkRanges; 