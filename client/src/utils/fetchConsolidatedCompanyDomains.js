const fetchConsolidatedCompanyDomains = async (activeTarget, setConsolidatedCompanyDomains, setConsolidatedCompanyDomainsCount) => {
    if (!activeTarget || !activeTarget.id) {
        console.log('No active target available for fetching consolidated company domains');
        setConsolidatedCompanyDomains([]);
        setConsolidatedCompanyDomainsCount(0);
        return;
    }

    try {
        const response = await fetch(
            `/api/consolidated-company-domains/${activeTarget.id}`
        );

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        setConsolidatedCompanyDomains(data.domains || []);
        setConsolidatedCompanyDomainsCount(data.count || 0);
    } catch (error) {
        console.error('Error fetching consolidated company domains:', error);
        setConsolidatedCompanyDomains([]);
        setConsolidatedCompanyDomainsCount(0);
    }
};

export default fetchConsolidatedCompanyDomains; 