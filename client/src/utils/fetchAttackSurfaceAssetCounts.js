const fetchAttackSurfaceAssetCounts = async (activeTarget, setASNsCount, setNetworkRangesCount, setIPAddressesCount, setLiveWebServersCount, setCloudAssetsCount, setFQDNsCount) => {
    if (!activeTarget || !activeTarget.id) {
        console.error('No active target available');
        setASNsCount(0);
        setNetworkRangesCount(0);
        setIPAddressesCount(0);
        setLiveWebServersCount(0);
        setCloudAssetsCount(0);
        setFQDNsCount(0);
        return;
    }

    try {
        const response = await fetch(
            `/api/attack-surface-asset-counts/${activeTarget.id}`,
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
        setASNsCount(data.asns || 0);
        setNetworkRangesCount(data.network_ranges || 0);
        setIPAddressesCount(data.ip_addresses || 0);
        setLiveWebServersCount(data.live_web_servers || 0);
        setCloudAssetsCount(data.cloud_assets || 0);
        setFQDNsCount(data.fqdns || 0);
    } catch (error) {
        console.error('Error fetching attack surface asset counts:', error);
        setASNsCount(0);
        setNetworkRangesCount(0);
        setIPAddressesCount(0);
        setLiveWebServersCount(0);
        setCloudAssetsCount(0);
        setFQDNsCount(0);
    }
};

export default fetchAttackSurfaceAssetCounts; 