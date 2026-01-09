const investigateFQDNs = async (activeTarget) => {
    if (!activeTarget || !activeTarget.id) {
        console.error('No active target available');
        return null;
    }

    try {
        const response = await fetch(
            `/api/investigate-fqdns/${activeTarget.id}`,
            {
                method: 'POST',
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
        console.error('Error investigating FQDNs:', error);
        return null;
    }
};

export default investigateFQDNs;

