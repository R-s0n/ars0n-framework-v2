export const fetchDNSxRawResults = async (scanId) => {
  try {
    const response = await fetch(
      `/api/dnsx-company/${scanId}/raw-results`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch DNSx raw results');
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching DNSx raw results:', error);
    throw error;
  }
}; 