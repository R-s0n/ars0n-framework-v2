const monitorIPPortScanStatus = async (scanId, onStatusUpdate, onComplete, onError) => {
  const API_BASE_URL = '/api';

  const checkStatus = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/ip-port-scan/status/${scanId}`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();

      if (onStatusUpdate) {
        onStatusUpdate(data);
      }

      switch (data.status) {
        case 'success':
          if (onComplete) {
            onComplete(data);
          }
          return; // Stop monitoring
        case 'error':
          if (onError) {
            onError(data.error_message || 'Unknown error');
          }
          return; // Stop monitoring
        case 'pending':
        case 'discovering_ips':
        case 'port_scanning':
          // Continue monitoring
          setTimeout(checkStatus, 3000);
          break;
        default:
          console.warn('Unknown scan status:', data.status);
          setTimeout(checkStatus, 3000);
      }
    } catch (error) {
      console.error('Error checking IP/Port scan status:', error);
      if (onError) {
        onError(error.message);
      }
    }
  };

  checkStatus();
};

export default monitorIPPortScanStatus; 