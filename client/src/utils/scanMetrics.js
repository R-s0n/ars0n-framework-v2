// G1.14 (first increment of decomposing App.js): pure scan-metric helpers lifted verbatim from
// App.js's module scope. No React / state / closures — behavior is identical to before.

// Count non-empty lines in an httpx scan's result blob.
export const getHttpxResultsCount = (scan) => {
  if (!scan?.result?.String) return 0;
  return scan.result.String.split('\n').filter((line) => line.trim()).length;
};

// Estimate IP/Port scan time from the consolidated network ranges (~1000 IPs/min, Naabu).
export const calculateEstimatedScanTime = (networkRanges) => {
  const totalIPs = networkRanges.reduce((total, range) => {
    const cidr = range.cidr_block || range.cidr;
    const [, prefix] = cidr.split('/');
    const prefixLength = parseInt(prefix);
    const ipCount = Math.pow(2, 32 - prefixLength);
    return total + ipCount;
  }, 0);

  const estimatedMinutes = Math.ceil(totalIPs / 1000);
  const estimatedSeconds = estimatedMinutes * 60;

  if (estimatedSeconds < 60) {
    return `${estimatedSeconds}s`;
  } else if (estimatedSeconds < 3600) {
    const minutes = Math.round(estimatedSeconds / 60);
    return `${minutes}m`;
  } else if (estimatedSeconds < 86400) {
    const hours = Math.round(estimatedSeconds / 3600);
    return `${hours}h`;
  } else {
    const days = Math.round(estimatedSeconds / 86400);
    return `${days}d`;
  }
};
