// The auto-scan step vocabulary, shared by the UI and written into auto_scan_state by the Go
// orchestrator (server/utils/autoScanOrchestrator.go). These strings ARE the wire format: the
// server writes current_step using exactly these values, so changing one here without changing the
// sequencer there makes a running scan render as an unknown step.
//
// Lifted out of wildcardAutoScan.js when the browser-side scan loop was deleted. That loop was why
// a refresh stopped a scan; the sequence now runs server-side and the browser only watches.
export const AUTO_SCAN_STEPS = {
  IDLE: 'idle', // 0
  AMASS: 'amass', // 1
  SUBLIST3R: 'sublist3r', // 2
  ASSETFINDER: 'assetfinder', // 3
  GAU: 'gau', // 4
  CTL: 'ctl', // 5
  SUBFINDER: 'subfinder', // 6
  CONSOLIDATE: 'consolidate', // 7
  HTTPX: 'httpx', // 8
  SHUFFLEDNS: 'shuffledns', // 9
  SHUFFLEDNS_CEWL: 'shuffledns_cewl', // 10
  CONSOLIDATE_ROUND2: 'consolidate_round2', // 10.5
  HTTPX_ROUND2: 'httpx_round2', // 10.75
  GOSPIDER: 'gospider', // 11
  SUBDOMAINIZER: 'subdomainizer', // 12
  CONSOLIDATE_ROUND3: 'consolidate_round3', // 12.5
  HTTPX_ROUND3: 'httpx_round3', // 12.75
  NUCLEI_SCREENSHOT: 'nuclei-screenshot', // 13
  METADATA: 'metadata', // 14
  NUCLEI: 'nuclei', // 15
  COMPLETED: 'completed' // 16
};

export default AUTO_SCAN_STEPS;
