// What a Nuclei scan runs when nobody has chosen otherwise.
//
// Mirrors server/utils/nucleiDefaults.go. Kept in one module because this list was previously
// written out four times on the client alone (the config modal's initial state, its load fallback,
// App.js's two config loaders) and twice more on the server. Six copies means the default quietly
// depends on which path the operator arrived through, and a change that misses one is invisible
// until a scan comes back with the wrong templates.
//
// Deliberately not every category and not every severity. The excluded four either do not apply to
// a web target or answer a question the framework already answers elsewhere:
//
//   network       port and service level checks, covered by the IP/port scanning stage
//   dns           resolver level checks, covered by the DNS enumeration stage
//   technologies  fingerprinting, not a vulnerability class, and duplicates httpx tech detection
//   headless      needs a browser per template, costs far more time than it returns
//
// Informational severity is off for the same reason: it is the bulk of Nuclei's output and almost
// none of it is actionable, so it buries the findings that are.
//
// These are defaults, not limits. Every category and severity is still selectable in the Nuclei
// Configure modal, and a target with a saved config keeps whatever it was given. The Select All
// buttons build their sets from the full category lists in the modal, not from these, so they
// still select everything.

export const DEFAULT_NUCLEI_TEMPLATES = [
  'cves',
  'vulnerabilities',
  'exposures',
  'misconfiguration',
  'takeovers',
];

export const DEFAULT_NUCLEI_SEVERITIES = [
  'critical',
  'high',
  'medium',
  'low',
];
