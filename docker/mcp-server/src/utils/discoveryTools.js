// The discovery tool vocabulary, mirroring discoveryToolOutputSources in
// server/utils/toolOutputAPI.go.
//
// It lives in its own zod-free module for one reason: test/tooloutput.test.js parses the Go file and
// compares the two lists, and the repo carries no node_modules, so anything that reaches through a
// zod-importing module skips locally. A parity check that only runs inside the image is a parity
// check nobody runs, and drift here is silent by construction. A key missing from this list is a tool
// whose output cannot be read; a key here that Go does not know is a 404 an agent reads as "that tool
// has never run against this target".
const DISCOVERY_TOOL_KEYS = [
  'amass', 'amass_enum_company', 'amass_intel', 'arjun', 'assetfinder', 'censys_company', 'cewl',
  'cloud_enum', 'ctl', 'ctl_company', 'dnsx_company', 'ffuf', 'ffuf_url', 'gau', 'gau_url',
  'github_recon', 'gospider', 'gospider_url', 'httpx', 'investigate', 'katana_company', 'katana_url',
  'linkfinder_url', 'metabigor_company', 'metadata', 'nuclei', 'nuclei_screenshot',
  'securitytrails_company', 'shodan_company', 'shuffledns', 'shufflednscustom', 'subdomainizer',
  'subfinder', 'sublist3r', 'waf_probe', 'waybackurls', 'x8',
];

module.exports = { DISCOVERY_TOOL_KEYS };
