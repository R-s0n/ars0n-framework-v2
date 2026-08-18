// The tools that TEST attack vectors, as data rather than as markup.
//
// Each of these sections is the same card repeated with different words in it, so the words live here
// and the card lives in one component. Ten tools written out as JSX would be roughly a thousand lines
// in App.js, and the eleventh would be copied from the tenth along with whatever was wrong with it.
//
// Only what the card SHOWS is here. The install and run commands, the language and whether a tool
// takes a URL list or one URL at a time all matter when the tool is actually wired up, and none of
// them belongs in a bundle the browser downloads to draw a name and a sentence.

export const ATTACK_TOOL_SECTIONS = [  {
    key: 'xss',
    title: 'Cross-Site Scripting (XSS)',
    tools: [
      {
        key: 'dalfox',
        name: 'Dalfox',
        url: 'https://github.com/hahwul/dalfox',
        description: 'Parameter-analysis-driven XSS scanner built for mass automation, with headless DOM verification.',
      },
      {
        key: 'domdig',
        name: 'domdig',
        url: 'https://github.com/fcavallarin/domdig',
        description: 'Headless-browser DOM XSS scanner that crawls single-page apps and fires events to reach sinks.',
      },
      {
        key: 'xssfuzz',
        name: 'xssFuzz',
        url: 'https://github.com/Asperis-Security/xssFuzz',
        description: 'Context-aware XSS fuzzer that ranks reflection contexts before firing payloads.',
      },
    ],
  },
  {
    key: 'sqli',
    title: 'SQL & NoSQL Injection',
    tools: [
      {
        key: 'sqlmap',
        name: 'sqlmap',
        url: 'https://github.com/sqlmapproject/sqlmap',
        description: 'The reference automated SQL injection detection and database takeover tool, covering boolean, error, time-based, UNION, stacked and out-of-band techniques.',
      },
      {
        key: 'ghauri',
        name: 'Ghauri',
        url: 'https://github.com/r0oth3x49/ghauri',
        description: 'Faster sqlmap alternative focused on reliable detection with fewer requests and better WAF handling.',
      },
      {
        key: 'sqlidetector',
        name: 'SQLiDetector',
        url: 'https://github.com/eslam3kl/SQLiDetector',
        description: 'Sends 14 payloads and matches 152 database-error regexes to flag error-based injection at scale. A triage pass: confirm what it flags with sqlmap or Ghauri.',
      },
    ],
  },
  {
    key: 'cmdi',
    title: 'Command Injection & Server-Side Template Injection',
    tools: [
      {
        key: 'commix',
        name: 'Commix',
        url: 'https://github.com/commixproject/commix',
        description: 'All-in-one OS command injection detection and exploitation, covering results-based, blind, time-based and file-based techniques.',
      },
      {
        key: 'sstimap',
        name: 'SSTImap',
        url: 'https://github.com/vladko312/SSTImap',
        description: 'Interactive template injection detection and exploitation across 30+ engines, with shell, file read and write, and code evaluation. The active successor to tplmap.',
      },
      {
        key: 'tinja',
        name: 'TInjA',
        url: 'https://github.com/Hackmanit/TInjA',
        description: 'Fingerprints 44 server-side and client-side template engines using polyglots, so it covers client-side template injection as well as server-side.',
      },
    ],
  },
  {
    key: 'redirect-ssrf',
    title: 'Open Redirect & Server-Side Request Forgery',
    tools: [
      {
        key: 'recollapse',
        name: 'REcollapse',
        url: 'https://github.com/0xacb/recollapse',
        description: 'Builds the payload list. Mutates your webhook URL to defeat the regexes guarding redirect and SSRF validation, and adds the framework’s own bypass forms. Configure the webhook first.',
      },
      {
        key: 'nuclei-dast',
        name: 'Nuclei DAST',
        url: 'https://github.com/projectdiscovery/fuzzing-templates',
        description: 'Fires the payload list at every eligible attack vector, then checks the webhook to see which ones actually called out. Also matches responses that come back directly, for the SSRF that needs no callback at all.',
      },
      {
        key: 'ssrfmap',
        name: 'SSRFmap',
        url: 'https://github.com/swisskyrepo/SSRFmap',
        description: 'Pivots a confirmed SSRF into internal port scanning, file read or worse, through 20+ modules. Becomes available once the scan above has found something.',
      },
    ],
  },
  {
    key: 'lfi',
    title: 'Local File Inclusion (LFI)',
    tools: [
      {
        key: 'lfimap',
        name: 'LFImap',
        url: 'https://github.com/hansmach1ne/LFImap',
        description: 'File inclusion discovery and exploitation covering PHP filter chains, wrappers, log poisoning, remote file inclusion and escalation to code execution.',
      },
      {
        key: 'lfihunt',
        name: 'LFIHunt',
        url: 'https://github.com/Chocapikk/LFIHunt',
        description: 'Runs five file-inclusion checks over a URL list: PHP filter chains, php://input, data://, /proc/self/environ and traversal. Its menu is interactive, but it ships a batch scanner and that is what runs here.',
      },
    ],
  },
  {
    key: 'cache',
    title: 'Web Cache Poisoning & Deception',
    tools: [
      {
        key: 'wcvs',
        name: 'Web Cache Vulnerability Scanner',
        url: 'https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner',
        description: 'Covers unkeyed header and parameter poisoning, fat GET, HTTP method override and web cache deception.',
      },
      {
        key: 'cacheboom',
        name: 'CacheBoom',
        url: 'https://github.com/omranisecurity/CacheBoom',
        description: 'Identifies both web cache deception and web cache poisoning. An early project with low adoption, so trust its findings but not its silence.',
      },
    ],
  },
  {
    key: 'smuggling',
    title: 'Request Smuggling & Desync',
    tools: [
      {
        key: 'smugglex',
        name: 'smugglex',
        url: 'https://github.com/hahwul/smugglex',
        description: 'Rust HTTP request smuggling scanner covering CL.TE, TE.CL and CL.0 desync.',
      },
      {
        key: 'http2smugl',
        name: 'http2smugl',
        url: 'https://github.com/neex/http2smugl',
        description: "Wallarm's HTTP/2 smuggling detector, probing HTTP/2 to HTTP/1.1 downgrade parsing differences.",
      },
    ],
  },
  {
    key: 'access-bypass',
    title: '403 & Access Control Bypass',
    tools: [
      {
        key: 'nomore403',
        name: 'nomore403',
        url: 'https://github.com/devploit/nomore403',
        description: 'Bypasses 401 and 403 through header injection, verb tampering, absolute URI, path mutation and raw desync. The successor to dontgo403.',
      },
      {
        key: 'forbidden',
        name: 'Forbidden',
        url: 'https://github.com/ivan-sincek/forbidden',
        description: 'Bypasses 4xx through protocols, methods, overrides, headers, path mutations, encodings and authentication tests. Built on PycURL, so it can send genuinely malformed requests.',
      },
    ],
  },
  {
    key: 'graphql',
    title: 'GraphQL',
    tools: [
      {
        key: 'graphql-cop',
        name: 'graphql-cop',
        url: 'https://github.com/dolevf/graphql-cop',
        description: 'Runs a battery of GraphQL misconfiguration checks: introspection, field suggestions, batching, denial of service and CSRF over GET.',
      },
      {
        key: 'clairvoyance',
        name: 'clairvoyance',
        url: 'https://github.com/nikitastupin/clairvoyance',
        description: 'Reconstructs a GraphQL schema even when introspection is disabled, by abusing the field suggestions in error messages.',
      },
      {
        key: 'graphw00f',
        name: 'graphw00f',
        url: 'https://github.com/dolevf/graphw00f',
        description: 'Fingerprints the GraphQL engine behind an endpoint and maps that implementation to its known CVEs.',
      },
    ],
  },
  {
    key: 'exposed-files',
    title: 'Sensitive Data Leak',
    tools: [
      {
        key: 'git-dumper',
        name: 'git-dumper',
        url: 'https://github.com/arthaud/git-dumper',
        description: 'Reconstructs a git repository from an exposed .git directory, even when directory listing is disabled. Feed whatever it recovers into a secret scanner.',
      },
      {
        key: 'gittools',
        name: 'GitTools',
        url: 'https://github.com/internetwache/GitTools',
        description: 'Finds exposed .git directories across a list of domains, downloads them and rebuilds the commits.',
      },
      {
        key: 'snallygaster',
        name: 'snallygaster',
        url: 'https://github.com/hannob/snallygaster',
        description: 'Scans for secret files and misconfigurations in one pass: .git, .svn, .env, .DS_Store, core dumps, backups, private keys, phpinfo and server-status.',
      },
    ],
  },
  {
    key: 'secrets',
    title: 'Exposed Secrets',
    tools: [
      {
        key: 'mantra',
        name: 'Mantra',
        url: 'https://github.com/MrEmpy/mantra',
        description: 'Hunts hardcoded API keys and credentials inside the JavaScript and HTML a target serves.',
      },
      {
        key: 'trufflehog',
        name: 'TruffleHog',
        url: 'https://github.com/trufflesecurity/trufflehog',
        description: 'Finds and live-verifies leaked credentials across 800+ detector types. The verification step is what separates a reportable finding from a string that merely looks like a key.',
      },
    ],
  },
  {
    key: 'misc',
    title: 'Miscellaneous',
    tools: [
      {
        key: 'upload-bypass',
        name: 'Upload_Bypass',
        url: 'https://github.com/sAjibuu/upload_bypass',
        description: 'Automates around 40 upload restriction bypass techniques from a saved raw HTTP request.',
      },
      {
        key: 'jwt-tool',
        name: 'jwt_tool',
        url: 'https://github.com/ticarpi/jwt_tool',
        description: 'JWT attack toolkit: alg none, key confusion, jku, x5u and kid injection, HMAC secret cracking and claim tampering.',
      },
      {
        key: 'pphack',
        name: 'pphack',
        url: 'https://github.com/edoardottt/pphack',
        description: 'Headless Chrome driven scanner for client-side prototype pollution.',
      },
    ],
  },
];

export default ATTACK_TOOL_SECTIONS;