const { z } = require('zod');
const { apiGet, apiPost, apiDelete } = require('../api');
const { limitResults, clampLimit } = require('../utils/truncate');

// Per-tool configuration for the URL workflow, plus the FFUF wordlist store. Every Configure modal
// the URL workflow has: FFUF, Arjun, x8, Nuclei, and the one shared modal behind Katana,
// GoSpider and LinkFinder.
//
// The reason this file is not a thin GET/POST wrapper is the shape of the Go save handlers. Every
// one of them decodes the request body into a struct and re-marshals the whole struct into the
// config column, so a POST is a full replace, not a patch. SaveFFUFConfig decodes into a zero-value
// FFUFConfig; a body carrying only {"threads": 10} therefore writes threads 10 and blanks the
// operator's headers, cookies, wordlist choice, matchers and filters in the same statement. The
// crawler handlers are the same shape with a different floor: saveCrawlerConfig decodes onto a
// struct pre-populated with DefaultKatanaURLConfig and friends, so an omitted field reverts to the
// built-in default rather than to zero, which is quieter and just as destructive. saveNucleiConfig
// replaces every column including advanced_config wholesale.
//
// So save here always reads the current config first, deep merges the caller's patch over it, and
// posts the result. An agent that sets one rate limit must not silently discard the session headers
// a human spent an afternoon getting right, and this repo has already shipped that bug once.
//
// The other thing worth knowing before writing anything: the Routing & WAF Probe measures a safe
// request rate and its Apply writes the result straight into these same configs. Rate, delay,
// thread and concurrency fields are therefore shared state between this tool and the probe, and
// whichever ran last wins. See PROBE_FIELDS below for exactly which keys per tool.

// Anything off the wire is capped at this, per field. Wordlists, POST bodies and interactsh tokens
// are the fields that get long.
const VALUE_LIMIT = 2000;

// === What each tool's config actually holds ====================================================
//
// These tables are the field names the Go structs carry, which is the only list that matters: a key
// missing from the struct is discarded on save without an error. That is not hypothetical, it is
// how headerFuzzValue and cookieFuzzValue were collected by the FFUF modal for months and never
// reached the database. Anything a caller sends that is not listed here is reported back as
// unrecognised rather than left to vanish.

// WHAT THIS CONFIG STILL DOES, AND WHAT IT NO LONGER DOES.
//
// The runner these scan fields once drove is retired: the live ffuf is the fuzz flow, reached through
// manage_fuzz. Everything here describing a scan (url, method, postData, the fuzz* phase switches,
// the wordlist ids, the matchers and filters) is written and then read by nothing, so saving it
// returns success and changes no traffic. Configure a run with manage_fuzz{action:'save_step'}.
//
// headers and cookies are the exception and are NOT dead: they are still read as auth material by the
// crawler config, the WAF probe and the scoped credential loader. That is the only reason this config
// is still writable at all.
const FFUF_FIELDS = {
  url: 'RETIRED, ignored by every runner. Use manage_fuzz{action:"save_step"} to set what gets fuzzed. Kept only so an existing stored value round-trips.',
  method: 'HTTP verb for the fuzzed request: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.',
  headers: 'STILL LIVE as auth material. Static headers as [{name, value}]; the crawler config, the WAF probe and the scoped credential loader all read these. Not used to compose a fuzz run.',
  cookies: 'Cookie header value, e.g. "sid=abc; theme=dark". Not sent during the cookie-fuzzing phase, because two values for one name make the result unattributable.',
  postData: 'Request body for POST/PUT. May contain the keyword.',
  fuzzEndpoints: 'Run the path-fuzzing phase (default on). Turn it off on a single-page app that answers every path with the same shell.',
  fuzzHeaders: 'Run the header-name fuzzing phase. Sends every wordlist entry as a request header against one unchanging URL, which works where path fuzzing cannot.',
  fuzzCookies: 'Run the cookie-name fuzzing phase. This is how you find a debug or is_admin cookie the application reads but never sets.',
  headerWordlistId: 'Wordlist for the header phase. "builtin-headers" or an id from manage_wordlists.',
  cookieWordlistId: 'Wordlist for the cookie phase. "builtin-cookies" or an id from manage_wordlists.',
  headerFuzzValue: 'Value paired with each fuzzed header name. A unique canary makes a reflected or honoured header easy to spot.',
  cookieFuzzValue: 'Value paired with each fuzzed cookie name.',
  http2: 'Send over HTTP/2 (-http2).',
  followRedirects: 'Follow redirects (-r), default on. Off reports the redirect itself, which is what you want when everything 302s to a login page and you need to see that.',
  timeout: 'Per-request timeout in seconds.',
  wordlistId: 'Wordlist for the endpoint phase: builtin-default, builtin-small, builtin-large, or an id from manage_wordlists.',
  customWordlist: 'Inline wordlist path, legacy. Prefer wordlistId.',
  wordlistName: 'Display name of the chosen wordlist. Cosmetic.',
  extensions: 'Comma separated extensions appended to the keyword, e.g. ".php,.bak".',
  keyword: 'The token replaced with each wordlist entry, default FUZZ.',
  matchStatusCodes: 'Status codes to report, e.g. "200-299,301,302,307,401,403,405,500".',
  matchLines: 'Report responses with this line count (-ml).',
  matchSize: 'Report responses of this byte size (-ms).',
  matchWords: 'Report responses with this word count (-mw).',
  matchRegex: 'Report responses matching this regex (-mr).',
  matcherMode: 'How multiple matchers combine: "or" or "and".',
  filterStatusCodes: 'Status codes to drop (-fc). The first thing to set when a target answers 200 to everything.',
  filterLines: 'Drop responses with this line count (-fl).',
  filterSize: 'Drop responses of this byte size (-fs).',
  filterWords: 'Drop responses with this word count (-fw).',
  filterRegex: 'Drop responses matching this regex (-fr).',
  filterMode: 'How multiple filters combine: "or" or "and".',
  threads: 'Concurrent requests (-t). Shared with the probe.',
  rateLimit: 'Requests per second cap (-rate), 0 for uncapped. Shared with the probe.',
  delay: 'Delay between requests (-p), e.g. "0.1" or a range "0.1-2.0". String, not a number.',
  maxTime: 'Hard stop for the whole run in seconds, 0 for none.',
  verbose: 'Verbose ffuf output.',
  autoCalibrate: 'Auto-calibration (-ac), default on. Without it a target serving one shell for every path returns the entire wordlist as findings.',
  recursion: 'Recurse into discovered directories.',
  recursionDepth: 'How deep recursion goes, 0 for unlimited.',
  proxyURL: 'Upstream proxy, e.g. http://127.0.0.1:8080.',
  clientCert: 'Client certificate path for mutual TLS.',
  clientKey: 'Client key path for mutual TLS.',
  stopOnAll: 'Abort the run on the first spurious error (-sa). Against anything behind a WAF this ends the scan in seconds with nothing to show, which is why it is off.',
  stopOn403: 'Abort on the first 403.',
  stopOnErrors: 'Abort on the first error.',
};

const ARJUN_FIELDS = {
  method: 'IGNORED. The verb now comes from the verb groups of the scan; use `verbs` instead.',
  headers: 'Headers sent with each probe. See the headers note on manage_tool_config.',
  threads: 'Concurrent requests. Shared with the probe.',
  delay: 'Delay between requests within a thread, in seconds. This is the knob the probe writes to pace arjun, since arjun has no rate flag: the aggregate rate is threads/delay.',
  timeout: 'Per-request timeout in seconds.',
  chunkSize: 'How many candidate parameters go in one request. Large chunks are fast and are also what trips a request-size limit.',
  wordlist: 'Path to a parameter-name wordlist inside the arjun container. Empty uses arjun\'s own.',
  passiveMode: 'IGNORED. Under -i, --passive derives the host from an empty value and aborts the whole run, so it is never emitted.',
  stableDetection: 'Extra requests to confirm a hit is stable rather than a fluke of a noisy response.',
  jsonOutput: 'Ask arjun for JSON. Leave on, the parser expects it.',
  includeParams: 'Extra parameters to always test, comma separated.',
  excludeParams: 'Parameters to never test, comma separated.',
  verbs: 'Per-verb overrides, keyed by HTTP method: {"POST": {"threads": 2, "timeout": 30}}. Each verb group is its own tool invocation, so anything on the command line can differ by verb. Anything absent falls back to the top-level value. Merged one verb at a time, so saving a GET override leaves an existing POST override alone; within a verb the object is replaced, so send the full override set for that verb.',
};

// x8 is configured per INJECTION PLACE, not per verb. Its passes vary by WHERE the candidates go
// (query, body, headers, cookies), and the verb comes from the endpoint itself.
//
// This table previously described a struct that no longer exists: method, maxDepth, concurrency,
// verifyRequests, checkReflection, checkBooleans and valueSize were all removed from X8Config, so
// every field an agent could actually set was reported back as unrecognised while the ones it was
// told to use were silently discarded on save.
const X8_FIELDS = {
  headers: 'Headers sent with every request, and the only way an x8 scan reaches an authenticated endpoint. See the headers note on manage_tool_config. Send session cookies as a header named Cookie: on the cookies place x8 appends its candidates to that header rather than replacing it.',
  bodyType: 'x8 -t, how body parameters are encoded: json or urlencoded. Only sent for the body place, because x8 uses it as the parameter template and it would otherwise write JSON into the URL. Note x8 accepts "urlencoded", not the "urlencode" its own --help prints.',
  bodyTemplate: 'x8 -b, e.g. {"data":{%s}}. The %s marks where candidates go, which is how you reach parameters nested under a wrapper object. Ignored without the marker, and only sent for the body place.',
  wordlist: 'Path to a parameter-name wordlist inside the x8 container, which mounts the repo wordlists directory at /app/wordlists. Empty falls back per place: param-names.txt for query and body, ffuf-headers.txt for headers, ffuf-cookies.txt for cookies. x8 ships NO wordlist and reads stdin when -w is absent, so an empty path with no fallback tests only its 11 built-in custom parameter names.',
  workers: 'x8 -W, concurrent url checks. x8 default is 1.',
  requestsPerUrl: 'x8 -c, concurrent requests within one url. A different knob from workers, also 1 by default.',
  delay: 'x8 -d, delay between requests in MILLISECONDS. This is what the Routing & WAF Probe writes to pace x8.',
  timeout: 'x8 --timeout, per-request timeout in seconds.',
  learnRequests: 'x8 --learn-requests, requests spent learning the target\'s normal response variation before testing. Too few and ordinary page noise looks like a finding.',
  maxParamsPerRequest: 'x8 -m, candidates per request. 0 uses x8\'s own per-place caps: 256 query, 64 headers, 512 body.',
  reflectedOnly: 'x8 --reflected-only, which DISABLES page comparison, x8\'s primary detector, and searches for reflected values only. Leave false unless reflection is all you want.',
  verify: 'x8 --verify, re-check each hit before reporting it.',
  strict: 'x8 --strict, only report parameters that changed a different part of the page.',
  followRedirects: 'x8 -L, follow redirects.',
  disableCustomParameters: 'x8 --disable-custom-parameters. x8 also tests admin, bot, captcha, debug, disable, encryption, env, show, sso, test and waf with non-random values like true and 1. Setting this true removes them, leaving the wordlist only.',
  mimicBrowser: 'x8 --mimic-browser, add the default headers a browser sends.',
  disableColors: 'x8 --disable-colors, keep ANSI escapes out of the stored output.',
  includeScripts: 'Bring content_class=script endpoints (JavaScript bundles) into the target set. Off by default: a bundle served by a CDN has no server-side parameter surface.',
  places: 'Per-injection-place overrides, keyed by query, body, headers or cookies: {"headers": {"workers": 2, "maxParamsPerRequest": 32}}. Each place is its own x8 invocation, so anything on the command line can differ by place, and a header sweep wants very different pacing from a query sweep. Anything absent falls back to the top-level value. Merged one place at a time, so setting a headers override leaves an existing cookies override alone; within a place the object is replaced, so send the full override set for that place.',
  verbs: 'DEPRECATED, read only so an older stored config still resolves. x8 is configured by place, so use places.',
};

// Nuclei splits into columns the handler writes individually plus one free-form advanced_config
// object. advanced_config is a map on the Go side, so keys outside this list survive a round trip,
// unlike every other tool here.
const NUCLEI_FIELDS = {
  targets: 'Attack-surface asset ids to scan. Empty means the target mode decides.',
  templates: 'Template categories to run: cves, vulnerabilities, exposures, technologies, misconfiguration, takeovers, network, dns, headless. ' +
    'Defaults to cves, vulnerabilities, exposures, misconfiguration and takeovers. The other four are off by default because network and dns duplicate the port and DNS enumeration stages, technologies is fingerprinting rather than a vulnerability class, and headless needs a browser per template.',
  severities: 'Severities to report: critical, high, medium, low, info. ' +
    'Defaults to everything except info, which is the bulk of Nuclei output and buries the actionable findings.',
  uploaded_templates: 'Custom templates uploaded through the UI. Objects, passed through untouched.',
  target_mode: '"attack_surface" (URL and Company workflows) or "httpx" (Wildcard, scan the live web servers). Empty saves as attack_surface.',
  template_ids: 'Individual template ids to run, which narrows far harder than a category.',
  exclude_ids: 'Template ids to skip. Reach for this when one noisy template floods the findings.',
  exclude_tags: 'Template tags to skip.',
  advanced_config: 'Nested object of runtime settings, merged key by key rather than replaced. See the advanced_config keys below.',
  'advanced_config.rate_limit': 'Requests per second (-rl). Shared with the probe.',
  'advanced_config.bulk_size': 'Hosts analysed in parallel (-bs). Shared with the probe.',
  'advanced_config.concurrency': 'Templates run in parallel (-c). Shared with the probe.',
  'advanced_config.timeout': 'Per-request timeout in seconds. Shared with the probe.',
  'advanced_config.retries': 'Retries per request. Shared with the probe.',
  'advanced_config.max_host_error': 'Errors tolerated per host before it is skipped. Shared with the probe.',
  'advanced_config.follow_redirects': 'Follow redirects (-fr).',
  'advanced_config.follow_host_redirects': 'Follow same-host redirects only (-fhr).',
  'advanced_config.max_redirects': 'Redirect hop limit.',
  'advanced_config.custom_headers': 'Headers as an array of raw "Name: value" strings, not name/value objects. Shared with the probe.',
  'advanced_config.proxy': 'Upstream proxy, e.g. http://127.0.0.1:8080.',
  'advanced_config.no_interactsh': 'Disable out-of-band detection (-ni). Turning this on silently removes every blind SSRF and blind RCE template\'s ability to confirm anything.',
  'advanced_config.interactsh_server': 'Self-hosted interactsh server URL.',
  'advanced_config.interactsh_token': 'Auth token for that server.',
  'advanced_config.headless': 'Enable headless browser templates.',
  'advanced_config.headless_bulk_size': 'Headless hosts in parallel.',
  'advanced_config.headless_concurrency': 'Headless templates in parallel.',
  'advanced_config.scan_strategy': 'auto, host-spray or template-spray.',
  'advanced_config.stop_at_first_match': 'Stop a host after its first match (-spm).',
  'advanced_config.protocol_types': 'Restrict to these protocols, e.g. ["http","dns"].',
  'advanced_config.template_condition': 'DSL filter over template metadata, e.g. contains(tags,\'cve\').',
  'advanced_config.author_filter': 'Only templates by these authors.',
  'advanced_config.system_resolvers': 'Use the system resolvers (-sr).',
  'advanced_config.leave_default_ports': 'Keep :80 and :443 in the URL (-ldp).',
};

const KATANA_FIELDS = {
  baseUrl: 'scheme://host[:port] to crawl. Empty uses the scope target. The probe sets this when the configured URL redirects somewhere else.',
  rateLimit: 'Requests per second (-rl), 0 for katana\'s own default of 150/s. Shared with the probe.',
  concurrency: 'Concurrent fetchers (-c). Shared with the probe.',
  parallelism: 'Inputs processed concurrently (-p).',
  depth: 'Crawl depth.',
  timeout: 'Per-request timeout in seconds.',
  retry: 'Retries per request.',
  crawlDurationSeconds: 'Hard stop for the crawl, 0 for no limit.',
  maxResponseSize: 'Largest response body katana will read, in bytes.',
  jsCrawl: 'Parse JavaScript for endpoints (-jc).',
  jsluice: 'Use jsluice for deeper JavaScript parsing. Memory intensive.',
  knownFiles: 'Fetch known files: all, robotstxt, sitemapxml.',
  fieldScope: 'Scope rule: dn, rdn, fqdn, or a regex.',
  extensionFilter: 'Extensions to skip, comma separated, e.g. png,css,woff.',
  ignoreQueryParams: 'Collapse URLs that differ only in query parameters.',
  automaticFormFill: 'Fill and submit forms found while crawling.',
  headless: 'Crawl with a real browser. Slower, and the only way to see a client-rendered route.',
  xhrExtraction: 'Record XHR requests the page makes, which is where the API surface of an SPA is.',
  cache_bust: 'Append a cache-busting parameter. The probe sets this when it finds a cache in front of the target.',
  reuse_session: 'Keep one connection across requests.',
  proxy: 'Upstream proxy.',
  headers: 'Extra headers as [{name, value}].',
  useFFUFAuth: 'Send the target\'s saved FFUF headers and cookie so the crawler sees the application rather than its login page.',
};

const GOSPIDER_FIELDS = {
  baseUrl: 'scheme://host[:port] to crawl. Empty uses the scope target.',
  concurrent: 'Concurrent requests per matching domain (-c). Shared with the probe.',
  threads: 'Sites crawled in parallel (-t).',
  depth: 'Crawl depth, 0 for infinite.',
  delay: 'Whole seconds between requests. GoSpider has no rate flag, so this is the only pacing it has and it is what the probe writes: the offered rate is concurrent/delay.',
  randomDelay: 'Extra random delay in seconds on top of delay.',
  timeout: 'Per-request timeout in seconds.',
  sitemap: 'Crawl sitemap.xml.',
  robots: 'Crawl robots.txt.',
  otherSource: 'Pull URLs from third-party sources such as the archives (-a).',
  includeSubs: 'Include subdomains found in those third-party sources.',
  includeOtherSource: 'Actually crawl the third-party URLs too (-r), not just list them.',
  js: 'Parse JavaScript for endpoints.',
  noRedirect: 'Do not follow redirects.',
  blacklist: 'Regex of URLs to skip.',
  whitelist: 'Regex of URLs to keep.',
  whitelistDomain: 'Domain to restrict the crawl to.',
  userAgent: 'User-Agent string.',
  cookie: 'Cookie header value.',
  proxy: 'Upstream proxy.',
  headers: 'Extra headers as [{name, value}].',
  useFFUFAuth: 'Send the target\'s saved FFUF headers and cookie.',
  cache_bust: 'Append a cache-busting parameter.',
  reuse_session: 'Keep one connection across requests.',
};

const LINKFINDER_FIELDS = {
  baseUrl: 'scheme://host[:port]. Empty uses the scope target.',
  inputSource: '"both" (default), "discovered_js" or "target". LinkFinder is a regex over text: pointed at a target URL it reads one page, which on an SPA is an empty shell. discovered_js feeds it the bundles Katana, GoSpider and the manual crawl already found, which is the job it exists for.',
  domainMode: 'Follow the script tags on the target page (-d). Only meaningful for the target arm.',
  maxJsFiles: 'Ceiling on JavaScript files fetched. 0 means NO limit and is the default: every ' +
    'file discovered so far is read. Any other value drops the excess newest-first with nothing ' +
    'recorded about it, so a truncated run is indistinguishable from a complete one. Each file ' +
    'is one request, so this is the whole cost of the scan.',
  requestDelayMs: 'Milliseconds between files. LinkFinder has no pacing of its own, so the framework waits this long, and this is what the probe writes.',
  timeout: 'Per-request timeout in seconds.',
  regexFilter: 'Only keep endpoints matching this regex (-r), e.g. ^/api/.',
  cookies: 'Cookie header value. LinkFinder takes cookies but not headers, so a bearer token in an Authorization header cannot be given to it.',
  useFFUFAuth: 'Reuse the saved FFUF session, cookies only for this tool.',
  includeRelative: 'Keep relative hits such as v1/users, resolved against the file they were found in rather than the site root.',
  headers: 'Present in the config for symmetry, but LinkFinder does not send headers.',
};

// Which keys the Routing & WAF Probe's Apply can overwrite per tool, from translateField in
// wafProbeUtils.go. Reported alongside a get so an agent can see what it is sharing with the probe
// before it writes, rather than after a value it set changes on its own.
const PROBE_FIELDS = {
  ffuf: ['rateLimit', 'threads', 'delay', 'timeout', 'headers', 'http2', 'followRedirects',
         'autoCalibrate', 'matchStatusCodes', 'filterStatusCodes', 'filterSize', 'filterLines',
         'filterWords', 'stopOn403', 'stopOnAll', 'stopOnErrors'],
  arjun: ['delay', 'threads', 'timeout', 'headers', 'method'],
  x8: ['delay', 'concurrency', 'timeout', 'headers', 'method'],
  nuclei: ['advanced_config.rate_limit', 'advanced_config.concurrency', 'advanced_config.bulk_size',
           'advanced_config.timeout', 'advanced_config.retries', 'advanced_config.max_host_error',
           'advanced_config.custom_headers'],
  katana: ['rateLimit', 'concurrency', 'baseUrl', 'cache_bust', 'reuse_session', 'timeout',
           'delay', 'headers', 'method'],
  gospider: ['delay', 'concurrent', 'baseUrl', 'cache_bust', 'reuse_session', 'timeout', 'headers',
             'method'],
  linkfinder: ['requestDelayMs', 'inputSource', 'baseUrl', 'timeout', 'headers', 'method'],
};

// The defaults the config modals start from, used only when the API reports no stored config at
// all. Without them, a first save from MCP that sets one field would write a config where every
// other field is a Go zero value: threads 0, no matchers, GET turned into an empty method. The
// crawler and nuclei routes already answer a missing row with their own defaults, so they need
// nothing here.
const SEED_DEFAULTS = {
  ffuf: {
    method: 'GET', headers: [], cookies: '', postData: '',
    fuzzEndpoints: true, fuzzHeaders: false, fuzzCookies: false,
    headerWordlistId: 'builtin-headers', cookieWordlistId: 'builtin-cookies',
    headerFuzzValue: 'ars0nprobe', cookieFuzzValue: 'ars0nprobe',
    http2: false, followRedirects: true, timeout: 10,
    wordlistId: 'builtin-default', wordlistName: '', extensions: '', keyword: 'FUZZ',
    matchStatusCodes: '200-299,301,302,307,401,403,405,500', matcherMode: 'or', filterMode: 'or',
    threads: 40, rateLimit: 0, verbose: false, autoCalibrate: true,
    recursion: false, recursionDepth: 0,
    stopOnAll: false, stopOn403: false, stopOnErrors: false,
  },
  arjun: {
    method: 'GET', headers: [], threads: 5, delay: 0, timeout: 10, chunkSize: 500,
    wordlist: '', passiveMode: false, stableDetection: true, jsonOutput: true,
    includeParams: '', excludeParams: '',
  },
  x8: {
    method: 'GET', headers: [], bodyType: 'json', wordlist: '', maxDepth: 1, concurrency: 10,
    delay: 0, learnRequests: 9, verifyRequests: 3, checkReflection: true, disableColors: true,
    followRedirects: false, checkBooleans: true, valueSize: 5,
  },
};

// HTTPX is the gate between Consolidate and everything downstream: metadata, ROI scoring and the
// Nuclei target list are all built from whatever it decided was live. A config that probes only
// 80 and 443 therefore shrinks the whole rest of the workflow, and it does so invisibly, because a
// small Live Web Servers count looks like a small attack surface rather than a narrow port list.
//
// The save handler decodes into map[string]interface{} and marshals the whole map back, so it is a
// full replace like the others and needs the same read-merge-write treatment.
const HTTPX_FIELDS = {
  ports: 'Ports to probe, as an array of integers. This is the single most consequential setting here: everything downstream only sees what httpx found.',
  threads: 'Concurrent workers (-threads).',
  rateLimit: 'Requests per second (-rate-limit). Shared with the Routing & WAF Probe.',
  timeout: 'Per-request timeout in seconds.',
  retries: 'Retries per host.',
  matchCodes: 'Status codes to keep, comma separated, e.g. "200,204,301,302,401,403".',
  probes: 'Nested object of what to record per host: statusCode, title, techDetect, server, contentLength, location, favicon, jarm, responseTime, lineCount, wordCount, method, websocket, ip, cname, asn, cdn, probe. Merged key by key.',
  filters: 'Nested object: filterCode, filterLength, filterLineCount, filterWordCount, filterString, filterRegex, filterCdn, filterResponseTime, filterCondition, filterDuplicates.',
  matchers: 'Nested object: matchLength, matchLineCount, matchWordCount, matchString, matchRegex, matchCdn, matchResponseTime, matchCondition, matchFavicon.',
  misc: 'Nested object: followRedirects, maxRedirects, probeAllIps, tlsProbe, cspProbe, tlsGrab, pipeline, http2, vhost, noFallback, noFallbackScheme, maxHostError.',
  headless: 'Nested object: screenshot, screenshotTimeout. Headless costs a browser per host.',
  extractors: 'Nested object: extractRegex, extractPreset, extractFqdn.',
  customHeaders: 'Extra headers as [{name, value}].',
  proxy: 'Upstream proxy.',
  resolvers: 'Custom DNS resolvers.',
  requestMethods: 'HTTP methods to probe with.',
  requestBody: 'Body to send when probing with a write method.',
};

// The Company workflow's five config surfaces. Four of them are domain or range SELECTIONS rather
// than tuning knobs, which makes them more consequential than they look: they decide which subset
// of everything discovered the next scan actually consumes. Saving an empty or wrong selection
// silently narrows the run, and the card still says the scan succeeded.
// Key names taken from what these routes actually return, not from what the UI labels them. The
// three domain selectors do NOT share a spelling: amass-enum and dnsx use `domains`, katana uses
// `selected_domains`. Guessing one for the other writes a key the handler ignores, and this file's
// own header records that exact failure shipping once already.
const AMASS_INTEL_FIELDS = {
  network_ranges: 'Which discovered CIDR ranges this target carries forward into the IP/port scan. Array.',
};
const AMASS_ENUM_COMPANY_FIELDS = {
  domains: 'Which consolidated root domains Amass Enum will enumerate. Array. This is the input set, so an empty array makes the scan a no-op that still reports success.',
  wildcard_domains: 'Wildcard-derived domains to include as well. Array.',
  include_wildcard_results: 'Whether results from the linked Wildcard targets are folded in.',
};
const DNSX_COMPANY_FIELDS = {
  domains: 'Which consolidated root domains DNSx will resolve. Array, same significance as the Amass Enum selection.',
  wildcard_domains: 'Wildcard-derived domains to include as well. Array.',
  include_wildcard_results: 'Whether results from the linked Wildcard targets are folded in.',
};
const KATANA_COMPANY_FIELDS = {
  selected_domains: 'Which domains Katana crawls for cloud assets. Array. Note the name: this one is selected_domains, while amass-enum and dnsx call the same idea `domains`.',
  selected_wildcard_domains: 'Wildcard-derived domains to crawl. Array.',
  selected_live_web_servers: 'Explicit live web servers to crawl, when a domain is not the right entry point. Array.',
  include_wildcard_results: 'Whether results from the linked Wildcard targets are folded in.',
};
const CLOUD_ENUM_FIELDS = {
  keywords: 'Brute-force keywords, usually the company and brand names. Array.',
  threads: 'Concurrent workers.',
  enabled_platforms: 'Which clouds to enumerate, as an object keyed aws / azure / gcp with boolean values.',
  selected_services: 'Which service types within those clouds to try. Array.',
  selected_regions: 'Regions to try. Array.',
  mutations_file_path: 'Mutation wordlist applied to each keyword.',
  brute_file_path: 'Wordlist used for the brute-force pass.',
  dns_resolver_mode: 'How DNS is resolved during enumeration.',
  custom_dns_server: 'A specific resolver to use.',
  additional_resolvers: 'Extra resolvers. Array.',
  resolver_config: 'Resolver configuration blob.',
  resolver_file_path: 'Path to a resolver list.',
};


// The two archive tools. Their interesting setting is not a rate limit (neither touches the target)
// but WHICH HOSTS to ask the archives about. Before this existed both were hardcoded to the scope
// target's own host, so an adjacent host on another registrable domain -- usually where the API
// lives -- was never queried by either.
const ARCHIVE_HOST_FIELDS = {
  hostMode: '"default" scans the direct host plus every in-scope adjacent host, resolved fresh at ' +
    'run time so a newly crawled host is picked up without editing this. "custom" scans exactly ' +
    'selectedHosts. A string rather than an empty array because "nothing chosen yet" and "the ' +
    'operator chose none" must not look identical.',
  selectedHosts: 'Hosts to query, used only when hostMode is "custom". Array of authorities ' +
    '("api.example.com", or "example.com:8443" when a non-default port is in play). A URL is ' +
    'accepted and reduced to its authority, port included. Read the candidates from ' +
    'get_archive_hosts; a host that is not a candidate is ignored, and selecting none makes the ' +
    'scan refuse rather than report zero endpoints.',
  includeSubdomains: 'Ask the archive about subdomains too (archivefetch drops -no-subs, gau adds ' +
    '--subs). Ignored for any host carrying a non-default port: the CDX index cannot match a ' +
    'wildcard in front of a host:port authority, so the port always wins.',
  timeoutMinutes: 'Bound on EACH host\'s query, not the run. Hosts are queried one at a time, so a ' +
    'run over twelve hosts can take twelve times this.',
};

const WAYBACKURLS_FIELDS = {
  ...ARCHIVE_HOST_FIELDS,
};

const GAU_FIELDS = {
  ...ARCHIVE_HOST_FIELDS,
  providers: 'Archive providers, any of wayback, commoncrawl, otx, urlscan. Defaults to all four. ' +
    'Dropping wayback on the assumption that the Waybackurls scan covers it measured as an 85% ' +
    'loss of archive surface (29 URLs versus 187). An unrecognised name is dropped rather than ' +
    'passed on, because gau exits on one.',
  threads: 'gau --threads, workers to spawn.',
  timeoutSeconds: 'gau --timeout, its own HTTP client timeout per request. Not the process bound; ' +
    'that is timeoutMinutes.',
  retries: 'gau --retries for its HTTP client.',
  blacklist: 'gau --blacklist, file extensions to skip. Array, leading dots optional.',
  fromDate: 'gau --from, YYYYMM. Earliest crawl date to accept.',
  toDate: 'gau --to, YYYYMM. Latest crawl date to accept.',
};

const TOOLS = {
  amass_intel: { path: 'amass-intel-config', fields: AMASS_INTEL_FIELDS, headerShape: 'none' },
  amass_enum_company: { path: 'amass-enum-config', fields: AMASS_ENUM_COMPANY_FIELDS, headerShape: 'none' },
  dnsx_company: { path: 'dnsx-config', fields: DNSX_COMPANY_FIELDS, headerShape: 'none' },
  katana_company: { path: 'katana-company-config', fields: KATANA_COMPANY_FIELDS, headerShape: 'none' },
  cloud_enum: { path: 'cloud-enum-config', fields: CLOUD_ENUM_FIELDS, headerShape: 'none' },
  httpx: {
    path: 'httpx-config', fields: HTTPX_FIELDS, headerShape: 'pair',
    nested: ['probes', 'filters', 'matchers', 'misc', 'headless', 'extractors'],
  },
  ffuf: { path: 'ffuf-config', fields: FFUF_FIELDS, headerShape: 'pair' },
  arjun: { path: 'arjun-config', fields: ARJUN_FIELDS, headerShape: 'map', nested: ['verbs'] },
  // `places` is the live per-pass map and has to merge one level deeper, or a patch touching the
  // headers place replaces the whole object and deletes the operator's other three.
  x8: { path: 'x8-config', fields: X8_FIELDS, headerShape: 'map', nested: ['places', 'verbs'] },
  nuclei: { path: 'nuclei-config', fields: NUCLEI_FIELDS, headerShape: 'none', nested: ['advanced_config'] },
  katana: { path: 'katana-url-config', fields: KATANA_FIELDS, headerShape: 'pair' },
  gospider: { path: 'gospider-url-config', fields: GOSPIDER_FIELDS, headerShape: 'pair' },
  linkfinder: { path: 'linkfinder-url-config', fields: LINKFINDER_FIELDS, headerShape: 'pair' },
  waybackurls: { path: 'waybackurls-url-config', fields: WAYBACKURLS_FIELDS, headerShape: 'none' },
  gau: { path: 'gau-url-config', fields: GAU_FIELDS, headerShape: 'none' },
};

// === manage_tool_config ========================================================================

const manageToolConfigSchema = z.object({
  action: z.enum(['get', 'save']).describe(
    'get: the tool\'s current configuration for this target, plus the writable field names and ' +
    'which of them the Routing & WAF Probe also writes. ' +
    'save: merge a patch over the stored config. The merge is not optional politeness, it is the ' +
    'contract: the Go handlers full-replace, so posting a bare {"threads": 10} straight at the API ' +
    'would blank the operator\'s headers, cookies, wordlist and filters in the same write. This ' +
    'tool reads the current config, deep merges your patch over it, and posts the whole thing, so ' +
    'only the keys you name change. Set replace:true if wiping the rest is genuinely what you want.'),

  tool: z.enum(['amass_intel', 'amass_enum_company', 'dnsx_company', 'katana_company', 'cloud_enum',
    'httpx', 'ffuf', 'arjun', 'x8', 'nuclei', 'katana', 'gospider', 'linkfinder',
    'waybackurls', 'gau'])
    .describe(
      'Which tool\'s configuration. The first five are Company-workflow selections rather than ' +
      'tuning knobs: amass_intel picks which network ranges carry forward, and ' +
      'amass_enum_company, dnsx_company and katana_company each pick which consolidated root ' +
      'domains that scan consumes, so an empty selection makes the scan a no-op that still ' +
      'reports success. cloud_enum holds the brute-force keywords and cloud list. ' +
      'httpx: the live-web-server probe behind all three ' +
      'Consolidate rounds of the Wildcard workflow, and the gate that decides what metadata, ' +
      'ROI scoring and Nuclei ever see, so its port list bounds the whole rest of the run. ' +
      'ffuf: content and endpoint fuzzing, and the target\'s session ' +
      'headers and cookie, which the crawlers reuse through their useFFUFAuth switch. ' +
      'arjun / x8: parameter discovery, two tools with different tradeoffs. ' +
      'nuclei: template selection and runtime tuning. ' +
      'katana / gospider / linkfinder: the three crawlers, which share one Configure modal in the UI. ' +
      'waybackurls / gau: the two archive tools, whose main setting is which hosts to query. ' +
      'Pair with get_archive_hosts to see the candidates first.'),

  target_id: z.string().uuid().describe('The scope target UUID. Configs are stored per target.'),

  config: z.record(z.any()).optional().describe(
    'save: the fields to change, using the exact key names from the field reference that action ' +
    '"get" returns. Anything you leave out keeps its stored value. Arrays replace wholesale, ' +
    'because merging two header lists element by element means nothing; nested objects such as ' +
    'nuclei\'s advanced_config merge key by key. Headers may be given as [{name, value}] for any ' +
    'tool and are converted to the shape that tool actually reads. A key the Go struct does not ' +
    'know is discarded on save without an error, so unrecognised keys are reported back to you.'),

  replace: z.boolean().optional().describe(
    'save: skip the merge and post the config exactly as given (default false). Every field you ' +
    'omit then reverts, to a Go zero value for ffuf, arjun, x8 and nuclei, and to the ' +
    'built-in default for the three crawlers. Use it to reset a config to a known state, not to ' +
    'change one setting.'),

  include_field_reference: z.boolean().optional().describe(
    'get: return the writable field names with a line on each and the probe-shared list ' +
    '(default true). Set false once you already know the fields and just want the values.'),
});

async function manageToolConfig(params) {
  const spec = TOOLS[params.tool];
  if (!spec) return { error: `unknown tool: ${params.tool}` };
  const path = `/${spec.path}/${params.target_id}`;

  if (params.action === 'get') {
    const current = await readConfig(spec, path);
    const out = {
      tool: params.tool,
      target_id: params.target_id,
      // stored:false means nothing was ever saved for this target and the values below are the
      // defaults a scan would run with, not choices anyone made.
      stored: current.stored,
      config: compactConfig(current.config),
    };
    if (params.include_field_reference !== false) {
      out.fields = spec.fields;
      out.probe_writes = PROBE_FIELDS[params.tool];
      out.probe_note =
        'The Routing & WAF Probe writes the fields above when its recommendations are applied, ' +
        'so those values are shared with it and whichever ran last wins.';
    }
    return out;
  }

  if (params.action !== 'save') return { error: `unknown action: ${params.action}` };
  if (!params.config || !Object.keys(params.config).length) {
    return { error: 'save needs config, an object of the fields to change' };
  }

  const patch = normalisePatch(spec, params.config);
  const unknown = unknownFields(spec, params.config);

  let body;
  if (params.replace) {
    body = patch;
  } else {
    const current = await readConfig(spec, path);
    body = deepMerge(current.config, patch, spec.nested || []);
  }

  // created_at round-trips through the nuclei handler as a decoded-but-ignored string; the row is
  // stamped with NOW() regardless. Sending back whatever the read returned only risks a decode
  // error on a field that changes nothing.
  delete body.created_at;

  await apiPost(path, body);

  // Read back rather than trusting the write. The handlers answer {"status":"success"} without
  // echoing what they stored, and the whole point of this tool is that what was stored is not
  // obviously what was sent.
  const after = await readConfig(spec, path);
  return clean({
    tool: params.tool,
    target_id: params.target_id,
    saved: true,
    merged: !params.replace,
    changed_fields: Object.keys(patch),
    unrecognised_fields: unknown.length ? unknown : undefined,
    unrecognised_note: unknown.length
      ? 'Those keys are not in the Go struct for this tool. They were sent anyway in case the ' +
        'struct has grown since, but expect them to be discarded. Check them against the field ' +
        'reference from action "get".'
      : undefined,
    probe_overlap: overlap(params.tool, Object.keys(patch)),
    probe_overlap_note: overlap(params.tool, Object.keys(patch)).length
      ? 'Applying Routing & WAF Probe recommendations to this target will overwrite those fields.'
      : undefined,
    config: compactConfig(after.config),
  });
}

// === manage_wordlists ==========================================================================

const manageWordlistsSchema = z.object({
  action: z.enum(['list', 'upload', 'delete']).describe(
    'list: every wordlist FFUF can use, the three built-ins and everything uploaded. The ids are ' +
    'what go in ffuf\'s wordlistId, headerWordlistId and cookieWordlistId. ' +
    'upload: store a new wordlist from text you supply. ' +
    'delete: remove an uploaded wordlist and its file. Built-ins are refused by the server. ' +
    'Nothing checks whether a config still points at the id you delete, and a config pointing at ' +
    'a missing wordlist falls back to the built-in default at scan time.'),

  name: z.string().optional().describe(
    'upload: the filename to store it under, e.g. "api-paths.txt". This is what the FFUF config ' +
    'modal shows in its dropdown, so make it say what the list is.'),
  content: z.string().optional().describe(
    'upload: the wordlist itself, one entry per line. The MCP server shares no filesystem with ' +
    'the API container, so the content has to travel in the call; there is no path to hand over.'),
  words: z.array(z.string()).optional().describe(
    'upload: the entries as an array instead of one blob of text. Joined with newlines. Use ' +
    'whichever is easier; supplying both appends the array after the text.'),

  wordlist_id: z.string().optional().describe('delete: the wordlist id, from action "list".'),

  max_results: z.number().optional().describe('list: maximum rows (default 50, max 1000)'),
});

async function manageWordlists(params) {
  switch (params.action) {
    case 'list': {
      const rows = await apiGet('/ffuf-wordlists');
      const projected = (Array.isArray(rows) ? rows : []).map((w) => clean({
        id: w.id,
        name: w.name,
        // size is the line count, which is the number that predicts how long a scan takes.
        entries: w.size,
        // Built-ins cannot be deleted and are always present, so this is the one distinction that
        // changes what a caller can do with a row.
        builtin: String(w.id).startsWith('builtin-') || undefined,
        path: w.path,
      }));
      return limitResults(projected, clampLimit(params.max_results));
    }

    case 'upload': {
      const parts = [];
      if (params.content) parts.push(params.content);
      if (params.words?.length) parts.push(params.words.join('\n'));
      if (!parts.length) return { error: 'upload needs content or words' };
      if (!params.name) return { error: 'upload needs name' };

      let text = parts.join('\n');
      // The server counts entries by counting newlines, so a final entry with no trailing newline
      // is not counted and the list reads as one short. Cheaper to fix here than to explain.
      if (!text.endsWith('\n')) text += '\n';

      const out = await uploadWordlist(params.name, text);
      return clean({
        id: out.id,
        name: out.name,
        entries: out.size,
        note: 'Point ffuf at it with manage_tool_config{tool:"ffuf", action:"save", ' +
              'config:{wordlistId:"' + out.id + '"}}.',
      });
    }

    case 'delete': {
      if (!params.wordlist_id) return { error: 'delete needs wordlist_id' };
      if (String(params.wordlist_id).startsWith('builtin-')) {
        return { error: 'built-in wordlists cannot be deleted' };
      }
      await apiDelete(`/ffuf-wordlists/${params.wordlist_id}`);
      return {
        deleted: true,
        wordlist_id: params.wordlist_id,
        note: 'Any config still pointing at it will fall back to the built-in default at scan time.',
      };
    }

    default:
      return { error: `unknown action: ${params.action}` };
  }
}

// === reading and merging =======================================================================

// Returns the stored config plus whether anything was actually stored. The config routes answer a
// missing row with {} for ffuf, arjun and x8, and with a fully populated default object
// for the crawlers and nuclei, so "empty object" is the only signal that nothing exists yet.
async function readConfig(spec, path) {
  const raw = await apiGet(path);
  const cfg = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const stored = Object.keys(cfg).length > 0;
  if (stored) return { stored: true, config: cfg };

  const seed = SEED_DEFAULTS[toolNameFor(spec)];
  return { stored: false, config: seed ? { ...seed } : {} };
}

function toolNameFor(spec) {
  return Object.keys(TOOLS).find((k) => TOOLS[k] === spec);
}

// Merges a patch over a base. Nested keys named in `nested` merge one level deeper, which is what
// nuclei's advanced_config needs: a caller setting rate_limit must not drop the interactsh server
// alongside it. Arrays replace, because there is no sane element-wise merge for a header list or a
// set of template ids and pretending otherwise would make a removal impossible.
function deepMerge(base, patch, nested) {
  const out = { ...base };
  for (const [k, v] of Object.entries(patch)) {
    if (nested.includes(k) && isPlainObject(v) && isPlainObject(out[k])) {
      out[k] = { ...out[k], ...v };
    } else {
      out[k] = v;
    }
  }
  return out;
}

// Puts the caller's patch into the shape the tool reads. The only real work is headers, and it is
// worth doing: ffuf reads h["name"] and h["value"] off each entry, while the arjun and x8
// launchers iterate the map with `for key, value := range header` and emit "key: value" per pair.
// Given {name: "X-Auth", value: "abc"} those three send two junk headers, "name: X-Auth" and
// "value: abc", and never the one that was asked for. So a pair goes out as {"X-Auth": "abc"} for
// them and as {name, value} for everything else, and a caller only has to know one shape.
function normalisePatch(spec, config) {
  const out = { ...config };
  if (Array.isArray(out.headers) && spec.headerShape !== 'none') {
    out.headers = out.headers
      .map(headerPair)
      .filter((h) => h && h.name)
      .map((h) => (spec.headerShape === 'map' ? { [h.name]: h.value } : { name: h.name, value: h.value }));
  }
  return out;
}

// Accepts {name, value}, {key, value} and the single-entry {"X-Auth": "abc"} map, because all three
// exist in this codebase already: the FFUF modal writes the first, the Arjun modal writes the
// second, and the map is what the launchers for arjun and x8 actually read.
function headerPair(h) {
  if (!isPlainObject(h)) return undefined;
  const keys = Object.keys(h);
  if (typeof h.name === 'string' && 'value' in h) return { name: h.name, value: str(h.value) };
  if (typeof h.key === 'string' && 'value' in h) return { name: h.key, value: str(h.value) };
  if (keys.length === 1) return { name: keys[0], value: str(h[keys[0]]) };
  return undefined;
}

// Keys the tool's Go struct has no home for. advanced_config is checked one level in, since that is
// where nuclei's runtime settings live and a typo there is just as silent as one at the top.
function unknownFields(spec, config) {
  const bad = [];
  for (const k of Object.keys(config)) {
    if (!(k in spec.fields)) {
      bad.push(k);
      continue;
    }
    if (k === 'advanced_config' && isPlainObject(config[k])) {
      for (const sub of Object.keys(config[k])) {
        if (!(`advanced_config.${sub}` in spec.fields)) bad.push(`advanced_config.${sub}`);
      }
    }
  }
  return bad;
}

function overlap(tool, keys) {
  const shared = PROBE_FIELDS[tool] || [];
  const hit = new Set();
  for (const k of keys) {
    if (shared.includes(k)) hit.add(k);
    if (k === 'advanced_config') {
      for (const s of shared) if (s.startsWith('advanced_config.')) hit.add(s);
    }
  }
  return [...hit];
}

// === helpers ===================================================================================

const API_BASE = process.env.API_URL || 'http://api:8443';

// api.js speaks JSON only, and this is the one multipart route in the whole contract, so widening
// the shared client for every tool in the server to carry it is not worth it. Same error shape and
// the same tolerant body read as api.js on purpose. The third argument to append is what puts a
// filename in the Content-Disposition header, which is what Go's FormFile("wordlist") requires.
async function uploadWordlist(name, content) {
  const form = new FormData();
  form.append('wordlist', new Blob([content], { type: 'text/plain' }), name);
  form.append('name', name);

  const res = await fetch(`${API_BASE}/ffuf-wordlists/upload`, { method: 'POST', body: form });
  const text = await res.text();
  if (!res.ok) throw new Error(`API POST /ffuf-wordlists/upload failed (${res.status}): ${text}`);
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

// Strips the keys that carry nothing and clips anything long. false and 0 survive: fuzzHeaders
// false and rateLimit 0 are both settings, not absences, and an omitted false would read as true
// against a default that is on. An empty string is treated as an absence because that is exactly
// what it means in these configs, an unset filter or an unset proxy.
function compactConfig(cfg) {
  if (!isPlainObject(cfg)) return cfg;
  const out = {};
  for (const [k, v] of Object.entries(cfg)) {
    if (v === null || v === undefined || v === '') continue;
    if (Array.isArray(v) && v.length === 0) continue;
    if (isPlainObject(v)) {
      const inner = compactConfig(v);
      if (Object.keys(inner).length) out[k] = inner;
      continue;
    }
    out[k] = typeof v === 'string' ? clip(v, VALUE_LIMIT) : v;
  }
  return out;
}

function clean(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined || v === '') continue;
    if (Array.isArray(v) && v.length === 0) continue;
    if (isPlainObject(v) && Object.keys(v).length === 0) continue;
    out[k] = v;
  }
  return out;
}

function clip(text, limit) {
  if (typeof text !== 'string' || text.length <= limit) return text;
  return text.slice(0, limit) + `\n... [truncated, ${text.length - limit} chars remaining]`;
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function str(v) {
  return v === null || v === undefined ? '' : String(v);
}


// === get_archive_hosts =========================================================================

// The candidate list the two archive tools draw from, so a caller can see what "default" resolves
// to before deciding whether to narrow it. Candidates are the scope target's own host plus the
// adjacent hosts the manual crawl observed and the operator left in scope; an out-of-scope host is
// absent entirely rather than present and unticked, because an archive query being passive is not a
// reason to widen the engagement boundary.
const getArchiveHostsSchema = z.object({
  target_id: z.string().uuid().describe('The URL scope target UUID.'),
  tool: z.enum(['waybackurls', 'gau']).describe(
    'Which saved selection to reflect in the `selected` flags. The candidate list itself is ' +
    'the same for both.'),
});

async function getArchiveHosts(params) {
  const res = await apiGet(`/archive-hosts/${params.tool}/${params.target_id}`);
  if (res.error) return res;
  return {
    tool: res.tool,
    host_mode: res.host_mode,
    total: res.total,
    adjacent_count: res.adjacent_count,
    selected_count: res.selected_count,
    targets: (res.targets || []).map((t) => ({
      host: t.host,
      url: t.url,
      is_direct: t.is_direct,
      selected: t.selected,
      crawl_requests: t.requests,
    })),
    note: res.host_mode === 'default'
      ? 'hostMode is "default", so every candidate is queried and a newly crawled host joins ' +
        'automatically. Switch to "custom" with manage_tool_config to narrow it.'
      : 'hostMode is "custom": only the hosts flagged selected are queried.',
  };
}

module.exports = {
  manageToolConfigSchema, manageToolConfig,
  manageWordlistsSchema, manageWordlists,
  getArchiveHostsSchema, getArchiveHosts,
};
