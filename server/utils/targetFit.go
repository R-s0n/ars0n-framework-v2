package utils

// PER-BUG-CLASS TARGET FIT AND TESTABILITY, for the operator deciding WHETHER a target is worth
// picking for a given bug class, BEFORE any crawling or scanning.
//
// WHY THIS EXISTS. The methodology in methodology.go tells you how to WORK a target you have already
// chosen and can already reach. It presupposes you are "logged in as a real user" and can "exercise
// every role you can obtain". It never asks the question that actually decides an engagement: can you
// reach the thing this bug class lives in AT ALL?
//
// TWO expensive misses taught this, both IDOR, and they are the reason the idor-bola entry below is
// written the way it is:
//   (1) An API was picked as an "excellent IDOR target" because it exposed a Swagger doc full of
//       /api/users/{id} object endpoints. Every one answered 401 Bearer and the token endpoint needed
//       a provisioned appName+appToken with no self-registration. The object map was perfect and
//       completely untestable - no obtainable context.
//   (2) A second API was then called an "unauthenticated IDOR" because object-looking paths returned
//       200/404/500 with no 401. Reading the BODIES killed it: the 200 was a soft auth failure
//       ({"error":"need authorization header"}), the 404s were Express "Cannot GET /x" (the paths were
//       client-side routes, not API routes), and the one real endpoint errored identically for an int,
//       a GUID and a big number - so the id was almost certainly a random GUID, unguessable, with no
//       leak source. Neither a boundary nor an obtainable identifier was ever shown.
//
// Those two misses are the whole lesson of real-world IDOR, and it generalises: an endpoint answering
// without auth is not a bug if the data is meant to be public, and "change the id" is not a bug if you
// can neither guess the id (random GUID) nor find it leaked. A bug class has a PREREQUISITE that
// decides testability, and some prerequisites INVERT the heuristics that are right for others: IDOR and
// SQLi want a plain origin with no WAF in the way, but cache poisoning REQUIRES a cache/CDN in front -
// the very thing you were avoiding. "Find me a good target for X" has a different answer for every X,
// and this is where those answers live. Served over /methodology to both the UI and the MCP so the
// operator, human or AI, can ask before investing.

// TargetFit is the selection-time profile for one bug class.
type TargetFit struct {
	Class string `json:"class"`
	// AlsoKnownAs carries the other names an operator might ask for this class by.
	AlsoKnownAs []string `json:"also_known_as,omitempty"`
	// GoodSignals are what make a target promising for this class - what to look for while selecting.
	GoodSignals []string `json:"good_signals"`
	// Prerequisite is the one thing that decides testability. If it does not hold, the target cannot
	// be tested for this class however good the surface looks. This is the gate that is skipped most.
	Prerequisite string `json:"testability_prerequisite"`
	// AntiSignals are the shapes that look promising but are not testable, or that kill this class.
	AntiSignals []string `json:"anti_signals"`
	// ReconChecks are the cheap selection-time probes that confirm the prerequisite BEFORE investing.
	ReconChecks []string `json:"recon_checks"`
	// Oracle is how you will know the bug fired - the observable signal this class is confirmed by.
	Oracle string `json:"oracle,omitempty"`
}

// targetFitByClass is the catalogue, ordered roughly by how often it is asked for. The class ids line
// up with the attack catalogue (client/src/data/attacks.js -> attackCatalog.go) so the selection view
// and the "what is this attack" view speak the same vocabulary.
var targetFitByClass = []TargetFit{
	{
		Class:       "idor-bola",
		AlsoKnownAs: []string{"idor", "bola", "broken object level authorization", "object-level access control"},
		GoodSignals: []string{
			"Requests carry a direct object reference the caller controls: an id/name for a user, order, document, account, tenancy or invoice, sitting in the path, query, body or a readable token.",
			"Multi-user / multi-tenant data - other principals' records EXIST to cross into (a single-user app has nothing to reach).",
			"A list-then-detail pattern, or a list/search/autocomplete/export endpoint: it both proves other objects exist AND is where an otherwise-unguessable id tends to leak.",
			"PREDICTABLE identifiers - sequential ints (/users/123 -> 124), short numbers, timestamps, base64/hex of an int, auto-increment ids echoed in Location/ETag - because you can enumerate those yourself, so impact scales to mass extraction.",
		},
		Prerequisite: "TWO things, and skipping either is the classic false IDOR. (1) You must be able to CROSS AN AUTHORIZATION BOUNDARY - reach an object you are not entitled to. An endpoint that returns data with no auth is NOT an IDOR if that data is intended to be public (a shared business card, a published profile, a directory); the boundary must be real - another tenant, a private record, fields the owner never exposes. (2) You must be able to OBTAIN the target object's IDENTIFIER: guess it (only if it is predictable) OR find it leaked in a response you can already reach. A random GUID/UUIDv4 (122 random bits) that you can neither see nor guess is NOT an exploitable IDOR - iterating it is computationally infeasible. Holding TWO obtainable accounts satisfies both at once (you have B's real id and A's session to test it with), which is why two cheap accounts is the ideal target.",
		AntiSignals: []string{
			"Object keyed ONLY by a random GUID/UUIDv4 that never appears in any response you can reach and cannot be guessed - there is nothing to enumerate, so no IDOR to prove by iteration (unless you first find the leak).",
			"The data returned is INTENDED to be public (directory, business card, published listing) - no boundary is crossed, so an unauthenticated 200 is not a finding.",
			"Provisioned-only auth (enterprise SSO, machine appName+appToken) with no self-registration AND no genuinely-unauth private object surface - you cannot obtain a context to test from.",
			"Single-tenant / single-user app - nobody else's objects exist to cross into.",
		},
		ReconChecks: []string{
			"Read the BODY, never just the status. A 200 can be a soft auth failure (e.g. {\"error\":\"need authorization header\"}); a 404 'Cannot GET /x' is an Express no-such-route (often a client-side route mistaken for an API); a 500 can be a generic lookup error. Confirm the endpoint actually RETURNS AN OBJECT before calling it unauth-readable.",
			"Classify the identifier: sequential/predictable (enumerable -> high impact) vs random GUID (needs a leak). If GUID, the real work is finding WHERE another principal's id leaks - a list/search endpoint, a profile, a share link, an error message, a JWT claim.",
			"Establish how to obtain a context: open instant email/password signup? credentials provided? two accounts? a genuinely unauth-and-private object? If none of these, the target is not IDOR-testable, whatever the object surface looks like.",
			"Design the PoC as account A (session) requesting account B's object by B's real id - that proves the boundary AND the obtainability together. With one account, you still need a second principal's id from somewhere.",
		},
		Oracle: "Using principal A's context (or no auth) with principal B's identifier returns B's PRIVATE data - a boundary crossed, not public data re-fetched. Two accounts make it unambiguous: A's session, B's id, B's data back.",
	},
	{
		Class:       "access-control",
		AlsoKnownAs: []string{"broken access control", "bfla", "broken function level authorization", "privilege escalation", "vertical privilege escalation", "forced browsing"},
		GoodSignals: []string{
			"A privilege HIERARCHY exists: anonymous < member < manager < admin, or free < paid < enterprise, or tenant-user < tenant-admin. The more tiers, the more boundaries to cross.",
			"Admin/management functionality reachable at guessable paths (/admin, /api/admin/*, /internal/*) or behind client-side-only gating (the button is hidden but the endpoint is live).",
			"The same action exposed at different privilege (GET allowed, DELETE/PUT maybe not; a low role can call a high-role mutation).",
			"Multi-step flows where one step's authorization is checked but a later/direct step is not.",
		},
		Prerequisite: "You can occupy the LOWER side of a privilege boundary and there is a HIGHER-privilege function to reach. Unlike IDOR (object-level, needs the object's id), this is FUNCTION-level: you are testing whether a low role can invoke a high role's operation or a hidden endpoint at all. You need a low-priv account (or anon) you can obtain, and knowledge of the privileged endpoints (from JS bundles, docs, or a higher-priv account to compare against).",
		AntiSignals: []string{
			"Flat authorization - everyone is the same role, so there is no vertical boundary to cross (object-level IDOR may still apply).",
			"Privileged endpoints enforced server-side on every call with no client-trust (the hidden-button-live-endpoint pattern is absent).",
			"You cannot obtain even the lowest-privilege context, and nothing is reachable anonymously.",
		},
		ReconChecks: []string{
			"Enumerate privileged routes from the frontend bundle (admin components, feature flags, role checks done in JS) and from content discovery - the gap between client gating and server enforcement is the bug.",
			"As the LOW role, call a function you should not have; as anon, call a member function. Compare to a high-priv account if you have one.",
			"Try method switching and step-skipping: GET-allowed -> DELETE/PUT; jump straight to step 3 of a flow whose step 1 did the auth check.",
		},
		Oracle: "A lower-privilege (or anonymous) principal successfully invokes a function reserved for a higher privilege - the server performs the action or returns the privileged data rather than 401/403.",
	},
	{
		Class:       "reflected-xss",
		AlsoKnownAs: []string{"xss", "reflected cross-site scripting", "type-1 xss"},
		GoodSignals: []string{
			"User input echoed back into an HTML response: search terms, error messages, breadcrumbs, 'you searched for X', 404 pages that quote the path.",
			"Server-rendered HTML pages (Content-Type text/html) rather than a pure JSON API.",
			"Often testable UNAUTHENTICATED - search and error pages usually need no account.",
		},
		Prerequisite: "Your input must REACH an HTML/JS rendering context in the RESPONSE and come back insufficiently encoded. A JSON API that never renders HTML has no reflected-XSS surface (look at DOM-XSS instead). Confirm a unique marker you send is reflected into an HTML response.",
		AntiSignals: []string{
			"JSON-only APIs (reflection in JSON that is never rendered as HTML is not XSS).",
			"A pure SPA where the server returns only data and the browser renders it - that is DOM-XSS, a different class and tool.",
			"A strict nonce-based CSP with no unsafe-inline - raises the bar sharply; note it during selection.",
		},
		ReconChecks: []string{
			"Send a distinctive marker (e.g. rs0nXSS1337) in each parameter and grep the HTML response for it reflected unencoded.",
			"Check Content-Type is text/html and read the Content-Security-Policy header - a strict CSP changes the effort a lot.",
		},
		Oracle: "A marker reflected into an executable HTML/JS context (not entity-encoded); confirmed when a benign payload parses as markup.",
	},
	{
		Class:       "stored-xss",
		AlsoKnownAs: []string{"persistent xss", "stored cross-site scripting", "type-2 xss", "second-order xss"},
		GoodSignals: []string{
			"User-generated content shown to OTHER users: profiles, display names, comments, support tickets, chat, reviews, uploaded filenames, B2B content a supplier/admin views.",
			"Admin or support panels that render end-user-submitted input.",
			"Cross-boundary rendering (a low-priv user's input viewed in a high-priv context).",
		},
		Prerequisite: "A write path you can reach (usually needs an account) AND a VIEWER context where the stored value is rendered as markup - ideally a DIFFERENT or higher-privilege user. Stored input that only ever renders back to you, escaped, is not a finding. Confirm both the write and the unescaped render.",
		AntiSignals: []string{
			"Input only ever shown back to the submitter, and escaped.",
			"No second viewer / no admin or cross-user rendering of the content.",
		},
		ReconChecks: []string{
			"Map which inputs are persisted and re-displayed, and crucially WHO sees them later.",
			"Check whether a second (victim/admin) context exists and whether you can get it to render your value.",
		},
		Oracle: "A value stored by one user renders as markup when viewed by another user/context.",
	},
	{
		Class:       "dom-xss",
		AlsoKnownAs: []string{"dom-based xss", "client-side xss", "type-0 xss"},
		GoodSignals: []string{
			"A rich client-side SPA (React/Angular/Vue) that reads location.hash / location.search / postMessage / document.referrer and writes to a sink (innerHTML, document.write, eval, dangerouslySetInnerHTML).",
			"Client-side routing with fragment (#) parameters - fragments never leave the browser, so no WAF or server sees them.",
		},
		Prerequisite: "A client-side source -> sink data flow in the page's JavaScript. Requires a real browser / headless engine (domdig) to drive and confirm - raw-HTTP tools are blind to it. Confirm the JS actually reads attacker-controllable input into a dangerous sink.",
		AntiSignals: []string{
			"Server-rendered-only apps with little client JS.",
			"No client-side use of location/hash/postMessage.",
		},
		ReconChecks: []string{
			"Read the bundled JS for sources (location.*, postMessage, referrer) flowing into sinks (innerHTML/eval/setAttribute).",
			"Drive it with a real browser or domdig; the corpus must contain a fragment vector for domdig to reach it.",
		},
		Oracle: "Attacker-controlled source reaches a DOM sink and executes in the browser (no server round-trip needed).",
	},
	{
		Class:       "sqli",
		AlsoKnownAs: []string{"sql injection", "sqli"},
		GoodSignals: []string{
			"A parameter that flows into a SQL query: search, filter, sort/orderBy, numeric ids, legacy endpoints, report builders.",
			"Backends with raw SQL or light ORM use; error messages that leak SQL.",
			"An observable oracle: database error, boolean content difference, or time delay.",
		},
		Prerequisite: "A parameter reaching a SQL datastore AND an oracle you can observe (error-based, boolean-based, or time-based). Note the edge: WAFs DO interfere with SQLi (it is payload-based), so a no-WAF or a non-prod instance helps. Confirm the oracle before committing.",
		AntiSignals: []string{
			"NoSQL / GraphQL / document-store backends (see nosqli).",
			"Fully parameterized ORM with no error/boolean/time oracle.",
			"An aggressive bot-management/WAF edge that blocks payloads before they reach the app.",
		},
		ReconChecks: []string{
			"Baseline a parameter, then send a single quote and a boolean pair (' OR '1'='1 vs ' AND '1'='2) and watch status/content/length deltas; try a time payload if blind.",
			"Fingerprint the DB from error strings; check whether the edge blocks a benign quote.",
		},
		Oracle: "A SQL error, a true/false content difference keyed to the injected condition, or a controllable response delay.",
	},
	{
		Class:       "nosqli",
		AlsoKnownAs: []string{"nosql injection", "mongodb injection", "operator injection"},
		GoodSignals: []string{
			"JSON APIs backed by MongoDB/Elasticsearch/CouchDB where request fields become query terms.",
			"Login, filter, and search endpoints that accept JSON objects (so an object can be slipped where a scalar is expected).",
		},
		Prerequisite: "A JSON body/parameter that reaches a NoSQL query AND the app accepts an OBJECT where it expects a scalar (so you can inject operators like {\"$ne\":null}, {\"$gt\":\"\"}, {\"$regex\":...}), with an oracle (auth bypass, changed result count). Strict schema validation that rejects objects kills it.",
		AntiSignals: []string{
			"SQL backends (see sqli).",
			"Strict input schema/validation that rejects non-scalar values outright.",
		},
		ReconChecks: []string{
			"In an auth or filter JSON field send {\"$ne\":null} / {\"$gt\":\"\"} and watch for auth bypass or an enlarged result set.",
			"Detect the datastore from errors/headers; confirm the endpoint parses JSON objects for that field.",
		},
		Oracle: "Operator injection changes the query's logic: authentication bypassed, or a result set that grows/shrinks with the operator.",
	},
	{
		Class:       "path-traversal-lfi",
		AlsoKnownAs: []string{"path traversal", "directory traversal", "lfi", "local file inclusion", "rfi", "arbitrary file read"},
		GoodSignals: []string{
			"A parameter that names a FILE or PATH: download?file=, ?template=, ?lang=, ?page=, ?doc=, image/report/export handlers, log viewers.",
			"Apps that read from disk by a user-supplied name, or include templates/pages by name (PHP include, server-side render by path).",
		},
		Prerequisite: "A parameter whose value is used to locate a file on the server, where you can influence the path (../, absolute path, null byte on old stacks, encoded separators). The oracle is file contents (reflected) or a differential (exists vs not). PHP stacks add RFI/wrappers; note the stack.",
		AntiSignals: []string{
			"File references are opaque ids resolved server-side to fixed paths (no user-controlled path component).",
			"Strict allow-list of filenames/extensions enforced before the read.",
		},
		ReconChecks: []string{
			"Find file/path/template/page parameters; send ../ sequences and an absolute path (/etc/passwd, C:\\windows\\win.ini) and watch for file contents or a path-dependent error.",
			"Try encodings (%2e%2e%2f, double-encoding) and, on PHP, php://filter and data:// wrappers.",
		},
		Oracle: "Server returns the contents of a file outside the intended directory (or a path-dependent behaviour that proves the read reaches an attacker-chosen path).",
	},
	{
		Class:       "cmdi",
		AlsoKnownAs: []string{"os command injection", "command injection", "rce", "shell injection"},
		GoodSignals: []string{
			"Features that shell out: ping/traceroute/network tools, file conversion, archive extraction, backup/restore, media/image processing, admin diagnostics.",
		},
		Prerequisite: "An input that reaches an OS command, with an oracle (output reflected, or blind via time/OOB). Rare and high-impact; confirm the feature plausibly invokes a shell before spending time.",
		AntiSignals: []string{"No feature that executes system commands; input handled entirely in-process."},
		ReconChecks: []string{
			"Find command-adjacent features; test with time-delay (; sleep 5) or OOB (nslookup canary) metacharacters across ; | & $() `` newline.",
		},
		Oracle: "Injected command executes: reflected command output, a controllable delay, or an OOB DNS/HTTP callback.",
	},
	{
		Class:       "ssti",
		AlsoKnownAs: []string{"server-side template injection", "template injection"},
		GoodSignals: []string{
			"User input rendered through a server-side template engine: invoices, PDFs, emails, report names, profile fields echoed into a themed page, B2B portals (Thymeleaf/Jinja/Twig/Freemarker/Velocity).",
		},
		Prerequisite: "Input that reaches a server-side TEMPLATE (not just HTML). Confirm with a math polyglot: ${7*7} / {{7*7}} / #{7*7} / *{7*7} rendering to 49. Needs a write/echo path that is template-evaluated server-side.",
		AntiSignals: []string{"Plain string interpolation with no template engine; client-only templating."},
		ReconChecks: []string{
			"Set a controllable field to a polyglot and render the surface (page/PDF/email); look for 49.",
			"On a hit, fingerprint the engine with a non-destructive probe before anything heavier.",
		},
		Oracle: "A template expression you injected is evaluated server-side (e.g. 7*7 renders as 49).",
	},
	{
		Class:       "xxe",
		AlsoKnownAs: []string{"xml external entity", "xxe injection"},
		GoodSignals: []string{
			"Endpoints that accept and PARSE XML: SOAP/OTA feeds, SAML, SVG/DOCX/XLSX uploads, XML import, or a JSON endpoint that also accepts application/xml.",
		},
		Prerequisite: "An endpoint that actually PARSES XML you supply (a real XML reader, DTD/entities not disabled). Confirm the body is parsed (415 vs an XML parse error on malformed input) before attempting entity resolution. Blind/OOB is the usual channel.",
		AntiSignals: []string{"Endpoints that discard the body; JSON-only parsers that reject XML with 415."},
		ReconChecks: []string{
			"Flip Content-Type to application/xml (or use the XML upload) and send malformed XML: a parse error means it is parsed; a 415 means it is not.",
			"Then test a benign external/parameter entity against an OOB canary.",
		},
		Oracle: "An external entity resolves - an OOB callback, a file read reflected into the response, or an XML parser error that proves entity processing.",
	},
	{
		Class:       "ssrf",
		AlsoKnownAs: []string{"server-side request forgery"},
		GoodSignals: []string{
			"Features that make the SERVER fetch a URL: webhooks/callbacks, url=/image-from-url, import-from-URL, PDF/screenshot renderers, link previews, document/avatar fetchers, SSO jwks_uri/metadata.",
			"Cloud-hosted apps (AWS/GCP/Azure) where a server-side fetch can reach a metadata endpoint.",
		},
		Prerequisite: "An input that triggers a SERVER-SIDE outbound request you can observe - out-of-band (a canary host you control catches the hit) or inferable (timing/response/error differences). Without a server-fetch feature there is no SSRF.",
		AntiSignals: []string{"No features that cause the server to fetch a URL."},
		ReconChecks: []string{
			"Find url/callback/webhook/import/render parameters; point one at an OOB canary and watch for the callback.",
			"If blind, use timing against internal vs external targets; try the cloud metadata endpoint only with explicit authorization.",
		},
		Oracle: "The server makes a request to an attacker-chosen host (seen on an OOB canary) or returns/behaves differently for internal vs external targets.",
	},
	{
		Class:       "open-redirect",
		AlsoKnownAs: []string{"open redirect", "unvalidated redirect", "url redirection"},
		GoodSignals: []string{
			"Redirect parameters: returnUrl, next, redirect, url, continue, dest - especially in login/logout/SSO flows.",
		},
		Prerequisite: "A parameter whose value controls a Location redirect to an arbitrary host. Confirm the server actually emits a 3xx to your value (or a client-side redirect reads it). Low severity alone; valuable chained (into OAuth token theft, SSRF).",
		AntiSignals: []string{"Redirect targets validated against an allow-list / only same-origin paths accepted."},
		ReconChecks: []string{
			"Set the redirect param to an external host and watch the Location header / client navigation.",
			"Try bypasses (//evil, https:evil, path-relative, @-tricks) only against a param that already redirects.",
		},
		Oracle: "The application redirects the user to an attacker-controlled external host via the parameter.",
	},
	{
		Class:       "cache-poisoning",
		AlsoKnownAs: []string{"web cache poisoning", "web cache deception", "cache deception"},
		GoodSignals: []string{
			"A CACHE or CDN IN FRONT of the app - Cloudflare, Akamai, Fastly, Varnish, CloudFront (this is the class where a CDN is a FEATURE, not an obstacle, inverting the IDOR/SQLi heuristic).",
			"Cacheable responses: 200s with Age / X-Cache / CF-Cache-Status: HIT, cache-control public/max-age, static-looking pages.",
			"POISONING: an UNKEYED input that influences the response (X-Forwarded-Host/-Scheme/-Port, X-Host, custom headers, or a query param the cache ignores in its key but the app reflects).",
			"DECEPTION: authenticated pages served under URLs the cache treats as static (…/account.css, …/profile?x=1.js) so a victim's private page gets cached publicly.",
		},
		Prerequisite: "For POISONING, confirm all three: (a) responses are actually CACHED (Age/X-Cache/CF-Cache-Status HIT on a repeat), (b) some input is UNKEYED (changes the response but not the cache key), (c) that unkeyed input is reflected or otherwise impactful. For DECEPTION, confirm the cache stores a response for an authenticated URL that the victim's browser would populate. Either way a cache/CDN must be present - a plain origin with no cache and cache-control: no-store is NOT a target (the opposite of what IDOR/SQLi want).",
		AntiSignals: []string{
			"No cache/CDN in front; everything private / no-store (good for IDOR, useless here).",
			"Every input is keyed (cache varies on it), so you cannot poison a shared entry.",
		},
		ReconChecks: []string{
			"Send a request twice and look for Age increasing / X-Cache or CF-Cache-Status going MISS->HIT.",
			"Add an unkeyed header (X-Forwarded-Host: canary) with a cache-buster and see if the canary is reflected AND whether it persists to other requests.",
			"For deception, request an authenticated page with a static-looking suffix and check whether it gets cached.",
			"Run WCVS/the cache section against a URL that is confirmed cacheable.",
		},
		Oracle: "An attacker-influenced or victim-private value served from cache to OTHER users, proven by a cache HIT returning the injected/private content.",
	},
	{
		Class:       "request-smuggling",
		AlsoKnownAs: []string{"http request smuggling", "desync", "http desync"},
		GoodSignals: []string{
			"A front-end/back-end chain (CDN/load-balancer -> origin) that may parse request framing differently; HTTP/1.1 to the back end.",
		},
		Prerequisite: "A multi-hop proxy chain with a differential in how Content-Length/Transfer-Encoding or framing is parsed. High-risk and easy to cause collateral impact - many programmes restrict it, and this framework's guidance is to be cautious. Confirm scope rules allow it.",
		AntiSignals: []string{"Single-hop/no front-end proxy; HTTP/2 end-to-end with strict framing; programme forbids it."},
		ReconChecks: []string{
			"Identify the edge vs origin servers; use timing-based CL.TE/TE.CL probes conservatively, never load-style.",
		},
		Oracle: "A desync: a crafted request affects a SUBSEQUENT request/response on the shared connection (observed carefully, without mass impact).",
	},
	{
		Class:       "host-header-injection",
		AlsoKnownAs: []string{"host header injection", "password reset poisoning", "host header attack"},
		GoodSignals: []string{
			"Password-reset / email-link flows that build an absolute URL from the request Host (reset links, verification links, invites).",
			"Apps that reflect the Host into the response body, a redirect, or a cached key.",
		},
		Prerequisite: "The application must TRUST the Host (or X-Forwarded-Host) header for something security-relevant - the link in a reset email, a redirect target, a cached response. Confirm the header influences output before investing; the highest-impact form is reset-link poisoning, which needs a reset flow you can trigger for a victim address.",
		AntiSignals: []string{"Host validated against an allow-list; absolute URLs built from fixed config, not the request Host."},
		ReconChecks: []string{
			"Send a spoofed Host / X-Forwarded-Host and look for it reflected in the body, a redirect Location, or (with a reset flow) the emailed link.",
			"Check whether the edge or app rejects an unknown Host outright.",
		},
		Oracle: "A spoofed Host lands in a security-relevant output - a poisoned reset link pointing at an attacker host, a redirect, or a reflected/cached value.",
	},
	{
		Class:       "csrf",
		AlsoKnownAs: []string{"cross-site request forgery", "csrf", "xsrf"},
		GoodSignals: []string{
			"State-changing actions (change email/password, transfer, settings, role grant) performed with COOKIE auth and no anti-CSRF token.",
			"Forms/endpoints that accept simple content types (form-urlencoded) so a cross-site form can submit them.",
		},
		Prerequisite: "Session auth that the browser attaches automatically (cookies) AND a state-changing action with NO unpredictable per-request token / no SameSite protection / no origin check. A Bearer-token-in-header API is generally not CSRF-able (the token is not auto-sent). Confirm the action succeeds cross-origin without a token.",
		AntiSignals: []string{
			"Auth via Authorization: Bearer header (not cookies) - nothing is auto-attached cross-site.",
			"SameSite=Lax/Strict cookies, anti-CSRF tokens validated server-side, or strict Origin/Referer checks.",
			"The sensitive action requires a JSON content type the browser cannot send cross-site without CORS.",
		},
		ReconChecks: []string{
			"Check how auth travels (cookie vs header) and whether cookies are SameSite.",
			"Replay a state-changing request with the CSRF token removed/altered and from a foreign Origin; see if it still succeeds.",
		},
		Oracle: "A state-changing action completes using only the victim's ambient cookie, driven from an attacker origin with no valid anti-CSRF token.",
	},
	{
		Class:       "cors-misconfiguration",
		AlsoKnownAs: []string{"cors misconfiguration", "cors", "cross-origin resource sharing"},
		GoodSignals: []string{
			"APIs returning sensitive data that set Access-Control-Allow-Origin dynamically (reflecting the request Origin) especially with Access-Control-Allow-Credentials: true.",
		},
		Prerequisite: "An endpoint that returns data worth stealing AND reflects an attacker Origin in Access-Control-Allow-Origin (or trusts null/a wildcard subdomain) WITH credentials allowed. Without credentials+reflected-origin, the misconfiguration is usually not exploitable.",
		AntiSignals: []string{"Static allow-list of origins; no ACAC:true; public data only (nothing to steal)."},
		ReconChecks: []string{
			"Send an Origin: https://evil.example and check whether Access-Control-Allow-Origin echoes it and Access-Control-Allow-Credentials is true.",
			"Try Origin: null and a sibling/subdomain to see what is trusted.",
		},
		Oracle: "A cross-origin page on an attacker-controlled origin can read an authenticated response (ACAO reflects the attacker origin and ACAC:true).",
	},
	{
		Class:       "jwt-session",
		AlsoKnownAs: []string{"jwt attacks", "jwt", "session fixation", "session management", "token flaws"},
		GoodSignals: []string{
			"JWTs used for auth/session, visible in requests - you can read the header/payload and probe the signature.",
			"Session cookies: check for fixation (cookie set before login and not rotated), weak/predictable values, missing HttpOnly/Secure.",
		},
		Prerequisite: "You can obtain a token/session to inspect and manipulate (usually a single account is enough). The bug is in how the token is VALIDATED: alg:none accepted, weak HMAC secret, key confusion (RS256->HS256), unverified kid/jku, or a session that is not rotated on login. Confirm you can read and resubmit the token.",
		AntiSignals: []string{"Opaque server-side session ids with no client-verifiable structure (nothing to forge); well-configured libraries that pin the algorithm."},
		ReconChecks: []string{
			"Decode the JWT; test alg:none, a stripped signature, and (if HMAC) a weak-secret crack; try RS256->HS256 key confusion with the public key.",
			"For sessions: does the id change on login (fixation)? is it random? HttpOnly/Secure/SameSite set?",
		},
		Oracle: "A token you forged/altered (or a fixed session you planted) is accepted as a valid authenticated identity.",
	},
	{
		Class:       "auth-oauth",
		AlsoKnownAs: []string{"authentication", "oauth", "oidc", "saml", "sso", "account takeover", "password reset", "mfa bypass", "account pre-hijacking"},
		GoodSignals: []string{
			"Self-serve auth flows you can exercise: OAuth/OIDC login, SAML, passwordless/OTP, password reset, MFA enrolment, email change, social login.",
			"Callback URLs, state/nonce handling, redirect_uri, tokens visible in the flow.",
		},
		Prerequisite: "You can actually REACH and drive the auth flow (usually unauthenticated to start). Note: the identity provider itself is often OUT OF SCOPE (a third-party Auth0/Okta/Ping host) - confirm the testable surface is the application's own callback/reset/link handling, not the IdP.",
		AntiSignals: []string{
			"Auth fully delegated to an out-of-scope IdP with nothing app-side to test.",
			"No self-serve reset/change/enrol flows reachable.",
		},
		ReconChecks: []string{
			"Walk the login/reset/registration flow and capture state/nonce/redirect_uri/token handling and where secrets travel (URL vs body).",
			"Check redirect_uri validation, state binding/single-use, reset-token strength/scoping, and whether an account can be pre-created for an email the victim later registers.",
		},
		Oracle: "A flow flaw that yields another user's session/account (leaked or replayable code/token, poisoned reset link, redirect_uri bypass, MFA skip, pre-hijack).",
	},
	{
		Class:       "mass-assignment",
		AlsoKnownAs: []string{"mass assignment", "autobinding", "over-posting", "parameter binding"},
		GoodSignals: []string{
			"Create/update endpoints that bind a JSON/form body straight onto a model (frameworks: Rails, Spring, Django, Express/Mongoose, Laravel).",
			"Objects with privileged fields you should not set: role, isAdmin, verified, balance, ownerId, tenantId, price, approved.",
		},
		Prerequisite: "An endpoint that accepts an object and PERSISTS fields you did not intend to be settable. You need a writable resource (usually an account) and knowledge of the privileged field names (from a GET of the same object, the JS, or docs). Confirm the extra field is actually stored.",
		AntiSignals: []string{"Strict server-side allow-list / DTO that ignores unknown fields; the privileged fields are set only by server logic and rejected from input."},
		ReconChecks: []string{
			"GET an object to learn its full field set, then PUT/POST it back with an added privileged field (role:admin, isVerified:true) and re-read to see if it stuck.",
			"Diff the response before/after to confirm the field persisted, not just echoed.",
		},
		Oracle: "A field you added to the request body is persisted on the object and changes privilege/state (e.g. your role becomes admin, your balance changes).",
	},
	{
		Class:       "business-logic",
		AlsoKnownAs: []string{"business logic", "logic flaw", "workflow bypass", "abuse of functionality"},
		GoodSignals: []string{
			"Multi-step flows with money/quota/state: checkout, coupons, refunds, transfers, subscription tiers, points/credits, invites, approval chains.",
			"Operations where order, repetition, sign, or quantity can be manipulated (negative amounts, re-applying a coupon, skipping a step, replaying a one-time action).",
		},
		Prerequisite: "You can drive the flow end to end and there is a RULE with value behind it (money, quota, access) that the implementation may not enforce as intended. This class is not tool-findable - it needs a reachable flow and an understanding of the intended rule. Usually needs an account.",
		AntiSignals: []string{"No stateful/valued workflow - a read-only or trivially stateless app has little logic to abuse."},
		ReconChecks: []string{
			"Map each valued flow and write down the intended rule, then test the edges: negative/zero/huge quantities, re-use of one-time tokens/coupons, step-skipping, concurrent requests, currency/sign tricks.",
		},
		Oracle: "The app grants value or state it should not under the intended rules (free/again/for-less/for-someone-else), with no technical error - the logic simply allowed it.",
	},
	{
		Class:       "race-condition",
		AlsoKnownAs: []string{"race condition", "toctou", "time-of-check-time-of-use", "concurrency bug"},
		GoodSignals: []string{
			"A limited/one-time action tied to value: redeem a coupon/gift card once, withdraw/transfer funds, use an invite, claim a seat, apply a vote/like, submit once.",
			"State guarded by a check-then-act that is not atomic (check balance -> debit; check used -> mark used).",
		},
		Prerequisite: "An action whose single-use/limit matters AND you can fire it CONCURRENTLY (parallel requests / single-packet attack) before the guard commits. Needs an account usually, and a target that will not be harmed by a short burst of near-simultaneous requests (respect scope/DoS rules - keep it to a minimal controlled burst).",
		AntiSignals: []string{"Actions with no limit/value to break; properly atomic/locked operations; targets where any burst is out of scope."},
		ReconChecks: []string{
			"Identify a one-time/limited valued action; send a small controlled batch of parallel requests and check whether the limit was exceeded (coupon applied twice, balance over-withdrawn).",
		},
		Oracle: "A one-time or limited action succeeds more times than allowed because concurrent requests passed the check before any committed.",
	},
	{
		Class:       "file-upload",
		AlsoKnownAs: []string{"malicious file upload", "unrestricted file upload", "file upload"},
		GoodSignals: []string{
			"Upload features: avatars, documents, attachments, images, requested-info files, presigned direct-to-object-store uploads.",
			"Uploaded files rendered/served back (SVG/HTML inline) or processed (image resize, antivirus, parsing).",
		},
		Prerequisite: "A reachable upload (often needs an account) AND knowledge of how the file is stored, served, and processed (content-type/extension validation, served path, inline vs attachment, server-side parsing). The impact lives in how the file is handled, so confirm the handling.",
		AntiSignals: []string{"No upload feature; uploads re-encoded/sandboxed and served from a cookieless origin with attachment disposition."},
		ReconChecks: []string{
			"Find the upload mutation/endpoint and inspect validation (magic bytes vs content-type vs extension) and the served URL/disposition.",
			"For presigned uploads, check whether Content-Type and the key prefix are pinned in the policy.",
		},
		Oracle: "A file that bypasses validation and is served/processed dangerously (stored XSS via inline SVG/HTML, path traversal in the key, or server-side parse of a malicious document).",
	},
	{
		Class:       "sensitive-data-exposure",
		AlsoKnownAs: []string{"sensitive data exposure", "information disclosure", "secrets leak", "exposed git", "exposed files", "info disclosure"},
		GoodSignals: []string{
			"Signs of sloppy deployment: a real server (not a CDN stub) serving an app directly, dev/qa/uat/staging environments, verbose errors, directory listings.",
			"Likely exposed artefacts: /.git, /.env, backups (.bak/.zip/.sql), /config, source maps (.js.map), /actuator, /debug, swagger/openapi, build/CI files.",
		},
		Prerequisite: "A host that actually SERVES its own files (so exposed paths return content), not a locked-down CDN/404-everything edge. This class is largely unauthenticated and does not need an account - it needs a live origin and good wordlists. Low bar to test, which makes it a good warm-up on any plain-infra target.",
		AntiSignals: []string{"Pure static CDN with a strict 404/deny for everything off-manifest; WAF that blocks dotfiles."},
		ReconChecks: []string{
			"Probe /.git/HEAD, /.env, common backups, /actuator/env, swagger, and .js.map alongside each JS bundle; the sensitive-leak section (snallygaster/git-dumper) automates this.",
			"Read JS bundles and responses for hardcoded keys/tokens/internal hostnames.",
		},
		Oracle: "The server returns a secret or non-public artefact - credentials/keys, source via .git or source maps, a database/backup dump, internal config.",
	},
	{
		Class:       "subdomain-takeover",
		AlsoKnownAs: []string{"subdomain takeover", "dangling dns", "dangling cname"},
		GoodSignals: []string{
			"A WILDCARD or large-footprint program with many subdomains, especially ones pointing at third-party SaaS (CNAME to github.io, herokuapp, s3, azurewebsites, fastly, zendesk, etc.).",
			"Old/abandoned projects and marketing microsites - dangling records accumulate where ownership lapsed.",
		},
		Prerequisite: "A subdomain whose DNS record (usually CNAME) points at a de-provisioned third-party resource you can CLAIM. Needs good subdomain enumeration and a fingerprint of the unclaimed-service error page. Confirm the service is actually claimable (the vendor allows registering the name) before reporting - a 404 alone is not takeover.",
		AntiSignals: []string{"A single apex/host target with no subdomains; records that resolve to live, owned infrastructure."},
		ReconChecks: []string{
			"Enumerate subdomains, resolve CNAMEs, and match against known-takeover fingerprints (the wildcard workflow / find_subdomain_takeover do this).",
			"Verify claimability on the pointed-to service before claiming anything.",
		},
		Oracle: "You can register/claim the dangling third-party resource and serve content on the victim subdomain.",
	},
	{
		Class:       "graphql",
		AlsoKnownAs: []string{"graphql abuse", "graphql injection", "graphql"},
		GoodSignals: []string{
			"A GraphQL endpoint (/graphql), especially with introspection on; batched queries; field-level resolvers that may skip authz.",
		},
		Prerequisite: "A reachable GraphQL endpoint whose schema you can learn (introspection, or a known client's operations). IDOR/BOLA at the resolver level still needs an obtainable auth context or an unauth field; injection still needs a sink. Learn the schema first.",
		AntiSignals: []string{"Introspection off AND no observed operations AND auth you cannot obtain (you are blind)."},
		ReconChecks: []string{
			"Try introspection; if off, harvest operations from the frontend bundle/captures.",
			"Probe per-field authz (a field returning another tenant's data) and alias/batch-based limits.",
		},
		Oracle: "A field/operation returns data or performs an action the caller should not be authorized for, or an injection reaches a backend sink.",
	},
	{
		Class:       "prototype-pollution",
		AlsoKnownAs: []string{"prototype pollution", "server-side prototype pollution", "client-side prototype pollution"},
		GoodSignals: []string{
			"Node/JS backends or JS-heavy clients that deep-merge or recursively assign user-supplied JSON (config merges, query-string parsers, object spreads).",
			"Inputs with __proto__, constructor.prototype keys accepted and merged.",
		},
		Prerequisite: "A sink that MERGES attacker-controlled keys into an object without filtering __proto__/constructor (server-side for RCE/DoS/logic gadgets; client-side for DOM-XSS gadgets). Confirm a polluted property leaks onto other objects. Needs a JS stack.",
		AntiSignals: []string{"Non-JS backends; input parsed into typed structs that ignore prototype keys; Object.create(null) or Map used for user data."},
		ReconChecks: []string{
			"Send {\"__proto__\":{\"polluted\":\"x\"}} (and constructor.prototype variants) into JSON/merge endpoints; check whether an unrelated object now has .polluted.",
			"Client-side: look for a gadget where a polluted property reaches a sink.",
		},
		Oracle: "A property set via __proto__/constructor appears on objects that never had it - proving the prototype was polluted - and ideally reaches an impactful gadget.",
	},
	{
		Class:       "insecure-deserialization",
		AlsoKnownAs: []string{"insecure deserialization", "object injection", "deserialization"},
		GoodSignals: []string{
			"Serialized objects crossing the wire: Java (rO0/ac ed), .NET ViewState/BinaryFormatter, Python pickle, Ruby Marshal, PHP serialize() in cookies/params.",
			"Frameworks known for gadget chains; a parameter/cookie that is clearly a serialized blob.",
		},
		Prerequisite: "An endpoint that DESERIALIZES attacker-controlled data with a vulnerable format/library, and (for impact) an available gadget chain. Confirm the blob is deserialized server-side; this is high-impact but needs the right stack and is often guarded.",
		AntiSignals: []string{"Only JSON with safe parsers (no type binding); no serialized objects in the traffic."},
		ReconChecks: []string{
			"Identify serialized formats by magic bytes/prefixes in cookies/params/bodies; test with a benign probe for the library, then a known gadget if the stack matches.",
		},
		Oracle: "A crafted serialized object triggers attacker-controlled behaviour on deserialization (OOB callback, error proving gadget execution, or code execution).",
	},
	{
		Class:       "websocket-hijacking",
		AlsoKnownAs: []string{"cross-site websocket hijacking", "cswsh", "websocket"},
		GoodSignals: []string{
			"A WebSocket endpoint (ws://, wss://) that carries authenticated/sensitive data and relies on the session COOKIE for auth with no additional token.",
		},
		Prerequisite: "A WebSocket handshake authorized ONLY by ambient cookies with NO Origin check and NO per-connection CSRF token - so an attacker page can open the socket as the victim. Confirm the handshake lacks Origin validation.",
		AntiSignals: []string{"Handshake validates Origin, or auth is a bearer token in the connection message (not auto-sent), or SameSite cookies block cross-site."},
		ReconChecks: []string{
			"Check the WS handshake for Origin enforcement and how it authenticates; attempt a handshake from a foreign Origin with the victim's cookie model.",
		},
		Oracle: "A cross-origin page opens the authenticated WebSocket as the victim and can read/send messages.",
	},
	{
		Class:       "other-injection",
		AlsoKnownAs: []string{"ldap injection", "xpath injection", "xquery injection", "crlf injection", "log injection", "header injection", "response splitting"},
		GoodSignals: []string{
			"LDAP: login/directory-search features backed by LDAP (filters built from input).",
			"XPath/XQuery: search over XML data stores.",
			"CRLF / response splitting: input reflected into a response header or a redirect Location, or written to logs, where a newline is not stripped.",
		},
		Prerequisite: "Input reaching the specific interpreter (an LDAP filter, an XPath query, a response header/log line) with the special characters NOT neutralised (LDAP *()|& ; XPath '[]/ ; CRLF %0d%0a). Confirm the input reaches that context before probing. These are niche - pick them only when the target's shape points at them.",
		AntiSignals: []string{"No LDAP/XML backend; headers/logs built without user input; frameworks that strip CR/LF."},
		ReconChecks: []string{
			"LDAP: send * and )(| in a login/search field and watch for auth bypass / changed result set.",
			"XPath: send ' and ]/../ and watch for query errors/content changes.",
			"CRLF: inject %0d%0a into a value reflected in a header/redirect and check for an injected header.",
		},
		Oracle: "The interpreter acts on your metacharacters: LDAP filter altered, XPath query altered, or an injected CRLF produces a new response header / split response.",
	},
}
