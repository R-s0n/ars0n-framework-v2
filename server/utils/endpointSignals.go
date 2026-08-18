package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// What Investigate actually learns from one endpoint.
//
// Everything here is Tier 0: computed from a response that has already been fetched, costing no
// extra requests. That constraint is what makes it affordable to run over thousands of endpoints
// inside a measured rate budget.
//
// The hard part is not detection, it is ranking. Five thousand endpoints on one application share
// a template, a CSP and a cookie jar, so a naive analyzer reports the same missing header five
// thousand times and the operator learns nothing. Signals carry a DedupeKey, and anything that
// turns out to be true almost everywhere is promoted to a single target-level finding and removed
// from the per-endpoint noise. What survives per endpoint is what makes that endpoint different.

type Signal struct {
	Family     string `json:"family"`
	Kind       string `json:"kind"`
	Severity   string `json:"severity"` // p0 | p1 | p2 | p3
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Evidence   string `json:"evidence,omitempty"`
	DedupeKey  string `json:"dedupe_key"`
	Confidence string `json:"confidence"`
}

type SignalInput struct {
	URL         string
	Method      string
	Status      int
	Header      http.Header
	Body        string
	ContentType string
	Cookies     []*http.Cookie
	// Values the crawl actually observed for this endpoint's parameters, used for the free
	// reflection check: no extra request, just look for them in the body that was already read.
	ObservedParams map[string]string
	Authenticated  bool
}

// AnalyzeEndpoint runs every Tier 0 analyzer over one already-fetched response.
func AnalyzeEndpoint(in SignalInput) []Signal {
	var out []Signal
	add := func(sigs ...Signal) { out = append(out, sigs...) }

	add(analyzeCSP(in)...)
	add(analyzeCookieScope(in)...)
	add(analyzeCacheBehaviour(in)...)
	add(analyzeInfraLeak(in)...)
	add(analyzeJWTs(in)...)
	add(analyzeSecrets(in)...)
	add(analyzeErrorVerbosity(in)...)
	add(analyzeClientConfig(in)...)
	add(analyzeScriptSurface(in)...)
	add(analyzeComments(in)...)
	add(analyzeIdentifiers(in)...)
	add(analyzeRedirectParams(in)...)
	add(analyzeReflection(in)...)
	add(analyzeAPISurface(in)...)
	add(analyzeUploadSurface(in)...)

	for i := range out {
		if out[i].DedupeKey == "" {
			out[i].DedupeKey = signalHash(out[i].Kind + "|" + out[i].Evidence)
		}
		if out[i].Confidence == "" {
			out[i].Confidence = "measured"
		}
	}
	return out
}

// ---------------------------------------------------------------- CSP

var reCSPDirective = regexp.MustCompile(`(?i)^([a-z-]+)\s*(.*)$`)

// analyzeCSP parses the policy rather than checking whether the header exists.
//
// "CSP present" is close to worthless. A policy carrying 'unsafe-inline' in script-src provides no
// XSS mitigation at all, and one missing base-uri can be bypassed with an injected <base> tag even
// when script-src looks strict.
func analyzeCSP(in SignalInput) []Signal {
	policy := in.Header.Get("Content-Security-Policy")
	reportOnly := false
	if policy == "" {
		policy = in.Header.Get("Content-Security-Policy-Report-Only")
		reportOnly = policy != ""
	}
	if policy == "" {
		if isHTMLResponse(in) {
			return []Signal{{
				Family: "csp", Kind: "csp_absent", Severity: "p3",
				Title:  "No Content-Security-Policy",
				Detail: "An HTML response with no CSP. Any injected script executes with no policy to stop it.",
			}}
		}
		return nil
	}

	directives := map[string][]string{}
	for _, part := range strings.Split(policy, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		m := reCSPDirective.FindStringSubmatch(part)
		if len(m) < 2 {
			continue
		}
		directives[strings.ToLower(m[1])] = strings.Fields(m[2])
	}

	var out []Signal
	script := directives["script-src"]
	if len(script) == 0 {
		script = directives["default-src"]
	}
	scriptJoined := strings.ToLower(strings.Join(script, " "))
	hasNonceOrHash := strings.Contains(scriptJoined, "'nonce-") || strings.Contains(scriptJoined, "'sha256-")

	if reportOnly {
		out = append(out, Signal{
			Family: "csp", Kind: "csp_report_only", Severity: "p2",
			Title:  "CSP is report-only",
			Detail: "The policy is observed and reported but never enforced, so it blocks nothing.",
		})
	}

	if strings.Contains(scriptJoined, "'unsafe-inline'") && !hasNonceOrHash {
		out = append(out, Signal{
			Family: "csp", Kind: "csp_unsafe_inline", Severity: "p1",
			Title: "script-src allows 'unsafe-inline'",
			Detail: "Inline scripts execute, so this policy provides no cross-site scripting mitigation. " +
				"A nonce or hash would, and neither is present.",
			Evidence: truncateEvidence(strings.Join(script, " ")),
		})
	}
	if strings.Contains(scriptJoined, "'unsafe-eval'") {
		out = append(out, Signal{
			Family: "csp", Kind: "csp_unsafe_eval", Severity: "p2",
			Title: "script-src allows 'unsafe-eval'",
			Detail: "eval and Function constructors are permitted, which turns many DOM sinks back into " +
				"executable paths.",
		})
	}
	if strings.Contains(scriptJoined, "data:") {
		out = append(out, Signal{
			Family: "csp", Kind: "csp_data_uri_script", Severity: "p1",
			Title:  "script-src allows data:",
			Detail: "A data: URI can carry arbitrary script, so this is equivalent to allowing inline script.",
		})
	}
	for _, src := range script {
		if src == "*" || strings.HasPrefix(src, "*.") || src == "https:" || src == "http:" {
			out = append(out, Signal{
				Family: "csp", Kind: "csp_wildcard_script", Severity: "p1",
				Title:    "script-src contains a wildcard source",
				Detail:   "Any host matching this pattern can serve executable script to this page.",
				Evidence: src,
			})
			break
		}
	}

	for directive, why := range map[string]string{
		"object-src":      "Without object-src 'none', a <object> or <embed> tag can execute Flash-era or plugin content and bypass script-src.",
		"base-uri":        "Without base-uri, an injected <base> tag rewrites every relative script URL, which defeats an otherwise strict script-src.",
		"frame-ancestors": "Without frame-ancestors, the page can be framed, so clickjacking is only prevented if X-Frame-Options happens to be set.",
	} {
		if _, ok := directives[directive]; !ok {
			severity := "p2"
			if directive == "base-uri" && hasNonceOrHash {
				// A nonce-based policy without base-uri is the classic bypass.
				severity = "p1"
			}
			out = append(out, Signal{
				Family: "csp", Kind: "csp_missing_" + strings.ReplaceAll(directive, "-", "_"),
				Severity: severity,
				Title:    "CSP has no " + directive,
				Detail:   why,
			})
		}
	}
	return out
}

// ---------------------------------------------------------------- cookies

var sessionCookieName = regexp.MustCompile(`(?i)(session|sess|sid|auth|token|jwt|login|remember|csrf|xsrf)`)

// analyzeCookieScope looks at where a cookie is valid, not just at its flags.
//
// A Secure HttpOnly cookie scoped to .example.com is still sent to every subdomain including the
// one running a third-party marketing app, which is how session cookies leak without any flag
// being wrong.
func analyzeCookieScope(in SignalInput) []Signal {
	var out []Signal
	host := hostOf(in.URL)

	for _, c := range in.Cookies {
		isSession := sessionCookieName.MatchString(c.Name)
		lower := strings.ToLower(c.Name)

		if c.Domain != "" {
			domain := strings.TrimPrefix(c.Domain, ".")
			if !strings.EqualFold(domain, host) && strings.HasSuffix(host, domain) {
				sev := "p2"
				if isSession {
					sev = "p1"
				}
				out = append(out, Signal{
					Family: "cookie", Kind: "cookie_domain_too_broad", Severity: sev,
					Title: fmt.Sprintf("Cookie %s is scoped to the whole domain", c.Name),
					Detail: fmt.Sprintf("Domain=%s means every subdomain of %s receives this cookie, "+
						"including any host the application does not control.", c.Domain, domain),
					Evidence:  c.Name,
					DedupeKey: signalHash("cookie_domain_too_broad|" + c.Name),
				})
			}
		}

		if isSession && !c.HttpOnly {
			out = append(out, Signal{
				Family: "cookie", Kind: "cookie_session_no_httponly", Severity: "p1",
				Title:     fmt.Sprintf("Session-shaped cookie %s is readable by JavaScript", c.Name),
				Detail:    "No HttpOnly flag, so any script execution on this origin can read it.",
				Evidence:  c.Name,
				DedupeKey: signalHash("cookie_session_no_httponly|" + c.Name),
			})
		}
		if isSession && !c.Secure && strings.HasPrefix(in.URL, "https://") {
			out = append(out, Signal{
				Family: "cookie", Kind: "cookie_no_secure", Severity: "p2",
				Title:     fmt.Sprintf("Cookie %s has no Secure flag on an HTTPS origin", c.Name),
				Detail:    "It will be sent over plaintext if the browser is ever downgraded to http.",
				Evidence:  c.Name,
				DedupeKey: signalHash("cookie_no_secure|" + c.Name),
			})
		}
		if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			out = append(out, Signal{
				Family: "cookie", Kind: "cookie_samesite_none_insecure", Severity: "p2",
				Title:    fmt.Sprintf("Cookie %s is SameSite=None without Secure", c.Name),
				Detail:   "Browsers reject this combination, so the cookie is silently dropped.",
				Evidence: c.Name,
			})
		}
		// Cookie prefixes are a browser-enforced contract, and violating one means the cookie is
		// rejected outright rather than merely weakened.
		if strings.HasPrefix(lower, "__host-") && (c.Domain != "" || c.Path != "/" || !c.Secure) {
			out = append(out, Signal{
				Family: "cookie", Kind: "cookie_host_prefix_violation", Severity: "p2",
				Title:    fmt.Sprintf("Cookie %s violates the __Host- prefix rules", c.Name),
				Detail:   "__Host- requires Secure, Path=/ and no Domain. Browsers reject it as written.",
				Evidence: c.Name,
			})
		}
		if strings.HasPrefix(lower, "__secure-") && !c.Secure {
			out = append(out, Signal{
				Family: "cookie", Kind: "cookie_secure_prefix_violation", Severity: "p2",
				Title:    fmt.Sprintf("Cookie %s violates the __Secure- prefix rules", c.Name),
				Detail:   "__Secure- requires the Secure flag. Browsers reject it as written.",
				Evidence: c.Name,
			})
		}
	}
	return out
}

// ---------------------------------------------------------------- caching

// analyzeCacheBehaviour hunts for the combination that leaks one user's data to another.
func analyzeCacheBehaviour(in SignalInput) []Signal {
	var out []Signal
	cacheControl := strings.ToLower(in.Header.Get("Cache-Control"))
	setCookie := in.Header.Values("Set-Cookie")
	vary := strings.ToLower(in.Header.Get("Vary"))

	if strings.Contains(cacheControl, "public") && len(setCookie) > 0 && !strings.Contains(vary, "cookie") {
		out = append(out, Signal{
			Family: "cache", Kind: "cache_public_with_set_cookie", Severity: "p0",
			Title: "Publicly cacheable response that also sets a cookie",
			Detail: "Cache-Control: public with a Set-Cookie and no Vary: Cookie. A shared cache can " +
				"store this response, including the cookie, and hand it to a different user.",
			Evidence: truncateEvidence(in.Header.Get("Cache-Control")),
		})
	}

	// A cache HIT on a response that required credentials means the cache key does not include
	// identity, so somebody else can be served this user's page.
	for _, h := range []string{"X-Cache", "CF-Cache-Status", "X-Drupal-Cache", "X-Varnish-Cache"} {
		v := strings.ToUpper(in.Header.Get(h))
		if strings.Contains(v, "HIT") && in.Authenticated {
			out = append(out, Signal{
				Family: "cache", Kind: "cache_hit_on_authenticated", Severity: "p0",
				Title: "Authenticated response served from a shared cache",
				Detail: fmt.Sprintf("%s reported %s on a request that carried credentials. If the "+
					"cache key does not include the session, another user can be served this page.", h, v),
				Evidence: h + ": " + in.Header.Get(h),
			})
			break
		}
	}
	return out
}

// ---------------------------------------------------------------- infrastructure leak

var versionish = regexp.MustCompile(`\d+\.\d+`)

func analyzeInfraLeak(in SignalInput) []Signal {
	var out []Signal

	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
		"X-Generator", "X-Drupal-Version", "X-Runtime"} {
		v := in.Header.Get(h)
		if v == "" {
			continue
		}
		sev := "p3"
		if versionish.MatchString(v) {
			sev = "p2" // a version number is what turns a banner into a CVE lookup
		}
		out = append(out, Signal{
			Family: "infra", Kind: "infra_version_banner", Severity: sev,
			Title:     fmt.Sprintf("%s discloses %s", h, v),
			Detail:    "A named product and version narrows the search for a known vulnerability.",
			Evidence:  h + ": " + v,
			DedupeKey: signalHash("infra_version_banner|" + h + "|" + v),
		})
	}

	// Unknown X- headers are the highest-yield thing in a header dump: they are almost always
	// bespoke to this application and frequently name internal systems.
	for name := range in.Header {
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "x-") || wellKnownXHeaders[lower] {
			continue
		}
		out = append(out, Signal{
			Family: "infra", Kind: "infra_unknown_header", Severity: "p3",
			Title:     "Non-standard header " + name,
			Detail:    "A header specific to this application. These frequently name internal services, tenants or build systems.",
			Evidence:  name + ": " + truncateEvidence(in.Header.Get(name)),
			DedupeKey: signalHash("infra_unknown_header|" + lower),
		})
	}
	return out
}

var wellKnownXHeaders = map[string]bool{
	"x-frame-options": true, "x-content-type-options": true, "x-xss-protection": true,
	"x-powered-by": true, "x-request-id": true, "x-correlation-id": true, "x-trace-id": true,
	"x-cache": true, "x-cache-hits": true, "x-served-by": true, "x-timer": true,
	"x-ratelimit-limit": true, "x-ratelimit-remaining": true, "x-ratelimit-reset": true,
	"x-amz-cf-id": true, "x-amz-cf-pop": true, "x-amz-request-id": true, "x-amzn-requestid": true,
	"x-amzn-trace-id": true, "x-azure-ref": true, "x-msedge-ref": true, "x-github-request-id": true,
	"x-runtime": true, "x-download-options": true, "x-permitted-cross-domain-policies": true,
	"x-dns-prefetch-control": true, "x-ua-compatible": true, "x-robots-tag": true,
	"x-content-duration": true, "x-fastly-request-id": true, "x-vercel-id": true,
	"x-nextjs-cache": true, "x-vercel-cache": true, "x-envoy-upstream-service-time": true,
}

// ---------------------------------------------------------------- JWT

var reJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)

// analyzeJWTs decodes the header and payload and stores structure only.
//
// The signature is never decoded and no claim value is ever stored. What matters for triage is the
// algorithm, whether the token expires, and how long it lives; the contents are the user's data
// and have no business sitting in this database.
func analyzeJWTs(in SignalInput) []Signal {
	var out []Signal
	seen := map[string]bool{}

	haystack := in.Body
	for _, v := range in.Header {
		haystack += "\n" + strings.Join(v, "\n")
	}
	for _, c := range in.Cookies {
		haystack += "\n" + c.Value
	}

	for _, token := range reJWT.FindAllString(haystack, 10) {
		parts := strings.Split(token, ".")
		if len(parts) < 2 {
			continue
		}
		headerJSON, err1 := base64.RawURLEncoding.DecodeString(parts[0])
		payloadJSON, err2 := base64.RawURLEncoding.DecodeString(parts[1])
		if err1 != nil || err2 != nil {
			continue
		}

		var hdr struct {
			Alg string `json:"alg"`
			Kid string `json:"kid"`
		}
		var claims map[string]interface{}
		if json.Unmarshal(headerJSON, &hdr) != nil || json.Unmarshal(payloadJSON, &claims) != nil {
			continue
		}
		fingerprint := hdr.Alg + "|" + fmt.Sprint(sortedKeys(claims))
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true

		out = append(out, Signal{
			Family: "jwt", Kind: "jwt_present", Severity: "p3",
			Title: "JSON Web Token in the response",
			Detail: fmt.Sprintf("alg=%s, claims present: %s. Values are not stored.",
				orNone(hdr.Alg), strings.Join(sortedKeys(claims), ", ")),
			DedupeKey: signalHash("jwt_present|" + fingerprint),
		})

		if strings.EqualFold(hdr.Alg, "none") {
			out = append(out, Signal{
				Family: "jwt", Kind: "jwt_alg_none", Severity: "p0",
				Title:  "JWT with alg=none",
				Detail: "The token declares no signature algorithm, so anyone can forge one.",
			})
		}
		exp, hasExp := claims["exp"].(float64)
		iat, hasIat := claims["iat"].(float64)
		if !hasExp {
			out = append(out, Signal{
				Family: "jwt", Kind: "jwt_no_expiry", Severity: "p1",
				Title:  "JWT has no exp claim",
				Detail: "The token never expires, so a leaked copy is valid forever.",
			})
		} else if hasIat && exp-iat > 86400 {
			out = append(out, Signal{
				Family: "jwt", Kind: "jwt_long_lifetime", Severity: "p2",
				Title: "JWT lifetime is long",
				Detail: fmt.Sprintf("Valid for roughly %d hours, which widens the window on a leaked token.",
					int((exp-iat)/3600)),
			})
		}
	}
	return out
}

// ---------------------------------------------------------------- secrets

type secretPattern struct {
	kind     string
	re       *regexp.Regexp
	severity string
	// publishable marks keys that are designed to ship in client code. Reporting a Stripe pk_ or a
	// Firebase apiKey as a leaked secret is the fastest way to make an operator stop reading.
	publishable bool
}

var secretPatterns = []secretPattern{
	{"aws_access_key", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), "p0", false},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), "p0", false},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), "p0", false},
	{"stripe_secret", regexp.MustCompile(`\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b`), "p0", false},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), "p2", true},
	{"stripe_publishable", regexp.MustCompile(`\bpk_(live|test)_[A-Za-z0-9]{20,}\b`), "p3", true},
	{"private_key_block", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`), "p0", false},
	{"slack_webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]+`), "p1", false},
	{"twilio_sid", regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`), "p1", false},
	{"sendgrid_key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b`), "p0", false},
	{"npm_token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), "p0", false},
}

// Generic assignments only count as secrets when the name says secret and the value looks random.
var reGenericSecret = regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|secret|password|passwd|token|auth[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret)\b["'\s:=]{1,6}["']([^"'\s]{12,120})["']`)

func analyzeSecrets(in SignalInput) []Signal {
	var out []Signal
	seen := map[string]bool{}

	for _, p := range secretPatterns {
		for _, match := range p.re.FindAllString(in.Body, 5) {
			key := p.kind + "|" + match
			if seen[key] {
				continue
			}
			seen[key] = true
			detail := "A credential matching a known provider format was found in the response body."
			if p.publishable {
				detail = "This key type is designed to be public and shipped in client code. It is " +
					"worth checking what it is scoped to, but it is not a leak on its own."
			}
			out = append(out, Signal{
				Family: "secret", Kind: "secret_" + p.kind, Severity: p.severity,
				Title:     "Possible " + strings.ReplaceAll(p.kind, "_", " "),
				Detail:    detail,
				Evidence:  redactSecret(match),
				DedupeKey: signalHash("secret|" + p.kind + "|" + match),
			})
		}
	}

	// The generic rule needs both gates or it fires on every "password" input field and every
	// minified variable in a bundle.
	for _, m := range reGenericSecret.FindAllStringSubmatch(in.Body, 20) {
		if len(m) < 3 {
			continue
		}
		name, value := m[1], m[2]
		if shannonEntropy(value) < 3.4 || looksLikePlaceholder(value) {
			continue
		}
		key := "generic|" + value
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Signal{
			Family: "secret", Kind: "secret_generic_assignment", Severity: "p1",
			Title: fmt.Sprintf("High-entropy value assigned to %q", name),
			Detail: fmt.Sprintf("A %d character value with entropy %.1f assigned to a name that "+
				"says credential.", len(value), shannonEntropy(value)),
			Evidence:  name + " = " + redactSecret(value),
			DedupeKey: signalHash("secret_generic|" + value),
		})
	}
	return out
}

func looksLikePlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, marker := range []string{"example", "placeholder", "your-", "xxxx", "changeme",
		"redacted", "dummy", "sample", "test-key", "<", "{{", "${", "null", "undefined"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func redactSecret(v string) string {
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + strings.Repeat("*", len(v)-8) + v[len(v)-4:]
}

// ---------------------------------------------------------------- error verbosity

var errorSignatures = []struct {
	kind string
	re   *regexp.Regexp
	what string
}{
	{"java_stack", regexp.MustCompile(`\bat [a-z][a-zA-Z0-9_.]+\.[A-Za-z0-9_$]+\([A-Za-z0-9_]+\.java:\d+\)`), "a Java stack trace"},
	{"python_traceback", regexp.MustCompile(`Traceback \(most recent call last\)`), "a Python traceback"},
	{"php_error", regexp.MustCompile(`(?i)(Fatal error|Warning|Parse error):.*? in .*? on line \d+`), "a PHP error with a file path"},
	{"dotnet_exception", regexp.MustCompile(`\[(HttpException|SqlException|NullReferenceException|InvalidOperationException)`), "a .NET exception"},
	{"rails_error", regexp.MustCompile(`(ActionController|ActiveRecord|ActionView)::[A-Za-z]+`), "a Rails exception class"},
	{"node_stack", regexp.MustCompile(`\bat [A-Za-z0-9_.<>\[\] ]+ \(/[^\s)]+\.js:\d+:\d+\)`), "a Node.js stack trace"},
	{"sql_error", regexp.MustCompile(`(?i)(SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|PG::[A-Za-z]+Error|SQLiteException)`), "a database error"},
	{"go_panic", regexp.MustCompile(`goroutine \d+ \[running\]:`), "a Go panic"},
}

var (
	reAbsPath   = regexp.MustCompile(`(?:/(?:home|var|usr|opt|srv|app|Users)/[A-Za-z0-9_.\-/]{4,}|[A-Z]:\\\\[A-Za-z0-9_.\\\-]{4,})`)
	rePrivateIP = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)
)

func analyzeErrorVerbosity(in SignalInput) []Signal {
	var out []Signal
	for _, sig := range errorSignatures {
		if m := sig.re.FindString(in.Body); m != "" {
			out = append(out, Signal{
				Family: "error", Kind: "error_" + sig.kind, Severity: "p1",
				Title:    "Response contains " + sig.what,
				Detail:   "Verbose errors reaching the client disclose the stack, file layout and often the query.",
				Evidence: truncateEvidence(m),
			})
		}
	}
	if m := reAbsPath.FindString(in.Body); m != "" {
		out = append(out, Signal{
			Family: "error", Kind: "error_filesystem_path", Severity: "p2",
			Title:    "Absolute filesystem path in the response",
			Detail:   "Discloses the deployment layout, which is useful for traversal and log poisoning.",
			Evidence: truncateEvidence(m),
		})
	}
	if m := rePrivateIP.FindString(in.Body); m != "" {
		out = append(out, Signal{
			Family: "error", Kind: "error_internal_ip", Severity: "p2",
			Title:    "Internal RFC1918 address in the response",
			Detail:   "Names an internal host, which is a target for server-side request forgery.",
			Evidence: m,
		})
	}
	return out
}

// ---------------------------------------------------------------- client config blobs

var clientConfigBlobs = []struct {
	kind   string
	marker string
}{
	{"next_data", "__NEXT_DATA__"},
	{"nuxt", "window.__NUXT__"},
	{"initial_state", "__INITIAL_STATE__"},
	{"preloaded_state", "__PRELOADED_STATE__"},
	{"app_config", "window.APP_CONFIG"},
	{"env_blob", "window.__ENV"},
	{"runtime_config", "window.__RUNTIME_CONFIG__"},
	{"apollo_state", "__APOLLO_STATE__"},
}

func analyzeClientConfig(in SignalInput) []Signal {
	var out []Signal
	for _, blob := range clientConfigBlobs {
		if !strings.Contains(in.Body, blob.marker) {
			continue
		}
		out = append(out, Signal{
			Family: "client_config", Kind: "config_" + blob.kind, Severity: "p2",
			Title: "Client-side state blob " + blob.marker,
			Detail: "Server-rendered state shipped to the browser. These routinely carry internal " +
				"identifiers, feature flags, role names and API hosts that are not exposed anywhere else.",
			Evidence:  blob.marker,
			DedupeKey: signalHash("config|" + blob.kind),
		})
	}
	if strings.Contains(in.Body, `name="csrf-token"`) || strings.Contains(in.Body, `name='csrf-token'`) {
		out = append(out, Signal{
			Family: "client_config", Kind: "config_csrf_meta", Severity: "p3",
			Title:  "CSRF token exposed in a meta tag",
			Detail: "Needed for forged requests during authorization testing.",
		})
	}
	return out
}

// ---------------------------------------------------------------- scripts, sourcemaps, SRI

var (
	reScriptTag   = regexp.MustCompile(`(?i)<script[^>]*\bsrc=["']([^"']+)["'][^>]*>`)
	reLinkTag     = regexp.MustCompile(`(?i)<link[^>]*\bhref=["']([^"']+)["'][^>]*>`)
	reSourceMap   = regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL=([^\s*]+)`)
	reIntegrity   = regexp.MustCompile(`(?i)\bintegrity=["']`)
	reCrossOrigin = regexp.MustCompile(`(?i)^https?://`)
)

func analyzeScriptSurface(in SignalInput) []Signal {
	var out []Signal
	host := hostOf(in.URL)

	if m := reSourceMap.FindStringSubmatch(in.Body); len(m) > 1 {
		out = append(out, Signal{
			Family: "script", Kind: "script_sourcemap", Severity: "p1",
			Title:    "Source map reference",
			Detail:   "If the map is reachable it returns the original, unminified source, including comments and often unshipped code paths.",
			Evidence: truncateEvidence(m[1]),
		})
	}

	thirdParty := map[string]bool{}
	for _, m := range reScriptTag.FindAllStringSubmatch(in.Body, 60) {
		if len(m) < 2 {
			continue
		}
		src, tag := m[1], m[0]
		if reCrossOrigin.MatchString(src) {
			if h := hostOf(src); h != "" && h != host {
				thirdParty[h] = true
				if !reIntegrity.MatchString(tag) {
					out = append(out, Signal{
						Family: "script", Kind: "script_no_sri", Severity: "p2",
						Title: "Cross-origin script with no integrity attribute",
						Detail: fmt.Sprintf("Loaded from %s with no subresource integrity, so that host "+
							"can change what executes on this page at any time.", h),
						Evidence:  truncateEvidence(src),
						DedupeKey: signalHash("script_no_sri|" + h),
					})
				}
			}
		}
	}
	for _, m := range reLinkTag.FindAllStringSubmatch(in.Body, 40) {
		if len(m) < 2 || !strings.Contains(strings.ToLower(m[0]), "stylesheet") {
			continue
		}
		if reCrossOrigin.MatchString(m[1]) {
			if h := hostOf(m[1]); h != "" && h != host {
				thirdParty[h] = true
			}
		}
	}
	if len(thirdParty) > 0 {
		hosts := sortedSetKeys(thirdParty)
		out = append(out, Signal{
			Family: "script", Kind: "script_third_party_hosts", Severity: "p3",
			Title:     fmt.Sprintf("%d third-party host(s) execute or style this page", len(hosts)),
			Detail:    "Each is a supply-chain dependency and a candidate for subdomain takeover or a dangling record.",
			Evidence:  strings.Join(hosts, ", "),
			DedupeKey: signalHash("third_party|" + strings.Join(hosts, ",")),
		})
	}
	return out
}

// ---------------------------------------------------------------- comments

var (
	reHTMLComment  = regexp.MustCompile(`<!--([\s\S]{8,400}?)-->`)
	reBlockComment = regexp.MustCompile(`/\*([\s\S]{8,400}?)\*/`)
	reScriptBlock  = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
	reLineComment  = regexp.MustCompile(`(?m)(?:^|[\s;{}(])//([^\n]{8,200})$`)
	reJuicyComment = regexp.MustCompile(`(?i)\b(todo|fixme|hack|xxx|bug|password|passwd|secret|apikey|api[_ -]key|token|credential|internal|staging|debug|remove before|do not|temporary|workaround|deprecated|backdoor)\b`)
)

// analyzeComments extracts comments without treating every URL as one.
//
// The previous implementation used `//(.*)` over the whole document, so `https://example.com/x`
// produced a comment reading "example.com/x". Line comments are now only read from inside script
// blocks, and only when not preceded by a colon, which is what a scheme looks like.
func analyzeComments(in SignalInput) []Signal {
	var found []string

	for _, m := range reHTMLComment.FindAllStringSubmatch(in.Body, 40) {
		if len(m) > 1 {
			found = append(found, strings.TrimSpace(m[1]))
		}
	}
	for _, block := range reScriptBlock.FindAllStringSubmatch(in.Body, 20) {
		if len(block) < 2 {
			continue
		}
		js := block[1]
		for _, m := range reBlockComment.FindAllStringSubmatch(js, 20) {
			if len(m) > 1 {
				found = append(found, strings.TrimSpace(m[1]))
			}
		}
		for _, m := range reLineComment.FindAllStringSubmatch(js, 40) {
			if len(m) > 1 {
				found = append(found, strings.TrimSpace(m[1]))
			}
		}
	}

	var out []Signal
	seen := map[string]bool{}
	for _, c := range found {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if !reJuicyComment.MatchString(c) {
			continue // a comment with nothing interesting in it is not a finding
		}
		out = append(out, Signal{
			Family: "comment", Kind: "comment_interesting", Severity: "p3",
			Title:     "Developer comment",
			Detail:    "Mentions something worth reading: a TODO, a credential, an internal system or a workaround.",
			Evidence:  truncateEvidence(c),
			DedupeKey: signalHash("comment|" + c),
		})
		if len(out) >= 10 {
			break
		}
	}
	return out
}

// ---------------------------------------------------------------- object identifiers

var (
	reUUIDv1  = regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	reUUIDv4  = regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	reMongoID = regexp.MustCompile(`\b[0-9a-f]{24}\b`)
	reSeqID   = regexp.MustCompile(`\b(?:id|Id|ID)["']?\s*[:=]\s*["']?(\d{1,9})\b`)
)

// analyzeIdentifiers classifies the object identifiers a response hands out.
//
// This is the input to access-control testing. A sequential integer is trivially enumerable; a
// UUIDv1 embeds a timestamp and MAC address so it is guessable given one sample; a Mongo ObjectId
// leads with a 4-byte timestamp for the same reason. A UUIDv4 is not guessable, which is exactly
// as useful to know.
func analyzeIdentifiers(in SignalInput) []Signal {
	var out []Signal

	if m := reSeqID.FindAllStringSubmatch(in.Body, 5); len(m) > 0 {
		out = append(out, Signal{
			Family: "identifier", Kind: "identifier_sequential", Severity: "p1",
			Title:    "Sequential integer identifiers",
			Detail:   "Objects are addressed by small integers, so neighbouring records can be requested by counting. This is the primary access-control test surface.",
			Evidence: fmt.Sprintf("%d sample(s), e.g. %s", len(m), m[0][1]),
		})
	}
	if reUUIDv1.MatchString(in.Body) {
		out = append(out, Signal{
			Family: "identifier", Kind: "identifier_uuid_v1", Severity: "p1",
			Title:  "UUIDv1 identifiers",
			Detail: "Version 1 UUIDs encode a timestamp and node identifier, so neighbouring values can be derived from one sample. They are not random.",
		})
	}
	if reMongoID.MatchString(in.Body) && !reUUIDv4.MatchString(in.Body) {
		out = append(out, Signal{
			Family: "identifier", Kind: "identifier_object_id", Severity: "p2",
			Title:  "MongoDB ObjectId identifiers",
			Detail: "The leading four bytes are a creation timestamp and the counter is monotonic, so nearby identifiers are predictable.",
		})
	}
	if reUUIDv4.MatchString(in.Body) {
		out = append(out, Signal{
			Family: "identifier", Kind: "identifier_uuid_v4", Severity: "p3",
			Title:  "UUIDv4 identifiers",
			Detail: "Random identifiers. Enumeration is not viable, so access-control testing here needs a real object reference.",
		})
	}
	return out
}

// ---------------------------------------------------------------- redirect parameters

var redirectParamNames = map[string]bool{
	"redirect": true, "redirect_uri": true, "redirect_url": true, "redirecturl": true,
	"return": true, "return_to": true, "returnurl": true, "return_url": true,
	"next": true, "continue": true, "callback": true, "callback_url": true,
	"url": true, "u": true, "target": true, "dest": true, "destination": true,
	"goto": true, "forward": true, "back": true, "backurl": true, "success_url": true,
	"failure_url": true, "cancel_url": true, "referrer": true, "origin": true,
}

func analyzeRedirectParams(in SignalInput) []Signal {
	var out []Signal
	u, err := url.Parse(in.URL)
	if err != nil {
		return nil
	}

	candidates := map[string]string{}
	for name, values := range u.Query() {
		if redirectParamNames[strings.ToLower(name)] && len(values) > 0 {
			candidates[name] = values[0]
		}
	}
	for name, value := range in.ObservedParams {
		if redirectParamNames[strings.ToLower(name)] {
			candidates[name] = value
		}
	}

	for name, value := range candidates {
		looksLikeURL := strings.HasPrefix(value, "http") || strings.HasPrefix(value, "/") ||
			strings.HasPrefix(value, "//")
		if !looksLikeURL {
			continue
		}
		out = append(out, Signal{
			Family: "redirect", Kind: "redirect_param_candidate", Severity: "p2",
			Title: fmt.Sprintf("Parameter %q carries a URL", name),
			Detail: "A parameter whose observed value is a URL or absolute path. Worth testing for " +
				"open redirect and, where it is fetched server side, for request forgery.",
			Evidence:  name + "=" + truncateEvidence(value),
			DedupeKey: signalHash("redirect_param|" + strings.ToLower(name)),
		})
	}
	return out
}

// ---------------------------------------------------------------- reflection

// analyzeReflection checks whether values the crawl already observed come back in the body.
//
// Free: no request is sent, and no canary is injected. It only reports that a value the
// application was genuinely given is echoed, and where, which is the precondition for injection
// rather than proof of it.
func analyzeReflection(in SignalInput) []Signal {
	if len(in.ObservedParams) == 0 || in.Body == "" {
		return nil
	}
	var out []Signal
	for name, value := range in.ObservedParams {
		if len(value) < 4 || len(value) > 200 {
			continue
		}
		idx := strings.Index(in.Body, value)
		if idx < 0 {
			continue
		}
		context, severity := reflectionContext(in.Body, idx, len(value))
		out = append(out, Signal{
			Family: "reflection", Kind: "reflection_" + context, Severity: severity,
			Title: fmt.Sprintf("Parameter %q is reflected in the response", name),
			Detail: fmt.Sprintf("The observed value appears in the body inside %s. This is where the "+
				"value lands, not proof that it is injectable.", describeContext(context)),
			Evidence:  name,
			DedupeKey: signalHash("reflection|" + name + "|" + context),
		})
		if len(out) >= 10 {
			break
		}
	}
	return out
}

// reflectionContext reports where in the document a value landed, which decides how much it matters.
func reflectionContext(body string, idx, length int) (string, string) {
	start := idx - 400
	if start < 0 {
		start = 0
	}
	before := body[start:idx]

	lastScript := strings.LastIndex(strings.ToLower(before), "<script")
	lastScriptEnd := strings.LastIndex(strings.ToLower(before), "</script")
	if lastScript > lastScriptEnd {
		return "script", "p1" // inside executable context is the dangerous one
	}
	if i := strings.LastIndexAny(before, "<>"); i >= 0 && before[i] == '<' {
		return "attribute", "p2"
	}
	return "html", "p2"
}

func describeContext(c string) string {
	switch c {
	case "script":
		return "a <script> block, which is executable context"
	case "attribute":
		return "an HTML tag, so it may be inside an attribute"
	}
	return "HTML text"
}

// ---------------------------------------------------------------- API surface

func analyzeAPISurface(in SignalInput) []Signal {
	var out []Signal
	body := in.Body
	lower := strings.ToLower(body)

	if strings.Contains(lower, `"__schema"`) || strings.Contains(lower, "graphql") {
		if strings.Contains(lower, "graphql") {
			out = append(out, Signal{
				Family: "api", Kind: "api_graphql", Severity: "p2",
				Title:  "GraphQL referenced",
				Detail: "Worth checking whether introspection is enabled and whether field-level authorization is enforced.",
			})
		}
	}
	for _, marker := range []string{"swagger-ui", "swagger.json", "openapi.json", "/v3/api-docs", "redoc"} {
		if strings.Contains(lower, marker) {
			out = append(out, Signal{
				Family: "api", Kind: "api_schema_hint", Severity: "p1",
				Title:     "API schema reference",
				Detail:    "An OpenAPI or Swagger document describes every endpoint, parameter and type, including ones no crawler would find.",
				Evidence:  marker,
				DedupeKey: signalHash("api_schema|" + marker),
			})
			break
		}
	}
	if strings.Contains(lower, "new websocket(") || strings.Contains(lower, "wss://") {
		out = append(out, Signal{
			Family: "api", Kind: "api_websocket", Severity: "p2",
			Title:  "WebSocket endpoint referenced",
			Detail: "WebSocket traffic bypasses most HTTP tooling and frequently carries a weaker authorization model.",
		})
	}
	if in.Header.Get("Access-Control-Allow-Origin") == "*" &&
		strings.EqualFold(in.Header.Get("Access-Control-Allow-Credentials"), "true") {
		out = append(out, Signal{
			Family: "api", Kind: "api_cors_wildcard_credentials", Severity: "p0",
			Title:  "CORS allows any origin with credentials",
			Detail: "Access-Control-Allow-Origin: * together with Allow-Credentials: true. Browsers reject this pair, but the intent behind it usually means the reflected-origin variant is present elsewhere.",
		})
	}
	return out
}

// ---------------------------------------------------------------- upload surface

var reFileInput = regexp.MustCompile(`(?i)<input[^>]*type=["']file["']`)

func analyzeUploadSurface(in SignalInput) []Signal {
	if !reFileInput.MatchString(in.Body) && !strings.Contains(strings.ToLower(in.Body), "multipart/form-data") {
		return nil
	}
	return []Signal{{
		Family: "upload", Kind: "upload_surface", Severity: "p1",
		Title:  "File upload surface",
		Detail: "A file input or multipart form. Upload endpoints carry content-type confusion, path traversal in the filename, and stored cross-site scripting.",
	}}
}

// ---------------------------------------------------------------- ranking and rollup

// RollupSignals separates what is true of the whole target from what is true of one endpoint.
//
// A missing security header on 4,000 endpoints is one fact about the application, not 4,000
// findings. Anything appearing on more than a fifth of the corpus, with a floor so a small corpus
// is not flattened, is promoted to a target-level finding and removed from the per-endpoint list.
// What is left is what makes each endpoint different from its neighbours.
func RollupSignals(perEndpoint map[string][]Signal) (target []Signal, kept map[string][]Signal) {
	total := len(perEndpoint)
	kept = map[string][]Signal{}
	if total == 0 {
		return nil, kept
	}

	counts := map[string]int{}
	sample := map[string]Signal{}
	for _, sigs := range perEndpoint {
		seenHere := map[string]bool{}
		for _, s := range sigs {
			if seenHere[s.DedupeKey] {
				continue
			}
			seenHere[s.DedupeKey] = true
			counts[s.DedupeKey]++
			if _, ok := sample[s.DedupeKey]; !ok {
				sample[s.DedupeKey] = s
			}
		}
	}

	threshold := total / 5
	if threshold < 20 {
		threshold = 20
	}
	if total < 20 {
		// On a small corpus nothing is promoted: every signal is still worth reading in place.
		threshold = total + 1
	}

	promoted := map[string]bool{}
	for key, n := range counts {
		if n < threshold {
			continue
		}
		promoted[key] = true
		s := sample[key]
		s.Detail = fmt.Sprintf("%s Present on %d of %d endpoints, so this is a property of the "+
			"application rather than of any one endpoint.", s.Detail, n, total)
		target = append(target, s)
	}

	for id, sigs := range perEndpoint {
		var remaining []Signal
		for _, s := range sigs {
			if !promoted[s.DedupeKey] {
				remaining = append(remaining, s)
			}
		}
		if len(remaining) > 0 {
			sort.SliceStable(remaining, func(i, j int) bool {
				return severityRank(remaining[i].Severity) < severityRank(remaining[j].Severity)
			})
			kept[id] = remaining
		}
	}

	sort.SliceStable(target, func(i, j int) bool {
		return severityRank(target[i].Severity) < severityRank(target[j].Severity)
	})
	return target, kept
}

// InterestScore turns an endpoint's signals into one number for ordering.
func InterestScore(sigs []Signal) int {
	score := 0
	for _, s := range sigs {
		switch s.Severity {
		case "p0":
			score += 100
		case "p1":
			score += 30
		case "p2":
			score += 8
		default:
			score += 2
		}
	}
	return score
}

func severityRank(s string) int {
	switch s {
	case "p0":
		return 0
	case "p1":
		return 1
	case "p2":
		return 2
	}
	return 3
}

// ---------------------------------------------------------------- helpers

func isHTMLResponse(in SignalInput) bool {
	return strings.Contains(strings.ToLower(in.ContentType), "html")
}

func signalHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func truncateEvidence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", ""))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

func sortedKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// FrameworkFingerprint is a {tech, version, evidence, confidence} tuple rather than a bare name.
type FrameworkFingerprint struct {
	Tech       string `json:"tech"`
	Version    string `json:"version,omitempty"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"`
}

var frameworkRules = []struct {
	tech     string
	header   string
	headerRe *regexp.Regexp
	bodyRe   *regexp.Regexp
	cookie   string
}{
	{tech: "nginx", header: "Server", headerRe: regexp.MustCompile(`(?i)^nginx(?:/([\d.]+))?`)},
	{tech: "Apache", header: "Server", headerRe: regexp.MustCompile(`(?i)^Apache(?:/([\d.]+))?`)},
	{tech: "IIS", header: "Server", headerRe: regexp.MustCompile(`(?i)Microsoft-IIS/([\d.]+)`)},
	{tech: "PHP", header: "X-Powered-By", headerRe: regexp.MustCompile(`(?i)PHP/([\d.]+)`)},
	{tech: "ASP.NET", header: "X-AspNet-Version", headerRe: regexp.MustCompile(`([\d.]+)`)},
	{tech: "Express", header: "X-Powered-By", headerRe: regexp.MustCompile(`(?i)^Express`)},
	{tech: "Next.js", bodyRe: regexp.MustCompile(`__NEXT_DATA__`)},
	{tech: "Nuxt", bodyRe: regexp.MustCompile(`window\.__NUXT__`)},
	{tech: "React", bodyRe: regexp.MustCompile(`data-reactroot|data-reactid|__REACT_DEVTOOLS`)},
	{tech: "Vue", bodyRe: regexp.MustCompile(`data-v-[0-9a-f]{8}|__VUE_DEVTOOLS`)},
	{tech: "Angular", bodyRe: regexp.MustCompile(`ng-version=["'][\d.]+|_nghost-|_ngcontent-`)},
	{tech: "WordPress", bodyRe: regexp.MustCompile(`/wp-content/|/wp-includes/`)},
	{tech: "Drupal", bodyRe: regexp.MustCompile(`(?i)Drupal\.settings|/sites/default/files`)},
	{tech: "Laravel", cookie: "laravel_session"},
	{tech: "Django", cookie: "csrftoken"},
	{tech: "Rails", cookie: "_session_id"},
	{tech: "Java servlet", cookie: "JSESSIONID"},
	{tech: "ASP.NET session", cookie: "ASP.NET_SessionId"},
}

// DetectFrameworks replaces the previous 14 substring tests, which matched "vue" inside the word
// "value" and reported Vue on any page containing a form.
func DetectFrameworks(header http.Header, body string, cookies []*http.Cookie) []FrameworkFingerprint {
	var out []FrameworkFingerprint
	seen := map[string]bool{}

	for _, rule := range frameworkRules {
		var evidence, version, confidence string

		switch {
		case rule.header != "":
			v := header.Get(rule.header)
			if v == "" {
				continue
			}
			m := rule.headerRe.FindStringSubmatch(v)
			if m == nil {
				continue
			}
			if len(m) > 1 {
				version = m[1]
			}
			evidence = rule.header + ": " + v
			confidence = "measured" // the server said so itself
		case rule.cookie != "":
			for _, c := range cookies {
				if strings.EqualFold(c.Name, rule.cookie) {
					evidence = "cookie " + c.Name
					confidence = "measured"
					break
				}
			}
			if evidence == "" {
				continue
			}
		case rule.bodyRe != nil:
			m := rule.bodyRe.FindString(body)
			if m == "" {
				continue
			}
			evidence = truncateEvidence(m)
			confidence = "inferred" // a marker in the body can be copied or cached
		default:
			continue
		}

		if seen[rule.tech] {
			continue
		}
		seen[rule.tech] = true
		out = append(out, FrameworkFingerprint{
			Tech: rule.tech, Version: version, Evidence: evidence, Confidence: confidence,
		})
	}
	return out
}

// ParseIntSafe is used by the signal writers when a header carries a count.
func ParseIntSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}
