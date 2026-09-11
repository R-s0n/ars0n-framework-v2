package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// expiredBearer reports whether a captured credential is a JWT whose exp has already passed.
//
// WHY THIS EXISTS. The capture loader below prefers captured headers over the operator's configured
// ones on the grounds that a capture is "real: a header the application actually accepted on a 2xx
// response". That reasoning holds for an API key and is exactly backwards for a bearer token with an
// expiry: it was real AT CAPTURE TIME, and a short-lived one is worthless minutes later.
//
// Measured on a live engagement: the target issues 900-second tokens, a manual crawl captured one,
// and sixteen hours later Katana was still being handed that dead token in preference to the fresh
// one sitting in the FFUF config. Every request 401'd, the crawl finished in 19 seconds, and the run
// was recorded as completed. That is a scanner reporting a clean result for a scan that never
// authenticated - the exact silent-nothing failure this codebase is otherwise careful about.
//
// The signature is deliberately NOT verified. This is not an authorisation decision, it is a
// freshness check on our own credential, and we hold no key to verify with. A token we cannot parse
// is treated as NOT expired, because refusing to send something merely because it is unfamiliar
// would break every non-JWT credential the loader handles.
func expiredBearer(value string) bool {
	tok := strings.TrimSpace(value)
	if i := strings.LastIndex(tok, " "); i >= 0 {
		tok = tok[i+1:] // strip a "Bearer " style prefix
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	payload := parts[1]
	if pad := len(payload) % 4; pad != 0 {
		payload += strings.Repeat("=", 4-pad)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(decoded, &claims) != nil || claims.Exp == 0 {
		return false
	}
	// A small skew allowance, so a token expiring during the scan is not rejected a second early.
	return time.Now().Add(-30 * time.Second).After(time.Unix(claims.Exp, 0))
}

// Credentials for validation and investigation, scoped to the host they were captured from.
//
// The rule that matters: a bearer token goes to the exact host it was captured from and nowhere
// else. A crawl of app.target.com captures an Authorization header; the endpoint list also contains
// cdn.target.com and, if adjacent capture was on, a third-party analytics host. Attaching that
// token to every request would hand the operator's session to hosts they never authenticated to.
// Cookies are matched by registrable domain, which is how a browser would scope them.

type ScopedAuthMaterial struct {
	Host    string
	Cookies string
	Headers map[string]string
	// QueryParams carries credentials that ride in the URL rather than in a header. They are applied
	// by rewriting the request's query string. Without this a token whose type is "query" was stored,
	// shown in the UI with a wire preview, exercised by the Validate button, and then never sent by
	// any actual scan.
	QueryParams map[string]string
	Source      string
}

type ScopedAuthContext struct {
	// byHost carries material only usable on that exact host: Authorization and similar. This is
	// where inferred credentials go, because a header guessed from a capture of app.target.com must
	// not travel to cdn.target.com.
	byHost map[string]*ScopedAuthMaterial
	// byDomain carries material usable across a registrable domain like a browser would scope a
	// cookie. Inferred material only ever puts cookies here. Operator-declared session tokens may
	// also put headers here, because naming a domain in the Session Manager is explicit consent for
	// that domain, which a guess from a capture is not.
	byDomain map[string]*ScopedAuthMaterial

	// Everything below exists so a long-running scan can pick up a credential that was refreshed
	// after the run started. See refreshIfStale.
	mu            sync.RWMutex
	scopeTargetID string
	loadedAt      time.Time
}

// How long a loaded credential set is trusted before For() re-reads it from the database.
//
// WHY THIS EXISTS. LoadScopedAuthContext used to be called exactly once per scan phase, before the
// endpoint loop, and the result was then used for every request in that phase. That is fine for an
// API key and wrong for a short-lived bearer token, which is what modern auth issues.
//
// Measured on a live engagement: the target's authorisation server issues 900-second tokens and
// returns NO refresh token, so a session cannot be captured once and reused - it has to be re-minted
// every fifteen minutes. A validate-then-investigate run over ~1,000 endpoints is paced to the rate
// the WAF probe measured and comfortably outlives that. The token therefore expired part-way through
// a phase, every endpoint after that point got a 401, and those 401s were recorded as evidence about
// the endpoints. The run does not fail; it fingerprints the login wall and calls it the application.
// Every verdict after the expiry moment is wrong, and wrong in the same direction, which is the
// failure mode this codebase is otherwise careful to refuse (see the acknowledge flag on the endpoint
// scan, which warns about precisely this and could not detect it here because nothing re-checked).
//
// Sixty seconds is the trade: short enough that an operator refreshing a 900-second token sees it
// used almost immediately, long enough that a thousand-endpoint scan costs about one extra query a
// minute rather than one per request.
const scopedAuthRefreshTTL = 60 * time.Second

// refreshIfStale re-reads the credential set when the loaded copy has aged past the TTL.
//
// A failed or empty reload KEEPS the existing material rather than replacing it. That asymmetry is
// deliberate: a transient database error or a config the operator is midway through editing must not
// silently convert an authenticated scan into an anonymous one, which would produce exactly the
// login-wall-as-evidence result this refresh exists to prevent. Stale credentials are recoverable;
// a run that quietly went anonymous is not, because nothing in the results says so.
func (c *ScopedAuthContext) refreshIfStale() {
	if c == nil {
		return
	}
	c.mu.RLock()
	id, age := c.scopeTargetID, time.Since(c.loadedAt)
	c.mu.RUnlock()
	// An empty scopeTargetID means this context was hand-built (tests, callers that assembled
	// material directly). There is nothing to re-read, so leave it alone.
	if id == "" || age < scopedAuthRefreshTTL {
		return
	}

	fresh := buildScopedAuthContext(id)

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check under the write lock: several request goroutines can pass the staleness test at once
	// and only the first should pay for the reload.
	if time.Since(c.loadedAt) < scopedAuthRefreshTTL {
		return
	}
	c.loadedAt = time.Now()
	if len(fresh.byHost) == 0 && len(fresh.byDomain) == 0 {
		log.Printf("[SCAN-CREDS] %s: credential refresh returned nothing usable; "+
			"keeping the previously loaded material rather than going anonymous mid-run", id)
		return
	}
	c.byHost, c.byDomain = fresh.byHost, fresh.byDomain
}

// Apply attaches whatever this material permits and reports what happened, so a result can say
// whether it was measured authenticated or not. An empty page is ambiguous without that.
func (m *ScopedAuthMaterial) Apply(req *http.Request) (applied bool, withheld string) {
	if m == nil {
		return false, "no_credentials_available"
	}
	if m.Cookies != "" {
		req.Header.Set("Cookie", m.Cookies)
		applied = true
	}
	for k, v := range m.Headers {
		req.Header.Set(k, v)
		applied = true
	}
	// Applied by rewriting the URL rather than a header. Safe here because Apply runs after the
	// request is built and before it is sent, and existing parameters are preserved: a credential
	// must not silently drop the query the caller meant to send.
	if len(m.QueryParams) > 0 && req.URL != nil {
		q := req.URL.Query()
		for k, v := range m.QueryParams {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
		applied = true
	}
	if !applied {
		return false, "no_credentials_for_host"
	}
	return true, ""
}

// authMaterialSource names where a request's credentials came from, or says plainly that there were
// none. Callers record this next to a result, so "" would read as authenticated-from-nowhere.
func authMaterialSource(m *ScopedAuthMaterial) string {
	if m == nil {
		return "none"
	}
	if m.Source == "" {
		return "unknown"
	}
	return m.Source
}

// merge overlays other on top of m and returns a new material, leaving both operands untouched.
// Used to let operator-declared credentials win over inferred ones without discarding the parts of
// the guess the operator did not replace.
func (m *ScopedAuthMaterial) merge(host string, other *ScopedAuthMaterial) *ScopedAuthMaterial {
	if m == nil {
		return other
	}
	if other == nil {
		return m
	}
	out := &ScopedAuthMaterial{
		Host: host, Cookies: m.Cookies, Source: m.Source,
		Headers: map[string]string{}, QueryParams: map[string]string{},
	}
	for k, v := range m.Headers {
		out.Headers[k] = v
	}
	for k, v := range m.QueryParams {
		out.QueryParams[k] = v
	}
	if other.Cookies != "" {
		out.Cookies = other.Cookies
	}
	for k, v := range other.Headers {
		out.Headers[k] = v
	}
	for k, v := range other.QueryParams {
		out.QueryParams[k] = v
	}
	if other.Source != "" && other.Source != m.Source {
		out.Source = m.Source + "+" + other.Source
	}
	return out
}

// LoadScopedAuthContext builds credential material from the manual crawl captures, falling back to
// the target's saved FFUF configuration.
//
// Captures are preferred because they are real: a header the application actually accepted on a 2xx
// response. The FFUF config is what an operator typed, which may be stale.
func LoadScopedAuthContext(scopeTargetID string) *ScopedAuthContext {
	ctx := buildScopedAuthContext(scopeTargetID)
	// Recorded so For() can re-read when the credential ages out mid-run. Set here rather than in
	// buildScopedAuthContext so the refresh path does not reset its own clock from inside itself.
	ctx.scopeTargetID = scopeTargetID
	ctx.loadedAt = time.Now()
	return ctx
}

// buildScopedAuthContext does the actual loading. Split out from LoadScopedAuthContext so that
// refreshIfStale can rebuild from the same rules without recursing through the refresh bookkeeping.
func buildScopedAuthContext(scopeTargetID string) *ScopedAuthContext {
	ctx := &ScopedAuthContext{
		byHost:   map[string]*ScopedAuthMaterial{},
		byDomain: map[string]*ScopedAuthMaterial{},
	}

	// No pool, no stored credentials. This is reached from the request-flow runner and the parameter
	// tools as well as the scanners now, and those have unit tests that exercise the send path with
	// no database at all; pgxpool panics on a nil receiver rather than returning an error. An empty
	// context is also the honest answer to "what credentials are stored" when there is nowhere to
	// store them, so this is a real guard and not only a test accommodation.
	if dbPool == nil {
		return ctx
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT url, headers, status_code
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		  AND headers IS NOT NULL
		  AND status_code BETWEEN 200 AND 299
		ORDER BY created_at DESC
		LIMIT 500`, scopeTargetID)
	// Expired captures are counted and reported once at the end rather than logged per row.
	//
	// The per-row line was fine when this loaded once per scan phase. It is not fine now that For()
	// re-reads every 60 seconds: the query walks up to 500 capture rows, a target whose captures all
	// carry the same dead bearer logs one line for each, and a single long run turned that into
	// thousands of identical lines - 1,332 in four minutes, measured. That buries the lines that
	// matter, including the refresh warnings. One summary per load says the same thing.
	expiredByHost := map[string]int{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rawURL string
			var headersJSON []byte
			var status *int
			if rows.Scan(&rawURL, &headersJSON, &status) != nil {
				continue
			}
			u, parseErr := url.Parse(rawURL)
			if parseErr != nil || u.Hostname() == "" {
				continue
			}
			host := strings.ToLower(u.Hostname())

			var headers map[string]interface{}
			if json.Unmarshal(headersJSON, &headers) != nil {
				continue
			}

			cookie := ""
			hostOnly := map[string]string{}
			for name, value := range headers {
				sv, ok := value.(string)
				if !ok || sv == "" {
					continue
				}
				switch strings.ToLower(name) {
				case "cookie":
					cookie = sv
				case "authorization", "x-api-key", "x-auth-token", "x-access-token",
					"x-csrf-token", "x-xsrf-token", "x-session-token":
					// A captured token whose exp has passed is not a credential, it is a guarantee of
					// 401s. Dropping it here lets the FFUF fallback below supply a live one instead of
					// being skipped because this host already looked covered.
					if expiredBearer(sv) {
						expiredByHost[host]++
						continue
					}
					hostOnly[canonicalHeaderName(name)] = sv
				}
			}

			if _, seen := ctx.byHost[host]; !seen && (cookie != "" || len(hostOnly) > 0) {
				ctx.byHost[host] = &ScopedAuthMaterial{
					Host: host, Cookies: cookie, Headers: hostOnly, Source: "manual_crawl",
				}
			}
			if cookie != "" {
				d := RegistrableDomain(host)
				if _, seen := ctx.byDomain[d]; !seen {
					ctx.byDomain[d] = &ScopedAuthMaterial{
						Host: host, Cookies: cookie, Source: "manual_crawl",
					}
				}
			}
		}
	}
	for host, n := range expiredByHost {
		log.Printf("[SCAN-CREDS] %s: ignoring %d EXPIRED captured credential(s) for %s; "+
			"falling back to the configured credential", scopeTargetID, n, host)
	}

	// The FFUF config, scoped to the scope target's own host only.
	//
	// This OVERLAYS the captured material per header rather than only filling in when the host was
	// not seen at all, and the difference is not cosmetic. A capture supplies a Cookie as well as an
	// Authorization header, so under the old rule any host with a captured cookie counted as covered
	// and the configured credential was never consulted - even after the expiry check above had just
	// discarded the captured bearer as dead. The operator would set a fresh token, watch the save
	// succeed, and still be handed the stale one.
	//
	// Per-header overlay keeps the file's original intent intact: a capture is still the source for
	// anything the operator has not spoken about, and inference still fills the gaps. What changes is
	// that an explicitly configured header now beats a guessed one, which is the same precedence the
	// Session Manager already gets and for the same reason.
	targetHost := scopeTargetHost(scopeTargetID)
	if targetHost != "" {
		if headers, cookies := ffufAuthMaterial(scopeTargetID); len(headers) > 0 || cookies != "" {
			existing := ctx.byHost[targetHost]
			if existing == nil {
				existing = &ScopedAuthMaterial{
					Host: targetHost, Headers: map[string]string{}, Source: "ffuf_config",
				}
				ctx.byHost[targetHost] = existing
			}
			if existing.Headers == nil {
				existing.Headers = map[string]string{}
			}
			for _, h := range headers {
				name := canonicalHeaderName(h.Name)
				// The same freshness rule the capture path applies, for the same reason. A configured
				// header was previously trusted unconditionally, so an operator who pasted a bearer
				// token once had it sent on every scan from then on: expired, guaranteed to 401, and
				// indistinguishable in the results from the target refusing a live session. Skipping it
				// lets HasAny() report the truth - that this run has no working credential - instead of
				// the run fingerprinting a login wall and recording it as evidence about the endpoints.
				if expiredBearer(h.Value) {
					log.Printf("[SCAN-CREDS] %s: ignoring EXPIRED configured %s for %s; "+
						"refresh the credential to scan authenticated",
						scopeTargetID, name, targetHost)
					continue
				}
				if _, had := existing.Headers[name]; had && existing.Source != "ffuf_config" {
					existing.Source = "manual_crawl+ffuf_config"
				}
				existing.Headers[name] = h.Value
			}
			if cookies != "" {
				existing.Cookies = cookies
				d := RegistrableDomain(targetHost)
				if _, seen := ctx.byDomain[d]; !seen {
					ctx.byDomain[d] = &ScopedAuthMaterial{
						Host: targetHost, Cookies: cookies, Source: "ffuf_config",
					}
				}
			}
		}
	}

	// Last, and therefore winning: the tokens the operator declared in the Session Manager.
	//
	// Everything above this line is inference. The capture scan guesses which header looked like a
	// credential; the FFUF config is whatever was typed there at some point and may be months old.
	// A session token says explicitly what it is, how it goes on the wire, and which hosts it
	// belongs to, so it overlays the guesses rather than competing with them.
	ctx.ApplySessionTokens(scopeTargetID)

	return ctx
}

// For returns the material usable against one host, and the reason when nothing is.
//
// Host material and domain material are MERGED rather than checked in order, with the domain layer
// winning. That ordering is the whole point: everything in byHost is inferred, and the operator's
// declared session tokens land in byDomain when they name a domain. Returning the first hit instead
// meant a stale bearer guessed from a month-old capture beat the fresh token the operator had just
// typed in, and nothing anywhere said so. The documented contract is that the Session Manager
// overlays the guesses, so it has to actually overlay them.
//
// Inferred material never puts headers in byDomain, so a header returned from the domain layer can
// only be one the operator explicitly scoped to that domain.
func (c *ScopedAuthContext) For(host string) (*ScopedAuthMaterial, string) {
	if c == nil {
		return nil, "no_credentials_available"
	}
	// Re-read before answering when the loaded copy has aged out, so a scan that outlives a
	// short-lived token keeps sending a live one instead of 401ing its way through the rest of the
	// corpus. No-op for a hand-built context or one loaded within the TTL.
	c.refreshIfStale()
	host = strings.ToLower(host)

	c.mu.RLock()
	hostMaterial := c.byHost[host]
	domainMaterial := c.byDomain[RegistrableDomain(host)]
	c.mu.RUnlock()

	merged := hostMaterial.merge(host, domainMaterial)
	if merged == nil {
		return nil, "no_credentials_for_host"
	}
	if merged.Cookies == "" && len(merged.Headers) == 0 && len(merged.QueryParams) == 0 {
		return nil, "no_credentials_for_host"
	}
	// Preserve the host the caller asked about rather than whichever layer supplied the material.
	out := *merged
	out.Host = host
	return &out, ""
}

// HasAny reports whether the run has credentials at all, so a login wall can be reported as
// "not authenticated" rather than as evidence about the endpoint.
func (c *ScopedAuthContext) HasAny() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.byHost) > 0 || len(c.byDomain) > 0
}

// RegistrableDomain approximates the public-suffix boundary well enough to scope cookies.
//
// It is not a full PSL. It handles the common two-label suffixes explicitly so co.uk and com.au
// do not collapse a whole country's namespace into one bucket, which would let a cookie captured
// on one customer's site be sent to another's.
//
// AN IP LITERAL IS ITS OWN BOUNDARY AND HAS NO REGISTRABLE DOMAIN. Without the check below,
// RegistrableDomain("10.0.0.18") returned "0.18": the dotted-quad split into four labels, "0.18" was
// not a known two-label suffix, and the last two labels came back. Two things followed from that one
// string, both measured on the Juice Shop target on 2026-08-21:
//
//   - LoadScanScope put "0.18" in s.domains, so the boundary rendered as "*.0.18, 10.0.0.18" in
//     every scan that printed it, and Allows() admitted ANY host ending in ".0.18".
//     hostWithinDomain("110.0.0.18", "0.18") is true, because "110.0.0.18" really does end in
//     ".0.18" at a label boundary. A completely unrelated machine would have been treated as in
//     scope and sent traffic.
//   - byDomain, the cookie bucket, keyed on it. Every address in a 10.x.x.18 or 192.x.x.18 range
//     shared one bucket, so a session cookie captured on one host could be attached to a request to
//     another.
//
// It returns the HOST rather than "". Empty looks tidier and is worse: byDomain is keyed on this
// value, so "" would collapse EVERY IP-literal host into a single bucket and hand one machine's
// cookies to the next. The host itself gives each address its own bucket, which is the correct
// answer to "what namespace does this belong to" for something that belongs to no namespace.
// LoadScanScope skips the domain widening for an address separately, so nothing renders "*.10.0.0.18".
func RegistrableDomain(host string) string {
	host = strings.ToLower(strings.Trim(host, "."))
	if isIPLiteralHost(host) {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	twoLabelSuffixes := map[string]bool{
		"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true,
		"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
		"co.nz": true, "co.za": true, "co.jp": true, "or.jp": true, "ne.jp": true,
		"com.br": true, "com.mx": true, "com.ar": true, "com.tr": true, "com.cn": true,
		"com.sg": true, "com.hk": true, "com.tw": true, "co.in": true, "com.in": true,
		"co.kr": true, "com.pl": true, "com.ua": true, "co.il": true, "com.my": true,
	}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if twoLabelSuffixes[last2] && len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return last2
}

// isIPLiteralHost reports whether a host string is an address rather than a name.
//
// Brackets are stripped because a URL authority writes IPv6 as [::1] and url.Hostname() does not
// always get to strip them before a host string reaches here.
func isIPLiteralHost(host string) bool {
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	return h != "" && net.ParseIP(h) != nil
}

func scopeTargetHost(scopeTargetID string) string {
	var raw string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target FROM scope_targets WHERE id = $1`, scopeTargetID).Scan(&raw); err != nil {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// ScopeTargetBase returns the scope target's scheme and host, used as the canonical base URL and
// the default scheme for canonicalisation.
func ScopeTargetBase(scopeTargetID string) (scheme, host, base string) {
	// Same reasoning as buildScopedAuthContext: pgxpool panics on a nil receiver, and this is now
	// reached from paths with unit tests that run without a database.
	if dbPool == nil {
		return "https", "", ""
	}
	var raw string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target FROM scope_targets WHERE id = $1`, scopeTargetID).Scan(&raw); err != nil {
		return "https", "", ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "https", "", ""
	}
	scheme = u.Scheme
	host = strings.ToLower(u.Hostname())
	hostPort := host
	if p := u.Port(); p != "" {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		if !isDefaultPort(scheme, n) {
			hostPort = host + ":" + p
		}
	}
	return scheme, host, scheme + "://" + hostPort
}
