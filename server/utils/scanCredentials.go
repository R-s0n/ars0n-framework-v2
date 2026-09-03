package utils

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
)

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
	ctx := &ScopedAuthContext{
		byHost:   map[string]*ScopedAuthMaterial{},
		byDomain: map[string]*ScopedAuthMaterial{},
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT url, headers, status_code
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		  AND headers IS NOT NULL
		  AND status_code BETWEEN 200 AND 299
		ORDER BY created_at DESC
		LIMIT 500`, scopeTargetID)
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

	// FFUF fallback, scoped to the scope target's own host only.
	targetHost := scopeTargetHost(scopeTargetID)
	if targetHost != "" {
		if _, exists := ctx.byHost[targetHost]; !exists {
			if headers, cookies := ffufAuthMaterial(scopeTargetID); len(headers) > 0 || cookies != "" {
				hostOnly := map[string]string{}
				for _, h := range headers {
					hostOnly[canonicalHeaderName(h.Name)] = h.Value
				}
				ctx.byHost[targetHost] = &ScopedAuthMaterial{
					Host: targetHost, Cookies: cookies, Headers: hostOnly, Source: "ffuf_config",
				}
				if cookies != "" {
					d := RegistrableDomain(targetHost)
					if _, seen := ctx.byDomain[d]; !seen {
						ctx.byDomain[d] = &ScopedAuthMaterial{
							Host: targetHost, Cookies: cookies, Source: "ffuf_config",
						}
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
	host = strings.ToLower(host)

	hostMaterial := c.byHost[host]
	domainMaterial := c.byDomain[RegistrableDomain(host)]

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
	return c != nil && (len(c.byHost) > 0 || len(c.byDomain) > 0)
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
