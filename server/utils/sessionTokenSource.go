package utils

import (
	"context"
	"log"
	"net/url"
	"strings"
)

// Active session tokens as a credential source for every scan.
//
// Before this, credentials were reverse-engineered out of manual crawl captures: take the last few
// hundred 2xx responses, look for anything that smells like a Cookie or an Authorization header,
// and hope. That works until it does not, and when it does not the failure is silent. A live run
// against a real target reported credentials_honoured=false and then validated two thousand
// endpoints against a login wall, because the capture heuristic found a header that was no longer
// good and nothing in the pipeline could tell the difference.
//
// The Session Manager makes the credential explicit: the operator says what the token is, exactly
// how it goes on the wire, which hosts it belongs to, and which auth flow can mint another one.
// That is strictly better evidence than a guess, so it wins.
//
// The capture heuristic stays as the fallback. An operator who has not set up a session should not
// suddenly lose the credentials that used to work, and on a fresh target the crawl is still the
// fastest way to get authenticated.

// ApplySessionTokens overlays the target's active session tokens onto a context built from the
// captures. Overlay rather than replace: a session is frequently a cookie the crawl saw plus a CSRF
// header the operator pasted in, and dropping either half breaks the request.
func (c *ScopedAuthContext) ApplySessionTokens(scopeTargetID string) {
	if c == nil {
		return
	}

	// Expired tokens are excluded rather than sent. expires_at used to be recorded and ignored, so a
	// token the framework already knew was dead still went on the wire and the 401s it produced were
	// indistinguishable from the target refusing a live session. A NULL expiry means the operator
	// did not say, which is not the same as expired.
	rows, err := dbPool.Query(context.Background(), `
		SELECT COALESCE(token_type,''), COALESCE(header_name,''), COALESCE(cookie_name,''),
		       COALESCE(param_name,''), COALESCE(value_prefix,''), COALESCE(token_value,''),
		       COALESCE(scope_domains, '{}'), COALESCE(cookie_domain,''), COALESCE(name,'')
		FROM session_tokens
		WHERE scope_target_id = $1 AND is_active = TRUE AND COALESCE(token_value,'') <> ''
		  AND (expires_at IS NULL OR expires_at > NOW())`,
		scopeTargetID)
	if err != nil {
		// The table not existing yet, on an install that has not migrated, is not a reason to fail
		// a scan. The capture fallback still carries it.
		return
	}
	defer rows.Close()

	// Counted separately so an operator whose only token just expired is told that, rather than
	// silently getting an anonymous scan that reads as a login wall on every endpoint.
	var expiredCount int
	_ = dbPool.QueryRow(context.Background(), `
		SELECT count(*) FROM session_tokens
		WHERE scope_target_id = $1 AND is_active = TRUE AND COALESCE(token_value,'') <> ''
		  AND expires_at IS NOT NULL AND expires_at <= NOW()`, scopeTargetID).Scan(&expiredCount)

	// Where a token applies when the operator did not say. The scope target's own registrable
	// domain is the honest default: it is the thing they authenticated to.
	_, targetHost, _ := ScopeTargetBase(scopeTargetID)
	defaultDomain := RegistrableDomain(strings.ToLower(targetHost))

	applied := 0
	skipped := map[string]string{}

	for rows.Next() {
		var kind, headerName, cookieName, paramName, prefix, value, cookieDomain, tokenName string
		var domains []string
		if rows.Scan(&kind, &headerName, &cookieName, &paramName, &prefix, &value,
			&domains, &cookieDomain, &tokenName) != nil {
			continue
		}

		scopes := normaliseTokenScopes(domains, cookieDomain, defaultDomain)
		if len(scopes) == 0 {
			continue
		}

		for _, scope := range scopes {
			switch kind {
			case "cookie":
				name := cookieName
				if name == "" {
					continue
				}
				// Which map a cookie lands in depends on whether its scope is a host or a domain,
				// and getting this wrong made the whole feature a no-op for its main use case.
				//
				// For() looks up byHost by exact host and byDomain by REGISTRABLE domain. A cookie
				// scoped to "mobile.prod-one.countr.one" filed under byDomain is looked for at
				// byDomain["countr.one"] and never found, so on any target that is not an apex
				// domain, which is the normal case, no cookie was ever attached to anything.
				//
				// A Set-Cookie that declared Domain=.example.com genuinely is domain-scoped and
				// belongs in byDomain. Anything else is a single host and belongs in byHost. The
				// scope is deliberately not widened to the registrable domain to make it match:
				// that would hand the session to every sibling subdomain.
				if scope == RegistrableDomain(scope) {
					c.addDomainCookie(scope, name+"="+value)
				} else {
					c.addHostCookie(scope, name+"="+value)
				}
			case "header", "api_key", "bearer":
				name := headerName
				if name == "" && kind == "bearer" {
					name = "Authorization"
				}
				if name == "" {
					// An api_key row carrying only a param_name is a query credential wearing the
					// wrong type. Handle it as one rather than dropping it on the floor.
					if paramName != "" {
						c.addScopedQueryParam(scope, paramName, prefix+value)
						break
					}
					skipped[tokenName] = "no header_name and no param_name"
					continue
				}
				// Where a header lands decides whether it can ever be found again, and getting this
				// wrong made declared tokens a no-op. For() matches byHost on the exact host and
				// byDomain on the REGISTRABLE domain. A token the operator scoped to "example.com"
				// filed under byHost is looked for at byHost["api.example.com"] and never found, so
				// on any target that is not a bare apex, which is the normal case, the operator's
				// declared session was never attached to anything.
				//
				// Naming a domain in the Session Manager is explicit consent for that domain, so a
				// domain scope belongs in byDomain. A single host still belongs in byHost, and an
				// inferred header from a capture never reaches byDomain at all.
				if scope == RegistrableDomain(scope) {
					c.addDomainHeader(scope, name, prefix+value)
				} else {
					c.addHostHeader(scope, name, prefix+value)
				}
			case "query":
				if paramName == "" {
					skipped[tokenName] = "no param_name"
					continue
				}
				c.addScopedQueryParam(scope, paramName, prefix+value)
			default:
				skipped[tokenName] = "unknown token_type " + kind
				continue
			}
			applied++
		}
	}

	if applied > 0 {
		log.Printf("[SESSION] %d active session token binding(s) applied for %s", applied, scopeTargetID)
	}
	// A token that was stored, activated, and then not attached is the failure this whole subsystem
	// exists to avoid, so it is said out loud rather than inferred later from a wall of 401s.
	for name, why := range skipped {
		log.Printf("[SESSION] token %q was NOT attached for %s: %s", name, scopeTargetID, why)
	}
	if expiredCount > 0 {
		log.Printf("[SESSION] %d active token(s) for %s are past expires_at and were not sent; "+
			"refresh them or the scan measures an anonymous session",
			expiredCount, scopeTargetID)
	}
}

// addDomainHeader files an operator-declared header against a registrable domain, where For() can
// find it for every host under that domain.
func (c *ScopedAuthContext) addDomainHeader(domain, name, value string) {
	m := c.byDomain[domain]
	if m == nil {
		m = &ScopedAuthMaterial{Host: domain, Headers: map[string]string{}, Source: "session_manager"}
		c.byDomain[domain] = m
	}
	if m.Headers == nil {
		m.Headers = map[string]string{}
	}
	m.Headers[name] = value
	m.Source = "session_manager"
}

// addScopedQueryParam files a URL-borne credential, choosing host or domain by the same rule the
// headers and cookies use.
func (c *ScopedAuthContext) addScopedQueryParam(scope, name, value string) {
	target := c.byHost
	if scope == RegistrableDomain(scope) {
		target = c.byDomain
	}
	m := target[scope]
	if m == nil {
		m = &ScopedAuthMaterial{Host: scope, Headers: map[string]string{}, Source: "session_manager"}
		target[scope] = m
	}
	if m.QueryParams == nil {
		m.QueryParams = map[string]string{}
	}
	m.QueryParams[name] = value
	m.Source = "session_manager"
}

// normaliseTokenScopes decides which hosts or domains a token covers.
func normaliseTokenScopes(domains []string, cookieDomain, defaultDomain string) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(d string) {
		d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" || seen[d] {
			return
		}
		if strings.Contains(d, "://") {
			if u, err := url.Parse(d); err == nil && u.Hostname() != "" {
				d = strings.ToLower(u.Hostname())
			}
		}
		seen[d] = true
		out = append(out, d)
	}
	for _, d := range domains {
		add(d)
	}
	// A Set-Cookie Domain attribute is a scope the server itself declared, so it counts even when
	// the operator left the scope list empty.
	add(cookieDomain)
	if len(out) == 0 {
		add(defaultDomain)
	}
	return out
}

func (c *ScopedAuthContext) addDomainCookie(domain, cookie string) {
	m := c.byDomain[domain]
	if m == nil {
		m = &ScopedAuthMaterial{Host: domain, Headers: map[string]string{}, Source: "session_manager"}
		c.byDomain[domain] = m
	}
	if m.Headers == nil {
		m.Headers = map[string]string{}
	}
	// Appended rather than replaced: a session is often several cookies and each one arrived from a
	// different place.
	if m.Cookies == "" {
		m.Cookies = cookie
	} else if !strings.Contains(m.Cookies, cookie) {
		m.Cookies = m.Cookies + "; " + cookie
	}
	m.Source = "session_manager"
}

// addHostCookie files a cookie against one exact host, which is where For() looks first.
func (c *ScopedAuthContext) addHostCookie(host, cookie string) {
	m := c.byHost[host]
	if m == nil {
		m = &ScopedAuthMaterial{Host: host, Headers: map[string]string{}, Source: "session_manager"}
		c.byHost[host] = m
	}
	if m.Cookies == "" {
		m.Cookies = cookie
	} else if !strings.Contains(m.Cookies, cookie) {
		m.Cookies = m.Cookies + "; " + cookie
	}
	m.Source = "session_manager"
}

func (c *ScopedAuthContext) addHostHeader(host, name, value string) {
	m := c.byHost[host]
	if m == nil {
		m = &ScopedAuthMaterial{Host: host, Headers: map[string]string{}, Source: "session_manager"}
		c.byHost[host] = m
	}
	if m.Headers == nil {
		m.Headers = map[string]string{}
	}
	m.Headers[name] = value
	m.Source = "session_manager"
}
