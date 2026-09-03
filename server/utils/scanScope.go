package utils

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Which hosts a request-issuing scan is allowed to contact.
//
// This exists because of a live incident, not as a precaution. A validation run against
// mobile.prod-one.countr.one contacted 112 distinct hosts, 91 of them unrelated to the target:
// irs.gov, walmart.com, experian.com, github.com, w3.org, moneygram.com, auth0.com, klarna.com,
// launchdarkly.com, googleapis.com, play.google.com. It did not merely fetch them. Validate created
// a per-directory not-found control for each, which means it sent synthetic /ars0nprobe-<random>
// requests into third-party directories, and Tier 1 requested robots.txt, security.txt and
// sitemap.xml from every one of them.
//
// Two independent holes caused it, which is why the enforcement point is here rather than in either
// of them. buildQueue selected every consolidated row regardless of is_direct, and Tier 1's host
// probes took hostOf(t.URL) with no check at all. Fixing both call sites would leave the next one
// unprotected, exactly like the verb allowlist did before it moved into ScanClient.
//
// An adjacent endpoint still belongs in the corpus: knowing the application loads scripts from a
// third party is worth recording, and it is how the third-party attack surface gets found. What is
// never acceptable is *sending requests* there under an engagement that did not authorize it.
//
// The default boundary is the scope target's own registrable domain, plus every host the operator's
// own manual crawl observed the application contacting. Being too narrow costs coverage the operator
// can see and widen, while being too wide sends unauthorized traffic to somebody who never agreed to
// it, so the line is drawn at evidence of the application's own behaviour.
//
// That second half is not a widening at all. It is the framework stopping throwing away a decision
// the operator already made. The extension only ever uploads a capture whose host passed
// shouldCapture, and buildScopeHosts admits exactly three things: the target host, its base domain
// when includeSubdomains is on, and hosts the operator typed into the popup by hand. So a capture on
// a host outside the target's registrable domain exists only because somebody explicitly authorized
// that host before recording. mercury-dev-api.one.app and dev-partner-auth.one.app, where this
// application's API and login actually live, got into the database that way and were then refused
// here as though nobody had ever vouched for them.
//
// walmart.com and w3.org, by contrast, reached the corpus from an archive crawler reading links off
// a page, which is evidence of nothing. Both groups were previously refused identically, and the
// first is the more valuable half of the engagement: 40 endpoints including a POST
// /cookieless/refresh observed 42 times answering 403.
//
// The default is still overridable in both directions, which is why scope_target_scope_hosts stores
// a boolean rather than a list of admitted hosts. An operator who scoped a whole base domain during
// recording can pull an analytics or CDN host back out without re-recording anything.

type ScanScope struct {
	// The scope target's own host, always allowed even if the registrable-domain computation is
	// unusual for its suffix.
	primary string
	// Registrable domains whose subdomains are in scope.
	domains map[string]bool
	// Hosts the operator named explicitly.
	extra map[string]bool

	// Set when the boundary could not be established at all. Refusing everything is the safe
	// failure: a scan that measures nothing is recoverable, unauthorized traffic is not.
	refuseAll bool

	// Authored pattern rules. When non-empty these REPLACE the three fields above as the boundary,
	// rather than adding to them, so a deny cannot be overridden by a legacy list.
	rules []ScopeRule

	mu      sync.Mutex
	refused map[string]int
}

// ErrOutOfScope is returned rather than silently succeeding, so a call site that reaches for a host
// it should not have is a visible failure rather than quiet unauthorized traffic.
var ErrOutOfScope = fmt.Errorf("scanHTTP: host is outside the scope of this target")

// LoadScanScope builds the boundary for a scope target.
func LoadScanScope(scopeTargetID string) *ScanScope {
	s := &ScanScope{
		domains: map[string]bool{},
		extra:   map[string]bool{},
		refused: map[string]int{},
	}

	host := scopeTargetHost(scopeTargetID)
	if host == "" {
		// No host means no boundary can be established. Refusing everything is the safe failure:
		// a run that measures nothing is recoverable, unauthorized traffic is not.
		return s
	}
	s.primary = strings.ToLower(host)
	// An address target is the exact host and nothing else. RegistrableDomain now returns the
	// address itself rather than the last two labels of it, so widening here would put "10.0.0.18"
	// in domains and Describe() would render the boundary as "*.10.0.0.18, 10.0.0.18". Nothing is
	// admitted that primary does not already admit, so the only thing the entry would add is a
	// wildcard in the operator's answer to "why was this skipped" that does not correspond to
	// anything a subdomain could ever match.
	if rd := RegistrableDomain(s.primary); rd != "" && !isIPLiteralHost(s.primary) {
		s.domains[rd] = true
	}
	// Only record hosts the domain rule does not already cover. Adding one that is already inside
	// the boundary changes nothing about what is allowed but does show up twice in Describe, and
	// that description is the operator's answer to "why was this skipped".
	crawled := InScopeCrawlHosts(scopeTargetID)
	for _, h := range crawled {
		if !s.Allows(h) {
			s.extra[h] = true
		}
	}

	// Load authored rules LAST, after the legacy boundary is fully built, because Allows() above
	// must still be answering with the legacy logic while that boundary is being assembled.
	// Assigning s.rules earlier would make those calls consult a half-built ruleset.
	rules, err := LoadScopeRules(scopeTargetID)
	if err != nil {
		// A target whose rules will not compile is refused entirely rather than silently falling
		// back to the wider legacy boundary. Falling back is the failure mode where an operator
		// writes a deny, it fails to load, and traffic goes out anyway.
		log.Printf("[SCOPE] target %s: rules failed to load, refusing everything: %v", scopeTargetID, err)
		return &ScanScope{
			domains: map[string]bool{}, extra: map[string]bool{}, refused: map[string]int{},
			refuseAll: true,
		}
	}
	if len(rules) > 0 {
		s.rules = rules
	}
	return s
}

// InScopeCrawlHosts returns the hosts this target's manual crawl observed that the framework may
// contact, after the operator's overrides are applied.
//
// Read by LoadScanScope and by the API that renders the modal, from here rather than duplicated, so
// what the operator is shown as in scope and what the scanner actually sends to cannot drift. That
// is the same reason InScopeHostSQL is a fragment instead of a helper call.
func InScopeCrawlHosts(scopeTargetID string) []string {
	decided := map[string]bool{}
	rows, err := dbPool.Query(context.Background(),
		`SELECT lower(host), in_scope FROM scope_target_scope_hosts WHERE scope_target_id = $1`,
		scopeTargetID)
	if err == nil {
		for rows.Next() {
			var host string
			var inScope bool
			if rows.Scan(&host, &inScope) == nil && host != "" {
				decided[host] = inScope
			}
		}
		rows.Close()
	}

	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}

	// Observed hosts are admitted unless the operator said otherwise.
	crawled, err := dbPool.Query(context.Background(),
		`SELECT DISTINCT capture_host(url) FROM manual_crawl_captures
		 WHERE scope_target_id = $1 AND capture_host(url) <> ''`, scopeTargetID)
	if err == nil {
		for crawled.Next() {
			var host string
			if crawled.Scan(&host) != nil || host == "" {
				continue
			}
			if in, ok := decided[host]; ok && !in {
				continue
			}
			add(host)
		}
		crawled.Close()
	}

	// Hosts the operator named that the crawl never saw, such as one typed in from a program's
	// scope page, still belong in the boundary.
	for host, inScope := range decided {
		if inScope {
			add(host)
		}
	}

	sort.Strings(out)
	return out
}

// Allow adds hosts or domains the operator has explicitly authorized, such as a second domain named
// in the same bug bounty program. A leading "*." is accepted and treated as the domain itself.
func (s *ScanScope) Allow(entries ...string) {
	// Lazily created: a zero-value ScanScope has nil maps, and assigning into one panics. Every
	// production path goes through LoadScanScope, which initialises them, but a panic in the helper
	// that widens a security boundary is not something to leave waiting for the next caller.
	if s.extra == nil {
		s.extra = map[string]bool{}
	}
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		e = strings.TrimPrefix(e, "*.")
		if e == "" {
			continue
		}
		if strings.Contains(e, "://") {
			if u, err := url.Parse(e); err == nil && u.Hostname() != "" {
				e = strings.ToLower(u.Hostname())
			}
		}
		s.extra[e] = true
	}
}

// Allows reports whether this scan may send a request to host.
func (s *ScanScope) Allows(host string) bool {
	if s == nil {
		return true // an unscoped client is the pre-existing behaviour for callers that opt out
	}
	if s.refuseAll {
		return false
	}

	// Authored rules, when there are any, are the WHOLE boundary. Neither the host lists below nor
	// the crawl's observed hosts are admitted alongside them.
	//
	// That is a deliberate narrowing and it is the point: a deny is meaningless if some other list
	// can still allow past it. An operator who authors rules is taking control of the boundary, and
	// coverage they lose is visible before they commit, because the preview endpoint reports
	// newly_denied for exactly this.
	//
	// A target with no authored rules never reaches this branch, so its behaviour is byte-for-byte
	// what it was before rules existed.
	if len(s.rules) > 0 {
		auth, ok := NormalizeAuthority(host, "")
		return DecideScope(s.rules, auth, ok, ScopeDecisionInput{}).Allowed
	}

	host = strings.ToLower(strings.Trim(host, "."))
	if host == "" {
		return false
	}
	if host == s.primary {
		return true
	}
	if s.extra[host] {
		return true
	}
	for d := range s.domains {
		if hostWithinDomain(host, d) {
			return true
		}
	}
	for d := range s.extra {
		if hostWithinDomain(host, d) {
			return true
		}
	}
	return false
}

// AllowsURL is the form the call sites want.
func (s *ScanScope) AllowsURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return s.Allows(u.Hostname())
}

// hostWithinDomain is a label-boundary check, never a suffix match. "notcountr.one" must not be
// treated as inside "countr.one", and strings.HasSuffix would say it is.
func hostWithinDomain(host, domain string) bool {
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

// Refuse records a host that was turned away, so the run can report what it declined to touch
// rather than leaving the operator to wonder why a quarter of the corpus has no verdict.
func (s *ScanScope) Refuse(host string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refused[strings.ToLower(host)]++
}

// Refused returns the out-of-scope hosts and how many requests were declined for each.
func (s *ScanScope) Refused() map[string]int {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.refused))
	for k, v := range s.refused {
		out[k] = v
	}
	return out
}

// Describe renders the boundary for the operator, so "why was this skipped" has an answer on screen.
func (s *ScanScope) Describe() string {
	if s == nil {
		return "unrestricted"
	}
	var parts []string
	if s.primary != "" {
		parts = append(parts, s.primary)
	}
	for d := range s.domains {
		parts = append(parts, "*."+d)
	}
	for d := range s.extra {
		parts = append(parts, d)
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "nothing (no host could be determined for this scope target)"
	}
	return strings.Join(parts, ", ")
}

// InScopeHostSQL is the predicate that keeps out-of-scope rows out of a work queue.
//
// It is a fragment rather than a helper call so the queue and the counts that describe it cannot
// disagree, which is the same reason InvestigationEligibility is a const.
func (s *ScanScope) InScopeHostSQL(column string) string {
	if s == nil || s.primary == "" {
		return "TRUE"
	}
	var conds []string
	add := func(d string) {
		d = strings.ReplaceAll(d, "'", "''")
		conds = append(conds,
			fmt.Sprintf("lower(%s) = '%s'", column, d),
			fmt.Sprintf("lower(%s) LIKE '%%.%s'", column, d))
	}
	add(s.primary)
	for d := range s.domains {
		add(d)
	}
	for d := range s.extra {
		add(d)
	}
	return "(" + strings.Join(conds, " OR ") + ")"
}

// LoadConfiguredScopeDomains returns the registrable domains of every other scope target the
// operator has configured. Offered as an opt-in widening, never applied automatically: owning two
// programs does not mean traffic for one belongs in the results of the other.
func LoadConfiguredScopeDomains() []string {
	rows, err := dbPool.Query(context.Background(),
		`SELECT type, scope_target FROM scope_targets WHERE type IN ('Wildcard','URL')`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var kind, raw string
		if rows.Scan(&kind, &raw) != nil {
			continue
		}
		raw = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "*.")
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "://") {
			u, err := url.Parse(raw)
			if err != nil || u.Hostname() == "" {
				continue
			}
			raw = u.Hostname()
		}
		if d := RegistrableDomain(raw); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}
