package utils

// Scope rules: parsing, normalisation and matching.
//
// This file and extension/lib/scoperules.js are two implementations of ONE algorithm. They are kept
// in agreement by scope/vectors.json, which both sides run as a test (TestScopeRuleVectors here,
// scoperules.test.mjs there). Changing behaviour in one without the other fails that test.
//
// THIS side is authoritative. The extension decides locally so it can drop a request without a
// round trip and so the popup can preview a rule as it is typed, but its verdict is never
// authorization: everything is re-decided here at ingest and before any outbound request.
//
// THE PROPERTY THAT MAKES TWO HAND-WRITTEN EVALUATORS SAFE:
// deny wins unconditionally, with no precedence, no ordering and no specificity override. The only
// thing the two implementations can disagree about is WHICH rule is named in the explanation, never
// whether a host is in scope. A divergence costs a wrong sentence, not a wrong boundary.

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

/* ------------------------------------------------------------------ types */

type ScopeEffect string
type ScopeKind string
type ScopeBlast string

const (
	EffectAllow ScopeEffect = "allow"
	EffectDeny  ScopeEffect = "deny"

	KindHost       ScopeKind = "host"
	KindSubtree    ScopeKind = "subtree"
	KindSubdomains ScopeKind = "subdomains"
	KindContains   ScopeKind = "contains"
	KindRegex      ScopeKind = "regex"

	BlastNarrow  ScopeBlast = "narrow"
	BlastBounded ScopeBlast = "bounded"
	BlastWide    ScopeBlast = "wide"
)

// ScopeRule is one operator-authored rule. Kept flat so the JSON shape is identical in Go, the REST
// API, the MCP layer and the extension.
type ScopeRule struct {
	ID      string      `json:"id,omitempty"`
	Effect  ScopeEffect `json:"effect"`
	Kind    ScopeKind   `json:"kind"`
	Value   string      `json:"value"`
	Port    int         `json:"port,omitempty"`
	Within  string      `json:"within,omitempty"`
	IsIP    bool        `json:"is_ip,omitempty"`
	Blast   ScopeBlast  `json:"blast"`
	Enabled bool        `json:"enabled"`

	compiled *regexp.Regexp
}

// ScopeAuthority is the subject of every decision: a host and the port it was reached on.
type ScopeAuthority struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	IsIP bool   `json:"is_ip"`
}

// ScopeVerdict is the answer, with the rule that produced it so the UI can explain itself.
type ScopeVerdict struct {
	Allowed bool       `json:"allowed"`
	Rule    *ScopeRule `json:"rule,omitempty"`
	Reason  string     `json:"reason"`
}

const (
	containsMinLength = 4
	regexMaxLength    = 200
	regexMaxRepeat    = 64
)

var containsHazards = map[string]bool{
	"www": true, "api": true, "app": true, "dev": true, "cdn": true, "cloud": true,
	"aws": true, "static": true, "assets": true, "com": true, "net": true, "org": true,
	"io": true, "co": true, "test": true, "local": true,
}

/* ------------------------------------------------------------------ step A: normalise */

// NormalizeAuthority turns a URL or a bare authority into the {host, port} pair every decision is
// made about. It returns ok=false for anything it cannot name, which is a DENY: a subject we cannot
// name is a subject we cannot authorize.
func NormalizeAuthority(input, schemeHint string) (ScopeAuthority, bool) {
	var zero ScopeAuthority
	raw := strings.TrimSpace(input)
	if raw == "" {
		return zero, false
	}

	scheme := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(schemeHint)), ":")
	authority := raw

	// A1. Split scheme from authority by hand rather than with net/url, whose leniency differs from
	// the JS side in ways that would put the two evaluators out of step.
	if i := strings.Index(raw, "://"); i > 0 {
		scheme = strings.ToLower(raw[:i])
		if !reScheme.MatchString(scheme) {
			return zero, false
		}
		authority = raw[i+3:]
		if end := strings.IndexAny(authority, "/?#"); end != -1 {
			authority = authority[:end]
		}
	}
	if authority == "" {
		return zero, false
	}

	// A2. Discard userinfo, up to and including the LAST '@'.
	//
	// capture_host in SQL does not do this: "https://user@host/x" yields "user@host". A contains
	// rule evaluated against that is a rule matched against text the attacker chose, because anyone
	// can put anything in front of an '@'. Stripping it is a prerequisite, not a nicety.
	if at := strings.LastIndex(authority, "@"); at != -1 {
		authority = authority[at+1:]
	}
	if authority == "" {
		return zero, false
	}

	// A3. Host and port, honouring bracketed IPv6.
	var host, portText string
	if strings.HasPrefix(authority, "[") {
		close := strings.Index(authority, "]")
		if close == -1 {
			return zero, false
		}
		host = authority[1:close]
		rest := authority[close+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return zero, false
			}
			portText = rest[1:]
		}
	} else if colon := strings.Index(authority, ":"); colon != -1 {
		host = authority[:colon]
		portText = authority[colon+1:]
		// A bare IPv6 with no brackets is ambiguous against host:port. Refuse rather than guess.
		if strings.Contains(portText, ":") {
			return zero, false
		}
	} else {
		host = authority
	}

	// A4. Lowercase; strip leading and trailing dots. A trailing dot is the DNS root and must not
	// make "example.com." a different subject from "example.com".
	host = strings.ToLower(host)
	host = strings.Trim(host, ".")
	if host == "" {
		return zero, false
	}

	// A5. ASCII only. Adding an IDNA library would create a fourth artifact that has to agree with
	// the other three; a U-label is denied and recorded instead.
	for i := 0; i < len(host); i++ {
		if host[i] < 0x20 || host[i] > 0x7e {
			return zero, false
		}
	}

	// A6. Address or name.
	isIP := looksLikeIP(host)
	if isIP {
		canonical := canonicalizeIP(host)
		if canonical == "" {
			return zero, false
		}
		host = canonical
	} else if !IsValidHostname(host) {
		return zero, false
	}

	// A7. Port: explicit, else derived from the scheme, else 0 meaning unknown.
	port := 0
	if portText != "" {
		if !rePort.MatchString(portText) {
			return zero, false
		}
		n, err := strconv.Atoi(portText)
		if err != nil || n < 1 || n > 65535 {
			return zero, false
		}
		port = n
	} else {
		switch scheme {
		case "https", "wss":
			port = 443
		case "http", "ws":
			port = 80
		}
	}

	return ScopeAuthority{Host: host, Port: port, IsIP: isIP}, true
}

var (
	reScheme = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)
	rePort   = regexp.MustCompile(`^[0-9]{1,5}$`)
	reLabel  = regexp.MustCompile(`^[a-z0-9_-]+$`)
	reIPv4   = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	reDigits = regexp.MustCompile(`^[0-9.]+$`)
)

func IsValidHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	// Two labels minimum: a single label is a search-domain-relative name, never a scope subject.
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		// Underscores are permitted: _dmarc.example.com and svc_internal.example.com are real
		// hosts. Safe because no rule value is ever interpolated into SQL or into a LIKE pattern.
		if !reLabel.MatchString(label) {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func looksLikeIP(host string) bool {
	if reDigits.MatchString(host) {
		return reIPv4.MatchString(host)
	}
	return strings.Contains(host, ":")
}

// canonicalizeIP makes one address exactly one subject, so 010.0.0.1 and 10.0.0.1 cannot be two.
// Returns "" for anything that is not actually an address.
func canonicalizeIP(host string) string {
	if !strings.Contains(host, ":") {
		parts := strings.Split(host, ".")
		if len(parts) != 4 {
			return ""
		}
		out := make([]string, 0, 4)
		for _, part := range parts {
			if len(part) < 1 || len(part) > 3 {
				return ""
			}
			for i := 0; i < len(part); i++ {
				if part[i] < '0' || part[i] > '9' {
					return ""
				}
			}
			n, err := strconv.Atoi(part)
			if err != nil || n > 255 {
				return ""
			}
			out = append(out, strconv.Itoa(n))
		}
		return strings.Join(out, ".")
	}

	ip := net.ParseIP(host)
	if ip == nil || ip.To16() == nil {
		return ""
	}
	// Expanded form, matching the JS canonicaliser exactly. net.IP.String() compresses with "::"
	// and would not agree with the JS side.
	v6 := ip.To16()
	groups := make([]string, 8)
	for i := 0; i < 8; i++ {
		groups[i] = strconv.FormatInt(int64(v6[i*2])<<8|int64(v6[i*2+1]), 16)
	}
	return strings.Join(groups, ":")
}

/* ------------------------------------------------------------------ parsing */

var reWithin = regexp.MustCompile(`\s+within\s+(\S+)\s*$`)

// ParseScopeRule turns one typed line into a rule. It never panics: the popup and the API both call
// it on unvalidated operator input.
func ParseScopeRule(line string) (ScopeRule, error) {
	var zero ScopeRule
	raw := strings.TrimSpace(line)
	if raw == "" {
		return zero, fmt.Errorf("empty")
	}

	rest := raw
	effect := EffectAllow
	if strings.HasPrefix(rest, "!") {
		effect = EffectDeny
		rest = strings.TrimSpace(rest[1:])
		if rest == "" {
			return zero, fmt.Errorf("a deny needs something to deny")
		}
	}

	within := ""
	if m := reWithin.FindStringSubmatchIndex(rest); m != nil {
		within = strings.Trim(strings.ToLower(rest[m[2]:m[3]]), ".")
		rest = strings.TrimSpace(rest[:m[0]])
		if !IsValidHostname(within) {
			return zero, fmt.Errorf("%q is not a valid domain", within)
		}
	}

	lower := strings.ToLower(rest)
	switch {
	case strings.HasPrefix(rest, "re:") || strings.HasPrefix(lower, "regex:"):
		pattern := strings.TrimSpace(rest[strings.Index(rest, ":")+1:])
		if err := ValidateScopeRegex(pattern); err != nil {
			return zero, err
		}
		return finishRule(ScopeRule{
			Effect: effect, Kind: KindRegex, Value: StripRegexAnchors(pattern), Within: within,
		})

	case strings.HasPrefix(rest, "~") || strings.HasPrefix(lower, "contains:"):
		var value string
		if strings.HasPrefix(rest, "~") {
			value = rest[1:]
		} else {
			value = rest[strings.Index(rest, ":")+1:]
		}
		value = strings.ToLower(strings.TrimSpace(value))
		if err := ValidateScopeContains(value); err != nil {
			return zero, err
		}
		return finishRule(ScopeRule{Effect: effect, Kind: KindContains, Value: value, Within: within})
	}

	if within != "" {
		return zero, fmt.Errorf(`"within" applies only to ~contains and re: rules`)
	}

	switch {
	case strings.HasPrefix(rest, "="):
		return hostShapedRule(effect, KindHost, rest[1:])
	case strings.HasPrefix(rest, "*."):
		return hostShapedRule(effect, KindSubdomains, rest[2:])
	default:
		// Bare host. Unchanged meaning: this host and every subdomain of it.
		return hostShapedRule(effect, KindSubtree, rest)
	}
}

func hostShapedRule(effect ScopeEffect, kind ScopeKind, text string) (ScopeRule, error) {
	var zero ScopeRule
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return zero, fmt.Errorf("missing host")
	}

	// Reuse the subject normaliser so a rule value and a subject can never normalise differently.
	auth, ok := NormalizeAuthority(trimmed, "")
	if !ok {
		return zero, fmt.Errorf("%q is not a valid host", trimmed)
	}
	if auth.IsIP && kind != KindHost {
		// An address has no subdomains and no subtree. Silently accepting *.10.0.0.18 is how
		// "10.0.0.18" once became "0.18".
		return zero, fmt.Errorf("an IP address has no subdomains; use =%s", auth.Host)
	}
	return finishRule(ScopeRule{
		Effect: effect, Kind: kind, Value: auth.Host, Port: auth.Port, IsIP: auth.IsIP,
	})
}

func finishRule(r ScopeRule) (ScopeRule, error) {
	r.Enabled = true
	r.Blast = ClassifyBlast(r)
	if r.Kind == KindRegex {
		compiled, err := regexp.Compile(`\A(?:` + r.Value + `)\z`)
		if err != nil {
			return ScopeRule{}, fmt.Errorf("regex does not compile: %w", err)
		}
		r.compiled = compiled
	}
	return r, nil
}

// ClassifyBlast answers: how much of the internet could this admit that nobody has seen yet?
//
// A deny is always narrow. Narrowing the boundary is always permitted, and an emergency exclusion
// must never be held behind a confirmation step.
func ClassifyBlast(r ScopeRule) ScopeBlast {
	if r.Effect == EffectDeny {
		return BlastNarrow
	}
	switch r.Kind {
	case KindHost:
		return BlastNarrow
	case KindContains, KindRegex:
		if r.Within != "" {
			return BlastBounded
		}
		return BlastWide
	default:
		return BlastBounded
	}
}

func ValidateScopeContains(value string) error {
	if value == "" {
		return fmt.Errorf("contains needs a value")
	}
	if len(value) < containsMinLength {
		return fmt.Errorf("%q is too short; a contains rule needs at least %d characters",
			value, containsMinLength)
	}
	hasAlnum := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			hasAlnum = true
		case c == '.' || c == '-':
		default:
			return fmt.Errorf("contains allows only letters, digits, dot and hyphen")
		}
	}
	if !hasAlnum {
		return fmt.Errorf("contains needs at least one letter or digit")
	}
	if containsHazards[value] {
		return fmt.Errorf("%q appears in a large share of all hostnames; narrow it or add \"within <domain>\"", value)
	}
	return nil
}

var (
	reRegexClasses = regexp.MustCompile(`\\[sSbBpPk]`)
	reRegexLook    = regexp.MustCompile(`\(\?[=!<]`)
	reRegexNamed   = regexp.MustCompile(`\(\?P?<`)
	reRegexBackref = regexp.MustCompile(`\\[1-9]`)
	reRegexRepeat  = regexp.MustCompile(`\{(\d+)(?:,(\d*))?\}`)
	reRegexUpper   = regexp.MustCompile(`[A-Z]`)
	reRegexAnchor  = regexp.MustCompile(`[^\\]\$|^\$|[^\\]\^|^\^`)
	reRegexFlags   = regexp.MustCompile(`\(\?[a-z]*[):]`)
	reRegexNonCap  = regexp.MustCompile(`\(\?:`)
)

// ValidateScopeRegex is a whitelist, not a blacklist: a construct nobody thought about cannot
// arrive by default.
func ValidateScopeRegex(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("regex needs a pattern")
	}
	if len(pattern) > regexMaxLength {
		return fmt.Errorf("regex is longer than %d characters", regexMaxLength)
	}
	body := StripRegexAnchors(pattern)

	if reRegexUpper.MatchString(body) {
		return fmt.Errorf("regex must be lowercase; the host is lowercased before matching")
	}
	// \s and \S differ between V8 and RE2: V8 matches U+00A0 and U+3000, RE2 does not. A rule that
	// means different things in the two evaluators is exactly the failure this design prevents, so
	// the construct is refused rather than approximated.
	if reRegexClasses.MatchString(body) {
		return fmt.Errorf(`regex may not use \s, \S, \b, \B, \p or \k`)
	}
	if reRegexLook.MatchString(body) {
		return fmt.Errorf("regex may not use lookahead or lookbehind")
	}
	if reRegexNamed.MatchString(body) {
		return fmt.Errorf("regex may not use named groups")
	}
	if reRegexFlags.MatchString(body) && !reRegexNonCap.MatchString(body) {
		return fmt.Errorf("regex may not set inline flags")
	}
	if reRegexBackref.MatchString(body) {
		return fmt.Errorf("regex may not use backreferences")
	}
	if reRegexAnchor.MatchString(body) {
		return fmt.Errorf("regex is always a full match; remove the ^ and $")
	}
	for _, token := range reRegexRepeat.FindAllStringSubmatch(body, -1) {
		hi := token[1]
		if len(token) > 2 && token[2] != "" {
			hi = token[2]
		}
		n, err := strconv.Atoi(hi)
		if err == nil && n > regexMaxRepeat {
			return fmt.Errorf("regex repetition {..%d} exceeds the limit of %d", n, regexMaxRepeat)
		}
	}
	if HasNestedQuantifier(body) {
		// Measured: (?:[a-z0-9-]{1,15}){1,15}\.example\.com takes over 100 seconds in V8 against a
		// 60-character non-matching host. The same rule text is evaluated by the extension on every
		// request and by the popup on every keystroke, so this is a syntactic refusal, not a
		// timeout. Go's RE2 would not blow up, but the JS mirror would, and they must agree.
		return fmt.Errorf("regex nests a quantifier inside a quantified group, which can hang the matcher")
	}
	if _, err := regexp.Compile(`\A(?:` + body + `)\z`); err != nil {
		return fmt.Errorf("regex does not compile: %w", err)
	}
	return nil
}

func StripRegexAnchors(pattern string) string {
	out := pattern
	out = strings.TrimPrefix(out, "^")
	if strings.HasSuffix(out, "$") && !strings.HasSuffix(out, `\$`) {
		out = out[:len(out)-1]
	}
	return out
}

// HasNestedQuantifier reports whether any quantifier appears inside a group that is itself
// quantified. Scanned with a stack, because detecting nesting is not something a regex can do.
func HasNestedQuantifier(body string) bool {
	type frame struct{ sawQuantifier bool }
	var stack []frame

	for i := 0; i < len(body); i++ {
		ch := body[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '[' {
			for i < len(body) && body[i] != ']' {
				if body[i] == '\\' {
					i++
				}
				i++
			}
			continue
		}
		if ch == '(' {
			stack = append(stack, frame{})
			continue
		}
		if ch == ')' {
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if i+1 < len(body) {
					next := body[i+1]
					if next == '*' || next == '+' || next == '?' || next == '{' {
						if top.sawQuantifier {
							return true
						}
					}
				}
			}
			continue
		}
		if ch == '*' || ch == '+' || ch == '{' {
			if len(stack) > 0 {
				stack[len(stack)-1].sawQuantifier = true
			}
		}
	}
	return false
}

/* ------------------------------------------------------------------ step B: one rule */

// WithinDomain matches on a label boundary, never on a bare suffix: notexample.com is outside
// example.com. The bare-suffix version of this is the bug the whole model exists to prevent.
func WithinDomain(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// RuleMatches answers whether one rule covers one subject.
func (r *ScopeRule) Matches(subject ScopeAuthority) bool {
	if !r.Enabled {
		return false
	}

	// B2. An unknown port never satisfies a port constraint, for EITHER effect. Letting it satisfy
	// an allow widens the boundary; letting it satisfy a deny over-denies. Both fail closed.
	if r.Port != 0 {
		if subject.Port == 0 || subject.Port != r.Port {
			return false
		}
	}

	if r.Within != "" && !WithinDomain(subject.Host, r.Within) {
		return false
	}

	// B5. An address is never subjected to label arithmetic, and a name never matches an address
	// rule. This makes the "10.0.0.18 becomes 0.18" class structurally impossible.
	if subject.IsIP && r.Kind != KindHost {
		return false
	}
	if r.IsIP && r.Kind == KindHost && !subject.IsIP {
		return false
	}

	switch r.Kind {
	case KindHost:
		return subject.Host == r.Value
	case KindSubtree:
		return WithinDomain(subject.Host, r.Value)
	case KindSubdomains:
		return strings.HasSuffix(subject.Host, "."+r.Value)
	case KindContains:
		return strings.Contains(subject.Host, r.Value)
	case KindRegex:
		if r.compiled == nil {
			// A rule that will not compile fails the target CLOSED rather than being dropped.
			// Dropping would be harmless for an allow and catastrophic for a deny, and nothing here
			// can safely tell which.
			return r.Effect == EffectDeny
		}
		return r.compiled.MatchString(subject.Host)
	}
	return false
}

/* ------------------------------------------------------------------ step C: the verdict */

// Ranking used only to choose WHICH rule to name in the explanation. It never decides whether a
// host is in scope, which is exactly why two hand-written implementations can coexist: a divergence
// here costs a wrong sentence, not a wrong boundary.
var kindRank = map[ScopeKind]int{
	KindHost: 6, KindSubdomains: 4, KindSubtree: 3, KindRegex: 2, KindContains: 1,
}

func pickScopeRule(matching []*ScopeRule) *ScopeRule {
	var best *ScopeRule
	for _, r := range matching {
		if best == nil {
			best = r
			continue
		}
		a, b := kindRank[r.Kind], kindRank[best.Kind]
		if a != b {
			if a > b {
				best = r
			}
			continue
		}
		if len(r.Value) != len(best.Value) {
			if len(r.Value) > len(best.Value) {
				best = r
			}
			continue
		}
		if r.ID < best.ID {
			best = r
		}
	}
	return best
}

// ScopeDecisionInput carries the parts of a decision that are not the rules themselves.
type ScopeDecisionInput struct {
	AdmitObserved bool
	Observed      map[string]bool // "host:port" and/or bare "host"
}

// DecideScope is the whole decision. Deny wins unconditionally; the default is deny.
func DecideScope(rules []ScopeRule, subject ScopeAuthority, ok bool, in ScopeDecisionInput) ScopeVerdict {
	if !ok {
		return ScopeVerdict{Allowed: false, Reason: "unnormalisable"}
	}

	var denies, allows []*ScopeRule
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || !r.Matches(subject) {
			continue
		}
		if r.Effect == EffectDeny {
			denies = append(denies, r)
		} else {
			allows = append(allows, r)
		}
	}

	if len(denies) > 0 {
		return ScopeVerdict{Allowed: false, Rule: pickScopeRule(denies), Reason: "rule_deny"}
	}
	if len(allows) > 0 {
		return ScopeVerdict{Allowed: true, Rule: pickScopeRule(allows), Reason: "rule_allow"}
	}

	if in.AdmitObserved && in.Observed != nil {
		key := subject.Host + ":" + strconv.Itoa(subject.Port)
		if in.Observed[key] || in.Observed[subject.Host] {
			return ScopeVerdict{Allowed: true, Reason: "observed"}
		}
	}

	return ScopeVerdict{Allowed: false, Reason: "default_deny"}
}

// URLInScope is the convenience the capture and scan paths use, which hold a URL rather than a
// parsed authority.
func URLInScope(rawURL string, rules []ScopeRule, in ScopeDecisionInput) bool {
	auth, ok := NormalizeAuthority(rawURL, "")
	return DecideScope(rules, auth, ok, in).Allowed
}

// CompileScopeRules prepares stored rules for evaluation. A rule that fails to compile fails the
// WHOLE target closed, by returning an error: dropping it would be fine for an allow and
// catastrophic for a deny, and the loader cannot safely tell which.
func CompileScopeRules(rules []ScopeRule) ([]ScopeRule, error) {
	out := make([]ScopeRule, len(rules))
	copy(out, rules)
	for i := range out {
		if out[i].Kind != KindRegex {
			continue
		}
		compiled, err := regexp.Compile(`\A(?:` + out[i].Value + `)\z`)
		if err != nil {
			return nil, fmt.Errorf("scope rule %s has an uncompilable pattern %q: %w",
				out[i].ID, out[i].Value, err)
		}
		out[i].compiled = compiled
	}
	return out, nil
}

/* ------------------------------------------------------------------ display */

// RenderScopeRule is the single source of the sentence every surface shows.
//
// A chip reading "example.com" silently means "and every subdomain", which is precisely what an
// operator misreads. No surface renders a bare pattern as the boundary.
func RenderScopeRule(r ScopeRule) string {
	verb := "Allow"
	if r.Effect == EffectDeny {
		verb = "DENY"
	}
	port := ""
	if r.Port != 0 {
		port = fmt.Sprintf(" on port %d only", r.Port)
	}
	within := ""
	if r.Within != "" {
		within = " under " + r.Within
	}

	switch r.Kind {
	case KindHost:
		return fmt.Sprintf("%s %s exactly, not its subdomains%s", verb, r.Value, port)
	case KindSubtree:
		return fmt.Sprintf("%s %s and every subdomain of it%s", verb, r.Value, port)
	case KindSubdomains:
		return fmt.Sprintf("%s every subdomain of %s, but not %s itself%s", verb, r.Value, r.Value, port)
	case KindContains:
		if within == "" {
			within = " anywhere"
		}
		return fmt.Sprintf("%s any host%s whose name contains %q", verb, within, r.Value)
	case KindRegex:
		return fmt.Sprintf("%s any host%s matching /%s/", verb, within, r.Value)
	}
	return fmt.Sprintf("%s %s", verb, r.Value)
}

// CanonicalScopeText is the stored form, and must re-parse to itself.
func CanonicalScopeText(r ScopeRule) string {
	bang := ""
	if r.Effect == EffectDeny {
		bang = "!"
	}
	within := ""
	if r.Within != "" {
		within = " within " + r.Within
	}
	port := ""
	if r.Port != 0 {
		port = ":" + strconv.Itoa(r.Port)
	}
	host := r.Value
	if r.IsIP && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	switch r.Kind {
	case KindHost:
		return bang + "=" + host + port
	case KindSubtree:
		return bang + host + port
	case KindSubdomains:
		return bang + "*." + host + port
	case KindContains:
		return bang + "~" + r.Value + within
	case KindRegex:
		return bang + "re:" + r.Value + within
	}
	return bang + r.Value
}
