package utils

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Carrying a value out of one step's response and into a later step's request.
//
// Without this, an auth flow can only replay applications that have no per-request CSRF token, which
// is very few of them. Measured against ginandjuice.shop: POST /login with no csrf answers
// 400 "Missing parameter 'csrf'", and with a stale one 400 "Invalid CSRF token", so the token is
// bound to the session that issued it. A replay already shares one cookie jar across steps, so the
// SESSION carries; the token does not, because a step is stored as opaque text and sent verbatim.
//
// So a replay now holds a second piece of cross-step state beside the jar: a string map, filled by
// per-step extraction rules and consumed by placeholder substitution over the raw request.

// authFlowVarPattern matches {{af:NAME}} with an optional encoding modifier.
//
// The five-byte {{af: prefix is deliberate. Bare {{NAME}} collides with Handlebars, Vue and Angular,
// and in this codebase specifically with the SSTI payloads the framework itself fires ({{7*7}});
// ${NAME} collides with JS template literals and with ${jndi:...}. Restricting the name to
// [A-Za-z0-9_] means no JSON, no base64, no URL-encoded form value and no template expression can
// match one by accident. There is no escape sequence for a literal {{af:NAME}}, because that is not
// a byte sequence a real request carries.
var authFlowVarPattern = regexp.MustCompile(`\{\{af:([A-Za-z0-9_]{1,64})(?:\|(raw|url|json))?\}\}`)

// AuthFlowExtraction captures one value out of a step's response.
type AuthFlowExtraction struct {
	Name    string `json:"name"`
	Source  string `json:"source"`               // body | header | cookie
	Key     string `json:"source_key,omitempty"` // the header or cookie name
	Pattern string `json:"pattern,omitempty"`    // RE2; capture group 1 is the value
	Decode  string `json:"decode_as,omitempty"`
	// Optional, NOT Required, so the zero value is the safe one. A rule decoded from JSON without
	// this field is treated as required, and a required rule that matches nothing refuses every
	// step that needs its value rather than sending a literal {{af:NAME}} at the target.
	Optional bool `json:"optional,omitempty"`
}

// ExtractionOutcome is what one rule did on one replay, reported back per step.
type ExtractionOutcome struct {
	Name    string `json:"name"`
	Matched bool   `json:"matched"`
	Value   string `json:"value,omitempty"`
	Problem string `json:"problem,omitempty"`
}

const extractionValuePreview = 512

// validateAuthFlowExtraction rejects a rule at save time rather than at replay time, because a rule
// that cannot work is far cheaper to explain while the operator is still looking at it.
func validateAuthFlowExtraction(rule AuthFlowExtraction) string {
	if strings.TrimSpace(rule.Name) == "" {
		return "a capture needs a name, which is what a later step refers to as {{af:NAME}}"
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(rule.Name) {
		return fmt.Sprintf("%q is not a usable capture name: use letters, digits and underscore, "+
			"because that is what {{af:NAME}} accepts", rule.Name)
	}
	switch rule.Source {
	case "body", "header", "cookie":
	case "":
		return "a capture needs a source: body, header or cookie"
	default:
		return fmt.Sprintf("%q is not a capture source; use body, header or cookie", rule.Source)
	}
	if (rule.Source == "header" || rule.Source == "cookie") && strings.TrimSpace(rule.Key) == "" {
		return fmt.Sprintf("a %s capture needs the %s name in source_key", rule.Source, rule.Source)
	}
	if rule.Source == "body" && strings.TrimSpace(rule.Pattern) == "" {
		return "a body capture needs a pattern, with the value in capture group 1, " +
			`for example name="csrf" value="([^"]+)"`
	}
	if rule.Pattern != "" {
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Sprintf("pattern does not compile: %v", err)
		}
		if compiled.NumSubexp() < 1 {
			return "pattern has no capture group, so there is nothing to take: put the value in " +
				"parentheses, for example name=\"csrf\" value=\"([^\"]+)\""
		}
	}
	switch rule.Decode {
	case "", "none", "html", "url":
	default:
		return fmt.Sprintf("%q is not a decoding; use none, html or url", rule.Decode)
	}
	return ""
}

// decodeExtracted applies the rule's decoding.
//
// The default is none, and that matters. Go's html.UnescapeString decodes the LEGACY entity set
// without requiring a trailing semicolon, so "abc&param=1" becomes "abc¶m=1" and "a&notb" becomes
// "a¬b". Captured values are very often URL shaped (an OAuth authorize or redirect URL, a SAML
// RelayState), and those are exactly the values full of &param=. Decoding by default would corrupt
// them silently, so it is opt in.
func decodeExtracted(value, decode string) string {
	switch decode {
	case "html":
		return html.UnescapeString(value)
	case "url":
		if unescaped, err := url.QueryUnescape(value); err == nil {
			return unescaped
		}
		return value
	default:
		return value
	}
}

// runAuthFlowExtractions applies a step's rules to the response it just produced.
func runAuthFlowExtractions(rules []AuthFlowExtraction, headers map[string][]string, body string) (map[string]string, []ExtractionOutcome) {
	values := map[string]string{}
	outcomes := make([]ExtractionOutcome, 0, len(rules))

	for _, rule := range rules {
		outcome := ExtractionOutcome{Name: rule.Name}

		if problem := validateAuthFlowExtraction(rule); problem != "" {
			outcome.Problem = problem
			outcomes = append(outcomes, outcome)
			continue
		}

		var haystacks []string
		switch rule.Source {
		case "body":
			haystacks = []string{body}
		case "header":
			haystacks = headerValuesFor(headers, rule.Key)
		case "cookie":
			haystacks = setCookieValuesFor(headers, rule.Key)
		}

		if len(haystacks) == 0 {
			outcome.Problem = fmt.Sprintf("no %s named %q in the response", rule.Source, rule.Key)
			outcomes = append(outcomes, outcome)
			continue
		}

		matched := ""
		found := false
		for _, haystack := range haystacks {
			if rule.Pattern == "" {
				// A header or cookie with no pattern means the whole value.
				matched, found = haystack, true
				break
			}
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				break
			}
			if groups := compiled.FindStringSubmatch(haystack); groups != nil && len(groups) > 1 {
				matched, found = groups[1], true
				break
			}
		}

		if !found {
			outcome.Problem = fmt.Sprintf("pattern did not match the %s", rule.Source)
			if rule.Source == "body" {
				outcome.Problem += fmt.Sprintf(" (%d bytes searched)", len(body))
			}
			outcomes = append(outcomes, outcome)
			continue
		}

		value := decodeExtracted(matched, rule.Decode)
		values[rule.Name] = value
		outcome.Matched = true
		outcome.Value = truncateForPreview(value, extractionValuePreview)
		outcomes = append(outcomes, outcome)
	}

	return values, outcomes
}

func truncateForPreview(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

func headerValuesFor(headers map[string][]string, name string) []string {
	want := strings.ToLower(strings.TrimSpace(name))
	for key, values := range headers {
		if strings.ToLower(key) == want {
			return values
		}
	}
	return nil
}

// setCookieValuesFor pulls one cookie's value out of the response's Set-Cookie lines.
//
// This is the double-submit case: the token is handed over as a cookie and has to be echoed back in
// a header or a form field, so it has to be readable as a value rather than only ride in the jar.
func setCookieValuesFor(headers map[string][]string, name string) []string {
	want := strings.TrimSpace(name)
	var out []string
	for _, line := range headerValuesFor(headers, "Set-Cookie") {
		parsed := (&http.Response{Header: http.Header{"Set-Cookie": []string{line}}}).Cookies()
		for _, cookie := range parsed {
			if cookie.Name == want {
				out = append(out, cookie.Value)
			}
		}
	}
	return out
}

// authFlowVarNames lists the placeholders a raw request refers to.
func authFlowVarNames(raw string) []string {
	seen := map[string]bool{}
	var names []string
	for _, match := range authFlowVarPattern.FindAllStringSubmatch(raw, -1) {
		if seen[match[1]] {
			continue
		}
		seen[match[1]] = true
		names = append(names, match[1])
	}
	return names
}

// substituteAuthFlowVars replaces every placeholder with the value an earlier step captured.
//
// Returns unresolved names rather than substituting an empty string. A step that quietly sends a
// blank csrf produces a 400 the operator then debugs at the target; a step that refuses to send says
// which capture did not fire.
func substituteAuthFlowVars(raw string, vars map[string]string) (out string, used []string, unresolved []string) {
	if !strings.Contains(raw, "{{af:") {
		return raw, nil, nil
	}

	head, sep, body := splitRawRequestHeadBody(raw)
	bodyEncoding := defaultBodyEncoding(head)

	seenUsed := map[string]bool{}
	seenMissing := map[string]bool{}

	replace := func(section string, inBody bool) string {
		return authFlowVarPattern.ReplaceAllStringFunc(section, func(token string) string {
			groups := authFlowVarPattern.FindStringSubmatch(token)
			name, encoding := groups[1], groups[2]

			value, ok := vars[name]
			if !ok {
				if !seenMissing[name] {
					seenMissing[name] = true
					unresolved = append(unresolved, name)
				}
				return token
			}

			if encoding == "" {
				// Chosen from where the placeholder sits. A token dropped raw into a form body
				// breaks the body the moment it contains & or =, and into a JSON body the moment it
				// contains a quote. Both are silent: the request goes out malformed and the target
				// answers with something that looks like an application error.
				if inBody {
					encoding = bodyEncoding
				} else {
					encoding = "raw"
				}
			}

			if !seenUsed[name] {
				seenUsed[name] = true
				used = append(used, name)
			}
			return encodeAuthFlowValue(value, encoding)
		})
	}

	if sep == "" {
		return replace(raw, false), used, unresolved
	}
	return replace(head, false) + sep + replace(body, true), used, unresolved
}

func encodeAuthFlowValue(value, encoding string) string {
	switch encoding {
	case "url":
		return url.QueryEscape(value)
	case "json":
		encoded, err := json.Marshal(value)
		if err != nil {
			return value
		}
		// Marshal wraps it in quotes; the placeholder already sits inside them.
		return strings.Trim(string(encoded), `"`)
	default:
		return value
	}
}

// defaultBodyEncoding reads the Content-Type so a substituted value lands correctly framed.
func defaultBodyEncoding(head string) string {
	lower := strings.ToLower(head)
	switch {
	case strings.Contains(lower, "application/x-www-form-urlencoded"):
		return "url"
	case strings.Contains(lower, "application/json"):
		return "json"
	default:
		return "raw"
	}
}

// splitRawRequestHeadBody splits on the first blank line, honouring either framing, and hands back
// the separator so the caller can rebuild the request without changing how it was framed.
func splitRawRequestHeadBody(raw string) (head, sep, body string) {
	crlf := strings.Index(raw, "\r\n\r\n")
	lf := strings.Index(raw, "\n\n")
	switch {
	case crlf >= 0 && (lf < 0 || crlf <= lf):
		return raw[:crlf], "\r\n\r\n", raw[crlf+4:]
	case lf >= 0:
		return raw[:lf], "\n\n", raw[lf+2:]
	default:
		return raw, "", ""
	}
}

// refreshContentLength rewrites the Content-Length header to match the body actually present, and
// touches nothing else.
//
// Deliberately NOT normalizeRawRequest, which is the obvious thing to reach for and is wrong here.
// That function replaces every \r\n in the WHOLE string, body included, and then recomputes the
// length from the shortened bytes: self-consistent and corrupt. An imported step replays byte-exact
// today because BuildRawHTTPRequest writes CRLF framing and the body verbatim, and running the full
// normalizer over a multipart body would rewrite every boundary CRLF to LF. Substitution changes the
// body's LENGTH, so only the header describing that length needs to move.
func refreshContentLength(raw string) string {
	head, sep, body := splitRawRequestHeadBody(raw)
	if sep == "" {
		return raw
	}

	eol := "\n"
	if strings.Contains(head, "\r\n") {
		eol = "\r\n"
	}

	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	kept := make([]string, 0, len(lines)+1)
	chunked := false
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "content-length:") {
			continue // recomputed below
		}
		if strings.HasPrefix(lower, "transfer-encoding:") && strings.Contains(lower, "chunked") {
			chunked = true
		}
		kept = append(kept, line)
	}
	if body != "" && !chunked {
		kept = append(kept, fmt.Sprintf("Content-Length: %d", len(body)))
	}

	return strings.Join(kept, eol) + sep + body
}

// prepareStepRequest is the whole per-step transform: substitute, then make the framing honest.
//
// Returns a reason instead of a request when a placeholder has no value, so the caller can record
// the step as not sent rather than firing a literal {{af:csrf}} at the target.
func prepareStepRequest(raw string, vars map[string]string) (string, []string, string) {
	out, used, unresolved := substituteAuthFlowVars(raw, vars)
	if len(unresolved) > 0 {
		return "", used, fmt.Sprintf(
			"not sent: no captured value for %s. Add a capture to an earlier step that produces it, "+
				"or check that step's capture actually matched.",
			strings.Join(asPlaceholders(unresolved), ", "))
	}
	if len(used) == 0 {
		// Nothing was rewritten, so the stored bytes are what the operator recorded. Leave them
		// exactly as they are.
		return raw, nil, ""
	}
	return refreshContentLength(out), used, ""
}

func asPlaceholders(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, "{{af:"+name+"}}")
	}
	return out
}
