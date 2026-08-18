package utils

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Turning one attack vector plus the stored settings into one command line, for any tool.
//
// Separate from the runner so the rules can be tested without a container, because the rules are not
// guessable and every one of them fails OPEN. A tool given the wrong flag does not error: it exits
// 0, reports nothing, and the operator reads a clean result for a vector that was never tested. Each
// rule was established by running the tool against a purpose-built target that wires all five
// insertion points to the same sink, changing one flag at a time.

func truthySetting(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1" || t == "yes"
	case float64:
		return t != 0
	case int:
		return t != 0
	}
	return false
}

// VectorInput is everything the composer needs about one attack vector. A struct rather than the
// database row so this file has no database dependency and can be tested directly.
type VectorInput struct {
	Method         string
	Scheme         string
	Domain         string
	Port           int
	Path           string
	InsertionPoint string
	Parameters     []string
	EvidenceURL    string
	ContentType    string
	Body           string
	// ObservedValues are the values recorded for the vector's parameters, where any were seen.
	ObservedValues map[string]string
	// Run is the sub-scan label, for tools that need more than one invocation per target. Empty for
	// the tools that need only one.
	Run string
	// RawRequestOverride is the recorded request bytes, for the tools that read a saved request from
	// a file rather than taking a URL.
	RawRequestOverride string
	// Section is the settings that belong to the whole section rather than to one tool, which for the
	// open redirect and SSRF section is the webhook pair.
	Section map[string]any
	// Token marks this vector in this scan. It is what turns "the webhook was called" into "the
	// webhook was called BY THIS VECTOR", so a callback names the parameter that produced it.
	Token string
	// ScopeTargetID is needed by the tools whose output is shared across a target rather than being
	// per vector, which is how REcollapse hands its payload list to the scanner.
	ScopeTargetID string
	// VectorID is the row this input came from, so a tool that reports once per vector can attribute
	// what it produced.
	VectorID string
}

// TargetURL rebuilds the URL to scan.
//
// The evidence URL is preferred when it carries a query string, because it is the request as it was
// actually observed and its parameter values are real. When it does not, the URL is rebuilt and a
// canary supplied for each parameter, which matters for more than tidiness: xssFuzz substitutes with
// re.sub("name=([^&]+)") against the URL TEXT, so a parameter that is not physically present in the
// string matches nothing and the tool reports clean.
func (v VectorInput) TargetURL() string {
	if v.InsertionPoint == "query" && strings.Contains(v.EvidenceURL, "?") {
		if merged, ok := v.mergeMissingParams(); ok {
			return merged
		}
	}
	base := v.baseURL()

	// A vector whose payload goes somewhere OTHER than the query string still keeps the query string
	// it was observed with. Endpoints routinely need it: ?action=view&id=5 selects what the handler
	// does, and dropping it sends a request the application answers differently, or not at all.
	//
	// Measured: a cookie vector on /index.php?point=cookie lost its query, the target read the wrong
	// input, and LFImap reported nothing on a cookie it finds in a second when the URL is intact.
	if v.InsertionPoint != "query" {
		if parsed, err := url.Parse(v.EvidenceURL); err == nil && parsed.RawQuery != "" {
			return base + "?" + parsed.RawQuery
		}
		return base
	}
	if len(v.Parameters) == 0 {
		return base
	}
	q := url.Values{}
	for _, name := range v.Parameters {
		q.Set(name, v.valueFor(name))
	}
	return base + "?" + q.Encode()
}

// mergeMissingParams keeps the observed query string and adds any of the vector's parameters that
// are absent from it. A vector often names parameters discovered by Arjun or x8 that the recorded
// request never carried; dropping them would scan a subset of what the row claims to cover.
func (v VectorInput) mergeMissingParams() (string, bool) {
	parsed, err := url.Parse(v.EvidenceURL)
	if err != nil {
		return "", false
	}
	q := parsed.Query()
	for _, name := range v.Parameters {
		if q.Get(name) == "" {
			q.Set(name, v.valueFor(name))
		}
	}
	parsed.RawQuery = q.Encode()
	return parsed.String(), true
}

func (v VectorInput) valueFor(name string) string {
	if got := strings.TrimSpace(v.ObservedValues[name]); got != "" {
		return got
	}
	// Case insensitively too, because header names are case insensitive on the wire. A value
	// recorded against "Referer" and looked up as "referer" would otherwise fall through to the
	// canary, and replacing a real header value with rs0n changes the request being tested.
	for stored, value := range v.ObservedValues {
		if strings.EqualFold(stored, name) {
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}
	return VectorCanary
}

func (v VectorInput) baseURL() string {
	scheme := v.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := v.Domain
	if v.Port != 0 && !((scheme == "https" && v.Port == 443) || (scheme == "http" && v.Port == 80)) {
		host = fmt.Sprintf("%s:%d", host, v.Port)
	}
	path := v.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + "://" + host + path
}

// ComposeDalfox builds the dalfox argv for one vector.
//
// The two rules that are not guessable, both measured by isolating a single flag:
//
//   - A HEADER target must NOT also be passed with -H. `-p X:header` finds the bug; adding
//     `-H 'X: value'` for the same name suppresses it completely. Auth headers with other names are
//     unaffected, so the target header is dropped from the user's list rather than the list being
//     discarded.
//   - A COOKIE target MUST also be passed with --cookies. `-p sid:cookie` on its own finds nothing;
//     with `--cookies sid=value` it finds the bug. A cookie of a different name does not help.
//
// They are exact opposites, which is why doing the same thing for both loses one of them.
// composeVectorSettings turns the stored settings into flags, using the tool's own vocabulary.
//
// Driven entirely by VectorOptionMeta, so a flag added to a vocabulary is emitted here without
// this function changing. Keys are emitted in sorted order so a command line is reproducible and
// a test can assert on it.
func composeVectorSettings(tool VectorTool, settings map[string]any, suppressedHeader string,
	skipKeys map[string]bool, warnings *[]string) []string {
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var args []string
	for _, key := range keys {
		if skipKeys[key] {
			// The composer emitted this itself, with the target marked. Emitting it again here
			// would put two --cookie flags on the command line and the second would win.
			continue
		}
		meta, known := tool.Options[key]
		if !known {
			// Reported rather than dropped. A misspelled key that vanishes silently is how an operator
			// comes to believe a setting is in force.
			*warnings = append(*warnings, "Ignored unknown "+tool.Name+" setting "+key+".")
			continue
		}
		value := settings[key]
		if value == nil {
			continue
		}

		switch meta.Kind {
		case "bool":
			if truthySetting(value) {
				args = append(args, meta.Flag)
			}
		case "int", "float":
			text := stringifySetting(value)
			if text != "" {
				args = append(args, meta.Flag, text)
			}
		default:
			for _, item := range settingValues(value) {
				if item == "" {
					continue
				}
				// The header the scan is aiming at, dropped from the user's auth headers. Passing it
				// alongside -p <name>:header suppresses the finding entirely.
				if suppressedHeader != "" && meta.Flag == "-H" && headerNameOf(item) == suppressedHeader {
					*warnings = append(*warnings, "Dropped your "+item[:min(len(item), 40)]+
						" header for this vector: dalfox reports nothing for a header that is both "+
						"supplied with -H and targeted with -p.")
					continue
				}
				args = append(args, meta.Flag, item)
			}
		}
	}
	return args
}

// headerNameOf reads the name out of a "Name: value" header setting.
func headerNameOf(header string) string {
	name, _, _ := strings.Cut(header, ":")
	return strings.ToLower(strings.TrimSpace(name))
}

// settingValues normalises one setting into the list of values to emit. A repeatable option stored
// as a JSON array becomes one flag occurrence per element; joining them with commas would produce a
// single header whose value contains a comma.
func settingValues(value any) []string {
	switch t := value.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, stringifySetting(item))
		}
		return out
	case []string:
		return t
	}
	return []string{stringifySetting(value)}
}

func stringifySetting(value any) string {
	switch t := value.(type) {
	case string:
		return strings.TrimSpace(t)
	case bool:
		return strconv.FormatBool(t)
	case float64:
		// JSON has one number type, so an int arrives as a float. 50 must not become "50.000000",
		// which ffuf and dalfox both reject as a parse error.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case nil:
		return ""
	}
	return fmt.Sprintf("%v", value)
}

// rawRequestBody pulls the content type and the body out of a stored raw request.
//
// The content type is what decides between -p name:body, -p name:json and -p name:multipart. Getting
// it wrong is not a syntax error: a JSON body injected as form-encoded produces a request the server
// rejects or ignores, and the scan reports clean.
//
// Both line endings are handled because the two sources of raw requests in this framework disagree.
// The manual crawl extension records real wire bytes with CRLF; a request typed into the Add
// Manually modal has whatever the textarea produced, which is LF.
func rawRequestBody(raw string) (contentType, body string) {
	text := strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, _ := strings.Cut(text, "\n\n")
	for _, line := range strings.Split(head, "\n")[1:] {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "content-type") {
			contentType = strings.TrimSpace(value)
			break
		}
	}
	return contentType, strings.TrimSpace(body)
}

// observedQueryValues reads the parameter values a recorded URL actually carried.
//
// A real value is preferred over the canary because it keeps the request shaped the way the
// application expects. Swapping a numeric id for the word rs0n can turn a 200 into a 400, and a 400
// reflects nothing, so the scan of that parameter finds nothing for a reason that has no bearing on
// whether the parameter is injectable.
func observedQueryValues(rawURL string) map[string]string {
	out := map[string]string{}
	if rawURL == "" {
		return out
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return out
	}
	for name, values := range parsed.Query() {
		if len(values) > 0 && strings.TrimSpace(values[0]) != "" {
			out[name] = values[0]
		}
	}
	return out
}


// observedRequestValues reads the value of a cookie or header out of the recorded raw request.
//
// It matters because the marker is appended to a VALUE. A cookie vector whose value is unknown gets
// the canary, so the request goes out as Cookie: session=rs0n*, and an application that checks its
// session answers 401 to every payload. A 401 injects nothing, the scan reports clean, and nothing
// anywhere says the reason was that we threw the session away.
func observedRequestValues(raw, insertionPoint string) map[string]string {
	out := map[string]string{}
	if raw == "" || (insertionPoint != "cookie" && insertionPoint != "header") {
		return out
	}
	text := strings.ReplaceAll(raw, "\r\n", "\n")
	head, _, _ := strings.Cut(text, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) < 2 {
		return out
	}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if insertionPoint == "header" {
			out[name] = value
			continue
		}
		if !strings.EqualFold(name, "cookie") {
			continue
		}
		for _, pair := range strings.Split(value, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if ok {
				out[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return out
}
