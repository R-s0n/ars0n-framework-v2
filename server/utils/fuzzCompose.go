package utils

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Turning a marked raw request into the exact bytes and argv a tool will run.
//
// ONE function renders, and both the preview and the executor call it. That is the whole reason
// this file exists separately from the runner: every time this codebase has described "what will be
// sent" from a second copy of the logic, the description drifted from reality and became a
// confident account of a scan that never happened.
//
// The stored request carries neutral {{pN}} tokens rather than a tool's own marker syntax, because
// ffuf has TWO incompatible dialects and the operator should not have to rewrite the request to
// change mode:
//   - clusterbomb and pitchfork bind one wordlist per NAMED KEYWORD (-w file:KEYWORD)
//   - sniper uses §...§ PAIRS, takes exactly one wordlist, and sends the text BETWEEN the marks at
//     every position it is not currently fuzzing
//
// Verified against ffuf v2.2.1 (its banner says 2.1.0-dev; the version constant was never bumped).

// fuzzTokenRe matches the neutral position token. Zero padded to two digits so no token is a prefix
// of another: ffuf substitutes with a plain strings.ReplaceAll, so a keyword that is a prefix of a
// longer one would corrupt it.
var fuzzTokenRe = regexp.MustCompile(`\{\{p(\d{1,2})\}\}`)

const (
	// maxFuzzPositions keeps the two-digit token guarantee true.
	maxFuzzPositions = 99
	// fuzzRequestCeiling is the point past which a run has to be acknowledged rather than started.
	// clusterbomb multiplies, so four positions against a 5000 word list is 6.25e14 requests and
	// ffuf will begin without complaint.
	fuzzRequestCeiling = 250000
)

type FuzzPosition struct {
	ID           string `json:"id"`
	Token        string `json:"token"`
	Ordinal      int    `json:"ordinal"`
	Role         string `json:"role"`
	RestingValue string `json:"resting_value"`
	Wordlist     string `json:"wordlist"`
	Encoder      string `json:"encoder"`
}

type FuzzStep struct {
	ID         string         `json:"id"`
	FlowID     string         `json:"flow_id"`
	Ordinal    int            `json:"ordinal"`
	Tool       string         `json:"tool"`
	Name       string         `json:"name"`
	Enabled    bool           `json:"enabled"`
	RawRequest string         `json:"raw_request"`
	Scheme     string         `json:"scheme"`
	Port       int            `json:"port,omitempty"`
	TargetHost string         `json:"target_host"`
	FFUFMode   string         `json:"ffuf_mode"`
	X8Place    string         `json:"x8_place"`
	Options    map[string]any `json:"options"`
	Positions  []FuzzPosition `json:"positions"`
}

// keywordFor is the ffuf keyword a token becomes in clusterbomb and pitchfork mode.
func keywordFor(n int) string { return fmt.Sprintf("FUZZP%02d", n) }

// keywordForToken derives the keyword from the token's OWN number rather than its position in the
// document. {{p02}} becoming FUZZP01 because it happens to appear first is technically consistent
// and reads like a bug every time an operator compares the request to the command.
func keywordForToken(token string) string {
	m := fuzzTokenRe.FindStringSubmatch(token)
	if len(m) < 2 {
		return "FUZZP00"
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 0 || n > maxFuzzPositions {
		return "FUZZP00"
	}
	return keywordFor(n)
}

// HostFromRawRequest reads the Host header out of a raw request.
//
// This is the single most safety-relevant function in the composer. BOTH tools take their
// connection target from this line, not from any URL the framework holds, and the raw text is
// exactly what the operator is handed to edit. So the Host line is a scope escape hatch by
// construction and has to be re-read from the FINAL rendered bytes before anything is sent.
func HostFromRawRequest(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break // end of headers
		}
		if i := strings.Index(line, ":"); i > 0 {
			if strings.EqualFold(strings.TrimSpace(line[:i]), "host") {
				host := strings.TrimSpace(line[i+1:])
				// Strip a port so the value compares against the scope boundary, which holds bare
				// hosts. InvestigationHostExpr does the same thing in SQL for the same reason.
				if h, _, ok := strings.Cut(host, ":"); ok {
					return strings.ToLower(h)
				}
				return strings.ToLower(host)
			}
		}
	}
	return ""
}

// FuzzRequestTargetErrors returns every reason the DESTINATION of a raw request cannot be
// established unambiguously.
//
// This is a scope-boundary check, not a tidiness check. HostFromRawRequest reads the Host header and
// the scope filter trusts it, but ffuf does not always use it, and both divergences were reproduced
// against ffuf 2.2.1 with two local hosts:
//
//   - An ABSOLUTE-FORM request line wins outright. "GET http://other:8099/q HTTP/1.1" with
//     "Host: allowed:8098" sent every request to `other` and none to `allowed`. The framework had
//     checked `allowed`, said yes, and the traffic went somewhere it had never authorised.
//   - A DUPLICATE Host header resolves to the LAST one, while HostFromRawRequest returns the first.
//     Same result: checked one host, contacted another.
//
// Both are refused rather than reinterpreted. Mirroring ffuf's precedence would make the boundary
// depend on matching another program's parser exactly, and this file's own header comment explains
// why the Host line is treated as an escape hatch by construction. A step that wants a different host
// says so in its Host header, where the check can see it.
func FuzzRequestTargetErrors(raw string) []string {
	var errs []string

	line, _, _ := strings.Cut(raw, "\n")
	fields := strings.Fields(strings.TrimRight(line, "\r"))
	switch {
	case len(fields) < 2:
		errs = append(errs, "The first line is not a request line, so there is no method and no path "+
			"to send. It should look like: GET /path HTTP/1.1")
	case strings.Contains(fields[1], "://"):
		errs = append(errs, fmt.Sprintf(
			"The request line names an absolute URL (%s). ffuf sends to THAT host and ignores the Host "+
				"header, so the scope check would be validating one host while the requests went to "+
				"another. Write the path only, and put the destination in the Host header.", fields[1]))
	case !strings.HasPrefix(fields[1], "/"):
		errs = append(errs, fmt.Sprintf(
			"The request target %q does not begin with /, so it would be appended to the hostname "+
				"rather than requested as a path.", fields[1]))
	}

	hosts := 0
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimRight(l, "\r")
		if l == "" {
			break // end of headers
		}
		if i := strings.Index(l, ":"); i > 0 &&
			strings.EqualFold(strings.TrimSpace(l[:i]), "host") {
			hosts++
		}
	}
	if hosts > 1 {
		errs = append(errs, fmt.Sprintf(
			"There are %d Host headers. The scope check reads the first and ffuf connects to the last, "+
				"so the request would go somewhere that was never checked. Keep exactly one.", hosts))
	}
	return errs
}

// unsupportedFuzzOptionErrors refuses the options that ffuf cannot honour in this mode.
//
// Refusing beats ignoring. An operator who sets extensions and is not told gets a quarter of the
// coverage they asked for and no hint that anything went wrong, which is worse than a step that will
// not start.
func unsupportedFuzzOptionErrors(opts map[string]any) []string {
	var errs []string
	if v, ok := opts["extensions"].(string); ok && strings.TrimSpace(v) != "" {
		errs = append(errs, "extensions is set, but ffuf applies -e to its own FUZZ keyword and this "+
			"step's positions are named FUZZP01 upward, so the extensions would be dropped and the step "+
			"would send a fraction of the requests you asked for. Put the variants in the wordlist as "+
			"separate entries, for example main.js and main.js.map.")
	}
	if v, ok := opts["recursion"].(bool); ok && v {
		errs = append(errs, "recursion is set, but ffuf requires the URL to end with its FUZZ keyword "+
			"for recursion and this step sends a raw request file, so ffuf refuses and exits 0. Add a "+
			"second step against the directory you want to descend into.")
	}
	if s, ok := opts["recursionStrategy"].(string); ok && strings.TrimSpace(s) != "" {
		errs = append(errs, "recursionStrategy is set, but it only has meaning together with recursion, "+
			"which this composer cannot run.")
	}
	if v, ok := opts["dirsearchMode"].(bool); ok && v {
		errs = append(errs, "dirsearchMode is set, but ffuf's -D only has meaning together with -e, "+
			"which this composer cannot use: extensions apply to ffuf's own FUZZ keyword and these "+
			"positions are named FUZZP01 upward.")
	}
	// -input-cmd REPLACES the wordlists. A step that set it would run with none of the wordlists
	// configured on its positions and a request count taken from -input-num, while the preview, the
	// estimate and the position list all still described the wordlists.
	for _, key := range []string{"inputCmd", "inputNum", "inputShell"} {
		if v, present := opts[key]; present && v != nil && v != "" && v != false {
			errs = append(errs, key+" is set, but ffuf's -input-cmd overrides -w entirely, so this "+
				"step's positions and their wordlists would silently not be used and its request count "+
				"would come from somewhere the preview cannot see.")
			break
		}
	}
	return errs
}

// classifyPositionRole says which part of the request a token sits in.
//
// ffuf itself only knows four containers, because substitution is one ReplaceAll per container
// (pkg/runner/simple.go): method, headers (name and value), URL, body. The finer roles below are
// for the operator's benefit; a cookie position IS a header position as far as the tool is
// concerned, and a path position IS a URL position.
func classifyPositionRole(raw, token string) string {
	idx := strings.Index(raw, token)
	if idx < 0 {
		return "missing"
	}

	headerEnd := strings.Index(raw, "\n\n")
	if crlf := strings.Index(raw, "\r\n\r\n"); crlf >= 0 && (headerEnd < 0 || crlf < headerEnd) {
		headerEnd = crlf
	}
	if headerEnd >= 0 && idx > headerEnd {
		return "body_value"
	}

	lineStart := strings.LastIndex(raw[:idx], "\n") + 1
	lineEnd := strings.Index(raw[idx:], "\n")
	if lineEnd < 0 {
		lineEnd = len(raw)
	} else {
		lineEnd += idx
	}
	line := raw[lineStart:lineEnd]

	// The request line is first, and holds the method and the URL.
	if lineStart == 0 {
		parts := strings.Fields(line)
		if len(parts) > 0 && strings.Contains(parts[0], token) {
			return "method"
		}
		if len(parts) > 1 && strings.Contains(parts[1], token) {
			if q := strings.Index(parts[1], "?"); q >= 0 && strings.Index(parts[1], token) > q {
				return "query_value"
			}
			return "path"
		}
		return "request_line"
	}

	colon := strings.Index(line, ":")
	if colon < 0 {
		return "raw"
	}
	name := strings.TrimSpace(line[:colon])
	if idx-lineStart < colon {
		return "header_name"
	}
	if strings.EqualFold(name, "cookie") {
		return "cookie_value"
	}
	return "header_value"
}

// RenderedFuzzStep is everything both the preview and the executor need, produced once.
type RenderedFuzzStep struct {
	Raw         string   `json:"raw"`
	Args        []string `json:"args"`
	Command     string   `json:"command"`
	Host        string   `json:"host"`
	Estimate    int64    `json:"estimated_requests"`
	Warnings    []string `json:"warnings"`
	Errors      []string `json:"errors"`
	Acknowledge bool     `json:"needs_acknowledgement"`
}

// RenderFuzzStep produces the exact request bytes and argv for one step, plus every reason it
// should not run.
//
// Errors are returned as a list rather than one error because an operator fixing a step wants to
// see everything wrong with it at once, not one problem per save.
func RenderFuzzStep(ctx context.Context, step FuzzStep, scope *ScanScope,
	reqFile, outFile string) RenderedFuzzStep {
	return RenderFuzzStepFor(ctx, step, scope, "", reqFile, outFile)
}

// RenderFuzzStepFor is RenderFuzzStep with the scope target, which the credential checks need.
//
// The target is threaded through rather than looked up from the step, because both callers already
// hold it and a second lookup is a second chance to disagree about which target a step belongs to.
func RenderFuzzStepFor(ctx context.Context, step FuzzStep, scope *ScanScope, scopeTargetID,
	reqFile, outFile string) RenderedFuzzStep {

	out := RenderedFuzzStep{Warnings: []string{}, Errors: []string{}}
	mode := strings.ToLower(strings.TrimSpace(step.FFUFMode))
	if mode == "" {
		mode = "clusterbomb"
	}

	// The flow's settings, with this step's own options laid over them. Applied HERE rather than when
	// the step is loaded, so the stored step keeps saying exactly what the operator typed: the preview
	// and the run both go through this function, so what is shown is what is sent either way, and a
	// default changed tomorrow changes every step that never overrode it instead of having been
	// frozen into each one at save time.
	if scopeTargetID != "" {
		step.Options = effectiveFuzzOptions(loadFuzzDefaults(ctx, scopeTargetID), step.Options)
	}

	// --- tokens present in the text, which is the authority, not the stored position rows -------
	found := map[string]bool{}
	for _, m := range fuzzTokenRe.FindAllString(step.RawRequest, -1) {
		found[m] = true
	}
	declared := map[string]FuzzPosition{}
	for _, p := range step.Positions {
		declared[p.Token] = p
	}
	for tok := range found {
		if _, ok := declared[tok]; !ok {
			out.Errors = append(out.Errors, fmt.Sprintf(
				"%s appears in the request but has no payload configured. ffuf would send it as "+
					"literal text rather than failing, so the scan would look like it ran.", tok))
		}
	}
	for tok := range declared {
		if !found[tok] {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"%s is configured but no longer appears in the request, so it does nothing.", tok))
		}
	}

	// --- render the text into the dialect this mode speaks --------------------------------------
	raw := step.RawRequest
	var wordlists []struct {
		keyword string
		path    string
		encoder string
		length  int64
	}

	active := make([]FuzzPosition, 0, len(step.Positions))
	for _, p := range step.Positions {
		if found[p.Token] {
			active = append(active, p)
		}
	}

	for _, p := range active {
		switch mode {
		case "sniper":
			// The text between the marks is what is sent while another position is being fuzzed,
			// so the resting value has to be the endpoint's real value, not a placeholder.
			raw = strings.ReplaceAll(raw, p.Token, "§"+p.RestingValue+"§")
		default:
			raw = strings.ReplaceAll(raw, p.Token, keywordForToken(p.Token))
		}
	}

	// Current credentials, when the step asks for them, BEFORE anything reads the bytes: the scope
	// check, the expiry check and the command all have to see what will actually be sent.
	if v, ok := step.Options["useSessionTokens"].(bool); ok && v {
		substituted, notes := applySessionTokens(raw, scopeTargetID)
		raw = substituted
		out.Warnings = append(out.Warnings, notes...)
	}

	out.Raw = raw
	out.Host = HostFromRawRequest(raw)

	// --- scope, read from the FINAL bytes -------------------------------------------------------
	//
	// The destination has to be UNAMBIGUOUS before it is worth checking: an absolute-form request line
	// or a second Host header makes ffuf connect somewhere the check never looked.
	out.Errors = append(out.Errors, FuzzRequestTargetErrors(raw)...)
	out.Errors = append(out.Errors, unsupportedFuzzOptionErrors(step.Options)...)
	// A dead credential is the difference between a scan and 5000 identical auth errors recorded as
	// findings, so it blocks the step rather than merely colouring the result.
	credErrs, credWarnings := fuzzCredentialProblems(raw, time.Now())
	out.Errors = append(out.Errors, credErrs...)
	out.Warnings = append(out.Warnings, credWarnings...)
	if out.Host == "" {
		out.Errors = append(out.Errors, "The request has no Host header, so there is nothing to send it to.")
	} else if scope != nil && !scope.Allows(out.Host) {
		out.Errors = append(out.Errors, fmt.Sprintf(
			"%s is outside this scope target (%s). The Host line decides where the request actually "+
				"goes, so this is checked against the rendered bytes rather than the saved form.",
			out.Host, scope.Describe()))
	}

	// --- wordlists ------------------------------------------------------------------------------
	for _, p := range active {
		if strings.TrimSpace(p.Wordlist) == "" {
			out.Errors = append(out.Errors, fmt.Sprintf(
				"%s has no wordlist bound.", p.Token))
			continue
		}
		path, err := resolveWordlist(p.Wordlist, "")
		if err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("%s: %v", p.Token, err))
			continue
		}
		n, err := wordlistLength(ctx, path)
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"%s: could not count %s, so the request estimate excludes it.", p.Token, path))
		}
		wordlists = append(wordlists, struct {
			keyword string
			path    string
			encoder string
			length  int64
		}{keywordForToken(p.Token), path, p.Encoder, n})
	}

	// --- mode specific rules --------------------------------------------------------------------
	switch mode {
	case "sniper":
		// ffuf refuses more than one wordlist in sniper mode outright.
		distinct := map[string]bool{}
		for _, w := range wordlists {
			distinct[w.path] = true
		}
		if len(distinct) > 1 {
			out.Errors = append(out.Errors, "Sniper takes exactly one wordlist, and this step binds "+
				strconv.Itoa(len(distinct))+". Bind every position to the same list, or use clusterbomb.")
		}
	case "pitchfork":
		// ffuf WRAPS a short list modulo rather than stopping, so unequal lengths silently produce
		// pairings that were never in the data. That is the opposite of what pitchfork is used for.
		lengths := map[int64]bool{}
		for _, w := range wordlists {
			if w.length > 0 {
				lengths[w.length] = true
			}
		}
		if len(lengths) > 1 {
			out.Errors = append(out.Errors, "Pitchfork pairs lists by index, but these lists are "+
				"different lengths and ffuf recycles the shorter one from the start rather than "+
				"stopping. Every pairing after the shortest list runs out would be invented. Use "+
				"equal length lists, or clusterbomb.")
		}
	}

	out.Estimate = estimateFuzzRequests(mode, wordlists, len(active))
	if out.Estimate > fuzzRequestCeiling {
		out.Acknowledge = true
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"This step is %s requests. clusterbomb multiplies every list together, so positions are "+
				"expensive in a way that is easy to miss.", formatCount(out.Estimate)))
	}

	// --- argv ------------------------------------------------------------------------------------
	args := []string{"-request", reqFile, "-request-proto", step.Scheme}
	for _, w := range wordlists {
		args = append(args, "-w", w.path+":"+w.keyword)
	}
	if mode == "sniper" {
		// Sniper reads § pairs out of the request and takes a bare -w.
		args = []string{"-request", reqFile, "-request-proto", step.Scheme}
		for _, w := range wordlists {
			args = append(args, "-w", w.path)
			break
		}
	}
	args = append(args, "-mode", mode)
	for _, w := range wordlists {
		if enc := strings.TrimSpace(w.encoder); enc != "" && mode != "sniper" {
			args = append(args, "-enc", w.keyword+":"+enc)
		}
	}
	// The first position's keyword, so -ac has something real to calibrate against.
	acKeyword := ""
	if len(wordlists) > 0 {
		acKeyword = wordlists[0].keyword
	}
	args = append(args, fuzfOptionArgs(step.Options, acKeyword)...)
	args = append(args, "-o", outFile, "-of", "json")
	// -od makes ffuf write the real request and response bytes for each matched result. Verified in
	// this composer's own mode (-request with a FUZZPnn keyword): it works, it writes one file per
	// MATCH rather than per request, and the file holds the request ffuf actually sent, including the
	// headers it adds itself, then a separator line, then the full response. That is the difference
	// between a finding an operator can act on and four numbers.
	if fuzzCaptureEvidenceFor(step) {
		args = append(args, "-od", FuzzEvidenceDirFor(outFile))
	}

	// Header NAME fuzzing races above one thread: at -t 40 ffuf has been observed transmitting the
	// unsubstituted marker instead of a payload. Forcing a single thread is the only way that
	// position type produces trustworthy results.
	if hasHeaderNamePosition(active) {
		args = append(args, "-t", "1")
		out.Warnings = append(out.Warnings, "A header NAME is being fuzzed, so this step runs at one "+
			"thread. Above that, ffuf intermittently sends the marker itself instead of the payload.")
	}

	// ignoreBody makes ffuf skip downloading the response content, so every measurement taken FROM the
	// content stops meaning anything: size and word counts collapse, the matchers and filters built on
	// them match nothing, the noise guard has no signature to group on, and the captured evidence has
	// no response to show. Warned rather than refused, because status-only fuzzing is a legitimate and
	// much cheaper thing to want; it just cannot be combined with the rest.
	if v, ok := step.Options["ignoreBody"].(bool); ok && v {
		var broken []string
		for _, k := range []string{"matchSize", "matchWords", "filterSize", "filterWords"} {
			if s, ok := step.Options[k].(string); ok && strings.TrimSpace(s) != "" {
				broken = append(broken, k)
			}
		}
		sort.Strings(broken)
		msg := "ignoreBody is on, so ffuf does not download response bodies. Response sizes and word " +
			"counts will be reported as zero, the noise guard has nothing to group on, and captured " +
			"evidence will carry no response body."
		if len(broken) > 0 {
			msg += " " + strings.Join(broken, " and ") + " read the body and will match nothing."
		}
		out.Warnings = append(out.Warnings, msg)
	}

	out.Args = args
	out.Command = "docker exec " + ffufContainer + " ffuf " + strings.Join(args, " ")
	return out
}

func hasHeaderNamePosition(positions []FuzzPosition) bool {
	for _, p := range positions {
		if p.Role == "header_name" {
			return true
		}
	}
	return false
}

// estimateFuzzRequests is the count ffuf will actually make, per mode.
//
// Taken from ffuf's own input.Total(): clusterbomb multiplies, pitchfork takes the MAXIMUM (it
// recycles short lists rather than stopping), sniper runs positions x list length as separate jobs.
func estimateFuzzRequests(mode string, lists []struct {
	keyword string
	path    string
	encoder string
	length  int64
}, positions int) int64 {

	if len(lists) == 0 {
		return 0
	}
	switch mode {
	case "pitchfork":
		var max int64
		for _, w := range lists {
			if w.length > max {
				max = w.length
			}
		}
		return max
	case "sniper":
		return int64(positions) * lists[0].length
	default:
		total := int64(1)
		for _, w := range lists {
			if w.length <= 0 {
				continue
			}
			total *= w.length
			if total > 1e15 {
				return int64(1e15) // saturate rather than overflow
			}
		}
		return total
	}
}

func formatCount(n int64) string {
	switch {
	case n >= 1e12:
		return fmt.Sprintf("%.1f trillion", float64(n)/1e12)
	case n >= 1e9:
		return fmt.Sprintf("%.1f billion", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1f million", float64(n)/1e6)
	default:
		return strconv.FormatInt(n, 10)
	}
}

// FuzzOptionKeys documents every option key a step honours, with a line on each.
//
// It is exported and returned by the step API because the alternative has already cost real scans:
// options is a free-form jsonb blob that fuzfOptionArgs reads a fixed set of keys out of, so
// {"match_status": "200"} or {"mc": "200"} saves cleanly, changes nothing, and reports success. A
// caller that can see the list can be told which of its keys did nothing.
var FuzzOptionKeys = map[string]string{
	"threads":          "-t, concurrent requests. ffuf's own default is 40, which is a lot for a target you are pacing.",
	"rate":             "-rate, requests per second across all threads. 0 means unlimited.",
	"timeout":          "-timeout, per-request timeout in seconds.",
	"delay":            "-p, delay between requests, e.g. \"0.1\" or a range \"0.1-2.0\".",
	"matchStatus":      "-mc, status codes that count as a finding. WITH NOTHING SET ffuf 2.2.1 installs 200-299,301,302,307,401,403,405,500, which includes 401 and 403, so an endpoint behind auth reports one finding per word. \"all\" matches everything and leaves the filtering to the filters. TRAP: setting any OTHER matcher (matchSize, matchWords, matchLines, matchRegexp) and leaving matchStatus unset makes ffuf drop that default status matcher entirely, so set matchStatus explicitly whenever you set another matcher.",
	"matchSize":        "-ms, response sizes that count as a finding.",
	"matchWords":       "-mw, response word counts that count as a finding.",
	"matchLines":       "-ml, response line counts that count as a finding.",
	"matchRegexp":      "-mr, regexp the response must match.",
	"matcherMode":      "-mmode, how multiple matchers combine: and, or.",
	"filterStatus":     "-fc, status codes to discard. This is the flag that removes an auth wall or a WAF's uniform answer.",
	"filterSize":       "-fs, response sizes to discard. The right tool for a soft-404 that returns 200 with one constant body.",
	"filterWords":      "-fw, response word counts to discard.",
	"filterLines":      "-fl, response line counts to discard.",
	"filterRegexp":     "-fr, regexp whose match discards a response.",
	"filterMode":       "-fmode, how multiple filters combine. THE DEFAULT IS or, so filterStatus 403 together with filterSize 33 discards every 403 of any size AND every 33-byte response of any status. Set \"and\" when the thing you mean to exclude is one status-and-size signature rather than either half of it.",
	"autocalibration":  "-ac, let ffuf measure the target's not-found response and filter it. PREFER AN EXPLICIT FILTER. Measured against ffuf 2.2.1 on a controlled target with six real files: without -ac all six were reported; with -ac one was silently filtered out (.env), and with -ac plus -ack naming this composer's keyword a different one was (api/v1/users). Autocalibration derives a filter from probe responses nobody sees, and on a step whose positions are named FUZZP01 rather than ffuf's default FUZZ it has nothing to substitute into unless -ack is sent, which the framework now sends for you. It also writes its probe string into the first result's input map. A filterStatus, filterSize or filterWords taken from a previous run is a number you can read, check and disagree with.",
	"followRedirects":  "-r, follow redirects.",
	"extensions":       "NOT SUPPORTED HERE, and setting it is refused rather than ignored. ffuf applies -e to its FUZZ keyword only, and this composer names positions FUZZP01 upward, so measured against ffuf 2.2.1 the extensions were silently dropped and three words produced three requests instead of nine. Put the variants in the wordlist itself, e.g. main.js and main.js.map as separate entries.",
	"recursion":        "NOT SUPPORTED HERE, and setting it is refused rather than ignored. ffuf requires \"the URL (-u) must end with FUZZ keyword\" for recursion and this composer sends a raw request file, so ffuf prints that error and exits 0. Add a second step against the directory you found instead.",
	"recursionDepth":   "NOT SUPPORTED HERE, see recursion.",
	"maxTime":          "-maxtime, seconds after which the whole step stops, whatever is left. The only hard bound on what a step can cost.",
	"ignoreComments":   "-ic, skip lines starting with # in the wordlist instead of requesting them.",
	"captureEvidence":  "Framework-side, not an ffuf flag, and ON by default. Records the request and response bytes for every matched result using ffuf's -od, so a finding can be read and replayed instead of being four numbers. ffuf writes one file per MATCH, not per request, and the capture is deleted with the run directory once it has been stored. Set false to skip it.",
	"useSessionTokens": "Framework-side, not an ffuf flag, and OFF by default. Replaces credential headers the request ALREADY carries with the current values from the Session Manager, so a step stops replaying the token frozen into it when it was seeded. Off by default because a fuzz step is text you wrote and silently rewriting it would break the rule that the preview is what goes on the wire; with it on, the preview shows the substitution too.",
	"noiseGuard":       "Framework-side, not an ffuf flag. Defaults on: when one response signature accounts for most of a step's results, those rows are reported as the endpoint's baseline instead of being stored as findings. Set false when the uniform response IS the subject.",

	"maxTimeJob":  "-maxtime-job, seconds after which the current JOB stops rather than the whole process. With one job per step this behaves much like maxTime; it differs once ffuf queues jobs of its own.",
	"proxyURL":    "-x, send every request through this proxy. HTTP or SOCKS5, e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080. The usual reason to set it is to watch a step in Burp or Caido while it runs.",
	"replayProxy": "-replay-proxy, send only the requests that MATCHED through this proxy, once, after the fact. This is the one to use on a large step: the whole run does not go through your proxy, only the handful of results worth looking at, which arrive in the proxy history ready to replay by hand.",
	"clientCert":  "-cc, client certificate for mutual TLS. Needs clientKey set as well or ffuf ignores it. The path is inside the ffuf container.",
	"clientKey":   "-ck, client key for mutual TLS. Needs clientCert set as well. The path is inside the ffuf container.",
	"http2":       "-http2, speak HTTP/2. Worth trying when a target's HTTP/1.1 behaviour differs, and required by some hosts that reject 1.1 outright.",
	"sni":         "-sni, the TLS server name to present, when it needs to differ from the Host header. Useful against a host that serves different certificates or different applications by SNI. It does not accept a fuzz position.",
	"rawURI":      "-raw, do not URI-encode the request. ffuf percent-encodes payloads that land in the URL, so a wordlist entry with a space goes out as %20; with this on it goes out as typed. Set it when the encoding is what you are testing, and leave it off otherwise, because a raw payload can produce a request the server rejects before it reaches the application.",
	"ignoreBody":  "-ignore-body, do not download the response body. It makes a step much faster and much cheaper on bandwidth, and it BREAKS everything that reads the body: response size and word counts collapse, so size and word matchers, size and word filters, the noise guard and the captured evidence all stop meaning anything. Only useful when status alone decides a finding.",
	"matchTime":   "-mt, match on time to first byte in milliseconds, as a comparison: \">100\" or \"<100\". A blind injection that makes the server pause is invisible to every other matcher.",
	"filterTime":  "-ft, discard by time to first byte, same \">100\" or \"<100\" syntax. The way to drop responses that only differ by being slow.",

	"autocalibrationPerHost":  "-ach, calibrate separately for each host rather than once for the run. Only matters when a step spans more than one host.",
	"autocalibrationStrategy": "-acs, named auto-calibration strategy. Implies -ac. Takes one value or a list.",
	"autocalibrationString":   "-acc, the probe string auto-calibration sends instead of ffuf's own. Implies -ac. Takes one value or a list.",

	"stopOnAll":    "-sa, abort the whole step at the first error of any kind. Implies stopOnErrors and stopOn403. Against anything behind a WAF this ends the scan in seconds with nothing to show, which is why it is off by default.",
	"stopOnErrors": "-se, abort on the first spurious error. Reasonable on a target you know is healthy; on a flaky one it turns a transient failure into a step that covered almost nothing.",
	"stopOn403":    "-sf, abort once more than 95% of responses are 403. The polite reading of \"you have been blocked\", and the one worth having on when you are not sure the target tolerates the rate.",

	"scrapers":    "-scrapers, which scraper groups run. ffuf's scrapers pull extra detail out of matched responses into the report. Default is all.",
	"scraperFile": "-scraperfile, a custom scraper definition file. The path is inside the ffuf container.",

	"recursionStrategy": "NOT SUPPORTED HERE, and setting it is refused rather than ignored. It only has meaning with recursion, which this composer cannot run: ffuf requires the URL to end in its FUZZ keyword and this step sends a raw request file.",
	"dirsearchMode":     "NOT SUPPORTED HERE, and setting it is refused rather than ignored. -D only has meaning together with -e, which this composer cannot use because ffuf applies extensions to its own FUZZ keyword and these positions are named FUZZP01 upward.",
	"inputCmd":          "NOT SUPPORTED HERE, and setting it is refused rather than ignored. -input-cmd OVERRIDES -w, so the wordlists configured on this step's positions would silently not be used and the request count would come from input-num instead.",
	"inputNum":          "NOT SUPPORTED HERE, see inputCmd.",
	"inputShell":        "NOT SUPPORTED HERE, see inputCmd.",
}

// FuzzOwnedFlags are ffuf's remaining flags: the ones the framework sets itself, and which are
// therefore not settings.
//
// They are listed rather than omitted because "the modal does not show it" and "the tool cannot do
// it" look identical from the outside, and an operator comparing this screen against ffuf's help
// deserves an answer for every line of it. Each says what does decide the value.
var FuzzOwnedFlags = map[string]string{
	"-u, -request, -request-proto": "The step's raw request and scheme. This composer always runs ffuf in request mode, which is what lets a position sit in a header, a cookie or a body rather than only in the URL.",
	"-w":                           "Each position's wordlist, chosen per position in Configure. The keyword is generated (FUZZP01 upward) so one position's keyword can never be a prefix of another's.",
	"-mode":                        "The step's mode: clusterbomb, pitchfork or sniper.",
	"-H, -X, -b, -d":               "Headers, method, cookies and body all come from the raw request text, where you can see them and put a position in any of them.",
	"-enc":                         "Set per position as its encoder, since an encoding applies to one payload rather than to the step.",
	"-ack":                         "Sent automatically alongside autocalibration, naming this step's own keyword. Without it ffuf calibrates against its default FUZZ keyword, finds nothing to substitute into, and installs a filter derived from the live payload's own size.",
	"-o, -of, -od":                 "The JSON report and the evidence directory, both read back by the framework. -od follows captureEvidence.",
	"-s":                           "Always on. The progress bar redrawn thousands of times is noise in a database column.",
	"-json, -c, -v, -V":            "Output formatting for a terminal nobody is watching. The framework parses the JSON report file instead.",
	"-config":                      "Would load a file of options that silently overrides everything set here.",
	"-or":                          "The report file is always wanted, including when a step matched nothing: that is a result.",
	"-search, -noninteractive":     "Interactive console features with no meaning in a container run non-attached.",
	"-debug-log":                   "Writes ffuf's internal log to a path inside the container. The step's stdout and the rendered command are already stored against the run.",
}

// FuzzOptionMeta is the same vocabulary again, typed and grouped, so a form can be BUILT from it
// rather than hand-written beside it.
//
// The Settings modal renders whatever this says, which is the point: a UI that hard-codes its own
// list of ffuf settings is a second copy of this file, and the two only have to disagree once for an
// operator to set something in the UI that no scan ever reads. Same reason the option documentation
// and the triage vocabulary are served rather than duplicated.
//
// Kinds are what the control has to be, not what ffuf receives: "int" is a spinner, "bool" a switch,
// "string" a text field, "enum" a select. "unsupported" renders disabled with the reason from
// FuzzOptionKeys, because a setting that is refused needs to be visible as refused rather than absent
// and quietly wished for.
type FuzzOptionMeta struct {
	Kind    string   `json:"kind"`
	Group   string   `json:"group"`
	Label   string   `json:"label"`
	Flag    string   `json:"flag,omitempty"`
	Choices []string `json:"choices,omitempty"`
	// Placeholder is what ffuf or the framework does when the option is not set.
	Placeholder string `json:"placeholder,omitempty"`
}

// FuzzOptionGroups is the order the groups are shown in, coarse to fine: how hard to hit the target,
// then what counts as a finding, then what to throw away, then how the framework itself behaves.
var FuzzOptionGroups = []string{"Pacing", "Connection", "Matchers", "Filters", "Calibration",
	"Behaviour", "Stop conditions", "Framework", "Refused"}

var FuzzOptionMetas = map[string]FuzzOptionMeta{
	"threads":    {Kind: "int", Group: "Pacing", Label: "Threads", Flag: "-t", Placeholder: "ffuf default 40"},
	"rate":       {Kind: "int", Group: "Pacing", Label: "Rate limit", Flag: "-rate", Placeholder: "0, unlimited"},
	"delay":      {Kind: "string", Group: "Pacing", Label: "Delay", Flag: "-p", Placeholder: "0.1 or 0.1-2.0"},
	"timeout":    {Kind: "int", Group: "Pacing", Label: "Timeout", Flag: "-timeout", Placeholder: "seconds"},
	"maxTime":    {Kind: "int", Group: "Pacing", Label: "Max time", Flag: "-maxtime", Placeholder: "seconds, 0 for none"},
	"maxTimeJob": {Kind: "int", Group: "Pacing", Label: "Max time per job", Flag: "-maxtime-job", Placeholder: "seconds, 0 for none"},

	"proxyURL":    {Kind: "string", Group: "Connection", Label: "Proxy", Flag: "-x", Placeholder: "http://127.0.0.1:8080"},
	"replayProxy": {Kind: "string", Group: "Connection", Label: "Replay proxy (matches only)", Flag: "-replay-proxy", Placeholder: "http://127.0.0.1:8080"},
	"clientCert":  {Kind: "string", Group: "Connection", Label: "Client certificate", Flag: "-cc", Placeholder: "path in the ffuf container"},
	"clientKey":   {Kind: "string", Group: "Connection", Label: "Client key", Flag: "-ck", Placeholder: "path in the ffuf container"},
	"http2":       {Kind: "bool", Group: "Connection", Label: "HTTP/2", Flag: "-http2"},
	"sni":         {Kind: "string", Group: "Connection", Label: "TLS SNI", Flag: "-sni", Placeholder: "defaults to the Host header"},

	"matchStatus": {Kind: "string", Group: "Matchers", Label: "Status", Flag: "-mc", Placeholder: "200,301 or all"},
	"matchSize":   {Kind: "string", Group: "Matchers", Label: "Size", Flag: "-ms"},
	"matchWords":  {Kind: "string", Group: "Matchers", Label: "Words", Flag: "-mw"},
	"matchLines":  {Kind: "string", Group: "Matchers", Label: "Lines", Flag: "-ml"},
	"matchRegexp": {Kind: "string", Group: "Matchers", Label: "Regexp", Flag: "-mr"},
	"matchTime":   {Kind: "string", Group: "Matchers", Label: "Time to first byte", Flag: "-mt", Placeholder: ">100 or <100"},
	"matcherMode": {Kind: "enum", Group: "Matchers", Label: "Combine with", Flag: "-mmode",
		Choices: []string{"or", "and"}, Placeholder: "or"},

	"filterStatus": {Kind: "string", Group: "Filters", Label: "Status", Flag: "-fc", Placeholder: "404"},
	"filterSize":   {Kind: "string", Group: "Filters", Label: "Size", Flag: "-fs"},
	"filterWords":  {Kind: "string", Group: "Filters", Label: "Words", Flag: "-fw"},
	"filterLines":  {Kind: "string", Group: "Filters", Label: "Lines", Flag: "-fl"},
	"filterRegexp": {Kind: "string", Group: "Filters", Label: "Regexp", Flag: "-fr"},
	"filterTime":   {Kind: "string", Group: "Filters", Label: "Time to first byte", Flag: "-ft", Placeholder: ">100 or <100"},
	"filterMode": {Kind: "enum", Group: "Filters", Label: "Combine with", Flag: "-fmode",
		Choices: []string{"or", "and"}, Placeholder: "or"},

	"followRedirects": {Kind: "bool", Group: "Behaviour", Label: "Follow redirects", Flag: "-r"},
	"ignoreComments":  {Kind: "bool", Group: "Behaviour", Label: "Ignore # comments", Flag: "-ic"},
	"rawURI":          {Kind: "bool", Group: "Behaviour", Label: "Send the URI unencoded", Flag: "-raw"},
	"ignoreBody":      {Kind: "bool", Group: "Behaviour", Label: "Do not download the body", Flag: "-ignore-body"},
	"scrapers":        {Kind: "string", Group: "Behaviour", Label: "Scraper groups", Flag: "-scrapers", Placeholder: "all"},
	"scraperFile":     {Kind: "string", Group: "Behaviour", Label: "Scraper file", Flag: "-scraperfile", Placeholder: "path in the ffuf container"},

	"autocalibration":         {Kind: "bool", Group: "Calibration", Label: "Autocalibration", Flag: "-ac"},
	"autocalibrationPerHost":  {Kind: "bool", Group: "Calibration", Label: "Calibrate per host", Flag: "-ach"},
	"autocalibrationStrategy": {Kind: "string", Group: "Calibration", Label: "Strategy", Flag: "-acs"},
	"autocalibrationString":   {Kind: "string", Group: "Calibration", Label: "Probe string", Flag: "-acc"},

	"stopOnAll":    {Kind: "bool", Group: "Stop conditions", Label: "Stop on any error", Flag: "-sa"},
	"stopOnErrors": {Kind: "bool", Group: "Stop conditions", Label: "Stop on spurious errors", Flag: "-se"},
	"stopOn403":    {Kind: "bool", Group: "Stop conditions", Label: "Stop when mostly 403", Flag: "-sf"},

	"captureEvidence":  {Kind: "bool", Group: "Framework", Label: "Capture request and response bytes", Placeholder: "on"},
	"useSessionTokens": {Kind: "bool", Group: "Framework", Label: "Use current session tokens", Placeholder: "off"},
	"noiseGuard":       {Kind: "bool", Group: "Framework", Label: "Noise guard", Placeholder: "on"},

	"extensions":        {Kind: "unsupported", Group: "Refused", Label: "Extensions", Flag: "-e"},
	"recursion":         {Kind: "unsupported", Group: "Refused", Label: "Recursion", Flag: "-recursion"},
	"recursionDepth":    {Kind: "unsupported", Group: "Refused", Label: "Recursion depth", Flag: "-recursion-depth"},
	"recursionStrategy": {Kind: "unsupported", Group: "Refused", Label: "Recursion strategy", Flag: "-recursion-strategy"},
	"dirsearchMode":     {Kind: "unsupported", Group: "Refused", Label: "DirSearch mode", Flag: "-D"},
	"inputCmd":          {Kind: "unsupported", Group: "Refused", Label: "Input command", Flag: "-input-cmd"},
	"inputNum":          {Kind: "unsupported", Group: "Refused", Label: "Input count", Flag: "-input-num"},
	"inputShell":        {Kind: "unsupported", Group: "Refused", Label: "Input shell", Flag: "-input-shell"},
}

// UnrecognisedFuzzOptions names the keys in a step's options that nothing reads, so a caller is told
// rather than left believing a setting took effect.
func UnrecognisedFuzzOptions(opts map[string]any) []string {
	var out []string
	for k := range opts {
		if _, ok := FuzzOptionKeys[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// fuzfOptionArgs turns the step's stored options into ffuf flags. Only options that map to a real
// flag are emitted; an unknown key is ignored rather than guessed at, and UnrecognisedFuzzOptions is
// what tells the caller that happened.
func fuzfOptionArgs(opts map[string]any, acKeyword string) []string {
	var args []string
	num := func(k string) (int, bool) {
		v, ok := opts[k]
		if !ok {
			return 0, false
		}
		switch t := v.(type) {
		case float64:
			return int(t), t > 0
		case int:
			return t, t > 0
		}
		return 0, false
	}
	str := func(k string) (string, bool) {
		if v, ok := opts[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v), true
		}
		return "", false
	}

	if n, ok := num("threads"); ok {
		args = append(args, "-t", strconv.Itoa(n))
	}
	if n, ok := num("rate"); ok {
		args = append(args, "-rate", strconv.Itoa(n))
	}
	if n, ok := num("timeout"); ok {
		args = append(args, "-timeout", strconv.Itoa(n))
	}
	if s, ok := str("delay"); ok {
		args = append(args, "-p", s)
	}
	// Matchers and filters decide what counts as a finding at all. Without at least one matcher
	// ffuf's default is status-based, which on a soft-404 target reports everything.
	for key, flag := range map[string]string{
		"matchStatus": "-mc", "matchSize": "-ms", "matchWords": "-mw",
		"matchLines": "-ml", "matchRegexp": "-mr",
		"filterStatus": "-fc", "filterSize": "-fs", "filterWords": "-fw",
		"filterLines": "-fl", "filterRegexp": "-fr",
	} {
		if s, ok := str(key); ok {
			args = append(args, flag, s)
		}
	}
	if s, ok := str("matcherMode"); ok {
		args = append(args, "-mmode", s)
	}
	if s, ok := str("filterMode"); ok {
		args = append(args, "-fmode", s)
	}
	if v, ok := opts["autocalibration"].(bool); ok && v {
		args = append(args, "-ac")
		// ffuf calibrates by substituting probe strings into its AutoCalibrationKeyword, which defaults
		// to "FUZZ". This composer names its keywords FUZZP01 upward, so without -ack there is nothing
		// for ffuf to substitute into: every calibration request is a byte-identical repeat of whatever
		// payload happened to be in flight, the responses trivially agree, and ffuf installs a filter
		// for THAT payload's own size. Measured on a controlled target with six real files, that
		// filtered .env out of the results entirely.
		if acKeyword != "" {
			args = append(args, "-ack", acKeyword)
		}
	}
	if v, ok := opts["followRedirects"].(bool); ok && v {
		args = append(args, "-r")
	}
	// -e and -recursion are deliberately NOT emitted. Both were added here on the assumption that a
	// missing flag was the only thing standing between an operator and a file hunt, and both were then
	// measured against ffuf 2.2.1 in this composer's own mode:
	//
	//   -e         applies extensions to the FUZZ keyword only. With -request and a named keyword,
	//              three words produced three requests instead of nine: the extensions were silently
	//              dropped, so a step would cover a quarter of what its operator believed.
	//   -recursion refuses outright: "When using -recursion the URL (-u) must end with FUZZ keyword",
	//              and there is no -u in request mode. It prints that and EXITS 0.
	//
	// RenderFuzzStep turns either option into a blocking error instead, because silently ignoring a
	// setting is how a scan comes to be trusted for coverage it never had.
	if n, ok := num("maxTime"); ok {
		args = append(args, "-maxtime", strconv.Itoa(n))
	}
	if n, ok := num("maxTimeJob"); ok {
		args = append(args, "-maxtime-job", strconv.Itoa(n))
	}
	if v, ok := opts["ignoreComments"].(bool); ok && v {
		args = append(args, "-ic")
	}

	// Connection, matching and stop behaviour. These are one-for-one with ffuf's own flags: there is
	// nothing clever to do with them, and leaving them out was the only reason an operator could not
	// point a step at a proxy or use a client certificate from here.
	for key, flag := range map[string]string{
		"proxyURL": "-x", "replayProxy": "-replay-proxy", "clientCert": "-cc", "clientKey": "-ck",
		"sni": "-sni", "matchTime": "-mt", "filterTime": "-ft",
		"scrapers": "-scrapers", "scraperFile": "-scraperfile",
	} {
		if s, ok := str(key); ok {
			args = append(args, flag, s)
		}
	}
	for key, flag := range map[string]string{
		"http2": "-http2", "rawURI": "-raw", "ignoreBody": "-ignore-body",
		"stopOnAll": "-sa", "stopOnErrors": "-se", "stopOn403": "-sf",
		"autocalibrationPerHost": "-ach",
	} {
		if v, ok := opts[key].(bool); ok && v {
			args = append(args, flag)
		}
	}
	// -acs and -acc may be given more than once, so a list is accepted as well as a single value.
	// Both imply -ac on ffuf's side, which is why they sit in the same group as it.
	for key, flag := range map[string]string{
		"autocalibrationStrategy": "-acs", "autocalibrationString": "-acc",
	} {
		switch v := opts[key].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				args = append(args, flag, strings.TrimSpace(v))
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					args = append(args, flag, strings.TrimSpace(s))
				}
			}
		}
	}
	// The JSON report is the output that matters and stdout is stored in a database column, so the
	// progress bar redrawing 5000 times is noise an operator has to scroll past.
	args = append(args, "-s")
	return args
}

// FuzzEvidenceDirFor is where a step's -od capture goes, derived from its own output file so it is
// unique per run per step and lands in the run directory that is removed afterwards.
func FuzzEvidenceDirFor(outFile string) string {
	return strings.TrimSuffix(outFile, ".json") + ".evidence"
}

// fuzzCaptureEvidence reports whether this step should record the bytes it sends and receives.
//
// On by default. Without it a finding is four numbers and no body, which is the single reason
// results were unreadable, and the cost is bounded in the way that matters: measured against ffuf
// 2.2.1, -od writes ONE FILE PER MATCHED RESULT, not per request. A 20 word list matching 6 wrote 6
// files totalling 28K, and the directory is deleted with the run.
//
// It cannot be switched off for a multi-position sniper step, because there it is not an attachment
// but the step's IDENTITY. ffuf reports every sniper slot under one keyword, so the slot is recovered
// from the captured bytes and folded into the finding key. Turning capture off would make the same
// request hash differently: the two slots would collapse back into one row, and turning it on again
// would insert permanent duplicates alongside the collapsed ones.
func fuzzCaptureEvidence(opts map[string]any) bool {
	if v, ok := opts["captureEvidence"].(bool); ok {
		return v
	}
	return true
}

// fuzzCaptureEvidenceFor answers the same question for a specific step.
func fuzzCaptureEvidenceFor(step FuzzStep) bool {
	if strings.EqualFold(step.FFUFMode, "sniper") && len(step.Positions) > 1 {
		return true
	}
	return fuzzCaptureEvidence(step.Options)
}

// wordlistLength counts entries inside the ffuf container, because that is the filesystem the file
// lives on. Counting it from the API container would be counting a different machine.
func wordlistLength(ctx context.Context, path string) (int64, error) {
	runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(runCtx, "docker", "exec", ffufContainer,
		"sh", "-c", "grep -vc '^[[:space:]]*$' "+shellQuoteArg(path)).Output()
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// shellQuoteArg is single-quote escaping for a path handed to sh -c.
func shellQuoteArg(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
