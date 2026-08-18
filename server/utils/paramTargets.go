package utils

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Which endpoints the parameter-enumeration tools may brute-force, and in what order.
//
// This exists as one file because every tool in this section used to carry its own copy of the
// same query, and the copies had already drifted: none filtered on a validation verdict, all
// filtered `is_direct = true`, none filtered `deleted_at`, and the row caps were absent, 50 and
// 100 respectively. So tools sitting in one section of the UI were each measuring a different
// corpus and none of them was measuring the right one.
//
// THE PREDICATE IS STRICT `valid`, which is narrower than Investigate's.
//
// That is deliberate and it is the opposite of the reasoning in InvestigationEligibility, which
// widens to unverified on purpose. These tools detect a hidden parameter by
// DIFFERENTIAL: send a candidate, compare the response to a baseline, report a difference. On this
// framework's usual target, a client-routed application, 756 of 836 eligible rows carry
// `unverified.spa_shell_ambiguous`, whose literal meaning is "this response could not be told apart
// from any other path on this host". Pointing a differential scanner at a row whose recorded verdict
// is that no working oracle exists is not merely low yield: every candidate parameter compares equal
// to a baseline that is itself the catch-all, so the run burns its whole request budget to learn
// nothing. Investigate can afford unverified rows because it reads one response; these tools send
// thousands per endpoint.
//
// Scripts are excluded on the same logic. A .js bundle is served by a CDN and has no server-side
// parameter surface, and on the reference target they are 34 of the 80 valid rows, so including them
// triples the request count for no reachable finding.

// ParamEnumEligibility narrows Investigate's ledger to endpoints worth brute-forcing.
//
// Layered on InvestigationEligibility rather than rewritten so the operator-facing invariants stay
// in one place: override_status beats validation_status, soft-deleted rows never come back, and
// destructive paths are never requested.
const ParamEnumEligibility = InvestigationEligibility + `
	  AND COALESCE(override_status, validation_status) = 'valid'`

// paramEnumScriptExclusion is separate so the caller can turn it off without restating the rest.
const paramEnumScriptExclusion = `
	  AND COALESCE(content_class, 'unknown') <> 'script'`

// ParamTarget is one unit of work: a URL and the verb to send it with. The verb is carried because
// `SELECT DISTINCT url` threw it away, so a POST-only API route was brute-forced as a GET and its
// real parameter surface was never touched.
type ParamTarget struct {
	ID     string
	URL    string
	Method string

	// Mode is the tool-specific request shape this endpoint is tested with. For Arjun it is one of
	// GET, POST, JSON or XML, which are body encodings and NOT HTTP verbs: a POST endpoint taking a
	// JSON body belongs in JSON, and testing it as form-encoded reaches nothing. AutoMode is what
	// the categoriser derived from the recorded request, kept alongside so the UI can show whether
	// the operator has overridden it.
	Mode     string
	AutoMode string

	// Enabled is whether this tool is set to scan the endpoint. Carried so one query can serve both
	// the runner (which wants only enabled rows) and the config UI (which must show the disabled
	// ones too, or they become unreachable to re-enable).
	Enabled bool
}

// ArjunModes are the four values Arjun's -m accepts, in the order the UI presents them.
var ArjunModes = []string{"GET", "POST", "JSON", "XML"}

func IsArjunMode(m string) bool {
	for _, v := range ArjunModes {
		if v == strings.ToUpper(m) {
			return true
		}
	}
	return false
}

// AutoArjunMode categorises an endpoint from what the crawl actually recorded, rather than from its
// verb alone.
//
// Verb alone is not enough and getting it wrong wastes the whole pass. Arjun's -m POST sends
// form-encoded candidates; an API route that only parses a JSON body ignores every one of them and
// answers identically, so the pass reads as "no parameters" when it never spoke the route's
// language. On the reference target 6 of the 8 body endpoints carry application/json, so verb-only
// categorisation would have tested all 8 as form-encoded.
//
// The Content-Type of the recorded REQUEST is the strongest signal, so it is checked first; the body
// itself is the fallback for captures that never recorded a header.
func AutoArjunMode(method, requestContentType, requestBody string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", "GET", "HEAD":
		return "GET"
	}

	ct := strings.ToLower(requestContentType)
	switch {
	case strings.Contains(ct, "json"):
		return "JSON"
	case strings.Contains(ct, "xml"):
		return "XML"
	case strings.Contains(ct, "form-urlencoded"), strings.Contains(ct, "form-data"):
		return "POST"
	}

	switch b := strings.TrimSpace(requestBody); {
	case strings.HasPrefix(b, "{"), strings.HasPrefix(b, "["):
		return "JSON"
	case strings.HasPrefix(b, "<"):
		return "XML"
	}

	// A body-bearing verb with nothing to go on. Form-encoded is Arjun's own default and the
	// broadest guess, and the operator can move it in one click.
	return "POST"
}

// X8Places are x8 injection points, which are the axis x8 varies. They are NOT body encodings, and
// that is the whole difference from Arjun: Arjun's -m picks how a body is written, while x8 picks
// WHERE the candidates go. Encoding is a separate x8 setting (-t) that only applies to the body.
var X8Places = []string{"query", "body", "headers", "cookies"}

func IsX8Place(p string) bool {
	for _, v := range X8Places {
		if v == strings.ToLower(strings.TrimSpace(p)) {
			return true
		}
	}
	return false
}

// AutoX8Place mirrors what x8 does on its own: query for GET, body for the write verbs.
//
// From its --invert help: "By default, parameters are sent within the body only in case
// POST,PUT,PATCH,DELETE methods are used." So the auto value is the one that needs NO flag, and any
// other choice for that endpoint is expressed by inverting. Headers and cookies are never automatic;
// they are worth testing but they are a deliberate extra pass, not a default.
func AutoX8Place(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return "body"
	default:
		return "query"
	}
}

// X8NeedsInvert reports whether reaching this place for this verb requires --invert, which is the
// only way to overwrite x8 default of query-for-GET and body-for-writes. Headers and cookies have
// their own flags and are unaffected.
func X8NeedsInvert(method, place string) bool {
	switch strings.ToLower(place) {
	case "query", "body":
		return place != AutoX8Place(method)
	}
	return false
}

// AutoModeFor is what the categoriser would choose for this tool with no operator input.
func (t ParamTarget) AutoModeFor(tool string) string {
	if tool == "x8" {
		return AutoX8Place(t.Method)
	}
	return t.AutoMode
}

// ModeFor resolves the stored category for a tool, falling back to what the categoriser derived.
func (t ParamTarget) ModeFor(tool string) string {
	if tool == "x8" {
		if IsX8Place(t.Mode) {
			return strings.ToLower(t.Mode)
		}
		return AutoX8Place(t.Method)
	}
	if IsArjunMode(t.Mode) {
		return strings.ToUpper(t.Mode)
	}
	if IsArjunMode(t.AutoMode) {
		return t.AutoMode
	}
	return "GET"
}

// ParamTargetOptions are the knobs a runner may expose.
type ParamTargetOptions struct {
	// Tool restricts the corpus to the endpoints this tool is selected to run against. Empty means
	// no selection filter, which is what the modal uses to render the full list with its
	// checkboxes.
	Tool string
	// IncludeScripts brings content_class='script' rows back in. Off by default.
	IncludeScripts bool
	// IncludeDisabled returns endpoints the tool is not set to scan, flagged rather than filtered.
	// The runner never sets this; the config UI always does.
	IncludeDisabled bool
	// MaxTargets caps the corpus. Applied AFTER the verdict filter, never as part of it: a cap
	// inside the predicate silently changes which endpoints are eligible rather than how many are
	// run, which is how x8's LIMIT 100 came to select 96 unverified rows and 1 valid one.
	MaxTargets int
}

// ParamTargetSelection is what was selected and what was left out, so a runner can report the
// second rather than leaving the operator to wonder why 25 endpoints came back from a target with
// 1137 rows.
type ParamTargetSelection struct {
	Targets   []ParamTarget  `json:"-"`
	ByMethod  map[string]int `json:"by_method"`
	Total     int            `json:"total"`
	Capped    bool           `json:"capped,omitempty"`
	Scope     string         `json:"scope"`
	Predicate string         `json:"predicate"`
}

// Verbs with no parameter surface of their own. OPTIONS answers a CORS preflight and HEAD returns no
// body, so neither can express a differential; on the reference target they are 21 of the 80 valid
// rows and would each cost a full wordlist pass to prove nothing.
var paramEnumSkippedVerbs = map[string]bool{"OPTIONS": true, "HEAD": true}

// SelectParamEnumTargets is the single source of targets for every tool in the section.
func SelectParamEnumTargets(ctx context.Context, scopeTargetID string,
	opts ParamTargetOptions) (ParamTargetSelection, error) {

	// The host boundary is applied here, at the point of selection, because these tools hand raw
	// URLs to a subprocess that opens its own sockets. Nothing downstream of this query can refuse
	// a request, so this is the last place the scope decision can be made at all.
	scope := LoadScanScope(scopeTargetID)

	where := ParamEnumEligibility
	if !opts.IncludeScripts {
		where += paramEnumScriptExclusion
	}
	where += "\n  AND " + scope.InScopeHostSQL(InvestigationHostExpr)

	sel := ParamTargetSelection{
		ByMethod: map[string]int{},
		Scope:    scope.Describe(),
		Predicate: "valid endpoints from Consolidate and Investigate" +
			map[bool]string{true: "", false: ", excluding scripts"}[opts.IncludeScripts],
	}

	// LEFT JOIN, and COALESCE to TRUE, so an endpoint with no stored decision is included. An INNER
	// JOIN here would silently scan nothing until the operator had opened the modal once.
	args := []interface{}{scopeTargetID}
	selectionFilter := ""
	storedMode := "NULL"
	storedEnabled := "TRUE"
	if opts.Tool != "" {
		args = append(args, opts.Tool)
		if !opts.IncludeDisabled {
			selectionFilter = `
		  AND COALESCE((
		        SELECT s.enabled FROM param_enum_endpoint_selection s
		        WHERE s.scope_target_id = consolidated_url_endpoints.scope_target_id
		          AND s.endpoint_id = consolidated_url_endpoints.id
		          AND s.tool = $2
		      ), TRUE)`
		}
		storedEnabled = `COALESCE((SELECT s.enabled FROM param_enum_endpoint_selection s
		        WHERE s.scope_target_id = consolidated_url_endpoints.scope_target_id
		          AND s.endpoint_id = consolidated_url_endpoints.id
		          AND s.tool = $2), TRUE)`
		storedMode = `(SELECT s.mode FROM param_enum_endpoint_selection s
		        WHERE s.scope_target_id = consolidated_url_endpoints.scope_target_id
		          AND s.endpoint_id = consolidated_url_endpoints.id
		          AND s.tool = $2)`
	}

	// The request Content-Type is read case-insensitively out of the headers object. Captures store
	// whatever casing the browser sent, so a plain headers->>'content-type' misses every row that
	// recorded "Content-Type" and silently sends a JSON API through the form-encoded pass.
	rows, err := dbPool.Query(ctx, `
		SELECT id, url, COALESCE(method, 'GET'),
		       COALESCE((SELECT v FROM jsonb_each_text(COALESCE(headers, '{}'::jsonb)) AS h(k, v)
		                  WHERE lower(k) = 'content-type' LIMIT 1), ''),
		       COALESCE(request_body, ''),
		       `+storedMode+`, `+storedEnabled+`
		FROM consolidated_url_endpoints
		WHERE `+where+selectionFilter+`
		ORDER BY url, method`, args...)
	if err != nil {
		return sel, fmt.Errorf("failed to select parameter enumeration targets: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var t ParamTarget
		var reqContentType, reqBody string
		var stored *string
		if rows.Scan(&t.ID, &t.URL, &t.Method, &reqContentType, &reqBody, &stored,
			&t.Enabled) != nil {
			continue
		}
		t.AutoMode = AutoArjunMode(t.Method, reqContentType, reqBody)
		if stored != nil {
			// Kept verbatim. The accepted values differ per tool (Arjun takes body encodings, x8
			// takes injection places), so validating against one tool's set here silently discarded
			// the other's and every reassignment appeared to do nothing.
			t.Mode = strings.TrimSpace(*stored)
		}
		t.Method = strings.ToUpper(strings.TrimSpace(t.Method))
		if t.Method == "" {
			t.Method = "GET"
		}
		if paramEnumSkippedVerbs[t.Method] {
			continue
		}
		// Arjun decides its whole input format from the first line of the file, so a row that is
		// not an absolute http(s) URL does not merely get skipped: it makes Arjun read nothing,
		// write no output and exit 0, which every caller records as a successful empty scan.
		if !strings.HasPrefix(t.URL, "http://") && !strings.HasPrefix(t.URL, "https://") {
			continue
		}
		sel.Targets = append(sel.Targets, t)
		sel.ByMethod[t.Method]++
	}
	if err := rows.Err(); err != nil {
		return sel, err
	}

	if opts.MaxTargets > 0 && len(sel.Targets) > opts.MaxTargets {
		sel.Targets = sel.Targets[:opts.MaxTargets]
		sel.Capped = true
		sel.ByMethod = map[string]int{}
		for _, t := range sel.Targets {
			sel.ByMethod[t.Method]++
		}
	}
	sel.Total = len(sel.Targets)
	return sel, nil
}

// VerbGroup is one sequential pass of a scan: a set of targets and the tool-specific mode to run
// them under. One scan runs its groups in order and folds every result into the same scan row, so
// the operator sees one scan with one result set rather than three.
type VerbGroup struct {
	// Label is what the operator reads, e.g. "GET" or "POST (JSON body)".
	Label string
	// Verb is the HTTP method this pass covers, and it is what per-verb settings key off. Kept
	// separate from Mode because they are not the same thing: Arjun runs two passes over the same
	// POST endpoints, so two groups share Verb "POST" while their Modes are "POST" and "JSON".
	Verb string
	// Mode is the value handed to the tool's own flag, whose meaning differs per tool: Arjun's -m
	// takes GET/POST/XML/JSON while x8's -X takes a real HTTP verb. Runners must not assume these
	// are interchangeable.
	Mode    string
	Targets []ParamTarget
}

// PlanVerbGroups splits targets into the passes a given tool can actually perform.
//
// The groups are per-tool capability axes, not the HTTP verb set, because the two tools do not
// agree on what a "method" is:
//
//   - x8   -X takes real HTTP verbs and accepts several at once.
//   - Arjun -m takes GET/POST/XML/JSON, which are request SHAPES. PUT, PATCH and DELETE are not
//     supported and fall through to POST inside requester.py, so offering them would silently
//     mislabel results. POST is run twice, form-encoded then JSON, because -m POST sends
//     form-encoded candidates and a modern API body is JSON, so form-only misses the real surface.
//     XML is deliberately not offered: bare -m XML raises inside requester, the exception is
//     swallowed, every URL is skipped and Arjun still exits 0.
func PlanVerbGroups(tool string, targets []ParamTarget) []VerbGroup {
	byVerb := map[string][]ParamTarget{}
	for _, t := range targets {
		byVerb[t.Method] = append(byVerb[t.Method], t)
	}

	get := byVerb["GET"]
	// Everything that is not a GET is body-bearing and is handled as a POST-shaped pass. Arjun
	// cannot express PUT/PATCH/DELETE at all, so folding them here is honest about what was
	// actually sent rather than inventing a flag.
	var write []ParamTarget
	for verb, list := range byVerb {
		if verb != "GET" {
			write = append(write, list...)
		}
	}
	sort.Slice(write, func(i, j int) bool { return write[i].URL < write[j].URL })

	var groups []VerbGroup
	add := func(label, verb, mode string, list []ParamTarget) {
		if len(list) > 0 {
			groups = append(groups, VerbGroup{Label: label, Verb: verb, Mode: mode, Targets: list})
		}
	}

	switch strings.ToLower(tool) {
	case "arjun":
		// Grouped by Arjun's four request shapes, not by HTTP verb, because that is what -m takes
		// and what each endpoint was categorised into.
		//
		// This replaces running every body endpoint TWICE, form-encoded then JSON, which was a hedge
		// against not knowing which one a route parsed. Now each endpoint carries its own answer
		// derived from its recorded Content-Type, so the hedge is unnecessary and the write half of
		// the scan costs half as many requests. The cost of the change is that a miscategorised
		// endpoint is tested in one shape only, which is why the category is editable per endpoint.
		byMode := map[string][]ParamTarget{}
		for _, t := range targets {
			byMode[t.ModeFor("arjun")] = append(byMode[t.ModeFor("arjun")], t)
		}
		for _, m := range ArjunModes {
			verb := "POST"
			if m == "GET" {
				verb = "GET"
			}
			add(m, verb, m, byMode[m])
		}
		return groups
	case "x8":
		// Grouped by injection place AND verb. A place can need two invocations, because --invert is
		// a single global flag: reaching the body of a GET and the body of a POST cannot be asked for
		// in one command, since the POST is already there by default and the GET needs inverting.
		//
		// The verb is part of the key for two measured reasons, both verified against x8 4.3.1:
		//
		//  1. x8's -X takes multiple VALUES but not multiple OCCURRENCES. Given "-X POST -X PUT" it
		//     exits 1 with "The argument '--method <methods>' was provided more than once", so a
		//     group holding two verbs failed as a whole and reported zero. Every target with both a
		//     POST and a PUT endpoint lost its entire body pass this way.
		//  2. Given the legal form "-X POST PUT", x8 tests EVERY url with EVERY method. Two urls and
		//     two verbs produced four url/method combinations on the wire, half of them requests no
		//     recorded endpoint ever answered, and any finding on one would be stored against a
		//     verb/url pair that does not exist.
		//
		// One verb per group avoids both. It costs more invocations and no extra requests.
		type x8Key struct {
			place  string
			verb   string
			invert bool
		}
		byKey := map[x8Key][]ParamTarget{}
		var order []x8Key
		for _, t := range targets {
			place := t.ModeFor("x8")
			k := x8Key{place, t.Method, X8NeedsInvert(t.Method, place)}
			if _, seen := byKey[k]; !seen {
				order = append(order, k)
			}
			byKey[k] = append(byKey[k], t)
		}
		placeOrder := map[string]int{}
		for i, place := range X8Places {
			placeOrder[place] = i
		}
		// Stable ordering: places in UI order, then verb alphabetically, then the plain pass before
		// the inverted one, so a stored `command` string is comparable between runs.
		sort.Slice(order, func(i, j int) bool {
			if placeOrder[order[i].place] != placeOrder[order[j].place] {
				return placeOrder[order[i].place] < placeOrder[order[j].place]
			}
			if order[i].verb != order[j].verb {
				return order[i].verb < order[j].verb
			}
			return !order[i].invert && order[j].invert
		})
		for _, k := range order {
			label := k.place + " " + k.verb
			mode := k.place
			if k.invert {
				label += " (inverted)"
				mode = k.place + "!"
			}
			add(label, k.verb, mode, byKey[k])
		}
		return groups
	default:
		add("GET", "GET", "GET", get)
		add("POST", "POST", "POST", write)
	}
	return groups
}

// TotalGroupWork is the denominator a progress bar needs. Summed across groups up front so
// processed/total never exceeds 1 partway through, which is what happens when total is written per
// group.
func TotalGroupWork(groups []VerbGroup) int {
	n := 0
	for _, g := range groups {
		n += len(g.Targets)
	}
	return n
}

// ParamHeaderLines renders configured headers as "Name: value", accepting both shapes that exist in
// the wild.
//
// The config modals write [{"key":"Authorization","value":"Bearer x"}] while every runner ranged
// over the map directly, so the pair was emitted as two headers literally named "key" and "value"
// and the real one never reached the target. The modals are fixed to write {"Authorization":"..."},
// but stored rows still carry the old shape, so both are read here rather than migrating rows and
// hoping none were missed.
func ParamHeaderLines(headers []map[string]string) []string {
	var out []string
	for _, h := range headers {
		if len(h) == 0 {
			continue
		}
		if name, value, ok := headerPairForm(h); ok {
			if name != "" {
				out = append(out, name+": "+value)
			}
			continue
		}
		names := make([]string, 0, len(h))
		for k := range h {
			names = append(names, k)
		}
		sort.Strings(names) // stable command lines make a stored `command` string comparable
		for _, k := range names {
			if strings.TrimSpace(k) != "" {
				out = append(out, k+": "+h[k])
			}
		}
	}
	return out
}

// headerPairForm detects the {"key":..,"value":..} shape the modals produce.
//
// Both halves must be present and they must be the only entries. Accepting a lone "key" would
// misread a genuine header named `key` as a pair and emit its value as the header name.
func headerPairForm(h map[string]string) (string, string, bool) {
	if len(h) != 2 {
		return "", "", false
	}
	var name, value string
	var haveName, haveValue bool
	for k, v := range h {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "key", "name":
			name, haveName = strings.TrimSpace(v), true
		case "value":
			value, haveValue = v, true
		}
	}
	return name, value, haveName && haveValue
}

// paramEnumGroupResult is what one verb group produced, so a runner can report per-group outcomes
// instead of one opaque total.
type paramEnumGroupResult struct {
	Label     string `json:"label"`
	Mode      string `json:"mode"`
	Endpoints int    `json:"endpoints"`
	Found     int    `json:"found"`
	Failed    bool   `json:"failed,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// StoreParameterFinding records one discovered parameter.
//
// ON CONFLICT DO NOTHING against the unique index, because a scan whose groups overlap (Arjun runs
// the same POST endpoints twice, form then JSON) would otherwise insert the same parameter twice
// and double the headline count. Returns whether a new row was actually written, so the counter
// reflects distinct findings rather than insert attempts.
//
// The conflict target includes parameter_type: the same name found in two different injection places
// is two findings, and keying without the place silently discarded the second one.
//
// exampleValue is the value that produced the difference where the tool reports one. x8 does for its
// non-random custom parameters, and that value is the finding: admin=true is the lead, not "admin".
// detectionReason is the tool's own words for why it reported the parameter.
func StoreParameterFinding(ctx context.Context, scanID, scanType, scopeTargetID, endpointURL,
	method, verbGroup, paramName, paramType, confidence, exampleValue, detectionReason string) bool {

	tag, err := dbPool.Exec(ctx, `
		INSERT INTO parameter_enumeration_results
		  (scan_id, scan_type, scope_target_id, endpoint_url, http_method, verb_group,
		   parameter_name, parameter_type, confidence, example_value, detection_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (scan_id, endpoint_url, http_method, parameter_name, parameter_type)
		DO NOTHING`,
		scanID, scanType, scopeTargetID, endpointURL, method, verbGroup,
		paramName, paramType, confidence, exampleValue, detectionReason)
	if err != nil {
		return false
	}
	return tag.RowsAffected() > 0
}
