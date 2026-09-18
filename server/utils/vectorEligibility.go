package utils

import (
	"context"
	"sort"
	"strings"
	"unicode"
)

// Which vectors a tool can actually test, and why the rest were left out.
//
// This exists because most of these tools cover a minority of the vector table and none of them says
// so. Handed a header vector, domdig scans its query string, finds nothing and exits 0. Handed a
// body vector, SQLiDetector does the same. There is no error to notice. The operator reads "0
// findings" and concludes the header is safe, when in fact it was never tested.
//
// So the count on the card is eligible-of-total rather than total, every skipped vector carries the
// reason it was skipped, and the reason is a fact about the tool rather than a shrug. Same idea as
// the ffuf baseline stating why a finding was excluded, applied one level up.

// VectorEligibility is the verdict for one vector against one tool.
type VectorEligibility struct {
	VectorID       string `json:"vector_id"`
	InsertionPoint string `json:"insertion_point"`
	Eligible       bool   `json:"eligible"`
	Reason         string `json:"reason,omitempty"`
	// IsBypassTarget says which table VectorID belongs to, so a skipped row is recorded against the
	// column whose foreign key will accept it.
	IsBypassTarget bool `json:"is_bypass_target,omitempty"`
	// IsGraphQLTarget and TargetURL are for a target that exists in no table, where the URL is the
	// only identity there is.
	IsGraphQLTarget bool   `json:"is_graphql_target,omitempty"`
	IsLeakTarget    bool   `json:"is_leak_target,omitempty"`
	TargetURL       string `json:"target_url,omitempty"`
}

// VectorEligibilityReport is the whole picture for one tool: enough to draw the card, and enough for
// an operator to challenge it.
type VectorEligibilityReport struct {
	Tool           string         `json:"tool"`
	ToolName       string         `json:"tool_name"`
	Category       string         `json:"category"`
	Total          int            `json:"total"`
	Eligible       int            `json:"eligible"`
	ByPoint        map[string]int `json:"by_point"`
	SkippedByPoint map[string]int `json:"skipped_by_point"`
	Reachable      []string       `json:"reachable"`
	Unreachable    []string       `json:"unreachable"`
	Limitation     string         `json:"limitation,omitempty"`
	// ScanCount is how many invocations a run will actually make. For the cache tools, whose unit of
	// work is a URL rather than a parameter, it is far smaller than Eligible, and it is the number
	// the progress bar counts against. Equal to Eligible for everything else.
	ScanCount int `json:"scan_count"`
	// ScanUnit names what ScanCount counts, so a card can say "34 URLs" rather than "34".
	ScanUnit string              `json:"scan_unit"`
	Blinded  map[string][]string `json:"blinded,omitempty"`
	Vectors  []VectorEligibility `json:"vectors,omitempty"`
}

// vectorSkipReason says, in the operator's terms, why this tool cannot test this insertion point.
// Written per tool rather than generically because "the tool does not support it" is not actionable
// and invites the reader to assume it is a framework limitation that will be fixed.
func vectorSkipReason(tool VectorTool, insertionPoint string) string {
	own := ""
	if tool.SkipReason != nil {
		own = tool.SkipReason(insertionPoint)
	}
	if insertionPoint == "fragment" && !mentionsFragment(own) {
		// The fragment is the one point whose reason is a fact about HTTP rather than about the
		// tool, so it is stated once here rather than repeated in thirty per-tool SkipReason
		// functions. A tool with something specific to say still wins, which is what the
		// mentionsFragment check is for: without it the catch-all default most of those functions
		// end in, "SQLiDetector can only test a query parameter", would be returned for a fragment.
		// That sentence is true and it is the wrong answer. It reads as a parameter-shape limitation
		// the operator might work around, when the real fact is that nothing SQLiDetector sends
		// could ever carry a fragment.
		//
		// It matters that this reads as a capability statement and not as a defect. An operator
		// seeing "0 of 4 fragment vectors eligible" on sqlmap has to be able to tell that nothing
		// was missed, because there was never anything for an HTTP tool to send.
		return tool.Name + " sends HTTP requests, and a URL fragment is never sent: the client " +
			"strips it before the request leaves, so it appears in no request line and no header. " +
			"Only a tool that drives a real browser can put a payload there. In this framework that " +
			"is domdig, whose fuzz mode injects into the hash."
	}
	if own != "" {
		return own
	}
	return tool.Name + " cannot reach a " + insertionPoint + " insertion point."
}

// mentionsFragment reports whether a tool's own skip reason is actually ABOUT the URL fragment,
// rather than a catch-all that happens to have been handed one.
//
// "hash" has to count, because that is what domdig and most operators call the fragment. It counts
// only as a WHOLE WORD and only beside "url", because the substring is everywhere else too: a
// response hash, a hash parameter, a password hash, hashcat, hashes. A catch-all ending in any of
// those would be returned INSTEAD of the shared fragment explanation, and a catch-all like
// "SQLiDetector can only test a query parameter" reads as a parameter-shape limitation an operator
// might work around rather than as the fact that nothing SQLiDetector sends could ever carry a
// fragment. That is the exact failure this guard was written to prevent, so the guard must not be
// the thing that causes it. A literal "#" counts too: nothing else in a skip reason writes one.
func mentionsFragment(reason string) bool {
	lowered := strings.ToLower(reason)
	if strings.Contains(lowered, "fragment") || strings.Contains(lowered, "#") {
		return true
	}
	words := strings.FieldsFunc(lowered, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for i, word := range words {
		if word != "hash" {
			continue
		}
		// The qualifier sits within a few words either side: "the URL hash", "the hash of the URL",
		// "injects into the hash in the URL".
		for j := i - 3; j <= i+3; j++ {
			if j < 0 || j >= len(words) || j == i {
				continue
			}
			if words[j] == "url" || words[j] == "urls" {
				return true
			}
		}
	}
	return false
}

// vectorPointNeedsOptIn reports whether this tool would reach the point but has not been asked to.
//
// Checked BEFORE the per-vector predicate and before the blinding rules, because "you did not ask
// for this" is a cheaper and more honest answer than any of them, and because reporting a
// deliberately-off point as "blinded by settings" would read as a misconfiguration.
func vectorPointNeedsOptIn(tool VectorTool, insertionPoint string, settings map[string]any) bool {
	setting, isOptIn := tool.OptInPoints[insertionPoint]
	if !isOptIn {
		return false
	}
	return !settingIsTrue(settings[setting])
}

// settingIsTrue reads a stored switch. Settings arrive from JSON, so a bool may have survived as a
// bool, as a string, or as a number, and only an explicit true turns an opt-in point on.
func settingIsTrue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1" || s == "yes" || s == "on"
	case float64:
		return v != 0
	case int:
		return v != 0
	}
	return false
}

// vectorOptInReason says the point was not tested BY CHOICE, names the switch that changes it, and
// says what the default is protecting. An operator reading a zero has to be able to tell "off by
// default" from "this tool cannot do that", and the two must never share wording.
func vectorOptInReason(tool VectorTool, insertionPoint string) string {
	setting := tool.OptInPoints[insertionPoint]
	return tool.Name + " can reach a " + insertionPoint + " insertion point but does not by default, " +
		"so nothing was sent here and this is not a clean result. Turn on \"" + setting + "\" to " +
		"include " + insertionPoint + " vectors. The default is off because " + tool.Name +
		" spends its budget in vector order: on a 249-vector corpus it covered body, header and " +
		"cookie in full and never reached a single query or path vector, which are the two points " +
		"most likely to carry a finding."
}

// BuildVectorEligibility works out what a scan with this tool would actually cover.
//
// alreadyFound holds the vector ids an earlier scan in this category has produced findings for, and
// is what gates the tools that only have work to do once something has been detected. Nil is fine
// for every tool that detects things itself.
// BuildVectorEligibilityFor is BuildVectorEligibility plus the operator's own per-vector choices.
//
// deselected holds the vector ids this tool has been switched OFF for, loaded from
// vector_scan_selection. Absent means enabled, so nil is the correct value for "the operator has not
// said anything" and every caller that does not care about selection can keep using
// BuildVectorEligibility unchanged.
func BuildVectorEligibilityFor(tool VectorTool, vectors []vectorRow, settings map[string]any,
	alreadyFound map[string]bool, sectionSettings map[string]any,
	deselected map[string]bool) VectorEligibilityReport {

	return buildVectorEligibility(tool, vectors, settings, alreadyFound, sectionSettings, deselected)
}

func BuildVectorEligibility(tool VectorTool, vectors []vectorRow, settings map[string]any,
	alreadyFound map[string]bool, sectionSettings map[string]any) VectorEligibilityReport {

	return buildVectorEligibility(tool, vectors, settings, alreadyFound, sectionSettings, nil)
}

func buildVectorEligibility(tool VectorTool, vectors []vectorRow, settings map[string]any,
	alreadyFound map[string]bool, sectionSettings map[string]any,
	deselected map[string]bool) VectorEligibilityReport {
	report := VectorEligibilityReport{
		Tool:           tool.Key,
		ToolName:       tool.Name,
		Category:       tool.Category,
		Total:          len(vectors),
		ByPoint:        map[string]int{},
		SkippedByPoint: map[string]int{},
		Reachable:      tool.InsertionPoints,
		Limitation:     tool.Limitation,
		Blinded:        VectorBlindedPoints(tool.Key, settings),
	}

	for _, point := range VectorInsertionPoints {
		if !VectorToolCanReach(tool, point) {
			report.Unreachable = append(report.Unreachable, point)
		}
	}
	sort.Strings(report.Unreachable)

	for _, v := range vectors {
		verdict := VectorEligibility{VectorID: v.ID, InsertionPoint: v.InsertionPoint,
			IsBypassTarget: v.IsBypassTarget, IsGraphQLTarget: v.IsGraphQLTarget,
			IsLeakTarget: v.IsLeakTarget, TargetURL: v.EvidenceURL}
		perVectorOK, perVectorWhy := true, ""
		if tool.VectorEligible != nil {
			perVectorOK, perVectorWhy = tool.VectorEligible(v.toInput())
		}

		switch {
		// The operator's own choice is checked FIRST and states itself plainly.
		//
		// Deliberately ahead of every capability reason, because when a vector is both switched off
		// and unreachable by this tool, the decisive fact is that someone switched it off. Reporting
		// the capability reason instead would hide the selection: the operator would look for their
		// deselection, see "this tool cannot reach a header insertion point", and reasonably conclude
		// the switch had not saved. Turning it back on reveals the capability reason underneath,
		// which is the honest order to learn them in.
		case deselected[v.ID]:
			verdict.Reason = "Deselected for " + tool.Name + " in its Config. The vector is still " +
				"here and still scanned by every other tool it was not deselected for; switch it " +
				"back on to include it in this one."
		case !VectorToolCanReach(tool, v.InsertionPoint):
			verdict.Reason = vectorSkipReason(tool, v.InsertionPoint)
		case vectorPointNeedsOptIn(tool, v.InsertionPoint, settings):
			verdict.Reason = vectorOptInReason(tool, v.InsertionPoint)
		case !perVectorOK:
			verdict.Reason = perVectorWhy
		case tool.RequiresSectionSetting != "" &&
			strings.TrimSpace(stringifySetting(sectionSettings[tool.RequiresSectionSetting])) == "":
			verdict.Reason = "The webhook is not configured yet. " + tool.Name + " builds its payloads " +
				"out of it, so there is nothing to send until it is filled in. Set it on the Webhook " +
				"tab of " + tool.Name + "'s Config."
		case tool.RequiresFinding != "" && !alreadyFound[v.ID]:
			verdict.Reason = "Nothing has been found on this vector yet. " + tool.Name + " works on a " +
				"parameter that has already been shown to be vulnerable, so run the detector first " +
				"and this becomes eligible for whatever it finds."
		case len(report.Blinded["all"]) > 0:
			verdict.Reason = "The current settings (" + joinAnd(report.Blinded["all"]) +
				") stop this tool sending payloads at all."
		case len(report.Blinded[v.InsertionPoint]) > 0:
			verdict.Reason = "The current settings (" + joinAnd(report.Blinded[v.InsertionPoint]) +
				") turn off the only mechanism that reaches a " + v.InsertionPoint + " insertion point."
		default:
			verdict.Eligible = true
		}

		if verdict.Eligible {
			report.Eligible++
			report.ByPoint[v.InsertionPoint]++
		} else {
			report.SkippedByPoint[v.InsertionPoint]++
		}
		report.Vectors = append(report.Vectors, verdict)
	}

	report.ScanCount, report.ScanUnit = report.Eligible, "vector"
	if tool.DedupeKey != nil {
		report.ScanUnit = "URL"
		if tool.ScanUnit != "" {
			report.ScanUnit = tool.ScanUnit
		}
		seen := map[string]bool{}
		for i, v := range vectors {
			if !report.Vectors[i].Eligible {
				continue
			}
			seen[tool.DedupeKey(v.toInput())] = true
		}
		report.ScanCount = len(seen)
	}
	return report
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	out := ""
	for i, item := range items[:len(items)-1] {
		if i > 0 {
			out += ", "
		}
		out += item
	}
	return out + " and " + items[len(items)-1]
}

// loadRowsFor returns the things a given tool scans.
//
// Most tools scan attack vectors. A tool that declares a RowSource scans something else entirely,
// and every caller goes through here so a section with its own targets cannot be wired into the
// runner but forgotten in the eligibility report, which would then describe a scan of the wrong
// table.
func loadRowsFor(ctx context.Context, tool VectorTool, scopeTargetID string) ([]vectorRow, error) {
	if tool.RowSource != nil {
		return tool.RowSource(ctx, scopeTargetID)
	}
	return loadVectorRows(ctx, scopeTargetID)
}

// loadVectorRows reads the attack vectors a scan would run against.
//
// Deleted rows are excluded for the same reason they are everywhere else: an operator who deleted a
// vector has said it is not worth testing, and resurrecting it in a scan would undo that by hand
// every time.
func loadVectorRows(ctx context.Context, scopeTargetID string) ([]vectorRow, error) {
	// The response content type comes along for the ride, as a CORRELATED SUBQUERY rather than a
	// join, because consolidated_url_endpoints holds one row per method per path and a join would
	// multiply every vector by however many of them there are.
	//
	// It is here for the browser-driven tools. domdig navigates a real Chromium and refuses anything
	// that is not text/html, one "[!] Content type is not text/html" per payload, so pointing it at a
	// JSON API burns the full scan budget and reports nothing. Measured on this estate: of 30 query
	// vectors, 14 are known JSON, 2 are known text/html, and 14 are unknown. Without this column all
	// 30 look identical to the eligibility check.
	//
	// TWO SOURCES, because the consolidated table is the poorer one. It holds a content type for 202
	// of 1060 endpoints here, since the rows that come from archives, LinkFinder and ffuf are URLs
	// nobody fetched. endpoint_validation_results is where the Validate step records what actually
	// came back, and it has one for 1673 of 1934 rows. Consulting both recovered 3 more of the 14
	// unknown query vectors, and all 3 agreed with a hand probe of the live endpoint.
	rows, err := dbPool.Query(ctx, `
		SELECT av.id::text, COALESCE(av.method,'GET'), COALESCE(av.scheme,'https'), COALESCE(av.domain,''),
		       COALESCE(av.port,0), COALESCE(av.path,'/'), COALESCE(av.insertion_point,'query'),
		       COALESCE(av.parameters, ARRAY[]::text[]), COALESCE(av.evidence_url,''),
		       COALESCE(av.raw_request,''), COALESCE(av.fragment,''),
		       COALESCE(av.reflection_status,''),
		       COALESCE((SELECT p.content_type FROM vector_reflection_probes p
		                 WHERE p.vector_id = av.id AND p.status = av.reflection_status
		                 ORDER BY p.probed_at DESC LIMIT 1), ''),
		       COALESCE((SELECT p.survived FROM vector_reflection_probes p
		                 WHERE p.vector_id = av.id AND p.status = av.reflection_status
		                 ORDER BY p.probed_at DESC LIMIT 1), ARRAY[]::text[]),
		       COALESCE(
		         (SELECT e.content_type FROM consolidated_url_endpoints e
		          WHERE e.scope_target_id = av.scope_target_id AND e.path = av.path
		            AND COALESCE(e.content_type,'') <> ''
		          ORDER BY e.last_seen DESC LIMIT 1),
		         (SELECT r.content_type FROM endpoint_validation_results r
		          JOIN consolidated_url_endpoints e2 ON e2.id = r.endpoint_id
		          WHERE r.scope_target_id = av.scope_target_id AND e2.path = av.path
		            AND COALESCE(r.content_type,'') <> ''
		          ORDER BY r.id DESC LIMIT 1),
		         '')
		FROM attack_vectors av
		WHERE av.scope_target_id = $1 AND av.deleted_at IS NULL
		ORDER BY av.insertion_point, av.domain, av.path`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []vectorRow
	for rows.Next() {
		var v vectorRow
		if err := rows.Scan(&v.ID, &v.Method, &v.Scheme, &v.Domain, &v.Port, &v.Path,
			&v.InsertionPoint, &v.Parameters, &v.EvidenceURL, &v.RawRequest,
			&v.Fragment, &v.ReflectionStatus, &v.ReflectionContentType, &v.ReflectionSurvived,
			&v.ResponseContentType); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// vectorRow is one attack_vectors row, as much of it as a scan needs.
type vectorRow struct {
	ID             string
	Method         string
	Scheme         string
	Domain         string
	Port           int
	Path           string
	InsertionPoint string
	Parameters     []string
	EvidenceURL    string
	RawRequest     string
	// Fragment is the client-side route or anchor, without its leading hash. Only a fragment vector
	// carries one, and without it a browser-driven tool would be pointed at the page rather than at
	// the view the payload has to be read in.
	Fragment string

	// ReflectionStatus is the summary of the reflection probe across this vector's parameters, and
	// ReflectionContentType is what the endpoint answered with on the probe that produced it. They
	// travel together because the GRADE needs both: raw reflection into text/html is a live lead and
	// raw reflection into application/json is the /api/v1/echo case, real but unrenderable.
	ReflectionStatus      string
	ReflectionContentType string
	// ReflectionSurvived is which of < > " ' came back unencoded on the probe that produced the
	// headline status. It travels with the content type because the grade needs both: a single
	// quote surviving a JSON response is an artefact of JSON escaping, not evidence of anything.
	ReflectionSurvived []string

	// ResponseContentType is what this endpoint was last seen answering with, or "" when nothing
	// observed it. Empty means UNKNOWN, never "not html": a tool that skipped on unknown would drop
	// every vector the crawls never reached, which is the larger loss.
	ResponseContentType string

	// IsBypassTarget marks a row that came from access_bypass_targets rather than attack_vectors.
	//
	// It changes which COLUMN the runner records against, and it has to: vector_id has a foreign key
	// onto attack_vectors, so writing a bypass target's id there fails the insert and the scan
	// records nothing at all for a target it really did scan.
	IsBypassTarget bool
	// IsGraphQLTarget marks a row that came from a tool's own endpoint list rather than from any
	// table. Those endpoints are not rows anywhere: the list IS the tool's settings, so there is no
	// id to reference and the scan records them by URL.
	IsGraphQLTarget bool
	// IsLeakTarget marks a directory from the sensitive data leak list, which has its own table.
	IsLeakTarget bool
	// BaselineStatus is the 4xx the target was originally seen returning. It is the control every
	// reported bypass is judged against, so a result that merely reproduces the original denial can
	// be told apart from one that got past it.
	BaselineStatus int
}

// toInput converts a stored row into the composer's input, pulling the content type and body out of
// the recorded raw request. A JSON body targeted as form-encoded is injected in the wrong syntax and
// silently misses, so the content type is worth the parse.
func (v vectorRow) toInput() VectorInput {
	in := VectorInput{
		VectorID:       v.ID,
		Method:         v.Method,
		Scheme:         v.Scheme,
		Domain:         v.Domain,
		Port:           v.Port,
		Path:           v.Path,
		InsertionPoint: v.InsertionPoint,
		Parameters:     v.Parameters,
		EvidenceURL:    v.EvidenceURL,
		Fragment:       v.Fragment,

		ResponseContentType: v.ResponseContentType,

		ObservedValues: map[string]string{},
	}
	if v.RawRequest != "" {
		in.ContentType, in.Body = rawRequestBody(v.RawRequest)
		in.RawRequestOverride = v.RawRequest
	}
	for name, value := range observedQueryValues(v.EvidenceURL) {
		in.ObservedValues[name] = value
	}
	// A cookie or header vector's value lives in the raw request rather than in the URL, and without
	// it the marker would be attached to the canary and the request would stop being the one that was
	// observed. A session cookie replaced by rs0n is a request that 401s, and a 401 injects nothing.
	for name, value := range observedRequestValues(v.RawRequest, v.InsertionPoint) {
		if _, seen := in.ObservedValues[name]; !seen {
			in.ObservedValues[name] = value
		}
	}
	return in
}

// loadFoundVectorIDs returns the vectors that any completed scan in this category has produced a
// finding for. It is what makes an exploitation tool eligible: not "this vector exists" but "the
// detector already showed this one is vulnerable".
// findingCategoryFor is the category whose findings gate this tool.
//
// RequiresFinding is documented as "the category whose findings count, so a tool is gated on
// another tool's work", but every caller used to pass tool.Category instead, and nothing noticed
// because the only tool that declares it (ssrfmap) has the same string for both. The first genuine
// cross-category gate anybody wrote would have read the WRONG category's findings, found none, and
// left the tool permanently ineligible with no error anywhere.
func findingCategoryFor(tool VectorTool) string {
	if tool.RequiresFinding != "" {
		return tool.RequiresFinding
	}
	return tool.Category
}

func loadFoundVectorIDs(ctx context.Context, scopeTargetID, category string) map[string]bool {
	found := map[string]bool{}
	// COALESCE across every identity a finding can carry, not just vector_id.
	//
	// A target is an attack vector, an access bypass target or a sensitive leak directory depending on
	// the section, and only one of those columns is ever populated. Reading vector_id alone made this
	// return nothing for the sections that use the others, which does not fail: it silently marks
	// every gated tool ineligible, so git-dumper would refuse to run on a repository the detector had
	// just found.
	rows, err := dbPool.Query(ctx, `
		SELECT DISTINCT COALESCE(f.vector_id, f.bypass_target_id, f.leak_target_id)::text
		FROM vector_findings f
		JOIN vector_scans s ON s.id = f.scan_id
		WHERE s.scope_target_id = $1 AND s.category = $2
		  AND COALESCE(f.vector_id, f.bypass_target_id, f.leak_target_id) IS NOT NULL
		  AND f.triage <> 'dismissed'`, scopeTargetID, category)
	if err != nil {
		return found
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			found[id] = true
		}
	}
	return found
}
