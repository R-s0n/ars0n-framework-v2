package utils

import (
	"context"
	"sort"
	"strings"
	"time"
)

// The tools that TEST attack vectors, as one registry.
//
// XSS came first and SQL injection turned out to be the same shape: a set of scanners, each able to
// reach some subset of the five insertion points, each configured from a server-side store that the
// Config modal and the MCP tool both edit. Ten more sections are planned. Copying the settings
// store, the eligibility check, the runner and the API once per section would be roughly nine
// hundred lines duplicated twelve times, and the copies only have to disagree once for a scan to
// behave unlike the screen that configured it.
//
// So everything generic lives here and in vectorSettings.go, vectorEligibility.go, vectorScan.go and
// vectorAPI.go. What stays per tool is the part that genuinely differs: its option vocabulary, how a
// command line is built from a vector, and how its output is read. Those arrive as Compose and Parse
// on the struct below, which is the whole extension point.

// VectorOptionMeta is one setting: enough for a form field to be built from it and for a command
// line to be composed from it, without either side hardcoding the other's knowledge.
type VectorOptionMeta struct {
	Kind    string   `json:"kind"` // bool | int | float | string | enum | csv | path
	Group   string   `json:"group"`
	Label   string   `json:"label"`
	Flag    string   `json:"flag,omitempty"`
	Choices []string `json:"choices,omitempty"`
	// Placeholder says what the TOOL does when the option is not set, so an empty field reads as a
	// decision rather than as a gap.
	Placeholder string `json:"placeholder,omitempty"`
	// Repeatable options are passed once per value rather than comma joined. dalfox's -H and sqlmap's
	// --tamper differ here, and comma joining a header produces one header whose value has a comma.
	Repeatable bool `json:"repeatable,omitempty"`
}

// VectorFinding is one result, normalised across tools that agree on nothing.
type VectorFinding struct {
	VectorID string
	Tool     string
	// Kind is the tool's OWN confidence class, kept rather than flattened. dalfox's V and A, and
	// sqlmap's boolean-based versus error-based, mean genuinely different things, and collapsing them
	// would put an informational note beside a proven injection.
	Kind            string
	Severity        string
	Confidence      string
	InsertionPoint  string
	Param           string
	Payload         string
	Method          string
	URL             string
	Evidence        string
	DetectionMethod string
	InjectType      string
	RawRequest      string
	RawResponse     string
	// IsBypassTarget says whether VectorID names an attack vector or an access bypass target. The two
	// live in different tables with different foreign keys.
	IsBypassTarget bool
	// IsGraphQLTarget says the id names an endpoint from a tool's own settings list, which exists in
	// no table at all, so it is stored against neither foreign key.
	IsGraphQLTarget bool
	// IsLeakTarget marks a directory from the sensitive data leak list, which has its own table.
	IsLeakTarget bool
}

// VectorComposer turns one attack vector plus the stored settings into one command line. Returning
// nil args means the tool REFUSED this vector, and the warnings say why.
type VectorComposer func(v VectorInput, settings map[string]any, reportPath string) ([]string, []string)

// VectorParser reads whatever the tool produced. Given both the captured stdout and the contents of
// the report file, because the three XSS tools and the three SQL tools between them use both.
type VectorParser func(stdout, report string, row vectorRow) []VectorFinding

// VectorTool is one scanner: what it can reach, how it is configured, and how it is driven.
type VectorTool struct {
	Key             string                      `json:"key"`
	Name            string                      `json:"name"`
	Category        string                      `json:"category"`
	Binary          string                      `json:"binary"`
	Container       string                      `json:"container"`
	Groups          []string                    `json:"groups"`
	Options         map[string]VectorOptionMeta `json:"options"`
	OwnedFlags      map[string]string           `json:"owned_flags"`
	InsertionPoints []string                    `json:"insertion_points"`
	Limitation      string                      `json:"limitation,omitempty"`

	// Blinding names settings that make an insertion point untestable while the scan still exits 0
	// and reports nothing. Keyed by setting, valued by the point it blinds, or "all".
	Blinding map[string]string `json:"blinding,omitempty"`

	// ReportPath is set when the tool writes its findings to a file rather than to stdout. The runner
	// reads that file back out of the shared /tmp volume.
	UsesReportFile bool `json:"-"`

	Compose    VectorComposer      `json:"-"`
	Parse      VectorParser        `json:"-"`
	SkipReason func(string) string `json:"-"`

	// AttemptsWhenEmpty is how many times to run a FLAKY detector on one vector before believing it
	// found nothing. Findings stop the retries immediately, so a working tool pays nothing.
	//
	// pphack is why. It drives headless Chrome and watches whether the page's own JavaScript merges
	// the payload into Object.prototype, and whether that happens depends on script load timing.
	// Measured against ginandjuice.shop/blog, which is definitively vulnerable and which pphack
	// reports on demand from the command line: 3 hits in 6 identical runs. One run per vector is a
	// coin flip, and the framework ran each vector exactly once, so 24 vectors came back clean on a
	// target whose prototype pollution the tool finds in seconds when asked twice.
	//
	// Left at 0 for every deterministic tool, where a retry would only double the traffic.
	AttemptsWhenEmpty int `json:"-"`

	// Incomplete reports, from the tool's own output, that the run DID NOT FINISH, and why. A
	// non-empty return marks the vector as an error rather than clean, while any findings already
	// parsed are still kept.
	//
	// This exists because a tool can tell you it gave up and the runner can still file the result as
	// clean. dalfox aborted every one of 53 vectors on --on-session-loss abort, writing
	// {"meta":{"findings_count":0,"incomplete":true,...,"error_code":"SESSION_LOST"}}, and the parser
	// skips meta lines, so the reason was read and thrown away. The operator saw 53 clean vectors on
	// an application whose own /vulnerabilities page lists four separate XSS.
	Incomplete func(stdout, report string) string `json:"-"`

	// VectorEligible refuses an INDIVIDUAL vector, with a reason, where the insertion point alone is
	// not the whole story.
	//
	// Commix is why this exists. It reaches a header only at --level 3, and only for the three names
	// it knows: user-agent, referer and host. Measured, a Referer carrying the bug is found and a
	// custom X-Name carrying the same bug is not, even with commix's own INJECT_HERE marker. Saying
	// "commix can reach headers" would then be true and useless, because every header vector this
	// framework produces is a custom one.
	VectorEligible func(VectorInput) (bool, string) `json:"-"`

	// RequiresFinding gates a tool on what an earlier scan already found.
	//
	// The Open Redirect and SSRF section is why. REcollapse mutates a value to get past a validation
	// regex and SSRFmap pivots an SSRF into file read or worse; neither DETECTS anything, and both
	// are meaningless against a parameter that has not been shown to redirect or to fetch. Running
	// them across a whole vector table would be thousands of requests to learn nothing, and in
	// SSRFmap's case would aim internal port scans at a target on the strength of a guess.
	//
	// The value is the category whose findings count, so a tool is gated on another tool's work.
	RequiresFinding string `json:"requires_finding,omitempty"`

	// RequiresSectionSetting names a SECTION setting the tool cannot work without.
	//
	// The webhook is why. A payload that points at a callback URL nobody configured points at
	// nothing, and the scan then completes having proved only that an empty string is not an SSRF.
	// Reported as ineligible with the reason rather than run.
	RequiresSectionSetting string `json:"requires_section_setting,omitempty"`

	// DedupeKey collapses vectors that would produce the SAME scan.
	//
	// The cache tools are why this exists. They take a URL and discover unkeyed inputs from their own
	// wordlists; they do not test the parameter a vector names. Seventy-one vectors across thirty-odd
	// URLs would therefore run the same multi-thousand-request scan over and over against the same
	// URL, which is wasteful against our own infrastructure and abusive against someone else's. When
	// set, one representative per key is scanned and the findings are attributed to every vector that
	// shares it. Nil means one scan per vector, which is right for XSS and SQL injection because
	// there the vector IS the thing being tested.
	DedupeKey func(VectorInput) string `json:"-"`

	// ScanUnit names what a run counts, for a tool whose unit is neither a vector nor a URL.
	ScanUnit string `json:"-"`

	// RowSource replaces the attack vector table as the thing this tool scans.
	//
	// The access control bypass section is why. Its targets are the URLs that already answered 401 or
	// 403 to something an earlier tool sent, consolidated from six tables that record an HTTP status.
	// Those are not attack vectors and must not be put in that table: every other section loads it
	// wholesale, so a few hundred 403 URLs would quietly become XSS and SQL injection targets too.
	RowSource func(context.Context, string) ([]vectorRow, error) `json:"-"`

	// Runs are the sub-scans a single vector needs. CacheBoom's -m is required and takes one of cd or
	// cp, so covering both means running it twice. Empty means a single unlabelled run.
	Runs []string `json:"runs,omitempty"`

	// Timeout bounds one run. Zero means the default.
	Timeout time.Duration `json:"-"`

	// TimeoutIsNormal marks a tool that does not exit on its own. CacheBoom's deception mode blocks
	// forever on task_queue.join(), because its workers return on the found flag without calling
	// task_done() for the items still queued: it finds the bug, prints it, and never terminates.
	// Killing it is the expected end of a successful run, not an error to report.
	TimeoutIsNormal bool `json:"-"`
}

// VectorInsertionPoints is every insertion point an attack vector can carry. Kept here so an
// eligibility report can name the ones a tool CANNOT reach, not only the ones it can.
var VectorInsertionPoints = []string{"query", "body", "header", "cookie", "path"}

// VectorCanary is the value substituted for a parameter whose name is known but whose value was
// never observed. On the reference target 16 of 27 query vectors are in that state: discovered by
// Arjun, x8 or ffuf, never seen carrying anything.
//
// It matters for more than tidiness. SQLiDetector and xssFuzz both substitute by matching the
// parameter in the URL TEXT, so a parameter that is not physically present matches nothing and the
// tool reports clean. Same word the ffuf baseline uses, so an operator grepping a proxy log for
// rs0n finds everything this framework injected regardless of which tool sent it.
const VectorCanary = FuzzCanaryValue

// vectorRegistry is populated by the per-category files in their init functions, so adding a section
// is adding a file rather than editing this one.
var vectorRegistry []VectorTool

func registerVectorTools(tools ...VectorTool) {
	vectorRegistry = append(vectorRegistry, tools...)
}

// VectorCategories is the display name for each section, in the order the cards appear.
var VectorCategories = []struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}{
	{"xss", "Cross-Site Scripting"},
	{"sqli", "SQL & NoSQL Injection"},
}

// VectorToolsFor returns one section's tools, in registration order.
func VectorToolsFor(category string) []VectorTool {
	var out []VectorTool
	for _, t := range vectorRegistry {
		if t.Category == category {
			out = append(out, t)
		}
	}
	return out
}

// VectorToolByKey looks up one tool. Returns false rather than a zero value, so a bad key from an
// API caller is an error at the edge instead of a scan that runs with no options and no composer.
func VectorToolByKey(key string) (VectorTool, bool) {
	for _, t := range vectorRegistry {
		if t.Key == key {
			return t, true
		}
	}
	return VectorTool{}, false
}

// VectorToolCanReach reports whether a tool can actually fuzz an insertion point.
func VectorToolCanReach(tool VectorTool, insertionPoint string) bool {
	for _, p := range tool.InsertionPoints {
		if p == insertionPoint {
			return true
		}
	}
	return false
}

// UnrecognisedVectorOptions reports keys nothing reads. Never silently dropped: an option that is
// stored and ignored is exactly how a caller comes to believe a setting took effect.
func UnrecognisedVectorOptions(tool VectorTool, settings map[string]any) []string {
	var unknown []string
	for key := range settings {
		if _, ok := tool.Options[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// vectorSettingEngaged reports whether a setting is actually in force.
//
// A switch is engaged when it is true. A setting that carries a VALUE is engaged when it has any
// value at all, which is the whole reason this function exists: dalfox's userAgent blinds the entire
// tool, and truthySetting("Mozilla/5.0 ...") is false, so a value-carrying blinder was invisible to
// the one check whose job is to catch blinders.
func vectorSettingEngaged(tool VectorTool, key string, value any) bool {
	switch tool.Options[key].Kind {
	case "string", "csv", "path", "enum":
		return strings.TrimSpace(stringifySetting(value)) != ""
	default:
		return truthySetting(value)
	}
}

// VectorBlindedPoints reports which insertion points a settings map would silently make untestable.
func VectorBlindedPoints(toolKey string, settings map[string]any) map[string][]string {
	tool, ok := VectorToolByKey(toolKey)
	if !ok || tool.Blinding == nil {
		return nil
	}
	blinded := map[string][]string{}
	for key, point := range tool.Blinding {
		if !vectorSettingEngaged(tool, key, settings[key]) {
			continue
		}
		blinded[point] = append(blinded[point], key)
	}
	for k := range blinded {
		sort.Strings(blinded[k])
	}
	return blinded
}
