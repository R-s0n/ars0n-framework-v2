package utils

import (
	"strings"
	"testing"
)

// The GraphQL section, measured against a lab with three endpoints that differ in exactly the ways
// the tools care about:
//
//	/graphql           introspection ON,  suggestions ON
//	/graphql-nointro   introspection OFF, suggestions ON   (clairvoyance's reason to exist)
//	/graphql-hardened  introspection OFF, suggestions OFF  (nothing is recoverable)
//	/notgraphql        an ordinary JSON endpoint

// The endpoint list is per tool, in that tool's own settings, by the operator's decision. So each
// tool's targets come from its own list and nothing is shared.
func TestGraphQLToolsScanTheirOwnEndpointList(t *testing.T) {
	for _, key := range graphqlSectionTools {
		tool, ok := VectorToolByKey(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		if tool.RowSource == nil {
			t.Errorf("%s must take its targets from its own endpoint list", key)
		}
		if tool.ScanUnit != "endpoint" {
			t.Errorf("%s scans an endpoint, and the card has to say so", key)
		}
		if _, ok := tool.Options[graphqlEndpointsSetting]; !ok {
			t.Errorf("%s has no endpoints setting, so it can never be given a target", key)
		}
	}
}

// Whatever the operator types has to become a usable list of URLs. A textarea produces newlines, the
// MCP server sends a string, and someone will paste a comma separated line.
func TestGraphQLEndpointListAcceptsWhatPeopleActuallyType(t *testing.T) {
	got := splitEndpointList("https://a.test/graphql\n  https://b.test/gql  \n\nhttps://a.test/graphql,c.test/api")
	want := []string{"https://a.test/graphql", "https://b.test/gql", "https://c.test/api"}

	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: expected %q, got %q", i, want[i], got[i])
		}
	}

	// A bare host gains a scheme, because two of the three tools behave differently without one.
	if got[2] != "https://c.test/api" {
		t.Errorf("a bare host must be made explicit: %q", got[2])
	}
	// And the duplicate is dropped rather than scanned twice.
	if len(splitEndpointList("x.test/graphql\nx.test/graphql")) != 1 {
		t.Error("the same endpoint listed twice is one target")
	}
}

// An endpoint keeps the same identity between runs, so its history stays attached to it.
func TestGraphQLEndpointIDIsStable(t *testing.T) {
	a := graphqlEndpointID("target-1", "graphql-cop", "https://x.test/graphql")
	b := graphqlEndpointID("target-1", "graphql-cop", "https://x.test/graphql")
	if a != b {
		t.Error("the same endpoint must keep the same id, or its findings detach on every run")
	}
	if graphqlEndpointID("target-1", "clairvoyance", "https://x.test/graphql") == a {
		t.Error("two tools' lists are separate, so the same URL is a different row in each")
	}
	if len(a) != 36 || strings.Count(a, "-") != 4 {
		t.Errorf("the scan tables take a uuid: %q", a)
	}
}

// The load generating checks are off unless asked for, and the exclusion is built from a verified
// vocabulary.
//
// This is not a preference. graphql-cop's -e IGNORES a name it does not recognise: it prints
// "<name> cannot be excluded, skipping" and then runs that check anyway. So an exclusion built from
// anything other than the real registry is a load generating query sent to a production endpoint by
// an operator who believed it was turned off.
func TestGraphqlCopExcludesLoadGeneratingChecksByDefault(t *testing.T) {
	v := VectorInput{EvidenceURL: "https://x.test/graphql"}
	args, warnings := ComposeGraphqlCop(v, map[string]any{}, "/tmp/rep")

	// Compared as whole names, not substrings: "introspection" is a substring of
	// "circular_query_introspection", so a Contains check here reports the wrong thing.
	excludedSet := map[string]bool{}
	for _, name := range strings.Split(argValueAfter(args, "-e"), ",") {
		excludedSet[strings.TrimSpace(name)] = true
	}
	for _, test := range graphqlCopTests {
		if test.DoS && !excludedSet[test.Flag] {
			t.Errorf("%s generates load and must be excluded by default", test.Flag)
		}
		if !test.DoS && excludedSet[test.Flag] {
			t.Errorf("%s is informational and should still run", test.Flag)
		}
	}
	if len(warnings) == 0 {
		t.Error("leaving checks out on the operator's behalf must be reported")
	}

	// Turning one on runs it, and says so.
	on, onWarnings := ComposeGraphqlCop(v, map[string]any{"aliasOverloading": true}, "/tmp/rep")
	onExcluded := map[string]bool{}
	for _, name := range strings.Split(argValueAfter(on, "-e"), ",") {
		onExcluded[strings.TrimSpace(name)] = true
	}
	if onExcluded["alias_overloading"] {
		t.Error("a check the operator selected was excluded anyway")
	}
	var announced bool
	for _, w := range onWarnings {
		if strings.Contains(w, "101 aliases") {
			announced = true
		}
	}
	if !announced {
		t.Error("enabling a load generating check must say what it does")
	}
}

// Every check name the composer can emit must exist in graphql-cop's registry, and the one upstream
// disabled must not be offered.
//
// field_duplication has a module but is commented out of the tests dict citing issue 43. Offering it
// would produce "cannot be excluded, skipping" and nothing else.
func TestGraphqlCopChecksMatchTheRealRegistry(t *testing.T) {
	real := map[string]bool{
		"field_suggestions": true, "introspection": true, "detect_graphiql": true,
		"get_method_support": true, "alias_overloading": true, "batch_query": true,
		"trace_mode": true, "directive_overloading": true, "circular_query_introspection": true,
		"get_based_mutation": true, "post_based_csrf": true, "unhandled_error_detection": true,
	}
	if len(graphqlCopTests) != len(real) {
		t.Errorf("graphql-cop registers %d tests, this has %d", len(real), len(graphqlCopTests))
	}
	for _, test := range graphqlCopTests {
		if !real[test.Flag] {
			t.Errorf("%s is not in graphql-cop's registry, so excluding it is ignored and including "+
				"it does nothing", test.Flag)
		}
		if test.Flag == "field_duplication" {
			t.Error("field_duplication is commented out upstream and must not be offered")
		}
	}
}

// An empty JSON array means the endpoint was skipped, not that it is clean.
//
// graphql-cop checks whether the target is GraphQL before running anything. If it decides it is not,
// it prints a sentence, skips every check and emits []. Reporting that as a clean scan is exactly
// the failure this framework exists to prevent.
func TestGraphqlCopEmptyResultIsNotACleanResult(t *testing.T) {
	row := vectorRow{ID: "e1", InsertionPoint: "body", Method: "POST",
		EvidenceURL: "https://x.test/notgraphql", IsGraphQLTarget: true}

	stdout := "https://x.test/notgraphql does not seem to be running GraphQL. " +
		"(Consider using -f to force the scan if GraphQL does exist on the endpoint)\n[]"

	findings := parseGraphqlCopOutput(stdout, "", row)
	if len(findings) != 1 {
		t.Fatalf("a skipped endpoint must be recorded, got %d", len(findings))
	}
	if findings[0].Kind != "not-tested" || findings[0].Severity != "info" {
		t.Errorf("skipped is not clean and not a vulnerability: %+v", findings[0])
	}
	if !findings[0].IsGraphQLTarget {
		t.Error("the finding must carry the identity, or the foreign key rejects it silently")
	}

	// A real result set with nothing firing IS clean, and produces nothing.
	clean := `[{"result":false,"title":"Introspection","severity":"HIGH"},` +
		`{"result":false,"title":"Field Suggestions","severity":"LOW"}]`
	if got := parseGraphqlCopOutput(clean, "", row); len(got) != 0 {
		t.Errorf("checks that ran and found nothing are a clean result: %+v", got)
	}
}

// Only result:true is a finding. Every check appears in the array whether or not it fired.
func TestGraphqlCopParsesOnlyWhatFired(t *testing.T) {
	row := vectorRow{ID: "e1", InsertionPoint: "body", Method: "POST",
		EvidenceURL: "https://x.test/graphql", IsGraphQLTarget: true}

	report := `[{"result":true,"title":"Introspection","description":"Introspection Query Enabled",` +
		`"impact":"Information Leakage - /graphql","severity":"HIGH","curl_verify":"curl ..."},` +
		`{"result":false,"title":"Trace Mode","description":"Trace Mode Enabled","severity":"INFO"}]`

	findings := parseGraphqlCopOutput(report, "", row)
	if len(findings) != 1 {
		t.Fatalf("one check fired, got %d findings", len(findings))
	}
	if findings[0].Kind != "graphql-introspection-enabled" {
		t.Errorf("the check keeps its own meaning: %+v", findings[0])
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity comes from the tool: %q", findings[0].Severity)
	}
	if findings[0].RawRequest == "" {
		t.Error("the curl reproduction must survive, it is how a finding is confirmed")
	}
}

// clairvoyance writes a schema whether or not it recovered anything. A schema of only built-in types
// is the technique failing, not an empty API, and the two must not read the same.
func TestClairvoyanceTellsRecoveryApartFromFailure(t *testing.T) {
	row := vectorRow{ID: "e1", InsertionPoint: "body", Method: "POST",
		EvidenceURL: "https://x.test/graphql-hardened", IsGraphQLTarget: true}

	// Measured against the hardened endpoint: with suggestions off, clairvoyance still names the root
	// type and one field, because the root's name needs no suggestions. That is not a recovery.
	empty := `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[
	  {"name":"Query","fields":[{"name":"currentUser"}]},
	  {"name":"String","fields":null},{"name":"__Type","fields":[]}]}}}`
	got := parseClairvoyanceSchema("", empty, row)
	if len(got) != 1 || got[0].Kind != "not-recovered" {
		t.Fatalf("a schema of only built-ins means nothing was recovered: %+v", got)
	}
	if got[0].Severity != "info" {
		t.Errorf("failing to recover is not a finding: %q", got[0].Severity)
	}

	recovered := `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[
	  {"name":"Query","fields":[{"name":"currentUser"}]},
	  {"name":"User","fields":[{"name":"id"},{"name":"email"},{"name":"isAdmin"}]},
	  {"name":"Invoice","fields":[{"name":"amountCents"}]},
	  {"name":"String","fields":null}]}}}`
	real := parseClairvoyanceSchema("", recovered, row)
	if len(real) != 1 || real[0].Kind != "graphql-schema-recovered" {
		t.Fatalf("a real recovery must be reported: %+v", real)
	}
	if !strings.Contains(real[0].Evidence, "2 types beyond the root") || !strings.Contains(real[0].Evidence, "5 fields") {
		t.Errorf("the evidence must say how much was recovered: %q", real[0].Evidence)
	}
	if !strings.Contains(real[0].Evidence, "User") {
		t.Errorf("naming the types is what makes it useful: %q", real[0].Evidence)
	}
}

// graphw00f names an engine and links its Threat Matrix entry. It ships NO CVE data, so the finding
// must not imply otherwise.
func TestGraphw00fReportsAnEngineNotAVulnerability(t *testing.T) {
	row := vectorRow{ID: "e1", InsertionPoint: "body", Method: "POST",
		EvidenceURL: "https://x.test/graphql", IsGraphQLTarget: true}

	stdout := "[*] Checking if GraphQL is available at https://x.test/graphql...\n" +
		"[!] Found GraphQL.\n[*] Attempting to fingerprint...\n" +
		"[*] Discovered GraphQL Engine: (Apollo)\n" +
		"[!] Attack Surface Matrix: https://github.com/nicholasaleks/graphql-threat-matrix/blob/master/implementations/apollo.md\n" +
		"[!] Technologies: JavaScript, Node.js\n[*] Completed.\n"

	findings := parseGraphw00fOutput(stdout, "", row)
	if len(findings) != 1 {
		t.Fatalf("expected the engine record, got %d", len(findings))
	}
	if findings[0].Severity != "info" {
		t.Errorf("knowing the engine is not a vulnerability: %q", findings[0].Severity)
	}
	if findings[0].InjectType != "Apollo" {
		t.Errorf("the engine name must be recorded: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Evidence, "graphql-threat-matrix") {
		t.Errorf("the Threat Matrix link is the useful part: %q", findings[0].Evidence)
	}
	if strings.Contains(strings.ToUpper(findings[0].Confidence), "CVE") &&
		!strings.Contains(findings[0].Confidence, "no CVE") {
		t.Errorf("graphw00f ships no CVE data and the report must not imply it does: %q", findings[0].Confidence)
	}
}

// The detect button is built on parsing this line, so the parse is pinned.
//
// From main.py: print('[!] Found GraphQL at {}'.format(target))
func TestGraphw00fDetectParse(t *testing.T) {
	output := "[*] Checking https://x.test/graphql...\n" +
		"[!] Found GraphQL at https://x.test/graphql\n" +
		"[!] Found GraphQL at https://x.test/api/graphql\n" +
		"[!] Found GraphQL at https://x.test/graphql\n"

	found := ParseGraphw00fDetect(output)
	if len(found) != 2 {
		t.Fatalf("two distinct endpoints, got %d: %v", len(found), found)
	}
	if found[0] != "https://x.test/graphql" || found[1] != "https://x.test/api/graphql" {
		t.Errorf("wrong endpoints parsed: %v", found)
	}

	if got := ParseGraphw00fDetect("[x] Could not find GraphQL anywhere.\n"); len(got) != 0 {
		t.Errorf("nothing found means nothing offered: %v", got)
	}
}

// clairvoyance depends entirely on its wordlist, so one is always supplied and the operator is told
// that a thin schema is usually a wordlist problem.
func TestClairvoyanceAlwaysHasAWordlist(t *testing.T) {
	v := VectorInput{EvidenceURL: "https://x.test/graphql"}
	args, warnings := ComposeClairvoyance(v, map[string]any{}, "/tmp/schema.json")

	if !argsContainPair(args, "-w", clairvoyanceWordlist) {
		t.Errorf("a wordlist must always be passed: %v", args)
	}
	if args[len(args)-1] != v.EvidenceURL {
		t.Errorf("the URL is positional and must come last: %v", args)
	}
	if !argsContainPair(args, "-o", "/tmp/schema.json") {
		t.Errorf("the schema is read back from the report path: %v", args)
	}
	var explained bool
	for _, w := range warnings {
		if strings.Contains(w, "wordlist problem") {
			explained = true
		}
	}
	if !explained {
		t.Error("a thin schema is usually the wordlist, and the operator should be told")
	}
}

// graphw00f fingerprints by default; detect mode walks a host's common paths and is a different job,
// so it is opt-in rather than doubling every run's request count.
func TestGraphw00fFingerprintsByDefaultAndDetectsOnRequest(t *testing.T) {
	v := VectorInput{EvidenceURL: "https://x.test/graphql"}

	args, _ := ComposeGraphw00f(v, map[string]any{}, "/tmp/rep")
	if !argsContain(args, "-f") {
		t.Errorf("fingerprinting is the job: %v", args)
	}
	if argsContain(args, "-d") {
		t.Error("detect mode must be opt-in")
	}

	on, warnings := ComposeGraphw00f(v, map[string]any{"alsoDetect": true}, "/tmp/rep")
	if !argsContain(on, "-d") {
		t.Error("detect mode was requested and not passed")
	}
	if len(warnings) == 0 {
		t.Error("walking a host's paths is extra requests and should say so")
	}
}

// A pathless endpoint is not one target, it is five.
//
// From graphql-cop's source: when urlparse(url).path is empty or "/", it DISCARDS the URL and scans
// its own hardcoded list instead: /, /graphiql, /playground, /console, /graphql. Every enabled check
// then runs against all five. Tolerable for the informational checks, not tolerable for the load
// generating ones, where it means five rounds of 101-alias queries at paths nobody named.
func TestGraphqlCopHandlesAPathlessEndpoint(t *testing.T) {
	for _, raw := range []string{"https://x.test", "https://x.test/"} {
		if !graphqlEndpointIsPathless(raw) {
			t.Errorf("%q has no path and graphql-cop will expand it", raw)
		}
	}
	if graphqlEndpointIsPathless("https://x.test/graphql") {
		t.Error("a named endpoint must be scanned as itself")
	}

	// Informational checks: allowed, but the expansion is stated.
	v := VectorInput{EvidenceURL: "https://x.test"}
	args, warnings := ComposeGraphqlCop(v, map[string]any{}, "/tmp/rep")
	if args == nil {
		t.Fatal("informational checks against a pathless endpoint should still run")
	}
	var explained bool
	for _, w := range warnings {
		if strings.Contains(w, "/playground") {
			explained = true
		}
	}
	if !explained {
		t.Error("the operator must be told which five paths will be scanned")
	}

	// Load generating checks against a pathless endpoint: refused, with the reason.
	refused, reasons := ComposeGraphqlCop(v, map[string]any{"aliasOverloading": true}, "/tmp/rep")
	if refused != nil {
		t.Error("101-alias queries must not be fired at five unnamed paths")
	}
	if len(reasons) == 0 || !strings.Contains(reasons[0], "no path") {
		t.Errorf("the refusal must say why: %v", reasons)
	}
}

// A hostname with a port but no scheme is the trap that reaches a tool intact.
//
// urlparse("host:8000/graphql") reads "host" as the SCHEME, because hyphens and letters are legal
// there, so graphql-cop's "URL missing scheme" guard passes and it scans nonsense while exiting 0
// with no findings. Prepending https:// whenever "://" is absent closes it before a tool sees it.
func TestGraphQLEndpointWithPortButNoSchemeIsFixed(t *testing.T) {
	got := splitEndpointList("x.test:8000/graphql")
	if len(got) != 1 {
		t.Fatalf("expected one endpoint, got %v", got)
	}
	if got[0] != "https://x.test:8000/graphql" {
		t.Errorf("a host:port with no scheme must be made explicit, got %q", got[0])
	}
}
