package utils

import (
	"time"
)

// The GraphQL section: graphql-cop, clairvoyance and graphw00f.
//
// Every tool here takes ONE endpoint and each keeps its OWN list of them, in its own settings. That
// is a deliberate choice by the operator: which endpoints speak GraphQL is their judgement, and
// marking one is an act rather than a guess. The cost is that three lists can disagree, so each
// config modal is told what the other two already know about.

// The twelve checks graphql-cop actually runs, taken from the tests dict in lib/tests/__init__.py
// rather than from the README. Four of them are load generating and are off by default.
//
// field_duplication is NOT here on purpose: the module exists but upstream commented it out of the
// registry, citing issue 43. Offering it would produce "cannot be excluded, skipping" and nothing else.
var graphqlCopTests = []struct {
	Key   string
	Flag  string
	Label string
	DoS   bool
}{
	{"introspection", "introspection", "Introspection enabled", false},
	{"fieldSuggestions", "field_suggestions", "Field suggestions enabled", false},
	{"detectGraphiql", "detect_graphiql", "GraphiQL console exposed", false},
	{"getMethodSupport", "get_method_support", "Queries accepted over GET", false},
	{"traceMode", "trace_mode", "Trace mode / debug enabled", false},
	{"getBasedMutation", "get_based_mutation", "Mutations accepted over GET", false},
	{"postBasedCsrf", "post_based_csrf", "POST based CSRF (form content type accepted)", false},
	{"unhandledError", "unhandled_error_detection", "Unhandled error disclosure", false},
	{"aliasOverloading", "alias_overloading", "Alias overloading (sends 101 aliases in one query)", true},
	{"batchQuery", "batch_query", "Query batching (sends a batched array)", true},
	{"directiveOverloading", "directive_overloading", "Directive overloading", true},
	{"circularIntrospection", "circular_query_introspection", "Circular introspection query", true},
}

var graphqlCopOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Endpoints", Label: "GraphQL endpoints (one per line)",
		Placeholder: "https://target/graphql"},
	"headers": {Kind: "string", Group: "Request", Label: "Header JSON", Flag: "-H", Repeatable: true,
		Placeholder: `{"Authorization": "Bearer ey..."}`},
	"proxy":    {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-x", Placeholder: "http://127.0.0.1:8080"},
	"force":    {Kind: "bool", Group: "Request", Label: "Scan even when GraphQL is not detected", Flag: "-f"},
	"wordlist": {Kind: "path", Group: "Request", Label: "Custom GraphQL endpoint wordlist", Flag: "-w"},
}

var graphqlCopOwned = map[string]string{
	"-t":               "The target is one endpoint from this tool's own list.",
	"--target":         "The target is one endpoint from this tool's own list.",
	"-o":               "Findings are read from the JSON output, so the format is fixed.",
	"--output":         "Findings are read from the JSON output, so the format is fixed.",
	"-e":               "Built from the individual check switches, because an unrecognised name is IGNORED and the check then runs anyway.",
	"--excluded-tests": "Built from the individual check switches, because an unrecognised name is IGNORED and the check then runs anyway.",
	"-l":               "Lists the checks and scans nothing.",
	"--list-tests":     "Lists the checks and scans nothing.",
	"-T":               "Tor is not wired into this framework.",
	"--tor":            "Tor is not wired into this framework.",
	"-v":               "Version only.",
	"--version":        "Version only.",
	"-d":               "Debug headers would end up in the evidence.",
	"--debug":          "Debug headers would end up in the evidence.",
}

var clairvoyanceOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Endpoints", Label: "GraphQL endpoints (one per line)",
		Placeholder: "https://target/graphql"},
	"wordlist":    {Kind: "path", Group: "Scan", Label: "Wordlist", Flag: "-w", Placeholder: "the shipped list"},
	"document":    {Kind: "string", Group: "Scan", Label: "Starting document", Flag: "-d", Placeholder: "query { FUZZ }"},
	"concurrent":  {Kind: "int", Group: "Scan", Label: "Concurrent requests", Flag: "-c"},
	"profile":     {Kind: "enum", Group: "Scan", Label: "Speed profile", Flag: "-p", Choices: []string{"slow", "fast"}},
	"maxRetries":  {Kind: "int", Group: "Scan", Label: "Max retries", Flag: "-m"},
	"backoff":     {Kind: "int", Group: "Scan", Label: "Backoff factor", Flag: "-b"},
	"headers":     {Kind: "string", Group: "Request", Label: "Header", Flag: "-H", Repeatable: true},
	"proxy":       {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-x"},
	"noSSL":       {Kind: "bool", Group: "Request", Label: "Skip TLS verification", Flag: "-k"},
	"inputSchema": {Kind: "path", Group: "Scan", Label: "Existing schema to extend", Flag: "-i"},
	"verbose":     {Kind: "bool", Group: "Scan", Label: "Verbose", Flag: "-v"},
}

var clairvoyanceOwned = map[string]string{
	"-o":         "The schema is written to a per-scan path, and is how the result is read back.",
	"--output":   "The schema is written to a per-scan path, and is how the result is read back.",
	"--progress": "A progress bar in a captured log is noise.",
	"-wv":        "Wordlist validation is a one-off check, not a scan setting.",
	"--validate": "Wordlist validation is a one-off check, not a scan setting.",
}

var graphw00fOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Endpoints", Label: "GraphQL endpoints (one per line)",
		Placeholder: "https://target/graphql"},
	"headers":    {Kind: "string", Group: "Request", Label: "Header", Flag: "-H", Repeatable: true},
	"userAgent":  {Kind: "string", Group: "Request", Label: "User-Agent", Flag: "-u"},
	"proxy":      {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-p"},
	"timeout":    {Kind: "int", Group: "Request", Label: "Timeout (s)", Flag: "-T"},
	"noRedirect": {Kind: "bool", Group: "Request", Label: "Do not follow redirects", Flag: "-r"},
	"wordlist":   {Kind: "path", Group: "Scan", Label: "Custom endpoint wordlist for detect mode", Flag: "-w"},
	"alsoDetect": {Kind: "bool", Group: "Scan", Label: "Also run detect mode against the endpoint's host"},
}

var graphw00fOwned = map[string]string{
	"-t":            "The target is one endpoint from this tool's own list.",
	"--target":      "The target is one endpoint from this tool's own list.",
	"-f":            "Fingerprinting is the whole point of running it here.",
	"--fingerprint": "Fingerprinting is the whole point of running it here.",
	"-o":            "The CSV is written to a per-scan path.",
	"--output-file": "The CSV is written to a per-scan path.",
	"-l":            "Lists the engines it knows and scans nothing.",
	"--list":        "Lists the engines it knows and scans nothing.",
	"-v":            "Version only.",
	"--version":     "Version only.",
}

func init() {
	registerVectorTools(
		VectorTool{
			Key: "graphql-cop", Name: "graphql-cop", Category: "graphql",
			Binary: "python", Container: "ars0n-framework-v2-graphql-cop-1",
			Groups:  []string{"Endpoints", "Checks", "Request"},
			Options: graphqlCopOptionsWithChecks(), OwnedFlags: graphqlCopOwned,
			InsertionPoints: VectorInsertionPoints,
			RowSource:       graphqlRowSource("graphql-cop"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "endpoint",
			Compose:         ComposeGraphqlCop,
			Parse:           parseGraphqlCopOutput,
			Timeout:         15 * time.Minute,
			Limitation: "graphql-cop runs a battery of checks against one endpoint. Four of them are " +
				"load generating rather than informational, and they are OFF unless you turn them on: " +
				"alias overloading sends 101 aliases in a single query and the others batch, nest and " +
				"overload directives. Its exclusion flag ignores a name it does not recognise and runs " +
				"the check anyway, so the framework only ever emits names it has verified exist.",
		},
		VectorTool{
			Key: "clairvoyance", Name: "clairvoyance", Category: "graphql",
			Binary: "python", Container: "ars0n-framework-v2-clairvoyance-1",
			Groups:  []string{"Endpoints", "Scan", "Request"},
			Options: clairvoyanceOptions, OwnedFlags: clairvoyanceOwned,
			InsertionPoints: VectorInsertionPoints,
			UsesReportFile:  true,
			RowSource:       graphqlRowSource("clairvoyance"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "endpoint",
			Compose:         ComposeClairvoyance,
			Parse:           parseClairvoyanceSchema,
			// A wordlist of several thousand entries is several thousand requests, in batches.
			Timeout: 45 * time.Minute,
			Limitation: "clairvoyance rebuilds a schema from the field suggestions in error messages, " +
				"which is worth doing only when introspection is DISABLED: with introspection on you " +
				"can simply download the schema, and this run would spend thousands of requests " +
				"rediscovering it. It also depends entirely on the server returning suggestions at " +
				"all. A server with suggestions turned off yields an empty schema rather than an " +
				"error, so an empty result here means \"nothing was recoverable\", not \"nothing is there\".",
		},
		VectorTool{
			Key: "graphw00f", Name: "graphw00f", Category: "graphql",
			// graphw00f-batch, not main.py: it asks "Continue anyway? [y/n]" when it cannot confirm
			// GraphQL and dies with EOFError on a non-TTY. See docker/graphw00f/Dockerfile.
			Binary: "graphw00f-batch", Container: "ars0n-framework-v2-graphw00f-1",
			Groups:  []string{"Endpoints", "Scan", "Request"},
			Options: graphw00fOptions, OwnedFlags: graphw00fOwned,
			InsertionPoints: VectorInsertionPoints,
			RowSource:       graphqlRowSource("graphw00f"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "endpoint",
			Compose:         ComposeGraphw00f,
			Parse:           parseGraphw00fOutput,
			Timeout:         10 * time.Minute,
			Limitation: "graphw00f identifies which GraphQL engine is behind an endpoint and links it " +
				"to that engine's entry in the GraphQL Threat Matrix, where its known weaknesses are " +
				"documented. It does NOT output CVEs: the repository contains no CVE data at all, so " +
				"the reference is a starting point for research rather than a vulnerability list. " +
				"Knowing the engine is what makes the rest of this section actionable, because the " +
				"defaults that matter differ sharply between implementations.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}{"graphql", "GraphQL"})
}

func graphqlCopOptionsWithChecks() map[string]VectorOptionMeta {
	out := make(map[string]VectorOptionMeta, len(graphqlCopOptions)+len(graphqlCopTests))
	for key, meta := range graphqlCopOptions {
		out[key] = meta
	}
	for _, test := range graphqlCopTests {
		label := test.Label
		if test.DoS {
			label += " [load generating]"
		}
		out[test.Key] = VectorOptionMeta{Kind: "bool", Group: "Checks", Label: label}
	}
	return out
}
