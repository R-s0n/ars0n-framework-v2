package utils

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Reading what the three GraphQL tools produced.
//
// Two of them report something that is not a vulnerability at all: graphw00f names an engine and
// clairvoyance hands back a schema. Both are recorded, because knowing which engine you are talking
// to and what the schema contains is most of the work of testing a GraphQL API, but neither is
// graded as a finding.

// graphqlCopResult is one entry of the JSON array graphql-cop prints with -o json. Taken from the
// dict each test module returns, verbatim:
//
//	{'result':False, 'title':'Introspection', 'description':'Introspection Query Enabled',
//	 'impact':'Information Leakage - /graphql', 'severity':'HIGH', 'color':'red', 'curl_verify':''}
type graphqlCopResult struct {
	Result      bool   `json:"result"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Severity    string `json:"severity"`
	CurlVerify  string `json:"curl_verify"`
}

// parseGraphqlCopOutput reads the JSON array.
//
// Every test appears in the array whether or not it fired, so only result:true is a finding. The
// case that matters more is an EMPTY array: graphql-cop checks whether the target is GraphQL first,
// and if it decides it is not, it prints a sentence to stdout, skips every test and emits []. An
// empty array is therefore "nothing was tested", not "nothing was found", and the two must not read
// the same.
func parseGraphqlCopOutput(stdout, report string, row vectorRow) []VectorFinding {
	source := strings.TrimSpace(stripANSI(stdout))

	// The JSON is printed after any human-readable lines, so take the array off the end.
	start := strings.Index(source, "[")
	if start < 0 {
		return graphqlNotTested(row, "graphql-cop", source)
	}

	var results []graphqlCopResult
	if err := json.Unmarshal([]byte(source[start:]), &results); err != nil {
		return graphqlNotTested(row, "graphql-cop", source)
	}
	if len(results) == 0 {
		return graphqlNotTested(row, "graphql-cop", source)
	}

	var findings []VectorFinding
	for _, result := range results {
		if !result.Result {
			continue
		}
		findings = append(findings, VectorFinding{
			VectorID:        row.ID,
			Tool:            "graphql-cop",
			Kind:            graphqlCopKind(result.Title),
			Severity:        strings.ToLower(strings.TrimSpace(result.Severity)),
			Confidence:      "graphql-cop confirmed this by sending the request in the reproduction below",
			InsertionPoint:  row.InsertionPoint,
			Method:          row.Method,
			URL:             row.EvidenceURL,
			Evidence:        result.Description + ". " + result.Impact,
			DetectionMethod: "graphql-cop " + result.Title,
			InjectType:      result.Title,
			RawRequest:      result.CurlVerify,
			IsGraphQLTarget: row.IsGraphQLTarget,
		})
	}
	return findings
}

// graphqlNotTested is the record for an endpoint that was skipped rather than cleared.
func graphqlNotTested(row vectorRow, tool, output string) []VectorFinding {
	reason := "graphql-cop decided this endpoint is not running GraphQL and skipped every check. " +
		"That is not a clean result: nothing was tested. If you know GraphQL is there, turn on " +
		"\"Scan even when GraphQL is not detected\"."
	if trimmed := strings.TrimSpace(output); trimmed != "" && len(trimmed) < 400 {
		reason += " It said: " + trimmed
	}
	return []VectorFinding{{
		VectorID:        row.ID,
		Tool:            tool,
		Kind:            "not-tested",
		Severity:        "info",
		Confidence:      "not a vulnerability: this endpoint was skipped, so it is untested",
		InsertionPoint:  row.InsertionPoint,
		Method:          row.Method,
		URL:             row.EvidenceURL,
		Evidence:        reason,
		DetectionMethod: tool + " detection",
		IsGraphQLTarget: row.IsGraphQLTarget,
	}}
}

// graphqlCopKind keeps the check's own name rather than flattening everything to "graphql
// misconfiguration", because these are genuinely different things: introspection being on is a
// disclosure, CSRF over GET is an attack path, and alias overloading is a resource problem.
func graphqlCopKind(title string) string {
	switch strings.ToLower(strings.TrimSpace(title)) {
	case "introspection":
		return "graphql-introspection-enabled"
	case "field suggestions":
		return "graphql-field-suggestions"
	case "graphiql":
		return "graphql-console-exposed"
	case "alias overloading", "batch queries", "directive overloading", "circular query":
		return "graphql-resource-exhaustion"
	case "get method query support", "get based mutation":
		return "graphql-get-accepted"
	case "post based csrf":
		return "graphql-csrf"
	case "trace mode":
		return "graphql-debug-enabled"
	}
	return "graphql-misconfiguration"
}

// parseGraphw00fOutput reads graphw00f's stdout.
//
// The lines are, verbatim from main.py:
//
//	print(bcolors.OKGREEN + '[*] Discovered GraphQL Engine: ({})'.format(name))
//	print('[!] Attack Surface Matrix: {}'.format(ref))
//	print('[!] Technologies: {}'.format(technologies))
//	print('[x] Nothing was found :-(')
//
// The reference is a link into the GraphQL Threat Matrix, NOT a CVE list: the repository contains no
// CVE data at all. The finding says so rather than implying a vulnerability was found.
func parseGraphw00fOutput(stdout, report string, row vectorRow) []VectorFinding {
	clean := stripANSI(stdout)

	engine := betweenWords(clean, "Discovered GraphQL Engine: (", ")")
	if strings.TrimSpace(engine) == "" {
		// Detect mode may still have found endpoints even when this one could not be fingerprinted.
		if found := ParseGraphw00fDetect(clean); len(found) > 0 {
			return []VectorFinding{graphqlDetectFinding(row, found)}
		}
		return nil
	}

	reference := strings.TrimSpace(lineValue(clean, "Attack Surface Matrix:"))
	technologies := strings.TrimSpace(lineValue(clean, "Technologies:"))

	evidence := "Engine: " + engine
	if technologies != "" {
		evidence += ". Technologies: " + technologies
	}
	if reference != "" {
		evidence += ". Threat Matrix entry: " + reference
	}

	findings := []VectorFinding{{
		VectorID:   row.ID,
		Tool:       "graphw00f",
		Kind:       "graphql-engine-identified",
		Severity:   "info",
		Confidence: "not a vulnerability: this is which implementation is answering, and where its " +
			"known weaknesses are documented. graphw00f ships no CVE data, so the Threat Matrix link " +
			"is the starting point rather than a finding.",
		InsertionPoint:  row.InsertionPoint,
		Method:          row.Method,
		URL:             row.EvidenceURL,
		Evidence:        evidence,
		DetectionMethod: "graphw00f fingerprint",
		InjectType:      engine,
		IsGraphQLTarget: row.IsGraphQLTarget,
	}}

	if found := ParseGraphw00fDetect(clean); len(found) > 0 {
		findings = append(findings, graphqlDetectFinding(row, found))
	}
	return findings
}

func graphqlDetectFinding(row vectorRow, found []string) VectorFinding {
	return VectorFinding{
		VectorID:        row.ID,
		Tool:            "graphw00f",
		Kind:            "graphql-endpoint-discovered",
		Severity:        "info",
		Confidence:      "not a vulnerability: these are GraphQL endpoints found on this host that you may not have marked yet",
		InsertionPoint:  row.InsertionPoint,
		Method:          row.Method,
		URL:             row.EvidenceURL,
		Evidence:        "Detect mode found: " + strings.Join(found, ", "),
		DetectionMethod: "graphw00f detect",
		IsGraphQLTarget: row.IsGraphQLTarget,
	}
}

// clairvoyanceSchema is enough of the recovered schema to judge whether anything was recovered.
type clairvoyanceSchema struct {
	Data struct {
		Schema struct {
			QueryType        struct{ Name string } `json:"queryType"`
			MutationType     struct{ Name string } `json:"mutationType"`
			SubscriptionType struct{ Name string } `json:"subscriptionType"`
			Types            []struct {
				Name   string `json:"name"`
				Kind   string `json:"kind"`
				Fields []struct {
					Name string `json:"name"`
				} `json:"fields"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
}

// parseClairvoyanceSchema reads the JSON schema clairvoyance wrote.
//
// A schema is not a vulnerability, so this is recorded as information. What it has to get right is
// the difference between a schema that was RECOVERED and an empty shell: clairvoyance depends on the
// server returning field suggestions, and against a server with suggestions turned off it writes a
// schema containing only GraphQL's own built-in types and exits 0. That file is not an error and not
// a result, and reporting it as "schema recovered" would be a lie.
func parseClairvoyanceSchema(stdout, report string, row vectorRow) []VectorFinding {
	trimmed := strings.TrimSpace(report)
	if trimmed == "" {
		return nil
	}

	var schema clairvoyanceSchema
	if err := json.Unmarshal([]byte(trimmed), &schema); err != nil {
		return nil
	}

	// Built-in types prove nothing was learned, and neither does the ROOT type on its own.
	//
	// Measured: against the hardened endpoint, where field suggestions are off and nothing should be
	// recoverable, clairvoyance still produced a schema naming "Query" with a single field, because
	// the root operation type's name comes back from an ordinary probe and needs no suggestions at
	// all. Counting that as a recovery reported success on the one endpoint that had defeated it.
	// Against the same server with suggestions on it recovered "Query, User" and five fields.
	roots := map[string]bool{
		schema.Data.Schema.QueryType.Name:        true,
		schema.Data.Schema.MutationType.Name:     true,
		schema.Data.Schema.SubscriptionType.Name: true,
	}
	delete(roots, "")

	custom, fields := 0, 0
	var names []string
	for _, t := range schema.Data.Schema.Types {
		if strings.HasPrefix(t.Name, "__") || graphqlBuiltinScalar(t.Name) {
			continue
		}
		fields += len(t.Fields)
		if roots[t.Name] {
			continue
		}
		custom++
		if len(names) < 12 {
			names = append(names, t.Name)
		}
	}

	// Nothing beyond the root, and at most a single field on it, is the technique failing.
	if custom == 0 && fields < 2 {
		return []VectorFinding{{
			VectorID:       row.ID,
			Tool:           "clairvoyance",
			Kind:           "not-recovered",
			Severity:       "info",
			Confidence:     "not a vulnerability, and not a clean result either: nothing was recovered",
			InsertionPoint: row.InsertionPoint,
			Method:         row.Method,
			URL:            row.EvidenceURL,
			Evidence: "clairvoyance produced a schema containing only GraphQL's own built-in types, " +
				"which is what it writes when the server does not return field suggestions. That is " +
				"the technique failing, not the schema being empty. Check whether suggestions are " +
				"disabled, and whether the wordlist suits this API.",
			DetectionMethod: "clairvoyance",
			IsGraphQLTarget: row.IsGraphQLTarget,
		}}
	}

	return []VectorFinding{{
		VectorID:   row.ID,
		Tool:       "clairvoyance",
		Kind:       "graphql-schema-recovered",
		Severity:   "medium",
		Confidence: "not a vulnerability in itself: the schema was reconstructed from the field " +
			"suggestions in error messages, which is only possible because those suggestions are on. " +
			"The schema is the map for everything else you test here.",
		InsertionPoint: row.InsertionPoint,
		Method:         row.Method,
		URL:            row.EvidenceURL,
		Evidence: "Recovered " + strconv.Itoa(custom) + " types beyond the root and " + strconv.Itoa(fields) +
			" fields without introspection: " + strings.Join(names, ", ") +
			pluralSuffix(custom, len(names)),
		DetectionMethod: "clairvoyance field suggestion brute force",
		RawResponse:     trimmed,
		IsGraphQLTarget: row.IsGraphQLTarget,
	}}
}

func pluralSuffix(total, shown int) string {
	if total > shown {
		return " and " + strconv.Itoa(total-shown) + " more"
	}
	return ""
}

func graphqlBuiltinScalar(name string) bool {
	switch name {
	case "String", "Int", "Float", "Boolean", "ID":
		return true
	}
	return false
}

// lineValue reads the rest of the line after a marker.
func lineValue(text, marker string) string {
	for _, line := range strings.Split(text, "\n") {
		if index := strings.Index(line, marker); index >= 0 {
			return strings.TrimSpace(line[index+len(marker):])
		}
	}
	return ""
}
