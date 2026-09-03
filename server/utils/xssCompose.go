package utils

import (
	"bufio"
	"encoding/json"
	"sort"
	"strings"
)

// Composing the three XSS scanners. The generic machinery is in vectorCompose.go; what lives here is
// the part that is specific to dalfox, domdig and xssFuzz.

// dalfoxLocationFor maps our insertion point onto dalfox's -p location token.
//
// Verified token by token against dalfox 3.2.1 on a reflector, by counting the REQUESTS each one
// produced rather than by trusting the exit code. An unrecognised token is not an error: dalfox logs
// "found reflected 1 params", then "XSS found 0 XSS", and exits 0.
//
//	-p q:query      6 requests, V finding      recognised, applies
//	-p q:json       7 requests, no finding     recognised, does not apply to a GET query
//	-p q:multipart  7 requests, no finding     recognised, does not apply to a GET query
//	-p q:path       3 requests, no finding     NOT RECOGNISED
//	-p q:bogus      3 requests, no finding     NOT RECOGNISED, byte-identical to :path
//
// PATH IS DELIBERATELY ABSENT, and dalfoxPathIsUnaimable below records the whole of what was tried.
func dalfoxLocationFor(insertionPoint, contentType string) (string, bool) {
	switch insertionPoint {
	case "query":
		return "query", true
	case "header":
		return "header", true
	case "cookie":
		return "cookie", true
	case "body":
		ct := strings.ToLower(contentType)
		switch {
		case strings.Contains(ct, "json"):
			return "json", true
		case strings.Contains(ct, "multipart"):
			return "multipart", true
		default:
			return "body", true
		}
	}
	return "", false
}

// dalfoxPathIsUnaimable is what every path vector is told, because a clean result for one does not
// mean what a clean result for a query vector means.
//
// EVERY WAY OF AIMING dalfox 3.2.1 at a path segment was tried against a target that reflects its
// last path segment into HTML and into a JavaScript string, unencoded. Request counts are from the
// target's own log, not from dalfox:
//
//	bare URL, discovery on                        660 requests, R Path path_segment_1   WORKS
//	-p path_segment_1:path  --skip-discovery      150 requests, clean
//	-p path_segment_1       --skip-discovery      156 requests, clean
//	-p bogus:bogus          --skip-discovery      150 requests, clean   <- identical to :path
//	--inject-marker M, M in the path segment        3 requests, clean
//	-i raw-http, --inject-marker M in the path      3 requests, clean
//
// So there is no way to aim it, and the two marker forms are worse than doing nothing: dalfox finds
// no marker to substitute, sends three requests and calls the target clean.
//
// What remains is dalfox's own path-reflection discovery, which really does work. It replaces each
// segment with a random 36-character token, requests that, and injects only where the token comes
// back in the response. That last clause is why this warning exists: a route that answers a token of
// the wrong shape with a 404, and any application that serves one page for every path, reflects
// nothing, so dalfox sends ZERO payloads into the path and still exits reporting clean.
const dalfoxPathIsUnaimable = "dalfox cannot be aimed at a path segment: -p name:path is accepted " +
	"and ignored, byte for byte like an invalid location token, and --inject-marker inside a path " +
	"segment reduces the whole scan to three requests reporting clean. The only mechanism that " +
	"reaches a path is dalfox's own path-reflection discovery, which replaces each segment with a " +
	"random token and injects only where that token comes back in the response. A clean result here " +
	"therefore means the segment did not echo a random token, NOT that payloads were sent into it " +
	"and repelled. Findings dalfox reports against a parameter it appended itself are discarded for " +
	"this vector: they are not path coverage."

// dalfoxMiningKeys are the settings that drive PARAMETER MINING, which is guessing query parameter
// names from a wordlist. Suppressed for a path vector, where mining is not merely wasteful.
//
// A path vector carries no -p, so nothing constrains dalfox to the input the vector names. Measured
// on a single-page-application shaped target, one path vector, requests counted at the target:
//
//	bare URL                166 requests, of which 2 touched a path segment and 164 were
//	                        148 distinct query parameter names dalfox invented
//	bare URL --skip-mining   19 requests
//
// and on a target that DOES reflect its path, --skip-mining kept the real R Path path_segment_1
// finding and removed a phantom V Query finding on "q", a parameter the vector never claimed and
// which parseDalfoxJSONL would have filed under insertion point "path".
var dalfoxMiningKeys = []string{
	"miningDictWord", "remoteWordlists", "skipMining", "skipMiningDict", "skipMiningDom",
}

// dalfoxMiningEnablers are the two of those five that ASK FOR MORE mining. They are the only ones
// worth a warning: --skip-mining strictly supersedes skipMining, skipMiningDict and skipMiningDom,
// so an operator who set one of those got what they wanted and more, and telling them their setting
// "was not applied" would be false. Dropping all five from the argv is still right, because a -W
// wordlist sitting next to --skip-mining is two flags arguing on one command line.
var dalfoxMiningEnablers = []string{"miningDictWord", "remoteWordlists"}

// ComposeDalfox builds the dalfox argv for one vector.
func ComposeDalfox(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("dalfox")
	var warnings []string

	args := []string{"scan", dalfoxTargetURL(v)}

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method != "" && method != "GET" {
		args = append(args, "-X", method)
	}
	// vectorBodyFor, not v.Body. Guarding on a recorded body meant that a body vector whose
	// raw_request was never captured produced `-X POST -p name:body` with no -d, so dalfox posted an
	// empty body, tested nothing, and the vector was recorded clean. All 10 POST vectors on
	// ginandjuice.shop are in exactly that state.
	if v.InsertionPoint == "body" {
		args = append(args, "-d", vectorBodyFor(v))
	}

	// The target header, lower-cased, so it can be removed from the user's -H list regardless of how
	// either was capitalised. Header names are case insensitive and Authorization would otherwise
	// survive a comparison against authorization.
	suppressedHeader := ""
	if v.InsertionPoint == "header" && len(v.Parameters) > 0 {
		suppressedHeader = strings.ToLower(v.Parameters[0])
	}

	var skipKeys map[string]bool

	if location, ok := dalfoxLocationFor(v.InsertionPoint, v.ContentType); ok {
		for _, name := range v.Parameters {
			args = append(args, "-p", name+":"+location)
		}
		if v.InsertionPoint == "cookie" {
			for _, name := range v.Parameters {
				args = append(args, "--cookies", name+"="+v.valueFor(name))
			}
		}
	} else if v.InsertionPoint == "path" {
		// No -p at all. There is no path token, and an unrecognised one is silently ignored rather
		// than rejected, so naming one here would produce a clean scan of nothing.
		if blinded := VectorBlindedPoints("dalfox", settings); len(blinded["path"]) > 0 {
			warnings = append(warnings, "Path vectors need dalfox's own path segment discovery, which "+
				strings.Join(blinded["path"], " and ")+" turns off. This vector was not scanned.")
			return nil, warnings
		}
		warnings = append(warnings, dalfoxPathIsUnaimable)

		// The operator's mining settings are dropped rather than emitted, so --skip-mining below
		// cannot end up on the same command line as --skip-mining-dict or a -W wordlist.
		skipKeys = map[string]bool{}
		for _, key := range dalfoxMiningKeys {
			skipKeys[key] = true
		}
		var overridden []string
		for _, key := range dalfoxMiningEnablers {
			if vectorSettingEngaged(tool, key, settings[key]) {
				overridden = append(overridden, key)
			}
		}
		sort.Strings(overridden)
		if len(overridden) > 0 {
			warnings = append(warnings, "Your "+joinAnd(overridden)+" setting was not applied to this "+
				"path vector. Mining guesses QUERY parameter names, and a path vector carries no -p, so "+
				"every name it guesses becomes an input dalfox scans and reports under this vector's "+
				"insertion point. Mining is on for your query, body, header and cookie vectors.")
		}
	}

	args = append(args, composeVectorSettings(tool, settings, suppressedHeader, skipKeys, &warnings)...)

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args,
		"--format", "jsonl",
		"--output", reportPath,
		"--include-all",
		"--no-color",
		"-S",
	)
	if v.InsertionPoint == "path" {
		args = append(args, "--skip-mining")
	}
	return args, warnings
}

// dalfoxTargetURL is TargetURL with any TEMPLATED path segment made concrete.
//
// A consolidated endpoint stores an identifier segment as a template, so the path arrives here as
// /rest/products/{id}/reviews. Sent literally that is a route the application does not have: it
// answers 404 or a catch-all page, dalfox's path probe sees its token come back nowhere, and the
// path is never injected into. sqliTargetURL has done this for sqlmap and ghauri since the marker
// rules were established; dalfox was left sending the braces.
//
// EVERY templated segment is replaced, not only the last one. sqlmap needs one concrete segment to
// hang its * marker on; dalfox probes every segment in turn, so any brace left anywhere breaks the
// route for all of them.
//
// Edited as text rather than through net/url, for the same reason sqliTargetURL is: round-tripping
// through url.URL re-encodes the path and changes the bytes on the wire.
func dalfoxTargetURL(v VectorInput) string {
	base := v.TargetURL()
	if !strings.Contains(base, "{") {
		return base
	}
	pathPart, queryPart, hasQuery := strings.Cut(base, "?")
	scheme, rest, hasScheme := strings.Cut(pathPart, "://")
	if !hasScheme {
		return base
	}
	host, path, hasPath := strings.Cut(rest, "/")
	if !hasPath {
		return base
	}

	segments := strings.Split(path, "/")
	replaced := false
	for i, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			segments[i] = VectorCanary
			replaced = true
		}
	}
	if !replaced {
		return base
	}

	out := scheme + "://" + host + "/" + strings.Join(segments, "/")
	if hasQuery {
		out += "?" + queryPart
	}
	return out
}

// parseDalfoxForVector reads dalfox's report and then holds it to the vector it was aimed at.
//
// Findings are parsed by parseDalfoxJSONL exactly as before. What this adds is one rule for PATH
// vectors: keep only what dalfox itself labelled location "Path".
//
// A path vector is the one case where dalfox is handed no -p, so nothing stops it scanning inputs
// the vector does not claim. Two kinds appear:
//
//   - parameters mined from a wordlist. ComposeDalfox now suppresses those with --skip-mining.
//   - __dalfox_key_inject__, the synthetic query parameter dalfox APPENDS ITSELF during discovery to
//     find out whether the endpoint echoes an arbitrary query string. This one cannot be turned off,
//     because discovery is also the only thing that reaches the path.
//
// parseDalfoxJSONL stamps every finding with the VECTOR's insertion point, which is right for the
// cookie-reported-as-Header case it was written for and wrong here: it filed a finding on a query
// parameter that does not exist in the application under "path". Reproduced on a target returning
// Express's default error page, which echoes the full original URL:
//
//	FINDING V Query __dalfox_key_inject__     <- reported as path coverage
//	FINDING V Path  path_segment_1
//	FINDING V Path  path_segment_2
//	FINDING V Query any                       <- a mined name, gone with --skip-mining
//
// All five of dalfox's false positives on the Juice Shop run were the first shape. A finding on a
// parameter dalfox invented says the application echoes arbitrary query strings; it says nothing
// about the path segment this vector names, and the query vectors for the same URLs cover the query
// surface properly. The operator is told this is happening by dalfoxPathIsUnaimable, on every path
// vector, rather than being left to notice the count.
func parseDalfoxForVector(stdout, report string, row vectorRow) []VectorFinding {
	findings := parseDalfoxJSONL(stdout, report, row)
	if row.InsertionPoint != "path" || len(findings) == 0 {
		return findings
	}

	locations := dalfoxFindingLocations(report)
	if len(locations) != len(findings) {
		// The report shape moved under us. Filtering on a mapping that cannot be trusted would DELETE
		// real findings, which is the worse direction to fail in, so nothing is dropped.
		return findings
	}

	kept := make([]VectorFinding, 0, len(findings))
	for i, finding := range findings {
		if strings.EqualFold(strings.TrimSpace(locations[i]), "path") {
			kept = append(kept, finding)
		}
	}
	return kept
}

// dalfoxFindingLocations reads the location field of each finding, in report order.
//
// Deliberately a second pass over the same bytes rather than a change to VectorFinding: location is
// dalfox's own word for where it injected, it agrees with nothing any other tool reports, and the
// only question asked of it is whether a path vector's finding was actually in the path.
//
// The line filter is IDENTICAL to parseDalfoxJSONL's on purpose. The two lists are zipped by index,
// so a line one of them keeps and the other drops would silently shift every location by one.
func dalfoxFindingLocations(report string) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(report))
	scanner.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var row struct {
			Type     string          `json:"type"`
			Location string          `json:"location"`
			Meta     json.RawMessage `json:"meta"`
		}
		if json.Unmarshal([]byte(line), &row) != nil || len(row.Meta) > 0 || row.Type == "" {
			continue
		}
		out = append(out, row.Location)
	}
	return out
}

// ComposeDomdig builds the domdig argv for one vector. domdig takes one URL and fuzzes its query
// string and hash, so there is nothing per-insertion-point to decide: the eligibility check has
// already ruled out everything it cannot reach.
func ComposeDomdig(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("domdig")
	var warnings []string

	args := []string{"/app/domdig.js"}
	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	// -J prints findings as JSON on stdout and -q silences the progress chatter that would otherwise
	// be interleaved with it. domdig has no --output, so the report is the captured stdout.
	args = append(args, "-J", "-q", v.TargetURL())
	_ = reportPath
	return args, warnings
}

// ComposeXSSFuzz builds the xssFuzz argv for one vector.
//
// --param is passed explicitly rather than letting xssFuzz discover parameters, because its
// discovery regex is (?<=\?|\&)[^=&]+ over the raw URL and would also pick up parameters this vector
// does not claim. TargetURL has already guaranteed every named parameter is physically present with
// a value, which is what xssFuzz's substitution needs in order to match at all.
func ComposeXSSFuzz(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("xssfuzz")
	var warnings []string

	args := []string{"/app/xssFuzz.py", "-u", v.TargetURL()}
	if len(v.Parameters) > 0 {
		args = append(args, "--param", strings.Join(v.Parameters, ","))
	}
	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	args = append(args, "-o", reportPath)
	return args, warnings
}
