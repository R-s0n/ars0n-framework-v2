package utils

import (
	"strings"
)

// Building the command lines for the GraphQL section.
//
// All three tools take one endpoint, so composing is mostly about two things: keeping the load
// generating checks off unless they were asked for, and making sure a tool that cannot do its job
// says so rather than producing an empty result that reads as a clean one.

// clairvoyanceWordlist is the list shipped inside the clairvoyance image.
const clairvoyanceWordlist = "/opt/clairvoyance/clairvoyance/wordlist.txt"

// ComposeGraphqlCop builds the graphql-cop argv for one endpoint.
func ComposeGraphqlCop(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("graphql-cop")
	var warnings []string

	args := []string{"/opt/graphql-cop/graphql-cop.py", "-t", v.EvidenceURL}

	// An endpoint with no path is not one target, it is five.
	//
	// From the source: when urlparse(url).path is empty or "/", graphql-cop discards the URL and
	// scans its own hardcoded list instead: /, /graphiql, /playground, /console, /graphql. Every
	// enabled check then runs against all five, which is fine for the informational ones and is not
	// fine for the load generating ones, where it means five rounds of 101-alias queries against
	// paths the operator never named.
	pathless := graphqlEndpointIsPathless(v.EvidenceURL)
	if pathless {
		var enabledDoS []string
		for _, test := range graphqlCopTests {
			if test.DoS && truthySetting(settings[test.Key]) {
				enabledDoS = append(enabledDoS, test.Flag)
			}
		}
		if len(enabledDoS) > 0 {
			return nil, []string{"This endpoint has no path, so graphql-cop will scan five paths of " +
				"its own (/, /graphiql, /playground, /console, /graphql) and the load generating " +
				"checks (" + strings.Join(enabledDoS, ", ") + ") would be sent against every one of " +
				"them. Give the exact endpoint path, or turn those checks off."}
		}
		warnings = append(warnings, "This endpoint has no path, so graphql-cop ignores it and scans "+
			"five paths of its own instead: /, /graphiql, /playground, /console and /graphql. Name "+
			"the exact endpoint to scan only that.")
	}

	// The exclusion list is built from what is NOT selected, because that is the only direction
	// graphql-cop offers: there is no include flag, only -e.
	//
	// It has to be built from a verified vocabulary. An unrecognised name does NOT stop the run and
	// does NOT disable anything: graphql-cop prints "<name> cannot be excluded, skipping" and the
	// check then runs. So a typo in an exclusion is a load generating query sent to a production
	// endpoint that the operator believed was turned off.
	anySelected := false
	for _, test := range graphqlCopTests {
		if truthySetting(settings[test.Key]) {
			anySelected = true
			break
		}
	}

	var excluded []string
	for _, test := range graphqlCopTests {
		switch {
		case anySelected && !truthySetting(settings[test.Key]):
			excluded = append(excluded, test.Flag)
		case !anySelected && test.DoS:
			// Nothing chosen: run the informational checks and leave the load generating ones out.
			excluded = append(excluded, test.Flag)
		}
	}
	if len(excluded) > 0 {
		args = append(args, "-e", strings.Join(excluded, ","))
	}

	if !anySelected {
		warnings = append(warnings, "No checks were selected, so this run used the eight informational "+
			"ones and left out the four that generate load: alias overloading, batching, directive "+
			"overloading and circular introspection. Turn those on deliberately.")
	} else {
		var enabledDoS []string
		for _, test := range graphqlCopTests {
			if test.DoS && truthySetting(settings[test.Key]) {
				enabledDoS = append(enabledDoS, test.Flag)
			}
		}
		if len(enabledDoS) > 0 {
			warnings = append(warnings, "Load generating checks are on ("+strings.Join(enabledDoS, ", ")+
				"). Alias overloading sends 101 aliases in one query and the batching check sends a "+
				"batched array; on a production endpoint that is real work for the server.")
		}
	}

	args = append(args, composeVectorSettings(tool, settings, "",
		map[string]bool{graphqlEndpointsSetting: true}, &warnings)...)

	args = append(args, "-o", "json")
	_ = reportPath
	return args, warnings
}

// ComposeClairvoyance builds the clairvoyance argv for one endpoint.
func ComposeClairvoyance(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("clairvoyance")
	var warnings []string

	args := []string{"-m", "clairvoyance"}

	skip := map[string]bool{graphqlEndpointsSetting: true}

	// A wordlist is not optional in practice: clairvoyance brute forces field names, so with no list
	// it has nothing to try. The shipped one is used unless the operator names another.
	if strings.TrimSpace(stringifySetting(settings["wordlist"])) == "" {
		args = append(args, "-w", clairvoyanceWordlist)
		skip["wordlist"] = true
		warnings = append(warnings, "No wordlist was set, so the one shipped with clairvoyance was "+
			"used. Everything this tool recovers comes from that list: a field whose name is not in "+
			"it is a field it cannot find, so a schema that looks thin is usually a wordlist problem "+
			"rather than a small schema.")
	}

	args = append(args, composeVectorSettings(tool, settings, "", skip, &warnings)...)

	// Framework owned, last. The schema goes to a file rather than stdout because stdout also carries
	// the tool's own logging and the runner merges the streams.
	args = append(args, "-o", reportPath, v.EvidenceURL)
	return args, warnings
}

// ComposeGraphw00f builds the graphw00f argv for one endpoint.
//
// Fingerprint mode always, detect mode only when asked. Detect walks a list of common GraphQL paths
// against the HOST, which is a different job from fingerprinting the endpoint that was given, and
// doing it silently on every run would multiply the request count for no benefit to an operator who
// has already said where the endpoint is.
func ComposeGraphw00f(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("graphw00f")
	var warnings []string

	args := []string{"-f", "-t", v.EvidenceURL}

	if truthySetting(settings["alsoDetect"]) {
		args = append(args, "-d")
		warnings = append(warnings, "Detect mode is on, so graphw00f also walks its list of common "+
			"GraphQL paths on this host rather than only fingerprinting the endpoint you gave it.")
	}

	args = append(args, composeVectorSettings(tool, settings, "",
		map[string]bool{graphqlEndpointsSetting: true, "alsoDetect": true}, &warnings)...)

	args = append(args, "-o", reportPath)
	return args, warnings
}
