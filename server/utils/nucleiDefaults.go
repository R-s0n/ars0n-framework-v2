package utils

import "strings"

// What a Nuclei scan runs when nobody has chosen otherwise.
//
// Kept in one place because the default was previously written out six times: the table DDL, the
// config API's empty-config response, the config modal's initial state, its load fallback, App.js's
// two loaders and the auto-scan step. Six copies of one list means the default silently depends on
// which path the operator arrived through, and a change that misses one of them is invisible until
// a scan comes back with the wrong templates.
//
// Deliberately not every category and not every severity. The excluded four either do not apply to
// a web target or answer a question the framework has already answered elsewhere:
//
//	network       port and service level checks, covered by the IP/port scanning stage
//	dns           resolver level checks, covered by the DNS enumeration stage
//	technologies  fingerprinting, not a vulnerability class, and duplicates httpx tech detection
//	headless      needs a browser per template, costs far more time than it returns
//
// Informational severity is off for the same reason: it is the bulk of Nuclei's output and almost
// none of it is actionable, so it buries the findings that are.
//
// These are defaults, not limits. Every category and severity is still selectable in the Nuclei
// Configure modal, and a target with a saved config keeps whatever it was given.
var (
	DefaultNucleiTemplates = []string{
		"cves",
		"vulnerabilities",
		"exposures",
		"misconfiguration",
		"takeovers",
	}

	DefaultNucleiSeverities = []string{
		"critical",
		"high",
		"medium",
		"low",
	}
)

// PostgresArrayLiteral renders a string slice as a Postgres array literal for use as a column
// default, so the DDL cannot drift from the Go values above.
//
// Only valid for the identifier-like values used here. It quotes nothing and escapes nothing,
// because a category or severity containing a comma, quote or backslash would be a bug worth
// failing on rather than quietly encoding.
func PostgresArrayLiteral(values []string) string {
	return "'{" + strings.Join(values, ",") + "}'"
}
