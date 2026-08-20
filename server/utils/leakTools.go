package utils

import (
	"time"
)

// Two sections, split by what they are FOR.
//
// Sensitive Data Leaks & Exposed Secrets is DISCOVERY: snallygaster looks for the files people leave
// behind, Mantra reads the JavaScript a target serves, and TruffleHog verifies whether a string that
// looks like a credential still works.
//
// Exposed Git Directories is what you do AFTERWARDS. git-dumper and GitTools rebuild a repository,
// which is only worth doing somewhere a repository actually is, so their config tab flags the .git
// directories snallygaster has already found.
//
// In both sections the targets are chosen by the operator, per tool, in the config modal. Nothing is
// derived automatically: these files sit wherever an application was deployed, so the operator
// pointing at a directory is the whole mechanism.

var snallygasterOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Targets", Label: "Endpoints to scan (one per line)",
		Placeholder: "https://target/app/admin/"},
	"tests":     {Kind: "string", Group: "Scan", Label: "Only these tests (comma separated)", Flag: "-t"},
	"info":      {Kind: "bool", Group: "Scan", Label: "Include informational tests", Flag: "-i"},
	"noisy":     {Kind: "bool", Group: "Scan", Label: "Include noisy tests (boring bugs, no security issue)", Flag: "-n"},
	"userAgent": {Kind: "string", Group: "Request", Label: "User-Agent", Flag: "--useragent"},
	"debug":     {Kind: "bool", Group: "Scan", Label: "Debug output", Flag: "-d"},
}

var snallygasterOwned = map[string]string{
	"-p":        "The directory comes from the endpoint you picked, so the scan looks where the application actually is rather than at the site root.",
	"--path":    "The directory comes from the endpoint you picked, so the scan looks where the application actually is rather than at the site root.",
	"-j":        "Findings are read from the JSON output, so the format is fixed.",
	"--json":    "Findings are read from the JSON output, so the format is fixed.",
	"--nowww":   "www.<host> is a DIFFERENT host, and scanning it would be testing something nobody put in scope.",
	"--nohttp":  "The scheme comes from the endpoint you picked; scanning both doubles every target.",
	"--nohttps": "The scheme comes from the endpoint you picked; scanning both doubles every target.",
}

var mantraOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Targets", Label: "Endpoints to scan (one per line)",
		Placeholder: "https://target/app.js"},
	"threads":       {Kind: "int", Group: "Scan", Label: "Threads", Flag: "-t", Placeholder: "50"},
	"detailed":      {Kind: "bool", Group: "Scan", Label: "Detailed output", Flag: "-d"},
	"extraPattern":  {Kind: "string", Group: "Scan", Label: "Extra regex pattern", Flag: "-ep"},
	"cookies":       {Kind: "string", Group: "Request", Label: "Cookies", Flag: "-c"},
	"userAgent":     {Kind: "string", Group: "Request", Label: "User-Agent", Flag: "-ua", Placeholder: "Mantra"},
}

var mantraOwned = map[string]string{
	"-s": "Silent mode hides the lines the findings are read from.",
}

var truffleHogOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Targets", Label: "Endpoints to scan (one per line)",
		Placeholder: "https://target/app.js"},
	"results":        {Kind: "string", Group: "Scan", Label: "Result types", Flag: "--results", Placeholder: "verified,unverified,unknown"},
	"noVerification": {Kind: "bool", Group: "Scan", Label: "Skip live verification", Flag: "--no-verification"},
	"concurrency":    {Kind: "int", Group: "Scan", Label: "Concurrent workers", Flag: "--concurrency"},
	"filterUnverified": {Kind: "bool", Group: "Scan", Label: "Only the first unverified result per chunk", Flag: "--filter-unverified"},
	"includeDetectors": {Kind: "string", Group: "Scan", Label: "Only these detectors", Flag: "--include-detectors"},
	"excludeDetectors": {Kind: "string", Group: "Scan", Label: "Exclude these detectors", Flag: "--exclude-detectors"},
}

var truffleHogOwned = map[string]string{
	"--json":     "Findings are read from the JSON output, so the format is fixed.",
	"-j":         "Findings are read from the JSON output, so the format is fixed.",
	"--no-color": "Escape codes would end up in the evidence.",
	"filesystem": "The framework fetches what you pointed it at and scans that, because TruffleHog has no URL source of its own.",
}

var gitDumperOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Targets", Label: "Directories with an exposed .git (one per line)",
		Placeholder: "https://target/app/admin/"},
	"jobs":      {Kind: "int", Group: "Scan", Label: "Simultaneous requests", Flag: "-j"},
	"retry":     {Kind: "int", Group: "Scan", Label: "Attempts before giving up", Flag: "-r"},
	"timeout":   {Kind: "int", Group: "Scan", Label: "Timeout (s)", Flag: "-t"},
	"userAgent": {Kind: "string", Group: "Request", Label: "User-Agent", Flag: "-u"},
	"headers":   {Kind: "string", Group: "Request", Label: "Header (NAME=VALUE)", Flag: "-H", Repeatable: true},
	"proxy":     {Kind: "string", Group: "Request", Label: "Proxy", Flag: "--proxy"},
}

var gitDumperOwned = map[string]string{
	"URL": "The .git URL is built from the directory you picked.",
	"DIR": "The output directory is per scan, and is how the result is read back.",
}

var gitToolsOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Targets", Label: "Directories with an exposed .git (one per line)",
		Placeholder: "https://target/app/admin/"},
	"extractCommits": {Kind: "bool", Group: "Scan", Label: "Rebuild every commit into its own directory"},
}

var gitToolsOwned = map[string]string{
	"gitdumper.sh": "Driven from the directory you picked.",
	"extractor.sh": "Run against what the dumper produced.",
	"gitfinder.py": "Not used: Finder is domain-only and hardcodes http://, so it cannot look inside a directory.",
}

func init() {
	registerVectorTools(
		VectorTool{
			Key: "snallygaster", Name: "snallygaster", Category: "sensitive-leak",
			Binary: "snallygaster", Container: "ars0n-framework-v2-snallygaster-1",
			Groups: []string{"Targets", "Scan", "Request"}, Options: snallygasterOptions, OwnedFlags: snallygasterOwned,
			InsertionPoints: VectorInsertionPoints,
			RowSource:       graphqlRowSource("snallygaster"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "endpoint",
			Compose:         ComposeSnallygaster,
			Parse:           parseSnallygasterOutput,
			// Measured at 189 requests and five seconds for one directory against a server that answers
			// immediately. A slow target multiplies the seconds, not the requests.
			Timeout: 10 * time.Minute,
			Limitation: "snallygaster checks one DIRECTORY for the files people leave behind: .git, " +
				".svn, .env, .DS_Store, backups, private keys, core dumps, phpinfo and server-status. " +
				"It scans the site root by default, which is the usual mistake, so the framework points " +
				"it at whichever endpoint you picked instead: these files sit wherever the application " +
				"was deployed, which is normally a subdirectory. Costs about 189 requests per endpoint. " +
				"When it finds a .git, take that directory over to Exposed Git Directories below.",
		},
		VectorTool{
			Key: "mantra", Name: "Mantra", Category: "sensitive-leak",
			Binary: "sh", Container: "ars0n-framework-v2-mantra-1",
			Groups: []string{"Targets", "Scan", "Request"}, Options: mantraOptions, OwnedFlags: mantraOwned,
			InsertionPoints: VectorInsertionPoints,
			RowSource:       graphqlRowSource("mantra"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "endpoint",
			Compose:         ComposeMantra,
			Parse:           parseMantraOutput,
			Timeout:         15 * time.Minute,
			Limitation: "Mantra reads the JavaScript and HTML an endpoint serves and looks for hardcoded " +
				"API keys and credentials in it. It takes its targets on stdin. What it reports is " +
				"pattern matching rather than proof, so treat a hit as something to check rather than " +
				"as a confirmed credential: TruffleHog is the tool that tries the key.",
		},
		VectorTool{
			Key: "trufflehog", Name: "TruffleHog", Category: "sensitive-leak",
			Binary: "sh", Container: "ars0n-framework-v2-trufflehog-1",
			Groups: []string{"Targets", "Scan"}, Options: truffleHogOptions, OwnedFlags: truffleHogOwned,
			InsertionPoints: VectorInsertionPoints,
			RowSource:       graphqlRowSource("trufflehog"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "endpoint",
			UsesReportFile:  true,
			Compose:         ComposeTruffleHog,
			Parse:           parseTruffleHogOutput,
			Timeout:         20 * time.Minute,
			Limitation: "TruffleHog has no URL source of its own, so the framework fetches what you " +
				"pointed it at and scans that. Its detectors PARSE what they match before reporting: " +
				"measured, a random blob between PEM markers is ignored while a real key is caught, " +
				"which is why it has so few false positives and why silence from it is meaningful. It " +
				"then tries the credential live, and a verified result is the difference between a " +
				"string that looks like a key and one that still works.",
		},

		VectorTool{
			Key: "git-dumper", Name: "git-dumper", Category: "exposed-git",
			// bash, not git-dumper: the command runs the dumper and then writes a manifest, because
			// git-dumper exits 0 whether it recovered a repository or found nothing and its real
			// output is a directory.
			Binary: "bash", Container: "ars0n-framework-v2-git-dumper-1",
			Groups: []string{"Targets", "Scan", "Request"}, Options: gitDumperOptions, OwnedFlags: gitDumperOwned,
			InsertionPoints: VectorInsertionPoints,
			RowSource:       graphqlRowSource("git-dumper"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "repository",
			Compose:         ComposeGitDumper,
			Parse:           parseGitDumperOutput,
			UsesReportFile:  true,
			Timeout:         30 * time.Minute,
			Limitation: "git-dumper rebuilds a repository from an exposed .git even when directory " +
				"listing is off, by reading the index and the packed refs rather than crawling. Point " +
				"it at the directory CONTAINING the .git. It downloads the whole object store, not just " +
				"the current tree, so a secret committed and later deleted is still recoverable: " +
				"measured, a token removed in a second commit came back from the first. The framework " +
				"greps every object for credentials rather than only the checked-out files.",
		},
		VectorTool{
			Key: "gittools", Name: "GitTools", Category: "exposed-git",
			Binary: "bash", Container: "ars0n-framework-v2-gittools-1",
			Groups: []string{"Targets", "Scan"}, Options: gitToolsOptions, OwnedFlags: gitToolsOwned,
			InsertionPoints: VectorInsertionPoints,
			RowSource:       graphqlRowSource("gittools"),
			DedupeKey:       func(v VectorInput) string { return v.EvidenceURL },
			ScanUnit:        "repository",
			Compose:         ComposeGitTools,
			Parse:           parseGitToolsOutput,
			UsesReportFile:  true,
			Timeout:         30 * time.Minute,
			Limitation: "GitTools is used here as its Dumper and Extractor. Its Finder is not: that " +
				"part only accepts bare domains and hardcodes http://, so it cannot look inside a " +
				"directory and would miss an HTTPS-only host entirely. Both this and git-dumper " +
				"recover the full history; what Extractor adds is a directory PER COMMIT, which is the " +
				"convenient shape when the job is grepping every historical state at once rather than " +
				"walking one repository with git log.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}{"sensitive-leak", "Sensitive Data Leaks & Exposed Secrets"},
		struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		}{"exposed-git", "Exposed Git Directories"})
}
