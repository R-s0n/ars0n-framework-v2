package utils

import (
	"strings"
	"testing"
)

// Two sections, split by what they are for.
//
// Sensitive Data Leaks & Exposed Secrets is DISCOVERY: snallygaster, Mantra and TruffleHog.
// Exposed Git Directories is what happens afterwards: git-dumper and GitTools, pointed at whatever
// the first section found.
//
// Measured against a lab where nothing sensitive is at the root:
//
//	snallygaster -p /app        -> dotenv    /app/.env
//	snallygaster -p /app/admin  -> git_dir   /app/admin/.git/config
//	Mantra on /app/main.js      -> the hardcoded Google API key
//	TruffleHog on a real key    -> PrivateKey, unverified
//	git-dumper on /app/admin/   -> critical, including a token deleted in a later commit

// Every tool in both sections takes a hand-picked endpoint list, because these files sit wherever an
// application was deployed and only the operator knows which endpoints matter.
func TestLeakSectionsTakeHandPickedEndpoints(t *testing.T) {
	sections := map[string][]string{
		"sensitive-leak": {"snallygaster", "mantra", "trufflehog"},
		"exposed-git":    {"git-dumper", "gittools"},
	}

	for category, tools := range sections {
		for _, key := range tools {
			tool, ok := VectorToolByKey(key)
			if !ok {
				t.Fatalf("%s is not registered", key)
			}
			if tool.Category != category {
				t.Errorf("%s belongs in %s, not %s", key, category, tool.Category)
			}
			if tool.RowSource == nil {
				t.Errorf("%s must take its targets from its own endpoint list", key)
			}
			if _, ok := tool.Options[graphqlEndpointsSetting]; !ok {
				t.Errorf("%s has no endpoints setting, so it can never be given a target", key)
			}
			if tool.Options[graphqlEndpointsSetting].Group != "Targets" {
				t.Errorf("%s must put its endpoints on a Targets tab", key)
			}
		}
	}
}

// snallygaster scans the ROOT by default, which is the mistake this section exists to avoid, so -p
// is always supplied and the scheme is pinned to the one the endpoint was picked at.
func TestSnallygasterScansThePickedEndpointNotTheRoot(t *testing.T) {
	v := VectorInput{EvidenceURL: "https://x.test/app/admin/"}
	args, _ := ComposeSnallygaster(v, map[string]any{}, "/tmp/rep")

	if !argsContainPair(args, "-p", "/app/admin") {
		t.Errorf("the directory must be passed with -p: %v", args)
	}
	if args[len(args)-1] != "x.test" {
		t.Errorf("the host is positional and last: %v", args)
	}
	if !argsContain(args, "-j") {
		t.Errorf("findings are read from the JSON output: %v", args)
	}

	// Left alone snallygaster scans http AND https AND www.<host>, turning one target into four and
	// sending three of them somewhere nobody asked about.
	if !argsContain(args, "--nowww") || !argsContain(args, "--nohttp") {
		t.Errorf("the scheme and www must be pinned: %v", args)
	}

	plain := VectorInput{EvidenceURL: "http://x.test/app/"}
	plainArgs, _ := ComposeSnallygaster(plain, map[string]any{}, "/tmp/rep")
	if !argsContain(plainArgs, "--nohttps") {
		t.Error("an http endpoint must not also be scanned over https")
	}

	// The site root has no path to pass, and -p '' would be meaningless.
	root := VectorInput{EvidenceURL: "https://x.test/"}
	if rootArgs, _ := ComposeSnallygaster(root, map[string]any{}, "/tmp/rep"); argsContain(rootArgs, "-p") {
		t.Errorf("the root needs no -p: %v", rootArgs)
	}
}

// Mantra reads its targets on STDIN, not from a flag.
func TestMantraTakesItsTargetOnStdin(t *testing.T) {
	v := VectorInput{EvidenceURL: "https://x.test/app.js"}
	args, _ := ComposeMantra(v, map[string]any{}, "/tmp/rep")

	if args[0] != "-c" {
		t.Fatalf("Mantra runs through a shell so the URL can be piped in: %v", args)
	}
	if !strings.Contains(args[1], "| mantra") {
		t.Errorf("the URL must be piped into mantra: %q", args[1])
	}
	if !strings.Contains(args[1], "x.test/app.js") {
		t.Errorf("the endpoint must reach the command: %q", args[1])
	}
	// Silent mode hides the very lines the findings are read from.
	tool, _ := VectorToolByKey("mantra")
	if _, owned := tool.OwnedFlags["-s"]; !owned {
		t.Error("-s must be framework owned: it suppresses the finding lines")
	}
}

// TruffleHog has NO URL source, so the framework fetches the endpoint and scans what came back.
func TestTruffleHogFetchesBeforeScanning(t *testing.T) {
	v := VectorInput{EvidenceURL: "https://x.test/app.js"}
	args, _ := ComposeTruffleHog(v, map[string]any{}, "/tmp/rep")

	if args[0] != "-c" {
		t.Fatalf("it runs through a shell: %v", args)
	}
	command := args[1]
	if !strings.Contains(command, "curl") {
		t.Errorf("TruffleHog cannot fetch a URL itself, so the framework must: %q", command)
	}
	if !strings.Contains(command, "trufflehog filesystem") {
		t.Errorf("the filesystem source is what scans the fetched body: %q", command)
	}
	if !strings.Contains(command, "--json") {
		t.Errorf("findings are read from the JSON output: %q", command)
	}

	// Turning verification off removes the reason to prefer this tool over a pattern matcher.
	_, warnings := ComposeTruffleHog(v, map[string]any{"noVerification": true}, "/tmp/rep")
	var warned bool
	for _, w := range warnings {
		if strings.Contains(w, "Live verification is off") {
			warned = true
		}
	}
	if !warned {
		t.Error("disabling verification must be reported")
	}
}

// A verified credential is a different class of finding from one that merely matched.
func TestTruffleHogGradesVerifiedCredentialsCritical(t *testing.T) {
	row := vectorRow{ID: "e1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "https://x.test/app.js", IsGraphQLTarget: true}

	report := `{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA...MPLE"}` + "\n" +
		`{"DetectorName":"PrivateKey","Verified":false,"Redacted":"-----BEGIN"}` + "\n"

	findings := parseTruffleHogOutput("", report, row)
	if len(findings) != 2 {
		t.Fatalf("expected two findings, got %d", len(findings))
	}

	bySeverity := map[string]string{}
	for _, f := range findings {
		bySeverity[f.InjectType] = f.Severity
	}
	if bySeverity["AWS"] != "critical" {
		t.Errorf("a credential TruffleHog used successfully is critical: %q", bySeverity["AWS"])
	}
	if bySeverity["PrivateKey"] != "medium" {
		t.Errorf("an unverified match is not proof: %q", bySeverity["PrivateKey"])
	}
}

// An endpoint Mantra could not fetch is not an endpoint with no secrets in it.
func TestMantraDistinguishesUnreachableFromClean(t *testing.T) {
	row := vectorRow{ID: "e1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "https://x.test/app.js", IsGraphQLTarget: true}

	unreachable := "[-] Unable to make a request for https://x.test/app.js\n"
	got := parseMantraOutput(unreachable, "", row)
	if len(got) != 1 || got[0].Kind != "not-tested" {
		t.Fatalf("an unfetchable endpoint must not read as clean: %+v", got)
	}

	hit := "[+] https://x.test/app.js [ apiKey:\"AIzaSyD-x9\" ]\n"
	found := parseMantraOutput(hit, "", row)
	if len(found) != 1 || found[0].Kind != "hardcoded-secret" {
		t.Fatalf("a match must be reported: %+v", found)
	}
	if !strings.Contains(found[0].Confidence, "TruffleHog") {
		t.Errorf("Mantra matches patterns; the report should point at the tool that verifies: %q",
			found[0].Confidence)
	}

	// A run that found nothing and fetched fine is genuinely clean.
	if got := parseMantraOutput("", "", row); len(got) != 0 {
		t.Errorf("a clean run produces nothing: %+v", got)
	}
}

// The .git URL is built with a trailing slash, because both tools join paths onto it.
func TestGitURLIsBuiltFromTheDirectory(t *testing.T) {
	if got := gitURLFor("https://x.test/app/admin/"); got != "https://x.test/app/admin/.git/" {
		t.Errorf("expected the .git under the directory, got %q", got)
	}
	if got := gitURLFor("https://x.test/app/admin"); got != "https://x.test/app/admin/.git/" {
		t.Errorf("a missing trailing slash must not change the result: %q", got)
	}
	// An operator who pastes the .git URL itself should not get .git/.git/.
	if got := gitURLFor("https://x.test/app/admin/.git"); got != "https://x.test/app/admin/.git/" {
		t.Errorf("a .git URL must be accepted as it is: %q", got)
	}
}

// The handover: snallygaster reports the FILE it matched, the recovery tools want the directory.
func TestGitDirectoryIsDerivedFromWhatWasFound(t *testing.T) {
	cases := map[string]string{
		"http://x.test/app/admin/.git/config": "http://x.test/app/admin/",
		"https://x.test/.git/config":          "https://x.test/",
		"http://x.test/legacy/.svn/entries":   "http://x.test/legacy/",
	}
	for found, want := range cases {
		if got := gitDirectoryOf(found); got != want {
			t.Errorf("%s should hand over %s, got %s", found, want, got)
		}
	}
	// Anything that is not a version control hit contributes nothing.
	if got := gitDirectoryOf("http://x.test/app/.env"); got != "" {
		t.Errorf("a .env is not a repository: %q", got)
	}
}

// Success is what ended up on disk, not the exit code, and the two tools leave DIFFERENT things.
//
// Measured: git-dumper checks out a working tree, while GitTools' Dumper downloads only the .git
// directory and the working tree does not exist until Extractor runs. An earlier version counted
// only files outside .git, which read correctly for git-dumper and reported nine recovered files as
// zero for GitTools.
func TestGitManifestCountsWhatEachToolActuallyLeaves(t *testing.T) {
	row := vectorRow{ID: "d1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "https://x.test/app/admin/", IsGraphQLTarget: true}

	nothing := "## FILES\n## FILECOUNT\n0\n## COMMITS\n## SECRETS\n"
	if got := parseGitManifest("", nothing, row, "git-dumper"); len(got) != 0 {
		t.Errorf("an empty directory is not a finding: %+v", got)
	}

	// GitTools: everything recovered is under .git, so FILES is empty and FILECOUNT is not.
	gitOnly := "## FILES\n## FILECOUNT\n9\n## COMMITS\n## SECRETS\n"
	got := parseGitManifest("", gitOnly, row, "gittools")
	if len(got) != 1 {
		t.Fatalf("nine recovered files is a finding even with no working tree: %+v", got)
	}
	if !strings.Contains(got[0].Evidence, "9 files") {
		t.Errorf("the count belongs in the evidence: %q", got[0].Evidence)
	}
}

// A credential in the HISTORY is the finding, and it outranks the repository being exposed.
func TestGitManifestGradesRecoveredCredentialsCritical(t *testing.T) {
	row := vectorRow{ID: "d1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "https://x.test/app/admin/", IsGraphQLTarget: true}

	report := "## FILES\n/tmp/x/index.html\n## FILECOUNT\n1\n## COMMITS\n9d1167b remove secrets\n" +
		"f6f95c8 add secrets\n## SECRETS\nAPI_TOKEN=committed-then-deleted-9931\n"

	got := parseGitManifest("", report, row, "git-dumper")
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].Severity != "critical" {
		t.Errorf("credentials in the history outrank the repository itself: %q", got[0].Severity)
	}
	if !strings.Contains(got[0].Evidence, "committed-then-deleted-9931") {
		t.Errorf("the recovered credential is the finding: %q", got[0].Evidence)
	}
}

// snallygaster's JSON is a flat array of {cause,url,misc}, captured from a real run.
func TestSnallygasterParsesItsJSON(t *testing.T) {
	row := vectorRow{ID: "d1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://x.test/app/", IsGraphQLTarget: true}

	report := `[{"cause": "dotenv", "url": "http://x.test/app/.env", "misc": ""},` +
		`{"cause": "ds_store", "url": "http://x.test/app/.DS_Store", "misc": ""}]`

	findings := parseSnallygasterOutput(report, "", row)
	if len(findings) != 2 {
		t.Fatalf("expected two findings, got %d", len(findings))
	}

	bySeverity := map[string]string{}
	for _, f := range findings {
		bySeverity[f.InjectType] = f.Severity
	}
	if bySeverity["dotenv"] != "high" {
		t.Errorf("a .env normally holds credentials: %q", bySeverity["dotenv"])
	}
	if bySeverity["ds_store"] != "low" {
		t.Errorf("a .DS_Store leaks file names, not contents: %q", bySeverity["ds_store"])
	}

	if got := parseSnallygasterOutput("[]", "", row); len(got) != 0 {
		t.Errorf("an empty result is clean for this tool: %+v", got)
	}
}

// A URL reaches a shell in both sections, so it is quoted.
func TestShellQuotingSurvivesAHostileURL(t *testing.T) {
	quoted := shellQuote("https://x.test/a'; touch /tmp/pwned; echo '")
	if strings.Contains(quoted, "; touch") && !strings.Contains(quoted, `'\''`) {
		t.Errorf("a quote in a URL must be broken out, not passed through: %s", quoted)
	}
	if !strings.HasPrefix(quoted, "'") || !strings.HasSuffix(quoted, "'") {
		t.Errorf("the value must be wrapped: %s", quoted)
	}
}
