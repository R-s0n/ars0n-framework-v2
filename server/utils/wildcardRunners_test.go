package utils

import (
	"strings"
	"testing"
)

// These tests exist for one reason: a settings screen whose values are silently ignored is worse
// than no settings screen. Two properties are asserted for every runner that was wired.
//
//	1. WITH NOTHING STORED THE COMMAND LINE IS UNCHANGED, byte for byte, from what it was before any
//	   of this existed. That is what makes wiring safe to ship: an operator who has never opened the
//	   config screen must not be able to tell that it was built.
//	2. WITH SOMETHING STORED IT REACHES THE COMMAND LINE. Not "would_add_args says it would"; the
//	   actual argument vector the runner hands to exec.Command.
//
// The default vectors below are written out as literals on purpose. A helper that regenerates them
// from the same code under test would pass no matter what changed, which is exactly the failure
// these are guarding against.

func wildcardTestTool(t *testing.T, key string) WildcardTool {
	t.Helper()
	tool, ok := WildcardToolByKey(key)
	if !ok {
		t.Fatalf("the registry has no tool called %q", key)
	}
	return tool
}

func assertArgv(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("argument count differs.\n got (%d): %s\nwant (%d): %s",
			len(got), strings.Join(got, " "), len(want), strings.Join(want, " "))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argument %d differs: got %q, want %q\n got: %s\nwant: %s",
				i, got[i], want[i], strings.Join(got, " "), strings.Join(want, " "))
		}
	}
}

func argvIndex(argv []string, token string) int {
	for i, a := range argv {
		if a == token {
			return i
		}
	}
	return -1
}

func argvHas(argv []string, token string) bool {
	return argvIndex(argv, token) >= 0
}

// argvValue returns the value following a flag, or "" when the flag is absent.
func argvValue(argv []string, flag string) string {
	i := argvIndex(argv, flag)
	if i < 0 || i+1 >= len(argv) {
		return ""
	}
	return argv[i+1]
}

// ---------------------------------------------------------------------------------------------
// gospider
// ---------------------------------------------------------------------------------------------

func gospiderDefaultArgv(url string) []string {
	return []string{
		"docker", "exec",
		"ars0n-framework-v2-gospider-1",
		"timeout", "300",
		"gospider",
		"-s", url,
		"-c", "10",
		"-d", "3",
		"-t", "3",
		"-k", "1",
		"-K", "2",
		"-m", "30",
		"--blacklist", ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|svg)",
		"-a",
		"-w",
		"-r",
		"--js",
		"--sitemap",
		"--robots",
		"--debug",
		"--json",
		"-v",
	}
}

func TestGoSpiderWildcardDefaultCommandIsUnchanged(t *testing.T) {
	tool := wildcardTestTool(t, "gospider")

	argv, notes := buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, map[string]any{})
	assertArgv(t, argv, gospiderDefaultArgv("https://www.example.com"))
	if len(notes) != 0 {
		t.Errorf("an unconfigured scan should produce no notes, got %v", notes)
	}

	// nil, not just empty: a target whose settings row does not exist at all.
	argv, _ = buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, nil)
	assertArgv(t, argv, gospiderDefaultArgv("https://www.example.com"))

	// And with the global custom HTTP settings populated, which is the other shape this runner has
	// always produced.
	argv, _ = buildGoSpiderWildcardCommand("https://www.example.com", "ars0n/1.0", "X-Bug-Bounty: rs0n", tool, nil)
	assertArgv(t, argv, append(gospiderDefaultArgv("https://www.example.com"),
		"--user-agent", "ars0n/1.0", "--header", "X-Bug-Bounty: rs0n"))
}

func TestGoSpiderWildcardSettingReachesTheCommandLine(t *testing.T) {
	tool := wildcardTestTool(t, "gospider")

	argv, _ := buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, map[string]any{
		"concurrent": 30,
		"depth":      1,
		"proxy":      "http://10.0.0.5:8080",
	})

	if got := argvValue(argv, "-c"); got != "30" {
		t.Errorf("concurrent did not reach the command line: -c is %q, want 30", got)
	}
	if got := argvValue(argv, "-d"); got != "1" {
		t.Errorf("depth did not reach the command line: -d is %q, want 1", got)
	}
	if got := argvValue(argv, "-p"); got != "http://10.0.0.5:8080" {
		t.Errorf("proxy did not reach the command line: -p is %q", got)
	}

	// Replaced IN PLACE, not appended alongside. A command line carrying `-c 10 ... -c 30` would run
	// correctly and still make the stored command a bad answer to "what did this run".
	if strings.Count(strings.Join(argv, " "), "-c ") != 1 {
		t.Errorf("-c appears more than once: %s", strings.Join(argv, " "))
	}
	if argvHas(argv, "10") {
		t.Errorf("the runner's hardcoded -c value survived alongside the setting: %s", strings.Join(argv, " "))
	}
}

// The trap the URL workflow already shipped once. GoSpider's --js and --robots default to TRUE
// inside the tool, so a composer that simply omits the flag leaves the feature ON while the UI says
// it is off: a switch that does nothing in either position.
func TestGoSpiderWildcardDefaultsTrueSwitchesAreNegated(t *testing.T) {
	tool := wildcardTestTool(t, "gospider")

	argv, notes := buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, map[string]any{
		"js":     false,
		"robots": false,
	})
	if !argvHas(argv, "--js=false") {
		t.Errorf("js off did not become --js=false: %s", strings.Join(argv, " "))
	}
	if !argvHas(argv, "--robots=false") {
		t.Errorf("robots off did not become --robots=false: %s", strings.Join(argv, " "))
	}
	if argvHas(argv, "--js") || argvHas(argv, "--robots") {
		t.Errorf("the bare enabling flag survived next to its negation: %s", strings.Join(argv, " "))
	}
	if len(notes) == 0 {
		t.Error("negating a defaults-true switch should be reported, because it is not obvious")
	}

	// A switch whose tool default is FALSE is turned off by removing the flag, not by negating it.
	argv, _ = buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, map[string]any{
		"sitemap":     false,
		"otherSource": false,
	})
	if argvHas(argv, "--sitemap") || argvHas(argv, "--sitemap=false") {
		t.Errorf("sitemap off should simply drop the flag: %s", strings.Join(argv, " "))
	}
	if argvHas(argv, "-a") {
		t.Errorf("otherSource off should drop -a: %s", strings.Join(argv, " "))
	}
	// Turning it back on puts it back exactly once.
	argv, _ = buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, map[string]any{"sitemap": true})
	if n := strings.Count(strings.Join(argv, " "), "--sitemap"); n != 1 {
		t.Errorf("sitemap on should appear exactly once, got %d: %s", n, strings.Join(argv, " "))
	}
}

// MEASURED: `--blacklist '['` panics GoSpider through regexp.MustCompile, the runner logs a WARN and
// moves to the next URL, and the whole scan stores as "No results found" with nothing naming the
// cause. One bad character must not be able to do that.
func TestGoSpiderWildcardInvalidRegexIsDroppedNotSent(t *testing.T) {
	tool := wildcardTestTool(t, "gospider")

	argv, notes := buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, map[string]any{
		"blacklist": "[",
	})
	if argvValue(argv, "--blacklist") == "[" {
		t.Fatalf("an uncompilable regex reached the command line: %s", strings.Join(argv, " "))
	}
	if len(notes) == 0 || !strings.Contains(strings.Join(notes, " "), "DROPPED") {
		t.Errorf("dropping a setting must be reported, got %v", notes)
	}
	// The runner's own blacklist is still there: dropping the operator's value must not disarm the
	// asset filter the crawl has always had.
	if argvValue(argv, "--blacklist") == "" {
		t.Errorf("the runner's own blacklist disappeared: %s", strings.Join(argv, " "))
	}

	// A valid one goes straight through and replaces the runner's.
	argv, _ = buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, map[string]any{
		"blacklist": `\.(png|jpg)$`,
	})
	if got := argvValue(argv, "--blacklist"); got != `\.(png|jpg)$` {
		t.Errorf("a valid blacklist did not reach the command line: %q", got)
	}
}

// Two screens must not be able to disagree about one flag. The per-target setting wins and the
// global is not sent at all, so the stored command shows one value for one flag.
func TestGoSpiderWildcardPerTargetSettingBeatsTheGlobalHTTPSettings(t *testing.T) {
	tool := wildcardTestTool(t, "gospider")

	argv, notes := buildGoSpiderWildcardCommand("https://www.example.com", "global-agent", "X-Global: 1", tool,
		map[string]any{"userAgent": "mobi", "headers": "Authorization: Bearer t"})

	if argvHas(argv, "--user-agent") {
		t.Errorf("the global User-Agent was still sent: %s", strings.Join(argv, " "))
	}
	if argvHas(argv, "--header") {
		t.Errorf("the global custom header was still sent: %s", strings.Join(argv, " "))
	}
	if got := argvValue(argv, "-u"); got != "mobi" {
		t.Errorf("the per-target userAgent did not reach the command line: %q", got)
	}
	if got := argvValue(argv, "-H"); got != "Authorization: Bearer t" {
		t.Errorf("the per-target header did not reach the command line: %q", got)
	}
	if len(notes) < 2 {
		t.Errorf("displacing a global setting must be reported, got %v", notes)
	}

	// With nothing per-target stored the globals are sent exactly as they always were.
	argv, _ = buildGoSpiderWildcardCommand("https://www.example.com", "global-agent", "X-Global: 1", tool, nil)
	if argvValue(argv, "--user-agent") != "global-agent" || argvValue(argv, "--header") != "X-Global: 1" {
		t.Errorf("the globals stopped working when nothing was configured: %s", strings.Join(argv, " "))
	}
}

// ---------------------------------------------------------------------------------------------
// subdomainizer
// ---------------------------------------------------------------------------------------------

func subdomainizerDefaultArgv(url string) []string {
	return []string{
		"docker", "exec",
		"ars0n-framework-v2-subdomainizer-1",
		"timeout", "300",
		"python3", "SubDomainizer.py",
		"-u", url,
		"-k",
		"-o", "/tmp/subdomainizer-mounts/output.txt",
		"-sop", "/tmp/subdomainizer-mounts/secrets.txt",
	}
}

func TestSubdomainizerWildcardDefaultCommandIsUnchanged(t *testing.T) {
	tool := wildcardTestTool(t, "subdomainizer")

	argv, notes := buildSubdomainizerWildcardCommand("https://www.example.com", tool, map[string]any{})
	assertArgv(t, argv, subdomainizerDefaultArgv("https://www.example.com"))
	if len(notes) != 0 {
		t.Errorf("an unconfigured scan should produce no notes, got %v", notes)
	}

	argv, _ = buildSubdomainizerWildcardCommand("https://www.example.com", tool, nil)
	assertArgv(t, argv, subdomainizerDefaultArgv("https://www.example.com"))
}

// -k is --nossl: THE FLAG IS THE OFF STATE. A generic bool composer emits the flag when the value is
// true, which would turn "verify certificates" into "do not verify certificates". Getting this
// backwards is not a cosmetic bug: omitting -k on a wildcard target makes every host with a
// mismatched certificate raise a fatal ConnectionError, which this runner records as a skipped host.
func TestSubdomainizerWildcardVerifyTLSIsTheInverseOfItsFlag(t *testing.T) {
	tool := wildcardTestTool(t, "subdomainizer")

	for _, tc := range []struct {
		name     string
		settings map[string]any
		wantK    bool
	}{
		{"unset keeps the runner's -k", map[string]any{}, true},
		{"verification off keeps -k", map[string]any{"verifyTls": false}, true},
		{"verification on removes -k", map[string]any{"verifyTls": true}, false},
	} {
		argv, _ := buildSubdomainizerWildcardCommand("https://www.example.com", tool, tc.settings)
		if got := argvHas(argv, "-k"); got != tc.wantK {
			t.Errorf("%s: -k present = %v, want %v (%s)", tc.name, got, tc.wantK, strings.Join(argv, " "))
		}
	}
}

// REPRODUCED against the installed tool: -g without -gt prints "Either both '-g' and '-gt' arguments
// are required or none required. Exiting..." and exits 1. This runner treats a non-zero exit as a
// per-URL failure and continues, so sending it would skip EVERY live host and store the scan as
// "No results found" with nothing naming the cause.
func TestSubdomainizerWildcardGitScanWithoutATokenIsRefused(t *testing.T) {
	tool := wildcardTestTool(t, "subdomainizer")

	argv, notes := buildSubdomainizerWildcardCommand("https://www.example.com", tool, map[string]any{
		"gitScan": true,
	})
	if argvHas(argv, "-g") {
		t.Fatalf("-g was sent with no token, which exits 1 on every host: %s", strings.Join(argv, " "))
	}
	if !strings.Contains(strings.Join(notes, " "), "gitScan was DROPPED") {
		t.Errorf("dropping gitScan must be reported, got %v", notes)
	}

	// With a token it goes through.
	argv, _ = buildSubdomainizerWildcardCommand("https://www.example.com", tool, map[string]any{
		"gitScan":  true,
		"gitToken": "ghp_example",
	})
	if !argvHas(argv, "-g") || argvValue(argv, "-gt") != "ghp_example" {
		t.Errorf("gitScan with a token did not reach the command line: %s", strings.Join(argv, " "))
	}
}

func TestSubdomainizerWildcardSettingsReachTheCommandLine(t *testing.T) {
	tool := wildcardTestTool(t, "subdomainizer")

	argv, _ := buildSubdomainizerWildcardCommand("https://www.example.com", tool, map[string]any{
		"extraDomains": "iana.org,example.net",
		"sanMode":      "same",
		"cookie":       "session=abc",
	})
	if got := argvValue(argv, "-d"); got != "iana.org,example.net" {
		t.Errorf("extraDomains did not reach the command line: %q", got)
	}
	if got := argvValue(argv, "-san"); got != "same" {
		t.Errorf("sanMode did not reach the command line: %q", got)
	}
	if got := argvValue(argv, "-c"); got != "session=abc" {
		t.Errorf("cookie did not reach the command line: %q", got)
	}
}

// The three collect switches carry no flag of their own because the FILENAME is runner owned. They
// are still real settings, and this is the half of them that reaches a command line.
func TestSubdomainizerWildcardCollectSwitchesOwnTheirPaths(t *testing.T) {
	tool := wildcardTestTool(t, "subdomainizer")

	// Secret extraction is paid for on every run today. Turning it off is the one thing that changes
	// the command line as things stand.
	argv, _ := buildSubdomainizerWildcardCommand("https://www.example.com", tool, map[string]any{
		"collectSecrets": false,
	})
	if argvHas(argv, "-sop") {
		t.Errorf("collectSecrets off should drop -sop: %s", strings.Join(argv, " "))
	}

	argv, _ = buildSubdomainizerWildcardCommand("https://www.example.com", tool, map[string]any{
		"collectCloudAssets": true,
	})
	if argvValue(argv, "-cop") != subdomainizerWildcardCloudPath {
		t.Errorf("collectCloudAssets did not add -cop with the runner's own path: %s", strings.Join(argv, " "))
	}

	// -gop is only meaningful with a working git scan, and a git scan without a token is refused, so
	// this must not produce a -gop for a scan that will not run a GitHub search at all.
	argv, _ = buildSubdomainizerWildcardCommand("https://www.example.com", tool, map[string]any{
		"collectGithubSecrets": true,
		"gitScan":              true,
	})
	if argvHas(argv, "-gop") {
		t.Errorf("-gop was added for a gitScan that was refused for having no token: %s", strings.Join(argv, " "))
	}

	argv, _ = buildSubdomainizerWildcardCommand("https://www.example.com", tool, map[string]any{
		"collectGithubSecrets": true,
		"gitScan":              true,
		"gitToken":             "ghp_example",
	})
	if argvValue(argv, "-gop") != subdomainizerWildcardGithubSecret {
		t.Errorf("collectGithubSecrets did not add -gop: %s", strings.Join(argv, " "))
	}
}

// The SAN phase only PRINTS what it finds, and savedata() has already written the -o file by then,
// so without this recovery the switch is a control that provably changes nothing.
func TestSubdomainizerSANHostnameRecovery(t *testing.T) {
	stdout := "" +
		"https://www.example.com/js/app.js\n" +
		"____________________________________________________________\n" +
		"\nFinding additional subdomains using Subject Alternative Names(SANs)...\n\n" +
		"\x1b[1m\x1b[32mapi.example.com\x1b[0m\n" +
		"*.cdn.example.com\n" +
		"unrelated-tenant.othercorp.net\n" +
		"not a hostname at all\n"

	got := subdomainizerSANHostnames(stdout, "example.com")
	want := map[string]bool{"api.example.com": true, "cdn.example.com": true}
	if len(got) != len(want) {
		t.Fatalf("recovered %v, want exactly %v", got, want)
	}
	for _, host := range got {
		if !want[host] {
			t.Errorf("recovered %q, which is not in scope for example.com", host)
		}
	}

	// Nothing before the SAN header is ever harvested, so the normal crawl output cannot leak in.
	if hosts := subdomainizerSANHostnames("api.example.com\n", "example.com"); len(hosts) != 0 {
		t.Errorf("harvested %v from output with no SAN section", hosts)
	}
}

// ---------------------------------------------------------------------------------------------
// nuclei-screenshot
// ---------------------------------------------------------------------------------------------

func nucleiScreenshotDefaultArgv() []string {
	return []string{
		"docker", "exec", "ars0n-framework-v2-nuclei-1", "nuclei",
		"-t", "/root/nuclei-templates/headless/screenshot.yaml",
		"-list", "/urls.txt",
		"-headless",
		"-c", "25",
		"-rl", "150",
		"-timeout", "10",
		"-retries", "1",
		"-bs", "25",
	}
}

func TestNucleiScreenshotDefaultCommandIsUnchanged(t *testing.T) {
	tool := wildcardTestTool(t, "nuclei-screenshot")

	argv, notes := buildNucleiScreenshotCommand("", "", tool, map[string]any{})
	assertArgv(t, argv, nucleiScreenshotDefaultArgv())
	if len(notes) != 0 {
		t.Errorf("an unconfigured scan should produce no notes, got %v", notes)
	}

	argv, _ = buildNucleiScreenshotCommand("ars0n/1.0", "X-Bug-Bounty: rs0n", tool, nil)
	assertArgv(t, argv, append(nucleiScreenshotDefaultArgv(),
		"-H", "X-Bug-Bounty: rs0n", "-H", "User-Agent: ars0n/1.0"))
}

func TestNucleiScreenshotSettingReachesTheCommandLine(t *testing.T) {
	tool := wildcardTestTool(t, "nuclei-screenshot")

	argv, _ := buildNucleiScreenshotCommand("", "", tool, map[string]any{
		"concurrency":  5,
		"rateLimit":    20,
		"systemChrome": true,
	})
	if got := argvValue(argv, "-c"); got != "5" {
		t.Errorf("concurrency did not reach the command line: -c is %q", got)
	}
	if got := argvValue(argv, "-rl"); got != "20" {
		t.Errorf("rateLimit did not reach the command line: -rl is %q", got)
	}
	if !argvHas(argv, "-sc") {
		t.Errorf("systemChrome did not reach the command line: %s", strings.Join(argv, " "))
	}
	if strings.Count(strings.Join(argv, " "), " -c ") != 1 {
		t.Errorf("the runner's hardcoded -c survived alongside the setting: %s", strings.Join(argv, " "))
	}
	// bulkSize was not configured, so the runner's own value is still there. Wiring one option must
	// not disturb the others.
	if got := argvValue(argv, "-bs"); got != "25" {
		t.Errorf("an unconfigured flag changed: -bs is %q, want the runner's 25", got)
	}
}

// ---------------------------------------------------------------------------------------------
// nuclei (engine flags)
// ---------------------------------------------------------------------------------------------

// The vector executeNucleiScan builds from nuclei_configs before the overlay runs, in the order it
// builds it.
func nucleiBaseArgv() []string {
	return []string{
		"-list", "/targets.txt", "-jsonl", "-nh", "-o", "/output.jsonl",
		"-c", "25", "-rl", "150", "-timeout", "10", "-retries", "1", "-bs", "25", "-mhe", "30",
	}
}

func TestNucleiWildcardDefaultCommandIsUnchanged(t *testing.T) {
	tool := wildcardTestTool(t, "nuclei")

	argv, notes := composeNucleiWildcardArgs(tool, map[string]any{}, nucleiBaseArgv())
	assertArgv(t, argv, nucleiBaseArgv())
	if len(notes) != 0 {
		t.Errorf("an unconfigured scan should produce no notes, got %v", notes)
	}

	argv, _ = composeNucleiWildcardArgs(tool, nil, nucleiBaseArgv())
	assertArgv(t, argv, nucleiBaseArgv())
}

// If nuclei_configs won this contest the Wildcard rate limit could never take effect under any
// circumstances, because the runner emits -rl on EVERY scan whether or not anything is stored. That
// is the difference between a setting and a decoration.
func TestNucleiWildcardSettingBeatsTheAdvancedConfigValue(t *testing.T) {
	tool := wildcardTestTool(t, "nuclei")

	argv, notes := composeNucleiWildcardArgs(tool, map[string]any{
		"rateLimit":    10,
		"maxHostError": 5,
	}, nucleiBaseArgv())

	if got := argvValue(argv, "-rl"); got != "10" {
		t.Errorf("rateLimit did not beat advanced_config: -rl is %q, want 10", got)
	}
	if got := argvValue(argv, "-mhe"); got != "5" {
		t.Errorf("maxHostError did not beat advanced_config: -mhe is %q, want 5", got)
	}
	if strings.Count(strings.Join(argv, " "), " -rl ") != 1 {
		t.Errorf("-rl appears more than once: %s", strings.Join(argv, " "))
	}
	if len(notes) == 0 {
		t.Error("displacing a value that came from another store must be reported")
	}
}

// A flag the runner owns must never reach the command line, even from a row written before the flag
// became owned. nuclei's -o and -jsonl decide whether any finding is parseable at all.
func TestNucleiWildcardOwnedFlagsCannotBeSmuggledIn(t *testing.T) {
	tool := wildcardTestTool(t, "nuclei")

	argv, notes := composeNucleiWildcardArgs(tool, map[string]any{
		"-o":        "/somewhere/else.jsonl",
		"-severity": "info",
		"-silent":   true,
	}, nucleiBaseArgv())

	if got := argvValue(argv, "-o"); got != "/output.jsonl" {
		t.Fatalf("an owned flag was displaced by a stored setting: -o is %q", got)
	}
	if argvHas(argv, "-silent") || argvHas(argv, "-severity") {
		t.Fatalf("an owned flag reached the command line: %s", strings.Join(argv, " "))
	}
	if len(notes) == 0 {
		t.Error("silently discarding a stored setting is the defect this work exists to remove; it must be reported")
	}
}

// A repeatable flag has to be replaced as a SET, not merged. The runner emits one -H per entry in
// nuclei_configs.advanced_config.custom_headers, and customHeaders declares shadowed_by against that
// exact key, so leaving the old ones in place would send headers from two stores at once and neither
// screen could say what the scan carried.
func TestNucleiWildcardRepeatableFlagReplacesTheWholeSet(t *testing.T) {
	tool := wildcardTestTool(t, "nuclei")
	base := append(nucleiBaseArgv(), "-H", "X-Old-One: 1", "-H", "X-Old-Two: 2")

	argv, _ := composeNucleiWildcardArgs(tool, map[string]any{
		"customHeaders": []string{"Authorization: Bearer t", "X-New: 1"},
	}, base)

	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "X-Old-One") || strings.Contains(joined, "X-Old-Two") {
		t.Errorf("the advanced_config headers survived alongside the wildcard ones: %s", joined)
	}
	if strings.Count(joined, " -H ") != 2 {
		t.Errorf("expected exactly the two configured headers, got: %s", joined)
	}
	if !strings.Contains(joined, "Authorization: Bearer t") || !strings.Contains(joined, "X-New: 1") {
		t.Errorf("the configured headers did not reach the command line: %s", joined)
	}
}

// Headless without -sc downloads ~150MB of Chromium at scan time on this exact container, even
// though Chrome is already installed. An operator turning headless on should not have to know that.
func TestNucleiWildcardHeadlessPairsWithSystemChrome(t *testing.T) {
	tool := wildcardTestTool(t, "nuclei")

	argv, _ := composeNucleiWildcardArgs(tool, map[string]any{"headless": true}, nucleiBaseArgv())
	if !argvHas(argv, "-headless") {
		t.Fatalf("headless did not reach the command line: %s", strings.Join(argv, " "))
	}
	if !argvHas(argv, "-sc") {
		t.Errorf("-sc was not paired with -headless: %s", strings.Join(argv, " "))
	}

	// An explicit choice is obeyed rather than overridden.
	argv, _ = composeNucleiWildcardArgs(tool,
		map[string]any{"headless": true, "systemChrome": false}, nucleiBaseArgv())
	if argvHas(argv, "-sc") {
		t.Errorf("systemChrome false was overridden: %s", strings.Join(argv, " "))
	}

	// And the flags that are inert without headless are not emitted at all.
	argv, _ = composeNucleiWildcardArgs(tool,
		map[string]any{"headlessOptions": []string{"--no-sandbox"}}, nucleiBaseArgv())
	if argvHas(argv, "-ho") {
		t.Errorf("-ho was emitted without -headless, which is a verified fatal error: %s", strings.Join(argv, " "))
	}
}

// ---------------------------------------------------------------------------------------------
// the overlay itself
// ---------------------------------------------------------------------------------------------

// A value that happens to spell a flag must not be mistaken for one. Without the arity map the walk
// would see the "-c" inside a header value and treat the next token as a flag.
func TestWildcardOverlayDoesNotMistakeAValueForAFlag(t *testing.T) {
	tool := wildcardTestTool(t, "nuclei")
	base := []string{"-list", "/targets.txt", "-H", "-rl", "-rl", "150"}

	overlay := wildcardOverlay{
		tool:      tool,
		settings:  map[string]any{"rateLimit": 7},
		baseArity: nucleiWildcardBaseArity,
	}
	got, _ := overlay.apply(base)
	assertArgv(t, got, []string{"-list", "/targets.txt", "-H", "-rl", "-rl", "7"})
}

// Determinism, because a command line that reorders between runs cannot be diffed, and diffing two
// scans is how anyone works out why one of them found less.
func TestWildcardOverlayIsDeterministic(t *testing.T) {
	tool := wildcardTestTool(t, "gospider")
	settings := map[string]any{
		"concurrent": 12, "depth": 4, "delay": 2, "proxy": "http://10.0.0.5:8080",
		"cookie": "a=b", "headers": []string{"X-One: 1", "X-Two: 2"}, "subs": true,
	}
	first, _ := buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, settings)
	for i := 0; i < 25; i++ {
		next, _ := buildGoSpiderWildcardCommand("https://www.example.com", "", "", tool, settings)
		assertArgv(t, next, first)
	}
}
