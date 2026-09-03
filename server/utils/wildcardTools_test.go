package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests guard the registry itself rather than any one tool, because the failure they are
// looking for is structural: a vocabulary that contradicts itself produces a save endpoint that
// 400s a setting for no visible reason, and the only symptom an operator ever sees is that saving
// quietly does nothing.

// The trap this codebase has already fallen into once. A flag listed in BOTH Options and OwnedFlags
// makes RefusedWildcardFlags reject the setting that names it, so the option is present in the UI,
// present in the MCP reference, and impossible to save. Nothing else catches it.
func TestWildcardNoOptionNamesAnOwnedFlag(t *testing.T) {
	for _, tool := range WildcardTools() {
		for key, meta := range tool.Options {
			if meta.Flag == "" {
				continue
			}
			if why, owned := tool.OwnedFlags[meta.Flag]; owned {
				t.Errorf("%s: option %q offers %s, which is also an owned flag (%s). "+
					"Saving it would be refused and the option would be unusable.",
					tool.Key, key, meta.Flag, why)
			}
			if why, owned := tool.OwnedFlags[key]; owned {
				t.Errorf("%s: option key %q is also an owned flag (%s).", tool.Key, key, why)
			}
		}
	}
}

// Two options fighting over one flag means the second silently wins on the command line while both
// are shown as settable.
func TestWildcardFlagsAreUniqueWithinATool(t *testing.T) {
	for _, tool := range WildcardTools() {
		seen := map[string]string{}
		for key, meta := range tool.Options {
			if meta.Flag == "" {
				continue
			}
			if other, dup := seen[meta.Flag]; dup {
				t.Errorf("%s: options %q and %q both compose %s.", tool.Key, other, key, meta.Flag)
			}
			seen[meta.Flag] = key
		}
	}
}

// Keys are unique by construction while Options is a map, so this asserts the property the tests
// actually depend on: every key is present exactly once across the whole registry serialization,
// non-empty, and does not collide with another tool's key under a different meaning.
func TestWildcardOptionKeysAreUniquePerTool(t *testing.T) {
	for _, tool := range WildcardTools() {
		seen := map[string]bool{}
		for _, key := range wildcardOptionKeys(tool) {
			if strings.TrimSpace(key) == "" {
				t.Errorf("%s: an option has an empty key.", tool.Key)
			}
			if seen[key] {
				t.Errorf("%s: option key %q appears more than once.", tool.Key, key)
			}
			seen[key] = true
		}
		if len(seen) != len(tool.Options) {
			t.Errorf("%s: %d distinct keys for %d options.", tool.Key, len(seen), len(tool.Options))
		}
	}
}

// Tool keys have to be unique or WildcardToolByKey returns whichever was registered first and the
// other tool becomes unreachable from every endpoint.
func TestWildcardToolKeysAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range WildcardTools() {
		if seen[tool.Key] {
			t.Errorf("duplicate tool key %q", tool.Key)
		}
		seen[tool.Key] = true
	}
	if len(WildcardTools()) == 0 {
		t.Fatal("the wildcard registry is empty")
	}
}

// A vocabulary is only useful if the form can lay it out, and a group name that is not in Groups
// means a field that renders into no section at all.
func TestWildcardEveryOptionGroupIsDeclared(t *testing.T) {
	for _, tool := range WildcardTools() {
		declared := map[string]bool{}
		for _, g := range tool.Groups {
			declared[g] = true
		}
		for key, meta := range tool.Options {
			if !declared[meta.Group] {
				t.Errorf("%s: option %q is in group %q, which is not in Groups %v.",
					tool.Key, key, meta.Group, tool.Groups)
			}
		}
	}
}

// The whole point of the registry is that both surfaces render what it says, so an option with no
// label is a blank form field and an option with no kind cannot be rendered at all.
func TestWildcardOptionMetadataIsComplete(t *testing.T) {
	kinds := map[string]bool{"bool": true, "int": true, "string": true, "enum": true, "list": true, "path": true}
	provenance := map[string]bool{"measured": true, "runner": true, "unverified": true}
	for _, tool := range WildcardTools() {
		for key, meta := range tool.Options {
			if !kinds[meta.Kind] {
				t.Errorf("%s.%s: kind %q is not renderable.", tool.Key, key, meta.Kind)
			}
			if strings.TrimSpace(meta.Label) == "" {
				t.Errorf("%s.%s: no label.", tool.Key, key)
			}
			if !provenance[meta.Provenance] {
				t.Errorf("%s.%s: provenance %q must be measured, runner or unverified. "+
					"An unmarked option lets a surface present a guess as a measurement.",
					tool.Key, key, meta.Provenance)
			}
			if meta.Kind == "enum" && len(meta.Choices) == 0 {
				t.Errorf("%s.%s: an enum with no choices cannot be rendered or validated.", tool.Key, key)
			}
			if meta.RequiresKey != "" {
				if _, ok := tool.Options[meta.RequiresKey]; !ok {
					t.Errorf("%s.%s: RequiresKey names %q, which is not an option of this tool.",
						tool.Key, key, meta.RequiresKey)
				}
			}
			if meta.InertWhenKey != "" {
				if _, ok := tool.Options[meta.InertWhenKey]; !ok {
					t.Errorf("%s.%s: InertWhenKey names %q, which is not an option of this tool.",
						tool.Key, key, meta.InertWhenKey)
				}
			}
		}
	}
}

// An empty vocabulary is a legitimate answer (assetfinder has one flag and the runner sets it) and
// must be distinguishable from a tool nobody got round to. Limitation is what makes that difference
// visible to the operator, so an empty Options map without one is a registry bug.
func TestWildcardEmptyVocabularyIsExplained(t *testing.T) {
	for _, tool := range WildcardTools() {
		if len(tool.Options) > 0 {
			continue
		}
		if strings.TrimSpace(tool.Limitation) == "" {
			t.Errorf("%s: no options and no Limitation. An empty vocabulary has to say WHY, or it reads "+
				"as unfinished work.", tool.Key)
		}
	}
}

// wildcardProbedTools is every tool that was probed against its real installed container. All of
// them must carry a vocabulary, owned flags and a placeholder on every option: a placeholder is what
// makes an empty field read as a decision rather than as a gap, and it is the first thing lost when
// a vocabulary is padded out from a help page instead of measured.
var wildcardProbedTools = []string{
	"amass", "subfinder", "gau", "ctl", "shuffledns", "cewl", "gospider", "subdomainizer", "nuclei",
}

func TestWildcardMeasuredToolsHaveVocabulary(t *testing.T) {
	for _, key := range wildcardProbedTools {
		tool, ok := WildcardToolByKey(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		if len(tool.Options) == 0 {
			t.Fatalf("%s has an empty vocabulary", key)
		}
		if len(tool.OwnedFlags) == 0 {
			t.Fatalf("%s declares no owned flags", key)
		}
		for optKey, meta := range tool.Options {
			if strings.TrimSpace(meta.Placeholder) == "" {
				t.Errorf("%s.%s: no placeholder. An empty field has to read as a decision rather than a gap.",
					key, optKey)
			}
			if strings.TrimSpace(meta.Why) == "" {
				t.Errorf("%s.%s: no why_it_matters. An option nobody can justify is one nobody should be "+
					"offered.", key, optKey)
			}
		}
	}
}

// The registry serves as many options as were measured, and a silent regression that halves a
// vocabulary would otherwise pass every structural test above. These counts come from the per-tool
// research files, minus the entries deliberately withheld with a reason recorded in OwnedFlags.
func TestWildcardVocabularySizes(t *testing.T) {
	// atLeast rather than exact: adding a measured option must not break the build, dropping half a
	// tool's vocabulary must.
	atLeast := map[string]int{
		"gau": 12, "ctl": 13, "shuffledns": 11, "cewl": 22, "gospider": 23,
		"subdomainizer": 9, "nuclei": 43,
	}
	for key, want := range atLeast {
		tool := mustTool(t, key)
		if len(tool.Options) < want {
			t.Errorf("%s: %d options, expected at least the %d that were measured against the container.",
				key, len(tool.Options), want)
		}
	}
}

// Every option that composes a repeated flag has to be a list, or BuildWildcardArgs takes the
// default branch and emits one flag with a comma-joined value the tool never asked for.
func TestWildcardRepeatableOptionsAreLists(t *testing.T) {
	for _, tool := range WildcardTools() {
		for key, meta := range tool.Options {
			if meta.Repeatable && meta.Kind != "list" {
				t.Errorf("%s.%s: repeatable but kind %q. Only a list can be passed once per value.",
					tool.Key, key, meta.Kind)
			}
		}
	}
}

// The flags that were MEASURED to be dangerous must be unreachable, not merely defaulted off. These
// are the specific ones that turn a scan into a clean-looking zero.
func TestWildcardBlacklistedFlagsAreOwned(t *testing.T) {
	mustOwn := map[string][]string{
		// -silent exits 0 with zero bytes on both streams and is stored as success.
		// -exclude and -include parse fine and do nothing at all in this build.
		"amass": {"-silent", "-exclude", "-include", "-demo", "-nocolor", "-d"},
		// -oJ and -oI change the output shape the parser depends on; -d is the target.
		"subfinder": {"-d", "-silent", "-oJ", "-oI", "-up"},
		// --fp discards ALL output with exit 0 on every run. --subs IS the subdomain scraping, so a
		// toggle would switch off the purpose of the step. --verbose is the only signal a provider
		// failed at all.
		"gau": {"--fp", "--subs", "--verbose", "--json", "--config"},
		// -silent hides the stderr that is the only evidence of a bad wordlist path; -mode changes
		// what -d means to the tool and the two call sites already pass -d differently.
		"shuffledns": {"-silent", "-mode", "-d", "-massdns", "-o", "-up"},
		// --debug prints the ENTIRE page body to stdout, which the runner parses as the wordlist.
		// -n suppresses the wordlist outright. -c is the format the parser splits on.
		"cewl": {"--debug", "-n", "-c", "-w", "-g", "--exclude"},
		// --json is the shape the parser depends on, and -s is the seed URL.
		"gospider": {"--json", "-s", "-o", "--burp", "-q"},
		// The three output paths must stay runner-owned because the runner reads them back out of
		// the container before it deletes the mount directory.
		"subdomainizer": {"-u", "-o", "-sop", "-cop", "-gop", "-l"},
		// TEMPLATE AND TARGET SELECTION. These already have first-class columns on nuclei_configs and
		// a Configure modal, and two screens setting templates is how a config contradicts itself.
		// -ept cut a 1478-template scan to 45 and -dast cut it to 5, both with exit 0.
		"nuclei": {
			"-tags", "-severity", "-id", "-eid", "-etags", "-ept", "-dast", "-pt", "-tc", "-a",
			"-list", "-t", "-o", "-jsonl", "-passive", "-up", "-auth",
		},
	}
	for toolKey, flags := range mustOwn {
		tool, ok := WildcardToolByKey(toolKey)
		if !ok {
			t.Fatalf("%s is not registered", toolKey)
		}
		for _, flag := range flags {
			why, owned := tool.OwnedFlags[flag]
			if !owned {
				t.Errorf("%s: %s must be framework-owned and is not.", toolKey, flag)
				continue
			}
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s: %s is owned with no reason. A refusal without a reason is unactionable.",
					toolKey, flag)
			}
		}
	}
}

func TestWildcardOwnedFlagsAllCarryAReason(t *testing.T) {
	for _, tool := range WildcardTools() {
		for flag, why := range tool.OwnedFlags {
			if strings.TrimSpace(flag) == "" {
				t.Errorf("%s: an owned flag has an empty name.", tool.Key)
			}
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s: owned flag %s carries no reason.", tool.Key, flag)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Save-path refusals. These are pure over the registry, so they run without a database.
// ---------------------------------------------------------------------------------------------

func TestWildcardSaveRefusesAnOwnedFlag(t *testing.T) {
	tool, _ := WildcardToolByKey("amass")

	// The MCP shape: a caller sends the flag itself.
	refused := RefusedWildcardFlags(tool, map[string]any{"-silent": true})
	if len(refused) != 1 {
		t.Fatalf("expected -silent to be refused, got %v", refused)
	}
	if !strings.Contains(refused[0], "-silent") {
		t.Errorf("the refusal must name the flag, got %q", refused[0])
	}
	if !strings.Contains(refused[0], "set by the framework") {
		t.Errorf("the refusal must say why, got %q", refused[0])
	}

	// Nothing legitimate is caught by the same check.
	if refused := RefusedWildcardFlags(tool, map[string]any{"timeoutMinutes": 30}); len(refused) != 0 {
		t.Errorf("a valid option was refused as framework-owned: %v", refused)
	}
}

func TestWildcardSaveRefusesAnUnknownKey(t *testing.T) {
	tool, _ := WildcardToolByKey("subfinder")

	// The realistic mistake: a near-miss on a real key.
	unknown := UnknownWildcardOptions(tool, map[string]any{"maxTimeMinutes": 20, "maxTime": 20})
	if len(unknown) != 1 || unknown[0] != "maxTimeMinutes" {
		t.Fatalf("expected only maxTimeMinutes to be unknown, got %v", unknown)
	}
	if len(UnknownWildcardOptions(tool, map[string]any{"maxTime": 20})) != 0 {
		t.Error("a valid key was reported unknown")
	}
}

func TestWildcardValueValidation(t *testing.T) {
	amass, _ := WildcardToolByKey("amass")
	subfinder, _ := WildcardToolByKey("subfinder")

	cases := []struct {
		name     string
		tool     WildcardTool
		settings map[string]any
		wantBad  bool
		mustSay  string
	}{
		// 0 is amass's "no wall-clock cap at all", and the runner uses plain exec.Command with no
		// context deadline, so nothing else would ever stop the scan.
		{"amass timeout 0 is refused", amass, map[string]any{"timeoutMinutes": float64(0)}, true, "at least 1"},
		{"amass timeout 60 is fine", amass, map[string]any{"timeoutMinutes": float64(60)}, false, ""},
		{"amass timeout must be a number", amass, map[string]any{"timeoutMinutes": "an hour"}, true, "number"},
		{"amass activeMode must be a bool", amass, map[string]any{"activeMode": "yes"}, true, "switch"},
		{"amass activeMode true is fine", amass, map[string]any{"activeMode": true}, false, ""},
		// Measured: subfinder drops an unrecognised source name silently when it is not the only one.
		{"subfinder source typo is refused", subfinder,
			map[string]any{"sources": "crtsh,notarealsource"}, true, "notarealsource"},
		{"subfinder real sources are fine", subfinder, map[string]any{"sources": "crtsh,anubis"}, false, ""},
		{"subfinder sources as an array is fine", subfinder,
			map[string]any{"sources": []any{"crtsh", "anubis"}}, false, ""},
		// Measured: -timeout 1 returned 3802 subdomains against a 23362 baseline, exit 0, silently.
		{"subfinder timeout below the floor is refused", subfinder,
			map[string]any{"timeout": float64(1)}, true, "at least 10"},
		// Measured: an all-invalid --providers list exits 0 with zero URLs and nothing on stderr.
		{"gau provider typo is refused", mustTool(t, "gau"),
			map[string]any{"providers": "wayback,bogus"}, true, "bogus"},
		{"gau real providers are fine", mustTool(t, "gau"),
			map[string]any{"providers": []any{"wayback", "otx", "urlscan"}}, false, ""},
		// Measured: cewl -m 40 emits zero words and exits 0, and the Go post-filter keeps only 3..20.
		{"cewl min word length above the post-filter ceiling is refused", mustTool(t, "cewl"),
			map[string]any{"minWordLength": float64(40)}, true, "at most 20"},
		{"cewl min word length of 3 is fine", mustTool(t, "cewl"),
			map[string]any{"minWordLength": float64(3)}, false, ""},
		// SubDomainizer's help lists exactly two SAN values; 'off' means not passing the flag at all,
		// so offering it as a value would compose an argument the tool rejects.
		{"subdomainizer san mode off is not a value", mustTool(t, "subdomainizer"),
			map[string]any{"sanMode": "off"}, true, "must be one of"},
		{"subdomainizer san mode same is fine", mustTool(t, "subdomainizer"),
			map[string]any{"sanMode": "same"}, false, ""},
		// Measured: -rl 0 is accepted and loads every template, and whether it means unlimited or
		// stalled was never determined, so it must not be reachable.
		{"nuclei rate limit 0 is refused", mustTool(t, "nuclei"),
			map[string]any{"rateLimit": float64(0)}, true, "at least 1"},
		{"nuclei rate limit 20 is fine", mustTool(t, "nuclei"),
			map[string]any{"rateLimit": float64(20)}, false, ""},
		// Measured: a low -rsr sends every request and never reaches a marker late in the body.
		{"nuclei response read size below 64KB is refused", mustTool(t, "nuclei"),
			map[string]any{"responseSizeRead": float64(1024)}, true, "at least 65536"},
		{"nuclei scan strategy must be one nuclei accepts", mustTool(t, "nuclei"),
			map[string]any{"scanStrategy": "bogus"}, true, "must be one of"},
		{"gospider depth 0 is allowed but bounded", mustTool(t, "gospider"),
			map[string]any{"depth": float64(0)}, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := ValidateWildcardSettings(tc.tool, tc.settings)
			if tc.wantBad && len(problems) == 0 {
				t.Fatalf("expected a refusal, got none")
			}
			if !tc.wantBad && len(problems) != 0 {
				t.Fatalf("expected no refusal, got %v", problems)
			}
			if tc.mustSay != "" && !strings.Contains(strings.Join(problems, " "), tc.mustSay) {
				t.Errorf("the refusal must say %q, got %v", tc.mustSay, problems)
			}
		})
	}
}

// A tool with no vocabulary refuses everything, and the reason is the measured one rather than a
// generic unknown-key error.
//
// ctl used to be in this list and no longer is. It was measured to have a large and consequential
// set of hardcoded values, so it now carries a vocabulary WITH a Limitation saying none of it is a
// flag. assetfinder and sublist3r stay: assetfinder's complete help is four lines and one flag the
// runner already sets, and sublist3r's container is never executed at all.
func TestWildcardToolsWithNoVocabularyExplainThemselves(t *testing.T) {
	for _, key := range []string{"assetfinder", "sublist3r", "httpx"} {
		tool := mustTool(t, key)
		if len(tool.Options) != 0 {
			t.Errorf("%s was expected to have an empty vocabulary", key)
		}
		if strings.TrimSpace(tool.Limitation) == "" {
			t.Errorf("%s has no Limitation explaining the empty vocabulary", key)
		}
	}
	// httpx specifically must point at the store that already owns it, or the Settings screen will
	// look like the place to configure it and silently be the wrong place.
	if got := mustTool(t, "httpx").DelegatesTo; got != "httpx_configs" {
		t.Errorf("httpx must delegate to httpx_configs, got %q", got)
	}
}

// ctl is the one tool whose options are not flags, because it has no command line: it is native Go
// and every value is a hardcoded literal. Two things follow and both are asserted here, because
// getting either wrong would produce a screen that promises a command line it cannot build.
func TestWildcardCTLOptionsAreNotFlags(t *testing.T) {
	ctl := mustTool(t, "ctl")

	if strings.TrimSpace(ctl.Limitation) == "" {
		t.Fatal("ctl must keep a Limitation: its options are proposals that need runner code, not flags.")
	}
	for key, meta := range ctl.Options {
		if meta.Flag != "" {
			t.Errorf("ctl.%s declares flag %q, but ctl has no command line. A flag here would compose "+
				"an argument for a process that is never spawned.", key, meta.Flag)
		}
	}

	// So a full settings payload composes nothing, and every option is reported rather than silently
	// dropped: an operator has to be able to see that saving this changed no command line.
	args, _ := BuildWildcardArgs(ctl, map[string]any{
		"retries": float64(3), "failOnZeroResults": true, "crtShTimeoutSeconds": float64(60),
	})
	if len(args) != 0 {
		t.Errorf("ctl settings must compose no arguments, got %v", args)
	}
}

// The nuclei vocabulary is engine flags. Template and target selection already live in
// nuclei_configs and the Configure modal, and a second screen setting them is how two screens come
// to disagree about what a scan tested.
func TestWildcardNucleiHasNoTemplateOrTargetSelection(t *testing.T) {
	nuclei := mustTool(t, "nuclei")

	forbidden := map[string]string{
		"-tags":     "template selection, from the Configure modal's templates column",
		"-severity": "template selection, from the nuclei_configs.severities column",
		"-s":        "short form of -severity",
		"-id":       "template selection, from nuclei_configs.template_ids",
		"-eid":      "exclusions, from nuclei_configs.exclude_ids",
		"-etags":    "exclusions, from nuclei_configs.exclude_tags",
		"-es":       "exclude-severity, the same axis as the severities column",
		"-t":        "template paths",
		"-ept":      "measured: -ept http cut a 1478-template scan to 45 templates with exit 0",
		"-dast":     "measured: it replaced a 1478-template set with 5",
		"-list":     "target selection",
		"-u":        "target selection",
		"-eh":       "target selection",
	}
	for key, meta := range nuclei.Options {
		if why, bad := forbidden[meta.Flag]; bad {
			t.Errorf("nuclei.%s composes %s, which is %s. It must not be settable from a settings "+
				"screen.", key, meta.Flag, why)
		}
	}
	// And the same flags must be refused on save rather than merely absent from the form, because the
	// MCP surface can send a flag directly.
	for flag := range forbidden {
		if _, owned := nuclei.OwnedFlags[flag]; !owned {
			t.Errorf("nuclei: %s must be declared framework-owned so a save that names it is refused.", flag)
		}
	}

	// The keys that already exist in nuclei_configs.advanced_config must SAY so, because the runner
	// reads snake_case literals and falls back to a hardcoded default on a key miss with no log line:
	// a settings screen that writes a different spelling produces a scan that runs at the defaults and
	// reports success while ignoring everything the operator typed.
	for _, key := range []string{
		"rateLimit", "bulkSize", "concurrency", "timeout", "retries", "maxHostError",
		"followRedirects", "followHostRedirects", "maxRedirects", "customHeaders", "proxy",
		"noInteractsh", "interactshServer", "interactshToken", "headless", "headlessBulkSize",
		"headlessConcurrency", "scanStrategy", "stopAtFirstMatch", "systemResolvers", "leaveDefaultPorts",
	} {
		meta, ok := nuclei.Options[key]
		if !ok {
			t.Errorf("nuclei.%s is missing: it is one of the keys the existing advanced_config accordion "+
				"already persists and the runner already reads.", key)
			continue
		}
		if !strings.HasPrefix(meta.ShadowedBy, "nuclei_configs.advanced_config.") {
			t.Errorf("nuclei.%s must declare the advanced_config key it competes with, got %q.",
				key, meta.ShadowedBy)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Inertness and composition.
// ---------------------------------------------------------------------------------------------

// subfinder's -t is documented "(-active only)". Storing it with activeOnly off is a field that
// does nothing, which is the exact defect this screen exists to prevent.
func TestWildcardInertOptionsAreReported(t *testing.T) {
	subfinder := mustTool(t, "subfinder")

	inert := WildcardInertOptions(subfinder, map[string]any{"resolverConcurrency": float64(50)})
	if _, ok := inert["resolverConcurrency"]; !ok {
		t.Fatalf("resolverConcurrency should be inert without activeOnly, got %v", inert)
	}
	inert = WildcardInertOptions(subfinder, map[string]any{
		"resolverConcurrency": float64(50), "activeOnly": true,
	})
	if len(inert) != 0 {
		t.Errorf("resolverConcurrency should be live with activeOnly on, got %v", inert)
	}

	// amass -norecursive makes -min-for-recursive dead.
	amass := mustTool(t, "amass")
	inert = WildcardInertOptions(amass, map[string]any{
		"minForRecursive": float64(3), "noRecursive": true,
	})
	if _, ok := inert["minForRecursive"]; !ok {
		t.Errorf("minForRecursive should be inert while noRecursive is on, got %v", inert)
	}
}

func TestWildcardBuildArgs(t *testing.T) {
	amass := mustTool(t, "amass")

	args, warnings := BuildWildcardArgs(amass, map[string]any{
		"activeMode":         true,
		"bruteForce":         false,
		"timeoutMinutes":     float64(30),
		"blacklistNames":     "www.example.com,cdn.example.com",
		"untrustedResolvers": []any{"8.8.8.8", "1.1.1.1"},
	})
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-active") {
		t.Errorf("a true switch must appear: %v", args)
	}
	if strings.Contains(joined, "-brute") {
		t.Errorf("a false switch must not appear: %v", args)
	}
	if !strings.Contains(joined, "-timeout 30") {
		t.Errorf("expected -timeout 30, got %v", args)
	}
	// -bl is repeatable, so two entries mean two flags rather than one comma-joined value.
	if strings.Count(joined, "-bl ") != 2 {
		t.Errorf("a repeatable list must be passed once per value, got %v", args)
	}
	if strings.Count(joined, "-r ") != 2 {
		t.Errorf("resolvers must be passed once per value, got %v", args)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}

	// An inert option must not reach the command line, and the caller must be told why.
	args, warnings = BuildWildcardArgs(amass, map[string]any{
		"noRecursive": true, "minForRecursive": float64(4),
	})
	if strings.Contains(strings.Join(args, " "), "-min-for-recursive") {
		t.Errorf("an inert option reached the command line: %v", args)
	}
	if len(warnings) == 0 {
		t.Errorf("an inert option must produce a warning")
	}

	// Non-repeatable lists comma-join, which is what subfinder -s expects.
	sub := mustTool(t, "subfinder")
	args, _ = BuildWildcardArgs(sub, map[string]any{"sources": []any{"crtsh", "anubis"}})
	if strings.Join(args, " ") != "-s crtsh,anubis" {
		t.Errorf("expected a comma-joined -s, got %v", args)
	}
}

// The composed arguments must be stable between calls, or the "what will this run" preview changes
// under the operator for no reason and cannot be diffed against a previous run.
func TestWildcardBuildArgsIsDeterministic(t *testing.T) {
	tool := mustTool(t, "gospider")
	settings := map[string]any{
		"depth": float64(4), "concurrent": float64(5), "threads": float64(2),
		"timeout": float64(20), "js": true, "robots": true, "otherSource": true, "includeSubs": true,
	}
	first, warnings := BuildWildcardArgs(tool, settings)
	// Every key above is a real option, so nothing may be dropped. Without this the test would still
	// pass on a vocabulary that had renamed all of them, since unknown keys only produce a warning.
	if len(warnings) != 0 {
		t.Fatalf("a settings map of real keys produced warnings: %v", warnings)
	}
	if len(first) == 0 {
		t.Fatal("nothing composed from eight real options")
	}
	for i := 0; i < 20; i++ {
		again, _ := BuildWildcardArgs(tool, settings)
		if strings.Join(first, " ") != strings.Join(again, " ") {
			t.Fatalf("composition is not deterministic:\n%v\n%v", first, again)
		}
	}
}

// gospider -B silently forces linkfinder, robots, other-source, include-subs and
// include-other-source all to false, whatever the operator set, and the five switches still read as
// ON in the saved config. Read from main.go:142-149 in the installed image. The vocabulary has to
// report that, or the form shows five switches that do nothing.
func TestWildcardGospiderBaseFlagGreysOutTheSourcesGroup(t *testing.T) {
	tool := mustTool(t, "gospider")

	overridden := []string{"js", "robots", "otherSource", "includeSubs", "includeOtherSource"}
	settings := map[string]any{"base": true}
	for _, key := range overridden {
		settings[key] = true
	}

	inert := WildcardInertOptions(tool, settings)
	for _, key := range overridden {
		if _, reported := inert[key]; !reported {
			t.Errorf("%s must be reported inert while base is on: -B forces it false inside gospider "+
				"while the saved config still says it is on.", key)
		}
	}

	args, warnings := BuildWildcardArgs(tool, settings)
	joined := strings.Join(args, " ")
	for _, flag := range []string{"--js", "--robots", "-a", "-w", "-r"} {
		if strings.Contains(joined, flag) {
			t.Errorf("%s reached the command line although -B overrides it: %v", flag, args)
		}
	}
	if len(warnings) < len(overridden) {
		t.Errorf("every overridden switch must produce a warning, got %v", warnings)
	}
}

// nuclei -sc, -ho and the headless sizing flags are FATAL or meaningless without -headless: `-sc`
// alone exits with `[FTL] Program exiting: headless mode (-headless) is required if -ho, -sb, -sc or
// -lha are set`. They must never reach a command line that has no -headless on it.
func TestWildcardNucleiHeadlessOnlyFlagsAreGated(t *testing.T) {
	tool := mustTool(t, "nuclei")

	gated := []string{"systemChrome", "headlessBulkSize", "headlessConcurrency", "pageTimeout", "headlessOptions"}
	settings := map[string]any{
		"systemChrome": true, "headlessBulkSize": float64(5), "headlessConcurrency": float64(5),
		"pageTimeout": float64(30), "headlessOptions": []any{"--no-sandbox"},
	}
	inert := WildcardInertOptions(tool, settings)
	for _, key := range gated {
		if _, reported := inert[key]; !reported {
			t.Errorf("%s must be reported inert without headless: nuclei exits FTL rather than scanning.", key)
		}
	}
	if args, _ := BuildWildcardArgs(tool, settings); len(args) != 0 {
		t.Errorf("headless-only flags composed without -headless: %v", args)
	}

	settings["headless"] = true
	if inert := WildcardInertOptions(tool, settings); len(inert) != 0 {
		t.Errorf("with headless on nothing should be inert, got %v", inert)
	}

	// -ni disables OAST entirely, so a server and token stored alongside it do nothing at all. That
	// combination is how an operator comes to believe callbacks are going somewhere they are not.
	inert = WildcardInertOptions(tool, map[string]any{
		"noInteractsh": true, "interactshServer": "https://oast.example.com", "interactshToken": "x",
	})
	for _, key := range []string{"interactshServer", "interactshToken"} {
		if _, reported := inert[key]; !reported {
			t.Errorf("%s must be inert while noInteractsh is on, got %v", key, inert)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// The round trip, exercised through the same merge semantics the handler uses.
// ---------------------------------------------------------------------------------------------

// mergeWildcardSettings mirrors the merge the handler performs, so the semantics can be tested
// without a database. A nil value deletes; everything else overwrites.
func mergeWildcardSettings(stored, incoming map[string]any, replace bool) map[string]any {
	merged := map[string]any{}
	if !replace {
		for k, v := range stored {
			merged[k] = v
		}
	}
	for k, v := range incoming {
		if v == nil {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}
	return merged
}

func TestWildcardValidSaveRoundTrips(t *testing.T) {
	tool := mustTool(t, "subfinder")

	incoming := map[string]any{
		"maxTime":    float64(20),
		"timeout":    float64(30),
		"activeOnly": true,
		"sources":    []any{"crtsh", "anubis", "hackertarget"},
	}

	if refused := RefusedWildcardFlags(tool, incoming); len(refused) != 0 {
		t.Fatalf("a valid save was refused as framework-owned: %v", refused)
	}
	if unknown := UnknownWildcardOptions(tool, incoming); len(unknown) != 0 {
		t.Fatalf("a valid save contained unknown keys: %v", unknown)
	}
	if problems := ValidateWildcardSettings(tool, incoming); len(problems) != 0 {
		t.Fatalf("a valid save failed validation: %v", problems)
	}

	stored := mergeWildcardSettings(map[string]any{}, incoming, false)
	if len(stored) != 4 {
		t.Fatalf("expected 4 stored settings, got %d: %v", len(stored), stored)
	}

	// The values survive a trip through jsonb, which is what actually happens between the two reads.
	stored = roundTripJSON(t, stored)
	if stored["maxTime"] != float64(20) {
		t.Errorf("maxTime did not round trip: %#v", stored["maxTime"])
	}
	if stored["activeOnly"] != true {
		t.Errorf("activeOnly did not round trip: %#v", stored["activeOnly"])
	}
	if problems := ValidateWildcardSettings(tool, stored); len(problems) != 0 {
		t.Errorf("what was stored no longer validates: %v", problems)
	}

	// A merge sends one key and must not blank the rest.
	stored = mergeWildcardSettings(stored, map[string]any{"maxTime": float64(45)}, false)
	if len(stored) != 4 || stored["maxTime"] != float64(45) {
		t.Errorf("a partial save clobbered the rest: %v", stored)
	}

	// A null removes exactly one key.
	stored = mergeWildcardSettings(stored, map[string]any{"activeOnly": nil}, false)
	if _, present := stored["activeOnly"]; present {
		t.Errorf("a null value did not remove the key: %v", stored)
	}
	if len(stored) != 3 {
		t.Errorf("a null value removed more than one key: %v", stored)
	}

	// Replace makes the payload the whole state, which is what a form that showed every field means.
	stored = mergeWildcardSettings(stored, map[string]any{"maxTime": float64(10)}, true)
	if len(stored) != 1 {
		t.Errorf("replace did not become the whole state: %v", stored)
	}
}

func TestWildcardLoopbackDetection(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "::1", "127.0.0.53", "0.0.0.0"} {
		if !isLoopbackHost(host) {
			t.Errorf("%s should be treated as loopback: inside a container it answers nothing, and the "+
				"measured result is 0 subdomains with exit 0 and an empty stderr.", host)
		}
	}
	for _, host := range []string{"8.8.8.8", "1.1.1.1", "host.docker.internal", "192.168.1.10"} {
		if isLoopbackHost(host) {
			t.Errorf("%s should not be treated as loopback", host)
		}
	}
	if got := proxyHostOf("http://127.0.0.1:8080"); got != "127.0.0.1" {
		t.Errorf("proxyHostOf with a scheme: got %q", got)
	}
	if got := proxyHostOf("127.0.0.1:8080"); got != "127.0.0.1" {
		t.Errorf("proxyHostOf without a scheme: got %q", got)
	}
	if got := proxyHostOf("socks5://10.0.0.5:1080"); got != "10.0.0.5" {
		t.Errorf("proxyHostOf with socks5: got %q", got)
	}
}

func TestWildcardListSettingAcceptsBothShapes(t *testing.T) {
	// A text field produces a comma separated string; an MCP caller produces an array. Both must mean
	// the same thing, or the same configuration behaves differently depending on which surface wrote
	// it, which is precisely the drift this store exists to prevent.
	fromString, ok := listSetting("a, b ,c")
	if !ok || strings.Join(fromString, "|") != "a|b|c" {
		t.Fatalf("comma separated string: %v %v", fromString, ok)
	}
	fromArray, ok := listSetting([]any{"a", " b ", "c"})
	if !ok || strings.Join(fromArray, "|") != "a|b|c" {
		t.Fatalf("array: %v %v", fromArray, ok)
	}
	if _, ok := listSetting([]any{"a", 3}); ok {
		t.Error("an array with a non-string must be rejected rather than silently coerced")
	}
}

// roundTripJSON puts a settings map through the same marshal/unmarshal the jsonb column imposes.
// It matters: an int written by a Go caller comes back as a float64, and validation that only ever
// saw hand-written literals would pass here and fail against the database.
func roundTripJSON(t *testing.T, in map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func mustTool(t *testing.T, key string) WildcardTool {
	t.Helper()
	tool, ok := WildcardToolByKey(key)
	if !ok {
		t.Fatalf("%s is not registered", key)
	}
	return tool
}

// wildcardWiringFiles are the files that make a runner read the settings store.
var wildcardWiringFiles = []string{
	"wildcardWire.go",
	"wildcardRunnerOverlay.go",
	"wildcardWiringGauCtlShufflednsCewl.go",
}

// A tool whose runner reads the settings store must SAY it does, and one whose runner does not must
// not claim it. The API attaches a "the next scan will use the hardcoded command line" note based
// entirely on this flag, so a wrong value is a sentence that lies to the operator in one direction
// or the other.
//
// MEASURED: this started as a single hardcoded list of four tools inside ONE of three wiring files.
// The other two layers were written without touching it, so amass, subfinder, gospider,
// subdomainizer, nuclei and nuclei-screenshot were all wired and all reported not wired, and the UI
// told operators their saved configuration would be ignored while it was being honoured.
//
// This reads the wiring sources rather than trusting a list, because a list is exactly what failed.
func TestWildcardWiredToolsClaimIt(t *testing.T) {
	claimed := map[string]bool{}
	for _, tool := range wildcardRegistry {
		if tool.RunnerReads {
			claimed[tool.Key] = true
		}
	}

	// Every tool key a wiring file names in a markWildcardRunnerWired call must end up claimed.
	declared := map[string]string{}
	for _, name := range wildcardWiringFiles {
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("cannot read wiring file %s: %v", name, err)
		}
		for _, call := range regexp.MustCompile(`markWildcardRunnerWired\(([^)]*)\)`).
			FindAllStringSubmatch(string(src), -1) {
			for _, quoted := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(call[1], -1) {
				declared[quoted[1]] = name
			}
		}
	}

	if len(declared) == 0 {
		t.Fatal("no wiring file declares any wired tool; either the helper was renamed or every " +
			"runner quietly stopped reading its settings")
	}

	for key, file := range declared {
		if _, ok := WildcardToolByKey(key); !ok {
			t.Errorf("%s claims to wire %q, which is not a registered tool. A rename here silently "+
				"un-wires a runner", file, key)
			continue
		}
		if !claimed[key] {
			t.Errorf("%s wires %q but the registry reports runner_reads_settings=false, so the API "+
				"tells the operator their configuration will be ignored when it will not", file, key)
		}
	}

	// And nothing may claim to be wired without a wiring file saying so.
	for key := range claimed {
		if declared[key] == "" {
			t.Errorf("%q reports runner_reads_settings=true but no wiring file declares it. The API "+
				"is promising the setting takes effect with nothing behind that promise", key)
		}
	}

	// The measured wired set at the time of writing. Not a duplicate of the source scan above: this
	// is the count that catches a wiring file being deleted wholesale, which the scan cannot see.
	if len(claimed) < 10 {
		t.Errorf("only %d tool(s) report their runner reads settings; 10 were wired "+
			"(amass, subfinder, gau, ctl, shuffledns, cewl, gospider, subdomainizer, nuclei, "+
			"nuclei-screenshot). Claimed: %v", len(claimed), claimed)
	}
}

// A tool that IS wired must not still carry a Limitation telling the operator it needs runner code.
//
// ctl is why. All thirteen of its options are read by ctlRunConfigFrom, and its Limitation still
// said each one "requires a RUNNER CHANGE, which is why they are marked unverified". The client
// renders Limitation as a persistent alert, so a working feature was advertised as not existing.
func TestWildcardWiredToolsDoNotClaimTheyNeedWiring(t *testing.T) {
	for _, tool := range wildcardRegistry {
		if !tool.RunnerReads {
			continue
		}
		lower := strings.ToLower(tool.Limitation)
		for _, phrase := range []string{"runner change", "does not read", "not read yet", "requires a runner"} {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s is wired but its Limitation says %q, which the UI shows as a permanent "+
					"alert: %q", tool.Key, phrase, tool.Limitation)
			}
		}
	}
}

// Invocation is the "go read the truth in one hop" promise, and it is also embedded in the sentence
// the operator sees when a tool is not wired. A LINE NUMBER in it is a promise that rots.
//
// MEASURED: amass said amassUtils.go:605 while the wiring call sat at :609, and subfinder said
// subdomainScrapingUtils.go:1462 while it sat at :1598. Both were wrong within one working session,
// pointing an operator at the wrong part of a file to answer "does my setting do anything".
// The file and the function name are enough to grep for and cannot drift.
func TestWildcardInvocationsCarryNoLineNumber(t *testing.T) {
	lineRef := regexp.MustCompile(`\.go:\d+`)
	for _, tool := range wildcardRegistry {
		if lineRef.MatchString(tool.Invocation) {
			t.Errorf("%s Invocation carries a line number and will be wrong within a week: %q",
				tool.Key, tool.Invocation)
		}
		if strings.TrimSpace(tool.Invocation) == "" {
			t.Errorf("%s has no Invocation, so nothing tells a reader which runner to check", tool.Key)
		}
	}
}
