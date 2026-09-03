package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// These tests guard the Company registry itself rather than any one tool, because the failure they
// are looking for is structural: a vocabulary that contradicts itself produces a save endpoint that
// 400s a setting for no visible reason, and the only symptom an operator ever sees is that saving
// quietly does nothing.
//
// They mirror wildcardTools_test.go deliberately. Where the two registries share an implementation,
// the same property is asserted on both, so a change to the shared code that breaks one workflow
// cannot pass by only being tested against the other.

func mustCompanyTool(t *testing.T, key string) CompanyTool {
	t.Helper()
	tool, ok := CompanyToolByKey(key)
	if !ok {
		t.Fatalf("%s is not registered in the company registry", key)
	}
	return tool
}

// ---------------------------------------------------------------------------------------------
// Structural invariants.
// ---------------------------------------------------------------------------------------------

// THE TRAP THIS CODEBASE HAS ALREADY FALLEN INTO ONCE. A flag listed in BOTH Options and OwnedFlags
// makes the refusal check reject the setting that names it, so the option is present in the UI,
// present in the MCP reference, and impossible to save. Nothing else catches it.
//
// It is a live risk here rather than a theoretical one: cloud_enum's two wordlist presets exist
// precisely because -m and -b are owned by cloud_enum_configs, and declaring either flag on the
// preset would have reproduced the bug on the first save.
func TestCompanyNoOptionNamesAnOwnedFlag(t *testing.T) {
	for _, tool := range CompanyTools() {
		for key, meta := range tool.Options {
			if meta.Flag != "" {
				if why, owned := tool.OwnedFlags[meta.Flag]; owned {
					t.Errorf("%s: option %q offers %s, which is also an owned flag (%s). Saving it would be "+
						"refused and the option would be unusable.", tool.Key, key, meta.Flag, why)
				}
			}
			if why, owned := tool.OwnedFlags[key]; owned {
				t.Errorf("%s: option key %q is also an owned flag (%s).", tool.Key, key, why)
			}
		}
	}
}

// Two options fighting over one flag means the second silently wins on the command line while both
// are shown as settable.
func TestCompanyFlagsAreUniqueWithinATool(t *testing.T) {
	for _, tool := range CompanyTools() {
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

func TestCompanyOptionKeysAreUniquePerTool(t *testing.T) {
	for _, tool := range CompanyTools() {
		seen := map[string]bool{}
		for _, key := range companyOptionKeys(tool) {
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

// Tool keys have to be unique or CompanyToolByKey returns whichever was registered first and the
// other tool becomes unreachable from every endpoint.
func TestCompanyToolKeysAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range CompanyTools() {
		if seen[tool.Key] {
			t.Errorf("duplicate tool key %q", tool.Key)
		}
		seen[tool.Key] = true
	}
	if len(CompanyTools()) == 0 {
		t.Fatal("the company registry is empty")
	}
}

// Steps must be unique and ordered, because the registration order IS the order the cards appear and
// a duplicate step number makes two cards claim the same position.
func TestCompanyStepsAreUniqueAndInOrder(t *testing.T) {
	last := 0
	seen := map[int]string{}
	for _, tool := range CompanyTools() {
		if other, dup := seen[tool.Step]; dup {
			t.Errorf("%s and %s both claim step %d.", other, tool.Key, tool.Step)
		}
		seen[tool.Step] = tool.Key
		if tool.Step < last {
			t.Errorf("%s is registered at step %d after step %d; registration order is the display order.",
				tool.Key, tool.Step, last)
		}
		last = tool.Step
	}
}

// A vocabulary is only useful if the form can lay it out, and a group name that is not in Groups
// means a field that renders into no section at all.
func TestCompanyEveryOptionGroupIsDeclared(t *testing.T) {
	for _, tool := range CompanyTools() {
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

// And the reverse: a declared group with no options renders as an empty section, which reads to an
// operator as a feature that failed to load rather than one that does not exist.
func TestCompanyEveryDeclaredGroupHasAnOption(t *testing.T) {
	for _, tool := range CompanyTools() {
		used := map[string]bool{}
		for _, meta := range tool.Options {
			used[meta.Group] = true
		}
		for _, g := range tool.Groups {
			if !used[g] {
				t.Errorf("%s declares group %q and puts no option in it, which renders as an empty section.",
					tool.Key, g)
			}
		}
	}
}

// The whole point of the registry is that both surfaces render what it says. An option with no label
// is a blank form field, one with no kind cannot be rendered at all, and one with no placeholder
// makes an empty field read as a gap rather than as a decision.
//
// EVERY company tool was probed, so unlike the Wildcard registry there is no "measured tools only"
// exemption here: placeholder and why are required on all of them.
func TestCompanyOptionMetadataIsComplete(t *testing.T) {
	kinds := map[string]bool{
		"bool": true, "int": true, "float": true, "string": true, "enum": true, "list": true, "path": true,
	}
	provenance := map[string]bool{"measured": true, "runner": true, "unverified": true}
	for _, tool := range CompanyTools() {
		// nuclei's vocabulary is the WILDCARD one, shared by reference. It is governed by
		// wildcardTools_test.go and must not be re-asserted against a stricter company rule here: doing so
		// would force an edit to a deployed vocabulary in order to satisfy a test in a different workflow,
		// which is the drift this sharing exists to prevent, running backwards.
		sharedVocabulary := companySharedSettingsStore[tool.Key] != ""

		for key, meta := range tool.Options {
			if !kinds[meta.Kind] {
				t.Errorf("%s.%s: kind %q is not renderable.", tool.Key, key, meta.Kind)
			}
			if strings.TrimSpace(meta.Label) == "" {
				t.Errorf("%s.%s: no label.", tool.Key, key)
			}
			if !provenance[meta.Provenance] {
				t.Errorf("%s.%s: provenance %q must be measured, runner or unverified. An unmarked option "+
					"lets a surface present a guess as a measurement.", tool.Key, key, meta.Provenance)
			}
			if strings.TrimSpace(meta.Placeholder) == "" {
				t.Errorf("%s.%s: no placeholder. An empty field has to read as a decision rather than a gap.",
					tool.Key, key)
			}
			if strings.TrimSpace(meta.Why) == "" {
				t.Errorf("%s.%s: no why_it_matters. An option nobody can justify is one nobody should be "+
					"offered.", tool.Key, key)
			}
			if !sharedVocabulary && strings.TrimSpace(meta.Danger) == "" {
				t.Errorf("%s.%s: no danger note. Every option in this workflow can change what a scan covers, "+
					"and the failure is always silent.", tool.Key, key)
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
			if len(meta.InertWhenValues) > 0 && meta.InertWhenKey == "" {
				t.Errorf("%s.%s: InertWhenValues without an InertWhenKey can never fire.", tool.Key, key)
			}
		}
	}
}

// An empty vocabulary is a legitimate answer and must be distinguishable from a tool nobody got round
// to. No company tool is in that state today, and this test is what keeps that true: the day one is
// added without a Limitation, it fails here rather than shipping as apparently-unfinished work.
func TestCompanyEmptyVocabularyIsExplained(t *testing.T) {
	for _, tool := range CompanyTools() {
		if len(tool.Options) > 0 {
			continue
		}
		if strings.TrimSpace(tool.Limitation) == "" {
			t.Errorf("%s: no options and no Limitation. An empty vocabulary has to say WHY, or it reads as "+
				"unfinished work.", tool.Key)
		}
	}
}

// A DELIBERATELY SHORT vocabulary is the same problem in a smaller size. cloud_enum has eight
// options because CloudEnumConfigModal already owns most of its CLI, and without a Limitation saying
// so the tab looks half-built.
func TestCompanyShortVocabulariesExplainThemselves(t *testing.T) {
	tool := mustCompanyTool(t, "cloud_enum")
	if strings.TrimSpace(tool.Limitation) == "" {
		t.Fatal("cloud_enum must carry a Limitation explaining why eight options is the complete answer, " +
			"or a short tab reads as an unfinished one.")
	}
	if !strings.Contains(tool.Limitation, "cloud_enum_configs") {
		t.Error("cloud_enum's Limitation must name the store that already owns the rest of its CLI, or an " +
			"operator cannot find where the other settings are.")
	}
}

func TestCompanyOwnedFlagsAllCarryAReason(t *testing.T) {
	for _, tool := range CompanyTools() {
		for flag, why := range tool.OwnedFlags {
			if strings.TrimSpace(flag) == "" {
				t.Errorf("%s: an owned flag has an empty name.", tool.Key)
			}
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s: owned flag %s carries no reason. A refusal without a reason is unactionable.",
					tool.Key, flag)
			}
		}
	}
}

// The registry serves as many options as were measured, and a silent regression that halves a
// vocabulary would otherwise pass every structural test above. These counts come from the per-tool
// research files, minus the entries deliberately withheld with a reason recorded in OwnedFlags.
func TestCompanyVocabularySizes(t *testing.T) {
	// atLeast rather than exact: adding a measured option must not break the build, dropping half a
	// tool's vocabulary must.
	atLeast := map[string]int{
		"amass_intel": 6, "metabigor_company": 4, "ip_port_scan": 8, "ctl_company": 16,
		"securitytrails_company": 12, "github_recon": 14, "shodan_company": 12, "censys_company": 13,
		"amass_enum_company": 14, "dnsx_company": 11, "cloud_enum": 8, "katana_company": 46,
		"nuclei": 43,
	}
	for key, want := range atLeast {
		tool := mustCompanyTool(t, key)
		if len(tool.Options) < want {
			t.Errorf("%s: %d options, expected at least the %d that were researched.",
				key, len(tool.Options), want)
		}
		if len(tool.OwnedFlags) == 0 {
			t.Errorf("%s declares no owned flags, which cannot be right for a tool that was probed.", key)
		}
	}
}

// Every option that composes a repeated flag has to be a list, or the composer takes the default
// branch and emits one flag with a comma-joined value the tool never asked for.
func TestCompanyRepeatableOptionsAreLists(t *testing.T) {
	for _, tool := range CompanyTools() {
		for key, meta := range tool.Options {
			if meta.Repeatable && meta.Kind != "list" {
				t.Errorf("%s.%s: repeatable but kind %q. Only a list can be passed once per value.",
					tool.Key, key, meta.Kind)
			}
		}
	}
}

// The values that were MEASURED to be dangerous must be UNREACHABLE, not merely defaulted off. Every
// entry here is a specific measurement: a flag that turns a scan into a clean-looking zero, or one
// that was proven to do nothing at all while looking like the fix for a real problem.
func TestCompanyBlacklistedFlagsAreOwned(t *testing.T) {
	mustOwn := map[string][]string{
		// -nocolor and -silent DO NOT EXIST on `amass intel` and exit 1; -exclude/-include parse and do
		// nothing; -v was measured producing zero bytes on both streams.
		"amass_intel": {"-silent", "-nocolor", "-exclude", "-include", "-demo", "-org", "-v", "-json"},
		// -v is load bearing for the parser; -J and -q silently zero the results; -x, --proxy and -c were
		// each measured doing nothing; netd is completely dead in this image.
		"metabigor_company": {"-v", "--verbose", "-J", "--json", "-q", "--quiet", "-x", "--proxy", "-c", "netd"},
		// -rc, -wd and -t 0 each exit 0 with zero bytes of stdout; -j is the shape the parser needs;
		// -rl and -t are measured inert with one host per invocation.
		"dnsx_company": {"-j", "-rc", "-wd", "-t", "-rl", "-ro", "-e", "-auth", "-proxy", "-cdn", "-asn"},
		// -s bogus, -fs notafield, -cs nomatchxyz and -e '.*' all printed nothing and exited 0, so the
		// regex and DSL scope flags must be unreachable. -ob blinds the body parser. -sc is a phantom.
		"katana_company": {"-ob", "-cs", "-cos", "-mr", "-fr", "-mdc", "-fdc", "-ns", "-sc", "-j", "-v", "-p", "-u", "-kb-validate-secrets"},
		// The whole of cloud_enum_configs, so the two screens cannot disagree about one setting.
		"cloud_enum": {"-l", "-f", "-k", "-kf", "-t", "-m", "-b", "-ns", "-nsf", "--disable-aws", "--aws-services", "--aws-regions"},
		// -s and -v were both measured injecting github.com / docs.github.com into the company's root
		// domains through the framework's own stdout parser.
		"github_recon": {"-s", "-v", "-d", "-t"},
		// Same binary as the wildcard amass step, same measurements.
		"amass_enum_company": {"-silent", "-exclude", "-include", "-demo", "-nocolor", "-d", "-passive", "-json"},
		// minify and facets both return HTTP 200 with nothing the parser can read.
		"shodan_company": {"minify=true", "facets=", "query string percent-encoding"},
		"censys_company": {"query string percent-encoding", "per_page above 100"},
		"ctl_company":    {"output=json", "url.QueryEscape on the company name", "space and comma rejection"},
	}
	for toolKey, flags := range mustOwn {
		tool := mustCompanyTool(t, toolKey)
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

// Five of the thirteen tools have NO command line at all. Their options must therefore carry no
// Flag, or the screen promises a command line it cannot build, and they must carry a Limitation
// saying so, or an operator reads "would_add_args: []" as a bug.
func TestCompanyToolsWithoutACommandLineCarryNoFlags(t *testing.T) {
	for _, key := range []string{
		"ip_port_scan", "ctl_company", "securitytrails_company", "shodan_company", "censys_company",
	} {
		tool := mustCompanyTool(t, key)
		if strings.TrimSpace(tool.Limitation) == "" {
			t.Errorf("%s has no command line and must say so in its Limitation.", key)
		}
		for optKey, meta := range tool.Options {
			if meta.Flag != "" {
				t.Errorf("%s.%s declares flag %q, but %s has no command line. A flag here would compose an "+
					"argument for a process that is never spawned.", key, optKey, meta.Flag, key)
			}
		}
		// So a full settings payload composes nothing: an operator has to be able to see that saving this
		// changed no command line.
		settings := map[string]any{}
		for optKey, meta := range tool.Options {
			switch meta.Kind {
			case "bool":
				settings[optKey] = true
			case "int", "float":
				if meta.Min != nil {
					settings[optKey] = *meta.Min
				} else {
					settings[optKey] = float64(1)
				}
			}
		}
		if args, _ := BuildCompanyArgs(tool, settings); len(args) != 0 {
			t.Errorf("%s settings must compose no arguments, got %v", key, args)
		}
	}
}

// Invocation is the "go read the truth in one hop" promise, and it is also embedded in the sentence
// the operator sees when a tool is not wired. A LINE NUMBER in it is a promise that rots: in the
// Wildcard build two invocations were wrong within one working session, pointing an operator at the
// wrong part of a file to answer "does my setting do anything".
func TestCompanyInvocationsCarryNoLineNumber(t *testing.T) {
	lineRef := regexp.MustCompile(`\.go:\d+`)
	for _, tool := range CompanyTools() {
		if lineRef.MatchString(tool.Invocation) {
			t.Errorf("%s Invocation carries a line number and will be wrong within a week: %q",
				tool.Key, tool.Invocation)
		}
		if strings.TrimSpace(tool.Invocation) == "" {
			t.Errorf("%s has no Invocation, so nothing tells a reader which runner to check", tool.Key)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Wiring claims.
// ---------------------------------------------------------------------------------------------

// companyWiringFiles are the files that make a runner read the settings store.
//
// DISCOVERED, NOT LISTED. This started as a hardcoded slice with one entry, and the first commit that
// added wiring files made it stale in exactly the way lesson 3 warns about: three newly wired tools
// reported runner_reads_settings=true while the test insisted nothing declared them, because the
// declaration was real and the LIST had not been updated. A list of the files that tell the truth is
// itself a thing that can be wrong, so there is no longer one - every .go file in the package is
// searched for the call.
//
// Test sources are excluded so that a string like markCompanyRunnerWired("x") written inside an
// assertion cannot forge a declaration.
func companyWiringFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot list the package directory to find the wiring files: %v", err)
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("cannot read %s: %v", name, err)
		}
		if strings.Contains(string(src), "markCompanyRunnerWired(") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files
}

// A tool whose runner reads the settings store must SAY it does, and one whose runner does not must
// not claim it. The API attaches a "the next scan will use the hardcoded behaviour" note based
// entirely on this flag, so a wrong value is a sentence that lies to the operator in one direction or
// the other.
//
// This reads the wiring sources rather than trusting a list, because in the Wildcard build a list is
// exactly what failed: six wired tools reported not-wired for a whole session.
func TestCompanyWiredToolsClaimIt(t *testing.T) {
	claimed := map[string]bool{}
	for _, tool := range companyRegistry {
		if tool.RunnerReads {
			claimed[tool.Key] = true
		}
	}

	declared := map[string]string{}
	for _, name := range companyWiringFiles(t) {
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("cannot read wiring file %s: %v", name, err)
		}
		for _, call := range regexp.MustCompile(`markCompanyRunnerWired\(([^)]*)\)`).
			FindAllStringSubmatch(string(src), -1) {
			for _, quoted := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(call[1], -1) {
				declared[quoted[1]] = name
			}
		}
	}

	if len(declared) == 0 {
		t.Fatal("no wiring file declares any wired tool; either the helper was renamed or the nuclei " +
			"sharing was removed")
	}

	for key, file := range declared {
		if _, ok := CompanyToolByKey(key); !ok {
			t.Errorf("%s claims to wire %q, which is not a registered company tool. A rename here silently "+
				"un-wires a runner", file, key)
			continue
		}
		if !claimed[key] {
			t.Errorf("%s wires %q but the registry reports runner_reads_settings=false, so the API tells the "+
				"operator their configuration will be ignored when it will not", file, key)
		}
	}

	for key := range claimed {
		if declared[key] == "" {
			t.Errorf("%q reports runner_reads_settings=true but no wiring file declares it. The API is "+
				"promising the setting takes effect with nothing behind that promise", key)
		}
	}
}

// The company nuclei claim rests on the WILDCARD overlay still wiring nuclei, because that is the
// half that lives in the runner. If the overlay ever stops doing it, the company claim becomes a lie
// and this is the only place that would notice.
func TestCompanyNucleiWiringDependsOnTheWildcardOverlay(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "wildcardRunnerOverlay.go"))
	if err != nil {
		t.Fatalf("cannot read wildcardRunnerOverlay.go: %v", err)
	}
	if !strings.Contains(string(src), `markWildcardRunnerWired(`) ||
		!strings.Contains(string(src), `"nuclei"`) {
		t.Fatal("wildcardRunnerOverlay.go no longer wires nuclei, so the COMPANY registry's claim that " +
			"nuclei reads its settings is now false. Either restore the wiring or remove " +
			"markCompanyRunnerWired(\"nuclei\") from companyNucleiShare.go.")
	}
	if !strings.Contains(string(src), "applyNucleiWildcardSettings") &&
		!strings.Contains(string(src), "wildcardRunnerSettings") {
		t.Error("the overlay no longer looks like the loader the company claim depends on; re-check that a " +
			"company scope target's nuclei settings are still read by scope_target_id alone.")
	}
}

// A tool that IS wired must not still carry a Limitation telling the operator it needs runner code.
// The client renders Limitation as a persistent alert, so in the Wildcard build a working feature was
// advertised as missing for a whole session.
func TestCompanyWiredToolsDoNotClaimTheyNeedWiring(t *testing.T) {
	for _, tool := range companyRegistry {
		if !tool.RunnerReads {
			continue
		}
		lower := strings.ToLower(tool.Limitation)
		for _, phrase := range []string{"runner change", "does not read", "not read yet", "requires a runner"} {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s is wired but its Limitation says %q, which the UI shows as a permanent alert: %q",
					tool.Key, phrase, tool.Limitation)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// nuclei: shared, not copied.
// ---------------------------------------------------------------------------------------------

// The company nuclei entry must reference THE SAME MAPS as the wildcard one, not equal copies of
// them. Equality would pass on the day it was written and drift the first time either side gained an
// option; identity cannot drift at all.
func TestCompanyNucleiSharesTheWildcardVocabulary(t *testing.T) {
	company := mustCompanyTool(t, "nuclei")
	wildcard, ok := WildcardToolByKey("nuclei")
	if !ok {
		t.Fatal("nuclei is not in the wildcard registry, which is where the shared vocabulary lives")
	}

	if reflect.ValueOf(company.Options).Pointer() != reflect.ValueOf(wildcard.Options).Pointer() {
		t.Error("company nuclei Options is a COPY of the wildcard map rather than the same map. Two option " +
			"maps for one runner is the drift this design exists to prevent, and the measured danger notes " +
			"on -ni, -mhe, -lna, -spm and -rsr are the most expensive text in this project to have right in " +
			"one place and wrong in another.")
	}
	if reflect.ValueOf(company.OwnedFlags).Pointer() != reflect.ValueOf(wildcard.OwnedFlags).Pointer() {
		t.Error("company nuclei OwnedFlags is a COPY of the wildcard map rather than the same map.")
	}
	if reflect.ValueOf(company.Groups).Pointer() != reflect.ValueOf(wildcard.Groups).Pointer() {
		t.Error("company nuclei Groups is a COPY of the wildcard slice rather than the same slice.")
	}

	// And the workflow-specific fields must NOT be shared, or the company card claims the wildcard's
	// position in the wildcard's phase.
	if company.Step == wildcard.Step {
		t.Errorf("company nuclei carries the wildcard's step %d; a tool served to two workflows needs a "+
			"per-workflow step.", company.Step)
	}
	if company.Phase == "" {
		t.Error("company nuclei has no phase.")
	}
}

// nuclei's settings must be read from and written to the store the RUNNER reads. Everything else in
// this build would look identical and do nothing.
func TestCompanyNucleiSettingsGoToTheWildcardStore(t *testing.T) {
	if got := companySettingsTable("nuclei"); got != "wildcard_tool_settings" {
		t.Fatalf("company nuclei settings would be written to %q. The runner reads wildcard_tool_settings by "+
			"scope target id alone, so anywhere else means the operator configures a scan and gets the "+
			"defaults with no way to tell.", got)
	}
	for _, tool := range CompanyTools() {
		if tool.Key == "nuclei" {
			continue
		}
		if got := companySettingsTable(tool.Key); got != "company_tool_settings" {
			t.Errorf("%s would be written to %q rather than company_tool_settings.", tool.Key, got)
		}
	}
	if companySharedStoreNote("nuclei") == "" {
		t.Error("a tool whose settings live in another workflow's table must say so on every response.")
	}
	if companySharedStoreNote("katana_company") != "" {
		t.Error("only nuclei shares a store; anything else claiming to would mislead a reader.")
	}
}

// ---------------------------------------------------------------------------------------------
// Target-selection stores: the collision map has to be true.
// ---------------------------------------------------------------------------------------------

// Every flag the collision map says an existing config store owns must ACTUALLY be declared
// framework-owned in the vocabulary. Otherwise the map claims a boundary the save endpoint does not
// enforce, and one setting becomes writable from two screens.
func TestCompanyTargetSelectionFlagsAreOwned(t *testing.T) {
	for toolKey, entry := range CompanyTargetSelectionStores() {
		tool := mustCompanyTool(t, toolKey)
		flags, _ := entry["owned_flags"].([]string)
		if len(flags) == 0 {
			t.Errorf("%s: the target-selection entry names no owned flags, so it documents no boundary.", toolKey)
		}
		for _, flag := range flags {
			if _, owned := tool.OwnedFlags[flag]; !owned {
				t.Errorf("%s: the target-selection map says %q belongs to %v, but the vocabulary does not "+
					"declare it framework-owned, so a save could write it from this screen too.",
					toolKey, flag, entry["table"])
			}
		}
		if strings.TrimSpace(entry["note"].(string)) == "" {
			t.Errorf("%s: the target-selection entry has no note saying what the other store owns.", toolKey)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Save-path refusals. Pure over the registry, so they run without a database.
// ---------------------------------------------------------------------------------------------

func TestCompanySaveRefusesAnOwnedFlag(t *testing.T) {
	tool := mustCompanyTool(t, "amass_intel")

	// The MCP shape: a caller sends the flag itself.
	refused := RefusedCompanyFlags(tool, map[string]any{"-silent": true})
	if len(refused) != 1 {
		t.Fatalf("expected -silent to be refused, got %v", refused)
	}
	if !strings.Contains(refused[0], "-silent") || !strings.Contains(refused[0], "set by the framework") {
		t.Errorf("the refusal must name the flag and say why, got %q", refused[0])
	}

	// Nothing legitimate is caught by the same check.
	if refused := RefusedCompanyFlags(tool, map[string]any{"timeoutMinutes": 30}); len(refused) != 0 {
		t.Errorf("a valid option was refused as framework-owned: %v", refused)
	}

	// The cloud_enum case that made the preset options flagless in the first place.
	cloud := mustCompanyTool(t, "cloud_enum")
	if refused := RefusedCompanyFlags(cloud, map[string]any{"-m": "/tmp/x.txt"}); len(refused) != 1 {
		t.Errorf("cloud_enum -m belongs to cloud_enum_configs and must be refused here, got %v", refused)
	}
	if refused := RefusedCompanyFlags(cloud, map[string]any{"mutationsPreset": "fuzz (1095)"}); len(refused) != 0 {
		t.Errorf("mutationsPreset carries no flag precisely so it can be saved; got %v", refused)
	}
}

func TestCompanySaveRefusesAnUnknownKey(t *testing.T) {
	tool := mustCompanyTool(t, "dnsx_company")

	// The realistic mistake: a near-miss on a real key.
	unknown := UnknownCompanyOptions(tool, map[string]any{"retry": 3, "retries": 3})
	if len(unknown) != 1 || unknown[0] != "retry" {
		t.Fatalf("expected only retry to be unknown, got %v", unknown)
	}
	if len(UnknownCompanyOptions(tool, map[string]any{"retries": 3})) != 0 {
		t.Error("a valid key was reported unknown")
	}
}

func TestCompanyValueValidation(t *testing.T) {
	cases := []struct {
		name     string
		tool     CompanyTool
		settings map[string]any
		wantBad  bool
		mustSay  string
	}{
		// amass intel -timeout 0 means unbounded on a process the framework cannot kill.
		{"amass intel timeout 0 is refused", mustCompanyTool(t, "amass_intel"),
			map[string]any{"timeoutMinutes": float64(0)}, true, "at least 1"},
		{"amass intel timeout 120 is fine", mustCompanyTool(t, "amass_intel"),
			map[string]any{"timeoutMinutes": float64(120)}, false, ""},
		// Measured: `-retry 0` exits 1, and the runner turns a non-zero exit into a skipped domain while
		// still finishing the scan as a success.
		{"dnsx retries 0 is refused", mustCompanyTool(t, "dnsx_company"),
			map[string]any{"retries": float64(0)}, true, "at least 1"},
		{"dnsx retries 3 is fine", mustCompanyTool(t, "dnsx_company"),
			map[string]any{"retries": float64(3)}, false, ""},
		// Measured: an empty host-discovery list makes every address read as dead.
		{"ip_port_scan empty discovery list is refused", mustCompanyTool(t, "ip_port_scan"),
			map[string]any{"hostDiscoveryPorts": ""}, true, "at least 1"},
		{"ip_port_scan a real discovery list is fine", mustCompanyTool(t, "ip_port_scan"),
			map[string]any{"hostDiscoveryPorts": "80,443,8443"}, false, ""},
		// Measured: an empty query list never enters the loop and stores zero domains as a success.
		{"shodan empty query list is refused", mustCompanyTool(t, "shodan_company"),
			map[string]any{"enabledQueries": []any{}}, true, "at least 1"},
		{"shodan a real query list is fine", mustCompanyTool(t, "shodan_company"),
			map[string]any{"enabledQueries": []any{"ssl.cert.subject.O"}}, false, ""},
		{"shodan an unknown query name is refused", mustCompanyTool(t, "shodan_company"),
			map[string]any{"enabledQueries": []any{"ssl.cert.subject.O", "notafilter"}}, true, "notafilter"},
		// Measured: katana treats an unrecognised strategy as nothing at all and exits 0 having crawled
		// zero endpoints.
		{"katana strategy must be one katana accepts", mustCompanyTool(t, "katana_company"),
			map[string]any{"strategy": "bogus"}, true, "must be one of"},
		{"katana breadth-first is fine", mustCompanyTool(t, "katana_company"),
			map[string]any{"strategy": "breadth-first"}, false, ""},
		{"katana fieldScope must be one katana accepts", mustCompanyTool(t, "katana_company"),
			map[string]any{"fieldScope": "notafield"}, true, "must be one of"},
		{"katana excludeHosts must be a known preset", mustCompanyTool(t, "katana_company"),
			map[string]any{"excludeHosts": []any{".*"}}, true, ".*"},
		{"katana excludeHosts private-ips is fine", mustCompanyTool(t, "katana_company"),
			map[string]any{"excludeHosts": []any{"private-ips"}}, false, ""},
		// Measured: -mrs 500 truncated a body mid-URL and handed the parser half a hostname.
		{"katana maxResponseSize below 64KB is refused", mustCompanyTool(t, "katana_company"),
			map[string]any{"maxResponseSize": float64(500)}, true, "at least 65536"},
		{"katana maxResponseSize 4MB is fine", mustCompanyTool(t, "katana_company"),
			map[string]any{"maxResponseSize": float64(4194304)}, false, ""},
		// The float kind, which only the company registry uses.
		{"shodan delay accepts a fraction", mustCompanyTool(t, "shodan_company"),
			map[string]any{"perQueryDelaySeconds": float64(0.5)}, false, ""},
		{"shodan delay above the ceiling is refused", mustCompanyTool(t, "shodan_company"),
			map[string]any{"perQueryDelaySeconds": float64(90)}, true, "at most 60"},
		{"censys rate limit below the floor is refused", mustCompanyTool(t, "censys_company"),
			map[string]any{"rateLimitPerSecond": float64(0.01)}, true, "at least 0.1"},
		// crt.sh's maxResults floor exists so nobody sets a small silent truncation.
		{"ctl maxResults below the floor is refused", mustCompanyTool(t, "ctl_company"),
			map[string]any{"maxResults": float64(10)}, true, "at least 100"},
		{"ctl queryField must be a known field", mustCompanyTool(t, "ctl_company"),
			map[string]any{"queryField": "ORG"}, true, "must be one of"},
		{"ctl a switch must be a bool", mustCompanyTool(t, "ctl_company"),
			map[string]any{"dropNamesContainingInc": "off"}, true, "switch"},
		// amass enum -timeout is minutes and 0 is unbounded on a process nothing kills.
		{"amass enum timeout 0 is refused", mustCompanyTool(t, "amass_enum_company"),
			map[string]any{"timeoutMinutes": float64(0)}, true, "at least 1"},
		{"amass enum maxDepth below the floor is refused", mustCompanyTool(t, "amass_enum_company"),
			map[string]any{"maxDepth": float64(2)}, true, "at least 3"},
		// cloud_enum's keyword logic is one of two values and argparse rejects anything else loudly.
		{"cloud_enum keywordLogic must be seq or conc", mustCompanyTool(t, "cloud_enum"),
			map[string]any{"keywordLogic": "parallel"}, true, "must be one of"},
		{"cloud_enum keywordLogic conc is fine", mustCompanyTool(t, "cloud_enum"),
			map[string]any{"keywordLogic": "conc"}, false, ""},
		// github_recon's script picker.
		{"github_recon script must be one that ships", mustCompanyTool(t, "github_recon"),
			map[string]any{"script": "github-dorks.py"}, true, "must be one of"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := ValidateCompanySettings(tc.tool, tc.settings)
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

// The refusals about a VALUE that is legal for its type and was measured to empty a scan anyway.
func TestCompanyUnsafeValues(t *testing.T) {
	cases := []struct {
		name     string
		tool     string
		settings map[string]any
		mustSay  string
	}{
		{"a dnsx resolver file path is refused", "dnsx_company",
			map[string]any{"resolvers": "/app/resolvers.txt"}, "file path"},
		{"a dnsx loopback resolver is refused", "dnsx_company",
			map[string]any{"resolvers": []any{"127.0.0.1"}}, "loopback"},
		{"a dnsx hostname resolver is refused", "dnsx_company",
			map[string]any{"resolvers": []any{"resolver.example.com"}}, "not an IP address"},
		{"a katana loopback proxy is refused", "katana_company",
			map[string]any{"proxy": "http://127.0.0.1:8080"}, "KATANA CONTAINER"},
		{"a katana header without a colon is refused", "katana_company",
			map[string]any{"headers": []any{"X-Bug-Bounty rs0n"}}, "no colon"},
		{"an amass enum loopback resolver is refused", "amass_enum_company",
			map[string]any{"untrustedResolvers": []any{"::1"}}, "loopback"},
		{"a non-numeric discovery port is refused", "ip_port_scan",
			map[string]any{"hostDiscoveryPorts": "80,https"}, "between 1 and 65535"},
		{"a port above 65535 is refused", "ip_port_scan",
			map[string]any{"webPorts": "80,70000"}, "between 1 and 65535"},
		{"a short aws account id is refused", "cloud_enum",
			map[string]any{"awsAccountId": "1234"}, "12 digits"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := companyUnsafeValues(mustCompanyTool(t, tc.tool), tc.settings)
			if len(problems) == 0 {
				t.Fatalf("expected a refusal, got none")
			}
			if !strings.Contains(strings.Join(problems, " "), tc.mustSay) {
				t.Errorf("the refusal must say %q, got %v", tc.mustSay, problems)
			}
		})
	}

	// And nothing legitimate is caught.
	ok := []struct {
		tool     string
		settings map[string]any
	}{
		{"dnsx_company", map[string]any{"resolvers": []any{"8.8.8.8", "1.1.1.1:53"}}},
		{"katana_company", map[string]any{"proxy": "http://host.docker.internal:8080"}},
		{"katana_company", map[string]any{"headers": []any{"X-Bug-Bounty: rs0n"}}},
		{"ip_port_scan", map[string]any{"hostDiscoveryPorts": "80,443,8080,8443,3000"}},
		{"cloud_enum", map[string]any{"awsAccountId": "123456789012"}},
		{"amass_enum_company", map[string]any{"untrustedResolvers": []any{"9.9.9.9"}}},
	}
	for _, tc := range ok {
		if problems := companyUnsafeValues(mustCompanyTool(t, tc.tool), tc.settings); len(problems) != 0 {
			t.Errorf("%s: a legitimate value was refused: %v", tc.tool, problems)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Inertness, advisories and composition.
// ---------------------------------------------------------------------------------------------

func TestCompanyInertOptionsAreReported(t *testing.T) {
	// amass intel -p does nothing without -active.
	intel := mustCompanyTool(t, "amass_intel")
	inert := CompanyInertOptions(intel, map[string]any{"certGrabPorts": "80,443,8443"})
	if _, ok := inert["certGrabPorts"]; !ok {
		t.Fatalf("certGrabPorts should be inert without activeMode, got %v", inert)
	}
	if inert := CompanyInertOptions(intel, map[string]any{
		"certGrabPorts": "80,443", "activeMode": true,
	}); len(inert) != 0 {
		t.Errorf("certGrabPorts should be live with activeMode on, got %v", inert)
	}

	// amass -norecursive makes -min-for-recursive dead.
	enum := mustCompanyTool(t, "amass_enum_company")
	if inert := CompanyInertOptions(enum, map[string]any{
		"minForRecursive": float64(3), "noRecursive": true,
	}); inert["minForRecursive"] == "" {
		t.Errorf("minForRecursive should be inert while noRecursive is on, got %v", inert)
	}

	// The whole katana headless group is fatal or meaningless without -hl.
	katana := mustCompanyTool(t, "katana_company")
	gated := []string{"systemChromePath", "noSandbox", "headlessOptions", "pageLoadStrategy", "hybrid", "xhrExtraction"}
	settings := map[string]any{
		"systemChromePath": "/usr/bin/chromium", "noSandbox": true,
		"headlessOptions": []any{"--disable-dev-shm-usage"}, "pageLoadStrategy": "networkidle",
		"hybrid": true, "xhrExtraction": true,
	}
	inert = CompanyInertOptions(katana, settings)
	for _, key := range gated {
		if _, reported := inert[key]; !reported {
			t.Errorf("%s must be reported inert without headless", key)
		}
	}
	if args, _ := BuildCompanyArgs(katana, settings); len(args) != 0 {
		t.Errorf("headless-only flags composed without -hl: %v", args)
	}
	settings["headless"] = true
	if inert := CompanyInertOptions(katana, settings); len(inert) != 0 {
		t.Errorf("with headless on nothing should be inert, got %v", inert)
	}

	// Censys pacing is inert until pagination exists.
	censys := mustCompanyTool(t, "censys_company")
	if inert := CompanyInertOptions(censys, map[string]any{"rateLimitPerSecond": float64(1)}); len(inert) == 0 {
		t.Error("rateLimitPerSecond must be inert without maxPages: it would throttle a single request")
	}
}

// The value-sensitive inertness the Wildcard registry had no need for: github-subdomains.py has no
// -a and no -r, so both switches are dead when it is selected and must not reach a command line that
// would reject them.
func TestCompanyInertWhenValuesGateOnTheScriptName(t *testing.T) {
	tool := mustCompanyTool(t, "github_recon")

	live := map[string]any{"script": "github-endpoints.py", "allDomains": true, "relativeUrls": true}
	if inert := CompanyInertOptions(tool, live); len(inert) != 0 {
		t.Errorf("with github-endpoints.py both switches are real, got %v", inert)
	}
	if args, _ := BuildCompanyArgs(tool, live); !strings.Contains(strings.Join(args, " "), "-a") {
		t.Errorf("-a should compose for github-endpoints.py, got %v", args)
	}

	dead := map[string]any{"script": "github-subdomains.py", "allDomains": true, "relativeUrls": true}
	inert := CompanyInertOptions(tool, dead)
	for _, key := range []string{"allDomains", "relativeUrls"} {
		if _, reported := inert[key]; !reported {
			t.Errorf("%s must be inert while script is github-subdomains.py, got %v", key, inert)
		}
	}
	args, warnings := BuildCompanyArgs(tool, dead)
	if joined := strings.Join(args, " "); strings.Contains(joined, "-a") || strings.Contains(joined, "-r") {
		t.Errorf("a switch the selected script does not have reached the command line: %v", args)
	}
	if len(warnings) < 2 {
		t.Errorf("each inert switch must produce a warning, got %v", warnings)
	}
}

func TestCompanyAdvisories(t *testing.T) {
	// The default-state defect: three ports are scanned in detail that no host can ever reach.
	scan := mustCompanyTool(t, "ip_port_scan")
	advisories := CompanyAdvisories(scan, map[string]any{})
	got, ok := advisories["webPorts"]
	if !ok {
		t.Fatal("the host-discovery / web-port mismatch is TRUE AT THE DEFAULTS and must be reported even " +
			"when nothing has been configured")
	}
	for _, port := range []string{"8080", "8443", "3000"} {
		if !strings.Contains(got, port) {
			t.Errorf("the advisory must name port %s, got %q", port, got)
		}
	}
	// Fixing the discovery list clears it.
	fixed := CompanyAdvisories(scan, map[string]any{
		"hostDiscoveryPorts": strings.Join(func() []string {
			var s []string
			for _, p := range ipPortScanDefaultWebPorts {
				s = append(s, strconv.Itoa(p))
			}
			return s
		}(), ","),
	})
	if _, still := fixed["webPorts"]; still {
		t.Errorf("with every web port in the discovery list there is no mismatch left, got %v", fixed)
	}

	// katana: the delay defeats the rate limit, and headless downloads a browser without a chrome path.
	katana := mustCompanyTool(t, "katana_company")
	adv := CompanyAdvisories(katana, map[string]any{"delay": float64(1), "rateLimit": float64(50)})
	if !strings.Contains(adv["rateLimit"], "effective rate") {
		t.Errorf("delay defeating rateLimit must be reported, got %v", adv)
	}
	adv = CompanyAdvisories(katana, map[string]any{"headless": true})
	if !strings.Contains(adv["headless"], "DOWNLOAD") {
		t.Errorf("headless without systemChromePath must warn about the scan-time download, got %v", adv)
	}
	adv = CompanyAdvisories(katana, map[string]any{"headless": true, "systemChromePath": "/usr/bin/chromium"})
	if _, still := adv["headless"]; still {
		t.Errorf("with a chrome path there is nothing to warn about, got %v", adv)
	}

	// cloud_enum: half a credential pair does nothing at all.
	cloud := mustCompanyTool(t, "cloud_enum")
	adv = CompanyAdvisories(cloud, map[string]any{"awsAccessKey": "AKIAEXAMPLE"})
	if adv["awsAccessKey"] == "" {
		t.Error("an access key with no secret key must be reported: neither half works alone")
	}
	adv = CompanyAdvisories(cloud, map[string]any{"awsAccessKey": "AKIAEXAMPLE", "awsSecretKey": "s"})
	if adv["awsAccessKey"] != "" || adv["awsSecretKey"] != "" {
		t.Errorf("a complete pair must not warn, got %v", adv)
	}

	// amass enum: the timeout is per domain and the loop has no aggregate cap.
	enum := mustCompanyTool(t, "amass_enum_company")
	if adv := CompanyAdvisories(enum, map[string]any{"timeoutMinutes": float64(300)}); !strings.Contains(
		adv["timeoutMinutes"], "PER DOMAIN") {
		t.Errorf("the per-domain multiplication must be reported, got %v", adv)
	}
}

// The defaults the advisory reasons about have to match the ones the vocabulary describes, or the
// warning is computed from one set of ports and explained with another.
func TestCompanyIPPortScanDefaultsAreDescribed(t *testing.T) {
	tool := mustCompanyTool(t, "ip_port_scan")
	discovery := tool.Options["hostDiscoveryPorts"].Placeholder
	for _, p := range ipPortScanDefaultDiscoveryPorts {
		if !strings.Contains(discovery, strconv.Itoa(p)) {
			t.Errorf("hostDiscoveryPorts placeholder does not mention default port %d, so the screen and the "+
				"advisory disagree about what the defaults are.", p)
		}
	}
	web := tool.Options["webPorts"].Placeholder
	for _, p := range ipPortScanDefaultWebPorts {
		if !strings.Contains(web, strconv.Itoa(p)) {
			t.Errorf("webPorts placeholder does not mention default port %d.", p)
		}
	}
}

func TestCompanyBuildArgs(t *testing.T) {
	enum := mustCompanyTool(t, "amass_enum_company")

	args, warnings := BuildCompanyArgs(enum, map[string]any{
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
	if strings.Count(joined, "-bl ") != 2 {
		t.Errorf("a repeatable list must be passed once per value, got %v", args)
	}
	if strings.Count(joined, "-r ") != 2 {
		t.Errorf("resolvers must be passed once per value, got %v", args)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}

	// Non-repeatable lists comma-join, which is what katana -ef expects.
	katana := mustCompanyTool(t, "katana_company")
	args, _ = BuildCompanyArgs(katana, map[string]any{"extensionFilter": []any{"png", "jpg"}})
	if strings.Join(args, " ") != "-ef png,jpg" {
		t.Errorf("expected a comma-joined -ef, got %v", args)
	}

	// An inert option must not reach the command line, and the caller must be told why.
	args, warnings = BuildCompanyArgs(enum, map[string]any{
		"noRecursive": true, "minForRecursive": float64(4),
	})
	if strings.Contains(strings.Join(args, " "), "-min-for-recursive") {
		t.Errorf("an inert option reached the command line: %v", args)
	}
	if len(warnings) == 0 {
		t.Error("an inert option must produce a warning")
	}
}

// The composed arguments must be stable between calls, or the "what will this run" preview changes
// under the operator for no reason and cannot be diffed against a previous run.
func TestCompanyBuildArgsIsDeterministic(t *testing.T) {
	tool := mustCompanyTool(t, "katana_company")
	settings := map[string]any{
		"depth": float64(3), "concurrency": float64(20), "rateLimit": float64(10),
		"delay": float64(0), "timeout": float64(120), "retry": float64(3),
		"jsCrawl": true, "noDefaultExtFilter": true, "omitRaw": true, "displayOutOfScope": true,
	}
	first, warnings := BuildCompanyArgs(tool, settings)
	// Every key above is a real option, so nothing may be dropped. Without this the test would still
	// pass on a vocabulary that had renamed all of them, since unknown keys only produce a warning.
	if len(warnings) != 0 {
		t.Fatalf("a settings map of real keys produced warnings: %v", warnings)
	}
	if len(first) == 0 {
		t.Fatal("nothing composed from ten real options")
	}
	for i := 0; i < 20; i++ {
		again, _ := BuildCompanyArgs(tool, settings)
		if strings.Join(first, " ") != strings.Join(again, " ") {
			t.Fatalf("composition is not deterministic:\n%v\n%v", first, again)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// The round trip, exercised through the same merge semantics the handler uses.
// ---------------------------------------------------------------------------------------------

func TestCompanyValidSaveRoundTrips(t *testing.T) {
	tool := mustCompanyTool(t, "dnsx_company")

	incoming := map[string]any{
		"queryPTR":  false,
		"querySRV":  false,
		"retries":   float64(5),
		"omitRaw":   true,
		"resolvers": []any{"8.8.8.8", "1.1.1.1"},
	}

	if refused := RefusedCompanyFlags(tool, incoming); len(refused) != 0 {
		t.Fatalf("a valid save was refused as framework-owned: %v", refused)
	}
	if unknown := UnknownCompanyOptions(tool, incoming); len(unknown) != 0 {
		t.Fatalf("a valid save contained unknown keys: %v", unknown)
	}
	if problems := ValidateCompanySettings(tool, incoming); len(problems) != 0 {
		t.Fatalf("a valid save failed validation: %v", problems)
	}
	if problems := companyUnsafeValues(tool, incoming); len(problems) != 0 {
		t.Fatalf("a valid save was refused as unsafe: %v", problems)
	}

	stored := mergeWildcardSettings(map[string]any{}, incoming, false)
	if len(stored) != 5 {
		t.Fatalf("expected 5 stored settings, got %d: %v", len(stored), stored)
	}

	// The values survive a trip through jsonb, which is what actually happens between the two reads.
	stored = roundTripJSON(t, stored)
	if stored["retries"] != float64(5) {
		t.Errorf("retries did not round trip: %#v", stored["retries"])
	}
	if stored["omitRaw"] != true {
		t.Errorf("omitRaw did not round trip: %#v", stored["omitRaw"])
	}
	if problems := ValidateCompanySettings(tool, stored); len(problems) != 0 {
		t.Errorf("what was stored no longer validates: %v", problems)
	}

	// A merge sends one key and must not blank the rest.
	stored = mergeWildcardSettings(stored, map[string]any{"retries": float64(2)}, false)
	if len(stored) != 5 || stored["retries"] != float64(2) {
		t.Errorf("a partial save clobbered the rest: %v", stored)
	}

	// A null removes exactly one key.
	stored = mergeWildcardSettings(stored, map[string]any{"omitRaw": nil}, false)
	if _, present := stored["omitRaw"]; present {
		t.Errorf("a null value did not remove the key: %v", stored)
	}
	if len(stored) != 4 {
		t.Errorf("a null value removed more than one key: %v", stored)
	}

	// Replace makes the payload the whole state, which is what a form that showed every field means.
	stored = mergeWildcardSettings(stored, map[string]any{"retries": float64(1)}, true)
	if len(stored) != 1 {
		t.Errorf("replace did not become the whole state: %v", stored)
	}
}

// The two registries share one validator, one composer and one merge rule. If they ever stop sharing
// them, this fails: a company tool would be validated by code the wildcard tests never exercise.
func TestCompanyAndWildcardShareOneImplementation(t *testing.T) {
	company := mustCompanyTool(t, "dnsx_company")
	settings := map[string]any{"retries": float64(0)}

	direct := ValidateWildcardSettings(company, settings)
	viaCompany := ValidateCompanySettings(company, settings)
	if strings.Join(direct, " ") != strings.Join(viaCompany, " ") {
		t.Errorf("the company validator disagrees with the shared one:\n%v\n%v", viaCompany, direct)
	}

	a1, w1 := BuildWildcardArgs(company, map[string]any{"retries": float64(3)})
	a2, w2 := BuildCompanyArgs(company, map[string]any{"retries": float64(3)})
	if strings.Join(a1, " ") != strings.Join(a2, " ") || len(w1) != len(w2) {
		t.Errorf("the company composer disagrees with the shared one:\n%v\n%v", a2, a1)
	}
}
