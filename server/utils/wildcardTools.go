package utils

import (
	"fmt"
	"sort"
	"strings"
)

// The Wildcard workflow's tools, as ONE server-side registry.
//
// The operator's requirement, in their words: "It is just ONE configuration, but it can be changed
// both ways." The Settings screen and the MCP tool are two editors of one store, so neither can
// carry its own idea of what a setting is. The vocabulary below is served over HTTP and both
// surfaces render whatever it says. Adding an option here makes it appear in the UI and become
// settable over MCP in the same commit, and there is no second list to forget.
//
// This is the same shape as vectorTools.go / xssOptions.go, which solved the identical problem for
// the URL workflow's scanners. It is deliberately a PARALLEL store rather than a reuse of
// vector_tool_settings: that table is keyed to the attack-vector layer, its tools carry Compose and
// Parse functions and insertion points, and none of that means anything to a subdomain scraper.
//
// PROVENANCE IS A FIELD, NOT A FOOTNOTE. Some of this vocabulary was measured against the real
// containers, flag by flag, including several flags that parse fine and do nothing. Some of it was
// derived from the command line the runner already executes in production, which proves the flag is
// accepted by the installed image but proves nothing about what a DIFFERENT value would do. Those
// two are not the same claim and the UI must be able to say which it is showing.

// WildcardOptionMeta is one setting: enough for a form field to be generated from it, for an MCP
// caller to be told what it does, and for a command line to be composed from it, without any of the
// three hardcoding the others' knowledge.
type WildcardOptionMeta struct {
	Kind    string   `json:"kind"`  // bool | int | string | enum | list | path
	Group   string   `json:"group"` // must be one of the tool's Groups
	Label   string   `json:"label"`
	Flag    string   `json:"flag,omitempty"`
	Choices []string `json:"choices,omitempty"`

	// Unit is spelled out because getting it wrong is not hypothetical. amass -timeout is MINUTES and
	// the wildcard runner passes 60, which is an hour. An operator typing "300" expecting seconds
	// gets a five-hour scan.
	Unit string `json:"unit,omitempty"`

	// Placeholder says what the TOOL does when the option is not set, so an empty field reads as a
	// decision rather than as a gap.
	Placeholder string `json:"placeholder,omitempty"`

	// Why the option is worth having at all. Rendered as help text; also what the MCP option
	// reference returns, so an agent choosing a value has the same reasoning a human would.
	Why string `json:"why,omitempty"`

	// Danger is the sentence that stops someone silently ruining a scan. Nearly every option in this
	// workflow has one, because the dominant failure mode here is not an error: it is a tool that
	// exits 0, prints nothing, and gets stored as a clean result.
	Danger string `json:"danger,omitempty"`

	// Repeatable options are passed once per value rather than comma joined.
	Repeatable bool `json:"repeatable,omitempty"`

	Min *float64 `json:"min,omitempty"`
	Max *float64 `json:"max,omitempty"`

	// MinItems is the shortest list that is not a scan-killer.
	//
	// ADDED FOR THE COMPANY REGISTRY, which shares this type. Three of its lists empty a scan while
	// the tool still exits 0: an empty ip_port_scan hostDiscoveryPorts makes isHostAlive return false
	// for every address, an empty webPorts makes the port scan find nothing, and an empty
	// shodan enabledQueries never enters the query loop at all. All three are then stored as a
	// successful scan with zero results. No wildcard option sets it, so wildcard behaviour is
	// unchanged.
	MinItems *float64 `json:"min_items,omitempty"`

	// InertWhenValues makes InertWhenKey value-sensitive rather than merely truthy.
	//
	// ADDED FOR THE COMPANY REGISTRY. github_recon can run either of two scripts and
	// github-subdomains.py has no -a and no -r, so those two switches are dead when it is selected.
	// A plain truthy test cannot express that, because the gating value is a script name rather than
	// a switch. Empty means the original truthy behaviour, which is what every wildcard option has.
	InertWhenValues []string `json:"inert_when_values,omitempty"`

	// Provenance is how this entry was established:
	//
	//	measured   - probed against the installed container, flag by flag, with the behaviour observed.
	//	runner     - taken from the command line the runner executes today. The flag is therefore
	//	             accepted by the installed image, but the effect of other VALUES was not measured.
	//	unverified - the flag exists in --help and was accepted, but its semantics were not proven.
	Provenance string `json:"provenance"`

	// RequiresKey names a boolean setting this option is INERT without. amass -p only matters with
	// -active; subfinder -t and -r only matter with -nW. A field that does nothing is the exact class
	// of defect this whole screen exists to avoid, so the UI greys it out instead of accepting it.
	RequiresKey string `json:"requires_key,omitempty"`

	// InertWhenKey names a boolean setting that, when ON, makes this option do nothing.
	// amass -norecursive makes -min-for-recursive dead.
	InertWhenKey string `json:"inert_when_key,omitempty"`

	// ShadowedBy names an existing global setting that competes with this one. Declared rather than
	// resolved silently: two screens disagreeing about a rate limit is worse than one screen saying
	// which wins.
	ShadowedBy string `json:"shadowed_by,omitempty"`
}

// WildcardTool is one step of the Wildcard workflow: what it is, where it runs, and what about it
// can be configured.
type WildcardTool struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Step  int    `json:"step"`
	Phase string `json:"phase"`

	// Container is set for a tool the framework docker execs into; Image is set for a tool run as an
	// ephemeral `docker run --rm`. Exactly one is populated, and which it is decides whether a
	// file-path option can ever work: a --rm container with no volume mount cannot read or write one.
	Container string `json:"container,omitempty"`
	Image     string `json:"image,omitempty"`
	Binary    string `json:"binary,omitempty"`
	Version   string `json:"version,omitempty"`

	// Invocation names the function that actually builds the command line, so anyone doubting this
	// vocabulary can go and read the truth in one hop.
	Invocation string `json:"invocation"`

	Groups     []string                      `json:"groups"`
	Options    map[string]WildcardOptionMeta `json:"options"`
	OwnedFlags map[string]string             `json:"owned_flags"`

	// Limitation explains an EMPTY vocabulary. A tool with nothing to configure is a legitimate
	// answer and must be distinguishable from a tool nobody has got round to yet, so an empty
	// Options map without a Limitation is a registry bug and the tests fail on it.
	Limitation string `json:"limitation,omitempty"`

	// DelegatesTo names an EXISTING config store that already owns this tool, when there is one.
	// httpx is the case: httpx_configs is populated, wired and in use, so a second httpx vocabulary
	// here would be a copy that can drift, which is precisely what this registry exists to prevent.
	DelegatesTo string `json:"delegates_to,omitempty"`

	// RunnerReads says whether the scan runner CURRENTLY consults wildcard_tool_settings.
	//
	// Reported rather than hidden. A stored setting nothing reads is how a caller comes to believe a
	// scan did something it did not, so the API says so on every read and on every save until the
	// runner is wired.
	//
	// SET IT WITH markWildcardRunnerWired, FROM THE FILE THAT DOES THE WIRING. Never edit it here.
	RunnerReads bool `json:"runner_reads_settings"`

	Notes string `json:"notes,omitempty"`
}

// markWildcardRunnerWired records that a runner now reads the settings store.
//
// EACH WIRING FILE CALLS THIS FOR ITS OWN TOOLS, in its own init, so the claim lives in the same
// file as the code that makes it true.
//
// It did not start that way and the cost was immediate. One of the three wiring layers kept a
// hardcoded list of the four tools IT wired; the other two layers were written without touching that
// list. Six wired tools (amass, subfinder, gospider, subdomainizer, nuclei, nuclei-screenshot) went
// on reporting runner_reads_settings false, and wildcardSettings.go attached a note to every read and
// every save telling the operator "the next scan will use the hardcoded command line" for settings
// that were in fact being honoured.
//
// That is this project's defect of choice wearing its coat inside out. Everywhere else the danger is
// a control that claims to have worked and did nothing; here it was a control that worked and
// claimed it had not. Both end the same way: the operator cannot trust what the screen says.
//
// Unknown keys are ignored rather than fatal, so a tool renamed in the registry degrades to the
// honest answer (not wired) instead of panicking the API on boot. TestWildcardWiredToolsClaimIt
// reads the wiring sources and fails if a tool is wired without claiming it.
func markWildcardRunnerWired(tools ...string) {
	for _, key := range tools {
		for i := range wildcardRegistry {
			if wildcardRegistry[i].Key == key {
				wildcardRegistry[i].RunnerReads = true
			}
		}
	}
}

// wildcardRegistry is populated by wildcardOptions.go in its init, in workflow order.
var wildcardRegistry []WildcardTool

func registerWildcardTools(tools ...WildcardTool) {
	wildcardRegistry = append(wildcardRegistry, tools...)
}

// WildcardTools returns every tool in the workflow, in the order the steps run.
func WildcardTools() []WildcardTool {
	out := make([]WildcardTool, len(wildcardRegistry))
	copy(out, wildcardRegistry)
	return out
}

// WildcardToolByKey looks up one tool. Returns false rather than a zero value, so a bad key from an
// API caller is an error at the edge instead of a save into a store nothing will ever read.
func WildcardToolByKey(key string) (WildcardTool, bool) {
	for _, t := range wildcardRegistry {
		if t.Key == key {
			return t, true
		}
	}
	return WildcardTool{}, false
}

// WildcardToolKeys is every registered key, for an error message that tells the caller what they
// could have said instead.
func WildcardToolKeys() []string {
	keys := make([]string, 0, len(wildcardRegistry))
	for _, t := range wildcardRegistry {
		keys = append(keys, t.Key)
	}
	return keys
}

// UnknownWildcardOptions reports keys the vocabulary does not contain.
//
// These are REFUSED on save rather than stored with a warning. A key nothing reads changes nothing,
// and a caller who typoed "timeoutMinute" and got a 200 back has been told their scan is configured
// when it is not. The URL workflow stores-and-warns; this one refuses, because here the mistake is
// invisible until a scan silently behaves like the default.
func UnknownWildcardOptions(tool WildcardTool, settings map[string]any) []string {
	var unknown []string
	for key := range settings {
		if _, ok := tool.Options[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// RefusedWildcardFlags reports settings whose flag the RUNNER owns.
//
// Refused at save time rather than overwritten at run time. A setting that is stored and then
// displaced by the runner is how an operator comes to believe a scan did something it did not, and
// the reason is returned with the flag so the refusal is actionable rather than mysterious.
//
// This matches on the setting KEY as well as on its declared flag, because a caller editing over
// MCP will reasonably send "-silent": true rather than a camelCase key that does not exist.
func RefusedWildcardFlags(tool WildcardTool, settings map[string]any) []string {
	var refused []string
	for key := range settings {
		if why, owned := tool.OwnedFlags[key]; owned {
			refused = append(refused, key+" is set by the framework: "+why)
			continue
		}
		meta, known := tool.Options[key]
		if !known || meta.Flag == "" {
			continue
		}
		if why, owned := tool.OwnedFlags[meta.Flag]; owned {
			refused = append(refused, meta.Flag+" is set by the framework: "+why)
		}
	}
	sort.Strings(refused)
	return refused
}

// ValidateWildcardSettings type-checks and range-checks values against the vocabulary.
//
// Worth doing here rather than at run time for the same reason as the owned-flag refusal: by the
// time a bad value reaches the command line the operator has already been told the scan is
// configured. Returns one human sentence per bad value, empty when everything is acceptable.
func ValidateWildcardSettings(tool WildcardTool, settings map[string]any) []string {
	var problems []string
	for key, value := range settings {
		meta, known := tool.Options[key]
		if !known {
			continue // unknown keys are reported separately, with a different reason
		}
		if problem := validateWildcardValue(key, meta, value); problem != "" {
			problems = append(problems, problem)
		}
	}
	sort.Strings(problems)
	return problems
}

func validateWildcardValue(key string, meta WildcardOptionMeta, value any) string {
	switch meta.Kind {
	case "bool":
		if _, ok := value.(bool); !ok {
			return key + " is a switch and takes true or false."
		}
	case "int":
		n, ok := numericSetting(value)
		if !ok {
			return key + " is a number."
		}
		if n != float64(int64(n)) {
			return key + " is a whole number."
		}
		if meta.Min != nil && n < *meta.Min {
			return fmt.Sprintf("%s must be at least %g%s. %s", key, *meta.Min, unitSuffix(meta), meta.Danger)
		}
		if meta.Max != nil && n > *meta.Max {
			return fmt.Sprintf("%s must be at most %g%s. %s", key, *meta.Max, unitSuffix(meta), meta.Danger)
		}
	case "float":
		// A fractional number. Only the Company registry uses it (a Censys requests-per-second floor
		// of 0.1 and a Shodan inter-query pause that is meaningfully sub-second), and it is here
		// rather than folded into "int" so that a UI can render a step of 0.1 and so that a value
		// like 0.5 is not silently truncated to 0, which for a pause means "no pause at all".
		n, ok := numericSetting(value)
		if !ok {
			return key + " is a number."
		}
		if meta.Min != nil && n < *meta.Min {
			return fmt.Sprintf("%s must be at least %g%s. %s", key, *meta.Min, unitSuffix(meta), meta.Danger)
		}
		if meta.Max != nil && n > *meta.Max {
			return fmt.Sprintf("%s must be at most %g%s. %s", key, *meta.Max, unitSuffix(meta), meta.Danger)
		}
	case "enum":
		s, ok := value.(string)
		if !ok {
			return key + " is one of: " + strings.Join(meta.Choices, ", ") + "."
		}
		for _, c := range meta.Choices {
			if c == s {
				return ""
			}
		}
		return key + " must be one of: " + strings.Join(meta.Choices, ", ") + ". Got " + s + "."
	case "list":
		items, ok := listSetting(value)
		if !ok {
			return key + " is a list: either a comma separated string or an array of strings."
		}
		// A list that is too short to work at all. Refused rather than warned, because every case
		// this guards produces a scan that exits 0, finds nothing, and is stored as a success.
		if meta.MinItems != nil && float64(len(items)) < *meta.MinItems {
			return fmt.Sprintf("%s needs at least %g entr%s. %s", key, *meta.MinItems,
				map[bool]string{true: "y", false: "ies"}[*meta.MinItems == 1], meta.Danger)
		}
		if len(meta.Choices) == 0 {
			return ""
		}
		var bad []string
		for _, item := range items {
			found := false
			for _, c := range meta.Choices {
				if strings.EqualFold(c, item) {
					found = true
					break
				}
			}
			if !found {
				bad = append(bad, item)
			}
		}
		if len(bad) > 0 {
			// Deliberately an error rather than a warning. Both measured tools with a name list drop
			// an unrecognised name SILENTLY: subfinder ran only crtsh for `-s crtsh,notarealsource`
			// and still exited 0, and `-es notarealsource` excluded nothing at all. A typo there is a
			// coverage change with no symptom.
			return key + " does not recognise " + strings.Join(bad, ", ") +
				". A name this tool does not know is dropped silently, so the setting would not do what it says."
		}
	case "string", "path":
		if _, ok := value.(string); !ok {
			return key + " is text."
		}
	}
	return ""
}

func unitSuffix(meta WildcardOptionMeta) string {
	if meta.Unit == "" {
		return ""
	}
	return " " + meta.Unit
}

func numericSetting(value any) (float64, bool) {
	switch n := value.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// listSetting accepts both shapes a caller might reasonably send: a comma separated string, which is
// what a text field produces, and a JSON array, which is what an MCP caller produces.
func listSetting(value any) ([]string, bool) {
	switch v := value.(type) {
	case string:
		var out []string
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
		return out, true
	case []string:
		return v, true
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			if p := strings.TrimSpace(s); p != "" {
				out = append(out, p)
			}
		}
		return out, true
	}
	return nil, false
}

// WildcardInertOptions reports settings that are stored but cannot take effect, given the rest of
// the settings.
//
// Returned on read as well as on save, keyed by option, valued by the sentence explaining it. This
// is the answer to "I set the resolver concurrency and nothing changed": subfinder's -t is
// documented "(-active only)" and does exactly nothing while activeOnly is off.
func WildcardInertOptions(tool WildcardTool, settings map[string]any) map[string]string {
	inert := map[string]string{}
	for key := range settings {
		meta, known := tool.Options[key]
		if !known {
			continue
		}
		if meta.RequiresKey != "" && !truthySetting(settings[meta.RequiresKey]) {
			inert[key] = key + " does nothing unless " + meta.RequiresKey + " is on."
		}
		if meta.InertWhenKey != "" {
			if len(meta.InertWhenValues) > 0 {
				// Value-sensitive form. The gate is another option's VALUE, not a switch.
				got := strings.TrimSpace(stringifySetting(settings[meta.InertWhenKey]))
				for _, dead := range meta.InertWhenValues {
					if strings.EqualFold(dead, got) {
						inert[key] = key + " does nothing while " + meta.InertWhenKey + " is " + got + "."
						break
					}
				}
			} else if truthySetting(settings[meta.InertWhenKey]) {
				inert[key] = key + " does nothing while " + meta.InertWhenKey + " is on."
			}
		}
	}
	return inert
}

// BuildWildcardArgs turns stored settings into command-line arguments, plus the warnings a caller
// should see about what was left out.
//
// PURE, and deliberately separate from every runner. Nothing calls it in the scan path yet: wiring
// a runner changes live scan behaviour and is a decision for the orchestrator, not a side effect of
// adding a settings screen. Having it here and tested means the wiring is one line per runner when
// that decision is made, and means the vocabulary can be proven to compose sanely today.
//
// Deterministic order (sorted by option key) so a composed command line can be diffed between runs.
func BuildWildcardArgs(tool WildcardTool, settings map[string]any) ([]string, []string) {
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	inert := WildcardInertOptions(tool, settings)

	var args, warnings []string
	for _, key := range keys {
		meta, known := tool.Options[key]
		if !known {
			warnings = append(warnings, "Nothing reads "+key+"; it was not put on the command line.")
			continue
		}
		if why, ok := inert[key]; ok {
			warnings = append(warnings, why+" It was not put on the command line.")
			continue
		}
		if meta.Flag == "" {
			// A framework-level switch rather than a tool flag. It changes what the runner DOES, not
			// what it passes, so it is correct for it to produce no argument.
			continue
		}
		value := settings[key]
		switch meta.Kind {
		case "bool":
			if truthySetting(value) {
				args = append(args, meta.Flag)
			}
		case "list":
			items, ok := listSetting(value)
			if !ok || len(items) == 0 {
				continue
			}
			if meta.Repeatable {
				for _, item := range items {
					args = append(args, meta.Flag, item)
				}
				continue
			}
			args = append(args, meta.Flag, strings.Join(items, ","))
		default:
			s := strings.TrimSpace(stringifySetting(value))
			if s == "" {
				continue
			}
			args = append(args, meta.Flag, s)
		}
	}
	return args, warnings
}
