package utils

import (
	"context"
	"database/sql"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Wiring the stored Wildcard configuration into the runners for gau, ctl, shuffledns and CeWL.
//
// WHY THIS FILE EXISTS. wildcard_tool_settings, the option vocabulary and both editors (the Settings
// screen and the MCP tool) were built first, and nothing read them. An operator could open the
// config screen, set a value, save it successfully, run a scan and get the old behaviour with
// nothing anywhere saying so. A control that reports success and does nothing is the same defect
// class this project keeps finding in its scanners, so it is worse than having no control at all.
// Everything here exists to close that gap for four runners.
//
// THE INVARIANT THAT MATTERS MOST: with NO stored settings the command line must be byte-identical
// to what it was before. Every function below short-circuits on an empty settings map for exactly
// that reason, and there is a test per runner asserting it.
//
// THE COMPOSER IS NOT REIMPLEMENTED HERE. BuildWildcardArgs in wildcardTools.go is pure, ordered and
// already covered by tests including a determinism test; this file only decides which settings reach
// it and how the resulting arguments are merged into a command line that already carries hardcoded
// values for some of the same flags.

// wildcardScopeTargetID reads the scope target off a scan row.
//
// The runners are all called as `go ExecuteAndParse...(scanID, domain)` from a dozen places
// including the auto-scan orchestrator, so changing their signatures to carry a scope target would
// mean touching every call site. The scan row already has the id, and the column is nullable
// (RunShuffleDNSWithWordlist and RunCeWLScansForUrls insert NULL), so a missing id is a normal
// answer meaning "no per-target configuration exists" rather than an error.
func wildcardScopeTargetID(ctx context.Context, query, scanID string) string {
	var id sql.NullString
	if err := dbPool.QueryRow(ctx, query, scanID).Scan(&id); err != nil {
		return ""
	}
	if !id.Valid {
		return ""
	}
	return strings.TrimSpace(id.String)
}

// wildcardStoredSettings loads one tool's stored settings for a target, or nil when there is no
// target to load them for. nil and empty behave identically everywhere downstream.
func wildcardStoredSettings(ctx context.Context, scopeTargetID, toolKey string) map[string]any {
	if strings.TrimSpace(scopeTargetID) == "" {
		return nil
	}
	settings := loadWildcardSettings(ctx, scopeTargetID, toolKey)
	if len(settings) == 0 {
		return nil
	}
	return settings
}

// wildcardCommandWithSettings merges stored settings into a runner's hardcoded command line.
//
// Returns the command to run and the notes explaining anything that was dropped, rewritten or
// refused. The notes are not decoration: they are stored on the scan row, because "what did this
// actually run, and why is it not what I configured" is the question the whole diagnostic layer
// exists to answer.
//
// THREE THINGS HAPPEN, IN THIS ORDER:
//
//  1. Settings naming a flag the RUNNER owns are dropped. The save endpoint already refuses those,
//     but a value stored before a flag became owned could still be sitting in the jsonb column, so
//     this is the second line of defence rather than a duplicate of the first.
//  2. Tool-specific sanitisation for the measured traps where passing the stored value verbatim
//     would produce a scan that exits 0 and returns nothing.
//  3. Any hardcoded occurrence of a flag the settings now govern is REMOVED from the base command
//     before the composed arguments are appended, so each flag appears exactly once. Relying on
//     "the last one wins" would be relying on a parser behaviour nobody measured, and it would also
//     make a bool that the operator turned OFF impossible to express: the composer emits nothing
//     for a false bool, so the hardcoded --with-numbers would survive and the setting would be a
//     control that reports success and does nothing.
func wildcardCommandWithSettings(base []string, toolKey string, settings map[string]any) ([]string, []string) {
	if len(settings) == 0 {
		return base, nil
	}
	tool, ok := WildcardToolByKey(toolKey)
	if !ok {
		// Cannot happen with a registered tool, and is reported rather than ignored if it ever does:
		// silently running the hardcoded command with settings stored is the exact failure this
		// whole file exists to remove.
		return base, []string{"No Wildcard registry entry for " + toolKey +
			", so the stored settings were not applied and this scan used the hardcoded command line."}
	}

	safe, notes := wildcardSettingsMinusOwned(tool, settings)
	safe, sanitiseNotes := wildcardSanitiseSettings(toolKey, safe)
	notes = append(notes, sanitiseNotes...)

	extra, warnings := BuildWildcardArgs(tool, safe)
	notes = append(notes, warnings...)

	governed := wildcardGovernedFlags(tool, safe)
	if len(governed) == 0 && len(extra) == 0 {
		return base, notes
	}

	// Copied rather than appended in place. Some callers build their base command with append (CeWL
	// adds --ua and the exclusion file conditionally), which can leave spare capacity that a further
	// append would write into. That would mutate the caller's slice as a side effect of composing a
	// command, which is exactly the kind of action at a distance nobody debugs quickly.
	stripped := wildcardStripGovernedFlags(base, governed)
	out := make([]string, 0, len(stripped)+len(extra))
	out = append(out, stripped...)
	out = append(out, extra...)
	return out, notes
}

// wildcardSettingsMinusOwned removes settings whose flag the runner owns, naming the reason.
//
// Matched on the setting KEY as well as on its declared flag, because a caller editing over MCP will
// reasonably have stored "-silent": true rather than a camelCase key.
func wildcardSettingsMinusOwned(tool WildcardTool, settings map[string]any) (map[string]any, []string) {
	safe := make(map[string]any, len(settings))
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var notes []string
	for _, key := range keys {
		if why, owned := tool.OwnedFlags[key]; owned {
			notes = append(notes, "Stored setting "+key+" was NOT applied: "+why)
			continue
		}
		if meta, known := tool.Options[key]; known && meta.Flag != "" {
			if why, owned := tool.OwnedFlags[meta.Flag]; owned {
				notes = append(notes, "Stored setting "+key+" ("+meta.Flag+") was NOT applied: "+why)
				continue
			}
		}
		safe[key] = settings[key]
	}
	return safe, notes
}

// wildcardGovernedFlags is the set of flags the settings now decide, mapped to whether the flag
// takes a following value. A hardcoded occurrence of one of these is stripped from the base command.
//
// A bool is governed whether it is true or FALSE, which is the whole point: withNumbers=false has to
// remove the runner's hardcoded --with-numbers, and it composes no argument of its own.
//
// An INERT setting is deliberately not governed. BuildWildcardArgs refuses to compose it and warns,
// so stripping the runner's hardcoded value would leave the flag off the command line entirely and
// silently change behaviour on the strength of a setting that was reported as having no effect.
func wildcardGovernedFlags(tool WildcardTool, settings map[string]any) map[string]bool {
	governed := map[string]bool{}
	inert := WildcardInertOptions(tool, settings)
	for key, value := range settings {
		meta, known := tool.Options[key]
		if !known || meta.Flag == "" {
			continue
		}
		if _, isInert := inert[key]; isInert {
			continue
		}
		if meta.Kind == "bool" {
			governed[meta.Flag] = false
			continue
		}
		if !wildcardValueComposes(meta, value) {
			continue
		}
		governed[meta.Flag] = true
	}
	return governed
}

// wildcardValueComposes mirrors BuildWildcardArgs' emptiness rules, so a flag is only treated as
// governed when the stored value actually produces an argument. An empty string is a stored value
// that composes nothing, and stripping the runner's hardcoded value for it would turn "I cleared
// this field" into "I removed the framework's default", which is not what clearing a field means.
func wildcardValueComposes(meta WildcardOptionMeta, value any) bool {
	if meta.Kind == "list" {
		items, ok := listSetting(value)
		return ok && len(items) > 0
	}
	return strings.TrimSpace(stringifySetting(value)) != ""
}

// wildcardStripGovernedFlags removes each governed flag, and its value where it takes one, from a
// command line. Returns the input untouched when nothing is governed, so the no-settings path can
// never differ by so much as a slice reallocation.
func wildcardStripGovernedFlags(base []string, governed map[string]bool) []string {
	if len(governed) == 0 {
		return base
	}
	out := make([]string, 0, len(base))
	for i := 0; i < len(base); i++ {
		takesValue, isGoverned := governed[base[i]]
		if !isGoverned {
			out = append(out, base[i])
			continue
		}
		if takesValue && i+1 < len(base) {
			i++
		}
	}
	return out
}

// wildcardSanitiseSettings holds the per-tool corrections for values that are accepted by the tool
// and measured to destroy the scan.
//
// This is deliberately NOT in BuildWildcardArgs. That function is the shared, pure composer both the
// UI preview and the MCP reference render from; a correction applied there would change what every
// surface claims. Applied here, the correction is visible in the notes that are stored on the scan
// row alongside the command that was really run.
func wildcardSanitiseSettings(toolKey string, settings map[string]any) (map[string]any, []string) {
	switch toolKey {
	case "gau":
		return gauSanitisedSettings(settings)
	}
	// ctl, shuffledns and CeWL need no correction. CeWL's one non-composable option, excludePaths, is
	// handled by its runner rather than dropped here: CeWL's --exclude takes a FILE of paths, so the
	// runner writes the operator's list into the container and passes that path.
	return settings, nil
}

// gauSanitisedSettings corrects the two measured ways a stored gau value silently zeroes a scan.
func gauSanitisedSettings(settings map[string]any) (map[string]any, []string) {
	if len(settings) == 0 {
		return settings, nil
	}
	out := make(map[string]any, len(settings))
	for k, v := range settings {
		out[k] = v
	}
	var notes []string

	// MEASURED: --blacklist is a complete no-op unless the extensions are dot-prefixed. A baseline of
	// 177 URLs with 69 matching png/jpg/css/js kept all 69 for `--blacklist png,jpg,css,js`, and only
	// `--blacklist .png,.js` removed anything. --help's wording ("list of extensions to skip") invites
	// the broken form, so the dot is added here rather than shipped as a filter that does nothing.
	if raw, ok := out["blacklistExtensions"]; ok {
		if items, valid := listSetting(raw); valid && len(items) > 0 {
			fixed := make([]string, 0, len(items))
			changed := false
			for _, item := range items {
				ext := strings.TrimSpace(item)
				if ext == "" {
					continue
				}
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
					changed = true
				}
				fixed = append(fixed, ext)
			}
			if len(fixed) > 0 {
				out["blacklistExtensions"] = fixed
			}
			if changed {
				notes = append(notes, "blacklistExtensions was dot-prefixed before use ("+
					strings.Join(fixed, ",")+"). Measured: gau 2.2.4 ignores --blacklist values without a "+
					"leading dot entirely, so the stored form would have filtered nothing while looking applied.")
			}
		}
	}

	// MEASURED: the MATCH filters are single-value only in 2.2.4 while the DROP filters are not.
	// `--mc 200,301,302` and `--mt text/css,image/png` both return ZERO lines with exit 0, reproduced
	// twice and three times respectively. Dropping the filter yields MORE data than was asked for,
	// which is recoverable; applying it yields an empty scan stored as a success, which is not.
	for _, key := range []string{"matchStatusCode", "matchMimeType"} {
		raw, ok := out[key]
		if !ok {
			continue
		}
		if strings.Contains(stringifySetting(raw), ",") {
			delete(out, key)
			notes = append(notes, key+" was NOT applied because it holds more than one value. Measured: "+
				"gau 2.2.4's match filters accept a single value only, and a multi-value one returns ZERO "+
				"URLs with exit 0, which would be stored as a clean scan. The scan ran unfiltered instead.")
		}
	}

	return out, notes
}

// wildcardAnnotatedStderr prefixes the notes onto the stderr a runner stores.
//
// stderr is where an operator looks after a scan behaved unexpectedly, and it is already stored on
// every one of these scan rows. Returns the input unchanged when there are no notes, so a scan with
// no stored settings writes exactly the bytes it wrote before.
func wildcardAnnotatedStderr(stderr string, notes []string) string {
	if len(notes) == 0 {
		return stderr
	}
	var b strings.Builder
	for _, note := range notes {
		b.WriteString("[wildcard config] ")
		b.WriteString(note)
		b.WriteString("\n")
	}
	b.WriteString(stderr)
	return b.String()
}

// wildcardSettingInt reads an int setting, returning the fallback when it is absent or not a number.
// The save endpoint has already range-checked anything that got this far; this is only about a value
// stored before the vocabulary tightened, or written straight into the table.
func wildcardSettingInt(settings map[string]any, key string, fallback int) int {
	raw, ok := settings[key]
	if !ok {
		return fallback
	}
	n, ok := numericSetting(raw)
	if !ok {
		return fallback
	}
	return int(n)
}

// wildcardSettingString reads a trimmed string setting, or the fallback when absent or empty.
func wildcardSettingString(settings map[string]any, key, fallback string) string {
	raw, ok := settings[key]
	if !ok {
		return fallback
	}
	s := strings.TrimSpace(stringifySetting(raw))
	if s == "" {
		return fallback
	}
	return s
}

// wildcardSettingBool reads a bool setting, or the fallback when absent. The fallback matters:
// includeApexDomain defaults ON, so "absent" and "false" are different answers.
func wildcardSettingBool(settings map[string]any, key string, fallback bool) bool {
	raw, ok := settings[key]
	if !ok {
		return fallback
	}
	return truthySetting(raw)
}

// wildcardSettingSeconds reads an int setting as a duration in seconds.
func wildcardSettingSeconds(settings map[string]any, key string, fallback time.Duration) time.Duration {
	raw, ok := settings[key]
	if !ok {
		return fallback
	}
	n, ok := numericSetting(raw)
	if !ok || n < 0 {
		return fallback
	}
	return time.Duration(n) * time.Second
}

// ---------------------------------------------------------------------------------------------
// ctl
// ---------------------------------------------------------------------------------------------

// ctlRunConfig is what wiring CTL means, because CTL HAS NO COMMAND LINE.
//
// Every other tool in this workflow is a binary and its configuration is a list of arguments. CTL is
// first-party Go making at most two HTTP requests, and each of its vocabulary entries was a hardcoded
// literal in the runner. There is nothing for BuildWildcardArgs to compose, so "wire the runner"
// here means "give the runner a config struct and read the store into it". The registry entries
// carry no Flag for exactly this reason, and BuildWildcardArgs correctly emits nothing for them.
//
// EVERY DEFAULT BELOW IS THE VALUE THE CODE USED BEFORE THIS EXISTED. With no stored settings the
// requests, the headers, the timeouts and the stored scan row are unchanged.
type ctlRunConfig struct {
	sourceMode          string
	certspotterAPIKey   string
	retries             int
	retryBackoff        time.Duration
	crtShTimeout        time.Duration
	certspotterTimeout  time.Duration
	crtShUserAgent      string
	crtShExcludeExpired bool
	crtShDeduplicate    bool
	failOnZeroResults   bool
	minResultsWarn      int
	maxResults          int
	includeApex         bool

	// configured is false when nothing was stored, and is what keeps the no-settings path from
	// writing so much as an extra byte onto the scan row.
	configured bool
}

// ctlDefaultUserAgent is the string the runner hardcoded. crt.sh deprioritises Go's default
// User-Agent, which is why a browser UA is presented at all.
const ctlDefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func ctlDefaultRunConfig() ctlRunConfig {
	return ctlRunConfig{
		sourceMode:         "crtsh_then_certspotter",
		retries:            0,
		retryBackoff:       0,
		crtShTimeout:       45 * time.Second,
		certspotterTimeout: 30 * time.Second,
		crtShUserAgent:     ctlDefaultUserAgent,
		includeApex:        true,
		maxResults:         0,
		minResultsWarn:     0,
	}
}

// ctlRunConfigFrom turns stored settings into a run configuration, plus the notes worth recording on
// the scan row.
//
// Pure, so the no-change-by-default guarantee is provable without a database or a network.
func ctlRunConfigFrom(settings map[string]any) (ctlRunConfig, []string) {
	cfg := ctlDefaultRunConfig()
	if len(settings) == 0 {
		return cfg, nil
	}

	tool, ok := WildcardToolByKey("ctl")
	var notes []string
	if ok {
		var ownedNotes []string
		settings, ownedNotes = wildcardSettingsMinusOwned(tool, settings)
		notes = append(notes, ownedNotes...)
	}
	if len(settings) == 0 {
		return cfg, notes
	}
	cfg.configured = true

	mode := wildcardSettingString(settings, "sourceMode", cfg.sourceMode)
	switch mode {
	case "crtsh_then_certspotter", "crtsh_only", "certspotter_only", "union_both":
		cfg.sourceMode = mode
	default:
		notes = append(notes, "sourceMode "+mode+" is not a value this runner knows, so the default "+
			"crtsh_then_certspotter was used.")
	}

	cfg.certspotterAPIKey = wildcardSettingString(settings, "certspotterApiKey", "")
	cfg.retries = wildcardSettingInt(settings, "retries", cfg.retries)
	if cfg.retries < 0 {
		cfg.retries = 0
	}
	cfg.retryBackoff = wildcardSettingSeconds(settings, "retryBackoffSeconds", cfg.retryBackoff)
	cfg.crtShTimeout = wildcardSettingSeconds(settings, "crtShTimeoutSeconds", cfg.crtShTimeout)
	cfg.certspotterTimeout = wildcardSettingSeconds(settings, "certspotterTimeoutSeconds", cfg.certspotterTimeout)
	cfg.crtShUserAgent = wildcardSettingString(settings, "crtShUserAgent", cfg.crtShUserAgent)
	cfg.crtShExcludeExpired = wildcardSettingBool(settings, "crtShExcludeExpired", false)
	cfg.crtShDeduplicate = wildcardSettingBool(settings, "crtShDeduplicate", false)
	cfg.failOnZeroResults = wildcardSettingBool(settings, "failOnZeroResults", false)
	cfg.minResultsWarn = wildcardSettingInt(settings, "minResultsWarnThreshold", 0)
	cfg.maxResults = wildcardSettingInt(settings, "maxResults", 0)
	// includeApexDomain defaults ON, so absent and false are different answers and the fallback has
	// to be true rather than the zero value.
	cfg.includeApex = wildcardSettingBool(settings, "includeApexDomain", true)

	// UNVERIFIED AND SAID SO ON EVERY SCAN THAT USES THEM. crt.sh returned HTTP 502 to all seven
	// probes during the research window, so neither parameter could be confirmed as supported. A
	// parameter crt.sh IGNORES is a filter the operator believes applied; one it REJECTS demotes the
	// scan to the certspotter fallback, which is roughly a 95% data loss. The full request URL is
	// recorded on the scan row so the outcome is at least diagnosable after the fact.
	if cfg.crtShExcludeExpired {
		notes = append(notes, "crtShExcludeExpired sent &exclude=expired to crt.sh. This parameter is "+
			"UNVERIFIED: crt.sh was unreachable when the vocabulary was measured. If crt.sh ignores it "+
			"nothing was filtered; if crt.sh rejects it this scan fell back to certspotter, which returns "+
			"a small fraction of the data. Check the recorded request URL and the source on this row.")
	}
	if cfg.crtShDeduplicate {
		notes = append(notes, "crtShDeduplicate sent &deduplicate=Y to crt.sh. Same UNVERIFIED caveat as "+
			"crtShExcludeExpired; the runner already deduplicates client-side, so this changes response "+
			"size at best.")
	}

	return cfg, notes
}

// ctlCrtShQuery builds the crt.sh request URL. q and output are runner owned: the `%.` prefix is what
// makes this a subdomain search rather than an exact-name lookup, and output=json is what the decoder
// depends on. Only the two optional parameters below are the operator's.
func ctlCrtShQuery(domain string, cfg ctlRunConfig) string {
	q := "https://crt.sh/?q=%." + domain + "&output=json"
	if cfg.crtShExcludeExpired {
		q += "&exclude=expired"
	}
	if cfg.crtShDeduplicate {
		q += "&deduplicate=Y"
	}
	return q
}

// ctlFetchWithRetries runs a CT source, retrying on error.
//
// With the default retries of 0 this makes exactly one attempt, which is what the code did before.
// Retries exist because a crt.sh 502 is frequently transient and comes back in half a second, and
// the cost of not retrying is the certspotter fallback: measured at 17 issuances and 9 unique names
// for hackerone.com where crt.sh returns hundreds.
func ctlFetchWithRetries(cfg ctlRunConfig, fetch func() ([]string, error)) ([]string, error) {
	attempts := cfg.retries + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 && cfg.retryBackoff > 0 {
			// Backoff is not optional politeness. crt.sh is chronically overloaded, and retrying a 502
			// with no gap is adding to the outage that caused it.
			time.Sleep(cfg.retryBackoff)
		}
		subs, err := fetch()
		if err == nil {
			return subs, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ctlApplyResultPolicy applies the apex filter and the result cap, in that order, and reports what it
// did. Truncation is REPORTED rather than silent: a capped result that looks complete is the same
// defect class as a zero-result scan stored as a success.
func ctlApplyResultPolicy(subdomains []string, domain string, cfg ctlRunConfig) ([]string, []string) {
	var notes []string
	out := subdomains

	if !cfg.includeApex {
		filtered := make([]string, 0, len(out))
		for _, sub := range out {
			if sub == domain {
				continue
			}
			filtered = append(filtered, sub)
		}
		if len(filtered) != len(out) {
			notes = append(notes, "includeApexDomain is off, so the apex "+domain+" was removed from the results.")
		}
		out = filtered
	}

	if cfg.maxResults > 0 && len(out) > cfg.maxResults {
		notes = append(notes, "maxResults truncated this scan from "+strconv.Itoa(len(out))+" to "+
			strconv.Itoa(cfg.maxResults)+" subdomains. THIS RESULT IS INCOMPLETE.")
		out = out[:cfg.maxResults]
	}

	return out, notes
}

// The four runners this change wired now read wildcard_tool_settings, so the API must stop telling
// callers that they do not.
//
// GetWildcardSettings and SaveWildcardSettings attach a pending_wiring note to every tool whose
// RunnerReads is false, saying the next scan will use the hardcoded command line. For these four
// that sentence is now FALSE, and a settings API that lies about whether a setting takes effect is
// the same defect in the opposite direction. The flag is flipped here rather than in the registry
// declaration because wildcardOptions.go is owned by the vocabulary, not by the wiring, and because
// this keeps the claim next to the code that makes it true: delete the wiring and this line stops
// compiling against anything meaningful.
//
// init runs after wildcardOptions.go's own init (Go initialises a package's files in sorted filename
// order, and wildcardOptions.go sorts before wildcardWiring...), so the registry is populated by the
// time this runs. The loop is written to be a no-op rather than a panic if that ever stops holding.
func init() {
	markWildcardRunnerWired("gau", "ctl", "shuffledns", "cewl")
}
