package utils

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Making the Company workflow's stored settings REAL.
//
// company_tool_settings, the option vocabulary and the two editors (the Settings screen and the MCP
// company tool) all existed before this file. What did not exist was anything that READ them: every
// runner executed its hardcoded command line or its hardcoded Go constants, so an operator could
// open the config screen, set a value, save it successfully, run a scan, and get the old behaviour
// with nothing anywhere saying so. A control that reports success and does nothing is the same
// defect class this project keeps finding INSIDE its scanners, and it is worse than having no
// control at all.
//
// FIVE RULES SHAPE EVERY WIRING FILE THAT USES THIS ONE.
//
//  1. THE DEFAULT MUST NOT CHANGE. With no stored settings for a scope target, every builder in
//     every companyWire*.go file returns the runner's existing argv or the runner's existing
//     constants, token for token and value for value. Every function here returns its input
//     untouched on an empty map, and there is a test per runner pinning the no-settings result
//     against the literal the runner used to build inline. Nobody's existing scan changes behaviour
//     because a config screen was added.
//
//  2. THE COMPOSER IS THE WILDCARD COMPOSER. CompanyTool and CompanyOptionMeta are type ALIASES of
//     the Wildcard types (companyTools.go), so BuildWildcardArgs, WildcardInertOptions,
//     validateWildcardValue and the whole wildcardOverlay work on company tools unchanged. A second
//     composer that put a flag on the command line the first one would have withheld is exactly the
//     drift this design exists to prevent, so there is not one.
//
//  3. FOUR THINGS NEVER REACH A SCAN, EVEN THOUGH THE SAVE ENDPOINT ALREADY REFUSES THEM: a setting
//     naming a runner-owned flag, a key the vocabulary no longer contains, a value a tightened range
//     would now reject, and a setting that is inert given the rest of the settings. The save endpoint
//     is the first line of defence and it cannot see a row written BEFORE a rule existed. This is the
//     second, and every drop carries its reason rather than happening in silence.
//
//  4. AN OVERRIDE REPLACES, IT DOES NOT DUPLICATE. Appending would produce `-timeout 120 ... -timeout
//     30` and rely on flag-package ordering nobody measured; worse, a bool turned OFF composes to
//     NOTHING, so the runner's hardcoded flag would survive and the switch would silently do nothing.
//     wildcardOverlay replaces a configured flag in place and appends only genuinely new ones.
//
//  5. THE RUNNER SAYS WHAT IT DID. When settings were applied the runner writes a preamble onto the
//     scan record naming the store, the values and every drop. With nothing configured the preamble
//     is the empty string, so a default scan's stored output is unchanged down to the byte.
//
// WHERE THE WIRING CLAIM LIVES. Each companyWire*.go file calls markCompanyRunnerWired for its own
// tools, in its own init. Never a central list: the Wildcard build kept one inside a single wiring
// file, the other two layers were written without touching it, and six wired tools spent a session
// telling operators their configuration would be ignored while it was being honoured.

// companyOverlay is the Wildcard overlay, under a company name. Same type, not a copy: see rule 2.
type companyOverlay = wildcardOverlay

// companyRunnerSettings loads one tool's stored settings for a scope target and returns only the
// ones that are safe to act on, plus the notes explaining anything that was withheld.
//
// EVERY FAILURE RETURNS AN EMPTY MAP, and that is deliberate. A target that has never been
// configured, a database hiccup, an unknown tool key and a settings row full of values the
// vocabulary has since tightened must all end at the tool's own default behaviour, because the
// alternative is a scan that refuses to run over a settings problem. The one thing that must never
// happen is a PARTIAL application of a value, which is why filtering is per key and each drop is
// named.
func companyRunnerSettings(scopeTargetID, toolKey string) (CompanyTool, map[string]any, []string) {
	tool, ok := CompanyToolByKey(toolKey)
	if !ok {
		return CompanyTool{}, map[string]any{}, []string{
			"No Company workflow tool called " + toolKey + ", so no stored configuration was applied and " +
				"the hardcoded behaviour was used."}
	}
	if strings.TrimSpace(scopeTargetID) == "" || dbPool == nil {
		return tool, map[string]any{}, nil
	}
	stored := loadCompanySettings(context.Background(), scopeTargetID, toolKey)
	if len(stored) == 0 {
		// THE FAST PATH IS THE GUARANTEE. Everything past this line can only run because somebody
		// deliberately configured something.
		return tool, map[string]any{}, nil
	}
	safe, notes := companySafeSettings(tool, stored)
	return tool, safe, notes
}

// companySafeSettings is the filter described by rule 3, as a PURE function so every case is unit
// tested without a database.
//
// Returns the settings a runner may act on and one human sentence per setting it may not.
func companySafeSettings(tool CompanyTool, stored map[string]any) (map[string]any, []string) {
	if len(stored) == 0 {
		return map[string]any{}, nil
	}

	var notes []string
	safe := make(map[string]any, len(stored))

	keys := make([]string, 0, len(stored))
	for key := range stored {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := stored[key]
		if why, owned := tool.OwnedFlags[key]; owned {
			notes = append(notes, key+" was NOT applied: the framework sets it. "+why)
			continue
		}
		meta, known := tool.Options[key]
		if !known {
			notes = append(notes, "Nothing reads "+key+" for "+tool.Name+" any more, so it was NOT applied. "+
				"It was stored before the option vocabulary changed.")
			continue
		}
		if meta.Flag != "" {
			if why, owned := tool.OwnedFlags[meta.Flag]; owned {
				notes = append(notes, key+" was NOT applied: "+meta.Flag+" is set by the framework. "+why)
				continue
			}
		}
		if problem := validateWildcardValue(key, meta, value); problem != "" {
			notes = append(notes, key+" was NOT applied, because its stored value is no longer acceptable: "+problem)
			continue
		}
		safe[key] = value
	}

	// Inertness is computed ONCE against the whole post-validation map and applied in one pass, so a
	// key removed here can never change whether another key is inert. Dropping an inert setting rather
	// than acting on it matters most for the tools with no command line: a backoff read without a
	// retry count, or a Censys requests-per-second read without pagination, would be a value the
	// runner obeys and the operator was told does nothing.
	inert := CompanyInertOptions(tool, safe)
	inertKeys := make([]string, 0, len(inert))
	for key := range inert {
		inertKeys = append(inertKeys, key)
	}
	sort.Strings(inertKeys)
	for _, key := range inertKeys {
		delete(safe, key)
		notes = append(notes, inert[key]+" It was NOT applied.")
	}

	return safe, notes
}

// companyScopeTargetForScan resolves the scope target a scan row belongs to.
//
// Several company runners are called with (scanID, companyName) and nothing else, so the scope
// target has to come off the scan row. Every failure returns the empty string, which means "no
// stored configuration", which means the hardcoded behaviour: a settings lookup that cannot answer
// must never be able to change a scan.
//
// It LOGS when it cannot answer, because "your configuration was ignored" is the one outcome this
// whole change exists to stop happening in silence. Fail-safe is right; fail-silent is not.
//
// scanTable is a compile-time constant at every call site. It is never caller-supplied.
func companyScopeTargetForScan(ctx context.Context, scanTable, scanID, toolKey string) string {
	if dbPool == nil {
		return ""
	}
	var scopeTargetID sql.NullString
	err := dbPool.QueryRow(ctx,
		`SELECT scope_target_id::text FROM `+scanTable+` WHERE scan_id = $1`, scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[WARN] Could not read the scope target for %s scan %s from %s (%v), so any stored Company "+
			"configuration for %s was NOT applied and the hardcoded behaviour was used.",
			toolKey, scanID, scanTable, err, toolKey)
		return ""
	}
	if !scopeTargetID.Valid || scopeTargetID.String == "" {
		log.Printf("[WARN] %s scan %s has no scope target on its row, so any stored Company configuration for "+
			"%s was NOT applied and the hardcoded behaviour was used.", toolKey, scanID, toolKey)
		return ""
	}
	return scopeTargetID.String
}

// companySettingsPreamble is the block a runner writes at the top of its stored output when, and
// only when, settings were applied.
//
// "What did this actually run" is answered by the stored command, for the tools that have one. This
// answers the next question - "and why is it different from the default" - on the scan record
// itself rather than in a log file that has already rotated. It is the ONLY answer available for the
// five company tools that have no command line at all.
//
// Returns the empty string when nothing was configured, so a default scan's stored output is
// unchanged down to the byte.
func companySettingsPreamble(tool CompanyTool, scopeTargetID string, settings map[string]any, notes []string) string {
	if len(settings) == 0 && len(notes) == 0 {
		return ""
	}
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var b strings.Builder
	fmt.Fprintf(&b, "=== Company settings applied to %s ===\n", tool.Name)
	fmt.Fprintf(&b, "Source: %s for scope target %s, the same store the Settings screen and the MCP company "+
		"tool both write. With nothing stored this scan is unchanged.\n",
		companySettingsTable(tool.Key), scopeTargetID)
	for _, key := range keys {
		fmt.Fprintf(&b, "  %s = %v\n", key, settings[key])
	}
	if len(notes) > 0 {
		b.WriteString("Notes:\n")
		for _, note := range notes {
			fmt.Fprintf(&b, "  - %s\n", note)
		}
	}
	b.WriteString("=== end settings ===\n")
	return b.String()
}

// companyLogNotes puts every note on the server log under one prefix, so the reason a scan differs
// from the default is discoverable even for the runners whose stored output is a JSON blob with
// nowhere to put a preamble.
func companyLogNotes(prefix string, notes []string) {
	for _, note := range notes {
		log.Printf("[%s] [INFO] Settings: %s", prefix, note)
	}
}

// ---------------------------------------------------------------------------------------------
// Typed readers for the tools that have NO command line.
//
// Five company tools compose no arguments at all: the on-prem IP/port scanner is Go inside the api
// container, and crt.sh, SecurityTrails, Shodan and Censys are single HTTP requests. Their settings
// are read directly, and every reader below takes the value the RUNNER USES TODAY as its fallback,
// so an absent, malformed or dropped setting is byte-identical to the hardcoded behaviour.
//
// They read the SAFE map, never the raw stored map, so an owned, unknown, invalid or inert value can
// never reach them.
// ---------------------------------------------------------------------------------------------

// companySettingIsSet reports whether a key carries a value that will actually do something, so
// "present but empty" is not mistaken for "configured".
func companySettingIsSet(settings map[string]any, key string) bool {
	value, ok := settings[key]
	if !ok || value == nil {
		return false
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case []any:
		return len(v) > 0
	case []string:
		return len(v) > 0
	}
	return true
}

// companyBoolSetting reads a switch. A stored false is a DECISION and is honoured; only an absent
// key falls back.
func companyBoolSetting(settings map[string]any, key string, fallback bool) bool {
	value, ok := settings[key]
	if !ok || value == nil {
		return fallback
	}
	if b, isBool := value.(bool); isBool {
		return b
	}
	return truthySetting(value)
}

func companyIntSetting(settings map[string]any, key string, fallback int) int {
	value, ok := settings[key]
	if !ok || value == nil {
		return fallback
	}
	n, numeric := numericSetting(value)
	if !numeric {
		return fallback
	}
	return int(n)
}

func companyFloatSetting(settings map[string]any, key string, fallback float64) float64 {
	value, ok := settings[key]
	if !ok || value == nil {
		return fallback
	}
	n, numeric := numericSetting(value)
	if !numeric {
		return fallback
	}
	return n
}

func companyStringSetting(settings map[string]any, key, fallback string) string {
	value, ok := settings[key]
	if !ok || value == nil {
		return fallback
	}
	s := strings.TrimSpace(stringifySetting(value))
	if s == "" {
		// An empty string is NOT a way to clear a setting. Clearing is done by sending null, which the
		// save endpoint deletes the key for. Treating "" as "use nothing" would let a blank field
		// silently remove a User-Agent or a query field the runner depends on.
		return fallback
	}
	return s
}

// companyListSetting returns the stored list, or the fallback when nothing usable is stored.
//
// An EMPTY stored list falls back rather than emptying the scan. Every list on a no-command-line
// company tool was measured to make the tool find nothing while still reporting success when it is
// empty (ip_port_scan's two port lists, shodan's enabledQueries and sourceFields), which is why the
// vocabulary carries MinItems and refuses one on save. This is the same rule one layer down, for a
// row that predates it.
func companyListSetting(settings map[string]any, key string, fallback []string) []string {
	value, ok := settings[key]
	if !ok || value == nil {
		return fallback
	}
	items, listy := listSetting(value)
	if !listy || len(items) == 0 {
		return fallback
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

// companyPortListSetting is companyListSetting for the IP/port scanner's two port lists.
//
// A non-numeric or out-of-range entry is DROPPED rather than allowed through, because this list is a
// plain Go slice inside the scanner and not a command line: a bad entry is not a parse error
// anywhere, it is a port that is silently never dialled. If dropping empties the list the whole
// setting falls back, because an empty host-discovery list records every address as dead and an
// empty web-port list finds nothing, both while the scan still reports success.
func companyPortListSetting(settings map[string]any, key string, fallback []int) ([]int, []string) {
	value, ok := settings[key]
	if !ok || value == nil {
		return fallback, nil
	}
	items, listy := listSetting(value)
	if !listy {
		return fallback, []string{key + " is not a list, so the hardcoded port list was used."}
	}
	var ports []int
	var notes []string
	for _, item := range items {
		n, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || n < 1 || n > 65535 {
			notes = append(notes, key+" entry "+item+" is not a TCP port between 1 and 65535 and was dropped.")
			continue
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return fallback, append(notes, key+" ended up empty, so the hardcoded port list was used. An empty "+
			"list would make the scan report success having probed nothing.")
	}
	return ports, notes
}

// companySecondsSetting reads a whole-second duration.
func companySecondsSetting(settings map[string]any, key string, fallback time.Duration) time.Duration {
	value, ok := settings[key]
	if !ok || value == nil {
		return fallback
	}
	n, numeric := numericSetting(value)
	if !numeric || n <= 0 {
		return fallback
	}
	return time.Duration(n * float64(time.Second))
}

// companyMillisSetting reads a millisecond duration. The IP/port scanner's three timeouts are
// milliseconds in the vocabulary and time.Duration in the ScanConfig, and that conversion is the
// single most likely place for this whole feature to introduce a silent thousand-fold error, so it
// happens in exactly one function.
func companyMillisSetting(settings map[string]any, key string, fallback time.Duration) time.Duration {
	value, ok := settings[key]
	if !ok || value == nil {
		return fallback
	}
	n, numeric := numericSetting(value)
	if !numeric || n <= 0 {
		return fallback
	}
	return time.Duration(n * float64(time.Millisecond))
}

// companySettingsSummary is a stable one-line rendering of what was applied, for a log line.
func companySettingsSummary(settings map[string]any) string {
	if len(settings) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", key, settings[key]))
	}
	return strings.Join(parts, ", ")
}
