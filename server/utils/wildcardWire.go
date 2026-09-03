package utils

import (
	"context"
	"database/sql"
	"log"
	"sort"
	"strconv"
	"strings"
)

// Making the Wildcard workflow's stored settings REAL for the subdomain-discovery runners.
//
// wildcard_tool_settings, the option vocabulary and the two editors (Settings screen and MCP tool)
// all existed before this file. What did not exist was anything that READ them: every runner still
// executed its hardcoded command line, so an operator could open the config screen, set a rate
// limit, save it successfully, run a scan, and get the old behaviour with nothing anywhere saying
// so. A control that reports success and does nothing is worse than no control at all, and it is the
// same defect class this project keeps finding inside its scanners.
//
// THREE RULES SHAPE EVERYTHING BELOW.
//
//  1. THE DEFAULT MUST NOT CHANGE. With no stored settings for a scope target these builders return
//     the runner's existing argv, token for token. wildcardWireCompose returns immediately on an
//     empty settings map for exactly that reason, and there is a test per tool asserting the
//     no-settings argv against the literal command the runner used to build inline.
//
//  2. A SETTING THAT NAMES A FLAG THE RUNNER OWNS NEVER REACHES THE COMMAND LINE. The save endpoint
//     already refuses those, but a value stored BEFORE a flag became owned would still be sitting in
//     the database, and the only place that can catch it is here. Same for a key the vocabulary no
//     longer contains and a value a tightened range would now reject: all three are dropped with a
//     note rather than composed.
//
//  3. AN OVERRIDE REPLACES, IT DOES NOT DUPLICATE. Appending blindly would be the obvious
//     implementation and it is wrong in both directions. `-timeout 60 ... -timeout 30` relies on
//     amass's flag package preferring the last occurrence, which nobody measured; and worse, an
//     operator turning activeMode OFF composes to NOTHING, so the runner's hardcoded -active would
//     survive and the switch would silently do nothing. That is the exact failure this whole change
//     exists to remove. So a stored setting also SUPERSEDES its flag in the base argv, which is
//     stripped before the composed arguments are appended.
//
// The composition itself is BuildWildcardArgs in wildcardTools.go. There is deliberately no second
// composer here: this file decides only what is safe to compose and what the base argv must give up.

// wildcardWireCompose turns one tool's stored settings into the arguments to APPEND and the base
// flags those settings SUPERSEDE.
//
// Pure: no database, no clock, no environment. Deterministic, because BuildWildcardArgs sorts by
// option key and the supersede set is a set.
//
// The returned notes are the things a caller must be told rather than have silently applied: a
// dropped key, a value the vocabulary would no longer accept, a setting that is inert given the rest
// of the settings. Runners log them against the scan.
func wildcardWireCompose(toolKey string, stored map[string]any) (extra []string, supersede map[string]bool, notes []string) {
	// The no-settings fast path IS the guarantee that today's scans are unchanged. Everything below
	// this line can only run because somebody deliberately configured something.
	if len(stored) == 0 {
		return nil, nil, nil
	}

	tool, ok := WildcardToolByKey(toolKey)
	if !ok {
		return nil, nil, []string{"No Wildcard workflow tool called " + toolKey +
			", so its stored settings were ignored and the hardcoded command line was used."}
	}

	// The second line of defence. The save endpoint refuses all three of these, so a row that
	// contains one was written before the vocabulary said so. Dropping it silently would recreate the
	// problem this file fixes, one layer down, so each drop carries its reason.
	safe := make(map[string]any, len(stored))
	for key, value := range stored {
		if why, owned := tool.OwnedFlags[key]; owned {
			notes = append(notes, key+" was NOT put on the command line: the framework sets it. "+why)
			continue
		}
		meta, known := tool.Options[key]
		if !known {
			notes = append(notes, "Nothing reads "+key+" for "+tool.Name+" any more, so it was NOT put on the "+
				"command line. It was stored before the option vocabulary changed.")
			continue
		}
		if meta.Flag != "" {
			if why, owned := tool.OwnedFlags[meta.Flag]; owned {
				notes = append(notes, key+" was NOT put on the command line: "+meta.Flag+
					" is set by the framework. "+why)
				continue
			}
		}
		if problem := validateWildcardValue(key, meta, value); problem != "" {
			notes = append(notes, key+" was NOT put on the command line, because its stored value is no "+
				"longer acceptable: "+problem)
			continue
		}
		safe[key] = value
	}

	extra, warnings := BuildWildcardArgs(tool, safe)
	notes = append(notes, warnings...)

	// Which base flags this settings map takes ownership of.
	//
	// A BOOL supersedes on PRESENCE, not on truth: the operator storing activeMode:false is an
	// explicit decision that the runner's hardcoded -active must go, and BuildWildcardArgs emits
	// nothing for a false bool, so presence is the only signal there is.
	//
	// Everything else supersedes only when it actually composes to a flag. A stored-but-blank
	// resolvers list must NOT strip the runner's twenty hardcoded resolvers and quietly hand amass
	// back its built-in pool.
	inert := WildcardInertOptions(tool, safe)
	supersede = map[string]bool{}
	for key, value := range safe {
		meta := tool.Options[key]
		if meta.Flag == "" {
			continue
		}
		if _, dead := inert[key]; dead {
			continue
		}
		switch meta.Kind {
		case "bool":
			supersede[meta.Flag] = true
		case "list":
			if items, ok := listSetting(value); ok && len(items) > 0 {
				supersede[meta.Flag] = true
			}
		default:
			if strings.TrimSpace(stringifySetting(value)) != "" {
				supersede[meta.Flag] = true
			}
		}
	}
	if len(supersede) == 0 {
		supersede = nil
	}

	sort.Strings(notes)
	return extra, supersede, notes
}

// wildcardWireApply removes from a runner's base argv every flag a stored setting has taken over,
// together with that flag's value.
//
// Arity comes from the vocabulary rather than from a hand-written list, so a bool loses one token
// and everything else loses two. Every flag in the supersede set came out of tool.Options, so the
// lookup cannot miss.
func wildcardWireApply(toolKey string, base []string, supersede map[string]bool) []string {
	if len(supersede) == 0 {
		return base
	}
	tool, ok := WildcardToolByKey(toolKey)
	if !ok {
		return base
	}

	takesValue := map[string]bool{}
	for _, meta := range tool.Options {
		if meta.Flag == "" {
			continue
		}
		takesValue[meta.Flag] = meta.Kind != "bool"
	}

	out := make([]string, 0, len(base))
	for i := 0; i < len(base); i++ {
		token := base[i]
		if supersede[token] {
			if takesValue[token] && i+1 < len(base) {
				i++ // drop the superseded flag's value with it
			}
			continue
		}
		out = append(out, token)
	}
	return out
}

// wildcardWireStoredSettings loads one tool's stored settings for the scope target a scan belongs
// to, and returns that scope target id so the runner can name it in its logs.
//
// The runners are called with (scanID, domain) and nothing else, so the scope target has to come
// back off the scan row. Every failure here returns an empty map, which means the hardcoded command
// line: a settings lookup that cannot answer must never be able to change a scan.
//
// It LOGS when it cannot answer, because "your configuration was ignored" is the one outcome this
// whole change exists to stop happening in silence. Fail-safe is the right behaviour; fail-silent is
// not.
//
// scanTable is a compile-time constant at every call site. It is never caller-supplied.
func wildcardWireStoredSettings(ctx context.Context, scanTable, scanID, toolKey string) (map[string]any, string) {
	if dbPool == nil {
		return nil, ""
	}
	var scopeTargetID sql.NullString
	err := dbPool.QueryRow(ctx,
		`SELECT scope_target_id::text FROM `+scanTable+` WHERE scan_id = $1`, scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[WARN] Could not read the scope target for %s scan %s from %s (%v), so any stored "+
			"Wildcard configuration for %s was NOT applied and the hardcoded command line was used.",
			toolKey, scanID, scanTable, err, toolKey)
		return nil, ""
	}
	if !scopeTargetID.Valid || scopeTargetID.String == "" {
		log.Printf("[WARN] %s scan %s has no scope target on its row, so any stored Wildcard configuration "+
			"for %s was NOT applied and the hardcoded command line was used.", toolKey, scanID, toolKey)
		return nil, ""
	}
	return loadWildcardSettings(ctx, scopeTargetID.String, toolKey), scopeTargetID.String
}

// ---------------------------------------------------------------------------------------------
// amass  (step 1)
// ---------------------------------------------------------------------------------------------

// amassWildcardResolvers is the twenty-resolver pool the wildcard amass runner has always passed,
// in the order it has always passed it. It is a variable only so the builder and its
// nothing-changed test can refer to the same list; the ORDER is part of the byte-identical
// guarantee and must not be sorted or deduplicated.
var amassWildcardResolvers = []string{
	"8.8.8.8", "1.1.1.1", "9.9.9.9", "64.6.64.6",
	"208.67.222.222", "208.67.220.220", "8.26.56.26", "8.20.247.20",
	"185.228.168.9", "185.228.169.9", "76.76.19.19", "76.223.122.150",
	"198.101.242.72", "176.103.130.130", "176.103.130.131", "94.140.14.14",
	"94.140.15.15", "1.0.0.1", "77.88.8.8", "77.88.8.1",
}

// amassWildcardCommandArgs builds the argv passed to `docker` for a wildcard amass enum.
//
// With no stored settings this is token-for-token the command ExecuteAndParseAmassScan built inline
// before this file existed, including `-min-for-recursive 2` (a deliberate deviation from amass's
// own default of 1 that predates this change) and `-timeout 60`, which is SIXTY MINUTES because
// amass measures -timeout in minutes.
//
// RATE LIMIT PRECEDENCE, DECIDED AND VISIBLE: the per-target resolverQPS wins over the global
// user_settings.amass_rate_limit. The global is what the runner has always passed and it stays the
// value for every target nobody has configured, so the global remains a real, working default rather
// than becoming dead. When a target sets resolverQPS the base -rqps is stripped and the per-target
// value is the only one on the command line, so the two can never both apply and there is nothing
// for the two screens to disagree about.
//
// UNIT TRAP, LEFT INTACT ON PURPOSE: timeoutMinutes composes straight to -timeout because that flag
// really is minutes. Nothing here multiplies or divides it. A value of 300 is five hours, which is
// why the vocabulary spells the unit out and caps it at 1440.
func amassWildcardCommandArgs(domain string, rateLimit int, stored map[string]any) ([]string, []string) {
	enum := []string{
		"enum", "-active", "-alts", "-brute", "-nocolor",
		"-min-for-recursive", "2", "-timeout", "60",
		"-d", domain,
	}
	for _, resolver := range amassWildcardResolvers {
		enum = append(enum, "-r", resolver)
	}
	enum = append(enum, "-rqps", strconv.Itoa(rateLimit))

	extra, supersede, notes := wildcardWireCompose("amass", stored)
	enum = wildcardWireApply("amass", enum, supersede)
	enum = append(enum, extra...)

	return append([]string{"run", "--rm", "caffix/amass"}, enum...), notes
}

// ---------------------------------------------------------------------------------------------
// subfinder  (step 6)
// ---------------------------------------------------------------------------------------------

// subfinderShippedRateLimitDefault is the value user_settings.subfinder_rate_limit is created with
// (settings.go GetRateLimit). It matters because the column is NOT NULL-able-by-absence: there is no
// way to ask it "did a human choose this?", and the answer decides whether it may throttle a scan.
// See subfinderWildcardCommandArgs.
const subfinderShippedRateLimitDefault = 20

// subfinderWildcardCommandArgs builds the argv passed to `docker` for a wildcard subfinder scan.
//
// TWO DELIBERATE CHANGES LIVE HERE AND THEY ARE SEPARATE FROM EACH OTHER.
//
// (1) THE WIRING. With no stored settings this adds nothing and removes nothing: the argv is the
// base below, unchanged. Proven by test.
//
// (2) -silent BECOMES -stats, AND IT IS A DELIBERATE CHANGE TO THE DEFAULT COMMAND LINE, not a side
// effect of the wiring. It is done because it is measured, cheap, and it is the single fix that
// makes this tool's dominant failure mode visible at all:
//
//   - MEASURED: without -silent, subfinder's STDOUT is byte-for-byte what it is today, bare
//     subdomains one per line, and every banner, INF and statistics line goes to STDERR. The stdout
//     parser is therefore untouched. With -silent, stderr is completely EMPTY and -stats is
//     suppressed entirely.
//   - WHY IT MATTERS: `-proxy http://127.0.0.1:9999` with nothing listening returned 0 subdomains
//     with exit 0 and an empty stderr; `-recursive` took a 23362-result domain to exactly zero the
//     same way. Under -silent both are stored as status "completed", stderr "No results found",
//     which is indistinguishable from a domain that genuinely has no subdomains. With -stats the
//     stderr column gets the per-source table (source, duration, results, requests, errors) and the
//     difference is recoverable after the fact.
//
// What this change does NOT do is reclassify anything. A run where every source errored is still
// stored as "completed"; making that an error is a change to a success path and is a separate
// decision for whoever owns that call. The evidence is now on the row for when it is made.
//
// RATE LIMIT PRECEDENCE, DECIDED AND VISIBLE:
//
//	per-target rateLimit  >  user_settings.subfinder_rate_limit  >  nothing
//
// with one guard. user_settings.subfinder_rate_limit is a DEAD column: it is read by
// GetSubfinderRateLimit, surfaced in the Settings UI, and has never had a caller, so subfinder has
// always run unthrottled. Making it live unconditionally would put `-rl 20` on every scan on every
// existing install, silently throttling scans nobody configured, which is precisely the "the default
// must not change" rule. So the global is applied only when it DIFFERS from the value it ships with:
// a stored 20 cannot be evidence of a decision, and any other value can only have been typed by
// somebody. That makes the orphaned setting real for everyone who ever set it, without touching
// anybody who did not. There is no second subfinder rate limit anywhere: this column is the global,
// wildcard_tool_settings.rateLimit is the per-target override, and the override strips the global off
// the command line rather than sitting beside it.
func subfinderWildcardCommandArgs(domain string, globalRateLimit int, stored map[string]any) ([]string, []string) {
	args := []string{
		"exec", "ars0n-framework-v2-subfinder-1",
		"subfinder",
		"-d", domain,
		// Was -silent. See the comment above: same stdout, and stderr becomes a per-source table
		// instead of nothing at all.
		"-stats",
	}

	if _, perTarget := stored["rateLimit"]; !perTarget &&
		globalRateLimit > 0 && globalRateLimit != subfinderShippedRateLimitDefault {
		args = append(args, "-rl", strconv.Itoa(globalRateLimit))
	}

	extra, supersede, notes := wildcardWireCompose("subfinder", stored)
	args = wildcardWireApply("subfinder", args, supersede)
	args = append(args, extra...)

	return args, notes
}

// wildcardWire.go wires amass and subfinder, so it claims those two. See markWildcardRunnerWired for
// why the claim lives beside the wiring rather than in a central list.
func init() {
	markWildcardRunnerWired("amass", "subfinder")
}
