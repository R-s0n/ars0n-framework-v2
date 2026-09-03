package utils

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Making a stored Wildcard setting actually change the scan.
//
// wildcardTools.go / wildcardOptions.go / wildcardSettings.go gave the workflow ONE option
// vocabulary and ONE store that the Settings screen and the MCP tool both edit. What they did not
// give it was a runner that reads any of it. An operator could open the config screen, set a rate
// limit, save it successfully, run a scan and get the old behaviour, with nothing anywhere saying
// so. A control that reports success and does nothing is the same defect class this project keeps
// finding inside its scanners, and it is worse than having no control at all.
//
// This file is the bridge, and it is deliberately NOT a second composer. BuildWildcardArgs is the
// one place settings become arguments; it is pure, deterministic and covered by tests. What is
// missing between "composed arguments" and "a command line" is three mechanical problems that every
// runner in this workflow has, and solving them once here is the difference between wiring four
// runners and writing four subtly different bugs:
//
//  1. THE RUNNERS ALREADY PASS THESE FLAGS. gospider hardcodes -c 10 -d 3 -t 3 -k 1 -K 2 -m 30 and
//     six switches; nuclei always emits -c -rl -timeout -retries -bs -mhe whether or not anything is
//     stored. Blindly appending the composed arguments would produce `-c 10 ... -c 20`. Both tools
//     take the last value (verified against the installed images: gospider accepts duplicate flags
//     with RC 0, and nuclei parsed `-rl 150 -rl 5 -c 25 -c 3` and failed only on the missing targets
//     file), so appending would WORK, and would still be wrong: the command stored on the scan row
//     is the thing the whole diagnostic layer exists to answer "what did this actually run" with,
//     and a command line that contains a flag twice with different values answers it ambiguously.
//     So a configured flag REPLACES the runner's copy in place, and only genuinely new flags are
//     appended.
//
//  2. A BOOL WHOSE TOOL DEFAULT IS TRUE CANNOT BE TURNED OFF BY OMITTING IT. BuildWildcardArgs emits
//     the flag when the value is true and nothing when it is false, which is right for a flag that
//     defaults off and useless for gospider's --js and --robots, which default to TRUE inside the
//     tool. The URL workflow shipped exactly that bug and documents the fix at
//     urlScanUtils.go:2735-2740: only `--js=false` disables it. Without the negation below a switch
//     does nothing in either position while the UI shows it as off, which is the phantom control
//     this whole exercise exists to remove.
//
//  3. AN OWNED FLAG MUST NEVER REACH THE COMMAND LINE. The save endpoint refuses one, but a value
//     stored before a flag became owned is still sitting in the jsonb column, so this is the second
//     line of defence rather than a duplicate of the first.
//
// THE DEFAULT IS SACRED. With no stored settings every function here returns its input untouched,
// so the command line is byte-identical to what it was before this file existed. There is a test per
// runner that pins the exact argument vector for that case.
type wildcardOverlay struct {
	tool     WildcardTool
	settings map[string]any

	// baseArity is the arity of the flags the RUNNER hardcodes: 0 for a switch, 1 for a flag that
	// takes a value. It is what lets the walk tell `-c 10` apart from a bare `-a`, so a VALUE is
	// never mistaken for a flag and displaced.
	baseArity map[string]int

	// negate maps an option's flag to the token that explicitly turns it OFF, for the tools whose
	// own default is on. Empty means "off is expressed by the flag being absent", which is the
	// normal case.
	negate map[string]string

	// skip names option KEYS the runner resolves itself, because their meaning is not "put this flag
	// on the command line". subdomainizer's verifyTls is the inverse of its flag; its three collect
	// switches decide a runner-owned output PATH; gospider's userAgent has to win or lose against a
	// global setting rather than simply be appended. Skipped keys are removed before composing so
	// BuildWildcardArgs never sees them, and the runner then does the right thing explicitly.
	skip map[string]bool
}

// apply returns the final argument vector and the human-readable notes about anything that was
// dropped, displaced or negated on the way there.
//
// The notes are not decoration. Every one of them describes a case where what the operator stored
// and what the scan ran are not the same thing, and that difference has to be visible on the scan
// record or the settings screen is back to being something you take on trust.
func (o wildcardOverlay) apply(base []string) ([]string, []string) {
	if len(o.settings) == 0 {
		return base, nil
	}

	effective := map[string]any{}
	for key, value := range o.settings {
		if o.skip[key] {
			continue
		}
		effective[key] = value
	}

	composed, notes := BuildWildcardArgs(o.tool, effective)
	composed, ownedNotes := o.dropOwnedFlags(composed)
	notes = append(notes, ownedNotes...)

	arity := o.mergedArity()
	order, byFlag := groupWildcardArgs(composed, arity)

	out := make([]string, 0, len(base)+len(composed))
	placed := map[string]bool{}
	i := 0
	for i < len(base) {
		token := base[i]
		width := 1
		if n, known := o.baseArity[token]; known {
			width += n
		}
		if width > len(base)-i {
			width = len(base) - i
		}
		if seq, override := byFlag[token]; override {
			if !placed[token] {
				if !sameWildcardArgs(seq, base[i:i+width]) {
					notes = append(notes, fmt.Sprintf(
						"%s was already on the command line as %q; the stored setting replaced it in place with %q.",
						token, strings.Join(base[i:i+width], " "), strings.Join(seq, " ")))
				}
				out = append(out, seq...)
				placed[token] = true
			} else {
				// A repeatable flag the runner emitted more than once. The stored setting replaces the
				// whole set rather than adding to it, because these options declare shadowed_by against
				// the store the runner's copies came from, and one flag with two sources is exactly the
				// disagreement this registry exists to prevent.
				notes = append(notes, fmt.Sprintf(
					"A further runner-supplied %s %q was dropped: the stored setting replaces every occurrence of "+
						"that flag, not just the first.", token, strings.Join(base[i+1:i+width], " ")))
			}
			i += width
			continue
		}
		out = append(out, base[i:i+width]...)
		i += width
	}
	for _, flag := range order {
		if placed[flag] {
			continue
		}
		out = append(out, byFlag[flag]...)
		placed[flag] = true
	}

	out, negationNotes := o.applyNegations(out, arity)
	notes = append(notes, negationNotes...)
	return out, notes
}

// dropOwnedFlags is the second line of defence described at the top of this file.
//
// The save endpoint refuses a setting that names a runner-owned flag, so in a healthy database this
// removes nothing. It exists for the row that was written BEFORE a flag became owned, which would
// otherwise reach the command line and displace something the runner depends on: nuclei's -o and
// -jsonl decide whether any finding is parseable at all, and gospider's --json decides whether the
// stdout parser sees anything it recognises.
func (o wildcardOverlay) dropOwnedFlags(composed []string) ([]string, []string) {
	if len(o.tool.OwnedFlags) == 0 {
		return composed, nil
	}
	arity := o.mergedArity()
	var out, notes []string
	for i := 0; i < len(composed); {
		token := composed[i]
		width := 1
		if n, known := arity[token]; known {
			width += n
		}
		if width > len(composed)-i {
			width = len(composed) - i
		}
		if why, owned := o.tool.OwnedFlags[token]; owned {
			notes = append(notes, fmt.Sprintf(
				"%s was dropped before it reached the command line: it is set by the framework (%s). "+
					"A setting naming it is refused on save, so this row predates that rule.", token, why))
			i += width
			continue
		}
		out = append(out, composed[i:i+width]...)
		i += width
	}
	return out, notes
}

// applyNegations turns an explicitly stored false into something the tool will actually obey.
//
// Three cases, and getting them confused is how a switch comes to do nothing in either position:
//
//   - the flag is on the command line and the tool's own default is ON  -> replace it with the
//     negated form (`--js` becomes `--js=false`), because removing it would leave the tool default,
//     which is on;
//   - the flag is on the command line and the tool's own default is OFF -> remove it;
//   - the flag is absent and the tool's own default is ON               -> append the negated form.
func (o wildcardOverlay) applyNegations(args []string, arity map[string]int) ([]string, []string) {
	keys := make([]string, 0, len(o.settings))
	for key := range o.settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	inert := WildcardInertOptions(o.tool, o.settings)

	var notes []string
	for _, key := range keys {
		if o.skip[key] {
			continue
		}
		meta, known := o.tool.Options[key]
		if !known || meta.Kind != "bool" || meta.Flag == "" {
			continue
		}
		if value, ok := o.settings[key].(bool); !ok || value {
			continue
		}
		if _, dead := inert[key]; dead {
			continue
		}
		negated := o.negate[meta.Flag]
		at := wildcardFlagIndex(args, arity, meta.Flag)
		switch {
		case at >= 0 && negated != "":
			args[at] = negated
			notes = append(notes, fmt.Sprintf(
				"%s is on by default inside the tool, so turning %s off had to be sent as %s rather than by "+
					"leaving the flag out.", meta.Flag, key, negated))
		case at >= 0:
			args = append(args[:at], args[at+1:]...)
			notes = append(notes, fmt.Sprintf("%s was removed because %s is off.", meta.Flag, key))
		case negated != "":
			args = append(args, negated)
			notes = append(notes, fmt.Sprintf(
				"%s is on by default inside the tool even though the runner does not pass it, so turning %s "+
					"off had to be sent as %s.", meta.Flag, key, negated))
		}
	}
	return args, notes
}

// mergedArity is the runner's own flags plus the vocabulary's, so a walk over a partially composed
// command line can tell a flag from the value that follows it.
func (o wildcardOverlay) mergedArity() map[string]int {
	arity := map[string]int{}
	for flag, n := range o.baseArity {
		arity[flag] = n
	}
	for _, meta := range o.tool.Options {
		if meta.Flag == "" {
			continue
		}
		if meta.Kind == "bool" {
			arity[meta.Flag] = 0
			continue
		}
		arity[meta.Flag] = 1
	}
	return arity
}

// groupWildcardArgs splits a composed argument vector back into one entry per flag, preserving the
// order BuildWildcardArgs produced and keeping a repeatable flag's occurrences together.
//
// This is a PARSE, not a second compose: every flag it sees came out of BuildWildcardArgs, so the
// arity is always known and there is no guessing.
func groupWildcardArgs(composed []string, arity map[string]int) ([]string, map[string][]string) {
	var order []string
	byFlag := map[string][]string{}
	for i := 0; i < len(composed); {
		flag := composed[i]
		width := 1
		if n, known := arity[flag]; known {
			width += n
		}
		if width > len(composed)-i {
			width = len(composed) - i
		}
		if _, seen := byFlag[flag]; !seen {
			order = append(order, flag)
		}
		byFlag[flag] = append(byFlag[flag], composed[i:i+width]...)
		i += width
	}
	return order, byFlag
}

func sameWildcardArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// wildcardFlagIndex finds a flag at a FLAG position, so a value that happens to spell a flag is
// never mistaken for one. Returns -1 when it is not there.
func wildcardFlagIndex(args []string, arity map[string]int, flag string) int {
	for i := 0; i < len(args); {
		width := 1
		if n, known := arity[args[i]]; known {
			width += n
		}
		if args[i] == flag {
			return i
		}
		i += width
	}
	return -1
}

// wildcardRunnerSettings loads one tool's stored settings for a scope target, for a runner that is
// about to build a command line.
//
// Every failure returns an EMPTY map rather than an error, and that is deliberate: a target that has
// never been configured, a database hiccup and an unknown tool key must all produce the tool's own
// default behaviour, because the alternative is a scan that refuses to run over a settings problem.
// The one thing that must never happen is a PARTIAL application, which is why the map is all or
// nothing.
func wildcardRunnerSettings(scopeTargetID, toolKey string) (WildcardTool, map[string]any) {
	tool, ok := WildcardToolByKey(toolKey)
	if !ok {
		return WildcardTool{}, map[string]any{}
	}
	if strings.TrimSpace(scopeTargetID) == "" || dbPool == nil {
		return tool, map[string]any{}
	}
	settings := loadWildcardSettings(context.Background(), scopeTargetID, toolKey)
	if settings == nil {
		settings = map[string]any{}
	}
	return tool, settings
}

// wildcardSettingsPreamble is the block a runner writes at the top of its stored stdout when, and
// only when, settings were applied.
//
// "What did this actually run" is answered by the stored command. This answers the next question,
// "and why is it different from the default", on the scan record itself rather than in a log file
// that has already rotated. It returns the empty string when nothing was configured, so a default
// scan's stored output is unchanged down to the byte.
func wildcardSettingsPreamble(tool WildcardTool, scopeTargetID string, settings map[string]any, notes []string) string {
	if len(settings) == 0 {
		return ""
	}
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var b strings.Builder
	fmt.Fprintf(&b, "=== Wildcard settings applied to %s ===\n", tool.Name)
	fmt.Fprintf(&b, "Source: wildcard_tool_settings for scope target %s, the same store the Settings screen and the "+
		"MCP wildcard tool both write. With nothing stored this command line is unchanged.\n", scopeTargetID)
	for _, key := range keys {
		fmt.Fprintf(&b, "  %s = %v\n", key, settings[key])
	}
	if inert := WildcardInertOptions(tool, settings); len(inert) > 0 {
		inertKeys := make([]string, 0, len(inert))
		for key := range inert {
			inertKeys = append(inertKeys, key)
		}
		sort.Strings(inertKeys)
		b.WriteString("Stored but unable to take effect:\n")
		for _, key := range inertKeys {
			fmt.Fprintf(&b, "  - %s\n", inert[key])
		}
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

// wildcardRunnerOverlay.go wires these four, so it claims these four. See markWildcardRunnerWired.
func init() {
	markWildcardRunnerWired("gospider", "subdomainizer", "nuclei", "nuclei-screenshot")
}
