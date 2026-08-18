package utils

import (
	"strings"
	"testing"
)

// The typed metadata and the documentation are two views of ONE vocabulary. A key in either and not
// the other is a setting the UI can render but nothing reads, or one nothing can render but a scan
// honours, and both failures are silent.
func TestOptionMetaCoversExactlyTheDocumentedOptions(t *testing.T) {
	for key := range FuzzOptionKeys {
		if _, ok := FuzzOptionMetas[key]; !ok {
			t.Errorf("%s is documented but has no metadata, so no control can be built for it", key)
		}
	}
	for key, meta := range FuzzOptionMetas {
		if _, ok := FuzzOptionKeys[key]; !ok {
			t.Errorf("%s has metadata but is not a documented option, so nothing reads it", key)
		}
		valid := map[string]bool{"int": true, "bool": true, "string": true, "enum": true, "unsupported": true}
		if !valid[meta.Kind] {
			t.Errorf("%s has kind %q, which no control knows how to render", key, meta.Kind)
		}
		if meta.Kind == "enum" && len(meta.Choices) == 0 {
			t.Errorf("%s is an enum with no choices", key)
		}
		inGroups := false
		for _, g := range FuzzOptionGroups {
			if g == meta.Group {
				inGroups = true
			}
		}
		if !inGroups {
			t.Errorf("%s is in group %q, which is not in FuzzOptionGroups so it would not be shown", key, meta.Group)
		}
	}
	// Everything the composer refuses must be visibly refused rather than quietly absent from the form.
	for _, refused := range []string{"extensions", "recursion", "recursionDepth"} {
		if FuzzOptionMetas[refused].Kind != "unsupported" {
			t.Errorf("%s is refused by the composer and must render as unsupported", refused)
		}
	}
}

// A default is what to do absent an instruction. A step that names a value has given one.
func TestStepOptionsWinOverFlowDefaults(t *testing.T) {
	defaults := map[string]any{"threads": float64(5), "filterStatus": "404", "noiseGuard": true}
	step := map[string]any{"threads": float64(40)}

	got := effectiveFuzzOptions(defaults, step)
	if got["threads"] != float64(40) {
		t.Errorf("the step's own threads must win, got %v", got["threads"])
	}
	if got["filterStatus"] != "404" {
		t.Errorf("a default the step did not mention must apply, got %v", got["filterStatus"])
	}
	if got["noiseGuard"] != true {
		t.Errorf("a default the step did not mention must apply, got %v", got["noiseGuard"])
	}

	// Neither input may be modified. The step editor and the preview both show the stored step, so
	// merging into it would make the defaults look like the operator had typed them.
	if _, leaked := step["filterStatus"]; leaked {
		t.Error("merging must not write defaults into the step's own options")
	}
	if len(defaults) != 3 {
		t.Error("merging must not modify the defaults")
	}

	// A flow with no settings leaves the step exactly as it was.
	if bare := effectiveFuzzOptions(map[string]any{}, step); bare["threads"] != float64(40) || len(bare) != 1 {
		t.Errorf("no defaults should mean no change, got %v", bare)
	}
}

// Every option marked unsupported must actually be REFUSED. A setting that renders as impossible but
// saves and runs silently is the same failure as one that is ignored, dressed up.
func TestEveryRefusedOptionIsActuallyRefused(t *testing.T) {
	values := map[string]any{
		"extensions": ".map", "recursion": true, "recursionDepth": float64(2),
		"recursionStrategy": "greedy", "dirsearchMode": true,
		"inputCmd": "seq 1 10", "inputNum": float64(10), "inputShell": "/bin/sh",
	}
	for key, meta := range FuzzOptionMetas {
		if meta.Kind != "unsupported" {
			continue
		}
		v, ok := values[key]
		if !ok {
			t.Errorf("%s renders as unsupported but this test has no value to refuse it with", key)
			continue
		}
		// recursionDepth and inputNum are modifiers: they are refused through the flag they belong to,
		// which the entries above cover, so they only have to emit nothing on their own.
		if key == "recursionDepth" || key == "inputNum" || key == "inputShell" {
			if got := fuzfOptionArgs(map[string]any{key: v}, "FUZZP01"); len(got) > 1 {
				t.Errorf("%s must not reach the command line, got %v", key, got)
			}
			continue
		}
		if errs := unsupportedFuzzOptionErrors(map[string]any{key: v}); len(errs) == 0 {
			t.Errorf("%s is shown as unsupported but setting it is accepted", key)
		}
		if got := fuzfOptionArgs(map[string]any{key: v}, "FUZZP01"); len(got) > 1 {
			t.Errorf("%s must never reach the command line, got %v", key, got)
		}
	}
}

// The owned flags are documentation, but they must not silently overlap the settable ones: a flag
// that appears in both lists is a flag two things claim to control.
func TestOwnedFlagsDoNotOverlapSettableOnes(t *testing.T) {
	settable := map[string]string{}
	for key, meta := range FuzzOptionMetas {
		if meta.Flag != "" && meta.Kind != "unsupported" {
			settable[meta.Flag] = key
		}
	}
	for owned := range FuzzOwnedFlags {
		for _, flag := range strings.Split(owned, ",") {
			flag = strings.TrimSpace(flag)
			if key, clash := settable[flag]; clash {
				t.Errorf("%s is listed as framework-owned but is also settable as %q", flag, key)
			}
		}
	}
}
