package utils

import (
	"encoding/json"
	"math"
	"testing"
)

// What the probe measures has to survive all the way to the command line. Every defect below was
// live, and every one of them failed silently: the apply journal recorded a rate, the UI showed it
// applied, and the tool ran with no pacing at all.

// achieved reports the request rate a tool would actually reach with the settings written to it,
// so the assertions can talk about rates rather than about flag values.
func achievedRate(tool string, cfg map[string]interface{}) float64 {
	switch tool {
	case "arjun":
		// -d is whole seconds, applied per request within each thread.
		d := numberOr(cfg["delay"], 0)
		if d <= 0 {
			return math.Inf(1) // no delay flag emitted, so nothing paces it
		}
		return numberOr(cfg["threads"], 5) / d
	case "x8":
		// --delay is milliseconds, across --workers.
		d := numberOr(cfg["delay"], 0)
		if d <= 0 {
			return math.Inf(1)
		}
		return numberOr(cfg["concurrency"], 10) / (d / 1000.0)
	}
	return math.NaN()
}

// applyRate runs one rate_limit recommendation through the real translation and returns the config
// as it would be stored, after a JSON round trip through the tool's own struct. The round trip is
// the point: it is where a float silently became a zero.
func applyRate(t *testing.T, tool string, current map[string]interface{}, rps float64) map[string]interface{} {
	t.Helper()

	field, value, ok := translateField(tool, current, "rate_limit", rps)
	if !ok {
		t.Fatalf("%s: translateField refused a rate of %v", tool, rps)
	}
	current[field] = value

	stored, err := json.Marshal(current)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	switch tool {
	case "arjun":
		var cfg ArjunConfig
		_ = UnmarshalConfigTolerant(stored, &cfg)
		return map[string]interface{}{
			"delay": float64(cfg.Delay), "threads": float64(cfg.Threads),
		}
	case "x8":
		var cfg X8Config
		_ = UnmarshalConfigTolerant(stored, &cfg)
		return map[string]interface{}{
			"delay": float64(cfg.Delay), "concurrency": float64(cfg.Concurrency),
		}
	}
	t.Fatalf("unknown tool %s", tool)
	return nil
}

// A fractional delay used to be written as a float, fail to decode into the int column, and leave
// the field at zero. Zero delay means no flag, which means no rate limit at all: the exact opposite
// of the measurement being applied.
func TestArjunRateSurvivesTheRoundTrip(t *testing.T) {
	for _, rps := range []float64{1, 2, 3, 5, 7.5, 10} {
		cfg := applyRate(t, "arjun", map[string]interface{}{"threads": float64(5)}, rps)

		if cfg["delay"].(float64) <= 0 {
			t.Fatalf("rps=%v: delay came back as %v, so no -d flag is emitted and arjun runs unpaced",
				rps, cfg["delay"])
		}
		got := achievedRate("arjun", cfg)
		if math.IsInf(got, 1) {
			t.Fatalf("rps=%v: arjun would run unpaced", rps)
		}
		// Erring slow is correct, erring fast is not: the probe measured what the target tolerates.
		if got > rps+0.001 {
			t.Errorf("rps=%v: arjun would run at %.2f, above the measured safe rate", rps, got)
		}
	}
}

// x8 --delay is milliseconds. The formula produced seconds, so a measured 5 rps was applied as a
// 2ms pause across 10 workers, which is roughly 5000 rps.
func TestX8RateIsInMillisecondsNotSeconds(t *testing.T) {
	for _, rps := range []float64{1, 2, 3, 5, 10} {
		cfg := applyRate(t, "x8", map[string]interface{}{"concurrency": float64(10)}, rps)

		got := achievedRate("x8", cfg)
		if math.IsInf(got, 1) {
			t.Fatalf("rps=%v: x8 would run unpaced", rps)
		}
		if got > rps+0.001 {
			t.Errorf("rps=%v: x8 would run at %.0f, %.0fx the measured safe rate",
				rps, got, got/rps)
		}
	}
}

// The tools that already worked must keep working, and must land on the exact flag value.
func TestIntegerRateToolsAreUnchanged(t *testing.T) {
	cases := []struct {
		tool, field string
		current     map[string]interface{}
		rps         float64
		want        int
	}{
		{"ffuf", "rateLimit", map[string]interface{}{}, 5, 5},
		{"katana", "rateLimit", map[string]interface{}{}, 5, 5},
		{"nuclei", "rate_limit", map[string]interface{}{}, 5, 5},
		{"linkfinder", "requestDelayMs", map[string]interface{}{}, 5, 200},
		{"gospider", "delay", map[string]interface{}{"concurrent": float64(10)}, 5, 2},
	}
	for _, c := range cases {
		field, value, ok := translateField(c.tool, c.current, "rate_limit", c.rps)
		if !ok {
			t.Errorf("%s: refused a rate", c.tool)
			continue
		}
		if field != c.field {
			t.Errorf("%s: wrote field %q, want %q", c.tool, field, c.field)
		}
		got, isInt := value.(int)
		if !isInt {
			t.Errorf("%s: wrote %T, but the config column is an integer and a float decodes to zero",
				c.tool, value)
			continue
		}
		if got != c.want {
			t.Errorf("%s: wrote %d, want %d", c.tool, got, c.want)
		}
	}
}

// Nothing may write a float into a field the tool reads as an integer, whatever the rate.
func TestNoRateTranslationEverProducesAFloat(t *testing.T) {
	tools := []string{"ffuf", "arjun", "x8", "katana", "gospider", "linkfinder", "nuclei"}
	for _, tool := range tools {
		for _, rps := range []float64{0.5, 1, 2.5, 3, 7.5, 11, 40} {
			current := map[string]interface{}{
				"threads": float64(5), "concurrency": float64(10), "concurrent": float64(10),
			}
			_, value, ok := translateField(tool, current, "rate_limit", rps)
			if !ok {
				continue // some tools have no knob, which is honest
			}
			if f, isFloat := value.(float64); isFloat {
				t.Errorf("%s at %v rps produced float %v; an int column decodes that to zero and "+
					"the tool then runs with no rate limit", tool, rps, f)
			}
		}
	}
}

// The tolerant decoder is what rescues configs written before the translation was corrected. A
// stored 1.67 must come back as a usable delay rather than as zero.
func TestTolerantDecodeRescuesAnAlreadyBrokenConfig(t *testing.T) {
	stored := []byte(`{"threads":5,"delay":1.67,"timeout":30,"method":"GET"}`)

	var strict ArjunConfig
	if err := json.Unmarshal(stored, &strict); err == nil {
		t.Fatal("expected the strict decoder to reject a fractional int, the premise has changed")
	}
	if strict.Delay != 0 {
		t.Fatalf("expected the strict decoder to leave delay at 0, got %d", strict.Delay)
	}

	var tolerant ArjunConfig
	if err := UnmarshalConfigTolerant(stored, &tolerant); err != nil {
		t.Fatalf("tolerant decode failed: %v", err)
	}
	if tolerant.Delay != 2 {
		t.Errorf("delay came back as %d, want 2 (1.67 rounded)", tolerant.Delay)
	}
	// The rest of the config has to survive the repair too.
	if tolerant.Threads != 5 || tolerant.Timeout != 30 || tolerant.Method != "GET" {
		t.Errorf("repair lost other settings: %+v", tolerant)
	}
}

// A healthy config must not be touched. Rounding a float that legitimately belongs in a float field
// would quietly change the setting.
func TestTolerantDecodeLeavesAHealthyConfigAlone(t *testing.T) {
	stored := []byte(`{"threads":8,"delay":2,"timeout":15,"method":"POST"}`)
	var cfg ArjunConfig
	if err := UnmarshalConfigTolerant(stored, &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Threads != 8 || cfg.Delay != 2 || cfg.Timeout != 15 || cfg.Method != "POST" {
		t.Errorf("healthy config was altered: %+v", cfg)
	}
}
