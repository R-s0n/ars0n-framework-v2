package utils

import (
	"encoding/json"
	"testing"
)

// The crawler configs are decoded onto a pre-populated struct, so a field the operator never set
// keeps its default. The tolerant decoder has to preserve that: its repair path re-marshals and
// decodes a second time, and if that second pass reset absent fields to zero, every default in
// DefaultKatanaURLConfig would vanish the moment a config held one fractional number.
func TestTolerantDecodePreservesPrePopulatedDefaults(t *testing.T) {
	cfg := DefaultKatanaURLConfig()
	defaultDepth := cfg.Depth
	defaultTimeout := cfg.Timeout
	if defaultDepth == 0 || defaultTimeout == 0 {
		t.Skip("defaults are zero, so this test cannot distinguish preserved from reset")
	}

	// Only rateLimit is stored, and it is fractional. Everything else must keep its default.
	stored := []byte(`{"rateLimit":2.5}`)
	if err := UnmarshalConfigTolerant(stored, &cfg); err != nil {
		t.Fatalf("tolerant decode failed: %v", err)
	}

	if cfg.RateLimit == 0 {
		t.Error("rateLimit decoded to 0, so the crawler would run with no rate limit at all")
	}
	if cfg.RateLimit != 3 {
		t.Errorf("rateLimit = %d, want 3 (2.5 rounded)", cfg.RateLimit)
	}
	if cfg.Depth != defaultDepth {
		t.Errorf("depth was reset to %d, want the default %d", cfg.Depth, defaultDepth)
	}
	if cfg.Timeout != defaultTimeout {
		t.Errorf("timeout was reset to %d, want the default %d", cfg.Timeout, defaultTimeout)
	}
}

// The same guarantee on the fast path, where no repair happens at all.
func TestTolerantDecodeFastPathPreservesDefaults(t *testing.T) {
	cfg := DefaultGoSpiderURLConfig()
	defaultThreads := cfg.Threads

	if err := UnmarshalConfigTolerant([]byte(`{"delay":2}`), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DelayS != 2 {
		t.Errorf("delay = %d, want 2", cfg.DelayS)
	}
	if cfg.Threads != defaultThreads {
		t.Errorf("threads was reset to %d, want the default %d", cfg.Threads, defaultThreads)
	}
}

// Strings that merely look numeric must not be touched. ffuf's filterSize is a string field holding
// "0", and rounding it into a number would change what the flag means.
func TestTolerantDecodeLeavesStringFieldsAlone(t *testing.T) {
	stored := []byte(`{"filterSize":"10900","rateLimit":5}`)
	var cfg struct {
		FilterSize string `json:"filterSize"`
		RateLimit  int    `json:"rateLimit"`
	}
	if err := UnmarshalConfigTolerant(stored, &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FilterSize != "10900" {
		t.Errorf("filterSize = %q, want %q", cfg.FilterSize, "10900")
	}
	if cfg.RateLimit != 5 {
		t.Errorf("rateLimit = %d, want 5", cfg.RateLimit)
	}
}

// An empty or absent config must not be treated as a parse failure.
func TestTolerantDecodeHandlesEmptyInput(t *testing.T) {
	cfg := DefaultLinkFinderURLConfig()
	want := cfg.Timeout
	if err := UnmarshalConfigTolerant(nil, &cfg); err != nil {
		t.Errorf("nil input returned an error: %v", err)
	}
	if err := UnmarshalConfigTolerant([]byte(``), &cfg); err != nil {
		t.Errorf("empty input returned an error: %v", err)
	}
	if cfg.Timeout != want {
		t.Errorf("defaults were disturbed: timeout = %d, want %d", cfg.Timeout, want)
	}
}

// Genuinely malformed JSON must still be reported, so an unreadable config is logged rather than
// silently becoming an all-defaults config.
func TestTolerantDecodeStillReportsRealCorruption(t *testing.T) {
	var cfg ArjunConfig
	if err := UnmarshalConfigTolerant([]byte(`{"threads":`), &cfg); err == nil {
		t.Error("truncated JSON decoded without error")
	}
	if err := UnmarshalConfigTolerant([]byte(`"not an object"`), &cfg); err == nil {
		t.Error("a JSON string decoded into a struct without error")
	}
}

// Nested structs and slices of structs are repaired too, since a config can hold either.
func TestTolerantDecodeRepairsNestedValues(t *testing.T) {
	type inner struct {
		Count int `json:"count"`
	}
	var cfg struct {
		Nested inner   `json:"nested"`
		List   []inner `json:"list"`
	}
	stored := []byte(`{"nested":{"count":1.6},"list":[{"count":2.4},{"count":3.5}]}`)
	if err := UnmarshalConfigTolerant(stored, &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Nested.Count != 2 {
		t.Errorf("nested count = %d, want 2", cfg.Nested.Count)
	}
	if len(cfg.List) != 2 || cfg.List[0].Count != 2 || cfg.List[1].Count != 4 {
		t.Errorf("list repaired to %+v, want counts 2 and 4", cfg.List)
	}
}

// The premise of the whole file: the strict decoder really does leave the field at zero rather than
// refusing the document outright. If encoding/json ever changed that, the tolerant path would be
// unnecessary and this test says so.
func TestStrictDecoderStillZeroesTheOffendingField(t *testing.T) {
	var cfg struct {
		A int `json:"a"`
		B int `json:"b"`
	}
	err := json.Unmarshal([]byte(`{"a":1.5,"b":7}`), &cfg)
	if err == nil {
		t.Fatal("expected a type error")
	}
	if cfg.A != 0 {
		t.Errorf("a = %d, expected the strict decoder to leave it at 0", cfg.A)
	}
	// The decoder carries on past the bad field, which is why the failure is invisible: the config
	// looks fine apart from the one setting that silently became zero.
	if cfg.B != 7 {
		t.Errorf("b = %d, want 7", cfg.B)
	}
}
