package utils

import (
	"net/url"
	"strings"
	"testing"
)

func TestWafCanaryPayloadKnownAndUnknown(t *testing.T) {
	// A class the scanner serves gets a canary; an unserved class gets none, so the caller never
	// miscalls a vector untested for a class the WAF was never tested against.
	if got := wafCanaryPayload("xss"); !strings.Contains(got, "<script>") {
		t.Fatalf("xss canary = %q, want an XSS payload", got)
	}
	if got := wafCanaryPayload("XSS"); got == "" {
		t.Fatalf("category match must be case-insensitive, got empty for %q", "XSS")
	}
	for _, cat := range []string{"sqli", "lfi", "cmdi", "ssti", "redirect"} {
		if wafCanaryPayload(cat) == "" {
			t.Errorf("expected a canary for served class %q", cat)
		}
	}
	for _, cat := range []string{"", "graphql", "smuggling", "unknown"} {
		if got := wafCanaryPayload(cat); got != "" {
			t.Errorf("class %q must have no canary, got %q", cat, got)
		}
	}
}

func TestIsWAFRefusalOnlyCleanRejections(t *testing.T) {
	// 403/406 are the content-rejection codes. 400 is app-layer shape rejection (the input reached
	// the app) and 429 is rate limiting (owned by vectorRateLimit.go), so neither counts here.
	blocked := []int{403, 406}
	notBlocked := []int{0, 200, 301, 400, 401, 404, 429, 500, 503}
	for _, s := range blocked {
		if !isWAFRefusal(s) {
			t.Errorf("status %d should read as a WAF refusal", s)
		}
	}
	for _, s := range notBlocked {
		if isWAFRefusal(s) {
			t.Errorf("status %d must NOT read as a WAF refusal", s)
		}
	}
}

func TestBuildWAFCanaryURLInjectsFirstParam(t *testing.T) {
	payload := `"><script>alert(1)</script>`
	raw := "https://travelers-api.example.com/attribution-links?component=footer&partnerId="
	out, ok := buildWAFCanaryURL(raw, payload)
	if !ok {
		t.Fatalf("buildWAFCanaryURL returned ok=false for %q", raw)
	}
	u, err := url.Parse(out)
	if err != nil {
		t.Fatalf("result did not parse: %v", err)
	}
	if u.Host != "travelers-api.example.com" || u.Path != "/attribution-links" {
		t.Fatalf("host/path not preserved: host=%q path=%q", u.Host, u.Path)
	}
	// "component" sorts before "partnerId", so it is the parameter that carries the payload, decoded
	// back to exactly what went in, and partnerId is still present.
	if got := u.Query().Get("component"); got != payload {
		t.Errorf("component = %q, want the raw payload %q", got, payload)
	}
	if _, present := u.Query()["partnerId"]; !present {
		t.Errorf("partnerId should be preserved alongside the injected param")
	}
	// The payload must not sit unescaped in the raw query on the wire.
	if strings.Contains(u.RawQuery, "<script>") {
		t.Errorf("payload is not URL-encoded in RawQuery: %q", u.RawQuery)
	}
}

func TestBuildWAFCanaryURLAppendsWhenNoParams(t *testing.T) {
	payload := `"><script>alert(1)</script>`
	out, ok := buildWAFCanaryURL("https://www.example.com/s", payload)
	if !ok {
		t.Fatalf("ok=false for a param-less URL")
	}
	u, err := url.Parse(out)
	if err != nil {
		t.Fatalf("result did not parse: %v", err)
	}
	if u.Query().Get("waf") != payload {
		t.Errorf("appended waf param = %q, want %q", u.Query().Get("waf"), payload)
	}
	if u.Path != "/s" {
		t.Errorf("path not preserved: %q", u.Path)
	}
}

func TestBuildWAFCanaryURLRejectsGarbage(t *testing.T) {
	// A URL with no host is not something the canary can send, and the caller must get ok=false so it
	// does not probe and does not demote.
	for _, bad := range []string{"", "not a url", "/relative/only", "://missing-scheme"} {
		if _, ok := buildWAFCanaryURL(bad, "x"); ok {
			t.Errorf("expected ok=false for %q", bad)
		}
	}
}

func TestProbeVectorWAFClassSkipsWithoutBaseline(t *testing.T) {
	// No benign baseline (or a benign arm that was itself refused) means the differential cannot be
	// established, so the probe must return Probed=false and the caller leaves the vector alone. A
	// nil client also returns unprobed. None of these touch the network.
	cases := []struct {
		name         string
		client       *ScanClient
		category     string
		benignStatus int
	}{
		{"nil client", nil, "xss", 200},
		{"no canary for class", &ScanClient{}, "graphql", 200},
		{"benign not observed", &ScanClient{}, "xss", 0},
		{"benign itself refused", &ScanClient{}, "xss", 403},
	}
	for _, c := range cases {
		obs := ProbeVectorWAFClass(nil, c.client, nil, c.category,
			"https://h.example.com/x?a=1", "h.example.com", c.benignStatus)
		if obs.Probed || obs.Blocked {
			t.Errorf("%s: expected unprobed/!blocked, got %+v", c.name, obs)
		}
	}
}
