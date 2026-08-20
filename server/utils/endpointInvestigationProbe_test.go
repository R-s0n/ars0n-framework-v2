package utils

import "testing"

// The defect: consolidation stores /catalog/product?productId=8 as /catalog/product with productId
// as a parameter, and Investigate then fetched it bare. A route that requires a parameter answers
// 400 with an empty error page, yielding no signals at all, so it scored 0. Measured on
// ginandjuice.shop 2026-08-19: /order/details, /catalog/product and /blog/post scored 0 while
// react-dom.development.js scored 160.

func TestProbeURLSuppliesAnObservedParameter(t *testing.T) {
	got := probeURLWithObservedParams(
		"https://ginandjuice.shop/catalog/product",
		map[string]string{"productId": "8"})

	if got != "https://ginandjuice.shop/catalog/product?productId=8" {
		t.Fatalf("the endpoint has to be asked with a value it can answer, got %q", got)
	}
}

func TestProbeURLLeavesARecordedQueryStringAlone(t *testing.T) {
	// What the crawl actually recorded beats anything reconstructed from parameter examples.
	const recorded = "https://ginandjuice.shop/blog?search=rs0n"
	if got := probeURLWithObservedParams(recorded, map[string]string{"search": "other"}); got != recorded {
		t.Fatalf("a recorded query string must not be rewritten, got %q", got)
	}
}

func TestProbeURLIsUnchangedWithoutParameters(t *testing.T) {
	const bare = "https://ginandjuice.shop/about"
	if got := probeURLWithObservedParams(bare, nil); got != bare {
		t.Fatalf("got %q", got)
	}
	if got := probeURLWithObservedParams(bare, map[string]string{}); got != bare {
		t.Fatalf("got %q", got)
	}
}

func TestProbeURLIsDeterministicAcrossRuns(t *testing.T) {
	// Map iteration order is random in Go. Without sorting, the same endpoint produces a different
	// URL on every run and two scans stop being comparable.
	params := map[string]string{"zeta": "1", "alpha": "2", "mid": "3"}
	first := probeURLWithObservedParams("https://x.test/search", params)
	for i := 0; i < 50; i++ {
		if got := probeURLWithObservedParams("https://x.test/search", params); got != first {
			t.Fatalf("run %d produced %q, first produced %q", i, got, first)
		}
	}
	if first != "https://x.test/search?alpha=2&mid=3&zeta=1" {
		t.Fatalf("got %q", first)
	}
}

func TestProbeURLEncodesValuesRatherThanConcatenating(t *testing.T) {
	got := probeURLWithObservedParams("https://x.test/s", map[string]string{"q": "a b&c=d"})
	if got != "https://x.test/s?q=a+b%26c%3Dd" {
		t.Fatalf("a raw value would forge extra parameters, got %q", got)
	}
}

func TestProbeURLSurvivesAnUnparseableURL(t *testing.T) {
	const bad = "://nope"
	if got := probeURLWithObservedParams(bad, map[string]string{"a": "1"}); got != bad {
		t.Fatalf("got %q", got)
	}
}
