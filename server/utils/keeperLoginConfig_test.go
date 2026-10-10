package utils

import (
	"strings"
	"testing"
)

// A fixed 32-byte key so the crypto round-trip is tested with no DB and no install-key dependency.
var testCredKey = []byte("0123456789abcdef0123456789abcdef")

func TestCredentialSealOpenRoundTrip(t *testing.T) {
	secret := "Sup3r-Secret-Passw0rd!"
	blob1, err := sealWithKey(testCredKey, secret)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	if strings.Contains(string(blob1), secret) {
		t.Fatal("the sealed blob must not contain the plaintext password")
	}
	got, err := openWithKey(testCredKey, blob1)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if got != secret {
		t.Fatalf("round-trip mismatch: got %q want %q", got, secret)
	}
	// A fresh nonce each time: two seals of the same plaintext differ but both decrypt back.
	blob2, err := sealWithKey(testCredKey, secret)
	if err != nil {
		t.Fatalf("second seal failed: %v", err)
	}
	if string(blob1) == string(blob2) {
		t.Error("two seals of the same plaintext must differ (random nonce)")
	}
	if g2, _ := openWithKey(testCredKey, blob2); g2 != secret {
		t.Error("the second blob must also decrypt to the original plaintext")
	}
}

func TestCredentialWrongKeyFailsClosed(t *testing.T) {
	secret := "another-reusable-password"
	blob, err := sealWithKey(testCredKey, secret)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	wrong := []byte("ffffffffffffffffffffffffffffffff")
	got, err := openWithKey(wrong, blob)
	if err == nil {
		t.Fatal("opening with the wrong key must fail, not return a value")
	}
	if got != "" {
		t.Error("a failed open must return an empty string")
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("the error must never contain the plaintext password")
	}
}

func TestCredentialEmptyAndShort(t *testing.T) {
	if b, err := sealWithKey(testCredKey, ""); err != nil || len(b) == 0 {
		// sealing an empty string still produces a valid (nonce+tag) blob; just must not error.
		if err != nil {
			t.Fatalf("sealing empty failed: %v", err)
		}
	}
	if _, err := openWithKey(testCredKey, []byte{0x01, 0x02}); err == nil {
		t.Error("a blob shorter than the nonce must be rejected, not panic")
	}
}

func TestValidateKeeperLoginConfig(t *testing.T) {
	goodSteps := []KeeperLoginStep{
		{Action: "type", Selector: "#user", ValueRef: "username"},
		{Action: "type", Selector: "#pass", ValueRef: "password"},
		{Action: "click", Selector: "button[type=submit]"},
	}
	goodProbe := KeeperSuccessProbe{Kind: "bearer"}
	if p := validateKeeperLoginConfig("https://app.example.com/login", goodSteps, goodProbe); p != "" {
		t.Fatalf("a valid config was rejected: %s", p)
	}

	cases := []struct {
		name  string
		url   string
		steps []KeeperLoginStep
		probe KeeperSuccessProbe
	}{
		{"bad url", "notaurl", goodSteps, goodProbe},
		{"ftp url", "ftp://x/login", goodSteps, goodProbe},
		{"empty steps", "https://a.b/login", nil, goodProbe},
		{"unknown action", "https://a.b/login", []KeeperLoginStep{{Action: "scroll", Selector: "#x"}}, goodProbe},
		{"type without selector", "https://a.b/login", []KeeperLoginStep{{Action: "type", ValueRef: "username"}}, goodProbe},
		{"type bad value_ref", "https://a.b/login", []KeeperLoginStep{{Action: "type", Selector: "#u", ValueRef: "email"}}, goodProbe},
		{"literal without value", "https://a.b/login", []KeeperLoginStep{{Action: "type", Selector: "#u", ValueRef: "literal"}}, goodProbe},
		{"no type step", "https://a.b/login", []KeeperLoginStep{{Action: "click", Selector: "#go"}}, goodProbe},
		{"bad probe kind", "https://a.b/login", goodSteps, KeeperSuccessProbe{Kind: "magic"}},
		{"url probe no value", "https://a.b/login", goodSteps, KeeperSuccessProbe{Kind: "url"}},
		{"selector probe no value", "https://a.b/login", goodSteps, KeeperSuccessProbe{Kind: "selector"}},
		{"cookie probe no value", "https://a.b/login", goodSteps, KeeperSuccessProbe{Kind: "cookie"}},
	}
	for _, c := range cases {
		if p := validateKeeperLoginConfig(c.url, c.steps, c.probe); p == "" {
			t.Errorf("%s: expected a validation error, got none", c.name)
		} else if strings.ContainsRune(p, rune(0x2014)) {
			t.Errorf("%s: validation message must not contain an em-dash", c.name)
		}
	}

	// A literal type step WITH a literal value and selector is valid.
	lit := []KeeperLoginStep{
		{Action: "type", Selector: "#u", ValueRef: "username"},
		{Action: "type", Selector: "#p", ValueRef: "password"},
		{Action: "type", Selector: "#tenant", ValueRef: "literal", Literal: "acme"},
		{Action: "submit", Selector: "form"},
	}
	if p := validateKeeperLoginConfig("https://a.b/login", lit, KeeperSuccessProbe{Kind: "cookie", Value: "sid"}); p != "" {
		t.Fatalf("a valid literal-step config was rejected: %s", p)
	}
}
