package utils

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Tests for the token characterisation engine.
//
// EVERY FIXTURE IN THIS FILE IS SYNTHETIC. Not one byte of a real credential appears here, and
// TestNoTestFixtureLooksLikeARealCredential at the bottom checks that claim mechanically rather
// than on my word, because a test fixture is a file on disk that gets committed and a credential
// in one is a credential on disk forever.

// ---------------------------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------------------------

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// makeJWT builds a compact JWS with the given header and claim maps. The signature is the literal
// word "signature", because nothing here verifies one and putting real-looking entropy in a test
// file is how a fixture starts looking like a credential.
func makeJWT(t *testing.T, header, claims map[string]interface{}) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return b64url(h) + "." + b64url(c) + "." + b64url([]byte("signature-not-verified"))
}

func makeJWE(t *testing.T, header map[string]interface{}) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	return strings.Join([]string{
		b64url(h), b64url([]byte("encrypted-key")), b64url([]byte("iv")),
		b64url([]byte("ciphertext")), b64url([]byte("tag")),
	}, ".")
}

func makePASETOPublic(t *testing.T, version string, claims map[string]interface{}) string {
	t.Helper()
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	// A real public PASETO appends a 64 byte Ed25519 signature to the JSON inside the same
	// base64url segment, which is exactly the thing a naive "decode and unmarshal" gets wrong.
	payload := append(c, bytes.Repeat([]byte{0x01}, 64)...)
	return version + ".public." + b64url(payload)
}

func encodeBase62(raw []byte) string {
	n := new(big.Int).SetBytes(raw)
	base := big.NewInt(62)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var out []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		out = append(out, brancaAlphabet[mod.Int64()])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func makeBranca(issued time.Time) string {
	raw := make([]byte, 0, 61)
	raw = append(raw, 0xBA)
	ts := make([]byte, 4)
	binary.BigEndian.PutUint32(ts, uint32(issued.Unix()))
	raw = append(raw, ts...)
	raw = append(raw, bytes.Repeat([]byte{0x02}, 24)...) // nonce
	raw = append(raw, bytes.Repeat([]byte{0x03}, 16)...) // ciphertext
	raw = append(raw, bytes.Repeat([]byte{0x04}, 16)...) // tag
	return encodeBase62(raw)
}

func makeSAML(notBefore, notOnOrAfter, sessionNotOnOrAfter string) string {
	session := ""
	if sessionNotOnOrAfter != "" {
		session = fmt.Sprintf(`<saml:AuthnStatement SessionNotOnOrAfter="%s"/>`, sessionNotOnOrAfter)
	}
	xml := fmt.Sprintf(`<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">`+
		`<saml:Assertion><saml:Issuer>https://idp.example.test/sso</saml:Issuer>`+
		`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"/>%s</saml:Assertion></samlp:Response>`,
		notBefore, notOnOrAfter, session)
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

// ---------------------------------------------------------------------------------------------
// The credential is served
// ---------------------------------------------------------------------------------------------

// A captured credential IS the finding, so every route a value takes out of a Go program has to
// carry it: a leaked token is proved by showing the token, and a type that printed a description
// of one instead would have destroyed the proof.
func TestACredentialIsServedThroughEveryRendering(t *testing.T) {
	const secret = "sk_live_THIS_IS_THE_EVIDENCE_0123456789"
	c := NewCredential(secret)

	type holder struct {
		Cred  Credential `json:"cred"`
		Other string     `json:"other"`
	}
	h := holder{Cred: c, Other: "safe"}

	marshalled, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	logger.Printf("credential=%v prefixed=%s quoted=%q plus=%+v struct=%+v", c, c, c, c, h)

	renderings := map[string]string{
		"%v":           fmt.Sprintf("%v", c),
		"%s":           fmt.Sprintf("%s", c),
		"%q":           fmt.Sprintf("%q", c),
		"%+v":          fmt.Sprintf("%+v", c),
		"struct %+v":   fmt.Sprintf("%+v", h),
		"json.Marshal": string(marshalled),
		"log.Printf":   buf.String(),
		"String()":     c.String(),
		"Value()":      c.Value(),
	}
	for how, got := range renderings {
		if !strings.Contains(got, secret) {
			t.Errorf("%s withheld the credential, which is the evidence: %s", how, got)
		}
	}
	// The fingerprint is still there to be taken, because it is the join key an issuing response or
	// a validation event is tied to a credential by.
	if c.Fingerprint() == "" || c.Fingerprint() == "none" {
		t.Errorf("the join key is gone: %q", c.Fingerprint())
	}
	if NewCredential(secret).Fingerprint() != c.Fingerprint() {
		t.Errorf("two wrappings of one value fingerprint differently, so the join is broken")
	}
}

// ---------------------------------------------------------------------------------------------
// JWT / JWS
// ---------------------------------------------------------------------------------------------

func TestJWTWithIatGivesAParsedTTL(t *testing.T) {
	iat := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	tok := makeJWT(t, map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": "abc"},
		map[string]interface{}{
			"iss": "https://issuer.example.test", "sub": "user-1", "jti": "j1",
			"iat": iat.Unix(), "exp": iat.Add(30 * time.Minute).Unix(),
		})

	p := ProfileCredential(NewCredential("Bearer "+tok), CredentialCarrier{Kind: "bearer", Name: "Authorization", Prefix: "Bearer "}, iat)
	if p.Kind != CredentialKindJWT {
		t.Fatalf("kind = %s, want jwt (%s)", p.Kind, p.KindEvidence)
	}
	if !p.TTLKnown || p.TTL != 30*time.Minute {
		t.Fatalf("TTL = %v known=%v, want 30m", p.TTL, p.TTLKnown)
	}
	if p.TTLProvenance != ProvParsed {
		t.Fatalf("provenance = %s, want parsed", p.TTLProvenance)
	}
	if !strings.Contains(p.TTLEvidence, "exp minus iat") {
		t.Fatalf("the evidence does not name the claims used: %q", p.TTLEvidence)
	}
	if p.Attributes["alg"] != "RS256" || p.Attributes["kid"] != "abc" {
		t.Fatalf("header attributes were not recorded: %+v", p.Attributes)
	}
	if p.Attributes["iss"] != "https://issuer.example.test" {
		t.Fatalf("iss was not recorded: %+v", p.Attributes)
	}
}

// THE LIVE SHAPE. The tokens on the target this engine was built for carry aud, c, email, exp, g,
// iss, jti, nbf, sub and uid, and NO iat. Fifty one distinct tokens read out of
// manual_crawl_captures, not one iat among them, and exp minus nbf is 900 on 29 of them and 901
// on 22. A TTL ladder that stops at exp minus iat reports UNKNOWN for the whole target.
func TestJWTWithNoIatFallsBackToNbfAndSaysSo(t *testing.T) {
	nbf := time.Date(2026, 9, 7, 23, 43, 0, 0, time.UTC)
	tok := makeJWT(t, map[string]interface{}{"alg": "ES256", "typ": "JWT", "kid": "GZY3M2YCG2P5UXW3", "xv": "1"},
		map[string]interface{}{
			"aud": "app", "c": "x", "email": "someone@example.test", "g": "y",
			"iss": "https://authx.example.test/v1", "jti": "j2", "sub": "u", "uid": "u",
			"nbf": nbf.Unix(), "exp": nbf.Add(900 * time.Second).Unix(),
		})

	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, nbf)
	if !p.TTLKnown {
		t.Fatalf("the TTL was reported unknown for a token whose exp and nbf are both present: %+v", p.Warnings)
	}
	if p.TTL != 15*time.Minute {
		t.Fatalf("TTL = %v, want 15m", p.TTL)
	}
	if !strings.Contains(p.TTLEvidence, "nbf") {
		t.Fatalf("a TTL derived from nbf must say so, got %q", p.TTLEvidence)
	}
	if !strings.Contains(p.TTLEvidence, "upper bound") {
		t.Fatalf("a TTL from nbf is an upper bound and the evidence must say why, got %q", p.TTLEvidence)
	}
	if !p.IssuedAtKnown || !p.IssuedAt.Equal(nbf) {
		t.Fatalf("nbf should stand in for the issue time, got %v known=%v", p.IssuedAt, p.IssuedAtKnown)
	}
	// THE EMAIL CLAIM IS SERVED, NOT JUST NAMED. Who a captured token is for is the finding: it is
	// what proves a token was minted for the wrong account and what an access-control report is
	// written around, so the address itself is what the profile carries.
	if p.Attributes["email"] != "someone@example.test" {
		t.Fatalf("the email claim is not served as the token carries it: %q", p.Attributes["email"])
	}
	// The other claims of this measured token, each with its value, including the ones no rule in
	// this file has ever heard of.
	for name, want := range map[string]string{"aud": "app", "c": "x", "g": "y", "uid": "u", "sub": "u", "jti": "j2"} {
		if p.Attributes[name] != want {
			t.Errorf("the %s claim reads %q, want %q", name, p.Attributes[name], want)
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), "someone@example.test") {
		t.Fatalf("the marshalled profile does not reach a reader with the email claim in it: %s", raw)
	}
}

func TestJWTWithExpButNoIssueTimeHasAnExpiryAndNoTTL(t *testing.T) {
	exp := time.Date(2026, 9, 20, 13, 0, 0, 0, time.UTC)
	tok := makeJWT(t, map[string]interface{}{"alg": "HS256"}, map[string]interface{}{"exp": exp.Unix()})

	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, exp.Add(-time.Hour))
	if !p.ExpiryKnown || !p.ExpiresAt.Equal(exp) {
		t.Fatalf("expiry = %v known=%v, want %v", p.ExpiresAt, p.ExpiryKnown, exp)
	}
	if p.TTLKnown {
		t.Fatalf("a TTL was invented for a token with no issue time: %v (%s)", p.TTL, p.TTLEvidence)
	}
	if p.TTLDisplay() != "UNKNOWN" {
		t.Fatalf("an unknown TTL must render as UNKNOWN, got %q", p.TTLDisplay())
	}
}

func TestJWTWithNoExpSaysItDoesNotExpireOnItsOwnTerms(t *testing.T) {
	tok := makeJWT(t, map[string]interface{}{"alg": "HS256"}, map[string]interface{}{"sub": "u", "iat": 1788825481})
	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, time.Now())
	if p.TTLKnown || p.ExpiryKnown {
		t.Fatalf("a lifetime was invented for a token with no exp: ttl=%v exp=%v", p.TTL, p.ExpiresAt)
	}
	if !warningsMention(p.Warnings, "no exp claim") {
		t.Fatalf("the absence of exp was not reported: %v", p.Warnings)
	}
}

func TestUnsignedJWTIsReportedAsAFinding(t *testing.T) {
	tok := makeJWT(t, map[string]interface{}{"alg": "none"}, map[string]interface{}{"exp": 1788826381, "iat": 1788825481})
	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, time.Now())
	if !warningsMention(p.Warnings, "unsigned") {
		t.Fatalf("alg none was not called out: %v", p.Warnings)
	}
}

func TestJWEIsRecognisedAndItsExpiryIsUnknownNotAbsent(t *testing.T) {
	tok := makeJWE(t, map[string]interface{}{"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "k1"})
	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, time.Now())
	if p.Kind != CredentialKindJWE {
		t.Fatalf("kind = %s, want jwe", p.Kind)
	}
	if p.Attributes["enc"] != "A256GCM" {
		t.Fatalf("the JWE header was not read: %+v", p.Attributes)
	}
	if p.TTLKnown || p.ExpiryKnown {
		t.Fatalf("a lifetime was invented for an encrypted token")
	}
	if !warningsMention(p.Warnings, "encrypted") {
		t.Fatalf("the reason the expiry is unreadable was not given: %v", p.Warnings)
	}
}

func TestJWTWithANonJSONPayloadIsStillAJWT(t *testing.T) {
	tok := b64url([]byte(`{"alg":"RS256","cty":"JWT"}`)) + "." + b64url([]byte("not json at all")) + "." + b64url([]byte("sig"))
	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, time.Now())
	if p.Kind != CredentialKindJWT {
		t.Fatalf("kind = %s, want jwt", p.Kind)
	}
	if !warningsMention(p.Warnings, "not JSON") {
		t.Fatalf("the unreadable payload was not reported: %v", p.Warnings)
	}
}

func TestFractionalNumericDateIsNotDropped(t *testing.T) {
	// A NumericDate is "seconds", and issuers do send a fractional one. An int64 parse drops the
	// whole token, which reads as "this credential has no expiry".
	raw := `{"iat":1788825481.5,"exp":1788826381.5}`
	tok := b64url([]byte(`{"alg":"HS256"}`)) + "." + b64url([]byte(raw)) + "." + b64url([]byte("sig"))
	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, time.Now())
	if !p.TTLKnown || p.TTL != 15*time.Minute {
		t.Fatalf("TTL = %v known=%v, want 15m from fractional NumericDates", p.TTL, p.TTLKnown)
	}
}

// ---------------------------------------------------------------------------------------------
// PASETO, Branca, SAML
// ---------------------------------------------------------------------------------------------

func TestPASETOPublicUsesRFC3339ClaimsNotUnixSeconds(t *testing.T) {
	iat := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	tok := makePASETOPublic(t, "v2", map[string]interface{}{
		"iss": "https://paseto.example.test",
		"iat": iat.Format(time.RFC3339),
		"exp": iat.Add(2 * time.Hour).Format(time.RFC3339),
	})
	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, iat)
	if p.Kind != CredentialKindPASETO {
		t.Fatalf("kind = %s, want paseto", p.Kind)
	}
	if !p.TTLKnown || p.TTL != 2*time.Hour {
		t.Fatalf("TTL = %v known=%v, want 2h", p.TTL, p.TTLKnown)
	}
	if p.TTLProvenance != ProvParsed {
		t.Fatalf("provenance = %s, want parsed", p.TTLProvenance)
	}
}

func TestPASETOLocalIsRecognisedAndItsExpiryIsUnknown(t *testing.T) {
	p := ProfileCredential(NewCredential("v4.local."+b64url([]byte("ciphertext-bytes-here"))),
		CredentialCarrier{Kind: "bearer", Name: "Authorization"}, time.Now())
	if p.Kind != CredentialKindPASETO {
		t.Fatalf("kind = %s, want paseto", p.Kind)
	}
	if p.TTLKnown || p.ExpiryKnown {
		t.Fatalf("a lifetime was invented for an encrypted PASETO")
	}
	if p.Attributes["paseto_purpose"] != "local" {
		t.Fatalf("the purpose was not recorded: %+v", p.Attributes)
	}
}

// Branca is the clean case of a credential whose ISSUE time is readable and whose LIFETIME is not
// in the token at all: the TTL is a parameter the verifier passes. Anything other than "issued
// then, expiry unknown" would be an invention.
func TestBrancaGivesAnIssueTimeAndNoExpiry(t *testing.T) {
	issued := time.Date(2026, 9, 20, 9, 30, 0, 0, time.UTC)
	p := ProfileCredential(NewCredential(makeBranca(issued)), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, issued)
	if p.Kind != CredentialKindBranca {
		t.Fatalf("kind = %s (%s), want branca", p.Kind, p.KindEvidence)
	}
	if !p.IssuedAtKnown || !p.IssuedAt.Equal(issued) {
		t.Fatalf("issued at = %v known=%v, want %v", p.IssuedAt, p.IssuedAtKnown, issued)
	}
	if p.ExpiryKnown || p.TTLKnown {
		t.Fatalf("a lifetime was invented for a Branca token: exp=%v ttl=%v", p.ExpiresAt, p.TTL)
	}
	if !warningsMention(p.Warnings, "parameter of the verifier") {
		t.Fatalf("why the TTL is unreadable was not explained: %v", p.Warnings)
	}
}

// A SAML response carries two lifetimes and they answer different questions. The session one is
// the one a scan is carrying; reporting the five minute assertion window as the session lifetime
// would tell an operator their hours-long session dies before the scan starts.
func TestSAMLPrefersTheSessionLifetimeOverTheAssertionWindow(t *testing.T) {
	nb := "2026-09-20T09:00:00Z"
	na := "2026-09-20T09:05:00Z"
	sess := "2026-09-20T17:00:00Z"
	p := ProfileCredential(NewCredential(makeSAML(nb, na, sess)), CredentialCarrier{Kind: "header", Name: "X-SAML"}, time.Now())
	if p.Kind != CredentialKindSAML {
		t.Fatalf("kind = %s, want saml_assertion", p.Kind)
	}
	want, _ := time.Parse(time.RFC3339, sess)
	if !p.ExpiryKnown || !p.ExpiresAt.Equal(want) {
		t.Fatalf("expiry = %v, want SessionNotOnOrAfter %v", p.ExpiresAt, want)
	}
	if !p.TTLKnown || p.TTL != 8*time.Hour {
		t.Fatalf("TTL = %v, want 8h", p.TTL)
	}
	if p.Attributes["conditions_not_on_or_after"] == "" {
		t.Fatalf("the assertion window was dropped rather than recorded alongside: %+v", p.Attributes)
	}
}

func TestSAMLWithoutASessionStatementSaysTheSessionLifetimeIsNotStated(t *testing.T) {
	p := ProfileCredential(NewCredential(makeSAML("2026-09-20T09:00:00Z", "2026-09-20T09:05:00Z", "")),
		CredentialCarrier{Kind: "header", Name: "X-SAML"}, time.Now())
	if !p.TTLKnown || p.TTL != 5*time.Minute {
		t.Fatalf("TTL = %v, want the 5m assertion window", p.TTL)
	}
	if !warningsMention(p.Warnings, "SessionNotOnOrAfter") {
		t.Fatalf("the missing session statement was not reported: %v", p.Warnings)
	}
}

// ---------------------------------------------------------------------------------------------
// Opaque credentials
// ---------------------------------------------------------------------------------------------

func TestKnownSessionCookiesAreNamedRatherThanCalledUnknown(t *testing.T) {
	for _, name := range []string{"PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "connect.sid", "laravel_session", "_myapp_session"} {
		p := ProfileCredential(NewCredential("a0b1c2d3e4f5a0b1c2d3e4f5"), CredentialCarrier{Kind: "cookie", Name: name}, time.Now())
		if p.Kind != CredentialKindSessionID {
			t.Errorf("%s: kind = %s, want opaque_session_id (%s)", name, p.Kind, p.KindEvidence)
		}
		if p.TTLKnown || p.ExpiryKnown {
			t.Errorf("%s: a lifetime was invented for a server-side session id", name)
		}
	}
}

// "API keys usually never expire" is an assumption, and this file does not trade in those. The
// kind is a finding; the lifetime stays unknown until something measures it.
func TestAnAPIKeyIsRecognisedWithoutInventingAnExpiry(t *testing.T) {
	p := ProfileCredential(NewCredential("sk_live_0000000000000000example"), CredentialCarrier{Kind: "api_key", Name: "X-Api-Key"}, time.Now())
	if p.Kind != CredentialKindAPIKey {
		t.Fatalf("kind = %s, want api_key", p.Kind)
	}
	if p.ExpiryStyle == ExpiryStyleNonExpiring {
		t.Fatalf("non_expiring was recorded from a prefix rather than from a measurement")
	}
	if p.TTLKnown || p.ExpiryKnown {
		t.Fatalf("a lifetime was invented for an API key")
	}
	if !warningsMention(p.Warnings, "unknown rather than unlimited") {
		t.Fatalf("the distinction between commonly-no-expiry and measured-no-expiry was not made: %v", p.Warnings)
	}
}

func TestAnEmptyCredentialIsReportedAndNotGuessedAt(t *testing.T) {
	p := ProfileCredential(NewCredential("   "), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, time.Now())
	if p.Kind != CredentialKindUnknown {
		t.Fatalf("kind = %s, want unknown", p.Kind)
	}
	if !warningsMention(p.Warnings, "empty") {
		t.Fatalf("an empty credential was not reported: %v", p.Warnings)
	}
}

// ---------------------------------------------------------------------------------------------
// Cookie attributes
// ---------------------------------------------------------------------------------------------

// RFC 6265 section 5.3: when both are present the client uses Max-Age. A server shortening a
// cookie sends a long Expires for old clients and a short Max-Age for everyone else, so reading
// Expires there overstates the lifetime by whatever the server was trying to take away.
func TestMaxAgeWinsOverExpires(t *testing.T) {
	issued := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	got := ParseSetCookieLifetime(
		"sid=abc; Max-Age=600; Expires=Sat, 20 Sep 2036 12:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax", issued)
	if !got.TTLKnown || got.TTL != 10*time.Minute {
		t.Fatalf("TTL = %v known=%v, want 10m from Max-Age", got.TTL, got.TTLKnown)
	}
	if !got.ExpiryKnown || !got.ExpiresAt.Equal(issued.Add(10*time.Minute)) {
		t.Fatalf("expiry = %v, want issue time plus Max-Age", got.ExpiresAt)
	}
	if !strings.Contains(got.Evidence, "precedence") {
		t.Fatalf("the precedence rule was applied silently: %q", got.Evidence)
	}
	for _, want := range []string{"secure", "httponly", "samesite", "path"} {
		if got.Attributes[want] == "" {
			t.Errorf("attribute %s was dropped: %+v", want, got.Attributes)
		}
	}
}

// A session cookie is a THIRD answer, not a shorter one and not a missing one.
func TestASessionCookieIsItsOwnAnswer(t *testing.T) {
	got := ParseSetCookieLifetime("sid=abc; Path=/; HttpOnly", time.Now())
	if got.Style != ExpiryStyleSession {
		t.Fatalf("style = %s, want session", got.Style)
	}
	if got.TTLKnown || got.ExpiryKnown {
		t.Fatalf("a lifetime was invented for a session cookie")
	}
	if got.AlreadyDead {
		t.Fatalf("a session cookie was read as deleted")
	}
}

// Max-Age=0 is how a server DELETES a cookie. Reading it as a lifetime records a live session for
// a credential that was just revoked.
func TestACookieDeletionIsNotALifetime(t *testing.T) {
	for _, header := range []string{
		"sid=; Max-Age=0; Path=/",
		"sid=; Max-Age=-1; Path=/",
		"sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
	} {
		got := ParseSetCookieLifetime(header, time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
		if !got.AlreadyDead {
			t.Errorf("%q was not read as a deletion: %+v", header, got)
		}
		if got.TTLKnown && got.TTL > 0 {
			t.Errorf("%q produced a positive lifetime %v", header, got.TTL)
		}
	}
}

func TestExpiresOnlyGivesAnExpiryAndATTLRelativeToTheResponse(t *testing.T) {
	issued := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	got := ParseSetCookieLifetime("sid=abc; Expires=Sun, 20 Sep 2026 14:00:00 GMT", issued)
	if !got.ExpiryKnown {
		t.Fatalf("the Expires attribute was not read: %+v", got)
	}
	if !got.TTLKnown || got.TTL != 2*time.Hour {
		t.Fatalf("TTL = %v, want 2h", got.TTL)
	}
}

// ---------------------------------------------------------------------------------------------
// OAuth token responses
// ---------------------------------------------------------------------------------------------

func TestOAuthResponseGivesAParsedTTLForAnOpaqueAccessToken(t *testing.T) {
	body := `{"access_token":"opaque-value","token_type":"Bearer","expires_in":3600,` +
		`"refresh_token":"another-opaque-value","refresh_token_expires_in":"2592000","scope":"read write"}`
	got, ok := ParseOAuthTokenResponse(body)
	if !ok {
		t.Fatalf("the body was not recognised as a token response")
	}
	if !got.ExpiresInKnown || got.ExpiresIn != time.Hour {
		t.Fatalf("expires_in = %v known=%v, want 1h", got.ExpiresIn, got.ExpiresInKnown)
	}
	if !got.RefreshTTLKnown || got.RefreshTTL != 30*24*time.Hour {
		t.Fatalf("refresh TTL = %v, want 30d (a string-encoded number must parse)", got.RefreshTTL)
	}
	if !got.HasRefreshToken || !got.HasAccessToken {
		t.Fatalf("the presence flags are wrong: %+v", got)
	}
	// AND THE CREDENTIALS THE RESPONSE ISSUED COME OUT WITH THEM. A token endpoint response is the
	// richest thing a crawl catches: the access token is the session and the refresh token renews
	// it. A parse that reported a refresh token exists and refused to say which one left the
	// operator with a fact they could not spend.
	if got.AccessToken != "opaque-value" {
		t.Errorf("the access token was dropped by the parse: %q", got.AccessToken)
	}
	if got.RefreshToken != "another-opaque-value" {
		t.Errorf("the refresh token was dropped by the parse: %q", got.RefreshToken)
	}
	blob, _ := json.Marshal(got)
	for _, want := range []string{"opaque-value", "another-opaque-value"} {
		if !strings.Contains(string(blob), want) {
			t.Errorf("the marshalled parse does not reach a reader with %q in it: %s", want, blob)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Corpus observation: a floor is a floor
// ---------------------------------------------------------------------------------------------

// THE MEASUREMENT THIS WHOLE DISTINCTION RESTS ON.
//
// The spans below are the real ones read out of manual_crawl_captures for the live target on
// 2026-09-20, grouped by distinct Authorization value: 0s, 0s, 0s, 11s, 45s, 78s, 133s, 358s,
// 868s. The parsed truth for those same tokens is 900s, measured independently from exp minus
// nbf on 51 tokens.
//
// So an implementation that reported the MEDIAN as the TTL would say 45 seconds against a real
// 900, wrong by a factor of twenty, and would tell an operator their 29 minute scan needs a
// credential every minute. An implementation that reported the MAXIMUM as the TTL would say 868
// and be almost right, and would still be asserting a measurement it does not have. The only
// honest statement is a floor.
func TestAnObservedSpanIsAFloorAndNeverATTL(t *testing.T) {
	base := time.Date(2026, 9, 7, 23, 43, 0, 0, time.UTC)
	spans := []time.Duration{0, 0, 0, 11 * time.Second, 45 * time.Second, 78 * time.Second,
		133 * time.Second, 358 * time.Second, 868 * time.Second}

	var samples []corpusSample
	at := base
	for i, span := range spans {
		samples = append(samples, corpusSample{
			Fingerprint: fmt.Sprintf("fp%06d", i),
			Count:       10,
			First:       at,
			Last:        at.Add(span),
		})
		at = at.Add(span + 4*time.Second)
	}

	obs := summariseCorpusSamples(samples, CredentialCarrier{Kind: "header", Name: "Authorization"})
	if obs.Floor != 868*time.Second {
		t.Fatalf("floor = %v, want the longest span 868s", obs.Floor)
	}
	if obs.MedianSpan != 45*time.Second {
		t.Fatalf("median span = %v, want 45s", obs.MedianSpan)
	}
	if obs.Samples != len(spans) || obs.Requests != 10*len(spans) {
		t.Fatalf("samples = %d requests = %d, want %d and %d", obs.Samples, obs.Requests, len(spans), 10*len(spans))
	}

	p := SessionTokenProfile{TTLProvenance: ProvUnknown, ExpiryStyle: ExpiryStyleUnknown}
	applyObservation(&p, obs)
	if p.TTLKnown {
		t.Fatalf("an observation set a TTL: %v via %s", p.TTL, p.TTLProvenance)
	}
	if !p.TTLFloorKnown || p.TTLFloor != 868*time.Second {
		t.Fatalf("floor = %v known=%v", p.TTLFloor, p.TTLFloorKnown)
	}
	display := p.TTLDisplay()
	if !strings.Contains(display, "UNKNOWN") || !strings.Contains(display, "at least") {
		t.Fatalf("a floor must render as an unknown TTL with a lower bound, got %q", display)
	}
	// The floor is 96% of the parsed truth here, which is useful, and it is still not the TTL. If
	// this ever renders as "TTL 14m28s" the distinction has been lost.
	if strings.Contains(display, "parsed") {
		t.Fatalf("an observed floor was labelled parsed: %q", display)
	}
}

func TestOneSampleCannotShowRotationAndSaysSo(t *testing.T) {
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	obs := summariseCorpusSamples([]corpusSample{
		{Fingerprint: "aaaaaaaa", Count: 40, First: base, Last: base.Add(3 * time.Minute)},
	}, CredentialCarrier{Kind: "cookie", Name: "PHPSESSID"})
	if obs.RotationInterval != 0 {
		t.Fatalf("a rotation interval was computed from one value: %v", obs.RotationInterval)
	}
	if !strings.Contains(obs.Evidence, "cannot show rotation") {
		t.Fatalf("the single-sample limitation was not stated: %q", obs.Evidence)
	}
}

func TestAnEmptyCorpusIsReportedAsEmptyAndNotAsZero(t *testing.T) {
	obs := summariseCorpusSamples(nil, CredentialCarrier{Kind: "cookie", Name: "PHPSESSID"})
	if obs.Samples != 0 || obs.Floor != 0 {
		t.Fatalf("unexpected reading off an empty corpus: %+v", obs)
	}
	if !strings.Contains(obs.Evidence, "no request carrying") {
		t.Fatalf("an empty corpus must say so: %q", obs.Evidence)
	}
	p := SessionTokenProfile{}
	applyObservation(&p, obs)
	if p.TTLFloorKnown {
		t.Fatalf("a floor was recorded from an empty corpus")
	}
}

// A floor longer than the declared lifetime is a contradiction worth surfacing, because the most
// likely explanation is a sliding expiry and that changes the answer to "will it survive my run".
func TestAFloorLongerThanTheParsedTTLIsFlagged(t *testing.T) {
	p := SessionTokenProfile{TTL: 15 * time.Minute, TTLKnown: true, TTLProvenance: ProvParsed}
	applyObservation(&p, CorpusObservation{Samples: 3, Requests: 30, Floor: 3 * time.Hour, Evidence: "x"})
	if !warningsMention(p.Warnings, "sliding") {
		t.Fatalf("the contradiction was not reported: %v", p.Warnings)
	}
	if p.TTL != 15*time.Minute || p.TTLProvenance != ProvParsed {
		t.Fatalf("the observation overwrote the parsed TTL: %v via %s", p.TTL, p.TTLProvenance)
	}
}

// ---------------------------------------------------------------------------------------------
// Survives: three states, not two
// ---------------------------------------------------------------------------------------------

// A scan configuration gate that treats an unmeasured TTL as "fine" is the same failure as a
// scanner treating an unprobed pair as clean. Survives therefore returns known separately, and
// this test pins every branch.
func TestSurvivesDistinguishesNoFromUnknown(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	run := 29 * time.Minute

	cases := []struct {
		name      string
		profile   SessionTokenProfile
		wantOK    bool
		wantKnown bool
		mentions  string
	}{
		{
			name:      "a live expiry beyond the run is a measured yes",
			profile:   SessionTokenProfile{ExpiresAt: now.Add(2 * time.Hour), ExpiryKnown: true},
			wantOK:    true,
			wantKnown: true,
			mentions:  "of life left",
		},
		{
			name:      "an expiry inside the run is a measured no",
			profile:   SessionTokenProfile{ExpiresAt: now.Add(10 * time.Minute), ExpiryKnown: true},
			wantOK:    false,
			wantKnown: true,
			mentions:  "of life left",
		},
		{
			name:      "an expiry already passed is a measured no",
			profile:   SessionTokenProfile{ExpiresAt: now.Add(-time.Minute), ExpiryKnown: true},
			wantOK:    false,
			wantKnown: true,
			mentions:  "expired",
		},
		{
			name:      "a lifetime shorter than the run is a measured no whatever the clock says",
			profile:   SessionTokenProfile{TTL: 15 * time.Minute, TTLKnown: true},
			wantOK:    false,
			wantKnown: true,
			mentions:  "however fresh it is",
		},
		{
			name:      "a lifetime longer than the run with no issue time is UNKNOWN",
			profile:   SessionTokenProfile{TTL: 8 * time.Hour, TTLKnown: true},
			wantOK:    false,
			wantKnown: false,
			mentions:  "we do not know when this value was issued",
		},
		{
			name:      "a floor and nothing else is UNKNOWN",
			profile:   SessionTokenProfile{TTLFloor: 5 * time.Minute, TTLFloorKnown: true},
			wantOK:    false,
			wantKnown: false,
			mentions:  "never measured",
		},
		{
			name:      "nothing measured at all is UNKNOWN",
			profile:   SessionTokenProfile{},
			wantOK:    false,
			wantKnown: false,
			mentions:  "neither the expiry nor the lifetime",
		},
		{
			name:      "measured non-expiring is a yes",
			profile:   SessionTokenProfile{ExpiryStyle: ExpiryStyleNonExpiring, ExpiryProvenance: ProvProbed},
			wantOK:    true,
			wantKnown: true,
			mentions:  "non-expiring",
		},
		{
			// The same style with NOTHING behind it is not a yes. Nothing in this package can
			// currently produce non_expiring, so a profile carrying it came from a row somebody
			// wrote by hand or a writer that guessed, and a hard yes on a guess is the defect.
			name:      "non-expiring with no provenance is UNKNOWN",
			profile:   SessionTokenProfile{ExpiryStyle: ExpiryStyleNonExpiring},
			wantOK:    false,
			wantKnown: false,
			mentions:  "unmeasured claim",
		},
	}

	for _, tc := range cases {
		ok, known, why := tc.profile.Survives(run, now)
		if ok != tc.wantOK || known != tc.wantKnown {
			t.Errorf("%s: ok=%v known=%v, want ok=%v known=%v (%s)", tc.name, ok, known, tc.wantOK, tc.wantKnown, why)
		}
		if !strings.Contains(why, tc.mentions) {
			t.Errorf("%s: reason %q does not mention %q", tc.name, why, tc.mentions)
		}
	}
}

func TestASlidingExpiryIsSaidOutLoudWhenItWouldOtherwiseFail(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	p := SessionTokenProfile{ExpiresAt: now.Add(10 * time.Minute), ExpiryKnown: true, ExpiryStyle: ExpiryStyleSliding}
	_, _, why := p.Survives(29*time.Minute, now)
	if !strings.Contains(why, "sliding") {
		t.Fatalf("a sliding expiry inside the run must be mentioned: %q", why)
	}
}

// ---------------------------------------------------------------------------------------------
// Refresh proof
// ---------------------------------------------------------------------------------------------

// Validated requires a proof of concept. The proof of concept for a refresh is two fingerprints
// that differ; anything less is an endpoint that answered.
func TestARefreshProofNeedsTwoDifferentFingerprints(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ before, after, mentions string }{
		{"", "abcd1234", "before and after"},
		{"abcd1234", "", "before and after"},
		{"abcd1234", "abcd1234", "renewed nothing"},
	} {
		err := RecordRefreshProof(ctx, uuid.New().String(), tc.before, tc.after)
		if err == nil {
			t.Errorf("RecordRefreshProof(%q, %q) was accepted as a proof", tc.before, tc.after)
			continue
		}
		if !strings.Contains(err.Error(), tc.mentions) {
			t.Errorf("RecordRefreshProof(%q, %q): %v does not mention %q", tc.before, tc.after, err, tc.mentions)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------------

func TestHumaniseTTLRendersALifetimeTheWayAnOperatorReadsOne(t *testing.T) {
	cases := map[time.Duration]string{
		900 * time.Second:         "15m",
		868 * time.Second:         "14m28s",
		0:                         "0s",
		time.Hour + 5*time.Second: "1h5s",
		49 * time.Hour:            "2d1h",
		-90 * time.Second:         "-1m30s",
	}
	for d, want := range cases {
		if got := humaniseTTL(d); got != want {
			t.Errorf("humaniseTTL(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestNoOutputContainsAnEmdash(t *testing.T) {
	iat := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	tok := makeJWT(t, map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"iat": iat.Unix(), "exp": iat.Add(time.Hour).Unix(), "iss": "https://i.example.test"})
	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, iat)
	blob, _ := json.Marshal(p)
	surfaces := []string{p.String(), p.TTLDisplay(), p.ExpiryDisplay(), string(blob)}
	_, _, why := p.Survives(29*time.Minute, iat)
	surfaces = append(surfaces, why)
	for _, s := range surfaces {
		if strings.ContainsRune(s, rune(0x2014)) || strings.ContainsRune(s, rune(0x2013)) {
			t.Errorf("an output string contains a dash character that is not a hyphen: %q", s)
		}
	}
}

// A field called ttl_seconds that serialises nanoseconds is the defect this codebase keeps
// rediscovering under the name of a count that is not a count. A time.Duration marshals as
// nanoseconds by default, so 15 minutes would leave here as 900000000000 under a name that says
// seconds, and every consumer would be wrong in the same direction.
func TestDurationsAreMarshalledAsSecondsNotNanoseconds(t *testing.T) {
	p := SessionTokenProfile{
		TTL: 900 * time.Second, TTLKnown: true, TTLProvenance: ProvParsed, TTLEvidence: "exp minus nbf",
		TTLFloor: 868 * time.Second, TTLFloorKnown: true,
		RotationInterval: 22 * time.Second, RotationKnown: true,
	}
	blob, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for field, want := range map[string]float64{
		"ttl_seconds":               900,
		"ttl_floor_seconds":         868,
		"rotation_interval_seconds": 22,
	} {
		n, ok := got[field].(float64)
		if !ok {
			t.Fatalf("%s is missing or not a number: %v", field, got[field])
		}
		if n != want {
			t.Errorf("%s = %v, want %v; a duration was serialised in the wrong unit under a name that states one", field, n, want)
		}
	}
	// The rendered sentence rides along so a client cannot render an unknown as a number.
	if !strings.Contains(got["ttl_display"].(string), "15m") {
		t.Errorf("ttl_display = %v", got["ttl_display"])
	}
}

// And an UNKNOWN must not arrive at a client as the number zero with no way to tell.
func TestAnUnknownTTLMarshalsWithItsKnownFlagAndAnHonestDisplay(t *testing.T) {
	blob, err := json.Marshal(SessionTokenProfile{ExpiryStyle: ExpiryStyleUnknown, TTLProvenance: ProvUnknown})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["ttl_known"] != false {
		t.Fatalf("ttl_known = %v, want false", got["ttl_known"])
	}
	if got["ttl_seconds"].(float64) != 0 {
		t.Fatalf("ttl_seconds = %v", got["ttl_seconds"])
	}
	if got["ttl_display"] != "UNKNOWN" {
		t.Fatalf("ttl_display = %v, want UNKNOWN; a zero next to no display is how an unmeasured lifetime becomes a measured one", got["ttl_display"])
	}
}

// ---------------------------------------------------------------------------------------------
// Fixture hygiene
// ---------------------------------------------------------------------------------------------

// Everything in this file is invented. This checks it rather than asserting it: a fixture that
// looked like a real token would be a credential committed to the repository, and the round 10
// pattern being copied here is exactly a grep of the test material for token-shaped strings.
func TestNoTestFixtureLooksLikeARealCredential(t *testing.T) {
	iat := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fixtures := []string{
		makeJWT(t, map[string]interface{}{"alg": "RS256"}, map[string]interface{}{"iat": iat.Unix(), "exp": iat.Add(time.Hour).Unix()}),
		makeJWE(t, map[string]interface{}{"alg": "RSA-OAEP", "enc": "A256GCM"}),
		makePASETOPublic(t, "v2", map[string]interface{}{"exp": iat.Format(time.RFC3339)}),
		makeBranca(iat),
		makeSAML("2026-09-20T09:00:00Z", "2026-09-20T09:05:00Z", ""),
	}
	// Real issuers in this engagement are named in comments, never in a value.
	forbidden := []string{"tradetalk", "alpaca", "authx.staging", "GZY3M2YCG2P5UXW3"}
	for _, f := range fixtures {
		for _, bad := range forbidden {
			if strings.Contains(strings.ToLower(f), strings.ToLower(bad)) {
				t.Errorf("a fixture contains %q, which means it came from a real target", bad)
			}
		}
	}
}

func warningsMention(warnings []string, want string) bool {
	for _, w := range warnings {
		if strings.Contains(w, want) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// Against a real database
// ---------------------------------------------------------------------------------------------
//
// These use triageTestDB, so with no TRIAGE_TEST_DATABASE_URL they are recorded as NOT MEASURED
// and the package fails at the end of the run. A skip is not a pass.

// sessionTokenProfileTestToken inserts one session token under a fresh scope target and returns
// both ids. The whole row goes away with the target.
func sessionTokenProfileTestToken(t *testing.T, ctx context.Context, tok SessionToken) (string, string) {
	t.Helper()
	target := triageTestTarget(t, ctx)
	var id string
	err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens
		  (scope_target_id, name, token_type, header_name, cookie_name, param_name,
		   value_prefix, token_value, scope_domains, expires_at, is_active, auth_flow_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id::text`,
		target, tok.Name, tok.TokenType, tok.HeaderName, tok.CookieName, tok.ParamName,
		tok.ValuePrefix, tok.TokenValue, tok.ScopeDomains, tok.ExpiresAt, tok.IsActive,
		nullUUID(tok.AuthFlowID)).Scan(&id)
	if err != nil {
		t.Fatalf("insert session token: %v", err)
	}
	return target, id
}

// sessionTokenProfileTestCaptures writes captured requests carrying a given header value, so the
// corpus observation has something to read. The values are invented here and never come from a
// real session: each one appears twice, span apart, and a new one starts every spacing.
func sessionTokenProfileTestCaptures(t *testing.T, ctx context.Context, target, header string,
	values []string, at time.Time, spacing, span time.Duration) {
	t.Helper()
	var sessionID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO manual_crawl_sessions (scope_target_id, target_url, status)
		VALUES ($1, $2, 'completed') RETURNING id::text`,
		target, "https://app.example.test/").Scan(&sessionID); err != nil {
		t.Fatalf("insert crawl session: %v", err)
	}
	for _, value := range values {
		blob, _ := json.Marshal(map[string]string{strings.ToLower(header): value})
		for _, offset := range []time.Duration{0, span} {
			if _, err := dbPool.Exec(ctx, `
				INSERT INTO manual_crawl_captures
				  (session_id, scope_target_id, url, endpoint, method, status_code, headers, timestamp)
				VALUES ($1,$2,$3,$4,'GET',200,$5,$6)`,
				sessionID, target, "https://app.example.test/api/me", "/api/me",
				string(blob), at.Add(offset)); err != nil {
				t.Fatalf("insert capture: %v", err)
			}
		}
		at = at.Add(spacing)
	}
}

// The corpus reading has to come back with a floor and a rotation interval and NO TTL, and it has
// to name the value that produced the floor so the claim can be checked against the capture.
func TestCorpusObservationProducesAFloorAndNotATTL(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	sessionTokenProfileTestCaptures(t, ctx, target, "Authorization",
		[]string{"invented-value-one", "invented-value-two", "invented-value-three"},
		base, 600*time.Second, 300*time.Second)

	obs, err := ObserveCarrierInCorpus(ctx, target, CredentialCarrier{Kind: "header", Name: "Authorization"})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if obs.Samples != 3 || obs.Requests != 6 {
		t.Fatalf("samples=%d requests=%d, want 3 and 6", obs.Samples, obs.Requests)
	}
	if obs.Floor != 300*time.Second {
		t.Fatalf("floor = %v, want 300s", obs.Floor)
	}
	if obs.RotationInterval != 600*time.Second {
		t.Fatalf("rotation interval = %v, want 600s", obs.RotationInterval)
	}
	if !strings.Contains(obs.Evidence, obs.FloorValue) || obs.FloorValue == "" {
		t.Fatalf("the evidence does not name the value that produced the floor (%q): %q", obs.FloorValue, obs.Evidence)
	}
	if obs.FloorFingerprint != triageCredFingerprint(obs.FloorValue) {
		t.Fatalf("the floor join key does not match the value it names: %q vs %q",
			obs.FloorFingerprint, obs.FloorValue)
	}
}

// A cookie is picked out of the Cookie header by name, and a cookie whose name merely ENDS with
// the one we want must not be counted as it.
func TestCorpusObservationMatchesACookieByWholeName(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	sessionTokenProfileTestCaptures(t, ctx, target, "Cookie",
		[]string{"other_sid=decoy; sid=wanted-one; tail=x", "other_sid=decoy; sid=wanted-two; tail=x"},
		base, 120*time.Second, 60*time.Second)

	obs, err := ObserveCarrierInCorpus(ctx, target, CredentialCarrier{Kind: "cookie", Name: "sid"})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if obs.Samples != 2 {
		t.Fatalf("samples = %d, want 2; a cookie named other_sid was probably counted as sid", obs.Samples)
	}
	if obs.Floor != 60*time.Second {
		t.Fatalf("floor = %v, want 60s", obs.Floor)
	}
}

// Everything measured has to survive the round trip to the row and back, and an UNKNOWN has to
// come back unknown rather than as a zero.
func TestProfilePersistsAndAnUnknownStaysUnknown(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const opaque = "an-invented-opaque-session-value"
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "opaque session", TokenType: tokenTypeCookie, CookieName: "PHPSESSID",
		TokenValue: opaque, IsActive: true,
	})

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p, err := ProfileAndSaveSessionToken(ctx, tok)
	if err != nil {
		t.Fatalf("profile and save: %v", err)
	}
	if p.Kind != CredentialKindSessionID {
		t.Fatalf("kind = %s, want opaque_session_id", p.Kind)
	}

	// The column must be NULL, not zero. A zero here reads as "expires immediately" to every
	// later caller and is the single worst available lie about a lifetime.
	var ttl, floor *int64
	var kind, prov string
	if err := dbPool.QueryRow(ctx, `
		SELECT ttl_seconds, ttl_floor_seconds, COALESCE(credential_kind,''), COALESCE(ttl_provenance,'')
		FROM session_tokens WHERE id = $1`, tokenID).Scan(&ttl, &floor, &kind, &prov); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if ttl != nil {
		t.Fatalf("ttl_seconds = %d for a credential with no measurable lifetime; it must be NULL", *ttl)
	}
	if kind != string(CredentialKindSessionID) {
		t.Fatalf("credential_kind = %q", kind)
	}
	if prov != string(ProvUnknown) {
		t.Fatalf("ttl_provenance = %q, want unknown", prov)
	}

	back, err := LoadSessionTokenProfile(ctx, tokenID)
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	if back.TTLKnown {
		t.Fatalf("an unknown TTL came back known: %v", back.TTL)
	}
	if back.Kind != CredentialKindSessionID || back.Fingerprint != p.Fingerprint {
		t.Fatalf("round trip lost information: %+v", back)
	}
	if !strings.HasPrefix(back.TTLDisplay(), "UNKNOWN") {
		t.Fatalf("an unknown rendered as %q", back.TTLDisplay())
	}

	// THE PROSE COLUMNS USED TO BE CHECKED FOR THE ABSENCE OF THE CREDENTIAL, and that check is
	// gone rather than softened. kind_evidence, ttl_evidence, observed_evidence, profile_warnings,
	// refresh_detail and expiry_evidence are the columns an operator reads to find out what this
	// framework observed, and a credential is what it observed: refresh_detail now carries both
	// credentials of a proven refresh on purpose, because two hashes that differ are an assertion
	// and the two credentials are the proof of it.
}

// A parsed TTL and an observed floor are stored side by side, so a reader can see the
// corroboration instead of one silently replacing the other.
func TestAParsedTTLAndAnObservedFloorAreBothStored(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	issued := time.Now().UTC().Add(-2 * time.Minute)
	value := makeJWT(t, map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{"nbf": issued.Unix(), "exp": issued.Add(900 * time.Second).Unix(),
			"iss": "https://idp.example.test/v1"})

	target, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "bearer", TokenType: tokenTypeBearer, HeaderName: "Authorization",
		ValuePrefix: "Bearer ", TokenValue: value, IsActive: true,
	})
	sessionTokenProfileTestCaptures(t, ctx, target, "Authorization",
		[]string{"Bearer " + value}, issued, time.Minute, 868*time.Second)

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p, err := ProfileAndSaveSessionToken(ctx, tok)
	if err != nil {
		t.Fatalf("profile and save: %v", err)
	}
	if !p.TTLKnown || p.TTL != 900*time.Second || p.TTLProvenance != ProvParsed {
		t.Fatalf("parsed TTL = %v known=%v prov=%s", p.TTL, p.TTLKnown, p.TTLProvenance)
	}
	if !p.TTLFloorKnown || p.TTLFloor != 868*time.Second {
		t.Fatalf("observed floor = %v known=%v (%s)", p.TTLFloor, p.TTLFloorKnown, p.ObservedEvidence)
	}
	var ttl, floor *int64
	if err := dbPool.QueryRow(ctx,
		`SELECT ttl_seconds, ttl_floor_seconds FROM session_tokens WHERE id = $1`, tokenID).Scan(&ttl, &floor); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if ttl == nil || *ttl != 900 {
		t.Fatalf("ttl_seconds = %v, want 900", ttl)
	}
	if floor == nil || *floor != 868 {
		t.Fatalf("ttl_floor_seconds = %v, want 868", floor)
	}
}

// SCOPE IS A SEPARATE AXIS FROM POSSIBILITY.
//
// On the live target the session is minted at a host outside the engagement and the stored flow
// is named "DO NOT REPLAY - OUT OF SCOPE HOST". The engine must report that as mint_out_of_scope,
// with the host named, and never as not_observed: an operator who can re-authenticate by hand has
// a completely different plan from one whose session genuinely cannot be renewed.
func TestAnOutOfScopeMintIsReportedAndNotTreatedAsUnrefreshable(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	target := triageTestTarget(t, ctx)

	var flowID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO auth_flows (scope_target_id, category, name, base_url)
		VALUES ($1, 'login', $2, $3) RETURNING id::text`,
		target, "DO NOT REPLAY - OUT OF SCOPE HOST - session mint",
		"https://authx.elsewhere.test").Scan(&flowID); err != nil {
		t.Fatalf("insert auth flow: %v", err)
	}
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO auth_flow_steps (auth_flow_id, step_order, name, raw_request)
		VALUES ($1, 1, 'mint', 'POST /v1/oauth2/token HTTP/1.1')`, flowID); err != nil {
		t.Fatalf("insert step: %v", err)
	}

	issued := time.Now().UTC()
	value := makeJWT(t, map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{"nbf": issued.Unix(), "exp": issued.Add(900 * time.Second).Unix(),
			"iss": "https://authx.elsewhere.test/v1"})
	var tokenID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens (scope_target_id, name, token_type, header_name, value_prefix,
		   token_value, is_active, auth_flow_id)
		VALUES ($1,'bearer','bearer','Authorization','Bearer ',$2,TRUE,$3) RETURNING id::text`,
		target, value, flowID).Scan(&tokenID); err != nil {
		t.Fatalf("insert token: %v", err)
	}

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if p.Refresh.Status != RefreshMintOutOfScope {
		t.Fatalf("refresh status = %s, want mint_out_of_scope (evidence: %v)", p.Refresh.Status, p.Refresh.Evidence)
	}
	if p.Refresh.MintHost != "authx.elsewhere.test" {
		t.Fatalf("mint host = %q, want the host the flow and the issuer both name", p.Refresh.MintHost)
	}
	if p.Refresh.MintInScope {
		t.Fatalf("an out-of-scope mint was marked in scope")
	}
	joined := strings.Join(p.Refresh.Evidence, " | ")
	if !strings.Contains(joined, "do-not-replay") {
		t.Fatalf("the operator's own do-not-replay label was not honoured: %s", joined)
	}
}

// A refresh_token field existing is RefreshAvailable and never RefreshProven, and only
// RecordRefreshProof with two differing fingerprints moves it.
func TestARefreshTokenFieldIsAvailableAndOnlyAProofIsProven(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	target, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "bearer", TokenType: tokenTypeBearer, HeaderName: "Authorization",
		TokenValue: "an-invented-opaque-bearer-value", IsActive: true,
	})
	var sessionID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO manual_crawl_sessions (scope_target_id, target_url, status)
		VALUES ($1, 'https://app.example.test/', 'completed') RETURNING id::text`, target).Scan(&sessionID); err != nil {
		t.Fatalf("crawl session: %v", err)
	}
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO manual_crawl_captures (session_id, scope_target_id, url, endpoint, method, status_code, response_body)
		VALUES ($1,$2,'https://app.example.test/api/session','/api/session','POST',200,$3)`,
		sessionID, target, `{"access_token":"x","refresh_token":"y","expires_in":900}`); err != nil {
		t.Fatalf("capture: %v", err)
	}

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if p.Refresh.Status == RefreshProven {
		t.Fatalf("a refresh_token field was accepted as proof that a refresh works")
	}
	if p.Refresh.Status != RefreshAvailable {
		t.Fatalf("refresh status = %s, want available (evidence: %v)", p.Refresh.Status, p.Refresh.Evidence)
	}
	if !strings.Contains(strings.Join(p.Refresh.Evidence, " "), "NOT evidence a refresh works") {
		t.Fatalf("the distinction was not stated: %v", p.Refresh.Evidence)
	}
	// AND THE REFRESH TOKEN ITSELF IS IN THE EVIDENCE. A refresh token in a captured response is a
	// credential: it is what a session is renewed from, and a line saying one is there without
	// saying what it is can neither be checked nor spent.
	if !strings.Contains(strings.Join(p.Refresh.Evidence, " "), "the most recently captured one is y") {
		t.Fatalf("the refresh token the corpus carries was counted but not served: %v", p.Refresh.Evidence)
	}

	if err := RecordRefreshProof(ctx, tokenID, "aaaaaaaa", "bbbbbbbb",
		"an-invented-opaque-bearer-value", "a-different-invented-opaque-bearer-value"); err != nil {
		t.Fatalf("record proof: %v", err)
	}
	tok, _ = loadSessionToken(tokenID)
	p = ProfileSessionToken(ctx, tok)
	if p.Refresh.Status != RefreshProven {
		t.Fatalf("after a recorded proof the status is %s", p.Refresh.Status)
	}
	if p.Refresh.ProvenAt.IsZero() {
		t.Fatalf("a proven refresh has no timestamp")
	}
	// THE PROOF SHOWS BOTH CREDENTIALS. The claim is that a DIFFERENT credential came back, and
	// two hashes that differ are the assertion while the two credentials are the proof of it. The
	// detail column is what the Session Manager reads back to the operator.
	proven := strings.Join(p.Refresh.Evidence, " ")
	events := refreshProofEventText(t, ctx, tokenID)
	for _, want := range []string{"an-invented-opaque-bearer-value", "a-different-invented-opaque-bearer-value"} {
		if !strings.Contains(proven, want) {
			t.Errorf("the PROVEN evidence does not carry the credential %q: %q", want, proven)
		}
		if !strings.Contains(events, want) {
			t.Errorf("the refresh event row does not carry the credential %q: %s", want, events)
		}
	}
}

// A declared expires_at that disagrees with the credential's own exp is surfaced rather than
// silently losing one of them: it usually means the stored value was rotated underneath.
func TestADeclaredExpiryThatDisagreesWithTheTokenIsReported(t *testing.T) {
	ctx := triageTestDB(t)
	issued := time.Now().UTC()
	value := makeJWT(t, map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"iat": issued.Unix(), "exp": issued.Add(15 * time.Minute).Unix()})
	declared := issued.Add(365 * 24 * time.Hour)
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "bearer", TokenType: tokenTypeBearer, HeaderName: "Authorization",
		TokenValue: value, IsActive: true, ExpiresAt: &declared,
	})
	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if p.ExpiryProvenance != ProvParsed {
		t.Fatalf("a declared column overrode the credential's own exp: %s", p.ExpiryProvenance)
	}
	if !warningsMention(p.Warnings, "disagrees with the credential's own expiry") {
		t.Fatalf("the disagreement was not reported: %v", p.Warnings)
	}
}

// ===============================================================================================
// ROUND 12: THE PROFILER STATED A FACT IT DID NOT READ (fail-first block)
// ===============================================================================================

// randomOpaqueSessionID builds an invented session identifier of a given length over a given
// alphabet. It is deterministic: the generator is seeded per cell so a measured false positive
// rate is reproducible and the exact strings that produced it can be named.
func randomOpaqueSessionID(rng *rand.Rand, alphabet string, length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

// sweepCells are the shapes the verifier measured: the alphabets and lengths real applications
// actually use for an opaque session identifier.
var sweepCells = []struct {
	name     string
	alphabet string
	length   int
}{
	{"alnum-86", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 86},
	{"alnum-128", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 128},
	{"alnum-64", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 64},
	{"upperdigit-64", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 64},
	{"upperdigit-128", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 128},
	{"lowerhex-64", "0123456789abcdef", 64},
	// The three shapes below exist so the JOSE, PASETO and SAML recognisers are measured rather
	// than argued about, by giving them something they could in principle match. Branca still
	// fires on some of these, which is not a contradiction: base62 excludes the dot, the hyphen,
	// the underscore, the plus, the slash and the equals, so a value CONTAINING one cannot be a
	// Branca token, but a random draw from an alphabet that is mostly alnum often contains none
	// of them. The measured output says so out loud rather than leaving it to be assumed.
	{"alnum-dot-86", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.", 86},
	{"base64url-86", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_", 86},
	{"base64std-88", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/=", 88},
}

func sweepN(t *testing.T) int {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv("SESSION_PROFILE_SWEEP_N")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 20000
}

// NO RECOGNISER MAY STATE A FACT IT DECODED OUT OF RANDOM BYTES.
//
// A recogniser that matches a random session identifier does not merely mislabel it. Before the
// second witness went in, profileAsBranca reported an IssuedAt decoded out of four random bytes,
// with dates from 1979 to 2104, and that date is persisted to session_tokens.issued_at and shown
// to the operator as something the credential said.
//
// The sweep is the measurement, not an assertion of belief: it prints the rate per shape every
// run. Branca cannot be driven to zero, because a 0xBA version byte plus a plausible timestamp is
// the whole of what the format discloses without the key, so the ceiling here is the honest
// number and the log line beside it says what was actually measured.
func TestNoStructuredRecogniserFiresOnRandomOpaqueSessionIds(t *testing.T) {
	n := sweepN(t)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	// THE CARRIER IS PART OF THE MEASUREMENT. A cookie whose name a framework publishes as its own
	// session handle is a stronger witness about what the value is than one byte inside it, so the
	// sweep measures a published name and an unpublished one separately rather than reporting one
	// number that averages the two.
	//
	// ROUND 14 ADDS A THIRD COOKIE CELL. knownSessionCookies labels "session" generic, so it no
	// longer vetoes the Branca recogniser and the cost of that decision has to be MEASURED here
	// rather than argued about: it is the rate at which a random opaque handle in a cookie called
	// session is reported as a Branca token, and it is held to the same ceiling as everything else.
	carriers := []CredentialCarrier{
		{Kind: "cookie", Name: "app_sid"},
		{Kind: "cookie", Name: "session"},
		{Kind: "cookie", Name: "PHPSESSID"},
		{Kind: "bearer", Name: "Authorization"},
	}
	total := map[CredentialKind]int{}
	drawn := 0
	for _, carrier := range carriers {
		perCarrier := map[CredentialKind]int{}
		for _, cell := range sweepCells {
			rng := rand.New(rand.NewSource(int64(len(cell.alphabet)*1000 + cell.length)))
			hits := map[CredentialKind]int{}
			var examples []string
			for i := 0; i < n; i++ {
				v := randomOpaqueSessionID(rng, cell.alphabet, cell.length)
				p := ProfileCredential(NewCredential(v), carrier, now)
				drawn++
				switch p.Kind {
				case CredentialKindSessionID, CredentialKindOpaqueBearer, CredentialKindUnknown:
					continue
				}
				hits[p.Kind]++
				perCarrier[p.Kind]++
				total[p.Kind]++
				if len(examples) < 3 {
					examples = append(examples, fmt.Sprintf("%s issued_at=%v known=%v %q",
						p.Kind, p.IssuedAt.Format(time.RFC3339), p.IssuedAtKnown, v))
				}
			}
			if len(hits) == 0 {
				t.Logf("SWEEP %-13s %-15s n=%d: no recogniser fired", carrier.Name, cell.name, n)
			}
			for kind, c := range hits {
				t.Logf("SWEEP %-13s %-15s n=%d kind=%-10s %d = %.4f%%", carrier.Name, cell.name, n, kind, c, 100*float64(c)/float64(n))
			}
			for _, e := range examples {
				t.Logf("SWEEP %-13s %-15s example: %s", carrier.Name, cell.name, e)
			}
		}
		t.Logf("SWEEP %-13s TOTAL over %d values: %v", carrier.Name, len(sweepCells)*n, perCarrier)
		// A PUBLISHED SESSION COOKIE NAME IS THE ONE CELL THAT CAN BE DRIVEN TO ZERO, because the
		// name is a fact about the application and not a one in 256 draw.
		if carrier.Name == "PHPSESSID" && len(perCarrier) > 0 {
			t.Errorf("a recogniser fired on %v inside a cookie whose name PHP publishes as its session handle", perCarrier)
		}
	}
	for kind, c := range total {
		// Branca is the one recogniser the format does not let anybody close completely. Every
		// other kind is a literal prefix, a segment count or a published key shape, and a random
		// session identifier must never reach one.
		if kind != CredentialKindBranca {
			t.Errorf("%d random opaque session identifiers were reported as %s; that recogniser fires on random bytes", c, kind)
		}
	}
	// THE RESIDUAL IS ARITHMETIC, NOT AN OPINION. What is left of the Branca recogniser after the
	// timestamp window is one version byte (1 in 256) times the share of four random bytes that
	// land between 2017 and the profiling clock plus a day (about 7.1%), which is 0.028% of the
	// values that can decode to 45 bytes at all. The ceiling below is that floor with room for the
	// draw, and it is the honest number: a lower one could only be bought with an assumption about
	// the application, which is the defect this file exists to prevent.
	ceiling := drawn / 2000 // 0.05% of everything generated
	if total[CredentialKindBranca] > ceiling {
		t.Errorf("%d of %d random opaque session identifiers were reported as Branca, over the ceiling of %d; the second witness is not holding",
			total[CredentialKindBranca], drawn, ceiling)
	}
}

// THE API KEY FORMATS, MEASURED WHERE THEY ACTUALLY FIRE.
//
// A prefix of four characters is unreachable by chance in a long random value, so the sweep above
// almost never exercises these formats; the one hit the round 12 verifier measured over 10.8M
// values was a ghs_ prefix on a 43 character base64url value. This measures the rate CONDITIONAL
// on the prefix being there, which is the number that matters: every value here already carries
// it, and what is being measured is whether the rest of the format is checked at all.
func TestTheAPIKeyFormatsAreMeasuredOnValuesThatCarryThePrefix(t *testing.T) {
	n := sweepN(t) / 2
	if n < 1000 {
		n = 1000
	}
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	carrier := CredentialCarrier{Kind: "bearer", Name: "Authorization"}
	const base64url = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
	cells := []struct {
		prefix string
		body   int
		want   string
	}{
		// The measured one: 43 characters in all, so 39 of key material, and a GitHub server
		// token has 36. Nothing of this length is one.
		{"ghs_", 39, "no length of 39 can be a GitHub token"},
		{"ghp_", 20, "too short"},
		{"gho_", 60, "too long"},
		{"npm_", 39, "npm tokens are 36 characters of base62"},
		// The residual: the right LENGTH, drawn from base64url. It matches only when all 36
		// characters happen to miss the hyphen and the underscore, which is (62/64)^36.
		{"ghs_", 36, "right length, so the alphabet is the only witness left"},
	}
	for _, cell := range cells {
		rng := rand.New(rand.NewSource(int64(len(cell.prefix)*7919 + cell.body)))
		hits := 0
		for i := 0; i < n; i++ {
			v := cell.prefix + randomOpaqueSessionID(rng, base64url, cell.body)
			if p := ProfileCredential(NewCredential(v), carrier, now); p.Kind == CredentialKindAPIKey {
				hits++
			}
		}
		t.Logf("APIKEY %s+%d n=%d hits=%d = %.4f%% (%s)", cell.prefix, cell.body, n, hits,
			100*float64(hits)/float64(n), cell.want)
		if cell.body != 36 && hits > 0 {
			t.Errorf("%d of %d random values of %s plus %d characters were called a key; that length is not the published one",
				hits, n, cell.prefix, cell.body)
		}
	}
}

// The five values below were produced by the fail-first sweep against the version byte alone.
// Each one is invented, each one decoded to a 0xBA byte, and each one made the profiler report a
// Branca token with an issue time it had decoded out of noise. They are pinned here so the fix
// cannot regress quietly: the sweep is statistical, this is not.
func TestTheRandomValuesThatBecameBrancaTokensAreOpaqueAgain(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	invented := map[string]string{
		"2067-10-17": "hLq2RJbmZvxaSDLf0tDP5tR5OtN0DeBhcSlMJlKXYTcAxvJZVaEqTMJJ0JMFudovSzQrFD6vtbqQdNL1LwK6sY",
		"1980-03-24": "AFAk7pMqCS5ctcToUT2XVuGYCP3s7M3cJlyCA4zGNdiGAu3FCT2hQXNbfyMriK4GoIhIZsSFg8M3x8jChtDzGklVGrGmUZaoJdpHUafmWy0dNGCRFRLbt8N7EWNfR0um",
		"1995-06-04": "1LJHchvfAjKUaVfD40XEaIiyjRlgPjPE02QthUeOl0yVFywh5uiXaNglpqZgAAdX",
		"2104-03-25": "AIHZAXFJ1KU7BPAOSX3UJ5D3WIN3KEAJ7ETDP1OLRAOYFBEEYAEPB34PAWKM5S6GN9GOVLC8G4O0814RK8UDMO19Q3DV7UCA4HXD0QDJR07OZF8VHTWF2KQD2YPF3ETJ",
		"1989-07-22": "1LI5SQ33HJD60KGEB1Y3AZKBPCXOXBN70OACJV5RW7N463O0415QOVSXU3TADUE8",
	}
	for inventedDate, value := range invented {
		p := ProfileCredential(NewCredential(value), CredentialCarrier{Kind: "cookie", Name: "app_sid"}, now)
		if p.Kind == CredentialKindBranca {
			t.Errorf("the value that used to report an issue time of %s is still a Branca token", inventedDate)
		}
		if p.IssuedAtKnown {
			t.Errorf("an issue time of %s is still being claimed for a random value", p.IssuedAt.Format(time.RFC3339))
		}
		if p.Kind != CredentialKindSessionID {
			t.Errorf("kind = %s, want the opaque answer", p.Kind)
		}
	}

	// And a genuine Branca token, whose timestamp is inside the window, still reads as one.
	real := makeBranca(now.Add(-10 * time.Minute))
	p := ProfileCredential(NewCredential(real), CredentialCarrier{Kind: "cookie", Name: "app_sid"}, now)
	if p.Kind != CredentialKindBranca || !p.IssuedAtKnown {
		t.Fatalf("a real Branca token was refused by the plausibility window: kind=%s known=%v", p.Kind, p.IssuedAtKnown)
	}
	// A Branca token minted before the format existed is not one either.
	ancient := makeBranca(time.Date(1999, 5, 5, 0, 0, 0, 0, time.UTC))
	if q := ProfileCredential(NewCredential(ancient), CredentialCarrier{Kind: "cookie", Name: "app_sid"}, now); q.Kind == CredentialKindBranca {
		t.Errorf("a token claiming to predate the Branca format was accepted as one")
	}
	// Nor is one minted in the future.
	future := makeBranca(now.Add(72 * time.Hour))
	if q := ProfileCredential(NewCredential(future), CredentialCarrier{Kind: "cookie", Name: "app_sid"}, now); q.Kind == CredentialKindBranca {
		t.Errorf("a token claiming to have been issued in the future was accepted as one")
	}
}

// A published key format is a prefix AND a shape. Four uppercase characters are not evidence on
// their own: the fail-first sweep turned one random 128 character value into an AWS access key id,
// and an AWS access key id is twenty characters.
func TestAnAPIKeyPrefixWithoutTheKeyShapeIsNotAKey(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	carrier := CredentialCarrier{Kind: "bearer", Name: "Authorization"}
	notKeys := []string{
		"AKIA" + strings.Repeat("Q", 90),                // right prefix, wrong length
		"AKIAlowercaseisnotinthealphabet0",              // right prefix, wrong alphabet
		"AIza" + strings.Repeat("B", 12),                // too short for a Google key
		"sk_live_",                                      // a prefix and nothing else
		"SG.noseconddotsotherestcannotbeakey0000000000", // SendGrid keys have two dots
	}
	for _, value := range notKeys {
		if p := ProfileCredential(NewCredential(value), carrier, now); p.Kind == CredentialKindAPIKey {
			t.Errorf("%q was called an API key on a prefix alone: %s", value, p.KindEvidence)
		}
	}
	areKeys := []string{
		"AKIA" + strings.Repeat("Q", 16),
		"AIza" + strings.Repeat("B", 35),
		"sk_live_0000000000000000example",
		"ghp_" + strings.Repeat("a", 36),
	}
	for _, value := range areKeys {
		if p := ProfileCredential(NewCredential(value), carrier, now); p.Kind != CredentialKindAPIKey {
			t.Errorf("%q is a published key format and was reported as %s", value, p.Kind)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// The ten shape matrix, measured off the wire
// ---------------------------------------------------------------------------------------------

// tenShapeApp is one real application. Each one ISSUES its credential over HTTP and the harness
// takes the credential and the issuing response the way a capture would, so nothing in this table
// is hand-fed: if a lifetime is on the wire and the profile says UNKNOWN, that is the defect.
type tenShapeApp struct {
	name         string
	path         string
	issue        func(w http.ResponseWriter, r *http.Request, now time.Time)
	carrierOf    func(resp *http.Response, body string) CredentialCarrier
	pick         func(t *testing.T, resp *http.Response, body string) string
	wantKind     CredentialKind
	wantTTL      time.Duration
	wantTTLKnown bool
	wantProv     Provenance
	wantStyle    ExpiryStyle
}

func wireCookieCarrier(name string) func(*http.Response, string) CredentialCarrier {
	return func(*http.Response, string) CredentialCarrier {
		return CredentialCarrier{Kind: "cookie", Name: name}
	}
}

func wireBearerCarrier() func(*http.Response, string) CredentialCarrier {
	return func(*http.Response, string) CredentialCarrier {
		return CredentialCarrier{Kind: "bearer", Name: "Authorization", Prefix: "Bearer "}
	}
}

func wirePickCookie(name string) func(*testing.T, *http.Response, string) string {
	return func(t *testing.T, resp *http.Response, _ string) string {
		t.Helper()
		for _, c := range resp.Cookies() {
			if c.Name == name {
				return c.Value
			}
		}
		t.Fatalf("the application did not set a %s cookie", name)
		return ""
	}
}

func wirePickJSONField(field string) func(*testing.T, *http.Response, string) string {
	return func(t *testing.T, _ *http.Response, body string) string {
		t.Helper()
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("the application body is not JSON: %v", err)
		}
		s, _ := m[field].(string)
		if s == "" {
			t.Fatalf("the application body has no %s", field)
		}
		return s
	}
}

// wireJWT and wirePASETO are the fixture builders without a *testing.T, because the ten
// applications build their credential inside an HTTP handler where there is no t to fail on.
func wireJWT(header, claims map[string]interface{}) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	return b64url(h) + "." + b64url(c) + "." + b64url([]byte("signature-not-verified"))
}

func wirePASETO(version string, claims map[string]interface{}) string {
	c, _ := json.Marshal(claims)
	return version + ".public." + b64url(append(c, bytes.Repeat([]byte{0x01}, 64)...))
}

// tenShapeApps are the ten applications. The invented credential values are spelled out here so
// no fixture can be mistaken for something that came off a real target.
func tenShapeApps() []tenShapeApp {
	return []tenShapeApp{
		{
			name: "PHPSESSID, no expiry", path: "/php",
			issue: func(w http.ResponseWriter, _ *http.Request, _ time.Time) {
				w.Header().Set("Set-Cookie", "PHPSESSID=invented0php0session0handle0000000000; Path=/; HttpOnly")
				w.Write([]byte("{\"ok\":true}"))
			},
			carrierOf: wireCookieCarrier("PHPSESSID"), pick: wirePickCookie("PHPSESSID"),
			wantKind: CredentialKindSessionID, wantProv: ProvUnknown, wantStyle: ExpiryStyleSession,
		},
		{
			name: "cookie Max-Age=3600", path: "/maxage",
			issue: func(w http.ResponseWriter, _ *http.Request, _ time.Time) {
				w.Header().Set("Set-Cookie", "app_sid=invented0maxage0session0handle000000; Path=/; Max-Age=3600; HttpOnly")
				w.Write([]byte("{\"ok\":true}"))
			},
			carrierOf: wireCookieCarrier("app_sid"), pick: wirePickCookie("app_sid"),
			wantKind: CredentialKindSessionID, wantTTL: time.Hour, wantTTLKnown: true,
			wantProv: ProvParsed, wantStyle: ExpiryStyleAbsolute,
		},
		{
			name: "cookie Expires, no Max-Age", path: "/expires",
			issue: func(w http.ResponseWriter, _ *http.Request, now time.Time) {
				w.Header().Set("Set-Cookie", "app_sid=invented0expires0session0handle00000; Path=/; Expires="+
					now.Add(2*time.Hour).Format(time.RFC1123))
				w.Write([]byte("{\"ok\":true}"))
			},
			carrierOf: wireCookieCarrier("app_sid"), pick: wirePickCookie("app_sid"),
			wantKind: CredentialKindSessionID, wantTTL: 2 * time.Hour, wantTTLKnown: true,
			wantProv: ProvParsed, wantStyle: ExpiryStyleAbsolute,
		},
		{
			name: "OAuth access+refresh expires_in", path: "/oauth/token",
			issue: func(w http.ResponseWriter, _ *http.Request, _ time.Time) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte("{\"access_token\":\"invented-opaque-access\",\"token_type\":\"Bearer\"," +
					"\"expires_in\":3600,\"refresh_token\":\"invented-opaque-refresh\",\"scope\":\"read\"}"))
			},
			carrierOf: wireBearerCarrier(), pick: wirePickJSONField("access_token"),
			wantKind: CredentialKindOAuthAccess, wantTTL: time.Hour, wantTTLKnown: true,
			wantProv: ProvParsed, wantStyle: ExpiryStyleAbsolute,
		},
		{
			name: "JWT exp, no iat", path: "/jwt-exp-only",
			issue: func(w http.ResponseWriter, _ *http.Request, now time.Time) {
				tok := wireJWT(map[string]interface{}{"alg": "RS256"},
					map[string]interface{}{"exp": now.Add(20 * time.Minute).Unix(), "sub": "invented-subject"})
				w.Write([]byte("{\"token\":\"" + tok + "\"}"))
			},
			carrierOf: wireBearerCarrier(), pick: wirePickJSONField("token"),
			wantKind: CredentialKindJWT, wantProv: ProvUnknown, wantStyle: ExpiryStyleAbsolute,
		},
		{
			name: "JWT alg:none", path: "/jwt-none",
			issue: func(w http.ResponseWriter, _ *http.Request, now time.Time) {
				tok := wireJWT(map[string]interface{}{"alg": "none"},
					map[string]interface{}{"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()})
				w.Write([]byte("{\"token\":\"" + tok + "\"}"))
			},
			carrierOf: wireBearerCarrier(), pick: wirePickJSONField("token"),
			wantKind: CredentialKindJWT, wantTTL: 10 * time.Minute, wantTTLKnown: true,
			wantProv: ProvParsed, wantStyle: ExpiryStyleAbsolute,
		},
		{
			name: "malformed, not base64", path: "/malformed",
			issue: func(w http.ResponseWriter, _ *http.Request, _ time.Time) {
				w.Write([]byte("{\"token\":\"not.a.token!!\"}"))
			},
			carrierOf: wireBearerCarrier(), pick: wirePickJSONField("token"),
			wantKind: CredentialKindOpaqueBearer, wantProv: ProvUnknown, wantStyle: ExpiryStyleUnknown,
		},
		{
			name: "API key sk_live_", path: "/apikey",
			issue: func(w http.ResponseWriter, _ *http.Request, _ time.Time) {
				w.Write([]byte("{\"token\":\"sk_live_0000000000000000fixture\"}"))
			},
			carrierOf: wireBearerCarrier(), pick: wirePickJSONField("token"),
			wantKind: CredentialKindAPIKey, wantProv: ProvUnknown, wantStyle: ExpiryStyleUnknown,
		},
		{
			name: "JWT exp+nbf", path: "/jwt-nbf",
			issue: func(w http.ResponseWriter, _ *http.Request, now time.Time) {
				tok := wireJWT(map[string]interface{}{"alg": "ES256"},
					map[string]interface{}{"nbf": now.Unix(), "exp": now.Add(15 * time.Minute).Unix()})
				w.Write([]byte("{\"token\":\"" + tok + "\"}"))
			},
			carrierOf: wireBearerCarrier(), pick: wirePickJSONField("token"),
			wantKind: CredentialKindJWT, wantTTL: 15 * time.Minute, wantTTLKnown: true,
			wantProv: ProvParsed, wantStyle: ExpiryStyleAbsolute,
		},
		{
			name: "PASETO v2.public", path: "/paseto",
			issue: func(w http.ResponseWriter, _ *http.Request, now time.Time) {
				tok := wirePASETO("v2", map[string]interface{}{
					"iat": now.Format(time.RFC3339), "exp": now.Add(30 * time.Minute).Format(time.RFC3339)})
				w.Write([]byte("{\"token\":\"" + tok + "\"}"))
			},
			carrierOf: wireBearerCarrier(), pick: wirePickJSONField("token"),
			wantKind: CredentialKindPASETO, wantTTL: 30 * time.Minute, wantTTLKnown: true,
			wantProv: ProvParsed, wantStyle: ExpiryStyleAbsolute,
		},
	}
}

// EVERY ANSWER THAT WAS ON THE WIRE MUST REACH THE PROFILE.
//
// Four of these ten applications state the lifetime in the response that issues the credential
// rather than in the credential itself: a Max-Age, an Expires, a session cookie with neither, and
// an OAuth expires_in. A profiler that reads only the credential bytes reports UNKNOWN for all
// four, which is most of the web.
func TestTheTenShapeMatrixIsMeasuredOffTheWire(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	apps := tenShapeApps()
	mux := http.NewServeMux()
	for i := range apps {
		app := apps[i]
		mux.HandleFunc(app.path, func(w http.ResponseWriter, r *http.Request) { app.issue(w, r, now) })
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, app := range apps {
		t.Run(app.name, func(t *testing.T) {
			resp, err := http.Get(srv.URL + app.path)
			if err != nil {
				t.Fatalf("GET %s: %v", app.path, err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body := string(raw)

			value := app.pick(t, resp, body)
			carrier := app.carrierOf(resp, body)
			p := profileOffTheWire(value, carrier, resp, body, now)

			t.Logf("MATRIX %-30s kind=%-18s ttl_known=%-5v ttl=%-12s prov=%-8s style=%s",
				app.name, p.Kind, p.TTLKnown, p.TTLDisplay(), p.TTLProvenance, p.ExpiryStyle)

			if p.Kind != app.wantKind {
				t.Errorf("kind = %s, want %s", p.Kind, app.wantKind)
			}
			if p.TTLKnown != app.wantTTLKnown {
				t.Errorf("ttl_known = %v, want %v (ttl_display %q)", p.TTLKnown, app.wantTTLKnown, p.TTLDisplay())
			}
			if app.wantTTLKnown && p.TTL != app.wantTTL {
				t.Errorf("ttl = %v, want %v", p.TTL, app.wantTTL)
			}
			if p.TTLProvenance != app.wantProv {
				t.Errorf("ttl_provenance = %s, want %s", p.TTLProvenance, app.wantProv)
			}
			if p.ExpiryStyle != app.wantStyle {
				t.Errorf("expiry_style = %s, want %s", p.ExpiryStyle, app.wantStyle)
			}

		})
	}
}

// profileOffTheWire is the harness the ten applications run through. It takes the issuing
// response exactly as a capture would: every Set-Cookie header and, where the body is a token
// endpoint response, the body, both whole and unedited, which is what the corpus query hands back
// out of Postgres too.
func profileOffTheWire(value string, carrier CredentialCarrier, resp *http.Response, body string, now time.Time) SessionTokenProfile {
	ev := CredentialEvidence{}
	for _, sc := range resp.Header.Values("Set-Cookie") {
		ev.SetCookies = append(ev.SetCookies, NewSetCookieObservation(sc, now))
	}
	if strings.Contains(body, "\"access_token\"") {
		ev.TokenResponses = append(ev.TokenResponses, NewTokenResponseObservation(body, now))
	}
	return ProfileCredentialWithEvidence(NewCredential(value), carrier, ev, now)
}

// ---------------------------------------------------------------------------------------------
// Opening the card must not edit the credential
// ---------------------------------------------------------------------------------------------

// MEASURING IS NOT EDITING. AttachSessionTokenProfiles characterises a token on the READ path, so
// every time an operator opens the Session Manager or the investigate card, SaveSessionTokenProfile
// runs. If that write touches updated_at, then merely looking at a credential moves the operator's
// "last edited" stamp on it, and the column that says when a human last changed the row becomes a
// column that says when a machine last looked at it. profiled_at already records the measurement.
//
// This tree has been bitten by an updated_at trap before: a built flow's verified state became
// structurally unreachable because something else touched the column it was compared against.
func TestProfilingDoesNotMoveTheOperatorsLastEditedStamp(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "opaque session", TokenType: tokenTypeCookie, CookieName: "PHPSESSID",
		TokenValue: "an-invented-opaque-session-value-for-the-stamp", IsActive: true,
	})

	// Backdate the stamp rather than sleeping, so the test measures the write and not the clock.
	edited := time.Date(2026, 9, 1, 8, 30, 0, 0, time.UTC)
	if _, err := dbPool.Exec(ctx, `UPDATE session_tokens SET updated_at = $2 WHERE id = $1`, tokenID, edited); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := ProfileAndSaveSessionToken(ctx, tok); err != nil {
		t.Fatalf("profile and save: %v", err)
	}

	var after time.Time
	var profiledAt *time.Time
	if err := dbPool.QueryRow(ctx,
		`SELECT updated_at, profiled_at FROM session_tokens WHERE id = $1`, tokenID).Scan(&after, &profiledAt); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !after.UTC().Equal(edited) {
		t.Errorf("updated_at moved from %s to %s just by profiling the credential; opening the card is not an edit",
			edited.Format(time.RFC3339), after.UTC().Format(time.RFC3339))
	}
	if profiledAt == nil {
		t.Errorf("profiled_at was not written, so the measurement has no timestamp of its own")
	}
}

// ---------------------------------------------------------------------------------------------
// A vocabulary value nothing can produce is a claim the type makes and the code cannot honour
// ---------------------------------------------------------------------------------------------

// Survives grants a HARD YES on a non-expiring style. Nothing in this package measures one, so the
// only way a profile can carry it is a database row somebody wrote by hand or a future writer that
// guessed. A yes that no measurement stands behind is the same defect as a scanner calling an
// unprobed pair clean, so the style alone must not be enough: the provenance has to name a method
// that could have established it.
func TestANonExpiringStyleWithNoMeasurementBehindItIsNotAYes(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	p := SessionTokenProfile{
		ExpiryStyle:      ExpiryStyleNonExpiring,
		ExpiryProvenance: ProvUnknown,
		TTLProvenance:    ProvUnknown,
	}
	ok, known, why := p.Survives(29*time.Minute, now)
	if ok || known {
		t.Errorf("Survives = (ok=%v known=%v) %q for a non-expiring style with provenance %q; nothing measured that",
			ok, known, why, p.ExpiryProvenance)
	}

	// And a style that WAS established by a method that can establish it still answers yes.
	measured := SessionTokenProfile{ExpiryStyle: ExpiryStyleNonExpiring, ExpiryProvenance: ProvProbed}
	if ok, known, _ := measured.Survives(29*time.Minute, now); !ok || !known {
		t.Errorf("a probed non-expiring credential must still survive: ok=%v known=%v", ok, known)
	}
}

// ---------------------------------------------------------------------------------------------
// The issuing response, read out of the corpus
// ---------------------------------------------------------------------------------------------

// sessionTokenProfileTestResponses writes captures that carry RESPONSE headers and bodies, which
// is where the lifetime of an opaque credential is stated. The header blob is written the way the
// capture extension writes it, as a JSON object whose value may be a string or a list.
func sessionTokenProfileTestResponses(t *testing.T, ctx context.Context, target string,
	responses []struct {
		Headers map[string]interface{}
		Body    string
		At      time.Time
	}) {
	t.Helper()
	var sessionID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO manual_crawl_sessions (scope_target_id, target_url, status)
		VALUES ($1, $2, 'completed') RETURNING id::text`,
		target, "https://app.example.test/").Scan(&sessionID); err != nil {
		t.Fatalf("insert crawl session: %v", err)
	}
	for _, r := range responses {
		blob, err := json.Marshal(r.Headers)
		if err != nil {
			t.Fatalf("marshal response headers: %v", err)
		}
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO manual_crawl_captures
			  (session_id, scope_target_id, url, endpoint, method, status_code,
			   headers, response_headers, response_body, timestamp)
			VALUES ($1,$2,$3,$4,'POST',200,'{}'::jsonb,$5,$6,$7)`,
			sessionID, target, "https://app.example.test/login", "/login",
			string(blob), r.Body, r.At); err != nil {
			t.Fatalf("insert capture: %v", err)
		}
	}
}

type testResponse = struct {
	Headers map[string]interface{}
	Body    string
	At      time.Time
}

// A COOKIE APPLICATION IS MOST OF THE WEB AND IT GOT NOTHING.
//
// The cookie value states no lifetime, by design. The Set-Cookie that issued it states all of it,
// and until the parsers were wired in, the profile of a Max-Age=3600 session cookie read UNKNOWN
// while the helper sitting beside it in this same file said one hour off the same bytes.
//
// The second half of this test is the rule that makes the first half safe: the credential value
// must never come back out of Postgres. Only the fingerprint and the attribute tail cross.
func TestTheSetCookieThatIssuedACredentialReachesTheProfile(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const value = "invented-cookie-value-for-the-corpus"
	issued := time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Second)

	target, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "app session", TokenType: tokenTypeCookie, CookieName: "app_sid",
		TokenValue: value, IsActive: true,
	})
	sessionTokenProfileTestResponses(t, ctx, target, []testResponse{
		{
			Headers: map[string]interface{}{
				"content-type": "application/json",
				// The list form, which is what several cookies on one response look like.
				"set-cookie": []string{
					"other_cookie=invented-other-value; Path=/",
					"app_sid=" + value + "; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax",
				},
			},
			Body: "{\"ok\":true}",
			At:   issued,
		},
	})

	ev, err := GatherIssuingEvidence(ctx, target, CredentialCarrier{Kind: "cookie", Name: "app_sid"})
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(ev.SetCookies) != 1 {
		t.Fatalf("got %d Set-Cookie observations, want exactly the one for app_sid: %+v", len(ev.SetCookies), ev.SetCookies)
	}
	obs := ev.SetCookies[0]
	if !strings.Contains(obs.Header, value) {
		t.Fatalf("the cookie value did not come back out of Postgres in the header, so the evidence is gone: %q", obs.Header)
	}
	if obs.Value != value {
		t.Fatalf("obs.Value = %q, want the captured cookie value %q", obs.Value, value)
	}
	if obs.ValueFingerprint != triageCredFingerprint(value) {
		t.Fatalf("value_fingerprint = %q, want %q; without it the evidence cannot be tied to this credential",
			obs.ValueFingerprint, triageCredFingerprint(value))
	}
	if !strings.Contains(obs.Header, "Max-Age=3600") {
		t.Fatalf("the attributes did not survive: %q", obs.Header)
	}

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if !p.TTLKnown || p.TTL != time.Hour {
		t.Fatalf("ttl = %v known=%v, want one hour; the answer was on the wire (%s)", p.TTL, p.TTLKnown, p.TTLDisplay())
	}
	if p.TTLProvenance != ProvParsed {
		t.Fatalf("ttl_provenance = %s, want parsed", p.TTLProvenance)
	}
	if !strings.Contains(p.TTLEvidence, "Max-Age") {
		t.Fatalf("the evidence does not name what was read: %q", p.TTLEvidence)
	}
	if !p.ExpiryKnown || !p.ExpiresAt.Equal(issued.Add(time.Hour)) {
		t.Fatalf("expires_at = %v known=%v, want %v", p.ExpiresAt, p.ExpiryKnown, issued.Add(time.Hour))
	}

}

// A SESSION COOKIE IS ITS OWN ANSWER AND NOT AN UNKNOWN, and the corpus is where that is read.
func TestASessionCookieInTheCorpusIsReportedAsOneRatherThanAsUnknown(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const value = "invented0php0handle0000000000000"
	target, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "php session", TokenType: tokenTypeCookie, CookieName: "PHPSESSID",
		TokenValue: value, IsActive: true,
	})
	sessionTokenProfileTestResponses(t, ctx, target, []testResponse{
		{
			Headers: map[string]interface{}{"set-cookie": "PHPSESSID=" + value + "; Path=/; HttpOnly"},
			Body:    "{\"ok\":true}",
			At:      time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second),
		},
	})

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if p.ExpiryStyle != ExpiryStyleSession {
		t.Fatalf("expiry_style = %s, want session; a cookie with neither Max-Age nor Expires has no wall-clock expiry at all, which is a different answer from unknown", p.ExpiryStyle)
	}
	if p.TTLKnown {
		t.Fatalf("a TTL of %v was produced for a session cookie, which states none", p.TTL)
	}
	if !strings.Contains(p.ExpiryDisplay(), "dies with the browser session") {
		t.Fatalf("expiry_display = %q", p.ExpiryDisplay())
	}
}

// AN OAUTH ACCESS TOKEN IS THE CASE WHERE AN OPAQUE VALUE HAS A PARSED LIFETIME, and the value it
// belongs to is decided by fingerprint: an expires_in from the response that minted somebody
// else's token is not a fact about this one.
func TestTheTokenEndpointResponseIsAppliedOnlyToTheCredentialItIssued(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const mine = "invented-access-token-value-mine"
	const theirs = "invented-access-token-value-theirs"
	minted := time.Now().UTC().Add(-3 * time.Minute).Truncate(time.Second)

	target, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "api bearer", TokenType: tokenTypeBearer, HeaderName: "Authorization",
		ValuePrefix: "Bearer ", TokenValue: mine, IsActive: true,
	})
	sessionTokenProfileTestResponses(t, ctx, target, []testResponse{
		{
			Headers: map[string]interface{}{"content-type": "application/json"},
			Body: "{\"access_token\":\"" + theirs + "\",\"token_type\":\"Bearer\"," +
				"\"expires_in\":86400,\"refresh_token\":\"invented-refresh-theirs\"}",
			At: minted.Add(-time.Hour),
		},
		{
			Headers: map[string]interface{}{"content-type": "application/json"},
			Body: "{\"access_token\":\"" + mine + "\",\"token_type\":\"Bearer\"," +
				"\"expires_in\":900,\"refresh_token\":\"invented-refresh-mine\",\"scope\":\"read\"}",
			At: minted,
		},
	})

	ev, err := GatherIssuingEvidence(ctx, target, CarrierForSessionToken(SessionToken{
		TokenType: tokenTypeBearer, HeaderName: "Authorization", ValuePrefix: "Bearer "}))
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(ev.TokenResponses) != 2 {
		t.Fatalf("got %d token responses, want 2", len(ev.TokenResponses))
	}
	found := 0
	for _, obs := range ev.TokenResponses {
		if strings.Contains(obs.Body, "REDACTED") {
			t.Fatalf("the body was edited on its way out of Postgres: %q", obs.Body)
		}
		if !strings.Contains(obs.Body, "invented-refresh") {
			t.Fatalf("the refresh token was dropped from the captured body: %q", obs.Body)
		}
		if strings.Contains(obs.Body, mine) || strings.Contains(obs.Body, theirs) {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("%d of the 2 captured bodies carried the access token they minted", found)
	}

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if p.Kind != CredentialKindOAuthAccess {
		t.Fatalf("kind = %s, want oauth_access_token; what it is was readable from its issuance", p.Kind)
	}
	if !p.TTLKnown || p.TTL != 900*time.Second {
		t.Fatalf("ttl = %v known=%v, want 900s from MY issuance and never the other one's 86400", p.TTL, p.TTLKnown)
	}
	if !p.ExpiryKnown || !p.ExpiresAt.Equal(minted.Add(900*time.Second)) {
		t.Fatalf("expires_at = %v, want %v", p.ExpiresAt, minted.Add(900*time.Second))
	}
	if p.Attributes["oauth_scope"] != "read" {
		t.Fatalf("the scope the response declared was lost: %+v", p.Attributes)
	}
}

// A token endpoint response that issued a DIFFERENT credential must leave the lifetime UNKNOWN and
// say why, rather than lending its number to the credential in hand.
func TestATokenResponseForAnotherCredentialLeavesTheLifetimeUnknown(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	ev := CredentialEvidence{TokenResponses: []TokenResponseObservation{
		NewTokenResponseObservation(
			"{\"access_token\":\"invented-somebody-elses-token\",\"expires_in\":3600}", now),
	}}
	p := ProfileCredentialWithEvidence(NewCredential("invented-opaque-value-in-hand"),
		CredentialCarrier{Kind: "bearer", Name: "Authorization"}, ev, now)
	if p.TTLKnown {
		t.Fatalf("a lifetime of %v was taken from a response that minted another credential", p.TTL)
	}
	if p.Kind != CredentialKindOpaqueBearer {
		t.Fatalf("kind = %s, want opaque_bearer", p.Kind)
	}
	if !warningsMention(p.Warnings, "none of them issued this credential") {
		t.Fatalf("the operator was not told why the declared lifetime was not used: %v", p.Warnings)
	}
}

// SLIDING IS A DIFFERENT ANSWER FROM ABSOLUTE and it changes whether a 30 minute credential
// survives a 29 minute run. The wire signature is the same value set again later with its death
// further out, which needs no model and no assumption.
func TestASlidingCookieIsReadOffTwoIssuancesOfTheSameValue(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	const value = "invented-sliding-session-value"
	ev := CredentialEvidence{SetCookies: []SetCookieObservation{
		NewSetCookieObservation("app_sid="+value+"; Path=/; Max-Age=1800", now.Add(-20*time.Minute)),
		NewSetCookieObservation("app_sid="+value+"; Path=/; Max-Age=1800", now.Add(-5*time.Minute)),
	}}
	p := ProfileCredentialWithEvidence(NewCredential(value),
		CredentialCarrier{Kind: "cookie", Name: "app_sid"}, ev, now)
	if p.ExpiryStyle != ExpiryStyleSliding {
		t.Fatalf("expiry_style = %s, want sliding", p.ExpiryStyle)
	}
	if !strings.Contains(p.ExpiryEvidence, "pushes the expiry out") {
		t.Fatalf("the evidence does not say what was read: %q", p.ExpiryEvidence)
	}
	if !strings.Contains(p.ExpiryEvidence, value) {
		t.Fatalf("the evidence does not say WHICH value was set twice: %q", p.ExpiryEvidence)
	}

	// The same cookie NAME with a new VALUE is a rotation, not an extension, and must not be read
	// as sliding.
	rotated := CredentialEvidence{SetCookies: []SetCookieObservation{
		NewSetCookieObservation("app_sid=invented-first-value; Path=/; Max-Age=1800", now.Add(-20*time.Minute)),
		NewSetCookieObservation("app_sid=invented-second-value; Path=/; Max-Age=1800", now.Add(-5*time.Minute)),
	}}
	q := ProfileCredentialWithEvidence(NewCredential("invented-second-value"),
		CredentialCarrier{Kind: "cookie", Name: "app_sid"}, rotated, now)
	if q.ExpiryStyle == ExpiryStyleSliding {
		t.Fatalf("a rotation was read as a sliding expiry")
	}
}

// A PROBED FLOOR IS NOT AN OBSERVED ONE. The corpus shows that a client kept SENDING a value; a
// validation of status active is a request this framework sent where the target answered
// differently because of the credential, so it is a record of the credential still WORKING.
func TestAProbedFloorOutranksAnObservedOneAndSaysWhich(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "probed session", TokenType: tokenTypeCookie, CookieName: "app_sid",
		TokenValue: "invented-probed-session-value", IsActive: true,
	})
	base := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	// Each event says WHICH credential it was about. Without that the span could cover a value
	// the row no longer holds, and applyProbeHistory refuses a floor it cannot attribute.
	stamped, err := json.Marshal(map[string]interface{}{
		CredentialFingerprintEvidenceKey: NewCredential("invented-probed-session-value").Fingerprint()})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	for _, e := range []struct {
		status string
		at     time.Time
	}{
		{tokenStatusActive, base},
		{tokenStatusNotHonoured, base.Add(10 * time.Minute)},
		{tokenStatusActive, base.Add(45 * time.Minute)},
	} {
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO session_token_events (session_token_id, kind, status, detail, evidence, created_at)
			VALUES ($1,'validate',$2,'an invented validation for the test',$3,$4)`,
			tokenID, e.status, stamped, e.at); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}

	tok, loadErr := loadSessionToken(tokenID)
	if loadErr != nil {
		t.Fatalf("load: %v", loadErr)
	}
	p := ProfileSessionToken(ctx, tok)
	if !p.TTLFloorKnown || p.TTLFloor != 45*time.Minute {
		t.Fatalf("floor = %v known=%v, want 45m across the two successful validations", p.TTLFloor, p.TTLFloorKnown)
	}
	if p.TTLFloorProvenance != ProvProbed {
		t.Fatalf("ttl_floor_provenance = %s, want probed", p.TTLFloorProvenance)
	}
	if p.TTLKnown {
		t.Fatalf("a floor was promoted to a TTL of %v", p.TTL)
	}
	if !strings.Contains(p.TTLDisplay(), "probed") || !strings.Contains(p.TTLDisplay(), "UNKNOWN") {
		t.Fatalf("ttl_display = %q, want an unknown with a probed floor beside it", p.TTLDisplay())
	}

	// And it survives the round trip to the row, because a reload that forgets how the floor was
	// got turns a probe back into a reading of somebody else's traffic.
	if err := SaveSessionTokenProfile(ctx, p); err != nil {
		t.Fatalf("save: %v", err)
	}
	back, err := LoadSessionTokenProfile(ctx, tokenID)
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	if back.TTLFloorProvenance != ProvProbed || back.TTLFloor != 45*time.Minute {
		t.Fatalf("the round trip lost the floor provenance: %s %v", back.TTLFloorProvenance, back.TTLFloor)
	}
}

// A refusal after a success bounds the death from the other side, and naming either end of that
// window as the expiry would be a precision nothing measured.
func TestADeathBetweenTwoProbesIsAWindowAndNotAnExpiry(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "dead session", TokenType: tokenTypeCookie, CookieName: "app_sid",
		TokenValue: "invented-dead-session-value", IsActive: true,
	})
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	// Both events carry the fingerprint of the value in the row: a refusal only bounds a death
	// when the success before it was the SAME credential, so an unattributed pair bounds nothing.
	stamped, err := json.Marshal(map[string]interface{}{
		CredentialFingerprintEvidenceKey: NewCredential("invented-dead-session-value").Fingerprint()})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	for _, e := range []struct {
		status string
		at     time.Time
	}{
		{tokenStatusActive, base},
		{tokenStatusExpired, base.Add(30 * time.Minute)},
	} {
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO session_token_events (session_token_id, kind, status, detail, evidence, created_at)
			VALUES ($1,'validate',$2,'an invented validation for the test',$3,$4)`,
			tokenID, e.status, stamped, e.at); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}
	tok, loadErr := loadSessionToken(tokenID)
	if loadErr != nil {
		t.Fatalf("load: %v", loadErr)
	}
	p := ProfileSessionToken(ctx, tok)
	if p.ExpiryKnown {
		t.Fatalf("an expiry of %v was stated from a refusal that only bounds it", p.ExpiresAt)
	}
	if !warningsMention(p.Warnings, "died somewhere in that") {
		t.Fatalf("the window was not reported: %v", p.Warnings)
	}
}

// ---------------------------------------------------------------------------------------------
// Round 13: a floor that cannot be attributed to ONE credential is not a measurement
// ---------------------------------------------------------------------------------------------

// A PROBED FLOOR MUST BELONG TO ONE CREDENTIAL.
//
// session_token_events carries no fingerprint and the refresh path replaces the stored value in
// place, so the span between two successful validations can cover two DIFFERENT credentials.
// Measured on the round 12 tree: a value stored one hour ago was reported as "alive across 5h59m
// of its own life", which is a sentence about a credential that is no longer in the row, and it is
// read downstream by the renewal interval, where an overstated floor renews LATE.
func TestAProbedFloorRefusesToSpanACredentialRotation(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const value = "invented-rotated-session-value"
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "rotated session", TokenType: tokenTypeCookie, CookieName: "app_sid",
		TokenValue: value, IsActive: true,
	})
	now := time.Now().UTC().Truncate(time.Second)

	// The row was last profiled an hour ago, and the fingerprint recorded then is the fingerprint
	// of the value stored NOW. That is the only thing in the schema that says which credential was
	// in the row at a given moment: any replacement since would have left a different fingerprint.
	anchor := now.Add(-time.Hour)
	if _, err := dbPool.Exec(ctx, `
		UPDATE session_tokens SET profiled_at = $2, value_fingerprint = $3 WHERE id = $1`,
		tokenID, anchor, NewCredential(value).Fingerprint()); err != nil {
		t.Fatalf("anchor the row: %v", err)
	}

	for _, at := range []time.Time{
		now.Add(-5*time.Hour - 59*time.Minute), // a DIFFERENT credential: before the anchor
		now.Add(-5 * time.Hour),                // also before it
		now.Add(-30 * time.Minute),             // this credential
		now.Add(-1 * time.Minute),              // this credential
	} {
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO session_token_events (session_token_id, kind, status, detail, created_at)
			VALUES ($1,'validate','active','an invented validation for the test',$2)`,
			tokenID, at); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}

	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)

	if p.TTLFloorKnown && p.TTLFloor > 30*time.Minute {
		t.Fatalf("the floor is %s, which spans a credential this row no longer holds; at most 29m of it belongs to the stored value (evidence: %q)",
			p.TTLFloor, p.TTLFloorEvidence)
	}
	if !p.TTLFloorKnown || p.TTLFloor != 29*time.Minute {
		t.Fatalf("floor = %v known=%v, want the 29m that IS attributable to the stored credential", p.TTLFloor, p.TTLFloorKnown)
	}
	if strings.Contains(p.TTLFloorEvidence, "5h59m") {
		t.Errorf("the evidence still states the unattributable span: %q", p.TTLFloorEvidence)
	}
	if !warningsMention(p.Warnings, "could not be attributed") {
		t.Errorf("the validations that were dropped were not reported: %v", p.Warnings)
	}
}

// With NOTHING that says which credential was in the row, there is no attributable floor at all,
// and the honest answer is no floor rather than a number covering an unknown number of values.
func TestAProbedFloorIsRefusedWhenNothingSaysWhichCredentialWasProbed(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "never profiled", TokenType: tokenTypeCookie, CookieName: "app_sid",
		TokenValue: "invented-unanchored-session-value", IsActive: true,
	})
	base := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Second)
	for _, at := range []time.Time{base, base.Add(3 * time.Hour)} {
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO session_token_events (session_token_id, kind, status, detail, created_at)
			VALUES ($1,'validate','active','an invented validation for the test',$2)`,
			tokenID, at); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}
	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if p.TTLFloorKnown {
		t.Fatalf("a floor of %s was stated from validations that cannot be attributed to any credential (%q)",
			p.TTLFloor, p.TTLFloorEvidence)
	}
	if !warningsMention(p.Warnings, "could not be attributed") {
		t.Errorf("the refusal was silent: %v", p.Warnings)
	}
}

// The strong form: an event that carries the fingerprint of the credential it was sent with needs
// no anchor, because it says which credential it was. This is what the producers should stamp.
func TestAValidationStampedWithItsCredentialFingerprintIsAttributed(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const value = "invented-stamped-session-value"
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "stamped session", TokenType: tokenTypeCookie, CookieName: "app_sid",
		TokenValue: value, IsActive: true,
	})
	fp := NewCredential(value).Fingerprint()
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	rows := []struct {
		at          time.Time
		fingerprint string
	}{
		{base, "deadbeef"}, // a DIFFERENT credential, and it is excluded by name
		{base.Add(time.Hour), fp},
		{base.Add(2*time.Hour + 45*time.Minute), fp},
	}
	for _, r := range rows {
		blob, err := json.Marshal(map[string]interface{}{CredentialFingerprintEvidenceKey: r.fingerprint})
		if err != nil {
			t.Fatalf("marshal evidence: %v", err)
		}
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO session_token_events (session_token_id, kind, status, detail, evidence, created_at)
			VALUES ($1,'validate','active','an invented validation for the test',$2,$3)`,
			tokenID, blob, r.at); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}
	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if !p.TTLFloorKnown || p.TTLFloor != 105*time.Minute {
		t.Fatalf("floor = %v known=%v, want the 1h45m between the two validations of THIS credential",
			p.TTLFloor, p.TTLFloorKnown)
	}
	if p.TTLFloorProvenance != ProvProbed {
		t.Fatalf("ttl_floor_provenance = %s, want probed", p.TTLFloorProvenance)
	}
	if !strings.Contains(p.TTLFloorEvidence, "fingerprint") {
		t.Errorf("the evidence does not say what attributed the span: %q", p.TTLFloorEvidence)
	}
}

// A floor with no recorded provenance is UNKNOWN, not observed. Defaulting it to observed is how
// a probed or unattributed floor acquires a provenance nothing earned.
func TestAFloorWithNoRecordedProvenanceIsNotCalledObserved(t *testing.T) {
	p := SessionTokenProfile{TTLFloor: 45 * time.Minute, TTLFloorKnown: true,
		TTLFloorEvidence: "a floor written before the provenance column existed"}
	got := p.TTLDisplay()
	if strings.Contains(got, string(ProvObserved)) {
		t.Fatalf("ttl_display = %q; nothing said this floor came from the corpus", got)
	}
	if !strings.Contains(got, string(ProvUnknown)) {
		t.Fatalf("ttl_display = %q, want the floor's provenance to read unknown", got)
	}
	if p.floorProvenanceStored() != ProvUnknown {
		t.Fatalf("the column would be written as %q", p.floorProvenanceStored())
	}
}

// Survives must not call a probed floor a reading of the corpus either.
func TestTheSurvivalSentenceNamesHowTheFloorWasGot(t *testing.T) {
	now := time.Now().UTC()
	probed := SessionTokenProfile{TTLFloor: 20 * time.Minute, TTLFloorKnown: true,
		TTLFloorProvenance: ProvProbed, TTLFloorEvidence: "two successful validations"}
	_, known, why := probed.Survives(time.Hour, now)
	if known {
		t.Fatalf("a floor answered a survival question: %q", why)
	}
	if strings.Contains(why, "corpus") {
		t.Fatalf("a probed floor was described as the corpus: %q", why)
	}
	observed := SessionTokenProfile{TTLFloor: 20 * time.Minute, TTLFloorKnown: true,
		TTLFloorProvenance: ProvObserved}
	if _, _, obsWhy := observed.Survives(time.Hour, now); !strings.Contains(obsWhy, "corpus") {
		t.Fatalf("an observed floor stopped naming the corpus: %q", obsWhy)
	}
}

// ---------------------------------------------------------------------------------------------
// Round 13: nbf is not an issue time
// ---------------------------------------------------------------------------------------------

// nbf is NOT-BEFORE. An issuer that backdates it for clock skew makes it EARLIER than the mint,
// and on the live estate no token carries iat at all, so this fallback is the common path rather
// than the rare one. Served as "issued at" with no caveat it is a fact nobody read.
func TestAnIssueTimeTakenFromNbfIsLabelledAsNotTheMintTime(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	header := map[string]interface{}{"alg": "RS256", "typ": "JWT"}
	withIat := makeJWT(t, header, map[string]interface{}{
		"iat": now.Add(-10 * time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	p := ProfileCredential(NewCredential(withIat), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, now)
	if p.IssuedAtSource != IssuedAtClaimIat || !p.IssuedAtSource.IsMintTime() {
		t.Fatalf("an iat claim is the mint time; source = %q", p.IssuedAtSource)
	}
	withNbf := makeJWT(t, header, map[string]interface{}{
		"nbf": now.Add(-10 * time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	q := ProfileCredential(NewCredential(withNbf), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, now)
	if !q.IssuedAtKnown {
		t.Fatalf("the nbf reading was dropped entirely; it is still worth showing, with its caveat")
	}
	if q.IssuedAtSource != IssuedAtClaimNbf {
		t.Fatalf("issued_at_source = %q, want nbf", q.IssuedAtSource)
	}
	if q.IssuedAtSource.IsMintTime() {
		t.Fatal("nbf was reported as the moment the credential was minted")
	}
	if !strings.Contains(q.IssuedAtSource.Evidence(), "not-before") {
		t.Fatalf("the caveat does not say what nbf is: %q", q.IssuedAtSource.Evidence())
	}
}

// And the probed floor must not count from a time that is not an issue time: nbf is a lower bound
// on the mint, so the last success minus nbf OVERSTATES the floor, in the direction that renews
// late.
func TestTheProbedFloorWillNotCountFromATimeThatIsNotTheMint(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	value := makeJWT(t, map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		map[string]interface{}{"nbf": now.Add(-8 * time.Hour).Unix(), "exp": now.Add(8 * time.Hour).Unix()})
	_, tokenID := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "nbf bearer", TokenType: "bearer", HeaderName: "Authorization",
		TokenValue: value, IsActive: true,
	})
	blob, err := json.Marshal(map[string]interface{}{
		CredentialFingerprintEvidenceKey: NewCredential(value).Fingerprint()})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO session_token_events (session_token_id, kind, status, detail, evidence, created_at)
		VALUES ($1,'validate','active','an invented validation for the test',$2,$3)`,
		tokenID, blob, now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if p.TTLFloorKnown && p.TTLFloor > time.Hour {
		t.Fatalf("a floor of %s was counted from nbf, which is not when the credential was minted: %q",
			p.TTLFloor, p.TTLFloorEvidence)
	}
}

// ---------------------------------------------------------------------------------------------
// Round 13: two recognisers that still fire on random bytes
// ---------------------------------------------------------------------------------------------

// MEASURED over 10.8M invented values: one hit, a ghs_ prefix matched on a 43 character base64url
// value. A GitHub server token is the prefix plus thirty six base62 characters, so a 43 character
// value carrying a hyphen is not one, and the published shape says so without any guessing.
func TestTheGitHubTokenShapeRefusesARandomValueThatOnlySharesThePrefix(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	carrier := CredentialCarrier{Kind: "bearer", Name: "Authorization"}
	notKeys := []string{
		"ghs_" + strings.Repeat("a", 39),           // right prefix, wrong length
		"ghs_" + strings.Repeat("a", 35),           // one short
		"ghs_aaaaaaaaaaaaaaaa-aaaaaaaaaaaaaaaaaaa", // right length, an alphabet GitHub does not use
		"ghp_" + strings.Repeat("b", 50),
		"gho_" + strings.Repeat("c", 20),
		"npm_" + strings.Repeat("d", 60),
	}
	for _, value := range notKeys {
		if p := ProfileCredential(NewCredential(value), carrier, now); p.Kind == CredentialKindAPIKey {
			t.Errorf("%q was called an API key: %s", value, p.KindEvidence)
		}
	}
	areKeys := []string{
		"ghs_" + strings.Repeat("a", 36),
		"ghp_" + strings.Repeat("b", 36),
		"gho_" + strings.Repeat("c", 36),
		"npm_" + strings.Repeat("d", 36),
	}
	for _, value := range areKeys {
		if p := ProfileCredential(NewCredential(value), carrier, now); p.Kind != CredentialKindAPIKey {
			t.Errorf("%q is the published shape of a GitHub or npm token and was reported as %s", value, p.Kind)
		}
	}
}

// A PUBLISHED COOKIE NAME OUTRANKS A ONE IN 256 VERSION BYTE. PHP writes PHPSESSID and PHP does
// not mint Branca tokens; reading a 0xBA first byte out of a framework's own session handle is the
// recogniser firing on noise, and the kind drives how the rest of the screen reads.
func TestBrancaDoesNotOutrankAPublishedSessionCookieName(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	value := makeBranca(now.Add(-10 * time.Minute))
	if p := ProfileCredential(NewCredential(value),
		CredentialCarrier{Kind: "cookie", Name: "PHPSESSID"}, now); p.Kind != CredentialKindSessionID {
		t.Errorf("a value in PHPSESSID was reported as %s on a version byte: %s", p.Kind, p.KindEvidence)
	}
	// The same value anywhere else is still read for what it is.
	if p := ProfileCredential(NewCredential(value),
		CredentialCarrier{Kind: "bearer", Name: "Authorization"}, now); p.Kind != CredentialKindBranca {
		t.Errorf("a real Branca token in a bearer header was reported as %s", p.Kind)
	}
}

// The question a caller has to ask before deriving anything from a floor is answered by the thing
// that produced the floor, because that is the only thing that knows how it was got.
func TestAFloorSaysWhetherItBelongsToOneCredential(t *testing.T) {
	none := SessionTokenProfile{}
	if ok, why := none.FloorBelongsToOneCredential(); ok || !strings.Contains(why, "no lower bound") {
		t.Errorf("a profile with no floor answered %v %q", ok, why)
	}
	unknown := SessionTokenProfile{TTLFloor: time.Hour, TTLFloorKnown: true}
	if ok, why := unknown.FloorBelongsToOneCredential(); ok {
		t.Errorf("a floor with no recorded provenance was said to belong to one credential: %q", why)
	}
	probed := SessionTokenProfile{TTLFloor: time.Hour, TTLFloorKnown: true,
		TTLFloorProvenance: ProvProbed, TTLFloorEvidence: "two attributed validations"}
	if ok, why := probed.FloorBelongsToOneCredential(); !ok || !strings.Contains(why, "attributed") {
		t.Errorf("an attributed probed floor answered %v %q", ok, why)
	}
	observed := SessionTokenProfile{TTLFloor: time.Hour, TTLFloorKnown: true,
		TTLFloorProvenance: ProvObserved, ObservedEvidence: "51 distinct values"}
	if ok, why := observed.FloorBelongsToOneCredential(); !ok || !strings.Contains(why, "not necessarily the value stored now") {
		t.Errorf("an observed floor answered %v %q", ok, why)
	}
}

// =================================================================================================
// ROUND 14: WHAT IS A CREDENTIAL, AND WHAT KIND IS IT
// =================================================================================================
//
// Three of these measure a defect visible in the live credential list of 2026-09-20. Every fixture
// below is a SHAPE taken from that list and rebuilt here; not one of them is a real value.

// MEASURED ON THE LIVE ESTATE. The cookie jar of app.staging-v2.tradetalk.us carries
//
//	CognitoIdentityServiceProvider.<clientid>.<sub>.accessToken       3 segments, alg RS256
//	CognitoIdentityServiceProvider.<clientid>.<sub>.idToken           3 segments, alg RS256
//	CognitoIdentityServiceProvider.<clientid>.<sub>.refreshToken      5 segments, alg RSA-OAEP enc A256GCM
//	CognitoIdentityServiceProvider.<clientid>.LastAuthUser            a 36 character user id
//
// read out of manual_crawl_captures.headers with the JOSE headers decoded (the header segment is
// not credential material: it carries alg, enc and kid and no key).
//
// LastAuthUser holds the name of the signed-in principal. It proves nothing, and the card was
// calling it opaque_session_id, which is how it became the governing credential of the TTL tile.
func TestACookieThatNamesAPrincipalIsNotCalledASession(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{
		"CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.LastAuthUser",
		"ai_user",
		"X-User-Id",
	} {
		carrier := CredentialCarrier{Kind: "cookie", Name: name}
		if strings.HasPrefix(name, "X-") {
			carrier = CredentialCarrier{Kind: "header", Name: name}
		}
		p := ProfileCredential(NewCredential("aaaaaaaa-bbbb-cccc-dddd-000000000001"), carrier, now)
		if p.Kind != CredentialKindPrincipalName {
			t.Errorf("%s was profiled as %s, want principal_name: %s", name, p.Kind, p.KindEvidence)
		}
		if !warningsMention(p.Warnings, "rather than claiming to prove it") {
			t.Errorf("%s carries no warning that the reading is of the name: %v", name, p.Warnings)
		}
	}
	// THE HEAD NOUN IS THE TEST AND NOT THE PRESENCE OF THE WORD. A userToken is a token.
	for _, name := range []string{
		"userToken",
		"CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa.accessToken",
		"user_session",
		"sessionid",
	} {
		p := ProfileCredential(NewCredential("aaaaaaaa-bbbb-cccc-dddd-000000000001"),
			CredentialCarrier{Kind: "cookie", Name: name}, now)
		if p.Kind == CredentialKindPrincipalName {
			t.Errorf("%s was profiled as principal_name, which loses a real credential: %s", name, p.KindEvidence)
		}
	}
}

// A FIVE SEGMENT VALUE IS NOT A JWE BECAUSE IT HAS FIVE SEGMENTS. RFC 7516 says the enc header
// parameter is REQUIRED in a JWE and RFC 7515 gives a JWS no such parameter, so enc is the witness
// that separates them. Without it the evidence sentence read "alg=dir enc=" and asserted a kind on
// a field nothing had read.
func TestAFiveSegmentValueWithNoEncHeaderIsNotCalledAJWE(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	tok := makeJWE(t, map[string]interface{}{"alg": "dir"})
	p := ProfileCredential(NewCredential(tok), CredentialCarrier{Kind: "bearer", Name: "Authorization"}, now)
	if p.Kind == CredentialKindJWE {
		t.Errorf("a five segment value with no enc header was called a JWE: %s", p.KindEvidence)
	}
	if strings.Contains(p.KindEvidence, "enc=") && p.Attributes["enc"] == "" {
		t.Errorf("the evidence names an enc that was never read: %s", p.KindEvidence)
	}
	// The real shape the live estate carries is still read, and its nested content type with it.
	real := makeJWE(t, map[string]interface{}{"alg": "RSA-OAEP", "enc": "A256GCM", "cty": "JWT"})
	rp := ProfileCredential(NewCredential(real), CredentialCarrier{Kind: "cookie",
		Name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa.refreshToken"}, now)
	if rp.Kind != CredentialKindJWE {
		t.Errorf("a compact JWE carrying alg, enc and cty was profiled as %s: %s", rp.Kind, rp.KindEvidence)
	}
	if !warningsMention(rp.Warnings, "nested") {
		t.Errorf("cty=JWT on a JWE was not reported as a nested token: %v", rp.Warnings)
	}
}

// THE BRANCA VETO, WEIGHED. Round 13 made a published cookie name outrank the version byte, which
// took the PHPSESSID false positive rate to zero and cost a GENUINE Branca token its issue time
// under every one of the thirteen published names. Three of those names identify no framework at
// all: knownSessionCookies labels session and sid "generic" and sessionid "Django or similar". A
// name that identifies a MINTER is evidence about what the value is; a name that identifies only
// a ROLE is not, and must not outrank a two witness structural read.
func TestTheBrancaVetoAppliesToFrameworkNamesAndNotToGenericOnes(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	value := makeBranca(now.Add(-10 * time.Minute))
	for _, name := range []string{"session", "sid", "sessionid"} {
		p := ProfileCredential(NewCredential(value), CredentialCarrier{Kind: "cookie", Name: name}, now)
		if p.Kind != CredentialKindBranca {
			t.Errorf("a real Branca token in a cookie named %q was reported as %s, losing its issue time: %s",
				name, p.Kind, p.KindEvidence)
		}
	}
	// PHP does not mint Branca tokens. That veto stays.
	for _, name := range []string{"PHPSESSID", "JSESSIONID", "laravel_session", "ASP.NET_SessionId"} {
		p := ProfileCredential(NewCredential(value), CredentialCarrier{Kind: "cookie", Name: name}, now)
		if p.Kind == CredentialKindBranca {
			t.Errorf("a version byte outranked the name %q, which the framework publishes as its session handle", name)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Round 15: what the card may print, and what a death does not erase
// ---------------------------------------------------------------------------------------------

// Synthetic identifiers. Both are shaped like the things they stand in for and neither came out of
// a corpus: the subject id convention is the one the identity report adopted for its own fixtures
// after its first draft used two real ones.
const (
	fixtureSubjectA = "aaaaaaaa-bbbb-cccc-dddd-000000000001"
	fixtureSubjectB = "aaaaaaaa-bbbb-cccc-dddd-000000000002"
	fixturePoolID   = "7cd3keuknr18mv2boiaesbgce3"
)

// A SUBJECT CLAIM IS EVIDENCE ABOUT THE TOKEN, so it goes out as the token carries it.
//
// RFC 7519 4.1.2 defines sub as the principal the JWT is about and PASETO's registered claim set
// uses the same name for the same thing. Whose token this is, is the first thing an access-control
// finding has to state, and a card that showed a hash of it could not state it at all.
func TestASubjectClaimIsServedAsTheTokenCarriesIt(t *testing.T) {
	now := time.Date(2026, 9, 21, 1, 0, 0, 0, time.UTC)

	jws := makeJWT(t,
		map[string]interface{}{"alg": "RS256", "kid": "KID0000000000001"},
		map[string]interface{}{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(4 * time.Minute).Unix(),
			"sub": fixtureSubjectA})
	paseto := makePASETOPublic(t, "v2", map[string]interface{}{
		"exp": now.Add(4 * time.Minute).Format(time.RFC3339), "sub": fixtureSubjectA})

	for _, tc := range []struct{ what, value string }{{"JWS", jws}, {"PASETO", paseto}} {
		p := ProfileCredential(NewCredential(tc.value), bearerCarrier, now)
		if p.Attributes["sub"] != fixtureSubjectA {
			t.Errorf("the %s profile does not carry the subject the token states: sub=%q, want %q",
				tc.what, p.Attributes["sub"], fixtureSubjectA)
		}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(raw), fixtureSubjectA) {
			t.Errorf("the marshalled %s profile does not reach a reader with the subject in it: %s", tc.what, raw)
		}
	}

	// Two subjects are still two, and one subject is still one, which is what this row is read for.
	sameSub := ProfileCredential(NewCredential(makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"exp": now.Add(time.Hour).Unix(), "sub": fixtureSubjectA})), bearerCarrier, now)
	otherSub := ProfileCredential(NewCredential(makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"exp": now.Add(time.Hour).Unix(), "sub": fixtureSubjectB})), bearerCarrier, now)
	if sameSub.Attributes["sub"] == otherSub.Attributes["sub"] {
		t.Errorf("two different subjects render identically: %q", sameSub.Attributes["sub"])
	}

	// EVERY CLAIM IS ITS OWN ATTRIBUTE, VALUE AND ALL. There is no separate roster of claim names
	// any more: a name list beside a set of values would be the same fact written twice, and the
	// reason it existed was to name the claims without serving them.
	if sameSub.Attributes["claims"] != "" {
		t.Errorf("the profile still carries a claim-name roster beside the claims themselves: %q", sameSub.Attributes["claims"])
	}
	if sameSub.Attributes["sub"] != fixtureSubjectA {
		t.Errorf("the sub claim is not served as the token carries it: %q", sameSub.Attributes["sub"])
	}
}

// A CREDENTIAL NAME CARRIES AN IDENTITY, and every sentence built out of it keeps that identity.
//
// Amplify writes CognitoIdentityServiceProvider.<client id>.<who>.<leaf>, where <who> is the user
// pool username, which is the subject id or, on a pool with an email alias, the address. Which
// account a cookie belongs to is the fact an access-control finding turns on, and on a jar with
// two sign-ins it is the difference between a coherent probe and an incoherent one.
func TestACredentialNameIsRenderedWhole(t *testing.T) {
	now := time.Date(2026, 9, 21, 1, 0, 0, 0, time.UTC)
	uuidName := "CognitoIdentityServiceProvider." + fixturePoolID + "." + fixtureSubjectA + ".accessToken"
	emailName := "CognitoIdentityServiceProvider." + fixturePoolID + ".person@example.test.accessToken"

	for _, tc := range []struct{ name, who string }{
		{uuidName, fixtureSubjectA},
		{emailName, "person@example.test"},
	} {
		carrier := CredentialCarrier{Kind: "cookie", Name: tc.name}
		if d := carrier.Describe(); !strings.Contains(d, tc.who) {
			t.Errorf("Describe drops the account the name belongs to: %q", d)
		}
		// Every sentence the engine writes about the carrier goes through the same rendering.
		p := ProfileCredential(NewCredential("8f14e45fceea167a5a36dedd4bea2543"), carrier, now)
		if !strings.Contains(p.KindEvidence, tc.who) {
			t.Errorf("the kind evidence drops the account: %q", p.KindEvidence)
		}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(raw), tc.who) {
			t.Errorf("the marshalled profile does not reach a reader with the account in it: %s", raw)
		}
	}

	// AND THE REST OF THE NAME IS WHOLE TOO, so the cookie can be found in a jar.
	rendered := CredentialCarrier{Kind: "cookie", Name: uuidName}.Describe()
	for _, want := range []string{"CognitoIdentityServiceProvider", fixturePoolID, fixtureSubjectA, "accessToken", "cookie"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the rendered name lost %q: %q", want, rendered)
		}
	}

	// AND AN ORDINARY NAME IS STILL RENDERED AS ITSELF.
	for _, plain := range []string{"PHPSESSID", "connect.sid", "Authorization", "X-Api-Key",
		"CognitoIdentityServiceProvider." + fixturePoolID + ".LastAuthUser", "firebase:authUser:abc123:[DEFAULT]"} {
		c := CredentialCarrier{Kind: "cookie", Name: plain}
		if !strings.HasPrefix(c.Describe(), plain) {
			t.Errorf("a plain name was rewritten: %q became %q", plain, c.Describe())
		}
	}
}

// AN expires_in WITH A MINT TIME IS AN EXPIRY, and reading it as a lifetime alone is what makes a
// credential invisible to the card's ordering: chooseGoverningCredential ranks on the REMAINING
// life, so a credential with a measured lifetime and no expiry is passed over however short it is.
func TestAnExpiresInWithAMintTimeGivesAnExpiryAndNotJustALifetime(t *testing.T) {
	now := time.Date(2026, 9, 21, 1, 0, 0, 0, time.UTC)
	iat := now.Add(-time.Minute)

	p := ProfileCredential(NewCredential(makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"iat": iat.Unix(), "expires_in": 60, "sub": fixtureSubjectA})), bearerCarrier, now)

	if !p.TTLKnown || p.TTL != time.Minute {
		t.Fatalf("the lifetime itself was lost: known=%v ttl=%s", p.TTLKnown, p.TTL)
	}
	if !p.ExpiryKnown {
		t.Fatalf("a lifetime of %s counted from a mint time at %s is an expiry, and it reads UNKNOWN: %s",
			humaniseTTL(p.TTL), iat.Format(time.RFC3339), p.ExpiryDisplay())
	}
	if want := iat.Add(time.Minute); !p.ExpiresAt.Equal(want) {
		t.Errorf("expiry is %s, want %s", p.ExpiresAt.Format(time.RFC3339), want.Format(time.RFC3339))
	}
	if p.ExpiryProvenance != ProvParsed {
		t.Errorf("provenance is %q, want parsed: both halves were read out of the token", p.ExpiryProvenance)
	}
	// THE SENTENCE NAMES BOTH READS. An expiry derived from two claims is not the same fact as an
	// exp, and the row has to say which two.
	for _, want := range []string{"expires_in", "iat"} {
		if !strings.Contains(p.ExpiryEvidence, want) {
			t.Errorf("the expiry evidence does not name %q: %q", want, p.ExpiryEvidence)
		}
	}
	if _, known := p.RemainingAt(now); !known {
		t.Error("the remaining life is still unknown, so the card's ordering still cannot see it")
	}

	// AND NOT FROM A TIME THAT IS NOT THE MINT. nbf can be backdated for clock skew, so counting a
	// lifetime from it would put the death later than the issuer meant.
	q := ProfileCredential(NewCredential(makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"nbf": iat.Unix(), "expires_in": 60})), bearerCarrier, now)
	if !q.TTLKnown {
		t.Fatalf("the lifetime was lost on the nbf case: %s", q.TTLDisplay())
	}
	if q.ExpiryKnown {
		t.Errorf("an expiry was invented from nbf, which is not the mint time: %s", q.ExpiryDisplay())
	}
}

// A CREDENTIAL'S DEATH DOES NOT UN-MEASURE ITS LIFETIME. "How long does a session last on this
// application" is answered by exp minus iat whether or not this particular value is still alive,
// and the survival sentence is where the engine threw that answer away.
func TestADeadCredentialStillStatesTheLifetimeThatWasRead(t *testing.T) {
	now := time.Date(2026, 9, 21, 1, 49, 50, 0, time.UTC)
	iat := now.Add(-13*time.Hour - 40*time.Minute)

	p := ProfileCredential(NewCredential(makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"iat": iat.Unix(), "exp": iat.Add(300 * time.Second).Unix()})), bearerCarrier, now)

	if !p.TTLKnown || p.TTL != 300*time.Second {
		t.Fatalf("the fixture is wrong: known=%v ttl=%s", p.TTLKnown, p.TTL)
	}
	ok, known, why := p.Survives(20*time.Minute, now)
	if ok || !known {
		t.Fatalf("a dead credential is a measured no: ok=%v known=%v", ok, known)
	}
	if !strings.Contains(why, "expired") {
		t.Errorf("the sentence no longer says it is dead: %q", why)
	}
	if !strings.Contains(why, "lifetime is 5m") {
		t.Errorf("the sentence drops the measured lifetime of the application's session, which is "+
			"the one thing this dead token still knows: %q", why)
	}
	if !strings.Contains(why, "exp minus iat") {
		t.Errorf("the sentence states a lifetime without naming what read it: %q", why)
	}
}

// A CAPTURE TIME NOTHING RECORDED IS NOT THE YEAR ONE. Both evidence sentences that name a
// captured response formatted its timestamp unconditionally, so a row whose time is missing
// produced "captured at 0001-01-01T00:00:00Z" inside the one string an operator audits a lifetime
// by. It is the same defect as a zero standing in for an unmeasured TTL, in the field whose whole
// job is to say what was read.
func TestACaptureWithNoRecordedTimeDoesNotGetATimestampInvented(t *testing.T) {
	now := time.Date(2026, 9, 21, 1, 0, 0, 0, time.UTC)
	value := "8f14e45fceea167a5a36dedd4bea2543"

	// The Set-Cookie half.
	obs := NewSetCookieObservation("app_sess="+value+"; Max-Age=900; Path=/", time.Time{})
	p := ProfileCredentialWithEvidence(NewCredential(value),
		CredentialCarrier{Kind: "cookie", Name: "app_sess"},
		CredentialEvidence{SetCookies: []SetCookieObservation{obs}}, now)
	if !p.TTLKnown {
		t.Fatalf("the fixture did not reach the Set-Cookie branch at all: %s", p.TTLDisplay())
	}
	if strings.Contains(p.TTLEvidence, "0001-01-01") {
		t.Errorf("the lifetime evidence states a capture time nothing recorded: %q", p.TTLEvidence)
	}
	if !strings.Contains(p.TTLEvidence, "not recorded") {
		t.Errorf("the lifetime evidence does not say the capture time is missing either: %q", p.TTLEvidence)
	}

	// The token endpoint half.
	body := `{"access_token":"` + value + `","token_type":"Bearer","expires_in":900}`
	tr := NewTokenResponseObservation(body, time.Time{})
	q := ProfileCredentialWithEvidence(NewCredential(value), bearerCarrier,
		CredentialEvidence{TokenResponses: []TokenResponseObservation{tr}}, now)
	if !q.TTLKnown {
		t.Fatalf("the fixture did not reach the token response branch at all: %s", q.TTLDisplay())
	}
	if strings.Contains(q.TTLEvidence, "0001-01-01") {
		t.Errorf("the lifetime evidence states a capture time nothing recorded: %q", q.TTLEvidence)
	}
	// AND NO EXPIRY IS INVENTED FROM IT. An opaque value carries no mint time of its own, so with
	// the capture time missing there is nothing to count nine hundred seconds from.
	if q.ExpiryKnown {
		t.Errorf("an expiry was counted from a capture time nothing recorded: %s", q.ExpiryDisplay())
	}
}

// =================================================================================================
// ROUND 16: WHICH KIND OF CREDENTIAL THE NAME CLAIMS
// =================================================================================================
//
// FAIL FIRST, measured against the tree as it stood:
//
//	--- FAIL: TestALongTermAuthenticatorIsReadOffTheLeaf
//	    undefined: credentialNameNamesALongTermAuthenticator
//
// which is the point: nothing in this file asked WHICH KIND of credential a name claims, so
// "password" answered the only question there was and randomPasswordKey read as proof of a
// session. See the vocabulary for what was measured on the live jars.

func TestALongTermAuthenticatorIsReadOffTheLeaf(t *testing.T) {
	const pool = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3"
	const sub = "aaaaaaaa-bbbb-cccc-dddd-000000000001"
	for _, tc := range []struct {
		name string
		want bool
		tok  string
		why  string
	}{
		{pool + "." + sub + ".randomPasswordKey", true, "password", "the Amplify device password"},
		{pool + "." + sub + ".deviceKey", true, "device", "the Amplify device key"},
		{pool + "." + sub + ".deviceGroupKey", true, "device", "the Amplify device group key"},
		{pool + "." + sub + ".accessToken", false, "", "the session token in the same namespace"},
		{pool + "." + sub + ".refreshToken", false, "", "the refresh token in the same namespace"},
		{"trusted_device_secret", true, "device", "an SDK nobody listed, same role"},
		{"mfa_token", true, "mfa", "a second factor is not a session"},
		{"clientSecret", true, "secret", "authenticates the client, not the session"},

		// AND IT LOSES TO A SESSION WORD STANDING BESIDE IT.
		{"deviceIdToken", false, "", "the leaf carries idToken as a compound"},
		{"device_manager_session_token", false, "", "the leaf says session token"},
		{"password_grant_access_token", false, "", "the leaf says access token"},
		{"csrf_secret", false, "", "csrf is a session word and it is not the secret"},
		{"sessionSecret", false, "", "session stands beside secret"},

		// AND THE PREFIX NEVER DECIDES. The leaf is the role word; everything before it is the
		// pool, the client id and whoever the record is for.
		{"device.accessToken", false, "", "device is the namespace, accessToken is the role"},
		{"password.sessionid", false, "", "password is the namespace, sessionid is the role"},
	} {
		tok, why, ok := credentialNameNamesALongTermAuthenticator(tc.name)
		if ok != tc.want {
			t.Errorf("%s: long-term=%v want %v (tok=%q why=%q) [%s]",
				tc.name, ok, tc.want, tok, why, tc.why)
			continue
		}
		if ok && tok != tc.tok {
			t.Errorf("%s: decided on %q, expected %q", tc.name, tok, tc.tok)
		}
		if ok && why == "" {
			t.Errorf("%s: held with nothing to say about it", tc.name)
		}
	}
}

// A JAR WITH TWO SIGN-INS IS GROUPED BY THE SEGMENT THAT NAMES THE ACCOUNT, and the key is the
// segment itself, so the sentence about the set that was held back can say whose it was.
func TestThePrincipalSegmentIsTheAccountItNames(t *testing.T) {
	const pool = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3"
	const subA = "d4887448-50b1-7015-03be-6b285cf9fb5e"
	const subB = "d4189418-5001-7019-d7ee-ce3897389622"

	a := credentialNamePrincipalSegment(pool + "." + subA + ".accessToken")
	b := credentialNamePrincipalSegment(pool + "." + subB + ".accessToken")
	if a == "" || b == "" {
		t.Fatalf("a namespaced name with a subject in it read as belonging to nobody: %q %q", a, b)
	}
	if a == b {
		t.Error("two subjects fingerprinted the same, so a jar with two people reads as one")
	}
	// TWO LEAVES OF ONE PERSON ARE ONE PERSON.
	if credentialNamePrincipalSegment(pool+"."+subA+".idToken") != a {
		t.Error("two leaves of the same record read as two principals")
	}
	// IT RETURNS THE SEGMENT ITSELF, which is what lets a sentence name the account.
	if a != subA || b != subB {
		t.Errorf("the grouping key is not the account segment: %q %q, want %q %q", a, b, subA, subB)
	}
	// AN ADDRESS IS THE OTHER SHAPE, and it names a person outright.
	if credentialNamePrincipalSegment("msal.account@example.test.idtoken") == "" {
		t.Error("a name whose segment is an address read as belonging to nobody")
	}
	// AND A NAME WITH NO SUCH SEGMENT BELONGS TO NOBODY IN PARTICULAR.
	for _, n := range []string{"app_session", "PHPSESSID", pool + ".LastAuthUser", ""} {
		if got := credentialNamePrincipalSegment(n); got != "" {
			t.Errorf("%s was attributed to a principal (%q) on no segment that names one", n, got)
		}
	}
}
