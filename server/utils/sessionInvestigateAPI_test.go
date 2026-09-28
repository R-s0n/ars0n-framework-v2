package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// WHAT THESE TESTS PIN, and why each one is here.
//
//  1. THE CREDENTIAL IS SERVED, VERBATIM. Asserted against the SERIALISED bytes of the handler's
//     own response, because the value is the evidence: a leaked token is proved by showing the
//     token, and a screen holding it back sends the operator elsewhere for what it already has.
//  2. AN UNMEASURED LIFETIME RENDERS AS THE WORD UNKNOWN. Never "0", never "", never "-". Those
//     three are what an operator reads as "no expiry", which is the opposite of the truth.
//  3. THE CARD TALKS ABOUT THE CREDENTIAL THAT GOVERNS THE SCAN, which is the shortest-lived of
//     the ones that will actually be sent, and says so.
//  4. A MEASURED NUMBER AND A GUESS DO NOT RENDER THE SAME. The provenance rides with the number
//     everywhere it appears.
//  5. THE ENDPOINT REFUSES WHAT IT CANNOT ACT ON rather than answering a question it did not hear.

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

// A real-shaped ES256 JWT with no iat, which is the live target's shape: the claim set is
// aud,c,email,exp,g,iss,jti,nbf,sub,uid and exp-nbf is 900. Built rather than pasted so no real
// credential is committed to the repository.
func investigateJWT(t *testing.T, nbf, exp time.Time) string {
	t.Helper()
	header := `{"xv":"1","alg":"ES256","kid":"TESTKID0000000001","typ":"JWT"}`
	payload := fmt.Sprintf(`{"aud":"test","exp":%d,"iss":"https://issuer.test","jti":"jti-1","nbf":%d,"sub":"user-1"}`,
		exp.Unix(), nbf.Unix())
	enc := func(s string) string {
		return strings.TrimRight(base64URL(s), "=")
	}
	return enc(header) + "." + enc(payload) + ".c2lnbmF0dXJl"
}

func base64URL(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var buf [3]byte
		n := copy(buf[:], data[i:])
		v := uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])
		chars := []byte{
			alphabet[(v>>18)&0x3f], alphabet[(v>>12)&0x3f],
			alphabet[(v>>6)&0x3f], alphabet[v&0x3f],
		}
		switch n {
		case 1:
			out.Write(chars[:2])
			out.WriteString("==")
		case 2:
			out.Write(chars[:3])
			out.WriteString("=")
		default:
			out.Write(chars)
		}
	}
	return out.String()
}

// profiledToken builds a token with its profile already attached, which is the state the handler
// sees after AttachSessionTokenProfiles. ProfileCredential is the engine's pure entry point, so
// this fixture measures exactly what production measures.
func profiledToken(id, name, value string, carrier CredentialCarrier, active bool, now time.Time) SessionToken {
	tok := SessionToken{
		ID: id, ScopeTargetID: "target-1", Name: name, TokenValue: value, IsActive: active,
		TokenType: carrier.Kind, ValuePrefix: carrier.Prefix,
	}
	switch carrier.Kind {
	case "cookie":
		tok.CookieName = carrier.Name
	case "query":
		tok.ParamName = carrier.Name
	default:
		tok.HeaderName = carrier.Name
	}
	p := ProfileCredential(NewCredential(value), carrier, now)
	p.TokenID = id
	p.Name = name
	p.ScopeTargetID = "target-1"
	tok.Profile = &p
	return tok
}

var bearerCarrier = CredentialCarrier{Kind: "bearer", Name: "Authorization", Prefix: "Bearer "}
var cookieCarrier = CredentialCarrier{Kind: "cookie", Name: "PHPSESSID"}

// ---------------------------------------------------------------------------------------------
// 1. The credential is served
// ---------------------------------------------------------------------------------------------

// THE RESPONSE CARRIES THE CREDENTIAL. This is a bug bounty framework: a credential in a captured
// response IS the finding, so the bytes go out whole, beside the fingerprint that tells two of
// them apart at a glance.
func TestTheInvestigationPayloadCarriesTheCredential(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 9, 43, 0, time.UTC)
	secret := investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second))
	opaque := "s%3AKf8Uq2Xn4pLz9Wm1Tv6Rb3Yc7Hd0Ge5J.aVerySecretSessionIdentifier"

	tokens := []SessionToken{
		profiledToken("tok-1", "app bearer", secret, bearerCarrier, true, now),
		profiledToken("tok-2", "php session", opaque, cookieCarrier, true, now),
	}

	body := investigateVia(t, tokens, http.MethodGet, "/session-tokens/target/target-1/investigate")

	for _, want := range []string{secret, opaque} {
		if !strings.Contains(body, want) {
			t.Fatalf("the response does not carry the credential it characterised:\n%s", body)
		}
	}
	// AND THE FINGERPRINT IS STILL THERE, because matching one credential against a log line or
	// against the runner's reading is what it is for.
	fp := NewCredential(secret).Fingerprint()
	if !strings.Contains(body, fp) {
		t.Fatalf("the response carries no fingerprint, so nothing matches the credential: %s", body)
	}
	if len(fp) != 8 {
		t.Fatalf("a fingerprint is meant to be 8 hex digits, got %d: %q", len(fp), fp)
	}
}

// The projection has a FIELD for the value, and it holds the value the token holds. Asserted on
// the rendered object rather than on the struct, because a json tag is what decides this.
func TestTheProjectionCarriesTheCredentialValue(t *testing.T) {
	now := time.Now().UTC()
	const value = "abcdefghijklmnopqrstuvwxyz0123456789"
	tok := profiledToken("tok-1", "app bearer", value, bearerCarrier, true, now)
	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)

	raw, err := json.Marshal(report.Credentials[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := string(m["value"]); got != `"`+value+`"` {
		t.Errorf("the credential projection renders value as %s, want the credential itself", got)
	}
	if _, ok := m["fingerprint"]; !ok {
		t.Error("the credential projection has no fingerprint, so nothing matches it to a log line")
	}
}

// ---------------------------------------------------------------------------------------------
// 2. An unmeasured lifetime is the word UNKNOWN
// ---------------------------------------------------------------------------------------------

// A PHPSESSID has no readable lifetime. Every lifetime field for it has to say so in words, and
// none of them may be a zero or a blank, because a tile reading "0" is read as "no expiry".
func TestAnUnmeasuredLifetimeIsNeverAZeroOrABlank(t *testing.T) {
	now := time.Now().UTC()
	tok := profiledToken("tok-1", "php session", "8f14e45fceea167a5a36dedd4bea2543", cookieCarrier, true, now)
	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)
	c := report.Credentials[0]

	if c.TTLKnown {
		t.Fatalf("an opaque session id was reported as having a measured lifetime: %+v", c.TTLDisplay)
	}
	for name, got := range map[string]string{
		"ttl_short":       c.TTLShort,
		"ttl_floor_short": c.TTLFloorShort,
		"remaining_short": c.RemainingShort,
		"rotation_short":  c.RotationShort,
	} {
		if got != ttlUnknownWord {
			t.Errorf("%s reads %q for an unmeasured lifetime; it must read %q", name, got, ttlUnknownWord)
		}
	}
	if report.TTLMetric.Value != ttlUnknownWord {
		t.Errorf("the card tile reads %q for an unmeasured lifetime", report.TTLMetric.Value)
	}
	if report.TTLMetric.Known {
		t.Error("the card tile claims the lifetime is known")
	}
	if report.TTLMetric.State != "unknown" {
		t.Errorf("the card tile state is %q, want unknown", report.TTLMetric.State)
	}
	if !strings.Contains(strings.ToLower(report.TTLMetric.Explain), "not") {
		t.Errorf("the tile's explanation does not say the lifetime was not measured: %q", report.TTLMetric.Explain)
	}
}

// A credential with no stored profile at all is a THIRD state: not characterised, as against
// characterised and unknowable. Both render UNKNOWN, and the report can tell them apart.
func TestNotCharacterisedIsDistinguishableFromCharacterisedAndUnknown(t *testing.T) {
	now := time.Now().UTC()
	unprofiled := SessionToken{ID: "tok-1", Name: "never measured", TokenValue: "abc123", IsActive: true,
		TokenType: "cookie", CookieName: "sid"}
	characterised := profiledToken("tok-2", "php session", "8f14e45fceea167a5a36dedd4bea2543", cookieCarrier, true, now)

	report := buildSessionInvestigation("target-1", []SessionToken{unprofiled, characterised}, sessionInvestigateOptions{}, now)
	if report.Credentials[0].Measured {
		t.Error("a credential with no profile reported itself as measured")
	}
	if !report.Credentials[1].Measured {
		t.Error("a credential the engine characterised reported itself as unmeasured")
	}
	if report.Credentials[0].TTLShort != ttlUnknownWord || report.Credentials[1].TTLShort != ttlUnknownWord {
		t.Error("both states must still render the word UNKNOWN")
	}
}

// An observed floor is a LOWER BOUND and must never be promoted into the TTL tile as a lifetime.
// This is the measurement that shaped the engine: the live corpus gives a floor of 14m28s and a
// median of 11s against a parsed truth of 900s.
func TestAnObservedFloorIsShownAsAFloorAndNotAsALifetime(t *testing.T) {
	now := time.Now().UTC()
	tok := profiledToken("tok-1", "php session", "8f14e45fceea167a5a36dedd4bea2543", cookieCarrier, true, now)
	tok.Profile.TTLFloor = 14*time.Minute + 28*time.Second
	tok.Profile.TTLFloorKnown = true
	tok.Profile.ObservedSamples = 51
	tok.Profile.ObservedRequests = 3701
	tok.Profile.ObservedEvidence = "51 distinct values across 3701 captured requests"

	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)
	if report.TTLMetric.Value != ttlUnknownWord {
		t.Fatalf("an observed floor was promoted into the TTL tile as %q", report.TTLMetric.Value)
	}
	if report.TTLMetric.State != "floor_only" {
		t.Errorf("state is %q, want floor_only", report.TTLMetric.State)
	}
	if !strings.Contains(report.TTLMetric.Detail, "14m28s") {
		t.Errorf("the tile does not carry the floor it does know: %q", report.TTLMetric.Detail)
	}
	if !strings.Contains(report.TTLMetric.Explain, "floor and not a lifetime") {
		t.Errorf("the tile does not say the floor is not a lifetime: %q", report.TTLMetric.Explain)
	}
}

// ---------------------------------------------------------------------------------------------
// 3. The card talks about the credential that governs the scan
// ---------------------------------------------------------------------------------------------

// Three credentials with three different lifetimes. The scan stops being authenticated when the
// FIRST one dies, so that is the one the tile reports, and it says it is one of three.
func TestTheTileReportsTheCredentialThatDiesFirst(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 9, 43, 0, time.UTC)
	short := profiledToken("tok-short", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)
	long := profiledToken("tok-long", "long lived bearer",
		investigateJWT(t, now.Add(-time.Minute), now.Add(11*time.Hour)),
		CredentialCarrier{Kind: "header", Name: "X-Long"}, true, now)
	opaque := profiledToken("tok-opaque", "php session", "8f14e45fceea167a5a36dedd4bea2543", cookieCarrier, true, now)

	report := buildSessionInvestigation("target-1", []SessionToken{long, opaque, short}, sessionInvestigateOptions{}, now)

	if report.Governing == nil {
		t.Fatal("no governing credential was chosen from three sendable ones")
	}
	if report.Governing.TokenID != "tok-short" {
		t.Fatalf("the tile is about %q; the first credential to die is tok-short", report.Governing.TokenID)
	}
	if report.Governing.OfSendable != 3 {
		t.Errorf("of_sendable is %d, want 3", report.Governing.OfSendable)
	}
	if !strings.Contains(report.Governing.WhyThisOne, "3") {
		t.Errorf("the reason does not say it was chosen from three: %q", report.Governing.WhyThisOne)
	}
	if !strings.Contains(report.TTLMetric.Detail, "of 3") {
		t.Errorf("the tile does not say the other credentials disagree: %q", report.TTLMetric.Detail)
	}
	governs := 0
	for _, c := range report.Credentials {
		if c.Governs {
			governs++
			if c.TokenID != "tok-short" {
				t.Errorf("the wrong credential is marked as governing: %s", c.TokenID)
			}
		}
	}
	if governs != 1 {
		t.Errorf("%d credentials are marked as governing; exactly one must be", governs)
	}
	// And the tile shows a lifetime, not a remaining life: 15m is the property of the app.
	//
	// IT SHOWS IT AS AN UPPER BOUND, because the php session beside it was never measured and is
	// also going out. Round 11 rendered this case as a flat "15m" with known=true, which is the
	// over-confidence TestTheTileIsNotConfidentWhenASiblingIsUnmeasured now pins.
	if report.TTLMetric.Value != "<=15m" {
		t.Errorf("the tile reads %q; exp minus nbf on this token is 900 seconds and one sibling is unmeasured",
			report.TTLMetric.Value)
	}
}

// A credential that will not be sent does not get to set the card's number, however short its
// lifetime. A switched-off token is the commonest case and used to be invisible.
func TestACredentialThatWillNotBeSentDoesNotGovern(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 9, 43, 0, time.UTC)
	off := profiledToken("tok-off", "switched off",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(60*time.Second)), bearerCarrier, false, now)
	on := profiledToken("tok-on", "live bearer",
		investigateJWT(t, now.Add(-time.Minute), now.Add(30*time.Minute)),
		CredentialCarrier{Kind: "header", Name: "X-Live"}, true, now)

	report := buildSessionInvestigation("target-1", []SessionToken{off, on}, sessionInvestigateOptions{}, now)
	if report.Governing == nil || report.Governing.TokenID != "tok-on" {
		t.Fatalf("a switched-off credential governed the card: %+v", report.Governing)
	}
	if report.Counts.Sendable != 1 {
		t.Errorf("sendable is %d, want 1", report.Counts.Sendable)
	}
	if report.Credentials[0].Sendable {
		t.Error("a switched-off credential reported itself as sendable")
	}
	if !strings.Contains(report.Credentials[0].NotSendableReason, "switched off") {
		t.Errorf("the row does not say why it will not be sent: %q", report.Credentials[0].NotSendableReason)
	}
}

// A dead credential whose row says otherwise. This is the hole round 10 found: an operator-typed
// expires_at of next year on a bearer whose own exp passed. The row must not be sendable and the
// disagreement has to be on screen, because the operator's next action depends on which of the two
// numbers is wrong.
func TestADeadCredentialWithALiveColumnIsShownAsDeadAndTheDisagreementIsNamed(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 9, 43, 0, time.UTC)
	dead := investigateJWT(t, now.Add(-30*time.Minute), now.Add(-15*time.Minute))
	tok := profiledToken("tok-1", "stale bearer", dead, bearerCarrier, true, now)
	future := now.Add(365 * 24 * time.Hour)
	tok.ExpiresAt = &future

	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)
	c := report.Credentials[0]
	if c.Sendable {
		t.Fatal("a credential whose own exp passed 15m ago is reported as sendable because the column says next year")
	}
	if !c.DeclaredDisagrees {
		t.Fatal("the column and the credential disagree by a year and the report does not say so")
	}
	if !strings.Contains(c.DeclaredDisagreement, "the credential is what the server checks") {
		t.Errorf("the disagreement does not say which number to believe: %q", c.DeclaredDisagreement)
	}
	if report.TTLMetric.State != "none" || report.TTLMetric.Value != "NO SESSION" {
		t.Errorf("with nothing sendable the tile reads %q/%q, want NO SESSION/none",
			report.TTLMetric.Value, report.TTLMetric.State)
	}
}

// With no credentials at all the tile must not read UNKNOWN, which would suggest there is a
// session whose length we have not measured. It reads NO SESSION.
func TestNoCredentialsReadsAsNoSessionAndNotAsUnknown(t *testing.T) {
	now := time.Now().UTC()
	report := buildSessionInvestigation("target-1", nil, sessionInvestigateOptions{}, now)
	if report.TTLMetric.Value != "NO SESSION" {
		t.Fatalf("the tile reads %q with no credentials stored", report.TTLMetric.Value)
	}
	if report.Governing != nil {
		t.Error("a governing credential was chosen from none")
	}
	// Searched across the notes rather than pinned to the first one: the wire reading's own
	// sentence now leads, because whether the runner's credential source was read qualifies
	// everything that follows it.
	if !investigateNoteSays(report.Notes, "anonymously") {
		t.Errorf("the report does not say what no credentials means: %v", report.Notes)
	}
}

// investigateNoteSays reports whether any note in the report carries a phrase.
func investigateNoteSays(notes []string, phrase string) bool {
	for _, n := range notes {
		if strings.Contains(n, phrase) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// 4. A measured number and a guess do not render the same
// ---------------------------------------------------------------------------------------------

// The provenance travels with every number. This is the whole point of the screen: an operator
// who cannot tell "read out of the token" from "somebody typed it" cannot act on either.
func TestEveryLifetimeNumberCarriesItsProvenanceInWords(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 9, 43, 0, time.UTC)
	tok := profiledToken("tok-1", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)

	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)
	c := report.Credentials[0]
	if c.TTLProvenance != string(ProvParsed) {
		t.Fatalf("a JWT's own exp minus nbf is %q, want parsed", c.TTLProvenance)
	}
	if !strings.Contains(c.TTLProvenanceLabel, "out of the credential") {
		t.Errorf("the provenance label does not say what parsed means: %q", c.TTLProvenanceLabel)
	}
	// The engine's ladder names the rung. On this target there is no iat, so it must say nbf.
	if !strings.Contains(c.TTLEvidence, "nbf") {
		t.Errorf("the evidence does not name the claims the number came from: %q", c.TTLEvidence)
	}
	if !strings.Contains(c.TTLEvidence, "upper bound") {
		t.Errorf("an nbf-derived TTL must be labelled an upper bound: %q", c.TTLEvidence)
	}
	if c.TTLSeconds != 900 {
		t.Errorf("ttl_seconds is %d; exp minus nbf is 900. A field named seconds must hold seconds", c.TTLSeconds)
	}
	// And the claims that matter are on screen, with their values.
	byName := map[string]string{}
	for _, cl := range c.Claims {
		byName[cl.Name] = cl.Value
	}
	for _, want := range []string{"alg", "kid", "iss", "jti", "sub", "aud", "nbf", "exp"} {
		if byName[want] == "" {
			t.Errorf("the claims table has no %s; every claim the token carries belongs on it", want)
		}
	}
	if byName["alg"] != "ES256" {
		t.Errorf("alg reads %q, want ES256", byName["alg"])
	}
	// EVERY CLAIM IS A ROW WITH ITS VALUE, AND nbf IS THE ONE THAT PROVES IT. It used to reach the
	// screen only as a name inside a roster string, which is a table telling the operator a claim
	// exists and refusing to say what it says.
	if byName["nbf"] != fmt.Sprint(now.Add(-30*time.Second).Unix()) {
		t.Errorf("nbf reads %q, want the value the token carries", byName["nbf"])
	}
	if byName["sub"] != "user-1" {
		t.Errorf("sub reads %q, want user-1. Who a captured token is for is the finding", byName["sub"])
	}
	if byName["claims"] != "" {
		t.Errorf("the claims table still carries a roster row beside the claims themselves: %q", byName["claims"])
	}
}

// Survives has three states and the wire keeps all three. An unmeasured lifetime against a 29
// minute run must answer "unknown", not "yes".
func TestTheSurvivalVerdictKeepsItsThirdState(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 9, 43, 0, time.UTC)
	opaque := profiledToken("tok-opaque", "php session", "8f14e45fceea167a5a36dedd4bea2543", cookieCarrier, true, now)
	short := profiledToken("tok-short", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)
	long := profiledToken("tok-long", "long bearer",
		investigateJWT(t, now.Add(-time.Minute), now.Add(11*time.Hour)),
		CredentialCarrier{Kind: "header", Name: "X-Long"}, true, now)

	report := buildSessionInvestigation("target-1", []SessionToken{opaque, short, long},
		sessionInvestigateOptions{RunMinutes: 29}, now)

	want := map[string]string{"tok-opaque": "unknown", "tok-short": "no", "tok-long": "yes"}
	for _, c := range report.Credentials {
		if c.Survives == nil {
			t.Fatalf("%s has no survival verdict against a run that was asked about", c.TokenID)
		}
		if c.Survives.Answer != want[c.TokenID] {
			t.Errorf("%s answers %q against a 29m run, want %q (%s)",
				c.TokenID, c.Survives.Answer, want[c.TokenID], c.Survives.Why)
		}
		if strings.TrimSpace(c.Survives.Why) == "" {
			t.Errorf("%s gives a verdict and no reason", c.TokenID)
		}
	}
	// unknown is not ok. A gate reading only the boolean must not read it as a yes.
	for _, c := range report.Credentials {
		if c.TokenID == "tok-opaque" && (c.Survives.OK || c.Survives.Known) {
			t.Error("an unmeasured credential reported ok or known against a run length")
		}
	}
}

// Nobody asked about a run length, so nobody gets a verdict about one. A verdict against an
// assumed run is a number nobody asked for wearing the clothes of one somebody did.
func TestNoRunLengthAskedMeansNoSurvivalVerdict(t *testing.T) {
	now := time.Now().UTC()
	tok := profiledToken("tok-1", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)
	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)
	if report.Credentials[0].Survives != nil {
		t.Fatalf("a survival verdict appeared for a run nobody named: %+v", report.Credentials[0].Survives)
	}
	if report.RunMinutes != 0 {
		t.Errorf("run_minutes is %d with no run asked about", report.RunMinutes)
	}
}

// Renewal may only be offered as a working option once a refresh has actually been performed, so
// the four statuses have to survive the trip to the screen distinctly.
func TestRefreshStatusReachesTheScreenUnflattened(t *testing.T) {
	now := time.Now().UTC()
	tok := profiledToken("tok-1", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)
	tok.Profile.Refresh = RefreshCapability{
		Status: RefreshMintOutOfScope, Mechanism: RefreshMechanismOAuthRefresh,
		MintHost: "authx.issuer.test", MintInScope: false,
		Evidence: []string{"the token endpoint is on a host outside this engagement"},
	}
	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)
	c := report.Credentials[0]
	if c.Refresh.Status != RefreshMintOutOfScope {
		t.Fatalf("refresh status arrived as %q", c.Refresh.Status)
	}
	if c.Refresh.MintHost != "authx.issuer.test" || c.Refresh.MintInScope {
		t.Errorf("the mint host and its scope did not survive: %+v", c.Refresh)
	}
	found := false
	for _, n := range report.Notes {
		if strings.Contains(n, "outside this engagement") {
			found = true
		}
	}
	if !found {
		t.Errorf("the report does not tell the operator they can still re-authenticate by hand: %v", report.Notes)
	}
	if report.Counts.RefreshProven != 0 {
		t.Errorf("refresh_proven is %d for a mechanism nobody exercised", report.Counts.RefreshProven)
	}
}

// ---------------------------------------------------------------------------------------------
// 5. The endpoint refuses what it cannot act on
// ---------------------------------------------------------------------------------------------

// A PUT that accepted an unrecognised body and answered saved:true is a live defect elsewhere in
// this codebase. This endpoint refuses instead, on both the query and the body.
func TestTheEndpointRefusesWhatItCannotActOn(t *testing.T) {
	now := time.Now().UTC()
	tokens := []SessionToken{profiledToken("tok-1", "app bearer", "abcdef0123456789", bearerCarrier, true, now)}

	cases := []struct {
		name, method, url, body string
		wantStatus              int
		wantIn                  string
	}{
		{"unknown query parameter", http.MethodGet,
			"/session-tokens/target/target-1/investigate?run_mins=30", "", http.StatusBadRequest, "run_mins"},
		{"run_minutes not a number", http.MethodGet,
			"/session-tokens/target/target-1/investigate?run_minutes=thirty", "", http.StatusBadRequest, "whole number"},
		{"run_minutes zero", http.MethodGet,
			"/session-tokens/target/target-1/investigate?run_minutes=0", "", http.StatusBadRequest, "between 1"},
		{"run_minutes absurd", http.MethodGet,
			"/session-tokens/target/target-1/investigate?run_minutes=99999999", "", http.StatusBadRequest, "between 1"},
		{"unknown body field", http.MethodPost,
			"/session-tokens/target/target-1/investigate", `{"reprofile":true,"renew":true}`,
			http.StatusBadRequest, "renew"},
		{"malformed body", http.MethodPost,
			"/session-tokens/target/target-1/investigate", `{"reprofile":`, http.StatusBadRequest, "can act on"},
		{"good query", http.MethodGet,
			"/session-tokens/target/target-1/investigate?run_minutes=29", "", http.StatusOK, `"run_minutes":29`},
		{"empty body is a plain re-measure", http.MethodPost,
			"/session-tokens/target/target-1/investigate", "", http.StatusOK, `"reprofiled":true`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := investigateRecorder(t, tokens, tc.method, tc.url, tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantIn) {
				t.Errorf("the response does not mention %q: %s", tc.wantIn, rec.Body.String())
			}
		})
	}
}

// A load failure is a 500 and not an empty report. An empty report would read as "this target has
// no credentials", which is a statement of fact we are in no position to make.
func TestALoadFailureIsNotAnEmptyReport(t *testing.T) {
	restore := sessionInvestigateLoader
	defer func() { sessionInvestigateLoader = restore }()
	sessionInvestigateLoader = func(ctx context.Context, id string, reprofile bool) ([]SessionToken, error) {
		return nil, fmt.Errorf("no database connection")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/session-tokens/target/target-1/investigate", nil)
	investigateRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "NO SESSION") {
		t.Error("a database failure was rendered as the target having no session")
	}
}

// POST re-measures, GET does not. The screen's Re-measure button and its initial load are
// different acts and the report says which one happened.
func TestPostReMeasuresAndGetDoesNot(t *testing.T) {
	now := time.Now().UTC()
	tokens := []SessionToken{profiledToken("tok-1", "app bearer", "abcdef0123456789", bearerCarrier, true, now)}

	var sawReprofile []bool
	restore := sessionInvestigateLoader
	defer func() { sessionInvestigateLoader = restore }()
	sessionInvestigateLoader = func(ctx context.Context, id string, reprofile bool) ([]SessionToken, error) {
		sawReprofile = append(sawReprofile, reprofile)
		return tokens, nil
	}

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/session-tokens/target/target-1/investigate", nil),
		httptest.NewRequest(http.MethodPost, "/session-tokens/target/target-1/investigate", nil),
	} {
		rec := httptest.NewRecorder()
		investigateRouter().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", req.Method, rec.Code, rec.Body.String())
		}
	}
	if len(sawReprofile) != 2 || sawReprofile[0] || !sawReprofile[1] {
		t.Fatalf("GET/POST reprofile flags were %v, want [false true]", sawReprofile)
	}
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

func investigateRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/session-tokens/target/{scope_target_id}/investigate",
		InvestigateSessionTokens).Methods("GET", "POST", "OPTIONS")
	return r
}

func investigateRecorder(t *testing.T, tokens []SessionToken, method, url, body string) *httptest.ResponseRecorder {
	t.Helper()
	restore := sessionInvestigateLoader
	t.Cleanup(func() { sessionInvestigateLoader = restore })
	sessionInvestigateLoader = func(ctx context.Context, id string, reprofile bool) ([]SessionToken, error) {
		return tokens, nil
	}

	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, url, nil)
	} else {
		req = httptest.NewRequest(method, url, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	investigateRouter().ServeHTTP(rec, req)
	return rec
}

func investigateVia(t *testing.T, tokens []SessionToken, method, url string) string {
	t.Helper()
	rec := investigateRecorder(t, tokens, method, url, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// ===============================================================================================
// ROUND 12: THE SCREEN AND THE RUNNER AGREE ABOUT WHAT GOES ON THE WIRE
// ===============================================================================================
//
// The round 11 verification measured four ways this screen was structurally present and
// functionally hollow. The tests below are the four, each carrying the output the old behaviour
// produced.

// wireFixture assembles the reading the runner's own source would produce, with the reading marked
// as read. It is the seam's return value, so the merge is exercised with no database.
func wireFixture(host string, creds ...sessionWireCredential) ([]sessionWireCredential, SessionWireReading) {
	return creds, SessionWireReading{
		Known:   true,
		Host:    host,
		Sources: []string{"session_tokens", "manual_crawl_captures"},
		Fresh:   len(creds),
	}
}

// capturedBearer is one credential the manual crawl caught going past, shaped exactly as
// triageDBFreshCreds.captureCandidates produces it: the whole header value including the scheme.
func capturedBearer(value string, observed, expires time.Time) sessionWireCredential {
	return sessionWireCredential{
		Carrier:      CredentialCarrier{Kind: "header", Name: "Authorization", Prefix: credentialSchemePrefix(value)},
		Value:        value,
		Fingerprint:  triageCredFingerprint(value),
		Source:       "manual_crawl_captures",
		Observed:     observed,
		Expires:      expires,
		ExpirySource: "the token's own exp claim",
	}
}

// ---------------------------------------------------------------------------------------------
// A. The screen reads the same source the runner reads
// ---------------------------------------------------------------------------------------------

// FAIL FIRST, measured against the tree as it stood:
//
//	--- FAIL: TestFailFirstA_TheScreenIgnoresTheCapturedCredentialTheRunnerWouldSend
//	    THE DEFECT: the tile reads "NO SESSION"/"none" while the runner would send a credential
//	    captured 90s ago; buildSessionInvestigation has no input for manual_crawl_captures at all
//
// The live engagement's shape exactly: the stored bearer's own exp passed fifteen minutes ago and
// the working one is a capture from ninety seconds back. The old screen said NO SESSION while the
// runner authenticated happily.
func TestACapturedCredentialTheRunnerWouldSendIsOnTheScreen(t *testing.T) {
	now := time.Date(2026, 9, 20, 13, 55, 0, 0, time.UTC)
	stale := profiledToken("tok-1", "app bearer",
		investigateJWT(t, now.Add(-30*time.Minute), now.Add(-15*time.Minute)), bearerCarrier, true, now)

	live := "Bearer " + investigateJWT(t, now.Add(-90*time.Second), now.Add(810*time.Second))
	wire, reading := wireFixture("app.example.test", capturedBearer(live, now.Add(-90*time.Second), now.Add(810*time.Second)))

	report := buildSessionInvestigation("target-1", []SessionToken{stale},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	if report.TTLMetric.State == "none" {
		t.Fatalf("the tile still reads %q while the runner would send a captured credential",
			report.TTLMetric.Value)
	}
	if report.Counts.Captured != 1 {
		t.Fatalf("counts.captured is %d, want 1: the capture is not on the screen at all", report.Counts.Captured)
	}
	if report.Counts.OnWire != 1 {
		t.Errorf("counts.on_wire is %d, want 1", report.Counts.OnWire)
	}
	// The stored one is still listed, and it says what happens to it instead.
	var storedRow, capturedRow *InvestigatedCredential
	for i := range report.Credentials {
		if report.Credentials[i].Stored {
			storedRow = &report.Credentials[i]
		} else {
			capturedRow = &report.Credentials[i]
		}
	}
	if storedRow == nil || capturedRow == nil {
		t.Fatalf("the report holds %d credentials; want the stored row and the captured one",
			len(report.Credentials))
	}
	if storedRow.OnTheWire {
		t.Error("a credential whose own exp passed 15m ago is reported as what goes on the wire")
	}
	if !strings.Contains(storedRow.WireNote, "different credential") {
		t.Errorf("the stored row does not say what goes out instead: %q", storedRow.WireNote)
	}
	if capturedRow.Source != "manual_crawl_captures" {
		t.Errorf("the captured credential's source reads %q", capturedRow.Source)
	}
	if !strings.Contains(capturedRow.SourceLabel, "manual crawl") {
		t.Errorf("the source is not in the operator's words: %q", capturedRow.SourceLabel)
	}
	if capturedRow.Stored {
		t.Error("a captured credential reported itself as a row in the Session Manager")
	}
	if !capturedRow.Governs {
		t.Error("the card is not about the credential the runner would send")
	}
	// And it was characterised by the same engine, so its lifetime is a measurement and not a gap.
	if !capturedRow.TTLKnown || capturedRow.TTLSeconds != 900 {
		t.Errorf("the captured credential's lifetime reads %q/%ds; exp minus nbf is 900",
			capturedRow.TTLShort, capturedRow.TTLSeconds)
	}
	if report.TTLMetric.Value != "15m" || !report.TTLMetric.Known {
		t.Errorf("the tile reads %q/known=%v for a single measured credential on the wire",
			report.TTLMetric.Value, report.TTLMetric.Known)
	}
}

// A stored credential the runner WOULD send is recognised as the same token rather than listed
// twice. The match is on the bytes that go out, prefix included, which is what the runner
// fingerprints: a bearer's stored value and its wire value differ by "Bearer " and fingerprinting
// the wrong one would report every stored bearer as replaced by a stranger.
func TestAStoredCredentialTheRunnerSendsIsMatchedAndNotDuplicated(t *testing.T) {
	now := time.Date(2026, 9, 20, 13, 55, 0, 0, time.UTC)
	value := investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second))
	stored := profiledToken("tok-1", "app bearer", value, bearerCarrier, true, now)

	// The runner's source found the SAME row and hands it out with the prefix attached.
	onWire := sessionWireCredential{
		Carrier:      CredentialCarrier{Kind: "header", Name: "Authorization", Prefix: "Bearer "},
		Value:        "Bearer " + value,
		Fingerprint:  triageCredFingerprint("Bearer " + value),
		Source:       "session_tokens",
		Observed:     now.Add(-time.Hour),
		Expires:      now.Add(870 * time.Second),
		ExpirySource: "the token's own exp claim",
	}
	wire, reading := wireFixture("app.example.test", onWire)

	report := buildSessionInvestigation("target-1", []SessionToken{stored},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	if len(report.Credentials) != 1 {
		t.Fatalf("one credential in two tables became %d rows on screen", len(report.Credentials))
	}
	c := report.Credentials[0]
	if !c.OnTheWire {
		t.Fatalf("the stored credential the runner hands out is not marked as going on the wire: %q", c.WireNote)
	}
	if c.WireExpiresAt == nil || !c.WireExpiresAt.Equal(now.Add(870*time.Second)) {
		t.Errorf("the runner's own reading of the expiry did not reach the row: %v", c.WireExpiresAt)
	}
	if !strings.Contains(c.WireExpirySource, "exp claim") {
		t.Errorf("the row does not say which expiry the runner read: %q", c.WireExpirySource)
	}
	if report.Counts.Captured != 0 {
		t.Errorf("counts.captured is %d for a credential that is stored", report.Counts.Captured)
	}
}

// WHEN THE RUNNER'S SOURCE CANNOT BE CONSULTED THE REPORT SAYS SO. An empty wire set would be this
// screen asserting the runner sends nothing, which is a fact nobody read.
func TestAnUnreadWireIsSaidOutLoudAndIsNotAnEmptyOne(t *testing.T) {
	now := time.Date(2026, 9, 20, 13, 55, 0, 0, time.UTC)
	tok := profiledToken("tok-1", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)

	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{
		WireReading: SessionWireReading{Known: false, WhyNotKnown: "this process has no database handle"},
	}, now)

	if report.Wire.Known {
		t.Fatal("an unread wire reported itself as read")
	}
	if !investigateNoteSays(report.Notes, "WAS NOT READ") {
		t.Fatalf("the report does not say the wire was not read: %v", report.Notes)
	}
	if !investigateNoteSays(report.Notes, "no database handle") {
		t.Errorf("the report does not say WHY the wire was not read: %v", report.Notes)
	}
	// The stored credential still governs, because it is the only thing there is to say, and the
	// tile carries the caveat rather than presenting itself as a reading of the wire.
	if report.Governing == nil || report.Governing.TokenID != "tok-1" {
		t.Fatalf("nothing governs the card with the wire unread: %+v", report.Governing)
	}
	if report.TTLMetric.Known {
		t.Errorf("the tile is styled as a settled measurement while what goes out was never read: %+v",
			report.TTLMetric)
	}
	if report.TTLMetric.State != "measured_partial" {
		t.Errorf("state is %q, want measured_partial", report.TTLMetric.State)
	}
	if !strings.Contains(report.TTLMetric.Explain, "could not be read") {
		t.Errorf("the tile's explanation does not carry the caveat: %q", report.TTLMetric.Explain)
	}
}

// A stored credential that IS sendable by the Session Manager's rules and is NOT what the runner
// hands out is a real disagreement between two layers, and the report names it rather than
// silently preferring one.
func TestADisagreementBetweenTheScreenAndTheRunnerIsNamed(t *testing.T) {
	now := time.Date(2026, 9, 20, 13, 55, 0, 0, time.UTC)
	// Live by every column and by its own exp, but scoped to a domain that is not this host, which
	// is one of the reasons the runner's source refuses a row.
	live := profiledToken("tok-1", "other-domain bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)

	wire, reading := wireFixture("app.example.test")
	report := buildSessionInvestigation("target-1", []SessionToken{live},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	if report.Credentials[0].OnTheWire {
		t.Fatal("a credential the runner's source did not hand out is reported as going on the wire")
	}
	if !report.Credentials[0].Sendable {
		t.Fatal("the fixture is wrong: this credential is sendable by the stored rules")
	}
	if !investigateNoteSays(report.Notes, "disagree") {
		t.Fatalf("the two layers disagree about one credential and no note says so: %v", report.Notes)
	}
	if !investigateNoteSays(report.Notes, "other-domain bearer") {
		t.Errorf("the note does not name the credential they disagree about: %v", report.Notes)
	}
	if report.TTLMetric.State != "none" {
		t.Errorf("the tile reads %q/%q; the runner would send nothing at all",
			report.TTLMetric.Value, report.TTLMetric.State)
	}
}

// The captured credential is a credential, and it is served like any other. The assertion is
// against the serialised response because a json tag is what decides this.
func TestACapturedCredentialIsServedWhole(t *testing.T) {
	now := time.Date(2026, 9, 20, 13, 55, 0, 0, time.UTC)
	secret := "Bearer " + investigateJWT(t, now.Add(-90*time.Second), now.Add(810*time.Second))
	cookie := "s%3AKf8Uq2Xn4pLz9Wm1Tv6Rb3Yc7Hd0Ge5J.aVerySecretSessionIdentifier"

	wire, reading := wireFixture("app.example.test",
		capturedBearer(secret, now.Add(-90*time.Second), now.Add(810*time.Second)),
		sessionWireCredential{
			Carrier:     CredentialCarrier{Kind: "cookie", Name: "connect.sid"},
			Value:       cookie,
			Fingerprint: triageCredFingerprint(cookie),
			Source:      "manual_crawl_captures",
			Observed:    now.Add(-2 * time.Minute),
		})

	report := buildSessionInvestigation("target-1", nil,
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{strings.TrimPrefix(secret, "Bearer "), cookie} {
		if !strings.Contains(body, want) {
			t.Fatalf("the response does not carry the captured credential:\n%s", body)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// C. One run length, published once
// ---------------------------------------------------------------------------------------------

// FAIL FIRST:
//
//	--- FAIL: TestFailFirstC_TheReportPublishesNoRunLength
//	    THE DEFECT: the report carries no run length, so nothing makes the modal's hardcoded 29
//	    minutes and the gate's 20m1s agree (an estimated 20m1s: 4000 probes at 3.33 per second)
func TestTheReportPublishesTheOneRunLengthTheRenewalGateUses(t *testing.T) {
	now := time.Now().UTC()
	gate, basis := TriageEstimatedRunDuration(TriageSettingsDefaults().Pacing)
	if gate <= 0 {
		t.Fatalf("the defaults produce no run estimate at all: %s", basis)
	}
	// Rounded UP. Rounding down is the direction that lies: a credential dying at minute 20 of a
	// 20m1s run would be reported as surviving a 20 minute one.
	want := int((gate + time.Minute - 1) / time.Minute)

	report := buildSessionInvestigation("target-1", nil, sessionInvestigateOptions{
		DefaultRunMinutes: want, RunLengthBasis: basis,
	}, now)
	if report.DefaultRunMinutes != want {
		t.Fatalf("default_run_minutes is %d, want %d (the gate's %s)", report.DefaultRunMinutes, want, humaniseTTL(gate))
	}
	if report.RunLengthBasis == "" {
		t.Error("the run length is published with no basis, so a screen cannot say where it came from")
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\"default_run_minutes\":") {
		t.Errorf("default_run_minutes is not on the wire: %s", raw)
	}
}

// triageConfiguredRunMinutes rounds UP and says so, and answers zero rather than a guess when the
// pacing cannot be read.
func TestTheConfiguredRunLengthRoundsUpAndRefusesToGuess(t *testing.T) {
	// dbPool is nil in this package's tests, which is the "cannot be read" path.
	mins, basis := triageConfiguredRunMinutes(context.Background(), "target-1")
	if mins != 0 {
		t.Fatalf("a run length of %d minutes was produced with no database to read the pacing from", mins)
	}
	if !strings.Contains(basis, "could not be read") {
		t.Errorf("the basis does not say the pacing was not read: %q", basis)
	}
}

// ---------------------------------------------------------------------------------------------
// D. The tile is not confident when something going out is unmeasured
// ---------------------------------------------------------------------------------------------

// FAIL FIRST:
//
//	--- FAIL: TestFailFirstD_TheTileIsConfidentBesideAnUnmeasuredSibling
//	    THE DEFECT: the tile reads "15m" with known=true and state="measured" while 1 of the 2
//	    credentials this scan would send have no measured lifetime; the caveat is only in notes[],
//	    which the card does not render
func TestTheTileIsNotConfidentWhenASiblingIsUnmeasured(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 9, 43, 0, time.UTC)
	measured := profiledToken("tok-measured", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)
	unmeasured := profiledToken("tok-opaque", "php session",
		"8f14e45fceea167a5a36dedd4bea2543", cookieCarrier, true, now)

	bearerWire := sessionWireCredential{
		Carrier: CredentialCarrier{Kind: "header", Name: "Authorization", Prefix: "Bearer "},
		Value:   "Bearer " + measured.TokenValue, Fingerprint: triageCredFingerprint("Bearer " + measured.TokenValue),
		Source: "session_tokens", Expires: now.Add(870 * time.Second), ExpirySource: "the token's own exp claim",
	}
	cookieWire := sessionWireCredential{
		Carrier: CredentialCarrier{Kind: "cookie", Name: "PHPSESSID"},
		Value:   unmeasured.TokenValue, Fingerprint: triageCredFingerprint(unmeasured.TokenValue),
		Source: "session_tokens",
	}
	wire, reading := wireFixture("app.example.test", bearerWire, cookieWire)

	report := buildSessionInvestigation("target-1", []SessionToken{measured, unmeasured},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	if report.TTLMetric.Known {
		t.Fatalf("the tile claims a settled measurement beside an unmeasured credential that also goes out: %+v",
			report.TTLMetric)
	}
	if report.TTLMetric.State != "measured_partial" {
		t.Fatalf("state is %q, want measured_partial", report.TTLMetric.State)
	}
	// The number is still there: an upper bound is real information and dropping it would be the
	// opposite error. It is spelled so it cannot be read as a settled lifetime.
	if report.TTLMetric.Value != "<=15m" {
		t.Errorf("the tile reads %q, want <=15m", report.TTLMetric.Value)
	}
	// THE CAVEAT IS ON THE TILE, not only in notes[]. The card renders detail and explain; it does
	// not render notes, and that is where this sentence used to live alone.
	if !strings.Contains(report.TTLMetric.Detail, "at most") {
		t.Errorf("the tile's one line does not say the number is a bound: %q", report.TTLMetric.Detail)
	}
	if !strings.Contains(report.TTLMetric.Explain, "UPPER BOUND") {
		t.Errorf("the tile's explanation does not say the number is a bound: %q", report.TTLMetric.Explain)
	}
	if !strings.Contains(report.TTLMetric.Explain, "die sooner") {
		t.Errorf("the tile's explanation does not say what could make it wrong: %q", report.TTLMetric.Explain)
	}
}

// And with every credential on the wire measured, the tile IS confident. A rule that made every
// tile read as a bound would be as useless as one that made none of them.
func TestTheTileIsConfidentWhenEverythingGoingOutIsMeasured(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 9, 43, 0, time.UTC)
	short := profiledToken("tok-short", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)
	long := profiledToken("tok-long", "long bearer",
		investigateJWT(t, now.Add(-time.Minute), now.Add(11*time.Hour)),
		CredentialCarrier{Kind: "header", Name: "X-Long"}, true, now)

	mk := func(tok SessionToken, name, prefix string) sessionWireCredential {
		v := prefix + tok.TokenValue
		return sessionWireCredential{
			Carrier: CredentialCarrier{Kind: "header", Name: name, Prefix: prefix},
			Value:   v, Fingerprint: triageCredFingerprint(v), Source: "session_tokens",
		}
	}
	wire, reading := wireFixture("app.example.test",
		mk(short, "Authorization", "Bearer "), mk(long, "X-Long", ""))

	report := buildSessionInvestigation("target-1", []SessionToken{short, long},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	if !report.TTLMetric.Known || report.TTLMetric.State != "measured" {
		t.Fatalf("the tile is hedged with everything on the wire measured: %+v", report.TTLMetric)
	}
	if report.TTLMetric.Value != "15m" {
		t.Errorf("the tile reads %q, want 15m", report.TTLMetric.Value)
	}
	if report.Counts.TTLUnknown != 0 {
		t.Errorf("ttl_unknown is %d with both credentials measured", report.Counts.TTLUnknown)
	}
}

// A QUERY CREDENTIAL IS NOT A DISAGREEMENT. The runner's source substitutes named carriers in the
// head of a request and skips query credentials by name, because rewriting a URL there would move
// a payload a class placed in the query string. The row says that rather than reporting the two
// layers as being at odds.
func TestAQueryCredentialIsSaidToBeOutsideTheSubstitutionLayer(t *testing.T) {
	now := time.Date(2026, 9, 20, 13, 55, 0, 0, time.UTC)
	q := profiledToken("tok-q", "api key in the query",
		"8f14e45fceea167a5a36dedd4bea2543", CredentialCarrier{Kind: "query", Name: "api_key"}, true, now)

	wire, reading := wireFixture("app.example.test")
	report := buildSessionInvestigation("target-1", []SessionToken{q},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	c := report.Credentials[0]
	if c.OnTheWire {
		t.Fatal("a query credential the source never substitutes is reported as one it hands out")
	}
	if !strings.Contains(c.WireNote, "does not substitute query-string") {
		t.Fatalf("the row does not say why the source is silent about it: %q", c.WireNote)
	}
	if investigateNoteSays(report.Notes, "disagree") {
		t.Errorf("a query credential was reported as the two layers disagreeing: %v", report.Notes)
	}
}

// ---------------------------------------------------------------------------------------------
// Round 13: no sentence may call a floor observed unless something observed it
// ---------------------------------------------------------------------------------------------

// THE TILE SENTENCE MUST NAME HOW THE FLOOR WAS GOT. A probed floor is a request this framework
// sent and watched work; describing it as "captured traffic" tells the operator a client was seen
// still sending the value, which is a different fact, and on a profile whose corpus held nothing
// it is a fact nobody read.
func TestTheFloorSentenceSaysHowTheFloorWasGot(t *testing.T) {
	now := time.Now().UTC()
	tok := profiledToken("tok-1", "php session", "8f14e45fceea167a5a36dedd4bea2543", cookieCarrier, true, now)
	tok.Profile.TTLFloor = 45 * time.Minute
	tok.Profile.TTLFloorKnown = true
	tok.Profile.TTLFloorProvenance = ProvProbed
	tok.Profile.TTLFloorEvidence = "the framework used this credential successfully twice, 45m apart"
	// The corpus held NOTHING, which is what makes the observed wording a fact nobody read.
	tok.Profile.ObservedSamples = 0
	tok.Profile.ObservedRequests = 0
	tok.Profile.ObservedEvidence = "no captured request carried this cookie"

	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)
	explain := report.TTLMetric.Explain
	if strings.Contains(strings.ToLower(explain), "captured traffic") {
		t.Fatalf("a probed floor was described as captured traffic: %q", explain)
	}
	if !strings.Contains(explain, "45m") {
		t.Errorf("the tile lost the floor it does know: %q", explain)
	}
	if !strings.Contains(explain, "floor and not a lifetime") {
		t.Errorf("the tile no longer says the floor is not a lifetime: %q", explain)
	}
	if !strings.Contains(explain, tok.Profile.TTLFloorEvidence) {
		t.Errorf("the tile does not carry the evidence behind the floor: %q", explain)
	}
	if report.Credentials[0].TTLFloorProvenance != string(ProvProbed) {
		t.Errorf("the wire does not carry how the floor was got: %q", report.Credentials[0].TTLFloorProvenance)
	}

	// An observed floor still says so, because that IS what the corpus shows.
	obs := profiledToken("tok-2", "php session", "8f14e45fceea167a5a36dedd4bea2544", cookieCarrier, true, now)
	obs.Profile.TTLFloor = 14*time.Minute + 28*time.Second
	obs.Profile.TTLFloorKnown = true
	obs.Profile.TTLFloorProvenance = ProvObserved
	obs.Profile.ObservedSamples = 51
	obs.Profile.ObservedRequests = 3701
	obs.Profile.ObservedEvidence = "51 distinct values across 3701 captured requests"
	obsReport := buildSessionInvestigation("target-1", []SessionToken{obs}, sessionInvestigateOptions{}, now)
	if !strings.Contains(strings.ToLower(obsReport.TTLMetric.Explain), "captured traffic") {
		t.Errorf("an observed floor stopped naming the corpus: %q", obsReport.TTLMetric.Explain)
	}
}

// The word beside the number has to describe the thing that happened. Nothing in this package
// uses a credential until it stops working, so a label saying so is a probe that does not exist.
func TestTheProbedLabelDescribesTheProbeThatActuallyRuns(t *testing.T) {
	label := provenanceLabel(ProvProbed)
	if strings.Contains(label, "until it died") {
		t.Fatalf("the probed label describes a probe nothing runs: %q", label)
	}
	for _, want := range []string{"framework", "worked"} {
		if !strings.Contains(strings.ToLower(label), want) {
			t.Errorf("the probed label does not say what was done: %q", label)
		}
	}
}

// TWO FIELDS IN ONE PAYLOAD MUST NOT CONTRADICT EACH OTHER. expiry_style_label said non-expiring
// "was measured rather than assumed" in the same response whose survival sentence said nothing
// established it; whichever the operator reads, they cannot tell it is disputed.
func TestTheNonExpiringLabelDoesNotClaimAMeasurementNothingMade(t *testing.T) {
	unmeasured := expiryStyleLabelFor(ExpiryStyleNonExpiring, ProvUnknown)
	if strings.Contains(unmeasured, "measured rather than assumed") {
		t.Fatalf("an unmeasured non-expiring style still claims it was measured: %q", unmeasured)
	}
	if !strings.Contains(unmeasured, "nothing says how") {
		t.Errorf("the label does not say the claim is unestablished: %q", unmeasured)
	}
	measured := expiryStyleLabelFor(ExpiryStyleNonExpiring, ProvProbed)
	if !strings.Contains(measured, "probed") {
		t.Errorf("a non-expiring style that WAS established does not name how: %q", measured)
	}

	// And the two fields of one payload agree.
	now := time.Now().UTC()
	tok := profiledToken("tok-1", "api key", "invented-opaque-api-value", bearerCarrier, true, now)
	tok.Profile.ExpiryStyle = ExpiryStyleNonExpiring
	tok.Profile.ExpiryProvenance = ProvUnknown
	report := buildSessionInvestigation("target-1", []SessionToken{tok},
		sessionInvestigateOptions{RunMinutes: 60}, now)
	cred := report.Credentials[0]
	if cred.Survives == nil {
		t.Fatal("no survival verdict was produced for a run length that was asked about")
	}
	if cred.Survives.Known {
		t.Fatalf("an unmeasured non-expiring style answered a survival question: %q", cred.Survives.Why)
	}
	if strings.Contains(cred.ExpiryStyleLabel, "measured rather than assumed") {
		t.Fatalf("the style label claims a measurement the survival sentence denies: %q vs %q",
			cred.ExpiryStyleLabel, cred.Survives.Why)
	}
}

// AN ISSUE TIME READ OUT OF nbf IS NOT AN ISSUE TIME. The wire has to carry which claim answered,
// because the screen renders the timestamp either way.
func TestTheWireSaysWhereTheIssueTimeCameFrom(t *testing.T) {
	now := time.Now().UTC()
	tok := profiledToken("tok-1", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)
	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)
	cred := report.Credentials[0]
	if cred.IssuedAt == nil {
		t.Fatal("the JWT carries an nbf and no issue time reached the wire at all")
	}
	if cred.IssuedAtSource != string(IssuedAtClaimNbf) {
		t.Fatalf("issued_at_source = %q, want nbf", cred.IssuedAtSource)
	}
	if cred.IssuedAtIsMintTime {
		t.Fatal("an nbf claim was published as the moment the credential was minted")
	}
	if !strings.Contains(cred.IssuedAtEvidence, "not-before") {
		t.Fatalf("the caveat does not say what was read: %q", cred.IssuedAtEvidence)
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{"issued_at_source", "issued_at_is_mint_time", "issued_at_evidence", "ttl_floor_provenance"} {
		if !strings.Contains(string(blob), want) {
			t.Errorf("the payload does not carry %s", want)
		}
	}
}

// AND IT IS NOT TOLD THAT A SEARCH FOR A REFRESH MECHANISM WAS RUN.
//
// The same defect the renewal gate had, in the other surface. investigateOne seeded every
// credential with RefreshCapability{Status: RefreshNotObserved} and returned early when no profile
// was attached, so a credential nobody had opened came back saying not_observed. That status is
// the answer of a search: DetectRefreshCapability writes it after reading the auth flows, the
// captured corpus and the token's own grants, and none of those is read on this branch.
//
// SessionInvestigateModal.js renders the status through REFRESH_WORD, where not_observed reads
// "None observed", so the operator is shown a finding where there is an absence of one.
func TestAnUncharacterisedCredentialIsNotToldASearchFoundNoRefresh(t *testing.T) {
	now := time.Now().UTC()
	unprofiled := SessionToken{ID: "tok-1", Name: "never measured", TokenValue: "abc123", IsActive: true,
		TokenType: "cookie", CookieName: "sid"}

	report := buildSessionInvestigation("target-1", []SessionToken{unprofiled}, sessionInvestigateOptions{}, now)
	c := report.Credentials[0]
	if c.Refresh.Status == RefreshNotObserved {
		t.Errorf("a credential nothing has characterised reports refresh status %q, which is the "+
			"answer of a search over the flows, the corpus and the token that this branch never ran", c.Refresh.Status)
	}
	// And it is not the empty string either, because SessionInvestigateModal.js falls back to
	// "None observed" on a falsy status, which puts the same claim back on the screen.
	if c.Refresh.Status == "" {
		t.Error("the refresh status is empty, and the modal's own fallback renders an empty status as \"None observed\"")
	}
	if c.Refresh.Status != RefreshNotCharacterised {
		t.Errorf("refresh status = %q, want %q", c.Refresh.Status, RefreshNotCharacterised)
	}
	if c.Refresh.Evidence == nil {
		t.Error("the evidence list is nil, so the modal cannot map over it")
	}
}

// A characterised credential still carries what the search found, so the change above cannot be a
// blanket that loses the real answer.
func TestACharacterisedCredentialKeepsWhatTheSearchFound(t *testing.T) {
	now := time.Now().UTC()
	tok := profiledToken("tok-2", "php session", "8f14e45fceea167a5a36dedd4bea2543", cookieCarrier, true, now)
	tok.Profile.Refresh = RefreshCapability{Status: RefreshNotObserved, Evidence: []string{"no auth flow, no mint endpoint, no refresh grant"}}

	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)
	if got := report.Credentials[0].Refresh.Status; got != RefreshNotObserved {
		t.Errorf("refresh status = %q, want %q: a real search that found nothing was downgraded", got, RefreshNotObserved)
	}
}

// ---------------------------------------------------------------------------------------------
// The ordering and the caveat must read the SAME facts
// ---------------------------------------------------------------------------------------------

// investigateJWTExpiresIn is a token that declares HOW LONG IT LIVES and not WHEN IT DIES: an
// expires_in claim and no exp. That is the shape that separates a measured LIFETIME from a
// measured REMAINING time, and the separation is the whole subject of the test below.
func investigateJWTExpiresIn(t *testing.T, seconds int) string {
	t.Helper()
	header := `{"alg":"ES256","kid":"TESTKID0000000002","typ":"JWT"}`
	payload := fmt.Sprintf(`{"aud":"test","expires_in":%d,"iss":"https://issuer.test","jti":"jti-2","sub":"user-2"}`,
		seconds)
	enc := func(s string) string { return strings.TrimRight(base64URL(s), "=") }
	return enc(header) + "." + enc(payload) + ".c2lnbmF0dXJl"
}

// FAIL FIRST. chooseGoverningCredential orders on RemainingKnown and sessionTTLMetric raises its
// caveat on TTLKnown, so a credential that has a MEASURED LIFETIME and no issue time is invisible
// to the ordering AND silences the caveat. The tile then reads a settled fifteen minutes beside a
// credential the same scan sends whose measured lifetime is one minute.
func TestAMeasuredLifetimeTheOrderingIgnoredStillReachesTheTile(t *testing.T) {
	now := time.Date(2026, 9, 21, 1, 49, 50, 0, time.UTC)
	long := profiledToken("tok-long", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)
	short := profiledToken("tok-short", "short header",
		investigateJWTExpiresIn(t, 60), CredentialCarrier{Kind: "header", Name: "X-Short"}, true, now)

	if !short.Profile.TTLKnown {
		t.Fatalf("the fixture did not produce a measured lifetime: %+v", short.Profile.TTLEvidence)
	}
	if short.Profile.ExpiryKnown {
		t.Fatalf("the fixture produced an expiry, so it does not exercise the gap being tested")
	}

	mk := func(tok SessionToken, name, prefix string) sessionWireCredential {
		v := prefix + tok.TokenValue
		return sessionWireCredential{
			Carrier: CredentialCarrier{Kind: "header", Name: name, Prefix: prefix},
			Value:   v, Fingerprint: triageCredFingerprint(v), Source: "session_tokens",
		}
	}
	wire, reading := wireFixture("app.example.test",
		mk(long, "Authorization", "Bearer "), mk(short, "X-Short", ""))

	report := buildSessionInvestigation("target-1", []SessionToken{long, short},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	if report.TTLMetric.Known || report.TTLMetric.State != "measured_partial" {
		t.Fatalf("the tile claims a settled lifetime beside a credential this scan sends whose measured "+
			"lifetime is shorter: %+v", report.TTLMetric)
	}
	if report.TTLMetric.Value != "<=15m" {
		t.Errorf("the tile reads %q, want <=15m", report.TTLMetric.Value)
	}
	if !strings.Contains(report.TTLMetric.Explain, "1m") {
		t.Errorf("the tile's explanation never names the shorter measured lifetime it is standing beside: %q",
			report.TTLMetric.Explain)
	}
}

// FAIL FIRST. credentialKindLabels is the one place a kind gets English beside it, and
// credentialKindLabel falls back to the raw token for anything missing. principal_name was added
// to the profiler in the same round and never added here, so a credential the profiler read as a
// pointer at a user renders on the card as the literal string "principal_name".
func TestEveryCredentialKindTheProfilerCanProduceHasWordsOnTheCard(t *testing.T) {
	kinds := []CredentialKind{
		CredentialKindJWT, CredentialKindJWE, CredentialKindPASETO, CredentialKindBranca,
		CredentialKindSAML, CredentialKindSessionID, CredentialKindOpaqueBearer,
		CredentialKindAPIKey, CredentialKindOAuthAccess, CredentialKindPrincipalName,
		CredentialKindUnknown,
	}
	for _, k := range kinds {
		label := credentialKindLabel(k)
		if label == string(k) {
			t.Errorf("kind %q renders on the card as its own raw token, so the screen shows a snake_case "+
				"enum where every other kind has English", k)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Does Re-measure actually re-measure? (against a real database)
// ---------------------------------------------------------------------------------------------
//
// THE SENTENCE THIS VERIFIES IS NOT YET SHIPPED. A round 14 report proposed telling the operator
// to "re-characterise this credential" when a stored floor cannot be trusted, and recorded that
// nobody had checked whether any control actually forces a re-measurement:
// AttachSessionTokenProfiles SKIPS re-profiling whenever the stored fingerprint still matches the
// value held, so advice that resolves to that path would name a button that changes nothing. This test measures both halves of the question on the production
// loader: the skip is real, and the Re-measure path steps over it.
//
// It uses triageTestDB, so with no TRIAGE_TEST_DATABASE_URL it is recorded as NOT MEASURED and the
// package fails at the end of the run. A skip is not a pass.
func TestReMeasureStepsOverTheFingerprintSkipThatTheReadPathTakes(t *testing.T) {
	ctx := triageTestDB(t)
	now := time.Now().UTC()
	value := investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second))
	target, id := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "app bearer", TokenType: "header", HeaderName: "Authorization",
		ValuePrefix: "Bearer ", TokenValue: value, IsActive: true,
	})

	// A STORED MEASUREMENT THAT DESCRIBES THIS EXACT VALUE AND IS WRONG ABOUT IT. The fingerprint
	// matches, which is the only thing the skip looks at, so this is what a row written by an
	// older algorithm looks like to the read path.
	stale := ProfileCredential(NewCredential(value),
		CredentialCarrier{Kind: "header", Name: "Authorization", Prefix: "Bearer "}, now)
	stale.TokenID, stale.ScopeTargetID, stale.Name = id, target, "app bearer"
	stale.Kind, stale.KindEvidence = CredentialKindAPIKey, "written by an older algorithm"
	stale.TTL, stale.TTLKnown, stale.TTLProvenance = 99*time.Hour, true, ProvParsed
	stale.ProfiledAt = now.Add(-time.Hour)
	if err := SaveSessionTokenProfile(ctx, stale); err != nil {
		t.Fatalf("store the stale measurement: %v", err)
	}

	// The read path. This is the half that must NOT change, and it is why the advice had to be
	// checked at all.
	kept, err := loadSessionTokensForInvestigation(ctx, target, false)
	if err != nil {
		t.Fatalf("read path: %v", err)
	}
	if len(kept) != 1 || kept[0].Profile == nil {
		t.Fatalf("the read path returned %d token(s) with a profile attached", len(kept))
	}
	if kept[0].Profile.Kind != CredentialKindAPIKey {
		t.Fatalf("the read path re-measured a value whose fingerprint still matched, so the skip this "+
			"test is about does not exist and the rest of it measures nothing: kind=%q", kept[0].Profile.Kind)
	}

	// The Re-measure path, which is what a POST to the investigate endpoint sends.
	fresh, err := loadSessionTokensForInvestigation(ctx, target, true)
	if err != nil {
		t.Fatalf("re-measure path: %v", err)
	}
	if len(fresh) != 1 || fresh[0].Profile == nil {
		t.Fatalf("the re-measure path returned %d token(s) with a profile attached", len(fresh))
	}
	if fresh[0].Profile.Kind != CredentialKindJWT {
		t.Errorf("RE-MEASURE DID NOT RE-MEASURE: the stored kind %q survived a reprofile of a value whose "+
			"fingerprint still matched, so any advice naming this control names a button that changes nothing",
			fresh[0].Profile.Kind)
	}
	if fresh[0].Profile.TTL == 99*time.Hour {
		t.Errorf("the stale lifetime survived the re-measure: %s", fresh[0].Profile.TTL)
	}

	// AND IT WROTE WHAT IT MEASURED. A re-measure that fixes the screen and leaves the row stale
	// would send the operator back to this button forever.
	back, err := LoadSessionTokenProfile(ctx, id)
	if err != nil {
		t.Fatalf("read the profile back: %v", err)
	}
	if back.Kind != CredentialKindJWT {
		t.Errorf("the re-measure did not reach the row: stored kind is still %q", back.Kind)
	}
}

// THE SHIPPED ADVICE RESTS ON THIS, so it is pinned rather than reasoned about. The two settings
// sentences in triageRenewalOptionFor and its target-level summary tell the operator to "open the
// Session Manager for this target, which characterises every credential it lists". GetSessionTokens characterises
// through the SAME AttachSessionTokenProfiles this loader's read path uses, and those sentences
// are emitted only where the refresh half is empty, which LoadTriageRenewalCredentials clears on
// the branch it takes when there is no usable stored profile. So the advice names a control that
// works exactly where it is given: with nothing stored, the read path measures rather than skips.
func TestTheReadPathCharacterisesACredentialNothingHasMeasured(t *testing.T) {
	ctx := triageTestDB(t)
	now := time.Now().UTC()
	target, id := sessionTokenProfileTestToken(t, ctx, SessionToken{
		Name: "app bearer", TokenType: "header", HeaderName: "Authorization", ValuePrefix: "Bearer ",
		TokenValue: investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), IsActive: true,
	})

	tokens, err := loadSessionTokensForInvestigation(ctx, target, false)
	if err != nil {
		t.Fatalf("read path: %v", err)
	}
	if len(tokens) != 1 || tokens[0].Profile == nil {
		t.Fatalf("the read path returned %d token(s) with a profile attached", len(tokens))
	}
	if tokens[0].Profile.Kind != CredentialKindJWT {
		t.Errorf("the read path left a credential nothing had measured uncharacterised: kind=%q",
			tokens[0].Profile.Kind)
	}
	// And it WROTE the measurement, which is the half that makes the advice stick after the modal
	// is closed.
	back, err := LoadSessionTokenProfile(ctx, id)
	if err != nil {
		t.Fatalf("read the profile back: %v", err)
	}
	if back.ProfiledAt.IsZero() || back.Kind != CredentialKindJWT {
		t.Errorf("the read path measured but did not store: profiled_at zero=%v kind=%q",
			back.ProfiledAt.IsZero(), back.Kind)
	}
	// AND IT LOOKED FOR A REFRESH MECHANISM, which is the second half of the same sentence.
	// ProfileSessionToken calls DetectRefreshCapability; an answer of not_observed IS the answer of
	// a search, and it is the state RefreshNotCharacterised exists to be distinguished from.
	if back.Refresh.Status == RefreshNotCharacterised || back.Refresh.Status == "" {
		t.Errorf("the read path stored no refresh answer, so the advice's second clause is wrong: %q",
			back.Refresh.Status)
	}
}

// FAIL FIRST. A credential the RUNNER would send whose own expiry has already passed. RemainingAt
// subtracts and does not clamp, so it arrives with a negative remaining, sorts first in
// chooseGoverningCredential and used to render its LIFETIME as a settled tile. Measured:
//
//	TILE {Value:15m Known:true State:measured ... Explain:dead bearer lives 15m ... it is the
//	      first of the 2 credentials this scan would send to die: -5m of life left ...}
//
// Not reachable from the stored rows alone: credentialIsSendable refuses an expired credential, so
// the fixture puts it on the WIRE, which is exactly the disagreement credentialGoesOut permits.
func TestATileNeverReportsAHealthyLifetimeForACredentialItReadsAsDead(t *testing.T) {
	now := time.Date(2026, 9, 21, 1, 49, 50, 0, time.UTC)
	dead := profiledToken("tok-dead", "dead bearer",
		investigateJWT(t, now.Add(-20*time.Minute), now.Add(-5*time.Minute)), bearerCarrier, true, now)
	live := profiledToken("tok-live", "live header",
		investigateJWT(t, now.Add(-time.Minute), now.Add(59*time.Minute)),
		CredentialCarrier{Kind: "header", Name: "X-Live"}, true, now)

	mk := func(tok SessionToken, name, prefix string) sessionWireCredential {
		v := prefix + tok.TokenValue
		return sessionWireCredential{
			Carrier: CredentialCarrier{Kind: "header", Name: name, Prefix: prefix},
			Value:   v, Fingerprint: triageCredFingerprint(v), Source: "session_tokens",
		}
	}
	wire, reading := wireFixture("app.example.test",
		mk(dead, "Authorization", "Bearer "), mk(live, "X-Live", ""))
	report := buildSessionInvestigation("target-1", []SessionToken{dead, live},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	if report.TTLMetric.Known {
		t.Fatalf("the tile is styled as a settled measurement for a credential it reads as dead: %+v",
			report.TTLMetric)
	}
	if report.TTLMetric.State != "expired" {
		t.Fatalf("state is %q, want expired: %+v", report.TTLMetric.State, report.TTLMetric)
	}
	if strings.Contains(report.TTLMetric.Value, "15m") {
		t.Errorf("the tile reads %q, which is the dead credential's lifetime", report.TTLMetric.Value)
	}
	if !strings.Contains(report.TTLMetric.Detail, "expired 5m ago") {
		t.Errorf("the one line under the tile does not say it is dead or how long ago: %q",
			report.TTLMetric.Detail)
	}
	// AND NO SENTENCE ANYWHERE CARRIES A NEGATIVE DURATION. "-5m of life left" is a rendering
	// nobody should ever see.
	for _, s := range []string{report.TTLMetric.Detail, report.TTLMetric.Explain,
		report.Governing.WhyThisOne} {
		if strings.Contains(s, "-5m") {
			t.Errorf("a negative duration reached an operator-facing sentence: %q", s)
		}
	}
	if !strings.Contains(report.Governing.WhyThisOne, "ALREADY EXPIRED") {
		t.Errorf("the governing sentence does not say the credential is dead: %q",
			report.Governing.WhyThisOne)
	}
}

// ---------------------------------------------------------------------------------------------
// R16. THE TILE IS WRONG ON A DEAD-TOKEN ESTATE
// ---------------------------------------------------------------------------------------------

// cognitoCookieCarrier is Amplify's storage key shape, which is the shape measured on the engaged
// estate: CognitoIdentityServiceProvider.<app client id>.<subject id>.<leaf>. The middle segment
// is the subject and the first is the application, and the card shows both as they were captured.
func cognitoCookieCarrier(sub, leaf string) CredentialCarrier {
	return CredentialCarrier{
		Kind: "cookie",
		Name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3." + sub + "." + leaf,
	}
}

// capturedCookie is one cookie the manual crawl caught going past, with no readable expiry, which
// is what every Cognito storage cookie on the engaged estate looks like.
func capturedCookie(carrier CredentialCarrier, value string, observed time.Time) sessionWireCredential {
	return sessionWireCredential{
		Carrier:     carrier,
		Value:       value,
		Fingerprint: triageCredFingerprint(value),
		Source:      "manual_crawl_captures",
		Observed:    observed,
	}
}

// liveEstateReport reproduces the shape of the engaged estate's card in one fixture: a stored
// bearer whose whole lifetime was READ out of it and which died long ago, beside captured Cognito
// cookies that carry a subject id in their name, have no readable lifetime, and are what the
// runner would actually send.
//
// THE OPERATOR'S ROW LABEL CARRIES THEIR OWN EMAIL ADDRESS because that is what they typed to tell
// two accounts apart, and it is what the API hands every caller today.
func liveEstateReport(t *testing.T, now time.Time) (SessionInvestigation, string, string) {
	t.Helper()
	const subA = "d4189418-5001-7019-d7ee-ce3897389622"
	const email = "rs0n.evolv3@gmail.com"

	// exp minus nbf is 299s, and it expired 13h35m before now. The lifetime is a measurement; the
	// remaining time is zero. They are different facts.
	mint := now.Add(-13*time.Hour - 40*time.Minute)
	bearer := profiledToken("tok-a", "authx bearer, account A ("+email+")",
		investigateJWT(t, mint, mint.Add(299*time.Second)), bearerCarrier, true, now)

	pwKey := cognitoCookieCarrier(subA, "randomPasswordKey")
	lastUser := CredentialCarrier{
		Kind: "cookie",
		Name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.LastAuthUser",
	}
	wire, reading := wireFixture("app.staging-v2.tradetalk.us",
		capturedCookie(pwKey, "n1BJoeT0zWc0oPaR", now.Add(-90*time.Second)),
		capturedCookie(lastUser, "someuser", now.Add(-90*time.Second)))

	report := buildSessionInvestigation("target-1", []SessionToken{bearer},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)
	return report, email, subA
}

// investigateExcerpt returns the bytes around a needle so a failure names what was served without
// printing a whole report.
func investigateExcerpt(haystack, needle string) string {
	i := strings.Index(haystack, needle)
	if i < 0 {
		return ""
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	end := i + len(needle) + 20
	if end > len(haystack) {
		end = len(haystack)
	}
	return haystack[start:end]
}

// THE OPERATOR'S OWN ROW LABEL GOES OUT AS THEY TYPED IT. They wrote an address into it to tell
// account A from account B, and a card that rewrote it would leave them unable to tell which
// account they are looking at, which is the one thing the label is for.
func TestTheCardServesTheOperatorsOwnLabelWhole(t *testing.T) {
	now := time.Date(2026, 9, 21, 8, 58, 3, 0, time.UTC)
	report, email, _ := liveEstateReport(t, now)

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), email) {
		t.Errorf("the report rewrote the label the operator typed: %q", report.Credentials[0].Name)
	}
	if want := "authx bearer, account A (" + email + ")"; report.Credentials[0].Name != want {
		t.Errorf("the row is named %q, want the operator's own label %q", report.Credentials[0].Name, want)
	}
}

// THE SUBJECT ID IN A COOKIE NAME IS SERVED. Amplify puts it in the storage key, the manual crawl
// caught it, and who a credential is for is a fact an operator opens this screen to read: on an
// IDOR it is the whole finding. It reaches carrier_name, token_id and the page DOM unchanged.
func TestTheCardPrintsTheCognitoSubjectId(t *testing.T) {
	now := time.Date(2026, 9, 21, 8, 58, 3, 0, time.UTC)
	report, _, sub := liveEstateReport(t, now)

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), sub) {
		t.Error("the report does not print the subject id the manual crawl captured")
	}
	if !strings.Contains(string(raw), "7cd3keuknr18mv2boiaesbgce3") {
		t.Error("the report does not print the app client id either")
	}
	var named int
	for _, c := range report.Credentials {
		if strings.Contains(c.CarrierName, sub) {
			named++
		}
		if c.Stored {
			continue
		}
		if strings.Contains(c.CarrierName, sub) && !strings.Contains(c.TokenID, sub) {
			t.Errorf("token_id drops the subject id the carrier name carries: %q", c.TokenID)
		}
	}
	if named == 0 {
		t.Error("no carrier_name carries the subject id; the cookie the crawl captured is named after it")
	}
	// AND TWO SUBJECTS STILL READ AS TWO, which is what the id in the name is read for.
	other := cognitoCookieCarrier("d4887448-50b1-7015-03be-6b285cf9fb5e", "randomPasswordKey")
	wire, reading := wireFixture("app.staging-v2.tradetalk.us",
		capturedCookie(cognitoCookieCarrier(sub, "randomPasswordKey"), "aaaa", now),
		capturedCookie(other, "bbbb", now))
	two := buildSessionInvestigation("target-1", nil,
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)
	if len(two.Credentials) != 2 {
		t.Fatalf("expected two captured cookies, got %d", len(two.Credentials))
	}
	if two.Credentials[0].CarrierName == two.Credentials[1].CarrierName {
		t.Errorf("two different subjects read as one name: %q", two.Credentials[0].CarrierName)
	}
	if two.Credentials[0].TokenID == two.Credentials[1].TokenID {
		t.Errorf("two different subjects read as one token_id: %q", two.Credentials[0].TokenID)
	}
}

// FAIL FIRST, measured against the tree as it stood, on the engaged estate's own numbers:
//
//	--- FAIL: TestFailFirstC_ZeroRemainingErasesTheLifetimeThatWasRead
//	    the tile publishes no lifetime although one was read out of a credential on this target:
//	    {Value:UNKNOWN Known:false State:unknown ...}
//
// Expiry and lifetime are different facts. The profiler already says both ("it expired 13h35m ago,
// and its whole lifetime is 5m, read from exp minus iat"); the card collapses the second into the
// first and then reports UNKNOWN governed by a cookie nobody measured. An operator asking how long
// a session lasts on this application has a perfect answer sitting in a dead token.
func TestFailFirstC_ZeroRemainingErasesTheLifetimeThatWasRead(t *testing.T) {
	now := time.Date(2026, 9, 21, 8, 58, 3, 0, time.UTC)
	report, _, _ := liveEstateReport(t, now)

	// The fixture is only interesting if the stored bearer really is unsendable and really did
	// have its lifetime read. Both are asserted so a fixture drift cannot make this pass vacuously.
	bearer := report.Credentials[0]
	if bearer.Sendable || bearer.OnTheWire {
		t.Fatalf("the fixture's bearer is still going out, so this is not the live shape: %q",
			bearer.NotSendableReason)
	}
	if !bearer.TTLKnown || bearer.TTLShort != "4m59s" {
		t.Fatalf("the fixture's bearer has no read lifetime: ttl_known=%v ttl_short=%q",
			bearer.TTLKnown, bearer.TTLShort)
	}

	m := report.TTLMetric
	if !m.LifetimeKnown {
		t.Errorf("the tile publishes no lifetime although one was read out of a credential on this "+
			"target: %+v", m)
	}
	if m.LifetimeShort != "4m59s" {
		t.Errorf("the tile's lifetime is %q, want 4m59s", m.LifetimeShort)
	}
	if m.Value != "4m59s" {
		t.Errorf("the tile reads %q; the lifetime that was read is 4m59s", m.Value)
	}
	if m.State != "lifetime_only" {
		t.Errorf("state is %q, want lifetime_only: a lifetime is known and the remaining time is zero",
			m.State)
	}
	// ZERO REMAINING IS ITS OWN STATEMENT AND IT IS NOT DROPPED EITHER.
	if !strings.Contains(m.Detail, "0 left") {
		t.Errorf("the one line under the tile does not say nothing is left of it: %q", m.Detail)
	}
	if !strings.Contains(m.Explain, "13h35m") {
		t.Errorf("the explanation does not say how long ago it died: %q", m.Explain)
	}
	// AND THE TILE IS NOT STYLED AS A SETTLED MEASUREMENT OF THIS SCAN'S SESSION, because nothing
	// this scan would send has a measured lifetime at all.
	if m.Known {
		t.Errorf("the tile claims a settled lifetime for a scan whose credentials were never "+
			"measured: %+v", m)
	}
	if !strings.Contains(m.Explain, "no measured lifetime") {
		t.Errorf("the explanation does not say the credentials this scan sends were never measured: %q",
			m.Explain)
	}
	// AND THE LIFETIME IS ATTRIBUTED. A number with no credential beside it is a number nobody can
	// check, and this one comes from a credential that is NOT going out.
	if !strings.Contains(m.LifetimeFrom, "account A") {
		t.Errorf("the tile does not say which credential the lifetime was read from: %q", m.LifetimeFrom)
	}
}

// A MEASURED TILE STILL PUBLISHES ITS LIFETIME, so a client reading lifetime_short does not have
// to special-case the state to get the same number the tile shows.
func TestTheLifetimeFieldsAgreeWithAMeasuredTile(t *testing.T) {
	now := time.Date(2026, 9, 21, 8, 58, 3, 0, time.UTC)
	live := profiledToken("tok-live", "app bearer",
		investigateJWT(t, now.Add(-30*time.Second), now.Add(870*time.Second)), bearerCarrier, true, now)
	onWire := "Bearer " + live.TokenValue
	wire, reading := wireFixture("app.example.test", sessionWireCredential{
		Carrier: bearerCarrier, Value: onWire, Fingerprint: triageCredFingerprint(onWire),
		Source: "session_tokens",
	})
	report := buildSessionInvestigation("target-1", []SessionToken{live},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	m := report.TTLMetric
	if m.State != "measured" || !m.Known {
		t.Fatalf("the fixture is not a measured tile: %+v", m)
	}
	if !m.LifetimeKnown || m.LifetimeShort != m.Value {
		t.Errorf("lifetime_short %q does not agree with the tile's own value %q",
			m.LifetimeShort, m.Value)
	}
	// AND AN UNMEASURED ONE SAYS THE WORD RATHER THAN LEAVING THE FIELD BLANK, which is the rule
	// every other rendered lifetime in this file already follows.
	none := buildSessionInvestigation("target-1", nil, sessionInvestigateOptions{}, now)
	if none.TTLMetric.LifetimeKnown || none.TTLMetric.LifetimeShort != ttlUnknownWord {
		t.Errorf("an unmeasured lifetime is not the word UNKNOWN: %+v", none.TTLMetric)
	}
}

// FAIL FIRST, measured against the tree as it stood. SessionInvestigateModal.js:833 renders
//
//	"{counts.sendable} would be sent. {counts.ttl_measured} of those have a measured lifetime
//	 and {counts.ttl_unknown} do not"
//
// and sendable is counted over the STORED rows while the two TTL counts are counted over the set
// that GOES OUT. On the engaged estate that renders "0 would be sent. 0 of those have a measured
// lifetime and 7 do not", which is arithmetic nobody can follow. The counts have to describe one
// set before the sentence can.
func TestFailFirstD_TheCountsSentenceIsComposedOverTwoSets(t *testing.T) {
	now := time.Date(2026, 9, 21, 8, 58, 3, 0, time.UTC)
	report, _, _ := liveEstateReport(t, now)

	c := report.Counts
	if c.Eligible != c.TTLMeasured+c.TTLUnknown {
		t.Errorf("the TTL counts are not counted over counts.eligible: eligible=%d measured=%d "+
			"unknown=%d", c.Eligible, c.TTLMeasured, c.TTLUnknown)
	}
	if c.Eligible != 2 {
		t.Errorf("counts.eligible is %d; the runner would send 2 credentials for this host", c.Eligible)
	}
	if c.Sendable == c.Eligible {
		t.Fatal("the fixture no longer distinguishes the two sets, so this test proves nothing")
	}
	if c.EligibleBasis != "wire" {
		t.Errorf("counts.eligible_basis is %q; the runner's own source was read for this report",
			c.EligibleBasis)
	}
	// AND THE BASIS IS THE OTHER WORD WHEN THE SOURCE COULD NOT BE READ, because "would be sent"
	// then means the stored rule and not the runner's answer.
	stored := buildSessionInvestigation("target-1", nil, sessionInvestigateOptions{}, now)
	if stored.Counts.EligibleBasis != "stored" {
		t.Errorf("with the wire unread counts.eligible_basis is %q, want stored",
			stored.Counts.EligibleBasis)
	}
}

// investigateJWTExpOnly declares WHEN IT DIES and not how long it lives: an exp claim, no nbf and
// no iat. Remaining is then a measurement and the lifetime is not, which is the separation the
// test below turns on.
func investigateJWTExpOnly(t *testing.T, exp time.Time) string {
	t.Helper()
	header := `{"alg":"ES256","kid":"TESTKID0000000003","typ":"JWT"}`
	payload := fmt.Sprintf(`{"aud":"test","exp":%d,"iss":"https://issuer.test","jti":"jti-3","sub":"user-3"}`,
		exp.Unix())
	enc := func(s string) string { return strings.TrimRight(base64URL(s), "=") }
	return enc(header) + "." + enc(payload) + ".c2lnbmF0dXJl"
}

// A LIFETIME THE ORDERING COULD NOT USE BELONGS TO A CREDENTIAL THAT IS GOING OUT, and then the
// tile may not say nothing going out was measured, because one of them was.
//
// THIS IS THE SENTENCE-AND-BRANCH RULE APPLIED TO THE NEW STATE. chooseGoverningCredential orders
// on REMAINING time first, so a credential with a readable expiry and no issue time wins the
// ordering over a sibling whose whole lifetime was read and whose mint time was not. The tile then
// has no lifetime from the credential it named and one from a credential it did not, and the two
// wordings are read off whether that credential is in the eligible set rather than off the state.
func TestTheLifetimeSentenceSaysWhetherThatCredentialGoesOut(t *testing.T) {
	now := time.Date(2026, 9, 21, 8, 58, 3, 0, time.UTC)

	// A readable expiry and no lifetime: exp says when it dies and nothing in it says when the
	// clock started, so how much is left is known and how long it lives is not.
	opaque := profiledToken("tok-when", "long header", investigateJWTExpOnly(t, now.Add(20*time.Minute)),
		CredentialCarrier{Kind: "header", Name: "X-When"}, true, now)

	// A lifetime and no expiry: expires_in says how long, nothing says from when.
	span := profiledToken("tok-span", "short header", investigateJWTExpiresIn(t, 60),
		CredentialCarrier{Kind: "header", Name: "X-Span"}, true, now)

	report := buildSessionInvestigation("target-1", []SessionToken{opaque, span},
		sessionInvestigateOptions{}, now)

	m := report.TTLMetric
	if !m.LifetimeKnown || m.LifetimeShort != "1m" {
		t.Fatalf("the read lifetime did not reach the tile: %+v", m)
	}
	if m.State != "lifetime_only" {
		t.Fatalf("state is %q, want lifetime_only: %+v", m.State, m)
	}
	// THE FALSE SENTENCE THIS GUARDS. Both credentials here are going out and one of them WAS
	// measured, so a tile saying nothing going out has a lifetime would be stating something the
	// same report contradicts two fields away.
	for _, s := range []string{m.Detail, m.Explain} {
		if strings.Contains(s, "Nothing this scan would send has a measured lifetime") ||
			strings.Contains(s, "nothing this scan sends has a measured lifetime") {
			t.Errorf("the tile says nothing going out was measured while a credential going out "+
				"has a measured lifetime of %s: %q", m.LifetimeShort, s)
		}
	}
	if !strings.Contains(m.Explain, "one this scan would send") {
		t.Errorf("the tile does not say the lifetime belongs to a credential going out: %q", m.Explain)
	}
	// AND REMAINING STAYS ITS OWN ANSWER. Nothing measured when this credential was minted, so how
	// much of its minute is left is UNKNOWN and is not rendered as zero.
	if !strings.Contains(m.Detail, ttlUnknownWord) {
		t.Errorf("an unmeasured remaining time is not said as %s: %q", ttlUnknownWord, m.Detail)
	}
}

// FAIL FIRST, measured against the tree as it stood:
//
//	--- FAIL: TestARemainingTimeIsNotCaptionedWithTheLifetimeProvenance
//	    the governing sentence says a number READ OUT OF THE EXP CLAIM was never measured:
//	    "the only credential this scan would send: 20m of life left, never measured"
//
// The governing ladder reaches its first rung on REMAINING time and captioned it with
// TTLProvenanceLabel, which is the provenance of the LIFETIME. They are the same word on a token
// carrying both exp and iat and they are different words on one carrying exp alone, which is every
// JWT this estate mints. The caption then contradicts the number standing beside it.
func TestARemainingTimeIsNotCaptionedWithTheLifetimeProvenance(t *testing.T) {
	now := time.Date(2026, 9, 21, 8, 58, 3, 0, time.UTC)
	tok := profiledToken("tok-when", "long header", investigateJWTExpOnly(t, now.Add(20*time.Minute)),
		CredentialCarrier{Kind: "header", Name: "X-When"}, true, now)
	report := buildSessionInvestigation("target-1", []SessionToken{tok}, sessionInvestigateOptions{}, now)

	c := report.Credentials[0]
	if c.TTLKnown || !c.RemainingKnown {
		t.Fatalf("the fixture does not separate the two provenances: ttl_known=%v remaining_known=%v",
			c.TTLKnown, c.RemainingKnown)
	}
	why := report.Governing.WhyThisOne
	if !strings.Contains(why, "20m of life left") {
		t.Fatalf("the governing sentence does not carry the remaining time: %q", why)
	}
	if strings.Contains(why, "never measured") {
		t.Errorf("the governing sentence says a number READ OUT OF THE EXP CLAIM was never "+
			"measured: %q", why)
	}
	if !strings.Contains(why, "out of the credential") {
		t.Errorf("the remaining time carries no provenance at all: %q", why)
	}
}

// =================================================================================================
// ROUND 17: THE TILE ANSWERS ABOUT THE APPLICATION UNDER TEST, OR IT SAYS UNKNOWN
// =================================================================================================
//
// Round 16 gave the tile a LIFETIME to publish beside the REMAINING time, so a dead credential
// stopped erasing the measurement that had been read out of it. Read back through this handler on
// the engaged estate's shape, the number it published was 15m1s and it came from the operator's
// own authx bearer, which is a different issuer from the application under test. The
// application's own answer, 4m59s of accessToken, had been measured by this framework and thrown
// away: SessionWireReading.Expired counted 21 rejected candidates and carried none of them, so
// the only credentials the card could see were the stored rows that happened to survive.
//
// It never claimed the session was alive, so this was not a false clean. It was the card
// answering "how long does a session on this application last" with a number from somewhere else,
// which is worse than UNKNOWN because it looks like an answer.

// capturedCookieNamed is one cookie the manual crawl caught going past, shaped exactly as
// triageDBFreshCreds.captureCandidates produces it. A zero expires is a credential whose lifetime
// this engine could not read, which is a different state from a short one.
func capturedCookieNamed(name, value string, observed, expires time.Time) sessionWireCredential {
	wc := sessionWireCredential{
		Carrier:     CredentialCarrier{Kind: "cookie", Name: name},
		Value:       value,
		Fingerprint: triageCredFingerprint(value),
		Source:      "manual_crawl_captures",
		Observed:    observed,
		Expires:     expires,
	}
	if !expires.IsZero() {
		wc.ExpirySource = "the token's own exp claim"
	}
	return wc
}

// withDeadCandidates puts the REJECTED candidates on the reading, which is what
// loadSessionWireCredentials does out of triageFreshCredStatus.Dead. Expired moves with them,
// because the count and the rows come off the same branch of the source and a fixture where they
// disagree would be testing a state the source cannot produce.
func withDeadCandidates(r SessionWireReading, dead ...sessionWireCredential) SessionWireReading {
	r.dead = append(r.dead, dead...)
	r.Expired += len(dead)
	return r
}

// estateShapedReport reproduces what the handler read on the engaged estate: an operator-typed
// bearer with a 15m1s lifetime that died three days ago, one captured cookie with no readable
// expiry as the only thing going out, and the accessToken the application itself issued, 4m59s
// long and dead, among the candidates the runner's source rejected.
func estateShapedReport(t *testing.T, now time.Time) (SessionInvestigation, sessionInvestigateOptions) {
	t.Helper()
	authx := profiledToken("tok-1", "authx bearer, account A",
		investigateJWT(t, now.Add(-72*time.Hour), now.Add(-72*time.Hour).Add(901*time.Second)),
		bearerCarrier, true, now)

	opaque := capturedCookieNamed("refreshToken", strings.Repeat("Q1w2", 40), now.Add(-3*time.Minute), time.Time{})
	dead := capturedCookieNamed("accessToken",
		investigateJWT(t, now.Add(-20*time.Minute), now.Add(-20*time.Minute).Add(299*time.Second)),
		now.Add(-20*time.Minute), now.Add(-20*time.Minute).Add(299*time.Second))

	wire, reading := wireFixture("app.example.test", opaque)
	opts := sessionInvestigateOptions{Wire: wire, WireReading: withDeadCandidates(reading, dead)}
	return buildSessionInvestigation("target-1", []SessionToken{authx}, opts, now), opts
}

// FAIL FIRST, measured on this tree with the source carrying the count and not the rows:
//
//	--- FAIL: TestTheTileReadsTheLifetimeOffTheApplicationsOwnToken
//	    the tile says a session on this application lasts "15m1s", read from "authx bearer,
//	    account A, exp minus iat"; the application's own accessToken says 4m59s and never
//	    reaches the card
func TestTheTileReadsTheLifetimeOffTheApplicationsOwnToken(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	report, _ := estateShapedReport(t, now)

	if report.TTLMetric.LifetimeShort != "4m59s" || report.TTLMetric.Value != "4m59s" {
		t.Errorf("the tile says a session on this application lasts %q (value %q), read from %q; "+
			"the application's own accessToken says 4m59s",
			report.TTLMetric.LifetimeShort, report.TTLMetric.Value, report.TTLMetric.LifetimeFrom)
	}
	if !strings.Contains(report.TTLMetric.LifetimeFrom, "accessToken") {
		t.Errorf("the lifetime names %q, which is not the credential the application issued",
			report.TTLMetric.LifetimeFrom)
	}
	if strings.Contains(report.TTLMetric.LifetimeFrom, "authx") {
		t.Errorf("the lifetime is still read off the operator's own bearer: %q", report.TTLMetric.LifetimeFrom)
	}
	if !strings.Contains(report.TTLMetric.Explain, "4m59s") {
		t.Errorf("the sentence an operator reads does not carry the number: %q", report.TTLMetric.Explain)
	}
}

// AND IT STILL REFUSES TO CLAIM THE SESSION IS ALIVE. The number is a lifetime and not a
// remaining time, it came from a credential nothing is sending, and every one of those facts is
// on the tile rather than in a note the card does not render.
func TestTheLifetimeFromADeadCredentialIsNeverStyledAsALiveSession(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	report, _ := estateShapedReport(t, now)

	if report.TTLMetric.Known {
		t.Errorf("the tile is styled as a settled measurement of THIS scan: %+v", report.TTLMetric)
	}
	if report.TTLMetric.State != "lifetime_only" {
		t.Errorf("the tile state is %q, want lifetime_only", report.TTLMetric.State)
	}
	if !strings.Contains(report.TTLMetric.Detail, "0 left") {
		t.Errorf("the tile does not say how much of it is left: %q", report.TTLMetric.Detail)
	}
	if !strings.Contains(report.TTLMetric.Explain, "died") {
		t.Errorf("the explanation does not say the credential is dead: %q", report.TTLMetric.Explain)
	}
	if !strings.Contains(report.TTLMetric.Explain, "Nothing this scan would send has a measured lifetime") {
		t.Errorf("the explanation does not say the number is not about what goes out: %q", report.TTLMetric.Explain)
	}
}

// A DEAD CANDIDATE IS NOT A CREDENTIAL THIS RUN HAS. It is on no count, it is on no row of the
// credential list, it is not sendable and it is not on the wire. Each of those is asserted rather
// than assumed, because the whole risk of carrying a rejected credential to a screen is that one
// of the surfaces that reads credentials picks it up.
func TestADeadCandidateCarriedForItsLifetimeIsOnNoOtherSurface(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	report, opts := estateShapedReport(t, now)

	for _, c := range report.Credentials {
		if c.CarrierName == "accessToken" {
			t.Errorf("the rejected candidate is on the credential list as %q (sendable=%v, on_the_wire=%v)",
				c.Name, c.Sendable, c.OnTheWire)
		}
	}
	if report.Counts.Captured != 1 {
		t.Errorf("counts.captured is %d, want 1: the rejected candidate is being counted as a credential",
			report.Counts.Captured)
	}
	if report.Counts.OnWire != 1 || report.Counts.Eligible != 1 {
		t.Errorf("counts.on_wire=%d eligible=%d, want 1 and 1", report.Counts.OnWire, report.Counts.Eligible)
	}
	if report.Counts.TTLMeasured != 0 || report.Counts.TTLUnknown != 1 {
		t.Errorf("the TTL counts moved: measured=%d unknown=%d, want 0 and 1",
			report.Counts.TTLMeasured, report.Counts.TTLUnknown)
	}

	only := sessionLifetimeOnlyCredentials(report, opts, now)
	if len(only) != 1 {
		t.Fatalf("the lifetime-only set has %d row(s), want 1", len(only))
	}
	if only[0].Sendable || only[0].OnTheWire {
		t.Errorf("a rejected candidate came back sendable=%v on_the_wire=%v", only[0].Sendable, only[0].OnTheWire)
	}
	if credentialGoesOut(only[0], true) {
		t.Error("credentialGoesOut says a rejected candidate would be carried by a probe")
	}
	if only[0].NotSendableReason == "" || only[0].WireNote == "" {
		t.Errorf("the row does not say why it is not going out: %+v", only[0])
	}
}

// A DEAD CANDIDATE THE REPORT ALREADY HOLDS IS NOT COUNTED TWICE. A stored row whose expiry has
// passed is read by BOTH paths: the loader puts it on the card and the runner's source rejects it,
// so without the fingerprint check one credential would answer the lifetime question as two.
func TestADeadCandidateAlreadyOnTheCardIsNotCarriedAgain(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	value := investigateJWT(t, now.Add(-2*time.Hour), now.Add(-2*time.Hour).Add(600*time.Second))
	stored := profiledToken("tok-1", "stored bearer", value, bearerCarrier, true, now)

	sameCred := sessionWireCredential{
		Carrier:      CredentialCarrier{Kind: "header", Name: "Authorization", Prefix: "Bearer "},
		Value:        "Bearer " + value,
		Fingerprint:  triageCredFingerprint("Bearer " + value),
		Source:       "session_tokens",
		Observed:     now.Add(-2 * time.Hour),
		Expires:      now.Add(-2 * time.Hour).Add(600 * time.Second),
		ExpirySource: "the token's own exp claim",
	}
	wire, reading := wireFixture("app.example.test")
	opts := sessionInvestigateOptions{Wire: wire, WireReading: withDeadCandidates(reading, sameCred)}
	report := buildSessionInvestigation("target-1", []SessionToken{stored}, opts, now)

	if got := len(sessionLifetimeOnlyCredentials(report, opts, now)); got != 0 {
		t.Errorf("the lifetime-only set carries %d row(s) for a credential the card already holds", got)
	}
}

// WITH NO CAPTURES AT ALL THE OPERATOR'S OWN ROW STILL ANSWERS. The middle rung prefers a
// credential the application issued; it does not refuse to answer when there is not one, because
// a target nobody has crawled would then have no lifetime at all and the old behaviour was right
// about that.
func TestWithNothingTheApplicationIssuedTheStoredRowStillAnswers(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	authx := profiledToken("tok-1", "authx bearer",
		investigateJWT(t, now.Add(-72*time.Hour), now.Add(-72*time.Hour).Add(901*time.Second)),
		bearerCarrier, true, now)
	wire, reading := wireFixture("app.example.test")
	report := buildSessionInvestigation("target-1", []SessionToken{authx},
		sessionInvestigateOptions{Wire: wire, WireReading: reading}, now)

	if report.TTLMetric.LifetimeShort != "15m1s" {
		t.Errorf("the lifetime is %q, want 15m1s off the only credential there is", report.TTLMetric.LifetimeShort)
	}
	if !strings.Contains(report.TTLMetric.LifetimeFrom, "authx bearer") {
		t.Errorf("the tile does not say where the number came from: %q", report.TTLMetric.LifetimeFrom)
	}
}

// AND A CREDENTIAL GOING OUT STILL BEATS BOTH. The first rung is unchanged: what the scan sends is
// the better evidence about the run, and a dead row must not displace it.
func TestACredentialGoingOutStillOutranksADeadOne(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	live := "Bearer " + investigateJWT(t, now.Add(-60*time.Second), now.Add(840*time.Second))
	wire, reading := wireFixture("app.example.test",
		capturedBearer(live, now.Add(-60*time.Second), now.Add(840*time.Second)))
	dead := capturedCookieNamed("accessToken",
		investigateJWT(t, now.Add(-20*time.Minute), now.Add(-20*time.Minute).Add(299*time.Second)),
		now.Add(-20*time.Minute), now.Add(-20*time.Minute).Add(299*time.Second))

	report := buildSessionInvestigation("target-1", nil,
		sessionInvestigateOptions{Wire: wire, WireReading: withDeadCandidates(reading, dead)}, now)

	if report.TTLMetric.LifetimeShort != "15m" {
		t.Errorf("the lifetime is %q, want 15m off the credential this scan sends (from %q)",
			report.TTLMetric.LifetimeShort, report.TTLMetric.LifetimeFrom)
	}
	if !report.TTLMetric.Known {
		t.Errorf("a measured credential that goes out is not styled as measured: %+v", report.TTLMetric)
	}
}
