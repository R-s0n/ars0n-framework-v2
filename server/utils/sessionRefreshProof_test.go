package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// WHAT THESE TESTS PIN.
//
// 1. A PROOF IS ONLY WRITTEN WHEN A DIFFERENT CREDENTIAL CAME BACK AND THE TARGET HONOURED IT.
//    Three ways to fail that, each with its own code and its own sentence, and none of them
//    reaches RefreshProven.
// 2. AN OUT-OF-SCOPE MINT SENDS NOTHING. The test counts requests at the out-of-scope server and
//    the count has to be zero. On the live engagement the mint is at a host the programme
//    excludes, so this is the path that actually matters there.
// 3. THE CONTROL BECOMES REACHABLE. Before this file the renewal gate could never be satisfied on
//    any application, because nothing in production wrote a proof. The end-to-end test drives the
//    routed settings endpoint and asserts the gate flips from refusing to offerable.
// 4. NO CREDENTIAL IS SERIALISED. The minted values below are full-length secrets and none of
//    them, nor any prefix of them, may appear in the result, its JSON, or the events written.
//
// They use triageTestDB, so with no TRIAGE_TEST_DATABASE_URL they are recorded as NOT MEASURED
// and the package fails at the end of the run. A skip is not a pass.

// The credential values these tests mint. They are invented here, they are long enough that a
// prefix check means something, and they must never appear in any output.
const (
	refreshProofOldValue = "old-session-value-9f2c41d8e7b6a5049382716253647589aabbccddeeff00112233"
	refreshProofMintedA  = "minted-session-value-5a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899"
	refreshProofMintedB  = "minted-session-value-cafed00dbeefb1a7c0ffee1234567890fedcba9876543210aaaa"
)

// ---------------------------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------------------------

// refreshProofApp is an application that mints a session at /login and guards /me with it.
//
// Every mint returns a DIFFERENT value, which is what a real session endpoint does and is the only
// thing that can be proven. The knobs let one test make it return the same value twice and another
// make it hand back a value it then refuses, which are the two failure shapes the proof must
// refuse rather than record.
type refreshProofApp struct {
	server    *httptest.Server
	hostPort  string
	mints     int
	logins    int
	mintSame  bool // always hand back the same value
	mintDead  bool // hand back a value /me does not accept
	lastValue string
}

func newRefreshProofApp(t *testing.T) *refreshProofApp {
	t.Helper()
	a := &refreshProofApp{}
	a.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			a.logins++
			a.mints++
			value := refreshProofMintedA
			if a.mints > 1 && !a.mintSame {
				value = refreshProofMintedB
			}
			if a.mintDead {
				value = "a-value-this-server-will-not-accept-" + fmt.Sprint(a.mints)
			} else {
				a.lastValue = value
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: value, Path: "/"})
			w.Write([]byte("signed in"))
		case "/me":
			c, err := r.Cookie("sid")
			if err != nil || a.lastValue == "" || c.Value != a.lastValue {
				w.WriteHeader(401)
				w.Write([]byte("please log in"))
				return
			}
			w.Write([]byte("your account page, which only a signed in caller sees"))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(a.server.Close)
	a.hostPort = strings.TrimPrefix(a.server.URL, "http://")
	return a
}

func (a *refreshProofApp) steps() []string {
	return []string{
		"POST /login HTTP/1.1\r\nHost: " + a.hostPort + "\r\n\r\n",
		"GET /me HTTP/1.1\r\nHost: " + a.hostPort + "\r\n\r\n",
	}
}

// refreshProofTarget makes a scope target whose scope_target IS the given URL, so the engagement
// boundary is that host and nothing else.
func refreshProofTarget(t *testing.T, ctx context.Context, url string) string {
	t.Helper()
	var id string
	if err := dbPool.QueryRow(ctx,
		`INSERT INTO scope_targets (type, mode, scope_target, active) VALUES ('URL','Passive',$1,FALSE) RETURNING id::text`,
		url).Scan(&id); err != nil {
		t.Fatalf("create scope target: %v", err)
	}
	t.Cleanup(func() {
		if _, err := dbPool.Exec(context.Background(), `DELETE FROM scope_targets WHERE id = $1`, id); err != nil {
			t.Errorf("could not clean up scope target %s: %v", id, err)
		}
	})
	return id
}

func refreshProofFlow(t *testing.T, ctx context.Context, target, base, name string, steps []string) string {
	t.Helper()
	var flowID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO auth_flows (scope_target_id, category, name, base_url)
		VALUES ($1,'login',$2,$3) RETURNING id::text`, target, name, base).Scan(&flowID); err != nil {
		t.Fatalf("insert auth flow: %v", err)
	}
	for i, raw := range steps {
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO auth_flow_steps (auth_flow_id, step_order, name, raw_request)
			VALUES ($1,$2,$3,$4)`, flowID, i+1, fmt.Sprintf("step %d", i+1), raw); err != nil {
			t.Fatalf("insert step: %v", err)
		}
	}
	return flowID
}

func refreshProofToken(t *testing.T, ctx context.Context, target, flowID, value string) string {
	t.Helper()
	var id string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens (scope_target_id, name, token_type, cookie_name, token_value, is_active, auth_flow_id)
		VALUES ($1,'sid','cookie','sid',$2,TRUE,$3) RETURNING id::text`,
		target, value, nullUUID(flowID)).Scan(&id); err != nil {
		t.Fatalf("insert session token: %v", err)
	}
	return id
}

// refreshProofStoredValue reads the value back so a test can say whether it was replaced. The
// value is COMPARED and never printed.
func refreshProofStoredValue(t *testing.T, ctx context.Context, tokenID string) string {
	t.Helper()
	var v string
	if err := dbPool.QueryRow(ctx, `SELECT COALESCE(token_value,'') FROM session_tokens WHERE id = $1`, tokenID).Scan(&v); err != nil {
		t.Fatalf("read back the stored credential: %v", err)
	}
	return v
}

func refreshProofEvents(t *testing.T, ctx context.Context, tokenID string) []string {
	t.Helper()
	rows, err := dbPool.Query(ctx, `
		SELECT kind || '/' || COALESCE(status,'') FROM session_token_events
		WHERE session_token_id = $1 ORDER BY created_at ASC, id ASC`, tokenID)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// 1. THE PROOF IS TAKEN, AND IT IS THE THING THE GATE READS
// ---------------------------------------------------------------------------------------------

// The whole point of the round. Before this, RecordRefreshProof had no production caller, so
// RefreshProven was unreachable and the renewal control could never become available on ANY
// application however good its refresh mechanism was.
func TestARealRefreshIsPerformedObservedAndRecordedAsTheProof(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, target, app.server.URL, "password login", app.steps())
	tokenID := refreshProofToken(t, ctx, target, flowID, refreshProofOldValue)

	before := NewCredential(refreshProofOldValue).Fingerprint()
	got := ProveSessionRefresh(ctx, tokenID)

	if got.Code != RefreshProofProven || !got.Proven {
		t.Fatalf("a real refresh against a real application was not accepted as a proof: code=%s detail=%s", got.Code, got.Detail)
	}
	if got.BeforeFingerprint != before || got.AfterFingerprint == "" || got.AfterFingerprint == before {
		t.Fatalf("the two fingerprints do not describe a rotation: %s -> %s", got.BeforeFingerprint, got.AfterFingerprint)
	}
	if !got.Attempted || !got.MintInScope || !got.StoredNewValue {
		t.Fatalf("the outcome does not describe what happened: %+v", got)
	}
	if got.ValidationStatus != tokenStatusActive {
		t.Fatalf("a proof was recorded without the target honouring the new credential: %s", got.ValidationStatus)
	}
	if app.logins == 0 {
		t.Fatal("nothing was ever sent at the mint, so no refresh was performed and the proof is an artefact")
	}

	// The credential the framework now holds is the one that was observed working.
	if refreshProofStoredValue(t, ctx, tokenID) != app.lastValue {
		t.Fatal("the stored credential is not the one the mint returned and the target honoured")
	}

	// And the thing the gate reads has actually moved.
	tok, err := loadSessionToken(tokenID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p := ProfileSessionToken(ctx, tok)
	if p.Refresh.Status != RefreshProven {
		t.Fatalf("after a performed and observed refresh the credential's refresh status is %s", p.Refresh.Status)
	}
	if p.Refresh.ProvenAt.IsZero() {
		t.Fatal("the proof has no timestamp, so the gate cannot age it")
	}

	// Exactly one success on the timeline for one refresh.
	events := refreshProofEvents(t, ctx, tokenID)
	successes := 0
	for _, e := range events {
		if e == "refresh/success" {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("one refresh produced %d success events on the timeline: %v", successes, events)
	}
}

// ---------------------------------------------------------------------------------------------
// 2. THE THREE WAYS A REFRESH IS NOT A PROOF
// ---------------------------------------------------------------------------------------------

// The endpoint answered and handed back what we already had. That proves the endpoint answers.
func TestAMintThatReturnsTheSameCredentialIsNotAProof(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	app.mintSame = true
	target := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, target, app.server.URL, "password login", app.steps())
	// The stored value IS what the mint will hand back, so the refresh renews nothing.
	tokenID := refreshProofToken(t, ctx, target, flowID, refreshProofMintedA)

	got := ProveSessionRefresh(ctx, tokenID)
	if got.Proven {
		t.Fatal("a refresh that returned the credential we already had was recorded as proof that the session can be renewed")
	}
	if got.Code != RefreshProofSameCredential {
		t.Fatalf("code = %s, want same_credential (detail: %s)", got.Code, got.Detail)
	}
	if !strings.Contains(got.Detail, "SAME credential") {
		t.Errorf("the refusal does not say what happened: %s", got.Detail)
	}
	if !got.Attempted {
		t.Error("a refresh that was actually performed is recorded as not attempted")
	}
}

// A new string is not a working session. This is the half that makes "proven" mean observed.
func TestAMintedCredentialTheTargetRefusesIsNotAProofAndDoesNotReplaceTheStoredOne(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	app.mintDead = true
	target := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, target, app.server.URL, "password login", app.steps())
	tokenID := refreshProofToken(t, ctx, target, flowID, refreshProofOldValue)

	got := ProveSessionRefresh(ctx, tokenID)
	if got.Proven {
		t.Fatalf("a credential nothing has seen work was recorded as a proof: %+v", got)
	}
	if got.Code != RefreshProofNotHonoured {
		t.Fatalf("code = %s, want new_credential_not_honoured (detail: %s)", got.Code, got.Detail)
	}
	if got.StoredNewValue {
		t.Fatal("the operator's stored credential was replaced with one the target refused")
	}
	if refreshProofStoredValue(t, ctx, tokenID) != refreshProofOldValue {
		t.Fatal("the stored credential changed although the minted one was never honoured")
	}
	// It IS an observation about the mechanism, so it goes on the timeline as a refresh failure
	// and the gate's second test can see it.
	if !refreshProofHasEvent(refreshProofEvents(t, ctx, tokenID), "refresh/not_honoured") {
		t.Fatalf("the failed refresh is not on the credential's timeline: %v", refreshProofEvents(t, ctx, tokenID))
	}

	// THE FAILURE PATH CARRIES BOTH CREDENTIALS. It is the one that carries the validation
	// evidence, which is the richest thing this file ever puts in a row, and it is the path where
	// an operator most needs to see the exact string the target refused.
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	hay := string(blob) + " " + fmt.Sprintf("%+v", got) + " " + refreshProofEventText(t, ctx, tokenID)
	for _, want := range []string{refreshProofOldValue, got.AfterValue} {
		if want == "" {
			t.Fatal("the not-honoured path recorded no credential at all")
		}
		if !strings.Contains(hay, want) {
			t.Errorf("the not-honoured path does not carry the credential %q, so nobody can check "+
				"which string the target refused", want)
		}
	}
}

// refreshProofEventText is every detail and evidence blob written for one credential, joined.
func refreshProofEventText(t *testing.T, ctx context.Context, tokenID string) string {
	t.Helper()
	rows, err := dbPool.Query(ctx, `SELECT COALESCE(detail,'') || ' ' || COALESCE(evidence::text,'')
		FROM session_token_events WHERE session_token_id = $1`, tokenID)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	defer rows.Close()
	out := ""
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			out += " " + s
		}
	}
	return out
}

// A credential tied to no flow has no mechanism to spend. Nothing is sent and nothing is a
// refresh failure, because no refresh was attempted.
func TestACredentialWithNoFlowIsRefusedWithoutSendingAndWithoutRevokingAnything(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	tokenID := refreshProofToken(t, ctx, target, "", refreshProofOldValue)

	got := ProveSessionRefresh(ctx, tokenID)
	if got.Attempted || got.Proven {
		t.Fatalf("a credential with no flow produced an attempt: %+v", got)
	}
	if got.Code != RefreshProofNoFlow {
		t.Fatalf("code = %s, want no_flow", got.Code)
	}
	if app.logins != 0 {
		t.Fatalf("%d request(s) were sent for a credential with no flow to replay", app.logins)
	}
	events := refreshProofEvents(t, ctx, tokenID)
	for _, e := range events {
		if strings.HasPrefix(e, "refresh/") {
			t.Fatalf("a refresh that was never attempted was filed as a refresh event (%s), which is what the renewal gate reads as a failure and would revoke a standing proof", e)
		}
	}
	if !refreshProofHasEvent(events, "refresh_proof/not_attempted") {
		t.Fatalf("the refusal left nothing on the timeline: %v", events)
	}
}

func refreshProofHasEvent(events []string, want string) bool {
	for _, e := range events {
		if e == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// 3. SCOPE. NOTHING IS SENT AT A HOST THE ENGAGEMENT DOES NOT ALLOW.
// ---------------------------------------------------------------------------------------------

// On the live engagement the session is minted at a host the programme excludes. The correct
// outcome is the gate's mint_out_of_scope state, and the measurement that matters is that the
// out-of-scope server received ZERO requests.
func TestAnOutOfScopeMintIsRefusedAndNothingIsSent(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	// The engagement is app.example.test. The mint is a REAL listening server on another host, so
	// if the scope check were missing the requests would actually land and be counted. A second
	// httptest server would not do: every one of them is 127.0.0.1 and scope is a host, so two of
	// them are the same host on two ports.
	elsewhere := newRefreshProofApp(t)

	target := refreshProofTarget(t, ctx, "https://app.example.test/")
	// The flow's base_url names the in-scope application and its STEPS go somewhere else. That is
	// exactly the trap: checking base_url alone would call this in scope.
	flowID := refreshProofFlow(t, ctx, target, "https://app.example.test", "sso login", elsewhere.steps())
	tokenID := refreshProofToken(t, ctx, target, flowID, refreshProofOldValue)

	got := ProveSessionRefresh(ctx, tokenID)

	if elsewhere.logins != 0 {
		t.Fatalf("%d request(s) were sent to a host outside the engagement", elsewhere.logins)
	}
	if got.Attempted {
		t.Fatalf("an out-of-scope mint was attempted: %+v", got)
	}
	if got.Code != RefreshProofMintOutOfScope {
		t.Fatalf("code = %s, want mint_out_of_scope (detail: %s)", got.Code, got.Detail)
	}
	if got.MintInScope {
		t.Fatal("an out-of-scope mint was reported as in scope")
	}
	if !strings.Contains(got.Detail, "NOTHING WAS SENT") {
		t.Errorf("the refusal does not say that nothing was sent: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "127.0.0.1") {
		t.Errorf("the refusal does not name the host it declined: %v / %s", got.MintHosts, got.Detail)
	}
	if refreshProofStoredValue(t, ctx, tokenID) != refreshProofOldValue {
		t.Fatal("a refusal changed the stored credential")
	}
}

// The operator's own do-not-replay label is honoured before scope is even consulted.
func TestTheOperatorsDoNotReplayLabelStopsTheRefresh(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	// Every host here IS in scope. The only thing stopping it is the label.
	flowID := refreshProofFlow(t, ctx, target, app.server.URL,
		"DO NOT REPLAY - OUT OF SCOPE HOST - session mint", app.steps())
	tokenID := refreshProofToken(t, ctx, target, flowID, refreshProofOldValue)

	got := ProveSessionRefresh(ctx, tokenID)
	if app.logins != 0 {
		t.Fatalf("%d request(s) were sent through a flow the operator labelled do-not-replay", app.logins)
	}
	if got.Code != RefreshProofMintOutOfScope || got.Attempted {
		t.Fatalf("the do-not-replay label was not honoured: %+v", got)
	}
}

// A credential belonging to another target is refused before anything is read off it.
func TestARefreshIsNotSpentOnACredentialBelongingToAnotherTarget(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	mine := refreshProofTarget(t, ctx, app.server.URL)
	theirs := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, theirs, app.server.URL, "password login", app.steps())
	tokenID := refreshProofToken(t, ctx, theirs, flowID, refreshProofOldValue)

	got := ProveSessionRefreshForTarget(ctx, mine, tokenID)
	if got.Code != RefreshProofWrongTarget || got.Attempted {
		t.Fatalf("a PUT against one target spent another target's refresh mechanism: %+v", got)
	}
	if app.logins != 0 {
		t.Fatalf("%d request(s) were sent for another target's credential", app.logins)
	}
}

// ---------------------------------------------------------------------------------------------
// 4. NOT ONE BYTE OF A CREDENTIAL
// ---------------------------------------------------------------------------------------------

// THE PROOF CARRIES BOTH CREDENTIALS, everywhere it is recorded: in the returned struct, in the
// JSON the browser reads, and in the event rows the Session Manager reads back. The proof's claim
// is that the flow returned a DIFFERENT value and the target honoured it, so the two values are
// the evidence for the claim and a record without them cannot be checked.
func TestTheRefreshProofCarriesBothCredentialValues(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, target, app.server.URL, "password login", app.steps())
	tokenID := refreshProofToken(t, ctx, target, flowID, refreshProofOldValue)

	got := ProveSessionRefresh(ctx, tokenID)
	if !got.Proven {
		t.Fatalf("setup: the proof was not taken, so this test is measuring the wrong thing: %s", got.Detail)
	}

	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The event detail is what lands in the database and is read back by the Session Manager.
	details := refreshProofEventText(t, ctx, tokenID)

	// THE EVENT ROW IS NOT CHECKED FOR THE VALUES, and that is a gap rather than a decision. On
	// the success path the row is written by RecordRefreshProof in sessionTokenProfile.go, which
	// takes two fingerprints and nothing else, so the values cannot reach it from here. Every
	// other outcome goes through finishRefreshProof, which does write before_value and
	// after_value, and TestAMintedCredentialTheTargetRefusesIsNotAProofAndDoesNotReplaceTheStoredOne
	// checks exactly that. Widen this map once RecordRefreshProof takes the values too.
	haystacks := map[string]string{
		"the result struct": fmt.Sprintf("%+v %v", got, got),
		"its JSON":          string(blob),
	}
	if !strings.Contains(details, got.BeforeFingerprint) || !strings.Contains(details, got.AfterFingerprint) {
		t.Errorf("the events it wrote do not even carry the fingerprints that were compared: %s", details)
	}
	if got.BeforeValue != refreshProofOldValue {
		t.Errorf("BeforeValue is not the credential the framework was holding: %q", got.BeforeValue)
	}
	if got.AfterValue != refreshProofMintedA && got.AfterValue != refreshProofMintedB {
		t.Errorf("AfterValue is not one of the values the mint hands out: %q", got.AfterValue)
	}
	for _, want := range []string{got.BeforeValue, got.AfterValue} {
		if want == "" {
			t.Fatal("the proof recorded an empty credential, so it compared nothing")
		}
		for where, hay := range haystacks {
			if !strings.Contains(hay, want) {
				t.Errorf("%s does not carry the credential %q. The proof asserts these two differ, "+
					"and a record that drops them cannot be checked against the wire", where, want)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// 5. END TO END: THE CONTROL IS REACHABLE THROUGH A ROUTED ENDPOINT
// ---------------------------------------------------------------------------------------------

// This is the test that would have caught the whole defect. It drives the settings endpoint the
// configuration screen actually talks to, asks it for a proof, and asserts the renewal gate goes
// from refusing to offerable in the same response.
func TestTheSettingsEndpointTakesAProofAndTheGateThenOffersRenewal(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, target, app.server.URL, "password login", app.steps())
	tokenID := refreshProofToken(t, ctx, target, flowID, refreshProofOldValue)

	r := mux.NewRouter()
	r.HandleFunc("/triage/{scope_target_id}/settings", SaveTriageSettings).Methods("PUT")
	r.HandleFunc("/triage/{scope_target_id}/settings", GetTriageSettings).Methods("GET")

	// Before: the gate refuses, and a GET must not send anything at the mint.
	getBody := refreshProofRoundTrip(t, r, "GET", "/triage/"+target+"/settings", nil)
	if gate := refreshProofGate(t, getBody); gate["offerable"] == true {
		t.Fatal("renewal was offerable before any refresh had been performed")
	}
	if app.logins != 0 {
		t.Fatalf("a GET of the settings sent %d request(s) at the application's login", app.logins)
	}

	// The PUT that asks for the proof.
	settings := TriageSettingsDefaults()
	body, _ := json.Marshal(map[string]any{
		"settings":      settings,
		"prove_refresh": map[string]string{"token_id": tokenID},
	})
	putBody := refreshProofRoundTrip(t, r, "PUT", "/triage/"+target+"/settings", body)

	proof, _ := putBody["refresh_proof"].(map[string]any)
	if proof == nil {
		keys := []string{}
		for k := range putBody {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("the settings endpoint was asked to take a refresh proof and reported nothing. Keys: %v", keys)
	}
	if proof["code"] != RefreshProofProven {
		t.Fatalf("the proof was not taken through the routed endpoint: %v", proof["detail"])
	}
	gate := refreshProofGate(t, putBody)
	if gate["offerable"] != true {
		t.Fatalf("after a performed and observed refresh the gate still refuses: %v", gate["reason"])
	}
	if !strings.Contains(fmt.Sprint(gate["reason"]), "performed and watched") {
		t.Errorf("the gate's sentence does not describe what made it offerable: %v", gate["reason"])
	}

	// And a second PUT that does NOT ask for a proof sends nothing more.
	sent := app.logins
	plain, _ := json.Marshal(map[string]any{"settings": settings})
	refreshProofRoundTrip(t, r, "PUT", "/triage/"+target+"/settings", plain)
	if app.logins != sent {
		t.Fatalf("a settings save that asked for no proof replayed the login flow anyway (%d -> %d)", sent, app.logins)
	}
}

// A settings PUT naming a credential that cannot be proven still saves, and says why it could not.
func TestAProofThatCouldNotBeTakenIsReportedOnTheSaveRatherThanSwallowed(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	tokenID := refreshProofToken(t, ctx, target, "", refreshProofOldValue)

	r := mux.NewRouter()
	r.HandleFunc("/triage/{scope_target_id}/settings", SaveTriageSettings).Methods("PUT")
	body, _ := json.Marshal(map[string]any{
		"settings":      TriageSettingsDefaults(),
		"prove_refresh": map[string]string{"token_id": tokenID},
	})
	got := refreshProofRoundTrip(t, r, "PUT", "/triage/"+target+"/settings", body)

	proof, _ := got["refresh_proof"].(map[string]any)
	if proof == nil || proof["code"] != RefreshProofNoFlow {
		t.Fatalf("the failed proof was swallowed: %v", got["refresh_proof"])
	}
	if got["saved"] != true {
		t.Fatalf("a valid settings document was refused because a proof could not be taken: %v", got["validation"])
	}
}

// A body with no prove_refresh field sends nothing; a malformed one is refused rather than ignored.
func TestTheProveRefreshSidecarIsStrictlyOptInAndRefusesAMalformedValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
		err  bool
	}{
		{"absent", `{"settings":{"tier":"full"}}`, "", false},
		{"null", `{"settings":{"tier":"full"},"prove_refresh":null}`, "", false},
		{"empty object", `{"settings":{"tier":"full"},"prove_refresh":{}}`, "", false},
		{"blank id", `{"settings":{"tier":"full"},"prove_refresh":{"token_id":"  "}}`, "", false},
		{"named", `{"settings":{"tier":"full"},"prove_refresh":{"token_id":"tok-1"}}`, "tok-1", false},
		{"a bare string", `{"settings":{"tier":"full"},"prove_refresh":"tok-1"}`, "", true},
	} {
		got, err := DecodeTriageProveRefresh([]byte(tc.body))
		if tc.err {
			if err == nil {
				t.Errorf("%s: a malformed prove_refresh was silently ignored, which is a button that does nothing", tc.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: token id = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func refreshProofRoundTrip(t *testing.T, r *mux.Router, method, path string, body []byte) map[string]any {
	t.Helper()
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode (%d): %v body=%s", method, path, w.Code, err, w.Body.String())
	}
	return out
}

func refreshProofGate(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	gate, _ := body["renewal_gate"].(map[string]any)
	if gate == nil {
		t.Fatalf("the response carries no renewal gate: %v", body)
	}
	return gate
}

// ---------------------------------------------------------------------------------------------
// 6. THE HOST RESOLUTION THE SCOPE CHECK RESTS ON
// ---------------------------------------------------------------------------------------------

// Checked on its own because the scope refusal above is only as good as this list. A flow whose
// base_url is the application and whose steps go elsewhere must produce BOTH hosts.
func TestEveryHostTheReplayWouldTouchIsResolvedAndNotJustTheBaseURL(t *testing.T) {
	ctx := triageTestDB(t)
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, target, "https://app.example.test", "sso login", []string{
		"POST /login HTTP/1.1\r\nHost: idp.elsewhere.test\r\n\r\n",
		"GET /me HTTP/1.1\r\nHost: app.example.test\r\n\r\n",
	})
	hosts, name, refusal := sessionRefreshTargets(flowID)
	if refusal != "" {
		t.Fatalf("unexpected refusal: %s", refusal)
	}
	if name != "sso login" {
		t.Errorf("flow name = %q", name)
	}
	joined := strings.Join(hosts, ",")
	if !strings.Contains(joined, "idp.elsewhere.test") || !strings.Contains(joined, "app.example.test") {
		t.Fatalf("the hosts a replay would touch were not all resolved: %v", hosts)
	}
}

// A flow that names no host anywhere cannot be sent: where it would go cannot be established, and
// an unestablished destination is refused rather than tried.
func TestAFlowWithNoResolvableHostIsRefusedRatherThanSent(t *testing.T) {
	ctx := triageTestDB(t)
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, target, "", "headless flow", []string{"POST /login HTTP/1.1\r\n\r\n"})
	hosts, _, refusal := sessionRefreshTargets(flowID)
	if refusal == "" {
		t.Fatalf("a flow with no host anywhere was accepted, resolving to %v", hosts)
	}
	if !strings.Contains(refusal, "nothing was sent") {
		t.Errorf("the refusal does not say that nothing was sent: %s", refusal)
	}
}

// A nil scope is outside, not everywhere. "We could not read the boundary" is never permission.
func TestANilScopeRefusesEveryHost(t *testing.T) {
	outside := hostsOutsideScope(nil, []string{"app.example.test", "idp.elsewhere.test"})
	if len(outside) != 2 {
		t.Fatalf("a boundary that could not be read let %d of 2 hosts through", 2-len(outside))
	}
}

// ---------------------------------------------------------------------------------------------
// 7. THE GATE'S SENTENCE MAY NOT STATE A FACT IT DID NOT READ
// ---------------------------------------------------------------------------------------------

// The shipped default branch hardcoded "the framework has never performed a refresh of any
// credential on this target", which is false on proof_stale and proof_broken and was contradicted
// two sentences later in its own message. It reaches the operator verbatim on the configure modal.
func TestTheGateDoesNotClaimNothingWasEverRefreshedWhenAProofIsOnRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		cred TriageRenewalCredential
		code string
	}{
		{"stale", aProvenCredential(40 * time.Minute), TriageRenewalProofStale},
		{"broken", refreshProofBrokenCredential(), TriageRenewalProofBroken},
	} {
		g := gateFor(tc.cred)
		o := theOnlyOption(t, g)
		if o.Code != tc.code {
			t.Fatalf("%s: setup produced %s, want %s", tc.name, o.Code, tc.code)
		}
		if o.ProvenAt.IsZero() {
			t.Fatalf("%s: setup has no proof on record", tc.name)
		}
		if strings.Contains(g.Reason, "never performed a refresh of any credential") {
			t.Errorf("%s: the gate states a fact it did not read. proven_at=%s code=%s, reason:\n  %s",
				tc.name, o.ProvenAt.Format(time.RFC3339), o.Code, g.Reason)
		}
		if !strings.Contains(g.Reason, "HAS been performed") {
			t.Errorf("%s: the gate does not say a proof exists: %s", tc.name, g.Reason)
		}
	}
}

// The never-proven target still gets the sentence that is true of it, unchanged.
func TestTheGateStillSaysNothingWasRefreshedWhenNothingWas(t *testing.T) {
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "app bearer", IsActive: true,
		Profile: aProfiledCredential(RefreshCapability{
			Status: RefreshAvailable, Mechanism: RefreshMechanismOAuthRefresh,
			MintHost: "login.example.test", MintInScope: true,
		}),
	}
	g := gateFor(c)
	if !strings.Contains(g.Reason, "never performed a refresh of any credential") {
		t.Fatalf("a target where nothing was ever refreshed no longer says so: %s", g.Reason)
	}
}

// A target whose every credential is non-expiring is not a refusal and may not read as one.
func TestAllNonExpiringCredentialsAreNotReportedAsAFailureToProveAnything(t *testing.T) {
	p := aProfiledCredential(RefreshCapability{Status: RefreshNotObserved})
	p.ExpiryStyle = ExpiryStyleNonExpiring
	g := gateFor(TriageRenewalCredential{TokenID: "tok-1", Name: "api key", IsActive: true, Profile: p})
	if strings.Contains(g.Reason, "never performed a refresh") {
		t.Errorf("a non-expiring credential is reported as an unproven refresh: %s", g.Reason)
	}
	if !strings.Contains(g.Reason, "non-expiring") {
		t.Errorf("the gate does not say why renewal is not offered: %s", g.Reason)
	}
}

func refreshProofBrokenCredential() TriageRenewalCredential {
	c := aProvenCredential(2 * time.Minute)
	c.LastRefreshAt = renewalNow.Add(-time.Minute)
	c.LastRefreshStatus = "replay_failed"
	c.LastRefreshDetail = "the auth flow could not be replayed"
	return c
}

// ---------------------------------------------------------------------------------------------
// 8. A NON-EXPIRING STYLE WITH NOTHING BEHIND IT IS NOT A MEASUREMENT HERE EITHER
// ---------------------------------------------------------------------------------------------
//
// SessionTokenProfile.Survives already refuses to grant an unconditional yes on the style alone,
// because nothing in this package can currently produce non_expiring and the only way a profile
// carries it is a hand-edited row or a future writer that guessed. The renewal gate had the same
// hole in two places and neither had the same guard:
//
//	TriageRenewalIntervalFor  returned "the credential was measured as non-expiring"
//	triageRenewalOptionFor    returned "a run of any length outlives it and renewal would
//	                          change nothing"
//
// Both are the word MEASURED applied to a claim nobody measured, and both are worse than the
// Survives hole they mirror: this one is not a missing yes, it is a positive assurance that the
// operator does not need renewal on a credential that may die at minute ten.
func TestANonExpiringClaimWithNoProvenanceIsNotTreatedAsAMeasurementByTheGate(t *testing.T) {
	unmeasured := aProfiledCredential(RefreshCapability{
		Status: RefreshAvailable, Mechanism: RefreshMechanismOAuthRefresh,
		MintHost: "login.example.test", MintInScope: true,
	})
	unmeasured.ExpiryStyle = ExpiryStyleNonExpiring
	unmeasured.ExpiryProvenance = ProvUnknown
	// Nothing measured a lifetime either, which is the shape a hand-edited row actually has.
	unmeasured.TTLKnown, unmeasured.TTL = false, 0
	unmeasured.TTLFloorKnown, unmeasured.TTLFloor = false, 0
	unmeasured.ExpiryKnown = false

	if _, known, why := TriageRenewalIntervalFor(unmeasured); known {
		t.Errorf("an interval was derived from an unmeasured non-expiring claim: %s", why)
	} else if strings.Contains(why, "was measured as non-expiring") {
		t.Errorf("the interval refusal calls an unmeasured claim a measurement: %s", why)
	}

	o := theOnlyOption(t, gateFor(TriageRenewalCredential{
		TokenID: "tok-1", Name: "api key", IsActive: true, Profile: unmeasured,
	}))
	if o.Code == TriageRenewalNotNeeded {
		t.Fatalf("the gate told the operator a run of any length outlives a credential nothing measured: %s", o.Reason)
	}
	if !strings.Contains(strings.Join(o.Warnings, " "), "nothing says how that was established") {
		t.Errorf("the unmeasured non-expiring claim is not reported at all: %v", o.Warnings)
	}

	// And a claim that DOES name a method that could have established it still works.
	measured := unmeasured
	measured.ExpiryProvenance = ProvProbed
	if o := theOnlyOption(t, gateFor(TriageRenewalCredential{
		TokenID: "tok-1", Name: "api key", IsActive: true, Profile: measured,
	})); o.Code != TriageRenewalNotNeeded {
		t.Fatalf("a probed non-expiring credential is no longer recognised: %s / %s", o.Code, o.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// THE RENEWAL DRIVER: THE THING THAT MAKES THE SETTING DO SOMETHING
// ---------------------------------------------------------------------------------------------
//
// WHAT THESE PIN. Before this driver, TriageRenewalEffective had no production caller: renewal
// could be switched on, stored and displayed, and no scan renewed anything. So the tests below are
// about the decisions, and they use seams rather than a network: whether a schedule starts at all,
// whether it keeps asking permission, and whether it stops the moment the gate takes the
// permission away. The refresh itself is proven against a real application elsewhere in this file.

// renewalDriverFor builds a driver whose gate and refresh are the ones the test supplies.
// minInterval is dropped to a millisecond so a schedule can be observed inside a test; the
// production floor is pinned separately by TestTheDriverRefusesAnIntervalBelowItsFloor.
func renewalDriverFor(t *testing.T, s TriageInvestigateSettings, gate TriageRenewalGate,
	perform func(ctx context.Context, scopeTargetID, tokenID string) SessionRefreshProofResult) *TriageSessionRenewalDriver {
	t.Helper()
	d := newTriageSessionRenewalDriver("target-1", "", s)
	d.evaluate = func(context.Context, string, TriagePacing) TriageRenewalGate { return gate }
	d.perform = perform
	d.now = func() time.Time { return renewalNow }
	d.minInterval = time.Millisecond
	return d
}

// renewalDriverProof is what a successful renewal looks like coming back: the two credentials it
// compared and the fingerprints that compared them.
func renewalDriverProof(tokenID string) SessionRefreshProofResult {
	return SessionRefreshProofResult{
		TokenID: tokenID, Code: RefreshProofProven, Proven: true, StoredNewValue: true,
		Attempted: true, BeforeFingerprint: "aaaa1111", AfterFingerprint: "bbbb2222",
		BeforeValue: "the-old-credential", AfterValue: "the-new-credential",
		At: time.Now().UTC(), Detail: "a different working credential came back",
	}
}

// THE ONE THAT MATTERS: renewal switched on, the gate allowing it, and a schedule that actually
// spends the refresh. This is the measurement that was missing: before it, this path existed and
// nothing walked it.
func TestTheDriverRenewsOnItsIntervalWhileTheGateStillAllowsIt(t *testing.T) {
	calls := make(chan string, 8)
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(aProvenCredential(time.Minute)),
		func(_ context.Context, scopeTargetID, tokenID string) SessionRefreshProofResult {
			calls <- scopeTargetID + "/" + tokenID
			return renewalDriverProof(tokenID)
		})
	d.start(context.Background())
	defer d.Stop()

	if !d.On {
		t.Fatalf("renewal was switched on and permitted, and no schedule started: %s", d.Decision)
	}
	if d.Interval != time.Second {
		t.Fatalf("interval = %s, want the 1s the document names", d.Interval)
	}
	select {
	case got := <-calls:
		if got != "target-1/tok-1" {
			t.Fatalf("the renewal was spent on %q, want target-1/tok-1", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no renewal was performed within ten seconds of a one second schedule, so the setting is still inert")
	}

	d.Stop()
	attempts := d.Attempts()
	if len(attempts) == 0 {
		t.Fatal("the driver recorded no attempt, so a run could not say whether anything was renewed")
	}
	if !attempts[0].Proven || attempts[0].After != "bbbb2222" {
		t.Fatalf("the attempt does not record what came back: %+v", attempts[0])
	}
}

// The setting switched OFF renews nothing and says so. The sentence matters as much as the
// silence: a run that did not renew and cannot say why is indistinguishable from one that did.
func TestTheDriverRenewsNothingWhenTheSettingIsOff(t *testing.T) {
	performed := 0
	d := renewalDriverFor(t, TriageSettingsDefaults(), gateFor(aProvenCredential(time.Minute)),
		func(context.Context, string, string) SessionRefreshProofResult {
			performed++
			return SessionRefreshProofResult{}
		})
	d.start(context.Background())
	d.Stop()

	if d.On || performed != 0 {
		t.Fatalf("renewal is off and %d refresh(es) were performed", performed)
	}
	if !strings.Contains(d.Decision, "switched off") {
		t.Errorf("the driver does not say why it renewed nothing: %s", d.Decision)
	}
}

// A document that says renewal is on, against a gate that no longer permits it, renews NOTHING.
// The document is not the permission: the gate is, and it is asked at the start of every run.
func TestTheDriverAsksTheGateRatherThanTrustingTheStoredSetting(t *testing.T) {
	performed := 0
	stale := aProvenCredential(30 * time.Minute) // older than the credential it minted could live
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(stale),
		func(context.Context, string, string) SessionRefreshProofResult {
			performed++
			return SessionRefreshProofResult{}
		})
	d.start(context.Background())
	d.Stop()

	if d.On || performed != 0 {
		t.Fatalf("a stored setting armed a renewal the gate refuses, and %d refresh(es) were performed", performed)
	}
	if !strings.Contains(d.Decision, "no longer permitted") {
		t.Errorf("the refusal does not say the gate withdrew it: %s", d.Decision)
	}
}

// AND IT KEEPS ASKING. A proof that breaks mid-run takes the schedule away without anybody
// editing the document, which is the whole reason TriageRenewalEffective is re-evaluated rather
// than read once.
func TestTheDriverStopsRenewingWhenTheGateWithdrawsMidRun(t *testing.T) {
	good := gateFor(aProvenCredential(time.Minute))
	broken := aProvenCredential(10 * time.Minute)
	broken.LastRefreshAt = renewalNow.Add(-time.Minute)
	broken.LastRefreshStatus = "replay_failed"

	var mu sync.Mutex
	performed := 0
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), good,
		func(context.Context, string, string) SessionRefreshProofResult {
			mu.Lock()
			performed++
			mu.Unlock()
			return renewalDriverProof("tok-1")
		})
	// The gate answers good once, then refuses for ever after.
	asked := 0
	d.evaluate = func(context.Context, string, TriagePacing) TriageRenewalGate {
		mu.Lock()
		defer mu.Unlock()
		asked++
		if asked <= 1 {
			return good
		}
		return gateFor(broken)
	}
	d.start(context.Background())
	if !d.On {
		t.Fatalf("the schedule did not start: %s", d.Decision)
	}

	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-d.done:
			mu.Lock()
			did := performed
			mu.Unlock()
			if did != 0 {
				t.Fatalf("%d refresh(es) were performed after the gate withdrew the permission", did)
			}
			attempts := d.Attempts()
			if len(attempts) != 1 || !attempts[0].Withdrawn {
				t.Fatalf("the withdrawal was not recorded as one: %+v", attempts)
			}
			if !strings.Contains(attempts[0].Detail, "no longer permitted") {
				t.Errorf("the withdrawal does not carry the gate's own reason: %s", attempts[0].Detail)
			}
			return
		case <-deadline:
			t.Fatal("the driver was still scheduled fifteen seconds after the gate withdrew the permission")
		}
	}
}

// An interval below the floor is CLAMPED UP TO IT and the clamp is said out loud, rather than
// refused. See triageRenewalMinInterval for the decision and the measurement behind it: refusing
// withheld renewal from exactly the applications whose credentials are too short to survive a run
// without it.
func TestAnIntervalBelowTheFloorIsClampedToItAndTheClampIsSaid(t *testing.T) {
	performed := 0
	d := newTriageSessionRenewalDriver("target-1", "", settingsRenewing("tok-1", 30))
	d.evaluate = func(context.Context, string, TriagePacing) TriageRenewalGate {
		return gateFor(aProvenCredential(time.Minute))
	}
	d.perform = func(context.Context, string, string) SessionRefreshProofResult {
		performed++
		return renewalDriverProof("tok-1")
	}
	d.now = func() time.Time { return renewalNow }
	d.start(context.Background())
	defer d.Stop()

	if !d.On {
		t.Fatalf("a 30s schedule was refused outright rather than clamped to the floor, so this target renews NOTHING: %s", d.Decision)
	}
	if d.Interval != triageRenewalMinInterval {
		t.Fatalf("interval = %s, want it clamped to the %s floor", d.Interval, triageRenewalMinInterval)
	}
	for _, want := range []string{"30s", "1m", "CLAMPED"} {
		if !strings.Contains(d.Decision, want) {
			t.Errorf("the decision does not say %q, so the operator cannot tell the schedule is not the one they set: %s", want, d.Decision)
		}
	}
	if triageRenewalMinInterval != time.Minute {
		t.Fatalf("the production floor is %s; this test's arithmetic assumes a minute", triageRenewalMinInterval)
	}
	_ = performed
}

// THE APPLICATION THE DECISION IS ABOUT. A credential measured at 45 seconds derives a 22 second
// schedule, which is under the floor. Refusing it means no renewal at all on the one application
// that cannot survive a run without it; clamping means the run is authenticated for the 45 seconds
// of every minute that the credential is alive. The gap is REAL and it is stated, because a
// schedule that leaves a window unauthenticated and does not say so is a scan that quietly went
// anonymous.
func TestAShortLivedCredentialGetsAClampedScheduleAndIsToldAboutTheGap(t *testing.T) {
	d := newTriageSessionRenewalDriver("target-1", "", settingsRenewingDerived("tok-1"))
	d.evaluate = func(context.Context, string, TriagePacing) TriageRenewalGate {
		return gateFor(aShortLivedProvenCredential())
	}
	d.perform = func(context.Context, string, string) SessionRefreshProofResult { return renewalDriverProof("tok-1") }
	d.now = func() time.Time { return renewalNow }
	d.start(context.Background())
	defer d.Stop()

	if !d.On {
		t.Fatalf("the credential that most needs renewal got none: %s", d.Decision)
	}
	if d.Interval != triageRenewalMinInterval {
		t.Fatalf("interval = %s, want the %s floor", d.Interval, triageRenewalMinInterval)
	}
	// The measured lifetime is 45s and the schedule is 1m0s, so 15s of every cycle is spent
	// holding a credential that has expired. Both figures have to be in the sentence.
	for _, want := range []string{"45s", "1m", "15s"} {
		if !strings.Contains(d.Decision, want) {
			t.Errorf("the decision does not name %q, so the unauthenticated window is invisible: %s", want, d.Decision)
		}
	}
}

// aShortLivedProvenCredential is the 45 second application: proven recently enough that the gate
// still allows it, with a lifetime that derives a schedule under the floor.
func aShortLivedProvenCredential() TriageRenewalCredential {
	c := aProvenCredential(10 * time.Second)
	c.Profile.TTL = 45 * time.Second
	c.Profile.ExpiresAt = renewalNow.Add(35 * time.Second)
	return c
}

// settingsRenewingDerived switches renewal on and names no interval, so the schedule is the one
// derived from the measured lifetime rather than one an operator typed.
func settingsRenewingDerived(tokenID string) TriageInvestigateSettings {
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: tokenID}
	return s
}

// A credential the runner will never send is not worth a login flow. The triage runner reads the
// ACTIVE session_tokens rows only, so renewing an inactive one changes nothing about the scan
// while the screen says renewal is on.
func TestTheDriverRefusesToRenewACredentialTheRunWillNotSend(t *testing.T) {
	inactive := aProvenCredential(time.Minute)
	inactive.IsActive = false
	performed := 0
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(inactive),
		func(context.Context, string, string) SessionRefreshProofResult {
			performed++
			return SessionRefreshProofResult{}
		})
	d.start(context.Background())
	d.Stop()

	if d.On || performed != 0 {
		t.Fatalf("an inactive credential was renewed %d time(s)", performed)
	}
	if !strings.Contains(d.Decision, "not an active credential") {
		t.Errorf("the refusal does not say what is wrong: %s", d.Decision)
	}
}

// What the driver keeps is the record of a login it performed against the target, so it keeps the
// credential it retired and the one it put in its place. A run record saying a rotation happened,
// without either value, cannot be reconciled with the requests that went out after it.
func TestWhatTheRenewalDriverKeepsCarriesBothCredentialValues(t *testing.T) {
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(aProvenCredential(time.Minute)),
		func(_ context.Context, _, tokenID string) SessionRefreshProofResult {
			r := renewalDriverProof(tokenID)
			r.BeforeValue, r.AfterValue = refreshProofOldValue, refreshProofMintedA
			r.Detail = "a different working credential came back"
			return r
		})
	d.start(context.Background())
	time.Sleep(1500 * time.Millisecond)
	d.Stop()

	// THE WHOLE RECORD, not a chosen corner of it. This used to marshal the decision and the
	// attempts; everything added since (the cost, the clamp, the summary sentence that is now
	// composed server side and rendered verbatim) would have been outside the assertion.
	blob, err := json.Marshal(d.Runtime())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{refreshProofOldValue, refreshProofMintedA} {
		if !strings.Contains(string(blob), want) {
			t.Fatalf("the credential %q is not in what the driver keeps, so the rotation cannot be "+
				"reconciled with the requests sent after it: %s", want, blob)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE PROOF ENDPOINT IS REACHABLE
// ---------------------------------------------------------------------------------------------

// ProveSessionRefreshHandler was DEAD CODE: /prove-refresh appeared in no route table, so no
// operator and no API caller could reach it, and the only way to record a proof at all was the
// prove_refresh sidecar on the Investigate settings save.
//
// The route table is read out of main.go rather than rebuilt here. A test that registers the route
// itself proves its own router and nothing about the product: that is exactly how this endpoint
// came to be tested end to end while being unreachable.
func TestTheProofEndpointIsRegisteredInTheRouteTable(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "main.go"))
	if err != nil {
		t.Fatalf("the route table could not be read: %v", err)
	}
	line := ""
	for _, l := range strings.Split(string(source), "\n") {
		if strings.Contains(l, "/session-tokens/{id}/prove-refresh") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("/session-tokens/{id}/prove-refresh is in no route table, so ProveSessionRefreshHandler is dead code and no proof can be recorded through the product")
	}
	// The same line has to name the handler and the method, so a path registered to something
	// else, or registered for GET, is not read as this endpoint being reachable.
	for _, want := range []string{"utils.ProveSessionRefreshHandler", `Methods("POST"`} {
		if !strings.Contains(line, want) {
			t.Errorf("the route does not carry %q, so it is not the proof endpoint: %s", want, strings.TrimSpace(line))
		}
	}
}

// THE WHOLE THING, AGAINST A REAL APPLICATION AND A REAL DATABASE: a proof is taken, renewal is
// switched on, and the credential the runner would send IS REPLACED WHILE THE SCHEDULE RUNS.
//
// Everything above this test is decisions. This one is the feature: without it, "auto-renew
// renews" rests on fakes agreeing with each other. The application mints a different session on
// each login, the driver spends the refresh on its own schedule, and the assertion is on the row
// the triage runner's credential source reads.
func TestRenewalReplacesTheStoredCredentialWhileTheScheduleRuns(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, target, app.server.URL, "password login", app.steps())
	tokenID := refreshProofToken(t, ctx, target, flowID, refreshProofOldValue)

	// The proof, taken the way the product takes it. Without it the gate refuses and the driver
	// never starts, which is the behaviour the rest of this file pins.
	if p := ProveSessionRefreshForTarget(ctx, target, tokenID); !p.Proven {
		t.Fatalf("the proof could not be taken, so renewal cannot be measured at all: %s", p.Detail)
	}
	atRunStart := refreshProofStoredValue(t, ctx, tokenID)
	loginsBefore := app.logins

	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: tokenID, IntervalSeconds: 1}

	// The production gate and the production refresh. Only the floor is lowered, so a schedule
	// can be observed inside a test rather than in a minute.
	d := newTriageSessionRenewalDriver(target, "", s)
	d.minInterval = time.Millisecond
	d.start(ctx)
	if !d.On {
		t.Fatalf("renewal was switched on against a proof just taken and no schedule started: %s", d.Decision)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && len(d.Attempts()) == 0 {
		time.Sleep(100 * time.Millisecond)
	}
	d.Stop()

	attempts := d.Attempts()
	if len(attempts) == 0 {
		t.Fatal("the schedule ran for thirty seconds at a one second interval and renewed nothing")
	}
	if !attempts[0].Proven || !attempts[0].Stored {
		t.Fatalf("the renewal did not produce and store a working credential: %+v", attempts[0])
	}
	if app.logins <= loginsBefore {
		t.Fatalf("the application saw %d login(s) during the schedule, so nothing was replayed", app.logins-loginsBefore)
	}

	// THE ASSERTION THAT MATTERS: the row the triage runner reads now holds a different credential
	// from the one the run started with, and it is still active and non-empty, which is what that
	// runner's own query requires.
	atRunEnd := refreshProofStoredValue(t, ctx, tokenID)
	if atRunEnd == atRunStart {
		t.Fatal("the stored credential is the one the run started with, so the scan would still be sending the old session")
	}
	var active bool
	if err := dbPool.QueryRow(ctx,
		`SELECT is_active AND COALESCE(token_value,'') <> '' FROM session_tokens WHERE id = $1`, tokenID).Scan(&active); err != nil {
		t.Fatalf("read back the renewed row: %v", err)
	}
	if !active {
		t.Fatal("the renewed credential is not one the runner's own query would read")
	}

	// And the renewal is on the credential's timeline as a proof, not as a bare refresh.
	events := refreshProofEvents(t, ctx, tokenID)
	successes := 0
	for _, e := range events {
		if e == "refresh/success" {
			successes++
		}
	}
	if successes < 2 {
		t.Fatalf("the timeline holds %d proof event(s) after a proof and a renewal, want at least 2: %v", successes, events)
	}
}

// ---------------------------------------------------------------------------------------------
// WHAT A ROTATION COSTS THE RUN THAT IS NOT TOLD ABOUT IT
// ---------------------------------------------------------------------------------------------
//
// MEASURED END TO END, on the verifier's own application: renewal worked and the run stayed
// authenticated to 2.2 times its token life, and it paid a 401 at t+1m15s and another at t+2m15s,
// one per rotation. The driver replaces the stored credential and says nothing to the runner's
// credential cache, so on a credential with no readable expiry THE 401 IS THE TRIGGER that picks
// the new value up. The renewal knows the instant it rotated. The cache should be told.

// TestARotationIsThrottledByTheFloorMeantForADeadSession is the interaction, reproduced with no
// database and no network, on the real cache.
//
// The floor added in round 12 is keyed on the credential SET FINGERPRINT and lasts five seconds,
// which is right for a wall of 401s against one dead session. A rotation arriving inside that
// window names the same set (the re-read that the 401 caused has not seen the new value yet,
// because the renewal had not stored it), so it is floored: the run goes on sending a credential
// that was replaced, until the TTL runs out or another refusal is honoured.
func TestARotationIsThrottledByTheFloorMeantForADeadSession(t *testing.T) {
	const host = "app.example.test"
	s := newTriageFreshCredentials("scope-fixture")
	set := []triageFreshCred{credFor("Authorization", "66875250")}
	seedCredEntry(s, host, set)

	// t+1m14.9s: a request sent before the rotation comes back 401. Honoured, so the reading is
	// revoked and re-read; the re-read lands the SAME set, because the renewal has not written
	// the new value yet.
	s.Invalidate(host)
	credReReadSameSet(s, host)

	// t+1m15.0s: the renewal stores the new credential. This is the moment the run needs to know.
	if hosts := triageCredentialsRotated(s); len(hosts) != 1 || hosts[0] != host {
		t.Fatalf("the rotation revoked %v, want the one cached host %q", hosts, host)
	}
	if !credReadAt(s, host).IsZero() {
		t.Fatal("the rotation did not revoke the cached reading, so the run keeps sending the credential that was just replaced " +
			"and only a second 401 will pick the new one up. That 401 is a refused request charged to the operator, once per rotation.")
	}

	// AND THE FLOOR STILL DOES ITS JOB. A wall of refusals against the set that is now cached is
	// still bounded: the rotation must not be a way to reset the throttle either.
	seedCredEntry(s, host, []triageFreshCred{credFor("Authorization", "561d93e8")})
	for i := 0; i < 50; i++ {
		s.Invalidate(host)
	}
	if _, floored := s.invalidationCounts(host); floored == 0 {
		t.Error("50 refusals of one credential were all honoured, so the rotation path has disarmed the floor")
	}
}

// ---------------------------------------------------------------------------------------------
// WHAT THE RENEWAL SPENDS, AND WHETHER ANYONE CAN SEE IT
// ---------------------------------------------------------------------------------------------

// A renewal login is a real request against the target. On a 90 minute run against a 5 minute
// token there are eighteen of them, and until this they went through no budget and appeared in no
// count the operator sees. probes_sent counts classifier probes and is right to; the renewal
// logins need their own count, and it has to be on the run record rather than in a log line.
func TestTheRunRecordSaysWhatTheRenewalLoginsCost(t *testing.T) {
	ctx := triageTestDB(t)
	target := refreshProofTarget(t, ctx, "https://app.example.test")
	runUUID := renewalTestRun(t, ctx, target, "renewal-cost")

	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(aProvenCredential(time.Minute)),
		func(_ context.Context, _, tokenID string) SessionRefreshProofResult {
			r := renewalDriverProof(tokenID)
			r.MintHosts = []string{"login.example.test", "app.example.test"}
			r.FlowSteps, r.FlowStepsFailed = 4, 1
			return r
		})
	d.RunUUID = runUUID
	d.start(ctx)
	waitForRenewalAttempts(t, d, 1)
	d.Stop()

	runtime := renewalRuntimeOf(t, ctx, runUUID)
	cost, ok := runtime["cost"].(map[string]any)
	if !ok {
		t.Fatalf("the run record carries no cost for the renewal logins at all, so a scan that replayed eighteen logins reads identically to one that replayed none: %v", keysOf(runtime))
	}
	if n, _ := cost["logins"].(float64); n < 1 {
		t.Errorf("logins = %v, want at least the one that was performed", cost["logins"])
	}
	if n, _ := cost["flow_steps"].(float64); n != 4 {
		t.Errorf("flow_steps = %v, want the 4 the replay reported", cost["flow_steps"])
	}
	if n, _ := cost["flow_steps_failed"].(float64); n != 1 {
		t.Errorf("flow_steps_failed = %v, want the 1 the replay reported", cost["flow_steps_failed"])
	}
	if _, ok := cost["budget_slots"]; !ok {
		t.Error("the record does not say whether the login was paced by the run budget at all")
	}
}

// C. The driver records its decision and every attempt on the run row, and NOTHING RENDERS IT.
// A run that quietly went anonymous has to be visible in the run record, and the first place any
// client of this API looks is the run status.
func TestTheRunStatusServesWhatRenewalDid(t *testing.T) {
	ctx := triageTestDB(t)
	target := refreshProofTarget(t, ctx, "https://app.example.test")
	runUUID := renewalTestRun(t, ctx, target, "renewal-render")
	d := renewalDriverFor(t, TriageSettingsDefaults(), gateFor(aProvenCredential(time.Minute)),
		func(context.Context, string, string) SessionRefreshProofResult { return SessionRefreshProofResult{} })
	d.RunUUID = runUUID
	d.start(ctx)
	d.Stop()

	router := mux.NewRouter()
	router.HandleFunc("/triage/{scope_target_id}/run/status", GetTriageRunStatus).Methods("GET")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("GET", "/triage/"+target+"/run/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("run status: %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	renewal, ok := body["session_renewal"].(map[string]any)
	if !ok {
		t.Fatalf("the run status says nothing about session renewal, so nobody can answer whether the scan stayed authenticated: %v", keysOf(body))
	}
	if s, _ := renewal["summary"].(string); !strings.Contains(s, "switched off") {
		t.Errorf("the summary does not say why nothing was renewed: %q", s)
	}
}

// keysOf names what a map holds without printing what is in it.
func keysOf(m map[string]any) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// renewalRuntimeOf reads back what the driver recorded on the run row.
func renewalRuntimeOf(t *testing.T, ctx context.Context, runUUID string) map[string]any {
	t.Helper()
	var raw []byte
	if err := dbPool.QueryRow(ctx,
		`SELECT COALESCE(settings_snapshot->'session_renewal_runtime', '{}'::jsonb)::text FROM triage_runs WHERE id = $1`,
		runUUID).Scan(&raw); err != nil {
		t.Fatalf("read the renewal runtime back: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode the renewal runtime: %v", err)
	}
	return out
}

// waitForRenewalAttempts blocks until the driver has performed n attempts, or fails the test.
func waitForRenewalAttempts(t *testing.T, d *TriageSessionRenewalDriver, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if len(d.Attempts()) >= n {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the driver performed %d renewal(s) in twenty seconds, want %d", len(d.Attempts()), n)
}

// credReReadSameSet stands in for the re-read the refusal caused, landing the SAME credential set
// because the renewal has not stored the new value yet. It is not seedCredEntry: that replaces the
// whole entry and silently resets the floor bookkeeping, which FreshFor carries across a re-read on
// purpose, and the carried bookkeeping is the thing under test.
func credReReadSameSet(s *triageDBFreshCreds, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[host].status.ReadAt = time.Now()
}

// fakeRenewalBudget is the run's pacing budget as far as a renewal can see it. It records what was
// charged rather than waiting, so a test pins the charge and not a token bucket.
type fakeRenewalBudget struct {
	mu      sync.Mutex
	charged []string
	abort   string
}

func (b *fakeRenewalBudget) Wait(_ context.Context, host string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.charged = append(b.charged, host)
	return nil
}

func (b *fakeRenewalBudget) Aborted() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.abort
}

func (b *fakeRenewalBudget) took() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.charged...)
}

// A. THE RUN IS TOLD THE MOMENT THE CREDENTIAL ROTATES, and only when one actually rotated.
// A renewal that minted nothing, or minted something the target refused, replaced no stored value,
// and revoking the run's cached reading on that would throw away a working credential for nothing.
func TestARenewalTellsTheRunsCacheTheMomentItRotatesAndNotOtherwise(t *testing.T) {
	var mu sync.Mutex
	told := 0
	results := []SessionRefreshProofResult{
		func() SessionRefreshProofResult { return renewalDriverProof("tok-1") }(),
		{
			TokenID: "tok-1", Code: RefreshProofNotHonoured, Attempted: true, StoredNewValue: false,
			BeforeFingerprint: "aaaa1111", AfterFingerprint: "cccc3333",
			Detail: "the target did not honour the credential that came back", At: time.Now().UTC(),
		},
	}
	at := 0
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(aProvenCredential(time.Minute)),
		func(context.Context, string, string) SessionRefreshProofResult {
			mu.Lock()
			defer mu.Unlock()
			r := results[at%len(results)]
			at++
			return r
		})
	d.rotated = func(before, after string) int {
		mu.Lock()
		defer mu.Unlock()
		told++
		if before == "" || after == "" || before == after {
			t.Errorf("the rotation was announced as %q -> %q, which is not a rotation", before, after)
		}
		return 3
	}
	d.start(context.Background())
	waitForRenewalAttempts(t, d, 2)
	d.Stop()

	attempts := d.Attempts()
	if !attempts[0].RotationTold || attempts[0].HostsRevoked != 3 {
		t.Errorf("the renewal that replaced the credential did not tell the run: %+v", attempts[0])
	}
	if attempts[1].RotationTold {
		t.Errorf("a renewal that stored nothing revoked the run's cached credential anyway: %+v", attempts[1])
	}
	mu.Lock()
	defer mu.Unlock()
	if told != 1 {
		t.Errorf("the cache was told %d time(s) across one rotation and one failed renewal, want 1", told)
	}
}

// B. THE LOGIN IS CHARGED TO THE RUN'S OWN BUDGET, one slot per host the mint touched, and the
// charge is what is recorded rather than an intention to charge.
func TestARenewalLoginIsChargedToTheRunsPacingBudget(t *testing.T) {
	budget := &fakeRenewalBudget{}
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(aProvenCredential(time.Minute)),
		func(_ context.Context, _, tokenID string) SessionRefreshProofResult {
			r := renewalDriverProof(tokenID)
			r.MintHosts = []string{"login.example.test", "app.example.test"}
			r.FlowSteps, r.FlowStepsFailed = 4, 1
			return r
		})
	d.budget = budget
	d.start(context.Background())
	waitForRenewalAttempts(t, d, 1)
	d.Stop()

	took := budget.took()
	if len(took) < 2 || took[0] != "login.example.test" || took[1] != "app.example.test" {
		t.Fatalf("the renewal login took %v from the run budget, want one slot per mint host", took)
	}
	cost := d.Cost()
	if cost.Logins < 1 || cost.BudgetSlots < 2 {
		t.Errorf("the cost records %d login(s) and %d budget slot(s): %+v", cost.Logins, cost.BudgetSlots, cost)
	}
	if cost.Unpaced != 0 {
		t.Errorf("a login charged to a budget was counted as unpaced: %+v", cost)
	}
	if cost.FlowSteps < 4 || cost.FlowStepsFailed < 1 {
		t.Errorf("the flow the replay reported is not in the cost: %+v", cost)
	}
	if !strings.Contains(d.Summary(), "NOT counted in probes_sent") {
		t.Errorf("the summary does not say these requests are outside probes_sent: %s", d.Summary())
	}
}

// A run with no budget lent to it says the logins were unpaced rather than claiming they were not.
func TestALoginWithNoRunBudgetBehindItIsCountedAsUnpaced(t *testing.T) {
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(aProvenCredential(time.Minute)),
		func(_ context.Context, _, tokenID string) SessionRefreshProofResult {
			r := renewalDriverProof(tokenID)
			r.MintHosts = []string{"login.example.test"}
			return r
		})
	d.start(context.Background())
	waitForRenewalAttempts(t, d, 1)
	d.Stop()

	if cost := d.Cost(); cost.Unpaced < 1 || cost.BudgetSlots != 0 {
		t.Errorf("a login with no budget behind it recorded %+v", cost)
	}
	if !strings.Contains(d.Summary(), "no run pacing budget") {
		t.Errorf("the summary does not say the logins were unpaced: %s", d.Summary())
	}
}

// The run stopped sending, so the schedule stops too. A budget aborts when a host is failing or
// the operator pulled the run up, and replaying whole logins at a target the run has just backed
// off from is the framework ignoring its own brake.
func TestRenewalStopsWhenTheRunsPacingBudgetHasAborted(t *testing.T) {
	budget := &fakeRenewalBudget{abort: "the host returned 27 consecutive 503s"}
	performed := 0
	var mu sync.Mutex
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(aProvenCredential(time.Minute)),
		func(context.Context, string, string) SessionRefreshProofResult {
			mu.Lock()
			performed++
			mu.Unlock()
			return renewalDriverProof("tok-1")
		})
	d.budget = budget
	d.start(context.Background())
	select {
	case <-d.done:
	case <-time.After(15 * time.Second):
		t.Fatal("the schedule was still running fifteen seconds after the run's budget aborted")
	}
	d.Stop()

	mu.Lock()
	defer mu.Unlock()
	if performed != 0 {
		t.Fatalf("%d login(s) were replayed at a target the run had already stopped sending to", performed)
	}
	if !strings.Contains(d.Decision, "27 consecutive 503s") {
		t.Errorf("the stop does not carry the budget's own reason: %s", d.Decision)
	}
}

// THE WHOLE OF A, END TO END, AGAINST A REAL APPLICATION, A REAL DATABASE AND THE RUNNER'S OWN
// CREDENTIAL SOURCE.
//
// The credential here has NO READABLE EXPIRY, which is the measured case: a cookie the server sets
// with no Expires, so neither the JWT claim nor the expires_at column can tell the cache anything
// and the 30 second TTL is the only clock it has. The test performs no refusal and calls no
// Invalidate. Before the rotation notice the source went on handing out the replaced credential
// until a 401 came back, and that 401 is a request the operator paid for, once per rotation.
func TestARotatedCredentialReachesTheNextRequestWithoutARefusal(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newRefreshProofApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)
	flowID := refreshProofFlow(t, ctx, target, app.server.URL, "password login", app.steps())
	tokenID := refreshProofToken(t, ctx, target, flowID, refreshProofOldValue)
	if p := ProveSessionRefreshForTarget(ctx, target, tokenID); !p.Proven {
		t.Fatalf("the proof could not be taken, so renewal cannot be measured at all: %s", p.Detail)
	}

	_, host, _ := ScopeTargetBase(target)
	creds := newTriageFreshCredentials(target)
	before, status := creds.FreshFor(host)
	if len(before) == 0 {
		t.Fatalf("the runner's own credential source has nothing for %s to begin with, so this test would measure nothing: %s",
			host, status.Note)
	}
	for _, c := range before {
		if !c.Expires.IsZero() {
			t.Fatalf("this credential has a readable expiry, so the TTL is not the only clock and the measurement is a different one: %s", c.ExpirySource)
		}
	}

	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: tokenID, IntervalSeconds: 1}
	d := newTriageSessionRenewalDriver(target, "", s)
	d.minInterval = time.Millisecond
	d.rotated = func(string, string) int { return len(triageCredentialsRotated(creds)) }
	d.start(ctx)
	if !d.On {
		t.Fatalf("renewal was switched on against a proof just taken and no schedule started: %s", d.Decision)
	}
	waitForRenewalAttempts(t, d, 1)
	d.Stop()

	if a := d.Attempts()[0]; !a.Stored {
		t.Fatalf("the renewal stored nothing, so there is no rotation to pick up: %+v", a)
	} else if a.HostsRevoked < 1 {
		t.Fatalf("the rotation revoked no cached host reading, so the run was not told: %+v", a)
	}

	// NO REFUSAL AND NO Invalidate BETWEEN THESE TWO READS. The only thing that has happened is
	// the rotation, and the TTL has not expired.
	after, _ := creds.FreshFor(host)
	if len(after) == 0 {
		t.Fatal("the credential source has nothing to hand out after the renewal")
	}
	if triageCredSetPrint(after) == triageCredSetPrint(before) {
		t.Fatalf("the run would still send the credential the renewal replaced, and only a 401 would pick the new one up. "+
			"Cached set %s", triageCredSetPrint(after))
	}
	if honoured, floored := creds.invalidationCounts(host); honoured != 0 || floored != 0 {
		t.Errorf("the rotation went through the refusal trigger (%d honoured, %d floored), which is the one the five second floor throttles",
			honoured, floored)
	}
}

// A renewal REFUSED before anything was sent is not a login. It must not be counted as a request
// against the target and it must not be counted as a login that failed: the sentence the operator
// reads has to agree with the count beside it.
func TestARenewalRefusedBeforeSendingIsNotCountedAsARequest(t *testing.T) {
	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(aProvenCredential(time.Minute)),
		func(_ context.Context, _, tokenID string) SessionRefreshProofResult {
			return SessionRefreshProofResult{
				TokenID: tokenID, Code: RefreshProofMintOutOfScope, Attempted: false,
				BeforeFingerprint: "aaaa1111", At: time.Now().UTC(),
				Detail: "the linked auth flow would send to a host outside this engagement, so NOTHING WAS SENT",
			}
		})
	budget := &fakeRenewalBudget{}
	d.budget = budget
	d.start(context.Background())
	waitForRenewalAttempts(t, d, 1)
	d.Stop()

	if cost := d.Cost(); cost.Logins != 0 || cost.BudgetSlots != 0 || cost.Unpaced != 0 {
		t.Errorf("a refusal that sent nothing was counted as a request: %+v", cost)
	}
	if took := budget.took(); len(took) != 0 {
		t.Errorf("a refusal that sent nothing was charged to the run budget: %v", took)
	}
	s := d.Summary()
	if !strings.Contains(s, "refused before anything was sent") {
		t.Errorf("the summary does not distinguish a refusal from a failed login: %s", s)
	}
	if strings.Contains(s, "did not.") && strings.Contains(s, "login replay(s) went to the target") {
		t.Errorf("the summary reports login replays when none were sent: %s", s)
	}
}

// renewalTestRun creates a triage run for a test and removes it afterwards.
//
// THE RUN ID MUST BE UNIQUE PER INVOCATION. triage_runs.run_id carries a UNIQUE constraint, which
// is right (a marker carrying another run's id is capped at stale_marker, so two runs may not share
// one), and a fixture that hard-codes a name fails the SECOND time the suite is run against the
// same database with "duplicate key value violates unique constraint triage_runs_run_id_key".
// Measured: this test passed on its own and failed in the full suite for exactly that reason, on a
// row an earlier run of itself had left behind. The row is deleted here rather than left to a
// cascade, because whether the scope target's delete reaches it is not something this test should
// be resting on.
func renewalTestRun(t *testing.T, ctx context.Context, target, name string) string {
	t.Helper()
	runID := fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
	runUUID, err := CreateTriageRun(ctx, TriageRunSpec{ScopeTargetID: target, RunID: runID})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	t.Cleanup(func() {
		if _, err := dbPool.Exec(context.Background(), `DELETE FROM triage_runs WHERE id = $1`, runUUID); err != nil {
			t.Errorf("could not clean up triage run %s: %v", runUUID, err)
		}
	})
	return runUUID
}

// D. THE RENEWAL RECORD IS THE ANSWER TO "IS MY SCAN STILL AUTHENTICATED", AND THAT QUESTION IS
// ASKED WHILE THE RUN IS RUNNING.
//
// record() was called on exactly three branches: at start, on a withdrawal, and from Stop. A run
// whose renewals all SUCCEED therefore wrote the record once, at start, with cost.Logins zero and
// an empty attempt list, and left it there for the whole run. GetTriageRunStatus reads that row, so
// for the ninety minutes an operator would actually be watching, the API served:
//
//	"Renewal was scheduled every 5m for app bearer. No login was replayed, so nothing about the
//	 credential changed during this run."
//
// beside eighteen logins that had already gone to the target. The record was written, served and
// WRONG until the run ended, which is worse than unread: a client that renders it faithfully
// renders a false sentence.
func TestTheRunRecordIsCurrentWhileTheRunIsStillRunning(t *testing.T) {
	ctx := triageTestDB(t)
	target := refreshProofTarget(t, ctx, "https://app.example.test")
	runUUID := renewalTestRun(t, ctx, target, "renewal-midrun")

	d := renewalDriverFor(t, settingsRenewing("tok-1", 1), gateFor(aProvenCredential(time.Minute)),
		func(_ context.Context, _, tokenID string) SessionRefreshProofResult {
			r := renewalDriverProof(tokenID)
			r.MintHosts = []string{"app.example.test"}
			r.FlowSteps = 3
			return r
		})
	d.RunUUID = runUUID
	d.start(ctx)
	defer d.Stop()
	waitForRenewalAttempts(t, d, 2)

	// READ WHILE THE SCHEDULE IS STILL RUNNING. No Stop, because an operator watching a run does
	// not get to stop it first.
	runtime := renewalRuntimeOf(t, ctx, runUUID)
	cost, ok := runtime["cost"].(map[string]any)
	if !ok {
		t.Fatalf("the run record carries no cost: %v", keysOf(runtime))
	}
	logins, _ := cost["logins"].(float64)
	if logins < 2 {
		t.Errorf("THE RECORD IS STALE WHILE THE RUN IS RUNNING: logins = %v on the run row and the driver has "+
			"performed %d. The run status API reads this row, so for the whole length of the run it answers "+
			"the question with a figure that was true only before the first renewal.",
			cost["logins"], len(d.Attempts()))
	}
	if attempts, _ := runtime["attempts"].([]any); len(attempts) < 2 {
		t.Errorf("attempts on the run row = %d, and the driver has performed %d, so nothing an operator can "+
			"read says a login happened until the run is over", len(attempts), len(d.Attempts()))
	}
	summary, _ := runtime["summary"].(string)
	if strings.Contains(summary, "No login was replayed") {
		t.Errorf("THE SERVED SUMMARY IS FALSE: %d login(s) have gone to the target and the run record says none "+
			"have: %q", len(d.Attempts()), summary)
	}
	if !strings.Contains(summary, "login replay(s) went to the target") {
		t.Errorf("the served summary does not say what the logins were: %q", summary)
	}
}

// AND THE RECORD HAS TO SAY THE SCHEDULE ENDED, IN A FIELD AND NOT ONLY IN A SENTENCE.
//
// On is set true when a schedule starts and was never set false again. The gate is re-evaluated
// before every renewal and can withdraw the permission mid-run, and the run's pacing budget can
// abort; both stop the loop. After either, the record kept serving on:true, so a client rendering a
// badge off that field shows renewal running for the rest of a run in which nothing has been
// renewed since minute four. The summary says it in prose, and prose is not what a badge reads.
func TestTheRecordSaysTheScheduleEndedAndNotOnlyInASentence(t *testing.T) {
	allow := gateFor(aProvenCredential(time.Minute))
	withdrawn := allow
	// A deep copy of the option slice: the two gates share a backing array otherwise, and
	// withdrawing the permission would withdraw it from the gate that is meant to allow it.
	withdrawn.Options = append([]TriageRenewalOption{}, allow.Options...)
	withdrawn.Options[0].Usable = false
	withdrawn.Options[0].Reason = "the refresh proof for this credential has gone stale"

	gates := make(chan TriageRenewalGate, 4)
	gates <- allow
	gates <- withdrawn

	d := newTriageSessionRenewalDriver("target-1", "", settingsRenewing("tok-1", 1))
	d.evaluate = func(context.Context, string, TriagePacing) TriageRenewalGate {
		select {
		case g := <-gates:
			return g
		default:
			return withdrawn
		}
	}
	d.perform = func(context.Context, string, string) SessionRefreshProofResult { return renewalDriverProof("tok-1") }
	d.now = func() time.Time { return renewalNow }
	d.minInterval = time.Millisecond
	d.start(context.Background())
	defer d.Stop()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && len(d.Attempts()) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	<-d.done

	rt := d.Runtime()
	stopped, ok := rt["stopped"].(bool)
	if !ok {
		t.Fatalf("the record has no field saying the schedule ended, so the only way to know is to parse a sentence: %v", keysOf(rt))
	}
	if !stopped {
		t.Errorf("stopped = false on a schedule the gate withdrew: on=%v decision=%q", rt["on"], rt["decision"])
	}
	if why, _ := rt["stopped_why"].(string); !strings.Contains(why, "stale") {
		t.Errorf("stopped_why does not carry the gate's own reason: %q", why)
	}
	// The sentence and the fields have to agree, or the client and the reader disagree.
	if s, _ := rt["summary"].(string); !strings.Contains(s, "THE SCHEDULE THEN STOPPED") {
		t.Errorf("the summary does not say the schedule stopped while the field does: %q", s)
	}
}
