package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------------------------
// PERFORMING A REFRESH AND RECORDING WHAT WAS OBSERVED
// ---------------------------------------------------------------------------------------------
//
// WHY THIS FILE EXISTS.
//
// The renewal gate in triageSettingsAPI.go refuses to offer automatic session renewal until a
// refresh has been PROVEN: performed, with a different credential observed coming back and
// observed to work. RecordRefreshProof in sessionTokenProfile.go is the only writer of that proof,
// and until this file landed it had NO PRODUCTION CALLER. Measured: a grep of the tree for
// RecordRefreshProof outside _test.go returned the definition and three comments and nothing else.
//
// That made the whole control unreachable on every application. The gate was correct at three
// layers and correct about nothing, because the state it demands could not be entered. A rule that
// can never be satisfied is not a safety property, it is a dead switch.
//
// So this is the thing that actually does it: it spends the refresh mechanism, watches what comes
// back, and writes a proof ONLY when it saw a different credential that the target then honoured.
//
// WHAT "PROVEN" MEANS HERE, AND WHY EACH PART IS REQUIRED.
//
//  1. A DIFFERENT CREDENTIAL CAME BACK. A mint that hands back the value you already had renewed
//     nothing; it proved the endpoint answers. RecordRefreshProof refuses two equal fingerprints
//     and this refuses before it gets there, so the operator reads a sentence about their session
//     rather than an error about an argument.
//
//  2. THE TARGET HONOURS IT. A new string is not a working session. The new value is sent at the
//     same probe the Session Manager's validation uses, beside an anonymous control, and only a
//     measured difference between the two arms counts. Without this the proof would be "the mint
//     returned something", which is the shape of every false clean in this codebase: an artefact
//     recorded as an observation.
//
// This is the standing rule that validated requires a proof of concept, applied to ourselves. The
// framework may not promise a scan will still be authenticated at minute twenty nine on the
// strength of a refresh_token field it has never spent.
//
// SCOPE IS DECIDED BEFORE ANYTHING IS SENT, AND IT IS DECIDED OVER EVERY HOST.
//
// A refresh is a replay of a recorded login flow, and a login flow routinely crosses hosts: the
// application redirects to an identity provider, the identity provider mints, the application
// takes the result. On the engagement this was built against the mint is at a host that is
// explicitly OUT OF SCOPE, and the operator's own flow is named "DO NOT REPLAY - OUT OF SCOPE
// HOST". The existing POST /session-tokens/{id}/refresh checks NONE of that: it replays whatever
// the flow says.
//
// This path refuses first and sends nothing. Every step's target host is resolved from its own raw
// request, the flow's base URL is resolved too, and if ANY of them is outside the engagement the
// answer is the gate's existing mint_out_of_scope state with the offending host named. The operator
// can nearly always re-authenticate by hand and paste a value; that is a different plan from "this
// session cannot be renewed", and collapsing the two throws away the one piece of advice that
// helps.
//
// WHAT IS WRITTEN AND WHAT IS NOT.
//
// A refresh that was ATTEMPTED and failed is recorded as a session_token_events row of kind
// "refresh" with a failing status, because that is a real observation about the mechanism and the
// gate's second test is meant to see it: a credential proven on Monday and failing since must stop
// being offerable.
//
// A refresh that was NOT attempted (out of scope, no flow, no value, a companion) is recorded with
// kind "refresh_proof" and status "not_attempted" instead. It is deliberately NOT a kind=refresh
// row: the gate reads the most recent refresh event of any status and treats an unrecognised one as
// a failure, so filing "we declined to touch an out-of-scope host" there would revoke a standing
// proof for a reason that says nothing whatever about whether the mint still works. The event is
// still written, because an operator pressing a button and seeing nothing in the timeline cannot
// tell a refusal from a crash.
//
// THE STORED VALUE IS ONLY REPLACED BY A CREDENTIAL THAT WAS OBSERVED TO WORK. The minted value is
// validated in memory first. A mint that returns a dead string therefore leaves the operator's
// working credential alone, which is the opposite of what the existing refresh handler does: it
// writes whatever came back before anything has asked the target about it.
//
// THAT IS NOT THE SAME AS LEAVING THE OPERATOR WHERE THEY STARTED, and the sentence says so. A
// login was performed, and on an application that rotates the session on login the credential we
// kept may have been invalidated by the very refresh that failed to produce a usable replacement.
// Keeping the old value is still the better half of a bad choice: it is the one that was last
// observed working, and the alternative is storing a value observed NOT working. The operator is
// told a refresh happened so they can validate by hand rather than discovering it mid-run.
//
// THE PROOF HOLDS BOTH CREDENTIALS. What it asserts is that the flow returned a DIFFERENT value
// and that the target honoured it, so the two values are the evidence for the claim and they are
// carried on the result, in the event detail and in the log line beside the fingerprints that
// compare them. A proof nobody can check against the wire is not a proof.

// The outcome codes. They are constants because the client renders a sentence per code, and a code
// invented at a call site is a sentence nobody wrote.
const (
	// The proof was taken.
	RefreshProofProven = "proven"

	// Attempted, and the attempt says something about the mechanism.
	RefreshProofSameCredential = "same_credential"
	RefreshProofNotHonoured    = "not_honoured"
	RefreshProofReplayFailed   = "replay_failed"
	RefreshProofNoTokenFound   = "no_token_found"
	RefreshProofNotRecorded    = "proof_not_recorded"

	// Not attempted. Nothing went on the wire on any of these paths.
	RefreshProofMintOutOfScope = "mint_out_of_scope"
	RefreshProofNoFlow         = "no_flow"
	RefreshProofNoCredential   = "no_credential_value"
	RefreshProofCompanion      = "companion_value"
	RefreshProofNoSuchToken    = "no_such_credential"
	RefreshProofWrongTarget    = "credential_belongs_elsewhere"
	RefreshProofNoDatabase     = "no_database"
)

// SessionRefreshProofResult is what one press of the button observed. It carries the two
// credentials it compared as well as their fingerprints: the fingerprints are the comparison, the
// values are the evidence.
type SessionRefreshProofResult struct {
	TokenID   string `json:"token_id"`
	TokenName string `json:"token_name"`

	// Code is the machine-readable answer and Detail is the sentence the operator acts on.
	Code   string `json:"code"`
	Detail string `json:"detail"`

	// Attempted says whether anything was sent. It is separate from Proven because "we declined to
	// touch an out-of-scope host" and "we tried and it did not work" are different facts and the
	// operator's next move differs.
	Attempted bool `json:"attempted"`
	Proven    bool `json:"proven"`
	// StoredNewValue says whether the credential the framework will send from now on was replaced.
	StoredNewValue bool `json:"stored_new_value"`

	// The fingerprints are the COMPARISON: equal fingerprints mean the flow handed back the same
	// credential and nothing was proven. The values beside them are what was compared.
	BeforeFingerprint string `json:"before_fingerprint"`
	AfterFingerprint  string `json:"after_fingerprint"`
	BeforeValue       string `json:"before_value"`
	AfterValue        string `json:"after_value"`

	// Where the mint is and whether the engagement allows it, named on every path so a refusal can
	// be argued with.
	MintHosts   []string `json:"mint_hosts"`
	MintInScope bool     `json:"mint_in_scope"`

	// What the target said about the value that came back. Empty when nothing was minted.
	ValidationStatus string `json:"validation_status"`
	ValidationDetail string `json:"validation_detail"`

	// Companions refreshed out of the same login response, by cookie name. A credential renewed
	// while its routing cookie still points at the old backend is worse than no renewal.
	CompanionsRefreshed []string `json:"companions_refreshed"`

	// WHAT THE REPLAY COST, as the replay itself reported it, so a caller that is renewing on a
	// schedule can account for what it is spending against the engagement.
	//
	// FlowSteps IS THE FLOW LENGTH AND NOT A REQUEST COUNT, and it is named for what was read.
	// replayFlowForToken records evidence["steps_replayed"] as len(steps), which includes any step
	// it refused before sending, so calling it requests-sent here would be a number this file never
	// measured. FlowStepsFailed is evidence["steps_failed"], which counts both a step refused before
	// it was sent and a step whose send errored. Both stay zero on every path that sent nothing.
	FlowSteps       int `json:"flow_steps"`
	FlowStepsFailed int `json:"flow_steps_failed"`

	Evidence []string  `json:"evidence"`
	At       time.Time `json:"at"`
}

// Attempted-or-not is worth saying once, for the event kind.
func (r SessionRefreshProofResult) eventKind() string {
	if r.Attempted {
		return "refresh"
	}
	return "refresh_proof"
}

// ProveSessionRefreshForTarget is the guarded entry point: it refuses a credential that belongs to
// a different scope target before doing anything else.
//
// The settings endpoint is addressed by scope target and the credential is named in the body, so
// without this check a PUT against target A could spend target B's refresh mechanism and rewrite
// B's stored credential. The two ids are compared rather than trusted.
func ProveSessionRefreshForTarget(ctx context.Context, scopeTargetID, tokenID string) SessionRefreshProofResult {
	out := SessionRefreshProofResult{TokenID: tokenID, At: time.Now().UTC(), Evidence: []string{}}
	if dbPool == nil {
		out.Code, out.Detail = RefreshProofNoDatabase,
			"There is no database connection, so the credential could not be read and no refresh was attempted."
		return out
	}
	tok, err := loadSessionToken(tokenID)
	if err != nil {
		out.Code, out.Detail = RefreshProofNoSuchToken,
			"No credential with that id is stored, so there was nothing to refresh."
		return out
	}
	if strings.TrimSpace(scopeTargetID) != "" && tok.ScopeTargetID != scopeTargetID {
		out.TokenName = tok.Name
		out.Code, out.Detail = RefreshProofWrongTarget, fmt.Sprintf(
			"The credential %q belongs to a different scope target, so it was not refreshed from here. "+
				"A refresh spends a real login and replaces a real stored value; doing that to another "+
				"target's session because its id was in a request body is not something this endpoint does.",
			tok.Name)
		return out
	}
	return proveSessionRefresh(ctx, tok)
}

// ProveSessionRefresh performs and records a refresh for one credential by id.
func ProveSessionRefresh(ctx context.Context, tokenID string) SessionRefreshProofResult {
	return ProveSessionRefreshForTarget(ctx, "", tokenID)
}

// proveSessionRefresh is the whole sequence, on a credential already loaded.
func proveSessionRefresh(ctx context.Context, tok SessionToken) SessionRefreshProofResult {
	out := SessionRefreshProofResult{
		TokenID:   tok.ID,
		TokenName: tok.Name,
		At:        time.Now().UTC(),
		Evidence:  []string{},
		MintHosts: []string{},
	}

	// ---- The refusals, in the order that makes the sentence most useful. Nothing is sent by any
	// of them, and each one is recorded as not_attempted rather than as a failed refresh.

	if strings.TrimSpace(tok.TokenValue) == "" {
		out.Code, out.Detail = RefreshProofNoCredential,
			"No value is stored for this credential, so there is nothing to compare a refreshed one against "+
				"and no proof could be taken. A proof is two credentials that differ; with no value there is only one."
		return finishRefreshProof(out)
	}
	out.BeforeValue = tok.TokenValue
	out.BeforeFingerprint = NewCredential(tok.TokenValue).Fingerprint()

	if tok.TokenRole == tokenRoleCompanion {
		out.Code, out.Detail = RefreshProofCompanion, fmt.Sprintf(
			"%s is a companion value rather than a credential, so it is not refreshed on its own and cannot "+
				"prove anything about a session. Companions are taken from the same login response as the "+
				"credential they travel with, when that credential is refreshed.", tok.Name)
		return finishRefreshProof(out)
	}

	if strings.TrimSpace(tok.AuthFlowID) == "" {
		out.Code, out.Detail = RefreshProofNoFlow, fmt.Sprintf(
			"%s is not tied to an auth flow, so there is no recorded sequence to replay and nothing that could "+
				"mint another one. Link it to the login flow that issues it in the Session Manager, then take the proof.",
			tok.Name)
		return finishRefreshProof(out)
	}

	// SCOPE, over every host the replay would touch, decided before anything is sent.
	hosts, flowName, scopeErr := sessionRefreshTargets(tok.AuthFlowID)
	out.MintHosts = hosts
	if scopeErr != "" {
		out.Code, out.Detail = RefreshProofNoFlow, scopeErr
		return finishRefreshProof(out)
	}
	if reDoNotReplay.MatchString(flowName) {
		out.Code, out.MintInScope = RefreshProofMintOutOfScope, false
		out.Detail = fmt.Sprintf(
			"The linked auth flow %q is labelled do-not-replay, so the mint is documented and must not be exercised "+
				"from here. Nothing was sent. Re-authenticate by hand and paste a fresh value before a long run.", flowName)
		return finishRefreshProof(out)
	}
	scope := LoadScanScope(tok.ScopeTargetID)
	if outside := hostsOutsideScope(scope, hosts); len(outside) > 0 {
		out.Code, out.MintInScope = RefreshProofMintOutOfScope, false
		out.Detail = fmt.Sprintf(
			"The linked auth flow %q would send to %s, which is outside this engagement's scope, so NOTHING WAS SENT. "+
				"The mechanism is documented and the framework must not exercise it. Re-authenticate by hand and paste "+
				"a fresh value before a long run.", flowName, strings.Join(outside, ", "))
		out.Evidence = append(out.Evidence, "the engagement boundary is "+scopeDescribe(scope))
		return finishRefreshProof(out)
	}
	out.MintInScope = true
	// Partition the admitted hosts so the proof is auditable: a host admitted BECAUSE it is a
	// classified auth host is called out by name rather than folded into "in scope", so the operator
	// sees exactly why an OAuth/SSO host the scanners refuse was nonetheless a legitimate refresh
	// destination.
	var inScopeHosts, authAdmitted []string
	for _, h := range hosts {
		if scope.IsAuthHost(h) && !scope.Allows(h) {
			authAdmitted = append(authAdmitted, h)
		} else {
			inScopeHosts = append(inScopeHosts, h)
		}
	}
	if len(inScopeHosts) > 0 {
		out.Evidence = append(out.Evidence, fmt.Sprintf(
			"every in-scope host the flow %q would send to (%s) is inside this engagement's scope",
			flowName, strings.Join(inScopeHosts, ", ")))
	}
	if len(authAdmitted) > 0 {
		out.Evidence = append(out.Evidence, fmt.Sprintf(
			"the flow %q also sends to %s, admitted as classified auth host(s): reachable to refresh the "+
				"session but excluded from every scan", flowName, strings.Join(authAdmitted, ", ")))
	}

	// ---- From here on, requests go out.
	out.Attempted = true

	var issuedCookies []string
	value, expires, evidence, err := replayFlowForToken(tok, &issuedCookies)
	if steps, ok := evidence["steps_replayed"].(int); ok {
		out.FlowSteps = steps
		out.Evidence = append(out.Evidence, fmt.Sprintf("%d step(s) of the flow were replayed", steps))
	}
	if failed, ok := evidence["steps_failed"].(int); ok {
		out.FlowStepsFailed = failed
	}
	if err != nil {
		out.Code = RefreshProofReplayFailed
		out.Detail = "The auth flow could not be replayed, so no credential was minted and nothing is proven: " +
			truncateReason(err.Error())
		return finishRefreshProof(out, evidence)
	}
	if strings.TrimSpace(value) == "" {
		out.Code = RefreshProofNoTokenFound
		out.Detail = fmt.Sprintf(
			"The flow replayed, but no new value for %s turned up in the responses, so there is nothing to compare and "+
				"nothing is proven. Check that the flow's steps still succeed and that the credential really is issued "+
				"as a Set-Cookie or in a response body rather than by a redirect this replay does not follow.",
			sessionTokenIdentity(tok))
		return finishRefreshProof(out, evidence)
	}

	out.AfterValue = value
	out.AfterFingerprint = NewCredential(value).Fingerprint()
	if out.AfterFingerprint == out.BeforeFingerprint {
		out.Code = RefreshProofSameCredential
		out.Detail = fmt.Sprintf(
			"The flow replayed and returned THE SAME credential (%s, %s). That proves the endpoint answers; it does not "+
				"prove the session can be renewed, so no proof was recorded and automatic renewal stays unavailable.",
			out.BeforeFingerprint, out.BeforeValue)
		return finishRefreshProof(out, evidence)
	}

	// TEST 2: does the target honour what came back? Asked BEFORE the stored value is replaced, so
	// a mint that returns a dead string leaves the operator's working credential alone.
	candidate := tok
	candidate.TokenValue = value
	candidate.ExpiresAt = DeriveSessionTokenExpiry(value, expires)
	status, detail, vEvidence := runSessionTokenValidation(candidate)
	out.ValidationStatus, out.ValidationDetail = status, detail
	for k, v := range vEvidence {
		evidence["validation_"+k] = v
	}
	if status != tokenStatusActive {
		out.Code = RefreshProofNotHonoured
		out.Detail = fmt.Sprintf(
			"A DIFFERENT credential came back (%s became %s: %s became %s), but the target did not honour it (%s), so a "+
				"refresh that produces a working session has NOT been shown. The stored value (%s) was left alone rather "+
				"than replaced with one nothing has seen work. A login DID happen, so if this application rotates the "+
				"session on login the stored value may have been invalidated by it: validate it before a long run. %s",
			out.BeforeFingerprint, out.AfterFingerprint, out.BeforeValue, out.AfterValue, status, out.BeforeValue, detail)
		return finishRefreshProof(out, evidence)
	}

	// The proof stands. Store the value that was observed working, then record it.
	if _, err := dbPool.Exec(ctx, `
		UPDATE session_tokens
		SET token_value = $1, expires_at = $2, last_refreshed_at = NOW(),
		    last_validation_status = $3, last_validation_detail = $4, last_validated_at = NOW(),
		    updated_at = NOW()
		WHERE id = $5`, value, candidate.ExpiresAt, status, detail, tok.ID); err != nil {
		// The refresh happened and was observed; only the write failed. Saying "proven" here would
		// arm a renewal against a credential the framework is not actually holding.
		out.Code = RefreshProofNotRecorded
		out.Detail = fmt.Sprintf(
			"A refresh was performed and a different working credential came back (%s became %s: %s became %s), but it "+
				"could not be stored, so the framework is still holding the old value and no proof was recorded: %s",
			out.BeforeFingerprint, out.AfterFingerprint, out.BeforeValue, out.AfterValue, truncateReason(err.Error()))
		return finishRefreshProof(out, evidence)
	}
	out.StoredNewValue = true

	// Companions come out of the same login response. A credential renewed while its routing cookie
	// still points at the backend the old session lived on is a session that authenticates nowhere.
	if names := refreshCompanionCookies(tok.ScopeTargetID, tok.ID, issuedCookies); len(names) > 0 {
		out.CompanionsRefreshed = names
		evidence["companions_refreshed"] = names
	}

	// The two credentials go into the proof row, not just their fingerprints. The proof IS that a
	// different working credential came back, and an operator reading the event later needs to see
	// which two: a fingerprint says they differed and shows neither.
	if err := RecordRefreshProof(ctx, tok.ID, out.BeforeFingerprint, out.AfterFingerprint,
		out.BeforeValue, out.AfterValue); err != nil {
		out.Code = RefreshProofNotRecorded
		out.Detail = fmt.Sprintf(
			"A refresh was performed and a different working credential came back (%s became %s: %s became %s) and was "+
				"stored, but the proof itself could not be written, so automatic renewal stays unavailable: %s",
			out.BeforeFingerprint, out.AfterFingerprint, out.BeforeValue, out.AfterValue, truncateReason(err.Error()))
		return finishRefreshProof(out, evidence)
	}

	out.Proven = true
	out.Code = RefreshProofProven
	out.Detail = fmt.Sprintf(
		"A refresh was performed: the flow was replayed, a DIFFERENT credential came back (%s became %s: %s became %s), "+
			"and the target answered differently with it than without it, so it is being honoured. That is the proof "+
			"automatic renewal requires, and it is now recorded.",
		out.BeforeFingerprint, out.AfterFingerprint, out.BeforeValue, out.AfterValue)
	// RecordRefreshProof has already written the kind=refresh status=success row, which IS the
	// proof. Writing a second one here would put two successes on the timeline for one refresh.
	out.Evidence = append(out.Evidence, "the target's answer with the new credential: "+detail)
	return out
}

// finishRefreshProof records the outcome on the credential's timeline and returns it.
//
// Attempted outcomes go in as kind=refresh so the renewal gate's "has a refresh failed since the
// proof" test can see them. Not-attempted ones go in as kind=refresh_proof so they cannot revoke a
// standing proof: declining to touch an out-of-scope host is not evidence that the mint broke.
func finishRefreshProof(out SessionRefreshProofResult, evidence ...map[string]interface{}) SessionRefreshProofResult {
	ev := map[string]interface{}{}
	if len(evidence) > 0 && evidence[0] != nil {
		ev = evidence[0]
	}
	ev["before_fingerprint"] = out.BeforeFingerprint
	if out.BeforeValue != "" {
		ev["before_value"] = out.BeforeValue
	}
	if out.AfterFingerprint != "" {
		ev["after_fingerprint"] = out.AfterFingerprint
	}
	if out.AfterValue != "" {
		ev["after_value"] = out.AfterValue
	}
	ev["mint_hosts"] = out.MintHosts
	ev["attempted"] = out.Attempted
	status := out.Code
	if !out.Attempted {
		status = "not_attempted"
		ev["not_attempted_because"] = out.Code
	}
	// session_token_events.status is VARCHAR(24) and an over-long one is not truncated by
	// Postgres, it is REFUSED: the whole row fails to insert and the operator's timeline silently
	// loses the event. Measured once already on this path, with "new_credential_not_honoured" at
	// 27 characters, and the only sign of it was a log line nobody was reading. The full code is
	// kept in the evidence so nothing is lost by the clamp.
	if len(status) > 24 {
		ev["status_code"] = status
		status = status[:24]
	}
	recordSessionTokenEvent(out.TokenID, out.eventKind(), status, out.Detail, ev)
	return out
}

// sessionRefreshTargets resolves every host the replay of one flow would send to.
//
// It is the whole scope check, and it reads the STEPS rather than only the flow's base_url,
// because the base URL is what an operator typed and the steps are what will actually be sent. A
// login flow that starts on the application and finishes at an identity provider has a base URL
// that says nothing about the second host.
//
// The empty host list is an error rather than an empty allow: a flow whose steps name no host at
// all is one whose destination cannot be established, and sending a request whose destination
// cannot be established is precisely what a scope boundary is for.
func sessionRefreshTargets(flowID string) (hosts []string, flowName string, refusal string) {
	baseURL, err := getFlowBaseURL(flowID)
	if err != nil {
		return nil, "", "The linked auth flow no longer exists, so there is nothing to replay."
	}
	if dbPool != nil {
		_ = dbPool.QueryRow(context.Background(),
			`SELECT COALESCE(name,'') FROM auth_flows WHERE id = $1`, flowID).Scan(&flowName)
	}
	steps, err := getStepsByFlow(flowID)
	if err != nil {
		return nil, flowName, "The linked auth flow's steps could not be read, so nothing was sent: " + truncateReason(err.Error())
	}
	if len(steps) == 0 {
		return nil, flowName, fmt.Sprintf(
			"The linked auth flow %q has no steps, so it documents the mint without being able to perform it. "+
				"Record the login once in the Auth Flows tab, then take the proof.", flowName)
	}

	seen := map[string]bool{}
	add := func(raw string) {
		if h := hostOfRawURL(raw); h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	add(baseURL)
	for _, s := range steps {
		// resolveBaseURL is the SAME function the replay uses to decide where each step goes, so
		// what is checked here is what will be sent rather than a second guess at it.
		add(resolveBaseURL(s.RawRequest, baseURL))
	}
	if len(hosts) == 0 {
		return nil, flowName, fmt.Sprintf(
			"The linked auth flow %q names no host in its base URL or in any of its %d step(s), so where a replay "+
				"would send cannot be established and nothing was sent.", flowName, len(steps))
	}
	return hosts, flowName, ""
}

// hostsOutsideScope returns the hosts the engagement does not allow, in the order given.
//
// It judges with AllowsForAuth, not Allows, because this is the REFRESH path: a host the operator
// classified as an auth host (an OAuth/SSO/token-mint host, reachable to renew a session but never
// scanned) is a legitimate destination for a refresh even though every scanner refuses it. Allows
// still governs scanning; this one extra admission is confined to the refresh gate.
//
// A NIL SCOPE IS OUTSIDE. LoadScanScope never returns nil for a real target, so a nil here means
// the boundary could not be constructed, and "we could not work out what is in scope" is not
// permission to send. This is the same fail-closed reading DetectRefreshCapability applies.
func hostsOutsideScope(scope *ScanScope, hosts []string) []string {
	out := []string{}
	for _, h := range hosts {
		if scope == nil || !scope.AllowsForAuth(h) {
			out = append(out, h)
		}
	}
	return out
}

// scopeDescribe renders the boundary for an evidence line, tolerating a nil scope.
func scopeDescribe(scope *ScanScope) string {
	if scope == nil {
		return "unknown: the engagement boundary could not be read, which is refused rather than treated as permission"
	}
	return scope.Describe()
}

// ---------------------------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------------------------

// ProveSessionRefreshHandler answers POST /session-tokens/{id}/prove-refresh.
//
// IT IS NOT THE EXISTING REFRESH BUTTON. POST /session-tokens/{id}/refresh replays whatever flow
// is linked, with no scope check, stores whatever comes back without asking the target about it,
// and records a kind=refresh status=refreshed event which is not a proof. This one refuses an
// out-of-scope mint before sending, validates what came back before storing it, and writes the
// proof the renewal gate reads. The two are kept separate rather than merged because the old
// button's contract is "get me a new value now" and this one's is "show me the mint works", and a
// button that silently changed what it does is worse than a second button.
//
// The status code is 200 for every outcome this endpoint can describe, including the refusals: a
// refusal is the measurement, and a 4xx would make the browser's error path swallow the sentence
// that says what would lift it. The codes that are genuinely a caller mistake keep their 4xx.
func ProveSessionRefreshHandler(w http.ResponseWriter, r *http.Request) {
	tokenID := sessionTokenIDFrom(r)
	if strings.TrimSpace(tokenID) == "" {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{
			"code": RefreshProofNoSuchToken, "detail": "No credential id in the path.",
		})
		return
	}
	result := ProveSessionRefresh(r.Context(), tokenID)
	switch result.Code {
	case RefreshProofNoSuchToken:
		writeSessionTokenJSON(w, http.StatusNotFound, result)
	case RefreshProofNoDatabase:
		writeSessionTokenJSON(w, http.StatusInternalServerError, result)
	default:
		writeSessionTokenJSON(w, http.StatusOK, result)
	}
}

// ---------------------------------------------------------------------------------------------
// RENEWING THE SESSION WHILE A SCAN IS RUNNING
// ---------------------------------------------------------------------------------------------
//
// WHY THIS IS HERE AND NOT IN THE SETTINGS FILE. TriageRenewalEffective is the one function a
// runner may ask "should I renew, and how often". Until this landed it had NO PRODUCTION CALLER:
// the operator could switch renewal on, the gate could arm it, the document stored it, and no scan
// ever renewed anything. Configurable and inert is worse than absent, because the screen says the
// session is being kept alive and the run is the thing that would have told you otherwise.
//
// WHAT RENEWING ACTUALLY MEANS HERE. It is the proof path, spent again: ProveSessionRefreshForTarget
// replays the recorded login, refuses an out-of-scope mint BEFORE sending, validates the minted
// credential against the target before storing it, and writes the event either way. So a renewal
// that produced a dead string leaves the run holding the credential that was last observed working,
// and the timeline says a login happened. Nothing else in this file is allowed to put a credential
// in the database without asking the target about it first, and neither is this.
//
// HOW A RENEWED CREDENTIAL REACHES THE WIRE. It is not handed to the runner. The triage runner's
// credential source re-reads session_tokens for a host on its own clock (triageFreshCredTTL, and
// sooner on a refusal or an approaching expiry), taking the active rows whose value is non-empty.
// So a renewal is visible to the run within that window with no coupling between the two, which is
// also why a credential that is NOT ACTIVE is refused below: the runner's own SQL would never read
// it, so renewing it would change nothing about the scan while the screen said renewal was on.
//
// IT IS FAIL CLOSED ON EVERY TICK, not only at the start. The gate is re-evaluated before each
// renewal, so a proof that breaks or ages out mid-run stops the schedule with a sentence, rather
// than a run that keeps replaying a login the gate would no longer allow.

// triageRenewalMinInterval is the shortest interval this driver will replay a login flow at.
//
// A renewal is a whole login: every step of the recorded flow, against the application and
// whatever identity provider it redirects to. Faster than once a minute that is an authentication
// burst against an engagement rather than a schedule, so the floor itself stays.
//
// IT CLAMPS RATHER THAN REFUSING, AND THAT IS A REVERSAL. It used to refuse, on the argument that
// a clamp invents a schedule the operator did not ask for and fires after the credential is
// already dead. Both halves of that were wrong about what the operator loses.
//
//	THE OPERATOR DID ASK FOR RENEWAL. What they did not choose is the interval: with no figure set
//	it is derived as half the measured lifetime, so on an application whose credential lives 45
//	seconds the schedule derives as 22s and the refusal took renewal away from precisely the
//	application that cannot finish a run without it. The setting said renewal was on, the gate
//	allowed it, and the run renewed nothing.
//
//	FIRING AFTER THE CREDENTIAL IS DEAD IS STILL WORTH DOING, because a renewal is a whole login
//	and does not depend on the credential it replaces. On a 45 second credential a one minute
//	schedule leaves 15 seconds of each cycle unauthenticated and re-authenticates the other 45.
//	Refusing leaves every second after the first 45 unauthenticated, for the whole run.
//
// What made the old refusal defensible was the second half of its own sentence: a run must not
// report that it renews while the schedule is worse than the operator thinks. So the clamp is
// SAID, in the decision, with the interval asked for, the floor, and, when the lifetime was
// measured, the exact window of every cycle that is spent holding an expired credential. A clamp
// nobody is told about would be the defect the refusal was avoiding; a clamp that states its own
// gap is a measurement.
const triageRenewalMinInterval = 60 * time.Second

// TriageRenewalBudget is the run's pacing budget, as much of it as a renewal needs.
//
// WHY THE RENEWAL PAYS AT ALL. A renewal login is a real request against the engagement. Until
// this seam existed the renewals went round the outside of the run's budget entirely: the operator
// set a rate, the run held itself to it, and a schedule alongside it spent logins nobody had
// counted and nothing had paced. On a 90 minute run against a five minute credential that is
// eighteen logins, each one a whole recorded flow.
//
// *HostBudget satisfies this already. It is an interface because a test cannot reproduce a token
// bucket by waiting for one.
type TriageRenewalBudget interface {
	// Wait blocks until this host's budget permits another request, or the context is done.
	Wait(ctx context.Context, host string) error
	// Aborted is the reason the run stopped sending, or empty.
	Aborted() string
}

// TriageRenewalRuntime is what the RUNNER lends the driver: its budget, and a way to tell its
// credential cache that the stored credential has just been replaced.
//
// Both are optional and both are nil in every path that has no run behind it (the settings screen
// taking a proof, a test pinning a decision). A nil one is not an error and is not silently
// treated as a zero: the record says which of them the run supplied.
type TriageRenewalRuntime struct {
	// Budget paces the renewal against the same per-host budget the run's probes use.
	Budget TriageRenewalBudget

	// Rotated is called the moment a renewal REPLACED the stored credential, and returns how many
	// of the run's cached host readings it revoked.
	//
	// WHY IT IS A CALLBACK AND NOT A WRITE. The runner re-reads session_tokens on its own clock
	// (triageFreshCredTTL, 30 seconds) and sooner on a refusal, so without this the FIRST REFUSED
	// REQUEST AFTER EVERY ROTATION is what picks the new credential up. Measured end to end: a
	// run that renewed twice paid a 401 at t+1m15s and another at t+2m15s, one per rotation, on a
	// credential with no readable expiry. The renewal knows exactly when it rotated, so the cost
	// is avoidable and the run is told rather than left to find out.
	Rotated func(before, after string) int
}

// TriageSessionRenewalAttempt is one renewal this driver performed, or one decision that stopped
// it performing any more. It holds a code, a sentence, and the credential pair the renewal
// compared: the fingerprints for the comparison and the values for the record.
type TriageSessionRenewalAttempt struct {
	At time.Time `json:"at"`
	// Attempted says whether anything was sent, carried through from the proof result. It is
	// separate from Proven for the reason it is separate there: a renewal refused for an
	// out-of-scope mint and a renewal that tried and failed are different facts, and only one of
	// them is a request against the engagement.
	Attempted bool   `json:"attempted"`
	Code      string `json:"code"`
	Proven    bool   `json:"proven"`
	Stored    bool   `json:"stored_new_value"`
	Before    string `json:"before_fingerprint"`
	After     string `json:"after_fingerprint"`
	// The two credentials those fingerprints stand for, as the renewal saw them.
	BeforeValue string `json:"before_value"`
	AfterValue  string `json:"after_value"`
	Detail      string `json:"detail"`
	Withdrawn   bool   `json:"withdrawn"`

	// WHAT THIS ONE COST, each figure read from the thing that did it rather than assumed.
	//
	// FlowSteps and FlowStepsFailed are the replay's own two numbers, carried through with their
	// meanings intact: see SessionRefreshProofResult, where FlowSteps is the LENGTH OF THE FLOW
	// and not a count of requests. BudgetSlots is how many per-host slots this attempt took from
	// the run's budget, which is one per mint host and zero when the run lent no budget.
	// HostsRevoked is how many cached host readings the rotation revoked, and it is zero both when
	// nothing rotated and when the run lent no cache; RotationTold tells those two apart.
	FlowSteps       int  `json:"flow_steps"`
	FlowStepsFailed int  `json:"flow_steps_failed"`
	BudgetSlots     int  `json:"budget_slots"`
	HostsRevoked    int  `json:"hosts_revoked"`
	RotationTold    bool `json:"rotation_told"`
}

// TriageRenewalCost is what a run spent on keeping its session alive, for the operator who has to
// account for every request this framework put on their target.
//
// LOGINS IS THE COUNT OF ATTEMPTS THAT REACHED THE WIRE, not of attempts: a renewal refused before
// anything was sent (an out-of-scope mint, a withdrawn gate) is not a request and is not counted as
// one. FlowSteps is the sum of the flow lengths those logins replayed, with the caveat that
// SessionRefreshProofResult.FlowSteps carries.
//
// THESE ARE NOT IN probes_sent AND MUST NOT BE ADDED TO IT. probes_sent is the classifier probe
// count, written by writeProgress from the runner's own ledger, and a login replay is not a probe:
// folding them together would make the one number that answers "how many probes did this run get
// through" answer something else. The standing rule is that a number named like a total has to be
// the total of the thing it is named for, which is why this is a second count and not an addition
// to the first.
type TriageRenewalCost struct {
	Logins          int `json:"logins"`
	FlowSteps       int `json:"flow_steps"`
	FlowStepsFailed int `json:"flow_steps_failed"`
	BudgetSlots     int `json:"budget_slots"`
	HostsRevoked    int `json:"hosts_revoked"`
	// Unpaced is how many of those logins went out with no run budget behind them, because the
	// caller lent none. It is the honest half of the pacing claim.
	Unpaced int `json:"unpaced_logins"`
}

// TriageSessionRenewalDriver keeps one run's session alive, or says why it is not doing so.
//
// Decision is a sentence on EVERY path, including the paths where nothing happens, because a run
// that decided not to renew and cannot say why produces a scan whose authentication silently died
// and a report that reads as a clean.
type TriageSessionRenewalDriver struct {
	ScopeTargetID string
	RunUUID       string

	// On says whether a schedule is actually running. Interval and TokenID are meaningful only
	// when it is true.
	On        bool
	TokenID   string
	TokenName string
	Interval  time.Duration
	Decision  string

	// Stopped says the schedule that WAS running has ended before the run did, and StoppedWhy is
	// the reason in the words of whatever ended it.
	//
	// THEY ARE FIELDS BECAUSE On IS NOT AN ANSWER TO THIS QUESTION. On is set when a schedule
	// starts and stays set: the gate is re-asked before every renewal and can withdraw the
	// permission, the run's pacing budget can abort, and the loop can crash, and after any of
	// those the record went on serving on:true for the rest of the run. A client rendering a badge
	// off On then shows renewal running over a run in which nothing has been renewed since minute
	// four. Summary says it in prose; a badge does not read prose.
	Stopped    bool
	StoppedWhy string

	// Clamped says the schedule running is the floor rather than the interval that was derived or
	// set, and DerivedInterval is what it would have been. Kept apart from Decision so a client
	// can render the clamp without parsing a sentence.
	Clamped         bool
	DerivedInterval time.Duration

	settings TriageInvestigateSettings

	// What the run lent this driver. Nil is normal and is recorded as such rather than as a zero.
	budget  TriageRenewalBudget
	rotated func(before, after string) int

	// The seams. Production fills them with the real gate and the real refresh; the tests fill
	// them with fakes, so what is pinned is this driver's own decisions rather than a network.
	evaluate    func(ctx context.Context, scopeTargetID string, pacing TriagePacing) TriageRenewalGate
	perform     func(ctx context.Context, scopeTargetID, tokenID string) SessionRefreshProofResult
	now         func() time.Time
	minInterval time.Duration

	mu       sync.Mutex
	attempts []TriageSessionRenewalAttempt
	cost     TriageRenewalCost

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// newTriageSessionRenewalDriver builds a driver with the production seams and starts nothing.
func newTriageSessionRenewalDriver(scopeTargetID, runUUID string, settings TriageInvestigateSettings) *TriageSessionRenewalDriver {
	return &TriageSessionRenewalDriver{
		ScopeTargetID: scopeTargetID,
		RunUUID:       runUUID,
		settings:      settings,
		evaluate:      TriageRenewalGateFor,
		perform:       ProveSessionRefreshForTarget,
		now:           func() time.Time { return time.Now().UTC() },
		minInterval:   triageRenewalMinInterval,
		attempts:      []TriageSessionRenewalAttempt{},
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
}

// StartTriageSessionRenewal is what a runner calls. It returns a driver on every path, so the
// caller never has to nil-check and always has a sentence to record.
//
//	renewal := StartTriageSessionRenewal(ctx, scopeTargetID, runUUID, settings)
//	defer renewal.Stop()
func StartTriageSessionRenewal(ctx context.Context, scopeTargetID, runUUID string, settings TriageInvestigateSettings) *TriageSessionRenewalDriver {
	return StartTriageSessionRenewalIn(ctx, scopeTargetID, runUUID, settings, TriageRenewalRuntime{})
}

// StartTriageSessionRenewalIn is the same thing with the run's budget and credential cache lent to
// it. A runner calls this one; the bare form above is for a caller that has neither.
func StartTriageSessionRenewalIn(ctx context.Context, scopeTargetID, runUUID string,
	settings TriageInvestigateSettings, runtime TriageRenewalRuntime) *TriageSessionRenewalDriver {

	d := newTriageSessionRenewalDriver(scopeTargetID, runUUID, settings)
	d.budget, d.rotated = runtime.Budget, runtime.Rotated
	return d.start(ctx)
}

// start makes the decision once and, where it is yes, runs the schedule until Stop or ctx.
func (d *TriageSessionRenewalDriver) start(ctx context.Context) *TriageSessionRenewalDriver {
	gate := d.evaluate(ctx, d.ScopeTargetID, d.settings.Pacing)
	on, interval, why := TriageRenewalEffective(d.settings, gate, d.now())
	d.Decision = why
	if !on {
		close(d.done)
		d.record(ctx)
		log.Printf("[TRIAGE-RENEWAL] %s: not renewing: %s", d.ScopeTargetID, why)
		return d
	}

	d.TokenID = strings.TrimSpace(d.settings.SessionRenewal.TokenID)
	o, haveOption := gate.Option(d.TokenID)
	if haveOption {
		d.TokenName = o.Name
		// THE RUNNER READS ACTIVE ROWS ONLY. Renewing a credential the run will never send is a
		// login flow spent on nothing, while the screen says the session is being kept alive.
		if !o.IsActive {
			d.Decision = fmt.Sprintf(
				"automatic session renewal is switched on for %s, which is not an active credential on this target. "+
					"The triage runner's credential source reads the ACTIVE session credentials only, so renewing this "+
					"row would not change what the scan sends. Activate it in the Session Manager, or point renewal at "+
					"the credential the scan is using.", o.Name)
			close(d.done)
			d.record(ctx)
			log.Printf("[TRIAGE-RENEWAL] %s: not renewing: %s", d.ScopeTargetID, d.Decision)
			return d
		}
	}

	interval, why = d.clampInterval(interval, why, o, haveOption)

	d.On, d.Interval, d.Decision = true, interval, why
	log.Printf("[TRIAGE-RENEWAL] %s: %s", d.ScopeTargetID, why)
	d.record(ctx)
	go d.loop(ctx)
	return d
}

// triageRenewalClampWhy is THE sentence about the floor, and there is one of it because there is
// one floor and TWO SHIPPED SURFACES that have to agree about what it does.
//
// The driver clamps; the settings validator used to hard-error on the same figure, so a document
// the driver would have run could not be saved and renewal was unreachable on exactly the
// applications whose credentials are too short to survive a run without it. Both surfaces now call
// this, so the words the operator reads at the point of configuration are the words the run says
// it is doing, character for character, and a test can assert that rather than trust it.
func triageRenewalClampWhy(asked, floor time.Duration) string {
	return fmt.Sprintf(
		"A renewal is a whole recorded login, and faster than the %s floor it is an authentication burst "+
			"against the engagement rather than a schedule, so the %s asked for is CLAMPED UP and renewal is "+
			"performed every %s instead.",
		humaniseTTL(floor), humaniseTTL(asked), humaniseTTL(floor))
}

// triageRenewalClampGap names the window of every cycle that is spent holding a credential which
// has already expired, and returns "" when there is no such window or the lifetime was never
// MEASURED. A clamp nobody is told about would be the defect the old refusal was avoiding; a clamp
// that states its own gap is a measurement.
func triageRenewalClampGap(floor time.Duration, o TriageRenewalOption, haveOption bool) string {
	if !haveOption || !o.TTLKnown || o.TTLSeconds <= 0 {
		return ""
	}
	ttl := time.Duration(o.TTLSeconds) * time.Second
	gap := floor - ttl
	if gap <= 0 {
		return ""
	}
	return fmt.Sprintf(
		" THE CREDENTIAL DOES NOT LIVE THAT LONG: its measured lifetime is %s, so about %s of every %s "+
			"cycle is spent holding a credential that has already expired and the run is unauthenticated "+
			"for that window. It renews anyway, because the alternative is being unauthenticated for "+
			"everything after the first %s of the run.",
		humaniseTTL(ttl), humaniseTTL(gap), humaniseTTL(floor), humaniseTTL(ttl))
}

// clampInterval holds the schedule to the floor and says so, in the decision, with both figures.
//
// THE SENTENCE IS THE POINT. See triageRenewalMinInterval for why this clamps rather than refuses:
// the only thing wrong with a clamp is a run that reports it renews while running a schedule the
// operator did not choose, and that is cured by saying which schedule is running and what it costs.
// The gap is only named where the lifetime was MEASURED; on an unmeasured one this says the clamp
// and nothing about a window it did not read.
func (d *TriageSessionRenewalDriver) clampInterval(interval time.Duration, why string,
	o TriageRenewalOption, haveOption bool) (time.Duration, string) {

	d.DerivedInterval = interval
	if interval >= d.minInterval {
		return interval, why
	}
	d.Clamped = true
	return d.minInterval, fmt.Sprintf("renewing every %s. %s The interval came from: %s.%s",
		humaniseTTL(d.minInterval), triageRenewalClampWhy(interval, d.minInterval), why,
		triageRenewalClampGap(d.minInterval, o, haveOption))
}

// loop waits out the interval and renews, re-asking the gate every time.
//
// A timer per iteration rather than a ticker, because the interval is re-derived on every tick:
// a credential whose measured lifetime changes mid-run changes the schedule with it, and a ticker
// would keep the figure it was built with.
func (d *TriageSessionRenewalDriver) loop(ctx context.Context) {
	defer close(d.done)
	// A renewal must never be able to kill the API. Same guard and the same reason as every other
	// bare goroutine in this package: Go takes the whole process down when one panics.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[TRIAGE-RENEWAL] PANIC while renewing the session for %s: %v", d.ScopeTargetID, rec)
			crashed := "The session renewal schedule crashed, so nothing has been renewed since. The run continued with whatever credential it was holding."
			d.Stopped, d.StoppedWhy = true, crashed
			d.appendAttempt(TriageSessionRenewalAttempt{
				At: d.now(), Code: "renewal_crashed", Withdrawn: true, Detail: crashed,
			})
		}
	}()
	for {
		timer := time.NewTimer(d.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-d.stop:
			timer.Stop()
			return
		case <-timer.C:
			if !d.renewOnce(ctx) {
				return
			}
		}
	}
}

// renewOnce re-asks the gate and then spends the refresh. It returns false when the schedule must
// stop: the gate withdrew it, and continuing would be renewing on a permission that is gone.
func (d *TriageSessionRenewalDriver) renewOnce(ctx context.Context) bool {
	gate := d.evaluate(ctx, d.ScopeTargetID, d.settings.Pacing)
	on, interval, why := TriageRenewalEffective(d.settings, gate, d.now())
	if !on {
		d.Decision = why
		d.Stopped, d.StoppedWhy = true, why
		d.appendAttempt(TriageSessionRenewalAttempt{At: d.now(), Code: "renewal_withdrawn", Withdrawn: true, Detail: why})
		log.Printf("[TRIAGE-RENEWAL] %s: stopping: %s", d.ScopeTargetID, why)
		d.record(ctx)
		return false
	}
	// The interval is re-derived on every tick, so a credential whose measured lifetime changes
	// mid-run changes the schedule with it. When it does, the DECISION changes with it too: the
	// run record has to describe the schedule that is running, clamp included, and not the one
	// this driver started with.
	o, haveOption := gate.Option(d.TokenID)
	if next, sentence := d.clampInterval(interval, why, o, haveOption); next != d.Interval {
		d.Interval, d.Decision = next, sentence
		log.Printf("[TRIAGE-RENEWAL] %s: the schedule changed: %s", d.ScopeTargetID, sentence)
	}

	// THE RUN STOPPED SENDING, SO THIS STOPS TOO. The pacing budget aborts when a host is failing
	// or the operator pulled the run up, and a schedule that kept replaying whole logins at a
	// target the run has already backed off from is the framework ignoring its own brake.
	if d.budget != nil {
		if aborted := d.budget.Aborted(); aborted != "" {
			d.Decision = "renewal stopped because the run's pacing budget aborted: " + aborted +
				". A renewal is a whole login against the same target the run has just stopped sending to."
			d.Stopped, d.StoppedWhy = true, d.Decision
			d.appendAttempt(TriageSessionRenewalAttempt{
				At: d.now(), Code: "renewal_stopped_pacing", Withdrawn: true, Detail: d.Decision,
			})
			log.Printf("[TRIAGE-RENEWAL] %s: stopping: %s", d.ScopeTargetID, d.Decision)
			d.record(ctx)
			return false
		}
	}

	res := d.perform(ctx, d.ScopeTargetID, d.TokenID)
	attempt := TriageSessionRenewalAttempt{
		At: res.At, Attempted: res.Attempted, Code: res.Code, Proven: res.Proven, Stored: res.StoredNewValue,
		Before: res.BeforeFingerprint, After: res.AfterFingerprint, Detail: res.Detail,
		BeforeValue: res.BeforeValue, AfterValue: res.AfterValue,
		FlowSteps: res.FlowSteps, FlowStepsFailed: res.FlowStepsFailed,
	}

	// THE CACHE IS TOLD, AND IT IS TOLD FIRST. The runner re-reads a host's credentials on a 30
	// second clock and on a refusal, so without this the next refused request is what picks the
	// rotation up, and that refusal is a request the operator paid for. Only res.StoredNewValue
	// branches here: it is set exactly where the UPDATE of session_tokens succeeded, so a renewal
	// that minted nothing, or minted something the target would not honour, changes no cached
	// reading because it changed no stored value.
	if res.StoredNewValue && d.rotated != nil {
		attempt.RotationTold = true
		attempt.HostsRevoked = d.rotated(res.BeforeFingerprint, res.AfterFingerprint)
	}

	// AND THE LOGIN IS PAID FOR, against the same per-host budget the run's probes use. One slot
	// per host the mint touched: that is what this file can measure, because the individual steps
	// of the flow are sent by replayFlowForToken, which takes no budget of its own. The figure
	// recorded is the number of slots actually taken, so an attempt that sent nothing pays nothing
	// and a run that lent no budget records zero rather than a claim.
	if res.Attempted {
		attempt.BudgetSlots = d.payForLogin(ctx, res.MintHosts)
	}
	d.noteCost(res, attempt)

	d.appendAttempt(attempt)
	// AND THE RUN ROW IS BROUGHT UP TO DATE, HERE, ON THE PATH WHERE SOMETHING HAPPENED.
	//
	// record used to run on three branches only: at start, on a withdrawal, and from Stop. A run
	// whose renewals all succeeded therefore left the row exactly as start wrote it, so for the
	// whole length of the run GetTriageRunStatus served "No login was replayed, so nothing about
	// the credential changed during this run" beside logins that had already gone to the target.
	// That is the question this record exists to answer, asked at the only time it can still be
	// acted on, and answered falsely. One UPDATE per renewal, which is at most one a minute.
	d.record(ctx)
	log.Printf("[TRIAGE-RENEWAL] %s: renewal of %s: %s (stored=%v, %s -> %s, %s -> %s, flow steps %d of which %d failed, %d budget slot(s), %d cached host reading(s) revoked)",
		d.ScopeTargetID, triageOrDefault(d.TokenName, d.TokenID), res.Code, res.StoredNewValue,
		triageOrDefault(res.BeforeFingerprint, "unknown"), triageOrDefault(res.AfterFingerprint, "nothing"),
		triageOrDefault(res.BeforeValue, "unknown"), triageOrDefault(res.AfterValue, "nothing"),
		attempt.FlowSteps, attempt.FlowStepsFailed, attempt.BudgetSlots, attempt.HostsRevoked)
	return true
}

// payForLogin takes one slot per mint host from the run's budget and returns how many it took.
//
// IT IS CHARGED AFTER THE LOGIN AND NOT BEFORE, because the hosts are read from what the replay
// reported it would touch rather than guessed ahead of it, and because a token bucket charged after
// the spend delays the run's NEXT probe by exactly what the login cost. The context is the one the
// caller is in, so a run being torn down cancels the wait instead of holding Stop open: a charge
// that could not be taken is recorded as not taken.
func (d *TriageSessionRenewalDriver) payForLogin(ctx context.Context, hosts []string) int {
	if d.budget == nil {
		return 0
	}
	// A charge must never hold Stop open. Stop waits for the renewal in flight on purpose, so the
	// login itself is left alone, but queueing behind a slow host budget after the work is done is
	// pure delay: the stop cancels the wait and the charge is recorded as not taken.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-d.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	paid := 0
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if err := d.budget.Wait(ctx, host); err != nil {
			log.Printf("[TRIAGE-RENEWAL] %s: the renewal login at %s was not charged to the run budget: %v",
				d.ScopeTargetID, host, err)
			continue
		}
		paid++
	}
	return paid
}

// Stop ends the schedule and waits for a renewal already in flight to finish.
//
// It WAITS on purpose. A login flow replay that outlived the run it was renewing for would be
// requests against the engagement with no run to account for them, and the operator watching the
// run finish would have no idea they were still going.
func (d *TriageSessionRenewalDriver) Stop() {
	d.stopOnce.Do(func() { close(d.stop) })
	<-d.done
	// The last word on the run row, so what renewal did survives the log buffer. context.Background
	// rather than the run's context: the run is finishing, and a cancelled write here would lose
	// the record of the renewals that did happen.
	d.record(context.Background())
}

// Attempts is every renewal and every withdrawal, in order. It is a copy, and it holds no value.
func (d *TriageSessionRenewalDriver) Attempts() []TriageSessionRenewalAttempt {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]TriageSessionRenewalAttempt{}, d.attempts...)
}

func (d *TriageSessionRenewalDriver) appendAttempt(a TriageSessionRenewalAttempt) {
	d.mu.Lock()
	d.attempts = append(d.attempts, a)
	d.mu.Unlock()
}

// noteCost adds one attempt to the run total. Only an attempt that REACHED THE WIRE counts as a
// login: res.Attempted is set at the one line in proveSessionRefresh that is past every refusal,
// so a renewal refused for an out-of-scope mint adds nothing to a count of requests.
func (d *TriageSessionRenewalDriver) noteCost(res SessionRefreshProofResult, a TriageSessionRenewalAttempt) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cost.HostsRevoked += a.HostsRevoked
	if !res.Attempted {
		return
	}
	d.cost.Logins++
	d.cost.FlowSteps += a.FlowSteps
	d.cost.FlowStepsFailed += a.FlowStepsFailed
	d.cost.BudgetSlots += a.BudgetSlots
	if d.budget == nil {
		d.cost.Unpaced++
	}
}

// Cost is what this run has spent on renewal so far. It is a copy, and it holds no value.
func (d *TriageSessionRenewalDriver) Cost() TriageRenewalCost {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cost
}

// Runtime is everything this driver knows about what renewal did on this run, in the shape that is
// written to the run row and served with the run status.
//
// IT CARRIES ITS OWN SUMMARY. The record was written for two rounds and nothing rendered it, and a
// client that has to compose a sentence from a decision, an attempt list and a cost will compose a
// different one in each client. The sentence is built here, next to the fields it reads.
func (d *TriageSessionRenewalDriver) Runtime() map[string]any {
	return map[string]any{
		"on":                       d.On,
		"token_id":                 d.TokenID,
		"token_name":               d.TokenName,
		"interval_seconds":         int64(d.Interval / time.Second),
		"derived_interval_seconds": int64(d.DerivedInterval / time.Second),
		"clamped":                  d.Clamped,
		"stopped":                  d.Stopped,
		"stopped_why":              d.StoppedWhy,
		"decision":                 d.Decision,
		"attempts":                 d.Attempts(),
		"cost":                     d.Cost(),
		"summary":                  d.Summary(),
	}
}

// Summary is the one sentence an operator reads to answer "was my scan authenticated the whole way
// through". EVERY CLAUSE IS COUNTED FROM THE ATTEMPT LIST, and it does not answer more than it can:
// a renewal that replaced the credential says so, and nothing here claims the run was authenticated
// at any moment, because no request in this file measured that.
func (d *TriageSessionRenewalDriver) Summary() string {
	if !d.On {
		return "This run did NOT renew its session, so it ran on the credential it started with for its whole length. " + d.Decision
	}
	// THE THREE OUTCOMES ARE COUNTED APART, because they are three different facts and adding
	// them up wrong is how a sentence stops matching its own numbers: a renewal REFUSED before
	// anything was sent (an out-of-scope mint) is not a login that failed, and counting it as one
	// would make the arithmetic in the sentence below disagree with cost.Logins.
	stored, failed, refused, withdrawn := 0, 0, 0, ""
	for _, a := range d.Attempts() {
		switch {
		case a.Withdrawn:
			withdrawn = a.Detail
		case !a.Attempted:
			refused++
		case a.Stored:
			stored++
		default:
			failed++
		}
	}
	cost := d.Cost()
	out := fmt.Sprintf("Renewal was scheduled every %s for %s. ", humaniseTTL(d.Interval),
		triageOrDefault(d.TokenName, d.TokenID))
	switch {
	case cost.Logins == 0:
		out += "No login was replayed, so nothing about the credential changed during this run."
	default:
		out += fmt.Sprintf("%d login replay(s) went to the target: %d replaced the stored credential and %d did not.",
			cost.Logins, stored, failed)
		if failed > 0 {
			// Only said when it happened. The stored value is left alone by a renewal that could
			// not produce a working one (see proveSessionRefresh), so this describes a real branch
			// rather than a hypothetical one.
			out += " After one that did not, the run carried on with the credential it was already holding."
		}
	}
	if refused > 0 {
		out += fmt.Sprintf(" A further %d renewal(s) were refused before anything was sent, so they are not requests against the target; the attempt list carries the reason for each.", refused)
	}
	if cost.Logins > 0 {
		out += fmt.Sprintf(" Those logins replayed %d flow step(s) in total (%d of which did not complete) and are NOT counted in probes_sent, which counts classifier probes.",
			cost.FlowSteps, cost.FlowStepsFailed)
		if cost.Unpaced > 0 {
			out += fmt.Sprintf(" %d of them went out with no run pacing budget behind them.", cost.Unpaced)
		}
	}
	if d.Clamped {
		out += " The schedule is the floor rather than the interval that was derived: " + d.Decision
	}
	if withdrawn != "" {
		out += " THE SCHEDULE THEN STOPPED: " + withdrawn + " Every request the run made after that carried whatever credential it was holding."
	}
	return out
}

// record writes what renewal did onto the run row, so it survives the log buffer and a page
// reload. A run that renewed and a run that could not are otherwise the same absence.
func (d *TriageSessionRenewalDriver) record(ctx context.Context) {
	if dbPool == nil || strings.TrimSpace(d.RunUUID) == "" {
		return
	}
	payload, err := json.Marshal(d.Runtime())
	if err != nil {
		return
	}
	if _, err := dbPool.Exec(ctx, `
		UPDATE triage_runs
		SET settings_snapshot = jsonb_set(COALESCE(settings_snapshot, '{}'::jsonb), '{session_renewal_runtime}', $2::jsonb, true)
		WHERE id = $1`, d.RunUUID, string(payload)); err != nil {
		log.Printf("[TRIAGE-RENEWAL] %s: the renewal decision could not be recorded on run %s: %v",
			d.ScopeTargetID, d.RunUUID, err)
	}
}
