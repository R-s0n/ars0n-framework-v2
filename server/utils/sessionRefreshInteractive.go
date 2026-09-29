package utils

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Interactive, resumable session refresh.
//
// The one-shot refresh in sessionTokens.go replays a linked auth flow end to end and lifts the new
// value out of the responses. That works for a login the framework can drive on its own. It cannot
// work for the logins most real targets use: an MFA step needs a code only the operator has, a
// password step may need a value that is not stored, and so on. The verdict for those is not "cannot
// be replayed" - it is "this step needs the user to supply X".
//
// So a refresh becomes a RESUMABLE RUN. The runner replays the automatable steps; when it reaches a
// step that needs a user-supplied value it PAUSES (status awaiting_input), reports exactly what it
// needs, and the operator (through the UI or MCP) supplies the value, which RESUMES the run from that
// step. The run is persisted, so a pause can last minutes and survive a restart.
//
// THE RESUME DOES NOT RE-RUN EARLIER STEPS. It rebuilds the cookie jar and the {{af:}} variable map
// from the ALREADY-STORED responses of the steps before the pause (the same seeding replayStepByID
// does), then continues. This matters: an MFA challenge issued by step one is consumed by step two,
// and re-running step one would issue a fresh challenge that the code the operator just typed no
// longer matches.
//
// Phase 1 handles interaction kinds "none" (replay verbatim) and "input" (pause and ask for a value).
// totp_auto, action (push / magic link) and browser hand-off are later phases; they validate here so
// a flow can be authored ahead of time, but the runner refuses to start a run that reaches one until
// its phase lands, rather than silently replaying it as if it were "none".

// ---------------------------------------------------------------------------
// Step interaction model
// ---------------------------------------------------------------------------

// StepInteraction is what a step needs from the user when the flow is refreshed. Stored on
// auth_flow_steps.interaction; {} (or kind "none") means the step is fully automatable.
type StepInteraction struct {
	// none | input   (future: totp_auto | action | browser)
	Kind string `json:"kind"`
	// The {{af:NAME}} this produces, so a later step's request can carry the supplied value. Required
	// for kind "input".
	VarName string `json:"var_name,omitempty"`
	// otp | totp | password | text | url | token. Purely a UI hint for how to render the input.
	InputKind string `json:"input_kind,omitempty"`
	// What to show the operator, e.g. "Enter the 6-digit code from your authenticator app".
	Prompt string `json:"prompt,omitempty"`
	// An optional input does not block the run when it is missing (the step is sent without it).
	Optional bool `json:"optional,omitempty"`
	// For kind "totp_auto": the operator's own TOTP shared secret (base32), from which the framework
	// generates the current code at refresh time so an authenticator-MFA login needs no pause. It is
	// the operator's own credential for their own account, stored like any other captured secret.
	TOTPSecret string `json:"totp_secret,omitempty"`
	// For kind "action": which out-of-band action the operator performs. "approve" is a push/2FA
	// approval - refresh pauses, the operator approves on their device and clicks Continue, then the
	// step's request (the status check that now succeeds) is sent. "magic_link" - refresh pauses, the
	// operator clicks the emailed link and pastes the URL they land on, which is substituted as
	// {{af:var_name}} into the step's request.
	ActionKind string `json:"action_kind,omitempty"`
}

// The interaction kinds this build understands. none/input are handled by the runner; the rest are
// accepted at save time (so a flow can be authored) but a run that reaches one is failed with a clear
// "not supported yet" rather than mis-replayed.
var interactionKinds = map[string]bool{
	"none": true, "input": true, "totp_auto": true, "action": true, "browser": true,
}

// The kinds the runner can actually execute today.
var interactionKindsRunnable = map[string]bool{"none": true, "input": true, "totp_auto": true, "action": true}

var interactionActionKinds = map[string]bool{"approve": true, "magic_link": true}

var interactionInputKinds = map[string]bool{
	"otp": true, "totp": true, "password": true, "text": true, "url": true, "token": true,
}

var interactionVarNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

func (si *StepInteraction) isNone() bool {
	return si == nil || strings.TrimSpace(si.Kind) == "" || strings.EqualFold(si.Kind, "none")
}

func (si *StepInteraction) needsInput() bool {
	return si != nil && strings.EqualFold(strings.TrimSpace(si.Kind), "input")
}

func (si *StepInteraction) isTOTPAuto() bool {
	return si != nil && strings.EqualFold(strings.TrimSpace(si.Kind), "totp_auto")
}

// cleanBase32Secret normalises a TOTP shared secret the way authenticator apps present it: upper-case,
// spaces removed, padding dropped. Returns the decoded key.
func cleanBase32Secret(secret string) ([]byte, error) {
	clean := strings.ToUpper(strings.TrimSpace(secret))
	clean = strings.NewReplacer(" ", "", "-", "", "=", "").Replace(clean)
	if clean == "" {
		return nil, fmt.Errorf("empty secret")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
}

// hotp is the RFC 4226 truncation (HMAC-SHA1, 6 digits) over an 8-byte counter. TOTP is HOTP with the
// counter set to the time step, so this is the testable core (checked against the RFC 4226 vectors).
func hotp(key []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])) % 1000000
	return fmt.Sprintf("%06d", code)
}

// generateTOTP computes the current RFC 6238 code (HMAC-SHA1, 30s step, 6 digits) for a base32 secret.
func generateTOTP(secret string) (string, error) {
	key, err := cleanBase32Secret(secret)
	if err != nil {
		return "", fmt.Errorf("the TOTP secret is not valid base32: %w", err)
	}
	return hotp(key, uint64(time.Now().Unix())/30), nil
}

// validateStepInteraction rejects an interaction that cannot work, at save time, so the operator is
// told while they are still looking at the step rather than at refresh time.
func validateStepInteraction(si *StepInteraction) string {
	if si.isNone() {
		return ""
	}
	kind := strings.ToLower(strings.TrimSpace(si.Kind))
	if !interactionKinds[kind] {
		return fmt.Sprintf("%q is not an interaction kind; use none, input or totp_auto", si.Kind)
	}
	if kind == "input" {
		if !interactionVarNamePattern.MatchString(strings.TrimSpace(si.VarName)) {
			return "an input interaction needs a var_name of letters, digits and underscore, which " +
				"a later step refers to as {{af:NAME}}"
		}
		if strings.TrimSpace(si.Prompt) == "" {
			return "an input interaction needs a prompt telling the operator what to enter"
		}
		if k := strings.ToLower(strings.TrimSpace(si.InputKind)); k != "" && !interactionInputKinds[k] {
			return fmt.Sprintf("%q is not an input_kind; use otp, totp, password, text, url or token", si.InputKind)
		}
	}
	if kind == "totp_auto" {
		if !interactionVarNamePattern.MatchString(strings.TrimSpace(si.VarName)) {
			return "a totp_auto interaction needs a var_name (letters, digits, underscore) which a " +
				"step refers to as {{af:NAME}} for the generated code"
		}
		if _, err := cleanBase32Secret(si.TOTPSecret); err != nil {
			return "a totp_auto interaction needs a valid base32 TOTP secret to generate the code from"
		}
	}
	if kind == "action" {
		ak := strings.ToLower(strings.TrimSpace(si.ActionKind))
		if !interactionActionKinds[ak] {
			return fmt.Sprintf("%q is not an action_kind; use approve or magic_link", si.ActionKind)
		}
		if strings.TrimSpace(si.Prompt) == "" {
			return "an action interaction needs a prompt telling the operator what to do"
		}
		if ak == "magic_link" && !interactionVarNamePattern.MatchString(strings.TrimSpace(si.VarName)) {
			return "a magic_link action needs a var_name for the URL the operator pastes, referred to " +
				"in the step's request as {{af:NAME}}"
		}
	}
	return ""
}

// normalizeStepInteractionJSON validates and renders an interaction for storage. A nil or none
// interaction stores {} so a step with nothing to ask reads back as automatable. Returns the JSON to
// store and a problem string (empty when valid).
func normalizeStepInteractionJSON(si *StepInteraction) ([]byte, string) {
	if si.isNone() {
		return []byte("{}"), ""
	}
	if problem := validateStepInteraction(si); problem != "" {
		return nil, problem
	}
	out := StepInteraction{
		Kind:       strings.ToLower(strings.TrimSpace(si.Kind)),
		VarName:    strings.TrimSpace(si.VarName),
		InputKind:  strings.ToLower(strings.TrimSpace(si.InputKind)),
		Prompt:     strings.TrimSpace(si.Prompt),
		Optional:   si.Optional,
		TOTPSecret: strings.TrimSpace(si.TOTPSecret),
		ActionKind: strings.ToLower(strings.TrimSpace(si.ActionKind)),
	}
	if out.Kind == "totp_auto" {
		out.InputKind = "totp"
	} else if out.Kind == "action" && out.ActionKind == "magic_link" {
		out.InputKind = "url"
	} else if out.InputKind == "" {
		out.InputKind = "text"
	}
	j, err := json.Marshal(out)
	if err != nil {
		return nil, "the interaction could not be encoded: " + err.Error()
	}
	return j, ""
}

// reStepCodeParam matches the request-side name of a one-time code, so a step that submits one can be
// suggested as needing input without the operator having to know it. Matched against get/post
// parameter names in the raw request.
var reStepCodeParam = regexp.MustCompile(`(?i)\b(otp|totp|mfa|twofa|2fa|one[_-]?time|passcode|verification[_-]?code|auth[_-]?code|security[_-]?code|code)\b`)

// DetectStepInteraction suggests an interaction for a step that looks like it submits a user-supplied
// code, so the UI can offer to set it. Conservative: it only fires on a request whose body or query
// carries a parameter named like a one-time code, which is the step that actually needs the input.
// Returns nil when nothing looks interactive.
func DetectStepInteraction(step AuthFlowStep) *StepInteraction {
	raw := step.RawRequest
	_, _, body := splitRawRequestHeadBody(raw)
	// Look in the body and the request-line query for a code-shaped parameter name=...
	haystack := body
	if i := strings.IndexAny(raw, "\r\n"); i > 0 {
		haystack += "\n" + raw[:i] // include the request line (carries the query string)
	}
	// name=value or "name": patterns
	for _, m := range regexp.MustCompile(`(?i)["&?]?([A-Za-z0-9_.-]{2,40})\s*["]?\s*[:=]`).FindAllStringSubmatch(haystack, -1) {
		name := m[1]
		if reStepCodeParam.MatchString(name) {
			return &StepInteraction{
				Kind:      "input",
				VarName:   "mfa_code",
				InputKind: "otp",
				Prompt:    "Enter the code this step submits (e.g. the 6-digit code from your authenticator or the one texted/emailed to you).",
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Flow refreshability classification
// ---------------------------------------------------------------------------

// reBrowserChallenge matches a response body that is a bot-management or CAPTCHA challenge, i.e. a
// step that only a real browser can clear. reIdPHost matches the login host of a federated identity
// provider, whose interactive login a headless replay cannot perform. reSingleUse matches a recorded
// value that is single-use by construction (an OAuth code/state, a magic-link token, or an authored
// placeholder), so replaying the recording sends a dead value.
var reBrowserChallenge = regexp.MustCompile(`(?i)(turnstile|recaptcha|hcaptcha|g-recaptcha|cf-chl|cf_chl|challenge-platform|just a moment|checking your browser|attention required|verify you are human)`)
var reIdPHost = regexp.MustCompile(`(?i)(accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com|\.okta\.com|\.auth0\.com|\.onelogin\.com|\.pingidentity\.com|github\.com/login|facebook\.com/(dialog|login)|appleid\.apple\.com)`)
var reSingleUse = regexp.MustCompile(`(?i)(SINGLE_USE_CODE|REDACTED_OPAQUE|[?&]code=[A-Za-z0-9._-]{6,}|[?&]state=[A-Za-z0-9._-]{8,})`)

// ClassifyFlowRefreshability decides how a linked flow can be refreshed, so the UI can route the
// operator to the right action instead of letting them link-and-fail. kind is one of:
//
//	replay        every step is automatable; a plain refresh works.
//	interactive   at least one step needs a user-supplied value (an MFA/OTP code); refresh pauses.
//	browser_only  the flow crosses a CAPTCHA / bot-management / federated IdP, or carries single-use
//	              values, so a headless replay cannot renew it. Refresh by re-capturing in the browser
//	              (Phase 4) or, for now, by pasting a fresh value.
//
// note is the operator-facing sentence; reasons carries the specific signals seen.
// The three refreshability kinds ClassifyFlowRefreshability returns. Named so autoRefreshDue and the
// MCP/UI layers agree on the exact strings rather than each spelling "browser_only" by hand.
const (
	flowRefreshReplay      = "replay"
	flowRefreshInteractive = "interactive"
	flowRefreshBrowserOnly = "browser_only"
)

func ClassifyFlowRefreshability(steps []AuthFlowStep) (kind, note string, reasons []string) {
	interactive := false
	for _, s := range steps {
		if s.Interaction.needsInput() || (!s.Interaction.isNone() && strings.EqualFold(strings.TrimSpace(s.Interaction.Kind), "action")) {
			interactive = true
		}
		// A step whose interaction the runner cannot execute (today "browser", and any future
		// non-runnable kind) can only be completed in a real browser, so the whole flow is
		// browser-only. This MUST mirror interactionKindsRunnable: it is the gate the unattended
		// auto-refresh loop trusts. Without it a browser hand-off flow classifies as "replay", the
		// loop fires on it, and the runner sends every earlier (credential-bearing) step to the live
		// target before it reaches the hand-off step and refuses it. executeSessionRefreshRun refuses
		// such a step, but only AFTER the prior steps have already gone out.
		if !s.Interaction.isNone() {
			k := strings.ToLower(strings.TrimSpace(s.Interaction.Kind))
			if !interactionKindsRunnable[k] {
				reasons = append(reasons, "step "+fmt.Sprint(s.StepOrder)+" needs a browser hand-off ("+k+") that cannot be replayed headlessly")
			}
		}
		host := requestFlowStepHost(s.RawRequest, "")
		if host != "" && reIdPHost.MatchString(host) {
			reasons = append(reasons, "step "+fmt.Sprint(s.StepOrder)+" logs in at a federated identity provider ("+host+")")
		}
		if reBrowserChallenge.MatchString(s.ResponseBody) {
			reasons = append(reasons, "step "+fmt.Sprint(s.StepOrder)+"'s response is a CAPTCHA / bot-management challenge")
		}
		if s.ResponseStatus != nil && *s.ResponseStatus == http.StatusForbidden && reBrowserChallenge.MatchString(s.ResponseBody) {
			reasons = append(reasons, "step "+fmt.Sprint(s.StepOrder)+" was blocked by a 403 challenge")
		}
		if reSingleUse.MatchString(s.RawRequest) {
			reasons = append(reasons, "step "+fmt.Sprint(s.StepOrder)+" carries a single-use value (an OAuth code/state or a placeholder) that is dead on replay")
		}
	}
	if len(reasons) > 0 {
		return flowRefreshBrowserOnly,
			"This flow cannot be renewed by a headless replay: " + strings.Join(reasons, "; ") +
				". Refresh it by re-capturing the session in the browser, or by pasting a fresh value.",
			reasons
	}
	if interactive {
		return flowRefreshInteractive,
			"This flow needs a value from you when it runs (an MFA/OTP code); refresh will pause and ask.",
			reasons
	}
	return flowRefreshReplay, "This flow can be refreshed automatically.", reasons
}

// detectFlowProvider names the identity provider or bot-management a flow crosses, for a precise label
// ("federated via Google", "Cloudflare Turnstile") rather than a generic "browser-only". "" when none
// is recognised.
func detectFlowProvider(steps []AuthFlowStep) string {
	hosts := map[string]string{
		"accounts.google.com": "Google", "login.microsoftonline.com": "Microsoft",
		"login.live.com": "Microsoft", "appleid.apple.com": "Apple",
		".okta.com": "Okta", ".auth0.com": "Auth0", ".onelogin.com": "OneLogin",
		".pingidentity.com": "Ping Identity", "github.com/login": "GitHub",
	}
	for _, s := range steps {
		h := strings.ToLower(requestFlowStepHost(s.RawRequest, ""))
		for needle, name := range hosts {
			if strings.Contains(h, needle) || strings.Contains(strings.ToLower(s.RawRequest), needle) {
				return name
			}
		}
		body := strings.ToLower(s.ResponseBody)
		switch {
		case strings.Contains(body, "turnstile"):
			return "Cloudflare Turnstile"
		case strings.Contains(body, "cf-chl") || strings.Contains(body, "challenge-platform") || strings.Contains(body, "just a moment"):
			return "Cloudflare"
		case strings.Contains(body, "recaptcha") || strings.Contains(body, "g-recaptcha"):
			return "Google reCAPTCHA"
		case strings.Contains(body, "hcaptcha"):
			return "hCaptcha"
		}
	}
	return ""
}

// GetFlowRefreshClassification handles GET /auth-flows/flow/{flow_id}/refresh-classification.
func GetFlowRefreshClassification(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	flowID := mux.Vars(r)["flow_id"]
	steps, err := getStepsByFlow(flowID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "could not read the flow's steps")
		return
	}
	kind, note, reasons := ClassifyFlowRefreshability(steps)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"kind": kind, "note": note, "reasons": reasons,
		"provider": detectFlowProvider(steps), "step_count": len(steps),
	})
}

// ---------------------------------------------------------------------------
// Run persistence
// ---------------------------------------------------------------------------

const (
	refreshRunRunning   = "running"
	refreshRunAwaiting  = "awaiting_input"
	refreshRunCompleted = "completed"
	refreshRunFailed    = "failed"
	refreshRunCancelled = "cancelled"
)

// RefreshInputRequest describes exactly what the paused run is waiting for.
type RefreshInputRequest struct {
	StepID    string `json:"step_id"`
	StepOrder int    `json:"step_order"`
	StepName  string `json:"step_name,omitempty"`
	VarName   string `json:"var_name"`
	InputKind string `json:"input_kind"`
	Prompt    string `json:"prompt"`
	// For an "action" pause: which action, and whether it needs a value. A push "approve" needs no
	// value (the operator approves on their device and clicks Continue); a "magic_link" needs the URL.
	ActionKind string `json:"action_kind,omitempty"`
	NoValue    bool   `json:"no_value,omitempty"`
}

// refreshStepPause returns the input the step is waiting for given the current vars and the values the
// operator has already provided, or nil when the step can run without pausing. It is the one place the
// pause decision lives, so the runner, the resume check and the UI cannot disagree.
func refreshStepPause(step AuthFlowStep, vars, provided map[string]string) *RefreshInputRequest {
	inter := step.Interaction
	if inter == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(inter.Kind)) {
	case "input":
		if inter.Optional || strings.TrimSpace(vars[inter.VarName]) != "" {
			return nil
		}
		return &RefreshInputRequest{StepID: step.ID, StepOrder: step.StepOrder, StepName: step.Name,
			VarName: inter.VarName, InputKind: inter.InputKind, Prompt: inter.Prompt}
	case "action":
		if strings.EqualFold(strings.TrimSpace(inter.ActionKind), "magic_link") {
			if strings.TrimSpace(vars[inter.VarName]) != "" {
				return nil
			}
			return &RefreshInputRequest{StepID: step.ID, StepOrder: step.StepOrder, StepName: step.Name,
				VarName: inter.VarName, InputKind: "url", ActionKind: "magic_link", Prompt: inter.Prompt}
		}
		// approve: a no-value continue, tracked by a synthetic provided key so it resolves once.
		key := "__continue:" + step.ID
		if provided[key] != "" {
			return nil
		}
		return &RefreshInputRequest{StepID: step.ID, StepOrder: step.StepOrder, StepName: step.Name,
			VarName: key, ActionKind: "approve", NoValue: true, Prompt: inter.Prompt}
	}
	return nil
}

// SessionRefreshRun is one interactive refresh, persisted so a pause survives across HTTP calls and a
// process restart.
type SessionRefreshRun struct {
	ID            string `json:"id"`
	TokenID       string `json:"token_id"`
	ScopeTargetID string `json:"scope_target_id"`
	AuthFlowID    string `json:"auth_flow_id"`
	Status        string `json:"status"`
	// CompletedSteps is how many leading steps have already run and been stored. The runner resumes at
	// steps[CompletedSteps] and never re-runs the ones before it.
	CompletedSteps int                  `json:"completed_steps"`
	InputRequest   *RefreshInputRequest `json:"input_request,omitempty"`
	Provided       map[string]string    `json:"provided"`
	// The accumulated state at the last pause, persisted so a resume continues from the EXACT values
	// the live run had rather than re-deriving them from the sanitized stored responses (which strip
	// NUL / invalid UTF-8 and can change a captured value). Captured is the {{af:}} vars, SetCookies
	// and Bodies feed the final token extraction. The cookie jar is still re-seeded from the stored
	// response headers, which go through json.Marshal and are not sanitized, so they cannot drift.
	Captured      map[string]string `json:"-"`
	SetCookies    []string          `json:"-"`
	Bodies        []string          `json:"-"`
	OutcomeStatus string            `json:"outcome_status,omitempty"`
	OutcomeDetail string            `json:"outcome_detail,omitempty"`
	NewValueSet   bool              `json:"new_value_set"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

var sessionRefreshRunsSchemaOnce sync.Once

func ensureSessionRefreshRunsSchema() {
	sessionRefreshRunsSchemaOnce.Do(func() {
		if _, err := dbPool.Exec(context.Background(), `
			CREATE TABLE IF NOT EXISTS session_refresh_runs (
				id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				token_id UUID NOT NULL REFERENCES session_tokens(id) ON DELETE CASCADE,
				scope_target_id UUID NOT NULL,
				auth_flow_id UUID,
				status VARCHAR(24) NOT NULL DEFAULT 'running',
				completed_steps INTEGER NOT NULL DEFAULT 0,
				input_request JSONB,
				provided JSONB NOT NULL DEFAULT '{}'::jsonb,
				outcome_status VARCHAR(32) NOT NULL DEFAULT '',
				outcome_detail TEXT NOT NULL DEFAULT '',
				new_value_set BOOLEAN NOT NULL DEFAULT FALSE,
				captured JSONB NOT NULL DEFAULT '{}'::jsonb,
				set_cookies JSONB NOT NULL DEFAULT '[]'::jsonb,
				bodies JSONB NOT NULL DEFAULT '[]'::jsonb,
				created_at TIMESTAMP NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMP NOT NULL DEFAULT NOW()
			)`); err != nil {
			log.Printf("[SESSION-REFRESH] Could not ensure session_refresh_runs schema: %v", err)
		}
		// Added after the table shipped, so an existing install needs them; IF NOT EXISTS keeps this a
		// no-op afterwards.
		for _, stmt := range []string{
			`ALTER TABLE session_refresh_runs ADD COLUMN IF NOT EXISTS captured JSONB NOT NULL DEFAULT '{}'::jsonb`,
			`ALTER TABLE session_refresh_runs ADD COLUMN IF NOT EXISTS set_cookies JSONB NOT NULL DEFAULT '[]'::jsonb`,
			`ALTER TABLE session_refresh_runs ADD COLUMN IF NOT EXISTS bodies JSONB NOT NULL DEFAULT '[]'::jsonb`,
		} {
			if _, err := dbPool.Exec(context.Background(), stmt); err != nil {
				log.Printf("[SESSION-REFRESH] Could not add session_refresh_runs column: %v", err)
			}
		}
		if _, err := dbPool.Exec(context.Background(),
			`CREATE INDEX IF NOT EXISTS idx_session_refresh_runs_token
			   ON session_refresh_runs(token_id, created_at DESC)`); err != nil {
			log.Printf("[SESSION-REFRESH] Could not ensure session_refresh_runs index: %v", err)
		}
	})
}

func insertSessionRefreshRun(run *SessionRefreshRun) error {
	ensureSessionRefreshRunsSchema()
	provided, _ := json.Marshal(orEmptyStringMap(run.Provided))
	return dbPool.QueryRow(context.Background(), `
		INSERT INTO session_refresh_runs (token_id, scope_target_id, auth_flow_id, status, completed_steps, provided)
		VALUES ($1, $2, NULLIF($3,'')::uuid, $4, $5, $6)
		RETURNING id, created_at, updated_at`,
		run.TokenID, run.ScopeTargetID, run.AuthFlowID, run.Status, run.CompletedSteps, provided).
		Scan(&run.ID, &run.CreatedAt, &run.UpdatedAt)
}

func saveSessionRefreshRun(run *SessionRefreshRun) error {
	ensureSessionRefreshRunsSchema()
	var inputReq interface{}
	if run.InputRequest != nil {
		b, _ := json.Marshal(run.InputRequest)
		inputReq = b
	}
	provided, _ := json.Marshal(orEmptyStringMap(run.Provided))
	captured, _ := json.Marshal(orEmptyStringMap(run.Captured))
	setCookies, _ := json.Marshal(orEmptyStringSlice(run.SetCookies))
	bodies, _ := json.Marshal(orEmptyStringSlice(run.Bodies))
	_, err := dbPool.Exec(context.Background(), `
		UPDATE session_refresh_runs
		SET status = $1, completed_steps = $2, input_request = $3, provided = $4,
		    outcome_status = $5, outcome_detail = $6, new_value_set = $7,
		    captured = $8, set_cookies = $9, bodies = $10, updated_at = NOW()
		WHERE id = $11`,
		run.Status, run.CompletedSteps, inputReq, provided,
		run.OutcomeStatus, run.OutcomeDetail, run.NewValueSet,
		captured, setCookies, bodies, run.ID)
	return err
}

func orEmptyStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func loadSessionRefreshRun(runID string) (*SessionRefreshRun, error) {
	ensureSessionRefreshRunsSchema()
	var run SessionRefreshRun
	var authFlowID *string
	var inputReq []byte
	var provided, captured, setCookies, bodies []byte
	err := dbPool.QueryRow(context.Background(), `
		SELECT id::text, token_id::text, scope_target_id::text, auth_flow_id::text, status,
		       completed_steps, input_request, COALESCE(provided,'{}'::jsonb),
		       COALESCE(captured,'{}'::jsonb), COALESCE(set_cookies,'[]'::jsonb), COALESCE(bodies,'[]'::jsonb),
		       outcome_status, outcome_detail, new_value_set, created_at, updated_at
		FROM session_refresh_runs WHERE id = $1`, runID).Scan(
		&run.ID, &run.TokenID, &run.ScopeTargetID, &authFlowID, &run.Status,
		&run.CompletedSteps, &inputReq, &provided, &captured, &setCookies, &bodies,
		&run.OutcomeStatus, &run.OutcomeDetail, &run.NewValueSet, &run.CreatedAt, &run.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if authFlowID != nil {
		run.AuthFlowID = *authFlowID
	}
	if len(inputReq) > 0 {
		var ir RefreshInputRequest
		if json.Unmarshal(inputReq, &ir) == nil {
			run.InputRequest = &ir
		}
	}
	run.Provided = map[string]string{}
	if len(provided) > 0 {
		_ = json.Unmarshal(provided, &run.Provided)
	}
	run.Captured = map[string]string{}
	if len(captured) > 0 {
		_ = json.Unmarshal(captured, &run.Captured)
	}
	if len(setCookies) > 0 {
		_ = json.Unmarshal(setCookies, &run.SetCookies)
	}
	if len(bodies) > 0 {
		_ = json.Unmarshal(bodies, &run.Bodies)
	}
	return &run, nil
}

// Per-token serialization. A refresh run replays a whole flow, writes each step's response back onto
// the shared auth_flow_steps rows, and holds a live server-side session across a pause; two runs for
// the same token at once would race those writes and could double-submit an MFA step. The whole
// start-and-execute and resume-and-execute are held under a per-token lock so, for one api process
// (the deployment), only one runs at a time. A second concurrent /refresh serialises behind the
// first; a second concurrent /input finds the run no longer awaiting and is rejected.
var (
	refreshTokenLocksMu sync.Mutex
	refreshTokenLocks   = map[string]*sync.Mutex{}
)

func lockTokenRefresh(tokenID string) func() {
	refreshTokenLocksMu.Lock()
	m, ok := refreshTokenLocks[tokenID]
	if !ok {
		m = &sync.Mutex{}
		refreshTokenLocks[tokenID] = m
	}
	refreshTokenLocksMu.Unlock()
	m.Lock()
	return m.Unlock
}

// cancelActiveRefreshRunsForToken marks any running or awaiting run on a token as cancelled, so a
// fresh refresh starts clean and there is only ever one active run per token.
func cancelActiveRefreshRunsForToken(tokenID string) {
	ensureSessionRefreshRunsSchema()
	if _, err := dbPool.Exec(context.Background(), `
		UPDATE session_refresh_runs SET status = 'cancelled', updated_at = NOW()
		WHERE token_id = $1 AND status IN ('running','awaiting_input')`, tokenID); err != nil {
		log.Printf("[SESSION-REFRESH] Could not cancel prior runs for token %s: %v", tokenID, err)
	}
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

// startSessionRefreshRun creates a run for a token whose flow may need user input, and executes it up
// to the first pause or to completion.
func startSessionRefreshRun(token SessionToken) (*SessionRefreshRun, error) {
	unlock := lockTokenRefresh(token.ID)
	defer unlock()
	cancelActiveRefreshRunsForToken(token.ID)
	run := &SessionRefreshRun{
		TokenID:       token.ID,
		ScopeTargetID: token.ScopeTargetID,
		// The REFRESH flow first: it is the headless "what the app does to stay logged in" flow (an OAuth
		// refresh grant), which the auth_flow (the interactive, usually browser_only CREATION flow) is
		// not. Fall back to the creation flow when no refresh flow is linked (today's behaviour).
		AuthFlowID: refreshFlowIDFor(token),
		Status:     refreshRunRunning,
		Provided:   map[string]string{},
	}
	if err := insertSessionRefreshRun(run); err != nil {
		return nil, err
	}
	executeSessionRefreshRun(run, token)
	return run, nil
}

// refreshFlowIDFor picks which flow a refresh replays: the dedicated headless refresh_flow_id when set,
// otherwise the auth_flow_id (the creation flow). "" when neither is linked.
func refreshFlowIDFor(token SessionToken) string {
	if strings.TrimSpace(token.RefreshFlowID) != "" {
		return token.RefreshFlowID
	}
	return token.AuthFlowID
}

// resumeSessionRefreshRun records the operator's value for the step the run paused on and continues.
// expectStepID, when non-empty, is the step the CALLER believes it is answering (echoed back from the
// input_request it was shown). It guards against a stale or duplicate submission: the lock serialises
// start and resume, so a second /input that was meant for an earlier pause can arrive after the run has
// already resolved that pause and advanced to a DIFFERENT one. Without the check the second value would
// be written under the new pause's var - silently satisfying a push-approve continue or storing an OTP
// under the wrong variable. With it, the mismatch is rejected and the operator answers the real prompt.
func resumeSessionRefreshRun(runID, value, expectStepID string) (*SessionRefreshRun, error) {
	// Load once to learn the token, then take the per-token lock and RE-LOAD under it, so the
	// "is this run still awaiting?" check is a compare-and-set: two concurrent /input posts cannot both
	// pass it and double-submit the step. The lock is the same one start uses.
	run, err := loadSessionRefreshRun(runID)
	if err != nil {
		return nil, fmt.Errorf("refresh run not found")
	}
	unlock := lockTokenRefresh(run.TokenID)
	defer unlock()
	run, err = loadSessionRefreshRun(runID)
	if err != nil {
		return nil, fmt.Errorf("refresh run not found")
	}
	if run.Status != refreshRunAwaiting || run.InputRequest == nil {
		return run, fmt.Errorf("this refresh run is not waiting for input (status %s)", run.Status)
	}
	if expectStepID != "" && run.InputRequest.StepID != "" && expectStepID != run.InputRequest.StepID {
		return run, fmt.Errorf(
			"this refresh has moved on to step %d and is waiting for %q; reload the run and answer the "+
				"current prompt", run.InputRequest.StepOrder, run.InputRequest.VarName)
	}
	// A push "approve" pause needs no value, just a Continue; everything else needs the value.
	if strings.TrimSpace(value) == "" && !run.InputRequest.NoValue {
		return run, fmt.Errorf("a value is required for %s", run.InputRequest.VarName)
	}
	if run.Provided == nil {
		run.Provided = map[string]string{}
	}
	stored := value
	if run.InputRequest.NoValue && strings.TrimSpace(stored) == "" {
		stored = "1" // record the continue so the pause resolves on resume
	}
	run.Provided[run.InputRequest.VarName] = stored
	run.InputRequest = nil
	run.Status = refreshRunRunning
	if err := saveSessionRefreshRun(run); err != nil {
		return run, err
	}
	token, err := loadSessionToken(run.TokenID)
	if err != nil {
		run.Status = refreshRunFailed
		run.OutcomeDetail = "the session token no longer exists"
		saveSessionRefreshRun(run)
		return run, nil
	}
	executeSessionRefreshRun(run, token)
	return run, nil
}

// executeSessionRefreshRun runs the flow from run.CompletedSteps to the first pause or to the end,
// mutating and persisting run. It never re-runs a completed step: the jar and the {{af:}} vars are
// rebuilt from the stored responses of the steps before the resume point.
func executeSessionRefreshRun(run *SessionRefreshRun, token SessionToken) {
	baseURL, err := getFlowBaseURL(run.AuthFlowID)
	if err != nil {
		finishRefreshRunFailed(run, "the linked auth flow no longer exists")
		return
	}
	steps, err := getStepsByFlow(run.AuthFlowID)
	if err != nil {
		finishRefreshRunFailed(run, "could not read the flow's steps: "+err.Error())
		return
	}
	if len(steps) == 0 {
		finishRefreshRunFailed(run, "the linked auth flow has no steps to replay")
		return
	}
	if run.CompletedSteps > len(steps) {
		run.CompletedSteps = len(steps)
	}
	// The resume point. replay_failed ("every step failed") is only meaningful for a fresh run: on a
	// resume the pre-pause steps are not re-sent, so this run's send counters exclude them.
	startedFrom := run.CompletedSteps

	// Rebuild the accumulated state so the resume CONTINUES rather than restarts. The cookie jar is
	// seeded from the stored response HEADERS of the completed steps (json.Marshal'd, never passed
	// through sanitizeForTextColumn, so cookie attribution is exact). The {{af:}} vars, the Set-Cookie
	// lines and the bodies come from the state PERSISTED at the pause, NOT re-derived from the stored
	// bodies: those are sanitized (NUL / invalid-UTF8 stripped) and re-extracting from them could
	// change a captured value. Plus the values the operator has provided so far.
	jar, _ := cookiejar.New(nil)
	vars := map[string]string{}
	var setCookies []string
	var bodies []string
	if startedFrom > 0 {
		seedJar(jar, baseURL, steps[:startedFrom])
		for name, value := range run.Captured {
			vars[name] = value
		}
		setCookies = append(setCookies, run.SetCookies...)
		bodies = append(bodies, run.Bodies...)
	}
	for name, value := range run.Provided {
		vars[name] = value
	}

	// Seed the {{token:NAME}} namespace from the STORED session tokens, so a refresh flow can carry the
	// stored refresh secret (and the current credential) into its token request. This is the one thing a
	// one-step OAuth refresh flow needs that a login flow does not: the refresh_token to spend. Seeded
	// fresh on every execution (including a resume) because it is derived from the current stored rows.
	// A missing value is left UNSET so {{token:refresh_token}} stays unresolved and prepareStepRequest
	// refuses the step rather than sending an empty secret.
	if strings.TrimSpace(token.TokenValue) != "" {
		vars[tokenVarKeyPrefix+"credential"] = token.TokenValue
		vars[tokenVarKeyPrefix+"access_token"] = token.TokenValue
	}
	if token.RefreshTokenID != "" {
		if rt, err := loadSessionToken(token.RefreshTokenID); err == nil && strings.TrimSpace(rt.TokenValue) != "" {
			vars[tokenVarKeyPrefix+"refresh_token"] = rt.TokenValue
		}
	}

	failed := 0
	succeeded := 0
	for i := run.CompletedSteps; i < len(steps); i++ {
		step := steps[i]
		inter := step.Interaction

		// totp_auto: generate the current code from the stored secret and inject it as {{af:VarName}}.
		// No pause - authenticator MFA is fully automatable when the operator has stored their secret.
		if inter.isTOTPAuto() && strings.TrimSpace(vars[inter.VarName]) == "" {
			code, terr := generateTOTP(inter.TOTPSecret)
			if terr != nil {
				finishRefreshRunFailed(run, fmt.Sprintf(
					"step %d: could not generate the TOTP code from the stored secret: %v", step.StepOrder, terr))
				return
			}
			vars[inter.VarName] = code
		}

		// A step that needs the operator (a value to enter, a push to approve, a magic link to click):
		// pause and ask. refreshStepPause is the single source of the pause decision.
		if pauseReq := refreshStepPause(step, vars, run.Provided); pauseReq != nil {
			run.Status = refreshRunAwaiting
			run.CompletedSteps = i
			run.InputRequest = pauseReq
			// Persist the exact accumulated state so the resume continues from these values, not from a
			// re-read of the sanitized stored responses.
			run.Captured = vars
			run.SetCookies = setCookies
			run.Bodies = bodies
			saveSessionRefreshRun(run)
			recordSessionTokenEvent(run.TokenID, "refresh", "awaiting_input",
				fmt.Sprintf("Paused at step %d: %s", step.StepOrder, pauseReq.Prompt), nil)
			return
		}

		// A step whose kind this build cannot execute (a later phase's kind) must stop the run with a
		// clear reason rather than be replayed as if it were "none".
		if !inter.isNone() && !inter.needsInput() {
			kind := strings.ToLower(strings.TrimSpace(inter.Kind))
			if !interactionKindsRunnable[kind] {
				finishRefreshRunFailed(run, fmt.Sprintf(
					"step %d needs the %q interaction, which this build does not run yet. "+
						"Refresh this session by pasting a fresh value instead.", step.StepOrder, kind))
				return
			}
		}

		request, _, refusal := prepareStepRequest(step.RawRequest, vars)
		if refusal != "" {
			failed++
			if uErr := updateStepResponse(step.ID, 0, nil, "", 0, refusal); uErr != nil {
				log.Printf("[SESSION-REFRESH] Failed to persist refusal of step %s: %v", step.ID, uErr)
			}
			run.CompletedSteps = i + 1
			continue
		}

		effBase := resolveBaseURL(request, baseURL)
		status, headers, body, ms, sendErr := sendRawRequest(request, effBase, jar)
		errStr := ""
		if sendErr != nil {
			errStr = sendErr.Error()
			failed++
		}
		if uErr := updateStepResponse(step.ID, status, headers, body, ms, errStr); uErr != nil {
			log.Printf("[SESSION-REFRESH] Failed to persist replay of step %s: %v", step.ID, uErr)
		}
		run.CompletedSteps = i + 1
		if sendErr != nil {
			continue
		}
		succeeded++
		captured, _ := runAuthFlowExtractions(step.Extractions, headers, body)
		for name, value := range captured {
			vars[name] = value
		}
		setCookies = append(setCookies, http.Header(headers).Values("Set-Cookie")...)
		if strings.TrimSpace(body) != "" {
			bodies = append(bodies, body)
		}
	}

	// Every step is done: pull the fresh value out of what came back. "Every step failed" is reported
	// only for a fresh run (startedFrom == 0) where NOT ONE step succeeded. The test is succeeded == 0,
	// not failed == sent: `failed` counts refusals plus send errors while a `sent` attempt counter also
	// counts errors, so failed == sent fired whenever the number of refused steps merely equalled the
	// number of successful ones and discarded a token a later step had genuinely refreshed. On a resume
	// (startedFrom > 0) the pre-pause successes are not in this counter, so the guard is skipped and a
	// post-pause failure falls through to extraction / no_token_found instead of a false total-failure.
	if startedFrom == 0 && succeeded == 0 && failed > 0 {
		finishRefreshRunOutcome(run, token, "replay_failed", false,
			"Every step of the flow failed to send, so no new value could be taken.", nil, nil)
		return
	}

	// OAuth refresh grant: if the flow's final response is a token endpoint response, mint the new access
	// token onto the anchor AND write the ROTATED refresh token back onto the linked refresh row. Without
	// the writeback the stored refresh token goes stale after one refresh and the NEXT refresh fails,
	// which is the single biggest correctness risk of a refresh-token flow. Tried before the generic
	// single-value extraction because a token response carries more than one value to store.
	if detail, wroteRefresh, ok := writebackRefreshResponse(token, bodies); ok {
		if names := refreshCompanionCookies(token.ScopeTargetID, run.TokenID, setCookies); len(names) > 0 {
			detail += fmt.Sprintf(" Also refreshed the companion value(s) %s.", strings.Join(names, ", "))
		}
		finishRefreshRunOutcome(run, token, "refreshed", true, detail,
			map[string]interface{}{"source": "oauth token endpoint response", "rotated_refresh": wroteRefresh,
				"auth_flow_id": run.AuthFlowID}, nil)
		return
	}

	value, expires, source := extractRefreshedTokenValue(token, setCookies, bodies)
	if value == "" {
		finishRefreshRunOutcome(run, token, "no_token_found", false, fmt.Sprintf(
			"The flow replayed, but no new value for %s turned up in the responses. Check the flow's "+
				"steps still succeed, and that the credential really is issued as a Set-Cookie or in a "+
				"response body rather than by a redirect this replay does not follow.",
			sessionTokenIdentity(token)), nil, nil)
		return
	}

	tag, err := dbPool.Exec(context.Background(), `
		UPDATE session_tokens
		SET token_value = $1, expires_at = $2, last_refreshed_at = NOW(),
		    last_validation_status = '', last_validation_detail = '', updated_at = NOW()
		WHERE id = $3`, value, DeriveSessionTokenExpiry(value, expires), run.TokenID)
	if err != nil {
		finishRefreshRunFailed(run, "the refreshed value could not be stored: "+err.Error())
		return
	}
	// A nil error with 0 rows means the token row was deleted mid-run: nothing was stored, so do not
	// report a phantom refresh (pgx does not error on a 0-row UPDATE).
	if tag.RowsAffected() == 0 {
		finishRefreshRunFailed(run, "the refreshed value could not be stored: the token row no longer exists")
		return
	}

	detail := fmt.Sprintf("Replayed the linked auth flow and took a new value for %s from %s.",
		sessionTokenIdentity(token), source)
	if names := refreshCompanionCookies(token.ScopeTargetID, run.TokenID, setCookies); len(names) > 0 {
		detail += fmt.Sprintf(" Also refreshed the companion value(s) %s from the same response.",
			strings.Join(names, ", "))
	}
	finishRefreshRunOutcome(run, token, "refreshed", true, detail,
		map[string]interface{}{"source": source, "auth_flow_id": run.AuthFlowID}, nil)
}

// writebackRefreshResponse applies an OAuth token endpoint response to the stored rows: the new
// access_token onto the anchor, and the ROTATED refresh_token onto the anchor's linked refresh row.
// Returns ok=false when the flow's responses hold no token endpoint response with an access_token, so the
// caller falls through to the generic single-value extraction (a cookie-session refresh flow).
//
// The rotation write is the point: many issuers return a fresh refresh_token on every refresh and
// invalidate the old one, so storing only the access token would break the next refresh.
func writebackRefreshResponse(token SessionToken, bodies []string) (detail string, wroteRefresh bool, ok bool) {
	// The LAST token response wins: a flow may touch the token endpoint more than once, and the freshest
	// is the one whose values are live.
	var parsed OAuthTokenResponse
	found := false
	for _, body := range bodies {
		if p, isToken := ParseOAuthTokenResponse(body); isToken && p.HasAccessToken && strings.TrimSpace(p.AccessToken) != "" {
			parsed = p
			found = true
		}
	}
	if !found {
		return "", false, false
	}

	now := time.Now().UTC()
	aExp := DeriveSessionTokenExpiry(parsed.AccessToken, ttlToExpiry(now, parsed.ExpiresIn, parsed.ExpiresInKnown))
	tag, err := dbPool.Exec(context.Background(), `
		UPDATE session_tokens
		SET token_value = $1, expires_at = $2, last_refreshed_at = NOW(),
		    last_validation_status = '', last_validation_detail = '', updated_at = NOW()
		WHERE id = $3`, parsed.AccessToken, aExp, token.ID)
	if err != nil {
		return "", false, false
	}
	// pgx returns a nil error for a 0-row UPDATE, so a nil error is NOT proof the row was written. If the
	// anchor no longer exists (deleted between load and here), nothing was stored: do not claim success,
	// fall through so the caller reports honestly rather than a phantom refresh.
	if tag.RowsAffected() == 0 {
		log.Printf("[SESSION-REFRESH] token endpoint response minted a value but the anchor row %s was gone, nothing stored", token.ID)
		return "", false, false
	}

	detail = fmt.Sprintf("Replayed the refresh flow and minted a new access token for %s.",
		sessionTokenIdentity(token))

	// Rotation: write the fresh refresh_token back onto the linked refresh row so the next refresh uses
	// it, not the spent one. Only when the response carried one AND this token is linked to a refresh row.
	if parsed.HasRefreshToken && strings.TrimSpace(parsed.RefreshToken) != "" && token.RefreshTokenID != "" {
		rExp := DeriveSessionTokenExpiry(parsed.RefreshToken, ttlToExpiry(now, parsed.RefreshTTL, parsed.RefreshTTLKnown))
		rTag, rErr := dbPool.Exec(context.Background(), `
			UPDATE session_tokens
			SET token_value = $1, expires_at = $2, updated_at = NOW()
			WHERE id = $3 AND token_role = 'refresh'`, parsed.RefreshToken, rExp, token.RefreshTokenID)
		// A nil error with 0 rows means the linked refresh row is gone or no longer a refresh row, so the
		// rotated secret was NOT stored. Claiming rotation there is a false success: the next refresh
		// would spend the now-invalidated old token. Warn honestly instead so the operator knows the next
		// refresh may fail (the CURRENT refresh still succeeded, the access token was minted).
		if rErr != nil || rTag.RowsAffected() == 0 {
			if rErr != nil {
				log.Printf("[SESSION-REFRESH] minted a new access token but could not store the rotated refresh token for %s: %v", token.ID, rErr)
			} else {
				log.Printf("[SESSION-REFRESH] minted a new access token but the linked refresh row %s is missing or not a refresh row, so the rotated refresh token was not stored", token.RefreshTokenID)
			}
			detail += " WARNING: the issuer rotated the refresh token but it could not be stored (the linked refresh row is missing or no longer a refresh row), so the next refresh may fail; re-link or re-capture the refresh token."
		} else {
			wroteRefresh = true
			detail += " Rotated the stored refresh token."
		}
	}
	return detail, wroteRefresh, true
}

func finishRefreshRunFailed(run *SessionRefreshRun, detail string) {
	run.Status = refreshRunFailed
	run.OutcomeStatus = "failed"
	run.OutcomeDetail = detail
	run.NewValueSet = false
	run.InputRequest = nil
	saveSessionRefreshRun(run)
	recordSessionTokenEvent(run.TokenID, "refresh", "failed", detail, nil)
}

func finishRefreshRunOutcome(run *SessionRefreshRun, token SessionToken, outcome string, newValue bool,
	detail string, evidence map[string]interface{}, _ interface{}) {
	run.Status = refreshRunCompleted
	run.OutcomeStatus = outcome
	run.OutcomeDetail = detail
	run.NewValueSet = newValue
	run.InputRequest = nil
	saveSessionRefreshRun(run)
	recordSessionTokenEvent(run.TokenID, "refresh", outcome, detail, evidence)
}

// ---------------------------------------------------------------------------
// HTTP shape
// ---------------------------------------------------------------------------

// refreshRunResponse is the one shape every interactive-refresh endpoint returns, so the client and
// MCP handle start, provide-input and status the same way.
func refreshRunResponse(run *SessionRefreshRun) map[string]interface{} {
	out := map[string]interface{}{
		"run_id":        run.ID,
		"token_id":      run.TokenID,
		"new_value_set": run.NewValueSet,
	}
	switch run.Status {
	case refreshRunAwaiting:
		out["status"] = "needs_input"
		out["input_request"] = run.InputRequest
		if run.InputRequest != nil {
			out["detail"] = run.InputRequest.Prompt
		}
	case refreshRunCompleted:
		out["status"] = run.OutcomeStatus
		out["detail"] = run.OutcomeDetail
	case refreshRunCancelled:
		out["status"] = "cancelled"
		out["detail"] = "This refresh was cancelled."
	default:
		out["status"] = run.OutcomeStatus
		if out["status"] == "" {
			out["status"] = run.Status
		}
		out["detail"] = run.OutcomeDetail
	}
	return out
}

// ProvideSessionRefreshInput handles POST /session-refresh-runs/{run_id}/input.
func ProvideSessionRefreshInput(w http.ResponseWriter, r *http.Request) {
	runID := mux.Vars(r)["run_id"]
	if _, err := uuid.Parse(runID); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "run_id must be a UUID"})
		return
	}
	var payload struct {
		Value string `json:"value"`
		// StepID echoes the step the caller is answering (from the input_request it was shown). Optional
		// for older callers, but when present it stops a stale/duplicate submit from landing on a
		// different pause the run has since advanced to.
		StepID string `json:"step_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "Invalid request body"})
		return
	}
	run, err := resumeSessionRefreshRun(runID, payload.Value, payload.StepID)
	if err != nil {
		status := http.StatusBadRequest
		if run == nil {
			status = http.StatusNotFound
		}
		writeSessionTokenJSON(w, status, map[string]interface{}{"error": err.Error()})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, refreshRunResponse(run))
}

// GetSessionRefreshRun handles GET /session-refresh-runs/{run_id}.
func GetSessionRefreshRun(w http.ResponseWriter, r *http.Request) {
	runID := mux.Vars(r)["run_id"]
	run, err := loadSessionRefreshRun(runID)
	if err != nil {
		writeSessionTokenJSON(w, http.StatusNotFound, map[string]interface{}{"error": "refresh run not found"})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, refreshRunResponse(run))
}

// CancelSessionRefreshRun handles POST /session-refresh-runs/{run_id}/cancel.
func CancelSessionRefreshRun(w http.ResponseWriter, r *http.Request) {
	runID := mux.Vars(r)["run_id"]
	run, err := loadSessionRefreshRun(runID)
	if err != nil {
		writeSessionTokenJSON(w, http.StatusNotFound, map[string]interface{}{"error": "refresh run not found"})
		return
	}
	if run.Status == refreshRunRunning || run.Status == refreshRunAwaiting {
		run.Status = refreshRunCancelled
		run.InputRequest = nil
		saveSessionRefreshRun(run)
	}
	writeSessionTokenJSON(w, http.StatusOK, refreshRunResponse(run))
}

// ---------------------------------------------------------------------------
// Unattended auto-refresh
// ---------------------------------------------------------------------------
//
// Opt-in per token (the auto_refresh column, off by default). The loop only ever touches a token that
// the operator has both marked auto_refresh AND already refreshed once by hand successfully, whose
// linked flow classifies as a pure replay. Anything that needs a code, crosses an IdP, or hits a bot
// challenge is excluded here because it cannot possibly succeed unattended: the point is to renew the
// credentials that CAN renew themselves before they lapse, never to hammer a target with a flow that
// will only pause for a human who is not watching.

// autoRefreshLead is how far ahead of expiry a token becomes due, so the refresh lands before the old
// value dies rather than after a scan has already started failing on it.
const autoRefreshLead = 5 * time.Minute

// autoRefreshCooldown keeps one token from being retried every tick when its refresh keeps failing (a
// flow that has quietly rotted, a target that is down). Best-effort and in-memory: a restart forgets
// it and the token gets one more attempt, which is harmless.
const autoRefreshCooldown = 15 * time.Minute

// autoRefreshDue is the pure gate: given a token, its flow's refreshability kind, and the clock, does
// this token want an unattended refresh right now, and why. Kept side-effect free so it is unit
// testable without a database or a live target.
func autoRefreshDue(tok SessionToken, flowKind string, now time.Time) (bool, string) {
	if !tok.AutoRefresh {
		return false, "auto-refresh is off for this token"
	}
	if !tok.IsActive {
		return false, "token is inactive"
	}
	// A refresh needs SOME flow to replay: the headless refresh flow when set, else the creation flow.
	// A token linked only to a refresh flow (an OAuth token with no stored creation flow) still qualifies.
	if refreshFlowIDFor(tok) == "" {
		return false, "token has no linked auth or refresh flow"
	}
	// refresh_proven: only a token that has been refreshed once, by hand, is trusted to refresh itself.
	// It proves the flow actually issues a new value and the operator has seen it work.
	if tok.LastRefreshedAt == nil {
		return false, "no successful refresh has been proven yet; run one by hand first"
	}
	if flowKind != flowRefreshReplay {
		return false, "the linked flow is not a pure replay (" + flowKind + "); it cannot run unattended"
	}
	// A reason to act: either the clock says it is about to lapse, or the last validation already found
	// it dead. Without one of those there is nothing to renew, so the loop leaves it alone.
	if tok.ExpiresAt != nil && !tok.ExpiresAt.After(now.Add(autoRefreshLead)) {
		return true, "expires within the lead window"
	}
	if sessionTokenRejectedStatuses[strings.ToLower(strings.TrimSpace(tok.LastValidationStatus))] {
		return true, "last validation was a rejection"
	}
	return false, "not near expiry and last validation did not reject it"
}

var (
	autoRefreshAttemptMu sync.Mutex
	autoRefreshAttempts  = map[string]time.Time{}
)

// autoRefreshOnCooldown reports whether this token was attempted too recently to try again.
func autoRefreshOnCooldown(tokenID string, now time.Time) bool {
	autoRefreshAttemptMu.Lock()
	defer autoRefreshAttemptMu.Unlock()
	last, ok := autoRefreshAttempts[tokenID]
	return ok && now.Sub(last) < autoRefreshCooldown
}

func markAutoRefreshAttempt(tokenID string, now time.Time) {
	autoRefreshAttemptMu.Lock()
	autoRefreshAttempts[tokenID] = now
	autoRefreshAttemptMu.Unlock()
}

// StartSessionAutoRefreshLoop launches the background ticker. It is safe to call once at startup: with
// no token opted in it does nothing every tick, so it is effectively off until an operator turns a
// token's auto_refresh on.
func StartSessionAutoRefreshLoop(interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			runDueAutoRefreshes()
		}
	}()
}

// runDueAutoRefreshes is one sweep: find the opted-in tokens, and for each one whose flow is a pure
// replay and whose clock/verdict says it is due, start a refresh run. A replay run never pauses, so it
// completes inside startSessionRefreshRun. Errors are logged, never fatal: this is a convenience loop.
func runDueAutoRefreshes() {
	now := time.Now()
	rows, err := dbPool.Query(context.Background(),
		`SELECT `+sessionTokenCols+sessionTokenFrom+
			`WHERE COALESCE(t.auto_refresh,false) = true AND t.is_active = true`)
	if err != nil {
		log.Printf("[SESSION-AUTOREFRESH] Could not list opted-in tokens: %v", err)
		return
	}
	var candidates []SessionToken
	for rows.Next() {
		tok, err := scanSessionToken(rows)
		if err != nil {
			log.Printf("[SESSION-AUTOREFRESH] Row scan failed: %v", err)
			continue
		}
		candidates = append(candidates, tok)
	}
	rows.Close()

	// classifyCache: one flow can back several tokens, so its steps are read and classified once.
	classifyCache := map[string]string{}
	for _, tok := range candidates {
		if autoRefreshOnCooldown(tok.ID, now) {
			continue
		}
		// Classify the flow refresh actually RUNS (refreshFlowIDFor: the headless refresh flow when set,
		// else the creation flow), not always the creation flow. A token whose creation flow is
		// browser_only but whose refresh flow is a pure replay is auto-refreshable via the refresh flow;
		// classifying the creation flow would wrongly exclude it.
		flowID := refreshFlowIDFor(tok)
		if flowID == "" {
			continue
		}
		kind, ok := classifyCache[flowID]
		if !ok {
			steps, err := getStepsByFlow(flowID)
			if err != nil {
				log.Printf("[SESSION-AUTOREFRESH] Could not read steps for flow %s: %v", flowID, err)
				continue
			}
			kind, _, _ = ClassifyFlowRefreshability(steps)
			classifyCache[flowID] = kind
		}
		due, reason := autoRefreshDue(tok, kind, now)
		if !due {
			continue
		}
		markAutoRefreshAttempt(tok.ID, now)
		log.Printf("[SESSION-AUTOREFRESH] Token %s (%s) is due: %s; starting refresh", tok.ID, tok.Name, reason)
		if _, err := startSessionRefreshRun(tok); err != nil {
			log.Printf("[SESSION-AUTOREFRESH] Refresh of token %s failed to start: %v", tok.ID, err)
		}
	}
}
