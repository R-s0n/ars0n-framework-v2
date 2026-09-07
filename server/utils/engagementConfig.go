package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// Per-target engagement rules: the header a programme demands, the User-Agent it demands, and the
// rate it caps you at.
//
// ============================================================================
// WHY THIS EXISTS
// ============================================================================
//
// user_settings.custom_header and user_settings.custom_user_agent already existed, and so did
// user_settings.amass_rate_limit and its siblings. Every one of them is GLOBAL: one value across
// every target in the database.
//
// That is the wrong shape for bug bounty work, because each programme's brief demands something
// different:
//
//	DailyPay        X-HackerOne-DailyPay-Research: <handle> on EVERY request, or their SOC treats
//	                the traffic as an attack.
//	Assurant        <H1-handle> APPENDED to an ordinary browser User-Agent, and a hard cap of 45
//	                requests per minute across the engagement.
//	Swan, Transmit  neither.
//
// With one global slot, switching targets means remembering to change it by hand, and forgetting
// means sending traffic to a programme without the header its brief calls mandatory. Which is why,
// in practice, every script written against these targets hardcoded the header: there was nowhere
// to put it. This file gives it somewhere, per target, and keeps user_settings as the FALLBACK
// rather than the only value.
//
// ============================================================================
// THE RESOLUTION RULE, AND WHY PROVENANCE IS PART OF THE ANSWER
// ============================================================================
//
//	per-target value  ->  user_settings global  ->  built-in default
//
// ResolveEngagementConfig returns the effective value AND which of those three it came from, per
// field. That is not decoration. An operator looking at "X-HackerOne-DailyPay-Research" on the
// Assurant target needs to know instantly whether they set it there or whether it leaked in from
// the global settings, because one of those is correct and the other sends another programme's
// header to a company that did not ask for it. A config screen that cannot tell you where a value
// came from is a config screen you stop trusting, and an untrusted config screen gets bypassed by
// hardcoding - which is exactly the state this feature is replacing.
//
// ============================================================================
// THE RAILS
// ============================================================================
//
//	NULL MEANS INHERIT.   Every override column is nullable and a PUT that omits a field leaves the
//	                      column alone. A partial update that wipes the fields it did not mention is
//	                      a bug this codebase has already shipped once, on a different table, and it
//	                      cost seven columns across fifty-eight rows. Clearing an override is the
//	                      separate DELETE .../engagement/{field}.
//	HEADER NAMES ARE VETTED. Cookie, Authorization and User-Agent are refused as custom header names,
//	                      at write time AND again when the header map is built. Cookie and
//	                      Authorization would smuggle a credential past the no-credentials rail of
//	                      every unauthenticated sender; User-Agent has its own field and two places
//	                      to set one value is how they end up disagreeing.
//	NO HEADER INJECTION.  CR and LF are refused in both the name and the value.
//	SEND_COOKIES NEEDS AN ACK. Setting it true requires acknowledge_state_risk:true in the same
//	                      request. A scanner carrying the operator's session acts AS the
//	                      authenticated user.
//	ACTIVE DETECTION IGNORES SEND_COOKIES ENTIRELY. See ResolvedEngagementConfig.SendCookies.

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

const (
	// EngagementFromTarget: set on this scope target, in scope_target_engagement_config.
	EngagementFromTarget = "target"
	// EngagementFromGlobal: inherited from user_settings, which every other target also sees.
	EngagementFromGlobal = "global"
	// EngagementFromDefault: nobody set it; this is the framework's built-in.
	EngagementFromDefault = "default"
)

// Built-in defaults. The traffic-shaping four deliberately mirror the active detector's own
// constants rather than inventing a second set of numbers: two files disagreeing about "the default
// request budget" is how an operator ends up reading one number and getting another.
const (
	engagementDefaultUserAgentMode = "replace"
	engagementDefaultMaxRPS        = flowDetectDefaultRPS
	engagementDefaultMaxRequests   = flowDetectDefaultMaxRequests
	engagementDefaultTimeoutS      = flowDetectDefaultTimeoutS
	engagementDefaultMaxRedirects  = flowDetectDefaultMaxRedirects

	// Mirrors the fallback in NewScanClient (scanHTTP.go). Duplicated rather than exported from
	// there because scanHTTP.go is not this pass's to edit; TestEngagementDefaultUserAgentMatchesScanClient
	// reads that file and fails if the two ever drift.
	engagementDefaultUserAgent = "ars0n-framework/2.0 (+authorized-testing)"
)

// Ceilings on what an operator may type. These are not programme rules, they are sanity bounds: a
// value outside them is a typo, and a typo in a rate cap is the kind that gets an account banned.
const (
	engagementMaxRPSCeiling      = 50.0
	engagementMaxRequestsCeiling = 100000
	engagementMaxTimeoutS        = 300
	engagementMaxRedirectsCap    = 20
	engagementMaxNotesLen        = 4000
)

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

// EngagementOverrides is one row of scope_target_engagement_config.
//
// EVERY FIELD IS A POINTER, and that is the whole point of the type. nil means "no override, fall
// back", which is a different statement from "the operator set this to zero/false/empty". Without
// the distinction, an unset max_rps reads as 0 and an unset follow_redirects reads as false, and the
// resolver cannot tell an inherited value from a deliberate one - which is both the provenance bug
// and the field-translation bug in one.
type EngagementOverrides struct {
	CustomHeaderName  *string  `json:"custom_header_name"`
	CustomHeaderValue *string  `json:"custom_header_value"`
	CustomUserAgent   *string  `json:"custom_user_agent"`
	UserAgentMode     *string  `json:"user_agent_mode"`
	MaxRPS            *float64 `json:"max_rps"`
	MaxRequestsPerRun *int     `json:"max_requests_per_run"`
	RequestTimeoutS   *int     `json:"request_timeout_s"`
	MaxRedirects      *int     `json:"max_redirects"`
	FollowRedirects   *bool    `json:"follow_redirects"`
	SendCookies       *bool    `json:"send_cookies"`
	ProgrammeNotes    *string  `json:"programme_notes"`
}

// EngagementGlobals is the user_settings row, which is the middle tier of the resolution order.
type EngagementGlobals struct {
	// CustomHeader is stored as one TEXT field in the shape the Settings modal asks for:
	// "X-Custom-Header: my-custom-value". Split on the FIRST colon, because a header value may
	// legitimately contain colons and the name may not.
	CustomHeader    string
	CustomUserAgent string
}

// ResolvedEngagementConfig is the effective config plus, per field, where each value came from.
type ResolvedEngagementConfig struct {
	CustomHeaderName  string  `json:"custom_header_name"`
	CustomHeaderValue string  `json:"custom_header_value"`
	CustomUserAgent   string  `json:"custom_user_agent"`
	UserAgentMode     string  `json:"user_agent_mode"`
	MaxRPS            float64 `json:"max_rps"`
	MaxRequestsPerRun int     `json:"max_requests_per_run"`
	RequestTimeoutS   int     `json:"request_timeout_s"`
	MaxRedirects      int     `json:"max_redirects"`
	FollowRedirects   bool    `json:"follow_redirects"`

	// SendCookies is stored and resolved, and ACTIVE FLOW DETECTION IGNORES IT.
	//
	// That is not an oversight and it must not be "fixed". flowDetectionActive.go builds its
	// ScanClient with a nil cookie jar, sends no Authorization header, and attaches no
	// ScopedAuthMaterial, because an unauthenticated request cannot act as anybody. This flag exists
	// for the senders that DO carry a session - the Request Flow Builder and Replay Requests, where
	// the operator is looking at one request at a time - so that the acknowledgement is recorded per
	// target instead of being re-clicked per request. An engagement config cannot re-enable a rail
	// the transport does not have.
	SendCookies    bool   `json:"send_cookies"`
	ProgrammeNotes string `json:"programme_notes"`

	// EffectiveUserAgent is the exact string that goes on the wire, after user_agent_mode has been
	// applied. Rendered here rather than left for the UI to reconstruct: custom_user_agent means two
	// different things depending on the mode (the whole UA, or a tag glued to the end of one), and
	// showing the operator the raw field alone is how they discover the difference against a live
	// programme.
	EffectiveUserAgent string `json:"effective_user_agent"`

	// Source maps each field name above to EngagementFromTarget / Global / Default.
	Source map[string]string `json:"source"`
}

// HeaderMap is the headers a sender must add, or nil.
//
// The name is re-vetted here even though the API already refused these at write time. The row may
// predate the validation, or have been written by a migration, or by hand; a rail that is only
// enforced on the way in is a rail that a database edit walks straight through. Cookie and
// Authorization are the two that matter: ScanRequest.Headers is applied with Set AFTER the
// framework's own headers, so either of them would land on the wire intact and turn an
// unauthenticated scanner into an authenticated one.
func (c ResolvedEngagementConfig) HeaderMap() map[string]string {
	name := strings.TrimSpace(c.CustomHeaderName)
	if name == "" || c.CustomHeaderValue == "" {
		return nil
	}
	if err := validateEngagementHeaderName(name); err != nil {
		log.Printf("[ENGAGEMENT] Refusing to send stored header %q: %v", name, err)
		return nil
	}
	if err := validateEngagementHeaderValue(c.CustomHeaderValue); err != nil {
		log.Printf("[ENGAGEMENT] Refusing to send stored header %q: %v", name, err)
		return nil
	}
	return map[string]string{name: c.CustomHeaderValue}
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

// ResolveEngagementFrom is the resolution order as a pure function: per-target, else global, else
// built-in default, recording the source of every field.
//
// Pure on purpose. The rule that decides whether DailyPay's mandatory header reaches DailyPay is a
// judgement call, and a judgement call that can only be exercised against a live database is one
// nobody will ever check. Every branch below is covered in engagementConfig_test.go against structs.
func ResolveEngagementFrom(over *EngagementOverrides, glob EngagementGlobals) ResolvedEngagementConfig {
	out := ResolvedEngagementConfig{Source: map[string]string{}}
	if over == nil {
		over = &EngagementOverrides{}
	}

	// --- the custom header -------------------------------------------------
	//
	// Name and value resolve as a PAIR, never independently. Taking the name from this target and
	// the value from the global would produce a header neither of them asked for - the exact
	// half-applied config this feature exists to stop.
	switch {
	case over.CustomHeaderName != nil && strings.TrimSpace(*over.CustomHeaderName) != "":
		out.CustomHeaderName = strings.TrimSpace(*over.CustomHeaderName)
		if over.CustomHeaderValue != nil {
			out.CustomHeaderValue = strings.TrimSpace(*over.CustomHeaderValue)
		}
		out.Source["custom_header_name"] = EngagementFromTarget
		out.Source["custom_header_value"] = EngagementFromTarget
	default:
		if n, v, ok := SplitEngagementHeader(glob.CustomHeader); ok {
			out.CustomHeaderName, out.CustomHeaderValue = n, v
			out.Source["custom_header_name"] = EngagementFromGlobal
			out.Source["custom_header_value"] = EngagementFromGlobal
		} else {
			out.Source["custom_header_name"] = EngagementFromDefault
			out.Source["custom_header_value"] = EngagementFromDefault
		}
	}

	// --- the user agent ----------------------------------------------------
	out.UserAgentMode = engagementDefaultUserAgentMode
	out.Source["user_agent_mode"] = EngagementFromDefault
	if over.UserAgentMode != nil && isEngagementUserAgentMode(*over.UserAgentMode) {
		out.UserAgentMode = strings.ToLower(strings.TrimSpace(*over.UserAgentMode))
		out.Source["user_agent_mode"] = EngagementFromTarget
	}

	targetUA := ""
	if over.CustomUserAgent != nil {
		targetUA = strings.TrimSpace(*over.CustomUserAgent)
	}
	globalUA := strings.TrimSpace(glob.CustomUserAgent)

	if out.UserAgentMode == "append" {
		// APPEND. custom_user_agent is a TAG, not a User-Agent. The base it is glued onto is the
		// inherited one - the global browser UA if the operator set one, otherwise the framework's
		// own - which is what makes "<H1-handle> appended to a normal browser User-Agent" expressible
		// at all. Naming the base in the provenance would be a lie, so the source reported for
		// custom_user_agent is where the TAG came from and EffectiveUserAgent shows the result.
		base := globalUA
		baseSource := EngagementFromGlobal
		if base == "" {
			base = engagementDefaultUserAgent
			baseSource = EngagementFromDefault
		}
		out.CustomUserAgent = targetUA
		if targetUA != "" {
			out.EffectiveUserAgent = base + " " + targetUA
			out.Source["custom_user_agent"] = EngagementFromTarget
		} else {
			// Mode says append and there is nothing to append. Not an error, but it must not silently
			// become something else: the base is sent unchanged and the provenance says so.
			out.EffectiveUserAgent = base
			out.Source["custom_user_agent"] = baseSource
		}
	} else {
		switch {
		case targetUA != "":
			out.CustomUserAgent = targetUA
			out.EffectiveUserAgent = targetUA
			out.Source["custom_user_agent"] = EngagementFromTarget
		case globalUA != "":
			out.CustomUserAgent = globalUA
			out.EffectiveUserAgent = globalUA
			out.Source["custom_user_agent"] = EngagementFromGlobal
		default:
			out.CustomUserAgent = ""
			out.EffectiveUserAgent = engagementDefaultUserAgent
			out.Source["custom_user_agent"] = EngagementFromDefault
		}
	}

	// --- the traffic bounds ------------------------------------------------
	//
	// There is no global tier for these. user_settings' rate limits are per TOOL (amass, ctl, cewl)
	// and mean queries per second inside one binary's own flags; reading "amass_rate_limit: 10" as
	// "this programme allows 10 requests per second" would be inventing a permission nobody granted.
	// So these fall straight from target to built-in default, and the provenance says 'default'
	// rather than pretending a global exists.
	out.MaxRPS = engagementDefaultMaxRPS
	out.Source["max_rps"] = EngagementFromDefault
	if over.MaxRPS != nil && *over.MaxRPS > 0 {
		out.MaxRPS = *over.MaxRPS
		out.Source["max_rps"] = EngagementFromTarget
	}

	out.MaxRequestsPerRun = engagementDefaultMaxRequests
	out.Source["max_requests_per_run"] = EngagementFromDefault
	if over.MaxRequestsPerRun != nil && *over.MaxRequestsPerRun > 0 {
		out.MaxRequestsPerRun = *over.MaxRequestsPerRun
		out.Source["max_requests_per_run"] = EngagementFromTarget
	}

	out.RequestTimeoutS = engagementDefaultTimeoutS
	out.Source["request_timeout_s"] = EngagementFromDefault
	if over.RequestTimeoutS != nil && *over.RequestTimeoutS > 0 {
		out.RequestTimeoutS = *over.RequestTimeoutS
		out.Source["request_timeout_s"] = EngagementFromTarget
	}

	out.MaxRedirects = engagementDefaultMaxRedirects
	out.Source["max_redirects"] = EngagementFromDefault
	if over.MaxRedirects != nil && *over.MaxRedirects >= 0 {
		out.MaxRedirects = *over.MaxRedirects
		out.Source["max_redirects"] = EngagementFromTarget
	}

	out.FollowRedirects = true
	out.Source["follow_redirects"] = EngagementFromDefault
	if over.FollowRedirects != nil {
		out.FollowRedirects = *over.FollowRedirects
		out.Source["follow_redirects"] = EngagementFromTarget
	}

	// send_cookies is the ONE column that cannot be NULL - it is NOT NULL DEFAULT FALSE, because a
	// nullable "should this scanner carry your session" is a three-state answer to a two-state
	// question. The cost is that the usual nil-means-inherit test cannot work here: every target that
	// has ever been saved for any reason has a send_cookies value.
	//
	// So provenance is decided by the VALUE, not by the pointer. Only `true` can have been chosen -
	// nobody arrives at it by accident, the API refuses it without an explicit acknowledgement.
	// `false` is reported as the default because that is what it is, and because "set for this
	// target" against a box the operator never touched is exactly the sort of provenance that makes
	// an operator stop believing the rest of the column.
	out.SendCookies = false
	out.Source["send_cookies"] = EngagementFromDefault
	if over.SendCookies != nil && *over.SendCookies {
		out.SendCookies = true
		out.Source["send_cookies"] = EngagementFromTarget
	}

	out.ProgrammeNotes = ""
	out.Source["programme_notes"] = EngagementFromDefault
	if over.ProgrammeNotes != nil && strings.TrimSpace(*over.ProgrammeNotes) != "" {
		out.ProgrammeNotes = strings.TrimSpace(*over.ProgrammeNotes)
		out.Source["programme_notes"] = EngagementFromTarget
	}

	return out
}

// SplitEngagementHeader parses the global user_settings.custom_header, which is stored as one string
// in the shape "X-Custom-Header: my-custom-value".
//
// Split on the FIRST colon. A header value may contain colons (a URL, a timestamp); a header name
// may not. Splitting on the last, or on all of them, silently truncates the value.
func SplitEngagementHeader(raw string) (name, value string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	i := strings.Index(raw, ":")
	if i <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(raw[:i])
	value = strings.TrimSpace(raw[i+1:])
	if name == "" || value == "" {
		return "", "", false
	}
	if validateEngagementHeaderName(name) != nil || validateEngagementHeaderValue(value) != nil {
		return "", "", false
	}
	return name, value, true
}

// ---------------------------------------------------------------------------
// Applying it to a run
// ---------------------------------------------------------------------------

// IsFromTarget reports whether a field's effective value is a real per-target override, as opposed to
// something inherited from user_settings or filled in from a framework built-in.
//
// It exists because "the resolved value" and "the programme's rule" are not the same thing, and one
// caller already treated them as one. See ApplyEngagementToDetection.
func (c ResolvedEngagementConfig) IsFromTarget(field string) bool {
	return c.Source[field] == EngagementFromTarget
}

// ApplyEngagementToDetection folds a target's engagement rules into a requested detection config.
//
// ONE RULE, APPLIED TO EVERY TRAFFIC-BOUNDING FIELD:
//
//	the run did not ask   ->  the engagement value IS the value      (it is the default)
//	the run did ask       ->  the stricter of the two wins, BUT ONLY IF THE TARGET SET ONE
//
// Both halves are needed. Default-only would mean a programme that caps at 45 requests per minute is
// silently ignored the moment a client sends any rps at all, which every client does. Ceiling-only
// would mean a per-target setting the operator can see on screen never takes effect, because
// ValidateFlowDetectionConfig fills the run's zero fields with framework defaults before anyone
// looks at the engagement config - a control that reports success and does nothing.
//
// So this runs BEFORE ValidateFlowDetectionConfig, while an unset field is still distinguishable
// from a set one.
//
// ============================================================================
// THE CEILING ONLY BITES WHEN THE TARGET ACTUALLY SET ONE. IsFromTarget, EVERY TIME.
// ============================================================================
//
// This is the correction to a bug that shipped in the first cut of this file, and it is worth stating
// plainly because it is easy to reintroduce.
//
// ResolveEngagementFrom ALWAYS returns a number. When the target overrides nothing, that number is
// the framework's own default - max_rps 1, max_requests 250, timeout 15s, 5 redirects - with
// Source[field] == "default". The first version clamped against that number unconditionally, so on
// every target that had never been configured (which is all of them), a client asking for 8 rps got
// 1, a client asking for 900 requests got 250, and the Detect Flows rate control was dead above the
// default it opened on. flowDetectMaxRPS is 10; nobody could reach 2.
//
// A framework default is not a programme rule. Clamping to it is a control that shows a number on
// screen and changes nothing on the wire - the exact failure the paragraph above says this ordering
// exists to prevent, reintroduced one field lower down.
//
// The ceiling therefore consults PROVENANCE, not the value. An inherited or defaulted field still
// FILLS an unset run field (that is what a default is for) but never lowers one the run asked for;
// only a value the operator actually put on this target can do that. The framework's own hard
// ceilings are unaffected: ValidateFlowDetectionConfig runs immediately after this and still applies
// flowDetectMaxRPS, flowDetectHardMaxRequests, flowDetectHardMaxRedirects and flowDetectMaxTimeoutS.
//
// WHAT IT CANNOT DO: it cannot widen anything. There is no path here that adds a method, enables a
// request body, turns on a cookie jar, or raises a hard framework ceiling. ValidateFlowDetectionConfig
// still runs afterwards and still refuses every shape it refused before.
func ApplyEngagementToDetection(cfg FlowDetectionConfig, eng ResolvedEngagementConfig) FlowDetectionConfig {
	out := cfg

	if out.RPS <= 0 {
		out.RPS = eng.MaxRPS
	} else if eng.IsFromTarget("max_rps") && eng.MaxRPS > 0 && out.RPS > eng.MaxRPS {
		out.RPS = eng.MaxRPS
	}

	if out.MaxRequests <= 0 {
		out.MaxRequests = eng.MaxRequestsPerRun
	} else if eng.IsFromTarget("max_requests_per_run") &&
		eng.MaxRequestsPerRun > 0 && out.MaxRequests > eng.MaxRequestsPerRun {
		out.MaxRequests = eng.MaxRequestsPerRun
	}

	if out.TimeoutS <= 0 {
		out.TimeoutS = eng.RequestTimeoutS
	} else if eng.IsFromTarget("request_timeout_s") &&
		eng.RequestTimeoutS > 0 && out.TimeoutS > eng.RequestTimeoutS {
		// A longer timeout holds a connection open on the target for longer, so it is bounded the
		// same way as everything else rather than being treated as a private client detail.
		out.TimeoutS = eng.RequestTimeoutS
	}

	if out.MaxRedirects <= 0 {
		out.MaxRedirects = eng.MaxRedirects
	} else if eng.IsFromTarget("max_redirects") && out.MaxRedirects > eng.MaxRedirects {
		out.MaxRedirects = eng.MaxRedirects
	}

	// AND, not "the run wins". follow_redirects:false on the target is a programme rule; a client
	// asking for true must not overturn it. Gated on provenance like the rest, though the default is
	// true so an inherited value could never have forced this branch anyway.
	if eng.IsFromTarget("follow_redirects") && !eng.FollowRedirects {
		follow := false
		out.FollowRedirects = &follow
		out.MaxRedirects = 0
	}

	return out
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// EngagementUpdateRequest is the PUT body. The override fields are pointers so an omitted field is
// distinguishable from a cleared one; AcknowledgeStateRisk is not an override and is never stored.
type EngagementUpdateRequest struct {
	EngagementOverrides
	AcknowledgeStateRisk bool `json:"acknowledge_state_risk"`
}

// ValidateEngagementUpdate refuses the shapes that would be dangerous, wrong, or unsendable, and
// returns a normalised copy.
func ValidateEngagementUpdate(req EngagementUpdateRequest) (EngagementOverrides, error) {
	out := req.EngagementOverrides

	// The name and the value are validated as a PAIR, because half a header is never a thing anybody
	// wants and both halves of the failure are silent: a name with no value sends an empty header
	// that looks configured on screen and identifies nobody on the wire, and a value with no name
	// sends nothing at all while the operator's box has text in it.
	//
	// An OMITTED name (nil) is not the same as an empty one. nil means "leave whatever is stored",
	// which is how a client updates only the value; an explicit "" means "clear it", which is only
	// coherent if the value is being cleared too.
	if out.CustomHeaderName != nil {
		name := strings.TrimSpace(*out.CustomHeaderName)
		switch {
		case name != "":
			if err := validateEngagementHeaderName(name); err != nil {
				return out, err
			}
			if out.CustomHeaderValue == nil || strings.TrimSpace(*out.CustomHeaderValue) == "" {
				return out, fmt.Errorf(
					"custom_header_name is set to %q but custom_header_value is empty. A programme "+
						"header sent with no value looks configured on screen and identifies nobody "+
						"on the wire", name)
			}
		case out.CustomHeaderValue != nil && strings.TrimSpace(*out.CustomHeaderValue) != "":
			return out, errors.New(
				"custom_header_value was given with an empty custom_header_name. A value with no " +
					"header name is never sent, so the box would have text in it and the wire would " +
					"carry nothing. Send both, or clear both")
		}
		out.CustomHeaderName = &name
	}
	if out.CustomHeaderValue != nil {
		value := strings.TrimSpace(*out.CustomHeaderValue)
		if value != "" {
			if err := validateEngagementHeaderValue(value); err != nil {
				return out, err
			}
		}
		out.CustomHeaderValue = &value
	}

	if out.UserAgentMode != nil {
		mode := strings.ToLower(strings.TrimSpace(*out.UserAgentMode))
		if mode == "" {
			mode = engagementDefaultUserAgentMode
		}
		if !isEngagementUserAgentMode(mode) {
			return out, fmt.Errorf(
				"user_agent_mode must be 'replace' or 'append', not %q. 'replace' means "+
					"custom_user_agent IS the User-Agent; 'append' means it is a tag added to the end "+
					"of the inherited one, which is how a programme that wants a research tag on a "+
					"normal browser User-Agent is expressed", *out.UserAgentMode)
		}
		out.UserAgentMode = &mode
	}

	if out.CustomUserAgent != nil {
		ua := strings.TrimSpace(*out.CustomUserAgent)
		if err := validateEngagementHeaderValue(ua); err != nil {
			return out, fmt.Errorf("custom_user_agent: %w", err)
		}
		out.CustomUserAgent = &ua
	}

	if out.MaxRPS != nil {
		if *out.MaxRPS <= 0 || *out.MaxRPS > engagementMaxRPSCeiling {
			return out, fmt.Errorf(
				"max_rps must be greater than 0 and at most %.0f, got %v", engagementMaxRPSCeiling, *out.MaxRPS)
		}
	}
	if out.MaxRequestsPerRun != nil {
		if *out.MaxRequestsPerRun <= 0 || *out.MaxRequestsPerRun > engagementMaxRequestsCeiling {
			return out, fmt.Errorf(
				"max_requests_per_run must be between 1 and %d, got %d",
				engagementMaxRequestsCeiling, *out.MaxRequestsPerRun)
		}
	}
	if out.RequestTimeoutS != nil {
		if *out.RequestTimeoutS <= 0 || *out.RequestTimeoutS > engagementMaxTimeoutS {
			return out, fmt.Errorf(
				"request_timeout_s must be between 1 and %d, got %d",
				engagementMaxTimeoutS, *out.RequestTimeoutS)
		}
	}
	if out.MaxRedirects != nil {
		if *out.MaxRedirects < 0 || *out.MaxRedirects > engagementMaxRedirectsCap {
			return out, fmt.Errorf(
				"max_redirects must be between 0 and %d, got %d",
				engagementMaxRedirectsCap, *out.MaxRedirects)
		}
	}
	if out.ProgrammeNotes != nil && len(*out.ProgrammeNotes) > engagementMaxNotesLen {
		return out, fmt.Errorf("programme_notes is limited to %d characters", engagementMaxNotesLen)
	}

	// THE ACKNOWLEDGEMENT. Turning cookies on makes a scanner act as the operator's logged-in user:
	// it can change state, and on at least one target already in this database it can dispatch a
	// one-time code to a real customer. Refused rather than defaulted, so the risk is named and
	// somebody has to answer it in the same request that carries the change.
	if out.SendCookies != nil && *out.SendCookies && !req.AcknowledgeStateRisk {
		return out, errors.New(
			"send_cookies cannot be enabled without acknowledge_state_risk:true in the same request. " +
				"A scanner that carries your session acts AS the authenticated user: it can change " +
				"data, and on some targets a single GET to the wrong endpoint dispatches a one-time " +
				"code to a real customer. Send acknowledge_state_risk:true to confirm you intend that")
	}

	return out, nil
}

// engagementHeaderNameDenied is the set of header names an engagement config may never set.
//
// cookie and authorization are credentials: ScanRequest.Headers is applied with Set AFTER the
// framework's own headers, so either would reach the wire intact and turn an unauthenticated
// scanner into an authenticated one, bypassing the no-credentials rail without touching the code
// that enforces it.
//
// user-agent has its own field with its own mode. Allowing it here would give one value two homes,
// and the one that wins would depend on map iteration order.
var engagementHeaderNameDenied = map[string]string{
	"cookie": "Cookie is a credential. Active detection sends no cookies by design; a session for a " +
		"sender that supports one belongs in the auth flow, not in a header field.",
	"authorization": "Authorization is a credential. It belongs in the target's auth material, which " +
		"is scoped and withheld off-host, not in a header that is sent to everything.",
	"user-agent": "User-Agent has its own field on this config, with a replace/append mode. Two " +
		"places to set one value is how they end up disagreeing.",
	"host": "Host is derived from the URL. Overriding it sends a request to one server addressed to " +
		"another, which is a routing attack rather than a programme identifier.",
	"content-length": "Content-Length describes a body. Nothing here has one.",
}

func validateEngagementHeaderName(name string) error {
	if name == "" {
		return errors.New("the header name is empty")
	}
	if reason, denied := engagementHeaderNameDenied[strings.ToLower(name)]; denied {
		return fmt.Errorf("%s cannot be set as a custom header. %s", name, reason)
	}
	// RFC 9110 token. Anything outside it - a space, a colon, a CR - either fails at the transport
	// or splits the request.
	for i := 0; i < len(name); i++ {
		c := name[i]
		isTok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
		if !isTok {
			return fmt.Errorf(
				"%q is not a usable header name: %q is not allowed in one. Use letters, digits and "+
					"-_. for example X-HackerOne-Research", name, string(rune(c)))
		}
	}
	return nil
}

func validateEngagementHeaderValue(value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return errors.New(
			"a header value cannot contain a carriage return or a newline. That is request splitting, " +
				"and it would send something other than what is on screen")
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 && value[i] != '\t' {
			return errors.New("a header value cannot contain control characters")
		}
	}
	return nil
}

func isEngagementUserAgentMode(m string) bool {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "replace", "append":
		return true
	}
	return false
}

// EngagementFieldColumns maps the field names used by the API to their columns. It is also the
// allowlist for DELETE .../engagement/{field}: a field not in this map is not clearable, which is
// what keeps an operator-supplied path segment out of the SQL text.
var EngagementFieldColumns = map[string]string{
	"custom_header_name":   "custom_header_name",
	"custom_header_value":  "custom_header_value",
	"custom_user_agent":    "custom_user_agent",
	"user_agent_mode":      "user_agent_mode",
	"max_rps":              "max_rps",
	"max_requests_per_run": "max_requests_per_run",
	"request_timeout_s":    "request_timeout_s",
	"max_redirects":        "max_redirects",
	"follow_redirects":     "follow_redirects",
	"send_cookies":         "send_cookies",
	"programme_notes":      "programme_notes",
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

// LoadEngagementOverrides reads a target's row, or nil when it has none.
//
// A MISSING ROW IS NOT AN ERROR; a failed read IS. The difference matters: no row means "this target
// inherits everything", which is a legitimate and common state, while a read failure means we do not
// know what this programme requires. Callers that are about to send traffic must fail closed on the
// second and carry on with the first.
func LoadEngagementOverrides(scopeTargetID string) (*EngagementOverrides, error) {
	var o EngagementOverrides
	err := dbPool.QueryRow(context.Background(), `
		SELECT custom_header_name, custom_header_value, custom_user_agent, user_agent_mode,
		       max_rps, max_requests_per_run, request_timeout_s, max_redirects,
		       follow_redirects, send_cookies, programme_notes
		  FROM scope_target_engagement_config
		 WHERE scope_target_id = $1`, scopeTargetID).Scan(
		&o.CustomHeaderName, &o.CustomHeaderValue, &o.CustomUserAgent, &o.UserAgentMode,
		&o.MaxRPS, &o.MaxRequestsPerRun, &o.RequestTimeoutS, &o.MaxRedirects,
		&o.FollowRedirects, &o.SendCookies, &o.ProgrammeNotes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// LoadEngagementGlobals reads the user_settings row that is the middle tier of the resolution order.
//
// The error is RETURNED rather than swallowed into empty strings, which is what GetCustomHTTPSettings
// does. A sender that cannot tell "this programme requires no header" from "we could not find out
// whether it does" will send traffic to DailyPay without the header their brief calls mandatory and
// report success.
func LoadEngagementGlobals() (EngagementGlobals, error) {
	var ua, header *string
	err := dbPool.QueryRow(context.Background(),
		`SELECT custom_user_agent, custom_header FROM user_settings LIMIT 1`).Scan(&ua, &header)
	if errors.Is(err, pgx.ErrNoRows) {
		// The schema seeds exactly one row, so this means somebody deleted it. Nothing global is
		// configured, which is a real and answerable state rather than a failure.
		return EngagementGlobals{}, nil
	}
	if err != nil {
		return EngagementGlobals{}, err
	}
	g := EngagementGlobals{}
	if ua != nil {
		g.CustomUserAgent = *ua
	}
	if header != nil {
		g.CustomHeader = *header
	}
	return g, nil
}

// ResolveEngagementConfig is the function every sender calls: the effective engagement config for
// one target, with per-field provenance.
func ResolveEngagementConfig(scopeTargetID string) (ResolvedEngagementConfig, error) {
	over, err := LoadEngagementOverrides(scopeTargetID)
	if err != nil {
		return ResolvedEngagementConfig{}, fmt.Errorf(
			"the engagement config for this target could not be read: %w", err)
	}
	glob, err := LoadEngagementGlobals()
	if err != nil {
		return ResolvedEngagementConfig{}, fmt.Errorf(
			"the global HTTP settings could not be read: %w", err)
	}
	return ResolveEngagementFrom(over, glob), nil
}

// ---------------------------------------------------------------------------
// GET /flow-config/{scope_target_id}/engagement
// ---------------------------------------------------------------------------

func GetEngagementConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	over, err := LoadEngagementOverrides(scopeTargetID)
	if err != nil {
		log.Printf("[ENGAGEMENT] Failed to read overrides for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The engagement config could not be read: "+err.Error())
		return
	}
	glob, err := LoadEngagementGlobals()
	if err != nil {
		log.Printf("[ENGAGEMENT] Failed to read global settings: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The global HTTP settings could not be read: "+err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"effective": ResolveEngagementFrom(over, glob),
		// The raw override row as well as the resolved answer, so the UI can render an empty box for
		// "inherited" and a filled one for "set here" rather than guessing from the resolved value.
		"overrides":     over,
		"has_overrides": over != nil,
		"global": map[string]string{
			"custom_header":     glob.CustomHeader,
			"custom_user_agent": glob.CustomUserAgent,
		},
	})
}

// ---------------------------------------------------------------------------
// PUT /flow-config/{scope_target_id}/engagement
// ---------------------------------------------------------------------------

// PutEngagementConfig upserts the overrides.
//
// A FIELD THE BODY DID NOT MENTION IS LEFT ALONE. Every column is written as
// COALESCE($n, existing), so a client that sends only max_rps does not wipe the header the operator
// set last week. This codebase has already shipped the other behaviour once, on a different table,
// and a partial PUT wiped seven columns across fifty-eight rows before anybody noticed. Clearing a
// field is the separate DELETE, which is explicit and cannot happen by omission.
func PutEngagementConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var req EngagementUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Body must be JSON: "+err.Error())
		return
	}

	over, err := ValidateEngagementUpdate(req)
	if err != nil {
		code := "invalid_config"
		if req.SendCookies != nil && *req.SendCookies && !req.AcknowledgeStateRisk {
			code = "state_risk_not_acknowledged"
		}
		writeJSONError(w, http.StatusBadRequest, code, err.Error())
		return
	}

	_, err = dbPool.Exec(context.Background(), `
		INSERT INTO scope_target_engagement_config
		  (scope_target_id, custom_header_name, custom_header_value, custom_user_agent,
		   user_agent_mode, max_rps, max_requests_per_run, request_timeout_s, max_redirects,
		   follow_redirects, send_cookies, programme_notes, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE($11,FALSE),$12,NOW(),NOW())
		ON CONFLICT (scope_target_id) DO UPDATE SET
		  custom_header_name   = COALESCE(EXCLUDED.custom_header_name,   scope_target_engagement_config.custom_header_name),
		  custom_header_value  = COALESCE(EXCLUDED.custom_header_value,  scope_target_engagement_config.custom_header_value),
		  custom_user_agent    = COALESCE(EXCLUDED.custom_user_agent,    scope_target_engagement_config.custom_user_agent),
		  user_agent_mode      = COALESCE(EXCLUDED.user_agent_mode,      scope_target_engagement_config.user_agent_mode),
		  max_rps              = COALESCE(EXCLUDED.max_rps,              scope_target_engagement_config.max_rps),
		  max_requests_per_run = COALESCE(EXCLUDED.max_requests_per_run, scope_target_engagement_config.max_requests_per_run),
		  request_timeout_s    = COALESCE(EXCLUDED.request_timeout_s,    scope_target_engagement_config.request_timeout_s),
		  max_redirects        = COALESCE(EXCLUDED.max_redirects,        scope_target_engagement_config.max_redirects),
		  follow_redirects     = COALESCE(EXCLUDED.follow_redirects,     scope_target_engagement_config.follow_redirects),
		  programme_notes      = COALESCE(EXCLUDED.programme_notes,      scope_target_engagement_config.programme_notes),
		  -- send_cookies is NOT COALESCEd from EXCLUDED unconditionally: $11 is NULL when the body
		  -- omitted it, and NOT NULL columns cannot take a NULL, so the existing value is kept
		  -- explicitly. Turning it OFF is therefore possible with send_cookies:false, which needs no
		  -- acknowledgement, while turning it ON still needs one.
		  send_cookies         = COALESCE($11, scope_target_engagement_config.send_cookies),
		  updated_at           = NOW()`,
		scopeTargetID,
		nullableString(over.CustomHeaderName), nullableString(over.CustomHeaderValue),
		nullableString(over.CustomUserAgent), nullableString(over.UserAgentMode),
		over.MaxRPS, over.MaxRequestsPerRun, over.RequestTimeoutS, over.MaxRedirects,
		over.FollowRedirects, over.SendCookies, nullableString(over.ProgrammeNotes))
	if err != nil {
		log.Printf("[ENGAGEMENT] Failed to save config for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The engagement config could not be saved: "+err.Error())
		return
	}

	resolved, err := ResolveEngagementConfig(scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	log.Printf("[ENGAGEMENT] Config saved for %s (header %q, ua mode %s, %.2f rps)",
		scopeTargetID, resolved.CustomHeaderName, resolved.UserAgentMode, resolved.MaxRPS)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"effective": resolved,
	})
}

// nullableString turns an empty override into a SQL NULL, which is what "no override" means in this
// schema. Without it, clearing a box in the UI would store an empty string, which resolves as a
// deliberate empty value rather than as an inheritance - and the operator would see "set for this
// target: (nothing)" where they expected the global.
func nullableString(s *string) interface{} {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil
	}
	return strings.TrimSpace(*s)
}

// ---------------------------------------------------------------------------
// DELETE /flow-config/{scope_target_id}/engagement/{field}
// ---------------------------------------------------------------------------

// DeleteEngagementConfigField clears ONE override so the field falls back to the global, or to the
// built-in default when there is no global.
func DeleteEngagementConfigField(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	field := strings.ToLower(strings.TrimSpace(vars["field"]))
	column, ok := EngagementFieldColumns[field]
	if !ok {
		// The allowlist is what keeps a path segment out of the SQL text. There is no branch below
		// that interpolates anything the operator typed.
		writeJSONError(w, http.StatusBadRequest, "unknown_field",
			"There is no engagement field called "+field)
		return
	}

	// send_cookies is NOT NULL, so "clear" means "back to the safe default" rather than NULL. Which
	// is the same thing for this column: false is both the default and the safe value.
	setClause := column + " = NULL"
	if column == "send_cookies" {
		setClause = "send_cookies = FALSE"
	}

	// THE HEADER IS ONE THING WITH TWO COLUMNS, so clearing either end clears both. Otherwise
	// clearing the name leaves an orphaned value: the operator's box still has "rs0n2" in it, the
	// resolver falls back to the global, and the screen shows a value that is not what gets sent.
	// Verified against the live schema - a single-column clear really does leave the other behind.
	if column == "custom_header_name" || column == "custom_header_value" {
		setClause = "custom_header_name = NULL, custom_header_value = NULL"
	}

	tag, err := dbPool.Exec(context.Background(),
		`UPDATE scope_target_engagement_config
		    SET `+setClause+`, updated_at = NOW()
		  WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		log.Printf("[ENGAGEMENT] Failed to clear %s for %s: %v", field, scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The override could not be cleared: "+err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		// No row means the target already inherits everything. Reported as success with a note
		// rather than as a 404: the operator asked for "this field should inherit" and it does.
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"note":    "This target had no overrides, so " + field + " was already inherited.",
		})
		return
	}

	resolved, err := ResolveEngagementConfig(scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	log.Printf("[ENGAGEMENT] Override %s cleared for %s; now %s",
		field, scopeTargetID, resolved.Source[field])

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"cleared":   field,
		"now_from":  resolved.Source[field],
		"effective": resolved,
	})
}
