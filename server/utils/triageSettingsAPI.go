package utils

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"ars0n-framework-v2-server/utils/internal/triagecap"
	"ars0n-framework-v2-server/utils/triage"

	"github.com/gorilla/mux"
)

// Per-target settings for the Investigate triage run: which classes run, how hard, how fast, and
// the operator's own payloads.
//
// WHERE THIS LIVES AND WHY IT IS NOT A NEW TABLE. vector_tool_settings (scope_target_id, tool,
// settings jsonb) is already the per-target settings store for every scanner in the URL workflow,
// and loadVectorSettings in vectorSettings.go is already the reader. Triage is one more tool key in
// it. A second store would be a second place for a setting to be stale, and the staleness would
// only be visible as a run that behaved unlike the screen that configured it.
//
// WHAT THE CLASS LIST IS BUILT FROM. triage.RegisteredClassifiers(), never a list in this file.
// Ten classes ship today out of twenty-seven planned, and a hardcoded list is a screen that goes
// stale the day class eleven registers itself, which is the same failure as a class silently
// missing from a run: a whole attack class the operator believes was covered.
//
// AND THE ONE CLASS THAT IS FILTERED OUT OF IT. triageclasses/example.go registers itself under
// the reserved id ClassExample. It says of itself that it plans nothing, so not one request
// leaves the process because of it and every verdict it emits is not_planned. It is registered
// because a boundary nothing has ever been registered through is a boundary nobody has tested,
// and that is a reason to register it, not a reason to offer the operator a switch for it.
// Offered, it rendered as "example | EXAMPLE | probes 1", on by default, and the count above the
// list read "11 of 11 classes enabled": one more attack class the operator believes was covered.
// TriageClassIsReserved is the filter, and it is applied HERE, on the server, rather than in the
// screen, so that every consumer of the vocabulary gets the same ten rather than each one
// remembering to drop the eleventh.
//
// THE CUSTOM PAYLOAD RULE, WHICH IS THE PART THAT MATTERS. The framework enforces that no two
// classes ship byte-equal payloads, because a payload rejected by a validator or a WAF cannot be
// attributed to either class, so one of them records clean for a test it never ran. A payload the
// operator types obeys the same law or it is refused. The check is triage.CheckPayloadIsolation,
// run over the real registry with the custom probes folded in, so a custom payload is held to
// exactly the constant the shipped ones are held to rather than to a second, weaker copy of it.
//
// AND THE SECOND REFUSAL. A payload that cannot reach the insertion point it targets is not a
// probe either. A cookie payload carrying a semicolon is delivered but split by any RFC 6265
// parser, and a header payload carrying CR or LF is refused by the transport. Both are run through
// the real encoder at save time, so the operator learns at the keyboard rather than from a silent
// clean result hours later.

// TriageSettingsTool is the vector_tool_settings key these settings are stored under.
const TriageSettingsTool = "triage-investigate"

// ---------------------------------------------------------------------------------------------
// 1. THE STORED SHAPE
// ---------------------------------------------------------------------------------------------

// TriageClassSetting is one attack class's entry. Tier and MaxRisk are per class because the
// classes are not equally expensive: SQL's full ladder is a different purchase from traversal's.
type TriageClassSetting struct {
	Enabled bool   `json:"enabled"`
	Tier    string `json:"tier"`     // reduced | full | opt_in
	MaxRisk string `json:"max_risk"` // R0 | R1 | R2 | R3
}

// TriagePacing is the run's rate and its probe budgets.
//
// Every budget here is a cap that produces a NAMED unknown when it bites, never a shortened clean.
// Zero is therefore refused for the two probe budgets: TriageBudget.Exhausted() is true the moment
// a remaining count reaches zero, so a budget of zero is a run where every slot reports exhausted
// and nothing is tested.
type TriagePacing struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	Concurrency       int     `json:"concurrency"`
	PerSlotProbes     int     `json:"per_slot_probes"`
	PerRunProbes      int     `json:"per_run_probes"`
	MutatingAllowance int     `json:"mutating_allowance"`
	BrowserAllowance  int     `json:"browser_allowance"`
	// RespectTargetBudget makes the runner read the target's own X-Ratelimit headers and pace to
	// them. See vectorRateLimit.go: the measured estate publishes 200 per 60 seconds per endpoint.
	RespectTargetBudget bool `json:"respect_target_budget"`
}

// TriageOOB is the out-of-band collaborator. Mode empty means none, and the classes that need one
// then emit no_collaborator rather than clean.
type TriageOOB struct {
	Mode          string `json:"mode"` // "" | wildcard_dns | http_path
	Base          string `json:"base"`
	ServesContent bool   `json:"serves_content"`
	GraceSeconds  int    `json:"grace_seconds"`
}

// Detection modes a custom payload may declare. A payload with no way to tell a hit from a miss is
// not a probe, so the mode is required and there is no default.
const (
	TriageDetectInherit      = "inherit"       // the owning class's own oracle judges it
	TriageDetectReflect      = "reflect"       // the payload's marker comes back in the response
	TriageDetectBodyRegex    = "body_regex"    // Pattern must match the response body
	TriageDetectBodyContains = "body_contains" // Pattern appears literally in the response body
	TriageDetectStatusIn     = "status_in"     // the response status is in Statuses
	TriageDetectTimeDelay    = "time_delay"    // the response is DelayMS slower than the baseline
)

// TriageDetection is how a hit is told from a miss for one custom payload.
type TriageDetection struct {
	Mode     string `json:"mode"`
	Pattern  string `json:"pattern,omitempty"`
	Statuses []int  `json:"statuses,omitempty"`
	DelayMS  int    `json:"delay_ms,omitempty"`
}

// TriageCustomPayload is one payload the operator added.
//
// Encoding exists so a payload can carry bytes that are not valid UTF-8. The registry declares
// payloads as []byte for the same reason: an overlong-UTF-8 probe written as a Go string literal
// is silently re-encoded to its shortest form and then tests something other than what was asked.
type TriageCustomPayload struct {
	ID        string          `json:"id"`
	Class     string          `json:"class"` // a registered class key, lowercased, e.g. "sql"
	Label     string          `json:"label"`
	Payload   string          `json:"payload"`
	Encoding  string          `json:"encoding"` // utf8 (default) | base64
	Points    []string        `json:"points"`   // slot kinds: query, body, header, cookie, path
	Encoder   string          `json:"encoder"`  // "" lets the slot kind's default encoder resolve
	Tier      string          `json:"tier"`
	Risk      string          `json:"risk"`
	MarkerPos string          `json:"marker_pos"` // prefix (default) | suffix | inline
	Detection TriageDetection `json:"detection"`
	Enabled   bool            `json:"enabled"`
	Notes     string          `json:"notes"`
}

// TriageSessionRenewal is the operator's choice to keep the authenticated session alive for the
// length of a run, and it is the one setting in this document that the operator is NOT always
// allowed to make.
//
// THE MEASUREMENT. On the estate this layer was built against the bearer is a fifteen minute JWT
// and a full run takes twenty nine minutes, so more than half of every authenticated run was sent
// with a credential that had already died. Round 10 made the runner substitute the freshest
// captured credential at send time; that is the mechanism. This is the part the operator sees.
//
// THE RULE. Enabled may only be true once the framework has PERFORMED a refresh and watched a
// different working credential come back. Not a refresh_token field in a body, not a recorded
// auth flow, not a mint endpoint in the corpus: those are RefreshAvailable and they are exactly
// the "vulnerable IF" with the IF unproven that this codebase refuses everywhere else. The gate
// is EvaluateTriageRenewalGate and the refusal is in ValidateTriageSettingsWithRenewal.
//
// IntervalSeconds is zero by default and MEANS "derive it from the measured lifetime", which is
// TriageRenewalIntervalFor. It is not a hidden default of some number: zero with no measured TTL
// is refused, because a renewal schedule invented here would under-run or over-run silently and
// the operator would have no way to tell which.
type TriageSessionRenewal struct {
	Enabled bool `json:"enabled"`
	// TokenID is the credential to renew. Empty with Enabled true is refused rather than resolved
	// to "the active one": a target routinely holds several credentials and renewing the wrong one
	// leaves the scan authenticated as nobody while the screen says renewal is on.
	TokenID string `json:"token_id"`
	// IntervalSeconds of zero means derive from the measured TTL. A non-zero value is the
	// OPERATOR'S figure and is recorded and rendered as such, never as a measurement.
	IntervalSeconds int `json:"interval_seconds"`
	// ProvenAt is the refresh proof this setting was armed against, copied from the gate at save
	// time. It is stored so a later read can say "armed against a proof taken at T" rather than
	// implying the proof is current; whether it IS current is decided by the gate on every read.
	ProvenAt time.Time `json:"proven_at"`
}

// TriageInvestigateSettings is the whole document stored under TriageSettingsTool.
type TriageInvestigateSettings struct {
	Tier           string                        `json:"tier"`
	Classes        map[string]TriageClassSetting `json:"classes"`
	Pacing         TriagePacing                  `json:"pacing"`
	OOB            TriageOOB                     `json:"oob"`
	CustomPayloads []TriageCustomPayload         `json:"custom_payloads"`
	SessionRenewal TriageSessionRenewal          `json:"session_renewal"`
}

// ---------------------------------------------------------------------------------------------
// 2. THE VOCABULARY, BUILT FROM THE REGISTRY
// ---------------------------------------------------------------------------------------------

// TriageClassInfo is one row of the class list the form is generated from.
type TriageClassInfo struct {
	ID         int    `json:"id"`
	Key        string `json:"key"`
	Name       string `json:"name"`
	ProbeCount int    `json:"probe_count"`
	// Tiers and Risks are the DISTINCT values this class's own probes declare, so a class with one
	// tier renders without a depth control instead of with a control that changes nothing.
	Tiers []string `json:"tiers"`
	Risks []string `json:"risks"`
	// Points is the slot kinds the class reaches, always or conditionally.
	Points []string `json:"points"`
	// Unreachable is slot kind to the class's own reason. It is served because a class absent from
	// a point with no reason reads as an oversight, and the two are the same pixel.
	Unreachable map[string]string `json:"unreachable"`
}

// TriageClassKey is the stable key a class is addressed by in the settings document. It is derived
// from the register in triage/types.go, so it cannot drift from the class list.
func TriageClassKey(id triage.ClassID) string { return strings.ToLower(id.String()) }

// TriageClassIsReserved reports whether a registered id is a RESERVED PLACEHOLDER rather than an
// attack class.
//
// It is a function over the id and not a list of keys, because a key is a string somebody has to
// type twice. ClassExample is reserved in triage/types.go for exactly this, so the question has
// one answer and it is derived from the register.
//
// A reserved class is left OUT of the vocabulary, out of the defaults and out of the enabled
// count. It stays in the registry, so the isolation law still runs over its payload and the
// runner still emits its not_planned rows: this filter removes a switch that promised coverage,
// and removes nothing that was ever measured.
func TriageClassIsReserved(id triage.ClassID) bool {
	return id == triage.ClassExample
}

// TriageClassVocabulary is every REGISTERED class, ascending by id. Not every class in the
// register: an unregistered class cannot run, and offering a switch for it would promise coverage
// the runner cannot deliver.
func TriageClassVocabulary() []TriageClassInfo {
	reg := triage.RegisteredClassifiers()
	ids := make([]triage.ClassID, 0, len(reg))
	for id := range reg {
		if TriageClassIsReserved(id) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	out := make([]TriageClassInfo, 0, len(ids))
	for _, id := range ids {
		c := reg[id]
		info := TriageClassInfo{
			ID:          int(id),
			Key:         TriageClassKey(id),
			Name:        id.String(),
			Unreachable: map[string]string{},
		}
		tiers, risks := map[string]bool{}, map[string]bool{}
		for _, p := range c.Probes() {
			info.ProbeCount++
			if p.Tier != "" {
				tiers[string(p.Tier)] = true
			}
			if p.Risk != "" {
				risks[string(p.Risk)] = true
			}
		}
		info.Tiers, info.Risks = sortedTriageFlagKeys(tiers), sortedTriageFlagKeys(risks)
		for _, k := range triage.AllSlotKinds() {
			r := c.Reaches(k, "")
			if r.Reach == triage.ReachNever {
				info.Unreachable[string(k)] = r.Reason
				continue
			}
			info.Points = append(info.Points, string(k))
		}
		out = append(out, info)
	}
	return out
}

// TriageSettingsVocabulary is everything the form needs to render itself without a second copy of
// any of these lists living in the client.
func TriageSettingsVocabulary() map[string]any {
	return map[string]any{
		"classes":    TriageClassVocabulary(),
		"tiers":      []string{string(triage.TierReduced), string(triage.TierFull), string(triage.TierOptIn)},
		"risks":      []string{string(triage.RiskR0), string(triage.RiskR1), string(triage.RiskR2), string(triage.RiskR3)},
		"slot_kinds": triageSettableSlotKinds(),
		"encoders":   triageSettableEncoders(),
		"oob_modes":  []string{string(triage.OOBNone), string(triage.OOBWildcardDNS), string(triage.OOBHTTPPath)},
		"encodings":  []string{"utf8", "base64"},
		// TriageMarkerPosNone is offered alongside the three placements because a payload whose
		// grammar cannot carry 16 extra bytes has to be authorable. Without it the modal can only
		// produce payloads the encoder refuses; see triageValidateMarkerPos.
		"marker_positions": []string{
			string(triage.MarkerPrefix), string(triage.MarkerSuffix), string(triage.MarkerInline),
			TriageMarkerPosNone,
		},
		"detection_modes":  triageDetectionModes(),
		"delivery_reasons": DeliveryReasons(),
	}
}

// triageSettableSlotKinds is every slot kind a payload may target. The fragment is excluded
// because no HTTP-level probe reaches it: every conforming client strips it before the request
// goes out, so offering it would offer coverage that cannot exist.
func triageSettableSlotKinds() []string {
	out := []string{}
	for _, k := range triage.AllSlotKinds() {
		if k == triage.KindFragment {
			continue
		}
		out = append(out, string(k))
	}
	return out
}

func triageSettableEncoders() []string {
	return []string{
		"", string(triage.EncodeQuery), string(triage.EncodeForm), string(triage.EncodePathSegment),
		string(triage.EncodeCookie), string(triage.EncodeHeaderValue), string(triage.EncodeJSONString),
		string(triage.EncodeJSONNodeReplace), string(triage.EncodeLiteralPct), string(triage.EncodePctTwice),
		string(triage.EncodeNameSlot),
	}
}

func triageDetectionModes() []map[string]string {
	return []map[string]string{
		{"mode": TriageDetectInherit, "label": "Use the class's own oracle", "requires": ""},
		{"mode": TriageDetectReflect, "label": "The marker comes back in the response", "requires": ""},
		{"mode": TriageDetectBodyRegex, "label": "A regular expression matches the body", "requires": "pattern"},
		{"mode": TriageDetectBodyContains, "label": "A literal string appears in the body", "requires": "pattern"},
		{"mode": TriageDetectStatusIn, "label": "The response status is one of", "requires": "statuses"},
		{"mode": TriageDetectTimeDelay, "label": "The response is slower than the baseline by", "requires": "delay_ms"},
	}
}

// ---------------------------------------------------------------------------------------------
// 3. DEFAULTS AND NORMALISATION
// ---------------------------------------------------------------------------------------------

// TriageSettingsDefaults is what a target that has never been configured runs on.
//
// Every registered class is on, at the reduced tier, capped at R2. R3 is the destructive tier and
// the registry's own rule is that it is opt-in per run, so it is not a default. The rate is the
// measured sustainable rate of the estate this layer was built against: 200 requests per 60
// seconds is 3.33 per second, and the framework spent hours at 5 because that number was written
// down rather than measured.
func TriageSettingsDefaults() TriageInvestigateSettings {
	s := TriageInvestigateSettings{
		Tier:    string(triage.TierReduced),
		Classes: map[string]TriageClassSetting{},
		Pacing: TriagePacing{
			RequestsPerSecond:   3.33,
			Concurrency:         2,
			PerSlotProbes:       24,
			PerRunProbes:        4000,
			MutatingAllowance:   0,
			BrowserAllowance:    0,
			RespectTargetBudget: true,
		},
		OOB:            TriageOOB{Mode: string(triage.OOBNone), GraceSeconds: 60},
		CustomPayloads: []TriageCustomPayload{},
	}
	for _, c := range TriageClassVocabulary() {
		s.Classes[c.Key] = TriageClassSetting{
			Enabled: true,
			Tier:    triageDefaultTierFor(c),
			MaxRisk: triageDefaultRiskFor(c),
		}
	}
	return s
}

// triageDefaultTierFor picks reduced when the class offers it and its only tier otherwise, so a
// class with a single tier is never stored against a tier it does not have.
func triageDefaultTierFor(c TriageClassInfo) string {
	for _, t := range c.Tiers {
		if t == string(triage.TierReduced) {
			return t
		}
	}
	if len(c.Tiers) == 1 {
		return c.Tiers[0]
	}
	return string(triage.TierReduced)
}

// triageDefaultRiskFor is the class's OWN highest declared risk, not a blanket R2.
//
// The ceiling is a refusal, and a ceiling above everything the class declares refuses nothing. R2
// on a class whose every probe is R0 changes not one request; the only thing it changes is what
// the screen says, where "up to R2" reads as a deeper run than any that exists. The classes this
// bites today are nosql, lfi and rfi at R0, and ssti and xss-r at R1.
//
// R3 is never a default, because the registry's own rule is that it is chosen per run with the
// cost named.
//
// IT IS A DEFAULT AND NOT A CLAMP, and that distinction is the whole safety argument. A stored
// ceiling above the class's own is left exactly as the operator left it, because clamping it down
// would narrow the run on the day the class gains a deeper probe, and a probe not sent is a bug
// not found. ValidateTriageSettings names the mismatch instead of quietly resolving it.
func triageDefaultRiskFor(c TriageClassInfo) string {
	best := ""
	for _, r := range c.Risks {
		if triage.RiskTier(r) == triage.RiskR3 {
			continue
		}
		if best == "" || triageRiskCeilingRank(r) > triageRiskCeilingRank(best) {
			best = r
		}
	}
	if best == "" {
		// A class that declares no risk declares no probes either, so nothing is refused whatever
		// this says. R2 keeps it consistent with the rest of the document.
		return string(triage.RiskR2)
	}
	return best
}

// triageRiskCeilingRank orders the risk tiers for the ceiling comparison, and returns -1 for
// anything that is not a tier, so a garbage value cannot silently rank as the top or the bottom.
// The run's own comparison lives with the runner; this one decides only what the form offers and
// what the validation says about it.
func triageRiskCeilingRank(r string) int {
	switch triage.RiskTier(r) {
	case triage.RiskR0:
		return 0
	case triage.RiskR1:
		return 1
	case triage.RiskR2:
		return 2
	case triage.RiskR3:
		return 3
	}
	return -1
}

// NormaliseTriageSettings fills the document out against the defaults and returns the keys it did
// not recognise. A class in the stored document that is no longer registered is REPORTED rather
// than silently dropped, because silently dropping it is how a class the operator deliberately
// turned off comes back on without anybody being told.
func NormaliseTriageSettings(in TriageInvestigateSettings) (TriageInvestigateSettings, []string) {
	def := TriageSettingsDefaults()
	out := in

	if strings.TrimSpace(out.Tier) == "" {
		out.Tier = def.Tier
	}
	if out.Pacing.RequestsPerSecond == 0 {
		out.Pacing.RequestsPerSecond = def.Pacing.RequestsPerSecond
	}
	if out.Pacing.Concurrency == 0 {
		out.Pacing.Concurrency = def.Pacing.Concurrency
	}
	if out.Pacing.PerSlotProbes == 0 {
		out.Pacing.PerSlotProbes = def.Pacing.PerSlotProbes
	}
	if out.Pacing.PerRunProbes == 0 {
		out.Pacing.PerRunProbes = def.Pacing.PerRunProbes
	}
	if out.OOB.GraceSeconds == 0 {
		out.OOB.GraceSeconds = def.OOB.GraceSeconds
	}
	if out.CustomPayloads == nil {
		out.CustomPayloads = []TriageCustomPayload{}
	}

	merged := map[string]TriageClassSetting{}
	var unknown []string
	for key, cs := range out.Classes {
		if _, known := def.Classes[key]; !known {
			unknown = append(unknown, key)
			continue
		}
		merged[key] = cs
	}
	for key, dv := range def.Classes {
		cs, present := merged[key]
		if !present {
			merged[key] = dv
			continue
		}
		if strings.TrimSpace(cs.Tier) == "" {
			cs.Tier = dv.Tier
		}
		if strings.TrimSpace(cs.MaxRisk) == "" {
			cs.MaxRisk = dv.MaxRisk
		}
		merged[key] = cs
	}
	out.Classes = merged
	sort.Strings(unknown)
	return out, unknown
}

// ---------------------------------------------------------------------------------------------
// 4. VALIDATION, RENDERABLE PER FIELD
// ---------------------------------------------------------------------------------------------

// TriageFieldProblem is one problem, addressed at the field that caused it so the form can put it
// next to the control rather than in a banner.
type TriageFieldProblem struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// TriagePayloadDelivery is what the real encoder did with one payload at one insertion point.
type TriagePayloadDelivery struct {
	Point   string `json:"point"`
	Media   string `json:"media,omitempty"`
	Encoder string `json:"encoder"`
	// WireLen is the length of the bytes handed to the encoder for this row: the logical payload
	// after the class token grammar and the marker, which is what the runner sends.
	WireLen int `json:"wire_len"`
	// MarkerOnWire says whether these bytes actually carry the run marker. It is not the same
	// question as MarkerPos: the renderer DROPS the marker rather than corrupt a payload the
	// node-replace encoder would then refuse, so a payload can be saved with a marker position
	// and go out without one. A probe with no marker on the wire cannot be attributed, and an
	// oracle that looks for a reflection of it can only ever be silent.
	MarkerOnWire bool   `json:"marker_on_wire"`
	Delivered    bool   `json:"delivered"`
	Survived     string `json:"survived"`
	// Proven is the predicate a clean verdict is allowed to rest on: intact or encoded, nothing
	// else. Delivered and not proven is the cookie semicolon case, which is the one that looks
	// fine and is not.
	Proven bool   `json:"proven"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// TriagePayloadCheck is one custom payload's whole verdict.
type TriagePayloadCheck struct {
	Index      int    `json:"index"`
	ID         string `json:"id"`
	Class      string `json:"class"`
	OK         bool   `json:"ok"`
	ProbeID    string `json:"probe_id"`
	LogicalLen int    `json:"logical_len"`
	// WireLen is the length of the bytes that will ACTUALLY be sent: the logical payload with the
	// class's token grammar applied and the run marker placed per MarkerPos. It is a separate
	// number from LogicalLen because they differ by at least triage.MarkerLen on every payload
	// that carries a marker, and the operator reads this one to decide whether a payload fits.
	WireLen  int                     `json:"wire_len"`
	Delivery []TriagePayloadDelivery `json:"delivery"`
	Problems []TriageFieldProblem    `json:"problems"`
}

// TriageSettingsValidation is the whole result. It is returned on GET as well as on PUT, because a
// stored document can stop being valid when a class is retired or an encoder changes, and a screen
// that only validates what you are typing hides that.
type TriageSettingsValidation struct {
	OK       bool                 `json:"ok"`
	Errors   []TriageFieldProblem `json:"errors"`
	Warnings []TriageFieldProblem `json:"warnings"`
	Payloads []TriagePayloadCheck `json:"payloads"`
	// EnabledClasses is what would actually run, so the count next to the save button is derived
	// from the same pass that validated it.
	EnabledClasses []string `json:"enabled_classes"`
	// RegistryViolations are the SHIPPED registry's own isolation failures, if any. They do not
	// block a save because they are not the operator's doing, but a run refuses to start on them,
	// so they are surfaced rather than swallowed.
	RegistryViolations []string `json:"registry_violations"`
	// IsolationChecksNotRun is the isolation law's own honest gap list. A check that has not been
	// written is not a check that passed.
	IsolationChecksNotRun []string `json:"isolation_checks_not_run"`
}

// ValidateTriageSettings is the whole validation pass with NO renewal gate supplied.
//
// It is pure: no database, no network, so the same function backs the handler and the test. An
// absent gate is not an open door: the zero TriageRenewalGate has Evaluated false, and an enabled
// renewal against an unevaluated gate is an ERROR. A caller that cannot evaluate the gate is a
// caller that cannot show a refresh was ever performed, and not knowing is not clean.
func ValidateTriageSettings(s TriageInvestigateSettings) TriageSettingsValidation {
	return ValidateTriageSettingsWithRenewal(s, TriageRenewalGate{})
}

// ValidateTriageSettingsWithRenewal is the same pass with the renewal gate the handler evaluated.
func ValidateTriageSettingsWithRenewal(s TriageInvestigateSettings, gate TriageRenewalGate) TriageSettingsValidation {
	v := TriageSettingsValidation{
		Errors:   []TriageFieldProblem{},
		Warnings: []TriageFieldProblem{},
		Payloads: []TriagePayloadCheck{},
	}
	vocab := map[string]TriageClassInfo{}
	for _, c := range TriageClassVocabulary() {
		vocab[c.Key] = c
	}

	triageValidateTier(&v, "tier", s.Tier)
	triageValidatePacing(&v, s.Pacing)
	triageValidateOOB(&v, s.OOB)
	triageValidateClasses(&v, s.Classes, vocab)
	triageValidatePayloads(&v, s.CustomPayloads, vocab)
	triageValidateSessionRenewal(&v, s.SessionRenewal, gate)

	v.OK = len(v.Errors) == 0
	return v
}

// triageValidateSessionRenewal is the refusal that makes the hard rule real.
//
// The switch may be stored as true ONLY while the gate says a refresh was performed and a
// different working credential came back. Every refusal here carries the gate's own sentence,
// which names what would lift it, so the operator is told what to do rather than that they may
// not.
//
// IT RUNS ON EVERY READ AS WELL AS EVERY WRITE. That is what makes a stale proof revoke the
// setting instead of the setting outliving the proof: a document saved yesterday against a proof
// that has since broken fails validation the next time the screen is opened, and
// TriageRenewalEffective refuses the same way at run time without the document being edited.
func triageValidateSessionRenewal(v *TriageSettingsValidation, r TriageSessionRenewal, gate TriageRenewalGate) {
	if r.IntervalSeconds < 0 {
		v.err("session_renewal.interval_seconds", "renewal_interval_negative",
			"A renewal interval cannot be negative. Leave it at zero to derive it from the measured lifetime.")
	}
	if !r.Enabled {
		return
	}

	if !gate.Evaluated {
		v.err("session_renewal.enabled", "renewal_"+TriageRenewalGateNotEvaluated,
			"Automatic renewal is switched on but the refresh gate was not evaluated, so nothing here shows the session can actually be refreshed. An unevaluated gate has proven nothing, and this is refused rather than believed.")
		return
	}
	if strings.TrimSpace(r.TokenID) == "" {
		v.err("session_renewal.token_id", "renewal_no_credential_named",
			"Automatic renewal is switched on but names no credential. A target usually holds several, and renewing the wrong one leaves the scan authenticated as nobody while the screen says renewal is on.")
		return
	}
	option, found := gate.Option(r.TokenID)
	if !found {
		v.err("session_renewal.token_id", "renewal_credential_unknown",
			fmt.Sprintf("Automatic renewal names a credential (%s) this target does not have. It was probably deleted; pick one of the %d that are there.", r.TokenID, len(gate.Options)))
		return
	}
	if !option.Usable {
		v.err("session_renewal.enabled", "renewal_"+option.Code,
			"Automatic renewal cannot be switched on for "+triageOrDefault(option.Name, "this credential")+". "+option.Reason)
		return
	}

	// The proof stands. Now the schedule, which is a separate question and has its own refusals.
	switch {
	case r.IntervalSeconds == 0 && !option.IntervalKnown:
		v.err("session_renewal.interval_seconds", "renewal_interval_not_derivable",
			"No renewal interval can be derived, because "+option.IntervalBasis+". Type one and it will be recorded as your figure rather than as a measurement.")
	case r.IntervalSeconds == 0:
		// Derived. The basis is surfaced as a warning only when the measurement it rests on is
		// itself qualified, so the common case is silent rather than noisy.
		if option.TTLIsUpperBound {
			v.warn("session_renewal.interval_seconds", "renewal_interval_from_upper_bound",
				"The interval is derived from a lifetime that is an UPPER BOUND ("+option.TTLEvidence+"), so the real lifetime may be shorter and renewal may fire after the credential is already dead.")
		}
		if !option.TTLKnown {
			v.warn("session_renewal.interval_seconds", "renewal_interval_from_floor",
				"The interval is derived from a LOWER BOUND rather than a measured lifetime: "+option.IntervalBasis+". The basis names which kind of bound it was.")
		}
		// THE DERIVED FIGURE IS HELD TO THE FLOOR, AND THE SAVE SAYS SO, because that is what the
		// run does with it. See triageRenewalClampWhy.
		if option.IntervalKnown && time.Duration(option.IntervalSeconds)*time.Second < triageRenewalMinInterval {
			v.warn("session_renewal.interval_seconds", "renewal_interval_clamped_to_floor",
				fmt.Sprintf("The interval derived from this credential's lifetime is %ds. %s%s Type an interval of your own if you want a different schedule.",
					option.IntervalSeconds,
					triageRenewalClampWhy(time.Duration(option.IntervalSeconds)*time.Second, triageRenewalMinInterval),
					triageRenewalClampGap(triageRenewalMinInterval, option, true)))
		}
	case option.TTLKnown && int64(r.IntervalSeconds) >= option.TTLSeconds:
		// THIS IS TESTED BEFORE THE FLOOR, AND THE ORDER IS THE WHOLE POINT OF IT.
		//
		// TriageRenewalEffective REFUSES an operator-set interval that is not shorter than the
		// measured lifetime, and it tests the figure that was SET rather than the one the driver
		// will clamp it to. Both conditions are satisfiable at once on a fast-rotating
		// application: a 45s credential with a typed 50s interval is below the 60s floor AND no
		// shorter than the lifetime. With the floor tested first, the save would have answered
		// "clamped, this is fine" about a document the run refuses outright, which is the same
		// contradiction as the one this round is closing, pointing the other way.
		v.err("session_renewal.interval_seconds", "renewal_interval_exceeds_lifetime",
			fmt.Sprintf("An interval of %ds is not shorter than the credential's measured lifetime of %ds, so the first renewal would fire after it had already expired. The derived interval is %ds.",
				r.IntervalSeconds, option.TTLSeconds, option.IntervalSeconds))
	case time.Duration(r.IntervalSeconds)*time.Second < triageRenewalMinInterval:
		// THE SAME FLOOR, AGAINST THE OPERATOR'S OWN FIGURE, AND THE SAME ANSWER.
		//
		// IT USED TO BE AN ERROR AND THAT WAS THE CONTRADICTION. The driver clamps, so a document
		// this refused was a document the run would have happily executed, and the refusal meant
		// renewal could not be switched on at all on a fast-rotating application. The floor exists
		// to stop a pathological schedule, not to deny the feature to the one target that cannot
		// finish a run without it. What the refusal was right about is that a run must not report
		// it renews while running a schedule the operator did not choose, and that is paid for by
		// saying which schedule will run, in the same words the run will use.
		v.warn("session_renewal.interval_seconds", "renewal_interval_clamped_to_floor",
			fmt.Sprintf("An interval of %ds was asked for. %s%s",
				r.IntervalSeconds,
				triageRenewalClampWhy(time.Duration(r.IntervalSeconds)*time.Second, triageRenewalMinInterval),
				triageRenewalClampGap(triageRenewalMinInterval, option, true)))
	case option.IntervalKnown && r.IntervalSeconds > option.IntervalSeconds:
		v.warn("session_renewal.interval_seconds", "renewal_interval_leaves_no_retry",
			fmt.Sprintf("An interval of %ds is longer than the derived %ds, which was half the lifetime so that a failed renewal still had a full window to retry in. Yours leaves less than that.",
				r.IntervalSeconds, option.IntervalSeconds))
	}

	// The measurement the whole feature exists for, said at the point of configuration.
	if option.SurvivesKnown && option.SurvivesRun {
		v.warn("session_renewal.enabled", "renewal_not_required_for_this_run",
			"This credential would survive the estimated run without renewal ("+option.SurvivesWhy+"), so renewal here is insurance rather than a requirement.")
	}
	for _, w := range option.Warnings {
		v.warn("session_renewal.enabled", "renewal_credential_note", w)
	}
}

func triageValidateTier(v *TriageSettingsValidation, field, tier string) {
	switch triage.ProbeTier(tier) {
	case triage.TierReduced, triage.TierFull, triage.TierOptIn:
		return
	}
	v.err(field, "unknown_tier", fmt.Sprintf("%q is not a probe tier. Use reduced, full or opt_in.", tier))
}

func triageValidatePacing(v *TriageSettingsValidation, p TriagePacing) {
	if p.RequestsPerSecond <= 0 {
		v.err("pacing.requests_per_second", "rate_not_positive", "A rate of zero or less sends nothing.")
	}
	if p.Concurrency <= 0 {
		v.err("pacing.concurrency", "concurrency_not_positive", "Concurrency must be at least 1.")
	}
	// Zero is the trap here, not a negative. TriageBudget.Exhausted() is true the moment a
	// remaining count reaches zero, so a budget of zero is a run in which every slot reports
	// probe_budget_exhausted and nothing is tested.
	if p.PerSlotProbes <= 0 {
		v.err("pacing.per_slot_probes", "budget_not_positive",
			"A per-slot budget of zero makes every slot report exhausted rather than tested.")
	}
	if p.PerRunProbes <= 0 {
		v.err("pacing.per_run_probes", "budget_not_positive",
			"A per-run budget of zero makes every slot report exhausted rather than tested.")
	}
	if p.MutatingAllowance < 0 {
		v.err("pacing.mutating_allowance", "allowance_negative", "This cannot be negative.")
	}
	if p.BrowserAllowance < 0 {
		v.err("pacing.browser_allowance", "allowance_negative", "This cannot be negative.")
	}
	if p.PerSlotProbes > 0 && p.PerRunProbes > 0 && p.PerRunProbes < p.PerSlotProbes {
		v.warn("pacing.per_run_probes", "run_budget_below_slot_budget",
			"The run budget is smaller than one slot's, so the run stops inside the first slot.")
	}
	if !p.RespectTargetBudget {
		v.warn("pacing.respect_target_budget", "target_budget_ignored",
			"The target's own rate-limit headers will not be read, and a 429 reflects nothing, so refused requests read as clean.")
	}
}

func triageValidateOOB(v *TriageSettingsValidation, o TriageOOB) {
	switch triage.OOBMode(o.Mode) {
	case triage.OOBNone:
		v.warn("oob.mode", "no_collaborator",
			"Classes that need a callback will report no_collaborator, which is not a clean.")
		return
	case triage.OOBWildcardDNS, triage.OOBHTTPPath:
	default:
		v.err("oob.mode", "unknown_oob_mode",
			fmt.Sprintf("%q is not an out-of-band mode. Use wildcard_dns or http_path, or leave it empty.", o.Mode))
		return
	}
	if strings.TrimSpace(o.Base) == "" {
		v.err("oob.base", "collaborator_base_required",
			"The framework ships no default collaborator, so this host has to be yours.")
	}
	if o.GraceSeconds <= 0 {
		v.err("oob.grace_seconds", "grace_not_positive",
			"A grace window of zero discards every callback that arrives after the probe.")
	}
	if triage.OOBMode(o.Mode) == triage.OOBHTTPPath {
		v.warn("oob.mode", "http_path_is_dns_blind",
			"An HTTP-path collaborator cannot see a DNS-only callback, which is most SSRF.")
	}
}

func triageValidateClasses(v *TriageSettingsValidation, classes map[string]TriageClassSetting, vocab map[string]TriageClassInfo) {
	keys := make([]string, 0, len(classes))
	for k := range classes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		cs := classes[key]
		field := "classes." + key
		info, known := vocab[key]
		if !known {
			v.err(field, "unknown_class",
				fmt.Sprintf("%q is not a registered triage class, so nothing would run it.", key))
			continue
		}
		if cs.Enabled {
			v.EnabledClasses = append(v.EnabledClasses, key)
		}
		triageValidateTier(v, field+".tier", cs.Tier)
		if len(info.Tiers) > 0 && !triageContainsString(info.Tiers, cs.Tier) {
			v.warn(field+".tier", "tier_has_no_probes",
				fmt.Sprintf("%s declares no probes at the %s tier, so this class would send nothing.", info.Name, cs.Tier))
		}
		switch triage.RiskTier(cs.MaxRisk) {
		case triage.RiskR0, triage.RiskR1, triage.RiskR2, triage.RiskR3:
			if cs.Enabled {
				triageValidateRiskCeiling(v, field+".max_risk", info, cs.MaxRisk)
			}
		default:
			v.err(field+".max_risk", "unknown_risk_tier",
				fmt.Sprintf("%q is not a risk tier. Use R0, R1, R2 or R3.", cs.MaxRisk))
		}
	}
	if v.EnabledClasses == nil {
		v.EnabledClasses = []string{}
	}
	if len(v.EnabledClasses) == 0 {
		v.warn("classes", "no_class_enabled",
			"No class is enabled, so this run would produce no verdicts at all rather than clean ones.")
	}
}

// triageValidateRiskCeiling compares the operator's ceiling against the risks this class's own
// probes declare. Only one of the two directions is worth saying out loud.
//
//   - A ceiling BELOW some of the class's probes refuses them. The run records each as skipped
//     with a risk_ceiling reason, so none of them reads as clean, which is right. But the
//     operator switched the class ON and is getting part of it, and the screen should say which
//     part rather than leave it to be found in the coverage rows afterwards.
//   - A ceiling ABOVE every probe the class declares refuses nothing, so it is not warned about.
//     It is also what stops a deeper probe added tomorrow from being silently excluded, which is
//     why a ceiling is never clamped down to fit. The form simply stops OFFERING the levels that
//     buy nothing, so this only ever fires on a document stored before that change.
//
// Only an enabled class is checked: a disabled class sends nothing whatever its ceiling says, and
// a warning about a run that is not happening is the kind of alert that teaches people to ignore
// the others.
func triageValidateRiskCeiling(v *TriageSettingsValidation, field string, info TriageClassInfo, ceiling string) {
	rank := triageRiskCeilingRank(ceiling)
	if rank < 0 || len(info.Risks) == 0 {
		return
	}
	var above []string
	for _, r := range info.Risks {
		if triageRiskCeilingRank(r) > rank {
			above = append(above, r)
		}
	}
	if len(above) == 0 {
		return
	}
	if len(above) == len(info.Risks) {
		v.warn(field, "risk_ceiling_refuses_every_probe",
			fmt.Sprintf("%s is enabled but declares no probe at or below %s, so it would send nothing. Its probes are at %s.",
				info.Name, ceiling, strings.Join(info.Risks, ", ")))
		return
	}
	v.warn(field, "risk_ceiling_refuses_some_probes",
		fmt.Sprintf("%s also declares probes at %s, above this %s ceiling. Those are refused on safety grounds and recorded as unknown, never as clean.",
			info.Name, strings.Join(above, ", "), ceiling))
}

func (v *TriageSettingsValidation) err(field, code, message string) {
	v.Errors = append(v.Errors, TriageFieldProblem{Field: field, Code: code, Message: message})
}

func (v *TriageSettingsValidation) warn(field, code, message string) {
	v.Warnings = append(v.Warnings, TriageFieldProblem{Field: field, Code: code, Message: message})
}

// ---------------------------------------------------------------------------------------------
// 5. CUSTOM PAYLOADS: THE ISOLATION LAW AND THE ENCODER
// ---------------------------------------------------------------------------------------------

// TriageCustomProbeID is the probe id a custom payload is registered under. It is namespaced so a
// custom payload can never collide with a shipped probe id by accident, and so a verdict that came
// from one is identifiable in the stored evidence.
func TriageCustomProbeID(classKey, payloadID string) triage.ProbeID {
	return triage.ProbeID("custom/" + classKey + "/" + payloadID)
}

// triageCustomClassifier wraps a registered classifier and replaces only its probe list, so the
// isolation check sees the real class's identity and the operator's payloads together. Everything
// else, Reaches included, is the real class's.
type triageCustomClassifier struct {
	triage.Classifier
	probes []triage.ProbeSpec
}

func (c triageCustomClassifier) Probes() []triage.ProbeSpec { return c.probes }

// triageDecodePayload turns the stored payload text into the logical bytes the runner would send.
func triageDecodePayload(p TriageCustomPayload) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(p.Encoding)) {
	case "", "utf8", "utf-8":
		return []byte(p.Payload), nil
	case "base64":
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p.Payload))
		if err != nil {
			return nil, fmt.Errorf("not valid base64: %v", err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("%q is not an encoding; use utf8 or base64", p.Encoding)
	}
}

// triageValidatePayloads is the whole custom-payload pass: identity, class, detection rule,
// isolation against every other payload in the system, and delivery through the real encoder.
func triageValidatePayloads(v *TriageSettingsValidation, payloads []TriageCustomPayload, vocab map[string]TriageClassInfo) {
	reg := triage.RegisteredClassifiers()

	// The payload index every isolation question is answered against: every shipped probe, plus
	// every custom payload seen so far. Keyed on the payload with markers normalised away, because
	// two probes differing only in their per-probe marker are the same payload for this purpose.
	type payloadOwner struct {
		describe string
		field    string
	}
	seen := map[string]payloadOwner{}
	for _, id := range sortedTriageClassIDs(reg) {
		for _, p := range reg[id].Probes() {
			key := string(triage.NormaliseMarkers(p.Logical))
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = payloadOwner{describe: fmt.Sprintf("the shipped probe %s of class %s", p.ID, id)}
		}
	}

	ids := map[string]int{}
	byProbeID := map[triage.ProbeID]int{}
	custom := map[triage.ClassID][]triage.ProbeSpec{}

	for i, p := range payloads {
		field := fmt.Sprintf("custom_payloads[%d]", i)
		check := TriagePayloadCheck{
			Index: i, ID: p.ID, Class: p.Class,
			Delivery: []TriagePayloadDelivery{},
			Problems: []TriageFieldProblem{},
		}
		add := func(f, code, msg string) {
			pr := TriageFieldProblem{Field: field + f, Code: code, Message: msg}
			check.Problems = append(check.Problems, pr)
			v.Errors = append(v.Errors, pr)
		}
		// A warning does NOT mark the payload failed and does not block the save. It is for a
		// fact the operator has to know that is not a reason to throw the payload away, which is
		// one insertion point's second medium refusing while the first carries it: the run
		// records a named not_reachable on those slots, never a clean, and refusing the save
		// would have cost the coverage the first medium was going to give.
		warn := func(f, code, msg string) {
			v.Warnings = append(v.Warnings, TriageFieldProblem{Field: field + f, Code: code, Message: msg})
		}

		if strings.TrimSpace(p.ID) == "" {
			add(".id", "id_required", "Every payload needs an id so its results can be traced back to it.")
		} else if prev, dup := ids[p.ID]; dup {
			add(".id", "duplicate_id", fmt.Sprintf("Payload %d already uses the id %q.", prev, p.ID))
		} else {
			ids[p.ID] = i
		}

		info, known := vocab[p.Class]
		if !known {
			add(".class", "unregistered_class", fmt.Sprintf(
				"%q is not a registered triage class. A payload has to belong to exactly one class that can run, or its results cannot be attributed. Registered: %s.",
				p.Class, strings.Join(sortedVocabKeys(vocab), ", ")))
			v.Payloads = append(v.Payloads, check)
			continue
		}
		classID := triage.ClassID(info.ID)
		classifier := reg[classID]

		logical, err := triageDecodePayload(p)
		if err != nil {
			add(".payload", "payload_not_decodable", err.Error())
		}
		if err == nil && len(logical) == 0 {
			add(".payload", "payload_empty",
				"A payload with no bytes sends nothing and would be recorded as a clean test.")
		}
		check.LogicalLen = len(logical)

		triageValidateDetection(add, p.Detection)
		triageValidateMarkerPos(add, p)
		if p.Tier != "" {
			switch triage.ProbeTier(p.Tier) {
			case triage.TierReduced, triage.TierFull, triage.TierOptIn:
			default:
				add(".tier", "unknown_tier", fmt.Sprintf("%q is not a probe tier.", p.Tier))
			}
		}
		if p.Risk != "" {
			switch triage.RiskTier(p.Risk) {
			case triage.RiskR0, triage.RiskR1, triage.RiskR2, triage.RiskR3:
			default:
				add(".risk", "unknown_risk_tier", fmt.Sprintf("%q is not a risk tier.", p.Risk))
			}
		}

		// Isolation, the law: byte equality against every shipped payload and every custom payload
		// already checked. A collision is named rather than described, because the operator has to
		// be able to go and look at the thing they collided with.
		if len(logical) > 0 {
			key := string(triage.NormaliseMarkers(logical))
			if owner, dup := seen[key]; dup {
				where := owner.describe
				if owner.field != "" {
					where += " (" + owner.field + ")"
				}
				add(".payload", "payload_collision", fmt.Sprintf(
					"These bytes are already %s. Two probes with the same payload cannot be told apart when one is blocked, so a block on either records the other as clean.", where))
			} else {
				seen[key] = payloadOwner{
					describe: fmt.Sprintf("your custom payload %q on class %s", p.ID, p.Class),
					field:    field,
				}
			}
		}

		// Insertion points, checked against the class's own Reaches rather than against a list.
		points := triageValidatePoints(add, p.Points, info)

		probeID := TriageCustomProbeID(p.Class, p.ID)
		check.ProbeID = string(probeID)
		if prev, dup := byProbeID[probeID]; dup {
			add(".id", "duplicate_probe_id", fmt.Sprintf("Payload %d resolves to the same probe id.", prev))
		}
		byProbeID[probeID] = i

		// Delivery, through the real renderer and the real encoder. This is the refusal the
		// operator would otherwise discover as a silent clean hours later.
		//
		// THE SPEC IS triageCustomProbeSpec'S AND NOT A SECOND COPY OF IT. That function is what
		// the runner builds the wire from, and its own comment says the two must not disagree:
		// "a payload is checked as one thing and sent as another, which is the failure this
		// function exists to make impossible". It was a copy here, with the same four defaults
		// written out twice, which is exactly the shape that drifts.
		if len(logical) > 0 && classifier != nil {
			spec, err := triageCustomProbeSpec(classID, p)
			switch {
			case err != nil:
				add(".payload", "payload_not_decodable", err.Error())
			default:
				// The VALIDATED points, not the raw strings: a point the class does not reach has
				// already been refused above and must not be probed here as though it were live.
				spec.Points = points
				check.WireLen, check.Delivery = triageCheckDelivery(add, warn, p, spec, points)
				triageCheckReflectHasAMarker(add, p, check.Delivery)
				custom[classID] = append(custom[classID], spec)
			}
		}

		check.OK = len(check.Problems) == 0
		v.Payloads = append(v.Payloads, check)
	}

	triageRunIsolationLaw(v, reg, custom, byProbeID)
}

// triageRunIsolationLaw folds the custom probes into the real registry and runs
// triage.CheckPayloadIsolation over the result. This is the same function the run itself refuses
// to start on, rather than a second copy of the rule that could drift from it.
func triageRunIsolationLaw(v *TriageSettingsValidation, reg map[triage.ClassID]triage.Classifier,
	custom map[triage.ClassID][]triage.ProbeSpec, byProbeID map[triage.ProbeID]int) {

	merged := map[triage.ClassID]triage.Classifier{}
	for id, c := range reg {
		extra := custom[id]
		if len(extra) == 0 {
			merged[id] = c
			continue
		}
		probes := append(append([]triage.ProbeSpec{}, c.Probes()...), extra...)
		merged[id] = triageCustomClassifier{Classifier: c, probes: probes}
	}

	rep := triage.CheckPayloadIsolation(merged)
	v.IsolationChecksNotRun = append([]string{}, rep.ChecksNotImplemented...)
	v.RegistryViolations = []string{}

	for _, viol := range rep.Violations {
		idxA, customA := byProbeID[viol.ProbeA]
		idxB, customB := byProbeID[viol.ProbeB]
		switch {
		case customA:
			v.err(fmt.Sprintf("custom_payloads[%d].payload", idxA), string(viol.Kind), viol.String())
			triageMarkPayloadFailed(v, idxA, fmt.Sprintf("custom_payloads[%d].payload", idxA), string(viol.Kind), viol.String())
		case customB:
			v.err(fmt.Sprintf("custom_payloads[%d].payload", idxB), string(viol.Kind), viol.String())
			triageMarkPayloadFailed(v, idxB, fmt.Sprintf("custom_payloads[%d].payload", idxB), string(viol.Kind), viol.String())
		default:
			// Not the operator's doing: the shipped registry itself. It does not block this save,
			// but a run refuses to start on it, so it is reported rather than swallowed.
			v.RegistryViolations = append(v.RegistryViolations, viol.String())
		}
	}
}

func triageMarkPayloadFailed(v *TriageSettingsValidation, index int, field, code, message string) {
	for i := range v.Payloads {
		if v.Payloads[i].Index != index {
			continue
		}
		v.Payloads[i].OK = false
		v.Payloads[i].Problems = append(v.Payloads[i].Problems,
			TriageFieldProblem{Field: field, Code: code, Message: message})
		return
	}
}

func triageValidateDetection(add func(f, code, msg string), d TriageDetection) {
	switch d.Mode {
	case "":
		// A payload with no way to tell a hit from a miss is not a probe. Inheriting the class's
		// oracle is a fine answer and it has to be chosen, not defaulted into.
		add(".detection.mode", "detection_mode_required",
			"Choose how a hit is told from a miss. Inherit the class's oracle if that is what you want.")
	case TriageDetectInherit, TriageDetectReflect:
	case TriageDetectBodyRegex:
		if strings.TrimSpace(d.Pattern) == "" {
			add(".detection.pattern", "pattern_required", "This mode needs a regular expression.")
			return
		}
		if _, err := regexp.Compile(d.Pattern); err != nil {
			add(".detection.pattern", "pattern_not_compilable", err.Error())
		}
	case TriageDetectBodyContains:
		if d.Pattern == "" {
			add(".detection.pattern", "pattern_required", "This mode needs a string to look for.")
		}
	case TriageDetectStatusIn:
		if len(d.Statuses) == 0 {
			add(".detection.statuses", "statuses_required", "This mode needs at least one status code.")
		}
		for _, s := range d.Statuses {
			if s < 100 || s > 599 {
				add(".detection.statuses", "status_out_of_range", fmt.Sprintf("%d is not an HTTP status.", s))
			}
		}
	case TriageDetectTimeDelay:
		if d.DelayMS <= 0 {
			add(".detection.delay_ms", "delay_required", "This mode needs a delay in milliseconds.")
		}
	default:
		add(".detection.mode", "unknown_detection_mode", fmt.Sprintf("%q is not a detection mode.", d.Mode))
	}
}

// TriageMarkerPosNone is the spelling of "this payload must stay bare" in the settings document.
// The runner reads it through triageCustomMarkerOmitted, which also accepts "omitted", and turns
// it into Variant["marker_placement"]="omitted", the same opt-out a shipped probe uses.
//
// WHY IT HAD TO EXIST. A marker is 16 bytes of [0-9a-z] and the runner places it per MarkerPos,
// defaulting to prefix. Prefixed onto {"$eq":"alice"} that makes zqj...{"$eq":"alice"}, which is
// not a JSON value, so the json_node_replace encoder refuses it and NOTHING IS SENT. Measured on
// run a218419a: 384 of class NOSQL's fidelity rows are json_node_payload_is_not_valid_json for
// exactly this reason, including both arms of its tier-1 arithmetic oracle. An operator writing
// the same payload by hand had no way to spell the opt-out, so every such payload was unsendable
// and the save-time check said yes to all of them.
const TriageMarkerPosNone = "none"

// triageMarkerOmitted reports whether this payload goes out bare. It is deliberately the same
// question triageCustomMarkerOmitted asks on the send path, in the same two spellings, because a
// payload validated as marked and sent bare (or the reverse) is the drift this whole pass exists
// to remove.
func triageMarkerOmitted(pos string) bool {
	switch strings.ToLower(strings.TrimSpace(pos)) {
	case TriageMarkerPosNone, "omitted":
		return true
	}
	return false
}

func triageValidateMarkerPos(add func(f, code, msg string), p TriageCustomPayload) {
	if triageMarkerOmitted(p.MarkerPos) {
		// A bare payload cannot be attributed by reflection: there is no token to look for. Every
		// other oracle still works, so this refuses the one combination that could not be judged
		// rather than refusing the position.
		if p.Detection.Mode == TriageDetectReflect {
			add(".detection.mode", "reflect_needs_a_marker",
				"This payload goes out bare, so there is no marker to come back. Reflection cannot "+
					"judge it: choose another oracle, or give the payload a marker position.")
		}
		return
	}
	switch triage.MarkerPos(p.MarkerPos) {
	case "", triage.MarkerPrefix, triage.MarkerSuffix, triage.MarkerInline:
	default:
		add(".marker_pos", "unknown_marker_position", fmt.Sprintf("%q is not a marker position.", p.MarkerPos))
	}
}

// triageValidatePoints checks the declared insertion points against the class's own Reaches. A
// point the class never reaches is dead weight in the cost model and the class's own reason for
// not reaching it is the message, which is the same rule ValidateClassifier applies to a shipped
// probe.
func triageValidatePoints(add func(f, code, msg string), points []string, info TriageClassInfo) []triage.SlotKind {
	if len(points) == 0 {
		add(".points", "points_required", "A payload that names no insertion point can never be planned.")
		return nil
	}
	out := make([]triage.SlotKind, 0, len(points))
	for _, raw := range points {
		k := triage.SlotKind(raw)
		if k == triage.KindFragment {
			add(".points", "point_unreachable",
				"The fragment is stripped by every conforming client, so no HTTP probe reaches it.")
			continue
		}
		if !triageContainsString(triageSettableSlotKinds(), raw) {
			add(".points", "unknown_point", fmt.Sprintf("%q is not an insertion point.", raw))
			continue
		}
		if why, never := info.Unreachable[raw]; never {
			add(".points", "class_does_not_reach_point",
				fmt.Sprintf("%s does not reach %s: %s", info.Name, raw, why))
			continue
		}
		out = append(out, k)
	}
	return out
}

// triageCheckDelivery renders the payload into every declared insertion point THE WAY THE RUNNER
// WILL, and reports the wire length plus one row per point and medium.
//
// A payload is refused, not warned about, when it cannot arrive faithfully. Delivered is not
// enough: a cookie value carrying a semicolon IS delivered and is then split by any RFC 6265
// parser, so the application reads a shorter string than the one sent. WireSurvival.Proven is the
// predicate a clean verdict is allowed to rest on, so it is the predicate here too.
//
// D2f, AND IT IS WHY THIS FUNCTION CHANGED. It used to hand EncodeSlotInto the LOGICAL payload:
// the bytes the operator typed. Those bytes are not what goes out. triageRenderPayload applies
// the owning class token grammar, substitutes every spelling of the marker, refuses a payload
// still carrying an unfillable token, and then places a triage.MarkerLen-byte marker per
// MarkerPos, which defaults to prefix. So the check answered a question about a string nobody
// sends, and a payload that fits without the marker and not with it passed here and failed live,
// which is precisely the silent clean this check exists to prevent.
//
// IT IS NOT A HYPOTHETICAL. On run a218419a, 384 of class NOSQL 965 fidelity rows came back
// json_node_payload_is_not_valid_json: {"$eq":"0"} is a JSON value, zqjfkqv0001dxm52{"$eq":"0"}
// is not, and json_node_replace refused every one. Four shipped probes, two of them the arms of
// that class tier-1 arithmetic oracle, never left the process. An operator payload of the same
// shape got no save-time warning at all.
//
// The synthetic request below has no per-slot impossible-byte table and no measured field limit,
// because both are measured against the live target at run time. This check is therefore a floor:
// it catches what is impossible everywhere, not what is impossible on one endpoint.
func triageCheckDelivery(add, warn func(f, code, msg string), p TriageCustomPayload,
	spec triage.ProbeSpec, points []triage.SlotKind) (int, []TriagePayloadDelivery) {

	out := []TriagePayloadDelivery{}
	marker, err := triageRepresentativeMarker(spec.Class)
	if err != nil {
		// Fail closed and say so. A check that cannot mint a marker cannot render the wire form,
		// and reporting the logical form instead would be the substitution this pass removed.
		add(".payload", "delivery_not_checked", fmt.Sprintf(
			"The wire form could not be rendered (%v), so this payload deliverability was NOT "+
				"checked. That is a gap, not a pass.", err))
		return 0, out
	}

	// The encoder the run will use for an operator payload is the declared one, verbatim: the
	// custom send path in triageRun.go passes it straight to EncodeSlotInto with no fallback to
	// the slot kind's default, unlike a shipped probe. This check matches that rather than being
	// kinder than the runner, because a check that is kinder than the runner is how a payload
	// passes here and is refused there.
	mode := triage.EncoderMode(strings.TrimSpace(p.Encoder))

	wireLen := 0
	for _, k := range points {
		probes := triageDeliveryProbes(k)
		rows := make([]TriagePayloadDelivery, 0, len(probes))
		proven := 0

		for _, probe := range probes {
			// The same ProbeRequest shape the runner builds for an operator payload, through the
			// same renderer, so marker_placement "omitted" and the class token grammar are honoured
			// here once rather than re-implemented.
			req := triage.ProbeRequest{
				Spec: spec.ID, Slot: probe.slot.Key, Marker: marker,
				Variant: triageCustomVariant(p),
			}
			// triageRenderPayloadInto, WITH THE MODE, and not the two-value wrapper. The
			// renderer's own marker rule depends on the encoder: it drops the marker rather than
			// turn a JSON value into something json_node_replace would refuse. Calling the
			// wrapper here would pass EncodeNone, place a marker the run will not place, and
			// refuse a payload that is perfectly deliverable, which is the same drift as D2f in
			// the other direction.
			wire, unresolved, pos := triageRenderPayloadInto(spec, req, probe.slot, marker, mode)
			if unresolved != "" {
				// The runner refuses this probe outright and records custom_payload_unrendered.
				// Nothing about the target is measured, so the refusal belongs at save time.
				add(".payload", "payload_token_unresolved", fmt.Sprintf(
					"On class %s this payload is rendered through that class own token grammar, and %s "+
						"An operator payload carries no per-probe values, so the run would send nothing.",
					p.Class, unresolved))
				return wireLen, out
			}
			if len(wire) > wireLen {
				// The longest rendered form across the declared points. They differ only where the
				// class grammar splices the observed value in, and the longest is the one that has
				// to fit.
				wireLen = len(wire)
			}

			enc := EncodeSlotInto(probe.tmpl, probe.slot, mode, wire, triage.SlotOverrides{})
			row := TriagePayloadDelivery{
				Point:        string(k),
				Media:        probe.media,
				Encoder:      encoderChainName(enc),
				WireLen:      len(wire),
				MarkerOnWire: pos != "",
				Delivered:    enc.Delivered,
				Survived:     string(enc.Wire.Survived),
				Proven:       enc.Delivered && enc.Wire.Survived.Proven(),
				Reason:       string(enc.Reason),
				Detail:       enc.Detail,
			}
			if row.Proven && !row.MarkerOnWire && !triageMarkerOmitted(p.MarkerPos) {
				// THE MARKER WAS ASKED FOR AND WILL NOT BE THERE. The renderer dropped it to keep
				// the payload deliverable, which is the right trade and is invisible from the
				// modal. Say it out loud: a probe with no marker on the wire cannot be attributed,
				// so nothing it provokes can be tied back to it.
				warn(".marker_pos", "marker_dropped_on_the_wire", fmt.Sprintf(
					"At %s the %d-byte marker is left off, because adding it would stop these bytes "+
						"being a JSON value and the %s encoder would refuse the whole probe. The "+
						"payload is sent as you wrote it and nothing it provokes can be attributed "+
						"to it by marker.", triageDeliveryWhere(k, probe.media), triage.MarkerLen, mode))
			}
			if row.Encoder == "" {
				// A refused encode has no chain, and a blank column reads as "no encoder was
				// involved" rather than "this one refused".
				row.Encoder = p.Encoder
			}
			if row.Proven {
				proven++
			}
			rows = append(rows, row)
		}

		out = append(out, rows...)
		for _, row := range rows {
			if row.Proven {
				continue
			}
			where := triageDeliveryWhere(k, row.Media)
			detail := row.Detail
			if detail == "" {
				detail = row.Reason
			}
			detail += triageMarkerBlame(p)

			// ONE MEDIUM REFUSING IS NOT AN UNDELIVERABLE PAYLOAD. json_node_replace reaches a JSON
			// body and cannot reach a form body; refusing the SAVE throws the JSON coverage away
			// too, while the form slots record a named not_reachable that no report may read as
			// clean. Coverage is the expensive side, so this is a warning when another medium at
			// the same point carries the payload, and an error when none does.
			if proven > 0 {
				warn(".payload", "not_deliverable_at_one_medium", fmt.Sprintf(
					"Will not be sent into %s: %s. The other medium at this insertion point carries it, "+
						"and those slots record a named refusal rather than a clean.", where, detail))
				continue
			}
			code, msg := "not_deliverable", fmt.Sprintf("Cannot be delivered into %s: %s", where, detail)
			if row.Delivered {
				code = "not_intact_on_the_wire"
				msg = fmt.Sprintf("Reaches %s but the application does not read it back: %s", where, detail)
			}
			add(".payload", code, msg)
		}
	}
	return wireLen, out
}

// triageCheckReflectHasAMarker refuses the one combination that could only ever read as a clean:
// an oracle that judges a hit by finding the marker in the response, on a payload the renderer
// will send with no marker in it.
//
// THIS IS THE SILENT-CLEAN SHAPE, NOT A TIDINESS RULE. triageCustomVerdict records StateClean
// with "went out as asked and its own declared oracle stayed silent" when a reflect-mode payload
// finds nothing. An unmarked probe finds nothing on every target there has ever been, so the
// verdict is clean on every slot, forever, and the operator reads coverage that does not exist.
// The bare marker position is refused with reflect for the same reason, in triageValidateMarkerPos.
func triageCheckReflectHasAMarker(add func(f, code, msg string), p TriageCustomPayload, rows []TriagePayloadDelivery) {
	if p.Detection.Mode != TriageDetectReflect {
		return
	}
	for _, row := range rows {
		if !row.Proven || row.MarkerOnWire {
			continue
		}
		add(".detection.mode", "reflect_marker_dropped_on_the_wire", fmt.Sprintf(
			"At %s this payload is sent WITHOUT the marker, because adding it would stop these "+
				"bytes being a JSON value and the %s encoder would refuse the probe. Reflection "+
				"looks for a marker that will not be in the request, so it can only ever be silent, "+
				"and a silent oracle is recorded as a clean. Choose another oracle for this payload.",
			triageDeliveryWhere(triage.SlotKind(row.Point), row.Media), row.Encoder))
		return
	}
}

// triageDeliveryWhere is the one spelling of an insertion point plus its medium, so the refusal
// and the warning about the same row name the same place.
func triageDeliveryWhere(k triage.SlotKind, media string) string {
	if media == "" {
		return string(k)
	}
	return string(k) + " (" + media + ")"
}

// triageMarkerBlame names the marker when the marker is part of what failed, because "not a JSON
// value" said about bytes the operator can see ARE a JSON value is the kind of message that gets
// reported as a bug in the checker.
func triageMarkerBlame(p TriageCustomPayload) string {
	if triageMarkerOmitted(p.MarkerPos) {
		return ""
	}
	return fmt.Sprintf(
		". This is the payload WITH the %d-byte run marker the runner places at the %s, which is what "+
			"goes on the wire. Set the marker position to %q if this payload grammar cannot carry it; "+
			"it can then no longer be judged by reflection.",
		triage.MarkerLen, triageOrDefault(p.MarkerPos, string(triage.MarkerPrefix)), TriageMarkerPosNone)
}

// triageCheckRunID is the run id the representative marker carries. Four bytes of [0-9a-z], which
// is what triage.WellFormedRunID requires, and a constant because this marker never leaves the
// process.
const triageCheckRunID = "0000"

// triageRepresentativeMarker mints a real, well-formed marker in this class own stripe, so the
// save-time check renders the payload the way a run will.
//
// IT IS REPRESENTATIVE, NOT THE RUN MARKER. The run id and the ordinal are not known until a run
// starts. That costs this check nothing: every marker is exactly triage.MarkerLen bytes drawn
// from [0-9a-z], anchor included, so any two are interchangeable for every question asked here,
// which is length, impossible bytes, JSON validity and cookie-octet survival. What they are not
// interchangeable for is attribution, and nothing here attributes anything.
func triageRepresentativeMarker(class triage.ClassID) (triage.Marker, error) {
	// The first ordinal in a class stripe is the class id itself, which is what MarkerMinter
	// allocates first, so the representative marker carries the same stripe arithmetic as a real
	// one rather than a shape that could never be minted.
	return triage.MintMarkerAt(triagecap.Grant(), triageCheckRunID, class, uint64(class))
}

func encoderChainName(e Encoded) string {
	if len(e.Wire.EncoderChain) == 0 {
		return ""
	}
	return string(e.Wire.EncoderChain[len(e.Wire.EncoderChain)-1])
}

// triageDeliveryProbe is one synthetic slot plus the request it sits in.
type triageDeliveryProbe struct {
	slot  triage.Slot
	tmpl  RequestTemplate
	media string
}

// triageDeliveryProbes builds the synthetic slots for one insertion point. Body is two probes, not
// one: a JSON string value escapes a raw quote and a form field percent-encodes an ampersand, and
// a payload that survives one may not survive the other.
func triageDeliveryProbes(k triage.SlotKind) []triageDeliveryProbe {
	base := func() RequestTemplate {
		return RequestTemplate{
			Method: "POST",
			URL:    "https://triage.invalid/probe/segment?p=v",
			Headers: [][2]string{
				{"Host", "triage.invalid"},
				{"Cookie", "c=v"},
				{"X-Probe", "v"},
			},
		}
	}
	slot := func(s triage.Slot) triage.Slot {
		s.VectorID = "triage-settings-check"
		s.Key = triage.SlotKey("triage-settings-check")
		s.Method = "POST"
		s.ServerReachable = true
		s.SegmentIndex = -1
		s.Origin = triage.SlotObserved
		s.ValueOrigin = triage.ValueObserved
		s.Constraints = triage.NewSlotConstraints()
		return s
	}

	switch k {
	case triage.KindQuery:
		return []triageDeliveryProbe{{slot: slot(triage.Slot{Kind: k, Name: "p", Value: "v"}), tmpl: base()}}
	case triage.KindCookie:
		return []triageDeliveryProbe{{slot: slot(triage.Slot{Kind: k, Name: "c", Value: "v"}), tmpl: base()}}
	case triage.KindHeader:
		return []triageDeliveryProbe{{slot: slot(triage.Slot{Kind: k, Name: "X-Probe", Value: "v"}), tmpl: base()}}
	case triage.KindPath:
		s := slot(triage.Slot{Kind: k, Value: "segment"})
		s.SegmentIndex = 1
		return []triageDeliveryProbe{{slot: s, tmpl: base()}}
	case triage.KindBody:
		jsonTmpl := base()
		jsonTmpl.Body = []byte(`{"f":"v"}`)
		jsonTmpl.BodyMedia = triage.BodyJSON
		jsonSlot := slot(triage.Slot{Kind: k, Name: "f", FieldPath: "/f", Value: "v", BodyMedia: triage.BodyJSON})

		formTmpl := base()
		formTmpl.Body = []byte("f=v")
		formTmpl.BodyMedia = triage.BodyForm
		formSlot := slot(triage.Slot{Kind: k, Name: "f", Value: "v", BodyMedia: triage.BodyForm})

		return []triageDeliveryProbe{
			{slot: jsonSlot, tmpl: jsonTmpl, media: "json"},
			{slot: formSlot, tmpl: formTmpl, media: "form"},
		}
	}
	return nil
}

func triageEncodersOf(mode string) []triage.EncoderMode {
	if strings.TrimSpace(mode) == "" {
		return nil
	}
	return []triage.EncoderMode{triage.EncoderMode(mode)}
}

// ---------------------------------------------------------------------------------------------
// 5b. AUTOMATIC SESSION RENEWAL, AND THE GATE THAT DECIDES WHETHER IT MAY BE OFFERED AT ALL
// ---------------------------------------------------------------------------------------------
//
// WHY THERE IS A GATE AND NOT JUST A SWITCH.
//
// A renewal switch is a promise that the scan will still be authenticated at minute twenty nine.
// The framework can only make that promise about a session it has actually renewed. Everything
// short of that is an assumption wearing a measurement's clothes:
//
//	a refresh_token field in a captured body   -> the grant exists. Nobody has spent it.
//	an auth flow recorded against the token    -> the steps exist. Nobody has replayed them.
//	a /token or /silent-renew in the corpus    -> the endpoint exists. Nobody has called it.
//
// Those are RefreshAvailable in SessionTokenProfile, and RefreshProven is reserved for the case
// where a refresh was performed and a DIFFERENT credential came back. RecordRefreshProof refuses
// to write proven without two fingerprints that differ. This gate refuses to offer the control
// without that status. It is the same discipline as validated-requires-a-proof-of-concept, and
// the cost of getting it wrong is the same shape: a scan the operator believes covered something.
//
// A STALE PROOF IS NOT A PROOF, AND HERE IS HOW THIS ONE EXPIRES.
//
// Three independent tests, all of which must hold. Each one is a fact in the database, not a
// timer somebody picked:
//
//  1. STATUS. There is a refresh event with status success, which is the only thing
//     RecordRefreshProof writes and the only thing DetectRefreshCapability will call proven.
//
//  2. NOT BROKEN SINCE. No LATER refresh event failed. This is the case the brief names and it is
//     a real hole in the layer below: DetectRefreshCapability selects the most recent SUCCESS and
//     never looks at what happened after it, so a token proven on Monday and failing every day
//     since still reads as proven. The gate reads the most recent refresh event of ANY status and
//     compares. Statuses the framework writes are success (the proof), refreshed (a real refresh
//     that did not record a proof), and no_flow, replay_failed and no_token_found (failures); an
//     UNRECOGNISED status counts as a failure and is quoted verbatim, because a status nobody
//     here has seen is not evidence that a refresh worked.
//
//  3. NOT OLDER THAN ITS OWN CLOCK. A proof is the statement "at time T this mechanism minted a
//     working credential". The credential it minted is dead by T plus the measured lifetime, and
//     after that nothing about the mechanism has been observed in the present tense. So the proof
//     window IS the measured lifetime: the TTL where the TTL was measured, the observed floor
//     where only a floor was (the floor is a lower bound, so holding the proof to it errs towards
//     re-proving), and where NEITHER was measured there is no lifetime clock at all and the
//     window falls back to the estimated length of the run the proof is being asked to cover,
//     derived from this document's own pacing. Every option carries the basis sentence, so the
//     operator can see which of the three it got and why.
//
// Test 3 looks aggressive on a fifteen minute token and it is meant to: prove the refresh, then
// start the run. It is also self-sustaining, because each renewal performed during a run records
// a fresh proof, so the proof follows the credential forward for as long as renewal is working
// and goes stale the moment it stops.
//
// WHAT IS A WARNING AND NOT A REFUSAL. A proof taken against a credential that has since been
// replaced by hand is reported and does not block: the proof is about the MECHANISM, and pasting
// a new value does not unprove that the mint works. An unmeasured lifetime does not block either;
// it removes the derived interval and makes the operator type one, which is then labelled as
// their figure. Refusing there would be refusing on a missing measurement rather than on a
// missing proof, and the missing proof is the thing this gate is for.

// Refusal and status codes. They are constants because the client renders a sentence per code and
// a code invented at a call site is a sentence nobody wrote.
const (
	// The gate as a whole.
	TriageRenewalGateNotEvaluated = "gate_not_evaluated"
	TriageRenewalNoCredential     = "no_credential"
	TriageRenewalNoneProven       = "no_credential_proven"
	TriageRenewalOfferable        = "offerable"

	// Per credential.
	TriageRenewalProven         = "proven"
	TriageRenewalNeverProven    = "never_proven"
	TriageRenewalProofBroken    = "proof_broken"
	TriageRenewalProofStale     = "proof_stale"
	TriageRenewalMintOutOfScope = "mint_out_of_scope"
	TriageRenewalNoMechanism    = "no_mechanism_found"
	TriageRenewalNotNeeded      = "non_expiring"
	TriageRenewalNoValue        = "no_credential_value"
	// TriageRenewalNotProfiled is NOT a weaker no_mechanism_found. It is the state before the
	// search: nothing has characterised this credential, so nothing has read its flow, its corpus
	// or its own claims, and no_mechanism_found would be a report of a search that never ran.
	TriageRenewalNotProfiled = "refresh_not_checked"
)

// triageRefreshEventIsFailure classifies one session_token_events row of kind refresh.
//
// The two statuses that are not failures are named explicitly and everything else is one. That is
// deliberate: a new status added elsewhere in the codebase must arrive here as "a refresh event
// this gate does not recognise" and take the control away, rather than being waved through by a
// default that assumed the best.
func triageRefreshEventIsFailure(status string) bool {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "success", "refreshed":
		return false
	}
	return true
}

// TriageRenewalCredential is everything the gate needs about one credential. It holds NO secret:
// the closest it comes is the profile's eight hex digit fingerprint.
type TriageRenewalCredential struct {
	TokenID  string
	Name     string
	IsActive bool
	Profile  SessionTokenProfile
	// ProfileIsStale is true when the stored characterisation described a DIFFERENT value than the
	// one held now, so the lifetime here was recomputed from the credential rather than read back.
	ProfileIsStale bool

	// LastRefresh is the most recent refresh event of ANY status, which is what test 2 above
	// needs and what DetectRefreshCapability does not look at.
	LastRefreshAt     time.Time
	LastRefreshStatus string
	LastRefreshDetail string

	// ProvenAt and ProofAfterFingerprint come from the most recent refresh event with status
	// success, which is the only thing RecordRefreshProof writes.
	ProvenAt              time.Time
	ProofDetail           string
	ProofAfterFingerprint string
}

// TriageRenewalOption is one credential as the configuration screen sees it.
type TriageRenewalOption struct {
	TokenID     string `json:"token_id"`
	Name        string `json:"name"`
	Carrier     string `json:"carrier"`
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint"`
	IsActive    bool   `json:"is_active"`

	// Usable is whether renewal may be turned on FOR THIS CREDENTIAL, and Reason is the sentence
	// the operator can act on either way. Code is the machine-readable form of the same answer.
	Usable bool   `json:"usable"`
	Code   string `json:"code"`
	Reason string `json:"reason"`

	// The measured lifetime, carried with its provenance because a number without one is exactly
	// the defect this codebase keeps rediscovering.
	TTLKnown      bool   `json:"ttl_known"`
	TTLSeconds    int64  `json:"ttl_seconds"`
	TTLDisplay    string `json:"ttl_display"`
	TTLProvenance string `json:"ttl_provenance"`
	TTLEvidence   string `json:"ttl_evidence"`
	// TTLIsUpperBound is set when the profiler said so in its own evidence, which today means a
	// lifetime derived from exp minus nbf. It matters here and nowhere else: an interval derived
	// from an upper bound can be too long, so the renewal can fire after the credential is dead.
	TTLIsUpperBound bool   `json:"ttl_is_upper_bound"`
	ExpiryDisplay   string `json:"expiry_display"`
	ExpiryStyle     string `json:"expiry_style"`

	// SurvivesRun is Survives() asked about the estimated run length: three states, and known
	// false is not a yes.
	SurvivesRun   bool   `json:"survives_run"`
	SurvivesKnown bool   `json:"survives_known"`
	SurvivesWhy   string `json:"survives_why"`

	// The derived schedule. IntervalKnown false means nothing measured can produce one and the
	// operator has to supply it.
	IntervalSeconds int    `json:"interval_seconds"`
	IntervalKnown   bool   `json:"interval_known"`
	IntervalBasis   string `json:"interval_basis"`

	// The proof, and the window it is being held to.
	RefreshStatus      string    `json:"refresh_status"`
	RefreshMechanism   string    `json:"refresh_mechanism"`
	MintHost           string    `json:"mint_host"`
	MintInScope        bool      `json:"mint_in_scope"`
	ProvenAt           time.Time `json:"proven_at"`
	ProofAgeSeconds    int64     `json:"proof_age_seconds"`
	ProofWindowSeconds int64     `json:"proof_window_seconds"`
	ProofWindowBasis   string    `json:"proof_window_basis"`
	RefreshEvidence    []string  `json:"refresh_evidence"`

	// Warnings are things the operator must see that do not take the control away.
	Warnings []string `json:"warnings"`
}

// TriageRenewalGate is the whole answer for one target.
type TriageRenewalGate struct {
	// Evaluated is false on the zero value, and a zero gate REFUSES an enabled renewal rather
	// than allowing it. A gate that was never computed has not proven anything.
	Evaluated bool `json:"evaluated"`
	// Offerable is whether the control may be shown as usable at all: true when at least one
	// credential is usable.
	Offerable bool                  `json:"offerable"`
	Code      string                `json:"code"`
	Reason    string                `json:"reason"`
	Options   []TriageRenewalOption `json:"options"`
	// The run length the proof window falls back to, and where it came from, carried so the
	// screen can show the arithmetic rather than a bare number.
	RunEstimateSeconds int64     `json:"run_estimate_seconds"`
	RunEstimateBasis   string    `json:"run_estimate_basis"`
	EvaluatedAt        time.Time `json:"evaluated_at"`
}

// Option returns the option for one token id.
func (g TriageRenewalGate) Option(tokenID string) (TriageRenewalOption, bool) {
	for _, o := range g.Options {
		if o.TokenID == tokenID {
			return o, true
		}
	}
	return TriageRenewalOption{}, false
}

// TriageEstimatedRunDuration is how long the configured run is expected to take, and the sentence
// that says how that was worked out.
//
// It is per_run_probes divided by requests_per_second: the run's own budget at the run's own rate.
// It is an ESTIMATE and is labelled as one everywhere it is shown. It is used for two things, both
// of which want an order of magnitude rather than a stopwatch: asking Survives() whether the
// credential would last the run, and bounding a refresh proof when nothing about the credential's
// lifetime was ever measured.
func TriageEstimatedRunDuration(p TriagePacing) (time.Duration, string) {
	if p.RequestsPerSecond <= 0 || p.PerRunProbes <= 0 {
		return 0, "the run length cannot be estimated: the pacing has no positive rate or no positive per-run budget"
	}
	secs := float64(p.PerRunProbes) / p.RequestsPerSecond
	d := time.Duration(secs * float64(time.Second))
	return d, fmt.Sprintf("an estimated %s: %d probes at %.2f per second", humaniseTTL(d), p.PerRunProbes, p.RequestsPerSecond)
}

// TriageRenewalIntervalFor derives the renewal interval FROM THE MEASURED LIFETIME.
//
// Half of it. Not two thirds, not ninety percent, and not a constant: at half the lifetime a
// renewal that fails still leaves a whole second half in which to retry before the credential
// dies, and one full retry window is the least that makes the schedule recoverable. Renewing at
// ninety percent leaves a tenth of a lifetime for a retry that has to traverse a login flow.
//
// The bool is the usual three-state honesty. Where no lifetime was measured there is nothing to
// halve, and this returns false rather than a number, because a schedule built on a guess
// under-runs or over-runs silently and the operator cannot tell which from the outside.
func TriageRenewalIntervalFor(p SessionTokenProfile) (time.Duration, bool, string) {
	if measured, how := triageNonExpiringIsMeasured(p); measured {
		return 0, false, "the credential was measured as non-expiring (" + how + "), so there is nothing to renew"
	}
	if p.TTLKnown && p.TTL > 0 {
		half := p.TTL / 2
		basis := fmt.Sprintf("half of the measured %s lifetime (%s: %s), which leaves one full retry window before it expires",
			humaniseTTL(p.TTL), p.TTLProvenance, p.TTLEvidence)
		if triageTTLIsUpperBound(p) {
			basis += ". That lifetime is an UPPER BOUND, so the real one may be shorter and this schedule may fire late"
		}
		return half, true, basis
	}
	if p.TTLFloorKnown && p.TTLFloor > 0 {
		// A floor is a lower bound on the lifetime, so half of it is safely early rather than
		// late. It is still not a TTL and it is not allowed to pretend to be one. AND IT IS ONLY
		// EARLY WHILE IT IS ONE CREDENTIAL'S OWN SPAN: see triageFloorBelongsToOneCredential.
		if ok, why := triageFloorBelongsToOneCredential(p); !ok {
			return 0, false, "the lifetime was never measured, and the lower bound on record cannot be used to derive one: " + why
		}
		half := p.TTLFloor / 2
		// The LABEL comes from the provenance, because the two kinds of floor are different facts
		// and one sentence may not use the same word for both. floorPhrase is the profile's own
		// wording for each, so a reader is not told twice in two vocabularies.
		return half, true, fmt.Sprintf(
			"half of the %s: %s (%s). The lifetime itself was never measured, so this is a floor and not a TTL: it renews early rather than late",
			triageFloorBoundLabel(p), floorPhrase(p.floorProvenance(), p.TTLFloor), p.FloorEvidence())
	}
	return 0, false, "neither a lifetime nor a lower bound has ever been measured for this credential, so no interval can be derived from a measurement"
}

// triageFloorBelongsToOneCredential answers whether the lower bound on record is a span of ONE
// credential's life. It is the only kind a schedule may be built on.
//
// THE MEASUREMENT THAT MADE THIS A FUNCTION. A value stored one hour ago carried a probed floor of
// 5h59m and a sentence saying it "was alive across 5h59m of its own life". Halving it scheduled the
// first renewal 2h59m out, on a credential whose real life was fifteen minutes. Renewing LATE is
// the one direction this feature may never run, so this is a refusal and not a warning.
//
// IT ASKS THE PROFILE RATHER THAN DECIDING AGAIN, AND THAT IS THE WHOLE POINT OF THE FUNCTION.
//
// This file used to answer the question itself, by switching on TTLFloorProvenance. That made two
// predicates on one question, and they disagreed: SessionTokenProfile.FloorBelongsToOneCredential
// returned true for a probed floor while this returned false for the same profile, so the same
// number was one credential's life to the thing that measured it and nobody's to the thing that
// read it. Only the producer knows how a floor was got, so only the producer may answer, and a
// second opinion here is a second thing to be wrong.
//
// WHAT THE PRODUCER ANSWERS TODAY, READ IN applyProbeHistory RATHER THAN ASSUMED HERE. A probed
// span is taken only across validation events attributeProbe could tie to the value stored now,
// by the fingerprint stamped on the event or by the anchor credentialHeldSince returns, and where
// it can tie none there is no floor at all. That attribution is what makes a probed floor usable,
// and it is also why the refusal above no longer applies to one.
//
// A FLOOR WITH NOTHING RECORDED IS STILL REFUSED, by the producer and for the same reason: nothing
// says which path produced it, so nothing can say whether it spans a rotation.
func triageFloorBelongsToOneCredential(p SessionTokenProfile) (bool, string) {
	return p.FloorBelongsToOneCredential()
}

// triageFloorBoundLabel names WHICH KIND of lower bound a sentence is about.
//
// Every sentence in this file used to say "OBSERVED LOWER BOUND" whatever the provenance was. That
// was harmless only while probed floors were refused outright; the moment one is allowed through,
// a span of the framework's own requests gets described to the operator as captured traffic, which
// is the defect this whole round is about arriving in a new place.
//
// The word comes from floorProvenance(), which returns unknown for an empty column rather than
// defaulting it to observed. The unlabelled case is the honest one for that: "LOWER BOUND" claims
// nothing about where the number came from. It is currently unreachable from the two callers,
// because both of them ask triageFloorBelongsToOneCredential first and an unknown provenance is
// refused there, and it is kept because a caller that stops asking must not start lying.
func triageFloorBoundLabel(p SessionTokenProfile) string {
	switch p.floorProvenance() {
	case ProvObserved:
		return "OBSERVED LOWER BOUND"
	case ProvProbed:
		return "PROBED LOWER BOUND"
	}
	return "LOWER BOUND"
}

// triageNonExpiringIsMeasured answers whether a non_expiring style is a MEASUREMENT or a claim.
//
// WHY THE STYLE ALONE IS NOT ENOUGH, AND WHY THIS FILE HAD THE HOLE TWICE.
//
// SessionTokenProfile.Survives already refuses to grant an unconditional yes on the style alone,
// and says why in its own comment: nothing in that package can currently produce non_expiring, so
// the only way a profile carries it is a row somebody wrote by hand or a future writer that
// guessed. This file then read the same style in two places and called it "measured" both times,
// which is the same defect the Survives guard exists to close and a worse one in its consequences.
// Survives failing open would withhold a yes; this failing open ASSURES the operator that a run of
// any length outlives a credential that may die at minute ten, and takes the renewal control away
// on the strength of it.
//
// The test is the same one Survives applies: the provenance has to name a method that could have
// established the claim. ProvUnknown cannot, and neither can an empty column.
func triageNonExpiringIsMeasured(p SessionTokenProfile) (bool, string) {
	if p.ExpiryStyle != ExpiryStyleNonExpiring {
		return false, ""
	}
	switch p.ExpiryProvenance {
	case ProvParsed, ProvProbed, ProvDeclared:
		return true, string(p.ExpiryProvenance)
	}
	return false, ""
}

// triageNonExpiringClaimIsUnbacked is the other half: the row says non-expiring and nothing says
// how that was established. It is a WARNING rather than a refusal, because the credential is then
// judged on its measured lifetime like any other and the claim is simply not used.
func triageNonExpiringClaimIsUnbacked(p SessionTokenProfile) bool {
	if p.ExpiryStyle != ExpiryStyleNonExpiring {
		return false
	}
	measured, _ := triageNonExpiringIsMeasured(p)
	return !measured
}

// triageTTLIsUpperBound reads the profiler's OWN wording. The exp-minus-nbf rung says so in its
// evidence because nbf may be backdated for clock skew, and a lifetime that may be longer than the
// truth is the one direction that makes a renewal schedule fire too late.
//
// It is a substring test on a sentence the profiler writes, which is weaker than a field, and the
// failure mode is chosen on purpose: if that wording ever changes, what is lost is a WARNING, and
// the evidence string itself is rendered verbatim beside the interval either way, so the operator
// still reads the same fact in the same place.
func triageTTLIsUpperBound(p SessionTokenProfile) bool {
	return strings.Contains(strings.ToLower(p.TTLEvidence), "upper bound")
}

// triageProofWindowFor is test 3: how long a refresh proof stays current for this credential, and
// the sentence saying which of the three clocks it got.
func triageProofWindowFor(p SessionTokenProfile, runEstimate time.Duration) (time.Duration, string) {
	if p.TTLKnown && p.TTL > 0 {
		return p.TTL, fmt.Sprintf("the measured %s lifetime (%s): the credential that refresh minted is dead after that, so nothing about the mint has been observed in the present since",
			humaniseTTL(p.TTL), p.TTLProvenance)
	}
	// THE SAME REFUSAL THE INTERVAL MAKES, AND FOR THE SAME REASON. A window taken from a floor
	// that spans a rotation holds a proof current for many times the life of the credential it
	// minted, which is the stale proof this gate exists to refuse, arriving through the clock.
	floorRefusal := ""
	if p.TTLFloorKnown && p.TTLFloor > 0 {
		ok, why := triageFloorBelongsToOneCredential(p)
		if ok {
			return p.TTLFloor, fmt.Sprintf("the %s of %s. The lifetime was never measured, so the proof is held to the only span that was, which errs towards re-proving",
				strings.ToLower(triageFloorBoundLabel(p)), humaniseTTL(p.TTLFloor))
		}
		floorRefusal = " The lower bound on record was not used: " + why
	}
	if runEstimate > 0 {
		return runEstimate, fmt.Sprintf("the estimated %s length of this run. Nothing this proof could be held to has been measured on the credential itself, so there is no clock of its own, and the proof is instead required to be no older than the run it is authorising.%s",
			humaniseTTL(runEstimate), floorRefusal)
	}
	return 0, "no window could be established: neither the credential's lifetime nor the run's length can be estimated." + floorRefusal
}

// EvaluateTriageRenewalGate is the whole gate, and it is PURE: the same function backs the handler
// and the tests, and it never reaches a database or a network.
func EvaluateTriageRenewalGate(creds []TriageRenewalCredential, pacing TriagePacing, now time.Time) TriageRenewalGate {
	runEstimate, runBasis := TriageEstimatedRunDuration(pacing)
	g := TriageRenewalGate{
		Evaluated:          true,
		Options:            []TriageRenewalOption{},
		RunEstimateSeconds: int64(runEstimate / time.Second),
		RunEstimateBasis:   runBasis,
		EvaluatedAt:        now.UTC(),
	}
	for _, c := range creds {
		g.Options = append(g.Options, triageRenewalOptionFor(c, runEstimate, now))
	}
	usable := 0
	for _, o := range g.Options {
		if o.Usable {
			usable++
		}
	}
	switch {
	case len(g.Options) == 0:
		g.Code = TriageRenewalNoCredential
		g.Reason = "This target has no session credential recorded, so there is no session to renew. Add one in the Session Manager."
	case usable > 0:
		g.Offerable = true
		g.Code = TriageRenewalOfferable
		g.Reason = fmt.Sprintf("%d of %d credential(s) have a refresh the framework has performed and watched return a different working credential.", usable, len(g.Options))
	default:
		g.Code = TriageRenewalNoneProven
		g.Reason = triageRenewalRefusalReason(g.Options)
	}
	return g
}

// triageRenewalRefusalReason is the target-level sentence when nothing is offerable.
//
// IT MAY NOT STATE A FACT IT DID NOT READ. The sentence this replaced was a hardcoded string:
// "the framework has never performed a refresh of any credential on this target and watched a new
// working credential come back". On proof_stale and on proof_broken that is FALSE, and it was
// falsified two sentences later in its own message by the per-credential advice, which says "One
// credential WAS proven". That whole paragraph reaches the operator verbatim on the configuration
// screen. Five shipped strings in this codebase have already been proven false by measurement and
// this was the sixth.
//
// So the claim is derived from the options rather than assumed: a proof is on record when an
// option carries a non-zero ProvenAt, which is read from session_token_events and is the same fact
// the per-credential branches used to contradict it with.
func triageRenewalRefusalReason(options []TriageRenewalOption) string {
	everProven, notNeeded, noValue := false, 0, 0
	for _, o := range options {
		if !o.ProvenAt.IsZero() {
			everProven = true
		}
		switch o.Code {
		case TriageRenewalNotNeeded:
			notNeeded++
		case TriageRenewalNoValue:
			noValue++
		}
	}
	whatToDo := triageRenewalWhatToDo(options)

	switch {
	case notNeeded == len(options) && len(options) > 0:
		// Nothing is refused here and saying "cannot be turned on" would read as a fault.
		return fmt.Sprintf("Automatic renewal is not offered: all %d credential(s) on this target were measured as non-expiring, so a run of any length outlives them and renewing would change nothing.", len(options))
	case noValue == len(options) && len(options) > 0:
		return fmt.Sprintf("Automatic renewal cannot be turned on: all %d credential(s) on this target have no value stored, so there is nothing to renew and nothing that could have been proven. %s", len(options), whatToDo)
	case everProven:
		return "Automatic renewal cannot be turned on. A refresh HAS been performed on this target and recorded, but that proof no longer describes what happens now, so it cannot support a promise that the scan will still be authenticated at the end of the run. " + whatToDo
	}
	return "Automatic renewal cannot be turned on: the framework has never performed a refresh of any credential on this target and watched a new working credential come back. Until it has, renewal would be a promise nothing measured supports. " + whatToDo
}

// triageRenewalWhatToDo turns the per-credential codes into one next action, because a refusal
// that does not say what would lift it is a refusal the operator argues with instead of acting on.
func triageRenewalWhatToDo(options []TriageRenewalOption) string {
	seen := map[string]bool{}
	for _, o := range options {
		seen[o.Code] = true
	}
	// THE ADVICE NAMES THE CONTROL THAT ACTUALLY RECORDS A PROOF, which is the proof button on
	// this screen: it saves with a prove_refresh sidecar, which is what reaches
	// ProveSessionRefreshForTarget and RecordRefreshProof. Three of these sentences used to say
	// "refresh once from the Session Manager". MEASURED end to end in round 12: that button
	// replays the flow, stores whatever comes back and records kind=refresh status=refreshed,
	// while the proof is read from kind=refresh status=SUCCESS, so following the instruction could
	// not lift the refusal on any application. An instruction that cannot work is worse than no
	// instruction: the operator does the thing, watches nothing change, and distrusts the screen.
	switch {
	case seen[TriageRenewalProofBroken]:
		return "One credential WAS proven and a refresh has failed since, so the proof no longer describes what happens now: fix the flow, then take a new proof with the proof button on this screen."
	case seen[TriageRenewalProofStale]:
		return "One credential was proven, but the proof is older than the credential it minted could live, so it says nothing about now: take a current proof with the proof button on this screen."
	case seen[TriageRenewalMintOutOfScope]:
		return "A refresh mechanism was found but it mints outside this engagement's scope, so the framework must not exercise it: re-authenticate by hand and paste a fresh value before a long run."
	case seen[TriageRenewalNeverProven]:
		return "A refresh mechanism was found but has never been exercised: take the proof with the proof button on this screen, which replays the recorded login once and records the proof only if a different working credential comes back."
	case seen[TriageRenewalNotProfiled]:
		return "No credential here has been characterised yet, so nothing has looked for a refresh mechanism: open the Session Manager for this target, which characterises every credential it lists."
	case seen[TriageRenewalNotNeeded]:
		return "The credential here was measured as non-expiring, so a long run does not need renewal."
	}
	return "No refresh mechanism was found for any credential on this target: no auth flow with executable steps, no mint endpoint in the captured corpus and no refresh grant in any captured response."
}

// triageRenewalOptionFor decides ONE credential. Every branch writes a Reason the operator can
// act on, and no branch leaves Usable true on an absent measurement.
func triageRenewalOptionFor(c TriageRenewalCredential, runEstimate time.Duration, now time.Time) TriageRenewalOption {
	p := c.Profile
	o := TriageRenewalOption{
		TokenID:          c.TokenID,
		Name:             c.Name,
		Carrier:          p.Carrier.Describe(),
		Kind:             string(p.Kind),
		Fingerprint:      p.Fingerprint,
		IsActive:         c.IsActive,
		TTLKnown:         p.TTLKnown,
		TTLSeconds:       int64(p.TTL / time.Second),
		TTLDisplay:       p.TTLDisplay(),
		TTLProvenance:    string(p.TTLProvenance),
		TTLEvidence:      p.TTLEvidence,
		TTLIsUpperBound:  triageTTLIsUpperBound(p),
		ExpiryDisplay:    p.ExpiryDisplay(),
		ExpiryStyle:      string(p.ExpiryStyle),
		RefreshStatus:    string(p.Refresh.Status),
		RefreshMechanism: string(p.Refresh.Mechanism),
		MintHost:         p.Refresh.MintHost,
		MintInScope:      p.Refresh.MintInScope,
		RefreshEvidence:  append([]string{}, p.Refresh.Evidence...),
		Warnings:         []string{},
	}
	o.SurvivesRun, o.SurvivesKnown, o.SurvivesWhy = p.Survives(runEstimate, now)
	if interval, known, basis := TriageRenewalIntervalFor(p); known {
		o.IntervalSeconds, o.IntervalKnown, o.IntervalBasis = int(interval/time.Second), true, basis
	} else {
		o.IntervalBasis = basis
	}
	if c.ProfileIsStale {
		o.Warnings = append(o.Warnings, "The stored characterisation described a different value than the one held now, so the lifetime shown here was recomputed from the credential itself and the corpus was not re-read.")
	}
	if p.TTLKnown && p.TTLProvenance != ProvDeclared && p.TTLProvenance != ProvParsed {
		o.Warnings = append(o.Warnings, fmt.Sprintf("This lifetime was %s rather than read from the credential or stated by the server, so the renewal schedule rests on an inference.", p.TTLProvenance))
	}
	if o.TTLIsUpperBound {
		o.Warnings = append(o.Warnings, "The measured lifetime is an UPPER BOUND, so the real one may be shorter and a schedule derived from it may fire after the credential is already dead.")
	}
	if !p.TTLKnown {
		o.Warnings = append(o.Warnings, "The lifetime of this credential has never been measured, so no interval can be derived from one; any interval used is a figure you supplied.")
	}
	if triageNonExpiringClaimIsUnbacked(p) {
		o.Warnings = append(o.Warnings, "This credential is recorded as non-expiring but nothing says how that was established, so it is an unmeasured claim and not a measurement. It is being judged on its measured lifetime instead, and the claim is not used.")
	}

	// The proof, in the order of the three tests. Each refusal names the test it failed.
	proofWindow, windowBasis := triageProofWindowFor(p, runEstimate)
	o.ProofWindowSeconds, o.ProofWindowBasis = int64(proofWindow/time.Second), windowBasis

	if p.Fingerprint == "" {
		o.Code, o.Reason = TriageRenewalNoValue, "This credential has no value stored, so there is nothing to renew and nothing that could have been proven."
		return o
	}
	if measured, how := triageNonExpiringIsMeasured(p); measured {
		o.Code, o.Reason = TriageRenewalNotNeeded, fmt.Sprintf(
			"This credential was measured as non-expiring (%s), so a run of any length outlives it and renewal would change nothing.", how)
		return o
	}

	// TEST 1: was it ever proven at all?
	if p.Refresh.Status != RefreshProven || c.ProvenAt.IsZero() {
		switch {
		case p.Refresh.Status == RefreshProven && c.ProvenAt.IsZero():
			// The column says proven and there is no event behind it. Trusting the column here
			// would let a hand-edited row arm a renewal nothing ever performed.
			o.Code = TriageRenewalNeverProven
			o.Reason = "This credential is recorded as proven but there is no successful refresh event behind that record, so there is no proof to read. Take one with the proof button on this screen."
		case p.Refresh.Status == RefreshMintOutOfScope:
			o.Code = TriageRenewalMintOutOfScope
			o.Reason = fmt.Sprintf("A refresh mechanism was found (%s at %s) but that host is outside this engagement's scope, so the framework must not mint from it. Re-authenticate by hand and paste a fresh value before a long run.",
				triageOrDefault(string(p.Refresh.Mechanism), "an unnamed mechanism"), triageOrDefault(p.Refresh.MintHost, "an unnamed host"))
		case p.Refresh.Status == RefreshAvailable:
			o.Code = TriageRenewalNeverProven
			o.Reason = fmt.Sprintf("A refresh mechanism exists (%s%s) but it has NEVER been exercised, so nothing here shows it yields a working credential. Take the proof with the proof button on this screen, which replays the recorded login once and records the proof only if a DIFFERENT credential comes back and the target honours it. The Session Manager's Refresh button is not that control: it replaces the stored value and records no proof. Over the API it is POST /session-tokens/{id}/prove-refresh, or a prove_refresh sidecar on this screen's save.",
				triageOrDefault(string(p.Refresh.Mechanism), "an unnamed mechanism"),
				triageRenewalMintSuffix(p))
		case p.Refresh.Status == "" || p.Refresh.Status == RefreshNotCharacterised:
			// NOT no_mechanism_found. Nothing has characterised this credential, so nothing has
			// read its flow, its corpus or its own claims: reporting a search here would be
			// reporting one that never ran. LoadTriageRenewalCredentials reaches this branch by
			// CLEARING the refresh half on its fallback path, which is a line in that function and
			// not a property of ProfileCredential: profileCredentialBytes returns not_observed,
			// and for two rounds that carried every uncharacterised credential into the default
			// branch below instead.
			//
			// RefreshNotCharacterised is accepted here as well as the zero value, so that when the
			// patch to profileCredentialBytes lands and it names the state instead of clearing it,
			// this branch keeps answering the same way rather than falling through again.
			o.Code = TriageRenewalNotProfiled
			o.Reason = "Nothing has characterised this credential yet, so no search for a refresh mechanism has been run for it. That is not the same as having looked and found none. Open the Session Manager for this target, which characterises every credential it lists and looks for the mechanism, then come back."
		default:
			o.Code = TriageRenewalNoMechanism
			o.Reason = "No refresh mechanism was found for this credential: no auth flow with executable steps, no mint endpoint in the captured corpus and no refresh grant in any captured response. Renewal cannot be offered for a session nothing knows how to renew."
		}
		return o
	}

	o.ProvenAt = c.ProvenAt.UTC()
	age := now.Sub(c.ProvenAt)
	if age < 0 {
		age = 0
	}
	o.ProofAgeSeconds = int64(age / time.Second)

	// TEST 2: has a refresh FAILED since the proof?
	if !c.LastRefreshAt.IsZero() && c.LastRefreshAt.After(c.ProvenAt) && triageRefreshEventIsFailure(c.LastRefreshStatus) {
		o.Code = TriageRenewalProofBroken
		o.Reason = fmt.Sprintf("A refresh WAS proven %s ago, and a refresh has FAILED since (%s, %s ago%s). The proof describes what used to happen, so renewal is not offered until a refresh succeeds again.",
			humaniseTTL(age), triageOrDefault(c.LastRefreshStatus, "an event with no status"),
			humaniseTTL(now.Sub(c.LastRefreshAt)), triageRenewalDetailSuffix(c.LastRefreshDetail))
		return o
	}

	// TEST 3: is the proof older than its own clock?
	if proofWindow <= 0 {
		o.Code = TriageRenewalProofStale
		o.Reason = "A refresh was proven, but " + windowBasis + ", so there is no way to say whether that proof is still current."
		return o
	}
	if age > proofWindow {
		o.Code = TriageRenewalProofStale
		o.Reason = fmt.Sprintf("The refresh was proven %s ago, which is older than %s. Nothing since then shows the mint still works, so the proof says nothing about now. Take a current one with the proof button on this screen.",
			humaniseTTL(age), windowBasis)
		return o
	}

	// The proof stands. Everything that is a warning rather than a refusal is added here.
	if c.ProofAfterFingerprint == "" {
		o.Warnings = append(o.Warnings, "That proof predates the recording of the credential it produced, so it could not be checked against the value held now.")
	} else if c.ProofAfterFingerprint != p.Fingerprint {
		o.Warnings = append(o.Warnings, fmt.Sprintf("The credential held now (%s) is not the one that refresh produced (%s), so the proof covers the mechanism rather than this value.",
			p.Fingerprint, c.ProofAfterFingerprint))
	}
	if !o.SurvivesKnown {
		o.Warnings = append(o.Warnings, "Whether this credential would have survived the run unrenewed is unknown: "+o.SurvivesWhy+".")
	} else if o.SurvivesRun {
		o.Warnings = append(o.Warnings, "This credential would survive the estimated run without renewal ("+o.SurvivesWhy+"), so renewal is insurance rather than a requirement here.")
	}
	o.Usable = true
	o.Code = TriageRenewalProven
	o.Reason = fmt.Sprintf("A refresh was performed %s ago and a DIFFERENT working credential came back%s. The proof is held to %s.",
		humaniseTTL(age), triageRenewalDetailSuffix(c.ProofDetail), windowBasis)
	return o
}

func triageRenewalMintSuffix(p SessionTokenProfile) string {
	if p.Refresh.MintHost == "" {
		return ""
	}
	return " at " + p.Refresh.MintHost
}

func triageRenewalDetailSuffix(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	return ": " + detail
}

// ---------------------------------------------------------------------------------------------
// What the runner is allowed to do with a stored renewal setting
// ---------------------------------------------------------------------------------------------

// TriageRenewalEffective is the ONE function a runner may ask "should I renew, and how often".
//
// IT IS FAIL CLOSED, and that is the whole point of it. A stored document that says enabled true
// is not permission: the gate is re-evaluated on every read, and a proof that has since broken or
// aged out takes the renewal away without anybody editing the document. The alternative is a
// setting that was true once and stays true forever, which is precisely the stale proof this
// section exists to refuse.
//
// The third return is always a sentence, on every path, because a runner that decided not to renew
// and cannot say why produces a scan whose authentication silently died.
func TriageRenewalEffective(s TriageInvestigateSettings, gate TriageRenewalGate, now time.Time) (bool, time.Duration, string) {
	r := s.SessionRenewal
	if !r.Enabled {
		return false, 0, "automatic session renewal is switched off for this target"
	}
	if !gate.Evaluated {
		return false, 0, "automatic session renewal is switched on, but the refresh gate was not evaluated for this run, and an unevaluated gate has proven nothing"
	}
	if strings.TrimSpace(r.TokenID) == "" {
		return false, 0, "automatic session renewal is switched on but names no credential, and renewing the wrong one leaves the scan authenticated as nobody"
	}
	o, found := gate.Option(r.TokenID)
	if !found {
		return false, 0, fmt.Sprintf("automatic session renewal names credential %s, which this target no longer has", r.TokenID)
	}
	if !o.Usable {
		return false, 0, "automatic session renewal is switched on but is no longer permitted: " + o.Reason
	}
	if r.IntervalSeconds > 0 {
		interval := time.Duration(r.IntervalSeconds) * time.Second
		// The same refusal the save endpoint makes, repeated here rather than assumed. The
		// validation pass is what a document written through the API is held to; this is what a
		// document is held to at the moment it is USED, and the two are different moments. An
		// interval no shorter than the lifetime schedules its first renewal for after the
		// credential is already dead, which is a run that renews nothing while reporting that it
		// renews.
		if o.TTLKnown && interval >= time.Duration(o.TTLSeconds)*time.Second {
			return false, 0, fmt.Sprintf("automatic session renewal is switched on with an interval of %s, which is not shorter than the credential's measured lifetime of %s, so the first renewal would fire after it had already expired",
				humaniseTTL(interval), humaniseTTL(time.Duration(o.TTLSeconds)*time.Second))
		}
		return true, interval, fmt.Sprintf("renewing %s every %s, the interval you set", o.Name, humaniseTTL(interval))
	}
	if !o.IntervalKnown {
		return false, 0, "automatic session renewal is switched on with no interval, and none can be derived: " + o.IntervalBasis
	}
	interval := time.Duration(o.IntervalSeconds) * time.Second
	return true, interval, fmt.Sprintf("renewing %s every %s, %s", o.Name, humaniseTTL(interval), o.IntervalBasis)
}

// ---------------------------------------------------------------------------------------------
// Reading the gate's inputs out of the database. Read only.
// ---------------------------------------------------------------------------------------------

// LoadTriageRenewalCredentials reads what the gate needs for one target. It WRITES NOTHING.
//
// It does not call AttachSessionTokenProfiles, which profiles on read and stores the result: a
// settings screen is not the place to take a measurement and a write, and the corpus group-by plus
// scope load that profiling costs would be paid on every GET of this form. Where a stored profile
// exists and describes the value held, it is used; where it does not, the lifetime half is
// recomputed with the PURE ProfileCredential and the option says the characterisation was stale.
//
// The refresh half is read from session_token_events directly rather than from the stored
// refresh_status column, because the column cannot express "proven and broken since": it is
// written by DetectRefreshCapability, which selects the most recent SUCCESS and never looks at
// what happened after it.
func LoadTriageRenewalCredentials(ctx context.Context, scopeTargetID string) ([]TriageRenewalCredential, error) {
	if dbPool == nil {
		return nil, fmt.Errorf("no database connection, so no credential could be read and no refresh proof could be checked")
	}
	rows, err := dbPool.Query(ctx,
		`SELECT `+sessionTokenCols+sessionTokenFrom+
			`WHERE t.scope_target_id = $1 ORDER BY t.is_active DESC, t.created_at ASC`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	tokens := []SessionToken{}
	for rows.Next() {
		t, scanErr := scanSessionToken(rows)
		if scanErr != nil {
			continue
		}
		tokens = append(tokens, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := make([]TriageRenewalCredential, 0, len(tokens))
	for _, tok := range tokens {
		cred := NewCredential(tok.TokenValue)
		c := TriageRenewalCredential{TokenID: tok.ID, Name: tok.Name, IsActive: tok.IsActive}

		stored, loadErr := LoadSessionTokenProfile(ctx, tok.ID)
		if loadErr == nil && !stored.ProfiledAt.IsZero() && stored.Fingerprint == cred.Fingerprint() {
			c.Profile = stored
		} else {
			// The pure profiler: the credential's own claims and the carrier, no corpus and no
			// network. It cannot see a refresh mechanism, which is why the refresh half below is
			// read separately and why a stale profile does not silently lose the proof.
			p := ProfileCredential(cred, CarrierForSessionToken(tok), now)
			p.TokenID, p.ScopeTargetID = tok.ID, tok.ScopeTargetID

			// AND THE REFRESH HALF IT RETURNS IS CLEARED, WHICH IS THE POINT OF THIS LINE.
			//
			// profileCredentialBytes fills Refresh with RefreshCapability{Status:
			// RefreshNotObserved}, and not_observed is the answer of a search: DetectRefreshCapability
			// writes it after reading the auth flows, the captured corpus and the token's own
			// grants. NOTHING ABOVE READ ANY OF THOSE. Left as it comes back, the gate's default
			// branch tells the operator "no auth flow with executable steps, no mint endpoint in
			// the captured corpus and no refresh grant in any captured response" about a credential
			// nobody has opened, and refresh_not_checked becomes unreachable on every real target.
			// Measured by driving this loader against a real database, after a pure test that built
			// the zero shape by hand had reported the same defect fixed twice.
			//
			// The zero capability is the state BEFORE the search, and that is the state here.
			p.Refresh = RefreshCapability{}

			if loadErr == nil && !stored.ProfiledAt.IsZero() {
				// A stored profile DID run the search, so its answer is kept even when the value
				// it described has been replaced. Losing it here would turn a real finding into
				// not-checked, which is the same defect pointing the other way.
				p.Refresh = stored.Refresh
				c.ProfileIsStale = true
			}
			c.Profile = p
		}
		c.Profile.Name = tok.Name

		// The proof and the most recent attempt, from the events table.
		var (
			provenAt     *time.Time
			provenDetail string
			provenAfter  string
		)
		_ = dbPool.QueryRow(ctx, `
			SELECT created_at, COALESCE(detail,''), COALESCE(evidence->>'after_fingerprint','')
			FROM session_token_events
			WHERE session_token_id = $1 AND kind = 'refresh' AND status = 'success'
			ORDER BY created_at DESC LIMIT 1`, tok.ID).Scan(&provenAt, &provenDetail, &provenAfter)
		if provenAt != nil {
			c.ProvenAt = provenAt.UTC()
			c.ProofDetail = provenDetail
			c.ProofAfterFingerprint = provenAfter
			// The stored profile can be older than the proof, and the pure profiler above cannot
			// see events at all. The event IS the proof, so it is what the profile says.
			c.Profile.Refresh.Status = RefreshProven
			c.Profile.Refresh.ProvenAt = c.ProvenAt
		}
		var (
			lastAt     *time.Time
			lastStatus string
			lastDetail string
		)
		_ = dbPool.QueryRow(ctx, `
			SELECT created_at, COALESCE(status,''), COALESCE(detail,'')
			FROM session_token_events
			WHERE session_token_id = $1 AND kind = 'refresh'
			ORDER BY created_at DESC LIMIT 1`, tok.ID).Scan(&lastAt, &lastStatus, &lastDetail)
		if lastAt != nil {
			c.LastRefreshAt = lastAt.UTC()
			c.LastRefreshStatus = lastStatus
			c.LastRefreshDetail = lastDetail
		}
		out = append(out, c)
	}
	return out, nil
}

// TriageRenewalGateFor loads the inputs and evaluates the gate. A database that cannot be read
// produces an EVALUATED gate that offers nothing and says why, rather than a zero gate: the two
// are the same refusal, but only one of them tells the operator what happened.
func TriageRenewalGateFor(ctx context.Context, scopeTargetID string, pacing TriagePacing) TriageRenewalGate {
	now := time.Now().UTC()
	creds, err := LoadTriageRenewalCredentials(ctx, scopeTargetID)
	if err != nil {
		runEstimate, runBasis := TriageEstimatedRunDuration(pacing)
		return TriageRenewalGate{
			Evaluated:          true,
			Offerable:          false,
			Code:               TriageRenewalNoCredential,
			Reason:             "The session credentials for this target could not be read, so no refresh proof could be checked and renewal cannot be offered: " + err.Error(),
			Options:            []TriageRenewalOption{},
			RunEstimateSeconds: int64(runEstimate / time.Second),
			RunEstimateBasis:   runBasis,
			EvaluatedAt:        now,
		}
	}
	return EvaluateTriageRenewalGate(creds, pacing, now)
}

// ---------------------------------------------------------------------------------------------
// 6. THE HANDLERS
// ---------------------------------------------------------------------------------------------

// LoadTriageSettings returns the effective settings for a target: the stored document filled out
// against the defaults. Absent is not an error, it is a target that has never been configured.
func LoadTriageSettings(ctx context.Context, scopeTargetID string) (TriageInvestigateSettings, []string) {
	raw := loadVectorSettings(ctx, scopeTargetID, TriageSettingsTool)
	var stored TriageInvestigateSettings
	if len(raw) > 0 {
		if b, err := json.Marshal(raw); err == nil {
			_ = json.Unmarshal(b, &stored)
		}
	}
	return NormaliseTriageSettings(stored)
}

// GetTriageSettings answers GET /triage/{scope_target_id}/settings.
func GetTriageSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if strings.TrimSpace(scopeTargetID) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_scope_target", "No scope target in the path.")
		return
	}

	ctx := context.Background()
	settings, retired := LoadTriageSettings(ctx, scopeTargetID)
	// The gate is RE-EVALUATED on every read, against the pacing this document actually carries.
	// That is what makes a proof that has since broken or aged out take the control away by
	// itself: the stored enabled:true then fails validation here, on the screen, rather than at
	// minute fifteen of a run that nobody is watching.
	gate := TriageRenewalGateFor(ctx, scopeTargetID, settings.Pacing)
	validation := ValidateTriageSettingsWithRenewal(settings, gate)

	json.NewEncoder(w).Encode(map[string]any{
		"scope_target_id": scopeTargetID,
		"tool":            TriageSettingsTool,
		"settings":        settings,
		"defaults":        TriageSettingsDefaults(),
		"vocabulary":      TriageSettingsVocabulary(),
		"validation":      validation,
		"retired_classes": retired,
		"renewal_gate":    gate,
	})
}

// triageSettingsBodyLimit bounds the read. The largest settings document this form can produce is
// the class table plus the operator's custom payloads, which is kilobytes; a megabyte is four
// orders of margin and still refuses a body nothing here could have meant.
const triageSettingsBodyLimit = 1 << 20

// DecodeTriageSettingsBody turns a PUT body into the settings document it names, or refuses it.
//
// =================================================================================================
// WHY IT IS A FUNCTION AND NOT A json.Decoder CALL IN THE HANDLER
// =================================================================================================
//
// The handler decoded into struct{ Settings TriageInvestigateSettings `json:"settings"` } and used
// the result unconditionally. MEASURED against the live endpoint, twice, same target, same minute:
//
//	PUT {"per_run_probes": 25000, ...}          -> 200 {"saved": true}, stored per_run_probes 4000
//	PUT {"settings": {"per_run_probes": 25000}} -> 200 {"saved": true}, stored per_run_probes 25000
//
// A body that IS the settings object carries no "settings" key, so the struct stayed entirely at
// its zero value. NormaliseTriageSettings does its job and fills a zero document with defaults,
// the defaults validate clean, and the INSERT ... ON CONFLICT DO UPDATE then replaced the
// operator's stored document with them. The caller was told it had saved what it sent.
//
// That is silent data loss on a write endpoint. It is reachable by anything driving this API
// directly rather than through the form, the MCP layer included, and the loss is invisible at the
// call site because the response carries saved:true and a settings object that looks plausible.
//
// THE RULE THIS FUNCTION ENFORCES: a body must NAME at least one field of the document it claims
// to be writing. Two shapes name one, the wrapper the form sends and the bare object a direct
// caller sends, and both are accepted because both are unambiguous. Everything else is refused,
// including the empty object: "the caller sent nothing" and "the caller sent exactly the defaults"
// are different requests and this endpoint may not answer them the same way.
//
// THE FIELD NAMES ARE READ OFF THE STRUCT and not typed out here, so a field added to
// TriageInvestigateSettings is recognised the day it is added rather than the day somebody
// remembers this list.
func DecodeTriageSettingsBody(body []byte) (TriageInvestigateSettings, error) {
	var zero TriageInvestigateSettings
	if len(bytes.TrimSpace(body)) == 0 {
		return zero, fmt.Errorf("the request body is empty, and an empty body is not a settings document: send either {\"settings\": {...}} or the settings object itself")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return zero, fmt.Errorf("the request body is not a JSON object, so it cannot be a settings document: %w", err)
	}

	known := triageSettingsFieldNames()
	named := make([]string, 0, len(known))
	for _, f := range known {
		if _, ok := top[f]; ok {
			named = append(named, f)
		}
	}
	wrapper, wrapped := top["settings"]

	switch {
	case wrapped && len(named) > 0:
		return zero, fmt.Errorf("the request body carries a \"settings\" wrapper AND the top-level settings field(s) %s, and there is no correct way to choose between them: send one shape or the other",
			strings.Join(named, ", "))
	case wrapped:
		var out TriageInvestigateSettings
		if err := json.Unmarshal(wrapper, &out); err != nil {
			return zero, fmt.Errorf("the \"settings\" value is not a settings document: %w", err)
		}
		return out, nil
	case len(named) > 0:
		var out TriageInvestigateSettings
		if err := json.Unmarshal(body, &out); err != nil {
			return zero, fmt.Errorf("the request body names settings fields but does not decode as a settings document: %w", err)
		}
		return out, nil
	}

	return zero, fmt.Errorf("the request body names no settings field at all (it carries %s), so nothing in it says what to store. Send {\"settings\": {...}} or a bare settings object naming at least one of: %s. It is refused rather than written, because a body that decodes to an empty document would overwrite the stored settings with the defaults and report success",
		triageSettingsKeyList(top), strings.Join(known, ", "))
}

// triageSettingsFieldNames is every json tag on TriageInvestigateSettings, in declaration order.
func triageSettingsFieldNames() []string {
	t := reflect.TypeOf(TriageInvestigateSettings{})
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, tag)
	}
	return out
}

// triageSettingsKeyList names what the body DID carry, so the refusal is actionable rather than a
// restatement of the rule. A typo in one key is the common case and seeing it echoed is the fix.
func triageSettingsKeyList(top map[string]json.RawMessage) string {
	if len(top) == 0 {
		return "no keys at all"
	}
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "the key(s) " + strings.Join(keys, ", ")
}

// DecodeTriageProveRefresh reads the OPTIONAL prove_refresh sidecar off a settings body.
//
// WHY THE SETTINGS PUT CARRIES IT. The renewal gate refuses until a refresh has been performed and
// observed, and the operator meets that refusal on this screen, on this credential, in this
// request. Making them leave, find the Session Manager, work out which credential the gate meant
// and press a different button is how a one-action refusal becomes an unreachable one. A press of
// "prove it now" is part of the same operator intent as turning the switch on, so it travels with
// the document: the proof is taken first, the gate is then evaluated against it, and one round
// trip either arms the control or says exactly why it could not be armed.
//
// IT IS STRICTLY OPT-IN. An absent field, a null, an empty object and an empty token id all mean
// "send nothing", because a settings save that quietly replayed a login flow would be a side
// effect nobody asked for. A malformed value is refused rather than ignored: a typo that silently
// does nothing is the same class of defect as a typo that silently overwrites a document, which is
// what DecodeTriageSettingsBody exists to refuse.
func DecodeTriageProveRefresh(body []byte) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return "", nil // the settings decoder reports this properly; do not report it twice
	}
	raw, present := top["prove_refresh"]
	if !present || len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return "", nil
	}
	var req struct {
		TokenID string `json:"token_id"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return "", fmt.Errorf("the \"prove_refresh\" value is not an object naming a credential: %w", err)
	}
	return strings.TrimSpace(req.TokenID), nil
}

// SaveTriageSettings answers PUT /triage/{scope_target_id}/settings.
//
// REPLACE, not merge, because this endpoint is written by a form that has just shown the operator
// every field, and there a cleared list and an untouched one are otherwise identical. A partial PUT
// to a full-document endpoint is how seven columns got wiped on fifty-eight rows in this codebase
// once already.
//
// Nothing is stored when validation fails. A refused payload that was saved anyway is a payload
// the operator believes is running.
func SaveTriageSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if strings.TrimSpace(scopeTargetID) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_scope_target", "No scope target in the path.")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, triageSettingsBodyLimit))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	incoming, err := DecodeTriageSettingsBody(body)
	if err != nil {
		// NOT A 200 WITH saved:true. See DecodeTriageSettingsBody: a body this endpoint cannot
		// recognise used to decode to the zero struct, pick up every default, validate clean and
		// be written over whatever the operator had stored.
		writeJSONError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	settings, retired := NormaliseTriageSettings(incoming)

	// THE PROOF, IF ONE WAS ASKED FOR, BEFORE THE GATE READS THE PROOFS. This is the only thing in
	// this handler that sends a request, and it sends nothing unless the body named a credential.
	// It is also the only production caller of RecordRefreshProof, which is what makes the renewal
	// control reachable at all: the gate demands a state that nothing else in the tree can enter.
	proveCtx := context.Background()
	var refreshProof *SessionRefreshProofResult
	proveTokenID, proveErr := DecodeTriageProveRefresh(body)
	if proveErr != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", proveErr.Error())
		return
	}
	if proveTokenID != "" {
		p := ProveSessionRefreshForTarget(proveCtx, scopeTargetID, proveTokenID)
		refreshProof = &p
	}

	gate := TriageRenewalGateFor(proveCtx, scopeTargetID, settings.Pacing)
	// The proof this switch is being armed against is stamped onto the document, so a later read
	// can say what it was armed against. It is NEVER what the later read trusts: the gate is
	// evaluated again every time, and this field is a record rather than a permission.
	if settings.SessionRenewal.Enabled {
		if o, ok := gate.Option(settings.SessionRenewal.TokenID); ok {
			settings.SessionRenewal.ProvenAt = o.ProvenAt
		}
	} else {
		settings.SessionRenewal.ProvenAt = time.Time{}
	}
	validation := ValidateTriageSettingsWithRenewal(settings, gate)
	if !validation.OK {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":         "invalid_settings",
			"saved":         false,
			"validation":    validation,
			"settings":      settings,
			"renewal_gate":  gate,
			"refresh_proof": refreshProof,
		})
		return
	}

	encoded, err := json.Marshal(settings)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO vector_tool_settings (scope_target_id, tool, settings, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (scope_target_id, tool)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		scopeTargetID, TriageSettingsTool, encoded); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"scope_target_id": scopeTargetID,
		"saved":           true,
		"settings":        settings,
		"validation":      validation,
		"retired_classes": retired,
		"renewal_gate":    gate,
		"refresh_proof":   refreshProof,
	})
}

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

func sortedTriageFlagKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedVocabKeys(m map[string]TriageClassInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedTriageClassIDs(reg map[triage.ClassID]triage.Classifier) []triage.ClassID {
	out := make([]triage.ClassID, 0, len(reg))
	for id := range reg {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func triageContainsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func triageOrDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
