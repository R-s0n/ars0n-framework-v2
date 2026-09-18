package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

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

// TriageInvestigateSettings is the whole document stored under TriageSettingsTool.
type TriageInvestigateSettings struct {
	Tier           string                        `json:"tier"`
	Classes        map[string]TriageClassSetting `json:"classes"`
	Pacing         TriagePacing                  `json:"pacing"`
	OOB            TriageOOB                     `json:"oob"`
	CustomPayloads []TriageCustomPayload         `json:"custom_payloads"`
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
		"marker_positions": []string{
			string(triage.MarkerPrefix), string(triage.MarkerSuffix), string(triage.MarkerInline),
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
	Point     string `json:"point"`
	Media     string `json:"media,omitempty"`
	Encoder   string `json:"encoder"`
	Delivered bool   `json:"delivered"`
	Survived  string `json:"survived"`
	// Proven is the predicate a clean verdict is allowed to rest on: intact or encoded, nothing
	// else. Delivered and not proven is the cookie semicolon case, which is the one that looks
	// fine and is not.
	Proven bool   `json:"proven"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// TriagePayloadCheck is one custom payload's whole verdict.
type TriagePayloadCheck struct {
	Index      int                     `json:"index"`
	ID         string                  `json:"id"`
	Class      string                  `json:"class"`
	OK         bool                    `json:"ok"`
	ProbeID    string                  `json:"probe_id"`
	LogicalLen int                     `json:"logical_len"`
	Delivery   []TriagePayloadDelivery `json:"delivery"`
	Problems   []TriageFieldProblem    `json:"problems"`
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

// ValidateTriageSettings is the whole validation pass. It is pure: no database, no network, so the
// same function backs the handler and the test.
func ValidateTriageSettings(s TriageInvestigateSettings) TriageSettingsValidation {
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

	v.OK = len(v.Errors) == 0
	return v
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
		triageValidateMarkerPos(add, p.MarkerPos)
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

		// Delivery, through the real encoder. This is the refusal the operator would otherwise
		// discover as a silent clean hours later.
		if len(logical) > 0 && classifier != nil {
			check.Delivery = triageCheckDelivery(add, p, logical, points)
			custom[classID] = append(custom[classID], triage.ProbeSpec{
				ID:        probeID,
				Class:     classID,
				Logical:   logical,
				Encoders:  triageEncodersOf(p.Encoder),
				Points:    points,
				MarkerPos: triage.MarkerPos(triageOrDefault(p.MarkerPos, string(triage.MarkerPrefix))),
				Tier:      triage.ProbeTier(triageOrDefault(p.Tier, string(triage.TierOptIn))),
				Risk:      triage.RiskTier(triageOrDefault(p.Risk, string(triage.RiskR1))),
				Notes:     p.Label,
			})
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

func triageValidateMarkerPos(add func(f, code, msg string), pos string) {
	switch triage.MarkerPos(pos) {
	case "", triage.MarkerPrefix, triage.MarkerSuffix, triage.MarkerInline:
	default:
		add(".marker_pos", "unknown_marker_position", fmt.Sprintf("%q is not a marker position.", pos))
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

// triageCheckDelivery renders the payload into every declared insertion point with the real
// encoder and reports what came out.
//
// A payload is refused, not warned about, when it cannot arrive faithfully. Delivered is not
// enough: a cookie value carrying a semicolon IS delivered and is then split by any RFC 6265
// parser, so the application reads a shorter string than the one sent. WireSurvival.Proven is the
// predicate a clean verdict is allowed to rest on, so it is the predicate here too.
//
// The synthetic request below has no per-slot impossible-byte table, because that table is
// measured against the live target at run time. This check is therefore a floor: it catches what
// is impossible everywhere, not what is impossible on one endpoint.
func triageCheckDelivery(add func(f, code, msg string), p TriageCustomPayload, logical []byte, points []triage.SlotKind) []TriagePayloadDelivery {
	out := []TriagePayloadDelivery{}
	for _, k := range points {
		for _, probe := range triageDeliveryProbes(k) {
			enc := EncodeSlotInto(probe.tmpl, probe.slot, triage.EncoderMode(p.Encoder), logical, triage.SlotOverrides{})
			row := TriagePayloadDelivery{
				Point:     string(k),
				Media:     probe.media,
				Encoder:   encoderChainName(enc),
				Delivered: enc.Delivered,
				Survived:  string(enc.Wire.Survived),
				Proven:    enc.Delivered && enc.Wire.Survived.Proven(),
				Reason:    string(enc.Reason),
				Detail:    enc.Detail,
			}
			out = append(out, row)
			if row.Proven {
				continue
			}
			where := string(k)
			if probe.media != "" {
				where += " (" + probe.media + ")"
			}
			detail := enc.Detail
			if detail == "" {
				detail = string(enc.Reason)
			}
			code, msg := "not_deliverable", fmt.Sprintf("Cannot be delivered into %s: %s", where, detail)
			if enc.Delivered {
				code = "not_intact_on_the_wire"
				msg = fmt.Sprintf("Reaches %s but the application does not read it back: %s", where, detail)
			}
			add(".payload", code, msg)
		}
	}
	return out
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

	settings, retired := LoadTriageSettings(context.Background(), scopeTargetID)
	validation := ValidateTriageSettings(settings)

	json.NewEncoder(w).Encode(map[string]any{
		"scope_target_id": scopeTargetID,
		"tool":            TriageSettingsTool,
		"settings":        settings,
		"defaults":        TriageSettingsDefaults(),
		"vocabulary":      TriageSettingsVocabulary(),
		"validation":      validation,
		"retired_classes": retired,
	})
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

	var req struct {
		Settings TriageInvestigateSettings `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	settings, retired := NormaliseTriageSettings(req.Settings)
	validation := ValidateTriageSettings(settings)
	if !validation.OK {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":      "invalid_settings",
			"saved":      false,
			"validation": validation,
			"settings":   settings,
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
