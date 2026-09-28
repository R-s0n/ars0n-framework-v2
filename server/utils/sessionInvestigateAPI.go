package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// ---------------------------------------------------------------------------------------------
// THE OPERATOR'S VIEW OF THE TOKEN CHARACTERISATION ENGINE
// ---------------------------------------------------------------------------------------------
//
// sessionTokenProfile.go answers, for one credential, what kind of thing it is, how long it lives,
// how we know that, and whether it can be renewed. This file is the only place those answers are
// assembled for a whole application and handed to a screen.
//
// WHY IT IS A SEPARATE ENDPOINT AND NOT A FIELD ON THE TOKEN LIST.
//
// GET /session-tokens/target/{id} carries SessionToken.Profile and nothing else this screen needs:
// no reading of what the runner would actually send, no survival verdict against a run length, no
// governing choice among credentials that disagree, no provenance rendered into words. The types
// below carry those, assembled once on the server so two screens cannot answer one question two
// different ways.
//
// IT CARRIES THE CREDENTIAL ITSELF, verbatim, beside its fingerprint and its length. This is a bug
// bounty framework and the bytes are the evidence: a leaked bearer, a session cookie that outlives
// a logout and a claim set naming the wrong subject are each proved by showing what was captured.
// A screen that showed a fingerprint where the value belongs would send the operator somewhere
// else to find the thing this process is already holding.
//
// WHAT THE SCREEN IS NOT ALLOWED TO DO.
//
// An unknown TTL leaves here as the word UNKNOWN in a rendered field, never as a zero, a dash or
// an empty string. This is the same rule the engine enforces in TTLDisplay, restated at the wire
// because a client that formats ttl_seconds itself has to remember that 0 means unmeasured, and
// the whole history of this codebase says that eventually one will not.
//
// WHICH CREDENTIAL THE CARD TALKS ABOUT.
//
// An application hands out several credentials and they do not agree: a fifteen minute bearer
// beside a session cookie with no readable expiry beside a CSRF header that never dies. The
// authenticated part of a scan ends when the FIRST credential the scan sends dies, so that is the
// one the card reports, and the report says out loud that it is one of several and why it was
// picked. See chooseGoverningCredential.
//
// WHERE THE CREDENTIAL THE RUNNER SENDS ACTUALLY COMES FROM.
//
// session_tokens is not the answer, and a screen built on it alone is a screen that disagrees with
// the runner. triageFreshCredential.go exists because the working credential on a live engagement
// was in manual_crawl_captures and the stale one was in the vector, so the runner asks a credential
// SOURCE at send time and substitutes the freshest CAPTURED credential over the one the corpus
// froze. Measured before this file read that source:
//
//	--- FAIL: TestFailFirstA_TheScreenIgnoresTheCapturedCredentialTheRunnerWouldSend
//	    THE DEFECT: the tile reads "NO SESSION"/"none" while the runner would send a credential
//	    captured 90s ago; buildSessionInvestigation has no input for manual_crawl_captures at all
//
// So the report now reads THE SAME SOURCE THE RUNNER READS, through the same triageFreshCredSource
// the runner constructs, and every credential on screen says which table it came out of. A
// credential the runner would send and the Session Manager has never heard of appears here as a
// row of its own; a stored credential the runner would substitute over says so on its row.
//
// AND WHEN THAT SOURCE CANNOT BE CONSULTED THE REPORT SAYS SO. There is no database handle in a
// unit test and there is no host on a target whose scope_target row cannot be read. Either way the
// honest answer is that what goes on the wire is UNKNOWN, which is a third state and not an empty
// set: an empty set would be the screen asserting the runner sends nothing, which is exactly the
// kind of unread fact this whole feature exists to refuse.

// ---------------------------------------------------------------------------------------------
// The wire types
// ---------------------------------------------------------------------------------------------

// SessionInvestigation is the whole answer for one scope target: every credential the framework
// holds for it, characterised, plus the single summary the Authentication card shows.
type SessionInvestigation struct {
	ScopeTargetID string    `json:"scope_target_id"`
	MeasuredAt    time.Time `json:"measured_at"`
	// Reprofiled says whether this run re-measured every credential from scratch or read back the
	// stored measurements. An operator looking at a stale answer should be able to tell.
	Reprofiled bool `json:"reprofiled"`
	// RunMinutes is the length of run the survival verdicts were asked about. Zero means the
	// caller did not ask, and then Survives is not populated: a verdict against an assumed run
	// length is a number nobody asked for wearing the clothes of one somebody did.
	RunMinutes int `json:"run_minutes"`

	// DefaultRunMinutes is THE run length this framework's configured pacing implies, published so
	// that every screen asking the survival question asks it about the same run. It is zero when
	// the pacing could not be read, and RunLengthBasis then says why.
	//
	// IT IS THE SAME NUMBER THE RENEWAL GATE USES. Before it was published the modal hardcoded 29
	// minutes and the gate computed 20m1s from TriageEstimatedRunDuration, so the two screens could
	// return contradictory verdicts about one credential.
	DefaultRunMinutes int    `json:"default_run_minutes"`
	RunLengthBasis    string `json:"run_length_basis"`

	Counts SessionInvestigationCounts `json:"counts"`
	// Wire is what the runner's own credential source says would go out for this target's host.
	Wire        SessionWireReading       `json:"wire"`
	TTLMetric   SessionTTLMetric         `json:"ttl_metric"`
	Governing   *GoverningCredential     `json:"governing"`
	Credentials []InvestigatedCredential `json:"credentials"`
	// Notes are sentences about the SET of credentials rather than about any one of them: nothing
	// active, several disagreeing lifetimes, nothing measured at all.
	Notes []string `json:"notes"`
}

// SessionWireReading is the screen's record of what the RUNNER would put on the wire, taken from
// the runner's own credential source rather than restated from session_tokens.
//
// Known false is a real answer and not a failure to answer: it means the source could not be
// consulted, the credentials below are the stored ones only, and nothing here may be read as a
// statement about what a scan would send.
type SessionWireReading struct {
	Known bool `json:"known"`
	// Host is the host the source was asked about. The runner asks per host, so a reading is about
	// one host and saying which is part of the answer.
	Host string `json:"host"`
	// Sources names the tables that were consulted.
	Sources []string `json:"sources"`
	// Fresh is how many credentials the source would hand the runner for that host, Expired how
	// many candidates it read and rejected because their own expiry had passed. Both are counts of
	// rows and neither is inferred from the other.
	Fresh   int `json:"fresh"`
	Expired int `json:"expired"`
	// Note is the source's own sentence about why there is nothing usable, when there is not.
	Note string `json:"note"`
	// Exhausted is the source's statement that it DID hold a usable credential for this host and
	// holds none now, which is a different thing from never having had one.
	Exhausted bool `json:"exhausted"`
	// WhyNotKnown says why the source could not be consulted, when Known is false.
	WhyNotKnown string `json:"why_not_known"`

	// dead is the CREDENTIALS BEHIND Expired, which is a count and cannot answer a question about
	// a lifetime. See triageFreshCredStatus.Dead for what the source puts in it and for the two
	// branches that fill it.
	//
	// IT IS AN INPUT TO THIS REPORT RATHER THAN A PART OF IT. Exactly one thing reads it,
	// sessionLifetimeOnlyCredentials, and what that produces is never added to report.Credentials,
	// never eligible and never sendable: a candidate the runner rejected may state the lifetime it
	// was issued with and may not be counted as a credential this scan would send.
	dead []sessionWireCredential
}

// SessionInvestigationCounts is the shape of the credential set.
type SessionInvestigationCounts struct {
	// Total and Active are about STORED credentials, the rows in session_tokens, because that is
	// what the Session Manager holds and what the operator's switch acts on. A captured credential
	// is neither stored nor switchable and is counted below instead.
	Total int `json:"total"`
	// Active is is_active, the operator's switch. Sendable is narrower: it is what
	// ApplySessionTokens would actually put on the wire, which additionally excludes an empty
	// value, a passed expires_at column and a credential whose own exp has gone by.
	Active   int `json:"active"`
	Sendable int `json:"sendable"`
	// Captured counts credentials the runner's source found in manual_crawl_captures that no
	// session_tokens row holds. They are not stored and nobody typed them in; a browser produced
	// them and the manual crawl caught them.
	Captured int `json:"captured"`
	// OnWire counts the credentials the runner's source would actually hand a probe for this
	// target's host. It is zero and MEANINGLESS when Wire.Known is false.
	OnWire int `json:"on_wire"`
	// TTLMeasured counts the credentials the card is about (the on-wire set when that is known,
	// the sendable stored ones otherwise) whose lifetime is an actual measurement.
	TTLMeasured int `json:"ttl_measured"`
	// TTLUnknown counts the same set's credentials whose lifetime was never measured. It is
	// reported beside TTLMeasured rather than inferred from it, because "3 of 5" and "3" are
	// different statements and only one of them says what is not known.
	TTLUnknown int `json:"ttl_unknown"`
	// RefreshProven counts credentials a refresh has actually been performed on. Renewal may only
	// be offered as a working option on these.
	RefreshProven int `json:"refresh_proven"`

	// Eligible is HOW MANY CREDENTIALS THE TWO TTL COUNTS ABOVE ARE ABOUT, published because
	// without it the only other count a sentence can open with is Sendable, and Sendable is
	// counted over a DIFFERENT SET.
	Eligible int `json:"eligible"`
	// EligibleBasis is which rule produced that set: "wire" when the runner's own credential
	// source was read, "stored" when it could not be and the stored sendable rule stood in.
	EligibleBasis string `json:"eligible_basis"`
}

// SessionTTLMetric is the Authentication card's Session TTL tile, rendered server side so the
// client cannot invent a default for a lifetime nobody measured.
type SessionTTLMetric struct {
	// Value is what the tile shows. "15m" when measured, the literal word "UNKNOWN" when not,
	// "NO SESSION" when nothing will be sent at all. Never blank, never "0", never "-".
	Value string `json:"value"`
	// Known is the tile's styling decision: a measured lifetime and an unmeasured one must not
	// look the same, and the client should not be re-deriving that from the string.
	//
	// IT IS TRUE ONLY WHEN THE WHOLE ANSWER IS MEASURED. A measured 15m credential standing beside
	// an unmeasured one that also goes on the wire does not make the session 15m long: it makes it
	// AT MOST 15m, and the unmeasured sibling may kill it sooner. See measured_partial.
	Known bool `json:"known"`
	// State is measured | measured_partial | floor_only | unknown | none.
	State string `json:"state"`
	// Detail is the one short line under the tile.
	Detail string `json:"detail"`
	// Explain is the full sentence, for a tooltip and for the modal header.
	Explain string `json:"explain"`

	// LifetimeShort, LifetimeKnown and LifetimeFrom are HOW LONG A SESSION LASTS ON THIS
	// APPLICATION, which is a different question from how much of one is left.
	LifetimeShort string `json:"lifetime_short"`
	LifetimeKnown bool   `json:"lifetime_known"`
	LifetimeFrom  string `json:"lifetime_from"`
}

// GoverningCredential is the credential the card is talking about, and why that one.
type GoverningCredential struct {
	TokenID   string `json:"token_id"`
	TokenName string `json:"token_name"`
	Carrier   string `json:"carrier"`
	Kind      string `json:"kind"`
	// WhyThisOne is the selection rule in words, including how many others it was chosen from.
	WhyThisOne string `json:"why_this_one"`
	// OfSendable is how many credentials this scan would send. More than one means the others
	// disagree with this one and the card is showing the shortest.
	OfSendable int `json:"of_sendable"`
}

// InvestigatedClaim is one fact read out of the credential, for the claims table.
type InvestigatedClaim struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Note says why the claim matters, where it does. Empty for the ones that speak for
	// themselves.
	Note string `json:"note"`
}

// SurvivalVerdict is SessionTokenProfile.Survives rendered for a screen, with the three states
// kept as three. Answer is "yes", "no" or "unknown", and unknown is not a yes.
type SurvivalVerdict struct {
	Answer string `json:"answer"`
	Known  bool   `json:"known"`
	OK     bool   `json:"ok"`
	Why    string `json:"why"`
}

// InvestigatedCredential is one credential, characterised, and the credential itself.
type InvestigatedCredential struct {
	TokenID  string `json:"token_id"`
	Name     string `json:"name"`
	IsActive bool   `json:"is_active"`
	// Stored says whether this is a row in session_tokens. A captured credential is not: it has no
	// on/off switch, no operator-typed expiry and no name but the one this screen gives it, so
	// IsActive is not a fact about it and it is counted separately.
	Stored bool `json:"stored"`
	// Source is the table it came out of: session_tokens or manual_crawl_captures. SourceLabel is
	// the same fact in the operator's words, because "which table" is the distinction between a
	// credential somebody typed in and one a browser actually produced.
	Source      string `json:"source"`
	SourceLabel string `json:"source_label"`
	// ObservedAt is when the row that carried it was written: the capture's created_at, or the
	// stored token's updated_at. Nil when the runner's source was not consulted.
	ObservedAt *time.Time `json:"observed_at"`

	// OnTheWire is whether the RUNNER'S OWN credential source would hand this credential to a
	// probe for this target's host, and WireNote says what happens to it instead when it would
	// not. Both are nil-valued and meaningless when the report's Wire.Known is false, which the
	// notes say out loud rather than leaving a false to be read as a no.
	OnTheWire bool   `json:"on_the_wire"`
	WireNote  string `json:"wire_note"`
	// WireExpiresAt is the expiry the runner's source read for this credential and
	// WireExpirySource says which of the token's own claim and the stored column answered. It is
	// the runner's reading, not this screen's, so the two cannot drift.
	WireExpiresAt    *time.Time `json:"wire_expires_at"`
	WireExpirySource string     `json:"wire_expiry_source"`

	// Sendable is whether a scan starting now would put this credential on the wire, and
	// NotSendableReason says why not when it would not. Both follow ApplySessionTokens rather
	// than restating its rules, so the screen cannot disagree with the runner.
	Sendable          bool   `json:"sendable"`
	NotSendableReason string `json:"not_sendable_reason"`

	// Carrier is where on the wire it rides. Scheme is the "Bearer" style prefix the header
	// carries in front of the value.
	CarrierKind string `json:"carrier_kind"`
	CarrierName string `json:"carrier_name"`
	Scheme      string `json:"scheme"`
	Carrier     string `json:"carrier"`

	// Value is the credential itself, as the Session Manager stores it or as the manual crawl
	// caught it going past. It is served because it is the evidence: a finding is proved by showing
	// the bytes, not by describing them.
	Value string `json:"value"`
	// Fingerprint is eight hex digits of the SHA-256 of the value, which is how one credential is
	// told from another at a glance, in a log line, and against the runner's own reading.
	Fingerprint string `json:"fingerprint"`
	// ValueLength is the byte length, which is often the shape of an opaque value in one number.
	ValueLength int `json:"value_length"`

	// Measured is false when nothing has ever been characterised for this credential, which is a
	// different state from "characterised and the answer was unknown".
	Measured     bool   `json:"measured"`
	Kind         string `json:"kind"`
	KindLabel    string `json:"kind_label"`
	KindEvidence string `json:"kind_evidence"`

	TTLSeconds    int64  `json:"ttl_seconds"`
	TTLKnown      bool   `json:"ttl_known"`
	TTLProvenance string `json:"ttl_provenance"`
	// TTLProvenanceLabel is the provenance in the operator's words, because "parsed" and
	// "observed" are the whole point of this screen and a one word tag does not carry it.
	TTLProvenanceLabel string `json:"ttl_provenance_label"`
	TTLEvidence        string `json:"ttl_evidence"`
	// TTLShort is the tile-sized rendering: "15m", or the word UNKNOWN. Never "0", never blank.
	TTLShort string `json:"ttl_short"`
	// TTLDisplay is the engine's own full sentence.
	TTLDisplay string `json:"ttl_display"`

	TTLFloorSeconds int64  `json:"ttl_floor_seconds"`
	TTLFloorKnown   bool   `json:"ttl_floor_known"`
	TTLFloorShort   string `json:"ttl_floor_short"`
	// TTLFloorProvenance is HOW the lower bound was got: the captured corpus, or a request this
	// framework sent and watched work. They are different facts and a screen that shows one number
	// for both tells the operator something nothing read.
	TTLFloorProvenance      string `json:"ttl_floor_provenance"`
	TTLFloorProvenanceLabel string `json:"ttl_floor_provenance_label"`
	TTLFloorEvidence        string `json:"ttl_floor_evidence"`
	ObservedSamples         int    `json:"observed_samples"`
	ObservedRequests        int    `json:"observed_requests"`
	ObservedEvidence        string `json:"observed_evidence"`

	RotationSeconds int64  `json:"rotation_interval_seconds"`
	RotationKnown   bool   `json:"rotation_known"`
	RotationShort   string `json:"rotation_short"`

	ExpiresAt        *time.Time `json:"expires_at"`
	ExpiryKnown      bool       `json:"expiry_known"`
	ExpiryProvenance string     `json:"expiry_provenance"`
	ExpiryStyle      string     `json:"expiry_style"`
	ExpiryStyleLabel string     `json:"expiry_style_label"`
	ExpiryEvidence   string     `json:"expiry_evidence"`
	ExpiryDisplay    string     `json:"expiry_display"`
	RemainingSeconds int64      `json:"remaining_seconds"`
	RemainingKnown   bool       `json:"remaining_known"`
	RemainingShort   string     `json:"remaining_short"`
	IssuedAt         *time.Time `json:"issued_at"`
	// IssuedAtSource is WHICH claim or observation produced that timestamp, and IssuedAtIsMintTime
	// says whether that source is the mint at all: nbf is not-before, and on an estate where no
	// token carries iat it is the common answer rather than the rare one.
	IssuedAtSource       string     `json:"issued_at_source"`
	IssuedAtEvidence     string     `json:"issued_at_evidence"`
	IssuedAtIsMintTime   bool       `json:"issued_at_is_mint_time"`
	DeclaredExpiresAt    *time.Time `json:"declared_expires_at"`
	DeclaredDisagrees    bool       `json:"declared_disagrees"`
	DeclaredDisagreement string     `json:"declared_disagreement"`

	Claims   []InvestigatedClaim `json:"claims"`
	Refresh  RefreshCapability   `json:"refresh"`
	Warnings []string            `json:"warnings"`
	// Survives is populated only when the caller asked about a run length.
	Survives   *SurvivalVerdict `json:"survives"`
	ProfiledAt *time.Time       `json:"profiled_at"`
	// Governs marks the one credential the card's metric is about.
	Governs bool `json:"governs"`

	// wireFingerprint is the fingerprint of the bytes this credential puts on the wire, prefix
	// included, which is what the runner's source fingerprints. IT IS THE MATCHING KEY: it exists so
	// a stored row and a runner credential can be recognised as the same token. The published
	// Fingerprint is of the stored value alone, and the two differ for anything carrying a scheme.
	wireFingerprint string
}

// ---------------------------------------------------------------------------------------------
// Vocabulary, rendered once here so the screen shows the server's words
// ---------------------------------------------------------------------------------------------

var credentialKindLabels = map[CredentialKind]string{
	CredentialKindJWT:          "JWT (signed, readable)",
	CredentialKindJWE:          "JWE (encrypted, claims unreadable)",
	CredentialKindPASETO:       "PASETO",
	CredentialKindBranca:       "Branca",
	CredentialKindSAML:         "SAML assertion",
	CredentialKindSessionID:    "Server-side session id",
	CredentialKindOpaqueBearer: "Opaque bearer",
	CredentialKindAPIKey:       "API key",
	CredentialKindOAuthAccess:  "OAuth access token",
	// A value that NAMES a principal rather than proving one. It is here because the wire rule
	// declines these before they reach a probe, so the card only ever shows one when a human typed
	// that carrier into the Session Manager by hand, which is exactly the case where the operator
	// needs to be told what the engine read.
	CredentialKindPrincipalName: "Names a principal, proves nothing",
	CredentialKindUnknown:       "Unrecognised",
}

func credentialKindLabel(k CredentialKind) string {
	if s, ok := credentialKindLabels[k]; ok {
		return s
	}
	if k == "" {
		return "Not characterised"
	}
	return string(k)
}

// provenanceLabels spell out what each provenance is worth. The distinction between a number read
// out of the credential and a number a human typed into a form is the entire reason this screen
// exists, so it is never shown as a bare tag.
var provenanceLabels = map[Provenance]string{
	ProvParsed:   "read out of the credential itself",
	ProvDeclared: "typed in by an operator, not measured",
	ProvObserved: "inferred from captured traffic, a lower bound only",
	// NOTHING IN THIS PACKAGE USES A CREDENTIAL UNTIL IT STOPS WORKING. What produces a probed
	// figure is a validation this framework sent, where the target answered differently because of
	// the credential, so the label says that and not a probe nobody wrote.
	ProvProbed:  "the framework sent a request with the credential and the target answered as though it worked",
	ProvUnknown: "never measured",
}

func provenanceLabel(p Provenance) string {
	if s, ok := provenanceLabels[p]; ok {
		return s
	}
	if p == "" {
		return "never measured"
	}
	return string(p)
}

var expiryStyleLabels = map[ExpiryStyle]string{
	ExpiryStyleAbsolute: "absolute: it dies at a fixed moment whatever you do",
	ExpiryStyleSliding:  "sliding: using it pushes the expiry out",
	ExpiryStyleSession:  "session: no wall-clock expiry, it dies with the browser session",
	// The unqualified form is deliberately the UNESTABLISHED one. Survives refuses a
	// non-expiring style whose provenance names no method that could have established it, and
	// this label used to say the opposite in the same payload: two fields contradicting each
	// other is worse than either being wrong alone, because whichever the operator reads they
	// cannot tell it is disputed. expiryStyleLabelFor is what a caller holding a profile uses.
	ExpiryStyleNonExpiring: "recorded as non-expiring, but nothing says how that was established",
	ExpiryStyleUnknown:     "unknown",
}

// expiryStyleLabelFor is the style in the operator words, given how the expiry was obtained.
//
// It exists because non-expiring is the one style that hands a gate an unconditional yes, and
// Survives will only grant it where the provenance names a method that could have established it.
// The label has to agree with that verdict, in the same payload, or the screen disputes itself.
func expiryStyleLabelFor(s ExpiryStyle, prov Provenance) string {
	if s == ExpiryStyleNonExpiring {
		switch prov {
		case ProvParsed, ProvProbed, ProvDeclared:
			return fmt.Sprintf("non-expiring, and that was established: %s (%s)", provenanceLabel(prov), prov)
		}
		return expiryStyleLabels[ExpiryStyleNonExpiring]
	}
	return expiryStyleLabel(s)
}

func expiryStyleLabel(s ExpiryStyle) string {
	if v, ok := expiryStyleLabels[s]; ok {
		return v
	}
	if s == "" {
		return "unknown"
	}
	return string(s)
}

// claimOrder is the order the claims table reads in: what signed it, who issued it, who it is
// for, then the lifetime claims. Anything else follows alphabetically, which is where email, a
// tenant id and the rest of the issuer's own claims land, each with its value.
var claimOrder = []string{"alg", "kid", "typ", "cty", "enc", "iss", "sub", "aud", "jti", "scope"}

// claimNotes explain the ones whose significance is not obvious from the name.
var claimNotes = map[string]string{
	"alg":   "the signing algorithm the issuer used",
	"kid":   "which key signed it",
	"jti":   "the token's own id, which is how a revocation list would name it",
	"scope": "what the credential is authorised for",
	"iss":   "who minted it",
	"sub":   "who it is for",
}

// ---------------------------------------------------------------------------------------------
// Building the report
// ---------------------------------------------------------------------------------------------

// buildSessionInvestigation turns the stored tokens and their profiles into the report.
//
// It is pure: no database, no clock of its own, no network. Everything the screen shows is decided
// here so it can be tested without any of those, which is also why the handler below is thin.
func buildSessionInvestigation(scopeTargetID string, tokens []SessionToken, opts sessionInvestigateOptions, now time.Time) SessionInvestigation {
	report := SessionInvestigation{
		ScopeTargetID:     scopeTargetID,
		MeasuredAt:        now.UTC(),
		Reprofiled:        opts.Reprofile,
		RunMinutes:        opts.RunMinutes,
		DefaultRunMinutes: opts.DefaultRunMinutes,
		RunLengthBasis:    opts.RunLengthBasis,
		Wire:              opts.WireReading,
		Credentials:       []InvestigatedCredential{},
		Notes:             []string{},
	}
	if report.Wire.Sources == nil {
		report.Wire.Sources = []string{}
	}
	if !report.Wire.Known && strings.TrimSpace(report.Wire.WhyNotKnown) == "" {
		// A caller that assembled no reading at all still gets a sentence rather than an empty
		// string, because an empty why is indistinguishable from a why nobody wrote down.
		report.Wire.WhyNotKnown = "the runner's credential source was not consulted for this report"
	}

	for i := range tokens {
		report.Credentials = append(report.Credentials, investigateOne(tokens[i], opts, now))
	}
	mergeWireCredentials(&report, opts, now)

	// ELIGIBLE IS THE SET THE CARD IS ABOUT, and it is the runner's set when the runner's set could
	// be read. Falling back to the stored sendable ones when it could not is the only honest
	// alternative, and the notes say which of the two happened.
	eligible := []int{}
	for i := range report.Credentials {
		if credentialGoesOut(report.Credentials[i], report.Wire.Known) {
			eligible = append(eligible, i)
		}
	}

	for _, c := range report.Credentials {
		if c.Stored {
			report.Counts.Total++
			if c.IsActive {
				report.Counts.Active++
			}
			if c.Sendable {
				report.Counts.Sendable++
			}
		} else {
			report.Counts.Captured++
		}
		if report.Wire.Known && c.OnTheWire {
			report.Counts.OnWire++
		}
		if c.Refresh.Status == RefreshProven {
			report.Counts.RefreshProven++
		}
	}
	// SAID AS A COUNT, because the two counts below are counted over THIS set and the only other
	// count a sentence could open with is Sendable, which is counted over the stored rows. See the
	// comment on Counts.Eligible.
	report.Counts.Eligible = len(eligible)
	report.Counts.EligibleBasis = "stored"
	if report.Wire.Known {
		report.Counts.EligibleBasis = "wire"
	}
	for _, i := range eligible {
		if report.Credentials[i].TTLKnown {
			report.Counts.TTLMeasured++
		} else {
			report.Counts.TTLUnknown++
		}
	}

	idx, why := chooseGoverningCredential(report.Credentials, eligible)
	if idx >= 0 {
		report.Credentials[idx].Governs = true
		g := report.Credentials[idx]
		report.Governing = &GoverningCredential{
			TokenID:    g.TokenID,
			TokenName:  g.Name,
			Carrier:    g.Carrier,
			Kind:       g.Kind,
			WhyThisOne: why,
			OfSendable: len(eligible),
		}
	}
	// THE LIFETIME-ONLY SET IS BUILT AFTER eligible AND IS NOT ADDED TO report.Credentials. It
	// answers one question and appears on no other surface; see sessionLifetimeOnlyCredentials
	// for the four things it is prevented from doing.
	lifetimeOnly := sessionLifetimeOnlyCredentials(report, opts, now)
	report.TTLMetric = sessionTTLMetric(report, eligible, idx, why, lifetimeOnly)
	report.Notes = investigationNotes(report, eligible)
	return report
}

// credentialGoesOut is the one rule for "would a scan starting now carry this", and the card, the
// counts and the governing choice all read it so none of them can answer it differently.
//
// With the runner's source read, it is that source's answer. WITH ONE NAMED EXCEPTION: a query
// credential. The source substitutes named carriers in the HEAD of a request and skips query
// credentials by name, so its silence about one is a statement about the substitution layer and
// not about the credential. Dropping a sendable query credential out of the card on the strength
// of that silence would report a target whose only credential is an api_key in the query string as
// having no session at all.
//
// With the source unread, it is the stored sendable rule, which is what this screen answered
// before the source existed, and the notes say that is what happened.
func credentialGoesOut(c InvestigatedCredential, wireKnown bool) bool {
	if !wireKnown {
		return c.Sendable
	}
	if c.OnTheWire {
		return true
	}
	return c.Sendable && c.CarrierKind == tokenTypeQuery
}

// ---------------------------------------------------------------------------------------------
// The runner's own view of what goes out
// ---------------------------------------------------------------------------------------------

// sessionWireCredential is ONE credential the runner's credential source would hand a probe. It is
// the screen's copy of triageFreshCred: the carrier, the bytes, and where they were read.
type sessionWireCredential struct {
	Carrier      CredentialCarrier
	Value        string
	Fingerprint  string
	Source       string
	Observed     time.Time
	Expires      time.Time
	ExpirySource string
}

// wireSourceLabels put the table names into the operator's words. The distinction is the point: a
// stored credential is one somebody typed into the Session Manager, and a captured one is one a
// browser actually produced and the manual crawl caught going past.
var wireSourceLabels = map[string]string{
	"session_tokens":        "stored in the Session Manager",
	"manual_crawl_captures": "captured from a real browser session by the manual crawl",
}

func wireSourceLabel(source string) string {
	if s, ok := wireSourceLabels[source]; ok {
		return s
	}
	if source == "" {
		return "source not recorded"
	}
	return source
}

// wireCarrierKey names a carrier for matching. Header names are compared case-insensitively
// because HTTP says they are; a cookie name is case sensitive and is not folded.
func wireCarrierKey(c CredentialCarrier) string {
	if c.Kind == "cookie" {
		return "c:" + c.Name
	}
	if c.Kind == "query" {
		return "q:" + c.Name
	}
	return "h:" + strings.ToLower(c.Name)
}

// mergeWireCredentials folds the runner's reading into the report.
//
// A runner credential that matches a stored row by carrier AND by the fingerprint of the bytes
// that go out marks that row as the one going out. One that matches nothing stored is appended as
// a credential in its own right, profiled by the same engine, because it is a credential this
// framework will send and a screen that cannot name it cannot be read as a picture of the run.
//
// A stored row the runner would NOT send keeps a sentence saying what happens to it instead. The
// two interesting shapes are a fresher credential on the same carrier, which is a substitution,
// and nothing at all on that carrier, which is a real disagreement between this screen's sendable
// rule and the runner's and is called one.
func mergeWireCredentials(report *SessionInvestigation, opts sessionInvestigateOptions, now time.Time) {
	if !report.Wire.Known {
		return
	}
	byKey := map[string]sessionWireCredential{}
	for _, wc := range opts.Wire {
		byKey[wireCarrierKey(wc.Carrier)] = wc
	}

	matched := map[string]bool{}
	for i := range report.Credentials {
		c := &report.Credentials[i]
		key := wireCarrierKey(CredentialCarrier{Kind: c.CarrierKind, Name: c.CarrierName})
		wc, ok := byKey[key]
		if !ok {
			// A QUERY CREDENTIAL IS ITS OWN ANSWER AND NOT A DISAGREEMENT. The runner's source
			// substitutes NAMED CARRIERS IN THE HEAD of a request and skips query credentials by
			// name, because rewriting a URL there would move a payload a class placed in the query
			// string. So it hands out nothing for one, and that is a statement about the
			// substitution layer rather than about this credential.
			if c.CarrierKind == tokenTypeQuery {
				c.WireNote = "the runner's credential source does not substitute query-string " +
					"credentials at all, by design, so nothing here says whether this one goes out; " +
					"the captured request's own query string is what a probe carries"
				continue
			}
			c.WireNote = fmt.Sprintf("the runner's credential source hands out nothing for %s on %s, "+
				"so this row is not what a probe would carry", c.Carrier, report.Wire.Host)
			continue
		}
		if wc.Fingerprint != c.wireFingerprint {
			c.WireNote = fmt.Sprintf("a different credential for %s is what goes out: %s, %s. "+
				"This row is not what a probe would carry",
				c.Carrier, wireSourceLabel(wc.Source), wireObservedPhrase(wc, now))
			continue
		}
		matched[key] = true
		c.OnTheWire = true
		c.WireNote = fmt.Sprintf("this is the credential the runner hands a probe for %s", report.Wire.Host)
		if !wc.Expires.IsZero() {
			exp := wc.Expires.UTC()
			c.WireExpiresAt = &exp
			c.WireExpirySource = wc.ExpirySource
		}
	}

	for _, wc := range opts.Wire {
		key := wireCarrierKey(wc.Carrier)
		if matched[key] {
			continue
		}
		report.Credentials = append(report.Credentials, investigateWireCredential(wc, report.Wire.Host, opts, now))
	}
}

// wireObservedPhrase says how fresh a runner credential is. Zero time is said as unrecorded rather
// than rendered as the year one, which is the shape this codebase has been bitten by before.
func wireObservedPhrase(wc sessionWireCredential, now time.Time) string {
	if wc.Observed.IsZero() {
		return "when it was captured is not recorded"
	}
	if wc.Observed.After(now) {
		return "captured at " + wc.Observed.UTC().Format(time.RFC3339)
	}
	return "captured " + humaniseTTL(now.Sub(wc.Observed)) + " ago"
}

// investigateWireCredential renders a credential the runner would send that no stored row holds.
//
// IT GOES THROUGH investigateOne LIKE EVERY OTHER CREDENTIAL. Building a second projection here
// would be the third place in this file that decides how a lifetime renders, and the whole point of
// the engine is that there is one. A synthetic row is assembled, profiled by ProfileCredential, and
// projected by the same function, so a captured credential and a stored one are characterised
// identically and cannot drift.
func investigateWireCredential(wc sessionWireCredential, host string, opts sessionInvestigateOptions, now time.Time) InvestigatedCredential {
	tok := SessionToken{
		// wireCarrierKey is the MATCHING key and this is the id the report publishes, which
		// SessionInvestigateModal.js puts straight into a data-testid. The fingerprint keeps it
		// unique, so two credentials on one carrier still make two ids.
		ID:          "capture:" + wireCarrierKey(wc.Carrier) + ":" + wc.Fingerprint,
		Name:        "captured " + wc.Carrier.Describe(),
		TokenValue:  wc.Value,
		TokenType:   wc.Carrier.Kind,
		ValuePrefix: wc.Carrier.Prefix,
		IsActive:    true,
	}
	switch wc.Carrier.Kind {
	case "cookie":
		tok.CookieName = wc.Carrier.Name
	case "query":
		tok.ParamName = wc.Carrier.Name
	default:
		tok.HeaderName = wc.Carrier.Name
	}
	p := ProfileCredential(NewCredential(wc.Value), wc.Carrier, now)
	tok.Profile = &p

	out := investigateOne(tok, opts, now)
	out.Stored = false
	out.Source = wc.Source
	out.SourceLabel = wireSourceLabel(wc.Source)
	out.OnTheWire = true
	out.WireNote = fmt.Sprintf("this is the credential the runner hands a probe for %s, and no row in "+
		"the Session Manager holds it: %s, %s", host, wireSourceLabel(wc.Source), wireObservedPhrase(wc, now))
	if !wc.Observed.IsZero() {
		at := wc.Observed.UTC()
		out.ObservedAt = &at
	}
	if !wc.Expires.IsZero() {
		exp := wc.Expires.UTC()
		out.WireExpiresAt = &exp
		out.WireExpirySource = wc.ExpirySource
	}
	return out
}

// RefreshNotCharacterised is the state BEFORE the search for a refresh mechanism, as against
// RefreshNotObserved, which is the state after one that found nothing.
//
// WHY IT EXISTS. A credential with no profile attached used to come back as not_observed, and
// SessionInvestigateModal.js renders that through REFRESH_WORD as "None observed": an operator
// reading a credential nobody has opened was shown the result of a search over the auth flows, the
// captured corpus and the token's grants that had never run. The renewal gate had the same hole
// under the name refresh_not_checked, and both are the same rule: an absent measurement is said as
// absent.
//
// IT IS DELIBERATELY NOT THE EMPTY STRING. That modal falls back to "None observed" on any falsy
// status, so a zero value would put the claim straight back on the screen from the other side.
const RefreshNotCharacterised RefreshStatus = "not_characterised"

// investigateOne projects one token and its profile onto the wire type.
func investigateOne(tok SessionToken, opts sessionInvestigateOptions, now time.Time) InvestigatedCredential {
	carrier := CarrierForSessionToken(tok)
	cred := NewCredential(tok.TokenValue)

	out := InvestigatedCredential{
		TokenID:     tok.ID,
		Name:        tok.Name,
		IsActive:    tok.IsActive,
		Stored:      true,
		Source:      "session_tokens",
		SourceLabel: wireSourceLabel("session_tokens"),
		CarrierKind: carrier.Kind,
		CarrierName: carrier.Name,
		Scheme:      strings.TrimSpace(carrier.Prefix),
		Carrier:     carrier.Describe(),
		Value:       tok.TokenValue,
		Fingerprint: cred.Fingerprint(),
		ValueLength: cred.Len(),
		// The bytes that go out, prefix included, which is what the runner's source fingerprints.
		// It is the key that identifies one credential across two tables.
		wireFingerprint: triageCredFingerprint(sessionTokenWireValue(tok)),
		// Until a profile says otherwise every lifetime field reads as unmeasured, and the two
		// rendered strings say the word rather than showing an empty box.
		Kind:               string(CredentialKindUnknown),
		KindLabel:          credentialKindLabel(""),
		TTLProvenance:      string(ProvUnknown),
		TTLProvenanceLabel: provenanceLabel(ProvUnknown),
		TTLShort:           ttlUnknownWord,
		TTLDisplay:         ttlUnknownWord,
		TTLFloorShort:      ttlUnknownWord,
		RotationShort:      ttlUnknownWord,
		RemainingShort:     ttlUnknownWord,
		ExpiryProvenance:   string(ProvUnknown),
		ExpiryStyle:        string(ExpiryStyleUnknown),
		ExpiryStyleLabel:   expiryStyleLabel(ExpiryStyleUnknown),
		ExpiryDisplay:      ttlUnknownWord,
		Claims:             []InvestigatedClaim{},
		Warnings:           []string{},
		// NOT not_observed. That status is the ANSWER OF A SEARCH: DetectRefreshCapability writes
		// it after reading the auth flows, the captured corpus and the token's own grants, and
		// none of those is read below. This seed is what a credential with no profile attached
		// keeps, because the branch a few lines down returns before anything looks at one.
		Refresh: RefreshCapability{Status: RefreshNotCharacterised, Evidence: []string{}},
	}

	out.Sendable, out.NotSendableReason = credentialIsSendable(tok, now)
	if tok.ExpiresAt != nil {
		t := tok.ExpiresAt.UTC()
		out.DeclaredExpiresAt = &t
	}
	if !tok.UpdatedAt.IsZero() {
		at := tok.UpdatedAt.UTC()
		out.ObservedAt = &at
	}

	p := tok.Profile
	if p == nil {
		return out
	}

	out.Measured = !p.ProfiledAt.IsZero()
	if out.Measured {
		at := p.ProfiledAt.UTC()
		out.ProfiledAt = &at
	}
	if p.Fingerprint != "" {
		out.Fingerprint = p.Fingerprint
	}
	out.Kind = string(p.Kind)
	out.KindLabel = credentialKindLabel(p.Kind)
	out.KindEvidence = p.KindEvidence

	out.TTLKnown = p.TTLKnown
	out.TTLProvenance = string(p.TTLProvenance)
	out.TTLProvenanceLabel = provenanceLabel(p.TTLProvenance)
	out.TTLEvidence = p.TTLEvidence
	out.TTLDisplay = p.TTLDisplay()
	if p.TTLKnown {
		out.TTLSeconds = int64(p.TTL / time.Second)
		out.TTLShort = humaniseTTL(p.TTL)
	}

	out.TTLFloorKnown = p.TTLFloorKnown
	if p.TTLFloorKnown {
		out.TTLFloorSeconds = int64(p.TTLFloor / time.Second)
		out.TTLFloorShort = humaniseTTL(p.TTLFloor)
		// floorProvenance is the profile's own rule: nothing recorded reads as unknown, never as
		// the corpus.
		out.TTLFloorProvenance = string(p.floorProvenance())
		out.TTLFloorProvenanceLabel = provenanceLabel(p.floorProvenance())
		out.TTLFloorEvidence = p.FloorEvidence()
	}
	out.ObservedSamples = p.ObservedSamples
	out.ObservedRequests = p.ObservedRequests
	out.ObservedEvidence = p.ObservedEvidence

	out.RotationKnown = p.RotationKnown
	if p.RotationKnown {
		out.RotationSeconds = int64(p.RotationInterval / time.Second)
		out.RotationShort = humaniseTTL(p.RotationInterval)
	}

	out.ExpiryKnown = p.ExpiryKnown
	out.ExpiryProvenance = string(p.ExpiryProvenance)
	out.ExpiryStyle = string(p.ExpiryStyle)
	out.ExpiryStyleLabel = expiryStyleLabelFor(p.ExpiryStyle, p.ExpiryProvenance)
	out.ExpiryEvidence = p.ExpiryEvidence
	out.ExpiryDisplay = p.ExpiryDisplay()
	if p.ExpiryKnown {
		at := p.ExpiresAt.UTC()
		out.ExpiresAt = &at
	}
	if p.IssuedAtKnown {
		at := p.IssuedAt.UTC()
		out.IssuedAt = &at
		out.IssuedAtSource = string(p.IssuedAtSource)
		out.IssuedAtEvidence = p.IssuedAtSource.Evidence()
		out.IssuedAtIsMintTime = p.IssuedAtSource.IsMintTime()
	}
	if remaining, known := p.RemainingAt(now); known {
		out.RemainingKnown = true
		out.RemainingSeconds = int64(remaining / time.Second)
		out.RemainingShort = humaniseTTL(remaining)
	}

	// THE COLUMN AND THE CREDENTIAL DISAGREEING IS ITSELF A FINDING. An operator who typed an
	// expiry of next year onto a credential whose own exp passed twenty minutes ago has a row that
	// says the session is fine and a session that is not, and this is the one screen that can show
	// them both numbers side by side.
	if out.DeclaredExpiresAt != nil && p.ExpiryKnown && p.ExpiryProvenance == ProvParsed {
		drift := out.DeclaredExpiresAt.Sub(p.ExpiresAt)
		if absDuration(drift) > time.Minute {
			out.DeclaredDisagrees = true
			direction := "later than"
			if drift < 0 {
				direction = "earlier than"
			}
			out.DeclaredDisagreement = fmt.Sprintf(
				"the stored expires_at is %s %s the credential's own expiry; the credential is what the server checks",
				humaniseTTL(absDuration(drift)), direction)
		}
	}

	out.Claims = claimsOf(p)
	out.Refresh = p.Refresh
	if out.Refresh.Evidence == nil {
		out.Refresh.Evidence = []string{}
	}
	if len(p.Warnings) > 0 {
		out.Warnings = append(out.Warnings, p.Warnings...)
	}

	if opts.RunMinutes > 0 {
		d := time.Duration(opts.RunMinutes) * time.Minute
		ok, known, why := p.Survives(d, now)
		answer := "unknown"
		if known {
			answer = "no"
			if ok {
				answer = "yes"
			}
		}
		out.Survives = &SurvivalVerdict{Answer: answer, Known: known, OK: ok, Why: why}
	}

	return out
}

// claimsOf renders the profile's attributes as an ordered table. Nothing is filtered here: the
// engine reads the claims out of the credential and this puts them into a reading order.
func claimsOf(p *SessionTokenProfile) []InvestigatedClaim {
	out := []InvestigatedClaim{}
	if len(p.Attributes) == 0 {
		return out
	}
	seen := map[string]bool{}
	for _, name := range claimOrder {
		if v, ok := p.Attributes[name]; ok && strings.TrimSpace(v) != "" {
			out = append(out, InvestigatedClaim{Name: name, Value: v, Note: claimNotes[name]})
			seen[name] = true
		}
	}
	rest := make([]string, 0, len(p.Attributes))
	for k, v := range p.Attributes {
		if seen[k] || strings.TrimSpace(v) == "" {
			continue
		}
		rest = append(rest, k)
	}
	sort.Strings(rest)
	for _, k := range rest {
		out = append(out, InvestigatedClaim{Name: k, Value: p.Attributes[k], Note: claimNotes[k]})
	}
	return out
}

// credentialIsSendable answers whether a scan starting now would put this credential on the wire.
//
// IT MIRRORS ApplySessionTokens AND MUST KEEP MIRRORING IT. The four reasons a stored credential
// does not go out are the switch, an empty value, a passed expires_at column and the credential's
// own expiry having gone by, and the last of those is delegated to credentialSaysItIsDead rather
// than re-derived, because a screen that disagrees with the runner about what is being sent is
// worse than no screen.
func credentialIsSendable(tok SessionToken, now time.Time) (bool, string) {
	if !tok.IsActive {
		return false, "switched off in the Session Manager, so no scan will send it"
	}
	if strings.TrimSpace(tok.TokenValue) == "" {
		return false, "the row holds no value"
	}
	if tok.ExpiresAt != nil && !tok.ExpiresAt.After(now) {
		return false, fmt.Sprintf("the stored expires_at passed %s ago", humaniseTTL(now.Sub(*tok.ExpiresAt)))
	}
	if dead, why := credentialSaysItIsDead(tok.TokenValue, tok.ValuePrefix, tok.TokenType,
		tok.CookieName, tok.HeaderName, tok.ParamName, now); dead {
		return false, why
	}
	return true, ""
}

// sessionTokenWireValue is the bytes a stored row puts on the wire.
//
// IT MIRRORS triageDBFreshCreds.sessionTokenCandidates, because the whole purpose of the value is
// to be fingerprinted and compared against what that function produced. A cookie carries its value
// alone; every header form carries the prefix in front of it, which is why a stored bearer's
// published fingerprint (of the value) and its wire fingerprint (of "Bearer " plus the value) are
// two different eight character strings and only one of them can match the runner.
func sessionTokenWireValue(tok SessionToken) string {
	if tok.TokenType == tokenTypeCookie {
		return tok.TokenValue
	}
	return tok.ValuePrefix + tok.TokenValue
}

// ttlUnknownWord is the one spelling of an unmeasured lifetime. It is a constant so that no field
// anywhere in this file can drift into a dash, a blank or a zero, which are the three renderings
// an operator reads as "no expiry".
const ttlUnknownWord = "UNKNOWN"

// chooseGoverningCredential picks the credential the card's metric is about and says why.
//
// THE RULE: the authenticated part of a scan ends when the FIRST credential the scan sends dies,
// so the governing credential is the shortest-lived of the sendable ones. The ladder, in order,
// because the three rungs are different qualities of answer:
//
//  1. shortest REMAINING life, where the expiry is known. This is the real answer: it accounts for
//     how long ago each credential was minted.
//  2. shortest LIFETIME, where a TTL is known but the issue time is not. We know it cannot outlive
//     this, and not when the clock started.
//  3. shortest observed FLOOR. A lower bound, labelled as one.
//
// If nothing was measured at all the first eligible credential is returned with a why that says
// nothing was measured, because the card still has to name which credential it is silent about.
// Returns -1 when there is nothing to send.
//
// THE ELIGIBLE SET IS PASSED IN rather than derived here, because what "would be sent" means
// depends on whether the runner's own credential source could be consulted. See
// buildSessionInvestigation.
func chooseGoverningCredential(creds []InvestigatedCredential, sendable []int) (int, string) {
	if len(sendable) == 0 {
		return -1, ""
	}

	others := func(n int) string {
		if n == 1 {
			return "the only credential this scan would send"
		}
		return fmt.Sprintf("the first of the %d credentials this scan would send to die", n)
	}

	best := -1
	for _, i := range sendable {
		if !creds[i].RemainingKnown {
			continue
		}
		if best < 0 || creds[i].RemainingSeconds < creds[best].RemainingSeconds ||
			(creds[i].RemainingSeconds == creds[best].RemainingSeconds && creds[i].Name < creds[best].Name) {
			best = i
		}
	}
	if best >= 0 {
		// A CREDENTIAL WHOSE REMAINING TIME IS PAST IS NOT "MINUS FIVE MINUTES OF LIFE LEFT".
		// RemainingAt subtracts and does not clamp, so an expired credential arrives here with a
		// negative RemainingSeconds, sorts first (correctly: it is the first to die, it already
		// has) and used to be described with the minus sign still in the sentence.
		// THE PROVENANCE OF A REMAINING TIME IS THE PROVENANCE OF THE EXPIRY IT WAS SUBTRACTED
		// FROM, and this rung was captioning it with the LIFETIME provenance. The two differ
		// whenever a credential declares when it dies and not how long it lives, which is every
		// JWT carrying exp and no iat. Measured:
		//
		//	the first of the 2 credentials this scan would send to die: 20m of life left,
		//	never measured
		//
		// The 20m was read out of the exp claim. "never measured" is the answer to a different
		// question sitting next to the number as though it were the answer to this one.
		remainingProv := provenanceLabel(Provenance(creds[best].ExpiryProvenance))
		if creds[best].RemainingSeconds <= 0 {
			return best, fmt.Sprintf("%s: it has ALREADY EXPIRED, %s ago, %s",
				others(len(sendable)),
				humaniseTTL(time.Duration(-creds[best].RemainingSeconds)*time.Second),
				remainingProv)
		}
		return best, fmt.Sprintf("%s: %s of life left, %s",
			others(len(sendable)), creds[best].RemainingShort, remainingProv)
	}

	for _, i := range sendable {
		if !creds[i].TTLKnown {
			continue
		}
		if best < 0 || creds[i].TTLSeconds < creds[best].TTLSeconds ||
			(creds[i].TTLSeconds == creds[best].TTLSeconds && creds[i].Name < creds[best].Name) {
			best = i
		}
	}
	if best >= 0 {
		return best, fmt.Sprintf("%s has the shortest measured lifetime of the %d this scan would send, %s; "+
			"when it was issued is not known, so how much of that is left is not either",
			creds[best].Name, len(sendable), creds[best].TTLShort)
	}

	for _, i := range sendable {
		if !creds[i].TTLFloorKnown {
			continue
		}
		if best < 0 || creds[i].TTLFloorSeconds < creds[best].TTLFloorSeconds ||
			(creds[i].TTLFloorSeconds == creds[best].TTLFloorSeconds && creds[i].Name < creds[best].Name) {
			best = i
		}
	}
	if best >= 0 {
		return best, fmt.Sprintf("no lifetime was measured for any of the %d credentials this scan would send; "+
			"%s has the shortest observed floor, %s, which is a lower bound and not a lifetime",
			len(sendable), creds[best].Name, creds[best].TTLFloorShort)
	}

	return sendable[0], fmt.Sprintf("nothing has been measured about any of the %d credentials this scan would send; "+
		"%s is named so the card says which credential it is silent about",
		len(sendable), creds[sendable[0]].Name)
}

// sessionTTLMetric renders the Authentication card's tile.
//
// The one thing it may never do is produce a number for a lifetime nobody measured. Every path out
// of here either carries a humanised duration with Known true, or the word UNKNOWN with Known
// false, or the words NO SESSION when there is no credential to talk about. There is no fourth
// path, and in particular there is no empty string and no zero: a tile reading "0" or "-" is read
// as "no expiry", which is the opposite of what an unmeasured lifetime means.
// A SECOND THING IT MAY NEVER DO, added after the round 11 verification: state a measured lifetime
// with confidence while another credential the scan sends has no measured lifetime at all.
// Measured before this rule existed:
//
//	--- FAIL: TestFailFirstD_TheTileIsConfidentBesideAnUnmeasuredSibling
//	    THE DEFECT: the tile reads "15m" with known=true and state="measured" while 1 of the 2
//	    credentials this scan would send have no measured lifetime; the caveat is only in notes[],
//	    which the card does not render
//
// The session in that state is not fifteen minutes long. It is AT MOST fifteen minutes long, and
// the unmeasured sibling may kill it in ninety seconds. So the tile reads "<=15m", the state is
// measured_partial, and Known is false: the number is still there, because the bound is real
// information, but nothing about it is styled as a settled measurement.
// sessionTTLMetric renders the tile and then attaches the half of the answer that is about the
// APPLICATION rather than about this scan. See withMeasuredLifetime.
func sessionTTLMetric(report SessionInvestigation, eligible []int, governing int, why string,
	lifetimeOnly []InvestigatedCredential) SessionTTLMetric {
	return withMeasuredLifetime(sessionTTLMetricForEligible(report, eligible, governing, why),
		report, eligible, governing, lifetimeOnly)
}

// sessionLifetimeCandidate is one credential the lifetime question may be answered from, with
// where it came from beside it: an index into report.Credentials, or -1 for a row that is on no
// other surface of this report and exists only to answer this one question.
type sessionLifetimeCandidate struct {
	cred InvestigatedCredential
	idx  int
}

// sessionLifetimeOnlyCredentials projects the DEAD candidates the runner's source rejected into
// the same shape every other credential on this report has.
//
// WHY THERE IS A SET AT ALL, measured on the engaged estate through this handler: the tile read
// 15m1s and named its source, an operator-typed authx bearer, which is a different issuer from
// the application under test. The application's own answer, 4m59s of accessToken, had been read
// by this framework and then dropped: SessionWireReading.Expired counted 21 candidates and
// carried none of them, so the only credentials the card could see were the stored rows that
// happen to survive. A number from somewhere else is worse than UNKNOWN, because it looks like an
// answer.
//
// WHAT THESE ROWS MAY NOT DO, and how each is prevented rather than merely intended:
//
//	become sendable        Sendable is forced false here, with a reason, after the projection.
//	go on the wire         OnTheWire is forced false here.
//	re-enter substitution  they are not in report.Credentials, so credentialGoesOut never sees
//	                       them, eligible cannot contain one and chooseGoverningCredential cannot
//	                       pick one. The runner's own source never returned them either:
//	                       triageFreshCredStatus.Dead is filled on the branch that CONTINUES past
//	                       the candidate append.
//	claim a live session   the tile's Known stays false whenever the lifetime came from outside
//	                       the eligible set, which is every row in here by construction.
//
// A DEAD CANDIDATE THE REPORT ALREADY HOLDS IS SKIPPED, keyed on the fingerprint of the bytes,
// because a stored row whose expiry has passed is on the card already and counting it twice would
// let one credential answer as two.
func sessionLifetimeOnlyCredentials(report SessionInvestigation, opts sessionInvestigateOptions,
	now time.Time) []InvestigatedCredential {
	if !report.Wire.Known || len(report.Wire.dead) == 0 {
		return nil
	}
	held := map[string]bool{}
	for i := range report.Credentials {
		// AN EMPTY FINGERPRINT IS NOT A MATCH. It is the absence of a reading, and letting it
		// into the map would silently drop every dead candidate whose own fingerprint is empty.
		if fp := report.Credentials[i].wireFingerprint; fp != "" {
			held[fp] = true
		}
	}
	out := []InvestigatedCredential{}
	for _, wc := range report.Wire.dead {
		if wc.Fingerprint != "" && held[wc.Fingerprint] {
			continue
		}
		c := investigateWireCredential(wc, report.Wire.Host, opts, now)
		c.OnTheWire = false
		c.Sendable = false
		// THE SENTENCE MATCHES THE BRANCH THAT PUT THE ROW HERE, which is triageFreshCredDead:
		// "expired" there means the expiry has passed OR passes inside the 60 second margin that
		// source refuses within, and a row an operator reads as already dead when it has fifty
		// seconds left would be a claim nothing measured.
		c.NotSendableReason = "the runner's credential source read this candidate and rejected it: its own " +
			"expiry has passed, or passes inside the margin that source refuses within. It is kept only " +
			"because a credential it will not send still states the lifetime it was issued with"
		c.WireNote = fmt.Sprintf("the runner's credential source read this on %s and would NOT hand it to a "+
			"probe: %s", report.Wire.Host, c.NotSendableReason)
		out = append(out, c)
	}
	return out
}

// sessionLifetimeSource picks the credential that answers HOW LONG A SESSION LASTS ON THIS
// APPLICATION, which is not the same question as how much of this scan session is left.
//
// THE LADDER, AND WHY THE MIDDLE RUNG EXISTS.
//
//  1. THE ELIGIBLE SET, because a credential going out is the better evidence about the run.
//  2. AMONG EVERYTHING ELSE, A CREDENTIAL THE APPLICATION ITSELF ISSUED, which means one out of
//     manual_crawl_captures: a browser asked the host under test and was handed it. A stored row
//     is a credential an OPERATOR pasted into the Session Manager, and an operator's own bearer
//     for some console can be minted by an issuer that has nothing to do with the host under
//     test, which is what this rung was added for. Measured on the
//     engaged estate, read back through this handler: with no such rung the tile answered "a
//     session on this application lasts 15m1s" off an authx bearer, while the accessToken the
//     application had issued to a real browser said 4m59s. Both numbers were read; only one of
//     them is about the application under test.
//  3. ANYTHING ELSE WITH A MEASURED LIFETIME, which is the operator's own rows, so a target with
//     no captures at all still gets an answer and still gets told where it came from.
//
// EVERY RUNG READS THE DEAD AS WELL AS THE LIVING. exp minus iat is a lifetime whether or not the
// clock has passed exp, and a card that drops it has thrown away a measurement because of a fact
// about the calendar. That used to be true of dead STORED rows only: a dead CAPTURED candidate
// was counted by the runner's source and then discarded, so the application's own token could
// never answer. lifetimeOnly is what carries those, and nothing in it is on any other surface of
// this report. See sessionLifetimeOnlyCredentials.
//
// Shortest wins within a rung, the same rule the governing ladder uses, and ties break on the
// name so the answer is stable across two runs over the same rows.
//
// The second return is the index into report.Credentials, or -1 when the answer came out of
// lifetimeOnly. The caller needs it to decide whether that credential goes out, and that decision
// may not be re-derived from anything else.
func sessionLifetimeSource(report SessionInvestigation, eligible []int,
	lifetimeOnly []InvestigatedCredential) (InvestigatedCredential, int, bool) {

	pick := func(cands []sessionLifetimeCandidate) int {
		best := -1
		for i := range cands {
			if !cands[i].cred.TTLKnown {
				continue
			}
			if best < 0 || cands[i].cred.TTLSeconds < cands[best].cred.TTLSeconds ||
				(cands[i].cred.TTLSeconds == cands[best].cred.TTLSeconds &&
					cands[i].cred.Name < cands[best].cred.Name) {
				best = i
			}
		}
		return best
	}

	going := make([]sessionLifetimeCandidate, 0, len(eligible))
	for _, i := range eligible {
		going = append(going, sessionLifetimeCandidate{cred: report.Credentials[i], idx: i})
	}
	if i := pick(going); i >= 0 {
		return going[i].cred, going[i].idx, true
	}

	all := make([]sessionLifetimeCandidate, 0, len(report.Credentials)+len(lifetimeOnly))
	for i := range report.Credentials {
		all = append(all, sessionLifetimeCandidate{cred: report.Credentials[i], idx: i})
	}
	for i := range lifetimeOnly {
		all = append(all, sessionLifetimeCandidate{cred: lifetimeOnly[i], idx: -1})
	}
	issued := make([]sessionLifetimeCandidate, 0, len(all))
	for _, c := range all {
		if c.cred.Source == "manual_crawl_captures" {
			issued = append(issued, c)
		}
	}
	if i := pick(issued); i >= 0 {
		return issued[i].cred, issued[i].idx, true
	}
	if i := pick(all); i >= 0 {
		return all[i].cred, all[i].idx, true
	}
	return InvestigatedCredential{}, -1, false
}

// withMeasuredLifetime stops ZERO REMAINING from erasing the LIFETIME that was read.
//
// EXPIRY AND LIFETIME ARE DIFFERENT FACTS, and only one of them is about the calendar. Measured on
// the engaged estate, where every captured Cognito credential the runner would send is an opaque
// cookie nobody has measured and the one credential whose lifetime was READ has been dead since
// yesterday:
//
//	--- FAIL: TestFailFirstC_ZeroRemainingErasesTheLifetimeThatWasRead
//	    the tile publishes no lifetime although one was read out of a credential on this target:
//	    {Value:UNKNOWN Known:false State:unknown ...}
//
// The profiler already says both halves on that credential ("it expired 13h35m ago, and its whole
// lifetime is 5m, read from exp minus iat"). The card collapsed the second into the first, counted
// ttl_measured as zero and fell back to UNKNOWN governed by a cookie. An operator asking how long
// a session lasts on this application had a perfect answer sitting in a dead token.
//
// WHAT THIS DOES NOT DO. It does not claim the measured lifetime is THIS scan session length, and
// Known stays false wherever the number came from a credential the scan would not send: nothing
// going out was measured, so how long the run stays authenticated is still UNKNOWN, and the
// explanation says that in the same breath as the number.
func withMeasuredLifetime(m SessionTTLMetric, report SessionInvestigation, eligible []int,
	governing int, lifetimeOnly []InvestigatedCredential) SessionTTLMetric {
	// NEVER BLANK. The same rule every other rendered lifetime in this file follows: a lifetime
	// nobody measured is the word, not an empty string a client will format as a zero.
	m.LifetimeShort = ttlUnknownWord

	src, idx, ok := sessionLifetimeSource(report, eligible, lifetimeOnly)
	if !ok {
		return m
	}
	m.LifetimeShort = src.TTLShort
	m.LifetimeKnown = true
	m.LifetimeFrom = fmt.Sprintf("%s, %s", src.Name, src.TTLProvenanceLabel)

	// GOES OUT IS READ OFF THE INDEX AND NOT OFF THE CREDENTIAL. A lifetime-only row carries
	// idx -1 and can never match an eligible index, which is the same answer arrived at the same
	// way for both kinds of source rather than a second rule about dead rows.
	goesOut := false
	for _, i := range eligible {
		if idx >= 0 && i == idx {
			goesOut = true
		}
	}

	// HOW MUCH OF THAT LIFETIME IS LEFT, said as its own statement rather than folded into the
	// lifetime. Unknown stays unknown: a credential with no readable expiry has a lifetime and no
	// answer at all to this question, and a zero there would be read as dead.
	remaining := "how much of it is left is " + ttlUnknownWord
	switch {
	case src.RemainingKnown && src.RemainingSeconds <= 0:
		remaining = "0 left"
	case src.RemainingKnown:
		remaining = src.RemainingShort + " left"
	}

	if m.State == "expired" {
		// The tile keeps the word EXPIRED, because what is left of this session really is nothing
		// and that is the first thing an operator has to read. The lifetime rides beside it.
		//
		// THE FIELDS ARE MUTATED AND NOT RE-LISTED. A struct literal here would silently drop any
		// field added to SessionTTLMetric later, which is the same class of defect as a projection
		// that forgets a column.
		if idx == governing {
			m.Detail += ", whole lifetime " + src.TTLShort
		}
		m.Explain = joinSentences(m.Explain, fmt.Sprintf(
			"A session on this application lasts %s: %s lives that long, %s. That is a measurement "+
				"and it is still true of a credential the clock has passed.",
			src.TTLShort, src.Name, src.TTLProvenanceLabel))
		return m
	}

	// Only the two states that report NO lifetime at all are rewritten. measured and
	// measured_partial already carry one, and none means there is no credential to talk about.
	if m.State != "unknown" && m.State != "floor_only" {
		return m
	}

	// THE SENTENCE AND THE BRANCH THAT EMITS IT HAVE TO AGREE. goesOut is false exactly when
	// sessionLifetimeSource fell through to the whole set, and it only falls through when NOTHING
	// in the eligible set has a measured lifetime; that is the fact this wording states, so it is
	// read off the same variable rather than assumed from the state.
	scanSentence := "Nothing this scan would send has a measured lifetime of its own, so how long " +
		"THIS scan stays authenticated is still " + ttlUnknownWord + ": the number above was read " +
		"from a credential this application issued and is not a measurement of the credentials " +
		"going out."
	scanDetail := "nothing this scan sends has a measured lifetime"
	if goesOut {
		scanSentence = "That credential is one this scan would send, and the credential the card " +
			"names below has no measured lifetime of its own."
		scanDetail = "the credential the card names has none of its own"
	}
	deadSentence := ""
	if src.RemainingKnown && src.RemainingSeconds <= 0 {
		deadSentence = fmt.Sprintf("%s died %s ago, so 0 of it is left. Expiry and lifetime are "+
			"different facts: a dead credential still answers how long a session here lasts.",
			src.Name, humaniseTTL(time.Duration(-src.RemainingSeconds)*time.Second))
	}

	m.Value = src.TTLShort
	m.Known = false
	m.State = "lifetime_only"
	m.Detail = fmt.Sprintf("%s lifetime, %s; %s", src.TTLShort, remaining, scanDetail)
	m.Explain = joinSentences(
		fmt.Sprintf("A session on this application lasts %s. That number was read from %s, %s.",
			src.TTLShort, src.Name, src.TTLProvenanceLabel),
		deadSentence, scanSentence, m.Explain)
	return m
}

func sessionTTLMetricForEligible(report SessionInvestigation, eligible []int, governing int, why string) SessionTTLMetric {
	if governing < 0 {
		detail := "no credential will be sent"
		if report.Counts.Total == 0 && report.Counts.Captured == 0 {
			detail = "no session tokens stored"
		} else if report.Counts.Total > 0 && report.Counts.Active == 0 {
			detail = fmt.Sprintf("%d stored, none switched on", report.Counts.Total)
		} else if report.Wire.Known {
			detail = fmt.Sprintf("nothing the runner would send to %s", report.Wire.Host)
		} else {
			detail = fmt.Sprintf("%d active, none of them sendable", report.Counts.Active)
		}
		return SessionTTLMetric{
			Value: "NO SESSION", Known: false, State: "none", Detail: detail,
			Explain: "Nothing the framework holds for this target would go on the wire, so a scan " +
				"started now would measure an anonymous session. " + detail + ".",
		}
	}

	g := report.Credentials[governing]
	disagree := ""
	if len(eligible) > 1 {
		disagree = fmt.Sprintf(" of %d", len(eligible))
	}

	// WHAT MAKES THE ANSWER PARTIAL. Either a credential that also goes out was never measured, or
	// the runner's own credential source could not be consulted at all and what goes out is
	// therefore not something this screen read. Both are the same defect from the operator's side:
	// a number on the tile that a credential nobody measured can make wrong.
	//
	// A SIBLING'S MEASURED LIFETIME IS A FACT ABOUT THIS SESSION EVEN WHERE THE ORDERING COULD NOT
	// USE IT. chooseGoverningCredential orders on REMAINING time first and reaches measured
	// LIFETIME only when nothing on the wire has an issue time, so a credential whose lifetime was
	// parsed and whose mint time was not can never win that ordering. Counting it as measured here
	// and nowhere else made it silence the caveat as well, which is the one way this tile can
	// assert something false with Known true. Measured before this branch existed:
	//
	//	--- FAIL: TestAMeasuredLifetimeTheOrderingIgnoredStillReachesTheTile
	//	    the tile claims a settled lifetime beside a credential this scan sends whose measured
	//	    lifetime is shorter: {Value:15m Known:true State:measured ...}
	//
	// The ordering is deliberately NOT changed to mix the two: 14m30s of life left and a 1m
	// lifetime are different quantities, and the rung that reads remaining time is the better
	// information. What changes is that the number becomes a BOUND and the sentence names the
	// shorter lifetime, so the fact the ordering could not use still reaches the operator.
	unmeasuredSiblings, shorterSiblings := 0, 0
	shortestSeconds, shortestName := int64(0), ""
	for _, i := range eligible {
		if i == governing {
			continue
		}
		s := report.Credentials[i]
		switch {
		case !s.TTLKnown:
			unmeasuredSiblings++
		case g.TTLKnown && s.TTLSeconds < g.TTLSeconds:
			if shorterSiblings == 0 || s.TTLSeconds < shortestSeconds {
				shortestSeconds, shortestName = s.TTLSeconds, s.Name
			}
			shorterSiblings++
		}
	}
	caveats := []string{}
	if unmeasuredSiblings > 0 {
		caveats = append(caveats, fmt.Sprintf("%d other credential(s) going out on this scan have no measured lifetime, "+
			"and any of them could die sooner than this.", unmeasuredSiblings))
	}
	if shorterSiblings > 0 {
		caveats = append(caveats, fmt.Sprintf("%d other credential(s) going out on this scan have a SHORTER measured "+
			"lifetime, the shortest being %s at %s, and this session ends when the first of them does.",
			shorterSiblings, shortestName, humaniseTTL(time.Duration(shortestSeconds)*time.Second)))
	}
	// Only where nothing above already said the answer is partial: the wire sentence explains why
	// this is a reading of the stored rows, and a credential that goes out unmeasured is the
	// stronger fact.
	if len(caveats) == 0 && !report.Wire.Known {
		caveats = append(caveats, "What the runner would actually send could not be read ("+report.Wire.WhyNotKnown+
			"), so this is the shortest STORED credential and not a reading of the wire.")
	}
	caveat := strings.Join(caveats, " ")

	// THE CREDENTIAL THIS SCAN WOULD SEND IS ALREADY DEAD, and the tile used to read as a healthy
	// measurement. Measured before this branch existed, with a bearer whose exp passed five
	// minutes ago and which the runner's source still hands to a probe:
	//
	//	TILE {Value:15m Known:true State:measured Detail:parsed, Authorization header of 2
	//	      Explain:dead bearer lives 15m. That number was read out of the credential itself.
	//	      It governs the scan because it is the first of the 2 credentials this scan would
	//	      send to die: -5m of life left ...}
	//
	// That is the worst output this tile can produce: a settled fifteen minutes for a session that
	// had already ended. HOW IT IS REACHED, because it is not reachable from the stored rows
	// alone: credentialIsSendable refuses an expired credential, so with the wire unread this
	// cannot happen. It happens when the RUNNER'S source says the credential goes out and this
	// screen reads its expiry as past, which credentialGoesOut permits on purpose, because the
	// runner is what decides the bytes.
	if g.RemainingKnown && g.RemainingSeconds <= 0 {
		dead := humaniseTTL(time.Duration(-g.RemainingSeconds) * time.Second)
		disagreement := ""
		if g.OnTheWire && !g.Sendable {
			disagreement = " The runner's own credential source would still hand it to a probe and this screen " +
				"reads it as expired: the two disagree, and the target is what decides."
		}
		return SessionTTLMetric{
			Value: "EXPIRED", Known: false, State: "expired",
			Detail: fmt.Sprintf("expired %s ago, %s%s", dead, g.Carrier, disagree),
			Explain: joinSentences(
				fmt.Sprintf("%s is the credential this scan would send and it expired %s ago, %s.",
					g.Name, dead, g.ExpiryDisplay),
				strings.TrimSpace(disagreement),
				"NOTHING HERE HAS ASKED THE APPLICATION whether it still accepts this credential; the reading "+
					"is of the credential's own expiry. If it does not, every probe of a scan starting now "+
					"measures the login wall, and a login wall looks like a target with nothing on it.",
				why, caveat),
		}
	}

	switch {
	case g.TTLKnown && caveat == "":
		detail := fmt.Sprintf("%s, %s%s", g.TTLProvenance, g.Carrier, disagree)
		return SessionTTLMetric{
			Value: g.TTLShort, Known: true, State: "measured", Detail: detail,
			Explain: fmt.Sprintf("%s lives %s. That number was %s. It governs the scan because it is %s. %s",
				g.Name, g.TTLShort, g.TTLProvenanceLabel, why, g.TTLEvidence),
		}
	case g.TTLKnown:
		detail := fmt.Sprintf("at most, %s, %s%s", g.TTLProvenance, g.Carrier, disagree)
		return SessionTTLMetric{
			Value: "<=" + g.TTLShort, Known: false, State: "measured_partial", Detail: detail,
			Explain: fmt.Sprintf("%s lives %s, %s. That is an UPPER BOUND on this session and not its "+
				"length: %s It governs the scan because it is %s. %s",
				g.Name, g.TTLShort, g.TTLProvenanceLabel, caveat, why, g.TTLEvidence),
		}
	case g.TTLFloorKnown:
		prov := Provenance(g.TTLFloorProvenance)
		detail := fmt.Sprintf("never measured, %s, %s%s", floorDetailPhrase(prov, g.TTLFloorShort), g.Carrier, disagree)
		return SessionTTLMetric{
			Value: ttlUnknownWord, Known: false, State: "floor_only", Detail: detail,
			Explain: joinSentences(
				fmt.Sprintf("The lifetime of %s has never been measured.", g.Name),
				floorExplainPhrase(prov, g.Name, g.TTLFloorShort)+", which is a floor and not a lifetime: "+
					"the real one is at least that and may be very much more.",
				g.TTLFloorEvidence, why, caveat),
		}
	default:
		detail := fmt.Sprintf("not measured, %s%s", g.Carrier, disagree)
		if !g.Measured {
			detail = fmt.Sprintf("not characterised yet, %s%s", g.Carrier, disagree)
		}
		return SessionTTLMetric{
			Value: ttlUnknownWord, Known: false, State: "unknown", Detail: detail,
			Explain: fmt.Sprintf("Nothing has measured how long %s lives. Not knowing is not the same as "+
				"it being long: a scan may outlive it and report a login wall as the application. %s %s",
				g.Name, why, caveat),
		}
	}
}

// floorExplainPhrase says WHAT produced the lower bound, in the words of the thing that produced
// it. Round 12 measured this sentence calling a probed floor captured traffic on a profile whose
// own corpus evidence said the corpus held nothing: a client still sending a value and a request
// this framework sent and watched work are different facts, and one sentence may not use the same
// words for both.
func floorExplainPhrase(prov Provenance, name, short string) string {
	switch prov {
	case ProvProbed:
		return fmt.Sprintf("The framework used %s successfully across %s of its own life", name, short)
	case ProvObserved:
		return fmt.Sprintf("Captured traffic shows one value of it still in use %s after it first appeared", short)
	}
	return fmt.Sprintf("A lower bound of %s is on file for it and nothing recorded how that was got", short)
}

// floorDetailPhrase is the same distinction, tile sized.
func floorDetailPhrase(prov Provenance, short string) string {
	switch prov {
	case ProvProbed:
		return "used successfully across " + short
	case ProvObserved:
		return "seen lasting " + short
	}
	return "a lower bound of " + short + " with no recorded provenance"
}

// joinSentences joins the parts of an explanation with single spaces, dropping the empty ones so
// an absent caveat does not leave a gap in the middle of a sentence.
func joinSentences(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			kept = append(kept, s)
		}
	}
	return strings.Join(kept, " ")
}

// investigationNotes are the sentences about the set rather than about one credential.
func investigationNotes(report SessionInvestigation, eligible []int) []string {
	notes := []string{}

	// SAID FIRST, BECAUSE IT QUALIFIES EVERYTHING BELOW IT. Whether the runner's own credential
	// source was read decides whether the rest of this report is a picture of the run or a picture
	// of one table.
	if report.Wire.Known {
		if report.Counts.Captured > 0 {
			notes = append(notes, fmt.Sprintf("%d of the credentials a scan of %s would send are NOT in the "+
				"Session Manager: the manual crawl captured them from a real browser session and the runner "+
				"substitutes the freshest one at send time. They are listed below with their source.",
				report.Counts.Captured, report.Wire.Host))
		}
		substituted := 0
		orphaned := []string{}
		for _, c := range report.Credentials {
			if !c.Stored || c.OnTheWire {
				continue
			}
			// A query credential is excluded from the disagreement count on purpose: the source
			// declines to substitute those by design, which is not the two layers disagreeing.
			if c.Sendable && c.CarrierKind != tokenTypeQuery {
				orphaned = append(orphaned, c.Name)
			}
			substituted++
		}
		if len(orphaned) > 0 {
			notes = append(notes, fmt.Sprintf("%d stored credential(s) would be sent by the Session Manager's "+
				"own rules and are NOT what the runner hands a probe for %s: %s. Each row says what goes out "+
				"instead. Where nothing goes out at all on that carrier the two disagree, and the runner is "+
				"what decides the bytes.", len(orphaned), report.Wire.Host, strings.Join(orphaned, ", ")))
		} else if substituted > 0 {
			notes = append(notes, fmt.Sprintf("%d stored credential(s) are not what goes out: a fresher "+
				"credential for the same carrier was captured, or the row is switched off or expired.", substituted))
		}
	} else {
		notes = append(notes, "WHAT THE RUNNER WOULD ACTUALLY SEND WAS NOT READ: "+report.Wire.WhyNotKnown+
			". Everything below is the stored credentials only. The runner substitutes the freshest captured "+
			"credential at send time, so a credential this list does not show may be the one on the wire.")
	}

	if report.Counts.Total == 0 && report.Counts.Captured == 0 {
		return append(notes, "No session tokens are stored for this target, so every scan runs anonymously. "+
			"Record an auth flow or paste a credential in Manage Sessions.")
	}
	if len(eligible) == 0 {
		notes = append(notes, fmt.Sprintf("%d credential(s) are stored and none of them would be sent. "+
			"Each row below says why.", report.Counts.Total))
	}
	if len(eligible) > 1 && report.Counts.TTLMeasured > 0 && report.Counts.TTLUnknown > 0 {
		notes = append(notes, fmt.Sprintf("Of the %d credentials this scan would send, %d have a measured "+
			"lifetime and %d do not. The card shows the shortest measured one as an upper bound; an unmeasured "+
			"credential could die sooner and nothing here would know.",
			len(eligible), report.Counts.TTLMeasured, report.Counts.TTLUnknown))
	}
	if len(eligible) > 0 && report.Counts.TTLMeasured == 0 {
		notes = append(notes, "No credential this scan would send has a measured lifetime. That is an absence "+
			"of measurement and not a long session.")
	}
	proven, available, outOfScope := 0, 0, 0
	for _, c := range report.Credentials {
		switch c.Refresh.Status {
		case RefreshProven:
			proven++
		case RefreshAvailable:
			available++
		case RefreshMintOutOfScope:
			outOfScope++
		}
	}
	if proven > 0 {
		notes = append(notes, fmt.Sprintf("%d credential(s) have had a refresh actually performed, so renewal "+
			"is a working option for them.", proven))
	}
	if available > 0 {
		notes = append(notes, fmt.Sprintf("%d credential(s) have a refresh mechanism that nobody has exercised. "+
			"A mechanism that exists is not a renewal that works; prove one before relying on it.", available))
	}
	if outOfScope > 0 {
		notes = append(notes, fmt.Sprintf("%d credential(s) are minted by a host outside this engagement, so the "+
			"framework must not renew them automatically. Re-authenticating by hand in a browser still works.",
			outOfScope))
	}
	return notes
}

// ---------------------------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------------------------

// sessionInvestigateOptions is the whole input to the pure builder: what the caller asked for, and
// what the handler loaded on its behalf. The builder does no I/O, so anything it needs from a
// database or from the runner's credential source arrives here.
type sessionInvestigateOptions struct {
	// RunMinutes is the run length the survival verdicts answer about. Zero means not asked.
	RunMinutes int
	// Reprofile re-measures every credential instead of reading the stored measurement back.
	Reprofile bool

	// DefaultRunMinutes and RunLengthBasis are the framework's own configured run length, the same
	// number TriageEstimatedRunDuration gives the renewal gate, so no second screen has to invent
	// one. Zero means the pacing could not be read and the basis says so.
	DefaultRunMinutes int
	RunLengthBasis    string

	// Wire and WireReading are the runner's credential source's answer for this target's host.
	// WireReading.Known false means it could not be consulted and Wire is empty for that reason
	// rather than because nothing would be sent.
	Wire        []sessionWireCredential
	WireReading SessionWireReading
}

// sessionInvestigateMaxRunMinutes is a decoding bound and not a policy about how long anybody may
// scan. It exists so that "run_minutes=99999999999999" is refused as unparseable rather than
// silently overflowing into a verdict. Fourteen days is longer than any run this framework has.
const sessionInvestigateMaxRunMinutes = 14 * 24 * 60

// decodeSessionInvestigateQuery reads the GET form of the request.
//
// STRICT. An unrecognised query parameter is refused rather than ignored, for the same reason the
// body decoder below sets DisallowUnknownFields: this codebase has a live defect where a PUT
// accepted a body it did not understand and answered saved:true, and a caller that asks a question
// the server silently did not hear gets an answer to a different question.
func decodeSessionInvestigateQuery(r *http.Request) (sessionInvestigateOptions, error) {
	opts := sessionInvestigateOptions{}
	for key, values := range r.URL.Query() {
		switch key {
		case "run_minutes":
			if len(values) != 1 {
				return opts, fmt.Errorf("run_minutes was given %d times; give it once", len(values))
			}
			n, err := strconv.Atoi(strings.TrimSpace(values[0]))
			if err != nil {
				return opts, fmt.Errorf("run_minutes must be a whole number of minutes, got %q", values[0])
			}
			if n <= 0 || n > sessionInvestigateMaxRunMinutes {
				return opts, fmt.Errorf("run_minutes must be between 1 and %d, got %d",
					sessionInvestigateMaxRunMinutes, n)
			}
			opts.RunMinutes = n
		default:
			return opts, fmt.Errorf("unrecognised query parameter %q", key)
		}
	}
	return opts, nil
}

// decodeSessionInvestigateBody reads the POST form. An empty body is a re-measure with no survival
// question, which is what the modal's Re-measure button sends.
func decodeSessionInvestigateBody(r *http.Request) (sessionInvestigateOptions, error) {
	opts := sessionInvestigateOptions{Reprofile: true}
	if r.Body == nil {
		return opts, nil
	}
	var payload struct {
		RunMinutes *int  `json:"run_minutes"`
		Reprofile  *bool `json:"reprofile"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		// An entirely empty body is not a malformed one.
		if err.Error() == "EOF" {
			return opts, nil
		}
		return opts, fmt.Errorf("the request body was not something this endpoint can act on: %v", err)
	}
	if payload.RunMinutes != nil {
		n := *payload.RunMinutes
		if n <= 0 || n > sessionInvestigateMaxRunMinutes {
			return opts, fmt.Errorf("run_minutes must be between 1 and %d, got %d",
				sessionInvestigateMaxRunMinutes, n)
		}
		opts.RunMinutes = n
	}
	if payload.Reprofile != nil {
		opts.Reprofile = *payload.Reprofile
	}
	return opts, nil
}

// sessionInvestigateLoader fetches the target's credentials and attaches their profiles. It is a
// variable so the handler can be tested end to end, response codes and serialisation included,
// without a database: the seam is the loader and nothing below it.
var sessionInvestigateLoader = loadSessionTokensForInvestigation

// loadSessionTokensForInvestigation reads the rows and characterises them.
//
// reprofile true re-measures every credential from scratch; false uses the stored measurement and
// falls back to measuring the ones that have none, which is what AttachSessionTokenProfiles
// already does for the token list.
func loadSessionTokensForInvestigation(ctx context.Context, scopeTargetID string, reprofile bool) ([]SessionToken, error) {
	if dbPool == nil {
		return nil, fmt.Errorf("no database connection")
	}
	rows, err := dbPool.Query(ctx,
		`SELECT `+sessionTokenCols+sessionTokenFrom+
			`WHERE t.scope_target_id = $1 ORDER BY t.is_active DESC, t.created_at ASC`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := []SessionToken{}
	for rows.Next() {
		t, scanErr := scanSessionToken(rows)
		if scanErr != nil {
			log.Printf("[SESSION-INVESTIGATE] failed to scan a token row: %v", scanErr)
			continue
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if reprofile {
		for i := range tokens {
			p, saveErr := ProfileAndSaveSessionToken(ctx, tokens[i])
			if saveErr != nil {
				log.Printf("[SESSION-INVESTIGATE] token %s was characterised but not stored: %v",
					tokens[i].ID, saveErr)
			}
			measured := p
			tokens[i].Profile = &measured
		}
		return tokens, nil
	}
	AttachSessionTokenProfiles(ctx, tokens)
	return tokens, nil
}

// ---------------------------------------------------------------------------------------------
// Reading what the runner would send, and how long the run is
// ---------------------------------------------------------------------------------------------

// sessionInvestigateWire is the seam onto the runner's credential source. It is a variable for the
// same reason the loader is: what goes on the wire depends on two tables and a scope target row,
// and the merge above has to be testable against a reading nobody can produce from a fixture.
var sessionInvestigateWire = loadSessionWireCredentials

// loadSessionWireCredentials asks THE RUNNER'S OWN SOURCE what it would hand a probe.
//
// It constructs the same triageDBFreshCreds the triage runner constructs and calls the same
// FreshFor, so there is no second implementation of the ranking, the expiry margin or the scope
// rule for this screen to get wrong. What it adds is nothing and what it takes away is nothing:
// the values that source read come through with it.
//
// IT SENDS NO REQUEST. FreshFor runs two SELECTs and ranks the rows. Nothing here mints, refreshes
// or validates a credential, and opening this screen therefore cannot touch the target.
func loadSessionWireCredentials(ctx context.Context, scopeTargetID string) ([]sessionWireCredential, SessionWireReading) {
	reading := SessionWireReading{
		Sources: []string{"session_tokens", "manual_crawl_captures"},
	}
	if dbPool == nil {
		reading.WhyNotKnown = "this process has no database handle, so the credential source the runner " +
			"reads could not be queried"
		return nil, reading
	}
	_, host, _ := ScopeTargetBase(scopeTargetID)
	reading.Host = host
	if host == "" {
		reading.WhyNotKnown = "this scope target has no readable host, and the runner's credential source " +
			"is asked per host"
		return nil, reading
	}

	creds, status := newTriageFreshCredentials(scopeTargetID).FreshFor(host)
	reading.Known = true
	reading.Fresh = status.Fresh
	reading.Expired = status.Expired
	reading.Note = status.Note
	reading.Exhausted = status.Exhausted
	// THE ROWS BEHIND THE COUNT, carried the same way the live ones are and through the same
	// projection, so a dead candidate and a live one cannot be described by two different pieces
	// of code. What separates them is where they go next, not how they were read.
	for _, c := range status.Dead {
		reading.dead = append(reading.dead, sessionWireWrap(c))
	}

	out := make([]sessionWireCredential, 0, len(creds))
	for _, c := range creds {
		out = append(out, sessionWireWrap(c))
	}
	return out, reading
}

// sessionWireWrap is the ONE projection from the runner's credential type onto this screen's, so
// the live set and the dead set cannot be read by two pieces of code that disagree.
func sessionWireWrap(c triageFreshCred) sessionWireCredential {
	carrier := CredentialCarrier{Kind: "header", Name: c.Header}
	if c.Header == "" {
		carrier = CredentialCarrier{Kind: "cookie", Name: c.Cookie}
	} else {
		carrier.Prefix = credentialSchemePrefix(c.value)
	}
	return sessionWireCredential{
		Carrier:      carrier,
		Value:        c.value,
		Fingerprint:  c.Fingerprint,
		Source:       c.Source,
		Observed:     c.Observed,
		Expires:      c.Expires,
		ExpirySource: c.ExpirySource,
	}
}

// credentialSchemePrefix returns the "Bearer " style prefix a raw header value carries, or "".
//
// The scheme is the part of the header in front of the value, and naming it lets the profiler
// strip it and the screen show it. Nothing after the first space is looked at.
func credentialSchemePrefix(value string) string {
	v := strings.TrimSpace(value)
	i := strings.IndexByte(v, ' ')
	if i <= 0 || i > 12 || !reAuthScheme.MatchString(v[:i]) {
		return ""
	}
	return v[:i] + " "
}

// sessionInvestigateRunLength is the seam onto the framework's configured run length.
var sessionInvestigateRunLength = triageConfiguredRunMinutes

// triageConfiguredRunMinutes is THE run length, published so two screens cannot ask the same
// survival question about two different runs.
//
// It is TriageEstimatedRunDuration over this target's own pacing, which is exactly what the renewal
// gate uses, and it is ROUNDED UP to the next whole minute. Rounding down is the direction that
// lies: a credential that dies at minute twenty of a run estimated at 20m1s would be reported as
// surviving a 20 minute run, and the survival verdict is the one number on this screen an operator
// acts on directly.
func triageConfiguredRunMinutes(ctx context.Context, scopeTargetID string) (int, string) {
	if dbPool == nil {
		return 0, "the configured run length could not be read: this process has no database handle"
	}
	settings, _ := LoadTriageSettings(ctx, scopeTargetID)
	d, basis := TriageEstimatedRunDuration(settings.Pacing)
	if d <= 0 {
		return 0, basis
	}
	mins := int((d + time.Minute - 1) / time.Minute)
	return mins, fmt.Sprintf("%s, rounded UP to %d minute(s). It is the same number the renewal gate "+
		"uses, so the two screens ask about one run", basis, mins)
}

// InvestigateSessionTokens handles GET and POST /session-tokens/target/{scope_target_id}/investigate.
//
// GET reads the stored characterisation, measuring anything that has never been measured. POST
// re-measures everything. Both return the same document, so the screen has one shape to render and
// the Re-measure button is a second call to the same place rather than a second view.
func InvestigateSessionTokens(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := strings.TrimSpace(mux.Vars(r)["scope_target_id"])
	if scopeTargetID == "" {
		http.Error(w, "scope_target_id is required", http.StatusBadRequest)
		return
	}

	var (
		opts sessionInvestigateOptions
		err  error
	)
	switch r.Method {
	case http.MethodPost:
		opts, err = decodeSessionInvestigateBody(r)
	default:
		opts, err = decodeSessionInvestigateQuery(r)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokens, err := sessionInvestigateLoader(r.Context(), scopeTargetID, opts.Reprofile)
	if err != nil {
		log.Printf("[SESSION-INVESTIGATE] failed to load credentials for %s: %v", scopeTargetID, err)
		http.Error(w, "Failed to load session tokens", http.StatusInternalServerError)
		return
	}
	// What the runner would actually put on the wire, and how long the configured run is. Neither
	// is allowed to fail the request: both have a third state that says the answer was not read,
	// and a screen that 500s because the pacing document is missing is worse than one that says so.
	opts.Wire, opts.WireReading = sessionInvestigateWire(r.Context(), scopeTargetID)
	opts.DefaultRunMinutes, opts.RunLengthBasis = sessionInvestigateRunLength(r.Context(), scopeTargetID)

	report := buildSessionInvestigation(scopeTargetID, tokens, opts, time.Now().UTC())
	writeSessionTokenJSON(w, http.StatusOK, report)
}
