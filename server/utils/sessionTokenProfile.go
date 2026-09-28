package utils

import (
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// THE TOKEN CHARACTERISATION ENGINE.
//
// What it answers, for one credential on one application: WHAT KIND of thing is this, HOW LONG
// does it live, and CAN IT BE REFRESHED. Nothing else in the framework asks those questions, and
// the cost of not asking them was measured on a live target on 2026-09-20:
//
//	the bearer in front of us is a 15 minute token, six distinct values arrived in ten minutes of
//	ordinary browsing, and a full triage run takes 29 minutes. The same endpoint in the same
//	minute answered 401 to the token frozen in attack_vectors.raw_request and 200 to the one in
//	manual_crawl_captures.
//
// So a scan configured without knowing the TTL is a scan that silently stops being authenticated
// partway through and reports a login wall as the application.
//
// ---------------------------------------------------------------------------------------------
// THE RULE THIS FILE IS BUILT AROUND
// ---------------------------------------------------------------------------------------------
//
// AN UNKNOWN TTL IS UNKNOWN. It is never a default, never a placeholder, and never quietly
// rounded up out of something weaker. Every number this file produces carries the provenance of
// how it was got, and the four provenances are not interchangeable:
//
//	parsed    the credential or its issuing response said so, and we read it
//	declared  the operator typed it into the Session Manager
//	observed  inferred from how the value behaved in the captured corpus, which is a FLOOR and
//	          not a measurement of the TTL (see the note on floors below)
//	probed    we sent requests until it stopped working, so we watched it die
//
// The type therefore has BOTH a TTL (with TTLKnown) and a separate TTLFloor. They are different
// facts and merging them is the defect this codebase keeps rediscovering under the name of a
// field called like a total that reports something else.
//
// WHY AN OBSERVED SPAN IS A FLOOR AND NOT A TTL, measured on the live corpus:
//
//	the tokens on this target are provably 900 second tokens (exp minus nbf, 51 distinct values,
//	29 of them exactly 900 and 22 exactly 901). Group the same corpus by distinct value and the
//	spans between first and last appearance are 0s, 0s, 0s, 11s, 45s, 78s, 133s, 358s, 868s. The
//	MEDIAN span is under a minute. A "TTL" read off the median would be wrong by a factor of
//	thirty, and wrong in the dangerous direction for the opposite reason too: the client here
//	rotates long before expiry, so the span measures the CLIENT'S refresh habit, not the SERVER'S
//	lifetime.
//
//	The only honest thing an observation of the corpus supports is: this value was still being
//	sent 868 seconds after it first appeared, therefore the TTL is AT LEAST 868 seconds. That is
//	TTLFloor. On this target the floor lands at 96% of the parsed truth, which is useful, and it
//	is still not the TTL.
//
// A RECOGNISER THAT CAN FIRE ON RANDOM BYTES NEEDS A SECOND WITNESS. Most of what this file does
// is decide what a value IS, and a session identifier is random characters, so any test that a
// random string can pass by luck will be passed by luck, on a schedule set by how many credentials
// get profiled. profileAsBranca tested one version byte and therefore reported a Branca token,
// with an ISSUE DATE DECODED OUT OF FOUR RANDOM BYTES, on up to 0.3875% of random session ids;
// dates from 1979 to 2104 were produced by the sweep and would have been persisted to
// session_tokens.issued_at and shown to the operator as a read fact. The rule that came out of it
// is written next to profileAsBranca and next to apiKeyFormat, and the sweep test measures both
// rather than asserting them.
//
// AND THE SECOND HALF OF THE SAME RULE: an answer that WAS on the wire must not be left unread.
// Most credentials state no lifetime of their own; their issuing response states all of it, in a
// Max-Age, an Expires or an expires_in. See CredentialEvidence.
//
// THE FRAMEWORK SERVES WHAT IT CAPTURED. This is a bug bounty tool, and a captured credential, a
// subject id, a namespaced cookie name and a token endpoint body are the EVIDENCE it exists to
// produce: an IDOR is proved by showing the other account's data and a leaked token is proved by
// showing the token. So nothing here hides a value it read. Fingerprint survives only where it is
// a JOIN KEY, tying an issuing response or a validation event to one credential without comparing
// bytes everywhere, and never where it stands in for something a person has to read.

// ---------------------------------------------------------------------------------------------
// Credential: the value, carried and served
// ---------------------------------------------------------------------------------------------

// Credential carries a credential value through this package.
//
// The field is unexported so the type owns how one is built, not so the bytes are unreachable:
// Value reads them, String prints them and MarshalJSON serves them.
type Credential struct {
	v string
}

// NewCredential wraps a raw value. A "Bearer " style scheme prefix is kept: it is part of what
// goes on the wire and stripping it here would make the value disagree with the stored row.
func NewCredential(raw string) Credential { return Credential{v: raw} }

// Value is the credential exactly as it was captured.
func (c Credential) Value() string { return c.v }

// Fingerprint is eight hex digits of the value's SHA-256, kept as a JOIN KEY: two rows with the
// same fingerprint carry the same credential and a rotation shows two different ones. It is not a
// stand-in for the value, which Value and String both serve.
func (c Credential) Fingerprint() string { return triageCredFingerprint(c.v) }

// IsZero reports an empty credential, which is not the same as a credential we could not parse.
func (c Credential) IsZero() bool { return strings.TrimSpace(c.v) == "" }

// Len is the byte length, occasionally the only distinguishing fact about an opaque value.
func (c Credential) Len() int { return len(c.v) }

// String is the value. %v, %s, %q and %x all reach it.
func (c Credential) String() string { return c.v }

// MarshalJSON serves the value, so an HTTP handler that marshals a struct holding a Credential
// publishes the credential rather than a description of one.
func (c Credential) MarshalJSON() ([]byte, error) { return json.Marshal(c.v) }

// ---------------------------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------------------------

// CredentialKind is what the thing IS, as opposed to how it travels. The distinction matters
// because the kind decides which questions have answers at all: a JWT carries its own expiry, a
// PHPSESSID carries nothing, and a JWE carries one we cannot read.
type CredentialKind string

const (
	// CredentialKindUnknown is the honest answer when nothing matched. It is NOT "opaque": opaque
	// is a positive finding about the shape of the value, unknown is an absence of one.
	CredentialKindUnknown CredentialKind = "unknown"
	// CredentialKindJWT is a compact JWS, the three-segment token everybody calls a JWT. Its
	// header and payload are base64url and readable without any key, which is why it is the one
	// kind where the TTL is simply a fact.
	CredentialKindJWT CredentialKind = "jwt"
	// CredentialKindJWE is the five-segment encrypted form. The header is readable, the claims
	// are not. Reporting this as unknown would be wrong: we know exactly what it is and exactly
	// why we cannot read its expiry.
	CredentialKindJWE CredentialKind = "jwe"
	// CredentialKindPASETO is a v1-v4 local or public token. Public payloads are readable,
	// local ones are encrypted, and its exp/iat/nbf are RFC3339 strings rather than unix seconds.
	CredentialKindPASETO CredentialKind = "paseto"
	// CredentialKindBranca carries its ISSUE time in cleartext and its payload encrypted. The TTL
	// is a parameter of the verifier and is not in the token at all, which makes it the clearest
	// example of a credential with a readable iat and an unknowable exp.
	CredentialKindBranca CredentialKind = "branca"
	// CredentialKindSAML is a base64 (optionally deflated) SAML assertion, whose lifetime lives in
	// Conditions/@NotOnOrAfter and whose session lifetime lives in AuthnStatement.
	CredentialKindSAML CredentialKind = "saml_assertion"
	// CredentialKindSessionID is a classic server-side session identifier: PHPSESSID, JSESSIONID,
	// ASP.NET_SessionId, a Rails _session, connect.sid. There is no readable expiry, by design.
	CredentialKindSessionID CredentialKind = "opaque_session_id"
	// CredentialKindOpaqueBearer is a bearer value with no structure we recognise.
	CredentialKindOpaqueBearer CredentialKind = "opaque_bearer"
	// CredentialKindAPIKey is a value matching a published API key format. These frequently never
	// expire, and "frequently" is exactly why this file does not record non_expiring for one: see
	// ExpiryStyleNonExpiring.
	CredentialKindAPIKey CredentialKind = "api_key"
	// CredentialKindOAuthAccess is an access token whose issuing response we read, so expires_in
	// and the refresh_token beside it are known even when the value itself is opaque.
	//
	// REACHED FROM: applyTokenResponseEvidence, when a captured token endpoint response carries an
	// access_token whose fingerprint is this credential. The fingerprint is the whole of the join:
	// a response that minted somebody else's token says nothing about this one.
	CredentialKindOAuthAccess CredentialKind = "oauth_access_token"
	// CredentialKindPrincipalName is a value that NAMES a principal rather than proving one: a
	// username, a user id, an account handle, a last-signed-in-as pointer.
	//
	// IT IS NOT A CREDENTIAL AND THAT IS THE POINT OF HAVING THE WORD. Cognito writes
	// CognitoIdentityServiceProvider.<clientid>.LastAuthUser beside the tokens that ARE the
	// session, and on the live estate that cookie became the GOVERNING credential of the
	// Authentication card: an unreadable lifetime on a value that has no lifetime, standing in
	// for a session whose real tokens had already expired. A pointer at a subject cannot be
	// refused by the application, so counting one as a live credential is a false clean with
	// extra steps.
	CredentialKindPrincipalName CredentialKind = "principal_name"
)

// Provenance says how a number was obtained. Every lifetime figure in a profile carries one.
type Provenance string

const (
	// ProvUnknown means nothing answered. It is a result, not a missing field.
	ProvUnknown Provenance = "unknown"
	// ProvParsed means we read it out of the credential itself or out of the response that
	// issued it. This is the only provenance that is a measurement of the server's intent.
	ProvParsed Provenance = "parsed"
	// ProvDeclared means a human typed it into the Session Manager. Believed, but it is a
	// claim, and a claim from the person being surprised by the TTL is worth labelling.
	ProvDeclared Provenance = "declared"
	// ProvObserved means inferred from the captured corpus. See the floor note at the top:
	// an observation supports a lower bound and never a TTL.
	//
	// REACHED FROM: applyObservation, as TTLFloorProvenance. It is deliberately unreachable as a
	// TTLProvenance and always will be, because promoting a corpus reading to a lifetime is the
	// defect this file is built around. Until TTLFloorProvenance existed the floor was the one
	// lifetime figure carrying no provenance at all, which is why this word could not be written.
	ProvObserved Provenance = "observed"
	// ProvProbed means we used the credential and watched what happened.
	//
	// REACHED FROM: applyProbeHistory, as TTLFloorProvenance. A session_token_events row of kind
	// validate and status active is a request this framework sent where the target answered
	// differently because of the credential, so it is a record of the credential still WORKING at
	// that moment, which is a stronger fact than the corpus showing a client still sending it.
	ProvProbed Provenance = "probed"
)

// IssuedAtSource names WHAT was read to get an issue time, because two of the things that can
// answer are not issue times at all.
//
// nbf is NOT-BEFORE, and a SAML assertion Conditions NotBefore is the same claim under another
// name: an issuer that backdates either for clock skew puts it EARLIER than the mint, so a
// lifetime counted from one is an over-estimate, in the direction that renews a credential late.
// On the live estate no token carries iat at all, which makes the nbf rung the COMMON path rather
// than the rare one. The source therefore travels with the timestamp everywhere the timestamp
// goes, and IsMintTime is what a caller branches on before counting anything from it.
type IssuedAtSource string

const (
	// IssuedAtNotRead is the default: no issue time was read.
	IssuedAtNotRead IssuedAtSource = ""
	// IssuedAtClaimIat is the iat claim of a JOSE or PASETO token, which IS the mint time.
	IssuedAtClaimIat IssuedAtSource = "iat"
	// IssuedAtClaimNbf is the nbf claim, read only where there is no iat.
	IssuedAtClaimNbf IssuedAtSource = "nbf"
	// IssuedAtBrancaTimestamp is the cleartext timestamp in a Branca header, which the format
	// defines as the issue time.
	IssuedAtBrancaTimestamp IssuedAtSource = "branca_timestamp"
	// IssuedAtSAMLNotBefore is the Conditions NotBefore of an assertion.
	IssuedAtSAMLNotBefore IssuedAtSource = "saml_not_before"
	// IssuedAtIssuingResponse is the moment the captured response that set THIS exact value was
	// received, which is when the server minted it.
	IssuedAtIssuingResponse IssuedAtSource = "issuing_response"
)

// issuedAtSources says, for each source, whether it is a mint time and what was actually read.
var issuedAtSources = map[IssuedAtSource]struct {
	mint     bool
	evidence string
}{
	IssuedAtClaimIat:        {true, "the iat claim of the token, which is when the issuer says it minted it"},
	IssuedAtClaimNbf:        {false, "the nbf claim of the token; nbf is not-before rather than issued-at, and an issuer that backdates it for clock skew puts it EARLIER than the mint, so it is a lower bound on the issue time and not the issue time"},
	IssuedAtBrancaTimestamp: {true, "the cleartext timestamp in the Branca header, which the format defines as the issue time"},
	IssuedAtSAMLNotBefore:   {false, "the Conditions NotBefore of the assertion; that is the earliest moment it may be presented rather than when it was minted"},
	IssuedAtIssuingResponse: {true, "the moment the captured response that set this exact value was received"},
}

// IsMintTime is true only where the source states when the credential was MINTED. Anything that
// counts a lifetime from an issue time has to branch on this first.
func (s IssuedAtSource) IsMintTime() bool { return issuedAtSources[s].mint }

// Evidence is the sentence behind the issue time, carrying the caveat where there is one.
func (s IssuedAtSource) Evidence() string {
	if v, ok := issuedAtSources[s]; ok {
		return v.evidence
	}
	return "nothing recorded where this issue time came from"
}

// ExpiryStyle is the SHAPE of the lifetime, which changes what a TTL even means.
type ExpiryStyle string

const (
	// ExpiryStyleUnknown is the default and stays the default until something is measured.
	ExpiryStyleUnknown ExpiryStyle = "unknown"
	// ExpiryStyleAbsolute: the credential dies at a fixed wall-clock moment whatever you do.
	ExpiryStyleAbsolute ExpiryStyle = "absolute"
	// ExpiryStyleSliding: using it pushes the expiry out. A 30 minute sliding session survives a
	// 29 minute scan comfortably and a 30 minute absolute one does not, which is the whole reason
	// this field exists separately from the TTL.
	//
	// REACHED FROM: cookieLooksSliding. The wire signature needs no model: the SAME cookie value
	// was set again later with a lifetime that puts its death further out. A new value with a
	// fresh Max-Age is a rotation and not an extension, and is excluded by construction.
	ExpiryStyleSliding ExpiryStyle = "sliding"
	// ExpiryStyleSession: a cookie with neither Expires nor Max-Age. It dies when the browser
	// closes, so it has NO wall-clock expiry of its own, and the server-side session behind it
	// has a lifetime we have not measured. This is a genuinely different answer from both "one
	// hour" and "unknown", and collapsing it into either loses the distinction the operator needs.
	//
	// REACHED FROM: applySetCookieEvidence, off a captured Set-Cookie. It is NOT inferred from
	// the credential being a cookie: a cookie with no captured issuance stays unknown, because
	// "we never saw the Set-Cookie" and "the Set-Cookie set no lifetime" are different facts.
	ExpiryStyleSession ExpiryStyle = "session"
	// ExpiryStyleNonExpiring is recorded ONLY from evidence: an explicit never-expires statement,
	// or a probe that kept working past any plausible lifetime. It is deliberately NOT inferred
	// from "it looks like an API key", because "API keys usually do not expire" is an assumption
	// and this file does not trade in those.
	//
	// NOT REACHED, DELIBERATELY, AND THE ONE VALUE IN THIS FILE THAT NOTHING CAN PRODUCE.
	//
	// There is no honest producer. An Expires far in the future is an ABSOLUTE expiry and saying
	// otherwise would be the inference this file refuses; an absent exp claim means the server
	// enforces the lifetime, not that there is none; RFC 6749 says an absent expires_in leaves the
	// lifetime unstated. The only thing that could establish it is a probe that outlived a stated
	// horizon, and no probe of that shape exists yet.
	//
	// It is NOT deleted, because sessionInvestigateAPI.go and triageSettingsAPI.go both reference
	// it and are outside this file. What was closed instead is the hole it opened: Survives used
	// to grant an unconditional YES on the style alone, so a row carrying the word from a hand
	// edit or a future writer would have told a scan configuration gate that an unmeasured
	// credential outlives any run. It now requires a provenance that could have established it.
	ExpiryStyleNonExpiring ExpiryStyle = "non_expiring"
)

// RefreshStatus answers "can this session be renewed", and the values are ordered by how much we
// actually did.
type RefreshStatus string

const (
	// RefreshNotObserved: we looked at the flows, the corpus and the token, and saw no mechanism.
	// NOT the same as "cannot be refreshed": it is the absence of evidence, said out loud.
	RefreshNotObserved RefreshStatus = "not_observed"
	// RefreshAvailable: a mechanism exists and its mint host is inside the engagement, but we have
	// not exercised it. A refresh_token field in a body is THIS, not proven.
	RefreshAvailable RefreshStatus = "available"
	// RefreshMintOutOfScope: a mechanism exists and we are not allowed to touch it, because the
	// host that mints the credential is outside the engagement. This must be REPORTED and never
	// silently folded into unrefreshable: the operator can often re-authenticate by hand in a
	// browser, which is a completely different plan from "this session cannot be renewed".
	RefreshMintOutOfScope RefreshStatus = "mint_out_of_scope"
	// RefreshProven: we did it and watched a DIFFERENT credential come back. The standing rule
	// here is that validated requires a proof of concept, and the proof of concept for a refresh
	// is two credentials that differ. RecordRefreshProof refuses to write this without two
	// fingerprints that differ, and records both credentials beside them so the claim can be
	// checked against the wire.
	RefreshProven RefreshStatus = "proven"
)

// RefreshMechanism names HOW, so the report says something an operator can act on.
type RefreshMechanism string

const (
	RefreshMechanismNone          RefreshMechanism = ""
	RefreshMechanismOAuthRefresh  RefreshMechanism = "oauth_refresh_token"
	RefreshMechanismTokenEndpoint RefreshMechanism = "token_endpoint"
	RefreshMechanismAuthFlow      RefreshMechanism = "auth_flow_replay"
	RefreshMechanismSilentRenew   RefreshMechanism = "silent_renew_endpoint"
	RefreshMechanismServerReissue RefreshMechanism = "server_reissue_on_use"
)

// RefreshCapability is the refresh half of a profile.
type RefreshCapability struct {
	Status    RefreshStatus    `json:"status"`
	Mechanism RefreshMechanism `json:"mechanism"`
	// MintHost is where a new credential would come from. Empty when no mechanism was found.
	MintHost string `json:"mint_host"`
	// MintInScope is whether that host is inside this engagement's scope, computed from the same
	// ScanScope every request-issuing scan uses, so it cannot drift from what the scanner allows.
	MintInScope bool `json:"mint_in_scope"`
	// Evidence is the list of observations that produced the status, in the operator's words. It
	// is what makes the difference between available and proven auditable.
	Evidence []string `json:"evidence"`
	// ProvenAt is when the refresh was last actually performed and a different credential came
	// back. Zero unless Status is proven.
	ProvenAt time.Time `json:"proven_at"`
}

// ---------------------------------------------------------------------------------------------
// CredentialCarrier: how it travels
// ---------------------------------------------------------------------------------------------

// CredentialCarrier is where on the wire the credential rides. It is separate from the kind
// because the two are independent: a JWT can arrive in an Authorization header, a cookie or a
// query parameter, and the carrier is what the corpus observation has to search for.
type CredentialCarrier struct {
	// Kind is one of the session_tokens token_type values: header, cookie, api_key, bearer, query.
	Kind string `json:"kind"`
	// Name is the header name, the cookie name or the parameter name.
	Name string `json:"name"`
	// Prefix is the scheme written before the value, typically "Bearer ".
	Prefix string `json:"prefix"`
}

// reCredentialNameUUID matches an RFC 4122 UUID standing alone as one whole segment of a name.
// An auth SDK puts the account in the key: Amplify's storage key is
// CognitoIdentityServiceProvider.<client id>.<username>.<leaf>, so a namespaced name carries a
// per-account segment between the client id and the role word. credentialNamePrincipalSegment
// reads it to group a jar by principal.
var reCredentialNameUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Describe renders the carrier for a reason string, with the whole name in it. A namespaced name
// carries the account it belongs to, and on a jar with two sign-ins that is exactly the fact the
// operator is reading the sentence for.
func (c CredentialCarrier) Describe() string {
	switch {
	case c.Name == "":
		return "an unnamed carrier"
	case c.Kind == "cookie":
		return c.Name + " cookie"
	case c.Kind == "query":
		return c.Name + " query parameter"
	default:
		return c.Name + " header"
	}
}

// ---------------------------------------------------------------------------------------------
// SessionTokenProfile: the one type the rest of the round builds on
// ---------------------------------------------------------------------------------------------

// SessionTokenProfile is the complete answer for one credential: what it is, how long it lives,
// and whether it can be refreshed. It carries the credential's Fingerprint as the join back to the
// row that holds the value, which SessionToken.TokenValue serves.
type SessionTokenProfile struct {
	TokenID       string `json:"token_id"`
	ScopeTargetID string `json:"scope_target_id"`
	// Name is the operator's label for the token, carried so a UI does not have to join.
	Name        string            `json:"name"`
	Carrier     CredentialCarrier `json:"carrier"`
	Fingerprint string            `json:"fingerprint"`

	Kind CredentialKind `json:"kind"`
	// KindEvidence says what made us say that, e.g. "three base64url segments, header alg ES256".
	KindEvidence string `json:"kind_evidence"`

	// TTL is how long the credential lives from issue. Valid ONLY when TTLKnown; a zero duration
	// with TTLKnown false means unknown and must never be rendered as "0".
	TTL      time.Duration `json:"ttl_seconds"`
	TTLKnown bool          `json:"ttl_known"`
	// TTLProvenance is how TTL was obtained. When TTLKnown is false it is ProvUnknown.
	TTLProvenance Provenance `json:"ttl_provenance"`
	// TTLEvidence names the claims or the columns that produced it, so the number can be audited
	// rather than believed. "exp minus nbf" and "exp minus iat" are different facts.
	TTLEvidence string `json:"ttl_evidence"`

	// TTLFloor is a LOWER BOUND on the lifetime taken from the corpus: this value was still in use
	// this long after it first appeared, so the TTL is at least this. It is deliberately a
	// different field from TTL. See the note at the top of this file for the measurement that
	// makes merging them a defect.
	TTLFloor      time.Duration `json:"ttl_floor_seconds"`
	TTLFloorKnown bool          `json:"ttl_floor_known"`
	// TTLFloorProvenance is HOW the floor was got, and it is a separate fact from how the TTL was
	// got. The doc on Provenance says every lifetime figure carries one; the floor is a lifetime
	// figure, and until this field existed it was the one that did not, which is also why
	// observed and probed were unreachable words. A floor can be OBSERVED (the captured corpus
	// shows the value still in use that long after it appeared) or PROBED (the framework itself
	// used the credential successfully that long after it was issued). Probed outranks observed:
	// one is a record of somebody else's traffic, the other is a request we sent and watched work.
	TTLFloorProvenance Provenance `json:"ttl_floor_provenance"`
	// TTLFloorEvidence names what produced the floor. Empty falls back to ObservedEvidence, which
	// is where a corpus floor's sentence lives.
	TTLFloorEvidence string `json:"ttl_floor_evidence"`
	// ObservedSamples is how many DISTINCT values of this carrier the corpus holds, and
	// ObservedRequests how many rows. One sample cannot show rotation, so the count is what makes
	// the floor readable rather than a bare number.
	ObservedSamples  int    `json:"observed_samples"`
	ObservedRequests int    `json:"observed_requests"`
	ObservedEvidence string `json:"observed_evidence"`
	// RotationInterval is the median gap between successive distinct values appearing. It is the
	// CLIENT'S refresh habit and is NOT the TTL; on the live target it is under a minute against
	// a 900 second TTL. It is reported because a scan that wants a fresh credential cares how
	// often one arrives.
	RotationInterval time.Duration `json:"rotation_interval_seconds"`
	RotationKnown    bool          `json:"rotation_known"`

	// ExpiresAt is the wall-clock moment this particular value dies. Valid only when ExpiryKnown.
	ExpiresAt        time.Time   `json:"expires_at"`
	ExpiryKnown      bool        `json:"expiry_known"`
	ExpiryProvenance Provenance  `json:"expiry_provenance"`
	ExpiryStyle      ExpiryStyle `json:"expiry_style"`
	ExpiryEvidence   string      `json:"expiry_evidence"`
	// IssuedAt is when the credential was minted. Two things can say so and both are READ rather
	// than inferred: the credential itself (a JWT iat, a Branca timestamp, a PASETO iat) and the
	// capture time of the response that ISSUED this exact value, matched by fingerprint. It is
	// kept because a floor computed against it is tighter than one computed against first capture,
	// and because a probed floor needs an origin to count from.
	//
	// It is NOT the time we first saw the value being sent. That is the corpus FirstSeen, which
	// measures when the capture started rather than when the server minted anything.
	IssuedAt      time.Time `json:"issued_at"`
	IssuedAtKnown bool      `json:"issued_at_known"`
	// IssuedAtSource is WHAT was read to get it. See the type: two of the things that can answer
	// are not issue times, and the timestamp alone cannot say which one did.
	IssuedAtSource IssuedAtSource `json:"issued_at_source"`

	Refresh RefreshCapability `json:"refresh"`

	// Attributes are the facts read off the credential and its issuance: alg, kid, iss, sub, aud,
	// typ, the cookie flags. Values go in as they were read.
	Attributes map[string]string `json:"attributes"`
	// Warnings are things the operator should know that are not errors, such as an unsigned JWT
	// or a payload that did not parse.
	Warnings []string `json:"warnings"`

	ProfiledAt time.Time `json:"profiled_at"`
}

// MarshalJSON renders the profile for an HTTP handler.
//
// IT EXISTS BECAUSE A time.Duration MARSHALS AS NANOSECONDS. A field tagged ttl_seconds that
// serialises 900000000000 is precisely the defect this codebase keeps rediscovering: a field
// named like one unit reporting another, believed by whoever reads it next. The durations are
// converted here, once, rather than in every consumer.
//
// The two rendered sentences ride along for the same reason. A client that formats ttl_seconds
// itself has to remember that zero means unknown; a client handed ttl_display cannot get it
// wrong, because an unmeasured lifetime arrives as the word UNKNOWN.
func (p SessionTokenProfile) MarshalJSON() ([]byte, error) {
	type alias SessionTokenProfile
	return json.Marshal(struct {
		alias
		TTL              int64  `json:"ttl_seconds"`
		TTLFloor         int64  `json:"ttl_floor_seconds"`
		RotationInterval int64  `json:"rotation_interval_seconds"`
		TTLDisplay       string `json:"ttl_display"`
		ExpiryDisplay    string `json:"expiry_display"`
	}{
		alias:            alias(p),
		TTL:              int64(p.TTL / time.Second),
		TTLFloor:         int64(p.TTLFloor / time.Second),
		RotationInterval: int64(p.RotationInterval / time.Second),
		TTLDisplay:       p.TTLDisplay(),
		ExpiryDisplay:    p.ExpiryDisplay(),
	})
}

// String is a safe one-line rendering, on a value receiver for the same reason Credential's is.
func (p SessionTokenProfile) String() string {
	return fmt.Sprintf("%s %s (%s): TTL %s, expiry %s, refresh %s",
		p.Kind, p.Carrier.Describe(), p.Fingerprint, p.TTLDisplay(), p.ExpiryDisplay(), p.Refresh.Status)
}

// TTLDisplay is the sentence a UI should show. It cannot render an unknown as a number, which is
// the point: the honesty is in the type rather than in every caller remembering.
func (p SessionTokenProfile) TTLDisplay() string {
	if p.TTLKnown {
		return fmt.Sprintf("%s (%s: %s)", humaniseTTL(p.TTL), p.TTLProvenance, p.TTLEvidence)
	}
	if p.TTLFloorKnown {
		return fmt.Sprintf("UNKNOWN, at least %s (%s: %s)", humaniseTTL(p.TTLFloor), p.floorProvenance(), p.FloorEvidence())
	}
	return "UNKNOWN"
}

// floorProvenance is how the floor was got, and a floor with NOTHING recorded is UNKNOWN.
//
// It used to default to observed, on the reasoning that every floor written before the column
// existed was a corpus reading. That default is how a probed floor, and a floor nothing can
// attribute, acquire a provenance neither earned: round 12 measured three operator-facing
// sentences calling a probed floor captured traffic, and every one of them was reading this
// default. An unknown provenance reads as unknown, like every other unmeasured thing here.
func (p SessionTokenProfile) floorProvenance() Provenance {
	if p.TTLFloorProvenance == "" {
		return ProvUnknown
	}
	return p.TTLFloorProvenance
}

// floorPhrase says where a lower bound came from in the words of the thing that produced it. A
// reading of somebody else's traffic and a request this framework sent are different facts, and one
// sentence may not use the same words for both.
func floorPhrase(prov Provenance, floor time.Duration) string {
	switch prov {
	case ProvProbed:
		return fmt.Sprintf("the framework itself only used it successfully across %s", humaniseTTL(floor))
	case ProvObserved:
		return fmt.Sprintf("the corpus only shows it lasting at least %s", humaniseTTL(floor))
	}
	return fmt.Sprintf("the only lower bound on file is %s and nothing recorded how that was got", humaniseTTL(floor))
}

// floorProvenanceStored is what goes in the column. It stays EMPTY when there is no floor, so an
// absent measurement is never persisted as the word observed, which is the same rule as writing
// NULL rather than zero into ttl_seconds.
func (p SessionTokenProfile) floorProvenanceStored() Provenance {
	if !p.TTLFloorKnown {
		return ""
	}
	return p.floorProvenance()
}

// FloorBelongsToOneCredential answers whether the lower bound on file is the span of ONE
// credential's life or of an unknown number of them, and it is the question a caller has to ask
// before deriving anything from a floor.
//
// It is answered here rather than by each reader because the producer of the floor is the only
// thing that knows how it was got. An OBSERVED floor is the longest span of a SINGLE distinct
// value of the carrier, identified by fingerprint, so it is one credential's own span, though not
// necessarily the one stored now. A PROBED floor is taken only across validation events that
// applyProbeHistory could tie to the value stored now, and where it could tie none there is no
// floor at all. Anything else has no recorded provenance, and a default is not a measurement.
func (p SessionTokenProfile) FloorBelongsToOneCredential() (bool, string) {
	if !p.TTLFloorKnown {
		return false, "no lower bound has been measured for this credential at all"
	}
	switch p.floorProvenance() {
	case ProvObserved:
		return true, "the corpus floor is the span of a single distinct value of this carrier, identified by fingerprint, so it is one credential's own life, though not necessarily the value stored now: " + p.FloorEvidence()
	case ProvProbed:
		return true, "the probed floor is taken only across validation events that could be attributed to the value stored now: " + p.FloorEvidence()
	}
	return false, "nothing recorded how the lower bound was obtained, so it cannot be shown to belong to one credential rather than to span a rotation"
}

// FloorEvidence is the sentence behind the lower bound, wherever it came from.
func (p SessionTokenProfile) FloorEvidence() string {
	if strings.TrimSpace(p.TTLFloorEvidence) != "" {
		return p.TTLFloorEvidence
	}
	return p.ObservedEvidence
}

// ExpiryDisplay renders the wall-clock death of this value.
func (p SessionTokenProfile) ExpiryDisplay() string {
	if !p.ExpiryKnown {
		if p.ExpiryStyle == ExpiryStyleSession {
			return "no wall-clock expiry; dies with the browser session"
		}
		return "UNKNOWN"
	}
	return fmt.Sprintf("%s (%s)", p.ExpiresAt.UTC().Format(time.RFC3339), p.ExpiryProvenance)
}

// RemainingAt is how much life this value has left. The second return is whether we know at all.
func (p SessionTokenProfile) RemainingAt(now time.Time) (time.Duration, bool) {
	if !p.ExpiryKnown {
		return 0, false
	}
	return p.ExpiresAt.Sub(now), true
}

// Survives is THE question a scan configuration gate asks: will this credential still be alive
// after d of scanning?
//
// It returns THREE states and not two. known=false is not a no and is emphatically not a yes: a
// gate that treats an unmeasured TTL as "fine" is the same failure as a scanner treating an
// unprobed pair as clean. Callers must branch on known before they branch on ok.
func (p SessionTokenProfile) Survives(d time.Duration, now time.Time) (ok bool, known bool, why string) {
	// A NON-EXPIRING STYLE IS ONLY A YES IF SOMETHING MEASURED IT.
	//
	// This is the one branch that hands a scan configuration gate an unconditional yes, so the
	// style alone must not be enough to reach it. Nothing in this package can currently produce
	// non_expiring (see the note on ExpiryStyleNonExpiring), which means the only way a profile
	// carries it is a row somebody wrote by hand or a future writer that guessed, and a yes with
	// no measurement behind it is the same defect as a scanner calling an unprobed pair clean.
	// The provenance has to name a method that could have established it.
	if p.ExpiryStyle == ExpiryStyleNonExpiring {
		switch p.ExpiryProvenance {
		case ProvParsed, ProvProbed, ProvDeclared:
			return true, true, fmt.Sprintf("the credential was measured as non-expiring (%s)", p.ExpiryProvenance)
		}
		return false, false, "the credential is recorded as non-expiring but nothing says how that was established, so it is an unmeasured claim and not a measurement"
	}
	if remaining, have := p.RemainingAt(now); have {
		if remaining <= 0 {
			// A DEATH IS NOT AN ERASURE. How long a session lasts on this application and whether
			// THIS value is still alive are two facts, and only one of them died. The first was
			// read out of the credential and is the answer to the question an operator opens this
			// screen with; dropping it here is what leaves a target whose access token lifetime is
			// a parsed 5m reading UNKNOWN because the newest capture is thirteen hours old.
			if p.TTLKnown {
				return false, true, fmt.Sprintf(
					"it expired %s ago, and its whole lifetime is %s, read from %s: the value is dead and the lifetime is still measured",
					humaniseTTL(-remaining), humaniseTTL(p.TTL), p.TTLEvidence)
			}
			return false, true, fmt.Sprintf("it expired %s ago", humaniseTTL(-remaining))
		}
		if remaining >= d {
			return true, true, fmt.Sprintf("%s of life left against a %s run", humaniseTTL(remaining), humaniseTTL(d))
		}
		extra := ""
		if p.ExpiryStyle == ExpiryStyleSliding {
			extra = ", though the expiry is sliding and use may push it out"
		}
		return false, true, fmt.Sprintf("%s of life left against a %s run%s", humaniseTTL(remaining), humaniseTTL(d), extra)
	}
	// No wall-clock expiry. A TTL alone cannot answer the question without an issue time, but a
	// TTL SHORTER than the run answers it in the negative regardless of when the clock started.
	if p.TTLKnown && p.TTL < d {
		return false, true, fmt.Sprintf("its whole lifetime is %s, shorter than a %s run, so it cannot survive one however fresh it is",
			humaniseTTL(p.TTL), humaniseTTL(d))
	}
	if p.TTLFloorKnown && p.TTLFloor < d && !p.TTLKnown {
		return false, false, fmt.Sprintf("the TTL was never measured; %s against a %s run",
			floorPhrase(p.floorProvenance(), p.TTLFloor), humaniseTTL(d))
	}
	if p.TTLKnown {
		return false, false, fmt.Sprintf("its lifetime is %s but we do not know when this value was issued, so its remaining life is unknown",
			humaniseTTL(p.TTL))
	}
	return false, false, "neither the expiry nor the lifetime of this credential has been measured"
}

// ---------------------------------------------------------------------------------------------
// Profiling a raw value: pure, no database, no network
// ---------------------------------------------------------------------------------------------

// ProfileCredential characterises a value and its carrier with no I/O at all.
//
// It is the half of the engine that is pure, so it is exhaustively testable, and it is the half
// the other callers can use on a value they hold in hand rather than one in a table.
func ProfileCredential(c Credential, carrier CredentialCarrier, now time.Time) SessionTokenProfile {
	return ProfileCredentialWithEvidence(c, carrier, CredentialEvidence{}, now)
}

// ProfileCredentialWithEvidence is ProfileCredential plus what the RESPONSE THAT ISSUED the
// credential said about it.
//
// MOST CREDENTIALS DO NOT CARRY THEIR OWN LIFETIME. A JWT, a PASETO and a SAML assertion state
// their expiry in their own bytes; a PHPSESSID, a rotating opaque cookie and an OAuth access token
// state it in the response that minted them, in a Max-Age, an Expires or an expires_in. A profiler
// that reads only the value therefore answers UNKNOWN for most of the web while the answer sat on
// the wire in the same exchange. That was measured: on ten applications, four of them said the
// lifetime out loud in the issuing response and all four profiled as UNKNOWN.
//
// The evidence is applied AFTER the structural parse and never over it. A token that states its
// own exp has said something about itself that a Set-Cookie around it cannot contradict silently:
// a disagreement is recorded as a warning, because the usual cause is a stored value that has been
// rotated underneath the response we captured.
func ProfileCredentialWithEvidence(c Credential, carrier CredentialCarrier, ev CredentialEvidence, now time.Time) SessionTokenProfile {
	p := profileCredentialBytes(c, carrier, now)
	applyIssuingResponse(&p, ev, carrier)
	return p
}

func profileCredentialBytes(c Credential, carrier CredentialCarrier, now time.Time) SessionTokenProfile {
	p := SessionTokenProfile{
		Carrier:          carrier,
		Fingerprint:      c.Fingerprint(),
		Kind:             CredentialKindUnknown,
		TTLProvenance:    ProvUnknown,
		ExpiryProvenance: ProvUnknown,
		ExpiryStyle:      ExpiryStyleUnknown,
		Attributes:       map[string]string{},
		Refresh:          RefreshCapability{Status: RefreshNotObserved},
		ProfiledAt:       now,
	}
	if c.IsZero() {
		p.Warnings = append(p.Warnings, "the stored credential is empty, so nothing could be characterised")
		return p
	}

	body := stripCredentialScheme(c.v, carrier.Prefix)

	switch {
	case profileAsJOSE(&p, body):
	case profileAsPASETO(&p, body):
	// A PUBLISHED COOKIE NAME OUTRANKS A ONE IN 256 VERSION BYTE. PHP writes PHPSESSID and PHP
	// does not mint Branca tokens, so reading a 0xBA first byte out of a framework session handle
	// is the recogniser firing on noise, and the kind drives how the rest of the screen reads.
	case !carrierNamesTheFrameworkThatMintedIt(carrier) && profileAsBranca(&p, body):
	case profileAsSAML(&p, body):
	default:
		profileAsOpaque(&p, body, carrier)
	}
	return p
}

// carrierNamesTheFrameworkThatMintedIt reports whether the credential travels in a cookie whose
// name identifies the FRAMEWORK that set it. That name is a stronger witness about what the value
// is than any single byte inside it, which is why it outranks the Branca version byte.
//
// ---------------------------------------------------------------------------------------------
// THE VETO IS NARROWER THAN THE LIST IT READS, AND THE NUMBERS SAY WHY
// ---------------------------------------------------------------------------------------------
//
// Round 13 gave every one of the thirteen published names in knownSessionCookies a veto over the
// Branca recogniser, and measured what it bought: on PHPSESSID the false positive rate went to
// zero, and OVERALL it moved nothing (0.00375% and 0.00364% against 0.00362% before). The whole
// gain was the one name, and the cost was paid everywhere: a genuine Branca token in ANY of the
// thirteen lost its issue time, which is the only thing the format discloses.
//
// The split is in the list itself. knownSessionCookies stores what each name says, and three of
// its entries say nothing about a minter: session and sid are labelled "generic" and sessionid is
// "Django or similar". PHP does not mint Branca tokens, and JSESSIONID, laravel_session and
// ASP.NET_SessionId are the same kind of statement about a runtime. A cookie called session is
// not anybody in particular, so it is a statement about the ROLE and cannot outrank two structural
// witnesses.
//
// What the narrowing costs is measured by the sweep in this package, which now draws a cookie
// named session alongside app_sid, PHPSESSID and Authorization, and holds the whole table to the
// same ceiling.
func carrierNamesTheFrameworkThatMintedIt(carrier CredentialCarrier) bool {
	if carrier.Kind != "cookie" {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(carrier.Name))
	if _, ok := knownSessionCookies[name]; !ok {
		return false
	}
	return !knownSessionCookiesNamingNoFramework[name]
}

// knownSessionCookiesNamingNoFramework are the entries of knownSessionCookies whose name states a
// ROLE and not a MINTER. They stay in that list, because "this is a server-side session handle" is
// still the right reading of an opaque value inside one; what they do not get is a veto over a
// structural recogniser. The membership is not an opinion: it is the three entries whose own
// framework label in knownSessionCookies is generic or hedged.
var knownSessionCookiesNamingNoFramework = map[string]bool{
	"session":   true, // labelled "generic"
	"sid":       true, // labelled "generic"
	"sessionid": true, // labelled "Django or similar"
}

// stripCredentialScheme removes a "Bearer " style prefix so the structural parsers see the token.
//
// The declared prefix is tried first, then a single leading word followed by a space, which is
// what an operator who pasted a whole header value leaves behind.
func stripCredentialScheme(value, prefix string) string {
	v := strings.TrimSpace(value)
	if prefix != "" && strings.HasPrefix(v, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(v, prefix))
	}
	if i := strings.IndexByte(v, ' '); i > 0 && i <= 12 && reAuthScheme.MatchString(v[:i]) {
		return strings.TrimSpace(v[i+1:])
	}
	return v
}

// ---------------------------------------------------------------------------------------------
// JOSE: compact JWS (the thing everybody calls a JWT) and compact JWE
// ---------------------------------------------------------------------------------------------

// joseClaims is the subset of RFC 7519 and OIDC claims that speak to lifetime and identity.
//
// The numeric ones are json.Number because a NumericDate is "the number of seconds", and issuers
// do emit fractional ones; parsing those into int64 silently drops the token.
type joseClaims struct {
	Exp      json.Number `json:"exp"`
	Iat      json.Number `json:"iat"`
	Nbf      json.Number `json:"nbf"`
	AuthTime json.Number `json:"auth_time"`
	Iss      string      `json:"iss"`
	Sub      string      `json:"sub"`
	Jti      string      `json:"jti"`
	Scope    string      `json:"scope"`
	// ExpiresIn appears in some issuers' access tokens and in every OAuth token response.
	ExpiresIn json.Number `json:"expires_in"`
}

// numericDate turns a NumericDate into a time, tolerating a fractional value.
func numericDate(n json.Number) (time.Time, bool) {
	s := strings.TrimSpace(n.String())
	if s == "" {
		return time.Time{}, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), true
}

// profileAsJOSE handles both compact JOSE serialisations and reports whether it matched.
//
// THE SIGNATURE IS NOT VERIFIED AND MUST NOT BE. We hold no key; this is a freshness reading of
// our own credential, not an authorisation decision about somebody else's.
func profileAsJOSE(p *SessionTokenProfile, tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 && len(parts) != 5 {
		return false
	}
	header, err := decodeJOSESegment(parts[0])
	if err != nil {
		return false
	}
	var head struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
		Cty string `json:"cty"`
	}
	if json.Unmarshal(header, &head) != nil || head.Alg == "" {
		return false
	}
	// enc IS THE WITNESS THAT SEPARATES THE TWO SERIALISATIONS, and it is checked before anything
	// is recorded so a value that turns out not to be JOSE leaves no attribute behind.
	//
	// RFC 7516 section 4.1.2 makes enc REQUIRED in a JWE header; RFC 7515 gives a JWS no such
	// parameter at all. Counting segments alone called any five-part base64url value a JWE and
	// wrote the evidence sentence "alg=dir enc=, so this is a compact JWE", which states a kind on
	// a field nothing read. A five segment value with no enc falls through to the recognisers
	// below and is reported as whatever it actually is.
	if len(parts) == 5 && strings.TrimSpace(head.Enc) == "" {
		return false
	}
	setIf(p.Attributes, "alg", head.Alg)
	setIf(p.Attributes, "typ", head.Typ)
	setIf(p.Attributes, "kid", head.Kid)
	setIf(p.Attributes, "cty", head.Cty)

	if len(parts) == 5 {
		// A JWE. The header is all we get; the claims are ciphertext.
		p.Kind = CredentialKindJWE
		setIf(p.Attributes, "enc", head.Enc)
		p.KindEvidence = fmt.Sprintf("five base64url segments with a JOSE header alg=%s enc=%s, so this is a compact JWE", head.Alg, head.Enc)
		p.Warnings = append(p.Warnings,
			"the claims of a JWE are encrypted to the server's key, so the expiry cannot be read from the token; only observation or probing can establish it")
		// MEASURED ON THE LIVE ESTATE: the Cognito refreshToken cookie carries
		// alg=RSA-OAEP enc=A256GCM cty=JWT, so its plaintext is itself a JWT with its own exp.
		// That exp is unreadable without the pool key, and saying which fact is missing is
		// different from saying nothing is known.
		if head.Cty != "" && strings.Contains(strings.ToLower(head.Cty), "jwt") {
			p.Warnings = append(p.Warnings,
				"cty declares a nested JWT, so the plaintext inside this JWE is itself a token with its own claims; they are encrypted to the issuer key and cannot be read here")
		}
		return true
	}

	p.Kind = CredentialKindJWT
	p.KindEvidence = fmt.Sprintf("three base64url segments with a JOSE header alg=%s, so this is a compact JWS", head.Alg)
	if strings.TrimSpace(head.Enc) != "" {
		p.Warnings = append(p.Warnings,
			"the header carries an enc parameter, which RFC 7515 gives no JWS: either this token was built by something that does not follow the spec, or the segment count is not what it appears to be")
	}
	if strings.EqualFold(head.Alg, "none") {
		p.Warnings = append(p.Warnings,
			"alg is none, so this token is unsigned: anything in it, the expiry included, is attacker-controllable and is worth a finding in its own right")
	}
	if head.Cty != "" && strings.Contains(strings.ToLower(head.Cty), "jwt") {
		p.Warnings = append(p.Warnings, "cty declares a nested JWT, so the payload is another token rather than a claim set")
	}

	payload, err := decodeJOSESegment(parts[1])
	if err != nil {
		p.Warnings = append(p.Warnings, "the payload segment is not valid base64url, so no claim could be read")
		return true
	}
	var claims joseClaims
	if json.Unmarshal(payload, &claims) != nil {
		p.Warnings = append(p.Warnings,
			"the payload is not JSON, which a nested or binary JWS is allowed to be; no claim could be read")
		return true
	}
	applyJOSEClaims(p, payload, claims)
	return true
}

// decodeJOSESegment decodes a base64url segment with or without padding. Issuers are supposed to
// omit the padding and some do not.
func decodeJOSESegment(seg string) ([]byte, error) {
	seg = strings.TrimRight(seg, "=")
	return base64.RawURLEncoding.DecodeString(seg)
}

// applyJOSEClaims fills the lifetime fields from a decoded claim set.
//
// THE TTL LADDER, AND WHY IT IS NOT JUST exp MINUS iat.
//
// The obvious formula is exp - iat, and on the live target in front of us it produces NOTHING: the
// tokens carry aud, c, email, exp, g, iss, jti, nbf, sub, uid, and there is no iat at all. Fifty
// one distinct tokens, not one iat among them. exp - nbf gives 900 on 29 of them and 901 on 22,
// which matches the fifteen minute lifetime measured independently from capture timestamps.
//
// So the ladder is exp-iat, then exp-nbf, then exp-auth_time, and the evidence string always names
// which rung answered. nbf is a WEAKER rung and is labelled as one: an issuer that backdates nbf
// for clock skew makes exp-nbf an over-estimate by the skew allowance, so a TTL from nbf is an
// upper bound on the real one.
//
// EVERY CLAIM GOES OUT AS THE TOKEN CARRIES IT, name and value both. RFC 7519 4.1.2 defines sub as
// the principal the token is about, and who a captured token is for is the finding: an IDOR is
// proved by showing whose record came back, and a token minted for the wrong account is proved by
// reading the account out of the token. The same goes for email, for a tenant id and for whatever
// else the issuer put in there; the claim set is the evidence and it is served whole.
func applyJOSEClaims(p *SessionTokenProfile, payload []byte, claims joseClaims) {
	for name, value := range claimSet(payload) {
		setIf(p.Attributes, name, value)
	}
	setIf(p.Attributes, "iss", claims.Iss)
	setIf(p.Attributes, "sub", claims.Sub)
	setIf(p.Attributes, "jti", claims.Jti)
	setIf(p.Attributes, "scope", claims.Scope)

	exp, hasExp := numericDate(claims.Exp)
	iat, hasIat := numericDate(claims.Iat)
	nbf, hasNbf := numericDate(claims.Nbf)
	auth, hasAuth := numericDate(claims.AuthTime)

	if hasIat {
		p.IssuedAt, p.IssuedAtKnown, p.IssuedAtSource = iat, true, IssuedAtClaimIat
	} else if hasNbf {
		p.IssuedAt, p.IssuedAtKnown, p.IssuedAtSource = nbf, true, IssuedAtClaimNbf
	}

	if hasExp {
		p.ExpiresAt, p.ExpiryKnown = exp, true
		p.ExpiryProvenance = ProvParsed
		p.ExpiryStyle = ExpiryStyleAbsolute
		p.ExpiryEvidence = "the exp claim of the token"
	}

	switch {
	case hasExp && hasIat:
		p.TTL, p.TTLKnown = exp.Sub(iat), true
		p.TTLProvenance = ProvParsed
		p.TTLEvidence = "exp minus iat, both claims of the token"
	case hasExp && hasNbf:
		p.TTL, p.TTLKnown = exp.Sub(nbf), true
		p.TTLProvenance = ProvParsed
		p.TTLEvidence = "exp minus nbf; the token carries no iat, and nbf is an upper bound on the lifetime because an issuer may backdate it for clock skew"
	case hasExp && hasAuth:
		p.TTL, p.TTLKnown = exp.Sub(auth), true
		p.TTLProvenance = ProvParsed
		p.TTLEvidence = "exp minus auth_time; the token carries neither iat nor nbf, and auth_time is when the user authenticated rather than when this token was minted"
	case hasExp:
		p.Warnings = append(p.Warnings,
			"the token has an exp but no iat, nbf or auth_time, so its expiry is known and its lifetime is not")
	default:
		p.Warnings = append(p.Warnings,
			"the token carries no exp claim, so it does not expire on its own terms and its lifetime is whatever the server enforces")
	}

	// expires_in inside a token body is rare but unambiguous when present.
	if !p.TTLKnown {
		if s := strings.TrimSpace(claims.ExpiresIn.String()); s != "" {
			if secs, err := strconv.ParseInt(s, 10, 64); err == nil && secs > 0 {
				p.TTL, p.TTLKnown = time.Duration(secs)*time.Second, true
				p.TTLProvenance = ProvParsed
				p.TTLEvidence = "the expires_in claim of the token"
				applyExpiryImpliedByLifetime(p, "the expires_in claim")
			}
		}
	}
}

// capturedAtPhrase says when a captured response was received, and says so differently when
// nothing recorded it.
//
// A ZERO TIMESTAMP IS NOT A TIMESTAMP. Formatted anyway it renders as 0001-01-01T00:00:00Z, and
// the evidence sentence then states a capture time nothing read, in the year one, inside the
// string an operator is meant to audit the lifetime by. It is the same defect as a TTL of zero
// standing in for an unmeasured one, in the one field whose whole job is to say what was read.
func capturedAtPhrase(at time.Time) string {
	if at.IsZero() {
		return "whose capture time is not recorded"
	}
	return "captured at " + at.UTC().Format(time.RFC3339)
}

// applyExpiryImpliedByLifetime records the DEATH implied by a lifetime that was just read, when
// something already read when the credential was minted.
//
// LEAVING IT AS A LIFETIME ALONE IS NOT NEUTRAL. The card's governing choice orders the credentials
// a scan sends by their REMAINING life, and reaches measured LIFETIME only when nothing going out
// has an issue time at all, so a credential with a parsed lifetime and no expiry cannot win that
// ordering however short it is. Measured on 2026-09-21 with two credentials the same scan sends,
// an 11m one carrying exp and iat and a 1m one carrying expires_in and iat: the tile named the
// 11m one and its number was the 11m one's. The two facts stay separate fields; what this does is
// stop the engine throwing away one of them when it holds both halves.
//
// IT COUNTS ONLY FROM A SOURCE THAT IS THE MINT. nbf is not-before and an issuer may backdate it
// for clock skew, so counting from one would put the death later than the issuer meant, and a
// death later than the truth is the direction that tells an operator a dead session is alive.
func applyExpiryImpliedByLifetime(p *SessionTokenProfile, what string) {
	if p.ExpiryKnown || !p.TTLKnown || !p.IssuedAtKnown || !p.IssuedAtSource.IsMintTime() {
		return
	}
	p.ExpiresAt, p.ExpiryKnown = p.IssuedAt.Add(p.TTL), true
	p.ExpiryProvenance = ProvParsed
	p.ExpiryStyle = ExpiryStyleAbsolute
	p.ExpiryEvidence = fmt.Sprintf("%s counted from the %s, which is when this credential was minted",
		what, p.IssuedAtSource)
}

// claimSet reads every claim of a payload, name to value.
//
// A JSON STRING IS UNQUOTED AND EVERYTHING ELSE IS KEPT AS IT WAS WRITTEN. An operator reading
// email wants alice@example.test and not "alice@example.test"; an operator reading exp or a nested
// object wants the bytes the issuer signed, and re-rendering those would be this layer deciding
// what the token said.
//
// IT DECODES RATHER THAN UNMARSHALS so a PASETO payload, whose signature bytes follow the JSON in
// the same buffer, reads exactly as a JWS payload does. A claim set that yields its values on one
// token format and not on another is a gap nobody would find until the target used the other one.
func claimSet(payload []byte) map[string]string {
	var m map[string]json.RawMessage
	if json.NewDecoder(strings.NewReader(string(payload))).Decode(&m) != nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, raw := range m {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			out[k] = s
			continue
		}
		out[k] = string(raw)
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// PASETO
// ---------------------------------------------------------------------------------------------

var rePASETO = regexp.MustCompile(`^v[1-4]\.(local|public)\.`)

// profileAsPASETO handles v1 to v4, local and public.
//
// A public token's payload segment is base64url of the JSON claim set FOLLOWED BY the signature
// bytes, so decoding and then taking the first complete JSON value is the correct read; a local
// token's payload is ciphertext and there is nothing to read. PASETO's exp, iat and nbf are
// RFC3339 STRINGS rather than unix seconds, which is the mistake a JWT-shaped parser makes here.
func profileAsPASETO(p *SessionTokenProfile, tok string) bool {
	if !rePASETO.MatchString(tok) {
		return false
	}
	parts := strings.Split(tok, ".")
	version, purpose := parts[0], parts[1]
	p.Kind = CredentialKindPASETO
	p.KindEvidence = fmt.Sprintf("a %s.%s PASETO", version, purpose)
	setIf(p.Attributes, "paseto_version", version)
	setIf(p.Attributes, "paseto_purpose", purpose)

	if purpose == "local" {
		p.Warnings = append(p.Warnings,
			"a local PASETO is encrypted to the server's key, so its expiry cannot be read from the token; only observation or probing can establish it")
		return true
	}
	if len(parts) < 3 {
		p.Warnings = append(p.Warnings, "the PASETO has no payload segment")
		return true
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[2], "="))
	if err != nil {
		p.Warnings = append(p.Warnings, "the PASETO payload is not valid base64url")
		return true
	}
	var claims struct {
		Exp string `json:"exp"`
		Iat string `json:"iat"`
		Nbf string `json:"nbf"`
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Jti string `json:"jti"`
	}
	// A json.Decoder stops at the end of the first complete value, which is exactly what is needed
	// when the signature bytes follow the JSON in the same buffer.
	if json.NewDecoder(strings.NewReader(string(raw))).Decode(&claims) != nil {
		p.Warnings = append(p.Warnings, "the PASETO payload did not contain a readable JSON claim set")
		return true
	}
	for name, value := range claimSet(raw) {
		setIf(p.Attributes, name, value)
	}
	setIf(p.Attributes, "iss", claims.Iss)
	setIf(p.Attributes, "sub", claims.Sub)
	setIf(p.Attributes, "jti", claims.Jti)

	exp, hasExp := parseRFC3339(claims.Exp)
	iat, hasIat := parseRFC3339(claims.Iat)
	nbf, hasNbf := parseRFC3339(claims.Nbf)
	if hasIat {
		p.IssuedAt, p.IssuedAtKnown, p.IssuedAtSource = iat, true, IssuedAtClaimIat
	} else if hasNbf {
		p.IssuedAt, p.IssuedAtKnown, p.IssuedAtSource = nbf, true, IssuedAtClaimNbf
	}
	if hasExp {
		p.ExpiresAt, p.ExpiryKnown = exp, true
		p.ExpiryProvenance = ProvParsed
		p.ExpiryStyle = ExpiryStyleAbsolute
		p.ExpiryEvidence = "the exp claim of the PASETO, an RFC3339 timestamp"
	}
	switch {
	case hasExp && hasIat:
		p.TTL, p.TTLKnown = exp.Sub(iat), true
		p.TTLProvenance = ProvParsed
		p.TTLEvidence = "exp minus iat, both RFC3339 claims of the PASETO"
	case hasExp && hasNbf:
		p.TTL, p.TTLKnown = exp.Sub(nbf), true
		p.TTLProvenance = ProvParsed
		p.TTLEvidence = "exp minus nbf; the PASETO carries no iat"
	case !hasExp:
		p.Warnings = append(p.Warnings, "the PASETO carries no exp claim, so it does not expire on its own terms")
	}
	return true
}

func parseRFC3339(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// ---------------------------------------------------------------------------------------------
// Branca
// ---------------------------------------------------------------------------------------------

const brancaAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// reBase62 is the SHAPE gate. It requires a canonical encoding: base62 by big integer never
// produces a leading zero digit, and a Branca token's 0xBA version byte puts its integer far above
// the range where one could appear, so a leading "0" is by itself proof the string did not come
// out of a Branca encoder.
var reBase62 = regexp.MustCompile(`^[1-9A-Za-z][0-9A-Za-z]{59,}$`)

// brancaIssuedFloor is the earliest issue time a Branca token can honestly carry. The format was
// published in 2017, so a token claiming to have been minted before it existed is not one.
var brancaIssuedFloor = time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)

// brancaClockSkew is how far AHEAD of the profiling clock an issue time may sit. A credential
// cannot have been issued in the future; a day of slack covers an issuer whose clock is wrong and
// nothing more.
const brancaClockSkew = 24 * time.Hour

// profileAsBranca reads the one thing a Branca token discloses.
//
// The binary layout is version(0xBA) || timestamp(4 bytes big endian) || nonce(24) || ciphertext
// || tag(16), base62 encoded. The timestamp is the ISSUE time and it is in CLEARTEXT. The lifetime
// is not in the token at all: Branca's TTL is a parameter the verifier passes when it decodes. So
// this is the clean example of a credential whose issue time is parsed and whose expiry is
// genuinely unknowable from the value, and reporting it any other way would be an invention.
//
// ---------------------------------------------------------------------------------------------
// WHY THIS RECOGNISER NEEDS A SECOND WITNESS, MEASURED
// ---------------------------------------------------------------------------------------------
//
// One version byte is a 1-in-256 witness, and a session identifier is random characters. Measured
// over 200000 invented opaque session ids per shape against the version byte alone:
//
//	alnum len 86     775/200000  0.3875%
//	alnum len 128    175/200000  0.0875%
//	alnum len 64      21/200000  0.0105%
//	upper+digit 64    97/200000  0.0485%
//	upper+digit 128  556/200000  0.2780%
//	lower hex 64       0/200000  0
//
// Every one of those hits reported kind=branca, the sentence saying so, and an IssuedAt DECODED
// OUT OF FOUR RANDOM BYTES: 2067-10-17, 1980-03-24, 2104-03-25, 1995-06-04 were all produced by
// the sweep. That date is persisted to session_tokens.issued_at and rendered to the operator as
// something the credential said, which makes this the worst class of defect in the feature: a
// stated fact that nothing read.
//
// The timestamp is therefore the second witness, held to a window that is a property of the FORMAT
// and not of any particular application: not before Branca existed, and not in the future. Four
// random bytes land in that window about 7% of the time, so the residual rate on the worst shape
// is measured at 0.0275% rather than 0.3875%, a fourteenfold reduction; the sweep test in this
// package holds the whole table to a ceiling and prints what it measured. It is not zero, and
// claiming zero would be the same kind of lie: a 60-plus character base62 string that decodes to
// a 0xBA version byte, at least 45 bytes and a plausible issue time is as far as the format lets
// anyone go without the key.
func profileAsBranca(p *SessionTokenProfile, tok string) bool {
	if !reBase62.MatchString(tok) {
		return false
	}
	raw, ok := decodeBase62(tok)
	if !ok || len(raw) < 45 || raw[0] != 0xBA {
		return false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint32(raw[1:5])), 0).UTC()
	if !brancaIssueTimeIsPlausible(issued, p.ProfiledAt) {
		// NOT a Branca token: fall through to the opaque path, where the value is reported as the
		// unstructured thing it is and no issue time is claimed at all.
		return false
	}
	p.Kind = CredentialKindBranca
	p.KindEvidence = fmt.Sprintf(
		"base62 decoding to a 0xBA version byte with a 29 byte cleartext header and an issue time of %s, which is after the format existed and not in the future, so this is a Branca token",
		issued.Format(time.RFC3339))
	p.IssuedAt, p.IssuedAtKnown, p.IssuedAtSource = issued, true, IssuedAtBrancaTimestamp
	p.Attributes["issued_at"] = issued.Format(time.RFC3339)
	p.Warnings = append(p.Warnings,
		"a Branca token carries its issue time in cleartext but not its lifetime: the TTL is a parameter of the verifier, so it can only be established by observation or probing")
	return true
}

// brancaIssueTimeIsPlausible is the second witness. now is the profiling clock; a zero one falls
// back to the wall clock so a caller that forgot to pass a time still gets the check.
func brancaIssueTimeIsPlausible(issued, now time.Time) bool {
	if issued.Before(brancaIssuedFloor) {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !issued.After(now.Add(brancaClockSkew))
}

// decodeBase62 decodes the Branca alphabet. A leading zero digit encodes a leading zero byte, and
// the 0xBA version byte means a valid token never has one, so no leading-zero handling is needed
// beyond refusing what does not start with 0xBA.
func decodeBase62(s string) ([]byte, bool) {
	n := new(big.Int)
	base := big.NewInt(62)
	for _, r := range s {
		idx := strings.IndexRune(brancaAlphabet, r)
		if idx < 0 {
			return nil, false
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}
	return n.Bytes(), true
}

// ---------------------------------------------------------------------------------------------
// SAML
// ---------------------------------------------------------------------------------------------

var (
	reSAMLNotOnOrAfter        = regexp.MustCompile(`<[^>]*\bConditions\b[^>]*\bNotOnOrAfter="([^"]+)"`)
	reSAMLNotBefore           = regexp.MustCompile(`<[^>]*\bConditions\b[^>]*\bNotBefore="([^"]+)"`)
	reSAMLSessionNotOnOrAfter = regexp.MustCompile(`\bSessionNotOnOrAfter="([^"]+)"`)
	reSAMLIssuer              = regexp.MustCompile(`<[^>]*Issuer[^>]*>([^<]+)</`)
)

// profileAsSAML reads an assertion's lifetime.
//
// Two lifetimes live in a SAML response and they answer different questions. Conditions
// NotBefore/NotOnOrAfter bound the ASSERTION, usually a few minutes, and that is the window in
// which it may be presented. AuthnStatement SessionNotOnOrAfter bounds the SESSION the assertion
// establishes, usually hours. A scan is carrying the session, so both are recorded and the
// session one, when present, is the expiry that matters.
func profileAsSAML(p *SessionTokenProfile, tok string) bool {
	xml, ok := decodeSAMLBlob(tok)
	if !ok {
		return false
	}
	p.Kind = CredentialKindSAML
	p.KindEvidence = "base64 decoding to XML carrying a SAML Assertion"
	if m := reSAMLIssuer.FindStringSubmatch(xml); len(m) == 2 {
		setIf(p.Attributes, "iss", strings.TrimSpace(m[1]))
	}

	nb, hasNB := parseRFC3339(firstSubmatch(reSAMLNotBefore, xml))
	na, hasNA := parseRFC3339(firstSubmatch(reSAMLNotOnOrAfter, xml))
	sess, hasSess := parseRFC3339(firstSubmatch(reSAMLSessionNotOnOrAfter, xml))

	if hasNB {
		p.IssuedAt, p.IssuedAtKnown, p.IssuedAtSource = nb, true, IssuedAtSAMLNotBefore
		p.Attributes["conditions_not_before"] = nb.Format(time.RFC3339)
	}
	if hasNA {
		p.Attributes["conditions_not_on_or_after"] = na.Format(time.RFC3339)
	}
	if hasSess {
		p.Attributes["session_not_on_or_after"] = sess.Format(time.RFC3339)
	}

	switch {
	case hasSess:
		p.ExpiresAt, p.ExpiryKnown = sess, true
		p.ExpiryProvenance = ProvParsed
		p.ExpiryStyle = ExpiryStyleAbsolute
		p.ExpiryEvidence = "AuthnStatement/@SessionNotOnOrAfter, which bounds the session rather than the assertion"
		if hasNB {
			p.TTL, p.TTLKnown = sess.Sub(nb), true
			p.TTLProvenance = ProvParsed
			p.TTLEvidence = "SessionNotOnOrAfter minus Conditions/@NotBefore"
		}
	case hasNA:
		p.ExpiresAt, p.ExpiryKnown = na, true
		p.ExpiryProvenance = ProvParsed
		p.ExpiryStyle = ExpiryStyleAbsolute
		p.ExpiryEvidence = "Conditions/@NotOnOrAfter, which bounds the ASSERTION and not necessarily the session it established"
		if hasNB {
			p.TTL, p.TTLKnown = na.Sub(nb), true
			p.TTLProvenance = ProvParsed
			p.TTLEvidence = "Conditions/@NotOnOrAfter minus Conditions/@NotBefore, the assertion window"
		}
		p.Warnings = append(p.Warnings,
			"the assertion has no SessionNotOnOrAfter, so the session lifetime it established is not stated and only the assertion window was read")
	default:
		p.Warnings = append(p.Warnings, "no Conditions or AuthnStatement lifetime was found in the assertion")
	}
	return true
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) == 2 {
		return m[1]
	}
	return ""
}

// decodeSAMLBlob handles the two encodings a SAML assertion arrives in: plain base64 (POST
// binding) and deflate-then-base64 (redirect binding).
func decodeSAMLBlob(tok string) (string, bool) {
	if strings.Contains(tok, "<") && strings.Contains(tok, "Assertion") {
		return tok, true
	}
	if len(tok) < 64 {
		return "", false
	}
	// The token is tried AS GIVEN before the percent-decoded form, and not the other way round.
	// url.QueryUnescape turns a "+" into a space, and standard base64 is full of them, so decoding
	// first destroys every assertion that was not actually URL encoded.
	candidates := []string{tok}
	if unescaped, err := url.QueryUnescape(tok); err == nil && unescaped != tok {
		candidates = append(candidates, unescaped)
	}
	for _, candidate := range candidates {
		raw, err := base64.StdEncoding.DecodeString(candidate)
		if err != nil {
			if raw, err = base64.RawStdEncoding.DecodeString(candidate); err != nil {
				continue
			}
		}
		if isSAMLXML(string(raw)) {
			return string(raw), true
		}
		// The redirect binding deflates before it base64s, so an assertion that did not look like
		// XML may still be one under a raw DEFLATE stream.
		inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(strings.NewReader(string(raw))), 1<<20))
		if err == nil && isSAMLXML(string(inflated)) {
			return string(inflated), true
		}
	}
	return "", false
}

func isSAMLXML(s string) bool {
	return strings.Contains(s, "Assertion") &&
		(strings.Contains(s, "urn:oasis:names:tc:SAML") || strings.Contains(s, "saml"))
}

// ---------------------------------------------------------------------------------------------
// Opaque values: the hard case, and the common one
// ---------------------------------------------------------------------------------------------

// knownSessionCookies are cookie names that are, by the framework that sets them, a server-side
// session handle with no client-readable expiry. Recognising them is worth doing because it turns
// "we could not parse this" into "there is nothing to parse, by design", which is a different
// thing to tell an operator and points them straight at observation or probing.
var knownSessionCookies = map[string]string{
	"phpsessid":         "PHP",
	"jsessionid":        "Java servlet container",
	"asp.net_sessionid": "ASP.NET",
	"connect.sid":       "Express connect/cookie-session",
	"laravel_session":   "Laravel",
	"ci_session":        "CodeIgniter",
	"sessionid":         "Django or similar",
	"session":           "generic",
	"_session_id":       "Rails",
	"cfid":              "ColdFusion",
	"cftoken":           "ColdFusion",
	"sid":               "generic",
	"ssesssionid":       "Drupal",
}

// apiKeyFormat is one published key format: the prefix that names it and the SHAPE the rest of it
// has to have.
//
// THE SHAPE IS THE SECOND WITNESS. A four character prefix is not evidence on its own. Measured
// over 200000 invented opaque session ids per shape, prefix matching alone reported one
// upper-plus-digits value of 128 characters as an API key; the only prefixes reachable in that
// alphabet are the AWS ones, because "AKIA" and "ASIA" are four characters that random uppercase
// produces. The consequence is milder than the Branca one, since no lifetime is invented, but it
// is still a kind stated about a value nothing read: an AWS access key id is twenty characters,
// so a ninety character value beginning AKIA is not one and saying so costs nothing.
type apiKeyFormat struct {
	prefix string
	what   string
	// shape is the whole published form, anchored. Set it only where the format is documented
	// exactly; a wrong shape here is a false negative, which is worse than a loose one.
	shape *regexp.Regexp
	// minBody is the least key material after the prefix, for the formats whose length is not
	// fixed. A bare prefix with nothing after it is not a key.
	minBody int
	// body is the alphabet THIS format draws its key material from, where the vendor publishes a
	// narrower one than reAPIKeyBody. A random base64url value carries hyphens and underscores
	// that a base62 key format never does, and that is what turned one invented 43 character
	// value into a GitHub server token in the round 12 sweep.
	body *regexp.Regexp
}

// reBase62Body and reHexBody are the alphabets the formats below actually use.
var (
	reBase62Body = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	reHexBody    = regexp.MustCompile(`^[a-f0-9]+$`)
	reDashBody   = regexp.MustCompile(`^[A-Za-z0-9\-]+$`)
	reTokenBody  = regexp.MustCompile(`^[A-Za-z0-9_\-]+$`)
)

// apiKeyFormats are published, unambiguous key formats, in a slice rather than a map so the order
// of matching is deterministic and a longer prefix can be tried before a shorter one.
//
// Matching one tells us the KIND. It deliberately does NOT set a lifetime: "API keys usually do
// not expire" is an assumption, and an assumption presented as a measurement is the exact defect
// this file exists to prevent.
var apiKeyFormats = []apiKeyFormat{
	// AWS publishes the length: the access key id is twenty characters of uppercase and digits.
	{prefix: "AKIA", what: "AWS access key id", shape: regexp.MustCompile(`^AKIA[A-Z0-9]{16}$`)},
	{prefix: "ASIA", what: "AWS temporary access key id", shape: regexp.MustCompile(`^ASIA[A-Z0-9]{16}$`)},
	// A Google API key is thirty nine characters.
	{prefix: "AIza", what: "Google API key", shape: regexp.MustCompile(`^AIza[0-9A-Za-z_\-]{35}$`)},
	// GitHub publishes the whole form: the prefix plus thirty six base62 characters, forty
	// characters in all. minBody 20 and the loose alphabet matched a 43 character base64url value
	// in the round 12 sweep, which is a kind stated about a value nothing read.
	{prefix: "github_pat_", what: "GitHub fine-grained personal access token", minBody: 50, body: reTokenBody},
	{prefix: "ghp_", what: "GitHub personal access token", shape: regexp.MustCompile(`^ghp_[A-Za-z0-9]{36}$`)},
	{prefix: "gho_", what: "GitHub OAuth token", shape: regexp.MustCompile(`^gho_[A-Za-z0-9]{36}$`)},
	{prefix: "ghs_", what: "GitHub server token", shape: regexp.MustCompile(`^ghs_[A-Za-z0-9]{36}$`)},
	{prefix: "sk_live_", what: "Stripe live secret key", minBody: 16, body: reBase62Body},
	{prefix: "sk_test_", what: "Stripe test secret key", minBody: 16, body: reBase62Body},
	{prefix: "pk_live_", what: "Stripe live publishable key", minBody: 16, body: reBase62Body},
	{prefix: "rk_live_", what: "Stripe restricted key", minBody: 16, body: reBase62Body},
	{prefix: "xoxb-", what: "Slack bot token", minBody: 10, body: reDashBody},
	{prefix: "xoxp-", what: "Slack user token", minBody: 10, body: reDashBody},
	{prefix: "xoxa-", what: "Slack app token", minBody: 10, body: reDashBody},
	{prefix: "SG.", what: "SendGrid API key", shape: regexp.MustCompile(`^SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}$`)},
	{prefix: "glpat-", what: "GitLab personal access token", minBody: 16, body: reTokenBody},
	{prefix: "npm_", what: "npm access token", shape: regexp.MustCompile(`^npm_[A-Za-z0-9]{36}$`)},
	{prefix: "shpat_", what: "Shopify access token", minBody: 32, body: reHexBody},
	{prefix: "dop_v1_", what: "DigitalOcean personal access token", minBody: 32, body: reHexBody},
}

// reAPIKeyBody is the alphabet key material is drawn from. It exists so a sentence that merely
// begins with a prefix, or a URL, is not read as a key.
var reAPIKeyBody = regexp.MustCompile(`^[A-Za-z0-9._~+/=\-]+$`)

// matches reports whether a value is this format, prefix and shape both.
func (f apiKeyFormat) matches(tok string) bool {
	if !strings.HasPrefix(tok, f.prefix) {
		return false
	}
	if f.shape != nil {
		return f.shape.MatchString(tok)
	}
	body := tok[len(f.prefix):]
	alphabet := f.body
	if alphabet == nil {
		alphabet = reAPIKeyBody
	}
	return len(body) >= f.minBody && alphabet.MatchString(body)
}

// ---------------------------------------------------------------------------------------------
// A NAME THAT SAYS WHO YOU ARE IS NOT A NAME THAT PROVES IT
// ---------------------------------------------------------------------------------------------
//
// MEASURED ON THE LIVE ESTATE, 2026-09-20. The Cognito family writes five things into the jar of
// app.staging-v2.tradetalk.us, and only three of them are credentials:
//
//	CognitoIdentityServiceProvider.<clientid>.<sub>.accessToken    a compact JWS, alg RS256
//	CognitoIdentityServiceProvider.<clientid>.<sub>.idToken        a compact JWS, alg RS256
//	CognitoIdentityServiceProvider.<clientid>.<sub>.refreshToken   a compact JWE, RSA-OAEP A256GCM
//	CognitoIdentityServiceProvider.<clientid>.<sub>.clockDrift     an integer
//	CognitoIdentityServiceProvider.<clientid>.LastAuthUser         the user id, 36 characters
//
// LastAuthUser is how the SDK remembers which of several signed-in users the other four belong to.
// It proves nothing to anybody. This engine profiled it as opaque_session_id, because the last
// branch of profileAsOpaque reads every unrecognised cookie as a session handle, and the
// Authentication card then made it the GOVERNING credential of the whole Session TTL tile: a
// credential with no lifetime, standing in for a session whose real tokens had already expired.
//
// THE RULE IS NOT A COGNITO RULE. The same shape is everywhere: ai_user beside ai_session,
// X-User-Id beside Authorization, a Firebase authUser pointer beside its token. Two general
// readings do the work and neither needs to know a vendor:
//
//  1. READ THE LEAF. A namespaced name is a path, and the last segment is the role. Splitting on
//     the separators Amplify, MSAL and Firebase all use means the engine reads accessToken and
//     LastAuthUser rather than one 100 character string it can say nothing about.
//  2. READ THE HEAD NOUN. English compounds put the head last, so userToken is a token and
//     LastAuthUser is a user. An id, a name or a handle is a qualifier and takes the word before
//     it, so X-User-Id is a user id and sessionid is a session id.
//
// AND IT LOSES TO PROOF. Any unambiguous credential word anywhere in the leaf wins outright, so
// user_session, sessionid and refreshToken are never read as pointers. The direction is
// deliberate: wrongly calling a real credential a pointer would drop it from the wire, which is
// the false clean this layer exists to close.

// credentialPrincipalWords name a SUBJECT. A value under one of these says who, and a who is not
// a proof.
var credentialPrincipalWords = map[string]bool{
	"user": true, "username": true, "userid": true, "uid": true, "login": true,
	"account": true, "subject": true, "sub": true, "principal": true, "identity": true,
	"email": true, "profile": true, "nickname": true, "displayname": true, "owner": true,
	"actor": true, "member": true, "persona": true,
}

// credentialPrincipalQualifiers are head nouns that name no subject by themselves and take the
// word before them. "id" is the one that matters: user id, account id, session id.
var credentialPrincipalQualifiers = map[string]bool{
	"id": true, "name": true, "handle": true, "guid": true, "uuid": true,
}

// credentialAmbiguousRoleWords are the short words that mean a session to some vendors and nothing
// to others. They are enough for the slot layer, whose safe direction is to refuse to perturb, and
// they are NOT enough on their own to call a value a proof of authentication. See
// triageWireCookieVerdict, which is the other half of this split.
var credentialAmbiguousRoleWords = map[string]bool{
	"sess": true, "sid": true, "auth": true, "token": true,
}

// credentialNameLeaf reads the last segment of a namespaced carrier name.
//
// The separators are the ones the three big auth SDKs actually use: Amplify and MSAL write dots,
// Firebase writes colons. A name with no separator is its own leaf. A trailing segment with no
// letter in it (a pool id, an index) is skipped, because it names no role.
func credentialNameLeaf(name string) string {
	name = strings.TrimSpace(name)
	segments := strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == ':' })
	hasLetter := func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }
	for i := len(segments) - 1; i >= 0; i-- {
		if strings.IndexFunc(segments[i], hasLetter) >= 0 {
			return segments[i]
		}
	}
	return name
}

// credentialNameClaimsProofOutright reports an UNAMBIGUOUS credential word in the name: one of the
// compound forms, or a whole word that is nobody's idea of a subject. It reuses the slot layer's
// own vocabulary so the two halves cannot drift apart on what the words are; what differs is which
// of them is allowed to decide.
func credentialNameClaimsProofOutright(name string) bool {
	compact := triageCompactName(name)
	for _, form := range triageCredentialCompactForms {
		if strings.Contains(compact, form) {
			return true
		}
	}
	for _, tok := range triageNameTokens(name) {
		if triageCredentialWholeWords[tok] && !credentialAmbiguousRoleWords[tok] {
			return true
		}
	}
	return false
}

// credentialNameNamesAPrincipal reports that this carrier holds a pointer at a subject rather than
// a proof of one, and says which word decided it.
func credentialNameNamesAPrincipal(name string) (string, bool) {
	leaf := credentialNameLeaf(name)
	if leaf == "" {
		return "", false
	}
	if credentialNameClaimsProofOutright(leaf) {
		return "", false
	}
	tokens := triageNameTokens(leaf)
	if len(tokens) == 0 {
		return "", false
	}
	head := tokens[len(tokens)-1]
	if credentialPrincipalQualifiers[head] {
		if len(tokens) >= 2 && credentialPrincipalWords[tokens[len(tokens)-2]] {
			return tokens[len(tokens)-2] + " " + head, true
		}
		return "", false
	}
	if credentialPrincipalWords[head] {
		return head, true
	}
	return "", false
}

// ---------------------------------------------------------------------------------------------
// WHICH KIND OF CREDENTIAL THE NAME CLAIMS, WHICH IS NOT THE SAME QUESTION AS WHETHER IT CLAIMS ONE
// ---------------------------------------------------------------------------------------------

// credentialLongTermAuthenticatorWords name a secret that ESTABLISHES a session rather than a
// handle that proves an established one, with what to say about each beside it.
//
// THE WIRE LAYER NEEDS THIS SPLIT AND THE SLOT LAYER DOES NOT. triageCredentialWholeWords asks
// "must a probe leave this alone?", and a stored password must be left alone, so "password"
// belongs there. triageWireCookieVerdict asks a different question: would substituting this onto
// a probe teach the run anything about how the application under test handles a SESSION. A
// password, a device secret or a one-time code answers no, and putting one on the wire discloses
// a long-lived secret for nothing in return.
//
// MEASURED ON THE LIVE ESTATE, on its captured jars rather than on a request. Amplify writes a
// Cognito DEVICE RECORD beside the session, under the same namespace as the tokens: deviceKey,
// deviceGroupKey and randomPasswordKey. The first two were held only by accident, because the
// slot vocabulary never called them candidates at all; the third rode every probe, because
// "password" is a credential word and nothing here asked WHICH KIND of credential it names. Those
// three are the device SRP secret an Amplify client presents to skip a second factor. Two facts
// separate them from the session and both were read in SQL over 4,011 captured jars on
// app.staging-v2.tradetalk.us: they are present in 43 captures whose jar carries no session token
// at all, where accessToken, idToken and refreshToken are present in exactly zero of those; and
// the jar holds them for TWO distinct Cognito subjects, so one probe went out carrying two
// people's device secrets.
//
// IT IS A ROLE VOCABULARY AND NOT A LIST OF COGNITO LEAF NAMES, so an SDK nobody has heard of
// that stores a device password under its own name is read the same way. A DECLINE ON ONE OF
// THESE CAN BE WRONG in the dangerous direction, the same as the telemetry words, so every one of
// them is reported by name with the word that decided it.
var credentialLongTermAuthenticatorWords = map[string]string{
	"password":   "a stored password, which establishes a session rather than proving one",
	"passwd":     "a stored password, which establishes a session rather than proving one",
	"passphrase": "a stored passphrase, which establishes a session rather than proving one",
	"device":     "a device secret, which outlives the session and is presented to skip a second factor",
	"machine":    "a remembered-machine secret, which outlives the session and is presented to skip a second factor",
	"otp":        "a one-time code, which establishes a session rather than proving one",
	"totp":       "a one-time code, which establishes a session rather than proving one",
	"mfa":        "a second-factor secret, which establishes a session rather than proving one",
	"recovery":   "a recovery secret, which establishes a session rather than proving one",
	"secret":     "a shared secret, which authenticates the client rather than proving a session",
}

// credentialNameNamesALongTermAuthenticator reports that this carrier holds a secret used to
// ESTABLISH a session rather than a handle that proves one, and says what it read.
//
// THE LEAF DECIDES, exactly as it does for a principal pointer, and for the same reason: on a
// namespaced SDK key the role word is the last segment and everything before it is the pool, the
// client id and whoever the record is for. Reading the whole name instead would refuse
// device_manager_session_token, whose leaf says session token and whose prefix says what the
// application is about.
//
// AND IT LOSES TO A JWS AND TO A PUBLISHED FRAMEWORK HANDLE. Those two are read before this one
// in triageWireCookieVerdict, so a value that is demonstrably a token, and a cookie name a
// framework publishes, are never refused on a word in the name.
func credentialNameNamesALongTermAuthenticator(name string) (string, string, bool) {
	leaf := credentialNameLeaf(name)
	if leaf == "" {
		return "", "", false
	}
	tok, why := "", ""
	for _, t := range triageNameTokens(leaf) {
		if w, ok := credentialLongTermAuthenticatorWords[t]; ok {
			tok, why = t, w
			break
		}
	}
	if tok == "" {
		return "", "", false
	}
	if credentialLeafClaimsASessionBeside(leaf) {
		return "", "", false
	}
	return tok, why, true
}

// credentialLeafClaimsASessionBeside reports a SESSION claim in this leaf standing beside whatever
// long-term word was found in it.
//
// IT IS THE SAME "AND IT LOSES TO PROOF" RULE credentialNameNamesAPrincipal APPLIES, with one
// difference that the measurement forced. A principal word and a proof word are different words,
// so that rule can ask credentialNameClaimsProofOutright directly. A long-term word IS a proof
// word: "password" is in triageCredentialWholeWords, which is why randomPasswordKey was read as
// proof in the first place, so asking the same question here would answer yes on the exact name
// this tier exists to hold. What is asked instead is whether anything BESIDE the long-term words
// claims a session.
//
// CAUGHT BY TestTheLongTermSecretRuleGeneralisesPastCognito BEFORE IT LEFT THIS FILE. Without it
// the tier held deviceIdToken, device_manager_session_token and password_grant_access_token, which
// is three real credentials lost in the direction this file calls dangerous.
//
// THE COMPOUND FORMS ARE READ ON THE WHOLE LEAF and the whole words on the leaf with the long-term
// words taken out. Reading the compounds on a leaf with a word cut out of it would splice two
// halves that were never adjacent: id_password_token would compact to "idtoken" and claim an id
// token nobody wrote. A compound that CARRIES a long-term word, clientsecret and sharedsecret and
// secretkey, is not a session claim either, and is skipped.
func credentialLeafClaimsASessionBeside(leaf string) bool {
	compact := triageCompactName(leaf)
	for _, form := range triageCredentialCompactForms {
		if !strings.Contains(compact, form) {
			continue
		}
		longTerm := false
		for word := range credentialLongTermAuthenticatorWords {
			if strings.Contains(form, word) {
				longTerm = true
				break
			}
		}
		if !longTerm {
			return true
		}
	}
	for _, t := range triageNameTokens(leaf) {
		if credentialLongTermAuthenticatorWords[t] != "" {
			continue
		}
		if triageCredentialWholeWords[t] && !credentialAmbiguousRoleWords[t] {
			return true
		}
	}
	return false
}

// credentialNamePrincipalSegment returns the segment of a namespaced carrier name that identifies
// WHOSE record it is, and "" when the name carries no such segment.
//
// TWO SHAPES ANSWER: an RFC 4122 UUID standing alone as a whole segment, which is what Amplify
// writes for a user pool subject, and a segment carrying an @, which is an address. The separators
// are the two credentialNameLeaf already splits on, so two readings of a name cannot disagree
// about where its segments are.
//
// IT RETURNS THE SEGMENT AND NOT A HASH OF IT. The caller groups a cookie jar by principal, and a
// grouping key works the same either way; what changes is what the sentence about a jar with two
// sign-ins can say, and naming the account the held-back credentials belong to is the point of
// writing that sentence at all.
func credentialNamePrincipalSegment(name string) string {
	for _, seg := range strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == ':' }) {
		if reCredentialNameUUID.MatchString(seg) || strings.Contains(seg, "@") {
			return seg
		}
	}
	return ""
}

// profileAsOpaque classifies a value with no readable structure, which is the case this engine is
// most often going to be in.
func profileAsOpaque(p *SessionTokenProfile, tok string, carrier CredentialCarrier) {
	name := strings.ToLower(strings.TrimSpace(carrier.Name))

	for _, format := range apiKeyFormats {
		if format.matches(tok) {
			p.Kind = CredentialKindAPIKey
			p.KindEvidence = fmt.Sprintf("the value carries the %s prefix of a %s and the rest of it has that format's shape",
				format.prefix, format.what)
			p.Warnings = append(p.Warnings,
				"API keys of this kind commonly have no expiry, but no expiry was MEASURED here, so the lifetime is unknown rather than unlimited")
			return
		}
	}

	// A POINTER AT A SUBJECT, READ BEFORE THE SESSION FALLBACK. This branch is reached only when
	// every structural recogniser has already declined, so a JWS, a PASETO or a SAML assertion in
	// a cookie called user is still read for what it is.
	if who, ok := credentialNameNamesAPrincipal(carrier.Name); ok {
		p.Kind = CredentialKindPrincipalName
		p.KindEvidence = fmt.Sprintf(
			"the last segment of %s reads as a %s, so this value names the principal rather than proving it, and no recogniser found any structure in the value either",
			carrier.Describe(), who)
		p.Warnings = append(p.Warnings,
			"this is a reading of the NAME and not of the value: the name says who the principal is rather than claiming to prove it, so until something measures the application refusing this value it must not be counted as a live credential or used to decide how long a session has left")
		return
	}

	if carrier.Kind == "cookie" {
		if framework, ok := knownSessionCookies[name]; ok {
			p.Kind = CredentialKindSessionID
			p.KindEvidence = fmt.Sprintf("the cookie name %s is the session handle of a %s application",
				carrier.Name, framework)
			p.Warnings = append(p.Warnings,
				"a server-side session identifier carries no expiry a client can read; its lifetime can only be established by observing the corpus or by probing until it stops working")
			return
		}
		// Rails and Drupal name their session cookie after the application, so the shape of the
		// name is the evidence rather than the name itself.
		if strings.HasSuffix(name, "_session") || strings.HasPrefix(name, "sess") {
			p.Kind = CredentialKindSessionID
			p.KindEvidence = fmt.Sprintf("the cookie name %s follows the framework convention for a server-side session handle",
				carrier.Name)
			p.Warnings = append(p.Warnings,
				"a server-side session identifier carries no expiry a client can read; its lifetime can only be established by observing the corpus or by probing until it stops working")
			return
		}
		p.Kind = CredentialKindSessionID
		p.KindEvidence = fmt.Sprintf("an unrecognised cookie value in %s with no readable structure",
			carrier.Name)
		p.Warnings = append(p.Warnings,
			"the cookie name matches no framework this engine knows, so calling it a session handle is a reading of where it travels and not of what it contains; its expiry can only come from the Set-Cookie that issued it, from the corpus or from probing")
		return
	}

	p.Kind = CredentialKindOpaqueBearer
	p.KindEvidence = fmt.Sprintf("a %d character value in %s with no structure this engine recognises", len(tok), carrier.Describe())
	p.Warnings = append(p.Warnings,
		"the value is opaque, so its expiry cannot be read; only observing the corpus or probing can establish it")
}

// ---------------------------------------------------------------------------------------------
// Cookie attributes
// ---------------------------------------------------------------------------------------------

// CookieLifetime is what a Set-Cookie header says about how long the cookie lives.
type CookieLifetime struct {
	Name string
	// TTL is the lifetime when Max-Age gave one. Max-Age is a duration, so it IS a TTL.
	TTL      time.Duration
	TTLKnown bool
	// ExpiresAt is the wall-clock death. From Max-Age it is relative to the response, so issuedAt
	// has to be supplied; from Expires it is absolute.
	ExpiresAt   time.Time
	ExpiryKnown bool
	Style       ExpiryStyle
	Evidence    string
	Attributes  map[string]string
	// AlreadyDead is a Max-Age of zero or less, or an Expires in the past relative to issuedAt,
	// which is how a server DELETES a cookie. Reading that as a lifetime would record a live
	// session for a credential the server just revoked.
	AlreadyDead bool
}

// ParseSetCookieLifetime reads the lifetime out of one Set-Cookie header value.
//
// MAX-AGE WINS OVER EXPIRES. RFC 6265 section 5.3 is explicit: if both are present the user agent
// uses Max-Age. Servers do send both, usually with the same meaning, but a server that is shortening
// a cookie sends a long Expires for old clients and a short Max-Age for everyone else, and reading
// Expires there overstates the lifetime.
//
// A cookie with NEITHER is a session cookie. That is its own answer: it has no wall-clock expiry,
// it dies when the browser does, and the server-side session behind it has a lifetime we have not
// measured. It is not one hour and it is not unknown-in-general.
//
// issuedAt is when the response carrying this header was received, which is what Max-Age counts
// from. Pass the capture timestamp; a zero time means the expiry from Max-Age cannot be computed
// and only the TTL is returned.
func ParseSetCookieLifetime(setCookie string, issuedAt time.Time) CookieLifetime {
	out := CookieLifetime{Style: ExpiryStyleUnknown, Attributes: map[string]string{}}
	parts := strings.Split(setCookie, ";")
	if len(parts) == 0 {
		return out
	}
	if name, _, ok := strings.Cut(strings.TrimSpace(parts[0]), "="); ok {
		out.Name = strings.TrimSpace(name)
	}

	var maxAge string
	var expires string
	for _, raw := range parts[1:] {
		attr := strings.TrimSpace(raw)
		key, value, _ := strings.Cut(attr, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "max-age":
			maxAge = strings.TrimSpace(value)
		case "expires":
			expires = strings.TrimSpace(value)
		case "domain":
			out.Attributes["domain"] = strings.TrimSpace(value)
		case "path":
			out.Attributes["path"] = strings.TrimSpace(value)
		case "samesite":
			out.Attributes["samesite"] = strings.TrimSpace(value)
		case "secure":
			out.Attributes["secure"] = "true"
		case "httponly":
			out.Attributes["httponly"] = "true"
		case "partitioned":
			out.Attributes["partitioned"] = "true"
		}
	}

	if maxAge != "" {
		if secs, err := strconv.ParseInt(maxAge, 10, 64); err == nil {
			out.Attributes["max_age"] = maxAge
			if secs <= 0 {
				out.AlreadyDead = true
				out.Evidence = "Max-Age is zero or negative, which is how a server deletes a cookie rather than a lifetime"
				out.Style = ExpiryStyleAbsolute
				return out
			}
			out.TTL, out.TTLKnown = time.Duration(secs)*time.Second, true
			out.Style = ExpiryStyleAbsolute
			out.Evidence = "the Max-Age attribute, which RFC 6265 gives precedence over Expires"
			if expires != "" {
				out.Evidence += " (an Expires attribute was also present and was ignored, per that precedence)"
			}
			if !issuedAt.IsZero() {
				out.ExpiresAt, out.ExpiryKnown = issuedAt.Add(out.TTL), true
			}
			return out
		}
	}

	if expires != "" {
		if t, ok := parseCookieDate(expires); ok {
			out.Attributes["expires"] = t.Format(time.RFC3339)
			out.ExpiresAt, out.ExpiryKnown = t, true
			out.Style = ExpiryStyleAbsolute
			out.Evidence = "the Expires attribute"
			if !issuedAt.IsZero() {
				if d := t.Sub(issuedAt); d > 0 {
					out.TTL, out.TTLKnown = d, true
					out.Evidence = "Expires minus the time the response was received"
				} else {
					out.AlreadyDead = true
					out.Evidence = "Expires is in the past relative to the response that set it, which is how a server deletes a cookie"
				}
			}
			return out
		}
		out.Evidence = "an Expires attribute that could not be parsed as a date"
		return out
	}

	out.Style = ExpiryStyleSession
	out.Evidence = "neither Max-Age nor Expires, so this is a session cookie with no wall-clock expiry of its own"
	return out
}

// cookieDateFormats covers the three forms RFC 6265 requires a client to accept plus the two
// non-conforming ones servers send anyway.
var cookieDateFormats = []string{
	time.RFC1123,
	"Mon, 02-Jan-2006 15:04:05 MST",
	"Mon, 02 Jan 2006 15:04:05 MST",
	"Mon, 02-Jan-06 15:04:05 MST",
	time.ANSIC,
	time.RFC1123Z,
}

func parseCookieDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range cookieDateFormats {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------------------------------------
// OAuth token responses
// ---------------------------------------------------------------------------------------------

// OAuthTokenResponse is what an RFC 6749 token endpoint said. It is the one place a TTL for an
// OPAQUE access token is a parsed fact rather than an inference, which makes it worth reading
// wherever the corpus has one.
type OAuthTokenResponse struct {
	HasAccessToken  bool
	HasRefreshToken bool
	HasIDToken      bool
	// The three credentials the response issued, as it issued them. A token endpoint response is
	// the single richest thing a crawl catches: the access token is the session, the refresh token
	// renews it and the id_token names the person it belongs to. They are carried because they are
	// the evidence; the booleans beside them stay because a caller often only wants to know a
	// grant exists.
	AccessToken  string
	RefreshToken string
	IDToken      string

	TokenType       string
	ExpiresIn       time.Duration
	ExpiresInKnown  bool
	RefreshTTL      time.Duration
	RefreshTTLKnown bool
	Scope           string
}

// ParseOAuthTokenResponse reads a token endpoint body.
//
// It returns the credentials the response carried and what the server declared about their
// lifetimes. A refresh_token that is present but has no declared lifetime is exactly the
// distinction between "a refresh exists" and "we know how long we can keep using it".
func ParseOAuthTokenResponse(body string) (OAuthTokenResponse, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &raw) != nil {
		return OAuthTokenResponse{}, false
	}
	out := OAuthTokenResponse{}
	seen := false
	for key, value := range raw {
		switch strings.ToLower(key) {
		case "access_token":
			out.HasAccessToken, seen = true, true
			_ = json.Unmarshal(value, &out.AccessToken)
		case "refresh_token":
			out.HasRefreshToken, seen = true, true
			_ = json.Unmarshal(value, &out.RefreshToken)
		case "id_token":
			out.HasIDToken, seen = true, true
			_ = json.Unmarshal(value, &out.IDToken)
		case "token_type":
			_ = json.Unmarshal(value, &out.TokenType)
			seen = true
		case "scope":
			_ = json.Unmarshal(value, &out.Scope)
		case "expires_in":
			if secs, ok := jsonSeconds(value); ok {
				out.ExpiresIn, out.ExpiresInKnown = secs, true
				seen = true
			}
		case "refresh_token_expires_in", "refresh_expires_in":
			if secs, ok := jsonSeconds(value); ok {
				out.RefreshTTL, out.RefreshTTLKnown = secs, true
			}
		}
	}
	return out, seen
}

// jsonSeconds reads a duration that may have been sent as a number or as a string, because both
// are common and a strict number parse drops half the issuers.
func jsonSeconds(v json.RawMessage) (time.Duration, bool) {
	var n json.Number
	if json.Unmarshal(v, &n) == nil {
		if secs, err := strconv.ParseInt(n.String(), 10, 64); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second, true
		}
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		if secs, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------------------------
// The issuing response: the half of the answer that is not in the credential
// ---------------------------------------------------------------------------------------------

// SetCookieObservation is one captured Set-Cookie header, whole.
//
// A Set-Cookie that issued a session is evidence: the cookie it set is the credential, and a
// framework that showed the attributes and withheld the value would have kept back the one part
// of the header that proves anything.
type SetCookieObservation struct {
	// Header is the Set-Cookie exactly as it was captured: "PHPSESSID=abc123; Path=/; HttpOnly".
	Header string `json:"header"`
	// Value is the cookie value the header set, pulled out so a caller does not have to re-parse
	// the header to get at it. Empty when the header carried none.
	Value string `json:"value"`
	// ValueFingerprint is eight hex digits of the SHA-256 of Value, kept as the JOIN KEY: it is how
	// an observation is tied to THIS credential or recognised as another issuance of the same
	// cookie. Empty when the value was not available to hash.
	ValueFingerprint string `json:"value_fingerprint"`
	// ObservedAt is when the response carrying the header was received, which is what a Max-Age
	// counts from. Without it a Max-Age still gives a TTL and cannot give a wall-clock expiry.
	ObservedAt time.Time `json:"observed_at"`
}

// TokenResponseObservation is one captured token endpoint response, body and all.
type TokenResponseObservation struct {
	// Body is the response body as the server sent it, access_token, refresh_token and id_token
	// values included. A token endpoint body is the proof of what was minted.
	Body string `json:"body"`
	// AccessTokenFingerprint identifies the credential the response issued, so an expires_in is
	// only ever applied to the value it was about. It is the join, not a substitute for Body.
	AccessTokenFingerprint string    `json:"access_token_fingerprint"`
	ObservedAt             time.Time `json:"observed_at"`
}

// CredentialEvidence is what the exchange around a credential said about it: the Set-Cookie that
// set it and the token endpoint response that minted it.
//
// It is deliberately a separate input from the credential. ProfileCredential stays pure and
// value-only for the callers that hold nothing else; anybody who has the issuing response hands it
// over here and gets the lifetime that was on the wire instead of UNKNOWN.
type CredentialEvidence struct {
	SetCookies     []SetCookieObservation     `json:"set_cookies"`
	TokenResponses []TokenResponseObservation `json:"token_responses"`
}

// IsZero reports evidence with nothing in it, which is the honest state for a credential somebody
// typed into the Session Manager with no capture behind it.
func (e CredentialEvidence) IsZero() bool {
	return len(e.SetCookies) == 0 && len(e.TokenResponses) == 0
}

// reSetCookieValue splits a Set-Cookie header into name, value and the attribute tail. The value
// runs to the first semicolon and may itself contain "=", which base64 padding routinely does.
var reSetCookieValue = regexp.MustCompile(`^\s*([^=;\s]+)=([^;]*)(.*)$`)

// NewSetCookieObservation builds an observation out of a live Set-Cookie header, keeping the
// header whole and pulling the value out beside it.
func NewSetCookieObservation(setCookie string, observedAt time.Time) SetCookieObservation {
	out := SetCookieObservation{Header: setCookie, ObservedAt: observedAt}
	m := reSetCookieValue.FindStringSubmatch(setCookie)
	if m == nil {
		return out
	}
	out.Value = m[2]
	if m[2] != "" {
		out.ValueFingerprint = triageCredFingerprint(m[2])
	}
	return out
}

// reAccessTokenValue pulls the access_token value out of a token endpoint body so the observation
// can be joined to the credential it issued.
var reAccessTokenValue = regexp.MustCompile(`"access_token"\s*:\s*"([^"]*)"`)

// NewTokenResponseObservation builds an observation out of a live token endpoint body, keeping the
// body as it arrived and fingerprinting the access token it carried so the observation can be tied
// to one credential.
func NewTokenResponseObservation(body string, observedAt time.Time) TokenResponseObservation {
	out := TokenResponseObservation{Body: body, ObservedAt: observedAt}
	if m := reAccessTokenValue.FindStringSubmatch(body); len(m) == 2 && m[1] != "" {
		out.AccessTokenFingerprint = triageCredFingerprint(m[1])
	}
	return out
}

// applyIssuingResponse folds the issuing exchange into a profile.
//
// THE ORDER OF PRECEDENCE, and why it is this way round:
//
//  1. what the credential says about itself wins, because it is the issuer's own statement and
//     survives the credential being copied anywhere;
//  2. the response that issued THIS EXACT VALUE comes next, matched by fingerprint;
//  3. a response that issued a DIFFERENT value of the same cookie comes last and gives a TTL but
//     never a wall-clock expiry, because the server's Max-Age for a cookie is a property of the
//     cookie and the death of a particular value is not.
//
// Nothing here overwrites a parsed fact. A disagreement between the two becomes a warning, which
// is how a stored value that has rotated underneath its capture makes itself visible.
func applyIssuingResponse(p *SessionTokenProfile, ev CredentialEvidence, carrier CredentialCarrier) {
	if ev.IsZero() {
		return
	}
	applySetCookieEvidence(p, ev, carrier)
	applyTokenResponseEvidence(p, ev)
}

func applySetCookieEvidence(p *SessionTokenProfile, ev CredentialEvidence, carrier CredentialCarrier) {
	name := strings.TrimSpace(carrier.Name)
	// A Set-Cookie describes a COOKIE. A credential that rides in a header of the same name is a
	// different thing travelling a different way, and reading one as the other would attach a
	// lifetime to a credential the response never mentioned.
	if carrier.Kind != "cookie" || name == "" || len(ev.SetCookies) == 0 {
		return
	}

	// Only observations of THIS cookie say anything about this credential.
	var mine []SetCookieObservation
	for _, obs := range ev.SetCookies {
		cl := ParseSetCookieLifetime(obs.Header, obs.ObservedAt)
		if strings.EqualFold(strings.TrimSpace(cl.Name), name) {
			mine = append(mine, obs)
		}
	}
	if len(mine) == 0 {
		return
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].ObservedAt.Before(mine[j].ObservedAt) })

	// The best witness is the most recent response that set THIS value.
	exact := -1
	for i := range mine {
		if p.Fingerprint != "" && mine[i].ValueFingerprint == p.Fingerprint {
			exact = i
		}
	}
	chosen := mine[len(mine)-1]
	sameValue := exact >= 0
	if sameValue {
		chosen = mine[exact]
	}

	cl := ParseSetCookieLifetime(chosen.Header, chosen.ObservedAt)
	for key, value := range cl.Attributes {
		setIf(p.Attributes, "cookie_"+key, value)
	}

	if cl.AlreadyDead {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"the captured Set-Cookie for %s is a DELETION rather than an issuance (%s), so it states no lifetime for this credential",
			cl.Name, cl.Evidence))
		return
	}

	where := "the Set-Cookie that set " + cl.Name + ", " + capturedAtPhrase(chosen.ObservedAt)
	if !sameValue {
		where += "; that response set a DIFFERENT value of this cookie, so it is the server's declared lifetime for the cookie and not a measurement of the value in hand"
	}

	if cl.TTLKnown {
		switch {
		case !p.TTLKnown:
			p.TTL, p.TTLKnown = cl.TTL, true
			p.TTLProvenance = ProvParsed
			p.TTLEvidence = cl.Evidence + ", read from " + where
		case absDuration(p.TTL-cl.TTL) > time.Minute:
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"the credential states a lifetime of %s and %s states %s; the two disagree, which usually means the stored value was issued by a different response than the one captured",
				humaniseTTL(p.TTL), where, humaniseTTL(cl.TTL)))
		}
	}

	// A wall-clock expiry only transfers when the response issued THIS value: the moment another
	// value of the same cookie dies is not the moment this one does.
	if cl.ExpiryKnown && sameValue && !p.ExpiryKnown {
		p.ExpiresAt, p.ExpiryKnown = cl.ExpiresAt, true
		p.ExpiryProvenance = ProvParsed
		p.ExpiryEvidence = cl.Evidence + ", read from " + where
	}
	// Same rule for the issue time: the response that SET this value was received when it was
	// received, which is when the server minted it. For another value of the cookie it says
	// nothing at all.
	if sameValue && !p.IssuedAtKnown && !chosen.ObservedAt.IsZero() {
		p.IssuedAt, p.IssuedAtKnown, p.IssuedAtSource = chosen.ObservedAt.UTC(), true, IssuedAtIssuingResponse
	}

	switch {
	case cl.Style == ExpiryStyleSession && !p.ExpiryKnown:
		// A cookie with neither Max-Age nor Expires is its own answer and not an unknown: it has
		// no wall-clock expiry at all, and the server-side session behind it has a lifetime this
		// measurement did not touch.
		p.ExpiryStyle = ExpiryStyleSession
		p.ExpiryEvidence = cl.Evidence + ", read from " + where
	case cl.Style == ExpiryStyleAbsolute && p.ExpiryStyle == ExpiryStyleUnknown:
		p.ExpiryStyle = ExpiryStyleAbsolute
	}

	if sliding, fingerprint, why := cookieLooksSliding(mine); sliding {
		p.ExpiryStyle = ExpiryStyleSliding
		if fingerprint != p.Fingerprint {
			why += "; that was measured on ANOTHER value of the same cookie, so it is the server policy for the cookie rather than an observation of the value in hand"
		}
		// Appended rather than assigned: the Max-Age or Expires that produced the wall-clock
		// death is still what produced it, and losing that sentence would leave the expiry
		// unattributable.
		if strings.TrimSpace(p.ExpiryEvidence) != "" {
			p.ExpiryEvidence += "; " + why
		} else {
			p.ExpiryEvidence = why
		}
	}
}

// cookieLooksSliding decides whether the server pushes the expiry out on use.
//
// The wire signature is unambiguous and needs no model: the SAME cookie value was set again later
// with a lifetime that puts its death further out than the first response did. A cookie that is
// merely re-sent with the same absolute Expires is not sliding, and a new VALUE with a fresh
// Max-Age is a rotation rather than an extension, so both are excluded by construction.
func cookieLooksSliding(observations []SetCookieObservation) (bool, string, string) {
	type window struct {
		value       string
		first, last time.Time
		firstDeath  time.Time
		lastDeath   time.Time
		seen        int
	}
	byValue := map[string]*window{}
	for _, obs := range observations {
		if obs.ValueFingerprint == "" || obs.ObservedAt.IsZero() {
			continue
		}
		cl := ParseSetCookieLifetime(obs.Header, obs.ObservedAt)
		if !cl.ExpiryKnown || cl.AlreadyDead {
			continue
		}
		w, ok := byValue[obs.ValueFingerprint]
		if !ok {
			byValue[obs.ValueFingerprint] = &window{
				value: obs.Value,
				first: obs.ObservedAt, last: obs.ObservedAt,
				firstDeath: cl.ExpiresAt, lastDeath: cl.ExpiresAt, seen: 1,
			}
			continue
		}
		w.seen++
		if obs.ObservedAt.After(w.last) {
			w.last, w.lastDeath = obs.ObservedAt, cl.ExpiresAt
		}
		if obs.ObservedAt.Before(w.first) {
			w.first, w.firstDeath = obs.ObservedAt, cl.ExpiresAt
		}
	}
	// Sorted so the answer does not depend on map iteration order, which would make the evidence
	// sentence change between runs on the same corpus.
	fingerprints := make([]string, 0, len(byValue))
	for fingerprint := range byValue {
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Strings(fingerprints)
	for _, fingerprint := range fingerprints {
		w := byValue[fingerprint]
		if w.seen < 2 {
			continue
		}
		if moved := w.lastDeath.Sub(w.firstDeath); moved > time.Second {
			which := w.value
			if which == "" {
				which = fingerprint
			}
			return true, fingerprint, fmt.Sprintf(
				"the same cookie value (%s) was set again %s after the first time and its expiry moved out by %s, so using it pushes the expiry out",
				which, humaniseTTL(w.last.Sub(w.first)), humaniseTTL(moved))
		}
	}
	return false, "", ""
}

func applyTokenResponseEvidence(p *SessionTokenProfile, ev CredentialEvidence) {
	if len(ev.TokenResponses) == 0 {
		return
	}
	var chosen *TokenResponseObservation
	others := 0
	for i := range ev.TokenResponses {
		obs := ev.TokenResponses[i]
		if p.Fingerprint != "" && obs.AccessTokenFingerprint == p.Fingerprint {
			if chosen == nil || obs.ObservedAt.After(chosen.ObservedAt) {
				chosen = &ev.TokenResponses[i]
			}
			continue
		}
		others++
	}
	if chosen == nil {
		// THIS IS THE HONEST ANSWER AND NOT A SILENCE. A token endpoint response that minted some
		// OTHER credential says nothing about the one in hand, and applying its expires_in anyway
		// is how a fifteen minute token comes to be reported as an hour.
		if others > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"%d captured token endpoint response(s) were found on this target, but none of them issued this credential (no access_token in them fingerprints to %s), so nothing any of them says about a lifetime was applied",
				others, p.Fingerprint))
		}
		return
	}

	parsed, ok := ParseOAuthTokenResponse(chosen.Body)
	if !ok {
		return
	}
	where := "the token endpoint response that issued this exact value, " + capturedAtPhrase(chosen.ObservedAt)

	if p.Kind == CredentialKindOpaqueBearer || p.Kind == CredentialKindUnknown {
		p.Kind = CredentialKindOAuthAccess
		p.KindEvidence = "an opaque value that arrived as the access_token of an RFC 6749 token endpoint response, so what it is was read from its issuance rather than from its bytes"
	}
	setIf(p.Attributes, "oauth_token_type", parsed.TokenType)
	setIf(p.Attributes, "oauth_scope", parsed.Scope)
	if parsed.HasRefreshToken {
		p.Attributes["oauth_refresh_token_present"] = "true"
		// AND THE REFRESH TOKEN ITSELF. This is the response that issued the very credential in
		// front of the operator, so the refresh token beside it is the one that renews THIS
		// session: it is what makes "a refresh exists" into something that can be spent.
		setIf(p.Attributes, "oauth_refresh_token", parsed.RefreshToken)
	}
	// The id_token from the same response names who the session belongs to, which is the fact an
	// access-control finding turns on.
	setIf(p.Attributes, "oauth_id_token", parsed.IDToken)
	if parsed.RefreshTTLKnown {
		p.Attributes["oauth_refresh_token_expires_in"] = humaniseTTL(parsed.RefreshTTL)
	}

	if !parsed.ExpiresInKnown {
		p.Warnings = append(p.Warnings,
			"the token endpoint response that issued this credential declares no expires_in, so RFC 6749 leaves its lifetime unstated; that is not the same as unlimited")
		return
	}

	switch {
	case !p.TTLKnown:
		p.TTL, p.TTLKnown = parsed.ExpiresIn, true
		p.TTLProvenance = ProvParsed
		p.TTLEvidence = "the expires_in of " + where
	case absDuration(p.TTL-parsed.ExpiresIn) > time.Minute:
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"the lifetime already measured for this credential is %s (%s: %s) and %s declares %s; the two disagree",
			humaniseTTL(p.TTL), p.TTLProvenance, p.TTLEvidence, where, humaniseTTL(parsed.ExpiresIn)))
	}

	if !p.ExpiryKnown && !chosen.ObservedAt.IsZero() {
		p.ExpiresAt, p.ExpiryKnown = chosen.ObservedAt.UTC().Add(parsed.ExpiresIn), true
		p.ExpiryProvenance = ProvParsed
		p.ExpiryStyle = ExpiryStyleAbsolute
		p.ExpiryEvidence = "expires_in counted from when " + where + " was received"
	} else if !p.ExpiryKnown {
		// The response says how long and this row has no record of WHEN it was received, so there
		// is nothing to count from here. The credential's own mint time answers that where it has
		// one; where it does not, the lifetime stands alone and the expiry stays UNKNOWN.
		applyExpiryImpliedByLifetime(p, "the expires_in of "+where)
	}
	if !p.IssuedAtKnown && !chosen.ObservedAt.IsZero() {
		p.IssuedAt, p.IssuedAtKnown, p.IssuedAtSource = chosen.ObservedAt.UTC(), true, IssuedAtIssuingResponse
	}
}

// ---------------------------------------------------------------------------------------------
// Corpus observation: the honest inference for an opaque credential
// ---------------------------------------------------------------------------------------------

// CorpusObservation is what the captured traffic shows about one carrier over time.
//
// EVERY FIELD IS A COUNT OF ROWS OR A TIMESTAMP OFF ONE. Nothing here is modelled and nothing is
// extrapolated, because the moment a number in this struct becomes an estimate it becomes
// indistinguishable from a parsed TTL to whoever reads it next.
type CorpusObservation struct {
	// Samples is how many DISTINCT values of the carrier were seen, Requests how many rows carried
	// one. One sample means the corpus has no evidence of rotation at all, which is a different
	// statement from a floor.
	Samples  int
	Requests int
	// Floor is the longest span between a single value's first and last appearance. It is a LOWER
	// BOUND on the TTL and nothing more: the value was still being sent this long after it first
	// arrived, so the server had not yet rejected it.
	Floor time.Duration
	// FloorValue is the value that produced the floor, exactly as the corpus holds it, so the claim
	// can be checked against the capture and the credential itself can be taken from here.
	FloorValue string
	// FloorFingerprint is that value's fingerprint, which is the JOIN: it is how a floor is matched
	// to the credential a row holds now.
	FloorFingerprint string
	// MedianSpan is the median of all the spans. It is recorded because it is what a naive
	// implementation would call the TTL, and on the live target it is under a minute against a
	// measured 900 seconds. It is NEVER promoted to a TTL.
	MedianSpan time.Duration
	// RotationInterval is the median gap between successive distinct values first appearing: how
	// often the client swapped credential. Also not a TTL.
	RotationInterval time.Duration
	FirstSeen        time.Time
	LastSeen         time.Time
	Evidence         string
}

// corpusSample is one distinct value's window.
type corpusSample struct {
	// Value is the credential as the corpus holds it. Fingerprint is derived from it and is the
	// join key; where a caller built a sample without a value, only the fingerprint is set.
	Value       string
	Fingerprint string
	Count       int
	First       time.Time
	Last        time.Time
}

// ObserveCarrierInCorpus measures how one carrier behaved across manual_crawl_captures.
//
// The grouping happens server side, one row per distinct value, and each row comes back with the
// value on it: which credential produced a floor is a fact about the corpus that an operator has
// to be able to check against the capture.
func ObserveCarrierInCorpus(ctx context.Context, scopeTargetID string, carrier CredentialCarrier) (CorpusObservation, error) {
	out := CorpusObservation{}
	if dbPool == nil {
		return out, fmt.Errorf("no database connection, so the corpus could not be observed")
	}
	name := strings.TrimSpace(carrier.Name)
	if name == "" {
		return out, fmt.Errorf("the carrier has no name, so there is nothing to look for in the corpus")
	}

	var query string
	var arg string
	switch carrier.Kind {
	case "cookie":
		// The cookie header is normalised to a single separator and given a leading one, so the
		// anchored pattern cannot match a cookie whose name merely ENDS with the one we want.
		query = `
			SELECT v, count(*), min(ts), max(ts)
			FROM (
				SELECT substring(';' || replace(headers->>'cookie', '; ', ';') FROM $2) AS v,
				       COALESCE(timestamp, created_at) AS ts
				FROM manual_crawl_captures
				WHERE scope_target_id = $1 AND (headers->>'cookie') IS NOT NULL
			) s
			WHERE v IS NOT NULL AND v <> ''
			GROUP BY 1 ORDER BY min(ts)`
		arg = ";" + escapePosixRegex(name) + "=([^;]*)"
	case "query":
		query = `
			SELECT v, count(*), min(ts), max(ts)
			FROM (
				SELECT get_params->>$2 AS v, COALESCE(timestamp, created_at) AS ts
				FROM manual_crawl_captures
				WHERE scope_target_id = $1 AND (get_params->>$2) IS NOT NULL
			) s
			WHERE v <> ''
			GROUP BY 1 ORDER BY min(ts)`
		arg = name
	default:
		// Captured request headers are stored with lowercased names.
		query = `
			SELECT v, count(*), min(ts), max(ts)
			FROM (
				SELECT headers->>$2 AS v, COALESCE(timestamp, created_at) AS ts
				FROM manual_crawl_captures
				WHERE scope_target_id = $1 AND (headers->>$2) IS NOT NULL
			) s
			WHERE v <> ''
			GROUP BY 1 ORDER BY min(ts)`
		arg = strings.ToLower(name)
	}

	rows, err := dbPool.Query(ctx, query, scopeTargetID, arg)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	var samples []corpusSample
	for rows.Next() {
		var s corpusSample
		if rows.Scan(&s.Value, &s.Count, &s.First, &s.Last) != nil {
			continue
		}
		s.Fingerprint = triageCredFingerprint(s.Value)
		samples = append(samples, s)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return summariseCorpusSamples(samples, carrier), nil
}

// summariseCorpusSamples turns the per-value windows into the observation. It is separate from the
// query so the arithmetic, which is where a floor gets quietly promoted to a TTL, is testable
// without a database.
func summariseCorpusSamples(samples []corpusSample, carrier CredentialCarrier) CorpusObservation {
	out := CorpusObservation{Samples: len(samples)}
	if len(samples) == 0 {
		out.Evidence = fmt.Sprintf("the captured corpus holds no request carrying a %s at all", carrier.Describe())
		return out
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].First.Before(samples[j].First) })

	spans := make([]time.Duration, 0, len(samples))
	var firsts []time.Time
	for _, s := range samples {
		out.Requests += s.Count
		span := s.Last.Sub(s.First)
		spans = append(spans, span)
		if span > out.Floor {
			out.Floor = span
			out.FloorValue = s.Value
			out.FloorFingerprint = s.Fingerprint
		}
		firsts = append(firsts, s.First)
	}
	out.FirstSeen = samples[0].First
	out.LastSeen = samples[len(samples)-1].Last
	out.MedianSpan = medianDuration(spans)

	if len(firsts) > 1 {
		gaps := make([]time.Duration, 0, len(firsts)-1)
		for i := 1; i < len(firsts); i++ {
			gaps = append(gaps, firsts[i].Sub(firsts[i-1]))
		}
		out.RotationInterval = medianDuration(gaps)
	}

	switch {
	case out.Samples == 1:
		out.Evidence = fmt.Sprintf("one value of the %s across %d captured requests, still in use %s after it first appeared; one value cannot show rotation, so this is a floor and not a lifetime",
			carrier.Describe(), out.Requests, humaniseTTL(out.Floor))
	default:
		// The longest-lived value is NAMED, because the whole claim is that one particular credential
		// was still being sent that long after it appeared, and a reader has to be able to go and
		// find it in the capture. Where a sample carries no value the fingerprint says which it was.
		longest := out.FloorValue
		if longest == "" {
			longest = out.FloorFingerprint
		}
		out.Evidence = fmt.Sprintf("%d distinct values of the %s across %d captured requests; the longest-lived (%s) was still in use %s after it first appeared, the median value lasted %s, and a new value appeared every %s",
			out.Samples, carrier.Describe(), out.Requests, longest,
			humaniseTTL(out.Floor), humaniseTTL(out.MedianSpan), humaniseTTL(out.RotationInterval))
	}
	return out
}

func medianDuration(in []time.Duration) time.Duration {
	if len(in) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), in...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

// escapePosixRegex escapes the metacharacters of a POSIX ERE, which is what Postgres substring()
// speaks. A cookie name is a token by RFC 6265 and so cannot contain most of these, but the name
// reaches here from a database row an operator typed, and a cookie called "a.b" matching "aXb" is
// a silently wrong observation rather than an error.
func escapePosixRegex(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// GatherIssuingEvidence finds, in the captured corpus, the responses that issued a credential.
//
// WHAT COMES BACK IS WHAT WAS CAPTURED: the Set-Cookie exactly as the server sent it, value and
// attributes, and the token endpoint body with its access_token, refresh_token and id_token in
// place. That is the evidence a finding is written out of, and it is the operator's own session in
// the operator's own locally running tool.
//
// A fingerprint still travels beside each observation, and only as the JOIN: it is what says an
// expires_in belongs to the credential in hand rather than to one the same endpoint minted for
// somebody else.
func GatherIssuingEvidence(ctx context.Context, scopeTargetID string, carrier CredentialCarrier) (CredentialEvidence, error) {
	out := CredentialEvidence{}
	if dbPool == nil {
		return out, fmt.Errorf("no database connection, so the issuing response could not be looked for")
	}
	if strings.TrimSpace(scopeTargetID) == "" {
		return out, fmt.Errorf("no scope target, so there is no corpus to look in")
	}

	if carrier.Kind == "cookie" && strings.TrimSpace(carrier.Name) != "" {
		cookies, err := gatherSetCookieEvidence(ctx, scopeTargetID, strings.TrimSpace(carrier.Name))
		if err != nil {
			return out, err
		}
		out.SetCookies = cookies
	}

	responses, err := gatherTokenResponseEvidence(ctx, scopeTargetID)
	if err != nil {
		return out, err
	}
	out.TokenResponses = responses
	return out, nil
}

// setCookieEvidenceQuery expands response_headers into the Set-Cookie headers of one target and
// hands back each one whole.
//
// A response_headers value is a string for one cookie and an array for several, and some captures
// join several into one string with newlines, so all three are flattened here. The name is
// compared server side because that is the filter: only the cookie the caller asked about is any
// evidence about the credential in hand.
const setCookieEvidenceQuery = `
	WITH raw AS (
		SELECT COALESCE(c.timestamp, c.created_at) AS ts, kv.value AS v
		FROM manual_crawl_captures c, LATERAL jsonb_each(c.response_headers) kv
		WHERE c.scope_target_id = $1 AND lower(kv.key) = 'set-cookie'
		  AND c.response_headers IS NOT NULL
	), flat AS (
		SELECT ts, v #>> '{}' AS sc FROM raw WHERE jsonb_typeof(v) <> 'array'
		UNION ALL
		SELECT raw.ts, e #>> '{}' AS sc FROM raw, LATERAL jsonb_array_elements(raw.v) e
		WHERE jsonb_typeof(raw.v) = 'array'
	), one AS (
		SELECT ts, line FROM flat, LATERAL regexp_split_to_table(flat.sc, E'\n') AS line
		WHERE flat.sc IS NOT NULL AND flat.sc <> ''
	)
	SELECT
		substring(line from '^[[:space:]]*([^=;[:space:]]+)=') AS cookie_name,
		COALESCE(substring(line from '^[^=]*=([^;]*)'), '') AS cookie_value,
		COALESCE(substring(line from '^[^;]*(;.*)$'), '') AS attributes,
		ts
	FROM one
	WHERE lower(COALESCE(substring(line from '^[[:space:]]*([^=;[:space:]]+)='), '')) = lower($2)
	ORDER BY ts ASC
	LIMIT 500`

func gatherSetCookieEvidence(ctx context.Context, scopeTargetID, name string) ([]SetCookieObservation, error) {
	rows, err := dbPool.Query(ctx, setCookieEvidenceQuery, scopeTargetID, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SetCookieObservation
	for rows.Next() {
		var cookieName, cookieValue, attributes string
		var ts time.Time
		if rows.Scan(&cookieName, &cookieValue, &attributes, &ts) != nil {
			continue
		}
		obs := SetCookieObservation{
			Header:     cookieName + "=" + cookieValue + attributes,
			Value:      cookieValue,
			ObservedAt: ts.UTC(),
		}
		if cookieValue != "" {
			obs.ValueFingerprint = triageCredFingerprint(cookieValue)
		}
		out = append(out, obs)
	}
	return out, rows.Err()
}

// tokenResponseEvidenceQuery returns the token endpoint bodies of one target as they were
// captured, plus the fingerprint of the access token each one issued.
//
// The fingerprint is taken in Postgres off the WHOLE body rather than in Go off the truncated one,
// so a body long enough to be cut can still be joined to the credential it minted.
const tokenResponseEvidenceQuery = `
	SELECT
		left(c.response_body, 200000) AS body,
		substring(encode(sha256(convert_to(COALESCE(substring(c.response_body from '"access_token"[[:space:]]*:[[:space:]]*"([^"]*)"'), ''), 'UTF8')), 'hex') for 8) AS access_fingerprint,
		COALESCE(c.timestamp, c.created_at) AS ts
	FROM manual_crawl_captures c
	WHERE c.scope_target_id = $1
	  AND c.response_body LIKE '%"access_token"%'
	ORDER BY ts DESC
	LIMIT 50`

func gatherTokenResponseEvidence(ctx context.Context, scopeTargetID string) ([]TokenResponseObservation, error) {
	rows, err := dbPool.Query(ctx, tokenResponseEvidenceQuery, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenResponseObservation
	for rows.Next() {
		var body, fingerprint string
		var ts time.Time
		if rows.Scan(&body, &fingerprint, &ts) != nil {
			continue
		}
		out = append(out, TokenResponseObservation{
			Body:                   body,
			AccessTokenFingerprint: fingerprint,
			ObservedAt:             ts.UTC(),
		})
	}
	return out, rows.Err()
}

// CredentialFingerprintEvidenceKey is the evidence member an event carries to say WHICH credential
// it was about. It is a JOIN KEY: eight hex digits of a SHA-256, the same thing the profile
// publishes, so an event written months ago can still be matched to the credential a row holds now
// without the two having to be compared byte for byte or the old value having to be kept around to
// compare against. Events that have the credential itself carry it as well, under their own keys.
const CredentialFingerprintEvidenceKey = "credential_fingerprint"

// StampCredentialFingerprint records on an event evidence map which credential the event was
// about. Producers of session_token_events call it; it stamps the join key and nothing else, so a
// caller that also wants the credential on the row puts it there itself.
func StampCredentialFingerprint(evidence map[string]interface{}, value string) map[string]interface{} {
	if evidence == nil {
		evidence = map[string]interface{}{}
	}
	if strings.TrimSpace(value) == "" {
		return evidence
	}
	evidence[CredentialFingerprintEvidenceKey] = triageCredFingerprint(value)
	return evidence
}

// How a validation event was attributed to the credential the row holds NOW. The sentence goes
// into the floor evidence, so an operator reading a floor can see what tied it to one credential.
const (
	probeAttributedByFingerprint = "attributed by the credential fingerprint recorded on each of those events"
	probeAttributedByAnchor      = "attributed by the profile that fingerprinted this exact value as the one in the row, before which the row may have held a different credential"
)

// credentialHeldSince is the earliest moment this row is KNOWN to have held the credential it
// holds now, and the empty time means nothing knows.
//
// session_tokens.value_fingerprint is written by every profiling, and every path that replaces the
// stored value either reprofiles it or stamps last_refreshed_at. So a stored fingerprint EQUAL to
// the value now says the last profiling was of this credential, and its profiled_at is a moment
// the row provably held it. It is a conservative anchor and not a perfect one: it can only ever
// shrink the window a floor is taken from, never widen it.
func credentialHeldSince(ctx context.Context, tokenID, fingerprint string) time.Time {
	if strings.TrimSpace(fingerprint) == "" {
		return time.Time{}
	}
	var stored string
	var profiledAt, lastRefreshed *time.Time
	if err := dbPool.QueryRow(ctx, `
		SELECT COALESCE(value_fingerprint,''), profiled_at, last_refreshed_at
		FROM session_tokens WHERE id = $1`, tokenID).Scan(&stored, &profiledAt, &lastRefreshed); err != nil {
		return time.Time{}
	}
	if stored == "" || stored != fingerprint || profiledAt == nil || profiledAt.IsZero() {
		return time.Time{}
	}
	since := profiledAt.UTC()
	// A refresh replaces the value in place without reprofiling, so anything before the last one
	// is a different credential whatever the fingerprint says.
	if lastRefreshed != nil && lastRefreshed.UTC().After(since) {
		since = lastRefreshed.UTC()
	}
	return since
}

// attributeProbe answers whether one validation event was about the credential stored now.
//
// A stamped fingerprint is the strong form and needs no anchor: the event says which credential it
// was, and one that names a DIFFERENT credential is excluded by its own evidence rather than by a
// guess. Without a stamp the only honest test is the anchor, and an event older than the anchor is
// not attributable to anything, which is a result and not a missing field.
func attributeProbe(stamped, fingerprint string, at, anchor time.Time) (how string, mine, elsewhere bool) {
	if stamped != "" {
		if fingerprint != "" && stamped == fingerprint {
			return probeAttributedByFingerprint, true, false
		}
		return "", false, true
	}
	if anchor.IsZero() || at.Before(anchor) {
		return "", false, false
	}
	return probeAttributedByAnchor, true, false
}

// applyProbeHistory turns the framework's OWN validation attempts into a probed lower bound.
//
// This is the difference between observed and probed, and it is a real one. A corpus floor is a
// reading of somebody else's traffic: the value was still being SENT that long after it appeared,
// which says the client had not rotated it, not that the server still accepted it. A validation
// event of status active is a request THIS FRAMEWORK sent, where the target answered differently
// because of the credential, so it is a record of the credential still WORKING at that moment.
//
// Two forms of bound come out of it, and the larger wins:
//
//	from the issue time, when one is known AND it is a mint time: it was alive T after it was
//	minted;
//	from the earliest attributable successful validation to the latest: it was alive across that
//	span.
//
// A validation of status not_honoured is deliberately not used. A live credential reads as
// not_honoured on a load balanced target, or on a base URL that looks the same signed in or out,
// which is a measurement of the probe and not of the credential.
//
// ---------------------------------------------------------------------------------------------
// WHY EVERY EVENT HAS TO BE ATTRIBUTED FIRST, MEASURED
// ---------------------------------------------------------------------------------------------
//
// session_token_events carries no fingerprint of its own and the refresh path replaces the stored
// value IN PLACE, so the rows for one token id can be about any number of different credentials.
// Measured on the round 12 tree: a value stored one hour earlier was reported as "alive across
// 5h59m of its own life", a sentence about a credential the row no longer held, and it is read
// downstream by the renewal interval, where an overstated floor renews LATE.
//
// So a span is only taken across events this function can tie to the value in the row now, and
// where it can tie NOTHING there is no floor at all. A floor that cannot be attributed is not a
// measurement, and the count of what was dropped is reported rather than silently omitted.
func applyProbeHistory(ctx context.Context, p *SessionTokenProfile, tokenID string) {
	if ctx == nil || dbPool == nil || strings.TrimSpace(tokenID) == "" {
		return
	}
	anchor := credentialHeldSince(ctx, tokenID, p.Fingerprint)

	rows, err := dbPool.Query(ctx, `
		SELECT COALESCE(status,''), created_at,
		       COALESCE(evidence->>'`+CredentialFingerprintEvidenceKey+`','')
		FROM session_token_events
		WHERE session_token_id = $1 AND kind = 'validate'
		ORDER BY created_at ASC`, tokenID)
	if err != nil {
		return
	}
	defer rows.Close()

	var (
		alive, unattributed, otherCredential int
		firstAlive, lastAlive, lastRefused   time.Time
		attributedBy                         string
	)
	for rows.Next() {
		var status, stamped string
		var at time.Time
		if rows.Scan(&status, &at, &stamped) != nil {
			continue
		}
		at = at.UTC()
		switch status {
		case tokenStatusActive, tokenStatusExpired:
		default:
			continue
		}
		how, mine, elsewhere := attributeProbe(stamped, p.Fingerprint, at, anchor)
		if elsewhere {
			otherCredential++
			continue
		}
		if !mine {
			unattributed++
			continue
		}
		if status == tokenStatusExpired {
			lastRefused = at
			continue
		}
		if attributedBy == "" || how == probeAttributedByFingerprint {
			attributedBy = how
		}
		alive++
		if firstAlive.IsZero() {
			firstAlive = at
		}
		lastAlive = at
	}
	if rows.Err() != nil {
		return
	}
	if unattributed > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"%d validation event(s) on this credential could not be attributed to the value stored now, so nothing was read from them: the timeline records no fingerprint of its own and the stored value can be replaced in place, which makes a span across those events a span across an unknown number of credentials",
			unattributed))
	}
	if otherCredential > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"%d validation event(s) name a credential this row no longer holds and were left out of the lower bound",
			otherCredential))
	}
	if alive == 0 {
		return
	}

	best := time.Duration(0)
	why := ""
	if span := lastAlive.Sub(firstAlive); span > 0 {
		best, why = span, fmt.Sprintf(
			"the framework used this credential successfully at %s and again at %s, so it was alive across %s of its own life (%s)",
			firstAlive.Format(time.RFC3339), lastAlive.Format(time.RFC3339), humaniseTTL(span), attributedBy)
	}
	// AN ISSUE TIME IS ONLY A STARTING POINT WHEN IT IS THE MINT. nbf is not-before and a SAML
	// Conditions NotBefore is the same claim: both can sit EARLIER than the mint, so counting from
	// one overstates the floor, and an overstated floor is read downstream as a credential that
	// lasts longer than anything measured.
	if p.IssuedAtKnown && p.IssuedAtSource.IsMintTime() {
		if fromIssue := lastAlive.Sub(p.IssuedAt); fromIssue > best {
			best, why = fromIssue, fmt.Sprintf(
				"this credential was issued at %s (%s) and the framework used it successfully at %s, so its lifetime is at least %s (%s)",
				p.IssuedAt.UTC().Format(time.RFC3339), p.IssuedAtSource, lastAlive.Format(time.RFC3339),
				humaniseTTL(fromIssue), attributedBy)
		}
	} else if p.IssuedAtKnown {
		if fromIssue := lastAlive.Sub(p.IssuedAt); fromIssue > best {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"a lower bound of %s could be counted from the time on file for this credential, but that time was read from %s, which is not when it was minted, so it was not counted",
				humaniseTTL(fromIssue), p.IssuedAtSource))
		}
	}
	if best > 0 && best >= p.TTLFloor {
		p.TTLFloor, p.TTLFloorKnown = best, true
		p.TTLFloorProvenance = ProvProbed
		p.TTLFloorEvidence = why
	}

	// A refusal AFTER the last success bounds the death from the other side. It is a warning and
	// not an expiry: the credential died somewhere inside that window, and naming either end of
	// it as the moment would be a precision nothing measured.
	if !lastRefused.IsZero() && lastRefused.After(lastAlive) {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"the framework used this credential successfully at %s and was refused at %s; if the stored value did not change in between, it died somewhere in that %s window, and the exact expiry was not measured either way",
			lastAlive.Format(time.RFC3339), lastRefused.Format(time.RFC3339), humaniseTTL(lastRefused.Sub(lastAlive))))
	}
}

// ---------------------------------------------------------------------------------------------
// The full profile: parse, then observe, then answer the refresh question
// ---------------------------------------------------------------------------------------------

// ProfileSessionToken is the top-level entry point: everything the engine can say about one stored
// session_tokens row.
//
// The order is deliberate. Parsing comes first because a parsed answer is the only one that is a
// measurement of the server's intent, and it must not be overwritten by a weaker one. Observation
// then fills the floor, which is recorded ALONGSIDE a parsed TTL rather than instead of it, so a
// parsed 900 seconds sitting next to an observed floor of 868 is visible as the corroboration it
// is. The operator's declared expires_at is applied last and only where nothing was parsed.
func ProfileSessionToken(ctx context.Context, tok SessionToken) SessionTokenProfile {
	now := time.Now().UTC()
	carrier := CarrierForSessionToken(tok)

	// The response that ISSUED this credential, where the corpus holds it. For most of the web
	// this is the only place the lifetime is stated at all: a PHPSESSID, a rotating opaque cookie
	// and an OAuth access token each say nothing about themselves, and the Max-Age, the Expires
	// or the expires_in that mints them says everything.
	var evidence CredentialEvidence
	var evidenceErr error
	if ctx != nil && dbPool != nil && tok.ScopeTargetID != "" {
		evidence, evidenceErr = GatherIssuingEvidence(ctx, tok.ScopeTargetID, carrier)
	}

	p := ProfileCredentialWithEvidence(NewCredential(tok.TokenValue), carrier, evidence, now)
	if evidenceErr != nil {
		p.Warnings = append(p.Warnings,
			"the response that issued this credential could not be looked for, so anything it declared about the lifetime was not read: "+evidenceErr.Error())
	}
	p.TokenID = tok.ID
	p.ScopeTargetID = tok.ScopeTargetID
	p.Name = tok.Name

	// Cookie flags the operator recorded are attributes of the credential and belong on the
	// profile even when the value itself was opaque.
	if tok.TokenType == tokenTypeCookie {
		setIf(p.Attributes, "cookie_domain", tok.CookieDomain)
		setIf(p.Attributes, "cookie_path", tok.CookiePath)
		setIf(p.Attributes, "samesite", tok.CookieSameSite)
		if tok.CookieSecure {
			p.Attributes["secure"] = "true"
		}
		if tok.CookieHTTPOnly {
			p.Attributes["httponly"] = "true"
		}
	}

	// The operator's declared expiry. Believed where nothing was parsed, and LABELLED either way:
	// a declared expiry that disagrees with the token's own exp is worth seeing rather than
	// silently losing, because it usually means the stored value has been rotated underneath it.
	if tok.ExpiresAt != nil && !tok.ExpiresAt.IsZero() {
		declared := tok.ExpiresAt.UTC()
		if !p.ExpiryKnown {
			p.ExpiresAt, p.ExpiryKnown = declared, true
			p.ExpiryProvenance = ProvDeclared
			p.ExpiryStyle = ExpiryStyleAbsolute
			p.ExpiryEvidence = "the expires_at recorded in the Session Manager"
		} else if diff := declared.Sub(p.ExpiresAt); diff > time.Minute || diff < -time.Minute {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"the expires_at recorded in the Session Manager (%s) disagrees with the credential's own expiry (%s) by %s, which usually means the stored value was replaced without the column being updated",
				declared.Format(time.RFC3339), p.ExpiresAt.Format(time.RFC3339), humaniseTTL(absDuration(diff))))
		}
	}

	if ctx != nil && dbPool != nil && tok.ScopeTargetID != "" {
		if obs, err := ObserveCarrierInCorpus(ctx, tok.ScopeTargetID, carrier); err == nil {
			applyObservation(&p, obs)
		} else {
			p.Warnings = append(p.Warnings, "the captured corpus could not be read, so no observed lower bound was established: "+err.Error())
		}
		// Applied after the corpus so a PROBED floor can outrank an OBSERVED one: a request we
		// sent and watched work outranks a reading of somebody else's traffic.
		applyProbeHistory(ctx, &p, tok.ID)
		p.Refresh = DetectRefreshCapability(ctx, tok, p)
	}
	return p
}

// applyObservation folds a corpus reading into a profile WITHOUT ever letting it become the TTL.
func applyObservation(p *SessionTokenProfile, obs CorpusObservation) {
	p.ObservedSamples = obs.Samples
	p.ObservedRequests = obs.Requests
	p.ObservedEvidence = obs.Evidence
	if obs.Samples > 0 && obs.Floor > 0 {
		p.TTLFloor, p.TTLFloorKnown = obs.Floor, true
		p.TTLFloorProvenance = ProvObserved
		p.TTLFloorEvidence = obs.Evidence
	}
	if obs.RotationInterval > 0 {
		p.RotationInterval, p.RotationKnown = obs.RotationInterval, true
	}
	// A floor that EXCEEDS a parsed TTL is not a better measurement, it is a contradiction, and
	// the most likely explanation is that the carrier is sliding: the same value kept working past
	// the lifetime the token declared.
	if p.TTLKnown && p.TTLFloorKnown && p.TTLFloor > p.TTL+time.Minute {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"the corpus shows one value still in use %s after it appeared, which is longer than the %s lifetime the credential declares; the expiry may be sliding, or the captures may span a clock change",
			humaniseTTL(p.TTLFloor), humaniseTTL(p.TTL)))
	}
}

// CarrierForSessionToken derives how a stored row travels.
func CarrierForSessionToken(tok SessionToken) CredentialCarrier {
	c := CredentialCarrier{Kind: tok.TokenType, Prefix: tok.ValuePrefix}
	switch tok.TokenType {
	case tokenTypeCookie:
		c.Name = tok.CookieName
	case tokenTypeQuery:
		c.Name = tok.ParamName
	case tokenTypeBearer:
		c.Kind = "header"
		c.Name = tok.HeaderName
		if c.Name == "" {
			c.Name = "Authorization"
		}
		if c.Prefix == "" {
			c.Prefix = "Bearer "
		}
	default:
		c.Kind = "header"
		c.Name = tok.HeaderName
		if c.Name == "" && tok.ParamName != "" {
			c.Kind = "query"
			c.Name = tok.ParamName
		}
	}
	return c
}

// ---------------------------------------------------------------------------------------------
// The refresh question
// ---------------------------------------------------------------------------------------------

// refreshEndpointPatterns are paths that mint or renew a credential. They are matched against the
// captured corpus, so a hit is evidence the APPLICATION has such an endpoint, not a guess that it
// might.
var refreshEndpointPatterns = []struct {
	re        *regexp.Regexp
	mechanism RefreshMechanism
	what      string
}{
	{regexp.MustCompile(`(?i)/(oauth2?|connect)/token(/|$|\?)`), RefreshMechanismTokenEndpoint, "an OAuth 2 token endpoint"},
	{regexp.MustCompile(`(?i)/token(/|$|\?)`), RefreshMechanismTokenEndpoint, "a token endpoint"},
	{regexp.MustCompile(`(?i)/(auth|session|token)s?/refresh(/|$|\?)`), RefreshMechanismSilentRenew, "a session refresh endpoint"},
	{regexp.MustCompile(`(?i)/refresh[-_]?token(/|$|\?)`), RefreshMechanismSilentRenew, "a refresh-token endpoint"},
	{regexp.MustCompile(`(?i)/(silent[-_]?renew|renew)(/|$|\?)`), RefreshMechanismSilentRenew, "a silent renew endpoint"},
	{regexp.MustCompile(`(?i)/authorize\?.*prompt=none`), RefreshMechanismSilentRenew, "an OIDC prompt=none silent authentication"},
}

// reDoNotReplay catches the label an operator puts on a flow they have decided must not be run.
// Honouring it is not optional: on the live target the session is minted at a host outside the
// engagement, and the flow is named exactly this.
var reDoNotReplay = regexp.MustCompile(`(?i)do not replay|out of scope|do-not-replay`)

// DetectRefreshCapability answers whether this session can be renewed, and by what.
//
// THE STRICTNESS IS THE POINT. A refresh_token field in a response body is RefreshAvailable, never
// RefreshProven. Proven means somebody performed the refresh and a DIFFERENT credential came back,
// which is the same standard this codebase applies to a vulnerability: validated requires a proof
// of concept, and "the field exists" is the IF in a vulnerable-IF with the IF unproven.
//
// SCOPE IS A SEPARATE AXIS FROM POSSIBILITY. A mechanism whose mint host is outside the engagement
// is reported as mint_out_of_scope and never as unrefreshable. The operator can very often
// re-authenticate by hand in a browser and paste a new value in, which is a different plan from
// "this session cannot be renewed", and collapsing the two loses the one piece of advice that
// would have helped.
func DetectRefreshCapability(ctx context.Context, tok SessionToken, p SessionTokenProfile) RefreshCapability {
	out := RefreshCapability{Status: RefreshNotObserved, Mechanism: RefreshMechanismNone}
	if ctx == nil || dbPool == nil {
		out.Evidence = append(out.Evidence, "no database connection, so no refresh mechanism could be looked for")
		return out
	}

	scope := LoadScanScope(tok.ScopeTargetID)

	// (1) What has already been PROVEN. A refresh event recorded against this token with a status
	// of success is the only thing that earns proven, and it is looked for first so nothing weaker
	// can overwrite it.
	var provenAt *time.Time
	var provenDetail string
	_ = dbPool.QueryRow(ctx, `
		SELECT created_at, COALESCE(detail,'') FROM session_token_events
		WHERE session_token_id = $1 AND kind = 'refresh' AND status = 'success'
		ORDER BY created_at DESC LIMIT 1`, tok.ID).Scan(&provenAt, &provenDetail)

	// (2) The auth flow the operator tied to this token.
	if tok.AuthFlowID != "" {
		var flowName, baseURL string
		var steps int
		if dbPool.QueryRow(ctx, `
			SELECT f.name, COALESCE(f.base_url,''),
			       (SELECT count(*) FROM auth_flow_steps s WHERE s.auth_flow_id = f.id)
			FROM auth_flows f WHERE f.id = $1`, tok.AuthFlowID).Scan(&flowName, &baseURL, &steps) == nil {

			host := hostOfRawURL(baseURL)
			out.Mechanism = RefreshMechanismAuthFlow
			out.MintHost = host
			out.MintInScope = host != "" && scope != nil && scope.Allows(host)

			switch {
			case reDoNotReplay.MatchString(flowName):
				out.Status = RefreshMintOutOfScope
				out.MintInScope = false
				out.Evidence = append(out.Evidence, fmt.Sprintf(
					"the linked auth flow %q is labelled do-not-replay, so the mint is documented but must not be exercised from here", flowName))
			case steps == 0:
				out.Status = RefreshNotObserved
				out.Evidence = append(out.Evidence, fmt.Sprintf(
					"the linked auth flow %q has no executable steps, so it documents the mint without being able to perform it", flowName))
			case !out.MintInScope:
				out.Status = RefreshMintOutOfScope
				out.Evidence = append(out.Evidence, fmt.Sprintf(
					"the linked auth flow %q mints at %s, which is outside this engagement's scope", flowName, host))
			default:
				out.Status = RefreshAvailable
				out.Evidence = append(out.Evidence, fmt.Sprintf(
					"the linked auth flow %q has %d executable steps against %s, which is in scope, but it has not been replayed to prove it yields a new credential",
					flowName, steps, host))
			}
		}
	}

	// (3) The issuer the credential names. For a JWT this is a parsed fact about where it came
	// from, and it is often a host nobody put in an auth flow.
	if issuer := p.Attributes["iss"]; issuer != "" {
		if host := hostOfRawURL(issuer); host != "" {
			inScope := scope != nil && scope.Allows(host)
			if out.MintHost == "" {
				out.MintHost = host
				out.MintInScope = inScope
			}
			verdict := "outside this engagement's scope"
			if inScope {
				verdict = "inside this engagement's scope"
			}
			out.Evidence = append(out.Evidence, fmt.Sprintf(
				"the credential names %s as its issuer, which is %s", host, verdict))
			if !inScope && out.Status == RefreshNotObserved {
				out.Status = RefreshMintOutOfScope
			}
		}
	}

	// (4) Endpoints in the captured corpus that mint or renew.
	if found, mech, what, host := findRefreshEndpoint(ctx, tok.ScopeTargetID); found {
		inScope := host != "" && scope != nil && scope.Allows(host)
		out.Evidence = append(out.Evidence, fmt.Sprintf(
			"the captured corpus contains %s at %s", what, host))
		if out.Mechanism == RefreshMechanismNone {
			out.Mechanism = mech
			out.MintHost = host
			out.MintInScope = inScope
		}
		switch {
		case out.Status == RefreshProven:
		case !inScope:
			if out.Status != RefreshAvailable {
				out.Status = RefreshMintOutOfScope
			}
		default:
			if out.Status == RefreshNotObserved {
				out.Status = RefreshAvailable
			}
		}
	}

	// (5) A refresh_token beside the access token. Evidence of a mechanism, never of a refresh.
	if n, latest := refreshTokenBodies(ctx, tok.ScopeTargetID); n > 0 {
		line := fmt.Sprintf(
			"%d captured response(s) carry a refresh_token field, so the grant exists; that a field exists is NOT evidence a refresh works", n)
		if latest != "" {
			line += ", and the most recently captured one is " + latest
		}
		out.Evidence = append(out.Evidence, line)
		if out.Mechanism == RefreshMechanismNone {
			out.Mechanism = RefreshMechanismOAuthRefresh
		}
		if out.Status == RefreshNotObserved {
			out.Status = RefreshAvailable
		}
	}

	// (1) again, applied last so it outranks everything weaker.
	if provenAt != nil {
		out.Status = RefreshProven
		out.ProvenAt = provenAt.UTC()
		detail := provenDetail
		if detail == "" {
			detail = "a refresh was performed and recorded"
		}
		out.Evidence = append(out.Evidence, "PROVEN: "+detail)
	}

	if len(out.Evidence) == 0 {
		out.Evidence = append(out.Evidence,
			"no auth flow, no issuer, no token or renew endpoint in the corpus and no refresh_token field; nothing was found, which is not the same as there being nothing")
	}
	return out
}

// findRefreshEndpoint looks for a minting endpoint in the captured corpus.
func findRefreshEndpoint(ctx context.Context, scopeTargetID string) (bool, RefreshMechanism, string, string) {
	rows, err := dbPool.Query(ctx, `
		SELECT DISTINCT url FROM manual_crawl_captures
		WHERE scope_target_id = $1
		  AND url ~* '(token|refresh|renew|authorize)'
		LIMIT 500`, scopeTargetID)
	if err != nil {
		return false, RefreshMechanismNone, "", ""
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		for _, pat := range refreshEndpointPatterns {
			if pat.re.MatchString(raw) {
				return true, pat.mechanism, pat.what, hostOfRawURL(raw)
			}
		}
	}
	return false, RefreshMechanismNone, "", ""
}

// refreshTokenBodies counts the captured responses carrying a refresh_token field and returns the
// most recently captured refresh token among them.
//
// THE VALUE COMES BACK WITH THE COUNT. A refresh token sitting in a captured response IS a
// credential, and the operator reading "the grant exists" is reading a sentence about something
// they should be able to see: a refresh token is what a session is renewed from, and a report that
// says one is there without saying what it is cannot be checked or used. It is pulled out in
// Postgres, the same way the access token beside it already is, so a body long enough to be cut
// still yields the credential it carried.
func refreshTokenBodies(ctx context.Context, scopeTargetID string) (int, string) {
	var n int
	_ = dbPool.QueryRow(ctx, `
		SELECT count(*) FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND response_body LIKE '%"refresh_token"%'`, scopeTargetID).Scan(&n)
	if n == 0 {
		return 0, ""
	}
	var latest string
	_ = dbPool.QueryRow(ctx, `
		SELECT COALESCE(substring(c.response_body from '"refresh_token"[[:space:]]*:[[:space:]]*"([^"]*)"'), '')
		FROM manual_crawl_captures c
		WHERE c.scope_target_id = $1 AND c.response_body LIKE '%"refresh_token"%'
		ORDER BY COALESCE(c.timestamp, c.created_at) DESC
		LIMIT 1`, scopeTargetID).Scan(&latest)
	return n, strings.TrimSpace(latest)
}

// RecordRefreshProof is the ONLY way a profile reaches RefreshProven.
//
// It refuses unless two fingerprints are supplied and they DIFFER. A refresh that returned the
// same credential proved that the endpoint answered, not that it renewed anything, and recording
// that as proven would let a scan configuration gate turn renewal on for a session that cannot be
// renewed. This is the same rule as validated-requires-a-proof-of-concept, applied to ourselves.
//
// THE TWO CREDENTIALS GO ON THE EVENT AND INTO THE DETAIL, because two hashes that differ are an
// assertion and the two credentials are the proof of it. The event row and the refresh_detail
// column are what the Session Manager reads back, and an operator who cannot see what came back
// cannot check the claim, cannot replay it and cannot report it. They are passed as credentials,
// in that order: before, then after.
//
// WHY THEY ARE A TRAILING ARGUMENT AND NOT TWO MORE PARAMETERS. The one production caller,
// ProveSessionRefresh in sessionRefreshProof.go, holds both values and passes neither yet; widening
// the fixed signature would break it from a file this change is not allowed to touch. A caller with
// only the fingerprints still records a proof, and the row then carries what that caller had.
func RecordRefreshProof(ctx context.Context, tokenID, beforeFingerprint, afterFingerprint string, credentials ...string) error {
	before := strings.TrimSpace(beforeFingerprint)
	after := strings.TrimSpace(afterFingerprint)
	if before == "" || after == "" {
		return fmt.Errorf("a refresh proof needs the fingerprint of the credential before and after; %q and %q were given", before, after)
	}
	if before == after {
		return fmt.Errorf("the credential after the refresh has the same fingerprint (%s) as the one before, so the refresh returned the SAME credential and renewed nothing", before)
	}
	if dbPool == nil {
		return fmt.Errorf("no database connection")
	}
	var beforeValue, afterValue string
	if len(credentials) > 0 {
		beforeValue = strings.TrimSpace(credentials[0])
	}
	if len(credentials) > 1 {
		afterValue = strings.TrimSpace(credentials[1])
	}
	detail := fmt.Sprintf("a refresh was performed and a different credential came back: %s became %s", before, after)
	if beforeValue != "" && afterValue != "" {
		detail = fmt.Sprintf("a refresh was performed and a different credential came back: %s became %s, which is %s becoming %s",
			before, after, beforeValue, afterValue)
	}
	evidence := map[string]interface{}{
		"before_fingerprint": before,
		"after_fingerprint":  after,
	}
	if beforeValue != "" {
		evidence["before_value"] = beforeValue
	}
	if afterValue != "" {
		evidence["after_value"] = afterValue
	}
	recordSessionTokenEvent(tokenID, "refresh", "success", detail, evidence)
	_, err := dbPool.Exec(ctx, `
		UPDATE session_tokens
		SET refresh_status = 'proven', refresh_proven_at = NOW(), refresh_detail = $2,
		    last_refreshed_at = NOW(), updated_at = NOW()
		WHERE id = $1`, tokenID, detail)
	return err
}

// hostOfRawURL is a tolerant host extractor: a base_url column holds anything an operator typed.
func hostOfRawURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// ---------------------------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------------------------

// SessionTokenProfileSchema adds the profile columns to session_tokens.
//
// They live on session_tokens rather than in a table of their own because there is exactly one
// current profile per token and every reader of the token wants it. The existing expires_at,
// last_validated_at and last_refreshed_at columns stay: expires_at is the operator's DECLARED
// expiry and the new columns record what was measured, which is a different fact and is why both
// are kept rather than one overwriting the other.
var SessionTokenProfileSchema = []string{
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS credential_kind VARCHAR(32) DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS kind_evidence TEXT DEFAULT '';`,
	// NULL means unknown. A zero would read as "expires immediately", which is the single worst
	// available lie about a credential's lifetime.
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS ttl_seconds BIGINT;`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS ttl_provenance VARCHAR(16) DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS ttl_evidence TEXT DEFAULT '';`,
	// The observed lower bound is its OWN column. Writing it into ttl_seconds would make a floor
	// indistinguishable from a measurement the moment anybody read the row.
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS ttl_floor_seconds BIGINT;`,
	// How the floor was got. observed is the captured corpus, probed is a request the framework
	// sent and watched work; they are different strengths of evidence and the column keeps them
	// apart, so a reload does not turn a probe back into a reading of somebody else traffic.
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS ttl_floor_provenance VARCHAR(16) DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS ttl_floor_evidence TEXT DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS observed_samples INTEGER;`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS observed_requests INTEGER;`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS observed_evidence TEXT DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS rotation_interval_seconds BIGINT;`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS measured_expires_at TIMESTAMP;`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS expiry_provenance VARCHAR(16) DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS expiry_style VARCHAR(16) DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS expiry_evidence TEXT DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS issued_at TIMESTAMP;`,
	// WHAT was read to get that issue time. Without it a reload cannot tell an iat from an nbf,
	// and the screen renders the timestamp the same way either way.
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS issued_at_source VARCHAR(32) DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_status VARCHAR(24) DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_mechanism VARCHAR(32) DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_mint_host TEXT DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_mint_in_scope BOOLEAN;`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_detail TEXT DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_proven_at TIMESTAMP;`,
	// The fingerprint is the JOIN KEY: it is how a row, an event and a profile are recognised as
	// being about the same credential, and it is what RecordRefreshProof compares. It is a short
	// stable name for the credential and not a substitute for it; token_value holds the credential
	// itself and every reader of this row is served both.
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS value_fingerprint VARCHAR(16) DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS profile_warnings TEXT DEFAULT '';`,
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS profiled_at TIMESTAMP;`,
}

// EnsureSessionTokenProfileSchema applies the profile columns. It is idempotent and cheap enough
// to call from a handler.
func EnsureSessionTokenProfileSchema(ctx context.Context) error {
	if dbPool == nil {
		return fmt.Errorf("no database connection")
	}
	for _, stmt := range SessionTokenProfileSchema {
		if _, err := dbPool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

// ensureProfileSchema applies the migration at most once per process, and latches only on
// success, so an install whose database was not up when the first request arrived is not left
// permanently without the columns.
var (
	profileSchemaMu   sync.Mutex
	profileSchemaDone bool
)

func ensureProfileSchema(ctx context.Context) error {
	profileSchemaMu.Lock()
	defer profileSchemaMu.Unlock()
	if profileSchemaDone {
		return nil
	}
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		return err
	}
	profileSchemaDone = true
	return nil
}

// AttachSessionTokenProfiles fills in the Profile field of each token for a read endpoint.
//
// A STORED profile is used where there is one, and a token that has never been profiled is
// measured once and the result written back. Measuring on a read is a deliberate choice: the
// alternative is an operator opening the Session Manager and being shown UNKNOWN for a token the
// engine could have characterised in fifty milliseconds, and an unknown that is only unknown
// because nobody pressed a button is the kind of false silence this whole feature exists to end.
func AttachSessionTokenProfiles(ctx context.Context, tokens []SessionToken) {
	if dbPool == nil || len(tokens) == 0 {
		return
	}
	if err := ensureProfileSchema(ctx); err != nil {
		log.Printf("[SESSION-PROFILE] could not apply the profile columns, so no token was characterised: %v", err)
		return
	}
	for i := range tokens {
		stored, err := LoadSessionTokenProfile(ctx, tokens[i].ID)
		if err == nil && !stored.ProfiledAt.IsZero() && stored.Fingerprint == NewCredential(tokens[i].TokenValue).Fingerprint() {
			// The stored measurement describes THIS value. A fingerprint mismatch means the value
			// was replaced since, and a profile of the previous credential is worse than none.
			p := stored
			tokens[i].Profile = &p
			continue
		}
		measured := ProfileSessionToken(ctx, tokens[i])
		if saveErr := SaveSessionTokenProfile(ctx, measured); saveErr != nil {
			log.Printf("[SESSION-PROFILE] token %s was characterised but not stored: %v", tokens[i].ID, saveErr)
		}
		p := measured
		tokens[i].Profile = &p
	}
}

// ReprofileSessionToken re-measures one token after its value changed. Failures are logged and
// never propagated: a profile is a measurement of a credential, and not being able to take one is
// not a reason to refuse the operator's write.
func ReprofileSessionToken(ctx context.Context, tokenID string) {
	if dbPool == nil || tokenID == "" {
		return
	}
	if err := ensureProfileSchema(ctx); err != nil {
		log.Printf("[SESSION-PROFILE] could not apply the profile columns: %v", err)
		return
	}
	tok, err := loadSessionToken(tokenID)
	if err != nil {
		log.Printf("[SESSION-PROFILE] token %s could not be loaded to characterise: %v", tokenID, err)
		return
	}
	p := ProfileSessionToken(ctx, tok)
	if err := SaveSessionTokenProfile(ctx, p); err != nil {
		log.Printf("[SESSION-PROFILE] token %s was characterised but not stored: %v", tokenID, err)
		return
	}
	log.Printf("[SESSION-PROFILE] %s: %v", tok.Name, p)
}

// SaveSessionTokenProfile writes a profile back onto its row.
//
// NULL is written for every unknown. A zero in ttl_seconds would be read by the next caller as a
// lifetime of nothing, and this whole file exists because a number that means "we did not measure"
// is indistinguishable from one that means "we measured zero" once it is in a column.
func SaveSessionTokenProfile(ctx context.Context, p SessionTokenProfile) error {
	if dbPool == nil {
		return fmt.Errorf("no database connection")
	}
	if p.TokenID == "" {
		return fmt.Errorf("the profile has no token id, so there is no row to write it to")
	}
	_, err := dbPool.Exec(ctx, `
		UPDATE session_tokens SET
			credential_kind = $2, kind_evidence = $3,
			ttl_seconds = $4, ttl_provenance = $5, ttl_evidence = $6,
			ttl_floor_seconds = $7, observed_samples = $8, observed_requests = $9,
			observed_evidence = $10, rotation_interval_seconds = $11,
			measured_expires_at = $12, expiry_provenance = $13, expiry_style = $14,
			expiry_evidence = $15, issued_at = $16, issued_at_source = $28,
			refresh_status = $17, refresh_mechanism = $18, refresh_mint_host = $19,
			refresh_mint_in_scope = $20, refresh_detail = $21, refresh_proven_at = $22,
			value_fingerprint = $23, profile_warnings = $24, profiled_at = $25,
			ttl_floor_provenance = $26, ttl_floor_evidence = $27
		WHERE id = $1`,
		p.TokenID,
		string(p.Kind), p.KindEvidence,
		nullSeconds(p.TTL, p.TTLKnown), string(p.TTLProvenance), p.TTLEvidence,
		nullSeconds(p.TTLFloor, p.TTLFloorKnown), nullInt(p.ObservedSamples), nullInt(p.ObservedRequests),
		p.ObservedEvidence, nullSeconds(p.RotationInterval, p.RotationKnown),
		nullTime(p.ExpiresAt, p.ExpiryKnown), string(p.ExpiryProvenance), string(p.ExpiryStyle),
		p.ExpiryEvidence, nullTime(p.IssuedAt, p.IssuedAtKnown),
		string(p.Refresh.Status), string(p.Refresh.Mechanism), p.Refresh.MintHost,
		p.Refresh.MintInScope, strings.Join(p.Refresh.Evidence, "\n"),
		nullTime(p.Refresh.ProvenAt, !p.Refresh.ProvenAt.IsZero()),
		p.Fingerprint, strings.Join(p.Warnings, "\n"), p.ProfiledAt,
		string(p.floorProvenanceStored()), p.TTLFloorEvidence, string(p.IssuedAtSource))
	return err
}

// LoadSessionTokenProfile reads back what was stored, so a UI can render the last measurement
// without re-profiling.
func LoadSessionTokenProfile(ctx context.Context, tokenID string) (SessionTokenProfile, error) {
	p := SessionTokenProfile{
		TokenID:          tokenID,
		Kind:             CredentialKindUnknown,
		TTLProvenance:    ProvUnknown,
		ExpiryProvenance: ProvUnknown,
		ExpiryStyle:      ExpiryStyleUnknown,
		Attributes:       map[string]string{},
		Refresh:          RefreshCapability{Status: RefreshNotObserved},
	}
	if dbPool == nil {
		return p, fmt.Errorf("no database connection")
	}
	var (
		kind, kindEv, ttlProv, ttlEv                     string
		obsEv, expProv, expStyle, expEv                  string
		refStatus, refMech, refHost, refDetail, warnings string
		floorProv, floorEv, issuedSource                 string
		fingerprint, name, scopeTargetID                 string
		ttlSecs, floorSecs, rotSecs                      *int64
		samples, requests                                *int32
		measuredExp, issuedAt, provenAt, profiledAt      *time.Time
		mintInScope                                      *bool
	)
	err := dbPool.QueryRow(ctx, `
		SELECT COALESCE(credential_kind,''), COALESCE(kind_evidence,''),
		       ttl_seconds, COALESCE(ttl_provenance,''), COALESCE(ttl_evidence,''),
		       ttl_floor_seconds, COALESCE(ttl_floor_provenance,''), COALESCE(ttl_floor_evidence,''),
		       observed_samples, observed_requests,
		       COALESCE(observed_evidence,''), rotation_interval_seconds,
		       measured_expires_at, COALESCE(expiry_provenance,''), COALESCE(expiry_style,''),
		       COALESCE(expiry_evidence,''), issued_at, COALESCE(issued_at_source,''),
		       COALESCE(refresh_status,''), COALESCE(refresh_mechanism,''),
		       COALESCE(refresh_mint_host,''), refresh_mint_in_scope,
		       COALESCE(refresh_detail,''), refresh_proven_at,
		       COALESCE(value_fingerprint,''), COALESCE(profile_warnings,''), profiled_at,
		       name, scope_target_id::text
		FROM session_tokens WHERE id = $1`, tokenID).Scan(
		&kind, &kindEv, &ttlSecs, &ttlProv, &ttlEv,
		&floorSecs, &floorProv, &floorEv, &samples, &requests, &obsEv, &rotSecs,
		&measuredExp, &expProv, &expStyle, &expEv, &issuedAt, &issuedSource,
		&refStatus, &refMech, &refHost, &mintInScope, &refDetail, &provenAt,
		&fingerprint, &warnings, &profiledAt, &name, &scopeTargetID)
	if err != nil {
		return p, err
	}

	p.Name, p.ScopeTargetID, p.Fingerprint = name, scopeTargetID, fingerprint
	if kind != "" {
		p.Kind = CredentialKind(kind)
	}
	p.KindEvidence = kindEv
	if ttlSecs != nil {
		p.TTL, p.TTLKnown = time.Duration(*ttlSecs)*time.Second, true
	}
	if ttlProv != "" {
		p.TTLProvenance = Provenance(ttlProv)
	}
	p.TTLEvidence = ttlEv
	if floorSecs != nil {
		p.TTLFloor, p.TTLFloorKnown = time.Duration(*floorSecs)*time.Second, true
	}
	if floorProv != "" {
		p.TTLFloorProvenance = Provenance(floorProv)
	}
	p.TTLFloorEvidence = floorEv
	if samples != nil {
		p.ObservedSamples = int(*samples)
	}
	if requests != nil {
		p.ObservedRequests = int(*requests)
	}
	p.ObservedEvidence = obsEv
	if rotSecs != nil {
		p.RotationInterval, p.RotationKnown = time.Duration(*rotSecs)*time.Second, true
	}
	if measuredExp != nil {
		p.ExpiresAt, p.ExpiryKnown = measuredExp.UTC(), true
	}
	if expProv != "" {
		p.ExpiryProvenance = Provenance(expProv)
	}
	if expStyle != "" {
		p.ExpiryStyle = ExpiryStyle(expStyle)
	}
	p.ExpiryEvidence = expEv
	if issuedAt != nil {
		p.IssuedAt, p.IssuedAtKnown = issuedAt.UTC(), true
		p.IssuedAtSource = IssuedAtSource(issuedSource)
	}
	if refStatus != "" {
		p.Refresh.Status = RefreshStatus(refStatus)
	}
	p.Refresh.Mechanism = RefreshMechanism(refMech)
	p.Refresh.MintHost = refHost
	if mintInScope != nil {
		p.Refresh.MintInScope = *mintInScope
	}
	if refDetail != "" {
		p.Refresh.Evidence = strings.Split(refDetail, "\n")
	}
	if provenAt != nil {
		p.Refresh.ProvenAt = provenAt.UTC()
	}
	if warnings != "" {
		p.Warnings = strings.Split(warnings, "\n")
	}
	if profiledAt != nil {
		p.ProfiledAt = profiledAt.UTC()
	}
	return p, nil
}

// ProfileAndSaveSessionToken is the one call a handler or a scan wants: measure, then persist.
func ProfileAndSaveSessionToken(ctx context.Context, tok SessionToken) (SessionTokenProfile, error) {
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		return SessionTokenProfile{}, err
	}
	p := ProfileSessionToken(ctx, tok)
	return p, SaveSessionTokenProfile(ctx, p)
}

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

func setIf(m map[string]string, key, value string) {
	if v := strings.TrimSpace(value); v != "" {
		m[key] = v
	}
}

func nullSeconds(d time.Duration, known bool) interface{} {
	if !known {
		return nil
	}
	return int64(d / time.Second)
}

func nullTime(t time.Time, known bool) interface{} {
	if !known || t.IsZero() {
		return nil
	}
	return t.UTC()
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// humaniseTTL renders a lifetime the way an operator reads one. A TTL of 900 seconds is
// "15m", not "15m0s", and a sub-second one is not rendered as "0".
func humaniseTTL(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	neg := ""
	if d < 0 {
		neg, d = "-", -d
	}
	d = d.Round(time.Second)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	mins := int(d / time.Minute)
	secs := int((d - time.Duration(mins)*time.Minute) / time.Second)

	var parts []string
	if days > 0 {
		parts = append(parts, strconv.Itoa(days)+"d")
	}
	if hours > 0 {
		parts = append(parts, strconv.Itoa(hours)+"h")
	}
	if mins > 0 {
		parts = append(parts, strconv.Itoa(mins)+"m")
	}
	if secs > 0 || len(parts) == 0 {
		parts = append(parts, strconv.Itoa(secs)+"s")
	}
	return neg + strings.Join(parts, "")
}
