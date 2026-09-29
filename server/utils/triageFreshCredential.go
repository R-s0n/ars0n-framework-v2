package utils

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------------------------
// THE FRESHEST CREDENTIAL THIS RUN CAN PUT ON THE WIRE, AND WHERE IT COMES FROM
// ---------------------------------------------------------------------------------------------
//
// MEASURED ON THE LIVE TARGET, 2026-09-20. One endpoint, one host, one mandatory header, two
// credentials out of two different tables:
//
//	the token in attack_vectors.raw_request, which is what the triage runner replays  -> 401
//	the token in manual_crawl_captures, captured 12:09:43 the same day                -> 200
//
// The corpus is days old and the application's bearer lives about fifteen minutes. So the runner
// was not measuring the application at all on the 170 of 317 vectors whose captured request
// carries an Authorization header: it was replaying a corpse and fingerprinting the wall that
// refused it. That is the false clean this whole layer exists to refuse, arriving through the
// transport instead of through a classifier.
//
// A FULL RUN TAKES ABOUT 1,757 SECONDS. THE TOKEN LIVES ABOUT 900. Substituting once, at unit
// setup, would fix the first half of a run and hand the second half the same corpse, so the
// source is asked again DURING the run and the trigger is defended below.
//
// THIS SOURCE NEVER MINTS. It runs two SELECTs and nothing else. The host that issues the token
// on the live engagement is OUT OF SCOPE, and the stored auth flow for it is named
// "DO NOT REPLAY - OUT OF SCOPE HOST". Everything here consumes credentials a browser already
// produced and the manual crawl already captured; when nothing fresh has been captured, the
// answer is to SAY SO, not to go and get one.
//
// IT PRINTS WHAT IT HOLDS. A captured credential is evidence: the operator is looking at their
// own tool, at material their own crawl captured, and a reason string that described a token
// without showing it could not be checked against the wire. Values go into the String, the log
// lines and the reason strings verbatim.

// triageFreshCredTTL is the floor on how often one host's credentials are re-read.
//
// THE TRIGGER IS THREE THINGS AND NOT ONE, because any single one of them is wrong in a way this
// engagement would hit:
//
//   - A TTL FLOOR (this constant). It bounds the cost: two queries per host per half minute over
//     a 29 minute run is about 60 reads, against tens of thousands of probes. A per-request read
//     would be correct and would put a database round trip in front of every probe.
//   - AN EXPIRY MARGIN (triageFreshCredMargin). A TTL alone is a clock that knows nothing about
//     the token. When the credential in hand dies within the margin, the cache is refused
//     whatever the TTL says, so the run reaches for the next captured token as soon as one can
//     help rather than up to a TTL late.
//   - INVALIDATION ON THE FIRST REFUSAL (Invalidate, called from the runner when a response
//     refuses a credential). This is the trigger that does not depend on our arithmetic being
//     right about anybody else's clock: if the target says no, we stop trusting what we hold and
//     re-read before the next probe.
//
// What none of them do is make a request. The only way a fresher credential appears is that a
// browser produced one and the crawl captured it.
const triageFreshCredTTL = 30 * time.Second

// triageFreshCredMargin is how close to its expiry a credential may come before this source stops
// treating the copy it holds as usable and re-reads, and how far in the future an expiry must be
// for a candidate to count as fresh at all. Sixty seconds is a little over one probe's timeout
// plus its pacing wait, so a credential handed out at the edge of the margin is still alive when
// the response comes back.
const triageFreshCredMargin = 60 * time.Second

// triageFreshCredRefusalFloor is the minimum interval between two re-reads of the SAME host
// caused by refusals of the SAME credential.
//
// THE THIRD TRIGGER DEFEATED THE FIRST TWO EXACTLY WHERE THEY MATTERED. Invalidation on refusal
// is right, and unbounded it is also the live shape: 170 vectors behind a wall means every probe
// answers 401, every 401 invalidates, and every following probe pays a full re-read. The TTL that
// was sized for about 60 reads over a 29 minute run becomes one read per probe, in front of
// tens of thousands of probes, and the run is slowest precisely when it is learning nothing.
//
// WHAT THE FLOOR DOES NOT DO IS SUPPRESS NEW INFORMATION. A refusal is only floored when the
// credential set this source is handing out for the host is THE SAME ONE that was already
// disproved: same carriers, same fingerprints, same order. The moment a re-read produces a
// different set, or the moment the set that was refused is a different one from the set refused
// last time, the next refusal is honoured immediately whatever the clock says. So a rotation is
// picked up on the first refusal of the new token and never waits out the floor.
//
// FIVE SECONDS, and the number is a bound on waste rather than a guess about a target. Worst
// case it delays noticing a credential captured by a browser BETWEEN two refusals of the same
// dead one by up to five seconds, which is under one probe timeout; in exchange a wall of
// identical 401s costs at most one re-read per five seconds per host instead of one per probe.
const triageFreshCredRefusalFloor = 5 * time.Second

// triageFreshCredCaptureLimit is how many of a host's newest 2xx captures are read per refresh.
// The rows are ordered newest first and only the best candidate per carrier survives ranking, so
// this is a bound on work and not on coverage.
const triageFreshCredCaptureLimit = 200

// triageFreshCredDeadKeep bounds the dead candidates one read carries out.
//
// IT IS A BOUND ON ROWS AND NOT ON THE ANSWER. The dedupe is per CARRIER and keeps the latest
// expiry, so a rotating accessToken read out of two hundred captures collapses to one row, the
// freshest reading of its own lifetime, long before this cap is reached. What the cap bounds is a
// host whose jars carry many DIFFERENT dead carriers, and there the card wants a handful of
// lifetimes rather than a list.
const triageFreshCredDeadKeep = 8

// triageFreshCred is ONE credential this run may put on the wire for one host.
//
// Exactly one of Header and Cookie is set: a credential is a named carrier, and a substitution
// that did not know which carrier it was would either overwrite the wrong field or invent one.
type triageFreshCred struct {
	// Header is the canonical field name for a header credential, "" for a cookie one.
	Header string
	// Cookie is the cookie name for a cookie credential, "" for a header one.
	Cookie string

	// value is the bytes that go on the wire, and the bytes String prints.
	value string

	// Source names the table this came out of, in the operator's words.
	Source string
	// Observed is when the row that carried it was written: the capture's created_at, or the
	// session token's updated_at.
	Observed time.Time
	// Expires is when this credential stops being usable, read from the credential ITSELF where
	// it can be (a JWT carries its own exp) and from the stored column otherwise. Zero means
	// neither could be read, which is a WEAKER position than a distant expiry and is ranked as
	// one.
	Expires time.Time
	// ExpirySource says which of those two answered, so a row can be audited rather than
	// believed.
	ExpirySource string
	// Fingerprint is a COMPARISON KEY: the first eight hex digits of the value's SHA-256. Two
	// rows carrying the same fingerprint are the same token; a run that rotated shows two
	// different ones. It is a short stand-in for an equality test between long values, and it
	// never stands in for the value itself, which String prints beside it.
	Fingerprint string
}

// Carrier is the name this credential rides under, for a reason string.
//
// THE NAME IS PRINTED AS THE STORE HOLDS IT. An auth SDK puts the account in the storage key:
// Amplify writes CognitoIdentityServiceProvider.<client id>.<subject>.<leaf>, and the subject in
// it is exactly what tells two signed-in accounts apart on the card. It is the operator's own
// captured jar and the whole point of the card is to say which account went on the wire.
func (c triageFreshCred) Carrier() string {
	if c.Header != "" {
		return c.Header + " header"
	}
	if c.Cookie != "" {
		return c.Cookie + " cookie"
	}
	return "an unnamed carrier"
}

// String renders this credential, value included, so that a caller who formats one with %v sees
// what actually went on the wire.
func (c triageFreshCred) String() string {
	exp := "no readable expiry"
	if !c.Expires.IsZero() {
		exp = "expiring " + c.Expires.UTC().Format(time.RFC3339) + " per " + c.ExpirySource
	}
	return fmt.Sprintf("%s from %s, fingerprint %s, %s, value %s",
		c.Carrier(), c.Source, c.Fingerprint, exp, c.value)
}

// Value is the bytes this credential puts on the wire. It exists so callers outside this file
// can record and report what was sent.
func (c triageFreshCred) Value() string { return c.value }

// triageFreshCredStatus is what the source knows about one host right now. It is the material a
// reason string is allowed to assert, and nothing in it is a guess: every field is either a count
// of rows read or a timestamp off one of them.
type triageFreshCredStatus struct {
	Host string
	// Fresh is how many usable credentials this source is handing out for the host.
	Fresh int
	// Verifiable is how many of those Fresh credentials carry an expiry this source could READ:
	// a JWT's own exp claim, or the session_tokens.expires_at column. Those are the only two
	// things in this file that can ever tell the run a credential has died.
	//
	// IT EXISTS BECAUSE Fresh CANNOT ANSWER THE QUESTION EXHAUSTION ASKS. A credential with no
	// readable expiry is never dropped by triageFreshCredDead, so it holds the set non-empty for
	// the whole run whatever happened to the credentials that actually authenticate. On the live
	// estate that is a five segment JWE refreshToken and a randomPasswordKey, neither of which
	// will ever leave the set, beside an accessToken and an idToken that live 300 seconds.
	Verifiable int
	// Expired is how many candidates it read and REJECTED because their own expiry had passed.
	// Counted so "no credential" can say whether there was never one or whether the last one
	// died.
	Expired int
	// Dead carries the candidates BEHIND that count: one per carrier, latest expiry first,
	// capped at triageFreshCredDeadKeep. A COUNT CANNOT ANSWER A QUESTION ABOUT A LIFETIME.
	//
	// WHY IT IS HERE. exp minus iat is a lifetime whether or not the clock has passed exp, so a
	// credential this source rejected still knows how long a session on that host lasts. With
	// only the count, the Authentication card answered "how long does a session on this
	// application last" out of whatever stored row happened to survive, which on the measured
	// estate was an operator-typed bearer from a DIFFERENT ISSUER than the application under
	// test. See sessionLifetimeSource.
	//
	// WHAT IT IS NOT. It is NOT a credential this run may send. Nothing in this slice is ever
	// returned by FreshFor, counted in Fresh or Verifiable, ranked beside the live candidates or
	// substituted onto a probe: the two sites that fill it are the branches that CONTINUE past
	// the candidate append. A captured cookie reaches it only after the substitution rule has
	// already agreed to send that cookie, so one held back as somebody else's is not in here
	// either.
	Dead []triageFreshCred
	// Newest is the latest expiry among the usable credentials, zero when none of them carries a
	// readable one.
	Newest time.Time
	// ReadAt is when the source last actually queried, as opposed to answered from cache.
	ReadAt time.Time
	// LastFreshAt is the last wall-clock moment this source had ANY usable credential for the
	// host. It is what makes exhaustion observable.
	LastFreshAt time.Time
	// LastVerifiableAt is the last wall-clock moment this source had any credential with a
	// READABLE EXPIRY for the host. It is to Verifiable what LastFreshAt is to Fresh, and it is
	// the memory the second exhaustion is measured against.
	LastVerifiableAt time.Time
	// ExhaustionKind names WHICH exhaustion fired, and it is a separate field rather than a
	// sentence because the two have different next moves and must not share a sentence. Empty
	// when Exhausted is false.
	ExhaustionKind string
	// NeverVerifiable is the FIRST-READ fact, and it is deliberately NOT an exhaustion: this
	// source is handing credentials out for this host and has never, on any read in this run,
	// held one whose lifetime it could read. Nothing was lost, so there is no transition to
	// report and Exhausted stays false; what there is instead is a run that could not have
	// reported the loss even if it happened, and that deserves saying out loud rather than
	// reading as not-yet-exhausted. See triageCredNeverVerifiableClause.
	NeverVerifiable bool
	// Unmeasured names the carriers this source is still handing out whose expiry it could not
	// read, capped, with the overflow counted.
	Unmeasured []string
	// Exhausted is the state this file was written to make impossible to miss: this run DID hold
	// a usable credential for this host and now holds none. A run that silently stops
	// authenticating produces a wall of 401s that reads exactly like a target refusing everyone.
	Exhausted bool
	// Note is why there is nothing usable, in words, when Fresh is zero. It reports what was read
	// and rejected; it never names a cause it did not observe.
	Note string
	// Declined names the captured carriers that WOULD have been substituted under the old rule
	// and were held back, each with the reason, so a narrowing that can lose a real credential is
	// visible rather than silent.
	Declined []string
}

// triageFreshCredSource is the runner's view of the credential store. It is an interface for the
// one reason an interface earns its place here: the rotation this run has to survive happens on
// somebody else's clock, and a test cannot reproduce it through a database.
type triageFreshCredSource interface {
	// FreshFor returns the usable credentials for exactly this host, with the reading that
	// produced them.
	FreshFor(host string) ([]triageFreshCred, triageFreshCredStatus)
	// Invalidate discards the cached reading for a host, so the next FreshFor re-reads. Called
	// when the target refuses a credential: at that point what we hold is disproved and a TTL is
	// no longer a reason to keep using it.
	Invalidate(host string)
}

// triageDBFreshCreds reads the two tables a browser session actually lands in.
type triageDBFreshCreds struct {
	scopeTargetID string
	// defaultDomain is the registrable domain of this run's scope target, used to scope a
	// session_tokens row that declares no domains of its own.
	//
	// READ ONCE, AT CONSTRUCTION, because the scope target is immutable for the run. It used to
	// be re-derived inside sessionTokenCandidates, which made every credential refresh THREE
	// SELECTs rather than two: session_tokens, manual_crawl_captures, and a scope_targets read
	// whose answer cannot change between the first probe and the last. With the refusal floor
	// above bounding how often a refresh happens at all, this is the other half of the same
	// cost: fewer refreshes, and each one a query cheaper.
	defaultDomain string

	mu    sync.Mutex
	cache map[string]*triageFreshCredEntry
	// anon is the captured-jar reading per host, built once and kept for the whole run. It is
	// NOT under the thirty second TTL the credential cache is under, and deliberately: it
	// describes a corpus that was written before this run started and that nothing in this run
	// adds to, so re-reading it on every refresh would be one full-table scan per probe for an
	// answer that cannot have changed. Guarded by mu, which FreshFor already holds when read
	// calls into this.
	anon map[string]*triageAnonWindow
}

type triageFreshCredEntry struct {
	creds  []triageFreshCred
	status triageFreshCredStatus

	// The refusal floor, per host. refusedPrint is the credential set that the last HONOURED
	// invalidation disproved, named by fingerprint because this string is only ever compared
	// against the next one; refusedAt is when that happened. honoured and floored are counted so the cost of the trigger is
	// measurable rather than asserted.
	refusedPrint string
	refusedAt    time.Time
	honoured     int
	floored      int

	// declinedPrint is the decline set that has already been reported for this host, so a
	// narrowing is said ONCE per host per distinct set rather than on every refresh. A refresh
	// that produces a DIFFERENT set is new information about the jar and is said again.
	declinedPrint string
}

// newTriageFreshCredentials builds the live source for one scope target.
func newTriageFreshCredentials(scopeTargetID string) *triageDBFreshCreds {
	// ScopeTargetBase is nil-pool safe and returns empty strings without a database, which is
	// exactly what the per-call version returned in that case too, so moving the read here
	// changes cost and not behaviour.
	_, targetHost, _ := ScopeTargetBase(scopeTargetID)
	return &triageDBFreshCreds{
		scopeTargetID: scopeTargetID,
		defaultDomain: RegistrableDomain(strings.ToLower(targetHost)),
		cache:         map[string]*triageFreshCredEntry{},
		anon:          map[string]*triageAnonWindow{},
	}
}

func (s *triageDBFreshCreds) Invalidate(host string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.cache[strings.ToLower(strings.TrimSpace(host))]
	if !ok {
		// Nothing cached for this host, so there is nothing to revoke and the next FreshFor
		// reads anyway. Not counted either way: no trigger fired.
		return
	}
	// THE FLOOR. What is compared is the credential set being disproved, not the clock alone: a
	// refusal that names a DIFFERENT set from the one already disproved is new information and
	// is honoured immediately, which is what keeps a rotation from waiting out the floor.
	setPrint := triageCredSetPrint(e.creds)
	now := time.Now()
	if setPrint == e.refusedPrint && !e.refusedAt.IsZero() && now.Sub(e.refusedAt) < triageFreshCredRefusalFloor {
		e.floored++
		return
	}
	e.refusedPrint = setPrint
	e.refusedAt = now
	e.honoured++
	// The reading is KEPT so LastFreshAt survives and exhaustion stays observable; only its
	// freshness is revoked, by dating the read to the zero time.
	e.status.ReadAt = time.Time{}
}

// triageCredSetPrint is a COMPARISON KEY for a credential set, not a rendering of one. It is the
// carrier and the eight-character fingerprint of each credential in the order the source hands
// them out, so two sets compare equal only when the run would send the same thing again. The
// fingerprint is here because this string is only ever compared, never read for its material.
//
// AN EMPTY SET HAS ITS OWN NAME rather than the zero value of a string, because "this host has
// no credential" is a real state that must be distinguishable from "this entry has never been
// invalidated": both would otherwise print as "" and the first refusal after the cache went dry
// would be floored against a comparison that never happened.
func triageCredSetPrint(creds []triageFreshCred) string {
	if len(creds) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(creds))
	for _, c := range creds {
		parts = append(parts, c.Carrier()+"="+c.Fingerprint)
	}
	return strings.Join(parts, ",")
}

// invalidationCounts reports how many refusal-driven re-reads this source honoured and how many
// it floored for a host. It exists so the cost of the third trigger is a measurement in a test
// and in a log line rather than a claim in a comment.
func (s *triageDBFreshCreds) invalidationCounts(host string) (honoured, floored int) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.cache[strings.ToLower(strings.TrimSpace(host))]; ok {
		return e.honoured, e.floored
	}
	return 0, 0
}

func (s *triageDBFreshCreds) FreshFor(host string) ([]triageFreshCred, triageFreshCredStatus) {
	if s == nil {
		return nil, triageFreshCredStatus{Host: host, Note: "no credential source is attached to this run"}
	}
	host = strings.ToLower(strings.TrimSpace(host))
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.cache[host]
	if entry != nil && s.usable(entry, now) {
		return entry.creds, entry.status
	}

	creds, status := s.read(host, now)
	var prev *triageFreshCredStatus
	if entry != nil {
		prev = &entry.status
	}
	status = triageCarryExhaustion(prev, creds, status, now)
	fresh := &triageFreshCredEntry{creds: creds, status: status}
	// WHAT WAS HELD BACK IS SAID OUT LOUD, ONCE. A rule that can narrow what goes on the wire has
	// to be auditable while the run is happening: the status Note carries the declines only when
	// the source has nothing usable, and the case that bit the live estate was a host with seven
	// credentials of which three were somebody else's.
	declinedPrint := strings.Join(status.Declined, "; ")
	if entry != nil {
		fresh.declinedPrint = entry.declinedPrint
	}
	if declinedPrint != "" && declinedPrint != fresh.declinedPrint {
		fresh.declinedPrint = declinedPrint
		log.Printf("[TRIAGE-CRED] %s: %s: %d captured cookie(s) were read and NOT substituted: %s",
			s.scopeTargetID, host, len(status.Declined), declinedPrint)
	}
	if entry != nil {
		// THE FLOOR'S BOOKKEEPING SURVIVES THE RE-READ IT CAUSED. Rebuilding the entry from
		// scratch would reset refusedAt on every refresh, so a wall of 401s would re-read,
		// forget, re-read and forget, and the floor would bound nothing at all. The counters
		// carry for the same reason: they are a statement about the host over the run.
		fresh.refusedPrint = entry.refusedPrint
		fresh.refusedAt = entry.refusedAt
		fresh.honoured = entry.honoured
		fresh.floored = entry.floored
	}
	s.cache[host] = fresh
	return creds, status
}

// The two exhaustions. They are different facts about the run and they have different next moves,
// so they are named apart and never share a sentence.
const (
	// triageCredExhaustedEmpty: this source hands out NOTHING for the host and it used to. The
	// next move is upstream of the runner: a browser has to produce a session and the crawl has
	// to capture it.
	triageCredExhaustedEmpty = "no_credential_at_all"
	// triageCredExhaustedUnverifiable: this source still hands credentials out, and not one of
	// them carries an expiry it can read, and it used to hold one that did. The run is not known
	// to be unauthenticated; it is known to be UNMEASURED, which is the state that reads as a
	// clean while the back half of a scan talks to a login wall.
	triageCredExhaustedUnverifiable = "nothing_with_a_readable_expiry"
)

// triageCountVerifiable counts the credentials whose expiry this source actually READ.
//
// Expires is assigned at four sites in this file and they name exactly TWO sources between them,
// each recorded in ExpirySource as it is set: "the token's own exp claim" (three sites, one per
// candidate path) and "the session_tokens.expires_at column (never validated)" (one). A zero
// Expires is the absence of a reading and not a distant one, which is why it is counted apart
// rather than treated as alive.
func triageCountVerifiable(creds []triageFreshCred) int {
	n := 0
	for _, c := range creds {
		if !c.Expires.IsZero() {
			n++
		}
	}
	return n
}

// triageUnmeasuredCarriers names the credentials being handed out whose expiry this source could
// not read. It is capped, and the overflow is COUNTED rather than dropped, so the sentence it
// feeds can never imply the list is the whole set.
func triageUnmeasuredCarriers(creds []triageFreshCred) []string {
	out := []string{}
	for _, c := range creds {
		if c.Expires.IsZero() {
			out = append(out, c.Carrier())
		}
	}
	const named = 4
	if len(out) > named {
		out = append(out[:named:named], fmt.Sprintf("and %d more", len(out)-named))
	}
	return out
}

// triageCarryExhaustion applies the RUN's memory to one READ and decides whether this host is
// exhausted.
//
// IT IS A FUNCTION RATHER THAN FOUR LINES INSIDE FreshFor because exhaustion is the auth-wall
// gate: noteCredExhaustion, the run warning and the per-row annotation all hang off the boolean it
// returns, and a decision that can only be exercised through two SELECTs is a decision nothing
// pins.
//
// THERE ARE TWO EXHAUSTIONS AND THE SECOND ONE IS THE ONE THE LIVE ESTATE IS IN.
//
//	THE SLICE IS EMPTY. This source hands out nothing and it used to. Unchanged.
//
//	NOTHING IT HANDS OUT HAS A LIFETIME IT CAN READ, and it used to hold one that did. Reported on
//	app.staging-v2.tradetalk.us by the round 14 audit, which read the jar in SQL: fresh=1,
//	exhausted=false, with BOTH Cognito JWS thirteen hours dead and a five segment JWE refreshToken
//	plus a randomPasswordKey holding the slice non-empty. Nothing in THIS round sent a request or
//	read that database; the shape is reproduced in the test beside this file. Under the old rule
//	that state read exhausted=false, so noteCredExhaustion never fired, the run warning never
//	listed the host, and the back half of a scan talking to a login wall was indistinguishable
//	from a target that refuses everyone.
//
// WHAT THE SECOND ONE DOES NOT CLAIM. It does not say the run is unauthenticated. Nothing in this
// file sends a request, so nothing here can know that. It says the run is UNMEASURED: what remains
// may still be accepted and this source will never be able to tell, which is a different sentence
// and is written as one everywhere it is said.
//
// A HOST THAT NEVER HELD ANYTHING VERIFIABLE IS NOT EXHAUSTED. LastVerifiableAt is the guard:
// without a moment when the count was above zero there is no transition to report, and reporting
// one would be inventing a past this source never observed.
func triageCarryExhaustion(prev *triageFreshCredStatus, creds []triageFreshCred,
	status triageFreshCredStatus, now time.Time) triageFreshCredStatus {

	// BOTH COUNTS ARE DERIVED FROM THE ONE SLICE, here, so the number that decides exhaustion and
	// the number that is printed beside it cannot be a pair that disagrees.
	status.Fresh = len(creds)
	status.Verifiable = triageCountVerifiable(creds)
	status.Unmeasured = triageUnmeasuredCarriers(creds)

	if prev != nil {
		// CARRIED ACROSS EVERY REFRESH, because exhaustion is a statement about the RUN and not
		// about this read. Without it a source that has gone dry looks exactly like one that was
		// never fed, and those have different next moves.
		status.LastFreshAt = prev.LastFreshAt
		status.LastVerifiableAt = prev.LastVerifiableAt
	}
	if status.Fresh > 0 {
		status.LastFreshAt = now
	}
	if status.Verifiable > 0 {
		status.LastVerifiableAt = now
	}

	switch {
	case status.Fresh == 0 && !status.LastFreshAt.IsZero():
		status.Exhausted, status.ExhaustionKind = true, triageCredExhaustedEmpty
	case status.Verifiable == 0 && !status.LastVerifiableAt.IsZero():
		status.Exhausted, status.ExhaustionKind = true, triageCredExhaustedUnverifiable
		// THE CARD READS THIS FIELD. SessionWireReading.Note is rendered whenever it is non-empty,
		// so the state goes to the screen and not only to a log line.
		if status.Note != "" {
			status.Note += "; "
		}
		status.Note += triageCredUnmeasuredClause(status)
	case status.Fresh > 0 && status.Verifiable == 0:
		// A FIRST READ OF ZERO IS ITS OWN FACT. LastVerifiableAt is still zero here, so there is
		// no transition and nothing is claimed to have been lost; what is claimed is that there
		// was never anything to lose. Said on the same surface as the exhaustion above, because a
		// run that could not have reported the loss is not in a better state than one that did.
		status.NeverVerifiable = true
		if status.Note != "" {
			status.Note += "; "
		}
		status.Note += triageCredNeverVerifiableClause(status)
	}
	return status
}

// triageCredUnmeasuredClause is the one wording of the second exhaustion, so the Note, the row
// sentence and the run warning cannot drift into three different claims.
//
// EVERY FIGURE IN IT WAS READ, AND NOTHING IN IT NAMES A CAUSE THIS SOURCE DID NOT OBSERVE.
//
//	LastVerifiableAt   the wall clock at the last read whose Verifiable count was above zero
//	Fresh, Unmeasured  derived from the credential slice, in triageCarryExhaustion above
//	Expired            incremented at the two sites in this file that call triageFreshCredDead
//
// In particular it does NOT say the credentials that carried an expiry expired. That is the usual
// reason and it is not the only one: a session_tokens row can be deactivated, and a capture can
// fall off the end of the row limit. Where an expiry WAS observed to pass, Expired is above zero
// and the clause says so as the count it actually is.
func triageCredUnmeasuredClause(st triageFreshCredStatus) string {
	out := fmt.Sprintf("this run last held a credential for this host whose expiry it could READ at %s, and not "+
		"one of the %d it is handing out now carries one (%s), so it can no longer tell whether it is still "+
		"authenticated here",
		st.LastVerifiableAt.UTC().Format(time.RFC3339), st.Fresh, strings.Join(st.Unmeasured, ", "))
	if st.Expired > 0 {
		out += fmt.Sprintf("; %d candidate(s) were read on this refresh and rejected because their own expiry had passed", st.Expired)
	}
	return out
}

// triageCredNeverVerifiableClause is the one wording of the state that is NOT an exhaustion.
//
// WHY IT HAS TO BE SAID. The second exhaustion asks whether the run HAD a readable lifetime and
// lost it, and its guard is right: without a moment when Verifiable was above zero there is no
// transition and reporting one would invent a past nothing observed. The consequence, measured on
// the one estate this engine can test against, is that the guard is never passed: the first read
// for app.staging-v2.tradetalk.us already reads Verifiable zero, both Cognito JWS having expired
// before the run began, so LastVerifiableAt stays zero for the whole run and NEITHER exhaustion
// can fire. Silence then reads as not-yet-exhausted, which is the one thing it is not.
//
// AND IT IS NOT AN EXHAUSTION. Exhausted stays false and ExhaustionKind stays empty, because
// nothing here transitioned and the next move is different: the second exhaustion says go and see
// what happened to the credential that had a lifetime, and this one says there has not been one
// since this run started, so capture a fresh sign-in before believing any clean this run reports.
//
// EVERY FIGURE IN IT WAS READ. Fresh and Unmeasured are derived from the credential slice in
// triageCarryExhaustion; Expired is incremented at the two sites that call triageFreshCredDead.
// Nothing here names a cause, because nothing here observed one.
func triageCredNeverVerifiableClause(st triageFreshCredStatus) string {
	out := fmt.Sprintf("this run has NEVER held a credential for this host whose expiry it could READ: all %d it is "+
		"handing out carry none (%s), so from the first probe onward it cannot tell whether it is still "+
		"authenticated here, and it could not report losing a session it was never able to measure",
		st.Fresh, strings.Join(st.Unmeasured, ", "))
	if st.Expired > 0 {
		out += fmt.Sprintf("; %d candidate(s) were read on this refresh and rejected because their own expiry had passed", st.Expired)
	}
	return out
}

// usable reports whether the cached reading may answer without a re-read.
func (s *triageDBFreshCreds) usable(e *triageFreshCredEntry, now time.Time) bool {
	if e.status.ReadAt.IsZero() || now.Sub(e.status.ReadAt) >= triageFreshCredTTL {
		return false
	}
	// THE EXPIRY MARGIN BEATS THE TTL. A credential that dies inside the margin is one this run
	// must stop handing out before the TTL is up, and re-reading is the only way another one can
	// arrive.
	for _, c := range e.creds {
		if !c.Expires.IsZero() && now.Add(triageFreshCredMargin).After(c.Expires) {
			return false
		}
	}
	return true
}

// read does the actual loading: session tokens first, captures second, ranked together.
func (s *triageDBFreshCreds) read(host string, now time.Time) ([]triageFreshCred, triageFreshCredStatus) {
	status := triageFreshCredStatus{Host: host, ReadAt: now}
	if dbPool == nil {
		status.Note = "this run has no database handle, so no stored credential could be read"
		return nil, status
	}
	if host == "" {
		status.Note = "the request carried no host to look a credential up by"
		return nil, status
	}

	candidates, expired, deadStored := s.sessionTokenCandidates(host, now)
	capCandidates, capExpired, deadCaptured, declined := s.captureCandidates(host, now)
	candidates = append(candidates, capCandidates...)
	status.Expired = expired + capExpired
	// THE COUNT AND THE ROWS COME OFF THE SAME TWO BRANCHES, so a card reading the rows and a
	// sentence reading the count cannot be describing two different sets. Dead is ranked on its
	// own and is deliberately NOT appended to candidates.
	status.Dead = triageRankDeadCreds(append(deadStored, deadCaptured...))
	// THE SESSION TOKENS PATH IS DELIBERATELY NOT FILTERED. A row in session_tokens is one an
	// operator typed into the Session Manager on purpose, and a rule that second-guessed that
	// would silently refuse to send a credential somebody chose. The narrowing applies to the
	// capture path, where nobody chose anything and a whole browser jar arrived at once.
	status.Declined = declined

	// ONE PRINCIPAL PER REQUEST. See triageOnePrincipal: the live jar holds two Cognito subjects
	// and every probe was carrying both.
	creds, splitPrincipals := triageOnePrincipal(triageRankFreshCreds(candidates))
	status.Declined = append(status.Declined, splitPrincipals...)
	// Fresh, Verifiable and Unmeasured are NOT set here. They all describe the same slice, and one
	// owner for the three of them is what stops a pair of numbers that disagree; triageCarryExhaustion
	// derives all three, and FreshFor calls it on every path that calls this.
	for _, c := range creds {
		if c.Expires.After(status.Newest) {
			status.Newest = c.Expires
		}
	}
	status.Note = triageCredNoteFor(len(creds), status.Expired, status.Declined)
	return creds, status
}

// triageCredNoteFor composes the status Note: what was read, what was rejected and what was held
// back, in the operator's words.
//
// It is a function so the composition can be pinned without a database. Every clause is a count of
// rows this source read or a reason this source produced; nothing in it is inferred.
func triageCredNoteFor(fresh, expired int, declined []string) string {
	note := ""
	if fresh == 0 {
		if expired > 0 {
			note = fmt.Sprintf("%d stored credential(s) for this host were read and every one of them has already expired; nothing newer has been captured", expired)
		} else {
			note = "no active session token and no 2xx manual-crawl capture for this host carries credential material"
		}
	}
	// WHAT WAS HELD BACK IS SAID ON EVERY BRANCH, NOT ONLY ON THE EMPTY ONE.
	//
	// It used to be inside the block above, so with Fresh greater than zero the Note was EMPTY and
	// the declines reached the API log and nowhere else. The round 14 audit read that state on the
	// live estate and reported fresh=1 with note="". The narrowing this source performs can be
	// wrong in the dangerous direction (a real application cookie named metrics_session, or
	// myapp_sid with an opaque value), and a decline nobody can see is how a wrongly held
	// credential stays invisible while the operator goes looking for a bug in the target.
	// SessionWireReading.Note carries this to the card, and SessionInvestigateModal renders
	// wire.note whenever it is non-empty, independently of the count beside it.
	if len(declined) > 0 {
		if note != "" {
			note += "; "
		}
		note += fmt.Sprintf("%d captured cookie(s) were read and not substituted: %s",
			len(declined), strings.Join(declined, "; "))
	}
	return note
}

// sessionTokenCandidates reads the table built for the job.
//
// IT DOES NOT FILTER THE EXPIRY IN SQL, deliberately, because a row rejected inside the database
// cannot be counted, and a status that cannot say "the one credential you had has expired" sends
// the operator looking for a bug instead of opening a browser.
func (s *triageDBFreshCreds) sessionTokenCandidates(host string, now time.Time) ([]triageFreshCred, int, []triageFreshCred) {
	rows, err := dbPool.Query(context.Background(), `
		SELECT COALESCE(token_type,''), COALESCE(header_name,''), COALESCE(cookie_name,''),
		       COALESCE(param_name,''), COALESCE(value_prefix,''), COALESCE(token_value,''),
		       COALESCE(scope_domains,'{}'), COALESCE(cookie_domain,''),
		       expires_at, COALESCE(updated_at, created_at)
		FROM session_tokens
		WHERE scope_target_id = $1 AND is_active = TRUE AND COALESCE(token_value,'') <> ''
		  -- A refresh secret is spent to mint, never replayed against an endpoint as a credential, so it
		  -- is excluded from the triage credential candidates just as it is from ApplySessionTokens.
		  AND COALESCE(token_role,'credential') <> 'refresh'`,
		s.scopeTargetID)
	if err != nil {
		// An install that has not migrated is not a reason to fail a run, and the capture path
		// below still carries the engagement. It IS a reason to say so once.
		log.Printf("[TRIAGE-CRED] %s: session_tokens could not be read (%v); "+
			"only manual-crawl captures can supply a credential for %s", s.scopeTargetID, err, host)
		return nil, 0, nil
	}
	defer rows.Close()

	// The scope target was read once, at construction. See triageDBFreshCreds.defaultDomain.
	defaultDomain := s.defaultDomain

	var out, dead []triageFreshCred
	expired := 0
	for rows.Next() {
		var kind, headerName, cookieName, paramName, prefix, value, cookieDomain string
		var domains []string
		var expiresAt, updatedAt *time.Time
		if rows.Scan(&kind, &headerName, &cookieName, &paramName, &prefix, &value,
			&domains, &cookieDomain, &expiresAt, &updatedAt) != nil {
			continue
		}
		if !triageTokenScopeCovers(normaliseTokenScopes(domains, cookieDomain, defaultDomain), host) {
			continue
		}
		cred := triageFreshCred{Source: "session_tokens"}
		switch kind {
		case "cookie":
			if cookieName == "" {
				continue
			}
			cred.Cookie = cookieName
			cred.value = value
		case "header", "api_key", "bearer":
			name := headerName
			if name == "" && kind == "bearer" {
				name = "Authorization"
			}
			if name == "" {
				// A query credential wearing the wrong type. This source substitutes NAMED
				// CARRIERS IN THE HEAD of the request; rewriting a URL here would move a payload
				// a class placed in the query string. Skipped by name, not silently.
				continue
			}
			cred.Header = canonicalHeaderName(name)
			cred.value = prefix + value
		default:
			continue
		}
		if updatedAt != nil {
			cred.Observed = *updatedAt
		}
		// THE JWT BEATS THE COLUMN, AND THAT ORDER IS THE MEASUREMENT. Both session_tokens rows
		// on the live engagement carry an operator-typed expires_at and an EMPTY
		// last_validation_status: nothing has ever checked either of them against the target. A
		// JWT states its own exp, from whoever issued it, and costs one base64 decode to read.
		// Trusting the column over the token would put a credential on the wire on the strength
		// of a field nobody has ever validated.
		if exp, ok := triageJWTExpiry(cred.value); ok {
			cred.Expires, cred.ExpirySource = exp, "the token's own exp claim"
		} else if expiresAt != nil {
			cred.Expires, cred.ExpirySource = *expiresAt, "the session_tokens.expires_at column (never validated)"
		}
		cred.Fingerprint = triageCredFingerprint(cred.value)
		if triageFreshCredDead(cred, now) {
			// COUNTED AND KEPT. The count is what says a credential died; the row beside it is
			// what still knows how long a session on this host lasts. It goes nowhere near out.
			expired++
			dead = append(dead, cred)
			continue
		}
		out = append(out, cred)
	}
	return out, expired, dead
}

// triageAnonWindowQuery reads every captured Cookie header for one host.
//
// IT IS NOT THE CANDIDATE QUERY AND IT MUST NOT BE. captureCandidates takes the most recent 200
// captures with a 2xx status, which is right for picking a credential to send and is exactly the
// wrong sample for this question: the unauthenticated part of a crawl is the older part, and a
// sign-in page answers 302 far more often than it answers 200. On the live estate the candidate
// query sees 200 rows of which 200 are authenticated; this one sees 4,011 rows of which 202 are
// not, and those 202 are the whole signal.
const triageAnonWindowQuery = `
	SELECT kv.value
	FROM manual_crawl_captures c, LATERAL jsonb_each_text(c.headers) kv
	WHERE c.scope_target_id = $1
	  AND c.headers IS NOT NULL
	  AND lower(kv.key) = 'cookie'
	  AND lower(split_part(split_part(split_part(c.url, '://', 2), '/', 1), ':', 1)) = $2`

// anonymousWindow reads the captured jars for one host and partitions them. Read once per host
// per run; see the anon field for why that is safe.
//
// A READ THAT FAILS PRODUCES AN EMPTY WINDOW, WHICH IS NOT DISCRIMINATING, so a database error
// makes this layer silent rather than making it guess. It is cached either way: a query that
// cannot run for this host will not start running on the next probe, and retrying it once per
// probe would be a full scan per probe for the same failure.
func (s *triageDBFreshCreds) anonymousWindow(host string) triageAnonWindow {
	if w, ok := s.anon[host]; ok {
		return *w
	}
	w := triageAnonWindow{Seen: map[string]int{}, InAnon: map[string]int{}}
	if dbPool != nil && host != "" {
		rows, err := dbPool.Query(context.Background(), triageAnonWindowQuery, s.scopeTargetID, host)
		if err != nil {
			log.Printf("[TRIAGE-CRED] %s: the captured jars for %s could not be partitioned, so the "+
				"anonymous-window rule will not speak for this host: %v", s.scopeTargetID, host, err)
		} else {
			for rows.Next() {
				var jar string
				if rows.Scan(&jar) != nil {
					continue
				}
				pairs := triageSplitCookieJar(jar)
				if len(pairs) == 0 {
					continue
				}
				authed := triageJarIsAuthenticated(pairs)
				if authed {
					w.Authed++
				} else {
					w.Anon++
				}
				// ONE JAR COUNTS ONCE PER NAME. A jar that repeats a cookie name, which a
				// browser does when the same name is set at two domain scopes, would otherwise
				// report more anonymous captures than this host has captures.
				seen := map[string]bool{}
				for _, pair := range pairs {
					if pair.Name == "" || seen[pair.Name] {
						continue
					}
					seen[pair.Name] = true
					w.Seen[pair.Name]++
					if !authed {
						w.InAnon[pair.Name]++
					}
				}
			}
			rows.Close()
			log.Printf("[TRIAGE-CRED] %s: %s: captured jars partitioned, %d carry a session and %d carry none, "+
				"over %d distinct cookie name(s); this layer %s for this host",
				s.scopeTargetID, host, w.Authed, w.Anon, len(w.Seen),
				map[bool]string{true: "will speak", false: "will not speak"}[w.Discriminating()])
		}
	}
	s.anon[host] = &w
	return w
}

// captureCandidates reads where the working token actually is today: the manual crawl.
//
// ONLY 2xx CAPTURES COUNT. A credential the application answered with a 200 is one it accepted at
// capture time; one that rode a 401 is a token the target had already refused, and promoting that
// to "freshest available" would substitute a known-bad credential over a merely old one.
func (s *triageDBFreshCreds) captureCandidates(host string, now time.Time) ([]triageFreshCred, int, []triageFreshCred, []string) {
	rows, err := dbPool.Query(context.Background(), `
		SELECT headers, created_at
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		  AND headers IS NOT NULL
		  AND status_code BETWEEN 200 AND 299
		  AND lower(split_part(split_part(split_part(url, '://', 2), '/', 1), ':', 1)) = $2
		ORDER BY created_at DESC
		LIMIT $3`, s.scopeTargetID, host, triageFreshCredCaptureLimit)
	if err != nil {
		log.Printf("[TRIAGE-CRED] %s: manual_crawl_captures could not be read for %s: %v",
			s.scopeTargetID, host, err)
		return nil, 0, nil, nil
	}
	defer rows.Close()

	// READ ONCE, BEFORE THE LOOP. The partition is over the whole corpus for this host and does
	// not depend on which capture is being read, so building it inside the loop would be the same
	// answer two hundred times.
	window := s.anonymousWindow(host)

	var out, dead []triageFreshCred
	expired := 0
	// One entry per carrier, in the order first met, so a jar repeated across two hundred captures
	// reports each decline once.
	declined := map[string]string{}
	var declinedOrder []string
	for rows.Next() {
		var headersJSON []byte
		var createdAt *time.Time
		if rows.Scan(&headersJSON, &createdAt) != nil {
			continue
		}
		var headers map[string]any
		if json.Unmarshal(headersJSON, &headers) != nil {
			continue
		}
		observed := time.Time{}
		if createdAt != nil {
			observed = *createdAt
		}
		for name, raw := range headers {
			value := stringifyHeaderValue(raw)
			if strings.TrimSpace(value) == "" {
				continue
			}
			lower := strings.ToLower(strings.TrimSpace(name))
			if lower == "cookie" {
				for _, pair := range triageSplitCookieJar(value) {
					// THE SUBSTITUTION RULE, WHICH IS NOT THE SLOT RULE. See
					// triageWireCookieVerdict for why sharing one boolean put a Stripe cookie,
					// an Intercom cookie and a Cognito username pointer on every probe, and why
					// that made exhaustion unreachable for the whole run.
					send, why := triageWireCookieVerdictInCorpus(pair.Name, pair.Value, window)
					if !send {
						if why != "" {
							if _, seen := declined[pair.Name]; !seen {
								declined[pair.Name] = why
								declinedOrder = append(declinedOrder, why)
							}
						}
						continue
					}
					cred := triageFreshCred{Cookie: pair.Name, value: pair.Value,
						Source: "manual_crawl_captures", Observed: observed}
					if exp, ok := triageJWTExpiry(pair.Value); ok {
						cred.Expires, cred.ExpirySource = exp, "the token's own exp claim"
					}
					cred.Fingerprint = triageCredFingerprint(cred.value)
					if triageFreshCredDead(cred, now) {
						// See the same branch in sessionTokenCandidates. This one is reached
						// only for a cookie the substitution rule above already agreed to send,
						// so a vendor cookie held back there is not carried here either.
						expired++
						dead = append(dead, cred)
						continue
					}
					out = append(out, cred)
				}
				continue
			}
			if !triageCredentialHeader(lower, value) {
				continue
			}
			cred := triageFreshCred{Header: canonicalHeaderName(lower), value: value,
				Source: "manual_crawl_captures", Observed: observed}
			if exp, ok := triageJWTExpiry(value); ok {
				cred.Expires, cred.ExpirySource = exp, "the token's own exp claim"
			}
			cred.Fingerprint = triageCredFingerprint(cred.value)
			if triageFreshCredDead(cred, now) {
				expired++
				dead = append(dead, cred)
				continue
			}
			out = append(out, cred)
		}
	}
	return out, expired, dead, declinedOrder
}

// ---------------------------------------------------------------------------------------------
// WHAT MAY BE SUBSTITUTED ONTO A PROBE AS A SESSION, WHICH IS NOT THE SAME QUESTION AS THE SLOTS
// ---------------------------------------------------------------------------------------------
//
// THIS FILE USED THE SLOT LAYER RULE AND SAID SO IN A COMMENT, so that "what this source is
// willing to substitute and what the runner is willing to call credential material cannot drift
// apart". The two never needed to agree, because they ask opposite questions and their safe
// directions point opposite ways:
//
//	triageCredentialCookie   must a probe leave this alone?   doubtful -> YES, and one probe is lost
//	triageWireCookieVerdict  would sending this teach us anything about the application under test?
//
// MEASURED ON THE LIVE ESTATE, 2026-09-20. Sharing one boolean put three cookies on every probe
// that authenticate nothing to the target:
//
//	__stripe_sid                                       Stripe, in 3875 captures
//	intercom-session-p7a9jdob                          Intercom, in 3789 captures
//	CognitoIdentity...LastAuthUser                     a user id, in 3776 captures
//
// AND IT IS NOT COSMETIC. applyFreshCredentials writes every credential this source hands out into
// the outgoing Cookie header, so a Stripe cookie was going out on every probe. Worse, FreshFor
// reports Fresh as the SIZE OF THAT SET and read() only reaches Exhausted when the set is empty.
// A third-party cookie can never expire and can never be refused by the target, so it holds the
// set non-empty forever: the run whose real session died twenty minutes ago keeps answering
// "7 fresh credentials", and noteCredExhaustion never fires. That is the false clean the whole
// credential layer exists to close, arriving through the COUNT instead of through a classifier.
//
// WHICH WAY AN AMBIGUOUS CASE FALLS. Wrongly declining a real credential reopens that same false
// clean, so every rule below either names a vendor, names a shape, or is reported by name in the
// status so the operator can see what was held back and put it in the Session Manager by hand.
// Only the third and fifth rules can be wrong in the dangerous direction, and each says out loud
// what it refused and on what word.

// triageWireVendorAddendum is the vendor rule's SHORT-TERM HOME for a named product the shared
// list does not carry yet, and it exists because of where that list lives.
//
// THE CANONICAL LIST IS triageThirdPartyCookieFamilies, in triageRun.go, and that is where these
// belong. This file may not edit that one, and shipping a measured vendor as "unrecognised" until
// somebody else can is how a Stripe cookie rides a probe for another round.
//
// WHY STRIPE, AND WHERE THE FIGURES WERE READ. Stripe publishes __stripe_mid and __stripe_sid.
// Both numbers below are read out of this file's own recorded measurements and not restated from
// anywhere else: the block above triageWireCookieVerdict records __stripe_sid in 3,875 captures,
// and the anonymous-window block records it in 186 of the 202 jars that carry no session at all.
// The application hands it to a visitor it has not authenticated, so it proves nobody. Until this
// round it was held by the qualifier tier, on the accident that "sid" is abbreviated, while
// _stripe_sess_id was sent, on the accident that "sess id" reaches a compact form. A vendor rule
// gives both spellings the same answer for the right reason, which a spelling rule never can.
//
// THE PREFIXES ARE BOTH SPELLINGS OF THE VENDOR'S OWN NAMESPACE, one underscore and two, so the
// answer does not depend on how many the product used.
//
// A HOLD HERE IS FINAL: triageWireCookieVerdictInCorpus may only overturn the qualifier tier, so
// nothing an entry here declines can be rescued by the jars. That is the same bar the shared list
// sets, and the reason the bar is the VENDOR and never a shape.
//
// TestTheVendorAddendumIsNotAlreadyInTheSharedList fails the moment an entry here is merged
// upstream, so this list empties itself rather than quietly becoming a second vendor list.
var triageWireVendorAddendum = []struct {
	Prefix string
	Vendor string
}{
	{Prefix: "__stripe_", Vendor: "Stripe"},
	{Prefix: "_stripe_", Vendor: "Stripe"},
}

// triageWireVendorFor names the third-party product this cookie belongs to, reading the shared
// list first and this file's addendum second. It is the only vendor lookup the wire rule makes.
func triageWireVendorFor(name string) string {
	if v := triageThirdPartyCookie(name); v != "" {
		return v
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return ""
	}
	for _, f := range triageWireVendorAddendum {
		if strings.HasPrefix(lower, f.Prefix) {
			return f.Vendor
		}
	}
	return ""
}

// triageWireSessionSpellings are the SHORT SPELLINGS of a claim the credential-word tier already
// accepts written out in full, and they are listed here because a tier that answers differently
// for two spellings of one claim is not a rule, it is an accident of the word list.
//
// WHAT WAS MEASURED, over the same 45 application cookie names and 24 third-party names the two
// rates in this file are measured on. Two pairs got OPPOSITE answers on the name rules alone:
//
//	__stripe_sid  held at the qualifier tier   _stripe_sess_id  sent at the credential-word tier
//	app_sess      held at the qualifier tier   app_session      sent at the credential-word tier
//
// In both pairs the sent spelling reaches triageCredentialCompactForms ("session", "sessid") and
// the held spelling does not, so what decided was whether the role word had been abbreviated. Two
// spellings of one vendor cannot be given opposite answers by a rule that claims to read names.
//
// WHICH WAY THE PAIRS WERE CLOSED, AND WHY THAT WAY. Closing them by HOLDING would mean reading
// "session" under a qualifier as ambiguous, which this file measured once already: it holds
// laravel_session, ci_session, user_session, _session_id, _gitlab_session, _discourse_session and
// appSession, seven real credentials lost, in the direction this file calls dangerous. Closing
// them by SENDING costs nothing that was measured, because the qualifier tier turns out to catch
// NO vendor cookie at all: of the 25 third-party names, that tier holds zero (the one vendor name
// held, _ga_session, is held by the NAMED VENDOR tier), while of the 45 application names it
// holds five. On this corpus it is pure loss, and taking the two session spellings out of it
// takes the miss count from 5 to 3 and moves the vendor rate by zero. Both rates are pinned in
// TestTheNameOnlyRatesOverBothCorpora.
//
// WHAT IT COSTS ANYWAY, said out loud because it is not zero. __stripe_sid is a real Stripe
// cookie and this engine now sends it on the NAME rules. It is held on the live estate, where the
// captured jars have an opinion about it (it is in 186 of the 202 unauthenticated jars), and it
// is NOT held on a host whose corpus cannot speak. The durable fix is the vendor list, which is
// where a named product belongs: triageThirdPartyCookieFamilies carries no Stripe entry, and a
// "__stripe_" and "_stripe_" prefix there would decline every spelling of it by vendor rather
// than by accident.
//
// WHAT IS DELIBERATELY NOT IN HERE. "auth" and "token" are the other two words the qualifier tier
// reads, and they stay there: this list is only for spellings of a claim the tier above already
// accepts in full, and neither "authentication" nor "token" is accepted there under a qualifier.
var triageWireSessionSpellings = map[string]bool{
	// sess is session. sid is session id, which is triageCredentialCompactForms "sessid" with the
	// three middle letters dropped.
	"sess": true, "sid": true,
}

// triageWireTelemetryWords are role words that describe MEASURING a visitor rather than
// authenticating one. They are the vendor-free half of the third-party rule: a product that has
// never been heard of still calls its cookie what it is.
//
// A DECLINE ON ONE OF THESE CAN BE WRONG. An application with its own session-replay or consent
// feature could name a real session cookie with one of these words, and it would be held back.
// That is reported by name rather than dropped silently, and it is the direction chosen because
// the alternative is a telemetry cookie masking exhaustion for a whole run.
var triageWireTelemetryWords = map[string]bool{
	"analytics": true, "analytic": true, "telemetry": true, "tracking": true, "tracker": true,
	"pixel": true, "beacon": true, "consent": true, "gdpr": true, "ccpa": true, "privacy": true,
	"experiment": true, "heatmap": true, "recording": true, "replay": true, "rum": true,
	"metric": true, "metrics": true, "stats": true, "visitor": true, "anon": true,
	"anonymous": true, "marketing": true, "campaign": true, "utm": true, "attribution": true,
	"referrer": true, "advert": true, "ads": true, "adtech": true,
}

// The tiers, numbered so a decline can be traced to the rule that made it and so the corpus
// layer below can name exactly which of them it is allowed to overturn.
const (
	triageWireTierNotACandidate      = iota // nothing in the name or value claimed a credential
	triageWireTierNamedVendor               // a published cookie name of a named third party
	triageWireTierJWS                       // the value is a compact JWS
	triageWireTierFrameworkHandle           // a published framework session cookie name
	triageWireTierTelemetryWord             // the name carries a word that describes measuring a visitor
	triageWireTierLongTermSecret            // the name carries a word that establishes a session
	triageWireTierCredentialWord            // the name carries an unambiguous credential word
	triageWireTierPrincipalPointer          // the name points at a principal rather than proving one
	triageWireTierSessionSpelling           // the short word is a spelling the tier above accepts in full
	triageWireTierAmbiguousQualified        // the only claim is a short word under somebody else qualifier
	triageWireTierNothingRefused            // no rule refused it
)

// triageWireCookieVerdict answers whether this cookie may be substituted onto a probe as a
// credential for the application under test, and says why not when the answer is no.
//
// A "" reason means the cookie was never a candidate at all, which is not a decline worth
// reporting: nothing in its name or value claimed a credential in the first place.
//
// THIS IS THE NAME-ONLY RULE. triageWireCookieVerdictInCorpus is the one the capture path calls;
// it reads the same tiers and then lets the captured jars overturn two of them. Both are kept
// because the name rule is what answers on a host the corpus cannot speak about, and because the
// two rates in the report are measured separately.
func triageWireCookieVerdict(name, value string) (bool, string) {
	send, _, why := triageWireCookieTier(name, value)
	return send, why
}

// triageWireCookieTier is the verdict with the deciding tier beside it.
func triageWireCookieTier(name, value string) (bool, int, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return false, triageWireTierNotACandidate, ""
	}

	// 1. WAS IT EVER A CANDIDATE. The slot layer vocabulary is still the entry gate, so this
	//    source never widens what the runner calls credential material; it only narrows it.
	if !triageCredentialCookie(name, value) {
		return false, triageWireTierNotACandidate, ""
	}

	// 2. A NAMED THIRD PARTY. Round 7 built this list and named the vendor beside each entry so a
	//    decline could be reported rather than merely made. This layer was not consulting it,
	//    which is how a cookie the OTHER credential layer already refused rode every probe.
	if vendor := triageWireVendorFor(name); vendor != "" {
		return false, triageWireTierNamedVendor, fmt.Sprintf("%s is a published cookie name of %s, so this engine reads it as "+
			"that product and not as a credential of the application under test", name, vendor)
	}

	// 3. THE VALUE IS THE STRONGEST WITNESS AND IT BEATS EVERY NAME RULE BELOW. A compact JWS is a
	//    credential whatever the cookie is called, which is what keeps a target that names its
	//    session after nothing in particular from losing it.
	if reflectionValueLooksLikeJWT(value) {
		return true, triageWireTierJWS, ""
	}

	// 4. A PUBLISHED FRAMEWORK SESSION HANDLE is the application own by definition.
	if _, ok := knownSessionCookies[strings.ToLower(name)]; ok {
		return true, triageWireTierFrameworkHandle, ""
	}

	tokens := triageNameTokens(name)

	// 5. TELEMETRY VOCABULARY, which is how a vendor nobody has listed is still recognisable.
	//
	//    IT IS READ BEFORE THE CREDENTIAL WORDS AND NOT AFTER, because a measurement product names
	//    its cookie after BOTH: QuantumMetricSessionID is a session-replay handle and the word
	//    session in it was enough to make it substitutable. An application does not name the
	//    cookie that proves who you are after analytics, so where the two vocabularies collide the
	//    measurement word is the one that identifies the product.
	for _, tok := range tokens {
		if triageWireTelemetryWords[tok] {
			return false, triageWireTierTelemetryWord, fmt.Sprintf("%s carries the word %q, which describes measuring a visitor "+
				"rather than authenticating one, so this engine reads it as a measurement cookie and "+
				"not as a credential of the application under test", name, tok)
		}
	}

	// 6. A SECRET THAT ESTABLISHES A SESSION IS NOT A HANDLE THAT PROVES ONE, and it is read
	//    BEFORE the credential words for the same reason the telemetry words are: "password" is
	//    an unambiguous credential word, so tier 7 kept randomPasswordKey and put an Amplify
	//    device secret on every probe. See credentialNameNamesALongTermAuthenticator for what was
	//    measured on the live jars and why the leaf is what decides.
	if tok, what, ok := credentialNameNamesALongTermAuthenticator(name); ok {
		return false, triageWireTierLongTermSecret, fmt.Sprintf("%s carries the word %q in its last segment, which names %s, "+
			"so substituting it would put a long-lived secret on the wire without testing how this "+
			"application handles a session", name, tok, what)
	}

	// 7. AN UNAMBIGUOUS CREDENTIAL WORD, read in the leaf of a namespaced name and in the whole
	//    name, so CognitoIdentityServiceProvider.<pool>.<sub>.accessToken is kept on accessToken.
	if credentialNameClaimsProofOutright(credentialNameLeaf(name)) ||
		credentialNameClaimsProofOutright(name) {
		return true, triageWireTierCredentialWord, ""
	}

	// 8. A POINTER AT A PRINCIPAL. See credentialNameNamesAPrincipal: the head noun decides, so a
	//    userToken is a token and a LastAuthUser is a user.
	if who, ok := credentialNameNamesAPrincipal(name); ok {
		return false, triageWireTierPrincipalPointer, fmt.Sprintf("%s names a principal (%s) rather than proving one, read from the "+
			"last segment of the name", name, who)
	}

	// 9. THE ONLY CLAIM IS A SHORT AMBIGUOUS WORD UNDER SOMEBODY ELSE QUALIFIER. sid means a
	//    session to some vendors and nothing to others; __stripe_sid is Stripe, and a cookie
	//    called just sid is the application. The qualifier is what separates them, and the rule
	//    needs to know no vendor to apply it.
	//
	//    IT IS A GUESS ABOUT A QUALIFIER AND IT IS THE ONE TIER THE CORPUS MAY OVERTURN. Measured
	//    over 45 session and auth cookie names real frameworks and real applications deploy, this
	//    tier is the only thing that holds any of them, and it holds five: portal_sid, acme_auth,
	//    mycompany_sso_token, app_sess and okta-token-storage. Every one of those qualifiers is
	//    the name of the application itself, which is a fact no name rule can check and the
	//    captured jars can. See triageWireCookieVerdictInCorpus.
	for _, tok := range tokens {
		if !credentialAmbiguousRoleWords[tok] {
			continue
		}
		// A SPELLING IS NOT A CLAIM. See triageWireSessionSpellings: tier 7 above sends
		// app_session and _stripe_sess_id on the compact forms "session" and "sessid", and this
		// tier was holding app_sess and __stripe_sid on the abbreviations of the same two words.
		// Whichever answer is right, it cannot be different for the two spellings.
		if triageWireSessionSpellings[tok] {
			return true, triageWireTierSessionSpelling, ""
		}
		if len(tokens) == 1 {
			return true, triageWireTierAmbiguousQualified, ""
		}
		return false, triageWireTierAmbiguousQualified, fmt.Sprintf("the only thing in %s that claims a credential is the ambiguous "+
			"word %q, and the rest of the name qualifies it; a cookie named just %q would have been "+
			"substituted", name, tok, tok)
	}

	return true, triageWireTierNothingRefused, ""
}

// ---------------------------------------------------------------------------------------------
// THE SIGNAL THE NAME CANNOT CARRY: WHETHER THE APPLICATION HANDS THIS COOKIE TO A VISITOR IT HAS
// NOT AUTHENTICATED
// ---------------------------------------------------------------------------------------------
//
// THE NAME IS EXHAUSTED AND THE MEASUREMENT SAYS SO. Over 45 cookie names real applications and
// frameworks deploy and 25 third-party names this tree hardcodes nowhere, the tiers above hold 5
// of the 45 and send 16 of the 25. The 16 are all of one shape, vendor_session: fs_session,
// _heap_session, _clarity_session, smartlook_session, mouseflow_session, _lr_uf_session,
// pendo_sess_id and nine more. The 5 are the same shape with a different qualifier: app_sess,
// portal_sid, acme_auth. NOTHING IN THE NAME SEPARATES app_sess FROM fs_session. Closing the 16
// by reading "session" under a qualifier as ambiguous would hold laravel_session, ci_session,
// user_session, _session_id, _gitlab_session, _discourse_session and appSession, which is seven
// real credentials lost to gain sixteen vendor ones, in the direction this file calls dangerous.
//
// WHAT WAS TRIED AND MEASURED AND IS NOT ENOUGH. A positive override on Set-Cookie evidence: of
// the 112 distinct cookie names this estate sends, only 8 were ever observed in a captured
// Set-Cookie, and placing that override above tier 2 or 5 would re-admit __cf_bm, cf_clearance,
// __ddg9_, arraffinitysamesite and _locale. A cookie name seen on two unrelated registrable
// domains: 8 of the same 112. A vendor host named in the estate own response bodies: it finds
// Intercom, Reddit, PostHog, Sentry and QuantumMetric, and misses Stripe and Amplitude, whose
// cookies are in 3,908 and 8,008 of the jars. Each is real evidence with almost no reach.
//
// WHAT DOES REACH. A first-party session credential is issued BY authenticating and a vendor
// cookie is set on sight, so the captured jars themselves carry the answer for every cookie in
// them. MEASURED IN SQL over all 4,011 captured jars for app.staging-v2.tradetalk.us, with the
// same anchored shape test reflectionValueLooksLikeJWT applies: 3,809 of them carry a compact JWS
// and 202 carry none, and across that split
//
//	present in the 202 unauthenticated jars     AMP_e6fe2a7b15 (390), AMP_MKTG_e6fe2a7b15 (377),
//	                                            _gcl_au (202), AMP_d6814239bf (202),
//	                                            __stripe_mid (200), __stripe_sid (186),
//	                                            _rdt_uuid (145), _rdt_em (142),
//	                                            intercom-session-p7a9jdob (43),
//	                                            intercom-device-id-p7a9jdob (43),
//	                                            onfido-web-sdk-analytics (14), and the Cognito
//	                                            deviceKey, deviceGroupKey and randomPasswordKey
//	                                            of BOTH subjects (43 and 28)
//
//	present in NONE of them                     accessToken, idToken, refreshToken, userData and
//	                                            clockDrift of both subjects, LastAuthUser, and
//	                                            amplify-signin-with-hostedUI
//
// That is a clean separation over 19 names against 12, once the ten AMP_TEST_ and AMP_TLDTEST_
// probe cookies are set aside: Amplitude writes those to find out whether cookies work at all and
// deletes them again, they appear in one or two captures each, and no rule here calls them
// candidates. Counting them the split is 29 against 23 and the line falls in the same place. The
// reach is the whole jar rather than 8 names in 112, and it independently reaches the same verdict
// on the device triple that tier 6 reaches from the word in the leaf.
//
// AND IT IS SILENT WHERE IT HAS NOTHING TO SAY. Of the twelve hosts in this corpus with captured
// jars, ELEVEN CANNOT SPEAK: ten have never been captured with a session at all, and one has never
// been captured without one. On all eleven this layer declines and the name rules answer alone.
// That is the same discipline as LastVerifiableAt: a partition with nothing on one side of it is
// not evidence of a boundary.

// triageAnonWindow is what the captured jars for ONE host say about the cookies in them.
type triageAnonWindow struct {
	// Authed and Anon are the capture counts on each side of the partition.
	Authed int
	Anon   int
	// Seen counts, per cookie name, the captures of either kind whose jar carried it. A name this
	// corpus never saw gets no opinion at all, in either direction.
	Seen map[string]int
	// InAnon counts, per cookie name, the UNAUTHENTICATED captures whose jar carried it.
	InAnon map[string]int
}

// Discriminating reports whether this corpus is entitled to an opinion: it has to have seen the
// host both with a session and without one. A corpus with nothing on one side does not describe
// an authentication boundary, it describes a crawl that only ever visited one state.
func (w triageAnonWindow) Discriminating() bool { return w.Authed > 0 && w.Anon > 0 }

// triageJarIsAuthenticated reads ONE captured cookie jar and reports whether the browser that
// sent it had been authenticated.
//
// TWO WITNESSES, AND BOTH ARE TIERS THAT CANNOT BE WRONG: a compact JWS in a value, and a
// PUBLISHED framework session handle by name. The name VOCABULARY is deliberately not used. The
// vocabulary is what this partition exists to correct, and seeding the partition with the rule
// under test would make the answer agree with the rule by construction.
//
// THE FRAMEWORK HANDLE IS IN THE SEED FOR A SPECIFIC FAILURE. An application whose session is an
// opaque PHPSESSID and which mints no JWS anywhere would otherwise read as unauthenticated in
// every capture, its own session cookie would be present in the unauthenticated jars, and this
// layer would hold the one credential the run has. With PHPSESSID in the seed those captures are
// authenticated, there is no anonymous side, and Discriminating is false.
func triageJarIsAuthenticated(pairs []triageCookiePair) bool {
	for _, p := range pairs {
		if reflectionValueLooksLikeJWT(p.Value) {
			return true
		}
		if _, ok := knownSessionCookies[strings.ToLower(strings.TrimSpace(p.Name))]; ok {
			return true
		}
	}
	return false
}

// triageWireCookieVerdictInCorpus is the verdict the capture path uses: the tiers above, with the
// captured jars allowed to overturn exactly two kinds of answer.
//
// IT MAY HOLD ANYTHING THE TIERS SENT. A cookie the application hands to a visitor it has not
// authenticated is not what proves who you are, whatever its name says and whatever its value
// looks like, so this overrules the JWS tier too: a JWS handed to an anonymous visitor is a
// configuration token and not a session.
//
// IT MAY SEND ONLY WHAT TIER 9 HELD. That tier is a guess about a QUALIFIER with no vendor
// evidence behind it, and it is the only tier that holds real application credentials. The other
// declines are left alone on purpose: a rescue at tier 2 or 5 would re-admit a named vendor or a
// telemetry cookie that an estate happens to set only after sign-in, and a rescue at tier 8 would
// re-admit LastAuthUser, which names a person and proves nobody.
func triageWireCookieVerdictInCorpus(name, value string, w triageAnonWindow) (bool, string) {
	send, tier, why := triageWireCookieTier(name, value)
	if !w.Discriminating() {
		return send, why
	}
	trimmed := strings.TrimSpace(name)
	if n := w.InAnon[trimmed]; n > 0 {
		if !send {
			return false, why
		}
		return false, fmt.Sprintf("%s was captured in %d of the %d jars this crawl recorded for this host that carry "+
			"no session of any kind, so the application hands it to a visitor it has not authenticated and it "+
			"cannot be what proves who you are", trimmed, n, w.Anon)
	}
	if send || tier != triageWireTierAmbiguousQualified || w.Seen[trimmed] == 0 {
		return send, why
	}
	return true, ""
}

// triageFreshCredDead reports a candidate whose own expiry has already passed, or passes within
// the margin. A credential with NO readable expiry is not dead: it is unverifiable, which is a
// different thing and is handled by ranking it below one that can be checked.
func triageFreshCredDead(c triageFreshCred, now time.Time) bool {
	if c.Expires.IsZero() {
		return false
	}
	return now.Add(triageFreshCredMargin).After(c.Expires)
}

// triageRankDeadCreds reduces the candidates this source rejected to the few that can still say
// something, and it is a DIFFERENT ranking from the live one for a reason.
//
// THE LIVE RANKING ASKS WHICH CREDENTIAL TO SEND. This one asks which dead credential best
// describes how long a session on this host lasts, and the answer to that is the most recently
// minted reading of each carrier: an accessToken that died four minutes ago and one that died
// three hours ago state the same lifetime, and the newer one was read off a token this
// application issued more recently.
//
//  1. ONE ROW PER CARRIER. Two hundred captures of a rotating accessToken are two hundred
//     candidates and one lifetime. Keyed exactly the way the live ranking keys a carrier, so a
//     header and a cookie of the same name stay two things.
//  2. LATEST EXPIRY WINS within a carrier, which on a token that rotates is the newest one read.
//  3. THE RESULT IS ORDERED LATEST EXPIRY FIRST, ties broken on the carrier name, so two runs
//     over the same rows produce the same slice and a cap cuts the same rows.
//
// A CANDIDATE WITH NO READABLE EXPIRY IS NEVER IN HERE. triageFreshCredDead returns false for
// one, so it was never rejected; carrying it would put a credential with no lifetime into the set
// that exists to supply a lifetime.
func triageRankDeadCreds(in []triageFreshCred) []triageFreshCred {
	if len(in) == 0 {
		return nil
	}
	best := map[string]triageFreshCred{}
	for _, c := range in {
		if c.Expires.IsZero() {
			continue
		}
		key := "h:" + strings.ToLower(c.Header)
		if c.Header == "" {
			key = "c:" + c.Cookie
		}
		cur, seen := best[key]
		if !seen || c.Expires.After(cur.Expires) {
			best[key] = c
		}
	}
	out := make([]triageFreshCred, 0, len(best))
	for _, c := range best {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Expires.Equal(out[j].Expires) {
			return out[i].Expires.After(out[j].Expires)
		}
		return out[i].Carrier() < out[j].Carrier()
	})
	if len(out) > triageFreshCredDeadKeep {
		out = out[:triageFreshCredDeadKeep]
	}
	return out
}

// triageRankFreshCreds keeps the single best candidate per carrier and orders the result.
//
// THE ORDER IS FRESHNESS FIRST AND PROVENANCE LAST, which inverts the obvious reading of "the
// operator's own table wins". The obvious reading is what the live engagement disproves: both
// operator-declared session tokens are days expired and neither has ever been validated, while
// the credential that works is sitting in a capture from twelve minutes ago. So:
//
//  1. A credential whose expiry can be READ beats one whose cannot. "I know this is alive for
//     another nine minutes" is a stronger claim than "nobody has said otherwise".
//  2. Among readable ones, the latest expiry wins. On the measured corpus two DISTINCT tokens
//     share one created_at to the microsecond, because a crawl writes a batch at once, and their
//     exps are 26 seconds apart. Ordering by created_at alone picks between them by luck.
//  3. Among unreadable ones, the most recently observed row wins.
//  4. Everything else equal, session_tokens beats a capture: the operator said that one out loud.
func triageRankFreshCreds(in []triageFreshCred) []triageFreshCred {
	best := map[string]triageFreshCred{}
	for _, c := range in {
		key := "h:" + strings.ToLower(c.Header)
		if c.Header == "" {
			key = "c:" + c.Cookie
		}
		cur, seen := best[key]
		if !seen || triageFreshCredBetter(c, cur) {
			best[key] = c
		}
	}
	out := make([]triageFreshCred, 0, len(best))
	for _, c := range best {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Header != out[j].Header {
			return out[i].Header < out[j].Header
		}
		return out[i].Cookie < out[j].Cookie
	})
	return out
}

// triageOnePrincipal keeps ONE person credentials in the set a probe will carry, and names what
// it dropped.
//
// MEASURED ON THE LIVE ESTATE. The captured jar for app.staging-v2.tradetalk.us holds two Cognito
// subjects side by side, each with its own accessToken, idToken, refreshToken, userData and
// device record, because Amplify keys its storage by subject and a jar that has seen two sign-ins
// keeps both. Their cookie NAMES differ, so every layer above this one reads them as different
// carriers and every one of them was substituted: a single probe went out asserting two people at
// once. That is not a stricter or a looser test of the target, it is an incoherent one, and no
// result from it means anything.
//
// THE PRINCIPAL IS READ OFF THE NAME. credentialNamePrincipalSegment returns the UUID or address
// segment of a namespaced name, as written, and it is the grouping key here and the account named
// in the sentence about what was held back. A name with no such segment belongs to nobody in
// particular and is ALWAYS KEPT: a bare session cookie is not evidence of a second person, and
// dropping one would be this rule losing a credential on a guess.
//
// WHICH PRINCIPAL WINS is the same comparison the ranking uses, applied to each group best
// credential, so the set that survives is the one whose freshest member is freshest. A readable
// expiry beats an unreadable one there, which is what makes the surviving set the one this run
// can still say something true about.
//
// AND A SESSION_TOKENS ROW IS NEVER NARROWED, which is the same exemption read() already states
// for the wire rule and it is stated for the same reason: a row in session_tokens is one an
// operator typed into the Session Manager on purpose, and a rule that silently dropped one would
// be second-guessing a choice somebody made out loud. The narrowing applies to the capture path,
// where nobody chose anything and a whole browser jar arrived at once. An operator who really has
// activated two accounts at once sees both go out and can see that on the card.
func triageOnePrincipal(in []triageFreshCred) ([]triageFreshCred, []string) {
	best := map[string]triageFreshCred{}
	for _, c := range in {
		who := credentialNamePrincipalSegment(c.Cookie)
		if who == "" || c.Source == "session_tokens" {
			continue
		}
		cur, seen := best[who]
		if !seen || triageFreshCredBetter(c, cur) {
			best[who] = c
		}
	}
	if len(best) < 2 {
		return in, nil
	}
	// THE PRINCIPALS ARE COMPARED IN A FIXED ORDER, because a Go map iterates in a different order
	// every time and two principals whose best credentials compare EQUAL would otherwise leave a
	// different one on the wire on every refresh. The winner has to be a function of what was read
	// and not of the runtime, or two probes a second apart assert two different people and no
	// result from either means anything.
	principals := make([]string, 0, len(best))
	for who := range best {
		principals = append(principals, who)
	}
	sort.Strings(principals)
	keep := principals[0]
	for _, who := range principals[1:] {
		if triageFreshCredBetter(best[who], best[keep]) {
			keep = who
		}
	}
	out := make([]triageFreshCred, 0, len(in))
	dropped := map[string][]string{}
	for _, c := range in {
		who := credentialNamePrincipalSegment(c.Cookie)
		if who == "" || who == keep || c.Source == "session_tokens" {
			out = append(out, c)
			continue
		}
		dropped[who] = append(dropped[who], c.Carrier())
	}
	others := make([]string, 0, len(dropped))
	for who := range dropped {
		others = append(others, who)
	}
	sort.Strings(others)
	declined := make([]string, 0, len(others))
	for _, who := range others {
		declined = append(declined, fmt.Sprintf("%s: this jar holds credentials for %d distinct principals and a probe "+
			"can only assert one, so the set for principal %s was held back and the set for principal %s was kept, "+
			"because its freshest credential is the freshest of the %d",
			strings.Join(dropped[who], ", "), len(best), who, keep, len(best)))
	}
	return out, declined
}

func triageFreshCredBetter(a, b triageFreshCred) bool {
	aKnown, bKnown := !a.Expires.IsZero(), !b.Expires.IsZero()
	if aKnown != bKnown {
		return aKnown
	}
	if aKnown && !a.Expires.Equal(b.Expires) {
		return a.Expires.After(b.Expires)
	}
	if !a.Observed.Equal(b.Observed) {
		return a.Observed.After(b.Observed)
	}
	return a.Source == "session_tokens" && b.Source != "session_tokens"
}

// triageTokenScopeCovers reports whether any of a token's declared scopes covers this host, using
// the same host-or-subdomain rule the scope boundary uses.
func triageTokenScopeCovers(scopes []string, host string) bool {
	for _, s := range scopes {
		if s != "" && hostWithinDomain(host, s) {
			return true
		}
	}
	return false
}

// triageJWTExpiry reads a compact JWS's exp claim.
//
// THE SIGNATURE IS NOT VERIFIED AND MUST NOT BE. This is not an authorisation decision about
// somebody else's token, it is a freshness check on our own, and we hold no key. A token that
// does not parse returns false, which means "unknown expiry" and NOT "expired": refusing to send
// a credential merely because it is not a JWT would drop every API key the framework holds.
func triageJWTExpiry(value string) (time.Time, bool) {
	tok := strings.TrimSpace(value)
	if i := strings.LastIndex(tok, " "); i >= 0 {
		tok = tok[i+1:] // strip a "Bearer " style prefix
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(decoded, &claims) != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

// triageCredFingerprint is a short equality key for a credential: two values are the same token
// when their fingerprints match, and a rotation shows as two different ones.
//
// EIGHT HEX DIGITS OF A SHA-256, and not a prefix of the token, because the first eight
// characters of a JWT are part of its header segment, which is identical on every token an issuer
// mints and so distinguishes nothing. It is a comparison aid and never a substitute for recording
// the value.
func triageCredFingerprint(value string) string {
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:4])
}

// triageCookiePair is one name=value out of a Cookie header.
type triageCookiePair struct {
	Name  string
	Value string
}

// triageSplitCookieJar splits a Cookie header into its pairs, preserving order.
func triageSplitCookieJar(jar string) []triageCookiePair {
	var out []triageCookiePair
	for _, part := range strings.Split(jar, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out = append(out, triageCookiePair{Name: name, Value: value})
	}
	return out
}

// triageSetCookieValue replaces one cookie's value inside a Cookie header, keeping every other
// pair and the ORDER of all of them.
//
// ORDER IS PRESERVED FOR THE SAME REASON RequestTemplate.SetHeader preserves header position: a
// probe whose jar is ordered differently from its own baseline has introduced a difference the
// comparator will later read as the payload's doing. It reports whether the name was there at
// all, so the caller can tell a substitution from an addition and say which on the row.
func triageSetCookieValue(jar, name, value string) (string, bool) {
	pairs := triageSplitCookieJar(jar)
	found := false
	for i := range pairs {
		if pairs[i].Name == name {
			pairs[i].Value = value
			found = true
		}
	}
	if !found {
		pairs = append(pairs, triageCookiePair{Name: name, Value: value})
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.Name+"="+p.Value)
	}
	return strings.Join(parts, "; "), found
}

// ---------------------------------------------------------------------------------------------
// WHAT WENT ON THE WIRE
// ---------------------------------------------------------------------------------------------

// triageCredWire is the record of one substitution: what this run replaced, what it added, what
// it deliberately left alone, and the material it used. It is what the gates quote, and it quotes
// the bytes: a row saying a credential was substituted, without the credential, cannot be checked
// against the request it describes.
type triageCredWire struct {
	// Substituted names each carrier whose captured value this run REPLACED.
	Substituted []string
	// Added names each carrier this run supplied that the capture did not carry at all.
	Added []string
	// HeldBack names each carrier this run refused to touch because the probe in flight is
	// targeting it on purpose.
	HeldBack []string
	// Describe is the one-line rendering of each credential used, from String(): carrier, source,
	// fingerprint, expiry and the value that went on the wire.
	Describe []string
	// Sent is what each substituted or added carrier actually carried, as "<carrier> = <value>",
	// in the order the credentials went on. This is the wire record proper: Describe says where
	// the material came from, this says what the request contained.
	Sent   []string
	Status triageFreshCredStatus
}

// Used reports that this run put fresher material on the wire than the capture held.
func (w triageCredWire) Used() bool { return len(w.Substituted) > 0 || len(w.Added) > 0 }

// Held reports that this run deliberately left a carrier alone because the probe in flight was
// aimed at it. IT IS NOT A FLAVOUR OF Used AND IT IS NOT AN ABSENCE OF ONE: a wire can be both
// (one credential substituted, another held back) and a held-back wire on which nothing was
// substituted still records a real decision that changed what went out.
func (w triageCredWire) Held() bool { return len(w.HeldBack) > 0 }

// HeldBackSentence is the CONFOUND clause, and it is the reason HeldBack exists as a field
// rather than as a continue statement.
//
// Holding the carrier back is correct: a class whose subject IS the credential opts into
// credential slots and then perturbs that exact header, and overwriting its payload with a live
// token would silently delete the only kind of probe that can say anything about a credential.
// What the holding back ALSO does is break the pairing that every differential in this runner
// rests on. The unperturbed control for the same vector is not a credential-slot request, so
// nothing is held back there and it goes out carrying the substituted LIVE credential, while the
// probe goes out carrying the CAPTURED one with a payload in it. Probe and control then differ
// by two variables and no row said so.
//
// IT IS WRITTEN DOWN RATHER THAN FIXED HERE because both alternatives are worse: substituting
// into the probe destroys the measurement, and withholding the substitution from the control
// would weaken every other class's baseline on the same vector. The row states the confound and
// names the experiment that removes it.
func (w triageCredWire) HeldBackSentence() string {
	if len(w.HeldBack) == 0 {
		return ""
	}
	return "CREDENTIAL HELD BACK, AND THIS ROW'S CONTROL IS NOT ITS MATCH: this probe writes to " +
		strings.Join(w.HeldBack, ", ") + ", so the live credential this run holds for that carrier " +
		"was deliberately left alone and the captured value went out unchanged, which is correct " +
		"because a class whose subject is the credential must keep its own payload. The unperturbed " +
		"control for this vector is NOT a credential-slot request, so nothing was held back there " +
		"and it carried the substituted live credential. PROBE AND CONTROL THEREFORE DIFFER BY TWO " +
		"VARIABLES, the payload and the credential, and a differential read off that pair is not a " +
		"single-variable measurement. THE EXPERIMENT THAT REMOVES THE CONFOUND: re-run this vector " +
		"with no credential source attached, so both arms replay the captured credential and the " +
		"payload is the only thing that differs"
}

// Sentence is the clause a reason string appends. It states what was measured and nothing else.
//
// THE CONFOUND CLAUSE IS APPENDED RATHER THAN SWITCHED ON, because a wire can substitute one
// carrier and hold another back on the same request, and reporting only the first would hide the
// second on exactly the rows where it matters most.
func (w triageCredWire) Sentence() string {
	s := w.substitutionSentence()
	if h := w.HeldBackSentence(); h != "" {
		if s != "" {
			s += ". "
		}
		s += h
	}
	return s
}

func (w triageCredWire) substitutionSentence() string {
	switch {
	case len(w.Substituted) > 0:
		return fmt.Sprintf("The bytes on the wire were NOT the captured ones: before sending, this run substituted the freshest credential it holds for this host (%s) into %s. What the request carried: %s",
			strings.Join(w.Describe, "; "), strings.Join(w.Substituted, ", "), strings.Join(w.Sent, "; "))
	case len(w.Added) > 0:
		return fmt.Sprintf("The captured request carried no credential of its own, and before sending, this run added the freshest one it holds for this host (%s) as %s. What the request carried: %s",
			strings.Join(w.Describe, "; "), strings.Join(w.Added, ", "), strings.Join(w.Sent, "; "))
	// THE TWO EXHAUSTIONS DO NOT SHARE A SENTENCE. The empty one is allowed to say the captured
	// bytes went out, because there was nothing to substitute. The second one is NOT: this run is
	// still handing carriers to the runner, so a claim that the wire carried the captured bytes
	// would be a statement about a request this branch did not read.
	case w.Status.Exhausted && w.Status.ExhaustionKind == triageCredExhaustedUnverifiable:
		return fmt.Sprintf("NOTHING THIS RUN HOLDS FOR %s HAS A LIFETIME IT CAN READ ANY MORE: %s",
			w.Status.Host, triageCredUnmeasuredClause(w.Status))
	case w.Status.Exhausted:
		return fmt.Sprintf("This run DID hold a usable credential for %s earlier and holds none now (%s), so the bytes on the wire were the captured ones: no browser session has been captured recently enough to replace them",
			w.Status.Host, w.Status.Note)
	case w.Status.Fresh == 0 && strings.TrimSpace(w.Status.Note) != "":
		return "This run holds no fresher credential for this host than the capture replays: " + w.Status.Note
	default:
		return ""
	}
}

// triageCredExhaustionLine is the run-level warning, said once per host.
//
// ONE LINE PER KIND, because the operator's next move differs. For an empty set the capture stream
// has stopped and a browser has to produce a session. For the second kind the run is still sending
// something and cannot tell whether it works, so the move is to put a credential whose lifetime is
// readable into the Session Manager, or to accept that everything after this point is unmeasured.
func triageCredExhaustionLine(runUUID, host string, st triageFreshCredStatus) string {
	if st.ExhaustionKind == triageCredExhaustedUnverifiable {
		return fmt.Sprintf("[TRIAGE-CRED] %s: NOTHING THIS RUN HOLDS FOR %s HAS A LIFETIME IT CAN READ. %s. "+
			"What remains may still be accepted and nothing this source reads can say either way, so from here "+
			"on the authentication state of this scan is UNMEASURED rather than known. Nothing here will mint a "+
			"credential: the host that issues it is out of scope. Open a browser session and let the manual "+
			"crawl capture one, or read every remaining result on this host as unmeasured.",
			runUUID, host, triageCredUnmeasuredClause(st))
	}
	return fmt.Sprintf("[TRIAGE-CRED] %s: NO FRESH CREDENTIAL IS ARRIVING FOR %s. "+
		"This run was authenticating with material last seen at %s and now has none (%s). "+
		"Nothing here will mint one: the host that issues it is out of scope. "+
		"Open a browser session and let the manual crawl capture it, or every remaining probe "+
		"measures the authentication wall.",
		runUUID, host, st.LastFreshAt.UTC().Format(time.RFC3339), st.Note)
}

// triageCredHostOf is the host a template addresses, lowercased, or "".
func triageCredHostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
