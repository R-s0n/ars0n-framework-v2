package utils

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// =================================================================================================
// WHAT THE RUNNER IS WILLING TO PUT ON THE WIRE AS A SESSION
// =================================================================================================
//
// THE TWO LAYERS ASK OPPOSITE QUESTIONS AND THE ANSWER CANNOT BE THE SAME BOOLEAN.
//
// triageCredentialCookie, in triageSlots.go, answers "must a probe leave this alone", and its safe
// direction is YES: perturbing a credential produces a 401 that reads exactly like a finding, so a
// doubtful cookie is refused as a slot and nothing is lost but one probe.
//
// This file answers "would substituting this teach us anything about the application under test",
// and its safe direction is the other way. A cookie that belongs to Stripe or Intercom is not
// refusable by the target, so it can never expire out of the credential set, so the source can
// never go Exhausted, so the run that stopped authenticating twenty minutes ago keeps reporting
// seven fresh credentials. That is the false clean this whole layer exists to close, arriving
// through the count instead of through a classifier.
//
// MEASURED ON THE LIVE ESTATE, 2026-09-20. The cookie jar of app.staging-v2.tradetalk.us, read out
// of manual_crawl_captures, carries __stripe_sid (3875 captures), __stripe_mid (3976),
// intercom-session-p7a9jdob (3789), intercom-device-id-p7a9jdob (3789) and
// CognitoIdentityServiceProvider.<clientid>.LastAuthUser (3776) beside the tokens that ARE the
// session. Of those the old gate admitted __stripe_sid, intercom-session-p7a9jdob and LastAuthUser
// as substitutable credentials, and all three reached the wire.

// triageWireVerdictCase is one cookie and what the substitution layer must do with it.
type triageWireVerdictCase struct {
	name  string
	value string
	send  bool
	why   string // a fragment the decline has to name, for the declines only
}

// THE CORPUS THE RULE IS MEASURED ON. Every name here was read out of the live
// manual_crawl_captures cookie jars; the values are shapes rebuilt in this file and none of them
// is a real value.
var triageWireVerdictCorpus = []triageWireVerdictCase{
	// Declined, by the vendor rule round 7 already built and this layer was not applying.
	{name: "intercom-session-p7a9jdob", value: strings.Repeat("a1B2", 90), send: false, why: "Intercom"},
	{name: "_hjSessionUser_2914", value: strings.Repeat("c3D4", 49), send: false, why: "Hotjar"},

	// Declined, by the general rule: the ONLY thing in the name that claims a credential is a
	// three or four letter word that means a session to some vendors and nothing to others, and
	// the rest of the name qualifies it.
	{name: "__stripe_sid", value: "bcb69e8a2f584ae498f62a0d3a05f7c56b1d1e", send: false, why: "sid"},

	// AND ITS COUNTER-CASE, KEPT, which is the honest limit of the general rule. rl_session is on
	// the same live estate and is very probably a vendor's, but the word session in it is
	// unambiguous and nothing in the name or the value says whose it is. Declining it would need
	// a vendor list, and a wrongly declined credential reopens the false clean the auth gate
	// exists to close, so this one goes out and Issue 5 of the round report says so.
	{name: "rl_session", value: strings.Repeat("e5F6", 36), send: true},

	// Declined, because it names a principal instead of proving one.
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.LastAuthUser",
		value: "aaaaaaaa-bbbb-cccc-dddd-000000000001", send: false, why: "principal"},

	// Kept. Every one of these is a real credential of a real application and declining one
	// reopens the false clean the auth gate exists to close.
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa.accessToken",
		value: "eyJraWQiOiJrMSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJ4In0.c2ln", send: true},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa.refreshToken",
		value: strings.Repeat("g7H8", 80), send: true},
	{name: "PHPSESSID", value: "26charactersofopaquehandle", send: true},
	{name: "ASP.NET_SessionId", value: "24charactersopaquehan01", send: true},
	{name: "TAsessionID", value: strings.Repeat("i9J0", 10), send: true},
	{name: "__RequestVerificationToken", value: strings.Repeat("k1L2", 27), send: true},
	{name: "sid", value: "26charactersofopaquehandle", send: true},
	{name: "connect.sid", value: "s%3Aopaquehandlevalue01", send: true},
	{name: "XSRF-TOKEN", value: strings.Repeat("m3N4", 10), send: true},
}

// TestTheWireLayerDeclinesACredentialItCannotLearnAnythingFrom is the A defect, measured.
func TestTheWireLayerDeclinesACredentialItCannotLearnAnythingFrom(t *testing.T) {
	for _, c := range triageWireVerdictCorpus {
		send, why := triageWireCookieVerdict(c.name, c.value)
		if send != c.send {
			t.Errorf("%s: substitutable = %v, want %v (%s)", c.name, send, c.send, why)
			continue
		}
		if send {
			continue
		}
		if why == "" {
			t.Errorf("%s was declined with no reason, so the operator cannot audit the decline", c.name)
		}
		if c.why != "" && !strings.Contains(why, c.why) {
			t.Errorf("%s was declined for %q, which does not name %q", c.name, why, c.why)
		}
	}
}

// THE LIVE JAR, END TO END THROUGH THE SPLITTER AND THE VERDICT.
//
// This is the cookie header of app.staging-v2.tradetalk.us with every value replaced by a shape of
// the same class and the same length class. What is asserted is the SET that reaches the wire: the
// three Cognito tokens that are the session, and nothing belonging to Stripe, to Intercom or to the
// Amplify bookkeeping beside them.
func TestTheLiveCookieJarSubstitutesOnlyTheApplicationsOwnCredentials(t *testing.T) {
	const pool = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3"
	const sub = "aaaaaaaa-bbbb-cccc-dddd-000000000001"
	jws := "eyJraWQiOiJrMSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJ4In0.c2ln"
	jar := strings.Join([]string{
		"_ga=GA1.1.0000000000.1700000000",
		"_gcl_au=1.1.000000000.0000000000",
		"__stripe_mid=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee00",
		"__stripe_sid=ffffffff-1111-2222-3333-44444444444455",
		"intercom-device-id-p7a9jdob=" + sub,
		"intercom-session-p7a9jdob=" + strings.Repeat("Q1w2", 90),
		"amplify-signin-with-hostedUI=false",
		pool + ".LastAuthUser=" + sub,
		pool + "." + sub + ".accessToken=" + jws,
		pool + "." + sub + ".idToken=" + jws,
		pool + "." + sub + ".refreshToken=" + strings.Repeat("R3e4", 80),
		pool + "." + sub + ".clockDrift=0",
		pool + "." + sub + ".deviceKey=us-east-1_00000000-1111-2222-3333-444444444444",
	}, "; ")

	var sent, declined []string
	for _, pair := range triageSplitCookieJar(jar) {
		ok, why := triageWireCookieVerdict(pair.Name, pair.Value)
		if ok {
			sent = append(sent, pair.Name)
			continue
		}
		if why != "" {
			declined = append(declined, pair.Name)
		}
	}
	want := []string{
		pool + "." + sub + ".accessToken",
		pool + "." + sub + ".idToken",
		pool + "." + sub + ".refreshToken",
	}
	if strings.Join(sent, "|") != strings.Join(want, "|") {
		t.Errorf("the wire set is\n  %s\nwant\n  %s", strings.Join(sent, "\n  "), strings.Join(want, "\n  "))
	}
	// THE THREE THAT USED TO RIDE EVERY PROBE, each now declined WITH A REASON rather than
	// dropped silently.
	for _, name := range []string{"__stripe_sid", "intercom-session-p7a9jdob", pool + ".LastAuthUser"} {
		found := false
		for _, d := range declined {
			if d == name {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was not declined with a reason the operator can read", name)
		}
	}
	// AND THE ANALYTICS NOISE IS NOT REPORTED AS A DECLINE. _ga was never a candidate, so listing
	// it would bury the three declines that matter in a jar of forty.
	for _, d := range declined {
		if strings.HasPrefix(d, "_ga") || strings.HasPrefix(d, "_gcl") {
			t.Errorf("%s was reported as a held-back credential; it was never a candidate", d)
		}
	}
}

// =================================================================================================
// THE WHOLE LIVE COOKIE CORPUS, BEFORE AND AFTER
// =================================================================================================
//
// 111 distinct cookie names read out of manual_crawl_captures on 2026-09-20 across every host the
// crawl touched, which is the estate this rule will actually meet: an application under test, its
// analytics, its consent banner, its bot management and two other tenants. The two Cognito subject
// ids in the names are replaced with synthetic UUIDs of the same shape, because a subject id names
// a person; nothing else is altered and no value is present at all.
//
// jws marks the names whose live value is a compact JWS (leading eyJ and exactly three segments),
// measured in SQL over the jars themselves. The fixtures below are built to that shape so the
// value net is exercised where it fires on the real estate and nowhere else.
//
// THE TEST LOGS THE WHOLE TABLE. The assertions are the handful of rows a regression would have to
// break, and the log is what makes the rest auditable instead of asserted.

type liveCookieName struct {
	name string
	jws  bool
}

var liveCookieCorpus = []liveCookieName{
	{name: "ai_session", jws: false},
	{name: "ai_user", jws: false},
	{name: "AMP_d6814239bf", jws: false},
	{name: "AMP_e6fe2a7b15", jws: false},
	{name: "AMP_f18952fd62", jws: false},
	{name: "amplify-signin-with-hostedUI", jws: false},
	{name: "AMP_MKTG_d6814239bf", jws: false},
	{name: "AMP_MKTG_e6fe2a7b15", jws: false},
	{name: "AMP_TEST_0b831ee3", jws: false},
	{name: "AMP_TEST_26a2679e", jws: false},
	{name: "AMP_TEST_2abbd7da", jws: false},
	{name: "AMP_TEST_588c9dbe", jws: false},
	{name: "AMP_TEST_6511729a", jws: false},
	{name: "AMP_TEST_7bc2108a", jws: false},
	{name: "AMP_TEST_7da1a77e", jws: false},
	{name: "AMP_TEST_80cfdfd9", jws: false},
	{name: "AMP_TEST_8b20233a", jws: false},
	{name: "AMP_TEST_8c3a1664", jws: false},
	{name: "AMP_TEST_a7e74fd4", jws: false},
	{name: "AMP_TEST_a88d1399", jws: false},
	{name: "AMP_TEST_b0bc209e", jws: false},
	{name: "AMP_TEST_b2bd6785", jws: false},
	{name: "AMP_TEST_b2e7571d", jws: false},
	{name: "AMP_TEST_b3bd1258", jws: false},
	{name: "AMP_TEST_becc28c7", jws: false},
	{name: "AMP_TEST_e5d9487b", jws: false},
	{name: "AMP_TEST_f26af051", jws: false},
	{name: "AMP_TLDTEST_632b8750", jws: false},
	{name: "AMP_TLDTEST_9f4da12c", jws: false},
	{name: "anon_tracking_id", jws: false},
	{name: "ARRAffinity", jws: false},
	{name: "ARRAffinitySameSite", jws: false},
	{name: "ASP.NET_SessionId", jws: false},
	{name: "_bti", jws: false},
	{name: "_bts", jws: false},
	{name: "__cf_bm", jws: false},
	{name: "cf_clearance", jws: false},
	{name: "cmapi_cookie_privacy", jws: false},
	{name: "cmapi_gtm_bl", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.accessToken", jws: true},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.clockDrift", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.deviceGroupKey", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.deviceKey", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.idToken", jws: true},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.randomPasswordKey", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.refreshToken", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.userData", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000002.accessToken", jws: true},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000002.clockDrift", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000002.deviceGroupKey", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000002.deviceKey", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000002.idToken", jws: true},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000002.randomPasswordKey", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000002.refreshToken", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000002.userData", jws: false},
	{name: "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.LastAuthUser", jws: false},
	{name: "__cuid", jws: false},
	{name: "_dailypay_session", jws: false},
	{name: "__ddg1_", jws: false},
	{name: "__ddg10_", jws: false},
	{name: "__ddg2_", jws: false},
	{name: "__ddg3", jws: false},
	{name: "__ddg5_", jws: false},
	{name: "__ddg8_", jws: false},
	{name: "__ddg9_", jws: false},
	{name: "__ddgid_", jws: false},
	{name: "ddg_last_challenge", jws: false},
	{name: "__ddgmark_", jws: false},
	{name: "_dd_s", jws: false},
	{name: "_dd_s_v2", jws: false},
	{name: "DSSP-APP-AFFINITY", jws: false},
	{name: "DSSP-APP-AFFINITYCORS", jws: false},
	{name: "_fbp", jws: false},
	{name: "_ga", jws: false},
	{name: "_ga_6GWPN1DQMV", jws: false},
	{name: "_ga_6N9DLV59RZ", jws: false},
	{name: "_ga_RYQTZXC7VF", jws: false},
	{name: "_gat_UA-68122528-1", jws: false},
	{name: "_gat_UA-90690411-48", jws: false},
	{name: "_gcl_au", jws: false},
	{name: "gdpr_accepted", jws: false},
	{name: "_gid", jws: false},
	{name: "intercom-device-id-p7a9jdob", jws: false},
	{name: "intercom-session-p7a9jdob", jws: false},
	{name: "_locale", jws: false},
	{name: "_mkto_trk", jws: false},
	{name: "notice_behavior", jws: false},
	{name: "notice_gdpr_prefs", jws: false},
	{name: "notice_preferences", jws: false},
	{name: "_one_NTAwMDAw", jws: false},
	{name: "onfido-web-sdk-analytics", jws: false},
	{name: "ph_phc_UCS6XEZHyunzC9LiIday0mfFoYXxKfjYV37jWJvvxAZ_posthog", jws: false},
	{name: "PHPSESSID", jws: false},
	{name: "QuantumMetricSessionID", jws: false},
	{name: "QuantumMetricUserID", jws: false},
	{name: "_rdt_em", jws: false},
	{name: "_rdt_uuid", jws: false},
	{name: "__RequestVerificationToken", jws: false},
	{name: "__rkp", jws: false},
	{name: "rl_anonymous_id", jws: false},
	{name: "rl_page_init_referrer", jws: false},
	{name: "rl_page_init_referring_domain", jws: false},
	{name: "rl_session", jws: false},
	{name: "_s_did", jws: true},
	{name: "__ssid", jws: false},
	{name: "__stripe_mid", jws: false},
	{name: "__stripe_sid", jws: false},
	{name: "TAsessionID", jws: false},
	{name: "time_zone", jws: false},
	{name: "_twpid", jws: false},
	{name: "wealth-ui-color-scheme", jws: false},
}

func TestTheWireRuleOverTheWholeLiveCookieCorpus(t *testing.T) {
	const opaque = "Hj28sKqmZ4tRw7yLbN1vXc0aPdEfGhIj"
	const jws = "eyJraWQiOiJrMSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJ4In0.c2ln"

	var wasCandidate, stillSent, heldBack []string
	reasons := map[string]string{}
	for _, c := range liveCookieCorpus {
		value := opaque
		if c.jws {
			value = jws
		}
		before := triageCredentialCookie(c.name, value)
		after, why := triageWireCookieVerdict(c.name, value)
		if !before {
			if after {
				t.Errorf("%s is sent by the wire rule and was never a candidate: this rule may only narrow", c.name)
			}
			continue
		}
		wasCandidate = append(wasCandidate, c.name)
		if after {
			stillSent = append(stillSent, c.name)
			continue
		}
		heldBack = append(heldBack, c.name)
		reasons[c.name] = why
		if why == "" {
			t.Errorf("%s was held back with no reason", c.name)
		}
	}
	t.Logf("LIVE COOKIE CORPUS: %d names, %d were credential candidates under the slot rule, "+
		"%d are substitutable under the wire rule, %d held back",
		len(liveCookieCorpus), len(wasCandidate), len(stillSent), len(heldBack))
	for _, n := range stillSent {
		t.Logf("  SEND %s", n)
	}
	for _, n := range heldBack {
		t.Logf("  HOLD %s: %s", n, reasons[n])
	}

	held := map[string]bool{}
	for _, n := range heldBack {
		held[n] = true
	}
	sent := map[string]bool{}
	for _, n := range stillSent {
		sent[n] = true
	}
	// The three that rode every probe on the live estate, and the session-replay handle the
	// telemetry tier catches only because it is read before the credential words.
	for _, n := range []string{
		"__stripe_sid",
		"intercom-session-p7a9jdob",
		"CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.LastAuthUser",
		"QuantumMetricSessionID",
	} {
		if !held[n] {
			t.Errorf("%s is still substituted onto every probe", n)
		}
	}
	// The application credentials on the same estate, which must all survive.
	for _, n := range []string{
		"CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.accessToken",
		"CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.idToken",
		"CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.aaaaaaaa-bbbb-cccc-dddd-000000000001.refreshToken",
		"PHPSESSID", "ASP.NET_SessionId", "TAsessionID", "__RequestVerificationToken",
	} {
		if !sent[n] {
			t.Errorf("%s is a real credential of a real application and the rule dropped it: %s", n, reasons[n])
		}
	}
}

// =================================================================================================
// EXHAUSTION IS ABOUT WHETHER ANYTHING THIS RUN CAN VERIFY IS STILL ALIVE
// =================================================================================================
//
// THE SHAPE BELOW IS REPRODUCED, NOT MEASURED HERE. Nothing in this round sent a request or read
// the ars0n database. What the round 14 audit read in SQL on app.staging-v2.tradetalk.us is:
// an accessToken and an idToken whose exp minus iat is 300 seconds, a five segment JWE
// refreshToken, and a randomPasswordKey; the newest capture 13h40m old; and the layer answering
// "fresh=1, exhausted=false" with BOTH tokens that authenticate long dead. The last two carriers
// have no readable expiry and never will, so triageFreshCredDead can never drop them, so the slice
// is never empty, so Exhausted could not fire.
//
// THE COUNT WAS ANSWERING A QUESTION IT CANNOT ANSWER. len(creds) says how many carriers this
// source would write into a request. Exhaustion asks whether anything that can authenticate is
// still alive, and the only evidence this file ever has for that is a READABLE EXPIRY.

// aCredWithAReadableExpiry is a credential this source can observe the death of: a JWT whose own
// exp claim was decoded. The value is a shape and not a token.
func aCredWithAReadableExpiry(cookie string, expires time.Time) triageFreshCred {
	return triageFreshCred{Cookie: cookie, value: "shape.not.a.token", Source: "manual_crawl_captures",
		Expires: expires, ExpirySource: "the token's own exp claim", Fingerprint: "1a2b3c4d"}
}

// aCredWithNoReadableExpiry is the shape that made exhaustion unreachable: a five segment JWE, or
// an opaque key, whose death this source can never observe.
func aCredWithNoReadableExpiry(cookie string) triageFreshCred {
	return triageFreshCred{Cookie: cookie, value: "opaque", Source: "manual_crawl_captures",
		Fingerprint: "5e6f7a8b"}
}

// statusFor builds what read() hands triageCarryExhaustion: the host, the rejected count, the
// declines and the Note composed from them. It deliberately does NOT set Fresh, Verifiable or
// Unmeasured, for the same reason read() does not: those three describe one slice and
// triageCarryExhaustion is their single owner.
func statusFor(host string, creds []triageFreshCred, expired int, declined []string) triageFreshCredStatus {
	return triageFreshCredStatus{
		Host: host, Expired: expired, Declined: declined,
		Note: triageCredNoteFor(len(creds), expired, declined),
	}
}

// TestExhaustionFiresWhenNothingThisRunCanVerifyIsAliveEvenThoughTheSliceIsNotEmpty is defect B,
// reproduced at the exact shape of the live estate.
func TestExhaustionFiresWhenNothingThisRunCanVerifyIsAliveEvenThoughTheSliceIsNotEmpty(t *testing.T) {
	const host = "app.staging-v2.tradetalk.us"
	t0 := time.Date(2026, 9, 20, 12, 9, 43, 0, time.UTC)

	// The capture is fresh: two Cognito JWS with a 300 second life, and two carriers whose death
	// this source can never see.
	alive := []triageFreshCred{
		aCredWithAReadableExpiry("CognitoIdentityServiceProvider.pool.sub.accessToken", t0.Add(300*time.Second)),
		aCredWithAReadableExpiry("CognitoIdentityServiceProvider.pool.sub.idToken", t0.Add(300*time.Second)),
		aCredWithNoReadableExpiry("CognitoIdentityServiceProvider.pool.sub.refreshToken"),
		aCredWithNoReadableExpiry("CognitoIdentityServiceProvider.pool.sub.randomPasswordKey"),
	}
	first := triageCarryExhaustion(nil, alive, statusFor(host, alive, 0, nil), t0)
	if first.Exhausted {
		t.Fatalf("a host holding two live tokens was called exhausted: %+v", first)
	}
	if first.Verifiable != 2 {
		t.Fatalf("verifiable = %d, want 2: two of the four carry an exp this source decoded", first.Verifiable)
	}

	// Thirteen hours forty minutes later, which is how old the newest Cognito capture actually is.
	// triageFreshCredDead has dropped both JWS; what is left is what can never expire.
	later := t0.Add(13*time.Hour + 40*time.Minute)
	left := alive[2:]
	second := triageCarryExhaustion(&first, left, statusFor(host, left, 2, nil), later)

	if second.Fresh == 0 {
		t.Fatal("this test is not reproducing the defect: the defect is that the slice is NOT empty")
	}
	if !second.Exhausted {
		t.Fatalf("EXHAUSTION IS UNREACHABLE: fresh=%d verifiable=%d exhausted=%v. "+
			"Both credentials that authenticate are thirteen hours dead and the run still reports it holds one, "+
			"so noteCredExhaustion never fires and the back half of the scan measures the login wall as a clean.",
			second.Fresh, second.Verifiable, second.Exhausted)
	}
	if second.ExhaustionKind != triageCredExhaustedUnverifiable {
		t.Errorf("exhaustion kind = %q, want %q: the operator's next move is different from the one for an empty set",
			second.ExhaustionKind, triageCredExhaustedUnverifiable)
	}
}

// AND THE OLD EXHAUSTION STILL FIRES. A host that goes from holding credentials to holding none is
// the case this field was written for and widening the rule must not lose it, including for a host
// whose only credentials never had a readable expiry in the first place.
func TestTheEmptySetExhaustionStillFiresAndIsNamedApart(t *testing.T) {
	const host = "app.example.test"
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		held []triageFreshCred
	}{
		{"credentials with a readable expiry", []triageFreshCred{aCredWithAReadableExpiry("sid", t0.Add(time.Hour))}},
		{"credentials with none", []triageFreshCred{aCredWithNoReadableExpiry("sid")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			had := triageCarryExhaustion(nil, tc.held, statusFor(host, tc.held, 0, nil), t0)
			if had.Exhausted {
				t.Fatalf("a host that holds a credential was called exhausted: %+v", had)
			}
			gone := triageCarryExhaustion(&had, nil, statusFor(host, nil, 1, nil), t0.Add(time.Hour))
			if !gone.Exhausted {
				t.Fatal("a host that held a credential and now holds none is not exhausted, which is the state this field was written for")
			}
			if gone.ExhaustionKind != triageCredExhaustedEmpty {
				t.Errorf("exhaustion kind = %q, want %q", gone.ExhaustionKind, triageCredExhaustedEmpty)
			}
		})
	}
}

// A host that NEVER held anything verifiable is not exhausted, it is unmeasured from the start,
// and calling that exhaustion would be inventing a past this source never observed.
func TestAHostThatNeverHeldAVerifiableCredentialIsNotCalledExhausted(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	held := []triageFreshCred{aCredWithNoReadableExpiry("opaque_handle")}
	first := triageCarryExhaustion(nil, held, statusFor("h", held, 0, nil), t0)
	second := triageCarryExhaustion(&first, held, statusFor("h", held, 0, nil), t0.Add(time.Hour))
	if second.Exhausted {
		t.Fatalf("a host whose credentials never carried a readable expiry was called exhausted, "+
			"which asserts a transition this source never observed: %+v", second)
	}
}

// THE TWO EXHAUSTIONS MUST NOT SHARE A SENTENCE. The empty one says the captured bytes went out
// because there was nothing to substitute. In the partial one the run IS still substituting, so
// that sentence would be a claim about the wire that nothing read.
func TestTheTwoExhaustionsDoNotShareASentence(t *testing.T) {
	const host = "app.staging-v2.tradetalk.us"
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	// Both states are reached through the production decision rather than typed into a struct, so
	// what is pinned is a sentence an operator can actually be shown.
	held := []triageFreshCred{
		aCredWithAReadableExpiry("CognitoIdentityServiceProvider.pool.sub.accessToken", t0.Add(5*time.Minute)),
		aCredWithNoReadableExpiry("CognitoIdentityServiceProvider.pool.sub.refreshToken"),
	}
	start := triageCarryExhaustion(nil, held, statusFor(host, held, 0, nil), t0)
	left := held[1:]
	partial := triageCarryExhaustion(&start, left, statusFor(host, left, 1, nil), t0.Add(time.Hour))
	empty := triageCarryExhaustion(&start, nil, statusFor(host, nil, 2, nil), t0.Add(time.Hour))

	if !partial.Exhausted || !empty.Exhausted {
		t.Fatalf("this test is not exercising both exhaustions: partial=%v empty=%v", partial.Exhausted, empty.Exhausted)
	}

	partialSentence := triageCredWire{Status: partial}.Sentence()
	emptySentence := triageCredWire{Status: empty}.Sentence()

	if partialSentence == emptySentence {
		t.Fatal("both exhaustions produce the same sentence, so the operator cannot tell a run holding nothing from a run holding only carriers it cannot measure")
	}
	for _, forbidden := range []string{"holds none now", "the bytes on the wire were the captured ones"} {
		if strings.Contains(partialSentence, forbidden) {
			t.Errorf("the partial exhaustion sentence claims %q, which is false: this run is still substituting %d credential(s): %s",
				forbidden, partial.Fresh, partialSentence)
		}
	}
	for _, want := range []string{"refreshToken", "expiry it could read"} {
		if !strings.Contains(strings.ToLower(partialSentence), strings.ToLower(want)) {
			t.Errorf("the partial exhaustion sentence does not name %q, so nothing tells the operator which carriers are still going out unmeasured: %s",
				want, partialSentence)
		}
	}
	// AND IT NAMES NO CAUSE IT DID NOT OBSERVE. A credential with a readable expiry can leave the
	// set without expiring: the session_tokens row can be deactivated, or the capture can fall off
	// the end of the row limit. When nothing was observed to expire, nothing may say one did.
	noneExpired := triageCarryExhaustion(&start, left, statusFor(host, left, 0, nil), t0.Add(time.Hour))
	clause := triageCredUnmeasuredClause(noneExpired)
	if strings.Contains(clause, "expiry had passed") {
		t.Errorf("the sentence says a credential expired and this source counted none expiring on that read: %s", clause)
	}
	if !strings.Contains(triageCredUnmeasuredClause(partial), "expiry had passed") {
		t.Errorf("the sentence drops the %d expiries that WERE observed: %s", partial.Expired, triageCredUnmeasuredClause(partial))
	}

	// And the run-level warning is the same two facts, told apart.
	partialLine := triageCredExhaustionLine("run-1", host, partial)
	emptyLine := triageCredExhaustionLine("run-1", host, empty)
	if partialLine == emptyLine {
		t.Error("the run-level exhaustion warning is the same line for both kinds")
	}
	if strings.Contains(partialLine, "now has none") {
		t.Errorf("the run warning for the partial exhaustion says the run has no credential, and it has %d: %s", partial.Fresh, partialLine)
	}
}

// DEFECT C. With Fresh above zero the declines reached only the API log, so an operator whose real
// credential was held back by the cookie rule had no way to find out. SessionWireReading.Note is
// what the card renders (client/src/modals/SessionInvestigateModal.js renders wire.note whenever it
// is non-empty, independently of wire.fresh), and it was empty on exactly the branch the live
// estate is on.
func TestADeclineReachesTheOperatorEvenWhenTheSourceStillHoldsSomething(t *testing.T) {
	declined := []string{
		"the only thing in myapp_sid that claims a credential is the ambiguous word sid",
		"metrics_session carries the word metric",
	}
	note := triageCredNoteFor(3, 0, declined)
	if note == "" {
		t.Fatal("THE DECLINES ARE INVISIBLE: the source held three credentials and held two back, and the status Note " +
			"is empty, so the card shows nothing and the only record is a line in the API log. A wrongly held " +
			"credential stays invisible exactly where it costs the most.")
	}
	for _, want := range []string{"myapp_sid", "metrics_session", "not substituted"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not name %q: %s", want, note)
		}
	}
	// The zero case keeps everything it already said.
	if n := triageCredNoteFor(0, 2, declined); !strings.Contains(n, "already expired") || !strings.Contains(n, "myapp_sid") {
		t.Errorf("the nothing-usable note lost a clause: %s", n)
	}
}

// =================================================================================================
// ROUND 16: A DEVICE SECRET IS NOT A SESSION CREDENTIAL
// =================================================================================================
//
// FAIL FIRST, measured against the tree as it stood:
//
//	--- FAIL: TestADeviceSecretIsNotSubstitutedAsASession
//	    randomPasswordKey was substituted onto the probe: the Amplify device password of a real
//	    person went out on every request, on the word "password" in its name
//	--- FAIL: TestOneProbeAssertsOnePrincipal
//	    the wire set asserts 2 principals at once: 6 credentials for 2 people
//	--- FAIL: TestAFirstReadOfZeroVerifiableIsSaidOutLoud
//	    a run that has never been able to measure a lifetime said nothing at all: NeverVerifiable
//	    is false and the note is ""
//
// WHAT THE LIVE JAR HOLDS, read in SQL over manual_crawl_captures and not over a request. Two
// Cognito subjects, each with deviceKey, deviceGroupKey, randomPasswordKey, accessToken, idToken,
// refreshToken, userData and clockDrift. The first two of each triple were held only because the
// slot vocabulary never called them candidates; the third rode every probe. deviceKey,
// deviceGroupKey and randomPasswordKey are Amplify's device SRP record: they are presented to skip
// a second factor, they outlive the session, and 43 captures carry them in a jar that carries no
// session token at all.

func TestADeviceSecretIsNotSubstitutedAsASession(t *testing.T) {
	const pool = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3"
	const sub = "aaaaaaaa-bbbb-cccc-dddd-000000000001"
	for _, tc := range []struct {
		name string
		send bool
	}{
		{pool + "." + sub + ".randomPasswordKey", false},
		{pool + "." + sub + ".deviceKey", false},
		{pool + "." + sub + ".deviceGroupKey", false},
		{pool + "." + sub + ".accessToken", true},
		{pool + "." + sub + ".idToken", true},
		{pool + "." + sub + ".refreshToken", true},
	} {
		send, why := triageWireCookieVerdict(tc.name, strings.Repeat("Q1w2", 8))
		if send != tc.send {
			t.Errorf("%s: send=%v want %v (%s)", tc.name, send, tc.send, why)
		}
		if !send && tc.name != pool+"."+sub+".deviceKey" && tc.name != pool+"."+sub+".deviceGroupKey" && why == "" {
			t.Errorf("%s was held with no reason the operator can read", tc.name)
		}
	}
}

// THE RULE IS A ROLE VOCABULARY AND NOT A LIST OF COGNITO LEAVES. An SDK nobody has heard of that
// stores a device password under its own name has to be read the same way, and a name whose LEAF
// says session token has to survive a prefix that says device.
func TestTheLongTermSecretRuleGeneralisesPastCognito(t *testing.T) {
	opaque := strings.Repeat("Q1w2", 8)
	for _, tc := range []struct {
		name string
		send bool
		note string
	}{
		{"myapp.device.randomPasswordKey", false, "another SDK, same device record"},
		{"trusted_device_secret", false, "a remembered-device secret under no namespace at all"},
		{"mfa_token", false, "a second factor is not a session"},
		{"totp_secret", false, "a one-time code seed is not a session"},
		{"recovery_token", false, "a recovery secret is not a session"},
		{"device_manager_session_token", true, "the leaf says session token; device is the subject of the app"},
		{"deviceIdToken", true, "an id token issued to a device is still a token this run can send"},
		{"accessToken", true, "unchanged"},
		{"password_grant_access_token", true, "the leaf is access token; the prefix names the grant"},
	} {
		send, why := triageWireCookieVerdict(tc.name, opaque)
		if send != tc.send {
			t.Errorf("%s: send=%v want %v (%s) [%s]", tc.name, send, tc.send, why, tc.note)
		}
	}
}

// THE CARRIER NAME IS WHAT THE CARD PRINTS, AND IT PRINTS THE WHOLE NAME. Three surfaces read it:
// the substitution sentence, the held-back sentence beside it and the unmeasured-carrier clause.
// An Amplify storage key carries the Cognito subject of whoever is signed in, and that subject is
// exactly what tells one signed-in account from another on the card. It goes out intact, along
// with the credential's own value.
func TestACarrierNamePrintsTheWholeStorageKey(t *testing.T) {
	const pool = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3"
	const sub = "d4887448-50b1-7015-03be-6b285cf9fb5e"
	name := pool + "." + sub + ".refreshToken"
	c := aCredWithNoReadableExpiry(name)
	got := c.Carrier()
	if !strings.Contains(got, sub) {
		t.Errorf("the carrier the card prints drops the subject that identifies the account: %s", got)
	}
	if !strings.Contains(got, "7cd3keuknr18mv2boiaesbgce3") {
		t.Errorf("the carrier drops the app client id: %s", got)
	}
	if !strings.Contains(c.String(), sub) {
		t.Errorf("the credential description drops the subject: %s", c.String())
	}
	if !strings.Contains(c.String(), c.Value()) {
		t.Errorf("the credential description does not carry the value that went on the wire: %s", c.String())
	}
	// TWO ACCOUNTS ARE VISIBLY TWO, by their own subjects rather than by a stand-in for one.
	other := aCredWithNoReadableExpiry(pool + ".d4189418-5001-7019-d7ee-ce3897389622.refreshToken")
	if other.Carrier() == got {
		t.Errorf("two subjects collapsed into one carrier name: %s", got)
	}
	// AND THE WIRE IS UNTOUCHED: the cookie a probe sets keeps the name the target looks for.
	if c.Cookie != name {
		t.Errorf("the rendering rewrote the cookie name a probe has to set: %q", c.Cookie)
	}
}

// ONE PROBE ASSERTS ONE PRINCIPAL. See triageOnePrincipal: a jar that has seen two sign-ins keeps
// both Amplify records, their cookie names differ, so every layer above read them as different
// carriers and substituted all of them.
func TestOneProbeAssertsOnePrincipal(t *testing.T) {
	const pool = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3"
	const subA = "aaaaaaaa-bbbb-cccc-dddd-000000000001"
	const subB = "bbbbbbbb-cccc-dddd-eeee-000000000002"
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	fresher := triageFreshCred{Cookie: pool + "." + subA + ".accessToken", value: "a", Fingerprint: "1111aaaa",
		Expires: t0.Add(time.Hour), ExpirySource: "the token's own exp claim"}
	staler := triageFreshCred{Cookie: pool + "." + subB + ".accessToken", value: "b", Fingerprint: "2222bbbb",
		Expires: t0.Add(time.Minute), ExpirySource: "the token's own exp claim"}
	unowned := aCredWithNoReadableExpiry("app_session")

	out, declined := triageOnePrincipal([]triageFreshCred{staler, fresher, unowned})
	seen := map[string]bool{}
	for _, c := range out {
		if who := credentialNamePrincipalSegment(c.Cookie); who != "" {
			seen[who] = true
		}
	}
	if len(seen) != 1 {
		t.Errorf("the wire set asserts %d principals at once: %d credentials", len(seen), len(out))
	}
	// THE FRESHEST PRINCIPAL IS THE ONE KEPT, by the same comparison the ranking uses.
	if len(out) != 2 || out[0].Cookie != fresher.Cookie && out[1].Cookie != fresher.Cookie {
		t.Errorf("the principal kept is not the one whose credential is freshest: %v", out)
	}
	// A CREDENTIAL THAT NAMES NOBODY IS ALWAYS KEPT. A bare session cookie is not evidence of a
	// second person, and dropping one would be this rule losing a credential on a guess.
	kept := false
	for _, c := range out {
		if c.Cookie == unowned.Cookie {
			kept = true
		}
	}
	if !kept {
		t.Error("a credential with no principal segment was dropped by the one-principal rule")
	}
	// AND WHAT WAS DROPPED IS SAID, naming BOTH accounts: which one went on the wire and which
	// one did not is the whole content of the decline, and a sentence that named neither would
	// leave the operator unable to tell which session the run is measuring.
	if len(declined) != 1 {
		t.Fatalf("the drop was silent: %v", declined)
	}
	if !strings.Contains(declined[0], subA) || !strings.Contains(declined[0], subB) {
		t.Errorf("the decline does not name the account it kept and the one it dropped: %s", declined[0])
	}
	// ONE PRINCIPAL IN THE JAR CHANGES NOTHING AT ALL.
	only, none := triageOnePrincipal([]triageFreshCred{fresher, unowned})
	if len(only) != 2 || len(none) != 0 {
		t.Errorf("a jar with one principal was narrowed: kept %d, declined %v", len(only), none)
	}
}

// =================================================================================================
// ROUND 16: A FIRST READ OF ZERO IS A DIFFERENT FACT FROM A TRANSITION TO ZERO
// =================================================================================================
//
// THE GUARD IS RIGHT AND ITS CONSEQUENCE IS NOT. Without a moment when Verifiable was above zero
// there is no transition to report and reporting one would invent a past. Measured on the live
// estate, the FIRST read already reads Verifiable zero, so LastVerifiableAt stays zero for the
// whole run and neither exhaustion can ever fire there. Silence then reads as not-yet-exhausted,
// which is the one thing it is not.

func TestAFirstReadOfZeroVerifiableIsSaidOutLoud(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	held := []triageFreshCred{aCredWithNoReadableExpiry("refreshToken")}
	first := triageCarryExhaustion(nil, held, statusFor("h", held, 0, nil), t0)

	if !first.NeverVerifiable {
		t.Errorf("a run that has never been able to measure a lifetime said nothing at all: "+
			"NeverVerifiable is %v and the note is %q", first.NeverVerifiable, first.Note)
	}
	// IT IS NOT AN EXHAUSTION. Nothing transitioned, so claiming one would be the invented past
	// the guard exists to prevent.
	if first.Exhausted || first.ExhaustionKind != "" {
		t.Errorf("a first read of zero was reported as an exhaustion: exhausted=%v kind=%q",
			first.Exhausted, first.ExhaustionKind)
	}
	if !strings.Contains(first.Note, "NEVER held a credential for this host whose expiry it could READ") {
		t.Errorf("the note does not say it out loud: %q", first.Note)
	}
	// AND IT SURVIVES THE REFRESH, because it is a statement about the run.
	second := triageCarryExhaustion(&first, held, statusFor("h", held, 0, nil), t0.Add(time.Hour))
	if !second.NeverVerifiable || second.Exhausted {
		t.Errorf("the state did not survive a refresh: %+v", second)
	}
	// THE TWO STATES NEVER SHARE A SENTENCE. A run that HAD a readable lifetime and lost it is
	// exhausted and says so; it must not also say it never had one.
	withOne := []triageFreshCred{{Cookie: "jwt", value: "v", Fingerprint: "aaaa1111",
		Expires: t0.Add(time.Hour), ExpirySource: "the token's own exp claim"}}
	had := triageCarryExhaustion(nil, withOne, statusFor("h", withOne, 0, nil), t0)
	lost := triageCarryExhaustion(&had, held, statusFor("h", held, 0, nil), t0.Add(time.Hour))
	if !lost.Exhausted || lost.ExhaustionKind != triageCredExhaustedUnverifiable {
		t.Fatalf("the transition stopped firing: %+v", lost)
	}
	if lost.NeverVerifiable {
		t.Error("a run that lost a readable lifetime also claimed it never had one")
	}
	if strings.Contains(lost.Note, "has NEVER held") {
		t.Errorf("the two states shared a sentence: %q", lost.Note)
	}
	// AND AN EMPTY SET IS STILL THE FIRST EXHAUSTION AND NOT THIS. Fresh is zero there, so there
	// is nothing being handed out to be unmeasurable.
	empty := triageCarryExhaustion(&had, nil, statusFor("h", nil, 0, nil), t0.Add(2*time.Hour))
	if empty.NeverVerifiable {
		t.Errorf("an empty set claimed it never held a readable lifetime: %+v", empty)
	}
}

// =================================================================================================
// ROUND 16: WHAT THE CAPTURED JARS KNOW THAT THE NAME CANNOT
// =================================================================================================
//
// MEASURED IN SQL over all 4,011 captured jars for app.staging-v2.tradetalk.us: 3,809 carry a
// compact JWS and 202 carry none. Every vendor cookie in that jar appears in the 202 and every
// credential that IS the session appears in none of them. That is the reach the name rule does not
// have: over 45 cookie names real applications deploy and 25 third-party names hardcoded nowhere,
// the name tiers alone held 5 of the 45 and sent 16 of the 25; with this partition they hold 0 and
// send 0.
//
// ROUND 17 MOVED THE FIRST OF THOSE TWO NUMBERS TO 3 and left the second at 16, by closing the two
// spellings that disagreed. portal_sid and app_sess are now sent by the name rules and no longer
// need rescuing, and _stripe_sess_id is now held by the VENDOR rule rather than sent. The rates
// are pinned in TestTheNameOnlyRatesOverBothCorpora, and the cases below are the ones where the
// corpus is still the only thing that answers.

func anonWindowFor(t *testing.T, anon, authed int, inAnon map[string]int, authedOnly ...string) triageAnonWindow {
	t.Helper()
	w := triageAnonWindow{Anon: anon, Authed: authed, Seen: map[string]int{}, InAnon: map[string]int{}}
	for n, c := range inAnon {
		w.InAnon[n] = c
		w.Seen[n] = c + authed
	}
	for _, n := range authedOnly {
		w.Seen[n] = authed
	}
	return w
}

func TestTheCapturedJarsHoldWhatTheApplicationGivesAnAnonymousVisitor(t *testing.T) {
	opaque := strings.Repeat("Q1w2", 8)
	w := anonWindowFor(t, 202, 3809, map[string]int{
		"fs_session": 186, "_clarity_session": 145, "_heap_session": 43, "_stripe_sess_id": 200,
	}, "portal_sid", "acme_auth", "app_sess", "mycompany_sso_token", "okta-token-storage")

	// THE HOLD DIRECTION. Sixteen of these shapes ride every probe on the name rule alone, and
	// nothing in the name separates fs_session from a real vendor_session nobody has listed.
	//
	// _stripe_sess_id IS NO LONGER ONE OF THEM and is asserted separately below: the vendor rule
	// holds it now, which is the right reason and the one that does not need a corpus.
	for _, n := range []string{"fs_session", "_clarity_session", "_heap_session"} {
		if send, _ := triageWireCookieVerdict(n, opaque); !send {
			t.Fatalf("%s was already held by the name rule; this case measures nothing", n)
		}
		send, why := triageWireCookieVerdictInCorpus(n, opaque, w)
		if send {
			t.Errorf("%s rode the probe although the application hands it to an anonymous visitor", n)
		}
		if !strings.Contains(why, "carry no session of any kind") {
			t.Errorf("%s was held without saying what was read: %q", n, why)
		}
	}

	// AND THE VENDOR RULE ANSWERS FOR STRIPE WITHOUT A CORPUS, for both spellings, which is what
	// a named product is for. See triageWireVendorAddendum.
	for _, n := range []string{"__stripe_sid", "_stripe_sess_id"} {
		send, why := triageWireCookieVerdict(n, opaque)
		if send || !strings.Contains(why, "Stripe") {
			t.Errorf("%s is not held by the vendor rule: send=%v why=%q", n, send, why)
		}
	}

	// THE KEEP DIRECTION, WHICH IS THE DANGEROUS ONE. Three real credentials are held by the
	// qualifier tier on a guess about a qualifier, and the corpus knows the qualifier is the
	// application's own.
	for _, n := range []string{"acme_auth", "mycompany_sso_token", "okta-token-storage"} {
		if send, _ := triageWireCookieVerdict(n, opaque); send {
			t.Fatalf("%s was already sent by the name rule; this case measures nothing", n)
		}
		if send, why := triageWireCookieVerdictInCorpus(n, opaque, w); !send {
			t.Errorf("%s is present only in authenticated jars and was still held: %s", n, why)
		}
	}
}

// THE RESCUE REACHES EXACTLY ONE TIER. A named vendor, a telemetry word and a principal pointer
// are NOT overturned by a cookie happening to be absent from the anonymous jars: an estate that
// loads its session replay only after sign-in would otherwise re-admit the cookie that makes
// exhaustion unreachable, and LastAuthUser would come back.
func TestTheCorpusRescueDoesNotReachTheOtherDeclines(t *testing.T) {
	opaque := strings.Repeat("Q1w2", 8)
	const lastAuth = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.LastAuthUser"
	w := anonWindowFor(t, 202, 3809, map[string]int{"_gcl_au": 202},
		"__cf_bm", "QuantumMetricSessionID", lastAuth, "cf_clearance",
		"CognitoIdentityServiceProvider.p.aaaaaaaa-bbbb-cccc-dddd-000000000001.randomPasswordKey")
	for _, n := range []string{
		"__cf_bm", "QuantumMetricSessionID", lastAuth, "cf_clearance",
		"CognitoIdentityServiceProvider.p.aaaaaaaa-bbbb-cccc-dddd-000000000001.randomPasswordKey",
	} {
		if send, why := triageWireCookieVerdictInCorpus(n, opaque, w); send {
			t.Errorf("%s was re-admitted by a corpus rescue it must not reach (%s)", n, why)
		}
	}
}

// A PARTITION WITH NOTHING ON ONE SIDE IS NOT EVIDENCE OF A BOUNDARY. Eleven of the twelve hosts
// in the live corpus have no authenticated side at all, so on all eleven this layer has to be
// silent and the name rules have to answer alone.
func TestACorpusThatSawOnlyOneStateSaysNothing(t *testing.T) {
	opaque := strings.Repeat("Q1w2", 8)
	names := []string{"fs_session", "app_sess", "portal_sid", "_clarity_session", "PHPSESSID", "accessToken"}
	for _, w := range []triageAnonWindow{
		{},
		anonWindowFor(t, 0, 3809, map[string]int{}, names...),
		anonWindowFor(t, 202, 0, map[string]int{"fs_session": 202, "app_sess": 202}),
	} {
		if w.Discriminating() {
			t.Fatalf("a corpus with authed=%d anon=%d claimed an opinion", w.Authed, w.Anon)
		}
		for _, n := range names {
			a, aw := triageWireCookieVerdict(n, opaque)
			b, bw := triageWireCookieVerdictInCorpus(n, opaque, w)
			if a != b || aw != bw {
				t.Errorf("a corpus with authed=%d anon=%d changed the verdict on %s: %v -> %v",
					w.Authed, w.Anon, n, a, b)
			}
		}
	}
}

// THE SEED IS TWO WITNESSES THAT CANNOT BE WRONG, and the framework handle is in it for a specific
// failure: an application whose session is an opaque PHPSESSID and which mints no JWS anywhere
// would otherwise read as unauthenticated in every capture, and this layer would hold the one
// credential the run has.
func TestTheAuthenticatedSeedReadsOnlyTheTiersThatCannotBeWrong(t *testing.T) {
	jws := "eyJraWQiOiJrMSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJ4In0.c2ln"
	for _, tc := range []struct {
		jar    string
		authed bool
		why    string
	}{
		{"app_session=" + jws, true, "a compact JWS is a session whatever the cookie is called"},
		{"PHPSESSID=abcdef0123456789abcdef0123", true, "a published framework handle"},
		{"sid=abcdef0123456789abcdef0123", true, "a published framework handle"},
		{"_ga=GA1.1.0.0; fs_session=abc123", false, "vendor cookies alone are an anonymous jar"},
		{"my_session=abcdef0123456789", false, "the name vocabulary is deliberately not in the seed"},
		{"", false, "no jar at all"},
	} {
		if got := triageJarIsAuthenticated(triageSplitCookieJar(tc.jar)); got != tc.authed {
			t.Errorf("%q read as authed=%v, want %v (%s)", tc.jar, got, tc.authed, tc.why)
		}
	}
}

// A ROW THE OPERATOR TYPED IN IS NEVER NARROWED BY THE ONE-PRINCIPAL RULE. read() states that
// exemption for the wire rule already, for the same reason, and the two must not disagree about
// what a deliberate choice is.
func TestTheOnePrincipalRuleDoesNotSecondGuessTheSessionManager(t *testing.T) {
	const pool = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3"
	const subA = "aaaaaaaa-bbbb-cccc-dddd-000000000001"
	const subB = "bbbbbbbb-cccc-dddd-eeee-000000000002"
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	typedIn := triageFreshCred{Cookie: pool + "." + subB + ".accessToken", value: "b", Fingerprint: "2222bbbb",
		Source: "session_tokens", Expires: t0.Add(time.Minute), ExpirySource: "the session_tokens.expires_at column (never validated)"}
	captured := triageFreshCred{Cookie: pool + "." + subA + ".accessToken", value: "a", Fingerprint: "1111aaaa",
		Source: "manual_crawl_captures", Expires: t0.Add(time.Hour), ExpirySource: "the token's own exp claim"}

	out, declined := triageOnePrincipal([]triageFreshCred{typedIn, captured})
	if len(out) != 2 || len(declined) != 0 {
		t.Errorf("a session_tokens row was dropped by the one-principal rule: kept %d, declined %v", len(out), declined)
	}

	// TWO CAPTURED PRINCIPALS ARE STILL NARROWED, so the exemption is an exemption and not a
	// switch that turns the rule off.
	third := triageFreshCred{Cookie: pool + ".cccccccc-dddd-eeee-ffff-000000000003.accessToken", value: "c",
		Fingerprint: "3333cccc", Source: "manual_crawl_captures", Expires: t0.Add(time.Minute)}
	out, declined = triageOnePrincipal([]triageFreshCred{typedIn, captured, third})
	if len(out) != 2 || len(declined) != 1 {
		t.Errorf("the capture path was not narrowed beside an exempt row: kept %d, declined %v", len(out), declined)
	}
}

// WHICH PRINCIPAL SURVIVES IS A FUNCTION OF WHAT WAS READ AND NOT OF THE RUNTIME. A Go map
// iterates in a different order every time, so two principals whose best credentials compare EQUAL
// would leave a different one on the wire on every refresh, and two probes a second apart would
// assert two different people.
func TestTheSurvivingPrincipalDoesNotDependOnMapOrder(t *testing.T) {
	const pool = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3"
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	in := []triageFreshCred{}
	// Six principals whose credentials are indistinguishable by every field the comparison reads:
	// no expiry, the same observation time, the same source.
	for _, sub := range []string{
		"aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002",
		"cccccccc-0000-0000-0000-000000000003", "dddddddd-0000-0000-0000-000000000004",
		"eeeeeeee-0000-0000-0000-000000000005", "ffffffff-0000-0000-0000-000000000006",
	} {
		in = append(in, triageFreshCred{Cookie: pool + "." + sub + ".accessToken", value: "v",
			Source: "manual_crawl_captures", Observed: t0, Fingerprint: "aaaa1111"})
	}
	first, firstWhy := triageOnePrincipal(in)
	if len(first) != 1 {
		t.Fatalf("six principals did not narrow to one: %d kept", len(first))
	}
	for i := 0; i < 200; i++ {
		again, againWhy := triageOnePrincipal(in)
		if len(again) != 1 || again[0].Cookie != first[0].Cookie {
			t.Fatalf("run %d kept a different principal: %s then %s",
				i, first[0].Cookie, again[0].Cookie)
		}
		if len(againWhy) != len(firstWhy) {
			t.Fatalf("run %d declined a different number of principals: %d then %d",
				i, len(firstWhy), len(againWhy))
		}
	}
}

// =================================================================================================
// ROUND 17: THE NAME RULE HAS TO BE COHERENT WITH ITSELF
// =================================================================================================
//
// The captured jars answer for a cookie they have seen. Where they have not seen one they have no
// opinion, and there the name rules decide alone, which is most hosts: eleven of the twelve in the
// live corpus cannot speak at all. So the name rules are still load bearing, and a rule that gives
// two spellings of one name opposite answers is not a rule.
//
// TWO PAIRS WERE MEASURED DISAGREEING, in both directions, on the names and after the jars were
// read:
//
//	__stripe_sid  held    _stripe_sess_id  sent
//	app_sess      held    app_session      sent
//
// In both, the sent spelling reaches triageCredentialCompactForms ("session", "sessid") and the
// held spelling reaches the qualifier tier instead, so what decided was whether the role word had
// been abbreviated. The Stripe pair is closed by the VENDOR rule, which is where a named product
// belongs and which answers the same for every spelling of it. The app pair is closed by reading
// the abbreviation as the word it abbreviates.

// r17AppCookies are 45 cookie names real applications and frameworks deploy. The rate over them is
// the DANGEROUS direction: every one held is a real credential this engine refuses to substitute.
var r17AppCookies = []string{
	"sessionid", "_session_id", "connect.sid", "PHPSESSID", "JSESSIONID", "laravel_session",
	"ci_session", "ASP.NET_SessionId", "user_session", "_gitlab_session", "_discourse_session",
	"remember_token", "remember_user_token", "auth_token", "access_token", "refresh_token",
	"id_token", "jwt", "jwt_token", "session_token", "csrftoken", "XSRF-TOKEN",
	"__Secure-next-auth.session-token", "next-auth.session-token",
	"sb-abcdefgh-auth-token", "appSession", "_oauth2_proxy", "SSESS0123456789abcdef",
	"wordpress_logged_in_0123456789", "keycloak-session", "AWSELBAuthSessionCookie-0",
	"sid", "session", "authToken", "accessToken", "idToken", "refreshToken",
	"mycompany_sso_token", "acme_auth", "portal_sid", "app_sess", "tenant_session_key",
	"okta-token-storage", "amplify-signin-with-hostedUI", "ory_kratos_session",
}

// r17VendorCookies are 25 third-party names this tree hardcodes nowhere. The rate over them is the
// other direction: every one sent is somebody else's cookie riding a probe.
var r17VendorCookies = []string{
	"_pendo_meta", "pendo_sess_id", "_fs_uid", "fs_session", "_heap_session",
	"ld_session", "launchdarkly_session", "sentry_session", "_braze_session",
	"drift_session", "__zlcmid", "zendesk_session", "QSI_SI_session",
	"_uetsid_exp", "_sp_id", "_scor_uid", "kameleoonVisitorCode", "_ga_session",
	"wisepops_session", "_omappvp", "_clarity_session", "smartlook_session",
	"_lr_uf_session", "mouseflow_session", "userpilot_session",
}

// FAIL FIRST, measured on this tree before the two rules below existed:
//
//	--- FAIL: TestTwoSpellingsOfOneNameGetOneAnswer
//	    __stripe_sid=false and _stripe_sess_id=true: one name, two answers
//	    app_session=true and app_sess=false: one name, two answers
func TestTwoSpellingsOfOneNameGetOneAnswer(t *testing.T) {
	opaque := strings.Repeat("Q1w2", 8)
	// A window that has seen neither spelling, which is the state that makes the NAME rule the
	// deciding one and is the state eleven of the twelve live hosts are in.
	silent := anonWindowFor(t, 202, 3809, map[string]int{"fs_session": 186}, "PHPSESSID")
	if !silent.Discriminating() {
		t.Fatalf("the window is not discriminating, so the in-corpus half measures nothing")
	}

	for _, pair := range [][2]string{{"__stripe_sid", "_stripe_sess_id"}, {"app_session", "app_sess"}} {
		a, aw := triageWireCookieVerdict(pair[0], opaque)
		b, bw := triageWireCookieVerdict(pair[1], opaque)
		if a != b {
			t.Errorf("%s=%v and %s=%v: one name, two answers (%q / %q)", pair[0], a, pair[1], b, aw, bw)
		}
		ca, caw := triageWireCookieVerdictInCorpus(pair[0], opaque, silent)
		cb, cbw := triageWireCookieVerdictInCorpus(pair[1], opaque, silent)
		if ca != cb {
			t.Errorf("after the jars are read %s=%v and %s=%v: one name, two answers (%q / %q)",
				pair[0], ca, pair[1], cb, caw, cbw)
		}
	}

	// AND EACH PAIR IS CLOSED THE WAY IT WAS MEANT TO BE, which is a separate assertion from
	// closing it: a pair that agreed because both spellings were wrongly sent would satisfy the
	// checks above and nothing else.
	for _, n := range []string{"__stripe_sid", "_stripe_sess_id"} {
		send, why := triageWireCookieVerdict(n, opaque)
		if send || !strings.Contains(why, "Stripe") {
			t.Errorf("%s is not held by the vendor rule: send=%v why=%q", n, send, why)
		}
	}
	for _, n := range []string{"app_session", "app_sess"} {
		if send, why := triageWireCookieVerdict(n, opaque); !send {
			t.Errorf("%s is a real application credential and was held: %q", n, why)
		}
	}
}

// THE RATES OVER BOTH CORPORA, PINNED. They are the only measurement that says which direction a
// change to the name rules moved in, and until this round they lived in a verifier's scratch
// directory, where a round could move them and nothing in the tree would notice.
//
// MEASURED BEFORE THIS ROUND: 5 of the 45 held, 16 of the 25 sent. The five were
// mycompany_sso_token, acme_auth, portal_sid, app_sess and okta-token-storage, and the qualifier
// tier that held all five held NONE of the 25: the one vendor name held, _ga_session, is held by
// the named-vendor tier. On this corpus that tier was pure loss, and taking the two session
// spellings out of it takes the misses to 3 and moves the vendor rate by zero.
func TestTheNameOnlyRatesOverBothCorpora(t *testing.T) {
	opaque := strings.Repeat("Q1w2", 8)

	held := []string{}
	for _, n := range r17AppCookies {
		if send, why := triageWireCookieVerdict(n, opaque); !send && why != "" {
			held = append(held, n)
		}
	}
	if len(held) != 3 {
		t.Errorf("the KEEP direction holds %d of %d real credentials, was 3: %s",
			len(held), len(r17AppCookies), strings.Join(held, ", "))
	}

	sent := []string{}
	for _, n := range r17VendorCookies {
		if send, _ := triageWireCookieVerdict(n, opaque); send {
			sent = append(sent, n)
		}
	}
	if len(sent) != 16 {
		t.Errorf("the HOLD direction sends %d of %d vendor cookies, was 16: %s",
			len(sent), len(r17VendorCookies), strings.Join(sent, ", "))
	}
	t.Logf("R17 name-only: KEEP %d/%d held (%s); HOLD %d/%d sent",
		len(held), len(r17AppCookies), strings.Join(held, " "), len(sent), len(r17VendorCookies))
}

// AND THE CORPUS STILL CLOSES BOTH DIRECTIONS WHERE IT CAN SPEAK. The name rules are the fallback
// and not the answer, so a change to them must not have cost the layer that actually works.
func TestTheCorpusStillClosesBothDirections(t *testing.T) {
	opaque := strings.Repeat("Q1w2", 8)
	inAnon := map[string]int{}
	for _, n := range r17VendorCookies {
		inAnon[n] = 190
	}
	w := anonWindowFor(t, 202, 3809, inAnon, r17AppCookies...)

	for _, n := range r17VendorCookies {
		if send, _ := triageWireCookieVerdictInCorpus(n, opaque, w); send {
			t.Errorf("%s rode a probe although the application hands it to an anonymous visitor", n)
		}
	}
	for _, n := range r17AppCookies {
		nameSend, _ := triageWireCookieVerdict(n, opaque)
		corpusSend, why := triageWireCookieVerdictInCorpus(n, opaque, w)
		if nameSend && !corpusSend {
			t.Errorf("the corpus took away a real credential the name rules kept: %s (%s)", n, why)
		}
	}
}

// THE ADDENDUM EMPTIES ITSELF. triageWireVendorAddendum is this file's stand-in for entries that
// belong in triageThirdPartyCookieFamilies, which lives in a file this round may not edit. The
// moment one is merged upstream this fails, and the fix is to delete the local entry rather than
// to keep two lists of vendors that can disagree.
func TestTheVendorAddendumIsNotAlreadyInTheSharedList(t *testing.T) {
	for _, f := range triageWireVendorAddendum {
		if v := triageThirdPartyCookie(f.Prefix + "probe"); v != "" {
			t.Errorf("%q is now in triageThirdPartyCookieFamilies as %q; delete it from "+
				"triageWireVendorAddendum so there is one vendor list again", f.Prefix, v)
		}
		if v := triageWireVendorFor(f.Prefix + "probe"); v != f.Vendor {
			t.Errorf("the wire rule reads %q for %q, the addendum says %q", v, f.Prefix, f.Vendor)
		}
	}
}

// =================================================================================================
// ROUND 17: A REJECTED CANDIDATE IS COUNTED AND KEPT
// =================================================================================================

// FAIL FIRST, measured before Dead existed:
//
//	--- FAIL: TestTheRejectedCandidatesAreOnePerCarrierNewestFirstAndCapped
//	    undefined: triageRankDeadCreds
//
// The source counted 21 rejected candidates on the engaged estate and carried none of them, so the
// card could not read a lifetime off the token the application itself issued. It carries them now,
// and the ranking is what keeps two hundred captures of one rotating cookie from becoming two
// hundred rows.
func TestTheRejectedCandidatesAreOnePerCarrierNewestFirstAndCapped(t *testing.T) {
	t0 := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	in := []triageFreshCred{}
	// Two hundred captures of one rotating cookie: one carrier, two hundred readings.
	for i := 0; i < 200; i++ {
		in = append(in, triageFreshCred{Cookie: "accessToken", value: "v",
			Fingerprint: fmt.Sprintf("%08x", i), Expires: t0.Add(-time.Duration(i) * time.Minute),
			ExpirySource: "the token's own exp claim"})
	}
	in = append(in, triageFreshCred{Header: "Authorization", value: "v", Fingerprint: "bbbb2222",
		Expires: t0.Add(-4 * time.Hour), ExpirySource: "the token's own exp claim"})
	// A candidate with no readable expiry is never rejected by triageFreshCredDead, so it can
	// never be in here; if one arrives it is dropped rather than carried as a lifetime.
	in = append(in, triageFreshCred{Cookie: "opaque", value: "v", Fingerprint: "cccc3333"})

	out := triageRankDeadCreds(in)
	if len(out) != 2 {
		t.Fatalf("the rejected set has %d row(s), want 2 (one per carrier, none unmeasured): %v", len(out), out)
	}
	if out[0].Cookie != "accessToken" || !out[0].Expires.Equal(t0) {
		t.Errorf("the newest reading of the rotating carrier did not win: %v", out[0])
	}
	if out[1].Header != "Authorization" {
		t.Errorf("the order is not latest expiry first: %v", out)
	}

	// THE CAP IS ON ROWS AND THE ORDER DECIDES WHICH SURVIVE, so a host with many dead carriers
	// keeps the ones read most recently.
	many := []triageFreshCred{}
	for i := 0; i < triageFreshCredDeadKeep+5; i++ {
		many = append(many, triageFreshCred{Cookie: fmt.Sprintf("c%02d", i), value: "v",
			Fingerprint: fmt.Sprintf("%08x", i), Expires: t0.Add(-time.Duration(i) * time.Minute)})
	}
	capped := triageRankDeadCreds(many)
	if len(capped) != triageFreshCredDeadKeep {
		t.Errorf("the cap let %d row(s) through, want %d", len(capped), triageFreshCredDeadKeep)
	}
	if capped[0].Cookie != "c00" {
		t.Errorf("the cap cut the newest rather than the oldest: %v", capped[0])
	}

	// AND IT IS STABLE. Two runs over the same rows produce the same slice, or a cap cuts a
	// different row each time and the card's answer moves for no reason.
	again := triageRankDeadCreds(many)
	for i := range capped {
		if capped[i].Cookie != again[i].Cookie {
			t.Fatalf("the ranking is not stable at %d: %q then %q", i, capped[i].Cookie, again[i].Cookie)
		}
	}
	if triageRankDeadCreds(nil) != nil {
		t.Error("an empty read produced a non-nil rejected set")
	}
}
