package utils

import (
	"os"
	"strings"
	"testing"
)

// The engagement config decides what identifies this framework's traffic to a bug bounty programme
// and how fast it is allowed to arrive. Getting it wrong in either direction has a real cost: a
// missing X-HackerOne-... header gets research traffic read by a SOC as an attack, and an ignored
// rate cap gets an account removed from the programme.
//
// So the resolution order, the provenance and the refusals are all tested against structs rather
// than against a live database, for the same reason the active detector's rails are.

func strp(s string) *string   { return &s }
func intp(i int) *int         { return &i }
func f64p(f float64) *float64 { return &f }
func boolp(b bool) *bool      { return &b }

func engSource(t *testing.T, c ResolvedEngagementConfig, field, want string) {
	t.Helper()
	if got := c.Source[field]; got != want {
		t.Errorf("%s should be reported as coming from %q, got %q", field, want, got)
	}
}

// ---------------------------------------------------------------------------
// Resolution order and provenance
// ---------------------------------------------------------------------------

// Nothing set anywhere: the built-in defaults, every field reported as 'default'.
func TestEngagementConfigResolvesToDefaultsWhenNothingIsSet(t *testing.T) {
	c := ResolveEngagementFrom(nil, EngagementGlobals{})

	if c.CustomHeaderName != "" || c.CustomHeaderValue != "" {
		t.Errorf("no header should be sent, got %q: %q", c.CustomHeaderName, c.CustomHeaderValue)
	}
	if c.EffectiveUserAgent != engagementDefaultUserAgent {
		t.Errorf("the framework's own User-Agent should be used, got %q", c.EffectiveUserAgent)
	}
	if c.UserAgentMode != "replace" {
		t.Errorf("the default mode is replace, got %q", c.UserAgentMode)
	}
	if c.MaxRPS != flowDetectDefaultRPS || c.MaxRequestsPerRun != flowDetectDefaultMaxRequests ||
		c.RequestTimeoutS != flowDetectDefaultTimeoutS || c.MaxRedirects != flowDetectDefaultMaxRedirects {
		t.Errorf("the traffic bounds must mirror the detector's own defaults, got %+v", c)
	}
	if !c.FollowRedirects {
		t.Error("redirects are the point of the detector, so the default is to follow them")
	}
	if c.SendCookies {
		t.Fatal("send_cookies must default to false")
	}
	for _, f := range []string{"custom_header_name", "custom_user_agent", "user_agent_mode",
		"max_rps", "max_requests_per_run", "request_timeout_s", "max_redirects",
		"follow_redirects", "send_cookies", "programme_notes"} {
		engSource(t, c, f, EngagementFromDefault)
	}
}

// THE FALLBACK. With nothing set on the target, the global user_settings values are used AND the
// provenance says 'global' - which is what tells an operator that the header they are looking at on
// the Assurant target is the one they set for DailyPay.
func TestEngagementConfigFallsBackToTheGlobalAndSaysSo(t *testing.T) {
	glob := EngagementGlobals{
		CustomHeader:    "X-HackerOne-DailyPay-Research: rs0n2",
		CustomUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
	}
	c := ResolveEngagementFrom(nil, glob)

	if c.CustomHeaderName != "X-HackerOne-DailyPay-Research" || c.CustomHeaderValue != "rs0n2" {
		t.Fatalf("the global header must be used, got %q: %q", c.CustomHeaderName, c.CustomHeaderValue)
	}
	engSource(t, c, "custom_header_name", EngagementFromGlobal)
	engSource(t, c, "custom_header_value", EngagementFromGlobal)

	if c.EffectiveUserAgent != glob.CustomUserAgent {
		t.Errorf("the global User-Agent must be used, got %q", c.EffectiveUserAgent)
	}
	engSource(t, c, "custom_user_agent", EngagementFromGlobal)

	// The traffic bounds have no global tier: user_settings' rate limits are per TOOL and mean
	// queries per second inside one binary's flags, not "this programme allows N requests per
	// second". Reading one as the other would invent a permission nobody granted.
	engSource(t, c, "max_rps", EngagementFromDefault)
}

// THE DEFECT THIS WHOLE PASS FIXES. The per-target value beats the global, so the Assurant target
// stops sending DailyPay's header.
func TestEngagementConfigPerTargetBeatsTheGlobal(t *testing.T) {
	glob := EngagementGlobals{
		CustomHeader:    "X-HackerOne-DailyPay-Research: rs0n2",
		CustomUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
	}
	over := &EngagementOverrides{
		CustomHeaderName:  strp("X-Assurant-Research"),
		CustomHeaderValue: strp("rs0n2"),
	}
	c := ResolveEngagementFrom(over, glob)

	if c.CustomHeaderName != "X-Assurant-Research" || c.CustomHeaderValue != "rs0n2" {
		t.Fatalf("the target's own header must win, got %q: %q", c.CustomHeaderName, c.CustomHeaderValue)
	}
	engSource(t, c, "custom_header_name", EngagementFromTarget)
	engSource(t, c, "custom_header_value", EngagementFromTarget)

	// The User-Agent was NOT overridden, so it still inherits, and the screen must be able to say so.
	if c.EffectiveUserAgent != glob.CustomUserAgent {
		t.Errorf("an un-overridden field must still inherit, got %q", c.EffectiveUserAgent)
	}
	engSource(t, c, "custom_user_agent", EngagementFromGlobal)
}

// The header name and value resolve as a PAIR. Taking the name from the target and the value from the
// global would produce a header neither of them asked for.
func TestEngagementConfigHeaderNameAndValueResolveTogether(t *testing.T) {
	glob := EngagementGlobals{CustomHeader: "X-Global: global-value"}
	over := &EngagementOverrides{CustomHeaderName: strp("X-Target")}

	c := ResolveEngagementFrom(over, glob)
	if c.CustomHeaderName != "X-Target" {
		t.Fatalf("got %q", c.CustomHeaderName)
	}
	if c.CustomHeaderValue == "global-value" {
		t.Fatal("the value must not be spliced in from the global; that is a header nobody configured")
	}
	engSource(t, c, "custom_header_value", EngagementFromTarget)
}

// ---------------------------------------------------------------------------
// The two User-Agent shapes
// ---------------------------------------------------------------------------

// ASSURANT'S SHAPE: a research tag APPENDED to an ordinary browser User-Agent. Expressing this is the
// reason user_agent_mode exists; with replace-only, the operator has to paste a whole browser UA plus
// the tag into a box and keep it in step with whatever the global says.
func TestEngagementConfigAppendsTheTagToTheInheritedUserAgent(t *testing.T) {
	glob := EngagementGlobals{
		CustomUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
	}
	over := &EngagementOverrides{
		UserAgentMode:   strp("append"),
		CustomUserAgent: strp("<H1-rs0n2>"),
	}
	c := ResolveEngagementFrom(over, glob)

	want := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 <H1-rs0n2>"
	if c.EffectiveUserAgent != want {
		t.Fatalf("append must glue the tag onto the inherited User-Agent\n got %q\nwant %q",
			c.EffectiveUserAgent, want)
	}
	// The raw field and the wire value are BOTH reported. custom_user_agent means two different
	// things depending on the mode, and showing only the raw one is how an operator discovers the
	// difference against a live programme.
	if c.CustomUserAgent != "<H1-rs0n2>" {
		t.Errorf("the stored tag must still be visible, got %q", c.CustomUserAgent)
	}
	engSource(t, c, "user_agent_mode", EngagementFromTarget)
	engSource(t, c, "custom_user_agent", EngagementFromTarget)
}

// Append with no global to append to still produces something sendable rather than a bare tag, which
// would be a User-Agent no browser or crawler has ever sent and the first thing a WAF blocks.
func TestEngagementConfigAppendFallsBackToTheFrameworkUserAgent(t *testing.T) {
	over := &EngagementOverrides{UserAgentMode: strp("append"), CustomUserAgent: strp("<H1-rs0n2>")}
	c := ResolveEngagementFrom(over, EngagementGlobals{})

	if c.EffectiveUserAgent != engagementDefaultUserAgent+" <H1-rs0n2>" {
		t.Fatalf("got %q", c.EffectiveUserAgent)
	}
}

// Mode says append and there is nothing to append. Not an error, but it must not silently become
// something else, and the provenance must say the value is inherited rather than set here.
func TestEngagementConfigAppendWithNoTagLeavesTheBaseAlone(t *testing.T) {
	glob := EngagementGlobals{CustomUserAgent: "Mozilla/5.0"}
	c := ResolveEngagementFrom(&EngagementOverrides{UserAgentMode: strp("append")}, glob)

	if c.EffectiveUserAgent != "Mozilla/5.0" {
		t.Fatalf("got %q", c.EffectiveUserAgent)
	}
	engSource(t, c, "custom_user_agent", EngagementFromGlobal)
}

// DAILYPAY'S SHAPE: a header, and a User-Agent set outright for this target.
func TestEngagementConfigReplaceUsesTheTargetUserAgentWhole(t *testing.T) {
	glob := EngagementGlobals{CustomUserAgent: "Mozilla/5.0 Chrome/120"}
	over := &EngagementOverrides{
		UserAgentMode:     strp("replace"),
		CustomUserAgent:   strp("dailypay-research/1.0 (rs0n2)"),
		CustomHeaderName:  strp("X-HackerOne-DailyPay-Research"),
		CustomHeaderValue: strp("rs0n2"),
	}
	c := ResolveEngagementFrom(over, glob)

	if c.EffectiveUserAgent != "dailypay-research/1.0 (rs0n2)" {
		t.Fatalf("replace must not carry the global through, got %q", c.EffectiveUserAgent)
	}
	if h := c.HeaderMap(); len(h) != 1 || h["X-HackerOne-DailyPay-Research"] != "rs0n2" {
		t.Fatalf("the programme's header must reach the sender, got %v", h)
	}
}

// The framework's fallback User-Agent is duplicated from NewScanClient, so something has to notice if
// the two ever drift. A constant that silently stops matching the transport's own default would make
// every "inherited" User-Agent on screen a different string from the one on the wire.
func TestEngagementConfigDefaultUserAgentMatchesScanClient(t *testing.T) {
	raw, err := os.ReadFile("scanHTTP.go")
	if err != nil {
		t.Fatalf("could not read the transport: %v", err)
	}
	if !strings.Contains(string(raw), engagementDefaultUserAgent) {
		t.Errorf("engagementDefaultUserAgent (%q) no longer matches NewScanClient's fallback. "+
			"The config screen would report an inherited User-Agent that is not what gets sent",
			engagementDefaultUserAgent)
	}
}

// ---------------------------------------------------------------------------
// Parsing the global header field
// ---------------------------------------------------------------------------

func TestEngagementConfigSplitsTheGlobalHeaderField(t *testing.T) {
	// Split on the FIRST colon. A value may contain colons; a name may not.
	name, value, ok := SplitEngagementHeader("X-Trace: https://example.com/x:1")
	if !ok || name != "X-Trace" || value != "https://example.com/x:1" {
		t.Errorf("got %q / %q / %v", name, value, ok)
	}

	if _, _, ok := SplitEngagementHeader("X-HackerOne-DailyPay-Research:rs0n2"); !ok {
		t.Error("no space after the colon is still a header")
	}

	for _, bad := range []string{
		"", "   ",
		"no-colon-at-all",
		": no name",
		"X-Empty:",
		// A refused name must not survive being written into the global field either. The global is
		// a single text box, so it is the easy way to smuggle one past the per-target validation.
		"Cookie: session=abc",
		"Authorization: Bearer abc",
		"User-Agent: Mozilla/5.0",
		"X-Bad\r\nInjected: x",
		"X-Bad: value\r\nInjected: x",
	} {
		if _, _, ok := SplitEngagementHeader(bad); ok {
			t.Errorf("%q must not parse into a sendable header", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

// THE ACKNOWLEDGEMENT. A scanner carrying the operator's session acts AS the authenticated user, so
// turning cookies on is refused unless the request names the risk in the same breath.
func TestEngagementConfigSendCookiesRefusedWithoutTheAcknowledgement(t *testing.T) {
	req := EngagementUpdateRequest{
		EngagementOverrides: EngagementOverrides{SendCookies: boolp(true)},
	}
	if _, err := ValidateEngagementUpdate(req); err == nil {
		t.Fatal("send_cookies:true without acknowledge_state_risk must be refused")
	} else if !strings.Contains(err.Error(), "acknowledge_state_risk") {
		t.Errorf("the refusal must name the flag the operator has to send, got %q", err)
	}

	req.AcknowledgeStateRisk = true
	if _, err := ValidateEngagementUpdate(req); err != nil {
		t.Fatalf("with the acknowledgement it must be accepted: %v", err)
	}

	// Turning it OFF needs no acknowledgement. Making the safe direction require a ceremony is how
	// operators learn to tick every box without reading it.
	off := EngagementUpdateRequest{
		EngagementOverrides: EngagementOverrides{SendCookies: boolp(false)},
	}
	if _, err := ValidateEngagementUpdate(off); err != nil {
		t.Errorf("disabling cookies must never be refused: %v", err)
	}

	// And an omitted field is not a request to change it, so it needs no acknowledgement either.
	if _, err := ValidateEngagementUpdate(EngagementUpdateRequest{}); err != nil {
		t.Errorf("an empty update must not trip the acknowledgement: %v", err)
	}
}

// Cookie and Authorization would smuggle a credential past the no-credentials rail of every
// unauthenticated sender, because ScanRequest.Headers is applied last. User-Agent has its own field.
func TestEngagementConfigRefusesCredentialAndDuplicateHeaderNames(t *testing.T) {
	for _, name := range []string{"Cookie", "cookie", "AUTHORIZATION", "Authorization",
		"User-Agent", "user-agent", "Host", "Content-Length"} {
		req := EngagementUpdateRequest{EngagementOverrides: EngagementOverrides{
			CustomHeaderName:  strp(name),
			CustomHeaderValue: strp("x"),
		}}
		if _, err := ValidateEngagementUpdate(req); err == nil {
			t.Errorf("%s must not be settable as a custom header", name)
		}
	}
}

func TestEngagementConfigRefusesHeaderInjectionAndBadNames(t *testing.T) {
	bad := []struct{ name, value, why string }{
		{"X-Bad\r\nInjected", "x", "a CRLF in the name splits the request"},
		{"X-Bad", "value\r\nInjected: 1", "a CRLF in the value splits the request"},
		{"X-Bad", "value\x00null", "a control character in the value"},
		{"X Bad", "x", "a space is not a token character"},
		{"X:Bad", "x", "a colon is not a token character"},
		{"", "x", "an empty name"},
	}
	for _, c := range bad {
		req := EngagementUpdateRequest{EngagementOverrides: EngagementOverrides{
			CustomHeaderName: strp(c.name), CustomHeaderValue: strp(c.value),
		}}
		if _, err := ValidateEngagementUpdate(req); err == nil {
			t.Errorf("%s must be refused (%s)", c.why, c.name)
		}
	}

	// The legal shape must still pass. A validator that refuses X-HackerOne-DailyPay-Research is
	// worse than none, because it sends the operator back to hardcoding.
	ok := EngagementUpdateRequest{EngagementOverrides: EngagementOverrides{
		CustomHeaderName: strp("X-HackerOne-DailyPay-Research"), CustomHeaderValue: strp("rs0n2"),
	}}
	if _, err := ValidateEngagementUpdate(ok); err != nil {
		t.Errorf("a normal programme header must be accepted: %v", err)
	}
}

// A header name with no value would be sent empty: it looks configured on the screen and identifies
// nobody on the wire, which is the worst of both.
func TestEngagementConfigRefusesAHeaderNameWithNoValue(t *testing.T) {
	req := EngagementUpdateRequest{EngagementOverrides: EngagementOverrides{
		CustomHeaderName: strp("X-HackerOne-Research"),
	}}
	if _, err := ValidateEngagementUpdate(req); err == nil {
		t.Fatal("a header name with no value must be refused")
	}
}

// A refused header that somehow reached the database must still not reach the wire. The write-time
// check is not the last line of defence, because a row can be written by a migration or by hand.
func TestEngagementConfigHeaderMapRevetsWhatIsStored(t *testing.T) {
	for _, c := range []ResolvedEngagementConfig{
		{CustomHeaderName: "Cookie", CustomHeaderValue: "session=abc"},
		{CustomHeaderName: "Authorization", CustomHeaderValue: "Bearer abc"},
		{CustomHeaderName: "X-Bad", CustomHeaderValue: "a\r\nInjected: 1"},
		{CustomHeaderName: "X-Bad Name", CustomHeaderValue: "x"},
		{CustomHeaderName: "X-Set", CustomHeaderValue: ""},
		{CustomHeaderName: "", CustomHeaderValue: "orphan"},
	} {
		if h := c.HeaderMap(); len(h) != 0 {
			t.Errorf("%q: %q must never be sent, got %v", c.CustomHeaderName, c.CustomHeaderValue, h)
		}
	}
}

func TestEngagementConfigValidatesTheTrafficBounds(t *testing.T) {
	bad := []EngagementOverrides{
		{MaxRPS: f64p(0)},
		{MaxRPS: f64p(-1)},
		{MaxRPS: f64p(engagementMaxRPSCeiling + 1)},
		{MaxRequestsPerRun: intp(0)},
		{MaxRequestsPerRun: intp(engagementMaxRequestsCeiling + 1)},
		{RequestTimeoutS: intp(0)},
		{RequestTimeoutS: intp(engagementMaxTimeoutS + 1)},
		{MaxRedirects: intp(-1)},
		{MaxRedirects: intp(engagementMaxRedirectsCap + 1)},
		{UserAgentMode: strp("prepend")},
	}
	for _, o := range bad {
		if _, err := ValidateEngagementUpdate(EngagementUpdateRequest{EngagementOverrides: o}); err == nil {
			t.Errorf("%+v must be refused", o)
		}
	}

	// Assurant's real cap: 45 requests per minute is 0.75 rps, which is below the framework default
	// and must be accepted rather than rounded up to something the brief forbids.
	good := EngagementOverrides{MaxRPS: f64p(0.75), MaxRedirects: intp(0)}
	if _, err := ValidateEngagementUpdate(EngagementUpdateRequest{EngagementOverrides: good}); err != nil {
		t.Errorf("a sub-1-rps programme cap must be accepted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Folding it into a run
// ---------------------------------------------------------------------------

// The engagement config is BOTH the default (when the run did not ask) and the ceiling (when it did).
// Default-only would let any client that sends an rps ignore the programme's cap, which every client
// does; ceiling-only would make a per-target setting invisible, because ValidateFlowDetectionConfig
// fills the zero fields before anyone consults it.
func TestEngagementConfigIsBothDefaultAndCeiling(t *testing.T) {
	eng := ResolveEngagementFrom(&EngagementOverrides{
		MaxRPS:            f64p(0.75), // Assurant: 45 requests per minute
		MaxRequestsPerRun: intp(100),
		RequestTimeoutS:   intp(10),
		MaxRedirects:      intp(2),
	}, EngagementGlobals{})

	// The run asked for nothing: the engagement values ARE the values.
	unset := ApplyEngagementToDetection(FlowDetectionConfig{}, eng)
	if unset.RPS != 0.75 || unset.MaxRequests != 100 || unset.TimeoutS != 10 || unset.MaxRedirects != 2 {
		t.Fatalf("an unset run must adopt the programme's values, got %+v", unset)
	}

	// The run asked for more than the programme allows: the programme wins.
	greedy := ApplyEngagementToDetection(FlowDetectionConfig{
		RPS: 10, MaxRequests: 5000, TimeoutS: 60, MaxRedirects: 10,
	}, eng)
	if greedy.RPS != 0.75 {
		t.Errorf("the programme's rate cap must not be exceeded, got %v", greedy.RPS)
	}
	if greedy.MaxRequests != 100 {
		t.Errorf("the programme's request budget must not be exceeded, got %d", greedy.MaxRequests)
	}
	if greedy.TimeoutS != 10 {
		t.Errorf("the programme's timeout must not be exceeded, got %d", greedy.TimeoutS)
	}
	if greedy.MaxRedirects != 2 {
		t.Errorf("the programme's redirect budget must not be exceeded, got %d", greedy.MaxRedirects)
	}

	// The run asked for LESS than the programme allows: the operator's stricter choice stands.
	timid := ApplyEngagementToDetection(FlowDetectionConfig{
		RPS: 0.2, MaxRequests: 10, TimeoutS: 5, MaxRedirects: 1,
	}, eng)
	if timid.RPS != 0.2 || timid.MaxRequests != 10 || timid.TimeoutS != 5 || timid.MaxRedirects != 1 {
		t.Errorf("a stricter run must not be loosened up to the cap, got %+v", timid)
	}
}

// follow_redirects is ANDed, not overwritten. A programme rule of "do not follow redirects" must not
// be overturned by a client that asks for true.
func TestEngagementConfigFollowRedirectsIsAnded(t *testing.T) {
	eng := ResolveEngagementFrom(&EngagementOverrides{FollowRedirects: boolp(false)}, EngagementGlobals{})
	yes := true
	out := ApplyEngagementToDetection(FlowDetectionConfig{FollowRedirects: &yes, MaxRedirects: 5}, eng)

	if out.FollowRedirects == nil || *out.FollowRedirects {
		t.Fatal("a target that forbids following redirects must win over a run that asks to")
	}
	if out.MaxRedirects != 0 {
		t.Errorf("a redirect budget with following disabled is a control that does nothing, got %d",
			out.MaxRedirects)
	}
}

// THE RAILS ARE NOT WIDENABLE. Whatever an engagement config says, the run still has to survive
// ValidateFlowDetectionConfig, which is where GET-only and the framework's hard ceilings live.
func TestEngagementConfigCannotWidenTheDetectionRails(t *testing.T) {
	// A generous engagement config: high rate, huge budget, long timeout, many redirects.
	eng := ResolveEngagementFrom(&EngagementOverrides{
		MaxRPS:            f64p(engagementMaxRPSCeiling),
		MaxRequestsPerRun: intp(engagementMaxRequestsCeiling),
		RequestTimeoutS:   intp(engagementMaxTimeoutS),
		MaxRedirects:      intp(engagementMaxRedirectsCap),
	}, EngagementGlobals{})

	// The verb is the operator's choice and the engagement config has no say in it either way: it
	// cannot forbid a POST and it cannot invent one.
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		if _, err := ValidateFlowDetectionConfig(ApplyEngagementToDetection(
			FlowDetectionConfig{Methods: []string{m}}, eng)); err != nil {
			t.Errorf("%s is the operator's choice to make, got %v", m, err)
		}
	}

	// And the framework's own hard ceilings still bite afterwards.
	cfg, err := ValidateFlowDetectionConfig(ApplyEngagementToDetection(FlowDetectionConfig{}, eng))
	if err != nil {
		t.Fatalf("a GET run should validate: %v", err)
	}
	if cfg.RPS > flowDetectMaxRPS {
		t.Errorf("the framework rps ceiling must still apply, got %v", cfg.RPS)
	}
	if cfg.MaxRequests > flowDetectHardMaxRequests {
		t.Errorf("the framework request ceiling must still apply, got %d", cfg.MaxRequests)
	}
	if cfg.TimeoutS > flowDetectMaxTimeoutS {
		t.Errorf("the framework timeout ceiling must still apply, got %d", cfg.TimeoutS)
	}
	if cfg.MaxRedirects > flowDetectHardMaxRedirects {
		t.Errorf("the framework redirect ceiling must still apply, got %d", cfg.MaxRedirects)
	}
}

// A target with no engagement row at all must behave exactly as the detector did before this feature
// existed. Anything else is a silent change to every unconfigured target in the database.
func TestEngagementConfigLeavesAnUnconfiguredTargetAlone(t *testing.T) {
	eng := ResolveEngagementFrom(nil, EngagementGlobals{})
	before := flowDetectCfg(t, FlowDetectionConfig{})
	after, err := ValidateFlowDetectionConfig(ApplyEngagementToDetection(FlowDetectionConfig{}, eng))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if after.RPS != before.RPS || after.MaxRequests != before.MaxRequests ||
		after.TimeoutS != before.TimeoutS || after.MaxRedirects != before.MaxRedirects ||
		*after.FollowRedirects != *before.FollowRedirects {
		t.Errorf("an unconfigured target must be unchanged\nbefore %+v\n after %+v", before, after)
	}
}

// AN UNCONFIGURED TARGET MUST NOT CAP A RUN THAT ASKED FOR MORE.
//
// This is the regression test for a bug that shipped: ApplyEngagementToDetection clamped against the
// RESOLVED value, and the resolved value of an unconfigured target is the framework default. So on
// every target nobody had configured - which is all of them - a run asking for 8 rps got 1, a run
// asking for 900 requests got 250, and the Detect Flows rate control was dead above the number it
// opened on, with flowDetectMaxRPS sitting unreachable at 10.
//
// TestEngagementConfigLeavesAnUnconfiguredTargetAlone did not catch it because it only ever passed an
// EMPTY FlowDetectionConfig, where the default-filling branch and the clamping branch produce the
// same answer. The bug lived entirely in the branch a non-empty run takes, so the run here asks for
// something.
func TestEngagementConfigDefaultIsNotACeiling(t *testing.T) {
	// Nothing set anywhere: no target row, no globals. Every traffic field resolves to 'default'.
	eng := ResolveEngagementFrom(nil, EngagementGlobals{})
	for _, field := range []string{"max_rps", "max_requests_per_run", "request_timeout_s", "max_redirects"} {
		if eng.Source[field] != EngagementFromDefault {
			t.Fatalf("precondition: %s should resolve to 'default', got %q", field, eng.Source[field])
		}
	}

	asked := FlowDetectionConfig{RPS: 8, MaxRequests: 900, TimeoutS: 30, MaxRedirects: 9}
	got := ApplyEngagementToDetection(asked, eng)

	if got.RPS != 8 {
		t.Errorf("a framework default is not a programme cap: asked for 8 rps, got %v", got.RPS)
	}
	if got.MaxRequests != 900 {
		t.Errorf("asked for 900 requests, got %d", got.MaxRequests)
	}
	if got.TimeoutS != 30 {
		t.Errorf("asked for a 30s timeout, got %d", got.TimeoutS)
	}
	if got.MaxRedirects != 9 {
		t.Errorf("asked for 9 redirects, got %d", got.MaxRedirects)
	}

	// And what the run actually gets is bounded by the FRAMEWORK's ceilings, which still apply.
	cfg, err := ValidateFlowDetectionConfig(got)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if cfg.RPS != 8 {
		t.Errorf("8 rps is under flowDetectMaxRPS (%v) and must survive validation, got %v",
			flowDetectMaxRPS, cfg.RPS)
	}
}

// The same distinction for the middle tier: a value inherited from user_settings is not a programme
// rule for THIS target either. Only the target's own row may lower a run.
func TestEngagementConfigOnlyATargetOverrideLowersARun(t *testing.T) {
	asked := FlowDetectionConfig{RPS: 8, MaxRequests: 900}

	// Globals carry a header and a UA and nothing else; the traffic fields still resolve to default.
	inherited := ResolveEngagementFrom(nil, EngagementGlobals{
		CustomHeader:    "X-Programme: rs0n2",
		CustomUserAgent: "Mozilla/5.0",
	})
	if out := ApplyEngagementToDetection(asked, inherited); out.RPS != 8 || out.MaxRequests != 900 {
		t.Errorf("an inherited config with no traffic rule must not cap the run, got %+v", out)
	}

	// The moment the TARGET states a cap, it binds.
	capped := ResolveEngagementFrom(&EngagementOverrides{
		MaxRPS: f64p(0.75), MaxRequestsPerRun: intp(100),
	}, EngagementGlobals{})
	out := ApplyEngagementToDetection(asked, capped)
	if out.RPS != 0.75 {
		t.Errorf("a per-target rate cap must bind, got %v", out.RPS)
	}
	if out.MaxRequests != 100 {
		t.Errorf("a per-target request budget must bind, got %d", out.MaxRequests)
	}
	if !capped.IsFromTarget("max_rps") || capped.IsFromTarget("custom_user_agent") {
		t.Error("IsFromTarget must distinguish a target override from an inherited value")
	}
}

// send_cookies is NOT NULL in the schema, so every saved row has a value and the nil test that gives
// every other field its provenance cannot work. Provenance therefore reads the value: only `true`
// can have been chosen. Without this, a target saved for any reason at all - a rate cap, a note -
// would report "cookies: set for this target" over a box nobody had touched.
func TestEngagementConfigSendCookiesProvenanceFollowsTheValue(t *testing.T) {
	off := ResolveEngagementFrom(&EngagementOverrides{SendCookies: boolp(false)}, EngagementGlobals{})
	if off.SendCookies {
		t.Error("false must resolve to off")
	}
	if off.Source["send_cookies"] != EngagementFromDefault {
		t.Errorf("an untouched send_cookies must not claim somebody set it here, got %q",
			off.Source["send_cookies"])
	}

	on := ResolveEngagementFrom(&EngagementOverrides{SendCookies: boolp(true)}, EngagementGlobals{})
	if !on.SendCookies || on.Source["send_cookies"] != EngagementFromTarget {
		t.Errorf("an enabled send_cookies is a deliberate per-target choice, got %v/%q",
			on.SendCookies, on.Source["send_cookies"])
	}
}

// ---------------------------------------------------------------------------
// Asserted against the source
// ---------------------------------------------------------------------------

// send_cookies exists in the schema and active detection must go on ignoring it. The rail is the
// nil cookie jar, and a per-target flag must not be able to re-enable something the transport does
// not have. Asserted against the source because the only other way to see it is to point the scanner
// at a live target while logged in.
func TestFlowDetectionNeverConsultsSendCookies(t *testing.T) {
	raw, err := os.ReadFile("flowDetectionActive.go")
	if err != nil {
		t.Fatalf("could not read the runner: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	body := code.String()

	if strings.Contains(body, "SendCookies") || strings.Contains(body, "send_cookies") {
		t.Error("active flow detection must never read send_cookies: its rail is the nil cookie jar, " +
			"and an engagement config cannot re-enable a rail the transport does not have")
	}
	// It must still apply the parts it is supposed to.
	if !strings.Contains(body, "engagement.EffectiveUserAgent") {
		t.Error("the run must send the programme's User-Agent")
	}
	if !strings.Contains(body, "engagement.HeaderMap()") {
		t.Error("the run must send the programme's header")
	}
	if !strings.Contains(body, "ResolveEngagementConfig(scopeTargetID)") {
		t.Error("the run must resolve the engagement config rather than assuming defaults")
	}
}

// The plan must fold the engagement config in BEFORE ValidateFlowDetectionConfig fills the zero
// fields with framework defaults, or a per-target rate cap can never take effect.
func TestFlowDetectionResolvesEngagementConfigBeforeValidating(t *testing.T) {
	raw, err := os.ReadFile("flowDetectionActive.go")
	if err != nil {
		t.Fatalf("could not read the planner: %v", err)
	}
	src := string(raw)
	start := strings.Index(src, "func PlanFlowDetection(")
	if start < 0 {
		t.Fatal("PlanFlowDetection not found")
	}
	body := src[start:]
	applyAt := strings.Index(body, "ApplyEngagementToDetection(")
	validateAt := strings.Index(body, "ValidateFlowDetectionConfig(cfg)")
	if applyAt < 0 || validateAt < 0 {
		t.Fatal("the plan must both apply the engagement config and validate the result")
	}
	if applyAt > validateAt {
		t.Error("the engagement config must be folded in before validation, or Validate's defaults " +
			"make an unset field indistinguishable from a requested one and the per-target cap " +
			"silently never applies")
	}
	if !strings.Contains(body, "engagement config could not be read, so no run may start") {
		t.Error("a failed read of the engagement config must refuse the run: sending a programme's " +
			"traffic without the header their brief requires is worse than not sending it")
	}
}
