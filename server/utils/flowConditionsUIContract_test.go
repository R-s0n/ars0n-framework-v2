package utils

import "testing"

// Every `when` string the RequestFlowBuilderModal's conditionsToWire can now emit, checked against
// the parser that will receive it.
func TestUIEmittedWhenStringsParse(t *testing.T) {
	steps := []FlowGraphStep{{ID: "a", Name: "Login", Enabled: true}}
	cases := []string{
		"status == 200",
		"status != 404",
		"status >= 400",
		"status <= 299",
		"status > 199",
		"status < 500",
		"time_ms > 2000",
		"size >= 0",
		"header.Location ~ /login",
		"header.Location !~ /login",
		"header.Set-Cookie =~ session=[a-f0-9]+",
		"header.Location =~ (?s).*",
		"header.X-Frame-Options == DENY",
		"body ~ error",
		"body !~ success",
		"body =~ (?i)invalid",
		"body == some value with spaces",
		`body == ""`,
		`body ~ "  padded  "`,
		"*",
	}
	for _, when := range cases {
		if problem := ValidateFlowConditions([]FlowCondition{{When: when, Then: "continue"}}, steps); problem != "" {
			t.Errorf("%q was refused: %s", when, problem)
		}
	}
}

// The "is present" spelling has to be TRUE for a header that is there, with any value including
// empty, and FALSE for one that is not.
func TestExistsPatternMeansPresent(t *testing.T) {
	conds := []FlowCondition{{When: "header.Location =~ (?s).*", Then: "stop"}}

	present := EvaluateFlowConditions(conds, FlowEvalContext{Response: FlowResponse{
		Ran: true, Status: 302, Headers: map[string][]string{"Location": {"/dashboard"}}}})
	if present.Action != "stop" {
		t.Errorf("a present header did not match: %+v", present)
	}

	empty := EvaluateFlowConditions(conds, FlowEvalContext{Response: FlowResponse{
		Ran: true, Status: 200, Headers: map[string][]string{"Location": {""}}}})
	if empty.Action != "stop" {
		t.Errorf("a present but empty header did not match: %+v", empty)
	}

	absent := EvaluateFlowConditions(conds, FlowEvalContext{Response: FlowResponse{
		Ran: true, Status: 200, Headers: map[string][]string{"Server": {"nginx"}}}})
	if absent.Action != "continue" || absent.Index != -1 {
		t.Errorf("an absent header matched: %+v", absent)
	}
}
