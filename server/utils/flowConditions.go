package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Conditional branching for BUILT request flows, and the loop protection that makes it safe.
//
// ---------------------------------------------------------------------------
// Why this is only for built flows
// ---------------------------------------------------------------------------
//
// A DETECTED flow (replayRequestFlows.go) is derived on every request from manual_crawl_captures by
// segmentCaptureFlows. It is a reading of history: there are no step rows, so there is nowhere to
// hang a condition and no id a goto could name that survives the next re-segmentation. A detected
// flow is therefore run LINEARLY, in captured order.
//
// A BUILT flow (requestFlowBuilder.go) has real, ordered, editable rows in request_flow_steps. Those
// rows are what a condition attaches to and what a goto names. So branching lives here, and the
// bridge between the two is the builder's existing "build from a detected flow" seed.
//
// ---------------------------------------------------------------------------
// The shape of a decision
// ---------------------------------------------------------------------------
//
// Each step carries an ORDERED list of conditions, evaluated against the response that step just
// produced. FIRST MATCH WINS. If none match, the flow continues to the next step in order, which is
// exactly what a flow with no conditions at all does - so adding branching cannot change what an
// existing flow does today.
//
//	{"when": "status == 302", "then": "goto", "target": "Follow redirect", "message": "..."}
//
// ---------------------------------------------------------------------------
// Loop protection is not optional and is not configurable off
// ---------------------------------------------------------------------------
//
// A condition that jumps backwards, or retries, can loop forever. A loop against a live bug bounty
// target is a denial of service, which is out of scope on every programme this framework is pointed
// at, and it gets the operator banned rather than paid. Four caps, none of which can be turned off,
// only lowered:
//
//	MAX EXECUTED STEPS      counts EXECUTIONS, not definitions. A 4-step flow that loops is 4
//	                        definitions and unbounded executions, so the budget counts the latter.
//	PER-STEP EXECUTION CAP  one step cannot be re-entered indefinitely inside a budget with room.
//	RETRY CAP               separate and small, with a delay between attempts.
//	WALL CLOCK              a run cannot outlive its operator's attention, however slowly it is paced.
//
// plus this target's engagement request budget, which is the programme's number and not ours, and
// the engagement rate limit, which paces EVERY request the runner sends, loop or not.
//
// Cycles are detected at AUTHORING time and warned about, not refused: a bounded retry loop is
// legitimate. The operator is told at the moment they create it rather than when it fires.
//
// A run that hits any cap STOPS and says which cap it hit, in those words. "Flow ended" with no
// reason is how an operator concludes the target is broken when it was their own flow.

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

// Actions a condition may take.
const (
	// FlowActionContinue: go to the next step in order. The same thing an unmatched step does, said
	// explicitly, which is worth having because it lets a condition stop the SEARCH: put
	// {"when": "status == 200", "then": "continue"} before a catch-all fail and the 200 case is
	// spelled out rather than implied.
	FlowActionContinue = "continue"
	// FlowActionGoto: jump to the named step. The only action that can move backwards, and therefore
	// the only one that can loop.
	FlowActionGoto = "goto"
	// FlowActionStop: end the run, reporting success.
	FlowActionStop = "stop"
	// FlowActionFail: end the run, reporting failure, with the message.
	FlowActionFail = "fail"
	// FlowActionRetry: re-send THIS step, subject to the retry cap and delay.
	FlowActionRetry = "retry"
)

// FlowCondition is one rule on one step.
type FlowCondition struct {
	// When is the expression, or the catch-all "*" / "else".
	When string `json:"when"`
	// Then is one of the FlowAction constants.
	Then string `json:"then"`
	// Target is the step a goto jumps to: a step id, or a step name.
	Target string `json:"target,omitempty"`
	// Message is what the operator will read in the trace, and for a fail it is the reason the run
	// ended. Optional everywhere, and worth writing everywhere.
	Message string `json:"message,omitempty"`
}

// flowConditionCatchAlls are the two spellings of "anything else".
//
// Allowed ONLY as the last condition, and rejected anywhere else. A catch-all in the middle makes
// every condition after it dead, and dead conditions are invisible: the operator sees them in the
// list, believes they can fire, and debugs the target when the flow never reaches them.
var flowConditionCatchAlls = map[string]bool{"*": true, "else": true}

// FlowResponse is what a step produced, as the evaluator sees it.
//
// Ran is not decoration. A step that was skipped, refused or never reached has no status, and a
// status of 0 must not read as "the server answered 0". Every field lookup on a response that did
// not run reports ABSENT, and absent never matches.
type FlowResponse struct {
	Ran     bool                `json:"ran"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    string              `json:"body,omitempty"`
	TimeMs  float64             `json:"time_ms"`
}

// FlowStepRef is an earlier step as seen from a condition.
//
// Response nil with Missing set is the case that matters: the step EXISTS in this flow but has no
// result, because it is disarmed, was refused, or has not been reached. That is a different error
// from naming a step that does not exist, and the operator needs to be told which one it was.
type FlowStepRef struct {
	Name     string
	Response *FlowResponse
	Missing  string
}

// FlowEvalContext is everything a decision may look at. No database, no HTTP: this is the whole
// input, so every branching decision is reproducible from a struct literal.
type FlowEvalContext struct {
	// Response is the response of the step that just ran.
	Response FlowResponse
	// Steps is every step of the flow, keyed BOTH by its id and by its lower-cased name, so
	// step.<name> and step.<id> resolve through the same map.
	Steps map[string]FlowStepRef
}

// FlowConditionMatch is the decision.
type FlowConditionMatch struct {
	// Index of the condition that matched, or -1 when none did.
	Index int `json:"index"`
	// Action is what to do: one of the FlowAction constants when a condition matched, and
	// FlowActionContinue when none did, because falling off the end of the list means "next step".
	Action  string `json:"action"`
	Target  string `json:"target,omitempty"`
	Message string `json:"message,omitempty"`
	When    string `json:"when,omitempty"`
	// Problems are conditions that could not be judged: a regex that will not compile, a numeric
	// comparison against text, a reference to a step that never ran. Reported rather than swallowed,
	// because a condition that silently never matches looks exactly like one whose case never
	// happened.
	Problems []string `json:"problems,omitempty"`
}

// ---------------------------------------------------------------------------
// The expression grammar
// ---------------------------------------------------------------------------
//
//	<field> <operator> <value>       status == 302
//	*  |  else                       the catch-all, last only
//
// FIELDS, against the response of the step that just ran:
//
//	status                the response status code
//	header.<name>         a response header, name matched case-insensitively
//	body                  the response body
//	size                  the response body length in bytes
//	time_ms               the elapsed time in milliseconds
//
// and the same five against an EARLIER step, because "did the login step succeed" is the obvious
// real use:
//
//	step.<name-or-id>.status        step.Login.status == 200
//	step.<name-or-id>.header.<name> step.Login.header.Location ~ /dashboard
//	step."GET /login".size > 0      quote the reference when the step's name has spaces
//
// OPERATORS:
//
//	>  <  >=  <=      numbers only; a non-numeric field or value is an error, not a false
//	==  !=            numeric when both sides are numbers, otherwise an exact string comparison
//	~   !~            case-insensitive substring
//	=~                RE2 regular expression
//
// A header with several values matches on ANY value for the positive operators and on ALL values for
// the negative ones (!= and !~), because "no value of this header contains x" is what a negation
// means when there are three of them.

type flowFieldRef struct {
	StepRef string // "" means the response of the step that just ran
	Kind    string // status | header | body | size | time_ms
	Header  string
}

func (f flowFieldRef) String() string {
	name := f.Kind
	if f.Kind == "header" {
		name = "header." + f.Header
	}
	if f.StepRef == "" {
		return name
	}
	return "step." + f.StepRef + "." + name
}

type flowConditionExpr struct {
	CatchAll bool
	Field    flowFieldRef
	Op       string
	Value    string
	Regex    *regexp.Regexp
}

var flowConditionOperators = []string{">=", "<=", "==", "!=", "!~", "=~", ">", "<", "~"}

func flowOperatorIsNumeric(op string) bool {
	switch op {
	case ">", "<", ">=", "<=":
		return true
	}
	return false
}

// parseFlowConditionExpr turns one expression into something evaluable, or explains why it is not.
//
// Errors here are read by an operator in a form, so they say what was expected rather than pointing
// at a byte offset.
func parseFlowConditionExpr(expr string) (flowConditionExpr, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return flowConditionExpr{}, fmt.Errorf(
			"a condition needs an expression, for example `status == 200`, or `*` for anything else")
	}
	if flowConditionCatchAlls[strings.ToLower(trimmed)] {
		return flowConditionExpr{CatchAll: true}, nil
	}

	fieldTok, op, value, quoted, err := splitFlowConditionExpr(trimmed)
	if err != nil {
		return flowConditionExpr{}, err
	}

	field, err := parseFlowFieldRef(fieldTok)
	if err != nil {
		return flowConditionExpr{}, err
	}

	if value == "" && !quoted {
		return flowConditionExpr{}, fmt.Errorf(
			"`%s` has nothing to compare against. Write the value after %s, and quote it if it is "+
				"empty or contains spaces", trimmed, op)
	}

	out := flowConditionExpr{Field: field, Op: op, Value: value}

	if flowOperatorIsNumeric(op) {
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return flowConditionExpr{}, fmt.Errorf(
				"%s only compares numbers, and %q is not one. Use == or ~ to compare text", op, value)
		}
	}
	if op == "=~" {
		compiled, cerr := regexp.Compile(value)
		if cerr != nil {
			// The whole point of validating at save time: an uncompilable regex found at run time is
			// a step that silently never matches, on a flow the operator is watching a target for.
			return flowConditionExpr{}, fmt.Errorf("that regular expression does not compile: %v", cerr)
		}
		out.Regex = compiled
	}

	return out, nil
}

// splitFlowConditionExpr cuts an expression into field, operator and value.
//
// Quoting is honoured inside the FIELD as well as the value, because a step name is operator-typed
// text the operator did not choose with a parser in mind: step."GET /login".status has to work, and
// so does a value containing an = or a space.
func splitFlowConditionExpr(expr string) (field, op, value string, valueQuoted bool, err error) {
	var fieldBuf strings.Builder
	i := 0
	for i < len(expr) {
		c := expr[i]
		if c == '"' || c == '\'' {
			rest := expr[i+1:]
			end := strings.IndexByte(rest, c)
			if end < 0 {
				return "", "", "", false, fmt.Errorf(
					"a quote is opened and never closed in `%s`", expr)
			}
			fieldBuf.WriteString(expr[i : i+1+end+1])
			i += 1 + end + 1
			continue
		}
		if c == ' ' || c == '\t' || strings.IndexByte("=!<>~", c) >= 0 {
			break
		}
		fieldBuf.WriteByte(c)
		i++
	}
	field = fieldBuf.String()
	if field == "" {
		return "", "", "", false, fmt.Errorf(
			"`%s` does not start with a field. Expected status, size, time_ms, body, header.<name> "+
				"or step.<name>.<field>", expr)
	}

	for i < len(expr) && (expr[i] == ' ' || expr[i] == '\t') {
		i++
	}
	rest := expr[i:]
	for _, candidate := range flowConditionOperators {
		if strings.HasPrefix(rest, candidate) {
			op = candidate
			break
		}
	}
	if op == "" {
		if strings.HasPrefix(strings.ToLower(field), "step.") && strings.Contains(expr, " ") {
			// Much the likeliest cause: the step's name has a space in it, because step names are
			// "GET /login". Saying "no operator" here would send the operator looking at the wrong end
			// of their expression.
			return "", "", "", false, fmt.Errorf(
				"`%s` could not be read. If the step's name contains a space, quote it: "+
					`step."My step".status == 200`, expr)
		}
		return "", "", "", false, fmt.Errorf(
			"`%s` has no operator. Use one of == != > < >= <= ~ !~ =~", expr)
	}

	value = strings.TrimSpace(rest[len(op):])
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
			valueQuoted = true
		}
	}
	return field, op, value, valueQuoted, nil
}

// parseFlowFieldRef resolves a field token, with or without a step reference.
func parseFlowFieldRef(token string) (flowFieldRef, error) {
	if !strings.HasPrefix(strings.ToLower(token), "step.") {
		kind, header, err := parseFlowFieldKind(token)
		return flowFieldRef{Kind: kind, Header: header}, err
	}

	rest := token[len("step."):]
	if rest == "" {
		return flowFieldRef{}, fmt.Errorf(
			"step. needs a step name or id and a field, for example step.Login.status")
	}

	var stepRef, kindPart string
	if rest[0] == '"' || rest[0] == '\'' {
		quote := rest[0]
		end := strings.IndexByte(rest[1:], quote)
		if end < 0 {
			return flowFieldRef{}, fmt.Errorf("the quoted step name in `%s` is never closed", token)
		}
		stepRef = rest[1 : 1+end]
		remainder := rest[1+end+1:]
		if !strings.HasPrefix(remainder, ".") {
			return flowFieldRef{}, fmt.Errorf(
				"`%s` names a step but no field. Add one, for example step.\"%s\".status", token, stepRef)
		}
		kindPart = remainder[1:]
	} else {
		lower := strings.ToLower(rest)
		if idx := strings.Index(lower, ".header."); idx >= 0 {
			// A step name may itself contain dots (GET /static/app.js), so the header marker is looked
			// for FIRST and the last-dot rule is only the fallback.
			stepRef, kindPart = rest[:idx], rest[idx+1:]
		} else if last := strings.LastIndex(rest, "."); last > 0 {
			stepRef, kindPart = rest[:last], rest[last+1:]
		} else {
			return flowFieldRef{}, fmt.Errorf(
				"`%s` names a step but no field. Add one, for example step.%s.status", token, rest)
		}
	}

	if strings.TrimSpace(stepRef) == "" {
		return flowFieldRef{}, fmt.Errorf("`%s` has an empty step reference", token)
	}
	kind, header, err := parseFlowFieldKind(kindPart)
	if err != nil {
		return flowFieldRef{}, err
	}
	return flowFieldRef{StepRef: strings.TrimSpace(stepRef), Kind: kind, Header: header}, nil
}

func parseFlowFieldKind(token string) (kind, header string, err error) {
	clean := strings.Trim(strings.TrimSpace(token), `"'`)
	lower := strings.ToLower(clean)
	switch lower {
	case "status", "body", "size", "time_ms":
		return lower, "", nil
	}
	if strings.HasPrefix(lower, "header.") {
		name := strings.Trim(strings.TrimSpace(clean[len("header."):]), `"'`)
		if name == "" {
			return "", "", fmt.Errorf("header. needs a header name, for example header.Location")
		}
		return "header", name, nil
	}
	return "", "", fmt.Errorf(
		"%q is not a field. Use status, header.<name>, body, size or time_ms, optionally prefixed "+
			"with step.<name-or-id>.", clean)
}

// ---------------------------------------------------------------------------
// The evaluator: a pure function over (conditions, response, prior results)
// ---------------------------------------------------------------------------

// EvaluateFlowConditions returns the action to take.
//
// First match wins. A condition that cannot be judged does NOT match and its reason is collected in
// Problems, so a run can explain itself afterwards. Nothing here touches a database, a socket or the
// clock, which is what makes every branching decision testable without a target.
func EvaluateFlowConditions(conds []FlowCondition, ctx FlowEvalContext) FlowConditionMatch {
	out := FlowConditionMatch{Index: -1, Action: FlowActionContinue}

	for i, cond := range conds {
		expr, err := parseFlowConditionExpr(cond.When)
		if err != nil {
			out.Problems = append(out.Problems,
				fmt.Sprintf("condition %d (%s) was skipped: %v", i+1, cond.When, err))
			continue
		}

		matched := expr.CatchAll
		if !expr.CatchAll {
			ok, problem := evaluateFlowExpr(expr, ctx)
			if problem != "" {
				out.Problems = append(out.Problems,
					fmt.Sprintf("condition %d (%s) did not match: %s", i+1, cond.When, problem))
			}
			matched = ok
		}
		if !matched {
			continue
		}

		out.Index = i
		out.When = cond.When
		out.Action = normalizeFlowAction(cond.Then)
		out.Target = cond.Target
		out.Message = cond.Message
		return out
	}

	return out
}

func normalizeFlowAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case FlowActionGoto:
		return FlowActionGoto
	case FlowActionStop:
		return FlowActionStop
	case FlowActionFail:
		return FlowActionFail
	case FlowActionRetry:
		return FlowActionRetry
	default:
		// Including the empty string. An action nobody recognises must not become a jump.
		return FlowActionContinue
	}
}

// flowFieldValue is one field, resolved. Present=false means ABSENT, which never matches anything.
type flowFieldValue struct {
	Present bool
	Texts   []string
	Num     float64
	IsNum   bool
}

// resolveFlowField looks a field up. The returned string is a problem, empty when there is none;
// a missing header is NOT a problem, it is simply absent.
func resolveFlowField(field flowFieldRef, ctx FlowEvalContext) (flowFieldValue, string) {
	resp := ctx.Response
	if field.StepRef != "" {
		ref, known := ctx.Steps[strings.ToLower(strings.TrimSpace(field.StepRef))]
		if !known {
			return flowFieldValue{}, fmt.Sprintf(
				"there is no step called %q in this flow, so %s could not be read",
				field.StepRef, field.String())
		}
		if ref.Response == nil {
			reason := ref.Missing
			if reason == "" {
				reason = "it has not run in this flow yet"
			}
			// The disarm case lands here, and saying so is required: a skipped step that silently
			// makes a condition false is how an operator concludes the target changed behaviour.
			return flowFieldValue{}, fmt.Sprintf(
				"step %q produced no response (%s), so %s could not be read",
				field.StepRef, reason, field.String())
		}
		resp = *ref.Response
	}

	if !resp.Ran {
		return flowFieldValue{}, ""
	}

	switch field.Kind {
	case "status":
		return flowFieldValue{Present: true, Texts: []string{strconv.Itoa(resp.Status)},
			Num: float64(resp.Status), IsNum: true}, ""
	case "size":
		return flowFieldValue{Present: true, Texts: []string{strconv.Itoa(len(resp.Body))},
			Num: float64(len(resp.Body)), IsNum: true}, ""
	case "time_ms":
		return flowFieldValue{Present: true,
			Texts: []string{strconv.FormatFloat(resp.TimeMs, 'f', -1, 64)},
			Num:   resp.TimeMs, IsNum: true}, ""
	case "body":
		return flowFieldValue{Present: true, Texts: []string{resp.Body}}, ""
	case "header":
		values := headerValuesFor(resp.Headers, field.Header)
		if len(values) == 0 {
			// ABSENT, deliberately, and not "". A header that is not there must not compare equal to
			// an empty string, or `header.X != "y"` would be true on a response with no X at all and
			// the flow would branch on a header the server never sent.
			return flowFieldValue{}, ""
		}
		return flowFieldValue{Present: true, Texts: values}, ""
	}
	return flowFieldValue{}, fmt.Sprintf("%q is not a field this evaluator knows", field.Kind)
}

// evaluateFlowExpr applies one operator. Never panics: every failure is a (false, problem).
func evaluateFlowExpr(expr flowConditionExpr, ctx FlowEvalContext) (bool, string) {
	value, problem := resolveFlowField(expr.Field, ctx)
	if problem != "" {
		return false, problem
	}
	if !value.Present {
		return false, ""
	}

	switch expr.Op {
	case ">", "<", ">=", "<=":
		want, err := strconv.ParseFloat(expr.Value, 64)
		if err != nil {
			return false, fmt.Sprintf("%s only compares numbers and %q is not one", expr.Op, expr.Value)
		}
		nums, ok := numericFlowValues(value)
		if !ok {
			return false, fmt.Sprintf(
				"%s is not a number (%s), so %s cannot compare it. Use == or ~ for text",
				expr.Field.String(), truncateForPreview(firstFlowText(value), 60), expr.Op)
		}
		for _, got := range nums {
			if compareFlowNumbers(got, expr.Op, want) {
				return true, ""
			}
		}
		return false, ""

	case "==", "!=":
		wantNum, wantIsNum := parseFlowNumber(expr.Value)
		equalAny := false
		for _, text := range value.Texts {
			var same bool
			if gotNum, gotIsNum := parseFlowNumber(text); wantIsNum && gotIsNum && value.IsNum {
				same = gotNum == wantNum
			} else {
				same = text == expr.Value
			}
			if same {
				equalAny = true
				break
			}
		}
		if expr.Op == "==" {
			return equalAny, ""
		}
		// != is "no value of this field equals it", which is what a negation means when a header has
		// three values. The field being ABSENT is handled above and is never a match either way.
		return !equalAny, ""

	case "~", "!~":
		needle := strings.ToLower(expr.Value)
		containsAny := false
		for _, text := range value.Texts {
			if strings.Contains(strings.ToLower(text), needle) {
				containsAny = true
				break
			}
		}
		if expr.Op == "~" {
			return containsAny, ""
		}
		return !containsAny, ""

	case "=~":
		if expr.Regex == nil {
			compiled, err := regexp.Compile(expr.Value)
			if err != nil {
				return false, fmt.Sprintf("that regular expression does not compile: %v", err)
			}
			expr.Regex = compiled
		}
		for _, text := range value.Texts {
			if expr.Regex.MatchString(text) {
				return true, ""
			}
		}
		return false, ""
	}

	return false, fmt.Sprintf("%q is not an operator this evaluator knows", expr.Op)
}

func compareFlowNumbers(got float64, op string, want float64) bool {
	switch op {
	case ">":
		return got > want
	case "<":
		return got < want
	case ">=":
		return got >= want
	case "<=":
		return got <= want
	}
	return false
}

func parseFlowNumber(s string) (float64, bool) {
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return n, err == nil
}

func numericFlowValues(value flowFieldValue) ([]float64, bool) {
	if value.IsNum {
		return []float64{value.Num}, true
	}
	out := make([]float64, 0, len(value.Texts))
	for _, text := range value.Texts {
		if n, ok := parseFlowNumber(text); ok {
			out = append(out, n)
		}
	}
	return out, len(out) > 0
}

func firstFlowText(value flowFieldValue) string {
	if len(value.Texts) == 0 {
		return ""
	}
	return value.Texts[0]
}

// ---------------------------------------------------------------------------
// Authoring-time validation
// ---------------------------------------------------------------------------

// FlowGraphStep is the shape the validator and the cycle detector need: enough to resolve a goto,
// and nothing else. Kept separate from RequestFlowStep so both can be exercised from struct literals.
type FlowGraphStep struct {
	ID         string
	Name       string
	Enabled    bool
	Conditions []FlowCondition
}

// ValidateFlowConditions refuses a condition list that cannot work, at the moment it is saved.
//
// Returns "" when the list is fine, and one sentence naming the offending condition when it is not.
// steps may be nil, in which case goto targets are not resolved (used when the caller has not loaded
// the flow, e.g. validating a step being added to an empty flow).
func ValidateFlowConditions(conds []FlowCondition, steps []FlowGraphStep) string {
	for i, cond := range conds {
		expr, err := parseFlowConditionExpr(cond.When)
		if err != nil {
			return fmt.Sprintf("condition %d: %v", i+1, err)
		}

		if expr.CatchAll && i != len(conds)-1 {
			// THE RULE THAT IS NOT A STYLE PREFERENCE. A catch-all matches everything, so every
			// condition after it is dead code that the operator can still see in the list.
			return fmt.Sprintf(
				"condition %d is the catch-all (%s), and %d condition(s) come after it. A catch-all "+
					"matches everything, so those would never run. Move it to the end.",
				i+1, strings.TrimSpace(cond.When), len(conds)-i-1)
		}

		action := normalizeFlowAction(cond.Then)
		if strings.TrimSpace(cond.Then) != "" && !isKnownFlowAction(cond.Then) {
			return fmt.Sprintf(
				"condition %d asks for %q, which is not an action. Use continue, goto, stop, fail or retry.",
				i+1, strings.TrimSpace(cond.Then))
		}

		if action == FlowActionGoto {
			if strings.TrimSpace(cond.Target) == "" {
				return fmt.Sprintf("condition %d is a goto with no target: name the step to jump to", i+1)
			}
			if len(steps) > 0 {
				if _, problem := resolveFlowStepTarget(cond.Target, steps); problem != "" {
					return fmt.Sprintf("condition %d: %s", i+1, problem)
				}
			}
		}
		if action != FlowActionGoto && strings.TrimSpace(cond.Target) != "" {
			return fmt.Sprintf(
				"condition %d names a target but its action is %s, and only goto jumps to a step. "+
					"Either change the action or remove the target.", i+1, action)
		}
	}
	return ""
}

func isKnownFlowAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case FlowActionContinue, FlowActionGoto, FlowActionStop, FlowActionFail, FlowActionRetry:
		return true
	}
	return false
}

// resolveFlowStepTarget finds the step a goto names: by id, else by name, case-insensitively.
//
// An ambiguous name is refused rather than resolved to the first match. Two steps called "Login"
// with a jump to "Login" is a flow whose behaviour depends on row order, and the operator would
// never see which one it chose.
func resolveFlowStepTarget(target string, steps []FlowGraphStep) (int, string) {
	want := strings.ToLower(strings.TrimSpace(target))
	if want == "" {
		return -1, "a goto needs a target step"
	}
	for i, s := range steps {
		if strings.ToLower(s.ID) == want {
			return i, ""
		}
	}
	found := -1
	count := 0
	for i, s := range steps {
		if strings.ToLower(strings.TrimSpace(s.Name)) == want {
			count++
			if found < 0 {
				found = i
			}
		}
	}
	switch {
	case count == 1:
		return found, ""
	case count > 1:
		return -1, fmt.Sprintf(
			"%d steps are called %q, so a goto naming it has no single destination. Use the step id.",
			count, strings.TrimSpace(target))
	}
	return -1, fmt.Sprintf("no step in this flow is called %q, so the goto has nowhere to jump to",
		strings.TrimSpace(target))
}

// DetectFlowConditionCycles reports every loop a goto can create, at authoring time.
//
// The graph is every goto edge plus the implicit fall-through from each step to the next, because
// that fall-through is what closes a loop: a single backwards goto is a cycle only when the steps
// between it and its target run again on the way back. A retry is a self-edge for the same reason.
//
// Warnings, NOT refusals. A bounded retry loop is legitimate and the caps below make it safe; what
// is not acceptable is the operator finding out when it fires against a live target.
func DetectFlowConditionCycles(steps []FlowGraphStep) []string {
	n := len(steps)
	if n == 0 {
		return nil
	}

	edges := make([][]int, n)
	labels := make([]map[int]string, n)
	for i := range steps {
		labels[i] = map[int]string{}
		if i+1 < n {
			edges[i] = append(edges[i], i+1)
			labels[i][i+1] = "falls through to"
		}
		for _, cond := range steps[i].Conditions {
			switch normalizeFlowAction(cond.Then) {
			case FlowActionRetry:
				edges[i] = append(edges[i], i)
				labels[i][i] = "retries itself when " + strings.TrimSpace(cond.When)
			case FlowActionGoto:
				to, problem := resolveFlowStepTarget(cond.Target, steps)
				if problem != "" || to < 0 {
					continue
				}
				edges[i] = append(edges[i], to)
				labels[i][to] = "jumps here when " + strings.TrimSpace(cond.When)
			}
		}
	}

	var warnings []string
	seen := map[string]bool{}
	state := make([]int, n) // 0 unvisited, 1 on the stack, 2 done
	stack := []int{}

	var walk func(int)
	walk = func(node int) {
		state[node] = 1
		stack = append(stack, node)
		for _, next := range edges[node] {
			switch state[next] {
			case 0:
				walk(next)
			case 1:
				// Found a back edge: everything from `next` to the top of the stack is the loop.
				start := 0
				for i, id := range stack {
					if id == next {
						start = i
						break
					}
				}
				cycle := append([]int{}, stack[start:]...)
				if w := describeFlowCycle(cycle, steps, labels); w != "" && !seen[w] {
					seen[w] = true
					warnings = append(warnings, w)
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[node] = 2
	}

	for i := 0; i < n; i++ {
		if state[i] == 0 {
			walk(i)
		}
	}
	return warnings
}

func describeFlowCycle(cycle []int, steps []FlowGraphStep, labels []map[int]string) string {
	if len(cycle) == 0 {
		return ""
	}
	names := make([]string, 0, len(cycle)+1)
	for _, idx := range cycle {
		names = append(names, flowStepLabel(steps[idx], idx))
	}
	names = append(names, flowStepLabel(steps[cycle[0]], cycle[0]))

	last := cycle[len(cycle)-1]
	how := labels[last][cycle[0]]
	if how == "" {
		how = "jumps back"
	}
	if len(cycle) == 1 {
		return fmt.Sprintf("%s can run again forever: it %s. The retry cap and the per-step "+
			"execution cap will stop it, but the run will end on a cap rather than on your flow.",
			flowStepLabel(steps[cycle[0]], cycle[0]), how)
	}
	return fmt.Sprintf("these steps form a loop: %s (%s %s). That is allowed, and the executed-step "+
		"budget will stop it, but a run that ends on a cap ends without an answer.",
		strings.Join(names, " -> "), flowStepLabel(steps[last], last), how)
}

func flowStepLabel(step FlowGraphStep, index int) string {
	if name := strings.TrimSpace(step.Name); name != "" {
		return name
	}
	return fmt.Sprintf("step %d", index+1)
}

// ---------------------------------------------------------------------------
// Loop protection
// ---------------------------------------------------------------------------

// The caps. DEFAULTS are what a run uses when the operator says nothing; CEILINGS are the most the
// operator may ask for. There is no "off": every number below is a positive integer at runtime,
// whatever arrives in the request body.
const (
	// Executions, not definitions. A 4-step flow that loops is 4 definitions and unbounded
	// executions, so this counts the latter - every VISIT to a step, including one that is skipped or
	// refused, because two disarmed steps that goto each other would otherwise spin forever without
	// sending a single request.
	flowRunDefaultMaxExecutions = 50
	flowRunMaxExecutionsCeiling = 300

	// One step cannot be re-entered indefinitely even inside a budget that still has room.
	flowRunDefaultPerStepExecutions = 10
	flowRunPerStepExecutionsCeiling = 50

	// Separate and small, because a retry is for a flaky response and not for brute force.
	flowRunDefaultRetryCap = 3
	flowRunRetryCapCeiling = 10

	// The delay between retries. A retry with no delay is a tight loop that happens to be counted.
	flowRunDefaultRetryDelayMs = 1000
	flowRunMinRetryDelayMs     = 250
	flowRunMaxRetryDelayMs     = 30000

	// However slowly a run is paced, it cannot outlive the operator watching it.
	flowRunDefaultWallClockS = 600
	flowRunWallClockCeilingS = 1800
)

// Stop reasons. The machine-readable half of "which cap stopped this run".
const (
	FlowStopCompleted     = "completed"
	FlowStopByCondition   = "stopped_by_condition"
	FlowStopFailed        = "failed_by_condition"
	FlowStopMaxExecutions = "max_executed_steps"
	FlowStopPerStepCap    = "per_step_execution_cap"
	FlowStopRetryCap      = "retry_cap"
	FlowStopWallClock     = "wall_clock"
	FlowStopRequestBudget = "engagement_request_budget"
	FlowStopGotoMissing   = "goto_target_missing"
)

// FlowRunCapRequest is what the operator may ask for. Every field is a pointer: absent means "use
// the default", which is a different statement from "zero", and zero must never mean "no cap".
type FlowRunCapRequest struct {
	MaxExecutions        *int `json:"max_executions"`
	PerStepMaxExecutions *int `json:"per_step_max_executions"`
	RetryCap             *int `json:"retry_cap"`
	RetryDelayMs         *int `json:"retry_delay_ms"`
	WallClockS           *int `json:"wall_clock_s"`
}

// FlowRunCaps is the resolved, clamped set actually enforced, reported back with the run so the
// operator can see the numbers their run was judged against.
type FlowRunCaps struct {
	MaxExecutions        int `json:"max_executions"`
	PerStepMaxExecutions int `json:"per_step_max_executions"`
	RetryCap             int `json:"retry_cap"`
	RetryDelayMs         int `json:"retry_delay_ms"`
	WallClockS           int `json:"wall_clock_s"`
	// MaxRequests is the engagement's own per-run request budget. Not ours to raise: it is the
	// programme's number, resolved per target.
	MaxRequests int `json:"max_requests"`
	// RPS is the engagement rate limit every request in this run is paced to, loop or not.
	RPS float64 `json:"rps"`
	// Notes records every value that was clamped, because a run that silently ignored what the
	// operator typed is a run whose numbers cannot be trusted.
	Notes []string `json:"notes,omitempty"`
}

// ResolveFlowRunCaps folds the request into the defaults and the ceilings. Pure, so the arithmetic
// that stands between a flow and a denial of service can be tested without a target.
func ResolveFlowRunCaps(req FlowRunCapRequest, eng ResolvedEngagementConfig) FlowRunCaps {
	out := FlowRunCaps{
		MaxExecutions:        flowRunDefaultMaxExecutions,
		PerStepMaxExecutions: flowRunDefaultPerStepExecutions,
		RetryCap:             flowRunDefaultRetryCap,
		RetryDelayMs:         flowRunDefaultRetryDelayMs,
		WallClockS:           flowRunDefaultWallClockS,
		MaxRequests:          eng.MaxRequestsPerRun,
		RPS:                  eng.MaxRPS,
	}

	clamp := func(asked *int, current, min, max int, label string) int {
		if asked == nil {
			return current
		}
		value := *asked
		if value < min {
			out.Notes = append(out.Notes, fmt.Sprintf(
				"%s was raised from %d to the minimum of %d", label, value, min))
			return min
		}
		if value > max {
			out.Notes = append(out.Notes, fmt.Sprintf(
				"%s was lowered from %d to the ceiling of %d, which is not configurable off",
				label, value, max))
			return max
		}
		return value
	}

	out.MaxExecutions = clamp(req.MaxExecutions, out.MaxExecutions, 1,
		flowRunMaxExecutionsCeiling, "max_executions")
	out.PerStepMaxExecutions = clamp(req.PerStepMaxExecutions, out.PerStepMaxExecutions, 1,
		flowRunPerStepExecutionsCeiling, "per_step_max_executions")
	out.RetryCap = clamp(req.RetryCap, out.RetryCap, 0, flowRunRetryCapCeiling, "retry_cap")
	out.RetryDelayMs = clamp(req.RetryDelayMs, out.RetryDelayMs, flowRunMinRetryDelayMs,
		flowRunMaxRetryDelayMs, "retry_delay_ms")
	out.WallClockS = clamp(req.WallClockS, out.WallClockS, 1, flowRunWallClockCeilingS, "wall_clock_s")

	if out.MaxRequests <= 0 {
		out.MaxRequests = flowRunMaxExecutionsCeiling
	}
	if out.RPS <= 0 {
		out.RPS = engagementDefaultMaxRPS
	}
	return out
}

// ---------------------------------------------------------------------------
// The trace
// ---------------------------------------------------------------------------

// FlowExecutionTrace is ONE execution of one step.
//
// Without this a branching flow is unexplainable, and an unexplainable automation is one nobody
// trusts. Every field here answers a question an operator asks out loud while reading a run: what
// ran, which time round, what came back, which condition fired, and what it did next.
type FlowExecutionTrace struct {
	Sequence   int     `json:"sequence"` // 1-based, across the whole run
	StepID     string  `json:"step_id"`
	StepName   string  `json:"step_name"`
	StepOrder  int     `json:"step_order"`
	Attempt    int     `json:"attempt"`    // 1, then 2+ after a retry
	Executions int     `json:"executions"` // how many times this step has now run
	Sent       bool    `json:"sent"`
	Status     int     `json:"status,omitempty"`
	SizeBytes  int     `json:"size_bytes"`
	TimeMs     float64 `json:"time_ms"`

	// Which condition matched, -1 when none did, and the action taken either way.
	MatchedCondition int    `json:"matched_condition"`
	MatchedWhen      string `json:"matched_when,omitempty"`
	Action           string `json:"action"`
	ActionTarget     string `json:"action_target,omitempty"`
	ActionTargetName string `json:"action_target_name,omitempty"`
	Message          string `json:"message,omitempty"`

	Skipped     bool                `json:"skipped,omitempty"`
	SkipReason  string              `json:"skip_reason,omitempty"`
	Refusal     string              `json:"refusal,omitempty"`
	Error       string              `json:"error,omitempty"`
	Captured    []ExtractionOutcome `json:"captured,omitempty"`
	Substituted []string            `json:"substituted,omitempty"`
	// Problems from the evaluator: a condition that referenced a disarmed step, a regex that would
	// not compile, a numeric comparison against text.
	ConditionProblems []string `json:"condition_problems,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

// FlowRunResult is one run of one flow.
type FlowRunResult struct {
	RunID    string    `json:"run_id"`
	FlowID   string    `json:"flow_id"`
	Started  time.Time `json:"started_at"`
	Finished time.Time `json:"finished_at"`

	// Outcome is the headline: completed, stopped, failed or capped.
	Outcome string `json:"outcome"`
	// StopReason is the machine-readable half; StopDetail is the sentence that names the cap in the
	// operator's own words, because "flow ended" with no reason is how somebody concludes the target
	// is broken when it was their own flow.
	StopReason string `json:"stop_reason"`
	StopDetail string `json:"stop_detail"`

	Executions   int                  `json:"executions"`
	RequestsSent int                  `json:"requests_sent"`
	Caps         FlowRunCaps          `json:"caps"`
	Trace        []FlowExecutionTrace `json:"trace"`
	// Warnings are run-level: cycles in the graph, a condition that referenced a disarmed step.
	Warnings []string `json:"warnings,omitempty"`
}

const (
	flowOutcomeCompleted = "completed"
	flowOutcomeStopped   = "stopped"
	flowOutcomeFailed    = "failed"
	flowOutcomeCapped    = "capped"
)

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

// flowRunDeps is everything the runner does to the outside world, injected.
//
// Not for its own sake: the loop protection is the safety-critical part of this feature, and a cap
// that can only be exercised by pointing a real runner at a real target is a cap nobody will ever
// check. With these four, every cap has a test.
type flowRunDeps struct {
	send    func(raw, baseURL string, jar http.CookieJar, timeout time.Duration) (int, map[string][]string, string, float64, error)
	persist func(stepID string, status int, headers map[string][]string, body string, ms float64, errStr string) error
	sleep   func(time.Duration)
	now     func() time.Time
}

// runRequestFlowConditional walks a flow, following its conditions.
//
// The invariants it shares with the linear replay, which are the reason a flow is a flow:
//
//   - ONE cookie jar for the whole run, so Set-Cookie from an earlier step rides on later ones.
//   - ONE variable map, so {{af:NAME}} substitution and extraction keep working ACROSS A JUMP: a step
//     reached by goto still sees every value captured by the steps that actually ran.
//   - The DISARM machinery is honoured. A disabled step is skipped, never sent, and the skip is
//     recorded so a condition that referenced it can say why it could not be judged.
//   - The BOUNDARY is checked on every send, on the SUBSTITUTED bytes: the operator's deny list
//     first, then the scope boundary, then the exclusion rules. See flowSendRails.
//   - The engagement config supplies the header, the user agent, the rate limit and the timeout.
func runRequestFlowConditional(flow RequestFlow, steps []RequestFlowStep, rails flowSendRails,
	eng ResolvedEngagementConfig, caps FlowRunCaps, jar http.CookieJar,
	deps flowRunDeps) *FlowRunResult {

	started := deps.now()
	result := &FlowRunResult{
		RunID:   uuid.New().String(),
		FlowID:  flow.ID,
		Started: started,
		Outcome: flowOutcomeCompleted,
		Caps:    caps,
		Trace:   []FlowExecutionTrace{},
	}
	result.Warnings = append(result.Warnings, DetectFlowConditionCycles(requestFlowGraph(steps))...)

	// Every step of the flow, keyed by id AND lower-cased name, so step.<name> and step.<id> resolve
	// through one map. Response stays nil until the step actually produces one.
	refs := map[string]FlowStepRef{}
	register := func(step RequestFlowStep, ref FlowStepRef) {
		refs[strings.ToLower(step.ID)] = ref
		if name := strings.ToLower(strings.TrimSpace(step.Name)); name != "" {
			refs[name] = ref
		}
	}
	for _, step := range steps {
		missing := "it has not run in this flow yet"
		if !step.Enabled {
			missing = "it is turned off, so the run skipped it rather than sending it"
		}
		register(step, FlowStepRef{Name: step.Name, Missing: missing})
	}

	vars := map[string]string{}
	perStep := map[string]int{}
	retriesUsed := map[string]int{}
	deadline := started.Add(time.Duration(caps.WallClockS) * time.Second)
	pacing := newFlowPacer(caps.RPS, deps.now, deps.sleep)
	timeout := time.Duration(eng.RequestTimeoutS) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(engagementDefaultTimeoutS) * time.Second
	}
	graph := requestFlowGraph(steps)

	stop := func(outcome, reason, detail string) *FlowRunResult {
		result.Outcome = outcome
		result.StopReason = reason
		result.StopDetail = detail
		result.Finished = deps.now()
		return result
	}

	index := 0
	attempt := 1
	for index >= 0 && index < len(steps) {
		if deps.now().After(deadline) {
			return stop(flowOutcomeCapped, FlowStopWallClock, fmt.Sprintf(
				"stopped: the run hit the WALL CLOCK cap of %d seconds after %d executed step(s). "+
					"Nothing further was sent.", caps.WallClockS, result.Executions))
		}
		if result.Executions >= caps.MaxExecutions {
			return stop(flowOutcomeCapped, FlowStopMaxExecutions, fmt.Sprintf(
				"stopped: the run hit the MAX EXECUTED STEPS cap of %d. This counts executions, not "+
					"steps, so a flow that jumps backwards reaches it even though it has only %d step(s). "+
					"Nothing further was sent.", caps.MaxExecutions, len(steps)))
		}

		step := steps[index]

		// Checked BEFORE the counters move, so a capped run's execution count still matches the
		// number of entries in its trace. A run whose own numbers disagree is one nobody can read.
		if perStep[step.ID]+1 > caps.PerStepMaxExecutions {
			return stop(flowOutcomeCapped, FlowStopPerStepCap, fmt.Sprintf(
				"stopped: step %q hit the PER-STEP EXECUTION CAP of %d. A condition keeps returning to "+
					"it. Nothing further was sent.", flowStepDisplayName(step), caps.PerStepMaxExecutions))
		}
		perStep[step.ID]++
		result.Executions++

		entry := FlowExecutionTrace{
			Sequence:         len(result.Trace) + 1,
			StepID:           step.ID,
			StepName:         flowStepDisplayName(step),
			StepOrder:        step.StepOrder,
			Attempt:          attempt,
			Executions:       perStep[step.ID],
			MatchedCondition: -1,
			Action:           FlowActionContinue,
		}

		// THE DISARM MACHINERY, HONOURED. A disabled step is not sent, its stored response is left
		// alone (it is evidence the operator kept), and its conditions are NOT evaluated, because a
		// step that produced no response cannot be branched on.
		if !step.Enabled {
			entry.Skipped = true
			entry.SkipReason = "this step is turned off, so it was not sent"
			if len(step.Conditions) > 0 {
				entry.Notes = append(entry.Notes, fmt.Sprintf(
					"%d condition(s) on this step were not evaluated, because a step that was not sent "+
						"has no response to judge", len(step.Conditions)))
			}
			result.Trace = append(result.Trace, entry)
			index++
			attempt = 1
			continue
		}

		request, substituted, refusal := prepareStepRequest(step.RawRequest, vars)
		entry.Substituted = substituted
		if refusal == "" {
			// Judged on the SUBSTITUTED text: a placeholder can sit in the Host header, and the host
			// that matters is the one that will actually be dialled.
			if host, scopeRefusal := requestFlowScopeRefusal(request, flow.BaseURL, rails); scopeRefusal != "" {
				if host != "" {
					rails.Scope.Refuse(host)
				}
				refusal = scopeRefusal
			}
		}
		if refusal != "" {
			// A refusal does not abort the run, for the same reason it does not in the linear replay:
			// every step still gets a row and each failure lands on the step it belongs to. The stored
			// response is cleared, so a previous 200 does not sit next to the reason this run did not
			// happen looking like a success.
			if err := deps.persist(step.ID, 0, nil, "", 0, refusal); err != nil {
				log.Printf("[REQUEST-FLOW] Failed to persist refusal for step %s: %v", step.ID, err)
			}
			entry.Refusal = refusal
			entry.Notes = append(entry.Notes,
				"conditions on this step were not evaluated, because it was not sent")
			result.Trace = append(result.Trace, entry)
			index++
			attempt = 1
			continue
		}

		if result.RequestsSent >= caps.MaxRequests {
			return stop(flowOutcomeCapped, FlowStopRequestBudget, fmt.Sprintf(
				"stopped: the run hit this target's ENGAGEMENT REQUEST BUDGET of %d request(s). That "+
					"is the programme's number, set in the engagement config, not a flow setting.",
				caps.MaxRequests))
		}

		// The engagement rate limit, applied to EVERY request the runner sends, loop or not.
		pacing.wait()

		outbound, engNotes := applyEngagementToRawRequest(request, eng)
		entry.Notes = append(entry.Notes, engNotes...)

		effBase := resolveBaseURL(outbound, flow.BaseURL)
		status, headers, body, ms, sendErr := deps.send(outbound, effBase, jar, timeout)
		result.RequestsSent++

		entry.Sent = true
		entry.Status = status
		entry.SizeBytes = len(body)
		entry.TimeMs = ms

		captured, outcomes := runAuthFlowExtractions(step.Extractions, headers, body)
		for name, value := range captured {
			// One variable map for the whole run, so a step reached by goto sees what earlier steps
			// captured, and a step run twice refreshes what it captures.
			vars[name] = value
		}
		entry.Captured = outcomes

		problems := []string{}
		if sendErr != nil {
			problems = append(problems, sendErr.Error())
		}
		for i, outcome := range outcomes {
			if !outcome.Matched && i < len(step.Extractions) && !step.Extractions[i].Optional {
				problems = append(problems, "capture "+outcome.Name+": "+outcome.Problem)
			}
		}
		if len(problems) > 0 {
			entry.Error = strings.Join(problems, "; ")
		}
		if err := deps.persist(step.ID, status, headers, body, ms, entry.Error); err != nil {
			log.Printf("[REQUEST-FLOW] Failed to persist replay for step %s: %v", step.ID, err)
		}

		response := FlowResponse{Ran: sendErr == nil, Status: status, Headers: headers,
			Body: body, TimeMs: ms}
		stored := response
		register(step, FlowStepRef{Name: step.Name, Response: &stored})

		match := EvaluateFlowConditions(step.Conditions, FlowEvalContext{Response: response, Steps: refs})
		entry.MatchedCondition = match.Index
		entry.MatchedWhen = match.When
		entry.Action = match.Action
		entry.Message = match.Message
		entry.ConditionProblems = match.Problems
		for _, problem := range match.Problems {
			if strings.Contains(problem, "it is turned off") {
				// Required by the disarm rule: skipping a step must not SILENTLY break a condition
				// that referenced it, so it is said at run level too and not only per step.
				result.Warnings = appendUnique(result.Warnings, fmt.Sprintf(
					"on step %q, %s", flowStepDisplayName(step), problem))
			}
		}

		switch match.Action {
		case FlowActionStop:
			entry.ActionTarget = ""
			result.Trace = append(result.Trace, entry)
			detail := strings.TrimSpace(match.Message)
			if detail == "" {
				detail = fmt.Sprintf("stopped: a condition on step %q ended the run (%s)",
					flowStepDisplayName(step), match.When)
			}
			return stop(flowOutcomeStopped, FlowStopByCondition, detail)

		case FlowActionFail:
			result.Trace = append(result.Trace, entry)
			detail := strings.TrimSpace(match.Message)
			if detail == "" {
				detail = fmt.Sprintf("failed: a condition on step %q ended the run (%s)",
					flowStepDisplayName(step), match.When)
			}
			return stop(flowOutcomeFailed, FlowStopFailed, detail)

		case FlowActionRetry:
			if retriesUsed[step.ID] >= caps.RetryCap {
				entry.Notes = append(entry.Notes, "the retry cap was already used up on this step")
				result.Trace = append(result.Trace, entry)
				return stop(flowOutcomeCapped, FlowStopRetryCap, fmt.Sprintf(
					"stopped: step %q hit the RETRY CAP of %d. Its condition asked to retry again and "+
						"the run stopped instead. Nothing further was sent.",
					flowStepDisplayName(step), caps.RetryCap))
			}
			retriesUsed[step.ID]++
			entry.Notes = append(entry.Notes, fmt.Sprintf("retrying in %dms (retry %d of %d)",
				caps.RetryDelayMs, retriesUsed[step.ID], caps.RetryCap))
			result.Trace = append(result.Trace, entry)
			deps.sleep(time.Duration(caps.RetryDelayMs) * time.Millisecond)
			attempt++
			continue // same index: re-send THIS step

		case FlowActionGoto:
			to, problem := resolveFlowStepTarget(match.Target, graph)
			if problem != "" {
				entry.Notes = append(entry.Notes, problem)
				result.Trace = append(result.Trace, entry)
				return stop(flowOutcomeFailed, FlowStopGotoMissing, fmt.Sprintf(
					"stopped: a condition on step %q jumps to %q and %s. Nothing further was sent.",
					flowStepDisplayName(step), match.Target, problem))
			}
			entry.ActionTarget = steps[to].ID
			entry.ActionTargetName = flowStepDisplayName(steps[to])
			result.Trace = append(result.Trace, entry)
			index = to
			attempt = 1
			continue

		default: // continue, and the no-match case, which mean the same thing
			result.Trace = append(result.Trace, entry)
			index++
			attempt = 1
		}
	}

	result.Finished = deps.now()
	result.StopReason = FlowStopCompleted
	result.StopDetail = fmt.Sprintf(
		"the flow ran to the end: %d executed step(s), %d request(s) sent.",
		result.Executions, result.RequestsSent)
	return result
}

func flowStepDisplayName(step RequestFlowStep) string {
	if name := strings.TrimSpace(step.Name); name != "" {
		return name
	}
	return fmt.Sprintf("step %d", step.StepOrder)
}

// requestFlowGraph adapts stored steps for the validator and the cycle detector.
func requestFlowGraph(steps []RequestFlowStep) []FlowGraphStep {
	out := make([]FlowGraphStep, 0, len(steps))
	for _, s := range steps {
		out = append(out, FlowGraphStep{ID: s.ID, Name: s.Name, Enabled: s.Enabled,
			Conditions: s.Conditions})
	}
	return out
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

// ---------------------------------------------------------------------------
// Pacing
// ---------------------------------------------------------------------------

// flowPacer holds the run to the engagement's rate limit.
//
// The full interval is slept here rather than handed to HostBudget, which clamps anything below 0.5
// rps UP to 0.5: several briefs cap at 20 requests per minute (0.33 rps), and a run that exceeded a
// programme's stated cap while the screen said otherwise is the failure this exists to avoid.
type flowPacer struct {
	interval time.Duration
	last     time.Time
	now      func() time.Time
	sleep    func(time.Duration)
}

func newFlowPacer(rps float64, now func() time.Time, sleep func(time.Duration)) *flowPacer {
	if rps <= 0 {
		rps = engagementDefaultMaxRPS
	}
	return &flowPacer{
		interval: time.Duration(float64(time.Second) / math.Max(rps, 0.001)),
		now:      now,
		sleep:    sleep,
	}
}

func (p *flowPacer) wait() {
	if !p.last.IsZero() {
		if remaining := p.interval - p.now().Sub(p.last); remaining > 0 {
			p.sleep(remaining)
		}
	}
	p.last = p.now()
}

// ---------------------------------------------------------------------------
// The sender
// ---------------------------------------------------------------------------

// applyEngagementToRawRequest puts the programme's identifying header and user agent on the bytes
// about to go out, and says what it changed.
//
// EVERY sender in this framework goes through ResolveEngagementConfig or it sends a programme's
// traffic without the header their brief calls mandatory, which is how a research run gets read by a
// SOC as an attack. A raw-bytes sender cannot take a header map, so the headers are spliced into the
// head of the request; the body is not touched, byte for byte, because a multipart boundary or a
// deliberate Content-Length disagreement is exactly what the operator is testing.
func applyEngagementToRawRequest(raw string, eng ResolvedEngagementConfig) (string, []string) {
	var notes []string

	for name, value := range eng.HeaderMap() {
		// HeaderMap has already refused Cookie, Authorization and anything with CRLF in it, so there
		// is no path from a stored row to a header that turns this into somebody else's session.
		if existing, ok := getRawRequestHeader(raw, name); ok && existing != value {
			notes = append(notes, fmt.Sprintf(
				"the engagement header %s replaced the one on this step (%s -> %s)",
				name, truncateForPreview(existing, 40), truncateForPreview(value, 40)))
		} else if !ok {
			notes = append(notes, "added the engagement header "+name)
		}
		raw = setRawRequestHeader(raw, name, value)
	}

	current, hasUA := getRawRequestHeader(raw, "User-Agent")
	switch {
	case eng.UserAgentMode == "append":
		// The custom UA is a TAG in append mode. Glued onto the step's own UA when it has one, so a
		// recorded browser request still looks like the browser it was, plus the operator's handle.
		tag := strings.TrimSpace(eng.CustomUserAgent)
		if tag != "" && hasUA && !strings.Contains(current, tag) {
			raw = setRawRequestHeader(raw, "User-Agent", current+" "+tag)
			notes = append(notes, "appended the engagement User-Agent tag")
		} else if !hasUA {
			raw = setRawRequestHeader(raw, "User-Agent", eng.EffectiveUserAgent)
			notes = append(notes, "set the engagement User-Agent")
		}
	case eng.Source["custom_user_agent"] == EngagementFromTarget ||
		eng.Source["custom_user_agent"] == EngagementFromGlobal:
		// Somebody deliberately set a User-Agent for this engagement, so it wins over the recorded one.
		if current != eng.EffectiveUserAgent {
			raw = setRawRequestHeader(raw, "User-Agent", eng.EffectiveUserAgent)
			notes = append(notes, "the engagement User-Agent replaced this step's own")
		}
	case !hasUA:
		// Nobody configured one and the step has none. Send the framework's, rather than Go's default
		// or nothing at all.
		raw = setRawRequestHeader(raw, "User-Agent", eng.EffectiveUserAgent)
		notes = append(notes, "set the framework's default User-Agent")
	}
	// The remaining case - no engagement UA configured and the step carries its own - deliberately
	// leaves the step alone. A built-in default is not an instruction, and overwriting the recorded
	// User-Agent changes the request the operator is testing.

	return raw, notes
}

// getRawRequestHeader reads a header off raw bytes without parsing the whole request, so it works on
// bytes that are mid-edit.
func getRawRequestHeader(raw, name string) (string, bool) {
	head, _, _ := splitRawRequestHeadBody(raw)
	if head == "" {
		head = raw
	}
	want := strings.ToLower(strings.TrimSpace(name)) + ":"
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // the request line
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), want) {
			_, value, _ := strings.Cut(line, ":")
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// setRawRequestHeader replaces or adds one header, leaving the request line, the other headers, the
// framing and the body exactly as they were.
func setRawRequestHeader(raw, name, value string) string {
	head, sep, body := splitRawRequestHeadBody(raw)
	if sep == "" {
		head, body = raw, ""
	}

	eol := "\n"
	if strings.Contains(head, "\r\n") {
		eol = "\r\n"
	}
	if sep == "" {
		sep = eol + eol
	}

	want := strings.ToLower(strings.TrimSpace(name)) + ":"
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	kept := make([]string, 0, len(lines)+1)
	for i, line := range lines {
		if i > 0 && strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), want) {
			continue
		}
		kept = append(kept, line)
	}
	// Trailing blank lines inside the head would push the new header after the header block.
	for len(kept) > 1 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}
	kept = append(kept, name+": "+value)

	return strings.Join(kept, eol) + sep + body
}

// sendFlowStepRequest is sendRawRequest with the engagement's timeout.
//
// It is not sendRawRequest itself only because that function hardcodes 30 seconds, and a programme
// that caps its request timeout has capped it for a reason. Everything else is deliberately
// identical: the same parser, the same "capture the 3xx instead of following it", the same 2MB body
// cap, so a step behaves the same way whether it is run alone or inside a conditional flow.
func sendFlowStepRequest(rawRequest, baseURL string, jar http.CookieJar,
	timeout time.Duration) (int, map[string][]string, string, float64, error) {

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))
	if err != nil {
		return 0, nil, "", 0, fmt.Errorf("failed to parse raw request: %w", err)
	}

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	scheme, host := "https", req.Host
	if baseURL != "" {
		u, perr := url.Parse(baseURL)
		if perr != nil || u.Host == "" {
			return 0, nil, "", 0, fmt.Errorf("invalid base_url %q", baseURL)
		}
		if u.Scheme != "" {
			scheme = u.Scheme
		}
		host = u.Host
	}
	if host == "" {
		return 0, nil, "", 0, fmt.Errorf("no Host header and no base_url; cannot determine target")
	}

	hostHeader := req.Host
	req.URL.Scheme = scheme
	req.URL.Host = host
	req.RequestURI = ""
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
	if hostHeader != "" {
		req.Host = hostHeader
	} else {
		req.Host = host
	}

	if timeout <= 0 {
		timeout = time.Duration(engagementDefaultTimeoutS) * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		Jar:     jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Captured, not followed. A 302 is a thing to branch on here, not a thing to chase.
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return 0, nil, "", elapsed, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	return resp.StatusCode, resp.Header, string(respBody), elapsed, nil
}

// liveFlowRunDeps is the real world.
func liveFlowRunDeps() flowRunDeps {
	return flowRunDeps{
		send:    sendFlowStepRequest,
		persist: updateRequestFlowStepResponse,
		sleep:   time.Sleep,
		now:     time.Now,
	}
}

// ---------------------------------------------------------------------------
// Persistence of the run
// ---------------------------------------------------------------------------

// saveRequestFlowRun records the run and its trace.
//
// Best effort by design: a run that happened is not un-happened by a failed INSERT, and the trace is
// returned to the caller regardless. The failure is logged rather than swallowed.
func saveRequestFlowRun(result *FlowRunResult) {
	traceJSON, err := json.Marshal(result.Trace)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Could not encode the run trace: %v", err)
		traceJSON = []byte("[]")
	}
	capsJSON, _ := json.Marshal(result.Caps)
	warningsJSON, _ := json.Marshal(orEmptyStrings(result.Warnings))

	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO request_flow_runs
		  (id, request_flow_id, started_at, finished_at, outcome, stop_reason, stop_detail,
		   executions, requests_sent, caps, warnings, trace)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		result.RunID, result.FlowID, result.Started, result.Finished, result.Outcome,
		result.StopReason, result.StopDetail, result.Executions, result.RequestsSent,
		capsJSON, warningsJSON, traceJSON); err != nil {
		log.Printf("[REQUEST-FLOW] Failed to record run %s: %v", result.RunID, err)
	}
}

func orEmptyStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// ListRequestFlowRuns handles GET /request-flow-builder/flow/{flow_id}/runs.
//
// Registered by whoever owns the router; harmless if it is not, because the runs table is written
// either way and the trace comes back on the replay response too. The history matters because a
// branching flow that behaved differently yesterday is the whole reason to keep a trace at all.
func ListRequestFlowRuns(flowID string, limit int) ([]FlowRunResult, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	rows, err := dbPool.Query(context.Background(), `
		SELECT id::text, request_flow_id::text, started_at, finished_at, outcome, stop_reason,
		       stop_detail, executions, requests_sent, caps, warnings, trace
		FROM request_flow_runs WHERE request_flow_id = $1
		ORDER BY started_at DESC LIMIT $2`, flowID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []FlowRunResult{}
	for rows.Next() {
		var r FlowRunResult
		var capsJSON, warningsJSON, traceJSON []byte
		if err := rows.Scan(&r.RunID, &r.FlowID, &r.Started, &r.Finished, &r.Outcome, &r.StopReason,
			&r.StopDetail, &r.Executions, &r.RequestsSent, &capsJSON, &warningsJSON, &traceJSON); err != nil {
			log.Printf("[REQUEST-FLOW] Failed to scan a run row: %v", err)
			continue
		}
		_ = json.Unmarshal(capsJSON, &r.Caps)
		_ = json.Unmarshal(warningsJSON, &r.Warnings)
		_ = json.Unmarshal(traceJSON, &r.Trace)
		out = append(out, r)
	}
	return out, rows.Err()
}
