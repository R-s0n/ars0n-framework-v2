package utils

import (
	"strings"
	"testing"
)

// FIX 1: SEVERITY IS EXECUTION AND DELIVERY.
//
// The contradiction this guards: vectorExplain.go's SeverityNote strings reason only about whether
// something EXECUTED, so an XSS that runs in a cookie the victim sets on themselves walked to high
// while the MCP guidance layer (docker/mcp-server/src/guidance/scanning.js, manage_xss.rule) called
// the same row not_enough_info. Two screens, opposite answers about one row.
func TestFindingDeliveryNote(t *testing.T) {
	cases := []struct {
		name     string
		tool     string
		point    string
		wantNote bool
	}{
		// The rule's own words: a query, path or fragment vector stays deliverable whatever its grade.
		{"xss query is deliverable", "dalfox", "query", false},
		{"xss path is deliverable", "dalfox", "path", false},
		{"xss fragment is deliverable", "domdig", "fragment", false},
		// Set by the browser the victim already has, so self-XSS until a chain is named.
		{"xss cookie needs a chain", "dalfox", "cookie", true},
		{"xss header needs a chain", "dalfox", "header", true},
		{"xss body needs a chain", "xssfuzz", "body", true},
		{"case and space do not matter", "DalFox", "  Cookie ", true},
		// Client-side prototype pollution needs a victim too.
		{"pphack cookie needs a chain", "pphack", "cookie", true},
		// Server side: the ATTACKER sends the request, so there is no delivery problem at all.
		{"sqlmap cookie is the attacker's own request", "sqlmap", "cookie", false},
		{"ghauri header is the attacker's own request", "ghauri", "header", false},
		{"nomore403 cookie is the attacker's own request", "nomore403", "cookie", false},
		// An unknown point must not be demoted out of sight, matching ReflectionInsertionPointDeliverable.
		{"unknown point stays visible", "dalfox", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			note := FindingDeliveryNote(tc.tool, tc.point)
			if (note != "") != tc.wantNote {
				t.Fatalf("FindingDeliveryNote(%q, %q) = %q, want note: %v",
					tc.tool, tc.point, note, tc.wantNote)
			}
			if tc.wantNote && !strings.Contains(note, "self-XSS") {
				t.Fatalf("the gate does not say what it is refusing: %q", note)
			}
			if tc.wantNote && !strings.Contains(note, "chain") {
				t.Fatalf("the gate does not name the way out: %q", note)
			}
		})
	}
}

// THE TWO MUST DIFFER, which is the whole point: the same execution at two insertion points is two
// different pieces of news.
func TestExplainFindingForVectorGatesOnDelivery(t *testing.T) {
	query := ExplainFindingForVector("dalfox", "V", "query")
	cookie := ExplainFindingForVector("dalfox", "V", "cookie")

	if query.SeverityNote == cookie.SeverityNote {
		t.Fatalf("a query vector and a cookie vector got the SAME severity note, so the "+
			"explanation layer is still reasoning about execution alone: %q", query.SeverityNote)
	}
	// The query row is the ungated one and must be byte-identical to the stored note.
	if query.SeverityNote != ExplainFinding("dalfox", "V").SeverityNote {
		t.Fatalf("a deliverable point changed the note, so the gate fires on every row and says "+
			"nothing: %q", query.SeverityNote)
	}
	// Substance kept: the execution half is still there, the delivery half is added.
	if !strings.Contains(cookie.SeverityNote, "browser confirms execution") {
		t.Fatalf("the existing note's substance was lost: %q", cookie.SeverityNote)
	}
	if !strings.Contains(cookie.SeverityNote, "self-XSS") {
		t.Fatalf("the cookie note does not gate on delivery: %q", cookie.SeverityNote)
	}
	// Server side is untouched at every point.
	for _, point := range []string{"query", "cookie", "header", "body"} {
		if got := ExplainFindingForVector("sqlmap", "UNION query", point).SeverityNote; got !=
			ExplainFinding("sqlmap", "UNION query").SeverityNote {
			t.Fatalf("sqlmap at %q was gated on delivery, but the attacker sends that request "+
				"themselves: %q", point, got)
		}
	}
}

// ONE LIST, NOT TWO. The gate must agree with ReflectionInsertionPointDeliverable and with the grade
// derived from it, because two lists is how the content type rule diverged across three layers.
func TestDeliveryGateAgreesWithTheProbeGrade(t *testing.T) {
	for _, point := range ReflectionProbedPoints() {
		gated := FindingDeliveryNote("dalfox", point) != ""
		if gated == ReflectionInsertionPointDeliverable(point) {
			t.Fatalf("point %q: the explanation gate and ReflectionInsertionPointDeliverable "+
				"disagree", point)
		}
		grade := XSSCandidateGrade(ReflectionRaw, "text/html", []string{"<", ">"}, point)
		wantChain := grade == XSSCandidateChain
		if gated != wantChain {
			t.Fatalf("point %q: gate=%v but XSSCandidateGrade says %q", point, gated, grade)
		}
	}
}

// THE CHAIN NAMED MUST BE A CHAIN THAT REACHES THAT POINT.
//
// The first version of the gate handed every non-deliverable point the same three chains, so a
// BODY vector was told to demonstrate "CRLF into Set-Cookie, a cookie write from a sibling
// subdomain, a cache poison". None of those reaches a body, and the same sentence claimed the
// victim's browser "sets" a body value, which it does not. dalfox reaches body, so that wrong
// sentence was reachable in production rather than hypothetical.
//
// ReflectionInsertionPointDeliverable's own comment already carried the right answer for body: a
// cross-site form POST to a form-encoded endpoint with no CSRF token is a real chain and a named
// one, but a chain rather than a link.
func TestTheGateNamesAChainThatReachesThePoint(t *testing.T) {
	cookieish := []string{"cookie", "header"}
	for _, point := range cookieish {
		note := FindingDeliveryNote("dalfox", point)
		if !strings.Contains(note, "Set-Cookie") {
			t.Errorf("%s gate does not name a cookie chain: %q", point, note)
		}
		if strings.Contains(note, "form POST") {
			t.Errorf("%s gate names a form POST, which is the body chain: %q", point, note)
		}
	}

	body := FindingDeliveryNote("dalfox", "body")
	if !strings.Contains(body, "form POST") || !strings.Contains(body, "CSRF") {
		t.Errorf("the body gate does not name the chain that actually reaches a body: %q", body)
	}
	if strings.Contains(body, "Set-Cookie") || strings.Contains(body, "sibling subdomain") {
		t.Errorf("the body gate still names cookie chains that cannot reach a body: %q", body)
	}
	// It must still say what it is refusing, or the operator gets a rule with no verdict.
	if !strings.Contains(body, "self-XSS") {
		t.Errorf("the body gate does not name the verdict: %q", body)
	}

	// And a deliverable point is never gated, whatever the tool.
	for _, point := range []string{"query", "path", "fragment"} {
		if note := FindingDeliveryNote("dalfox", point); note != "" {
			t.Errorf("%s is attacker-deliverable and must not be gated: %q", point, note)
		}
	}
}
