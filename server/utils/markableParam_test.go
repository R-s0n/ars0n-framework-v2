package utils

import "testing"

// THE WRONG-COOKIE BUG, pinned across every section that had it.
//
// The parameter list is stored SORTED, so taking Parameters[0] takes the alphabetically first name.
// On a load-balanced target that is AWSALB. One line, wrong three ways: the injection marker landed
// on the load balancer's stickiness cookie, the application's own parameters were never tested, and
// corrupting that cookie broke session affinity for the rest of the run.
//
// It was found and fixed for sqlmap and ghauri, and left in place in cmdiCompose, lfiCompose,
// redirectCompose, redirectParse and redirectStore, which is how one defect survived in five more
// files. This test is per-section so a future section cannot quietly reintroduce it.
func TestTheInjectionMarkerNeverLandsOnTheLoadBalancerCookie(t *testing.T) {
	// Sorted, as the column stores it. AWSALB sorts first; category is the application's own input
	// and the only one worth injecting into.
	v := VectorInput{
		InsertionPoint: "cookie",
		Parameters:     []string{"AWSALB", "AWSALBCORS", "category", "session"},
	}
	got := markableParam(v)
	if got == "AWSALB" || got == "AWSALBCORS" {
		t.Fatalf("the marker landed on the load balancer's own cookie (%q). No application code ever "+
			"reads it, so a finding is impossible while breaking backend affinity for the rest of the "+
			"run is certain.", got)
	}
	if got == "session" {
		t.Errorf("the marker landed on the session cookie (%q). Corrupting it logs the scan out, and "+
			"every vector after that point reports clean against a login wall.", got)
	}
	if got != "category" {
		t.Errorf("expected the application's own parameter, got %q", got)
	}
}

// The ranking has to survive a vector where EVERY name is one we would rather not touch, because
// returning nothing at all would mean the vector is silently never injected.
func TestSomethingIsAlwaysChosenEvenWhenEveryOptionIsPoor(t *testing.T) {
	v := VectorInput{InsertionPoint: "cookie", Parameters: []string{"AWSALB", "AWSALBCORS"}}
	if markableParam(v) == "" {
		t.Error("with only edge cookies available one must still be chosen, or the vector is composed " +
			"with no marker and the scan tests nothing while reporting clean")
	}
	if markableParam(VectorInput{Parameters: nil}) != "" {
		t.Error("a vector with no parameters has nothing to mark and must return empty")
	}
}

// Header vectors have the same problem with a different vocabulary: the framework's own probe headers
// and the routing headers an edge adds are not application input.
func TestApplicationHeadersOutrankInfrastructureOnes(t *testing.T) {
	v := VectorInput{
		InsertionPoint: "header",
		Parameters:     []string{"Authorization", "X-Custom-Feature", "X-Forwarded-For"},
	}
	if got := markableParam(v); got != "X-Custom-Feature" {
		t.Errorf("the application's own header is the one worth injecting into, got %q", got)
	}
}
