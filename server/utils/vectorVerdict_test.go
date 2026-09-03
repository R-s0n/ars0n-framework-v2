package utils

import "testing"

// The whole point of the verdict is that "0 findings" is not a result on its own. These cases are the
// ones this project actually shipped and misread: a run that stopped after 8 of 53 vectors because
// the session died, and a run that rejected its own command line and exited in forty seconds. Both
// rendered as a clean scan, and both were believed.
func TestAScanThatDidNotFinishIsNeverClean(t *testing.T) {
	cases := []struct {
		name, status, scanError string
		untested                int
		want                    string
	}{
		{
			name:   "finished everything, found nothing",
			status: "completed", scanError: "", untested: 0, want: "clean",
		},
		{
			name:   "session died partway, tail marked untested",
			status: "completed",
			scanError: "UNTESTED: the scan stopped after 8 of 53 vectors because the session stopped " +
				"being honoured. Everything from here on is unknown, not clean.",
			untested: 45, want: "unverified",
		},
		{
			// The scan row is marked completed even after a session loss, because the break falls
			// through to the same UPDATE. So status alone can never be the signal.
			name:   "completed status but an error recorded",
			status: "completed", scanError: "something went wrong", untested: 0, want: "unverified",
		},
		{
			// The inverse: rows were marked untested but nothing was written to scan.error. The count
			// has to be able to carry the verdict on its own.
			name:   "untested rows with no scan-level error",
			status: "completed", scanError: "", untested: 3, want: "unverified",
		},
		{
			name:   "still going",
			status: "running", scanError: "", untested: 0, want: "running",
		},
		{
			name:   "whitespace in the error field is not an error",
			status: "completed", scanError: "   \n\t ", untested: 0, want: "clean",
		},
	}
	for _, c := range cases {
		if got := vectorScanVerdict(c.status, c.scanError, c.untested); got != c.want {
			t.Errorf("%s: got %q, want %q. A wrong verdict here is how an operator comes to believe "+
				"a target has no bugs in it.", c.name, got, c.want)
		}
	}
}

// The counterpart that keeps this honest. If every finished scan came back "unverified" the label
// would carry no information and operators would learn to ignore it, which is exactly the failure
// mode that promoting every non-zero exit to an error would have caused in the runner.
func TestACompletedScanWithNothingOutstandingIsClean(t *testing.T) {
	if got := vectorScanVerdict("completed", "", 0); got != "clean" {
		t.Errorf("a scan that finished all its work and found nothing must read clean, got %q", got)
	}
}
