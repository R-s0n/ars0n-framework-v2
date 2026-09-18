package utils

import (
	"encoding/json"
	"testing"
)

// TWO TABLES IN ONE MODAL DISAGREED ABOUT THE SAME INPUT.
//
// The vector list served reflection_probes with status and content type and nothing else. The
// client badge needs four fields to reach a grade, so with two of them missing it fell through to
// its own fail-loud defaults: an absent survived list counts as markup and an absent insertion
// point counts as deliverable, both deliberately. The result was that EVERY reflected_raw row into
// an HTML or empty content type rendered XSS High, including the rows this server had already
// graded xss_candidate_low (only a quote survived) and xss_candidate_chain (a cookie, a header or
// a body). The reflection results panel one tab over showed the server's grade for the same row.
//
// The fix is that the payload carries the grade, so the client has something to prefer and never
// derives a second opinion. These are the three shapes that used to collapse into one.
func TestVectorListProbeRowCarriesTheServersGrade(t *testing.T) {
	cases := []struct {
		name string
		row  reflectionProbeRow
		want string
	}{
		{
			name: "markup survived at an input a link reaches",
			row: reflectionProbeRow{Status: "reflected_raw", ContentType: "text/html",
				Survived: []string{"<", ">", "'"}, InsertionPoint: "query"},
			want: "xss_candidate_high",
		},
		{
			// 13 of the first 14 raw reflections on record survived only this character, because
			// JSON escapes the double quote and the backslash and nothing else.
			name: "only a quote survived, which is the response format talking",
			row: reflectionProbeRow{Status: "reflected_raw", ContentType: "text/html",
				Survived: []string{"'"}, InsertionPoint: "query"},
			want: "xss_candidate_low",
		},
		{
			name: "markup survived, but only the victim's own browser sets this input",
			row: reflectionProbeRow{Status: "reflected_raw", ContentType: "text/html",
				Survived: []string{"<"}, InsertionPoint: "cookie"},
			want: "xss_candidate_chain",
		},
		{
			name: "not knowing is not clean",
			row: reflectionProbeRow{Status: "blocked", ContentType: "", Survived: nil,
				InsertionPoint: "query"},
			want: "xss_unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.row.withGrade().Grade
			if got != tc.want {
				t.Fatalf("grade = %q, want %q", got, tc.want)
			}
			if got != XSSCandidateGrade(tc.row.Status, tc.row.ContentType, tc.row.Survived,
				tc.row.InsertionPoint) {
				t.Error("the row's grade is not the one XSSCandidateGrade computes, so this " +
					"payload is a second derivation again")
			}
		})
	}

	// THE FIELDS THE CLIENT NEEDS HAVE TO BE ON THE WIRE. grade carries no omitempty on purpose:
	// an absent key is what sent the client back to deriving its own.
	raw, err := json.Marshal(reflectionProbeRow{Status: "not_probed"}.withGrade())
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]interface{}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"grade", "survived", "insertion_point", "status"} {
		if _, ok := wire[key]; !ok {
			t.Errorf("the vector list payload has no %q, so the client has to guess it", key)
		}
	}
	if wire["grade"] != "xss_unknown" {
		t.Errorf("an unprobed row graded %v, and not knowing is not clean", wire["grade"])
	}
}
