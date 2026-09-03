package utils

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The Go catalog and the MCP catalog are both generated from client/src/data/attacks.js. If someone
// edits attacks.js and does not regenerate, the dropdown offers attacks the API then refuses, which
// looks like a broken form rather than stale codegen. This runs the generator in --check mode so
// that failure surfaces here instead.
func TestAttackCatalogIsNotStale(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available; cannot verify the generated catalog is current")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	script := filepath.Join(root, "scripts", "gen-attack-catalog.mjs")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("generator not found at %s", script)
	}
	cmd := exec.Command("node", script, "--check")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("attack catalog is stale, run: node scripts/gen-attack-catalog.mjs\n%s", out)
	}
}

// Guards the invariant the API relies on when it rejects a pairing: every attack claims at least one
// STRIDE category, and every id that has categories also has a display name. A half-generated
// catalog would otherwise reject valid input with an empty "valid choices" list.
func TestAttackCatalogIsInternallyConsistent(t *testing.T) {
	if len(AttackNames) == 0 {
		t.Fatal("AttackNames is empty")
	}
	if len(AttackNames) != len(AttackCategories) {
		t.Fatalf("AttackNames has %d entries, AttackCategories has %d", len(AttackNames), len(AttackCategories))
	}
	valid := map[string]bool{
		"spoofing": true, "tampering": true, "repudiation": true,
		"information_disclosure": true, "denial_of_service": true, "elevation_of_privilege": true,
	}
	for id, cats := range AttackCategories {
		if AttackNames[id] == "" {
			t.Errorf("attack %q has categories but no name", id)
		}
		if len(cats) == 0 {
			t.Errorf("attack %q declares no STRIDE category", id)
		}
		for _, c := range cats {
			if !valid[c] {
				t.Errorf("attack %q declares unknown category %q", id, c)
			}
			if !IsValidAttackForCategory(id, c) {
				t.Errorf("IsValidAttackForCategory(%q, %q) = false, want true", id, c)
			}
		}
	}
	if IsValidAttackForCategory("", "spoofing") {
		t.Error("an empty attack id must never validate")
	}
	if IsValidAttackForCategory("not-a-real-attack", "spoofing") {
		t.Error("an unknown attack id must never validate")
	}
}

// The two generated artefacts must agree; the API validates against the Go map while the MCP tool
// builds its enum from the JSON, so a mismatch means the two write paths disagree about what is legal.
func TestGoAndMCPCatalogsAgree(t *testing.T) {
	path := filepath.Join("..", "..", "docker", "mcp-server", "src", "data", "attackCatalog.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("MCP catalog not present: %v", err)
	}
	var doc struct {
		Attacks []struct {
			ID         string   `json:"id"`
			Name       string   `json:"name"`
			Categories []string `json:"categories"`
		} `json:"attacks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing MCP catalog: %v", err)
	}
	if len(doc.Attacks) != len(AttackNames) {
		t.Fatalf("MCP catalog has %d attacks, Go has %d", len(doc.Attacks), len(AttackNames))
	}
	for _, a := range doc.Attacks {
		if AttackNames[a.ID] != a.Name {
			t.Errorf("attack %q: MCP name %q, Go name %q", a.ID, a.Name, AttackNames[a.ID])
		}
		for _, c := range a.Categories {
			if !IsValidAttackForCategory(a.ID, c) {
				t.Errorf("attack %q: MCP lists category %q, Go does not", a.ID, c)
			}
		}
	}
}

// resolveAttackChoice is the single place that decides whether a threat names a legal attack, and
// both handlers write whatever it returns. These are the cases that must never both be stored.
func TestResolveAttackChoice(t *testing.T) {
	cases := []struct {
		name       string
		id, custom string
		category   string
		wantID     string
		wantCustom string
		wantErr    bool
	}{
		{"catalogue entry valid for the category", "xss", "", "spoofing", "xss", "", false},
		{"catalogue entry wrong for the category", "xss", "", "repudiation", "", "", true},
		{"unknown catalogue id", "not-real", "", "spoofing", "", "", true},
		{"custom name only", "", "Account Enumeration", "repudiation", "", "Account Enumeration", false},
		{"custom name is trimmed", "", "  Padded  ", "repudiation", "", "Padded", false},
		{"whitespace-only custom name counts as absent", "", "   ", "spoofing", "", "", true},
		{"neither supplied", "", "", "spoofing", "", "", true},
		{"both supplied", "xss", "Something", "spoofing", "", "", true},
		{"both supplied, id invalid for category", "xss", "Something", "repudiation", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, custom, err := resolveAttackChoice(c.id, c.custom, c.category)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if err != nil {
				return
			}
			if id != c.wantID || custom != c.wantCustom {
				t.Errorf("got (%q, %q), want (%q, %q)", id, custom, c.wantID, c.wantCustom)
			}
			if id != "" && custom != "" {
				t.Error("both columns set; they are mutually exclusive")
			}
		})
	}
}

func TestResolveAttackName(t *testing.T) {
	if got := resolveAttackName("xss", ""); got != AttackNames["xss"] {
		t.Errorf("catalogue id should resolve to its catalogue name, got %q", got)
	}
	if got := resolveAttackName("", "Ad Hoc"); got != "Ad Hoc" {
		t.Errorf("custom name should be its own label, got %q", got)
	}
	if got := resolveAttackName("", ""); got != "" {
		t.Errorf("nothing named should resolve to empty, got %q", got)
	}
}
