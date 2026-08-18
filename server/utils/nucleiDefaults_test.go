package utils

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The default is a deliberate choice, so it is pinned. Anything that widens it back out to every
// category or reintroduces informational severity should have to change this test on purpose.
func TestNucleiDefaultsAreTheChosenSubset(t *testing.T) {
	wantTemplates := []string{"cves", "vulnerabilities", "exposures", "misconfiguration", "takeovers"}
	wantSeverities := []string{"critical", "high", "medium", "low"}

	if strings.Join(DefaultNucleiTemplates, ",") != strings.Join(wantTemplates, ",") {
		t.Errorf("templates = %v, want %v", DefaultNucleiTemplates, wantTemplates)
	}
	if strings.Join(DefaultNucleiSeverities, ",") != strings.Join(wantSeverities, ",") {
		t.Errorf("severities = %v, want %v", DefaultNucleiSeverities, wantSeverities)
	}

	// Named individually so a failure says which one came back rather than just that the set differs.
	for _, off := range []string{"network", "dns", "technologies", "headless"} {
		for _, on := range DefaultNucleiTemplates {
			if on == off {
				t.Errorf("%q is enabled by default but was deliberately turned off", off)
			}
		}
	}
	for _, sev := range DefaultNucleiSeverities {
		if sev == "info" || sev == "informational" {
			t.Error("informational severity is enabled by default but was deliberately turned off")
		}
	}
}

// The client keeps its own copy because it cannot import Go. That copy has to agree, or the default
// depends on whether a config was created through the UI or the API.
func TestClientDefaultsMatchTheServer(t *testing.T) {
	const clientFile = "../../client/src/utils/nucleiDefaults.js"

	src, err := os.ReadFile(clientFile)
	if err != nil {
		t.Skipf("client defaults not readable from here: %v", err)
	}

	parse := func(name string) []string {
		re := regexp.MustCompile(`(?s)export const ` + name + ` = \[(.*?)\]`)
		m := re.FindSubmatch(src)
		if m == nil {
			t.Fatalf("could not find %s in %s", name, clientFile)
		}
		var out []string
		for _, item := range regexp.MustCompile(`'([a-z]+)'`).FindAllStringSubmatch(string(m[1]), -1) {
			out = append(out, item[1])
		}
		return out
	}

	if got := parse("DEFAULT_NUCLEI_TEMPLATES"); strings.Join(got, ",") != strings.Join(DefaultNucleiTemplates, ",") {
		t.Errorf("client templates %v do not match server %v", got, DefaultNucleiTemplates)
	}
	if got := parse("DEFAULT_NUCLEI_SEVERITIES"); strings.Join(got, ",") != strings.Join(DefaultNucleiSeverities, ",") {
		t.Errorf("client severities %v do not match server %v", got, DefaultNucleiSeverities)
	}
}

// The DDL default is built from the Go values, so this guards the rendering rather than the list.
func TestPostgresArrayLiteral(t *testing.T) {
	if got := PostgresArrayLiteral(DefaultNucleiTemplates); got != "'{cves,vulnerabilities,exposures,misconfiguration,takeovers}'" {
		t.Errorf("templates literal = %s", got)
	}
	if got := PostgresArrayLiteral(DefaultNucleiSeverities); got != "'{critical,high,medium,low}'" {
		t.Errorf("severities literal = %s", got)
	}
	if got := PostgresArrayLiteral(nil); got != "'{}'" {
		t.Errorf("empty literal = %s, want '{}'", got)
	}
}

// Every default has to be a category the modal actually offers, or it selects a checkbox that does
// not exist and the operator cannot see or change it.
func TestDefaultsAreAllSelectableInTheModal(t *testing.T) {
	src, err := os.ReadFile("../../client/src/modals/NucleiConfigModal.js")
	if err != nil {
		t.Skipf("modal not readable from here: %v", err)
	}
	body := string(src)

	for _, key := range DefaultNucleiTemplates {
		if !strings.Contains(body, "key: '"+key+"'") {
			t.Errorf("default template %q has no entry in templateCategories", key)
		}
	}
	for _, key := range DefaultNucleiSeverities {
		if !strings.Contains(body, "key: '"+key+"'") {
			t.Errorf("default severity %q has no entry in severityCategories", key)
		}
	}
}
