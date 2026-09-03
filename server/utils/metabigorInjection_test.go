package utils

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A company name must never reach a shell.
//
// PROVEN VULNERABILITY, fixed here, guarded by this test. Every metabigor runner built a shell string
// and ran it through sh -c:
//
//	fmt.Sprintf("echo '%s' | /usr/bin/docker exec -i <container> %s", name, args)
//
// with the company name interpolated raw inside single quotes. Measured with a benign marker before
// the fix:
//
//	"Cloudflare"                -> "Cloudflare"
//	"O'Reilly"                  -> sh: -c: line 0: unexpected EOF while looking for matching '
//	"x'; echo INJECTED; echo '" -> "x\nINJECTED"    <- arbitrary command execution
//
// The sink is reachable from the Add Target form and from the MCP add_target tool, and the api
// container mounts /var/run/docker.sock, so this was a route from a text field to the host's Docker
// daemon. It also broke outright on any genuine name containing an apostrophe, which is why it read
// as a quoting bug for so long.
//
// This test reads the source rather than calling the function, because the property being defended
// is structural: there must be no shell to inject into.
func TestMetabigorNeverBuildsAShellCommand(t *testing.T) {
	src, err := os.ReadFile("metabigorCompanyUtils.go")
	if err != nil {
		t.Fatalf("cannot read metabigorCompanyUtils.go: %v", err)
	}

	for i, line := range strings.Split(string(src), "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "//") {
			continue // the doc comment quotes the old bug on purpose
		}
		for _, shell := range []string{`exec.Command("sh"`, `exec.Command("bash"`, `exec.Command("/bin/sh"`} {
			if strings.Contains(code, shell) {
				t.Errorf("metabigorCompanyUtils.go:%d runs a shell: %s\n"+
					"A company name reaches this. Use metabigorStdin, which passes argv and puts the "+
					"subject on stdin, so there is no shell to break out of.", i+1, code)
			}
		}
	}
}

// The counterpart: the subject must not be interpolated into any string that is later executed.
// Escaping is not the fix and must not creep back in, because escaping keeps the shell.
func TestMetabigorSubjectIsNotInterpolatedIntoACommand(t *testing.T) {
	src, err := os.ReadFile("metabigorCompanyUtils.go")
	if err != nil {
		t.Fatalf("cannot read metabigorCompanyUtils.go: %v", err)
	}

	// `echo '%s'` is the exact shape that was vulnerable.
	bad := regexp.MustCompile(`echo\s+'%s'`)
	for i, line := range strings.Split(string(src), "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "//") {
			continue
		}
		if bad.MatchString(code) {
			t.Errorf("metabigorCompanyUtils.go:%d interpolates a value inside shell single quotes: %s\n"+
				"One apostrophe in the value closes the quote and the rest is shell.", i+1, code)
		}
	}
}

// metabigorStdin must put the subject on stdin and keep it out of argv entirely, so that no value a
// user can type is ever parsed as an argument or an option.
func TestMetabigorStdinKeepsTheSubjectOutOfArgv(t *testing.T) {
	for _, subject := range []string{
		"Cloudflare",
		"O'Reilly",                  // a real name that used to crash the scan
		"x'; echo INJECTED; echo '", // the proven payload
		"--org",                     // a value that looks like a flag
		"$(id)", "`id`", "a\nb",     // substitution and a newline
	} {
		cmd := metabigorStdinCommandForTest(subject, "metabigor", "net", "--org", "-v")

		for _, arg := range cmd.Args {
			if strings.Contains(arg, subject) && subject != "--org" {
				t.Errorf("subject %q leaked into argv: %v", subject, cmd.Args)
			}
		}
		if cmd.Stdin == nil {
			t.Errorf("subject %q was not placed on stdin", subject)
		}
		if got := cmd.Path; strings.Contains(got, "sh") && !strings.Contains(got, "docker") {
			t.Errorf("subject %q is being run through %q rather than docker", subject, got)
		}
	}
}
