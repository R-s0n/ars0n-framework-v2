package utils

import (
	"strings"
	"testing"
)

// The unsigned javascript template measured against nuclei v3.11.1. On its own nuclei exits 1 with
// "no templates provided for scan"; next to an http template it is dropped with no output unless -v
// is set, and the scan exits 0. Either way the operator must be told.
const measuredUnsignedJSTemplate = `id: r2-js-unsigned
info:
  name: r2 js unsigned
  author: r2
  severity: info
javascript:
  - code: |
      let a = 1;
      a == 1;
    args:
      Host: "{{Host}}"
    matchers:
      - type: dsl
        dsl:
          - "success == true"
`

const measuredHTTPTemplate = `id: r2-http-probe
info:
  name: r2 http probe
  author: r2
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`

func TestUnsignedJavascriptTemplateUploadIsNotSilent(t *testing.T) {
	for name, content := range map[string]string{
		"as measured": measuredUnsignedJSTemplate,
		"crlf upload": strings.ReplaceAll(measuredUnsignedJSTemplate, "\n", "\r\n"),
	} {
		note := nucleiUnsignedJSTemplateNote(content, "probe.yaml")
		if !strings.HasPrefix(note, "skipped: unsigned") || !strings.Contains(note, "probe.yaml") {
			t.Errorf("%s: an unsigned javascript template nuclei will refuse must produce a note naming it, got %q", name, note)
		}
	}
}

func TestTemplatesNucleiRunsProduceNoNote(t *testing.T) {
	signed := measuredUnsignedJSTemplate + "# digest: 4a0a00473045022100f1e2:0123456789abcdef\n"
	for name, content := range map[string]string{
		"signed javascript": signed,
		"http only":         measuredHTTPTemplate,
		"empty":             "",
	} {
		if note := nucleiUnsignedJSTemplateNote(content, "t.yaml"); note != "" {
			t.Errorf("%s: a template nuclei runs must not be reported as skipped, got %q", name, note)
		}
	}
}
