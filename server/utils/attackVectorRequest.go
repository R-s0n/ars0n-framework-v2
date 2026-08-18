package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// The request a vector describes, with the user-controlled parts marked.
//
// A row of verb, host, path and parameter names is a description of a request rather than a request.
// What an operator does next is send one, and to do that they need the bytes: the request line, the
// Host, whatever container the parameters live in, and above all WHICH SPANS they control. That last
// part is the whole point of the view and the one thing a table cannot show.
//
// Returned as PARTS rather than as a string with markers in it, the same way the fuzz finding detail
// does. A parameter name containing a quote or an angle bracket cannot then break the rendering or be
// mistaken for framework text, because the client never parses the request at all: it renders spans
// it was handed.

// vectorRequestPart is one span. Input marks the spans the user controls, which are the spans an
// operator is going to put a payload in.
type vectorRequestPart struct {
	Text  string `json:"text"`
	Input bool   `json:"input,omitempty"`
	Param string `json:"param,omitempty"`
}

// attackVectorSlot is what stands in for a value nobody recorded. It reads as a slot rather than as
// data, which is what it is: the framework knows the parameter is there and does not know what was
// sent in it.
const attackVectorSlot = "FUZZ"

// GetAttackVectorRequest answers GET /attack-vectors/item/{id}/request.
func GetAttackVectorRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_id", "That is not a vector id.")
		return
	}

	var v attackVector
	var rawRequest, evidenceURL string
	var port *int
	if dbPool.QueryRow(context.Background(), `
		SELECT method, scheme, domain, port, path, insertion_point, parameters,
		       COALESCE(raw_request,''), COALESCE(evidence_url,'')
		FROM attack_vectors WHERE id = $1`, id).
		Scan(&v.Method, &v.Scheme, &v.Domain, &port, &v.Path, &v.InsertionPoint, &v.Parameters,
			&rawRequest, &evidenceURL) != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "No such attack vector.")
		return
	}
	if port != nil {
		v.Port = *port
	}

	var parts []vectorRequestPart
	note := ""
	captured := strings.TrimSpace(rawRequest) != ""
	if captured {
		// Real bytes beat a reconstruction, so they are used whenever a run recorded them. The
		// parameter spans are then FOUND in those bytes rather than built into them.
		parts = markInputSpans(rawRequest, v.Parameters, v.InsertionPoint)
		note = "These are the bytes the framework recorded for this vector. The marked spans are the " +
			"parameters it believes the application reads."
	} else {
		parts = buildVectorRequest(v)
		note = fmt.Sprintf(
			"No request was recorded for this vector, so this one is reconstructed from what is known "+
				"about it: the verb, the host, the path and the parameters. %s stands where a value "+
				"would go, because the framework knows the parameter is read and not what was sent in it.",
			attackVectorSlot)
	}

	raw := strings.Builder{}
	for _, p := range parts {
		raw.WriteString(p.Text)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": id, "parts": parts, "raw": raw.String(),
		"reconstructed": !captured, "note": note,
		"evidence_url":    evidenceURL,
		"insertion_point": v.InsertionPoint,
		"parameters":      v.Parameters,
	})
}

// buildVectorRequest renders the request a vector describes, marking the spans as it writes them.
//
// Building the marks WHILE building the text, rather than searching for them afterwards, means the
// two can never disagree: a parameter called "Host" or one containing a quote is marked exactly where
// it was written and nowhere else.
func buildVectorRequest(v attackVector) []vectorRequestPart {
	var parts []vectorRequestPart
	add := func(text string) { parts = append(parts, vectorRequestPart{Text: text}) }
	addInput := func(text, param string) {
		parts = append(parts, vectorRequestPart{Text: text, Input: true, Param: param})
	}

	host := v.Domain
	if v.Port > 0 {
		host = fmt.Sprintf("%s:%d", v.Domain, v.Port)
	}
	method := strings.ToUpper(v.Method)
	if method == "" {
		method = "GET"
	}

	// --- request line -----------------------------------------------------------------------
	add(method + " ")
	switch v.InsertionPoint {
	case "path":
		// The value IS the path, so the marked span is the last segment of it: that is the thing an
		// operator replaces, and marking the whole path would say the host prefix is theirs too.
		dir, last := splitLastSegment(v.Path)
		add(dir)
		if last != "" {
			addInput(last, "")
		} else {
			addInput(attackVectorSlot, "")
		}
	case "query":
		add(v.Path)
		add("?")
		for i, name := range v.Parameters {
			if i > 0 {
				add("&")
			}
			addInput(name+"="+attackVectorSlot, name)
		}
	default:
		add(v.Path)
	}
	add(" HTTP/1.1\n")

	// --- headers ----------------------------------------------------------------------------
	add("Host: " + host + "\n")
	switch v.InsertionPoint {
	case "header":
		for _, name := range v.Parameters {
			addInput(name+": "+attackVectorSlot, name)
			add("\n")
		}
	case "cookie":
		add("Cookie: ")
		for i, name := range v.Parameters {
			if i > 0 {
				add("; ")
			}
			addInput(name+"="+attackVectorSlot, name)
		}
		add("\n")
	case "body":
		add("Content-Type: application/json\n")
	}

	// --- body -------------------------------------------------------------------------------
	if v.InsertionPoint == "body" {
		add("\n{")
		for i, name := range v.Parameters {
			if i > 0 {
				add(",")
			}
			add("\"")
			addInput(name, name)
			add("\":\"")
			addInput(attackVectorSlot, name)
			add("\"")
		}
		add("}")
	} else {
		add("\n")
	}
	return parts
}

// markInputSpans finds each parameter inside bytes the framework did not compose, and marks the span
// it occupies.
//
// Conservative on purpose. A name that cannot be located is simply not marked: a request shown with
// one span missing is a smaller failure than a request with a span marked in the wrong place, which
// would tell an operator they control something they do not.
func markInputSpans(raw string, names []string, insertionPoint string) []vectorRequestPart {
	type span struct {
		start, end int
		param      string
	}
	var spans []span

	claimed := func(start, end int) bool {
		for _, s := range spans {
			if start < s.end && s.start < end {
				return true
			}
		}
		return false
	}

	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		// Each of the forms a parameter takes on the wire, tried in order of how specific they are.
		for _, form := range []string{
			"\"" + name + "\":", // JSON key
			name + "=",          // query string, form body, cookie
			name + ": ",         // header
		} {
			at := strings.Index(raw, form)
			if at < 0 {
				continue
			}
			end := at + len(form)
			// Extend over the value, up to whatever ends it in this container.
			stop := strings.IndexAny(raw[end:], "&;,}\n\r")
			if strings.HasPrefix(form, "\"") {
				// A JSON value runs to its closing quote rather than to a delimiter.
				if q := strings.Index(raw[end+1:], "\""); q >= 0 {
					stop = q + 2
				}
			}
			if stop < 0 {
				stop = len(raw) - end
			}
			if !claimed(at, end+stop) {
				spans = append(spans, span{at, end + stop, name})
			}
			break
		}
	}

	// A path vector has no parameter to find, so the last segment of the request target is the span.
	if insertionPoint == "path" && len(spans) == 0 {
		if nl := strings.IndexAny(raw, "\r\n"); nl > 0 {
			line := raw[:nl]
			if fields := strings.Fields(line); len(fields) >= 2 {
				target := fields[1]
				if at := strings.Index(raw, target); at >= 0 {
					dir, last := splitLastSegment(target)
					if last != "" {
						spans = append(spans, span{at + len(dir), at + len(target), ""})
					}
				}
			}
		}
	}

	// Sorted so the text can be walked once, and so two spans can never be emitted out of order.
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j].start < spans[j-1].start; j-- {
			spans[j], spans[j-1] = spans[j-1], spans[j]
		}
	}

	var parts []vectorRequestPart
	at := 0
	for _, s := range spans {
		if s.start > at {
			parts = append(parts, vectorRequestPart{Text: raw[at:s.start]})
		}
		if s.end > len(raw) {
			s.end = len(raw)
		}
		parts = append(parts, vectorRequestPart{Text: raw[s.start:s.end], Input: true, Param: s.param})
		at = s.end
	}
	if at < len(raw) {
		parts = append(parts, vectorRequestPart{Text: raw[at:]})
	}
	return parts
}

// splitLastSegment cuts a path into everything up to the final slash, and the segment after it.
func splitLastSegment(path string) (dir, last string) {
	if path == "" {
		return "/", ""
	}
	if at := strings.LastIndex(path, "/"); at >= 0 {
		return path[:at+1], path[at+1:]
	}
	return "", path
}
