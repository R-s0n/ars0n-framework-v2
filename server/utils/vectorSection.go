package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// Settings that belong to a SECTION rather than to one tool.
//
// The open redirect and SSRF section needs a webhook, and both of its working tools need the same
// one: REcollapse builds its payloads out of it, and the scanner asks it afterwards whether anything
// arrived. Storing that per tool would mean entering it twice and having the two copies disagree.

// VectorSectionField is one setting on the section, typed so the modal is generated rather than
// written, exactly like the per-tool vocabulary.
type VectorSectionField struct {
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Help        string `json:"help,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// VectorSectionFields is the vocabulary, per category. Only the sections that need one appear.
var VectorSectionFields = map[string][]struct {
	Key   string             `json:"key"`
	Field VectorSectionField `json:"field"`
}{
	"redirect-ssrf": {
		{"listeningWebhookURL", VectorSectionField{
			Kind:  "string",
			Label: "Listening Webhook URL",
			Placeholder: "https://webhook.site/8f3c...",
			Help: "The URL the payloads point at. A server-side request forgery is proved by the " +
				"target making a request to somewhere you control, so this has to be reachable from " +
				"the internet rather than from your own machine.",
			Required: true,
		}},
		{"resultsWebhookURL", VectorSectionField{
			Kind:  "string",
			Label: "Webhook Results URL",
			Placeholder: "https://webhook.site/token/8f3c.../requests",
			Help: "The URL the framework READS to find out whether the listening URL was called. For " +
				"webhook.site this is the token requests endpoint; anything returning the received " +
				"requests as text or JSON works, because the check is whether the run's token appears " +
				"in what it returns.",
			Required: true,
		}},
		{"resultsAuthHeader", VectorSectionField{
			Kind:  "string",
			Label: "Results auth header",
			Placeholder: "Api-Key: abc123",
			Help:        "Sent when reading the results URL, if that service needs one. Optional.",
		}},
	},
}

// loadVectorSectionSettings returns a section's settings. Absent is not an error: a section that has
// never been configured simply has no webhook, and the tools that need one report that rather than
// running without it.
func loadVectorSectionSettings(ctx context.Context, scopeTargetID, category string) map[string]any {
	var raw []byte
	err := dbPool.QueryRow(ctx, `
		SELECT COALESCE(settings, '{}'::jsonb) FROM vector_section_settings
		WHERE scope_target_id = $1 AND category = $2`, scopeTargetID, category).Scan(&raw)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// GetVectorSectionSettings answers GET /{category}/{scope_target_id}/section-settings.
func GetVectorSectionSettings(category string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scopeTargetID := mux.Vars(r)["scope_target_id"]
		settings := loadVectorSectionSettings(context.Background(), scopeTargetID, category)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"category": category,
			"settings": settings,
			"fields":   VectorSectionFields[category],
			"configured": sectionWebhookConfigured(settings),
			"note": "These belong to the section, so every tool in it reads the same pair. The same " +
				"store is what manage_redirect reads and writes.",
		})
	}
}

// SaveVectorSectionSettings answers POST /{category}/{scope_target_id}/section-settings.
func SaveVectorSectionSettings(category string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scopeTargetID := mux.Vars(r)["scope_target_id"]

		var req struct {
			Settings map[string]any `json:"settings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
			return
		}
		if req.Settings == nil {
			req.Settings = map[string]any{}
		}

		// Validated before it is stored, because a webhook that is not a URL fails silently later: the
		// payloads go out pointing at nothing and the results check finds nothing, which is
		// indistinguishable from a target that simply did not call out.
		if problems := validateSectionWebhook(req.Settings); len(problems) > 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid_webhook", strings.Join(problems, " "))
			return
		}

		encoded, err := json.Marshal(req.Settings)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_settings", err.Error())
			return
		}
		if _, err := dbPool.Exec(context.Background(), `
			INSERT INTO vector_section_settings (scope_target_id, category, settings, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (scope_target_id, category)
			DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
			scopeTargetID, category, encoded); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"saved":      true,
			"settings":   req.Settings,
			"configured": sectionWebhookConfigured(req.Settings),
		})
	}
}

// validateSectionWebhook rejects what cannot work, with the reason.
func validateSectionWebhook(settings map[string]any) []string {
	var problems []string
	listening := strings.TrimSpace(stringifySetting(settings["listeningWebhookURL"]))
	results := strings.TrimSpace(stringifySetting(settings["resultsWebhookURL"]))

	for label, value := range map[string]string{
		"The listening webhook URL": listening,
		"The webhook results URL":   results,
	} {
		if value == "" {
			continue
		}
		if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			problems = append(problems, label+" has to start with http:// or https://.")
		}
	}

	// A listening URL on localhost is the mistake worth catching: the request that proves an SSRF is
	// made BY THE TARGET, so it has to reach a host on the internet. Pointed at 127.0.0.1 the scan
	// runs, nothing arrives, and the result reads as "no SSRF found".
	for _, local := range []string{"127.0.0.1", "localhost", "0.0.0.0", "::1"} {
		if strings.Contains(listening, local) {
			problems = append(problems, "The listening webhook URL points at "+local+
				". The request that proves an SSRF is made by the TARGET, so it has to reach something "+
				"on the internet; a local address would simply never be called and the scan would "+
				"report nothing found.")
			break
		}
	}
	return problems
}

// sectionWebhookConfigured reports whether both halves are present. The card and the eligibility
// report both key on this, because a tool that needs a webhook and has none should say so rather
// than run.
func sectionWebhookConfigured(settings map[string]any) bool {
	return strings.TrimSpace(stringifySetting(settings["listeningWebhookURL"])) != "" &&
		strings.TrimSpace(stringifySetting(settings["resultsWebhookURL"])) != ""
}
