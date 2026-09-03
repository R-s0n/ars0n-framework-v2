package utils

// nuclei is ONE runner serving TWO workflows, and this file is the whole of what the Company
// workflow needed in order to use it. No second vocabulary, no second store, no second runner.
//
// WHY THERE IS NO COMPANY NUCLEI VOCABULARY. There is exactly one nuclei scan util in the client
// (initiateNucleiScan.js), exactly one start route in main.go, exactly one handler, and exactly one
// executeNucleiScan. That runner ends with applyNucleiWildcardSettings, which calls
// wildcardRunnerSettings(scopeTargetID, "nuclei"), whose query is:
//
//	SELECT COALESCE(settings, '{}'::jsonb) FROM wildcard_tool_settings
//	WHERE scope_target_id = $1 AND tool = $2
//
// It keys on the scope target id ALONE. It never reads scope_targets.type. So a Company scope
// target's nuclei settings are already loaded and already applied, today, with no change to any
// runner. What the Company workflow was missing was a way to WRITE them, not a way to read them.
//
// COPYING nucleiWildcardOptions INTO A COMPANY FILE WOULD HAVE BEEN THE EXACT DRIFT THIS DESIGN
// EXISTS TO PREVENT. Those 43 options carry measured danger notes - -ni excludes the entire blind
// class while still reporting 6824 templates loaded, -mhe drops hosts mid-scan, -lna blocks every
// request to an internal target while the template count is unchanged, -spm reports one finding per
// host instead of all, -rsr set low sends every request and never reaches the marker - and that text
// is the most expensive thing in this project to have right in one place and wrong in another. So
// the company registry entry references the SAME MAPS by name rather than copying them, and
// TestCompanyNucleiSharesTheWildcardVocabulary asserts they are the same maps rather than equal ones.
//
// THE STORE IS SHARED TOO, AND IT HAS TO BE. If a Company target's nuclei settings were written into
// company_tool_settings, the runner would keep reading wildcard_tool_settings and find nothing, and
// the operator would have configured a scan that behaves exactly as if they had not. Company nuclei
// reads and writes wildcard_tool_settings, and every API response says so in settings_store.

// companySharedSettingsStore maps a company tool key to the table its settings actually live in,
// when that is NOT company_tool_settings.
//
// Deliberately a map rather than a boolean on the tool: the interesting fact is WHICH store, and a
// response that just said "shared" would leave a reader to guess. Empty for every other tool.
var companySharedSettingsStore = map[string]string{
	"nuclei": "wildcard_tool_settings",
}

// companySettingsTable is the table one tool's settings are read from and written to.
func companySettingsTable(toolKey string) string {
	if shared, ok := companySharedSettingsStore[toolKey]; ok {
		return shared
	}
	return "company_tool_settings"
}

// companySharedStoreNote is the sentence a caller gets when a tool's settings do not live in the
// company store. It names the store, says why, and says what the consequence would have been.
func companySharedStoreNote(toolKey string) string {
	shared, ok := companySharedSettingsStore[toolKey]
	if !ok {
		return ""
	}
	return "These settings are stored in " + shared + ", not company_tool_settings, because ONE nuclei " +
		"runner serves both workflows and it loads settings by scope target id alone without ever reading " +
		"the target's type. Writing them anywhere else would leave the runner reading an empty row, so the " +
		"scan would behave exactly as if nothing had been configured. The Wildcard Settings screen and the " +
		"MCP tool edit the same row for the same target: it is one configuration, reachable from either " +
		"workflow."
}

// The wiring claim, made HERE because this file is what makes it true.
//
// The runner-side half (applyNucleiWildcardSettings) already existed and is claimed by
// wildcardRunnerOverlay.go for the Wildcard registry. The company-side half is the routing above:
// company nuclei saves land in the row that runner reads. Without this file a company nuclei save
// would go to company_tool_settings and the claim would be false, which is why the claim lives next
// to the routing rather than in the registry file.
//
// TestCompanyWiredToolsClaimIt reads this file for the call, and TestCompanyNucleiWiringDependsOnTheWildcardOverlay
// additionally reads wildcardRunnerOverlay.go, so that if the runner-side wiring is ever removed the
// company claim fails with it rather than quietly becoming a lie.
func init() {
	markCompanyRunnerWired("nuclei")
}
