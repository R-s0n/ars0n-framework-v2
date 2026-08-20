package utils

import (
	"time"
)

// The Miscellaneous section: Upload_Bypass, jwt_tool and pphack.
//
// They share nothing except that each is the only tool of its kind here, and each takes a different
// target: a request the operator marked as an upload, a token the framework found, and a GET vector.

var uploadBypassOptions = map[string]VectorOptionMeta{
	"endpoints": {Kind: "csv", Group: "Targets", Label: "Requests that upload a file (pick them below)"},

	// Required by the tool. Without a way to tell an accepted upload from a rejected one it cannot
	// decide anything, and it refuses to start rather than guessing.
	"extension":  {Kind: "string", Group: "Upload", Label: "Forbidden extension to try", Flag: "-E", Placeholder: "php"},
	"allowed":    {Kind: "string", Group: "Upload", Label: "Allowed extension (auto-detected if empty)", Flag: "-A", Placeholder: "jpeg"},
	"success":    {Kind: "string", Group: "Upload", Label: "Message shown on a successful upload", Flag: "-s"},
	"failure":    {Kind: "string", Group: "Upload", Label: "Message shown on a rejected upload", Flag: "-f"},
	"statusCode": {Kind: "int", Group: "Upload", Label: "Status code meaning success", Flag: "-S"},
	"uploadDir":  {Kind: "string", Group: "Upload", Label: "Where uploads land, if known", Flag: "-D", Placeholder: "/uploads"},

	"detect":      {Kind: "bool", Group: "Mode", Label: "Upload harmless sample files"},
	"exploit":     {Kind: "bool", Group: "Mode", Label: "Upload WEB SHELLS (leaves code on the target)"},
	"antiMalware": {Kind: "bool", Group: "Mode", Label: "Upload the EICAR anti-malware test file"},

	"includeOnly": {Kind: "string", Group: "Modules", Label: "Only these modules", Flag: "-i"},
	"exclude":     {Kind: "string", Group: "Modules", Label: "Exclude these modules", Flag: "-x"},

	"base64":         {Kind: "bool", Group: "Request", Label: "Base64 encode the file data", Flag: "--base64"},
	"allowRedirects": {Kind: "bool", Group: "Request", Label: "Follow redirects", Flag: "--allow_redirects"},
	"put":            {Kind: "bool", Group: "Request", Label: "Use PUT instead of POST", Flag: "-P"},
	"patch":          {Kind: "bool", Group: "Request", Label: "Use PATCH instead of POST", Flag: "-Pa"},
	"continueAll":    {Kind: "bool", Group: "Request", Label: "Keep testing after the first success", Flag: "-c"},
	"timeout":        {Kind: "int", Group: "Request", Label: "Timeout (s)", Flag: "-t", Placeholder: "8"},
	"rateLimit":      {Kind: "int", Group: "Request", Label: "Delay between requests (ms)", Flag: "-rl"},
	"insecure":       {Kind: "bool", Group: "Request", Label: "Skip TLS verification", Flag: "-k"},
	"proxy":          {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-p"},
}

var uploadBypassOwned = map[string]string{
	"-r":             "The request comes from the one you marked as an upload.",
	"--request_file": "The request comes from the one you marked as an upload.",
	"-o":             "The report path is per scan, and is how findings are read back.",
	"--output":       "The report path is per scan, and is how findings are read back.",
	"-u":             "Updating the tool mid-scan would change what is being run.",
	"--update":       "Updating the tool mid-scan would change what is being run.",
	"--burp_http":    "Points the scan at a proxy on localhost, which does not exist in this container.",
	"--burp_https":   "Points the scan at a proxy on localhost, which does not exist in this container.",
	"-l":             "Lists modules and scans nothing.",
	"--list":         "Lists modules and scans nothing.",
	"--resume":       "Each scan here is its own run.",
	"-U":             "Prints usage instructions.",
	"--usage":        "Prints usage instructions.",
}

var jwtToolOptions = map[string]VectorOptionMeta{
	// Every one of these needs a target URL. Measured: with a mode selected and no -t, jwt_tool prints
	// "No target secified (-t), cannot scan offline." and does nothing at all.
	"playbook":     {Kind: "bool", Group: "Scan", Label: "Playbook audit (-M pb, needs a target URL)"},
	"errorFuzz":    {Kind: "bool", Group: "Scan", Label: "Fuzz existing claims for errors (-M er, needs a target URL)"},
	"commonClaims": {Kind: "bool", Group: "Scan", Label: "Fuzz common claims (-M cc, needs a target URL)"},
	"allTests":     {Kind: "bool", Group: "Scan", Label: "All tests (-M at, needs a target URL)"},

	"algNone":       {Kind: "bool", Group: "Exploits", Label: "alg:none"},
	"nullSignature": {Kind: "bool", Group: "Exploits", Label: "Null signature"},
	"blankPassword": {Kind: "bool", Group: "Exploits", Label: "Blank password accepted"},
	"psychic":       {Kind: "bool", Group: "Exploits", Label: "Psychic signature (ECDSA)"},
	"injectJWKS":    {Kind: "bool", Group: "Exploits", Label: "Inject inline JWKS"},
	"spoofJWKS":     {Kind: "bool", Group: "Exploits", Label: "Spoof JWKS (needs a JWKS URL)"},
	"jwksURL":       {Kind: "string", Group: "Exploits", Label: "JWKS URL you control", Flag: "-ju"},
	"keyConfusion":  {Kind: "bool", Group: "Exploits", Label: "Key confusion (needs a public key)"},
	"publicKey":     {Kind: "path", Group: "Exploits", Label: "Public key for key confusion", Flag: "-pk"},

	"privateKey": {Kind: "path", Group: "Exploits", Label: "Private key for asymmetric signing", Flag: "-pr"},
	"jwksFile":   {Kind: "path", Group: "Exploits", Label: "JWKS file for asymmetric crypto", Flag: "-jw"},
	"verify":     {Kind: "bool", Group: "Exploits", Label: "Verify the RSA signature against the public key", Flag: "-V"},

	// -C is an argparse error without one of these three, so the composer refuses rather than letting
	// jwt_tool print its usage and exit having touched nothing.
	"crack":      {Kind: "bool", Group: "Crack", Label: "Crack the HMAC secret (needs a wordlist, password or key file)", Flag: "-C"},
	"dictionary": {Kind: "path", Group: "Crack", Label: "Wordlist", Flag: "-d"},
	"password":   {Kind: "string", Group: "Crack", Label: "Single password to try", Flag: "-p"},
	"keyfile":    {Kind: "path", Group: "Crack", Label: "Key file (for kid attacks)", Flag: "-kf"},

	"targetURL":   {Kind: "string", Group: "Request", Label: "Send forged tokens here", Flag: "-t"},
	"canaryValue": {Kind: "string", Group: "Request", Label: "Text that appears ONLY when a token is accepted", Flag: "-cv"},
	"headers":     {Kind: "string", Group: "Request", Label: "Header", Flag: "-rh", Repeatable: true},
	"cookies":     {Kind: "string", Group: "Request", Label: "Cookies", Flag: "-rc"},
	"postData":    {Kind: "string", Group: "Request", Label: "POST data to send with the forged request", Flag: "-pd"},
	"rate":        {Kind: "int", Group: "Request", Label: "Max requests per minute", Flag: "-rt"},
	"noRedirect":  {Kind: "bool", Group: "Request", Label: "Do not follow redirects", Flag: "-nr"},
}

var jwtToolOwned = map[string]string{
	// Measured: the config jwt_tool generates on first run points at a proxy on 127.0.0.1:8080, so
	// every request-sending run died with "[ERROR] ProxyError - check proxy is up" having tested
	// nothing. -np is the only control it offers, and it is always on.
	"-np":            "Always set. jwt_tool's own config sends every request through a proxy on 127.0.0.1:8080 that does not exist here, and this is the only way to disable it.",
	"--noproxy":      "Always set. jwt_tool's own config sends every request through a proxy on 127.0.0.1:8080 that does not exist here, and this is the only way to disable it.",
	"-i":             "This means 'use HTTP for the passed request', not 'skip TLS checks'. The scheme comes from the target URL instead.",
	"--insecure":     "This means 'use HTTP for the passed request', not 'skip TLS checks'. The scheme comes from the target URL instead.",
	"-r":             "The token is passed directly; there is no saved request to base one on.",
	"--request":      "The token is passed directly; there is no saved request to base one on.",
	"-Q":             "Queries an entry in jwt_tool's own log and scans nothing.",
	"--query":        "Queries an entry in jwt_tool's own log and scans nothing.",
	"-T":             "Tamper mode is INTERACTIVE: it prompts for each claim and would hang a scan forever.",
	"--tamper":       "Tamper mode is INTERACTIVE: it prompts for each claim and would hang a scan forever.",
	"-I":             "Claim injection is interactive in the same way.",
	"--injectclaims": "Claim injection is interactive in the same way.",
	"-M":             "Built from the individual scan switches.",
	"--mode":         "Built from the individual scan switches.",
	"-X":             "Built from the individual exploit switches.",
	"--exploit":      "Built from the individual exploit switches.",
	"-S":             "Signing is chosen by the exploit rather than set separately.",
	"--sign":         "Signing is chosen by the exploit rather than set separately.",
	"-b":             "Bare output drops the explanation the findings are read from.",
	"--bare":         "Bare output drops the explanation the findings are read from.",
}

var pphackOptions = map[string]VectorOptionMeta{
	"concurrency": {Kind: "int", Group: "Scan", Label: "Concurrency", Flag: "-c", Placeholder: "50"},
	"timeout":     {Kind: "int", Group: "Scan", Label: "Timeout (s)", Flag: "-t", Placeholder: "20"},
	"rateLimit":   {Kind: "int", Group: "Scan", Label: "Rate limit (per second)", Flag: "-rl"},
	"payload":     {Kind: "string", Group: "Scan", Label: "Custom payload", Flag: "-p"},
	"javascript":  {Kind: "string", Group: "Scan", Label: "Custom JavaScript to run", Flag: "-js"},
	"exploit":     {Kind: "bool", Group: "Scan", Label: "Automatic exploitation", Flag: "-e"},
	"userAgent":   {Kind: "string", Group: "Request", Label: "User-Agent", Flag: "-ua"},
	"headers":     {Kind: "string", Group: "Request", Label: "Header", Flag: "-H", Repeatable: true},
	"proxy":       {Kind: "string", Group: "Request", Label: "Proxy", Flag: "-px"},
	"verbose":     {Kind: "bool", Group: "Scan", Label: "Verbose", Flag: "-v"},
}

var pphackOwned = map[string]string{
	"-u":      "The URL comes from the GET attack vector being tested.",
	"-url":    "The URL comes from the GET attack vector being tested.",
	"-l":      "One vector per run, so a finding can be attributed to it.",
	"-list":   "One vector per run, so a finding can be attributed to it.",
	"-j":      "Findings are read from the JSON output, so the format is fixed.",
	"-json":   "Findings are read from the JSON output, so the format is fixed.",
	"-s":      "Silent mode drops the lines the findings are read from.",
	"-silent": "Silent mode drops the lines the findings are read from.",
	"-o":      "Output goes to the per-scan report path.",
}

func init() {
	registerVectorTools(
		VectorTool{
			Key: "upload-bypass", Name: "Upload_Bypass", Category: "misc",
			// Run through env, not python, because the target's scheme has to reach the tool as an
			// environment variable: it has no flag for it. See ComposeUploadBypass.
			Binary: "env", Container: "ars0n-framework-v2-upload-bypass-1",
			Groups:  []string{"Targets", "Upload", "Mode", "Modules", "Request"},
			Options: uploadBypassOptions, OwnedFlags: uploadBypassOwned,
			InsertionPoints: VectorInsertionPoints,
			RowSource:       uploadRequestRowSource,
			ScanUnit:        "request",
			UsesReportFile:  true,
			Compose:         ComposeUploadBypass,
			Parse:           parseUploadBypassOutput,
			Timeout:         30 * time.Minute,
			Limitation: "Upload_Bypass works from a request that ALREADY uploads a file successfully: " +
				"every one of its techniques is a mutation of a working upload, so pick a request you " +
				"know succeeds. It also cannot decide anything without being told how success looks, " +
				"so give it a success message, a failure message or a status code. Uploading web " +
				"shells is off unless you turn it on, because that leaves executable code on someone " +
				"else's server.",
		},
		VectorTool{
			Key: "jwt-tool", Name: "jwt_tool", Category: "misc",
			Binary: "python", Container: "ars0n-framework-v2-jwt-tool-1",
			Groups:  []string{"Scan", "Exploits", "Crack", "Request"},
			Options: jwtToolOptions, OwnedFlags: jwtToolOwned,
			InsertionPoints: VectorInsertionPoints,
			RowSource:       jwtRowSource,
			ScanUnit:        "token",
			Compose:         ComposeJWTTool,
			Parse:           parseJWTToolOutput,
			Timeout:         30 * time.Minute,
			Limitation: "The tokens are found automatically wherever this target's captured traffic " +
				"carries one, and deduplicated by token: the same token on forty endpoints is one " +
				"thing to attack. Reading a token proves nothing on its own, so the checks that " +
				"MATTER need somewhere to send the forged token: set a target URL and a canary value, " +
				"or jwt_tool can only tell you what the token says rather than whether the server " +
				"accepts a forgery. Its tamper and claim-injection modes are interactive and are not " +
				"available here.",
		},
		VectorTool{
			Key: "pphack", Name: "pphack", Category: "misc",
			Binary: "pphack", Container: "ars0n-framework-v2-pphack-1",
			Groups:  []string{"Scan", "Request"},
			Options: pphackOptions, OwnedFlags: pphackOwned,
			// GET only, and not by preference: the payload reaches the sink through the URL, so a body
			// vector is a request spent on something that cannot fire.
			InsertionPoints: []string{"query", "path"},
			RowSource:       getVectorRowSource,
			DedupeKey:       func(v VectorInput) string { return v.TargetURL() },
			ScanUnit:        "URL",
			Compose:         ComposePphack,
			Parse:           parsePphackOutput,
			// Measured on ginandjuice.shop/blog, which pphack reports as VULN from the command line:
			// 3 hits in 6 identical runs. Whether the page's own scripts have loaded and merged the
			// payload by the time it looks is a race, so one run is a coin flip and 24 vectors came
			// back clean on a target with documented client-side prototype pollution. Four attempts
			// takes a 50% detector to about 94%.
			AttemptsWhenEmpty: 4,
			SkipReason:        pphackSkipReason,
			Timeout:           20 * time.Minute,
			Limitation: "pphack loads the page in headless Chrome and watches whether the page's own " +
				"JavaScript merges attacker input into Object.prototype. That is why it only takes GET " +
				"vectors: the payload travels in the URL, and a POST body never reaches the sink. It " +
				"finds CLIENT-side pollution only; server-side prototype pollution is a different bug " +
				"with different tooling.",
		},
	)
	VectorCategories = append(VectorCategories, struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}{"misc", "Miscellaneous"})
}

func pphackSkipReason(insertionPoint string) string {
	switch insertionPoint {
	case "body", "cookie", "header":
		return "pphack pollutes through the URL, which the page's JavaScript then parses. A " +
			insertionPoint + " never reaches that sink, so scanning one would be requests spent on " +
			"something that cannot fire."
	}
	return ""
}
