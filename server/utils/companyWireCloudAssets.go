package utils

import (
	"fmt"
	"strconv"
	"strings"
)

// Wiring the Cloud Asset Enumeration phase: amass enum (company), dnsx, cloud_enum and katana.
//
// ALL FOUR HAVE A REAL COMMAND LINE, so all four go through the shared overlay and the whole of this
// file is base command lines, flag arities and the handful of framework-level switches that carry no
// flag. There is no second composer anywhere in it.
//
// THE DEFAULT MUST NOT CHANGE. Each builder's zero-settings argv is token for token what the runner
// built inline, including amass's eighteen hardcoded resolvers in their original order, dnsx's eight
// record-type flags, cloud_enum's entire config-modal-driven command, and katana's `-p 20` that has
// nothing to parallelise.

// ---------------------------------------------------------------------------------------------
// amass_enum_company  (step 9)
// ---------------------------------------------------------------------------------------------

// amassEnumCompanyResolvers is the eighteen-resolver pool the company amass runner has always passed,
// in the order it has always passed it.
//
// A variable only so the builder and its nothing-changed test can refer to the same list. THE ORDER
// IS PART OF THE BYTE-IDENTICAL GUARANTEE and must not be sorted or deduplicated. Note this is 18,
// two fewer than the Wildcard runner's 20: the company list has no AdGuard pair.
var amassEnumCompanyResolvers = []string{
	"8.8.8.8", "8.8.4.4", // Google
	"1.1.1.1", "1.0.0.1", // Cloudflare
	"9.9.9.9", "149.112.112.112", // Quad9
	"64.6.64.6", "64.6.65.6", // Verisign
	"208.67.222.222", "208.67.220.220", // OpenDNS
	"76.76.19.19", "76.223.100.101", // Alternate DNS
	"8.26.56.26", "8.20.247.20", // Comodo Secure DNS
	"185.228.168.9", "185.228.169.9", // CleanBrowsing
	"77.88.8.8", "77.88.8.1", // Yandex DNS
}

// amassEnumCompanyBaseArity is the arity of the flags the RUNNER hardcodes.
var amassEnumCompanyBaseArity = map[string]int{
	"-passive":           0,
	"-alts":              0,
	"-brute":             0,
	"-nocolor":           0,
	"-min-for-recursive": 1,
	"-timeout":           1,
	"-d":                 1,
	"-r":                 1,
	"-rqps":              1,
}

// amassEnumCompanyCommandArgs builds the argv passed to exec.Command for ONE domain of a Company
// amass enum scan.
//
// With no stored settings this is token for token the command ExecuteAmassEnumCompanyScan built
// inline, including:
//
//   - `-passive`, which v4.2.0's own help calls "Deprecated since passive is the default setting" and
//     which is therefore a no-op the runner emits. It is framework-owned rather than exposed, because
//     the meaningful control is activeMode - and passing -active ALONGSIDE the existing -passive was
//     verified to exit 0 with MORE results (22 lines against 18), so turning activeMode on is safe
//     even though the runner keeps emitting -passive;
//   - `-timeout 300`, which is FIVE HOURS PER DOMAIN, in a loop over every selected domain with no
//     aggregate cap and no context deadline.
//
// RATE LIMIT PRECEDENCE, DECIDED AND VISIBLE, AND IT IS THE SAME RULE AS THE WILDCARD REGISTRY'S:
// the per-target resolverQPS WINS over the global user_settings.amass_rate_limit. The global stays
// the value for every target nobody has configured, so it remains a real default rather than becoming
// dead; when a target sets resolverQPS the base -rqps is REPLACED IN PLACE rather than appended
// beside, so the stored command shows one value for one flag.
func amassEnumCompanyCommandArgs(domain string, rateLimit int, tool CompanyTool,
	settings map[string]any) ([]string, []string) {
	base := []string{
		"docker", "run", "--rm",
		"caffix/amass",
		"enum", "-passive", "-alts", "-brute", "-nocolor",
		"-min-for-recursive", "2", "-timeout", "300",
		"-d", domain,
	}
	for _, resolver := range amassEnumCompanyResolvers {
		base = append(base, "-r", resolver)
	}
	base = append(base, "-rqps", strconv.Itoa(rateLimit))

	overlay := companyOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: amassEnumCompanyBaseArity,
	}
	args, notes := overlay.apply(base)

	if companySettingIsSet(settings, "timeoutMinutes") {
		notes = append(notes, "timeoutMinutes is PER DOMAIN. ExecuteAmassEnumCompanyScan loops over every "+
			"selected domain sequentially with no aggregate deadline and no context, so the worst case for "+
			"the whole scan is this value times the number of selected domains.")
	}
	if companySettingIsSet(settings, "blacklistNames") {
		notes = append(notes, "blacklistNames uses -bl, which is the ONLY filter flag that works on this build "+
			"(-exclude and -include were verified to parse and do nothing). Blacklisting a name that is a "+
			"selected domain or a parent of one empties that domain's entire enumeration while amass still "+
			"exits 0; the save endpoint refuses that specific case.")
	}
	return args, notes
}

// ---------------------------------------------------------------------------------------------
// dnsx_company  (step 10)
// ---------------------------------------------------------------------------------------------

// dnsxCompanyBaseArity is the arity of the flags the RUNNER hardcodes. The eight record types and the
// two output flags are switches; only -retry takes a value.
var dnsxCompanyBaseArity = map[string]int{
	"-a": 0, "-aaaa": 0, "-cname": 0, "-mx": 0, "-ns": 0, "-txt": 0, "-ptr": 0, "-srv": 0,
	"-re": 0, "-j": 0, "-retry": 1,
}

// dnsxCompanyCommandArgs builds the argv for ONE domain of a Company dnsx scan.
//
// With no stored settings this is token for token what ExecuteDNSxCompanyScan built inline. The
// target is NOT on the command line at all: the runner writes the hostname to the process's STDIN,
// one per invocation, which is why -l and -d are framework-owned and why -rl and -t are owned as
// MEASURED INERT (a worker pool and a per-host rate limit can do nothing with one host).
//
// TURNING A RECORD TYPE OFF REMOVES ITS FLAG FROM THE BASE rather than adding anything: all eight
// default to on because the runner passes all eight, and none of them is a flag whose absence means
// "on" inside the tool, so removal is the correct and complete way to express off.
func dnsxCompanyCommandArgs(tool CompanyTool, settings map[string]any) ([]string, []string) {
	base := []string{
		"docker", "exec", "-i",
		"ars0n-framework-v2-dnsx-1",
		"dnsx",
		"-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-ptr", "-srv",
		"-re", "-j",
		"-retry", "3",
	}

	overlay := companyOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: dnsxCompanyBaseArity,
	}
	args, notes := overlay.apply(base)

	// A scan with every record type turned off still runs, still exits 0 and still stores a successful
	// scan with no records, because dnsx falls back to its own default of -a when no type flag is
	// given. That is a coverage decision with no symptom, so it is said out loud.
	if dnsxAllRecordTypesOff(settings) {
		notes = append(notes, "EVERY record type is switched off. dnsx falls back to its own default of -a "+
			"when no type flag is given, so the scan will still run and still exit 0 - it will simply resolve "+
			"A records and the parser will store whatever comes back. If the intent was to scan nothing, "+
			"that is not what will happen.")
	}
	return args, notes
}

// dnsxCompanyRecordTypeKeys are the eight toggles, in the order the runner emits their flags.
var dnsxCompanyRecordTypeKeys = []string{
	"queryA", "queryAAAA", "queryCNAME", "queryMX", "queryNS", "queryTXT", "queryPTR", "querySRV",
}

func dnsxAllRecordTypesOff(settings map[string]any) bool {
	for _, key := range dnsxCompanyRecordTypeKeys {
		if companyBoolSetting(settings, key, true) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------------------------
// cloud_enum  (step 11)
// ---------------------------------------------------------------------------------------------

// cloudEnumCompanyBaseArity covers every flag the runner emits from cloud_enum_configs.
//
// EVERY ONE OF THEM IS FRAMEWORK-OWNED, because CloudEnumConfigModal already owns them through
// cloud_enum_configs and two controls for one setting is the disagreement this registry exists to
// prevent. They are listed here anyway so the overlay's walk can tell a flag from the value that
// follows it - without `-k`'s arity, a keyword that happened to spell a flag would displace one.
var cloudEnumCompanyBaseArity = map[string]int{
	"-l": 1, "-f": 1, "-k": 1, "-t": 1, "-m": 1, "-b": 1,
	"-ns": 1, "-nsf": 1,
	"--disable-aws": 0, "--disable-azure": 0, "--disable-gcp": 0,
	"--aws-services": 1, "--azure-services": 1, "--gcp-services": 1,
	"--aws-regions": 1, "--azure-regions": 1, "--gcp-regions": 1,
}

// cloudEnumWordlistPresets maps a vocabulary choice to the path of a list that is ALREADY INSIDE THE
// CONTAINER.
//
// Measured with wc -l in the running image: fuzz_small.txt is 141 lines (the tool's own default),
// fuzz.txt is 1095, fuzz_large.txt is 1790, and the fork's own rs0nfuzz.txt is 1013. Going from 141
// to 1790 is a twelve-fold change in the candidate namespace for the same keywords, and no current
// configuration can reach any of the three larger lists without uploading a file from the host.
var cloudEnumWordlistPresets = map[string]string{
	"fuzz_small (141)":  "/app/enum_tools/fuzz_small.txt",
	"fuzz (1095)":       "/app/enum_tools/fuzz.txt",
	"fuzz_large (1790)": "/app/enum_tools/fuzz_large.txt",
	"rs0nfuzz (1013)":   "/app/enum_tools/rs0nfuzz.txt",
}

// cloudEnumApplySettings overlays the stored settings onto the command the runner already composed
// from cloud_enum_configs, and resolves the two flagless wordlist presets.
//
// THE PRESETS CARRY NO FLAG ON PURPOSE. -m and -b belong to cloud_enum_configs.mutations_file_path
// and brute_file_path, and a key that appears in both Options and OwnedFlags makes the save endpoint
// refuse the setting with no visible symptom. So the RUNNER resolves the preset, and it does so only
// when the modal has NOT supplied an uploaded file: the uploaded file wins, because it is the more
// specific instruction and because emitting -m twice would put the same flag on the command line from
// two sources, which is exactly the ambiguity this design removes. When the modal wins, the preset
// says so rather than silently losing.
func cloudEnumApplySettings(base []string, mutationsFileSet, bruteFileSet bool, tool CompanyTool,
	settings map[string]any) ([]string, []string) {
	overlay := companyOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: cloudEnumCompanyBaseArity,
	}
	args, notes := overlay.apply(base)

	if preset := strings.TrimSpace(companyStringSetting(settings, "mutationsPreset", "")); preset != "" {
		path, known := cloudEnumWordlistPresets[preset]
		switch {
		case !known:
			notes = append(notes, "mutationsPreset "+strconv.Quote(preset)+" is not one of the known in-container "+
				"lists, so the tool's own default (/app/enum_tools/fuzz_small.txt, 141 entries) was used.")
		case mutationsFileSet:
			notes = append(notes, "mutationsPreset was NOT applied: CloudEnumConfigModal has an uploaded "+
				"mutations file for this target and that file wins, because it is the more specific "+
				"instruction and because emitting -m from two sources would put the same flag on the command "+
				"line twice. Clear the uploaded file to use the preset.")
		default:
			args = append(args, "-m", path)
			notes = append(notes, "mutationsPreset selected "+path+". Note the runtime cost: this multiplies "+
				"every keyword by every mutation across every enabled service and region, so it is not the "+
				"same scan length at all.")
		}
	}

	if preset := strings.TrimSpace(companyStringSetting(settings, "bruteListPreset", "")); preset != "" {
		path, known := cloudEnumWordlistPresets[preset]
		switch {
		case !known:
			notes = append(notes, "bruteListPreset "+strconv.Quote(preset)+" is not one of the known in-container "+
				"lists, so the tool's own default (/app/enum_tools/fuzz_small.txt) was used.")
		case bruteFileSet:
			notes = append(notes, "bruteListPreset was NOT applied: CloudEnumConfigModal has an uploaded brute "+
				"file for this target and that file wins, for the same reason as the mutations preset.")
		default:
			args = append(args, "-b", path)
			notes = append(notes, "bruteListPreset selected "+path+". It is the list of Azure blob CONTAINER "+
				"names tried inside a storage account that has already been found, so it is inert unless Azure "+
				"is enabled AND a storage account is discovered.")
		}
	}

	if companyBoolSetting(settings, "quickScan", false) {
		notes = append(notes, "quickScan is on. MEASURED: the banner then reads 'Mutations: NONE! (Using "+
			"quickscan)'. A quickscan that finds nothing is NOT the same claim as a full scan that finds "+
			"nothing, and the scan row records neither, so the two results are indistinguishable afterwards.")
	}
	if companyBoolSetting(settings, "verbose", false) {
		notes = append(notes, "verbose changes STDOUT, and the runner parses the LOG FILE. It cannot change "+
			"results. It is also only half useful today, because the runner discards stdout apart from one "+
			"DEBUG log line - which is how the measured 'AWS RATE LIMITING DETECTED / Skipping S3 HTTP "+
			"enumeration' block gets thrown away on this host on every scan.")
	}
	return args, notes
}

// cloudEnumRedactCredentials removes the AWS credential VALUES from a command string before it is
// written to cloud_enum_scans.command.
//
// UpdateCloudEnumScanStatus stores the joined command on every scan, so without this an operator who
// used the tool's own documented remedy for the S3 rate-limit skip would have their AWS secret access
// key sitting in the database in plaintext. The executed command is unchanged - the values are still
// argv elements and are therefore still visible in the container's process table for the duration of
// the scan, which is a runner change (pass them by environment variable) rather than a settings one.
func cloudEnumRedactCredentials(command string, settings map[string]any) string {
	for _, key := range []string{"awsAccessKey", "awsSecretKey"} {
		value := strings.TrimSpace(companyStringSetting(settings, key, ""))
		if value == "" {
			continue
		}
		command = strings.ReplaceAll(command, value, "REDACTED-"+key)
	}
	return command
}

// ---------------------------------------------------------------------------------------------
// katana_company  (step 12)
// ---------------------------------------------------------------------------------------------

// katanaCompanyBaseArity is the arity of the flags the RUNNER hardcodes.
var katanaCompanyBaseArity = map[string]int{
	"-u": 1, "-d": 1, "-jc": 0, "-j": 0, "-v": 0,
	"-timeout": 1, "-c": 1, "-p": 1, "-retry": 1, "-rd": 1, "-rl": 1,
}

// katanaCompanyCommandArgs builds the argv for ONE domain of a Company katana crawl.
//
// With no stored settings this is token for token what ExecuteKatanaCompanyScan built inline:
//
//	docker exec ars0n-framework-v2-katana-1 katana -u <url> -d 3 -jc -j -v -timeout 120 -c 20 -p 20 -retry 3 -rd 1 -rl 10
//
// THREE OF THOSE ARE ALREADY DOING NOTHING AND THE VOCABULARY SAYS SO RATHER THAN QUIETLY FIXING IT:
// -p 20 has nothing to parallelise because the runner passes one -u per process; -v was measured to
// add nothing on v1.7.0 because request, response.headers and response.body all appear with -j alone;
// and -rd 1 dominates -rl 10, so the effective rate is about 1/s and raising rateLimit alone changes
// nothing an operator can see. All three are framework-owned or reported as advisories.
func katanaCompanyCommandArgs(targetURL string, tool CompanyTool, settings map[string]any) ([]string, []string) {
	base := []string{
		"docker", "exec", "ars0n-framework-v2-katana-1",
		"katana",
		"-u", targetURL,
		"-d", "3",
		"-jc",
		"-j",
		"-v",
		"-timeout", "120",
		"-c", "20",
		"-p", "20",
		"-retry", "3",
		"-rd", "1",
		"-rl", "10",
	}

	overlay := companyOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: katanaCompanyBaseArity,
	}
	args, notes := overlay.apply(base)

	// The advisories are computed by the SAME function the save endpoint uses, so the settings screen
	// and the scan record can never disagree about them.
	for key, advisory := range CompanyAdvisories(tool, settings) {
		notes = append(notes, key+": "+advisory)
	}
	if !companySettingIsSet(settings, "crawlDurationSeconds") && len(settings) > 0 {
		notes = append(notes, "crawlDurationSeconds is NOT set, so this crawl has no time bound of any kind: "+
			"the runner uses plain exec.Command with no context and loops over every selected domain. The URL "+
			"workflow's equivalent wraps katana in a 20-minute context; this one does not.")
	}
	return args, notes
}

// companyWireCloudAssets.go wires these four, so it claims these four.
func init() {
	markCompanyRunnerWired("amass_enum_company", "dnsx_company", "cloud_enum", "katana_company")
}

// companyDomainLoopNote is the sentence every per-domain runner in this phase needs on its record:
// a failed domain is skipped with `continue` and the scan is still finalised as a success, so any
// setting that can make a tool exit non-zero removes a domain from the results without removing it
// from the apparent coverage.
func companyDomainLoopNote(tool string, failed, total int) string {
	if failed == 0 {
		return ""
	}
	return fmt.Sprintf("%d of %d domains FAILED and were skipped, and this scan is still recorded as a "+
		"success with whatever the other domains produced. A run in which every domain failed is stored "+
		"identically to a run that found nothing. Tool: %s.", failed, total, tool)
}
