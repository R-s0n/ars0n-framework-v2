package utils

import (
	"net/url"
	"strings"
)

// Building the command lines for the sensitive data leak section.
//
// The recurring job here is aiming the tools at a DIRECTORY rather than a host, which each of them
// expresses differently: snallygaster takes a hostname plus -p, git-dumper takes a full .git URL,
// and GitTools takes a full .git URL and then a second command to rebuild the commits.

// ComposeSnallygaster builds the argv for one directory.
//
// snallygaster takes a HOSTNAME positionally and the directory separately with -p. Its default is to
// scan the root, which is the mistake this whole section exists to avoid, so -p is always supplied.
func ComposeSnallygaster(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("snallygaster")
	var warnings []string

	parsed, err := url.Parse(v.EvidenceURL)
	if err != nil || parsed.Host == "" {
		return nil, []string{"This target is not a URL, so there is no host to scan."}
	}

	args := []string{"-j"}

	// The scheme is decided by the URL this directory was found on, and the other one is turned off.
	// Left alone, snallygaster scans http AND https AND www.<host>, which turns one target into four
	// and sends three of them somewhere nobody asked about.
	if strings.EqualFold(parsed.Scheme, "https") {
		args = append(args, "--nohttp")
	} else {
		args = append(args, "--nohttps")
	}
	args = append(args, "--nowww")

	path := strings.TrimSuffix(parsed.Path, "/")
	if path != "" {
		args = append(args, "-p", path)
	}

	args = append(args, composeVectorSettings(tool, settings, "",
		map[string]bool{graphqlEndpointsSetting: true}, &warnings)...)
	args = append(args, parsed.Host)
	_ = reportPath
	return args, warnings
}

// ComposeGitDumper builds the command for one exposed repository.
//
// Run through a shell so a MANIFEST can be written afterwards. git-dumper's own exit code is 0
// whether it recovered a repository or found nothing at all, and its output is a DIRECTORY rather
// than a report, so the only reliable success signal is what ended up on disk. Measured: a URL with
// no .git leaves the output directory created and empty.
func ComposeGitDumper(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("git-dumper")
	var warnings []string

	flags := composeVectorSettings(tool, settings, "",
		map[string]bool{graphqlEndpointsSetting: true}, &warnings)
	dumpDir := reportPath + ".repo"

	command := "mkdir -p " + shellQuote(dumpDir) + " ; git-dumper " + strings.Join(quoteAll(flags), " ") +
		" " + shellQuote(gitURLFor(v.EvidenceURL)) + " " + shellQuote(dumpDir) +
		" ; " + gitManifestScript(dumpDir, "", reportPath)

	return []string{"-c", command}, warnings
}

// gitManifestScript writes everything the parser needs about a recovered repository.
//
// The repository itself is not the finding; what is inside it is. So the manifest records how much
// came back, which commits exist, and any line that looks like a credential ACROSS THE WHOLE HISTORY
// rather than only the current tree. Measured: a secret committed and then deleted in a later commit
// is still recoverable, because git-dumper downloads the object store rather than just checking out
// HEAD, so grepping only the working tree would miss the thing most worth finding.
func gitManifestScript(repoDir, extraDir, reportPath string) string {
	// Written section by section with appends rather than one brace group. A brace group joined with
	// separators produces "{ ; echo ..." which is a syntax error, and the whole manifest is then lost
	// with exit status 2 while the dump itself succeeded.
	repo := shellQuote(repoDir)
	out := shellQuote(reportPath)

	// COUNT EVERYTHING, including what is inside .git.
	//
	// The two tools leave different things behind and an earlier version of this counted only the
	// working tree, which reads correctly for git-dumper and reports NOTHING for GitTools: its Dumper
	// downloads the .git directory alone, and the working tree does not exist until Extractor runs.
	// Measured: nine files recovered, counted as zero, reported as no repository.
	roots := repo
	if extraDir != "" {
		roots += " " + shellQuote(extraDir)
	}

	return strings.Join([]string{
		"echo '## FILES' > " + out,
		// The readable names first: what a human wants to see is the source, not the object store.
		"find " + roots + " -type f -not -path '*/.git/*' 2>/dev/null | head -200 >> " + out,
		"echo '## FILECOUNT' >> " + out,
		"find " + roots + " -type f 2>/dev/null | wc -l >> " + out,
		"echo '## COMMITS' >> " + out,
		"git -C " + repo + " log --all --oneline 2>/dev/null | head -100 >> " + out,
		"echo '## SECRETS' >> " + out,
		// Every blob in the object store, not just the checked-out tree, because a secret committed
		// and then deleted is still an object and is usually the thing worth finding.
		"git -C " + repo + " rev-list --all --objects 2>/dev/null | head -500 | awk '{print $1}' | " +
			"while read o; do git -C " + repo + " cat-file -p \"$o\" 2>/dev/null | " +
			"grep -aEi " + shellQuote(leakSecretPattern) + " | head -3; done | sort -u | head -40 >> " + out,
		// And anything credential-shaped in the files themselves, which is where the Extractor output
		// lives: its per-commit directories are ordinary files rather than git objects.
		"grep -rlaEi " + shellQuote(leakSecretPattern) + " " + roots + " 2>/dev/null | " +
			"grep -v '/[.]git/' | head -20 | while read f; do " +
			"grep -aEi " + shellQuote(leakSecretPattern) + " \"$f\" | head -2; done | sort -u | head -20 >> " + out,
	}, " ; ")
}

// secretPattern is what a credential tends to look like in a committed file. Deliberately broad: a
// false positive costs a glance, a miss costs the finding.
const leakSecretPattern = `(api[_-]?key|secret|passwd|password|token|BEGIN [A-Z ]*PRIVATE KEY|` +
	`AKIA[0-9A-Z]{16}|aws_secret|client_secret|authorization)\s*[:=]|BEGIN [A-Z ]*PRIVATE KEY`

func quoteAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, shellQuote(value))
	}
	return out
}

// ComposeGitTools drives the Dumper and, when asked, the Extractor.
//
// Two programs rather than one, so they run through a shell, and the same manifest is written
// afterwards for the same reason: neither program's exit code distinguishes "recovered a repository"
// from "there was nothing there".
//
// Extractor is what makes GitTools worth having next to git-dumper. Both recover the full object
// store, so both can reach a deleted file, but git-dumper leaves you a repository to run git log
// through while Extractor materialises a DIRECTORY PER COMMIT, which is what you want when the job
// is grepping every historical state at once.
func ComposeGitTools(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	var warnings []string

	gitURL := gitURLFor(v.EvidenceURL)
	dumped := reportPath + ".repo"

	script := "mkdir -p " + shellQuote(dumped) + " ; " +
		"bash /opt/GitTools/Dumper/gitdumper.sh " + shellQuote(gitURL) + " " + shellQuote(dumped) +
		" </dev/null"

	extracted := ""
	if truthySetting(settings["extractCommits"]) {
		extracted = reportPath + ".commits"
		script += " ; mkdir -p " + shellQuote(extracted) +
			" ; bash /opt/GitTools/Extractor/extractor.sh " + shellQuote(dumped) + " " +
			shellQuote(extracted) + " </dev/null"
		warnings = append(warnings, "Every commit is being rebuilt into its own directory, which is "+
			"how a credential that was committed and later deleted becomes greppable.")
	} else {
		warnings = append(warnings, "Only the repository is being downloaded. Turn on rebuilding every "+
			"commit to materialise each historical state, which is the usual reason a secret is still "+
			"recoverable after it was deleted.")
	}

	script += " ; " + gitManifestScript(dumped, extracted, reportPath)
	return []string{"-c", script}, warnings
}

// gitURLFor turns a directory URL into the .git URL underneath it.
//
// Always with the trailing slash: both tools treat the URL as a prefix and join paths onto it, so
// ".../.git" without one produces requests for ".../.gitHEAD".
func gitURLFor(directory string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(directory), "/")
	if strings.HasSuffix(trimmed, "/.git") {
		return trimmed + "/"
	}
	return trimmed + "/.git/"
}

// shellQuote wraps a value for the single shell command GitTools needs. Single quotes, with any
// embedded quote broken out, because a URL is attacker-influenced data reaching a shell.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// ComposeMantra builds the command for one endpoint.
//
// Mantra reads its targets on STDIN, not from a flag, so it runs through a shell with the URL echoed
// into it. -s is framework owned because silent mode suppresses the very lines the findings are read
// from.
func ComposeMantra(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("mantra")
	var warnings []string

	flags := composeVectorSettings(tool, settings, "",
		map[string]bool{graphqlEndpointsSetting: true}, &warnings)

	command := "printf '%s\n' " + shellQuote(v.EvidenceURL) + " | mantra " +
		strings.Join(quoteAll(flags), " ")
	_ = reportPath
	return []string{"-c", command}, warnings
}

// ComposeTruffleHog fetches the endpoint and scans what came back.
//
// TruffleHog has no URL source: its sources are git, filesystem, S3, Docker and so on. So the
// framework curls the endpoint into a file and points the filesystem source at it. Anything else
// would be pretending it can scan a website, which it cannot.
func ComposeTruffleHog(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("trufflehog")
	var warnings []string

	flags := composeVectorSettings(tool, settings, "",
		map[string]bool{graphqlEndpointsSetting: true}, &warnings)

	if truthySetting(settings["noVerification"]) {
		warnings = append(warnings, "Live verification is off, so every result is a string that looks "+
			"like a credential rather than one known to work. Verification is the reason to use this "+
			"tool over a pattern matcher.")
	}

	fetched := reportPath + ".body"
	command := strings.Join([]string{
		"curl -sSL --max-time 60 -o " + shellQuote(fetched) + " " + shellQuote(v.EvidenceURL),
		"trufflehog filesystem " + shellQuote(fetched) + " --json --no-color " +
			strings.Join(quoteAll(flags), " ") + " > " + shellQuote(reportPath) + " 2>/dev/null",
	}, " ; ")

	return []string{"-c", command}, warnings
}
