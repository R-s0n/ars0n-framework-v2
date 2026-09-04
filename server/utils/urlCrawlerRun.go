package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Running Katana and GoSpider across every host an operator selected.
//
// The archive tools got the same ability first (urlArchiveRun.go) and the shape is deliberately
// the same, but the reasons are different and only one of them carries over.
//
// These crawlers SEND REQUESTS. That changes two things. Admission stops being a formality: a host
// the operator excluded must never receive traffic, so ScanScope decides per host and a refusal
// skips that host rather than the run. And credentials stop being safe to hoist: the material that
// unlocks the target is not material an adjacent host is entitled to, and an adjacent host can sit
// on a completely different registrable domain.
//
// One process per host, and that is forced rather than chosen. katana's -H and gospider's
// --cookie/-H are process-global flags: a single process seeded with several hosts sends the same
// Authorization and Cookie headers to all of them. There is no way to vary them within one process,
// so the per-host answer has nowhere to live except a per-host process.

// crawlAuth is the credential material approved for ONE host, and nothing else.
//
// It exists because ffufAuthMaterial returns a flat (headers, cookie) pair with no host attached,
// which is safe only while a crawl has exactly one seed. Resolving that once and passing it to
// every host would hand the target's session to third-party origins, which is precisely what
// ScopedAuthContext.For refuses to do. Withheld records WHY nothing is being sent, so a host that
// crawled a login wall is not later read as an application with nothing on it.
type crawlAuth struct {
	Headers  []NameVal
	Cookie   string
	Source   string
	Withheld string
}

func (a crawlAuth) sends() bool { return len(a.Headers) > 0 || strings.TrimSpace(a.Cookie) != "" }

// resolveCrawlAuth answers "what may this host be sent" using the same helper every other scanner
// in this codebase uses, rather than a second implementation of cookie scoping.
//
// The rule it inherits: headers travel only to the exact host they were captured from or that the
// operator explicitly declared, and cookies travel only across one registrable domain, the way a
// browser would scope them. TestCredentialsAreScopedToTheirHost pins it.
func resolveCrawlAuth(scopeTargetID, host string, useSavedSession bool) crawlAuth {
	if !useSavedSession {
		return crawlAuth{Withheld: "the tool's saved-session switch is off"}
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return crawlAuth{Withheld: "no host to scope credentials to"}
	}

	material, reason := LoadScopedAuthContext(scopeTargetID).For(host)
	if material == nil {
		if reason == "" {
			reason = "no_credentials_for_host"
		}
		return crawlAuth{Withheld: reason}
	}

	out := crawlAuth{Cookie: material.Cookies, Source: material.Source}
	for name, value := range material.Headers {
		if strings.TrimSpace(name) == "" {
			continue
		}
		out.Headers = append(out.Headers, NameVal{Name: name, Value: value})
	}
	// Go randomises map iteration, so two identical runs would otherwise produce two different
	// command lines. The command is stored and compared by operators; it should not shuffle.
	sort.Slice(out.Headers, func(i, j int) bool { return out.Headers[i].Name < out.Headers[j].Name })
	return out
}

// crawlHostOutcome is one host's crawl, before its URLs are folded into the run.
type crawlHostRun struct {
	Command  []string
	Stdout   string
	Stderr   string
	Err      error
	Elapsed  time.Duration
	TimedOut bool
	Auth     crawlAuth
}

// crawlSeedURL decides what to actually point the crawler at for one host.
//
// The baseUrl override belongs to the DIRECT host alone. It is the probe's redirect-corrected
// origin for the scope target, so applying it to every host would crawl the same origin N times
// under N different host labels and report the results as if they came from the adjacent hosts.
func crawlSeedURL(t ScanHostTarget, baseURL string) string {
	if t.IsDirect && strings.TrimSpace(baseURL) != "" {
		return strings.TrimSpace(baseURL)
	}
	return t.URL
}

// executeCrawlerScan is the body of both crawler scans. They differ only in the table they write to
// and how a command line is built.
//
// targetDomain is the SCOPE TARGET's domain and is passed unchanged for every host, for the same
// reason as in the archive runner: processURLsWithParameters decides is_direct by comparing each
// discovered URL's domain against it, so passing the host being crawled would mark every adjacent
// host's findings as direct.
func executeCrawlerScan(
	tool, table, scanID, targetURL, scopeTargetID string,
	targets []ScanHostTarget,
	perHostTimeout time.Duration,
	useSavedSession bool,
	baseURLOverride string,
	build func(seedURL string, t ScanHostTarget, auth crawlAuth) []string,
	update func(scanID, status, result, errorMsg, command, execTime string),
) {
	startTime := time.Now()

	targetDomain := extractDomain(targetURL)
	if targetDomain == "" {
		update(scanID, "error", "", "Failed to extract domain from target URL", "", time.Since(startTime).String())
		return
	}

	scope := LoadScanScope(scopeTargetID)

	var (
		results     []HostRunResult
		allURLs     []string
		allStdout   strings.Builder
		allStderr   strings.Builder
		allCommands []string
	)

	for _, target := range targets {
		res := HostRunResult{Host: target.Host, IsDirect: target.IsDirect}

		// Admission first, and separately from credentials. "In scope" and "may receive the session"
		// are different questions about the same host and both have to be asked.
		if scope != nil && !scope.Allows(target.Host) {
			res.Status = "skipped"
			res.Error = "out of scope for this target, so no request was sent"
			results = append(results, res)
			log.Printf("[INFO] %s skipped out-of-scope host %s", tool, target.Host)
			continue
		}

		auth := resolveCrawlAuth(scopeTargetID, target.Host, useSavedSession)
		if auth.Withheld != "" {
			log.Printf("[INFO] %s crawling %s unauthenticated: %s", tool, target.Host, auth.Withheld)
		}

		cmdArgs := build(crawlSeedURL(target, baseURLOverride), target, auth)
		res.Command = strings.Join(cmdArgs, " ")
		res.Authenticated = auth.sends()
		res.AuthNote = auth.Withheld

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), perHostTimeout)
		cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		log.Printf("[INFO] %s crawling %s: %s", tool, target.Host, res.Command)
		err := cmd.Run()
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()

		run := crawlHostRun{
			Command: cmdArgs, Stdout: stdout.String(), Stderr: stderr.String(),
			Err: err, Elapsed: time.Since(start), TimedOut: timedOut, Auth: auth,
		}
		res.Elapsed = run.Elapsed.String()

		allCommands = append(allCommands, res.Command)
		if run.Stdout != "" {
			fmt.Fprintf(&allStdout, "# %s\n%s\n", target.Host, run.Stdout)
		}
		if run.Stderr != "" {
			fmt.Fprintf(&allStderr, "# %s\n%s\n", target.Host, run.Stderr)
		}

		if run.Err != nil {
			res.Status = "error"
			if run.TimedOut {
				res.Error = fmt.Sprintf("crawl timed out after %s", perHostTimeout)
			} else {
				res.Error = strings.TrimSpace(run.Stderr)
				if res.Error == "" {
					res.Error = run.Err.Error()
				}
			}
			results = append(results, res)
			continue
		}

		urls := crawlerURLsFromOutput(tool, run.Stdout)

		// The same guard the single-host runs used, applied per host. A crawler that reached its
		// target writes something, so a completely silent exit 0 means it never got there.
		if reason := discoveryScanFailure(discoveryRun{
			Tool:             tool,
			Stdout:           run.Stdout,
			Stderr:           run.Stderr,
			URLsFound:        len(urls),
			Elapsed:          run.Elapsed,
			SilenceIsFailure: true,
		}); reason != "" {
			res.Status = "error"
			res.Error = reason
			results = append(results, res)
			continue
		}

		res.Status = "success"
		res.URLs = len(urls)
		allURLs = append(allURLs, urls...)
		results = append(results, res)
	}

	storeDiscoveryScanOutput(table, scanID, allStdout.String(), allStderr.String())
	storeHostRunResults(table, scanID, results)

	command := strings.Join(allCommands, " ; ")
	execTime := time.Since(startTime).String()

	succeeded := 0
	for _, r := range results {
		if r.Status == "success" {
			succeeded++
		}
	}
	if succeeded == 0 {
		update(scanID, "error", "", firstHostError(results), command, execTime)
		return
	}

	endpoints, err := processURLsWithParameters(allURLs, targetDomain, scanID, tool, scopeTargetID)
	if err != nil {
		update(scanID, "error", "", fmt.Sprintf("Failed to process URLs: %v", err), command, execTime)
		return
	}
	if err := storeDiscoveredEndpoints(endpoints); err != nil {
		update(scanID, "error", "", fmt.Sprintf("Failed to store endpoints: %v", err), command, execTime)
		return
	}

	direct, adjacent := 0, 0
	for _, ep := range endpoints {
		if ep.IsDirect {
			direct++
		} else {
			adjacent++
		}
	}

	log.Printf("[INFO] %s completed in %s across %d hosts for %s", tool, execTime, len(results), targetURL)
	update(scanID, "success", summariseHostRun(results, direct, adjacent), "", command, execTime)
}

// parseGoSpiderOutput reads GoSpider's --json stream. One JSON object per line, and the URL lives
// in "output"; a line that does not parse is progress noise, not a finding.
func parseGoSpiderOutput(stdout string) []string {
	var out []string
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row map[string]interface{}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if u, ok := row["output"].(string); ok && u != "" {
			out = append(out, u)
		}
	}
	return out
}

// crawlerURLsFromOutput turns one crawler's stdout into URLs. Katana prints one per line; GoSpider
// prints JSON objects, which the existing single-host parser already knows how to read.
func crawlerURLsFromOutput(tool, stdout string) []string {
	if tool == "gospider" {
		return parseGoSpiderOutput(stdout)
	}
	var out []string
	for _, line := range strings.Split(stdout, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// firstHostError reports why a run with no successful host failed, preferring a real error over a
// skip so the operator sees the thing that broke rather than the thing that was declined.
func firstHostError(results []HostRunResult) string {
	if len(results) == 0 {
		return "No hosts were selected for this scan. Open Config and choose at least one."
	}
	for _, r := range results {
		if r.Status == "error" && r.Error != "" {
			return fmt.Sprintf("%s: %s", r.Host, r.Error)
		}
	}
	for _, r := range results {
		if r.Error != "" {
			return fmt.Sprintf("%s: %s", r.Host, r.Error)
		}
	}
	return "No host produced a result."
}
