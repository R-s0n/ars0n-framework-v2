package utils

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Running an archive tool across every host an operator selected.
//
// Hosts are queried STRICTLY SEQUENTIALLY, one process per host. Three reasons, and the first is
// the one that decides it: web.archive.org rate limits by client, and it is the provider both tools
// lean on hardest. Firing twelve concurrent CDX queries from one egress address is the fastest way
// to turn a working run into twelve 429s. The second is that archivefetch's only flag (-no-subs) is
// per invocation and the correct value differs per host, so the hosts cannot share one command
// anyway. The third is that per-host status is only attributable when the processes are separate.
//
// A run therefore takes the SUM of its hosts' durations, which is why the timeout in both configs
// is documented as per host rather than per run.

// archiveHostRun is one host's query, independent of which tool ran it.
type archiveHostRun struct {
	Target   ArchiveTarget
	Command  []string
	Stdout   string
	Stderr   string
	Err      error
	Elapsed  time.Duration
	TimedOut bool
}

// runArchiveHosts executes build(host) once per selected target, in order, and returns what each
// one produced.
//
// The per-host runtime floor is applied by the CALLER, per host. It must never be applied to the
// run as a whole: archiveQueryFloor exists because a query that returns in under 2s never reached
// the archive, and summing twelve 300ms failures produces 3.6s, which would clear a run-level floor
// while every single query in it had failed.
func runArchiveHosts(
	targets []ArchiveTarget,
	perHostTimeout time.Duration,
	build func(plan archiveQuery) []string,
	onHost func(t ArchiveTarget, run archiveHostRun),
) {
	for _, target := range targets {
		// planArchiveQuery runs per host, not once for the run. It is what refuses an IP literal and
		// what decides whether the subdomain wildcard is legal for this particular authority, and
		// both answers differ host by host. A refusal skips that host and leaves the rest alone.
		plan := planArchiveQuery(target.URL)
		if plan.SkipReason != "" {
			t := target
			t.Skip = plan.SkipReason
			onHost(t, archiveHostRun{Target: t})
			continue
		}

		cmdArgs := build(plan)
		start := time.Now()

		ctx, cancel := context.WithTimeout(context.Background(), perHostTimeout)
		cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		log.Printf("[INFO] Archive query for %s: %s", target.Host, strings.Join(cmdArgs, " "))
		err := cmd.Run()
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()

		onHost(target, archiveHostRun{
			Target:   target,
			Command:  cmdArgs,
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			Err:      err,
			Elapsed:  time.Since(start),
			TimedOut: timedOut,
		})
	}
}

// archiveHostOutcome converts one host's process result into a recorded outcome plus the URLs it
// yielded, applying the per-host floor that catches a tool which failed fast and quietly.
func archiveHostOutcome(tool string, t ArchiveTarget, run archiveHostRun) (ArchiveTargetResult, []string) {
	res := ArchiveTargetResult{
		Host:     t.Host,
		IsDirect: t.IsDirect,
		Command:  strings.Join(run.Command, " "),
	}
	if run.Elapsed > 0 {
		res.Elapsed = run.Elapsed.String()
	}

	if t.Skip != "" {
		res.Status = "skipped"
		res.Error = t.Skip
		return res, nil
	}

	if run.Err != nil {
		res.Status = "error"
		if run.TimedOut {
			res.Error = "query timed out"
		} else {
			res.Error = strings.TrimSpace(run.Stderr)
			if res.Error == "" {
				res.Error = run.Err.Error()
			}
		}
		return res, nil
	}

	var urls []string
	for _, line := range strings.Split(run.Stdout, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			urls = append(urls, line)
		}
	}

	// Per host, deliberately. See runArchiveHosts.
	if reason := discoveryScanFailure(discoveryRun{
		Tool:       tool,
		Stdout:     run.Stdout,
		Stderr:     run.Stderr,
		URLsFound:  len(urls),
		Elapsed:    run.Elapsed,
		MinRuntime: archiveQueryFloor,
	}); reason != "" {
		res.Status = "error"
		res.Error = reason
		return res, nil
	}

	res.Status = "success"
	res.URLs = len(urls)
	return res, urls
}

// ---------------------------------------------------------------- command builders

// buildGAUCommand assembles gau's flags from the config. Every flag here appears in gau --help;
// nothing is invented.
func buildGAUCommand(plan archiveQuery, cfg GAUURLConfig) []string {
	cmd := []string{
		"docker", "run", "--rm",
		"sxcurity/gau:latest",
		plan.Host,
		"--providers", strings.Join(cfg.Providers, ","),
		"--threads", strconv.Itoa(cfg.Threads),
		"--timeout", strconv.Itoa(cfg.TimeoutSeconds),
	}
	if cfg.Retries > 0 {
		cmd = append(cmd, "--retries", strconv.Itoa(cfg.Retries))
	}
	// plan.WithSubs, not the config alone: a host carrying a non-default port cannot be asked about
	// with a subdomain wildcard, whatever the operator ticked.
	if cfg.IncludeSubdomains && plan.WithSubs {
		cmd = append(cmd, "--subs")
	}
	if len(cfg.Blacklist) > 0 {
		cmd = append(cmd, "--blacklist", strings.Join(cfg.Blacklist, ","))
	}
	if cfg.FromDate != "" {
		cmd = append(cmd, "--from", cfg.FromDate)
	}
	if cfg.ToDate != "" {
		cmd = append(cmd, "--to", cfg.ToDate)
	}
	return cmd
}

// buildArchiveFetchCommand is buildWaybackURLsCommand with the operator's subdomain preference
// folded in. The port rule still wins: see WaybackURLsURLConfig.IncludeSubdomains.
func buildArchiveFetchCommand(plan archiveQuery, cfg WaybackURLsURLConfig) []string {
	if !cfg.IncludeSubdomains {
		plan.WithSubs = false
	}
	return buildWaybackURLsCommand(plan)
}

// ---------------------------------------------------------------- the two runs

// executeArchiveScan is the whole body of both tools' scans. They differ only in which table they
// write to and how a command line is built, so they share everything else rather than drifting.
//
// targetDomain is the SCOPE TARGET's domain and is passed through unchanged for every host. This is
// load-bearing: processURLsWithParameters decides is_direct by comparing each discovered URL's
// domain against this value, so passing the host currently being queried would mark every adjacent
// host's endpoints as direct and destroy the distinction the results modal is built on.
func executeArchiveScan(
	tool, table, scanID, targetURL, scopeTargetID string,
	targets []ArchiveTarget,
	perHostTimeout time.Duration,
	build func(plan archiveQuery) []string,
	update func(scanID, status, result, errorMsg, command, execTime string),
) {
	startTime := time.Now()

	targetDomain := extractDomain(targetURL)
	if targetDomain == "" {
		update(scanID, "error", "", "Failed to extract domain from target URL", "", time.Since(startTime).String())
		return
	}

	var (
		results     []ArchiveTargetResult
		allURLs     []string
		allStdout   strings.Builder
		allStderr   strings.Builder
		allCommands []string
	)

	runArchiveHosts(targets, perHostTimeout, build, func(t ArchiveTarget, run archiveHostRun) {
		res, urls := archiveHostOutcome(tool, t, run)
		results = append(results, res)
		allURLs = append(allURLs, urls...)
		if res.Command != "" {
			allCommands = append(allCommands, res.Command)
		}
		if run.Stdout != "" {
			fmt.Fprintf(&allStdout, "# %s\n%s\n", t.Host, run.Stdout)
		}
		if run.Stderr != "" {
			fmt.Fprintf(&allStderr, "# %s\n%s\n", t.Host, run.Stderr)
		}
	})

	storeDiscoveryScanOutput(table, scanID, allStdout.String(), allStderr.String())
	storeArchiveTargetResults(table, scanID, results)

	command := strings.Join(allCommands, " ; ")
	execTime := time.Since(startTime).String()

	// A run only fails when EVERY host failed. One host's 429 is not a reason to discard the other
	// eleven hosts' endpoints, and reporting a whole run as failed when most of it worked is how an
	// operator learns to ignore the status.
	succeeded := 0
	for _, r := range results {
		if r.Status == "success" {
			succeeded++
		}
	}
	if succeeded == 0 {
		update(scanID, "error", "", firstArchiveError(results), command, execTime)
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

	log.Printf("[INFO] %s scan completed in %s across %d hosts for %s", tool, execTime, len(results), targetURL)
	update(scanID, "success", summariseArchiveRun(results, direct, adjacent), "", command, execTime)
}

// firstArchiveError reports why a run with no successful host failed, preferring a real error over
// a skip so the operator sees the thing that broke rather than the thing that was declined.
func firstArchiveError(results []ArchiveTargetResult) string {
	if len(results) == 0 {
		return "No hosts were selected for this scan. Open Configure and choose at least one."
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
