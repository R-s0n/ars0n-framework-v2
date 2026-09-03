// archivefetch asks the Wayback Machine which URLs it has seen for a host, and says so when it
// could not ask.
//
// WHY THIS EXISTS RATHER THAN waybackurls. tomnomnom/waybackurls calls http.Get with Go's default
// client, which sends User-Agent "Go-http-client/1.1". web.archive.org answers that UA with
// HTTP 429. waybackurls then tries to json.Unmarshal the 429 body, that fails, and the fetch
// goroutine returns the error into a discard:
//
//	resp, err := fetch(domain, noSubs)
//	if err != nil {
//	    return
//	}
//
// So the process prints nothing, writes nothing to stderr, and EXITS 0. A total refusal by the
// archive is byte-identical to a host with no archive history.
//
// MEASURED IN THE waybackurls CONTAINER, 2026-08-21, against ginandjuice.shop:
//
//	User-Agent                                 status   bytes
//	(Go default, what waybackurls sends)          429     162
//	ars0n-framework/2.0 (+archive-discovery)      200   9,826
//	curl/8.5.0                                    200   9,826
//	Wget/1.21                                     200   9,826
//
// waybackurls@v0.1.0 and waybackurls@latest both return 0 bytes and exit 0 here, while wget against
// the identical CDX URL from the same container returns real data. The container's network is fine;
// the User-Agent is the whole defect.
//
// The UA below is descriptive rather than a browser string. It gets 200, and claiming to be Chrome
// to a public archive would be a lie told for no gain.
//
// This program reports failure THROUGH ITS EXIT CODE. That is the entire point: the caller records
// stderr and marks the scan failed, instead of storing a green zero.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// userAgent identifies the caller honestly. Anything other than Go's default is accepted; see the
// measurement table above.
const userAgent = "ars0n-framework/2.0 (+archive-discovery)"

// The CDX API is slow and occasionally rate limits even a well-behaved client, so a single attempt
// would turn a transient 429 into "this host has no history".
const (
	attempts       = 4
	backoffInitial = 3 * time.Second
	requestTimeout = 180 * time.Second
)

func main() {
	noSubs := flag.Bool("no-subs", false, "do not prepend the *. subdomain wildcard to the host")
	flag.Parse()

	hosts := flag.Args()
	if len(hosts) == 0 {
		// Same convention as waybackurls, so anything piping into it keeps working.
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			if h := strings.TrimSpace(sc.Text()); h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "archivefetch: no host given, on the command line or on stdin")
		os.Exit(2)
	}

	seen := map[string]bool{}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for _, host := range hosts {
		urls, err := fetch(host, *noSubs)
		if err != nil {
			// Exit non-zero on the FIRST failure rather than continuing quietly. A partial answer
			// presented as a whole one is the failure mode this program was written to remove.
			out.Flush()
			fmt.Fprintf(os.Stderr, "archivefetch: %v\n", err)
			os.Exit(1)
		}
		for _, u := range urls {
			if !seen[u] {
				seen[u] = true
				fmt.Fprintln(out, u)
			}
		}
	}
}

// queryURL builds the CDX request.
//
// output=text with fl=original returns one URL per line, which is a third the size of the JSON form
// for the same answer and needs no parser. collapse=urlkey drops the repeat captures: the archive
// holds one row per crawl, and forty snapshots of the same URL are one endpoint.
//
// The wildcard is only prepended when the caller allows it. *.host:8080/* is not a pattern the index
// can match, because the wildcard belongs in front of a hostname and not in front of a host:port
// authority.
func queryURL(host string, noSubs bool) string {
	pattern := host + "/*"
	if !noSubs {
		pattern = "*." + pattern
	}
	q := url.Values{}
	q.Set("url", pattern)
	q.Set("output", "text")
	q.Set("fl", "original")
	q.Set("collapse", "urlkey")
	return "http://web.archive.org/cdx/search/cdx?" + q.Encode()
}

func fetch(host string, noSubs bool) ([]string, error) {
	target := queryURL(host, noSubs)
	client := &http.Client{Timeout: requestTimeout}

	backoff := backoffInitial
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			time.Sleep(backoff)
			backoff *= 2
		}

		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			return nil, fmt.Errorf("could not build the request for %s: %w", host, err)
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("could not reach web.archive.org for %s: %w", host, err)
			continue
		}

		// 429 and 5xx are worth another attempt. Anything else is the archive's final answer and
		// retrying it just spends time.
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf(
				"web.archive.org answered HTTP %d for %s after %d attempt(s). This is the archive "+
					"refusing the query, not a host with no history",
				resp.StatusCode, host, attempt)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("web.archive.org answered HTTP %d for %s: %s",
				resp.StatusCode, host, strings.TrimSpace(string(body)))
		}

		urls, err := readLines(resp.Body)
		resp.Body.Close()
		if err != nil {
			// A read that died partway through is a truncated answer, and returning it would
			// understate the surface without saying so.
			lastErr = fmt.Errorf("the response from web.archive.org for %s ended early: %w", host, err)
			continue
		}
		return urls, nil
	}
	return nil, lastErr
}

func readLines(r io.Reader) ([]string, error) {
	var urls []string
	sc := bufio.NewScanner(r)
	// CDX rows are URLs, and a URL can be long. The default 64KB token limit would abort a read
	// partway through and look like a short archive.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			urls = append(urls, line)
		}
	}
	return urls, sc.Err()
}
