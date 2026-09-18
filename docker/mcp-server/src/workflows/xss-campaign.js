// THE XSS SCANNING CAMPAIGN, written from the run of 2026-09-17 against app.staging-v2.tradetalk.us
// while it was happening, not reconstructed afterwards.
//
// Source material, all measured that day and all in the campaign scratchpad:
// LESSONS-xss-campaign.md, FINDING-echo-reflection.md, FINDING-domdig-cannot-scan-json.md,
// reflection-probe.md.
//
// This entry is organised around FAILURES rather than around steps, and the schema is what forces
// that. The steps were never the hard part: four restarts went on configuration that fails open, and
// a list of steps would have prevented none of them. Read the gotchas first.

module.exports = {
  name: 'xss-campaign',
  title: 'XSS scanning campaign across a consolidated attack vector corpus',

  purpose:
    'Run dalfox, domdig and xssFuzz across every attack vector on one target and come out with a ' +
    'verdict per vector that means something. The ordering is one sentence and is not the work. ' +
    'The work is that all three tools exit 0 and report nothing when they have been told something ' +
    'they do not understand, so a clean result and a never-ran result are indistinguishable in the ' +
    'UI and clean is the one an operator acts on.',

  reach_for_it_when:
    'Step 6/8 Vector Scanning, on a target whose attack vectors are already consolidated, when the ' +
    'operator asks for an XSS sweep or for "all unauthenticated vectors". Pull it BEFORE ' +
    'configuring the first tool: five of the gotchas below are settings that fail open, and none ' +
    'of them can be detected from the result afterwards.',

  not_for:
    'Checking one URL for one reflection. That is replay_request and a canary string, and it takes ' +
    'a minute. This workflow is for a corpus, and its cheapest arm still costs about half an hour.',

  measured_on:
    'app.staging-v2.tradetalk.us, scope target 1e9b4bec-e8ca-41ac-9da3-744322637f2b, 2026-09-17. ' +
    '215 attack vectors, later 218, across 3 tools and 2 arms. Rate limit 200 requests per 60s.',

  cost:
    'dalfox about 35s per vector at rateLimit 5, roughly 172 requests each. xssFuzz seconds. ' +
    'domdig about 7 minutes per vector, driving real Chromium and pulling about 7 MB per 30s. The ' +
    'corrected campaign estimate was 6.5 hours against the 11 hours the mis-scoped plan implied, ' +
    'and half of that 11 was structurally void. All four figures are at ' +
    'xss/LESSONS-xss-campaign.md:196 for dalfox, :198 for domdig, :201 for the 6.5 hours and ' +
    ':202 for the 11.',

  updated: '2026-09-17, at the end of the run that produced it.',

  related: ['sqli-campaign'],

  preconditions: [
    {
      check: 'The attack vector corpus is consolidated and you have read its size.',
      why:
        'Every count in this workflow is relative to the corpus size. A selection left behind by ' +
        'an earlier per-vector phase makes a 27 vector corpus read as 2 eligible, and that reads ' +
        'like a small corpus rather than like a filter.',
      how: 'manage_attack_vectors action=list, then manage_vector_selection to read eligibility.',
    },
    {
      check: 'You know how many vectors carry a stored raw_request, and how many do not.',
      why:
        'The arm split is computed from the captured request, because that is the only evidence of ' +
        'how the application actually reached the route. 16 of the 215 vectors here came from ' +
        'parameter discovery tools that store no request bytes and had to be filed by hand.',
      how: 'Read the corpus and count the rows whose raw_request is present.',
    },
    {
      check: 'A credential can be minted on demand, and you know its lifetime.',
      why:
        'The authenticated arm re-mints per vector. The bearer here lives 900 seconds with no ' +
        'refresh token, so anything that batches more than a few vectors under one credential ends ' +
        'the run recording everything after the expiry as clean.',
      how: 'check_session_tokens, then manage_session_tokens action=list.',
    },
    {
      check: 'The engagement header is known, and you have somewhere to put it that is not userAgent.',
      why:
        'A mandatory bug bounty header is the most common reason an operator reaches for the user ' +
        'agent setting, and on dalfox that setting blinds the tool completely. It belongs in ' +
        'headers, passed as a list.',
      how: 'manage_xss action=settings, set headers, leave userAgent unset.',
    },
    {
      check: 'The target rate limit has been read off a real response header rather than assumed.',
      why:
        'X-Ratelimit-Limit 200 per 60 seconds is 3.33 requests per second. The campaign ran at 5 ' +
        'and one dalfox vector spends about 189 requests, so the limiter was reached inside a ' +
        'single vector.',
      how: 'replay_request against any endpoint and read X-Ratelimit-Limit off the response.',
    },
  ],

  steps: [
    {
      do:
        'Classify the whole corpus into an UNAUTHENTICATED arm and an AUTHENTICATED arm from each ' +
        'vector raw_request. Authorization header present means authenticated; request present ' +
        'with no such header means unauthenticated; no stored request means authenticated.',
      tool: 'manage_attack_vectors action=list, then read raw_request per vector.',
      assert:
        'The three counts sum to the corpus size. Here: 170 with an Authorization header, 29 ' +
        'without, 16 with no stored request, totalling 215.',
      verify:
        'The unauthenticated arm is small and its members are routes you can name. Here it was 29 ' +
        'vectors: 26 cookie, 2 query, 1 path.',
      source: 'xss/LESSONS-xss-campaign.md:128, which states the resulting arms and their split.',
      looks_like:
        'Skipping this step looks like full coverage. Scanning all 215 anonymously produces 401 ' +
        'for every payload, no reflection, and a verdict of clean on about 170 vectors.',
    },
    {
      do:
        'For the unauthenticated arm, deactivate every session_tokens row, then confirm zero are ' +
        'active.',
      tool: 'manage_session_tokens action=list and deactivate, then check_session_tokens.',
      assert: 'Zero active rows before the run starts, not merely a row you believe is stale.',
      verify:
        'The run does not abort partway. Run 1 of this campaign died exactly here and recorded 207 ' +
        'of 215 vectors UNTESTED.',
      source: 'xss/LESSONS-xss-campaign.md:96, the run that died on a stale token row.',
      looks_like:
        'A live token row does not add a credential to the scan, it adds a HEALTH CHECK that will ' +
        'abort the run when that credential dies. An unauthenticated sweep with a stale row is a ' +
        'sweep that stops.',
    },
    {
      do:
        'Configure each tool for the unauthenticated arm: no userAgent, headers as a LIST, ' +
        'rateLimit pinned under the measured limit, no vector limit, onSessionLoss continue, and ' +
        'sessionCheckUrl pointed at a URL whose answer does not depend on a credential.',
      tool: 'manage_xss action=settings, once per tool.',
      assert:
        'The save comes back with an empty blinded list and the eligible count equals the arm ' +
        'size. A blinded_warning on the save is the tool telling you it will scan 0 of 215.',
      verify:
        'Read the composed command back and check it holds no literal newline, and that every ' +
        'header you set is its own flag.',
      looks_like:
        'A newline-joined header emits ONE -H containing a newline. Measured in the dalfox ' +
        'container: two separate -H flags gave 174 requests and 1 finding, one -H with an embedded ' +
        'newline gave 1 request, 0 findings and exit 0.',
    },
    {
      do:
        'Select the unauthenticated arm for the tool, assert the eligible count, and run.',
      tool: 'manage_vector_selection, then manage_xss action=run.',
      assert:
        'eligible equals the arm size for this tool, read fresh. Selection is stored sparsely: only ' +
        'the vectors switched OFF are recorded, so a stale selection survives the phase that set it.',
      verify:
        'Per-vector wall clock is plausible against the oracle self-test. The oracle ran 70 ' +
        'seconds and passed while two real domdig vectors ran 3.2s and 3.5s; both had crashed and ' +
        'both were recorded clean.',
      source:
        'xss/LESSONS-xss-campaign.md:239, where the 70s oracle sits beside the 3.2s and 3.5s ' +
        'real vectors.',
      looks_like:
        'A scan that sent nothing finishes fast and reports clean. Duration against the positive ' +
        'control is the single cheapest crash detector available, and it is free on every run.',
    },
    {
      do:
        'Verify the unauthenticated run before configuring the next tool: positive control passed, ' +
        'untested count is zero, per-vector durations plausible, and the payload count in the raw ' +
        'output is not zero.',
      tool: 'manage_xss action=results, then get_tool_output for the argv and the stdout.',
      assert:
        'The oracle line "Positive control PASSED" is present for this run. It is the most ' +
        'valuable single signal in the section.',
      verify:
        'Findings are split on the oracle URL before anything is counted. On one prior run 26 of ' +
        '61 stored finding rows were oracle rows, and the prior XSS baseline of 11 findings on ' +
        'this target was 11 oracle rows and 0 real ones.',
      source:
        'xss/LESSONS-xss-campaign.md:153 for the 26 of 61 oracle rows, :157 for the prior ' +
        'baseline of 11 being 11 oracle rows.',
      looks_like:
        'Coverage that went UP. Every fail-open path in this section increases the number of ' +
        'vectors marked tested, which is why the metric cannot be used to check the metric.',
    },
    {
      do:
        'Run the authenticated arm ONE VECTOR AT A TIME: mint a fresh bearer, put it in BOTH the ' +
        'tool headers setting and a live session_tokens row, activate, select one vector, assert ' +
        'eligible is 1, run, wait, repeat.',
      tool: 'manage_session_tokens, manage_vector_selection, manage_xss action=run.',
      assert:
        'The bearer is in headers (which is what is SENT) and the same bearer is in the ' +
        'session_tokens row (which is what is WATCHED). Either one alone produces a run that is ' +
        'wrong in a different direction.',
      verify:
        'The vector completes with a verdict rather than a SESSION_LOST error. If the ' +
        'sessionCheckUrl for this arm is not auth-sensitive, session loss detection is impossible ' +
        'and the re-minting is pointless.',
      looks_like:
        'Moving the bearer out of headers and into session_tokens alone removes the credential ' +
        'from the request entirely, and with onSessionLoss abort it turns every cookie vector ' +
        'UNTESTED.',
    },
    {
      do:
        'Report the outcome in classes rather than as one clean total: real findings, oracle rows, ' +
        'untested, crashed, not-eligible-by-tool, path vectors, and Authorization-header vectors.',
      tool: 'manage_xss action=results, manage_attack_vectors for the per-class counts.',
      assert:
        'The classes sum to the corpus size. Any vector not in a class is a vector nobody decided ' +
        'about.',
      verify:
        'Every number in the report can be traced to a query or a stdout line. On this target the ' +
        'honest answer included 51 path vectors and 49 Authorization-header vectors that no tool ' +
        'in this section can test at all.',
      source:
        'xss/LESSONS-xss-campaign.md:165 for the 51 path vectors, ' +
        'xss/workflows-tool.md:100 for the 49 authorization-header vectors.',
      looks_like:
        'A single "215 vectors scanned, 0 findings" line, which is true in the same way that ' +
        '"48,859 requests sent" was true of the run that found nothing.',
    },
  ],

  lessons: [
    {
      lesson:
        'Verify a fix on a handful of vectors before committing to a full run. The check that ' +
        'settles a theory is almost always cheaper than the theory.',
      measured:
        'Two wrong explanations of the session preflight failure cost 30 minutes each. The check ' +
        'that settled it, comparing which vectors passed against which failed, took 3 minutes and ' +
        'named the cause immediately: SPA routes 200 clean, API routes 401 error.',
      source:
        'xss/LESSONS-xss-campaign.md:62 for the two wrong explanations, :71 for the ' +
        'passed-against-failed comparison that named the cause in 3 minutes.',
      cost: 'About an hour of the run, and it was the second most expensive error of the day.',
    },
    {
      lesson:
        '"All unauthenticated attack vectors" is a SET, not a MODE. It means the vectors reachable ' +
        'without a credential, not all the vectors with the credential removed.',
      measured:
        '170 of 215 vectors were captured with an Authorization header. Of the 30 clean verdicts ' +
        'recorded before the run was stopped, 21 were on auth-required routes. Had it finished, ' +
        'roughly 170 of 215 would have been false negatives that looked exactly like coverage.',
      source:
        'xss/LESSONS-xss-campaign.md:113, which carries the 170 of 215 arm split and the 21 of 30 ' +
        'clean verdicts that were on auth-required routes.',
      cost:
        'The single most expensive error of the run, and the operator caught it rather than the ' +
        'agent. It was a reading comprehension failure, not a tooling failure.',
    },
    {
      lesson:
        'Wall clock against the positive control is the cheapest correctness check in the whole ' +
        'section, and it is available for free on every run.',
      measured:
        'The domdig oracle ran 70 seconds and passed. The two real vectors ran 3.2s and 3.5s with ' +
        'byte-identical output, both crashed, and both were recorded CLEAN.',
      source:
        'xss/LESSONS-xss-campaign.md:239, where the 70s oracle sits beside the 3.2s and 3.5s real ' +
        'vectors.',
    },
    {
      lesson:
        'Split findings on the oracle URL before counting anything. The self-test is a genuinely ' +
        'good countermeasure and it is also stored as a real finding at critical or high severity.',
      measured:
        '26 of 61 finding rows on one prior run were oracle rows. The prior XSS baseline of 11 ' +
        'findings on this target was 11 oracle rows: there has never been a real XSS finding here.',
      source:
        'xss/LESSONS-xss-campaign.md:153 for the 26 of 61 oracle rows, :157 for the prior ' +
        'baseline of 11 being 11 oracle rows.',
    },
    {
      lesson:
        'A shortfall in tool reach is not a coverage failure. Report it as eligible-of-eligible, ' +
        'not as a gap.',
      measured:
        'dalfox reaches query, body, header, cookie and path, so 29 unauth and 186 auth. domdig ' +
        'and xssFuzz reach query only, so 2 unauth and 25 auth each. "2 of 2 eligible" is the ' +
        'honest line, not "2 of 215".',
      source:
        'xss/LESSONS-xss-campaign.md:138, which states the eligible-of-eligible wording and the ' +
        'per-tool reach it is computed from.',
    },
    {
      lesson:
        'Verify a number before propagating it, especially one you are about to use as the reason ' +
        'a safeguard cannot work.',
      measured:
        'I repeated "domdig exits 1 as its normal way of reporting nothing found" from an earlier ' +
        'measurement without checking. Over all 31 exit-1 domdig traces stored for this target: 17 ' +
        'were "[!] 404", 10 were genuine crashes, 4 were content-type refusals. The claim was ' +
        'false, and so was my first correction of it.',
      source:
        'xss/FINDING-domdig-cannot-scan-json.md:10, the breakdown over all 31 exit-1 domdig ' +
        'traces in the database.',
    },
    {
      lesson:
        'A reflection is not a finding until something renders it. Document the ones that are not, ' +
        'with the reason, because a later content-type bug turns them live in one step.',
      measured:
        '/api/v1/echo reflects <svg onload=alert(1)> raw, with nosniff, CSP and X-Frame-Options ' +
        'all absent. 5 attempts to move the content type off application/json all failed, so there ' +
        'is no proof of concept and it is not_enough_info rather than validated.',
      source:
        'xss/FINDING-echo-reflection.md:31 for the absent nosniff, CSP and X-Frame-Options, and ' +
        'the 5 failed attempts to move the content type.',
    },
  ],

  gotchas: [
    {
      gotcha:
        'dalfox userAgent blinds the tool entirely. Any custom value, including Mozilla/5.0, makes ' +
        'it find the reflection and then verify nothing.',
      symptom:
        'A completely normal-looking scan. The requests still go out, the run completes, the ' +
        'duration is plausible, and there are no findings and no error.',
      measured:
        'A prior run spent 53 vectors and 48,859 requests and found zero, against a target with 4 ' +
        'documented XSS. With the setting present the selection endpoint reads 0 of 215 eligible.',
      source:
        'xss/coverage-contract.md:147 for the blinded_warning and the 0 of 215 eligible, ' +
        'xss/LESSONS-xss-campaign.md:33 for the 53 vectors and 48,859 requests.',
      fix:
        'Leave userAgent unset. The framework encodes this in the Blinding map in ' +
        'server/utils/xssOptions.go and the settings save returns a blinded_warning, so assert the ' +
        'blinded list is empty and eligible equals the intended count after every save.',
    },
    {
      gotcha:
        'Headers must be passed as a LIST. settingValues in vectorCompose.go does not split a ' +
        'string, so "A: 1\\nB: 2" emits ONE -H flag containing a literal newline.',
      symptom:
        'One request, exit 0, zero findings, and a green canary. dalfox reports UNREACHABLE ' +
        '(request build error) with incomplete:false, and incomplete is the field the parser keys ' +
        'on.',
      measured:
        'In the dalfox container: no -H gave 172 requests and 1 finding, two separate -H flags gave ' +
        '174 requests and 1 finding, one -H with an embedded newline gave 1 request and 0 findings.',
      source:
        'xss/LESSONS-xss-campaign.md:48 for the three request counts side by side, ' +
        'xss/driver-fixes-2.md:39 for the same run written up.',
      fix:
        'Pass headers as a list, then read the composed command back and assert it contains no ' +
        'literal newline and that per-vector duration is plausible.',
      blast_radius:
        'The canary cannot catch it: vectorCanary.go strips Group "Session" before the oracle ' +
        'probe and dalfox headers is in that group, so the canary runs WITHOUT the broken header, ' +
        'fires green, and certifies the run. A bearer substring check passes too.',
    },
    {
      gotcha:
        'The credential header class. 49 of the header vectors fuzz the authorization header ' +
        'itself, which cannot be done while authenticated.',
      symptom:
        'Those vectors complete finding-free and look clean. The composer correctly drops the ' +
        'operator Authorization -H for exactly those vectors, the request goes out anonymous, and ' +
        'the API 401s every payload.',
      measured:
        '49 vectors. Left inside the authenticated arm they tripped the session breaker after 31 ' +
        'of 152 vectors, because every one of them looks like a lost session to the health check.',
      source:
        'xss/workflows-tool.md:100, recording the 49 authorization-header vectors tripping the ' +
        'breaker after 31 of 152.',
      fix:
        'Pull them out as their own class before the authenticated arm starts. They are not clean ' +
        'and they are not untested by accident, they are untestable this way, and saying so is the ' +
        'report.',
    },
    {
      gotcha:
        'domdig only scans text/html. Pointed at a JSON API it prints "Content type is not ' +
        'text/html" once per payload and EXITS 0.',
      symptom:
        'Exit 0, no findings, and the framework records a clean scan. This is the fail-open ' +
        'pattern in its worst form, because the coverage number goes UP.',
      measured:
        '21 of 42 stored domdig runs were untested rather than clean. Of the 30 query vectors that ' +
        'are domdig entire reachable surface here, 28 answer application/json and 2 answer ' +
        'text/html, so the authenticated domdig pass had ZERO scannable targets.',
      source:
        'xss/workflows-tool.md:101 for the 21 of 42 stored runs untested, ' +
        'xss/FINDING-domdig-cannot-scan-json.md:56 for the content-type census behind it.',
      fix:
        'domdigVectorEligible in server/utils/xssOptions.go now refuses an endpoint known to answer ' +
        'with something other than HTML and states the reason. Unknown content type stays eligible ' +
        'deliberately: 14 vectors had no recorded type, 13 were JSON and 1 was genuinely text/html.',
    },
    {
      gotcha:
        'The rate limit turns into false cleans. A 429 body reflects nothing, so a rate-limited ' +
        'payload is indistinguishable from a payload that was safely handled.',
      symptom:
        'Clean verdicts that arrive slightly faster than the others, with no error anywhere. ' +
        'Nothing in the chain reads the status code as a reason to distrust the verdict.',
      measured:
        'X-Ratelimit-Limit is 200 per 60 seconds, which is 3.33 requests per second. The campaign ' +
        'ran at rateLimit 5 and one dalfox vector spends about 189 requests, so the limiter is ' +
        'reached inside a single vector.',
      source:
        'xss/rate-and-traces.md:14 for the budget reading, :15 for the 189 requests in 16.1s on a ' +
        'single parameter.',
      fix:
        'Pin rateLimit below the measured limit before the first run, and read the limit off a ' +
        'live response header rather than guessing it.',
    },
    {
      gotcha:
        'The CORS logout. The mandatory X-BUG-BOUNTY header, set through setExtraHTTPHeaders, ' +
        'makes Chromium refuse the cross-origin token POST, and the application then revokes its ' +
        'own session.',
      symptom:
        'The browser-driven scan logs itself out mid-run and everything afterwards is scanned ' +
        'anonymously, which reads as clean.',
      measured:
        'The preflight, run by hand: OPTIONS /v1/oauth2/token answers 204 with ' +
        'Access-Control-Allow-Headers: Authorization, Content-Type, X-Correspondent. X-BUG-BOUNTY ' +
        'is not allow-listed and asking for it does not add it. The Cognito trace then reads ' +
        'GetUser 200 four times, RevokeToken 200, GetUser 400 Access Token has been revoked. A ' +
        'real password login in the same browser ended the same way, which is what ruled out the ' +
        'cookie jar.',
      source:
        'xss/authenticated-dom-scan.md:172, the preflight response with its ' +
        'Access-Control-Allow-Headers list.',
      fix:
        'Inject the header in request.continue({headers}) instead, which puts it on the wire below ' +
        'the CORS check: every request still carries it and the token POST returns 200. domdig -E ' +
        'sets headers the setExtraHTTPHeaders way, so an authenticated domdig run as specified ' +
        'would have scanned the logged-out application and looked clean.',
    },
    {
      gotcha:
        'The dalfox session preflight probes the SCAN TARGET, so a route that legitimately answers ' +
        '401 without a credential reads as a dead session.',
      symptom:
        'A clean split that looks like a tool bug: SPA routes clean, API routes error. Two ' +
        'plausible explanations are both wrong before the right one.',
      measured:
        'clean on /, /account/activities and /account/login, all 200. error on /api/v1/accounts ' +
        'and its subpaths, all 401. onSessionLoss abort is already the default, and the flag was ' +
        'present on the command line in 31 of 32 traces, so neither was the cause.',
      source:
        'xss/LESSONS-xss-campaign.md:66 for the flag being present in 31 of 32 traces, :71 for ' +
        'the clean-against-error split that named the cause.',
      fix:
        'Point sessionCheckUrl at a credential-independent 200 for the unauthenticated arm. The ' +
        'authenticated arm must use an auth-sensitive route instead, or session loss detection is ' +
        'impossible, which is the entire reason that arm re-mints per vector.',
    },
    {
      gotcha:
        'session_tokens is a MONITOR, not an INJECTOR. It is read every N vectors as a health ' +
        'check and it is never put into the scan.',
      symptom:
        'Two opposite mistakes that both look reasonable: an unauthenticated sweep that aborts, ' +
        'and an authenticated sweep that sends no credential at all.',
      measured:
        'vectorScan.go:259 calls SessionStillHonoured() and probes with the active rows. ' +
        'xssCompose_test.go confirms the tool headers setting is the only route to an ' +
        'Authorization header. Run 1 died this way with 207 of 215 vectors UNTESTED.',
      source:
        'xss/LESSONS-xss-campaign.md:96 for the 207 of 215 untested, ' +
        'server/utils/vectorScan.go:259 for the SessionStillHonoured call itself.',
      fix:
        'The authenticated arm needs BOTH: the bearer in headers, which is what is sent, and a ' +
        'live session_tokens row carrying the same bearer, which is what is watched. The ' +
        'unauthenticated arm needs zero active rows.',
    },
    {
      gotcha:
        'Vector selection is stored SPARSELY. Only the vectors switched OFF are recorded, so a ' +
        'selection outlives the phase that set it.',
      symptom:
        'A tool reports a small eligible count and it reads as a small corpus rather than as a ' +
        'leftover filter.',
      measured:
        'domdig read 2 eligible and xssfuzz read 1, on a 27 vector corpus, both left over from an ' +
        'earlier per-vector phase.',
      source:
        'xss/LESSONS-xss-campaign.md:143 for the domdig 2 and xssfuzz 1 on a 27 vector corpus, ' +
        'xss/coverage-contract.md:54 for the stored OFF rows.',
      fix:
        'Read the selection endpoint and assert eligible equals the intended count BEFORE every ' +
        'scan. Do not trust that the previous phase left it clean.',
    },
    {
      gotcha:
        'The oracle self-test is written into vector_findings as a real finding at critical or ' +
        'high severity.',
      symptom:
        'A findings count that looks like a productive run. The severity is real, the row is real, ' +
        'and the URL is http://oracle:8000/xss.',
      measured:
        '26 of 61 rows on one prior run. The prior XSS baseline of 11 findings on this target was ' +
        '11 oracle rows, and the three 2026-09-08 sweeps ran 3, 2 and 1 eligible vectors out of ' +
        '215 while being stored as completed.',
      source:
        'xss/LESSONS-xss-campaign.md:153 for the 26 of 61 rows, :157 for the baseline of 11, :158 ' +
        'for the three 2026-09-08 sweeps.',
      fix:
        'Split on url NOT LIKE %oracle:8000% before counting or reporting anything. The self-test ' +
        'itself is a good countermeasure and its "Positive control PASSED" line is the most ' +
        'valuable signal in a run.',
    },
    {
      gotcha:
        'dalfox cannot be aimed at a path segment. -p name:path is accepted and ignored, byte for ' +
        'byte.',
      symptom:
        'Path vectors complete and join the clean total. They were reachable only through dalfox ' +
        'own token-echo discovery, which sends nothing useful at a catch-all SPA.',
      measured:
        '51 path vectors on this target. One of them, /api/v1/echo, hit the 600 second cap with no ' +
        'verdict while dalfox ran bare-URL path discovery and never sent the one parameter the ' +
        'endpoint actually reads.',
      source:
        'xss/FINDING-echo-reflection.md:9 for the 600 second cap with no verdict, ' +
        'xss/authdriver-review.md:151 for the 51 path vectors.',
      fix:
        'Report path vectors as their own class. Where an endpoint names its own input in an error ' +
        'body, harvest it and add it as a query vector instead: that worked on 3 of 41 GET path ' +
        'vectors here, which is the honest number and not the systemic gap expected.',
    },
    {
      gotcha:
        'A tool that CRASHES is recorded clean, and this is the SHARED runner so every section is ' +
        'exposed.',
      symptom:
        'A fast run with no findings. refusedItsCommandLine() at vectorScan.go:1081 matches only ' +
        'argument parser complaints, and the exit code cannot discriminate.',
      measured:
        'domdig crashed on both unauthenticated vectors in about 3 seconds with byte-identical ' +
        'output and both were recorded CLEAN. Blast radius on this target: 4 domdig vectors ' +
        'falsely clean, plus an lfihunt trace.',
      source:
        'xss/LESSONS-xss-campaign.md:239 for the two 3s crashes recorded clean, ' +
        'xss/crash-detection-report.md:43 for the lfihunt trace in the same shape.',
      fix:
        'A crashed(output) companion keyed on markers that cannot appear in a successful run: ' +
        '"Traceback (most recent call last)", "panic:" with goroutine, ' +
        '"triggerUncaughtException". And compare wall clock against the oracle, which caught this ' +
        'one first.',
    },
    {
      gotcha:
        'xssFuzz reports clean after sending ZERO payloads. It pre-checks whether any parameter ' +
        'mishandles dangerous characters and sends nothing at all if none does.',
      symptom:
        'A clean verdict in 3 seconds. Not a crash, and defensible behaviour, but ' +
        'indistinguishable from 3775 payloads sent and none working.',
      measured:
        'Both unauthenticated vectors. The oracle run logged "Loaded 3775 Payloads" and found the ' +
        'bug in 151 seconds; the real runs logged "Loaded 0 Payloads" and "No Valid Payloads ' +
        'Found" in 3 seconds.',
      source:
        'xss/LESSONS-xss-campaign.md:251 for the oracle 3775 payloads in 151 seconds, :253 for ' +
        'the real runs at 0 payloads in 3 seconds.',
      fix:
        'Read the payload count out of the raw output and report a clean with 0 payloads as its ' +
        'own class. It means the cheap pre-filter declined to test, not that the vector survived ' +
        'testing.',
    },
    {
      gotcha:
        'domdig is effectively unusable on any page embedding a third-party iframe, and both ' +
        'documented mitigations fail.',
      symptom:
        'A DOMException about reading a named property from a cross-origin Window, an unhandled ' +
        'promise rejection, and a dead process that the runner files as a completed scan.',
      measured:
        'Across every domdig trace stored for this target: 29 of 39 crashed, 4 hit the 30 minute ' +
        'timeout, 4 completed. About a 10 percent success rate, predating this campaign. -O ' +
        '(sameOriginOnly) does not stop evaluation in an already-attached frame, and -X aborts the ' +
        'request while the frame element still exists and is still evaluated.',
      source:
        'xss/LESSONS-xss-campaign.md:265, the 29 of 39 crashed against 4 timed out and 4 ' +
        'completed.',
      fix:
        'The real fix is patching htcrawl frame enumeration to wrap evaluation in try/catch, which ' +
        'is a change to a vendored third-party tool and is an operator decision rather than ' +
        'something to slip into a scan run. Until then, treat domdig results on any page with a ' +
        'payment or analytics iframe as unmeasured.',
    },
    {
      gotcha:
        'Every HTML page on this host is the same page, so text/html does not mean "a page", it ' +
        'means the SPA catch-all.',
      symptom:
        'A browser-driven tool appears to scan many distinct routes and scans one document N ' +
        'times. Coverage rises, work does not.',
      measured:
        'Byte-identical at 15197 bytes, confirmed with cmp, across /dashboard/overview, ' +
        '/oauth/authorize, /verify, an account subpath and a deliberately nonsense path.',
      source:
        'xss/FINDING-domdig-cannot-scan-json.md:56 and :57, five paths all answering 200 ' +
        'text/html at 15197 bytes.',
      fix:
        'Reduce the browser tool job to "crawl the SPA once" and spend the budget on the ' +
        'authenticated crawl instead, which boots the app with a session and renders the real ' +
        'views. That is where DOM XSS on an SPA lives and it has never been done here.',
    },
  ],
};
