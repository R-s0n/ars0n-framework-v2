// THE SQL INJECTION SCANNING CAMPAIGN, written from the run of 2026-09-18 against
// app.staging-v2.tradetalk.us while it was happening, not reconstructed afterwards.
//
// Source material, all measured that day and all in the campaign scratchpad:
// WORKFLOW-sqli-campaign.md, framework-canary-reuse.md, framework-rate-detection.md,
// campaign.log and sqli-ledger.json.
//
// Companion to xss-campaign. Everything that entry says about arms, credentials and fail-open
// detection is a property of the CORPUS and the RUNNER rather than of the tools, so it applies here
// unchanged and is not repeated. What is repeated is only what is different about SQLi, and what is
// different is that these two tools take TYPED settings: an option of the wrong type does not
// error, it produces a run that sends nothing and exits in a way the framework files as clean.

module.exports = {
  name: 'sqli-campaign',
  title: 'SQL injection campaign with sqlmap and ghauri across a vector corpus',

  purpose:
    'Run sqlmap, ghauri and SQLiDetector across every attack vector on one target and come out ' +
    'with a verdict per vector that means something. The ordering is one sentence and is not the ' +
    'work. The work is that both injection tools accept a setting of the wrong TYPE or a baseline ' +
    'they cannot authenticate against, send zero useful requests, and finish in a way the runner ' +
    'records as clean.',

  reach_for_it_when:
    'Step 6/8 Vector Scanning, on a target whose attack vectors are already consolidated, when the ' +
    'operator asks for a SQLi sweep. Pull it BEFORE configuring the first tool: four of the ' +
    'gotchas below are settings that fail open, and none of them can be detected from the result.',

  not_for:
    'Testing one parameter you already suspect. That is one sqlmap run at level 3 on one URL and ' +
    'it takes 3 minutes. This workflow is for a corpus, and one authenticated ghauri cookie vector ' +
    'alone spends about 1690 requests and 28 minutes.',

  measured_on:
    'app.staging-v2.tradetalk.us, scope target 1e9b4bec-e8ca-41ac-9da3-744322637f2b, 2026-09-18. ' +
    '218 attack vectors across 3 tools and 2 arms. The estate publishes X-Ratelimit-Limit 200 over ' +
    'about 60s, read as a token bucket of roughly 200 burst refilling near 3.33/s.',

  cost:
    'sqlmap at level 1, delay 0.35, threads 1: the ledger holds 10 CLEAN rows measuring 95, 95, ' +
    '141, 206, 233, 310, 310, 340 and 417 seconds on body insertion points and 65 on a cookie ' +
    'one, plus 4 rows recorded TIMED_OUT at the 900s cap. Those are LEDGER ROWS and not a census ' +
    'of the run: the log answers CLEAN for 3 of those 4 timeouts and carries 6 settled vectors ' +
    'the ledger never received, so read the concurrent-driver gotcha before quoting any of them. ' +
    'ghauri at delay 1, threads 1: about 28 minutes on a real cookie vector. The positive control ' +
    'is 49.7s for sqlmap and 129s for ghauri, once per SCAN. sqli/sqli-ledger.json:44 for a ' +
    'TIMED_OUT row the log answers CLEAN at sqli/campaign.log:36; ' +
    'sqli/WORKFLOW-sqli-campaign.md:17 for the 49.7s control.',

  updated:
    '2026-09-18, with the authenticated sqlmap arm still running. The per-vector counts were ' +
    'reconciled against campaign.log after 2 concurrent drivers were found sharing 1 ledger.',

  related: ['xss-campaign'],

  preconditions: [
    {
      check: 'The session cache state of BOTH tools has been read out of the composer, today.',
      why:
        'ghauri keys its session by HOST and replays a stored verdict in about one second having ' +
        'sent nothing. A previous run had 6 of 7 findings restored from a scan 20 hours earlier, ' +
        'and the positive control itself was a replay.',
      how:
        'Read sqliCompose.go:84 for sqlmap and :138 for ghauri. Both were framework-owned ' +
        '--flush-session on 2026-09-18. A memory note said sqlmap had no such flag, which was true ' +
        'when it was written and false when it was acted on, so CHECK rather than assume in either ' +
        'direction.',
    },
    {
      check: 'The rate limit has been characterised as a BUDGET with a shape, not as a number.',
      why:
        'X-Ratelimit-Limit 200 over about 60 seconds is a token bucket of roughly 200 burst ' +
        'refilling near 3.33/s. A single rate figure applied to the whole target throttles a cheap ' +
        'endpoint needlessly and lets an expensive one drain its own bucket, and one ghauri cookie ' +
        'vector at about 1690 requests is 8 whole buckets on its own.',
      how:
        'Read the header off a response rather than inferring the budget from a scan. Whether the ' +
        'bucket is per endpoint or per target was never isolated by an experiment on this run, so ' +
        'pace per endpoint as the safe reading and do not report it as established.',
    },
    {
      check: 'The per-tool positive control cost is known BEFORE the first real vector runs.',
      why:
        'A control that passes too fast is a replayed verdict certifying a broken run, and the ' +
        'only way to see that is to know what a real one costs.',
      how:
        'A good sqlmap control here is 49.7s, three techniques (boolean-based blind, stacked ' +
        'queries, time-based blind), ending "back-end DBMS: PostgreSQL". ghauri is 129s. The ' +
        'measured bad one was 871ms.',
    },
    {
      check: 'The arm split is computed and the credential-header class is pulled out of it first.',
      why:
        'The split is a property of the corpus, identical to the XSS campaign because it comes ' +
        'from the captured requests and not from the tool.',
      how:
        '29 unauthenticated and 140 authenticated for sqlmap and ghauri, which is 189 minus the 49 ' +
        'vectors that fuzz the authorization header itself and cannot be tested while ' +
        'authenticated. SQLiDetector reaches query only: 2 and 28.',
    },
    {
      check: 'The selection endpoint response shape has been read, not guessed.',
      why:
        'It answers with "vectors" plus top-level "selected", "eligible" and "scan_will_run". ' +
        'There is no "items" key, and reading one returns 0, which invites you to cancel a run ' +
        'that was configured correctly. That happened on this run.',
      how: 'Assert the real shape and refuse to start on a mismatch, the way sqlisweep.py does.',
    },
    {
      check: 'You know how to stop a running scan, and you know that killing your shell is not it.',
      why:
        'This was hit twice in one session and both times ended with TWO TOOLS SCANNING ' +
        'CONCURRENTLY, which doubles the request rate against an estate whose whole constraint is ' +
        'its rate limit.',
      how: 'Read the stopping gotcha below before you start, not when you want to stop.',
    },
  ],

  steps: [
    {
      do:
        'Split the corpus into an UNAUTHENTICATED arm and an AUTHENTICATED arm from each vector ' +
        'raw_request, then lift the credential-header vectors out of the authenticated arm as ' +
        'their own untestable class.',
      tool: 'manage_attack_vectors action=list, then read raw_request per vector.',
      assert:
        'The classes sum to the corpus size. Here: 218 eligible of 218 total, 140 in the ' +
        'authenticated arm, 49 pulled out as credential-header, 29 unauthenticated.',
      verify: 'The unauthenticated arm is small and its members are routes you can name.',
      looks_like:
        'Scanning everything with a credential looks like full coverage and tests the 49 ' +
        'credential-header vectors anonymously, which 401 every payload and read as clean.',
    },
    {
      do:
        'Configure each tool with ignoreCode 401, the delay typed CORRECTLY PER TOOL (float for ' +
        'sqlmap, integer for ghauri), threads 1, headers as a LIST, and ghauri keeping T in its ' +
        'technique set.',
      tool: 'manage_sqli action=settings, once per tool.',
      assert:
        'Read the composed command back. It holds no literal newline, every header is its own -H, ' +
        'and --technique still contains T for ghauri.',
      verify:
        'The saved delay survives the round trip as the right type. sqlmap 0.35 with threads 1 is ' +
        'about 2.8 req/s; ghauri 1 with threads 1 is about 1 req/s.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:49 for the sqlmap pacing and :50 for the ghauri pacing, ' +
        'both chosen off the published budget on :48.',
      looks_like:
        'ghauri 1.4.3 given --delay 0.5 exits 2 having sent zero requests, and because it reports ' +
        'on stdout its exit code was once discarded entirely: a 53-vector run finished in 40 ' +
        'seconds and recorded all 53 clean.',
    },
    {
      do:
        'Run the two tools SEQUENTIALLY, never together, and run the whole unauthenticated arm as ' +
        'ONE scan.',
      tool: 'manage_vector_selection, then manage_sqli action=run.',
      assert:
        'No other sqli scan is running first. Check the scan rows AND the live tool processes, ' +
        'because the two disagree routinely.',
      verify:
        'The control ran once for the scan rather than once per vector. 29 separate scans would ' +
        'spend 23 minutes proving the same thing 29 times at the measured 49.7s each.',
      source: 'sqli/WORKFLOW-sqli-campaign.md:17 for the 49.7s control this arithmetic rests on.',
      looks_like:
        'Two tools at their individually safe rates exceed the bucket together, and the 429s come ' +
        'back as false cleans because a 429 body injects nothing and reflects nothing.',
    },
    {
      do:
        'Verify the unauthenticated run before configuring anything else: control passed and took ' +
        'real time, untested count is zero, per-vector durations plausible.',
      tool: 'manage_sqli action=results, then get_tool_output for the argv and the stdout.',
      assert:
        'The control line is present for THIS scan and its duration is near the measured 49.7s, ' +
        'not near 871ms.',
      verify:
        'The result is reportable as a sentence with a control in it. Here: sqlmap unauthenticated ' +
        '29 of 29 vectors, zero findings, control verified. That run is Postgres scan ' +
        'b7fe528f-6e7a-41e1-81fc-eb437cd58c92 at 2026-09-18 02:31:48, 29 TARGET vectors all ' +
        'status=clean plus 1 CANARY row with status=findings. It predates campaign.log, so looking ' +
        'for it there finds nothing and reads like an invented number.',
      looks_like:
        'A replayed session verdict is indistinguishable from a fast clean scan except by its ' +
        'duration, which is why the duration is the assertion.',
    },
    {
      do:
        'Run the authenticated arm ONE SCAN PER VECTOR, minting a fresh credential before each, ' +
        'and record the token lifetime left at the start of each vector.',
      tool: 'manage_session_tokens, manage_vector_selection, manage_sqli action=run.',
      assert:
        'Selection actually took effect: eligible is 1, read back fresh. One vector here was ' +
        'recorded NOT_SCANNED_SELECTION because the select-one call reported success and left ' +
        'eligible at 0.',
      verify:
        'Each vector settles with an outcome rather than an expiry. The 10 ledger rows that record ' +
        'a token lifetime started with between 482 and 835 seconds of it, and those two extremes ' +
        'are the 417s vector and the 65s one, so no settled row here outlived its credential. The ' +
        'other 6 rows record no lifetime at all, so that is a range over 10 of 16 rows and not ' +
        'over the arm.',
      source:
        'sqli/sqli-ledger.json:230 for the 482 low, which is the 417s vector, and :105 for the ' +
        '835 high, which is the 65s one.',
      looks_like:
        'A vector that outlives its credential reports clean for everything after the expiry, and ' +
        'the 900s cap is longer than the remaining lifetime of a mid-life token.',
    },
    {
      do:
        'Report the outcome in classes rather than as one clean total: clean, timed out, untested ' +
        'by cancel, untested by restart, not-scanned-by-selection, credential-header, and ' +
        'not-eligible-by-tool.',
      tool: 'manage_sqli action=results, manage_attack_vectors for the per-class counts.',
      assert: 'The classes sum to the corpus size, so no vector is left undecided.',
      verify:
        'Every number traces to a scan row or a stdout line, it says WHICH, and it says whether ' +
        'that artifact is complete. The ledger first 13 by finished_at are 9 clean, 3 timed out at ' +
        'the 900s cap and 1 never scanned, and that sentence is true only OF THE LEDGER: two ' +
        'drivers shared it on this run, the log answers CLEAN for 2 of those 3 timeouts in the ' +
        'other series, and it holds 6 settled vectors the ledger never received. Reconcile the ' +
        'two before reporting a count: 16 ledger rows against 21 in the log is a union of 22.',
      source:
        'sqli/sqli-ledger.json:44 against sqli/campaign.log:36 for a row the ledger holds ' +
        'TIMED_OUT and the log answers CLEAN, and sqli/campaign.log:48 for the first of the 6 ' +
        'settled vectors the ledger never received.',
      looks_like:
        'A single "218 vectors scanned, 0 findings" line, which counts a 1.9s not-authorized exit ' +
        'and a 907s timeout as the same result.',
    },
  ],

  lessons: [
    {
      lesson:
        'Do not extrapolate pacing from the local oracle. The control runs against a cooperative ' +
        'local app and a real vector does not.',
      measured:
        'The oracle control completes in 49.7s for sqlmap and 129s for ghauri, while one real ' +
        'cookie vector spends about 1690 requests and about 28 minutes. That mistake was made ' +
        'during this very run, when the campaign budget was sized off the control.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:17 for the 49.7s sqlmap control, ' +
        'sqli/framework-canary-reuse.md:60 for the 129s ghauri control, ' +
        'sqli/framework-rate-detection.md:15 for the 1690 requests. No request count was ever ' +
        'measured for the oracle, so the ratio this lesson used to quote is not restated.',
      cost: 'The whole pacing plan for the ghauri arm had to be recomputed after 1 vector.',
    },
    {
      lesson:
        'ghauri --threads does NOT throttle anything. The delay is global to the run, not per ' +
        'thread, so raising threads does not buy speed and lowering them does not buy safety.',
      measured:
        'delay 1 at threads 1, 2, 3 and 4 measured 144s, 135s, 141s and 149s for identical output. ' +
        'The spread is noise.',
      source:
        'memory/sqli-tooling.md:69, measured 2026-09-18. This one is in the operator memory and ' +
        'not in the sqli scratchpad, which is why looking only at the campaign artifacts makes it ' +
        'read as unsourced.',
    },
    {
      lesson:
        'Complete coverage at level 1 beats partial coverage at level 3. Level 3 is a follow-up on ' +
        'something interesting, not a default.',
      measured:
        'A five-parameter query vector at level 1 took 179s and ended in an honest "all tested ' +
        'parameters do not appear to be injectable". Level 3 is roughly 3x, which across 338 ' +
        'vector-scans is 50+ hours.',
      source: 'sqli/WORKFLOW-sqli-campaign.md:55, timed on this target with a stopwatch.',
    },
    {
      lesson:
        'The level question does not generalise between targets, and two data points that ' +
        'disagree can both be right.',
      measured:
        'On ginandjuice.shop the boundary is a plain quote and level 3 bought nothing. On Juice ' +
        'Shop the sink is LIKE "%q%" so the boundary is a 3 character close that only level 3 ' +
        'tries. Decide it per target, on the cheap arm, with a stopwatch.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:61, which carries both data points and why they disagree.',
    },
    {
      lesson:
        'A written note about a tool flag has a shelf life, and acting on a stale one is ' +
        'indistinguishable from acting on a wrong one.',
      measured:
        'The stored note said sqlmap has no --flush-session. Verified on 2026-09-18 at ' +
        'sqliCompose.go:84 for sqlmap and :138 for ghauri: both are framework-owned today. 1 note, ' +
        'true when written, false when used.',
      source:
        'server/utils/sqliCompose.go:84 and server/utils/sqliCompose.go:138 in this repo, both ' +
        'composing --flush-session; sqli/WORKFLOW-sqli-campaign.md:11 records the check itself.',
      cost: 'It is the reason this book reports the age of every entry on every read.',
    },
    {
      lesson:
        'Wall clock against the positive control is the cheapest correctness check available, and ' +
        'it is free on every run.',
      measured:
        'A good control is 49.7s with three techniques ending "back-end DBMS: PostgreSQL". The ' +
        'measured bad one was 871ms and it certified a run that sent no test request. The oracle ' +
        'differential itself is 146 bytes true against 87 false.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:17 for the good control, :18 for the 871ms bad one, :19 ' +
        'for the 146 against 87 byte differential.',
    },
    {
      lesson:
        'A clean arm is only reportable with the control attached to it, and then it is worth ' +
        'reporting.',
      measured:
        'sqlmap unauthenticated: 29 of 29 vectors, zero findings, control verified. That sentence ' +
        'is the deliverable, and without the last clause it is the same sentence a blinded run ' +
        'produces.',
      source:
        'Postgres scan b7fe528f-6e7a-41e1-81fc-eb437cd58c92 at 2026-09-18 02:31:48: 29 TARGET ' +
        'vectors all status=clean plus 1 CANARY row with status=findings. It predates campaign.log ' +
        'and is not in it, so the scan id is the only address this claim has.',
    },
  ],

  gotchas: [
    {
      gotcha:
        'sqlmap treats a 401 baseline as FATAL. It prints "[CRITICAL] not authorized" and EXITS 0, ' +
        'which the framework files as clean.',
      symptom:
        'A very fast clean verdict with no error anywhere. The run completes, the coverage number ' +
        'goes up, and nothing in the chain reads the exit as a refusal to test.',
      measured:
        'Cost of omitting ignoreCode 401 on an earlier run: 91 of 249 vectors, 37 percent, each ' +
        'recorded clean in 1.9s having tested nothing.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:30 and memory/sqli-tooling.md:165, which also carries ' +
        'sqlmap\'s own [CRITICAL] not authorized sentence verbatim.',
      fix:
        'Set ignoreCode 401 on BOTH tools before the first run, and treat any sub-5s clean as ' +
        'untested until its stdout is read.',
    },
    {
      gotcha:
        'delay is a FLOAT for sqlmap and an INT for ghauri, and the wrong type is not an error the ' +
        'framework surfaces.',
      symptom:
        'ghauri 1.4.3 given --delay 0.5 exits 2 having sent zero requests. It reports on stdout, ' +
        'so the exit code was once discarded entirely.',
      measured:
        'A 53-vector ghauri run finished in 40 seconds and recorded all 53 vectors clean. That is ' +
        '0.75s per vector against a real per-vector cost of minutes.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:34 for the exit-2 behaviour, ' +
        'memory/vector-runner-fail-open.md:23 for the 53 vectors in 40 seconds.',
      fix:
        'Type the delay per tool: 0.35 for sqlmap, 1 for ghauri. Read the composed command back ' +
        'and check the per-vector wall clock against the control before trusting the arm.',
    },
    {
      gotcha:
        'header must be a LIST for both tools. Both declare it Repeatable with flag -H, and the ' +
        'composer does not split a string.',
      symptom:
        'A newline-joined string composes to ONE -H containing a literal newline. It passes any ' +
        'substring check for the bearer and puts no usable credential on the wire.',
      measured:
        '1 -H flag instead of 2, with the whole credential inside it. The authenticated arm then ' +
        'runs anonymously against routes that 401 every payload, and 0 of them are testable.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:38, where _repeatable_header_auth in authdriver.py is ' +
        'recorded refusing a string rather than splitting it.',
      fix:
        'Pass headers as a list. _repeatable_header_auth in authdriver.py refuses a string rather ' +
        'than splitting it, which is the right direction: refuse, do not repair.',
    },
    {
      gotcha:
        'ghauri keys its session cache by HOST, so it replays a verdict for a vector it has never ' +
        'seen.',
      symptom:
        'A result in about one second, including a positive control that "passes" having sent ' +
        'nothing at all.',
      measured:
        'A previous run had 6 of 7 findings restored from a scan 20 hours earlier, and the control ' +
        'itself was a replay at 871ms against a real 49.7s.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:14 for the 6 of 7 restored findings, :18 for the 871ms ' +
        'replayed control; server/utils/sqliCompose.go:138 for the flag that stops it.',
      fix:
        'Confirm --flush-session is composed for both tools, today, at sqliCompose.go:84 and :138. ' +
        'Then assert the control duration rather than the control verdict.',
    },
    {
      gotcha:
        'Dropping T from the ghauri technique set fails the canary, and the failure reads as a ' +
        'tooling fault rather than a configuration one.',
      symptom:
        'Every result is stamped "unverified, not clean" and the run looks broken twelve hours ' +
        'later when somebody reads it.',
      measured:
        'ghauri does not detect the oracle boolean differential at all, 146 bytes true against 87 ' +
        'false, and passes the control ONLY via PG_SLEEP time-based. Pinning --dbms buys nothing ' +
        'either: it is ignored and PostgreSQL is concluded regardless.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:23 for PG_SLEEP being the only path that passes, :19 for ' +
        'the 146 against 87 byte differential ghauri does not see.',
      fix: 'Keep T in the technique set for ghauri, always, whatever the rest of the set is.',
    },
    {
      gotcha:
        'The rate limit is a TOKEN BUCKET with a burst, not a sustained rate, and one vector can ' +
        'drain it on its own.',
      symptom:
        'A per-target rate setting that looks conservative still drains one busy endpoint bucket, ' +
        'and the 429s that follow come back as clean verdicts.',
      measured:
        'X-Ratelimit-Limit 200 over about 60 seconds, read as roughly 200 burst refilling near ' +
        '3.33/s. One ghauri cookie vector spends about 1690 requests, which is 8 full buckets. ' +
        'Per ENDPOINT is OBSERVED rather than proven: no experiment on this run isolated one ' +
        'endpoint bucket from another, so pace per endpoint as the safe reading and say so.',
      source:
        'sqli/WORKFLOW-sqli-campaign.md:48 for the published header, ' +
        'sqli/framework-rate-detection.md:14 for the burst reading, :15 for the 1690 requests.',
      fix:
        'Pace per endpoint, run the tools sequentially, and read the framework throttle detector ' +
        'output: a vector the target refused is UNTESTED, not clean.',
      blast_radius:
        'vectorRateLimit.go guards only what the framework sends through ScanClient. Every ' +
        'containerised tool opens its own sockets and is invisible to it, and 27 of the 31 ' +
        'registered tools declare no incomplete-output hook at all.',
    },
    {
      gotcha:
        'The selection endpoint has no "items" key, and a select-one call can report success while ' +
        'leaving nothing selected.',
      symptom:
        'Reading the wrong key returns 0 and invites you to cancel a correctly configured run. The ' +
        'opposite case starts a scan with eligible 0 and settles it in 2 seconds.',
      measured:
        'Both happened on this run. Vector 2170bce2 was recorded NOT_SCANNED_SELECTION after 2 ' +
        'seconds with eligible 0 of 218.',
      source:
        'sqli/campaign.log:20 and the ledger entry for vector ' +
        '2170bce2-dfc2-4169-ad3a-7ddd7166013c in sqli/sqli-ledger.json, eligible_now 0.',
      fix:
        'Read "vectors" plus the top-level "selected", "eligible" and "scan_will_run", assert ' +
        'eligible equals the intended count, and refuse to start on a mismatch.',
    },
    {
      gotcha:
        'Stopping a run takes FOUR steps and killing the shell is not one of them. A framework ' +
        'scan lives server side and campaign.sh relaunches drivers.',
      symptom:
        'The scan you believe you stopped is still sending. Hit twice in one session, both times ' +
        'ending with two tools scanning the same rate-limited estate concurrently.',
      measured:
        'TaskStop stops the chain, not the scan, and a chain stopped mid-phase may have fired the ' +
        'next scan microseconds earlier. The API cancel is cooperative and checked BETWEEN ' +
        'vectors, so at ghauri 28 minutes per cookie vector it can take half an hour to land.',
      source:
        'memory/stopping-a-scan-campaign.md:11 for the 2 times a scan was reported stopped while ' +
        'still sending, :16 for why 3 steps were not enough, :28 for the /proc walk.',
      fix:
        'Kill the tool process in its container to stop it now, then verify by BOTH the scan rows ' +
        'and the live processes. ps is NOT installed in these containers: walk /proc. A ps-based ' +
        'check returns empty and reads exactly like "nothing is running", which is how ghauri was ' +
        'declared dead while it was working fine.',
      blast_radius:
        'Cancel cannot interrupt a vector in flight. On a workload where one vector is 28 minutes ' +
        'that makes cancel close to useless for the case you most want it, which is stopping ' +
        'because you have realised the run is wrong.',
    },
    {
      gotcha:
        'A resume ledger keyed by tool and vector id is CORRUPTED SILENTLY by a second driver over ' +
        'the same corpus. The later write takes the key and the earlier result is simply gone.',
      symptom:
        'Nothing errors and nothing looks absent. The ledger is well formed and every row in it is ' +
        'plausible, so the count you report is a property of which write landed last rather than ' +
        'of the campaign.',
      measured:
        'Two authdriver.py runs shared one ledger here, their progress counters interleaving from ' +
        '12:08:51. The ledger holds 16 entries, the log holds 21 distinct vectors and the union is ' +
        '22: 6 settled cookie vectors, all CLEAN between 12:41:19 and 12:53:24, are in the log and ' +
        'in no ledger row. It is not even last-write-wins by finished_at, because 1351d948 is held ' +
        'TIMED_OUT at 12:08:49 while the log answers CLEAN at 12:10:29.',
      source:
        'sqli/campaign.log:34 and :35, where the two progress series interleave; :48 through :53 ' +
        'for the 6 settled vectors the ledger never received; sqli/campaign.log:36 against ' +
        'sqli/sqli-ledger.json:44 for the stale row. campaign.sh:44 is the line both drivers ran.',
      fix:
        'Check the log for a second progress series before you quote any ledger count, and ' +
        'reconcile the two by vector id. The way to not be here is the stopping gotcha above: ' +
        'killing the shell is what leaves the first driver running.',
      blast_radius:
        'Two drivers also double the request rate against an estate whose whole constraint is a ' +
        '200 request bucket, so this arrives as the stopping gotcha and the rate-limit gotcha at ' +
        'once, and the 429s it causes come back as clean verdicts.',
    },
  ],
};
