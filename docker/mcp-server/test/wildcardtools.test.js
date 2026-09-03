const test = require('node:test');
const assert = require('node:assert');

// A stand-in for the four Go handlers, installed BEFORE the tool module is required so the actions
// themselves are exercised rather than only their projections. The shapes here are the ones
// server/utils/wildcardSettings.go builds, including the {error, message} body writeJSONError sends
// with a 400. node --test runs one process per file, so this stub cannot reach another suite.
//
// The registry fixture is deliberately small and local: loading the real 197KB registry would make
// this suite depend on a running server, which is the opposite of what it is for.
const FIXTURE = {
  workflow: 'wildcard',
  provenance_meaning: { measured: 'Probed against the installed container.' },
  owned_flags_meaning: 'Flags the runner sets itself.',
  tools: [
    {
      key: 'amass', name: 'Amass', step: 1, phase: 'Subdomain discovery',
      image: 'caffix/amass', binary: 'amass enum', version: 'v4.2.0',
      invocation: 'server/utils/amassUtils.go:605 ExecuteAndParseAmassScan',
      groups: ['Runtime', 'Scope Filters'],
      options: {
        timeoutMinutes: {
          kind: 'int', group: 'Runtime', label: 'Enumeration time limit', unit: 'minutes',
          flag: '-timeout', provenance: 'measured', min: 1, max: 1440,
          placeholder: 'The wildcard runner hardcodes 60, which is SIXTY MINUTES.',
          danger: 'Too small truncates the scan silently.',
        },
        blacklistNames: {
          kind: 'list', group: 'Scope Filters', label: 'Blacklisted subdomain names',
          flag: '-bl', repeatable: true, provenance: 'measured',
          placeholder: 'Empty. Nothing is excluded.',
        },
        maxDepth: {
          kind: 'int', group: 'Runtime', label: 'Max subdomain labels', flag: '-max-depth',
          provenance: 'unverified', min: 3, placeholder: 'Unset.',
        },
      },
      owned_flags: { '-silent': 'BLACKLISTED. Exit 0 with zero bytes on stdout AND stderr.' },
      runner_reads_settings: false,
      notes: 'There is no amass container.',
    },
    {
      key: 'httpx', name: 'httpx', step: 8, phase: 'Live web servers',
      container: 'ars0n-framework-v2-httpx-1',
      invocation: 'server/utils/liveWebServers.go:187 ExecuteAndParseHttpxScan',
      groups: [], options: {}, owned_flags: {}, runner_reads_settings: false,
      delegates_to: 'httpx_configs',
      limitation: 'httpx ALREADY has a configuration store and it is wired.',
    },
  ],
};

// What the tool actually sent, recorded by the stub. It has to be captured HERE rather than by
// reassigning api.apiPost later, because the tool module destructures the two functions at import
// time and holds the references.
const POSTED = [];

let stubbed = null;
try {
  const apiPath = require.resolve('../src/api.js');
  const stub = {
    apiGet: async (path) => {
      if (path === '/wildcard-tools') return FIXTURE;
      if (path === '/scopetarget/read') return [{ id: 'active-target', active: true }];
      const one = path.match(/^\/wildcard-tools\/([^/]+)\/([^/]+)\/settings$/);
      if (one) {
        const tool = FIXTURE.tools.find((t) => t.key === one[2]);
        return {
          tool: tool.key, tool_name: tool.name, step: tool.step, phase: tool.phase,
          invocation: tool.invocation, groups: tool.groups, options: tool.options,
          owned_flags: tool.owned_flags, runner_reads_settings: tool.runner_reads_settings,
          settings: { timeoutMinutes: 30, timeoutMinute: 5 },
          would_add_args: ['-timeout', '30'],
          compose_warnings: ['Nothing reads timeoutMinute; it was not put on the command line.'],
          notes: tool.notes, limitation: tool.limitation, delegates_to: tool.delegates_to,
          pending_wiring: 'Stored, but the runner does not read this store yet.',
        };
      }
      if (/^\/wildcard-tools\/[^/]+\/settings$/.test(path)) {
        return { scope_target_id: 'active-target', tools: FIXTURE.tools.map((t) => ({
          tool: t.key, tool_name: t.name, settings: {}, configured_count: 0,
          option_count: Object.keys(t.options).length, runner_reads_settings: false,
        })) };
      }
      throw new Error(`API GET ${path} failed (404): not found`);
    },
    apiPost: async (path, body) => {
      POSTED.push({ path, body });
      const keys = Object.keys(body.settings || {});
      if (keys.includes('-silent')) {
        throw new Error(`API POST ${path} failed (400): ${JSON.stringify({
          error: 'framework_owned',
          message: '-silent is set by the framework: BLACKLISTED. Measured: exit 0 with zero bytes '
            + 'on stdout AND zero bytes on stderr.',
        })}`);
      }
      return { saved: true, tool: 'amass', settings: body.settings, would_add_args: ['-timeout', '30'],
        pending_wiring: 'Stored, but the runner does not read this store yet.' };
    },
  };
  require.cache[apiPath] = { id: apiPath, filename: apiPath, loaded: true, exports: stub };
  stubbed = true;
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

// The module imports zod, and the repo's tests skip rather than fail where node_modules is absent,
// matching parity.test.js and detail.test.js. A red suite that means "you have not run npm install"
// trains people to ignore red suites.
let wct = null;
try {
  wct = require('../src/tools/wildcardtools');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = wct ? test : test.skip;
const wired = wct && stubbed ? test : test.skip;

// Real entries, copied from the server's vocabulary (server/utils/wildcardOptions.go), because the
// thing under test is whether a projection survives THIS prose rather than a short fixture.
const AMASS_TIMEOUT = {
  kind: 'int',
  group: 'Runtime',
  label: 'Enumeration time limit',
  unit: 'minutes',
  flag: '-timeout',
  provenance: 'measured',
  min: 1,
  max: 1440,
  placeholder: 'The wildcard runner hardcodes 60, which is SIXTY MINUTES. amass\'s own default of 0 '
    + 'means no wall-clock cap at all.',
  why: 'The single biggest lever on how long a wildcard scan blocks the workflow. The unit is '
    + 'MINUTES; --help says \'Number of minutes to let enumeration run before quitting\', and timing '
    + 'confirms it (-timeout 1 finished in 48s while -timeout 0 ran 73s to natural completion).',
  danger: 'Two-sided, and both sides are silent. Too small truncates: -timeout 1 returned 15 result '
    + 'lines where -timeout 0 returned 18 on the same target, both exit 0, with nothing marking the '
    + 'run incomplete. Too large, or 0, is unbounded.',
};

const CTL_SOURCE_MODE = {
  kind: 'enum',
  group: 'Sources',
  label: 'Certificate transparency source strategy',
  provenance: 'unverified',
  choices: ['crtsh_then_certspotter', 'crtsh_only', 'certspotter_only', 'union_both'],
  placeholder: 'Hardcoded crtsh_then_certspotter.',
  danger: 'NOT IMPLEMENTED. fetchCTLSubdomains at line 1153 has no mode parameter.',
};

const SUBFINDER_CONCURRENCY = {
  kind: 'int',
  group: 'Active resolution',
  label: 'Resolver concurrency',
  flag: '-t',
  provenance: 'measured',
  min: 1,
  max: 500,
  requires_key: 'activeOnly',
  placeholder: '10 concurrent goroutines.',
  danger: 'Help text is explicit that this is \'(-active only)\': it does absolutely nothing unless '
    + 'activeOnly is on, so the UI greys it out.',
};

// A tool's danger note is only useful if the headline survives compaction. These notes are written
// headline-first, and the headline is the part that stops a scan being ruined silently.
maybe('firstSentence keeps the headline and does not split inside a hostname or a version', () => {
  assert.strictEqual(
    wct.firstSentence('VERIFIED SILENT-NOTHING. `--providers bogus` exits 0 and prints zero URLs.'),
    'VERIFIED SILENT-NOTHING.',
  );
  // crt.sh, example.com and v4.2.0 all contain a full stop with no following whitespace.
  assert.strictEqual(
    wct.firstSentence('crt.sh returned HTTP 502 for every request in v4.2.0 against example.com. Then it stopped.'),
    'crt.sh returned HTTP 502 for every request in v4.2.0 against example.com.',
  );
  assert.strictEqual(wct.firstSentence(''), undefined);
  assert.strictEqual(wct.firstSentence(undefined), undefined);
});

maybe('firstSentence clips a sentence longer than the budget instead of returning all of it', () => {
  const long = `${'word '.repeat(200)}end.`;
  const out = wct.firstSentence(long, 120);
  assert.ok(out.length <= 124, `headline came back at ${out.length} characters`);
  assert.ok(out.endsWith('...'), 'a clipped headline has to say it was clipped');
});

// amass -timeout is in MINUTES and the runner passes 60, meaning one hour. A caller reading it as
// seconds and sending 300 has asked for a five-hour scan. The unit is the one field that must never
// be dropped for size, at either detail level.
maybe('the unit survives compaction, because minutes read as seconds is a five-hour scan', () => {
  const compact = wct.compactOption('timeoutMinutes', AMASS_TIMEOUT, false);
  assert.strictEqual(compact.unit, 'minutes');
  const full = wct.compactOption('timeoutMinutes', AMASS_TIMEOUT, true);
  assert.strictEqual(full.unit, 'minutes');
  for (const row of [compact, full]) {
    assert.strictEqual(row.min, 1, 'the floor is what stops 0 meaning unbounded');
    assert.strictEqual(row.max, 1440);
    assert.strictEqual(row.flag, '-timeout');
  }
});

// An option whose semantics nobody proved must not be presented as though someone did, so provenance
// is carried at both levels even though the prose that explains it is not.
maybe('provenance is never dropped, at either detail level', () => {
  for (const full of [false, true]) {
    assert.strictEqual(wct.compactOption('timeoutMinutes', AMASS_TIMEOUT, full).provenance, 'measured');
    assert.strictEqual(wct.compactOption('sourceMode', CTL_SOURCE_MODE, full).provenance, 'unverified');
  }
});

maybe('compact reports the headline and the size of the prose it left out', () => {
  const row = wct.compactOption('timeoutMinutes', AMASS_TIMEOUT, false);
  assert.ok(!('danger' in row), 'compact must not carry the full danger note');
  assert.ok(!('why' in row), 'compact must not carry the full why');
  assert.strictEqual(row.danger_headline, 'Two-sided, and both sides are silent.');
  assert.strictEqual(row.danger_chars, AMASS_TIMEOUT.danger.length);
  // This placeholder is 114 characters, inside the budget, so it comes back whole rather than as a
  // headline. That is where the unit trap is stated and it is worth every character.
  assert.strictEqual(row.default_behaviour, AMASS_TIMEOUT.placeholder);
  assert.ok(row.default_behaviour.includes('SIXTY MINUTES'));
  assert.ok(!('default_behaviour_chars' in row));
});

// Measured on the real registry: headlining all three prose fields put a compact nuclei listing at
// 26238 characters, over the cap and only 15% below full, which is not a compact mode. `why` argues
// for wanting an option; danger and default behaviour are what stop a mistake. So `why` keeps its
// size and loses its headline, which took the same listing to 20377.
maybe('why keeps its size but loses its headline, because it is the one that does not prevent a mistake', () => {
  const row = wct.compactOption('timeoutMinutes', AMASS_TIMEOUT, false);
  assert.strictEqual(row.why_chars, AMASS_TIMEOUT.why.length,
    'the size has to survive, or prose that exists cannot be told from prose never written');
  assert.ok(!('why_headline' in row));
  assert.ok('danger_headline' in row, 'the danger headline is the one that must never be dropped');
  assert.ok('default_behaviour' in row, 'and the default behaviour is the other one worth keeping');
});

maybe('full returns the measured prose, which is the only place the behaviour is written down', () => {
  const row = wct.compactOption('timeoutMinutes', AMASS_TIMEOUT, true);
  assert.strictEqual(row.danger, AMASS_TIMEOUT.danger);
  assert.strictEqual(row.why, AMASS_TIMEOUT.why);
  assert.strictEqual(row.default_behaviour, AMASS_TIMEOUT.placeholder);
  assert.ok(!('danger_chars' in row), 'full must not pay for the size fields as well as the prose');
  assert.ok(!('danger_headline' in row));
});

// requires_key is what makes a field inert. subfinder -t is documented "(-active only)" and does
// absolutely nothing while activeOnly is off, which is the answer to "I set it and nothing changed".
maybe('the keys that make an option inert survive compaction', () => {
  const row = wct.compactOption('resolverConcurrency', SUBFINDER_CONCURRENCY, false);
  assert.strictEqual(row.requires_key, 'activeOnly');
});

// ctl has no command line at all: it is native Go with hardcoded literals, so its options compose
// nothing and need runner code. An agent that cannot tell that from a normal option will believe it
// configured a scan it did not.
maybe('an option with no flag says so rather than looking like a normal setting', () => {
  const row = wct.compactOption('sourceMode', CTL_SOURCE_MODE, false);
  assert.ok(!('flag' in row));
  assert.match(row.no_flag, /composes no command-line argument/);
  const withFlag = wct.compactOption('timeoutMinutes', AMASS_TIMEOUT, false);
  assert.ok(!('no_flag' in withFlag), 'a flagged option must not carry the warning');
});

// A short choice list is worth its characters; the 50 subfinder source names are not, until asked for.
maybe('a long choice list is counted in compact and returned in full', () => {
  const sources = Array.from({ length: 50 }, (_, i) => `source${i}`);
  const meta = { kind: 'list', group: 'Sources', label: 'Only use these sources', flag: '-s',
    provenance: 'measured', choices: sources };
  const compact = wct.compactOption('sources', meta, false);
  assert.ok(!('choices' in compact));
  assert.strictEqual(compact.choice_count, 50);
  assert.deepStrictEqual(wct.compactOption('sources', meta, true).choices, sources);

  // Four choices are cheaper than the sentence explaining where to find them.
  assert.deepStrictEqual(wct.compactOption('sourceMode', CTL_SOURCE_MODE, false).choices,
    CTL_SOURCE_MODE.choices);
});

// nuclei carries the largest vocabulary in this registry, 43 options. A compact listing of it has to
// be small enough to actually return, or the output cap turns the answer into nothing usable at all.
maybe('a forty-four option compact listing fits the output budget', () => {
  const rows = Array.from({ length: 44 }, (_, i) => wct.compactOption(`option${i}`, AMASS_TIMEOUT, false));
  const chars = JSON.stringify(rows, null, 2).length;
  // Deliberately a literal rather than ROW_BUDGET: this asserts that compact IS compact, which has to
  // stay true independently of where the downgrade threshold happens to sit.
  assert.ok(chars < 25000, `forty-four compact options serialise to ${chars} characters`);
});

// MEASURED DEFECT: with headline and size emitted unconditionally, a compact owned-flag listing for
// nuclei came to 11195 characters against 10473 for the same list in full. Most owned-flag reasons
// are a single short sentence, so the headline reproduced the whole note and the size field was pure
// overhead. Compact costing more than full is a compact mode that does nothing.
maybe('compact never costs more than full, whatever the prose is like', () => {
  // Two short sentences. Headlining this would return the first four words and a size field, which
  // costs about what the whole note costs and tells the caller less.
  const short = 'Output file path. The runner captures stdout.';
  const row = wct.compactOwnedFlag('-o', short, false);
  assert.strictEqual(row.reason, short, 'a note that already fits the budget is returned whole');
  assert.ok(!('reason_headline' in row), 'a headline is only worth its field name when it saves size');
  assert.ok(!('reason_chars' in row), 'and its size is then a field saying what is already visible');

  const long = 'BROKEN IN THIS BUILD, verified twice. `enum -v -exclude Bing,Google,Yahoo` still '
    + 'logged Querying Bing, Querying Google and Querying Yahoo, and all 45 sources ran. Exit 0, no '
    + 'warning. A data-source picker built on this would be a control that does nothing, which is '
    + 'why there is not one.';
  const clipped = wct.compactOwnedFlag('-exclude', long, false);
  assert.strictEqual(clipped.reason_headline, 'BROKEN IN THIS BUILD, verified twice.');
  assert.strictEqual(clipped.reason_chars, long.length,
    'the field name says there is more, and the size says how much');
  assert.ok(!('reason' in clipped));

  // The same rule applies to an option's prose, where the field name carries the distinction.
  const oneLine = { kind: 'bool', group: 'Advanced', label: 'Disable update check', flag: '-duc',
    provenance: 'measured', danger: 'Low risk.' };
  const opt = wct.compactOption('disableUpdateCheck', oneLine, false);
  assert.strictEqual(opt.danger, 'Low risk.');
  assert.ok(!('danger_chars' in opt));
});

// The alternative to this guard is a response the caller never receives. detail:"full" for all 43
// nuclei options measures 30845 characters against the real registry, so it has to come back as
// compact rows WITH THE REASON rather than as a silently clipped list or as nothing at all.
maybe('full downgrades to compact when it would not fit, and says so', () => {
  const keys = Array.from({ length: 44 }, (_, i) => `option${i}`);
  const project = (key, full) => wct.compactOption(key, AMASS_TIMEOUT, full);

  const fits = wct.projectRows(keys.slice(0, 3), project, true);
  assert.strictEqual(fits.detail, 'full');
  assert.ok(!('downgraded_from_full' in fits));
  assert.strictEqual(typeof fits.rows[0].danger, 'string', 'a listing that fits keeps the prose');

  const overflows = wct.projectRows(keys, project, true);
  assert.strictEqual(overflows.detail, 'compact');
  assert.match(overflows.downgraded_from_full, /past the output cap/);
  assert.match(overflows.downgraded_from_full, /group, provenance or option/,
    'a downgrade has to say how to get what was asked for');
  assert.strictEqual(overflows.rows.length, 44, 'downgrading is not the same as dropping rows');
  assert.ok(!('danger' in overflows.rows[0]));
  assert.ok('danger_headline' in overflows.rows[0]);

  // A compact request is never downgraded, because it is already the floor.
  const compact = wct.projectRows(keys, project, false);
  assert.strictEqual(compact.detail, 'compact');
  assert.ok(!('downgraded_from_full' in compact));
});

// The registry entry says whether a tool runs in a long-lived container or as `docker run --rm`. That
// is not trivia: amass runs as an ephemeral image with NO volume mount, so every file-path flag it
// has is unreachable, which is why they are owned rather than shipped broken.
maybe('a tool row says how it runs, and sizes the notes rather than carrying them', () => {
  const tool = {
    key: 'amass', name: 'Amass', step: 1, phase: 'Subdomain discovery',
    image: 'caffix/amass', binary: 'amass enum', version: 'v4.2.0',
    invocation: 'server/utils/amassUtils.go:605 ExecuteAndParseAmassScan',
    groups: ['Runtime'], options: { timeoutMinutes: AMASS_TIMEOUT },
    owned_flags: { '-silent': 'BLACKLISTED.', '-exclude': 'BROKEN IN THIS BUILD.' },
    runner_reads_settings: false,
    notes: 'x'.repeat(4000),
  };
  const compact = wct.compactTool(tool, false);
  assert.strictEqual(compact.runs_as_ephemeral_image, 'caffix/amass');
  assert.ok(!('runs_in_container' in compact));
  assert.strictEqual(compact.option_count, 1);
  assert.strictEqual(compact.owned_flag_count, 2);
  assert.strictEqual(compact.notes_chars, 4000);
  assert.ok(!('notes' in compact));
  assert.strictEqual(compact.runner_reads_settings, false,
    'false is an answer: nothing reads this store yet and hiding that is how a caller comes to '
    + 'believe a scan was configured');

  const full = wct.compactTool(tool, true);
  assert.strictEqual(full.notes.length, 4000);
  assert.ok(!('notes_chars' in full));
});

maybe('a tool with an empty vocabulary keeps the sentence that says why', () => {
  const assetfinder = {
    key: 'assetfinder', name: 'Assetfinder', step: 3, phase: 'Subdomain discovery',
    container: 'ars0n-framework-v2-assetfinder-1',
    invocation: 'server/utils/subdomainScrapingUtils.go:574',
    groups: [], options: {}, owned_flags: { '-subs-only': 'The tool\'s ONLY flag.' },
    runner_reads_settings: false,
    limitation: 'AN EMPTY VOCABULARY IS THE MEASURED ANSWER, NOT A GAP.',
  };
  const row = wct.compactTool(assetfinder, false);
  assert.strictEqual(row.option_count, 0, 'zero is an answer and must not be dropped as empty');
  assert.match(row.limitation, /MEASURED ANSWER/);
  assert.strictEqual(row.runs_in_container, 'ars0n-framework-v2-assetfinder-1');
});

// An owned flag's reason is the diagnostic. -exclude is absent because it is BROKEN in the installed
// build, not because nobody added it, and an agent that cannot read that will keep asking for it.
maybe('an owned flag carries its reason, headlined in compact and whole in full', () => {
  const reason = 'BROKEN IN THIS BUILD, verified twice. `enum -v -exclude Bing,Google,Yahoo` still '
    + 'logged Querying Bing, Querying Google and Querying Yahoo, and all 45 sources ran. Exit 0, no '
    + 'warning. A data-source picker built on this would be a control that does nothing.';
  const compact = wct.compactOwnedFlag('-exclude', reason, false);
  assert.strictEqual(compact.flag, '-exclude');
  assert.strictEqual(compact.reason_headline, 'BROKEN IN THIS BUILD, verified twice.');
  assert.strictEqual(compact.reason_chars, reason.length);
  assert.strictEqual(wct.compactOwnedFlag('-exclude', reason, true).reason, reason);
});

// The refusal reason is the whole diagnostic: it names which key was wrong and what could have been
// said instead. apiPost throws it inside a generic message, and losing it there would leave a caller
// with a 400 and nothing else.
maybe('a refusal is recovered from the thrown API error, verbatim', () => {
  const body = JSON.stringify({
    error: 'framework_owned',
    message: '-silent is set by the framework: BLACKLISTED. Measured: exit 0 with zero bytes on '
      + 'stdout AND zero bytes on stderr.',
  });
  const parsed = wct.parseRefusal(new Error(
    `API POST /wildcard-tools/abc/amass/settings failed (400): ${body}`));
  assert.strictEqual(parsed.http_status, 400);
  assert.strictEqual(parsed.refusal_code, 'framework_owned');
  assert.match(parsed.reason, /zero bytes on stdout AND zero bytes on stderr/);
});

maybe('a non-JSON error body is still returned rather than swallowed', () => {
  const parsed = wct.parseRefusal(new Error('API POST /x failed (500): upstream exploded'));
  assert.strictEqual(parsed.http_status, 500);
  assert.strictEqual(parsed.reason, 'upstream exploded');
  assert.ok(!('refusal_code' in parsed));
});

maybe('an error that is not an API failure is not mistaken for a refusal', () => {
  assert.strictEqual(wct.parseRefusal(new Error('fetch failed')), null);
  assert.strictEqual(wct.parseRefusal(undefined), null);
});

maybe('save_settings refuses a missing argument without a round trip to the API', async () => {
  const noTool = await wct.manageWildcardTools({
    action: 'save_settings', target_id: '00000000-0000-0000-0000-000000000000',
    settings: { timeoutMinutes: 30 },
  });
  assert.match(noTool.error, /tool is required/);

  const noSettings = await wct.manageWildcardTools({
    action: 'save_settings', target_id: '00000000-0000-0000-0000-000000000000', tool: 'amass',
  });
  assert.match(noSettings.error, /settings is required/);
  assert.match(noSettings.error, /not by flag/,
    'the error is the place to say the keys are option keys rather than flags');
});

maybe('the action list offers exactly the five documented actions', () => {
  const actions = [...wct.manageWildcardToolsSchema.shape.action._def.values];
  assert.deepStrictEqual(actions.sort(),
    ['option_reference', 'owned_flags', 'save_settings', 'settings', 'tools']);
});

maybe('detail exists, offers two levels, and defaults to compact', () => {
  const detail = wct.manageWildcardToolsSchema.shape.detail;
  assert.ok(detail, 'without a detail parameter the whole vocabulary is the only answer available');
  assert.deepStrictEqual([...detail._def.innerType._def.values].sort(), ['compact', 'full']);
  assert.ok(detail.isOptional(), 'compact has to be the default, not something a caller opts into');
});

// A closed enum of tool keys here would be a second copy of something the server owns, and a tool
// added on the server would be unreachable over MCP until this file was edited too. The handler
// validates against the live registry instead, and answers with the registry's own keys.
maybe('the tool parameter is not a second copy of the server registry', () => {
  const tool = wct.manageWildcardToolsSchema.shape.tool;
  assert.strictEqual(tool._def.innerType._def.typeName, 'ZodString');
});

maybe('replace and settings exist so a merge is the default and null can remove a key', () => {
  const shape = wct.manageWildcardToolsSchema.shape;
  assert.ok(shape.replace.isOptional(), 'merge has to be what a caller gets when it did not ask');
  assert.ok(shape.settings.isOptional());
  assert.match(shape.settings.description, /null value removes that key/);
});

// ---------------------------------------------------------------------------------------------
// The actions themselves, against the stubbed API installed at the top of this file.
// ---------------------------------------------------------------------------------------------

wired('tools returns the registry and names the tools whose runner does not read it', async () => {
  const out = await wct.manageWildcardTools({ action: 'tools' });
  assert.deepStrictEqual(out.tools.map((t) => t.tool), ['amass', 'httpx']);
  assert.strictEqual(out.tools[0].runs_as_ephemeral_image, 'caffix/amass');
  assert.match(out.pending_wiring, /amass, httpx/,
    'a tool whose runner does not read the store must be named, or a caller reads a saved setting '
    + 'as applied behaviour');
  assert.match(out.tools_with_no_vocabulary, /answer, not a gap/,
    'httpx has zero options on purpose and the response has to distinguish that from an omission');
  assert.match(out.note, /same settings the Wildcard Settings screen writes/);
});

// The runners are being wired one at a time. A fixed sentence saying "nothing reads this store"
// starts true and silently becomes a lie the moment one is wired, which is the exact failure this
// whole registry exists to prevent, so the note is derived and names the tools it applies to.
maybe('the wiring note names tools rather than making a claim that can go stale', () => {
  const some = wct.pendingWiringNote([
    { tool: 'gau', runner_reads_settings: true },
    { tool: 'amass', runner_reads_settings: false },
  ]);
  assert.match(some, /for: amass/);
  assert.ok(!/gau/.test(some), 'a wired tool must not be listed as unwired');

  assert.strictEqual(
    wct.pendingWiringNote([{ tool: 'gau', runner_reads_settings: true }]),
    undefined,
    'once every tool in the answer is wired the sentence has to disappear entirely',
  );
});

wired('an unknown tool is answered with the registry own keys, not a schema error', async () => {
  const out = await wct.manageWildcardTools({ action: 'tools', tool: 'amasss' });
  assert.match(out.error, /No Wildcard workflow tool called amasss/);
  assert.match(out.error, /amass, httpx/, 'the error has to say what could have been said instead');
});

wired('option_reference without a tool is an index, not the whole vocabulary', async () => {
  const out = await wct.manageWildcardTools({ action: 'option_reference' });
  assert.deepStrictEqual(out.tools[0].option_keys, ['blacklistNames', 'maxDepth', 'timeoutMinutes']);
  assert.ok(!out.tools[0].options, 'the index must not carry the options themselves');
  assert.match(out.note, /does not fit the output cap/);
});

wired('option_reference filters by group and by provenance', async () => {
  const byGroup = await wct.manageWildcardTools({
    action: 'option_reference', tool: 'amass', group: 'scope filters',
  });
  assert.strictEqual(byGroup.returned, 1, 'group matching is case-insensitive');
  assert.strictEqual(byGroup.options[0].option, 'blacklistNames');
  assert.strictEqual(byGroup.option_count, 3, 'the unfiltered count still has to be visible');

  const byProvenance = await wct.manageWildcardTools({
    action: 'option_reference', tool: 'amass', provenance: 'unverified',
  });
  assert.deepStrictEqual(byProvenance.options.map((o) => o.option), ['maxDepth']);

  const badGroup = await wct.manageWildcardTools({
    action: 'option_reference', tool: 'amass', group: 'Nope',
  });
  assert.match(badGroup.error, /Runtime, Scope Filters/, 'name the groups that do exist');
});

wired('one option comes back in full whatever detail says', async () => {
  const out = await wct.manageWildcardTools({
    action: 'option_reference', tool: 'amass', option: 'timeoutMinutes',
  });
  assert.strictEqual(out.option.unit, 'minutes');
  assert.strictEqual(out.option.danger, 'Too small truncates the scan silently.');
  const missing = await wct.manageWildcardTools({
    action: 'option_reference', tool: 'amass', option: 'timeout',
  });
  assert.match(missing.error, /blacklistNames, maxDepth, timeoutMinutes/);
});

// The measured trap this exists to stop: a caller sends "-silent" because that is the flag name it
// knows, and the server refuses it with the reason. Losing that reason leaves a 400 and nothing else.
wired('a refusal comes back with the server reason verbatim and nothing is saved', async () => {
  const out = await wct.manageWildcardTools({
    action: 'save_settings', tool: 'amass', settings: { '-silent': true },
  });
  assert.strictEqual(out.saved, false);
  assert.strictEqual(out.refused, true);
  assert.strictEqual(out.refusal_code, 'framework_owned');
  assert.strictEqual(out.http_status, 400);
  assert.match(out.reason, /zero bytes on stdout AND zero bytes on stderr/,
    'the measured reason is the whole diagnostic and has to survive intact');
  assert.match(out.what_this_means, /owned_flags/, 'and it has to say where to look next');
});

wired('a successful save reports the arguments it would compose', async () => {
  const out = await wct.manageWildcardTools({
    action: 'save_settings', tool: 'amass', settings: { timeoutMinutes: 30 },
  });
  assert.strictEqual(out.saved, true);
  assert.deepStrictEqual(out.would_add_args, ['-timeout', '30']);
  assert.match(out.pending_wiring, /does not read this store yet/);
});

// A null value REMOVES a key. Stripping it here would turn a deletion into a no-op, and the caller
// would be told the setting was cleared while it was still stored.
wired('a null value reaches the server rather than being filtered out on the way', async () => {
  POSTED.length = 0;
  await wct.manageWildcardTools({
    action: 'save_settings', tool: 'amass', settings: { timeoutMinutes: null, blacklistNames: ['x'] },
  });
  assert.strictEqual(POSTED.length, 1);
  const sent = POSTED[0];
  assert.strictEqual(sent.path, '/wildcard-tools/active-target/amass/settings');
  assert.ok('timeoutMinutes' in sent.body.settings, 'the key has to survive to the server');
  assert.strictEqual(sent.body.settings.timeoutMinutes, null);
  assert.strictEqual(sent.body.replace, false,
    'merge is the default, so sending one setting never blanks the rest');

  POSTED.length = 0;
  await wct.manageWildcardTools({
    action: 'save_settings', tool: 'amass', settings: { timeoutMinutes: 30 }, replace: true,
  });
  assert.strictEqual(POSTED[0].body.replace, true, 'and replace is passed through when asked for');
});

wired('settings shows the composed arguments and names a stored key nothing reads', async () => {
  const out = await wct.manageWildcardTools({ action: 'settings', tool: 'amass' });
  assert.strictEqual(out.scope_target_id, 'active-target', 'the active target is resolved for you');
  assert.deepStrictEqual(out.would_add_args, ['-timeout', '30']);
  assert.deepStrictEqual(out.stored_but_unknown, ['timeoutMinute'],
    'a stored key outside the vocabulary composes nothing, so it must not sit there looking set');
  assert.match(out.stored_but_unknown_warning, /Send them as null to remove them/);
  assert.ok(!out.options, 'compact settings must not repeat the whole vocabulary');
  assert.strictEqual(out.notes_chars, FIXTURE.tools[0].notes.length);
});

// Repeating all 43 nuclei options in a settings response measured 25730 characters, for a question
// about the keys somebody had actually configured.
wired('settings at full describes the keys that are set, not every key that exists', async () => {
  const out = await wct.manageWildcardTools({ action: 'settings', tool: 'amass', detail: 'full' });
  assert.deepStrictEqual(out.configured_options.map((o) => o.option), ['timeoutMinutes'],
    'timeoutMinute is stored but is not in the vocabulary, so it has no entry to describe');
  assert.strictEqual(out.configured_options[0].danger, 'Too small truncates the scan silently.');
  assert.strictEqual(out.notes, FIXTURE.tools[0].notes);
});

// ctl and metadata carry options with no flag at all, so composing nothing is a legitimate result.
// An empty array is dropped as saying nothing, which would make "these settings add no arguments"
// look identical to "the response never worked it out".
wired('an empty would_add_args survives, because composing nothing is an answer', async () => {
  POSTED.length = 0;
  const saved = await wct.manageWildcardTools({
    action: 'save_settings', tool: 'amass', settings: { blacklistNames: [] },
  });
  assert.ok(Array.isArray(saved.would_add_args), 'would_add_args must always be present');

  const read = await wct.manageWildcardTools({ action: 'settings', tool: 'amass' });
  assert.ok(Array.isArray(read.would_add_args));
});

wired('a provenance filter that matches nothing answers with the counts', async () => {
  const out = await wct.manageWildcardTools({
    action: 'option_reference', tool: 'amass', provenance: 'runner',
  });
  assert.strictEqual(out.returned, 0);
  assert.match(out.message, /No Amass option was established as "runner"/);
  assert.deepStrictEqual(out.options_by_provenance, { measured: 2, unverified: 1 },
    'the counts are the question behind the filter, and an absent options key reads as a bug');
});

wired('owned_flags carries the reason a flag is not an option', async () => {
  const out = await wct.manageWildcardTools({ action: 'owned_flags', tool: 'amass' });
  assert.strictEqual(out.owned_flags[0].flag, '-silent');
  assert.match(out.owned_flags[0].reason, /BLACKLISTED/);
  assert.match(out.note, /NOT options/);
  assert.match(out.note, /never appears in both lists/,
    'an option and an owned flag naming one flag 400s every save with no visible symptom');
});
