const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// A stand-in for the four Go handlers in server/utils/companySettings.go, installed BEFORE the tool
// module is required so the actions themselves are exercised rather than only their projections. The
// shapes here are the ones those handlers build, including the {error, message} body writeJSONError
// sends with a 400, and the fields that are company specific and have no Wildcard equivalent:
// settings_store, settings_stores, settings_store_note, target_selection_stores, advisories.
//
// node --test runs one process per file, so this stub cannot reach another suite.
//
// The registry fixture is deliberately small and local, and its OPTION PROSE IS REAL, copied from
// server/utils/companyOptions*.go. Loading the whole registry would make this suite depend on a
// running server, which is the opposite of what it is for; using invented one-line prose would make
// the size assertions meaningless, since the thing under test is whether a projection survives THIS
// prose.
const IP_PORT_HOST_DISCOVERY = {
  kind: 'list',
  group: 'Host Discovery',
  label: 'Ports used to decide a host is alive',
  provenance: 'measured',
  min_items: 1,
  placeholder: '80, 443, 22, 21, 25, 53, 110, 995, 993, 143. isHostAlive tries them in order and '
    + 'returns true on the first successful connect.',
  why: 'This is the gate. An address that does not answer on one of these ports is never port '
    + 'scanned, never probed for a web service and never appears in discovered_live_ips. Every other '
    + 'setting in this tool operates on what this list lets through.',
  danger: 'A LIVE HOST ON A PORT OUTSIDE THIS LIST IS RECORDED AS DEAD AND NOTHING SAYS SO. Not '
    + 'hypothetical and not avoided by the default: 8080, 8443 and 3000 are all in webPorts and NONE '
    + 'of them is here, so a host serving only on 8443 is discarded before the port scanner that '
    + 'would have found it ever runs. An EMPTY list makes isHostAlive return false for every '
    + 'address, which is a scan that reports success with zero live IPs, so at least one port is '
    + 'required.',
};

const IP_PORT_PROBE_TIMEOUT = {
  kind: 'int',
  group: 'Host Discovery',
  label: 'Connect timeout per host-discovery port',
  unit: 'milliseconds',
  provenance: 'measured',
  min: 100,
  max: 10000,
  placeholder: '1000 (one second). Applied PER PORT, not per host.',
  why: 'It is the deadline that decides alive from dead.',
  danger: 'TWO-SIDED AND BOTH SIDES ARE SILENT. Too low and a live host whose SYN-ACK arrives at '
    + '1.2s is recorded as dead, with no retry, no log, and no distinction from a host that refused. '
    + 'Too high and the cost multiplies by the length of hostDiscoveryPorts because the loop is '
    + 'sequential: measured, a black-holed address costs exactly 10.004s at the 1s default.',
};

const GITHUB_ALL_DOMAINS = {
  kind: 'bool',
  group: 'Result Breadth',
  label: 'Emit endpoints on all domains, not only ones matching the company',
  flag: '-a',
  provenance: 'unverified',
  inert_when_key: 'script',
  inert_when_values: ['github-subdomains.py'],
  placeholder: 'Off. For every absolute URL found, the script re-runs the company regex against the '
    + 'URL\'s netloc and skips anything that does not match.',
  why: 'Arguably the single most valuable flag for THIS phase.',
  danger: 'Untargeted. With -a the output is every URL in every file that mentioned the company, so '
    + 'the framework\'s extractor will harvest CDN hosts, package registries and documentation sites '
    + 'and store them as COMPANY ROOT DOMAINS. It also does not exist on github-subdomains.py, so it '
    + 'is inert when that script is selected.',
};

const SHODAN_DELAY = {
  kind: 'float',
  group: 'Reliability',
  label: 'Pause between Shodan queries',
  unit: 'seconds',
  provenance: 'runner',
  min: 0,
  max: 60,
  placeholder: '1 second, hardcoded as time.Sleep(1 * time.Second) at the END of every loop '
    + 'iteration INCLUDING the last one, so every scan pays a second it does not need.',
  why: 'Shodan\'s documented API limit is one request per second.',
  danger: 'Lowering it to 0 invites 429. A 429 does not error the scan: it breaks out of the query '
    + 'loop, abandoning the remaining queries, and the scan is still stored as \'success\' with a '
    + 'partial domain set and no record that anything was skipped.',
};

const SHODAN_QUERIES = {
  kind: 'list',
  group: 'Queries',
  label: 'Which Shodan queries to run',
  choices: ['ssl.cert.subject.O', 'http.title', 'http.html', 'org'],
  provenance: 'runner',
  min_items: 1,
  placeholder: 'All four, hardcoded and always in this order.',
  danger: 'AN EMPTY LIST IS REFUSED ON SAVE. With no queries the loop body never executes, the '
    + 'domain list stays nil, and the scan stores zero domains with status \'success\'.',
};

const FIXTURE = {
  workflow: 'company',
  provenance_meaning: { measured: 'Probed against the installed container or the live API.' },
  owned_flags_meaning: 'Flags and values the runner sets itself.',
  no_command_line_note: 'Five of these tools have no command line at all: the on-prem IP/port '
    + 'scanner is Go inside the api container, and crt.sh, SecurityTrails, Shodan and Censys are '
    + 'single HTTP requests.',
  settings_stores: {
    default: 'company_tool_settings',
    shared: { nuclei: 'wildcard_tool_settings' },
    note: 'nuclei is the one tool whose settings do NOT live in company_tool_settings.',
  },
  target_selection_stores: {
    ip_port_scan: {
      table: '',
      owns_keys: [],
      owned_flags: ['consolidated_network_ranges (the target set)'],
      note: 'No config table exists. The input worth naming is amass_intel_configs.'
        + 'selected_network_ranges, which LOOKS like it filters this scan\'s targets and is not read '
        + 'by it.',
    },
    github_recon: undefined,
    nuclei: {
      table: 'nuclei_configs',
      owns_keys: ['targets', 'templates'],
      owned_flags: ['-list', '-u', '-t', '-tags'],
      note: 'TEMPLATES AND TARGETS stay with nuclei_configs and the Configure modal; only ENGINE '
        + 'FLAGS are configurable here.',
    },
  },
  tools: [
    {
      key: 'ip_port_scan',
      name: 'Discover Live Web Servers (On-Prem)',
      step: 3,
      phase: 'Discover Live Web Servers (On-Prem)',
      version: 'Not applicable: first-party Go inside the api container, not a packaged tool.',
      invocation: 'server/utils/ipPortScanUtils.go ExecuteIPPortScan',
      groups: ['Host Discovery', 'Port Scanning'],
      options: {
        hostDiscoveryPorts: IP_PORT_HOST_DISCOVERY,
        hostProbeTimeout: IP_PORT_PROBE_TIMEOUT,
      },
      owned_flags: {
        'consolidated_network_ranges (the target set)': 'THE TARGET. getConsolidatedNetworkRanges '
          + 'selects EVERY range the Company workflow has discovered for the scope target.',
      },
      runner_reads_settings: false,
      limitation: 'THERE IS NO NMAP AND THERE IS NO COMMAND LINE, so nothing here is a flag. It is '
        + 'Go using net.DialTimeout: no SYN scan, no ICMP, no UDP, no OS detection, no scripts, no '
        + 'retries, no rate limiting, and no way to cancel a running scan.',
      notes: 'x'.repeat(3200),
    },
    {
      key: 'github_recon',
      name: 'GitHub Recon Tools',
      step: 6,
      phase: 'Root Domain Discovery (API Key)',
      container: 'ars0n-framework-v2-github-recon-1',
      binary: 'python3 /app/github-search/github-endpoints.py',
      invocation: 'server/utils/githubReconUtils.go ExecuteGitHubReconScan',
      groups: ['Result Breadth', 'Search Seed'],
      options: {
        allDomains: GITHUB_ALL_DOMAINS,
        searchSeedMode: {
          kind: 'enum',
          group: 'Search Seed',
          label: 'What is passed to -d',
          choices: ['alphanumericStrip', 'companyNameVerbatim', 'rootDomainFromScope'],
          provenance: 'measured',
          placeholder: 'alphanumericStrip.',
          danger: 'An empty or one-character seed makes GitHub code search match effectively '
            + 'everything or nothing, and the script exits 0 either way.',
        },
      },
      owned_flags: { '-t': 'THE CREDENTIAL. Supplied from the framework API key store.' },
      runner_reads_settings: false,
      notes: 'y'.repeat(2400),
    },
    {
      key: 'shodan_company',
      name: 'Shodan',
      step: 7,
      phase: 'Root Domain Discovery (API Key)',
      invocation: 'server/utils/shodanCompanyUtils.go ExecuteShodanCompanyScan',
      groups: ['Queries', 'Reliability'],
      options: { enabledQueries: SHODAN_QUERIES, perQueryDelaySeconds: SHODAN_DELAY },
      owned_flags: {
        'the unencoded query string': 'MEASURED DEFECT, NOT A SETTING. A two-word company returns '
          + 'HTTP 400 with an empty body and the runner swallows it with continue.',
      },
      runner_reads_settings: false,
      limitation: 'NO COMMAND LINE: four HTTP GETs to api.shodan.io per scan, so nothing here is a '
        + 'flag.',
    },
    {
      key: 'nuclei',
      name: 'Nuclei (engine flags)',
      step: 13,
      phase: 'Vulnerability scanning',
      container: 'ars0n-framework-v2-nuclei-1',
      binary: 'nuclei',
      invocation: 'server/utils/nucleiUtils.go executeNucleiScan',
      groups: ['Rate & Concurrency'],
      options: {
        rateLimit: {
          kind: 'int',
          group: 'Rate & Concurrency',
          label: 'Requests per second',
          flag: '-rl',
          provenance: 'measured',
          min: 1,
          max: 1000,
          placeholder: '150.',
          danger: 'Set low it silently lengthens the scan past any deadline around it.',
        },
      },
      owned_flags: { '-u': 'THE TARGET.' },
      runner_reads_settings: true,
      delegates_to: 'wildcard_tool_settings (tool \'nuclei\')',
    },
  ],
};

// What the tool actually sent, recorded by the stub. It has to be captured HERE rather than by
// reassigning api.apiPost later, because the tool module destructures the two functions at import
// time and holds the references.
const POSTED = [];

const SETTINGS_BY_TOOL = {
  ip_port_scan: {
    settings: { hostProbeTimeout: 3000, hostProbeTimeoutMs: 3000 },
    would_add_args: [],
    advisories: {
      webPorts: 'Ports 8080, 8443, 3000 are scanned in detail but are NOT in hostDiscoveryPorts, so '
        + 'a host that listens only on one of them is recorded as DEAD before the port scan ever '
        + 'runs. Measured: this is already true at the defaults.',
    },
    settings_store: 'company_tool_settings',
    pending_wiring: 'Stored, but server/utils/ipPortScanUtils.go ExecuteIPPortScan does not read '
      + 'this store yet, so the next scan will use the hardcoded behaviour.',
  },
  nuclei: {
    settings: { rateLimit: 50 },
    would_add_args: ['-rl', '50'],
    settings_store: 'wildcard_tool_settings',
    settings_store_note: 'These settings are stored in wildcard_tool_settings, not '
      + 'company_tool_settings, because ONE nuclei runner serves both workflows and it loads '
      + 'settings by scope target id alone without ever reading the target\'s type.',
  },
};

let stubbed = null;
try {
  const apiPath = require.resolve('../src/api.js');
  const stub = {
    apiGet: async (apiRoute) => {
      if (apiRoute === '/company-tools') return FIXTURE;
      if (apiRoute === '/scopetarget/read') return [{ id: 'active-target', active: true }];
      const one = apiRoute.match(/^\/company-tools\/([^/]+)\/([^/]+)\/settings$/);
      if (one) {
        const tool = FIXTURE.tools.find((t) => t.key === one[2]);
        const stored = SETTINGS_BY_TOOL[one[2]] || { settings: {}, would_add_args: [] };
        return {
          tool: tool.key,
          tool_name: tool.name,
          step: tool.step,
          phase: tool.phase,
          invocation: tool.invocation,
          groups: tool.groups,
          options: tool.options,
          owned_flags: tool.owned_flags,
          runner_reads_settings: tool.runner_reads_settings,
          notes: tool.notes,
          limitation: tool.limitation,
          delegates_to: tool.delegates_to,
          target_selection: FIXTURE.target_selection_stores[tool.key],
          ...stored,
        };
      }
      if (/^\/company-tools\/[^/]+\/settings$/.test(apiRoute)) {
        return {
          scope_target_id: 'active-target',
          tools: FIXTURE.tools.map((t) => {
            const stored = SETTINGS_BY_TOOL[t.key] || { settings: {} };
            return {
              tool: t.key,
              tool_name: t.name,
              step: t.step,
              phase: t.phase,
              settings: stored.settings,
              configured_count: Object.keys(stored.settings).length,
              option_count: Object.keys(t.options).length,
              runner_reads_settings: t.runner_reads_settings,
              settings_store: stored.settings_store || 'company_tool_settings',
              limitation: t.limitation,
              advisories: stored.advisories,
            };
          }),
        };
      }
      throw new Error(`API GET ${apiRoute} failed (404): not found`);
    },
    apiPost: async (apiRoute, body) => {
      POSTED.push({ path: apiRoute, body });
      const keys = Object.keys(body.settings || {});
      if (keys.includes('resolvers')) {
        throw new Error(`API POST ${apiRoute} failed (400): ${JSON.stringify({
          error: 'unsafe_value',
          message: 'resolvers may not be a file path (/app/resolvers.txt): the path would resolve '
            + 'inside the tool\'s container and the framework copies nothing in. MEASURED on dnsx: a '
            + 'nonexistent -r file exits 0 with zero bytes of stdout and no error, and the domain is '
            + 'stored as successfully scanned with no DNS records.',
        })}`);
      }
      if (keys.includes('-silent')) {
        throw new Error(`API POST ${apiRoute} failed (400): ${JSON.stringify({
          error: 'framework_owned',
          message: '-silent is set by the framework: DOES NOT EXIST ON THIS SUBCOMMAND. Measured: '
            + '`intel -silent` exits 1 with \'flag provided but not defined\'.',
        })}`);
      }
      return {
        saved: true,
        tool: 'ip_port_scan',
        settings: body.settings,
        settings_store: 'company_tool_settings',
        would_add_args: [],
        advisories: SETTINGS_BY_TOOL.ip_port_scan.advisories,
        advisory_warning: 'Ports 8080, 8443, 3000 are scanned in detail but are NOT in '
          + 'hostDiscoveryPorts.',
        pending_wiring: SETTINGS_BY_TOOL.ip_port_scan.pending_wiring,
      };
    },
  };
  require.cache[apiPath] = { id: apiPath, filename: apiPath, loaded: true, exports: stub };
  stubbed = true;
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

// The module imports zod, and the repo's tests skip rather than fail where node_modules is absent,
// matching parity.test.js and wildcardtools.test.js. A red suite that means "you have not run npm
// install" trains people to ignore red suites.
let cct = null;
try {
  cct = require('../src/tools/companytools');
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}
const maybe = cct ? test : test.skip;
const wired = cct && stubbed ? test : test.skip;

// ---------------------------------------------------------------------------------------------
// The two fields that exist ONLY for this registry. No Wildcard option sets either, which is why
// the shared projection does not carry them and why they have to be added here.
// ---------------------------------------------------------------------------------------------

// An empty hostDiscoveryPorts makes isHostAlive return false for every address; an empty webPorts
// makes the port scan find nothing; an empty enabledQueries never enters the query loop. All three
// were measured to be stored as a successful scan with zero results, so the floor is enforced at
// save time. A caller that cannot see the floor will try to disable a phase by emptying its list and
// be refused with no idea what the problem was.
maybe('the list floor survives compaction, because an empty list is a scan that finds nothing', () => {
  for (const full of [false, true]) {
    assert.strictEqual(cct.companyOption('hostDiscoveryPorts', IP_PORT_HOST_DISCOVERY, full).min_items, 1);
    assert.strictEqual(cct.companyOption('enabledQueries', SHODAN_QUERIES, full).min_items, 1);
  }
  // An option without one must not grow a phantom floor.
  assert.ok(!('min_items' in cct.companyOption('hostProbeTimeout', IP_PORT_PROBE_TIMEOUT, false)));
});

// github-subdomains.py has NO -a and NO -r. The gating value is a SCRIPT NAME rather than a switch
// being on, which a plain truthy inert_when_key cannot express, so the values themselves have to
// reach the caller or "why did my -a do nothing" is unanswerable.
maybe('the values that make an option inert survive compaction, not just the key', () => {
  for (const full of [false, true]) {
    const row = cct.companyOption('allDomains', GITHUB_ALL_DOMAINS, full);
    assert.strictEqual(row.inert_when_key, 'script');
    assert.deepStrictEqual(row.inert_when_values, ['github-subdomains.py']);
  }
});

// ip_port_scan's three timeouts are MILLISECONDS while amass's are MINUTES and applied PER DOMAIN.
// A caller that reads 1000 as seconds has asked for a sixteen-minute per-port connect timeout.
maybe('the unit survives compaction, because these tools do not share one', () => {
  for (const full of [false, true]) {
    const row = cct.companyOption('hostProbeTimeout', IP_PORT_PROBE_TIMEOUT, full);
    assert.strictEqual(row.unit, 'milliseconds');
    assert.strictEqual(row.min, 100, 'the floor is what stops a value that can never connect');
    assert.strictEqual(row.max, 10000);
  }
});

// The float kind was added to the shared type for censys requests/sec and shodan's sub-second pause.
// A caller told this is an int will send 1 where it meant 0.5 and double the pacing.
maybe('a float option is reported as a float rather than rounded into an int', () => {
  for (const full of [false, true]) {
    const row = cct.companyOption('perQueryDelaySeconds', SHODAN_DELAY, full);
    assert.strictEqual(row.kind, 'float');
    assert.strictEqual(row.min, 0, 'zero is a legal value here and must not be dropped as empty');
    assert.strictEqual(row.unit, 'seconds');
  }
});

// ---------------------------------------------------------------------------------------------
// The no-command-line tools. Sixty-one flagless options across five of them.
// ---------------------------------------------------------------------------------------------

maybe('a tool with no command line is derived from its own vocabulary, not from a list', () => {
  const noCli = FIXTURE.tools.find((t) => t.key === 'ip_port_scan');
  const cli = FIXTURE.tools.find((t) => t.key === 'github_recon');
  assert.strictEqual(cct.hasCommandLine(noCli), false);
  assert.strictEqual(cct.hasCommandLine(cli), true, 'github_recon has -a and -e');
});

// compactOption attaches a ~250 character no_flag sentence to every option that composes nothing.
// Across the five tools with no command line at all that is 61 repetitions of one fact their own
// limitation already states, which is roughly fifteen kilobytes of a budget that is the binding
// constraint. It is said once at the response level instead. On a tool that DOES have a command
// line, a flagless option is genuinely surprising and keeps its sentence.
maybe('the no-flag sentence is said once for a tool with no command line, and kept where it surprises', () => {
  const onNoCli = cct.companyOption('hostDiscoveryPorts', IP_PORT_HOST_DISCOVERY, false, false);
  assert.ok(!('no_flag' in onNoCli), 'sixty-one repetitions of one fact is not an explanation');
  assert.ok(!('flag' in onNoCli));

  const frameworkSwitch = {
    kind: 'bool', group: 'Result handling', label: 'Retry with spaces removed', provenance: 'runner',
    placeholder: 'ON, and hardcoded.',
  };
  const onCli = cct.companyOption('retryWithoutSpaces', frameworkSwitch, false, true);
  assert.match(onCli.no_flag, /composes no command-line argument/,
    'on metabigor, which has real flags, a flagless option is a framework switch and must say so');
});

maybe('the once-per-response sentence names what the tool is instead of a binary', () => {
  assert.match(cct.NO_COMMAND_LINE, /NO COMMAND LINE/);
  assert.match(cct.NO_COMMAND_LINE, /would_add_args is correctly empty/,
    'an empty argument list has to read as the answer rather than as a failure');
  assert.match(cct.NO_COMMAND_LINE, /NOT IMPLEMENTED/,
    'several of these options are not read by the runner either, and that is a different claim');
});

// ---------------------------------------------------------------------------------------------
// Which store the values live in, and which OTHER store owns the targets.
// ---------------------------------------------------------------------------------------------

// nuclei is registered in the Company registry but its settings live in wildcard_tool_settings,
// because one runner serves both workflows and loads by scope target id alone. Writing them anywhere
// else would leave the runner reading an empty row, so the scan would behave exactly as if nothing
// had been configured. Derived from the server's own settings_stores block rather than hardcoded.
maybe('the settings store is read off the server payload, including the one exception', () => {
  const stores = FIXTURE.settings_stores;
  assert.strictEqual(cct.settingsStoreFor('nuclei', stores), 'wildcard_tool_settings');
  assert.strictEqual(cct.settingsStoreFor('ip_port_scan', stores), 'company_tool_settings');
  assert.strictEqual(cct.settingsStoreFor('a_tool_added_next_week', stores), 'company_tool_settings',
    'a tool this file has never heard of still gets the right default');
});

maybe('a tool row says where the target picker is, and headlines the note in compact', () => {
  const tool = FIXTURE.tools.find((t) => t.key === 'ip_port_scan');
  const sel = FIXTURE.target_selection_stores;
  const compact = cct.companyTool(tool, false, FIXTURE.settings_stores, sel);
  assert.strictEqual(compact.settings_store, 'company_tool_settings');
  assert.strictEqual(compact.composes_no_arguments, true);
  assert.strictEqual(compact.notes_chars, 3200, 'the notes are the heaviest field and are sized');
  assert.ok(!('notes' in compact));
  // ip_port_scan has no config table at all, so there is no table name - but the NOTE is the useful
  // part: amass_intel_configs.selected_network_ranges looks like it filters this scan and is not
  // read by it.
  assert.ok(!('target_selection_store' in compact), 'an empty table name is not a table name');
  assert.match(compact.target_selection_note_headline || compact.target_selection_note,
    /No config table exists/);

  const nuclei = FIXTURE.tools.find((t) => t.key === 'nuclei');
  const nucleiRow = cct.companyTool(nuclei, false, FIXTURE.settings_stores, sel);
  assert.strictEqual(nucleiRow.settings_store, 'wildcard_tool_settings');
  assert.strictEqual(nucleiRow.target_selection_store, 'nuclei_configs');
  assert.strictEqual(nucleiRow.target_selection_owned_flag_count, 4);
  assert.strictEqual(nucleiRow.runner_reads_settings, true);
  assert.ok(!('composes_no_arguments' in nucleiRow));

  const full = cct.companyTool(tool, true, FIXTURE.settings_stores, sel);
  assert.strictEqual(full.notes.length, 3200);
  assert.match(full.target_selection_note, /is not read by it/,
    'full returns the whole note, which is where the trap is actually written');
});

// ---------------------------------------------------------------------------------------------
// Size. The registry is 207 options and 359 owned flags of dense measured prose, so a listing that
// does not fit the output cap returns nothing usable at all.
// ---------------------------------------------------------------------------------------------

// katana_company carries 46 options and nuclei 43, the two largest vocabularies in this registry.
maybe('a forty-six option compact listing fits the output budget', () => {
  const rows = Array.from({ length: 46 }, (_, i) => cct.companyOption(`option${i}`, IP_PORT_HOST_DISCOVERY, false, false));
  const chars = JSON.stringify(rows, null, 2).length;
  // Deliberately a literal rather than ROW_BUDGET: this asserts that compact IS compact, which has
  // to stay true independently of where the downgrade threshold happens to sit.
  assert.ok(chars < 25000, `forty-six compact options serialise to ${chars} characters`);
  const full = JSON.stringify(
    Array.from({ length: 46 }, (_, i) => cct.companyOption(`option${i}`, IP_PORT_HOST_DISCOVERY, true, false)),
    null, 2,
  ).length;
  assert.ok(full > chars, `compact must cost less than full: ${chars} against ${full}`);
});

// ---------------------------------------------------------------------------------------------
// The schema. Four actions, compact by default, and no second copy of the server registry.
// ---------------------------------------------------------------------------------------------

maybe('the action list offers exactly the four documented actions', () => {
  const actions = [...cct.manageCompanyToolsSchema.shape.action._def.values];
  assert.deepStrictEqual(actions.sort(),
    ['option_reference', 'save_settings', 'settings', 'tools']);
  assert.deepStrictEqual([...cct.ACTIONS].sort(),
    ['option_reference', 'save_settings', 'settings', 'tools']);
});

// 359 owned flags carry a measured reason each, and the reason is the difference between "nobody
// added this flag" and "this flag was measured to do nothing in the installed build". Reaching them
// must not require guessing a flag name and being refused.
maybe('the owned flags are reachable, as a view of the option reference', () => {
  const shape = cct.manageCompanyToolsSchema.shape;
  assert.ok(shape.owned_flags, 'the reason on 359 owned flags has to be readable somehow');
  assert.ok(shape.owned_flags.isOptional());
  assert.match(shape.owned_flags.description, /NOT options/);
  assert.match(shape.owned_flags.description, /before concluding a flag is missing/);
});

maybe('detail exists, offers two levels, and defaults to compact', () => {
  const detail = cct.manageCompanyToolsSchema.shape.detail;
  assert.ok(detail, 'without a detail parameter the whole vocabulary is the only answer available');
  assert.deepStrictEqual([...detail._def.innerType._def.values].sort(), ['compact', 'full']);
  assert.ok(detail.isOptional(), 'compact has to be the default, not something a caller opts into');
});

// A closed enum of tool keys here would be a second copy of something the server owns, and a tool
// added on the server would be unreachable over MCP until this file was edited too.
maybe('the tool parameter is not a second copy of the server registry', () => {
  assert.strictEqual(
    cct.manageCompanyToolsSchema.shape.tool._def.innerType._def.typeName, 'ZodString');
});

maybe('replace and settings exist so a merge is the default and null can remove a key', () => {
  const shape = cct.manageCompanyToolsSchema.shape;
  assert.ok(shape.replace.isOptional(), 'merge has to be what a caller gets when it did not ask');
  assert.ok(shape.settings.isOptional());
  assert.match(shape.settings.description, /null value removes that key/);
  assert.match(shape.settings.description, /NOT by flag/);
});

// The one fact the whole surface was asked to carry. An agent told the on-prem live web server scan
// is nmap will spend its turn setting flags that do not exist on a tool that is not there.
maybe('the tool description says the on-prem scan is not nmap and what it is instead', () => {
  const index = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');
  const start = index.indexOf('manage_company_tools');
  assert.ok(start > 0, 'manage_company_tools is not registered in index.js');
  const description = index.slice(start, index.indexOf('manageCompanyToolsSchema.shape', start));
  assert.match(description, /IS NOT NMAP/);
  assert.match(description, /TCP connect/);
  assert.match(description, /net\.DialTimeout/);
  assert.match(description, /no SYN scan/);
  assert.match(description, /MILLISECONDS/,
    'the unit split between this tool and amass is the other thing an agent cannot infer');
  assert.match(description, /8443/,
    'the default host-discovery list already excludes ports the port scan looks at');
});

// ---------------------------------------------------------------------------------------------
// The actions themselves, against the stubbed API installed at the top of this file.
// ---------------------------------------------------------------------------------------------

wired('tools returns the registry and names the tools whose runner does not read it', async () => {
  const out = await cct.manageCompanyTools({ action: 'tools' });
  assert.deepStrictEqual(out.tools.map((t) => t.tool),
    ['ip_port_scan', 'github_recon', 'shodan_company', 'nuclei']);
  assert.match(out.pending_wiring, /ip_port_scan, github_recon, shodan_company/);
  assert.ok(!/nuclei/.test(out.pending_wiring),
    'nuclei IS wired and must not be listed as unwired: it is the one tool a saved setting reaches');
  assert.match(out.tools_with_no_command_line, /no command line at all/);
  assert.match(out.target_selection_is_a_different_store, /domain picker/);
  assert.strictEqual(out.settings_stores.shared.nuclei, 'wildcard_tool_settings');
  assert.match(out.note, /same settings the Company Settings screen writes/);
});

wired('an unknown tool is answered with the registry own keys, not a schema error', async () => {
  const out = await cct.manageCompanyTools({ action: 'tools', tool: 'ip_port_scanner' });
  assert.match(out.error, /No Company workflow tool called ip_port_scanner/);
  assert.match(out.error, /ip_port_scan, github_recon/,
    'the error has to say what could have been said instead');
});

wired('option_reference without a tool is an index, not the whole vocabulary', async () => {
  const out = await cct.manageCompanyTools({ action: 'option_reference' });
  assert.deepStrictEqual(out.tools[0].option_keys, ['hostDiscoveryPorts', 'hostProbeTimeout']);
  assert.strictEqual(out.tools[0].composes_no_arguments, true);
  assert.strictEqual(out.tools[3].settings_store, 'wildcard_tool_settings');
  assert.ok(!out.tools[0].options, 'the index must not carry the options themselves');
  assert.match(out.note, /does not fit the output cap/);
});

wired('one tool reference states the no-command-line fact once and drops it from every row', async () => {
  const out = await cct.manageCompanyTools({ action: 'option_reference', tool: 'ip_port_scan' });
  assert.strictEqual(out.option_count, 2);
  assert.match(out.no_command_line, /NO COMMAND LINE/);
  for (const row of out.options) assert.ok(!('no_flag' in row));
  assert.match(out.limitation, /THERE IS NO NMAP/);
  assert.match(out.target_selection.note, /is not read by it/);
  assert.match(out.pending_wiring, /does not read this store yet/);
});

wired('option_reference filters by group and by provenance', async () => {
  const byGroup = await cct.manageCompanyTools({
    action: 'option_reference', tool: 'github_recon', group: 'search seed',
  });
  assert.strictEqual(byGroup.returned, 1, 'group matching is case-insensitive');
  assert.strictEqual(byGroup.options[0].option, 'searchSeedMode');
  assert.strictEqual(byGroup.option_count, 2, 'the unfiltered count still has to be visible');

  const badGroup = await cct.manageCompanyTools({
    action: 'option_reference', tool: 'github_recon', group: 'Nope',
  });
  assert.match(badGroup.error, /Result Breadth, Search Seed/, 'name the groups that do exist');

  const noMatch = await cct.manageCompanyTools({
    action: 'option_reference', tool: 'github_recon', provenance: 'runner',
  });
  assert.strictEqual(noMatch.returned, 0);
  assert.deepStrictEqual(noMatch.options_by_provenance, { unverified: 1, measured: 1 },
    'the counts are the question behind the filter, and an absent options key reads as a bug');
});

wired('one option comes back in full whatever detail says', async () => {
  const out = await cct.manageCompanyTools({
    action: 'option_reference', tool: 'ip_port_scan', option: 'hostDiscoveryPorts',
  });
  assert.strictEqual(out.option.min_items, 1);
  assert.match(out.option.danger, /RECORDED AS DEAD/);
  assert.match(out.no_command_line, /NO COMMAND LINE/);
  const missing = await cct.manageCompanyTools({
    action: 'option_reference', tool: 'ip_port_scan', option: 'hostDiscoveryPort',
  });
  assert.match(missing.error, /hostDiscoveryPorts, hostProbeTimeout/);
});

wired('owned_flags carries the reason a flag is not an option', async () => {
  const perTool = await cct.manageCompanyTools({ action: 'option_reference', owned_flags: true });
  assert.strictEqual(perTool.tools[0].owned_flag_count, 1);
  assert.match(perTool.note, /not flags at all/,
    'a tool with no command line owns VALUES, and the response must not call them flags');

  const one = await cct.manageCompanyTools({
    action: 'option_reference', owned_flags: true, tool: 'shodan_company',
  });
  assert.strictEqual(one.owned_flags[0].flag, 'the unencoded query string');
  assert.match(one.owned_flags[0].reason || one.owned_flags[0].reason_headline, /MEASURED DEFECT/);
  assert.match(one.note, /never appears in both lists/,
    'an option and an owned flag naming one flag 400s every save with no visible symptom');
});

// group, provenance and option describe OPTIONS. Accepting one alongside owned_flags and quietly
// ignoring it would hand back the whole list looking filtered, which is the same defect class as a
// stored setting nothing reads.
wired('an option filter passed to the owned-flag view is refused rather than ignored', async () => {
  const out = await cct.manageCompanyTools({
    action: 'option_reference', owned_flags: true, tool: 'shodan_company', group: 'Queries',
  });
  assert.match(out.error, /group does not apply when owned_flags is true/);
  assert.match(out.error, /Drop it to read the owned flags/,
    'a refusal has to say what could have been done instead');

  const two = await cct.manageCompanyTools({
    action: 'option_reference', owned_flags: true, provenance: 'measured', option: 'maxPages',
  });
  assert.match(two.error, /provenance, option do not apply/);
});

// The ip_port_scan advisory fires with NOTHING configured, because the scanner's own defaults
// already disagree with each other. That makes it the single most useful line in the response and
// the easiest to mistake for noise.
wired('settings for every tool reports the advisory that fires at the defaults', async () => {
  const out = await cct.manageCompanyTools({ action: 'settings' });
  assert.strictEqual(out.scope_target_id, 'active-target', 'the active target is resolved for you');
  const ipRow = out.tools.find((t) => t.tool === 'ip_port_scan');
  assert.match(ipRow.advisories.webPorts, /recorded as DEAD before the port scan ever runs/);
  assert.match(out.advisories_note, /fire at the DEFAULTS/);
  assert.match(out.advisories_note, /ip_port_scan/);
  const shodanRow = out.tools.find((t) => t.tool === 'shodan_company');
  assert.strictEqual(shodanRow.configured_count, 0,
    'zero is an answer and must survive dropEmpty: it means the tool runs on its own defaults');
  assert.strictEqual(out.tools.find((t) => t.tool === 'nuclei').settings_store,
    'wildcard_tool_settings');
});

wired('settings for one tool shows the composed arguments and names a stored key nothing reads', async () => {
  const out = await cct.manageCompanyTools({ action: 'settings', tool: 'ip_port_scan' });
  assert.deepStrictEqual(out.would_add_args, [],
    'a tool with no command line composes nothing, and the empty list is the answer');
  assert.match(out.composes_nothing, /EXPECTED for a tool with no command line/);
  assert.deepStrictEqual(out.stored_but_unknown, ['hostProbeTimeoutMs'],
    'a stored key outside the vocabulary composes nothing, so it must not sit there looking set');
  assert.match(out.stored_but_unknown_warning, /Send them as null to remove them/);
  assert.strictEqual(out.notes_chars, 3200);
  assert.ok(!out.options, 'compact settings must not repeat the whole vocabulary');
  assert.match(out.no_command_line, /NO COMMAND LINE/);
});

wired('settings at full describes the keys that are set, not every key that exists', async () => {
  const out = await cct.manageCompanyTools({
    action: 'settings', tool: 'ip_port_scan', detail: 'full',
  });
  assert.deepStrictEqual(out.configured_options.map((o) => o.option), ['hostProbeTimeout'],
    'hostProbeTimeoutMs is stored but is not in the vocabulary, so it has no entry to describe');
  assert.strictEqual(out.configured_options[0].unit, 'milliseconds');
  assert.strictEqual(out.notes.length, 3200);
});

wired('nuclei settings report the store they actually live in, and why', async () => {
  const out = await cct.manageCompanyTools({ action: 'settings', tool: 'nuclei' });
  assert.strictEqual(out.settings_store, 'wildcard_tool_settings');
  assert.match(out.settings_store_note, /scope target id alone/);
  assert.strictEqual(out.runner_reads_settings, true);
  assert.ok(!('pending_wiring' in out),
    'the one wired tool must not carry the sentence saying nothing reads its settings');
});

// The measured trap this exists to stop: a caller sends a resolver that is a file path, because dnsx
// documents -r as "file or comma separated", and the file does not exist inside the container. It
// exits 0 with zero bytes of stdout and the domain is stored as successfully scanned.
wired('a refusal comes back with the server reason verbatim and nothing is saved', async () => {
  const out = await cct.manageCompanyTools({
    action: 'save_settings', tool: 'dnsx_company', settings: { resolvers: ['/app/resolvers.txt'] },
  });
  assert.strictEqual(out.saved, false);
  assert.strictEqual(out.refused, true);
  assert.strictEqual(out.refusal_code, 'unsafe_value');
  assert.strictEqual(out.http_status, 400);
  assert.match(out.reason, /exits 0 with zero bytes of stdout/,
    'the measured reason is the whole diagnostic and has to survive intact');
  assert.match(out.what_this_means, /loopback/,
    'and it has to name the rest of the class, not just the one that was hit');

  const owned = await cct.manageCompanyTools({
    action: 'save_settings', tool: 'amass_intel', settings: { '-silent': true },
  });
  assert.strictEqual(owned.refusal_code, 'framework_owned');
  assert.match(owned.reason, /DOES NOT EXIST ON THIS SUBCOMMAND/);
  assert.match(owned.what_this_means, /owned_flags/, 'it has to say where to look next');
});

wired('a successful save reports the advisory the settings just triggered', async () => {
  const out = await cct.manageCompanyTools({
    action: 'save_settings', tool: 'ip_port_scan', settings: { hostProbeTimeout: 3000 },
  });
  assert.strictEqual(out.saved, true);
  assert.strictEqual(out.settings_store, 'company_tool_settings');
  assert.match(out.advisories.webPorts, /recorded as DEAD/);
  assert.match(out.advisory_warning, /NOT in hostDiscoveryPorts/);
  assert.match(out.pending_wiring, /does not read this store yet/);
  assert.deepStrictEqual(out.would_add_args, [],
    'composing nothing is a result for this tool, not an absence');
});

// A null value REMOVES a key. Stripping it here would turn a deletion into a no-op, and the caller
// would be told the setting was cleared while it was still stored.
wired('a null value reaches the server rather than being filtered out on the way', async () => {
  POSTED.length = 0;
  await cct.manageCompanyTools({
    action: 'save_settings',
    tool: 'ip_port_scan',
    settings: { hostProbeTimeout: null, webPorts: ['80', '443'] },
  });
  assert.strictEqual(POSTED.length, 1);
  const sent = POSTED[0];
  assert.strictEqual(sent.path, '/company-tools/active-target/ip_port_scan/settings');
  assert.ok('hostProbeTimeout' in sent.body.settings, 'the key has to survive to the server');
  assert.strictEqual(sent.body.settings.hostProbeTimeout, null);
  assert.strictEqual(sent.body.replace, false,
    'merge is the default, so sending one setting never blanks the rest');

  POSTED.length = 0;
  await cct.manageCompanyTools({
    action: 'save_settings', tool: 'ip_port_scan', settings: { webPorts: ['80'] }, replace: true,
  });
  assert.strictEqual(POSTED[0].body.replace, true, 'and replace is passed through when asked for');
});

wired('save_settings refuses a missing argument without a round trip to the API', async () => {
  const noTool = await cct.manageCompanyTools({
    action: 'save_settings', target_id: '00000000-0000-0000-0000-000000000000',
    settings: { hostProbeTimeout: 3000 },
  });
  assert.match(noTool.error, /tool is required/);

  const noSettings = await cct.manageCompanyTools({
    action: 'save_settings', target_id: '00000000-0000-0000-0000-000000000000', tool: 'ip_port_scan',
  });
  assert.match(noSettings.error, /settings is required/);
  assert.match(noSettings.error, /not by flag/,
    'the error is the place to say the keys are option keys rather than flags');
});
