import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import CompanyToolConfigModal from './CompanyToolConfigModal';
import IPPortScanConfigModal from './IPPortScanConfigModal';
import AmassEnumConfigModal from './AmassEnumConfigModal';
import DNSxConfigModal from './DNSxConfigModal';
import KatanaCompanyConfigModal from './KatanaCompanyConfigModal';
import { resetRegistryCache } from '../components/useToolSettings';

// These modals render for real, in jsdom, because the last modals added to this app compiled
// cleanly and then threw on mount, white-screening a whole workflow. A test of a pure function would
// have passed through that.
//
// THE VOCABULARY BELOW IS DELIBERATELY INVENTED. Not one of these option keys, labels, groups or
// flags exists in the Company registry. That is the point of the fixture: if these files were
// drawing a hand written form, made-up options could not appear on screen and these assertions
// would fail. Everything that renders here renders because the SERVER said so, which is the same
// reason the MCP company tool and these screens cannot drift apart.

const TARGET = { id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' };

const jsonResponse = (body, ok = true) => Promise.resolve({ ok, json: () => Promise.resolve(body) });

const REGISTRY = {
  provenance_meaning: {
    measured: 'Probed against the installed container, flag by flag.',
    runner: 'Taken from the command line the runner executes today.',
    unverified: 'The flag is accepted, but its semantics were not proven.',
  },
  owned_flags_meaning: 'Values the runner sets itself. They are refused on save, with the reason.',
};

const SETTINGS = {
  tool: 'faketool',
  tool_name: 'Fake Company Tool',
  step: 4,
  phase: 'Invented company phase',
  container: 'ars0n-framework-v2-fake-1',
  version: 'v9.9.9',
  invocation: 'server/utils/fakeUtils.go ExecuteFakeCompanyScan',
  settings: { alphaSwitch: true, deltaNames: ['one', 'two'], strayKey: 'left over' },
  options: {
    alphaSwitch: {
      kind: 'bool', group: 'Invented Group A', label: 'Alpha switch', flag: '-alpha',
      provenance: 'measured',
      placeholder: 'Off in the tool, but the runner hardcodes it on today.',
      why: 'Alpha is the biggest coverage lever.',
      danger: 'ALPHA DANGER: turning this off exits 0 and scans nothing.',
    },
    betaMinutes: {
      kind: 'int', group: 'Invented Group A', label: 'Beta budget', flag: '-beta',
      provenance: 'unverified', unit: 'minutes', min: 1, max: 10,
      placeholder: 'Unset, so the tool applies no budget.',
      danger: 'BETA DANGER: a truncated run is stored as a complete one.',
    },
    gammaPause: {
      kind: 'float', group: 'Invented Group B', label: 'Gamma pause', flag: '-gamma',
      provenance: 'measured', unit: 'seconds', min: 0.1,
      placeholder: 'Unset, so there is no pause at all.',
    },
    deltaNames: {
      kind: 'list', group: 'Invented Group B', label: 'Delta names', flag: '-delta',
      provenance: 'measured', choices: ['one', 'two', 'three'], min_items: 1,
      placeholder: 'Unset, so every name runs.',
    },
    zetaSwitch: {
      kind: 'bool', group: 'Invented Group B', label: 'Zeta switch', flag: '-zeta',
      provenance: 'runner', placeholder: 'Off.',
    },
    epsilonPorts: {
      kind: 'list', group: 'Invented Group B', label: 'Epsilon ports', flag: '-eps',
      provenance: 'runner', requires_key: 'zetaSwitch',
      placeholder: 'Unset, so the tool uses 80,443.',
    },
  },
  groups: ['Invented Group A', 'Invented Group B'],
  owned_flags: { '-ownedflag': 'OWNED REASON: the runner sets this and a stored value would be displaced.' },
  runner_reads_settings: false,
  pending_wiring: 'Stored, but ExecuteFakeCompanyScan does not read this store yet.',
  would_add_args: ['-alpha'],
  advisories: { deltaNames: 'ADVISORY: two of these names are never reached at the current depth.' },
};

const IP_PORT_SETTINGS = {
  tool: 'ip_port_scan',
  tool_name: 'Discover Live Web Servers (On-Prem)',
  step: 3,
  phase: 'Discover Live Web Servers (On-Prem)',
  version: 'INVENTED VERSION STRING: first-party Go inside the api container.',
  invocation: 'server/utils/ipPortScanUtils.go ExecuteIPPortScan',
  settings: {},
  options: {
    maxIpsPerRange: {
      kind: 'int', group: 'Invented Range Group', label: 'Maximum addresses probed per network range',
      provenance: 'measured', min: 1, max: 65534,
      placeholder: '254, from getDefaultScanConfig. discoverLiveIPs applies it as ips[:254].',
    },
  },
  groups: ['Invented Range Group'],
  owned_flags: {
    'consolidated_network_ranges (the target set)':
      'OWNED TARGET SET: every consolidated range is selected, unfiltered.',
  },
  limitation: 'THERE IS NO NMAP AND THERE IS NO COMMAND LINE, so nothing here is a flag. The rest of this sentence exists only so the collapsed form has something to hide, and it goes on for a while to make sure the summary is not the whole text.',
  runner_reads_settings: false,
  pending_wiring: 'Stored, but ExecuteIPPortScan does not read this store yet.',
  would_add_args: [],
  target_selection: {
    table: '',
    note: 'INVENTED TARGET NOTE: no config table exists for this tool.',
  },
};

const RANGES = {
  count: 2,
  network_ranges: [
    { cidr_block: '10.0.0.0/23', asn: 'AS64500', organization: 'Invented Org', source: 'metabigor' },
    { cidr_block: '2607:6bc0::/48', asn: '', organization: 'Invented Org', source: 'metabigor' },
  ],
};

const mockFetch = (overrides = {}) => {
  const calls = [];
  global.fetch = jest.fn((url, init) => {
    const u = String(url);
    calls.push({ url: u, init });
    if (u.endsWith('/company-tools')) {
      return overrides.registryOk === false ? jsonResponse({}, false) : jsonResponse(REGISTRY);
    }
    if (u.includes('/consolidated-network-ranges/')) return jsonResponse(overrides.ranges || RANGES);
    if (u.includes('/company-tools/')) {
      if (init && init.method === 'POST') {
        return jsonResponse(overrides.saveResponse || { saved: true, settings: {}, would_add_args: [] },
          overrides.saveOk !== false);
      }
      if (overrides.settingsOk === false) return jsonResponse({}, false);
      // Keyed on the tool in the path, exactly as the real endpoint is.
      if (u.includes('/ip_port_scan/')) return jsonResponse(overrides.settings || IP_PORT_SETTINGS);
      return jsonResponse(overrides.settings || SETTINGS);
    }
    // Everything the target pickers fetch: domains, scope targets, scan history.
    return jsonResponse(overrides.other || { domains: [], targets: [], target_urls: [] });
  });
  return calls;
};

beforeEach(() => { resetRegistryCache(); mockFetch(); });

const openGeneric = (props = {}) => render(
  <CompanyToolConfigModal
    show
    handleClose={() => {}}
    activeTarget={TARGET}
    tool={{ key: 'faketool', name: 'Fake Company Tool' }}
    {...props}
  />,
);

// ---------------------------------------------------------------------------------------------
// The generic modal: Amass Intel, Metabigor and the Company Nuclei Settings button.
// ---------------------------------------------------------------------------------------------

test('the form is built from the served vocabulary, not from a list in the client', async () => {
  openGeneric();
  // These labels exist nowhere in the client. They render because the server sent them.
  await waitFor(() => expect(screen.getByText('Alpha switch')).toBeInTheDocument());
  expect(screen.getByText('Beta budget')).toBeInTheDocument();
  expect(screen.getByText('Gamma pause')).toBeInTheDocument();
  expect(screen.getByText('Epsilon ports')).toBeInTheDocument();
});

test('the tabs are the groups the server declares, in that order', async () => {
  openGeneric();
  await waitFor(() => expect(screen.getByText('Invented Group A (2)')).toBeInTheDocument());
  const first = screen.getByText('Invented Group A (2)');
  const second = screen.getByText('Invented Group B (4)');
  // Node.DOCUMENT_POSITION_FOLLOWING === 4.
  expect(first.compareDocumentPosition(second) & 4).toBeTruthy();
});

// An empty field is a decision, not a gap. Without this the operator cannot tell what NOT setting an
// option does, which for this workflow is usually "the runner hardcodes something else".
test('every option states what leaving it alone does', async () => {
  openGeneric();
  await waitFor(() => expect(screen.getByText(/the runner hardcodes it on today/)).toBeInTheDocument());
  expect(screen.getByText(/the tool applies no budget/)).toBeInTheDocument();
  expect(screen.getByText(/there is no pause at all/)).toBeInTheDocument();
});

// An option nobody proved must not look like one that was probed against the container.
test('provenance is shown per option, with the server definition of each', async () => {
  openGeneric();
  await waitFor(() => expect(screen.getAllByText('measured').length).toBeGreaterThan(0));
  expect(screen.getAllByText('unverified').length).toBeGreaterThan(0);
  expect(screen.getAllByText('runner').length).toBeGreaterThan(0);
  expect(screen.getByText(/semantics were not proven/)).toBeInTheDocument();
});

// The measured caveats survive in full. What changed is that they are HELP TEXT rather than an
// <Alert variant="danger">: on the live registry 172 of 207 company options carry one, so rendering
// each as an error made every working tool look broken.
test('the measured caveats and advisories are kept, as help text rather than as errors', async () => {
  openGeneric();
  await waitFor(() => expect(screen.getByText(/ALPHA DANGER/)).toBeInTheDocument());
  expect(screen.getByText(/BETA DANGER/)).toBeInTheDocument();
  expect(screen.getByText(/ALPHA DANGER/).closest('.alert')).toBeNull();
  expect(screen.getByText(/BETA DANGER/).closest('.alert')).toBeNull();
  // An advisory is NOT a danger: the setting works, it just does less than it looks like.
  expect(screen.getByText(/ADVISORY: two of these names/)).toBeInTheDocument();
  expect(screen.getByText(/ADVISORY: two of these names/).closest('.alert')).toBeNull();
});

test('the framework-owned values are listed read-only, with the reason', async () => {
  openGeneric();
  await waitFor(() => expect(screen.getByText('-ownedflag')).toBeInTheDocument());
  expect(screen.getByText(/OWNED REASON/)).toBeInTheDocument();
  expect(screen.getByText(/refused on save/)).toBeInTheDocument();
  // It is not an input. An owned flag that could be typed into would 400 the save with no symptom.
  expect(screen.queryByLabelText('-ownedflag')).not.toBeInTheDocument();
});

// A setting nothing reads is how an operator comes to believe a scan did something it did not.
test('a store nothing reads yet says so', async () => {
  openGeneric();
  await waitFor(() => expect(
    screen.getAllByText(/does not read this store yet/).length).toBeGreaterThan(0));
});

test('an option that needs another switch is disabled until that switch is on', async () => {
  openGeneric();
  await waitFor(() => expect(screen.getByText('Epsilon ports')).toBeInTheDocument());
  expect(screen.getByText(/Does nothing unless "Zeta switch" is on/)).toBeInTheDocument();
  expect(document.getElementById('company-faketool-epsilonPorts')).toBeDisabled();

  fireEvent.click(document.getElementById('company-faketool-zetaSwitch-on'));
  await waitFor(() => expect(document.getElementById('company-faketool-epsilonPorts')).not.toBeDisabled());
});

// Two states would make "off" unreachable, and several of these switches are hardcoded ON by the
// runner today, so an explicit false is a real thing an operator needs to be able to store.
test('switches are three-state: not set, on, off', async () => {
  openGeneric();
  await waitFor(() => expect(document.getElementById('company-faketool-alphaSwitch')).toBeInTheDocument());
  ['unset', 'on', 'off'].forEach((state) => {
    expect(document.getElementById(`company-faketool-alphaSwitch-${state}`)).toBeInTheDocument();
  });
  expect(document.getElementById('company-faketool-alphaSwitch-on')).toBeChecked();
});

test('a list with a fixed set of choices is picked, never typed', async () => {
  openGeneric();
  await waitFor(() => expect(screen.getByLabelText('one')).toBeInTheDocument());
  expect(screen.getByLabelText('one')).toBeChecked();
  expect(screen.getByLabelText('two')).toBeChecked();
  expect(screen.getByLabelText('three')).not.toBeChecked();
});

test('saving posts typed values to the company endpoint and replaces the whole stored state', async () => {
  const calls = mockFetch();
  openGeneric();
  await waitFor(() => expect(screen.getByText('Alpha switch')).toBeInTheDocument());

  fireEvent.change(document.getElementById('company-faketool-betaMinutes'), { target: { value: '7' } });
  // A fractional pause must NOT be truncated to 0, which for a pause means "no pause at all".
  fireEvent.change(document.getElementById('company-faketool-gammaPause'), { target: { value: '0.5' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save Settings' }));

  await waitFor(() => expect(calls.some((c) => c.init && c.init.method === 'POST')).toBe(true));
  const post = calls.find((c) => c.init && c.init.method === 'POST');
  expect(post.url).toBe(`/api/company-tools/${TARGET.id}/faketool/settings`);
  const sent = JSON.parse(post.init.body);
  expect(sent.replace).toBe(true);
  expect(sent.settings.alphaSwitch).toBe(true);
  expect(sent.settings.betaMinutes).toBe(7);
  expect(sent.settings.gammaPause).toBe(0.5);
  expect(sent.settings.deltaNames).toEqual(['one', 'two']);
  // The stored key the vocabulary no longer has is NOT sent back: this endpoint refuses an unknown
  // key, so carrying it would 400 every save the operator ever attempted.
  expect(sent.settings.strayKey).toBeUndefined();
});

test('a stored key the vocabulary does not have is reported rather than silently dropped', async () => {
  openGeneric();
  await waitFor(() => expect(screen.getAllByText('strayKey').length).toBeGreaterThan(0));
  expect(screen.getAllByText(/not in the current vocabulary/).length).toBeGreaterThan(0);
});

// The server refuses an owned flag, an unknown key, an unacceptable value and a value measured to
// empty a scan, each with the reason. Swallowing that reason would leave a form that just does not save.
test("the server's refusal is shown verbatim", async () => {
  // Nothing in this tool's vocabulary is called hostDiscoveryPorts, so there is no field to put it
  // on and it stays at the top rather than being swallowed.
  mockFetch({ saveOk: false, saveResponse: { message: 'hostDiscoveryPorts needs at least 1 entry.' } });
  openGeneric();
  await waitFor(() => expect(screen.getByText('Alpha switch')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Save Settings' }));
  await waitFor(() => expect(
    screen.getAllByText('hostDiscoveryPorts needs at least 1 entry.').length).toBeGreaterThan(0));
});

// A refusal the operator cannot see next to the field it is about is a refusal they have to hunt
// for on a screen with forty options.
test("a refusal that names a field is attached to that field", async () => {
  mockFetch({
    saveOk: false,
    saveResponse: { message: 'betaMinutes must be at most 10 minutes. BETA DANGER: a truncated run is stored as a complete one.' },
  });
  openGeneric();
  await waitFor(() => expect(screen.getByText('Alpha switch')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Save Settings' }));

  await waitFor(() => expect(screen.getByTestId('error-betaMinutes')).toBeInTheDocument());
  expect(screen.getByTestId('error-betaMinutes').textContent).toMatch(/must be at most 10 minutes/);
  expect(document.getElementById('company-faketool-betaMinutes').className).toMatch(/is-invalid/);
});

// ---------------------------------------------------------------------------------------------
// Validation. These screens used to render a red <Alert> under every option carrying a caveat and
// validate nothing at all: no min_items, no isInvalid, every numeric option a free text box with a
// paragraph under it explaining what not to type.
// ---------------------------------------------------------------------------------------------

// THE REGRESSION GUARD. A tool whose options are all ordinary must render no alert at all.
const ORDINARY = {
  tool: 'ordinarytool',
  tool_name: 'Ordinary Company Tool',
  step: 2,
  phase: 'Invented ordinary phase',
  settings: {},
  options: {
    ordinaryCount: {
      kind: 'int', group: 'Ordinary Group', label: 'Ordinary count', flag: '-n',
      provenance: 'measured', min: 1, max: 50,
      placeholder: 'Unset, so the tool uses its own default.',
      danger: 'Raising it raises the load a single origin sees, which the per-host limits are the correct answer to rather than lowering this.',
    },
    ordinaryNames: {
      kind: 'list', group: 'Ordinary Group', label: 'Ordinary names', flag: '-s',
      provenance: 'measured', choices: ['alpha', 'beta', 'gamma'], min_items: 2,
      placeholder: 'Unset, so every name runs.',
      danger: 'Either choice changes what the scan covers.',
    },
    ordinaryPorts: {
      kind: 'list', group: 'Ordinary Group', label: 'Ordinary ports', flag: '-p',
      provenance: 'runner',
      placeholder: 'Unset, so the tool uses 80,443.',
    },
  },
  groups: ['Ordinary Group'],
  owned_flags: {},
  runner_reads_settings: true,
  would_add_args: [],
};

const openOrdinary = () => render(
  <CompanyToolConfigModal
    show
    handleClose={() => {}}
    activeTarget={TARGET}
    tool={{ key: 'ordinarytool', name: 'Ordinary Company Tool' }}
  />,
);

test('a company tool whose options are all ordinary renders NO alert', async () => {
  mockFetch({ settings: ORDINARY });
  openOrdinary();
  await waitFor(() => expect(screen.getByText('Ordinary count')).toBeInTheDocument());
  expect(screen.getByText(/Raising it raises the load/)).toBeInTheDocument();
  expect(screen.getByText(/Either choice changes what the scan covers/)).toBeInTheDocument();
  expect(document.querySelectorAll('.alert')).toHaveLength(0);
  expect(document.querySelectorAll('.invalid-feedback')).toHaveLength(0);
});

// min_items had ZERO uses in the client before this. An empty list is "not set" and is fine; a list
// with too few entries in it is a scan that exits 0 and finds nothing.
test('a list with too few entries is refused inline and blocks Save', async () => {
  mockFetch({ settings: ORDINARY });
  openOrdinary();
  await waitFor(() => expect(screen.getByLabelText('alpha')).toBeInTheDocument());

  // Empty is not an error: it means "not set", it is not sent, and the tool uses its own list.
  expect(screen.queryByTestId('error-ordinaryNames')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Save Settings' })).not.toBeDisabled();

  fireEvent.click(screen.getByLabelText('alpha'));
  await waitFor(() => expect(screen.getByTestId('error-ordinaryNames')).toBeInTheDocument());
  expect(screen.getByTestId('error-ordinaryNames').textContent).toMatch(/at least 2 entries/);
  expect(screen.getByRole('button', { name: 'Save Settings' })).toBeDisabled();

  fireEvent.click(screen.getByLabelText('beta'));
  await waitFor(() => expect(screen.queryByTestId('error-ordinaryNames')).not.toBeInTheDocument());
  expect(screen.getByRole('button', { name: 'Save Settings' })).not.toBeDisabled();
});

// A free list is a control that knows it is a list, not a textarea split on newlines.
test('a free list adds and removes entries and posts them as an array', async () => {
  const calls = mockFetch({ settings: ORDINARY });
  openOrdinary();
  await waitFor(() => expect(document.getElementById('company-ordinarytool-ordinaryPorts')).toBeInTheDocument());
  const input = document.getElementById('company-ordinarytool-ordinaryPorts');

  fireEvent.change(input, { target: { value: '8080' } });
  fireEvent.keyDown(input, { key: 'Enter' });
  // A pasted multi-line list becomes one entry per line. A single-line input strips the newlines
  // out of the value, so without handling the paste itself the whole block would arrive as one
  // run-together entry.
  fireEvent.paste(input, { clipboardData: { getData: () => '8443\n3000' } });
  await waitFor(() => expect(screen.getByLabelText('remove 3000')).toBeInTheDocument());

  fireEvent.click(screen.getByLabelText('remove 8443'));
  fireEvent.click(screen.getByRole('button', { name: 'Save Settings' }));

  await waitFor(() => expect(calls.some((c) => c.init && c.init.method === 'POST')).toBe(true));
  const sent = JSON.parse(calls.find((c) => c.init && c.init.method === 'POST').init.body);
  expect(sent.settings.ordinaryPorts).toEqual(['8080', '3000']);
});

// Several of these lists hold values that legitimately contain a comma: a header line such as
// `Accept: text/html,application/xhtml`, a regex with a {2,3} repetition, a Shodan query. Splitting
// an entry on commas would quietly change what the scan sends, with no symptom anywhere.
test('a free list entry containing a comma stays one entry', async () => {
  const calls = mockFetch({ settings: ORDINARY });
  openOrdinary();
  await waitFor(() => expect(document.getElementById('company-ordinarytool-ordinaryPorts')).toBeInTheDocument());
  const input = document.getElementById('company-ordinarytool-ordinaryPorts');

  fireEvent.change(input, { target: { value: 'Accept: text/html,application/xhtml' } });
  fireEvent.keyDown(input, { key: 'Enter' });
  await waitFor(() => expect(screen.getByLabelText('remove Accept: text/html,application/xhtml')).toBeInTheDocument());

  fireEvent.click(screen.getByRole('button', { name: 'Save Settings' }));
  await waitFor(() => expect(calls.some((c) => c.init && c.init.method === 'POST')).toBe(true));
  const sent = JSON.parse(calls.find((c) => c.init && c.init.method === 'POST').init.body);
  expect(sent.settings.ordinaryPorts).toEqual(['Accept: text/html,application/xhtml']);
});

// ---------------------------------------------------------------------------------------------
// The on-prem scanner. The operator called these "the nmap configurations" and there is no nmap.
// ---------------------------------------------------------------------------------------------

const openIPPortScan = (props = {}) => render(
  <IPPortScanConfigModal show handleClose={() => {}} activeTarget={TARGET} {...props} />,
);

test('the on-prem scanner says what it really is and names no nmap tab', async () => {
  openIPPortScan();
  // The tab titles are the SERVER's groups. Nothing here is called nmap.
  await waitFor(() => expect(screen.getByText('Invented Range Group (1)')).toBeInTheDocument());
  expect(screen.getByText(/there is no nmap here/i)).toBeInTheDocument();
  expect(screen.queryByText(/nmap options to set/i)).toBeInTheDocument();
  expect(document.body.textContent).not.toMatch(/nmap scan|nmap settings|nmap configuration/i);
});

test('the targets tab shows what the next scan will really reach, per range', async () => {
  openIPPortScan();
  await waitFor(() => expect(screen.getByText('10.0.0.0/23')).toBeInTheDocument());
  // A /23 holds 510 usable addresses and the limit stated in the SERVER's own placeholder probes
  // the first 254 of them, so the second half of the range is never dialled and nothing else in
  // this app says so.
  expect(screen.getByText(/10\.0\.0\.1\s.+\s10\.0\.0\.254/)).toBeInTheDocument();
  expect(screen.getByText(/never dialled: 10\.0\.0\.255\s.+\s10\.0\.1\.254/)).toBeInTheDocument();
  // IPv6 contributes zero probed addresses while still counting as a range.
  expect(screen.getByText('2607:6bc0::/48')).toBeInTheDocument();
  expect(screen.getByText(/IPv6: the address generator returns an empty slice/)).toBeInTheDocument();
});

test('the targets tab does not pretend a per-range selection exists', async () => {
  openIPPortScan();
  await waitFor(() => expect(screen.getByText('10.0.0.0/23')).toBeInTheDocument());
  expect(screen.getByText(/EVERY consolidated range below is scanned/)).toBeInTheDocument();
  // No tick boxes over the range list: the runner reads no such selection, and offering one would
  // be a stored setting nothing reads.
  const rangeRow = screen.getByText('10.0.0.0/23').closest('tr');
  expect(rangeRow.querySelector('input[type="checkbox"]')).toBeNull();
});

test('changing the per-range limit updates the coverage preview before anything is saved', async () => {
  openIPPortScan();
  await waitFor(() => expect(screen.getByText('10.0.0.0/23')).toBeInTheDocument());
  fireEvent.change(document.getElementById('company-ip_port_scan-maxIpsPerRange'), { target: { value: '510' } });
  await waitFor(() => expect(screen.getByText(/10\.0\.0\.1\s.+\s10\.0\.1\.254/)).toBeInTheDocument());
  expect(screen.queryByText(/never dialled/)).not.toBeInTheDocument();
});

// ---------------------------------------------------------------------------------------------
// The pickers that grew tabs. The existing target selection must keep working exactly as it did.
// ---------------------------------------------------------------------------------------------

test('the Amass Enum domain picker still works when the company registry is missing', async () => {
  // An api container that predates these routes answers 404 for the vocabulary. The settings tabs
  // are then empty, and the domain picker - a different store, a different endpoint - is unaffected.
  mockFetch({ settingsOk: false, registryOk: false, other: { domains: ['invented-domain.example'] } });
  render(
    <AmassEnumConfigModal
      show
      handleClose={() => {}}
      activeTarget={TARGET}
      consolidatedCompanyDomains={['invented-domain.example']}
    />,
  );
  await waitFor(() => expect(screen.getByText('invented-domain.example')).toBeInTheDocument());
  expect(screen.getByRole('button', { name: /Save Configuration \(0 domains\)/ })).toBeInTheDocument();
});

test('the Amass Enum modal carries the served settings as extra tabs beside its picker', async () => {
  render(
    <AmassEnumConfigModal
      show
      handleClose={() => {}}
      activeTarget={TARGET}
      consolidatedCompanyDomains={['invented-domain.example']}
    />,
  );
  await waitFor(() => expect(screen.getByText('Domains (0)')).toBeInTheDocument());
  expect(screen.getByText('Invented Group A (2)')).toBeInTheDocument();
  expect(screen.getByText('What runs & what is fixed')).toBeInTheDocument();
  // And the picker itself is still the first thing on screen.
  expect(screen.getByText('invented-domain.example')).toBeInTheDocument();
});

// The other two pickers took the identical edit, and the failure mode being guarded against is a
// modal that compiles and then throws on mount.
test('the DNSx picker mounts with its settings tabs', async () => {
  render(
    <DNSxConfigModal
      show
      handleClose={() => {}}
      activeTarget={TARGET}
      consolidatedCompanyDomains={['invented-domain.example']}
    />,
  );
  await waitFor(() => expect(screen.getByText('Invented Group B (4)')).toBeInTheDocument());
  expect(screen.getByText('Domains (0)')).toBeInTheDocument();
  expect(screen.getByText('invented-domain.example')).toBeInTheDocument();
});

test('the Katana picker mounts with its settings tabs', async () => {
  render(
    <KatanaCompanyConfigModal
      show
      handleClose={() => {}}
      activeTarget={TARGET}
      consolidatedCompanyDomains={['invented-domain.example']}
    />,
  );
  await waitFor(() => expect(screen.getByText('Invented Group A (2)')).toBeInTheDocument());
  expect(screen.getByText('Targets (0)')).toBeInTheDocument();
});
