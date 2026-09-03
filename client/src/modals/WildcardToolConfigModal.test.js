import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import WildcardToolConfigModal from './WildcardToolConfigModal';
import { resetRegistryCache } from '../components/useToolSettings';

// This modal renders for real, in jsdom, because the last two modals added to this app compiled
// cleanly and then threw on mount, white-screening a whole workflow. A test of a pure function would
// have passed through both.
//
// THE VOCABULARY BELOW IS DELIBERATELY INVENTED. Not one of these option keys, labels or flags exists
// in the Wildcard registry. That is the point of the fixture: if this file were drawing a hand written
// form, made-up options could not appear on screen and these assertions would fail. Everything that
// renders here renders because the SERVER said so, which is the same reason the MCP tool and this
// screen cannot drift apart.

const TARGET = { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' };
const TOOL = { key: 'faketool', name: 'Fake Tool' };

const jsonResponse = (body, ok = true) => Promise.resolve({ ok, json: () => Promise.resolve(body) });

const REGISTRY = {
  provenance_meaning: {
    measured: 'Probed against the installed container, flag by flag.',
    runner: 'Taken from the command line the runner executes today.',
    unverified: 'The flag is accepted, but its semantics were not proven.',
  },
  owned_flags_meaning: 'Flags the runner sets itself. They are refused on save, with the reason.',
};

const SETTINGS = {
  tool: 'faketool',
  tool_name: 'Fake Tool',
  step: 4,
  phase: 'Invented phase',
  container: 'ars0n-framework-v2-fake-1',
  version: 'v9.9.9',
  invocation: 'server/utils/fakeUtils.go:1 ExecuteFakeScan',
  settings: { alphaSwitch: true, deltaNames: ['one', 'two'], strayKey: 'left over' },
  options: {
    alphaSwitch: {
      kind: 'bool', group: 'First Group', label: 'Alpha switch', flag: '-alpha',
      provenance: 'measured',
      placeholder: 'Off in the tool, but the runner hardcodes it on today.',
      why: 'Alpha is the biggest coverage lever.',
      danger: 'ALPHA DANGER: turning this off exits 0 and scans nothing.',
    },
    betaMinutes: {
      kind: 'int', group: 'First Group', label: 'Beta budget', flag: '-beta',
      provenance: 'unverified', unit: 'minutes', min: 1, max: 10,
      placeholder: 'Unset, so the tool applies no budget.',
      danger: 'BETA DANGER: a truncated run is stored as a complete one.',
    },
    zetaSwitch: {
      kind: 'bool', group: 'Second Group', label: 'Zeta switch', flag: '-zeta',
      provenance: 'runner', placeholder: 'Off.',
    },
    gammaPorts: {
      kind: 'list', group: 'Second Group', label: 'Gamma ports', flag: '-gamma',
      provenance: 'runner', requires_key: 'zetaSwitch',
      placeholder: 'Unset, so the tool uses 80,443.',
    },
    deltaNames: {
      kind: 'list', group: 'Second Group', label: 'Delta names', flag: '-delta',
      provenance: 'measured', choices: ['one', 'two', 'three'],
      placeholder: 'Unset, so every name runs.',
    },
    epsilonText: {
      kind: 'string', group: 'Second Group', label: 'Epsilon text', flag: '-eps',
      provenance: 'measured', placeholder: 'Unset.',
      shadowed_by: 'user_settings.fake_rate_limit',
    },
  },
  groups: ['First Group', 'Second Group'],
  owned_flags: { '-ownedflag': 'OWNED REASON: the runner sets this and a stored value would be displaced.' },
  runner_reads_settings: false,
  pending_wiring: 'Stored, but ExecuteFakeScan does not read this store yet.',
  would_add_args: ['-alpha'],
};

const mockFetch = (overrides = {}) => {
  const calls = [];
  global.fetch = jest.fn((url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith('/wildcard-tools')) return jsonResponse(REGISTRY);
    if (init && init.method === 'POST') {
      return jsonResponse(overrides.saveResponse || { saved: true, settings: {}, would_add_args: [] },
        overrides.saveOk !== false);
    }
    return jsonResponse(overrides.settings || SETTINGS);
  });
  return calls;
};

beforeEach(() => { resetRegistryCache(); mockFetch(); });

const openModal = (props = {}) => render(
  <WildcardToolConfigModal
    show
    handleClose={() => {}}
    activeTarget={TARGET}
    tool={TOOL}
    {...props}
  />,
);

test('the form is built from the served vocabulary, not from a list in this file', async () => {
  openModal();
  // These labels exist nowhere in the client. They render because the server sent them.
  await waitFor(() => expect(screen.getByText('Alpha switch')).toBeInTheDocument());
  expect(screen.getByText('Beta budget')).toBeInTheDocument();
  expect(screen.getByText('Gamma ports')).toBeInTheDocument();
  // Twice: once as the option's own flag, once in the composed argument preview.
  expect(screen.getAllByText('-alpha').length).toBeGreaterThan(0);
});

// A settings screen that cannot show what it will run is one the operator has to take on trust.
test('the composed command-line arguments are shown', async () => {
  openModal();
  await waitFor(() => expect(
    screen.getByText(/Arguments the saved settings add/)).toBeInTheDocument());
});

test('groups are rendered as sections in the order the server declares them', async () => {
  openModal();
  await waitFor(() => expect(screen.getByText('First Group')).toBeInTheDocument());
  const first = screen.getByText('First Group');
  const second = screen.getByText('Second Group');
  // Node.DOCUMENT_POSITION_FOLLOWING === 4: "Second Group" comes after "First Group" in the document.
  expect(first.compareDocumentPosition(second) & 4).toBeTruthy();
});

// An empty field is a decision, not a gap. Without this the operator cannot tell what NOT setting an
// option does, which for this workflow is usually "the runner hardcodes something else".
test('every option states what leaving it alone does', async () => {
  openModal();
  await waitFor(() => expect(
    screen.getByText(/the runner hardcodes it on today/)).toBeInTheDocument());
  expect(screen.getByText(/the tool applies no budget/)).toBeInTheDocument();
  expect(screen.getByText(/the tool uses 80,443/)).toBeInTheDocument();
});

// An option nobody proved must not look like one that was probed against the container.
test('provenance is shown per option and unverified is distinguishable from measured', async () => {
  openModal();
  await waitFor(() => expect(screen.getAllByText('measured').length).toBeGreaterThan(0));
  expect(screen.getAllByText('unverified').length).toBeGreaterThan(0);
  expect(screen.getAllByText('runner').length).toBeGreaterThan(0);
  // And the server's own definition of each, so the badge is not just a colour.
  expect(screen.getByText(/semantics were not proven/)).toBeInTheDocument();
});

// The measured caveats are expensive knowledge and every one of them survives. What changed is that
// they are HELP TEXT rather than an <Alert variant="danger">: on the live registry 130 of 175 options
// carry one, so rendering each as an error made a working tool look broken.
test('the measured caveats are kept, as help text rather than as errors', async () => {
  openModal();
  await waitFor(() => expect(screen.getByText(/ALPHA DANGER/)).toBeInTheDocument());
  expect(screen.getByText(/BETA DANGER/)).toBeInTheDocument();
  expect(screen.getByText(/ALPHA DANGER/).closest('.alert')).toBeNull();
  expect(screen.getByText(/BETA DANGER/).closest('.alert')).toBeNull();
});

// So an operator can see why a flag they expected is missing, rather than concluding the screen is
// half finished.
test('the framework-owned flags are listed read-only, with the reason', async () => {
  openModal();
  await waitFor(() => expect(screen.getByText('-ownedflag')).toBeInTheDocument());
  expect(screen.getByText(/OWNED REASON/)).toBeInTheDocument();
  expect(screen.getByText(/refused on save/)).toBeInTheDocument();
  // It is not an input. An owned flag that could be typed into would 400 the save with no symptom.
  expect(screen.queryByLabelText('-ownedflag')).not.toBeInTheDocument();
});

// A setting nothing reads is how a caller comes to believe a scan did something it did not. This is
// one of only two things on this screen that still warrant an alert, and asserting the alert really
// is one is what makes the "no alert for an ordinary tool" guard below mean anything.
test('a store nothing reads yet says so, and says it as an alert', async () => {
  openModal();
  await waitFor(() => expect(
    screen.getByText(/does not read this store yet/)).toBeInTheDocument());
  expect(screen.getByText(/does not read this store yet/).closest('.alert')).not.toBeNull();
});

// requires_key options are inert, and greying them out beats letting someone believe they configured
// something the tool will ignore.
test('an option that needs another switch is disabled until that switch is on', async () => {
  openModal();
  await waitFor(() => expect(screen.getByText('Gamma ports')).toBeInTheDocument());
  expect(screen.getByText(/Does nothing unless "Zeta switch" is on/)).toBeInTheDocument();
  expect(document.getElementById('wildcard-faketool-gammaPorts')).toBeDisabled();

  // Turning the governing switch on releases it immediately, without a save round trip.
  fireEvent.click(document.getElementById('wildcard-faketool-zetaSwitch-on'));
  await waitFor(() => expect(document.getElementById('wildcard-faketool-gammaPorts')).not.toBeDisabled());
});

// Two states would make "off" unreachable, and several of these switches are hardcoded ON by the
// runner today, so an explicit false is a real thing an operator needs to be able to store.
test('switches are three-state: not set, on, off', async () => {
  openModal();
  await waitFor(() => expect(document.getElementById('wildcard-faketool-alphaSwitch')).toBeInTheDocument());
  ['unset', 'on', 'off'].forEach((state) => {
    expect(document.getElementById(`wildcard-faketool-alphaSwitch-${state}`)).toBeInTheDocument();
  });
  // The stored true came back as "on" rather than as an unchecked box.
  expect(document.getElementById('wildcard-faketool-alphaSwitch-on')).toBeChecked();
  expect(document.getElementById('wildcard-faketool-alphaSwitch-unset')).not.toBeChecked();
});

test('a list with a fixed set of choices is picked, never typed', async () => {
  openModal();
  await waitFor(() => expect(screen.getByLabelText('one')).toBeInTheDocument());
  // Both stored names came back ticked; the third did not.
  expect(screen.getByLabelText('one')).toBeChecked();
  expect(screen.getByLabelText('two')).toBeChecked();
  expect(screen.getByLabelText('three')).not.toBeChecked();
});

test('saving posts typed values and replaces the whole stored state', async () => {
  const calls = mockFetch();
  openModal();
  await waitFor(() => expect(screen.getByText('Alpha switch')).toBeInTheDocument());

  fireEvent.change(document.getElementById('wildcard-faketool-betaMinutes'), { target: { value: '7' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));

  await waitFor(() => expect(calls.some((c) => c.init && c.init.method === 'POST')).toBe(true));
  const post = calls.find((c) => c.init && c.init.method === 'POST');
  expect(post.url).toBe(`/api/wildcard-tools/${TARGET.id}/faketool/settings`);
  const sent = JSON.parse(post.init.body);
  // replace, because this form has just shown every field the vocabulary has, so it IS the state.
  expect(sent.replace).toBe(true);
  expect(sent.settings.alphaSwitch).toBe(true);
  expect(sent.settings.betaMinutes).toBe(7);
  expect(sent.settings.deltaNames).toEqual(['one', 'two']);
  // The stored key the vocabulary no longer has is NOT sent back: this endpoint refuses an unknown
  // key, so carrying it would 400 every save the operator ever attempted.
  expect(sent.settings.strayKey).toBeUndefined();
});

test('a stored key the vocabulary does not have is reported rather than silently dropped', async () => {
  openModal();
  await waitFor(() => expect(screen.getByText('strayKey')).toBeInTheDocument());
  expect(screen.getByText(/not in the current vocabulary/)).toBeInTheDocument();
});

// The server refuses an owned flag, an unknown key and an unacceptable value, each with the reason.
// Swallowing that reason would leave the operator with a form that just does not save. It is put on
// the FIELD the server named, because that is the only place the operator can act on it.
test("the server's refusal lands on the field it names", async () => {
  mockFetch({ saveOk: false, saveResponse: { message: 'betaMinutes must be at most 10 minutes. BETA DANGER: a truncated run is stored as a complete one.' } });
  openModal();
  await waitFor(() => expect(screen.getByText('Alpha switch')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));

  await waitFor(() => expect(screen.getByTestId('error-betaMinutes')).toBeInTheDocument());
  expect(screen.getByTestId('error-betaMinutes').textContent).toMatch(/must be at most 10 minutes/);
  // And the field itself is marked, not just some text somewhere on a long page.
  expect(document.getElementById('wildcard-faketool-betaMinutes').className).toMatch(/is-invalid/);
});

// A refusal that is about the REQUEST rather than about one field has no field to go on, so it stays
// at the top. Losing it would leave a form that simply does not save.
test('a refusal that names no field is still shown', async () => {
  mockFetch({
    saveOk: false,
    saveResponse: { message: 'Nothing reads notAnOption for Fake Tool. A stored setting nothing reads changes nothing.' },
  });
  openModal();
  await waitFor(() => expect(screen.getByText('Alpha switch')).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(screen.getByText(/Nothing reads notAnOption/)).toBeInTheDocument());
});

// httpx already has a wired configuration store. A second vocabulary for it would be exactly the
// drift this registry exists to prevent, so the modal links out instead of drawing a form.
test('a tool that delegates links out instead of rendering a form', async () => {
  mockFetch({
    settings: {
      tool: 'httpx', tool_name: 'httpx', step: 8, phase: 'Live web servers',
      settings: {}, options: {}, groups: [], owned_flags: {},
      delegates_to: 'httpx_configs',
      limitation: 'httpx ALREADY has a configuration store and it is wired.',
      runner_reads_settings: true,
    },
  });
  const onDelegate = jest.fn();
  openModal({ tool: { key: 'httpx', name: 'httpx' }, onDelegate });

  await waitFor(() => expect(
    screen.getByRole('button', { name: /Open the existing httpx_configs configuration/ })).toBeInTheDocument());
  expect(screen.getByText(/ALREADY has a configuration store/)).toBeInTheDocument();
  // No form, and therefore no Save: there is nothing here to save.
  expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: /Open the existing httpx_configs configuration/ }));
  expect(onDelegate).toHaveBeenCalledWith('httpx_configs', expect.objectContaining({ tool: 'httpx' }));
});

// An empty vocabulary is a legitimate answer for assetfinder and sublist3r, and it must be
// distinguishable from a tool nobody got round to.
test('a tool with nothing to configure explains why rather than showing an empty form', async () => {
  mockFetch({
    settings: {
      tool: 'assetfinder', tool_name: 'Assetfinder', step: 3, phase: 'Subdomain discovery',
      settings: {}, options: {}, groups: [],
      owned_flags: { '-subs-only': "The tool's ONLY flag, and the runner already sets it." },
      limitation: 'AN EMPTY VOCABULARY IS THE MEASURED ANSWER, NOT A GAP.',
      runner_reads_settings: true,
    },
  });
  openModal({ tool: { key: 'assetfinder', name: 'Assetfinder' } });

  await waitFor(() => expect(screen.getByText(/MEASURED ANSWER, NOT A GAP/)).toBeInTheDocument());
  expect(screen.getByText('-subs-only')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
});

// ---------------------------------------------------------------------------------------------
// Validation. The screen used to put a red <Alert> under EVERY option that carried a caveat, which
// on the live registry is 130 of 175 of them, while doing no validation at all: zero type="number"
// inputs, zero uses of min_items, zero isInvalid. These are the properties that has to keep.
// ---------------------------------------------------------------------------------------------

// THE REGRESSION GUARD. A tool whose options are all ordinary must produce a screen with no alert
// on it at all. If this fails, someone has started rendering prose as an error again.
const ORDINARY = {
  tool: 'ordinarytool',
  tool_name: 'Ordinary Tool',
  step: 2,
  phase: 'Invented ordinary phase',
  settings: {},
  options: {
    ordinaryCount: {
      kind: 'int', group: 'Ordinary Group', label: 'Ordinary count', flag: '-n',
      provenance: 'measured', min: 1, max: 50,
      placeholder: 'Unset, so the tool uses its own default.',
      why: 'It decides how many things are looked at.',
      danger: 'Raising it raises the load a single origin sees, which the per-host limits are the correct answer to rather than lowering this.',
    },
    ordinaryMode: {
      kind: 'enum', group: 'Ordinary Group', label: 'Ordinary mode', flag: '-m',
      provenance: 'measured', choices: ['fast', 'thorough'],
      placeholder: 'Unset.',
      danger: 'Either choice changes what the scan covers.',
    },
    ordinarySwitch: {
      kind: 'bool', group: 'Ordinary Group', label: 'Ordinary switch', flag: '-o',
      provenance: 'unverified',
      placeholder: 'Off.',
      danger: 'SEMANTICS UNVERIFIED. The flag is accepted but no test proved what it does.',
    },
  },
  groups: ['Ordinary Group'],
  owned_flags: {},
  runner_reads_settings: true,
  would_add_args: [],
};

test('a tool whose options are all ordinary renders NO alert', async () => {
  mockFetch({ settings: ORDINARY });
  openModal({ tool: { key: 'ordinarytool', name: 'Ordinary Tool' } });
  await waitFor(() => expect(screen.getByText('Ordinary count')).toBeInTheDocument());

  // Every caveat is still on the page. None of them is an error, a warning or a box.
  expect(screen.getByText(/Raising it raises the load/)).toBeInTheDocument();
  expect(screen.getByText(/Either choice changes what the scan covers/)).toBeInTheDocument();
  expect(screen.getByText(/SEMANTICS UNVERIFIED/)).toBeInTheDocument();
  expect(document.querySelectorAll('.alert')).toHaveLength(0);
  expect(document.querySelectorAll('.invalid-feedback')).toHaveLength(0);
});

test('a number input carries the schema constraint so a bad value is hard to enter at all', async () => {
  mockFetch({ settings: ORDINARY });
  openModal({ tool: { key: 'ordinarytool', name: 'Ordinary Tool' } });
  await waitFor(() => expect(document.getElementById('wildcard-ordinarytool-ordinaryCount')).toBeInTheDocument());
  const input = document.getElementById('wildcard-ordinarytool-ordinaryCount');
  expect(input).toHaveAttribute('type', 'number');
  expect(input).toHaveAttribute('min', '1');
  expect(input).toHaveAttribute('max', '50');
  expect(input).toHaveAttribute('step', '1');
});

test('an out-of-range number shows an inline error on that field and blocks Save', async () => {
  mockFetch({ settings: ORDINARY });
  openModal({ tool: { key: 'ordinarytool', name: 'Ordinary Tool' } });
  await waitFor(() => expect(document.getElementById('wildcard-ordinarytool-ordinaryCount')).toBeInTheDocument());
  const input = document.getElementById('wildcard-ordinarytool-ordinaryCount');

  fireEvent.change(input, { target: { value: '0' } });
  fireEvent.blur(input);

  await waitFor(() => expect(screen.getByTestId('error-ordinaryCount')).toBeInTheDocument());
  expect(screen.getByTestId('error-ordinaryCount').textContent).toMatch(/at least 1/);
  expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
  // And the operator is told WHICH field, because "something is invalid" is not an answer on a
  // screen with forty options.
  expect(screen.getByText(/Fix Ordinary count to save/)).toBeInTheDocument();
});

test('a valid number shows nothing at all and leaves Save enabled', async () => {
  mockFetch({ settings: ORDINARY });
  openModal({ tool: { key: 'ordinarytool', name: 'Ordinary Tool' } });
  await waitFor(() => expect(document.getElementById('wildcard-ordinarytool-ordinaryCount')).toBeInTheDocument());
  const input = document.getElementById('wildcard-ordinarytool-ordinaryCount');

  fireEvent.change(input, { target: { value: '7' } });
  fireEvent.blur(input);

  expect(screen.queryByTestId('error-ordinaryCount')).not.toBeInTheDocument();
  expect(document.querySelectorAll('.invalid-feedback')).toHaveLength(0);
  expect(screen.getByRole('button', { name: 'Save' })).not.toBeDisabled();
});

// A value already in the store that the vocabulary would now refuse is shown straight away: it is a
// committed decision, not something the operator is halfway through typing.
test('a stored value the vocabulary would refuse is flagged without being touched', async () => {
  mockFetch({ settings: { ...ORDINARY, settings: { ordinaryCount: 999 } } });
  openModal({ tool: { key: 'ordinarytool', name: 'Ordinary Tool' } });
  await waitFor(() => expect(screen.getByTestId('error-ordinaryCount')).toBeInTheDocument());
  expect(screen.getByTestId('error-ordinaryCount').textContent).toMatch(/at most 50/);
  expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
});

// An enum is a select built from the served choices, so a value outside them cannot be typed.
test('an enum offers exactly the served choices and nothing else', async () => {
  mockFetch({ settings: ORDINARY });
  openModal({ tool: { key: 'ordinarytool', name: 'Ordinary Tool' } });
  await waitFor(() => expect(document.getElementById('wildcard-ordinarytool-ordinaryMode')).toBeInTheDocument());
  const select = document.getElementById('wildcard-ordinarytool-ordinaryMode');
  expect(select.tagName).toBe('SELECT');
  expect([...select.options].map((o) => o.value)).toEqual(['', 'fast', 'thorough']);
});

// A stored enum value the vocabulary no longer offers must not vanish into a blank select and be
// rewritten by the next save without anybody being told.
test('a stored enum value outside the choices is kept, shown and marked', async () => {
  mockFetch({ settings: { ...ORDINARY, settings: { ordinaryMode: 'retired' } } });
  openModal({ tool: { key: 'ordinarytool', name: 'Ordinary Tool' } });
  await waitFor(() => expect(screen.getByTestId('error-ordinaryMode')).toBeInTheDocument());
  const select = document.getElementById('wildcard-ordinarytool-ordinaryMode');
  expect(select.value).toBe('retired');
  expect(screen.getByTestId('error-ordinaryMode').textContent).toMatch(/only: fast, thorough/);
});

// The sparing case, and it is the SERVER that decides. A caveat is help text no matter how alarming
// it reads; a warning appears only where the registry declares one.
//
// The classifier this replaced read the English of `danger` and was wrong on 4 of the 20 fields it
// marked, twice putting "Throws real findings away" on an option whose own text begins
// "NOT IMPLEMENTED". Prose is written to explain, not to be parsed.
test('a caveat is help text; only a server-declared hazard is marked', async () => {
  mockFetch({
    settings: {
      ...ORDINARY,
      options: {
        ...ORDINARY.options,
        // Alarming prose, no declaration. Renders as help text like any other caveat.
        formFill: {
          kind: 'bool', group: 'Ordinary Group', label: 'Automatic form filling', flag: '-aff',
          provenance: 'unverified', placeholder: 'Off.',
          danger: 'It SUBMITS FORMS on a live estate: on a production site that can mean created records, sent mail or triggered workflows.',
        },
        // Declared by the server. This is the only thing that earns emphasis.
        wipeResults: {
          kind: 'bool', group: 'Ordinary Group', label: 'Clear stored results first', flag: '-wipe',
          provenance: 'measured', placeholder: 'Off.',
          danger: 'Deletes every stored finding for this target before the scan starts.',
          hazard: 'Throws real findings away',
        },
      },
    },
  });
  openModal({ tool: { key: 'ordinarytool', name: 'Ordinary Tool' } });
  await waitFor(() => expect(screen.getByText(/SUBMITS FORMS/)).toBeInTheDocument());

  // Exactly one field on the screen is marked, and it is the declared one.
  expect(screen.getAllByText(/Throws real findings away/)).toHaveLength(1);

  // The alarming-but-undeclared caveat is plain muted help text, same as every other caveat.
  expect(screen.getByText(/SUBMITS FORMS/).className).toMatch(/text-white-50/);
  expect(screen.getByText(/Raising it raises the load/).className).toMatch(/text-white-50/);

  // And still no alert boxes anywhere. This is the property that was broken.
  expect(document.querySelectorAll('.alert')).toHaveLength(0);
});