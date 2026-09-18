import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import AttackVectorConfigureModal, {
  assertSelectionShape, domainOf, groupByDomain, problemsByField, riskChoicesFor,
} from './AttackVectorConfigureModal';

// These render for real, in jsdom. Two modals added to this app before compiled cleanly and threw
// on mount, and one of them white-screened the whole URL workflow.
//
// The fixtures below are shaped from the LIVE responses: GET /triage/{id}/settings measured on
// 1e9b4bec-e8ca-41ac-9da3-744322637f2b, and GET /{category}/{id}/{tool}/selection, whose handler
// (GetVectorSelection) is the one the endpoint tab reads. Every count in the selection fixture is
// different from every other, because a fixture where selected equals eligible would let a screen
// that renders one number twice pass.

const TARGET = { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' };

const jsonResponse = (body, ok = true, status = 200) => Promise.resolve({
  ok, status, json: () => Promise.resolve(body),
});

const SELECTION = {
  tool: 'triage-investigate',
  total: 5,
  selected: 4,
  eligible: 2,
  selected_but_unreachable: 2,
  scan_will_run: '2 of 5 vectors',
  reachable: ['query', 'body'],
  unreachable: ['fragment'],
  vectors: [
    { vector_id: 'v1', method: 'GET', url: 'https://beta.example.test/a?q=1', insertion_point: 'query', parameters: 'q', selected: true, eligible: true, deselected_by_operator: false },
    { vector_id: 'v2', method: 'GET', url: 'https://beta.example.test/b?s=1', insertion_point: 'query', parameters: 's', selected: false, eligible: false, deselected_by_operator: true, reason: 'Deselected for this run.' },
    { vector_id: 'v3', method: 'POST', url: 'https://alpha.example.test/c', insertion_point: 'body', parameters: 'id', selected: true, eligible: true, deselected_by_operator: false },
    { vector_id: 'v4', method: 'GET', url: 'https://alpha.example.test/d', insertion_point: 'fragment', parameters: '', selected: true, eligible: false, deselected_by_operator: false, reason: 'No HTTP probe reaches the fragment.' },
    { vector_id: 'v5', method: 'GET', url: 'https://alpha.example.test/e', insertion_point: 'header', parameters: 'X-Probe', selected: true, eligible: false, deselected_by_operator: false, reason: 'Not reached at this depth.' },
  ],
  note: 'Selection is stored sparsely: only the vectors you switch OFF are recorded.',
};

// Two classes only, and one of them is a name no hardcoded list in this app has ever contained.
// A form built from a list in the client would render neither.
const VOCABULARY = {
  classes: [
    {
      id: 1, key: 'ssti', name: 'SSTI', probe_count: 62,
      tiers: ['full', 'reduced'], risks: ['R1'],
      points: ['query', 'body', 'header', 'cookie', 'path'],
      unreachable: { fragment: 'the browser strips it before the request goes out' },
    },
    {
      id: 42, key: 'newclass', name: 'NEWCLASS', probe_count: 7,
      tiers: ['reduced'], risks: ['R0'],
      points: ['query'],
      unreachable: { cookie: 'no cookie parser reaches this sink' },
    },
    {
      id: 43, key: 'onerisk', name: 'ONERISK', probe_count: 3,
      tiers: ['reduced'], risks: ['R0'],
      points: ['body'],
      unreachable: { header: 'the sink is server side and never reads a header' },
    },
  ],
  tiers: ['reduced', 'full', 'opt_in'],
  risks: ['R0', 'R1', 'R2', 'R3'],
  slot_kinds: ['query', 'body', 'header', 'cookie', 'path'],
  encoders: ['', 'query', 'form', 'cookie'],
  oob_modes: ['', 'wildcard_dns', 'http_path'],
  encodings: ['utf8', 'base64'],
  marker_positions: ['prefix', 'suffix', 'inline'],
  detection_modes: [
    { mode: 'inherit', label: "Use the class's own oracle", requires: '' },
    { mode: 'reflect', label: 'The marker comes back in the response', requires: '' },
    { mode: 'body_regex', label: 'A regular expression matches the body', requires: 'pattern' },
    { mode: 'status_in', label: 'The response status is one of', requires: 'statuses' },
    { mode: 'time_delay', label: 'The response is slower than the baseline by', requires: 'delay_ms' },
  ],
  delivery_reasons: ['value_contains_crlf', 'slot_impossible_byte'],
};

const SETTINGS = {
  tier: 'reduced',
  classes: {
    ssti: { enabled: true, tier: 'reduced', max_risk: 'R2' },
    newclass: { enabled: false, tier: 'reduced', max_risk: 'R1' },
    onerisk: { enabled: true, tier: 'reduced', max_risk: 'R0' },
  },
  pacing: {
    requests_per_second: 3.33, concurrency: 2, per_slot_probes: 24, per_run_probes: 4000,
    mutating_allowance: 0, browser_allowance: 0, respect_target_budget: true,
  },
  oob: { mode: '', base: '', serves_content: false, grace_seconds: 60 },
  custom_payloads: [],
};

const VALIDATION = {
  ok: true,
  errors: [],
  warnings: [{
    field: 'oob.mode', code: 'no_collaborator',
    message: 'Classes that need a callback will report no_collaborator, which is not a clean.',
  }],
  payloads: [],
  enabled_classes: ['ssti', 'onerisk'],
  registry_violations: [],
  isolation_checks_not_run: [],
};

const SETTINGS_BODY = {
  scope_target_id: TARGET.id,
  tool: 'triage-investigate',
  settings: SETTINGS,
  defaults: SETTINGS,
  vocabulary: VOCABULARY,
  validation: VALIDATION,
  retired_classes: null,
};

// THE ROUTE IS PART OF THE CONTRACT, AND THIS MOCK USED TO HIDE IT.
//
// It matched any URL ending in "/selection" and answered everything else with an empty 200. Every
// test below passed while GET /api/attack-vectors/{id}/selection 404'd against the running
// server: the only selection routes registered were the per-tool
// /{category}/{id}/{tool}/selection, and vector_scan_selection is keyed by tool, so no per-target
// selection existed at all. A test that cannot fail for the reason the feature is broken is not a
// test.
//
// So the mock is now a ROUTER: it serves exactly the two URLs the server registers, and answers
// anything else with a 404 the way an unregistered route does. selectionRoute is a variable so a
// test can move the server's route and prove the suite notices.
const SELECTION_ROUTE = `/api/attack-vectors/${TARGET.id}/selection`;
const SETTINGS_ROUTE = `/api/triage/${TARGET.id}/settings`;

// What a gorilla/mux miss actually looks like: 404 with a text body, so res.json() would throw.
// The modal must survive that on its own, which is why this is not a JSON 404.
const notFound = () => Promise.resolve({
  ok: false,
  status: 404,
  json: () => Promise.reject(new SyntaxError('Unexpected token < in JSON at position 0')),
});

let selectionBody;
let settingsBody;
let putHandler;
let selectionRoute;

beforeEach(() => {
  selectionBody = SELECTION;
  settingsBody = SETTINGS_BODY;
  putHandler = null;
  selectionRoute = SELECTION_ROUTE;
  global.fetch = jest.fn((url, init) => {
    const u = String(url);
    if (u === selectionRoute) {
      if (init && init.method === 'POST') {
        return jsonResponse({
          tool: 'triage-investigate', updated: 1, enabled: false, total: 5,
          now_selected: 3, now_eligible: 1, selected_but_unreachable: 2,
          scan_will_run: '1 of 5 vectors',
          reading: '3 vectors are selected, and 1 of the 5 total will actually be sent.',
        });
      }
      return jsonResponse(selectionBody);
    }
    if (u === SETTINGS_ROUTE) {
      if (init && init.method === 'PUT' && putHandler) return putHandler(JSON.parse(init.body));
      return jsonResponse(settingsBody);
    }
    return notFound();
  });
});

const openTab = async (name) => {
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText(name)).toBeInTheDocument());
  fireEvent.click(screen.getByText(name));
};

// ---------------------------------------------------------------------------------------------
// The pure helpers
// ---------------------------------------------------------------------------------------------

test('the selection shape is asserted, and the refusal names the keys that actually arrived', () => {
  // The exact failure that once cancelled a correctly configured 29-vector scan: the caller
  // assumed a key named "items", read zero and stopped.
  const msg = assertSelectionShape({ items: [], count: 29 });
  expect(msg).toMatch(/no vectors array/);
  expect(msg).toMatch(/count, items/);
  expect(msg).toMatch(/vectors, selected, eligible, total, scan_will_run/);
  expect(assertSelectionShape(SELECTION)).toBe('');
});

test('a vector is grouped under its host, and an unparseable URL is kept rather than dropped', () => {
  expect(domainOf('https://a.example.test/x?q=1')).toBe('a.example.test');
  expect(domainOf('a.example.test/x')).toBe('a.example.test');
  expect(domainOf('')).toBe('unknown host');

  const groups = groupByDomain(SELECTION.vectors, '');
  expect(groups.map((g) => g.domain)).toEqual(['alpha.example.test', 'beta.example.test']);
  expect(groups[0].items).toHaveLength(3);
  expect(groups[1].selected).toBe(1);
});

test('a search narrows what is shown without changing a group count', () => {
  const groups = groupByDomain(SELECTION.vectors, 'X-Probe');
  const alpha = groups.find((g) => g.domain === 'alpha.example.test');
  expect(alpha.shown).toHaveLength(1);
  // The header still reports the whole group, or an operator reads "1 of 1 selected" on three.
  expect(alpha.items).toHaveLength(3);
});

test('validation is indexed by field so a problem lands on its own control', () => {
  const index = problemsByField({
    errors: [{ field: 'pacing.per_slot_probes', code: 'budget_not_positive', message: 'zero' }],
    warnings: [{ field: 'oob.mode', code: 'no_collaborator', message: 'not a clean' }],
  });
  expect(index['pacing.per_slot_probes'][0].level).toBe('error');
  expect(index['oob.mode'][0].level).toBe('warning');
});

// ---------------------------------------------------------------------------------------------
// Tab 1
// ---------------------------------------------------------------------------------------------

// The route, asserted as a literal string, because the bug was the route and nothing else. This
// URL is registered in server/main.go as GET /attack-vectors/{scope_target_id}/selection and
// served by utils.GetTargetVectorSelection; nginx strips the /api prefix.
test('the endpoint list is read from the per-target selection route', async () => {
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText('2 of 5 vectors')).toBeInTheDocument());

  const gets = global.fetch.mock.calls
    .filter(([, init]) => !init || !init.method || init.method === 'GET')
    .map(([u]) => String(u));
  expect(gets).toContain(`/api/attack-vectors/${TARGET.id}/selection`);
  // And EVERY selection read goes there. The per-tool route is
  // /api/{category}/{id}/{tool}/selection, keyed (scope_target_id, tool, vector_id), and it
  // cannot answer "which endpoints does the Investigate run cover".
  expect(gets.filter((u) => u.endsWith('/selection')))
    .toEqual([`/api/attack-vectors/${TARGET.id}/selection`]);
});

// THE NEGATIVE CONTROL for the test above, and the reason this file can be trusted now. With the
// server serving the OLD per-tool route only, the tab must fail visibly. If this test ever passes
// while the previous one also passes against a wrong URL, the mock has gone back to matching a
// suffix.
test('the tab reports a 404 when the selection route is not the one the server serves', async () => {
  selectionRoute = `/api/sqli/${TARGET.id}/sqlmap/selection`;
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText(/HTTP 404/)).toBeInTheDocument());
  expect(screen.queryByText('2 of 5 vectors')).not.toBeInTheDocument();
});

test('a write goes to the same per-target route the list was read from', async () => {
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText('alpha.example.test')).toBeInTheDocument());
  fireEvent.click(screen.getAllByRole('checkbox')[0]);

  await waitFor(() => {
    const post = global.fetch.mock.calls.find(([, init]) => init && init.method === 'POST');
    expect(post).toBeTruthy();
    expect(String(post[0])).toBe(`/api/attack-vectors/${TARGET.id}/selection`);
  });
});

test('the endpoint tab shows the SERVER counts, not a sum over the rows', async () => {
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText('2 of 5 vectors')).toBeInTheDocument());
  expect(screen.getByText(/4 of 5 selected/)).toBeInTheDocument();
  // The gap between chosen and sent is stated. Without it a clean result for 5 vectors reads as
  // 5 tested when 2 were.
  expect(screen.getByText(/2 selected vectors will not be sent/)).toBeInTheDocument();
});

test('endpoints are grouped by domain, hosts alphabetical', async () => {
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText('alpha.example.test')).toBeInTheDocument());
  const rows = screen.getByTestId('endpoint-rows');
  const hosts = within(rows).getAllByText(/example\.test$/).map((el) => el.textContent);
  expect(hosts).toEqual(['alpha.example.test', 'beta.example.test']);
});

test('a whole domain is selected by named ids, never by all:true', async () => {
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText('alpha.example.test')).toBeInTheDocument());
  const rows = screen.getByTestId('endpoint-rows');
  // The first "None" inside the list belongs to the first domain group.
  fireEvent.click(within(rows).getAllByText('None')[0]);

  await waitFor(() => {
    const post = global.fetch.mock.calls.find(([, init]) => init && init.method === 'POST');
    expect(post).toBeTruthy();
    const body = JSON.parse(post[1].body);
    // all:true resolves against every vector the server has, not the three on this host, so a
    // group action has to name its ids or it acts on the whole table.
    expect(body.all).toBeUndefined();
    expect(body.vector_ids).toEqual(['v3', 'v4', 'v5']);
    expect(body.enabled).toBe(false);
  });
});

test('deselecting one endpoint posts just that vector and shows the server reading', async () => {
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText('alpha.example.test')).toBeInTheDocument());
  fireEvent.click(screen.getByLabelText('POST https://alpha.example.test/c body'));

  await waitFor(() => {
    const post = global.fetch.mock.calls.find(([, init]) => init && init.method === 'POST');
    expect(JSON.parse(post[1].body)).toEqual({ vector_ids: ['v3'], enabled: false });
  });
  await waitFor(() => expect(
    screen.getByText(/3 vectors are selected, and 1 of the 5 total/),
  ).toBeInTheDocument());
});

test('an endpoint reply without a vectors array is refused, not read as an empty selection', async () => {
  selectionBody = { items: [], count: 29 };
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText(/no vectors array/)).toBeInTheDocument());
  // And nothing claims a zero: no count is drawn at all.
  expect(screen.queryByText(/will be scanned/)).toBeNull();
  expect(screen.queryByText(/of 5 selected/)).toBeNull();
});

test('the search box filters the endpoint rows', async () => {
  render(<AttackVectorConfigureModal show handleClose={() => {}} activeTarget={TARGET} />);
  await waitFor(() => expect(screen.getByText('alpha.example.test')).toBeInTheDocument());
  fireEvent.change(screen.getByLabelText('Filter endpoints'), { target: { value: 'beta' } });
  await waitFor(() => expect(screen.queryByText('alpha.example.test')).toBeNull());
  expect(screen.getByText('beta.example.test')).toBeInTheDocument();
});

// ---------------------------------------------------------------------------------------------
// Tab 2
// ---------------------------------------------------------------------------------------------

test('the class list is built from the served vocabulary, including a class no list here knows', async () => {
  await openTab('Investigate settings');
  // If the form were hand written this would pass with the server sending nothing at all, so the
  // fixture names a class that appears in no constant in this app.
  await waitFor(() => expect(screen.getByText('NEWCLASS')).toBeInTheDocument());
  expect(screen.getByText('SSTI')).toBeInTheDocument();
  expect(screen.getByText('7 probes')).toBeInTheDocument();
  expect(screen.getByText('2 of 3 classes enabled.')).toBeInTheDocument();
});

// The count and the list are whatever the server hands over. The placeholder classifier used to
// arrive in that list, enabled, and the line above it read "11 of 11 classes enabled" for a class
// that plans nothing and sends nothing. The filter belongs on the server, so what is asserted
// here is that this screen adds nothing of its own to what it was given.
test('the class list is exactly the served list, with nothing added and nothing assumed', async () => {
  await openTab('Investigate settings');
  await waitFor(() => expect(screen.getByText('NEWCLASS')).toBeInTheDocument());
  const names = VOCABULARY.classes.map((c) => c.name);
  names.forEach((n) => expect(screen.getByText(n)).toBeInTheDocument());
  expect(screen.queryByText('EXAMPLE')).toBeNull();
  expect(screen.getByText(`2 of ${names.length} classes enabled.`)).toBeInTheDocument();
});

test('a class with one tier gets no depth control, and one with two does', async () => {
  await openTab('Investigate settings');
  await waitFor(() => expect(screen.getByText('NEWCLASS')).toBeInTheDocument());
  expect(screen.getByLabelText('Depth for SSTI')).toBeInTheDocument();
  expect(screen.queryByLabelText('Depth for NEWCLASS')).toBeNull();
});

// ---------------------------------------------------------------------------------------------
// the risk ceiling offers the class's own levels, not the global vocabulary
// ---------------------------------------------------------------------------------------------

test('the risk levels offered are the class\'s own, and the global vocabulary is not one of them', () => {
  // The four global tiers rendered for every class, so "up to R2" appeared on classes whose every
  // probe is R0. The ceiling is a refusal: above the top probe it refuses nothing.
  expect(riskChoicesFor({ risks: ['R0'] }, 'R0')).toEqual(['R0']);
  expect(riskChoicesFor({ risks: ['R0', 'R2'] }, 'R2')).toEqual(['R0', 'R2']);
  // The stored value is kept even when the class does not declare it, because a select whose
  // value matches no option renders blank and a blank ceiling reads as no ceiling.
  expect(riskChoicesFor({ risks: ['R0'] }, 'R2')).toEqual(['R0', 'R2']);
  expect(riskChoicesFor({ risks: [] }, '')).toEqual([]);
  // Ordered by depth rather than alphabetically, so the list reads as a ladder.
  expect(riskChoicesFor({ risks: ['R3', 'R1', 'R0'] }, '')).toEqual(['R0', 'R1', 'R3']);
});

test('a class with one risk level gets no ceiling control, and one with two does', async () => {
  await openTab('Investigate settings');
  await waitFor(() => expect(screen.getByText('ONERISK')).toBeInTheDocument());

  // ONERISK declares R0 and is stored at R0: there is nothing to choose, so there is no control,
  // the same rule the depth control follows.
  expect(screen.queryByLabelText('Maximum risk for ONERISK')).toBeNull();
  // Scoped to that class's own row: 'up to R0' is also an option inside another class's select,
  // and a test that matched it there would pass with this row rendering nothing at all.
  const row = screen.getByText('ONERISK').closest('div');
  expect(within(row).getByText('up to R0')).toBeInTheDocument();

  // SSTI declares R1 and the stored document says R2, which is the shape every document saved
  // before this change has. Both stay offered, and the select is not blank.
  const select = screen.getByLabelText('Maximum risk for SSTI');
  expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual(['up to R1', 'up to R2']);
  expect(select).toHaveValue('R2');
  // R3 is in the global vocabulary and in no class here, so it must not be offered anywhere.
  expect(screen.queryByText('up to R3')).toBeNull();
});

test('a ceiling that refuses some of the class\'s probes is reported on that control', async () => {
  settingsBody = {
    ...SETTINGS_BODY,
    validation: {
      ...VALIDATION,
      warnings: [{
        field: 'classes.ssti.max_risk', code: 'risk_ceiling_refuses_some_probes',
        message: 'SSTI also declares probes at R2, above this R1 ceiling. Those are refused on safety grounds and recorded as unknown, never as clean.',
      }],
    },
  };
  await openTab('Investigate settings');
  await waitFor(() => expect(screen.getByText(/above this R1 ceiling/)).toBeInTheDocument());
  expect(screen.getByText(/never as clean/)).toBeInTheDocument();
});

// ---------------------------------------------------------------------------------------------

test('the tab says what the Investigate button does with what is configured here', async () => {
  // The screen stored a document nothing read, which is a tab claiming to configure a scan it did
  // not drive. StartTriageRun reads it now, so the sentence is a statement rather than a caveat.
  await openTab('Investigate settings');
  await waitFor(() => expect(
    screen.getByText(/reflection passes first and then the classifiers configured here/),
  ).toBeInTheDocument());
});

test('a point the class never reaches is shown with the reason rather than omitted', async () => {
  await openTab('Investigate settings');
  await waitFor(() => expect(screen.getByText('NEWCLASS')).toBeInTheDocument());
  const never = screen.getByText('cookie never');
  expect(never).toHaveAttribute('title', 'no cookie parser reaches this sink');
});

test('a warning from the stored document is rendered at its own field', async () => {
  await openTab('Investigate settings');
  await waitFor(() => expect(
    screen.getByText(/report no_collaborator, which is not a clean/),
  ).toBeInTheDocument());
});

test('save PUTs the whole document and reports what would run', async () => {
  let sent = null;
  putHandler = (body) => {
    sent = body;
    return jsonResponse({ scope_target_id: TARGET.id, saved: true, settings: body.settings, validation: VALIDATION, retired_classes: [] });
  };
  await openTab('Investigate settings');
  await waitFor(() => expect(screen.getByText('NEWCLASS')).toBeInTheDocument());
  fireEvent.click(screen.getByText('Save'));

  await waitFor(() => expect(sent).toBeTruthy());
  // Whole document, not a diff: a partial write to a full-document endpoint wipes what it omits.
  expect(Object.keys(sent.settings).sort()).toEqual(['classes', 'custom_payloads', 'oob', 'pacing', 'tier']);
  expect(sent.settings.classes.newclass).toEqual({ enabled: false, tier: 'reduced', max_risk: 'R1' });
  // A class whose ceiling control is not rendered still travels in the document at its stored
  // value. Dropping it would be a partial write to a full-document endpoint.
  expect(sent.settings.classes.onerisk).toEqual({ enabled: true, tier: 'reduced', max_risk: 'R0' });
  await waitFor(() => expect(screen.getByText(/Saved\. 2 classes will run\./)).toBeInTheDocument());
});

test('a refused save keeps the typed document and puts each problem on its control', async () => {
  putHandler = () => jsonResponse({
    error: 'invalid_settings',
    saved: false,
    settings: SETTINGS,
    validation: {
      ok: false,
      errors: [{
        field: 'pacing.per_slot_probes', code: 'budget_not_positive',
        message: 'A per-slot budget of zero makes every slot report exhausted rather than tested.',
      }],
      warnings: [],
      payloads: [],
      enabled_classes: ['ssti'],
      registry_violations: [],
      isolation_checks_not_run: [],
    },
  }, false, 400);

  await openTab('Investigate settings');
  await waitFor(() => expect(screen.getByLabelText('Probes per slot')).toBeInTheDocument());
  fireEvent.change(screen.getByLabelText('Probes per slot'), { target: { value: '0' } });
  fireEvent.click(screen.getByText('Save'));

  await waitFor(() => expect(
    screen.getByText(/A per-slot budget of zero makes every slot report exhausted/),
  ).toBeInTheDocument());
  // Nothing was written, so the form still holds what the operator typed.
  expect(screen.getByLabelText('Probes per slot')).toHaveValue(0);
});

// ---------------------------------------------------------------------------------------------
// The custom payload editor
// ---------------------------------------------------------------------------------------------

const addPayload = async () => {
  await openTab('Investigate settings');
  await waitFor(() => expect(screen.getByText('Add payload')).toBeInTheDocument());
  fireEvent.click(screen.getByText('Add payload'));
  await waitFor(() => expect(screen.getByLabelText('Attack class for cp-1')).toBeInTheDocument());
};

test('a payload must be given exactly one class, and there is no all', async () => {
  await addPayload();
  const select = screen.getByLabelText('Attack class for cp-1');
  const options = within(select).getAllByRole('option').map((o) => o.textContent);
  expect(options).toEqual(['Choose one class', 'SSTI (62 probes)', 'NEWCLASS (7 probes)', 'ONERISK (3 probes)']);
  expect(options.some((o) => /all/i.test(o))).toBe(false);
  expect(select).toHaveValue('');
});

test('a payload must be given a detection rule, and inherit is a choice rather than the default', async () => {
  await addPayload();
  const select = screen.getByLabelText('Detection mode for cp-1');
  expect(select).toHaveValue('');
  const options = within(select).getAllByRole('option').map((o) => o.textContent);
  expect(options[0]).toBe('Choose one');
  expect(options).toContain("Use the class's own oracle");

  // The mode that needs a pattern grows the field that carries it.
  expect(screen.queryByLabelText('Detection pattern for cp-1')).toBeNull();
  fireEvent.change(select, { target: { value: 'body_regex' } });
  expect(screen.getByLabelText('Detection pattern for cp-1')).toBeInTheDocument();
});

test('an insertion point the chosen class never reaches cannot be ticked', async () => {
  await addPayload();
  fireEvent.change(screen.getByLabelText('Attack class for cp-1'), { target: { value: 'newclass' } });
  const cookie = screen.getByLabelText('cookie');
  expect(cookie).toBeDisabled();
  expect(screen.getByLabelText('query')).not.toBeDisabled();
});

test('a collision refusal is shown on the payload, naming what already owns those bytes', async () => {
  putHandler = () => jsonResponse({
    error: 'invalid_settings',
    saved: false,
    settings: SETTINGS,
    validation: {
      ok: false,
      errors: [{
        field: 'custom_payloads[0].payload', code: 'payload_collision',
        message: 'These bytes are already the shipped probe sql/boolean-1 of class SQL. Two probes with the same payload cannot be told apart when one is blocked, so a block on either records the other as clean.',
      }],
      warnings: [],
      payloads: [{
        index: 0, id: 'cp-1', class: 'ssti', ok: false, probe_id: 'custom/ssti/cp-1', logical_len: 12,
        delivery: [],
        problems: [],
      }],
      enabled_classes: ['ssti'],
      registry_violations: [],
      isolation_checks_not_run: [],
    },
  }, false, 400);

  await addPayload();
  fireEvent.click(screen.getByText('Save'));
  await waitFor(() => expect(
    screen.getByText(/already the shipped probe sql\/boolean-1 of class SQL/),
  ).toBeInTheDocument());
});

test("the server's delivery check is shown per insertion point, and delivered is not enough", async () => {
  putHandler = () => jsonResponse({
    error: 'invalid_settings',
    saved: false,
    settings: SETTINGS,
    validation: {
      ok: false,
      errors: [],
      warnings: [],
      payloads: [{
        index: 0, id: 'cp-1', class: 'ssti', ok: false, probe_id: 'custom/ssti/cp-1', logical_len: 9,
        delivery: [
          { point: 'query', encoder: 'query', delivered: true, survived: 'encoded', proven: true },
          {
            point: 'cookie', encoder: 'cookie', delivered: true, survived: 'mangled', proven: false,
            reason: 'slot_impossible_byte',
            detail: 'a semicolon in a cookie value is split by any RFC 6265 parser',
          },
        ],
        problems: [],
      }],
      enabled_classes: ['ssti'],
      registry_violations: [],
      isolation_checks_not_run: [],
    },
  }, false, 400);

  await addPayload();
  fireEvent.click(screen.getByText('Save'));
  await waitFor(() => expect(screen.getByText(/arrives encoded/)).toBeInTheDocument());
  // The cookie row is the one that looks fine and is not: delivered true, proven false.
  expect(screen.getByText(/split by any RFC 6265 parser/)).toBeInTheDocument();
});

test('a retired class is named rather than silently dropped', async () => {
  // Both a class the register dropped and the placeholder that was never an attack class arrive
  // here, and the one honest thing they share is that nothing would run them.
  settingsBody = { ...SETTINGS_BODY, retired_classes: ['example', 'ldap'] };
  await openTab('Investigate settings');
  await waitFor(() => expect(
    screen.getByText(/Removed from this document because nothing would run them/),
  ).toBeInTheDocument());
  expect(screen.getByText(/example, ldap/)).toBeInTheDocument();
});
