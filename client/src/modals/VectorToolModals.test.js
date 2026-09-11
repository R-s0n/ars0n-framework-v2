import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import VectorToolResultsModal from './VectorToolResultsModal';
import VectorToolConfigModal from './VectorToolConfigModal';
import AttackToolCard from '../components/AttackToolCard';
import GraphQLEndpointHelper, { appendEndpoints } from './GraphQLEndpointHelper';
import { ATTACK_TOOL_SECTIONS } from '../data/attackTools';
import { WIRED_CATEGORIES } from '../data/wiredCategories';

// These render for real, in jsdom, because the last two modals added to this app compiled cleanly
// and then threw on mount: one from a const arrow named in a dependency array above its own
// declaration, which white-screened the entire URL workflow. A test that only checks the output of a
// pure function would have passed through both.

const TOOL = { key: 'domdig', name: 'domdig', url: 'https://example.invalid', description: 'x' };
const TARGET = { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' };

const jsonResponse = (body) => Promise.resolve({ ok: true, json: () => Promise.resolve(body) });

const RESULTS = {
  scan_id: 's1',
  findings: [{
    id: 'f1', vector_id: 'v1', tool: 'domdig', kind: 'domxss',
    kind_label: 'Executed in a browser', severity: 'high', confidence: 'confirmed',
    insertion_point: 'query', param: 'q', payload: '<img src=a onerror=alert(1)>',
    method: 'GET', url: 'http://t/x?q=1', evidence: 'DOM XSS found',
    detection_method: 'browser-execution', inject_type: '', raw_request: 'GET /x', raw_response: '200',
    triage: 'new', domain: 't', vector_path: '/x',
  }],
  skipped: [
    { vector_id: 'v2', reason: 'domdig navigates a browser and cannot POST a body.', insertion_point: 'body', method: 'POST', domain: 't', path: '/c' },
    { vector_id: 'v3', reason: 'domdig navigates a browser and cannot POST a body.', insertion_point: 'body', method: 'POST', domain: 't', path: '/d' },
  ],
};

// The selection payload, shaped exactly like the live one measured against a real target: five
// vectors of which the operator switched one off, the tool cannot reach two, and two will be sent.
// The three counts are deliberately all different, because a fixture where selected == eligible
// would let a screen that renders one number twice pass every test here.
const SELECTION = {
  tool: 'domdig', tool_name: 'domdig', category: 'xss',
  total: 5, selected: 4, eligible: 2, selected_but_unreachable: 2,
  scan_will_run: '2 of 5 vectors',
  reachable: ['query'], unreachable: ['body', 'header'],
  limitation: 'domdig fuzzes the query string.',
  vectors: [
    { vector_id: 'v1', method: 'GET', url: 'http://t/a?q=1', insertion_point: 'query', parameters: 'q', selected: true, eligible: true, deselected_by_operator: false },
    { vector_id: 'v2', method: 'GET', url: 'http://t/b?q=1', insertion_point: 'query', parameters: 'q', selected: false, eligible: false, deselected_by_operator: true, reason: 'Deselected for domdig in its Config. The vector is still here and still scanned by every other tool it was not deselected for.' },
    { vector_id: 'v5', method: 'GET', url: 'http://t/e?s=1', insertion_point: 'query', parameters: 's', selected: true, eligible: true, deselected_by_operator: false },
    { vector_id: 'v3', method: 'POST', url: 'http://t/c', insertion_point: 'body', parameters: 'id', selected: true, eligible: false, deselected_by_operator: false, reason: 'domdig navigates a browser and cannot POST a body.' },
    { vector_id: 'v4', method: 'GET', url: 'http://t/d', insertion_point: 'header', parameters: 'X-Forwarded-For', selected: true, eligible: false, deselected_by_operator: false, reason: 'domdig cannot reach a header insertion point.' },
  ],
  note: 'Selection is per tool and stored sparsely.',
};

// Opening the tab is two steps in every selection test, so it is one function here.
const openVectorTab = async () => {
  render(<VectorToolConfigModal show handleClose={() => {}} activeTarget={TARGET} tool={TOOL} category="xss" />);
  await waitFor(() => expect(screen.getByText('Attack vectors')).toBeInTheDocument());
  fireEvent.click(screen.getByText('Attack vectors'));
  await waitFor(() => expect(screen.getByText(/vectors will be scanned/)).toBeInTheDocument());
};

const STATUS = {
  tool: 'domdig',
  eligibility: { tool: 'domdig', eligible: 27, total: 71, reachable: ['query'], unreachable: ['body', 'cookie', 'header', 'path'], limitation: 'domdig fuzzes the query string.' },
  scan: { scan_id: 's1', status: 'completed', total_vectors: 71, eligible_vectors: 27, completed_vectors: 27, finding_count: 1, current_host: '' },
};

beforeEach(() => {
  global.fetch = jest.fn((url) => {
    if (String(url).endsWith('/results')) return jsonResponse(RESULTS);
    if (String(url).endsWith('/status')) return jsonResponse(STATUS);
    if (String(url).endsWith('/selection')) return jsonResponse(SELECTION);
    if (String(url).endsWith('/settings')) {
      return jsonResponse({
        tool: 'domdig', tool_name: 'domdig', settings: { modes: 'fuzz' },
        options: {
          modes: { kind: 'csv', group: 'Scan modes', label: 'Modes', flag: '-m' },
          excludeUrl: { kind: 'string', group: 'Scope', label: 'Exclude', flag: '-X', repeatable: true },
        },
        groups: ['Scan modes', 'Scope'],
        eligibility: STATUS.eligibility,
      });
    }
    return jsonResponse({});
  });
});

test('the results modal mounts and shows the findings', async () => {
  render(<VectorToolResultsModal show handleClose={() => {}} activeTarget={TARGET} tool={TOOL} category="xss" />);
  await waitFor(() => expect(screen.getByText(/Executed in a browser/)).toBeInTheDocument());
});

// The whole reason this screen exists. Two of the three tools cover a minority of the vector table,
// so a findings list on its own would let "0 findings" be read as "nothing there".
test('the results modal reports how many vectors were never tested', async () => {
  render(<VectorToolResultsModal show handleClose={() => {}} activeTarget={TARGET} tool={TOOL} category="xss" />);
  await waitFor(() => expect(screen.getByText(/never tested/)).toBeInTheDocument());
  expect(screen.getByText(/Not tested \(2\)/)).toBeInTheDocument();
  expect(screen.getByText(/vectors tested/)).toBeInTheDocument();
});

test('the config modal mounts and builds its form from the served vocabulary', async () => {
  render(<VectorToolConfigModal show handleClose={() => {}} activeTarget={TARGET} tool={TOOL} category="xss" />);
  // The label comes from the server, not from a list in the modal. If the form were hand written
  // this would pass with the server sending nothing at all.
  await waitFor(() => expect(screen.getByText('Modes')).toBeInTheDocument());
  expect(screen.getByText('-m')).toBeInTheDocument();
});

test('the config modal states how much of the vector table the tool can reach', async () => {
  render(<VectorToolConfigModal show handleClose={() => {}} activeTarget={TARGET} tool={TOOL} category="xss" />);
  await waitFor(() => expect(screen.getByText(/of 71/)).toBeInTheDocument());
  expect(screen.getByText('27')).toBeInTheDocument();
});

// THE HEADER IS THE FEATURE. Selected and eligible are different numbers and the gap between them is
// the thing an operator has to see: a screen reporting only "4 selected" lets a clean result be read
// as four vectors tested when two were sent.
test('the vector tab states both counts and the gap between them', async () => {
  await openVectorTab();
  // What will actually be sent.
  expect(screen.getByText('of 5 vectors will be scanned')).toBeInTheDocument();
  expect(screen.getByText('2')).toBeInTheDocument();
  // What the operator chose, and what they switched off, which is a different number again.
  expect(screen.getByText(/4 of 5 selected, 1 switched off here\./)).toBeInTheDocument();
  // The gap. Phrased as the consequence, not as the mechanism: a tool that CAN reach a body vector
  // and simply is not configured to would be libelled by the word "unreachable", and the operator
  // talked out of the setting that fixes it.
  expect(screen.getByText(/2 selected vectors will not be sent by domdig\. Each one below says why\./))
    .toBeInTheDocument();
});

// Two ineligible vectors, ineligible for reasons that are not alike: one the operator can undo from
// this screen and one they cannot. Rendering both as a checkbox makes the control lie.
test('a vector the operator switched off stays switchable, one the tool cannot reach does not', async () => {
  await openVectorTab();

  // Three live checkboxes: the two eligible query vectors and the one the operator switched off.
  // The body and header vectors the tool cannot reach get no control at all.
  const boxes = screen.getAllByRole('checkbox');
  expect(boxes).toHaveLength(3);
  expect(screen.getByLabelText('GET http://t/b?q=1')).not.toBeChecked();
  expect(screen.getByLabelText('GET http://t/a?q=1')).toBeChecked();
  expect(screen.queryByLabelText('POST http://t/c')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('GET http://t/d')).not.toBeInTheDocument();

  // And they are labelled as the two different things they are.
  expect(screen.getByText('switched off')).toBeInTheDocument();
  expect(screen.getAllByText('not sent')).toHaveLength(2);
});

// The server writes a reason per vector for the operator to read, so both kinds show theirs. Hiding
// the tool's reason would leave an unscanned vector with no explanation on the screen that decides it.
test('the reason is shown whichever kind of ineligible the vector is', async () => {
  await openVectorTab();
  expect(screen.getByText(/Deselected for domdig in its Config/)).toBeInTheDocument();
  expect(screen.getByText('domdig navigates a browser and cannot POST a body.')).toBeInTheDocument();
  expect(screen.getByText('domdig cannot reach a header insertion point.')).toBeInTheDocument();
});

test('the vectors are grouped by insertion point, each group counting both numbers', async () => {
  await openVectorTab();
  // query holds three vectors, two of them selected, and both of those will be sent.
  expect(screen.getByText('2 of 3 selected, 2 will be scanned')).toBeInTheDocument();
  // body and header hold one vector each, selected, and neither will be sent.
  expect(screen.getAllByText('1 of 1 selected, 0 will be scanned')).toHaveLength(2);
  // A group the tool cannot reach at all says so on the group, so the fact survives a Deselect all
  // rewriting every row's reason into the operator's own.
  expect(screen.getByText('domdig cannot reach a body insertion point')).toBeInTheDocument();
});

test('ticking a switched-off vector back on posts just that vector for just this tool', async () => {
  await openVectorTab();
  fireEvent.click(screen.getByLabelText('GET http://t/b?q=1'));

  await waitFor(() => {
    const posts = global.fetch.mock.calls.filter(([, init]) => init && init.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0][0]).toBe(`/api/xss/${TARGET.id}/domdig/selection`);
    expect(JSON.parse(posts[0][1].body)).toEqual({ vector_ids: ['v2'], enabled: true });
  });
});

test('deselect all switches off every vector this tool has, in one call', async () => {
  await openVectorTab();
  // The first None is the one above the groups; the group ones follow it.
  fireEvent.click(screen.getAllByRole('button', { name: 'None' })[0]);

  await waitFor(() => {
    const posts = global.fetch.mock.calls.filter(([, init]) => init && init.method === 'POST');
    expect(posts).toHaveLength(1);
    // all:true, because the server resolves it against the vectors this tool actually has rather
    // than against whatever the modal happens to be holding.
    expect(JSON.parse(posts[0][1].body)).toEqual({ all: true, enabled: false });
  });
});

// A group action must name its vectors. all:true would switch off the whole table.
test('a group action names only that group vectors', async () => {
  await openVectorTab();
  fireEvent.click(screen.getAllByRole('button', { name: 'None' })[1]);

  await waitFor(() => {
    const posts = global.fetch.mock.calls.filter(([, init]) => init && init.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0][1].body)).toEqual({
      vector_ids: ['v1', 'v2', 'v5'], enabled: false,
    });
  });
});

// Measured against the live API: Dalfox returns unreachable:null and 137 of its 215 selected vectors
// still will not be sent, because it CAN reach a body insertion point and is not configured to. The
// row is locked all the same, since no checkbox on this screen fixes it, but nothing may claim the
// tool cannot reach body or the operator will never find the setting that does fix it.
test('a vector held back by a setting is locked, and nothing calls that unreachable', async () => {
  global.fetch = jest.fn((url) => {
    if (String(url).endsWith('/selection')) {
      return jsonResponse({
        tool: 'dalfox', tool_name: 'Dalfox', category: 'xss',
        total: 2, selected: 2, eligible: 1, selected_but_unreachable: 1,
        reachable: ['query', 'body', 'header', 'cookie', 'path'],
        unreachable: null, // Not [] and not absent. The client must not index into it.
        vectors: [
          { vector_id: 'q1', method: 'GET', url: 'http://t/a?q=1', insertion_point: 'query', selected: true, eligible: true, deselected_by_operator: false },
          { vector_id: 'b1', method: 'PATCH', url: 'http://t/api/v1/accounts/1/details', insertion_point: 'body', parameters: 'suffix', selected: true, eligible: false, deselected_by_operator: false, reason: 'Dalfox can reach a body insertion point but does not by default. Turn on "scanBodyVectors" to include body vectors.' },
        ],
      });
    }
    if (String(url).endsWith('/settings')) return jsonResponse({ groups: [], options: {}, settings: {} });
    return jsonResponse({});
  });

  render(<VectorToolConfigModal show handleClose={() => {}} activeTarget={TARGET} tool={{ key: 'dalfox', name: 'Dalfox' }} category="xss" />);
  // A tool with no settings groups opens on the vector tab rather than on no tab at all.
  await waitFor(() => expect(screen.getByText('of 2 vectors will be scanned')).toBeInTheDocument());

  // Locked, because no checkbox here sends it.
  expect(screen.getAllByRole('checkbox')).toHaveLength(1);
  expect(screen.getByText('not sent')).toBeInTheDocument();
  // But the row points at the setting that would, and the group is not libelled as out of reach.
  expect(screen.getByText(/Turn on "scanBodyVectors"/)).toBeInTheDocument();
  expect(screen.queryByText(/cannot reach a body insertion point/)).not.toBeInTheDocument();
});

// An empty vector table has two causes and they need different sentences. Measured against
// 1e9b4bec, which HAS 215 consolidated vectors: nomore403 still returns total 0, because it works
// from the 4xx responses rather than the vector table, and graphql-cop and git-dumper do the same
// from endpoints and repositories. Telling that operator to go and consolidate endpoints sends them
// to redo work already finished, and the promise that every vector produced "will be selected for
// nomore403" is one the backend never keeps. scan_unit is what separates the two cases.
const renderEmpty = async (scanUnit) => {
  global.fetch = jest.fn((url) => {
    if (String(url).endsWith('/selection')) {
      return jsonResponse({
        tool: 'nomore403', tool_name: 'nomore403', category: 'access-bypass',
        total: 0, selected: 0, eligible: 0, selected_but_unreachable: 0,
        scan_will_run: '0 of 0 vectors',
        reachable: ['query', 'body', 'header', 'cookie', 'path'], unreachable: null,
        vectors: [],
      });
    }
    if (String(url).endsWith('/settings')) {
      return jsonResponse({
        groups: [], options: {}, settings: {},
        eligibility: { tool: 'nomore403', total: 0, eligible: 0, scan_count: 0, scan_unit: scanUnit },
      });
    }
    return jsonResponse({});
  });
  render(<VectorToolConfigModal show handleClose={() => {}} activeTarget={TARGET}
                                tool={{ key: 'nomore403', name: 'nomore403' }} category="access-bypass" />);
};

test('a tool that does not scan vectors is not told to go and consolidate endpoints', async () => {
  await renderEmpty('URL');
  await waitFor(() => expect(
    screen.getByText(/does not choose its targets from the attack vector table/),
  ).toBeInTheDocument());
  expect(screen.getByText(/It scans by\s+URL/)).toBeInTheDocument();
  // The instruction that would waste the operator's time must NOT be on screen.
  expect(screen.queryByText(/Consolidate endpoints and build the attack vector table/))
    .not.toBeInTheDocument();
});

// And the genuinely-empty case keeps the instruction, because there it is the right one.
test('a vector-scanning tool with nothing consolidated yet still says how to fix it', async () => {
  await renderEmpty('vector');
  await waitFor(() => expect(
    screen.getByText(/Consolidate endpoints and build the attack vector table/),
  ).toBeInTheDocument());
});

// The eligibility panel on the settings tabs reports the same pair of numbers. Two panels a few
// pixels apart is how one of them gets to be quietly wrong, so only one is on screen at a time.
test('the coverage panel is not drawn twice while the vector tab is open', async () => {
  await openVectorTab();
  expect(screen.queryByText(/attack vectors can be tested by/)).not.toBeInTheDocument();
  // And the settings form is not underneath it either.
  expect(screen.queryByText('Modes')).not.toBeInTheDocument();
});

// The card must never advertise the full table for a tool that cannot scan it, or the operator reads
// a clean result for vectors that were never sent.
test('the card shows eligible of total rather than total', () => {
  render(<AttackToolCard tool={TOOL} status={STATUS} />);
  expect(screen.getByText('27/71')).toBeInTheDocument();
  expect(screen.getByText('Eligible Attack Vectors')).toBeInTheDocument();
});

test('the card shows scan position while a scan is running', () => {
  const running = {
    ...STATUS,
    scan: { ...STATUS.scan, status: 'running', completed_vectors: 14, finding_count: 3 },
  };
  render(<AttackToolCard tool={TOOL} status={running} />);
  expect(screen.getByText('14/27')).toBeInTheDocument();
  expect(screen.getByText('Vectors Scanned')).toBeInTheDocument();
  // Scan is disabled while one is already running, so a second is not started by accident.
  expect(screen.getByRole('button', { name: 'Scanning' })).toBeDisabled();
});

// A cache scan tests a URL, and vectors sharing one are scanned once between them. The card must
// say URLs, or it promises 71 scans and performs 34.
test('the card counts URLs, not vectors, for a tool that deduplicates', () => {
  const cache = {
    tool: 'wcvs',
    eligibility: { eligible: 71, total: 71, scan_count: 34, scan_unit: 'URL', reachable: ['query'] },
    scan: { status: 'completed', finding_count: 2, eligible_vectors: 34, completed_vectors: 34 },
  };
  render(<AttackToolCard tool={TOOL} status={cache} />);
  expect(screen.getByText('34')).toBeInTheDocument();
  expect(screen.getByText('URLs to Scan')).toBeInTheDocument();
  // The dedupe sublabel was removed from the card: it made the card's height depend on the data,
  // which shifted the buttons relative to the card beside it. The number it explained is still on
  // screen, and the explanation lives in the results modal.
  expect(screen.queryByText(/from 71 attack vectors/)).not.toBeInTheDocument();
});

test('the card renders without a status, for tools that are not wired up', () => {
  render(<AttackToolCard tool={{ key: 'x', name: 'X', url: 'https://e.invalid', description: 'd' }} />);
  expect(screen.getByRole('button', { name: 'Scan' })).toBeInTheDocument();
});

// The card must render its numbers from the EXACT payload the API returns before any scan has run,
// which has no `scan` key at all. The mocked status used above always carried one, so a card that
// only rendered when a scan existed would have passed every test and shown nothing in the app.
test('the card shows numbers before any scan has ever run', () => {
  const beforeAnyScan = {
    eligibility: {
      tool: 'nuclei-dast', tool_name: 'Nuclei DAST', category: 'redirect',
      total: 71, eligible: 39,
      by_point: { body: 12, query: 27 },
      skipped_by_point: { cookie: 3, header: 18, path: 11 },
      reachable: ['query', 'body'], unreachable: ['cookie', 'header', 'path'],
      scan_count: 39, scan_unit: 'vector',
    },
    tool: 'nuclei-dast', tool_name: 'Nuclei DAST',
    // No `scan` key: nothing has run yet.
  };
  render(<AttackToolCard tool={TOOL} status={beforeAnyScan} />);
  expect(screen.getByText('39/71')).toBeInTheDocument();
  expect(screen.getByText('Eligible Attack Vectors')).toBeInTheDocument();
  // The insertion-point sublabel was removed for the same reason. Pinned as ABSENT so it is not
  // reintroduced by accident.
  expect(screen.queryByText('query, body only')).not.toBeInTheDocument();
});

// The bug this guards against shipped: the section key in attackTools.js was 'redirect-ssrf' and the
// client filtered on 'redirect', so those three cards were dropped from the wiring map. They then
// rendered with no numbers and their buttons fell through to the "not wired up yet" toast, while
// every other section worked. Nothing failed; the section just quietly did nothing.
test('every wired category names a section that actually exists', () => {
  const sectionKeys = new Set(ATTACK_TOOL_SECTIONS.map((s) => s.key));
  WIRED_CATEGORIES.forEach((category) => {
    expect(sectionKeys.has(category)).toBe(true);
  });
});

test('every wired section has at least one tool to draw', () => {
  WIRED_CATEGORIES.forEach((category) => {
    const section = ATTACK_TOOL_SECTIONS.find((s) => s.key === category);
    expect(section.tools.length).toBeGreaterThan(0);
  });
});

// The GraphQL section keeps its endpoint list in each tool's own config, by the operator's choice.
// That makes two things easy to get wrong and invisible when you do: an endpoint marked in one tool
// is silently skipped by the other two, and the operator has to know the endpoint's path by hand.
// This is the helper that addresses both, mounted for real because a modal that compiles and then
// throws on mount is how this file came to exist.
test('the graphql endpoint helper lets you PICK an endpoint rather than type it', async () => {
  global.fetch = jest.fn((url) => {
    if (String(url).includes('candidate-endpoints')) {
      return jsonResponse({
        count: 2,
        truncated: false,
        candidates: [
          { url: 'https://x.test/graphql', sources: ['manual-crawl'], likely: true, in_scope: true },
          { url: 'https://x.test/login', sources: ['manual-crawl'], likely: false, in_scope: true },
        ],
      });
    }
    if (String(url).includes('known-endpoints')) {
      return jsonResponse({ endpoints: [{ url: 'https://x.test/api/gql', tools: ['graphw00f'] }] });
    }
    return jsonResponse({ found: [], output: '' });
  });

  const onAppend = jest.fn();
  render(
    <GraphQLEndpointHelper
      activeTarget={{ id: TARGET.id, scope_target: 'https://x.test' }}
      current={''}
      onAppend={onAppend}
      onSet={() => {}}
      category="graphql"
    />,
  );

  // The endpoints this target already has are listed, so nothing has to be retyped.
  await waitFor(() => expect(screen.getByText('https://x.test/graphql')).toBeInTheDocument());
  expect(screen.getByText('https://x.test/login')).toBeInTheDocument();
  // The one that looks like GraphQL is flagged, as an ordering hint rather than a filter.
  expect(screen.getByText('likely')).toBeInTheDocument();

  // Ticking one marks it for this tool.
  fireEvent.click(screen.getAllByRole('checkbox')[0]);
  expect(onAppend).toHaveBeenCalledWith(['https://x.test/graphql']);

  // And an endpoint another tool holds is surfaced, because this tool would otherwise skip it.
  expect(screen.getByText(/api\/gql/)).toBeInTheDocument();
});

// Accepting detected endpoints must not duplicate what is already listed.
test('appending endpoints keeps the list unique', () => {
  const current = 'https://x.test/graphql';
  expect(appendEndpoints(current, ['https://x.test/graphql'])).toBe(current);
  expect(appendEndpoints(current, ['https://x.test/api/gql']))
    .toBe('https://x.test/graphql\nhttps://x.test/api/gql');
  expect(appendEndpoints('', ['https://x.test/a'])).toBe('https://x.test/a');
});

// The access control bypass section used to have its own derived target list and a Manage Targets
// screen. The operator replaced both with a per-tool Targets tab, like every other section that
// scans URLs, so the picker is what covers it now. This asserts the piece unique to that section:
// the endpoints that ALREADY answered 401 or 403 are offered, because those are the ones where
// something is actually being denied.
test('the picker offers endpoints that already denied us, for the bypass section', async () => {
  global.fetch = jest.fn((url) => {
    if (String(url).includes('denied-endpoints')) {
      return jsonResponse({
        count: 2,
        by_status: [{ status_code: 403, count: 2 }],
        denied: [
          { url: 'https://x.test/admin', status_code: 403, sources: ['manual-crawl'], in_scope: true, primary: true },
          { url: 'https://www.transunion.com/x', status_code: 403, sources: ['manual-crawl'], in_scope: false, primary: true },
        ],
      });
    }
    if (String(url).includes('candidate-endpoints')) {
      return jsonResponse({ count: 0, truncated: false, candidates: [] });
    }
    return jsonResponse({ endpoints: [] });
  });

  render(
    <GraphQLEndpointHelper
      activeTarget={{ id: TARGET.id, scope_target: 'https://x.test' }}
      current={''}
      onAppend={() => {}}
      onSet={() => {}}
      category="access-bypass"
    />,
  );

  // The in-scope denial is offered.
  await waitFor(() => expect(screen.getByText(/403 https:\/\/x\.test\/admin/)).toBeInTheDocument());
  // A third party's 403 is not this operator's business, so it is not offered for one-click adding.
  expect(screen.queryByText(/transunion/)).not.toBeInTheDocument();
});
