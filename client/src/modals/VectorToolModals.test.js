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

const STATUS = {
  tool: 'domdig',
  eligibility: { tool: 'domdig', eligible: 27, total: 71, reachable: ['query'], unreachable: ['body', 'cookie', 'header', 'path'], limitation: 'domdig fuzzes the query string.' },
  scan: { scan_id: 's1', status: 'completed', total_vectors: 71, eligible_vectors: 27, completed_vectors: 27, finding_count: 1, current_host: '' },
};

beforeEach(() => {
  global.fetch = jest.fn((url) => {
    if (String(url).endsWith('/results')) return jsonResponse(RESULTS);
    if (String(url).endsWith('/status')) return jsonResponse(STATUS);
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
