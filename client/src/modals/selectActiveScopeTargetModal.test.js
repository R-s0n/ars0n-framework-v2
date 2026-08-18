import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import SelectActiveScopeTargetModal from './selectActiveScopeTargetModal';

// A build passing says the file parsed, not that the component runs. The previous modal shipped a
// dependency array naming a `const` declared further down, which is a temporal-dead-zone
// ReferenceError thrown on EVERY render: it compiled clean and white-screened the app. So this
// mounts the thing for real, effects and all, and then asserts what the modal is supposed to say.

const targets = [
  { id: 'a1', type: 'Company', scope_target: 'OnePay' },
  { id: 'b1', type: 'Wildcard', scope_target: '*.countr.one' },
  { id: 'b2', type: 'Wildcard', scope_target: '*.safecorp.com' },
  { id: 'c1', type: 'URL', scope_target: 'https://global.cdn.mercury-dev.countr.one' },
];

// The shape the server really returns, trimmed to what the table reads.
const payload = {
  metrics: {
    a1: { root_domains: 6, cloud_assets: 20, live_servers: 867 },
    b1: { subdomains: 160, live_servers: 146, findings: 2249, impactful: 0 },
    c1: { endpoints: 1137, parameters: 6, fuzz_findings: 66, session: 4 },
  },
  definitions: {
    Company: [
      { key: 'root_domains', label: 'Root Domains', hint: 'h' },
      { key: 'network_ranges', label: 'Ranges', hint: 'h' },
      { key: 'cloud_assets', label: 'Cloud', hint: 'h' },
      { key: 'live_servers', label: 'Live Servers', hint: 'h', emphasis: true },
    ],
    Wildcard: [
      { key: 'subdomains', label: 'Subdomains', hint: 'h' },
      { key: 'live_servers', label: 'Live Servers', hint: 'h' },
      { key: 'findings', label: 'Findings', hint: 'h' },
      { key: 'impactful', label: 'Impactful', hint: 'h', emphasis: true },
    ],
    URL: [
      { key: 'endpoints', label: 'Endpoints', hint: 'h' },
      { key: 'parameters', label: 'Parameters', hint: 'h' },
      { key: 'fuzz_findings', label: 'Fuzz Findings', hint: 'h', emphasis: true },
      { key: 'session', label: 'Session', hint: 'h' },
    ],
  },
};

const baseProps = {
  showActiveModal: true,
  handleActiveModalClose: () => {},
  scopeTargets: targets,
  activeTarget: targets[3],
  handleActiveSelect: () => {},
  handleDelete: () => {},
};

beforeAll(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
});

beforeEach(() => {
  global.fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve(payload) });
});

async function mount(props) {
  // Cleared per mount, not per test: the modal renders through a portal onto document.body, so a
  // second mount inside one test would otherwise be read together with the first one's markup.
  document.body.innerHTML = '';
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(<SelectActiveScopeTargetModal {...{ ...baseProps, ...props }} />);
  });
  // The modal renders through a portal, so its markup lands on document.body rather than in the
  // container the root was given.
  return document.body.textContent;
}

afterEach(() => { document.body.innerHTML = ''; });

test('it mounts, and opens on the active target\'s type', async () => {
  const text = await mount({});
  expect(text).toContain('Manage Scope Targets');
  // Active target is a URL, so the URL columns are the ones on screen.
  expect(text).toContain('Endpoints');
  expect(text).toContain('Fuzz Findings');
  expect(text).toContain('1,137');
});

test('there is no All tab, and the three types are', async () => {
  const text = await mount({});
  expect(text).not.toMatch(/\bAll\b/);
  ['Company', 'Wildcard', 'URL'].forEach((t) => expect(text).toContain(t));
});

test('columns are unique per type rather than shared', async () => {
  const url = await mount({ activeTarget: targets[3] });
  expect(url).toContain('Parameters');
  expect(url).not.toContain('Subdomains');

  const wildcard = await mount({ activeTarget: targets[1] });
  expect(wildcard).toContain('Subdomains');
  expect(wildcard).toContain('Impactful');
  expect(wildcard).not.toContain('Endpoints');

  const company = await mount({ activeTarget: targets[0] });
  expect(company).toContain('Root Domains');
  expect(company).toContain('Cloud');
  expect(company).not.toContain('Subdomains');
  expect(company).toContain('867');
});

test('a metric never produced shows a dash, not a zero', async () => {
  // OnePay has no network_ranges key at all, and its Ranges column must not claim zero.
  const text = await mount({ activeTarget: targets[0] });
  expect(text).toContain('—');
});

test('it survives an empty list, no active target, and an unknown type', async () => {
  await expect(mount({ scopeTargets: [], activeTarget: null })).resolves.toContain('No Company targets yet');
  const odd = [{ id: 'z1', type: 'Mystery', scope_target: 'unknown-type' }];
  await expect(mount({ scopeTargets: odd, activeTarget: odd[0] })).resolves.toContain('Manage Scope Targets');
});

test('it still renders when the metrics request fails', async () => {
  global.fetch = () => Promise.reject(new Error('down'));
  const text = await mount({});
  expect(text).toContain('Manage Scope Targets');
  expect(text).toContain('mercury-dev.countr.one');
});
