import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import ManageEndpointsModal from './ManageEndpointsModal';

// The list is the whole point of this modal, so what is worth testing is that the tabs open on the
// verdict work starts from, that the filters are built from the rows actually loaded, and that the
// default order puts the endpoints which take input at the top.

const ep = (over) => ({
  id: over.id, url: `https://h.test${over.path || '/'}`, domain: 'h.test', path: '/', method: 'GET',
  is_direct: true, status_codes: [200], parameters: [], request_count: 1, content_class: 'page',
  validation_status: 'unverified', override_status: null, deleted_at: null, sources: [],
  ...over,
});

const rows = [
  ep({ id: '1', path: '/a', validation_status: 'valid', parameters: [{ id: 'p1' }, { id: 'p2' }] }),
  ep({ id: '2', path: '/b', validation_status: 'valid', request_count: 9 }),
  ep({ id: '3', path: '/c', validation_status: 'valid', status_codes: [404], content_class: 'api' }),
  ep({ id: '4', path: '/d', validation_status: 'ruled_out' }),
  ep({ id: '5', path: '/e', validation_status: 'unverified', is_direct: false, domain: 'other.test' }),
  ep({ id: '6', path: '/f', validation_status: 'skipped', method: 'POST' }),
  // A query string counts as parameters even when consolidation did not break it into rows.
  ep({ id: '7', path: '/g', validation_status: 'valid', url: 'https://h.test/g?id=1&x=2' }),
];

beforeAll(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  // jsdom implements no layout, so every element reports clientHeight 0, and VirtualizedList renders
  // nothing at all until it has measured a height. Without this the list is empty and a test can
  // assert happily about tabs and filters while never once seeing an endpoint row.
  Object.defineProperty(window.HTMLElement.prototype, 'clientHeight', {
    configurable: true,
    get() { return 800; },
  });
});

let seedCalls;

const SEED = {
  raw: 'GET /a?id=1 HTTP/1.1' + String.fromCharCode(10) + 'Host: h.test' + String.fromCharCode(10) +
    'accept: */*' + String.fromCharCode(10) + String.fromCharCode(10),
  method: 'GET', host: 'h.test', known_params: ['id'], notes: [],
};

beforeEach(() => {
  seedCalls = [];
  global.fetch = (url) => {
    if (String(url).includes('/consolidated-endpoints/')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(rows) });
    }
    if (String(url).includes('/fuzz/seed/')) {
      seedCalls.push(String(url));
      return Promise.resolve({ ok: true, json: () => Promise.resolve(SEED) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve([]) });
  };
});
afterEach(() => { document.body.innerHTML = ''; });

async function mount() {
  document.body.innerHTML = '';
  const c = document.createElement('div');
  document.body.appendChild(c);
  const root = createRoot(c);
  await act(async () => {
    root.render(<ManageEndpointsModal show onHide={() => {}} scopeTargetId="t1" />);
  });
  return document.body;
}

const tabs = (body) => [...body.querySelectorAll('.nav-link')].map((a) => a.textContent.trim());
const shownPaths = (body) => [...body.querySelectorAll('.nav-link')].length
  ? [...body.querySelectorAll('code, .font-monospace')].map((e) => e.textContent)
  : [];

async function selectValue(body, currentValue, next) {
  const select = [...body.querySelectorAll('select')].find(
    (s) => [...s.options].some((o) => o.value === next) && s.value === currentValue);
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, 'value').set;
    setter.call(select, next);
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
}

test('the tabs are verdict first, in the order work happens', async () => {
  const body = await mount();
  const labels = tabs(body).map((t) => t.replace(/\s*\(\d+\)$/, ''));
  expect(labels).toEqual(['Valid', 'Ruled out', 'Unverified', 'Direct', 'Adjacent', 'All']);
});

test('it opens on Valid rather than All', async () => {
  const body = await mount();
  const active = [...body.querySelectorAll('.nav-link')].find((a) => a.classList.contains('active'));
  expect(active.textContent).toMatch(/^Valid/);
  // Four rows carry a valid verdict; the ruled out and unverified ones are not on screen.
  expect(active.textContent).toContain('(4)');
});

test('the counts and options come from the rows, not from a hardcoded list', async () => {
  const body = await mount();
  const options = [...body.querySelectorAll('option')].map((o) => o.textContent);
  // Statuses present in the data, and nothing else.
  expect(options.some((o) => o.startsWith('200'))).toBe(true);
  expect(options.some((o) => o.startsWith('404'))).toBe(true);
  expect(options.some((o) => o.startsWith('500'))).toBe(false);
  // Methods and hosts likewise.
  expect(options.some((o) => o.startsWith('POST'))).toBe(true);
  expect(options.some((o) => o.startsWith('other.test'))).toBe(true);
  expect(options.some((o) => o.startsWith('DELETE'))).toBe(false);
});

test('parameters can be filtered for, and a query string counts as parameters', async () => {
  const body = await mount();
  // Two rows in the whole set take input: one with parameter rows, one with only a query string.
  expect([...body.querySelectorAll('option')].some((o) => o.textContent === 'With parameters (2)'))
    .toBe(true);
  await selectValue(body, '', 'with');
  expect(body.textContent).toContain('2 shown');
});

test('the header block of counts and validation prose is gone', async () => {
  const body = await mount();
  const text = body.textContent;
  expect(text).not.toMatch(/Total:\s*\d/);
  expect(text).not.toMatch(/Direct:\s*\d/);
  expect(text).not.toMatch(/Adjacent:\s*\d/);
  expect(text).not.toContain('Investigated');
  expect(text).not.toContain('directory controls');
  expect(text).not.toContain('Requests were confined');
});

// Expanding a row shows the request itself, rendered by the server rather than stitched together
// here: the same bytes a fuzz step would be seeded with, so the two cannot describe different
// requests.
async function expandFirstRow(body) {
  // Selected by its content, not by [role="button"] alone: react-bootstrap gives every Nav.Link that
  // role too, so the first match is the Valid tab and clicking it expands nothing.
  const header = [...body.querySelectorAll('[role="button"]')]
    .find((el) => el.textContent.includes('/a') && el.textContent.includes('reqs'));
  if (!header) throw new Error('no endpoint row to expand');
  await act(async () => { header.click(); });
  return body.textContent;
}

test('the raw request is not fetched until a row is expanded', async () => {
  const body = await mount();
  expect(seedCalls).toHaveLength(0);
  await expandFirstRow(body);
  expect(seedCalls).toHaveLength(1);
});

test('an expanded row shows the raw request above the metadata', async () => {
  const body = await mount();
  const text = await expandFirstRow(body);
  expect(text).toContain('Raw request');
  expect(text).toContain('GET /a?id=1 HTTP/1.1');
  expect(text).toContain('Host: h.test');
  expect(text).toContain('known parameters: id');
  // Above the URL block, which is what "at the top" means.
  expect(text.indexOf('Raw request')).toBeLessThan(text.indexOf('Full URL'));
});

test('an endpoint the server cannot render says so instead of showing nothing', async () => {
  const realFetch = global.fetch;
  global.fetch = (url) => (String(url).includes('/fuzz/seed/')
    ? Promise.resolve({ ok: false, json: () => Promise.resolve({}) })
    : realFetch(url));
  const body = await mount();
  const text = await expandFirstRow(body);
  expect(text).toContain('could not be rendered');
});
