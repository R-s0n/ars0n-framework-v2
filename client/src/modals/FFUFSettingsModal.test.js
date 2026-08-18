import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import FFUFSettingsModal from './FFUFSettingsModal';

// The form is generated from the server's vocabulary, so what is worth testing is that it renders
// whatever the server sends rather than a list of its own, that each category is a TAB rather than a
// section to scroll past, and that saving does not destroy the settings it chose not to show.

const payload = {
  settings: { threads: 5, filterStatus: '404', noiseGuard: false, extensions: '.map' },
  options: {
    threads: 'concurrent requests doc',
    filterStatus: 'status codes to discard doc',
    matcherMode: 'how matchers combine doc',
    noiseGuard: 'framework side doc',
    recursion: 'NOT SUPPORTED HERE, and setting it is refused rather than ignored.',
    extensions: 'NOT SUPPORTED HERE either.',
  },
  meta: {
    threads: { kind: 'int', group: 'Pacing', label: 'Threads', flag: '-t' },
    filterStatus: { kind: 'string', group: 'Filters', label: 'Status', flag: '-fc' },
    matcherMode: { kind: 'enum', group: 'Matchers', label: 'Combine with', choices: ['or', 'and'] },
    noiseGuard: { kind: 'bool', group: 'Framework', label: 'Noise guard' },
    recursion: { kind: 'unsupported', group: 'Refused', label: 'Recursion' },
    extensions: { kind: 'unsupported', group: 'Refused', label: 'Extensions' },
  },
  groups: ['Pacing', 'Matchers', 'Filters', 'Framework', 'Refused'],
  owned_flags: { '-w': 'each position wordlist' },
  step_count: 3,
  step_overrides: { threads: ['CDN leaked build artefacts'] },
  note: 'These apply to every ffuf step of this flow that does not set the same key itself.',
};

let posted;

beforeAll(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });
beforeEach(() => {
  posted = null;
  global.fetch = (url, opts) => {
    if (opts && opts.method === 'POST') {
      posted = JSON.parse(opts.body);
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ settings: {}, saved: true }) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(payload) });
  };
});
afterEach(() => { document.body.innerHTML = ''; });

async function mount(props = {}) {
  document.body.innerHTML = '';
  const c = document.createElement('div');
  document.body.appendChild(c);
  const root = createRoot(c);
  await act(async () => {
    root.render(<FFUFSettingsModal show handleClose={() => {}}
      activeTarget={{ id: '11111111-1111-4111-8111-111111111111' }} {...props} />);
  });
  return document.body;
}

const tabNames = (body) => [...body.querySelectorAll('.nav-link')].map((a) => a.textContent);

async function openTab(body, name) {
  const link = [...body.querySelectorAll('.nav-link')].find((a) => a.textContent.startsWith(name));
  if (!link) throw new Error(`no tab named ${name}, have: ${tabNames(body).join(' | ')}`);
  await act(async () => { link.click(); });
  return body.textContent;
}

async function clickSave(body) {
  const btn = [...body.querySelectorAll('button')].find((b) => b.textContent.includes('Save Settings'));
  await act(async () => { btn.click(); });
}

test('each ffuf category is a tab, and only the open one is rendered', async () => {
  const body = await mount();
  ['Pacing', 'Matchers', 'Filters'].forEach((g) =>
    expect(tabNames(body).some((t) => t.startsWith(g))).toBe(true));

  // Pacing opens first, so the filters are NOT on screen. That is the point of tabbing them.
  expect(body.textContent).toContain('Threads');
  expect(body.textContent).not.toContain('status codes to discard doc');
  expect(await openTab(body, 'Filters')).toContain('status codes to discard doc');
});

test('the framework, refused and framework-owned tabs are gone', async () => {
  const body = await mount();
  const tabs = tabNames(body);
  ['Framework', 'Refused', 'Framework-owned'].forEach((name) =>
    expect(tabs.some((t) => t.startsWith(name))).toBe(false));
  // And their contents are nowhere on the screen either.
  expect(body.textContent).not.toContain('Noise guard');
  expect(body.textContent).not.toContain('NOT SUPPORTED HERE');
  expect(body.textContent).not.toContain('each position wordlist');
});

// The regression this modal would otherwise ship: it saves with replace, so anything it declines to
// draw would be deleted the first time somebody opened it and pressed Save.
test('settings it does not show survive a save untouched', async () => {
  const body = await mount();
  await clickSave(body);
  expect(posted.replace).toBe(true);
  expect(posted.settings.noiseGuard).toBe(false);
  expect(posted.settings.extensions).toBe('.map');
  // And what it does show is still sent.
  expect(posted.settings.threads).toBe(5);
  expect(posted.settings.filterStatus).toBe('404');
});

test('each tab counts the settings it holds a value for', async () => {
  const body = await mount();
  const pacing = [...body.querySelectorAll('.nav-link')].find((a) => a.textContent.startsWith('Pacing'));
  expect(pacing.textContent).toMatch(/Pacing\s*1/);
});

test('it shows the server own documentation rather than a paraphrase', async () => {
  const body = await mount();
  expect(body.textContent).toContain('concurrent requests doc');
  expect(await openTab(body, 'Filters')).toContain('status codes to discard doc');
});

test('stored values populate the controls', async () => {
  const body = await mount();
  expect([...body.querySelectorAll('input')].some((i) => i.value === '5')).toBe(true);
  await openTab(body, 'Filters');
  expect([...body.querySelectorAll('input')].some((i) => i.value === '404')).toBe(true);
});

test('a step overriding a default is named', async () => {
  const text = (await mount()).textContent;
  expect(text).toContain('CDN leaked build artefacts');
  expect(text).toMatch(/Overridden by step/);
});

test('it survives no active target and a failed load', async () => {
  await expect(mount({ activeTarget: null })).resolves.toBeTruthy();
  global.fetch = () => Promise.reject(new Error('down'));
  const text = (await mount()).textContent;
  expect(text).toContain('Could not load the ffuf settings');
});
