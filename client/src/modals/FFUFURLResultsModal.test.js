import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import FFUFURLResultsModal from './FFUFURLResultsModal';

// What matters in this table is the order rows arrive in, that every column can be sorted and the
// obvious things filtered, and that the payload column shows the word that was sent rather than the
// framework's own keyword bookkeeping.

const f = (over) => ({
  id: over.id, tool: 'ffuf', step_ordinal: 3, step_name: 'a step', host: 'h.test',
  url: `https://h.test/${over.id}`, method: 'GET', position_token: '{{p01}}',
  payload: 'FUZZP01=word', http_status: 404, response_size: 100, times_seen: 1,
  triage: 'new', first_seen: '2026-08-17T10:00:00Z', has_evidence: false, ...over,
});

const rows = [
  f({ id: 'a', http_status: 404, response_size: 10, payload: 'FUZZP01=zeta' }),
  f({ id: 'b', http_status: 200, response_size: 500, payload: 'FUZZP01=admin', method: 'POST' }),
  f({ id: 'c', http_status: 403, response_size: 250, payload: 'FUZZP01=beta', step_ordinal: 7 }),
  f({ id: 'd', http_status: 200, response_size: 900, payload: 'FUZZ=sniperword' }),
  f({ id: 'e', http_status: 301, response_size: 30, payload: 'FUZZP01=a&FUZZP02=b' }),
];

beforeAll(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });
beforeEach(() => {
  global.fetch = () => Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ findings: rows, total: rows.length, truncated: false }),
  });
});
afterEach(() => { document.body.innerHTML = ''; });

async function mount() {
  document.body.innerHTML = '';
  const c = document.createElement('div');
  document.body.appendChild(c);
  const root = createRoot(c);
  await act(async () => {
    root.render(<FFUFURLResultsModal show handleClose={() => {}}
      activeTarget={{ id: '11111111-1111-4111-8111-111111111111' }} />);
  });
  return document.body;
}

const headers = (body) => [...body.querySelectorAll('thead th')].map(
  (th) => th.textContent.replace(/[▲▼↕]/g, '').trim());
const bodyRows = (body) => [...body.querySelectorAll('tbody tr')]
  .filter((tr) => tr.querySelectorAll('td').length > 1);
const columnText = (body, index) => bodyRows(body).map(
  (tr) => tr.querySelectorAll('td')[index].textContent.trim());

async function clickHeader(body, label) {
  const th = [...body.querySelectorAll('thead th')].find((h) => h.textContent.includes(label));
  await act(async () => { th.click(); });
}

test('the columns are the ones worth seeing, with step last', async () => {
  const body = await mount();
  expect(headers(body)).toEqual(
    ['Status', 'Method', 'URL', 'Payload', 'Size', 'First seen', 'Step']);
});

test('position and seen columns are gone', async () => {
  const body = await mount();
  expect(headers(body)).not.toContain('Position');
  expect(headers(body)).not.toContain('Seen');
  // The position token is not rendered in the row either.
  expect(body.textContent).not.toContain('{{p01}}');
});

test('the 200s are at the top by default', async () => {
  const body = await mount();
  const statuses = columnText(body, 0).map((t) => t.replace(/\D/g, ''));
  expect(statuses.slice(0, 2)).toEqual(['200', '200']);
  expect(statuses).toEqual(['200', '200', '301', '403', '404']);
});

test('the payload column shows the word, not the keyword', async () => {
  const body = await mount();
  const payloads = columnText(body, 3);
  expect(payloads).toContain('admin');
  expect(payloads).toContain('sniperword');
  expect(body.textContent).not.toContain('FUZZP01=');
  expect(body.textContent).not.toContain('FUZZ=');
  // A step with two positions shows both words rather than one concatenated string.
  expect(payloads.some((p) => p.includes('a') && p.includes('b'))).toBe(true);
});

test('any column can be sorted, both ways', async () => {
  const body = await mount();
  await clickHeader(body, 'Size');
  expect(columnText(body, 4)).toEqual(['900', '500', '250', '30', '10']);
  await clickHeader(body, 'Size');
  expect(columnText(body, 4)).toEqual(['10', '30', '250', '500', '900']);

  await clickHeader(body, 'Step');
  expect(columnText(body, 6)[0]).toBe('7');
});

test('status, method and size can be filtered', async () => {
  const body = await mount();
  const selects = [...body.querySelectorAll('select')];
  const setSelect = async (select, value) => {
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(
        window.HTMLSelectElement.prototype, 'value').set;
      setter.call(select, value);
      select.dispatchEvent(new Event('change', { bubbles: true }));
    });
  };

  await setSelect(selects[0], '200');
  expect(bodyRows(body)).toHaveLength(2);

  await setSelect(selects[1], 'POST');
  expect(bodyRows(body)).toHaveLength(1);
  expect(columnText(body, 3)).toEqual(['admin']);
});

test('size is filtered as a range', async () => {
  const body = await mount();
  const numbers = [...body.querySelectorAll('input[type=number]')];
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value').set;
    setter.call(numbers[0], '200');
    numbers[0].dispatchEvent(new Event('input', { bubbles: true }));
  });
  // Only the three rows of 200 bytes or more survive, still in the default status order (the two
  // 200s, then the 403) rather than being re-sorted by the thing that was filtered on.
  expect(columnText(body, 4)).toEqual(['500', '900', '250']);
  expect(columnText(body, 0).map((t) => t.replace(/\D/g, ''))).toEqual(['200', '200', '403']);
});

// The baseline: the same request with a value that cannot exist. A finding is only meaningful if the
// canary gets a DIFFERENT answer, so the comparison is the first thing the expanded row shows.
const detailWith = (baseline) => ({
  id: 'b', url: 'https://h.test/b', method: 'GET', payload: 'FUZZP01=admin',
  response: { status: 200, size: 500, words: 10, lines: 3 },
  evidence: { request: 'GET /admin HTTP/1.1', response: 'HTTP/1.1 200 OK' },
  positions: [], request_parts: null, request_note: 'x',
  ...baseline,
});

async function expandRow(body) {
  const row = [...body.querySelectorAll('tbody tr')].find((tr) => tr.querySelectorAll('td').length > 1);
  await act(async () => { row.click(); });
  return body.textContent;
}

test('a finding whose canary answers differently is called out', async () => {
  global.fetch = (url) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(String(url).includes('/fuzz/findings/')
      ? detailWith({ baseline: { canary: 'rs0n', http_status: 404, response_size: 12,
          verdict: 'differs', request: 'GET /rs0n HTTP/1.1', response: 'HTTP/1.1 404',
          note: 'The canary (rs0n) answers 404 where this payload answers 200.' } })
      : { findings: rows, total: rows.length, truncated: false }),
  });
  const body = await mount();
  const text = await expandRow(body);
  expect(text).toContain('FFUF STATUS');
  expect(text).toContain('BASELINE STATUS');
  expect(text).toContain('FFUF SIZE');
  expect(text).toContain('BASELINE SIZE');
  expect(text).toContain('differs from baseline');
});

test('a finding that matches its canary is shown as the wall, not a discovery', async () => {
  global.fetch = (url) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(String(url).includes('/fuzz/findings/')
      ? detailWith({ baseline: { canary: 'rs0n', http_status: 200, response_size: 500,
          verdict: 'same', request: 'GET /rs0n HTTP/1.1', response: 'HTTP/1.1 200 OK',
          note: 'A value that cannot exist gets the SAME answer.' } })
      : { findings: rows, total: rows.length, truncated: false }),
  });
  const body = await mount();
  const text = await expandRow(body);
  expect(text).toContain('same as baseline');
  expect(text).toContain('gets the SAME answer');
});

test('the exchange tabs switch between the ffuf request and the baseline', async () => {
  global.fetch = (url) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(String(url).includes('/fuzz/findings/')
      ? detailWith({ baseline: { canary: 'rs0n', http_status: 404, response_size: 12,
          verdict: 'differs', request: 'GET /rs0n HTTP/1.1', response: 'HTTP/1.1 404 NOPE',
          note: 'differs' } })
      : { findings: rows, total: rows.length, truncated: false }),
  });
  const body = await mount();
  let text = await expandRow(body);
  // FFUF is open first.
  expect(text).toContain('GET /admin HTTP/1.1');
  expect(text).not.toContain('NOPE');

  const tab = [...body.querySelectorAll('button')].find((b) => b.textContent.includes('Baseline'));
  await act(async () => { tab.click(); });
  text = body.textContent;
  expect(text).toContain('GET /rs0n HTTP/1.1');
  expect(text).toContain('NOPE');
  expect(text).toContain('The request the baseline sent');
});

test('a finding with no baseline says so rather than showing nothing', async () => {
  global.fetch = (url) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(String(url).includes('/fuzz/findings/')
      ? detailWith({ baseline_note: 'No baseline has been taken for this finding yet.' })
      : { findings: rows, total: rows.length, truncated: false }),
  });
  const body = await mount();
  const text = await expandRow(body);
  expect(text).toContain('No baseline has been taken');
});

// The bug this suite missed the first time: the strip read response.status while the server sends
// response.http_status, so FFUF status rendered as a dash on every row while the number sat in the
// payload. The fixtures below use the SERVER'S field names for exactly that reason.
test('the strip shows the real ffuf status and size, not dashes', async () => {
  global.fetch = (url) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(String(url).includes('/fuzz/findings/')
      ? {
        id: 'b', url: 'https://h.test/b', method: 'GET', payload: 'FUZZP01=admin',
        response: { http_status: 404, size: 182, words: 6, lines: 11 },
        evidence: { request: 'GET /admin HTTP/1.1', response: 'HTTP/1.1 404' },
        positions: [], request_note: 'x',
        baseline: { canary: 'rs0n', http_status: 404, response_size: 154, verdict: 'same',
          request: 'GET /rs0n HTTP/1.1', response: 'HTTP/1.1 404', note: 'same' },
      }
      : { findings: rows, total: rows.length, truncated: false }),
  });
  const body = await mount();
  const row = [...body.querySelectorAll('tbody tr')].find((tr) => tr.querySelectorAll('td').length > 1);
  await act(async () => { row.click(); });
  const text = body.textContent;
  expect(text).toContain('182');
  expect(text).toContain('154');
  // Four labelled figures, none of them unknown.
  ['FFUF STATUS', 'BASELINE STATUS', 'FFUF SIZE', 'BASELINE SIZE'].forEach((l) =>
    expect(text).toContain(l));
  const strip = body.querySelector('.rounded.p-2.mb-3');
  expect(strip.textContent).not.toContain('-');
});

test('every row carries its baseline status and size', async () => {
  const withBaseline = rows.map((r, i) => ({
    ...r,
    baseline_http_status: 404,
    baseline_response_size: 154,
    baseline_verdict: i === 0 ? 'same' : 'differs',
  }));
  global.fetch = () => Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ findings: withBaseline, total: withBaseline.length, truncated: false }),
  });
  const body = await mount();
  const statusCol = [...body.querySelectorAll('tbody tr')]
    .filter((tr) => tr.querySelectorAll('td').length > 1)
    .map((tr) => tr.querySelectorAll('td')[0].textContent);
  expect(statusCol.every((t) => t.includes('vs 404'))).toBe(true);
  const sizeCol = [...body.querySelectorAll('tbody tr')]
    .filter((tr) => tr.querySelectorAll('td').length > 1)
    .map((tr) => tr.querySelectorAll('td')[4].textContent);
  expect(sizeCol.every((t) => t.includes('vs 154'))).toBe(true);
});

test('rows can be filtered to the ones that differ from their control', async () => {
  const withBaseline = rows.map((r, i) => ({
    ...r, baseline_http_status: 404, baseline_response_size: 154,
    baseline_verdict: i < 2 ? 'same' : 'differs',
  }));
  global.fetch = () => Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ findings: withBaseline, total: withBaseline.length, truncated: false }),
  });
  const body = await mount();
  const select = [...body.querySelectorAll('select')].find(
    (sel) => [...sel.options].some((o) => o.value === 'differs'));
  expect([...select.options].map((o) => o.textContent)).toContain('Differs from baseline (3)');
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, 'value').set;
    setter.call(select, 'differs');
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  expect([...body.querySelectorAll('tbody tr')]
    .filter((tr) => tr.querySelectorAll('td').length > 1)).toHaveLength(3);
});

// Triage: the operator's own mark on a row. It belongs at the top of the expanded panel because
// "have I already written this off" is a question about the row, not about the comparison.
test('the top of the accordion shows the triage state', async () => {
  for (const state of ['new', 'interesting', 'dismissed']) {
    global.fetch = (url) => Promise.resolve({
      ok: true,
      json: () => Promise.resolve(String(url).includes('/fuzz/findings/')
        ? {
          id: 'b', url: 'https://h.test/b', method: 'GET', payload: 'FUZZP01=admin', triage: state,
          response: { http_status: 404, size: 182, words: 6, lines: 11 },
          evidence: { request: 'GET /admin HTTP/1.1', response: 'HTTP/1.1 404' },
          positions: [], request_note: 'x',
          baseline: { canary: 'rs0n', http_status: 404, response_size: 154, verdict: 'same',
            request: 'GET /rs0n HTTP/1.1', response: 'HTTP/1.1 404', note: 'same' },
        }
        : { findings: rows, total: rows.length, truncated: false }),
    });
    const body = await mount();
    const row = [...body.querySelectorAll('tbody tr')].find((tr) => tr.querySelectorAll('td').length > 1);
    await act(async () => { row.click(); });
    const strip = body.querySelector('.rounded.p-2.mb-3');
    expect(strip.textContent).toContain(state);
    document.body.innerHTML = '';
  }
});

// It shows with no baseline too, since the mark is about the row rather than the control.
test('the triage state shows even when no baseline has been taken', async () => {
  global.fetch = (url) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(String(url).includes('/fuzz/findings/')
      ? {
        id: 'b', url: 'https://h.test/b', method: 'GET', payload: 'FUZZP01=admin',
        triage: 'interesting',
        response: { http_status: 404, size: 182 }, positions: [], request_note: 'x',
        baseline_note: 'No baseline has been taken for this finding yet.',
      }
      : { findings: rows, total: rows.length, truncated: false }),
  });
  const body = await mount();
  const row = [...body.querySelectorAll('tbody tr')].find((tr) => tr.querySelectorAll('td').length > 1);
  await act(async () => { row.click(); });
  expect(body.textContent).toContain('interesting');
  expect(body.textContent).toContain('No baseline has been taken');
});

test('dismissed rows are hidden by default and can be filtered back in', async () => {
  const triaged = rows.map((r, i) => ({
    ...r, triage: i === 0 ? 'dismissed' : i === 1 ? 'interesting' : 'new',
  }));
  global.fetch = (url) => {
    // The modal must ask for everything, or a dismissed row can never be filtered back to.
    if (String(url).includes('/findings?')) expect(String(url)).toContain('triage=all');
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ findings: triaged, total: triaged.length, truncated: false }),
    });
  };
  const body = await mount();
  const visible = () => [...body.querySelectorAll('tbody tr')]
    .filter((tr) => tr.querySelectorAll('td').length > 1);

  // Default view hides the dismissed one.
  expect(visible()).toHaveLength(4);

  const select = [...body.querySelectorAll('select')].find(
    (sel) => [...sel.options].some((o) => o.value === 'dismissed'));
  expect([...select.options].map((o) => o.textContent)).toContain('Interesting (1)');

  const pick = async (value) => {
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, 'value').set;
      setter.call(select, value);
      select.dispatchEvent(new Event('change', { bubbles: true }));
    });
  };
  await pick('dismissed');
  expect(visible()).toHaveLength(1);
  await pick('interesting');
  expect(visible()).toHaveLength(1);
  await pick('all');
  expect(visible()).toHaveLength(5);
});
