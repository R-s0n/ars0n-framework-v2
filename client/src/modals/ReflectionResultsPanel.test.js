import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import ReflectionResultsPanel, {
  probeAsVector,
  probeGrade,
  sortProbes,
  survivedSummary,
  evidenceSource,
  filterProbes,
  summarise,
  MAX_ROWS,
} from './ReflectionResultsPanel';

// WHAT THESE TESTS PIN, and why each one exists.
//
// 1. A row the framework could not answer for is never counted, coloured or sorted as a clean row.
//    blocked, error, needs_browser and not_probed are the whole reason the reflection probe reports
//    a status rather than a boolean, and the failure this codebase keeps meeting is a screen that
//    quietly renders them as nothing.
// 2. The grade comes from the SERVER. Go's XSSCandidateGrade is the authority and the panel must
//    show what it sent, not a second opinion derived in the browser.
// 3. A lone single quote and an angle bracket are different news. JSON escaping returns a quote from
//    every endpoint that echoes anything, so a panel that treats "something survived" as one fact
//    is measuring the response format.
// 4. A passive row and an active row are different strengths of claim, and the row says which.

const p = (over) => ({
  vector_id: '11111111-1111-4111-8111-111111111111',
  parameter: 'q',
  insertion_point: 'query',
  status: 'not_reflected',
  grade: 'xss_candidate_none',
  survived: [],
  content_type: 'application/json',
  http_status: 200,
  evidence: '',
  detail: '',
  probe_url: 'https://h.test/s?q=CANARY',
  canary: 'rs0nA1',
  auth_applied: false,
  probed_at: '2026-09-17T10:00:00Z',
  evidence_source: 'active',
  method: 'GET',
  domain: 'h.test',
  path: '/s',
  fragment: '',
  vector_reflection_status: 'not_reflected',
  vector_grade: 'xss_candidate_none',
  ...over,
});

// --- the grade is the server's ------------------------------------------------------------------

test('the row carries the grade the server sent, not one derived here', () => {
  // A row whose stored content type would grade LOW locally, labelled HIGH by Go. The panel must
  // show Go's answer: if the two ever disagree it is Go that is right and this file that follows.
  const row = p({ status: 'reflected_raw', content_type: 'application/json', survived: ["'"], grade: 'xss_candidate_high' });
  expect(probeGrade(row)).toBe('xss_candidate_high');
  expect(probeAsVector(row).reflection_grade).toBe('xss_candidate_high');
});

test('a grade this build cannot rank falls back to the shared derivation rather than passing through', () => {
  const row = p({ status: 'reflected_raw', content_type: 'text/html', survived: ['<', '>'], grade: 'xss_candidate_martian' });
  expect(probeGrade(row)).toBe('xss_candidate_high');
});

test('a row with no grade field at all is still graded, from status and content type', () => {
  const row = p({ status: 'reflected_raw', content_type: 'text/html', survived: ['<'], grade: undefined });
  expect(probeGrade(row)).toBe('xss_candidate_high');
  const json = p({ status: 'reflected_raw', content_type: 'application/json', survived: ['<'], grade: undefined });
  expect(probeGrade(json)).toBe('xss_candidate_low');
});

// --- not knowing is not clean -------------------------------------------------------------------

test('every unknown status is counted as not known, and none of them as a clean result', () => {
  const rows = [
    p({ status: 'blocked', grade: 'xss_unknown' }),
    p({ status: 'error', grade: 'xss_unknown' }),
    p({ status: 'needs_browser', grade: 'xss_unknown' }),
    p({ status: 'not_probed', grade: 'xss_unknown' }),
    p({ status: 'is_credential', grade: 'xss_unknown' }),
    p({ status: 'probe_refused', grade: 'xss_unknown' }),
    p({ status: 'not_reflected', grade: 'xss_candidate_none' }),
  ];
  const s = summarise(rows);
  expect(s.total).toBe(7);
  expect(s.notKnown).toBe(6);
  expect(s.grades.xss_candidate_none).toBe(1);
  // Named individually, because "6 unknown" does not tell an operator that a WAF ate the probes.
  expect(Object.fromEntries(s.notKnownBreakdown)).toEqual({
    blocked: 1, error: 1, needs_browser: 1, not_probed: 1, is_credential: 1, probe_refused: 1,
  });
});

test('a target that refused everything reports zero clean rows, not zero findings', () => {
  const rows = [p({ status: 'blocked', grade: 'xss_unknown' }), p({ status: 'blocked', grade: 'xss_unknown' })];
  const s = summarise(rows);
  expect(s.notKnown).toBe(2);
  expect(s.grades.xss_candidate_none).toBe(0);
  expect(s.grades.xss_candidate_high).toBe(0);
});

test('a grade with no rows is a zero rather than a missing key', () => {
  const s = summarise([]);
  expect(s.grades).toEqual({
    xss_candidate_high: 0, xss_candidate_chain: 0, xss_candidate_low: 0,
    xss_candidate_none: 0, xss_unknown: 0,
  });
  expect(s.notKnown).toBe(0);
});

// --- worst first --------------------------------------------------------------------------------

test('worst first, and an unknown outranks a clean no-reflection', () => {
  const rows = [
    p({ parameter: 'clean', status: 'not_reflected', grade: 'xss_candidate_none' }),
    p({ parameter: 'never', status: 'not_probed', grade: 'xss_unknown' }),
    p({ parameter: 'waf', status: 'blocked', grade: 'xss_unknown' }),
    p({ parameter: 'low', status: 'reflected_raw', grade: 'xss_candidate_low' }),
    p({ parameter: 'high', status: 'reflected_raw', grade: 'xss_candidate_high' }),
    p({ parameter: 'echo', status: 'reflected_observed', grade: 'xss_candidate_low' }),
    p({ parameter: 'enc', status: 'reflected_encoded', grade: 'xss_candidate_none' }),
    p({ parameter: 'chain', status: 'reflected_raw', grade: 'xss_candidate_chain', insertion_point: 'cookie' }),
  ];
  expect(sortProbes(rows).map((r) => r.parameter))
    .toEqual(['high', 'chain', 'low', 'echo', 'enc', 'waf', 'clean', 'never']);
});

test('sorting does not mutate the array it was handed', () => {
  const rows = [
    p({ parameter: 'clean', status: 'not_reflected' }),
    p({ parameter: 'high', status: 'reflected_raw', grade: 'xss_candidate_high' }),
  ];
  sortProbes(rows);
  expect(rows.map((r) => r.parameter)).toEqual(['clean', 'high']);
});

// --- what survived ------------------------------------------------------------------------------

test('an angle bracket is called markup and a lone quote is not', () => {
  const bracket = survivedSummary(['<', "'"], 'reflected_raw');
  expect(bracket.markup).toBe(true);
  expect(bracket.weak).toBe(false);
  expect(bracket.note).toMatch(/angle bracket/i);

  const quote = survivedSummary(["'"], 'reflected_raw');
  expect(quote.markup).toBe(false);
  expect(quote.weak).toBe(true);
  expect(quote.note).toMatch(/JSON escaping/i);
  // The quote is still shown. It matters for an attribute or a JS string; it just is not evidence
  // that a tag can be opened.
  expect(quote.chars).toEqual(["'"]);
});

test('nothing survived and nobody recorded it are different answers', () => {
  const none = survivedSummary([], 'not_reflected');
  expect(none.markup).toBe(false);
  expect(none.weak).toBe(false);
  expect(none.measured).toBe(true);

  // Not an array means the probe never wrote the field, and that is treated as markup for the same
  // reason an empty content type is treated as rendering: hiding a candidate costs more.
  for (const missing of [null, undefined, 'not an array']) {
    expect(survivedSummary(missing, 'reflected_raw').markup).toBe(true);
    expect(survivedSummary(missing, 'reflected_raw').note).toMatch(/not recorded/i);
  }
});

// A CLEAN SENTENCE ON A ROW WHERE NOTHING WAS EVER SENT.
//
// The server COALESCEs survived to an empty array, so blocked, not_probed, is_credential and
// probe_refused all arrive looking exactly like a probe that went out and came back clean. The
// caption branched on the array alone, so all four rendered "Nothing came back unencoded." as the
// tooltip and as the first line of the expanded detail: a statement about a target that was never
// asked the question. The caption now depends on whether anything was sent.
test('a row where nothing was sent never reads as a clean answer', () => {
  for (const status of ['blocked', 'not_probed', 'is_credential', 'probe_refused',
    'error', 'needs_browser']) {
    const s = survivedSummary([], status);
    expect(s.measured).toBe(false);
    expect(s.note).not.toMatch(/nothing came back/i);
    expect(s.note.length).toBeGreaterThan(0);
  }

  // The three where nothing left the framework at all say so in those words, because that is the
  // whole point of the row.
  for (const status of ['is_credential', 'probe_refused', 'not_probed']) {
    expect(survivedSummary([], status).note).toMatch(/nothing was sent|never been probed/i);
  }

  // A status this build has not learned about yet gets the same treatment, rather than falling
  // through to the clean sentence one release later.
  const future = survivedSummary([], 'reflected_sideways');
  expect(future.measured).toBe(false);
  expect(future.note).not.toMatch(/nothing came back/i);

  // And the clean answer itself still says the clean thing, in words that say a probe was sent.
  const clean = survivedSummary([], 'not_reflected');
  expect(clean.measured).toBe(true);
  expect(clean.note).toMatch(/probe was sent/i);

  // A passive echo is measured and yet nothing was sent for it either, so it does not borrow the
  // active pass's sentence.
  const echoed = survivedSummary([], 'reflected_observed');
  expect(echoed.measured).toBe(true);
  expect(echoed.note).not.toMatch(/probe was sent/i);
  expect(echoed.note).toMatch(/stored response/i);

  // A row that did record characters is read for those characters whatever its status: a stored
  // measurement is never thrown away because the status was not one of the four.
  const odd = survivedSummary(['<'], 'blocked');
  expect(odd.chars).toEqual(['<']);
  expect(odd.markup).toBe(true);
});

// --- passive against active ---------------------------------------------------------------------

test('a stored row and a sent row are labelled differently, and the default is a sent probe', () => {
  expect(evidenceSource('passive').label).toBe('stored');
  expect(evidenceSource('passive').why).toMatch(/no traffic was sent/i);
  expect(evidenceSource('active').label).toBe('probe');
  // A row from an api container that predates the column must not claim to be passive: passive is
  // the stronger promise (nothing was sent) and defaulting to it would be a false one.
  expect(evidenceSource('').label).toBe('probe');
  expect(evidenceSource(undefined).label).toBe('probe');
});

// --- filters ------------------------------------------------------------------------------------

test('each filter narrows on its own field and an empty filter keeps every row', () => {
  const rows = [
    p({ parameter: 'a', status: 'blocked', grade: 'xss_unknown', insertion_point: 'query' }),
    p({ parameter: 'b', status: 'reflected_raw', grade: 'xss_candidate_high', insertion_point: 'path' }),
    p({ parameter: 'c', status: 'reflected_observed', grade: 'xss_candidate_low', evidence_source: 'passive' }),
  ];
  expect(filterProbes(rows, {}).length).toBe(3);
  expect(filterProbes(rows, { grade: 'xss_unknown' }).map((r) => r.parameter)).toEqual(['a']);
  expect(filterProbes(rows, { status: 'reflected_raw' }).map((r) => r.parameter)).toEqual(['b']);
  expect(filterProbes(rows, { point: 'path' }).map((r) => r.parameter)).toEqual(['b']);
  expect(filterProbes(rows, { source: 'passive' }).map((r) => r.parameter)).toEqual(['c']);
  expect(filterProbes(rows, { source: 'active' }).map((r) => r.parameter)).toEqual(['a', 'b']);
});

test('search matches host, path, parameter and verb', () => {
  const rows = [
    p({ parameter: 'token', domain: 'api.h.test', path: '/v1/echo' }),
    p({ parameter: 'q', domain: 'www.h.test', path: '/search', method: 'POST' }),
  ];
  expect(filterProbes(rows, { search: 'echo' }).map((r) => r.parameter)).toEqual(['token']);
  expect(filterProbes(rows, { search: 'API.H' }).map((r) => r.parameter)).toEqual(['token']);
  expect(filterProbes(rows, { search: 'post' }).map((r) => r.parameter)).toEqual(['q']);
  expect(filterProbes(rows, { search: '   ' }).length).toBe(2);
});

// --- the rendered table -------------------------------------------------------------------------

beforeAll(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });
afterEach(() => { document.body.innerHTML = ''; });

const serve = (probes) => {
  global.fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve({ probes, count: probes.length }) });
};

async function mount() {
  document.body.innerHTML = '';
  const c = document.createElement('div');
  document.body.appendChild(c);
  const root = createRoot(c);
  await act(async () => {
    root.render(<ReflectionResultsPanel
      activeTarget={{ id: '11111111-1111-4111-8111-111111111111' }} />);
  });
  return document.body;
}

const bodyText = (body) => body.textContent;
const rowBadges = (body) => [...body.querySelectorAll('tbody tr td:first-child span')]
  .map((s) => s.textContent);

test('the table lists one row per input, worst first, with a word on every badge', async () => {
  serve([
    p({ parameter: 'clean', status: 'not_reflected', grade: 'xss_candidate_none' }),
    p({ parameter: 'waf', status: 'blocked', grade: 'xss_unknown' }),
    p({ parameter: 'hot', status: 'reflected_raw', grade: 'xss_candidate_high', content_type: 'text/html', survived: ['<', '>'] }),
  ]);
  const body = await mount();
  expect(rowBadges(body)).toEqual(['XSS High', 'Blocked', 'No Reflection']);
});

test('the not-known count is on screen even when the probe found candidates', async () => {
  serve([
    p({ parameter: 'hot', status: 'reflected_raw', grade: 'xss_candidate_high', content_type: 'text/html', survived: ['<'] }),
    p({ parameter: 'waf', status: 'blocked', grade: 'xss_unknown' }),
    p({ parameter: 'never', status: 'not_probed', grade: 'xss_unknown' }),
  ]);
  const body = await mount();
  expect(bodyText(body)).toContain('2 not known');
  expect(bodyText(body)).toContain('blocked 1');
  expect(bodyText(body)).toContain('not probed 1');
});

test('a run where nothing was answered still says so rather than showing an empty clean table', async () => {
  serve([p({ status: 'blocked', grade: 'xss_unknown' }), p({ status: 'error', grade: 'xss_unknown' })]);
  const body = await mount();
  expect(bodyText(body)).toContain('2 not known');
  expect(body.querySelectorAll('tbody tr').length).toBe(2);
});

test('a lone quote is marked as quotes only and an angle bracket as opening a tag', async () => {
  serve([
    p({ parameter: 'json', status: 'reflected_raw', grade: 'xss_candidate_low', survived: ["'"] }),
    p({ parameter: 'html', status: 'reflected_raw', grade: 'xss_candidate_high', content_type: 'text/html', survived: ['<', '>'] }),
  ]);
  const body = await mount();
  expect(bodyText(body)).toContain('quotes only');
  expect(bodyText(body)).toContain('opens a tag');
});

// THE TOOLTIP ON A ROW WHERE NOTHING WAS SENT SAID THE TARGET WAS CLEAN.
//
// The server COALESCEs survived to an empty array, so blocked, not_probed, is_credential and
// probe_refused reached the caption looking like a probe that came back with nothing in it.
test('a row nobody sent anything for does not claim the response was clean', async () => {
  serve([
    p({ parameter: 'waf', status: 'blocked', grade: 'xss_unknown' }),
    p({ parameter: 'session', status: 'is_credential', grade: 'xss_unknown' }),
    p({ parameter: 'never', status: 'not_probed', grade: 'xss_unknown' }),
    p({ parameter: 'clean', status: 'not_reflected', grade: 'xss_candidate_none' }),
  ]);
  const body = await mount();
  // Keyed by input name, because the table is sorted worst first and not in the order served.
  const captions = Object.fromEntries([...body.querySelectorAll('tbody tr')]
    .map((tr) => [tr.children[1].querySelector('code').textContent,
      tr.children[3].getAttribute('title')]));
  const { waf, session: credential, never, clean } = captions;

  [waf, credential, never].forEach((c) => {
    expect(c).not.toMatch(/nothing came back unencoded/i);
    expect(c.length).toBeGreaterThan(0);
  });
  expect(credential).toMatch(/nothing was sent/i);
  expect(never).toMatch(/nothing was sent|never been probed/i);
  // And the row that really was answered still says the clean thing.
  expect(clean).toMatch(/nothing came back unencoded/i);
});

test('the row says whether it came from stored traffic or from a probe that was sent', async () => {
  serve([
    p({ parameter: 'echoed', status: 'reflected_observed', grade: 'xss_candidate_low', evidence_source: 'passive' }),
    p({ parameter: 'sent', status: 'reflected_raw', grade: 'xss_candidate_low', evidence_source: 'active' }),
  ]);
  const body = await mount();
  const how = [...body.querySelectorAll('tbody tr')].map((tr) => tr.children[4].textContent);
  expect(how).toEqual(['probe', 'stored']);
});

test('a target with no probe rows is told to run Investigate, not shown a clean table', async () => {
  serve([]);
  const body = await mount();
  expect(bodyText(body)).toContain('No reflection probe rows yet');
  expect(body.querySelectorAll('tbody tr').length).toBe(0);
});

test('a failed load says so instead of rendering an empty result', async () => {
  global.fetch = () => Promise.resolve({ ok: false, json: () => Promise.resolve({}) });
  const body = await mount();
  expect(bodyText(body)).toContain('Could not load reflection probe results');
});

test('more rows than the render ceiling are capped and the rest are counted, not dropped silently', async () => {
  const many = [];
  for (let i = 0; i < MAX_ROWS + 25; i += 1) {
    many.push(p({ parameter: `p${i}`, status: 'blocked', grade: 'xss_unknown' }));
  }
  serve(many);
  const body = await mount();
  expect(body.querySelectorAll('tbody tr').length).toBe(MAX_ROWS);
  expect(bodyText(body)).toContain('25 more rows match');
  // The counts describe everything that was loaded, never only what was drawn.
  expect(bodyText(body)).toContain(`${MAX_ROWS + 25} not known`);
});

test('expanding a row shows the evidence and the reason, and says when no snippet was kept', async () => {
  serve([
    p({
      parameter: 'q', status: 'blocked', grade: 'xss_unknown', evidence: '',
      detail: 'The target answered 403 with a WAF signature.',
    }),
  ]);
  const body = await mount();
  await act(async () => {
    body.querySelector('tbody tr').dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  expect(bodyText(body)).toContain('The target answered 403 with a WAF signature.');
  expect(bodyText(body)).toContain('No response snippet was kept');
});
