/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import PointersModal, {
  rankPointers,
  filterPointers,
  markerTerms,
  splitOnTerms,
  emptyState,
  coverageChips,
  strengthTone,
  originNote,
  STRENGTH_NOTE,
} from './PointersModal';

// WHAT THESE TESTS PIN, and why each one exists.
//
// 1. A pointer is a lead, not a finding, and the screen never lets the two read the same. The
//    strength word, the baseline line and the "IF the class confirms" wording are the difference.
// 2. THE COVERAGE IS ALWAYS ON SCREEN. 34 pointers beside 1714 unknown probe rows is the live
//    shape of this data, and a list of 34 with nothing beside it reads as "the rest is fine".
//    That false negative is the reason this layer exists, so the strip is asserted on the same
//    render as a populated list, not on its own.
// 3. An empty list says WHICH empty it is. Never scanned and scanned-with-no-lead are different
//    facts about the target and must never render the same sentence.
// 4. The evidence is highlighted in BOTH the request and the response, from terms taken off the
//    pointer rather than guessed, because the operator's ask was to be able to see the marker.
// 5. Nothing is re-derived: rank, grade, rule, attack path and next tool are the server's and the
//    screen shows what it sent.

const TARGET = { id: '1e9b4bec-e8ca-41ac-9da3-744322637f2b' };

// Both fixtures are trimmed copies of real rows from
// GET /attack-vectors/1e9b4bec-e8ca-41ac-9da3-744322637f2b/pointers on the measured corpus.
const REFLECTION = {
  id: 'reflection_probe:118bd186-ce37-4eaf-b141-ee920ae5144e',
  source: 'reflection_probe',
  source_detail: 'passive reflection pass: no request was sent, the value was found in a stored response',
  attack_class: 'XSS-R',
  attack_class_label: 'Reflected XSS',
  grade: 'xss_candidate_low',
  grade_source: 'XSSCandidateGrade, the server\'s own reflection grade, carried unchanged',
  strength: 'passive_echo',
  strength_rank: 1,
  delta_checked: false,
  rank: 10,
  why_ranked: '10 of 43. The value came back in a response the crawl had already stored.',
  vector_id: 'e44e97fd-ab82-4c41-8011-b2f18c501a84',
  method: 'GET',
  url: 'https://app.h.test/api/v1/accounts/edd0edb9-7562-4c9f-a5cb-5c70d5996c08/trade_account/margin',
  domain: 'app.h.test',
  path: '/api/v1/accounts/{uuid}/trade_account/margin',
  insertion_point: 'path',
  parameter: '',
  slot_key: '',
  rule: 'A value the crawl sent was found echoed in the response the crawl stored.',
  evidence: '{"id":"edd0edb9-7562-4c9f-a5cb-5c70d5996c08"',
  http_status: 200,
  content_type: 'application/json; charset=UTF-8',
  deliverable: true,
  next_tool: 'dalfox',
  next_tool_reason: 'Dalfox drives the reflection towards an executable position.',
  detail_url: `/attack-vectors/${TARGET.id}/pointers/reflection_probe:118bd186-ce37-4eaf-b141-ee920ae5144e`,
};

const FINDING = {
  id: 'vector_finding:21a29bd5-e749-4f6c-9023-25324b899f55',
  source: 'vector_finding',
  source_detail: 'trufflehog reported exposed-credential on an earlier scan',
  attack_class: 'SECRET',
  attack_class_label: 'Exposed secret',
  grade: 'medium',
  grade_source: 'trufflehog\'s own severity, stored unchanged.',
  strength: 'prior_finding',
  strength_rank: 2,
  delta_checked: false,
  rank: 1,
  why_ranked: '1 of 43. A tool flagged this vector on an earlier scan.',
  vector_id: '',
  method: 'GET',
  url: 'https://app.h.test/env.js',
  domain: '',
  path: '',
  insertion_point: 'body',
  parameter: '',
  rule: 'trufflehog reported exposed-credential, by detection method trufflehog AmplitudeApiKey.',
  evidence: 'AmplitudeApiKey: d68142...1d77',
  http_status: 0,
  content_type: '',
  deliverable: true,
  next_tool: '',
  next_tool_reason: 'A secret is confirmed by reading it and using it, not by another scanner.',
  detail_url: `/attack-vectors/${TARGET.id}/pointers/vector_finding:21a29bd5-e749-4f6c-9023-25324b899f55`,
};

const COVERAGE = {
  vectors: {
    total: 218,
    with_pointer: 28,
    concluded: 32,
    unknown: 186,
    by_grade: { xss_candidate_high: 0, xss_candidate_low: 26, xss_candidate_none: 6, xss_unknown: 186 },
  },
  reflection: {
    probe_rows: 1764,
    by_status: { is_credential: 1555, error: 110, probe_refused: 49, reflected_observed: 34, not_reflected: 16 },
    by_grade: { xss_candidate_low: 34, xss_candidate_none: 16, xss_unknown: 1714 },
    unknown: 1714,
    unknown_by_reason: { is_credential: 1555, error: 110, probe_refused: 49 },
    run_status: 'completed',
  },
  findings: {
    rows: 415, pointers: 9, excluded_canary: 390, excluded_dismissed: 16,
    note: 'The positive control fires every tool at the framework\'s own oracle container first.',
  },
  triage: {
    run_id: '', status: 'no_run_yet', slots: 0, coverage_pairs: 0, verdicts: 0,
    positive: 0, unknown: 0, payload_unproven: 0,
    note: 'The triage runner is built and not yet wired. That is a gap in coverage, not a clean result.',
  },
  headline: '43 pointers across 28 of 218 vectors. 186 vectors have no conclusion from any source, '
    + 'and 1714 of 1764 probe rows are unknown rather than clean.',
};

const LIST = {
  scope_target_id: TARGET.id,
  pointers: [FINDING, REFLECTION],
  count: 2,
  total: 2,
  filters_applied: { attack_class: [], source: [], grade: [], insertion_point: [] },
  counts: {
    by_attack_class: { 'XSS-R': 1, SECRET: 1 },
    by_source: { reflection_probe: 1, vector_finding: 1, triage_verdict: 0 },
    by_grade: { xss_candidate_low: 1, medium: 1 },
    by_insertion_point: { body: 1, path: 1 },
    by_strength: { passive_echo: 1, prior_finding: 1 },
  },
  coverage: COVERAGE,
  vocabulary: {
    sources: ['reflection_probe', 'vector_finding', 'triage_verdict'],
    strength_order: ['delta_checked', 'tool_reported', 'probe_observed', 'prior_finding', 'passive_echo', 'unattributed'],
    class_labels: { 'XSS-R': 'Reflected XSS', SECRET: 'Exposed secret' },
  },
};

const REFLECTION_DETAIL = {
  pointer: REFLECTION,
  request: {
    raw: 'GET /api/v1/accounts/edd0edb9-7562-4c9f-a5cb-5c70d5996c08/trade_account/margin HTTP/1.1\n'
      + 'Host: app.h.test\naccept: */*\n\n',
    origin: 'captured',
    note: 'The request the crawl stored for this vector.',
  },
  response: {
    raw: '{"id":"edd0edb9-7562-4c9f-a5cb-5c70d5996c08","status":"ONBOARDING"}',
    origin: 'evidence_snippet',
    note: 'A window around the match in a response the crawl had already stored. Not the whole body.',
  },
  baseline: {
    compared: false,
    what: 'None. The passive pass compares nothing: it looks for a value the crawl already sent.',
  },
  rule: {
    fired: 'A value the crawl sent was found echoed in the response the crawl stored.',
    means: 'This input reaches the response body.',
    did_not_establish: 'Execution. Whether the angle brackets survive is UNTESTED.',
  },
  grade: {
    value: 'xss_candidate_low',
    source: 'XSSCandidateGrade, the server\'s own reflection grade, carried unchanged',
    why: 'A browser does not render application/json, so a payload here has nowhere to execute.',
  },
  attack_path: {
    entry: 'The attacker controls the path value on GET https://app.h.test/api/v1/accounts/...',
    reaches: 'A value the crawl sent was found echoed in the stored response. '
      + 'The response was application/json; charset=UTF-8.',
    deliverable: true,
    possible_attacks: [
      'Script in the victim\'s origin: session theft where the cookie is reachable.',
      'A chain into account takeover if the page exposes an email change.',
    ],
    next: {
      tool: 'dalfox',
      reason: 'Dalfox drives the reflection towards an executable position.',
      vector_id: 'e44e97fd-ab82-4c41-8011-b2f18c501a84',
      insertion_point: 'path',
      parameter: '',
    },
  },
};

const FINDING_DETAIL = {
  pointer: FINDING,
  request: {
    raw: 'GET /env.js HTTP/1.1\nHost: app.h.test\n\n',
    origin: 'reconstructed',
    note: 'trufflehog recorded neither the request nor the response, so this was COMPOSED.',
  },
  response: { raw: '', origin: 'none' },
  baseline: { compared: false, what: 'trufflehog ran its own comparison and this framework did not see it.' },
  rule: { fired: 'trufflehog reported exposed-credential.', means: '', did_not_establish: '' },
  grade: { value: 'medium', source: 'trufflehog\'s own severity, stored unchanged.', why: '' },
  attack_path: {
    entry: 'The attacker controls the body value on GET https://app.h.test/env.js.',
    reaches: 'trufflehog reported exposed-credential.',
    deliverable: true,
    possible_attacks: ['Direct use of the credential against whatever issued it.'],
    next: { tool: '', reason: 'A secret is confirmed by reading it and using it.', vector_id: '', insertion_point: 'body', parameter: '' },
  },
  reproduction: {
    url: 'https://app.h.test/env.js',
    curl: "curl -i -sS 'https://app.h.test/env.js'",
    raw_request: 'GET /env.js HTTP/1.1\nHost: app.h.test\n\n',
    steps: ['Send the request below and compare it against the same request with the payload removed.'],
    caveat: 'RECONSTRUCTED, not captured.',
    request_origin: 'reconstructed',
  },
};

// --- ordering ------------------------------------------------------------------------------

test('the list is the server rank, worst first, whatever order the rows arrive in', () => {
  const ranked = rankPointers([REFLECTION, FINDING]);
  expect(ranked.map((p) => p.rank)).toEqual([1, 10]);
  expect(ranked[0].attack_class).toBe('SECRET');
  // The input array is never mutated: the raw response is kept as the server sent it.
  expect([REFLECTION, FINDING][0].rank).toBe(10);
});

// --- filters ---------------------------------------------------------------------------------

test('each filter narrows on its own field and an empty filter keeps every pointer', () => {
  const rows = [FINDING, REFLECTION];
  expect(filterPointers(rows, {}).length).toBe(2);
  expect(filterPointers(rows, { attackClass: 'XSS-R' }).map((p) => p.id)).toEqual([REFLECTION.id]);
  expect(filterPointers(rows, { source: 'vector_finding' }).map((p) => p.id)).toEqual([FINDING.id]);
  expect(filterPointers(rows, { search: 'env.js' }).map((p) => p.id)).toEqual([FINDING.id]);
  expect(filterPointers(rows, { search: 'DALFOX' }).map((p) => p.id)).toEqual([REFLECTION.id]);
  expect(filterPointers(rows, { search: '   ' }).length).toBe(2);
});

// --- the marker ---------------------------------------------------------------------------------

test('the highlight terms come off the pointer, including the path segment the server templated', () => {
  // The path template carries {uuid} where the url carries the real value. That difference IS the
  // attacker-controlled value, and it is the string that came back in the response.
  expect(markerTerms(REFLECTION)).toContain('edd0edb9-7562-4c9f-a5cb-5c70d5996c08');

  const query = {
    ...REFLECTION,
    url: 'https://app.h.test/search?q=rs0nCanary1&page=2',
    path: '/search',
    insertion_point: 'query',
    parameter: 'q',
  };
  // The VALUE is the term that matters. A one character parameter name is deliberately dropped:
  // marking every "q" in a 4KB request highlights nothing.
  expect(markerTerms(query)).toEqual(['rs0nCanary1']);
  expect(markerTerms({ ...query, parameter: 'redirect_uri' }))
    .toEqual(expect.arrayContaining(['redirect_uri']));

  // A pointer with nothing addressable on it highlights nothing rather than inventing a term.
  expect(markerTerms({ url: '', path: '', parameter: '' })).toEqual([]);
  expect(markerTerms(null)).toEqual([]);
});

test('every occurrence of a term is marked and the rest of the text is left alone', () => {
  const runs = splitOnTerms('a=CANARY&b=2&c=canary', ['CANARY']);
  expect(runs.filter((r) => r.hit).map((r) => r.text)).toEqual(['CANARY', 'canary']);
  expect(runs.map((r) => r.text).join('')).toBe('a=CANARY&b=2&c=canary');

  // No term is not an excuse to mark the whole blob.
  expect(splitOnTerms('plain', [])).toEqual([{ text: 'plain', hit: false }]);
  // A term with regex metacharacters is matched literally, not compiled.
  expect(splitOnTerms('a.b and axb', ['a.b']).filter((r) => r.hit).map((r) => r.text)).toEqual(['a.b']);
});

// --- coverage -------------------------------------------------------------------------------

test('the coverage chips report every source, with the reason each unknown is unknown', () => {
  const chips = coverageChips(COVERAGE);
  const byKey = Object.fromEntries(chips.map((c) => [c.key, c]));

  expect(byKey.vectors.text).toContain('218 vectors');
  expect(byKey.vectors.text).toContain('186 with no conclusion');
  expect(byKey.vectors.unknown).toBe(true);

  expect(byKey.reflection.text).toContain('1714 unknown');
  expect(byKey.reflection.text).toContain('is credential 1555');
  expect(byKey.reflection.text).toContain('error 110');

  expect(byKey.findings.text).toContain('390 positive control');
  expect(byKey.findings.text).toContain('16 dismissed');

  // A source that has never run is an unknown, not a zero to be read as a clean result.
  expect(byKey.triage.text).toContain('no run yet');
  expect(byKey.triage.unknown).toBe(true);
  expect(byKey.triage.why).toMatch(/gap in coverage, not a clean result/i);
});

test('a target with no coverage at all still gets a chip per source rather than a blank strip', () => {
  const chips = coverageChips(undefined);
  expect(chips.map((c) => c.key)).toEqual(['vectors', 'reflection', 'findings', 'triage']);
  expect(chips[0].text).toContain('0 vectors');
});

// --- the two empties --------------------------------------------------------------------------

test('never scanned and scanned-with-no-lead are different states and read differently', () => {
  const never = emptyState({ reflection: { probe_rows: 0 }, findings: { rows: 0 }, triage: { verdicts: 0 } });
  expect(never.kind).toBe('never_scanned');
  expect(never.title).toMatch(/nothing has been scanned/i);
  expect(never.detail).toMatch(/not that the target has nothing on it/i);

  const scanned = emptyState({
    reflection: { probe_rows: 1764, unknown: 1714 },
    findings: { rows: 415 },
    triage: { verdicts: 0 },
  });
  expect(scanned.kind).toBe('scanned_nothing_found');
  expect(scanned.title).toContain('1764 probe rows');
  expect(scanned.title).toContain('415 stored findings');
  // And it is still not a clean bill while unknowns remain.
  expect(scanned.detail).toContain('1714');
  expect(scanned.detail).toMatch(/gap in coverage rather than a clean result/i);
  expect(scanned.title).not.toBe(never.title);
});

// --- the words on a lead ------------------------------------------------------------------------

test('a lead and a measurement are never the same colour or the same sentence', () => {
  expect(strengthTone({ strength: 'delta_checked' })).toBe('#dc3545');
  expect(strengthTone({ strength: 'probe_observed' })).toBe('#fd7e14');
  // A prior finding and a passive echo are leads. They are muted on purpose.
  expect(strengthTone({ strength: 'prior_finding' })).toBe('rgba(255,255,255,0.55)');
  expect(strengthTone({ strength: 'passive_echo' })).toBe('rgba(255,255,255,0.55)');
  expect(strengthTone({})).toBe('rgba(255,255,255,0.55)');

  expect(STRENGTH_NOTE.passive_echo).toMatch(/nothing was sent/i);
  expect(STRENGTH_NOTE.prior_finding).toMatch(/not a measurement of the application today/i);
  expect(STRENGTH_NOTE.delta_checked).toMatch(/compared against a baseline/i);
});

test('a composed request never describes itself as a recording', () => {
  expect(originNote({ origin: 'reconstructed' })).toMatch(/not a recording/i);
  expect(originNote({ origin: 'captured' })).toMatch(/recorded on the wire/i);
  // The server's own note wins when it sent one.
  expect(originNote({ origin: 'captured', note: 'server said this' })).toBe('server said this');
  expect(originNote(undefined)).toMatch(/nothing was recorded/i);
});

// --- the rendered modal ---------------------------------------------------------------------

beforeAll(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });

let container;
let root;
let requested;

const serve = (list, detailFor) => {
  requested = [];
  global.fetch = (url) => {
    const u = String(url);
    requested.push(u);
    if (u.includes('/pointers/')) {
      const body = detailFor ? detailFor(u) : null;
      if (!body) {
        return Promise.resolve({
          ok: false,
          status: 404,
          json: () => Promise.resolve({ error: 'pointer_not_found', message: 'No pointer with that id.' }),
        });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
    }
    if (u.includes('/pointers')) {
      if (!list) {
        return Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(list) });
    }
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) });
  };
};

const settle = async () => {
  for (let i = 0; i < 5; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => {});
  }
};

async function mount() {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(<PointersModal show handleClose={() => {}} activeTarget={TARGET} />);
  });
  await settle();
  return document.body;
}

afterEach(() => {
  if (root) act(() => { root.unmount(); });
  if (container) container.remove();
  root = null;
  container = null;
  document.body.innerHTML = '';
});

const rows = () => [...document.querySelectorAll('[data-pointer-id]')];
const detailPane = () => document.querySelectorAll('.modal-body > div')[1].children[1];

const detailRouter = (u) => {
  if (u.includes(REFLECTION.id)) return REFLECTION_DETAIL;
  if (u.includes(FINDING.id)) return FINDING_DETAIL;
  return null;
};

test('the list names the class, the vector and the strength on every row, worst first', async () => {
  serve(LIST, detailRouter);
  const body = await mount();
  const r = rows();
  expect(r).toHaveLength(2);
  // Rank 1 first, whatever order the server listed them in.
  expect(r[0].getAttribute('data-pointer-id')).toBe(FINDING.id);
  expect(r[0].textContent).toContain('Exposed secret');
  expect(r[0].textContent).toContain('prior_finding');
  expect(r[1].textContent).toContain('Reflected XSS');
  expect(r[1].textContent).toContain('passive_echo');
  expect(r[1].textContent).toContain('/api/v1/accounts/{uuid}/trade_account/margin');
  // The row says which tool to point at it without a click.
  expect(r[1].textContent).toContain('run dalfox');
  expect(body.textContent).toContain('2 of 2 pointers');
});

// THE FALSE NEGATIVE THIS WHOLE LAYER EXISTS TO PREVENT. Asserted on a render that HAS pointers,
// because that is the render where a reader is most likely to conclude the rest is fine.
test('the coverage is on screen beside a populated list, not behind a toggle', async () => {
  serve(LIST, detailRouter);
  const body = await mount();
  expect(body.textContent).toContain('186 vectors have no conclusion from any source');
  expect(body.textContent).toContain('1714 unknown');
  expect(body.textContent).toContain('is credential 1555');
  expect(body.textContent).toContain('triage: no run yet');
  // No control hides it: the strip is not inside a details, a collapse or a tab.
  expect(document.querySelectorAll('.modal-body details').length).toBe(0);
});

test('the highlighted pointer opens with its evidence, and the attack path is drawn as a path', async () => {
  serve(LIST, detailRouter);
  await mount();
  // The first row is selected on load, so the pane is never an empty box beside a full list.
  expect(requested.some((u) => u.includes(FINDING.id))).toBe(true);

  await act(async () => {
    rows()[1].dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  await settle();

  const pane = detailPane().textContent;
  expect(requested.some((u) => u.includes(REFLECTION.id))).toBe(true);
  // Entry, travel, landing, consequence, next tool.
  expect(pane).toContain('Input the attacker controls');
  expect(pane).toContain('Where it travels');
  expect(pane).toContain('Where it lands');
  expect(pane).toContain('What an attacker could do from there, IF the class confirms');
  expect(pane).toContain('Point this next');
  expect(pane).toContain('Script in the victim\'s origin');
  expect(pane).toContain('dalfox');
  // The open question, stated as the server stated it.
  expect(pane).toContain('Whether the angle brackets survive is UNTESTED');
});

test('the marker is highlighted in the request and in the response', async () => {
  serve(LIST, detailRouter);
  await mount();
  await act(async () => {
    rows()[1].dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  await settle();

  const pres = [...detailPane().querySelectorAll('pre')];
  // Request, response and the reproduction block.
  expect(pres.length).toBeGreaterThanOrEqual(2);
  const marks = pres.slice(0, 2).map((pre) => [...pre.querySelectorAll('mark')].map((m) => m.textContent));
  expect(marks[0]).toContain('edd0edb9-7562-4c9f-a5cb-5c70d5996c08');
  expect(marks[1]).toContain('edd0edb9-7562-4c9f-a5cb-5c70d5996c08');
  // Marking the value did not eat the rest of the bytes.
  expect(pres[0].textContent).toContain('Host: app.h.test');
});

test('a pointer with no baseline and a composed request says both, in the pane', async () => {
  serve(LIST, detailRouter);
  await mount();
  const pane = detailPane().textContent;
  expect(pane).toContain('Not compared.');
  expect(pane).toContain('trufflehog ran its own comparison');
  expect(pane).toContain('no baseline compared');
  expect(pane).toContain('COMPOSED');
  // A prior finding says out loud that it is about the past.
  expect(pane).toMatch(/not a measurement of the application today/i);
  // And the response that was never recorded is named rather than drawn as an empty box.
  expect(pane).toContain('No response was recorded for this pointer');
});

test('a target nobody has scanned is told so, and is not shown as scanned with nothing found', async () => {
  serve({
    ...LIST,
    pointers: [],
    count: 0,
    total: 0,
    counts: { by_attack_class: {}, by_source: {}, by_grade: {}, by_insertion_point: {}, by_strength: {} },
    coverage: {
      vectors: { total: 0, with_pointer: 0, concluded: 0, unknown: 0, by_grade: {} },
      reflection: { probe_rows: 0, by_status: {}, by_grade: {}, unknown: 0, unknown_by_reason: {}, run_status: 'no_run_yet' },
      findings: { rows: 0, pointers: 0, excluded_canary: 0, excluded_dismissed: 0, note: '' },
      triage: { status: 'no_run_yet', verdicts: 0, payload_unproven: 0, note: 'not wired yet' },
      headline: 'No source has run on this target.',
    },
  }, detailRouter);
  const body = await mount();
  expect(body.textContent).toContain('Nothing has been scanned on this target yet');
  expect(body.textContent).not.toContain('No pointer from');
  expect(rows()).toHaveLength(0);
});

test('a scan that found no lead says what it examined, and does not read as clean', async () => {
  serve({
    ...LIST,
    pointers: [],
    count: 0,
    total: 0,
    counts: { by_attack_class: {}, by_source: {}, by_grade: {}, by_insertion_point: {}, by_strength: {} },
  }, detailRouter);
  const body = await mount();
  expect(body.textContent).toContain('No pointer from 1764 probe rows, 415 stored findings');
  expect(body.textContent).toContain('1714 of those probe rows are unknown rather than clean');
  expect(body.textContent).not.toContain('Nothing has been scanned on this target yet');
});

test('filters that match nothing say so without claiming the corpus is empty', async () => {
  serve(LIST, detailRouter);
  const body = await mount();
  const search = document.querySelector('.modal-body input');
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(search, 'nothing-matches-this');
    search.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await settle();
  expect(body.textContent).toContain('None of the 2 pointers match these filters');
  // The coverage is still the corpus, never the filtered view.
  expect(body.textContent).toContain('186 vectors have no conclusion from any source');
});

test('a failed load says so instead of rendering an empty, clean looking screen', async () => {
  serve(null, detailRouter);
  const body = await mount();
  expect(body.textContent).toContain('Could not load pointers');
  expect(rows()).toHaveLength(0);
});

test('a pointer whose row has gone says why rather than showing the last one selected', async () => {
  serve(LIST, () => null);
  const body = await mount();
  expect(body.textContent).toContain('No pointer with that id');
});
