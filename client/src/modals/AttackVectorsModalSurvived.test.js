import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import { VectorDetail } from './AttackVectorsModal';

// THE OTHER SURVIVED RENDERER.
//
// The vector-detail table printed (p.survived || []).join(' ') || '-' in text-warning, with no
// title and no caption, so a row the probe never reached and a row that was sent and came back
// clean were the same yellow dash. survivedSummary already draws that distinction on the
// Reflection Results tab, and this pins that the detail table now goes through it too.

beforeAll(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });
afterEach(() => { document.body.innerHTML = ''; });

const probe = (over) => ({
  parameter: 'q',
  insertion_point: 'query',
  status: 'not_reflected',
  grade: 'xss_candidate_none',
  survived: [],
  content_type: 'application/json',
  http_status: 200,
  evidence_source: 'active',
  detail: '',
  ...over,
});

const vector = (probes) => ({
  id: '11111111-1111-4111-8111-111111111111',
  method: 'GET',
  domain: 'h.test',
  path: '/s',
  insertion_point: 'query',
  parameters: ['q'],
  reflection_probes: probes,
});

async function mount(probes) {
  const c = document.createElement('div');
  document.body.appendChild(c);
  const root = createRoot(c);
  await act(async () => {
    root.render(<VectorDetail vector={vector(probes)} request="" note=""
      onNoteChange={() => {}} onSaveNote={() => {}} saving={false} />);
  });
  // The Survived column is the fourth cell of each probe row.
  return [...document.querySelectorAll('tbody tr')]
    .map((tr) => tr.children[3])
    .filter(Boolean);
}

test('a blocked row and a clean row no longer read the same', async () => {
  const cells = await mount([
    probe({ parameter: 'clean', status: 'not_reflected' }),
    probe({ parameter: 'waf', status: 'blocked' }),
  ]);
  expect(cells).toHaveLength(2);

  const [clean, blocked] = cells;
  expect(clean.getAttribute('title')).toMatch(/sent and nothing came back unencoded/i);
  expect(blocked.getAttribute('title')).toMatch(/Unknown, not clean/i);
  expect(blocked.getAttribute('title')).not.toEqual(clean.getAttribute('title'));
  expect(blocked.textContent).toMatch(/not measured/i);
  expect(clean.textContent).not.toMatch(/not measured/i);
});

test('an angle bracket is coloured and captioned, a lone quote is not', async () => {
  const cells = await mount([
    probe({ parameter: 'hot', status: 'reflected_raw', survived: ['<', '>'], content_type: 'text/html' }),
    probe({ parameter: 'weak', status: 'reflected_raw', survived: ["'"] }),
  ]);
  const [markup, weak] = cells;
  expect(markup.textContent).toContain('< >');
  expect(markup.textContent).toMatch(/opens a tag/i);
  expect(markup.getAttribute('style')).toContain('rgb(220, 53, 69)');
  expect(weak.textContent).toMatch(/quotes only/i);
  expect(weak.getAttribute('style')).not.toContain('rgb(220, 53, 69)');
});
