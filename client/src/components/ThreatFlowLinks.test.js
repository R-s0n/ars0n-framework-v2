import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import ThreatFlowLinks, {
  describeFlow,
  flowKindOf,
  flowOptionLabel,
  linkWriteAction,
  DEFAULT_DETECTED_FLOW_NAME,
} from './ThreatFlowLinks';

beforeAll(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });

// Shapes copied from the live API, not invented:
//   GET /api/replay-request/{target}/flows?limit=200
//   GET /api/flow-threat-links/{target}
const DETECTED_ID = 'a57d7a76-daeb-4701-839e-1252ad8459cb~536846846~e0e9db8a-b697-4bee-b21b-dc08047c36dc';
const BUILT_ID = '7ea1c83f-6a8e-42d7-8477-04e6703a78c0';

const FLOWS = [
  {
    id: BUILT_ID,
    kind: 'built',
    name: 'IDOR probe: account details as the wrong account',
    label: 'Built from detected flow',
    host: 'app.staging-v2.tradetalk.us',
    step_count: 3,
    request_count: 3,
    started_at: '2026-09-08T01:07:18.905426Z',
  },
  {
    id: DETECTED_ID,
    kind: 'detected',
    name: DEFAULT_DETECTED_FLOW_NAME,
    label: 'GET /dashboard/overview',
    host: 'app.staging-v2.tradetalk.us',
    request_count: 406,
    started_at: '2026-09-08T00:29:26.296Z',
  },
];

const THREAT = { id: '9bdee062-db9d-4ee9-93ca-cdda86ee590a' };
const byId = FLOWS.reduce((acc, f) => { acc[f.id] = f; return acc; }, {});

const render = (props) => {
  document.body.innerHTML = '';
  const c = document.createElement('div');
  document.body.appendChild(c);
  const root = createRoot(c);
  return act(async () => {
    root.render(<ThreatFlowLinks threat={THREAT} flows={FLOWS} flowsById={byId}
      flowsTotal={FLOWS.length} {...props} />);
  });
};

const buttonNamed = (label) => [...document.body.querySelectorAll('button')]
  .find((b) => b.textContent.trim() === label);

// React listens for `input` on text controls, and the value has to go through the native setter or
// React never sees it change.
const typeInto = async (el, text) => {
  const proto = el.tagName === 'TEXTAREA'
    ? window.HTMLTextAreaElement.prototype
    : window.HTMLInputElement.prototype;
  await act(async () => {
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, text);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
};

const filterBox = () => document.body.querySelector('input[type="search"]');
const optionTexts = () => [...document.body.querySelectorAll('option')].map((o) => o.textContent);

test('a detected flow id is never treated as a UUID', () => {
  // The whole feature dies if this rule is broken: 46 of 49 flows on a real target are detected.
  expect(flowKindOf({ id: DETECTED_ID })).toBe('detected');
  expect(flowKindOf({ id: BUILT_ID })).toBe('built');
  // The server's own kind wins over the id shape, and flow_kind (the links endpoint's field name)
  // is read as well as kind (the flow list's).
  expect(flowKindOf({ id: BUILT_ID, flow_kind: 'built' })).toBe('built');
  expect(flowKindOf({ id: DETECTED_ID, kind: 'detected' })).toBe('detected');
});

test('a flow is described by name, and a placeholder name does not lead', () => {
  const built = describeFlow(FLOWS[0], null);
  expect(built.title).toBe('IDOR probe: account details as the wrong account');
  expect(built.named).toBe(true);
  expect(built.meta).toContain('3 steps');

  // All 46 detected flows carry the same placeholder name, so leading with it would make them
  // indistinguishable. The request line leads and the placeholder is demoted, not dropped.
  const detected = describeFlow(FLOWS[1], null);
  expect(detected.title).toBe('GET /dashboard/overview');
  expect(detected.detail).toBe(DEFAULT_DETECTED_FLOW_NAME);
  expect(detected.named).toBe(false);
  expect(detected.meta).toContain('406 requests');

  // Every option is distinguishable from every other one.
  const labels = FLOWS.map(flowOptionLabel);
  expect(new Set(labels).size).toBe(labels.length);
});

test('linked flows render by name and kind, never as a raw id', async () => {
  await render({
    links: [
      // Exactly what the server returns: the built link carries NO flow_name at all.
      { id: 'l1', threat_id: THREAT.id, flow_id: BUILT_ID, flow_kind: 'built' },
      { id: 'l2', threat_id: THREAT.id, flow_id: DETECTED_ID, flow_kind: 'detected',
        flow_name: DEFAULT_DETECTED_FLOW_NAME },
    ],
  });
  const text = document.body.textContent;
  expect(text).toContain('IDOR probe: account details as the wrong account');
  expect(text).toContain('GET /dashboard/overview');
  // The composite provenance string is a title attribute, never body text.
  expect(text).not.toContain(DETECTED_ID);
  expect(text).not.toContain(BUILT_ID);
  // The two kinds are told apart, because a built flow may never have been sent.
  const badges = [...document.body.querySelectorAll('span')].map((s) => s.textContent.trim());
  expect(badges).toContain('built');
  expect(badges).toContain('detected');
  expect(text).toContain('2 flows mapped');
  // Both linked, so there is nothing left to pick.
  expect(document.body.querySelector('select').textContent).toContain('Every flow is already mapped');
});

test('a link to a flow missing from the list says so instead of inventing a name', async () => {
  await render({
    flows: [],
    flowsById: {},
    flowsTotal: 0,
    links: [{ id: 'l3', threat_id: THREAT.id, flow_id: BUILT_ID, flow_kind: 'built' }],
  });
  expect(document.body.textContent).toContain('not in the current flow list');
});

test('a DETECTED link whose flow is missing warns too, despite carrying a placeholder name', async () => {
  // The regression this pins. GetFlowThreatLinks fills flow_name with "(Automated Flow Detected)"
  // for every detected link whether or not that flow is still in the list, so treating "we have a
  // title" as "we resolved the flow" declared all 46 detected rows known. A link whose flow was
  // deleted, or which sits past the fetch limit, then rendered as a bare placeholder with no host,
  // no request line and no warning - unidentifiable, and silent about being unidentifiable.
  await render({
    flows: [],
    flowsById: {},
    flowsTotal: 0,
    links: [{ id: 'l4', threat_id: THREAT.id, flow_id: DETECTED_ID, flow_kind: 'detected',
      flow_name: DEFAULT_DETECTED_FLOW_NAME }],
  });
  expect(document.body.textContent).toContain('not in the current flow list');
  expect(describeFlow(undefined, { flow_id: DETECTED_ID, flow_kind: 'detected',
    flow_name: DEFAULT_DETECTED_FLOW_NAME }).known).toBe(false);
  // A flow the list DOES resolve is still known, so the warning is not simply always on.
  expect(describeFlow(FLOWS[1], { flow_id: DETECTED_ID, flow_kind: 'detected',
    flow_name: DEFAULT_DETECTED_FLOW_NAME }).known).toBe(true);
  // And a real, operator-chosen name resolves a link on its own without the flow list.
  expect(describeFlow(undefined, { flow_id: BUILT_ID, flow_kind: 'built',
    flow_name: 'IDOR probe' }).known).toBe(true);
});

test('the picker offers both kinds and adding calls back with the flow id', async () => {
  const calls = [];
  await render({
    links: [],
    onLink: (threatId, flowId) => { calls.push(['link', threatId, flowId]); return true; },
  });
  expect(document.body.textContent).toContain('No flow is mapped to this threat yet');
  const select = document.body.querySelector('select');
  const groups = [...select.querySelectorAll('optgroup')].map((g) => g.label);
  expect(groups.some((g) => g.startsWith('Built flows (1)'))).toBe(true);
  expect(groups.some((g) => g.startsWith('Detected flows (1)'))).toBe(true);

  // Nothing picked yet, so the button cannot fire.
  expect(buttonNamed('Map flow').disabled).toBe(true);

  await act(async () => {
    Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, 'value')
      .set.call(select, DETECTED_ID);
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await act(async () => { buttonNamed('Map flow').click(); });
  expect(calls).toEqual([['link', THREAT.id, DETECTED_ID]]);
});

test('removing calls back with the same id the link carries', async () => {
  const calls = [];
  await render({
    links: [{ id: 'l1', threat_id: THREAT.id, flow_id: DETECTED_ID, flow_kind: 'detected' }],
    onUnlink: (threatId, flowId) => { calls.push(['unlink', threatId, flowId]); },
  });
  await act(async () => { buttonNamed('Remove').click(); });
  expect(calls).toEqual([['unlink', THREAT.id, DETECTED_ID]]);
});

test('a failed read of the links is not rendered as "nothing is mapped"', async () => {
  await render({ links: [], linksError: 'flow-threat links request failed: 500' });
  expect(document.body.textContent).toContain('could not be read');
  expect(document.body.textContent).not.toContain('No flow is mapped to this threat yet');
});

test('a failed read of the flow list disables mapping and says why', async () => {
  await render({ links: [], flowsError: 'flow list request failed: 500' });
  expect(document.body.textContent).toContain('nothing can be mapped right now');
  expect(document.body.querySelector('select')).toBeNull();
});

test('a truncated flow list admits it is showing a subset', async () => {
  await render({ links: [], flowsTotal: 640 });
  expect(document.body.textContent).toContain('Showing 2 of 640 flows');
});

test('a note can be written on a mapping that already exists', async () => {
  // The note is the whole value of the mapping a month later: it records WHY this sequence shows
  // this threat. Writing one must not mean removing the link and adding it back.
  const calls = [];
  await render({
    links: [{ id: 'l1', threat_id: THREAT.id, flow_id: DETECTED_ID, flow_kind: 'detected',
      flow_name: DEFAULT_DETECTED_FLOW_NAME }],
    onSetNote: (threatId, flowId, note) => { calls.push([threatId, flowId, note]); return true; },
  });
  expect(buttonNamed('Add note')).toBeTruthy();
  await act(async () => { buttonNamed('Add note').click(); });
  // The link is still there while the note is being typed: this is an edit, not a replace.
  expect(buttonNamed('Remove')).toBeTruthy();

  const box = document.body.querySelector('textarea');
  expect(box.value).toBe('');
  await typeInto(box, '  step 2 returns 200 for the other tenant  ');
  await act(async () => { buttonNamed('Save note').click(); });
  expect(calls).toEqual([[THREAT.id, DETECTED_ID, 'step 2 returns 200 for the other tenant']]);
  // Saved, so the editor closes and the row is a row again.
  expect(document.body.querySelector('textarea')).toBeNull();
});

test('an existing note opens in the editor, and the control is absent without a writer', async () => {
  await render({
    links: [{ id: 'l1', threat_id: THREAT.id, flow_id: DETECTED_ID, flow_kind: 'detected',
      note: 'the id in step 2 is the victim account' }],
    onSetNote: () => true,
  });
  expect(document.body.textContent).toContain('the id in step 2 is the victim account');
  await act(async () => { buttonNamed('Edit note').click(); });
  // OPENS ON THE STORED TEXT. Opening empty would make every correction a rewrite from scratch, and
  // a saved empty box clears the note.
  expect(document.body.querySelector('textarea').value).toBe('the id in step 2 is the victim account');

  // No writer, no control: a button that cannot do anything is worse than no button.
  await render({ links: [{ id: 'l1', threat_id: THREAT.id, flow_id: DETECTED_ID, note: 'x' }] });
  expect(buttonNamed('Edit note')).toBeUndefined();
  expect(buttonNamed('Add note')).toBeUndefined();
  expect(document.body.querySelector('textarea')).toBeNull();
});

test('a failed note save keeps the typed text instead of throwing it away', async () => {
  await render({
    links: [{ id: 'l1', threat_id: THREAT.id, flow_id: DETECTED_ID, flow_kind: 'detected' }],
    onSetNote: () => false,
  });
  await act(async () => { buttonNamed('Add note').click(); });
  await typeInto(document.body.querySelector('textarea'), 'a sentence worth keeping');
  await act(async () => { buttonNamed('Save note').click(); });
  expect(document.body.querySelector('textarea').value).toBe('a sentence worth keeping');
});

test('mapping a flow that is already mapped writes nothing, so its note survives', () => {
  // REPRODUCED LIVE before this existed: a link holding "TAB-B-NOTE-worth-keeping" came back with no
  // note at all after a single note-less POST, because the create is
  // `ON CONFLICT DO UPDATE SET note = EXCLUDED.note`.
  const stored = [{ threat_id: THREAT.id, flow_id: BUILT_ID, note: 'TAB-B-NOTE-worth-keeping' }];
  expect(linkWriteAction(stored, THREAT.id, BUILT_ID)).toBe('skip');

  // A genuinely new mapping is still written.
  expect(linkWriteAction(stored, THREAT.id, DETECTED_ID)).toBe('create');
  expect(linkWriteAction([], THREAT.id, BUILT_ID)).toBe('create');
  // Same flow, different threat: a different row, so it is a create.
  expect(linkWriteAction(stored, 'bacf95cb-23bd-4143-8ec0-075f54bfdc42', BUILT_ID)).toBe('create');

  // A FAILED READ IS NOT AN EMPTY ONE. Treating "could not find out" as "there is nothing there"
  // resolves the note to '' and overwrites it, which is the whole bug.
  expect(linkWriteAction(null, THREAT.id, BUILT_ID)).toBe('unknown');
  expect(linkWriteAction(undefined, THREAT.id, BUILT_ID)).toBe('unknown');
});

test('the picker never offers a flow that is already mapped, so a create cannot hit an existing row', async () => {
  // Why the check above has to run against a FRESH read rather than the rendered list: the only way
  // a create reaches an existing row is when the rendered list did not know about it, and then a
  // lookup in that list finds nothing and resolves the note to ''.
  await render({
    links: [{ id: 'l1', threat_id: THREAT.id, flow_id: BUILT_ID, flow_kind: 'built' }],
    onLink: () => true,
  });
  const values = [...document.body.querySelectorAll('option')].map((o) => o.value);
  expect(values).not.toContain(BUILT_ID);
  expect(values).toContain(DETECTED_ID);
});

test('the filter narrows the picker by name, request line and host', async () => {
  await render({ links: [] });
  // Two hundred options in a dropdown is not a list anybody can use, and flow 201 is not in it at
  // all, so the filter has to narrow on the three things a flow is recognised by.
  await typeInto(filterBox(), 'idor');
  expect(optionTexts().some((t) => t.includes('IDOR probe'))).toBe(true);
  expect(optionTexts().some((t) => t.includes('GET /dashboard/overview'))).toBe(false);
  expect(document.body.textContent).toContain('1 of 2 unmapped flows match');

  await typeInto(filterBox(), 'dashboard');   // the request line
  expect(optionTexts().some((t) => t.includes('GET /dashboard/overview'))).toBe(true);
  expect(optionTexts().some((t) => t.includes('IDOR probe'))).toBe(false);

  await typeInto(filterBox(), 'TRADETALK');   // the host, case-insensitively
  expect(document.body.textContent).toContain('2 of 2 unmapped flows match');

  // A filter that matches nothing says THAT, not "every flow is already mapped": the two are
  // different facts and only one of them is fixed by clearing the box.
  await typeInto(filterBox(), 'zzz');
  const select = document.body.querySelector('select');
  expect(select.textContent).toContain('No flow matches "zzz"');
  expect(select.textContent).not.toContain('Every flow is already mapped');
  expect(buttonNamed('Map flow').disabled).toBe(true);
});

test('a truncated list still says so while the filter is hiding rows', async () => {
  // The point of saying it: a flow that is missing because it was never fetched and a flow that is
  // missing because the filter excluded it look identical in an empty dropdown.
  await render({ links: [], flowsTotal: 640 });
  await typeInto(filterBox(), 'zzz');
  expect(document.body.textContent).toContain('No flow matches "zzz"');
  expect(document.body.textContent).toContain('Showing 2 of 640 flows');
  expect(document.body.textContent).toContain('past that cap');
});

test('a choice the filter has hidden cannot be mapped, and comes back when it is cleared', async () => {
  const calls = [];
  await render({ links: [], onLink: (threatId, flowId) => { calls.push(flowId); return true; } });
  const select = document.body.querySelector('select');
  await act(async () => {
    Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, 'value')
      .set.call(select, DETECTED_ID);
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  expect(buttonNamed('Map flow').disabled).toBe(false);

  // Narrowing the filter past the selection must not leave it attached to the button: mapping a flow
  // the operator can no longer see is a mapping nobody asked for.
  await typeInto(filterBox(), 'idor');
  expect(buttonNamed('Map flow').disabled).toBe(true);
  expect(document.body.querySelector('select').value).toBe('');

  // Suspended, not discarded - clearing the box does not make them find the flow again.
  await typeInto(filterBox(), '');
  expect(buttonNamed('Map flow').disabled).toBe(false);
  await act(async () => { buttonNamed('Map flow').click(); });
  expect(calls).toEqual([DETECTED_ID]);
});
