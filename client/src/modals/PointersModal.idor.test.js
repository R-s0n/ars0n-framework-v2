/* eslint-disable testing-library/no-unnecessary-act */
import { createRoot } from 'react-dom/client';
import { act } from 'react-dom/test-utils';
import { IdentityBlock } from './PointersModal';

// IDOR and RBAC-VIOLATION are ADDITIVE pointer classes. The filter, the ranked list and the detail
// header render them through the same generic path every other class uses: the label comes from
// vocabulary.class_labels / attack_class_label and the strength from strengthTone, so a no-replay
// candidate (prior_finding / unattributed) is muted, never drawn as a measurement. The one piece
// this file pins is the IDOR detail block, because it is the one place the screen could overclaim.

const IDENTITY = {
  id_location: 'path',
  object_ref: 'owner_id',
  guess_tier: 'LOW',
  guess_note: 'uuid_v4: not enumerable. A valid id must be leaked before this can be tested.',
  id_leaked: true,
  id_leak_source: 'GET /api/v1/accounts',
  known_id_value: 'edd0edb9-7562-4c9f-a5cb-5c70d5996c08',
  auth_caveat: 'The corpus shows this endpoint carried client-sent auth (an Authorization header '
    + 'or bearer). That is NOT proof the server enforces authorization on it.',
  operator_action: "Replay this request with a SECOND identity's session and diff the response "
    + 'body. If the owned object comes back unchanged, authorization is not enforced.',
  ownership_note: "This framework does not assert whether the id is yours or a third party's.",
};

beforeAll(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });

let container;
let root;

const draw = (node) => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  act(() => { root.render(node); });
  return container;
};

afterEach(() => {
  if (root) act(() => { root.unmount(); });
  if (container) container.remove();
  root = null; container = null; document.body.innerHTML = '';
});

test('the IDOR block names the id to swap and the tier, and says it is client-sent not enforced', () => {
  const text = draw(<IdentityBlock identity={IDENTITY} />).textContent;
  expect(text).toContain('edd0edb9-7562-4c9f-a5cb-5c70d5996c08');
  expect(text).toContain('id in path');
  // A uuid_v4 is a LEAD that needs a leak, not a hot finding.
  expect(text).toContain('guessability LOW');
  expect(text).toContain('id leaked by GET /api/v1/accounts');
  // THE HONESTY GUARD, on its face: auth is client-sent, never "enforced".
  expect(text).toMatch(/client-sent, not proven enforced/i);
  expect(text).not.toMatch(/authorization is enforced|enforced by the server/i);
  // The one action, and ownership left to the operator.
  expect(text).toMatch(/Replay this request with a SECOND identity/i);
  expect(text).toMatch(/does not assert whether the id is yours/i);
});

test('a HIGH tier reads hot but the block invents no id it was not given', () => {
  const text = draw(<IdentityBlock identity={{ guess_tier: 'HIGH' }} />).textContent;
  expect(text).toContain('guessability HIGH');
  expect(text).not.toContain('A real id to swap');
  expect(text).not.toMatch(/client-sent/i);
});

test('an empty identity renders the section rather than throwing', () => {
  const text = draw(<IdentityBlock identity={{}} />).textContent;
  expect(text).toContain('The object reference');
});
