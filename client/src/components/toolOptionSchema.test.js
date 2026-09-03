import {
  attributeServerMessage,
  buildSettingsPayload,
  constraintSummary,
  hazardOf,
  invalidFields,
  validateOptionValue,
} from './toolOptionSchema';

// These are the rules the two settings screens are built on, tested on their own because getting one
// of them wrong is invisible in a render test: a screen that validates nothing still renders.

describe('validateOptionValue mirrors what the server would refuse', () => {
  test('an empty field is never an error, because empty means not set', () => {
    expect(validateOptionValue({ kind: 'int', min: 1 }, '')).toBe('');
    expect(validateOptionValue({ kind: 'int', min: 1 }, undefined)).toBe('');
    expect(validateOptionValue({ kind: 'enum', choices: ['a'] }, '')).toBe('');
    expect(validateOptionValue({ kind: 'list', min_items: 2 }, [])).toBe('');
  });

  test('a number is checked against the schema min, max and wholeness', () => {
    const meta = { kind: 'int', min: 1, max: 10, unit: 'minutes' };
    expect(validateOptionValue(meta, '5')).toBe('');
    expect(validateOptionValue(meta, '0')).toMatch(/at least 1 minutes/);
    expect(validateOptionValue(meta, '11')).toMatch(/at most 10 minutes/);
    expect(validateOptionValue(meta, '1.5')).toMatch(/whole number/);
    expect(validateOptionValue(meta, 'abc')).toMatch(/number/);
  });

  // float exists precisely so that 0.5 is not truncated to 0, which for a pause between requests
  // means "no pause at all".
  test('a float keeps its fraction and is not required to be whole', () => {
    const meta = { kind: 'float', min: 0.1 };
    expect(validateOptionValue(meta, '0.5')).toBe('');
    expect(validateOptionValue(meta, '0.05')).toMatch(/at least 0.1/);
  });

  test('an enum accepts only the served choices', () => {
    const meta = { kind: 'enum', choices: ['breadth-first', 'depth-first'] };
    expect(validateOptionValue(meta, 'depth-first')).toBe('');
    expect(validateOptionValue(meta, 'sideways')).toMatch(/only: breadth-first, depth-first/);
  });

  // The measured tools with a name list DROP an unrecognised name silently and still exit 0, so a
  // typo is a coverage change with no symptom anywhere. It is an error, not a warning.
  test('a name a tool does not know is refused, not passed through', () => {
    const meta = { kind: 'list', choices: ['crtsh', 'hackertarget'] };
    expect(validateOptionValue(meta, ['crtsh'])).toBe('');
    expect(validateOptionValue(meta, ['crtsh', 'notasource'])).toMatch(/notasource is not a name/);
  });

  test('min_items counts entries, and is only checked once the list has something in it', () => {
    const meta = { kind: 'list', min_items: 1 };
    expect(validateOptionValue(meta, [])).toBe('');
    expect(validateOptionValue({ kind: 'list', min_items: 2 }, ['80'])).toMatch(/at least 2 entries/);
    expect(validateOptionValue({ kind: 'list', min_items: 2 }, ['80', '443'])).toBe('');
  });
});

describe('buildSettingsPayload', () => {
  const options = {
    aSwitch: { kind: 'bool' },
    aCount: { kind: 'int' },
    aPause: { kind: 'float' },
    aList: { kind: 'list' },
    aText: { kind: 'string' },
  };

  test('an empty field is omitted rather than sent as zero or an empty string', () => {
    expect(buildSettingsPayload(options, { aCount: '', aText: '   ', aList: [] })).toEqual({});
  });

  test('an explicit off is a real stored value, distinct from not set', () => {
    expect(buildSettingsPayload(options, { aSwitch: 'false' })).toEqual({ aSwitch: false });
    expect(buildSettingsPayload(options, { aSwitch: '' })).toEqual({});
  });

  test('int is truncated and float is not', () => {
    expect(buildSettingsPayload(options, { aCount: '7.9', aPause: '0.5' }))
      .toEqual({ aCount: 7, aPause: 0.5 });
  });
});

describe('invalidFields skips what the operator cannot edit', () => {
  test('an inert option is not allowed to block a save', () => {
    const options = { gated: { kind: 'int', min: 5 } };
    const values = { gated: '1' };
    expect(invalidFields(options, values, () => false)).toHaveProperty('gated');
    expect(invalidFields(options, values, () => true)).toEqual({});
  });
});

describe('attributeServerMessage puts the refusal on the field it names', () => {
  const options = { timeoutMinutes: {}, hostDiscoveryPorts: {}, webPorts: {} };

  test('one refusal goes to one field', () => {
    const { fields, rest } = attributeServerMessage('timeoutMinutes must be at least 1 minutes.', options);
    expect(fields.timeoutMinutes).toBe('timeoutMinutes must be at least 1 minutes.');
    expect(rest).toBe('');
  });

  test('several refusals are split across their fields', () => {
    const msg = 'hostDiscoveryPorts needs at least 1 entry. timeoutMinutes must be at least 1 minutes.';
    const { fields } = attributeServerMessage(msg, options);
    expect(fields.hostDiscoveryPorts).toBe('hostDiscoveryPorts needs at least 1 entry.');
    expect(fields.timeoutMinutes).toBe('timeoutMinutes must be at least 1 minutes.');
  });

  // The server appends the option's own caveat to its refusal, and those caveats name OTHER options.
  // A mention is not a refusal, and treating it as one would hand half of one field's message to
  // another field.
  test('an option merely mentioned inside another refusal does not steal it', () => {
    const msg = 'webPorts needs at least 1 entry. Adding a port here does not help because hostDiscoveryPorts eliminates the host one phase earlier.';
    const { fields } = attributeServerMessage(msg, options);
    expect(Object.keys(fields)).toEqual(['webPorts']);
    expect(fields.webPorts).toMatch(/hostDiscoveryPorts eliminates/);
  });

  // A refused framework-owned flag or an unknown key is about the REQUEST, not about a field on the
  // form. It has nowhere to go except the top, and losing it would leave a form that will not save
  // and will not say why.
  test('a refusal about the request keeps its place at the top', () => {
    const msg = 'Nothing reads notAnOption for Amass Intel. A stored setting nothing reads changes nothing.';
    const { fields, rest } = attributeServerMessage(msg, options);
    expect(fields).toEqual({});
    expect(rest).toBe(msg);
  });
});

// The discipline that keeps this from becoming the wall of red it replaced. Every string below is
// verbatim from server/utils, and the split between them is the operator's own: a warning is for an
// option that acts on the live estate, throws real findings away, or silently defeats another
// setting. A tradeoff, a coverage note and an unproven semantic are help text.
describe('hazardOf shows only what the SERVER declares', () => {
  // The heuristic this replaces read the English of `danger` and got 4 of 20 wrong, every one loud
  // and confident. Two of them put "Throws real findings away" on options whose own text begins
  // "NOT IMPLEMENTED", which is the exact failure the whole repair exists to undo: a broken option
  // rendered as the loudest thing on the field.
  const realCaveats = {
    'katana automaticFormFill': "katana marks it experimental, and it SUBMITS FORMS on a live company estate: on a production site that can mean created records, sent mail or triggered workflows.",
    'ip_port_scan hostDiscoveryPorts': 'A LIVE HOST ON A PORT OUTSIDE THIS LIST IS RECORDED AS DEAD AND NOTHING SAYS SO.',
    'katana concurrency': 'Raising it raises the load a single origin sees.',
    'restrictToCompanyTlds': 'NOT IMPLEMENTED. An over-narrow list silently deletes real findings.',
    'requireWhoisMatch': 'NOT IMPLEMENTED, and it depends on WHOIS data.',
    'matchSubdomains': 'A whitelist that destroys evidence when it is too narrow.',
    'katanaDepth': 'Inert unless runKatana is on, so this is the option most likely to be set by someone who then sees no change at all.',
  };

  // NONE of them is marked on prose alone, including the genuinely hazardous ones. That is the
  // point: the caveat still renders as help text either way, and a missing amber line costs an
  // operator far less than a wrong one.
  Object.entries(realCaveats).forEach(([name, danger]) => {
    test(`${name} is not marked from its prose`, () => {
      expect(hazardOf({ danger })).toBeNull();
    });
  });

  test('a server declaration is the only thing that marks a field', () => {
    expect(hazardOf({ danger: 'Ordinary tradeoff.', hazard: 'Acts on the live estate' }))
      .toMatchObject({ label: 'Acts on the live estate' });
    // The caveat text still travels with it, so the declaration adds emphasis and never replaces
    // the measured sentence.
    expect(hazardOf({ danger: 'It SUBMITS FORMS.', hazard: 'Acts on the live estate' }).text)
      .toBe('It SUBMITS FORMS.');
  });

  test('an absent, empty or non-string declaration marks nothing', () => {
    expect(hazardOf({})).toBeNull();
    expect(hazardOf({ danger: 'It SUBMITS FORMS on a live estate.' })).toBeNull();
    expect(hazardOf({ danger: 'x', hazard: '' })).toBeNull();
    expect(hazardOf({ danger: 'x', hazard: '   ' })).toBeNull();
    expect(hazardOf({ danger: 'x', hazard: false })).toBeNull();
    expect(hazardOf(null)).toBeNull();
  });
});

test('constraintSummary states the limits before a value is typed, not after one is refused', () => {
  expect(constraintSummary({ min: 1, max: 10 })).toBe('min 1, max 10');
  expect(constraintSummary({ min_items: 1 })).toBe('at least 1 entry');
  expect(constraintSummary({ min_items: 3 })).toBe('at least 3 entries');
  expect(constraintSummary({})).toBe('');
});
