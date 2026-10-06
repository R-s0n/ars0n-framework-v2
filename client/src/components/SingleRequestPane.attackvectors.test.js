// Unit tests for the attack-vector overlay helpers wired into the Replay Requests sitemap and the
// request mirror. Pure functions only: no component render, no fetch, no fake timers. They prove the
// two things the feature cannot be wrong about - a templatized vector path matches the right concrete
// request, and highlighting a parameter name never changes a single painted byte of the request the
// operator will send (the coloured mirror sits pixel-for-pixel behind the editable textarea).

import {
  httpSegments,
  renderHttpNodes,
  pathMatchesTemplate,
  buildAttackVectorIndex,
  matchAttackVectors,
} from './SingleRequestPane';

// Flatten the React nodes renderHttpNodes returns (elements, nested elements, and bare '\n' strings)
// down to the exact text they paint. This is what must stay byte-identical whether or not a parameter
// name is highlighted.
function textOf(node) {
  if (node === null || node === undefined || node === false || node === true) return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(textOf).join('');
  if (node.props) return textOf(node.props.children);
  return '';
}

// Every element in the tree whose inline style sets a background-color - i.e. a highlight wrapper.
function highlightSpans(node, out = []) {
  if (node === null || typeof node !== 'object') return out;
  if (Array.isArray(node)) { node.forEach((n) => highlightSpans(n, out)); return out; }
  const style = node.props && node.props.style;
  if (style && style.backgroundColor) out.push(node);
  if (node.props) highlightSpans(node.props.children, out);
  return out;
}

describe('pathMatchesTemplate', () => {
  test('a {placeholder} segment matches any concrete value', () => {
    expect(pathMatchesTemplate('/a/5', '/a/{id}')).toBe(true);
  });

  test('a different segment count never matches', () => {
    expect(pathMatchesTemplate('/a/b/c', '/a/{id}')).toBe(false);
    expect(pathMatchesTemplate('/a', '/a/{id}')).toBe(false);
  });

  test('a literal path matches itself and mismatches anything else', () => {
    expect(pathMatchesTemplate('/api/v1/logo', '/api/v1/logo')).toBe(true);
    expect(pathMatchesTemplate('/api/v1/logo', '/api/v1/icon')).toBe(false);
  });

  test('trailing slashes are tolerated on either side', () => {
    expect(pathMatchesTemplate('/a/5/', '/a/{id}')).toBe(true);
    expect(pathMatchesTemplate('/a/5', '/a/{id}/')).toBe(true);
    expect(pathMatchesTemplate('/oauth/clients/abc/', '/oauth/clients/{token}')).toBe(true);
  });

  test('segment matching is case-sensitive', () => {
    expect(pathMatchesTemplate('/A/5', '/a/{id}')).toBe(false);
  });
});

describe('buildAttackVectorIndex + matchAttackVectors', () => {
  const vectors = [
    { id: 'v1', method: 'get', domain: 'www.example.com', path: '/api/v1/oauth/clients/{token}', insertion_point: 'path', parameters: ['token'] },
    { id: 'v2', method: 'POST', domain: 'www.example.com:443', path: '/api/v1/logo', insertion_point: 'body', parameters: ['logo', 'crop'] },
    { id: 'v3', method: 'GET', domain: 'api.other.com', path: '/a/{id}', insertion_point: 'path', parameters: ['id'] },
  ];
  const index = buildAttackVectorIndex(vectors);

  test('matches a templatized path by method + host', () => {
    const hits = matchAttackVectors(index, 'GET', 'www.example.com', '/api/v1/oauth/clients/abc123');
    expect(hits.map((h) => h.id)).toEqual(['v1']);
  });

  test('ignores the port on the request host and on the vector domain', () => {
    const hits = matchAttackVectors(index, 'POST', 'www.example.com:8080', '/api/v1/logo');
    expect(hits.map((h) => h.id)).toEqual(['v2']);
  });

  test('a lower-case request method is upcased before matching', () => {
    const hits = matchAttackVectors(index, 'get', 'api.other.com', '/a/42');
    expect(hits.map((h) => h.id)).toEqual(['v3']);
  });

  test('a method, host, or path mismatch yields nothing', () => {
    expect(matchAttackVectors(index, 'DELETE', 'www.example.com', '/api/v1/logo')).toEqual([]);
    expect(matchAttackVectors(index, 'GET', 'nope.example.com', '/a/42')).toEqual([]);
    expect(matchAttackVectors(index, 'GET', 'www.example.com', '/api/v1/unknown/x')).toEqual([]);
  });

  test('a null or empty index is safe and returns []', () => {
    expect(matchAttackVectors(null, 'GET', 'www.example.com', '/a/5')).toEqual([]);
    expect(matchAttackVectors(buildAttackVectorIndex([]), 'GET', 'www.example.com', '/a/5')).toEqual([]);
  });
});

describe('renderHttpNodes parameter highlight', () => {
  const RAW = 'GET /assets/logo.png HTTP/1.1\r\nHost: www.example.com\r\n\r\n';
  const segs = httpSegments(RAW);

  test('highlighting a term never changes a single painted character', () => {
    const plain = textOf(renderHttpNodes(segs, false, null));
    const lit = textOf(renderHttpNodes(segs, false, ['logo']));
    expect(lit).toBe(plain);
    // And the request line is still present and unbroken.
    expect(plain).toContain('/assets/logo.png');
  });

  test('a matching term is wrapped in a background-only highlight span', () => {
    const nodes = renderHttpNodes(segs, false, ['logo']);
    const spans = highlightSpans(nodes);
    expect(spans.length).toBeGreaterThan(0);
    // Exactly the token, nothing more.
    expect(spans.map((s) => textOf(s))).toContain('logo');
    // Background + radius ONLY - never anything that changes glyph width or line metrics, or the mirror
    // drifts out from behind the textarea.
    spans.forEach((s) => {
      const style = (s.props && s.props.style) || {};
      expect(style.backgroundColor).toBeTruthy();
      expect(style.fontWeight).toBeUndefined();
      expect(style.fontSize).toBeUndefined();
      expect(style.fontFamily).toBeUndefined();
      expect(style.letterSpacing).toBeUndefined();
      expect(style.padding).toBeUndefined();
      expect(style.margin).toBeUndefined();
      expect(style.width).toBeUndefined();
    });
  });

  test('no term, an empty list, or a non-matching term produces no highlight span', () => {
    expect(highlightSpans(renderHttpNodes(segs, false, null)).length).toBe(0);
    expect(highlightSpans(renderHttpNodes(segs, false, [])).length).toBe(0);
    expect(highlightSpans(renderHttpNodes(segs, false, ['nomatch'])).length).toBe(0);
  });
});
