import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import VectorToolResultsModal, { stripReconstructedBanner, originOf } from './VectorToolResultsModal';

// Send to Replay: from a finding's request bytes to the repeater, loaded and NOT sent.
//
// Two things this file is guarding.
//
//   1. The bytes that travel are sendable. finding.raw_request is returned by the API with the
//      composed-request banner still on it, and those six '#' lines in front of the request line
//      make the whole thing unparseable as HTTP. Handing them over unstripped produces a repeater
//      that answers "This does not parse as an HTTP request" for a request that is fine.
//
//   2. Clicking the button sends nothing. Loaded and ready is the requirement.

const TARGET = { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' };
const TOOL = { key: 'nomore403', name: 'nomore403' };

const CAPTURED = 'GET /admin HTTP/1.1\r\nHost: app.example.com\r\nX-Real: 1\r\n\r\n';
const UNDER_BANNER = 'GET /api/v1/%2e%2e%2f_internal HTTP/1.1\nHost: app.example.com\n\n';
const BANNERED = '#### RECONSTRUCTED REQUEST, NOT CAPTURED BYTES ####\n'
  + '# nomore403 reported this finding without any request bytes, so the framework composed\n'
  + '# the request below from the attack vector the scan was aimed at.\n'
  + '# How it was built: rendered from the curl command nomore403 reported.\n'
  + '##################################################\n'
  + UNDER_BANNER;

const RESULTS = {
  scan_id: 's1',
  findings: [
    {
      id: 'captured', tool: 'nomore403', kind: 'V', kind_label: 'Bypassed',
      insertion_point: 'path', param: '', method: 'GET',
      url: 'http://app.example.com/admin', domain: 'app.example.com', vector_path: '/admin',
      raw_request: CAPTURED, raw_request_origin: 'captured', raw_response: 'HTTP/1.1 200 OK',
      triage: 'new',
    },
    {
      id: 'composed', tool: 'nomore403', kind: 'V', kind_label: 'Bypassed',
      insertion_point: 'path', param: '', method: 'GET',
      url: 'https://app.example.com/api/v1/_internal', domain: 'app.example.com',
      vector_path: '/api/v1/_internal',
      raw_request: BANNERED, raw_request_origin: 'reconstructed', raw_response: '',
      triage: 'new',
    },
    {
      id: 'nothing', tool: 'nomore403', kind: 'I', kind_label: 'Informational',
      insertion_point: 'path', param: '', method: 'GET',
      url: 'https://app.example.com/x', domain: 'app.example.com', vector_path: '/x',
      raw_request: '', raw_request_origin: 'none', raw_response: '', triage: 'new',
    },
  ],
  skipped: [], untested: [], traces: [],
};

const STATUS = { tool: 'nomore403', scan: { scan_id: 's1', status: 'completed' } };

const jsonResponse = (body) => Promise.resolve({ ok: true, json: () => Promise.resolve(body) });

beforeEach(() => {
  global.fetch = jest.fn((url) => {
    if (String(url).endsWith('/results')) return jsonResponse(RESULTS);
    if (String(url).endsWith('/status')) return jsonResponse(STATUS);
    return jsonResponse({});
  });
});

describe('the banner strip', () => {
  test('a composed request loses its banner and keeps every byte under it', () => {
    expect(stripReconstructedBanner(BANNERED)).toBe(UNDER_BANNER);
  });

  test('a captured request is returned untouched, CRLF and all', () => {
    expect(stripReconstructedBanner(CAPTURED)).toBe(CAPTURED);
  });

  test('a request whose own body contains a # line is not truncated at it', () => {
    const withHash = 'POST /x HTTP/1.1\r\nHost: h\r\n\r\n# not a banner\nvalue=1';
    expect(stripReconstructedBanner(withHash)).toBe(withHash);
  });

  test('a banner with nothing under it yields nothing, not a request made of hashes', () => {
    expect(stripReconstructedBanner('#### RECONSTRUCTED REQUEST, NOT CAPTURED BYTES ####\n# only\n'))
      .toBe('');
  });

  test('anything that is not a string is nothing', () => {
    expect(stripReconstructedBanner(undefined)).toBe('');
    expect(stripReconstructedBanner(null)).toBe('');
  });
});

describe('the origin the bytes are sent to', () => {
  test('scheme and host, and the scheme is the finding\'s own rather than assumed https', () => {
    expect(originOf('http://app.example.com/admin?q=1')).toBe('http://app.example.com');
    expect(originOf('https://app.example.com:8443/x')).toBe('https://app.example.com:8443');
  });

  test('a url that will not parse yields nothing rather than a guess', () => {
    expect(originOf('/admin')).toBe('');
    expect(originOf(undefined)).toBe('');
  });
});

describe('the button on a finding', () => {
  const open = async (props) => {
    render(
      <VectorToolResultsModal
        show handleClose={() => {}} activeTarget={TARGET} tool={TOOL} category="access-bypass"
        {...props}
      />
    );
    await waitFor(() => expect(screen.getAllByText(/Bypassed/).length).toBeGreaterThan(0));
  };

  test('one button per finding that has bytes, and none on the finding that has none', async () => {
    await open({ onSendToRepeater: () => {} });
    // Three findings, two with request bytes.
    expect(screen.getAllByRole('button', { name: /Send to Replay/ })).toHaveLength(2);
    // And the finding with nothing still explains itself, which is why the button is hidden rather
    // than rendered dead next to that explanation.
    expect(screen.getByText(/No raw exchange was captured for this finding/)).toBeInTheDocument();
  });

  test('the composed finding hands over the stripped bytes and its own origin', async () => {
    const sent = [];
    await open({ onSendToRepeater: (p) => sent.push(p) });

    fireEvent.click(screen.getAllByRole('button', { name: /Send to Replay/ })[1]);

    expect(sent).toHaveLength(1);
    expect(sent[0].raw_request).toBe(UNDER_BANNER);
    expect(sent[0].raw_request).not.toContain('####');
    expect(sent[0].base_url).toBe('https://app.example.com');
    expect(sent[0].label).toBe('nomore403 finding');
  });

  test('the captured finding hands over its bytes verbatim, on its own scheme', async () => {
    const sent = [];
    await open({ onSendToRepeater: (p) => sent.push(p) });

    fireEvent.click(screen.getAllByRole('button', { name: /Send to Replay/ })[0]);

    expect(sent[0].raw_request).toBe(CAPTURED);
    // http, because that is what the finding says. Dropping it would replay an http finding over TLS.
    expect(sent[0].base_url).toBe('http://app.example.com');
  });

  test('clicking it sends no HTTP request of any kind', async () => {
    await open({ onSendToRepeater: () => {} });
    const before = global.fetch.mock.calls.length;

    fireEvent.click(screen.getAllByRole('button', { name: /Send to Replay/ })[0]);

    // Not the replay endpoint, not anything. A results list that fired a request at a live target
    // because a button was clicked in it is the failure this test exists for.
    expect(global.fetch.mock.calls).toHaveLength(before);
    expect(global.fetch.mock.calls.some(([u]) => String(u).includes('/replay-request/send')))
      .toBe(false);
  });

  test('with no handler wired up the button is not rendered at all', async () => {
    await open({});
    expect(screen.queryByRole('button', { name: /Send to Replay/ })).not.toBeInTheDocument();
  });
});
