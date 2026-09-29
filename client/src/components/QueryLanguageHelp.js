import { Accordion, Table } from 'react-bootstrap';

// The query-language help, shared by every screen that filters the capture corpus with the same
// grammar: the Replay Requests repeater and the Request Flows list. One copy so the two can never
// drift - a field added to the server's BuildCaptureFilter is documented in exactly one place, and
// both screens get it.
//
// onExample(query) is called when a field/operator/example is clicked, so the caller can drop it into
// its own search box (setQuery in the repeater, setFlowQuery in the flows list).

export const QUERY_FIELDS = [
  ['method', 'Request method', 'method = POST'],
  ['status', 'Response status code', 'status >= 400'],
  ['host', 'Hostname from the url', 'host ~ assurant'],
  ['domain', 'Same as host', 'domain = api.example.com'],
  ['path', 'Url path, no query string', 'path ^= /api'],
  ['url', 'The whole url', 'url ~ /admin'],
  ['query', 'The raw query string', 'query ~ redirect'],
  ['mime', 'Response mime type', 'mime ~ json'],
  ['ext', 'File extension from the path', 'ext = js'],
  ['body', 'Request body', 'body ~ password'],
  ['resp.body', 'Response body. Recorded bodies only, see the note below', 'resp.body ~ token'],
  ['size', 'Response body length in bytes. Recorded bodies only', 'size > 10000'],
  ['time', 'Request duration in milliseconds', 'time > 2000'],
  ['status_class', 'First digit of the status: 1, 2, 3, 4 or 5', 'status_class = 4'],
  ['resource_type', 'Browser resource type', 'resource_type = xhr'],
  ['initiator', 'What issued the request', 'initiator ~ main.js'],
  ['is_direct', 'On the scope target host itself: true or false', 'is_direct = true'],
  ['graphql', 'GraphQL operation name', 'graphql ~ mutation'],
  ['header.<NAME>', 'A REQUEST header, by name', 'header.cookie ~ session'],
  ['resp.header.<NAME>', 'A RESPONSE header, by name', 'resp.header.server ~ nginx'],
  ['param.<NAME>', 'A GET or POST parameter, by name', 'param.id = 5'],
  ['has:header.<NAME>', 'Presence test on a request header', 'has:header.authorization'],
  ['has:param.<NAME>', 'Presence test on a parameter', 'has:param.debug'],
];

export const QUERY_OPERATORS = [
  ['=', 'Equals, case insensitive', 'method = GET'],
  ['!=', 'Not equals', 'method != GET'],
  ['~', 'Contains, case insensitive', 'host ~ assurant'],
  ['!~', 'Does not contain', 'path !~ /static'],
  ['^=', 'Starts with', 'path ^= /api'],
  ['$=', 'Ends with', 'url $= .json'],
  ['=~', 'Matches a regular expression (RE2)', 'path =~ ^/api/v[0-9]+/'],
  ['>  <  >=  <=', 'Numeric. Valid on status, size, time and status_class', 'size >= 5000'],
];

export const QUERY_EXAMPLES = [
  ['method = POST AND status >= 400', 'Writes that the application rejected.'],
  ['host ~ assurant AND (ext = js OR ext = json)', 'Script and data files on one host.'],
  ['has:header.authorization AND NOT path ^= /static', 'Authenticated requests, minus the asset noise.'],
  ['resp.header.content-type ~ json AND size > 5000', 'Substantial JSON responses.'],
  ['header.cookie ~ session AND method != GET', 'Session-carrying requests that change state.'],
  ['login', 'A bare term. Substring match across url, method and status.'],
  ['status_class = 5 AND time > 2000', 'Server errors that were also slow.'],
  ['path =~ ^/api/v[0-9]+/ AND method != GET', 'Versioned API routes that are not reads.'],
  ['param.id = 5 OR has:param.redirect', 'Object references and redirect parameters.'],
  ['graphql ~ mutation AND resp.body ~ error', 'GraphQL mutations whose response mentioned an error.'],
  ['is_direct = true AND resource_type = xhr', 'XHR traffic on the scope target host itself.'],
  ['path = "/a b/c"', 'Double quotes for any value containing spaces.'],
];

// extra is optional screen-specific content rendered at the bottom of the accordion body, full width
// under the three columns. The Request Flows list passes the notes about how the query relates to
// flows there, so they live in this help panel instead of cluttering the narrow list column; Replay
// Requests passes nothing.
function QueryLanguageHelp({ onExample, extra }) {
  const use = (q) => { if (onExample) onExample(q); };
  return (
    <Accordion className="mb-2" data-bs-theme="dark">
      <Accordion.Item eventKey="0" className="bg-dark border-secondary">
        <Accordion.Header>
          <span className="text-danger">
            <i className="bi bi-question-circle me-2" />
            How to search: the query language
          </span>
        </Accordion.Header>
        <Accordion.Body style={{ maxHeight: '45vh', overflowY: 'auto' }}>
          <div className="row g-3">
            <div className="col-lg-5">
              <div className="text-light small fw-bold mb-1">Fields</div>
              <Table size="sm" variant="dark" borderless className="mb-0">
                <tbody>
                  {QUERY_FIELDS.map(([name, meaning, example]) => (
                    <tr key={name}>
                      <td style={{ whiteSpace: 'nowrap' }}><code className="text-danger">{name}</code></td>
                      <td className="text-white-50" style={{ fontSize: '0.75rem' }}>{meaning}</td>
                      <td>
                        <code
                          className="text-info"
                          style={{ fontSize: '0.72rem', cursor: 'pointer' }}
                          onClick={() => use(example)}
                        >
                          {example}
                        </code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>

            <div className="col-lg-3">
              <div className="text-light small fw-bold mb-1">Operators</div>
              <Table size="sm" variant="dark" borderless className="mb-3">
                <tbody>
                  {QUERY_OPERATORS.map(([symbol, meaning, example]) => (
                    <tr key={symbol}>
                      <td style={{ whiteSpace: 'nowrap' }}><code className="text-danger">{symbol}</code></td>
                      <td className="text-white-50" style={{ fontSize: '0.75rem' }}>
                        {meaning}
                        <div>
                          <code
                            className="text-info"
                            style={{ fontSize: '0.72rem', cursor: 'pointer' }}
                            onClick={() => use(example)}
                          >
                            {example}
                          </code>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>

              <div className="text-light small fw-bold mb-1">Booleans and grouping</div>
              <div className="text-white-50" style={{ fontSize: '0.75rem' }}>
                <div><code className="text-danger">AND</code>, <code className="text-danger">OR</code>,{' '}
                  <code className="text-danger">NOT</code> and parentheses.</div>
                <div className="mt-1">
                  <code className="text-danger">AND</code> is implied between adjacent terms, so{' '}
                  <code className="text-info">method = POST status &gt;= 400</code> means the same as{' '}
                  <code className="text-info">method = POST AND status &gt;= 400</code>.
                </div>
                <div className="mt-1">
                  A <strong>bare term</strong> with no field is a case insensitive substring match across
                  url, method and status. Typing <code className="text-info">login</code> matches any
                  capture whose url contains "login".
                </div>
                <div className="mt-1">
                  Use <strong>double quotes</strong> for a value containing spaces:{' '}
                  <code className="text-info">path = "/a b/c"</code>.
                </div>
              </div>
            </div>

            <div className="col-lg-4">
              <div className="text-light small fw-bold mb-1">Examples, click to use</div>
              <Table size="sm" variant="dark" borderless className="mb-0">
                <tbody>
                  {QUERY_EXAMPLES.map(([example, meaning]) => (
                    <tr key={example}>
                      <td>
                        <code
                          className="text-info"
                          style={{ fontSize: '0.73rem', cursor: 'pointer' }}
                          onClick={() => use(example)}
                        >
                          {example}
                        </code>
                        <div className="text-white-50" style={{ fontSize: '0.7rem' }}>{meaning}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <div className="text-white-50 mt-2" style={{ fontSize: '0.72rem' }}>
                A query the parser cannot read is reported under the search box with the position it
                stopped at. The previous result stays on screen, so a syntax error never looks like a
                search that matched nothing.
              </div>
              <div className="text-warning mt-2" style={{ fontSize: '0.72rem' }}>
                <i className="bi bi-info-circle me-1" />
                The manual crawl does not store a response body for every capture. A capture without
                one is excluded from <code className="text-danger">size</code> and{' '}
                <code className="text-danger">resp.body</code> entirely, including from the negative
                forms: <code className="text-info">resp.body !~ password</code> will not answer for a
                body nobody recorded. Every other field covers the whole corpus.
              </div>
            </div>
          </div>
          {extra && (
            <div className="mt-3 pt-3 border-top border-secondary">
              {extra}
            </div>
          )}
        </Accordion.Body>
      </Accordion.Item>
    </Accordion>
  );
}

export default QueryLanguageHelp;
