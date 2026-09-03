import { Card, Button, Row, Col, Spinner } from 'react-bootstrap';

// One tool that tests attack vectors.
//
// Deliberately the same shape as every other tool card in the workflow: the name linking to the
// project, one italic line saying what it does, the two numbers, and Config, Scan, Results.
//
// The card is a component rather than repeated JSX because there are thirty-two of them. Written out
// by hand that is several thousand lines in App.js, and the thirty-third gets copied from the
// thirty-second along with whatever was wrong with it.
//
// THE FIRST NUMBER IS ELIGIBLE OF TOTAL, NOT TOTAL. Two of the three XSS tools can only reach a
// query parameter: domdig navigates a browser and has no way to POST a body or fuzz a header, and
// xssFuzz calls requests.get and nothing else. Handed a header vector either one scans the query
// string, finds nothing and exits 0. Showing 71 here would promise coverage the run cannot deliver,
// and "0 findings" would then read as "nothing there" for a table that was mostly never sent.

const AttackToolCard = ({ tool, status, onConfig, onScan, onResults, disabled = false }) => {
  const eligibility = status?.eligibility;
  const scan = status?.scan;
  const running = scan?.status === 'running';

  // While a scan runs, the numbers give way to its position. The operator's standing complaint about
  // the ffuf card was that a running scan did not say which step it was on, so this says which of how
  // many rather than only that something is happening.
  //
  // The UNIT comes from the server, because it is not always a vector. A cache scan tests a URL, and
  // vectors that share one are scanned once between them, so a cache card that said "71 vectors"
  // would promise seventy-one scans and perform half that. The server counts what it will actually
  // run and names it.
  const unit = eligibility?.scan_unit || 'vector';
  const unitLabel = unit === 'URL' ? 'URLs' : 'Vectors';
  const scanCount = eligibility?.scan_count;
  const dedupes = unit !== 'vector' && scanCount !== undefined && scanCount !== eligibility?.eligible;

  const primary = running
    ? `${scan.completed_vectors}/${scan.eligible_vectors}`
    : (eligibility
      ? (dedupes ? `${scanCount}` : `${eligibility.eligible}/${eligibility.total}`)
      : '-');
  const primaryLabel = running
    ? `${unitLabel} Scanned`
    : (dedupes ? `${unitLabel} to Scan` : 'Eligible Attack Vectors');
  const secondary = running ? (scan.finding_count || 0) : (scan?.finding_count ?? 0);

  return (
    <Card className="shadow-sm h-100 text-center" style={{ minHeight: '250px' }}>
      <Card.Body className="d-flex flex-column">
        <Card.Title className="text-danger mb-3">
          <a href={tool.url} className="text-danger text-decoration-none"
            target="_blank" rel="noopener noreferrer">
            {tool.name}
          </a>
        </Card.Title>
        <Card.Text className="text-white small fst-italic">
          {tool.description}
        </Card.Text>

        {/* Metrics AND buttons share one bottom-pinned block, so the gap between the label row and
            the buttons is identical on every card in a row no matter how long the description is.
            With the metrics outside this, a two-line description shifted the numbers relative to
            the buttons on the card next to it. */}
        <div className="mt-auto">
        {status && (
          <div className="mb-3">
            <Row className="text-center align-items-center">
              <Col>
                <div className="text-danger fw-bold fs-4">
                  {running && <Spinner animation="border" size="sm" className="me-2" />}
                  {primary}
                </div>
                <div className="text-muted small card-metric-label">{primaryLabel}</div>
              </Col>
              <Col>
                <div className="text-danger fw-bold fs-4">{secondary}</div>
                <div className="text-muted small card-metric-label">Findings</div>
              </Col>
            </Row>
            {/* The insertion-point breakdown ("query, body, header only") and the dedupe note used to
                render here as small grey sublabels. Removed: they made the card's vertical size
                depend on the data, which pushed the buttons around between cards in the same row.
                Both facts are still available in the tool's results modal, which is where a number
                that needs explaining belongs. */}
            {running && scan.current_host && (
              <div className="text-muted mt-1 text-truncate" style={{ fontSize: '0.7rem' }}>
                {scan.current_host}
              </div>
            )}
          </div>
        )}
          <Row className="g-2">
            <Col>
              <Button variant="outline-danger" className="w-100" disabled={disabled}
                onClick={() => onConfig && onConfig(tool)}>Config</Button>
            </Col>
            <Col>
              <Button variant="outline-danger" className="w-100" disabled={disabled || running}
                onClick={() => onScan && onScan(tool)}>{running ? 'Scanning' : 'Scan'}</Button>
            </Col>
            <Col>
              <Button variant="outline-danger" className="w-100" disabled={disabled}
                onClick={() => onResults && onResults(tool)}>Results</Button>
            </Col>
          </Row>
        </div>
      </Card.Body>
    </Card>
  );
};

export default AttackToolCard;
