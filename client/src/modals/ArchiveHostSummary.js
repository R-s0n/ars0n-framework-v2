import { Badge, Table } from 'react-bootstrap';

// Per-host outcomes for an archive run.
//
// These scans now query several hosts in one run, and without this the whole run collapses into a
// single endpoint count. That matters most when it goes partly wrong: a run where three of five
// hosts were refused still reports "success", and the only place an operator can see which three is
// here. It also answers the question the counts raise on their own, which is which host the
// endpoints actually came from.
export const ArchiveHostSummary = ({ scan }) => {
  let rows = [];
  try {
    const raw = scan?.target_results;
    if (raw) rows = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch (e) {
    // A scan from before this column existed, or a malformed blob. Showing the endpoints without
    // the breakdown is better than failing the whole modal.
    rows = [];
  }
  if (!Array.isArray(rows) || rows.length === 0) return null;

  const tone = { success: 'success', error: 'danger', skipped: 'secondary' };

  return (
    <div className="mb-3">
      <div className="d-flex align-items-center gap-2 mb-1">
        <span className="text-danger small fw-bold">HOSTS QUERIED</span>
        <span className="text-white-50" style={{ fontSize: '0.75rem' }}>
          one at a time, in this order
        </span>
      </div>
      <Table size="sm" variant="dark" className="mb-0" style={{ fontSize: '0.8rem' }}>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.host}-${i}`}>
              <td style={{ whiteSpace: 'nowrap' }}>
                {r.host}{' '}
                {r.is_direct
                  ? <Badge bg="danger">direct</Badge>
                  : <Badge bg="secondary">adjacent</Badge>}
              </td>
              <td style={{ whiteSpace: 'nowrap' }}>
                <Badge bg={tone[r.status] || 'secondary'}>{r.status}</Badge>
              </td>
              <td style={{ whiteSpace: 'nowrap' }}>{r.urls || 0} URLs</td>
              <td style={{ whiteSpace: 'nowrap' }} className="text-white-50">{r.elapsed || ''}</td>
              <td className="text-white-50" style={{ wordBreak: 'break-word' }}>{r.error || ''}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
};
