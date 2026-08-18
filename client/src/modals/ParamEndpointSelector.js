import { useState, useEffect, useCallback } from 'react';
import { Alert, Badge, Button, Form, Spinner } from 'react-bootstrap';

// The valid-endpoint corpus, grouped by HTTP verb, with a checkbox per endpoint for one tool.
//
// Shared by all three parameter-tool config modals rather than copied into each, because three
// copies of the same endpoint query is exactly how the Go runners drifted apart: one had no row
// cap, one capped at 50 and one at 100, and nobody noticed they were scanning different corpora.
//
// Selection is stored sparsely server-side and an absent row means enabled, so an endpoint
// consolidated after the last time this modal was opened is scanned by default rather than
// silently left out.
export const ParamEndpointSelector = ({ tool, targetId, includeScripts }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [collapsed, setCollapsed] = useState({});

  const load = useCallback(async () => {
    if (!targetId || !tool) return;
    setLoading(true);
    setError('');
    try {
      const response = await fetch(
        `/api/param-enum/${targetId}/targets?tool=${tool}&include_scripts=${includeScripts ? 'true' : 'false'}`
      );
      if (!response.ok) {
        setError('Could not load the endpoint list');
        return;
      }
      setData(await response.json());
    } catch (err) {
      setError('Could not load the endpoint list: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [targetId, tool, includeScripts]);

  useEffect(() => { load(); }, [load]);

  const post = async (body) => {
    setBusy(true);
    try {
      const response = await fetch(`/api/param-enum/${targetId}/selection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool, include_scripts: !!includeScripts, ...body }),
      });
      if (!response.ok) {
        setError('Could not save the selection');
        return;
      }
      await load();
    } catch (err) {
      setError('Could not save the selection: ' + err.message);
    } finally {
      setBusy(false);
    }
  };

  const toggleOne = (endpoint) => post({ endpoint_ids: [endpoint.id], enabled: !endpoint.enabled });
  const setGroup = (verb, enabled) => post({ all: true, verb, enabled });
  const setAll = (enabled) => post({ all: true, enabled });

  if (loading && !data) {
    return (
      <div className="text-center py-3">
        <Spinner animation="border" size="sm" variant="danger" />
      </div>
    );
  }

  if (error && !data) {
    return <Alert variant="dark" className="border border-secondary text-light py-2">{error}</Alert>;
  }

  if (!data || !data.total) {
    return (
      <Alert variant="dark" className="border border-secondary text-light py-2 small">
        No valid endpoints yet. Parameter enumeration runs against endpoints Validate confirmed as
        real, so run <strong>Consolidate</strong> and then <strong>Investigate</strong> first.
      </Alert>
    );
  }

  return (
    <div className="mb-3">
      <div className="d-flex justify-content-between align-items-center mb-2">
        <Form.Label className="text-white mb-0">
          Endpoints to scan
          <Badge bg="dark" className="ms-2 border border-secondary text-light">
            {data.enabled} of {data.total}
          </Badge>
        </Form.Label>
        <div className="d-flex gap-2">
          <Button size="sm" variant="link" className="p-0 text-danger"
                  disabled={busy} onClick={() => setAll(true)}>
            Select all
          </Button>
          <span className="text-white-50">|</span>
          <Button size="sm" variant="link" className="p-0 text-white-50"
                  disabled={busy} onClick={() => setAll(false)}>
            None
          </Button>
        </div>
      </div>

      <div className="text-white-50 small mb-2">
        {data.predicate}. {/* total_runs is not the endpoint count: Arjun scans a body endpoint
            twice, form-encoded then JSON, because an API route usually only answers the second. */}
        This scan will make <strong className="text-light">{data.total_runs}</strong> tool
        {data.total_runs === 1 ? ' pass' : ' passes'} across{' '}
        {data.groups.length} verb{data.groups.length === 1 ? '' : 's'}, run one verb at a time into a
        single result set.
      </div>

      {error && (
        <Alert variant="dark" className="border border-danger text-danger py-1 small"
               onClose={() => setError('')} dismissible>
          {error}
        </Alert>
      )}

      {data.groups.map((group) => (
        <div key={group.verb} className="border border-secondary rounded mb-2">
          <div className="d-flex justify-content-between align-items-center px-2 py-1"
               style={{ backgroundColor: '#2b2b2b' }}>
            <div className="d-flex align-items-center gap-2">
              <Button
                size="sm"
                variant="link"
                className="p-0 text-white-50"
                onClick={() => setCollapsed((c) => ({ ...c, [group.verb]: !c[group.verb] }))}
              >
                <i className={`bi bi-chevron-${collapsed[group.verb] ? 'right' : 'down'}`} />
              </Button>
              <Badge bg="dark" className={`border ${group.verb === 'GET'
                ? 'border-secondary text-light' : 'border-danger text-danger'}`}>
                {group.label}
              </Badge>
              <span className="text-white-50 small">
                {group.enabled_count} of {group.endpoints.length} selected
                {group.runs !== group.enabled_count && `, ${group.runs} passes`}
              </span>
            </div>
            <div className="d-flex gap-2">
              <Button size="sm" variant="link" className="p-0 text-danger small"
                      disabled={busy} onClick={() => setGroup(group.verb, true)}>
                All
              </Button>
              <Button size="sm" variant="link" className="p-0 text-white-50 small"
                      disabled={busy} onClick={() => setGroup(group.verb, false)}>
                None
              </Button>
            </div>
          </div>

          {!collapsed[group.verb] && (
            <div style={{ maxHeight: '260px', overflowY: 'auto' }}>
              {group.endpoints.map((endpoint) => (
                <div key={endpoint.id}
                     className="d-flex align-items-center px-2 py-1 border-top border-secondary">
                  <Form.Check
                    type="checkbox"
                    checked={endpoint.enabled}
                    disabled={busy}
                    onChange={() => toggleOne(endpoint)}
                    className="me-2"
                  />
                  <div className="flex-grow-1 text-truncate" title={endpoint.url}>
                    {/* The host is part of the identity here: most valid endpoints on a real target
                        live on an adjacent API host, not on the scope target itself. */}
                    <span className="text-white-50 small">{endpoint.host}</span>
                    <code className="text-light ms-2 small">{endpoint.path}</code>
                  </div>
                  {!endpoint.is_direct && (
                    <Badge bg="dark" className="border border-secondary text-white-50 ms-2"
                           style={{ fontSize: '0.6rem' }} title="On an adjacent host">
                      adjacent
                    </Badge>
                  )}
                  {endpoint.interest_score > 0 && (
                    <span className="text-white-50 ms-2 small" title="Investigate interest score">
                      {endpoint.interest_score}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default ParamEndpointSelector;
