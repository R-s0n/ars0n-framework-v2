import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Badge, Spinner, Alert, Form, Table } from 'react-bootstrap';

// Choosing which endpoints a GraphQL tool will scan.
//
// The requirement was to "identify any endpoint as a GraphQL endpoint", and a free-text box does not
// meet it: the endpoints are already in the database, so retyping one is both work and a chance to
// get it wrong. This lists what the target already has, ticked rather than typed, with the likely
// ones floated to the top and everything else still reachable through the filter.
//
// Nothing is marked automatically. The list is per tool by the operator's decision, so the second
// half of this component exists to stop that being invisible: an endpoint the other tools already
// hold is shown here, because otherwise this tool silently skips it.

export function appendEndpoints(current, found) {
  const existing = new Set(
    String(current || '')
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const added = found.filter((f) => !existing.has(f));
  if (added.length === 0) return current;
  const prefix = String(current || '').trim();
  return (prefix ? `${prefix}\n` : '') + added.join('\n');
}

export function removeEndpoint(current, url) {
  return String(current || '')
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((s) => s !== url)
    .join('\n');
}

function GraphQLEndpointHelper({ activeTarget, current, onAppend, onSet, category, tool }) {
  const [known, setKnown] = useState([]);
  const [candidates, setCandidates] = useState(null);
  const [loadingCandidates, setLoadingCandidates] = useState(false);
  const [filter, setFilter] = useState('');
  const [detecting, setDetecting] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const selected = useMemo(
    () => new Set(String(current || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)),
    [current],
  );

  const loadKnown = useCallback(async () => {
    if (!activeTarget) return;
    try {
      const res = await fetch(`/api/graphql/${activeTarget.id}/known-endpoints`);
      if (!res.ok) return;
      const data = await res.json();
      setKnown(data.endpoints || []);
    } catch {
      // A helper that cannot load is not worth an error banner; the field still works.
    }
  }, [activeTarget]);

  // Upload_Bypass picks REQUESTS, not endpoints. A URL is not enough to identify one: two uploads to
  // the same endpoint with different bodies are two different things to test, and the tool mutates a
  // specific saved request rather than building one from a URL.
  const picksRequests = tool === 'upload-bypass';

  const loadCandidates = useCallback(async () => {
    if (!activeTarget) return;
    setLoadingCandidates(true);
    setError('');
    try {
      const path = picksRequests
        ? `/api/misc/${activeTarget.id}/upload-candidates`
        : `/api/${category || 'graphql'}/${activeTarget.id}/candidate-endpoints`;
      const res = await fetch(path);
      if (!res.ok) throw new Error(`could not load targets (${res.status})`);
      setCandidates(await res.json());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoadingCandidates(false);
    }
  }, [activeTarget, category, picksRequests]);

  const [gitFound, setGitFound] = useState([]);
  const [denied, setDenied] = useState([]);

  const loadDenied = useCallback(async () => {
    if (!activeTarget || category !== 'access-bypass') return;
    try {
      const res = await fetch(`/api/access-bypass/${activeTarget.id}/denied-endpoints`);
      if (!res.ok) return;
      const data = await res.json();
      setDenied((data.denied || []).filter((d) => d.in_scope && d.primary));
    } catch {
      // Optional convenience; the picker below still works.
    }
  }, [activeTarget, category]);

  const loadGitFound = useCallback(async () => {
    if (!activeTarget || category !== 'exposed-git') return;
    try {
      const res = await fetch(`/api/exposed-git/${activeTarget.id}/git-endpoints`);
      if (!res.ok) return;
      const data = await res.json();
      setGitFound(data.found || []);
    } catch {
      // Optional convenience; the picker below still works.
    }
  }, [activeTarget, category]);

  useEffect(() => { loadGitFound(); }, [loadGitFound]);
  useEffect(() => { loadDenied(); }, [loadDenied]);
  useEffect(() => { if (category === 'graphql') loadKnown(); }, [loadKnown, category]);
  useEffect(() => { loadCandidates(); }, [loadCandidates]);

  const detect = async () => {
    if (!activeTarget) return;
    setDetecting(true);
    setError('');
    setResult(null);
    try {
      const res = await fetch('/api/graphql/detect-endpoints', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: activeTarget.scope_target }),
      });
      if (!res.ok) throw new Error(`detection failed (${res.status})`);
      setResult(await res.json());
    } catch (e) {
      setError(e.message);
    } finally {
      setDetecting(false);
    }
  };

  const toggle = (url) => {
    if (selected.has(url)) onSet(removeEndpoint(current, url));
    else onAppend([url]);
  };

  const visible = useMemo(() => {
    const all = candidates?.candidates || [];
    const needle = filter.trim().toLowerCase();
    const matched = needle ? all.filter((c) => (c.url || '').toLowerCase().includes(needle)) : all;
    return matched.slice(0, 60);
  }, [candidates, filter]);

  const elsewhere = known.filter((k) => !selected.has(k.url));

  return (
    <div className="mt-2">
      <div className="d-flex align-items-center gap-2 flex-wrap mb-2">
        <Badge bg={selected.size > 0 ? 'danger' : 'secondary'}>
          {picksRequests
            ? `${selected.size} request${selected.size === 1 ? '' : 's'} marked as uploads`
            : `${selected.size} endpoint${selected.size === 1 ? '' : 's'} selected for this tool`}
        </Badge>
        {category === 'graphql' && (
          <>
            <Button size="sm" variant="outline-danger" onClick={detect} disabled={!activeTarget || detecting}>
              {detecting ? <><Spinner animation="border" size="sm" /> Detecting…</> : 'Detect a GraphQL endpoint'}
            </Button>
            <span className="text-white-50" style={{ fontSize: '0.7rem' }}>
              Detection runs graphw00f against the common GraphQL paths and stops at the FIRST one that
              answers, so a second endpoint still has to be picked by hand. Nothing is added until you accept it.
            </span>
          </>
        )}
      </div>

      {error && <Alert variant="danger" className="py-1 px-2 mb-2" style={{ fontSize: '0.75rem' }}>{error}</Alert>}

      {result && (
        <div className="mb-2">
          {(result.found || []).length > 0 ? (
            <div className="d-flex align-items-center gap-2 flex-wrap">
              {(result.found || []).map((url) => (
                <Badge key={url} bg="secondary" className="text-break">{url}</Badge>
              ))}
              <Button size="sm" variant="outline-success" onClick={() => onAppend(result.found)}>
                Add {result.found.length} to this list
              </Button>
            </div>
          ) : (
            <div className="text-white-50" style={{ fontSize: '0.75rem' }}>
              graphw00f found no GraphQL on its common paths. That is not proof there is none: it only
              tried the paths it knows and stops at the first hit, and its positive test is loose, so
              pick the endpoint below if you know where it is.
            </div>
          )}
        </div>
      )}

      {category === 'access-bypass' && (
        <div className="mb-2">
          {denied.length > 0 ? (
            <>
              <div className="text-white-50 mb-1" style={{ fontSize: '0.7rem' }}>
                Endpoints on this target that already answered 401 or 403. These are the ones worth
                trying to bypass, because something is actually being denied there.
              </div>
              <div className="d-flex align-items-center gap-2 flex-wrap">
                {denied.slice(0, 12).map((d) => (
                  <Badge key={d.url} bg={selected.has(d.url) ? 'success' : 'danger'} className="text-break">
                    {d.status_code} {d.url}
                  </Badge>
                ))}
                <Button
                  size="sm"
                  variant="outline-success"
                  onClick={() => onAppend(denied.map((d) => d.url))}
                >
                  Add all {denied.length} denied
                </Button>
              </div>
            </>
          ) : (
            <div className="text-white-50" style={{ fontSize: '0.72rem' }}>
              Nothing on this target has answered 401 or 403 yet, so there is no obvious thing to
              bypass. Run the URL workflow first, or pick any endpoint below to try it anyway.
            </div>
          )}
        </div>
      )}

      {category === 'exposed-git' && (
        <div className="mb-2">
          {gitFound.length > 0 ? (
            <>
              <div className="text-white-50 mb-1" style={{ fontSize: '0.7rem' }}>
                Version control directories already found on this target. This is the handover from
                the section above: snallygaster discovers them, these tools do the work afterwards.
              </div>
              <div className="d-flex align-items-center gap-2 flex-wrap">
                {gitFound.map((g) => (
                  <Badge key={g.directory} bg={selected.has(g.directory) ? 'success' : 'danger'} className="text-break">
                    {g.directory}
                  </Badge>
                ))}
                <Button
                  size="sm"
                  variant="outline-success"
                  onClick={() => onAppend(gitFound.map((g) => g.directory))}
                >
                  Add all {gitFound.length} found
                </Button>
              </div>
            </>
          ) : (
            <div className="text-white-50" style={{ fontSize: '0.72rem' }}>
              No exposed .git found yet. Run snallygaster in Sensitive Data Leaks &amp; Exposed Secrets
              first and anything it finds appears here, or pick a directory below to try it anyway.
            </div>
          )}
        </div>
      )}

      <div className="border rounded p-2" style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
        <div className="d-flex align-items-center gap-2 mb-2">
          <Form.Control
            size="sm"
            className="custom-input"
            placeholder={picksRequests
              ? "Filter this target's captured requests, e.g. upload"
              : "Filter this target's endpoints, e.g. graphql"}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <Button size="sm" variant="outline-secondary" onClick={loadCandidates} disabled={loadingCandidates}>
            {loadingCandidates ? 'Loading…' : 'Refresh'}
          </Button>
        </div>

        {loadingCandidates ? (
          <div className="text-center py-3"><Spinner animation="border" size="sm" variant="danger" /></div>
        ) : (candidates?.candidates || []).length === 0 ? (
          <div className="text-white-50 py-2" style={{ fontSize: '0.75rem' }}>
            {picksRequests
              ? 'This target has no captured requests yet, so there is nothing to mark. Record a file '
                + 'upload with the manual crawl extension, or capture one as an attack vector, and it '
                + 'appears here.'
              : 'This target has no discovered endpoints yet, so there is nothing to pick from. Run the '
                + 'URL workflow first, or paste the endpoint into the field above.'}
          </div>
        ) : picksRequests ? (
          <>
            <Table variant="dark" size="sm" hover className="mb-1">
              <tbody>
                {visible.map((c) => (
                  <tr key={c.id}>
                    <td style={{ width: '2rem' }}>
                      <Form.Check
                        type="checkbox"
                        checked={selected.has(c.id)}
                        disabled={!c.markable}
                        onChange={() => toggle(c.id)}
                      />
                    </td>
                    <td className="text-break">
                      <code style={{ fontSize: '0.75rem' }}>{c.method} {c.url}</code>
                      {c.looks_like_upload && <Badge bg="danger" className="ms-2">looks like an upload</Badge>}
                      <div style={{ fontSize: '0.68rem' }} className={c.markable ? 'text-white-50' : 'text-warning'}>
                        {c.hint}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
              Showing {visible.length} of {candidates.count}. Mark the requests that upload a file.
              Upload_Bypass mutates a request that ALREADY WORKS, so pick one you know succeeds: every
              technique it has is a change to a working upload. Requests it cannot rewrite are greyed
              out, because running one would report a bypass for a file it never altered.
            </div>
          </>
        ) : (
          <>
            <Table variant="dark" size="sm" hover className="mb-1">
              <tbody>
                {visible.map((c) => (
                  <tr key={c.url}>
                    <td style={{ width: '2rem' }}>
                      <Form.Check
                        type="checkbox"
                        checked={selected.has(c.url)}
                        onChange={() => toggle(c.url)}
                      />
                    </td>
                    <td className="text-break">
                      <code style={{ fontSize: '0.75rem' }}>{c.url}</code>
                      {c.likely && <Badge bg="danger" className="ms-2">likely</Badge>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
              Showing {visible.length} of {candidates.count}
              {candidates.truncated && ' (capped)'}. Likely ones are listed first, but that is only an
              ordering hint: mark whichever endpoint you know speaks GraphQL.
            </div>
          </>
        )}
      </div>

      {category === 'graphql' && elsewhere.length > 0 && (
        <div className="mt-2">
          <div className="text-white-50" style={{ fontSize: '0.7rem' }}>
            Marked in another tool but not here, so this tool will skip it:
          </div>
          <div className="d-flex align-items-center gap-2 flex-wrap mt-1">
            {elsewhere.map((k) => (
              <Badge key={k.url} bg="warning" text="dark" className="text-break">
                {k.url} <span style={{ opacity: 0.7 }}>({k.tools.join(', ')})</span>
              </Badge>
            ))}
            <Button
              size="sm"
              variant="outline-secondary"
              onClick={() => onAppend(elsewhere.map((k) => k.url))}
            >
              Add all
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export default GraphQLEndpointHelper;
