import { Modal, Button, Form, Spinner, Alert, Nav, Badge } from 'react-bootstrap';
import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import GraphQLEndpointHelper, { appendEndpoints } from './GraphQLEndpointHelper';
import {
  reflectionBadge, vectorReflectionStatus, byReflectionInterest, isReflecting,
  gradeCounts, REFLECTION_FILTERS, matchesReflectionFilter, GRADE_WHY,
} from '../data/reflectionGrades';

// One XSS tool's settings, for one target.
//
// THE FORM IS GENERATED FROM THE SERVER'S VOCABULARY. Nothing in this file lists a flag: the
// controls, their types, their groups and their placeholder text all arrive from
// GET /xss/{id}/{tool}/settings, which serves the same option map the command composer reads and the
// same store manage_xss writes. A hand-written form would be a second copy of that list, and the two
// only have to disagree once for an operator to set something here that no scan ever reads.
//
// That shared store is also why a change made here is visible to the MCP server immediately, and the
// other way round. There is one copy, not a UI copy and an agent copy.

const ACCENT = '#dc3545';

const POINT_LABEL = {
  query: 'query', body: 'body', header: 'header', cookie: 'cookie', path: 'path',
  // Never sent, so only a browser-driven tool can reach it. domdig is the only one here that can.
  fragment: 'fragment',
};

// The vector list is a tab like any settings group, but it is not a settings group, so it needs a key
// the server can never send. The server's groups are human labels like "Scan modes".
const VECTORS_TAB = '__vectors__';

// What the reflection probe found for one vector, as a word and a colour in that order.
//
// Drawn from the shared vocabulary in data/reflectionGrades.js rather than from a local map, so the
// vector list, this selection screen and the card on the workflow page cannot end up calling the
// same status two different things. The title is always the full explanation: an operator hovering
// "Blocked" has to be able to learn that blocked means UNKNOWN rather than clean without leaving
// the screen they are making the selection on.
const ReflectionBadge = ({ vector, size }) => {
  const b = reflectionBadge(vector);
  return (
    <span
      title={b.why}
      style={{
        display: 'inline-block',
        flexShrink: 0,
        fontSize: size === 'sm' ? '0.6rem' : '0.68rem',
        lineHeight: 1.4,
        padding: '0 0.4em',
        borderRadius: '0.25rem',
        border: `1px solid ${b.border}`,
        background: b.background,
        color: b.color,
        whiteSpace: 'nowrap',
      }}
    >
      {b.label}
    </span>
  );
};

// Which of this target's attack vectors THIS tool is aimed at.
//
// The same shape as ParamEndpointSelector, for the same reason: selection is stored sparsely and an
// absent row means selected, so a vector consolidated after the last time this modal was opened is
// scanned by default rather than silently dropped. Selection is PER TOOL, so switching a vector off
// here leaves every other scanner still testing it.
//
// TWO COUNTS, NOT ONE. `selected` is what the operator chose; `eligible` is what will actually be
// sent, and it is always the smaller of the two because no tool can reach every insertion point. A
// screen that showed only `selected` would let an operator read a clean result for 215 vectors when
// 78 were tested, which is the failure this whole surface exists to prevent.
export const VectorSelector = ({ category, targetId, tool, toolName, scanUnit, onCoverage }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [collapsed, setCollapsed] = useState({});
  // Reflection filter and sort. Both default to off, so the list an operator has learned the shape
  // of does not rearrange itself the first time a probe runs; the controls say what they will do
  // and the counts beside them say whether pressing one is worth it.
  const [reflectionFilter, setReflectionFilter] = useState('');
  const [reflectionFirst, setReflectionFirst] = useState(false);

  // Held in a ref rather than named in load's dependency array. The parent passes this to keep the
  // eligibility panel on the settings tabs in step with a selection change, and a callback that is a
  // dependency refetches the whole list on every render of the parent.
  const onCoverageRef = useRef(onCoverage);
  useEffect(() => { onCoverageRef.current = onCoverage; }, [onCoverage]);

  const load = useCallback(async () => {
    if (!targetId || !tool) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/${category}/${targetId}/${tool}/selection`);
      if (!res.ok) {
        setError('Could not load the attack vector list');
        return;
      }
      const body = await res.json();
      setData(body);
      if (onCoverageRef.current) {
        onCoverageRef.current({ eligible: body.eligible, total: body.total });
      }
    } catch (err) {
      setError('Could not load the attack vector list: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [category, targetId, tool]);

  useEffect(() => { load(); }, [load]);

  // Reloaded rather than patched from the POST's counts, because switching a vector off REWRITES the
  // reasons: the deselection reason takes precedence over the capability reason underneath it, and a
  // list that kept the old text would explain the row with a fact that is no longer the decisive one.
  const post = async (body) => {
    setBusy(true);
    setError('');
    try {
      const res = await fetch(`/api/${category}/${targetId}/${tool}/selection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
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

  const toggleOne = (v) => post({ vector_ids: [v.vector_id], enabled: !v.selected });
  const setAll = (enabled) => post({ all: true, enabled });
  // Named ids, not all:true with a filter, because the server resolves all:true against every vector
  // this tool has. A group action has to say which vectors it means or it acts on the whole table.
  const setGroup = (group, enabled) =>
    post({ vector_ids: group.items.map((v) => v.vector_id), enabled });

  const allVectors = useMemo(() => (data && data.vectors) || [], [data]);

  // How many of THIS TOOL'S vectors the probe found reflecting, and how many it could not answer
  // for. Counted over the tool's own list rather than read from a target-wide figure: a tool that
  // only sources query vectors must not be told there are 12 candidates when 9 of them are body.
  const reflection = useMemo(() => {
    const counts = gradeCounts(allVectors);
    const probed = allVectors.filter((v) => vectorReflectionStatus(v) !== 'not_probed').length;
    const blocked = allVectors.filter((v) => vectorReflectionStatus(v) === 'blocked').length;
    const reflectingIds = allVectors.filter(isReflecting).map((v) => v.vector_id);
    return { counts, probed, blocked, reflectingIds };
  }, [allVectors]);

  // Deselect everything, then select the reflecting ids, as two requests with ONE reload at the
  // end. Running it through post() twice would reload between them and repaint the whole list as
  // empty for a moment, which reads as the action having wiped the selection.
  const selectOnlyReflecting = async () => {
    if (!reflection.reflectingIds.length) return;
    setBusy(true);
    setError('');
    try {
      const url = `/api/${category}/${targetId}/${tool}/selection`;
      const send = (body) => fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const off = await send({ all: true, enabled: false });
      if (!off.ok) {
        setError('Could not clear the selection');
        return;
      }
      const on = await send({ vector_ids: reflection.reflectingIds, enabled: true });
      if (!on.ok) {
        // Said plainly, because the target state after a failure here is EVERYTHING DESELECTED,
        // which would otherwise look like a scan configured to send nothing.
        setError('Cleared the selection but could not select the reflecting vectors. Nothing is selected right now.');
        return;
      }
      await load();
    } catch (err) {
      setError('Could not apply the reflecting selection: ' + err.message);
    } finally {
      setBusy(false);
    }
  };

  const groups = useMemo(() => {
    const order = [];
    const byPoint = new Map();
    allVectors.forEach((v) => {
      const point = v.insertion_point || 'unknown';
      if (!byPoint.has(point)) {
        byPoint.set(point, []);
        order.push(point);
      }
      byPoint.get(point).push(v);
    });
    const built = order.map((point) => {
      const items = byPoint.get(point);
      // `shown` is what gets rendered; `items` stays the WHOLE group so the header keeps reporting
      // the real selected and eligible counts. A filter that also changed those numbers would let
      // an operator read "3 of 3 selected" on a group of ninety.
      let shown = items.filter((v) => matchesReflectionFilter(v, reflectionFilter));
      if (reflectionFirst) shown = shown.slice().sort(byReflectionInterest);
      return {
        point,
        items,
        shown,
        selected: items.filter((v) => v.selected).length,
        eligible: items.filter((v) => v.eligible).length,
        best: items.length ? [...items].sort(byReflectionInterest)[0] : null,
      };
    });
    if (!reflectionFirst) return built;
    // Groups are ordered by their most interesting row when the sort is on, so the insertion point
    // holding an XSS High candidate is the one at the top of the screen rather than whichever point
    // the server happened to emit first.
    return built.slice().sort((a, b) => {
      if (!a.best || !b.best) return 0;
      return byReflectionInterest(a.best, b.best);
    });
  }, [allVectors, reflectionFilter, reflectionFirst]);

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
    // AN EMPTY TABLE HAS TWO CAUSES AND ONLY ONE OF THEM IS THE OPERATOR'S TO FIX.
    //
    // Measured on 1e9b4bec: that target has 215 consolidated vectors, and nomore403, graphql-cop,
    // snallygaster, git-dumper and gittools still return total 0, because they do not source targets
    // from the vector table at all. nomore403 works from the 4xx responses, graphql-cop from the
    // discovered GraphQL endpoints, git-dumper from repositories. Telling that operator to
    // "consolidate endpoints first" sends them to redo work already done, and promising that every
    // vector it produces "will be selected for nomore403" is a promise the backend never keeps.
    //
    // scan_unit is the signal, and it comes from the settings payload the parent already holds: a
    // tool measured in URLs, endpoints or repositories is not measured in vectors.
    const emptyName = toolName || tool;
    const scansVectors = !scanUnit || scanUnit === 'vector';
    return (
      <Alert variant="dark" className="border border-secondary text-light py-2 small">
        {scansVectors ? (
          <>
            No attack vectors yet for this target. Consolidate endpoints and build the attack vector
            table first, and every vector it produces will be selected for {emptyName} by default.
          </>
        ) : (
          <>
            {emptyName} does not choose its targets from the attack vector table. It scans by{' '}
            {scanUnit}, and builds that list itself, so there is nothing to pick here and
            consolidating more endpoints will not add anything to this tab. What it will scan is
            decided on its own settings tabs.
          </>
        )}
      </Alert>
    );
  }

  const gap = data.selected_but_unreachable || 0;
  const switchedOff = data.total - data.selected;
  const name = toolName || data.tool_name || tool;
  const unreachable = data.unreachable || [];

  return (
    <div>
      {/* THE HEADER IS THE POINT. Both counts and the distance between them, in that order: what
          will actually be sent, then what was chosen, then how many chosen vectors this tool cannot
          reach. Reading only the second number is how a scan comes back believed to have covered
          everything. */}
      <div className="mb-3 p-3 rounded" style={{ background: 'rgba(255,255,255,0.03)' }}>
        <div className="d-flex align-items-baseline gap-2 flex-wrap">
          <span className="text-white" style={{ fontSize: '1.5rem', fontWeight: 600, lineHeight: 1 }}>
            {data.eligible}
          </span>
          <span className="text-white" style={{ fontSize: '0.95rem' }}>
            {`of ${data.total} vectors will be scanned`}
          </span>
          {(data.reachable || []).map((p) => (
            <Badge key={p} bg="dark" className="text-white-50 border border-secondary">
              {POINT_LABEL[p] || p}
            </Badge>
          ))}
        </div>

        <div className="mt-2" style={{ fontSize: '0.8rem' }}>
          <span className="text-white-50">
            {data.selected} of {data.total} selected
            {switchedOff > 0
              ? `, ${switchedOff} switched off here.`
              : '.'}
          </span>{' '}
          {/* "will not be sent" rather than "is unreachable", because the two are not the same and
              the rows below know the difference: Dalfox CAN reach a body insertion point and simply
              does not by default, so calling those 137 vectors unreachable would contradict the
              reason printed under each one and talk an operator out of the setting that fixes it. */}
          {gap > 0 ? (
            <span style={{ color: '#ffc107' }}>
              {gap} selected {gap === 1 ? 'vector' : 'vectors'} will not be sent by {name}. Each one
              below says why.
            </span>
          ) : (
            <span className="text-white-50">Every selected vector will be sent.</span>
          )}
        </div>

        {data.limitation && (
          <div className="text-white-50 mt-2" style={{ fontSize: '0.78rem' }}>
            {data.limitation}
          </div>
        )}
        {/* Said out loud because Save sits in the footer of this modal and belongs to the settings
            form. Without this, a checkbox ticked here looks like it is waiting on that button. */}
        <div className="text-white-50 mt-2" style={{ fontSize: '0.72rem' }}>
          Each change here is saved as you make it, for {name} only. Every other tool keeps its own
          selection.
        </div>

        {/* WHAT THE REFLECTION PROBE FOUND, on the screen where the run is aimed.
            This is the point of the whole feature: the operator choosing what to scan sees which
            vectors already put a canary back into a response before they spend the budget.

            The unprobed case gets its own sentence rather than a row of zeroes. Zeroes here would
            read as "nothing reflects", and the truth is that nothing has been asked. */}
        <div className="mt-3 pt-2" style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}>
          {reflection.probed === 0 ? (
            <div className="text-white-50" style={{ fontSize: '0.78rem' }}>
              No reflection probe has run against these vectors. Every row below reads{' '}
              <strong>Not Probed</strong>, which means unknown, not clean. Run{' '}
              <strong>Investigate</strong> on the Consolidate Attack Vectors card to fill this
              in, then come back and aim {name} at what answered.
            </div>
          ) : (
            <div className="d-flex align-items-center gap-3 flex-wrap" style={{ fontSize: '0.8rem' }}>
              <span style={{ color: '#dc3545', fontWeight: 600 }}>
                {reflection.counts.xss_candidate_high} XSS High
              </span>
              {/* Its own count, not folded into XSS Low. The two have different next moves:
                  low needs a content type you can move, chain needs the write primitive. */}
              <span style={{ color: '#a98eda' }}>
                {reflection.counts.xss_candidate_chain ?? 0} Needs a Chain
              </span>
              <span style={{ color: '#ffc107' }}>
                {reflection.counts.xss_candidate_low} XSS Low
              </span>
              <span className="text-white-50">
                {reflection.counts.xss_candidate_none} no candidate
              </span>
              {/* Blocked is pulled out of the unknown bucket because it is a fact about the TARGET,
                  not an absence of work: something rejected the probe, so those vectors are the
                  ones this tool is most likely to be lied to about as well. */}
              {reflection.blocked > 0 && (
                <span style={{ color: '#fd7e14' }} title="The target rejected the probe on these, so whether they reflect is unknown. A payload carrying an angle bracket is exactly what a WAF drops.">
                  {reflection.blocked} blocked by the target
                </span>
              )}
              <span className="text-white-50">
                {reflection.counts.xss_unknown} unknown
              </span>
            </div>
          )}

          <div className="d-flex align-items-center gap-2 flex-wrap mt-2">
            <Form.Select
              size="sm"
              style={{ width: 'auto' }}
              data-bs-theme="dark"
              value={reflectionFilter}
              onChange={(e) => setReflectionFilter(e.target.value)}
              aria-label="Filter the list by what the reflection probe found"
            >
              <option value="">Any reflection result</option>
              {REFLECTION_FILTERS.map((f) => (
                <option key={f.key} value={f.key}>{f.label}</option>
              ))}
            </Form.Select>
            <Form.Check
              type="switch"
              id={`reflection-first-${tool}`}
              className="text-white-50"
              style={{ fontSize: '0.78rem' }}
              label="Reflecting first"
              checked={reflectionFirst}
              onChange={(e) => setReflectionFirst(e.target.checked)}
              title="Order the insertion points, and the rows inside them, by what the probe found. XSS High floats to the top."
            />
            {/* One click, and it says exactly how many it will end up with. Disabled with a reason
                rather than hidden, so an operator who came here for it learns why it is not
                available instead of hunting for a button that was never drawn. */}
            <Button
              size="sm"
              variant="outline-danger"
              disabled={busy || reflection.reflectingIds.length === 0}
              onClick={selectOnlyReflecting}
              title={reflection.reflectingIds.length === 0
                ? 'No vector on this tool reflected a canary raw, so this would deselect everything.'
                : `Deselects every vector, then selects the ${reflection.reflectingIds.length} that reflected a canary raw. ${GRADE_WHY.xss_candidate_low}`}
            >
              Select only reflecting ({reflection.reflectingIds.length})
            </Button>
          </div>
        </div>
      </div>

      <div className="d-flex justify-content-between align-items-center mb-2">
        <Form.Label className="text-white mb-0" style={{ fontSize: '0.85rem', fontWeight: 600 }}>
          Vectors to scan with {name}
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

      {error && (
        <Alert variant="dark" className="border border-danger text-danger py-1 small"
               onClose={() => setError('')} dismissible>
          {error}
        </Alert>
      )}

      {/* A filter that matched nothing says so. Without this the screen goes blank below the
          controls and reads as a failed load rather than as a filter doing its job. */}
      {reflectionFilter && groups.every((g) => g.shown.length === 0) && (
        <Alert variant="dark" className="border border-secondary text-white-50 py-2 small">
          No vector on {name} matches that reflection result.
        </Alert>
      )}

      {/* The vector rows, fenced off from the controls above them.
          data-testid, not a class: the checkboxes in here are the per-vector ones and the ones
          above are settings, and a test that asked the whole screen for "every checkbox" counted
          the Reflecting-first switch as a vector the moment it was added. What those tests are
          about is WHICH VECTOR has a live control, so they ask this list rather than the page. */}
      <div data-testid="vector-rows">
      {groups.map((group) => {
        const pointIsUnreachable = unreachable.includes(group.point);
        if (reflectionFilter && group.shown.length === 0) return null;
        const reflectingHere = group.items.filter(isReflecting).length;
        return (
          <div key={group.point} className="border border-secondary rounded mb-2">
            <div className="d-flex justify-content-between align-items-center px-2 py-1"
                 style={{ backgroundColor: '#2b2b2b' }}>
              <div className="d-flex align-items-center gap-2 flex-wrap">
                <Button
                  size="sm"
                  variant="link"
                  className="p-0 text-white-50"
                  onClick={() => setCollapsed((c) => ({ ...c, [group.point]: !c[group.point] }))}
                >
                  <i className={`bi bi-chevron-${collapsed[group.point] ? 'right' : 'down'}`} />
                </Button>
                <Badge bg="dark" className={`border ${pointIsUnreachable
                  ? 'border-secondary text-white-50' : 'border-danger text-danger'}`}>
                  {POINT_LABEL[group.point] || group.point}
                </Badge>
                <span className="text-white-50 small">
                  {`${group.selected} of ${group.items.length} selected, ${group.eligible} will be scanned`}
                </span>
                {/* Counted over the whole group, not over what the filter left visible, so the
                    number does not shrink as the operator narrows the list. */}
                {reflectingHere > 0 && (
                  <span className="small" style={{ color: '#dc3545' }}>
                    {reflectingHere} reflecting
                  </span>
                )}
                {reflectionFilter && group.shown.length !== group.items.length && (
                  <span className="text-white-50 small">
                    showing {group.shown.length}
                  </span>
                )}
                {/* Stated on the group as well as on each row, because after a Deselect all every
                    row explains itself with the deselection and the tool's own limit would vanish
                    from the screen entirely. */}
                {pointIsUnreachable && (
                  <span className="small" style={{ color: '#ffc107' }}>
                    {name} cannot reach a {POINT_LABEL[group.point] || group.point} insertion point
                  </span>
                )}
              </div>
              <div className="d-flex gap-2">
                <Button size="sm" variant="link" className="p-0 text-danger small"
                        disabled={busy} onClick={() => setGroup(group, true)}>
                  All
                </Button>
                <Button size="sm" variant="link" className="p-0 text-white-50 small"
                        disabled={busy} onClick={() => setGroup(group, false)}>
                  None
                </Button>
              </div>
            </div>

            {!collapsed[group.point] && (
              <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                {group.shown.map((v) => {
                  // Ineligible for two very different reasons, and they must not look alike. The
                  // operator's own switch is theirs to undo from here, so it keeps a live checkbox.
                  // A vector the TOOL cannot reach is not undone by any checkbox on this screen, so
                  // it does not get one: a live control that changes nothing is a lie about what is
                  // being scanned.
                  const lockedByTool = !v.eligible && !v.deselected_by_operator;
                  return (
                    <div key={v.vector_id}
                         className="d-flex align-items-start px-2 py-1 border-top border-secondary"
                         style={{ opacity: lockedByTool ? 0.85 : 1 }}>
                      {lockedByTool ? (
                        <span
                          className="me-2 d-inline-block text-center text-white-50"
                          style={{ width: '1em', flexShrink: 0 }}
                          title={`${name} will not send this vector as configured, so a checkbox here would change nothing. The reason beside it says what would.`}
                        >
                          <i className="bi bi-slash-circle" />
                        </span>
                      ) : (
                        <Form.Check
                          type="checkbox"
                          checked={v.selected}
                          disabled={busy}
                          onChange={() => toggleOne(v)}
                          className="me-2"
                          aria-label={`${v.method} ${v.url}`}
                        />
                      )}
                      <div className="flex-grow-1" style={{ minWidth: 0 }}>
                        <div className="text-truncate" title={v.url}>
                          <span className="text-white-50 small">{v.method}</span>
                          <code className="text-light ms-2 small">{v.url}</code>
                        </div>
                        {v.parameters && (
                          <div className="text-white-50 text-truncate" style={{ fontSize: '0.7rem' }}>
                            {v.parameters}
                          </div>
                        )}
                        {/* Shown for BOTH kinds. The server writes these for the operator to read,
                            and the colour is what says which kind this is. */}
                        {v.reason && (
                          <div style={{
                            fontSize: '0.7rem',
                            lineHeight: 1.4,
                            color: lockedByTool ? 'rgba(255,193,7,0.75)' : 'rgba(255,255,255,0.5)',
                          }}>
                            {v.reason}
                          </div>
                        )}
                        {/* The content type is what decides High from Low, so it is printed rather
                            than left inside a tooltip: application/json beside a raw reflection is
                            the whole explanation for why that row is not the one to chase. */}
                        {v.reflection_content_type
                          && vectorReflectionStatus(v).startsWith('reflected_') && (
                          <div className="text-white-50" style={{ fontSize: '0.68rem' }}>
                            answered {v.reflection_content_type}
                          </div>
                        )}
                      </div>
                      {/* Ahead of the eligibility badges, because this one says whether the vector
                          is worth sending and those say whether it will be. */}
                      <span className="ms-2 d-flex align-items-center" style={{ flexShrink: 0 }}>
                        <ReflectionBadge vector={v} size="sm" />
                      </span>
                      {lockedByTool && (
                        <Badge bg="dark" className="border border-warning ms-2"
                               style={{ fontSize: '0.6rem', color: '#ffc107', flexShrink: 0 }}>
                          not sent
                        </Badge>
                      )}
                      {v.deselected_by_operator && (
                        <Badge bg="dark" className="border border-secondary text-white-50 ms-2"
                               style={{ fontSize: '0.6rem', flexShrink: 0 }}>
                          switched off
                        </Badge>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
      </div>

      {data.note && (
        <div className="text-white-50 mt-3" style={{ fontSize: '0.75rem' }}>{data.note}</div>
      )}
    </div>
  );
};

function VectorToolConfigModal({ show, handleClose, activeTarget, tool, category, onSaved}) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [meta, setMeta] = useState({});
  const [groups, setGroups] = useState([]);
  const [eligibility, setEligibility] = useState(null);
  const [note, setNote] = useState('');
  const [tab, setTab] = useState('');
  // Held as strings while editing, so a half-typed number is not coerced under the operator's
  // cursor. Converted on save, which is also where empty means "not set" rather than zero.
  const [values, setValues] = useState({});
  // Anything the server sent that this modal has no metadata for. Carried through a save untouched:
  // this form saves with replace, so without it, opening the modal and pressing Save would DELETE a
  // key set through manage_xss simply because the modal never drew it.
  const [carried, setCarried] = useState({});
  // What jwt_tool found for itself. No other tool in the framework picks its own targets, so this is
  // the only place an operator can see what a run is about to attack.
  const [foundTokens, setFoundTokens] = useState(null);

  const toolKey = tool?.key;

  const load = useCallback(async () => {
    if (!activeTarget || !toolKey) return;
    setLoading(true);
    setError('');
    setNotice('');
    try {
      const res = await fetch(`/api/${category}/${activeTarget.id}/${toolKey}/settings`);
      if (!res.ok) {
        setError(`Could not load the ${tool?.name || toolKey} settings for this target.`);
        return;
      }
      const data = await res.json();
      const options = data.options || {};
      setMeta(options);
      setGroups(data.groups || []);
      setEligibility(data.eligibility || null);
      setNote(data.note || '');
      // The vector tab survives a reload the same way a settings group does, and it is the fallback
      // when a tool has no settings at all rather than leaving the modal on no tab.
      setTab((prev) => (prev === VECTORS_TAB || (data.groups || []).includes(prev)
        ? prev
        : (data.groups || [])[0] || VECTORS_TAB));

      const asText = {};
      const keep = {};
      Object.entries(data.settings || {}).forEach(([k, v]) => {
        if (!options[k]) { keep[k] = v; return; }
        if (typeof v === 'boolean') { asText[k] = v; return; }
        // A repeatable option is stored as an array and edited as one value per line, because that
        // is the only shape in which a value containing a comma survives the round trip.
        asText[k] = Array.isArray(v) ? v.join('\n') : String(v);
      });
      setValues(asText);
      setCarried(keep);
    } catch (err) {
      setError('Could not load these settings: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [activeTarget, toolKey, tool, category]);

  useEffect(() => { if (show) load(); }, [show, load]);

  useEffect(() => {
    if (!show || toolKey !== 'jwt-tool' || !activeTarget) return;
    (async () => {
      try {
        const res = await fetch(`/api/misc/${activeTarget.id}/found-jwts`);
        if (res.ok) setFoundTokens(await res.json());
      } catch {
        // The list is explanatory; the settings form works without it.
      }
    })();
  }, [show, toolKey, activeTarget]);

  const setValue = (key, v) => setValues((prev) => ({ ...prev, [key]: v }));

  // A selection change moves the coverage number the settings tabs report, and that panel was
  // fetched when the modal opened. Patched rather than reloaded, because reloading would also
  // replace the form and take any unsaved edit with it. Identity is stable and the update is a
  // no-op when nothing moved, so this cannot drive the child into a refetch loop.
  const applyCoverage = useCallback(({ eligible, total }) => {
    setEligibility((prev) => {
      if (!prev || (prev.eligible === eligible && prev.total === total)) return prev;
      return { ...prev, eligible, total };
    });
  }, []);

  const save = async () => {
    if (!activeTarget || !toolKey) return;
    setSaving(true);
    setError('');
    setNotice('');
    try {
      const payload = { ...carried };
      Object.entries(values).forEach(([key, raw]) => {
        const m = meta[key];
        if (!m) return;
        if (m.kind === 'bool') {
          if (raw === true) payload[key] = true;
          return;
        }
        const text = String(raw ?? '').trim();
        if (text === '') return;
        if (m.repeatable) {
          const items = text.split('\n').map((s) => s.trim()).filter(Boolean);
          if (items.length) payload[key] = items;
          return;
        }
        if (m.kind === 'int') { payload[key] = parseInt(text, 10); return; }
        if (m.kind === 'float') { payload[key] = parseFloat(text); return; }
        payload[key] = text;
      });

      // replace, not merge: this form has just shown every field, so it IS the whole state. Merging
      // would make a field the operator cleared indistinguishable from one they never touched.
      const res = await fetch(`/api/${category}/${activeTarget.id}/${toolKey}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings: payload, replace: true }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.message || 'Could not save these settings.');
        return;
      }
      // The blinding warning wins over the generic one. It is the only message here that says the
      // scan will now report clean for vectors it never sent, so it is worth holding the modal open
      // for; everything else closes, because a form that stays put after a successful save reads as
      // a form that did not save.
      const consequential = data.blinded_warning || data.warning;
      if (consequential) {
        setNotice(consequential);
        if (onSaved) onSaved(consequential, 'warning');
        await load();
        return;
      }

      let message = 'Settings saved.';
      // Only speak about the webhook when THIS save actually carried a webhook value. A whole-form
      // save always round-trips the stored pair, so keying the message on the server's
      // webhook_configured alone made every REcollapse save announce "Webhook saved" even when the
      // operator had only changed a mutation setting on a different tab.
      const touchedWebhook = Object.keys(payload).some((key) => meta[key]?.group === 'Webhook');
      if (touchedWebhook && data.webhook_configured === true) {
        message = 'Webhook saved. Both URLs are set, so REcollapse can run.';
      } else if (data.webhook_configured === false) {
        message = 'Saved, but the webhook needs BOTH URLs before a callback can prove anything.';
      }
      // CLOSE FIRST, then notify. The app's toast container sits at z-index 1000 and a Bootstrap
      // modal backdrop renders above that, so a toast raised while this modal is still open is
      // hidden behind it and the operator sees no confirmation at all, which is the exact complaint
      // this change exists to fix.
      if (handleClose) handleClose();
      if (onSaved) onSaved(message, data.webhook_configured === false ? 'warning' : 'success');
      return;
    } catch (err) {
      setError('Could not save these settings: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  const renderControl = (key) => {
    const m = meta[key] || {};

    let control;
    if (m.kind === 'bool') {
      control = (
        <Form.Check
          type="switch"
          id={`xss-${toolKey}-${key}`}
          checked={values[key] === true}
          label={values[key] === true ? 'on' : (m.placeholder ? `default: ${m.placeholder}` : 'off')}
          onChange={(e) => setValue(key, e.target.checked ? true : undefined)}
          className="text-white-50"
        />
      );
    } else if (m.kind === 'enum') {
      control = (
        <Form.Select
          size="sm"
          value={values[key] ?? ''}
          onChange={(e) => setValue(key, e.target.value || undefined)}
        >
          <option value="">{m.placeholder ? `default: ${m.placeholder}` : 'not set'}</option>
          {(m.choices || []).map((c) => <option key={c} value={c}>{c}</option>)}
        </Form.Select>
      );
    } else if (m.repeatable || m.kind === 'csv') {
      control = (
        <Form.Control
          className="custom-input"
          size="sm"
          as="textarea"
          rows={2}
          placeholder={m.placeholder ? `${m.placeholder} (one per line)` : 'one per line'}
          value={values[key] ?? ''}
          onChange={(e) => setValue(key, e.target.value)}
        />
      );
    } else {
      control = (
        <Form.Control
          className="custom-input"
          size="sm"
          type={m.kind === 'int' || m.kind === 'float' ? 'number' : 'text'}
          step={m.kind === 'float' ? '0.1' : undefined}
          placeholder={m.placeholder || 'not set'}
          value={values[key] ?? ''}
          onChange={(e) => setValue(key, e.target.value)}
        />
      );
    }

    return (
      <div key={key} className="mb-3">
        <div className="d-flex align-items-baseline gap-2 mb-1 flex-wrap">
          <span className="text-white" style={{ fontSize: '0.85rem', fontWeight: 600 }}>
            {m.label || key}
          </span>
          {m.flag && (
            <code style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.35)' }}>{m.flag}</code>
          )}
          <code style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.25)' }}>{key}</code>
        </div>
        {control}
        {key === 'endpoints' && (
          <GraphQLEndpointHelper
            activeTarget={activeTarget}
            current={values[key] ?? ''}
            onAppend={(found) => setValue(key, appendEndpoints(values[key] ?? '', found))}
            onSet={(next) => setValue(key, next)}
            category={category}
            tool={toolKey}
          />
        )}
        {m.choices && m.kind === 'csv' && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.7rem' }}>
            Comma separated. Options: {m.choices.join(', ')}
          </div>
        )}
        {/* The longer explanation, for a setting whose consequences do not fit in a placeholder.
            Added with the webhook pair, which moved off its own modal onto this one and would
            otherwise have lost the text saying why a localhost callback URL is refused. */}
        {m.help && (
          <div className="text-white-50 mt-1" style={{ fontSize: '0.72rem', lineHeight: 1.45 }}>
            {m.help}
          </div>
        )}
      </div>
    );
  };

  const keysInTab = useMemo(
    () => Object.keys(meta).filter((k) => meta[k]?.group === tab).sort(
      (a, b) => (meta[a].label || a).localeCompare(meta[b].label || b)),
    [meta, tab],
  );

  const blinded = eligibility?.blinded || {};
  const hasBlinding = Object.keys(blinded).length > 0;

  return (
    <Modal data-bs-theme="dark" show={show} onHide={handleClose} size="xl" scrollable>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">{tool?.name || 'XSS tool'} settings</Modal.Title>
      </Modal.Header>
      <Modal.Body style={{ minHeight: '60vh' }}>
        {loading ? (
          <div className="text-center py-5"><Spinner animation="border" variant="danger" /></div>
        ) : (
          <>
            {error && <Alert variant="danger" className="py-2">{error}</Alert>}
            {notice && <Alert variant="secondary" className="py-2">{notice}</Alert>}

            {/* What a scan with these settings would actually cover. On the settings screen rather
                than only on the results screen, because it is these controls that change it.
                Hidden on the vector tab, whose own header states the same coverage and more: two
                panels reporting the same pair of numbers a few pixels apart is how one of them gets
                to be quietly wrong. */}
            {eligibility && tab !== VECTORS_TAB && (
              <div className="mb-3 p-3 rounded" style={{ background: 'rgba(255,255,255,0.03)' }}>
                <div className="d-flex align-items-baseline gap-3 flex-wrap">
                  <span className="text-white" style={{ fontSize: '1.4rem', fontWeight: 600 }}>
                    {eligibility.eligible}
                    <span className="text-white-50" style={{ fontSize: '1rem' }}>
                      {' '}of {eligibility.total}
                    </span>
                  </span>
                  <span className="text-white-50" style={{ fontSize: '0.8rem' }}>
                    attack vectors can be tested by {tool?.name}
                  </span>
                  {(eligibility.reachable || []).map((p) => (
                    <Badge key={p} bg="dark" className="text-white-50 border border-secondary">
                      {POINT_LABEL[p] || p}
                    </Badge>
                  ))}
                </div>
                {eligibility.limitation && (
                  <div className="text-white-50 mt-2" style={{ fontSize: '0.78rem' }}>
                    {eligibility.limitation}
                  </div>
                )}
                {hasBlinding && (
                  <Alert variant="warning" className="py-2 mt-2 mb-0" style={{ fontSize: '0.78rem' }}>
                    {Object.entries(blinded).map(([point, keys]) => (
                      <div key={point}>
                        {keys.join(' and ')}{' '}
                        {point === 'all'
                          ? 'stops this tool sending payloads at all.'
                          : `makes every ${point} vector untestable.`}
                        {' '}Those vectors are reported as skipped rather than clean.
                      </div>
                    ))}
                  </Alert>
                )}
              </div>
            )}

            {/* jwt_tool is the one tool here with no target list to configure: a token is
                recognisable on sight, so the framework finds them. Showing what it found is what
                makes the vector count on the card explainable rather than a number to be trusted. */}
            {toolKey === 'jwt-tool' && foundTokens && (
              <div className="border rounded p-2 mb-3" style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
                <div className="text-white mb-1" style={{ fontSize: '0.8rem', fontWeight: 600 }}>
                  {foundTokens.count} token{foundTokens.count === 1 ? '' : 's'} found in this
                  target&apos;s captured traffic
                </div>
                <div className="text-white-50 mb-2" style={{ fontSize: '0.7rem' }}>
                  Deduplicated by token: the same token on many endpoints is one thing to attack.
                  Nothing needs picking. Reading a token proves nothing, so set a target URL and a
                  canary value on the Request tab to find out whether the server accepts a forgery.
                </div>
                {(foundTokens.tokens || []).slice(0, 8).map((t, i) => (
                  <div key={i} className="text-break" style={{ fontSize: '0.72rem' }}>
                    <Badge bg={t.alg && t.alg.toLowerCase() === 'none' ? 'danger' : 'secondary'}>
                      {t.alg || 'unknown alg'}
                    </Badge>{' '}
                    <code style={{ color: 'rgba(255,255,255,0.6)' }}>{t.preview}</code>
                    {t.issuer && <span className="text-white-50"> from {t.issuer}</span>}
                  </div>
                ))}
              </div>
            )}

            <Nav variant="tabs" activeKey={tab} onSelect={(k) => k && setTab(k)} className="mb-3">
              {groups.map((g) => {
                const count = Object.keys(meta).filter(
                  (k) => meta[k]?.group === g && values[k] !== undefined && values[k] !== '',
                ).length;
                return (
                  <Nav.Item key={g}>
                    <Nav.Link
                      eventKey={g}
                      style={tab === g ? { color: ACCENT, borderColor: 'rgba(220,53,69,0.4)' } : {}}
                    >
                      {g}
                      {count > 0 && (
                        <span className="ms-2 text-white-50" style={{ fontSize: '0.7rem' }}>
                          {count}
                        </span>
                      )}
                    </Nav.Link>
                  </Nav.Item>
                );
              })}
              {/* Last, after the settings groups, because it is a different kind of thing: these
                  are the vectors the tool is pointed at, not how it behaves once it gets there. */}
              <Nav.Item>
                <Nav.Link
                  eventKey={VECTORS_TAB}
                  style={tab === VECTORS_TAB
                    ? { color: ACCENT, borderColor: 'rgba(220,53,69,0.4)' } : {}}
                >
                  Attack vectors
                  {eligibility && (
                    <span className="ms-2 text-white-50" style={{ fontSize: '0.7rem' }}>
                      {eligibility.eligible}/{eligibility.total}
                    </span>
                  )}
                </Nav.Link>
              </Nav.Item>
            </Nav>

            {tab === VECTORS_TAB ? (
              <VectorSelector
                category={category}
                targetId={activeTarget?.id}
                tool={toolKey}
                toolName={tool?.name || toolKey}
                scanUnit={eligibility?.scan_unit}
                onCoverage={applyCoverage}
              />
            ) : (
              <>
                <Form>{keysInTab.map(renderControl)}</Form>

                {note && (
                  <div className="text-white-50 mt-3" style={{ fontSize: '0.75rem' }}>{note}</div>
                )}
              </>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        {/* Clear all empties the FORM, and a save then writes that emptiness. On REcollapse that
            would take the webhook with it, which is a value the operator typed once and cannot get
            back from here, so the webhook keys are preserved unless the operator clears them by
            hand on their own tab. Every other setting has a placeholder describing its default;
            the webhook has no default, only an absence that switches the tool off. */}
        {/* Hidden on the vector tab. It clears the SETTINGS form, and an operator looking at a list
            of checkboxes would reasonably read it as clearing the selection, which it does not do. */}
        {tab !== VECTORS_TAB && (
          <Button
            variant="outline-secondary"
            onClick={() => setValues((prev) => {
              const kept = {};
              Object.keys(prev).forEach((key) => {
                if (meta[key]?.group === 'Webhook') kept[key] = prev[key];
              });
              return kept;
            })}
            disabled={saving}
          >
            Clear all
          </Button>
        )}
        <Button variant="outline-secondary" onClick={handleClose} disabled={saving}>Close</Button>
        <Button variant="danger" onClick={save} disabled={saving || loading}>
          {saving ? 'Saving...' : 'Save'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default VectorToolConfigModal;
