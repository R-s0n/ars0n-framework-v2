import { useMemo, useState } from 'react';

// RequestFlowChart: a hand-built vertical tree of the requests that make up one flow through the
// application. Same spirit as AuthFlowChart, one size larger: no graph library, status-coloured
// nodes, click to select with a red border.
//
// The point of this view is the EDGES, not the nodes. A list of requests already exists in the
// Single Request sitemap. What that list cannot show is that a POST answered 302, which pulled a
// GET, whose parser pulled three XHRs. So every connector is drawn in the style of its kind and
// carries a label, and a redirect connector carries its status code, because a redirect chain is
// the thing the operator opened this tab to see.
//
// Two rules this file exists to protect:
//
//   1. The filter is never silent. The caller filters subresources out of `nodes` before they get
//      here and reports how many with `hiddenCount`. That number is painted at the top, in words,
//      next to the toggle that reveals them. If every node in a flow was filtered away, the empty
//      state says so rather than claiming the flow was empty.
//
//   2. Double-click is never the only way. Double-click opens a request in the repeater, but a
//      gesture with no affordance is a gesture nobody finds, so it is also a hint line at the top,
//      a tooltip on every node, a chip on hover, and a plain button on the selected node.

const INDENT_PX = 20;
const MAX_INDENT_DEPTH = 10; // deeper than this, stop indenting and print the depth on the card
const RENDER_CAP = 300;      // display cap only, announced in the UI, never a silent drop

// Card colours, inline rather than by utility class. See the note at the card itself: every
// Bootstrap colour utility ships !important and would win against the inline styles that mark the
// root and the hover row. These are the values those utilities paint.
const CARD_BG = '#212529';        // .bg-dark
const HOVER_BG = '#2b3035';
const BORDER_COLOR = '#495057';   // resting border, dark enough that selection reads clearly
const SELECTED_COLOR = '#dc3545'; // .border-danger, the house selection colour
const ROOT_COLOR = '#ffc107';     // .text-warning, the rail on the navigation that rooted the flow

// Connector styling per edge kind. The redirect colour is deliberately the same cyan the status
// badge paints a 3xx with, so the "302" on the connector and the "302" on the card that issued it
// read as one fact.
const EDGE_KINDS = {
  redirect: {
    label: 'redirect', color: '#0dcaf0', width: 3, dashed: false, height: 26,
    hint: 'The response redirected here. This is a real, server-driven link between two requests.',
  },
  initiator: {
    label: 'initiator', color: '#8a94a6', width: 2, dashed: false, height: 20,
    hint: 'The parent request issued this one: the HTML parser or a script asked for it.',
  },
  preflight: {
    label: 'CORS preflight', color: '#b18ae0', width: 2, dashed: false, height: 12,
    hint: 'A CORS preflight paired with the request it clears.',
  },
  sequence: {
    label: 'sequence', color: '#565d66', width: 2, dashed: true, height: 20,
    hint: 'A guess from timestamp order only. There was no redirect or initiator to link these.',
  },
};

// Higher wins when a node has more than one incoming edge. A redirect is an explicit fact, a
// sequence edge is only a temporal guess, so the redirect must be the one that shapes the tree.
const EDGE_PRIORITY = { redirect: 4, preflight: 3, initiator: 2, sequence: 1 };

const EDGE_ORDER = ['redirect', 'initiator', 'preflight', 'sequence'];

function edgeKindOf(kind) {
  return EDGE_KINDS[kind] ? kind : 'sequence';
}

function statusVariant(status) {
  const code = Number(status);
  if (!code) return 'secondary';
  if (code < 300) return 'success';
  if (code < 400) return 'info';
  if (code < 500) return 'warning';
  return 'danger';
}

function formatBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDuration(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  if (n < 1000) return `${Math.round(n)} ms`;
  return `${(n / 1000).toFixed(1)} s`;
}

// Middle truncation, because CSS truncation always eats the tail and the tail of a path is where
// the object id lives. The full url is on the card's tooltip either way.
function shortenPath(path, limit = 96) {
  const text = String(path == null ? '' : path);
  if (text.length <= limit) return text || '/';
  const head = Math.ceil((limit - 3) * 0.45);
  const tail = limit - 3 - head;
  return `${text.slice(0, head)}...${text.slice(text.length - tail)}`;
}

function hostOf(node) {
  if (!node) return '';
  if (node.host) return String(node.host);
  try {
    return new URL(String(node.url || '')).host;
  } catch (err) {
    return '';
  }
}

// Builds the drawing order. Nodes are laid out depth-first from the roots so a child always sits
// directly under its parent, and siblings keep the order the caller supplied (which is timestamp
// order). With no edges at all this degenerates to the caller's own order, which is exactly what a
// flat, unlinked flow should look like.
function buildRows(nodes, edges) {
  const byId = new Map();
  let duplicates = 0;
  nodes.forEach((node, i) => {
    const key = String(node && node.id);
    // Ids are the graph's identity: they key the edges, the selection and the repeater callback,
    // so a repeat has to collapse. It is counted rather than swallowed, because a node that
    // vanishes from the chart looks exactly like a request that was never captured.
    if (byId.has(key)) {
      duplicates += 1;
      return;
    }
    byId.set(key, { node, order: i });
  });

  const parentOf = new Map();  // childId -> { parentId, kind }
  const extraKinds = new Map(); // childId -> [kind, ...] for the edges that lost the priority race

  const noteExtra = (childId, kind) => {
    const list = extraKinds.get(childId) || [];
    if (!list.includes(kind)) list.push(kind);
    extraKinds.set(childId, list);
  };

  (edges || []).forEach((edge) => {
    if (!edge) return;
    const to = String(edge.to);
    const from = String(edge.from);
    if (to === from || !byId.has(to) || !byId.has(from)) return;
    const kind = edgeKindOf(edge.kind);
    const current = parentOf.get(to);
    if (!current) {
      parentOf.set(to, { parentId: from, kind });
      return;
    }
    if (EDGE_PRIORITY[kind] > EDGE_PRIORITY[current.kind]) {
      noteExtra(to, current.kind);
      parentOf.set(to, { parentId: from, kind });
    } else {
      noteExtra(to, kind);
    }
  });

  // A cycle in the edge set would hang the walk below, so break any parent chain that loops.
  // The node that closes the loop becomes a root: visible and honest, rather than missing.
  byId.forEach((_entry, id) => {
    const seen = new Set([id]);
    let cursor = parentOf.get(id);
    let guard = 0;
    while (cursor && guard <= byId.size) {
      if (seen.has(cursor.parentId)) {
        parentOf.delete(id);
        break;
      }
      seen.add(cursor.parentId);
      cursor = parentOf.get(cursor.parentId);
      guard += 1;
    }
  });

  const childrenOf = new Map();
  const roots = [];
  byId.forEach((entry, id) => {
    const link = parentOf.get(id);
    if (!link) {
      roots.push(id);
      return;
    }
    const list = childrenOf.get(link.parentId) || [];
    list.push(id);
    childrenOf.set(link.parentId, list);
  });

  const byOrder = (a, b) => byId.get(a).order - byId.get(b).order;
  roots.sort(byOrder);
  childrenOf.forEach((list) => list.sort(byOrder));

  const rows = [];
  const visited = new Set();
  const stack = roots.slice().reverse().map((id) => ({ id, depth: null }));

  while (stack.length) {
    const frame = stack.pop();
    if (visited.has(frame.id)) continue;
    visited.add(frame.id);

    const entry = byId.get(frame.id);
    const link = parentOf.get(frame.id);
    const supplied = Number(entry.node && entry.node.depth);
    // A linked node is drawn one level under its parent. An unlinked one keeps whatever depth the
    // caller gave it, so a caller that already computed depths does not get them thrown away.
    const depth = frame.depth != null
      ? frame.depth
      : (Number.isFinite(supplied) && supplied >= 0 ? supplied : 0);

    rows.push({
      node: entry.node,
      id: frame.id,
      depth,
      edgeKind: link ? link.kind : null,
      parent: link ? (byId.get(link.parentId) || {}).node : null,
      extras: extraKinds.get(frame.id) || [],
    });

    const kids = childrenOf.get(frame.id) || [];
    for (let i = kids.length - 1; i >= 0; i -= 1) {
      if (!visited.has(kids[i])) stack.push({ id: kids[i], depth: depth + 1 });
    }
  }

  // Belt and braces: anything the walk somehow missed still gets drawn.
  byId.forEach((entry, id) => {
    if (visited.has(id)) return;
    visited.add(id);
    const supplied = Number(entry.node && entry.node.depth);
    rows.push({
      node: entry.node,
      id,
      depth: Number.isFinite(supplied) && supplied >= 0 ? supplied : 0,
      edgeKind: null,
      parent: null,
      extras: extraKinds.get(id) || [],
    });
  });

  return { rows, duplicates };
}

function EdgeSwatch({ kind }) {
  const spec = EDGE_KINDS[kind];
  return (
    <span className="d-inline-flex align-items-center me-3" title={spec.hint}>
      <span
        style={{
          display: 'inline-block',
          width: 22,
          borderTop: `${spec.width}px ${spec.dashed ? 'dashed' : 'solid'} ${spec.color}`,
          marginRight: 6,
        }}
      />
      <span style={{ color: spec.color, fontSize: '0.7rem' }}>{spec.label}</span>
    </span>
  );
}

// The connector drawn above a node: a vertical line in the style of the edge kind, a label chip,
// and an arrowhead pointing into the card below it.
function Connector({ kind, indent, label, title }) {
  const spec = EDGE_KINDS[kind];
  const prominent = kind === 'redirect';
  return (
    <div style={{ paddingLeft: indent }} aria-hidden="true">
      <div className="d-flex align-items-center" style={{ height: spec.height }}>
        <div
          style={{
            width: 14,
            height: '100%',
            borderRight: `${spec.width}px ${spec.dashed ? 'dashed' : 'solid'} ${spec.color}`,
          }}
        />
        <span
          className="ms-2 d-inline-flex align-items-center"
          title={title || spec.hint}
          style={{
            fontSize: '0.65rem',
            color: prominent ? '#04252b' : spec.color,
            background: prominent ? spec.color : 'transparent',
            border: prominent ? 'none' : `1px solid ${spec.color}55`,
            borderRadius: 3,
            padding: prominent ? '1px 6px' : '0 5px',
            fontWeight: prominent ? 700 : 400,
            whiteSpace: 'nowrap',
          }}
        >
          {label}
        </span>
      </div>
      <div
        style={{
          marginLeft: 8,
          color: spec.color,
          fontSize: prominent ? '0.75rem' : '0.6rem',
          lineHeight: '8px',
          height: 10,
        }}
      >
        &#9660;
      </div>
    </div>
  );
}

const RequestFlowChart = ({
  nodes = [],
  edges = [],
  selectedId = null,
  onSelect,
  onOpenInRepeater,
  hiddenCount = 0,
  showAll = false,
  onToggleShowAll,
  redirectsPromised = false,
}) => {
  const [hoveredId, setHoveredId] = useState(null);
  const [renderAll, setRenderAll] = useState(false);

  const { rows, duplicates } = useMemo(() => buildRows(
    Array.isArray(nodes) ? nodes.filter(Boolean) : [],
    Array.isArray(edges) ? edges : [],
  ), [nodes, edges]);

  const hidden = Number(hiddenCount) > 0 ? Number(hiddenCount) : 0;
  const rootHost = hostOf(rows.length ? rows[0].node : null);
  const capped = !renderAll && rows.length > RENDER_CAP;
  const visibleRows = capped ? rows.slice(0, RENDER_CAP) : rows;

  const kindsPresent = useMemo(() => {
    const present = new Set();
    rows.forEach((row) => { if (row.edgeKind) present.add(row.edgeKind); });
    return EDGE_ORDER.filter((kind) => present.has(kind));
  }, [rows]);

  // The flow list badges this flow as having redirects and the graph draws none. Saying nothing
  // there is the worst option: an unexplained absence reads as a broken diagram, and the operator
  // goes looking for a bug in the tool instead of understanding the data. Two real causes, both
  // upstream of this component: the recorder writes some hops with from == location, which is a
  // self-loop and correctly refused; and a hop whose destination was never captured has no node to
  // point at, since every node here must be a row the repeater can actually open.
  const redirectsMissing = redirectsPromised
    && rows.length > 0
    && !rows.some((row) => row.edgeKind === 'redirect');

  const filterLine = (() => {
    if (showAll) {
      return (
        <span className="text-white-50" style={{ fontSize: '0.72rem' }}>
          Showing every request in this flow, subresources included.
          {onToggleShowAll && (
            <button
              type="button"
              className="btn btn-link btn-sm p-0 ms-2 align-baseline text-info text-decoration-underline"
              style={{ fontSize: '0.72rem' }}
              onClick={onToggleShowAll}
            >
              hide subresources
            </button>
          )}
        </span>
      );
    }
    if (hidden > 0) {
      return (
        <span className="text-warning" style={{ fontSize: '0.72rem' }}>
          <i className="bi bi-funnel-fill me-1" />
          {hidden.toLocaleString()} subresource{hidden === 1 ? '' : 's'} hidden
          {onToggleShowAll && (
            <button
              type="button"
              className="btn btn-link btn-sm p-0 ms-2 align-baseline text-warning text-decoration-underline"
              style={{ fontSize: '0.72rem' }}
              onClick={onToggleShowAll}
            >
              show all
            </button>
          )}
        </span>
      );
    }
    return (
      <span className="text-white-50" style={{ fontSize: '0.72rem' }}>
        Nothing filtered: this is every request in the flow.
      </span>
    );
  })();

  const header = (
    <div className="border-bottom border-secondary pb-2 mb-2">
      <div className="d-flex flex-wrap align-items-center justify-content-between gap-2">
        {filterLine}
        <span className="text-white-50" style={{ fontSize: '0.72rem' }}>
          <i className="bi bi-mouse2 me-1" />
          Click a request for its details.
          <span className="text-info ms-1">Double-click to open it in Single Request.</span>
        </span>
      </div>
      {kindsPresent.length > 0 && (
        <div className="mt-2 d-flex flex-wrap align-items-center">
          <span className="text-white-50 me-2" style={{ fontSize: '0.65rem' }}>edges:</span>
          {kindsPresent.map((kind) => <EdgeSwatch key={kind} kind={kind} />)}
        </div>
      )}
      {redirectsMissing && (
        <div className="mt-2 text-warning" style={{ fontSize: '0.7rem' }}>
          <i className="bi bi-exclamation-triangle me-1" />
          This flow is marked as having redirects, but none could be drawn. Either the recorder
          stored the hop with the same URL on both ends, or the destination was never captured, so
          there is no request here to point at. The grouping is still right: the requests either
          side of the redirect are in this flow.
        </div>
      )}
      {duplicates > 0 && (
        <div className="text-warning mt-1" style={{ fontSize: '0.65rem' }}>
          <i className="bi bi-exclamation-triangle me-1" />
          {duplicates.toLocaleString()} request{duplicates === 1 ? '' : 's'} shared an id with another
          and {duplicates === 1 ? 'is' : 'are'} drawn once.
        </div>
      )}
    </div>
  );

  if (!rows.length) {
    return (
      <div className="d-flex flex-column">
        {header}
        <div className="text-center text-white-50 py-4 fst-italic">
          {hidden > 0 ? (
            <>
              Every request in this flow was filtered out as a subresource.
              {' '}
              {hidden.toLocaleString()} hidden.
              {onToggleShowAll && (
                <button
                  type="button"
                  className="btn btn-sm btn-outline-warning ms-2"
                  onClick={onToggleShowAll}
                >
                  Show all resources
                </button>
              )}
            </>
          ) : (
            'No requests in this flow.'
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="d-flex flex-column">
      {header}

      <div style={{ overflowX: 'auto' }}>
        <div style={{ minWidth: 420 }}>
          {visibleRows.map((row, idx) => {
            const node = row.node || {};
            const id = row.id;
            const selected = selectedId != null && String(selectedId) === String(id);
            const hovered = String(hoveredId) === String(id);
            const indent = Math.min(row.depth, MAX_INDENT_DEPTH) * INDENT_PX;
            const clippedDepth = row.depth > MAX_INDENT_DEPTH;
            const host = hostOf(node);
            const crossHost = Boolean(rootHost && host && host !== rootHost);
            const size = formatBytes(node.size);
            const duration = formatDuration(node.duration_ms);
            const path = node.path || node.url || '/';
            const isRoot = Boolean(node.is_root) || (idx === 0 && !row.edgeKind);
            const inPreflightPair = row.edgeKind === 'preflight';

            let connectorLabel = null;
            let connectorTitle = null;
            if (row.edgeKind === 'redirect') {
              const parentStatus = row.parent && Number(row.parent.status_code);
              const code = parentStatus && parentStatus >= 300 && parentStatus < 400 ? parentStatus : null;
              connectorLabel = code ? `${code} redirect` : 'redirect';
              if (crossHost) connectorLabel += ` → ${host}`;
              connectorTitle = code
                ? `The parent request answered ${code} and pointed here.`
                : EDGE_KINDS.redirect.hint;
            } else if (row.edgeKind === 'initiator') {
              const init = node.initiator ? String(node.initiator) : '';
              connectorLabel = init && init !== 'preflight' ? `initiator: ${init}` : 'initiator';
              connectorTitle = init === 'parser'
                ? 'The HTML parser of the parent document requested this.'
                : (init === 'script' ? 'Javascript requested this.' : EDGE_KINDS.initiator.hint);
            } else if (row.edgeKind === 'preflight') {
              connectorLabel = 'CORS preflight cleared this';
            } else if (row.edgeKind === 'sequence') {
              connectorLabel = 'sequence (timing only)';
            }

            const title = [
              node.url || path,
              node.mime_type ? `type: ${node.mime_type}` : null,
              node.timestamp ? `time: ${node.timestamp}` : null,
              'Double-click to open in Single Request',
            ].filter(Boolean).join('\n');

            // The card's border and background are inline longhands on purpose. Bootstrap's
            // `.border`, `.border-secondary` and `.bg-dark` utilities all carry !important, so a
            // utility class here would quietly beat the root's gold rail and the hover tint, and
            // the loss would be invisible until someone wondered why roots looked like children.
            // These are the same hex values those utilities paint, minus the specificity fight.
            const edgeColor = selected ? SELECTED_COLOR : BORDER_COLOR;
            const leftColor = selected
              ? SELECTED_COLOR
              : (isRoot ? ROOT_COLOR : BORDER_COLOR);

            return (
              <div key={`${id}-${idx}`}>
                {row.edgeKind && (
                  <Connector
                    kind={row.edgeKind}
                    indent={indent}
                    label={connectorLabel}
                    title={connectorTitle}
                  />
                )}

                <div
                  role="button"
                  tabIndex={0}
                  title={title}
                  onClick={() => onSelect && onSelect(id)}
                  onDoubleClick={() => onOpenInRepeater && onOpenInRepeater(id)}
                  onMouseEnter={() => setHoveredId(id)}
                  onMouseLeave={() => setHoveredId((prev) => (String(prev) === String(id) ? null : prev))}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      if (onSelect) onSelect(id);
                    } else if (e.key === 'o' || e.key === 'O') {
                      e.preventDefault();
                      if (onOpenInRepeater) onOpenInRepeater(id);
                    }
                  }}
                  className="rounded px-2 py-1"
                  style={{
                    cursor: 'pointer',
                    marginLeft: indent,
                    marginTop: inPreflightPair ? 0 : 2,
                    marginBottom: 2,
                    backgroundColor: hovered ? HOVER_BG : CARD_BG,
                    borderStyle: 'solid',
                    borderTopWidth: 1,
                    borderRightWidth: 1,
                    borderBottomWidth: 1,
                    borderLeftWidth: isRoot ? 4 : 1,
                    borderTopColor: edgeColor,
                    borderRightColor: edgeColor,
                    borderBottomColor: edgeColor,
                    borderLeftColor: leftColor,
                  }}
                >
                  <div className="d-flex align-items-center gap-2">
                    <span
                      className="badge bg-dark border border-secondary text-white-50"
                      style={{ fontSize: '0.58rem', minWidth: 46 }}
                    >
                      {node.method || '?'}
                    </span>

                    <code
                      className={`flex-grow-1 text-truncate ${selected ? 'text-light' : 'text-white-50'}`}
                      style={{ fontSize: '0.75rem', minWidth: 0 }}
                    >
                      {shortenPath(path)}
                    </code>

                    {node.has_body && (
                      <span
                        className="badge bg-dark border border-info text-info"
                        style={{ fontSize: '0.55rem' }}
                        title="This request carried a body"
                      >
                        body
                      </span>
                    )}

                    <span className={`badge bg-${statusVariant(node.status_code)}`} style={{ fontSize: '0.58rem' }}>
                      {node.status_code || '?'}
                    </span>
                  </div>

                  <div
                    className="d-flex flex-wrap align-items-center gap-2 mt-1 text-white-50"
                    style={{ fontSize: '0.62rem' }}
                  >
                    {isRoot && (
                      <span className="badge bg-warning text-dark" style={{ fontSize: '0.55rem' }}>
                        <i className="bi bi-signpost-2 me-1" />
                        flow root
                      </span>
                    )}
                    {node.resource_type && <span>{node.resource_type}</span>}
                    {crossHost && (
                      <span className="text-info" title={`Different host to the flow root (${rootHost})`}>
                        <i className="bi bi-box-arrow-up-right me-1" />
                        {host}
                      </span>
                    )}
                    {size && <span>{size}</span>}
                    {duration && <span>{duration}</span>}
                    {clippedDepth && <span title="Nesting depth, beyond what the indentation shows">{`depth ${row.depth}`}</span>}
                    {row.extras.map((kind) => (
                      <span
                        key={kind}
                        style={{ color: EDGE_KINDS[kind].color }}
                        title={`Also linked to another request by a ${EDGE_KINDS[kind].label} edge.`}
                      >
                        {`+${EDGE_KINDS[kind].label}`}
                      </span>
                    ))}

                    <span className="ms-auto d-flex align-items-center gap-2">
                      {hovered && !selected && (
                        <span className="text-info" style={{ fontSize: '0.6rem' }}>
                          double-click to open
                        </span>
                      )}
                      {selected && onOpenInRepeater && (
                        <button
                          type="button"
                          className="btn btn-sm btn-outline-danger py-0 px-2"
                          style={{ fontSize: '0.6rem' }}
                          title="Open this request in the Single Request repeater. Double-clicking the row does the same."
                          onClick={(e) => { e.stopPropagation(); onOpenInRepeater(id); }}
                          onDoubleClick={(e) => e.stopPropagation()}
                        >
                          <i className="bi bi-arrow-repeat me-1" />
                          Open in Single Request
                        </button>
                      )}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {capped && (
        <div className="text-center py-2 border-top border-secondary mt-2">
          <span className="text-warning" style={{ fontSize: '0.72rem' }}>
            Drawing the first {RENDER_CAP} of {rows.length.toLocaleString()} requests in this flow.
            Nothing is filtered, this is a display cap.
          </span>
          <button
            type="button"
            className="btn btn-sm btn-outline-warning ms-2 py-0 px-2"
            style={{ fontSize: '0.7rem' }}
            onClick={() => setRenderAll(true)}
          >
            Draw all {rows.length.toLocaleString()}
          </button>
        </div>
      )}
    </div>
  );
};

export default RequestFlowChart;
