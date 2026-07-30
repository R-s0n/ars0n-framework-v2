import { useRef, useState, useEffect, useCallback } from 'react';
import { VariableSizeList } from 'react-window';

/**
 * VirtualizedList — dynamic-height vertical virtualization (G1.5).
 *
 * Renders only the rows near the viewport, so the DOM node count stays roughly constant no
 * matter how many items there are. This is the fix for the screens that froze the browser by
 * mounting a node per row at 10k+ (Screenshot grid, attack-surface table, etc.).
 *
 * Row heights are measured after render via ResizeObserver, so variable / expandable content
 * works without hard-coded sizes — when a row grows or shrinks (e.g. the parent expands an
 * item) the list re-lays-out automatically.
 *
 * The parent does not need an explicit pixel height: this renders an outer box at `height`
 * (any CSS height, default 65vh), measures its pixel height, and feeds that to react-window.
 *
 * IMPORTANT: any per-row UI state that must survive a row being scrolled out of and back into
 * the window (selection, "expanded") MUST live in the PARENT and be threaded through
 * `renderItem`. react-window unmounts off-screen rows, so row-local state would be lost.
 *
 * Props:
 *   items             array of data items
 *   renderItem        (item, index) => ReactNode
 *   estimatedItemSize px estimate used before a row is measured (default 96)
 *   overscanCount     extra rows rendered above/below the viewport (default 4)
 *   height            CSS height of the scroll viewport (default '65vh')
 *   width             CSS width (default '100%')
 *   itemKey           (item, index) => stable key; recommended so recycled rows map correctly
 *   className, style  applied to the outer box
 */

const Row = ({ index, style, data }) => {
  const { items, renderItem, setSize } = data;
  const rowRef = useRef(null);

  // Measure on every render of this row and observe size changes (expand/collapse, async
  // images, content edits). Cheap because only visible rows mount.
  useEffect(() => {
    const el = rowRef.current;
    if (!el) return undefined;
    const measure = () => setSize(index, el.getBoundingClientRect().height);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  });

  return (
    <div style={style}>
      <div ref={rowRef}>{renderItem(items[index], index)}</div>
    </div>
  );
};

const VirtualizedList = ({
  items = [],
  renderItem,
  estimatedItemSize = 96,
  overscanCount = 4,
  height = '65vh',
  width = '100%',
  itemKey,
  className,
  style,
}) => {
  const listRef = useRef(null);
  const outerRef = useRef(null);
  const sizeMap = useRef({});
  const [measuredHeight, setMeasuredHeight] = useState(0);

  // Auto-size the viewport to the outer box (no dependency on the parent's flex chain).
  useEffect(() => {
    const el = outerRef.current;
    if (!el) return undefined;
    const update = () => setMeasuredHeight(el.clientHeight);
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const setSize = useCallback((index, size) => {
    const rounded = Math.ceil(size);
    if (rounded > 0 && sizeMap.current[index] !== rounded) {
      sizeMap.current[index] = rounded;
      // Force-recompute offsets from this index down so the new height takes effect now.
      if (listRef.current) listRef.current.resetAfterIndex(index);
    }
  }, []);

  const getSize = useCallback(
    (index) => sizeMap.current[index] || estimatedItemSize,
    [estimatedItemSize]
  );

  // When the dataset changes, drop stale measurements and re-lay-out from the top.
  useEffect(() => {
    sizeMap.current = {};
    if (listRef.current) listRef.current.resetAfterIndex(0);
  }, [items]);

  const itemData = { items, renderItem, setSize };

  return (
    <div ref={outerRef} className={className} style={{ height, width, ...style }}>
      {measuredHeight > 0 && items.length > 0 && (
        <VariableSizeList
          ref={listRef}
          height={measuredHeight}
          width={width}
          itemCount={items.length}
          itemSize={getSize}
          estimatedItemSize={estimatedItemSize}
          overscanCount={overscanCount}
          itemData={itemData}
          itemKey={itemKey ? (index, data) => itemKey(data.items[index], index) : undefined}
        >
          {Row}
        </VariableSizeList>
      )}
    </div>
  );
};

export default VirtualizedList;
