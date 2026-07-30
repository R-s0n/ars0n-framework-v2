import VirtualizedList from './VirtualizedList';

/**
 * VirtualizedTable — tabular virtualization on top of {@link VirtualizedList} (G1.5).
 *
 * Because react-window rows are absolutely positioned, a real <table> can't be virtualized
 * directly. This renders a non-scrolling flex header above a virtualized body of flex rows; the
 * header and each row use the same per-column flex/width, so columns line up. Rows are
 * dynamic-height (multi-line cells grow instead of clipping).
 *
 * Sorting/selection state lives in the parent (passed via onSort / renderCell), so it survives
 * rows recycling as the user scrolls.
 *
 * Props:
 *   columns            [{ key, label, sortable?, flex?, width?, minWidth? }]
 *   rows               array of row data
 *   renderCell         (row, columnKey) => ReactNode
 *   onSort             (columnKey) => void   (only called for sortable columns)
 *   renderSortIcon     (columnKey) => ReactNode
 *   getRowKey          (row, index) => stable key
 *   height             CSS height of the scroll viewport (default '60vh')
 *   estimatedRowHeight px estimate before a row is measured (default 44)
 *   headerClassName, className, style
 */

const colStyle = (col) => ({
  flex: col.flex != null ? col.flex : 1,
  width: col.width,
  minWidth: col.minWidth != null ? col.minWidth : 80,
  wordBreak: 'break-word',
});

const VirtualizedTable = ({
  columns = [],
  rows = [],
  renderCell,
  onSort,
  renderSortIcon,
  getRowKey,
  height = '60vh',
  estimatedRowHeight = 44,
  headerClassName = '',
  className,
  style,
}) => {
  return (
    <div className={className} style={style}>
      <div className={`d-flex bg-dark border-bottom border-secondary ${headerClassName}`}>
        {columns.map((col) => (
          <div
            key={col.key}
            className="px-2 py-2 fw-bold text-white"
            style={{
              ...colStyle(col),
              cursor: col.sortable && onSort ? 'pointer' : 'default',
              userSelect: 'none',
            }}
            onClick={col.sortable && onSort ? () => onSort(col.key) : undefined}
          >
            {col.label}
            {col.sortable && renderSortIcon ? <> {renderSortIcon(col.key)}</> : null}
          </div>
        ))}
      </div>
      <VirtualizedList
        items={rows}
        height={height}
        estimatedItemSize={estimatedRowHeight}
        itemKey={getRowKey}
        renderItem={(row, index) => (
          <div
            className="d-flex border-bottom border-secondary"
            style={{ background: index % 2 ? 'rgba(255,255,255,0.03)' : 'transparent' }}
          >
            {columns.map((col) => (
              <div key={col.key} className="px-2 py-1 text-white" style={colStyle(col)}>
                {renderCell(row, col.key)}
              </div>
            ))}
          </div>
        )}
      />
    </div>
  );
};

export default VirtualizedTable;
