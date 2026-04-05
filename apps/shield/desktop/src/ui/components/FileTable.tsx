import { useCallback, useRef, useEffect, useState } from 'react';
import { Virtuoso } from 'react-virtuoso';
import type { FileTableRow, SortField, SortDir } from '../../types';

interface Props {
  fileTable: {
    rows: FileTableRow[];
    loading: boolean;
    error: string | null;
    selectedRow: FileTableRow | null;
    setSelectedRow: (row: FileTableRow | null) => void;
    sortField: SortField;
    setSortField: (field: SortField) => void;
    sortDir: SortDir;
    setSortDir: (dir: SortDir) => void;
    loadMore: () => void;
    hasMore: boolean;
    rowCount: number;
  };
  caseId: string | null;
}

const COLUMNS = [
  { key: 'score', label: 'Score', width: 60, sortable: true },
  { key: 'name', label: 'Name', width: 200, sortable: true },
  { key: 'path', label: 'Path', width: 300, sortable: true },
  { key: 'extension', label: 'Ext', width: 60, sortable: true },
  { key: 'size_bytes', label: 'Size', width: 80, sortable: true },
  { key: 'modified_utc', label: 'Modified', width: 140, sortable: true },
  { key: 'entropy', label: 'Entropy', width: 70, sortable: true },
  { key: 'category', label: 'Category', width: 100, sortable: true },
  { key: 'source_type', label: 'Source', width: 80, sortable: true },
];

function formatSize(bytes?: number): string {
  if (!bytes) return '-';
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)}M`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)}G`;
}

function formatDate(utc?: string): string {
  if (!utc) return '-';
  try {
    return new Date(utc).toLocaleDateString() + ' ' + new Date(utc).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '-';
  }
}

export function FileTable({ fileTable, caseId }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; row: FileTableRow } | null>(null);
  const { rows, loading, error, selectedRow, setSelectedRow, sortField, setSortField, sortDir, setSortDir, loadMore, hasMore, rowCount } = fileTable;

  const handleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSortDir(sortDir === 'Asc' ? 'Desc' : 'Asc');
    } else {
      setSortField(field);
      setSortDir('Asc');
    }
  }, [sortField, sortDir, setSortField, setSortDir]);

  const getRowKey = useCallback((index: number) => {
    const row = rows[index];
    return `${row.source_type}:${row.source_id}`;
  }, [rows]);

  const handleContextMenu = useCallback((e: React.MouseEvent, row: FileTableRow) => {
    e.preventDefault();
    setSelectedRow(row);
  }, [setSelectedRow]);

  useEffect(() => {
    const handleClickOutside = () => setContextMenu(null);
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, []);

  if (!caseId) {
    return (
      <div className="file-table-empty">
        <p>Open a case to view files</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="file-table-error">
        <p>Error: {error}</p>
      </div>
    );
  }

  return (
    <div className="file-table" ref={containerRef}>
      <div className="table-header">
        {COLUMNS.map(col => (
          <div
            key={col.key}
            className={`th ${col.sortable ? 'sortable' : ''} ${sortField === col.key ? 'sorted' : ''}`}
            style={{ width: col.width, minWidth: col.width }}
            onClick={() => col.sortable && handleSort(col.key as SortField)}
          >
            {col.label}
            {sortField === col.key && (
              <span className="sort-indicator">{sortDir === 'Asc' ? '↑' : '↓'}</span>
            )}
          </div>
        ))}
      </div>
      
      <div className="table-body">
        <Virtuoso
          style={{ height: '100%' }}
          data={rows}
          itemContent={(index, row) => (
            <div
              key={getRowKey(index)}
              className={`tr ${selectedRow?.id === row.id ? 'selected' : ''}`}
              onClick={() => setSelectedRow(row)}
              onContextMenu={(e) => handleContextMenu(e, row)}
            >
              <div className="td" style={{ width: 60, minWidth: 60 }}>
                {row.score > 0 ? (
                  <span className={`score-badge ${row.score > 50 ? 'high' : row.score > 20 ? 'medium' : 'low'}`}>
                    {row.score.toFixed(0)}
                  </span>
                ) : '-'}
              </div>
              <div className="td" style={{ width: 200, minWidth: 200 }} title={row.name}>
                {row.name}
              </div>
              <div className="td" style={{ width: 300, minWidth: 300 }} title={row.path}>
                {row.path}
              </div>
              <div className="td" style={{ width: 60, minWidth: 60 }}>
                {row.extension || '-'}
              </div>
              <div className="td" style={{ width: 80, minWidth: 80 }}>
                {formatSize(row.size_bytes)}
              </div>
              <div className="td" style={{ width: 140, minWidth: 140 }}>
                {formatDate(row.modified_utc)}
              </div>
              <div className="td" style={{ width: 70, minWidth: 70 }}>
                {row.entropy?.toFixed(1) || '-'}
              </div>
              <div className="td" style={{ width: 100, minWidth: 100 }}>
                {row.category || '-'}
              </div>
              <div className="td" style={{ width: 80, minWidth: 80 }}>
                <span className={`source-badge ${row.source_type}`}>
                  {row.source_type}
                </span>
              </div>
            </div>
          )}
          endReached={() => {
            if (hasMore && !loading) {
              loadMore();
            }
          }}
        />
      </div>

      <div className="table-footer">
        <span>{rowCount} rows</span>
        {loading && <span className="loading-indicator">Loading...</span>}
        {!hasMore && rowCount > 0 && <span>All loaded</span>}
      </div>

      {contextMenu && (
        <div
          className="context-menu"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={e => e.stopPropagation()}
        >
          <button
            onClick={() => {
              // Add to notes - would call API here
              setContextMenu(null);
            }}
          >
            Add to Notes
          </button>
          <button
            onClick={() => {
              navigator.clipboard.writeText(contextMenu.row.path);
              setContextMenu(null);
            }}
          >
            Copy Path
          </button>
          {contextMenu.row.source_id && (
            <button
              onClick={() => {
                navigator.clipboard.writeText(contextMenu.row.source_id);
                setContextMenu(null);
              }}
            >
              Copy ID
            </button>
          )}
        </div>
      )}
    </div>
  );
}
