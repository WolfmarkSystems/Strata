import { useEffect, useState } from 'react'
import {
  getSqliteTables,
  getSqliteTableData,
  type SqliteTable,
  type SqliteTableData,
  type SqliteCell,
} from '../ipc'
import { formatBadge } from '../util/timestamp'

interface Props {
  filePath: string
}

const PAGE_SIZES = [50, 100, 250] as const

export default function SqliteViewer({ filePath }: Props) {
  const [tables, setTables] = useState<SqliteTable[]>([])
  const [selectedTable, setSelectedTable] = useState<string | null>(null)
  const [tableData, setTableData] = useState<SqliteTableData | null>(null)
  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useState<number>(50)
  const [loadingTables, setLoadingTables] = useState(true)
  const [loadingRows, setLoadingRows] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Load tables when file path changes.
  useEffect(() => {
    let cancelled = false
    setLoadingTables(true)
    setError(null)
    setTables([])
    setSelectedTable(null)
    setTableData(null)
    setPage(0)

    getSqliteTables(filePath)
      .then((list) => {
        if (cancelled) return
        setTables(list)
        if (list.length > 0) {
          setSelectedTable(list[0].name)
        }
      })
      .catch((e) => {
        if (!cancelled) setError(String(e))
      })
      .finally(() => {
        if (!cancelled) setLoadingTables(false)
      })

    return () => {
      cancelled = true
    }
  }, [filePath])

  // Load rows when table or pagination changes.
  useEffect(() => {
    if (!selectedTable) return
    let cancelled = false
    setLoadingRows(true)
    getSqliteTableData(filePath, selectedTable, page, pageSize)
      .then((data) => {
        if (!cancelled) setTableData(data)
      })
      .finally(() => {
        if (!cancelled) setLoadingRows(false)
      })
    return () => {
      cancelled = true
    }
  }, [filePath, selectedTable, page, pageSize])

  const handleExportCsv = () => {
    if (!tableData || !selectedTable) return
    const lines: string[] = []
    lines.push(tableData.columns.map((c) => csvEscape(c.name)).join(','))
    for (const row of tableData.rows) {
      lines.push(
        row.cells
          .map((cell) => {
            if (cell.is_null) return ''
            if (cell.converted) return csvEscape(cell.converted)
            return csvEscape(cell.raw)
          })
          .join(','),
      )
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${selectedTable}_page${page + 1}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const totalPages =
    tableData && tableData.page_size > 0
      ? Math.max(1, Math.ceil(tableData.total_rows / tableData.page_size))
      : 1

  // ─── Empty state ────────────────────────────────────────────────────────
  if (loadingTables) {
    return (
      <div style={centered}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Loading tables...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div style={centered}>
        <div style={{ fontSize: 12, color: 'var(--flag)', marginBottom: 6 }}>
          Failed to open database
        </div>
        <div
          style={{
            fontSize: 10,
            color: 'var(--text-muted)',
            fontFamily: 'monospace',
            maxWidth: 400,
            textAlign: 'center',
          }}
        >
          {error}
        </div>
      </div>
    )
  }

  if (tables.length === 0) {
    return (
      <div style={centered}>
        <div style={{ fontSize: 22, marginBottom: 8 }}>{'\u{1F5C4}'}</div>
        <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 6 }}>
          No tables found
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center', maxWidth: 360 }}>
          Database may be empty, encrypted (SQLCipher), or corrupted. Try parsing with DB Browser for SQLite.
        </div>
      </div>
    )
  }

  // ─── Main view ──────────────────────────────────────────────────────────
  return (
    <div
      style={{
        flex: 1,
        display: 'flex',
        overflow: 'hidden',
        minHeight: 0,
      }}
    >
      {/* Tables sidebar */}
      <div
        style={{
          width: 180,
          minWidth: 180,
          borderRight: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          flexShrink: 0,
        }}
      >
        <div
          style={{
            padding: '10px 12px',
            fontSize: 9,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            borderBottom: '1px solid var(--border-sub)',
          }}
        >
          Tables ({tables.length})
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {tables.map((t) => {
            const active = selectedTable === t.name
            return (
              <button
                key={t.name}
                onClick={() => {
                  setSelectedTable(t.name)
                  setPage(0)
                }}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 8,
                  background: active ? 'var(--bg-elevated)' : 'transparent',
                  border: 'none',
                  borderLeft: `2px solid ${active ? 'var(--accent-2)' : 'transparent'}`,
                  color: active ? 'var(--text-1)' : 'var(--text-2)',
                  cursor: 'pointer',
                  textAlign: 'left',
                  fontFamily: 'monospace',
                  fontSize: 11,
                }}
              >
                <span
                  style={{
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {t.name}
                </span>
                <span
                  style={{
                    fontSize: 9,
                    color: 'var(--text-muted)',
                    flexShrink: 0,
                  }}
                >
                  {t.row_count}
                </span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Main area */}
      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          minWidth: 0,
        }}
      >
        {selectedTable && tableData ? (
          <>
            {/* Toolbar */}
            <div
              style={{
                padding: '8px 12px',
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                borderBottom: '1px solid var(--border-sub)',
                fontSize: 10,
                color: 'var(--text-muted)',
                flexShrink: 0,
              }}
            >
              <span style={{ fontSize: 11, color: 'var(--text-1)', fontWeight: 700 }}>
                {selectedTable}
              </span>
              <span>·</span>
              <span>
                {tableData.total_rows.toLocaleString()} rows,{' '}
                {tableData.columns.length} columns
              </span>
              <div style={{ flex: 1 }} />
              <button
                onClick={handleExportCsv}
                className="btn-secondary"
                style={{ padding: '4px 10px', fontSize: 10 }}
              >
                Export CSV
              </button>
            </div>

            {/* Column headers + rows — scrollable */}
            <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
              <table
                style={{
                  borderCollapse: 'collapse',
                  fontFamily: 'monospace',
                  fontSize: 11,
                  width: '100%',
                  tableLayout: 'auto',
                }}
              >
                <thead>
                  <tr>
                    {tableData.columns.map((col) => (
                      <th
                        key={col.name}
                        style={{
                          padding: '6px 10px',
                          textAlign: 'left',
                          background: 'var(--bg-elevated)',
                          borderBottom: '1px solid var(--border)',
                          position: 'sticky',
                          top: 0,
                          fontSize: 9,
                          textTransform: 'uppercase',
                          letterSpacing: '0.06em',
                          color: 'var(--text-2)',
                          fontWeight: 700,
                          whiteSpace: 'nowrap',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          {col.is_timestamp && (
                            <span
                              style={{ fontSize: 11, color: 'var(--hashed)' }}
                              title="Timestamp column — converted dates shown"
                            >
                              {'\u{1F550}'}
                            </span>
                          )}
                          <span>{col.name}</span>
                          {col.is_timestamp && col.timestamp_format && (
                            <span
                              style={{
                                fontSize: 8,
                                padding: '1px 5px',
                                background: 'var(--bg-panel)',
                                border: '1px solid var(--border)',
                                borderRadius: 'var(--radius-pill)',
                                color: 'var(--hashed)',
                              }}
                            >
                              {formatBadge(col.timestamp_format)}
                            </span>
                          )}
                          <span style={{ color: 'var(--text-off)', fontSize: 8 }}>
                            {col.col_type}
                          </span>
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tableData.rows.map((row, ri) => (
                    <tr
                      key={ri}
                      style={{
                        background:
                          ri % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)',
                      }}
                    >
                      {row.cells.map((cell, ci) => (
                        <td
                          key={ci}
                          style={{
                            padding: '6px 10px',
                            borderBottom: '1px solid var(--border-sub)',
                            verticalAlign: 'top',
                            maxWidth: 420,
                            overflow: 'hidden',
                          }}
                        >
                          <Cell cell={cell} />
                        </td>
                      ))}
                    </tr>
                  ))}
                  {loadingRows && tableData.rows.length === 0 && (
                    <tr>
                      <td
                        colSpan={tableData.columns.length}
                        style={{
                          padding: 20,
                          textAlign: 'center',
                          color: 'var(--text-muted)',
                          fontSize: 11,
                        }}
                      >
                        Loading rows...
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div
              style={{
                padding: '8px 12px',
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                borderTop: '1px solid var(--border-sub)',
                fontSize: 10,
                color: 'var(--text-muted)',
                flexShrink: 0,
              }}
            >
              <button
                onClick={() => setPage(Math.max(0, page - 1))}
                disabled={page === 0}
                className="btn-secondary"
                style={{ padding: '3px 10px', fontSize: 10 }}
              >
                ← Prev
              </button>
              <span>
                Page {page + 1} of {totalPages}
              </span>
              <button
                onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
                disabled={page + 1 >= totalPages}
                className="btn-secondary"
                style={{ padding: '3px 10px', fontSize: 10 }}
              >
                Next →
              </button>
              <div style={{ flex: 1 }} />
              <span>Rows per page:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value))
                  setPage(0)
                }}
                style={{
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-2)',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: 10,
                  fontFamily: 'monospace',
                }}
              >
                {PAGE_SIZES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
          </>
        ) : (
          <div style={centered}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {loadingRows ? 'Loading...' : 'Select a table'}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function Cell({ cell }: { cell: SqliteCell }) {
  if (cell.is_null) {
    return (
      <span
        style={{
          color: 'var(--text-off)',
          fontStyle: 'italic',
          fontSize: 10,
        }}
      >
        NULL
      </span>
    )
  }

  if (cell.is_blob) {
    return (
      <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
        {'\u{1F5C4}'} {cell.raw}
      </span>
    )
  }

  if (cell.is_timestamp && cell.converted) {
    return (
      <div>
        <div style={{ color: 'var(--hashed)', fontWeight: 700 }}>{cell.converted}</div>
        <div
          style={{
            color: 'var(--text-off)',
            fontSize: 9,
            marginTop: 1,
          }}
        >
          raw: {cell.raw}
        </div>
      </div>
    )
  }

  if (cell.is_timestamp && !cell.converted) {
    return (
      <span style={{ color: 'var(--sus)' }} title="Timestamp format not recognized">
        {cell.raw} <span style={{ opacity: 0.6 }}>?</span>
      </span>
    )
  }

  return <span style={{ color: 'var(--text-2)' }}>{cell.raw}</span>
}

function csvEscape(s: string): string {
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`
  }
  return s
}

const centered: React.CSSProperties = {
  flex: 1,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  padding: 20,
}
