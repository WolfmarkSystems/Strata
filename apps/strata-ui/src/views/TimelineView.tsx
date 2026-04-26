import { useEffect, useMemo, useState } from 'react'
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels'
import { useAppStore } from '../store/appStore'
import ArtifactDetail from '../components/ArtifactDetail'
import EmptyState from '../components/EmptyState'
import { getArtifactsTimeline, type Artifact } from '../ipc'

function dateInputToUnix(value: string): number | undefined {
  if (!value) return undefined
  const ms = new Date(`${value}T00:00:00`).getTime()
  if (Number.isNaN(ms)) return undefined
  return Math.floor(ms / 1000)
}

function endDateInputToUnix(value: string): number | undefined {
  if (!value) return undefined
  const ms = new Date(`${value}T23:59:59`).getTime()
  if (Number.isNaN(ms)) return undefined
  return Math.floor(ms / 1000)
}

function formatTimestamp(timestamp: string | null): string {
  if (!timestamp) return ''
  const numeric = Number(timestamp)
  if (Number.isFinite(numeric)) {
    return new Date(numeric * 1000).toLocaleString()
  }
  return timestamp
}

function csvEscape(value: string | null): string {
  const safe = value ?? ''
  return `"${safe.replaceAll('"', '""')}"`
}

export default function TimelineView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const [items, setItems] = useState<Artifact[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [jumpDate, setJumpDate] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!evidenceId) {
      setItems([])
      return
    }
    setLoading(true)
    getArtifactsTimeline(
      evidenceId,
      dateInputToUnix(startDate),
      endDateInputToUnix(endDate),
      1000,
    ).then((rows) => {
      setItems(rows)
      setSelectedId(rows[0]?.id ?? null)
      setLoading(false)
    })
  }, [evidenceId, startDate, endDate])

  const selected = useMemo(
    () => items.find((item) => item.id === selectedId) ?? null,
    [items, selectedId],
  )

  if (!evidenceLoaded) {
    return (
      <EmptyState
        icon={'\u{1F552}'}
        title="Timeline"
        subtitle="Load evidence and run plugins to build the unified event timeline"
      />
    )
  }

  const exportCsv = () => {
    const header = ['timestamp', 'artifact', 'category', 'source', 'plugin']
    const rows = items.map((item) => [
      formatTimestamp(item.timestamp),
      item.name,
      item.category,
      item.source_path,
      item.plugin,
    ])
    const csv = [header, ...rows].map((row) => row.map(csvEscape).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'strata-timeline.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const jumpToDate = () => {
    const target = dateInputToUnix(jumpDate)
    if (!target) return
    const row = items.find((item) => Number(item.timestamp) >= target)
    if (row) setSelectedId(row.id)
  }

  return (
    <PanelGroup direction="horizontal" style={{ flex: 1, overflow: 'hidden' }}>
      <Panel defaultSize={70} minSize={45}>
        <div className="bubble" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: 12, borderBottom: '1px solid var(--border-sub)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              TIMELINE — {items.length.toLocaleString()} events with timestamps
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center' }}>
              <input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} />
              <input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} />
              <input type="date" value={jumpDate} onChange={(e) => setJumpDate(e.target.value)} />
              <button onClick={jumpToDate}>Jump</button>
              <button onClick={exportCsv}>Export CSV</button>
            </div>
          </div>
          <div style={{ flex: 1, overflow: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ color: 'var(--text-muted)', textAlign: 'left' }}>
                  <th style={{ padding: 8 }}>Timestamp</th>
                  <th style={{ padding: 8 }}>Artifact</th>
                  <th style={{ padding: 8 }}>Category</th>
                  <th style={{ padding: 8 }}>Source</th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr><td colSpan={4} style={{ padding: 12, color: 'var(--text-muted)' }}>Loading</td></tr>
                )}
                {!loading && items.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => setSelectedId(item.id)}
                    style={{
                      cursor: 'pointer',
                      background: selectedId === item.id ? 'var(--bg-elevated)' : 'transparent',
                      borderTop: '1px solid var(--border-sub)',
                    }}
                  >
                    <td style={{ padding: 8, whiteSpace: 'nowrap' }}>{formatTimestamp(item.timestamp)}</td>
                    <td style={{ padding: 8 }}>{item.name}</td>
                    <td style={{ padding: 8 }}>{item.category}</td>
                    <td style={{ padding: 8, color: 'var(--text-muted)' }}>{item.plugin}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Panel>
      <PanelResizeHandle className="resize-handle" />
      <Panel defaultSize={30} minSize={20}>
        <ArtifactDetail artifact={selected} />
      </Panel>
    </PanelGroup>
  )
}
