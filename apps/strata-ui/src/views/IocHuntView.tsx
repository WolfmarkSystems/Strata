import { useMemo, useState } from 'react'
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels'
import { useAppStore } from '../store/appStore'
import ArtifactDetail from '../components/ArtifactDetail'
import EmptyState from '../components/EmptyState'
import { searchIocs, type Artifact, type IocMatch } from '../ipc'

export default function IocHuntView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const [input, setInput] = useState('')
  const [matches, setMatches] = useState<IocMatch[]>([])
  const [selected, setSelected] = useState<Artifact | null>(null)
  const [loading, setLoading] = useState(false)

  const grouped = useMemo(() => {
    const map = new Map<string, IocMatch[]>()
    for (const match of matches) {
      const rows = map.get(match.indicator) ?? []
      rows.push(match)
      map.set(match.indicator, rows)
    }
    return Array.from(map.entries())
  }, [matches])

  if (!evidenceLoaded || !evidenceId) {
    return (
      <EmptyState
        icon={'\u{1F50E}'}
        title="IOC Hunt"
        subtitle="Load evidence and run plugins before searching indicators"
      />
    )
  }

  const runSearch = async () => {
    const indicators = input
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
    setLoading(true)
    const results = await searchIocs({ evidence_id: evidenceId, indicators })
    setMatches(results)
    setSelected(results[0]?.artifact ?? null)
    setLoading(false)
  }

  return (
    <PanelGroup direction="horizontal" style={{ flex: 1, overflow: 'hidden' }}>
      <Panel defaultSize={68} minSize={42}>
        <div className="bubble" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: 12, borderBottom: '1px solid var(--border-sub)' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
              IOC HUNT
            </div>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="192.168.1.100&#10;evil.example&#10;malware.exe"
              style={{ width: '100%', minHeight: 88, resize: 'vertical', fontFamily: 'monospace', fontSize: 12 }}
            />
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }}>
              <button onClick={runSearch} disabled={loading}>Search</button>
              <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                Searching {input.split(/\r?\n/).filter((line) => line.trim()).length} IOCs across cached artifacts
              </span>
            </div>
          </div>
          <div style={{ flex: 1, overflow: 'auto', padding: 12 }}>
            {grouped.map(([indicator, rows]) => (
              <div key={indicator} style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 6 }}>
                  {indicator} — {rows.length} matches
                </div>
                {rows.map((row) => (
                  <button
                    key={`${row.indicator}-${row.artifact.id}-${row.match_field}`}
                    onClick={() => setSelected(row.artifact)}
                    style={{
                      display: 'block',
                      width: '100%',
                      textAlign: 'left',
                      padding: '7px 8px',
                      marginBottom: 4,
                      background: selected?.id === row.artifact.id ? 'var(--bg-elevated)' : 'transparent',
                      color: 'var(--text-2)',
                      border: '1px solid var(--border-sub)',
                      borderRadius: 6,
                      cursor: 'pointer',
                    }}
                  >
                    {row.artifact.category}: {row.artifact.name} [{row.artifact.plugin}] · {row.match_field} · {row.confidence}
                  </button>
                ))}
              </div>
            ))}
            {!loading && matches.length === 0 && (
              <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No IOC matches</div>
            )}
          </div>
        </div>
      </Panel>
      <PanelResizeHandle className="resize-handle" />
      <Panel defaultSize={32} minSize={20}>
        <ArtifactDetail artifact={selected} />
      </Panel>
    </PanelGroup>
  )
}
