import { useEffect, useMemo, useState } from 'react'
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels'
import { useAppStore } from '../store/appStore'
import ArtifactDetail from '../components/ArtifactDetail'
import EmptyState from '../components/EmptyState'
import { getArtifacts, type Artifact } from '../ipc'

export interface DomainStat {
  label: string
  value: string | number
  emphasis?: 'critical' | 'amber' | 'normal'
}

interface Props {
  title: string
  subtitle: string
  icon: string
  category: string
  computeStats: (artifacts: Artifact[]) => DomainStat[]
  highlightCritical?: boolean
}

export default function DomainView({
  title,
  subtitle,
  icon,
  category,
  computeStats,
  highlightCritical = false,
}: Props) {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const [artifacts, setArtifacts] = useState<Artifact[]>([])
  const [pluginsNotRun, setPluginsNotRun] = useState(false)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<Artifact | null>(null)

  useEffect(() => {
    if (!evidenceId) return
    setLoading(true)
    getArtifacts(evidenceId, category)
      .then((res) => {
        setArtifacts(res.artifacts)
        setPluginsNotRun(res.plugins_not_run)
        setSelected(res.artifacts[0] ?? null)
      })
      .finally(() => setLoading(false))
  }, [evidenceId, category])

  const stats = useMemo(() => computeStats(artifacts), [artifacts, computeStats])

  if (!evidenceLoaded || !evidenceId) {
    return (
      <EmptyState
        icon={icon}
        title={title}
        subtitle="Load evidence and run plugins before reviewing this category"
      />
    )
  }

  return (
    <PanelGroup direction="horizontal" style={{ flex: 1, overflow: 'hidden' }}>
      <Panel defaultSize={68} minSize={42}>
        <div className="bubble" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
          <div
            style={{
              padding: 12,
              borderBottom: '1px solid var(--border-sub)',
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
              <span
                style={{
                  fontSize: 11,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em',
                  fontWeight: 700,
                }}
              >
                {title}
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {'·'} {subtitle}
              </span>
              <div style={{ flex: 1 }} />
              <span
                style={{
                  fontSize: 10,
                  color: 'var(--text-muted)',
                  fontFamily: 'monospace',
                }}
              >
                {artifacts.length} artifacts
              </span>
            </div>
            <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap' }}>
              {stats.map((stat) => (
                <StatCell key={stat.label} stat={stat} />
              ))}
            </div>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {loading ? (
              <CenterText>Loading {title}...</CenterText>
            ) : pluginsNotRun ? (
              <CenterText>Run analysis plugins first</CenterText>
            ) : artifacts.length === 0 ? (
              <CenterText>No {title} artifacts found</CenterText>
            ) : (
              artifacts.map((a) => (
                <ArtifactRow
                  key={a.id}
                  artifact={a}
                  selected={selected?.id === a.id}
                  onClick={() => setSelected(a)}
                  highlightCritical={highlightCritical}
                />
              ))
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

function StatCell({ stat }: { stat: DomainStat }) {
  const color =
    stat.emphasis === 'critical'
      ? 'var(--flag)'
      : stat.emphasis === 'amber'
        ? 'var(--sus)'
        : 'var(--text-1)'
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span
        style={{
          fontSize: 9,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
        }}
      >
        {stat.label}
      </span>
      <span
        style={{
          fontSize: 16,
          fontWeight: 700,
          color,
          fontFamily: 'monospace',
        }}
      >
        {stat.value}
      </span>
    </div>
  )
}

function CenterText({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 12,
        color: 'var(--text-muted)',
        padding: 24,
        textAlign: 'center',
      }}
    >
      {children}
    </div>
  )
}

function ArtifactRow({
  artifact,
  selected,
  onClick,
  highlightCritical,
}: {
  artifact: Artifact
  selected: boolean
  onClick: () => void
  highlightCritical: boolean
}) {
  const isCritical = highlightCritical && artifact.forensic_value === 'high'
  const fvColor =
    artifact.forensic_value === 'high'
      ? 'var(--flag)'
      : artifact.forensic_value === 'medium'
        ? 'var(--sus)'
        : 'var(--text-muted)'
  return (
    <div
      onClick={onClick}
      style={{
        display: 'flex',
        alignItems: 'center',
        minHeight: 32,
        borderBottom: '1px solid #0d1018',
        cursor: 'pointer',
        background: selected
          ? 'var(--bg-elevated)'
          : isCritical
            ? 'rgba(168,64,64,0.05)'
            : 'transparent',
      }}
    >
      <div style={{ width: 4, alignSelf: 'stretch', background: fvColor, flexShrink: 0 }} />
      <div
        style={{
          flex: 3,
          padding: '7px 10px',
          fontSize: 12,
          color: isCritical ? 'var(--flag)' : 'var(--text-1)',
          fontWeight: isCritical ? 700 : 400,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {artifact.name}
      </div>
      <div
        style={{
          flex: 2,
          padding: '7px 10px',
          fontSize: 12,
          color: 'var(--text-2)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {artifact.value}
      </div>
      <div
        style={{
          flex: 1,
          padding: '7px 10px',
          fontSize: 11,
          fontFamily: 'monospace',
          color: 'var(--text-muted)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {artifact.plugin}
      </div>
    </div>
  )
}
