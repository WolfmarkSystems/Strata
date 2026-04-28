import { useEffect, useMemo, useState } from 'react'
import { useAppStore } from '../store/appStore'
import EmptyState from '../components/EmptyState'
import {
  getArtifactCategories,
  getArtifacts,
  getPluginStatuses,
  runAllPlugins,
  type Artifact,
  type ArtifactCategory,
  type PluginStatus,
} from '../ipc'
import type { ViewMode } from '../types'

const CATEGORY_VIEW: Record<string, ViewMode> = {
  'Dark Web': 'darkweb',
  Cryptocurrency: 'crypto',
  Financial: 'financial',
  'Linux System': 'linux',
  Advisory: 'advisory',
}

export default function DashboardView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const evidenceName = useAppStore((s) => s.evidenceName)
  const examinerProfile = useAppStore((s) => s.examinerProfile)
  const stats = useAppStore((s) => s.stats)
  const caseData = useAppStore((s) => s.caseData)
  const setView = useAppStore((s) => s.setView)
  const setSelectedPlugin = useAppStore((s) => s.setSelectedPlugin)
  const setSelectedArtifactCat = useAppStore((s) => s.setSelectedArtifactCat)

  const [plugins, setPlugins] = useState<PluginStatus[]>([])
  const [categories, setCategories] = useState<ArtifactCategory[]>([])
  const [advisory, setAdvisory] = useState<Artifact[]>([])
  const [running, setRunning] = useState(false)

  const refresh = async () => {
    if (!evidenceId) return
    const [p, c, adv] = await Promise.all([
      getPluginStatuses(),
      getArtifactCategories(evidenceId),
      getArtifacts(evidenceId, 'Advisory'),
    ])
    setPlugins(p)
    setCategories(c)
    setAdvisory(adv.artifacts)
  }

  useEffect(() => {
    void refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidenceId])

  const top = useMemo(() => topFindings(categories, advisory), [categories, advisory])

  if (!evidenceLoaded || !evidenceId) {
    return (
      <EmptyState
        icon={'\u{1F3E0}'}
        title="Case Dashboard"
        subtitle="Open a case or load evidence to see the case overview"
      />
    )
  }

  const completed = plugins.filter((p) => p.status === 'complete').length
  const totalPlugins = plugins.length

  const anomalies = advisory.filter((a) => /anomaly/i.test(a.name)).length
  const obstructions = advisory.filter((a) => /obstruct/i.test(a.name)).length
  const highRisk = advisory.some((a) => (a.confidence_score ?? 0) > 0.85)
  const mediumRisk = advisory.some(
    (a) => (a.confidence_score ?? 0) >= 0.65 && (a.confidence_score ?? 0) <= 0.85,
  )
  const risk = highRisk ? 'HIGH' : mediumRisk ? 'MEDIUM' : 'LOW'
  const riskColor =
    risk === 'HIGH' ? 'var(--flag)' : risk === 'MEDIUM' ? 'var(--sus)' : 'var(--clean)'

  const totalArtifacts = categories.reduce((sum, c) => sum + c.count, 0)
  const populatedCategories = categories.filter((c) => c.count > 0).length

  const handleRunAll = async () => {
    if (!evidenceId || running) return
    setRunning(true)
    try {
      await runAllPlugins(evidenceId)
      await refresh()
    } finally {
      setRunning(false)
    }
  }


  return (
    <div
      style={{
        flex: 1,
        background: 'var(--bg-base)',
        padding: 8,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        overflowY: 'auto',
      }}
    >
      <div
        className="bubble-tight"
        style={{
          padding: '10px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          flexWrap: 'wrap',
        }}
      >
        <span
          style={{
            fontSize: 13,
            fontWeight: 700,
            letterSpacing: '0.1em',
            color: 'var(--text-1)',
          }}
        >
          {caseData?.case_number ?? evidenceName ?? 'Untitled Case'}
        </span>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {'·'} Examiner: {examinerProfile?.name ?? 'Unknown'}
        </span>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {'·'} {new Date().toLocaleDateString()}
        </span>
      </div>

      {/* 4-card grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 8,
        }}
      >
        <Card label="Evidence">
          <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)' }}>
            {stats.files.toLocaleString()}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            files indexed
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
            {stats.hashed.toLocaleString()} hashed
          </div>
        </Card>

        <Card label="Artifacts">
          <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--artifact)' }}>
            {totalArtifacts.toLocaleString()}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            across {populatedCategories} categories
          </div>
          <button
            onClick={() => setView('artifacts')}
            style={linkBtn}
          >
            view all {'→'}
          </button>
        </Card>

        <Card label="Risk">
          <div style={{ fontSize: 22, fontWeight: 700, color: riskColor }}>
            {risk}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {anomalies} anomalies · {obstructions} obstructions
          </div>
          <button onClick={() => setView('advisory')} style={linkBtn}>
            advisory {'→'}
          </button>
        </Card>

        <Card label="Status">
          <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)' }}>
            {completed}/{totalPlugins || 24}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            plugins complete
          </div>
          <button
            onClick={handleRunAll}
            disabled={running}
            style={{
              ...linkBtn,
              color: running ? 'var(--text-muted)' : 'var(--carved)',
            }}
          >
            {running ? 'running...' : 'run all'} {'→'}
          </button>
        </Card>
      </div>

      {/* Plugin grid */}
      <div className="bubble" style={{ padding: 12 }}>
        <SectionTitle>Plugins</SectionTitle>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 6,
            marginTop: 8,
          }}
        >
          {plugins.length === 0 ? (
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              No plugin data yet — run plugins to populate.
            </div>
          ) : (
            plugins.map((p) => (
              <PluginChip
                key={p.name}
                plugin={p}
                onClick={() => {
                  setSelectedPlugin(p.name)
                  setView('plugins')
                }}
              />
            ))
          )}
        </div>
      </div>

      {/* Findings */}
      <div className="bubble" style={{ padding: 12, flex: 1 }}>
        <SectionTitle>Top Findings</SectionTitle>
        <div style={{ marginTop: 8 }}>
          {top.length === 0 ? (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: 16 }}>
              No findings yet. Run plugins to populate.
            </div>
          ) : (
            top.map((f) => (
              <FindingRow
                key={f.key}
                finding={f}
                onClick={() => {
                  const next = CATEGORY_VIEW[f.category]
                  if (next) {
                    setView(next)
                  } else {
                    setSelectedArtifactCat(f.category)
                    setView('artifacts')
                  }
                }}
              />
            ))
          )}
        </div>
      </div>
    </div>
  )
}

interface Finding {
  key: string
  category: string
  label: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
}

function topFindings(categories: ArtifactCategory[], advisory: Artifact[]): Finding[] {
  const out: Finding[] = []
  for (const cat of categories) {
    if (cat.count === 0) continue
    const sev =
      cat.name === 'Dark Web'
        ? 'CRITICAL'
        : cat.name === 'Cryptocurrency' || cat.name === 'Malware Indicators'
          ? 'HIGH'
          : cat.count > 50
            ? 'MEDIUM'
            : 'LOW'
    out.push({
      key: `cat-${cat.name}`,
      category: cat.name,
      label: `${cat.name} - ${cat.count} artifacts`,
      severity: sev,
    })
  }
  for (const a of advisory.slice(0, 3)) {
    const c = a.confidence_score ?? 0
    out.push({
      key: `adv-${a.id}`,
      category: 'Advisory',
      label: `${a.name} - ${a.value}`,
      severity: c > 0.85 ? 'HIGH' : c > 0.65 ? 'MEDIUM' : 'LOW',
    })
  }
  return out
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, 8)
}

function severityRank(s: Finding['severity']): number {
  return s === 'CRITICAL' ? 4 : s === 'HIGH' ? 3 : s === 'MEDIUM' ? 2 : 1
}

function Card({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="bubble" style={{ padding: 14 }}>
      <div
        style={{
          fontSize: 9,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
          fontWeight: 700,
          marginBottom: 10,
        }}
      >
        {label}
      </div>
      {children}
    </div>
  )
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: 10,
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        fontWeight: 700,
      }}
    >
      {children}
    </div>
  )
}

const linkBtn: React.CSSProperties = {
  marginTop: 8,
  background: 'transparent',
  border: 'none',
  padding: 0,
  fontSize: 10,
  fontFamily: 'monospace',
  letterSpacing: '0.06em',
  textTransform: 'lowercase',
  color: 'var(--carved)',
  cursor: 'pointer',
}

function PluginChip({
  plugin,
  onClick,
}: {
  plugin: PluginStatus
  onClick: () => void
}) {
  const color =
    plugin.status === 'complete'
      ? 'var(--clean)'
      : plugin.status === 'running'
        ? 'var(--sus)'
        : plugin.status === 'error'
          ? 'var(--flag)'
          : 'var(--text-muted)'
  const symbol =
    plugin.status === 'complete'
      ? '✓'
      : plugin.status === 'running'
        ? '◐'
        : plugin.status === 'error'
          ? '✗'
          : '·'
  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        padding: '4px 10px',
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border)',
        borderRadius: 4,
        fontSize: 11,
        fontFamily: 'monospace',
        color: 'var(--text-2)',
        cursor: 'pointer',
      }}
      title={`${plugin.name} - ${plugin.status} (${plugin.artifact_count} artifacts)`}
    >
      <span style={{ color }}>{symbol}</span>
      <span>{plugin.name}</span>
      {plugin.artifact_count > 0 && (
        <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>
          {plugin.artifact_count}
        </span>
      )}
    </button>
  )
}

function FindingRow({ finding, onClick }: { finding: Finding; onClick: () => void }) {
  const sevColor =
    finding.severity === 'CRITICAL'
      ? 'var(--flag)'
      : finding.severity === 'HIGH'
        ? 'var(--sus)'
        : finding.severity === 'MEDIUM'
          ? 'var(--carved)'
          : 'var(--text-muted)'
  return (
    <div
      onClick={onClick}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: '7px 10px',
        borderBottom: '1px solid var(--border-sub)',
        cursor: 'pointer',
      }}
      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-elevated)')}
      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
    >
      <span
        style={{
          fontSize: 9,
          fontFamily: 'monospace',
          padding: '1px 6px',
          borderRadius: 3,
          background: 'transparent',
          border: `1px solid ${sevColor}`,
          color: sevColor,
          minWidth: 64,
          textAlign: 'center',
        }}
      >
        [{finding.category}]
      </span>
      <span style={{ flex: 1, fontSize: 12, color: 'var(--text-2)' }}>
        {finding.label}
      </span>
      <span
        style={{
          fontSize: 10,
          fontFamily: 'monospace',
          color: sevColor,
          fontWeight: 700,
        }}
      >
        {finding.severity}
      </span>
      <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace' }}>{'→'}</span>
    </div>
  )
}
