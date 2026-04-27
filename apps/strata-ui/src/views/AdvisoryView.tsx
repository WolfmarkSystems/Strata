import { useEffect, useMemo, useState } from 'react'
import { useAppStore } from '../store/appStore'
import EmptyState from '../components/EmptyState'
import { getArtifacts, type Artifact } from '../ipc'

type FindingKind = 'anomaly' | 'obstruction' | 'charge' | 'summary' | 'other'
type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW'

function classify(a: Artifact): FindingKind {
  const blob = `${a.name} ${a.value}`.toLowerCase()
  if (blob.includes('anomaly') || a.name.toLowerCase().includes('anomaly')) return 'anomaly'
  if (blob.includes('obstruct')) return 'obstruction'
  if (blob.includes('charge') || blob.includes('offense')) return 'charge'
  if (blob.includes('summary')) return 'summary'
  return 'other'
}

function riskFor(artifacts: Artifact[]): RiskLevel {
  const high = artifacts.some((a) => (a.confidence_score ?? 0) > 0.85)
  if (high) return 'HIGH'
  const med = artifacts.some(
    (a) => (a.confidence_score ?? 0) >= 0.65 && (a.confidence_score ?? 0) <= 0.85,
  )
  if (med) return 'MEDIUM'
  return 'LOW'
}

const KIND_COLOR: Record<FindingKind, string> = {
  anomaly: 'var(--flag)',
  obstruction: 'var(--sus)',
  charge: 'var(--carved)',
  summary: 'var(--text-muted)',
  other: 'var(--text-muted)',
}

const KIND_LABEL: Record<FindingKind, string> = {
  anomaly: 'Anomaly',
  obstruction: 'Obstruction',
  charge: 'Charge',
  summary: 'Summary',
  other: 'Advisory',
}

export default function AdvisoryView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const [artifacts, setArtifacts] = useState<Artifact[]>([])
  const [loading, setLoading] = useState(false)
  const [pluginsNotRun, setPluginsNotRun] = useState(false)

  useEffect(() => {
    if (!evidenceId) return
    setLoading(true)
    getArtifacts(evidenceId, 'Advisory')
      .then((res) => {
        setArtifacts(res.artifacts)
        setPluginsNotRun(res.plugins_not_run)
      })
      .finally(() => setLoading(false))
  }, [evidenceId])

  const grouped = useMemo(() => {
    const map: Record<FindingKind, Artifact[]> = {
      anomaly: [],
      obstruction: [],
      charge: [],
      summary: [],
      other: [],
    }
    for (const a of artifacts) {
      map[classify(a)].push(a)
    }
    return map
  }, [artifacts])

  const risk = useMemo(() => riskFor(artifacts), [artifacts])

  if (!evidenceLoaded || !evidenceId) {
    return (
      <EmptyState
        icon={'\u{1F9E0}'}
        title="ML Advisory Review"
        subtitle="Run the Advisory plugin to surface ML findings"
      />
    )
  }

  const riskColor =
    risk === 'HIGH' ? 'var(--flag)' : risk === 'MEDIUM' ? 'var(--sus)' : 'var(--text-2)'

  return (
    <div
      style={{
        flex: 1,
        background: 'var(--bg-base)',
        padding: 8,
        display: 'flex',
        gap: 8,
        overflow: 'hidden',
      }}
    >
      <div
        className="bubble"
        style={{
          width: 240,
          display: 'flex',
          flexDirection: 'column',
          flexShrink: 0,
        }}
      >
        <SectionHeader>Summary</SectionHeader>
        <div style={{ padding: 14, overflowY: 'auto', flex: 1 }}>
          <div
            style={{
              fontSize: 9,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              marginBottom: 4,
            }}
          >
            Risk Level
          </div>
          <div
            style={{
              fontSize: 24,
              fontWeight: 700,
              color: riskColor,
              fontFamily: 'monospace',
              marginBottom: 16,
            }}
          >
            {risk}
          </div>
          <SummaryCount label="Anomalies" count={grouped.anomaly.length} color="var(--flag)" />
          <SummaryCount
            label="Obstructions"
            count={grouped.obstruction.length}
            color="var(--sus)"
          />
          <SummaryCount label="Charges" count={grouped.charge.length} color="var(--carved)" />
          <SummaryCount label="Summaries" count={grouped.summary.length} color="var(--text-muted)" />
          <div style={{ height: 1, background: 'var(--border-sub)', margin: '14px 0' }} />
          <div
            style={{
              fontSize: 10,
              color: 'var(--sus)',
              padding: '8px 10px',
              background: 'rgba(184,120,64,0.08)',
              border: '1px solid rgba(184,120,64,0.3)',
              borderRadius: 4,
              lineHeight: 1.5,
            }}
          >
            {'⚠'} ML findings are advisory. They require examiner verification before legal use.
          </div>
        </div>
      </div>

      <div className="bubble" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <SectionHeader>Findings</SectionHeader>
        <div style={{ flex: 1, overflowY: 'auto', padding: 12 }}>
          {loading ? (
            <Center>Loading advisory findings...</Center>
          ) : pluginsNotRun ? (
            <Center>Run Advisory plugin first</Center>
          ) : artifacts.length === 0 ? (
            <Center>No advisory findings</Center>
          ) : (
            (
              ['anomaly', 'obstruction', 'charge', 'summary', 'other'] as FindingKind[]
            ).map((kind) =>
              grouped[kind].length === 0 ? null : (
                <div key={kind} style={{ marginBottom: 16 }}>
                  <div
                    style={{
                      fontSize: 10,
                      color: KIND_COLOR[kind],
                      textTransform: 'uppercase',
                      letterSpacing: '0.1em',
                      fontWeight: 700,
                      marginBottom: 6,
                    }}
                  >
                    {KIND_LABEL[kind]} {'·'} {grouped[kind].length}
                  </div>
                  {grouped[kind].map((a) => (
                    <FindingCard key={a.id} artifact={a} kind={kind} />
                  ))}
                </div>
              ),
            )
          )}
        </div>
      </div>
    </div>
  )
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        padding: '7px 10px',
        fontSize: 9,
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        borderBottom: '1px solid var(--border-sub)',
        flexShrink: 0,
      }}
    >
      {children}
    </div>
  )
}

function SummaryCount({
  label,
  count,
  color,
}: {
  label: string
  count: number
  color: string
}) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'baseline',
        marginBottom: 8,
      }}
    >
      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{label}</span>
      <span style={{ fontSize: 14, fontWeight: 700, color, fontFamily: 'monospace' }}>
        {count}
      </span>
    </div>
  )
}

function FindingCard({ artifact, kind }: { artifact: Artifact; kind: FindingKind }) {
  const conf = artifact.confidence_score ?? 1
  const color = KIND_COLOR[kind]
  const mitre = artifact.mitre_technique
  return (
    <div
      style={{
        padding: 10,
        marginBottom: 8,
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${color}`,
        borderRadius: 4,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 4 }}>
        <span
          style={{
            fontSize: 9,
            padding: '1px 6px',
            borderRadius: 3,
            background: 'transparent',
            border: `1px solid ${color}`,
            color,
            fontFamily: 'monospace',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
          }}
        >
          {KIND_LABEL[kind]}
        </span>
        <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-1)' }}>
          {artifact.name}
        </span>
        <div style={{ flex: 1 }} />
        {mitre && (
          <a
            href={`https://attack.mitre.org/techniques/${mitre.replace('.', '/')}/`}
            target="_blank"
            rel="noreferrer"
            style={{
              fontSize: 9,
              fontFamily: 'monospace',
              padding: '1px 6px',
              borderRadius: 3,
              background: 'rgba(74,120,144,0.15)',
              border: '1px solid rgba(74,120,144,0.3)',
              color: 'var(--carved)',
              textDecoration: 'none',
            }}
          >
            {mitre}
          </a>
        )}
      </div>
      <div
        style={{
          fontSize: 11,
          color: 'var(--text-2)',
          marginBottom: 8,
          lineHeight: 1.5,
        }}
      >
        {artifact.value}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span
          style={{
            fontSize: 9,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
          }}
        >
          Confidence
        </span>
        <div
          style={{
            flex: 1,
            height: 4,
            background: 'var(--bg-panel)',
            borderRadius: 2,
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              width: `${Math.min(100, Math.max(0, conf * 100))}%`,
              height: '100%',
              background: color,
            }}
          />
        </div>
        <span
          style={{
            fontSize: 10,
            fontFamily: 'monospace',
            color: 'var(--text-2)',
            minWidth: 32,
            textAlign: 'right',
          }}
        >
          {conf.toFixed(2)}
        </span>
        <span
          style={{
            fontSize: 9,
            color: 'var(--text-muted)',
            fontFamily: 'monospace',
          }}
        >
          via {artifact.plugin}
        </span>
      </div>
    </div>
  )
}

function Center({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        textAlign: 'center',
        color: 'var(--text-muted)',
        fontSize: 12,
        padding: 24,
      }}
    >
      {children}
    </div>
  )
}
