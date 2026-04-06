import { useEffect, useState } from 'react'
import type { PluginInfo } from '../types'
import type { PluginStatus } from '../ipc'

interface Props {
  plugin: PluginInfo | null
  status: PluginStatus | undefined
  onRun: () => void
  evidenceLoaded: boolean
}

const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

function hexToRgba(hex: string, alpha: number): string {
  const h = hex.replace('#', '')
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

export default function PluginDetailPane({
  plugin,
  status,
  onRun,
  evidenceLoaded,
}: Props) {
  const [frame, setFrame] = useState(0)
  const [runHover, setRunHover] = useState(false)

  const isRunning = status?.status === 'running'
  const isComplete = status?.status === 'complete'
  const isError = status?.status === 'error'

  useEffect(() => {
    if (!isRunning) return
    const t = setInterval(() => setFrame((f) => (f + 1) % SPINNER.length), 150)
    return () => clearInterval(t)
  }, [isRunning])

  if (!plugin) {
    return (
      <div
        style={{
          width: 300,
          minWidth: 300,
          background: '#0a0c12',
          borderLeftStyle: 'solid',
          borderLeftWidth: 1,
          borderLeftColor: 'var(--border-sub)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 13,
          color: 'var(--text-muted)',
          flexShrink: 0,
          padding: 12,
          textAlign: 'center',
        }}
      >
        Select a plugin to view details
      </div>
    )
  }

  const accent = plugin.accent_color
  const runDisabled = !evidenceLoaded || isRunning
  const runLabel = isRunning
    ? `RUNNING ${status?.progress ?? 0}%`
    : isComplete
      ? `RE-RUN STRATA ${plugin.name.toUpperCase()}`
      : `RUN STRATA ${plugin.name.toUpperCase()}`

  return (
    <div
      style={{
        width: 300,
        minWidth: 300,
        background: '#0a0c12',
        borderLeft: '1px solid var(--border-sub)',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        flexShrink: 0,
      }}
    >
      {/* Accent bar */}
      <div style={{ height: 3, background: accent, flexShrink: 0 }} />

      {/* Scroll area */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
        {/* Header */}
        <div style={{ fontSize: 16, fontWeight: 700, color: accent, marginBottom: 2 }}>
          {plugin.name}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {plugin.version} · Type: {plugin.plugin_type}
        </div>

        {/* Status indicator */}
        {status && status.status !== 'idle' && (
          <div style={{ marginTop: 8 }}>
            {isRunning && (
              <div
                style={{
                  padding: '6px 10px',
                  borderRadius: 4,
                  fontSize: 11,
                  background: hexToRgba(accent, 0.1),
                  border: `1px solid ${hexToRgba(accent, 0.3)}`,
                  color: accent,
                }}
              >
                <div>
                  {SPINNER[frame]} Running... {status.progress}%
                </div>
                <div
                  style={{
                    height: 3,
                    background: accent,
                    width: `${status.progress}%`,
                    transition: 'width 0.3s',
                    marginTop: 6,
                    borderRadius: 2,
                  }}
                />
              </div>
            )}
            {isComplete && (
              <div
                style={{
                  padding: '6px 10px',
                  borderRadius: 4,
                  fontSize: 11,
                  background: 'rgba(72,120,88,0.1)',
                  border: '1px solid rgba(72,120,88,0.3)',
                  color: 'var(--clean)',
                }}
              >
                ✓ Complete — {status.artifact_count} artifacts found
              </div>
            )}
            {isError && (
              <div
                style={{
                  padding: '6px 10px',
                  borderRadius: 4,
                  fontSize: 11,
                  background: 'rgba(168,64,64,0.1)',
                  border: '1px solid rgba(168,64,64,0.3)',
                  color: 'var(--flag)',
                }}
              >
                ✗ Error
              </div>
            )}
          </div>
        )}

        <Sep />

        <SectionLabel>WHAT IT DOES</SectionLabel>
        <div
          style={{
            fontSize: 12,
            color: 'var(--text-2)',
            lineHeight: 1.7,
          }}
        >
          {plugin.full_desc}
        </div>

        <Sep />

        <SectionLabel>FORENSIC CATEGORIES</SectionLabel>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {plugin.categories.map((c) => (
            <span
              key={c}
              style={{
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border)',
                borderRadius: 3,
                padding: '2px 8px',
                fontSize: 10,
                color: 'var(--text-2)',
                fontFamily: 'monospace',
              }}
            >
              {c}
            </span>
          ))}
        </div>

        <Sep />

        <SectionLabel>MITRE COVERAGE</SectionLabel>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {plugin.mitre.map((m) => (
            <span
              key={m}
              style={{
                background: 'rgba(74,120,144,0.1)',
                border: '1px solid rgba(74,120,144,0.3)',
                borderRadius: 3,
                padding: '2px 8px',
                fontSize: 10,
                color: 'var(--carved)',
                fontFamily: 'monospace',
                cursor: 'pointer',
              }}
            >
              {m}
            </span>
          ))}
        </div>

        <Sep />

        <SectionLabel>CHANGELOG</SectionLabel>
        {plugin.changelog.map((entry, idx) => (
          <div key={idx} style={{ marginBottom: idx < plugin.changelog.length - 1 ? 10 : 0 }}>
            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                color: 'var(--text-2)',
                fontFamily: 'monospace',
                marginBottom: 4,
              }}
            >
              {entry.version}
            </div>
            {entry.changes.map((c, i) => (
              <div
                key={i}
                style={{
                  fontSize: 11,
                  color: 'var(--text-muted)',
                  lineHeight: 1.6,
                  paddingLeft: 12,
                  position: 'relative',
                }}
              >
                <span style={{ position: 'absolute', left: 2 }}>·</span>
                {c}
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* Footer with run button */}
      <div
        style={{
          borderTop: '1px solid var(--border-sub)',
          padding: '12px 14px',
          flexShrink: 0,
        }}
      >
        <button
          onClick={onRun}
          onMouseEnter={() => setRunHover(true)}
          onMouseLeave={() => setRunHover(false)}
          disabled={runDisabled}
          style={{
            width: '100%',
            padding: 10,
            background: runHover && !runDisabled ? hexToRgba(accent, 0.1) : 'var(--bg-elevated)',
            border: `1px solid ${accent}`,
            borderRadius: 5,
            color: accent,
            fontSize: 13,
            fontFamily: 'monospace',
            fontWeight: 700,
            letterSpacing: '0.06em',
            cursor: runDisabled ? 'not-allowed' : 'pointer',
            transition: 'all 0.15s',
            opacity: runDisabled ? 0.4 : 1,
          }}
        >
          {runLabel}
        </button>
      </div>
    </div>
  )
}

function Sep() {
  return <div style={{ height: 1, background: 'var(--border-sub)', margin: '12px 0' }} />
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: 9,
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        marginBottom: 8,
      }}
    >
      {children}
    </div>
  )
}
