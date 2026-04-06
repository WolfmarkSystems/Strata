import { useEffect, useState } from 'react'
import type { PluginInfo } from '../types'
import type { PluginStatus } from '../ipc'

interface Props {
  plugin: PluginInfo
  status: PluginStatus | undefined
  isSelected: boolean
  onSelect: () => void
  onRun: () => void
  evidenceLoaded: boolean
}

const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

// Convert hex color to rgba with given alpha
function hexToRgba(hex: string, alpha: number): string {
  const h = hex.replace('#', '')
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

export default function PluginCard({
  plugin,
  status,
  isSelected,
  onSelect,
  onRun,
  evidenceLoaded,
}: Props) {
  const [hover, setHover] = useState(false)
  const [runHover, setRunHover] = useState(false)
  const [frame, setFrame] = useState(0)

  const isRunning = status?.status === 'running'
  const isComplete = status?.status === 'complete'
  const isError = status?.status === 'error'

  useEffect(() => {
    if (!isRunning) return
    const t = setInterval(() => setFrame((f) => (f + 1) % SPINNER.length), 150)
    return () => clearInterval(t)
  }, [isRunning])

  const accent = plugin.accent_color
  const bg = isSelected ? '#0f1e30' : hover ? '#111622' : 'var(--bg-elevated)'
  const borderColor = isSelected ? '#1c3050' : 'var(--border)'

  const runDisabled = !evidenceLoaded || isRunning
  const runLabel = isRunning ? 'RUNNING...' : isComplete ? 'RE-RUN' : 'RUN'

  return (
    <div
      onClick={onSelect}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        background: bg,
        border: `1px solid ${borderColor}`,
        borderRadius: 6,
        padding: '12px 14px 12px 17px',
        cursor: 'pointer',
        transition: 'background 0.1s, border-color 0.1s',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Accent bar (replaces borderLeft to avoid React shorthand warning) */}
      <div
        style={{
          position: 'absolute',
          top: 0,
          bottom: 0,
          left: 0,
          width: 4,
          background: accent,
        }}
      />

      {/* Progress bar */}
      {isRunning && (
        <div
          style={{
            position: 'absolute',
            bottom: 0,
            left: 0,
            height: 2,
            background: accent,
            width: `${status?.progress ?? 0}%`,
            transition: 'width 0.3s ease',
            opacity: 0.8,
          }}
        />
      )}

      {/* Row 1 — Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 4,
        }}
      >
        <span style={{ fontSize: 13, fontWeight: 700, color: accent }}>{plugin.name}</span>
        <span
          style={{
            fontSize: 10,
            color: 'var(--text-muted)',
            background: 'var(--bg-panel)',
            padding: '1px 5px',
            borderRadius: 3,
            fontFamily: 'monospace',
          }}
        >
          {plugin.version}
        </span>
        <span
          style={{
            fontSize: 9,
            color: 'var(--text-muted)',
            border: '1px solid var(--border)',
            padding: '1px 5px',
            borderRadius: 3,
            marginLeft: 'auto',
          }}
        >
          {plugin.plugin_type}
        </span>
        {isRunning && (
          <span style={{ color: accent, fontSize: 13, fontFamily: 'monospace' }}>
            {SPINNER[frame]}
          </span>
        )}
        {isComplete && <span style={{ color: 'var(--clean)', fontSize: 13 }}>✓</span>}
        {isError && <span style={{ color: 'var(--flag)', fontSize: 13 }}>✗</span>}
      </div>

      {/* Row 2 — Description */}
      <div
        style={{
          fontSize: 11,
          color: 'var(--text-muted)',
          lineHeight: 1.4,
          marginBottom: 8,
          overflow: 'hidden',
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
        }}
      >
        {plugin.short_desc}
      </div>

      {/* Row 3 — Footer */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button
          onClick={(e) => {
            e.stopPropagation()
            if (!runDisabled) onRun()
          }}
          onMouseEnter={() => setRunHover(true)}
          onMouseLeave={() => setRunHover(false)}
          disabled={runDisabled}
          style={{
            padding: '3px 10px',
            borderRadius: 3,
            fontSize: 10,
            fontFamily: 'monospace',
            fontWeight: 700,
            border: `1px solid ${accent}`,
            color: accent,
            background: runHover && !runDisabled ? hexToRgba(accent, 0.15) : 'transparent',
            cursor: runDisabled ? 'not-allowed' : 'pointer',
            transition: 'all 0.15s',
            opacity: runDisabled ? 0.3 : 1,
          }}
        >
          {runLabel}
        </button>

        {isComplete && (
          <span
            style={{
              marginLeft: 'auto',
              fontSize: 11,
              color: (status?.artifact_count ?? 0) > 0 ? accent : 'var(--text-muted)',
            }}
          >
            {status?.artifact_count} artifacts
          </span>
        )}
      </div>
    </div>
  )
}
