import { useState } from 'react'
import type { ArtifactCategory, Artifact } from '../ipc'
import { useAppStore } from '../store/appStore'

interface Props {
  category: ArtifactCategory | null
  artifacts: Artifact[]
  selectedId: string | null
  onSelect: (a: Artifact) => void
  loading: boolean
}

interface ColumnDef {
  label: string
  flex: number
}

function columnsFor(categoryName: string | undefined): ColumnDef[] {
  switch (categoryName) {
    case 'User Activity':
      return [
        { label: 'Artifact', flex: 3 },
        { label: 'Value',    flex: 2 },
        { label: 'Timestamp', flex: 2 },
        { label: 'Source',   flex: 1 },
      ]
    case 'Execution History':
      return [
        { label: 'Process / Task', flex: 3 },
        { label: 'Value',          flex: 2 },
        { label: 'Timestamp',      flex: 2 },
        { label: 'Source',         flex: 1 },
      ]
    case 'Deleted & Recovered':
      return [
        { label: 'Item',       flex: 3 },
        { label: 'Value',      flex: 2 },
        { label: 'Deleted At', flex: 2 },
        { label: 'Source',     flex: 1 },
      ]
    default:
      return [
        { label: 'Name',      flex: 3 },
        { label: 'Value',     flex: 2 },
        { label: 'Timestamp', flex: 2 },
        { label: 'Source',    flex: 1 },
      ]
  }
}

function pluginFor(artifacts: Artifact[]): string {
  if (artifacts.length === 0) return ''
  const first = artifacts[0].plugin
  return artifacts.every((a) => a.plugin === first) ? first : 'Multiple'
}

export default function ArtifactResults({
  category,
  artifacts,
  selectedId,
  onSelect,
  loading,
}: Props) {
  const setView = useAppStore((s) => s.setView)
  const cols = columnsFor(category?.name)

  return (
    <div
      style={{
        height: '100%',
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: 'var(--bg-base)',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '8px 12px',
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          borderBottomStyle: 'solid',
          borderBottomWidth: 1,
          borderBottomColor: 'var(--border-sub)',
          flexShrink: 0,
          background: 'var(--bg-surface)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}
      >
        <span style={{ flex: 1 }}>
          {category
            ? `${category.name} \u2014 ${artifacts.length} results`
            : 'No category selected'}
        </span>
        {artifacts.length > 0 && (
          <span
            style={{
              fontSize: 10,
              padding: '1px 6px',
              borderRadius: 3,
              background: 'var(--bg-elevated)',
              borderStyle: 'solid',
              borderWidth: 1,
              borderColor: 'var(--border)',
              color: 'var(--text-muted)',
              fontFamily: 'monospace',
              textTransform: 'none',
              letterSpacing: 'normal',
            }}
          >
            via {pluginFor(artifacts)}
          </span>
        )}
      </div>

      {/* Column headers */}
      {category && artifacts.length > 0 && (
        <div
          style={{
            display: 'flex',
            background: '#0a0c12',
            borderBottomStyle: 'solid',
            borderBottomWidth: 1,
            borderBottomColor: 'var(--border-sub)',
            flexShrink: 0,
            fontSize: 10,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
          }}
        >
          {/* Spacer for forensic value bar */}
          <div style={{ width: 4, flexShrink: 0 }} />
          {cols.map((c) => (
            <div
              key={c.label}
              style={{
                flex: c.flex,
                padding: '7px 10px',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {c.label}
            </div>
          ))}
        </div>
      )}

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {!category ? (
          <div
            style={{
              height: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 13,
              color: 'var(--text-muted)',
            }}
          >
            Select a category to view artifacts
          </div>
        ) : loading ? (
          <div
            style={{
              height: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 13,
              color: 'var(--text-muted)',
            }}
          >
            Loading artifacts...
          </div>
        ) : artifacts.length === 0 ? (
          <div
            style={{
              height: '100%',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 6,
              padding: 20,
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: 24 }}>{'\u{1F50D}'}</div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              No {category.name} artifacts found
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-off)' }}>
              Run analysis plugins to discover {category.name} artifacts
            </div>
            <button
              onClick={() => setView('plugins')}
              style={{
                marginTop: 8,
                padding: '5px 12px',
                background: 'var(--bg-elevated)',
                borderStyle: 'solid',
                borderWidth: 1,
                borderColor: 'var(--border)',
                borderRadius: 4,
                color: 'var(--text-2)',
                fontSize: 11,
                fontFamily: 'monospace',
                fontWeight: 700,
                cursor: 'pointer',
                letterSpacing: '0.06em',
              }}
            >
              OPEN PLUGINS {'\u2192'}
            </button>
          </div>
        ) : (
          artifacts.map((a) => (
            <ArtifactRow
              key={a.id}
              artifact={a}
              cols={cols}
              selected={selectedId === a.id}
              onClick={() => onSelect(a)}
            />
          ))
        )}
      </div>
    </div>
  )
}

function ArtifactRow({
  artifact,
  cols,
  selected,
  onClick,
}: {
  artifact: Artifact
  cols: ColumnDef[]
  selected: boolean
  onClick: () => void
}) {
  const [hover, setHover] = useState(false)

  let bg = 'transparent'
  if (selected) bg = '#0f1e30'
  else if (hover) bg = '#0f1420'

  const fvColor =
    artifact.forensic_value === 'high'
      ? 'var(--flag)'
      : artifact.forensic_value === 'medium'
        ? 'var(--sus)'
        : 'var(--text-muted)'

  const isHigh = artifact.forensic_value === 'high'

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex',
        alignItems: 'center',
        minHeight: 32,
        borderBottomStyle: 'solid',
        borderBottomWidth: 1,
        borderBottomColor: '#0d1018',
        cursor: 'pointer',
        background: bg,
        transition: 'background 0.1s',
      }}
    >
      {/* Forensic value bar */}
      <div
        style={{
          width: 4,
          alignSelf: 'stretch',
          background: fvColor,
          flexShrink: 0,
        }}
      />

      {/* Name cell with MITRE badge */}
      <div
        style={{
          flex: cols[0].flex,
          padding: '7px 10px',
          fontSize: 12,
          color: 'var(--text-1)',
          fontWeight: isHigh ? 700 : 400,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
        }}
      >
        <span
          style={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            flex: 1,
            minWidth: 0,
          }}
        >
          {artifact.name}
        </span>
        {artifact.mitre_technique && (
          <span
            style={{
              padding: '1px 5px',
              borderRadius: 3,
              fontSize: 9,
              fontFamily: 'monospace',
              background: 'rgba(74,120,144,0.15)',
              borderStyle: 'solid',
              borderWidth: 1,
              borderColor: 'rgba(74,120,144,0.3)',
              color: 'var(--carved)',
              flexShrink: 0,
            }}
          >
            {artifact.mitre_technique}
          </span>
        )}
      </div>

      <Cell flex={cols[1].flex}>{artifact.value}</Cell>
      <Cell flex={cols[2].flex} mono>
        {artifact.timestamp ?? '\u2014'}
      </Cell>
      <Cell flex={cols[3].flex} mono>
        {artifact.source_file}
      </Cell>
    </div>
  )
}

function Cell({
  flex,
  mono = false,
  children,
}: {
  flex: number
  mono?: boolean
  children: React.ReactNode
}) {
  return (
    <div
      style={{
        flex,
        padding: '7px 10px',
        fontSize: mono ? 11 : 12,
        color: mono ? 'var(--text-muted)' : 'var(--text-2)',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        fontFamily: mono ? 'monospace' : undefined,
      }}
    >
      {children}
    </div>
  )
}
