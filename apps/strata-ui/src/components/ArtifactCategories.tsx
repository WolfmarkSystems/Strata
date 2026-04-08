import { useState } from 'react'
import type { ArtifactCategory } from '../ipc'

interface Props {
  categories: ArtifactCategory[]
  selectedCat: string | null
  onSelect: (name: string) => void
}

function hexToRgba(hex: string, alpha: number): string {
  const h = hex.replace('#', '')
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

export default function ArtifactCategories({ categories, selectedCat, onSelect }: Props) {
  // Sort: count > 0 first (desc), then count === 0 below
  const sorted = [...categories].sort((a, b) => {
    if (a.count === 0 && b.count === 0) return 0
    if (a.count === 0) return 1
    if (b.count === 0) return -1
    return b.count - a.count
  })

  return (
    <div
      className="bubble"
      style={{
        height: '100%',
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <div
        style={{
          padding: '7px 10px',
          fontSize: 9,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
          borderBottomStyle: 'solid',
          borderBottomWidth: 1,
          borderBottomColor: 'var(--border-sub)',
          flexShrink: 0,
        }}
      >
        Categories
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {sorted.map((cat) => (
          <CategoryRow
            key={cat.name}
            cat={cat}
            selected={selectedCat === cat.name}
            onClick={() => onSelect(cat.name)}
          />
        ))}
      </div>
    </div>
  )
}

function CategoryRow({
  cat,
  selected,
  onClick,
}: {
  cat: ArtifactCategory
  selected: boolean
  onClick: () => void
}) {
  const [hover, setHover] = useState(false)
  const hasResults = cat.count > 0

  let bg = 'transparent'
  if (selected) bg = 'var(--bg-elevated)'
  else if (hover) bg = 'var(--bg-elevated)'

  let nameColor: string = hasResults ? 'var(--text-2)' : 'var(--text-muted)'
  if (selected) nameColor = 'var(--text-1)'
  else if (hover) nameColor = 'var(--text-2)'

  const badgeBg = hasResults ? hexToRgba(cat.color, 0.15) : 'var(--bg-elevated)'
  const badgeBorder = hasResults ? hexToRgba(cat.color, 0.3) : 'var(--border)'
  const badgeColor = hasResults ? cat.color : 'var(--text-off)'

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        padding: '9px 12px',
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        cursor: 'pointer',
        fontSize: 12,
        background: bg,
        transition: 'background 0.1s',
        borderBottomStyle: 'solid',
        borderBottomWidth: 1,
        borderBottomColor: 'rgba(18,22,32,0.5)',
        userSelect: 'none',
      }}
    >
      <span
        style={{
          fontSize: 14,
          width: 20,
          flexShrink: 0,
          textAlign: 'center',
        }}
      >
        {cat.icon}
      </span>
      <span
        style={{
          flex: 1,
          fontSize: 12,
          color: nameColor,
          fontWeight: hasResults ? 700 : 400,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {cat.name}
      </span>
      <span
        style={{
          padding: '1px 7px',
          borderRadius: 3,
          fontSize: 10,
          fontWeight: 700,
          fontFamily: 'monospace',
          flexShrink: 0,
          background: badgeBg,
          borderStyle: 'solid',
          borderWidth: 1,
          borderColor: badgeBorder,
          color: badgeColor,
        }}
      >
        {cat.count}
      </span>
    </div>
  )
}
