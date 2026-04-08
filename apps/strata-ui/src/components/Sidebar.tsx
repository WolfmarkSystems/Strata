import { useState } from 'react'
import { useAppStore } from '../store/appStore'
import type { ViewMode } from '../types'

interface NavItem {
  id: ViewMode
  icon: string
  label: string
}

const TOP_ITEMS: NavItem[] = [
  { id: 'files',     icon: '\u{1F4C1}', label: 'Files' },
  { id: 'artifacts', icon: '\u{1F5C2}', label: 'Artifacts' },
  { id: 'tags',      icon: '\u{1F3F7}', label: 'Tags' },
  { id: 'notes',     icon: '\u{1F4DD}', label: 'Notes' },
  { id: 'plugins',   icon: '\u{1F50C}', label: 'Plugins' },
]

const BOTTOM_ITEMS: NavItem[] = [
  { id: 'settings', icon: '\u{2699}', label: 'Settings' },
]

export default function Sidebar() {
  const view = useAppStore((s) => s.view)
  const setView = useAppStore((s) => s.setView)

  return (
    <div
      className="bubble"
      style={{
        width: 72,
        height: '100%',
        alignSelf: 'stretch',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: '14px 0',
        gap: 8,
        flexShrink: 0,
      }}
    >
      {TOP_ITEMS.map((item) => (
        <SidebarIcon
          key={item.id}
          item={item}
          active={view === item.id}
          onClick={() => setView(item.id)}
        />
      ))}

      <div style={{ flex: 1 }} />

      {BOTTOM_ITEMS.map((item) => (
        <SidebarIcon
          key={item.id}
          item={item}
          active={view === item.id}
          onClick={() => setView(item.id)}
        />
      ))}
    </div>
  )
}

function SidebarIcon({
  item,
  active,
  onClick,
}: {
  item: NavItem
  active: boolean
  onClick: () => void
}) {
  const [hover, setHover] = useState(false)

  const bg = active ? 'var(--bg-elevated)' : hover ? 'var(--bg-elevated)' : 'transparent'
  const color = active ? 'var(--text-1)' : hover ? 'var(--text-2)' : 'var(--text-muted)'
  const borderColor = active ? 'var(--accent-2)' : hover ? 'var(--border)' : 'transparent'

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      title={item.label}
      style={{
        width: 48,
        height: 48,
        borderRadius: 'var(--radius-md)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 24,
        cursor: 'pointer',
        border: `1px solid ${borderColor}`,
        background: bg,
        color,
        transition: 'all 0.15s',
        padding: 0,
      }}
    >
      {item.icon}
    </button>
  )
}
