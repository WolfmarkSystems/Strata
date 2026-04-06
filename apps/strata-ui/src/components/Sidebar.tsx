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
      style={{
        width: 42,
        background: '#090a0d',
        borderRight: '1px solid var(--border-sub)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: '8px 0',
        gap: 4,
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

  const bg = active ? '#0f1e30' : hover ? '#111622' : 'transparent'
  const color = active ? '#8fa8c0' : hover ? 'var(--text-2)' : 'var(--text-muted)'

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      title={item.label}
      style={{
        width: 30,
        height: 30,
        borderRadius: 5,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 15,
        cursor: 'pointer',
        border: 'none',
        background: bg,
        color,
        transition: 'all 0.15s',
      }}
    >
      {item.icon}
    </button>
  )
}
