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
  { id: 'tags',      icon: '\u{1F3F7}', label: 'Tagged Evidence' },
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
        width: 48,
        background: 'var(--bg-panel)',
        borderRight: '1px solid var(--border-sub)',
        display: 'flex',
        flexDirection: 'column',
        padding: '8px 0',
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
  return (
    <button
      onClick={onClick}
      title={item.label}
      style={{
        width: 32,
        height: 32,
        margin: '4px auto',
        background: active ? '#0f1e30' : 'transparent',
        color: active ? '#8fa8c0' : 'var(--text-muted)',
        border: 'none',
        borderRadius: 6,
        fontSize: 18,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
      onMouseEnter={(e) => {
        if (!active) e.currentTarget.style.background = 'var(--bg-elevated)'
      }}
      onMouseLeave={(e) => {
        if (!active) e.currentTarget.style.background = 'transparent'
      }}
    >
      {item.icon}
    </button>
  )
}
