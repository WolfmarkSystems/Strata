import { useState } from 'react'
import { useAppStore } from '../store/appStore'
import type { ViewMode } from '../types'

interface NavItem {
  id: ViewMode
  icon: string
  label: string
  badge?: number
  badgeColor?: string
  restricted?: boolean
}

interface NavSection {
  title: string
  items: NavItem[]
}

export default function Sidebar() {
  const view = useAppStore((s) => s.view)
  const setView = useAppStore((s) => s.setView)
  const stats = useAppStore((s) => s.stats)
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)

  // Counts only show after evidence is processed
  const showCounts = evidenceLoaded && stats.artifacts > 0

  const sections: NavSection[] = [
    {
      title: 'Case',
      items: [
        { id: 'dashboard', icon: '\u{1F3E0}', label: 'Overview' },
        { id: 'files', icon: '\u{1F4C1}', label: 'Files' },
      ],
    },
    {
      title: 'Artifacts',
      items: [
        { id: 'artifacts', icon: '\u{1F5C2}', label: 'All Artifacts' },
        { id: 'timeline', icon: '\u{1F552}', label: 'Timeline' },
        {
          id: 'tags',
          icon: '\u{1F3F7}',
          label: 'Flagged',
          badge: showCounts ? stats.flagged : undefined,
        },
      ],
    },
    {
      title: 'Investigation',
      items: [
        { id: 'ioc', icon: '\u{1F50E}', label: 'IOC Hunt' },
        { id: 'darkweb', icon: '\u{1F47B}', label: 'Dark Web' },
        { id: 'crypto', icon: '₿', label: 'Cryptocurrency' },
        { id: 'financial', icon: '\u{1F4B5}', label: 'Financial' },
        { id: 'linux', icon: '\u{1F427}', label: 'Linux' },
      ],
    },
    {
      title: 'Review',
      items: [
        {
          id: 'advisory',
          icon: '\u{1F9E0}',
          label: 'Advisory',
        },
        {
          id: 'csam',
          icon: '\u{1F512}',
          label: 'CSAM (Restricted)',
          restricted: true,
        },
        { id: 'charges', icon: '\u{2696}', label: 'Charges' },
        { id: 'warrant', icon: '\u{1F4DC}', label: 'Warrant' },
      ],
    },
    {
      title: 'Evidence',
      items: [
        { id: 'custody', icon: '\u{1F4DC}', label: 'Chain of Custody' },
        { id: 'notes', icon: '\u{1F4DD}', label: 'Notes' },
      ],
    },
    {
      title: 'Tools',
      items: [
        { id: 'plugins', icon: '\u{1F50C}', label: 'Plugins' },
        { id: 'settings', icon: '\u{2699}', label: 'Settings' },
      ],
    },
  ]

  return (
    <div
      className="bubble"
      style={{
        width: 84,
        height: '100%',
        alignSelf: 'stretch',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'stretch',
        padding: '10px 0',
        flexShrink: 0,
        overflowY: 'auto',
      }}
    >
      {sections.map((section, idx) => (
        <div key={section.title}>
          {idx > 0 && (
            <div
              style={{
                height: 1,
                background: 'var(--border-sub)',
                margin: '8px 12px',
              }}
            />
          )}
          <div
            style={{
              fontSize: 8,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.12em',
              textAlign: 'center',
              padding: '4px 0',
              fontWeight: 700,
            }}
          >
            {section.title}
          </div>
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 4,
              padding: '2px 0',
            }}
          >
            {section.items.map((item) => (
              <SidebarIcon
                key={item.id}
                item={item}
                active={view === item.id}
                onClick={() => setView(item.id)}
              />
            ))}
          </div>
        </div>
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
  const borderColor = active
    ? 'var(--accent-2)'
    : hover
      ? 'var(--border)'
      : 'transparent'

  const tooltip = item.restricted ? `${item.label} - RESTRICTED` : item.label
  const showBadge = item.badge !== undefined && item.badge > 0
  const badgeColor = item.badgeColor ?? 'var(--sus)'

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      title={tooltip}
      style={{
        position: 'relative',
        width: 60,
        minHeight: 44,
        borderRadius: 'var(--radius-md)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 1,
        cursor: 'pointer',
        border: `1px solid ${borderColor}`,
        background: bg,
        color,
        transition: 'all 0.15s',
        padding: '4px 2px',
      }}
    >
      <span style={{ fontSize: 18, lineHeight: 1 }}>{item.icon}</span>
      <span
        style={{
          fontSize: 8,
          letterSpacing: '0.04em',
          color,
          textAlign: 'center',
          maxWidth: 56,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {item.label}
      </span>
      {showBadge && (
        <span
          style={{
            position: 'absolute',
            top: 2,
            right: 4,
            minWidth: 14,
            height: 14,
            padding: '0 4px',
            background: badgeColor,
            color: 'var(--bg-base)',
            fontSize: 9,
            fontWeight: 700,
            fontFamily: 'monospace',
            borderRadius: 7,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          {item.badge && item.badge > 99 ? '99+' : item.badge}
        </span>
      )}
      {item.restricted && (
        <span
          style={{
            position: 'absolute',
            top: 2,
            left: 4,
            width: 6,
            height: 6,
            background: 'var(--flag)',
            borderRadius: '50%',
          }}
        />
      )}
    </button>
  )
}
