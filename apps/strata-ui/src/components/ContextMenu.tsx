import { useEffect, useState } from 'react'
import { useAppStore } from '../store/appStore'

interface Props {
  x: number
  y: number
  fileId: string
  fileName: string
  currentTag: string | null
  onTag: (tag: string, color: string) => void
  onUntag: () => void
  onClose: () => void
}

const TAG_OPTIONS: Array<{ name: string; color: string }> = [
  { name: 'Critical Evidence', color: '#a84040' },
  { name: 'Suspicious',        color: '#b87840' },
  { name: 'Needs Review',      color: '#b8a840' },
  { name: 'Confirmed Clean',   color: '#487858' },
  { name: 'Key Artifact',      color: '#4a7890' },
  { name: 'Excluded',          color: '#3a4858' },
]

export default function ContextMenu({
  x,
  y,
  fileId,
  fileName,
  currentTag,
  onTag,
  onUntag,
  onClose,
}: Props) {
  const setView = useAppStore((s) => s.setView)
  const setSelectedFile = useAppStore((s) => s.setSelectedFile)

  // Position clamping
  const menuWidth = 220
  const menuHeight = currentTag ? 320 : 290
  let clampedX = x
  let clampedY = y
  if (x + menuWidth > window.innerWidth) clampedX = x - menuWidth
  if (y + menuHeight > window.innerHeight) clampedY = y - menuHeight
  if (clampedX < 0) clampedX = 4
  if (clampedY < 0) clampedY = 4

  // Click outside to close
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      const target = e.target as HTMLElement
      if (!target.closest('[data-context-menu]')) onClose()
    }
    // Defer attaching to avoid catching the right-click that opened us
    const t = setTimeout(() => document.addEventListener('mousedown', handler), 0)
    return () => {
      clearTimeout(t)
      document.removeEventListener('mousedown', handler)
    }
  }, [onClose])

  // Escape to close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div
      data-context-menu
      style={{
        position: 'fixed',
        left: clampedX,
        top: clampedY,
        zIndex: 1000,
        background: '#0f1420',
        borderStyle: 'solid',
        borderWidth: 1,
        borderColor: 'var(--border)',
        borderRadius: 6,
        minWidth: menuWidth,
        overflow: 'hidden',
        boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
      }}
    >
      {/* Header (file name) */}
      <div
        style={{
          padding: '6px 12px',
          fontSize: 11,
          color: 'var(--text-muted)',
          borderBottomStyle: 'solid',
          borderBottomWidth: 1,
          borderBottomColor: 'var(--border)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {fileName}
      </div>

      {/* Tag as label */}
      <div
        style={{
          padding: '5px 12px 3px',
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
        }}
      >
        Tag as:
      </div>

      {/* Tag options */}
      {TAG_OPTIONS.map((tag) => (
        <TagRow
          key={tag.name}
          name={tag.name}
          color={tag.color}
          isCurrent={currentTag === tag.name}
          onClick={() => onTag(tag.name, tag.color)}
        />
      ))}

      {/* Separator + remove (only if currently tagged) */}
      {currentTag && (
        <>
          <Separator />
          <MenuItem onClick={onUntag} color="var(--flag)">
            Remove tag
          </MenuItem>
        </>
      )}

      {/* Separator + view in file explorer */}
      <Separator />
      <MenuItem
        onClick={() => {
          setView('files')
          setSelectedFile(fileId)
          onClose()
        }}
      >
        View in File Explorer
      </MenuItem>
    </div>
  )
}

function TagRow({
  name,
  color,
  isCurrent,
  onClick,
}: {
  name: string
  color: string
  isCurrent: boolean
  onClick: () => void
}) {
  const [hover, setHover] = useState(false)
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        padding: '7px 12px',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        cursor: 'pointer',
        fontSize: 12,
        color: 'var(--text-2)',
        background: isCurrent ? '#0f1e30' : hover ? '#1a2030' : 'transparent',
        transition: 'background 0.1s',
      }}
    >
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: color,
          flexShrink: 0,
        }}
      />
      <span style={{ flex: 1 }}>{name}</span>
      {isCurrent && <span style={{ color, fontSize: 12, fontWeight: 700 }}>{'\u2713'}</span>}
    </div>
  )
}

function Separator() {
  return <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />
}

function MenuItem({
  onClick,
  color = 'var(--text-2)',
  children,
}: {
  onClick: () => void
  color?: string
  children: React.ReactNode
}) {
  const [hover, setHover] = useState(false)
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        padding: '7px 12px',
        cursor: 'pointer',
        fontSize: 12,
        color,
        background: hover ? '#1a2030' : 'transparent',
        transition: 'background 0.1s',
      }}
    >
      {children}
    </div>
  )
}
