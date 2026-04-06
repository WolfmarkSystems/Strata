import { useState, useMemo } from 'react'
import type { FileEntry } from '../types'
import { useAppStore } from '../store/appStore'
import { tagFile, untagFile } from '../ipc'
import ContextMenu from './ContextMenu'

interface Props {
  files: FileEntry[]
  selectedFileId: string | null
  onFileSelect: (file: FileEntry) => void
}

const TAG_COLOR_MAP: Record<string, string> = {
  'Critical Evidence': '#a84040',
  'Suspicious':        '#b87840',
  'Needs Review':      '#b8a840',
  'Confirmed Clean':   '#487858',
  'Key Artifact':      '#4a7890',
  'Excluded':          '#3a4858',
}

interface ContextMenuState {
  x: number
  y: number
  file: FileEntry
}

type SortCol = 'name' | 'size' | 'modified' | 'created' | 'sha256'

const COLS: { id: SortCol; label: string; flex: number }[] = [
  { id: 'name',     label: 'Name',     flex: 3 },
  { id: 'size',     label: 'Size',     flex: 1 },
  { id: 'modified', label: 'Modified', flex: 2 },
  { id: 'created',  label: 'Created',  flex: 2 },
  { id: 'sha256',   label: 'SHA-256',  flex: 2 },
]

export default function FileListing({ files, selectedFileId, onFileSelect }: Props) {
  const [sortCol, setSortCol] = useState<SortCol>('name')
  const [sortAsc, setSortAsc] = useState(true)
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null)
  const taggedFiles = useAppStore((s) => s.taggedFiles)
  const setFileTag = useAppStore((s) => s.setFileTag)
  const removeFileTag = useAppStore((s) => s.removeFileTag)

  const sorted = useMemo(() => {
    const arr = [...files]
    arr.sort((a, b) => {
      let cmp = 0
      switch (sortCol) {
        case 'name':     cmp = a.name.localeCompare(b.name); break
        case 'size':     cmp = a.size - b.size; break
        case 'modified': cmp = a.modified.localeCompare(b.modified); break
        case 'created':  cmp = a.created.localeCompare(b.created); break
        case 'sha256':   cmp = (a.sha256 ?? '').localeCompare(b.sha256 ?? ''); break
      }
      return sortAsc ? cmp : -cmp
    })
    return arr
  }, [files, sortCol, sortAsc])

  const handleSort = (col: SortCol) => {
    if (col === sortCol) setSortAsc(!sortAsc)
    else {
      setSortCol(col)
      setSortAsc(true)
    }
  }

  return (
    <div
      style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: 'var(--bg-base)',
      }}
    >
      {/* Column headers */}
      <div
        style={{
          display: 'flex',
          background: '#0a0c12',
          borderBottom: '1px solid var(--border-sub)',
          flexShrink: 0,
        }}
      >
        {COLS.map((col) => {
          const active = sortCol === col.id
          return (
            <div
              key={col.id}
              onClick={() => handleSort(col.id)}
              style={{
                flex: col.flex,
                padding: '7px 10px',
                fontSize: 10,
                color: active ? 'var(--text-2)' : 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
                cursor: 'pointer',
                userSelect: 'none',
                overflow: 'hidden',
                whiteSpace: 'nowrap',
                textOverflow: 'ellipsis',
              }}
            >
              {col.label}
              {active && (sortAsc ? ' \u2191' : ' \u2193')}
            </div>
          )
        })}
      </div>

      {/* File rows */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {sorted.length === 0 ? (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              height: '100%',
              fontSize: 13,
              color: 'var(--text-muted)',
            }}
          >
            Select a folder in the tree
          </div>
        ) : (
          sorted.map((file) => (
            <FileRow
              key={file.id}
              file={file}
              selected={selectedFileId === file.id}
              tagName={taggedFiles[file.id] ?? null}
              onClick={() => onFileSelect(file)}
              onContextMenu={(e) => {
                e.preventDefault()
                setContextMenu({ x: e.clientX, y: e.clientY, file })
              }}
            />
          ))
        )}
      </div>

      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          fileId={contextMenu.file.id}
          fileName={contextMenu.file.name}
          currentTag={taggedFiles[contextMenu.file.id] ?? null}
          onTag={async (tag, color) => {
            const f = contextMenu.file
            await tagFile(
              f.id,
              f.name,
              f.extension,
              f.size_display,
              f.modified,
              f.name, // full_path placeholder — FileEntry doesn't carry full path
              tag,
              color,
            )
            setFileTag(f.id, tag)
            setContextMenu(null)
          }}
          onUntag={async () => {
            await untagFile(contextMenu.file.id)
            removeFileTag(contextMenu.file.id)
            setContextMenu(null)
          }}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  )
}

function FileRow({
  file,
  selected,
  tagName,
  onClick,
  onContextMenu,
}: {
  file: FileEntry
  selected: boolean
  tagName: string | null
  onClick: () => void
  onContextMenu: (e: React.MouseEvent) => void
}) {
  const [hover, setHover] = useState(false)

  let nameColor: string = 'var(--text-2)'
  if (file.is_flagged) nameColor = 'var(--flag)'
  else if (file.is_suspicious) nameColor = 'var(--sus)'

  const deletedStyle: React.CSSProperties = file.is_deleted
    ? { textDecoration: 'line-through', color: 'var(--text-off)' }
    : {}

  let bg = 'transparent'
  if (selected) bg = '#0f1e30'
  else if (hover) bg = '#0f1420'

  // Tag dot color: use store-based tagName first, fall back to file.tag_color
  const tagDotColor = tagName ? TAG_COLOR_MAP[tagName] : file.tag_color

  return (
    <div
      onClick={onClick}
      onContextMenu={onContextMenu}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex',
        alignItems: 'center',
        minHeight: 28,
        borderBottomStyle: 'solid',
        borderBottomWidth: 1,
        borderBottomColor: '#0d1018',
        cursor: 'pointer',
        background: bg,
        transition: 'background 0.1s',
      }}
    >
      {/* Name */}
      <div
        style={{
          flex: 3,
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '6px 10px',
          overflow: 'hidden',
        }}
      >
        {tagDotColor && (
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: tagDotColor,
              flexShrink: 0,
            }}
          />
        )}
        <ExtBadge ext={file.extension} />
        <span
          style={{
            flex: 1,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            fontSize: 13,
            color: nameColor,
            ...deletedStyle,
          }}
        >
          {file.name}
        </span>
      </div>

      {/* Size */}
      <Cell flex={1}>{file.size_display}</Cell>
      <Cell flex={2}>{file.modified}</Cell>
      <Cell flex={2}>{file.created}</Cell>
      <Cell flex={2} mono>
        {file.sha256 ?? '\u2014'}
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
        padding: '6px 10px',
        fontSize: mono ? 10 : 12,
        color: 'var(--text-muted)',
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

interface BadgeColors {
  bg: string
  border: string
  color: string
}

function badgeColorsFor(ext: string): BadgeColors {
  const e = ext.toLowerCase()
  if (['exe', 'dll', 'sys'].includes(e))
    return { bg: 'rgba(168,64,64,0.15)', border: 'rgba(168,64,64,0.5)', color: '#a84040' }
  if (['log', 'evtx'].includes(e))
    return { bg: 'rgba(74,120,144,0.15)', border: 'rgba(74,120,144,0.5)', color: '#4a7890' }
  if (['reg', 'hiv', 'dat'].includes(e))
    return { bg: 'rgba(96,88,120,0.15)', border: 'rgba(96,88,120,0.5)', color: '#605878' }
  if (e === 'lnk')
    return { bg: 'rgba(184,120,64,0.15)', border: 'rgba(184,120,64,0.5)', color: '#b87840' }
  if (['zip', 'rar', '7z'].includes(e))
    return { bg: 'rgba(120,96,64,0.15)', border: 'rgba(120,96,64,0.5)', color: '#786040' }
  if (['ps1', 'bat', 'cmd'].includes(e))
    return { bg: 'rgba(184,120,64,0.2)', border: 'rgba(184,120,64,0.6)', color: '#b87840' }
  if (['pdf', 'doc', 'docx'].includes(e))
    return { bg: 'rgba(96,88,120,0.15)', border: 'rgba(96,88,120,0.5)', color: '#605878' }
  return { bg: 'rgba(58,72,88,0.15)', border: 'rgba(58,72,88,0.5)', color: '#3a4858' }
}

function ExtBadge({ ext }: { ext: string }) {
  const c = badgeColorsFor(ext)
  const label = ext ? ext.toUpperCase() : '\u2014'
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '1px 5px',
        borderRadius: 3,
        fontSize: 9,
        fontFamily: 'monospace',
        flexShrink: 0,
        background: c.bg,
        border: `1px solid ${c.border}`,
        color: c.color,
        minWidth: 24,
        textAlign: 'center',
      }}
    >
      {label}
    </span>
  )
}
