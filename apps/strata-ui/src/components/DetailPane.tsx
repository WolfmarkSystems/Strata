import { useEffect, useState } from 'react'
import { getFileMetadata } from '../ipc'
import type { FileMetadata } from '../types'

interface Props {
  fileId: string | null
}

type Tab = 'meta' | 'hex' | 'text' | 'image'

const TABS: { id: Tab; label: string }[] = [
  { id: 'meta',  label: 'META' },
  { id: 'hex',   label: 'HEX' },
  { id: 'text',  label: 'TEXT' },
  { id: 'image', label: 'IMAGE' },
]

export default function DetailPane({ fileId }: Props) {
  const [tab, setTab] = useState<Tab>('meta')
  const [meta, setMeta] = useState<FileMetadata | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!fileId) {
      setMeta(null)
      return
    }
    setLoading(true)
    getFileMetadata(fileId).then((m) => {
      setMeta(m)
      setLoading(false)
    })
  }, [fileId])

  return (
    <div
      style={{
        width: 260,
        minWidth: 260,
        background: '#0a0c12',
        borderLeft: '1px solid var(--border-sub)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        overflow: 'hidden',
      }}
    >
      {/* Tab bar */}
      <div
        style={{
          display: 'flex',
          background: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border-sub)',
          flexShrink: 0,
        }}
      >
        {TABS.map((t) => {
          const active = tab === t.id
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '7px 12px',
                fontSize: 11,
                cursor: 'pointer',
                background: 'transparent',
                color: active ? '#8fa8c0' : 'var(--text-muted)',
                border: 'none',
                borderBottom: `2px solid ${active ? '#8fa8c0' : 'transparent'}`,
                transition: 'all 0.15s',
                fontFamily: 'inherit',
              }}
            >
              {t.label}
            </button>
          )
        })}
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {!fileId ? (
          <div
            style={{
              height: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 13,
              color: 'var(--text-muted)',
              padding: 12,
              textAlign: 'center',
            }}
          >
            Select a file to preview
          </div>
        ) : tab === 'meta' ? (
          <MetaContent meta={meta} loading={loading} />
        ) : tab === 'hex' ? (
          <Placeholder text="Hex viewer — Day 4" />
        ) : tab === 'text' ? (
          <Placeholder text="Text viewer — Day 4" />
        ) : (
          <Placeholder text="Image preview — Day 4" />
        )}
      </div>
    </div>
  )
}

function Placeholder({ text }: { text: string }) {
  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 12,
        color: 'var(--text-muted)',
      }}
    >
      {text}
    </div>
  )
}

function MetaContent({ meta, loading }: { meta: FileMetadata | null; loading: boolean }) {
  if (loading) {
    return (
      <div
        style={{
          padding: 12,
          fontSize: 12,
          color: 'var(--text-muted)',
        }}
      >
        Loading...
      </div>
    )
  }
  if (!meta) {
    return (
      <div style={{ padding: 12, fontSize: 12, color: 'var(--text-muted)' }}>
        No metadata
      </div>
    )
  }

  const lower = meta.category.toLowerCase()
  let categoryColor: string = 'var(--text-2)'
  if (lower.includes('malware')) categoryColor = 'var(--flag)'
  else if (lower.includes('suspicious')) categoryColor = 'var(--sus)'

  const deletedColor = meta.is_deleted ? 'var(--flag)' : 'var(--clean)'
  const deletedText = meta.is_deleted ? 'Yes' : 'No'

  return (
    <div style={{ padding: 10 }}>
      <Row k="Name" v={meta.name} />
      <Row k="Category" v={meta.category} valueColor={categoryColor} />
      <Row k="Size" v={meta.size_display} />
      <Row k="Path" v={meta.full_path} />
      <Row k="Modified" v={meta.modified} />
      <Row k="Created" v={meta.created} />
      <Row k="Accessed" v={meta.accessed} />
      <Row k="Extension" v={meta.extension || '\u2014'} />
      <Row k="MIME" v={meta.mime_type ?? '\u2014'} />
      {meta.mft_entry !== null && <Row k="MFT Entry" v={String(meta.mft_entry)} />}
      {meta.permissions && <Row k="Perms" v={meta.permissions} />}
      <Row k="Deleted" v={deletedText} valueColor={deletedColor} />

      <Sep />

      <div
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginBottom: 4,
        }}
      >
        SHA-256
      </div>
      <div
        style={{
          fontFamily: 'monospace',
          fontSize: 10,
          color: 'var(--text-muted)',
          wordBreak: 'break-all',
          lineHeight: 1.5,
        }}
      >
        {meta.sha256 ?? '\u2014'}
      </div>

      {meta.md5 && (
        <>
          <div
            style={{
              fontSize: 10,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginTop: 8,
              marginBottom: 4,
            }}
          >
            MD5
          </div>
          <div
            style={{
              fontFamily: 'monospace',
              fontSize: 10,
              color: 'var(--text-muted)',
              wordBreak: 'break-all',
              lineHeight: 1.5,
            }}
          >
            {meta.md5}
          </div>
        </>
      )}
    </div>
  )
}

function Row({
  k,
  v,
  valueColor = 'var(--text-2)',
}: {
  k: string
  v: string
  valueColor?: string
}) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        marginBottom: 8,
        gap: 8,
      }}
    >
      <span
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          flexShrink: 0,
          marginTop: 1,
        }}
      >
        {k}
      </span>
      <span
        style={{
          fontSize: 12,
          color: valueColor,
          textAlign: 'right',
          wordBreak: 'break-all',
        }}
      >
        {v}
      </span>
    </div>
  )
}

function Sep() {
  return (
    <div
      style={{
        height: 1,
        background: 'var(--border-sub)',
        margin: '8px 0',
      }}
    />
  )
}
