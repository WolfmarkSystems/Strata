import { useEffect, useState } from 'react'
import { getFileMetadata } from '../ipc'
import type { FileMetadata } from '../types'
import HexViewer from './HexViewer'
import TextViewer from './TextViewer'

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
      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
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
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <MetaContent meta={meta} loading={loading} />
          </div>
        ) : tab === 'hex' ? (
          <HexViewer fileId={fileId} />
        ) : tab === 'text' ? (
          <TextViewer fileId={fileId} extension={meta?.extension} />
        ) : (
          <div
            style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexDirection: 'column',
              gap: 8,
            }}
          >
            <div style={{ fontSize: 24 }}>{'\u{1F5BC}'}</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Not an image file</div>
          </div>
        )}
      </div>
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

  const showFlags = meta.is_flagged || meta.is_suspicious || meta.is_deleted

  return (
    <div style={{ padding: 10 }}>
      <Row k="Name" v={meta.name} />
      <Row k="Category" v={meta.category} valueColor={categoryColor} />
      <Row k="Size" v={meta.size_display} />
      <Row k="Modified" v={meta.modified} />
      <Row k="Created" v={meta.created} />
      <Row k="Accessed" v={meta.accessed} />
      <Row k="Extension" v={meta.extension || '\u2014'} />
      <Row k="MIME" v={meta.mime_type ?? '\u2014'} />
      {meta.mft_entry !== null && <Row k="MFT Entry" v={String(meta.mft_entry)} />}
      {meta.permissions && <Row k="Perms" v={meta.permissions} />}
      <Row k="Deleted" v={deletedText} valueColor={deletedColor} />

      {/* Full path — monospace, separate row for word-break */}
      <div
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginTop: 4,
          marginBottom: 2,
        }}
      >
        Full Path
      </div>
      <div
        style={{
          fontFamily: 'monospace',
          fontSize: 10,
          color: 'var(--text-2)',
          wordBreak: 'break-all',
          marginBottom: 6,
        }}
      >
        {meta.full_path}
      </div>

      {showFlags && (
        <div
          style={{
            background: 'rgba(168,64,64,0.08)',
            border: '1px solid rgba(168,64,64,0.2)',
            borderRadius: 4,
            padding: '8px 10px',
            margin: '8px 0',
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}
        >
          <div
            style={{
              fontSize: 9,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginBottom: 2,
            }}
          >
            Forensic Flags
          </div>
          {meta.is_flagged && (
            <div style={{ color: 'var(--flag)', fontSize: 11, fontWeight: 700 }}>
              ⚠ FLAGGED — Known threat indicator
            </div>
          )}
          {meta.is_suspicious && (
            <div style={{ color: 'var(--sus)', fontSize: 11 }}>
              ◈ SUSPICIOUS — Requires investigation
            </div>
          )}
          {meta.is_deleted && (
            <div style={{ color: 'var(--flag)', fontSize: 11 }}>
              ✗ DELETED — File was removed from filesystem. Recovery may be possible.
            </div>
          )}
        </div>
      )}

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
