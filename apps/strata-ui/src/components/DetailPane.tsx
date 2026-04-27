import { useEffect, useMemo, useState } from 'react'
import {
  getEvidenceIntegrity,
  getFileMetadata,
  hashFile,
  verifyEvidenceIntegrity,
} from '../ipc'
import type { FileMetadata } from '../types'
import type { EvidenceIntegrity, HashResult } from '../ipc'
import HexViewer from './HexViewer'
import TextViewer from './TextViewer'
import SqliteViewer from './SqliteViewer'
import TimestampConverter from './TimestampConverter'
import { lookupKnowledge, type KnowledgeLookupResult } from '../data/knowledgeBank'

interface Props {
  fileId: string | null
  evidenceId: string | null
}

type Tab = 'meta' | 'hex' | 'text' | 'image' | 'sqlite'

const BASE_TABS: { id: Tab; label: string }[] = [
  { id: 'meta',  label: 'META' },
  { id: 'hex',   label: 'HEX' },
  { id: 'text',  label: 'TEXT' },
  { id: 'image', label: 'IMAGE' },
]

const SQLITE_EXTENSIONS = new Set(['db', 'sqlite', 'sqlite3', 'db3', 'storedata', 'sqlitedb'])

function isSqliteFile(meta: FileMetadata | null): boolean {
  if (!meta) return false
  const ext = (meta.extension ?? '').toLowerCase().replace(/^\./, '')
  if (SQLITE_EXTENSIONS.has(ext)) return true
  // Filename-based detection for databases with no extension
  const name = (meta.name ?? '').toLowerCase()
  return (
    name.endsWith('.db') ||
    name.endsWith('.sqlite') ||
    name.endsWith('.sqlite3') ||
    name === 'history' ||
    name === 'places.sqlite' ||
    name === 'knowledgec.db' ||
    name === 'sms.db' ||
    name === 'chat.db'
  )
}

export default function DetailPane({ fileId, evidenceId }: Props) {
  const [tab, setTab] = useState<Tab>('meta')
  const [meta, setMeta] = useState<FileMetadata | null>(null)
  const [loading, setLoading] = useState(false)
  const [integrity, setIntegrity] = useState<EvidenceIntegrity | null>(null)
  const [verifying, setVerifying] = useState(false)

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

  useEffect(() => {
    if (!evidenceId || fileId) {
      setIntegrity(null)
      return
    }
    getEvidenceIntegrity(evidenceId).then(setIntegrity)
  }, [evidenceId, fileId])

  const handleVerify = async () => {
    if (!evidenceId || verifying) return
    setVerifying(true)
    try {
      const next = await verifyEvidenceIntegrity(evidenceId)
      setIntegrity(next)
    } finally {
      setVerifying(false)
    }
  }

  // Build the tab list dynamically — append SQLITE when the selected file
  // is a SQLite database.
  const isSqlite = isSqliteFile(meta)
  const tabs = useMemo<{ id: Tab; label: string }[]>(() => {
    if (isSqlite) {
      return [...BASE_TABS, { id: 'sqlite', label: 'SQLITE' }]
    }
    return BASE_TABS
  }, [isSqlite])

  // If the user switches away from a SQLite file while on the SQLITE tab,
  // fall back to META.
  useEffect(() => {
    if (tab === 'sqlite' && !isSqlite) {
      setTab('meta')
    }
  }, [tab, isSqlite])

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
      {/* Tab bar */}
      <div
        style={{
          display: 'flex',
          background: 'transparent',
          borderBottom: '1px solid var(--border)',
          flexShrink: 0,
        }}
      >
        {tabs.map((t) => {
          const active = tab === t.id
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '10px 14px',
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: '0.08em',
                cursor: 'pointer',
                background: 'transparent',
                color: active ? 'var(--text-1)' : 'var(--text-muted)',
                border: 'none',
                borderBottom: `2px solid ${active ? 'var(--accent-2)' : 'transparent'}`,
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
          <EvidenceIntegrityPanel
            integrity={integrity}
            verifying={verifying}
            onVerify={handleVerify}
          />
        ) : tab === 'meta' ? (
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <MetaContent meta={meta} loading={loading} fileId={fileId} evidenceId={evidenceId} />
            {isSqlite && (
              <div style={{ padding: 10 }}>
                <TimestampConverter />
              </div>
            )}
          </div>
        ) : tab === 'hex' ? (
          <HexViewer fileId={fileId} />
        ) : tab === 'text' ? (
          <TextViewer fileId={fileId} extension={meta?.extension} />
        ) : tab === 'sqlite' ? (
          meta?.full_path ? (
            <SqliteViewer filePath={meta.full_path} />
          ) : (
            <div
              style={{
                flex: 1,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 11,
                color: 'var(--text-muted)',
                padding: 12,
                textAlign: 'center',
              }}
            >
              File path unavailable — SQLite viewer needs a real filesystem path.
            </div>
          )
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

function EvidenceIntegrityPanel({
  integrity,
  verifying,
  onVerify,
}: {
  integrity: EvidenceIntegrity | null
  verifying: boolean
  onVerify: () => void
}) {
  if (!integrity) {
    return (
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
    )
  }
  const computed = new Date(integrity.computed_at * 1000).toLocaleString()
  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 12 }}>
      <div
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginBottom: 8,
        }}
      >
        Evidence Integrity
      </div>
      <Row k="Status" v={integrity.verified ? 'Verified at load time' : 'Mismatch detected'} />
      <Row k="Size" v={`${integrity.file_size_bytes.toLocaleString()} bytes`} />
      <Row k="Computed" v={computed} />
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
        SHA-256
      </div>
      <div
        style={{
          fontFamily: 'monospace',
          fontSize: 10,
          color: integrity.verified ? 'var(--text-2)' : 'var(--flag)',
          wordBreak: 'break-all',
          marginBottom: 12,
        }}
      >
        {integrity.sha256}
      </div>
      <button
        onClick={onVerify}
        disabled={verifying}
        style={{
          padding: '6px 10px',
          fontSize: 11,
          fontFamily: 'monospace',
          fontWeight: 700,
          color: 'var(--text-1)',
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderRadius: 4,
          cursor: verifying ? 'wait' : 'pointer',
        }}
      >
        {verifying ? 'VERIFYING...' : 'RE-VERIFY'}
      </button>
    </div>
  )
}

function MetaContent({
  meta,
  loading,
  fileId,
  evidenceId,
}: {
  meta: FileMetadata | null
  loading: boolean
  fileId: string | null
  evidenceId: string | null
}) {
  const [hashes, setHashes] = useState<HashResult | null>(null)
  const [hashing, setHashing] = useState(false)
  useEffect(() => {
    setHashes(null)
  }, [fileId])
  const handleHash = async () => {
    if (!fileId || !evidenceId || hashing) return
    setHashing(true)
    try {
      const result = await hashFile(evidenceId, fileId)
      setHashes(result)
    } finally {
      setHashing(false)
    }
  }
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

      <Sep />
      <div
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginBottom: 6,
        }}
      >
        Compute Hashes
      </div>
      <button
        onClick={handleHash}
        disabled={!fileId || !evidenceId || hashing}
        style={{
          padding: '5px 10px',
          fontSize: 11,
          fontFamily: 'monospace',
          fontWeight: 700,
          color: 'var(--text-1)',
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderRadius: 4,
          cursor: !fileId || !evidenceId || hashing ? 'not-allowed' : 'pointer',
          letterSpacing: '0.06em',
        }}
      >
        {hashing ? 'HASHING...' : 'HASH FILE'}
      </button>
      {hashes && (
        <div style={{ marginTop: 10 }}>
          <HashLine label="MD5" value={hashes.md5} />
          <HashLine label="SHA-1" value={hashes.sha1} />
          <HashLine label="SHA-256" value={hashes.sha256} />
          <HashLine label="SHA-512" value={hashes.sha512} />
        </div>
      )}

      <KnowledgeBankSection
        entry={lookupKnowledge(meta.name, meta.extension)}
      />
    </div>
  )
}

function HashLine({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ marginBottom: 6 }}>
      <div
        style={{
          fontSize: 9,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          marginBottom: 2,
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontFamily: 'monospace',
          fontSize: 10,
          color: 'var(--text-2)',
          wordBreak: 'break-all',
          lineHeight: 1.5,
        }}
      >
        {value}
      </div>
    </div>
  )
}

function KnowledgeBankSection({ entry }: { entry: KnowledgeLookupResult | null }) {
  if (!entry) return null

  const knowledge = entry.entry

  const titleColor =
    knowledge.forensic_value === 'critical'
      ? 'var(--flag)'
      : knowledge.forensic_value === 'high'
        ? 'var(--sus)'
        : knowledge.forensic_value === 'medium'
          ? 'var(--text-2)'
          : 'var(--text-muted)'

  return (
    <>
      <Sep />

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 10,
        }}
      >
        <span style={{ fontSize: 14 }}>{'\u{1F4DA}'}</span>
        <span
          style={{
            fontSize: 9,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
          }}
        >
          Knowledge Bank
        </span>
      </div>

      <div
        style={{
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          padding: '10px 12px',
        }}
      >
        <div
          style={{
            fontSize: 13,
            fontWeight: 700,
            color: titleColor,
            marginBottom: 6,
          }}
        >
          {knowledge.title}
        </div>

        {entry.matchType === 'extension' && entry.extension && (
          <div
            style={{
              fontSize: 10,
              color: 'var(--text-muted)',
              fontStyle: 'italic',
              marginBottom: 8,
            }}
          >
            Generic match — applies to all .{entry.extension} files
          </div>
        )}

        <div
          style={{
            fontSize: 11,
            color: 'var(--text-2)',
            lineHeight: 1.6,
            marginBottom: 10,
          }}
        >
          {knowledge.summary}
        </div>

        {knowledge.artifact_types.length > 0 && (
          <>
            <KbLabel>ARTIFACTS</KbLabel>
            <div style={{ marginBottom: 4 }}>
              {knowledge.artifact_types.map((t) => (
                <div
                  key={t}
                  style={{
                    fontSize: 10,
                    color: 'var(--text-muted)',
                    paddingLeft: 8,
                    lineHeight: 1.7,
                  }}
                >
                  {'\u00B7'} {t}
                </div>
              ))}
            </div>
          </>
        )}

        {knowledge.mitre_techniques.length > 0 && (
          <>
            <KbLabel style={{ marginTop: 8 }}>MITRE</KbLabel>
            <div style={{ marginBottom: 4 }}>
              {knowledge.mitre_techniques.map((m) => (
                <span
                  key={m}
                  style={{
                    display: 'inline-block',
                    background: 'rgba(88,136,160,0.15)',
                    border: '1px solid rgba(88,136,160,0.3)',
                    color: 'var(--carved)',
                    fontSize: 9,
                    fontFamily: 'monospace',
                    padding: '1px 6px',
                    borderRadius: 'var(--radius-pill)',
                    margin: '2px 2px',
                  }}
                >
                  {m}
                </span>
              ))}
            </div>
          </>
        )}

        {knowledge.threat_indicators && knowledge.threat_indicators.length > 0 && (
          <>
            <div
              style={{
                fontSize: 9,
                color: 'var(--flag)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                marginTop: 8,
                marginBottom: 4,
              }}
            >
              THREAT INDICATORS
            </div>
            {knowledge.threat_indicators.map((ti) => (
              <div
                key={ti}
                style={{
                  fontSize: 10,
                  color: 'var(--sus)',
                  paddingLeft: 8,
                  lineHeight: 1.7,
                }}
              >
                {'\u26A0'} {ti}
              </div>
            ))}
          </>
        )}

        <KbLabel style={{ marginTop: 8 }}>EXAMINER NOTES</KbLabel>
        <div
          style={{
            fontSize: 11,
            color: 'var(--text-muted)',
            fontStyle: 'italic',
            lineHeight: 1.6,
            marginTop: 2,
          }}
        >
          {knowledge.examiner_notes}
        </div>
      </div>
    </>
  )
}

function KbLabel({
  children,
  style,
}: {
  children: React.ReactNode
  style?: React.CSSProperties
}) {
  return (
    <div
      style={{
        fontSize: 9,
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        marginBottom: 4,
        ...style,
      }}
    >
      {children}
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
