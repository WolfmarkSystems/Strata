import { useEffect, useState } from 'react'
import type { Artifact } from '../ipc'
import { getArtifactNote, navigateToPath, saveArtifactNote } from '../ipc'
import { useAppStore } from '../store/appStore'
import ThreadContextPanel from './ThreadContextPanel'

interface Props {
  artifact: Artifact | null
}

export default function ArtifactDetail({ artifact }: Props) {
  const [rawExpanded, setRawExpanded] = useState(false)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const setView = useAppStore((s) => s.setView)
  const setSelectedNode = useAppStore((s) => s.setSelectedNode)
  const expandTreeNodes = useAppStore((s) => s.expandTreeNodes)
  const [navStatus, setNavStatus] = useState<string | null>(null)
  const [note, setNote] = useState('')
  const [flagged, setFlagged] = useState(false)
  const [noteStatus, setNoteStatus] = useState<string | null>(null)

  useEffect(() => {
    if (!artifact) {
      setNote('')
      setFlagged(false)
      setNoteStatus(null)
      return
    }
    getArtifactNote(artifact.id).then((saved) => {
      setNote(saved?.note ?? '')
      setFlagged(saved?.flagged ?? false)
      setNoteStatus(null)
    })
  }, [artifact])

  const handleGoToSource = async () => {
    if (!artifact || !evidenceId) return
    setNavStatus('Locating...')
    const target = await navigateToPath(evidenceId, artifact.source_path)
    if (!target) {
      setNavStatus('Source not found in evidence tree')
      setTimeout(() => setNavStatus(null), 3000)
      return
    }
    expandTreeNodes(target.breadcrumb)
    setSelectedNode(target.node_id)
    setView('files')
    setNavStatus(null)
  }

  const handleSaveNote = async () => {
    if (!artifact || !evidenceId) return
    const saved = await saveArtifactNote(artifact.id, evidenceId, note, flagged)
    if (saved) {
      setNote(saved.note)
      setFlagged(saved.flagged)
      setNoteStatus('Saved')
      window.dispatchEvent(new CustomEvent('strata-artifact-note-saved'))
      setTimeout(() => setNoteStatus(null), 1800)
    }
  }

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
        Artifact Detail
      </div>

      {!artifact ? (
        <div
          style={{
            flex: 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 13,
            color: 'var(--text-muted)',
            padding: 12,
            textAlign: 'center',
          }}
        >
          Select an artifact to view details
        </div>
      ) : (
        <div style={{ flex: 1, overflowY: 'auto', padding: 12 }}>
          {/* Title */}
          <div
            style={{
              fontSize: 14,
              fontWeight: 700,
              color: 'var(--text-1)',
              marginBottom: 4,
              lineHeight: 1.4,
              wordBreak: 'break-word',
            }}
          >
            {artifact.name}
          </div>

          {/* Category + plugin */}
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {artifact.category} {'\u00B7'} via {artifact.plugin}
          </div>

          {/* Forensic value banner */}
          <ForensicBanner value={artifact.forensic_value} />

          <Sep />

          {/* Field rows */}
          <Row k="Value" v={artifact.value} />
          {artifact.timestamp && (
            <Row k="Timestamp" v={formatTimestamp(artifact.timestamp)} mono />
          )}
          <Row k="Source File" v={artifact.source_file} mono />

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
            Source Path
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
            {artifact.source_path}
          </div>

          {/* Sprint-11 P2 — Go to Source button. Switches to the
              Evidence Tree view, expands the breadcrumb chain, and
              selects the file's containing folder so the examiner
              can see the raw data underlying the artifact. */}
          <button
            onClick={handleGoToSource}
            disabled={!evidenceId || !artifact.source_path}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '4px 10px',
              fontSize: 11,
              fontFamily: 'monospace',
              color: 'var(--carved)',
              background: 'rgba(74,120,144,0.1)',
              border: '1px solid rgba(74,120,144,0.3)',
              borderRadius: 4,
              cursor: evidenceId && artifact.source_path ? 'pointer' : 'not-allowed',
              marginBottom: 6,
            }}
            title="Switch to Evidence Tree and select this file"
          >
            {'→'} Go to Source
          </button>
          {navStatus && (
            <div
              style={{
                fontSize: 10,
                color: 'var(--sus)',
                marginBottom: 6,
              }}
            >
              {navStatus}
            </div>
          )}

          {artifact.mitre_technique && (
            <>
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
                MITRE ATT&CK
              </div>
              <span
                style={{
                  display: 'inline-block',
                  fontFamily: 'monospace',
                  fontSize: 11,
                  color: 'var(--carved)',
                  background: 'rgba(74,120,144,0.1)',
                  borderStyle: 'solid',
                  borderWidth: 1,
                  borderColor: 'rgba(74,120,144,0.3)',
                  padding: '2px 8px',
                  borderRadius: 3,
                }}
              >
                {artifact.mitre_technique}
              </span>
              {artifact.mitre_name && (
                <div
                  style={{
                    fontSize: 11,
                    color: 'var(--text-muted)',
                    marginTop: 4,
                  }}
                >
                  {artifact.mitre_name}
                </div>
              )}
            </>
          )}

          {artifact.raw_data && (
            <>
              <Sep />
              <div
                onClick={() => setRawExpanded((v) => !v)}
                style={{
                  fontSize: 10,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  marginBottom: 6,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <span style={{ fontSize: 9 }}>{rawExpanded ? '\u25BC' : '\u25B6'}</span>
                Raw Data
              </div>
              {rawExpanded && (
                <div
                  style={{
                    background: 'var(--bg-elevated)',
                    borderStyle: 'solid',
                    borderWidth: 1,
                    borderColor: 'var(--border)',
                    borderRadius: 4,
                    padding: '8px 10px',
                    fontFamily: 'monospace',
                    fontSize: 10,
                    color: 'var(--text-muted)',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                  }}
                >
                  {artifact.raw_data}
                </div>
              )}
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
            Examiner Note
          </div>
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 11,
              color: 'var(--text-2)',
              marginBottom: 8,
              cursor: 'pointer',
            }}
          >
            <input
              type="checkbox"
              checked={flagged}
              onChange={(e) => setFlagged(e.target.checked)}
            />
            Flag artifact
          </label>
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            style={{
              width: '100%',
              minHeight: 82,
              boxSizing: 'border-box',
              resize: 'vertical',
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              color: 'var(--text-2)',
              fontSize: 12,
              fontFamily: 'inherit',
              padding: 8,
              outline: 'none',
            }}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
            <button
              onClick={handleSaveNote}
              disabled={!evidenceId}
              style={{
                padding: '5px 10px',
                fontSize: 11,
                fontFamily: 'monospace',
                fontWeight: 700,
                color: 'var(--text-1)',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                cursor: evidenceId ? 'pointer' : 'not-allowed',
              }}
            >
              SAVE NOTE
            </button>
            {noteStatus && <span style={{ fontSize: 11, color: 'var(--clean)' }}>{noteStatus}</span>}
          </div>

          {/* Sprint-11 follow-up — thread context renders below the
              raw-data section, only when the selected artifact
              belongs to a real conversation thread. Hidden for
              non-message categories. */}
          <ThreadContextPanel
            evidenceId={evidenceId}
            category={artifact.category}
            artifactId={artifact.id}
          />
        </div>
      )}
    </div>
  )
}

function ForensicBanner({ value }: { value: string }) {
  let bg = ''
  let border = ''
  let color = ''
  let label = ''
  if (value === 'high') {
    bg = 'rgba(168,64,64,0.1)'
    border = 'rgba(168,64,64,0.3)'
    color = 'var(--flag)'
    label = '\u26A0 HIGH FORENSIC VALUE'
  } else if (value === 'medium') {
    bg = 'rgba(184,120,64,0.1)'
    border = 'rgba(184,120,64,0.3)'
    color = 'var(--sus)'
    label = '\u25C8 MEDIUM FORENSIC VALUE'
  } else {
    bg = 'rgba(58,72,88,0.1)'
    border = 'var(--border)'
    color = 'var(--text-muted)'
    label = '\u00B7 LOW FORENSIC VALUE'
  }
  return (
    <div
      style={{
        margin: '10px 0',
        padding: '6px 10px',
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 700,
        background: bg,
        borderStyle: 'solid',
        borderWidth: 1,
        borderColor: border,
        color,
      }}
    >
      {label}
    </div>
  )
}

function Row({ k, v, mono = false }: { k: string; v: string; mono?: boolean }) {
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
          fontSize: mono ? 11 : 12,
          color: 'var(--text-2)',
          textAlign: 'right',
          wordBreak: 'break-all',
          fontFamily: mono ? 'monospace' : undefined,
        }}
      >
        {v}
      </span>
    </div>
  )
}

function formatTimestamp(ts: string): string {
  const n = Number(ts)
  if (!Number.isFinite(n) || n <= 0) return ts
  const d = new Date(n * 1000)
  if (Number.isNaN(d.getTime())) return ts
  return d.toISOString().replace('T', ' ').replace(/\..*$/, ' UTC')
}

function Sep() {
  return (
    <div
      style={{
        height: 1,
        background: 'var(--border-sub)',
        margin: '10px 0',
      }}
    />
  )
}
