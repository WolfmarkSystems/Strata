import { useEffect, useState } from 'react'
import { useAppStore } from '../store/appStore'
import EmptyState from '../components/EmptyState'
import { getFlaggedArtifacts, type ArtifactNote } from '../ipc'

export default function NotesView() {
  const caseData = useAppStore((s) => s.caseData)
  const updateCaseNotes = useAppStore((s) => s.updateCaseNotes)
  const caseModified = useAppStore((s) => s.caseModified)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const setView = useAppStore((s) => s.setView)
  const setSelectedArtifactId = useAppStore((s) => s.setSelectedArtifactId)
  const [artifactNotes, setArtifactNotes] = useState<ArtifactNote[]>([])

  useEffect(() => {
    if (!evidenceId) {
      setArtifactNotes([])
      return
    }
    getFlaggedArtifacts(evidenceId).then(setArtifactNotes)
    const handler = () => {
      if (evidenceId) getFlaggedArtifacts(evidenceId).then(setArtifactNotes)
    }
    window.addEventListener('strata-artifact-note-saved', handler)
    return () => window.removeEventListener('strata-artifact-note-saved', handler)
  }, [evidenceId])

  const jumpToArtifact = (id: string) => {
    setSelectedArtifactId(id)
    setView('artifacts')
  }

  // Local mirror so typing is instant; pushes to store on change.
  const [text, setText] = useState(caseData?.notes ?? '')
  const [savedFlash, setSavedFlash] = useState(false)

  // Sync local text when the underlying case changes (e.g. user opens a
  // different case).
  useEffect(() => {
    setText(caseData?.notes ?? '')
  }, [caseData?.case_number])

  // Show "Saved" indicator briefly when caseModified flips back to false
  // (the autosave timer in the store fires).
  const [prevModified, setPrevModified] = useState(caseModified)
  useEffect(() => {
    if (prevModified && !caseModified) {
      setSavedFlash(true)
      const t = setTimeout(() => setSavedFlash(false), 1500)
      return () => clearTimeout(t)
    }
    setPrevModified(caseModified)
  }, [caseModified, prevModified])

  if (!caseData) {
    return (
      <EmptyState
        icon={'\u{1F4DD}'}
        title="Case Notes"
        subtitle="Open or create a case to start taking notes"
        hint="Notes auto-save into the case file"
      />
    )
  }

  const charCount = text.length

  return (
    <div
      style={{
        flex: 1,
        background: 'var(--bg-base)',
        padding: 8,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
    >
      {/* Header bubble */}
      <div
        className="bubble-tight"
        style={{
          padding: '10px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          flexShrink: 0,
        }}
      >
        <span
          style={{
            fontSize: 12,
            fontWeight: 700,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            color: 'var(--text-1)',
          }}
        >
          Case Notes
        </span>
        <span
          style={{
            fontSize: 10,
            color: 'var(--text-muted)',
            fontFamily: 'monospace',
          }}
        >
          {caseData.case_number} {'\u00B7'} {caseData.case_name}
        </span>
        <div style={{ flex: 1 }} />
        <span
          style={{
            fontSize: 10,
            color: savedFlash
              ? 'var(--clean)'
              : caseModified
                ? 'var(--sus)'
                : 'var(--text-muted)',
            fontFamily: 'monospace',
            transition: 'color 0.3s',
          }}
        >
          {savedFlash
            ? '\u2713 Saved'
            : caseModified
              ? '\u25CF Modified'
              : 'Auto-save on'}
        </span>
        <span
          style={{
            fontSize: 10,
            color: 'var(--text-muted)',
            fontFamily: 'monospace',
          }}
        >
          {charCount} chars
        </span>
      </div>

      {/* Editor + Artifact notes side-by-side */}
      <div style={{ flex: 1, display: 'flex', gap: 8, minHeight: 0 }}>
      <div
        className="bubble"
        style={{
          flex: 2,
          display: 'flex',
        }}
      >
        <textarea
          value={text}
          onChange={(e) => {
            const v = e.target.value
            setText(v)
            updateCaseNotes(v)
          }}
          placeholder="# Investigation Notes&#10;&#10;Use markdown formatting. Notes auto-save 5 seconds after the last change, or press Cmd+S to save immediately."
          spellCheck={false}
          style={{
            flex: 1,
            background: 'transparent',
            border: 'none',
            outline: 'none',
            resize: 'none',
            color: 'var(--text-2)',
            fontFamily: 'Menlo, monospace',
            fontSize: 13,
            lineHeight: 1.7,
            padding: 20,
            width: '100%',
            height: '100%',
          }}
        />
      </div>

      <div
        className="bubble"
        style={{
          flex: 1,
          minWidth: 280,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <div
          style={{
            padding: '8px 12px',
            fontSize: 9,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            borderBottom: '1px solid var(--border-sub)',
            display: 'flex',
            alignItems: 'baseline',
            gap: 8,
          }}
        >
          <span>Artifact Notes</span>
          <span style={{ fontFamily: 'monospace', color: 'var(--text-muted)' }}>
            {artifactNotes.length}
          </span>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: 10 }}>
          {artifactNotes.length === 0 ? (
            <div
              style={{
                fontSize: 11,
                color: 'var(--text-muted)',
                padding: 16,
                textAlign: 'center',
                lineHeight: 1.5,
              }}
            >
              No artifact notes yet. Flag artifacts from the Artifacts view to build the running examiner log.
            </div>
          ) : (
            artifactNotes.map((n) => (
              <div
                key={`${n.evidence_id}-${n.artifact_id}`}
                style={{
                  marginBottom: 8,
                  padding: 10,
                  background: 'var(--bg-elevated)',
                  border: `1px solid ${n.flagged ? 'rgba(168,64,64,0.4)' : 'var(--border)'}`,
                  borderRadius: 4,
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    gap: 6,
                    marginBottom: 4,
                  }}
                >
                  {n.flagged && (
                    <span style={{ color: 'var(--flag)', fontSize: 11 }}>{'⚠'}</span>
                  )}
                  <span
                    style={{
                      fontSize: 11,
                      fontWeight: 700,
                      color: 'var(--text-1)',
                      fontFamily: 'monospace',
                      flex: 1,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {n.artifact_id}
                  </span>
                  <span
                    style={{
                      fontSize: 9,
                      color: 'var(--text-muted)',
                      fontFamily: 'monospace',
                    }}
                  >
                    {new Date(n.created_at * 1000).toLocaleString()}
                  </span>
                </div>
                <div
                  style={{
                    fontSize: 11,
                    color: 'var(--text-2)',
                    whiteSpace: 'pre-wrap',
                    lineHeight: 1.5,
                    marginBottom: 6,
                  }}
                >
                  {n.note || <span style={{ color: 'var(--text-muted)' }}>(no note)</span>}
                </div>
                <button
                  onClick={() => jumpToArtifact(n.artifact_id)}
                  style={{
                    fontSize: 10,
                    fontFamily: 'monospace',
                    color: 'var(--carved)',
                    background: 'rgba(74,120,144,0.1)',
                    border: '1px solid rgba(74,120,144,0.3)',
                    borderRadius: 3,
                    padding: '2px 8px',
                    cursor: 'pointer',
                  }}
                >
                  {'→'} Jump to artifact
                </button>
              </div>
            ))
          )}
        </div>
      </div>
      </div>
    </div>
  )
}
