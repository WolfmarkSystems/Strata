import { useEffect, useState } from 'react'
import { useAppStore } from '../store/appStore'
import EmptyState from '../components/EmptyState'

export default function NotesView() {
  const caseData = useAppStore((s) => s.caseData)
  const updateCaseNotes = useAppStore((s) => s.updateCaseNotes)
  const caseModified = useAppStore((s) => s.caseModified)

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

      {/* Editor bubble */}
      <div
        className="bubble"
        style={{
          flex: 1,
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
    </div>
  )
}
