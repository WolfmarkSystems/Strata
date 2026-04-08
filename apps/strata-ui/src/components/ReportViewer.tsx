import { useEffect, useRef, useState } from 'react'
import { useAppStore } from '../store/appStore'
import { saveReport } from '../ipc'

export default function ReportViewer() {
  const reportHtml = useAppStore((s) => s.reportHtml)
  const setReportVisible = useAppStore((s) => s.setReportVisible)
  const casePath = useAppStore((s) => s.casePath)
  const iframeRef = useRef<HTMLIFrameElement>(null)
  const [savedPath, setSavedPath] = useState<string | null>(null)
  const [savedFlash, setSavedFlash] = useState(false)

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setReportVisible(false)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [setReportVisible])

  const handlePrint = () => {
    const win = iframeRef.current?.contentWindow
    if (win) {
      win.focus()
      win.print()
    }
  }

  const handleSaveHtml = async () => {
    if (!reportHtml) return
    if (!casePath) {
      // Fallback: use a Blob URL download in the browser
      const blob = new Blob([reportHtml], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `strata-report-${new Date().toISOString().replace(/[:.]/g, '-')}.html`
      a.click()
      URL.revokeObjectURL(url)
      setSavedFlash(true)
      setTimeout(() => setSavedFlash(false), 2500)
      return
    }
    const path = await saveReport(reportHtml, casePath)
    if (path) {
      setSavedPath(path)
      setSavedFlash(true)
      setTimeout(() => setSavedFlash(false), 4000)
    }
  }

  const handleClose = () => setReportVisible(false)

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.85)',
        zIndex: 10000,
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Toolbar */}
      <div
        style={{
          height: 48,
          background: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          padding: '0 16px',
          gap: 10,
          flexShrink: 0,
        }}
      >
        <div
          style={{
            fontSize: 13,
            fontWeight: 700,
            color: 'var(--text-1)',
            letterSpacing: '0.08em',
          }}
        >
          FORENSIC REPORT
        </div>
        <span
          style={{
            fontSize: 10,
            color: 'var(--text-muted)',
            fontFamily: 'monospace',
          }}
        >
          {'\u00B7'} {casePath ? 'Linked to case' : 'Preview mode'}
        </span>

        {savedFlash && (
          <span
            style={{
              fontSize: 10,
              color: 'var(--clean)',
              fontFamily: 'monospace',
              marginLeft: 8,
              animation: 'gateFade 200ms ease-out',
            }}
            title={savedPath ?? undefined}
          >
            {'\u2713'} {savedPath ? `Saved to ${savedPath.split('/').pop()}` : 'Downloaded'}
          </span>
        )}

        <div style={{ flex: 1 }} />

        <button
          onClick={handleSaveHtml}
          disabled={!reportHtml}
          style={toolbarButton('var(--text-2)')}
        >
          {'\u{1F4BE}'} SAVE HTML
        </button>
        <button onClick={handlePrint} style={toolbarButton('var(--text-2)')}>
          {'\u29C9'} PRINT / SAVE PDF
        </button>
        <button onClick={handleClose} style={toolbarButton('var(--text-muted)')}>
          {'\u2715'} CLOSE
        </button>
      </div>

      {/* Report iframe */}
      <div
        style={{
          flex: 1,
          overflow: 'hidden',
          padding: 24,
          display: 'flex',
          justifyContent: 'center',
        }}
      >
        <iframe
          ref={iframeRef}
          srcDoc={reportHtml ?? '<html><body>No report generated.</body></html>'}
          title="Forensic Report"
          style={{
            width: '100%',
            maxWidth: 900,
            height: '100%',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            background: '#ffffff',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          }}
        />
      </div>
    </div>
  )
}

function toolbarButton(color: string): React.CSSProperties {
  return {
    padding: '6px 14px',
    fontSize: 11,
    fontFamily: 'monospace',
    letterSpacing: '0.06em',
    background: 'var(--bg-elevated)',
    color,
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
  }
}
