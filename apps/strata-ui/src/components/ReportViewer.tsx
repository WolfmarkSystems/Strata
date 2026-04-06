import { useEffect, useRef } from 'react'
import { useAppStore } from '../store/appStore'

export default function ReportViewer() {
  const reportHtml = useAppStore((s) => s.reportHtml)
  const setReportVisible = useAppStore((s) => s.setReportVisible)
  const iframeRef = useRef<HTMLIFrameElement>(null)

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
          {'\u00B7'} Preview mode
        </span>
        <div style={{ flex: 1 }} />
        <button
          onClick={handlePrint}
          style={{
            padding: '6px 14px',
            fontSize: 11,
            fontFamily: 'monospace',
            letterSpacing: '0.06em',
            background: 'var(--bg-elevated)',
            color: 'var(--text-2)',
            border: '1px solid var(--border)',
            borderRadius: 4,
            cursor: 'pointer',
          }}
        >
          {'\u29C9'} PRINT / SAVE PDF
        </button>
        <button
          onClick={handleClose}
          style={{
            padding: '6px 14px',
            fontSize: 11,
            fontFamily: 'monospace',
            letterSpacing: '0.06em',
            background: 'transparent',
            color: 'var(--text-muted)',
            border: '1px solid var(--border)',
            borderRadius: 4,
            cursor: 'pointer',
          }}
        >
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
            borderRadius: 4,
            background: '#ffffff',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          }}
        />
      </div>
    </div>
  )
}
