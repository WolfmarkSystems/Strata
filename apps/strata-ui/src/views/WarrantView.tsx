import { useState } from 'react'
import { useAppStore } from '../store/appStore'
import EmptyState from '../components/EmptyState'
import { generateReport } from '../ipc'
import { Stub } from './ChargesView'

export default function WarrantView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const stats = useAppStore((s) => s.stats)
  const [generating, setGenerating] = useState(false)
  const [status, setStatus] = useState<string | null>(null)

  if (!evidenceLoaded || !evidenceId) {
    return (
      <EmptyState
        icon={'\u{1F4DC}'}
        title="Warrant Preparation"
        subtitle="Complete evidence analysis before drafting warrant language"
      />
    )
  }

  const analysisComplete = stats.artifacts > 0

  const handleDraft = async () => {
    if (!evidenceId || generating) return
    setGenerating(true)
    setStatus('Generating warrant draft...')
    try {
      const path = await generateReport(evidenceId, '', 'html')
      setStatus(`Draft saved: ${path}`)
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div
      style={{
        flex: 1,
        background: 'var(--bg-base)',
        padding: 8,
        display: 'flex',
      }}
    >
      <div
        className="bubble"
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <div
          style={{
            padding: '10px 14px',
            fontSize: 11,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            fontWeight: 700,
            borderBottom: '1px solid var(--border-sub)',
          }}
        >
          Warrant Preparation
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
          <Stub
            icon={'\u{1F4DC}'}
            title={
              analysisComplete
                ? 'Ready to draft warrant language'
                : 'Complete evidence analysis first'
            }
            body="This feature generates warrant language based on confirmed artifacts, IOC findings and MITRE technique mapping, chain of custody documentation, and examiner credentials and jurisdiction."
            cta={
              generating
                ? 'GENERATING...'
                : analysisComplete
                  ? 'PREPARE WARRANT DRAFT'
                  : 'COMPLETE EVIDENCE ANALYSIS FIRST'
            }
            onCta={handleDraft}
            disabled={!analysisComplete || generating}
            status={status}
            footer={[
              '⚠ All warrant language requires attorney review before submission.',
              '   Strata does not provide legal advice.',
            ]}
          />
        </div>
      </div>
    </div>
  )
}
