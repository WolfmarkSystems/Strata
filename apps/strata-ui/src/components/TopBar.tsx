import { useAppStore } from '../store/appStore'
import { useWindowSize } from '../hooks/useWindowSize'
import { openEvidenceDialog, loadEvidence, getStats, generateReport } from '../ipc'
import WolfMark from './WolfMark'

export default function TopBar() {
  const stats = useAppStore((s) => s.stats)
  const caseName = useAppStore((s) => s.caseName)
  const isDev = useAppStore((s) => s.isDev)
  const metadataSearch = useAppStore((s) => s.metadataSearch)
  const fulltextSearch = useAppStore((s) => s.fulltextSearch)
  const toggleMetadata = useAppStore((s) => s.toggleMetadata)
  const toggleFulltext = useAppStore((s) => s.toggleFulltext)
  const setEvidence = useAppStore((s) => s.setEvidence)
  const setStats = useAppStore((s) => s.setStats)
  const setSelectedNode = useAppStore((s) => s.setSelectedNode)
  const setCase = useAppStore((s) => s.setCase)
  const setSearchActive = useAppStore((s) => s.setSearchActive)
  const licenseResult = useAppStore((s) => s.licenseResult)
  const examinerProfile = useAppStore((s) => s.examinerProfile)
  const setReportHtml = useAppStore((s) => s.setReportHtml)
  const setReportVisible = useAppStore((s) => s.setReportVisible)

  const handleOpenEvidence = async () => {
    const path = await openEvidenceDialog()
    if (!path) return

    const result = await loadEvidence(path)
    if (!result.success) {
      console.error('Failed to load evidence:', result.error)
      return
    }

    setEvidence(result.evidence_id, result.name)
    setCase(result.evidence_id, result.name)

    const stats = await getStats(result.evidence_id)
    setStats(stats)

    setSelectedNode('vol-ntfs')
  }

  const handleReport = async () => {
    const result = await generateReport({
      case_number: 'STRATA-2026-001',
      case_name: caseName ?? 'Unsaved Session',
      examiner_name: examinerProfile?.name ?? 'Dev Examiner',
      examiner_agency: examinerProfile?.agency ?? 'Wolfmark Systems',
      examiner_badge: examinerProfile?.badge ?? 'DEV-001',
      include_artifacts: true,
      include_tagged: true,
      include_mitre: true,
      include_timeline: true,
    })
    setReportHtml(result.html)
    setReportVisible(true)
  }

  const { width } = useWindowSize()
  const narrow = width < 900
  const veryNarrow = width < 1280

  return (
    <div style={{ flexShrink: 0 }}>
      {/* ═══ ROW 1 ═══ */}
      <div
        style={{
          height: 44,
          background: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          padding: '0 14px',
          gap: 8,
        }}
      >
        {/* LEFT */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            flexShrink: 0,
          }}
        >
          {/* Wolf mark */}
          <div style={{ marginRight: 10, display: 'flex', alignItems: 'center' }}>
            <WolfMark size={28} />
          </div>

          {/* STRATA wordmark */}
          <div
            style={{
              fontSize: 18,
              fontWeight: 700,
              letterSpacing: '0.18em',
              color: 'var(--text-1)',
              marginRight: 12,
            }}
          >
            STRATA
          </div>

          <div className="vdiv" />
        </div>

        {/* CENTER nav */}
        <div
          style={{
            flex: 1,
            display: 'flex',
            justifyContent: 'center',
            gap: 8,
          }}
        >
          <button className="btn-primary" onClick={handleOpenEvidence}>
            {narrow ? '+' : '+ Open Evidence'}
          </button>
          <button className="btn-secondary">
            {narrow ? 'New' : 'New Case'}
          </button>
          <button className="btn-secondary">
            {narrow ? 'Open' : 'Open Case'}
          </button>
        </div>

        {/* RIGHT */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexShrink: 0,
          }}
        >
          <span
            style={{
              fontSize: 10,
              color: 'var(--text-muted)',
              letterSpacing: '0.08em',
            }}
          >
            CASE
          </span>
          <span
            style={{
              fontSize: 11,
              color: 'var(--text-2)',
            }}
          >
            {examinerProfile?.name
              ? `${shortName(examinerProfile.name)} \u00B7 ${caseName ?? 'Unsaved Session'}`
              : (caseName ?? 'Unsaved Session')}
          </span>

          <div className="vdiv" />

          <LicenseBadge tier={licenseResult?.tier ?? 'pro'} days={licenseResult?.days_remaining ?? 999} />

          {isDev && (
            <span
              className="badge"
              style={{
                background: '#2a1a00',
                border: '1px solid var(--sus)',
                color: 'var(--sus)',
              }}
            >
              DEV
            </span>
          )}
        </div>
      </div>

      {/* ═══ ROW 2 ═══ */}
      <div
        style={{
          height: 36,
          background: '#090a0e',
          borderBottom: '1px solid var(--border-sub)',
          display: 'flex',
          alignItems: 'center',
          padding: '0 14px',
          gap: 8,
        }}
      >
        {/* LEFT spacer for centering */}
        <div style={{ flex: 1 }} />

        {/* Search group */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            flexShrink: 0,
          }}
        >
          <span
            style={{
              fontSize: 13,
              color: 'var(--text-muted)',
              flexShrink: 0,
            }}
          >
            ⌕
          </span>
          <input
            type="text"
            placeholder="Search files, paths, extensions..."
            readOnly
            onFocus={() => setSearchActive(true)}
            onClick={() => setSearchActive(true)}
            style={{
              width: 440,
              maxWidth: '100%',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              padding: '5px 10px',
              color: 'var(--text-2)',
              fontSize: 12,
              cursor: 'pointer',
            }}
          />
          <button
            onClick={toggleMetadata}
            style={{
              padding: '3px 8px',
              borderRadius: 3,
              fontSize: 10,
              border: `1px solid ${metadataSearch ? '#1c3050' : 'var(--border)'}`,
              background: metadataSearch ? '#0f1e30' : 'var(--bg-elevated)',
              color: metadataSearch ? 'var(--text-2)' : 'var(--text-muted)',
              fontFamily: 'monospace',
            }}
          >
            Metadata
          </button>
          <button
            onClick={toggleFulltext}
            style={{
              padding: '3px 8px',
              borderRadius: 3,
              fontSize: 10,
              border: `1px solid ${fulltextSearch ? '#1c3050' : 'var(--border)'}`,
              background: fulltextSearch ? '#0f1e30' : 'var(--bg-elevated)',
              color: fulltextSearch ? 'var(--text-2)' : 'var(--text-muted)',
              fontFamily: 'monospace',
            }}
          >
            Full-text
          </button>
        </div>

        <div style={{ flex: 1 }} />

        <div className="vdiv" />

        {/* Stats */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            flexShrink: 0,
          }}
        >
          {!veryNarrow && <Stat label="FILES" value={stats.files} color="#4a6080" />}
          <Stat label="SUSPICIOUS" value={stats.suspicious} color="var(--sus)" />
          <Stat label="FLAGGED" value={stats.flagged} color="var(--flag)" />
          {!veryNarrow && <Stat label="CARVED" value={stats.carved} color="var(--carved)" />}
          {!veryNarrow && <Stat label="HASHED" value={stats.hashed} color="var(--hashed)" />}
          {!narrow && <Stat label="ARTIFACTS" value={stats.artifacts} color="var(--artifact)" />}
        </div>

        <div className="vdiv" />

        {/* Action buttons */}
        <div
          style={{
            display: 'flex',
            gap: 6,
            flexShrink: 0,
          }}
        >
          <button
            className="btn-action"
            style={{
              color: 'var(--text-2)',
              border: '1px solid #1a2840',
              background: 'var(--bg-elevated)',
            }}
          >
            HASH ALL
          </button>
          <button
            className="btn-action"
            style={{
              color: 'var(--text-muted)',
              border: '1px solid var(--border)',
              background: '#0c0e12',
            }}
          >
            CARVE
          </button>
          <button
            className="btn-action"
            onClick={handleReport}
            style={{
              color: 'var(--hashed)',
              border: '1px solid #142018',
              background: '#0a1410',
              cursor: 'pointer',
            }}
          >
            REPORT
          </button>
          <button
            className="btn-action"
            style={{
              color: 'var(--sus)',
              border: '1px solid #382010',
              background: '#140e08',
            }}
          >
            EXPORT
          </button>
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div
      style={{
        display: 'flex',
        gap: 4,
        alignItems: 'baseline',
        fontSize: 11,
        fontWeight: 700,
      }}
    >
      <span style={{ color: 'var(--text-muted)' }}>{label}</span>
      <span style={{ color }}>{value}</span>
    </div>
  )
}

function shortName(name: string): string {
  const parts = name.trim().split(/\s+/)
  if (parts.length === 1) return parts[0]
  return `${parts[0][0]}. ${parts[parts.length - 1]}`
}

function LicenseBadge({ tier, days }: { tier: string; days: number }) {
  if (tier === 'trial') {
    return (
      <span
        className="badge"
        style={{
          background: '#2a1a00',
          border: '1px solid var(--sus)',
          color: 'var(--sus)',
        }}
      >
        Trial {'\u2014'} {days}d
      </span>
    )
  }
  if (tier === 'none') {
    return (
      <span
        className="badge"
        style={{
          background: '#2a0a0a',
          border: '1px solid var(--flag)',
          color: 'var(--flag)',
        }}
      >
        No License
      </span>
    )
  }
  return (
    <span
      className="badge"
      style={{
        background: '#0f1c2e',
        border: '1px solid #1c3050',
        color: '#8fa8c0',
      }}
    >
      Pro
    </span>
  )
}
