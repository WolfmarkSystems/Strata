import { useAppStore } from '../store/appStore'
import { useWindowSize } from '../hooks/useWindowSize'
import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  openEvidenceDialog,
  openFolderDialog,
  loadEvidence,
  getStats,
  generateReport,
  hashAllFiles,
  getTreeChildren,
  getTreeRoot,
  onHashProgress,
  openCase,
  runAllPlugins,
} from '../ipc'
import WolfMark from './WolfMark'
import NewCaseModal from './NewCaseModal'

// Sprint 8 P1 F1 — pulsed badge shown while the post-load auto-index
// (`runAllPlugins` triggered from `handleOpenEvidence`) is in flight.
function IndexingBadge() {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        padding: '2px 10px',
        borderRadius: 4,
        background: 'rgba(200, 160, 64, 0.12)',
        border: '1px solid rgba(200, 160, 64, 0.45)',
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: '0.12em',
        color: 'var(--artifact)',
        animation: 'pulse 1.6s ease-in-out infinite',
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: 'var(--artifact)',
        }}
      />
      INDEXING...
    </div>
  )
}

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
  const evidenceId = useAppStore((s) => s.evidenceId)
  const caseData = useAppStore((s) => s.caseData)
  const caseModified = useAppStore((s) => s.caseModified)
  const setCaseData = useAppStore((s) => s.setCaseData)

  const [newCaseOpen, setNewCaseOpen] = useState(false)
  const [reportOpen, setReportOpen] = useState(false)

  const handleOpenCase = async () => {
    const result = await openCase()
    if (result) {
      setCaseData(result.case, result.case_path)
    }
  }

  // Hashing progress state
  const [hashing, setHashing] = useState(false)
  const [hashProgress, setHashProgress] = useState<{ done: number; total: number } | null>(null)

  useEffect(() => {
    let unlisten: (() => void) | null = null
    onHashProgress((data) => {
      setHashProgress(data)
      if (data.total > 0 && data.done >= data.total) {
        setHashing(false)
        // Refresh stats so the HASHED counter updates
        if (evidenceId) {
          getStats(evidenceId).then(setStats)
        }
      }
    }).then((u) => {
      unlisten = u
    })
    return () => {
      if (unlisten) unlisten()
    }
  }, [evidenceId, setStats])

  const handleHashAll = async () => {
    if (!evidenceId || hashing) return
    setHashing(true)
    setHashProgress({ done: 0, total: 0 })
    try {
      await hashAllFiles(evidenceId)
    } finally {
      setHashing(false)
      const s = await getStats(evidenceId)
      setStats(s)
    }
  }

  const setPluginsRunning = useAppStore((s) => s.setPluginsRunning)
  const pluginsRunning = useAppStore((s) => s.pluginsRunning)

  const handleOpenPath = async (path: string | null) => {
    if (!path) return

    const result = await loadEvidence(path)
    if (!result.success) {
      console.error('Failed to load evidence:', result.error)
      return
    }

    setEvidence(result.evidence_id, result.name)
    setCase(result.evidence_id, result.name)

    const preStats = await getStats(result.evidence_id)
    setStats(preStats)

    const roots = await getTreeRoot(result.evidence_id)
    const root = roots[0]
    if (root) {
      const children = root.has_children ? await getTreeChildren(root.id) : []
      setSelectedNode(children[0]?.id ?? root.id)
    }

    // Sprint 8 P1 F1: auto-index immediately after load so the
    // artifact count reflects reality by the time the examiner
    // reaches the Artifacts view. TopBar renders an INDEXING badge
    // while this is in flight.
    setPluginsRunning(true)
    try {
      await runAllPlugins(result.evidence_id)
      const postStats = await getStats(result.evidence_id)
      setStats(postStats)
    } catch (e) {
      console.error('runAllPlugins failed:', e)
    } finally {
      setPluginsRunning(false)
    }
  }

  const handleReport = async () => {
    if (!evidenceId) return
    setReportOpen(true)
  }

  const { width } = useWindowSize()
  const narrow = width < 900
  const veryNarrow = width < 1280

  return (
    <div
      style={{
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--bg-base)',
        padding: '8px 8px 0 8px',
        gap: 8,
      }}
    >
      {/* ─── ROW 1 — floating wolf + brand + nav + case info ─── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          minWidth: 0,
          height: 44,
        }}
      >
        {/* Floating wolf head (no box) */}
        <div
          style={{
            width: 44,
            height: 44,
            flexShrink: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <WolfMark size={44} />
        </div>

        {/* STRATA wordmark bubble */}
        <div
          className="bubble-tight"
          style={{
            height: 44,
            padding: '0 18px',
            display: 'flex',
            alignItems: 'center',
            fontSize: 18,
            fontWeight: 700,
            letterSpacing: '0.22em',
            color: 'var(--text-1)',
            flexShrink: 0,
          }}
        >
          STRATA
        </div>

        {/* Nav buttons bubble */}
        <div
          className="bubble-tight"
          style={{
            height: 44,
            padding: '0 8px',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            flexShrink: 0,
          }}
        >
          <button
            className="btn-primary"
            onClick={async () => handleOpenPath(await openEvidenceDialog())}
          >
            {narrow ? '+' : '+ Open Evidence'}
          </button>
          <button
            className="btn-secondary"
            onClick={async () => handleOpenPath(await openFolderDialog())}
            title="Open a folder of extracted evidence (logical image, mobile filesystem dump, Cellebrite UFED export, etc.)"
          >
            {narrow ? '+F' : '+ Open Folder'}
          </button>
          <button className="btn-secondary" onClick={() => setNewCaseOpen(true)}>
            {narrow ? 'New' : 'New Case'}
          </button>
          <button className="btn-secondary" onClick={handleOpenCase}>
            {narrow ? 'Open' : 'Open Case'}
          </button>
        </div>

        <div style={{ flex: 1 }} />

        {/* Case info bubble */}
        <div
          className="bubble-tight"
          style={{
            height: 44,
            padding: '0 14px',
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
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            {examinerProfile?.name
              ? `${shortName(examinerProfile.name)} \u00B7 ${caseName ?? 'Unsaved Session'}`
              : (caseName ?? 'Unsaved Session')}
            {caseData && caseModified && (
              <span
                title="Unsaved changes — Cmd+S to save now"
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: 'var(--sus)',
                  display: 'inline-block',
                  flexShrink: 0,
                }}
              />
            )}
          </span>
          <div className="vdiv" />
          <LicenseBadge tier={licenseResult?.tier ?? 'pro'} days={licenseResult?.days_remaining ?? 999} />
          {isDev && (
            <span
              className="badge"
              style={{
                background: 'var(--bg-elevated)',
                border: '1px solid var(--sus)',
                color: 'var(--sus)',
              }}
            >
              DEV
            </span>
          )}
        </div>
      </div>

      {/* ─── ROW 2 — search + stats + actions, all floating bubbles ─── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          minWidth: 0,
          height: 40,
        }}
      >
        {/* Search bubble — flexes to fill */}
        <div
          className="bubble-tight"
          style={{
            flex: 1,
            minWidth: 0,
            height: 40,
            padding: '0 10px',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
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
              flex: 1,
              minWidth: 0,
              background: 'transparent',
              border: 'none',
              padding: '4px 6px',
              color: 'var(--text-2)',
              fontSize: 12,
              cursor: 'pointer',
              outline: 'none',
            }}
          />
          <button
            onClick={toggleMetadata}
            style={{
              padding: '4px 10px',
              borderRadius: 'var(--radius-sm)',
              fontSize: 10,
              border: `1px solid ${metadataSearch ? 'var(--accent-2)' : 'var(--border)'}`,
              background: 'var(--bg-elevated)',
              color: metadataSearch ? 'var(--text-1)' : 'var(--text-muted)',
              fontFamily: 'monospace',
              flexShrink: 0,
            }}
          >
            Metadata
          </button>
          <button
            onClick={toggleFulltext}
            style={{
              padding: '4px 10px',
              borderRadius: 'var(--radius-sm)',
              fontSize: 10,
              border: `1px solid ${fulltextSearch ? 'var(--accent-2)' : 'var(--border)'}`,
              background: 'var(--bg-elevated)',
              color: fulltextSearch ? 'var(--text-1)' : 'var(--text-muted)',
              fontFamily: 'monospace',
              flexShrink: 0,
            }}
          >
            Full-text
          </button>
        </div>

        {/* Stats bubble */}
        <div
          className="bubble-tight"
          style={{
            height: 40,
            padding: '0 14px',
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            flexShrink: 0,
          }}
        >
          {!veryNarrow && (
            <Stat
              label="FILES"
              value={stats.files}
              color="var(--text-2)"
              sub={`${stats.known_good} known-good / ${stats.unknown} unknown`}
            />
          )}
          <Stat label="SUSPICIOUS" value={stats.suspicious} color="var(--sus)" />
          <Stat label="FLAGGED" value={stats.flagged} color="var(--flag)" />
          {!veryNarrow && <Stat label="CARVED" value={stats.carved} color="var(--carved)" />}
          {!veryNarrow && <Stat label="HASHED" value={stats.hashed} color="var(--hashed)" />}
          {!narrow && <Stat label="ARTIFACTS" value={stats.artifacts} color="var(--artifact)" />}
          {pluginsRunning && <IndexingBadge />}
        </div>

        {/* Action buttons bubble */}
        <div
          className="bubble-tight"
          style={{
            height: 40,
            padding: '0 8px',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            flexShrink: 0,
          }}
        >
          <button
            className="btn-action"
            onClick={handleHashAll}
            disabled={!evidenceId || hashing}
            title={!evidenceId ? 'Load evidence first' : hashing ? 'Hashing in progress' : 'Hash every file in the evidence'}
            style={{
              color: hashing ? 'var(--sus)' : evidenceId ? 'var(--text-2)' : 'var(--text-muted)',
              border: '1px solid var(--border)',
              background: 'var(--bg-elevated)',
              cursor: !evidenceId || hashing ? 'not-allowed' : 'pointer',
              opacity: !evidenceId ? 0.5 : 1,
            }}
          >
            {hashing && hashProgress && hashProgress.total > 0
              ? `HASHING ${hashProgress.done}/${hashProgress.total}`
              : 'HASH ALL'}
          </button>
          <button
            className="btn-action"
            style={{
              color: 'var(--text-muted)',
              border: '1px solid var(--border)',
              background: 'var(--bg-elevated)',
            }}
          >
            CARVE
          </button>
          <button
            className="btn-action"
            onClick={handleReport}
            style={{
              color: 'var(--hashed)',
              border: '1px solid var(--border)',
              background: 'var(--bg-elevated)',
              cursor: 'pointer',
            }}
          >
            REPORT
          </button>
          <button
            className="btn-action"
            style={{
              color: 'var(--sus)',
              border: '1px solid var(--border)',
              background: 'var(--bg-elevated)',
            }}
          >
            EXPORT
          </button>
        </div>
      </div>
      {newCaseOpen && createPortal(<NewCaseModal onClose={() => setNewCaseOpen(false)} />, document.body)}
      {reportOpen && createPortal(
        <ReportGenerateDialog
          evidenceId={evidenceId}
          caseName={caseName ?? 'Unsaved Session'}
          examiner={examinerProfile?.name ?? 'Unknown Examiner'}
          onClose={() => setReportOpen(false)}
        />,
        document.body,
      )}
    </div>
  )
}

function ReportGenerateDialog({
  evidenceId,
  caseName,
  examiner,
  onClose,
}: {
  evidenceId: string | null
  caseName: string
  examiner: string
  onClose: () => void
}) {
  const [format, setFormat] = useState<'html' | 'pdf'>('html')
  const [outputPath, setOutputPath] = useState('')
  const [generatedPath, setGeneratedPath] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const handleGenerate = async () => {
    if (!evidenceId || busy) return
    setBusy(true)
    try {
      const path = await generateReport(evidenceId, outputPath, format)
      setGeneratedPath(path)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.45)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
    >
      <div
        className="bubble"
        style={{ width: 520, padding: 18, display: 'flex', flexDirection: 'column', gap: 12 }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ flex: 1, fontSize: 14, fontWeight: 700, color: 'var(--text-1)' }}>
            Generate Report
          </div>
          <button className="btn-secondary" onClick={onClose}>Close</button>
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
          {caseName} · {examiner}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className={format === 'html' ? 'btn-primary' : 'btn-secondary'}
            onClick={() => setFormat('html')}
          >
            HTML
          </button>
          <button
            className={format === 'pdf' ? 'btn-primary' : 'btn-secondary'}
            onClick={() => setFormat('pdf')}
          >
            PDF
          </button>
        </div>
        <input
          value={outputPath}
          onChange={(e) => setOutputPath(e.target.value)}
          placeholder={`/tmp/strata-report.${format}`}
          style={{
            background: 'var(--bg-elevated)',
            border: '1px solid var(--border)',
            borderRadius: 4,
            color: 'var(--text-2)',
            padding: '8px 10px',
            fontSize: 12,
          }}
        />
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Includes cover page, methodology, evidence integrity, findings, flagged notes, custody log, and certification.
        </div>
        <button className="btn-action" onClick={handleGenerate} disabled={!evidenceId || busy}>
          {busy ? 'GENERATING...' : 'GENERATE'}
        </button>
        {generatedPath && (
          <div style={{ fontSize: 11, color: 'var(--clean)', wordBreak: 'break-all' }}>
            Saved: {generatedPath}
          </div>
        )}
      </div>
    </div>
  )
}

function Stat({
  label,
  value,
  color,
  sub,
}: {
  label: string
  value: number
  color: string
  sub?: string
}) {
  return (
    <div
      title={sub}
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
          background: 'var(--bg-elevated)',
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
        background: 'var(--bg-elevated)',
        border: '1px solid var(--accent-2)',
        color: 'var(--text-1)',
      }}
    >
      Pro
    </span>
  )
}
