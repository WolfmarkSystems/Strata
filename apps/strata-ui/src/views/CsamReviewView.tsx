import { useEffect, useState } from 'react'
import { useAppStore } from '../store/appStore'
import EmptyState from '../components/EmptyState'
import {
  csamCreateSession,
  csamDropSession,
  csamImportHashSet,
  csamRunScan,
  csamListHits,
  csamReviewHit,
  csamConfirmHit,
  csamDismissHit,
  csamGenerateReport,
  csamExportAuditLog,
  csamSessionSummary,
  type CsamHitInfo,
  type CsamSessionSummary,
} from '../ipc'

const DISMISS_REASONS = [
  'Legal adult content',
  'Not CSAM',
  'Hash collision',
  'Other',
]

const DEFAULT_SCAN_OPTIONS = {
  run_exact_hash: true,
  run_perceptual: true,
  perceptual_threshold: 8,
  scan_all_files: false,
  image_extensions: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'heic', 'heif'],
}

type HitFilter = 'pending' | 'confirmed' | 'dismissed'

export default function CsamReviewView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const examinerProfile = useAppStore((s) => s.examinerProfile)
  const caseData = useAppStore((s) => s.caseData)

  const [sessionActive, setSessionActive] = useState(false)
  const [summary, setSummary] = useState<CsamSessionSummary | null>(null)
  const [hits, setHits] = useState<CsamHitInfo[]>([])
  const [scanning, setScanning] = useState(false)
  const [scanStatus, setScanStatus] = useState<string | null>(null)
  const [hashSetPath, setHashSetPath] = useState('')
  const [hashSetName, setHashSetName] = useState('NCMEC')
  const [filter, setFilter] = useState<HitFilter>('pending')
  const [confirmDialog, setConfirmDialog] = useState<CsamHitInfo | null>(null)
  const [dismissDialog, setDismissDialog] = useState<CsamHitInfo | null>(null)

  const examiner = examinerProfile?.name ?? 'Examiner'
  const caseNumber = caseData?.case_number ?? evidenceId ?? 'unknown'

  const refresh = async () => {
    if (!evidenceId) return
    const list = await csamListHits(evidenceId)
    setHits(list)
    const sum = await csamSessionSummary(evidenceId)
    setSummary(sum)
  }

  useEffect(() => {
    if (sessionActive) void refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionActive, evidenceId])

  if (!evidenceLoaded || !evidenceId) {
    return (
      <EmptyState
        icon={'\u{1F512}'}
        title="CSAM Review"
        subtitle="Load evidence before starting a CSAM review session"
        hint="Restricted - Law Enforcement Use Only"
      />
    )
  }

  const handleCreateSession = async () => {
    const ok = await csamCreateSession(evidenceId, examiner, caseNumber)
    if (ok) {
      setSessionActive(true)
      setScanStatus('Session created')
    } else {
      setScanStatus('Failed to create session')
    }
  }

  const handleDropSession = async () => {
    await csamDropSession(evidenceId)
    setSessionActive(false)
    setHits([])
    setSummary(null)
    setScanStatus(null)
  }

  const handleImport = async () => {
    if (!hashSetPath.trim() || !hashSetName.trim()) return
    setScanStatus('Importing hash set...')
    const result = await csamImportHashSet(
      evidenceId,
      hashSetPath.trim(),
      hashSetName.trim(),
      examiner,
      caseNumber,
    )
    if (result) {
      setScanStatus(`Imported ${result.entry_count.toLocaleString()} entries from ${result.name}`)
      setHashSetPath('')
      await refresh()
    } else {
      setScanStatus('Import failed')
    }
  }

  const handleScan = async () => {
    setScanning(true)
    setScanStatus('Scanning evidence...')
    const result = await csamRunScan(evidenceId, DEFAULT_SCAN_OPTIONS)
    setScanning(false)
    if (result) {
      setScanStatus(
        `Scan complete - ${result.files_scanned.toLocaleString()} files, ${result.hits_found} hits`,
      )
      await refresh()
    } else {
      setScanStatus('Scan failed')
    }
  }

  const handleConfirm = async (hitId: string, notes: string) => {
    if (!notes.trim()) return
    await csamReviewHit(evidenceId, hitId)
    await csamConfirmHit(evidenceId, hitId, notes.trim())
    setConfirmDialog(null)
    await refresh()
  }

  const handleDismiss = async (hitId: string, reason: string) => {
    await csamReviewHit(evidenceId, hitId)
    await csamDismissHit(evidenceId, hitId, reason)
    setDismissDialog(null)
    await refresh()
  }

  const handleGenerateReport = async () => {
    const path = `${caseNumber}-csam-report.pdf`
    const ok = await csamGenerateReport(evidenceId, path)
    setScanStatus(ok ? `Report generated: ${path}` : 'Report generation failed')
  }

  const handleExportAudit = async () => {
    const path = `${caseNumber}-csam-audit.json`
    const ok = await csamExportAuditLog(evidenceId, path)
    setScanStatus(ok ? `Audit log exported: ${path}` : 'Audit export failed')
  }

  const pending = hits.filter((h) => !h.examiner_reviewed)
  const confirmed = hits.filter((h) => h.examiner_reviewed && h.examiner_confirmed)
  const dismissed = hits.filter((h) => h.examiner_reviewed && !h.examiner_confirmed)
  const allReviewed = hits.length > 0 && pending.length === 0

  const visible =
    filter === 'pending' ? pending : filter === 'confirmed' ? confirmed : dismissed

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
      <RestrictedBanner />

      <div style={{ display: 'flex', flex: 1, gap: 8, overflow: 'hidden' }}>
        {/* Session panel */}
        <div
          className="bubble"
          style={{
            width: 280,
            display: 'flex',
            flexDirection: 'column',
            flexShrink: 0,
          }}
        >
          <SectionHeader>Session</SectionHeader>
          <div style={{ padding: 12, overflowY: 'auto', flex: 1 }}>
            <Row k="Status" v={sessionActive ? 'Active' : 'Inactive'} />
            <Row k="Examiner" v={examiner} />
            <Row k="Case" v={caseNumber} />
            {summary && (
              <>
                <Row k="Hash Sets" v={String(summary.hash_set_count)} />
                <Row k="Hits" v={String(summary.hit_count)} />
                <Row k="Confirmed" v={String(summary.confirmed_count)} />
                <Row k="Audit Entries" v={String(summary.audit_entry_count)} />
              </>
            )}
            <Sep />
            {!sessionActive ? (
              <button
                className="btn-primary"
                onClick={handleCreateSession}
                style={{ width: '100%', marginBottom: 8 }}
              >
                CREATE SESSION
              </button>
            ) : (
              <>
                <div
                  style={{
                    fontSize: 10,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    marginBottom: 6,
                  }}
                >
                  Import Hash Set
                </div>
                <input
                  value={hashSetName}
                  onChange={(e) => setHashSetName(e.target.value)}
                  placeholder="NCMEC"
                  style={inputStyle}
                />
                <input
                  value={hashSetPath}
                  onChange={(e) => setHashSetPath(e.target.value)}
                  placeholder="/path/to/hashset.csv"
                  style={inputStyle}
                />
                <button
                  className="btn-secondary"
                  onClick={handleImport}
                  style={{ width: '100%', marginBottom: 8 }}
                >
                  IMPORT
                </button>
                <Sep />
                <button
                  className="btn-primary"
                  onClick={handleScan}
                  disabled={scanning}
                  style={{ width: '100%', marginBottom: 8 }}
                >
                  {scanning ? 'SCANNING...' : 'RUN SCAN'}
                </button>
                <button
                  className="btn-secondary"
                  onClick={handleGenerateReport}
                  disabled={!allReviewed}
                  title={
                    allReviewed
                      ? 'Generate certified PDF report'
                      : 'Review all hits first'
                  }
                  style={{ width: '100%', marginBottom: 8, opacity: allReviewed ? 1 : 0.5 }}
                >
                  GENERATE REPORT
                </button>
                <button
                  className="btn-secondary"
                  onClick={handleExportAudit}
                  style={{ width: '100%', marginBottom: 8 }}
                >
                  EXPORT AUDIT LOG
                </button>
                <button
                  className="btn-secondary"
                  onClick={handleDropSession}
                  style={{ width: '100%' }}
                >
                  END SESSION
                </button>
              </>
            )}
            {scanStatus && (
              <div
                style={{
                  marginTop: 10,
                  fontSize: 11,
                  color: 'var(--text-muted)',
                  fontFamily: 'monospace',
                  wordBreak: 'break-all',
                }}
              >
                {scanStatus}
              </div>
            )}
          </div>
        </div>

        {/* Review queue */}
        <div className="bubble" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <SectionHeader>Review Queue</SectionHeader>
          <div
            style={{
              display: 'flex',
              padding: '8px 12px',
              gap: 6,
              borderBottom: '1px solid var(--border-sub)',
              flexShrink: 0,
            }}
          >
            <FilterChip
              label={`Pending ${pending.length}`}
              active={filter === 'pending'}
              color="var(--sus)"
              onClick={() => setFilter('pending')}
            />
            <FilterChip
              label={`Confirmed ${confirmed.length}`}
              active={filter === 'confirmed'}
              color="var(--flag)"
              onClick={() => setFilter('confirmed')}
            />
            <FilterChip
              label={`Dismissed ${dismissed.length}`}
              active={filter === 'dismissed'}
              color="var(--text-muted)"
              onClick={() => setFilter('dismissed')}
            />
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 12 }}>
            {visible.length === 0 ? (
              <div
                style={{
                  textAlign: 'center',
                  color: 'var(--text-muted)',
                  fontSize: 12,
                  padding: 24,
                }}
              >
                {sessionActive
                  ? `No ${filter} hits`
                  : 'Create a session and run a scan to see hits'}
              </div>
            ) : (
              visible.map((hit) => (
                <CsamHitCard
                  key={hit.hit_id}
                  hit={hit}
                  filter={filter}
                  onConfirm={() => setConfirmDialog(hit)}
                  onDismiss={() => setDismissDialog(hit)}
                />
              ))
            )}
          </div>
        </div>
      </div>

      {confirmDialog && (
        <CsamConfirmDialog
          hit={confirmDialog}
          onClose={() => setConfirmDialog(null)}
          onConfirm={(notes) => handleConfirm(confirmDialog.hit_id, notes)}
        />
      )}
      {dismissDialog && (
        <CsamDismissDialog
          hit={dismissDialog}
          onClose={() => setDismissDialog(null)}
          onDismiss={(reason) => handleDismiss(dismissDialog.hit_id, reason)}
        />
      )}
    </div>
  )
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg-elevated)',
  border: '1px solid var(--border)',
  borderRadius: 4,
  color: 'var(--text-2)',
  padding: '6px 8px',
  fontSize: 11,
  fontFamily: 'monospace',
  marginBottom: 6,
  boxSizing: 'border-box',
}

function RestrictedBanner() {
  return (
    <div
      className="bubble-tight"
      style={{
        padding: '8px 14px',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        background: 'rgba(168,64,64,0.10)',
        border: '1px solid rgba(168,64,64,0.45)',
      }}
    >
      <span style={{ fontSize: 14 }}>{'⚠'}</span>
      <span
        style={{
          fontSize: 11,
          fontWeight: 700,
          letterSpacing: '0.12em',
          color: 'var(--flag)',
          textTransform: 'uppercase',
        }}
      >
        Restricted
      </span>
      <span style={{ fontSize: 11, color: 'var(--text-2)' }}>
        Law Enforcement Use Only. All review actions are logged to an immutable audit trail.
        File previews are intentionally disabled - hash-only review.
      </span>
    </div>
  )
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        padding: '7px 10px',
        fontSize: 9,
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        borderBottom: '1px solid var(--border-sub)',
        flexShrink: 0,
      }}
    >
      {children}
    </div>
  )
}

function FilterChip({
  label,
  active,
  color,
  onClick,
}: {
  label: string
  active: boolean
  color: string
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '4px 10px',
        fontSize: 10,
        fontFamily: 'monospace',
        fontWeight: 700,
        letterSpacing: '0.06em',
        textTransform: 'uppercase',
        borderRadius: 3,
        background: active ? 'var(--bg-elevated)' : 'transparent',
        border: `1px solid ${active ? color : 'var(--border)'}`,
        color: active ? color : 'var(--text-muted)',
        cursor: 'pointer',
      }}
    >
      {label}
    </button>
  )
}

function CsamHitCard({
  hit,
  filter,
  onConfirm,
  onDismiss,
}: {
  hit: CsamHitInfo
  filter: HitFilter
  onConfirm: () => void
  onDismiss: () => void
}) {
  return (
    <div
      style={{
        marginBottom: 10,
        padding: 12,
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border)',
        borderRadius: 4,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          gap: 8,
          marginBottom: 6,
        }}
      >
        <span
          style={{
            fontSize: 12,
            fontWeight: 700,
            color: 'var(--text-1)',
            fontFamily: 'monospace',
          }}
        >
          Hit {hit.hit_id.slice(0, 8)}
        </span>
        <span
          style={{
            fontSize: 9,
            padding: '1px 6px',
            borderRadius: 3,
            background: 'rgba(74,120,144,0.15)',
            border: '1px solid rgba(74,120,144,0.3)',
            color: 'var(--carved)',
            fontFamily: 'monospace',
            textTransform: 'uppercase',
          }}
        >
          {hit.match_type}
        </span>
        <span
          style={{
            fontSize: 9,
            color: 'var(--text-muted)',
            fontFamily: 'monospace',
          }}
        >
          {hit.confidence}
        </span>
        <div style={{ flex: 1 }} />
        <span
          style={{
            fontSize: 10,
            color: 'var(--text-muted)',
            fontFamily: 'monospace',
          }}
        >
          {hit.timestamp_utc}
        </span>
      </div>

      <Row k="Source" v={hit.match_source} />
      <Row k="Path" v={hit.file_path} mono />
      <Row k="Size" v={`${hit.file_size.toLocaleString()} bytes`} />
      <Row k="MD5" v={hit.md5} mono />
      <Row k="SHA-1" v={hit.sha1} mono />
      <Row k="SHA-256" v={hit.sha256} mono />
      {hit.perceptual_hash && (
        <Row
          k="dHash"
          v={`${hit.perceptual_hash} (distance ${hit.perceptual_distance ?? '—'})`}
          mono
        />
      )}
      {hit.examiner_notes && <Row k="Notes" v={hit.examiner_notes} />}

      {filter === 'pending' && (
        <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
          <button
            onClick={onConfirm}
            style={{
              padding: '5px 12px',
              fontSize: 11,
              fontFamily: 'monospace',
              fontWeight: 700,
              letterSpacing: '0.06em',
              color: 'var(--flag)',
              background: 'rgba(168,64,64,0.1)',
              border: '1px solid rgba(168,64,64,0.45)',
              borderRadius: 4,
              cursor: 'pointer',
            }}
          >
            CONFIRM CSAM
          </button>
          <button
            onClick={onDismiss}
            style={{
              padding: '5px 12px',
              fontSize: 11,
              fontFamily: 'monospace',
              fontWeight: 700,
              letterSpacing: '0.06em',
              color: 'var(--text-2)',
              background: 'var(--bg-panel)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              cursor: 'pointer',
            }}
          >
            DISMISS
          </button>
        </div>
      )}
    </div>
  )
}

function CsamConfirmDialog({
  hit,
  onClose,
  onConfirm,
}: {
  hit: CsamHitInfo
  onClose: () => void
  onConfirm: (notes: string) => void
}) {
  const [notes, setNotes] = useState('')
  return (
    <ModalShell title="Confirm CSAM Hit" onClose={onClose}>
      <div
        style={{
          padding: '10px 12px',
          fontSize: 11,
          color: 'var(--flag)',
          background: 'rgba(168,64,64,0.1)',
          border: '1px solid rgba(168,64,64,0.45)',
          borderRadius: 4,
          marginBottom: 12,
        }}
      >
        {'⚠'} This action records a CSAM confirmation in the immutable audit log.
        It cannot be undone.
      </div>
      <Row k="Hit" v={hit.hit_id} mono />
      <Row k="Path" v={hit.file_path} mono />
      <Row k="SHA-256" v={hit.sha256} mono />
      <div
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginTop: 12,
          marginBottom: 6,
        }}
      >
        Examiner Notes (required)
      </div>
      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="Document basis for confirmation, hash database source, and any contextual evidence."
        style={{
          width: '100%',
          minHeight: 96,
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderRadius: 4,
          color: 'var(--text-2)',
          padding: 8,
          fontSize: 12,
          fontFamily: 'inherit',
          boxSizing: 'border-box',
          resize: 'vertical',
        }}
      />
      <div style={{ display: 'flex', gap: 8, marginTop: 12, justifyContent: 'flex-end' }}>
        <button className="btn-secondary" onClick={onClose}>CANCEL</button>
        <button
          onClick={() => onConfirm(notes)}
          disabled={!notes.trim()}
          style={{
            padding: '6px 14px',
            fontSize: 11,
            fontFamily: 'monospace',
            fontWeight: 700,
            letterSpacing: '0.06em',
            color: 'var(--flag)',
            background: 'rgba(168,64,64,0.1)',
            border: '1px solid rgba(168,64,64,0.45)',
            borderRadius: 4,
            cursor: notes.trim() ? 'pointer' : 'not-allowed',
            opacity: notes.trim() ? 1 : 0.5,
          }}
        >
          CONFIRM CSAM
        </button>
      </div>
    </ModalShell>
  )
}

function CsamDismissDialog({
  hit,
  onClose,
  onDismiss,
}: {
  hit: CsamHitInfo
  onClose: () => void
  onDismiss: (reason: string) => void
}) {
  const [reason, setReason] = useState(DISMISS_REASONS[0])
  return (
    <ModalShell title="Dismiss Hit" onClose={onClose}>
      <Row k="Hit" v={hit.hit_id} mono />
      <Row k="Path" v={hit.file_path} mono />
      <div
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginTop: 12,
          marginBottom: 6,
        }}
      >
        Dismissal Reason
      </div>
      <select
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        style={{
          width: '100%',
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderRadius: 4,
          color: 'var(--text-2)',
          padding: '6px 8px',
          fontSize: 12,
          boxSizing: 'border-box',
        }}
      >
        {DISMISS_REASONS.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
      <div style={{ display: 'flex', gap: 8, marginTop: 12, justifyContent: 'flex-end' }}>
        <button className="btn-secondary" onClick={onClose}>CANCEL</button>
        <button className="btn-primary" onClick={() => onDismiss(reason)}>
          DISMISS HIT
        </button>
      </div>
    </ModalShell>
  )
}

function ModalShell({
  title,
  onClose,
  children,
}: {
  title: string
  onClose: () => void
  children: React.ReactNode
}) {
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        className="bubble"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 540,
          maxHeight: '80vh',
          overflowY: 'auto',
          padding: 18,
        }}
      >
        <div
          style={{
            fontSize: 14,
            fontWeight: 700,
            color: 'var(--text-1)',
            marginBottom: 12,
          }}
        >
          {title}
        </div>
        {children}
      </div>
    </div>
  )
}

function Row({
  k,
  v,
  mono = false,
}: {
  k: string
  v: string
  mono?: boolean
}) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        marginBottom: 6,
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
          fontSize: mono ? 10 : 11,
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
