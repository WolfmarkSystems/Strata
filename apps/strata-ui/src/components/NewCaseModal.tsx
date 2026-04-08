import { useEffect, useState } from 'react'
import { useAppStore } from '../store/appStore'
import { listDrives, newCase, type DriveInfo } from '../ipc'

interface Props {
  onClose: () => void
}

const CASE_TYPES = ['Criminal', 'Civil', 'Internal', 'Other'] as const
type CaseType = (typeof CASE_TYPES)[number]

export default function NewCaseModal({ onClose }: Props) {
  const examinerProfile = useAppStore((s) => s.examinerProfile)
  const setCaseData = useAppStore((s) => s.setCaseData)

  const year = new Date().getFullYear()
  const [caseNumber, setCaseNumber] = useState(`CID-${year}-001`)
  const [caseName, setCaseName] = useState('')
  const [caseType, setCaseType] = useState<CaseType>('Criminal')
  const [drives, setDrives] = useState<DriveInfo[]>([])
  const [selectedDriveId, setSelectedDriveId] = useState<string | null>(null)
  const [errors, setErrors] = useState<{ caseNumber?: string; caseName?: string; drive?: string }>({})
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    listDrives().then((all) => {
      const permitted = all.filter((d) => d.is_permitted)
      setDrives(permitted)
      // Pre-select T7 / first permitted drive
      const t7 = permitted.find((d) => d.name.toLowerCase().includes('t7'))
      setSelectedDriveId(t7?.id ?? permitted[0]?.id ?? null)
    })
  }, [])

  // Esc closes
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  const handleCreate = async () => {
    const newErrors: typeof errors = {}
    if (!caseNumber.trim()) newErrors.caseNumber = 'Required'
    if (!caseName.trim()) newErrors.caseName = 'Required'
    if (!selectedDriveId) newErrors.drive = 'Select an evidence drive'
    setErrors(newErrors)
    if (Object.keys(newErrors).length > 0) return

    const drive = drives.find((d) => d.id === selectedDriveId)
    if (!drive) return

    const examiner = examinerProfile ?? {
      name: 'Dev Examiner',
      agency: 'Wolfmark Systems',
      badge: '',
      email: '',
    }

    const basePath = `${drive.mount_point}/strata-cases`

    setCreating(true)
    const result = await newCase(
      caseNumber.trim(),
      caseName.trim(),
      caseType,
      examiner,
      basePath,
    )
    setCreating(false)

    if (!result) {
      setErrors({ drive: 'Failed to create case folder. Check write permissions.' })
      return
    }

    setCaseData(result.case, result.case_path)
    onClose()
  }

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0, 0, 0, 0.85)',
        zIndex: 10000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="bubble"
        style={{
          width: 480,
          padding: '32px 36px',
          display: 'flex',
          flexDirection: 'column',
          gap: 18,
        }}
      >
        <div>
          <div
            style={{
              fontSize: 18,
              fontWeight: 700,
              letterSpacing: '0.14em',
              color: 'var(--text-1)',
              marginBottom: 4,
            }}
          >
            NEW CASE
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Creates a new case folder on your evidence drive.
          </div>
        </div>

        <Field
          label="Case Number *"
          value={caseNumber}
          onChange={(v) => {
            setCaseNumber(v)
            if (errors.caseNumber) setErrors({ ...errors, caseNumber: undefined })
          }}
          placeholder="CID-2026-001"
          error={errors.caseNumber}
        />

        <Field
          label="Case Name *"
          value={caseName}
          onChange={(v) => {
            setCaseName(v)
            if (errors.caseName) setErrors({ ...errors, caseName: undefined })
          }}
          placeholder="Investigation Name"
          error={errors.caseName}
        />

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <label style={labelStyle}>Case Type</label>
          <div style={{ display: 'flex', gap: 6 }}>
            {CASE_TYPES.map((t) => {
              const active = caseType === t
              return (
                <button
                  key={t}
                  onClick={() => setCaseType(t)}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    border: `1px solid ${active ? 'var(--accent-2)' : 'var(--border)'}`,
                    background: active ? 'var(--bg-elevated)' : 'transparent',
                    color: active ? 'var(--text-1)' : 'var(--text-muted)',
                    fontSize: 11,
                    fontFamily: 'monospace',
                    cursor: 'pointer',
                    transition: 'all 0.15s',
                  }}
                >
                  {t}
                </button>
              )
            })}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <label style={labelStyle}>Evidence Drive *</label>
          {drives.length === 0 ? (
            <div
              style={{
                fontSize: 11,
                color: 'var(--text-muted)',
                fontStyle: 'italic',
                padding: '10px 12px',
                border: '1px dashed var(--border)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              No permitted drives detected. Connect an external drive.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {drives.map((d) => {
                const active = selectedDriveId === d.id
                return (
                  <button
                    key={d.id}
                    onClick={() => setSelectedDriveId(d.id)}
                    style={{
                      padding: '10px 14px',
                      borderRadius: 'var(--radius-sm)',
                      border: `1px solid ${active ? 'var(--accent-2)' : 'var(--border)'}`,
                      background: active ? 'var(--bg-elevated)' : 'transparent',
                      color: 'var(--text-2)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.15s',
                      fontFamily: 'monospace',
                    }}
                  >
                    <div style={{ fontSize: 12, fontWeight: 700 }}>{d.name}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                      {d.mount_point} {'\u00B7'} {d.free_gb.toFixed(0)} GB free
                    </div>
                  </button>
                )
              })}
            </div>
          )}
          {errors.drive && (
            <div style={{ fontSize: 10, color: 'var(--flag)', marginTop: 4 }}>{errors.drive}</div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
          <button
            onClick={handleCreate}
            disabled={creating}
            className="btn-primary"
            style={{ flex: 1, height: 42 }}
          >
            {creating ? 'Creating...' : 'CREATE CASE'}
          </button>
          <button onClick={onClose} className="btn-secondary" style={{ height: 42 }}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

const labelStyle: React.CSSProperties = {
  fontSize: 10,
  color: 'var(--text-muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.1em',
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  error,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  error?: string
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <label style={labelStyle}>{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          height: 38,
          padding: '0 12px',
          background: 'var(--bg-input)',
          border: `1px solid ${error ? 'var(--flag)' : 'var(--border)'}`,
          borderRadius: 'var(--radius-sm)',
          color: 'var(--text-1)',
          fontSize: 13,
          fontFamily: 'monospace',
          outline: 'none',
        }}
      />
      {error && (
        <div style={{ fontSize: 10, color: 'var(--flag)' }}>{error}</div>
      )}
    </div>
  )
}
