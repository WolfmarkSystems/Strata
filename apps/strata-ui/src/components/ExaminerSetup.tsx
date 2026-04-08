import { useState } from 'react'
import { useAppStore } from '../store/appStore'
import { saveExaminerProfile } from '../ipc'
import GateBackground from './GateBackground'
import DevSkip from './DevSkip'

export default function ExaminerSetup() {
  const setGate = useAppStore((s) => s.setGate)
  const setExaminerProfile = useAppStore((s) => s.setExaminerProfile)
  const isDevMode = useAppStore((s) => s.isDevMode)

  const [name, setName] = useState('')
  const [agency, setAgency] = useState('')
  const [email, setEmail] = useState('')
  const [errors, setErrors] = useState<{ name?: string; agency?: string }>({})

  const handleContinue = async () => {
    const newErrors: typeof errors = {}
    if (!name.trim()) newErrors.name = 'Required'
    if (!agency.trim()) newErrors.agency = 'Required'
    setErrors(newErrors)
    if (Object.keys(newErrors).length > 0) return

    const profile = {
      name: name.trim(),
      agency: agency.trim(),
      badge: '',
      email: email.trim(),
    }
    await saveExaminerProfile(profile)
    setExaminerProfile(profile)
    setGate('drive')
  }

  const handleDevSkip = () => {
    setExaminerProfile({
      name: 'Dev Examiner',
      agency: 'Wolfmark Systems',
      badge: '',
      email: 'dev@wolfmark.local',
    })
    setGate('drive')
  }

  return (
    <GateBackground>
      <div
        style={{
          width: 480,
          background: 'var(--bg-panel)',
          borderStyle: 'solid',
          borderWidth: 1,
          borderColor: 'var(--border)',
          borderRadius: 12,
          padding: '40px 44px',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* Header */}
        <div style={{ marginBottom: 28, textAlign: 'center' }}>
          <div
            style={{
              fontSize: 22,
              fontWeight: 700,
              color: 'var(--text-1)',
              margin: '8px 0 4px',
            }}
          >
            Examiner Profile
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            This information appears in all generated reports
          </div>
        </div>

        {/* Fields */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <Field
            label="Full Name *"
            value={name}
            onChange={(v) => {
              setName(v)
              if (errors.name) setErrors({ ...errors, name: undefined })
            }}
            placeholder="Jane Smith"
            error={errors.name}
          />
          <Field
            label="Agency / Organization *"
            value={agency}
            onChange={(v) => {
              setAgency(v)
              if (errors.agency) setErrors({ ...errors, agency: undefined })
            }}
            placeholder="Metropolitan Police"
            error={errors.agency}
          />
          <Field
            label="Email Address"
            value={email}
            onChange={setEmail}
            placeholder="j.smith@metpolice.gov"
          />
        </div>

        <button
          onClick={handleContinue}
          style={{
            height: 46,
            marginTop: 20,
            background:
              'linear-gradient(135deg, #c8d8e8 0%, #d8e2ec 50%, #c8d8e8 100%)',
            color: '#070809',
            fontSize: 14,
            fontWeight: 700,
            fontFamily: 'monospace',
            letterSpacing: '0.06em',
            border: 'none',
            borderRadius: 6,
            cursor: 'pointer',
            transition: 'opacity 0.15s',
          }}
        >
          Continue to Evidence Setup {'\u2192'}
        </button>

        <div
          onClick={() => setGate('splash')}
          style={{
            textAlign: 'center',
            marginTop: 12,
            fontSize: 11,
            color: 'var(--text-muted)',
            cursor: 'pointer',
          }}
        >
          {'\u2190'} Back to license
        </div>
      </div>

      {isDevMode && <DevSkip onClick={handleDevSkip} />}
    </GateBackground>
  )
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
  placeholder: string
  error?: string
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
      <label
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
        }}
      >
        {label}
      </label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: '100%',
          height: 40,
          fontSize: 13,
          padding: '0 12px',
          borderStyle: 'solid',
          borderWidth: 1,
          borderColor: error ? 'var(--flag)' : 'var(--border)',
        }}
      />
      {error && (
        <div style={{ fontSize: 10, color: 'var(--flag)', marginTop: 2 }}>{error}</div>
      )}
    </div>
  )
}
