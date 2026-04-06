import { useState } from 'react'
import { useAppStore } from '../store/appStore'
import WolfMark from '../components/WolfMark'
import { THEMES } from '../themes'

type Tab = 'appearance' | 'examiner' | 'hashsets' | 'license' | 'about'

const TABS: Array<{ id: Tab; label: string }> = [
  { id: 'appearance', label: 'Appearance' },
  { id: 'examiner',   label: 'Examiner' },
  { id: 'hashsets',   label: 'Hash Sets' },
  { id: 'license',    label: 'License' },
  { id: 'about',      label: 'About' },
]

export default function SettingsView() {
  const [tab, setTab] = useState<Tab>('appearance')

  return (
    <div
      style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: 'var(--bg-base)',
      }}
    >
      {/* Tab bar */}
      <div
        style={{
          display: 'flex',
          borderBottomStyle: 'solid',
          borderBottomWidth: 1,
          borderBottomColor: 'var(--border-sub)',
          background: 'var(--bg-surface)',
          flexShrink: 0,
        }}
      >
        {TABS.map((t) => {
          const active = tab === t.id
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '10px 16px',
                fontSize: 12,
                cursor: 'pointer',
                background: 'transparent',
                color: active ? '#8fa8c0' : 'var(--text-muted)',
                borderTopStyle: 'none',
                borderRightStyle: 'none',
                borderLeftStyle: 'none',
                borderBottomStyle: 'solid',
                borderBottomWidth: 2,
                borderBottomColor: active ? '#8fa8c0' : 'transparent',
                transition: 'all 0.15s',
                fontFamily: 'inherit',
                userSelect: 'none',
              }}
            >
              {t.label}
            </button>
          )
        })}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        {tab === 'appearance' && <AppearanceTab />}
        {tab === 'examiner' && <ExaminerTab />}
        {tab === 'hashsets' && <HashSetsTab />}
        {tab === 'license' && <LicenseTab />}
        {tab === 'about' && <AboutTab />}
      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Appearance tab
// ──────────────────────────────────────────────────────────────────────────────

function AppearanceTab() {
  const activeTheme = useAppStore((s) => s.activeTheme)
  const setTheme = useAppStore((s) => s.setTheme)
  const [hover, setHover] = useState<string | null>(null)

  return (
    <div>
      <SectionLabel>Theme</SectionLabel>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {THEMES.map((t) => {
          const active = activeTheme === t.name
          const isHover = hover === t.name
          return (
            <div
              key={t.name}
              onClick={() => setTheme(t.name)}
              onMouseEnter={() => setHover(t.name)}
              onMouseLeave={() => setHover(null)}
              style={{
                background: t.vars['--bg-elevated'],
                borderStyle: 'solid',
                borderWidth: active ? 2 : 1,
                borderColor: active
                  ? t.vars['--accent-1']
                  : isHover
                    ? t.vars['--accent-muted']
                    : t.vars['--border'],
                borderRadius: 'var(--radius-md)',
                padding: active ? '11px 17px' : '12px 18px',
                cursor: 'pointer',
                minWidth: 140,
                transition: 'border-color 0.15s',
                userSelect: 'none',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  gap: 6,
                  marginBottom: 8,
                }}
              >
                {(
                  [
                    '--bg-base',
                    '--bg-surface',
                    '--accent-muted',
                    '--accent-2',
                    '--accent-1',
                  ] as const
                ).map((k) => (
                  <div
                    key={k}
                    style={{
                      width: 14,
                      height: 14,
                      borderRadius: 'var(--radius-sm)',
                      background: t.vars[k],
                      border: `1px solid ${t.vars['--border']}`,
                    }}
                  />
                ))}
              </div>
              <div
                style={{
                  fontSize: 13,
                  fontWeight: 700,
                  color: t.vars['--accent-1'],
                }}
              >
                {t.name}
              </div>
              <div
                style={{
                  fontSize: 10,
                  color: t.vars['--text-muted'],
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  marginTop: 2,
                }}
              >
                {active ? 'ACTIVE' : 'CLICK TO APPLY'}
              </div>
            </div>
          )
        })}
      </div>
      <div
        style={{
          fontSize: 11,
          color: 'var(--text-off)',
          marginTop: 16,
          fontStyle: 'italic',
        }}
      >
        Theme changes apply instantly across the app.
      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Examiner tab
// ──────────────────────────────────────────────────────────────────────────────

function ExaminerTab() {
  const examinerName = useAppStore((s) => s.examinerName)
  const [name, setName] = useState(examinerName)
  const [agency, setAgency] = useState('Wolfmark Systems')
  const [email, setEmail] = useState('dev@wolfmark.local')
  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div>
      <SectionLabel>Examiner Profile</SectionLabel>
      <div style={{ maxWidth: 440, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <Field label="Full Name" value={name} onChange={setName} />
        <Field label="Agency / Organization" value={agency} onChange={setAgency} />
        <Field label="Email Address" value={email} onChange={setEmail} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 4 }}>
          <button
            onClick={handleSave}
            className="btn-primary"
          >
            Save Profile
          </button>
          {saved && (
            <span style={{ fontSize: 11, color: 'var(--clean)' }}>
              {'\u2713'} Saved
            </span>
          )}
        </div>
      </div>

      <div
        style={{
          background: 'var(--bg-elevated)',
          borderStyle: 'solid',
          borderWidth: 1,
          borderColor: 'var(--border)',
          borderRadius: 6,
          padding: '12px 16px',
          marginTop: 20,
          fontSize: 12,
          color: 'var(--text-2)',
          maxWidth: 440,
        }}
      >
        <div style={{ fontWeight: 700, marginBottom: 6 }}>{name || examinerName}</div>
        <div style={{ color: 'var(--text-muted)' }}>{agency}</div>
        <div style={{ color: 'var(--text-muted)' }}>{email}</div>
        <div
          style={{
            fontSize: 11,
            color: 'var(--text-off)',
            marginTop: 8,
            fontStyle: 'italic',
          }}
        >
          This information appears in generated reports.
        </div>
      </div>
    </div>
  )
}

function Field({
  label,
  value,
  onChange,
}: {
  label: string
  value: string
  onChange: (v: string) => void
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <label
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
        }}
      >
        {label}
      </label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{ width: '100%', fontSize: 12 }}
      />
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Hash Sets tab
// ──────────────────────────────────────────────────────────────────────────────

function HashSetsTab() {
  const [flagMalware, setFlagMalware] = useState(true)
  const [markClean, setMarkClean] = useState(true)
  const [showName, setShowName] = useState(false)

  return (
    <div>
      <SectionLabel>Loaded Hash Sets</SectionLabel>
      <div
        style={{
          background: 'var(--bg-elevated)',
          borderStyle: 'solid',
          borderWidth: 1,
          borderColor: 'var(--border)',
          borderRadius: 6,
          overflow: 'hidden',
          marginBottom: 16,
        }}
      >
        <div
          style={{
            display: 'flex',
            padding: '9px 14px',
            background: 'var(--bg-panel)',
            borderBottomStyle: 'solid',
            borderBottomWidth: 1,
            borderBottomColor: 'var(--border)',
            fontSize: 10,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
          }}
        >
          <span style={{ flex: 2 }}>Name</span>
          <span style={{ flex: 1 }}>Hashes</span>
          <span style={{ flex: 1 }}>Status</span>
        </div>
        <HashRow name="NSAM v3.0" hashes="78,244,903" />
        <HashRow name="Custom-IOC" hashes="247" last />
      </div>

      <button className="btn-secondary">Import .txt / .csv / .hdb</button>

      <div style={{ marginTop: 24 }}>
        <SectionLabel>Hash Settings</SectionLabel>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <Checkbox
            checked={flagMalware}
            onChange={() => setFlagMalware((v) => !v)}
            label="Flag known malware hashes"
          />
          <Checkbox
            checked={markClean}
            onChange={() => setMarkClean((v) => !v)}
            label="Mark known good hashes as clean"
          />
          <Checkbox
            checked={showName}
            onChange={() => setShowName((v) => !v)}
            label="Show hash set name in results"
          />
        </div>
      </div>
    </div>
  )
}

function HashRow({ name, hashes, last = false }: { name: string; hashes: string; last?: boolean }) {
  return (
    <div
      style={{
        display: 'flex',
        padding: '9px 14px',
        fontSize: 12,
        color: 'var(--text-2)',
        borderBottomStyle: last ? 'none' : 'solid',
        borderBottomWidth: 1,
        borderBottomColor: 'var(--border)',
      }}
    >
      <span style={{ flex: 2 }}>{name}</span>
      <span style={{ flex: 1, fontFamily: 'monospace', color: 'var(--text-muted)' }}>{hashes}</span>
      <span style={{ flex: 1, color: 'var(--clean)' }}>{'\u2713'} Loaded</span>
    </div>
  )
}

function Checkbox({
  checked,
  onChange,
  label,
}: {
  checked: boolean
  onChange: () => void
  label: string
}) {
  return (
    <label
      onClick={onChange}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        cursor: 'pointer',
        fontSize: 12,
        color: 'var(--text-2)',
        userSelect: 'none',
      }}
    >
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 14,
          height: 14,
          borderRadius: 3,
          borderStyle: 'solid',
          borderWidth: 1,
          borderColor: checked ? 'var(--accent-2)' : 'var(--border)',
          background: checked ? 'rgba(138,154,170,0.15)' : 'var(--bg-elevated)',
          color: 'var(--accent-1)',
          fontSize: 11,
        }}
      >
        {checked ? '\u2713' : ''}
      </span>
      {label}
    </label>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// License tab
// ──────────────────────────────────────────────────────────────────────────────

function LicenseTab() {
  const [showKey, setShowKey] = useState(false)

  return (
    <div>
      <div
        style={{
          background: 'rgba(72,120,88,0.08)',
          borderStyle: 'solid',
          borderWidth: 1,
          borderColor: 'rgba(72,120,88,0.3)',
          borderRadius: 6,
          padding: '14px 16px',
          marginBottom: 20,
        }}
      >
        <div
          style={{
            color: 'var(--clean)',
            fontWeight: 700,
            fontSize: 13,
            marginBottom: 4,
          }}
        >
          {'\u2713'} Pro License Active
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Licensee: Dev Mode</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>999 days remaining</div>
      </div>

      <SectionLabel>License Details</SectionLabel>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 440 }}>
        <div>
          <div
            style={{
              fontSize: 10,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginBottom: 4,
            }}
          >
            Machine ID
          </div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontFamily: 'monospace',
              fontSize: 11,
              color: 'var(--text-2)',
            }}
          >
            <span>4F2A-9C8E-7B3D-1A6F</span>
            <button
              className="btn-secondary"
              style={{ padding: '2px 8px', fontSize: 10 }}
              onClick={() => navigator.clipboard?.writeText('4F2A-9C8E-7B3D-1A6F')}
            >
              Copy
            </button>
          </div>
        </div>
        <div>
          <div
            style={{
              fontSize: 10,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginBottom: 4,
            }}
          >
            License Key
          </div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontFamily: 'monospace',
              fontSize: 11,
              color: 'var(--text-2)',
            }}
          >
            <span>{showKey ? 'DEV-MODE-9F2A8C' : 'DEV-MODE-XXXXXX'}</span>
            <button
              className="btn-secondary"
              style={{ padding: '2px 8px', fontSize: 10 }}
              onClick={() => setShowKey((v) => !v)}
            >
              {showKey ? 'Hide' : 'View key'}
            </button>
          </div>
        </div>
      </div>

      <div
        style={{
          marginTop: 24,
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
          fontSize: 11,
        }}
      >
        <a
          href="#"
          onClick={(e) => e.preventDefault()}
          style={{ color: 'var(--text-muted)', textDecoration: 'underline' }}
        >
          Transfer License
        </a>
        <a
          href="#"
          onClick={(e) => e.preventDefault()}
          style={{ color: 'var(--flag)', textDecoration: 'underline', opacity: 0.7 }}
        >
          Deactivate License
        </a>
      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// About tab
// ──────────────────────────────────────────────────────────────────────────────

function AboutTab() {
  return (
    <div
      style={{
        marginTop: 20,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
      }}
    >
      <WolfMark size={80} />

      <div
        style={{
          fontSize: 28,
          fontWeight: 700,
          letterSpacing: '0.2em',
          color: 'var(--text-1)',
          margin: '12px 0 6px',
        }}
      >
        STRATA
      </div>
      <div
        style={{
          fontSize: 12,
          color: 'var(--text-muted)',
          fontStyle: 'italic',
        }}
      >
        Every layer. Every artifact. Every platform.
      </div>

      <div
        style={{
          height: 1,
          background: 'var(--border-sub)',
          width: 220,
          margin: '20px 0',
        }}
      />

      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'center' }}>
        <InfoLine k="Version" v="0.3.0" />
        <InfoLine k="Platform" v="macOS ARM64" />
        <InfoLine k="Build" v="dev-bypass" />
      </div>

      <div
        style={{
          fontSize: 13,
          fontWeight: 700,
          color: 'var(--text-1)',
          marginTop: 16,
        }}
      >
        Wolfmark Systems
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
        wolfmarksystems@proton.me
      </div>

      <div
        style={{
          fontSize: 10,
          color: 'var(--text-off)',
          marginTop: 16,
        }}
      >
        {'\u00A9'} 2026 Wolfmark Systems {'\u00B7'} All Rights Reserved
      </div>
    </div>
  )
}

function InfoLine({ k, v }: { k: string; v: string }) {
  return (
    <div style={{ fontSize: 12, color: 'var(--text-2)' }}>
      <span style={{ color: 'var(--text-muted)' }}>{k}: </span>
      {v}
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared
// ──────────────────────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: 10,
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        marginBottom: 12,
        fontWeight: 700,
      }}
    >
      {children}
    </div>
  )
}
