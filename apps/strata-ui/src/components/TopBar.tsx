import { useAppStore } from '../store/appStore'

export default function TopBar() {
  const stats = useAppStore((s) => s.stats)
  const caseName = useAppStore((s) => s.caseName)
  const isDev = useAppStore((s) => s.isDev)

  return (
    <div
      style={{
        background: 'var(--bg-panel)',
        borderBottom: '1px solid var(--border)',
        padding: '6px 12px',
        flexShrink: 0,
      }}
    >
      {/* ── Row 1: Logo + nav + case info + badges ─────────── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          marginBottom: 8,
        }}
      >
        {/* Wolf PNG slot */}
        <div
          style={{
            width: 32,
            height: 32,
            marginRight: 8,
            border: '1px dashed #181c24',
            borderRadius: 4,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 10,
            color: '#1a2030',
          }}
        >
          WLF
        </div>

        {/* STRATA wordmark */}
        <div
          style={{
            color: 'var(--text-1)',
            fontSize: 18,
            fontWeight: 700,
            letterSpacing: '0.18em',
          }}
        >
          STRATA
        </div>

        {/* Center nav buttons */}
        <div style={{ display: 'flex', gap: 8, marginLeft: 'auto', marginRight: 'auto' }}>
          <button
            style={{
              background: 'var(--accent-1)',
              color: 'var(--bg-base)',
              border: 'none',
              borderRadius: 6,
              padding: '6px 14px',
              fontSize: 13,
              fontWeight: 700,
            }}
          >
            + Open Evidence
          </button>
          <button
            style={{
              background: 'transparent',
              color: 'var(--text-2)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              padding: '6px 14px',
              fontSize: 13,
            }}
          >
            New Case
          </button>
          <button
            style={{
              background: 'transparent',
              color: 'var(--text-2)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              padding: '6px 14px',
              fontSize: 13,
            }}
          >
            Open Case
          </button>
        </div>

        {/* Right: case info + badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>CASE</span>
          <span style={{ color: 'var(--text-1)', fontSize: 12, fontWeight: 700 }}>
            {caseName ?? 'Unsaved Session'}
          </span>
          <span
            style={{
              background: 'var(--bg-elevated)',
              color: 'var(--clean)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              padding: '2px 6px',
              fontSize: 10,
              fontWeight: 700,
            }}
          >
            Pro
          </span>
          {isDev && (
            <span
              style={{
                background: '#2a1a00',
                color: '#c8855a',
                border: '1px solid #c8855a',
                borderRadius: 3,
                padding: '2px 6px',
                fontSize: 10,
                fontWeight: 700,
              }}
            >
              DEV
            </span>
          )}
        </div>
      </div>

      {/* ── Row 2: Search + stats + action buttons ─────────── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
        }}
      >
        {/* Left spacer to center search */}
        <div style={{ flex: 1 }} />

        {/* Search bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input
            type="text"
            placeholder="Search files, paths, extensions..."
            style={{
              width: 480,
              fontSize: 13,
              padding: '7px 12px',
            }}
          />
          <button
            style={{
              background: 'var(--bg-elevated)',
              color: 'var(--text-2)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              padding: '6px 10px',
              fontSize: 11,
            }}
            title="Metadata search"
          >
            META
          </button>
          <button
            style={{
              background: 'var(--bg-elevated)',
              color: 'var(--text-2)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              padding: '6px 10px',
              fontSize: 11,
            }}
            title="Full-text search"
          >
            TEXT
          </button>
        </div>

        {/* Inline stats */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Stat label="FILES" value={stats.files} color="#4a6080" />
          <Sep />
          <Stat label="SUSPICIOUS" value={stats.suspicious} color="var(--sus)" />
          <Sep />
          <Stat label="FLAGGED" value={stats.flagged} color="var(--flag)" />
          <Sep />
          <Stat label="CARVED" value={stats.carved} color="var(--carved)" />
          <Sep />
          <Stat label="HASHED" value={stats.hashed} color="var(--hashed)" />
          <Sep />
          <Stat label="ARTIFACTS" value={stats.artifacts} color="var(--artifact)" />
        </div>

        {/* Action buttons */}
        <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
          <ActionBtn label="HASH ALL" textColor="#8a9aaa" borderColor="#1a2840" />
          <ActionBtn label="CARVE" textColor="#3a4858" borderColor="#181c24" />
          <ActionBtn label="REPORT" textColor="#487858" borderColor="#142018" />
          <ActionBtn label="EXPORT" textColor="#b87840" borderColor="#382010" />
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ display: 'flex', gap: 4, alignItems: 'baseline' }}>
      <span style={{ color: '#1c2638', fontSize: 11 }}>{label}</span>
      <span style={{ color, fontSize: 12, fontWeight: 700 }}>{value}</span>
    </div>
  )
}

function Sep() {
  return <span style={{ color: '#1c2638', fontSize: 11 }}>|</span>
}

function ActionBtn({
  label,
  textColor,
  borderColor,
}: {
  label: string
  textColor: string
  borderColor: string
}) {
  return (
    <button
      style={{
        background: 'var(--bg-elevated)',
        color: textColor,
        border: `1px solid ${borderColor}`,
        borderRadius: 6,
        padding: '6px 12px',
        fontSize: 12,
        fontWeight: 700,
      }}
    >
      {label}
    </button>
  )
}
