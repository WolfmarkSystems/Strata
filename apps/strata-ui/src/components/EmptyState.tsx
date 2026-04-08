interface EmptyStateProps {
  icon: string
  title: string
  subtitle: string
  hint?: string
}

export default function EmptyState({ icon, title, subtitle, hint }: EmptyStateProps) {
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
          alignItems: 'center',
          justifyContent: 'center',
          width: '100%',
          height: '100%',
        }}
      >
        <div style={{ fontSize: 32, marginBottom: 12 }}>{icon}</div>
        <div
          style={{
            fontSize: 16,
            color: 'var(--text-2)',
            fontWeight: 700,
            marginBottom: 6,
            letterSpacing: '0.04em',
          }}
        >
          {title}
        </div>
        <div
          style={{
            fontSize: 13,
            color: 'var(--text-muted)',
            marginBottom: 4,
          }}
        >
          {subtitle}
        </div>
        {hint && (
          <div style={{ fontSize: 11, color: 'var(--text-off)' }}>{hint}</div>
        )}
      </div>
    </div>
  )
}
