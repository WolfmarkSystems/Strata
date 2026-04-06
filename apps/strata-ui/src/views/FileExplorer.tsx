export default function FileExplorer() {
  return (
    <div
      style={{
        flex: 1,
        background: 'var(--bg-base)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <div
        style={{
          color: 'var(--text-1)',
          fontSize: 28,
          fontWeight: 700,
          letterSpacing: '0.1em',
        }}
      >
        File Explorer
      </div>
      <div style={{ color: 'var(--text-muted)', fontSize: 14, marginTop: 8 }}>
        Coming in Day 3
      </div>
    </div>
  )
}
