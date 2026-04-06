export default function SplashScreen() {
  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        background: 'var(--bg-base)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <div
        style={{
          color: 'var(--text-1)',
          fontSize: 52,
          letterSpacing: '0.26em',
          fontWeight: 700,
        }}
      >
        S T R A T A
      </div>
    </div>
  )
}
