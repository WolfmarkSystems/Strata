interface Props {
  onClick: () => void
}

export default function DevSkip({ onClick }: Props) {
  return (
    <button
      onClick={onClick}
      style={{
        position: 'fixed',
        bottom: 24,
        left: 24,
        padding: '4px 12px',
        background: 'transparent',
        borderStyle: 'solid',
        borderWidth: 1,
        borderColor: 'var(--sus)',
        borderRadius: 3,
        color: 'var(--sus)',
        fontSize: 10,
        fontFamily: 'monospace',
        letterSpacing: '0.06em',
        cursor: 'pointer',
        zIndex: 100,
      }}
    >
      DEV SKIP {'\u2192'}
    </button>
  )
}
