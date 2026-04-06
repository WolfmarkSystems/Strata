interface Props {
  children: React.ReactNode
}

export default function GateBackground({ children }: Props) {
  return (
    <div
      style={{
        width: '100vw',
        height: '100vh',
        background:
          'radial-gradient(ellipse 60% 50% at 50% 40%, #0c0e14 0%, #070809 100%)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        overflow: 'hidden',
        position: 'relative',
      }}
    >
      {children}
    </div>
  )
}
