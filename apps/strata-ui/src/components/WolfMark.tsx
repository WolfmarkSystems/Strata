import wolfmarkUrl from '../assets/wolfmark.png'

interface WolfMarkProps {
  size?: number
  className?: string
}

export default function WolfMark({ size = 32, className }: WolfMarkProps) {
  return (
    <img
      src={wolfmarkUrl}
      width={size}
      height={size}
      alt="Wolfmark"
      className={className}
      draggable={false}
      style={{
        display: 'block',
        flexShrink: 0,
        width: size,
        height: size,
        objectFit: 'contain',
        userSelect: 'none',
        pointerEvents: 'none',
      }}
    />
  )
}
