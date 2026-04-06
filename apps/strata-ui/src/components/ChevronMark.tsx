interface Props {
  width?: number
  height?: number
}

export default function ChevronMark({ width = 60, height = 52 }: Props) {
  return (
    <svg width={width} height={height} viewBox="0 0 80 70" xmlns="http://www.w3.org/2000/svg">
      <polygon points="40,4 68,20 40,36 12,20" fill="#d8e2ec" opacity="0.95" />
      <polygon points="68,20 68,28 40,44 40,36" fill="#3d5878" />
      <polygon points="12,20 12,28 40,44 40,36" fill="#8a9aaa" />
      <polygon points="68,28 72,30 72,38 68,36" fill="#2a3a55" />
      <polygon points="12,28 8,30 8,38 12,36" fill="#4a6880" />
      <line x1="12" y1="36" x2="68" y2="36" stroke="#d8e2ec" strokeWidth="0.5" opacity="0.4" />
      <polygon points="68,36 72,38 72,46 68,44" fill="#1a2840" />
      <polygon points="12,36 8,38 8,46 12,44" fill="#3a5268" />
      <polygon points="12,52 8,54 36,66 40,64 40,56" fill="#0f1c2e" opacity="0.9" />
      <polygon points="68,52 72,54 44,66 40,64 40,56" fill="#080e18" opacity="0.9" />
      <polyline
        points="12,20 40,4 68,20"
        stroke="#ffffff"
        strokeWidth="0.6"
        opacity="0.5"
        fill="none"
      />
    </svg>
  )
}
