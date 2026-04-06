import { useEffect, useState } from 'react'
import { getFileHex } from '../ipc'
import type { HexData } from '../ipc'

interface Props {
  fileId: string
}

export default function HexViewer({ fileId }: Props) {
  const [data, setData] = useState<HexData | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    getFileHex(fileId, 0, 512).then((d) => {
      setData(d)
      setLoading(false)
    })
  }, [fileId])

  if (loading) {
    return (
      <div
        style={{
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--text-muted)',
          fontSize: 12,
        }}
      >
        Loading hex data...
      </div>
    )
  }

  if (!data || data.lines.length === 0) {
    return (
      <div
        style={{
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--text-muted)',
          fontSize: 12,
        }}
      >
        No hex data available
      </div>
    )
  }

  // PE detection — check first line for MZ magic
  const firstHex = data.lines[0]?.hex.split(' ').slice(0, 2).join(' ')
  const isPE = firstHex === '4D 5A'

  const totalBytes = data.lines.reduce((sum, l) => sum + l.hex.split(' ').length, 0)

  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--bg-base)',
        fontFamily: "'Courier New', monospace",
        fontSize: 11,
      }}
    >
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {/* PE header banner */}
        {isPE && (
          <div
            style={{
              background: 'rgba(168,64,64,0.1)',
              border: '1px solid rgba(168,64,64,0.3)',
              borderRadius: 4,
              padding: '6px 10px',
              margin: 8,
              fontSize: 11,
              color: 'var(--flag)',
            }}
          >
            ⚠ PE Executable — MZ header detected at offset 0x00000000
          </div>
        )}

        {/* Sticky header row */}
        <div
          style={{
            position: 'sticky',
            top: 0,
            background: 'var(--bg-panel)',
            borderBottom: '1px solid var(--border-sub)',
            padding: '4px 10px',
            display: 'flex',
            color: 'var(--text-muted)',
            fontSize: 10,
            zIndex: 1,
          }}
        >
          <div style={{ width: 80, flexShrink: 0 }}>OFFSET</div>
          <div style={{ flex: 1 }}>00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F</div>
          <div style={{ width: 130, flexShrink: 0 }}>ASCII</div>
        </div>

        {/* Hex lines */}
        {data.lines.map((line, idx) => (
          <HexRow key={idx} line={line} isPEStart={isPE && idx === 0} />
        ))}
      </div>

      {/* Footer */}
      <div
        style={{
          borderTop: '1px solid var(--border-sub)',
          padding: '4px 10px',
          fontSize: 10,
          color: 'var(--text-muted)',
          display: 'flex',
          gap: 16,
          flexShrink: 0,
        }}
      >
        <span>Offset: 0x{data.offset.toString(16).padStart(8, '0').toUpperCase()}</span>
        <span>Size: {data.total_size.toLocaleString()} bytes</span>
        <span>
          Showing bytes {data.offset}–{data.offset + totalBytes - 1}
        </span>
      </div>
    </div>
  )
}

function HexRow({ line, isPEStart }: { line: { offset: string; hex: string; ascii: string }; isPEStart: boolean }) {
  const [hover, setHover] = useState(false)
  const bytes = line.hex.split(' ')

  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex',
        padding: '3px 10px',
        alignItems: 'center',
        borderBottom: '1px solid rgba(24,28,36,0.5)',
        cursor: 'pointer',
        background: hover ? '#0f1420' : 'transparent',
        transition: 'background 0.1s',
      }}
    >
      <div
        style={{
          width: 80,
          color: '#3a5878',
          fontWeight: 700,
          letterSpacing: '0.05em',
          flexShrink: 0,
        }}
      >
        {line.offset}
      </div>
      <div style={{ flex: 1, display: 'flex', gap: 4, flexWrap: 'nowrap' }}>
        {bytes.map((b, i) => {
          const val = parseInt(b, 16)
          let color: string = 'var(--text-2)'
          let weight: number | undefined
          if (b === '00') color = 'var(--text-off)'
          else if (val >= 0x80) color = 'var(--sus)'
          if (isPEStart && (i === 0 || i === 1)) {
            color = 'var(--flag)'
            weight = 700
          }
          return (
            <span key={i} style={{ color, fontWeight: weight }}>
              {b}
            </span>
          )
        })}
      </div>
      <div
        style={{
          width: 130,
          color: 'var(--text-muted)',
          letterSpacing: '0.05em',
          flexShrink: 0,
          paddingLeft: 8,
        }}
      >
        {line.ascii.split('').map((c, i) => (
          <span
            key={i}
            style={{
              color: c === '.' ? 'var(--text-off)' : 'var(--text-2)',
            }}
          >
            {c}
          </span>
        ))}
      </div>
    </div>
  )
}
