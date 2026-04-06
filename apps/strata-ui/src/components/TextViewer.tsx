import { useEffect, useState } from 'react'
import { getFileText } from '../ipc'

interface Props {
  fileId: string
  extension?: string
}

const POWERSHELL_KEYWORDS = [
  'Remove-Item',
  'Clear-EventLog',
  'vssadmin',
  'wevtutil',
  'Write-Host',
  'Get-Item',
  'Set-Item',
  'Invoke-Expression',
]

export default function TextViewer({ fileId, extension }: Props) {
  const [content, setContent] = useState<string>('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    getFileText(fileId).then((c) => {
      setContent(c)
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
        Loading text...
      </div>
    )
  }

  if (content.startsWith('[Binary')) {
    return (
      <div
        style={{
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--text-muted)',
          fontSize: 12,
          padding: 12,
          textAlign: 'center',
        }}
      >
        Binary file — use HEX tab to view
      </div>
    )
  }

  const lines = content.split('\n')
  const isScript = ['ps1', 'bat', 'cmd'].includes(extension ?? '')

  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--bg-base)',
      }}
    >
      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: 10,
          fontFamily: "'Courier New', monospace",
        }}
      >
        {lines.map((line, idx) => (
          <div
            key={idx}
            style={{
              display: 'flex',
              fontSize: 12,
              lineHeight: 1.6,
            }}
          >
            <div
              style={{
                width: 40,
                color: 'var(--text-off)',
                textAlign: 'right',
                paddingRight: 12,
                fontSize: 11,
                borderRight: '1px solid var(--border-sub)',
                marginRight: 12,
                userSelect: 'none',
                flexShrink: 0,
              }}
            >
              {idx + 1}
            </div>
            <div
              style={{
                flex: 1,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                color: 'var(--text-2)',
              }}
            >
              {isScript ? <HighlightedLine line={line} /> : line || '\u00A0'}
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div
        style={{
          borderTop: '1px solid var(--border-sub)',
          padding: '4px 10px',
          fontSize: 10,
          color: 'var(--text-muted)',
          flexShrink: 0,
        }}
      >
        {lines.length} lines · UTF-8
      </div>
    </div>
  )
}

function HighlightedLine({ line }: { line: string }) {
  // Comment lines: muted italic
  if (line.trimStart().startsWith('#')) {
    return (
      <span
        style={{
          color: 'var(--text-muted)',
          fontStyle: 'italic',
        }}
      >
        {line || '\u00A0'}
      </span>
    )
  }

  // Tokenize: keywords, paths, strings, regular text
  const parts: { text: string; color: string }[] = []
  let remaining = line

  while (remaining.length > 0) {
    // Match path
    const pathMatch = remaining.match(/^([A-Z]:\\[^\s'"]*|\\\\[^\s'"]+)/)
    if (pathMatch) {
      parts.push({ text: pathMatch[0], color: 'var(--flag)' })
      remaining = remaining.slice(pathMatch[0].length)
      continue
    }
    // Match single-quoted string
    const sqMatch = remaining.match(/^'[^']*'/)
    if (sqMatch) {
      parts.push({ text: sqMatch[0], color: '#6090d0' })
      remaining = remaining.slice(sqMatch[0].length)
      continue
    }
    // Match double-quoted string
    const dqMatch = remaining.match(/^"[^"]*"/)
    if (dqMatch) {
      parts.push({ text: dqMatch[0], color: '#6090d0' })
      remaining = remaining.slice(dqMatch[0].length)
      continue
    }
    // Match keyword
    let matchedKeyword: string | null = null
    for (const kw of POWERSHELL_KEYWORDS) {
      if (remaining.startsWith(kw)) {
        matchedKeyword = kw
        break
      }
    }
    if (matchedKeyword) {
      parts.push({ text: matchedKeyword, color: 'var(--sus)' })
      remaining = remaining.slice(matchedKeyword.length)
      continue
    }
    // Plain char
    parts.push({ text: remaining[0], color: 'var(--text-2)' })
    remaining = remaining.slice(1)
  }

  // Coalesce adjacent parts with same color
  const coalesced: { text: string; color: string }[] = []
  for (const p of parts) {
    const last = coalesced[coalesced.length - 1]
    if (last && last.color === p.color) last.text += p.text
    else coalesced.push({ ...p })
  }

  if (coalesced.length === 0) return <span>{'\u00A0'}</span>

  return (
    <>
      {coalesced.map((p, i) => (
        <span key={i} style={{ color: p.color }}>
          {p.text}
        </span>
      ))}
    </>
  )
}
