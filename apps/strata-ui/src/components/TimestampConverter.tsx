import { useMemo, useState } from 'react'
import {
  convertTimestamp,
  formatLabel,
  type TimestampFormat,
} from '../util/timestamp'

const FORMATS: TimestampFormat[] = [
  'auto',
  'unix_s',
  'unix_ms',
  'unix_us',
  'mac_absolute',
  'chrome',
  'windows_filetime',
]

/**
 * Standalone timestamp converter widget. Examiner pastes any suspicious
 * number and picks a format (or leaves on auto-detect) to see what date
 * it represents.
 */
export default function TimestampConverter() {
  const [raw, setRaw] = useState('')
  const [format, setFormat] = useState<TimestampFormat>('auto')

  const result = useMemo(() => {
    if (!raw.trim()) return null
    return convertTimestamp(raw, format)
  }, [raw, format])

  return (
    <div
      className="bubble-tight"
      style={{
        padding: '10px 12px',
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          marginBottom: 2,
        }}
      >
        <span style={{ fontSize: 12 }}>{'\u{1F550}'}</span>
        <div
          style={{
            fontSize: 9,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
          }}
        >
          Timestamp Converter
        </div>
      </div>
      <div style={{ display: 'flex', gap: 6 }}>
        <input
          type="text"
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          placeholder="Paste a raw timestamp..."
          spellCheck={false}
          style={{
            flex: 1,
            background: 'var(--bg-input)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            padding: '6px 10px',
            color: 'var(--text-1)',
            fontSize: 11,
            fontFamily: 'monospace',
            outline: 'none',
          }}
        />
        <select
          value={format}
          onChange={(e) => setFormat(e.target.value as TimestampFormat)}
          style={{
            background: 'var(--bg-elevated)',
            border: '1px solid var(--border)',
            color: 'var(--text-2)',
            borderRadius: 'var(--radius-sm)',
            padding: '4px 8px',
            fontSize: 10,
            fontFamily: 'monospace',
          }}
        >
          {FORMATS.map((f) => (
            <option key={f} value={f}>
              {formatLabel(f)}
            </option>
          ))}
        </select>
      </div>

      {result && (
        <div
          style={{
            fontSize: 10,
            color: result.ok ? 'var(--hashed)' : 'var(--flag)',
            fontFamily: 'monospace',
            lineHeight: 1.5,
            background: 'var(--bg-panel)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            padding: '6px 10px',
          }}
        >
          {result.ok ? (
            <>
              <div style={{ fontWeight: 700 }}>{result.iso}</div>
              <div style={{ color: 'var(--text-muted)' }}>{result.pretty}</div>
              <div
                style={{
                  fontSize: 9,
                  color: 'var(--text-off)',
                  marginTop: 3,
                }}
              >
                Detected: {result.message} · Unix seconds: {result.unixSeconds}
              </div>
            </>
          ) : (
            <div>{'\u26A0'} {result.message}</div>
          )}
        </div>
      )}
    </div>
  )
}
