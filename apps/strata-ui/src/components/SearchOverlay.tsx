import { useEffect, useState, useRef } from 'react'
import { useAppStore } from '../store/appStore'
import { searchFiles } from '../ipc'
import type { SearchResult } from '../ipc'

interface BadgeColors {
  bg: string
  border: string
  color: string
}

function badgeColorsFor(ext: string): BadgeColors {
  const e = ext.toLowerCase()
  if (['exe', 'dll', 'sys'].includes(e))
    return { bg: 'rgba(168,64,64,0.15)', border: 'rgba(168,64,64,0.5)', color: '#a84040' }
  if (['log', 'evtx'].includes(e))
    return { bg: 'rgba(74,120,144,0.15)', border: 'rgba(74,120,144,0.5)', color: '#4a7890' }
  if (['reg', 'hiv', 'dat'].includes(e))
    return { bg: 'rgba(96,88,120,0.15)', border: 'rgba(96,88,120,0.5)', color: '#605878' }
  if (e === 'lnk')
    return { bg: 'rgba(184,120,64,0.15)', border: 'rgba(184,120,64,0.5)', color: '#b87840' }
  if (['zip', 'rar', '7z'].includes(e))
    return { bg: 'rgba(120,96,64,0.15)', border: 'rgba(120,96,64,0.5)', color: '#786040' }
  if (['ps1', 'bat', 'cmd'].includes(e))
    return { bg: 'rgba(184,120,64,0.2)', border: 'rgba(184,120,64,0.6)', color: '#b87840' }
  return { bg: 'rgba(58,72,88,0.15)', border: 'rgba(58,72,88,0.5)', color: '#3a4858' }
}

export default function SearchOverlay() {
  const searchQuery = useAppStore((s) => s.searchQuery)
  const setSearchQuery = useAppStore((s) => s.setSearchQuery)
  const setSearchActive = useAppStore((s) => s.setSearchActive)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const setSelectedFile = useAppStore((s) => s.setSelectedFile)
  const setView = useAppStore((s) => s.setView)

  const [results, setResults] = useState<SearchResult[]>([])
  const [loading, setLoading] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  useEffect(() => {
    if (!searchQuery.trim()) {
      setResults([])
      return
    }
    setLoading(true)
    searchFiles(searchQuery, evidenceId ?? '').then((r) => {
      setResults(r)
      setLoading(false)
    })
  }, [searchQuery, evidenceId])

  const filenameMatches = results.filter((r) => r.match_field === 'filename')
  const contentMatches = results.filter((r) => r.match_field === 'content')

  const handleSelect = (r: SearchResult) => {
    setSelectedFile(r.id)
    setView('files')
    setSearchActive(false)
  }

  return (
    <div
      style={{
        position: 'fixed',
        top: 80,
        left: 42,
        right: 0,
        bottom: 0,
        background: 'rgba(7,8,9,0.92)',
        backdropFilter: 'blur(2px)',
        zIndex: 100,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          borderBottom: '1px solid var(--border)',
          background: 'var(--bg-surface)',
        }}
      >
        <span style={{ fontSize: 18, color: 'var(--text-muted)' }}>{'\u2315'}</span>
        <input
          ref={inputRef}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search files, paths, extensions, content..."
          style={{
            fontSize: 16,
            background: 'transparent',
            border: 'none',
            color: 'var(--text-1)',
            flex: 1,
            outline: 'none',
            padding: 0,
          }}
        />
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {loading ? 'Searching...' : `${results.length} results`}
        </span>
        <button
          onClick={() => setSearchActive(false)}
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            fontSize: 16,
            cursor: 'pointer',
            padding: '4px 8px',
          }}
          title="Close (Esc)"
        >
          ✕
        </button>
      </div>

      {/* Results */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 0' }}>
        {!searchQuery.trim() ? (
          <div
            style={{
              padding: 40,
              textAlign: 'center',
              color: 'var(--text-muted)',
              fontSize: 13,
            }}
          >
            Start typing to search
          </div>
        ) : results.length === 0 && !loading ? (
          <div
            style={{
              padding: 40,
              textAlign: 'center',
              color: 'var(--text-muted)',
              fontSize: 13,
            }}
          >
            No results for "{searchQuery}"
            <div
              style={{ fontSize: 11, color: 'var(--text-off)', marginTop: 6 }}
            >
              Try a different search term or check the extension filter
            </div>
          </div>
        ) : (
          <>
            {filenameMatches.length > 0 && (
              <>
                <GroupHeader label="Filename Matches" />
                {filenameMatches.map((r) => (
                  <ResultRow key={r.id} result={r} onClick={() => handleSelect(r)} />
                ))}
              </>
            )}
            {contentMatches.length > 0 && (
              <>
                <GroupHeader label="Content Matches" />
                {contentMatches.map((r) => (
                  <ResultRow key={r.id} result={r} onClick={() => handleSelect(r)} />
                ))}
              </>
            )}
          </>
        )}
      </div>
    </div>
  )
}

function GroupHeader({ label }: { label: string }) {
  return (
    <div
      style={{
        padding: '6px 16px',
        fontSize: 10,
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
      }}
    >
      {label}
    </div>
  )
}

function ResultRow({ result, onClick }: { result: SearchResult; onClick: () => void }) {
  const [hover, setHover] = useState(false)
  const c = badgeColorsFor(result.extension)

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        padding: '10px 16px',
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        cursor: 'pointer',
        borderBottom: '1px solid var(--border-sub)',
        background: hover ? '#0f1420' : 'transparent',
        transition: 'background 0.1s',
      }}
    >
      {/* Extension badge */}
      <span
        style={{
          display: 'inline-block',
          padding: '2px 6px',
          borderRadius: 3,
          fontSize: 9,
          fontFamily: 'monospace',
          flexShrink: 0,
          background: c.bg,
          border: `1px solid ${c.border}`,
          color: c.color,
          minWidth: 30,
          textAlign: 'center',
        }}
      >
        {result.extension ? result.extension.toUpperCase() : '\u2014'}
      </span>

      {/* Center */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            style={{
              fontSize: 13,
              color: 'var(--text-1)',
              fontWeight: 700,
              textDecoration: result.is_deleted ? 'line-through' : undefined,
            }}
          >
            {result.name}
          </span>
          <span
            style={{
              fontSize: 9,
              padding: '1px 6px',
              borderRadius: 3,
              background: 'var(--bg-elevated)',
              color: 'var(--text-muted)',
              border: '1px solid var(--border)',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
            }}
          >
            {result.match_field}
          </span>
        </div>
        <div
          style={{
            fontSize: 11,
            color: 'var(--text-muted)',
            fontFamily: 'monospace',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            marginTop: 2,
          }}
        >
          {result.full_path}
        </div>
      </div>

      {/* Right */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          flexShrink: 0,
        }}
      >
        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{result.size_display}</div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{result.modified}</div>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {result.is_flagged && (
            <span style={{ fontSize: 10, color: 'var(--flag)' }}>●</span>
          )}
          {result.is_suspicious && (
            <span style={{ fontSize: 10, color: 'var(--sus)' }}>●</span>
          )}
        </div>
      </div>
    </div>
  )
}
