import { useEffect, useState } from 'react'
import type { MessageThread, ThreadMessage } from '../ipc'
import { getArtifactsByThread } from '../ipc'

// Sprint-11 follow-up — the thread context panel attaches below the
// artifact detail. Given the currently-selected artifact, it locates
// its parent thread and renders the surrounding messages with the
// selected one highlighted. Hidden entirely when the selected
// artifact has no thread metadata, so non-message categories aren't
// affected.
//
// Matches Cellebrite UFED + Magnet AXIOM behavior: the artifact list
// stays the primary surface; thread context is a contextual aid in
// the detail pane, not a replacement for the flat list.

interface Props {
  evidenceId: string | null
  category: string | null
  artifactId: string | null
}

export default function ThreadContextPanel({ evidenceId, category, artifactId }: Props) {
  const [threads, setThreads] = useState<MessageThread[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!evidenceId || !category) {
      setThreads([])
      return
    }
    setLoading(true)
    getArtifactsByThread(evidenceId, category).then((t) => {
      setThreads(t)
      setLoading(false)
    })
  }, [evidenceId, category])

  if (!artifactId || !evidenceId || !category) return null

  // Find the thread containing this artifact.
  const owning = threads.find((t) =>
    t.messages.some((m) => m.artifact_id === artifactId),
  )
  if (loading || !owning) return null
  // Skip the synthetic ungrouped bucket — there's no real thread to
  // visualise around an orphan artifact.
  if (owning.thread_id === '__ungrouped__') return null

  return (
    <div
      style={{
        borderTop: '1px solid var(--border-sub)',
        marginTop: 12,
        paddingTop: 10,
      }}
    >
      <div
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginBottom: 6,
        }}
      >
        Thread Context
      </div>
      <div
        style={{
          fontSize: 11,
          color: 'var(--text-2)',
          marginBottom: 6,
          display: 'flex',
          alignItems: 'baseline',
          gap: 8,
        }}
      >
        <span style={{ fontWeight: 600 }}>{owning.participant || owning.thread_id}</span>
        {owning.service && (
          <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>{owning.service}</span>
        )}
        <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
          ({owning.messages.length} messages)
        </span>
      </div>
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
          maxHeight: 360,
          overflowY: 'auto',
          padding: '6px 4px',
          background: 'var(--bg-base)',
          border: '1px solid var(--border-sub)',
          borderRadius: 4,
        }}
      >
        {owning.messages.map((m) => (
          <MessageRow key={m.artifact_id} message={m} highlighted={m.artifact_id === artifactId} />
        ))}
      </div>
    </div>
  )
}

function MessageRow({ message, highlighted }: { message: ThreadMessage; highlighted: boolean }) {
  const isOutbound = message.direction === 'outbound'
  const ts = message.timestamp ? formatTimestamp(message.timestamp) : '—'
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: isOutbound ? 'flex-end' : 'flex-start',
        gap: 2,
      }}
    >
      <div
        style={{
          fontSize: 9,
          color: 'var(--text-muted)',
          letterSpacing: '0.04em',
          padding: '0 4px',
        }}
      >
        {ts}
        {message.service ? ` · ${message.service}` : ''}
        {' · '}
        {isOutbound ? 'OUTBOUND' : message.direction === 'inbound' ? 'INBOUND' : '—'}
      </div>
      <div
        style={{
          maxWidth: '85%',
          padding: '6px 10px',
          borderRadius: 10,
          background: isOutbound ? 'var(--accent-2)' : 'var(--bg-elevated)',
          color: isOutbound ? 'var(--bg-base)' : 'var(--text-1)',
          fontSize: 11,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          border: highlighted
            ? '2px solid var(--sus)'
            : '1px solid var(--border)',
          boxShadow: highlighted ? '0 0 0 2px rgba(200,160,64,0.18)' : 'none',
        }}
      >
        {message.body || '(empty)'}
      </div>
    </div>
  )
}

function formatTimestamp(ts: string): string {
  const n = Number(ts)
  if (!Number.isFinite(n) || n <= 0) return ts
  const d = new Date(n * 1000)
  if (Number.isNaN(d.getTime())) return ts
  return d.toISOString().replace('T', ' ').replace(/\..*$/, ' UTC')
}
