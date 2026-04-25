import { useEffect, useState } from 'react'
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels'
import { getArtifactsByThread } from '../ipc'
import type { MessageThread, ThreadMessage } from '../ipc'

// Sprint-11 P1 — two-panel conversation view for the Communications
// category. Left: thread list grouped by participant. Right: messages
// in the selected thread, sorted chronologically, with direction
// (inbound/outbound) and service (iMessage/SMS) badges. Falls back
// to a flat list rendering when artifacts have no thread metadata
// (the `__ungrouped__` thread the backend returns).

interface Props {
  evidenceId: string
  category: string
  // Renders the supplied fallback (the existing flat ArtifactResults)
  // when the only thread coming back is the __ungrouped__ bucket —
  // i.e. no plugin in this category populated thread context.
  flatFallback: React.ReactNode
}

export default function ConversationView({ evidenceId, category, flatFallback }: Props) {
  const [threads, setThreads] = useState<MessageThread[]>([])
  const [selectedThreadId, setSelectedThreadId] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!evidenceId || !category) {
      setThreads([])
      return
    }
    setLoading(true)
    getArtifactsByThread(evidenceId, category).then((t) => {
      setThreads(t)
      const firstReal = t.find((x) => x.thread_id !== '__ungrouped__')
      setSelectedThreadId(firstReal?.thread_id ?? null)
      setLoading(false)
    })
  }, [evidenceId, category])

  const realThreads = threads.filter((t) => t.thread_id !== '__ungrouped__')
  const onlyUngrouped = realThreads.length === 0 && threads.length > 0

  if (loading) {
    return (
      <div style={{ padding: 16, color: 'var(--text-muted)', fontSize: 12 }}>
        Loading conversations...
      </div>
    )
  }

  // No threads have populated thread_context — defer to the existing
  // flat list. Preserves backwards compatibility for non-message
  // artifacts in the Communications category (calendar invites,
  // contacts) and for plugins that haven't been ported.
  if (onlyUngrouped || realThreads.length === 0) {
    return <>{flatFallback}</>
  }

  const selected = realThreads.find((t) => t.thread_id === selectedThreadId) ?? realThreads[0]

  return (
    <PanelGroup direction="horizontal" style={{ flex: 1 }}>
      <Panel defaultSize={30} minSize={20}>
        <ThreadList
          threads={realThreads}
          selectedId={selected?.thread_id ?? null}
          onSelect={setSelectedThreadId}
        />
      </Panel>
      <PanelResizeHandle className="resize-handle" />
      <Panel defaultSize={70}>
        <ConversationPane thread={selected} />
      </Panel>
    </PanelGroup>
  )
}

function ThreadList({
  threads,
  selectedId,
  onSelect,
}: {
  threads: MessageThread[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        overflowY: 'auto',
        background: 'var(--bg-elevated)',
      }}
    >
      <div
        style={{
          padding: '8px 12px',
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: '0.12em',
          color: 'var(--text-muted)',
          borderBottom: '1px solid var(--border)',
        }}
      >
        THREADS ({threads.length})
      </div>
      {threads.map((t) => {
        const last = t.messages[t.messages.length - 1]
        const preview = last?.body?.slice(0, 60) ?? ''
        const isSelected = t.thread_id === selectedId
        return (
          <button
            key={t.thread_id}
            onClick={() => onSelect(t.thread_id)}
            style={{
              textAlign: 'left',
              padding: '10px 12px',
              border: 'none',
              borderBottom: '1px solid var(--border)',
              background: isSelected ? 'var(--bg-base)' : 'transparent',
              color: 'var(--text-1)',
              cursor: 'pointer',
              display: 'flex',
              flexDirection: 'column',
              gap: 4,
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'baseline',
                gap: 6,
              }}
            >
              <span style={{ fontSize: 12, fontWeight: 600 }}>
                {t.participant || t.thread_id}
              </span>
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                ({t.messages.length})
              </span>
            </div>
            {preview && (
              <span
                style={{
                  fontSize: 11,
                  color: 'var(--text-muted)',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {preview}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

function ConversationPane({ thread }: { thread: MessageThread | null }) {
  if (!thread) {
    return (
      <div style={{ padding: 16, color: 'var(--text-muted)', fontSize: 12 }}>
        Select a thread on the left.
      </div>
    )
  }
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        overflowY: 'auto',
        background: 'var(--bg-base)',
      }}
    >
      <div
        style={{
          padding: '10px 14px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'baseline',
          gap: 10,
        }}
      >
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-1)' }}>
          {thread.participant || thread.thread_id}
        </span>
        {thread.service && (
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{thread.service}</span>
        )}
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
          ({thread.messages.length} messages)
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: 14 }}>
        {thread.messages.map((m) => (
          <MessageRow key={m.artifact_id} message={m} />
        ))}
      </div>
    </div>
  )
}

function MessageRow({ message }: { message: ThreadMessage }) {
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
          fontSize: 10,
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
          maxWidth: '70%',
          padding: '8px 12px',
          borderRadius: 12,
          background: isOutbound ? 'var(--accent-2)' : 'var(--bg-elevated)',
          color: isOutbound ? 'var(--bg-base)' : 'var(--text-1)',
          fontSize: 12,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          border: '1px solid var(--border)',
        }}
      >
        {message.body || '(empty)'}
      </div>
    </div>
  )
}

function formatTimestamp(ts: string): string {
  // Backend emits seconds-since-unix as a stringified integer. If it
  // parses cleanly, render as ISO; otherwise pass the string through.
  const n = Number(ts)
  if (!Number.isFinite(n) || n <= 0) return ts
  const d = new Date(n * 1000)
  if (Number.isNaN(d.getTime())) return ts
  return d.toISOString().replace('T', ' ').replace(/\..*$/, ' UTC')
}
