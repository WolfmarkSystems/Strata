import { useEffect, useState } from 'react'
import { useAppStore } from '../store/appStore'
import EmptyState from '../components/EmptyState'
import { getCustodyLog, type CustodyEntry } from '../ipc'

function formatTs(ts: number): string {
  return new Date(ts * 1000).toLocaleString()
}

export default function CustodyLogView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const [entries, setEntries] = useState<CustodyEntry[]>([])

  useEffect(() => {
    if (!evidenceId) {
      setEntries([])
      return
    }
    getCustodyLog(evidenceId).then(setEntries)
  }, [evidenceId])

  if (!evidenceLoaded || !evidenceId) {
    return (
      <EmptyState
        icon={'\u{1F4DC}'}
        title="Chain of Custody"
        subtitle="Load evidence to record examiner actions"
      />
    )
  }

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(entries, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'strata-custody-log.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="bubble" style={{ height: '100%', width: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: 12, borderBottom: '1px solid var(--border-sub)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          CHAIN OF CUSTODY — {entries.length.toLocaleString()} entries
        </div>
        <button onClick={exportJson}>Export JSON</button>
      </div>
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ color: 'var(--text-muted)', textAlign: 'left' }}>
              <th style={{ padding: 8 }}>Timestamp</th>
              <th style={{ padding: 8 }}>Examiner</th>
              <th style={{ padding: 8 }}>Action</th>
              <th style={{ padding: 8 }}>Details</th>
              <th style={{ padding: 8 }}>Hash</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, idx) => (
              <tr key={`${entry.timestamp}-${entry.action}-${idx}`} style={{ borderTop: '1px solid var(--border-sub)' }}>
                <td style={{ padding: 8, whiteSpace: 'nowrap' }}>{formatTs(entry.timestamp)}</td>
                <td style={{ padding: 8 }}>{entry.examiner}</td>
                <td style={{ padding: 8 }}>{entry.action}</td>
                <td style={{ padding: 8 }}>{entry.details}</td>
                <td style={{ padding: 8, color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: 10 }}>
                  {entry.hash_after ?? entry.hash_before ?? ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
