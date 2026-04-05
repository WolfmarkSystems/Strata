import { useEffect, useState } from 'react'
import { open } from '@tauri-apps/plugin-dialog'

function CaseManager({ caseId, caseDbPath, isCaseRestoredFromSession = false, onCaseChange }) {
  const [localCaseId, setLocalCaseId] = useState(caseId || '')
  const [localDbPath, setLocalDbPath] = useState(caseDbPath || 'exports/cases/')

  useEffect(() => {
    setLocalCaseId(caseId || '')
  }, [caseId])

  useEffect(() => {
    setLocalDbPath(caseDbPath || 'exports/cases/')
  }, [caseDbPath])

  const applyCaseChange = (nextCaseId, nextDbPath) => {
    setLocalCaseId(nextCaseId)
    setLocalDbPath(nextDbPath)
    onCaseChange(nextCaseId, nextDbPath)
  }

  const handleBrowseDb = async () => {
    try {
      const selected = await open({
        defaultPath: localDbPath,
        multiple: false,
        filters: [{
          name: 'SQLite Database',
          extensions: ['sqlite', 'db', 'sqlite3']
        }],
        directory: false
      })
      
      if (selected) {
        applyCaseChange(localCaseId, selected)
      }
    } catch (e) {
      console.error('Failed to browse:', e)
    }
  }

  const handleCaseChange = (newCaseId, newDbPath) => {
    const nextCaseId = typeof newCaseId === 'string' ? newCaseId : localCaseId
    const nextDbPath = typeof newDbPath === 'string' ? newDbPath : localDbPath
    applyCaseChange(nextCaseId, nextDbPath)
  }

  return (
    <div className="case-manager">
      <h3>Case Manager</h3>
      
      <div className="input-group">
        <label htmlFor="caseId">Case ID:</label>
        <input
          id="caseId"
          type="text"
          value={localCaseId}
          onChange={(e) => handleCaseChange(e.target.value, null)}
          placeholder="e.g., CASE-2026-001"
        />
      </div>
      
      <div className="input-group">
        <label htmlFor="dbPath">Database:</label>
        <input
          id="dbPath"
          type="text"
          value={localDbPath}
          onChange={(e) => handleCaseChange(null, e.target.value)}
          placeholder="exports/cases/"
        />
        <button onClick={handleBrowseDb} className="btn btn-secondary btn-small" type="button">
          Browse...
        </button>
      </div>
      
      {(caseId || caseDbPath) && (
        <div className="case-info">
          <span className="case-badge">Case: {caseId || '(not set)'}</span>
          {isCaseRestoredFromSession && (
            <div className="setting-description">Restored previous session context.</div>
          )}
        </div>
      )}
    </div>
  )
}

export default CaseManager
