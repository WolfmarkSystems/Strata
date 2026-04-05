import { useState } from 'react'
import { open } from '@tauri-apps/plugin-dialog'
import { stat } from '@tauri-apps/plugin-fs'

const SUPPORTED_EXTENSIONS = ['.img', '.dd', '.raw', '.e01']
const UNSUPPORTED_EXTENSIONS = ['.evtx', '.zip', '.rar']

function EvidenceLoader({
  evidencePath,
  isEvidencePathRestoredFromSession = false,
  onPathChange,
  onInfoChange,
}) {
  const [evidenceInfo, setEvidenceInfo] = useState(null)
  const [error, setError] = useState(null)

  const handleBrowse = async () => {
    try {
      const selected = await open({
        defaultPath: 'D:\\forensic-suite\\evidence\\',
        multiple: false,
        filters: [{
          name: 'Evidence Files',
          extensions: ['img', 'dd', 'raw', 'e01', 'evtx', 'zip', 'rar']
        }]
      })
      
      if (selected) {
        onPathChange(selected)
        
        const metadata = await stat(selected)
        const filename = selected.split(/[/\\]/).pop()
        const ext = filename.includes('.') ? '.' + filename.split('.').pop().toLowerCase() : ''
        
        const info = {
          filename,
          size: metadata.size,
          extension: ext,
          path: selected
        }
        
        setEvidenceInfo(info)
        onInfoChange(info)
        setError(null)
      }
    } catch (e) {
      setError(e.message)
    }
  }

  const isSupported = evidenceInfo && !UNSUPPORTED_EXTENSIONS.includes(evidenceInfo.extension.toLowerCase())

  return (
    <div className="evidence-loader">
      <div className="input-group">
        <label htmlFor="evidence">Evidence Path:</label>
        <input
          id="evidence"
          type="text"
          value={evidencePath}
          onChange={(e) => {
            onPathChange(e.target.value)
            setEvidenceInfo(null)
            onInfoChange(null)
          }}
          placeholder="Path to evidence file"
        />
        <button onClick={handleBrowse} className="btn btn-secondary" type="button">
          Browse...</button>
      </div>

      {isEvidencePathRestoredFromSession && evidencePath && (
        <p className="setting-description">Restored previous session evidence path.</p>
      )}
      
      {error && <div className="error-message">{error}</div>}
      
      {evidenceInfo && (
        <div className="evidence-info">
          <div className="info-item">
            <span className="info-label">Filename:</span>
            <span className="info-value">{evidenceInfo.filename}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Size:</span>
            <span className="info-value">{evidenceInfo.size?.toLocaleString()} bytes</span>
          </div>
          <div className="info-item">
            <span className="info-label">Extension:</span>
            <span className="info-value">{evidenceInfo.extension || 'none'}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Path:</span>
            <span className="info-value path">{evidenceInfo.path}</span>
          </div>
          {!isSupported && (
            <div className="warning-message">
              <strong>Warning:</strong> Unsupported format. Supported: {SUPPORTED_EXTENSIONS.join(', ')}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default EvidenceLoader
