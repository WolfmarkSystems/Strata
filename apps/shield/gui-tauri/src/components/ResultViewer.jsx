import { useState } from 'react'
import { open as openPath } from '@tauri-apps/plugin-shell'
import { formatLocalTimestamp } from '../lib/timeFormat'

function ResultViewer({ result, previousResult }) {
  const [showJson, setShowJson] = useState(false)
  const [copySuccess, setCopySuccess] = useState(false)
  const [expandedSections, setExpandedSections] = useState({
    outputs: true,
    sizes: true,
    data: false
  })

  const displayResult = result || previousResult

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }))
  }

  const handleCopyJson = async () => {
    if (!displayResult?.envelope_json) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(displayResult.envelope_json, null, 2))
      setCopySuccess(true)
      setTimeout(() => setCopySuccess(false), 2000)
    } catch (e) {
      console.error('Failed to copy:', e)
    }
  }

  const handleOpenFile = async () => {
    if (!displayResult?.json_path) return
    try {
      await openPath(displayResult.json_path)
    } catch (e) {
      console.error('Failed to open file:', e)
    }
  }

  const getStatusBadge = () => {
    if (!displayResult) return null
    const exitCode = displayResult.exit_code
    const envelopeStatus = String(displayResult?.envelope_json?.status || '').toLowerCase()
    if (envelopeStatus === 'ok') return <span className="status-badge status-ok">OK</span>
    if (envelopeStatus === 'warn') return <span className="status-badge status-warn">WARN</span>
    if (envelopeStatus === 'error') return <span className="status-badge status-error">ERROR</span>
    if (exitCode === 0) return <span className="status-badge status-ok">OK</span>
    if (exitCode === 3) return <span className="status-badge status-warn">WARN</span>
    return <span className="status-badge status-error">ERROR</span>
  }

  const renderCapabilitiesSummary = (data) => {
    if (!data?.capabilities) return null
    const caps = data.capabilities
    const byStatus = {
      production: caps.filter(c => c.status === 'production'),
      beta: caps.filter(c => c.status === 'beta'),
      experimental: caps.filter(c => c.status === 'experimental'),
      stub: caps.filter(c => c.status === 'stub')
    }
    
    return (
      <div className="command-summary">
        <h4>Capabilities ({caps.length} total)</h4>
        <div className="capability-stats">
          <span className="stat stat-ok">{byStatus.production.length} Production</span>
          <span className="stat stat-info">{byStatus.beta.length} Beta</span>
          <span className="stat stat-warn">{byStatus.experimental.length} Experimental</span>
          <span className="stat stat-stub">{byStatus.stub.length} Stub</span>
        </div>
      </div>
    )
  }

  const renderDoctorSummary = (data) => {
    if (!data) return null
    return (
      <div className="command-summary">
        <h4>System Info</h4>
        <div className="info-grid">
          <div className="info-item">
            <span className="info-label">Platform:</span>
            <span className="info-value">{data.platform || 'N/A'}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Version:</span>
            <span className="info-value">{data.tool_version || 'N/A'}</span>
          </div>
          <div className="info-item">
            <span className="info-label">WebView2:</span>
            <span className={`info-value ${data.webview2_found ? 'text-success' : 'text-error'}`}>
              {data.webview2_found ? 'Installed' : 'Not Found'}
            </span>
          </div>
        </div>
      </div>
    )
  }

  const renderSmokeTestSummary = (data) => {
    if (!data) return null
    const analysisValid = typeof data.analysis_valid === 'boolean' ? data.analysis_valid : null
    return (
      <div className="command-summary">
        <h4>Smoke Test Results</h4>
        <div className="info-grid">
          <div className="info-item">
            <span className="info-label">Container:</span>
            <span className="info-value">{data.container_type || 'N/A'}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Analysis:</span>
            <span className={`info-value ${analysisValid === null ? '' : analysisValid ? 'text-success' : 'text-error'}`}>
              {analysisValid === null ? 'Unknown' : analysisValid ? 'Valid' : 'Invalid'}
            </span>
          </div>
          <div className="info-item">
            <span className="info-label">Evidence Size:</span>
            <span className="info-value">{data.evidence_size_bytes?.toLocaleString() || 'N/A'} bytes</span>
          </div>
          <div className="info-item">
            <span className="info-label">MFT Records:</span>
            <span className="info-value">{data.mft_records_emitted || 0}</span>
          </div>
          {data.error && (
            <div className="info-item full-width">
              <span className="info-label">Error:</span>
              <span className="info-value text-error">{data.error}</span>
            </div>
          )}
        </div>
      </div>
    )
  }

  const renderWatchpointsSummary = (data) => {
    if (!data) return null
    return (
      <div className="command-summary">
        <h4>Watchpoints Status</h4>
        <div className="info-grid">
          {data.action && (
            <div className="info-item">
              <span className="info-label">Action:</span>
              <span className="info-value">{data.action}</span>
            </div>
          )}
          <div className="info-item">
            <span className="info-label">Enabled:</span>
            <span className={`info-value ${data.watchpoints_enabled ? 'text-success' : ''}`}>
              {typeof data.watchpoints_enabled === 'boolean'
                ? data.watchpoints_enabled ? 'Yes' : 'No'
                : 'Unknown'}
            </span>
          </div>
          {data.integrity_violation_count !== undefined && (
            <div className="info-item">
              <span className="info-label">Violation Count:</span>
              <span className="info-value">{data.integrity_violation_count}</span>
            </div>
          )}
        </div>
      </div>
    )
  }

  const renderViolationsSummary = (data) => {
    if (!data) return null
    const violations = Array.isArray(data.violations) ? data.violations : []
    const latestTimestamp = violations
      .map((entry) => entry?.occurred_utc)
      .filter(Boolean)
      .reduce((latest, current) => (new Date(current) > new Date(latest) ? current : latest), null)

    return (
      <div className="command-summary">
        <h4>Violations</h4>
        <div className="info-grid">
          <div className="info-item">
            <span className="info-label">Total:</span>
            <span className="info-value">{data.total_returned ?? violations.length}</span>
          </div>
          {data.since_utc && (
            <div className="info-item">
              <span className="info-label">Since:</span>
              <span className="info-value">{data.since_utc}</span>
            </div>
          )}
          {data.limit !== undefined && (
            <div className="info-item">
              <span className="info-label">Limit:</span>
              <span className="info-value">{data.limit}</span>
            </div>
          )}
          {latestTimestamp && (
            <div className="info-item">
              <span className="info-label">Most Recent:</span>
              <span className="info-value">{formatLocalTimestamp(latestTimestamp)}</span>
            </div>
          )}
        </div>
      </div>
    )
  }

  const renderCommandSummary = () => {
    if (!displayResult?.envelope_json?.data) return null
    const data = displayResult.envelope_json.data
    const command = displayResult.envelope_json.command

    switch (command) {
      case 'capabilities':
        return renderCapabilitiesSummary(data)
      case 'doctor':
        return renderDoctorSummary(data)
      case 'smoke-test':
        return renderSmokeTestSummary(data)
      case 'watchpoints':
        return renderWatchpointsSummary(data)
      case 'violations':
        return renderViolationsSummary(data)
      default:
        return null
    }
  }

  const renderOutputs = (outputs) => {
    if (!outputs) return null
    const entries = Object.entries(outputs)
    if (entries.length === 0) return null
    
    return (
      <div className="result-section">
        <button className="section-header" onClick={() => toggleSection('outputs')}>
          <span>Outputs ({entries.length})</span>
          <span className="toggle-icon">{expandedSections.outputs ? '-' : '+'}</span>
        </button>
        {expandedSections.outputs && (
          <div className="section-content">
            {entries.map(([key, value]) => (
              <div key={key} className="output-item">
                <span className="output-key">{key}:</span>
                <span className="output-value">{value || '(empty)'}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  const renderSizes = (sizes) => {
    if (!sizes) return null
    const entries = Object.entries(sizes)
    if (entries.length === 0) return null
    
    return (
      <div className="result-section">
        <button className="section-header" onClick={() => toggleSection('sizes')}>
          <span>Sizes ({entries.length})</span>
          <span className="toggle-icon">{expandedSections.sizes ? '-' : '+'}</span>
        </button>
        {expandedSections.sizes && (
          <div className="section-content">
            {entries.map(([key, value]) => (
              <div key={key} className="size-item">
                <span className="size-key">{key}:</span>
                <span className="size-value">{value?.toLocaleString()} bytes</span>
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  const renderJson = () => {
    if (!displayResult?.envelope_json) return null
    
    return (
      <div className="result-section">
        <button className="section-header" onClick={() => toggleSection('data')}>
          <span>Raw JSON Data</span>
          <span className="toggle-icon">{expandedSections.data ? '-' : '+'}</span>
        </button>
        {expandedSections.data && (
          <div className="section-content json-content">
            <pre>{JSON.stringify(displayResult.envelope_json.data, null, 2)}</pre>
          </div>
        )}
      </div>
    )
  }

  if (!displayResult) {
    return (
      <section className="panel results-panel">
        <h2>Results</h2>
        <p className="no-data">Run a command to see results</p>
      </section>
    )
  }

  const envelope = displayResult.envelope_json
  const exitCode = displayResult.exit_code

  return (
    <section className="panel results-panel">
      <div className="results-header">
        <h2>Results</h2>
        <div className="result-actions">
          <button onClick={handleCopyJson} className="btn btn-small" disabled={!envelope}>
            {copySuccess ? 'Copied!' : 'Copy JSON'}
          </button>
          {displayResult.json_path && (
            <button onClick={handleOpenFile} className="btn btn-small">
              Open File
            </button>
          )}
        </div>
      </div>

      {/* Summary Card */}
      <div className={`summary-card ${exitCode === 0 ? 'status-ok' : exitCode === 3 ? 'status-warn' : 'status-error'}`}>
        <div className="summary-main">
          <span className="summary-command">{envelope?.command || 'Unknown'}</span>
          {getStatusBadge()}
        </div>
        <div className="summary-details">
          <span>Exit: {exitCode}</span>
          <span>Time: {envelope?.elapsed_ms?.toLocaleString() || 'N/A'} ms</span>
          <span>At: {formatLocalTimestamp(envelope?.timestamp_utc)}</span>
        </div>
        {envelope?.error && (
          <div className="summary-error">
            <strong>Error:</strong> {envelope.error}
          </div>
        )}
        {envelope?.warning && (
          <div className="summary-warning">
            <strong>Warning:</strong> {envelope.warning}
          </div>
        )}
      </div>

      {/* Command-Specific Summary */}
      {renderCommandSummary()}

      {/* Outputs */}
      {renderOutputs(envelope?.outputs)}

      {/* Sizes */}
      {renderSizes(envelope?.sizes)}

      {/* JSON Data */}
      {renderJson()}

      {/* Stderr/Stdout for errors */}
      {displayResult.stderr && exitCode !== 0 && (
        <div className="result-section">
          <div className="section-content error-output">
            <pre>{displayResult.stderr}</pre>
          </div>
        </div>
      )}
    </section>
  )
}

export default ResultViewer
