import { useEffect, useState } from 'react'
import { DEFAULT_APP_SETTINGS } from '../lib/appSettings'

function buildFormState(settings) {
  return {
    defaultSmokeMftCount: String(settings?.defaultSmokeMftCount ?? DEFAULT_APP_SETTINGS.defaultSmokeMftCount),
    defaultExaminePreset: settings?.defaultExaminePreset ?? DEFAULT_APP_SETTINGS.defaultExaminePreset,
    defaultFileTableLimit: String(settings?.defaultFileTableLimit ?? DEFAULT_APP_SETTINGS.defaultFileTableLimit),
    historyRetentionMode: settings?.historyRetentionMode ?? DEFAULT_APP_SETTINGS.historyRetentionMode,
    maxHistoryFiles: String(settings?.maxHistoryFiles ?? DEFAULT_APP_SETTINGS.maxHistoryFiles),
    rememberLastCase: Boolean(settings?.rememberLastCase),
    rememberLastEvidencePath: Boolean(settings?.rememberLastEvidencePath),
  }
}

function Settings({
  settings,
  onSaveSettings,
  onResetSettings,
  onRunHistoryCleanup,
  historyCleanupResult,
  isHistoryCleanupRunning = false,
}) {
  const [formState, setFormState] = useState(buildFormState(settings))
  const [feedback, setFeedback] = useState(null)

  useEffect(() => {
    setFormState(buildFormState(settings))
  }, [settings])

  const handleChange = (key, value) => {
    setFormState((previous) => ({ ...previous, [key]: value }))
  }

  const handleSave = async () => {
    setFeedback(null)
    const nextSettings = {
      defaultSmokeMftCount: Number.parseInt(formState.defaultSmokeMftCount, 10),
      defaultExaminePreset: formState.defaultExaminePreset,
      defaultFileTableLimit: Number.parseInt(formState.defaultFileTableLimit, 10),
      historyRetentionMode: formState.historyRetentionMode,
      maxHistoryFiles: Number.parseInt(formState.maxHistoryFiles, 10),
      rememberLastCase: formState.rememberLastCase,
      rememberLastEvidencePath: formState.rememberLastEvidencePath,
    }

    try {
      const result = await Promise.resolve(onSaveSettings?.(nextSettings))
      if (result?.settings) {
        setFormState(buildFormState(result.settings))
      }
      if (result?.persisted) {
        setFeedback({ kind: 'success', message: 'Settings saved.' })
      } else {
        setFeedback({
          kind: 'error',
          message: `Settings applied in-memory, but local save failed: ${result?.error || 'unknown error'}`,
        })
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      setFeedback({ kind: 'error', message: `Failed to save settings: ${message}` })
    }
  }

  const handleReset = async () => {
    setFeedback(null)
    try {
      const result = await Promise.resolve(onResetSettings?.())
      if (result?.settings) {
        setFormState(buildFormState(result.settings))
      } else {
        setFormState(buildFormState(DEFAULT_APP_SETTINGS))
      }

      if (result?.persisted) {
        setFeedback({ kind: 'success', message: 'Settings reset to defaults.' })
      } else {
        setFeedback({
          kind: 'error',
          message: `Defaults applied in-memory, but local save failed: ${result?.error || 'unknown error'}`,
        })
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      setFeedback({ kind: 'error', message: `Failed to reset settings: ${message}` })
    }
  }

  const renderCleanupMessage = () => {
    if (!historyCleanupResult) return null
    const ranAt = historyCleanupResult.ranAt ? new Date(historyCleanupResult.ranAt).toLocaleString() : 'N/A'
    return (
      <div className="setting-item">
        <div className="setting-info">
          <label>Last Cleanup</label>
          <span className="setting-description">
            {`Ran ${ranAt}. Deleted ${historyCleanupResult.deletedCount || 0} file(s), kept ${historyCleanupResult.keptCount || 0}.`}
          </span>
          {(historyCleanupResult.warningCount || 0) > 0 && (
            <span className="setting-description text-error">
              {`Warnings: ${historyCleanupResult.warningCount}`}
            </span>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="page settings">
      <header className="page-header">
        <h1>Settings</h1>
        <p className="page-subtitle">Shared defaults and local workstation preferences.</p>
      </header>

      <div className="settings-layout">
        <section className="panel settings-section">
          <h2>Command Defaults</h2>

          <div className="setting-item">
            <div className="setting-info">
              <label>Default Smoke MFT Count</label>
              <span className="setting-description">Used by smoke-test quick actions unless manually overridden.</span>
            </div>
            <input
              type="number"
              min="1"
              step="1"
              value={formState.defaultSmokeMftCount}
              onChange={(event) => handleChange('defaultSmokeMftCount', event.target.value)}
              className="setting-input"
            />
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <label>Default Examine Preset</label>
              <span className="setting-description">Used for examine commands in Artifacts and Case Overview.</span>
            </div>
            <input
              type="text"
              value={formState.defaultExaminePreset}
              onChange={(event) => handleChange('defaultExaminePreset', event.target.value)}
              className="setting-input"
            />
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <label>Default File Table Limit</label>
              <span className="setting-description">Initial `filetable --limit` value in File Explorer.</span>
            </div>
            <input
              type="number"
              min="1"
              step="1"
              value={formState.defaultFileTableLimit}
              onChange={(event) => handleChange('defaultFileTableLimit', event.target.value)}
              className="setting-input"
            />
          </div>
        </section>

        <section className="panel settings-section">
          <h2>History Retention</h2>

          <div className="setting-item">
            <div className="setting-info">
              <label>Retention Mode</label>
              <span className="setting-description">Keep all history by default, or cap stored history files.</span>
            </div>
            <select
              value={formState.historyRetentionMode}
              onChange={(event) => handleChange('historyRetentionMode', event.target.value)}
              className="setting-select"
            >
              <option value="keep-all">Keep all history</option>
              <option value="max-files">Limit history files</option>
            </select>
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <label>Max History Files</label>
              <span className="setting-description">Only applies when retention mode is set to limit files.</span>
            </div>
            <input
              type="number"
              min="1"
              step="1"
              disabled={formState.historyRetentionMode !== 'max-files'}
              value={formState.maxHistoryFiles}
              onChange={(event) => handleChange('maxHistoryFiles', event.target.value)}
              className="setting-input"
            />
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <label>Cleanup</label>
              <span className="setting-description">Run retention cleanup now with current settings.</span>
            </div>
            <button
              className="btn btn-secondary"
              onClick={onRunHistoryCleanup}
              disabled={isHistoryCleanupRunning}
            >
              {isHistoryCleanupRunning ? 'Cleaning...' : 'Run Cleanup Now'}
            </button>
          </div>

          {renderCleanupMessage()}
        </section>

        <section className="panel settings-section">
          <h2>Workspace Memory</h2>

          <div className="setting-item">
            <div className="setting-info">
              <label>Remember Last Case</label>
              <span className="setting-description">Restore prior case ID and DB path on startup.</span>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={formState.rememberLastCase}
                onChange={(event) => handleChange('rememberLastCase', event.target.checked)}
              />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <label>Remember Last Evidence Path</label>
              <span className="setting-description">Restore prior evidence path on startup.</span>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={formState.rememberLastEvidencePath}
                onChange={(event) => handleChange('rememberLastEvidencePath', event.target.checked)}
              />
              <span className="toggle-slider"></span>
            </label>
          </div>
        </section>

        {feedback && (
          <section className="panel">
            {feedback.kind === 'success' ? (
              <div className="hint">{feedback.message}</div>
            ) : (
              <div className="error-message">{feedback.message}</div>
            )}
          </section>
        )}

        <section className="panel settings-actions">
          <button className="btn btn-secondary" onClick={handleReset}>
            Reset to Defaults
          </button>
          <button className="btn btn-primary" onClick={handleSave}>
            Save / Apply
          </button>
        </section>
      </div>
    </div>
  )
}

export default Settings
