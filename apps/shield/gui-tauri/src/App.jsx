import { useState, useEffect, useMemo, useRef } from 'react'
import { BrowserRouter, Routes, Route, useLocation, useNavigate } from 'react-router-dom'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import Navigation from './components/Navigation'
import Dashboard from './pages/Dashboard'
import CaseOverview from './pages/CaseOverview'
import EvidenceSources from './pages/EvidenceSources'
import FileExplorer from './pages/FileExplorer'
import Timeline from './pages/Timeline'
import Artifacts from './pages/Artifacts'
import HashSets from './pages/HashSets'
import Logs from './pages/Logs'
import Settings from './pages/Settings'
import {
  loadPersistedJobs,
  persistJobEnvelope,
  persistNormalizedStdoutJsonResult,
  prunePersistedHistory,
} from './lib/jobHistory'
import {
  loadAppSettings,
  saveAppSettings,
  resetAppSettings,
  loadRememberedContext,
  persistRememberedContext,
  clearRememberedContext,
} from './lib/appSettings'
import './App.css'

const DEFAULT_EVIDENCE_PATH = 'D:\\forensic-suite\\evidence\\Stack001_Surface_HDD.E01'
const DEFAULT_CASE_DB_PATH = 'exports/cases/'
const GUARDIAN_WARNING_TTL_MS = 30 * 60 * 1000

function loadInitialAppState() {
  const settings = loadAppSettings()
  const remembered = loadRememberedContext()
  return { settings, remembered }
}

const RESTORABLE_ROUTES = new Set([
  '/',
  '/case',
  '/evidence',
  '/files',
  '/timeline',
  '/artifacts',
  '/hashes',
  '/logs',
  '/settings',
])

function normalizeRememberedRoute(pathname) {
  if (typeof pathname !== 'string') return ''
  const trimmed = pathname.trim()
  if (!trimmed.startsWith('/')) return ''
  if (!RESTORABLE_ROUTES.has(trimmed)) return ''
  return trimmed
}

function StartupRouteRestore({ rememberedPath }) {
  const location = useLocation()
  const navigate = useNavigate()
  const hasRestored = useRef(false)

  useEffect(() => {
    if (hasRestored.current) return
    hasRestored.current = true
    const target = normalizeRememberedRoute(rememberedPath)
    if (!target || target === location.pathname) return
    navigate(target, { replace: true })
  }, [rememberedPath, location.pathname, navigate])

  return null
}

function SessionRouteTracker() {
  const location = useLocation()

  useEffect(() => {
    if (!location?.pathname) return
    const result = persistRememberedContext({ lastActivePage: location.pathname })
    if (!result.persisted && result.error) {
      console.warn('Failed to persist last active page:', result.error)
    }
  }, [location?.pathname])

  return null
}

function App() {
  const [initialState] = useState(() => loadInitialAppState())
  const restoredCaseId = initialState.settings.rememberLastCase && initialState.remembered.caseId
    ? initialState.remembered.caseId
    : ''
  const restoredCaseDbPath = initialState.settings.rememberLastCase && initialState.remembered.caseDbPath
    ? initialState.remembered.caseDbPath
    : ''
  const restoredEvidencePath = initialState.settings.rememberLastEvidencePath && initialState.remembered.evidencePath
    ? initialState.remembered.evidencePath
    : ''
  const shouldRestoreLastPage = initialState.settings.rememberLastCase || initialState.settings.rememberLastEvidencePath
  const restoredLastActivePage = shouldRestoreLastPage
    ? normalizeRememberedRoute(initialState.remembered.lastActivePage)
    : ''

  const [appSettings, setAppSettings] = useState(initialState.settings)
  const [isRunning, setIsRunning] = useState(false)
  const [activeCommand, setActiveCommand] = useState('')
  const [currentResult, setCurrentResult] = useState(null)
  const [evidencePath, setEvidencePath] = useState(() => {
    if (restoredEvidencePath) {
      return restoredEvidencePath
    }
    return DEFAULT_EVIDENCE_PATH
  })
  const [evidenceInfo, setEvidenceInfo] = useState(null)
  const [caseId, setCaseId] = useState(() => {
    if (restoredCaseId) {
      return restoredCaseId
    }
    return ''
  })
  const [caseDbPath, setCaseDbPath] = useState(() => {
    if (restoredCaseDbPath) {
      return restoredCaseDbPath
    }
    return DEFAULT_CASE_DB_PATH
  })
  const [jobs, setJobs] = useState([])
  const [historyMalformedCount, setHistoryMalformedCount] = useState(0)
  const [historyIgnoredCount, setHistoryIgnoredCount] = useState(0)
  const [historyError, setHistoryError] = useState(null)
  const [isHistoryLoading, setIsHistoryLoading] = useState(false)
  const [historyCleanupResult, setHistoryCleanupResult] = useState(null)
  const [isHistoryCleanupRunning, setIsHistoryCleanupRunning] = useState(false)
  const [guardianWarnings, setGuardianWarnings] = useState([])
  const [guardianWarningNow, setGuardianWarningNow] = useState(() => Date.now())
  const isCaseRestoredFromSession = (
    Boolean(restoredCaseId || restoredCaseDbPath)
    && caseId === (restoredCaseId || '')
    && caseDbPath === (restoredCaseDbPath || DEFAULT_CASE_DB_PATH)
  )
  const isEvidencePathRestoredFromSession = Boolean(restoredEvidencePath) && evidencePath === restoredEvidencePath

  const handleCaseChange = (newCaseId, newDbPath) => {
    if (typeof newCaseId === 'string') setCaseId(newCaseId)
    if (typeof newDbPath === 'string') setCaseDbPath(newDbPath)
  }

  const refreshHistory = async () => {
    setIsHistoryLoading(true)
    setHistoryError(null)
    try {
      const { jobs: persistedJobs, malformedCount, ignoredCount } = await loadPersistedJobs()
      setJobs(persistedJobs)
      setHistoryMalformedCount(malformedCount)
      setHistoryIgnoredCount(ignoredCount)
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      console.error('Failed to load job history:', e)
      setJobs([])
      setHistoryMalformedCount(0)
      setHistoryIgnoredCount(0)
      setHistoryError(message)
    } finally {
      setIsHistoryLoading(false)
    }
  }

  useEffect(() => {
    refreshHistory()
  }, [])

  useEffect(() => {
    const unlistenPromise = listen('guardian-warning', (event) => {
      const payload = event?.payload || {}
      if (typeof payload.warning !== 'string' || payload.warning.trim().length === 0) {
        return
      }

      const normalized = {
        command: typeof payload.command === 'string' && payload.command.trim().length > 0 ? payload.command : 'unknown',
        warning: payload.warning.trim(),
        timestamp: typeof payload.timestamp === 'string' && payload.timestamp.trim().length > 0
          ? payload.timestamp
          : new Date().toISOString(),
      }

      setGuardianWarnings((previous) => [...previous, normalized].slice(-20))
    })

    return () => {
      unlistenPromise.then((unlisten) => unlisten())
    }
  }, [])

  useEffect(() => {
    const timer = window.setInterval(() => setGuardianWarningNow(Date.now()), 60 * 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (appSettings.rememberLastCase) {
      const result = persistRememberedContext({ caseId, caseDbPath })
      if (!result.persisted && result.error) {
        console.warn('Failed to persist remembered case context:', result.error)
      }
      return
    }
    const clearResult = clearRememberedContext(['caseId', 'caseDbPath'])
    if (!clearResult.cleared && clearResult.error) {
      console.warn('Failed to clear remembered case context:', clearResult.error)
    }
  }, [appSettings.rememberLastCase, caseId, caseDbPath])

  useEffect(() => {
    if (appSettings.rememberLastEvidencePath) {
      const result = persistRememberedContext({ evidencePath })
      if (!result.persisted && result.error) {
        console.warn('Failed to persist remembered evidence path:', result.error)
      }
      return
    }
    const clearResult = clearRememberedContext(['evidencePath'])
    if (!clearResult.cleared && clearResult.error) {
      console.warn('Failed to clear remembered evidence path:', clearResult.error)
    }
  }, [appSettings.rememberLastEvidencePath, evidencePath])

  const saveGuiSettings = (nextSettings) => {
    const result = saveAppSettings(nextSettings)
    setAppSettings(result.settings)
    return result
  }

  const resetGuiSettings = () => {
    const result = resetAppSettings()
    setAppSettings(result.settings)
    return result
  }

  const maybeApplyHistoryPrune = async () => {
    if (appSettings.historyRetentionMode !== 'max-files') return
    try {
      const result = await prunePersistedHistory({
        historyRetentionMode: appSettings.historyRetentionMode,
        maxHistoryFiles: appSettings.maxHistoryFiles,
      })
      if (result.deletedCount > 0 || result.warningCount > 0) {
        setHistoryCleanupResult({
          ...result,
          ranAt: new Date().toISOString(),
          trigger: 'auto',
        })
      }
    } catch (e) {
      console.warn('Failed to apply history pruning:', e)
    }
  }

  const runHistoryCleanupNow = async () => {
    setIsHistoryCleanupRunning(true)
    try {
      const result = await prunePersistedHistory({
        historyRetentionMode: appSettings.historyRetentionMode,
        maxHistoryFiles: appSettings.maxHistoryFiles,
      })
      setHistoryCleanupResult({
        ...result,
        ranAt: new Date().toISOString(),
        trigger: 'manual',
      })
      await refreshHistory()
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      setHistoryCleanupResult({
        mode: appSettings.historyRetentionMode,
        maxFiles: appSettings.maxHistoryFiles,
        totalHistoryFiles: jobs.length,
        deletedCount: 0,
        keptCount: jobs.length,
        skippedCount: 0,
        warningCount: 1,
        warnings: [message],
        deletedFiles: [],
        ranAt: new Date().toISOString(),
        trigger: 'manual',
      })
    } finally {
      setIsHistoryCleanupRunning(false)
    }
  }

  const runCommand = async (command, args = []) => {
    setIsRunning(true)
    setActiveCommand(command)
    try {
      const result = await invoke('run_cli', { args: [command, ...args] })
      setCurrentResult(result)
      if (result.envelope_json) {
        try {
          await persistJobEnvelope(command, result.envelope_json)
          await maybeApplyHistoryPrune()
          await refreshHistory()
        } catch (persistError) {
          console.error('Failed to persist command result:', persistError)
        }
      }
    } catch (error) {
      setCurrentResult({
        exit_code: -1,
        stdout: '',
        stderr: error.toString(),
        envelope_json: null,
        json_path: null
      })
    } finally {
      setIsRunning(false)
      setActiveCommand('')
    }
  }

  const activeGuardianWarnings = useMemo(() => {
    return guardianWarnings.filter((warning) => {
      const parsed = Date.parse(warning.timestamp)
      if (Number.isNaN(parsed)) return true
      return (guardianWarningNow - parsed) <= GUARDIAN_WARNING_TTL_MS
    })
  }, [guardianWarnings, guardianWarningNow])

  const clearGuardianWarnings = () => {
    setGuardianWarnings([])
  }

  const persistGuiCommandResult = async (command, args, normalizedResult) => {
    try {
      let persisted = null
      if (normalizedResult?.mode === 'envelope' && normalizedResult?.raw?.envelopeJson) {
        persisted = await persistJobEnvelope(command, normalizedResult.raw.envelopeJson)
      } else {
        persisted = await persistNormalizedStdoutJsonResult(command, args, normalizedResult)
      }
      if (persisted) {
        await maybeApplyHistoryPrune()
        await refreshHistory()
      }
      return { persisted, error: null }
    } catch (persistError) {
      console.error('Failed to persist normalized command result:', persistError)
      const message = persistError instanceof Error ? persistError.message : String(persistError)
      return { persisted: null, error: message }
    }
  }

  return (
    <BrowserRouter>
      <div className="app">
        <SessionRouteTracker />
        <StartupRouteRestore rememberedPath={restoredLastActivePage} />
        <Navigation caseId={caseId} />
        
        <main className="app-main">
          {isRunning && (
            <div className="active-command-strip" role="status" aria-live="polite">
              <div className="spinner" aria-hidden="true"></div>
              <span className="active-command-label">Command running:</span>
              <span className="active-command-name">{activeCommand}</span>
            </div>
          )}
          <Routes>
            <Route 
              path="/" 
              element={
                <Dashboard 
                  caseId={caseId}
                  caseDbPath={caseDbPath}
                  evidencePath={evidencePath}
                  evidenceInfo={evidenceInfo}
                  defaultSmokeMftCount={appSettings.defaultSmokeMftCount}
                  defaultExaminePreset={appSettings.defaultExaminePreset}
                  jobs={jobs}
                  isRunning={isRunning}
                  activeCommand={activeCommand}
                  guardianWarnings={activeGuardianWarnings}
                  onClearGuardianWarnings={clearGuardianWarnings}
                  onRunCommand={runCommand}
                />
              } 
            />
            <Route 
              path="/case" 
              element={
                <CaseOverview 
                  caseId={caseId}
                  caseDbPath={caseDbPath}
                  evidencePath={evidencePath}
                  isCaseRestoredFromSession={isCaseRestoredFromSession}
                  defaultExaminePreset={appSettings.defaultExaminePreset}
                  jobs={jobs}
                  onCaseChange={handleCaseChange}
                  onRunCommand={runCommand}
                  isRunning={isRunning}
                />
              } 
            />
            <Route 
              path="/evidence" 
              element={
                <EvidenceSources 
                  caseId={caseId}
                  caseDbPath={caseDbPath}
                  evidencePath={evidencePath}
                  evidenceInfo={evidenceInfo}
                  isEvidencePathRestoredFromSession={isEvidencePathRestoredFromSession}
                  defaultSmokeMftCount={appSettings.defaultSmokeMftCount}
                  onPathChange={setEvidencePath}
                  onInfoChange={setEvidenceInfo}
                  onRunCommand={runCommand}
                  onPersistGuiCommandResult={persistGuiCommandResult}
                  isRunning={isRunning}
                  jobs={jobs}
                />
              } 
            />
            <Route 
              path="/files" 
              element={
                <FileExplorer 
                  caseId={caseId}
                  caseDbPath={caseDbPath}
                  evidencePath={evidencePath}
                  jobs={jobs}
                  defaultFileTableLimit={appSettings.defaultFileTableLimit}
                  onPersistGuiCommandResult={persistGuiCommandResult}
                />
              } 
            />
            <Route 
              path="/timeline" 
              element={
                <Timeline 
                  caseId={caseId}
                  caseDbPath={caseDbPath}
                  jobs={jobs}
                  onPersistGuiCommandResult={persistGuiCommandResult}
                />
              } 
            />
            <Route 
              path="/artifacts" 
              element={
                <Artifacts 
                  caseId={caseId}
                  caseDbPath={caseDbPath}
                  evidencePath={evidencePath}
                  defaultExaminePreset={appSettings.defaultExaminePreset}
                  jobs={jobs}
                  onRunCommand={runCommand}
                  isRunning={isRunning}
                />
              } 
            />
            <Route 
              path="/hashes" 
              element={
                <HashSets 
                  caseId={caseId}
                  caseDbPath={caseDbPath}
                  jobs={jobs}
                  onRunCommand={runCommand}
                  onPersistGuiCommandResult={persistGuiCommandResult}
                  isRunning={isRunning}
                />
              } 
            />
            <Route 
              path="/logs" 
              element={
                <Logs 
                  jobs={jobs}
                  currentResult={currentResult}
                  isRunning={isRunning}
                  activeCommand={activeCommand}
                  isHistoryLoading={isHistoryLoading}
                  historyMalformedCount={historyMalformedCount}
                  historyIgnoredCount={historyIgnoredCount}
                  historyError={historyError}
                  onRefreshHistory={refreshHistory}
                />
              } 
            />
            <Route 
              path="/settings" 
              element={
                <Settings
                  settings={appSettings}
                  onSaveSettings={saveGuiSettings}
                  onResetSettings={resetGuiSettings}
                  onRunHistoryCleanup={runHistoryCleanupNow}
                  historyCleanupResult={historyCleanupResult}
                  isHistoryCleanupRunning={isHistoryCleanupRunning}
                />
              } 
            />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App



