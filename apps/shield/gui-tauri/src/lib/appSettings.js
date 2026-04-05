import {
  DEFAULT_HISTORY_RETENTION_MODE,
  DEFAULT_MAX_HISTORY_FILES,
  sanitizeHistoryRetentionSettings,
} from './jobHistory'

export const APP_SETTINGS_STORAGE_KEY = 'forensic-suite.app-settings.v1'
const LEGACY_HISTORY_RETENTION_SETTINGS_KEY = 'forensic-suite.history-retention.v1'
const REMEMBERED_CONTEXT_STORAGE_KEY = 'forensic-suite.remembered-context.v1'
export const LAST_CASE_ID_STORAGE_KEY = 'forensic-suite.lastCaseId'
export const LAST_CASE_DB_PATH_STORAGE_KEY = 'forensic-suite.lastCaseDbPath'
export const LAST_EVIDENCE_PATH_STORAGE_KEY = 'forensic-suite.lastEvidencePath'
export const LAST_ACTIVE_PAGE_STORAGE_KEY = 'forensic-suite.lastActivePage'

export const DEFAULT_SMOKE_MFT_COUNT = 50
export const DEFAULT_EXAMINE_PRESET = 'Fast Triage'
export const DEFAULT_FILETABLE_LIMIT = 200

export const DEFAULT_APP_SETTINGS = Object.freeze({
  defaultSmokeMftCount: DEFAULT_SMOKE_MFT_COUNT,
  defaultExaminePreset: DEFAULT_EXAMINE_PRESET,
  defaultFileTableLimit: DEFAULT_FILETABLE_LIMIT,
  historyRetentionMode: DEFAULT_HISTORY_RETENTION_MODE,
  maxHistoryFiles: DEFAULT_MAX_HISTORY_FILES,
  rememberLastCase: false,
  rememberLastEvidencePath: false,
})

function sanitizePositiveInt(value, fallback, min, max) {
  const parsed = Number.parseInt(String(value ?? ''), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(Math.max(parsed, min), max)
}

function sanitizeString(value, fallback) {
  if (typeof value !== 'string') return fallback
  const trimmed = value.trim()
  return trimmed || fallback
}

function sanitizeBoolean(value, fallback = false) {
  if (typeof value === 'boolean') return value
  if (value === 'true' || value === '1' || value === 1) return true
  if (value === 'false' || value === '0' || value === 0) return false
  return fallback
}

export function sanitizeAppSettings(rawSettings) {
  const retention = sanitizeHistoryRetentionSettings(rawSettings)
  return {
    defaultSmokeMftCount: sanitizePositiveInt(
      rawSettings?.defaultSmokeMftCount,
      DEFAULT_APP_SETTINGS.defaultSmokeMftCount,
      1,
      1_000_000,
    ),
    defaultExaminePreset: sanitizeString(
      rawSettings?.defaultExaminePreset,
      DEFAULT_APP_SETTINGS.defaultExaminePreset,
    ),
    defaultFileTableLimit: sanitizePositiveInt(
      rawSettings?.defaultFileTableLimit,
      DEFAULT_APP_SETTINGS.defaultFileTableLimit,
      1,
      10_000,
    ),
    historyRetentionMode: retention.historyRetentionMode,
    maxHistoryFiles: retention.maxHistoryFiles,
    rememberLastCase: sanitizeBoolean(rawSettings?.rememberLastCase, DEFAULT_APP_SETTINGS.rememberLastCase),
    rememberLastEvidencePath: sanitizeBoolean(
      rawSettings?.rememberLastEvidencePath,
      DEFAULT_APP_SETTINGS.rememberLastEvidencePath,
    ),
  }
}

function parseJsonStorage(key) {
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

export function loadAppSettings() {
  const parsed = parseJsonStorage(APP_SETTINGS_STORAGE_KEY)
  if (parsed) {
    return sanitizeAppSettings(parsed)
  }

  // Retain existing history retention preferences from older builds.
  const legacyRetention = parseJsonStorage(LEGACY_HISTORY_RETENTION_SETTINGS_KEY)
  return sanitizeAppSettings({
    ...DEFAULT_APP_SETTINGS,
    ...(legacyRetention || {}),
  })
}

export function saveAppSettings(nextSettings) {
  const sanitized = sanitizeAppSettings(nextSettings)
  try {
    localStorage.setItem(APP_SETTINGS_STORAGE_KEY, JSON.stringify(sanitized))
    return { settings: sanitized, persisted: true, error: null }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { settings: sanitized, persisted: false, error: message }
  }
}

export function resetAppSettings() {
  return saveAppSettings(DEFAULT_APP_SETTINGS)
}

function sanitizeRememberedContext(rawContext) {
  const caseId = typeof rawContext?.caseId === 'string' ? rawContext.caseId.trim() : ''
  const caseDbPath = typeof rawContext?.caseDbPath === 'string' ? rawContext.caseDbPath.trim() : ''
  const evidencePath = typeof rawContext?.evidencePath === 'string' ? rawContext.evidencePath.trim() : ''
  const lastActivePage = typeof rawContext?.lastActivePage === 'string' ? rawContext.lastActivePage.trim() : ''
  return { caseId, caseDbPath, evidencePath, lastActivePage }
}

function readSanitizedStorageValue(key) {
  try {
    const raw = localStorage.getItem(key)
    if (raw === null || raw === undefined) return ''
    const trimmed = String(raw).trim()
    if (!trimmed) {
      localStorage.removeItem(key)
      return ''
    }
    return trimmed
  } catch {
    return ''
  }
}

export function loadRememberedContext() {
  const directContext = sanitizeRememberedContext({
    caseId: readSanitizedStorageValue(LAST_CASE_ID_STORAGE_KEY),
    caseDbPath: readSanitizedStorageValue(LAST_CASE_DB_PATH_STORAGE_KEY),
    evidencePath: readSanitizedStorageValue(LAST_EVIDENCE_PATH_STORAGE_KEY),
    lastActivePage: readSanitizedStorageValue(LAST_ACTIVE_PAGE_STORAGE_KEY),
  })

  if (directContext.caseId || directContext.caseDbPath || directContext.evidencePath || directContext.lastActivePage) {
    return directContext
  }

  // Backward compatibility: older builds stored remembered context in one JSON value.
  const parsed = parseJsonStorage(REMEMBERED_CONTEXT_STORAGE_KEY)
  if (!parsed) return directContext
  return sanitizeRememberedContext(parsed)
}

export function persistRememberedContext(updates) {
  const current = loadRememberedContext()
  const merged = sanitizeRememberedContext({
    ...current,
    ...(updates || {}),
  })
  try {
    if (merged.caseId) localStorage.setItem(LAST_CASE_ID_STORAGE_KEY, merged.caseId)
    else localStorage.removeItem(LAST_CASE_ID_STORAGE_KEY)

    if (merged.caseDbPath) localStorage.setItem(LAST_CASE_DB_PATH_STORAGE_KEY, merged.caseDbPath)
    else localStorage.removeItem(LAST_CASE_DB_PATH_STORAGE_KEY)

    if (merged.evidencePath) localStorage.setItem(LAST_EVIDENCE_PATH_STORAGE_KEY, merged.evidencePath)
    else localStorage.removeItem(LAST_EVIDENCE_PATH_STORAGE_KEY)

    if (merged.lastActivePage) localStorage.setItem(LAST_ACTIVE_PAGE_STORAGE_KEY, merged.lastActivePage)
    else localStorage.removeItem(LAST_ACTIVE_PAGE_STORAGE_KEY)

    // Keep writing legacy format for compatibility with prior loaders.
    localStorage.setItem(REMEMBERED_CONTEXT_STORAGE_KEY, JSON.stringify(merged))
    return { context: merged, persisted: true, error: null }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { context: merged, persisted: false, error: message }
  }
}

export function clearRememberedContext(fields = []) {
  const clearAll = !Array.isArray(fields) || fields.length === 0
  if (clearAll) {
    try {
      localStorage.removeItem(LAST_CASE_ID_STORAGE_KEY)
      localStorage.removeItem(LAST_CASE_DB_PATH_STORAGE_KEY)
      localStorage.removeItem(LAST_EVIDENCE_PATH_STORAGE_KEY)
      localStorage.removeItem(LAST_ACTIVE_PAGE_STORAGE_KEY)
      localStorage.removeItem(REMEMBERED_CONTEXT_STORAGE_KEY)
      return { cleared: true, error: null }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return { cleared: false, error: message }
    }
  }

  const current = loadRememberedContext()
  const next = { ...current }
  fields.forEach((field) => {
    if (field === 'caseId' || field === 'caseDbPath' || field === 'evidencePath' || field === 'lastActivePage') {
      next[field] = ''
    }
  })

  if (!next.caseId && !next.caseDbPath && !next.evidencePath && !next.lastActivePage) {
    return clearRememberedContext()
  }

  try {
    if (next.caseId) localStorage.setItem(LAST_CASE_ID_STORAGE_KEY, next.caseId)
    else localStorage.removeItem(LAST_CASE_ID_STORAGE_KEY)

    if (next.caseDbPath) localStorage.setItem(LAST_CASE_DB_PATH_STORAGE_KEY, next.caseDbPath)
    else localStorage.removeItem(LAST_CASE_DB_PATH_STORAGE_KEY)

    if (next.evidencePath) localStorage.setItem(LAST_EVIDENCE_PATH_STORAGE_KEY, next.evidencePath)
    else localStorage.removeItem(LAST_EVIDENCE_PATH_STORAGE_KEY)

    if (next.lastActivePage) localStorage.setItem(LAST_ACTIVE_PAGE_STORAGE_KEY, next.lastActivePage)
    else localStorage.removeItem(LAST_ACTIVE_PAGE_STORAGE_KEY)

    localStorage.setItem(REMEMBERED_CONTEXT_STORAGE_KEY, JSON.stringify(next))
    return { cleared: true, error: null }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { cleared: false, error: message }
  }
}
