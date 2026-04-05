import {
  BaseDirectory,
  exists,
  mkdir,
  remove,
  readDir,
  readTextFile,
  writeTextFile,
} from '@tauri-apps/plugin-fs'

const RUNS_DIR = 'gui/runs'
const NORMALIZED_HISTORY_FORMAT = 'gui-normalized-command-result-v1'
export const DEFAULT_HISTORY_RETENTION_MODE = 'keep-all'
export const DEFAULT_MAX_HISTORY_FILES = 500
const MAX_HISTORY_FILES_HARD_CAP = 20000

function normalizeTimestamp(value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed) return null
  // Rust timestamps may include nanoseconds; trim to milliseconds for JS Date parsing.
  const normalized = trimmed.replace(/\.(\d{3})\d+(?=(Z|[+-]\d{2}:\d{2})$)/, '.$1')
  const date = new Date(normalized)
  if (Number.isNaN(date.getTime())) return null
  return {
    iso: date.toISOString(),
    epochMs: date.getTime(),
  }
}

function parseTimestampFromHistoryFilename(filename) {
  if (typeof filename !== 'string') return null
  const match = filename.match(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})(?:-(\d{3}))?_/)
  if (!match) return null
  const [, day, hour, minute, second, millis] = match
  const iso = `${day}T${hour}:${minute}:${second}.${millis || '000'}Z`
  return normalizeTimestamp(iso)
}

function parseCommandFromHistoryFilename(filename) {
  if (typeof filename !== 'string') return null
  const match = filename.match(/^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}(?:-\d{3})?_(.+)\.json$/)
  if (!match) return null
  const rawCommand = match[1].replace(/_\d{2}$/, '')
  return rawCommand || null
}

function formatTimestampForFilename(input) {
  const date = input instanceof Date ? input : new Date(input)
  const safeDate = Number.isNaN(date.getTime()) ? new Date() : date
  return safeDate.toISOString().replace(/:/g, '-').replace(/\./g, '-').replace('Z', '')
}

function sanitizeCommand(command) {
  const value = String(command || 'command').trim().toLowerCase()
  const cleaned = value.replace(/[^a-z0-9_-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '')
  return cleaned || 'command'
}

function parseExitCode(value) {
  return Number.isInteger(value) ? value : null
}

function deriveStatus(status, exitCode) {
  if (typeof status === 'string' && status.trim()) return status
  if (exitCode === 0) return 'ok'
  if (exitCode === 3) return 'warn'
  if (exitCode === null) return 'unknown'
  return 'error'
}

function isNormalizedHistoryRecord(value) {
  return value?.history_format === NORMALIZED_HISTORY_FORMAT
}

function buildJob(envelope, filename) {
  const safeRecord = envelope && typeof envelope === 'object' && !Array.isArray(envelope) ? envelope : {}
  const filenameTimestamp = parseTimestampFromHistoryFilename(filename)
  const recordTimestamp = normalizeTimestamp(safeRecord.timestamp_utc)
  const timestamp = recordTimestamp || filenameTimestamp
  const exitCode = parseExitCode(safeRecord.exit_code)
  const filenameCommand = parseCommandFromHistoryFilename(filename)
  const command = typeof safeRecord.command === 'string' && safeRecord.command
    ? safeRecord.command
    : (filenameCommand || 'unknown')
  const recognizedByShape = isNormalizedHistoryRecord(safeRecord)
    || (typeof safeRecord.command === 'string' && typeof safeRecord.timestamp_utc === 'string')
  const recognizedByFilename = Boolean(filenameTimestamp)
  const isHistoryFile = recognizedByShape || recognizedByFilename

  return {
    filename,
    filePath: `${RUNS_DIR}/${filename}`,
    timestamp: timestamp?.iso || safeRecord.timestamp_utc || null,
    timestamp_epoch_ms: timestamp?.epochMs || 0,
    sort_epoch_ms: filenameTimestamp?.epochMs || timestamp?.epochMs || 0,
    command,
    status: deriveStatus(safeRecord.status, exitCode),
    exit_code: exitCode,
    elapsed_ms: Number.isInteger(safeRecord.elapsed_ms) ? safeRecord.elapsed_ms : null,
    record_type: isNormalizedHistoryRecord(safeRecord) ? 'normalized_stdout_json' : 'cli_envelope',
    source_mode: typeof safeRecord.source_mode === 'string' ? safeRecord.source_mode : 'envelope',
    is_history_file: isHistoryFile,
    data: safeRecord,
  }
}

export function sanitizeHistoryRetentionSettings(settings) {
  const mode = settings?.historyRetentionMode === 'max-files'
    ? 'max-files'
    : DEFAULT_HISTORY_RETENTION_MODE
  const rawMax = Number.parseInt(String(settings?.maxHistoryFiles ?? DEFAULT_MAX_HISTORY_FILES), 10)
  const maxFiles = Number.isFinite(rawMax)
    ? Math.min(Math.max(rawMax, 1), MAX_HISTORY_FILES_HARD_CAP)
    : DEFAULT_MAX_HISTORY_FILES

  return {
    historyRetentionMode: mode,
    maxHistoryFiles: maxFiles,
  }
}

export async function ensureRunsDir() {
  await mkdir(RUNS_DIR, { baseDir: BaseDirectory.App, recursive: true })
}

export async function writeJsonSidecar(filename, obj) {
  await ensureRunsDir()
  const filePath = `${RUNS_DIR}/${filename}`
  await writeTextFile(filePath, JSON.stringify(obj, null, 2), { baseDir: BaseDirectory.App })
  return { filename, filePath }
}

export async function readJsonSidecar(filename) {
  try {
    const filePath = `${RUNS_DIR}/${filename}`
    if (!(await exists(filePath, { baseDir: BaseDirectory.App }))) return null
    const content = await readTextFile(filePath, { baseDir: BaseDirectory.App })
    return JSON.parse(content)
  } catch {
    return null
  }
}

export async function persistJobEnvelope(command, envelopeJson) {
  if (!envelopeJson || typeof envelopeJson !== 'object') return null

  await ensureRunsDir()

  const envelopeTimestamp = normalizeTimestamp(envelopeJson.timestamp_utc)
  const timestampPart = formatTimestampForFilename(envelopeTimestamp?.iso || Date.now())
  const commandPart = sanitizeCommand(command || envelopeJson.command)

  let filename = `${timestampPart}_${commandPart}.json`
  let suffix = 1

  // Defensive collision handling for repeated runs in the same millisecond.
  while (await exists(`${RUNS_DIR}/${filename}`, { baseDir: BaseDirectory.App })) {
    suffix += 1
    filename = `${timestampPart}_${commandPart}_${String(suffix).padStart(2, '0')}.json`
  }

  const filePath = `${RUNS_DIR}/${filename}`
  await writeTextFile(filePath, JSON.stringify(envelopeJson, null, 2), { baseDir: BaseDirectory.App })
  return { filename, filePath }
}

function pickRecordTimestamp(normalizedResult) {
  const data = normalizedResult?.data
  const fromData = normalizeTimestamp(data?.detection_timestamp_utc)
    || normalizeTimestamp(data?.timestamp_utc)
    || normalizeTimestamp(data?.generated_utc)
    || normalizeTimestamp(data?.occurred_utc)
  if (fromData) return fromData.iso
  return new Date().toISOString()
}

export function buildNormalizedHistoryRecord(command, args, normalizedResult) {
  if (!normalizedResult || typeof normalizedResult !== 'object') return null
  if (normalizedResult.mode !== 'stdout_json') return null
  if (normalizedResult.data === null || normalizedResult.data === undefined) return null

  const status = typeof normalizedResult.status === 'string' && normalizedResult.status
    ? normalizedResult.status
    : normalizedResult.ok
      ? 'ok'
      : 'error'

  return {
    history_format: NORMALIZED_HISTORY_FORMAT,
    source_mode: 'stdout_json',
    source_adapter: 'runGuiCommand',
    timestamp_utc: pickRecordTimestamp(normalizedResult),
    command: String(command || normalizedResult.command || 'unknown'),
    args: Array.isArray(args) ? args : [],
    status,
    exit_code: Number.isInteger(normalizedResult.exitCode) ? normalizedResult.exitCode : null,
    ok: Boolean(normalizedResult.ok),
    error: typeof normalizedResult.error === 'string' ? normalizedResult.error : null,
    warning: typeof normalizedResult.warning === 'string' ? normalizedResult.warning : null,
    data: normalizedResult.data,
    raw: {
      stdout: typeof normalizedResult.raw?.stdout === 'string' ? normalizedResult.raw.stdout : '',
      stderr: typeof normalizedResult.raw?.stderr === 'string' ? normalizedResult.raw.stderr : '',
    },
  }
}

export async function persistNormalizedStdoutJsonResult(command, args, normalizedResult) {
  const record = buildNormalizedHistoryRecord(command, args, normalizedResult)
  if (!record) return null
  return persistJobEnvelope(command, record)
}

export async function loadPersistedJobs() {
  try {
    await ensureRunsDir()
  } catch {
    // If directory creation fails for any reason, continue and let readDir surface error details.
  }

  const entries = await readDir(RUNS_DIR, { baseDir: BaseDirectory.App })
  const jsonFiles = entries.filter((entry) => {
    const name = entry?.name || ''
    return name.toLowerCase().endsWith('.json')
  })

  const jobs = []
  let malformedCount = 0
  let ignoredCount = 0

  await Promise.all(
    jsonFiles.map(async (file) => {
      if (!file?.name) return
      try {
        const content = await readTextFile(`${RUNS_DIR}/${file.name}`, { baseDir: BaseDirectory.App })
        const envelope = JSON.parse(content)
        const job = buildJob(envelope, file.name)
        if (job.is_history_file) {
          jobs.push(job)
        } else {
          ignoredCount += 1
        }
      } catch {
        malformedCount += 1
      }
    }),
  )

  jobs.sort((a, b) => {
    if (b.sort_epoch_ms !== a.sort_epoch_ms) {
      return b.sort_epoch_ms - a.sort_epoch_ms
    }
    return String(b.filename || '').localeCompare(String(a.filename || ''))
  })

  return { jobs, malformedCount, ignoredCount }
}

export async function prunePersistedHistory(settings) {
  const retention = sanitizeHistoryRetentionSettings(settings)
  const { jobs, malformedCount, ignoredCount } = await loadPersistedJobs()

  if (retention.historyRetentionMode !== 'max-files') {
    return {
      mode: retention.historyRetentionMode,
      maxFiles: retention.maxHistoryFiles,
      totalHistoryFiles: jobs.length,
      deletedCount: 0,
      keptCount: jobs.length,
      skippedCount: malformedCount + ignoredCount,
      warningCount: 0,
      warnings: [],
      deletedFiles: [],
    }
  }

  const candidates = jobs.filter((job) => job.is_history_file)
  if (candidates.length <= retention.maxHistoryFiles) {
    return {
      mode: retention.historyRetentionMode,
      maxFiles: retention.maxHistoryFiles,
      totalHistoryFiles: candidates.length,
      deletedCount: 0,
      keptCount: candidates.length,
      skippedCount: malformedCount + ignoredCount,
      warningCount: 0,
      warnings: [],
      deletedFiles: [],
    }
  }

  let filesToDelete = candidates.length - retention.maxHistoryFiles
  const newestByCommand = new Map()
  candidates.forEach((job) => {
    if (!newestByCommand.has(job.command)) {
      newestByCommand.set(job.command, job.filename)
    }
  })

  const oldestFirst = [...candidates].sort((a, b) => {
    if (a.sort_epoch_ms !== b.sort_epoch_ms) {
      return a.sort_epoch_ms - b.sort_epoch_ms
    }
    return String(a.filename || '').localeCompare(String(b.filename || ''))
  })

  const preferredDeletes = []
  const protectedOldest = []

  oldestFirst.forEach((job) => {
    if (newestByCommand.get(job.command) === job.filename) {
      protectedOldest.push(job)
    } else {
      preferredDeletes.push(job)
    }
  })

  const selectedDeletes = []
  for (const job of preferredDeletes) {
    if (filesToDelete <= 0) break
    selectedDeletes.push(job)
    filesToDelete -= 1
  }

  // If required, delete newest-per-command files only as a last resort.
  for (const job of protectedOldest) {
    if (filesToDelete <= 0) break
    selectedDeletes.push(job)
    filesToDelete -= 1
  }

  const warnings = []
  const deletedFiles = []

  for (const job of selectedDeletes) {
    try {
      await remove(`${RUNS_DIR}/${job.filename}`, { baseDir: BaseDirectory.App })
      deletedFiles.push(job.filename)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      warnings.push(`Failed to delete ${job.filename}: ${message}`)
    }
  }

  const deletedCount = deletedFiles.length
  const keptCount = candidates.length - deletedCount

  return {
    mode: retention.historyRetentionMode,
    maxFiles: retention.maxHistoryFiles,
    totalHistoryFiles: candidates.length,
    deletedCount,
    keptCount,
    skippedCount: malformedCount + ignoredCount,
    warningCount: warnings.length,
    warnings,
    deletedFiles,
  }
}
