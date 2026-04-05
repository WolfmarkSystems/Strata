import { invoke } from '@tauri-apps/api/core'

export const COMMAND_OUTPUT_MODES = Object.freeze({
  capabilities: 'envelope',
  doctor: 'envelope',
  'smoke-test': 'envelope',
  verify: 'envelope',
  'triage-session': 'envelope',
  examine: 'envelope',
  watchpoints: 'envelope',
  violations: 'envelope',
  timeline: 'envelope',
  artifacts: 'envelope',
  hashset: 'envelope',
  'registry-persistence': 'envelope',
  'execution-correlation': 'envelope',
  'recent-execution': 'envelope',
  'macos-catalog': 'envelope',
  // These commands may print plain-text errors in some failure paths.
  'open-evidence': 'stdout_json',
  filetable: 'stdout_json',
  search: 'stdout_json',
  strings: 'stdout_json',
})

function getOutputMode(command) {
  return COMMAND_OUTPUT_MODES[command] || 'stdout_text'
}

function inferStatusFromExitCode(exitCode) {
  if (exitCode === null || exitCode === undefined) return null
  return exitCode === 0 ? 'ok' : 'error'
}

function trimToNull(value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function buildRaw(result) {
  return {
    stdout: typeof result?.stdout === 'string' ? result.stdout : '',
    stderr: typeof result?.stderr === 'string' ? result.stderr : '',
    envelopeJson: result?.envelope_json ?? null,
    jsonPath: result?.json_path ?? null,
  }
}

export async function runGuiCommand(command, args = []) {
  const configuredMode = getOutputMode(command)

  try {
    const result = await invoke('run_cli', { args: [command, ...args] })
    const raw = buildRaw(result)
    const exitCode = Number.isInteger(result?.exit_code) ? result.exit_code : null

    if (raw.envelopeJson) {
      const envelope = raw.envelopeJson
      const status = typeof envelope.status === 'string' ? envelope.status : inferStatusFromExitCode(exitCode)
      const error = envelope.error ?? null
      const warning = envelope.warning ?? null
      const ok = exitCode === 0 && status !== 'error' && !error

      return {
        ok,
        command,
        mode: 'envelope',
        exitCode,
        status,
        data: envelope.data ?? null,
        error: error || (!ok ? trimToNull(raw.stderr) : null),
        warning,
        raw,
      }
    }

    if (configuredMode === 'stdout_json') {
      if (!raw.stdout.trim()) {
        return {
          ok: false,
          command,
          mode: 'stdout_json',
          exitCode,
          status: inferStatusFromExitCode(exitCode),
          data: null,
          error: trimToNull(raw.stderr) || `Command '${command}' returned no JSON on stdout.`,
          warning: null,
          raw,
        }
      }

      try {
        const parsed = JSON.parse(raw.stdout)
        const status = typeof parsed?.status === 'string' ? parsed.status : inferStatusFromExitCode(exitCode)
        const parsedError = typeof parsed?.error === 'string' ? parsed.error : null
        const warning = typeof parsed?.warning === 'string' ? parsed.warning : null
        const ok = exitCode === 0 && status !== 'error' && !parsedError

        return {
          ok,
          command,
          mode: 'stdout_json',
          exitCode,
          status,
          data: parsed,
          error: parsedError || (!ok ? trimToNull(raw.stderr) : null),
          warning,
          raw,
        }
      } catch (error) {
        const parseMessage = error instanceof Error ? error.message : String(error)
        return {
          ok: false,
          command,
          mode: 'stdout_json',
          exitCode,
          status: inferStatusFromExitCode(exitCode),
          data: null,
          error: `Failed to parse JSON stdout for '${command}': ${parseMessage}`,
          warning: null,
          raw,
        }
      }
    }

    const status = inferStatusFromExitCode(exitCode)
    const ok = exitCode === 0
    return {
      ok,
      command,
      mode: 'stdout_text',
      exitCode,
      status,
      data: raw.stdout,
      error: ok ? null : trimToNull(raw.stderr) || `Command '${command}' failed.`,
      warning: null,
      raw,
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return {
      ok: false,
      command,
      mode: configuredMode,
      exitCode: null,
      status: 'error',
      data: null,
      error: `Failed to invoke run_cli for '${command}': ${message}`,
      warning: null,
      raw: {
        stdout: '',
        stderr: message,
        envelopeJson: null,
        jsonPath: null,
      },
    }
  }
}
