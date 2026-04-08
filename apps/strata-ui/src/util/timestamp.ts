/**
 * Timestamp format detection and conversion.
 *
 * Supported formats:
 *   - `unix_s`          Unix seconds (1970 epoch)
 *   - `unix_ms`         Unix milliseconds
 *   - `unix_us`         Unix microseconds
 *   - `mac_absolute`    Core Data seconds since 2001-01-01
 *   - `chrome`          Webkit / Chrome microseconds since 1601-01-01
 *   - `windows_filetime` 100-ns ticks since 1601-01-01
 *   - `auto`            Auto-detect based on value magnitude
 */

export type TimestampFormat =
  | 'auto'
  | 'unix_s'
  | 'unix_ms'
  | 'unix_us'
  | 'mac_absolute'
  | 'chrome'
  | 'windows_filetime'

export interface ConversionResult {
  ok: boolean
  /** The detected / chosen format that was actually used to convert. */
  format: TimestampFormat
  /** ISO-8601 formatted UTC string (`2026-04-06T14:22:00.000Z`). */
  iso: string
  /** Human-friendly UTC string (`Mon, 06 Apr 2026 14:22:00 GMT`). */
  pretty: string
  /** Unix seconds equivalent (for cross-comparison). */
  unixSeconds: number
  /** Explanatory message shown to the user. */
  message: string
}

/**
 * Convert a raw timestamp string/number into a human readable UTC datetime.
 *
 * `auto` mode uses value-magnitude heuristics:
 *   - > 1e17  → Windows FILETIME (100ns ticks since 1601)
 *   - > 1e16  → Chrome microseconds (since 1601)
 *   - > 1e15  → generic microseconds (since 1970)
 *   - > 1e12  → milliseconds (since 1970)
 *   - 5e8..9e8 → Mac Absolute (seconds since 2001)
 *   - 1e9..2e9 → Unix seconds (2001-2033)
 *   - else    → treat as Unix seconds (may be out of range)
 */
export function convertTimestamp(raw: string, format: TimestampFormat = 'auto'): ConversionResult {
  const trimmed = raw.trim()
  const invalid = (msg: string): ConversionResult => ({
    ok: false,
    format,
    iso: '',
    pretty: '',
    unixSeconds: 0,
    message: msg,
  })

  if (trimmed.length === 0) return invalid('Empty input')

  // Try to parse as number (support scientific notation + floats).
  const asNumber = Number(trimmed)
  if (!Number.isFinite(asNumber)) return invalid('Not a number')
  if (asNumber < 0) return invalid('Negative value')

  let unixSeconds: number
  let chosen: TimestampFormat = format

  if (format === 'auto') {
    const v = asNumber
    if (v > 1e17) {
      chosen = 'windows_filetime'
      unixSeconds = v / 1e7 - 11_644_473_600
    } else if (v > 1e16) {
      chosen = 'chrome'
      unixSeconds = v / 1e6 - 11_644_473_600
    } else if (v > 1e15) {
      chosen = 'unix_us'
      unixSeconds = v / 1e6
    } else if (v > 1e12) {
      chosen = 'unix_ms'
      unixSeconds = v / 1e3
    } else if (v >= 5e8 && v < 9e8) {
      // Mac Absolute range — 2016..2029 ish
      chosen = 'mac_absolute'
      unixSeconds = v + 978_307_200
    } else if (v >= 1e9 && v < 2e9) {
      chosen = 'unix_s'
      unixSeconds = v
    } else {
      chosen = 'unix_s'
      unixSeconds = v
    }
  } else {
    switch (format) {
      case 'unix_s':
        unixSeconds = asNumber
        break
      case 'unix_ms':
        unixSeconds = asNumber / 1_000
        break
      case 'unix_us':
        unixSeconds = asNumber / 1_000_000
        break
      case 'mac_absolute':
        unixSeconds = asNumber + 978_307_200
        break
      case 'chrome':
        unixSeconds = asNumber / 1_000_000 - 11_644_473_600
        break
      case 'windows_filetime':
        unixSeconds = asNumber / 10_000_000 - 11_644_473_600
        break
      default:
        unixSeconds = asNumber
    }
  }

  const date = new Date(unixSeconds * 1000)
  if (isNaN(date.getTime())) return invalid('Out of range for JavaScript Date')
  // JS Date supports ~ ±100,000,000 days from epoch — check practical bounds.
  if (unixSeconds < -62_135_596_800 || unixSeconds > 253_402_300_799) {
    return invalid('Out of range (date before year 1 or after 9999)')
  }

  const iso = date.toISOString()
  const pretty = date.toUTCString()

  return {
    ok: true,
    format: chosen,
    iso,
    pretty,
    unixSeconds,
    message: formatLabel(chosen),
  }
}

export function formatLabel(format: TimestampFormat): string {
  switch (format) {
    case 'unix_s':
      return 'Unix seconds'
    case 'unix_ms':
      return 'Unix milliseconds'
    case 'unix_us':
      return 'Unix microseconds'
    case 'mac_absolute':
      return 'Mac Absolute (Cocoa epoch)'
    case 'chrome':
      return 'Chrome / Webkit time'
    case 'windows_filetime':
      return 'Windows FILETIME'
    case 'auto':
      return 'Auto-detect'
  }
}

/** Short badge label for the column-header format chip. */
export function formatBadge(format: string | null | undefined): string {
  if (!format) return ''
  switch (format) {
    case 'unix_s':
      return 'UNIX'
    case 'unix_ms':
      return 'MS'
    case 'unix_us':
      return 'US'
    case 'mac_absolute':
      return 'MAC'
    case 'chrome':
      return 'CHROME'
    case 'windows_filetime':
      return 'FILETIME'
    case 'auto':
      return 'AUTO'
    default:
      return format.toUpperCase()
  }
}
