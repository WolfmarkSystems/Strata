const TIMESTAMP_FORMATTER = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});

function parseDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

export function formatLocalTimestamp(value, fallback = 'N/A') {
  const date = parseDate(value);
  if (!date) return value ? String(value) : fallback;
  return TIMESTAMP_FORMATTER.format(date);
}

export function formatRelativeTime(value, nowValue = Date.now()) {
  const date = parseDate(value);
  const now = parseDate(nowValue);
  if (!date || !now) return 'N/A';

  const deltaMs = date.getTime() - now.getTime();
  const absMs = Math.abs(deltaMs);
  const isFuture = deltaMs > 0;

  if (absMs < 30 * 1000) return 'just now';

  const units = [
    { label: 'day', ms: 24 * 60 * 60 * 1000 },
    { label: 'hour', ms: 60 * 60 * 1000 },
    { label: 'minute', ms: 60 * 1000 },
    { label: 'second', ms: 1000 },
  ];

  for (const unit of units) {
    const count = Math.floor(absMs / unit.ms);
    if (count >= 1) {
      const suffix = count === 1 ? unit.label : `${unit.label}s`;
      return isFuture ? `in ${count} ${suffix}` : `${count} ${suffix} ago`;
    }
  }

  return 'just now';
}

export function formatUtcIsoSeconds(value) {
  const date = parseDate(value);
  if (!date) return '';
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
