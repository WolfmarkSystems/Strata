function parseTimestampToEpoch(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const normalized = trimmed.replace(/\.(\d{3})\d+(?=(Z|[+-]\d{2}:\d{2})$)/, '.$1');
  const parsed = Date.parse(normalized);
  return Number.isNaN(parsed) ? null : parsed;
}

function normalizeCommand(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeEntryCommands(entry) {
  const commands = [];
  const source = normalizeCommand(entry?.source);
  const type = normalizeCommand(entry?.type);

  if (source === 'activity' || source === 'evidence' || source === 'timeline') {
    commands.push('timeline');
  }
  if (source === 'violations' || source === 'violation' || type === 'violation') {
    commands.push('violations', 'timeline');
  }
  if (type === 'verification') commands.push('verify');
  if (type === 'triage') commands.push('triage-session');
  if (type === 'examination') commands.push('examine');
  if (type === 'evidence-check') commands.push('smoke-test');
  if (type === 'evidence-detection') commands.push('open-evidence');
  if (source && !commands.includes(source)) commands.push(source);

  return commands.filter(Boolean);
}

function jobTimestampEpoch(job) {
  if (typeof job?.sort_epoch_ms === 'number' && Number.isFinite(job.sort_epoch_ms)) {
    return job.sort_epoch_ms;
  }
  return parseTimestampToEpoch(job?.timestamp);
}

export function normalizeJobFilename(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.replace(/^[/\\]+/, '');
}

export function buildLogSelectionState(filename) {
  const normalized = normalizeJobFilename(filename);
  return normalized ? { selectJobFilename: normalized } : {};
}

export function findJobByFilename(jobs, filename) {
  const normalized = normalizeJobFilename(filename);
  if (!normalized || !Array.isArray(jobs)) return null;
  return jobs.find((job) => normalizeJobFilename(job?.filename) === normalized) || null;
}

export function findLatestJobFilename(jobs, command) {
  if (!Array.isArray(jobs)) return null;
  const normalizedCommand = normalizeCommand(command);
  const match = jobs.find((job) => normalizeCommand(job?.command) === normalizedCommand && normalizeJobFilename(job?.filename));
  return normalizeJobFilename(match?.filename);
}

export function buildLogSelectionStateForCommand(jobs, command) {
  const filename = findLatestJobFilename(jobs, command);
  return buildLogSelectionState(filename);
}

export function resolveTimelineEntryJobFilename(entry, jobs) {
  if (!Array.isArray(jobs) || jobs.length === 0) {
    return normalizeJobFilename(entry?.sourceJobFilename);
  }

  const linkedFilename = normalizeJobFilename(entry?.sourceJobFilename);
  if (linkedFilename && findJobByFilename(jobs, linkedFilename)) {
    return linkedFilename;
  }

  const preferredCommands = normalizeEntryCommands(entry);
  const targetEpoch = parseTimestampToEpoch(entry?.timestamp);
  const candidates = jobs.filter((job) => normalizeJobFilename(job?.filename));

  const scoped = preferredCommands.length > 0
    ? candidates.filter((job) => preferredCommands.includes(normalizeCommand(job?.command)))
    : candidates;
  const candidatePool = scoped.length > 0 ? scoped : candidates;
  if (candidatePool.length === 0) return linkedFilename;

  const ranked = [...candidatePool].sort((left, right) => {
    const leftCommandIndex = preferredCommands.indexOf(normalizeCommand(left?.command));
    const rightCommandIndex = preferredCommands.indexOf(normalizeCommand(right?.command));
    const leftPriority = leftCommandIndex === -1 ? Number.MAX_SAFE_INTEGER : leftCommandIndex;
    const rightPriority = rightCommandIndex === -1 ? Number.MAX_SAFE_INTEGER : rightCommandIndex;
    if (leftPriority !== rightPriority) return leftPriority - rightPriority;

    if (targetEpoch !== null) {
      const leftDelta = Math.abs((jobTimestampEpoch(left) ?? targetEpoch) - targetEpoch);
      const rightDelta = Math.abs((jobTimestampEpoch(right) ?? targetEpoch) - targetEpoch);
      if (leftDelta !== rightDelta) return leftDelta - rightDelta;
    }

    return (jobTimestampEpoch(right) || 0) - (jobTimestampEpoch(left) || 0);
  });

  return normalizeJobFilename(ranked[0]?.filename) || linkedFilename;
}
