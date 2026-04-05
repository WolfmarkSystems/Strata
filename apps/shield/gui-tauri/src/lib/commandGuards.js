function asNonEmptyString(value) {
  if (typeof value !== 'string') return '';
  return value.trim();
}

export function getRunningGuardReason(isRunning, activeCommand = '') {
  if (!isRunning) return '';
  const command = asNonEmptyString(activeCommand);
  return command
    ? `Command '${command}' is currently running.`
    : 'A command is currently running.';
}

export function getCaseContextGuardReason(caseId, caseDbPath) {
  const hasCaseId = Boolean(asNonEmptyString(caseId));
  const hasDbPath = Boolean(asNonEmptyString(caseDbPath));
  if (hasCaseId && hasDbPath) return '';
  return 'Requires both Case ID and DB path.';
}

export function getEvidenceGuardReason(evidencePath) {
  if (Boolean(asNonEmptyString(evidencePath))) return '';
  return 'Requires a selected evidence path.';
}

export function getCommandDisabledReason({
  isRunning = false,
  activeCommand = '',
  requiresCaseContext = false,
  caseId = '',
  caseDbPath = '',
  requiresEvidence = false,
  evidencePath = '',
  extraReason = '',
} = {}) {
  const runningReason = getRunningGuardReason(isRunning, activeCommand);
  if (runningReason) return runningReason;

  if (requiresCaseContext) {
    const caseReason = getCaseContextGuardReason(caseId, caseDbPath);
    if (caseReason) return caseReason;
  }

  if (requiresEvidence) {
    const evidenceReason = getEvidenceGuardReason(evidencePath);
    if (evidenceReason) return evidenceReason;
  }

  return asNonEmptyString(extraReason);
}
