function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function normalizeStatus(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'ok' || value === 'pass' || value === 'success') return 'ok';
  if (value === 'warn' || value === 'warning') return 'warn';
  if (value === 'error' || value === 'fail' || value === 'failed' || value === 'missing') return 'error';
  return 'info';
}

function latestJob(jobs, command) {
  return jobs.find((job) => job.command === command) || null;
}

function getViolationsCount(violationsJob) {
  const data = asObject(violationsJob?.data?.data);
  if (!data) return 0;
  if (typeof data.total_returned === 'number') return data.total_returned;
  if (Array.isArray(data.violations)) return data.violations.length;
  return 0;
}

function smokeIsActionable(smokeJob) {
  if (!smokeJob) return false;
  const status = normalizeStatus(smokeJob.status);
  if (status === 'ok' || status === 'warn') return true;
  const smokeData = asObject(smokeJob?.data?.data);
  return smokeData?.analysis_mode === 'container_only';
}

function stepState(isComplete) {
  return isComplete ? 'complete' : 'pending';
}

export function deriveWorkflowState({ caseId, caseDbPath, evidencePath, jobs = [] }) {
  const safeJobs = Array.isArray(jobs) ? jobs : [];
  const hasCaseContext = Boolean(String(caseId || '').trim() && String(caseDbPath || '').trim());
  const hasEvidenceContext = Boolean(String(evidencePath || '').trim());

  const smoke = latestJob(safeJobs, 'smoke-test');
  const examine = latestJob(safeJobs, 'examine');
  const verify = latestJob(safeJobs, 'verify');
  const triage = latestJob(safeJobs, 'triage-session');
  const violations = latestJob(safeJobs, 'violations');

  return {
    hasCaseContext,
    hasEvidenceContext,
    smoke,
    smokeActionable: smokeIsActionable(smoke),
    examine,
    verify,
    triage,
    violations,
    violationsCount: getViolationsCount(violations),
  };
}

export function buildWorkflowRunbookSteps(state) {
  const steps = [
    {
      id: 'evidence',
      title: 'Evidence Selected',
      detail: state.hasEvidenceContext ? 'Evidence context is available.' : 'Select evidence in Evidence Sources.',
      state: stepState(state.hasEvidenceContext),
    },
    {
      id: 'case',
      title: 'Case Context Set',
      detail: state.hasCaseContext ? 'Case ID and DB path are set.' : 'Set Case ID and DB path in Case Overview.',
      state: stepState(state.hasCaseContext),
    },
    {
      id: 'smoke',
      title: 'Smoke Tested',
      detail: state.smoke ? 'Smoke-test result is available.' : 'Run smoke-test to baseline evidence readiness.',
      state: stepState(Boolean(state.smoke)),
    },
    {
      id: 'examine',
      title: 'Examined',
      detail: state.examine ? 'Examine result is available.' : 'Run examine for session outputs.',
      state: stepState(Boolean(state.examine)),
    },
    {
      id: 'verify',
      title: 'Verified',
      detail: state.verify ? 'Verify result is available.' : 'Run verify to validate case state.',
      state: stepState(Boolean(state.verify)),
    },
    {
      id: 'triage',
      title: 'Triaged',
      detail: state.triage ? 'Triage-session result is available.' : 'Run triage-session for bundle/session packaging.',
      state: stepState(Boolean(state.triage)),
    },
  ];

  let nextAction = {
    id: 'open-logs',
    label: 'Open Logs',
    detail: 'Review the latest envelopes and outputs in Logs.',
  };

  if (!state.hasEvidenceContext) {
    nextAction = {
      id: 'go-evidence',
      label: 'Go to Evidence Sources',
      detail: 'Select an evidence source first.',
    };
  } else if (!state.hasCaseContext) {
    nextAction = {
      id: 'go-case',
      label: 'Go to Case Overview',
      detail: 'Set case context before case-level commands.',
    };
  } else if (!state.smoke) {
    nextAction = {
      id: 'run-smoke',
      label: 'Run Smoke Test',
      detail: 'Run smoke-test now to establish evidence readiness.',
    };
  } else if (!state.examine) {
    nextAction = {
      id: 'run-examine',
      label: 'Run Examine',
      detail: 'Run examine to generate case/session outputs.',
    };
  } else if (!state.verify) {
    nextAction = {
      id: 'run-verify',
      label: 'Run Verify',
      detail: 'Run verify to validate case consistency.',
    };
  } else if (!state.triage) {
    nextAction = {
      id: 'run-triage',
      label: 'Run Triage',
      detail: 'Run triage-session for defensibility bundle output.',
    };
  } else if (state.violationsCount > 0) {
    nextAction = {
      id: 'review-violations',
      label: 'Review Violations',
      detail: `${state.violationsCount} violation(s) returned in latest violations result.`,
    };
  }

  return { steps, nextAction };
}
