import { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import CaseManager from '../components/CaseManager';
import { formatLocalTimestamp, formatRelativeTime } from '../lib/timeFormat';
import { getCommandDisabledReason } from '../lib/commandGuards';
import { buildLogSelectionState } from '../lib/logLinks';

function normalizeStatus(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'ok' || value === 'pass' || value === 'success') return 'ok';
  if (value === 'warn' || value === 'warning') return 'warn';
  if (value === 'error' || value === 'fail' || value === 'failed' || value === 'missing') return 'error';
  return 'warn';
}

function getCommandData(job) {
  const data = job?.data?.data;
  return data && typeof data === 'object' && !Array.isArray(data) ? data : null;
}

function summarizeVerify(job) {
  const data = getCommandData(job);
  if (!job || !data) return null;

  const checks = Array.isArray(data.checks) ? data.checks : [];
  const warnChecks = checks.filter((check) => String(check?.status || '').toLowerCase() === 'warn').length;
  const failChecks = checks.filter((check) => {
    const status = String(check?.status || '').toLowerCase();
    return status === 'fail' || status === 'error' || status === 'missing';
  }).length;

  return {
    status: data.status || job.status || null,
    checksCount: checks.length,
    warnChecks,
    failChecks,
    stats: data.stats && typeof data.stats === 'object' ? data.stats : null,
    warning: job?.data?.warning || null,
    error: job?.data?.error || null,
  };
}

function summarizeTriage(job) {
  const data = getCommandData(job);
  if (!job || !data) return null;
  const result = data.result && typeof data.result === 'object' ? data.result : null;
  return {
    status: result?.status || job.status || null,
    stepsRun: Array.isArray(data.steps_run) ? data.steps_run : [],
    violationsCount: result?.violations_count ?? null,
    sessionId: result?.session_id || null,
    replayId: result?.replay_id || null,
    verificationId: result?.verification_id || null,
    bundlePath: result?.bundle_path || null,
    bundleHash: result?.bundle_hash_sha256 || null,
    warning: job?.data?.warning || null,
    error: job?.data?.error || null,
  };
}

function summarizeExamine(job) {
  const data = getCommandData(job);
  if (!job || !data) return null;
  const result = data.result && typeof data.result === 'object' ? data.result : null;
  return {
    presetName: data.preset_name || null,
    status: result?.status || job.status || null,
    sessionId: result?.session_id || null,
    violationsCount: result?.violations_count ?? null,
    bundlePath: result?.bundle_path || job?.data?.outputs?.bundle_zip || null,
    bundleHash: result?.bundle_hash_sha256 || null,
    warning: job?.data?.warning || null,
    error: job?.data?.error || null,
  };
}

function summarizeWatchpoints(job) {
  const data = getCommandData(job);
  if (!job || !data) return null;
  return {
    action: data.action || null,
    enabled: typeof data.watchpoints_enabled === 'boolean' ? data.watchpoints_enabled : null,
    violationCount: data.integrity_violation_count ?? null,
    warning: job?.data?.warning || null,
    error: job?.data?.error || null,
  };
}

function summarizeViolations(job) {
  const data = getCommandData(job);
  if (!job || !data) return null;
  const list = Array.isArray(data.violations) ? data.violations : [];
  const latestTimestamp = list
    .map((item) => item?.occurred_utc)
    .filter(Boolean)
    .reduce((latest, current) => (new Date(current) > new Date(latest) ? current : latest), null);

  return {
    totalReturned: data.total_returned ?? list.length,
    sinceUtc: data.since_utc || null,
    limit: data.limit ?? null,
    latestTimestamp,
    warning: job?.data?.warning || null,
    error: job?.data?.error || null,
  };
}

function pickLatestUtc(values) {
  return values
    .filter((value) => typeof value === 'string' && value.trim())
    .reduce((latest, current) => {
      if (!latest) return current;
      return new Date(current) > new Date(latest) ? current : latest;
    }, null);
}

function summarizeExecution(job) {
  const data = getCommandData(job);
  if (!job || !data) return null;
  const correlations = Array.isArray(data.correlations) ? data.correlations : [];
  const top = correlations[0] && typeof correlations[0] === 'object' ? correlations[0] : null;
  const latestSeen = pickLatestUtc(correlations.map((row) => row?.last_seen_utc));
  return {
    status: job.status || null,
    totalReturned: data.total_returned ?? correlations.length,
    totalAvailable: data.total_available ?? null,
    sourceRows: data.source_rows && typeof data.source_rows === 'object' ? data.source_rows : null,
    topExecutable: top?.executable_name || null,
    topSources: Array.isArray(top?.sources) ? top.sources : [],
    latestSeenUtc: latestSeen,
    warning: job?.data?.warning || null,
    error: job?.data?.error || null,
  };
}

function summarizePersistence(job) {
  const data = getCommandData(job);
  if (!job || !data) return null;
  const correlations = Array.isArray(data.correlations) ? data.correlations : [];
  const highConfidence = correlations.filter((row) => String(row?.overall_confidence || '').toLowerCase() === 'high').length;
  const mediumConfidence = correlations.filter((row) => String(row?.overall_confidence || '').toLowerCase() === 'medium').length;
  const latestExecution = pickLatestUtc(correlations.map((row) => row?.latest_execution_utc));
  return {
    status: job.status || null,
    totalReturned: data.total_returned ?? correlations.length,
    totalAvailable: data.total_available ?? null,
    sourceRows: data.source_rows && typeof data.source_rows === 'object' ? data.source_rows : null,
    highConfidence,
    mediumConfidence,
    latestExecutionUtc: latestExecution,
    warning: job?.data?.warning || null,
    error: job?.data?.error || null,
  };
}

function summarizeJobStatus(job) {
  if (!job) return { label: 'not run', className: 'status-info' };
  const normalized = normalizeStatus(job.status);
  if (normalized === 'ok') return { label: 'ok', className: 'status-ok' };
  if (normalized === 'warn') return { label: 'warn', className: 'status-warn' };
  return { label: 'error', className: 'status-error' };
}

function CaseOverview({
  caseId,
  caseDbPath,
  evidencePath,
  isCaseRestoredFromSession = false,
  defaultExaminePreset = 'Fast Triage',
  jobs,
  onCaseChange,
  onRunCommand,
  isRunning,
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [activeTab, setActiveTab] = useState('info');

  const caseJobs = jobs.filter((job) =>
    job.command === 'verify'
    || job.command === 'triage-session'
    || job.command === 'examine'
    || job.command === 'watchpoints'
    || job.command === 'violations'
  );
  const persistenceJobs = jobs.filter((job) => job.command === 'registry-persistence');
  const executionJobs = jobs.filter((job) => job.command === 'recent-execution' || job.command === 'execution-correlation');
  const overviewJobs = jobs.filter((job) =>
    caseJobs.includes(job)
    || job.command === 'registry-persistence'
    || job.command === 'recent-execution'
    || job.command === 'execution-correlation'
  );

  const lastVerify = caseJobs.find((job) => job.command === 'verify');
  const lastTriage = caseJobs.find((job) => job.command === 'triage-session');
  const lastExamine = caseJobs.find((job) => job.command === 'examine');
  const lastWatchpoints = caseJobs.find((job) => job.command === 'watchpoints');
  const lastViolations = caseJobs.find((job) => job.command === 'violations');
  const lastPersistence = persistenceJobs[0] || null;
  const lastExecution = executionJobs[0] || null;

  const verifySummary = summarizeVerify(lastVerify);
  const triageSummary = summarizeTriage(lastTriage);
  const examineSummary = summarizeExamine(lastExamine);
  const watchpointsSummary = summarizeWatchpoints(lastWatchpoints);
  const violationsSummary = summarizeViolations(lastViolations);
  const persistenceSummary = summarizePersistence(lastPersistence);
  const executionSummary = summarizeExecution(lastExecution);
  const hasCaseContext = Boolean(caseId && caseDbPath);
  const latestBundlePath = triageSummary?.bundlePath || examineSummary?.bundlePath || null;
  const latestBundleHash = triageSummary?.bundleHash || examineSummary?.bundleHash || null;
  const verifyStatus = summarizeJobStatus(lastVerify);
  const triageStatus = summarizeJobStatus(lastTriage);
  const examineStatus = summarizeJobStatus(lastExamine);
  const watchpointsStatus = summarizeJobStatus(lastWatchpoints);
  const violationsStatus = summarizeJobStatus(lastViolations);
  const persistenceStatus = summarizeJobStatus(lastPersistence);
  const executionStatus = summarizeJobStatus(lastExecution);
  const caseCommandDisabledReason = getCommandDisabledReason({
    isRunning,
    requiresCaseContext: true,
    caseId,
    caseDbPath,
  });
  const rollupCommandDisabledReason = getCommandDisabledReason({ isRunning });
  const latestBundleJobFilename = lastTriage?.filename || lastExamine?.filename || null;
  const latestCaseJob = overviewJobs[0] || null;
  const openJobInLogs = (job) => {
    const state = buildLogSelectionState(job?.filename);
    if (!state.selectJobFilename) return;
    navigate('/logs', { state });
  };

  useEffect(() => {
    const requestedTab = location?.state?.focusTab;
    if (requestedTab === 'verify' || requestedTab === 'triage' || requestedTab === 'examine' || requestedTab === 'watchpoints' || requestedTab === 'violations' || requestedTab === 'info') {
      setActiveTab(requestedTab);
    }
  }, [location?.state?.focusTab]);

  const followUpSuggestions = useMemo(() => {
    const suggestions = [];

    if (!evidencePath) {
      suggestions.push({
        id: 'select-evidence',
        title: 'Select evidence source',
        detail: 'Evidence context is missing for end-to-end workflow continuity.',
        actionLabel: 'Go to Evidence Sources',
        action: () => navigate('/evidence'),
      });
    }

    if (hasCaseContext && !lastVerify) {
      suggestions.push({
        id: 'run-verify',
        title: 'Run Verify',
        detail: 'No verify result is available yet for this case.',
        actionLabel: 'Verify Case',
        action: () => onRunCommand('verify', ['--case', caseId, '--db', caseDbPath]),
        disabledReason: caseCommandDisabledReason,
      });
    }

    if (hasCaseContext && !lastExamine) {
      suggestions.push({
        id: 'run-examine',
        title: 'Run Examine',
        detail: 'No examine result is available yet for this case context.',
        actionLabel: 'Run Examine',
        action: () => onRunCommand('examine', ['--case', caseId, '--db', caseDbPath, '--preset', defaultExaminePreset || 'Fast Triage']),
        disabledReason: caseCommandDisabledReason,
      });
    }

    if (hasCaseContext && lastExamine && !lastTriage) {
      suggestions.push({
        id: 'run-triage',
        title: 'Run Triage Session',
        detail: 'Triage-session result is missing. Run triage to generate bundle/session outputs.',
        actionLabel: 'Run Triage',
        action: () => onRunCommand('triage-session', ['--case', caseId, '--db', caseDbPath]),
        disabledReason: caseCommandDisabledReason,
      });
    }

    if (violationsSummary && violationsSummary.totalReturned > 0) {
      suggestions.push({
        id: 'review-violations',
        title: 'Review Integrity Violations',
        detail: `${violationsSummary.totalReturned} violation(s) were returned in the latest result.`,
        actionLabel: 'Open Violations Tab',
        action: () => setActiveTab('violations'),
      });
    }

    if (watchpointsSummary && watchpointsSummary.enabled === false && hasCaseContext) {
      suggestions.push({
        id: 'enable-watchpoints',
        title: 'Enable Watchpoints',
        detail: 'Watchpoints are currently disabled for this case context.',
        actionLabel: 'Enable Watchpoints',
        action: () => onRunCommand('watchpoints', ['--case', caseId, '--db', caseDbPath, '--enable']),
        disabledReason: caseCommandDisabledReason,
      });
    }

    if (!lastExecution) {
      suggestions.push({
        id: 'run-recent-execution',
        title: 'Run Recent Execution Correlation',
        detail: 'No recent execution correlation result is available yet.',
        actionLabel: 'Run Recent Execution',
        action: () => onRunCommand('recent-execution', ['--limit', '200']),
        disabledReason: getCommandDisabledReason({ isRunning }),
      });
    }

    if (!lastPersistence) {
      suggestions.push({
        id: 'run-registry-persistence',
        title: 'Run Registry Persistence Correlation',
        detail: 'No registry persistence rollup is available yet.',
        actionLabel: 'Run Persistence',
        action: () => onRunCommand('registry-persistence', ['--limit', '200']),
        disabledReason: getCommandDisabledReason({ isRunning }),
      });
    }

    if (persistenceSummary?.highConfidence > 0) {
      suggestions.push({
        id: 'review-high-confidence-persistence',
        title: 'Review High Confidence Persistence Signals',
        detail: `${persistenceSummary.highConfidence} high-confidence persistence correlation(s) detected.`,
        actionLabel: 'Open Logs',
        action: () => navigate('/logs'),
      });
    }

    suggestions.push({
      id: 'open-logs',
      title: 'Review Logs',
      detail: 'Inspect full command envelopes, warnings, and output paths.',
      actionLabel: 'Open Logs',
      action: () => navigate('/logs'),
    });

    return suggestions;
  }, [
    evidencePath,
    hasCaseContext,
    lastVerify,
    lastExamine,
    lastTriage,
    violationsSummary,
    watchpointsSummary,
    lastExecution,
    lastPersistence,
    persistenceSummary,
    isRunning,
    navigate,
    onRunCommand,
    caseId,
    caseDbPath,
    defaultExaminePreset,
    caseCommandDisabledReason,
  ]);

  return (
    <div className="page case-overview">
      <header className="page-header">
        <h1>Case Overview</h1>
        <p className="page-subtitle">Manage case context and review case-level command results.</p>
      </header>

      <div className="case-layout">
        <section className="panel full-width workflow-strip">
          <h2>Workflow Status</h2>
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">Case Selected</span>
              <span className={`status-badge ${hasCaseContext ? 'status-ok' : 'status-info'}`}>
                {hasCaseContext ? 'yes' : 'no'}
              </span>
            </div>
            <div className="info-item">
              <span className="info-label">Evidence Selected</span>
              <span className={`status-badge ${evidencePath ? 'status-ok' : 'status-info'}`}>
                {evidencePath ? 'yes' : 'no'}
              </span>
            </div>
            <div className="info-item">
              <span className="info-label">Verify</span>
              <span className={`status-badge ${verifyStatus.className}`}>{verifyStatus.label}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Examine</span>
              <span className={`status-badge ${examineStatus.className}`}>{examineStatus.label}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Triage</span>
              <span className={`status-badge ${triageStatus.className}`}>{triageStatus.label}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Watchpoints</span>
              <span className={`status-badge ${watchpointsStatus.className}`}>{watchpointsStatus.label}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Violations</span>
              <span className={`status-badge ${violationsStatus.className}`}>{violationsStatus.label}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Persistence</span>
              <span className={`status-badge ${persistenceStatus.className}`}>{persistenceStatus.label}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Execution</span>
              <span className={`status-badge ${executionStatus.className}`}>{executionStatus.label}</span>
            </div>
          </div>
          <div className="analysis-actions">
            <button className="btn btn-secondary" onClick={() => navigate('/evidence')}>
              Go to Evidence Sources
            </button>
            <button className="btn btn-secondary" onClick={() => navigate('/logs')}>
              Open Logs
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => openJobInLogs(latestCaseJob)}
              disabled={!latestCaseJob?.filename}
              title={latestCaseJob?.filename ? 'Open latest case command result in Logs.' : 'No case command result file yet.'}
            >
              Open Latest Case Job In Logs
            </button>
          </div>
        </section>

        <section className="panel case-config-panel">
          <h2>Case Configuration</h2>
          <CaseManager
            caseId={caseId}
            caseDbPath={caseDbPath}
            isCaseRestoredFromSession={isCaseRestoredFromSession}
            onCaseChange={onCaseChange}
          />
        </section>

        {caseId && (
          <>
            <section className="panel full-width">
              <h2>Recommended Follow-Ups</h2>
              <div className="outputs-preview">
                {followUpSuggestions.map((suggestion) => (
                  <div key={suggestion.id} className="output-row">
                    <div>
                      <div className="info-value">{suggestion.title}</div>
                      <div className="setting-description">{suggestion.detail}</div>
                    </div>
                    <button
                      className="btn btn-secondary btn-small"
                      onClick={suggestion.action}
                      disabled={Boolean(suggestion.disabledReason)}
                      title={suggestion.disabledReason || ''}
                    >
                      {suggestion.actionLabel}
                    </button>
                  </div>
                ))}
              </div>
            </section>

            <section className="panel full-width">
              <h2>Persistence &amp; Execution Rollups</h2>
              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">Latest Persistence</span>
                  <span className="info-value">
                    {lastPersistence
                      ? `${formatLocalTimestamp(lastPersistence.timestamp)} (${formatRelativeTime(lastPersistence.timestamp)})`
                      : 'No registry-persistence result yet'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Latest Execution</span>
                  <span className="info-value">
                    {lastExecution
                      ? `${formatLocalTimestamp(lastExecution.timestamp)} (${formatRelativeTime(lastExecution.timestamp)})`
                      : 'No recent-execution result yet'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Persistence Returned</span>
                  <span className="info-value">
                    {typeof persistenceSummary?.totalReturned === 'number' ? persistenceSummary.totalReturned : 'N/A'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Execution Returned</span>
                  <span className="info-value">
                    {typeof executionSummary?.totalReturned === 'number' ? executionSummary.totalReturned : 'N/A'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">High Confidence Persistence</span>
                  <span className="info-value">
                    {typeof persistenceSummary?.highConfidence === 'number' ? persistenceSummary.highConfidence : 'N/A'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Latest Execution Seen</span>
                  <span className="info-value">
                    {executionSummary?.latestSeenUtc ? formatLocalTimestamp(executionSummary.latestSeenUtc) : 'N/A'}
                  </span>
                </div>
                {executionSummary?.topExecutable && (
                  <div className="info-item full-width">
                    <span className="info-label">Top Execution Target</span>
                    <span className="info-value path">
                      {executionSummary.topExecutable}
                      {executionSummary.topSources.length > 0 ? ` (${executionSummary.topSources.join(', ')})` : ''}
                    </span>
                  </div>
                )}
                {persistenceSummary?.warning && (
                  <div className="info-item full-width">
                    <span className="info-label">Persistence Warning</span>
                    <span className="info-value">{persistenceSummary.warning}</span>
                  </div>
                )}
                {executionSummary?.warning && (
                  <div className="info-item full-width">
                    <span className="info-label">Execution Warning</span>
                    <span className="info-value">{executionSummary.warning}</span>
                  </div>
                )}
              </div>
              <div className="analysis-actions">
                <button
                  className="btn btn-secondary"
                  onClick={() => onRunCommand('registry-persistence', ['--limit', '200'])}
                  disabled={Boolean(rollupCommandDisabledReason)}
                  title={rollupCommandDisabledReason}
                >
                  Run Registry Persistence
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => onRunCommand('recent-execution', ['--limit', '200'])}
                  disabled={Boolean(rollupCommandDisabledReason)}
                  title={rollupCommandDisabledReason}
                >
                  Run Recent Execution
                </button>
                <button className="btn btn-secondary" onClick={() => navigate('/timeline', { state: { source: 'execution' } })}>
                  Open Timeline
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => openJobInLogs(lastPersistence || lastExecution)}
                  disabled={!lastPersistence?.filename && !lastExecution?.filename}
                  title={lastPersistence?.filename || lastExecution?.filename ? 'Open latest persistence/execution result in Logs.' : 'No rollup result file yet.'}
                >
                  Open Latest Rollup In Logs
                </button>
              </div>
              <p className="helper-text">
                These rollups use existing CLI outputs from <code>registry-persistence</code> and <code>recent-execution</code>.
              </p>
            </section>

            {latestBundlePath && (
              <section className="panel full-width">
                <h2>Latest Bundle Output</h2>
                <div className="info-grid">
                  <div className="info-item full-width">
                    <span className="info-label">Bundle Path</span>
                    <span className="info-value path">{latestBundlePath}</span>
                  </div>
                  {latestBundleHash && (
                    <div className="info-item full-width">
                      <span className="info-label">Bundle Hash</span>
                      <span className="info-value path">{latestBundleHash}</span>
                    </div>
                  )}
                </div>
                {latestBundleJobFilename && (
                  <div className="analysis-actions">
                    <button
                      className="btn btn-secondary"
                      onClick={() => navigate('/logs', { state: buildLogSelectionState(latestBundleJobFilename) })}
                    >
                      Open Latest Bundle Result In Logs
                    </button>
                  </div>
                )}
              </section>
            )}

            <section className="panel case-info-panel">
              <h2>Case Information</h2>
              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">Case ID</span>
                  <span className="info-value">{caseId}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Database</span>
                  <span className="info-value">{caseDbPath}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Status</span>
                  <span className="info-value text-success">Active</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Commands Run</span>
                  <span className="info-value">{caseJobs.length}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Rollup Commands Run</span>
                  <span className="info-value">{persistenceJobs.length + executionJobs.length}</span>
                </div>
              </div>
            </section>

            <section className="panel case-actions-panel">
              <h2>Case Commands</h2>
              <div className="button-grid">
                <button
                  className="btn btn-primary"
                  onClick={() => onRunCommand('verify', ['--case', caseId, '--db', caseDbPath])}
                  disabled={Boolean(caseCommandDisabledReason)}
                  title={caseCommandDisabledReason}
                >
                  Verify Case
                </button>
                <button
                  className="btn btn-warning"
                  onClick={() => onRunCommand('triage-session', ['--case', caseId, '--db', caseDbPath])}
                  disabled={Boolean(caseCommandDisabledReason)}
                  title={caseCommandDisabledReason}
                >
                  Run Triage
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => onRunCommand('examine', ['--case', caseId, '--db', caseDbPath, '--preset', defaultExaminePreset || 'Fast Triage'])}
                  disabled={Boolean(caseCommandDisabledReason)}
                  title={caseCommandDisabledReason}
                >
                  Examine
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => onRunCommand('watchpoints', ['--case', caseId, '--db', caseDbPath, '--status'])}
                  disabled={Boolean(caseCommandDisabledReason)}
                  title={caseCommandDisabledReason}
                >
                  Watchpoints
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => onRunCommand('violations', ['--case', caseId, '--db', caseDbPath])}
                  disabled={Boolean(caseCommandDisabledReason)}
                  title={caseCommandDisabledReason}
                >
                  Violations
                </button>
              </div>
              <p className="helper-text">Case commands require both Case ID and DB path from Case Configuration.</p>
            </section>

            <section className="panel case-results-panel">
              <h2>Case Results</h2>
              {violationsSummary && violationsSummary.totalReturned > 0 && (
                <div className="warning-message">
                  <div>
                    <strong>Violations detected:</strong> {violationsSummary.totalReturned} returned in the latest violations result.
                  </div>
                  <div className="analysis-actions">
                    <button
                      className="btn btn-secondary btn-small"
                      onClick={() => setActiveTab('violations')}
                    >
                      Review Violations
                    </button>
                  </div>
                </div>
              )}
              <div className="tabs">
                <button
                  className={`tab ${activeTab === 'info' ? 'active' : ''}`}
                  onClick={() => setActiveTab('info')}
                >
                  Info
                </button>
                <button
                  className={`tab ${activeTab === 'verify' ? 'active' : ''}`}
                  onClick={() => setActiveTab('verify')}
                >
                  Verify
                </button>
                <button
                  className={`tab ${activeTab === 'triage' ? 'active' : ''}`}
                  onClick={() => setActiveTab('triage')}
                >
                  Triage
                </button>
                <button
                  className={`tab ${activeTab === 'examine' ? 'active' : ''}`}
                  onClick={() => setActiveTab('examine')}
                >
                  Examine
                </button>
                <button
                  className={`tab ${activeTab === 'watchpoints' ? 'active' : ''}`}
                  onClick={() => setActiveTab('watchpoints')}
                >
                  Watchpoints
                </button>
                <button
                  className={`tab ${activeTab === 'violations' ? 'active' : ''}`}
                  onClick={() => setActiveTab('violations')}
                >
                  Violations
                </button>
              </div>

              <div className="tab-content">
                {activeTab === 'info' && (
                  <div className="tab-panel">
                    <div className="info-grid">
                      <div className="info-item">
                        <span className="info-label">Verify</span>
                        <span className="info-value">{lastVerify ? `Last run ${formatLocalTimestamp(lastVerify.timestamp)} (${formatRelativeTime(lastVerify.timestamp)})` : 'No verify result yet'}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Triage Session</span>
                        <span className="info-value">{lastTriage ? `Last run ${formatLocalTimestamp(lastTriage.timestamp)} (${formatRelativeTime(lastTriage.timestamp)})` : 'No triage-session result yet'}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Examine</span>
                        <span className="info-value">{lastExamine ? `Last run ${formatLocalTimestamp(lastExamine.timestamp)} (${formatRelativeTime(lastExamine.timestamp)})` : 'No examine result yet'}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Watchpoints</span>
                        <span className="info-value">{lastWatchpoints ? `Last run ${formatLocalTimestamp(lastWatchpoints.timestamp)} (${formatRelativeTime(lastWatchpoints.timestamp)})` : 'No watchpoints result yet'}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Violations</span>
                        <span className="info-value">{lastViolations ? `Last run ${formatLocalTimestamp(lastViolations.timestamp)} (${formatRelativeTime(lastViolations.timestamp)})` : 'No violations result yet'}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Registry Persistence</span>
                        <span className="info-value">{lastPersistence ? `Last run ${formatLocalTimestamp(lastPersistence.timestamp)} (${formatRelativeTime(lastPersistence.timestamp)})` : 'No registry-persistence result yet'}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Recent Execution</span>
                        <span className="info-value">{lastExecution ? `Last run ${formatLocalTimestamp(lastExecution.timestamp)} (${formatRelativeTime(lastExecution.timestamp)})` : 'No recent-execution result yet'}</span>
                      </div>
                    </div>
                    <div className="analysis-actions">
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => openJobInLogs(lastVerify)}
                        disabled={!lastVerify?.filename}
                        title={lastVerify?.filename ? 'Open latest verify result in Logs.' : 'No verify result file yet.'}
                      >
                        Open Verify In Logs
                      </button>
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => openJobInLogs(lastTriage)}
                        disabled={!lastTriage?.filename}
                        title={lastTriage?.filename ? 'Open latest triage result in Logs.' : 'No triage result file yet.'}
                      >
                        Open Triage In Logs
                      </button>
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => openJobInLogs(lastExamine)}
                        disabled={!lastExamine?.filename}
                        title={lastExamine?.filename ? 'Open latest examine result in Logs.' : 'No examine result file yet.'}
                      >
                        Open Examine In Logs
                      </button>
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => openJobInLogs(lastWatchpoints)}
                        disabled={!lastWatchpoints?.filename}
                        title={lastWatchpoints?.filename ? 'Open latest watchpoints result in Logs.' : 'No watchpoints result file yet.'}
                      >
                        Open Watchpoints In Logs
                      </button>
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => openJobInLogs(lastViolations)}
                        disabled={!lastViolations?.filename}
                        title={lastViolations?.filename ? 'Open latest violations result in Logs.' : 'No violations result file yet.'}
                      >
                        Open Violations In Logs
                      </button>
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => openJobInLogs(lastPersistence)}
                        disabled={!lastPersistence?.filename}
                        title={lastPersistence?.filename ? 'Open latest registry persistence result in Logs.' : 'No persistence result file yet.'}
                      >
                        Open Persistence In Logs
                      </button>
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => openJobInLogs(lastExecution)}
                        disabled={!lastExecution?.filename}
                        title={lastExecution?.filename ? 'Open latest recent execution result in Logs.' : 'No execution result file yet.'}
                      >
                        Open Execution In Logs
                      </button>
                    </div>
                  </div>
                )}

                {activeTab === 'verify' && (
                  <div className="tab-panel">
                    {!verifySummary && <p className="no-data">No verify result yet. Run Verify Case.</p>}
                    {verifySummary && (
                      <>
                        <div className="info-grid">
                          <div className="info-item">
                            <span className="info-label">Status</span>
                            <span className={`status-badge status-${normalizeStatus(verifySummary.status)}`}>{verifySummary.status}</span>
                          </div>
                          <div className="info-item">
                            <span className="info-label">Checks</span>
                            <span className="info-value">{verifySummary.checksCount}</span>
                          </div>
                          <div className="info-item">
                            <span className="info-label">Warn Checks</span>
                            <span className="info-value">{verifySummary.warnChecks}</span>
                          </div>
                          <div className="info-item">
                            <span className="info-label">Fail/Missing Checks</span>
                            <span className="info-value">{verifySummary.failChecks}</span>
                          </div>
                          {typeof verifySummary.stats?.fts_queue_depth === 'number' && (
                            <div className="info-item">
                              <span className="info-label">FTS Queue Depth</span>
                              <span className="info-value">{verifySummary.stats.fts_queue_depth}</span>
                            </div>
                          )}
                          {verifySummary.warning && (
                            <div className="info-item full-width">
                              <span className="info-label">Warning</span>
                              <span className="info-value">{verifySummary.warning}</span>
                            </div>
                          )}
                          {verifySummary.error && (
                            <div className="info-item full-width">
                              <span className="info-label">Error</span>
                              <span className="info-value text-error">{verifySummary.error}</span>
                            </div>
                          )}
                        </div>
                        {lastVerify?.filename && (
                          <div className="analysis-actions">
                            <button className="btn btn-secondary btn-small" onClick={() => openJobInLogs(lastVerify)}>
                              Open Verify Result In Logs
                            </button>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {activeTab === 'triage' && (
                  <div className="tab-panel">
                    {!triageSummary && <p className="no-data">No triage-session result yet. Run Triage.</p>}
                    {triageSummary && (
                      <>
                        <div className="info-grid">
                          <div className="info-item">
                            <span className="info-label">Status</span>
                            <span className={`status-badge status-${normalizeStatus(triageSummary.status)}`}>{triageSummary.status}</span>
                          </div>
                          {triageSummary.sessionId && (
                            <div className="info-item">
                              <span className="info-label">Session ID</span>
                              <span className="info-value">{triageSummary.sessionId}</span>
                            </div>
                          )}
                          {triageSummary.violationsCount !== null && (
                            <div className="info-item">
                              <span className="info-label">Violations</span>
                              <span className="info-value">{triageSummary.violationsCount}</span>
                            </div>
                          )}
                          {triageSummary.stepsRun.length > 0 && (
                            <div className="info-item">
                              <span className="info-label">Steps Run</span>
                              <span className="info-value">{triageSummary.stepsRun.join(', ')}</span>
                            </div>
                          )}
                          {triageSummary.bundlePath && (
                            <div className="info-item full-width">
                              <span className="info-label">Bundle Path</span>
                              <span className="info-value path">{triageSummary.bundlePath}</span>
                            </div>
                          )}
                          {triageSummary.bundleHash && (
                            <div className="info-item full-width">
                              <span className="info-label">Bundle Hash</span>
                              <span className="info-value path">{triageSummary.bundleHash}</span>
                            </div>
                          )}
                          {triageSummary.error && (
                            <div className="info-item full-width">
                              <span className="info-label">Error</span>
                              <span className="info-value text-error">{triageSummary.error}</span>
                            </div>
                          )}
                        </div>
                        {lastTriage?.filename && (
                          <div className="analysis-actions">
                            <button className="btn btn-secondary btn-small" onClick={() => openJobInLogs(lastTriage)}>
                              Open Triage Result In Logs
                            </button>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {activeTab === 'examine' && (
                  <div className="tab-panel">
                    {!examineSummary && <p className="no-data">No examine result yet. Run Examine.</p>}
                    {examineSummary && (
                      <>
                        <div className="info-grid">
                          <div className="info-item">
                            <span className="info-label">Status</span>
                            <span className={`status-badge status-${normalizeStatus(examineSummary.status)}`}>{examineSummary.status}</span>
                          </div>
                          {examineSummary.presetName && (
                            <div className="info-item">
                              <span className="info-label">Preset</span>
                              <span className="info-value">{examineSummary.presetName}</span>
                            </div>
                          )}
                          {examineSummary.sessionId && (
                            <div className="info-item">
                              <span className="info-label">Session ID</span>
                              <span className="info-value">{examineSummary.sessionId}</span>
                            </div>
                          )}
                          {examineSummary.violationsCount !== null && (
                            <div className="info-item">
                              <span className="info-label">Violations</span>
                              <span className="info-value">{examineSummary.violationsCount}</span>
                            </div>
                          )}
                          {examineSummary.bundlePath && (
                            <div className="info-item full-width">
                              <span className="info-label">Bundle Path</span>
                              <span className="info-value path">{examineSummary.bundlePath}</span>
                            </div>
                          )}
                          {examineSummary.error && (
                            <div className="info-item full-width">
                              <span className="info-label">Error</span>
                              <span className="info-value text-error">{examineSummary.error}</span>
                            </div>
                          )}
                        </div>
                        {lastExamine?.filename && (
                          <div className="analysis-actions">
                            <button className="btn btn-secondary btn-small" onClick={() => openJobInLogs(lastExamine)}>
                              Open Examine Result In Logs
                            </button>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {activeTab === 'watchpoints' && (
                  <div className="tab-panel">
                    {!watchpointsSummary && <p className="no-data">No watchpoints result yet. Run Watchpoints.</p>}
                    {watchpointsSummary && (
                      <>
                        <div className="info-grid">
                          {watchpointsSummary.action && (
                            <div className="info-item">
                              <span className="info-label">Action</span>
                              <span className="info-value">{watchpointsSummary.action}</span>
                            </div>
                          )}
                          {watchpointsSummary.enabled !== null && (
                            <div className="info-item">
                              <span className="info-label">Enabled</span>
                              <span className="info-value">{watchpointsSummary.enabled ? 'Yes' : 'No'}</span>
                            </div>
                          )}
                          {watchpointsSummary.violationCount !== null && (
                            <div className="info-item">
                              <span className="info-label">Violation Count</span>
                              <span className="info-value">{watchpointsSummary.violationCount}</span>
                            </div>
                          )}
                          {watchpointsSummary.error && (
                            <div className="info-item full-width">
                              <span className="info-label">Error</span>
                              <span className="info-value text-error">{watchpointsSummary.error}</span>
                            </div>
                          )}
                        </div>
                        {lastWatchpoints?.filename && (
                          <div className="analysis-actions">
                            <button className="btn btn-secondary btn-small" onClick={() => openJobInLogs(lastWatchpoints)}>
                              Open Watchpoints Result In Logs
                            </button>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {activeTab === 'violations' && (
                  <div className="tab-panel">
                    {!violationsSummary && <p className="no-data">No violations result yet. Run Violations.</p>}
                    {violationsSummary && (
                      <>
                        <div className="info-grid">
                          <div className="info-item">
                            <span className="info-label">Total Returned</span>
                            <span className="info-value">{violationsSummary.totalReturned}</span>
                          </div>
                          {violationsSummary.latestTimestamp && (
                            <div className="info-item">
                              <span className="info-label">Most Recent</span>
                              <span className="info-value">{formatLocalTimestamp(violationsSummary.latestTimestamp)}</span>
                            </div>
                          )}
                          {violationsSummary.sinceUtc && (
                            <div className="info-item">
                              <span className="info-label">Since</span>
                              <span className="info-value">{violationsSummary.sinceUtc}</span>
                            </div>
                          )}
                          {violationsSummary.limit !== null && (
                            <div className="info-item">
                              <span className="info-label">Limit</span>
                              <span className="info-value">{violationsSummary.limit}</span>
                            </div>
                          )}
                          {violationsSummary.error && (
                            <div className="info-item full-width">
                              <span className="info-label">Error</span>
                              <span className="info-value text-error">{violationsSummary.error}</span>
                            </div>
                          )}
                        </div>
                        {lastViolations?.filename && (
                          <div className="analysis-actions">
                            <button className="btn btn-secondary btn-small" onClick={() => openJobInLogs(lastViolations)}>
                              Open Violations Result In Logs
                            </button>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}
              </div>
            </section>
          </>
        )}

        {!caseId && (
          <section className="panel empty-state">
            <p>No case loaded. Create or load a case to see case-specific features.</p>
          </section>
        )}
      </div>
    </div>
  );
}

export default CaseOverview;
