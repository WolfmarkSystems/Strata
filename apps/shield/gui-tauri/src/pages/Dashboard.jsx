import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { formatLocalTimestamp, formatRelativeTime } from '../lib/timeFormat';
import { getCommandDisabledReason } from '../lib/commandGuards';
import { buildWorkflowRunbookSteps, deriveWorkflowState } from '../lib/workflowRunbook';
import { buildLogSelectionState, buildLogSelectionStateForCommand } from '../lib/logLinks';

function normalizeStatus(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'ok' || value === 'pass' || value === 'success') return 'ok';
  if (value === 'warn' || value === 'warning') return 'warn';
  if (value === 'error' || value === 'fail' || value === 'failed' || value === 'missing') return 'error';
  return 'warn';
}

function summarizeCapabilities(job) {
  const capabilities = Array.isArray(job?.data?.data?.capabilities) ? job.data.data.capabilities : null;
  if (!capabilities) return null;

  const counts = { production: 0, beta: 0, experimental: 0, stub: 0 };
  capabilities.forEach((capability) => {
    const status = String(capability?.status || '').toLowerCase();
    if (Object.prototype.hasOwnProperty.call(counts, status)) {
      counts[status] += 1;
    }
  });

  return {
    total: capabilities.length,
    counts,
    generatedUtc: job?.data?.data?.generated_utc || null,
  };
}

function summarizeDoctor(job) {
  const data = job?.data?.data;
  if (!data || typeof data !== 'object') return null;
  return {
    platform: data.platform || null,
    version: data.tool_version || null,
    webview2Found: typeof data.webview2_found === 'boolean' ? data.webview2_found : null,
  };
}

function summarizeSmoke(job) {
  const data = job?.data?.data;
  if (!data || typeof data !== 'object') return null;
  return {
    status: job?.status || null,
    containerType: data.container_type || null,
    analysisMode: data.analysis_mode || null,
    analysisValid: typeof data.analysis_valid === 'boolean' ? data.analysis_valid : null,
    error: data.error || job?.data?.error || null,
  };
}

function summarizeTimeline(job) {
  const data = job?.data?.data;
  if (!data || typeof data !== 'object') return null;
  const counts = data.counts_by_source && typeof data.counts_by_source === 'object'
    ? data.counts_by_source
    : null;

  return {
    status: job?.status || null,
    totalReturned: typeof data.total_returned === 'number' ? data.total_returned : null,
    sourceFilter: data.source_filter || null,
    fromUtc: data.from_utc || null,
    toUtc: data.to_utc || null,
    limit: typeof data.limit === 'number' ? data.limit : null,
    counts,
  };
}

function Dashboard({
  caseId,
  caseDbPath,
  evidencePath,
  evidenceInfo,
  defaultSmokeMftCount = 50,
  defaultExaminePreset = 'Fast Triage',
  jobs,
  isRunning,
  activeCommand,
  guardianWarnings = [],
  onClearGuardianWarnings = () => {},
  onRunCommand,
}) {
  const navigate = useNavigate();
  const recentJobs = jobs.slice(0, 5);
  const lastJob = jobs[0] || null;
  const hasCaseContext = Boolean(caseId && caseDbPath);
  const hasEvidenceContext = Boolean(evidencePath);

  const latestCapabilities = jobs.find((job) => job.command === 'capabilities');
  const latestDoctor = jobs.find((job) => job.command === 'doctor');
  const latestSmoke = jobs.find((job) => job.command === 'smoke-test');
  const latestTimeline = jobs.find((job) => job.command === 'timeline');
  const capabilitiesLogState = buildLogSelectionStateForCommand(jobs, 'capabilities');
  const doctorLogState = buildLogSelectionStateForCommand(jobs, 'doctor');
  const smokeLogState = buildLogSelectionStateForCommand(jobs, 'smoke-test');
  const timelineLogState = buildLogSelectionStateForCommand(jobs, 'timeline');

  const capabilitiesSummary = summarizeCapabilities(latestCapabilities);
  const doctorSummary = summarizeDoctor(latestDoctor);
  const smokeSummary = summarizeSmoke(latestSmoke);
  const timelineSummary = summarizeTimeline(latestTimeline);
  const workflowState = useMemo(
    () => deriveWorkflowState({ caseId, caseDbPath, evidencePath, jobs }),
    [caseId, caseDbPath, evidencePath, jobs],
  );
  const runbook = useMemo(() => buildWorkflowRunbookSteps(workflowState), [workflowState]);
  const runbookCompletion = useMemo(() => {
    const total = runbook.steps.length;
    const complete = runbook.steps.filter((step) => step.state === 'complete').length;
    const percent = total > 0 ? Math.round((complete / total) * 100) : 0;
    return { complete, total, percent };
  }, [runbook.steps]);
  const recentActivityFresh = useMemo(() => {
    const lastTimestamp = jobs[0]?.timestamp;
    if (!lastTimestamp) return { hasRecent: false, message: 'No command activity yet.' };
    const lastEpoch = Date.parse(lastTimestamp);
    if (Number.isNaN(lastEpoch)) return { hasRecent: false, message: 'Latest activity timestamp is unavailable.' };
    const isFresh = (Date.now() - lastEpoch) <= (24 * 60 * 60 * 1000);
    return {
      hasRecent: isFresh,
      message: isFresh ? `Recent activity: ${formatRelativeTime(lastTimestamp)}` : `Last activity: ${formatRelativeTime(lastTimestamp)}`,
    };
  }, [jobs]);

  const quickActions = [
    { label: 'Capabilities', command: 'capabilities' },
    { label: 'Doctor', command: 'doctor' },
    { label: 'Smoke Test', command: 'smoke-test', requiresEvidence: true },
    { label: 'Verify Case', command: 'verify', requiresCaseContext: true },
    { label: 'Triage', command: 'triage-session', requiresCaseContext: true },
  ];

  const getActionDisabledReason = (action) => {
    return getCommandDisabledReason({
      isRunning,
      activeCommand,
      requiresCaseContext: Boolean(action.requiresCaseContext),
      caseId,
      caseDbPath,
      requiresEvidence: Boolean(action.requiresEvidence),
      evidencePath,
    });
  };

  const handleQuickAction = (action) => {
    const disabledReason = getActionDisabledReason(action);
    if (disabledReason) return;
    const { command } = action;
    if (command === 'capabilities' || command === 'doctor') {
      onRunCommand(command, []);
    } else if (command === 'smoke-test') {
      const smokeMftCount = Number.isFinite(Number(defaultSmokeMftCount)) && Number(defaultSmokeMftCount) > 0
        ? String(Math.trunc(Number(defaultSmokeMftCount)))
        : '50';
      onRunCommand(command, ['--image', evidencePath, '--out', 'exports/smoke/surface_smoke', '--mft', smokeMftCount, '--no-timeline', '--no-audit']);
    } else if (command === 'verify' || command === 'triage-session') {
      onRunCommand(command, ['--case', caseId, '--db', caseDbPath]);
    }
    navigate('/logs');
  };

  const runbookActionRequiresRun = runbook.nextAction.id.startsWith('run-');
  const runbookActionDisabledReason = runbookActionRequiresRun
    ? getCommandDisabledReason({
      isRunning,
      activeCommand,
      requiresCaseContext: runbook.nextAction.id === 'run-examine' || runbook.nextAction.id === 'run-verify' || runbook.nextAction.id === 'run-triage',
      caseId,
      caseDbPath,
      requiresEvidence: runbook.nextAction.id === 'run-smoke',
      evidencePath,
    })
    : ''
  const recentGuardianWarnings = guardianWarnings.slice(-3).reverse();

  const handleRunbookAction = (actionId) => {
    if (actionId === 'go-evidence') {
      navigate('/evidence');
      return;
    }
    if (actionId === 'go-case') {
      navigate('/case');
      return;
    }
    if (actionId === 'run-smoke') {
      if (runbookActionDisabledReason) return;
      const smokeMftCount = Number.isFinite(Number(defaultSmokeMftCount)) && Number(defaultSmokeMftCount) > 0
        ? String(Math.trunc(Number(defaultSmokeMftCount)))
        : '50';
      onRunCommand('smoke-test', ['--image', evidencePath, '--out', 'exports/smoke/surface_smoke', '--mft', smokeMftCount, '--no-timeline', '--no-audit']);
      navigate('/logs');
      return;
    }
    if (actionId === 'run-examine') {
      if (runbookActionDisabledReason) return;
      onRunCommand('examine', ['--case', caseId, '--db', caseDbPath, '--preset', defaultExaminePreset || 'Fast Triage']);
      navigate('/logs');
      return;
    }
    if (actionId === 'run-verify') {
      if (runbookActionDisabledReason) return;
      onRunCommand('verify', ['--case', caseId, '--db', caseDbPath]);
      navigate('/logs');
      return;
    }
    if (actionId === 'run-triage') {
      if (runbookActionDisabledReason) return;
      onRunCommand('triage-session', ['--case', caseId, '--db', caseDbPath]);
      navigate('/logs');
      return;
    }
    if (actionId === 'review-violations') {
      navigate('/case', { state: { focusTab: 'violations' } });
      return;
    }
    navigate('/logs');
  };

  return (
    <div className="page dashboard">
      <header className="page-header">
        <h1>Dashboard</h1>
        <p className="page-subtitle">Operational summary and quick actions.</p>
      </header>

      {guardianWarnings.length > 0 && (
        <div className="warning-message" style={{ marginBottom: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <strong>{`Guardian: ${guardianWarnings.length} warning(s) from recent operations`}</strong>
            <button className="btn btn-secondary btn-small" onClick={onClearGuardianWarnings}>
              Clear
            </button>
          </div>
          <details style={{ marginTop: '10px' }}>
            <summary>View recent warnings</summary>
            <div className="outputs-preview" style={{ marginTop: '10px' }}>
              {recentGuardianWarnings.map((item) => (
                <div key={`${item.timestamp}-${item.command}-${item.warning}`} className="output-row">
                  <div>
                    <div className="info-value">{item.command}</div>
                    <div className="setting-description">{item.warning}</div>
                  </div>
                  <span className="job-time">{formatLocalTimestamp(item.timestamp)}</span>
                </div>
              ))}
            </div>
          </details>
        </div>
      )}

      <div className="dashboard-grid">
        <section className="panel status-panel">
          <h2>Case Status</h2>
          <div className="status-cards">
            <div className={`status-card ${caseId ? 'active' : 'inactive'}`}>
              <span className="card-dot" aria-hidden="true"></span>
              <div className="card-content">
                <span className="card-label">Case</span>
                <span className="card-value">{caseId || 'No case loaded'}</span>
              </div>
            </div>
            <div className={`status-card ${evidencePath ? 'active' : 'inactive'}`}>
              <span className="card-dot" aria-hidden="true"></span>
              <div className="card-content">
                <span className="card-label">Evidence</span>
                <span className="card-value">{evidencePath ? 'Selected' : 'No evidence'}</span>
              </div>
            </div>
            <div className="status-card">
              <span className="card-dot neutral" aria-hidden="true"></span>
              <div className="card-content">
                <span className="card-label">Recent Jobs</span>
                <span className="card-value">{jobs.length}</span>
              </div>
            </div>
          </div>
          {lastJob ? (
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Last Command</span>
                <span className="info-value">{lastJob.command}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Last Exit Code</span>
                <span className="info-value">{lastJob.exit_code ?? 'N/A'}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Last Run Age</span>
                <span className="info-value">{formatRelativeTime(lastJob.timestamp)}</span>
              </div>
              {lastJob?.filename && (
                <div className="info-item full-width">
                  <button
                    className="btn btn-secondary btn-small"
                    onClick={() => navigate('/logs', { state: buildLogSelectionState(lastJob.filename) })}
                  >
                    Open Last Command In Logs
                  </button>
                </div>
              )}
            </div>
          ) : (
            <p className="no-data">No command results yet. Run a command from Quick Actions.</p>
          )}
        </section>

        <section className="panel quick-actions-panel">
          <h2>Quick Actions</h2>
          <div className="quick-actions">
            {quickActions.map((action) => (
              <button
                key={action.command}
                className="quick-action-btn"
                onClick={() => handleQuickAction(action)}
                disabled={Boolean(getActionDisabledReason(action))}
                title={getActionDisabledReason(action) || `Run ${action.label}`}
              >
                <span className="action-label">{action.label}</span>
              </button>
            ))}
          </div>
          <p className="helper-text">
            Verify/Triage require Case ID and DB path. Smoke Test requires a selected evidence path.
          </p>
        </section>

        <section className="panel">
          <h2>Workflow Runbook</h2>
          <div className="info-grid compact-grid">
            <div className="info-item">
              <span className="info-label">Completion</span>
              <span className="info-value">{runbookCompletion.complete}/{runbookCompletion.total}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Progress</span>
              <span className="info-value">{runbookCompletion.percent}%</span>
            </div>
            <div className="info-item full-width">
              <span className="info-label">Activity Freshness</span>
              <span className="info-value">{recentActivityFresh.message}</span>
            </div>
          </div>
          {!recentActivityFresh.hasRecent && (
            <div className="warning-message">
              Workflow note: no fresh command activity in the last 24 hours.
            </div>
          )}
          <div className="outputs-preview">
            {runbook.steps.map((step) => (
              <div key={step.id} className="output-row">
                <div>
                  <div className="info-value">{step.title}</div>
                  <div className="setting-description">{step.detail}</div>
                </div>
                <span className={`status-badge ${step.state === 'complete' ? 'status-ok' : 'status-info'}`}>
                  {step.state}
                </span>
              </div>
            ))}
          </div>
          <div className="analysis-actions">
            <button
              className="btn btn-primary"
              onClick={() => handleRunbookAction(runbook.nextAction.id)}
              disabled={Boolean(runbookActionDisabledReason)}
              title={runbookActionDisabledReason || runbook.nextAction.detail}
            >
              {runbook.nextAction.label}
            </button>
            <button className="btn btn-secondary" onClick={() => navigate('/logs')}>
              Open Logs
            </button>
          </div>
          <p className="helper-text">{runbook.nextAction.detail}</p>
        </section>

        <section className="panel capabilities-panel">
          <h2>Capabilities Summary</h2>
          {capabilitiesSummary ? (
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Total</span>
                <span className="info-value">{capabilitiesSummary.total}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Production</span>
                <span className="info-value">{capabilitiesSummary.counts.production}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Beta</span>
                <span className="info-value">{capabilitiesSummary.counts.beta}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Experimental</span>
                <span className="info-value">{capabilitiesSummary.counts.experimental}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Stub</span>
                <span className="info-value">{capabilitiesSummary.counts.stub}</span>
              </div>
              {capabilitiesSummary.generatedUtc && (
                <div className="info-item full-width">
                  <span className="info-label">Generated</span>
                  <span className="info-value">{formatLocalTimestamp(capabilitiesSummary.generatedUtc)}</span>
                </div>
              )}
            </div>
          ) : (
            <p className="no-data">No capabilities result yet. Run Capabilities to load this section.</p>
          )}
          <div className="analysis-actions">
            <button
              className="btn btn-secondary btn-small"
              onClick={() => navigate('/logs', { state: capabilitiesLogState })}
              disabled={!capabilitiesLogState.selectJobFilename}
              title={capabilitiesLogState.selectJobFilename ? 'Open latest capabilities result in Logs.' : 'No capabilities result file yet.'}
            >
              Open Latest Capabilities In Logs
            </button>
          </div>
        </section>

        <section className="panel doctor-panel">
          <h2>Doctor Summary</h2>
          {doctorSummary ? (
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Platform</span>
                <span className="info-value">{doctorSummary.platform || 'N/A'}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Version</span>
                <span className="info-value">{doctorSummary.version || 'N/A'}</span>
              </div>
              <div className="info-item">
                <span className="info-label">WebView2</span>
                <span className={`info-value ${doctorSummary.webview2Found ? 'text-success' : 'text-error'}`}>
                  {doctorSummary.webview2Found === null ? 'Unknown' : doctorSummary.webview2Found ? 'Installed' : 'Not Found'}
                </span>
              </div>
            </div>
          ) : (
            <p className="no-data">No doctor result yet. Run Doctor to load this section.</p>
          )}
          <div className="analysis-actions">
            <button
              className="btn btn-secondary btn-small"
              onClick={() => navigate('/logs', { state: doctorLogState })}
              disabled={!doctorLogState.selectJobFilename}
              title={doctorLogState.selectJobFilename ? 'Open latest doctor result in Logs.' : 'No doctor result file yet.'}
            >
              Open Latest Doctor In Logs
            </button>
          </div>
        </section>

        <section className="panel evidence-panel">
          <h2>Evidence Summary</h2>
          {evidencePath ? (
            <div className="info-grid">
              <div className="info-item full-width">
                <span className="info-label">Selected Path</span>
                <span className="info-value path">{evidencePath}</span>
              </div>
              {evidenceInfo?.size !== undefined && (
                <div className="info-item">
                  <span className="info-label">File Size</span>
                  <span className="info-value">{Number(evidenceInfo.size).toLocaleString()} bytes</span>
                </div>
              )}
              {evidenceInfo?.extension && (
                <div className="info-item">
                  <span className="info-label">Extension</span>
                  <span className="info-value">{evidenceInfo.extension}</span>
                </div>
              )}
              {smokeSummary && (
                <>
                  <div className="info-item">
                    <span className="info-label">Last Smoke Status</span>
                    <span className={`status-badge status-${normalizeStatus(smokeSummary.status)}`}>
                      {smokeSummary.status || 'unknown'}
                    </span>
                  </div>
                  {smokeSummary.containerType && (
                    <div className="info-item">
                      <span className="info-label">Container Type</span>
                      <span className="info-value">{smokeSummary.containerType}</span>
                    </div>
                  )}
                  {smokeSummary.analysisMode && (
                    <div className="info-item">
                      <span className="info-label">Analysis Mode</span>
                      <span className="info-value">{smokeSummary.analysisMode}</span>
                    </div>
                  )}
                  {smokeSummary.analysisValid !== null && (
                    <div className="info-item">
                      <span className="info-label">Analysis Valid</span>
                      <span className="info-value">{smokeSummary.analysisValid ? 'Yes' : 'No'}</span>
                    </div>
                  )}
                  {smokeSummary.error && (
                    <div className="info-item full-width">
                      <span className="info-label">Last Smoke Error</span>
                      <span className="info-value text-error">{smokeSummary.error}</span>
                    </div>
                  )}
                </>
              )}
              {!smokeSummary && (
                <div className="info-item full-width">
                  <span className="info-label">Smoke Test</span>
                  <span className="info-value">No smoke-test result yet</span>
                </div>
              )}
            </div>
          ) : (
            <p className="no-data">No evidence selected. Go to Evidence Sources to set an evidence path.</p>
          )}
          <button className="btn btn-secondary" onClick={() => navigate('/evidence')}>
            Manage Evidence
          </button>
          <button
            className="btn btn-secondary btn-small"
            onClick={() => navigate('/logs', { state: smokeLogState })}
            disabled={!smokeLogState.selectJobFilename}
            title={smokeLogState.selectJobFilename ? 'Open latest smoke-test result in Logs.' : 'No smoke-test result file yet.'}
          >
            Open Latest Smoke In Logs
          </button>
        </section>

        <section className="panel recent-jobs-panel">
          <h2>Recent Jobs</h2>
          {recentJobs.length > 0 ? (
            <ul className="recent-jobs-list">
              {recentJobs.map((job) => (
                <li key={job.filename}>
                  <button
                    type="button"
                    className={`recent-job-item status-${job.status}`}
                    onClick={() => navigate('/logs', { state: buildLogSelectionState(job.filename) })}
                    title={job.filename ? `Open ${job.filename} in Logs` : 'Open in Logs'}
                  >
                  <div className="job-info">
                    <span className="job-command">{job.command}</span>
                    <span className={`job-status-badge status-${job.status}`}>{job.status}</span>
                  </div>
                  <div className="job-meta">
                    <span className="job-time">{formatLocalTimestamp(job.timestamp)}</span>
                    <span className="job-elapsed">{job.elapsed_ms ?? 'N/A'}ms</span>
                    <span className="job-elapsed">{formatRelativeTime(job.timestamp)}</span>
                  </div>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="no-data">No jobs yet.</p>
          )}
          <button className="btn btn-secondary" onClick={() => navigate('/logs')}>
            View All Logs
          </button>
        </section>

        <section className="panel">
          <h2>Timeline Summary</h2>
          {timelineSummary ? (
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Status</span>
                <span className={`status-badge status-${normalizeStatus(timelineSummary.status)}`}>
                  {timelineSummary.status || 'unknown'}
                </span>
              </div>
              <div className="info-item">
                <span className="info-label">Total Events</span>
                <span className="info-value">
                  {timelineSummary.totalReturned ?? 'N/A'}
                </span>
              </div>
              <div className="info-item">
                <span className="info-label">Source Filter</span>
                <span className="info-value">{timelineSummary.sourceFilter || 'all'}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Limit</span>
                <span className="info-value">{timelineSummary.limit ?? 'N/A'}</span>
              </div>
              {timelineSummary.counts && (
                <>
                  <div className="info-item">
                    <span className="info-label">Activity</span>
                    <span className="info-value">{timelineSummary.counts.activity ?? 0}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Evidence</span>
                    <span className="info-value">{timelineSummary.counts.evidence ?? 0}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Violations</span>
                    <span className="info-value">{timelineSummary.counts.violations ?? 0}</span>
                  </div>
                </>
              )}
              {(timelineSummary.fromUtc || timelineSummary.toUtc) && (
                <div className="info-item full-width">
                  <span className="info-label">Query Window</span>
                  <span className="info-value">
                    {timelineSummary.fromUtc || 'beginning'} to {timelineSummary.toUtc || 'now'}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <p className="no-data">No timeline result yet. Open Timeline and run Load Timeline.</p>
          )}
          <button className="btn btn-secondary" onClick={() => navigate('/timeline')}>
            Open Timeline
          </button>
          <button
            className="btn btn-secondary btn-small"
            onClick={() => navigate('/logs', { state: timelineLogState })}
            disabled={!timelineLogState.selectJobFilename}
            title={timelineLogState.selectJobFilename ? 'Open latest timeline result in Logs.' : 'No timeline result file yet.'}
          >
            Open Latest Timeline In Logs
          </button>
        </section>
      </div>

    </div>
  );
}

export default Dashboard;


