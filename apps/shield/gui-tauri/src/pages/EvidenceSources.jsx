import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import EvidenceLoader from '../components/EvidenceLoader';
import { runGuiCommand } from '../lib/commandAdapter';
import { formatLocalTimestamp, formatRelativeTime } from '../lib/timeFormat';
import { getCommandDisabledReason } from '../lib/commandGuards';
import { buildLogSelectionState, findLatestJobFilename } from '../lib/logLinks';

function normalizeStatus(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'ok' || value === 'pass' || value === 'success') return 'ok';
  if (value === 'warn' || value === 'warning') return 'warn';
  if (value === 'error' || value === 'fail' || value === 'failed') return 'error';
  return 'warn';
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function summarizeStepStatus(job) {
  if (!job) return { label: 'not run', className: 'status-info' };
  const normalized = normalizeStatus(job.status);
  if (normalized === 'ok') return { label: 'ok', className: 'status-ok' };
  if (normalized === 'warn') return { label: 'warn', className: 'status-warn' };
  return { label: 'error', className: 'status-error' };
}

function EvidenceSources({
  caseId,
  caseDbPath,
  evidencePath,
  evidenceInfo,
  isEvidencePathRestoredFromSession = false,
  defaultSmokeMftCount = 50,
  onPathChange,
  onInfoChange,
  onRunCommand,
  onPersistGuiCommandResult,
  isRunning,
  jobs,
}) {
  const navigate = useNavigate();
  const [openEvidenceResult, setOpenEvidenceResult] = useState(null);
  const [isDetectingEvidence, setIsDetectingEvidence] = useState(false);

  const smokeTestJobs = jobs.filter((job) => job.command === 'smoke-test');
  const latestSmoke = smokeTestJobs[0] || null;
  const latestOpenEvidence = jobs.find((job) => job.command === 'open-evidence') || null;
  const smokeEnvelope = latestSmoke?.data || null;
  const smokeData = asObject(smokeEnvelope?.data);
  const latestExamine = jobs.find((job) => job.command === 'examine') || null;
  const latestVerify = jobs.find((job) => job.command === 'verify') || null;
  const latestTriage = jobs.find((job) => job.command === 'triage-session') || null;
  const hasCaseContext = Boolean(caseId && caseDbPath);
  const smokeStatus = summarizeStepStatus(latestSmoke);
  const examineStatus = summarizeStepStatus(latestExamine);
  const verifyStatus = summarizeStepStatus(latestVerify);
  const triageStatus = summarizeStepStatus(latestTriage);
  const smokeIsActionable = Boolean(
    latestSmoke
      && (smokeStatus.className === 'status-ok'
        || smokeStatus.className === 'status-warn'
        || smokeData?.analysis_mode === 'container_only'),
  );
  const smokeDisabledReason = getCommandDisabledReason({
    isRunning,
    requiresEvidence: true,
    evidencePath,
  });
  const detectDisabledReason = getCommandDisabledReason({
    isRunning: isRunning || isDetectingEvidence,
    activeCommand: isDetectingEvidence ? 'open-evidence' : '',
    requiresEvidence: true,
    evidencePath,
  });
  const latestSmokeFilename = findLatestJobFilename(jobs, 'smoke-test');
  const latestOpenEvidenceFilename = findLatestJobFilename(jobs, 'open-evidence');

  useEffect(() => {
    setOpenEvidenceResult(null);
  }, [evidencePath]);

  const handleSmokeTest = () => {
    const smokeMftCount = Number.isFinite(Number(defaultSmokeMftCount)) && Number(defaultSmokeMftCount) > 0
      ? String(Math.trunc(Number(defaultSmokeMftCount)))
      : '50';
    onRunCommand('smoke-test', [
      '--image', evidencePath,
      '--out', 'exports/smoke/surface_smoke',
      '--mft', smokeMftCount,
      '--no-timeline',
      '--no-audit',
    ]);
  };

  const handleOpenEvidence = async () => {
    if (!evidencePath || isDetectingEvidence) return;
    setIsDetectingEvidence(true);
    try {
      const openEvidenceArgs = [evidencePath, '--json'];
      const result = await runGuiCommand('open-evidence', openEvidenceArgs);
      setOpenEvidenceResult(result);
      if (onPersistGuiCommandResult) {
        await onPersistGuiCommandResult('open-evidence', openEvidenceArgs, result);
      }
    } finally {
      setIsDetectingEvidence(false);
    }
  };

  const persistedOpenEvidenceData = useMemo(
    () => asObject(latestOpenEvidence?.data?.data),
    [latestOpenEvidence],
  );
  const evidenceDetection = useMemo(
    () => asObject(openEvidenceResult?.data) || persistedOpenEvidenceData,
    [openEvidenceResult, persistedOpenEvidenceData],
  );
  const detectionContainer = asObject(evidenceDetection?.container_type);
  const detectionPartition = asObject(evidenceDetection?.partition_scheme);
  const detectionChecks = Array.isArray(evidenceDetection?.capability_checks) ? evidenceDetection.capability_checks : [];
  const satisfiedChecks = detectionChecks.filter((check) => check?.is_satisfied === true).length;
  const unsatisfiedChecks = detectionChecks.filter((check) => check?.is_satisfied === false).length;
  const detectionWarnings = Array.isArray(evidenceDetection?.warnings) ? evidenceDetection.warnings : [];
  const detectionErrors = Array.isArray(evidenceDetection?.errors) ? evidenceDetection.errors : [];
  const openEvidenceError = openEvidenceResult?.error || latestOpenEvidence?.data?.error || null;
  const hasDetectionRun = Boolean(openEvidenceResult || latestOpenEvidence);
  const detectionDataSource = openEvidenceResult
    ? 'Current session run'
    : latestOpenEvidence
      ? 'Persisted history'
      : 'Not available';
  const detectionStatus = useMemo(() => {
    if (!evidencePath) return { label: 'not available', className: 'status-info' };
    if (!hasDetectionRun) return { label: 'not run', className: 'status-info' };
    if (evidenceDetection) return { label: 'ok', className: 'status-ok' };
    if (openEvidenceError) return { label: 'error', className: 'status-error' };
    return { label: 'no data', className: 'status-warn' };
  }, [evidencePath, hasDetectionRun, evidenceDetection, openEvidenceError]);

  const smokeOutputs = asObject(smokeData?.outputs);
  const smokeOutputRows = smokeOutputs ? Object.entries(smokeOutputs).slice(0, 5) : [];
  const recommendedSteps = useMemo(() => {
    if (!evidencePath) {
      return [
        {
          id: 'load-evidence',
          title: 'Select evidence source',
          detail: 'Choose an evidence path first to unlock smoke-test and evidence detection.',
          actionLabel: 'Choose Evidence',
          action: () => navigate('/evidence'),
        },
      ];
    }

    const steps = [];

    if (!latestSmoke) {
      steps.push({
        id: 'run-smoke',
        title: 'Run Smoke Test',
        detail: 'Capture initial container/filesystem status and baseline outputs for this evidence.',
        actionLabel: 'Run Smoke Test',
        action: handleSmokeTest,
        disabledReason: smokeDisabledReason,
      });
    }

    if (!hasCaseContext) {
      steps.push({
        id: 'set-case-context',
        title: 'Set case and database context',
        detail: 'Case-level commands (examine/verify/triage) need both case ID and DB path.',
        actionLabel: 'Go to Case Overview',
        action: () => navigate('/case'),
      });
    }

    if (hasCaseContext && smokeIsActionable && !latestExamine) {
      steps.push({
        id: 'run-examine',
        title: 'Run Examine next',
        detail: 'Use the current case context to produce examination outputs from this evidence.',
        actionLabel: 'Go to Case Overview',
        action: () => navigate('/case'),
      });
    }

    if (hasCaseContext && smokeIsActionable) {
      steps.push({
        id: 'review-filetable',
        title: 'Review File Table',
        detail: 'Inspect currently indexed file records for quick triage context.',
        actionLabel: 'Go to File Explorer',
        action: () => navigate('/files'),
      });
    }

    if (hasCaseContext && latestExamine && !latestVerify) {
      steps.push({
        id: 'run-verify',
        title: 'Run Verify',
        detail: 'Verify case consistency after initial examination.',
        actionLabel: 'Go to Case Overview',
        action: () => navigate('/case'),
      });
    }

    if (hasCaseContext && latestExamine && !latestTriage) {
      steps.push({
        id: 'run-triage',
        title: 'Run Triage Session',
        detail: 'Generate a defensibility-oriented session/bundle with current case context.',
        actionLabel: 'Go to Case Overview',
        action: () => navigate('/case'),
      });
    }

    if (latestVerify || latestTriage) {
      steps.push({
        id: 'review-logs',
        title: 'Review execution logs',
        detail: 'Open Logs to inspect full envelopes, warnings, and output paths.',
        actionLabel: 'Open Logs',
        action: () => navigate('/logs'),
      });
    }

    return steps;
  }, [
    evidencePath,
    latestSmoke,
    latestExamine,
    latestVerify,
    latestTriage,
    hasCaseContext,
    smokeIsActionable,
    smokeDisabledReason,
    handleSmokeTest,
    navigate,
  ]);

  return (
    <div className="page evidence-sources">
      <header className="page-header">
        <h1>Evidence Sources</h1>
        <p className="page-subtitle">Manage evidence context and run evidence-focused commands.</p>
      </header>

      <section className="panel workflow-strip evidence-context-strip">
        <h2>Evidence Intake Status</h2>
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
            <span className="info-label">Smoke Tested</span>
            <span className={`status-badge ${smokeStatus.className}`}>{smokeStatus.label}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Evidence Detection</span>
            <span className={`status-badge ${detectionStatus.className}`}>{detectionStatus.label}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Examined</span>
            <span className={`status-badge ${examineStatus.className}`}>{examineStatus.label}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Ready For Case Commands</span>
            <span className={`status-badge ${hasCaseContext && smokeIsActionable ? 'status-ok' : 'status-info'}`}>
              {hasCaseContext && smokeIsActionable ? 'yes' : 'not yet'}
            </span>
          </div>
          <div className="info-item full-width">
            <span className="info-label">Case Context</span>
            <span className="info-value">{caseId || 'No case selected'} | {caseDbPath || 'No DB path selected'}</span>
          </div>
          <div className="info-item full-width">
            <span className="info-label">Latest Case Steps</span>
            <span className="info-value">
              Verify: {verifyStatus.label} | Triage: {triageStatus.label}
            </span>
          </div>
          <div className="info-item full-width">
            <span className="info-label">Latest Evidence Command Age</span>
            <span className="info-value">
              Smoke: {latestSmoke?.timestamp ? formatRelativeTime(latestSmoke.timestamp) : 'not run'} | Detect: {latestOpenEvidence?.timestamp ? formatRelativeTime(latestOpenEvidence.timestamp) : 'not run'}
            </span>
          </div>
        </div>
        <div className="analysis-actions">
          <button className="btn btn-secondary" onClick={() => navigate('/case')}>
            Go to Case Overview
          </button>
          <button className="btn btn-secondary" onClick={() => navigate('/logs')}>
            Open Logs
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => navigate('/logs', { state: buildLogSelectionState(latestSmokeFilename) })}
            disabled={!latestSmokeFilename}
            title={latestSmokeFilename ? `Open ${latestSmokeFilename} in Logs.` : 'No smoke-test result file yet.'}
          >
            Open Latest Smoke In Logs
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => navigate('/logs', { state: buildLogSelectionState(latestOpenEvidenceFilename) })}
            disabled={!latestOpenEvidenceFilename}
            title={latestOpenEvidenceFilename ? `Open ${latestOpenEvidenceFilename} in Logs.` : 'No open-evidence result file yet.'}
          >
            Open Latest Detection In Logs
          </button>
        </div>
      </section>

      <section className="panel">
        <h2>Recommended Next Steps</h2>
        {recommendedSteps.length === 0 ? (
          <p className="no-data">No immediate next step required. Continue with Case Overview or Logs as needed.</p>
        ) : (
          <div className="outputs-preview">
            {recommendedSteps.map((step) => (
              <div key={step.id} className="output-row">
                <div>
                  <div className="info-value">{step.title}</div>
                  <div className="setting-description">{step.detail}</div>
                </div>
                <button className="btn btn-secondary btn-small" onClick={step.action} disabled={Boolean(step.disabledReason)} title={step.disabledReason || ''}>
                  {step.actionLabel}
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      <div className="evidence-layout">
        <section className="panel evidence-loader-panel">
          <h2>Add Evidence</h2>
          <EvidenceLoader
            evidencePath={evidencePath}
            isEvidencePathRestoredFromSession={isEvidencePathRestoredFromSession}
            onPathChange={onPathChange}
            onInfoChange={onInfoChange}
          />
        </section>

        {evidencePath && (
          <>
            <section className="panel evidence-details-panel">
              <h2>Evidence Details</h2>
              <div className="info-grid">
                <div className="info-item full-width">
                  <span className="info-label">Path</span>
                  <span className="info-value path">{evidencePath}</span>
                </div>
                {evidenceInfo?.filename && (
                  <div className="info-item">
                    <span className="info-label">Filename</span>
                    <span className="info-value">{evidenceInfo.filename}</span>
                  </div>
                )}
                {evidenceInfo?.extension && (
                  <div className="info-item">
                    <span className="info-label">Extension</span>
                    <span className="info-value">{evidenceInfo.extension}</span>
                  </div>
                )}
                {evidenceInfo?.size !== undefined && (
                  <div className="info-item">
                    <span className="info-label">Size</span>
                    <span className="info-value">{Number(evidenceInfo.size).toLocaleString()} bytes</span>
                  </div>
                )}
                {!evidenceInfo && (
                  <div className="info-item full-width">
                    <span className="info-label">Metadata</span>
                    <span className="info-value">No local file metadata yet. Use Browse to capture metadata.</span>
                  </div>
                )}
              </div>
            </section>

            <section className="panel evidence-analysis-panel">
              <h2>Analysis</h2>
              <div className="analysis-actions">
                <button
                  className="btn btn-warning"
                  onClick={handleSmokeTest}
                  disabled={Boolean(smokeDisabledReason)}
                  title={smokeDisabledReason}
                >
                  Run Smoke Test
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={handleOpenEvidence}
                  disabled={Boolean(detectDisabledReason)}
                  title={detectDisabledReason}
                >
                  {isDetectingEvidence ? 'Detecting...' : 'Detect Evidence'}
                </button>
                <button
                  className="btn btn-secondary"
                  disabled
                  title="CLI gap: no stable hash calculation command is wired for this page yet."
                >
                  Calculate Hashes (CLI Gap)
                </button>
                <button
                  className="btn btn-secondary"
                  disabled
                  title="CLI gap: no evidence-scoped carve workflow is wired for this page yet."
                >
                  Carve Files (CLI Gap)
                </button>
              </div>
              <p className="no-data">
                Capability gap: hash and carve actions are intentionally stubbed until a stable case/evidence-scoped CLI flow is available.
              </p>
              <p className="helper-text">Smoke Test and Detect Evidence require a selected evidence path.</p>
            </section>

            <section className="panel evidence-detection-panel">
              <h2>Evidence Detection</h2>
              {!hasDetectionRun && (
                <p className="no-data">No evidence-detection result yet. Run Detect Evidence.</p>
              )}

              {hasDetectionRun && evidenceDetection && (
                <div className="info-grid">
                  <div className="info-item">
                    <span className="info-label">Data Source</span>
                    <span className="info-value">{detectionDataSource}</span>
                  </div>
                  {latestOpenEvidenceFilename && (
                    <div className="info-item">
                      <span className="info-label">Result File</span>
                      <span className="info-value">{latestOpenEvidenceFilename}</span>
                    </div>
                  )}
                  {evidenceDetection.evidence_id && (
                    <div className="info-item">
                      <span className="info-label">Evidence ID</span>
                      <span className="info-value">{evidenceDetection.evidence_id}</span>
                    </div>
                  )}
                  {evidenceDetection.detection_timestamp_utc && (
                    <div className="info-item">
                      <span className="info-label">Detected At</span>
                      <span className="info-value">{formatLocalTimestamp(evidenceDetection.detection_timestamp_utc)}</span>
                    </div>
                  )}
                  {evidenceDetection.detection_timestamp_utc && (
                    <div className="info-item">
                      <span className="info-label">Detected Age</span>
                      <span className="info-value">{formatRelativeTime(evidenceDetection.detection_timestamp_utc)}</span>
                    </div>
                  )}
                  {evidenceDetection.source_path && (
                    <div className="info-item full-width">
                      <span className="info-label">Source Path</span>
                      <span className="info-value path">{evidenceDetection.source_path}</span>
                    </div>
                  )}
                  {detectionContainer && (
                    <>
                      <div className="info-item">
                        <span className="info-label">Container</span>
                        <span className="info-value">{detectionContainer.container_type || 'Unknown'}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Container Supported</span>
                        <span className="info-value">{String(detectionContainer.is_supported)}</span>
                      </div>
                      {detectionContainer.size_bytes !== undefined && (
                        <div className="info-item">
                          <span className="info-label">Container Size</span>
                          <span className="info-value">{Number(detectionContainer.size_bytes).toLocaleString()} bytes</span>
                        </div>
                      )}
                    </>
                  )}
                  {detectionPartition && (
                    <>
                      <div className="info-item">
                        <span className="info-label">Partition Scheme</span>
                        <span className="info-value">{detectionPartition.scheme || 'Unknown'}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Partition Count</span>
                        <span className="info-value">{detectionPartition.partition_count ?? 'N/A'}</span>
                      </div>
                    </>
                  )}
                  <div className="info-item">
                    <span className="info-label">Volumes</span>
                    <span className="info-value">{Array.isArray(evidenceDetection.volumes) ? evidenceDetection.volumes.length : 0}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Capability Checks</span>
                    <span className="info-value">{detectionChecks.length}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Satisfied Checks</span>
                    <span className="info-value">{satisfiedChecks}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Unsatisfied Checks</span>
                    <span className="info-value">{unsatisfiedChecks}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Warnings</span>
                    <span className="info-value">{detectionWarnings.length}</span>
                  </div>
                  <div className="info-item">
                    <span className="info-label">Errors</span>
                    <span className="info-value">{detectionErrors.length}</span>
                  </div>
                </div>
              )}

              {hasDetectionRun && !evidenceDetection && (
                <p className="no-data">No structured evidence data available in the latest result.</p>
              )}

              {openEvidenceError && (
                <div className="warning-message">
                  <strong>Open Evidence:</strong> {openEvidenceError}
                </div>
              )}
              {latestOpenEvidenceFilename && (
                <div className="analysis-actions">
                  <button
                    className="btn btn-secondary btn-small"
                    onClick={() => navigate('/logs', { state: buildLogSelectionState(latestOpenEvidenceFilename) })}
                  >
                    Open Detection Result In Logs
                  </button>
                </div>
              )}
            </section>

            {latestSmoke && (
              <section className="panel smoke-results-panel">
                <h2>Smoke Test Results</h2>
                <div className="result-summary">
                  <span className={`status-badge status-${normalizeStatus(latestSmoke.status)}`}>{latestSmoke.status}</span>
                  <span className="elapsed">{latestSmoke.elapsed_ms ?? 'N/A'}ms</span>
                  <span className="timestamp">{formatLocalTimestamp(latestSmoke.timestamp)}</span>
                  <span className="timestamp">{formatRelativeTime(latestSmoke.timestamp)}</span>
                </div>
                {latestSmokeFilename && (
                  <div className="analysis-actions">
                    <button
                      className="btn btn-secondary btn-small"
                      onClick={() => navigate('/logs', { state: buildLogSelectionState(latestSmokeFilename) })}
                    >
                      Open Smoke Result In Logs
                    </button>
                  </div>
                )}

                {smokeData ? (
                  <div className="info-grid">
                    {smokeData.container_type && (
                      <div className="info-item">
                        <span className="info-label">Container</span>
                        <span className="info-value">{smokeData.container_type}</span>
                      </div>
                    )}
                    {smokeData.analysis_mode && (
                      <div className="info-item">
                        <span className="info-label">Analysis Mode</span>
                        <span className="info-value">{smokeData.analysis_mode}</span>
                      </div>
                    )}
                    {typeof smokeData.analysis_valid === 'boolean' && (
                      <div className="info-item">
                        <span className="info-label">Analysis Valid</span>
                        <span className="info-value">{smokeData.analysis_valid ? 'Yes' : 'No'}</span>
                      </div>
                    )}
                    {smokeData.evidence_size_bytes !== undefined && (
                      <div className="info-item">
                        <span className="info-label">Evidence Size</span>
                        <span className="info-value">{Number(smokeData.evidence_size_bytes).toLocaleString()} bytes</span>
                      </div>
                    )}
                    {smokeData.mft_records_emitted !== undefined && (
                      <div className="info-item">
                        <span className="info-label">MFT Records Emitted</span>
                        <span className="info-value">{smokeData.mft_records_emitted}</span>
                      </div>
                    )}
                    {(smokeData.error || smokeEnvelope?.error) && (
                      <div className="info-item full-width">
                        <span className="info-label">Error</span>
                        <span className="info-value text-error">{smokeData.error || smokeEnvelope?.error}</span>
                      </div>
                    )}
                    {(smokeData.warning || smokeEnvelope?.warning) && (
                      <div className="info-item full-width">
                        <span className="info-label">Warning</span>
                        <span className="info-value">{smokeData.warning || smokeEnvelope?.warning}</span>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="no-data">No structured smoke-test data available in the latest result.</p>
                )}

                {smokeOutputRows.length > 0 && (
                  <div className="outputs-preview">
                    {smokeOutputRows.map(([key, value]) => (
                      <div key={key} className="output-row">
                        <span className="output-key">{key}</span>
                        <span className="output-value">{String(value).substring(0, 80)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            )}
          </>
        )}

        {!evidencePath && (
          <section className="panel empty-state">
            <p>No evidence selected. Add evidence using the form above.</p>
          </section>
        )}
      </div>
    </div>
  );
}

export default EvidenceSources;
