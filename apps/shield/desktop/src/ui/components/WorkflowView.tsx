import { useState, useCallback, useEffect } from 'react';
import { api } from '../../api/tauri';
import type { 
  PresetInfo, 
  TriageSessionResult, 
  VerificationReport, 
  ReplayReport, 
  IntegrityViolation
} from '../../types';

interface Props {
  caseId: string | null;
}

export function WorkflowView({ caseId }: Props) {
  const [presets, setPresets] = useState<PresetInfo[]>([]);
  const [selectedPreset, setSelectedPreset] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  // Verification/Replay state
  const [verification, setVerification] = useState<VerificationReport | null>(null);
  const [replay, setReplay] = useState<ReplayReport | null>(null);
  
  // Violations state
  const [violations, setViolations] = useState<IntegrityViolation[]>([]);
  
  // Export state
  const [exportOptions, setExportOptions] = useState({
    strict: false,
    maxAge: 0,
    noVerify: false,
  });
  
  // Triage session state
  const [triageResult, setTriageResult] = useState<TriageSessionResult | null>(null);
  
  // Report skeleton state
  const [reportOutputDir, setReportOutputDir] = useState('./report');
  const [generatedFiles, setGeneratedFiles] = useState<Record<string, string>>({});

  // Worker state
  const [workerLoopRunning, setWorkerLoopRunning] = useState(false);
  const [workerStatus, setWorkerStatus] = useState<{ queued: number; running: number; last_status: string } | null>(null);

  // Load presets on mount
  useEffect(() => {
    if (caseId) {
      loadPresets();
    }
  }, [caseId]);

  const loadPresets = useCallback(async () => {
    try {
      const result = await api.listPresets();
      setPresets(result);
      if (result.length > 0) {
        setSelectedPreset(result[0].name);
      }
    } catch (e) {
      console.error('Failed to load presets:', e);
    }
  }, []);

  const handleStartExamination = useCallback(async () => {
    if (!caseId || !selectedPreset) return;
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      await api.startExamination(caseId, selectedPreset);
      setSuccess(`Examination started with preset: ${selectedPreset}`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId, selectedPreset]);

  const handleRunTriage = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const result = await api.runTriageSession(caseId);
      setTriageResult(result);
      setSuccess(`Triage completed. Bundle: ${result.bundle_path || 'N/A'}`);
      // Refresh violations
      const violResult = await api.listViolations(caseId);
      setViolations(violResult);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  const handleRunVerify = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await api.runVerify(caseId);
      setVerification(result);
      setSuccess('Verification completed');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  const handleRunReplay = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await api.runReplay(caseId);
      setReplay(result);
      setSuccess('Replay completed');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  const handleLoadViolations = useCallback(async () => {
    if (!caseId) return;
    try {
      const result = await api.listViolations(caseId);
      setViolations(result);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [caseId]);

  const handleClearViolations = useCallback(async () => {
    if (!caseId) return;
    if (!confirm('Are you sure you want to clear all violations?')) return;
    try {
      await api.clearViolations(caseId);
      setViolations([]);
      setSuccess('Violations cleared');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [caseId]);

  const handleExport = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await api.exportCase(caseId, './exports', exportOptions);
      setSuccess(`Exported to: ${result.output_path}`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId, exportOptions]);

  const handleGenerateReport = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await api.generateReportSkeleton(caseId, reportOutputDir);
      setGeneratedFiles(result);
      setSuccess('Report skeleton generated');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId, reportOutputDir]);

  const handleWorkerOnce = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      await api.workerOnce(caseId);
      setSuccess('Worker ran once');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  const handleWorkerStartLoop = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      await api.workerStartLoop(caseId);
      setWorkerLoopRunning(true);
      setSuccess('Worker loop started');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  const handleWorkerStopLoop = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      await api.workerStopLoop(caseId);
      setWorkerLoopRunning(false);
      setSuccess('Worker loop stopped');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  const handleWorkerStatus = useCallback(async () => {
    if (!caseId) return;
    try {
      const status = await api.workerStatus(caseId);
      setWorkerStatus(status);
    } catch (e: unknown) {
      console.error('Failed to get worker status:', e);
    }
  }, [caseId]);

  // Load worker status on mount
  useEffect(() => {
    if (caseId) {
      handleWorkerStatus();
      const interval = setInterval(handleWorkerStatus, 5000);
      return () => clearInterval(interval);
    }
  }, [caseId, handleWorkerStatus]);

  // Load violations on mount
  useEffect(() => {
    if (caseId) {
      handleLoadViolations();
    }
  }, [caseId, handleLoadViolations]);

  if (!caseId) {
    return (
      <div className="workflow-view">
        <div className="view-empty">
          <p>Open a case to access workflow controls</p>
        </div>
      </div>
    );
  }

  return (
    <div className="workflow-view">
      {error && (
        <div className="workflow-error">
          <span>{error}</span>
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}
      
      {success && (
        <div className="workflow-success">
          <span>{success}</span>
          <button onClick={() => setSuccess(null)}>×</button>
        </div>
      )}

      <div className="workflow-section">
        <h3>Examiner Preset</h3>
        <div className="preset-list">
          {presets.map(preset => (
            <label key={preset.name} className={`preset-item ${selectedPreset === preset.name ? 'selected' : ''}`}>
              <input
                type="radio"
                name="preset"
                value={preset.name}
                checked={selectedPreset === preset.name}
                onChange={e => setSelectedPreset(e.target.value)}
              />
              <span className="preset-name">{preset.name}</span>
              <span className="preset-desc">{preset.description}</span>
              {preset.locked_fields.length > 0 && (
                <span className="preset-locked">🔒 {preset.locked_fields.join(', ')}</span>
              )}
            </label>
          ))}
        </div>
        <button 
          className="workflow-btn primary" 
          onClick={handleStartExamination}
          disabled={loading || !selectedPreset}
        >
          Start Examination
        </button>
      </div>

      <div className="workflow-section">
        <h3>Triage Session</h3>
        <button 
          className="workflow-btn primary" 
          onClick={handleRunTriage}
          disabled={loading}
        >
          {loading ? 'Running...' : 'Start Triage Session'}
        </button>
        {triageResult && (
          <div className="triage-result">
            <div className="result-row">
              <span>Status:</span>
              <span className={`badge ${triageResult.status.toLowerCase()}`}>{triageResult.status}</span>
            </div>
            <div className="result-row">
              <span>Violations:</span>
              <span>{triageResult.violations_count}</span>
            </div>
            {triageResult.bundle_path && (
              <div className="result-row">
                <span>Bundle:</span>
                <span>{triageResult.bundle_path}</span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="workflow-section collapsible">
        <h3>Verification Report</h3>
        <button onClick={handleRunVerify} disabled={loading}>Run Verification</button>
        {verification && (
          <div className="report-summary">
            <div className="result-row">
              <span>Status:</span>
              <span className={`badge ${verification.status.toLowerCase()}`}>{verification.status}</span>
            </div>
            <div className="result-row">
              <span>Completed:</span>
              <span>{verification.completed_utc || '-'}</span>
            </div>
            {verification.checks && verification.checks.length > 0 && (
              <div className="checks-list">
                {verification.checks.map((check, i) => (
                  <div key={i} className={`check-item ${check.status.toLowerCase()}`}>
                    <span>{check.check_name}</span>
                    <span>{check.status}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="workflow-section collapsible">
        <h3>Replay Report</h3>
        <button onClick={handleRunReplay} disabled={loading}>Run Replay</button>
        {replay && (
          <div className="report-summary">
            <div className="result-row">
              <span>Status:</span>
              <span className={`badge ${replay.status.toLowerCase()}`}>{replay.status}</span>
            </div>
            <div className="result-row">
              <span>Deterministic:</span>
              <span>{replay.is_deterministic ? 'Yes' : 'No'}</span>
            </div>
            {replay.mismatches && replay.mismatches.length > 0 && (
              <div className="mismatches-list">
                <h4>Mismatches ({replay.mismatches.length})</h4>
                {replay.mismatches.slice(0, 5).map((m, i) => (
                  <div key={i} className="mismatch-item">
                    {m.table_name}.{m.field}: expected {m.expected}, got {m.actual}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="workflow-section collapsible">
        <h3>Integrity Violations</h3>
        <div className="violations-actions">
          <button onClick={handleLoadViolations}>Refresh</button>
          <button 
            className="danger" 
            onClick={handleClearViolations}
            disabled={violations.length === 0}
          >
            Clear All
          </button>
        </div>
        {violations.length > 0 ? (
          <div className="violations-list">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Table</th>
                  <th>Action</th>
                  <th>Actor</th>
                </tr>
              </thead>
              <tbody>
                {violations.slice(0, 20).map((v, i) => (
                  <tr key={i}>
                    <td>{new Date(parseInt(v.detected_utc) * 1000).toLocaleString()}</td>
                    <td>{v.table_name}</td>
                    <td>{v.operation}</td>
                    <td>{v.actor}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {violations.length > 20 && (
              <div className="more-count">+{violations.length - 20} more</div>
            )}
          </div>
        ) : (
          <div className="empty-state">No violations</div>
        )}
      </div>

      <div className="workflow-section collapsible">
        <h3>Worker Control</h3>
        <div className="worker-controls">
          <button onClick={handleWorkerOnce} disabled={loading}>
            Run Worker Once
          </button>
          <button 
            onClick={handleWorkerStartLoop} 
            disabled={loading || workerLoopRunning}
          >
            Start Worker Loop
          </button>
          <button 
            onClick={handleWorkerStopLoop} 
            disabled={loading || !workerLoopRunning}
          >
            Stop Worker Loop
          </button>
        </div>
        {workerStatus && (
          <div className="worker-status">
            <div className="result-row">
              <span>Queued Jobs:</span>
              <span>{workerStatus.queued}</span>
            </div>
            <div className="result-row">
              <span>Running:</span>
              <span>{workerStatus.running}</span>
            </div>
            <div className="result-row">
              <span>Last Status:</span>
              <span>{workerStatus.last_status || '-'}</span>
            </div>
          </div>
        )}
      </div>

      <div className="workflow-section collapsible">
        <h3>Export Case</h3>
        <div className="export-options">
          <label>
            <input
              type="checkbox"
              checked={exportOptions.strict}
              onChange={e => setExportOptions(o => ({ ...o, strict: e.target.checked }))}
            />
            Strict
          </label>
          <label>
            <input
              type="checkbox"
              checked={exportOptions.noVerify}
              onChange={e => setExportOptions(o => ({ ...o, noVerify: e.target.checked }))}
            />
            No Verify
          </label>
          <label>
            Max Age (days):
            <input
              type="number"
              value={exportOptions.maxAge}
              onChange={e => setExportOptions(o => ({ ...o, maxAge: parseInt(e.target.value) || 0 }))}
            />
          </label>
        </div>
        <button onClick={handleExport} disabled={loading}>
          Export Case
        </button>
      </div>

      <div className="workflow-section collapsible">
        <h3>Report Skeleton</h3>
        <div className="report-options">
          <label>
            Output Directory:
            <input
              type="text"
              value={reportOutputDir}
              onChange={e => setReportOutputDir(e.target.value)}
            />
          </label>
        </div>
        <button onClick={handleGenerateReport} disabled={loading}>
          Generate Report Skeleton
        </button>
        {Object.keys(generatedFiles).length > 0 && (
          <div className="generated-files">
            <h4>Generated Files:</h4>
            <ul>
              {Object.entries(generatedFiles).map(([name, path]) => (
                <li key={name}>{name}: {path}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
