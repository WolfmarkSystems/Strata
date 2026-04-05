import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getCommandDisabledReason } from '../lib/commandGuards';
import { buildLogSelectionState } from '../lib/logLinks';
import { runGuiCommand } from '../lib/commandAdapter';

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function normalizeStatus(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'ok' || value === 'pass' || value === 'success') return 'ok';
  if (value === 'warn' || value === 'warning') return 'warn';
  if (value === 'error' || value === 'fail' || value === 'failed') return 'error';
  return 'warn';
}

function formatTimestamp(value) {
  if (!value) return 'N/A';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function summarizeExamineJob(job) {
  if (!job) return null;
  const envelope = asObject(job.data);
  const data = asObject(envelope?.data);
  const result = asObject(data?.result);
  const outputs = asObject(envelope?.outputs);
  const sizes = asObject(envelope?.sizes);

  return {
    timestamp: job.timestamp || envelope?.timestamp_utc || null,
    status: result?.status || envelope?.status || job.status || null,
    exitCode: job.exit_code ?? envelope?.exit_code ?? null,
    elapsedMs: job.elapsed_ms ?? envelope?.elapsed_ms ?? null,
    presetName: data?.preset_name || null,
    sessionId: result?.session_id || null,
    violationsCount: result?.violations_count ?? null,
    bundlePath: result?.bundle_path || envelope?.outputs?.bundle_zip || null,
    bundleHash: result?.bundle_hash_sha256 || null,
    outputs,
    sizes,
    warning: envelope?.warning || null,
    error: envelope?.error || null,
    data,
  };
}

function findArtifactCollections(examineData) {
  const collections = [];
  const root = asObject(examineData);
  if (!root) return collections;

  const candidates = [
    ['data', root],
    ['data.result', asObject(root.result)],
  ];

  candidates.forEach(([prefix, source]) => {
    if (!source) return;
    Object.entries(source).forEach(([key, value]) => {
      if (!Array.isArray(value)) return;
      if (!key.toLowerCase().includes('artifact')) return;

      const first = value[0];
      const sampleKeys = asObject(first) ? Object.keys(first).slice(0, 8) : [];
      collections.push({
        id: `${prefix}.${key}`,
        label: `${prefix}.${key}`,
        count: value.length,
        sampleKeys,
        sample: first ?? null,
      });
    });
  });

  return collections;
}

function Artifacts({
  caseId,
  caseDbPath,
  evidencePath,
  defaultExaminePreset = 'Fast Triage',
  jobs,
  onRunCommand,
  isRunning,
}) {
  const navigate = useNavigate();
  const [presetName, setPresetName] = useState(defaultExaminePreset || 'Fast Triage');
  const [selectedCollectionId, setSelectedCollectionId] = useState(null);
  const [artifactCliData, setArtifactCliData] = useState(null);
  const [artifactCliMode, setArtifactCliMode] = useState('idle');
  const [artifactCliError, setArtifactCliError] = useState(null);
  const [artifactLoadAttempted, setArtifactLoadAttempted] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState('');

  useEffect(() => {
    setPresetName(defaultExaminePreset || 'Fast Triage');
  }, [defaultExaminePreset]);

  useEffect(() => {
    const loadArtifactsFromCli = async () => {
      if (!caseId || !caseDbPath) {
        setArtifactCliData(null);
        setArtifactCliMode('idle');
        setArtifactCliError(null);
        setArtifactLoadAttempted(false);
        return;
      }

      setArtifactCliMode('loading');
      setArtifactCliError(null);

      try {
        const result = await runGuiCommand('artifacts', [
          '--case', caseId,
          '--db', caseDbPath,
          '--limit', '100',
        ]);

        if (result.ok && result.data && typeof result.data === 'object') {
          const data = result.data;
          const hasArtifacts = Array.isArray(data.artifacts) && data.artifacts.length > 0;
          const totalCount = data.total_count ?? 0;

          if (hasArtifacts || totalCount > 0) {
            setArtifactCliData(data);
            setArtifactCliMode('real');
          } else {
            setArtifactCliData(null);
            setArtifactCliMode('empty');
          }
        } else if (result.error) {
          setArtifactCliError(result.error);
          setArtifactCliMode('fallback');
        } else {
          setArtifactCliMode('fallback');
        }
      } catch (err) {
        setArtifactCliError(err?.message || 'Unknown error loading artifacts');
        setArtifactCliMode('fallback');
      }

      setArtifactLoadAttempted(true);
    };

    loadArtifactsFromCli();
  }, [caseId, caseDbPath]);

  const latestExamineJob = useMemo(
    () => jobs.find((job) => job.command === 'examine') || null,
    [jobs],
  );

  const examineSummary = useMemo(
    () => summarizeExamineJob(latestExamineJob),
    [latestExamineJob],
  );

  const artifactCollections = useMemo(
    () => findArtifactCollections(examineSummary?.data),
    [examineSummary],
  );

  const selectedCollection = useMemo(
    () => artifactCollections.find((collection) => collection.id === selectedCollectionId) || null,
    [artifactCollections, selectedCollectionId],
  );

  const outputRows = examineSummary?.outputs ? Object.entries(examineSummary.outputs) : [];
  const sizeRows = examineSummary?.sizes ? Object.entries(examineSummary.sizes) : [];

  const handleRunExamine = () => {
    if (!caseId || !caseDbPath) return;
    onRunCommand('examine', ['--case', caseId, '--db', caseDbPath, '--preset', presetName]);
  };

  const runExamineDisabledReason = getCommandDisabledReason({
    isRunning,
    requiresCaseContext: true,
    caseId,
    caseDbPath,
  });

  return (
    <div className="page artifacts">
      <header className="page-header">
        <h1>Artifacts</h1>
        <p className="page-subtitle">Artifact examination status and outputs from current CLI capabilities.</p>
      </header>

      <div className="artifacts-layout">
        <section className="panel artifacts-sidebar">
          <h2>Context</h2>
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">Case ID</span>
              <span className="info-value">{caseId || 'No case selected'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">DB Path</span>
              <span className="info-value path">{caseDbPath || 'No database path selected'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Evidence</span>
              <span className="info-value path">{evidencePath || 'No evidence selected'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Latest Examine</span>
              <span className="info-value">{latestExamineJob ? formatTimestamp(latestExamineJob.timestamp) : 'No result yet'}</span>
            </div>
          </div>

          <h3>Actions</h3>
          <div className="artifacts-toolbar">
            <input
              type="text"
              value={presetName}
              onChange={(event) => setPresetName(event.target.value)}
              className="search-input"
              placeholder="Preset name"
            />
            <button
              className="btn btn-primary"
              onClick={handleRunExamine}
              disabled={Boolean(runExamineDisabledReason)}
              title={runExamineDisabledReason}
            >
              {isRunning ? 'Running...' : 'Run Examine'}
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => navigate('/logs', { state: buildLogSelectionState(latestExamineJob?.filename) })}
              disabled={!latestExamineJob?.filename}
              title={latestExamineJob?.filename ? 'Open latest examine result in Logs.' : 'No examine result file available yet.'}
            >
              Open Logs
            </button>
          </div>
          <p className="helper-text">Examine requires current case context (Case ID and DB path).</p>
          
          <h3>Artifact Data Source</h3>
          {artifactCliMode === 'loading' && (
            <p className="info-text">Loading artifact data from database...</p>
          )}
          {artifactCliMode === 'real' && (
            <p className="success-text">
              Real artifact records loaded from database ({artifactCliData?.total_count ?? 0} total artifacts)
            </p>
          )}
          {artifactCliMode === 'empty' && (
            <p className="no-data">
              No artifact records found in database. Showing examination status only.
            </p>
          )}
          {artifactCliMode === 'fallback' && (
            <p className="no-data">
              Artifact CLI command unavailable. Showing examination status and output artifacts only.
              {artifactCliError && <span> (Error: {artifactCliError})</span>}
            </p>
          )}
          {artifactCliMode === 'idle' && caseId && caseDbPath && (
            <p className="no-data">
              No artifact data loaded. Select a case to view artifacts.
            </p>
          )}
        </section>

        <section className="panel artifacts-main">
          <h2>Latest Examine Summary</h2>

          {!caseId && (
            <p className="no-data">No case selected. Create or load a case before running examine.</p>
          )}
          {caseId && !caseDbPath && (
            <p className="no-data">No database path selected. Examine requires a valid `--db` path.</p>
          )}
          {caseId && caseDbPath && !examineSummary && (
            <p className="no-data">No examine result yet. Run Examine to capture artifact extraction status.</p>
          )}

          {examineSummary && (
            <>
              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">Status</span>
                  <span className={`status-badge status-${normalizeStatus(examineSummary.status)}`}>
                    {examineSummary.status || 'unknown'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Exit Code</span>
                  <span className="info-value">{examineSummary.exitCode ?? 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Preset</span>
                  <span className="info-value">{examineSummary.presetName || 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Session ID</span>
                  <span className="info-value">{examineSummary.sessionId || 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Violations</span>
                  <span className="info-value">{examineSummary.violationsCount ?? 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Elapsed</span>
                  <span className="info-value">{examineSummary.elapsedMs !== null ? `${examineSummary.elapsedMs} ms` : 'N/A'}</span>
                </div>
                {examineSummary.bundlePath && (
                  <div className="info-item full-width">
                    <span className="info-label">Bundle Path</span>
                    <span className="info-value path">{examineSummary.bundlePath}</span>
                  </div>
                )}
                {examineSummary.bundleHash && (
                  <div className="info-item full-width">
                    <span className="info-label">Bundle Hash</span>
                    <span className="info-value path">{examineSummary.bundleHash}</span>
                  </div>
                )}
                {examineSummary.warning && (
                  <div className="info-item full-width">
                    <span className="info-label">Warning</span>
                    <span className="info-value">{examineSummary.warning}</span>
                  </div>
                )}
                {examineSummary.error && (
                  <div className="info-item full-width">
                    <span className="info-label">Error</span>
                    <span className="info-value text-error">{examineSummary.error}</span>
                  </div>
                )}
              </div>

              {outputRows.length > 0 && (
                <div className="outputs-preview">
                  <h3>Outputs Available</h3>
                  {outputRows.map(([key, value]) => (
                    <div key={key} className="output-row">
                      <span className="output-key">{key}</span>
                      <span className="output-value">{value ? String(value) : '(empty)'}</span>
                    </div>
                  ))}
                </div>
              )}

              {sizeRows.length > 0 && (
                <div className="outputs-preview">
                  <h3>Output Sizes</h3>
                  {sizeRows.map(([key, value]) => (
                    <div key={key} className="output-row">
                      <span className="output-key">{key}</span>
                      <span className="output-value">
                        {typeof value === 'number' ? `${value.toLocaleString()} bytes` : String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {latestExamineJob?.filename && (
                <div className="analysis-actions">
                  <button
                    className="btn btn-secondary"
                    onClick={() => navigate('/logs', { state: buildLogSelectionState(latestExamineJob.filename) })}
                  >
                    Open Latest Examine Result In Logs
                  </button>
                </div>
              )}
            </>
          )}
        </section>

        <section className="panel artifact-details-panel">
          <h2>Structured Artifact Data</h2>
          
          {artifactCliMode === 'real' && artifactCliData && (
            <>
              <div className="artifacts-filter-bar">
                <label>
                  Filter by Category:
                  <select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="search-input"
                  >
                    <option value="">All Categories</option>
                    {artifactCliData.artifacts && [...new Set(artifactCliData.artifacts.map(a => a.category).filter(Boolean))].map(cat => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                </label>
                <span className="artifact-count-label">
                  Showing {artifactCliData.returned_count} of {artifactCliData.total_count} artifacts
                </span>
              </div>
              
              {artifactCliData.artifacts && artifactCliData.artifacts.length > 0 ? (
                <div className="artifacts-grid">
                  {artifactCliData.artifacts
                    .filter(a => !selectedCategory || a.category === selectedCategory)
                    .map((artifact, idx) => (
                      <div
                        key={`${artifact.artifact_type}-${idx}`}
                        className="artifact-card"
                      >
                        <div className="artifact-header">
                          <span className="artifact-name">{artifact.artifact_type}</span>
                        </div>
                        <div className="artifact-meta">
                          <span className="artifact-category">{artifact.category || 'unknown'}</span>
                          <span className="artifact-count">{artifact.count} records</span>
                        </div>
                      </div>
                    ))}
                </div>
              ) : (
                <p className="no-data">No artifacts match the selected filter.</p>
              )}
            </>
          )}
          
          {artifactCliMode !== 'real' && (
            <>
              {!examineSummary && (
                <p className="no-data">No examine result yet.</p>
              )}
              {examineSummary && artifactCollections.length === 0 && (
                <p className="no-data">
                  Structured artifact record collections were not found in the latest examine output. The current CLI result appears to provide session-level metadata and output paths only.
                </p>
              )}
              {artifactCollections.length > 0 && (
                <>
                  <div className="artifacts-grid">
                    {artifactCollections.map((collection) => (
                      <div
                        key={collection.id}
                        className={`artifact-card ${selectedCollection?.id === collection.id ? 'selected' : ''}`}
                        onClick={() => setSelectedCollectionId(collection.id)}
                      >
                        <div className="artifact-header">
                          <span className="artifact-name">{collection.label}</span>
                        </div>
                        <div className="artifact-meta">
                          <span className="artifact-count">{collection.count} records</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  {selectedCollection && (
                    <div className="info-grid">
                      <div className="info-item">
                        <span className="info-label">Collection</span>
                        <span className="info-value">{selectedCollection.label}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Record Count</span>
                        <span className="info-value">{selectedCollection.count}</span>
                      </div>
                      {selectedCollection.sampleKeys.length > 0 && (
                        <div className="info-item full-width">
                          <span className="info-label">Sample Fields</span>
                          <span className="info-value">{selectedCollection.sampleKeys.join(', ')}</span>
                        </div>
                      )}
                      {selectedCollection.sample && (
                        <div className="info-item full-width">
                          <span className="info-label">Sample Record</span>
                          <span className="info-value path">{JSON.stringify(selectedCollection.sample)}</span>
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </section>
      </div>
    </div>
  );
}

export default Artifacts;
