import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { COMMAND_OUTPUT_MODES, runGuiCommand } from '../lib/commandAdapter';
import { getCommandDisabledReason } from '../lib/commandGuards';
import { buildLogSelectionState, findLatestJobFilename } from '../lib/logLinks';
import { formatRelativeTime } from '../lib/timeFormat';
import { readJsonSidecar, writeJsonSidecar } from '../lib/jobHistory';
import { open } from '@tauri-apps/plugin-dialog';

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function normalizeStatus(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'ok' || value === 'pass' || value === 'success') return 'ok';
  if (value === 'warn' || value === 'warning') return 'warn';
  if (value === 'error' || value === 'fail' || value === 'failed' || value === 'missing') return 'error';
  return 'warn';
}

function matchesHashCapability(capability) {
  const name = String(capability?.name || '').toLowerCase();
  const description = String(capability?.description || '').toLowerCase();
  const text = `${name} ${description}`;
  return (
    text.includes('hash')
    || text.includes('hashset')
    || text.includes('known_good')
    || text.includes('known_bad')
    || text.includes('known good')
    || text.includes('known bad')
    || text.includes('nsrl')
    || text.includes('md5')
    || text.includes('sha1')
    || text.includes('sha256')
  );
}

function summarizeHashCapabilityStatuses(capabilities) {
  const counts = { production: 0, beta: 0, experimental: 0, stub: 0, unknown: 0 };
  capabilities.forEach((capability) => {
    const status = String(capability?.status || '').toLowerCase();
    if (Object.prototype.hasOwnProperty.call(counts, status)) {
      counts[status] += 1;
    } else {
      counts.unknown += 1;
    }
  });
  return counts;
}

function formatTimestamp(value) {
  if (!value) return 'N/A';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function HashSets({
  caseId,
  caseDbPath,
  jobs,
  onRunCommand,
  onPersistGuiCommandResult,
  isRunning = false,
}) {
  const navigate = useNavigate();
  const [hashsetListData, setHashsetListData] = useState(null);
  const [hashsetStatsData, setHashsetStatsData] = useState(null);
  const [hashsetMatchData, setHashsetMatchData] = useState(null);
  const [hashsetLoading, setHashsetLoading] = useState(false);
  const [hashsetError, setHashsetError] = useState(null);
  const [hashsetLoadAttempted, setHashsetLoadAttempted] = useState(false);
  const [nsrlPath, setNsrlPath] = useState('');
  const [knownGoodPath, setKnownGoodPath] = useState('');
  const [knownBadPath, setKnownBadPath] = useState('');
  const [hashsetLoadMeta, setHashsetLoadMeta] = useState(null);

  useEffect(() => {
    // Restore last hashset input metadata from sidecar
    (async () => {
      const meta = await readJsonSidecar('hashset_load_meta.json');
      if (meta?.inputs) {
        setNsrlPath(meta.inputs.nsrl || '');
        setKnownGoodPath(meta.inputs.known_good || '');
        setKnownBadPath(meta.inputs.known_bad || '');
        setHashsetLoadMeta(meta);
      }
    })();
  }, []);

  useEffect(() => {
    const loadHashsetData = async () => {
      if (!caseId || !caseDbPath) {
        setHashsetListData(null);
        setHashsetStatsData(null);
        setHashsetMatchData(null);
        setHashsetLoadMeta(null);
        setHashsetError(null);
        setHashsetLoadAttempted(false);
        return;
      }

      setHashsetLoading(true);
      setHashsetError(null);

      try {
        const [listResult, statsResult, matchResult] = await Promise.all([
          runGuiCommand('hashset', ['list', '--case', caseId, '--db', caseDbPath]),
          runGuiCommand('hashset', ['stats', '--case', caseId, '--db', caseDbPath]),
          runGuiCommand('hashset', ['match', '--case', caseId, '--db', caseDbPath, '--limit', '25']),
        ]);

        if (listResult.ok && listResult.data) {
          setHashsetListData(listResult.data);
          if (onPersistGuiCommandResult) {
            onPersistGuiCommandResult(
              'hashset',
              ['list', '--case', caseId, '--db', caseDbPath],
              listResult,
            );
          }
        }
        if (statsResult.ok && statsResult.data) {
          setHashsetStatsData(statsResult.data);
          if (onPersistGuiCommandResult) {
            onPersistGuiCommandResult(
              'hashset',
              ['stats', '--case', caseId, '--db', caseDbPath],
              statsResult,
            );
          }
        }
          if (matchResult.ok && matchResult.data) {
            setHashsetMatchData(matchResult.data);
            const inputs = matchResult.data?.inputs || {};
            if (inputs.nsrl) setNsrlPath(inputs.nsrl);
            if (inputs.known_good) setKnownGoodPath(inputs.known_good);
            if (inputs.known_bad) setKnownBadPath(inputs.known_bad);
            if (inputs) {
              setHashsetLoadMeta({
                ts: new Date().toISOString(),
                caseId,
                dbPath: caseDbPath,
                inputs,
                counts: matchResult.data?.hash_counts || {},
              });
              await writeJsonSidecar('hashset_load_meta.json', {
                history_format: 'hashset-load-meta-v1',
                ts: new Date().toISOString(),
                caseId,
                dbPath: caseDbPath,
                inputs,
                counts: matchResult.data?.hash_counts || {},
              });
            }
            if (onPersistGuiCommandResult) {
              onPersistGuiCommandResult(
                'hashset',
                ['match', '--case', caseId, '--db', caseDbPath, '--limit', '25'],
              matchResult,
            );
          }
        }

        if (!listResult.ok || !statsResult.ok || !matchResult.ok) {
          setHashsetError(
            listResult.error || statsResult.error || matchResult.error || 'Failed to load hashset data'
          );
        }
      } catch (err) {
        setHashsetError(err?.message || 'Unknown error loading hashset data');
      }

      setHashsetLoading(false);
      setHashsetLoadAttempted(true);
    };

    loadHashsetData();
  }, [caseId, caseDbPath]);

  const hashsetsLoaded = hashsetListData?.hashset_loaded === true;
  const derivedNsrlLoaded = hashsetListData?.nsrl_loaded
    || (hashsetMatchData?.hash_counts?.known_good_loaded > 0)
    || (hashsetLoadMeta?.counts?.known_good_loaded > 0);
  const derivedCustomLoaded = hashsetListData?.custom_loaded
    || (hashsetMatchData?.hash_counts?.known_bad_loaded > 0)
    || (hashsetLoadMeta?.counts?.known_bad_loaded > 0);
  const derivedKnownGoodCount = hashsetMatchData?.hash_counts?.known_good_loaded
    ?? hashsetLoadMeta?.counts?.known_good_loaded
    ?? hashsetListData?.known_good_count
    ?? 0;
  const derivedKnownBadCount = hashsetMatchData?.hash_counts?.known_bad_loaded
    ?? hashsetLoadMeta?.counts?.known_bad_loaded
    ?? hashsetListData?.known_bad_count
    ?? 0;
  const effectiveHashsetsLoaded = hashsetsLoaded || derivedNsrlLoaded || derivedCustomLoaded;
  const hasHashCoverage = hashsetStatsData && (
    (hashsetStatsData.files_hashed > 0) ||
    (hashsetStatsData.evidence_rows_with_hashes > 0) ||
    (hashsetStatsData.exhibits_with_hashes > 0) ||
    (hashsetStatsData.carved_files_with_hashes > 0) ||
    (hashsetStatsData.file_table_rows_with_hashes > 0)
  );

  return (
    <div className="page hash-sets">
      <header className="page-header">
        <h1>Hash Sets</h1>
        <p className="page-subtitle">
          Current hash capability status from real command outputs. This is not yet a full hash-set manager.
        </p>
      </header>

      <div className="hash-layout">
        <section className="panel hash-sets-panel">
          <div className="panel-header">
            <h2>Hash Set Engine Status</h2>
            <div className="analysis-actions">
              <div className="input-grid three-cols">
                <label className="input-item">
                  <span className="input-label">NSRL / Known Good</span>
                  <div className="input-with-button">
                    <input
                      type="text"
                      placeholder="Path to NSRL/known-good CSV or hash list"
                      value={nsrlPath}
                      onChange={(e) => setNsrlPath(e.target.value)}
                    />
                    <button
                      type="button"
                      className="btn btn-tertiary btn-small"
                      onClick={async () => {
                        const chosen = await open({ multiple: false, filters: [{ name: 'CSV/Hash', extensions: ['csv', 'txt', 'json'] }] });
                        if (typeof chosen === 'string') setNsrlPath(chosen);
                      }}
                      title="Pick NSRL/known-good file"
                    >
                      Pick
                    </button>
                  </div>
                </label>
                <label className="input-item">
                  <span className="input-label">Known Good (alt)</span>
                  <div className="input-with-button">
                    <input
                      type="text"
                      placeholder="Optional additional known-good hashes"
                      value={knownGoodPath}
                      onChange={(e) => setKnownGoodPath(e.target.value)}
                    />
                    <button
                      type="button"
                      className="btn btn-tertiary btn-small"
                      onClick={async () => {
                        const chosen = await open({ multiple: false, filters: [{ name: 'CSV/Hash', extensions: ['csv', 'txt', 'json'] }] });
                        if (typeof chosen === 'string') setKnownGoodPath(chosen);
                      }}
                      title="Pick known-good file"
                    >
                      Pick
                    </button>
                  </div>
                </label>
                <label className="input-item">
                  <span className="input-label">Known Bad</span>
                  <div className="input-with-button">
                    <input
                      type="text"
                      placeholder="Known-bad hash list or CSV"
                      value={knownBadPath}
                      onChange={(e) => setKnownBadPath(e.target.value)}
                    />
                    <button
                      type="button"
                      className="btn btn-tertiary btn-small"
                      onClick={async () => {
                        const chosen = await open({ multiple: false, filters: [{ name: 'CSV/Hash', extensions: ['csv', 'txt', 'json'] }] });
                        if (typeof chosen === 'string') setKnownBadPath(chosen);
                      }}
                      title="Pick known-bad file"
                    >
                      Pick
                    </button>
                  </div>
                </label>
              </div>
              <button
                className="btn btn-primary btn-small"
                onClick={() => {
                  if (!caseId || !caseDbPath) return;
                  setHashsetLoadAttempted(false);
                  setHashsetLoading(true);
                  const matchArgs = ['match', '--case', caseId, '--db', caseDbPath, '--limit', '25'];
                  if (nsrlPath.trim()) matchArgs.push('--nsrl', nsrlPath.trim());
                  if (knownGoodPath.trim()) matchArgs.push('--known-good', knownGoodPath.trim());
                  if (knownBadPath.trim()) matchArgs.push('--known-bad', knownBadPath.trim());

                  Promise.all([
                    runGuiCommand('hashset', ['list', '--case', caseId, '--db', caseDbPath]),
                    runGuiCommand('hashset', ['stats', '--case', caseId, '--db', caseDbPath]),
                    runGuiCommand('hashset', matchArgs),
                  ]).then(([listResult, statsResult, matchResult]) => {
                    if (listResult.ok && listResult.data) setHashsetListData(listResult.data);
                    if (statsResult.ok && statsResult.data) setHashsetStatsData(statsResult.data);
                    if (matchResult.ok && matchResult.data) setHashsetMatchData(matchResult.data);
                    if (!listResult.ok || !statsResult.ok || !matchResult.ok) {
                      setHashsetError(listResult.error || statsResult.error || matchResult.error || 'Failed to load');
                    }
                    setHashsetLoading(false);
                    setHashsetLoadAttempted(true);
                  }).catch((err) => {
                    setHashsetError(err?.message || 'Failed to load hashset data');
                    setHashsetLoading(false);
                    setHashsetLoadAttempted(true);
                  });
                }}
                disabled={!caseId || !caseDbPath || hashsetLoading}
                title={!caseId || !caseDbPath ? 'Select a case first' : 'Refresh hashset status'}
              >
                {hashsetLoading ? 'Loading...' : 'Refresh'}
              </button>
            </div>
          </div>

          {!caseId && (
            <p className="no-data">No case selected. Select a case to view hash set status.</p>
          )}
          {caseId && !caseDbPath && (
            <p className="no-data">No database path selected. Hashset commands require a valid `--db` path.</p>
          )}
          {caseId && caseDbPath && hashsetLoading && (
            <p className="info-text">Loading hash set data...</p>
          )}
          {caseId && caseDbPath && !hashsetLoading && hashsetError && (
            <div className="error-message">
              <strong>Error:</strong> {hashsetError}
            </div>
          )}

          {hashsetListData && (
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Hash Sets Loaded</span>
                <span className={`status-badge status-${effectiveHashsetsLoaded ? 'ok' : 'warn'}`}>
                  {effectiveHashsetsLoaded ? 'Yes' : 'No'}
                </span>
              </div>
              <div className="info-item">
                <span className="info-label">NSRL Loaded</span>
                <span className={`status-badge status-${derivedNsrlLoaded ? 'ok' : 'warn'}`}>
                  {derivedNsrlLoaded ? 'Yes' : 'No'}
                </span>
              </div>
              <div className="info-item">
                <span className="info-label">Custom Sets Loaded</span>
                <span className={`status-badge status-${derivedCustomLoaded ? 'ok' : 'warn'}`}>
                  {derivedCustomLoaded ? 'Yes' : 'No'}
                </span>
              </div>
              <div className="info-item">
                <span className="info-label">Known Good Hashes</span>
                <span className="info-value">{derivedKnownGoodCount}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Known Bad Hashes</span>
                <span className="info-value">{derivedKnownBadCount}</span>
              </div>
              {hashsetListData.warning && (
                <div className="info-item full-width">
                  <span className="info-label">Note</span>
                  <span className="info-value">{hashsetListData.warning}</span>
                </div>
              )}
            </div>
          )}

          {hashsetListData && hashsetListData.os_artifact_patterns && (
            <div className="outputs-preview">
              <h3>OS Artifact Patterns</h3>
              <div className="output-row">
                <span className="output-value">{hashsetListData.os_artifact_patterns.slice(0, 5).join(', ')}</span>
              </div>
              {hashsetListData.os_artifact_patterns.length > 5 && (
                <div className="output-row">
                  <span className="output-value">...and {hashsetListData.os_artifact_patterns.length - 5} more</span>
                </div>
              )}
            </div>
          )}
        </section>

        <section className="panel hash-details-panel">
          <h2>Case Hash Coverage</h2>

          {!hashsetLoadAttempted && caseId && caseDbPath && (
            <p className="no-data">Click Refresh to load hash coverage data.</p>
          )}

          {hashsetLoadAttempted && !hashsetStatsData && (
            <p className="no-data">No hash coverage data available.</p>
          )}

          {hashsetStatsData && (
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Files with SHA256</span>
                <span className="info-value">{hashsetStatsData.files_hashed ?? 0}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Evidence with Hashes</span>
                <span className="info-value">{hashsetStatsData.evidence_rows_with_hashes ?? 0}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Exhibits with Hashes</span>
                <span className="info-value">{hashsetStatsData.exhibits_with_hashes ?? 0}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Carved Files</span>
                <span className="info-value">{hashsetStatsData.carved_files_with_hashes ?? 0}</span>
              </div>
              <div className="info-item">
                <span className="info-label">File Table Rows</span>
                <span className="info-value">{hashsetStatsData.file_table_rows_with_hashes ?? 0}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Total Files in Case</span>
                <span className="info-value">{hashsetStatsData.total_files_in_case ?? 0}</span>
              </div>
              {hashsetStatsData.warning && (
                <div className="info-item full-width">
                  <span className="info-label">Note</span>
                  <span className="info-value">{hashsetStatsData.warning}</span>
                </div>
              )}
            </div>
          )}
        </section>

        <section className="panel hash-matches-panel">
          <h2>Match Results</h2>

          {hashsetMatchData && (
            <>
              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">Known Good Matches</span>
                  <span className="info-value">
                    {hashsetMatchData.match_counts?.known_good ?? hashsetStatsData?.known_good_matches ?? 0}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Known Bad Matches</span>
                  <span className="info-value">
                    {hashsetMatchData.match_counts?.known_bad ?? hashsetStatsData?.known_bad_matches ?? 0}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Unmatched</span>
                  <span className="info-value">
                    {(hashsetMatchData.match_counts?.total_hashed ?? 0)
                      - (hashsetMatchData.match_counts?.known_good ?? 0)
                      - (hashsetMatchData.match_counts?.known_bad ?? 0)}
                  </span>
                </div>
              </div>

              {hashsetStatsData?.category_breakdown && (
                <div className="outputs-preview">
                  <h3>Category Breakdown</h3>
                  <div className="output-row">
                    <span className="output-key">Known Good</span>
                    <span className="output-value">{hashsetStatsData.category_breakdown.known_good ?? 0}</span>
                  </div>
                  <div className="output-row">
                    <span className="output-key">Known Bad</span>
                    <span className="output-value">{hashsetStatsData.category_breakdown.known_bad ?? 0}</span>
                  </div>
                  <div className="output-row">
                    <span className="output-key">OS Artifact</span>
                    <span className="output-value">{hashsetStatsData.category_breakdown.os_artifact ?? 0}</span>
                  </div>
                  <div className="output-row">
                    <span className="output-key">Unknown</span>
                    <span className="output-value">{hashsetStatsData.category_breakdown.unknown ?? 0}</span>
                  </div>
                </div>
              )}
            </>
          )}

          {!hashsetsLoaded && (
            <p className="no-data">
              Matching results not available because no hash sets are currently loaded.
              Load hash sets (NSRL or custom) to enable matching.
            </p>
          )}

          <div className="button-grid" style={{ marginTop: '1rem' }}>
            <button
              className="btn btn-secondary"
              disabled
              title="CLI gap: hashset import functionality not yet implemented"
            >
              Import Hash Set (CLI Gap)
            </button>
            <button
              className="btn btn-secondary"
              disabled
              title="CLI gap: hashset export functionality not yet implemented"
            >
              Export Hash Set (CLI Gap)
            </button>
          </div>

          <div className="info-grid" style={{ marginTop: '1rem' }}>
            <div className="info-item">
              <span className="info-label">Registered Hash Commands</span>
              <span className="info-value">
                {Object.keys(COMMAND_OUTPUT_MODES).filter(cmd => 
                  cmd.includes('hash') || cmd.includes('hashset')
                ).join(', ') || 'hashset'}
              </span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

export default HashSets;
