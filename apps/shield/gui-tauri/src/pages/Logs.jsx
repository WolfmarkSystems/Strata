import { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import JobHistory from '../components/JobHistory';
import ResultViewer from '../components/ResultViewer';
import { formatLocalTimestamp, formatRelativeTime, formatUtcIsoSeconds } from '../lib/timeFormat';
import { findJobByFilename, normalizeJobFilename } from '../lib/logLinks';
import { getCommandNavigationTarget, getRouteLabel } from '../lib/commandRouting';

const LOGS_FILTERS_STORAGE_KEY = 'forensic-suite.logs-filters.v1';

function loadLogsFilters() {
  try {
    const raw = localStorage.getItem(LOGS_FILTERS_STORAGE_KEY);
    if (!raw) return { filter: 'all', commandFilter: 'all', searchText: '', fromUtc: '', toUtc: '' };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { filter: 'all', commandFilter: 'all', searchText: '', fromUtc: '', toUtc: '' };
    return {
      filter: typeof parsed.filter === 'string' ? parsed.filter : 'all',
      commandFilter: typeof parsed.commandFilter === 'string' ? parsed.commandFilter : 'all',
      searchText: typeof parsed.searchText === 'string' ? parsed.searchText : '',
      fromUtc: typeof parsed.fromUtc === 'string' ? parsed.fromUtc : '',
      toUtc: typeof parsed.toUtc === 'string' ? parsed.toUtc : '',
    };
  } catch {
    return { filter: 'all', commandFilter: 'all', searchText: '', fromUtc: '', toUtc: '' };
  }
}

function persistLogsFilters(next) {
  try {
    localStorage.setItem(LOGS_FILTERS_STORAGE_KEY, JSON.stringify(next));
  } catch {
    // Non-fatal: filters continue without persistence.
  }
}

function parseEpoch(value) {
  const parsed = Date.parse(String(value || ''));
  return Number.isNaN(parsed) ? null : parsed;
}

function Logs({
  jobs,
  currentResult,
  isRunning,
  activeCommand,
  isHistoryLoading,
  historyMalformedCount,
  historyIgnoredCount,
  historyError,
  onRefreshHistory,
}) {
  const location = useLocation();
  const navigate = useNavigate();
  const [initialFilters] = useState(() => loadLogsFilters());
  const [selectedJob, setSelectedJob] = useState(null);
  const [filter, setFilter] = useState(initialFilters.filter);
  const [commandFilter, setCommandFilter] = useState(initialFilters.commandFilter);
  const [searchText, setSearchText] = useState(initialFilters.searchText);
  const [fromUtc, setFromUtc] = useState(initialFilters.fromUtc);
  const [toUtc, setToUtc] = useState(initialFilters.toUtc);
  const [linkSelectionWarning, setLinkSelectionWarning] = useState('');
  const [copyFeedback, setCopyFeedback] = useState('');

  const normalizedSearch = searchText.trim().toLowerCase();
  const fromEpoch = parseEpoch(fromUtc);
  const toEpoch = parseEpoch(toUtc);

  const availableCommands = useMemo(
    () => ['all', ...Array.from(new Set(jobs.map((job) => String(job.command || '').trim()).filter(Boolean)))],
    [jobs],
  );

  const filterCounts = {
    all: jobs.length,
    success: jobs.filter((job) => job.status === 'ok').length,
    warning: jobs.filter((job) => job.status === 'warn').length,
    error: jobs.filter((job) => job.status === 'error').length,
  };

  const filteredJobs = jobs.filter(j => {
    if (filter === 'all') return true;
    if (filter === 'success' && j.status !== 'ok') return false;
    if (filter === 'warning' && j.status !== 'warn') return false;
    if (filter === 'error' && j.status !== 'error') return false;

    return true;
  }).filter((job) => {
    const timestampEpoch = parseEpoch(job.timestamp);
    if ((fromEpoch !== null || toEpoch !== null) && timestampEpoch === null) return false;
    if (fromEpoch !== null && timestampEpoch !== null && timestampEpoch < fromEpoch) return false;
    if (toEpoch !== null && timestampEpoch !== null && timestampEpoch > toEpoch) return false;
    if (commandFilter !== 'all' && job.command !== commandFilter) return false;
    if (!normalizedSearch) return true;
    const haystack = [
      job.command,
      job.filename,
      job.filePath,
      job.status,
      String(job.exit_code ?? ''),
    ]
      .map((value) => String(value || '').toLowerCase())
      .join(' ');
    return haystack.includes(normalizedSearch);
  });

  const handleJobSelect = (job) => {
    setSelectedJob(job);
  };
  const setQuickWindow = (hours) => {
    const now = new Date();
    const from = new Date(now.getTime() - (hours * 60 * 60 * 1000));
    setFromUtc(formatUtcIsoSeconds(from));
    setToUtc(formatUtcIsoSeconds(now));
  };
  const clearFilters = () => {
    setFilter('all');
    setCommandFilter('all');
    setSearchText('');
    setFromUtc('');
    setToUtc('');
  };
  const copyToClipboard = async (text, label) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopyFeedback(`${label} copied.`);
    } catch {
      setCopyFeedback(`Unable to copy ${label.toLowerCase()} in this environment.`);
    }
  };
  const selectedNavigationTarget = getCommandNavigationTarget(selectedJob?.command);
  const selectedRoute = selectedNavigationTarget.route;
  const selectedRouteLabel = getRouteLabel(selectedRoute);
  const selectedArgs = Array.isArray(selectedJob?.data?.args) ? selectedJob.data.args : [];
  const selectedWarning = selectedJob?.data?.warning || null;
  const selectedError = selectedJob?.data?.error || null;
  const selectedRelativeTime = selectedJob?.timestamp ? formatRelativeTime(selectedJob.timestamp) : 'N/A';
  const filteredSummary = useMemo(() => {
    const warnCount = filteredJobs.filter((job) => job.status === 'warn').length;
    const errorCount = filteredJobs.filter((job) => job.status === 'error').length;
    const uniqueCommands = new Set(filteredJobs.map((job) => job.command)).size;
    return { warnCount, errorCount, uniqueCommands };
  }, [filteredJobs]);

  useEffect(() => {
    persistLogsFilters({ filter, commandFilter, searchText, fromUtc, toUtc });
  }, [filter, commandFilter, searchText, fromUtc, toUtc]);

  useEffect(() => {
    if (!copyFeedback) return undefined;
    const timer = setTimeout(() => setCopyFeedback(''), 1800);
    return () => clearTimeout(timer);
  }, [copyFeedback]);

  useEffect(() => {
    if (filteredJobs.length === 0) {
      setSelectedJob(null);
      return;
    }
    if (!selectedJob?.filename) {
      setSelectedJob(filteredJobs[0]);
      return;
    }
    const refreshedSelection = filteredJobs.find((job) => job.filename === selectedJob.filename);
    setSelectedJob(refreshedSelection || filteredJobs[0]);
  }, [filteredJobs, selectedJob?.filename]);

  useEffect(() => {
    if (commandFilter === 'all') return;
    if (!availableCommands.includes(commandFilter)) {
      setCommandFilter('all');
    }
  }, [commandFilter, availableCommands]);

  useEffect(() => {
    const requestedFilename = normalizeJobFilename(location?.state?.selectJobFilename);
    if (!requestedFilename) return;

    setFilter('all');
    setCommandFilter('all');
    setSearchText('');
    setFromUtc('');
    setToUtc('');

    const linkedJob = findJobByFilename(jobs, requestedFilename);
    if (linkedJob) {
      setSelectedJob(linkedJob);
      setLinkSelectionWarning('');
    } else {
      setLinkSelectionWarning(`Linked result file '${requestedFilename}' was not found in current history.`);
    }

    const nextState = { ...(location?.state || {}) };
    delete nextState.selectJobFilename;
    navigate(location.pathname, {
      replace: true,
      state: Object.keys(nextState).length > 0 ? nextState : null,
    });
  }, [location?.pathname, location?.state, jobs, navigate]);

  return (
    <div className="page logs">
      <header className="page-header">
        <h1>Logs</h1>
        <p className="page-subtitle">Durable command history and result envelopes.</p>
      </header>

      <div className="logs-layout">
        <section className="panel logs-sidebar">
          <h2>Job History</h2>
          <div className="filter-buttons">
            <button 
              className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
              onClick={() => setFilter('all')}
            >
              All ({filterCounts.all})
            </button>
            <button 
              className={`filter-btn ${filter === 'success' ? 'active' : ''}`}
              onClick={() => setFilter('success')}
            >
              OK ({filterCounts.success})
            </button>
            <button 
              className={`filter-btn ${filter === 'warning' ? 'active' : ''}`}
              onClick={() => setFilter('warning')}
            >
              Warn ({filterCounts.warning})
            </button>
            <button 
              className={`filter-btn ${filter === 'error' ? 'active' : ''}`}
              onClick={() => setFilter('error')}
            >
              Error ({filterCounts.error})
            </button>
          </div>
          <input
            type="text"
            className="filter-input logs-search-input"
            placeholder="Search command, status, file..."
            value={searchText}
            onChange={(event) => setSearchText(event.target.value)}
          />
          <div className="analysis-actions">
            <select
              className="setting-select"
              value={commandFilter}
              onChange={(event) => setCommandFilter(event.target.value)}
            >
              {availableCommands.map((command) => (
                <option key={command} value={command}>
                  {command === 'all' ? 'All commands' : command}
                </option>
              ))}
            </select>
            <button
              className="btn btn-secondary btn-small"
              onClick={clearFilters}
            >
              Clear Filters
            </button>
            <button className="btn btn-secondary btn-small" onClick={() => setQuickWindow(24)}>
              Last 24h
            </button>
            <button className="btn btn-secondary btn-small" onClick={() => setQuickWindow(24 * 7)}>
              Last 7d
            </button>
          </div>
          <div className="analysis-actions">
            <input
              type="text"
              className="filter-input logs-search-input"
              placeholder="From UTC (optional)"
              value={fromUtc}
              onChange={(event) => setFromUtc(event.target.value)}
            />
            <input
              type="text"
              className="filter-input logs-search-input"
              placeholder="To UTC (optional)"
              value={toUtc}
              onChange={(event) => setToUtc(event.target.value)}
            />
          </div>
          <p className="helper-text">Showing {filteredJobs.length} of {jobs.length} jobs.</p>
          <div className="info-grid compact-grid">
            <div className="info-item">
              <span className="info-label">Warnings</span>
              <span className="info-value">{filteredSummary.warnCount}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Errors</span>
              <span className="info-value">{filteredSummary.errorCount}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Commands</span>
              <span className="info-value">{filteredSummary.uniqueCommands}</span>
            </div>
          </div>
          {linkSelectionWarning && (
            <div className="analysis-actions">
              <p className="no-jobs text-error">{linkSelectionWarning}</p>
              <button className="btn btn-secondary btn-small" onClick={() => setLinkSelectionWarning('')}>
                Dismiss
              </button>
            </div>
          )}
          {copyFeedback && <p className="helper-text">{copyFeedback}</p>}
          <JobHistory 
            jobs={filteredJobs} 
            onSelectJob={handleJobSelect}
            onRefresh={onRefreshHistory}
            loading={isHistoryLoading}
            malformedCount={historyMalformedCount}
            ignoredCount={historyIgnoredCount}
            error={historyError}
            selectedJobFilename={selectedJob?.filename || null}
          />
        </section>

        <section className="panel logs-main">
          <h2>Result</h2>
          {isRunning ? (
            <div className="running-indicator">
              <div className="spinner"></div>
              <span>Running: {activeCommand}...</span>
            </div>
          ) : selectedJob ? (
            <>
              <div className="info-grid compact-grid">
                <div className="info-item">
                  <span className="info-label">Command</span>
                  <span className="info-value">{selectedJob.command || 'Unknown'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Status</span>
                  <span className={`status-badge status-${selectedJob.status || 'info'}`}>{selectedJob.status || 'unknown'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Timestamp</span>
                  <span className="info-value">{formatLocalTimestamp(selectedJob.timestamp)}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Age</span>
                  <span className="info-value">{selectedRelativeTime}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Exit Code</span>
                  <span className="info-value">{selectedJob.exit_code ?? 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Record Type</span>
                  <span className="info-value">{selectedJob.record_type || 'cli_envelope'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Source Mode</span>
                  <span className="info-value">{selectedJob.source_mode || 'envelope'}</span>
                </div>
              </div>
              <div className="json-path">
                Result file: {selectedJob.filename || 'N/A'} ({selectedJob.filePath || 'path unavailable'})
              </div>
              <div className="analysis-actions">
                <button
                  className="btn btn-secondary btn-small"
                  onClick={() => navigate(selectedRoute, selectedNavigationTarget.state ? { state: selectedNavigationTarget.state } : undefined)}
                >
                  Open {selectedRouteLabel}
                </button>
                <button
                  className="btn btn-secondary btn-small"
                  onClick={() => copyToClipboard(selectedJob.filename, 'Filename')}
                  disabled={!selectedJob.filename}
                >
                  Copy Filename
                </button>
                <button
                  className="btn btn-secondary btn-small"
                  onClick={() => copyToClipboard(selectedJob.filePath, 'Path')}
                  disabled={!selectedJob.filePath}
                >
                  Copy Path
                </button>
              </div>
              {selectedArgs.length > 0 && (
                <div className="info-grid compact-grid">
                  <div className="info-item full-width">
                    <span className="info-label">Command Args</span>
                    <span className="info-value path">{selectedArgs.join(' ')}</span>
                  </div>
                </div>
              )}
              {selectedWarning && (
                <div className="warning-message">
                  <strong>Warning:</strong> {selectedWarning}
                </div>
              )}
              {selectedError && (
                <div className="error-message">
                  <strong>Error:</strong> {selectedError}
                </div>
              )}
              <ResultViewer
                result={{
                  exit_code: selectedJob.exit_code,
                  envelope_json: selectedJob.data,
                  stdout: selectedJob.data?.raw?.stdout || '',
                  stderr: selectedJob.data?.raw?.stderr || '',
                }}
                previousResult={null}
              />
            </>
          ) : currentResult ? (
            <ResultViewer 
              result={currentResult}
              previousResult={null}
            />
          ) : (
            <p className="no-data">Select a job from the history or run a command to see results.</p>
          )}
        </section>
      </div>
    </div>
  );
}

export default Logs;
