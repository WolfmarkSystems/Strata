import { formatLocalTimestamp } from '../lib/timeFormat'

function JobHistory({
  jobs,
  onSelectJob,
  onRefresh,
  loading = false,
  malformedCount = 0,
  ignoredCount = 0,
  error = null,
  selectedJobFilename = null,
}) {
  const getStatusClass = (status, exitCode) => {
    if (status === 'ok' || status === 'warn' || status === 'error') {
      return `status-${status}`
    }
    if (exitCode === 0) return 'status-ok'
    if (exitCode === 3) return 'status-warn'
    return 'status-error'
  }

  return (
    <div className="job-history">
      <div className="panel-header">
        <h3>Job History</h3>
        <button
          className="btn btn-secondary btn-small"
          onClick={onRefresh}
          disabled={loading}
        >
          {loading ? 'Refreshing...' : 'Refresh History'}
        </button>
      </div>
      {error && (
        <p className="no-jobs text-error">Failed to load history: {error}</p>
      )}
      {malformedCount > 0 && (
        <p className="no-jobs">Skipped malformed result files: {malformedCount}</p>
      )}
      {ignoredCount > 0 && (
        <p className="no-jobs">Ignored unrecognized JSON files in history folder: {ignoredCount}</p>
      )}
      {loading && jobs.length === 0 && (
        <p className="no-jobs">Loading history...</p>
      )}
      {jobs.length === 0 && !loading && (
        <p className="no-jobs">No history files yet.</p>
      )}
      <div className="job-list">
        {jobs.map((job, index) => (
          <button
            type="button"
            key={job.filename || index} 
            className={`job-item ${getStatusClass(job.status, job.exit_code)} ${selectedJobFilename === job.filename ? 'selected' : ''}`}
            onClick={() => onSelectJob(job)}
            aria-pressed={selectedJobFilename === job.filename}
          >
            <div className="job-header">
              <span className="job-command">{job.command}</span>
              <span className="job-exit">{job.exit_code ?? 'N/A'}</span>
            </div>
            <div className="job-meta">
              <span className="job-timestamp">{formatLocalTimestamp(job.timestamp)}</span>
              <span className={`status-badge status-${job.status || 'info'}`}>{job.status || 'unknown'}</span>
            </div>
            <div className="job-meta">
              <span className="job-timestamp" title={job.filename || ''}>{job.filename || 'No filename'}</span>
              <span className="job-filepath" title={job.filePath || ''}>{job.filePath || ''}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

export default JobHistory
