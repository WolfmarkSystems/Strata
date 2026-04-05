import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { runGuiCommand } from '../lib/commandAdapter';
import { buildLogSelectionState, findLatestJobFilename } from '../lib/logLinks';
import { formatRelativeTime } from '../lib/timeFormat';

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function asString(value) {
  return value === null || value === undefined ? '' : String(value);
}

function formatBytes(size) {
  if (typeof size !== 'number' || Number.isNaN(size)) return '-';
  return `${size.toLocaleString()} B`;
}

function parseRowsPayload(resultData) {
  const data = asObject(resultData);
  if (!data) return { rows: null, totalCount: null, nextCursor: null };

  if (Array.isArray(data.rows)) {
    return {
      rows: data.rows,
      totalCount: typeof data.total_count === 'number' ? data.total_count : null,
      nextCursor: data.next_cursor ?? null,
    };
  }

  const nested = asObject(data.result);
  if (nested && Array.isArray(nested.rows)) {
    return {
      rows: nested.rows,
      totalCount: typeof nested.total_count === 'number' ? nested.total_count : null,
      nextCursor: nested.next_cursor ?? null,
    };
  }

  return { rows: null, totalCount: null, nextCursor: null };
}

function rowHasTruthyBoolean(row, keys) {
  return keys.some((key) => typeof row?.[key] === 'boolean' && row[key] === true);
}

function rowIsFlagged(row) {
  if (rowHasTruthyBoolean(row, ['flagged', 'is_flagged'])) return true;
  if (Array.isArray(row?.tags) && row.tags.length > 0) return true;
  return false;
}

function compareValues(left, right, sortBy) {
  if (sortBy === 'size_bytes' || sortBy === 'score') {
    const a = typeof left === 'number' ? left : Number.NEGATIVE_INFINITY;
    const b = typeof right === 'number' ? right : Number.NEGATIVE_INFINITY;
    return a - b;
  }

  if (sortBy === 'modified_utc' || sortBy === 'created_utc') {
    const a = Date.parse(asString(left));
    const b = Date.parse(asString(right));
    if (Number.isNaN(a) && Number.isNaN(b)) return 0;
    if (Number.isNaN(a)) return -1;
    if (Number.isNaN(b)) return 1;
    return a - b;
  }

  return asString(left).localeCompare(asString(right), undefined, { sensitivity: 'base' });
}

function FileExplorer({
  caseId,
  caseDbPath,
  evidencePath,
  jobs = [],
  defaultFileTableLimit = 200,
  onPersistGuiCommandResult,
}) {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);
  const [selectedRow, setSelectedRow] = useState(null);
  const [loading, setLoading] = useState(false);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [shapeError, setShapeError] = useState(null);
  const [queryError, setQueryError] = useState(null);
  const [queryWarning, setQueryWarning] = useState(null);
  const [lastQuery, setLastQuery] = useState(null);
  const [searchText, setSearchText] = useState('');
  const [extensionFilter, setExtensionFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [stateFilter, setStateFilter] = useState('all');
  const [sortBy, setSortBy] = useState('name');
  const [sortDir, setSortDir] = useState('asc');
  const [limit, setLimit] = useState(String(defaultFileTableLimit || 200));
  const canLoadFiles = Boolean(caseId && caseDbPath);
  const latestFiletableFilename = findLatestJobFilename(jobs, 'filetable');
  const loadFilesDisabledReason = loading
    ? 'File table query is currently running.'
    : !canLoadFiles
      ? 'Requires both Case ID and DB path.'
      : '';

  useEffect(() => {
    setLimit(String(defaultFileTableLimit || 200));
  }, [defaultFileTableLimit]);

  const availableExtensions = useMemo(() => {
    const unique = new Set();
    rows.forEach((row) => {
      const ext = asString(row?.extension).toLowerCase().trim();
      if (ext) unique.add(ext);
    });
    return [...unique].sort((a, b) => a.localeCompare(b));
  }, [rows]);

  const availableSourceTypes = useMemo(() => {
    const unique = new Set();
    rows.forEach((row) => {
      const sourceType = asString(row?.source_type).toLowerCase().trim();
      if (sourceType) unique.add(sourceType);
    });
    return [...unique].sort((a, b) => a.localeCompare(b));
  }, [rows]);

  const hasDeletedField = useMemo(
    () => rows.some((row) => row && (Object.prototype.hasOwnProperty.call(row, 'deleted') || Object.prototype.hasOwnProperty.call(row, 'is_deleted'))),
    [rows],
  );
  const hasCarvedSignal = useMemo(
    () => rows.some((row) => row && (Object.prototype.hasOwnProperty.call(row, 'is_carved') || asString(row?.source_type).toLowerCase() === 'carved')),
    [rows],
  );
  const hasFlaggedSignal = useMemo(
    () => rows.some((row) => row && (Object.prototype.hasOwnProperty.call(row, 'flagged') || Object.prototype.hasOwnProperty.call(row, 'is_flagged') || Array.isArray(row?.tags))),
    [rows],
  );

  const filteredRows = useMemo(() => {
    const search = searchText.trim().toLowerCase();

    return rows
      .filter((row) => {
        if (search) {
          const haystack = [
            row?.name,
            row?.path,
            row?.extension,
            row?.source_type,
            row?.category,
          ]
            .map((value) => asString(value).toLowerCase())
            .join(' ');
          if (!haystack.includes(search)) return false;
        }

        if (extensionFilter !== 'all') {
          const ext = asString(row?.extension).toLowerCase().trim();
          if (ext !== extensionFilter) return false;
        }

        if (sourceFilter !== 'all') {
          const sourceType = asString(row?.source_type).toLowerCase().trim();
          if (sourceType !== sourceFilter) return false;
        }

        if (stateFilter === 'deleted') {
          if (!rowHasTruthyBoolean(row, ['deleted', 'is_deleted'])) return false;
        }
        if (stateFilter === 'carved') {
          const carvedBool = rowHasTruthyBoolean(row, ['is_carved', 'carved']);
          const carvedSource = asString(row?.source_type).toLowerCase() === 'carved';
          if (!carvedBool && !carvedSource) return false;
        }
        if (stateFilter === 'flagged') {
          if (!rowIsFlagged(row)) return false;
        }

        return true;
      })
      .sort((left, right) => {
        const result = compareValues(left?.[sortBy], right?.[sortBy], sortBy);
        return sortDir === 'asc' ? result : result * -1;
      });
  }, [rows, searchText, extensionFilter, sourceFilter, stateFilter, sortBy, sortDir]);

  const availableStateFilters = useMemo(() => {
    const options = [{ value: 'all', label: 'All states' }];
    if (hasDeletedField) options.push({ value: 'deleted', label: 'Deleted only' });
    if (hasCarvedSignal) options.push({ value: 'carved', label: 'Carved only' });
    if (hasFlaggedSignal) options.push({ value: 'flagged', label: 'Flagged only' });
    return options;
  }, [hasDeletedField, hasCarvedSignal, hasFlaggedSignal]);

  useEffect(() => {
    if (!selectedRow) return;
    const stillVisible = filteredRows.some((row) => row === selectedRow);
    if (!stillVisible) {
      setSelectedRow(filteredRows[0] || null);
    }
  }, [filteredRows, selectedRow]);

  const handleResetFilters = () => {
    setSearchText('');
    setExtensionFilter('all');
    setSourceFilter('all');
    setStateFilter('all');
    setSortBy('name');
    setSortDir('asc');
  };

  const handleLoadFiles = async () => {
    setHasLoaded(true);
    setShapeError(null);
    setQueryError(null);
    setQueryWarning(null);
    setLoading(true);

    if (!caseId) {
      setRows([]);
      setQueryError('No case selected. File table queries require a case ID.');
      setLoading(false);
      return;
    }

    if (!caseDbPath) {
      setRows([]);
      setQueryError('No case database path selected. File table queries require --db.');
      setLoading(false);
      return;
    }

    const parsedLimit = Number.parseInt(limit, 10);
    const safeLimit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? parsedLimit : 200;
    const args = ['--case', caseId, '--db', caseDbPath, '--limit', String(safeLimit), '--json'];

    try {
      const result = await runGuiCommand('filetable', args);
      if (onPersistGuiCommandResult) {
        await onPersistGuiCommandResult('filetable', args, result);
      }

      const payload = parseRowsPayload(result.data);
      const rowCount = Array.isArray(payload.rows) ? payload.rows.length : 0;

      setLastQuery({
        mode: result.mode,
        status: result.status || (result.ok ? 'ok' : 'error'),
        exitCode: result.exitCode,
        fetchedAt: new Date().toISOString(),
        rowCount,
        totalCount: payload.totalCount,
        nextCursor: payload.nextCursor,
      });

      setQueryWarning(result.warning || null);

      if (!result.ok) {
        setRows([]);
        setSelectedRow(null);
        setQueryError(result.error || 'File table query failed.');
        return;
      }

      if (!Array.isArray(payload.rows)) {
        setRows([]);
        setSelectedRow(null);
        setShapeError('CLI returned structured JSON, but no usable rows array was found.');
        return;
      }

      setRows(payload.rows);
      setSelectedRow(payload.rows[0] || null);
      setShapeError(null);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setRows([]);
      setSelectedRow(null);
      setQueryError(`Failed to load file table: ${message}`);
    } finally {
      setLoading(false);
    }
  };

  const selectedDetails = useMemo(() => {
    if (!selectedRow) return [];
    const fields = [
      ['ID', selectedRow.id],
      ['Name', selectedRow.name],
      ['Path', selectedRow.path],
      ['Source Type', selectedRow.source_type],
      ['Source ID', selectedRow.source_id],
      ['Evidence ID', selectedRow.evidence_id],
      ['Volume ID', selectedRow.volume_id],
      ['Extension', selectedRow.extension],
      ['Size', typeof selectedRow.size_bytes === 'number' ? `${selectedRow.size_bytes.toLocaleString()} bytes` : selectedRow.size_bytes],
      ['Modified', selectedRow.modified_utc],
      ['Created', selectedRow.created_utc],
      ['Entropy', typeof selectedRow.entropy === 'number' ? selectedRow.entropy.toFixed(3) : selectedRow.entropy],
      ['Category', selectedRow.category],
      ['Score', typeof selectedRow.score === 'number' ? selectedRow.score.toFixed(3) : selectedRow.score],
      ['Tags', Array.isArray(selectedRow.tags) ? selectedRow.tags.join(', ') : selectedRow.tags],
    ];

    return fields.filter(([, value]) => value !== undefined && value !== null && `${value}`.trim() !== '');
  }, [selectedRow]);

  return (
    <div className="page file-explorer">
      <header className="page-header">
        <h1>File Explorer</h1>
        <p className="page-subtitle">Read-only file table view from current CLI output (`filetable --json`).</p>
      </header>

      <div className="explorer-layout">
        <section className="panel explorer-toolbar">
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
              <span className="info-label">Evidence Path</span>
              <span className="info-value path">{evidencePath || 'No evidence selected'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Last Query</span>
              <span className="info-value">
                {!lastQuery ? 'No file query yet' : `${lastQuery.status} (mode: ${lastQuery.mode}, exit: ${lastQuery.exitCode ?? 'N/A'})`}
              </span>
            </div>
            <div className="info-item">
              <span className="info-label">Last Query Age</span>
              <span className="info-value">{lastQuery?.fetchedAt ? formatRelativeTime(lastQuery.fetchedAt) : 'N/A'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Latest Result File</span>
              <span className="info-value">{latestFiletableFilename || 'No filetable history file yet'}</span>
            </div>
          </div>

          <div className="toolbar-row">
            <label className="filter-label" htmlFor="file-limit">Limit</label>
            <input
              id="file-limit"
              type="number"
              min="1"
              step="1"
              value={limit}
              onChange={(event) => setLimit(event.target.value)}
              className="setting-input"
            />
            <button
              className="btn btn-primary"
              onClick={handleLoadFiles}
              disabled={Boolean(loadFilesDisabledReason)}
              title={loadFilesDisabledReason}
            >
              {loading ? 'Loading...' : 'Load Files'}
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => navigate('/logs', { state: buildLogSelectionState(latestFiletableFilename) })}
              disabled={!latestFiletableFilename}
              title={latestFiletableFilename ? `Open ${latestFiletableFilename} in Logs.` : 'No filetable result file yet.'}
            >
              Open Latest Filetable In Logs
            </button>
          </div>
          <p className="helper-text">File queries require Case ID and DB path. Evidence path helps workflow context but is not required by this command.</p>

          <div className="toolbar-row">
            <input
              type="text"
              placeholder="Search by name, path, extension, source..."
              value={searchText}
              onChange={(event) => setSearchText(event.target.value)}
              className="filter-input"
            />
            <select
              value={extensionFilter}
              onChange={(event) => setExtensionFilter(event.target.value)}
              className="setting-select"
            >
              <option value="all">All extensions</option>
              {availableExtensions.map((extension) => (
                <option key={extension} value={extension}>
                  {extension}
                </option>
              ))}
            </select>
            <select
              value={sourceFilter}
              onChange={(event) => setSourceFilter(event.target.value)}
              className="setting-select"
            >
              <option value="all">All source types</option>
              {availableSourceTypes.map((sourceType) => (
                <option key={sourceType} value={sourceType}>
                  {sourceType}
                </option>
              ))}
            </select>
            <select
              value={stateFilter}
              onChange={(event) => setStateFilter(event.target.value)}
              className="setting-select"
            >
              {availableStateFilters.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <select
              value={sortBy}
              onChange={(event) => setSortBy(event.target.value)}
              className="setting-select"
            >
              <option value="name">Sort: Name</option>
              <option value="path">Sort: Path</option>
              <option value="source_type">Sort: Source Type</option>
              <option value="extension">Sort: Extension</option>
              <option value="size_bytes">Sort: Size</option>
              <option value="modified_utc">Sort: Modified</option>
              <option value="created_utc">Sort: Created</option>
              <option value="score">Sort: Score</option>
            </select>
            <select
              value={sortDir}
              onChange={(event) => setSortDir(event.target.value)}
              className="setting-select"
            >
              <option value="asc">Asc</option>
              <option value="desc">Desc</option>
            </select>
            <button className="btn btn-secondary" type="button" onClick={handleResetFilters}>
              Reset Filters
            </button>
          </div>

          <div className="toolbar-row">
            <span className="info-value">
              Rows shown: {filteredRows.length}
              {lastQuery?.totalCount !== null && lastQuery?.totalCount !== undefined ? ` / total: ${lastQuery.totalCount}` : ''}
            </span>
            {lastQuery?.nextCursor && (
              <span className="info-value">More rows may be available (next cursor present).</span>
            )}
          </div>
        </section>

        <section className="panel file-list-panel">
          {queryError && (
            <div className="error-message">
              <strong>File table query failed:</strong> {queryError}
            </div>
          )}
          {queryWarning && (
            <div className="warning-message">
              <strong>Warning:</strong> {queryWarning}
            </div>
          )}
          {shapeError && (
            <div className="warning-message">
              <strong>Result shape:</strong> {shapeError}
            </div>
          )}
          {!caseId && !loading && (
            <p className="no-data">No case selected. Set Case ID and DB path in Case Overview first.</p>
          )}
          {!!caseId && !caseDbPath && !loading && (
            <p className="no-data">No database path selected. File table requires a valid `--db` path.</p>
          )}
          {caseId && caseDbPath && !hasLoaded && !loading && (
            <p className="no-data">No file data loaded yet. Click Load Files to query `filetable --json`.</p>
          )}
          {hasLoaded && !loading && rows.length === 0 && !queryError && !shapeError && (
            <p className="no-data">
              File table returned no rows. The case may not be indexed yet or no matching file records are available.
            </p>
          )}
          {hasLoaded && !loading && rows.length > 0 && filteredRows.length === 0 && (
            <p className="no-data">No file rows match the active filters.</p>
          )}

          {filteredRows.length > 0 && (
            <table className="file-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Path</th>
                  <th>Source</th>
                  <th>Ext</th>
                  <th>Size</th>
                  <th>Modified</th>
                  <th>Score</th>
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((row, index) => {
                  const isSelected = row === selectedRow || (selectedRow?.id !== undefined && selectedRow?.id === row?.id)
                  return (
                    <tr
                      key={`${row?.id ?? 'row'}-${index}`}
                      className={`file-row ${isSelected ? 'selected' : ''}`}
                      onClick={() => setSelectedRow(row)}
                    >
                      <td className="file-name">{row?.name || '-'}</td>
                      <td className="file-path">{row?.path || '-'}</td>
                      <td>{row?.source_type || '-'}</td>
                      <td>{row?.extension || '-'}</td>
                      <td>{formatBytes(row?.size_bytes)}</td>
                      <td>{row?.modified_utc || '-'}</td>
                      <td>{typeof row?.score === 'number' ? row.score.toFixed(3) : '-'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel file-details-panel">
          <h2>Row Details</h2>
          {!selectedRow && (
            <p className="no-data">Select a row to view available fields.</p>
          )}
          {selectedRow && (
            <div className="file-details">
              <p className="no-data">Read-only view. Metadata shown only if returned by current filetable output.</p>
              <div className="info-grid">
                {selectedDetails.map(([label, value]) => (
                  <div key={label} className="info-item">
                    <span className="info-label">{label}</span>
                    <span className={`info-value ${label === 'Path' ? 'path' : ''}`}>{String(value)}</span>
                  </div>
                ))}
              </div>
              {selectedRow.summary !== undefined && (
                <div className="result-section">
                  <div className="section-header">
                    <span>Summary JSON</span>
                  </div>
                  <div className="section-content json-content">
                    <pre>{JSON.stringify(selectedRow.summary, null, 2)}</pre>
                  </div>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

export default FileExplorer;
