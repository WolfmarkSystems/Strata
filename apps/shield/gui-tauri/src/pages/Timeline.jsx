import { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { formatLocalTimestamp } from '../lib/timeFormat';
import { runGuiCommand } from '../lib/commandAdapter';
import {
  buildLogSelectionState,
  findLatestJobFilename,
  resolveTimelineEntryJobFilename,
} from '../lib/logLinks';
import { getRouteLabel, getTimelineEntryRoute } from '../lib/commandRouting';

const TIMELINE_CONTROLS_STORAGE_KEY = 'forensic-suite.timeline-controls.v1';
const DEFAULT_TIMELINE_CONTROLS = Object.freeze({
  searchText: '',
  typeFilter: 'all',
  severityFilter: 'all',
  sourceFilter: 'all',
  linkedOnly: false,
  querySource: 'all',
  queryLimit: '200',
  queryFromUtc: '',
  queryToUtc: '',
});

function loadTimelineControls() {
  try {
    const raw = localStorage.getItem(TIMELINE_CONTROLS_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_TIMELINE_CONTROLS };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { ...DEFAULT_TIMELINE_CONTROLS };

    const source = String(parsed.querySource || 'all').toLowerCase();
    const safeQuerySource = ['all', 'activity', 'evidence', 'violations', 'execution'].includes(source) ? source : 'all';
    const severity = String(parsed.severityFilter || 'all').toLowerCase();
    const safeSeverity = ['all', 'ok', 'warn', 'error', 'info'].includes(severity) ? severity : 'all';

    return {
      searchText: typeof parsed.searchText === 'string' ? parsed.searchText : '',
      typeFilter: typeof parsed.typeFilter === 'string' ? parsed.typeFilter : 'all',
      severityFilter: safeSeverity,
      sourceFilter: typeof parsed.sourceFilter === 'string' ? parsed.sourceFilter : 'all',
      linkedOnly: parsed.linkedOnly === true,
      querySource: safeQuerySource,
      queryLimit: typeof parsed.queryLimit === 'string' ? parsed.queryLimit : '200',
      queryFromUtc: typeof parsed.queryFromUtc === 'string' ? parsed.queryFromUtc : '',
      queryToUtc: typeof parsed.queryToUtc === 'string' ? parsed.queryToUtc : '',
    };
  } catch {
    return { ...DEFAULT_TIMELINE_CONTROLS };
  }
}

function persistTimelineControls(controls) {
  try {
    localStorage.setItem(TIMELINE_CONTROLS_STORAGE_KEY, JSON.stringify(controls));
  } catch {
    // Non-fatal. Timeline remains usable without local persistence.
  }
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function normalizeStatus(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'ok' || value === 'pass' || value === 'success') return 'ok';
  if (value === 'warn' || value === 'warning') return 'warn';
  if (value === 'error' || value === 'fail' || value === 'failed') return 'error';
  return 'info';
}

function parseTimestamp(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  // Rust timestamps may include nanoseconds. JS Date handles milliseconds.
  const normalized = trimmed.replace(/\.(\d{3})\d+(?=(Z|[+-]\d{2}:\d{2})$)/, '.$1');
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return null;
  return {
    iso: date.toISOString(),
    epochMs: date.getTime(),
  };
}

function firstValidTimestamp(...candidates) {
  for (const candidate of candidates) {
    const parsed = parseTimestamp(candidate);
    if (parsed) return parsed;
  }
  return null;
}

function parseTimelineLimit(value) {
  const parsed = Number.parseInt(String(value || ''), 10);
  if (!Number.isFinite(parsed)) return 200;
  return Math.max(1, Math.min(parsed, 2000));
}

function toUtcIsoString(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function downloadJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

function mapTimelineType(source, eventType) {
  const sourceValue = String(source || '').toLowerCase();
  if (sourceValue === 'violations') return 'violation';
  if (sourceValue === 'activity') return 'activity';
  if (sourceValue === 'evidence') return 'evidence';
  if (sourceValue === 'execution') return 'execution';
  if (eventType) return String(eventType);
  return 'timeline-event';
}

function describeTimelineCommandEvent(event) {
  const parts = [];
  if (event?.summary) parts.push(String(event.summary));
  if (event?.event_type) parts.push(`type: ${event.event_type}`);
  if (event?.event_category) parts.push(`category: ${event.event_category}`);
  if (event?.table_name) parts.push(`table: ${event.table_name}`);
  if (event?.operation) parts.push(`operation: ${event.operation}`);
  if (event?.reason) parts.push(`reason: ${event.reason}`);
  if (event?.source_module) parts.push(`module: ${event.source_module}`);
  if (parts.length === 0) parts.push('Timeline event from CLI timeline command.');
  return parts.join(' | ');
}

function buildTimelineCommandEntries(payload, sourceJobFilename = null) {
  const events = Array.isArray(payload?.events) ? payload.events : [];
  const entries = events
    .map((event, index) => {
      const timestamp = firstValidTimestamp(event?.timestamp_utc);
      if (!timestamp) return null;

      const source = String(event?.source || 'timeline');
      const eventType = String(event?.event_type || 'event');
      const summary = String(event?.summary || '').trim();
      const title = summary || `${source} ${eventType}`;

      return {
        id: String(event?.id || `${source}-${timestamp.epochMs}-${index}`),
        timestamp: timestamp.iso,
        type: mapTimelineType(source, eventType),
        title,
        description: describeTimelineCommandEvent(event),
        source,
        severity: normalizeStatus(event?.severity || 'info'),
        sourceJobFilename,
      };
    })
    .filter(Boolean);

  entries.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  return entries;
}

function describeVerify(data, envelope) {
  const checks = Array.isArray(data?.checks) ? data.checks : [];
  const warnChecks = checks.filter((check) => String(check?.status || '').toLowerCase() === 'warn').length;
  const failChecks = checks.filter((check) => {
    const status = String(check?.status || '').toLowerCase();
    return status === 'fail' || status === 'error' || status === 'missing';
  }).length;
  const parts = [];
  if (data?.status) parts.push(`status: ${data.status}`);
  if (checks.length > 0) parts.push(`checks: ${checks.length}`);
  if (warnChecks > 0) parts.push(`warn: ${warnChecks}`);
  if (failChecks > 0) parts.push(`fail/missing: ${failChecks}`);
  if (envelope?.warning) parts.push(`warning: ${envelope.warning}`);
  return parts.join(' | ');
}

function describeTriage(data, envelope) {
  const result = asObject(data?.result);
  const parts = [];
  if (result?.status) parts.push(`status: ${result.status}`);
  if (result?.session_id) parts.push(`session: ${result.session_id}`);
  if (result?.violations_count !== undefined) parts.push(`violations: ${result.violations_count}`);
  if (result?.bundle_path) parts.push(`bundle: ${result.bundle_path}`);
  if (envelope?.warning) parts.push(`warning: ${envelope.warning}`);
  return parts.join(' | ');
}

function describeExamine(data, envelope) {
  const result = asObject(data?.result);
  const parts = [];
  if (data?.preset_name) parts.push(`preset: ${data.preset_name}`);
  if (result?.status) parts.push(`status: ${result.status}`);
  if (result?.session_id) parts.push(`session: ${result.session_id}`);
  if (result?.violations_count !== undefined) parts.push(`violations: ${result.violations_count}`);
  if (result?.bundle_path || envelope?.outputs?.bundle_zip) {
    parts.push(`bundle: ${result?.bundle_path || envelope.outputs.bundle_zip}`);
  }
  if (envelope?.warning) parts.push(`warning: ${envelope.warning}`);
  return parts.join(' | ');
}

function describeSmoke(data, envelope) {
  const parts = [];
  if (data?.status) parts.push(`status: ${data.status}`);
  if (data?.container_type) parts.push(`container: ${data.container_type}`);
  if (data?.analysis_mode) parts.push(`mode: ${data.analysis_mode}`);
  if (typeof data?.analysis_valid === 'boolean') parts.push(`analysis valid: ${data.analysis_valid ? 'yes' : 'no'}`);
  if (envelope?.warning) parts.push(`warning: ${envelope.warning}`);
  return parts.join(' | ');
}

function describeOpenEvidence(data, envelope) {
  const container = asObject(data?.container_type);
  const warnings = Array.isArray(data?.warnings) ? data.warnings.length : 0;
  const errors = Array.isArray(data?.errors) ? data.errors.length : 0;
  const parts = [];
  if (data?.evidence_id) parts.push(`evidence id: ${data.evidence_id}`);
  if (container?.container_type) parts.push(`container: ${container.container_type}`);
  if (warnings > 0) parts.push(`warnings: ${warnings}`);
  if (errors > 0) parts.push(`errors: ${errors}`);
  if (envelope?.warning) parts.push(`warning: ${envelope.warning}`);
  return parts.join(' | ');
}

function describeViolations(data, envelope) {
  const list = Array.isArray(data?.violations) ? data.violations : [];
  const total = data?.total_returned ?? list.length;
  const parts = [`returned: ${total}`];
  if (data?.since_utc) parts.push(`since: ${data.since_utc}`);
  if (data?.limit !== undefined) parts.push(`limit: ${data.limit}`);
  if (envelope?.warning) parts.push(`warning: ${envelope.warning}`);
  return parts.join(' | ');
}

function describeExecution(data, envelope) {
  const total = data?.total_returned;
  const available = data?.total_available;
  const sourceRows = asObject(data?.source_rows);
  const parts = [];
  if (typeof total === 'number') parts.push(`returned: ${total}`);
  if (typeof available === 'number') parts.push(`available: ${available}`);
  if (typeof sourceRows?.prefetch === 'number') parts.push(`prefetch rows: ${sourceRows.prefetch}`);
  if (typeof sourceRows?.jumplist === 'number') parts.push(`jumplist rows: ${sourceRows.jumplist}`);
  if (typeof sourceRows?.shortcut === 'number') parts.push(`shortcut rows: ${sourceRows.shortcut}`);
  if (envelope?.warning) parts.push(`warning: ${envelope.warning}`);
  return parts.join(' | ');
}

function describePersistence(data, envelope) {
  const total = data?.total_returned;
  const sourceRows = asObject(data?.source_rows);
  const correlations = Array.isArray(data?.correlations) ? data.correlations : [];
  const highConfidence = correlations.filter((row) => String(row?.overall_confidence || '').toLowerCase() === 'high').length;
  const parts = [];
  if (typeof total === 'number') parts.push(`returned: ${total}`);
  if (highConfidence > 0) parts.push(`high confidence: ${highConfidence}`);
  if (typeof sourceRows?.autorun === 'number') parts.push(`autorun rows: ${sourceRows.autorun}`);
  if (typeof sourceRows?.scheduled_tasks === 'number') parts.push(`task rows: ${sourceRows.scheduled_tasks}`);
  if (typeof sourceRows?.bam === 'number') parts.push(`bam rows: ${sourceRows.bam}`);
  if (typeof sourceRows?.dam === 'number') parts.push(`dam rows: ${sourceRows.dam}`);
  if (typeof sourceRows?.amcache === 'number') parts.push(`amcache rows: ${sourceRows.amcache}`);
  if (envelope?.warning) parts.push(`warning: ${envelope.warning}`);
  return parts.join(' | ');
}

function buildPrimaryEntry(job) {
  const envelope = asObject(job?.data) || {};
  const data = asObject(envelope.data);
  const command = job?.command || envelope.command || 'unknown';
  const baseTimestamp = firstValidTimestamp(envelope.timestamp_utc, job?.timestamp);
  let timestamp = baseTimestamp;
  let type = 'job';
  let source = command;
  let title = `Command run: ${command}`;
  let description = '';
  let severity = normalizeStatus(envelope.status || job?.status);

  if (command === 'verify') {
    timestamp = firstValidTimestamp(data?.verified_at_utc, data?.timestamp_utc, envelope.timestamp_utc, job?.timestamp);
    type = 'verification';
    title = 'Case verification';
    description = describeVerify(data, envelope);
  } else if (command === 'triage-session') {
    timestamp = firstValidTimestamp(
      data?.result?.completed_at_utc,
      data?.result?.timestamp_utc,
      data?.timestamp_utc,
      envelope.timestamp_utc,
      job?.timestamp,
    );
    type = 'triage';
    title = 'Triage session';
    description = describeTriage(data, envelope);
  } else if (command === 'examine') {
    timestamp = firstValidTimestamp(
      data?.result?.completed_at_utc,
      data?.result?.timestamp_utc,
      data?.timestamp_utc,
      envelope.timestamp_utc,
      job?.timestamp,
    );
    type = 'examination';
    title = 'Examination run';
    description = describeExamine(data, envelope);
  } else if (command === 'smoke-test') {
    timestamp = firstValidTimestamp(data?.timestamp_utc, envelope.timestamp_utc, job?.timestamp);
    type = 'evidence-check';
    title = 'Smoke test';
    description = describeSmoke(data, envelope);
  } else if (command === 'open-evidence') {
    timestamp = firstValidTimestamp(data?.detection_timestamp_utc, data?.timestamp_utc, envelope.timestamp_utc, job?.timestamp);
    type = 'evidence-detection';
    title = 'Evidence detection';
    description = describeOpenEvidence(data, envelope);
  } else if (command === 'violations') {
    timestamp = firstValidTimestamp(envelope.timestamp_utc, data?.timestamp_utc, job?.timestamp);
    type = 'violation';
    title = 'Violations query';
    description = describeViolations(data, envelope);
  } else if (command === 'execution-correlation' || command === 'recent-execution') {
    timestamp = firstValidTimestamp(envelope.timestamp_utc, data?.timestamp_utc, job?.timestamp);
    type = 'execution';
    title = 'Recent execution correlations';
    description = describeExecution(data, envelope);
  } else if (command === 'registry-persistence') {
    timestamp = firstValidTimestamp(envelope.timestamp_utc, data?.timestamp_utc, job?.timestamp);
    type = 'persistence';
    title = 'Registry persistence correlations';
    description = describePersistence(data, envelope);
  } else {
    const detailParts = [];
    if (envelope.status) detailParts.push(`status: ${envelope.status}`);
    if (job?.exit_code !== undefined) detailParts.push(`exit code: ${job.exit_code}`);
    description = detailParts.join(' | ');
  }

  if (!timestamp) return null;

  return {
    id: `${command}-${timestamp.epochMs}-${job?.filename || 'job'}`,
    timestamp: timestamp.iso,
    type,
    title,
    description: description || 'No additional details.',
    source,
    severity,
    sourceJobFilename: job?.filename || null,
  };
}

function buildViolationEntries(job) {
  const envelope = asObject(job?.data);
  const data = asObject(envelope?.data);
  if (job?.command !== 'violations' || !data) return [];

  const violations = Array.isArray(data.violations) ? data.violations : [];
  return violations
    .map((violation, index) => {
      const timestamp = firstValidTimestamp(
        violation?.occurred_utc,
        violation?.timestamp_utc,
        violation?.verified_at_utc,
      );
      if (!timestamp) return null;

      const title = violation?.rule_id
        ? `Violation: ${violation.rule_id}`
        : violation?.rule_name
          ? `Violation: ${violation.rule_name}`
          : 'Violation record';

      const parts = [];
      if (violation?.message) parts.push(violation.message);
      if (violation?.path) parts.push(`path: ${violation.path}`);
      if (violation?.entity) parts.push(`entity: ${violation.entity}`);
      if (violation?.severity) parts.push(`severity: ${violation.severity}`);
      if (parts.length === 0) parts.push('Violation event from violations result.');

      return {
        id: `violations-${timestamp.epochMs}-${index}-${job?.filename || 'job'}`,
        timestamp: timestamp.iso,
        type: 'violation',
        title,
        description: parts.join(' | '),
        source: 'violations',
        severity: normalizeStatus(violation?.severity || envelope?.status || job?.status || 'error'),
        sourceJobFilename: job?.filename || null,
      };
    })
    .filter(Boolean);
}

function buildFallbackTimelineEntries(jobs) {
  const entries = [];
  jobs.forEach((job) => {
    const primary = buildPrimaryEntry(job);
    if (primary) entries.push(primary);

    const violationEntries = buildViolationEntries(job);
    if (violationEntries.length > 0) entries.push(...violationEntries);
  });

  return entries.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

function formatTimestamp(timestamp) {
  return formatLocalTimestamp(timestamp, String(timestamp || 'N/A'));
}

function summarizeTimelinePayload(payload, fallbackCount) {
  const counts = asObject(payload?.counts_by_source);
  return {
    totalReturned: typeof payload?.total_returned === 'number' ? payload.total_returned : fallbackCount,
    totalAvailable: typeof payload?.total_available === 'number' ? payload.total_available : null,
    cursor: typeof payload?.cursor === 'string' ? payload.cursor : null,
    nextCursor: typeof payload?.next_cursor === 'string' ? payload.next_cursor : null,
    sourceFilter: payload?.source_filter || 'all',
    fromUtc: payload?.from_utc || null,
    toUtc: payload?.to_utc || null,
    limit: typeof payload?.limit === 'number' ? payload.limit : null,
    activityCount: typeof counts?.activity === 'number' ? counts.activity : null,
    evidenceCount: typeof counts?.evidence === 'number' ? counts.evidence : null,
    violationsCount: typeof counts?.violations === 'number' ? counts.violations : null,
    executionCount: typeof counts?.execution === 'number' ? counts.execution : null,
  };
}

function Timeline({
  caseId,
  caseDbPath,
  jobs,
  onPersistGuiCommandResult,
}) {
  const location = useLocation();
  const navigate = useNavigate();
  const [initialControls] = useState(() => loadTimelineControls());
  const [timelineEntries, setTimelineEntries] = useState([]);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [loadedAt, setLoadedAt] = useState(null);
  const [searchText, setSearchText] = useState(initialControls.searchText);
  const [typeFilter, setTypeFilter] = useState(initialControls.typeFilter);
  const [severityFilter, setSeverityFilter] = useState(initialControls.severityFilter);
  const [sourceFilter, setSourceFilter] = useState(initialControls.sourceFilter);
  const [linkedOnly, setLinkedOnly] = useState(Boolean(initialControls.linkedOnly));
  const [isLoading, setIsLoading] = useState(false);
  const [querySource, setQuerySource] = useState(initialControls.querySource);
  const [queryLimit, setQueryLimit] = useState(initialControls.queryLimit);
  const [queryFromUtc, setQueryFromUtc] = useState(initialControls.queryFromUtc);
  const [queryToUtc, setQueryToUtc] = useState(initialControls.queryToUtc);
  const [lastLoadMode, setLastLoadMode] = useState('none');
  const [loadNote, setLoadNote] = useState('');
  const [loadNoteKind, setLoadNoteKind] = useState('info');
  const [timelineMeta, setTimelineMeta] = useState(null);
  const latestTimelineJobFilename = findLatestJobFilename(jobs, 'timeline');

  const availableTypes = useMemo(
    () => ['all', ...Array.from(new Set(timelineEntries.map((entry) => entry.type)))],
    [timelineEntries],
  );
  const availableSources = useMemo(
    () => ['all', ...Array.from(new Set(timelineEntries.map((entry) => entry.source)))],
    [timelineEntries],
  );

  useEffect(() => {
    persistTimelineControls({
      searchText,
      typeFilter,
      severityFilter,
      sourceFilter,
      linkedOnly,
      querySource,
      queryLimit,
      queryFromUtc,
      queryToUtc,
    });
  }, [searchText, typeFilter, severityFilter, sourceFilter, linkedOnly, querySource, queryLimit, queryFromUtc, queryToUtc]);

  useEffect(() => {
    const requestedSource = String(location?.state?.source || '').toLowerCase();
    if (['all', 'activity', 'evidence', 'violations', 'execution'].includes(requestedSource)) {
      setQuerySource(requestedSource);
    }
  }, [location?.state?.source]);

  const filteredEntries = useMemo(() => {
    const term = searchText.trim().toLowerCase();
    return timelineEntries.filter((entry) => {
      if (typeFilter !== 'all' && entry.type !== typeFilter) return false;
      if (severityFilter !== 'all' && entry.severity !== severityFilter) return false;
      if (sourceFilter !== 'all' && entry.source !== sourceFilter) return false;
      if (linkedOnly && !entry.sourceJobFilename) return false;

      if (!term) return true;
      return (
        entry.title.toLowerCase().includes(term)
        || entry.description.toLowerCase().includes(term)
        || entry.source.toLowerCase().includes(term)
        || entry.type.toLowerCase().includes(term)
      );
    });
  }, [timelineEntries, searchText, typeFilter, severityFilter, sourceFilter, linkedOnly]);

  const filteredCounts = useMemo(() => {
    const countsByType = {};
    const countsBySeverity = {};
    const countsBySource = {};
    filteredEntries.forEach((entry) => {
      countsByType[entry.type] = (countsByType[entry.type] || 0) + 1;
      countsBySeverity[entry.severity] = (countsBySeverity[entry.severity] || 0) + 1;
      countsBySource[entry.source] = (countsBySource[entry.source] || 0) + 1;
    });
    return { countsByType, countsBySeverity, countsBySource };
  }, [filteredEntries]);

  useEffect(() => {
    if (typeFilter !== 'all' && !availableTypes.includes(typeFilter)) {
      setTypeFilter('all');
    }
  }, [typeFilter, availableTypes]);

  useEffect(() => {
    if (sourceFilter !== 'all' && !availableSources.includes(sourceFilter)) {
      setSourceFilter('all');
    }
  }, [sourceFilter, availableSources]);

  const handleResetControls = () => {
    setSearchText(DEFAULT_TIMELINE_CONTROLS.searchText);
    setTypeFilter(DEFAULT_TIMELINE_CONTROLS.typeFilter);
    setSeverityFilter(DEFAULT_TIMELINE_CONTROLS.severityFilter);
    setSourceFilter(DEFAULT_TIMELINE_CONTROLS.sourceFilter);
    setLinkedOnly(DEFAULT_TIMELINE_CONTROLS.linkedOnly);
    setQuerySource(DEFAULT_TIMELINE_CONTROLS.querySource);
    setQueryLimit(DEFAULT_TIMELINE_CONTROLS.queryLimit);
    setQueryFromUtc(DEFAULT_TIMELINE_CONTROLS.queryFromUtc);
    setQueryToUtc(DEFAULT_TIMELINE_CONTROLS.queryToUtc);
    setLoadNote('Timeline controls reset to defaults.');
    setLoadNoteKind('info');
  };

  const handleLoadTimeline = async () => {
    const fallbackEntries = buildFallbackTimelineEntries(jobs);
    const sanitizedLimit = parseTimelineLimit(queryLimit);
    setQueryLimit(String(sanitizedLimit));

    if (!caseId || !caseDbPath) {
      setTimelineEntries(fallbackEntries);
      setTimelineMeta(null);
      setHasLoaded(true);
      setLoadedAt(new Date().toISOString());
      setLastLoadMode('fallback');
      setLoadNote('Case ID and DB path are required for the CLI timeline command. Showing interim history entries only.');
      setLoadNoteKind('warn');
      return;
    }

    const args = [
      '--case', caseId,
      '--db', caseDbPath,
      '--limit', String(sanitizedLimit),
      '--source', querySource,
    ];

    const fromTrimmed = queryFromUtc.trim();
    if (fromTrimmed) args.push('--from', fromTrimmed);
    const toTrimmed = queryToUtc.trim();
    if (toTrimmed) args.push('--to', toTrimmed);

    setIsLoading(true);
    try {
      const result = await runGuiCommand('timeline', args);
      let persistedHistory = null;

      if (typeof onPersistGuiCommandResult === 'function') {
        persistedHistory = await onPersistGuiCommandResult('timeline', args, result);
      }

      const payload = asObject(result?.data);
      const hasStructuredEvents = payload && Array.isArray(payload.events);

      if (result.ok && hasStructuredEvents) {
        const sourceJobFilename = persistedHistory?.persisted?.filename || latestTimelineJobFilename || null;
        const commandEntries = buildTimelineCommandEntries(payload, sourceJobFilename);
        setTimelineEntries(commandEntries);
        setTimelineMeta(summarizeTimelinePayload(payload, commandEntries.length));
        setLastLoadMode('timeline');
        setLoadNote(result.warning || '');
        setLoadNoteKind(result.warning ? 'warn' : 'info');
      } else {
        setTimelineEntries(fallbackEntries);
        setTimelineMeta(null);
        setLastLoadMode('fallback');
        if (result?.error) {
          setLoadNote(`Timeline command unavailable: ${result.error}. Showing interim history entries.`);
          setLoadNoteKind('warn');
        } else if (!hasStructuredEvents) {
          setLoadNote('Timeline command returned no structured events payload. Showing interim history entries.');
          setLoadNoteKind('warn');
        } else {
          setLoadNote('Timeline command did not return a usable result. Showing interim history entries.');
          setLoadNoteKind('warn');
        }
      }
    } finally {
      setIsLoading(false);
      setHasLoaded(true);
      setLoadedAt(new Date().toISOString());
    }
  };

  const handleOpenInLogs = (entry) => {
    const resolvedFilename = resolveTimelineEntryJobFilename(entry, jobs);
    const selectionState = buildLogSelectionState(resolvedFilename);
    if (!selectionState.selectJobFilename) return;
    navigate('/logs', { state: selectionState });
  };

  const handleOpenEntryPage = (entry) => {
    const route = getTimelineEntryRoute(entry);
    navigate(route);
  };

  const handleOpenFirstLinkedLog = () => {
    const firstLinked = filteredEntries.find((entry) => entry.sourceJobFilename);
    if (!firstLinked) return;
    handleOpenInLogs(firstLinked);
  };

  const handleExportFilteredEntries = () => {
    if (filteredEntries.length === 0) return;
    const fileName = `timeline-visible-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    downloadJson(fileName, filteredEntries);
  };

  const handleCopyQueryPreview = async () => {
    const preview = [
      'timeline',
      '--case', caseId || '<case-id>',
      '--db', caseDbPath || '<db-path>',
      '--limit', String(parseTimelineLimit(queryLimit)),
      '--source', querySource,
      ...(queryFromUtc.trim() ? ['--from', queryFromUtc.trim()] : []),
      ...(queryToUtc.trim() ? ['--to', queryToUtc.trim()] : []),
    ].join(' ');
    try {
      await navigator.clipboard.writeText(preview);
      setLoadNote('Timeline query preview copied.');
      setLoadNoteKind('info');
    } catch {
      setLoadNote(`Timeline query preview: ${preview}`);
      setLoadNoteKind('warn');
    }
  };

  const setQuickRange = (hours) => {
    const now = new Date();
    const from = new Date(now.getTime() - (hours * 60 * 60 * 1000));
    setQueryFromUtc(toUtcIsoString(from));
    setQueryToUtc(toUtcIsoString(now));
  };

  return (
    <div className="page timeline">
      <header className="page-header">
        <h1>Timeline</h1>
        <p className="page-subtitle">
          Real case timeline via the CLI <code>timeline</code> command when available, with a truthful interim history fallback.
        </p>
      </header>

      <div className="timeline-layout">
        <section className="panel timeline-filters">
          <h2>Timeline Controls</h2>
          <div className="filter-row">
            <button className="btn btn-primary" onClick={handleLoadTimeline} disabled={isLoading} title={isLoading ? 'Timeline query is currently running.' : ''}>
              {isLoading ? 'Loading Timeline...' : 'Load Timeline'}
            </button>
            <button className="btn btn-secondary" onClick={handleResetControls} disabled={isLoading} title={isLoading ? 'Wait for timeline load to finish before resetting controls.' : ''}>
              Reset Controls
            </button>
            <button className="btn btn-secondary" onClick={() => setQuickRange(24)} disabled={isLoading}>
              Last 24h
            </button>
            <button className="btn btn-secondary" onClick={() => setQuickRange(24 * 7)} disabled={isLoading}>
              Last 7d
            </button>
            <button className="btn btn-secondary" onClick={() => { setQueryFromUtc(''); setQueryToUtc(''); }} disabled={isLoading}>
              Clear Window
            </button>
          </div>
          <div className="filter-row">
            <label className="filter-label" htmlFor="timeline-linked-only">Linked Logs Only</label>
            <input
              id="timeline-linked-only"
              type="checkbox"
              checked={linkedOnly}
              onChange={(event) => setLinkedOnly(event.target.checked)}
            />
          </div>
          <div className="filter-row">
            <span className="filter-label">Case</span>
            <span className="info-value">{caseId || 'No case loaded'}</span>
          </div>
          <div className="filter-row">
            <span className="filter-label">Case DB</span>
            <span className="info-value path">{caseDbPath || 'No DB path selected'}</span>
          </div>
          <div className="filter-row">
            <span className="filter-label">History Jobs Available</span>
            <span className="info-value">{jobs.length}</span>
          </div>
          <div className="filter-row">
            <span className="filter-label">Timeline Source</span>
            <span className="info-value">
              {lastLoadMode === 'timeline'
                ? 'CLI timeline command'
                : lastLoadMode === 'fallback'
                  ? 'Interim history fallback'
                  : 'Not loaded'}
            </span>
          </div>
          {loadedAt && (
            <div className="filter-row">
              <span className="filter-label">Last Loaded</span>
              <span className="info-value">{formatTimestamp(loadedAt)}</span>
            </div>
          )}
          <div className="filter-row">
            <span className="filter-label">Command Source Filter</span>
            <select className="setting-select" value={querySource} onChange={(e) => setQuerySource(e.target.value)}>
              <option value="all">all</option>
              <option value="activity">activity</option>
              <option value="evidence">evidence</option>
              <option value="violations">violations</option>
              <option value="execution">execution</option>
            </select>
          </div>
          <div className="filter-row">
            <span className="filter-label">Command Limit</span>
            <input
              type="number"
              className="filter-input"
              min="1"
              max="2000"
              value={queryLimit}
              onChange={(e) => setQueryLimit(e.target.value)}
            />
          </div>
          <div className="filter-row">
            <span className="filter-label">Command From UTC (optional)</span>
            <input
              type="text"
              className="filter-input"
              placeholder="2026-03-07T14:22:10Z"
              value={queryFromUtc}
              onChange={(e) => setQueryFromUtc(e.target.value)}
            />
          </div>
          <div className="filter-row">
            <span className="filter-label">Command To UTC (optional)</span>
            <input
              type="text"
              className="filter-input"
              placeholder="2026-03-08T00:00:00Z"
              value={queryToUtc}
              onChange={(e) => setQueryToUtc(e.target.value)}
            />
          </div>
          <div className="filter-row">
            <span className="filter-label">Type</span>
            <select className="setting-select" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
              {availableTypes.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>
          <div className="filter-row">
            <span className="filter-label">Source</span>
            <select className="setting-select" value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
              {availableSources.map((source) => (
                <option key={source} value={source}>
                  {source}
                </option>
              ))}
            </select>
          </div>
          <div className="filter-row">
            <span className="filter-label">Severity</span>
            <select className="setting-select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
              <option value="all">all</option>
              <option value="ok">ok</option>
              <option value="warn">warn</option>
              <option value="error">error</option>
              <option value="info">info</option>
            </select>
          </div>
          <div className="filter-row">
            <span className="filter-label">Search</span>
            <input
              type="text"
              className="filter-input"
              placeholder="Search title/description/source..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
            />
          </div>
        </section>

        <section className="panel timeline-results">
          <div className="timeline-header">
            <h2>Activity Entries ({filteredEntries.length})</h2>
            <div className="analysis-actions">
              <button
                className="btn btn-secondary btn-small"
                onClick={() => navigate('/logs', { state: buildLogSelectionState(latestTimelineJobFilename) })}
                disabled={!latestTimelineJobFilename}
                title={latestTimelineJobFilename ? 'Open latest timeline command result in Logs.' : 'No timeline result file yet.'}
              >
                Open Latest Timeline Log
              </button>
              <button
                className="btn btn-secondary btn-small"
                onClick={handleOpenFirstLinkedLog}
                disabled={!filteredEntries.some((entry) => entry.sourceJobFilename)}
              >
                Open First Linked Log
              </button>
              <button
                className="btn btn-secondary btn-small"
                onClick={handleExportFilteredEntries}
                disabled={filteredEntries.length === 0}
              >
                Export Visible JSON
              </button>
              <button className="btn btn-secondary btn-small" onClick={handleCopyQueryPreview}>
                Copy Query Preview
              </button>
            </div>
          </div>

          {loadNote && (
            <div className={loadNoteKind === 'warn' ? 'warning-message' : 'helper-text'}>
              {loadNote}
            </div>
          )}

          {timelineMeta && (
            <div className="info-grid compact-grid">
              <div className="info-item">
                <span className="info-label">Total Returned</span>
                <span className="info-value">{timelineMeta.totalReturned}</span>
              </div>
              {timelineMeta.totalAvailable !== null && (
                <div className="info-item">
                  <span className="info-label">Total Available</span>
                  <span className="info-value">{timelineMeta.totalAvailable}</span>
                </div>
              )}
              <div className="info-item">
                <span className="info-label">Source Filter</span>
                <span className="info-value">{timelineMeta.sourceFilter}</span>
              </div>
              {timelineMeta.limit !== null && (
                <div className="info-item">
                  <span className="info-label">Limit</span>
                  <span className="info-value">{timelineMeta.limit}</span>
                </div>
              )}
              {timelineMeta.activityCount !== null && (
                <div className="info-item">
                  <span className="info-label">Activity</span>
                  <span className="info-value">{timelineMeta.activityCount}</span>
                </div>
              )}
              {timelineMeta.evidenceCount !== null && (
                <div className="info-item">
                  <span className="info-label">Evidence</span>
                  <span className="info-value">{timelineMeta.evidenceCount}</span>
                </div>
              )}
              {timelineMeta.violationsCount !== null && (
                <div className="info-item">
                  <span className="info-label">Violations</span>
                  <span className="info-value">{timelineMeta.violationsCount}</span>
                </div>
              )}
              {timelineMeta.executionCount !== null && (
                <div className="info-item">
                  <span className="info-label">Execution</span>
                  <span className="info-value">{timelineMeta.executionCount}</span>
                </div>
              )}
              {timelineMeta.cursor && (
                <div className="info-item">
                  <span className="info-label">Cursor</span>
                  <span className="info-value">{timelineMeta.cursor}</span>
                </div>
              )}
              {timelineMeta.nextCursor && (
                <div className="info-item">
                  <span className="info-label">Next Cursor</span>
                  <span className="info-value">{timelineMeta.nextCursor}</span>
                </div>
              )}
              {(timelineMeta.fromUtc || timelineMeta.toUtc) && (
                <div className="info-item full-width">
                  <span className="info-label">Query Window</span>
                  <span className="info-value">
                    {timelineMeta.fromUtc || 'beginning'} to {timelineMeta.toUtc || 'now'}
                  </span>
                </div>
              )}
              <div className="info-item full-width">
                <span className="info-label">Visible Type Counts</span>
                <span className="info-value">
                  {Object.keys(filteredCounts.countsByType).length === 0
                    ? 'none'
                    : Object.entries(filteredCounts.countsByType).map(([key, value]) => `${key}: ${value}`).join(' | ')}
                </span>
              </div>
              <div className="info-item full-width">
                <span className="info-label">Visible Severity Counts</span>
                <span className="info-value">
                  {Object.keys(filteredCounts.countsBySeverity).length === 0
                    ? 'none'
                    : Object.entries(filteredCounts.countsBySeverity).map(([key, value]) => `${key}: ${value}`).join(' | ')}
                </span>
              </div>
              <div className="info-item full-width">
                <span className="info-label">Visible Source Counts</span>
                <span className="info-value">
                  {Object.keys(filteredCounts.countsBySource).length === 0
                    ? 'none'
                    : Object.entries(filteredCounts.countsBySource).map(([key, value]) => `${key}: ${value}`).join(' | ')}
                </span>
              </div>
            </div>
          )}

          {!hasLoaded && (
            <p className="no-data">
              No timeline loaded yet. Click Load Timeline. If the command is unavailable for the selected DB, this page falls back to interim history entries.
            </p>
          )}

          {hasLoaded && timelineEntries.length === 0 && (
            <p className="no-data">
              No usable timestamped events were returned for the current context and filters.
            </p>
          )}

          {hasLoaded && timelineEntries.length > 0 && filteredEntries.length === 0 && (
            <p className="no-data">No timeline entries match the selected filters.</p>
          )}

          <div className="timeline-list">
            {filteredEntries.map((entry) => (
              <div key={entry.id} className={`timeline-event severity-${entry.severity}`}>
                <div className="event-time">
                  <span className="timestamp">{formatTimestamp(entry.timestamp)}</span>
                </div>
                <div className="event-marker"></div>
                <div className="event-content">
                  <div className="timeline-entry-header">
                    <span className="event-type">{entry.title}</span>
                    <span className="type-chip">{entry.type}</span>
                    <span className="type-chip source-chip">{entry.source}</span>
                    <span className={`status-badge status-${entry.severity}`}>{entry.severity}</span>
                  </div>
                  <span className="event-description">{entry.description}</span>
                  {entry.sourceJobFilename && (
                    <span className="event-description">source log: {entry.sourceJobFilename}</span>
                  )}
                  <div className="timeline-entry-actions">
                    {entry.sourceJobFilename && (
                      <button
                        className="btn btn-secondary btn-small"
                        onClick={() => handleOpenInLogs(entry)}
                        title={`Open ${entry.sourceJobFilename} in Logs`}
                      >
                        Open In Logs
                      </button>
                    )}
                    <button
                      className="btn btn-secondary btn-small"
                      onClick={() => handleOpenEntryPage(entry)}
                    >
                      Open {getRouteLabel(getTimelineEntryRoute(entry))}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

export default Timeline;
