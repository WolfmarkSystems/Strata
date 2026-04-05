import { useState, useEffect, useCallback } from 'react';
import { api } from '../../api/tauri';
import { eventStore } from '../../api/events';
import type {
  FileTableQuery,
  FileTableRow,
  FileTableCursor,
  SortField,
  SortDir,
  EngineEvent,
  CapabilitiesReport,
  PreflightReport,
  GlobalSearchHit,
  EvidenceTimelineEvent,
} from '../../types';

export function useCase() {
  const [caseId, setCaseId] = useState<string | null>(null);
  const [casePath, setCasePath] = useState<string>('');
  const [evidenceId, setEvidenceId] = useState<string | null>(null);
  const [evidencePath, setEvidencePath] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const openCase = useCallback(async (path: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.openCase(path);
      setCaseId(result.case_id);
      setCasePath(path);
      await eventStore.init(result.case_id);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const openEvidence = useCallback(async (path: string) => {
    if (!caseId) {
      setError('No case opened');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await api.openEvidence(caseId, path);
      setEvidenceId(result.evidence_id);
      setEvidencePath(path);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  return {
    caseId,
    casePath,
    evidenceId,
    evidencePath,
    error,
    loading,
    openCase,
    openEvidence,
    clearError: () => setError(null),
  };
}

export function useFileTable(caseId: string | null) {
  const [rows, setRows] = useState<FileTableRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cursor, setCursor] = useState<FileTableCursor | null>(null);
  const [hasMore, setHasMore] = useState(true);
  const [selectedRow, setSelectedRow] = useState<FileTableRow | null>(null);
  
  const [sortField, setSortField] = useState<SortField>('Name');
  const [sortDir, setSortDir] = useState<SortDir>('Asc');
  const [filters, setFilters] = useState({
    name_contains: '',
    ext_in: '',
    category_in: '',
    score_min: 0,
    min_size: 0,
    max_size: 0,
    source_types: [] as string[],
  });

  const buildQuery = useCallback((resetCursor = false): FileTableQuery => {
    const query: FileTableQuery = {
      case_id: caseId || '',
      filter: {
        name_contains: filters.name_contains || undefined,
        ext_in: filters.ext_in ? filters.ext_in.split(',').map(e => e.trim()) : undefined,
        category_in: filters.category_in ? filters.category_in.split(',').map(c => c.trim()) : undefined,
        score_min: filters.score_min > 0 ? filters.score_min : undefined,
        min_size: filters.min_size > 0 ? filters.min_size : undefined,
        max_size: filters.max_size > 0 ? filters.max_size : undefined,
        source_types: filters.source_types.length > 0 ? filters.source_types : undefined,
      },
      sort_field: sortField,
      sort_dir: sortDir,
      limit: 100,
      cursor: resetCursor ? undefined : (cursor ? JSON.stringify(cursor) : undefined),
    };
    return query;
  }, [caseId, sortField, sortDir, cursor, filters]);

  const loadRows = useCallback(async (reset = false) => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const query = buildQuery(reset);
      const result = await api.fileTableQuery(query);
      if (reset) {
        setRows(result.rows);
      } else {
        setRows(prev => [...prev, ...result.rows]);
      }
      setCursor(result.next_cursor ? JSON.parse(result.next_cursor) : null);
      setHasMore(result.has_more);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId, buildQuery]);

  useEffect(() => {
    if (caseId) {
      loadRows(true);
    }
  }, [caseId, sortField, sortDir]);

  const applyFilters = useCallback(() => {
    setCursor(null);
    loadRows(true);
  }, [loadRows]);

  const loadMore = useCallback(() => {
    if (hasMore && !loading) {
      loadRows(false);
    }
  }, [hasMore, loading, loadRows]);

  return {
    rows,
    loading,
    error,
    selectedRow,
    setSelectedRow,
    sortField,
    setSortField,
    sortDir,
    setSortDir,
    filters,
    setFilters,
    applyFilters,
    loadMore,
    hasMore,
    rowCount: rows.length,
  };
}

export function useCapabilities() {
  const [capabilities, setCapabilities] = useState<CapabilitiesReport | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    api.getCapabilities()
      .then(setCapabilities)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return { capabilities, loading };
}

export function usePreflight() {
  const [report, setReport] = useState<PreflightReport | null>(null);
  const [loading, setLoading] = useState(false);

  const run = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.runPreflight();
      setReport(result);
    } catch (e) {
      console.error('Preflight failed:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  return { report, loading, run };
}

export function useEvents() {
  const [events, setEvents] = useState<EngineEvent[]>([]);
  const [filter, setFilter] = useState({ severity: '', kind: '', search: '' });
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    const unsubscribe = eventStore.subscribe((evts: EngineEvent[]) => {
      if (!paused) {
        setEvents(evts);
      }
    });
    return unsubscribe;
  }, [paused]);

  const filteredEvents = events.filter(e => {
    if (filter.severity && e.severity !== filter.severity) return false;
    if (filter.kind && !(e.kind?.type || '').toLowerCase().includes(filter.kind.toLowerCase())) return false;
    if (filter.search && !(e.message || '').toLowerCase().includes(filter.search.toLowerCase())) return false;
    return true;
  });

  return {
    events: filteredEvents,
    filter,
    setFilter,
    paused,
    setPaused,
    totalCount: events.length,
  };
}

export function useGlobalSearch(caseId: string | null) {
  const [results, setResults] = useState<GlobalSearchHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(true);
  const [cursor, setCursor] = useState<{ after_rank?: number; after_rowid?: number } | null>(null);
  
  const [query, setQuery] = useState('');
  const [filters, setFilters] = useState({
    entity_types: [] as string[],
    date_start_utc: '',
    date_end_utc: '',
    category: '',
    tags_any: '',
    path_prefix: '',
  });

  const search = useCallback(async (reset = false) => {
    if (!caseId || !query.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const result = await api.globalSearch({
        case_id: caseId,
        q: query,
        entity_types: filters.entity_types.length > 0 ? filters.entity_types : undefined,
        date_start_utc: filters.date_start_utc || undefined,
        date_end_utc: filters.date_end_utc || undefined,
        category: filters.category || undefined,
        tags_any: filters.tags_any ? filters.tags_any.split(',').map(t => t.trim()) : undefined,
        path_prefix: filters.path_prefix || undefined,
        limit: 50,
        after_rank: reset ? undefined : cursor?.after_rank,
        after_rowid: reset ? undefined : cursor?.after_rowid,
      });
      
      if (reset) {
        setResults(result);
      } else {
        setResults(prev => [...prev, ...result]);
      }
      
      const lastResult = result[result.length - 1];
      if (lastResult) {
        setCursor({ after_rank: lastResult.rank, after_rowid: parseInt(lastResult.id) });
        setHasMore(result.length === 50);
      } else {
        setHasMore(false);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId, query, filters, cursor]);

  const loadMore = useCallback(() => {
    if (hasMore && !loading) {
      search(false);
    }
  }, [hasMore, loading, search]);

  const rebuildIndex = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    try {
      await api.rebuildGlobalSearch(caseId);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  return {
    results,
    loading,
    error,
    hasMore,
    query,
    setQuery,
    filters,
    setFilters,
    search,
    loadMore,
    rebuildIndex,
    resultCount: results.length,
  };
}

export function useTimeline(caseId: string | null) {
  const [events, setEvents] = useState<EvidenceTimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(true);
  const [cursor, setCursor] = useState<{ last_time?: number; last_id?: number } | null>(null);
  
  const [filters, setFilters] = useState({
    event_category: '',
    event_type: '',
    source_module: '',
    date_start: '',
    date_end: '',
  });

  const loadEvents = useCallback(async (reset = false) => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await api.getEvidenceTimelineAfter(
        caseId,
        reset ? undefined : cursor?.last_time,
        reset ? undefined : cursor?.last_id,
        50
      );
      
      if (reset) {
        setEvents(result);
      } else {
        setEvents(prev => [...prev, ...result]);
      }
      
      const lastEvent = result[result.length - 1];
      if (lastEvent) {
        setCursor({ last_time: lastEvent.event_time, last_id: parseInt(lastEvent.id) });
        setHasMore(result.length === 50);
      } else {
        setHasMore(false);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [caseId, cursor]);

  useEffect(() => {
    if (caseId) {
      loadEvents(true);
    }
  }, [caseId]);

  const loadMore = useCallback(() => {
    if (hasMore && !loading) {
      loadEvents(false);
    }
  }, [hasMore, loading, loadEvents]);

  return {
    events,
    loading,
    error,
    hasMore,
    filters,
    setFilters,
    loadMore,
    loadEvents,
    eventCount: events.length,
  };
}

export function useAddToNotes() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const addToNotes = useCallback(async (
    caseId: string,
    mode: 'note_only' | 'exhibit_only' | 'with_exhibit' | 'create_packet',
    items: Array<{
      item_type: string;
      file_path?: string;
      evidence_id?: string;
      volume_id?: string;
      hash_sha256?: string;
      provenance?: string;
    }>,
    filters?: Record<string, unknown>,
    search?: string,
  ) => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.addToNotes({
        case_id: caseId,
        mode,
        selection_items: items,
        filters,
        search,
      });
      return result;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  return { addToNotes, loading, error };
}
