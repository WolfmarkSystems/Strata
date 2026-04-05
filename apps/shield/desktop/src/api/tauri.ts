import { invoke } from '@tauri-apps/api/core';
import type {
  CaseInfo,
  FileTableQuery,
  FileTableResult,
  PreviewResult,
  AddToNotesRequest,
  AddToNotesResult,
  EngineEvent,
  CapabilitiesReport,
  PreflightReport,
  ScoreUpdateResult,
  ScoreExplainResult,
  GlobalSearchHit,
  GlobalSearchQuery,
  EvidenceTimelineEvent,
  PresetInfo,
  PresetDetails,
  TriageSessionResult,
  VerificationReport,
  ReplayReport,
  IntegrityViolation,
  ExportResult,
} from '../types';

async function wrap<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e: unknown) {
    if (e && typeof e === 'object' && 'message' in e) {
      throw new Error((e as { message: string }).message);
    }
    if (typeof e === 'string') {
      throw new Error(e);
    }
    throw new Error(`Command ${cmd} failed: ${String(e)}`);
  }
}

export const api = {
  async openCase(casePath: string): Promise<{ case_id: string }> {
    return wrap('open_case', { casePath });
  },

  async listCases(): Promise<CaseInfo[]> {
    return wrap('list_cases', {});
  },

  async openEvidence(caseId: string, evidencePath: string): Promise<{ evidence_id: string }> {
    return wrap('open_evidence', { caseId, evidencePath });
  },

  async fileTableQuery(query: FileTableQuery): Promise<FileTableResult> {
    return wrap('file_table_query', {
      caseId: query.filter?.case_id,
      dbPath: './forensic.db',
      sourceTypes: query.filter?.source_types,
      sortField: query.sort_field,
      sortDir: query.sort_dir,
      limit: query.limit,
      cursorJson: query.cursor ? JSON.stringify(query.cursor) : null,
      nameContains: query.filter?.name_contains,
      extFilter: query.filter?.ext_in,
      categoryFilter: query.filter?.category_in,
      minSize: query.filter?.min_size,
      maxSize: query.filter?.max_size,
    });
  },

  async fileTablePreview(
    caseId: string,
    sourceType: string,
    sourceId: string,
    _mode: 'text' | 'hex' | 'metadata'
  ): Promise<PreviewResult> {
    return wrap('file_table_preview', {
      caseId,
      dbPath: './forensic.db',
      rowId: 0,
      sourceType,
      sourceId,
    });
  },

  async addToNotes(req: AddToNotesRequest): Promise<AddToNotesResult> {
    return wrap('add_to_notes', {
      caseId: req.case_id,
      mode: req.mode,
      noteText: req.note_text || '',
      selectionItems: req.selection_items,
      filters: req.filters,
      search: req.search || '',
    });
  },

  async getEventBuffer(caseId?: string, limit?: number): Promise<EngineEvent[]> {
    return wrap('get_event_buffer', { caseId: caseId || null, limit: limit || 200 });
  },

  async getCapabilities(): Promise<CapabilitiesReport> {
    return wrap('get_capabilities', {});
  },

  async runPreflight(): Promise<PreflightReport> {
    return wrap('run_preflight', {});
  },

  async getPreflightReport(): Promise<PreflightReport> {
    return wrap('get_preflight_report', {});
  },

  async rebuildScores(caseId: string): Promise<ScoreUpdateResult> {
    return wrap('rebuild_scores', { caseId, dbPath: './forensic.db' });
  },

  async explainScore(caseId: string, rowId: number): Promise<ScoreExplainResult> {
    return wrap('explain_score', { caseId, dbPath: './forensic.db', rowId });
  },

  async globalSearch(query: GlobalSearchQuery): Promise<GlobalSearchHit[]> {
    return wrap('global_search', {
      caseId: query.case_id,
      q: query.q,
      entityTypes: query.entity_types,
      dateStartUtc: query.date_start_utc,
      dateEndUtc: query.date_end_utc,
      category: query.category,
      tagsAny: query.tags_any,
      pathPrefix: query.path_prefix,
      limit: query.limit,
      afterRank: query.after_rank,
      afterRowid: query.after_rowid,
    });
  },

  async rebuildGlobalSearch(caseId: string): Promise<void> {
    return wrap('rebuild_global_search', { caseId, dbPath: './forensic.db' });
  },

  async getEvidenceTimelineAfter(
    caseId: string,
    lastEventTime?: number,
    lastRowid?: number,
    limit?: number
  ): Promise<EvidenceTimelineEvent[]> {
    return wrap('get_evidence_timeline_after', {
      caseId,
      lastEventTime,
      lastRowid,
      limit: limit || 50,
    });
  },

  async listPresets(): Promise<PresetInfo[]> {
    return wrap('list_presets', {});
  },

  async getPreset(name: string): Promise<PresetDetails | null> {
    return wrap('get_preset', { name });
  },

  async startExamination(caseId: string, presetName: string): Promise<void> {
    return wrap('start_examination', { caseId, presetName, dbPath: './forensic.db' });
  },

  async runTriageSession(caseId: string): Promise<TriageSessionResult> {
    return wrap('run_triage_session', { caseId, dbPath: './forensic.db' });
  },

  async runVerify(caseId: string): Promise<VerificationReport> {
    return wrap('run_verify', { caseId, dbPath: './forensic.db' });
  },

  async runReplay(caseId: string): Promise<ReplayReport> {
    return wrap('run_replay', { caseId, dbPath: './forensic.db' });
  },

  async listViolations(caseId: string): Promise<IntegrityViolation[]> {
    return wrap('list_violations', { caseId });
  },

  async clearViolations(caseId: string): Promise<void> {
    return wrap('violations_clear', { caseId });
  },

  async exportCase(
    caseId: string,
    outputDir: string,
    options: { strict?: boolean; maxAge?: number; noVerify?: boolean }
  ): Promise<ExportResult> {
    return wrap('export_case', {
      caseId,
      dbPath: './forensic.db',
      outputDir,
      strict: options.strict || false,
      maxAge: options.maxAge,
      noVerify: options.noVerify || false,
    });
  },

  async generateReportSkeleton(caseId: string, outputDir: string): Promise<Record<string, string>> {
    return wrap('generate_report_skeleton', { caseId, dbPath: './forensic.db', outputDir });
  },

  async workerOnce(caseId: string): Promise<void> {
    return wrap('worker_run_once', { caseId });
  },

  async workerStartLoop(caseId: string): Promise<void> {
    return wrap('worker_start_loop', { caseId });
  },

  async workerStopLoop(caseId: string): Promise<void> {
    return wrap('worker_stop_loop', { caseId });
  },

  async workerStatus(caseId: string): Promise<{ queued: number; running: number; last_status: string }> {
    return wrap('worker_status', { caseId });
  },
};
