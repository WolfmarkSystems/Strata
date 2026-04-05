export interface GlobalSearchHit {
  id: string;
  entity_type: string;
  entity_id: string;
  title: string;
  snippet: string;
  path?: string;
  category?: string;
  source_module?: string;
  rank: number;
  json_data?: Record<string, unknown>;
}

export interface CaseInfo {
  id: string;
  name: string;
  created_utc: string;
  evidence_paths: string[];
  total_files: number;
  case_dir: string;
}

export interface FileTableQuery {
  case_id: string;
  filters?: Record<string, unknown>;
  filter?: Record<string, unknown>;
  sort_by?: string;
  sort_field?: string;
  sort_dir?: 'asc' | 'desc' | 'Asc' | 'Desc';
  limit?: number;
  offset?: number;
  cursor?: string;
}

export interface FileTableResult {
  rows: FileTableRow[];
  total: number;
  has_more: boolean;
  next_cursor?: string;
}

export interface FileTableCursor {
  offset: number;
  rowid: number;
}

export interface PreviewResult {
  preview_text?: string;
  preview_hex?: string;
  preview_metadata?: Record<string, unknown>;
  preview_type: 'text' | 'hex' | 'metadata' | 'none';
  content?: string;
}

export interface AddToNotesRequest {
  case_id: string;
  note_text?: string;
  selection_items?: Array<{
    item_type: string;
    file_path?: string;
    evidence_id?: string;
    volume_id?: string;
    hash_sha256?: string;
    provenance?: string;
  }>;
  filters?: Record<string, unknown>;
  search?: string;
  items?: Array<{
    item_type: string;
    file_path?: string;
    evidence_id?: string;
    volume_id?: string;
    hash_sha256?: string;
    provenance?: string;
  }>;
  mode: 'note_only' | 'exhibit_only' | 'with_exhibit' | 'create_packet';
}

export interface AddToNotesResult {
  notes_id: string;
  items_added: number;
}

export type EngineEvent = {
  event_type: string;
  timestamp_utc: string;
  occurred_utc?: string;
  severity?: 'info' | 'warn' | 'error';
  kind?: { type: string };
  message?: string;
  payload?: Record<string, unknown>;
};

export interface CapabilitiesReport {
  overall_status: string;
  capabilities: Array<{
    name: string;
    status: string;
    message?: string;
  }>;
}

export interface PreflightReport {
  overall_status: string;
  results: Array<{
    name: string;
    status: string;
    message?: string;
  }>;
}

export interface ScoreUpdateResult {
  updated_count: number;
}

export interface ScoreExplainResult {
  file_id: number;
  score: number;
  signals: Array<{
    key: string;
    points: number;
    evidence: string;
  }>;
}

export type SortField = 'name' | 'size' | 'modified' | 'created' | 'score' | 'extension' | 'Name' | 'Size' | 'Modified' | 'Created' | 'Score' | 'Extension';
export type SortDir = 'asc' | 'desc' | 'Asc' | 'Desc';

export interface GlobalSearchQuery {
  case_id: string;
  q: string;
  entity_types?: string[];
  date_start_utc?: string;
  date_end_utc?: string;
  category?: string;
  tags_any?: string[];
  path_prefix?: string;
  limit: number;
  after_rank?: number;
  after_rowid?: number;
}

export interface EvidenceTimelineEvent {
  id: string;
  case_id: string;
  event_time: number;
  event_type: string;
  event_category?: string;
  artifact_id?: string;
  source_module?: string;
  source_record_id?: string;
  summary?: string;
  details_json?: string;
}

export type Tab = 'files' | 'search' | 'timeline' | 'workflow';

export interface SelectionContext {
  kind: 'file' | 'search' | 'timeline';
  data: FileTableRow | GlobalSearchHit | EvidenceTimelineEvent;
  filters: {
    searchQuery?: string;
    timelineRange?: { start?: number; end?: number };
    fileFilters?: Record<string, unknown>;
  };
}

export interface PresetInfo {
  name: string;
  description: string;
  locked_fields: string[];
}

export interface PresetDetails extends PresetInfo {
  config_json: string;
}

export interface TriageSessionResult {
  session_id: string;
  status: string;
  verification_status?: string;
  replay_status?: string;
  violations_count: number;
  bundle_path?: string;
  started_utc: string;
  completed_utc?: string;
}

export interface VerificationReport {
  id: string;
  case_id: string;
  status: 'Pass' | 'Fail' | 'Warn';
  started_utc: string;
  completed_utc?: string;
  checks: VerificationCheck[];
  summary_json?: string;
}

export interface VerificationCheck {
  check_name: string;
  status: 'Pass' | 'Fail' | 'Warn';
  message: string;
}

export interface ReplayReport {
  id: string;
  case_id: string;
  status: string;
  is_deterministic: boolean;
  fingerprint: string;
  mismatches: ReplayMismatch[];
  started_utc: string;
  completed_utc?: string;
}

export interface ReplayMismatch {
  table_name: string;
  field: string;
  expected: string;
  actual: string;
}

export interface IntegrityViolation {
  id: string;
  case_id: string;
  table_name: string;
  record_id: string;
  operation: string;
  actor: string;
  detected_utc: string;
  details?: string;
}

export interface ExportResult {
  output_path: string;
  files: string[];
  verification_included: boolean;
  hash: string;
}

export interface FileTableRow {
  id: number;
  source_type: string;
  source_id: string;
  evidence_id?: string;
  volume_id?: string;
  path: string;
  name: string;
  extension?: string;
  size_bytes?: number;
  modified_utc?: string;
  created_utc?: string;
  entropy?: number;
  category?: string;
  score: number;
  tags: string[];
  summary: ScoreSignalsSummary;
}

export interface ScoreSignalsSummary {
  score_signals?: ScoreSignal[];
  [key: string]: unknown;
}

export interface ScoreSignal {
  key: string;
  points: number;
  evidence: string;
}
