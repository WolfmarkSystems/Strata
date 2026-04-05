import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Card from "../components/Card";
import StatusBadge from "../components/StatusBadge";

export interface FileRow {
  path?: string | null;
  size_bytes?: number | null;
  hash_sha256?: string | null;
  hash_md5?: string | null;
  created_utc?: string | null;
  modified_utc?: string | null;
  extension?: string | null;
  type?: string | null;
  deleted?: boolean | null;
}

interface FileExplorerProps {
  rows?: FileRow[];
  evidencePath?: string | null;
  caseDbPath?: string | null;
  queryStatus?: string | null;
  onLoadFiles?: () => void;
  loading?: boolean;
  volumeIndex?: number | null;
}

interface MountResult {
  volumes?: Array<{ volumeIndex: number }>;
}

interface VolumeEntryRow {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  modifiedTime?: number | null;
}

interface VfsPreview {
  bytesRead?: number;
  totalBytes?: number;
  truncated?: boolean;
  contentUtf8?: string;
  hexDump?: string;
}

function formatSize(value: number | null | undefined) {
  if (value === null || value === undefined || Number.isNaN(value)) return "N/A";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function formatUnix(value?: number | null) {
  if (!value || !Number.isFinite(value)) return undefined;
  const millis = value > 1_000_000_000_000 ? value : value * 1000;
  const date = new Date(millis);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export default function FileExplorer({
  rows = [],
  evidencePath,
  caseDbPath,
  queryStatus,
  onLoadFiles,
  loading = false,
  volumeIndex = null,
}: FileExplorerProps) {
  const [search, setSearch] = useState("");
  const [extFilter, setExtFilter] = useState("");
  const [showDeletedOnly, setShowDeletedOnly] = useState(false);
  const [backendRows, setBackendRows] = useState<FileRow[]>([]);
  const [backendLoading, setBackendLoading] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [preview, setPreview] = useState<VfsPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const effectiveRows = rows.length > 0 ? rows : backendRows;
  const effectiveLoading = loading || backendLoading;

  const loadFromBackend = async () => {
    if (!evidencePath) {
      setBackendError("No evidence path selected.");
      return;
    }

    setBackendLoading(true);
    setBackendError(null);
    try {
      const mount = await invoke<MountResult>("mount_evidence", { path: evidencePath });
      const firstVolume = volumeIndex ?? mount.volumes?.[0]?.volumeIndex ?? 0;
      const entries = await invoke<VolumeEntryRow[]>("enumerate_volume", {
        evidencePath,
        volumeIndex: firstVolume,
      });

      const mapped = entries
        .filter((entry) => !entry.isDir)
        .map<FileRow>((entry) => {
          const parts = entry.path.split(".");
          const extension = parts.length > 1 ? parts[parts.length - 1].toLowerCase() : "";
          return {
            path: entry.path,
            size_bytes: entry.size,
            modified_utc: formatUnix(entry.modifiedTime),
            extension,
            type: extension,
            deleted: false,
          };
        });

      setBackendRows(mapped);
    } catch (error) {
      setBackendError(String(error));
      setBackendRows([]);
    } finally {
      setBackendLoading(false);
    }
  };

  useEffect(() => {
    if (!evidencePath || rows.length > 0) return;
    loadFromBackend().catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidencePath, volumeIndex, rows.length]);

  const filtered = useMemo(() => {
    return effectiveRows.filter((row) => {
      const path = String(row.path || "").toLowerCase();
      const extension = String(row.extension || row.type || "").toLowerCase();
      const matchesSearch = !search.trim() || path.includes(search.trim().toLowerCase());
      const matchesExt = !extFilter.trim() || extension === extFilter.trim().toLowerCase();
      const matchesDeleted = !showDeletedOnly || row.deleted === true;
      return matchesSearch && matchesExt && matchesDeleted;
    });
  }, [effectiveRows, search, extFilter, showDeletedOnly]);

  const loadPreview = async (path: string) => {
    if (!evidencePath) return;
    setSelectedPath(path);
    setPreview(null);
    setPreviewError(null);
    setPreviewLoading(true);
    try {
      const result = await invoke<VfsPreview>("read_vfs_file", {
        evidencePath,
        artifactPath: path,
        maxBytes: 16384,
      });
      setPreview(result);
    } catch (error) {
      setPreviewError(String(error));
    } finally {
      setPreviewLoading(false);
    }
  };

  return (
    <div className="fs-grid">
      <Card
        title="File Explorer"
        subtitle="VFS-backed explorer using mount_evidence + enumerate_volume"
        actions={
          <button
            className="fs-btn"
            onClick={async () => {
              if (onLoadFiles) onLoadFiles();
              if (!onLoadFiles || rows.length === 0) await loadFromBackend();
            }}
            disabled={effectiveLoading}
          >
            {effectiveLoading ? "Loading..." : "Load Files"}
          </button>
        }
      >
        <div className="fs-field-grid two-col" style={{ marginBottom: 12 }}>
          <div className="fs-field">
            <label>Search Path</label>
            <input className="fs-input" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Path contains..." />
          </div>
          <div className="fs-field">
            <label>Extension / Type</label>
            <input className="fs-input" value={extFilter} onChange={(e) => setExtFilter(e.target.value)} placeholder="e.g. exe, dll, jpg" />
          </div>
        </div>
        <div className="fs-inline" style={{ marginBottom: 12, justifyContent: "space-between" }}>
          <label className="fs-inline fs-muted">
            <input type="checkbox" checked={showDeletedOnly} onChange={(e) => setShowDeletedOnly(e.target.checked)} />
            Deleted only
          </label>
          <StatusBadge status={queryStatus || "info"} label={queryStatus || "No query yet"} />
        </div>
        <div className="fs-inline fs-muted" style={{ marginBottom: 8 }}>
          <span title={caseDbPath || ""}>DB: {caseDbPath || "Not selected"}</span>
          <span>|</span>
          <span title={evidencePath || ""}>Evidence: {evidencePath || "Not selected"}</span>
          <span>|</span>
          <span>Rows: {filtered.length}</span>
        </div>

        {backendError && <div className="fs-empty">Error loading VFS rows: {backendError}</div>}
        {!caseDbPath && <div className="fs-empty">No case database selected.</div>}
        {caseDbPath && !evidencePath && <div className="fs-empty">No evidence selected.</div>}
        {caseDbPath && evidencePath && effectiveRows.length === 0 && !effectiveLoading && !backendError && (
          <div className="fs-empty">No file data loaded yet or volume enumeration returned no rows.</div>
        )}

        {filtered.length > 0 && (
          <div className="fs-table-wrap">
            <table className="fs-table">
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Size</th>
                  <th>SHA256</th>
                  <th>Modified</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((row, index) => (
                  <tr
                    key={`${row.path || "row"}-${index}`}
                    onClick={() => row.path && loadPreview(String(row.path))}
                    style={{ cursor: row.path ? "pointer" : "default" }}
                  >
                    <td>
                      <div className="fs-path-wrap">
                        <span className="fs-path" title={row.path || ""}>{row.path || "N/A"}</span>
                        {row.path && (
                          <button
                            className="fs-icon-btn"
                            onClick={(event) => {
                              event.stopPropagation();
                              navigator.clipboard.writeText(String(row.path));
                            }}
                            title="Copy path"
                            type="button"
                          >
                            Copy
                          </button>
                        )}
                      </div>
                    </td>
                    <td>{formatSize(row.size_bytes)}</td>
                    <td className="fs-mono fs-path" title={row.hash_sha256 || row.hash_md5 || ""}>
                      {row.hash_sha256 || row.hash_md5 || "N/A"}
                    </td>
                    <td>{row.modified_utc || row.created_utc || "N/A"}</td>
                    <td><StatusBadge status={row.deleted ? "warn" : "ok"} label={row.deleted ? "deleted" : "active"} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {(selectedPath || previewLoading || previewError || preview) && (
          <div style={{ marginTop: 12 }}>
            <div className="fs-inline fs-muted" style={{ marginBottom: 6, justifyContent: "space-between" }}>
              <span title={selectedPath || ""}>Preview: {selectedPath || "No file selected"}</span>
              {preview ? <span>{preview.bytesRead || 0}/{preview.totalBytes || 0} bytes</span> : null}
            </div>
            {previewLoading ? (
              <div className="fs-empty">Loading file preview...</div>
            ) : previewError ? (
              <div className="fs-empty">Preview error: {previewError}</div>
            ) : (
              <pre className="fs-state" style={{ maxHeight: 180, overflow: "auto" }}>
                {(preview?.contentUtf8 || "No preview content available.").slice(0, 4000)}
              </pre>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
