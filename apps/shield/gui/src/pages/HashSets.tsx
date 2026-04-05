import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import Card from "../components/Card";
import StatusBadge from "../components/StatusBadge";

interface MatchRow {
  path?: string | null;
  sha256?: string | null;
  category?: string | null;
  size_bytes?: number | null;
}

interface HashSetsProps {
  caseId?: string | null;
  caseDbPath?: string | null;
  evidencePath?: string | null;
  nsrlPath: string;
  knownGoodPath: string;
  knownBadPath: string;
  onNsrlPathChange: (value: string) => void;
  onKnownGoodPathChange: (value: string) => void;
  onKnownBadPathChange: (value: string) => void;
  onRunMatch?: () => void;
  running?: boolean;
  status?: {
    hashsetsLoaded?: boolean;
    nsrlLoaded?: boolean;
    customLoaded?: boolean;
    knownGoodCount?: number;
    knownBadCount?: number;
    knownGoodMatches?: number;
    knownBadMatches?: number;
    unmatched?: number;
  } | null;
  matches?: MatchRow[];
}

interface HashSetLoadResult {
  nsrlCount: number;
  customBadCount: number;
}

interface HashVfsFilesResult {
  totalFiles: number;
  hashedFiles: number;
  knownGoodMatches: number;
  knownBadMatches: number;
  unmatched: number;
  nsrlCount: number;
  customBadCount: number;
  sampleMatches: Array<{
    path: string;
    sha256: string;
    category: string;
    size: number;
  }>;
}

async function chooseHashFile(): Promise<string | null> {
  const selected = await open({
    directory: false,
    multiple: false,
    filters: [{ name: "Hash data", extensions: ["csv", "txt", "json", "db", "sqlite"] }],
    title: "Select hash set file",
  });
  if (typeof selected === "string") return selected;
  return null;
}

export default function HashSets({
  caseId,
  caseDbPath,
  evidencePath,
  nsrlPath,
  knownGoodPath,
  knownBadPath,
  onNsrlPathChange,
  onKnownGoodPathChange,
  onKnownBadPathChange,
  onRunMatch,
  running = false,
  status,
  matches = [],
}: HashSetsProps) {
  const [backendRunning, setBackendRunning] = useState(false);
  const [backendStatus, setBackendStatus] = useState<HashSetsProps["status"] | null>(null);
  const [backendMatches, setBackendMatches] = useState<MatchRow[]>([]);
  const [backendError, setBackendError] = useState<string | null>(null);

  const effectiveRunning = running || backendRunning;
  const effectiveStatus = status ?? backendStatus;
  const effectiveMatches = matches.length > 0 ? matches : backendMatches;

  const canRunBackend = useMemo(
    () => Boolean(evidencePath && caseId && caseDbPath),
    [evidencePath, caseId, caseDbPath]
  );

  const runBackendMatch = async () => {
    if (!evidencePath) {
      setBackendError("Evidence path is required to hash VFS files.");
      return;
    }

    setBackendRunning(true);
    setBackendError(null);
    try {
      if (nsrlPath) {
        await invoke<HashSetLoadResult>("load_nsrl_database", {
          nsrlPath,
        });
      }

      const result = await invoke<HashVfsFilesResult>("hash_vfs_files", {
        evidencePath,
        nsrlPath: nsrlPath || null,
        customBadPath: knownBadPath || null,
      });

      setBackendStatus({
        hashsetsLoaded: (result.nsrlCount || 0) > 0 || (result.customBadCount || 0) > 0,
        nsrlLoaded: (result.nsrlCount || 0) > 0,
        customLoaded: (result.customBadCount || 0) > 0,
        knownGoodCount: result.nsrlCount || 0,
        knownBadCount: result.customBadCount || 0,
        knownGoodMatches: result.knownGoodMatches || 0,
        knownBadMatches: result.knownBadMatches || 0,
        unmatched: result.unmatched || 0,
      });

      setBackendMatches(
        (result.sampleMatches || []).map((row) => ({
          path: row.path,
          sha256: row.sha256,
          category: row.category,
          size_bytes: row.size,
        }))
      );
    } catch (error) {
      setBackendStatus(null);
      setBackendMatches([]);
      setBackendError(String(error));
    } finally {
      setBackendRunning(false);
    }
  };

  return (
    <div className="fs-grid">
      <Card
        title="Hash Sets"
        subtitle="Known-good / known-bad matching via Tauri hashset commands"
        actions={
          <button
            className="fs-btn"
            onClick={async () => {
              if (onRunMatch) {
                onRunMatch();
                return;
              }
              await runBackendMatch();
            }}
            disabled={effectiveRunning || (!onRunMatch && !canRunBackend)}
          >
            {effectiveRunning ? "Running..." : "Run Match"}
          </button>
        }
      >
        <div className="fs-inline fs-muted" style={{ marginBottom: 12 }}>
          <span title={caseId || ""}>Case: {caseId || "Not selected"}</span>
          <span>|</span>
          <span title={caseDbPath || ""}>DB: {caseDbPath || "Not selected"}</span>
          <span>|</span>
          <span title={evidencePath || ""}>Evidence: {evidencePath || "Not selected"}</span>
        </div>

        <div className="fs-field-grid">
          <div className="fs-inline">
            <div className="fs-field" style={{ flex: 1 }}>
              <label>NSRL / Known Good</label>
              <input className="fs-input" value={nsrlPath} onChange={(e) => onNsrlPathChange(e.target.value)} placeholder="Path to NSRL SQLite/CSV/hash list" />
            </div>
            <button
              type="button"
              className="fs-btn"
              onClick={async () => {
                const path = await chooseHashFile();
                if (path) onNsrlPathChange(path);
              }}
            >
              Pick
            </button>
          </div>

          <div className="fs-inline">
            <div className="fs-field" style={{ flex: 1 }}>
              <label>Known Good (Optional)</label>
              <input className="fs-input" value={knownGoodPath} onChange={(e) => onKnownGoodPathChange(e.target.value)} placeholder="Additional known-good hash list" />
            </div>
            <button
              type="button"
              className="fs-btn"
              onClick={async () => {
                const path = await chooseHashFile();
                if (path) onKnownGoodPathChange(path);
              }}
            >
              Pick
            </button>
          </div>

          <div className="fs-inline">
            <div className="fs-field" style={{ flex: 1 }}>
              <label>Known Bad</label>
              <input className="fs-input" value={knownBadPath} onChange={(e) => onKnownBadPathChange(e.target.value)} placeholder="Known-bad hash list" />
            </div>
            <button
              type="button"
              className="fs-btn"
              onClick={async () => {
                const path = await chooseHashFile();
                if (path) onKnownBadPathChange(path);
              }}
            >
              Pick
            </button>
          </div>
        </div>

        {backendError && <div className="fs-empty" style={{ marginTop: 10 }}>Hashset error: {backendError}</div>}
      </Card>

      <Card title="Load Status" subtitle="Live status from hashset/hashing command output">
        {!effectiveStatus ? (
          <div className="fs-empty">No hashset status available yet.</div>
        ) : (
          <div className="fs-field-grid two-col">
            <div>{effectiveStatus.hashsetsLoaded ? <StatusBadge status="ok" label="Hashsets Loaded" /> : <StatusBadge status="warn" label="Not Loaded" />}</div>
            <div>{effectiveStatus.nsrlLoaded ? <StatusBadge status="ok" label="NSRL Loaded" /> : <StatusBadge status="warn" label="NSRL Missing" />}</div>
            <div>{effectiveStatus.customLoaded ? <StatusBadge status="ok" label="Custom Loaded" /> : <StatusBadge status="warn" label="Custom Missing" />}</div>
            <div className="fs-muted">Known Good: {effectiveStatus.knownGoodCount ?? 0}</div>
            <div className="fs-muted">Known Bad: {effectiveStatus.knownBadCount ?? 0}</div>
            <div className="fs-muted">Known Good Matches: {effectiveStatus.knownGoodMatches ?? 0}</div>
            <div className="fs-muted">Known Bad Matches: {effectiveStatus.knownBadMatches ?? 0}</div>
            <div className="fs-muted">Unmatched: {effectiveStatus.unmatched ?? 0}</div>
          </div>
        )}
      </Card>

      <Card title="Match Table" subtitle="Sample matched rows from hash_vfs_files output">
        {effectiveMatches.length === 0 ? (
          <div className="fs-empty">
            No match samples returned yet. This is expected when no hash sets are loaded or no case hashes exist.
          </div>
        ) : (
          <div className="fs-table-wrap">
            <table className="fs-table">
              <thead>
                <tr>
                  <th>Path</th>
                  <th>SHA256</th>
                  <th>Category</th>
                  <th>Size</th>
                </tr>
              </thead>
              <tbody>
                {effectiveMatches.map((row, index) => (
                  <tr key={`${row.sha256 || "hash"}-${index}`}>
                    <td className="fs-path" title={row.path || ""}>{row.path || "N/A"}</td>
                    <td className="fs-mono fs-path" title={row.sha256 || ""}>{row.sha256 || "N/A"}</td>
                    <td><StatusBadge status={row.category || "info"} label={row.category || "unknown"} /></td>
                    <td>{row.size_bytes ?? "N/A"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
