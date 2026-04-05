import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Card from "../components/Card";
import StatusBadge from "../components/StatusBadge";

export interface TimelineRow {
  id?: string;
  timestamp?: string | null;
  type?: string | null;
  title?: string | null;
  description?: string | null;
  source?: string | null;
  severity?: string | null;
}

interface TimelineProps {
  entries?: TimelineRow[];
  loading?: boolean;
  onReload?: () => void;
}

interface BuiltTimelineRow {
  id: string;
  timestamp?: number | null;
  eventType?: string | null;
  source?: string | null;
  description?: string | null;
}

const ROW_HEIGHT = 86;
const VIEWPORT_HEIGHT = 520;

function normalizeText(value: unknown) {
  return String(value || "").toLowerCase();
}

function formatTimestamp(value?: number | null) {
  if (!value || !Number.isFinite(value)) return null;
  const millis = value > 1_000_000_000_000 ? value : value * 1000;
  const d = new Date(millis);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export default function Timeline({ entries = [], loading = false, onReload }: TimelineProps) {
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [scrollTop, setScrollTop] = useState(0);
  const [backendEntries, setBackendEntries] = useState<TimelineRow[]>([]);
  const [backendLoading, setBackendLoading] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);
  const viewportRef = useRef<HTMLDivElement | null>(null);

  const effectiveEntries = entries.length > 0 ? entries : backendEntries;
  const effectiveLoading = loading || backendLoading;

  const fetchTimeline = async () => {
    setBackendLoading(true);
    setBackendError(null);
    try {
      const builtRows = await invoke<BuiltTimelineRow[]>("get_timeline_rows", { limit: 5000 });
      if (builtRows.length > 0) {
        setBackendEntries(
          builtRows
            .filter((row) => (row.timestamp ?? 0) > 0)
            .map((row) => ({
              id: row.id,
              timestamp: formatTimestamp(row.timestamp),
              type: row.eventType || "Event",
              title: row.eventType || "Event",
              description: row.description || "",
              source: row.source || "",
              severity: "info",
            }))
        );
      } else {
        const initial = await invoke<Array<{ id?: string | number; timestamp?: number | null; artifactType?: string; description?: string; sourcePath?: string }>>(
          "get_initial_timeline",
          { limit: 5000 }
        );
        setBackendEntries(
          initial
            .filter((row) => (row.timestamp ?? 0) > 0)
            .map((row, idx) => ({
              id: String(row.id ?? idx),
              timestamp: formatTimestamp(row.timestamp),
              type: row.artifactType || "Event",
              title: row.artifactType || "Event",
              description: row.description || "",
              source: row.sourcePath || "",
              severity: "info",
            }))
        );
      }
    } catch (error) {
      setBackendEntries([]);
      setBackendError(String(error));
    } finally {
      setBackendLoading(false);
    }
  };

  useEffect(() => {
    if (entries.length > 0) return;
    fetchTimeline().catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entries.length]);

  const filtered = useMemo(() => {
    const sorted = [...effectiveEntries].sort((a, b) => {
      const aTime = new Date(a.timestamp || 0).getTime();
      const bTime = new Date(b.timestamp || 0).getTime();
      return bTime - aTime;
    });
    return sorted.filter((entry) => {
      const joined = `${entry.title || ""} ${entry.description || ""} ${entry.source || ""}`;
      const matchesSearch = !search.trim() || normalizeText(joined).includes(normalizeText(search));
      const matchesSource = !sourceFilter.trim() || normalizeText(entry.source) === normalizeText(sourceFilter);
      const matchesSeverity = !severityFilter.trim() || normalizeText(entry.severity) === normalizeText(severityFilter);
      return matchesSearch && matchesSource && matchesSeverity;
    });
  }, [effectiveEntries, search, sourceFilter, severityFilter]);

  const sourceFacets = useMemo(() => {
    const counts = new Map<string, number>();
    effectiveEntries.forEach((entry) => {
      const key = String(entry.source || "unknown");
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [effectiveEntries]);

  const saveCurrentFilter = () => {
    const payload = { search, sourceFilter, severityFilter };
    localStorage.setItem("vantor.timeline.filters", JSON.stringify(payload));
  };

  const loadSavedFilter = () => {
    try {
      const raw = localStorage.getItem("vantor.timeline.filters");
      if (!raw) return;
      const parsed = JSON.parse(raw) as { search?: string; sourceFilter?: string; severityFilter?: string };
      setSearch(parsed.search || "");
      setSourceFilter(parsed.sourceFilter || "");
      setSeverityFilter(parsed.severityFilter || "");
    } catch {
      // ignore malformed local storage payloads
    }
  };

  const totalHeight = filtered.length * ROW_HEIGHT;
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - 4);
  const endIndex = Math.min(filtered.length, startIndex + Math.ceil(VIEWPORT_HEIGHT / ROW_HEIGHT) + 8);
  const visible = filtered.slice(startIndex, endIndex);
  const offsetY = startIndex * ROW_HEIGHT;

  return (
    <Card
      title="Timeline"
      subtitle="Built timeline rows from Tauri backend"
      actions={
        <button
          className="fs-btn"
          onClick={async () => {
            onReload?.();
            if (entries.length === 0) await fetchTimeline();
          }}
          disabled={effectiveLoading}
        >
          {effectiveLoading ? "Loading..." : "Load Timeline"}
        </button>
      }
    >
      <div className="fs-field-grid two-col" style={{ marginBottom: 12 }}>
        <div className="fs-field">
          <label>Search</label>
          <input className="fs-input" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="title/description/source" />
        </div>
        <div className="fs-field-grid two-col">
          <div className="fs-field">
            <label>Source</label>
            <input className="fs-input" value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} placeholder="filesystem, registry..." />
          </div>
          <div className="fs-field">
            <label>Severity</label>
            <input className="fs-input" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} placeholder="info, warn, error" />
          </div>
        </div>
      </div>
      <div className="fs-inline" style={{ justifyContent: "space-between", marginBottom: 12 }}>
        <div className="fs-inline fs-muted">
          <span>Filtered: {filtered.length}</span>
          <span>|</span>
          <span>Total: {effectiveEntries.length}</span>
        </div>
        <div className="fs-inline">
          <button className="fs-btn" type="button" onClick={saveCurrentFilter}>Save Filters</button>
          <button className="fs-btn" type="button" onClick={loadSavedFilter}>Load Filters</button>
        </div>
      </div>
      {sourceFacets.length > 0 && (
        <div className="fs-inline fs-muted" style={{ marginBottom: 12, flexWrap: "wrap" }}>
          {sourceFacets.map(([source, count]) => (
            <button key={source} className="fs-btn" type="button" onClick={() => setSourceFilter(source)}>
              {source} ({count})
            </button>
          ))}
        </div>
      )}

      {backendError && <div className="fs-empty">Timeline load error: {backendError}</div>}

      {filtered.length === 0 ? (
        <div className="fs-empty">
          No usable timestamped entries are available yet.
        </div>
      ) : (
        <div
          ref={viewportRef}
          style={{ height: VIEWPORT_HEIGHT, overflow: "auto", border: "1px solid var(--fs-border)", borderRadius: 8 }}
          onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
        >
          <div style={{ height: totalHeight, position: "relative" }}>
            <div style={{ transform: `translateY(${offsetY}px)` }}>
              {visible.map((entry, index) => (
                <div
                  key={entry.id || `${startIndex + index}-${entry.timestamp || "t"}`}
                  style={{
                    minHeight: ROW_HEIGHT - 1,
                    borderBottom: "1px solid var(--fs-border)",
                    background: "var(--fs-card)",
                    padding: "10px 12px",
                    display: "grid",
                    gap: 6,
                  }}
                >
                  <div className="fs-inline" style={{ justifyContent: "space-between" }}>
                    <strong>{entry.title || entry.type || "Timeline event"}</strong>
                    <StatusBadge status={entry.severity || "info"} />
                  </div>
                  <div className="fs-muted">{entry.description || "No description available."}</div>
                  <div className="fs-inline fs-muted" style={{ justifyContent: "space-between" }}>
                    <span>{entry.timestamp || "Unknown time"}</span>
                    <span>{entry.source || "Unknown source"}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
