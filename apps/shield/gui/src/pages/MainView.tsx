import React, { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Clock,
  Cpu,
  Filter,
  Search,
  Terminal,
  LayoutList,
  History,
  Activity,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import ArtifactTable, {
  ArtifactTableContextAction,
  UnifiedArtifactRow,
} from "@/components/ArtifactTable";
import ArtifactNavigator from "@/components/ArtifactNavigator";
import { detectCategory } from "@/lib/artifactProviders";

export type MainTab = "table" | "hex" | "strings" | "timeline";

interface TimelineEntry {
  id: string;
  timestamp: string;
  source: string;
  event_type: string;
  description: string;
  severity: string;
}

interface ArtifactPreview {
  artifactPath: string;
  bytesRead: number;
  totalBytes: number;
  truncated: boolean;
  hexDump: string;
  strings: string[];
}

interface MainViewProps {
  rows: UnifiedArtifactRow[];
  activeTab: MainTab;
  onActiveTabChange: (tab: MainTab) => void;
  timeline: TimelineEntry[];
  preview: ArtifactPreview | null;
  previewLoading: boolean;
  previewError: string | null;
  selectedRowId: string | null;
  onPrimaryRowChange: (row: UnifiedArtifactRow | null) => void;
  onContextAction: (action: ArtifactTableContextAction, row: UnifiedArtifactRow) => void;
  onExportSelected: (rows: UnifiedArtifactRow[]) => void;
  evidencePath?: string | null;
}

interface TreeNodeLike {
  name: string;
  path: string;
  isDir: boolean;
  size?: number;
  createdTime?: number;
  modifiedTime?: number;
  accessedTime?: number;
  mftChangedTime?: number;
  hash?: string;
  category?: string;
  isDeleted?: boolean;
  children?: TreeNodeLike[];
}

function formatTimestamp(value?: number): string {
  if (value === undefined || value === null || !Number.isFinite(value)) return "-";
  if (value > 10_000_000_000_000) {
    const unixMs = Math.floor(value / 10_000 - 11_644_473_600_000);
    const d = new Date(unixMs);
    if (!Number.isNaN(d.getTime())) return d.toLocaleString();
    return `${value}`;
  }
  if (value > 1_000_000_000_000) {
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) return d.toLocaleString();
    return `${value}`;
  }
  if (value > 0) {
    const d = new Date(value * 1000);
    if (!Number.isNaN(d.getTime())) return d.toLocaleString();
  }
  return `${value}`;
}

export default function MainView({
  rows,
  activeTab,
  onActiveTabChange,
  timeline,
  preview,
  previewLoading,
  previewError: _previewError,
  selectedRowId,
  onPrimaryRowChange,
  onContextAction,
  onExportSelected: _onExportSelected,
  evidencePath = null,
}: MainViewProps) {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [treeSelection, setTreeSelection] = useState<{type: string, value: string} | null>(null);
  
  const [backendRows, setBackendRows] = useState<UnifiedArtifactRow[]>([]);
  const [backendTimeline, setBackendTimeline] = useState<TimelineEntry[]>([]);
  const [_backendLoading, setBackendLoading] = useState(false);
  const [_backendError, setBackendError] = useState<string | null>(null);

  useEffect(() => {
    if (!evidencePath || rows.length > 0) return;

    let cancelled = false;
    const run = async () => {
      setBackendLoading(true);
      setBackendError(null);
      try {
        const loaded = await invoke<{ tree: TreeNodeLike }>("load_evidence_and_build_tree", {
          path: evidencePath,
          runArtifactParsers: true, // Enabled for better detection
        });

        const flattened: UnifiedArtifactRow[] = [];
        const walk = (node: TreeNodeLike) => {
          flattened.push({
            id: `fs:${node.path}:${node.name}`,
            sourceType: node.category ? "artifact" : "file",
            name: node.name,
            path: node.path,
            type: node.isDir ? "directory" : (node.path.split(".").pop() || "file"),
            size: node.size,
            createdTime: node.createdTime,
            modifiedTime: node.modifiedTime,
            accessedTime: node.accessedTime,
            mftChangedTime: node.mftChangedTime,
            sha256: node.hash,
            category: node.category || detectCategory(node.name, node.path),
            deleted: Boolean(node.isDeleted),
            isDir: node.isDir,
            nodeRef: node,
          });
          node.children?.forEach(walk);
        };
        walk(loaded.tree);

        const tRows = await invoke<Array<{ id: string; timestamp?: number | null; eventType?: string; source?: string; description?: string }>>(
          "get_timeline_rows",
          { limit: 5000 }
        );

        if (!cancelled) {
          setBackendRows(flattened);
          setBackendTimeline(
            tRows.map((row) => ({
              id: row.id,
              timestamp: String(row.timestamp ?? ""),
              source: row.source || "",
              event_type: row.eventType || "Event",
              description: row.description || "",
              severity: "info",
            }))
          );
        }
      } catch (error) {
        if (!cancelled) {
          setBackendRows([]);
          setBackendTimeline([]);
          setBackendError(String(error));
        }
      } finally {
        if (!cancelled) setBackendLoading(false);
      }
    };
    run().catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, [evidencePath, rows.length]);

  const effectiveRows = rows.length > 0 ? rows : backendRows;
  const effectiveTimeline = timeline.length > 0 ? timeline : backendTimeline;

  useEffect(() => {
    if (!selectedRowId) return;
    setSelectedIds(new Set([selectedRowId]));
    const row = rows.find((item) => item.id === selectedRowId) || null;
    const fallback = effectiveRows.find((item) => item.id === selectedRowId) || null;
    if (row || fallback) onPrimaryRowChange(row || fallback);
  }, [selectedRowId, rows, effectiveRows, onPrimaryRowChange]);

  const filteredRows = useMemo(() => {
    return effectiveRows.filter((row) => {
      // 1. Search Query
      const text = `${row.name} ${row.path} ${row.type} ${row.md5 || ""} ${row.sha1 || ""} ${row.sha256 || ""}`
        .toLowerCase();
      if (query && !text.includes(query.toLowerCase())) return false;

      // 2. Type Filter (Select box)
      if (typeFilter !== "all") {
        if (typeFilter === "artifact" && row.sourceType !== "artifact") return false;
        if (typeFilter === "directory" && !row.isDir) return false;
        if (typeFilter === "file" && (row.sourceType !== "file" || row.isDir)) return false;
      }

      // 3. Tree Selection
      if (treeSelection) {
        if (treeSelection.type === "category") {
          const rowCat = row.category || detectCategory(row.name, row.path);
          if (rowCat !== treeSelection.value) return false;
        } else if (treeSelection.type === "provider") {
            const rowText = `${row.name} ${row.path}`.toLowerCase();
            if (!rowText.includes(treeSelection.value.split(":")[1].toLowerCase())) return false;
        }
      }

      return true;
    });
  }, [effectiveRows, query, typeFilter, treeSelection]);

  const selectedRows = useMemo(() => {
    if (selectedIds.size === 0) return [];
    const idSet = new Set(selectedIds);
    return filteredRows.filter((row) => idSet.has(row.id));
  }, [selectedIds, filteredRows]);

  const primarySelectedRow = useMemo(() => {
    if (selectedRowId) {
      const fromExternal = filteredRows.find((row) => row.id === selectedRowId);
      if (fromExternal) return fromExternal;
    }
    const first = selectedRows[0];
    return first || null;
  }, [filteredRows, selectedRowId, selectedRows]);

  const tableTabs: Array<{ id: MainTab; label: string; icon: React.ComponentType<{ className?: string }> }> = [
    { id: "table", label: "Evidence Table", icon: Filter },
    { id: "hex", label: "Hex Viewer", icon: Cpu },
    { id: "strings", label: "Strings", icon: Terminal },
    { id: "timeline", label: "Timeline", icon: Clock },
  ];

  return (
    <div className="h-full w-full overflow-hidden flex flex-row bg-background">
      {/* LEFT: Category Navigator */}
      <ArtifactNavigator 
        className="w-64"
        rows={effectiveRows}
        selectedId={treeSelection?.value || null}
        onSelect={(type, value) => setTreeSelection({ type, value })}
      />

      <div className="flex-1 overflow-hidden flex flex-col border-l border-border">
        {/* TOP: Search and Filters */}
        <div className="h-12 border-b border-border flex items-center px-4 gap-4 bg-muted/30">
          <div className="flex-1 relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter current view..."
              className="w-full bg-background border border-border rounded-md pl-9 pr-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <select 
            value={typeFilter} 
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-background border border-border rounded-md px-2 py-1.5 text-sm outline-none"
          >
            <option value="all">All Items</option>
            <option value="artifact">Artifacts Only</option>
            <option value="file">Files Only</option>
            <option value="directory">Folders Only</option>
          </select>
          <div className="flex items-center gap-2 text-xs text-muted-foreground bg-background/50 px-2 py-1 rounded border border-border/50">
            <Activity className="w-3 h-3 text-primary animate-pulse" />
            <span>{filteredRows.length.toLocaleString()} matching artifacts</span>
          </div>
        </div>

        {/* MIDDLE: Content Area */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Sub Tabs */}
          <div className="flex border-b border-border bg-muted/20">
            {tableTabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => onActiveTabChange(tab.id)}
                className={cn(
                  "px-4 py-2 text-xs font-medium border-b-2 transition-colors flex items-center gap-2",
                  activeTab === tab.id 
                    ? "border-primary text-primary bg-background" 
                    : "border-transparent text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                )}
              >
                <tab.icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-hidden relative">
            {activeTab === "table" && (
              <ArtifactTable
                rows={filteredRows}
                selectedIds={selectedIds}
                onSelectionChange={(ids, primary) => {
                  setSelectedIds(ids);
                  onPrimaryRowChange(primary);
                }}
                onContextAction={onContextAction}
              />
            )}
            
            {activeTab === "hex" && (
              <div className="h-full p-4 overflow-auto font-mono text-xs bg-muted/5">
                {previewLoading ? <p className="text-center py-10">Loading hex...</p> : <pre className="whitespace-pre-wrap">{preview?.hexDump || "No data"}</pre>}
              </div>
            )}

            {activeTab === "strings" && (
                <div className="h-full p-4 overflow-auto font-mono text-xs bg-muted/5">
                    {previewLoading ? <p className="text-center py-10">Extracting strings...</p> : <pre className="whitespace-pre-wrap">{preview?.strings?.join("\n") || "No strings"}</pre>}
                </div>
            )}
            
            {activeTab === "timeline" && (
                <div className="h-full p-4 overflow-auto">
                    {effectiveTimeline.length > 0 ? (
                        effectiveTimeline.map((e) => (
                            <div key={e.id} className="mb-2 p-2 border border-border rounded bg-card text-xs">
                                <span className="font-bold">{e.event_type}</span> | {e.timestamp} | {e.source}
                                <p className="mt-1 opacity-70">{e.description}</p>
                            </div>
                        ))
                    ) : (
                        <div className="h-full grid place-items-center text-center text-sm text-muted-foreground">
                            {evidencePath
                                ? "Timeline is building — artifact parsers are running in background."
                                : "Load evidence to generate a timeline."}
                        </div>
                    )}
                </div>
            )}
          </div>
        </div>

        {/* BOTTOM: Detail Preview */}
        {primarySelectedRow && (
          <div className="h-48 border-t border-border bg-card p-4 overflow-auto">
            <div className="flex items-center gap-2 mb-3 text-muted-foreground text-[10px] uppercase font-bold tracking-wider">
               <History className="w-3 h-3" />
               Artifact Intelligence Details
            </div>
            <div className="grid grid-cols-3 gap-6 text-sm">
              <div className="space-y-2">
                <div>
                  <label className="text-[10px] text-muted-foreground block mb-0.5">INTERNAL NAME</label>
                  <div className="font-medium truncate">{primarySelectedRow.name}</div>
                </div>
                <div>
                  <label className="text-[10px] text-muted-foreground block mb-0.5">SOURCE PATH</label>
                  <div className="font-mono text-[11px] truncate">{primarySelectedRow.path}</div>
                </div>
              </div>
              <div className="space-y-2 text-xs">
                 <div className="flex flex-col">
                    <span className="text-muted-foreground">CREATED</span>
                    <span>{formatTimestamp(primarySelectedRow.createdTime)}</span>
                 </div>
                 <div className="flex flex-col">
                    <span className="text-muted-foreground">MODIFIED</span>
                    <span>{formatTimestamp(primarySelectedRow.modifiedTime)}</span>
                 </div>
              </div>
              <div className="space-y-2">
                 <div>
                    <label className="text-[10px] text-muted-foreground block mb-0.5 text-right">HASH (SHA256)</label>
                    <div className="font-mono text-[10px] text-right truncate bg-muted/30 p-1 rounded border border-border/50">
                        {primarySelectedRow.sha256 || "UNKNOWN"}
                    </div>
                 </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* RIGHT: Quick Filters or Metadata? */}
      <div className="w-12 bg-muted/10 border-l border-border flex flex-col items-center py-4 gap-6">
         <LayoutList className="w-5 h-5 text-muted-foreground hover:text-primary cursor-pointer" />
         <History className="w-5 h-5 text-muted-foreground hover:text-primary cursor-pointer" />
         <ChevronRight className="w-5 h-5 text-muted-foreground hover:text-primary cursor-pointer mt-auto" />
      </div>
    </div>
  );
}

