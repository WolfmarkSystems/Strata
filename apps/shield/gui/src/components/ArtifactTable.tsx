import React, { useMemo, useState } from "react";
import { Database, File, Folder } from "lucide-react";
import { cn } from "@/lib/utils";
import ProviderIcon from "@/components/ProviderIcon";

export type ArtifactTableContextAction =
  | "export"
  | "add-note"
  | "tag"
  | "view-hex"
  | "view-strings"
  | "view-timeline";

export interface UnifiedArtifactRow {
  id: string;
  sourceType: "file" | "artifact";
  name: string;
  path: string;
  type: string;
  size?: number;
  createdTime?: number;
  modifiedTime?: number;
  accessedTime?: number;
  mftChangedTime?: number;
  md5?: string;
  sha1?: string;
  sha256?: string;
  category?: string;
  deleted?: boolean;
  mftRecord?: number;
  sequence?: number;
  description?: string;
  isDir?: boolean;
  nodeRef?: unknown;
}

interface ArtifactTableProps {
  rows: UnifiedArtifactRow[];
  selectedIds: Set<string>;
  onSelectionChange: (ids: Set<string>, primary: UnifiedArtifactRow | null) => void;
  onContextAction: (action: ArtifactTableContextAction, row: UnifiedArtifactRow) => void;
}

type SortDirection = "asc" | "desc";

type ColumnId =
  | "name"
  | "path"
  | "type"
  | "size"
  | "createdTime"
  | "modifiedTime"
  | "accessedTime"
  | "mftChangedTime"
  | "md5"
  | "sha1"
  | "sha256"
  | "category"
  | "deleted";

interface ColumnDef {
  id: ColumnId;
  label: string;
  width: number;
  minWidth: number;
  resizable?: boolean;
  sortable?: boolean;
}

const COLUMNS: ColumnDef[] = [
  { id: "name", label: "Name", width: 260, minWidth: 160, sortable: true },
  { id: "path", label: "Full Path", width: 360, minWidth: 220, sortable: true },
  { id: "type", label: "Type", width: 120, minWidth: 90, sortable: true },
  { id: "size", label: "Size", width: 110, minWidth: 90, sortable: true },
  { id: "createdTime", label: "Birth", width: 160, minWidth: 140, sortable: true },
  { id: "modifiedTime", label: "Modified", width: 160, minWidth: 140, sortable: true },
  { id: "accessedTime", label: "Accessed", width: 160, minWidth: 140, sortable: true },
  { id: "mftChangedTime", label: "MFT Changed", width: 170, minWidth: 150, sortable: true },
  { id: "md5", label: "MD5", width: 170, minWidth: 130, sortable: true },
  { id: "sha256", label: "SHA-256", width: 220, minWidth: 150, sortable: true },
  { id: "category", label: "Category", width: 130, minWidth: 110, sortable: true },
  { id: "deleted", label: "Deleted", width: 95, minWidth: 80, sortable: true },
];

function formatSize(bytes?: number): string {
  if (bytes === undefined || bytes === null || !Number.isFinite(bytes)) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(1)} ${units[idx]}`;
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

function getSortValue(row: UnifiedArtifactRow, columnId: ColumnId): string | number {
  switch (columnId) {
    case "name":
      return row.name.toLowerCase();
    case "path":
      return row.path.toLowerCase();
    case "type":
      return row.type.toLowerCase();
    case "size":
      return row.size ?? -1;
    case "createdTime":
      return row.createdTime ?? -1;
    case "modifiedTime":
      return row.modifiedTime ?? -1;
    case "accessedTime":
      return row.accessedTime ?? -1;
    case "mftChangedTime":
      return row.mftChangedTime ?? -1;
    case "md5":
      return qStr(row.md5);
    case "sha256":
      return qStr(row.sha256);
    case "category":
      return qStr(row.category);
    case "deleted":
      return row.deleted ? 1 : 0;
    default:
      return "";
  }
}

function qStr(v?: string) {
  return (v || "").toLowerCase();
}

function rowIcon(row: UnifiedArtifactRow) {
  if (row.isDir) return <Folder className="w-3.5 h-3.5 text-amber-500 fill-amber-500/20" />;

  return (
    <ProviderIcon
      text={`${row.name} ${row.path} ${row.category || ""}`}
      fallback={
        row.sourceType === "artifact" ? (
          <Database className="w-3.5 h-3.5 text-cyan-500" />
        ) : (
          <File className="w-3.5 h-3.5 text-muted-foreground/60" />
        )
      }
    />
  );
}

export default function ArtifactTable({
  rows,
  selectedIds,
  onSelectionChange,
  onContextAction: _onContextAction,
}: ArtifactTableProps) {
  const [sortColumn, setSortColumn] = useState<ColumnId>("name");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [columnWidths] = useState<Record<string, number>>(() => {
    return COLUMNS.reduce((acc, col) => ({ ...acc, [col.id]: col.width }), {});
  });
  const [anchorIndex, setAnchorIndex] = useState<number | null>(null);

  const sortedRows = useMemo(() => {
    const copy = [...rows];
    copy.sort((a, b) => {
      const left = getSortValue(a, sortColumn);
      const right = getSortValue(b, sortColumn);
      if (left < right) return sortDirection === "asc" ? -1 : 1;
      if (left > right) return sortDirection === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }, [rows, sortColumn, sortDirection]);

  const handleRowClick = (event: React.MouseEvent, row: UnifiedArtifactRow, index: number) => {
    if (event.shiftKey && anchorIndex !== null) {
      const start = Math.min(anchorIndex, index);
      const end = Math.max(anchorIndex, index);
      const rangeIds = new Set(selectedIds);
      sortedRows.slice(start, end + 1).forEach((r) => rangeIds.add(r.id));
      onSelectionChange(rangeIds, row);
    } else if (event.ctrlKey || event.metaKey) {
      const next = new Set(selectedIds);
      if (next.has(row.id)) next.delete(row.id);
      else next.add(row.id);
      onSelectionChange(next, row);
    } else {
      onSelectionChange(new Set([row.id]), row);
      setAnchorIndex(index);
    }
  };

  const renderCell = (row: UnifiedArtifactRow, col: ColumnId) => {
    switch (col) {
      case "name":
        return (
          <div className="flex items-center gap-2.5 min-w-0 px-2 py-0.5">
            {rowIcon(row)}
            <span className="truncate font-medium">{row.name}</span>
          </div>
        );
      case "path":
        return <span className="truncate opacity-70 text-[11px] font-mono">{row.path}</span>;
      case "size":
        return <span className="text-right tabular-nums">{formatSize(row.size)}</span>;
      case "createdTime":
        return <span className="tabular-nums opacity-80">{formatTimestamp(row.createdTime)}</span>;
      case "category":
        return (
          <span
            className={cn(
              "px-2 py-0.5 rounded-full text-[10px] uppercase font-bold tracking-tight",
              row.sourceType === "artifact"
                ? "bg-cyan-500/10 text-cyan-500 border border-cyan-500/20"
                : "bg-muted text-muted-foreground"
            )}
          >
            {row.category || "General"}
          </span>
        );
      default:
        return <span className="truncate font-mono text-[11px]">{String(getSortValue(row, col))}</span>;
    }
  };

  return (
    <div className="h-full w-full overflow-auto bg-background selection:bg-primary/20">
      <table className="w-full border-collapse min-w-[1200px]">
        <thead className="sticky top-0 z-10 bg-muted/80 backdrop-blur-sm border-b border-border shadow-sm">
          <tr>
            {COLUMNS.map((col) => (
              <th
                key={col.id}
                className="text-left px-4 py-2 text-[11px] font-bold text-muted-foreground uppercase tracking-widest cursor-pointer hover:text-foreground transition-colors"
                style={{ width: columnWidths[col.id] }}
                onClick={() => {
                  if (sortColumn === col.id) setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
                  else {
                    setSortColumn(col.id);
                    setSortDirection("asc");
                  }
                }}
              >
                <div className="flex items-center gap-2">
                  {col.label}
                  {sortColumn === col.id && (
                    <span className="text-[10px] text-primary">{sortDirection === "asc" ? "\u2191" : "\u2193"}</span>
                  )}
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border/40">
          {sortedRows.map((row, index) => (
            <tr
              key={row.id}
              onClick={(e) => handleRowClick(e, row, index)}
              className={cn(
                "group hover:bg-muted/30 transition-colors cursor-default text-[13px]",
                selectedIds.has(row.id) && "bg-primary/5 ring-1 ring-inset ring-primary/20 shadow-inner"
              )}
            >
              {COLUMNS.map((col) => (
                <td key={col.id} className="px-4 py-1.5 align-middle whitespace-nowrap overflow-hidden">
                  {renderCell(row, col.id)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}