import React, { useEffect, useMemo, useState } from "react";
import { Copy, Download, File, Folder, Hash, NotebookPen, Tag, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import ProviderIcon from "@/components/ProviderIcon";

export type UnifiedTableAction = "export" | "add-note" | "view-hex" | "view-strings" | "tag";

export interface UnifiedTableRow {
  id: string;
  name: string;
  fullPath: string;
  size?: number;
  birth?: number;
  modified?: number;
  accessed?: number;
  mftChanged?: number;
  md5?: string;
  sha1?: string;
  sha256?: string;
  category?: string;
  deleted?: boolean;
  mftRecord?: number;
  sequence?: number;
  tags?: string[];
  isDir?: boolean;
  nodeRef?: unknown;
}

interface UnifiedTableProps {
  rows: UnifiedTableRow[];
  selectedIds: Set<string>;
  onSelectionChange: (ids: Set<string>, primary: UnifiedTableRow | null) => void;
  onAction: (action: UnifiedTableAction, row: UnifiedTableRow) => void;
}

type SortDirection = "asc" | "desc";

type ColumnId =
  | "name"
  | "fullPath"
  | "size"
  | "birth"
  | "modified"
  | "accessed"
  | "mftChanged"
  | "md5"
  | "sha1"
  | "sha256"
  | "category"
  | "deleted"
  | "mftRecord"
  | "sequence"
  | "tags";

interface ColumnDef {
  id: ColumnId;
  label: string;
  width: number;
  minWidth: number;
  sortable?: boolean;
  filterable?: boolean;
}

const COLUMNS: ColumnDef[] = [
  { id: "name", label: "Name", width: 250, minWidth: 160, sortable: true, filterable: true },
  { id: "fullPath", label: "Full Path", width: 360, minWidth: 220, sortable: true, filterable: true },
  { id: "size", label: "Size", width: 110, minWidth: 90, sortable: true },
  { id: "birth", label: "Birth/Created", width: 170, minWidth: 140, sortable: true },
  { id: "modified", label: "Modified", width: 170, minWidth: 140, sortable: true },
  { id: "accessed", label: "Accessed", width: 170, minWidth: 140, sortable: true },
  { id: "mftChanged", label: "MFT Changed", width: 170, minWidth: 140, sortable: true },
  { id: "md5", label: "MD5", width: 180, minWidth: 140, sortable: true, filterable: true },
  { id: "sha1", label: "SHA1", width: 180, minWidth: 140, sortable: true, filterable: true },
  { id: "sha256", label: "SHA-256", width: 220, minWidth: 150, sortable: true, filterable: true },
  { id: "category", label: "Category", width: 120, minWidth: 100, sortable: true, filterable: true },
  { id: "deleted", label: "Deleted", width: 95, minWidth: 80, sortable: true, filterable: true },
  { id: "mftRecord", label: "MFT Record", width: 120, minWidth: 100, sortable: true },
  { id: "sequence", label: "Sequence", width: 100, minWidth: 90, sortable: true },
  { id: "tags", label: "Tags", width: 160, minWidth: 120, sortable: true, filterable: true },
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
    const date = new Date(unixMs);
    return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
  }
  if (value > 1_000_000_000_000) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
  }
  if (value > 0) {
    const date = new Date(value * 1000);
    return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
  }
  return "-";
}

function toSortValue(row: UnifiedTableRow, column: ColumnId): string | number {
  switch (column) {
    case "name":
      return row.name.toLowerCase();
    case "fullPath":
      return row.fullPath.toLowerCase();
    case "size":
      return row.size ?? -1;
    case "birth":
      return row.birth ?? -1;
    case "modified":
      return row.modified ?? -1;
    case "accessed":
      return row.accessed ?? -1;
    case "mftChanged":
      return row.mftChanged ?? -1;
    case "md5":
      return (row.md5 || "").toLowerCase();
    case "sha1":
      return (row.sha1 || "").toLowerCase();
    case "sha256":
      return (row.sha256 || "").toLowerCase();
    case "category":
      return (row.category || "Unknown").toLowerCase();
    case "deleted":
      return row.deleted ? 1 : 0;
    case "mftRecord":
      return row.mftRecord ?? -1;
    case "sequence":
      return row.sequence ?? -1;
    case "tags":
      return (row.tags || []).join(",").toLowerCase();
    default:
      return "";
  }
}

function iconForRow(row: UnifiedTableRow) {
  if (row.isDir) {
    return <Folder className="w-3.5 h-3.5 text-yellow-400" />;
  }

  return (
    <ProviderIcon
      text={`${row.name} ${row.fullPath} ${row.category || ""}`}
      fallback={<File className="w-3.5 h-3.5 fs-muted-icon" />}
    />
  );
}

export default function UnifiedTable({ rows, selectedIds, onSelectionChange, onAction }: UnifiedTableProps) {
  const [sortColumn, setSortColumn] = useState<ColumnId>("name");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [columnWidths, setColumnWidths] = useState<Record<ColumnId, number>>(() => {
    return COLUMNS.reduce((acc, column) => {
      acc[column.id] = column.width;
      return acc;
    }, {} as Record<ColumnId, number>);
  });
  const [filters, setFilters] = useState<Partial<Record<ColumnId, string>>>({});
  const [anchorIndex, setAnchorIndex] = useState<number | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; row: UnifiedTableRow } | null>(null);

  useEffect(() => {
    const close = () => setContextMenu(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, []);

  const filteredRows = useMemo(() => {
    return rows.filter((row) => {
      const tagText = (row.tags || []).join(",");
      const checks: Record<ColumnId, string> = {
        name: row.name,
        fullPath: row.fullPath,
        size: String(row.size ?? ""),
        birth: formatTimestamp(row.birth),
        modified: formatTimestamp(row.modified),
        accessed: formatTimestamp(row.accessed),
        mftChanged: formatTimestamp(row.mftChanged),
        md5: row.md5 || "",
        sha1: row.sha1 || "",
        sha256: row.sha256 || "",
        category: row.category || "Unknown",
        deleted: row.deleted ? "yes" : "no",
        mftRecord: String(row.mftRecord ?? ""),
        sequence: String(row.sequence ?? ""),
        tags: tagText,
      };

      return COLUMNS.every((column) => {
        const term = (filters[column.id] || "").toLowerCase();
        if (!term) return true;
        return checks[column.id].toLowerCase().includes(term);
      });
    });
  }, [rows, filters]);

  const sortedRows = useMemo(() => {
    const copy = [...filteredRows];
    copy.sort((a, b) => {
      const left = toSortValue(a, sortColumn);
      const right = toSortValue(b, sortColumn);
      if (left < right) return sortDirection === "asc" ? -1 : 1;
      if (left > right) return sortDirection === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }, [filteredRows, sortColumn, sortDirection]);

  const toggleSort = (column: ColumnId) => {
    if (sortColumn === column) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
      return;
    }
    setSortColumn(column);
    setSortDirection("asc");
  };

  const beginResize = (event: React.MouseEvent, column: ColumnDef) => {
    event.preventDefault();
    event.stopPropagation();
    const startX = event.clientX;
    const startWidth = columnWidths[column.id];

    const onMove = (moveEvent: MouseEvent) => {
      const nextWidth = Math.max(column.minWidth, startWidth + moveEvent.clientX - startX);
      setColumnWidths((prev) => ({ ...prev, [column.id]: nextWidth }));
    };

    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const updateSelection = (next: Set<string>, primary: UnifiedTableRow | null, index: number | null) => {
    onSelectionChange(next, primary);
    setAnchorIndex(index);
  };

  const onRowClick = (event: React.MouseEvent, row: UnifiedTableRow, index: number) => {
    const isMulti = event.ctrlKey || event.metaKey;

    if (event.shiftKey && anchorIndex !== null) {
      const start = Math.min(anchorIndex, index);
      const end = Math.max(anchorIndex, index);
      const next = new Set(selectedIds);
      sortedRows.slice(start, end + 1).forEach((item) => next.add(item.id));
      updateSelection(next, row, index);
      return;
    }

    if (isMulti) {
      const next = new Set(selectedIds);
      if (next.has(row.id)) next.delete(row.id);
      else next.add(row.id);
      const primary = sortedRows.find((item) => next.has(item.id)) || null;
      updateSelection(next, primary, index);
      return;
    }

    updateSelection(new Set([row.id]), row, index);
  };

  const copyPath = async (event: React.MouseEvent, path: string) => {
    event.stopPropagation();
    try {
      await navigator.clipboard.writeText(path);
    } catch {
      // ignore clipboard failures in restricted contexts
    }
  };

  const renderCell = (row: UnifiedTableRow, column: ColumnId) => {
    switch (column) {
      case "name":
        return (
          <div className="flex items-center gap-2 min-w-0">
            {iconForRow(row)}
            <span className="truncate" title={row.name}>{row.name}</span>
          </div>
        );
      case "fullPath":
        return (
          <div className="flex items-center gap-2 min-w-0">
            <span className="truncate" title={row.fullPath}>{row.fullPath}</span>
            <button className="fs-cell-icon" onClick={(event) => copyPath(event, row.fullPath)} title="Copy full path">
              <Copy className="w-3 h-3" />
            </button>
          </div>
        );
      case "size":
        return <span>{formatSize(row.size)}</span>;
      case "birth":
        return <span>{formatTimestamp(row.birth)}</span>;
      case "modified":
        return <span>{formatTimestamp(row.modified)}</span>;
      case "accessed":
        return <span>{formatTimestamp(row.accessed)}</span>;
      case "mftChanged":
        return <span>{formatTimestamp(row.mftChanged)}</span>;
      case "md5":
        return <span className="font-mono text-[11px]">{row.md5 || "-"}</span>;
      case "sha1":
        return <span className="font-mono text-[11px]">{row.sha1 || "-"}</span>;
      case "sha256":
        return <span className="font-mono text-[11px]">{row.sha256 || "-"}</span>;
      case "category":
        return <span className={cn("fs-status-badge", /malware|csam|notable/i.test(row.category || "") ? "flagged" : "completed")}>{row.category || "Unknown"}</span>;
      case "deleted":
        return <span className={cn("fs-status-badge", row.deleted ? "flagged" : "completed")}>{row.deleted ? "Yes" : "No"}</span>;
      case "mftRecord":
        return <span className="font-mono text-[11px]">{row.mftRecord ?? "-"}</span>;
      case "sequence":
        return <span className="font-mono text-[11px]">{row.sequence ?? "-"}</span>;
      case "tags":
        return <span>{row.tags && row.tags.length > 0 ? row.tags.join(", ") : "-"}</span>;
      default:
        return <span>-</span>;
    }
  };

  const actions: Array<{ id: UnifiedTableAction; label: string; icon: React.ReactNode }> = [
    { id: "export", label: "Export", icon: <Download className="w-3.5 h-3.5" /> },
    { id: "add-note", label: "Add Note", icon: <NotebookPen className="w-3.5 h-3.5" /> },
    { id: "view-hex", label: "View in Hex", icon: <Hash className="w-3.5 h-3.5" /> },
    { id: "view-strings", label: "View Strings", icon: <Terminal className="w-3.5 h-3.5" /> },
    { id: "tag", label: "Tag", icon: <Tag className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="fs-table-shell">
      <div className="fs-table-scroll">
        <table className="fs-table-grid">
          <thead>
            <tr>
              {COLUMNS.map((column) => (
                <th key={column.id} className="fs-th" style={{ width: columnWidths[column.id], minWidth: column.minWidth }} onClick={() => column.sortable && toggleSort(column.id)}>
                  <div className="fs-th-content">
                    <span>{column.label}</span>
                    {sortColumn === column.id && <span className="fs-sort">{sortDirection === "asc" ? "^" : "v"}</span>}
                  </div>
                  <div className="fs-col-resizer" onMouseDown={(event) => beginResize(event, column)} />
                </th>
              ))}
            </tr>
            <tr>
              {COLUMNS.map((column) => (
                <th key={`${column.id}-filter`} className="fs-filter-th">
                  {column.filterable ? (
                    <input
                      value={filters[column.id] || ""}
                      onChange={(event) => setFilters((prev) => ({ ...prev, [column.id]: event.target.value }))}
                      className="fs-filter-input"
                      placeholder="Filter"
                    />
                  ) : (
                    <span className="fs-filter-spacer" />
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sortedRows.map((row, index) => {
              const isSelected = selectedIds.has(row.id);
              return (
                <tr
                  key={row.id}
                  className={cn("fs-row", index % 2 === 0 ? "fs-row-even" : "fs-row-odd", isSelected && "is-selected")}
                  onClick={(event) => onRowClick(event, row, index)}
                  onContextMenu={(event) => {
                    event.preventDefault();
                    if (!selectedIds.has(row.id)) {
                      updateSelection(new Set([row.id]), row, index);
                    }
                    setContextMenu({ x: event.clientX, y: event.clientY, row });
                  }}
                >
                  {COLUMNS.map((column) => (
                    <td key={`${row.id}-${column.id}`} className="fs-td" style={{ width: columnWidths[column.id], minWidth: column.minWidth }}>
                      {renderCell(row, column.id)}
                    </td>
                  ))}
                </tr>
              );
            })}
            {sortedRows.length === 0 && (
              <tr>
                <td className="fs-empty-row" colSpan={COLUMNS.length}>No results</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {contextMenu && (
        <div className="fs-context-menu" style={{ top: contextMenu.y, left: contextMenu.x }}>
          {actions.map((action) => (
            <button
              key={action.id}
              className="fs-context-item"
              onClick={() => {
                onAction(action.id, contextMenu.row);
                setContextMenu(null);
              }}
            >
              {action.icon}
              <span>{action.label}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

