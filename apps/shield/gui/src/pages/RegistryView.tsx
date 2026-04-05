import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { File } from "lucide-react";
import ProviderIcon from "@/components/ProviderIcon";
import { cn } from "@/lib/utils";

export interface RegistryRow {
  id: string;
  key: string;
  value: string;
  data: string;
  lastWrite?: number;
  source: string;
}

interface RegistryViewProps {
  rows: RegistryRow[];
}

type SortColumn = "key" | "value" | "data" | "lastWrite" | "source";

function formatTimestamp(value?: number): string {
  if (value === undefined || value === null || !Number.isFinite(value)) return "—";
  if (value > 10_000_000_000_000) {
    const unixMs = Math.floor(value / 10_000 - 11_644_473_600_000);
    const date = new Date(unixMs);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
  }
  if (value > 1_000_000_000_000) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
  }
  if (value > 0) {
    const date = new Date(value * 1000);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
  }
  return "—";
}

export default function RegistryView({ rows }: RegistryViewProps) {
  const [sortBy, setSortBy] = useState<SortColumn>("lastWrite");
  const [direction, setDirection] = useState<"asc" | "desc">("desc");
  const [backendRows, setBackendRows] = useState<RegistryRow[]>([]);
  const [backendError, setBackendError] = useState<string | null>(null);

  const effectiveRows = rows.length > 0 ? rows : backendRows;

  useEffect(() => {
    if (rows.length > 0) return;

    invoke<RegistryRow[]>("get_registry_rows", { limit: 5000 })
      .then((result) => {
        setBackendRows(result);
        setBackendError(null);
      })
      .catch((error) => {
        setBackendRows([]);
        setBackendError(String(error));
      });
  }, [rows]);

  const sortedRows = useMemo(() => {
    const copy = [...effectiveRows];
    copy.sort((a, b) => {
      const left = sortBy === "lastWrite" ? a.lastWrite || 0 : String(a[sortBy] || "").toLowerCase();
      const right = sortBy === "lastWrite" ? b.lastWrite || 0 : String(b[sortBy] || "").toLowerCase();
      if (left < right) return direction === "asc" ? -1 : 1;
      if (left > right) return direction === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }, [effectiveRows, sortBy, direction]);

  const toggleSort = (column: SortColumn) => {
    if (sortBy === column) {
      setDirection((prev) => (prev === "asc" ? "desc" : "asc"));
      return;
    }
    setSortBy(column);
    setDirection(column === "lastWrite" ? "desc" : "asc");
  };

  return (
    <div className="fs-secondary-view">
      <div className="fs-secondary-header">Registry View</div>
      <div className="fs-secondary-body">
        {backendError && <div className="fs-empty">Registry load error: {backendError}</div>}
        <table className="fs-secondary-table">
          <thead>
            <tr>
              <th onClick={() => toggleSort("key")}>Key</th>
              <th onClick={() => toggleSort("value")}>Value</th>
              <th onClick={() => toggleSort("data")}>Data</th>
              <th onClick={() => toggleSort("lastWrite")}>LastWrite time</th>
              <th onClick={() => toggleSort("source")}>Source</th>
            </tr>
          </thead>
          <tbody>
            {sortedRows.map((row, index) => (
              <tr key={row.id} className={cn(index % 2 === 0 ? "even" : "odd")}>
                <td title={row.key}>
                  <div className="fs-cell-with-icon">
                    <ProviderIcon
                      text={`${row.key} ${row.value} ${row.data} ${row.source}`}
                      fallback={<File className="w-3.5 h-3.5 fs-muted-icon" />}
                    />
                    <span>{row.key || "—"}</span>
                  </div>
                </td>
                <td>{row.value || "—"}</td>
                <td title={row.data}>{row.data || "—"}</td>
                <td>{formatTimestamp(row.lastWrite)}</td>
                <td>{row.source || "—"}</td>
              </tr>
            ))}
            {sortedRows.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">No registry artifacts available</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
