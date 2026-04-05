import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { File } from "lucide-react";
import ProviderIcon from "@/components/ProviderIcon";
import { cn } from "@/lib/utils";

export interface EmailRow {
  id: string;
  from: string;
  to: string;
  subject: string;
  date?: number;
  attachments: number;
  source: string;
}

interface EmailViewProps {
  rows: EmailRow[];
}

type SortColumn = "from" | "to" | "subject" | "date" | "attachments" | "source";

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

export default function EmailView({ rows }: EmailViewProps) {
  const [sortBy, setSortBy] = useState<SortColumn>("date");
  const [direction, setDirection] = useState<"asc" | "desc">("desc");
  const [backendRows, setBackendRows] = useState<EmailRow[]>([]);
  const [backendError, setBackendError] = useState<string | null>(null);

  const effectiveRows = rows.length > 0 ? rows : backendRows;

  useEffect(() => {
    if (rows.length > 0) return;

    invoke<EmailRow[]>("get_email_rows", { limit: 5000 })
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
      const left = sortBy === "date" ? a.date || 0 : String(a[sortBy] || "").toLowerCase();
      const right = sortBy === "date" ? b.date || 0 : String(b[sortBy] || "").toLowerCase();
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
    setDirection(column === "date" ? "desc" : "asc");
  };

  return (
    <div className="fs-secondary-view">
      <div className="fs-secondary-header">Email View</div>
      <div className="fs-secondary-body">
        {backendError && <div className="fs-empty">Email load error: {backendError}</div>}
        <table className="fs-secondary-table">
          <thead>
            <tr>
              <th onClick={() => toggleSort("from")}>From</th>
              <th onClick={() => toggleSort("to")}>To</th>
              <th onClick={() => toggleSort("subject")}>Subject</th>
              <th onClick={() => toggleSort("date")}>Date</th>
              <th onClick={() => toggleSort("attachments")}>Attachment count</th>
              <th onClick={() => toggleSort("source")}>Source</th>
            </tr>
          </thead>
          <tbody>
            {sortedRows.map((row, index) => (
              <tr key={row.id} className={cn(index % 2 === 0 ? "even" : "odd")}>
                <td>{row.from || "—"}</td>
                <td>{row.to || "—"}</td>
                <td title={row.subject}>
                  <div className="fs-cell-with-icon">
                    <ProviderIcon
                      text={`${row.subject} ${row.source} ${row.from} ${row.to}`}
                      fallback={<File className="w-3.5 h-3.5 fs-muted-icon" />}
                    />
                    <span>{row.subject || "—"}</span>
                  </div>
                </td>
                <td>{formatTimestamp(row.date)}</td>
                <td>{row.attachments}</td>
                <td>{row.source || "—"}</td>
              </tr>
            ))}
            {sortedRows.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">No email artifacts available</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
