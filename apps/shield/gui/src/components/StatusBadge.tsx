export type StatusKind = "ok" | "warn" | "error" | "info" | "unknown";

interface StatusBadgeProps {
  status: string | null | undefined;
  label?: string;
}

function normalizeStatus(status: string | null | undefined): StatusKind {
  const value = String(status || "").toLowerCase();
  if (["ok", "success", "pass", "passed"].includes(value)) return "ok";
  if (["warn", "warning", "partial"].includes(value)) return "warn";
  if (["error", "fail", "failed"].includes(value)) return "error";
  if (["info", "running", "queued"].includes(value)) return "info";
  return "unknown";
}

export default function StatusBadge({ status, label }: StatusBadgeProps) {
  const normalized = normalizeStatus(status);
  const text = label || (status ? String(status) : "unknown");
  const kindClass = normalized === "unknown" ? "fs-status-info" : `fs-status-${normalized}`;
  return <span className={`fs-status-badge ${kindClass}`}>{text}</span>;
}
