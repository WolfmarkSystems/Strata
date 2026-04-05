import type { ReactNode } from "react";
import StatusBadge from "./StatusBadge";

interface ContextStripProps {
  caseId?: string | null;
  caseDbPath?: string | null;
  evidencePath?: string | null;
  workflow?: Array<{ label: string; complete: boolean }>;
  actions?: ReactNode;
}

function stripPath(value: string | null | undefined) {
  if (!value) return "Not set";
  return value;
}

export default function ContextStrip({
  caseId,
  caseDbPath,
  evidencePath,
  workflow = [],
  actions,
}: ContextStripProps) {
  return (
    <div className="fs-context-strip">
      <div className="fs-context-row">
        <div className="fs-context-items">
          <span className="fs-chip" title={caseId || ""}>
            <strong>Case</strong> {caseId || "Not selected"}
          </span>
          <span className="fs-chip" title={caseDbPath || ""}>
            <strong>DB</strong> {stripPath(caseDbPath)}
          </span>
          <span className="fs-chip" title={evidencePath || ""}>
            <strong>Evidence</strong> {stripPath(evidencePath)}
          </span>
          {workflow.map((step) => (
            <span className="fs-chip" key={step.label}>
              <strong>{step.label}</strong> <StatusBadge status={step.complete ? "ok" : "warn"} label={step.complete ? "Done" : "Pending"} />
            </span>
          ))}
        </div>
        {actions && <div className="fs-inline">{actions}</div>}
      </div>
    </div>
  );
}
