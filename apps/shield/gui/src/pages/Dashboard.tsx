import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CheckCircle,
  FileSearch,
  Flag,
  GripVertical,
  HardDrive,
  Hash,
  Loader2,
  ShieldCheck,
  Clock,
} from "lucide-react";

interface DashboardTask {
  id: string;
  name: string;
  status: "running" | "queued" | "completed";
  progress: number;
  detail: string;
}

interface DashboardActivityItem {
  id: string;
  kind: "success" | "warning" | "running" | "info";
  text: string;
  timeAgo: string;
}

interface DashboardFileTypeRow {
  label: string;
  value: number;
  colorClass: string;
}

interface DashboardArtifactRow {
  label: string;
  value: number;
}

interface DashboardTimelinePoint {
  label: string;
  value: number;
}

interface DashboardProps {
  caseName?: string | null;
  caseId?: string | null;
  examiner?: string | null;
  openedDate?: string | null;
  verified: boolean;
  hasActiveCase: boolean;
  hasEvidenceLoaded: boolean;
  evidenceSources: number;
  indexedItems: number;
  hashMatches: number;
  flaggedItems: number;
  timelineEvents: number;
  artifactCount: number;
  progressPercent: number;
  tasks: DashboardTask[];
  recentActivity: DashboardActivityItem[];
  fileTypeRows: DashboardFileTypeRow[];
  artifactRows: DashboardArtifactRow[];
  timelineBars: DashboardTimelinePoint[];
}

interface KbHealthSummary {
  status?: string;
  message?: string;
  provider?: string;
}

interface KbSearchResult {
  content: string;
  score?: number;
}
function formatCompact(value: number) {
  if (value >= 1000) {
    return `${(value / 1000).toFixed(value >= 10000 ? 0 : 1)}k`;
  }
  return value.toLocaleString();
}

function ProgressRing({ percent }: { percent: number }) {
  const size = 88;
  const stroke = 7;
  const radius = (size - stroke) / 2;
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (Math.max(0, Math.min(100, percent)) / 100) * circumference;

  return (
    <div className="fs-progress-ring" aria-label={`Progress ${percent}%`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          className="fs-progress-ring-track"
          strokeWidth={stroke}
          fill="transparent"
          r={radius}
          cx={size / 2}
          cy={size / 2}
        />
        <circle
          className="fs-progress-ring-indicator"
          strokeWidth={stroke}
          fill="transparent"
          r={radius}
          cx={size / 2}
          cy={size / 2}
          strokeDasharray={`${circumference} ${circumference}`}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="fs-progress-ring-label">{percent}%</div>
    </div>
  );
}

function WidgetHeader({ title }: { title: string }) {
  return (
    <div className="widget-header fs-widget-header-row">
      <span>{title}</span>
      <GripVertical className="w-3.5 h-3.5" />
    </div>
  );
}

export default function Dashboard({
  caseName,
  caseId,
  examiner,
  openedDate,
  verified,
  hasActiveCase,
  hasEvidenceLoaded,
  evidenceSources,
  indexedItems,
  hashMatches,
  flaggedItems,
  timelineEvents,
  artifactCount,
  progressPercent,
  tasks,
  recentActivity,
  fileTypeRows,
  artifactRows,
  timelineBars,
}: DashboardProps) {
  const [kbHealth, setKbHealth] = useState<KbHealthSummary | null>(null);
  const [capabilityCount, setCapabilityCount] = useState<number | null>(null);
  const [kbQuery, setKbQuery] = useState("");
  const [kbResults, setKbResults] = useState<KbSearchResult[]>([]);
  const [kbState, setKbState] = useState<"idle" | "loading" | "ready" | "empty" | "unavailable">("idle");

  useEffect(() => {
    let cancelled = false;

    invoke<KbHealthSummary>("kb_bridge_health")
      .then((result) => {
        if (!cancelled) setKbHealth(result);
      })
      .catch(() => {
        if (!cancelled) setKbHealth(null);
      });

    invoke<{ commands?: Record<string, boolean> }>("capabilities")
      .then((result) => {
        if (!cancelled) {
          const count = result?.commands ? Object.values(result.commands).filter(Boolean).length : 0;
          setCapabilityCount(count);
        }
      })
      .catch(() => {
        if (!cancelled) setCapabilityCount(null);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const handleKbSearch = async () => {
    const query = kbQuery.trim();
    if (!query) {
      setKbResults([]);
      setKbState("idle");
      return;
    }

    try {
      setKbState("loading");
      const response = await invoke<{ results?: KbSearchResult[] }>("search_kb_bridge", { query });
      const results = (response.results ?? []).slice(0, 3);
      setKbResults(results);
      setKbState(results.length > 0 ? "ready" : "empty");
    } catch {
      setKbResults([]);
      setKbState("unavailable");
    }
  };
  const largestArtifact = Math.max(...artifactRows.map((row) => row.value), 1);
  const largestTimeline = Math.max(...timelineBars.map((row) => row.value), 1);
  const donutTotal = Math.max(fileTypeRows.reduce((acc, row) => acc + row.value, 0), 1);
  const donutStops = fileTypeRows
    .reduce<Array<{ color: string; start: number; end: number }>>((acc, row) => {
      const start = acc.length === 0 ? 0 : acc[acc.length - 1].end;
      const end = start + (row.value / donutTotal) * 100;
      acc.push({ color: row.colorClass, start, end });
      return acc;
    }, [])
    .map((stop) => `${stop.color} ${stop.start}% ${stop.end}%`)
    .join(", ");
  const bannerTitle = hasActiveCase ? caseName || "Untitled Case" : "No case loaded";
  const bannerMeta = hasActiveCase
    ? [caseId ? `ID: ${caseId}` : null, examiner ? `Examiner: ${examiner}` : null, openedDate || null].filter(Boolean)
    : ["Use File > Add Evidence to begin a new examination."];
  const bannerBadge = hasActiveCase ? "Active" : "Ready";
  const statusTitle = hasEvidenceLoaded ? (verified ? "Evidence Verified" : "Verification Pending") : "No evidence loaded";
  const statusDetail = hasEvidenceLoaded
    ? verified
      ? "All sources verified"
      : "Awaiting evidence confirmation"
    : "Load evidence to start indexing and artifact builders.";
  const statusClass = hasEvidenceLoaded && verified ? "is-verified" : "is-neutral";

  return (
    <div className="dashboard">
      <div className="dashboard-inner">
        <section className="forensic-card fs-case-banner">
          <div className="fs-case-banner-top">
            <div className="fs-case-banner-primary">
              <span className={hasActiveCase ? "fs-status-badge active" : "fs-status-badge completed"}>
                {bannerBadge}
              </span>
              <h1>{bannerTitle}</h1>
              <div className="fs-case-meta">
                {bannerMeta.map((item) => (
                  <span key={item}>{item}</span>
                ))}
              </div>
            </div>
            <div className={`fs-case-verified ${statusClass}`}>
              {verified ? <CheckCircle className="w-4 h-4" /> : hasEvidenceLoaded ? <Activity className="w-4 h-4" /> : <HardDrive className="w-4 h-4" />}
              <div>
                <div>{statusTitle}</div>
                <div>{statusDetail}</div>
              </div>
            </div>
          </div>

          <div className="fs-case-stats-row">
            {[
              [evidenceSources, "Evidence Sources"],
              [indexedItems, "Indexed Items"],
              [hashMatches, "Hash Matches"],
              [flaggedItems, "Flagged Items"],
            ].map(([value, label]) => (
              <div key={String(label)} className="fs-case-stat-cell">
                <div className="fs-case-stat-value">{hasEvidenceLoaded ? Number(value).toLocaleString() : "—"}</div>
                <div className="fs-case-stat-label">{label}</div>
              </div>
            ))}
          </div>
          <div className="fs-inline fs-muted" style={{ marginTop: 10, gap: 12, flexWrap: "wrap" }}>
            <span>
              KB Bridge: {kbHealth?.status || kbHealth?.message || "Unavailable"}
            </span>
            <span>
              Backend capabilities: {capabilityCount ?? 0}
            </span>
          </div>
          <div style={{ marginTop: 14, display: "grid", gap: 8, maxWidth: 560 }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase" }}>
                Methodology Search
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                className="fs-filter-input"
                value={kbQuery}
                onChange={(event) => setKbQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    void handleKbSearch();
                  }
                }}
                placeholder="Search methodology knowledge base..."
              />
              <button className="fs-accent-btn" onClick={() => void handleKbSearch()} disabled={kbState === "loading"}>
                {kbState === "loading" ? "Searching..." : "Search"}
              </button>
            </div>
            {kbState === "empty" && <div className="fs-muted" style={{ fontSize: 13 }}>No results — KB may be starting up</div>}
            {kbState === "unavailable" && <div className="fs-muted" style={{ fontSize: 13 }}>KB unavailable</div>}
            {kbState === "ready" && (
              <div style={{ display: "grid", gap: 6 }}>
                {kbResults.map((result, index) => (
                  <div key={`${index}-${result.score ?? 0}`} className="fs-empty-state" style={{ textAlign: "left" }}>
                    {result.content.length > 180 ? `${result.content.slice(0, 180)}...` : result.content}
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        <section className="fs-quick-stats-grid">
          {[
            { icon: HardDrive, value: evidenceSources, label: "Evidence Sources", tone: "operational" },
            { icon: FileSearch, value: indexedItems, label: "Indexed Items", tone: "operational" },
            { icon: Hash, value: hashMatches, label: "Hash Matches", tone: "warning" },
            { icon: Flag, value: flaggedItems, label: "Flagged Items", tone: "warning" },
            { icon: Clock, value: timelineEvents, label: "Timeline Events", tone: "neutral" },
            { icon: Activity, value: artifactCount, label: "Artifacts", tone: "operational" },
          ].map((item) => (
            <div key={item.label} className="forensic-card fs-quick-stat-card">
              <div className={`fs-quick-stat-icon ${item.tone}`}>
                <item.icon className="w-5 h-5" />
              </div>
              <div className="fs-quick-stat-value">{Number(item.value).toLocaleString()}</div>
              <div className="fs-quick-stat-label">{item.label}</div>
            </div>
          ))}
        </section>

        <section className="fs-main-widget-grid">
          <div className="forensic-card">
            <WidgetHeader title="Processing Status" />
            <div className="fs-widget-body fs-processing-widget">
              <div className="fs-processing-hero">
                <ProgressRing percent={progressPercent} />
                <div className="fs-processing-copy">
                  <h3>{progressPercent >= 100 ? "Processing Complete" : "Processing Active"}</h3>
                  <p>{progressPercent >= 100 ? "All background tasks finished" : `${progressPercent}% complete across ${tasks.length} tasks`}</p>
                  <div className="fs-thin-progress">
                    <div style={{ width: `${progressPercent}%` }} />
                  </div>
                </div>
              </div>

              <div className="fs-task-list">
                {tasks.length > 0 ? tasks.map((task) => (
                  <div key={task.id} className="fs-task-row">
                    <div className="fs-task-main">
                      <span className="fs-task-icon">
                        {task.status === "running" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : task.status === "queued" ? <Clock className="w-3.5 h-3.5" /> : <CheckCircle className="w-3.5 h-3.5" />}
                      </span>
                      <div>
                <div className="fs-task-name">{task.name}</div>
                        <div className="fs-task-detail">{task.detail}</div>
                      </div>
                    </div>
                    <div className="fs-task-progress">{task.progress}%</div>
                  </div>
                )) : (
                  <div className="fs-empty-state">No active tasks</div>
                )}
              </div>
            </div>
          </div>

          <div className="forensic-card">
            <WidgetHeader title="File Type Distribution" />
          </div>

          <div className="forensic-card">
            <WidgetHeader title="File Type Distribution" />
            <div className="fs-widget-body fs-distribution-widget">
              <div className="fs-donut" style={{ background: `conic-gradient(${donutStops})` }}>
                <div className="fs-donut-inner">{formatCompact(indexedItems)}</div>
              </div>
              <div className="fs-distribution-legend">
                {fileTypeRows.map((row) => (
                  <div key={row.label} className="fs-legend-row">
                    <span className="fs-legend-swatch" style={{ background: row.colorClass }} />
                    <span className="fs-legend-name">{row.label}</span>
                    <span className="fs-legend-value">{formatCompact(row.value)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="forensic-card">
            <WidgetHeader title="Artifact Breakdown" />
            <div className="fs-widget-body fs-artifact-breakdown">
              {artifactRows.map((row) => (
                <div key={row.label} className="fs-horizontal-bar-row">
                  <div className="fs-horizontal-bar-label">{row.label}</div>
                  <div className="fs-horizontal-bar-track">
                    <div className="fs-horizontal-bar-fill" style={{ width: `${(row.value / largestArtifact) * 100}%` }} />
                  </div>
                  <div className="fs-horizontal-bar-value">{formatCompact(row.value)}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="fs-lower-widget-grid">
          <div className="forensic-card">
            <WidgetHeader title="Timeline Activity" />
            <div className="fs-widget-body fs-timeline-widget">
              <div className="fs-timeline-bars">
                {timelineBars.map((row) => (
                  <div key={row.label} className="fs-timeline-bar-group">
                    <div className="fs-timeline-bar-track">
                      <div className="fs-timeline-bar-fill" style={{ height: `${(row.value / largestTimeline) * 100}%` }} />
                    </div>
                    <div className="fs-timeline-bar-label">{row.label}</div>
                  </div>
                ))}
              </div>
              <div className="fs-widget-footer-row">
                <span>Last 7 days</span>
                <span>{timelineEvents.toLocaleString()} total events</span>
              </div>
            </div>
          </div>

          <div className="forensic-card">
            <WidgetHeader title="Recent Examiner Activity" />
            <div className="fs-widget-body fs-activity-list">
              {recentActivity.map((item) => (
                <div key={item.id} className="fs-activity-row">
                  <div className={`fs-activity-icon ${item.kind}`}>
                    {item.kind === "success" ? <CheckCircle2 className="w-3.5 h-3.5" /> : item.kind === "warning" ? <AlertTriangle className="w-3.5 h-3.5" /> : item.kind === "running" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                  </div>
                  <div className="fs-activity-text">{item.text}</div>
                  <div className="fs-activity-time">{item.timeAgo}</div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
