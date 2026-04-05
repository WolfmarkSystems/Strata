import { useEffect, useMemo, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import toast from "react-hot-toast";
import {
  CheckCircle,
  File as FileIcon,
  FolderOpen,
  HardDrive,
  Layers,
  Plus,
  RefreshCw,
  StickyNote,
  Trash2,
  UserCog,
  UserRound,
  X,
  XCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import Layout, { ShellSection } from "@/components/Layout";
import ProviderIcon from "@/components/ProviderIcon";
import { UnifiedArtifactRow } from "@/components/ArtifactTable";
import UnifiedTable, { UnifiedTableAction, UnifiedTableRow } from "@/components/UnifiedTable";
import VirtualTree, { EvidenceNode, countNodes } from "@/components/VirtualTree";
import EmailView, { EmailRow } from "@/pages/EmailView";
import RegistryView, { RegistryRow } from "@/pages/RegistryView";
import Dashboard from "@/pages/Dashboard";
import MainView, { MainTab } from "@/pages/MainView";
import "./App.css";

function mapToArtifactRow(row: UnifiedTableRow): UnifiedArtifactRow {
  return {
    id: row.id,
    sourceType: row.nodeRef ? "artifact" : "file", // Heuristic
    name: row.name,
    path: row.fullPath,
    type: row.isDir ? "directory" : (row.fullPath.split(".").pop() || "file"),
    size: row.size,
    createdTime: row.birth,
    modifiedTime: row.modified,
    accessedTime: row.accessed,
    mftChangedTime: row.mftChanged,
    md5: row.md5,
    sha1: row.sha1,
    sha256: row.sha256,
    category: row.category,
    deleted: row.deleted,
    mftRecord: row.mftRecord,
    sequence: row.sequence,
    isDir: row.isDir,
    nodeRef: row.nodeRef,
  };
}

interface JobProgress {
  job_id: string;
  job_type: string;
  status: string;
  progress: number;
  message: string;
}

interface TimelineEntry {
  id: number;
  timestamp?: number | null;
  artifactType: string;
  description: string;
  sourcePath: string;
  createdUtc: string;
}

interface ArtifactTag {
  tagId: number;
  name: string;
  color: string;
  isSystem: boolean;
}

interface ArtifactNote {
  noteId: number;
  artifactPath: string;
  content: string;
  author: string;
  createdUtc: string;
  modifiedUtc: string;
}

interface ArtifactPreview {
  artifactPath: string;
  bytesRead: number;
  totalBytes: number;
  truncated: boolean;
  hexDump: string;
  strings: string[];
}

interface ArtifactItem {
  artifactType: string;
  name: string;
  path: string;
  description: string;
  timestamp?: number;
  createdTime?: number;
  modifiedTime?: number;
  accessedTime?: number;
  mftChangedTime?: number;
  size?: number;
}

interface BuiltTimelineRow {
  id: string;
  timestamp?: number | null;
  eventType: string;
  source: string;
  description: string;
}

interface BuiltMediaRow {
  id: string;
  name: string;
  path: string;
  mediaType: string;
  size: number;
  modifiedTime?: number | null;
}

interface UiSettingsState {
  defaultSmokeMftCount: number;
  defaultExaminePreset: string;
  defaultFileTableLimit: number;
  historyRetentionMode: "keep-all" | "max-files";
  maxHistoryFiles: number;
  rememberLastCase: boolean;
  rememberLastEvidencePath: boolean;
}

const DEFAULT_UI_SETTINGS: UiSettingsState = {
  defaultSmokeMftCount: 100,
  defaultExaminePreset: "triage_default",
  defaultFileTableLimit: 500,
  historyRetentionMode: "keep-all",
  maxHistoryFiles: 500,
  rememberLastCase: true,
  rememberLastEvidencePath: true,
};

const SECTIONS_WITH_TREE = new Set<ShellSection>([
  "file-system",
  "registry",
  "communications",
  "browser-data",
  "carved-files",
  "hash-sets",
]);

const normalizePath = (value: string) => value.replace(/\\/g, "/").toLowerCase();

const formatSize = (bytes?: number) => {
  if (bytes === undefined || bytes === null || !Number.isFinite(bytes)) return "Ã¢â‚¬â€";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(1)} ${units[idx]}`;
};

const formatTimestamp = (value?: number | null) => {
  if (value === null || value === undefined || !Number.isFinite(value)) return "Ã¢â‚¬â€";
  if (value > 10_000_000_000_000) {
    const unixMs = Math.floor(value / 10_000 - 11_644_473_600_000);
    const date = new Date(unixMs);
    return Number.isNaN(date.getTime()) ? "Ã¢â‚¬â€" : date.toLocaleString();
  }
  if (value > 1_000_000_000_000) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Ã¢â‚¬â€" : date.toLocaleString();
  }
  if (value > 0) {
    const date = new Date(value * 1000);
    return Number.isNaN(date.getTime()) ? "Ã¢â‚¬â€" : date.toLocaleString();
  }
  return "Ã¢â‚¬â€";
};

const formatTimelineTimestamp = (value?: number | null) => {
  if (value === null || value === undefined || !Number.isFinite(value)) return "Ã¢â‚¬â€";
  if (value <= 0) return "Ã¢â‚¬â€";
  const millis = value > 1_000_000_000_000 ? value : value * 1000;
  const date = new Date(millis);
  return Number.isNaN(date.getTime()) ? "Ã¢â‚¬â€" : date.toLocaleString();
};

const isValidTimelineEntry = (entry: TimelineEntry) => {
  const hasDescription = Boolean(entry.description && entry.description.trim().length > 0);
  const ts = entry.timestamp;
  const hasValidTimestamp = ts !== null && ts !== undefined && Number.isFinite(ts) && ts > 0;
  return hasDescription && hasValidTimestamp;
};

const pickHash = (meta: Record<string, string> | undefined, key: string) => {
  if (!meta) return undefined;
  const lowered = Object.entries(meta).reduce<Record<string, string>>((acc, [k, v]) => {
    acc[k.toLowerCase()] = v;
    return acc;
  }, {});
  return lowered[key.toLowerCase()];
};

function App() {
  const [screen, setScreen] = useState<"splash" | "main">("splash");
  const [activeSection, setActiveSection] = useState<ShellSection>("dashboard");
  const [artifactSubtab, setArtifactSubtab] = useState<"artifacts" | "hex" | "strings">("artifacts");

  const [evidenceTree, setEvidenceTree] = useState<EvidenceNode | null>(null);
  const [selectedNode, setSelectedNode] = useState<EvidenceNode | null>(null);
  const [selectedTableIds, setSelectedTableIds] = useState<Set<string>>(new Set());

  const [jobs, setJobs] = useState<JobProgress[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [artifactMatches, setArtifactMatches] = useState<ArtifactItem[]>([]);
  const [builtTimelineRows, setBuiltTimelineRows] = useState<BuiltTimelineRow[]>([]);
  const [builtEmailRows, setBuiltEmailRows] = useState<EmailRow[]>([]);
  const [builtRegistryRows, setBuiltRegistryRows] = useState<RegistryRow[]>([]);
  const [builtMediaRows, setBuiltMediaRows] = useState<BuiltMediaRow[]>([]);
  const [caseInfo, setCaseInfo] = useState<{ id: string; name: string; created: string } | null>(null);

  const [allTags, setAllTags] = useState<ArtifactTag[]>([]);
  const [selectedNodeTags, setSelectedNodeTags] = useState<ArtifactTag[]>([]);
  const [notes, setNotes] = useState<ArtifactNote[]>([]);
  const [newNoteContent, setNewNoteContent] = useState("");

  const [loadedEvidencePath, setLoadedEvidencePath] = useState<string | null>(null);
  const [artifactPreview, setArtifactPreview] = useState<ArtifactPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const [isLoading, setIsLoading] = useState(false);
  const [loadingStatus, setLoadingStatus] = useState("");
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");
  const [uiSettings, setUiSettings] = useState<UiSettingsState>(DEFAULT_UI_SETTINGS);
  const [theme, setTheme] = useState<"light" | "dark">(
    () => (window.localStorage.getItem("fs-ui-theme") as "light" | "dark" | null) || "light"
  );
  const [currentExaminer, setCurrentExaminer] = useState(() => window.localStorage.getItem("fs-current-examiner") || "Examiner");
  const [examinerNameDraft, setExaminerNameDraft] = useState(() => window.localStorage.getItem("fs-current-examiner") || "Examiner");
  const [profileDialogOpen, setProfileDialogOpen] = useState(false);
  const [preferencesDialogOpen, setPreferencesDialogOpen] = useState(false);
  const [isExportingTimeline, setIsExportingTimeline] = useState(false);

  useEffect(() => {
    console.info("[Vantor Shield] App Component Initialized");
    console.info("[Vantor Shield] Screen:", screen);
    console.info("[Vantor Shield] Section:", activeSection);
  }, [screen, activeSection]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    window.localStorage.setItem("fs-ui-theme", theme);
  }, [theme]);

  useEffect(() => {
    setScreen("main");
    setActiveSection("artifacts");
  }, []);

  useEffect(() => {
    const unlistenProgress = listen<JobProgress>("job-progress", (event) => {
      const payload = event.payload;
      setJobs((prev) => {
        const idx = prev.findIndex((j) => j.job_id === payload.job_id);
        if (idx === -1) return [...prev, payload];
        const next = [...prev];
        next[idx] = payload;
        return next;
      });
      if (payload.job_type === "image_loading" && payload.message) setLoadingStatus(payload.message);
    });

    const unlistenTimeline = listen<TimelineEntry>("timeline-entry-added", (event) => {
      const entry = event.payload;
      if (!isValidTimelineEntry(entry)) return;
      setTimeline((prev) => [entry, ...prev].slice(0, 1000));
    });

    return () => {
      unlistenProgress.then((fn) => fn());
      unlistenTimeline.then((fn) => fn());
    };
  }, []);

  useEffect(() => {
    invoke<ArtifactTag[]>("get_all_tags").then(setAllTags).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!loadedEvidencePath) {
      setTimeline([]);
      setBuiltTimelineRows([]);
      setBuiltEmailRows([]);
      setBuiltRegistryRows([]);
      setBuiltMediaRows([]);
      return;
    }

    let cancelled = false;
    const refreshSpecializedViews = () => {
      invoke<TimelineEntry[]>("get_initial_timeline", { limit: 1000 })
        .then((entries) => {
          if (!cancelled) setTimeline(entries.filter(isValidTimelineEntry));
        })
        .catch(() => {
          if (!cancelled) setTimeline([]);
        });

      invoke<BuiltTimelineRow[]>("get_built_timeline_rows", { limit: 5000 })
        .then((rows) => {
          if (!cancelled) setBuiltTimelineRows(rows.filter((row) => (row.timestamp ?? 0) > 0));
        })
        .catch(() => {
          if (!cancelled) setBuiltTimelineRows([]);
        });

      invoke<EmailRow[]>("get_built_email_rows", { limit: 5000 })
        .then((rows) => {
          if (!cancelled) setBuiltEmailRows(rows);
        })
        .catch(() => {
          if (!cancelled) setBuiltEmailRows([]);
        });

      invoke<RegistryRow[]>("get_built_registry_rows", { limit: 5000 })
        .then((rows) => {
          if (!cancelled) setBuiltRegistryRows(rows);
        })
        .catch(() => {
          if (!cancelled) setBuiltRegistryRows([]);
        });

      invoke<BuiltMediaRow[]>("get_built_media_rows", { limit: 10000 })
        .then((rows) => {
          if (!cancelled) setBuiltMediaRows(rows);
        })
        .catch(() => {
          if (!cancelled) setBuiltMediaRows([]);
        });
    };

    refreshSpecializedViews();
    const timer = window.setInterval(refreshSpecializedViews, 30000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [loadedEvidencePath]);

  useEffect(() => {
    if (!selectedNode || selectedNode.isDir) {
      setArtifactMatches([]);
      return;
    }
    invoke<ArtifactItem[]>("get_artifacts_for_path", { path: selectedNode.path })
      .then((rows) => setArtifactMatches(rows.slice(0, 1000)))
      .catch(() => setArtifactMatches([]));
  }, [selectedNode]);

  useEffect(() => {
    if (!selectedNode) {
      setSelectedNodeTags([]);
      setNotes([]);
      return;
    }
    invoke<ArtifactTag[]>("get_tags_for_artifact", { artifactPath: selectedNode.path }).then(setSelectedNodeTags).catch(() => setSelectedNodeTags([]));
    invoke<ArtifactNote[]>("get_notes_for_artifact", { artifactPath: selectedNode.path }).then(setNotes).catch(() => setNotes([]));
  }, [selectedNode]);

  useEffect(() => {
    const needsPreview = activeSection === "artifacts" && artifactSubtab !== "artifacts" && selectedNode && !selectedNode.isDir && loadedEvidencePath;
    if (!needsPreview || !selectedNode || !loadedEvidencePath) {
      setArtifactPreview(null);
      setPreviewError(null);
      setPreviewLoading(false);
      return;
    }

    let cancelled = false;
    setPreviewLoading(true);
    setPreviewError(null);
    invoke<ArtifactPreview>("read_artifact_preview", {
      evidencePath: loadedEvidencePath,
      artifactPath: selectedNode.path,
      maxBytes: 131072,
    })
      .then((preview) => {
        if (!cancelled) setArtifactPreview(preview);
      })
      .catch((error) => {
        if (!cancelled) setPreviewError(String(error));
      })
      .finally(() => {
        if (!cancelled) setPreviewLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [activeSection, artifactSubtab, selectedNode, loadedEvidencePath]);

  const getNodeId = (node: EvidenceNode) => `${node.path}::${node.name}`;

  const collectInitialExpandedNodes = (tree: EvidenceNode): Set<string> => {
    const expanded = new Set<string>();
    const rootId = getNodeId(tree);
    expanded.add(rootId);
    if (tree.children && tree.children.length > 0) {
      const firstChild = tree.children[0];
      expanded.add(getNodeId(firstChild));
    }
    return expanded;
  };

  const handleOpenEvidence = async () => {
    try {
      let selected = await open({
        multiple: false,
        filters: [
          { name: "All Evidence Files", extensions: ["e01", "E01", "dd", "raw", "img", "vhd", "vmdk", "vhdx", "aff", "s01", "001"] },
          { name: "All Files", extensions: ["*"] },
        ],
        title: "Open evidence",
      });
      if (!selected) selected = await open({ directory: true, title: "Select Evidence Directory" });
      const selectedPath = Array.isArray(selected) ? selected[0] : selected;
      if (!selectedPath) return;

      setIsLoading(true);
      setLoadingStatus("Loading evidence...");
      setLoadedEvidencePath(selectedPath);
      setTimeline([]);
      setBuiltTimelineRows([]);
      setBuiltEmailRows([]);
      setBuiltRegistryRows([]);
      setBuiltMediaRows([]);
      setSelectedNode(null);
      setExpandedNodes(new Set());

      const result = await invoke<any>("load_evidence_and_build_tree", {
        path: selectedPath,
        runArtifactParsers: true,
      });

      const tree = result.tree as EvidenceNode;
      setEvidenceTree(tree);
      void invoke("start_specialized_view_builders", { evidencePath: selectedPath }).catch(() => undefined);
      setExpandedNodes(collectInitialExpandedNodes(tree));
      setCaseInfo({ id: crypto.randomUUID(), name: tree.name, created: new Date().toISOString() });
      setActiveSection("dashboard");
      toast.success(`Loaded ${tree.name}`);
    } catch (error) {
      toast.error(`Failed to load evidence: ${error}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleExportTimeline = async () => {
    try {
      setIsExportingTimeline(true);
      const destination = await open({ directory: true, title: "Select export destination" });
      if (!destination) return;
      const destinationDir = Array.isArray(destination) ? destination[0] : destination;
      const outputPath = `${destinationDir}/timeline_export.jsonl`;
      await invoke<string>("export_jsonl_timeline", { outputPath });
      toast.success("Timeline exported");
    } catch (error) {
      toast.error(`Timeline export failed: ${error}`);
    } finally {
      setIsExportingTimeline(false);
    }
  };
  const exportPaths = async (paths: string[]) => {
    const unique = Array.from(new Set(paths.filter(Boolean)));
    if (unique.length === 0) return;
    const destination = await open({ directory: true, title: "Select Export Destination" });
    if (!destination) return;
    const destinationDir = Array.isArray(destination) ? destination[0] : destination;
    let success = 0;
    for (const sourcePath of unique) {
      try {
        await invoke<string>("export_artifact", { sourcePath, destinationDir, includeMetadata: true, verifyHash: true });
        success += 1;
      } catch {
        // continue
      }
    }
    toast.success(`Exported ${success}/${unique.length}`);
  };

  const handleAddTag = async (tagId: number) => {
    if (!selectedNode) return;
    await invoke("add_tag", { artifactPath: selectedNode.path, tagId });
    const tags = await invoke<ArtifactTag[]>("get_tags_for_artifact", { artifactPath: selectedNode.path });
    setSelectedNodeTags(tags);
  };

  const handleRemoveTag = async (tagId: number) => {
    if (!selectedNode) return;
    await invoke("remove_tag", { artifactPath: selectedNode.path, tagId });
    const tags = await invoke<ArtifactTag[]>("get_tags_for_artifact", { artifactPath: selectedNode.path });
    setSelectedNodeTags(tags);
  };

  const handleAddNote = async () => {
    if (!selectedNode || !newNoteContent.trim()) return;
    await invoke("add_note", { artifactPath: selectedNode.path, content: newNoteContent, author: currentExaminer });
    const nodeNotes = await invoke<ArtifactNote[]>("get_notes_for_artifact", { artifactPath: selectedNode.path });
    setNotes(nodeNotes);
    setNewNoteContent("");
  };

  const handleDeleteNote = async (noteId: number) => {
    await invoke("delete_note", { noteId });
    if (!selectedNode) return;
    const nodeNotes = await invoke<ArtifactNote[]>("get_notes_for_artifact", { artifactPath: selectedNode.path });
    setNotes(nodeNotes);
  };

  const tableRows = useMemo(() => {
    const rows: UnifiedTableRow[] = [];

    const walk = (node: EvidenceNode) => {
      rows.push({
        id: `node:${normalizePath(node.path)}:${node.name.toLowerCase()}`,
        name: node.name,
        fullPath: node.path,
        size: node.size,
        birth: node.createdTime,
        modified: node.modifiedTime,
        accessed: node.accessedTime,
        mftChanged: node.mftChangedTime,
        md5: pickHash(node.metadata, "md5"),
        sha1: pickHash(node.metadata, "sha1"),
        sha256: pickHash(node.metadata, "sha256") || node.hash,
        category: node.category || "Unknown",
        deleted: Boolean(node.isDeleted),
        mftRecord: node.mftRecordId,
        sequence: node.sequenceNumber,
        tags: [],
        isDir: node.isDir,
        nodeRef: node,
      });
      node.children?.forEach(walk);
    };

    if (evidenceTree) walk(evidenceTree);
    return rows;
  }, [evidenceTree]);

  const emailRows = useMemo<EmailRow[]>(() => {
    return artifactMatches
      .filter((item) => /mail|email|pst|ost|outlook|gmail/i.test(item.artifactType + " " + item.path + " " + item.name))
      .map((item, idx) => {
        const parts = item.description?.split("|") || [];
        return {
          id: `email:${idx}:${item.path}`,
          from: parts[0]?.trim() || "Ã¢â‚¬â€",
          to: parts[1]?.trim() || "Ã¢â‚¬â€",
          subject: item.name || "Ã¢â‚¬â€",
          date: item.timestamp,
          attachments: Number(parts[2]) || 0,
          source: item.path,
        };
      });
  }, [artifactMatches]);

  const registryRows = useMemo<RegistryRow[]>(() => {
    return artifactMatches
      .filter((item) => /registry|reg/i.test(item.artifactType + " " + item.path))
      .map((item, idx) => {
        const parts = item.description?.split("|") || [];
        return {
          id: `reg:${idx}:${item.path}`,
          key: item.path,
          value: parts[0]?.trim() || item.name,
          data: parts[1]?.trim() || item.description || "Ã¢â‚¬â€",
          lastWrite: item.timestamp,
          source: item.artifactType,
        };
      });
  }, [artifactMatches]);

  const effectiveEmailRows = builtEmailRows.length > 0 ? builtEmailRows : emailRows;
  const effectiveRegistryRows = builtRegistryRows.length > 0 ? builtRegistryRows : registryRows;
  const timelineRowsForDisplay = timeline.length > 0
    ? timeline.map((entry) => ({
        id: `timeline:${entry.id}`,
        timestamp: entry.timestamp ?? null,
        eventType: entry.artifactType || "Ã¢â‚¬â€",
        source: entry.sourcePath || "Ã¢â‚¬â€",
        description: entry.description || "Ã¢â‚¬â€",
      }))
    : builtTimelineRows;

  const setSelectedFromTableRow = (row: UnifiedTableRow | null) => {
    if (!row) {
      setSelectedNode(null);
      setSelectedTableIds(new Set());
      return;
    }

    if (row.nodeRef && typeof row.nodeRef === "object") {
      setSelectedNode(row.nodeRef as EvidenceNode);
      return;
    }

    setSelectedNode({
      name: row.name,
      path: row.fullPath,
      isDir: Boolean(row.isDir),
      size: row.size,
      createdTime: row.birth,
      modifiedTime: row.modified,
      accessedTime: row.accessed,
      mftChangedTime: row.mftChanged,
      hash: row.sha256,
      metadata: {
        md5: row.md5 || "",
        sha1: row.sha1 || "",
        sha256: row.sha256 || "",
      },
      mftRecordId: row.mftRecord,
      sequenceNumber: row.sequence,
      category: row.category,
      isDeleted: row.deleted,
    });
  };

  const onUnifiedAction = (action: UnifiedTableAction, row: UnifiedTableRow) => {
    setSelectedFromTableRow(row);
    if (action === "export") exportPaths([row.fullPath]);
    if (action === "add-note") toast("Use right sidebar to add a note.");
    if (action === "tag") toast("Use right sidebar tags for this row.");
    if (action === "view-hex") {
      setActiveSection("artifacts");
      setArtifactSubtab("hex");
    }
    if (action === "view-strings") {
      setActiveSection("artifacts");
      setArtifactSubtab("strings");
    }
  };

  const saveExaminerProfile = () => {
    const next = examinerNameDraft.trim() || "Examiner";
    setCurrentExaminer(next);
    window.localStorage.setItem("fs-current-examiner", next);
    setProfileDialogOpen(false);
    toast.success(`Signed in as ${next}`);
  };

  const handleSignOut = () => {
    setCurrentExaminer("Examiner");
    setExaminerNameDraft("Examiner");
    window.localStorage.removeItem("fs-current-examiner");
    setProfileDialogOpen(false);
    setPreferencesDialogOpen(false);
    toast.success("Examiner session cleared.");
  };

  const normalizedSearch = searchQuery.trim().toLowerCase();

  const matchesSearch = (...values: Array<string | number | boolean | null | undefined>) => {
    if (!normalizedSearch) return true;
    return values.some((value) => String(value ?? "").toLowerCase().includes(normalizedSearch));
  };

  const filteredTableRows = useMemo(
    () =>
      tableRows.filter((row) =>
        matchesSearch(
          row.name,
          row.fullPath,
          row.category,
          row.md5,
          row.sha1,
          row.sha256,
          row.deleted ? "deleted" : "active",
          row.tags?.join(",")
        )
      ),
    [tableRows, normalizedSearch]
  );

  const filteredArtifactMatches = useMemo(
    () =>
      artifactMatches.filter((item) =>
        matchesSearch(item.name, item.path, item.artifactType, item.description)
      ),
    [artifactMatches, normalizedSearch]
  );

  const filteredTimelineRows = useMemo(
    () =>
      timelineRowsForDisplay.filter((entry) =>
        matchesSearch(entry.eventType, entry.source, entry.description, formatTimelineTimestamp(entry.timestamp))
      ),
    [timelineRowsForDisplay, normalizedSearch]
  );

  const filteredEmailRows = useMemo(
    () =>
      effectiveEmailRows.filter((row) =>
        matchesSearch(row.from, row.to, row.subject, row.source, row.attachments)
      ),
    [effectiveEmailRows, normalizedSearch]
  );

  const filteredRegistryRows = useMemo(
    () =>
      effectiveRegistryRows.filter((row) =>
        matchesSearch(row.key, row.value, row.data, row.source)
      ),
    [effectiveRegistryRows, normalizedSearch]
  );

  const filteredMediaRows = useMemo(
    () =>
      builtMediaRows.filter((row) =>
        matchesSearch(row.name, row.path, row.mediaType, formatSize(row.size))
      ),
    [builtMediaRows, normalizedSearch]
  );

  const dashboardFileTypeRows = useMemo(() => {
    const buckets = {
      Documents: 0,
      Images: 0,
      Executables: 0,
      Archives: 0,
      Other: 0,
    };

    filteredTableRows.forEach((row) => {
      if (row.isDir) return;
      const ext = row.fullPath.split(".").pop()?.toLowerCase() || "";
      if (["doc", "docx", "pdf", "txt", "xls", "xlsx", "ppt", "pptx", "csv"].includes(ext)) buckets.Documents += 1;
      else if (["jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp"].includes(ext)) buckets.Images += 1;
      else if (["exe", "dll", "sys", "bat", "ps1", "msi"].includes(ext)) buckets.Executables += 1;
      else if (["zip", "7z", "rar", "cab", "tar", "gz"].includes(ext)) buckets.Archives += 1;
      else buckets.Other += 1;
    });

    return [
      { label: "Documents", value: buckets.Documents, colorClass: "hsl(152 55% 30%)" },
      { label: "Images", value: buckets.Images, colorClass: "hsl(220 15% 60%)" },
      { label: "Executables", value: buckets.Executables, colorClass: "hsl(38 90% 48%)" },
      { label: "Archives", value: buckets.Archives, colorClass: "hsl(220 15% 40%)" },
      { label: "Other", value: buckets.Other, colorClass: "hsl(220 15% 78%)" },
    ];
  }, [filteredTableRows]);

  const dashboardArtifactRows = useMemo(
    () => [
      { label: "Registry", value: filteredRegistryRows.length },
      { label: "Timeline", value: filteredTimelineRows.length },
      { label: "Email", value: filteredEmailRows.length },
      { label: "Media", value: filteredMediaRows.length },
      { label: "Matches", value: filteredArtifactMatches.length },
    ],
    [filteredArtifactMatches.length, filteredEmailRows.length, filteredMediaRows.length, filteredRegistryRows.length, filteredTimelineRows.length]
  );

  const dashboardTimelineBars = useMemo(() => {
    const buckets = new Array(7).fill(0).map((_, index) => ({ label: `D${index + 1}`, value: 0 }));
    filteredTimelineRows.forEach((row) => {
      const timestamp = row.timestamp ?? 0;
      if (!timestamp || timestamp <= 0) return;
      const millis = timestamp > 1_000_000_000_000 ? timestamp : timestamp * 1000;
      const dayIndex = new Date(millis).getDay();
      buckets[dayIndex % 7].value += 1;
    });
    return buckets;
  }, [filteredTimelineRows]);

  const dashboardTasks = useMemo(
    (): Array<{ id: string; name: string; status: "running" | "queued" | "completed"; progress: number; detail: string }> =>
      jobs.slice(0, 4).map((job) => ({
        id: job.job_id,
        name: job.job_type.replace(/_/g, " "),
        status:
          job.status === "completed" ? "completed" : job.status === "running" ? "running" : "queued",
        progress: Math.round(job.progress || 0),
        detail: job.message || "Working",
      })),
    [jobs]
  );

  const dashboardRecentActivity = useMemo(
    (): Array<{ id: string; kind: "success" | "warning" | "running" | "info"; text: string; timeAgo: string }> =>
      jobs.slice(0, 5).map((job, index) => ({
        id: `${job.job_id}:${index}`,
        kind:
          job.status === "completed"
            ? "success"
            : job.status === "failed"
              ? "warning"
              : job.status === "running"
                ? "running"
                : "info",
        text: `${job.job_type.replace(/_/g, " ")} Ã¢â‚¬â€ ${job.message || job.status}`,
        timeAgo: job.status === "completed" ? "just now" : "active",
      })),
    [jobs]
  );

  const knownBadRows = useMemo(
    () => filteredTableRows.filter((row) => /malware|csam|notable/i.test(row.category || "")),
    [filteredTableRows]
  );

  const deletedRows = useMemo(
    () => filteredTableRows.filter((row) => row.deleted),
    [filteredTableRows]
  );

  const rowsWithHashes = useMemo(
    () => filteredTableRows.filter((row) => row.md5 || row.sha256),
    [filteredTableRows]
  );

  const totalNodeCount = useMemo(() => {
    if (!evidenceTree) return 0;
    return countNodes(evidenceTree);
  }, [evidenceTree]);

  const handleToggleExpand = useCallback((nodeId: string) => {
    setExpandedNodes((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  }, []);

  const handleSelectNode = useCallback((node: EvidenceNode) => {
    setSelectedNode(node);
  }, []);


  const renderMediaPanel = () => (
    <div className="fs-secondary-view">
      <div className="fs-secondary-header">Media View</div>
      <div className="fs-secondary-body">
        <table className="fs-secondary-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Path</th>
              <th>Size</th>
              <th>Modified</th>
            </tr>
          </thead>
          <tbody>
            {filteredMediaRows.map((row, idx) => (
              <tr key={row.id} className={cn(idx % 2 === 0 ? "even" : "odd")}>
                <td>
                  <div className="fs-cell-with-icon">
                    <ProviderIcon
                      text={`${row.name} ${row.path} ${row.mediaType}`}
                      fallback={<FileIcon className="w-3.5 h-3.5 fs-muted-icon" />}
                    />
                    <span title={row.name || "Ã¢â‚¬â€"}>{row.name || "Ã¢â‚¬â€"}</span>
                  </div>
                </td>
                <td>{row.mediaType || "Ã¢â‚¬â€"}</td>
                <td title={row.path}>{row.path || "Ã¢â‚¬â€"}</td>
                <td>{formatSize(row.size)}</td>
                <td>{formatTimelineTimestamp(row.modifiedTime)}</td>
              </tr>
            ))}
            {filteredMediaRows.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">No media artifacts yet. Media builder is running in Active Jobs.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );

  const renderSummaryPanel = (title: string, body: React.ReactNode) => (
    <div className="fs-secondary-view">
      <div className="fs-secondary-header">{title}</div>
      <div className="fs-secondary-body" style={{ padding: "16px 20px" }}>
        {body}
      </div>
    </div>
  );

  const renderCardGrid = (children: React.ReactNode) => (
    <div className="fs-detail-grid">{children}</div>
  );

  const renderCaseOverviewPanel = () =>
    renderCardGrid(
      <>
        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Case Summary</div>
          <div className="fs-detail-card-body">
            <div className="fs-detail-row"><span>Name</span><strong>{caseInfo?.name || "No case loaded"}</strong></div>
            <div className="fs-detail-row"><span>Case ID</span><span className="fs-mono">{caseInfo?.id || "Ã¢â‚¬â€"}</span></div>
            <div className="fs-detail-row"><span>Created</span><span>{caseInfo?.created ? new Date(caseInfo.created).toLocaleString() : "Ã¢â‚¬â€"}</span></div>
            <div className="fs-detail-row"><span>Evidence</span><span>{loadedEvidencePath ? "Loaded" : "Not loaded"}</span></div>
          </div>
        </div>

        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Evidence Posture</div>
          <div className="fs-detail-card-body">
            <div className="fs-metric-strip">
              <div><strong>{filteredTableRows.length.toLocaleString()}</strong><span>Indexed</span></div>
              <div><strong>{filteredArtifactMatches.length.toLocaleString()}</strong><span>Artifacts</span></div>
              <div><strong>{filteredTimelineRows.length.toLocaleString()}</strong><span>Events</span></div>
            </div>
            <div className="fs-detail-list">
              <div>Current source: <span className="fs-selection-path">{loadedEvidencePath || "No evidence selected"}</span></div>
              <div>Visible search scope: {normalizedSearch ? `filtered by "${searchQuery}"` : "all records"}</div>
            </div>
          </div>
        </div>

        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Current Examination</div>
          <div className="fs-detail-card-body">
            <div className="fs-detail-list">
              <div>Selected path: <span className="fs-selection-path">{selectedNode?.path || "None selected"}</span></div>
              <div>Selected tags: {selectedNodeTags.length}</div>
              <div>Open notes: {notes.length}</div>
            </div>
          </div>
        </div>
      </>
    );

  const renderEvidenceSourcesPanel = () =>
    renderCardGrid(
      <>
        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Primary Evidence Source</div>
          <div className="fs-detail-card-body">
            <div className="fs-selection-path">{loadedEvidencePath || "No evidence selected"}</div>
            <div className="fs-detail-list">
              <div>Source count: {loadedEvidencePath ? 1 : 0}</div>
              <div>Tree items: {evidenceTree ? countNodes(evidenceTree).toLocaleString() : 0}</div>
              <div>Directories: {filteredTableRows.filter((row) => row.isDir).length.toLocaleString()}</div>
              <div>Files: {filteredTableRows.filter((row) => !row.isDir).length.toLocaleString()}</div>
            </div>
          </div>
        </div>

        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Ingestion Status</div>
          <div className="fs-detail-card-body">
            <div className="fs-metric-strip">
              <div><strong>{jobs.length}</strong><span>Jobs</span></div>
              <div><strong>{jobs.filter((job) => job.status === "running").length}</strong><span>Running</span></div>
              <div><strong>{jobs.filter((job) => job.status === "completed").length}</strong><span>Completed</span></div>
            </div>
            <div className="fs-detail-list">
              {jobs.slice(0, 4).map((job) => (
                <div key={job.job_id}>{job.job_type}: {job.message || job.status}</div>
              ))}
              {jobs.length === 0 && <div>No ingestion jobs recorded yet.</div>}
            </div>
          </div>
        </div>
      </>
    );

  const renderHashSetsPanel = () =>
    renderCardGrid(
      <>
        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Hash Matching Summary</div>
          <div className="fs-detail-card-body">
            <div className="fs-metric-strip">
              <div><strong>{rowsWithHashes.length.toLocaleString()}</strong><span>Hashed Rows</span></div>
              <div><strong>{filteredArtifactMatches.length.toLocaleString()}</strong><span>Artifact Hits</span></div>
              <div><strong>{knownBadRows.length.toLocaleString()}</strong><span>Notable Matches</span></div>
            </div>
            <div className="fs-detail-list">
              <div>MD5/SHA-256 rows available: {rowsWithHashes.length}</div>
              <div>Current known-bad/notable rows: {knownBadRows.length}</div>
              <div>Deleted rows under review: {deletedRows.length}</div>
            </div>
          </div>
        </div>

        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Sample Match Queue</div>
          <div className="fs-detail-card-body">
            <table className="fs-secondary-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Category</th>
                  <th>SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {knownBadRows.slice(0, 8).map((row, idx) => (
                  <tr key={`${row.id}-${idx}`} className={cn(idx % 2 === 0 ? "even" : "odd")}>
                    <td>{row.name}</td>
                    <td>{row.category || "Unknown"}</td>
                    <td className="fs-mono">{row.sha256 || "Ã¢â‚¬â€"}</td>
                  </tr>
                ))}
                {knownBadRows.length === 0 && (
                  <tr>
                    <td colSpan={3} className="empty">No known-bad or notable rows surfaced in the current scope.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </>
    );

  const renderReportsPanel = () =>
    renderCardGrid(
      <>
        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Report Modules</div>
          <div className="fs-detail-card-body">
            <div className="fs-report-grid">
              {[
                ["Case Summary", "Evidence overview, counts, and validation state"],
                ["Timeline Report", "Chronological activity export from parsed timeline rows"],
                ["Artifact Report", "Artifact-centric findings and descriptions"],
                ["Hash Match Report", "Known-good / known-bad match summary"],
              ].map(([name, description]) => (
                <div key={name} className="fs-report-tile">
                  <strong>{name}</strong>
                  <span>{description}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Export Readiness</div>
          <div className="fs-detail-card-body">
            <div className="fs-detail-list">
              <div>Rows available for export: {filteredTableRows.length.toLocaleString()}</div>
              <div>Timeline rows available: {filteredTimelineRows.length.toLocaleString()}</div>
              <div>Artifact rows available: {filteredArtifactMatches.length.toLocaleString()}</div>
              <div>Report generation backend: pending next pass</div>
            </div>
            <div style={{ marginTop: 16 }}>
              <button
                className="fs-accent-btn"
                onClick={handleExportTimeline}
                disabled={isExportingTimeline || !loadedEvidencePath}
                title={loadedEvidencePath ? undefined : "Load evidence first"}
              >
                {isExportingTimeline
                  ? "Exporting Timeline..."
                  : `Export Timeline (${filteredTimelineRows.length.toLocaleString()} events)`}
              </button>
            </div>
            </div>
          </div>
      </>
    );

  const renderSettingsPanel = () =>
    renderCardGrid(
      <>
        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Workflow Defaults</div>
          <div className="fs-detail-card-body">
            <div className="fs-form-grid">
              <label className="fs-form-field">
                <span>Default Smoke MFT Count</span>
                <input
                  className="fs-filter-input"
                  type="number"
                  min={1}
                  value={uiSettings.defaultSmokeMftCount}
                  onChange={(event) =>
                    setUiSettings((prev) => ({ ...prev, defaultSmokeMftCount: Number(event.target.value || 1) }))
                  }
                />
              </label>
              <label className="fs-form-field">
                <span>Default Examine Preset</span>
                <input
                  className="fs-filter-input"
                  value={uiSettings.defaultExaminePreset}
                  onChange={(event) =>
                    setUiSettings((prev) => ({ ...prev, defaultExaminePreset: event.target.value }))
                  }
                />
              </label>
              <label className="fs-form-field">
                <span>Default File Table Limit</span>
                <input
                  className="fs-filter-input"
                  type="number"
                  min={1}
                  value={uiSettings.defaultFileTableLimit}
                  onChange={(event) =>
                    setUiSettings((prev) => ({ ...prev, defaultFileTableLimit: Number(event.target.value || 1) }))
                  }
                />
              </label>
              <label className="fs-form-field">
                <span>History Retention</span>
                <select
                  className="fs-filter-input"
                  value={uiSettings.historyRetentionMode}
                  onChange={(event) =>
                    setUiSettings((prev) => ({
                      ...prev,
                      historyRetentionMode: event.target.value as UiSettingsState["historyRetentionMode"],
                    }))
                  }
                >
                  <option value="keep-all">Keep all</option>
                  <option value="max-files">Max files</option>
                </select>
              </label>
            </div>
          </div>
        </div>

        <div className="forensic-card fs-detail-card">
          <div className="widget-header">Session Continuity</div>
          <div className="fs-detail-card-body">
            <label className="fs-checkbox-row">
              <input
                type="checkbox"
                checked={uiSettings.rememberLastCase}
                onChange={(event) => setUiSettings((prev) => ({ ...prev, rememberLastCase: event.target.checked }))}
              />
              <span>Remember last case</span>
            </label>
            <label className="fs-checkbox-row">
              <input
                type="checkbox"
                checked={uiSettings.rememberLastEvidencePath}
                onChange={(event) =>
                  setUiSettings((prev) => ({ ...prev, rememberLastEvidencePath: event.target.checked }))
                }
              />
              <span>Remember last evidence path</span>
            </label>
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button
                className="fs-accent-btn"
                onClick={() => toast.success("UI settings saved locally for this session.")}
              >
                Save Settings
              </button>
              <button
                className="fs-ghost-btn"
                onClick={() => {
                  setUiSettings(DEFAULT_UI_SETTINGS);
                  toast.success("Settings reset to defaults.");
                }}
              >
                Reset Defaults
              </button>
            </div>
          </div>
        </div>
      </>
    );

  const renderWorkspaceCenter = () => {
    switch (activeSection) {
      case "file-system":
        return (
          <UnifiedTable
            rows={filteredTableRows}
            selectedIds={selectedTableIds}
            onSelectionChange={(ids, primary) => {
              setSelectedTableIds(ids);
              setSelectedFromTableRow(primary);
            }}
            onAction={onUnifiedAction}
          />
        );
      case "artifacts":
      case "timeline":
        return (
          <MainView
            rows={filteredTableRows.map(mapToArtifactRow)}
            activeTab={activeSection === "timeline" ? "timeline" : (artifactSubtab === "artifacts" ? "table" : artifactSubtab as MainTab)}
            onActiveTabChange={(tab) => {
              if (tab === "table") setArtifactSubtab("artifacts");
              else if (tab === "hex") setArtifactSubtab("hex");
              else if (tab === "strings") setArtifactSubtab("strings");
              else if (tab === "timeline") setActiveSection("timeline");
            }}
            timeline={filteredTimelineRows.map(r => ({
              id: r.id,
              timestamp: String(r.timestamp || ""),
              source: r.source,
              event_type: r.eventType,
              description: r.description,
              severity: "info"
            }))}
            preview={artifactPreview}
            previewLoading={previewLoading}
            previewError={previewError}
            selectedRowId={selectedNode ? `node:${normalizePath(selectedNode.path)}:${selectedNode.name.toLowerCase()}` : null}
            onPrimaryRowChange={(row) => setSelectedFromTableRow(row ? {
                id: row.id,
                name: row.name,
                fullPath: row.path,
                size: row.size,
                birth: row.createdTime,
                modified: row.modifiedTime,
                accessed: row.accessedTime,
                mftChanged: row.mftChangedTime,
                md5: row.md5,
                sha1: row.sha1,
                sha256: row.sha256,
                category: row.category,
                deleted: row.deleted,
                mftRecord: row.mftRecord,
                sequence: row.sequence,
                tags: [],
                isDir: row.isDir,
                nodeRef: row.nodeRef,
            } : null)}
            onContextAction={(action, row) => onUnifiedAction(action as any, {
                id: row.id,
                name: row.name,
                fullPath: row.path,
                size: row.size,
                birth: row.createdTime,
                modified: row.modifiedTime,
                accessed: row.accessedTime,
                mftChanged: row.mftChangedTime,
                md5: row.md5,
                sha1: row.sha1,
                sha256: row.sha256,
                category: row.category,
                deleted: row.deleted,
                mftRecord: row.mftRecord,
                sequence: row.sequence,
                tags: [],
                isDir: row.isDir,
                nodeRef: row.nodeRef,
            })}
            onExportSelected={(rows) => exportPaths(rows.map(r => r.path))}
            evidencePath={loadedEvidencePath}
          />
        );
      case "communications":
        return <EmailView rows={filteredEmailRows} />;
      case "registry":
        return <RegistryView rows={filteredRegistryRows} />;
      case "browser-data":
        return (
          <UnifiedTable
            rows={filteredTableRows.filter((row) =>
              matchesSearch(row.fullPath, row.name, row.category) &&
              /chrome|edge|firefox|brave|browser|cache|history|cookies/i.test(`${row.fullPath} ${row.name} ${row.category || ""}`)
            )}
            selectedIds={selectedTableIds}
            onSelectionChange={(ids, primary) => {
              setSelectedTableIds(ids);
              setSelectedFromTableRow(primary);
            }}
            onAction={onUnifiedAction}
          />
        );
      case "carved-files":
        return (
          <UnifiedTable
            rows={filteredTableRows.filter((row) => row.deleted || /carv/i.test(`${row.fullPath} ${row.name} ${row.category || ""}`))}
            selectedIds={selectedTableIds}
            onSelectionChange={(ids, primary) => {
              setSelectedTableIds(ids);
              setSelectedFromTableRow(primary);
            }}
            onAction={onUnifiedAction}
          />
        );
      case "logs":
        return renderSummaryPanel(
          "Logs",
          <div className="space-y-2">
            {jobs.length === 0 ? (
              <p className="fs-state">No logs yet.</p>
            ) : (
              jobs.map((job) => (
                <div key={job.job_id} className="fs-job-card">
                  <div className="fs-job-header">
                    <span className="fs-job-title">{job.job_type}</span>
                    <span className={`fs-status-badge ${job.status === "completed" ? "completed" : job.status === "failed" ? "error" : "processing"}`}>
                      {job.status}
                    </span>
                  </div>
                  <div className="fs-job-message">{job.message}</div>
                </div>
              ))
            )}
          </div>
        );
      case "case-overview":
        return renderCaseOverviewPanel();
      case "evidence-sources":
        return renderEvidenceSourcesPanel();
      case "hash-sets":
        return renderHashSetsPanel();
      case "reports":
        return renderReportsPanel();
      case "settings":
        return renderSettingsPanel();
      default:
        return renderMediaPanel();
    }
  };

  if (screen === "splash") {
    return (
      <div className="h-screen w-screen flex flex-col items-center justify-center" style={{ background: "hsl(var(--background))" }}>
        <div className="w-20 h-20 rounded-2xl flex items-center justify-center animate-pulse" style={{ background: "color-mix(in srgb, hsl(var(--operational)) 12%, transparent)", color: "hsl(var(--operational))" }}>
          <FolderOpen className="w-10 h-10" />
        </div>
        <h1 className="mt-5 text-2xl font-bold" style={{ color: "hsl(var(--foreground))" }}>Vantor Shield</h1>
        <p className="mt-2 text-sm" style={{ color: "hsl(var(--muted-foreground))" }}>Initializing forensic workspace...</p>
      </div>
    );
  }

  const renderRightDetailPanel = () => (
    <div className="fs-pane forensic-card">
      <div className="widget-header">
        <div className="fs-widget-header-row">
          <span>Notes &amp; Tags</span>
          <StickyNote className="w-3.5 h-3.5" />
        </div>
      </div>
      <div className="fs-pane-body pad">
        {selectedNode ? (
          <>
            <div className="fs-selection-card">
              <div className="fs-sidebar-status-label">Selected</div>
              <div className="fs-selection-name">{selectedNode.name}</div>
              <div className="fs-selection-path">{selectedNode.path}</div>
              <div className="fs-selection-meta">Birth {formatTimestamp(selectedNode.createdTime)}</div>
              <div className="fs-selection-meta">Modified {formatTimestamp(selectedNode.modifiedTime)}</div>
              <div className="fs-selection-meta">Accessed {formatTimestamp(selectedNode.accessedTime)}</div>
              <div className="fs-selection-meta">MFT Changed {formatTimestamp(selectedNode.mftChangedTime)}</div>
            </div>

            <div className="fs-tag-card">
              <div className="fs-sidebar-status-label">Tags</div>
              <div className="fs-tag-cloud">
                {selectedNodeTags.map((tag) => (
                  <span key={tag.tagId} className="fs-tag-pill" style={{ backgroundColor: `${tag.color}20`, color: tag.color }}>
                    {tag.name}
                    <button onClick={() => handleRemoveTag(tag.tagId)} className="fs-note-delete">
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
                {selectedNodeTags.length === 0 && <div className="fs-empty-state">No tags applied.</div>}
              </div>
              <div className="fs-tag-options">
                {allTags
                  .filter((t) => !selectedNodeTags.some((st) => st.tagId === t.tagId))
                  .map((tag) => (
                    <button key={tag.tagId} onClick={() => handleAddTag(tag.tagId)} className="fs-tag-button" style={{ color: tag.color }}>
                      <Plus className="w-3 h-3" />
                      {tag.name}
                    </button>
                  ))}
              </div>
            </div>

            <div className="fs-note-card">
              <div className="fs-sidebar-status-label">Notes</div>
              <textarea value={newNoteContent} onChange={(e) => setNewNoteContent(e.target.value)} placeholder="Add examiner note..." />
              <div style={{ marginTop: 8 }}>
                <button onClick={handleAddNote} disabled={!newNoteContent.trim()} className="fs-accent-btn" style={{ width: "100%" }}>
                  Add Note
                </button>
              </div>
              <div className="fs-note-list" style={{ marginTop: 10 }}>
                {notes.length === 0 ? (
                  <div className="fs-empty-state">No notes for this item.</div>
                ) : (
                  notes.map((note) => (
                    <div key={note.noteId} className="fs-note-item">
                      <div className="fs-note-item-header">
                        <span className="fs-note-item-author">{note.author}</span>
                        <button onClick={() => handleDeleteNote(note.noteId)} className="fs-note-delete">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                      <div className="fs-note-item-content">{note.content}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </>
        ) : (
          <div className="fs-empty-panel">Select a file or folder to manage notes and tags.</div>
        )}

        <div className="fs-job-card" style={{ marginTop: 16 }}>
          <div className="fs-sidebar-status-label" style={{ marginBottom: 8 }}>Active Jobs</div>
          <div className="fs-job-list">
            {jobs.filter((j) => j.job_type !== "image_loading").length === 0 ? (
              <div className="fs-empty-state">No active jobs.</div>
            ) : (
              jobs
                .filter((j) => j.job_type !== "image_loading")
                .map((job) => (
                  <div key={job.job_id} className="fs-job-card">
                    <div className="fs-job-header">
                      <span className="fs-job-title">{job.job_type}</span>
                      {job.status === "running" && <RefreshCw className="w-3 h-3 animate-spin" />}
                      {job.status === "completed" && <CheckCircle className="w-3 h-3" />}
                      {job.status === "failed" && <XCircle className="w-3 h-3" />}
                    </div>
                    <div className="fs-job-progress-track">
                      <div className="fs-accent-progress" style={{ width: `${job.progress}%` }} />
                    </div>
                    <div className="fs-job-message" style={{ marginTop: 6 }}>{job.message}</div>
                  </div>
                ))
            )}
          </div>
        </div>
      </div>
    </div>
  );

  const renderWorkspacePage = (title: string, description: string) => {
    const showTree = SECTIONS_WITH_TREE.has(activeSection);

    return (
    <div className="fs-page">
      <div className="fs-page-inner">
        <div className="fs-page-title-row">
          <div className="fs-page-title">
            <h2>{title}</h2>
            <p>{description}</p>
          </div>
          <div className="fs-toolbar-pill">
            <HardDrive className="w-3.5 h-3.5" />
            <span>{loadedEvidencePath ? "Evidence loaded" : "No evidence loaded"}</span>
          </div>
        </div>

        <div className={cn("fs-workspace", !showTree && "fs-workspace-single")}>
          {showTree ? (
            <div className="fs-pane forensic-card">
              <div className="widget-header">
                <div className="fs-widget-header-row">
                  <span>File System Tree</span>
                  <Layers className="w-3.5 h-3.5" />
                </div>
              </div>
              <div className="fs-pane-body pad">
                {evidenceTree && (
                  <div className="fs-tree-summary">
                    {evidenceTree.name} - {totalNodeCount.toLocaleString()} items
                  </div>
                )}
                <div className="fs-tree-container" style={{ height: "calc(100vh - 300px)" }}>
                  {isLoading ? (
                    <div className="fs-empty-state" style={{ height: "100%", display: "grid", placeItems: "center", gap: 10 }}>
                      <div className="fs-inline" style={{ gap: 10 }}>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Loading evidence tree...</span>
                      </div>
                    </div>
                  ) : !loadedEvidencePath ? (
                    <div className="fs-empty-state" style={{ height: "100%", display: "grid", placeItems: "center" }}>
                      No evidence loaded. Use File &gt; Open Evidence to begin.
                    </div>
                  ) : evidenceTree ? (
                    <VirtualTree
                      tree={evidenceTree}
                      expandedNodes={expandedNodes}
                      selectedNode={selectedNode}
                      onToggleExpand={handleToggleExpand}
                      onSelectNode={handleSelectNode}
                      formatSize={formatSize}
                    />
                  ) : (
                    <div className="fs-empty-state" style={{ height: "100%", display: "grid", placeItems: "center" }}>
                      No evidence loaded. Use File &gt; Open Evidence to begin.
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : null}
          <div className={cn("fs-pane", (activeSection === "artifacts" || activeSection === "timeline") && "flex-1 overflow-hidden")}>
             {renderWorkspaceCenter()}
          </div>

          {showTree && activeSection !== "artifacts" && activeSection !== "timeline" ? renderRightDetailPanel() : null}
        </div>
      </div>
    </div>
    );
  };

  return (
    <>
      <div id="MOUNT_CHECK" style={{ position: 'fixed', top: 0, left: 0, background: 'red', color: 'white', zIndex: 9999, padding: '10px' }}>
        REACT_MOUNT_OK
      </div>
      <Layout
        caseName={caseInfo?.name || null}
        evidenceSource={loadedEvidencePath}
        currentSection={activeSection}
        onSectionChange={setActiveSection}
        onOpenEvidence={handleOpenEvidence}
        searchQuery={searchQuery}
        onSearchQueryChange={setSearchQuery}
        taskCount={jobs.filter((job) => job.status !== "completed").length}
        currentExaminer={currentExaminer}
        theme={theme}
        onToggleTheme={() => setTheme((prev) => (prev === "light" ? "dark" : "light"))}
        onOpenProfile={() => {
          setExaminerNameDraft(currentExaminer);
          setProfileDialogOpen(true);
        }}
        onOpenPreferences={() => setPreferencesDialogOpen(true)}
        onSignOut={handleSignOut}
      >
        {activeSection === "dashboard" ? (
          <Dashboard
            caseName={caseInfo?.name || null}
            caseId={caseInfo?.id ? caseInfo.id.slice(0, 8) : null}
            examiner={caseInfo ? currentExaminer : null}
            openedDate={caseInfo?.created ? new Date(caseInfo.created).toLocaleDateString() : null}
            verified={Boolean(loadedEvidencePath)}
            hasActiveCase={Boolean(caseInfo)}
            hasEvidenceLoaded={Boolean(loadedEvidencePath)}
            evidenceSources={loadedEvidencePath ? 1 : 0}
            indexedItems={filteredTableRows.length}
            hashMatches={filteredArtifactMatches.length}
            flaggedItems={filteredTableRows.filter((row) => row.deleted || /notable|malware|csam/i.test(row.category || "")).length}
            timelineEvents={filteredTimelineRows.length}
            artifactCount={filteredArtifactMatches.length + filteredRegistryRows.length + filteredEmailRows.length + filteredMediaRows.length}
            progressPercent={jobs.length > 0 ? Math.round(jobs.reduce((acc, job) => acc + (job.progress || 0), 0) / jobs.length) : 0}
            tasks={dashboardTasks.length > 0 ? dashboardTasks : [
              { id: "idle-1", name: "Awaiting evidence load", status: "queued", progress: 0, detail: "Open evidence to begin indexing." },
              { id: "idle-2", name: "Artifact builders", status: "queued", progress: 0, detail: "Timeline, registry, media, and email parsers are idle." },
            ]}
            recentActivity={dashboardRecentActivity.length > 0 ? dashboardRecentActivity : [
              { id: "activity-1", kind: "info", text: "Workspace initialized. Add evidence when you are ready.", timeAgo: "now" },
            ]}
            fileTypeRows={dashboardFileTypeRows}
            artifactRows={dashboardArtifactRows}
            timelineBars={dashboardTimelineBars}
          />
        ) : (
          renderWorkspacePage(
            activeSection === "file-system" ? "File System" :
            activeSection === "artifacts" ? "Artifacts" :
            activeSection === "timeline" ? "Timeline" :
            activeSection === "registry" ? "Registry" :
            activeSection === "communications" ? "Communications" :
            activeSection === "browser-data" ? "Browser Data" :
            activeSection === "carved-files" ? "Carved Files" :
            activeSection === "evidence-sources" ? "Evidence Sources" :
            activeSection === "case-overview" ? "Case Overview" :
            activeSection === "hash-sets" ? "Hash Sets" :
            activeSection === "reports" ? "Reports" :
            activeSection === "settings" ? "Settings" : "Logs",
            activeSection === "file-system"
              ? "Explore the mounted evidence tree and inspect indexed records."
              : activeSection === "artifacts"
                ? "Review extracted forensic artifacts for the selected path."
                : activeSection === "timeline"
                  ? "Investigate time-based activity across parsed evidence."
                  : activeSection === "registry"
                    ? "Inspect registry artifacts and LastWrite activity."
                    : activeSection === "communications"
                      ? "Review communication and email-related artifacts."
                      : activeSection === "browser-data"
                        ? "Focus on browser history, cache, cookie, and web traces."
                        : activeSection === "carved-files"
                          ? "Inspect deleted or carved records surfaced during processing."
                          : "Operational page content for the current forensic workspace."
          )
        )}
      </Layout>

      {isLoading && (
        <div className="fs-loading-overlay">
          <div className="fs-loading-card">
            <div className="fs-loading-card-header">
              <RefreshCw className="w-5 h-5 animate-spin" />
              <h3>Loading Evidence</h3>
            </div>
            <div className="fs-loading-card-copy">{loadingStatus || "Loading image..."}</div>
            <div className="fs-loading-card-copy" style={{ marginTop: 6 }}>Hashing and builders continue in the background.</div>
          </div>
        </div>
      )}

      {profileDialogOpen && (
        <div className="fs-modal-overlay" onClick={() => setProfileDialogOpen(false)}>
          <div className="forensic-card fs-modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="widget-header">
              <div className="fs-widget-header-row">
                <span>Examiner Profile</span>
                <UserRound className="w-3.5 h-3.5" />
              </div>
            </div>
            <div className="fs-modal-body">
              <label className="fs-form-field">
                <span>Examiner Name</span>
                <input
                  className="fs-filter-input"
                  value={examinerNameDraft}
                  onChange={(event) => setExaminerNameDraft(event.target.value)}
                  placeholder="Enter examiner name"
                />
              </label>
              <div className="fs-modal-actions">
                <button className="fs-ghost-btn" onClick={() => setProfileDialogOpen(false)}>Cancel</button>
                <button className="fs-accent-btn" onClick={saveExaminerProfile}>Save Profile</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {preferencesDialogOpen && (
        <div className="fs-modal-overlay" onClick={() => setPreferencesDialogOpen(false)}>
          <div className="forensic-card fs-modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="widget-header">
              <div className="fs-widget-header-row">
                <span>Preferences</span>
                <UserCog className="w-3.5 h-3.5" />
              </div>
            </div>
            <div className="fs-modal-body">
              <div className="fs-preference-row">
                <div>
                  <div className="fs-section-title">Theme</div>
                  <div className="fs-state">Switch between the light and dark workspace themes.</div>
                </div>
                <button className="fs-accent-btn" onClick={() => setTheme((prev) => (prev === "light" ? "dark" : "light"))}>
                  {theme === "light" ? "Enable Night Mode" : "Use Light Mode"}
                </button>
              </div>
              <label className="fs-checkbox-row">
                <input
                  type="checkbox"
                  checked={uiSettings.rememberLastCase}
                  onChange={(event) => setUiSettings((prev) => ({ ...prev, rememberLastCase: event.target.checked }))}
                />
                <span>Remember last case</span>
              </label>
              <label className="fs-checkbox-row">
                <input
                  type="checkbox"
                  checked={uiSettings.rememberLastEvidencePath}
                  onChange={(event) =>
                    setUiSettings((prev) => ({ ...prev, rememberLastEvidencePath: event.target.checked }))
                  }
                />
                <span>Remember last evidence path</span>
              </label>
              <div className="fs-modal-actions">
                <button className="fs-ghost-btn" onClick={() => setPreferencesDialogOpen(false)}>Close</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default App;

