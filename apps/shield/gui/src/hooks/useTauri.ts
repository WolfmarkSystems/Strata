import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

export interface EvidenceNode {
  name: string;
  path: string;
  isDir: boolean;
  size?: number;
  children?: EvidenceNode[];
  metadata?: Record<string, string>;
}

export interface JobProgress {
  job_id: string;
  job_type: string;
  status: "running" | "completed" | "failed" | "cancelled";
  progress: number;
  message: string;
}

export interface TimelineEntry {
  id: string;
  timestamp?: number | null;
  source?: string;
  eventType?: string;
  description?: string;
}

export function useTauriInvoke() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const invokeCmd = useCallback(async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<T>(cmd, args);
      return result;
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      setError(errorMsg);
      throw e;
    } finally {
      setLoading(false);
    }
  }, []);

  return { invoke: invokeCmd, loading, error };
}

export function useTauriEvent<T>(eventName: string, callback: (payload: T) => void) {
  useEffect(() => {
    let unlisten: UnlistenFn | undefined;

    const setupListener = async () => {
      unlisten = await listen<T>(eventName, (event) => {
        callback(event.payload);
      });
    };

    setupListener();

    return () => {
      if (unlisten) {
        unlisten();
      }
    };
  }, [eventName, callback]);
}

export async function loadEvidence(path: string): Promise<EvidenceNode> {
  const result = await invoke<{ tree: EvidenceNode }>("load_evidence_and_build_tree", {
    path,
    runArtifactParsers: true,
  });
  return result.tree;
}

export async function getTimeline(limit = 1000): Promise<TimelineEntry[]> {
  return invoke<TimelineEntry[]>("get_timeline_rows", { limit });
}

export async function generateReport(caseId: string, format: string): Promise<string> {
  return invoke<string>("generate_report", { caseId, format });
}

export async function acquireMemory(outputPath?: string): Promise<string> {
  return invoke<string>("acquire_live_memory", { outputPath });
}

export async function listPlugins(): Promise<Array<{ name?: string; version?: string }>> {
  return invoke<Array<{ name?: string; version?: string }>>("list_plugins");
}

export async function mountEvidence(path: string): Promise<unknown> {
  return invoke("mount_evidence", { path });
}

export async function enumerateVolume(evidencePath: string, volumeIndex?: number): Promise<unknown[]> {
  return invoke<unknown[]>("enumerate_volume", { evidencePath, volumeIndex });
}

export async function readVfsFile(evidencePath: string, artifactPath: string, maxBytes = 16384): Promise<unknown> {
  return invoke("read_vfs_file", { evidencePath, artifactPath, maxBytes });
}

export async function loadNsrlDatabase(nsrlPath: string): Promise<unknown> {
  return invoke("load_nsrl_database", { nsrlPath });
}

export async function hashVfsFiles(evidencePath: string, nsrlPath?: string, customBadPath?: string): Promise<unknown> {
  return invoke("hash_vfs_files", { evidencePath, nsrlPath, customBadPath });
}

export interface KbBridgeSearchResult {
  content: string;
  score?: number;
}

export async function startSpecializedViewBuilders(evidencePath: string): Promise<void> {
  return invoke<void>("start_specialized_view_builders", { evidencePath });
}

export async function exportJsonlTimeline(outputPath: string): Promise<string> {
  return invoke<string>("export_jsonl_timeline", { outputPath });
}

export async function searchKbBridge(query: string): Promise<{ results?: KbBridgeSearchResult[] }> {
  return invoke<{ results?: KbBridgeSearchResult[] }>("search_kb_bridge", { query });
}