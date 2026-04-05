import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Card from "../components/Card";

export interface UiSettings {
  defaultSmokeMftCount: number;
  defaultExaminePreset: string;
  defaultFileTableLimit: number;
  historyRetentionMode: "keep-all" | "max-files";
  maxHistoryFiles: number;
  rememberLastCase: boolean;
  rememberLastEvidencePath: boolean;
}

interface SettingsProps {
  value: UiSettings;
  onChange: (next: UiSettings) => void;
  onSave: (next: UiSettings) => Promise<{ ok: boolean; message?: string } | void>;
  onReset: () => Promise<{ ok: boolean; message?: string } | void>;
  onCleanupNow?: () => Promise<{ ok: boolean; message?: string } | void>;
  cleanupRunning?: boolean;
}

const DEFAULTS: UiSettings = {
  defaultSmokeMftCount: 100,
  defaultExaminePreset: "triage_default",
  defaultFileTableLimit: 500,
  historyRetentionMode: "keep-all",
  maxHistoryFiles: 500,
  rememberLastCase: true,
  rememberLastEvidencePath: true,
};

export default function SettingsPage({
  value,
  onChange,
  onSave,
  onReset,
  onCleanupNow,
  cleanupRunning = false,
}: SettingsProps) {
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [kbBridgeStatus, setKbBridgeStatus] = useState<string>("Checking...");
  const [capabilityCount, setCapabilityCount] = useState<number>(0);

  const hasChanges = useMemo(() => JSON.stringify(value) !== JSON.stringify(DEFAULTS), [value]);

  useEffect(() => {
    let cancelled = false;

    invoke<{ status?: string; message?: string }>("kb_bridge_health")
      .then((health) => {
        if (!cancelled) {
          setKbBridgeStatus(health.status || health.message || "Healthy");
        }
      })
      .catch((error) => {
        if (!cancelled) setKbBridgeStatus(`Unavailable (${String(error)})`);
      });

    invoke<{ commands?: Record<string, boolean> }>("capabilities")
      .then((caps) => {
        if (!cancelled) {
          const count = caps?.commands ? Object.values(caps.commands).filter(Boolean).length : 0;
          setCapabilityCount(count);
        }
      })
      .catch(() => {
        if (!cancelled) setCapabilityCount(0);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  async function handleSave() {
    setSaving(true);
    setToast(null);
    try {
      const result = await onSave(value);
      setToast({ type: result?.ok === false ? "error" : "success", text: result?.message || "Settings saved." });
    } catch (error) {
      setToast({ type: "error", text: `Save failed: ${String(error)}` });
    } finally {
      setSaving(false);
    }
  }

  async function handleReset() {
    setSaving(true);
    setToast(null);
    try {
      const result = await onReset();
      setToast({ type: result?.ok === false ? "error" : "success", text: result?.message || "Settings reset." });
    } catch (error) {
      setToast({ type: "error", text: `Reset failed: ${String(error)}` });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fs-grid">
      <Card
        title="Settings"
        subtitle="Command defaults, retention policy, and session continuity"
        actions={
          <div className="fs-inline">
            <button className="fs-btn" onClick={handleSave} disabled={saving}>{saving ? "Saving..." : "Save / Apply"}</button>
            <button className="fs-btn" onClick={handleReset} disabled={saving}>Reset Defaults</button>
          </div>
        }
      >
        {toast && <div className={`fs-toast ${toast.type}`}>{toast.text}</div>}
        <div className="fs-field-grid two-col" style={{ marginTop: 12 }}>
          <div className="fs-field">
            <label>Default Smoke MFT Count</label>
            <input
              className="fs-input"
              type="number"
              min={1}
              value={value.defaultSmokeMftCount}
              onChange={(e) => onChange({ ...value, defaultSmokeMftCount: Number(e.target.value || 1) })}
            />
          </div>
          <div className="fs-field">
            <label>Default Examine Preset</label>
            <input
              className="fs-input"
              value={value.defaultExaminePreset}
              onChange={(e) => onChange({ ...value, defaultExaminePreset: e.target.value })}
            />
          </div>
          <div className="fs-field">
            <label>Default File Table Limit</label>
            <input
              className="fs-input"
              type="number"
              min={1}
              value={value.defaultFileTableLimit}
              onChange={(e) => onChange({ ...value, defaultFileTableLimit: Number(e.target.value || 1) })}
            />
          </div>
          <div className="fs-field">
            <label>History Retention Mode</label>
            <select
              className="fs-select"
              value={value.historyRetentionMode}
              onChange={(e) => onChange({ ...value, historyRetentionMode: e.target.value as UiSettings["historyRetentionMode"] })}
            >
              <option value="keep-all">Keep all</option>
              <option value="max-files">Max files</option>
            </select>
          </div>
          <div className="fs-field">
            <label>Max History Files</label>
            <input
              className="fs-input"
              type="number"
              min={1}
              value={value.maxHistoryFiles}
              onChange={(e) => onChange({ ...value, maxHistoryFiles: Number(e.target.value || 1) })}
              disabled={value.historyRetentionMode !== "max-files"}
            />
          </div>
          <div className="fs-field">
            <label>Cleanup</label>
            <button className="fs-btn" disabled={!onCleanupNow || cleanupRunning} onClick={() => onCleanupNow?.()}>
              {cleanupRunning ? "Cleaning..." : "Run Cleanup Now"}
            </button>
          </div>
          <label className="fs-inline fs-muted">
            <input
              type="checkbox"
              checked={value.rememberLastCase}
              onChange={(e) => onChange({ ...value, rememberLastCase: e.target.checked })}
            />
            Remember last case
          </label>
          <label className="fs-inline fs-muted">
            <input
              type="checkbox"
              checked={value.rememberLastEvidencePath}
              onChange={(e) => onChange({ ...value, rememberLastEvidencePath: e.target.checked })}
            />
            Remember last evidence path
          </label>
        </div>
        <div className="fs-muted" style={{ marginTop: 10 }}>
          {hasChanges ? "Unsaved changes present." : "No unsaved changes."}
        </div>
        <div className="fs-muted" style={{ marginTop: 6 }}>
          KB Bridge: {kbBridgeStatus}
        </div>
        <div className="fs-muted" style={{ marginTop: 4 }}>
          Backend capabilities detected: {capabilityCount}
        </div>
      </Card>
    </div>
  );
}
