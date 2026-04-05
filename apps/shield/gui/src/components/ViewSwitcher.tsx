import React from "react";
import {
  Database,
  FileSearch,
  FileSpreadsheet,
  Film,
  Inbox,
  ScrollText,
  Timer,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type CenterViewMode =
  | "table"
  | "artifacts"
  | "timeline"
  | "email"
  | "media"
  | "registry"
  | "logs";

interface ViewSwitcherProps {
  activeView: CenterViewMode;
  onChange: (view: CenterViewMode) => void;
  orientation?: "horizontal" | "vertical";
}

const VIEW_ITEMS: Array<{ id: CenterViewMode; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: "artifacts", label: "Artifacts", icon: FileSearch },
  { id: "timeline", label: "Timeline", icon: Timer },
  { id: "email", label: "Email", icon: Inbox },
  { id: "media", label: "Media Viewer", icon: Film },
  { id: "registry", label: "Registry", icon: Database },
  { id: "logs", label: "Logs", icon: ScrollText },
  { id: "table", label: "Table", icon: FileSpreadsheet },
];

export default function ViewSwitcher({ activeView, onChange, orientation = "horizontal" }: ViewSwitcherProps) {
  return (
    <div className={cn("fs-view-switcher", orientation === "vertical" && "is-vertical")} aria-label="Center view switcher">
      {VIEW_ITEMS.map((item) => (
        <button
          key={item.id}
          type="button"
          className={cn("fs-view-icon", activeView === item.id && "is-active")}
          onClick={() => onChange(item.id)}
          title={item.label}
          aria-label={item.label}
        >
          <item.icon className="w-4 h-4" />
        </button>
      ))}
    </div>
  );
}
