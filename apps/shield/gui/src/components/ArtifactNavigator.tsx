import React, { useMemo, useState } from "react";
import { 
  Users, 
  MessageSquare, 
  Mail, 
  Globe, 
  Cloud, 
  Settings, 
  Image as ImageIcon,
  ChevronDown,
  ChevronRight,
  Database,
  FileSearch,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { detectCategory, ArtifactCategory } from "@/lib/artifactProviders";
import ProviderIcon from "@/components/ProviderIcon";

export interface ArtifactTreeNode {
  id: string;
  label: string;
  type: "category" | "provider" | "artifact";
  category?: ArtifactCategory;
  providerId?: string;
  icon?: React.ReactNode;
  count?: number;
  children?: ArtifactTreeNode[];
}

interface ArtifactNavigatorProps {
  rows: any[]; // Flattened artifacts
  selectedId: string | null;
  onSelect: (type: "category" | "provider" | "artifact", value: string) => void;
  className?: string;
}

const CATEGORY_ICONS: Record<ArtifactCategory, React.ReactNode> = {
  "Social Media": <Users className="w-4 h-4" />,
  "Messaging": <MessageSquare className="w-4 h-4" />,
  "Email": <Mail className="w-4 h-4" />,
  "Browsing": <Globe className="w-4 h-4" />,
  "Cloud Storage": <Cloud className="w-4 h-4" />,
  "Productivity": <Database className="w-4 h-4" />,
  "System Artifacts": <Settings className="w-4 h-4" />,
  "Multimedia": <ImageIcon className="w-4 h-4" />,
  "Other": <FileSearch className="w-4 h-4" />,
};

export default function ArtifactNavigator({ rows, selectedId, onSelect, className }: ArtifactNavigatorProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set(["Social Media", "Messaging", "Email"]));

  const tree = useMemo(() => {
    const categories: Record<string, Set<string>> = {};
    const counts: Record<string, number> = {};

    rows.forEach(row => {
      const cat = detectCategory(row.name, row.path);
      if (!categories[cat]) categories[cat] = new Set();
      
      // Simple logic to extract provider if possible
      const providerMatch = row.name.toLowerCase().match(/facebook|instagram|snapchat|whatsapp|telegram|signal|gmail|outlook|chrome|edge/);
      const provider = providerMatch ? providerMatch[0].charAt(0).toUpperCase() + providerMatch[0].slice(1) : "Other";
      
      categories[cat].add(provider);
      counts[`${cat}:${provider}`] = (counts[`${cat}:${provider}`] || 0) + 1;
      counts[cat] = (counts[cat] || 0) + 1;
    });

    return Object.keys(categories).sort().map(cat => ({
      id: cat,
      label: cat,
      type: "category" as const,
      category: cat as ArtifactCategory,
      icon: CATEGORY_ICONS[cat as ArtifactCategory],
      count: counts[cat],
      children: Array.from(categories[cat]).sort().map(prov => ({
        id: `${cat}:${prov}`,
        label: prov,
        type: "provider" as const,
        providerId: prov.toLowerCase(),
        count: counts[`${cat}:${prov}`],
      }))
    }));
  }, [rows]);

  const toggle = (id: string) => {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpanded(next);
  };

  return (
    <div className={cn("flex flex-col h-full bg-card border-r border-border", className)}>
      <div className="p-3 border-b border-border flex items-center gap-2">
        <Database className="w-4 h-4 text-primary" />
        <span className="font-semibold text-sm">Forensic Artifacts</span>
      </div>
      <div className="flex-1 overflow-auto py-2">
        {tree.map(node => (
          <div key={node.id} className="select-none">
            <div 
              className={cn(
                "flex items-center gap-2 px-3 py-1.5 transition-colors cursor-pointer text-sm group",
                selectedId === node.id ? "bg-primary/10 text-primary" : "hover:bg-accent"
              )}
              onClick={() => {
                toggle(node.id);
                onSelect("category", node.id);
              }}
            >
              <span className="w-4 h-4 flex items-center justify-center">
                {expanded.has(node.id) ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
              </span>
              <span className="text-muted-foreground group-hover:text-foreground">
                {node.icon}
              </span>
              <span className="flex-1 truncate">{node.label}</span>
              <span className="text-[10px] bg-muted px-1.5 py-0.5 rounded-full text-muted-foreground">
                {node.count}
              </span>
            </div>

            {expanded.has(node.id) && node.children && (
              <div className="ml-6 border-l border-border mt-0.5">
                {node.children.map(child => (
                  <div 
                    key={child.id}
                    className={cn(
                      "flex items-center gap-2 pl-4 pr-3 py-1.5 transition-colors cursor-pointer text-xs group",
                      selectedId === child.id ? "bg-primary/10 text-primary border-r-2 border-primary" : "hover:bg-accent"
                    )}
                    onClick={() => onSelect("provider", child.id)}
                  >
                    <ProviderIcon text={child.label} size={12} className="opacity-70 group-hover:opacity-100" />
                    <span className="flex-1 truncate">{child.label}</span>
                    <span className="text-[10px] opacity-50">
                      {child.count}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
