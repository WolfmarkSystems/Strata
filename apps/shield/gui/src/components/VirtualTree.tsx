import React, { useCallback, useRef, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, File as FileIcon, Folder } from "lucide-react";

export interface EvidenceNode {
  name: string;
  nodeType?: string;
  isDir: boolean;
  path: string;
  size?: number;
  children?: EvidenceNode[];
  metadata?: Record<string, string>;
  category?: string;
  hash?: string;
  mftRecordId?: number;
  sequenceNumber?: number;
  isDeleted?: boolean;
  createdTime?: number;
  modifiedTime?: number;
  accessedTime?: number;
  mftChangedTime?: number;
}

interface FlatNode {
  node: EvidenceNode;
  level: number;
  isExpanded: boolean;
  hasChildren: boolean;
  id: string;
}

interface VirtualTreeProps {
  tree: EvidenceNode | null;
  expandedNodes: Set<string>;
  selectedNode: EvidenceNode | null;
  onToggleExpand: (nodeId: string) => void;
  onSelectNode: (node: EvidenceNode) => void;
  formatSize?: (bytes?: number) => string;
}

const formatSizeDefault = (bytes?: number) => {
  if (bytes === undefined || bytes === null || !Number.isFinite(bytes)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(1)} ${units[idx]}`;
};

const ROW_HEIGHT = 28;
const OVERSCAN = 10;

export default function VirtualTree({
  tree,
  expandedNodes,
  selectedNode,
  onToggleExpand,
  onSelectNode,
  formatSize = formatSizeDefault,
}: VirtualTreeProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(400);

  const formatSizeRef = formatSize || formatSizeDefault;

  const flatNodes = React.useMemo<FlatNode[]>(() => {
    if (!tree) return [];

    const result: FlatNode[] = [];
    const stack: { node: EvidenceNode; level: number }[] = [{ node: tree, level: 0 }];

    while (stack.length > 0) {
      const { node, level } = stack.pop()!;
      const nodeId = `${node.path}::${node.name}`;
      const isExpanded = expandedNodes.has(nodeId);
      const hasChildren = Boolean(node.children && node.children.length > 0);

      result.push({
        node,
        level,
        isExpanded,
        hasChildren,
        id: nodeId,
      });

      if (isExpanded && node.children) {
        for (let i = node.children.length - 1; i >= 0; i--) {
          stack.push({ node: node.children[i], level: level + 1 });
        }
      }
    }

    return result;
  }, [tree, expandedNodes]);

  const handleToggle = useCallback(
    (nodeId: string) => {
      onToggleExpand(nodeId);
    },
    [onToggleExpand]
  );

  const handleSelect = useCallback(
    (node: EvidenceNode) => {
      onSelectNode(node);
    },
    [onSelectNode]
  );

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setContainerHeight(entry.contentRect.height);
      }
    });

    observer.observe(container);
    setContainerHeight(container.clientHeight);

    return () => observer.disconnect();
  }, []);

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  }, []);

  if (!tree) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400">
        No evidence loaded
      </div>
    );
  }

  if (flatNodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400">
        Loading tree...
      </div>
    );
  }

  const selectedId = selectedNode ? `${selectedNode.path}::${selectedNode.name}` : null;
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(
    flatNodes.length - 1,
    Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + OVERSCAN
  );
  const visibleNodes = flatNodes.slice(startIndex, endIndex + 1);
  const totalHeight = flatNodes.length * ROW_HEIGHT;
  const offsetY = startIndex * ROW_HEIGHT;

  return (
    <div ref={containerRef} className="h-full w-full overflow-auto" onScroll={handleScroll}>
      <div style={{ height: totalHeight, position: "relative" }}>
        <div style={{ position: "absolute", top: offsetY, left: 0, right: 0 }}>
          {visibleNodes.map((flat) => {
            const isSelected = flat.id === selectedId;

            return (
              <div
                key={flat.id}
                className={`flex items-center gap-1 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 ${
                  isSelected ? "bg-blue-100 dark:bg-blue-900" : ""
                }`}
                style={{ height: ROW_HEIGHT }}
                onClick={() => handleSelect(flat.node)}
              >
                <div
                  style={{
                    paddingLeft: flat.level * 16 + 4,
                    display: "flex",
                    alignItems: "center",
                    gap: 4,
                    flex: 1,
                    minWidth: 0,
                  }}
                >
                  <button
                    className="w-4 h-4 flex items-center justify-center flex-shrink-0"
                    onClick={(e) => {
                      e.stopPropagation();
                      if (flat.hasChildren) handleToggle(flat.id);
                    }}
                  >
                    {flat.hasChildren ? (
                      flat.isExpanded ? (
                        <ChevronDown className="w-3 h-3" />
                      ) : (
                        <ChevronRight className="w-3 h-3" />
                      )
                    ) : null}
                  </button>
                  <span className="flex-shrink-0">
                    {flat.node.isDir ? (
                      <Folder className="w-4 h-4 text-yellow-500" />
                    ) : (
                      <FileIcon className="w-4 h-4 text-gray-500" />
                    )}
                  </span>
                  <span className="truncate text-sm">{flat.node.name}</span>
                  <span className="ml-auto text-xs text-gray-400 flex-shrink-0 pr-2">
                    {flat.node.isDir
                      ? (flat.node.children?.length ?? 0).toLocaleString()
                      : formatSizeRef(flat.node.size)}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export function countNodes(node: EvidenceNode): number {
  let total = 1;
  node.children?.forEach((child) => {
    total += countNodes(child);
  });
  return total;
}
