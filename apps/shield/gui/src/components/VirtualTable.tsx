import React, { useCallback, useRef, useEffect, useState } from "react";

export interface VirtualTableColumn<T> {
  key: string;
  header: string;
  width?: number;
  flex?: number;
  render?: (row: T, index: number) => React.ReactNode;
}

interface VirtualTableProps<T> {
  data: T[];
  columns: VirtualTableColumn<T>[];
  rowHeight?: number;
  onRowClick?: (row: T, index: number) => void;
  selectedId?: string | null;
  getRowId?: (row: T) => string;
  emptyMessage?: string;
  isLoading?: boolean;
}

const DEFAULT_ROW_HEIGHT = 32;
const OVERSCAN = 5;

export default function VirtualTable<T>({
  data,
  columns,
  rowHeight = DEFAULT_ROW_HEIGHT,
  onRowClick,
  selectedId,
  getRowId,
  emptyMessage = "No data",
  isLoading = false,
}: VirtualTableProps<T>) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(400);

  const handleRowClick = useCallback(
    (index: number) => {
      if (onRowClick) {
        onRowClick(data[index], index);
      }
    },
    [onRowClick, data]
  );

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  }, []);

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

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400">
        Loading...
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400">
        {emptyMessage}
      </div>
    );
  }

  const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
  const endIndex = Math.min(
    data.length - 1,
    Math.ceil((scrollTop + containerHeight) / rowHeight) + OVERSCAN
  );
  const visibleData = data.slice(startIndex, endIndex + 1);
  const totalHeight = data.length * rowHeight;
  const offsetY = startIndex * rowHeight;

  return (
    <div className="h-full w-full flex flex-col">
      <div
        className="flex items-center bg-gray-100 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 font-medium text-sm flex-shrink-0"
        style={{ height: rowHeight }}
      >
        {columns.map((col) => {
          const width = col.width || (col.flex ? col.flex * 100 : 100);
          return (
            <div
              key={col.key}
              className="px-2 py-1"
              style={{ width, minWidth: width, flex: col.width ? undefined : col.flex || 1 }}
            >
              {col.header}
            </div>
          );
        })}
      </div>
      <div ref={containerRef} className="flex-1 min-h-0 overflow-auto" onScroll={handleScroll}>
        <div style={{ height: totalHeight, position: "relative" }}>
          <div style={{ position: "absolute", top: offsetY, left: 0, right: 0 }}>
            {visibleData.map((row, i) => {
              const index = startIndex + i;
              const rowId = getRowId ? getRowId(row) : String(index);
              const isSelected = selectedId === rowId;

              return (
                <div
                  key={rowId}
                  className={`flex items-center border-b border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 ${
                    isSelected ? "bg-blue-50 dark:bg-blue-900/30" : ""
                  }`}
                  style={{ height: rowHeight }}
                  onClick={() => handleRowClick(index)}
                >
                  {columns.map((col) => {
                    const width = col.width || (col.flex ? col.flex * 100 : 100);
                    const content = col.render ? col.render(row, index) : String((row as Record<string, unknown>)[col.key] ?? "");

                    return (
                      <div
                        key={col.key}
                        className="px-2 py-1 overflow-hidden text-sm"
                        style={{ width, minWidth: width, flex: col.width ? undefined : col.flex || 1 }}
                      >
                        {content}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
