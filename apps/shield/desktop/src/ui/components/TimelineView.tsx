import { useCallback, useState, useEffect } from 'react';
import { useTimeline } from '../hooks';
import type { EvidenceTimelineEvent, FileTableRow } from '../../types';

interface Props {
  caseId: string | null;
  onSelectFile: (row: FileTableRow) => void;
  onSwitchToFiles: () => void;
  onPreviewEvent: (event: EvidenceTimelineEvent) => void;
  onAddToNotes: (items: Array<{
    item_type: string;
    file_path?: string;
    evidence_id?: string;
    volume_id?: string;
    hash_sha256?: string;
    provenance?: string;
  }>, mode: 'note_only' | 'exhibit_only' | 'with_exhibit' | 'create_packet') => void;
}

const EVENT_CATEGORIES = ['threat', 'system', 'activity', 'artifact', 'network', 'persistence'];

export function TimelineView({ caseId, onSwitchToFiles, onPreviewEvent, onAddToNotes }: Props) {
  const timeline = useTimeline(caseId);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; event: EvidenceTimelineEvent } | null>(null);

  const handleEventClick = useCallback((event: EvidenceTimelineEvent) => {
    onPreviewEvent(event);
  }, [onPreviewEvent]);

  useEffect(() => {
    const handleClick = () => setContextMenu(null);
    document.addEventListener('click', handleClick);
    return () => document.removeEventListener('click', handleClick);
  }, []);

  const handleContextMenu = useCallback((e: React.MouseEvent, event: EvidenceTimelineEvent) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, event });
  }, []);

  const findRelatedFile = useCallback((event: EvidenceTimelineEvent) => {
    // Try to find related file via artifact_id or path
    if (event.artifact_id || event.source_record_id) {
      onSwitchToFiles();
    }
  }, [onSwitchToFiles]);

  const formatTime = (timestamp: number): string => {
    try {
      return new Date(timestamp * 1000).toLocaleString();
    } catch {
      return String(timestamp);
    }
  };

  const getCategoryColor = (category?: string): string => {
    switch (category) {
      case 'threat': return 'var(--error)';
      case 'system': return 'var(--accent)';
      case 'activity': return 'var(--warning)';
      default: return 'var(--text-secondary)';
    }
  };

  if (!caseId) {
    return (
      <div className="view-empty">
        <p>Open a case to view timeline</p>
      </div>
    );
  }

  return (
    <div className="timeline-view">
      <div className="timeline-filters">
        <label>
          Event Category:
          <select
            value={timeline.filters.event_category}
            onChange={e => timeline.setFilters(f => ({ ...f, event_category: e.target.value }))}
          >
            <option value="">All</option>
            {EVENT_CATEGORIES.map(cat => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
        </label>

        <label>
          Event Type:
          <input
            type="text"
            value={timeline.filters.event_type}
            onChange={e => timeline.setFilters(f => ({ ...f, event_type: e.target.value }))}
            placeholder="e.g. IOC_HIT, FILE_CREATE"
          />
        </label>

        <label>
          Source Module:
          <input
            type="text"
            value={timeline.filters.source_module}
            onChange={e => timeline.setFilters(f => ({ ...f, source_module: e.target.value }))}
            placeholder="e.g. ioc_scanner, carving"
          />
        </label>

        <label>
          Date Range:
          <div className="date-range">
            <input
              type="date"
              value={timeline.filters.date_start}
              onChange={e => timeline.setFilters(f => ({ ...f, date_start: e.target.value }))}
            />
            <span>to</span>
            <input
              type="date"
              value={timeline.filters.date_end}
              onChange={e => timeline.setFilters(f => ({ ...f, date_end: e.target.value }))}
            />
          </div>
        </label>

        <button onClick={() => timeline.loadEvents(true)}>
          Apply Filters
        </button>
      </div>

      <div className="timeline-list">
        {timeline.error && <div className="timeline-error">{timeline.error}</div>}
        
        {timeline.events.map((event, idx) => (
          <div
            key={`${event.id}-${idx}`}
            className="timeline-event"
            onClick={() => handleEventClick(event)}
            onContextMenu={e => handleContextMenu(e, event)}
          >
            <div className="event-time">{formatTime(event.event_time)}</div>
            <div 
              className="event-category"
              style={{ color: getCategoryColor(event.event_category) }}
            >
              {event.event_category || '-'}
            </div>
            <div className="event-type">{event.event_type}</div>
            <div className="event-summary">
              {event.summary || event.source_module || event.source_record_id || '-'}
            </div>
            {event.artifact_id && (
              <div className="event-artifact" title={event.artifact_id}>
                📎
              </div>
            )}
          </div>
        ))}

        {timeline.loading && <div className="timeline-loading">Loading...</div>}
        
        {!timeline.loading && timeline.events.length === 0 && (
          <div className="timeline-empty">No timeline events found</div>
        )}

        {!timeline.loading && timeline.hasMore && (
          <button className="load-more" onClick={timeline.loadMore}>
            Load More
          </button>
        )}
      </div>

      {contextMenu && (
        <div
          className="context-menu"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={e => e.stopPropagation()}
        >
          <button onClick={() => {
            onAddToNotes([{
              item_type: 'file',
              file_path: contextMenu.event.artifact_id,
              provenance: `${contextMenu.event.source_module}:${contextMenu.event.source_record_id}`,
            }], 'with_exhibit');
            setContextMenu(null);
          }}>
            Add to Notes
          </button>
          <button onClick={() => {
            navigator.clipboard.writeText(JSON.stringify(contextMenu.event, null, 2));
            setContextMenu(null);
          }}>
            Copy JSON
          </button>
          {(contextMenu.event.artifact_id || contextMenu.event.source_record_id) && (
            <button onClick={() => {
              findRelatedFile(contextMenu.event);
              setContextMenu(null);
            }}>
              Find Related File
            </button>
          )}
        </div>
      )}
    </div>
  );
}
