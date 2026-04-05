import { useRef, useEffect, useState } from 'react';
import type { EngineEvent } from '../../types';

interface Props {
  events: EngineEvent[];
  filter: { severity: string; kind: string; search: string };
  setFilter: (f: { severity: string; kind: string; search: string }) => void;
  paused: boolean;
  setPaused: (p: boolean) => void;
  totalCount: number;
  visible: boolean;
  onToggle: () => void;
}

function formatTime(utc: string): string {
  try {
    return new Date(utc).toLocaleTimeString();
  } catch {
    return utc;
  }
}

function getKindLabel(kind: { type: string } | undefined): string {
  if (kind && 'type' in kind) {
    return kind.type;
  }
  return 'Unknown';
}

export function EventConsole({ events, filter, setFilter, paused, setPaused, totalCount, visible, onToggle }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && containerRef.current && !paused) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [events, autoScroll, paused]);

  if (!visible) {
    return (
      <div className="event-console collapsed">
        <button className="console-toggle" onClick={onToggle}>
          ▲ Events ({totalCount})
        </button>
      </div>
    );
  }

  return (
    <div className="event-console">
      <div className="console-header">
        <span className="console-title">Events ({totalCount})</span>
        
        <div className="console-filters">
          <select
            value={filter.severity}
            onChange={e => setFilter({ ...filter, severity: e.target.value })}
          >
            <option value="">All Severity</option>
            <option value="Info">Info</option>
            <option value="Warn">Warn</option>
            <option value="Error">Error</option>
          </select>

          <input
            type="text"
            placeholder="Search messages..."
            value={filter.search}
            onChange={e => setFilter({ ...filter, search: e.target.value })}
          />
        </div>

        <div className="console-controls">
          <label>
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={e => setAutoScroll(e.target.checked)}
            />
            Auto-scroll
          </label>
          <button onClick={() => setPaused(!paused)}>
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button onClick={onToggle}>▼</button>
        </div>
      </div>

      <div className="console-body" ref={containerRef}>
        {events.length === 0 ? (
          <div className="console-empty">No events</div>
        ) : (
          events.map((event, i) => (
            <div key={i} className={`event-row ${event.severity?.toLowerCase() || 'info'}`}>
              <span className="event-time">{formatTime(event.occurred_utc || event.timestamp_utc)}</span>
              <span className={`event-severity ${event.severity?.toLowerCase() || 'info'}`}>
                {event.severity || 'info'}
              </span>
              <span className="event-kind">{getKindLabel(event.kind)}</span>
              <span className="event-message">{event.message || ''}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
