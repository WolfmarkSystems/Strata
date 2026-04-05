import { useState, useEffect, useCallback } from 'react';
import { api } from '../../api/tauri';
import type { FileTableRow, GlobalSearchHit, EvidenceTimelineEvent, ScoreSignal } from '../../types';

type PreviewData = {
  kind: 'file' | 'search' | 'timeline';
  data: FileTableRow | GlobalSearchHit | EvidenceTimelineEvent;
};

interface Props {
  previewData: PreviewData | null;
  caseId: string | null;
}

type Tab = 'text' | 'hex' | 'metadata';

export function Preview({ previewData, caseId }: Props) {
  const [activeTab, setActiveTab] = useState<Tab>('metadata');
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!previewData || !caseId) {
      setContent('');
      return;
    }

    const loadContent = async () => {
      setLoading(true);
      setError(null);
      
      if (previewData.kind === 'file') {
        const row = previewData.data as FileTableRow;
        try {
          const result = await api.fileTablePreview(caseId, row.source_type, row.source_id, activeTab);
          setContent(result.content || '(No content)');
        } catch (e: unknown) {
          setError(e instanceof Error ? e.message : String(e));
        }
      } else if (previewData.kind === 'search') {
        const hit = previewData.data as GlobalSearchHit;
        // Show search hit details
        if (activeTab === 'metadata') {
          setContent(JSON.stringify(hit.json_data || {
            id: hit.id,
            type: hit.entity_type,
            title: hit.title,
            snippet: hit.snippet,
            path: hit.path,
            category: hit.category,
          }, null, 2));
        } else {
          setContent(hit.snippet);
        }
      } else if (previewData.kind === 'timeline') {
        const event = previewData.data as EvidenceTimelineEvent;
        // Show timeline event details
        if (activeTab === 'metadata') {
          setContent(JSON.stringify({
            id: event.id,
            time: event.event_time,
            type: event.event_type,
            category: event.event_category,
            module: event.source_module,
            artifact: event.artifact_id,
            summary: event.summary,
            details: event.details_json ? JSON.parse(event.details_json) : null,
          }, null, 2));
        } else {
          setContent(event.summary || event.event_type);
        }
      }
      
      setLoading(false);
    };

    loadContent();
  }, [previewData, caseId, activeTab]);

  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text);
  }, []);

  if (!previewData) {
    return (
      <div className="preview-empty">
        <p>Select an item to preview</p>
      </div>
    );
  }

  const getTitle = (): string => {
    if (previewData.kind === 'file') {
      return (previewData.data as FileTableRow).name;
    } else if (previewData.kind === 'search') {
      return (previewData.data as GlobalSearchHit).title;
    } else {
      return (previewData.data as EvidenceTimelineEvent).event_type;
    }
  };

  const getScoreSignals = (): ScoreSignal[] | undefined => {
    if (previewData.kind === 'file') {
      const row = previewData.data as FileTableRow;
      return row.summary?.score_signals as ScoreSignal[] | undefined;
    }
    return undefined;
  };

  const scoreSignals = getScoreSignals();

  return (
    <div className="preview">
      <div className="preview-header">
        <h3>{getTitle()}</h3>
        <div className="preview-actions">
          <button onClick={() => copyToClipboard(content)} title="Copy">
            Copy
          </button>
        </div>
      </div>

      <div className="preview-tabs">
        <button
          className={activeTab === 'metadata' ? 'active' : ''}
          onClick={() => setActiveTab('metadata')}
        >
          Metadata
        </button>
        <button
          className={activeTab === 'text' ? 'active' : ''}
          onClick={() => setActiveTab('text')}
        >
          Text
        </button>
        <button
          className={activeTab === 'hex' ? 'active' : ''}
          onClick={() => setActiveTab('hex')}
        >
          Hex
        </button>
      </div>

      <div className="preview-content">
        {loading && <div className="preview-loading">Loading...</div>}
        {error && <div className="preview-error">{error}</div>}
        {!loading && !error && (
          <>
            {activeTab === 'metadata' && (
              <div className="metadata-view">
                {previewData.kind === 'file' && (
                  <>
                    {(previewData.data as FileTableRow).path && (
                      <dl>
                        <dt>Path</dt><dd>{(previewData.data as FileTableRow).path}</dd>
                        <dt>Size</dt><dd>{(previewData.data as FileTableRow).size_bytes || '-'}</dd>
                        <dt>Modified</dt><dd>{(previewData.data as FileTableRow).modified_utc || '-'}</dd>
                        <dt>Created</dt><dd>{(previewData.data as FileTableRow).created_utc || '-'}</dd>
                        <dt>Entropy</dt><dd>{(previewData.data as FileTableRow).entropy?.toFixed(2) || '-'}</dd>
                        <dt>Category</dt><dd>{(previewData.data as FileTableRow).category || '-'}</dd>
                        <dt>Source</dt><dd>{(previewData.data as FileTableRow).source_type}</dd>
                        <dt>Score</dt><dd>{(previewData.data as FileTableRow).score.toFixed(2)}</dd>
                      </dl>
                    )}
                  </>
                )}
                
                {previewData.kind === 'search' && (
                  <dl>
                    {(previewData.data as GlobalSearchHit).path && (
                      <>
                        <dt>Path</dt><dd>{(previewData.data as GlobalSearchHit).path}</dd>
                      </>
                    )}
                    <dt>Type</dt><dd>{(previewData.data as GlobalSearchHit).entity_type}</dd>
                    <dt>Rank</dt><dd>{(previewData.data as GlobalSearchHit).rank.toFixed(2)}</dd>
                  </dl>
                )}
                
                {previewData.kind === 'timeline' && (
                  <dl>
                    <dt>Event Type</dt><dd>{(previewData.data as EvidenceTimelineEvent).event_type}</dd>
                    <dt>Category</dt><dd>{(previewData.data as EvidenceTimelineEvent).event_category || '-'}</dd>
                    <dt>Module</dt><dd>{(previewData.data as EvidenceTimelineEvent).source_module || '-'}</dd>
                    <dt>Artifact</dt><dd>{(previewData.data as EvidenceTimelineEvent).artifact_id || '-'}</dd>
                  </dl>
                )}

                {scoreSignals && scoreSignals.length > 0 && (
                  <div className="score-explain">
                    <h4>Score Signals</h4>
                    <ul>
                      {scoreSignals.map((signal, i) => (
                        <li key={i}>
                          <span className="signal-points">+{signal.points}</span>
                          <span className="signal-key">{signal.key}</span>
                          <span className="signal-evidence">{signal.evidence}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
            {(activeTab === 'text' || activeTab === 'hex') && (
              <pre className={`${activeTab}-view`}>{content}</pre>
            )}
          </>
        )}
      </div>
    </div>
  );
}
