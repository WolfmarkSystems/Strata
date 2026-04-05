import { useState, useCallback, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { FileTable } from './components/FileTable';
import { Preview } from './components/Preview';
import { EventConsole } from './components/EventConsole';
import { SearchView } from './components/SearchView';
import { TimelineView } from './components/TimelineView';
import { WorkflowView } from './components/WorkflowView';
import { useCase, useFileTable, useCapabilities, usePreflight, useEvents, useAddToNotes } from './hooks';
import type { FileTableRow, GlobalSearchHit, EvidenceTimelineEvent, Tab } from '../types';
import './styles.css';

export default function App() {
  const caseState = useCase();
  const fileTable = useFileTable(caseState.caseId);
  const { capabilities } = useCapabilities();
  const { report: preflightReport, run: runPreflight } = usePreflight();
  const eventState = useEvents();
  const { addToNotes } = useAddToNotes();
  
  const [activeTab, setActiveTab] = useState<Tab>('files');
  const [showConsole, setShowConsole] = useState(true);
  
  // Preview state - can be file, search result, or timeline event
  const [previewData, setPreviewData] = useState<{
    kind: 'file' | 'search' | 'timeline';
    data: FileTableRow | GlobalSearchHit | EvidenceTimelineEvent;
  } | null>(null);

  const getCapabilityStatus = (name: string): string => {
    const cap = capabilities?.capabilities.find((c: { name: string }) => c.name === name);
    return cap?.status || 'Unknown';
  };

  // Handle file selection from file table
  const handleSelectFile = useCallback((row: FileTableRow) => {
    fileTable.setSelectedRow(row);
    setPreviewData({ kind: 'file', data: row });
    setActiveTab('files');
  }, [fileTable]);

  // Handle timeline event preview
  const handleTimelineEventClick = useCallback((event: EvidenceTimelineEvent) => {
    setPreviewData({ kind: 'timeline', data: event });
  }, []);

  // Unified Add to Notes
  const handleAddToNotes = useCallback(async (
    items: Array<{
      item_type: string;
      file_path?: string;
      evidence_id?: string;
      volume_id?: string;
      hash_sha256?: string;
      provenance?: string;
    }>,
    mode: 'note_only' | 'exhibit_only' | 'with_exhibit' | 'create_packet'
  ) => {
    if (!caseState.caseId) return;
    try {
      await addToNotes(caseState.caseId, mode, items);
      // Show success toast (could add toast library)
      console.log('Added to notes');
    } catch (e) {
      console.error('Failed to add to notes:', e);
    }
  }, [caseState.caseId, addToNotes]);

  // Update preview when fileTable selection changes
  useEffect(() => {
    if (fileTable.selectedRow && activeTab === 'files') {
      setPreviewData({ kind: 'file', data: fileTable.selectedRow });
    }
  }, [fileTable.selectedRow, activeTab]);

  return (
    <div className="app">
      <header className="app-header">
        <h1>Forensic Suite</h1>
        
        <nav className="nav-tabs">
          <button
            className={`nav-tab ${activeTab === 'files' ? 'active' : ''}`}
            onClick={() => setActiveTab('files')}
          >
            Files
          </button>
          <button
            className={`nav-tab ${activeTab === 'search' ? 'active' : ''}`}
            onClick={() => setActiveTab('search')}
          >
            Search
          </button>
          <button
            className={`nav-tab ${activeTab === 'timeline' ? 'active' : ''}`}
            onClick={() => setActiveTab('timeline')}
          >
            Timeline
          </button>
          <button
            className={`nav-tab ${activeTab === 'workflow' ? 'active' : ''}`}
            onClick={() => setActiveTab('workflow')}
          >
            Workflow
          </button>
        </nav>

        {caseState.caseId && (
          <div className="header-info">
            <span className="badge">Case: {caseState.caseId.slice(0, 8)}...</span>
            {capabilities && (
              <span className={`badge status-${getCapabilityStatus('core').toLowerCase()}`}>
                {getCapabilityStatus('core')}
              </span>
            )}
          </div>
        )}
      </header>

      {caseState.error && (
        <div className="error-banner">
          <span>{caseState.error}</span>
          <button onClick={caseState.clearError}>×</button>
        </div>
      )}

      {preflightReport && preflightReport.overall_status !== 'Pass' && (
        <div className={`preflight-banner ${preflightReport.overall_status.toLowerCase()}`}>
          <span>
            Preflight: {preflightReport.overall_status} - 
            {preflightReport.results.map((r: { name: string }) => r.name).join(', ')}
          </span>
        </div>
      )}

      <div className="app-body">
        <Sidebar
          caseState={caseState}
          fileTable={fileTable}
          onRunPreflight={runPreflight}
        />
        
        <main className="main-content">
          {activeTab === 'files' && (
            <FileTable
              fileTable={fileTable}
              caseId={caseState.caseId}
            />
          )}
          
          {activeTab === 'search' && (
            <SearchView
              caseId={caseState.caseId}
              onSelectFile={handleSelectFile}
              onSwitchToFiles={() => setActiveTab('files')}
              onAddToNotes={handleAddToNotes}
            />
          )}
          
          {activeTab === 'timeline' && (
            <TimelineView
              caseId={caseState.caseId}
              onSelectFile={handleSelectFile}
              onSwitchToFiles={() => setActiveTab('files')}
              onPreviewEvent={handleTimelineEventClick}
              onAddToNotes={handleAddToNotes}
            />
          )}
          
          {activeTab === 'workflow' && (
            <WorkflowView caseId={caseState.caseId} />
          )}
        </main>

        <aside className="preview-pane">
          <Preview
            previewData={previewData}
            caseId={caseState.caseId}
          />
        </aside>
      </div>

      <EventConsole
        events={eventState.events}
        filter={eventState.filter}
        setFilter={eventState.setFilter}
        paused={eventState.paused}
        setPaused={eventState.setPaused}
        totalCount={eventState.totalCount}
        visible={showConsole}
        onToggle={() => setShowConsole(!showConsole)}
      />
    </div>
  );
}
