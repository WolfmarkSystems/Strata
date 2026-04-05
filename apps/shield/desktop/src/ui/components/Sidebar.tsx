import { useState } from 'react';

interface CaseState {
  caseId: string | null;
  casePath: string;
  evidenceId: string | null;
  evidencePath: string;
  error: string | null;
  loading: boolean;
  openCase: (path: string) => Promise<void>;
  openEvidence: (path: string) => Promise<void>;
  clearError: () => void;
}

interface FileTableState {
  filters: {
    name_contains: string;
    ext_in: string;
    category_in: string;
    score_min: number;
    min_size: number;
    max_size: number;
    source_types: string[];
  };
  setFilters: React.Dispatch<React.SetStateAction<FileTableState['filters']>>;
  applyFilters: () => void;
}

interface Props {
  caseState: CaseState;
  fileTable: FileTableState;
  onRunPreflight: () => void;
}

export function Sidebar({ caseState, fileTable, onRunPreflight }: Props) {
  const [casePathInput, setCasePathInput] = useState('');
  const [evidencePathInput, setEvidencePathInput] = useState('');

  const handleOpenCase = () => {
    if (casePathInput) {
      caseState.openCase(casePathInput);
    }
  };

  const handleOpenEvidence = () => {
    if (evidencePathInput) {
      caseState.openEvidence(evidencePathInput);
    }
  };

  return (
    <aside className="sidebar">
      <section className="sidebar-section">
        <h3>Case</h3>
        <input
          type="text"
          placeholder="Case path or DB path"
          value={casePathInput}
          onChange={e => setCasePathInput(e.target.value)}
          disabled={caseState.loading}
        />
        <button onClick={handleOpenCase} disabled={caseState.loading || !casePathInput}>
          Open Case
        </button>
        {caseState.caseId && (
          <div className="current-value">
            <small>Active: {caseState.casePath}</small>
          </div>
        )}
      </section>

      <section className="sidebar-section">
        <h3>Evidence</h3>
        <input
          type="text"
          placeholder="Evidence file path"
          value={evidencePathInput}
          onChange={e => setEvidencePathInput(e.target.value)}
          disabled={caseState.loading || !caseState.caseId}
        />
        <button 
          onClick={handleOpenEvidence} 
          disabled={caseState.loading || !caseState.caseId || !evidencePathInput}
        >
          Open Evidence
        </button>
        {caseState.evidenceId && (
          <div className="current-value">
            <small>Active: {caseState.evidencePath}</small>
          </div>
        )}
      </section>

      <section className="sidebar-section">
        <h3>Filters</h3>
        <label>
          Name contains:
          <input
            type="text"
            placeholder="e.g. document"
            value={fileTable.filters.name_contains}
            onChange={e => fileTable.setFilters(f => ({ ...f, name_contains: e.target.value }))}
          />
        </label>
        
        <label>
          Extensions (comma):
          <input
            type="text"
            placeholder="pdf, docx, exe"
            value={fileTable.filters.ext_in}
            onChange={e => fileTable.setFilters(f => ({ ...f, ext_in: e.target.value }))}
          />
        </label>
        
        <label>
          Categories (comma):
          <input
            type="text"
            placeholder="document, image"
            value={fileTable.filters.category_in}
            onChange={e => fileTable.setFilters(f => ({ ...f, category_in: e.target.value }))}
          />
        </label>
        
        <label>
          Min Score:
          <input
            type="range"
            min="0"
            max="100"
            value={fileTable.filters.score_min}
            onChange={e => fileTable.setFilters(f => ({ ...f, score_min: Number(e.target.value) }))}
          />
          <span>{fileTable.filters.score_min}</span>
        </label>

        <label>
          Source Types:
          <div className="checkbox-group">
            <label>
              <input
                type="checkbox"
                checked={fileTable.filters.source_types.includes('fs')}
                onChange={e => {
                  const types = e.target.checked
                    ? [...fileTable.filters.source_types, 'fs']
                    : fileTable.filters.source_types.filter(t => t !== 'fs');
                  fileTable.setFilters(f => ({ ...f, source_types: types }));
                }}
              />
              FS
            </label>
            <label>
              <input
                type="checkbox"
                checked={fileTable.filters.source_types.includes('carved')}
                onChange={e => {
                  const types = e.target.checked
                    ? [...fileTable.filters.source_types, 'carved']
                    : fileTable.filters.source_types.filter(t => t !== 'carved');
                  fileTable.setFilters(f => ({ ...f, source_types: types }));
                }}
              />
              Carved
            </label>
            <label>
              <input
                type="checkbox"
                checked={fileTable.filters.source_types.includes('ioc')}
                onChange={e => {
                  const types = e.target.checked
                    ? [...fileTable.filters.source_types, 'ioc']
                    : fileTable.filters.source_types.filter(t => t !== 'ioc');
                  fileTable.setFilters(f => ({ ...f, source_types: types }));
                }}
              />
              IOC
            </label>
          </div>
        </label>

        <button onClick={fileTable.applyFilters} disabled={!caseState.caseId}>
          Apply Filters
        </button>
      </section>

      <section className="sidebar-section">
        <h3>System</h3>
        <button onClick={onRunPreflight}>
          Run Preflight
        </button>
      </section>
    </aside>
  );
}
