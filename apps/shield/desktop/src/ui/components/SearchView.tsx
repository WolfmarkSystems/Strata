import { useCallback, useState, useEffect } from 'react';
import { useGlobalSearch } from '../hooks';
import type { GlobalSearchHit, FileTableRow } from '../../types';

interface Props {
  caseId: string | null;
  onSelectFile: (row: FileTableRow) => void;
  onSwitchToFiles: () => void;
  onAddToNotes: (items: Array<{
    item_type: string;
    file_path?: string;
    evidence_id?: string;
    volume_id?: string;
    hash_sha256?: string;
    provenance?: string;
  }>, mode: 'note_only' | 'exhibit_only' | 'with_exhibit' | 'create_packet') => void;
}

const ENTITY_TYPES = ['file', 'timeline', 'exhibit', 'note', 'bookmark', 'artifact'];

export function SearchView({ caseId, onSwitchToFiles, onAddToNotes }: Props) {
  const search = useGlobalSearch(caseId);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; hit: GlobalSearchHit } | null>(null);
  
  const handleSearch = useCallback(() => {
    if (search.query.trim()) {
      search.search(true);
    }
  }, [search]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  }, [handleSearch]);

  const handleResultClick = useCallback(async (hit: GlobalSearchHit) => {
    if (hit.entity_type === 'file') {
      // Try to find in file table - for now, show preview
      // In a full implementation, we'd query file_table with the hash/path
      onSwitchToFiles();
    }
  }, [onSwitchToFiles]);

  useEffect(() => {
    const handleClick = () => setContextMenu(null);
    document.addEventListener('click', handleClick);
    return () => document.removeEventListener('click', handleClick);
  }, []);

  const handleContextMenu = useCallback((e: React.MouseEvent, hit: GlobalSearchHit) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, hit });
  }, []);

  const copySnippet = useCallback((text: string) => {
    navigator.clipboard.writeText(text);
  }, []);

  if (!caseId) {
    return (
      <div className="view-empty">
        <p>Open a case to search</p>
      </div>
    );
  }

  return (
    <div className="search-view">
      <div className="search-controls">
        <div className="search-input-row">
          <input
            type="text"
            placeholder="Search..."
            value={search.query}
            onChange={e => search.setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="search-input"
          />
          <button onClick={handleSearch} disabled={search.loading || !search.query.trim()}>
            Search
          </button>
        </div>

        <div className="search-filters">
          <label>
            Entity Types:
            <div className="checkbox-group">
              {ENTITY_TYPES.map(type => (
                <label key={type}>
                  <input
                    type="checkbox"
                    checked={search.filters.entity_types.includes(type)}
                    onChange={e => {
                      const types = e.target.checked
                        ? [...search.filters.entity_types, type]
                        : search.filters.entity_types.filter(t => t !== type);
                      search.setFilters(f => ({ ...f, entity_types: types }));
                    }}
                  />
                  {type}
                </label>
              ))}
            </div>
          </label>

          <label>
            Category:
            <input
              type="text"
              value={search.filters.category}
              onChange={e => search.setFilters(f => ({ ...f, category: e.target.value }))}
              placeholder="e.g. threat, artifact"
            />
          </label>

          <label>
            Tags (comma):
            <input
              type="text"
              value={search.filters.tags_any}
              onChange={e => search.setFilters(f => ({ ...f, tags_any: e.target.value }))}
              placeholder="e.g. suspicious, ioc"
            />
          </label>

          <label>
            Path prefix:
            <input
              type="text"
              value={search.filters.path_prefix}
              onChange={e => search.setFilters(f => ({ ...f, path_prefix: e.target.value }))}
              placeholder="/Users/"
            />
          </label>

          <button onClick={() => search.search(true)}>
            Apply Filters
          </button>

          <button onClick={search.rebuildIndex} className="rebuild-btn">
            Rebuild Index
          </button>
        </div>
      </div>

      <div className="search-results">
        {search.error && <div className="search-error">{search.error}</div>}
        
        {search.results.map((hit, idx) => (
          <div
            key={`${hit.entity_type}-${hit.entity_id}-${idx}`}
            className="search-result"
            onClick={() => handleResultClick(hit)}
            onContextMenu={e => handleContextMenu(e, hit)}
          >
            <div className="result-header">
              <span className={`entity-type ${hit.entity_type}`}>{hit.entity_type}</span>
              <span className="result-rank">#{hit.rank.toFixed(1)}</span>
            </div>
            <div className="result-title">{hit.title}</div>
            <div className="result-snippet">{hit.snippet}</div>
            {hit.path && <div className="result-path">{hit.path}</div>}
          </div>
        ))}

        {search.loading && <div className="search-loading">Searching...</div>}
        
        {!search.loading && search.results.length === 0 && search.query && (
          <div className="search-empty">No results found</div>
        )}

        {!search.loading && search.hasMore && (
          <button className="load-more" onClick={search.loadMore}>
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
              file_path: contextMenu.hit.path,
              provenance: contextMenu.hit.source_module || contextMenu.hit.entity_type,
            }], 'with_exhibit');
            setContextMenu(null);
          }}>
            Add to Notes
          </button>
          <button onClick={() => {
            copySnippet(contextMenu.hit.snippet);
            setContextMenu(null);
          }}>
            Copy Snippet
          </button>
          {contextMenu.hit.path && (
            <button onClick={() => {
              copySnippet(contextMenu.hit.path || '');
              setContextMenu(null);
            }}>
              Copy Path
            </button>
          )}
        </div>
      )}
    </div>
  );
}
