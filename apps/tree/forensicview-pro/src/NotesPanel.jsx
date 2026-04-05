import React from 'react';

export default function NotesPanel({ notes, onChange }) {
  return (
    <div className="h-full w-full p-2">
      <textarea
        className="w-full h-full min-h-[120px] text-xs p-2 border border-border rounded bg-muted"
        value={notes}
        onChange={e => onChange(e.target.value)}
        placeholder="Add notes for this case..."
      />
    </div>
  );
}
