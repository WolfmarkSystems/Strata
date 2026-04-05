import React from 'react';

export default function PreviewPanel({ content }) {
  return (
    <div className="h-full w-full p-2 text-xs bg-muted rounded">
      {content || <span className="text-muted-foreground">No preview available.</span>}
    </div>
  );
}
