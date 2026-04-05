import React from 'react';

export default function DataTable({ rows, columns }) {
  return (
    <div className="overflow-auto h-full w-full">
      <table className="min-w-full text-xs border-separate border-spacing-y-1">
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key} className="text-left px-2 py-1 font-semibold text-muted-foreground bg-muted rounded-t">{col.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="hover:bg-accent cursor-pointer">
              {columns.map((col) => (
                <td key={col.key} className="px-2 py-1 whitespace-nowrap">{row[col.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
