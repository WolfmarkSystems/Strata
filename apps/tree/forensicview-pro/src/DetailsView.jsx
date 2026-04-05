import React from 'react';

export default function DetailsView({ details }) {
  return (
    <div className="p-3 text-xs">
      <table className="w-full">
        <tbody>
          {Object.entries(details).map(([key, value]) => (
            <tr key={key}>
              <td className="font-semibold text-muted-foreground pr-2 align-top whitespace-nowrap">{key}</td>
              <td className="break-all">{String(value)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
