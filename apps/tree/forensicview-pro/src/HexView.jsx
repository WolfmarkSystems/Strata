import React from 'react';

export default function HexView({ data }) {
  // data: Uint8Array or string
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(chunk).map(b => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    lines.push({
      offset: i,
      hex,
      ascii,
    });
  }
  return (
    <div className="font-mono text-xs overflow-auto h-full w-full bg-muted rounded p-2">
      <table>
        <tbody>
          {lines.map((line, idx) => (
            <tr key={idx}>
              <td className="pr-2 text-muted-foreground">{line.offset.toString(16).padStart(8, '0')}</td>
              <td className="pr-2">{line.hex}</td>
              <td>{line.ascii}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
