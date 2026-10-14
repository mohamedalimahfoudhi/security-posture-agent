import React from 'react';
import SeverityBadge from '../ui/SeverityBadge';
import RiskIndicator from '../ui/RiskIndicator';
import StatusBadge from '../ui/StatusBadge';

export default function IntelligenceTable({ headers, data, onRowClick, emptyMessage = 'No data available' }) {
  if (!data || data.length === 0) {
    return (
      <div className="border border-hairline rounded-lg bg-[#0D0F11] p-4">
        <p className="text-xs text-mist text-center">{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div className="border border-hairline rounded-lg bg-[#0D0F11] overflow-hidden">
      <table className="w-full">
        <thead>
          <tr className="border-b border-hairline bg-void/50">
            {headers.map((header, idx) => (
              <th key={idx} className="text-left text-[10px] font-semibold text-mist uppercase tracking-wider px-3 py-2">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, rowIdx) => (
            <tr 
              key={rowIdx}
              onClick={() => onRowClick && onRowClick(row)}
              className="border-b border-hairline/50 last:border-0 hover:bg-void/30 cursor-pointer transition-colors"
            >
              {row.map((cell, cellIdx) => (
                <td key={cellIdx} className="px-3 py-2">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
