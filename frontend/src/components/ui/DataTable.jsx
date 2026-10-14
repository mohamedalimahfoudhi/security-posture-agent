import React from 'react';

export default function DataTable({ headers, children, emptyMessage = "No records found" }) {
  return (
    <div className="w-full overflow-x-auto rounded-md border border-border-base bg-panel shadow-sm">
      <table className="w-full text-left text-sm whitespace-nowrap">
        <thead className="bg-table-header border-b border-border-base text-text-muted text-[11px] uppercase tracking-wider font-semibold">
          <tr>
            {headers.map((header, i) => (
              <th key={i} className="px-4 py-2.5 font-semibold">{header}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border-base/70">
          {children || (
            <tr>
              <td colSpan={headers.length} className="px-4 py-8 text-center text-text-muted text-xs font-body">
                {emptyMessage}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
