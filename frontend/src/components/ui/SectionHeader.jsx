import React from 'react';

export default function SectionHeader({ title, count, actions }) {
  return (
    <div className="flex items-center justify-between py-2 mb-4 border-b border-hairline">
      <div className="flex items-center gap-3">
        <h2 className="text-sm font-display tracking-wide text-ink font-semibold uppercase">{title}</h2>
        {count !== undefined && (
          <span className="bg-hairline text-mist text-xs font-mono px-2 py-0.5 rounded">
            {count}
          </span>
        )}
      </div>
      {actions && <div>{actions}</div>}
    </div>
  );
}
