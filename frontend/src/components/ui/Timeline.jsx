import React from 'react';

export function Timeline({ children }) {
  return (
    <div className="relative pl-3 border-l-2 border-hairline space-y-6">
      {children}
    </div>
  );
}

export function TimelineItem({ title, date, description, dotColor = 'bg-mist' }) {
  return (
    <div className="relative">
      <div className={`absolute -left-[17px] top-1.5 w-2.5 h-2.5 rounded-full ${dotColor} border-2 border-panel`} />
      <div className="flex flex-col gap-1">
        <div className="flex items-center justify-between">
          <span className="text-sm font-bold text-ink">{title}</span>
          <span className="text-[10px] font-mono text-mist">{date}</span>
        </div>
        {description && <p className="text-xs text-mist">{description}</p>}
      </div>
    </div>
  );
}
