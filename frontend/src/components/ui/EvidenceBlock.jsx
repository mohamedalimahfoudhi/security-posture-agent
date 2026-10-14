import React from 'react';
import { Info } from 'lucide-react';

export default function EvidenceBlock({ title = "EVIDENCE", content, className = '' }) {
  if (!content) return null;
  
  return (
    <div className={`bg-[#1A1E20] border border-hairline rounded p-3 ${className}`}>
      <div className="flex items-center gap-2 mb-2">
        <Info className="w-3.5 h-3.5 text-viz-blue" />
        <span className="text-[10px] font-bold text-mist tracking-wider">{title}</span>
      </div>
      <div className="text-xs text-ink/90 font-mono leading-relaxed whitespace-pre-wrap">
        {typeof content === 'object' ? JSON.stringify(content, null, 2) : content}
      </div>
    </div>
  );
}
