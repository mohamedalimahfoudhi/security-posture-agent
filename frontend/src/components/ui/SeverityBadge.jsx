import React from 'react';

export default function SeverityBadge({ severity }) {
  const safeSev = severity === null || severity === undefined ? 'UNKNOWN' : String(severity);
  const norm = safeSev.toUpperCase() || 'UNKNOWN';
  
  const config = {
    CRITICAL: { bg: 'bg-red-950/40', text: 'text-red-400', border: 'border-red-500/30' },
    HIGH: { bg: 'bg-orange-950/40', text: 'text-orange-400', border: 'border-orange-500/30' },
    MEDIUM: { bg: 'bg-amber-950/40', text: 'text-amber-400', border: 'border-amber-500/30' },
    ELEVATED: { bg: 'bg-amber-950/40', text: 'text-amber-400', border: 'border-amber-500/30' },
    LOW: { bg: 'bg-blue-950/40', text: 'text-blue-400', border: 'border-blue-500/30' },
    INFO: { bg: 'bg-slate-900/60', text: 'text-slate-400', border: 'border-slate-700/40' },
    UNKNOWN: { bg: 'bg-slate-900/40', text: 'text-slate-400', border: 'border-slate-800' }
  };
  
  const style = config[norm] || config.UNKNOWN;
  
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${style.bg} ${style.text} border ${style.border}`}>
      {norm}
    </span>
  );
}
