import React from 'react';

export default function StatusBadge({ status }) {
  const safeStatus = status === null || status === undefined ? 'UNKNOWN' : String(status);
  const norm = safeStatus.toUpperCase() || 'UNKNOWN';
  
  const config = {
    NEW: { bg: 'bg-sky-950/40', text: 'text-sky-400', border: 'border-sky-500/30', label: 'NEW' },
    IN_PROGRESS: { bg: 'bg-amber-950/40', text: 'text-amber-400', border: 'border-amber-500/30', label: 'IN PROGRESS' },
    MITIGATED: { bg: 'bg-emerald-950/40', text: 'text-emerald-400', border: 'border-emerald-500/30', label: 'MITIGATED' },
    RESOLVED: { bg: 'bg-emerald-950/40', text: 'text-emerald-400', border: 'border-emerald-500/30', label: 'RESOLVED' },
    DISMISSED: { bg: 'bg-slate-900/60', text: 'text-slate-400', border: 'border-slate-800', label: 'DISMISSED' },
    ACTIVE: { bg: 'bg-red-950/40', text: 'text-red-400', border: 'border-red-500/30', label: 'ACTIVE' },
    NOT_CHECKED: { bg: 'bg-slate-900/60', text: 'text-slate-400', border: 'border-slate-800', label: 'NOT CHECKED' },
    UNKNOWN: { bg: 'bg-slate-900/60', text: 'text-slate-400', border: 'border-slate-800', label: 'UNKNOWN' }
  };
  
  const style = config[norm] || config.UNKNOWN;
  
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${style.bg} ${style.text} border ${style.border}`}>
      {style.label}
    </span>
  );
}
